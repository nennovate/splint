//! The time a host goes by when it destroys something.
//!
//! Mail is deleted on the host's own clock, and a clock can jump. Refusing a message by a wrong clock
//! does no harm, because it's retried. Deleting one by a wrong clock can't be undone, so this holds a
//! forward jump at arm's length until it has lasted long enough to believe. A clock running slow or
//! set back only keeps things a little longer, so that's always taken as it is.
//!
//! What counts as a jump is the wall clock moving further than the time this process has measured
//! passing, which no change to the wall clock can touch. A small lead is taken, but measured from
//! only once it has lasted a day, or one small step after another would add up to a big one. The time
//! measured, never a lead, is kept in Postgres with how long any lead has lasted, so a restart neither
//! makes a wrong clock look right nor starts a hold over. A host that really was down for a while, or
//! suspended, looks the same as a small lead, and cleans up up to that much later.

use std::sync::Arc;
use std::time::{Duration, Instant};

use splint_core::unix_now;
use sqlx::{PgPool, Row};
use tokio::sync::Mutex;

use crate::Host;

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS cleanup_clock (
        only_row BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (only_row),
        believed BIGINT NOT NULL
    );
    ALTER TABLE cleanup_clock ADD COLUMN IF NOT EXISTS leading_since BIGINT;
    ALTER TABLE cleanup_clock ADD COLUMN IF NOT EXISTS ahead_since BIGINT;
";

/// More than a correction would ever be, and far less than a message's shortest life.
const MAX_AHEAD_SECS: u64 = 10 * 60;
/// Long enough for someone to see it in the logs and fix it, and short enough that a clock that was
/// really behind isn't argued with for long. Until then, cleanup goes on by the time measured.
const BELIEVE_AFTER_SECS: u64 = 24 * 60 * 60;

/// What a restart starts from. Every time in it is on the measured timeline, which a wall clock
/// can't move forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Kept {
    measured: u64,
    /// When the wall clock went ahead of what's measured at all, if it still is.
    leading_since: Option<u64>,
    /// When it went more than `MAX_AHEAD_SECS` ahead, if it still is.
    ahead_since: Option<u64>,
}

#[derive(Clone, Copy)]
struct Reading {
    /// The last time measured from, and when, as measured since this process started.
    believed: u64,
    believed_at: Duration,
    leading_since: Option<u64>,
    ahead_since: Option<u64>,
}

fn has_lasted(since: u64, measured: u64) -> bool {
    measured.saturating_sub(since) >= BELIEVE_AFTER_SECS
}

impl Reading {
    fn resume(kept: Kept) -> Self {
        Self {
            believed: kept.measured,
            believed_at: Duration::ZERO,
            leading_since: kept.leading_since,
            ahead_since: kept.ahead_since,
        }
    }

    fn kept(&self, elapsed: Duration) -> Kept {
        Kept {
            measured: self.measured(elapsed),
            leading_since: self.leading_since,
            ahead_since: self.ahead_since,
        }
    }

    fn believe(&mut self, wall: u64, elapsed: Duration) -> u64 {
        *self = Self {
            believed: wall,
            believed_at: elapsed,
            leading_since: None,
            ahead_since: None,
        };
        wall
    }

    fn measured(&self, elapsed: Duration) -> u64 {
        self.believed
            .saturating_add(elapsed.saturating_sub(self.believed_at).as_secs())
    }

    fn time_at(&mut self, wall: u64, elapsed: Duration) -> u64 {
        let measured = self.measured(elapsed);
        if wall <= measured {
            return self.believe(wall, elapsed);
        }
        let leading_since = *self.leading_since.get_or_insert(measured);
        if wall <= measured.saturating_add(MAX_AHEAD_SECS) {
            // A big lead's day starts over, so a day spent a little ahead can't approve a later jump.
            self.ahead_since = None;
            // Taken, but measured from only after a day: moving up to every small lead would let the
            // next small step start from this one.
            if has_lasted(leading_since, measured) {
                return self.believe(wall, elapsed);
            }
            return wall;
        }
        let ahead_since = *self.ahead_since.get_or_insert(measured);
        if has_lasted(ahead_since, measured) {
            return self.believe(wall, elapsed);
        }
        measured
    }
}

pub struct CleanupClock {
    started: Instant,
    reading: Mutex<Reading>,
}

fn stored(value: Option<i64>) -> Option<u64> {
    value.and_then(|value| u64::try_from(value).ok())
}

fn to_store(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(0)
}

impl CleanupClock {
    /// Starts from what was kept, or from the wall clock on a host's first start.
    pub async fn load(db: &PgPool) -> Result<Self, sqlx::Error> {
        let row = sqlx::query("SELECT believed, leading_since, ahead_since FROM cleanup_clock")
            .fetch_optional(db)
            .await?;
        let kept = match row {
            Some(row) => Kept {
                measured: stored(Some(row.try_get::<i64, _>("believed")?)).unwrap_or_else(unix_now),
                leading_since: stored(row.try_get::<Option<i64>, _>("leading_since")?),
                ahead_since: stored(row.try_get::<Option<i64>, _>("ahead_since")?),
            },
            None => Kept {
                measured: unix_now(),
                leading_since: None,
                ahead_since: None,
            },
        };
        Ok(Self {
            started: Instant::now(),
            reading: Mutex::new(Reading::resume(kept)),
        })
    }

    #[cfg(test)]
    pub fn starting_now() -> Self {
        Self {
            started: Instant::now(),
            reading: Mutex::new(Reading {
                believed: unix_now(),
                believed_at: Duration::ZERO,
                leading_since: None,
                ahead_since: None,
            }),
        }
    }

    /// The time to judge by before destroying anything. It stands in for the wall clock only while
    /// that's ahead of what's been measured.
    pub async fn now(&self) -> u64 {
        let mut reading = self.reading.lock().await;
        reading.time_at(unix_now(), self.started.elapsed())
    }

    /// What a restart may start from, after a reading like any other.
    async fn kept(&self) -> Kept {
        let mut reading = self.reading.lock().await;
        let elapsed = self.started.elapsed();
        reading.time_at(unix_now(), elapsed);
        reading.kept(elapsed)
    }

    pub async fn now_for_sql(&self) -> i64 {
        to_store(self.now().await)
    }
}

/// Says so while the clock is held at arm's length, and keeps what a restart starts from. It keeps
/// saving during a hold, so a restart neither loses the time measured nor starts the day over.
pub async fn run_keeper(host: Arc<Host>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        let kept = host.clock.kept().await;
        if let Some(since) = kept.ahead_since {
            tracing::error!(
                held_secs = kept.measured.saturating_sub(since),
                "this host's clock is ahead of the time it has measured passing, so nothing is being deleted by it"
            );
        }
        let saved = sqlx::query(
            "INSERT INTO cleanup_clock (believed, leading_since, ahead_since) VALUES ($1, $2, $3)
             ON CONFLICT (only_row) DO UPDATE
             SET believed = $1, leading_since = $2, ahead_since = $3",
        )
        .bind(to_store(kept.measured))
        .bind(kept.leading_since.map(to_store))
        .bind(kept.ahead_since.map(to_store))
        .execute(&host.db)
        .await;
        if let Err(error) = saved {
            tracing::warn!(%error, "couldn't save the time this host has measured");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;
    const EIGHT_DAYS: u64 = 8 * DAY;

    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn fresh() -> Reading {
        Reading::resume(Kept {
            measured: START,
            leading_since: None,
            ahead_since: None,
        })
    }

    /// One reading a minute, the way cleanup and the keeper read it, for a host that restarts every
    /// hour from what the keeper last kept and is down for `down` seconds each time. The wall clock
    /// reads `wall(real time)`. Returns the real time and the time judged by at each reading.
    fn run_with_restarts(hours: u64, down: u64, wall: impl Fn(u64) -> u64) -> Vec<(u64, u64)> {
        let mut kept = Kept {
            measured: START,
            leading_since: None,
            ahead_since: None,
        };
        let mut started = START;
        let mut seen = Vec::new();
        for _ in 0..hours {
            let mut reading = Reading::resume(kept);
            for minute in 1..=60 {
                let elapsed = minute * 60;
                let real = started + elapsed;
                seen.push((real, reading.time_at(wall(real), secs(elapsed))));
                kept = reading.kept(secs(elapsed));
            }
            started += 60 * 60 + down;
        }
        seen
    }

    #[test]
    fn a_clock_keeping_time_is_taken_as_it_is() {
        let mut reading = fresh();
        assert_eq!(reading.time_at(START + 60, secs(60)), START + 60);
        // A correction this small isn't a jump.
        assert_eq!(reading.time_at(START + 180, secs(120)), START + 180);
    }

    #[test]
    fn a_forward_jump_goes_by_the_time_measured_and_ends_when_the_clock_is_fixed() {
        let mut reading = fresh();
        assert_eq!(reading.time_at(START + EIGHT_DAYS, secs(5)), START + 5);
        assert_eq!(
            reading.time_at(START + EIGHT_DAYS + 7, secs(12)),
            START + 12
        );
        assert_eq!(reading.time_at(START + 20, secs(20)), START + 20);
        assert_eq!(reading.ahead_since, None);
    }

    #[test]
    fn a_jump_that_lasts_long_enough_is_believed() {
        let mut reading = fresh();
        assert_eq!(reading.time_at(START + EIGHT_DAYS, secs(1)), START + 1);
        assert_eq!(
            reading.time_at(START + EIGHT_DAYS + DAY - 1, secs(DAY)),
            START + DAY
        );
        assert_eq!(
            reading.time_at(START + EIGHT_DAYS + DAY, secs(DAY + 1)),
            START + EIGHT_DAYS + DAY
        );
    }

    #[test]
    fn small_steps_ahead_one_after_another_never_add_up() {
        let mut reading = fresh();
        let step = 9 * 60;
        for minute in 1..=60 {
            let elapsed = minute * 60;
            let wall = START + elapsed + step * minute;
            let now = reading.time_at(wall, secs(elapsed));
            assert!(
                now <= START + elapsed + MAX_AHEAD_SECS,
                "minute {minute}: {now}"
            );
        }
    }

    #[test]
    fn small_steps_ahead_never_add_up_across_restarts_either() {
        // The clock steps 9 minutes further ahead every hour, and the host restarts every hour,
        // straight back up. If a restart started from a time that took in a lead, each one would add
        // to it.
        for (real, now) in run_with_restarts(20, 0, |real| {
            real + 9 * 60 * ((real - START) / (60 * 60) + 1)
        }) {
            assert!(
                now <= real + MAX_AHEAD_SECS,
                "{}s in, {}s ahead",
                real - START,
                now.saturating_sub(real)
            );
        }
    }

    #[test]
    fn a_small_lead_that_lasts_a_day_is_measured_from_at_most_once_a_day() {
        let mut reading = fresh();
        let lead = 5 * 60;
        assert_eq!(reading.time_at(START + 2 + lead, secs(2)), START + 2 + lead);
        reading.time_at(START + DAY + 1 + lead, secs(DAY + 1));
        assert_eq!(reading.kept(secs(DAY + 1)).measured, START + DAY + 1);
        reading.time_at(START + DAY + 2 + lead, secs(DAY + 2));
        assert_eq!(reading.kept(secs(DAY + 2)).measured, START + DAY + 2 + lead);
        // Another 9 minutes on top is still taken, but measured from only after another day.
        let wall = START + DAY + 3 + lead + 9 * 60;
        assert_eq!(reading.time_at(wall, secs(DAY + 3)), wall);
        assert_eq!(reading.kept(secs(DAY + 3)).measured, START + DAY + 3 + lead);
    }

    #[test]
    fn a_host_with_a_right_clock_that_restarts_often_is_never_held_for_long() {
        // Down 90 seconds every hour, for 40 days. Each restart's downtime looks like a lead, and they
        // add up past 10 minutes, but a hold that survives restarts lets each one go after a day.
        let seen = run_with_restarts(40 * 24, 90, |real| real);
        let mut worst = 0;
        for &(real, now) in &seen {
            worst = worst.max(real.saturating_sub(now));
        }
        assert!(worst <= 3 * 60 * 60, "cleanup fell {worst}s behind");
        let last_week = seen.len() - 7 * 24 * 60;
        assert!(
            seen.iter().skip(last_week).any(|&(real, now)| now == real),
            "still held in the last week"
        );
    }

    #[test]
    fn a_jump_is_believed_a_day_later_however_often_the_host_restarts() {
        let seen = run_with_restarts(30, 0, |real| real + EIGHT_DAYS);
        let believed: Vec<_> = seen
            .iter()
            .filter(|&&(real, now)| now == real + EIGHT_DAYS)
            .collect();
        let first = believed.first().map(|&&(real, _)| real - START);
        assert!(
            first.is_some_and(|after| (DAY..DAY + 60 * 60).contains(&after)),
            "first believed {first:?}s in"
        );
    }

    #[test]
    fn a_day_a_little_ahead_does_not_count_toward_believing_a_jump() {
        let mut reading = fresh();
        assert_eq!(reading.time_at(START + EIGHT_DAYS, secs(1)), START + 1);
        assert_eq!(reading.time_at(START + 2 + 60, secs(2)), START + 62);
        assert_eq!(
            reading.time_at(START + EIGHT_DAYS + DAY + 1, secs(DAY + 1)),
            START + DAY + 1
        );
    }

    #[test]
    fn a_slow_clock_is_taken_and_measured_from() {
        let mut reading = fresh();
        for minute in 1..=60 {
            let elapsed = minute * 60;
            let wall = START + elapsed / 2;
            assert_eq!(reading.time_at(wall, secs(elapsed)), wall);
        }
        // A jump after that is measured from the slow time, not from where the clock started.
        assert_eq!(
            reading.time_at(START + EIGHT_DAYS, secs(3601)),
            START + 1800 + 1
        );
    }

    #[test]
    fn a_clock_set_back_is_taken_at_once_and_can_still_be_caught_jumping_forward() {
        let mut reading = fresh();
        assert_eq!(
            reading.time_at(START - EIGHT_DAYS, secs(1)),
            START - EIGHT_DAYS
        );
        assert_eq!(reading.time_at(START, secs(2)), START - EIGHT_DAYS + 1);
    }
}

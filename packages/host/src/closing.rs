//! A host its operator is closing: from the moment they set a date, it takes no new agents, says so on
//! its well-known page, and says when on every answer, so its own agents' Signets hear it.
//!
//! What an agent does about it is its own and its person's: moving to another host keeps its ID and
//! contacts. The host only states the date, and keeps working as before until its operator stops it.
//! The date is in the database, which the running host reads every 2 seconds, so setting or cancelling
//! it needs no restart.

use std::env;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use splint_core::host_api::CLOSING_HEADER;
use splint_core::transport::Scheme;
use splint_core::unix_now;
use sqlx::PgPool;

use crate::Host;
use crate::log_limit::LogLimit;

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS host_closing (
        only_row BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (only_row),
        closing_at BIGINT NOT NULL
    );
";

const REREAD_EVERY: Duration = Duration::from_secs(2);
const DAY_SECS: u64 = 24 * 60 * 60;
static UNREAD: LogLimit = LogLimit::new();

pub const USAGE: &str = "\
splint-host close YYYY-MM-DD  Closes this host on that day (UTC). From now it takes no new agents,
                              its page says so, and its agents hear the date, for them to move.
                              Nothing restarts, and it runs as before until you stop it.
splint-host close cancel      Takes the date back, so it takes new agents again.
splint-host close             Says whether a date is set.
Each needs this host's SPLINT_DATABASE_URL.";

/// When this host closes, as its operator last set it, or none. Read on every answer, so it's a number
/// rather than a lock: 0 is none.
#[derive(Default)]
pub struct Closing(AtomicU64);

impl Closing {
    pub fn at(&self) -> Option<u64> {
        Some(self.0.load(Ordering::Relaxed)).filter(|at| *at > 0)
    }

    fn set(&self, at: Option<u64>) {
        self.0.store(at.unwrap_or(0), Ordering::Relaxed);
    }
}

async fn read(db: &PgPool) -> Result<Option<u64>, sqlx::Error> {
    let at: Option<i64> = sqlx::query_scalar("SELECT closing_at FROM host_closing")
        .fetch_optional(db)
        .await?;
    Ok(at
        .and_then(|at| u64::try_from(at).ok())
        .filter(|at| *at > 0))
}

/// What the database says, taken at start so the first answers already say it.
pub async fn at_start(db: &PgPool) -> Result<Closing, sqlx::Error> {
    let closing = Closing::default();
    closing.set(read(db).await?);
    if let Some(at) = closing.at() {
        tracing::warn!(
            closing_at = at,
            "this host is closing, so it takes no new agents"
        );
    }
    Ok(closing)
}

/// Takes up a date set or cancelled while the host runs, and says so in the log.
pub async fn run_rereading(host: Arc<Host>) {
    loop {
        tokio::time::sleep(REREAD_EVERY).await;
        match read(&host.db).await {
            Ok(now) if now != host.closing.at() => {
                host.closing.set(now);
                match now {
                    Some(at) => tracing::warn!(
                        closing_at = at,
                        "this host is closing, so it takes no new agents, and its agents hear when"
                    ),
                    None => tracing::info!("this host's closing date was taken back"),
                }
            }
            Ok(_) => {}
            Err(error) => {
                if let Some(count) = UNREAD.due() {
                    tracing::warn!(%error, count, "couldn't read whether this host is closing");
                }
            }
        }
    }
}

/// Says the closing time on every answer while there is one, whoever asked: it's on the public page
/// anyway, and a Signet hears it on whatever it called.
pub async fn say_on_answers(
    State(host): State<Arc<Host>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    if let Some(at) = host.closing.at() {
        response.headers_mut().insert(
            HeaderName::from_static(CLOSING_HEADER),
            HeaderValue::from(at),
        );
    }
    response
}

#[derive(thiserror::Error)]
pub enum CloseError {
    #[error("{0}")]
    Usage(&'static str),
    #[error("that isn't a date: give the day as YYYY-MM-DD, such as 2027-01-31")]
    NotADate,
    #[error("that day has passed: give today or a day after it")]
    Past,
    #[error("SPLINT_DATABASE_URL has to name this host's database, as in its host.env")]
    NoDatabase,
    #[error("couldn't reach this host's database, so nothing changed: check SPLINT_DATABASE_URL")]
    Unreachable,
    #[error("couldn't write to stdout")]
    Stdout,
    #[error("{0}")]
    Transport(splint_core::transport::TransportRefused),
}

/// A `main` that returns an error prints it this way, and the operator reading needs the sentence.
impl std::fmt::Debug for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl From<sqlx::Error> for CloseError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database error");
        Self::Unreachable
    }
}

/// Runs `splint-host close ...` and says how it went. Like the key commands, it writes to stdout
/// because a person is reading.
pub async fn run(args: &[&str]) -> Result<(), CloseError> {
    let change = match args {
        ["close"] => None,
        ["close", "cancel"] => Some(None),
        ["close", day] => Some(Some(start_of(day, unix_now())?)),
        _ => return Err(CloseError::Usage(USAGE)),
    };
    let url = env::var("SPLINT_DATABASE_URL").map_err(|_| CloseError::NoDatabase)?;
    let scheme = Scheme::from_env().map_err(CloseError::Transport)?;
    let db = crate::database::connect(&url, scheme, crate::database::ONE_SHOT_PATIENCE)
        .await
        .map_err(|_| CloseError::Unreachable)?;
    sqlx::raw_sql(SCHEMA).execute(&db).await?;
    let said = match change {
        None => match read(&db).await? {
            Some(at) => format!(
                "This host closes on {}: it takes no new agents, and its agents hear the date.",
                day_of(at)
            ),
            None => "This host isn't closing.".to_owned(),
        },
        Some(None) => {
            sqlx::query("DELETE FROM host_closing").execute(&db).await?;
            "This host isn't closing now. Within a few seconds it takes new agents again, and its \
             agents hear that no date is set."
                .to_owned()
        }
        Some(Some(at)) => {
            sqlx::query(
                "INSERT INTO host_closing (only_row, closing_at) VALUES (TRUE, $1)
                 ON CONFLICT (only_row) DO UPDATE SET closing_at = $1",
            )
            .bind(i64::try_from(at).map_err(|_| CloseError::NotADate)?)
            .execute(&db)
            .await?;
            // A count that couldn't be read isn't said as none.
            let agents = match sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM agents WHERE retirement IS NULL",
            )
            .fetch_one(&db)
            .await
            {
                Ok(1) => "its 1 agent hears the date on its next call".to_owned(),
                Ok(count) => format!("its {count} agents hear the date on their next call"),
                Err(_) => "its agents hear the date on their next call".to_owned(),
            };
            format!(
                "This host closes on {} (UTC). Within a few seconds it takes no new agents, says so \
                 on its page, and {agents}, for each to move to another host with its ID and \
                 contacts. It runs as before until you stop it. `sudo splint-hostctl close cancel` \
                 takes the date back.",
                day_of(at)
            )
        }
    };
    let mut out = io::stdout().lock();
    writeln!(out, "{said}").map_err(|_| CloseError::Stdout)
}

/// Seconds since 1970 at the start of a day given as YYYY-MM-DD, in UTC, if it's today or later. A
/// day that doesn't exist, such as April 31, isn't a date rather than the next one.
fn start_of(day: &str, now: u64) -> Result<u64, CloseError> {
    let mut parts = day.split('-');
    let (Some(year), Some(month), Some(date), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CloseError::NotADate);
    };
    let digits = |text: &str, count: usize| {
        (text.len() == count && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse::<i64>().ok())
            .flatten()
    };
    let (Some(year), Some(month), Some(date)) =
        (digits(year, 4), digits(month, 2), digits(date, 2))
    else {
        return Err(CloseError::NotADate);
    };
    let days = days_from_civil(year, month, date);
    if !(1..=12).contains(&month) || date < 1 || civil_from_days(days) != (year, month, date) {
        return Err(CloseError::NotADate);
    }
    let at = u64::try_from(days)
        .ok()
        .and_then(|days| days.checked_mul(DAY_SECS))
        .ok_or(CloseError::NotADate)?;
    if at < now - now % DAY_SECS {
        return Err(CloseError::Past);
    }
    Ok(at)
}

fn day_of(at: u64) -> String {
    let days = i64::try_from(at / DAY_SECS).unwrap_or(i64::MAX);
    let (year, month, date) = civil_from_days(days);
    format!("{year:04}-{month:02}-{date:02}")
}

/// Days since 1970-01-01 of a date, and the date of a day, after Howard Hinnant's algorithms.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let from_march = if month > 2 { month - 3 } else { month + 9 };
    let of_year = (153 * from_march + 2) / 5 + day - 1;
    let of_cycle = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    era * 146_097 + of_cycle - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let of_cycle = days.rem_euclid(146_097);
    let of_era = (of_cycle - of_cycle / 1460 + of_cycle / 36_524 - of_cycle / 146_096) / 365;
    let of_year = of_cycle - (365 * of_era + of_era / 4 - of_era / 100);
    let from_march = (5 * of_year + 2) / 153;
    let day = of_year - (153 * from_march + 2) / 5 + 1;
    let month = if from_march < 10 {
        from_march + 3
    } else {
        from_march - 9
    };
    let year = of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bugs: a typo'd day rolled over to another, a past day closed the host at once, or a day came out
    /// shifted from what the operator typed.
    #[test]
    fn only_a_real_day_from_today_on_is_taken_as_typed() {
        let now = 1_795_000_000; // 2026-11-18, mid-day
        let today = now - now % DAY_SECS;
        assert_eq!(day_of(start_of("2026-11-18", now).unwrap()), "2026-11-18");
        assert_eq!(start_of("2026-11-18", now).unwrap(), today);
        assert_eq!(day_of(start_of("2028-02-29", now).unwrap()), "2028-02-29");
        assert!(matches!(start_of("2026-11-17", now), Err(CloseError::Past)));
        for typo in [
            "2027-02-29",
            "2027-04-31",
            "2027-13-01",
            "2027-00-10",
            "2027-1-01",
            "27-01-01",
            "2027-01-01-01",
            "2027/01/01",
            "+027-01-01",
            "",
        ] {
            assert!(
                matches!(start_of(typo, now), Err(CloseError::NotADate)),
                "{typo}"
            );
        }
    }
}

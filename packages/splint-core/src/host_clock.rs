//! How far this computer's clock is from its host's, read from the `Date` header every HTTP answer
//! carries, so a clock that's off is named as the problem rather than the host. A host refuses dates
//! that don't fit its clock, which a wrong clock here makes of everything signed here. What a host says
//! its time is decides nothing: it only says what to tell a person, and a host could always refuse.

use crate::CLOCK_TOLERANCE_SECS;

const SECS_A_MINUTE: u64 = 60;
const SECS_AN_HOUR: u64 = 60 * SECS_A_MINUTE;
const SECS_A_DAY: u64 = 24 * SECS_AN_HOUR;
/// Up to this far off, a person reads it in minutes, and in hours up to a couple of days.
const SAID_IN_MINUTES_UP_TO: u64 = 2 * SECS_AN_HOUR;
const SAID_IN_HOURS_UP_TO: u64 = 2 * SECS_A_DAY;
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// This computer's clock less its host's, in seconds, when that's more than a host takes, from the
/// host's `Date` and the time here as the answer came.
pub fn off_by(host_date: &str, now: u64) -> Option<i64> {
    let host = i64::try_from(http_date_secs(host_date)?).ok()?;
    let off = i64::try_from(now).ok()?.checked_sub(host)?;
    (off.unsigned_abs() > CLOCK_TOLERANCE_SECS).then_some(off)
}

/// What's wrong, in words for a person or an agent, for a clock `off` seconds ahead of the host's.
pub fn described(off: i64) -> String {
    let secs = off.unsigned_abs();
    let amount = if secs <= SAID_IN_MINUTES_UP_TO {
        counted(secs.div_ceil(SECS_A_MINUTE), "minute")
    } else if secs <= SAID_IN_HOURS_UP_TO {
        counted(secs.div_ceil(SECS_AN_HOUR), "hour")
    } else {
        counted(secs.div_ceil(SECS_A_DAY), "day")
    };
    let way = if off > 0 { "ahead of" } else { "behind" };
    format!(
        "this computer's clock is {amount} {way} its host's, so the host refuses what's signed here \
         until this computer's clock is set right, as by turning on automatic time"
    )
}

fn counted(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

/// `Sun, 06 Nov 1994 08:49:37 GMT`, the one form an HTTP server sends, as seconds since 1970.
fn http_date_secs(text: &str) -> Option<u64> {
    let mut words = text.trim().split(' ');
    let _weekday = words.next()?;
    let day: u64 = number(words.next()?, 2)?;
    let month_name = words.next()?;
    let month = MONTHS.iter().position(|name| *name == month_name)?;
    let year: u64 = number(words.next()?, 4)?;
    let mut clock = words.next()?.split(':');
    let hours: u64 = number(clock.next()?, 2)?;
    let minutes: u64 = number(clock.next()?, 2)?;
    let seconds: u64 = number(clock.next()?, 2)?;
    let whole = clock.next().is_none() && words.next() == Some("GMT") && words.next().is_none();
    let fits = (1..=31).contains(&day) && hours < 24 && minutes < 60 && seconds < 61;
    if !whole || !fits || year < 1970 {
        return None;
    }
    let days = days_since_1970(year, u64::try_from(month).ok()?.checked_add(1)?, day)?;
    days.checked_mul(SECS_A_DAY)?
        .checked_add(hours * SECS_AN_HOUR + minutes * SECS_A_MINUTE + seconds)
}

fn number(text: &str, digits: usize) -> Option<u64> {
    (text.len() == digits && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// Days from 1970-01-01 to a Gregorian date, by Howard Hinnant's
/// `days_from_civil`, kept to years from 1970.
fn days_since_1970(year: u64, month: u64, day: u64) -> Option<u64> {
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let month_from_march = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era).checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug caught: a host's `Date` read wrongly, so a right clock is blamed or a wrong one isn't, or
    /// a host's odd header taken for a time at all.
    #[test]
    fn a_hosts_date_is_read_exactly_and_nothing_else_is() {
        for (date, secs) in [
            ("Thu, 01 Jan 1970 00:00:00 GMT", 0),
            ("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777),
            ("Tue, 29 Feb 2028 23:59:59 GMT", 1_835_481_599),
            ("Fri, 13 Nov 2026 10:43:01 GMT", 1_794_566_581),
        ] {
            assert_eq!(http_date_secs(date), Some(secs), "{date}");
        }
        for odd in [
            "",
            "Sun, 06 Nov 1994 08:49:37",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nob 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 08:49:37 GMT extra",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun, 06 Nov 1969 08:49:37 GMT",
        ] {
            assert_eq!(http_date_secs(odd), None, "{odd}");
        }
    }

    /// Bug caught: a clock within what a host takes blamed, or one past it not named, either way.
    #[test]
    fn only_a_clock_past_what_a_host_takes_is_off() {
        let host = "Fri, 13 Nov 2026 10:43:01 GMT";
        let at = 1_794_566_581;
        assert_eq!(off_by(host, at + CLOCK_TOLERANCE_SECS), None);
        assert_eq!(off_by(host, at - CLOCK_TOLERANCE_SECS), None);
        assert_eq!(off_by(host, at + 600), Some(600));
        assert_eq!(off_by(host, at - 3600), Some(-3600));
        assert!(described(-600).contains("10 minutes behind"));
        assert!(described(3 * 3600).contains("3 hours ahead of"));
    }
}

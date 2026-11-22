//! Times, which Signet holds as seconds and an agent reads and writes as dates, like
//! 2026-11-04T10:30Z, and the fields of each type that hold them.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value, json};

use crate::failure::Failure;

const DAY_SECS: i64 = 86_400;
const A_TIME: &str = "a time looks like 2026-11-04T10:30Z";

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

/// A time as an agent reads it, with seconds only when there are some.
pub fn shown_time(unix: &Value) -> String {
    let Some(unix) = unix.as_i64() else {
        return unix.to_string();
    };
    let (year, month, day) = civil_from_days(unix.div_euclid(DAY_SECS));
    let of_day = unix.rem_euclid(DAY_SECS);
    let (hour, minute, second) = (of_day / 3600, of_day % 3600 / 60, of_day % 60);
    if second == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}Z")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }
}

/// Digits only, of exactly this many.
fn number(text: &str, digits: usize) -> Option<i64> {
    (text.len() == digits && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// A day that doesn't exist, such as April 31, is refused rather than rolled over to another.
fn unix_of(text: &str) -> Option<i64> {
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-');
    let (year, month, day) = (date.next()?, date.next()?, date.next()?);
    if date.next().is_some() {
        return None;
    }
    let (year, month, day) = (number(year, 4)?, number(month, 2)?, number(day, 2)?);
    let (clock, offset) = match time.strip_suffix('Z') {
        Some(clock) => (clock, 0),
        None => {
            let ((clock, zone), sign) = match time.rsplit_once('+') {
                Some(split) => (split, 1),
                None => (time.rsplit_once('-')?, -1),
            };
            let (hours, minutes) = zone.split_once(':')?;
            let (hours, minutes) = (number(hours, 2)?, number(minutes, 2)?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            (clock, sign * (hours * 3600 + minutes * 60))
        }
    };
    let mut clock = clock.split(':');
    let (hour, minute) = (number(clock.next()?, 2)?, number(clock.next()?, 2)?);
    let second = match clock.next() {
        Some(second) => number(second, 2)?,
        None => 0,
    };
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if !(1..=12).contains(&month) || civil_from_days(days) != (year, month, day) {
        return None;
    }
    Some(days * DAY_SECS + hour * 3600 + minute * 60 + second - offset)
}

fn unix_from(value: &Value) -> Result<Value, Failure> {
    value
        .as_str()
        .and_then(unix_of)
        .map(|unix| json!(unix))
        .ok_or_else(|| Failure::refused(A_TIME))
}

/// A field's times, with a refusal that says what the field takes, since a model reads it to retry.
fn times_from(name: &str, value: &Value) -> Result<Value, Failure> {
    match value {
        Value::String(_) => unix_from(value),
        Value::Array(items) => items
            .iter()
            .map(unix_from)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        _ => Err(Failure::refused(format!(
            "{name} takes times, like [\"2026-11-04T10:30Z\"]"
        ))),
    }
}

/// What these commands need from the schemas Signet runs: which fields hold times, where a pick names
/// the times field it chooses from.
pub struct Times {
    by_type: HashMap<String, HashSet<String>>,
}

impl Times {
    pub fn new(schemas: &[Value]) -> Self {
        let mut times = Self {
            by_type: HashMap::new(),
        };
        for schema in schemas {
            let mut fields = HashSet::new();
            for part in ["offer", "result", "say"] {
                if let Some(part) = schema.get(part).and_then(Value::as_object) {
                    for (name, rule) in part {
                        if rule.get("times").is_some() {
                            fields.insert(name.clone());
                        }
                    }
                }
            }
            if let Some(pick) = schema.get("pick").and_then(Value::as_object) {
                fields.extend(pick.keys().cloned());
            }
            let kind = super::text_at(schema, "/type").to_owned();
            times.by_type.insert(kind, fields);
        }
        times
    }

    fn holds_times(&self, kind: &str, name: &str) -> bool {
        self.by_type
            .get(kind)
            .is_some_and(|fields| fields.contains(name))
    }

    /// What an agent wrote, with its dates as Signet takes them. Anything else goes on as it is.
    pub fn to_signet(&self, kind: &str, given: Option<&Value>) -> Result<Value, Failure> {
        let Some(given) = given else {
            return Ok(json!({}));
        };
        let Value::Object(fields) = given else {
            return Err(Failure::refused("fields are an object"));
        };
        let mut sent = Map::new();
        for (name, value) in fields {
            let value = if self.holds_times(kind, name) {
                times_from(name, value)?
            } else {
                value.clone()
            };
            sent.insert(name.clone(), value);
        }
        Ok(Value::Object(sent))
    }

    pub fn shown(&self, kind: &str, fields: &Value) -> Value {
        let Value::Object(fields) = fields else {
            return fields.clone();
        };
        let shown = fields.iter().map(|(name, value)| {
            let value = match value {
                _ if !self.holds_times(kind, name) => value.clone(),
                Value::Array(items) => Value::Array(
                    items
                        .iter()
                        .map(|at| Value::String(shown_time(at)))
                        .collect(),
                ),
                Value::Number(_) => Value::String(shown_time(value)),
                other => other.clone(),
            };
            (name.clone(), value)
        });
        Value::Object(shown.collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bugs these catch: a time read a day or an hour off, an offset added the wrong way, and a day
    // that doesn't exist rolled over to one nobody asked for.
    #[test]
    fn a_time_reads_back_as_written_and_a_bad_one_is_refused() {
        for (written, unix) in [
            ("2026-11-04T10:30Z", 1_793_788_200),
            ("2024-02-29T00:00Z", 1_709_164_800),
            ("1970-01-01T00:00:01Z", 1),
        ] {
            assert_eq!(unix_of(written), Some(unix), "{written}");
            assert_eq!(shown_time(&json!(unix)), written);
        }
        assert_eq!(
            unix_of("2026-11-04T12:30+02:00"),
            unix_of("2026-11-04T10:30Z")
        );
        assert_eq!(
            unix_of("2026-11-04T05:30-05:00"),
            unix_of("2026-11-04T10:30Z")
        );
        for bad in [
            "2026-04-31T10:00Z",
            "2025-02-29T10:00Z",
            "2026-13-01T10:00Z",
            "2026-11-04T24:00Z",
            "2026-11-04 10:30Z",
            "2026-11-04T10:30",
            "26-11-04T10:30Z",
        ] {
            assert_eq!(unix_of(bad), None, "{bad}");
        }
    }
}

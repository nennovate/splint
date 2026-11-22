//! A line in the user's own crontab for one service, where no manager keeps it: on Linux without
//! lingering or without a user manager at all, as on many cloud machines. Linux only: on a Mac,
//! writing a crontab asks for an admin's yes in a dialog, which nobody can give over SSH, so a start
//! there would wait on it. Every minute it runs what a manager would, `splint run-service NAME`, which starts the service
//! from its launch file if it isn't running, and otherwise leaves. So it comes back within a
//! minute of a reboot or a crash, and of a start at boot that failed because the network wasn't up.
//! On Linux a crontab needs no admin.
//!
//! The line holds the agent's folder and nothing secret, as everything else is in the launch file,
//! proxy settings included, so what cron's bare environment lacks is read from there. Only lines that
//! end with this service's own mark are ever changed. Where there's no `crontab`, or it refuses, the
//! service runs as it did, and `splint status` says nothing brings it back, and why.

use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};

use super::Unit;

const CRONTAB: &str = "crontab";
/// Every minute, as cron can't start it again when it exits the way a manager does.
const EVERY_MINUTE: &str = "* * * * *";
/// What cron says, on Linux and macOS alike, to a user who has no crontab yet.
const NONE_YET: &str = "no crontab for";

/// What this user's crontab holds, or why it can't be read.
enum Listed {
    Text(String),
    NoCommand,
    Refused,
}

fn listed() -> Listed {
    let done = match Command::new(CRONTAB)
        .arg("-l")
        .stdin(Stdio::null())
        .output()
    {
        Ok(done) => done,
        Err(error) if error.kind() == ErrorKind::NotFound => return Listed::NoCommand,
        Err(_) => return Listed::Refused,
    };
    if done.status.success() {
        return match String::from_utf8(done.stdout) {
            Ok(text) => Listed::Text(text),
            Err(_) => Listed::Refused,
        };
    }
    // Anything else, such as a user cron doesn't allow, is a refusal: taking it for an empty crontab
    // would write over the user's own lines.
    if String::from_utf8_lossy(&done.stderr).contains(NONE_YET) {
        Listed::Text(String::new())
    } else {
        Listed::Refused
    }
}

fn written(text: &str) -> bool {
    let Ok(mut child) = Command::new(CRONTAB)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let sent = child
        .stdin
        .take()
        .is_some_and(|mut input| input.write_all(text.as_bytes()).is_ok());
    child.wait().is_ok_and(|status| status.success()) && sent
}

/// How a line of this service ends, which no other line does.
fn mark(unit: &Unit) -> String {
    format!("# splint {}", unit.label)
}

/// A word for `sh`, single-quoted. cron reads `%` as a line break before `sh` sees it, so a path with
/// one, or with anything else that could end the line or the quote, gets no line.
fn word(value: &str) -> Option<String> {
    (!value
        .chars()
        .any(|c| c.is_control() || c == '\'' || c == '%'))
    .then(|| format!("'{value}'"))
}

/// Settings, then the command, as a keeper runs it. Its output goes nowhere, as `run-service` says
/// "already running" every minute, and a program it starts writes to its own log.
fn line(unit: &Unit) -> Option<String> {
    let mut words = Vec::new();
    for (name, value) in unit.env() {
        words.push(format!("{name}={}", word(&value)?));
    }
    for each in unit.command() {
        words.push(word(&each)?);
    }
    Some(format!(
        "{EVERY_MINUTE} {} >/dev/null 2>&1 {}",
        words.join(" "),
        mark(unit)
    ))
}

/// The crontab with this service's line in place of any it had, or with none, every other line as it
/// was.
fn with_line(text: &str, mark: &str, line: Option<&str>) -> String {
    let mut kept = String::new();
    for each in text.lines().filter(|each| !has_mark(each, mark)) {
        kept.push_str(each);
        kept.push('\n');
    }
    if let Some(line) = line {
        kept.push_str(line);
        kept.push('\n');
    }
    kept
}

fn has_mark(text: &str, mark: &str) -> bool {
    text.lines().any(|each| each.trim_end().ends_with(mark))
}

/// Whether a crontab line is how a service comes back here.
fn here() -> bool {
    std::env::consts::OS == "linux"
}

/// Puts this service's line in, once, writing nothing when it's there already. Where it can't, the
/// service runs as it did, and `splint status` says nothing brings it back.
pub fn keep(unit: &Unit) {
    if !here() {
        return;
    }
    let (Listed::Text(text), Some(line)) = (listed(), line(unit)) else {
        return;
    };
    let mark = mark(unit);
    let ours = text.lines().filter(|each| has_mark(each, &mark)).count();
    if !(ours == 1 && text.lines().any(|each| each == line)) {
        written(&with_line(&text, &mark, Some(&line)));
    }
}

/// Takes out this service's line, if there's one, and otherwise writes nothing. A failure leaves a
/// line that starts nothing, as `splint stop` takes out the launch file too.
pub fn remove(unit: &Unit) {
    let Listed::Text(text) = listed() else {
        return;
    };
    let mark = mark(unit);
    if has_mark(&text, &mark) {
        written(&with_line(&text, &mark, None));
    }
}

pub fn is_defined(unit: &Unit) -> bool {
    matches!(listed(), Listed::Text(text) if has_mark(&text, &mark(unit)))
}

/// Why there's no line for a service, for `splint status`. On a Mac it's that launchd had no login
/// session for this user. Only SSH says so of itself, so any other cause is said to be unknown, not
/// guessed.
pub fn why_not() -> &'static str {
    if !here() {
        if std::env::var_os("SSH_CONNECTION").is_some() {
            return "only launchd starts it again on a Mac, and it keeps nothing for a session that \
                    came in over SSH, as this one did";
        }
        return "only launchd starts it again on a Mac, and it had no login session for this user, \
                for a reason Splint can't see from here, such as a sandbox or a start from outside \
                a login";
    }
    match listed() {
        Listed::NoCommand => "there's no crontab here to start it",
        Listed::Refused => "crontab refused to keep it",
        Listed::Text(_) => "your crontab has no line for it",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this catches: a start or a stop that drops, doubles or rewrites someone else's line.
    #[test]
    fn only_this_services_line_changes() {
        let mark = "# splint splint-signet.default.0a1b2c3d";
        let theirs = "MAILTO=me\n0 3 * * * backup # splint splint-signet.default.ffffffff\n";
        let line = format!("* * * * * new {mark}");
        let added = with_line(theirs, mark, Some(&line));
        assert_eq!(added, format!("{theirs}{line}\n"));
        let again = with_line(&added, mark, Some(&line));
        assert_eq!(again, added);
        let moved = with_line(
            &format!("* * * * * old {mark}\n{theirs}"),
            mark,
            Some(&line),
        );
        assert_eq!(moved, added);
        assert_eq!(with_line(&added, mark, None), theirs);
        assert_eq!(
            with_line("no newline at the end", mark, None),
            "no newline at the end\n"
        );
    }
}

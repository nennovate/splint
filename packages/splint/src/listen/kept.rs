//! `splint listen --keep -- COMMAND`: the listener as one of the agent's own kept services, beside
//! Signet, so whatever the command wakes hears of a change within seconds through a crash, a reboot
//! or an upgrade, with nothing for a runtime to supervise.
//!
//! Only a shell on this machine registers one. No tool an agent is given, no host and nothing anyone
//! sends can, as that would hand them a command to run here. What's registered is written in the
//! agent's folder, `splint status` always shows it, and the listener reads it from there each time
//! it starts, so what status shows is what runs.
//!
//! All a counterparty can cause is that command to run, as it was registered: nothing of theirs is
//! in its arguments, its environment or its input. How often is for the runtime to bound, with
//! `--gap`, as each run can cost it a turn.

use std::env;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::path::{self, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use splint_core::private_files;

use crate::failure::Failure;
use crate::home::{HOME_SETTING, Home, Installed, PROFILE_SETTING};
use crate::secrets::write_private;
use crate::services::{self, Keep, Service, Started};

pub const SERVICE: &str = "splint-listen";
const THIS_PROGRAM: &str = "splint";
/// What the keeper runs: `splint listen --kept`, which reads the command from the agent's folder.
pub const KEPT: &str = "--kept";

/// The command a kept listener runs, as it was registered.
#[derive(Serialize, Deserialize)]
pub struct Kept {
    /// The command's whole path, found when it was registered, as a keeper's PATH holds little.
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The folder it runs in: the one it was registered from, whatever folder a keeper starts in.
    pub folder: PathBuf,
    /// The least time between two runs, which the runtime chose. None unless it did.
    pub gap_secs: u64,
}

impl Kept {
    pub fn load(home: &Home) -> Result<Option<Self>, Failure> {
        let bytes = match fs::read(home.kept_listener_file()) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            Failure::refused(format!(
                "the kept listener's command in {} can't be read: remove it with {} listen --unkeep, \
                 then keep it again",
                home.kept_listener_file().display(),
                home.command()
            ))
        })
    }

    /// The command and its words, for a list a program reads.
    pub fn words(&self) -> Vec<String> {
        let mut words = vec![self.program.to_string_lossy().into_owned()];
        words.extend(self.args.iter().cloned());
        words
    }

    /// The command as one line for a person, each word that isn't plain written out in quotes, so
    /// what's shown can't pass for another command.
    pub fn shown(&self) -> String {
        let plain = |word: &str| {
            !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
        };
        self.words()
            .iter()
            .map(|word| {
                if plain(word) {
                    word.clone()
                } else {
                    format!("{word:?}")
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn gap(&self) -> Duration {
        Duration::from_secs(self.gap_secs)
    }
}

/// Registers the command and starts the listener, in place of any kept before.
pub async fn keep(
    home: &Home,
    program: &Path,
    args: &[String],
    gap: Duration,
) -> Result<String, Failure> {
    Installed::require(home)?;
    let kept = Kept {
        program: path::absolute(program)?,
        args: args.to_vec(),
        folder: env::current_dir()?,
        gap_secs: gap.as_secs(),
    };
    let bytes = serde_json::to_vec(&kept)
        .map_err(|_| Failure::refused("couldn't write down the command to keep"))?;
    // One kept before runs the command it started with, so it stops first.
    stop(home).await?;
    write_private(&home.kept_listener_file(), &bytes)?;
    let splint = home.command();
    let pace = match kept.gap_secs {
        0 => String::new(),
        1 => ", at most once a second".to_owned(),
        gap => format!(", at most once every {gap} seconds"),
    };
    let state = match start(home)? {
        Some(Started::LeftStopped) => format!(
            "It starts with {splint} start, as your person stopped Splint here, which only they \
             undo"
        ),
        _ => format!("It's running{}", crate::status::comes_back(home, SERVICE)?),
    };
    Ok(format!(
        "Kept: {command} runs for each change, from {folder}{pace}. {state}. It stops with {splint} \
         stop and starts with {splint} start, {splint} status shows it, and {splint} listen --unkeep \
         removes it. It's told only which kinds changed, in SPLINT_CHANGED, and nothing anyone else \
         wrote. Someone this agent is in an exchange with can make it run back to back, so --gap N \
         is how you bound what that costs.",
        command = kept.shown(),
        folder = kept.folder.display(),
    ))
}

/// Stops the kept listener and forgets its command.
pub async fn unkeep(home: &Home) -> Result<String, Failure> {
    let was_kept = home.kept_listener_file().exists();
    forget(home).await?;
    Ok(if was_kept {
        "No listener is kept for this agent now: its command is forgotten, and nothing starts it \
         again."
            .to_owned()
    } else {
        "No listener was kept for this agent.".to_owned()
    })
}

/// As `unkeep`, for a folder that's being reset too.
pub async fn forget(home: &Home) -> Result<(), Failure> {
    stop(home).await?;
    for file in [home.kept_listener_file(), home.kept_listener_woke()] {
        match fs::remove_file(file) {
            Err(error) if error.kind() != ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    Ok(())
}

/// Starts the kept listener, if one is registered, kept as Signet is.
pub fn start(home: &Home) -> Result<Option<Started>, Failure> {
    if Kept::load(home)?.is_none() {
        return Ok(None);
    }
    let home_dir = env::var(HOME_SETTING)
        .map_err(|_| Failure::refused(format!("{HOME_SETTING} isn't set")))?;
    let mut env = vec![(HOME_SETTING, home_dir.as_str())];
    if let Some(profile) = home.profile() {
        env.push((PROFILE_SETTING, profile));
    }
    services::start(
        home,
        &Service {
            name: SERVICE,
            binary: THIS_PROGRAM,
            args: &["listen", KEPT],
            env,
            keep: Keep::AcrossRestarts,
        },
    )
    .map(Some)
}

/// Stops it, and leaves its command registered for the next start.
pub async fn stop(home: &Home) -> Result<(), Failure> {
    services::stop(home, SERVICE, THIS_PROGRAM).await
}

pub fn is_running(home: &Home) -> Result<bool, Failure> {
    services::is_running(home, SERVICE)
}

/// Stops one from an older install, so the next start runs this build.
pub async fn stop_older(home: &Home) -> Result<(), Failure> {
    services::stop_older(home, SERVICE, THIS_PROGRAM).await
}

/// Now, in milliseconds since 1970, as a gap of seconds mustn't end most of a second early.
fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// When the kept listener last ran its command, if that's within its gap, so a listener that starts
/// again, as after a crash, holds to the gap its runtime chose.
pub fn last_woke(home: &Home, gap: Duration) -> Option<Instant> {
    if gap.is_zero() {
        return None;
    }
    let at: u64 = fs::read_to_string(home.kept_listener_woke())
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let ago = Duration::from_millis(unix_millis().saturating_sub(at));
    (ago < gap)
        .then(|| Instant::now().checked_sub(ago))
        .flatten()
}

/// Only the gap rests on it, so one that can't be written means a restart may run the command sooner.
pub fn note_woke(home: &Home) {
    let _ = write_private(
        &home.kept_listener_woke(),
        unix_millis().to_string().as_bytes(),
    );
}

/// Held for as long as a `splint listen` that says its line to a runtime runs for this agent. Its
/// runtime wakes a session on each line, so the kept listener's command can be told one is listening
/// too. A lock that can't be taken only means the command isn't told.
pub fn watching(home: &Home) -> Option<File> {
    Home::make_private(&home.run_dir()).ok()?;
    let file = private_files::open(
        OpenOptions::new().create(true).truncate(false).write(true),
        &home.watchers_lock(),
    )
    .ok()?;
    file.lock_shared().ok()?;
    Some(file)
}

/// Whether such a listener runs for this agent now.
pub fn session_listens(home: &Home) -> bool {
    let Ok(file) = OpenOptions::new().write(true).open(home.watchers_lock()) else {
        return false;
    };
    matches!(file.try_lock(), Err(TryLockError::WouldBlock))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this catches: a kept command with a space, a quote or a line break in a word shown in
    /// `splint status` as if it were other words, so a person approves a command that isn't what runs.
    #[test]
    fn a_word_that_isnt_plain_is_shown_in_quotes() {
        let kept = Kept {
            program: PathBuf::from("/usr/bin/wake"),
            args: vec![
                "--url=https://wake.example/a".to_owned(),
                "two words".to_owned(),
                "line\nbreak; rm".to_owned(),
                String::new(),
            ],
            folder: PathBuf::from("/"),
            gap_secs: 0,
        };
        let shown = kept.shown();
        assert!(shown.starts_with("/usr/bin/wake --url=https://wake.example/a "));
        assert!(shown.contains(r#" "two words" "#));
        assert!(shown.contains(r#" "line\nbreak; rm" "#) && !shown.contains('\n'));
        assert!(shown.ends_with(r#" """#));
    }
}

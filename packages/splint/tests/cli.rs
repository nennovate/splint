//! `splint` as a person first types it, before anything is set up, on every system CI builds for,
//! Windows included, where these were first seen to go wrong.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

type Outcome<T> = Result<T, Box<dyn Error>>;

/// A folder for one test, removed when it's done: `profile` is the user's own folder, and `appdata`
/// their application data, each empty to start.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Outcome<Self> {
        let path = std::env::temp_dir().join(format!("splint-cli-{name}-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(path.join("profile"))?;
        fs::create_dir_all(path.join("appdata"))?;
        Ok(Self(path))
    }

    fn profile(&self) -> PathBuf {
        self.0.join("profile")
    }

    fn appdata(&self) -> PathBuf {
        self.0.join("appdata")
    }

    fn splint(&self, args: &[&str]) -> Outcome<Output> {
        self.splint_with(args, &[])
    }

    fn splint_with(&self, args: &[&str], settings: &[(&str, &str)]) -> Outcome<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_splint"))
            .args(args)
            .env("HOME", self.profile())
            .env("USERPROFILE", self.profile())
            .env("LOCALAPPDATA", self.appdata())
            .env("APPDATA", self.appdata())
            .envs(settings.iter().copied())
            .env_remove("SPLINT_AS")
            .output()?)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The bug this catches: `splint join --help` was seen exiting 1 on Windows, so an agent reading
/// the exit code took a command's help for a failure. Each command's help is its own usage.
#[test]
fn help_after_a_command_prints_its_usage_and_succeeds() -> Outcome<()> {
    let scratch = Scratch::new("help")?;
    for (command, flag) in [("join", "--help"), ("status", "-h"), ("controls", "--help")] {
        let said = scratch.splint(&[command, flag])?;
        let text = String::from_utf8(said.stdout)?;
        assert!(
            said.status.success() && text.contains(&format!("splint {command} ")),
            "{command} {flag}: {text}{}",
            String::from_utf8_lossy(&said.stderr)
        );
    }
    Ok(())
}

/// The bug this catches: on Windows the Splint folder was under `LOCALAPPDATA`, which Windows sends,
/// for a packaged app such as one from the Store, to that app's own private folder, so the Task
/// Scheduler tasks that keep Signet running found no program there. It's `.splint` in the profile
/// folder, as `~/.splint` is elsewhere, and nothing under application data is read.
#[test]
fn the_splint_folder_is_in_the_profile_folder_not_application_data() -> Outcome<()> {
    let scratch = Scratch::new("folder")?;
    fs::create_dir_all(scratch.profile().join(".splint/profiles/in-profile"))?;
    for folder in ["splint", ".splint"] {
        fs::create_dir_all(scratch.appdata().join(folder).join("profiles/in-appdata"))?;
    }
    let said = scratch.splint(&["profiles"])?;
    let text = String::from_utf8(said.stdout)?;
    assert!(
        said.status.success() && text.contains("in-profile") && !text.contains("in-appdata"),
        "{text}{}",
        String::from_utf8_lossy(&said.stderr)
    );
    Ok(())
}

/// The bugs this catches, on Windows, where nothing starts what runs here at login and the next
/// command that needs it does: a command starting what its person stopped, and `status` starting what
/// it's asked about, so it could never say it was down. Splint on this computer stands in for all of
/// them, as it starts with no agent set up. Its launch file, left by an earlier start, says it was
/// running, and its log appears the moment anything starts it.
#[cfg(windows)]
#[test]
fn only_a_command_that_needs_it_starts_what_a_sign_out_stopped_and_never_what_its_person_did()
-> Outcome<()> {
    let scratch = Scratch::new("comes-back")?;
    let run = scratch.profile().join(".splint/run");
    fs::create_dir_all(&run)?;
    fs::write(run.join("splint-computer.json"), b"{}")?;
    let log = run.join("splint-computer.log");
    // A port of its own, so this runs beside anything holding the usual one.
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port()
        .to_string();
    let settings = [
        ("SPLINT_COMPUTER_PORT", port.as_str()),
        ("SPLINT_COMPUTER_SIGN_IN", "file"),
    ];
    let splint = |args: &[&str]| scratch.splint_with(args, &settings);
    fs::write(run.join("stopped"), b"")?;
    splint(&["check"])?;
    let started_what_was_stopped = log.exists();
    fs::remove_file(run.join("stopped"))?;
    splint(&["status"])?;
    let status_started_it = log.exists();
    splint(&["check"])?;
    let check_started_it = log.exists();
    // What this started, it stops.
    let stopped = splint(&["stop"])?;
    assert!(
        !started_what_was_stopped,
        "check started what its person stopped"
    );
    assert!(!status_started_it, "status started what it reports on");
    assert!(
        check_started_it && stopped.status.success(),
        "check didn't start what a sign-out left down: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    Ok(())
}

//! Splint's services as a person and their keepers run them: `splint stop` with what a keeper left in
//! the agent's folder, and a second copy of a service finding the one running. The system's own tools
//! are stand-ins on PATH, so nothing here reaches this machine's crontab, launchd or systemd.
#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use aws_lc_rs::digest;

type Outcome<T> = Result<T, Box<dyn Error>>;

/// A folder for one test's home and stand-ins, removed when it's done.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Outcome<Self> {
        let path = std::env::temp_dir().join(format!("splint-{name}-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A program on PATH that answers as `script` says.
fn stand_in(folder: &Path, name: &str, script: &str) -> Outcome<()> {
    let path = folder.join(name);
    fs::write(&path, format!("#!/bin/sh\n{script}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// The name a keeper's files have for this service of the agent whose folder is `run`, as `splint`
/// gives them, so a stand-in's record shows it found the one here.
fn label(run: &Path, service: &str) -> String {
    let hash = digest::digest(&digest::SHA256, run.as_os_str().as_bytes());
    let short: String = hash
        .as_ref()
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{service}.default.{short}")
}

fn splint(home: &Path, stand_ins: &Path, args: &[&str]) -> Outcome<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_splint"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", format!("{}:/usr/bin:/bin", stand_ins.display()))
        .output()?)
}

/// The bugs this catches: a Task Scheduler task a person deleted in Task Scheduler itself made `splint
/// stop` fail on it every time, before it reached Signet, so Signet was left running; and a task that
/// is there left in place, so it starts the service again at the next login.
#[test]
fn splint_stop_deletes_a_task_that_is_there_and_goes_past_one_already_gone() {
    // What schtasks says of a task that isn't there, whatever it's asked to do with it, and of one
    // that is.
    let gone = "echo 'ERROR: The system cannot find the file specified.' >&2\nexit 1";
    let there = "exit 0";
    for (schtasks, deleted) in [(gone, false), (there, true)] {
        let scratch = Scratch::new("stop-task").unwrap();
        let home = scratch.0.join("home");
        let run = home.join(".splint").join("run");
        fs::create_dir_all(&run).unwrap();
        fs::write(home.join(".splint").join("join.json"), "{}").unwrap();
        let definition = run.join(format!("{}.task.xml", label(&run, "splint-signet")));
        fs::write(&definition, "").unwrap();

        let stand_ins = scratch.0.join("stand-ins");
        fs::create_dir(&stand_ins).unwrap();
        let asked = scratch.0.join("schtasks-asked");
        stand_in(
            &stand_ins,
            "schtasks",
            &format!("echo \"$*\" >> '{}'\n{schtasks}", asked.display()),
        )
        .unwrap();
        for tool in ["crontab", "launchctl", "systemctl"] {
            stand_in(&stand_ins, tool, "exit 1").unwrap();
        }

        let stopped = splint(&home, &stand_ins, &["stop"]).unwrap();
        assert!(
            stopped.status.success(),
            "{}",
            String::from_utf8_lossy(&stopped.stderr)
        );
        let asked = fs::read_to_string(&asked).unwrap_or_default();
        assert!(asked.contains("/TN \\Splint\\splint-signet."), "{asked}");
        assert_eq!(
            asked.contains("/Delete /TN \\Splint\\splint-signet."),
            deleted,
            "{asked}"
        );
        assert!(!definition.exists(), "its definition is still there");
    }
}

/// The bug this catches: a lock held by another copy that hasn't written its pid yet, as for a moment
/// as it starts, taken as this process's own, so two copies of `splint auto` would both run and both
/// sign.
#[test]
fn a_lock_held_by_another_copy_before_its_pid_is_written_isnt_taken_as_ours() {
    let scratch = Scratch::new("services-held").unwrap();
    let home = scratch.0.join("home");
    let run = home.join(".splint").join("run");
    fs::create_dir_all(&run).unwrap();
    let lock = fs::File::create(run.join("splint-auto.lock")).unwrap();
    lock.try_lock().unwrap();

    let mut auto = Command::new(env!("CARGO_BIN_EXE_splint"))
        .arg("auto")
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while auto.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let finished = auto.try_wait().unwrap().is_some();
    if !finished {
        let _ = auto.kill();
    }
    let said = auto.wait_with_output().unwrap();
    assert!(finished, "a second splint auto ran as the only copy");
    assert!(
        String::from_utf8_lossy(&said.stdout).contains("already running"),
        "{}",
        String::from_utf8_lossy(&said.stdout)
    );
}

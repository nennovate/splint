//! The Task Scheduler tasks an earlier build made on Windows, which started each service at login. An
//! unsigned program that starts itself at login is what Windows' malware checks quarantine, so nothing
//! makes one now, and this only deletes one an earlier build left. Such a build kept the task's
//! definition in the agent's own folder too, which is how one is known to be there without asking Task
//! Scheduler.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::Unit;
use crate::failure::Failure;

const SCHTASKS: &str = "schtasks";
/// The folder in Task Scheduler that an earlier build's tasks went in.
const FOLDER: &str = "\\Splint\\";

fn task_name(unit: &Unit) -> String {
    format!("{FOLDER}{}", unit.label)
}

fn definition(unit: &Unit) -> PathBuf {
    unit.run_dir.join(format!("{}.task.xml", unit.label))
}

pub fn is_here() -> bool {
    env::consts::OS == "windows"
}

/// Runs `schtasks`, and says what it said if it failed.
fn schtasks(args: &[&str]) -> Result<(), Failure> {
    let done = Command::new(SCHTASKS)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if done.status.success() {
        return Ok(());
    }
    Err(Failure::refused(format!(
        "{SCHTASKS} {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&done.stderr).trim()
    )))
}

/// Whether Task Scheduler has the task. One a person deleted there themselves isn't, though its
/// definition is still here.
fn is_scheduled(name: &str) -> Result<bool, Failure> {
    Ok(Command::new(SCHTASKS)
        .args(["/Query", "/TN", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

/// Nothing to do unless an earlier build made one here. Once it's deleted, nothing starts it at login.
/// A task already gone from Task Scheduler has nothing to delete, or `splint stop` would fail on it
/// each time and leave Signet running.
pub fn remove(unit: &Unit) -> Result<(), Failure> {
    let path = definition(unit);
    if !path.exists() {
        return Ok(());
    }
    let name = task_name(unit);
    if is_scheduled(&name)? {
        schtasks(&["/Delete", "/TN", &name, "/F"])?;
    }
    fs::remove_file(path)?;
    Ok(())
}

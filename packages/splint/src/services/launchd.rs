//! A launchd agent for one service, in the logged-in user's own domain: started at once and at each
//! login, and again after it exits with a failure. One that exits cleanly, as `splint auto` does once
//! its folder has gone, stays stopped.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::{Unit, manage, plain, user_id};
use crate::failure::Failure;
use crate::secrets::write_private;

const AGENTS: &str = "Library/LaunchAgents";

fn plist_of(unit: &Unit) -> PathBuf {
    unit.user_home
        .join(AGENTS)
        .join(format!("{}.plist", unit.label))
}

/// The logged-in user's domain, which only a login session has, so not one over SSH alone.
fn domain() -> Result<String, Failure> {
    Ok(format!("gui/{}", user_id()?))
}

fn is_loaded(target: &str) -> Result<bool, Failure> {
    Ok(Command::new("launchctl")
        .args(["print", target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

pub fn is_here() -> bool {
    env::consts::OS == "macos" && domain().is_ok_and(|domain| is_loaded(&domain).unwrap_or(false))
}

pub fn is_defined(unit: &Unit) -> bool {
    plist_of(unit).exists()
}

fn xml(value: &str) -> Result<String, Failure> {
    Ok(plain(value)?
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;"))
}

fn plist(unit: &Unit) -> Result<String, Failure> {
    let mut arguments = String::new();
    for word in unit.command() {
        arguments.push_str(&format!("    <string>{}</string>\n", xml(&word)?));
    }
    let mut environment = String::new();
    for (name, value) in unit.env() {
        environment.push_str(&format!(
            "    <key>{name}</key>\n    <string>{}</string>\n",
            xml(&value)?
        ));
    }
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{arguments}  </array>
  <key>EnvironmentVariables</key>
  <dict>
{environment}  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
</dict>
</plist>
"#,
        label = xml(&unit.label)?,
    ))
}

pub fn install(unit: &Unit) -> Result<(), Failure> {
    let path = plist_of(unit);
    if let Some(agents) = path.parent() {
        fs::create_dir_all(agents)?;
    }
    write_private(&path, plist(unit)?.as_bytes())?;
    manage(
        "launchctl",
        &["bootstrap", &domain()?, &path.to_string_lossy()],
    )
}

/// Nothing to do unless one was installed here. Once it's out, launchd starts it no more.
pub fn remove(unit: &Unit) -> Result<(), Failure> {
    let path = plist_of(unit);
    if !path.exists() {
        return Ok(());
    }
    let target = format!("{}/{}", domain()?, unit.label);
    if is_loaded(&target)? {
        manage("launchctl", &["bootout", &target])?;
    }
    fs::remove_file(path)?;
    Ok(())
}

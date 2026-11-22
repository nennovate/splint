//! A `systemd --user` unit for one service: enabled, so it starts with the user's manager, and
//! restarted after it exits with a failure. One that exits cleanly, as `splint auto` does once its
//! folder has gone, stays stopped. The unit file stays in the agent's own folder and is linked in, so
//! nothing of an agent's lives anywhere else but that link.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::{Unit, manage, plain, user_id};
use crate::failure::Failure;
use crate::secrets::write_private;

fn unit_name(unit: &Unit) -> String {
    format!("{}.service", unit.label)
}

fn unit_file(unit: &Unit) -> PathBuf {
    unit.run_dir.join(unit_name(unit))
}

fn asks(args: &[&str]) -> bool {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A user manager that answers, which containers and sessions without one don't have.
fn has_user_manager() -> bool {
    env::consts::OS == "linux" && asks(&["show-environment"])
}

/// Unless this user lingers, systemd stops their manager, and every unit in it, when their last
/// session ends, and starts it again only at their next login. Someone who joins over SSH and logs out
/// would leave the agent offline, which running detached doesn't.
fn lingers() -> bool {
    let Ok(user) = user_id() else {
        return false;
    };
    Command::new("loginctl")
        .args(["show-user", &user, "--property=Linger", "--value"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|done| done.status.success() && done.stdout.trim_ascii() == b"yes")
}

pub fn is_here() -> bool {
    has_user_manager() && lingers()
}

pub fn stops_at_logout() -> bool {
    has_user_manager() && !lingers()
}

pub fn is_defined(unit: &Unit) -> bool {
    unit_file(unit).exists()
}

/// A word of `ExecStart=`, quoted, where systemd expands both `%` specifiers and `$` variables.
fn command_word(value: &str) -> Result<String, Failure> {
    Ok(format!(
        "\"{}\"",
        plain(value)?.replace('%', "%%").replace('$', "$$")
    ))
}

/// An `Environment=` setting, quoted. systemd expands `%` specifiers there and not `$`, so a `$$` would
/// reach the program as it's written.
fn setting(name: &str, value: &str) -> Result<String, Failure> {
    Ok(format!("\"{name}={}\"", plain(value)?.replace('%', "%%")))
}

fn unit_text(unit: &Unit) -> Result<String, Failure> {
    let mut command = Vec::new();
    for word in unit.command() {
        command.push(command_word(&word)?);
    }
    let mut environment = Vec::new();
    for (name, value) in unit.env() {
        environment.push(setting(name, &value)?);
    }
    Ok(format!(
        "\
[Unit]
Description=Splint {name}, kept running for {label}

[Service]
Type=simple
ExecStart={command}
Environment={environment}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
",
        name = unit.name,
        label = unit.label,
        command = command.join(" "),
        environment = environment.join(" "),
    ))
}

pub fn install(unit: &Unit) -> Result<(), Failure> {
    let path = unit_file(unit);
    write_private(&path, unit_text(unit)?.as_bytes())?;
    manage(
        "systemctl",
        &["--user", "enable", "--now", &path.to_string_lossy()],
    )
}

/// Nothing to do unless one was installed here. Once it's disabled, systemd starts it no more.
pub fn remove(unit: &Unit) -> Result<(), Failure> {
    let path = unit_file(unit);
    if !path.exists() {
        return Ok(());
    }
    let name = unit_name(unit);
    if asks(&["is-active", &name]) || asks(&["is-enabled", &name]) {
        manage("systemctl", &["--user", "disable", "--now", &name])?;
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The finding: `$` was doubled in `Environment=` too, where systemd leaves it, so a home folder
    /// with a `$` in its name reached `run-service` as another folder, and the agent never started.
    #[test]
    fn a_dollar_reaches_the_program_as_written_in_each_place() {
        let home = "/home/a$b%c";
        let unit = Unit {
            label: "splint-signet.default.00000000".to_owned(),
            name: "splint-signet".to_owned(),
            user_home: PathBuf::from(home),
            profile: None,
            splint: PathBuf::from(format!("{home}/.splint/bin/splint")),
            log: PathBuf::from(format!("{home}/.splint/run/splint-signet.log")),
            run_dir: PathBuf::from(format!("{home}/.splint/run")),
        };
        let text = unit_text(&unit).unwrap();
        let line = |key: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap()
                .to_owned()
        };
        assert!(line("ExecStart=").contains("/home/a$$b%%c/.splint/bin/splint"));
        // The setting is named for the system the test runs on, though only Linux has systemd.
        let home_setting = format!("\"{}=/home/a$b%%c\"", crate::home::HOME_SETTING);
        assert!(line("Environment=").contains(&home_setting));
    }
}

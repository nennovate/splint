//! The programs that keep running after a command ends, each with a lock and a log.
//!
//! Signet and `splint auto` are the user's own services where the system has a manager for them, so it
//! restarts them after a crash and starts them at login: a launchd agent on macOS, a `systemd --user`
//! unit on Linux, if that user's manager outlasts their logging out. Where there's neither, as in most
//! containers and many cloud machines, they run detached as the host does, and a line in the user's
//! crontab starts them again within a minute of a reboot or a crash, where there's a crontab that takes
//! one. On Windows `run-service` itself starts the program again after a crash, as Windows has no
//! manager of a user's own services that does, and nothing starts one at login yet: the next `splint`
//! command after a sign-out or a restart starts again what was running, until the Windows builds are
//! code-signed. `splint status` says which.
//!
//! Whatever starts one runs `splint run-service NAME`, which reads what to run from a file only this user
//! can read and becomes that program, holding `run/NAME.lock` as it does. Only a running copy holds
//! that lock, so it alone says whether one runs and which process to stop, and a second copy leaves. So no token is in a service's definition or in anyone's
//! arguments, and the program's environment holds what it was given and nothing else.

mod crontab;
mod launchd;
mod scheduler;
mod systemd;

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::future::Future;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
#[cfg(unix)]
use std::time::SystemTime;
use std::time::{Duration, Instant};

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};
use splint_core::private_files;

use crate::failure::Failure;
use crate::home::{HOME_SETTING, Home, PROFILE_SETTING};
use crate::secrets::write_private;

const POLL: Duration = Duration::from_millis(100);
/// How each program's `main` starts the line it leaves in its log as it refuses to run: Signet's, and
/// Splint's own, as Splint on the computer is.
const REFUSAL_LINES: [&str; 2] = ["Error: ", "splint: "];
/// What ends the line a keeper on Windows writes as it starts a program again, after that program's
/// own last words, which are still why it stopped.
const STARTS_AGAIN: &str = "so it starts again in";
/// More than the last line of a log takes, and all of a refusal that's shown.
const LOG_TAIL_BYTES: u64 = 4096;
const MOST_REFUSAL_CHARS: usize = 600;
const STOP_WAIT: Duration = Duration::from_secs(5);
/// Far longer than anything that only checks the lock holds it.
const TAKE_WAIT: Duration = Duration::from_secs(2);
/// What a service manager runs, which then becomes the program.
pub const RUN_SERVICE: &str = "run-service";
const NAME_FOR_THE_DEFAULT: &str = "default";
/// Enough of a hash of the agent's folder to tell two homes' services apart on one machine.
const FOLDER_HASH_BYTES: usize = 4;
/// What an install from before locks ran, by its pid file's name and its program's. It wrote
/// `run/NAME.pid` as it started each, and nothing else says one still runs. There was none on Windows.
#[cfg(unix)]
const BEFORE_LOCKS: [(&str, &str); 3] = [
    ("splint-signet", "splint-signet"),
    ("splint-auto", "splint"),
    ("splint-host", "splint-host"),
];
/// Between starting a program and writing its pid down, with `ps` counting in whole seconds.
#[cfg(unix)]
const PID_WRITTEN_WITHIN: Duration = Duration::from_secs(2);
#[cfg(unix)]
const SECS_A_DAY: u64 = 24 * 60 * 60;
/// Set by `run-service` on Windows for the program it keeps, which can't hold the lock itself as it
/// isn't the same process, so the program knows the lock's holder is keeping it and not another copy.
#[cfg(windows)]
const KEPT_BY: &str = "SPLINT_KEPT_BY";
/// After the program a Windows `run-service` keeps crashes: the first wait, doubled each time up to
/// the last, as systemd waits 2 s.
#[cfg(windows)]
const RESTART_WAITS: (Duration, Duration) = (Duration::from_secs(2), Duration::from_secs(60));

pub struct Service<'a> {
    pub name: &'static str,
    pub binary: &'static str,
    pub args: &'a [&'a str],
    pub env: Vec<(&'a str, &'a str)>,
    pub keep: Keep,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    /// Until it's stopped or exits, as for the host, whose database doesn't come back by itself either.
    UntilStopped,
    /// Started again after a crash, and at login, wherever this system can.
    AcrossRestarts,
}

/// What brings a service back after a crash or a restart.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Keeper {
    Launchd,
    Systemd,
    /// Windows: `run-service` starts the program again after a crash, and the next `splint` command
    /// after a sign-out or a restart, as nothing starts it at login there yet.
    OnDemand,
    Nothing,
}

impl Keeper {
    /// The manager for this user's own services that this system has running, if any.
    pub fn here() -> Self {
        if launchd::is_here() {
            Self::Launchd
        } else if scheduler::is_here() {
            Self::OnDemand
        } else if systemd::is_here() {
            Self::Systemd
        } else {
            Self::Nothing
        }
    }
}

/// A manager for this user's own services that would keep them, if it outlasted their logging out.
/// `splint status` says how to make it.
pub fn stops_at_logout() -> bool {
    systemd::stops_at_logout()
}

/// What brings a service back, from what its last start left.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeptBy {
    /// This system's manager for the user's own services.
    Manager,
    /// A line in the user's crontab, where there's no such manager.
    Crontab,
    /// On Windows, its keeper after a crash, and the next `splint` command after a sign-out or a
    /// restart.
    NextCommand,
    Nothing,
}

pub fn kept_by(home: &Home, name: &str) -> Result<KeptBy, Failure> {
    if Keeper::here() == Keeper::OnDemand {
        return Ok(KeptBy::NextCommand);
    }
    let unit = Unit::of(home, name)?;
    Ok(
        if launchd::is_defined(&unit) || systemd::is_defined(&unit) {
            KeptBy::Manager
        } else if crontab::is_defined(&unit) {
            KeptBy::Crontab
        } else {
            KeptBy::Nothing
        },
    )
}

/// On Windows, said wherever an agent is told how its Signet keeps running, as nothing starts it at
/// login there yet. Nothing elsewhere.
pub fn not_at_login() -> &'static str {
    if Keeper::here() == Keeper::OnDemand {
        " It doesn't start at login on Windows yet, so after a sign-out or a restart the next splint \
         command that needs it, such as check, starts it again."
    } else {
        ""
    }
}

/// Deletes the tasks an earlier build made to start these services at login, wherever one is left.
/// An upgrade otherwise leaves one running whatever program is at that path at each login.
#[cfg(windows)]
pub fn forget_old_tasks(home: &Home, names: &[&str]) {
    for name in names {
        if let Ok(unit) = Unit::of(home, name) {
            let _ = scheduler::remove(&unit);
        }
    }
}

/// Whether it was started and never stopped, as its launch file says, but isn't running now, as after
/// a sign-out or a restart on Windows, where nothing starts it at login.
#[cfg(windows)]
pub fn left_down(home: &Home, name: &str) -> bool {
    home.launch_file(name).exists() && matches!(is_running(home, name), Ok(false))
}

/// Whether this process is a program a Windows keeper runs, as `splint auto` is, which starts nothing
/// itself.
#[cfg(windows)]
pub fn run_by_a_keeper() -> bool {
    env::var_os(KEPT_BY).is_some()
}

/// Why there's no crontab line to start a service again, for `splint status`.
pub fn why_no_crontab_line() -> &'static str {
    crontab::why_not()
}

/// What a service manager needs to start one service of one agent.
struct Unit {
    /// Unique to this service of this agent's folder, so homes and profiles never share one.
    label: String,
    name: String,
    /// The folder `HOME` names, which may not be this account's own, as when testing.
    user_home: PathBuf,
    profile: Option<String>,
    splint: PathBuf,
    log: PathBuf,
    run_dir: PathBuf,
}

impl Unit {
    fn of(home: &Home, name: &str) -> Result<Self, Failure> {
        let run_dir = home.run_dir();
        let hash = digest::digest(&digest::SHA256, run_dir.as_os_str().as_encoded_bytes());
        let short: String = hash
            .as_ref()
            .iter()
            .take(FOLDER_HASH_BYTES)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let profile = home.profile().map(str::to_owned);
        Ok(Self {
            label: format!(
                "{name}.{}.{short}",
                profile.as_deref().unwrap_or(NAME_FOR_THE_DEFAULT)
            ),
            name: name.to_owned(),
            user_home: home.user_home()?.to_owned(),
            profile,
            splint: env::current_exe()?,
            log: home.log_file(name),
            run_dir,
        })
    }

    /// What every keeper sets, so `run-service` finds this agent's folder: nothing secret.
    fn env(&self) -> Vec<(&'static str, String)> {
        let mut env = vec![(HOME_SETTING, self.user_home.to_string_lossy().into_owned())];
        if let Some(profile) = &self.profile {
            env.push((PROFILE_SETTING, profile.clone()));
        }
        env
    }

    fn command(&self) -> Vec<String> {
        vec![
            self.splint.to_string_lossy().into_owned(),
            RUN_SERVICE.to_owned(),
            self.name.clone(),
        ]
    }
}

/// The proxy and the certificates this computer uses to reach the internet, carried from the shell
/// that starts a service. Without them, an agent whose only way out is a proxy joins, and then its
/// Signet can't reach its host. A proxy's address can hold its password, which is why these go only
/// into the launch file, never into a service's definition.
pub(crate) const HOW_THIS_COMPUTER_REACHES_OUT: [&str; 10] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// What a Windows program needs from its environment to start at all, carried where every other
/// setting is cleared: without `SystemRoot`, Windows can't load what a program needs to reach the
/// network, and without `LOCALAPPDATA` and `APPDATA` a program can't find its own cache or settings,
/// as Go's `os.UserCacheDir` can't. None of these is secret. Nothing on Unix.
pub fn what_every_program_needs() -> Vec<(&'static str, OsString)> {
    #[cfg(windows)]
    {
        [
            "SystemRoot",
            "windir",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
        ]
        .into_iter()
        .filter_map(|name| env::var_os(name).map(|value| (name, value)))
        .collect()
    }
    #[cfg(unix)]
    {
        Vec::new()
    }
}

/// What `run-service` becomes. It holds the program's settings, tokens among them.
#[derive(Serialize, Deserialize)]
struct Launch {
    binary: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

/// The settings a service was last started with, for running one of its own commands beside it. None
/// if it has never been started, or was stopped.
pub fn settings_of(home: &Home, name: &str) -> Result<Option<Vec<(String, String)>>, Failure> {
    let bytes = match fs::read(home.launch_file(name)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    serde_json::from_slice::<Launch>(&bytes)
        .map(|launch| Some(launch.env))
        .map_err(|_| Failure::refused(format!("how {name} starts can't be read")))
}

/// The other programs are installed beside this one.
pub fn beside_this_program(binary: &str) -> Result<PathBuf, Failure> {
    let this = env::current_exe()?;
    let dir = this
        .parent()
        .ok_or_else(|| Failure::refused("can't tell where splint is installed"))?;
    Ok(dir.join(format!("{binary}{}", env::consts::EXE_SUFFIX)))
}

/// Which process holds a service's lock. Only the running program does, for as long as it runs, so a
/// lock nobody holds is a service that's stopped, whatever a file says.
enum Holder {
    Nobody,
    /// Its pid, which it writes once it holds the lock, so none for a moment as it starts.
    Running(Option<u32>),
}

/// What's written in a lock file, if it's a pid.
fn pid_in(text: &str) -> Option<u32> {
    text.trim().parse().ok().filter(|&pid| pid > 0)
}

fn written_pid(path: &Path) -> Result<Option<u32>, Failure> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(pid_in(&text)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Asks the lock, which takes it for a moment: whoever starts the service tries again for longer
/// than that.
fn holder(home: &Home, name: &str) -> Result<Holder, Failure> {
    let path = home.lock_file(name);
    let file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Holder::Nobody),
        Err(error) => return Err(error.into()),
    };
    match file.try_lock() {
        Ok(()) => {
            // The pid of one that ended without `stop`, which may be another process's by now.
            file.set_len(0)?;
            Ok(Holder::Nobody)
        }
        Err(TryLockError::WouldBlock) => Ok(Holder::Running(written_pid(&pid_file(home, name))?)),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

/// Where the lock's holder writes its pid: in the lock itself on Unix, where a lock doesn't stop
/// others reading. On Windows it does, so beside it.
fn pid_file(home: &Home, name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        home.lock_file(name)
    }
    #[cfg(windows)]
    {
        home.run_dir().join(format!("{name}.holder"))
    }
}

/// Writes this process's pid where `pid_file` says, once it holds `lock`.
fn write_pid(home: &Home, name: &str, lock: &File) -> Result<(), Failure> {
    let pid = process::id().to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        let _ = (home, name);
        lock.write_all_at(pid.as_bytes(), 0)?;
    }
    #[cfg(windows)]
    {
        let _ = lock;
        write_private(&pid_file(home, name), pid.as_bytes())?;
    }
    Ok(())
}

/// Whether the copy holding the lock is this process, or on Windows the `run-service` keeping it.
fn holds_it_for_us(written: Option<u32>) -> bool {
    #[cfg(windows)]
    let kept_by = env::var(KEPT_BY).ok().and_then(|pid| pid_in(&pid));
    #[cfg(unix)]
    let kept_by = None;
    written.is_some() && (written == Some(process::id()) || written == kept_by)
}

enum Taken {
    /// This process holds it now, with its pid written in.
    Now(File),
    /// This process held it already, as `run-service` took it before becoming this program.
    Already,
    Elsewhere,
}

/// Takes a service's lock for this process, unless another holds it. A check that holds it for a
/// moment is waited out, so only a running copy counts.
fn take(home: &Home, name: &str) -> Result<Taken, Failure> {
    let path = home.lock_file(name);
    let file = private_files::open(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
        &path,
    )?;
    let deadline = Instant::now() + TAKE_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => {
                file.set_len(0)?;
                write_pid(home, name, &file)?;
                return Ok(Taken::Now(file));
            }
            Err(TryLockError::WouldBlock) => {
                if holds_it_for_us(written_pid(&pid_file(home, name))?) {
                    return Ok(Taken::Already);
                }
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Ok(Taken::Elsewhere);
        }
        std::thread::sleep(POLL);
    }
}

/// Held for as long as this process runs as the one copy of a service.
pub struct OnlyCopy {
    _lock: Option<File>,
}

/// This process as the only copy of a service, or nothing if another copy is running.
pub fn the_only_copy(home: &Home, name: &str) -> Result<Option<OnlyCopy>, Failure> {
    Home::make_private(&home.run_dir())?;
    Ok(match take(home, name)? {
        Taken::Now(file) => Some(OnlyCopy { _lock: Some(file) }),
        Taken::Already => Some(OnlyCopy { _lock: None }),
        Taken::Elsewhere => None,
    })
}

#[cfg(unix)]
fn listing(pid: u32) -> Result<String, Failure> {
    let answer = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "stat=,comm="])
        .output()?;
    Ok(String::from_utf8_lossy(&answer.stdout).into_owned())
}

/// The lock says which process runs a service, and this is a second check before signalling one:
/// a pid read in the moment a new copy takes the lock, before it writes its own, is a stopped one's.
#[cfg(unix)]
fn is_this_program(pid: u32, binary: &str) -> Result<bool, Failure> {
    Ok(listed_as(&listing(pid)?, binary))
}

/// On Windows the lock's holder is always `run-service`, which is `splint` keeping the program, so
/// that's what the process must be.
#[cfg(windows)]
fn is_this_program(pid: u32, _binary: &str) -> Result<bool, Failure> {
    let answer = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .stdin(Stdio::null())
        .output()?;
    let splint = format!("splint{}", env::consts::EXE_SUFFIX);
    Ok(String::from_utf8_lossy(&answer.stdout)
        .lines()
        .any(|line| in_tasklist(line, pid, &splint)))
}

/// Whether a line of `tasklist /FO CSV` is that process, by its pid and its program's name.
#[cfg(any(windows, test))]
fn in_tasklist(line: &str, pid: u32, program: &str) -> bool {
    let fields: Vec<&str> = line
        .trim()
        .split(',')
        .map(|f| f.trim_matches('"'))
        .collect();
    matches!(fields.as_slice(), [name, listed, ..]
        if name.eq_ignore_ascii_case(program) && listed.parse() == Ok(pid))
}

/// Ends a process and everything it started, as `run-service` on Windows starts the program.
fn end_process(pid: u32) -> Result<(), Failure> {
    #[cfg(unix)]
    Command::new("kill").arg(pid.to_string()).output()?;
    #[cfg(windows)]
    Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .output()?;
    Ok(())
}

/// What `ps` says about one process: its state, then its name or path.
#[cfg(unix)]
fn listed_as(line: &str, binary: &str) -> bool {
    let Some((state, name)) = line.trim().split_once(char::is_whitespace) else {
        return false;
    };
    !state.starts_with('Z')
        && Path::new(name.trim())
            .file_name()
            .and_then(|name| name.to_str())
            == Some(binary)
}

/// Whether a copy of it runs for this agent's folder, by its lock, or by the pid file an install from
/// before locks left there.
pub fn is_running(home: &Home, name: &str) -> Result<bool, Failure> {
    Ok(matches!(holder(home, name)?, Holder::Running(_)) || before_locks(home, name)?.is_some())
}

/// `ps`'s elapsed time, `[[DD-]HH:]MM:SS`.
#[cfg(unix)]
fn elapsed(text: &str) -> Option<Duration> {
    let text = text.trim();
    let (days, clock) = match text.split_once('-') {
        Some((days, clock)) => (days.parse::<u64>().ok()?, clock),
        None => (0, text),
    };
    let parts: Vec<&str> = clock.split(':').collect();
    if !(2..=3).contains(&parts.len()) {
        return None;
    }
    let mut secs: u64 = 0;
    for part in parts {
        secs = secs.checked_mul(60)?.checked_add(part.parse().ok()?)?;
    }
    Some(Duration::from_secs(
        days.checked_mul(SECS_A_DAY)?.checked_add(secs)?,
    ))
}

/// When a process started, if it's running.
#[cfg(unix)]
fn started_at(pid: u32) -> Result<Option<SystemTime>, Failure> {
    let answer = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "etime="])
        .output()?;
    Ok(elapsed(&String::from_utf8_lossy(&answer.stdout))
        .and_then(|running_for| SystemTime::now().checked_sub(running_for)))
}

/// The process an install from before locks started for this agent's folder, while it runs: the pid
/// in that folder's own pid file, still that program, and started before the file was written. A pid
/// the system has since given to another process started later, so it never counts.
#[cfg(windows)]
fn before_locks(_home: &Home, _name: &str) -> Result<Option<u32>, Failure> {
    Ok(None)
}

#[cfg(unix)]
fn before_locks(home: &Home, name: &str) -> Result<Option<u32>, Failure> {
    let Some(&(_, binary)) = BEFORE_LOCKS.iter().find(|(named, _)| *named == name) else {
        return Ok(None);
    };
    let path = home.run_dir().join(format!("{name}.pid"));
    let Some(pid) = written_pid(&path)? else {
        return Ok(None);
    };
    let written = fs::metadata(&path)?.modified()?;
    let latest = written.checked_add(PID_WRITTEN_WITHIN);
    let ours = started_at(pid)?
        .zip(latest)
        .is_some_and(|(started, latest)| started <= latest)
        && is_this_program(pid, binary)?;
    Ok(ours.then_some(pid))
}

/// Whether the copy holding the lock runs a build this install has replaced: installing writes each
/// program anew, and the copy wrote its lock as it started.
fn runs_an_older_build(home: &Home, name: &str, binary: &str) -> Result<bool, Failure> {
    if !matches!(holder(home, name)?, Holder::Running(_)) {
        return Ok(false);
    }
    let started = fs::metadata(home.lock_file(name))?.modified()?;
    match fs::metadata(beside_this_program(binary)?) {
        Ok(program) => Ok(program.modified()? > started),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Whether what runs for this agent's folder is from an older install, which `start` runs this one in
/// place of.
pub fn runs_older(home: &Home, name: &str, binary: &str) -> Result<bool, Failure> {
    Ok(before_locks(home, name)?.is_some() || runs_an_older_build(home, name, binary)?)
}

/// Stops what runs for this agent's folder from an older install, so starting it runs this build. An
/// upgrade otherwise leaves the old one running, still signing, beside whatever starts next.
pub async fn stop_older(home: &Home, name: &str, binary: &str) -> Result<(), Failure> {
    if runs_older(home, name, binary)? {
        stop(home, name, binary).await?;
    }
    Ok(())
}

fn remove_if_there(path: &Path) -> Result<(), Failure> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// A log only this user can read, made before any keeper opens it, as one may make it readable to all.
fn private_log(path: &Path) -> Result<File, Failure> {
    Ok(private_files::open(
        OpenOptions::new().create(true).append(true),
        path,
    )?)
}

/// What `splint stop` leaves, before it stops anything, so nothing starting meanwhile outlasts it.
pub fn mark_stopped(home: &Home) -> Result<(), Failure> {
    if !home.exists() {
        return Ok(());
    }
    Home::make_private(&home.run_dir())?;
    write_private(&home.stopped_mark(), b"")?;
    Ok(())
}

pub fn clear_stopped(home: &Home) -> Result<(), Failure> {
    remove_if_there(&home.stopped_mark())
}

/// Whether its person ran `splint stop` here and hasn't started it since, which nothing else undoes.
pub fn stopped_by_person(home: &Home) -> bool {
    home.stopped_mark().exists()
}

/// What `start` did.
#[must_use]
pub enum Started {
    Running,
    /// Its owner ran `splint stop`, so it's left stopped until they run `splint start`.
    LeftStopped,
}

/// Starts it, kept by the system's own service manager where it should be and can be, and otherwise
/// in a process group of its own, so closing the terminal doesn't stop it. It gets the settings it's
/// given and how this computer reaches out, its proxy and certificates, and nothing else from this
/// shell, and neither they nor its log reach anyone else. One that's kept across restarts stays
/// stopped after `splint stop`, whatever else would start it.
pub fn start(home: &Home, service: &Service<'_>) -> Result<Started, Failure> {
    if service.keep == Keep::AcrossRestarts && home.stopped_mark().exists() {
        return Ok(Started::LeftStopped);
    }
    // Where its lock, launch file and log go, which a person who has only installed doesn't have yet.
    Home::make_private(&home.run_dir())?;
    let unit = Unit::of(home, service.name)?;
    let keeper = match service.keep {
        Keep::AcrossRestarts => Keeper::here(),
        Keep::UntilStopped => Keeper::Nothing,
    };
    let by_crontab = service.keep == Keep::AcrossRestarts && keeper == Keeper::Nothing;
    if is_running(home, service.name)? {
        // One started detached before there were crontab lines, which a start now gives one.
        if by_crontab && !launchd::is_defined(&unit) && !systemd::is_defined(&unit) {
            crontab::keep(&unit);
        }
        return Ok(Started::Running);
    }
    // One left from before, which may be starting it again with what it had then. On Windows that's
    // a task at login from an earlier build, which goes and isn't made again.
    launchd::remove(&unit)?;
    systemd::remove(&unit)?;
    scheduler::remove(&unit)?;
    if !by_crontab {
        crontab::remove(&unit);
    }
    let mut env: Vec<(String, String)> = service
        .env
        .iter()
        .map(|&(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    for name in HOW_THIS_COMPUTER_REACHES_OUT {
        if let Ok(value) = env::var(name)
            && !env.iter().any(|(given, _)| given == name)
        {
            env.push((name.to_owned(), value));
        }
    }
    let launch = Launch {
        binary: service.binary.to_owned(),
        args: service.args.iter().map(|&arg| arg.to_owned()).collect(),
        env,
    };
    let bytes = serde_json::to_vec(&launch)
        .map_err(|_| Failure::refused(format!("couldn't write down how {} starts", unit.name)))?;
    write_private(&home.launch_file(service.name), &bytes)?;
    let log = private_log(&unit.log)?;
    match keeper {
        Keeper::Launchd => launchd::install(&unit)?,
        Keeper::Systemd => systemd::install(&unit)?,
        // On Windows nothing starts it at login, as an unsigned program that starts itself at login
        // is what Windows' malware checks quarantine. Its keeper starts it again after a crash, and
        // the next splint command after a sign-out or a restart.
        Keeper::OnDemand | Keeper::Nothing => detached(home, &unit, log)?,
    }
    // After the launch file it reads is written. Without one, it runs as it did, and status says so.
    if by_crontab {
        crontab::keep(&unit);
    }
    Ok(Started::Running)
}

fn detached(home: &Home, unit: &Unit, log: File) -> Result<(), Failure> {
    let mut command = Command::new(&unit.splint);
    command
        .args([RUN_SERVICE, &unit.name])
        .env_clear()
        .envs(what_every_program_needs())
        .envs(unit.env())
        .stdin(Stdio::null())
        .stdout(File::try_clone(&log)?)
        .stderr(log);
    let mut child = own_group(&mut command)
        .map_err(|error| Failure::refused(format!("couldn't start {}: {error}", unit.name)))?;
    // `run-service` takes the lock as it becomes the program. Whoever waits next looks at once, so
    // this waits for that. Another copy that started meanwhile counts too, as this one then leaves.
    let pid = child.id();
    let deadline = Instant::now() + STOP_WAIT;
    loop {
        let running = holder(home, &unit.name)?;
        if matches!(running, Holder::Running(Some(holder)) if holder == pid) {
            break;
        }
        if child.try_wait()?.is_some() {
            if matches!(running, Holder::Running(_)) {
                break;
            }
            return Err(Failure::refused(format!(
                "{} stopped as it started: see {}",
                unit.name,
                unit.log.display()
            )));
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(POLL);
    }
    drop(child);
    Ok(())
}

/// Starts it in a process group of its own, so closing the terminal doesn't stop it. On Windows that's
/// with no console window, and out of the terminal's job if the job allows, as some end everything in
/// it when they close.
fn own_group(command: &mut Command) -> std::io::Result<process::Child> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0).spawn()
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        let flags = CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
        match command
            .creation_flags(flags | CREATE_BREAKAWAY_FROM_JOB)
            .spawn()
        {
            Ok(child) => Ok(child),
            // A job that doesn't allow leaving it refuses the start: it runs inside it then.
            Err(_) => command.creation_flags(flags).spawn(),
        }
    }
}

/// Takes it out of its keeper and the crontab, so nothing starts it again, then stops whatever holds
/// its lock, which is the one copy running. It's stopped once the lock is free.
pub async fn stop(home: &Home, name: &str, binary: &str) -> Result<(), Failure> {
    let unit = Unit::of(home, name)?;
    launchd::remove(&unit)?;
    systemd::remove(&unit)?;
    scheduler::remove(&unit)?;
    crontab::remove(&unit);
    let deadline = Instant::now() + STOP_WAIT;
    let mut signalled = None;
    while let Holder::Running(pid) = holder(home, name)? {
        if let Some(pid) = pid
            && signalled != Some(pid)
            && is_this_program(pid, binary)?
        {
            end_process(pid)?;
            signalled = Some(pid);
        }
        if Instant::now() >= deadline {
            return Err(Failure::refused(format!("{binary} wouldn't stop")));
        }
        tokio::time::sleep(POLL).await;
    }
    // One an install from before locks started, which its pid file in this folder alone names.
    let mut signalled = None;
    while let Some(pid) = before_locks(home, name)? {
        if signalled != Some(pid) {
            end_process(pid)?;
            signalled = Some(pid);
        }
        if Instant::now() >= deadline {
            return Err(Failure::refused(format!("{binary} wouldn't stop")));
        }
        tokio::time::sleep(POLL).await;
    }
    remove_if_there(&home.run_dir().join(format!("{name}.pid")))?;
    // A signup code given to Signet once is in here, and needn't outlast it.
    remove_if_there(&home.launch_file(name))
}

/// Waits for `ready`, and gives up early if the program has already exited.
pub async fn wait_for<F, Ready>(
    home: &Home,
    name: &str,
    binary: &str,
    timeout: Duration,
    ready: F,
) -> Result<(), Failure>
where
    F: Fn() -> Ready,
    Ready: Future<Output = bool>,
{
    let gave_up = || {
        Failure::refused(format!(
            "{binary} didn't start: see {}",
            home.log_file(name).display()
        ))
    };
    let deadline = Instant::now() + timeout;
    // A keeper starts it a moment later, so not running yet is still starting.
    let mut was_running = false;
    loop {
        if ready().await {
            return Ok(());
        }
        let running = is_running(home, name)?;
        if (was_running && !running) || Instant::now() >= deadline {
            return Err(gave_up());
        }
        was_running = running;
        tokio::time::sleep(POLL).await;
    }
}

/// What a service said as it refused to run, if that's the last thing in its log, as it is for one that
/// has stopped for that reason. Only ever that program's own words.
pub fn last_refusal(home: &Home, name: &str) -> Option<String> {
    refusal_in(&home.log_file(name), name, LogEnd(0))
}

/// Where a service's log ends, taken before starting it, so a refusal it gives then can be told from
/// one it gave before, days ago perhaps, which is no reason for this start failing.
#[derive(Clone, Copy)]
pub struct LogEnd(u64);

pub fn log_end(home: &Home, name: &str) -> LogEnd {
    end_of(&home.log_file(name))
}

fn end_of(log: &Path) -> LogEnd {
    LogEnd(fs::metadata(log).map_or(0, |log| log.len()))
}

/// What a service said as it refused to run, as [`last_refusal`] finds it, if it said it after `since`.
pub fn refusal_since(home: &Home, name: &str, since: LogEnd) -> Option<String> {
    refusal_in(&home.log_file(name), name, since)
}

fn refusal_in(log: &Path, name: &str, since: LogEnd) -> Option<String> {
    let mut log = File::open(log).ok()?;
    let length = log.metadata().ok()?.len();
    // A log shorter than at the mark was made again since, so all of it came after.
    let since = if length < since.0 { 0 } else { since.0 };
    log.seek(SeekFrom::Start(
        length.saturating_sub(LOG_TAIL_BYTES).max(since),
    ))
    .ok()?;
    let mut tail = Vec::new();
    log.read_to_end(&mut tail).ok()?;
    let tail = String::from_utf8_lossy(&tail);
    let keeper = format!("splint {RUN_SERVICE} {name}: ");
    let last = tail
        .lines()
        .rev()
        .find(|line| !(line.starts_with(&keeper) && line.contains(STARTS_AGAIN)))?;
    let said = REFUSAL_LINES
        .iter()
        .find_map(|start| last.strip_prefix(start))?;
    Some(
        said.chars()
            .filter(|c| !c.is_control())
            .take(MOST_REFUSAL_CHARS)
            .collect(),
    )
}

/// What a keeper runs: becomes the program its launch file names, with only the settings there, as
/// the one copy running. Without a launch file it was stopped, or its folder is gone, and with
/// another copy running it isn't needed, so either ends as a success and isn't started again.
pub fn run(home: &Home, name: &str) -> Result<String, Failure> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Failure::Usage);
    }
    let bytes = match fs::read(home.launch_file(name)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(format!("{name} was stopped, so there's nothing to run"));
        }
        Err(error) => return Err(error.into()),
    };
    let Taken::Now(lock) = take(home, name)? else {
        return Ok(format!("{name} is already running"));
    };
    // A keeper may have nowhere else to say why it couldn't start.
    let mut log = private_log(&home.log_file(name))?;
    #[cfg(unix)]
    let failure = become_it(name, &bytes, &log, lock);
    #[cfg(windows)]
    let failure = match keep_it(home, name, &bytes, &log, lock) {
        Ok(said) => return Ok(said),
        Err(failure) => failure,
    };
    let _ = writeln!(log, "splint {RUN_SERVICE} {name}: {failure}");
    Err(failure)
}

/// The program a launch file names, installed beside this one, ready to start with only its settings,
/// and its name.
fn launched(name: &str, bytes: &[u8], log: &File) -> Result<(Command, String), Failure> {
    let Ok(launch) = serde_json::from_slice::<Launch>(bytes) else {
        return Err(Failure::refused(format!("how {name} starts can't be read")));
    };
    // Only ever a program installed beside this one.
    if Path::new(&launch.binary)
        .file_name()
        .and_then(|n| n.to_str())
        != Some(&launch.binary)
    {
        return Err(Failure::refused(format!(
            "how {name} starts names no program here"
        )));
    }
    let program = beside_this_program(&launch.binary)?;
    let binary = launch.binary.clone();
    let mut command = Command::new(program);
    command
        .args(&launch.args)
        .env_clear()
        .envs(what_every_program_needs())
        .envs(launch.env)
        .env("NO_COLOR", "1")
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?);
    Ok((command, binary))
}

/// Returns only if it couldn't. The lock is the program's standard input, the one open file that
/// outlasts becoming it, so the program holds it for as long as it runs and no longer. None of these
/// programs reads its input, and what each starts gets input of its own.
#[cfg(unix)]
fn become_it(name: &str, bytes: &[u8], log: &File, lock: File) -> Failure {
    use std::os::unix::process::CommandExt;
    let (mut command, binary) = match launched(name, bytes, log) {
        Ok(launched) => launched,
        Err(failure) => return failure,
    };
    let error = command.stdin(lock).exec();
    Failure::refused(format!("couldn't start {binary}: {error}"))
}

/// Windows has no way to become another program, so this keeps it: holds the lock while the program
/// runs, and starts it again after it exits with a failure, as launchd and systemd do, waiting longer
/// each time. One that exits cleanly, as `splint auto` does once its folder has gone, stays stopped,
/// and so does one whose launch file `splint stop` took away. `splint stop` ends this and the program
/// together.
#[cfg(windows)]
fn keep_it(
    home: &Home,
    name: &str,
    bytes: &[u8],
    log: &File,
    _lock: File,
) -> Result<String, Failure> {
    // Started at login by a task an earlier build left, this has a console window of its own, which
    // goes now.
    splint_core::private_files::windows::leave_console();
    let mut wait = RESTART_WAITS.0;
    loop {
        let (mut command, binary) = launched(name, bytes, log)?;
        command
            .stdin(Stdio::null())
            .env(KEPT_BY, process::id().to_string());
        let mut child = own_group(&mut command)
            .map_err(|error| Failure::refused(format!("couldn't start {binary}: {error}")))?;
        let ended = child.wait()?;
        if ended.success() {
            return Ok(format!("{name} ended"));
        }
        if !home.launch_file(name).exists() {
            return Ok(format!("{name} was stopped"));
        }
        let mut said = log.try_clone()?;
        let _ = writeln!(
            said,
            "splint {RUN_SERVICE} {name}: it exited with {ended}, {STARTS_AGAIN} {} s",
            wait.as_secs()
        );
        std::thread::sleep(wait);
        wait = wait.saturating_mul(2).min(RESTART_WAITS.1);
    }
}

/// A path or name written into a service definition, refused if it could break out of its place there.
fn plain(value: &str) -> Result<&str, Failure> {
    if value
        .chars()
        .any(|c| c.is_control() || c == '"' || c == '\\')
    {
        return Err(Failure::refused(
            "the Splint folder's path has characters a service definition can't hold",
        ));
    }
    Ok(value)
}

/// This user's number, which is how each service manager names their own domain.
fn user_id() -> Result<String, Failure> {
    let done = Command::new("id").arg("-u").output()?;
    let id = String::from_utf8_lossy(&done.stdout).trim().to_owned();
    if !done.status.success() || id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        return Err(Failure::refused("can't tell which user this is"));
    }
    Ok(id)
}

/// Runs a service manager's command, and says what it said if it failed.
fn manage(program: &str, args: &[&str]) -> Result<(), Failure> {
    let done = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if done.status.success() {
        return Ok(());
    }
    Err(Failure::refused(format!(
        "{program} {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&done.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this catches: why Splint on the computer won't start, such as another user holding its
    /// pipe's name, never shown, as it's Splint's own refusal and not Signet's, or as a keeper on
    /// Windows wrote that it starts it again after it.
    #[test]
    fn a_refusal_is_found_under_the_keepers_restarts() {
        let log = std::env::temp_dir().join(format!("splint-refusal-{}.log", process::id()));
        let said = |lines: &str| {
            fs::write(&log, lines).ok()?;
            refusal_in(&log, "splint-computer", LogEnd(0))
        };
        let restart = "splint run-service splint-computer: it exited with exit code: 1, so it starts \
                       again in 2 s\n";
        assert_eq!(
            said(&format!("splint: the pipe is taken\n{restart}{restart}")).as_deref(),
            Some("the pipe is taken")
        );
        assert_eq!(
            said("Error: something is listening\n").as_deref(),
            Some("something is listening")
        );
        assert_eq!(said("splint: refused\nstarted fine\n"), None);
        assert_eq!(
            said("splint: refused\nsplint run-service splint-computer: couldn't start it\n"),
            None
        );
        let _ = fs::remove_file(&log);
    }

    /// The bug this catches: a refusal from an earlier start, days ago perhaps, given as why this one
    /// failed, where it said nothing yet or was left stopped.
    #[test]
    fn only_a_refusal_since_the_start_is_its_reason() {
        let log = std::env::temp_dir().join(format!("splint-refusal-since-{}.log", process::id()));
        let _ = fs::remove_file(&log);
        assert_eq!(refusal_in(&log, "splint-computer", end_of(&log)), None);
        fs::write(&log, "splint: something was in the way days ago\n").unwrap();
        let before = end_of(&log);
        assert_eq!(refusal_in(&log, "splint-computer", before), None);
        let mut appended = OpenOptions::new().append(true).open(&log).unwrap();
        appended.write_all(b"splint: the pipe is taken\n").unwrap();
        assert_eq!(
            refusal_in(&log, "splint-computer", before).as_deref(),
            Some("the pipe is taken")
        );
        let _ = fs::remove_file(&log);
    }

    /// The bug this catches: a pid file from before locks taken for a process that started after it was
    /// written, which would be someone else's, or one running past a day missed.
    #[cfg(unix)]
    #[test]
    fn elapsed_reads_every_form_ps_gives() {
        assert_eq!(elapsed(" 00:07\n"), Some(Duration::from_secs(7)));
        assert_eq!(elapsed("01:02:03"), Some(Duration::from_secs(3723)));
        assert_eq!(elapsed("2-00:00:01"), Some(Duration::from_secs(172_801)));
        assert_eq!(elapsed(""), None);
        assert_eq!(elapsed("7"), None);
        assert_eq!(elapsed("1:2:3:4"), None);
    }

    #[cfg(unix)]
    #[test]
    fn only_that_program_still_running_counts() {
        assert!(listed_as("S    splint-signet\n", "splint-signet"));
        assert!(listed_as(
            "Ss   /home/a/.splint/bin/splint-signet\n",
            "splint-signet"
        ));
        assert!(!listed_as(
            "Z    splint-signet <defunct>\n",
            "splint-signet"
        ));
        assert!(!listed_as("Z    splint-signet\n", "splint-signet"));
        assert!(!listed_as("S    something-else\n", "splint-signet"));
        assert!(!listed_as("", "splint-signet"));
    }

    /// The bug this catches: `splint stop` on Windows ending a process that isn't Splint's, because a
    /// pid the lock named was another program's by then, or another pid's line was taken for it.
    #[test]
    fn only_that_pid_running_splint_counts_in_tasklist() {
        let line = "\"splint.exe\",\"4242\",\"Console\",\"1\",\"9,876 K\"";
        assert!(in_tasklist(line, 4242, "splint.exe"));
        assert!(in_tasklist(&line.to_uppercase(), 4242, "splint.exe"));
        assert!(!in_tasklist(line, 424, "splint.exe"));
        assert!(!in_tasklist(line, 4242, "splint-signet.exe"));
        let other = "\"notepad.exe\",\"4242\",\"Console\",\"1\",\"9,876 K\"";
        assert!(!in_tasklist(other, 4242, "splint.exe"));
        assert!(!in_tasklist(
            "INFO: No tasks are running which match the specified criteria.",
            4242,
            "splint.exe"
        ));
        assert!(!in_tasklist("", 4242, "splint.exe"));
    }
}

//! `splint listen`: keeps watch on this agent's Signet for whatever runs the agent, which wakes it
//! only when a process it watches says something changed. Splint never starts or wakes an agent
//! itself. This only makes that process reliable.
//!
//! What it says is one fixed line naming the kinds that changed, from a closed set, so nothing a
//! counterparty wrote reaches the runtime or a command through it. A Signet that stops answering for
//! longer than a restart takes is said too, once, so silence never reads as nothing new. A command it
//! runs gets an empty environment apart from those kinds, `HOME` (on Windows `USERPROFILE`, and what
//! any Windows program needs to start) and, for a profile, `SPLINT_AS`, so a `splint` it runs acts as
//! this agent, and never this agent's token.
//!
//! `--keep` registers the listener and its command as one of the agent's own kept services, as
//! [`kept`] says.

pub mod kept;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use splint_core::private_files;

use crate::check;
use crate::failure::Failure;
use crate::home::{HOME_SETTING, Home, Installed, PROFILE_SETTING};
use crate::secrets::write_private;
use crate::services::{self, what_every_program_needs};
use crate::signet_api::{Changed, SignetApi};

/// What comes this soon after a change is said with it, so an invite and the note behind it, which
/// arrive together, are one wake. Short enough that it never slows an exchange.
const SETTLE: Duration = Duration::from_millis(250);
/// The longest gap a runtime can ask for between wakes.
const MAX_GAP_SECS: u64 = 60 * 60;
/// How long Signet can go without answering before a listener says so: longer than a restart takes,
/// so an upgrade, or a keeper bringing Signet back, wakes nobody.
const SAY_AWAY_AFTER: Duration = Duration::from_secs(20);
const FIRST_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// How long one wait on Signet lasts while nothing changes.
const IDLE_WAIT_SECS: u64 = 60;
/// Shorter with a mark, so one that a newer listener on the same mark has taken over leaves soon.
const MARK_WAIT_SECS: u64 = 30;
const DEFAULT_ONCE_SECS: u64 = 300;
/// What a command learns, as Signet's words joined by commas.
const CHANGED_SETTING: &str = "SPLINT_CHANGED";
const MAX_MARK_CHARS: usize = 80;
/// A mark nobody has used in this long belongs to a session that's over.
const MARK_KEPT: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// What a kept listener's command is given, as `yes`, when a `splint listen` that says its line to a
/// runtime was running for this agent as the change came: a session there hears the same change.
const ALSO_LISTENING_SETTING: &str = "SPLINT_ALSO_LISTENING";

pub const HERE: &str = "--here";
const ONCE: &str = "--once";
const MARK: &str = "--mark";
const SECONDS: &str = "--seconds";
const GAP: &str = "--gap";
const KEEP: &str = "--keep";
const UNKEEP: &str = "--unkeep";
const COMMAND: &str = "--";

pub struct Options {
    pub here: bool,
    /// The least time between two wakes, which is the runtime's to choose, as each can cost it a
    /// turn. None by default, so an exchange between agents goes at the pace they answer.
    gap: Duration,
    mode: Mode,
}

enum Mode {
    /// A line on stdout for each change.
    Say,
    /// The first change since this mark's last, then out.
    Once { mark: String, seconds: u64 },
    /// The command for each change, one copy at a time.
    Run { program: PathBuf, args: Vec<String> },
    /// Registers that, as one of the agent's own kept services.
    Keep { program: PathBuf, args: Vec<String> },
    /// Stops the kept listener and forgets its command.
    Unkeep,
    /// The kept listener itself, which whatever keeps it runs.
    Kept,
}

/// What came of listening.
pub enum Heard {
    /// Something changed, or Signet stopped answering, and was said, or `--here` kept it quiet.
    Done,
    /// Nothing changed in time.
    Nothing,
    /// What keeping a listener, or no longer keeping one, did, for whoever typed it.
    Said(String),
}

/// A name a runtime can give its own mark, which can't climb out of the marks folder.
fn is_mark_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && name.chars().count() <= MAX_MARK_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Where a command named without a path is found, in the PATH this runs with, as a shell would.
fn found_program(name: &str) -> Result<PathBuf, Failure> {
    let not_found = || Failure::refused("splint listen couldn't find the command it was given");
    if name.contains('/') || (cfg!(windows) && name.contains('\\')) {
        let path = PathBuf::from(name);
        return if path.is_file() {
            Ok(path)
        } else {
            Err(not_found())
        };
    }
    let path = env::var_os("PATH").unwrap_or_default();
    env::split_paths(&path)
        .flat_map(|dir| {
            runnable_names(name)
                .into_iter()
                .map(move |each| dir.join(each))
        })
        .find(|candidate| fs::metadata(candidate).is_ok_and(|found| is_runnable(&found)))
        .ok_or_else(not_found)
}

#[cfg(unix)]
fn runnable_names(name: &str) -> Vec<String> {
    vec![name.to_owned()]
}

#[cfg(unix)]
fn is_runnable(found: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    found.is_file() && found.permissions().mode() & 0o111 != 0
}

/// A Windows program is found by its name with `.exe`, or named with it. Only a program run directly
/// counts, as a `.cmd` or `.bat` would be handed to a shell.
#[cfg(windows)]
fn runnable_names(name: &str) -> Vec<String> {
    match std::path::Path::new(name).extension() {
        Some(ending) if ending.eq_ignore_ascii_case("exe") => vec![name.to_owned()],
        Some(_) => Vec::new(),
        None => vec![format!("{name}{}", env::consts::EXE_SUFFIX)],
    }
}

#[cfg(windows)]
fn is_runnable(found: &fs::Metadata) -> bool {
    found.is_file()
}

pub fn options(words: &[&str]) -> Result<Options, Failure> {
    let mut here = false;
    let mut once = false;
    let mut mark = None;
    let mut seconds = None;
    let mut gap = None;
    let mut command = None;
    let (mut keep, mut unkeep, mut kept) = (false, false, false);
    let mut rest = words.iter();
    while let Some(word) = rest.next() {
        match *word {
            HERE => here = true,
            ONCE => once = true,
            KEEP => keep = true,
            UNKEEP => unkeep = true,
            kept::KEPT => kept = true,
            MARK => mark = Some(*rest.next().ok_or(Failure::Usage)?),
            SECONDS => {
                let given = rest.next().ok_or(Failure::Usage)?;
                seconds = Some(given.parse::<u64>().map_err(|_| Failure::Usage)?);
            }
            GAP => {
                let given = rest.next().ok_or(Failure::Usage)?;
                let given = given.parse::<u64>().map_err(|_| Failure::Usage)?;
                if given > MAX_GAP_SECS {
                    return Err(Failure::refused(format!(
                        "--gap is up to {MAX_GAP_SECS} seconds"
                    )));
                }
                gap = Some(given);
            }
            COMMAND => {
                let (program, args) = rest.as_slice().split_first().ok_or(Failure::Usage)?;
                command = Some((
                    found_program(program)?,
                    args.iter().map(|arg| (*arg).to_owned()).collect(),
                ));
                break;
            }
            _ => return Err(Failure::Usage),
        }
    }
    // A kept listener runs from wherever its keeper starts it, so it has no folder to be quiet
    // outside of, and it takes nothing that's for one wait.
    if keep || unkeep || kept {
        let alone = !here && !once && mark.is_none() && seconds.is_none();
        let mode = match (keep, unkeep, kept, command) {
            _ if !alone => return Err(Failure::Usage),
            (true, false, false, Some((program, args))) => Mode::Keep { program, args },
            (true, false, false, None) => {
                return Err(Failure::refused(
                    "--keep takes the command to keep running for each change, after --",
                ));
            }
            (false, true, false, None) if gap.is_none() => Mode::Unkeep,
            (false, false, true, None) if gap.is_none() => Mode::Kept,
            _ => return Err(Failure::Usage),
        };
        return Ok(Options {
            here,
            gap: Duration::from_secs(gap.unwrap_or(0)),
            mode,
        });
    }
    let mode = match (once, mark, seconds, command) {
        (false, None, None, None) => Mode::Say,
        (false, None, None, Some((program, args))) => Mode::Run { program, args },
        (true, Some(mark), seconds, None) => {
            if !is_mark_name(mark) {
                return Err(Failure::refused(format!(
                    "a mark's name is up to {MAX_MARK_CHARS} letters, digits, - and _, starting \
                     with a letter or digit"
                )));
            }
            Mode::Once {
                mark: mark.to_owned(),
                seconds: seconds.unwrap_or(DEFAULT_ONCE_SECS),
            }
        }
        _ => return Err(Failure::Usage),
    };
    Ok(Options {
        here,
        gap: Duration::from_secs(gap.unwrap_or(0)),
        mode,
    })
}

/// Signet's words for these, joined by commas.
fn words_of(kinds: &[Changed]) -> String {
    kinds
        .iter()
        .map(|kind| kind.word())
        .collect::<Vec<_>>()
        .join(",")
}

/// What a listener says, all of it fixed words, and with `--here` the agent and its folder, as a
/// runtime there may run sessions for other projects too.
struct Lines {
    splint: String,
    whose: String,
}

impl Lines {
    fn changed(&self, kinds: &[Changed]) -> String {
        format!("{}{}", line_for(&self.splint, kinds), self.whose)
    }

    fn unanswered(&self, failure: &Failure) -> String {
        format!("{}{}", check::unanswered(failure, &self.splint), self.whose)
    }
}

/// The one line said for a change: fixed words for each kind, and how to look.
fn line_for(splint: &str, kinds: &[Changed]) -> String {
    let named: Vec<&str> = kinds
        .iter()
        .map(|kind| match kind {
            Changed::Requests => "requests",
            Changed::Messages => "invites or messages",
            // Not "word from your person": the agent's own accept, and what its person's device
            // signs by their rules with nobody there, are noted the same way.
            Changed::Owner => "changes on your person's side",
        })
        .collect();
    let what = match named.split_last() {
        Some((last, [])) => (*last).to_owned(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => "something".to_owned(),
    };
    format!(
        "Splint: new {what} for this agent. Run {splint} check for what waits, then {}",
        crate::check::handle_them(splint)
    )
}

fn say(line: &str) -> Result<(), Failure> {
    let mut out = io::stdout().lock();
    writeln!(out, "{line}")?;
    out.flush()?;
    Ok(())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Signet not answering, said once each time it's away for longer than a restart takes.
#[derive(Default)]
struct Away {
    since: Option<Instant>,
    said: bool,
}

impl Away {
    fn answered(&mut self) {
        *self = Self::default();
    }

    /// How long it has been away, counting from now at the first call that fails.
    fn so_far(&mut self) -> Duration {
        self.since.get_or_insert_with(Instant::now).elapsed()
    }

    /// Whether to say so now, which is true once for each time it goes away.
    fn now_said(&mut self) -> bool {
        if self.said || self.so_far() < SAY_AWAY_AFTER {
            return false;
        }
        self.said = true;
        true
    }

    /// A pause before trying again that ends by the time it's to be said.
    fn pause(&mut self, pause: Duration) -> Duration {
        if self.said {
            return pause;
        }
        pause.min(SAY_AWAY_AFTER.saturating_sub(self.so_far()))
    }
}

/// What came of calling Signet until it answered.
enum Answer<T> {
    Got(T),
    /// It has been away long enough to say so, in these words.
    Away(String),
    OutOfTime,
}

/// What `call` gives once Signet answers, waiting Signet out while it's away, as when it restarts,
/// until it has been away long enough to say so, or `until` passes first.
async fn while_away<T, Called>(
    until: Option<Instant>,
    away: &mut Away,
    lines: &Lines,
    mut call: impl FnMut() -> Called,
) -> Answer<T>
where
    Called: Future<Output = Result<T, Failure>>,
{
    let mut backoff = FIRST_BACKOFF;
    loop {
        match call().await {
            Ok(answered) => {
                away.answered();
                return Answer::Got(answered);
            }
            Err(failure) => {
                if away.now_said() {
                    return Answer::Away(lines.unanswered(&failure));
                }
            }
        }
        let left = until.map(|at| at.saturating_duration_since(Instant::now()));
        if left == Some(Duration::ZERO) {
            return Answer::OutOfTime;
        }
        tokio::time::sleep(away.pause(left.map_or(backoff, |left| backoff.min(left)))).await;
        backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
    }
}

/// What a wait came to.
enum Event {
    Changed(Vec<Changed>),
    /// Signet has been away long enough to say so, in these words.
    Away(String),
}

/// Where Signet is up to for one listener, when it last woke anyone, and whether Signet answers.
struct Watch {
    since: u64,
    last_wake: Option<Instant>,
    gap: Duration,
    away: Away,
}

impl Watch {
    /// Until a change, said once what comes with it has settled and the runtime's gap since the last
    /// wake is up, or until `until` passes with none, or `keep_on` says to stop. Signet going away,
    /// as when it restarts, is waited out, and a mark from before a restart is answered with
    /// everything, so nothing is missed. Away for longer than a restart takes, with no change held,
    /// it says that Signet doesn't answer. `heard` is called once, as a change is first heard.
    async fn next(
        &mut self,
        api: &SignetApi<'_>,
        lines: &Lines,
        idle_secs: u64,
        until: Option<Instant>,
        keep_on: &mut dyn FnMut() -> bool,
        heard: &mut dyn FnMut(),
    ) -> Option<Event> {
        let mut backoff = FIRST_BACKOFF;
        let first = loop {
            if !keep_on() {
                return None;
            }
            let left = until.map(|at| at.saturating_duration_since(Instant::now()));
            if left == Some(Duration::ZERO) {
                return None;
            }
            let window = left.map_or(Duration::from_secs(idle_secs), |left| {
                left.min(Duration::from_secs(idle_secs))
            });
            let seconds = window
                .as_secs()
                .saturating_add(u64::from(window.subsec_nanos() > 0));
            match api.wait(Some(self.since), seconds).await {
                Ok(waited) => {
                    backoff = FIRST_BACKOFF;
                    self.away.answered();
                    self.since = waited.since;
                    if !waited.new.is_empty() {
                        break waited.new;
                    }
                }
                Err(failure) => {
                    if self.away.now_said() {
                        return Some(Event::Away(lines.unanswered(&failure)));
                    }
                    let pause = self
                        .away
                        .pause(left.map_or(backoff, |left| backoff.min(left)));
                    tokio::time::sleep(pause).await;
                    backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
                }
            }
        };
        heard();
        let mut pending: BTreeSet<Changed> = first.into_iter().collect();
        let now = Instant::now();
        let gap_up = self
            .last_wake
            .and_then(|at| at.checked_add(self.gap))
            .unwrap_or(now);
        let mut due = now.checked_add(SETTLE).unwrap_or(now).max(gap_up);
        if let Some(until) = until {
            due = due.min(until);
        }
        // Held to its time while a newer listener on the mark may take over, so one that has can
        // leave without waiting out a long gap.
        while Instant::now() < due {
            if !keep_on() {
                return None;
            }
            let pause = due
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(MARK_WAIT_SECS));
            tokio::time::sleep(pause).await;
        }
        // What came while it settled is said with it. With Signet away, what's held is said now, as
        // it would be with Signet there, and what came meanwhile is heard after.
        if let Ok(waited) = api.wait(Some(self.since), 0).await {
            self.away.answered();
            self.since = waited.since;
            pending.extend(waited.new);
        }
        self.last_wake = Some(Instant::now());
        Some(Event::Changed(pending.into_iter().collect()))
    }
}

/// What each change does, besides waking nobody twice in a burst.
enum Action<'a> {
    Say,
    Run {
        program: &'a PathBuf,
        args: &'a [String],
        /// `HOME`, and for a profile `SPLINT_AS`, which name this agent and hold nothing secret.
        handed: Vec<(&'static str, OsString)>,
        kept: Option<KeptRun<'a>>,
    },
}

/// What only the kept listener does around its command.
struct KeptRun<'a> {
    home: &'a Home,
    /// The folder the command was registered from, which it runs in.
    folder: &'a Path,
    /// Whether a runtime chose a gap, which then holds across a restart of the listener.
    keeps_gap: bool,
    /// Whether a listener for a session ran as this change was heard.
    session_listened: &'a Cell<bool>,
}

impl Action<'_> {
    async fn act(&self, lines: &Lines, kinds: &[Changed]) -> Result<(), Failure> {
        match self {
            Self::Say => say(&lines.changed(kinds)),
            Self::Run {
                program,
                args,
                handed,
                kept,
            } => {
                // Nothing else of this program's environment goes with it, so neither does a token
                // set there, and it reads nothing from whoever started this.
                let mut command = Command::new(program);
                command
                    .args(*args)
                    .env_clear()
                    .envs(what_every_program_needs())
                    .envs(handed.iter().map(|(name, value)| (name, value)))
                    .env(CHANGED_SETTING, words_of(kinds))
                    .stdin(Stdio::null());
                if let Some(kept) = kept {
                    command.current_dir(kept.folder);
                    // A session's listener leaves once it has said its line, so one that ran as
                    // the change was heard counts, as well as one running now.
                    if kept.session_listened.get() || kept::session_listens(kept.home) {
                        command.env(ALSO_LISTENING_SETTING, "yes");
                    }
                    if kept.keeps_gap {
                        kept::note_woke(kept.home);
                    }
                }
                let ran = tokio::task::spawn_blocking(move || command.status()).await;
                // The gap counts from when the command ended, as it does while this listener runs.
                if let Some(kept) = kept
                    && kept.keeps_gap
                {
                    kept::note_woke(kept.home);
                }
                // A turn that fails is the runtime's, and the next change starts another.
                if !matches!(ran, Ok(Ok(_))) {
                    let _ = writeln!(
                        io::stderr(),
                        "splint: the command given to listen didn't run"
                    );
                }
                Ok(())
            }
        }
    }

    /// Signet not answering is said where a change would be, or for a command, to whoever runs this,
    /// as the command can't reach Signet either.
    fn unanswered(&self, line: &str) -> Result<(), Failure> {
        match self {
            Self::Say => say(line),
            Self::Run { .. } => {
                writeln!(io::stderr(), "{line}")?;
                Ok(())
            }
        }
    }
}

/// Listens until stopped, acting on what's already waiting first. `last_wake` is when a listener
/// before this one last woke anyone, if the gap since still counts, and `heard` is called as each
/// change is heard, before it settles.
async fn keep_listening(
    home: &Home,
    installed: &Installed,
    lines: &Lines,
    gap: Duration,
    action: Action<'_>,
    last_wake: Option<Instant>,
    heard: &mut dyn FnMut(),
) -> Result<Heard, Failure> {
    let api = SignetApi::new(home, installed)?;
    let mut away = Away::default();
    // The mark first, so whatever comes while what's waiting is counted is heard after.
    let since = loop {
        let mark = while_away(None, &mut away, lines, || async {
            Ok(api.wait(None, 0).await?.since)
        });
        match mark.await {
            Answer::Got(since) => break since,
            Answer::Away(line) => action.unanswered(&line)?,
            Answer::OutOfTime => return Ok(Heard::Nothing),
        }
    };
    let mut watch = Watch {
        since,
        last_wake,
        gap,
        away,
    };
    if let Ok(waiting) = check::waiting(&api, home).await
        && !waiting.is_empty()
    {
        if let Some(gap_up) = last_wake.and_then(|at| at.checked_add(gap)) {
            tokio::time::sleep(gap_up.saturating_duration_since(Instant::now())).await;
        }
        heard();
        action.act(lines, &waiting.kinds()).await?;
        watch.last_wake = Some(Instant::now());
    }
    loop {
        match watch
            .next(&api, lines, IDLE_WAIT_SECS, None, &mut || true, heard)
            .await
        {
            Some(Event::Changed(kinds)) => action.act(lines, &kinds).await?,
            Some(Event::Away(line)) => action.unanswered(&line)?,
            None => {}
        }
    }
}

/// One listener's own mark, kept in the agent's folder so its changes are its own: another
/// listener hearing one first never takes it from this one.
#[derive(Serialize, Deserialize, Clone, Copy)]
struct Stored {
    since: u64,
    /// When it last woke anyone, in seconds since 1970, or 0.
    woke_at: u64,
    /// Which listener on this mark is the newest. An older one leaves without a word.
    holder: u64,
    /// Said that Signet doesn't answer, and it hasn't answered since, so the next listener on this
    /// mark doesn't say it again, which would wake a session again and again.
    #[serde(default)]
    away_said: bool,
}

struct MarkFile {
    path: PathBuf,
    lock: PathBuf,
    dir: PathBuf,
}

impl MarkFile {
    fn new(home: &Home, name: &str) -> Result<Self, Failure> {
        let dir = home.marks_dir();
        Home::make_private(&dir)?;
        Ok(Self {
            path: dir.join(format!("{name}.json")),
            lock: dir.join(format!("{name}.lock")),
            dir,
        })
    }

    /// This mark to itself until what's returned is dropped, so two listeners on it, such as the
    /// hooks of two turns, never write at once or over what the other just wrote.
    fn held(&self) -> Result<File, Failure> {
        let lock = private_files::open(
            OpenOptions::new().create(true).truncate(false).write(true),
            &self.lock,
        )?;
        lock.lock()?;
        Ok(lock)
    }

    fn read(&self) -> Option<Stored> {
        serde_json::from_slice(&fs::read(&self.path).ok()?).ok()
    }

    fn write(&self, stored: Stored) -> Result<(), Failure> {
        let bytes = serde_json::to_vec(&stored)
            .map_err(|_| Failure::refused("couldn't write down where this listener is up to"))?;
        write_private(&self.path, &bytes)?;
        self.forget_old();
        Ok(())
    }

    /// Marks no listener has used in a month, which belong to sessions that are over.
    fn forget_old(&self) {
        let Ok(found) = fs::read_dir(&self.dir) else {
            return;
        };
        for entry in found.filter_map(Result::ok) {
            let old = entry
                .metadata()
                .and_then(|found| found.modified())
                .ok()
                .and_then(|at| at.elapsed().ok())
                .is_some_and(|age| age > MARK_KEPT);
            if old
                && let Err(error) = fs::remove_file(entry.path())
                && error.kind() != ErrorKind::NotFound
            {
                return;
            }
        }
    }
}

fn this_listener() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    u64::from(std::process::id()) << 32 | u64::from(nanos)
}

/// The first change since this mark's last, or what's already waiting the first time it's used, or
/// that Signet doesn't answer, once each time it goes away.
async fn once(
    home: &Home,
    installed: &Installed,
    lines: &Lines,
    name: &str,
    seconds: u64,
    gap: Duration,
) -> Result<Heard, Failure> {
    let api = SignetApi::new(home, installed)?;
    let file = MarkFile::new(home, name)?;
    let me = this_listener();
    let until = Instant::now().checked_add(Duration::from_secs(seconds));
    let stored = {
        let _held = file.held()?;
        let stored = file.read();
        if let Some(stored) = stored {
            file.write(Stored {
                holder: me,
                ..stored
            })?;
        }
        stored
    };
    let still_mine = || file.read().is_some_and(|stored| stored.holder == me);
    let mut watch = match stored {
        Some(stored) => {
            let ago = Duration::from_secs(unix_secs().saturating_sub(stored.woke_at));
            Watch {
                since: stored.since,
                last_wake: Instant::now().checked_sub(ago),
                gap,
                away: Away {
                    since: None,
                    said: stored.away_said,
                },
            }
        }
        None => {
            let mut away = Away::default();
            let first_look = while_away(until, &mut away, lines, || async {
                let since = api.wait(None, 0).await?.since;
                Ok((since, check::waiting(&api, home).await?))
            })
            .await;
            let (since, waiting) = match first_look {
                Answer::Got(looked) => looked,
                Answer::Away(line) => {
                    {
                        let _held = file.held()?;
                        // No mark Signet gave, so once it's back its first answer is everything,
                        // which is how this mark hears that it's back.
                        file.write(Stored {
                            since: 0,
                            woke_at: unix_secs(),
                            holder: me,
                            away_said: true,
                        })?;
                    }
                    say(&line)?;
                    return Ok(Heard::Done);
                }
                Answer::OutOfTime => return Ok(Heard::Nothing),
            };
            let woke = !waiting.is_empty();
            {
                let _held = file.held()?;
                file.write(Stored {
                    since,
                    woke_at: if woke { unix_secs() } else { 0 },
                    holder: me,
                    away_said: false,
                })?;
            }
            if woke {
                say(&lines.changed(&waiting.kinds()))?;
                return Ok(Heard::Done);
            }
            Watch {
                since,
                last_wake: None,
                gap,
                away,
            }
        }
    };
    let said_before = watch.away.said;
    let heard = watch
        .next(
            &api,
            lines,
            MARK_WAIT_SECS,
            until,
            &mut || still_mine(),
            &mut || {},
        )
        .await;
    let Some(heard) = heard else {
        // Signet answered after it was said to be away, so the next time it goes away is said too.
        if watch.away.said != said_before {
            let _held = file.held()?;
            if let Some(stored) = file.read().filter(|stored| stored.holder == me) {
                file.write(Stored {
                    away_said: watch.away.said,
                    ..stored
                })?;
            }
        }
        return Ok(Heard::Nothing);
    };
    let mine = {
        let _held = file.held()?;
        let mine = still_mine();
        if mine {
            file.write(Stored {
                since: watch.since,
                woke_at: unix_secs(),
                holder: me,
                away_said: watch.away.said,
            })?;
        }
        mine
    };
    if !mine {
        return Ok(Heard::Nothing);
    }
    say(&match heard {
        Event::Changed(kinds) => lines.changed(&kinds),
        Event::Away(line) => line,
    })?;
    Ok(Heard::Done)
}

/// The kept listener, as whatever keeps it runs it: the command registered in this agent's folder,
/// as the one copy running. With none registered there's nothing to run, which ends as a success, so
/// nothing starts it again.
async fn run_kept(home: &Home) -> Result<Heard, Failure> {
    let Some(kept) = kept::Kept::load(home)? else {
        return Ok(Heard::Said(
            "No listener is kept for this agent, so there's nothing to run.".to_owned(),
        ));
    };
    let Some(_only_copy) = services::the_only_copy(home, kept::SERVICE)? else {
        return Ok(Heard::Said(
            "This agent's kept listener is already running.".to_owned(),
        ));
    };
    let (installed, _) = Installed::require(home)?;
    let lines = Lines {
        splint: home.command(),
        whose: String::new(),
    };
    let session_listened = Cell::new(false);
    let action = Action::Run {
        program: &kept.program,
        args: &kept.args,
        handed: handed(home),
        kept: Some(KeptRun {
            home,
            folder: &kept.folder,
            keeps_gap: kept.gap_secs > 0,
            session_listened: &session_listened,
        }),
    };
    let last_wake = kept::last_woke(home, kept.gap());
    let mut heard = || session_listened.set(kept::session_listens(home));
    keep_listening(
        home,
        &installed,
        &lines,
        kept.gap(),
        action,
        last_wake,
        &mut heard,
    )
    .await
}

/// `HOME`, and for a profile `SPLINT_AS`, so a `splint` the command runs acts as this agent.
fn handed(home: &Home) -> Vec<(&'static str, OsString)> {
    let mut handed = Vec::new();
    if let Some(dir) = env::var_os(HOME_SETTING) {
        handed.push((HOME_SETTING, dir));
    }
    if let Some(profile) = home.profile() {
        handed.push((PROFILE_SETTING, OsString::from(profile)));
    }
    handed
}

pub async fn listen(home: &Home, chosen: bool, options: &Options) -> Result<Heard, Failure> {
    match &options.mode {
        Mode::Keep { program, args } => {
            return Ok(Heard::Said(
                kept::keep(home, program, args, options.gap).await?,
            ));
        }
        Mode::Unkeep => return Ok(Heard::Said(kept::unkeep(home).await?)),
        Mode::Kept => return run_kept(home).await,
        Mode::Say | Mode::Once { .. } | Mode::Run { .. } => {}
    }
    let Some(installed) = check::agent_here(home, chosen, options.here)? else {
        return Ok(Heard::Done);
    };
    let lines = Lines {
        splint: home.command(),
        whose: if options.here {
            check::whose(&installed)
        } else {
            String::new()
        },
    };
    let gap = options.gap;
    match &options.mode {
        Mode::Say => {
            let _watching = kept::watching(home);
            keep_listening(home, &installed, &lines, gap, Action::Say, None, &mut || {}).await
        }
        Mode::Run { program, args } => {
            let action = Action::Run {
                program,
                args,
                handed: handed(home),
                kept: None,
            };
            keep_listening(home, &installed, &lines, gap, action, None, &mut || {}).await
        }
        Mode::Once { mark, seconds } => {
            let _watching = kept::watching(home);
            once(home, &installed, &lines, mark, *seconds, gap).await
        }
        // Answered above, before anything here is read.
        Mode::Keep { .. } | Mode::Unkeep | Mode::Kept => Err(Failure::Usage),
    }
}

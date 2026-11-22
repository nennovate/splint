//! The limits whoever runs a host sets, with the numbers one small server was measured carrying for
//! anyone who sets none.
//!
//! They belong to this host alone, so they protect this host and the people on it. What stands against
//! an agent on another host is that host's settings, which it can ignore, and each check here counts
//! what arrives for itself. An owner's signed rules can only go lower: each check takes the lower.
//! A mistyped name or number stops the host, rather than leaving a limit other than the one meant.
//!
//! With `SPLINT_LIMITS_FILE` they're in a file the running host reads again every few seconds, so a
//! limit counted on each call changes with no restart: all of the file, or none of it if any line is
//! wrong. The limits a host builds its guards from as it starts keep their numbers until a restart.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use splint_core::rules::RulesLimits;

use crate::answers::PAGE_BYTES;
use crate::{Host, MAX_REQUEST_BYTES};

const PREFIX: &str = "SPLINT_MAX_";
/// Names a file of limits, one `SPLINT_MAX_...=number` a line, which the host reads again as it runs.
pub const FILE_SETTING: &str = "SPLINT_LIMITS_FILE";
/// How soon a change to the file is taken. Reading it costs nothing next to a call.
const REREAD_EVERY: Duration = Duration::from_secs(2);

/// How an agent came to this host, which decides how much it can send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Came {
    WithCode,
    Open,
    /// On its own, with an owner who hasn't confirmed yet.
    Unconfirmed,
}

/// What part of an open signup's sends an agent whose owner hasn't confirmed gets. Provisional.
const UNCONFIRMED_PART: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// What one 1 vCPU, 2 GB server carried cleanly: 1,166 owners sending 200 messages a day at ten
    /// times the average rate. CPU, not disk: every agent at every per-agent limit at once would need
    /// more disk than that server has.
    pub agents: u32,
    /// More than an owner needs, and few enough that one owner with leaked codes can't fill a host.
    pub agents_per_owner: u32,
    /// Slows a leaked batch of codes, so whoever runs the host can notice.
    pub new_agents_per_hour: u32,
    /// So a flood of free signups leaves room for whoever holds a code. Provisional.
    pub open_agents: u32,
    /// Slow enough for whoever runs the host to notice someone filling it. Provisional.
    pub open_agents_per_hour: u32,
    /// So one network can't use up the hour for everyone else. An owner needs far fewer. Provisional.
    pub open_agents_per_source_per_day: u32,
    /// So one network can't take its day's all at once. Provisional.
    pub open_agents_per_source_per_hour: u32,
    /// Open signups from one network held at once, whoever they act for, so a network that waits out
    /// the day still holds no more. One that goes, unused or retired, makes room. Provisional.
    pub open_agents_per_source: u32,
    /// Open signups whose owners haven't confirmed that nobody has used yet, so a flood of agents
    /// nobody uses can't hold all the room for open signups. Each goes after 30 days unused.
    /// Provisional.
    pub unused_stand_ins: u32,
    /// Open signups whose owners haven't confirmed, used or not. Agents can make each other used, so
    /// this keeps room among open signups for agents whose owners join first. Provisional.
    pub open_stand_ins: u32,
    pub sends_per_agent_per_hour: u32,
    pub sends_per_agent_per_day: u32,
    /// Lower, as anyone can have one of these. Provisional.
    pub sends_per_open_agent_per_hour: u32,
    pub sends_per_open_agent_per_day: u32,
    /// What all strangers together can hold for one agent. Past this they're dropped, so a flood fills
    /// this queue and can't reach the inbox, at the cost of a real stranger arriving during one. One
    /// relaying host gets half, so one taking open signups, where agents cost nothing, can't take it all.
    pub quarantined_per_agent: u32,
    /// So one stranger can't take a whole quarantine.
    pub quarantined_per_sender: u32,
    /// The most an owner can sign for one contact, or for everyone let in by reach. A fooled agent's
    /// leak goes up with these, as `docs/protocol.md` says, and it's the owner who raises its own.
    pub new_requests_per_contact_per_day: u32,
    pub new_from_others_per_day: u32,
    /// Open at once, as held by the proxy. At 18 KB each these are small next to the rest.
    pub connections: u32,
    /// In progress at once. Past this a host refuses, rather than have everyone wait until they time out.
    pub calls_at_once: u32,
    /// One caller's share of that.
    pub calls_at_once_per_source: u32,
    /// Far past what a busy peer needs, and little next to what a host can verify in a second.
    pub calls_per_source_per_second: u32,
    /// Bytes of callers' bodies held at once, from a body's first byte until its call ends. This is
    /// what callers can make a host hold of what they send, so it's sized to the server's memory: the
    /// largest body there is for each call in progress, and a call past it is told to come back.
    pub body_bytes_at_once: u32,
    /// One caller's share of that: a sixteenth, which is the largest body for each delivery a peer
    /// makes at once.
    pub body_bytes_at_once_per_source: u32,
    /// Bytes of answers held at once, from before a page is read until its caller has read it or its
    /// connection has gone. This is what callers who read slowly can make a host hold of what it
    /// answers, so it's sized to the server's memory, and a call past it is told to come back.
    pub answer_bytes_at_once: u32,
    /// One caller's share of that: a sixteenth, which is four pages being read at once.
    pub answer_bytes_at_once_per_source: u32,
    /// Signets' calls held until something comes for their agents, at most two an agent and half of
    /// this from one source. Each holds a connection and little else, so this is half the connections,
    /// which is two for every agent a host takes. Past it a Signet asks every few seconds, as before.
    /// Zero holds none. Provisional.
    pub waits_at_once: u32,
    /// Hosts this one meets for the first time and keeps the key of, in an hour, leaving out the ones
    /// its operator names. Anyone with a domain can make up hosts, and each is a row kept for good, so
    /// past this a new host's first delivery waits for the hour to move on. Provisional.
    pub new_hosts_per_hour: u32,
}

#[derive(PartialEq, Eq, thiserror::Error)]
pub enum LimitSettingError {
    #[error("{0} isn't a limit a host has")]
    Unknown(String),
    #[error("{0} has to be a whole number")]
    NotANumber(&'static str),
    #[error("{0} has to be at least 1, or the host would answer nobody")]
    AnswersNobody(&'static str),
    #[error(
        "{0} has to be at least {1}, the largest body a host takes, or one that size would never fit"
    )]
    FitsNoBody(&'static str, usize),
    #[error("{0} has to be at least {1}, a page of answers, or a full page would never fit")]
    FitsNoPage(&'static str, usize),
    #[error(
        "line {0} of the limits file has to be a limit and its number, as in \
         SPLINT_MAX_AGENTS=1000, or a comment starting with #, or blank"
    )]
    NotALine(usize),
    #[error("{0} is in the limits file twice")]
    Twice(String),
    #[error(
        "{0} is set in the environment while {FILE_SETTING} names a file, so it isn't clear which \
         is meant: limits go in the file"
    )]
    OutsideTheFile(String),
    #[error("{FILE_SETTING} names {0}, and that couldn't be read")]
    Unreadable(String),
}

/// A `main` that returns an error prints it this way, and the person reading needs the sentence.
impl std::fmt::Debug for LimitSettingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// The limits a file sets, by name. Anything that isn't a limit is refused rather than passed over,
/// as a line that does nothing leaves a limit other than the one meant.
fn settings_in(text: &str) -> Result<Vec<(String, String)>, LimitSettingError> {
    let mut settings: Vec<(String, String)> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .map(|(name, value)| (name.trim(), value.trim()))
            .filter(|(name, _)| name.starts_with(PREFIX))
            .ok_or(LimitSettingError::NotALine(index + 1))?;
        if settings.iter().any(|(set, _)| set == name) {
            return Err(LimitSettingError::Twice(name.to_owned()));
        }
        settings.push((name.to_owned(), value.to_owned()));
    }
    Ok(settings)
}

/// The limits in force, which every check reads as it's made. The ones counted on each call change
/// when the limits file does. The ones a host's guards were built from stay as they started.
pub struct Live {
    now: RwLock<Limits>,
}

impl Live {
    pub fn new(limits: Limits) -> Self {
        Self {
            now: RwLock::new(limits),
        }
    }

    pub fn now(&self) -> Limits {
        *self.now.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes what the file says, all of it or none. It answers with the limits it says differently
    /// that only a restart changes, which stay as they are.
    fn take(&self, text: &str) -> Result<Vec<&'static str>, LimitSettingError> {
        let read = Limits::from_settings(settings_in(text)?)?;
        let running = self.now();
        let at_restart = read
            .built_at_start()
            .into_iter()
            .zip(running.built_at_start())
            .filter(|((_, read), (_, running))| read != running)
            .map(|((name, _), _)| name)
            .collect();
        *self.now.write().unwrap_or_else(PoisonError::into_inner) = read.as_built_in(&running);
        Ok(at_restart)
    }
}

/// Reads the limits file again every few seconds, and takes it when it has changed. A file that's
/// gone or wrong leaves every limit as it was, and says so once for each change, not every time.
pub async fn run_rereading(host: Arc<Host>, file: PathBuf) {
    // What a start took isn't kept, so the first look reads it again, and finds nothing changed.
    let mut last: Option<Option<String>> = None;
    loop {
        tokio::time::sleep(REREAD_EVERY).await;
        let path = file.clone();
        let Ok(read) = tokio::task::spawn_blocking(move || fs::read_to_string(path).ok()).await
        else {
            continue;
        };
        if last.as_ref() == Some(&read) {
            continue;
        }
        let before = host.limits.now();
        match read.as_deref().map(|text| host.limits.take(text)) {
            None => tracing::warn!(
                file = %file.display(),
                "the limits file can't be read, so every limit stays as it was"
            ),
            Some(Err(error)) => tracing::warn!(
                %error,
                "the limits file was refused, so every limit stays as it was"
            ),
            Some(Ok(at_restart)) => {
                if host.limits.now() != before {
                    tracing::info!("took the limits in the limits file, with no restart");
                }
                for setting in at_restart {
                    tracing::warn!(
                        setting,
                        "this limit is built in as a host starts, so it keeps the number it \
                         started with until: sudo systemctl restart splint-host"
                    );
                }
            }
        }
        last = Some(read);
    }
}

impl Limits {
    pub fn from_env() -> Result<Self, LimitSettingError> {
        Self::from_settings(env::vars())
    }

    /// A host's limits as it starts, and the file they came from if one is named. With a file, a limit
    /// in the environment as well is refused, as only one of the two could be the one in force.
    pub fn at_start() -> Result<(Self, Option<PathBuf>), LimitSettingError> {
        let Some(file) = env::var_os(FILE_SETTING).filter(|file| !file.is_empty()) else {
            return Ok((Self::from_env()?, None));
        };
        if let Some((name, _)) = env::vars().find(|(name, _)| name.starts_with(PREFIX)) {
            return Err(LimitSettingError::OutsideTheFile(name));
        }
        let file = PathBuf::from(file);
        Ok((Self::from_file(&file)?, Some(file)))
    }

    fn from_file(file: &Path) -> Result<Self, LimitSettingError> {
        let text = fs::read_to_string(file)
            .map_err(|_| LimitSettingError::Unreadable(file.display().to_string()))?;
        Self::from_settings(settings_in(&text)?)
    }

    /// The limits a host builds its guards from as it starts: connections, calls and bytes held at
    /// once, and held waits. A running host keeps these, whatever its limits file comes to say.
    fn built_at_start(&self) -> [(&'static str, u32); 9] {
        [
            ("SPLINT_MAX_CONNECTIONS", self.connections),
            ("SPLINT_MAX_CALLS_AT_ONCE", self.calls_at_once),
            (
                "SPLINT_MAX_CALLS_AT_ONCE_PER_SOURCE",
                self.calls_at_once_per_source,
            ),
            (
                "SPLINT_MAX_CALLS_PER_SOURCE_PER_SECOND",
                self.calls_per_source_per_second,
            ),
            ("SPLINT_MAX_BODY_BYTES_AT_ONCE", self.body_bytes_at_once),
            (
                "SPLINT_MAX_BODY_BYTES_AT_ONCE_PER_SOURCE",
                self.body_bytes_at_once_per_source,
            ),
            ("SPLINT_MAX_ANSWER_BYTES_AT_ONCE", self.answer_bytes_at_once),
            (
                "SPLINT_MAX_ANSWER_BYTES_AT_ONCE_PER_SOURCE",
                self.answer_bytes_at_once_per_source,
            ),
            ("SPLINT_MAX_WAITS_AT_ONCE", self.waits_at_once),
        ]
    }

    /// These limits, with the ones built in at a start as `running` has them.
    fn as_built_in(self, running: &Self) -> Self {
        Self {
            connections: running.connections,
            calls_at_once: running.calls_at_once,
            calls_at_once_per_source: running.calls_at_once_per_source,
            calls_per_source_per_second: running.calls_per_source_per_second,
            body_bytes_at_once: running.body_bytes_at_once,
            body_bytes_at_once_per_source: running.body_bytes_at_once_per_source,
            answer_bytes_at_once: running.answer_bytes_at_once,
            answer_bytes_at_once_per_source: running.answer_bytes_at_once_per_source,
            waits_at_once: running.waits_at_once,
            ..self
        }
    }

    fn from_settings(
        settings: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, LimitSettingError> {
        let settings: BTreeMap<String, String> = settings
            .into_iter()
            .filter(|(name, _)| name.starts_with(PREFIX))
            .collect();
        let mut known = BTreeSet::new();
        let mut read = |name: &'static str, usual: u32| -> Result<u32, LimitSettingError> {
            known.insert(name);
            let Some(value) = settings.get(name) else {
                return Ok(usual);
            };
            let value = value
                .parse()
                .map_err(|_| LimitSettingError::NotANumber(name))?;
            if value > usual {
                tracing::warn!(
                    setting = name,
                    value,
                    usual,
                    "this limit is above what a small server was measured carrying"
                );
            }
            Ok(value)
        };
        let agents = read("SPLINT_MAX_AGENTS", 1000)?;
        // Half a host unless its operator says, so a flood leaves room for whoever holds a code.
        let open_agents = read("SPLINT_MAX_OPEN_AGENTS", agents / 2)?;
        let limits = Self {
            agents,
            agents_per_owner: read("SPLINT_MAX_AGENTS_PER_OWNER", 8)?,
            new_agents_per_hour: read("SPLINT_MAX_NEW_AGENTS_PER_HOUR", 30)?,
            open_agents,
            open_agents_per_hour: read("SPLINT_MAX_OPEN_AGENTS_PER_HOUR", 20)?,
            open_agents_per_source_per_day: read("SPLINT_MAX_OPEN_AGENTS_PER_SOURCE_PER_DAY", 5)?,
            open_agents_per_source_per_hour: read("SPLINT_MAX_OPEN_AGENTS_PER_SOURCE_PER_HOUR", 3)?,
            open_agents_per_source: read("SPLINT_MAX_OPEN_AGENTS_PER_SOURCE", 5)?,
            // Half the open signups unless its operator says, so those in use always have room.
            unused_stand_ins: read("SPLINT_MAX_UNUSED_STAND_INS", open_agents / 2)?,
            // Three quarters of the open signups unless its operator says.
            open_stand_ins: read("SPLINT_MAX_OPEN_STAND_INS", open_agents / 4 * 3)?,
            sends_per_agent_per_hour: read("SPLINT_MAX_SENDS_PER_AGENT_PER_HOUR", 300)?,
            sends_per_agent_per_day: read("SPLINT_MAX_SENDS_PER_AGENT_PER_DAY", 2500)?,
            sends_per_open_agent_per_hour: read("SPLINT_MAX_SENDS_PER_OPEN_AGENT_PER_HOUR", 120)?,
            sends_per_open_agent_per_day: read("SPLINT_MAX_SENDS_PER_OPEN_AGENT_PER_DAY", 500)?,
            quarantined_per_agent: read("SPLINT_MAX_QUARANTINED_PER_AGENT", 64)?,
            quarantined_per_sender: read("SPLINT_MAX_QUARANTINED_PER_SENDER", 8)?,
            new_requests_per_contact_per_day: read(
                "SPLINT_MAX_NEW_REQUESTS_PER_CONTACT_PER_DAY",
                1000,
            )?,
            new_from_others_per_day: read("SPLINT_MAX_NEW_FROM_OTHERS_PER_DAY", 1000)?,
            connections: read("SPLINT_MAX_CONNECTIONS", 4096)?,
            calls_at_once: read("SPLINT_MAX_CALLS_AT_ONCE", 128)?,
            calls_at_once_per_source: read("SPLINT_MAX_CALLS_AT_ONCE_PER_SOURCE", 32)?,
            calls_per_source_per_second: read("SPLINT_MAX_CALLS_PER_SOURCE_PER_SECOND", 100)?,
            body_bytes_at_once: read("SPLINT_MAX_BODY_BYTES_AT_ONCE", 64 * 1024 * 1024)?,
            body_bytes_at_once_per_source: read(
                "SPLINT_MAX_BODY_BYTES_AT_ONCE_PER_SOURCE",
                4 * 1024 * 1024,
            )?,
            answer_bytes_at_once: read("SPLINT_MAX_ANSWER_BYTES_AT_ONCE", 64 * 1024 * 1024)?,
            answer_bytes_at_once_per_source: read(
                "SPLINT_MAX_ANSWER_BYTES_AT_ONCE_PER_SOURCE",
                4 * 1024 * 1024,
            )?,
            waits_at_once: read("SPLINT_MAX_WAITS_AT_ONCE", 2048)?,
            new_hosts_per_hour: read("SPLINT_MAX_NEW_HOSTS_PER_HOUR", 120)?,
        };
        if let Some(name) = settings.keys().find(|name| !known.contains(name.as_str())) {
            return Err(LimitSettingError::Unknown(name.clone()));
        }
        // Zero is how an operator stops new agents or sends. Here it would stop everything.
        for (name, value) in [
            ("SPLINT_MAX_CONNECTIONS", limits.connections),
            ("SPLINT_MAX_CALLS_AT_ONCE", limits.calls_at_once),
            (
                "SPLINT_MAX_CALLS_AT_ONCE_PER_SOURCE",
                limits.calls_at_once_per_source,
            ),
            (
                "SPLINT_MAX_CALLS_PER_SOURCE_PER_SECOND",
                limits.calls_per_source_per_second,
            ),
        ] {
            if value == 0 {
                return Err(LimitSettingError::AnswersNobody(name));
            }
        }
        // Less than this and the largest body would be refused for good, however quiet the host.
        for (name, value) in [
            ("SPLINT_MAX_BODY_BYTES_AT_ONCE", limits.body_bytes_at_once),
            (
                "SPLINT_MAX_BODY_BYTES_AT_ONCE_PER_SOURCE",
                limits.body_bytes_at_once_per_source,
            ),
        ] {
            if usize::try_from(value).unwrap_or(usize::MAX) < MAX_REQUEST_BYTES {
                return Err(LimitSettingError::FitsNoBody(name, MAX_REQUEST_BYTES));
            }
        }
        // Less than a page and one that's full would be refused for good, however quiet the host.
        for (name, value) in [
            (
                "SPLINT_MAX_ANSWER_BYTES_AT_ONCE",
                limits.answer_bytes_at_once,
            ),
            (
                "SPLINT_MAX_ANSWER_BYTES_AT_ONCE_PER_SOURCE",
                limits.answer_bytes_at_once_per_source,
            ),
        ] {
            if usize::try_from(value).unwrap_or(usize::MAX) < PAGE_BYTES {
                return Err(LimitSettingError::FitsNoPage(name, PAGE_BYTES));
            }
        }
        Ok(limits)
    }

    /// An agent's sends in an hour and a day: this host's numbers for how it came, or lower if its
    /// owner signed lower. An owner who signed nothing, or more, gets this host's. One whose owner
    /// hasn't confirmed gets half an open signup's, whatever its stand-in signed.
    pub fn sends_for(&self, came: Came, owner: Option<&RulesLimits>) -> (u32, u32) {
        let part = |number: u32| number.div_ceil(UNCONFIRMED_PART).max(1);
        let (per_hour, per_day) = if came == Came::Unconfirmed {
            (
                part(self.sends_per_open_agent_per_hour),
                part(self.sends_per_open_agent_per_day),
            )
        } else if came == Came::Open {
            (
                self.sends_per_open_agent_per_hour,
                self.sends_per_open_agent_per_day,
            )
        } else {
            (self.sends_per_agent_per_hour, self.sends_per_agent_per_day)
        };
        let lowered =
            |host: u32, signed: Option<u32>| signed.map_or(host, |signed| host.min(signed));
        (
            lowered(per_hour, owner.and_then(|limits| limits.sends_per_hour)),
            lowered(per_day, owner.and_then(|limits| limits.sends_per_day)),
        )
    }

    /// New interactions with one sender let in by reach in a day: what the owner signed, up to this
    /// host's most.
    pub fn new_requests_for(&self, owner: &RulesLimits) -> u32 {
        owner
            .new_requests_per_contact_per_day
            .min(self.new_requests_per_contact_per_day)
    }

    /// New interactions with one peer in a day, from what the owner signed for them, up to this host's
    /// most.
    pub fn new_requests_capped(&self, signed: u32) -> u32 {
        signed.min(self.new_requests_per_contact_per_day)
    }

    /// New interactions and messages from everyone let in by reach, the same way.
    pub fn new_from_others_for(&self, owner: &RulesLimits) -> u32 {
        owner
            .new_from_others_per_day
            .min(self.new_from_others_per_day)
    }
}

#[cfg(test)]
impl Limits {
    pub fn for_tests() -> Self {
        Self::from_settings([]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(settings: &[(&str, &str)]) -> Result<Limits, LimitSettingError> {
        Limits::from_settings(
            settings
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        )
    }

    fn owner(sends_per_hour: Option<u32>, sends_per_day: Option<u32>) -> RulesLimits {
        RulesLimits {
            new_requests_per_contact_per_day: 3,
            open_requests_per_contact: 3,
            open_approvals: 10,
            new_from_others_per_day: 50,
            texts_per_contact_per_day: 20,
            agreed_texts_per_day: None,
            agreed_new_requests_per_day: None,
            sends_per_hour,
            sends_per_day,
        }
    }

    #[test]
    fn an_operator_can_raise_or_lower_each_and_open_signups_follow_the_total() {
        let set = limits(&[
            ("SPLINT_MAX_AGENTS", "9000"),
            ("SPLINT_MAX_AGENTS_PER_OWNER", "0"),
        ]);
        let set = set.unwrap();
        assert_eq!((set.agents, set.open_agents), (9000, 4500));
        assert_eq!(set.agents_per_owner, 0);
        let set = limits(&[
            ("SPLINT_MAX_AGENTS", "9000"),
            ("SPLINT_MAX_OPEN_AGENTS", "7"),
        ]);
        assert_eq!(set.unwrap().open_agents, 7);
    }

    #[test]
    fn a_mistyped_name_or_number_stops_the_host() {
        for wrong in [
            ("SPLINT_MAX_AGENT", "9000"),
            ("SPLINT_MAX_AGENTS", "many"),
            ("SPLINT_MAX_AGENTS", "-1"),
            ("SPLINT_MAX_AGENTS", ""),
            ("SPLINT_MAX_AGENTS", "4294967296"),
            ("SPLINT_MAX_CONNECTIONS", "0"),
            ("SPLINT_MAX_CALLS_AT_ONCE", "0"),
            ("SPLINT_MAX_CALLS_AT_ONCE_PER_SOURCE", "0"),
            ("SPLINT_MAX_CALLS_PER_SOURCE_PER_SECOND", "0"),
            ("SPLINT_MAX_BODY_BYTES_AT_ONCE", "64"),
            ("SPLINT_MAX_BODY_BYTES_AT_ONCE_PER_SOURCE", "0"),
            ("SPLINT_MAX_ANSWER_BYTES_AT_ONCE", "4096"),
            ("SPLINT_MAX_ANSWER_BYTES_AT_ONCE_PER_SOURCE", "0"),
        ] {
            assert!(limits(&[wrong]).is_err(), "{wrong:?}");
        }
    }

    /// The bugs: a line that sets nothing passing as a limit, and half a file taken when a later
    /// line is wrong, so a host runs on numbers nobody chose.
    #[test]
    fn a_limits_file_is_taken_whole_or_not_at_all() {
        let live = Live::new(limits(&[]).unwrap());
        let usual = live.now();
        for wrong in [
            "SPLINT_MAX_AGENTS=5\nSPLINT_MAX_AGENTS=6",
            "SPLINT_MAX_AGENTS=5\nSPLINT_DOMAIN=host.example",
            "SPLINT_MAX_AGENTS=5\nSPLINT_MAX_AGENTS_PER_OWNER",
            "SPLINT_MAX_AGENTS=5\nSPLINT_MAX_AGENTS_PER_OWNER=many",
            "SPLINT_MAX_AGENTS=5\nSPLINT_MAX_AGENT=9",
            "SPLINT_MAX_AGENTS=5\nexport SPLINT_MAX_AGENTS_PER_OWNER=2",
            "SPLINT_MAX_AGENTS=5\nSPLINT_MAX_CONNECTIONS=0",
        ] {
            assert!(live.take(wrong).is_err(), "{wrong}");
            assert!(live.now() == usual, "{wrong}");
        }

        let at_restart = live
            .take("# a comment\n\n  SPLINT_MAX_AGENTS = 5 \n#SPLINT_MAX_AGENTS_PER_OWNER=1\nSPLINT_MAX_CONNECTIONS=7\n")
            .unwrap();
        assert_eq!(at_restart, ["SPLINT_MAX_CONNECTIONS"]);
        let taken = live.now();
        assert_eq!((taken.agents, taken.open_agents), (5, 2));
        assert_eq!(taken.agents_per_owner, usual.agents_per_owner);
        assert_eq!(
            taken.connections, usual.connections,
            "its guard was built for this many"
        );

        // A limit taken out of the file goes back to the usual number, as at a start.
        assert!(live.take("").unwrap().is_empty());
        assert!(live.now() == usual);
    }

    #[test]
    fn an_owner_can_only_lower_what_the_host_allows() {
        let raised = limits(&[
            ("SPLINT_MAX_SENDS_PER_AGENT_PER_HOUR", "5000"),
            ("SPLINT_MAX_SENDS_PER_AGENT_PER_DAY", "90000"),
            ("SPLINT_MAX_NEW_REQUESTS_PER_CONTACT_PER_DAY", "5000"),
            ("SPLINT_MAX_NEW_FROM_OTHERS_PER_DAY", "4000"),
        ])
        .unwrap();
        let usual = limits(&[]).unwrap();
        assert_eq!(raised.sends_for(Came::WithCode, None), (5000, 90000));
        assert_eq!(
            raised.sends_for(Came::WithCode, Some(&owner(Some(10), None))),
            (10, 90000)
        );
        assert_eq!(
            raised.sends_for(Came::WithCode, Some(&owner(None, Some(20)))),
            (5000, 20)
        );
        for came in [Came::WithCode, Came::Open] {
            assert_eq!(
                usual.sends_for(came, Some(&owner(Some(u32::MAX), Some(u32::MAX)))),
                usual.sends_for(came, None),
                "signing more than the host allows gets no more"
            );
        }

        let mut signed = owner(None, None);
        signed.new_requests_per_contact_per_day = 3000;
        signed.new_from_others_per_day = 6000;
        assert_eq!(raised.new_requests_for(&signed), 3000);
        assert_eq!(raised.new_from_others_for(&signed), 4000);
        signed.new_requests_per_contact_per_day = 3;
        assert_eq!(raised.new_requests_for(&signed), 3);
    }
}

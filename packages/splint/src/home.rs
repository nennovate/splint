//! Where one agent's Splint lives: `~/.splint`, readable only by whoever set it up. On Windows `~` is
//! the user's profile folder, and Signet's socket and Splint on the computer's are named pipes.
//!
//! A profile is another agent of the same person on this machine, in `~/.splint/profiles/NAME`, with
//! its own Signet, keys, token, contacts and settings. What belongs to the person, their owner key and
//! the agents they've authorized, stays in `~/.splint` and is shared. With no profile chosen it's the
//! agent in `~/.splint` itself, as before profiles.

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use splint_core::{SplintId, parse_address, private_files};

use crate::failure::Failure;
use crate::owner_key::AgentBackup;
use crate::secrets::{Token, write_private};

/// The setting that says where the user's own folder is, which the Splint folder is inside. On Windows
/// it's their profile folder, not their application data: Windows sends what a packaged app, such as
/// one from the Store, writes under `AppData` to the app's own folder instead, which nothing outside
/// the app sees, so a Task Scheduler task found nothing there, and which is deleted with the app, keys
/// and all. A packaged app's writes go nowhere else in the profile. The cost: a roaming profile copies
/// everything but `AppData\Local` to its server at logoff and onto each PC the user logs in to, so
/// the keys and Signet's state go with it, and nothing yet warns of one.
#[cfg(unix)]
pub const HOME_SETTING: &str = "HOME";
#[cfg(windows)]
pub const HOME_SETTING: &str = "USERPROFILE";
/// The Splint folder's name inside it.
const SPLINT_FOLDER: &str = ".splint";
/// The installed `splint`, as a person types it on a Mac or Linux.
pub const SPLINT_SHOWN_ON_UNIX: &str = "~/.splint/bin/splint";
/// The same on Windows, in PowerShell, where a quoted path runs only after `&`. Nothing installs it
/// on PATH, and `$env:USERPROFILE` is the folder `HOME_SETTING` names. It's for a person at their own
/// Windows computer; an agent there is given `SPLINT_SHOWN_ON_UNIX`, which a real Windows run showed
/// both Windows PowerShell 5.1 and Git Bash run, where this form fails in Git Bash.
pub const SPLINT_SHOWN_ON_WINDOWS: &str = r#"& "$env:USERPROFILE\.splint\bin\splint.exe""#;
/// Chooses a profile for a program that starts `splint` or an adapter itself, as `--as` does.
pub const PROFILE_SETTING: &str = "SPLINT_AS";
const PROFILES: &str = "profiles";
const MAX_PROFILE_CHARS: usize = 32;
/// The longest socket path every system takes: macOS's 104 bytes, less the ending zero.
#[cfg(unix)]
const MAX_SOCKET_PATH_BYTES: usize = 103;
/// Enough of a hash of a folder to tell one agent's pipe from another's on one machine.
#[cfg(windows)]
const PIPE_HASH_BYTES: usize = 8;

pub struct Home {
    /// `~/.splint`, with what the person has: the owner key, programs, schemas and a host.
    root: PathBuf,
    /// This agent's own folder, which is `root` for the default profile.
    own: PathBuf,
    profile: Option<String>,
}

/// The installed `splint`, as a person or an agent types it in a message here.
pub fn splint_shown() -> &'static str {
    SPLINT_SHOWN_ON_UNIX
}

/// A line that runs `command` with `value` on its standard input, where no other user of this
/// machine can list it as they can a process's arguments: `printf` in a Unix shell, and on Windows
/// `echo`, which both PowerShell, with no `printf`, and Git Bash run with a single-quoted value.
pub fn with_on_stdin(value: &str, command: &str) -> String {
    if cfg!(windows) {
        format!("echo '{value}' | {command}")
    } else {
        format!("printf '%s' '{value}' | {command}")
    }
}

/// A pipe's name for one program of one Splint folder: `\\.\pipe\splint-PROGRAM-` and a hash of
/// `dir`, so two agents', or two people's, never share one on one machine.
#[cfg(windows)]
fn pipe_named(program: &str, dir: &Path) -> PathBuf {
    let hash = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        dir.as_os_str().as_encoded_bytes(),
    );
    let short: String = hash
        .as_ref()
        .iter()
        .take(PIPE_HASH_BYTES)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    PathBuf::from(format!(r"\\.\pipe\splint-{program}-{short}"))
}

/// A name a person can type and read, which can't climb out of the profiles folder or look like an option.
pub fn is_profile_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && name.chars().count() <= MAX_PROFILE_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl Home {
    /// The profile `--as` named, or else `SPLINT_AS`, or else the default.
    pub fn from_env(chosen: Option<&str>) -> Result<Self, Failure> {
        let home = env::var_os(HOME_SETTING)
            .ok_or_else(|| Failure::refused(format!("{HOME_SETTING} isn't set")))?;
        let root = Path::new(&home).join(SPLINT_FOLDER);
        let setting = env::var(PROFILE_SETTING)
            .ok()
            .filter(|name| !name.is_empty());
        match chosen.map(str::to_owned).or(setting) {
            Some(name) => Self::profile_in(root, &name),
            None => Ok(Self {
                own: root.clone(),
                root,
                profile: None,
            }),
        }
    }

    fn profile_in(root: PathBuf, name: &str) -> Result<Self, Failure> {
        if !is_profile_name(name) {
            return Err(Failure::refused(format!(
                "a profile's name is up to {MAX_PROFILE_CHARS} lower-case letters, digits and -, \
                 starting with a letter or digit"
            )));
        }
        Ok(Self {
            own: root.join(PROFILES).join(name),
            root,
            profile: Some(name.to_owned()),
        })
    }

    /// The default and every profile on this machine, the default first.
    pub fn every(&self) -> Result<Vec<Self>, Failure> {
        let mut names: Vec<String> = match fs::read_dir(self.root.join(PROFILES)) {
            Ok(found) => found
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| is_profile_name(name))
                .collect(),
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        names.sort();
        let mut all = vec![self.the_default()];
        for name in names {
            all.push(Self::profile_in(self.root.clone(), &name)?);
        }
        Ok(all)
    }

    /// The agent in `~/.splint` itself, which signs for the agents authorized from this machine.
    pub fn the_default(&self) -> Self {
        Self {
            own: self.root.clone(),
            root: self.root.clone(),
            profile: None,
        }
    }

    /// The profile's name, or `None` for the default.
    pub fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    /// How an agent runs `splint` as this agent: the whole path, as installing puts nothing on PATH,
    /// and a profile's own `--as`, or what it runs would reach the default agent.
    pub fn command(&self) -> String {
        let splint = splint_shown();
        match &self.profile {
            Some(name) => format!("{splint} --as {name}"),
            None => splint.to_owned(),
        }
    }

    /// Tightens a directory that's already there, because `make install` may have made it.
    pub fn make_private(dir: &Path) -> Result<(), Failure> {
        private_files::make_private_dir(dir)?;
        Ok(())
    }

    fn prepare_own(&self) -> Result<(), Failure> {
        Self::make_private(&self.root)?;
        if self.profile.is_some() {
            Self::make_private(&self.root.join(PROFILES))?;
        }
        Self::make_private(&self.own)?;
        Self::make_private(&self.signet_dir())?;
        Self::make_private(&self.own.join("run"))
    }

    pub fn prepare(&self) -> Result<(), Failure> {
        self.prepare_own()?;
        Self::make_private(&self.owner_dir())
    }

    /// For an agent whose owner's device is somewhere else: no folder for keys, as none belong here.
    pub fn prepare_for_agent(&self) -> Result<(), Failure> {
        self.prepare_own()
    }

    /// For an agent joining on its own, whose stand-in is its alone, even beside its owner's key.
    pub fn prepare_for_stand_in(&self) -> Result<(), Failure> {
        self.prepare_own()?;
        Self::make_private(&self.stand_in_dir())
    }

    pub fn exists(&self) -> bool {
        self.own.exists()
    }

    /// Whether an agent is here, joined or waiting for its owner. A folder alone isn't one, as a
    /// command run with a mistyped profile could have left one.
    pub fn has_agent(&self) -> bool {
        self.saved_path().exists() || self.join_file().exists()
    }

    /// When no agent is here but others are on this machine: which they are, and how to choose one.
    /// Told to join instead, an agent that left out or mistyped `--as` makes a second agent of itself.
    pub fn others_instead(&self) -> Result<Option<String>, Failure> {
        // An owner's device needn't have an agent of its own, beside those it authorized.
        if self.has_agent() || (self.profile.is_none() && self.authorized_file().exists()) {
            return Ok(None);
        }
        let others: Vec<Self> = self.every()?.into_iter().filter(Self::has_agent).collect();
        let Some(first) = others.first() else {
            return Ok(None);
        };
        let names: Vec<String> = others
            .iter()
            .map(|one| match one.profile() {
                Some(name) => format!("--as {name}"),
                None => "the default, with no --as".to_owned(),
            })
            .collect();
        let missing = match &self.profile {
            Some(name) => format!("no agent called {name} is on this machine"),
            None => "no agent is set up here without --as".to_owned(),
        };
        Ok(Some(format!(
            "{missing}. Run each command as the agent you are, which here is one of: {}. Such as {} \
             status, or {PROFILE_SETTING}=NAME for a program that runs splint",
            names.join(", "),
            first.command(),
        )))
    }

    /// Refuses a command for no agent at all, when the one meant is another on this machine.
    pub fn refuse_if_another_is_meant(&self) -> Result<(), Failure> {
        match self.others_instead()? {
            Some(words) => Err(Failure::refused(words)),
            None => Ok(()),
        }
    }

    /// The key that signs for this agent here: its own stand-in if it joined on its own, or else the
    /// owner's, which every profile shares.
    pub fn owner_dir(&self) -> PathBuf {
        let stand_in = self.stand_in_dir();
        if self.profile.is_some() && stand_in.exists() {
            return stand_in;
        }
        self.root.join("owner")
    }

    /// Where a stand-in for this agent's owner is kept, which is deleted once they confirm it. It's the
    /// owner's own folder for the default, as it always was.
    pub fn stand_in_dir(&self) -> PathBuf {
        self.own.join("owner")
    }

    /// What Splint on this computer keeps for the person who uses it: their sign-in and owner ID, apart
    /// from any agent's folder or stand-in, and what their agents asked. Every profile shares it.
    pub fn computer_dir(&self) -> PathBuf {
        self.root.join("computer")
    }

    /// Where Splint on this computer takes asks from programs run by this user alone.
    #[cfg(unix)]
    pub fn computer_socket(&self) -> PathBuf {
        self.root.join("run").join("computer.sock")
    }

    /// On Windows, a named pipe, named from the Splint folder, which only this user can open. Any
    /// user can see a pipe's name, so a client also checks `computer_lock` is held before it sends
    /// anything, as for Signet's.
    #[cfg(windows)]
    pub fn computer_socket(&self) -> PathBuf {
        pipe_named("computer", &self.root.join("run"))
    }

    /// Held by Splint on this computer for as long as it runs, from once its pipe is its own, so a
    /// client knows the pipe is its: as `signet_lock` is Signet's.
    #[cfg(windows)]
    pub fn computer_lock(&self) -> PathBuf {
        self.computer_dir().join("computer.lock")
    }

    pub fn signet_dir(&self) -> PathBuf {
        self.own.join("signet")
    }

    pub fn host_dir(&self) -> PathBuf {
        self.root.join("host")
    }

    pub fn adapters(&self) -> PathBuf {
        self.root.join("adapters")
    }

    /// One-use links this owner made, with their keys, so a link can be copied again until it ends.
    pub fn guest_links_file(&self) -> PathBuf {
        self.root.join("owner").join("guest-links.json")
    }

    pub fn schemas(&self) -> PathBuf {
        self.root.join("schemas")
    }

    pub fn rules_file(&self) -> PathBuf {
        self.own.join("rules.json")
    }

    /// Where the agent's Signet is, and where to find its token. Nothing secret is in it, so sourcing
    /// it can't put a token in a shell's trace or environment.
    pub fn agent_env(&self) -> PathBuf {
        self.own.join("agent.env")
    }

    /// The agent's token, as curl options, so curl reads it and it's never in anyone's arguments.
    pub fn agent_curl(&self) -> PathBuf {
        self.own.join("agent.curl")
    }

    /// What `splint join` is waiting on, until the owner's answer comes.
    pub fn join_file(&self) -> PathBuf {
        self.own.join("join.json")
    }

    /// The keys an owner-first join prepared, set aside while a signup code is tried in its place.
    pub fn owner_first_signet_dir(&self) -> PathBuf {
        self.own.join("signet-owner-first")
    }

    /// A move to another host under way: where to, and the ask or what the owner signed for it.
    pub fn move_file(&self) -> PathBuf {
        self.own.join("move.json")
    }

    /// Where a release that took pairing codes kept the owner whose answer this agent waited for. It's
    /// only removed now, with the rest of an agent's files.
    pub fn pairing_file(&self) -> PathBuf {
        self.own.join("pairing.json")
    }

    /// This agent's public key, which Signet writes when asked to prepare.
    pub fn agent_public_key(&self) -> PathBuf {
        self.signet_dir().join("agent.pub")
    }

    /// On an owner's device: the agents authorized from here, whichever profile authorized them.
    pub fn authorized_file(&self) -> PathBuf {
        self.root.join("authorized.json")
    }

    /// On an owner's device: the network addresses its owner named for reaching agents' Signets
    /// straight, by agent, whichever profile named them.
    pub fn direct_file(&self) -> PathBuf {
        self.root.join("direct.json")
    }

    /// On an owner's device: how each agent was last reached, straight or by way of its host.
    pub fn routes_file(&self) -> PathBuf {
        self.root.join("routes.json")
    }

    /// On an owner's device: when each agent's newest view read here was signed, so an older one
    /// handed back straight from the network isn't taken over it.
    pub fn views_file(&self) -> PathBuf {
        self.root.join("views.json")
    }

    /// On an owner's device: rules and where the owner gets paid that only something answering for an
    /// agent's Signet took, each kept until its host takes it.
    pub fn not_at_host_dir(&self) -> PathBuf {
        self.root.join("not-at-host")
    }

    /// Where what keeps this agent's programs running lives: pid files, logs and what each starts with.
    pub fn run_dir(&self) -> PathBuf {
        self.own.join("run")
    }

    /// Locked by a service for as long as it runs, with its pid inside, so whether one runs, and which
    /// process it is, never rests on a pid file that a stopped one left.
    pub fn lock_file(&self, service: &str) -> PathBuf {
        self.run_dir().join(format!("{service}.lock"))
    }

    /// Left by `splint stop`, and cleared only by `splint start` or `splint setup`, so nothing else
    /// starts this agent's services again behind its owner's back.
    pub fn stopped_mark(&self) -> PathBuf {
        self.run_dir().join("stopped")
    }

    /// Where Signet serves its API, which only this user can reach, as the folder is theirs alone. A
    /// client that finds nothing there sends nothing, so no other program can take Signet's place and
    /// hear a token, as one could on a loopback port while Signet was stopped.
    #[cfg(unix)]
    pub fn signet_socket(&self) -> PathBuf {
        self.run_dir().join("signet.sock")
    }

    /// On Windows, a named pipe, named from this agent's folder, which only this user can open. Any user
    /// can see a pipe's name, so a client also checks Signet's lock is held before it sends anything,
    /// as `signet_lock` says.
    #[cfg(windows)]
    pub fn signet_socket(&self) -> PathBuf {
        pipe_named("signet", &self.run_dir())
    }

    /// Held by Signet for as long as it runs. On Windows nothing else can open it to write meanwhile,
    /// which is how a client knows the pipe it's about to send to is Signet's: while Signet runs, no
    /// other user can make an instance of its pipe, and once it stops this can be opened again.
    #[cfg(windows)]
    pub fn signet_lock(&self) -> PathBuf {
        self.signet_dir().join("signet.lock")
    }

    /// The same, if the system can listen there, as a socket's path has a short limit, and if the files
    /// that name it can hold it.
    pub fn usable_signet_socket(&self) -> Result<PathBuf, Failure> {
        let socket = self.signet_socket();
        if socket.to_string_lossy().chars().any(char::is_control) {
            return Err(Failure::refused(
                "the Splint folder's path has characters Signet's socket can't be named with",
            ));
        }
        #[cfg(unix)]
        if socket.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
            return Err(Failure::refused(format!(
                "Signet's socket would be {}, which is longer than this system takes for one: use a \
                 shorter profile name or a shorter home folder",
                socket.display()
            )));
        }
        Ok(socket)
    }

    pub fn log_file(&self, service: &str) -> PathBuf {
        self.run_dir().join(format!("{service}.log"))
    }

    /// What a service starts with, its settings and tokens among them, which only this user can read.
    pub fn launch_file(&self, service: &str) -> PathBuf {
        self.run_dir().join(format!("{service}.json"))
    }

    /// The `HOME` this Splint folder is in, where the system looks for a user's own services.
    pub fn user_home(&self) -> Result<&Path, Failure> {
        self.root
            .parent()
            .ok_or_else(|| Failure::refused("can't tell which home folder Splint is in"))
    }

    /// The command this agent's kept listener runs for each change, as whoever registered it from a
    /// shell here gave it. Not in `run`, as it outlasts `splint stop`.
    pub fn kept_listener_file(&self) -> PathBuf {
        self.own.join("listener.json")
    }

    /// When the kept listener last ran its command, so the gap its runtime chose holds across a
    /// restart of the listener.
    pub fn kept_listener_woke(&self) -> PathBuf {
        self.run_dir().join("splint-listen.woke")
    }

    /// Held, shared, by each `splint listen` that says its line to a runtime with a session open, for
    /// as long as it runs, so the kept listener can tell its command that one is listening too.
    pub fn watchers_lock(&self) -> PathBuf {
        self.run_dir().join("watchers.lock")
    }

    /// Where each program keeping watch for this agent keeps the mark it last heard up to.
    pub fn marks_dir(&self) -> PathBuf {
        self.own.join("marks")
    }

    pub fn saved_path(&self) -> PathBuf {
        self.own.join("setup.json")
    }
}

/// What setup decided, kept so every later command does the same.
#[derive(Serialize, Deserialize)]
pub struct Installed {
    pub address: String,
    pub api_token: Token,
    pub owner_token: Token,
    pub backup: AgentBackup,
    /// The agent's ID, once the host has taken its registration. A code is spent by then.
    pub agent: Option<SplintId>,
    /// The owner's public identity, if their keys are on another device. Nothing here can sign for
    /// them then, and a command that would have to is refused rather than making new keys.
    #[serde(default)]
    pub owner_elsewhere: Option<String>,
    /// The folder the agent joined from, so what keeps watch for it in a runtime started there can
    /// stay quiet everywhere else on this machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_from: Option<PathBuf>,
    /// Where Signet also listens for its owner's device on another machine, which its operator turned
    /// on. Off unless they did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_network: Option<OwnerNetwork>,
    /// The agent's ID a Signet started here takes up in place of making a new one, after its person
    /// recovered on a new computer, until that Signet has taken the recovery naming its keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovering: Option<String>,
    /// New keys may take the place of this agent's lost ones: its person said yes, or a recovery made
    /// this folder, which never held any. So a run that's cut off doesn't ask again, and one that kept
    /// good keys until it was cut off still asks if they're lost afterwards.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replacing_keys: bool,
}

/// Owner network access, as its operator turned it on.
#[derive(Clone, Serialize, Deserialize)]
pub struct OwnerNetwork {
    /// An IP address and port on this machine, such as its LAN or VPN address.
    pub at: String,
    /// The operator meant every address this machine has, which is otherwise refused.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub every_network: bool,
}

impl Installed {
    pub fn create(address: &str, backup: AgentBackup) -> Result<Self, Failure> {
        Ok(Self {
            address: address.to_owned(),
            api_token: Token::generate()?,
            owner_token: Token::generate()?,
            backup,
            agent: None,
            owner_elsewhere: None,
            joined_from: None,
            owner_network: None,
            recovering: None,
            replacing_keys: false,
        })
    }

    /// Notes the folder this runs in as where the agent joined, unless one's noted already. Only
    /// what the agent runs itself calls this, never its person's setup, which runs elsewhere.
    #[must_use]
    pub fn joined_here(self) -> Self {
        if self.joined_from.is_some() {
            return self;
        }
        Self {
            joined_from: env::current_dir().and_then(|dir| dir.canonicalize()).ok(),
            ..self
        }
    }

    pub fn load(home: &Home) -> Result<Option<Self>, Failure> {
        match fs::read(home.saved_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| Failure::refused("setup.json in the Splint folder can't be read")),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// For commands that need setup to have finished.
    pub fn require(home: &Home) -> Result<(Self, SplintId), Failure> {
        home.refuse_if_another_is_meant()?;
        let not_yet = || {
            Failure::refused(if home.join_file().exists() {
                "this agent is waiting for its owner: run splint finish with their answer"
            } else if home.profile().is_none() && home.authorized_file().exists() {
                "the agents you authorized run on other devices: splint agents lists them"
            } else {
                "this agent isn't set up yet: an agent runs splint join"
            })
        };
        let installed = Self::load(home)?.ok_or_else(not_yet)?;
        let agent = installed.agent.clone().ok_or_else(not_yet)?;
        Ok((installed, agent))
    }

    pub fn save(&self, home: &Home) -> Result<(), Failure> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| Failure::refused("couldn't write down the setup"))?;
        write_private(&home.saved_path(), &bytes)?;
        // It names the socket too, so a curl call made with it reaches only this agent's Signet, whatever
        // address it's given.
        let curl = format!(
            "header = \"Authorization: Bearer {}\"\nheader = \"Content-Type: application/json\"\n\
             unix-socket = \"{}\"\n",
            self.api_token.expose(),
            curl_quoted(&home.signet_socket().to_string_lossy()),
        );
        write_private(&home.agent_curl(), curl.as_bytes())?;
        let env = format!(
            "export SPLINT_SIGNET_SOCKET={}\nexport SPLINT_CURL_CONFIG={}\n",
            home.signet_socket().display(),
            home.agent_curl().display(),
        );
        // What the adapter checks is held before it sends anything down the pipe.
        #[cfg(windows)]
        let env = format!(
            "{env}export SPLINT_SIGNET_LOCK={}\n",
            home.signet_lock().display()
        );
        write_private(&home.agent_env(), env.as_bytes())?;
        Ok(())
    }

    /// The same, for what only the owner can do, which has to happen on the device with their key.
    pub fn require_owner_here(home: &Home, what: &str) -> Result<(Self, SplintId), Failure> {
        let (installed, agent) = Self::require(home)?;
        if installed.owner_elsewhere.is_some() {
            return Err(Failure::refused(format!(
                "only your owner can {what}, from their own device, as their key isn't here"
            )));
        }
        Ok((installed, agent))
    }

    pub fn host_domain(&self) -> Result<&str, Failure> {
        Ok(parse_address(&self.address)?.1)
    }
}

/// Inside a quoted value of a curl config file, where `\\` and `"` are escaped.
fn curl_quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_name_stays_inside_its_folder_and_is_never_an_option() {
        for good in ["work", "a", "agent-2", "0", &"a".repeat(MAX_PROFILE_CHARS)] {
            assert!(is_profile_name(good), "{good}");
        }
        for bad in [
            "",
            "..",
            ".",
            "a/b",
            "../owner",
            "-rf",
            "--as",
            "Work",
            "a b",
            "a.b",
            "a_b",
            "é",
            &"a".repeat(MAX_PROFILE_CHARS + 1),
        ] {
            assert!(!is_profile_name(bad), "{bad}");
        }
    }
}

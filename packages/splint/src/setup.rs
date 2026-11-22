//! `splint setup`, and keeping what it set up running.

use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use serde_json::json;
use splint_core::registration_state::RegistrationState;
use splint_core::transport::stays_on_this_machine;
use splint_core::{AgentKeys, Identity, name_parts, parse_address, unix_now};

use crate::authorize;
use crate::auto;
use crate::contacts::line_for;
use crate::failure::Failure;
use crate::home::{Home, Installed, PROFILE_SETTING};
use crate::host_calls::HostCalls;
use crate::join::{prepared_key, waiting_address};
use crate::listen::kept;
use crate::owner_key::OwnerKey;
use crate::owner_side;
use crate::rules::{self, first_rules};
use crate::services::{self, Keep, Service, Started};
use crate::signet_api::{SignetApi, Who};

pub const SIGNET: &str = "splint-signet";
/// Setup makes the owner key as the user it runs as, which is the user Signet runs as too, and nothing
/// here can tell which user an agent runs as. So it's off unless the owner says no agent runs as this
/// user, and that's warned of whenever it's so.
pub const OWNER_KEY_HERE: &str = "--owner-key-here";
/// How long a Signet has to answer. It answers whether or not its host does.
const SIGNET_WAIT: Duration = Duration::from_secs(40);
const CONNECT_NOTE: &str = "connect.txt";

/// From stdin, where other programs on this machine can't list it, and a spent code stays useless
/// to anyone reading this shell's history.
/// A program piping one in sees no prompt, as there's nobody to read it.
pub fn read_signup_code() -> Result<String, Failure> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        write!(io::stderr(), "Signup code from whoever runs the host: ")?;
        io::stderr().flush()?;
    }
    let mut code = String::new();
    stdin.lock().read_line(&mut code)?;
    let code = code.trim().to_owned();
    if code.is_empty() {
        return Err(Failure::SignupCodeNeeded(
            "this host needs a signup code from whoever runs it, on stdin".to_owned(),
        ));
    }
    Ok(code)
}

/// Starts Signet if it isn't running, kept running where this system can, on its socket in this
/// agent's own folder.
pub async fn start_signet(
    home: &Home,
    installed: &Installed,
    signup_code: Option<&str>,
) -> Result<(), Failure> {
    let socket = home.usable_signet_socket()?;
    let socket = socket.to_string_lossy();
    // Written again each time, so what an older install wrote, which named a port, names the socket.
    installed.save(home)?;
    let owner = match &installed.owner_elsewhere {
        Some(identity) => identity.clone(),
        None => OwnerKey::new(home).identity()?,
    };
    let state = home.signet_dir();
    let state = state.to_string_lossy();
    let mut env = vec![
        ("SPLINT_ADDRESS", installed.address.as_str()),
        ("SPLINT_STATE_DIR", state.as_ref()),
        ("SPLINT_API_TOKEN", installed.api_token.expose()),
        ("SPLINT_OWNER_TOKEN", installed.owner_token.expose()),
        ("SPLINT_OWNER_IDENTITY", owner.as_str()),
        (
            "SPLINT_RECOVERY_COMMITMENT",
            installed.backup.commitment.as_str(),
        ),
        ("SPLINT_LISTEN_SOCKET", socket.as_ref()),
    ];
    // Then nothing can call in to its owner, so it leaves what they read at its host.
    if installed.owner_elsewhere.is_some() {
        env.push(("SPLINT_OWNER_AWAY", "yes"));
    }
    // A host on this machine has no certificate to show, and traffic to it never leaves. Anything
    // else is HTTPS, and no setting here changes that.
    if stays_on_this_machine(installed.host_domain()?) {
        env.push(("SPLINT_SCHEME", "http"));
        env.push(("SPLINT_TEST_ONLY_PLAIN_HTTP", "yes"));
    }
    if let Some(code) = signup_code {
        env.push(("SPLINT_SIGNUP_CODE", code));
    }
    // So a folder that lost what says who it is can't start as a new agent.
    if installed.agent.is_some() {
        env.push(("SPLINT_JOINED", "yes"));
    }
    // Its ID, to take up with new keys, where the keys it ran on were lost.
    if let Some(identity) = &installed.recovering {
        env.push(("SPLINT_RECOVERING", identity.as_str()));
    }
    if let Some(network) = &installed.owner_network {
        env.push(("SPLINT_OWNER_NETWORK", network.at.as_str()));
        if network.every_network {
            env.push(("SPLINT_OWNER_NETWORK_EVERY_NETWORK", "yes"));
        }
    }
    let before = services::log_end(home, SIGNET);
    let started = services::start(
        home,
        &Service {
            name: SIGNET,
            binary: SIGNET,
            args: &[],
            env,
            keep: Keep::AcrossRestarts,
        },
    );
    let wont_start = |failure| match services::refusal_since(home, SIGNET, before) {
        Some(said) => Failure::SignetWontStart(said),
        None => failure,
    };
    let Started::Running = started.map_err(wont_start)? else {
        return Err(Failure::Stopped);
    };
    let api = SignetApi::new(home, installed)?;
    let ready = || api.is_up();
    if let Err(failure) = services::wait_for(home, SIGNET, SIGNET, SIGNET_WAIT, ready).await {
        // It answers whatever its host does, so this is Signet's own trouble, and a keeper would only
        // start it again and again.
        services::stop(home, SIGNET, SIGNET).await?;
        return Err(wont_start(failure));
    }
    let Some(failure) = not_signed_on(home, installed, &api.who_settled().await?)? else {
        return Ok(());
    };
    // A code it was given needn't outlast this, and what keeps Signet running stays otherwise, so it
    // signs on by itself once it can, and this agent can still move away from a host that's gone.
    if signup_code.is_some() {
        services::stop(home, SIGNET, SIGNET).await?;
    }
    Err(failure)
}

/// Why a Signet that answers isn't signed on at its host, for whoever started it. An agent with no
/// binding yet, or one only its owner can put right, has nothing to wait for here.
fn not_signed_on(
    home: &Home,
    installed: &Installed,
    who: &Who,
) -> Result<Option<Failure>, Failure> {
    let domain = installed.host_domain()?;
    let said = who.registration_problem.clone().unwrap_or_default();
    let splint = home.command();
    let goes_on = format!(
        "Signet stays up and keeps trying by itself: {splint} status says when it's back, and if \
         that host is gone for good, {splint} switch-host HANDLE~HOST --leave-mail moves this agent"
    );
    Ok(match who.registration {
        None
        | Some(
            RegistrationState::Registered
            | RegistrationState::NotBound
            | RegistrationState::NeedsOwner
            | RegistrationState::Unknown,
        ) => None,
        Some(RegistrationState::Starting | RegistrationState::HostUnreachable) => {
            Some(Failure::HostUnreachable(format!(
                "Signet is running, but can't reach its host {domain} yet, so nothing can be read or \
                 sent. {goes_on}"
            )))
        }
        Some(RegistrationState::ClockOff) => Some(Failure::ClockOff(format!(
            "Signet can't sign in at {domain}, as {said}"
        ))),
        Some(RegistrationState::HostBusy) => Some(Failure::TryLater(format!("{said}. {goes_on}"))),
        Some(RegistrationState::SignupCodeRefused) => Some(Failure::SignupCodeRefused),
        Some(RegistrationState::NameTaken) => {
            let (handle, _) = parse_address(&installed.address)?;
            Some(Failure::HandleTaken {
                handle: handle.to_owned(),
                domain: domain.to_owned(),
            })
        }
        Some(RegistrationState::HostRefused | RegistrationState::OtherProtocol) => {
            Some(Failure::NotRegistered(format!(
                "{domain} didn't take this agent back: {said}. {goes_on}"
            )))
        }
    })
}

/// Whether Signet is up after all, with only its host keeping it from signing on, which it goes on
/// trying by itself.
pub fn up_without_its_host(failure: &Failure) -> bool {
    matches!(
        failure,
        Failure::HostUnreachable(_)
            | Failure::ClockOff(_)
            | Failure::TryLater(_)
            | Failure::NotRegistered(_)
    )
}

/// Each adapter says how it's connected, because nothing in `packages/` may name a runtime. An
/// adapter's settings name no socket and no file, only the profile if there is one, so they're the same
/// before the agent joins and after: it finds both in the agent's folder.
pub fn connect(home: &Home) -> Result<String, Failure> {
    let env_file = home.agent_env();
    let curl_file = home.agent_curl();
    let mut adapters: Vec<_> = match fs::read_dir(home.adapters()) {
        Ok(found) => found
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect(),
        Err(_) => Vec::new(),
    };
    adapters.sort();
    let joined = Installed::load(home)?.filter(|installed| installed.agent.is_some());
    let mut text = match &joined {
        Some(_) => format!(
            "Connect your agent. Its Signet listens on {}, which only you can reach, and its token is \
             in {}, which only you can read. Nothing needs it shown, so keep it out of what your agent \
             prints. Both are written in {}, where the adapters look for them.\n",
            home.signet_socket().display(),
            curl_file.display(),
            env_file.display(),
        ),
        None => {
            "Connect your agent. It hasn't joined yet, and once connected it can join from there, \
                 or with splint join HANDLE HOST.\n"
                .to_owned()
        }
    };
    // What an adapter's settings name this agent by: only the profile, if it's one.
    let agent_settings = match home.profile() {
        Some(profile) => {
            let _ = writeln!(
                text,
                "\nThis is the profile {profile}. A program that runs splint itself needs \
                 {PROFILE_SETTING}={profile} in its environment, so it acts as this agent."
            );
            json!({ PROFILE_SETTING: profile })
        }
        None => json!({}),
    }
    .to_string();
    for adapter in adapters {
        if let Ok(note) = fs::read_to_string(adapter.join(CONNECT_NOTE)) {
            // One that names the token file has nothing to name until the agent has joined. On
            // Windows it never does, as curl can't reach Signet's pipe.
            if (joined.is_none() || cfg!(windows)) && note.contains("{curl}") {
                continue;
            }
            // A Windows path goes into JSON, where `\` starts an escape, and Node takes `/` there too.
            let adapter = adapter.to_string_lossy();
            let adapter = if cfg!(windows) {
                adapter.replace('\\', "/")
            } else {
                adapter.into_owned()
            };
            let note = note
                .replace("{adapter}", &adapter)
                .replace("{env}", &env_file.to_string_lossy())
                .replace("{curl}", &curl_file.to_string_lossy())
                .replace("{agent_settings}", &agent_settings)
                .replace("{wake}", &crate::check::each_wake(&home.command()))
                .replace("{splint}", &home.command());
            text.push('\n');
            text.push_str(note.trim_end());
            text.push('\n');
        }
    }
    Ok(text.trim_end().to_owned())
}

/// What's said whenever an owner's own key sits beside the agent's Signet, as a setting that weakens a
/// check has to be.
pub fn owner_key_here_warning(home: &Home) -> String {
    format!(
        "Warning: your owner key is in {}, where anything running as this computer user can read it. An \
         agent that runs as this user, or can read that folder, can sign anything as you. splint join \
         and splint authorize keep it on your own device instead.",
        home.owner_dir().display()
    )
}

/// Says so on stderr, if an owner's own key is here, so it's seen whatever the output goes to. That
/// holds for an agent whose owner confirmed it from elsewhere too: a key beside it then is one nobody
/// meant to be there, which anything running as this user could have made.
pub fn warn_if_owner_key_here(home: &Home) -> Result<(), Failure> {
    if OwnerKey::new(home).is_real_owner() {
        writeln!(io::stderr(), "{}", owner_key_here_warning(home))?;
    }
    Ok(())
}

/// The agent's own handle, as `splint join` takes no owner part: that comes once the owner confirms.
fn keep_the_owner_key_apart(address: &str, name: &str, domain: &str) -> Failure {
    let (handle, _) = name_parts(name);
    Failure::refused(format!(
        "\
setup would make your owner key here, where anything running as this computer user can read it, so an
agent with a shell as this user could sign anything as you. To keep it apart, have your agent run
splint join {handle} {domain} as its own user, and run the splint authorize line it sends you on your own
device, or as another user on this one. If no agent will run as this user or read ~/.splint, you can
run splint setup {address} {OWNER_KEY_HERE} yourself. An agent never should: it runs splint join."
    ))
}

pub async fn setup(
    home: &Home,
    address: &str,
    with_code: bool,
    owner_key_here: bool,
) -> Result<String, Failure> {
    let (name, domain) = parse_address(address).map_err(Failure::not_an_address)?;
    if Installed::load(home)?.is_some_and(|found| found.owner_elsewhere.is_some()) {
        return Err(Failure::refused(
            "your owner authorized this agent from their own device, so there's nothing to set up here",
        ));
    }
    // Before anything's made, so a refusal leaves no key behind.
    if !owner_key_here {
        return Err(keep_the_owner_key_apart(address, name, domain));
    }
    home.prepare()?;
    // Setting up is asking for it to run.
    services::clear_stopped(home)?;
    let owner_key = OwnerKey::new(home);
    // A profile shares its owner's key, and a stand-in for an agent that joined on its own isn't one.
    if home.profile().is_some() && owner_key.is_stand_in() {
        return Err(Failure::refused(
            "the owner key this would use is a stand-in for an agent that joined on its own, so it \
             can't set up another agent. That agent's person sets up their controls from the link \
             it sends them, or with splint authorize",
        ));
    }
    owner_key.identity()?;
    warn_if_owner_key_here(home)?;
    let installed = match Installed::load(home)? {
        Some(installed) if installed.agent.is_some() && installed.address != address => {
            return Err(Failure::AlreadyJoined(installed.address));
        }
        // No host has taken this one, so a mistyped host or a taken name can still be put right.
        Some(installed) => Installed {
            address: address.to_owned(),
            ..installed
        },
        None => Installed::create(address, owner_key.new_agent_backup()?)?,
    };
    installed.save(home)?;

    // Whatever's still running may hold another address or a code that didn't work. Signet says
    // itself whether it's registered, so a setup that died just after spending a code asks for none.
    services::stop(home, SIGNET, SIGNET).await?;
    start_signet(home, &installed, None).await?;
    if !SignetApi::new(home, &installed)?.who().await?.registered {
        if with_code || !HostCalls::new(installed.host_domain()?)?.is_open().await {
            let code = read_signup_code()?;
            services::stop(home, SIGNET, SIGNET).await?;
            start_signet(home, &installed, Some(&code)).await?;
        }
        if let Err(failure) = register(home, &installed, &owner_key).await {
            services::stop(home, SIGNET, SIGNET).await?;
            return Err(failure);
        }
    }
    let api = SignetApi::new(home, &installed)?;
    let agent = api.who().await?.agent_id;
    let installed = Installed {
        agent: Some(agent.clone()),
        ..installed
    };
    installed.save(home)?;

    // A repeat of setup finishes what failed, and always ends with rules Signet holds, the newest
    // signed anywhere.
    let draft = match owner_side::rules_beside(home, &installed, &agent).await? {
        Some(signed) => signed.draft,
        None => first_rules(),
    };
    let agreed = rules::agreed_in_words(&draft);
    rules::sign_and_apply(home, &installed, &agent, draft).await?;
    // So its Signet says yes to what has no value with this device shut.
    let api = SignetApi::new(home, &installed)?;
    let delegating = owner_key.delegate(&agent, &api.who().await?.delegate)?;
    if let Some(delegation) = &delegating.delegation {
        api.put_delegation(delegation).await?;
    }
    let at_host = api.put_rules(&delegating.rules).await?;
    let Started::Running = auto::start(home)? else {
        return Err(Failure::Stopped);
    };

    let said = format!(
        "\
You're set up as {address}.

Your line, for anyone your agent should reach. They run it, and you run theirs. Until you've both run
each other's line, they're not your contact:

  {line}

{agreed}

Your agent's Signet listens on {socket}.{not_at_login} Its token is only in {curl}, and nothing prints it. Your owner
key is in {owner}, which anything running as this user can read, so run your agent as another user or
where it can't read that folder. Move the backup keys there off this machine.

splint connect prints how to connect an agent. splint page and splint waiting show what's waiting for
you. What your rules allow gets signed by itself on this device, unless you choose ask me, and your
rules last until you sign others. Its Signet says yes to meetings and RSVPs for you too, which have
no amount in them.",
        line = line_for(address, &agent),
        socket = home.signet_socket().display(),
        not_at_login = services::not_at_login(),
        curl = home.agent_curl().display(),
        owner = home.owner_dir().display(),
    );
    Ok(rules::told(said, at_host))
}

pub async fn register(
    home: &Home,
    installed: &Installed,
    owner_key: &OwnerKey,
) -> Result<(), Failure> {
    let api = SignetApi::new(home, installed)?;
    let who = api.who().await?;
    let binding = owner_key.bind(&who.identity, &installed.address, &installed.backup)?;
    api.put_binding(&binding)
        .await
        .map_err(|failure| match failure {
            Failure::Refused(why) => Failure::refused(format!(
                "the host didn't take this address, so check the signup code, the host and that \
                 nobody has that name, then run this again: {why}"
            )),
            typed => typed,
        })
}

pub async fn start(home: &Home) -> Result<String, Failure> {
    // Before anything's checked, so a stop made before joining, or while waiting on the owner, never
    // leaves join, finish and start each saying to run another.
    services::clear_stopped(home)?;
    start_unless_stopped(home).await
}

/// What `start` starts, leaving a person's stop where it is: what's kept across restarts finds their
/// mark and stays stopped, so a `splint stop` that lands while this runs, for something that only
/// checked for the mark beforehand, holds.
async fn start_unless_stopped(home: &Home) -> Result<String, Failure> {
    // An upgrade leaves the build it replaced running until this, still signing, and a start that took
    // it for this one would leave it so, or run a second beside it.
    services::stop_older(home, SIGNET, SIGNET).await?;
    auto::stop_older(home).await?;
    kept::stop_older(home).await?;
    // An owner's device with only agents elsewhere has nothing to start but what signs for them.
    if home.profile().is_none()
        && Installed::load(home)?.is_none()
        && !authorize::all(home)?.is_empty()
    {
        let Started::Running = auto::start(home)? else {
            return Err(Failure::Stopped);
        };
        return Ok("Signing what your rules allow for the agents you authorized here.".to_owned());
    }
    let (installed, _) = Installed::require(home)?;
    warn_if_owner_key_here(home)?;
    // Signet signs on by itself once its host can be reached, and what signs by the owner's rules has
    // to be running then too.
    let unreachable = match start_signet(home, &installed, None).await {
        Ok(()) => None,
        Err(failure) if up_without_its_host(&failure) => Some(failure),
        Err(failure) => return Err(failure),
    };
    if installed.owner_elsewhere.is_none() {
        let Started::Running = auto::start(home)? else {
            return Err(Failure::Stopped);
        };
    }
    // A listener its runtime keeps waits Signet out by itself, so it starts whether or not Signet
    // answers yet.
    if let Some(Started::LeftStopped) = kept::start(home)? {
        return Err(Failure::Stopped);
    }
    if let Some(failure) = unreachable {
        return Err(failure);
    }
    Ok(format!("Running {}.", installed.address))
}

/// What an upgrade runs for each folder: starts again only what's running now, which runs the build
/// just installed in place of the old. What its person stopped, what crashed and what never started
/// are left as they are, as only a person starts those, and nothing is said of them, as an upgrade
/// runs this for every folder. Running is by the lock a running copy holds, which a crash lets go.
pub async fn start_if_running(home: &Home) -> Result<String, Failure> {
    if services::stopped_by_person(home) {
        return Ok(String::new());
    }
    if services::is_running(home, SIGNET)? {
        return start_unless_stopped(home).await;
    }
    // A kept listener waits out a Signet that crashed, so it runs on too, and is started again on
    // this build alone.
    let listener = if kept::is_running(home)? {
        kept::stop_older(home).await?;
        if let Some(Started::LeftStopped) = kept::start(home)? {
            return Err(Failure::Stopped);
        }
        "Running the kept listener on this build."
    } else {
        ""
    };
    // What signs by the owner's rules runs on where Signet crashed, and on an owner's device with
    // only agents elsewhere, so it alone is started again.
    if auto::is_running(home)? {
        auto::stop_older(home).await?;
        let Started::Running = auto::start(home)? else {
            return Err(Failure::Stopped);
        };
        return Ok(format!("Running splint auto on this build. {listener}")
            .trim_end()
            .to_owned());
    }
    Ok(listener.to_owned())
}

/// The commands that need Signet or what signs by the owner's rules running, and so start again,
/// first, what a sign-out or a restart stopped on Windows. Any other command, such as `status`, which
/// says what's down, `stop`, `retire` or one added later, starts nothing it wasn't asked to.
#[cfg(windows)]
const BRINGS_BACK: [&str; 34] = [
    "inbox",
    "ack",
    "contacts",
    "send",
    "delivery",
    "wait",
    "types",
    "where-paid",
    "requests",
    "open",
    "move",
    "propose",
    "invite",
    "invites",
    "accept",
    "decline",
    "card",
    "check",
    "listen",
    "add",
    "remove",
    "page",
    "controls",
    "ask",
    "ask-owner",
    "renew",
    "settings",
    "direct",
    "waiting",
    "approve",
    "deny",
    "accept-change",
    "say",
    "get-paid",
];

#[cfg(windows)]
fn brings_back(words: &[&str]) -> bool {
    let words = match words {
        ["for", _, rest @ ..] => rest,
        _ => words,
    };
    match words {
        // Stops the kept listener, so starting it first would only be undone.
        ["listen", flags @ ..] => !flags
            .iter()
            .take_while(|flag| **flag != "--")
            .any(|flag| *flag == "--unkeep"),
        // With a port of the person's own, the page and relay sign nothing and need nothing here.
        ["controls", _, flags @ ..] if flags.contains(&"--port") => false,
        ["computer", "approve", ..] => true,
        [command, ..] => BRINGS_BACK.contains(command),
        [] => false,
    }
}

/// On Windows nothing starts Signet at login yet, as an unsigned program that starts itself at login is
/// what Windows' malware checks quarantine. So before a command that needs them, this starts again
/// what a sign-out or a restart stopped, as `splint start` would: Signet, what signs by the owner's
/// rules and a kept listener, and Splint on this computer. Whatever its person stopped stays stopped,
/// even when their stop lands while this runs, as nothing here clears their mark. Whatever the command,
/// it also deletes the tasks an earlier build made to start them at login. Whatever fails here, the
/// command itself says what it finds.
#[cfg(windows)]
pub async fn come_back(home: &Home, words: &[&str]) {
    if services::run_by_a_keeper() || matches!(words, ["computer", "run"]) {
        return;
    }
    let default = home.the_default();
    services::forget_old_tasks(home, &[SIGNET, auto::AUTO, kept::SERVICE]);
    services::forget_old_tasks(&default, &[crate::computer::SERVICE]);
    if !brings_back(words) {
        return;
    }
    if !services::stopped_by_person(home)
        && (services::left_down(home, SIGNET) || services::left_down(home, auto::AUTO))
    {
        let _ = start_unless_stopped(home).await;
    }
    if !services::stopped_by_person(&default)
        && services::left_down(&default, crate::computer::SERVICE)
    {
        let _ = crate::computer::start(&default);
    }
}

/// Whether anything here would start: an agent that joined or is joining, or agents authorized here.
fn anything_set_up(home: &Home) -> Result<bool, Failure> {
    Ok(Installed::load(home)?.is_some()
        || home.join_file().exists()
        || (home.profile().is_none() && !authorize::all(home)?.is_empty())
        || services::is_running(home, SIGNET)?
        || auto::is_running(home)?
        || kept::is_running(home)?)
}

/// Left stopped until `splint start` or `splint setup`, whatever else here would start it. With nothing
/// set up there's nothing to leave stopped, so no mark is left for a join to trip on.
pub async fn stop(home: &Home) -> Result<String, Failure> {
    if !anything_set_up(home)? {
        // Someone with no agent here can still have Splint on this computer running, kept across
        // restarts, and this is the only way to stop it. No mark, so nothing here keeps a join out.
        if home.profile().is_none() && services::is_running(home, crate::computer::SERVICE)? {
            services::stop(home, crate::computer::SERVICE, "splint").await?;
            return Ok("Stopped Splint on this computer.".to_owned());
        }
        return Ok("Nothing is set up here, so there's nothing to stop.".to_owned());
    }
    // Marked first, so nothing starting meanwhile outlasts it, but what runs is stopped even when the
    // mark can't be written, as on a full disk.
    let marked = services::mark_stopped(home);
    services::stop(home, SIGNET, SIGNET).await?;
    auto::stop(home).await?;
    // Its command stays registered, so splint start brings it back with Signet.
    kept::stop(home).await?;
    // Splint on this computer is the person's, kept with their default folder, so it stops with that.
    if home.profile().is_none() {
        services::stop(home, crate::computer::SERVICE, "splint").await?;
    }
    marked?;
    Ok(format!(
        "Stopped. Messages wait at the host until {} start.",
        home.command()
    ))
}

/// What `splint network-access` takes after its name.
pub const EVERY_NETWORK: &str = "--every-network";

/// Turns owner network access on at an address on this machine, or off, and starts Signet again with
/// it. Anyone who can reach that address gets only refusals and views sealed to the owner, so an agent
/// that turned it on by itself gains nothing by it, and it's said whenever it's on.
pub async fn network_access(home: &Home, words: &[&str]) -> Result<String, Failure> {
    let (installed, _) = Installed::require(home)?;
    let network = match words {
        ["off"] => None,
        ["on", at, flags @ ..] => {
            let every_network = match flags {
                [] => false,
                [EVERY_NETWORK] => true,
                _ => return Err(Failure::Usage),
            };
            let named: std::net::SocketAddr = at
                .parse()
                .ok()
                .filter(|named: &std::net::SocketAddr| named.port() != 0)
                .ok_or_else(|| {
                    Failure::refused(
                        "that isn't this machine's IP address and a port, such as \
                         192.168.1.20:7491, so nothing changed",
                    )
                })?;
            if crate::direct::every_address(named.ip()) && !every_network {
                return Err(Failure::refused(format!(
                    "{at} is every network this machine is ever on, such as a café's Wi-Fi, not only \
                     the one you mean, so nothing changed: name this machine's address on your LAN \
                     or VPN, or add {EVERY_NETWORK} if every network is what you mean"
                )));
            }
            Some(crate::home::OwnerNetwork {
                at: named.to_string(),
                every_network,
            })
        }
        _ => return Err(Failure::Usage),
    };
    let installed = Installed {
        owner_network: network.clone(),
        ..installed
    };
    installed.save(home)?;
    let said = match &network {
        Some(network) => format!(
            "Owner network access is on at {at}. Your person's device on another machine reaches this \
             agent's Signet there once they run splint for {address} direct {reach}, and by way of \
             its host otherwise. Anyone who can reach {at} gets only refusals and views sealed to your \
             person, and can see when their device calls. {splint} network-access off turns it off.",
            at = network.at,
            // splint for ... direct refuses every address, so it names this machine's own instead.
            reach = match network.at.parse::<std::net::SocketAddr>() {
                Ok(named) if crate::direct::every_address(named.ip()) => format!(
                    "IP:{}, with IP this machine's address on their LAN or VPN",
                    named.port()
                ),
                _ => network.at.clone(),
            },
            address = installed.address,
            splint = home.command(),
        ),
        None => "Owner network access is off: only this computer and its host reach this agent's \
                 Signet."
            .to_owned(),
    };
    if services::stopped_by_person(home) {
        return Ok(format!(
            "{said} Signet is stopped, so it counts from {} start.",
            home.command()
        ));
    }
    services::stop(home, SIGNET, SIGNET).await?;
    start_signet(home, &installed, None).await?;
    Ok(said)
}

pub async fn renew(home: &Home) -> Result<String, Failure> {
    if let Some(elsewhere) = authorize::the_agent_elsewhere(home)? {
        return authorize::renew(home, &elsewhere).await;
    }
    let (installed, agent) = Installed::require_owner_here(home, "sign this agent's rules again")?;
    let signed = owner_side::rules_beside(home, &installed, &agent)
        .await?
        .ok_or_else(|| Failure::refused("there are no rules to sign again yet"))?;
    let draft = rules::without_ended_invitations(signed.draft, unix_now());
    let at_host = rules::sign_and_apply(home, &installed, &agent, draft).await?;
    Ok(rules::told(
        "Signed your rules again. They last until you sign others.",
        at_host,
    ))
}

fn remove_file_if_there(path: &Path) -> Result<(), Failure> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

fn remove_dir_if_there(path: &Path) -> Result<(), Failure> {
    match fs::remove_dir_all(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// Stops this agent and deletes what makes this folder that agent, so an agent can join from it
/// again: its setup, Signet's folder with its keys, its rules, what it was waiting on, the files its
/// adapters read, and its own stand-in. The owner's key, which every profile here shares, stays, and so
/// does what signs for agents authorized from this device.
pub async fn reset(home: &Home) -> Result<(), Failure> {
    // The default's stand-in is in the owner's own folder, which only a stand-in may take with it.
    let stand_in_here = home.profile().is_some() || OwnerKey::new(home).is_stand_in();
    services::stop(home, SIGNET, SIGNET).await?;
    if home.profile().is_some() || authorize::all(home)?.is_empty() {
        auto::stop(home).await?;
    }
    // The command was kept for the agent that's going, so it isn't left to run for the next one.
    kept::forget(home).await?;
    for file in [
        home.saved_path(),
        home.join_file(),
        home.pairing_file(),
        home.rules_file(),
        home.agent_env(),
        home.agent_curl(),
    ] {
        remove_file_if_there(&file)?;
    }
    remove_dir_if_there(&home.signet_dir())?;
    remove_dir_if_there(&home.owner_first_signet_dir())?;
    remove_dir_if_there(&home.marks_dir())?;
    if stand_in_here {
        remove_dir_if_there(&home.stand_in_dir())?;
    }
    services::clear_stopped(home)
}

/// Whether `address`'s host has never taken this folder's agent, as it says itself: nobody has the
/// handle, or whoever has it has other keys. What can't be told is said, for a person to decide on.
pub(crate) async fn never_taken(home: &Home, address: &str) -> Result<bool, String> {
    let (handle, domain) =
        parse_address(address).map_err(|_| format!("{address} isn't an address"))?;
    let unanswered = || format!("{domain} couldn't be asked whether it has {address}");
    let host = HostCalls::new(domain).map_err(|_| unanswered())?;
    if !host.handle_taken(handle).await.map_err(|_| unanswered())? {
        return Ok(true);
    }
    let unclear = || format!("{domain} has someone at {address}, and it couldn't be told who");
    let here = AgentKeys::from_encoded(&prepared_key(home).map_err(|_| unclear())?)
        .map_err(|_| unclear())?;
    let there = host.resolve(address).await.map_err(|_| unclear())?;
    let there = Identity::from_encoded(&there.identity).map_err(|_| unclear())?;
    Ok(!there.keys().iter().any(|key| key.point() == &here.key))
}

/// A person at a terminal can say to delete this folder's keys though its host couldn't be asked. An
/// agent's run has no terminal, so for one it's always no.
fn person_says_go_on(address: &str, why: &str) -> Result<bool, Failure> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Ok(false);
    }
    write!(
        io::stderr(),
        "{why}. If it has this agent, deleting its keys leaves it there with nobody to act for it. To \
         delete them anyway, type {address} again: "
    )?;
    io::stderr().flush()?;
    let mut typed = String::new();
    stdin.lock().read_line(&mut typed)?;
    Ok(typed.trim() == address)
}

/// Retires this agent at its host, for good, and resets its folder. The address is typed out, so a
/// slip retires nothing. It's signed by the key that signs for the agent here, so where that key is
/// its person's, on another device, only they can: an agent can't shed what its owner set up.
pub async fn retire(home: &Home, typed: &str) -> Result<String, Failure> {
    let installed = Installed::load(home)?;
    let address = match &installed {
        Some(installed) => installed.address.clone(),
        None if home.join_file().exists() => waiting_address(home)?,
        None => {
            return Err(Failure::refused(
                "nothing is set up here, so there's nothing to retire",
            ));
        }
    };
    if typed != address {
        return Err(Failure::refused(format!(
            "to retire this agent, which can't be undone, type its own address: {} retire {address}",
            home.command()
        )));
    }
    // Its person's retirement, which Signet found they signed at its host, is all it takes: there's
    // nothing left to sign, and only the folder to free.
    if let Some(found) = installed.as_ref().filter(|found| found.agent.is_some())
        && services::is_running(home, SIGNET)?
        && SignetApi::new(home, found)?.retired().await
    {
        reset(home).await?;
        return Ok(format!(
            "Your person retired {address} at its host, for good. This folder is reset, so an agent \
             can join from it again, with another handle."
        ));
    }
    if installed
        .as_ref()
        .is_some_and(|found| found.owner_elsewhere.is_some())
    {
        let splint = home.command();
        return Err(Failure::refused(format!(
            "only this agent's person can retire it, as their key is on their own device, not here. \
             On their computer they run: splint for {address} retire. Once they have, Signet hears \
             it from its host while it runs, and this frees the folder. If its host is gone for \
             good, {splint} reset {address} frees this folder without it"
        )));
    }
    let agent = installed.as_ref().and_then(|found| found.agent.clone());
    let Some((installed, agent)) = installed.zip(agent) else {
        // A setup or join that stopped between the host taking the agent and this folder noting it
        // leaves no ID here, and deleting its keys then would leave the host holding an agent nobody
        // can act for. So the host is asked first, and only a person can say to go on without it.
        match never_taken(home, &address).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(Failure::refused(format!(
                    "{address}'s host has this agent, though joining didn't finish here, so nothing \
                     was deleted. Run join or setup again to finish, then retire it"
                )));
            }
            Err(why) if person_says_go_on(&address, &why)? => {}
            Err(why) => {
                return Err(Failure::refused(format!(
                    "{why}, so nothing was deleted. Try again once it answers, or run this at a \
                     terminal to delete this folder's keys anyway"
                )));
            }
        }
        reset(home).await?;
        return Ok(format!(
            "No host had taken {address} yet, so there was nothing to retire there. This folder is \
             reset, so an agent can join from it again."
        ));
    };
    let retirement = OwnerKey::new(home).retire(&agent)?;
    // A host that let an unused agent go has nothing left to retire, which is as good.
    HostCalls::new(installed.host_domain()?)?
        .post_retirement(&retirement)
        .await?;
    reset(home).await?;
    Ok(format!(
        "\
Retired {address} at its host, for good: it can't send or be found, and it no longer counts against
its owner's limit there. Its handle stays its own, so nobody else gets that address. This folder is
reset, so an agent can join from it again, with another handle."
    ))
}

/// Frees this folder for an agent whose host is gone for good, with no host to ask: its keys and
/// setup are deleted here and nothing is signed or sent, so its ID isn't retired anywhere. Only a
/// person at a terminal, typing its address again, does this. A host that still has the agent is
/// told apart first, as its person should retire it there instead.
pub async fn reset_without_host(home: &Home, typed: &str) -> Result<String, Failure> {
    let (installed, agent) = Installed::require(home)?;
    let address = installed.address.clone();
    let splint = home.command();
    if typed != address {
        return Err(Failure::refused(format!(
            "to free this folder without its host, type its own address: {splint} reset {address}"
        )));
    }
    if still_has(&installed, &agent).await {
        return Err(Failure::refused(format!(
            "{address}'s host still has this agent, so nothing was deleted: retire it, with \
             {splint} retire {address}, or where its person's key is on their own computer, they \
             run splint for {address} retire there"
        )));
    }
    let why = format!(
        "This deletes {address}'s keys here, and nothing tells any host or contact: its ID isn't \
         retired anywhere, and its handle stays its own wherever its host comes back"
    );
    if !person_says_go_on(&address, &why)? {
        return Err(Failure::refused(
            "only a person at a terminal, typing the address again, frees a folder without its \
             host, so nothing was deleted",
        ));
    }
    reset(home).await?;
    Ok(format!(
        "Deleted {address}'s keys here, and nothing else: its ID isn't retired anywhere. This folder \
         is reset, so an agent can join from it again."
    ))
}

/// Whether this agent's host answers that it has this agent now. Anything else, an answer for
/// someone else or none at all, is no.
async fn still_has(installed: &Installed, agent: &splint_core::SplintId) -> bool {
    let Ok(domain) = installed.host_domain() else {
        return false;
    };
    let Ok(host) = HostCalls::new(domain) else {
        return false;
    };
    host.resolve(&installed.address)
        .await
        .is_ok_and(|found| &found.agent_id == agent)
}

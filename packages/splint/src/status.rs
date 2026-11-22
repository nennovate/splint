//! `splint status`: what someone needs to see, without opening anyone's files. With `--json`, the same
//! for a program, such as an agent's adapter, that has to act on it.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde::Serialize;
use splint_core::registration_state::RegistrationState;
use splint_core::{Identity, unix_now};

use crate::auto::{self, AUTO};
use crate::check::host_closing;
use crate::contacts::line_for;
use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::host_calls::HostCalls;
use crate::join::{
    controls_install_line, controls_install_line_on_windows, controls_open_line,
    controls_open_line_on_windows, keep_watch, waiting_address,
};
use crate::listen::kept::{self, Kept};
use crate::owner_key::OwnerKey;
use crate::page::controls::DEFAULT_PORT;
use crate::rules;
use crate::services::{
    Keeper, KeptBy, is_running, kept_by, last_refusal, runs_older, stopped_by_person,
    stops_at_logout, why_no_crontab_line,
};
use crate::setup::SIGNET;
use crate::signet_api::{self, SignetApi};

const DAY_SECS: u64 = 24 * 60 * 60;
const HOUR_SECS: u64 = 60 * 60;

/// How long ago a time Signet gave was, in the largest whole unit, for a person.
fn ago(at: u64, now: u64) -> String {
    let secs = now.saturating_sub(at);
    let (count, unit) = match secs {
        0..60 => (secs, "second"),
        60..HOUR_SECS => (secs / 60, "minute"),
        HOUR_SECS..DAY_SECS => (secs / HOUR_SECS, "hour"),
        _ => (secs / DAY_SECS, "day"),
    };
    format!("{count} {unit}{} ago", if count == 1 { "" } else { "s" })
}

/// Where this agent stands at its host, as its Signet says, in words for a person or an agent.
fn at_its_host(home: &Home, installed: &Installed, who: &signet_api::Who) -> Option<String> {
    let domain = installed.host_domain().ok()?;
    let splint = home.command();
    let problem = who
        .registration_problem
        .as_deref()
        .unwrap_or("it gave no reason");
    let way_out = format!(
        "{splint} switch-host HANDLE~HOST --leave-mail moves this agent to another, without what \
         waits there"
    );
    match who.registration {
        _ if who.registered && who.host_answering => None,
        _ if who.registered => Some(format!(
            "registered at {domain}, which isn't answering now, so nothing can be read or sent until \
             it does. Signet keeps looking by itself. If that host is gone for good, {way_out}"
        )),
        Some(RegistrationState::Starting) => Some(format!("signing on at {domain} now")),
        _ if who.keeps_trying() => Some(format!(
            "not registered at {domain}: {problem}. Nothing can be read or sent until it takes this \
             agent back, and Signet keeps trying by itself. If that host is gone for good, {way_out}"
        )),
        Some(RegistrationState::NameTaken | RegistrationState::SignupCodeRefused) => Some(format!(
            "not registered at {domain}: {problem}. Signet won't try it again by itself. {way_out}"
        )),
        Some(RegistrationState::NeedsOwner) => Some(format!(
            "not registered at {domain}: {problem}. If this agent should go elsewhere, {way_out}"
        )),
        _ => Some(format!(
            "not registered at {domain}: this agent's owner has to sign for it there again"
        )),
    }
}

/// The kept listener, if this agent has one, with its exact command, so its person always sees what
/// runs here when something arrives.
fn listener_line(home: &Home, kept: &Kept, stopped_by_them: bool) -> Result<String, Failure> {
    let splint = home.command();
    let pace = match kept.gap_secs {
        0 => String::new(),
        gap => format!(", at most once every {gap} seconds"),
    };
    let state = if kept::is_running(home)? {
        format!("It's running{}", comes_back(home, kept::SERVICE)?)
    } else if stopped_by_them {
        "It's stopped with Signet, by your person".to_owned()
    } else {
        format!("It's stopped: run {splint} start")
    };
    Ok(format!(
        "Listener  kept: runs {} for each change, from {}{pace}. {state}. {splint} listen --unkeep \
         removes it",
        kept.shown(),
        kept.folder.display(),
    ))
}

/// Whether anything listens, in words, from what Signet saw. `kept` is whether a listener is kept,
/// and whether it runs.
fn listening_line(listening: &signet_api::Listening, kept: Option<bool>, now: u64) -> String {
    let held = match (listening.wait_held, kept) {
        (true, _) => "a wait is held on Signet now",
        (false, Some(true)) => "no wait is held on Signet now, and the kept listener runs",
        (false, Some(false)) => {
            "nothing holds a wait on Signet now, and the kept listener isn't running"
        }
        (false, None) => "nothing holds a wait on Signet now, and no listener is kept",
    };
    let since =
        |at: Option<u64>| at.map_or("not since Signet started".to_owned(), |at| ago(at, now));
    format!(
        "Listening {held}. Last wait: {}. What waits was last read: {}",
        since(listening.last_wait_at),
        since(listening.last_read_at),
    )
}

/// Rules last until the owner signs others, unless they chose an end.
fn rules_line(ends_at: Option<Option<u64>>, now: u64) -> String {
    match ends_at {
        None => "Rules     none signed yet".to_owned(),
        Some(None) => "Rules     in force until you sign others".to_owned(),
        Some(Some(end)) if now >= end => {
            "Rules     past the end you gave them, so your agent is stopped".to_owned()
        }
        Some(Some(end)) => match end.saturating_sub(now) / DAY_SECS {
            0 => "Rules     in force for less than a day more, the end you gave them".to_owned(),
            1 => "Rules     in force for 1 more day, the end you gave them".to_owned(),
            days => format!("Rules     in force for {days} more days, the end you gave them"),
        },
    }
}

/// Whether what's running comes back by itself, and what to do if it doesn't.
pub fn comes_back(home: &Home, name: &str) -> Result<String, Failure> {
    let splint = home.command();
    Ok(match (kept_by(home, name)?, Keeper::here()) {
        (KeptBy::Manager, _) => ", and comes back by itself after a crash or a restart".to_owned(),
        (KeptBy::NextCommand, _) => ", and starts again by itself after a crash. It doesn't start at \
                                     login on Windows yet, so after a sign-out or a restart the next \
                                     splint command that needs it, such as check, starts it again"
            .to_owned(),
        (KeptBy::Crontab, _) => ". A line in your crontab starts it again within a minute of a \
                                 restart or a crash, as nothing else here would, wherever cron runs"
            .to_owned(),
        (KeptBy::Nothing, Keeper::Nothing) if stops_at_logout() => format!(
            ". Nothing brings it back after a crash or a restart, as {}. To have it come back, let \
             this user's services outlast logging out with loginctl enable-linger, which may need \
             an admin, then run {splint} stop and {splint} start",
            why_no_crontab_line()
        ),
        (KeptBy::Nothing, Keeper::Nothing) => format!(
            ". Nothing on this system brings it back after a crash or a restart, as {}, so run \
             {splint} start then",
            why_no_crontab_line()
        ),
        (KeptBy::Nothing, _) => format!(
            ". It won't come back by itself after a crash or a restart until you run {splint} stop, \
             then {splint} start"
        ),
    })
}

/// What brings Signet back, as a word a program acts on.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComesBackBy {
    /// launchd or `systemd --user`: after a crash, a restart or a login.
    Service,
    /// A line in the user's crontab, within a minute of a restart or a crash.
    Crontab,
    /// On Windows, its keeper after a crash, and the next `splint` command after a sign-out or a
    /// restart, as nothing starts it at login there yet.
    NextCommand,
    /// Nothing, so after a crash or a restart it stays down until `splint start`.
    Nothing,
    /// Its person ran `splint stop`, and only they start it again. A runtime that keeps an agent's
    /// Signet up leaves this one stopped.
    StoppedByPerson,
}

fn comes_back_by(home: &Home, running: bool) -> Result<ComesBackBy, Failure> {
    if !running && stopped_by_person(home) {
        return Ok(ComesBackBy::StoppedByPerson);
    }
    Ok(match kept_by(home, SIGNET)? {
        KeptBy::Manager => ComesBackBy::Service,
        KeptBy::Crontab => ComesBackBy::Crontab,
        KeptBy::NextCommand => ComesBackBy::NextCommand,
        KeptBy::Nothing => ComesBackBy::Nothing,
    })
}

/// The owner ID that approved this agent's controls, as its Signet holds it, or where that isn't
/// running, as this folder noted. Whoever approves first by a link becomes the owner, so the agent has
/// to be able to see who that was.
async fn owner_who_approved(home: &Home, installed: &Installed) -> Option<String> {
    if is_running(home, SIGNET).ok()?
        && let Ok(api) = SignetApi::new(home, installed)
        && let Ok(who) = api.who().await
        && let Some(owner) = who.owner_id
    {
        return Some(owner.to_string());
    }
    let identity = match &installed.owner_elsewhere {
        Some(identity) => identity.clone(),
        None => OwnerKey::new(home).identity().ok()?,
    };
    Some(Identity::from_encoded(&identity).ok()?.id().to_string())
}

/// Said of the owner ID that approved, wherever an agent reads where it stands.
fn approved_by(owner: &str) -> String {
    format!(
        "Owner ID {owner} approved these controls. Your person's own is shown under Account in their \
         controls: if it isn't this one, someone else approved, so tell them at once."
    )
}

pub async fn status(home: &Home) -> Result<String, Failure> {
    let (installed, agent) = Installed::require(home)?;
    let splint = home.command();
    let mut out = String::new();
    let mut line = |text: String| {
        let _ = writeln!(out, "{text}");
    };
    let owner_here = installed.owner_elsewhere.is_none() && OwnerKey::new(home).is_real_owner();
    let stand_in = installed.owner_elsewhere.is_none() && OwnerKey::new(home).is_stand_in();
    line(format!("Address   {}", installed.address));
    // What a person runs on their own device to add this one. An agent invites by address instead.
    if owner_here {
        line(format!(
            "Your line {}",
            line_for(&installed.address, &agent)
        ));
    }
    let running = is_running(home, SIGNET)?;
    // An agent reads this too, so after its person's stop it's told to leave it, never to start it.
    let stopped_by_them = !running && stopped_by_person(home);
    // Holding its lock isn't answering: one that doesn't can't be asked anything below.
    let answering = running && SignetApi::new(home, &installed)?.is_up().await;
    line(if running && runs_older(home, SIGNET, SIGNET)? {
        format!(
            "Signet    running an older build than this one: {splint} start runs this one in its place"
        )
    } else if running && !answering {
        format!(
            "Signet    running, but not answering on {}: {splint} stop, then {splint} start, starts it \
             again",
            home.signet_socket().display()
        )
    } else if running {
        format!(
            "Signet    running, on {}{}",
            home.signet_socket().display(),
            comes_back(home, SIGNET)?
        )
    } else if stopped_by_them {
        format!("Signet    stopped: {}", Failure::Stopped)
    } else if let Some(said) = last_refusal(home, SIGNET) {
        format!("Signet    stopped: {said}")
    } else if let Some(clock) = host_clock(&installed).await {
        format!("Signet    stopped, as {clock}. Then run {splint} start")
    } else {
        format!(
            "Signet    stopped, though nobody ran splint stop, as after a crash or a restart: run \
             {splint} start"
        )
    });
    line(match &installed.owner_network {
        Some(network) => format!(
            "Network   owner network access is on at {}: anyone who can reach it gets only refusals \
             and views sealed to your owner, and sees when their device calls. {splint} \
             network-access off turns it off",
            network.at
        ),
        None => "Network   off: only this computer and its host reach Signet".to_owned(),
    });
    let signed = rules::last_signed(home)?;
    if auto::is_running(home)? {
        // What it signs depends on who it signs for: a stand-in has no rules of its person's.
        let does = if stand_in {
            "signing in contacts agreed by invite, until your person sets up their controls"
        } else if signed.is_some() {
            "signing what your rules allow"
        } else {
            "running, but no rules are signed here, so it signs nothing"
        };
        line(format!("Auto      {does}{}", comes_back(home, AUTO)?));
    } else if owner_here && stopped_by_them {
        line("Auto      stopped with Signet, by your person".to_owned());
    } else if owner_here {
        line(format!(
            "Auto      stopped, so nothing signs with nobody there: run {splint} start"
        ));
    }
    line(if installed.owner_elsewhere.is_some() {
        "Rules     your owner signs these on their own device".to_owned()
    } else if stand_in {
        let domain = installed.host_domain()?;
        format!(
            "Controls  none set up yet. {ask} asks your person to: it gives you computer_link to hand \
             over, which opens on Splint on their own computer, and where they use this computer \
             it's asked for here by itself. To install Splint on their computer and open their \
             controls: {install}\n          On Windows, in PowerShell: {install_on_windows}\n          \
             With Splint there already: {open}, or on Windows: {open_on_windows}",
            ask = format_args!("{} controls", home.command()),
            install = controls_install_line(domain),
            install_on_windows = controls_install_line_on_windows(domain),
            open = controls_open_line(domain),
            open_on_windows = controls_open_line_on_windows(domain),
        )
    } else {
        rules_line(signed.map(|signed| signed.draft.ends_at), unix_now())
    });
    if !stand_in && let Some(owner) = owner_who_approved(home, &installed).await {
        line(format!("Owner     {}", approved_by(&owner)));
    }
    if OwnerKey::new(home).is_real_owner() {
        line(format!(
            "Warning   your owner key is in {}, so an agent running as this user can sign as you",
            home.owner_dir().display()
        ));
    }
    // Shown whether or not anything runs, so a command kept here is never out of sight. One that
    // can't be read runs nothing, and is said rather than hiding the rest.
    let kept_listener = match Kept::load(home) {
        Ok(kept) => kept,
        Err(failure) => {
            line(format!("Listener  {failure}"));
            None
        }
    };
    if let Some(kept) = &kept_listener {
        line(listener_line(home, kept, stopped_by_them)?);
    }
    if !running {
        return Ok(out.trim_end().to_owned());
    }

    let api = SignetApi::new(home, &installed)?;
    if let Some(stopped) = api.stopped().await {
        line(format!("Stopped   {stopped}"));
    }
    // Nothing else here counts for an agent that's finished.
    if api.retired().await {
        return Ok(out.trim_end().to_owned());
    }
    if let Some(at) = api.host_closing_at().await {
        line(format!("Host      {}", host_closing(at, &splint)));
    }
    let who = api.who().await.ok();
    line(match who.as_ref() {
        Some(who) => match at_its_host(home, &installed, who) {
            Some(words) => format!("Host      {words}"),
            None => format!("Host      registered at {}", installed.host_domain()?),
        },
        None => "Host      can't tell, as Signet isn't answering".to_owned(),
    });
    if who.as_ref().is_some_and(|who| !who.owner_recovery_set) && !stand_in {
        line(format!("Recovery  not set. {RECOVERY_NOT_SET}"));
    }
    if let Ok(listening) = api.listening().await {
        let now = unix_now();
        let kept = match kept_listener {
            Some(_) => Some(kept::is_running(home)?),
            None => None,
        };
        line(listening_line(&listening, kept, now));
        if let Some(at) = listening.oldest_unread_at {
            line(format!(
                "Unread    the oldest unread message came {}",
                ago(at, now)
            ));
        }
        for held in signet_api::HeldMail::lines(&listening.held) {
            line(format!("Held      {held}"));
        }
    }
    // A host that refused the newest rules holds this agent's sends to older ones (issue 411).
    let at_host = who.and_then(|who| who.rules_at_host);
    if let Some(host) = rules::status_line(at_host) {
        line(host);
    }
    // Addresses come from what other owners signed, so they're escaped for this terminal. Signet
    // doesn't answer while its host can't be reached, and that shouldn't hide the rest.
    let contacts = match api.contacts().await {
        Ok(contacts) => contacts,
        Err(failure) => {
            line(format!("Contacts  can't tell: {failure}"));
            return Ok(out.trim_end().to_owned());
        }
    };
    if contacts.is_empty() {
        line("Contacts  none yet".to_owned());
    }
    for contact in contacts {
        let mark = if contact.approved_by_owner {
            ""
        } else {
            "  (added by your agent: your person hasn't approved them)"
        };
        line(format!(
            "Contact   {}{mark}",
            contact.address.escape_debug()
        ));
    }
    // Asks the host, which may be away. That shouldn't hide the rest.
    match api.held().await {
        Ok(held) => {
            // A contact the agent added is listed above, marked, and waits for nobody.
            let senders: BTreeSet<String> = held
                .into_iter()
                .filter(|found| found.kind != "agreed")
                .map(|found| match (found.kind.as_str(), found.address) {
                    ("disagreed", Some(address)) => format!(
                        "the host of {} names someone other than the ID you signed or your agent knew there",
                        address.escape_debug()
                    ),
                    ("asked", Some(address)) => format!(
                        "your agent asks to write to someone. To add them: {}",
                        own_line(home, &line_for(&address, &found.sender)).escape_debug()
                    ),
                    (_, Some(address)) => format!(
                        "someone wrote. To let them in: {}",
                        own_line(home, &line_for(&address, &found.sender)).escape_debug()
                    ),
                    (_, None) => format!(
                        "someone wrote. To let them in: {}, with no address that checks out",
                        found.sender
                    ),
                })
                .collect();
            for sender in senders {
                line(format!("Waiting   {sender}"));
            }
        }
        Err(failure) => line(format!("Waiting   can't tell: {failure}")),
    }
    Ok(out.trim_end().to_owned())
}

/// Where an agent stands, in words that don't change with the wording people read.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Nothing here has joined, or a join stopped before the host took it.
    None,
    /// The owner's device has to sign before there's an address.
    WaitingForOwner,
    /// It has an address and works, without its owner's oversight, until they set up their controls.
    NoControlsYet,
    /// Its owner's key signed for it.
    ControlsSet,
    /// Its owner retired it at its host, for good, as their signature there says. Running `splint
    /// retire` with its own address frees its folder.
    Retired,
}

/// What `splint join`, `status` and `finish` print with `--json`: facts, never words for anyone to say.
#[derive(Serialize)]
pub struct Standing {
    pub address: Option<String>,
    pub agent_id: Option<String>,
    pub state: State,
    pub signet: Option<String>,
    /// What starts Signet again after a crash or a restart, once it has joined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signet_comes_back_by: Option<ComesBackBy>,
    /// Whether its Signet answers now, once it has joined. Running isn't always answering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signet_answering: Option<bool>,
    /// Whether its host has taken it since its Signet started, while its Signet answers to say so.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    /// How far signing on has got, as its Signet says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationState>,
    /// Whether its host answered Signet's last look, as registered can't tell of a host gone since.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_answering: Option<bool>,
    /// How many contacts its Signet has, when it's running and answers.
    pub contacts: Option<usize>,
    /// Where things stand and what runs next, in plain words for the agent.
    pub next: String,
    /// How its person sets up their controls, once it has joined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controls: Option<Controls>,
    /// The message the release wrote for the owner's device, when `splint join` has just made it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub for_owner: Option<String>,
    /// Where Signet also listens for its owner's device on another machine, when that's on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_network: Option<String>,
    /// Where a move under way, started with `splint switch-host`, is to, until it's done.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moving_to: Option<String>,
    /// When its host says it closes, as its Signet last heard. `next` says what moving keeps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_closes: Option<String>,
    /// `not_set` while its owner's ID has no recovery code, as its Signet says. Left out once it's
    /// set, or where that can't be told.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_code: Option<RecoveryCode>,
    /// Whether anything listens for this agent, once it has joined: facts for its own side, which
    /// nobody who writes to it is told.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listening: Option<Listening>,
    /// How many seconds ago its oldest unread message came, by Signet's clock, when one waits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_unread: Option<u64>,
    /// What waits at its host unread because its Signet can't open or check it yet, of each kind,
    /// with why in plain words.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<signet_api::HeldMail>,
}

/// Whether a wait is held on this agent's Signet or a listener is kept for it, and when its side last
/// waited or read, as Signet saw it. Nothing listening means nothing hears a message until someone
/// looks.
#[derive(Serialize)]
pub struct Listening {
    /// A wait is held on Signet right now, as by `splint listen` or the agent's own wait. False while
    /// Signet isn't running, and left out where one that runs didn't say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_held: Option<bool>,
    /// The kept listener, when one is registered here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kept: Option<KeptListener>,
    /// When a wait was last held, and when the inbox, invites or requests were last read, in seconds
    /// since 1970. Left out for not since Signet started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_wait_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_read_at: Option<u64>,
}

/// The kept listener, with the exact command it runs.
#[derive(Serialize)]
pub struct KeptListener {
    pub command: Vec<String>,
    pub folder: String,
    pub gap_secs: u64,
    pub running: bool,
}

/// Whether the owner's ID can be recovered, as a word a program acts on.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCode {
    NotSet,
}

/// What an agent is told while its owner's ID has no recovery code: never to ask for it.
pub const RECOVERY_NOT_SET: &str = "Your person's owner ID has no recovery code yet, so losing the \
     computer their sign-in is on would lose that ID, and you with it. They set one by typing splint \
     computer recovery in their own terminal, or on their controls page. Never ask for the code or \
     take it: it's theirs alone, and whoever holds it can take their ID.";

/// The person's path to their controls, as data. How and when an agent shows it is the agent's.
#[derive(Serialize)]
pub struct Controls {
    /// Whether its owner's key has signed for it.
    pub set: bool,
    /// The owner ID that approved them, once they're set, to check against the one the person sees
    /// under Account in their controls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    /// One line that installs Splint on the person's own Mac or Linux computer, from this release, and
    /// opens their controls there. This and the three after it stay once controls are set, as the
    /// person opens them again wherever they set them up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install: Option<String>,
    /// The same as `install`, for a person whose own computer runs Windows, in PowerShell.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_on_windows: Option<String>,
    /// Opens their controls where Splint is installed already.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open: Option<String>,
    /// The same as `open`, on Windows, in PowerShell.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_on_windows: Option<String>,
    /// Where their controls open, on their own computer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// What this agent runs to ask its person to set up their controls for it: it gives a link to
    /// hand over, and where they use this computer it's asked for here too, and it takes up what they
    /// sign by itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask: Option<String>,
    /// What this agent runs to ask its person for exactly what it wants changed, once its controls
    /// are set: `splint ask` with the changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask_for_changes: Option<String>,
}

/// A line of `splint` for this agent to run, as this agent.
fn own_line(home: &Home, line: &str) -> String {
    match line.strip_prefix("splint ") {
        Some(rest) => format!("{} {rest}", home.command()),
        None => line.to_owned(),
    }
}

const NOT_JOINED: &str = "Not joined yet. Join with your handle and the host's address, as splint join \
                          HANDLE HOST.";
const WAITING: &str = "Waiting for your owner's device to sign before there's an address. for_owner, or \
                       splint join again, has the release's message for them. Their answer is a line \
                       starting splint finish, which you run.";
const NO_CONTROLS: &str = "Joined. Until your person sets up their controls you work without their \
                           oversight, and Splint treats you accordingly: tighter limits, you can commit \
                           them to nothing, and your contacts see no controls set up yet. Run \
                           controls.ask to ask them: it gives you computer_link to hand over, which \
                           opens on Splint on their own computer, and where your person uses this \
                           computer it's asked for here by itself. Whoever approves first by a link \
                           becomes your owner, so send one only where your person alone reads it. If \
                           Splint isn't on their computer yet, controls.install installs it and opens \
                           their controls, or controls.install_on_windows on Windows: guide them \
                           through it. You take up what they sign by yourself, with nothing to paste.";
const CONTROLS: &str = "Your owner's controls are set. Work within them: splint status shows who's \
                        waiting.";

/// Never refused for an agent that hasn't joined, as saying so is the answer.
pub async fn standing(home: &Home) -> Result<Standing, Failure> {
    let joined = Installed::load(home)?.and_then(|installed| {
        let agent = installed.agent.clone()?;
        Some((installed, agent))
    });
    let Some((installed, agent)) = joined else {
        let waiting = waiting_address(home).ok();
        let state = if waiting.is_some() {
            State::WaitingForOwner
        } else {
            State::None
        };
        // Never to join, when another agent here is the one meant, or it would make a second.
        let next = match (state, home.others_instead()?) {
            (State::None, Some(others)) => sentence(&others),
            (State::None, None) => NOT_JOINED.to_owned(),
            _ => WAITING.to_owned(),
        };
        return Ok(Standing {
            address: waiting,
            agent_id: None,
            state,
            signet: None,
            signet_comes_back_by: None,
            signet_answering: None,
            registered: None,
            registration: None,
            host_answering: None,
            contacts: None,
            next,
            controls: None,
            for_owner: None,
            owner_network: None,
            moving_to: None,
            host_closes: None,
            recovery_code: None,
            listening: None,
            oldest_unread: None,
            held: Vec::new(),
        });
    };
    let state = if installed.owner_elsewhere.is_none() && OwnerKey::new(home).is_stand_in() {
        State::NoControlsYet
    } else {
        State::ControlsSet
    };
    let running = is_running(home, SIGNET)?;
    let who = if running {
        SignetApi::new(home, &installed)?.who().await.ok()
    } else {
        None
    };
    // A Signet that's started but not answering yet has no count to give, which isn't a failure.
    let (contacts, stopped, closing, recovery_code, heard, retired) = if running {
        let api = SignetApi::new(home, &installed)?;
        let not_set =
            state == State::ControlsSet && who.as_ref().is_some_and(|who| !who.owner_recovery_set);
        (
            api.contacts().await.ok().map(|list| list.len()),
            api.stopped().await,
            api.host_closing_at().await,
            not_set.then_some(RecoveryCode::NotSet),
            api.listening().await.ok(),
            api.retired().await,
        )
    } else {
        (None, None, None, None, None, false)
    };
    // One whose file can't be read runs nothing, which `splint status` says in words.
    let kept_listener = match Kept::load(home).ok().flatten() {
        Some(kept) => Some(KeptListener {
            command: kept.words(),
            folder: kept.folder.to_string_lossy().into_owned(),
            gap_secs: kept.gap_secs,
            running: kept::is_running(home)?,
        }),
        None => None,
    };
    let held = heard
        .as_ref()
        .map(|heard| heard.held.clone())
        .unwrap_or_default();
    let oldest_unread = heard
        .as_ref()
        .and_then(|heard| heard.oldest_unread_at)
        .map(|at| unix_now().saturating_sub(at));
    let listening = Listening {
        wait_held: match &heard {
            Some(heard) => Some(heard.wait_held),
            None if running => None,
            None => Some(false),
        },
        kept: kept_listener,
        last_wait_at: heard.as_ref().and_then(|heard| heard.last_wait_at),
        last_read_at: heard.as_ref().and_then(|heard| heard.last_read_at),
    };
    let domain = installed.host_domain()?;
    let set = state == State::ControlsSet;
    let owner_id = if set {
        owner_who_approved(home, &installed).await
    } else {
        None
    };
    let controls = Controls {
        set,
        owner_id,
        install: Some(controls_install_line(domain)),
        install_on_windows: Some(controls_install_line_on_windows(domain)),
        open: Some(controls_open_line(domain)),
        open_on_windows: Some(controls_open_line_on_windows(domain)),
        page: Some(format!("http://localhost:{DEFAULT_PORT}/owner")),
        ask: (!set).then(|| format!("{} controls", home.command())),
        ask_for_changes: set.then(|| format!("{} ask CHANGES", home.command())),
    };
    let mut next = match (state, stopped) {
        (_, Some(stopped)) => stopped.to_owned(),
        (State::NoControlsYet, None) => NO_CONTROLS.to_owned(),
        _ => CONTROLS.to_owned(),
    };
    if !running && stopped_by_person(home) {
        next = sentence(&Failure::Stopped.to_string());
    } else if let (false, Some(said)) = (running, last_refusal(home, SIGNET)) {
        let _ = write!(next, " Signet isn't running: {said}.");
    } else if !running {
        let why = match host_clock(&installed).await {
            Some(clock) => format!("isn't running, as {clock}. Then"),
            None => "isn't running, though nobody ran splint stop, so".to_owned(),
        };
        let _ = write!(next, " Signet {why} run {} start.", home.command());
    } else if who.is_none() {
        let _ = write!(next, " Signet is running, but isn't answering.");
    }
    if let Some(words) = who
        .as_ref()
        .and_then(|who| at_its_host(home, &installed, who))
    {
        let _ = write!(next, " This agent is {words}.");
    }
    // A retired agent has nothing to move, recover or keep watch for: only its retirement counts.
    if !retired {
        if let Some(owner) = &controls.owner_id {
            next.push(' ');
            next.push_str(&approved_by(owner));
        }
        if let Some(at) = closing {
            next.push(' ');
            next.push_str(&host_closing(at, &home.command()));
        }
        if recovery_code.is_some() {
            let _ = write!(next, " {RECOVERY_NOT_SET}");
        }
        // One line, as the rest of next is, from the words join prints.
        for word in keep_watch(home).split_whitespace() {
            next.push(' ');
            next.push_str(word);
        }
    }
    Ok(Standing {
        address: Some(installed.address.clone()),
        agent_id: Some(agent.as_str().to_owned()),
        state: if retired { State::Retired } else { state },
        signet: Some(home.signet_socket().to_string_lossy().into_owned()),
        signet_comes_back_by: Some(comes_back_by(home, running)?),
        signet_answering: Some(who.is_some()),
        registered: who.as_ref().map(|who| who.registered),
        registration: who.as_ref().and_then(|who| who.registration),
        host_answering: who.as_ref().map(|who| who.host_answering),
        contacts,
        next,
        controls: Some(controls),
        for_owner: None,
        owner_network: installed.owner_network.map(|network| network.at),
        moving_to: crate::switch_host::under_way(home),
        host_closes: closing
            .map(|at| crate::agent_commands::times::shown_time(&serde_json::json!(at))),
        recovery_code,
        listening: Some(listening),
        oldest_unread,
        held,
    })
}

/// A failure's words as a sentence of their own.
fn sentence(words: &str) -> String {
    let mut chars = words.chars();
    let first: String = chars
        .next()
        .into_iter()
        .flat_map(char::to_uppercase)
        .collect();
    format!("{first}{}.", chars.as_str())
}

/// What's wrong with this computer's clock, by its host's, when that keeps Signet from signing in.
async fn host_clock(installed: &Installed) -> Option<String> {
    let calls = HostCalls::new(installed.host_domain().ok()?).ok()?;
    calls
        .clock_off()
        .await
        .map(splint_core::host_clock::described)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rules once ended 30 days after they were signed. Now only an end the owner gave them stops the
    /// agent.
    #[test]
    fn rules_stop_the_agent_only_at_an_end_the_owner_gave_them() {
        let now = 2_000_000_000;
        assert!(rules_line(None, now).contains("none"));
        assert!(!rules_line(Some(None), now).contains("stopped"));
        assert!(rules_line(Some(Some(now + 3 * DAY_SECS)), now).contains("3 more days"));
        assert!(rules_line(Some(Some(now)), now).contains("stopped"));
    }
}

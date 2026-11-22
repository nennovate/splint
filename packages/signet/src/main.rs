//! Signet: the small process beside each agent that holds its key and seals what it sends.
//!
//! An agent can be any program that can make an HTTP call. Signet assumes that program may be
//! fooled, so nothing the agent sends can reach the key, and every message is verified here
//! again before the agent sees it, without trusting the host.

mod activity;
mod agent_api;
mod arrivals;
mod asks;
mod binding;
mod body_room;
mod budget;
mod carried;
mod changes;
mod contact_asks;
mod contacts;
mod delegation;
mod ending;
mod grants;
mod host_client;
mod invites;
mod listening;
mod own_keys;
mod owner_network;
mod owner_relay;
mod receipts;
mod recovery;
mod release;
mod requests;
mod retired;
mod rules;
mod sealing;
mod secret_egress;
mod seen;
mod sent;
mod state_file;
mod who;

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use splint_core::private_files;
use splint_core::transport::Scheme;
use splint_core::{AGENT_KEYS_LOST_EXIT, AgentKeys, SealingKey, SigningKey, parse_address};
use tokio::sync::Mutex;

use crate::binding::Registered;
use crate::budget::Budget;
use crate::contacts::Contacts;
use crate::host_client::{HostClient, Lookup};
use crate::requests::Requests;
use crate::requests::store::Store;
use crate::rules::RulesStore;
use crate::seen::Seen;
use crate::who::Who;

const DEFAULT_SYNC_MILLIS: u64 = 2000;
/// The argument that makes this agent's key and stops, before its owner has signed anything.
const PREPARE: &str = "prepare";
const LOOK_AT_KEYS: &str = "look-at-keys";
const RETIREMENT_FILE: &str = "retirement.json";
const PUBLIC_KEY_FILE: &str = "agent.pub";
/// Held for as long as this Signet runs, so a second one on the same folder refuses to start.
const LOCK_FILE: &str = "signet.lock";

impl Signet {
    /// Looks someone up through this agent's own host, signed as this agent.
    pub fn lookup<'a>(&'a self, who: &'a Who) -> Lookup<'a> {
        Lookup {
            host: &self.host,
            key: &self.key,
            me: who.identity.id(),
        }
    }
}

pub struct Signet {
    pub key: SigningKey,
    /// What contacts seal to. It never leaves this folder, like the signing key.
    pub seal_key: SealingKey,
    who: RwLock<Arc<Who>>,
    who_path: PathBuf,
    /// Held while a statement about who this agent is goes through, so two can't cross.
    pub changing_who: Mutex<()>,
    /// The address it was started at, and the one its binding names now. They differ only in the owner
    /// part of the name, after a new owner gave it theirs.
    started_at: String,
    address: RwLock<String>,
    pub api_token: String,
    pub host: HostClient,
    pub contacts: Contacts,
    pub seen: Seen,
    pub requests: Requests,
    pub rules: RulesStore,
    pub registered: Registered,
    pub budget: Budget,
    pub grants: grants::Grants,
    pub own_changes: changes::Own,
    pub seen_changes: Arc<changes::Seen>,
    pub contact_asks: Arc<contact_asks::ContactAsks>,
    /// What this agent asked its owner to change, signed and kept until it's done or over.
    pub asks: asks::Asks,
    pub their_sealing: sealing::TheirSealing,
    pub invites: invites::Invites,
    /// What an agent can wait on, and what tells the loop beside it to go to its host now.
    pub activity: activity::Activity,
    /// The key the owner may let sign within their limits while they're away.
    pub delegation: delegation::Delegation,
    /// What came from each contact lately, for the facts beside each arrival and the owner's usage.
    pub arrivals: arrivals::Arrivals,
    /// What the owner signed that's been taken, so a copy by another route does nothing.
    pub owner_signed: owner_relay::TakenOnce,
    /// The retirement its owner signed for it, once it holds one, kept across restarts.
    pub retired: retired::Retired,
    /// Mail brought along from a host this agent left.
    pub carried: carried::Carried,
    /// Every note this agent sent, until it's delivered or ended and a while after.
    pub sent: sent::Sent,
    /// What this Signet owes the senders of notes it opened.
    pub receipts: receipts::Receipts,
}

/// Makes this agent's keys and writes down their public halves, for an owner's device to authorize. Its
/// ID hashes them with a backup commitment only the owner's device can make, so nothing else can start
/// yet.
fn prepare() -> Result<(), Box<dyn Error>> {
    let state = PathBuf::from(env::var("SPLINT_STATE_DIR")?);
    // Before anything is made inside, which on Windows takes the folder's access.
    private_files::restrict(&state)?;
    let (key, seal_key) = own_keys::for_preparing(&state)?;
    let public = AgentKeys {
        key: key.public_key(),
        seal: seal_key.public_key(),
    };
    fs::write(state.join(PUBLIC_KEY_FILE), public.encoded())?;
    Ok(())
}

/// Says whether this agent's keys are lost for good, by how it ends, for what would replace them. Keys
/// that can be put right, or that are fine, are never replaced, and a refusal says why in its own words.
fn look_at_keys() -> Result<ExitCode, Box<dyn Error>> {
    let state = PathBuf::from(env::var("SPLINT_STATE_DIR")?);
    match own_keys::look_at(&state) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(refused) if refused.lost_for_good() => Ok(ExitCode::from(AGENT_KEYS_LOST_EXIT)),
        Err(refused) => Err(refused.into()),
    }
}

/// Two Signets on one folder would each write over what the other saved, and both would answer for
/// the agent. The lock goes when the process does, however it ends, and its pid inside says which
/// one holds it.
fn the_only_signet_on(state: &Path) -> Result<fs::File, Box<dyn Error>> {
    let path = state.join(LOCK_FILE);
    #[cfg(unix)]
    let opened = private_files::open(
        fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true),
        &path,
    );
    // On Windows, while this is open nothing else can open it to write, and that's how a client tells
    // this Signet still runs before it sends anything down its pipe. A client can't hold a lock to
    // test one there, and a second Signet's open fails just as its lock would.
    #[cfg(windows)]
    let opened = private_files::pipe::hold(&path).map_err(|error| {
        if private_files::pipe::held_elsewhere(&error) {
            already_running(state, &path)
        } else {
            error.into()
        }
    });
    let lock = opened?;
    if lock.try_lock().is_err() {
        return Err(already_running(state, &path));
    }
    lock.set_len(0)?;
    write_pid(&lock)?;
    Ok(lock)
}

#[cfg(unix)]
fn write_pid(lock: &fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    lock.write_all_at(std::process::id().to_string().as_bytes(), 0)
}

#[cfg(windows)]
fn write_pid(lock: &fs::File) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let pid = std::process::id().to_string();
    let written = lock.seek_write(pid.as_bytes(), 0)?;
    if written != pid.len() {
        return Err(std::io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

fn already_running(state: &Path, path: &Path) -> Box<dyn Error> {
    let holder = fs::read_to_string(path).unwrap_or_default();
    let holder = holder.trim();
    let holder = if !holder.is_empty() && holder.chars().all(|c| c.is_ascii_digit()) {
        format!(" as process {holder}")
    } else {
        String::new()
    };
    format!(
        "another Signet is already running for {}{holder}: stop it, then start this one",
        state.display()
    )
    .into()
}

#[tokio::main]
async fn main() -> Result<ExitCode, Box<dyn Error>> {
    tracing_subscriber::fmt().init();

    match env::args().nth(1).as_deref() {
        Some(PREPARE) => return prepare().map(|()| ExitCode::SUCCESS),
        Some(LOOK_AT_KEYS) => return look_at_keys(),
        _ => {}
    }
    // Hashed first, before an update can replace the file this is running from.
    let release = splint_core::release::Release::of_this_program();

    let address = env::var("SPLINT_ADDRESS")?;
    let (_, domain) = parse_address(&address)?;
    let scheme = Scheme::from_env()?;
    if !scheme.is_https() {
        tracing::warn!("plain HTTP to the host, as in a test setup: don't run this for real");
    }
    // Trusted beside the public roots and the system's own, as a proxy that opens TLS needs. It's the
    // machine's setting, not Splint's, so it's said each time rather than refused.
    for setting in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
        if let Some(named) = env::var_os(setting) {
            tracing::warn!(
                setting,
                named = %named.to_string_lossy(),
                "trusting the certificates named here for TLS, as well as the public ones"
            );
        }
    }
    scheme.check_destination(domain)?;
    let listen_at = listening::Where::from_env(scheme)?;
    let owner_network = owner_network::Setting::from_env()?;
    let state = PathBuf::from(env::var("SPLINT_STATE_DIR")?);
    // An agent must not be able to read any of this, whoever made the folder, and on Windows what's
    // made inside takes the folder's access, so it's restricted before anything is.
    private_files::restrict(&state)?;
    let _only_signet = the_only_signet_on(&state)?;
    let (key, seal_key) = own_keys::for_starting(&state)?;
    let who_path = state.join(own_keys::WHO_FILE);
    let who = Who::load(&who_path, &key, &seal_key)?;
    let host = HostClient::new(domain.to_owned(), scheme)?;

    let requests = Requests {
        store: Store::load(state.join("requests.json"))?,
        person_texts: requests::person_text::Waiting::load(
            state.join("person-texts.json"),
            state.join("person-texts-taken.json"),
        )?,
        where_paid: requests::payments::WherePaid::load(state.join("where-paid.json"))?,
        held_opens: requests::held_opens::HeldOpens::load(state.join("held-opens.json"))?,
        owner_token: env::var("SPLINT_OWNER_TOKEN").ok(),
        types: requests::types::AgreedTypes::default(),
        refused: requests::refusals::Refusals::load(state.join("refused.json"))?,
        guest_steps_read: 0.into(),
    };
    let sync_every = match env::var("SPLINT_SYNC_MILLIS") {
        Ok(millis) => Duration::from_millis(millis.parse()?),
        Err(_) => Duration::from_millis(DEFAULT_SYNC_MILLIS),
    };

    let registered = Registered::new(env::var("SPLINT_SIGNUP_CODE").unwrap_or_default());
    let known = Arc::new(contacts::Known::load(state.join("known.json"))?);
    let seen_changes = Arc::new(changes::Seen::load(state.join("seen-changes.json"))?);
    let contact_asks = Arc::new(contact_asks::ContactAsks::load(
        state.join("contact-asks.json"),
    )?);
    let own_changes = changes::Own::load(
        state.join("history.json"),
        state.join("listeners.json"),
        &who.identity,
    )?;
    let rules = RulesStore::load(
        state.join("rules.json"),
        &state,
        &who.owner,
        who.identity.id(),
        known.clone(),
        seen_changes.clone(),
    )?;
    let address_now = who::address_now(&who, &address);
    let retired = retired::Retired::load(state.join(RETIREMENT_FILE), &who)?;
    let their_sealing = sealing::TheirSealing::load(state.join("their-sealing.json"))?;
    let signet = Arc::new(Signet {
        key,
        seal_key,
        who: RwLock::new(Arc::new(who)),
        who_path,
        changing_who: Mutex::new(()),
        address: RwLock::new(address_now),
        started_at: address,
        api_token: env::var("SPLINT_API_TOKEN")?,
        host,
        contacts: Contacts::load(
            state.join("contacts.json"),
            known,
            seen_changes.clone(),
            contact_asks.clone(),
        )?,
        seen: Seen::load(state.join("seen.json"))?,
        requests,
        rules,
        registered,
        budget: Budget::load(state.join("budget.json"))?,
        grants: grants::Grants::load(state.join("grants.json"))?,
        own_changes,
        seen_changes,
        contact_asks,
        asks: asks::Asks::load(state.join("asks.json"))?,
        their_sealing,
        invites: invites::Invites::load(
            state.join("invites-sent.json"),
            state.join("invites-pending.json"),
        )?,
        activity: activity::Activity::load(state.join("wakes.json"))?,
        delegation: delegation::Delegation::load(&state)?,
        arrivals: arrivals::Arrivals::load(
            state.join("arrivals.json"),
            state.join("arrivals-notes.json"),
        )?,
        owner_signed: owner_relay::TakenOnce::load(state.join("owner-signed-taken.json"))?,
        retired,
        carried: carried::Carried::load(state.join("carried-mail.json"))?,
        sent: sent::Sent::load(state.join("sent.json"))?,
        receipts: receipts::Receipts::load(state.join("receipts.json"))?,
    });
    requests::types::read_all(&signet).await;
    signet.requests.settle_held_opens().await?;
    // Said before anything can ask, and tried only once this Signet listens: an agent whose host has gone
    // for good still has to be able to reach this API, to move to another.
    let registering = binding::note_what_is_saved(&signet);
    let listening = listen_at.bind().await?;
    if registering {
        tokio::spawn(binding::keep_registering(signet.clone()));
    }
    let owner_away = (env::var("SPLINT_OWNER_AWAY").as_deref() == Ok("yes")).then(|| {
        let mail_taken = Arc::new(tokio::sync::Notify::new());
        tokio::spawn(owner_relay::run(signet.clone(), mail_taken.clone()));
        mail_taken
    });
    tokio::spawn(requests::sync::run(signet.clone(), sync_every, owner_away));
    tokio::spawn({
        let signet = signet.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                signet.activity.release_due();
            }
        }
    });
    tokio::spawn(changes::run(signet.clone(), sync_every));
    if let Some(setting) = owner_network {
        let listener = setting.bind().await?;
        let signet = signet.clone();
        tokio::spawn(async move {
            if let Err(error) = owner_network::serve(listener, signet).await {
                tracing::warn!(%error, "owner network access stopped, so the owner's device goes by way of the host");
            }
        });
    }
    let api = agent_api::routes(signet)
        .merge(release::routes(release))
        .layer(axum::middleware::from_fn_with_state(
            body_room::BodyRoom::default(),
            body_room::hold_bodies,
        ))
        .layer(axum::middleware::from_fn(release::one_protocol));
    listening.serve(api).await?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// The bug this catches: Signet holding its lock in a way that lets something else open it to
    /// write while Signet runs, which is how every client tells Signet's pipe is Signet's before it
    /// sends a token down it, as the protocol says. Clients would then take a running Signet for a
    /// stopped one and send nothing, or a second Signet could start on the same folder.
    #[test]
    fn while_signet_holds_its_lock_nothing_else_can_open_it_to_write() {
        let state = std::env::temp_dir().join(format!("signet-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        private_files::make_private_dir(&state).unwrap();
        let lock = state.join(LOCK_FILE);

        let held = the_only_signet_on(&state).unwrap();
        assert!(private_files::pipe::is_held(&lock));
        assert!(the_only_signet_on(&state).is_err());

        drop(held);
        assert!(!private_files::pipe::is_held(&lock));
        fs::remove_dir_all(&state).unwrap();
    }
}

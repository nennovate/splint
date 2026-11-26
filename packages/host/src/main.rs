//! A Splint host: registers agents, stores messages durably and delivers them to other hosts.
//!
//! It holds no agent keys. It checks every signature itself and treats other hosts as hostile.

mod admission;
mod answers;
mod api_error;
mod changes;
mod clock;
mod closing;
mod connections;
mod contact_holds;
mod counts;
mod database;
mod delivery;
mod destinations;
mod guest;
mod host_identity;
mod inbox;
mod invites;
mod join;
mod limits;
mod log_limit;
mod lookup;
mod note_receipts;
mod operator;
mod overload;
mod own_id;
mod owner_api;
mod owner_keys;
mod owner_relay;
mod peering;
mod refused;
mod registry;
mod release;
mod requests;
mod waits;

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use splint_core::canonical_domain;
use splint_core::transport::Scheme;
use sqlx::PgPool;

use crate::operator::{SettingError, Stopped, required, yes_or_unset};

const MAX_REQUEST_BYTES: usize = 512 * 1024;
// Every body is read under the cap above before any route sees it, so no route can take more, and a
// Signet trims its owner's view to fit this one. A bigger view would be refused here, and only here.
const _: () = assert!(splint_core::host_api::MAX_OWNER_VIEW_BYTES <= MAX_REQUEST_BYTES);
const PEER_TIMEOUT: Duration = Duration::from_secs(3);

pub struct Host {
    pub db: PgPool,
    /// What to go by before destroying anything, rather than the wall clock alone.
    pub clock: clock::CleanupClock,
    pub domain: String,
    pub scheme: Scheme,
    /// Which hosts this one exchanges with: every host but those blocked, unless its operator keeps it
    /// private. The operator can change it while it runs.
    pub peers: peering::Peers,
    /// Whether this host takes new agents with no signup code, as its operator chose.
    pub open_signup: bool,
    /// What its operator set, and what these numbers come to for an owner's rules.
    pub limits: limits::Live,
    /// This host's ID and the key it counts now, which its operator can change while it runs.
    pub own: own_id::OwnId,
    /// How this host calls other hosts, which goes by where each may be. See `destinations`.
    pub calls: destinations::Callers,
    /// Hosts this one hasn't met yet: what it fetched of them, and how much fetching is going on.
    pub first_contact: host_identity::FirstContact,
    /// Hosts this one has pinned: when it last looked at each for a key change.
    pub known_peers: host_identity::KnownPeers,
    /// The room this host's answers take until their callers have read them.
    pub answers: Arc<answers::AnswerRoom>,
    /// Signets' calls held until something comes for their agents.
    pub waits: waits::Waits,
    /// When its operator has said this host closes, which they can set or take back while it runs.
    pub closing: closing::Closing,
    /// Names its operator keeps back, which nobody here has as a name of their own.
    pub kept_names: registry::kept_names::KeptNames,
}

impl Host {
    /// A host whose database is closed, for showing what a route refuses before it asks the database
    /// anything. Once it asks, its answer is `Unavailable`.
    #[cfg(test)]
    async fn with_closed_database(domain: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy_with(sqlx::postgres::PgConnectOptions::new());
        db.close().await;
        Ok(Self {
            db,
            clock: clock::CleanupClock::starting_now(),
            domain: domain.to_owned(),
            scheme: Scheme::PlainHttpForTests,
            peers: peering::Peers::new(peering::PeerList::naming_none(domain)),
            open_signup: false,
            limits: limits::Live::new(limits::Limits::from_env()?),
            answers: answers::AnswerRoom::new(&limits::Limits::from_env()?),
            own: own_id::OwnId::new(own_id::Own::fresh(domain)?),
            calls: destinations::Callers::new(Scheme::PlainHttpForTests, false)?,
            first_contact: host_identity::FirstContact::default(),
            known_peers: host_identity::KnownPeers::default(),
            waits: waits::Waits::new(1),
            closing: closing::Closing::default(),
            kept_names: registry::kept_names::KeptNames::default(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Stopped> {
    let command: Vec<String> = env::args().skip(1).collect();
    if command.is_empty() {
        tracing_subscriber::fmt().init();
        return serve().await;
    }
    // What a one-shot prints is its answer, so what it logs goes beside that and not into it.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let command: Vec<&str> = command.iter().map(String::as_str).collect();
    operator::run(&command).await
}

/// Everything a host's operator set that a start reads before it touches the database.
pub struct Settings {
    domain: String,
    peers: peering::PeerList,
    peers_file: Option<PathBuf>,
    scheme: Scheme,
    internal_allowed: bool,
    listen: String,
    open_signup: bool,
    limits: limits::Limits,
    limits_file: Option<PathBuf>,
    pub database_url: String,
    pub key_file: PathBuf,
    pub new_host_key: bool,
    cleanup_every: Duration,
    kept_names: registry::kept_names::KeptNames,
}

/// Reads them as a start does, and refuses the first that's wrong by its name. `splint-host check`
/// runs this too, so what it passes is what a start takes.
pub fn settings() -> Result<Settings, Stopped> {
    // Addresses name a domain in one spelling only, so these have to match it to match at all.
    let domain = canonical_domain(&required("SPLINT_DOMAIN")?)
        .map_err(|_| SettingError::NotAHostName("SPLINT_DOMAIN"))?;
    let scheme = Scheme::from_env()?;
    if !scheme.is_https() {
        tracing::warn!("plain HTTP between hosts, as in a test setup: don't run this for real");
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
    let (peers, peers_file) = peering::at_start(&domain, scheme)?;
    let internal_allowed = destinations::internal_allowed_from(
        env::var(destinations::INTERNAL_SETTING).ok().as_deref(),
    )?;
    if internal_allowed {
        tracing::warn!(
            setting = destinations::INTERNAL_SETTING,
            "any host may be called on an internal address or any port, so anyone who can name a \
             host to this one can have it call services on its own network"
        );
    }
    let listen = required("SPLINT_LISTEN")?;
    scheme
        .check_listen_address(&listen)
        .map_err(|refused| SettingError::refused("SPLINT_LISTEN", refused))?;

    let open_signup = registry::open_signup_from(env::var("SPLINT_OPEN_SIGNUP").ok().as_deref())?;
    if open_signup {
        tracing::warn!("anyone with an owner key can take an address here, within the limits");
    }

    // Nenye decided on 2026-11-21 that hosts serve no page that makes or signs with a passkey, so
    // these do nothing now. An operator who set one hears so, rather than wondering where it went.
    for gone in ["SPLINT_OWNER_PAGE", "SPLINT_OWNER_PAGE_RP_ID"] {
        if env::var_os(gone).is_some() {
            tracing::warn!(
                setting = gone,
                "this setting is no longer read: hosts serve no owner page, and owners sign on their \
                 own computers. Take it out"
            );
        }
    }

    let (limits, limits_file) = limits::Limits::at_start()?;
    let new_host_key = yes_or_unset(own_id::NEW_KEY_SETTING)?;
    if new_host_key {
        tracing::warn!(
            "{} is on: if this host's key file is ever missing, it makes a new key, which every \
             host that pinned the old one refuses. Take the setting out once the host is up",
            own_id::NEW_KEY_SETTING
        );
    }
    let cleanup_every = match env::var("SPLINT_CLEANUP_SECS") {
        // Each cleanup loop sleeps this long between writes, so zero would never let Postgres rest.
        Ok(secs) => Duration::from_secs(
            secs.parse::<u64>()
                .ok()
                .filter(|secs| *secs > 0)
                .ok_or(SettingError::NotSeconds("SPLINT_CLEANUP_SECS"))?,
        ),
        Err(_) => inbox::DEFAULT_CLEANUP_INTERVAL,
    };
    Ok(Settings {
        domain,
        peers,
        peers_file,
        scheme,
        internal_allowed,
        listen,
        open_signup,
        limits,
        limits_file,
        database_url: required(database::SETTING)?,
        key_file: PathBuf::from(required(own_id::KEY_FILE_SETTING)?),
        new_host_key,
        cleanup_every,
        kept_names: registry::kept_names::KeptNames::at_start()?,
    })
}

async fn serve() -> Result<(), Stopped> {
    // Hashed first, before an update can replace the file this is running from.
    let release = splint_core::release::Release::of_this_program();
    let Settings {
        domain,
        peers,
        peers_file,
        scheme,
        internal_allowed,
        listen,
        open_signup,
        limits,
        limits_file,
        database_url,
        key_file,
        new_host_key,
        cleanup_every,
        kept_names,
    } = settings()?;
    let connections = connections::within_file_limit(limits.connections);
    // Held calls take connections, so they never take more than half, whatever the setting.
    let waits_at_once = usize::try_from(limits.waits_at_once)
        .unwrap_or(usize::MAX)
        .min(connections / 2);

    let db = database::connect(&database_url, scheme, database::HOST_PATIENCE).await?;
    sqlx::raw_sql(registry::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(delivery::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(inbox::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(requests::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(admission::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(lookup::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(host_identity::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(own_id::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(clock::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(changes::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(contact_holds::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(join::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(owner_relay::SCHEMA).execute(&db).await?;
    owner_relay::seal_what_waited_in_plain(&db).await?;
    sqlx::raw_sql(guest::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(refused::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(waits::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(invites::SCHEMA).execute(&db).await?;
    sqlx::raw_sql(owner_api::agents::SCHEMA)
        .execute(&db)
        .await?;
    sqlx::raw_sql(owner_api::RETIRED_SCHEMA)
        .execute(&db)
        .await?;
    sqlx::raw_sql(closing::SCHEMA).execute(&db).await?;
    host_identity::accept_new_keys(&db, &env::var("SPLINT_REPIN_PEERS").unwrap_or_default())
        .await?;
    host_identity::accept_new_keys_named(&db, peers.repin()).await?;
    registry::add_signup_codes(
        &db,
        &env::var(registry::SIGNUP_CODES_SETTING).unwrap_or_default(),
    )
    .await?;
    let own_files = own_id::Files::beside(&key_file);
    let own = own_id::at_start(
        &own_files,
        own_id::kept(&db).await?,
        &domain,
        own_id::NewKey {
            used: own_id::has_been_used(&db).await?,
            allowed: new_host_key,
        },
    )?;
    own_id::keep(&db, own.identity()).await?;
    own_id::warn_while_no_code(&own);

    let host = Arc::new(Host {
        clock: clock::CleanupClock::load(&db).await?,
        closing: closing::at_start(&db).await?,
        db,
        domain,
        scheme,
        peers: peering::Peers::new(peers),
        open_signup,
        limits: limits::Live::new(limits),
        answers: answers::AnswerRoom::new(&limits),
        own: own_id::OwnId::new(own),
        calls: destinations::Callers::new(scheme, internal_allowed)?,
        first_contact: host_identity::FirstContact::default(),
        known_peers: host_identity::KnownPeers::default(),
        waits: waits::Waits::new(waits_at_once),
        kept_names,
    });

    if let Some(file) = peers_file {
        tokio::spawn(peering::run_rereading(host.clone(), file));
    }
    tokio::spawn(own_id::run_rereading(host.clone(), own_files));
    tokio::spawn(closing::run_rereading(host.clone()));
    tokio::spawn(delivery::run_worker(host.clone()));
    tokio::spawn(inbox::run_cleanup(host.clone(), cleanup_every));
    tokio::spawn(delivery::run_cleanup(host.clone(), cleanup_every));
    tokio::spawn(requests::run_cleanup(host.clone(), cleanup_every));
    tokio::spawn(admission::run_cleanup(host.clone(), cleanup_every));
    tokio::spawn(lookup::run_cleanup(host.clone(), cleanup_every));
    tokio::spawn(guest::run_cleanup(host.clone(), cleanup_every));
    tokio::spawn(invites::run_cleanup(host.clone(), cleanup_every));
    tokio::spawn(registry::open_signup::run_cleanup(
        host.clone(),
        cleanup_every,
    ));
    tokio::spawn(clock::run_keeper(host.clone(), cleanup_every));
    tokio::spawn(changes::run_passing_on(host.clone()));
    tokio::spawn(waits::run_listener(host.clone()));
    match limits_file {
        Some(file) => {
            tracing::info!(
                file = %file.display(),
                "limits counted on each call are taken from this file as it changes. Connections, \
                 calls and bytes held at once, and held waits, keep their numbers until a restart"
            );
            tokio::spawn(limits::run_rereading(host.clone(), file));
        }
        None => tracing::info!(
            "limits are from the environment, so changing one takes a restart: name a file in {} \
             to change them as the host runs",
            limits::FILE_SETTING
        ),
    }

    let app = Router::new()
        .merge(join::routes())
        .merge(contact_holds::routes())
        .merge(owner_relay::routes())
        .merge(registry::routes())
        .merge(host_identity::routes())
        .merge(delivery::routes())
        .merge(inbox::routes())
        .merge(invites::routes())
        .merge(owner_api::routes())
        .merge(waits::routes())
        .merge(requests::routes())
        .merge(admission::routes())
        .merge(lookup::routes())
        .merge(changes::routes())
        .merge(guest::routes())
        .merge(refused::routes())
        .merge(release::routes(release))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(middleware::map_response(api_error::fixed_words_only))
        .layer(middleware::from_fn_with_state(
            host.answers.clone(),
            answers::count,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::new(overload::CallGuard::new(&limits, MAX_REQUEST_BYTES)),
            overload::limit_calls,
        ))
        .layer(middleware::from_fn(release::one_protocol))
        .layer(middleware::from_fn_with_state(
            host.clone(),
            closing::say_on_answers,
        ))
        .layer(middleware::from_fn(owner_api::open_to_any_page))
        .with_state(host);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|error| SettingError::CantListen("SPLINT_LISTEN", listen, error))?;
    tracing::info!(address = %listener.local_addr()?, "host listening");
    connections::serve(
        connections::GuardedListener::new(listener, connections),
        app,
    )
    .await;
    Ok(())
}

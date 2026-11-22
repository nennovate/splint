//! Publishes this host's ID and key, and pins other hosts' IDs.
//!
//! A peer's ID is taken once, from its own domain over verified TLS, and kept. Someone who later gets
//! on the path, or takes over that domain's certificate, can't swap it without the operator saying
//! so, and a delivery doesn't cost another call to the peer. It's kept only once a delivery's proof
//! has checked out against its key, and only so many new hosts are kept an hour.
//!
//! An ID moves on only by a key it counted or by its backup, so when a peer's key changes, this host
//! follows by itself: a proof that fails under the pinned key has it look at what the peer publishes
//! now, and take it only if it's a valid successor of the pin. A host from before IDs is pinned by
//! its key alone, and that pin takes the ID the key signs for, or one whose history the key began.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::host_id::PublishedHost;
use splint_core::{Identity, PublicKey};
use sqlx::PgPool;

use crate::api_error::ApiError;
use crate::destinations::family_of;
use crate::log_limit::LogLimit;
use crate::{Host, database};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS peer_keys (
        domain TEXT PRIMARY KEY,
        key TEXT NOT NULL,
        pinned_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE peer_keys ADD COLUMN IF NOT EXISTS identity TEXT NOT NULL DEFAULT '';
    CREATE TABLE IF NOT EXISTS repins_taken (
        domain TEXT PRIMARY KEY
    );
    CREATE TABLE IF NOT EXISTS new_hosts_met (
        domain TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        family TEXT NOT NULL,
        met_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS new_hosts_met_family ON new_hosts_met (family);
    CREATE INDEX IF NOT EXISTS new_hosts_met_source ON new_hosts_met (source);
";

const PATH: &str = "/.well-known/splint/host";
/// A domain, a key and an ID, which is at most 80 K characters however often its key changed.
const MAX_HOST_INFO_BYTES: usize = 96 * 1024;
/// Key fetches from hosts nobody named, at once in all and for one source. Each can take as long as a
/// call to another host is allowed, so these are what a flood of made-up names can hold. Provisional.
const MAX_FETCHES_AT_ONCE: usize = 8;
const MAX_FETCHES_AT_ONCE_PER_SOURCE: usize = 2;
/// The same for a source a fetch failed for in the last minute. Names are free, so whoever keeps naming
/// hosts that hang is kept to these, and can't hold the places a real new host needs. It's the source
/// that's doubted and never the name, as anyone can name a host under someone else's domain. Provisional.
const MAX_DOUBTFUL_FETCHES_AT_ONCE: usize = 2;
const MAX_DOUBTFUL_FETCHES_AT_ONCE_PER_SOURCE: usize = 1;
/// Looks at hosts already pinned for a key change, at once in all, apart from those, so noise naming
/// hosts nobody has met can't hold up a known host's change. Past this a look waits its turn, in the
/// order asked and one to a host, so slow pages of hosts someone keeps pinned here delay a real host's
/// change by their share and never shut it out. Provisional.
const MAX_PINNED_FETCHES_AT_ONCE: usize = 4;
/// One source's or one family of names' part of the hour's new hosts, as a fraction of them. Anyone with
/// a wildcard domain can make up as many hosts with valid proofs as they like, and without this could
/// spend the whole hour's limit, leaving every real new host waiting. Provisional.
const NEW_HOST_SHARES: i64 = 8;
/// How long what a fetch found is gone by. A failure is short, so a host that was down is soon met; a
/// key is longer, so deliveries with forged proofs naming a real host don't each cost a call to it.
const FAILURE_REMEMBERED: Duration = Duration::from_secs(60);
const KEY_REMEMBERED: Duration = Duration::from_secs(10 * 60);
/// Hosts whose fetch is remembered, past which the oldest is forgotten first, and what their IDs can
/// take in all, as one can be 80 K characters.
const MAX_REMEMBERED: usize = 4096;
const MAX_REMEMBERED_ID_BYTES: usize = 8 * 1024 * 1024;
/// After a look at a pinned host found nothing new, how long before a failed proof looks again. Anyone
/// can send a proof that fails, so this is what one costs the host it names: a call a minute.
const LOOKED_LASTS: Duration = Duration::from_secs(60);
/// How often a pinned host is looked at after a delivery that went fine, so a host that recovered from
/// a stolen key is followed here within about an hour of its next word, though the thief's proofs
/// still pass under the old key.
const REFRESH_EVERY: Duration = Duration::from_secs(60 * 60);
/// Anyone can bring the hour's limit on new hosts closer, so it's said once a minute at most.
static AT_PIN_LIMIT: LogLimit = LogLimit::new();
/// Two copies of one ID that part ways: only the peer's own keys can make them.
static FORKED_PEER: LogLimit = LogLimit::new();

pub fn routes() -> Router<Arc<Host>> {
    Router::new().route(PATH, get(publish))
}

#[derive(Serialize, Deserialize)]
struct HostInfo {
    domain: String,
    /// The key the host signs deliveries with, which is the one its ID counts now.
    key: String,
    /// The host's ID, encoded, and its key's `splint-host-id` statement that the ID is this host. A
    /// host from before IDs has neither, and a page with only one is no page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_proof: Option<String>,
    /// Whether this host takes new agents with no signup code. It's the host's word, and a lie costs
    /// nothing, as it only says whether a registration with no code would be refused.
    #[serde(default)]
    open_signup: bool,
    /// The protocols this host speaks, as `splint-protocols` says them on each answer. Left out by a
    /// host from before ranges, which speaks only protocol 1.
    #[serde(default)]
    protocols: Option<String>,
    /// When this host closes, as seconds since 1970, once its operator has set a date. From then it
    /// takes no new agents. None while it isn't closing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    closing_at: Option<u64>,
}

async fn publish(State(host): State<Arc<Host>>) -> Json<HostInfo> {
    let own = host.own.now();
    Json(HostInfo {
        domain: host.domain.clone(),
        key: own.key().public_key().encoded(),
        identity: Some(own.identity().encoded()),
        identity_proof: Some(own.proof().to_owned()),
        open_signup: host.open_signup,
        protocols: Some(splint_core::release::SPOKEN.header_value()),
        closing_at: host.closing.at(),
    })
}

/// An operator who knows a peer really did change its key says so at startup, by naming it in
/// `SPLINT_REPIN_PEERS`. The next delivery from that peer pins whatever it then publishes.
pub async fn accept_new_keys(db: &PgPool, peers: &str) -> Result<(), sqlx::Error> {
    for peer in peers.split(',').filter(|peer| !peer.is_empty()) {
        sqlx::query("DELETE FROM peer_keys WHERE domain = $1")
            .bind(peer)
            .execute(db)
            .await?;
        tracing::warn!(peer, "will accept a new key from this peer");
    }
    Ok(())
}

/// The same while running, by a `repin` line in the peers file. A line is acted on once, when it
/// first appears, and that's remembered here in Postgres. So a line left in the file doesn't let go of
/// the pin again when another line changes or the host restarts, either of which would let whoever
/// serves that name at that moment bring a key of their own. Taking the line out and putting it back
/// asks again.
pub async fn accept_new_keys_named(
    db: &PgPool,
    named: &BTreeSet<String>,
) -> Result<(), sqlx::Error> {
    let named: Vec<&str> = named.iter().map(String::as_str).collect();
    let mut transaction = database::begin(db).await?;
    let fresh: Vec<String> = sqlx::query_scalar(
        "SELECT peer FROM unnest($1::text[]) AS peer
         WHERE peer NOT IN (SELECT domain FROM repins_taken)",
    )
    .bind(&named)
    .fetch_all(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM peer_keys WHERE domain = ANY($1)")
        .bind(&fresh)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM repins_taken WHERE domain <> ALL($1)")
        .bind(&named)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("INSERT INTO repins_taken (domain) SELECT unnest($1::text[])")
        .bind(&fresh)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    for peer in &fresh {
        tracing::warn!(%peer, "will accept a new key from this peer, as the peers file says");
    }
    Ok(())
}

/// What a host's page says it is: its ID, checked, or for a host from before IDs, its key alone.
#[derive(Clone)]
enum Page {
    Bare(PublicKey),
    Id(Arc<PublishedHost>),
}

impl Page {
    fn key(&self) -> &PublicKey {
        match self {
            Self::Bare(key) => key,
            Self::Id(published) => published.key(),
        }
    }

    /// What `peer_keys.identity` holds for it: the encoded ID, or nothing.
    fn identity_text(&self) -> String {
        match self {
            Self::Bare(_) => String::new(),
            Self::Id(published) => published.identity().encoded(),
        }
    }
}

/// A pinned host, as `peer_keys` holds it: its key, and its encoded ID, empty for a pin made before
/// it had one.
#[derive(Clone, PartialEq, Eq)]
pub struct Pin {
    key: String,
    identity: String,
}

/// A host's key, for checking one delivery's proof, and whether it still has to be pinned.
pub struct PeerKey {
    key: PublicKey,
    pinned: Option<Pin>,
    named: bool,
    page: Option<Page>,
}

impl PeerKey {
    pub const fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The pin the key came from, if it came from one.
    pub const fn pin(&self) -> Option<&Pin> {
        self.pinned.as_ref()
    }
}

/// The key to check a delivery from this host against: the pinned one, or failing that what the host
/// publishes now. A key fetched here is pinned only once a proof has verified against it, by [`pin`].
///
/// Anyone can name any host as a delivery's sender, and each name this host hasn't met costs a call
/// out. So for a host the operator didn't name, what a fetch found is remembered for a while, and
/// fetches are bounded: a few at once in all, fewer from one source, past which the caller is told to
/// come back. A named host is spared all of this.
pub async fn key_for_delivery(host: &Host, peer: &str, source: &str) -> Result<PeerKey, ApiError> {
    if let Some(pin) = pinned(host, peer).await? {
        return Ok(PeerKey {
            key: PublicKey::from_encoded(&pin.key)?,
            pinned: Some(pin),
            named: false,
            page: None,
        });
    }
    let named = host.peers.current().names(peer);
    let page = if named {
        fetch_page(host, peer).await?
    } else if let Some(remembered) = host.first_contact.remembered(peer) {
        remembered?
    } else {
        let fetched = {
            let _fetching = host.first_contact.start_fetch(source)?;
            fetch_page(host, peer).await
        };
        if fetched.is_err() {
            host.first_contact.fetch_failed(source);
        }
        host.first_contact.remember(peer, fetched.as_ref().ok());
        fetched?
    };
    Ok(PeerKey {
        key: page.key().clone(),
        pinned: None,
        named,
        page: Some(page),
    })
}

/// Pins a key a delivery's proof has just verified against, and the ID beside it, unless it's pinned
/// already. New hosts are limited to so many an hour, and one source or one family of names to a share
/// of those, counted under a lock with the pin itself, so first deliveries racing each other can't each
/// see room for one more. Two racing with different keys or IDs both end up with the one stored, and
/// the other is told to come back. With no proxy to say where calls come from, every call has the same
/// source, so sources aren't told apart.
pub async fn pin(host: &Host, peer: &str, key: &PeerKey, source: &str) -> Result<(), ApiError> {
    let Some(page) = &key.page else {
        return Ok(());
    };
    let ours = Pin {
        key: page.key().encoded(),
        identity: page.identity_text(),
    };
    let mut transaction = database::begin(&host.db).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('pinning a new host'))")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM new_hosts_met WHERE met_at <= now() - interval '1 hour'")
        .execute(&mut *transaction)
        .await?;
    let limit = i64::from(host.limits.now().new_hosts_per_hour);
    let family = family_of(peer);
    let room: bool = sqlx::query_scalar(
        "SELECT $1 OR (
             (SELECT count(*) FROM peer_keys WHERE pinned_at > now() - interval '1 hour') < $2
             AND (SELECT count(*) FROM new_hosts_met WHERE family = $4) < $3
             AND ($5 = '' OR (SELECT count(*) FROM new_hosts_met WHERE source = $5) < $3)
         )",
    )
    .bind(key.named)
    .bind(limit)
    .bind((limit / NEW_HOST_SHARES).max(1))
    .bind(&family)
    .bind(source)
    .fetch_one(&mut *transaction)
    .await?;
    if !room {
        if let Some(count) = AT_PIN_LIMIT.due() {
            tracing::warn!(
                count,
                "new hosts pinned this hour are at the limit, so first deliveries wait"
            );
        }
        return Err(ApiError::TooMany(
            "this host has met all the new hosts it can for now",
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO peer_keys (domain, key, identity) VALUES ($1, $2, $3)
         ON CONFLICT (domain) DO NOTHING",
    )
    .bind(peer)
    .bind(&ours.key)
    .bind(&ours.identity)
    .execute(&mut *transaction)
    .await?;
    if inserted.rows_affected() > 0 && !key.named {
        sqlx::query(
            "INSERT INTO new_hosts_met (domain, source, family) VALUES ($1, $2, $3)
             ON CONFLICT (domain) DO NOTHING",
        )
        .bind(peer)
        .bind(source)
        .bind(&family)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    if inserted.rows_affected() > 0 {
        // What it publishes was just read, so the next look is an hour off.
        host.known_peers.just_looked(peer);
        tracing::info!(peer, key = %ours.key, with_id = !ours.identity.is_empty(), "pinned a peer's host key");
        return Ok(());
    }
    let Some(stored) = pinned(host, peer).await? else {
        return Err(ApiError::Unavailable);
    };
    if stored.key != ours.key {
        return Err(ApiError::Unavailable);
    }
    // The same key, and either the same ID, which a later look moves on if this copy is newer, or an
    // ID where the pin had none yet.
    if stored.identity == ours.identity || same_id(&stored.identity, &ours.identity) {
        return Ok(());
    }
    if stored.identity.is_empty() && take(host, peer, &stored, page).await?.is_some() {
        return Ok(());
    }
    Err(ApiError::Unavailable)
}

fn same_id(one: &str, other: &str) -> bool {
    !one.is_empty()
        && !other.is_empty()
        && Identity::claimed_id(one).ok() == Identity::claimed_id(other).ok()
}

async fn pinned(host: &Host, peer: &str) -> Result<Option<Pin>, sqlx::Error> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT key, identity FROM peer_keys WHERE domain = $1")
            .bind(peer)
            .fetch_optional(&host.db)
            .await?;
    Ok(row.map(|(key, identity)| Pin { key, identity }))
}

/// After a delivery's proof failed under a pinned key: what the peer publishes now, followed if it's a
/// valid successor of the pin, as the key to check that proof under again.
///
/// What the page says decides, not what caused the look, so forged proofs naming a host can't stop it
/// being followed. A look that finds nothing new isn't made again for a minute, so they can't make it
/// cost that host more than a call a minute either. With every look busy, this one waits its turn
/// behind this delivery, whose sender is told to come back and finds the pin moved.
pub async fn follow(host: &Arc<Host>, peer: &str, pin: &Pin) -> Result<Option<PeerKey>, ApiError> {
    if !host.known_peers.may_look(peer) {
        return Ok(None);
    }
    let Some(looking) = host.known_peers.claim(peer) else {
        return Err(ApiError::Unavailable);
    };
    // The look that held the claim until just now may have started the minute.
    if !host.known_peers.may_look(peer) {
        return Ok(None);
    }
    let Ok(turn) = host.known_peers.turns.clone().try_acquire_owned() else {
        look_in_turn(host, peer, pin, looking, Look::AfterAFailedProof);
        return Err(ApiError::Unavailable);
    };
    let page = fetch_page(host, peer).await;
    drop(turn);
    let moved = match &page {
        Ok(page) => take(host, peer, pin, page).await?,
        Err(_) => None,
    };
    if moved.is_none() {
        host.known_peers.looked(peer);
    }
    drop(looking);
    Ok(moved)
}

/// After a delivery verified under a pin, at most once an hour for each peer: a look in the background
/// at what it publishes now, taking a valid successor. So a host that recovered from a stolen key is
/// followed here though the thief's proofs still pass, and a pin from before IDs takes the peer's ID.
pub fn refresh_now_and_then(host: &Arc<Host>, peer: &str, pin: &Pin) {
    if !host.known_peers.refresh_due(peer) {
        return;
    }
    let Some(looking) = host.known_peers.claim(peer) else {
        host.known_peers.refresh_missed(peer);
        return;
    };
    look_in_turn(host, peer, pin, looking, Look::Refresh);
}

/// Why a look is made, which says whether finding nothing holds off the next failed proof's.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Look {
    AfterAFailedProof,
    Refresh,
}

/// A look in the background, once one of the places for looks comes free.
fn look_in_turn(host: &Arc<Host>, peer: &str, pin: &Pin, looking: Looking, why: Look) {
    let (host, peer, pin) = (host.clone(), peer.to_owned(), pin.clone());
    tokio::spawn(async move {
        let _looking = looking;
        let Ok(turn) = host.known_peers.turns.clone().acquire_owned().await else {
            return;
        };
        // What it waited behind may have moved the pin already.
        let held = pinned(&host, &peer).await.ok().flatten().unwrap_or(pin);
        let page = fetch_page(&host, &peer).await;
        drop(turn);
        // What a look finds is taken or left; a refresh that fails is tried again in an hour.
        let moved = match &page {
            Ok(page) => take(&host, &peer, &held, page).await.ok().flatten(),
            Err(_) => None,
        };
        if moved.is_none() && why == Look::AfterAFailedProof {
            host.known_peers.looked(&peer);
        }
    });
}

/// Moves the pin to what the page says, if the pin follows it: an ID that's a valid successor of the
/// pinned one, or for a pin with no ID, the ID its key signs for or began. A page with no ID never
/// changes a pin. Compared and set against the pin as it was read, so two racing take one.
async fn take(
    host: &Host,
    peer: &str,
    pin: &Pin,
    page: &Page,
) -> Result<Option<PeerKey>, ApiError> {
    let Page::Id(published) = page else {
        return Ok(None);
    };
    let follows = if pin.identity.is_empty() {
        PublicKey::from_encoded(&pin.key).is_ok_and(|key| published.follows_bare(&key))
    } else {
        Identity::from_encoded(&pin.identity).is_ok_and(|held| {
            let replaces = published.identity().replaces(&held);
            if replaces == Err(splint_core::Error::Forked)
                && let Some(count) = FORKED_PEER.due()
            {
                tracing::warn!(
                    %peer,
                    count,
                    "this peer publishes a copy of its ID that parts ways with the one pinned here, so \
                     it's kept as it was; only that host's own keys can make one"
                );
            }
            replaces == Ok(true)
        })
    };
    if !follows {
        return Ok(None);
    }
    let next = Pin {
        key: published.key().encoded(),
        identity: published.identity().encoded(),
    };
    let updated = sqlx::query(
        "UPDATE peer_keys SET key = $2, identity = $3
         WHERE domain = $1 AND key = $4 AND identity = $5",
    )
    .bind(peer)
    .bind(&next.key)
    .bind(&next.identity)
    .bind(&pin.key)
    .bind(&pin.identity)
    .execute(&host.db)
    .await?;
    if updated.rows_affected() == 0 {
        // Another delivery took a change first: go by what it took, if it's this one.
        return Ok(pinned(host, peer)
            .await?
            .filter(|stored| *stored == next)
            .map(|stored| PeerKey {
                key: published.key().clone(),
                pinned: Some(stored),
                named: false,
                page: None,
            }));
    }
    host.known_peers.just_looked(peer);
    if next.key == pin.key {
        tracing::info!(%peer, "this peer's host ID is pinned now, or a newer copy of it");
    } else {
        tracing::info!(%peer, old = %pin.key, new = %next.key, "followed a peer's host key change");
    }
    Ok(Some(PeerKey {
        key: published.key().clone(),
        pinned: Some(next),
        named: false,
        page: None,
    }))
}

/// Fetches what a peer publishes from its own domain, wherever this host may call it.
async fn fetch_page(host: &Host, peer: &str) -> Result<Page, ApiError> {
    let call = host
        .call(peer, PATH)
        .map_err(|_| ApiError::Forbidden("this host doesn't call that host"))?;
    let response = call
        .get()
        .send()
        .await
        .map_err(|_| ApiError::Unavailable)?
        .error_for_status()
        .map_err(|_| ApiError::Unavailable)?;
    let info = read_host_info(response).await?;
    if info.domain != peer {
        return Err(ApiError::Forbidden("peer reports a different domain"));
    }
    let key = PublicKey::from_encoded(&info.key)?;
    match (info.identity, info.identity_proof) {
        (None, None) => Ok(Page::Bare(key)),
        (Some(identity), Some(proof)) => PublishedHost::verify(peer, &key, &identity, &proof)
            .map(|published| Page::Id(Arc::new(published)))
            .map_err(|_| ApiError::Unavailable),
        _ => Err(ApiError::Unavailable),
    }
}

/// Fetches in progress, a few at once in all and fewer for one source, past which a caller is told to
/// come back.
struct Slots {
    at_once: usize,
    per_source: usize,
    state: Mutex<InFlight>,
}

#[derive(Default)]
struct InFlight {
    total: usize,
    by_source: BTreeMap<String, usize>,
}

/// A fetch in progress, which frees its place when it ends however it ends.
struct Fetching<'a> {
    slots: &'a Slots,
    source: String,
}

impl Drop for Fetching<'_> {
    fn drop(&mut self) {
        let mut state = lock(&self.slots.state);
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.by_source.get_mut(&self.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.by_source.remove(&self.source);
            }
        }
    }
}

impl Slots {
    fn new(at_once: usize, per_source: usize) -> Self {
        Self {
            at_once,
            per_source,
            state: Mutex::new(InFlight::default()),
        }
    }

    /// A place for one fetch, or the answer for a caller past the limits: busy in all, or too many
    /// from this source.
    fn start(&self, source: &str) -> Result<Fetching<'_>, ApiError> {
        let mut state = lock(&self.state);
        if state.total >= self.at_once {
            return Err(ApiError::Unavailable);
        }
        let from_source = state.by_source.get(source).copied().unwrap_or(0);
        if from_source >= self.per_source {
            return Err(ApiError::TooMany("too many first contacts at once"));
        }
        state.total = state.total.saturating_add(1);
        state
            .by_source
            .insert(source.to_owned(), from_source.saturating_add(1));
        Ok(Fetching {
            slots: self,
            source: source.to_owned(),
        })
    }
}

fn lock<T>(state: &Mutex<T>) -> MutexGuard<'_, T> {
    // Nothing here is left half done across a panic, so a poisoned lock is still whole.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What this host goes by for hosts it hasn't met: fetches in progress, and what recent ones found.
/// Each is bounded, as the names are anyone's choosing.
pub struct FirstContact {
    slots: Slots,
    doubtful_slots: Slots,
    /// Sources a fetch failed for, and when.
    failed_for: Mutex<BTreeMap<String, Instant>>,
    found: Mutex<BTreeMap<String, Found>>,
}

impl Default for FirstContact {
    fn default() -> Self {
        Self {
            slots: Slots::new(MAX_FETCHES_AT_ONCE, MAX_FETCHES_AT_ONCE_PER_SOURCE),
            doubtful_slots: Slots::new(
                MAX_DOUBTFUL_FETCHES_AT_ONCE,
                MAX_DOUBTFUL_FETCHES_AT_ONCE_PER_SOURCE,
            ),
            failed_for: Mutex::default(),
            found: Mutex::default(),
        }
    }
}

struct Found {
    at: Instant,
    page: Option<Page>,
}

impl Found {
    fn fresh(&self, now: Instant) -> bool {
        let lasts = if self.page.is_some() {
            KEY_REMEMBERED
        } else {
            FAILURE_REMEMBERED
        };
        now.saturating_duration_since(self.at) < lasts
    }

    fn id_bytes(&self) -> usize {
        match &self.page {
            Some(Page::Id(published)) => published.identity().encoded().len(),
            Some(Page::Bare(_)) | None => 0,
        }
    }
}

impl FirstContact {
    /// A place for one fetch of a host's page for this source.
    fn start_fetch(&self, source: &str) -> Result<Fetching<'_>, ApiError> {
        let doubtful = lock(&self.failed_for)
            .get(source)
            .is_some_and(|at| at.elapsed() < FAILURE_REMEMBERED);
        if doubtful {
            self.doubtful_slots.start(source)
        } else {
            self.slots.start(source)
        }
    }

    /// With no proxy to say where calls come from, every call has the same source, and one caller's
    /// failure mustn't count against the rest, so nothing is noted.
    fn fetch_failed(&self, source: &str) {
        if !source.is_empty() {
            mark(&mut lock(&self.failed_for), source, FAILURE_REMEMBERED);
        }
    }

    /// What a recent fetch found: the page, or that it failed, if it's recent enough to go by.
    fn remembered(&self, peer: &str) -> Option<Result<Page, ApiError>> {
        let found = lock(&self.found);
        let one = found.get(peer)?;
        one.fresh(Instant::now())
            .then(|| one.page.clone().ok_or(ApiError::Unavailable))
    }

    fn remember(&self, peer: &str, page: Option<&Page>) {
        let now = Instant::now();
        let mut found = lock(&self.found);
        found.remove(peer);
        let adding = Found {
            at: now,
            page: page.cloned(),
        };
        let full = |found: &BTreeMap<String, Found>| {
            found.len() >= MAX_REMEMBERED
                || found
                    .values()
                    .map(Found::id_bytes)
                    .sum::<usize>()
                    .saturating_add(adding.id_bytes())
                    > MAX_REMEMBERED_ID_BYTES
        };
        if full(&found) {
            found.retain(|_, one| one.fresh(now));
        }
        while full(&found) {
            let oldest = found
                .iter()
                .min_by_key(|(_, one)| one.at)
                .map(|(name, _)| name.clone());
            match oldest {
                Some(oldest) => found.remove(&oldest),
                None => break,
            };
        }
        found.insert(peer.to_owned(), adding);
    }
}

/// What this host goes by for hosts it has pinned: when it last looked at each for a key change, and
/// its own fetches for that, apart from first contact's.
pub struct KnownPeers {
    /// Places for looks, handed out in the order asked.
    turns: Arc<Semaphore>,
    /// Hosts with a look waiting or under way, so each is in line once.
    under_way: Arc<Mutex<BTreeSet<String>>>,
    /// Looks that found nothing new, which a failed proof doesn't repeat for a while.
    looked: Mutex<BTreeMap<String, Instant>>,
    /// Looks after a delivery went fine.
    refreshed: Mutex<BTreeMap<String, Instant>>,
}

impl Default for KnownPeers {
    fn default() -> Self {
        Self {
            turns: Arc::new(Semaphore::new(MAX_PINNED_FETCHES_AT_ONCE)),
            under_way: Arc::default(),
            looked: Mutex::default(),
            refreshed: Mutex::default(),
        }
    }
}

/// A look at one host, waiting or under way, which lets the next be asked for when it ends.
struct Looking {
    under_way: Arc<Mutex<BTreeSet<String>>>,
    peer: String,
}

impl Drop for Looking {
    fn drop(&mut self) {
        lock(&self.under_way).remove(&self.peer);
    }
}

impl KnownPeers {
    /// The one look at this host, unless one is waiting or under way. Only pinned hosts get here, and
    /// the line is bounded as the table of looks is.
    fn claim(&self, peer: &str) -> Option<Looking> {
        let mut under_way = lock(&self.under_way);
        if under_way.len() >= MAX_REMEMBERED || !under_way.insert(peer.to_owned()) {
            return None;
        }
        Some(Looking {
            under_way: self.under_way.clone(),
            peer: peer.to_owned(),
        })
    }

    fn may_look(&self, peer: &str) -> bool {
        lock(&self.looked)
            .get(peer)
            .is_none_or(|at| at.elapsed() >= LOOKED_LASTS)
    }

    fn looked(&self, peer: &str) {
        mark(&mut lock(&self.looked), peer, LOOKED_LASTS);
    }

    /// Whether it's time to look at this peer again, marking it looked at if so.
    fn refresh_due(&self, peer: &str) -> bool {
        let mut refreshed = lock(&self.refreshed);
        if refreshed
            .get(peer)
            .is_some_and(|at| at.elapsed() < REFRESH_EVERY)
        {
            return false;
        }
        mark(&mut refreshed, peer, REFRESH_EVERY);
        true
    }

    /// A page that was just read and taken, so a delivery that verifies under the pin doesn't look again
    /// for an hour.
    fn just_looked(&self, peer: &str) {
        mark(&mut lock(&self.refreshed), peer, REFRESH_EVERY);
    }

    fn refresh_missed(&self, peer: &str) {
        lock(&self.refreshed).remove(peer);
    }
}

/// Notes when a peer was looked at, keeping the table to recent looks, and to so many, oldest out.
/// Only pinned hosts are kept, which take a proof to get in, but there's no end to those in time.
fn mark(table: &mut BTreeMap<String, Instant>, peer: &str, lasts: Duration) {
    if table.len() >= MAX_REMEMBERED && !table.contains_key(peer) {
        table.retain(|_, at| at.elapsed() < lasts);
        if table.len() >= MAX_REMEMBERED {
            let oldest = table
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                table.remove(&oldest);
            }
        }
    }
    table.insert(peer.to_owned(), Instant::now());
}

/// Stops reading as soon as the answer passes the limit, because the peer decides how much it sends.
async fn read_host_info(mut response: reqwest::Response) -> Result<HostInfo, ApiError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Unavailable)? {
        if body.len() + chunk.len() > MAX_HOST_INFO_BYTES {
            return Err(ApiError::Unavailable);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ApiError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug: tarpit names, fresh each time, keep every place for a first fetch, so a real new host is
    /// told to come back for as long as the attack runs.
    #[test]
    fn whoever_fetches_hang_for_gets_only_the_doubtful_places() {
        let contact = FirstContact::default();
        let doubted = |number: usize| format!("198.51.100.{number}");
        for number in 0..=MAX_DOUBTFUL_FETCHES_AT_ONCE {
            contact.fetch_failed(&doubted(number));
        }

        let held: Vec<_> = (0..MAX_DOUBTFUL_FETCHES_AT_ONCE)
            .filter_map(|number| contact.start_fetch(&doubted(number)).ok())
            .collect();
        assert_eq!(held.len(), MAX_DOUBTFUL_FETCHES_AT_ONCE);
        assert!(
            contact
                .start_fetch(&doubted(MAX_DOUBTFUL_FETCHES_AT_ONCE))
                .is_err(),
            "a source a fetch just failed for"
        );

        let others: Vec<_> = (0..MAX_FETCHES_AT_ONCE)
            .map(|number| contact.start_fetch(&format!("203.0.113.{number}")))
            .collect();
        assert!(others.iter().all(Result::is_ok), "everyone else's places");
    }
}

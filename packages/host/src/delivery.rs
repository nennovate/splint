//! Durable delivery between hosts.
//!
//! An accepted message is committed to Postgres before the sender hears back. A worker then
//! retries until the other host accepts it. A crash can cause a resend, and the receiving
//! host ignores anything it already stored, so each message lands once.
//!
//! A peer's refusal keeps a message alive until it expires, because a peer list, a proxy or a bad
//! deploy can refuse everything or some of it for a while, and none of that is the message's fault.
//! That includes a peer calling the envelope malformed: this host has just verified it, so the peer
//! is broken or on another version, and either can be fixed. Only this host's own check ends one.
//!
//! Content stays here only while it may still be sent. Delivery, failing that check or expiry clears
//! it and keeps the row, whose ID refuses a repeat for as long as the message is valid. An expired
//! message can't pass verification, so its row can then go, after its sender has had time to ask.
//!
//! The owner's rules are read again before every attempt, so pausing an agent or blocking a contact
//! also stops what's already queued. An attempt already out can still land.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::changes::is_notice_body;
use splint_core::contact_invites::is_introduction_body;
use splint_core::host_api::{DeliveryStatus, OutboundRequest};
use splint_core::rules::{Admission, VerifiedRules};
use splint_core::{
    DeliveryFailure, DeliveryProof, DeliveryState, Identity, MessageId, PublicKey, SplintId,
    VerifiedBinding, VerifiedEnvelope, canonical_domain, claimed_message_id, claimed_sender,
    parse_address, unix_now,
};
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};
use tokio::sync::Semaphore;

use crate::admission::{self, QueuedMessage, SenderRecord};
use crate::api_error::{ADMISSION_HEADER, ApiError, QUARANTINED, REFUSAL_HEADER};
use crate::limits::Came;
use crate::log_limit::LogLimit;
use crate::peering::PeerList;
use crate::{
    Host, database, guest, host_identity, inbox, invites, note_receipts, refused, registry,
    release, requests,
};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS outbound (
        message_id TEXT PRIMARY KEY,
        sender TEXT NOT NULL,
        envelope TEXT NOT NULL,
        sender_identity TEXT NOT NULL,
        recipient_host TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_failure TEXT,
        last_attempt_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS outbound_sender ON outbound (sender, created_at);
    CREATE INDEX IF NOT EXISTS outbound_queued ON outbound (sender)
        WHERE status IN ('pending', 'peer_removed');
    ALTER TABLE outbound ADD COLUMN IF NOT EXISTS recipient TEXT NOT NULL DEFAULT '';
    DROP INDEX IF EXISTS outbound_due;
    CREATE INDEX IF NOT EXISTS outbound_due_to_peer ON outbound (recipient_host, next_attempt_at)
        WHERE status = 'pending';
    CREATE INDEX IF NOT EXISTS outbound_peer_removed ON outbound (recipient_host)
        WHERE status = 'peer_removed';
    CREATE INDEX IF NOT EXISTS outbound_expiry ON outbound (expires_at);
    CREATE INDEX IF NOT EXISTS outbound_due_at ON outbound (next_attempt_at)
        WHERE status = 'pending';
    CREATE INDEX IF NOT EXISTS outbound_unreachable ON outbound (recipient_host)
        WHERE status = 'pending' AND last_failure = 'unreachable';
    CREATE TABLE IF NOT EXISTS hosts_sent_to (
        agent TEXT NOT NULL,
        host TEXT NOT NULL,
        at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (agent, host)
    );
    CREATE INDEX IF NOT EXISTS hosts_sent_to_host ON hosts_sent_to (host);
    ALTER TABLE outbound ADD COLUMN IF NOT EXISTS receipt_of TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS outbound_one_receipt ON outbound (sender, receipt_of)
        WHERE receipt_of IS NOT NULL;
";

const DELIVER_PATH: &str = "/v0/deliver";
const WORKER_INTERVAL: Duration = Duration::from_millis(250);
const MAX_IN_FLIGHT: usize = 32;
/// Well below the total, so one hung peer can't take every slot, however long its backlog.
const MAX_IN_FLIGHT_PER_PEER: usize = 8;
/// What all hosts that aren't proven share. A host is proven by taking a delivery from this one, for as
/// long as it can still be reached, or by the operator naming it. Agents here can name any host, and
/// many that never answer would otherwise hold every slot. Provisional.
const MAX_IN_FLIGHT_UNPROVEN: usize = 8;
/// One such host's share of those, so a hung one with a backlog can't take them all and leave every
/// other first contact waiting behind it. Provisional.
const MAX_IN_FLIGHT_PER_UNPROVEN_PEER: usize = 2;
/// Hosts looked at in one pass of the worker, the longest waiting first, among proven hosts and among
/// the rest apart, so hosts that never answer can't fill the pass and leave known hosts out of it.
const MAX_HOSTS_PER_PASS: i64 = 256;
/// The hosts each agent has sent to, newest kept, which hear its retirement or its recovery.
const MAX_HOSTS_SENT_TO_PER_AGENT: i64 = 256;
/// A claimed message is retried after this long if the host dies while sending it.
const LEASE_SECS: f64 = 10.0;
const MAX_BACKOFF_SECS: f64 = 30.0;
/// A peer that answers and says no needs someone to fix something, which takes longer than a
/// restart, and retrying its whole backlog every 30 seconds for up to a month helps nobody.
const MAX_REFUSED_BACKOFF_SECS: f64 = 300.0;
/// How long a sender can still find out that a message expired.
const KEEP_AFTER_EXPIRY_SECS: i64 = 24 * 60 * 60;
/// Waiting to go out from one agent, so a hung peer can't make one agent's backlog everyone's.
const MAX_QUEUED_PER_AGENT: i64 = 128;
const MAX_QUEUED_BYTES_PER_AGENT: i64 = 8 * 1024 * 1024;
/// How much of that, in messages and bytes, can wait for one recipient host, and for one recipient. A
/// dead peer or a full inbox holds what's sent to it until it expires, and that mustn't stop the agent
/// reaching anyone else. On a single host every recipient shares its host's part, so there it's the
/// recipient's part that keeps one full inbox from stopping the rest.
const HOST_SHARE_OF_QUEUE: i64 = 2;
const RECIPIENT_SHARE_OF_QUEUE: i64 = 4;
const QUEUE_FULL: &str = "this agent has too much waiting to go out";
/// Anyone can send a delivery naming a peer, with a proof that peer never signed. Each host the operator
/// named is counted apart, and every other host shares one count, as anyone can make up names.
static REFUSED_PROOFS: LogLimit = LogLimit::new();
/// A binding or a delivery proof is a few short signed lines. Past this one isn't kept, because it
/// would count against what Signet will read of an inbox page.
const MAX_SENDER_RECORD_BYTES: usize = 4096;
/// A real answer is one short field, and a peer decides how much it sends.
const MAX_ANSWER_BYTES: usize = 4096;

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route("/v0/outbound", post(accept_outbound))
        .route("/v0/outbound/{message_id}", get(status))
        .route(DELIVER_PATH, post(receive))
}

#[derive(Serialize, Deserialize)]
struct Accepted {
    message_id: MessageId,
}

/// Takes a signed message from one of this host's agents and commits to delivering it.
async fn accept_outbound(
    State(host): State<Arc<Host>>,
    Json(request): Json<OutboundRequest>,
) -> Result<Json<Accepted>, ApiError> {
    // Judged now, so a message this host could never send isn't taken. A name that resolves somewhere
    // it mustn't go is found out as it's sent.
    host.call(&request.recipient_host, DELIVER_PATH)
        .map_err(|_| ApiError::Forbidden("this host doesn't send to that host"))?;
    let sender = claimed_sender(&request.envelope)?;
    let identity = registry::identity_of(&host, &sender)
        .await?
        .ok_or(ApiError::Forbidden("sender isn't registered here"))?;
    let envelope = VerifiedEnvelope::verify(&request.envelope, &identity, unix_now())?;
    let rules = match admission::check_may_send(&host, &envelope).await {
        Ok(rules) => rules,
        Err(error) => {
            refused::going_out(&host, envelope.sender(), &error).await;
            return Err(error);
        }
    };
    // A receipt for a note its agent was sent here counts against nothing the agent sends, and has
    // room of its own, so confirming what came in can't stop the agent writing.
    let receipt_of = note_receipts::for_note_received(&host, &envelope).await?;
    check_send_limits(
        &host,
        &envelope,
        rules.as_ref(),
        &request.recipient_host,
        receipt_of.is_some(),
    )
    .await?;
    requests::store_if_step(&host, &envelope, &identity).await?;
    admission::note_met(&host, &envelope).await?;

    let mut transaction = database::begin(&host.db).await?;
    // One agent's sends take turns from here, so sends at the same moment can't each see room for one.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(envelope.sender().as_str())
        .execute(&mut *transaction)
        .await?;
    if !registry::hold_off_retirement(&mut transaction, &identity).await? {
        return Err(ApiError::Forbidden("sender isn't registered here"));
    }
    let receipt = receipt_of.is_some();
    if !has_room_to_queue(
        &mut *transaction,
        &envelope,
        &request.recipient_host,
        receipt,
    )
    .await?
    {
        return Err(ApiError::TooMany(QUEUE_FULL));
    }
    // A second receipt for the same note is taken as a repeat of the first, which is all it says.
    sqlx::query(
        "INSERT INTO outbound (message_id, sender, envelope, sender_identity, recipient_host,
             expires_at, is_notice, recipient, receipt_of)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT DO NOTHING",
    )
    .bind(envelope.id().as_str())
    .bind(envelope.sender().as_str())
    .bind(envelope.compact())
    .bind(identity.encoded())
    .bind(&request.recipient_host)
    .bind(i64::try_from(envelope.expires_at()).unwrap_or(i64::MAX))
    .bind(is_notice_body(envelope.body()))
    .bind(envelope.recipient().as_str())
    .bind(receipt_of.as_ref().map(MessageId::as_str))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    // The list can change while a message is on its way into the queue. The worker holds what was
    // queued before it looked, and this holds one queued after, so neither waits unseen as `pending`.
    if !host.peers.current().exchanges_with(&request.recipient_host) {
        sqlx::query(
            "UPDATE outbound SET status = 'peer_removed'
             WHERE message_id = $1 AND status = 'pending'",
        )
        .bind(envelope.id().as_str())
        .execute(&host.db)
        .await?;
    }
    tracing::info!(
        message_id = %envelope.id(),
        sender = %envelope.sender(),
        recipient_host = %request.recipient_host,
        "verified the agent's signature and stored it for delivery"
    );
    Ok(Json(Accepted {
        message_id: envelope.id().clone(),
    }))
}

/// Refuses a new message from an agent at its limits. A repeat of one already taken is free, so a
/// sender retrying after a lost answer can't use up its own room. The queue is checked here so nothing
/// else is stored for a message refused, and again as it's queued, so sends at once can't pass it. A
/// receipt for a note received counts for nothing and only has to fit its own room.
async fn check_send_limits(
    host: &Host,
    envelope: &VerifiedEnvelope,
    rules: Option<&VerifiedRules>,
    recipient_host: &str,
    receipt: bool,
) -> Result<(), ApiError> {
    if receipt {
        return if has_room_to_queue(&host.db, envelope, recipient_host, true).await? {
            Ok(())
        } else {
            Err(ApiError::TooMany(QUEUE_FULL))
        };
    }
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM outbound WHERE sender = $1 AND receipt_of IS NULL
                  AND created_at > now() - interval '1 hour') AS this_hour,
             (SELECT count(*) FROM outbound WHERE sender = $1 AND receipt_of IS NULL
                  AND created_at > now() - interval '1 day') AS today,
             EXISTS (SELECT 1 FROM outbound WHERE message_id = $2 AND sender = $1) AS here,
             EXISTS (SELECT 1 FROM agents WHERE id = $1 AND open_source IS NOT NULL) AS came_open,
             (SELECT owner_identity FROM agents WHERE id = $1) AS owner_identity",
    )
    .bind(envelope.sender().as_str())
    .bind(envelope.id().as_str())
    .fetch_one(&host.db)
    .await?;
    if row.try_get::<bool, _>("here")? {
        return Ok(());
    }
    // A notice tells contacts about a replaced key or owner, so a thief holding the owner's key can't
    // stop one by signing a limit of nothing. Only this host's own numbers hold those back.
    let signed = rules
        .filter(|_| !is_notice_body(envelope.body()))
        .map(VerifiedRules::limits);
    let unconfirmed = row
        .try_get::<Option<String>, _>("owner_identity")?
        .and_then(|owner| Identity::from_encoded(&owner).ok())
        .is_some_and(|owner| owner.is_unconfirmed_owner());
    let came = if unconfirmed {
        Came::Unconfirmed
    } else if row.try_get::<bool, _>("came_open")? {
        Came::Open
    } else {
        Came::WithCode
    };
    let (per_hour, per_day) = host.limits.now().sends_for(came, signed);
    if row.try_get::<i64, _>("this_hour")? >= i64::from(per_hour)
        || row.try_get::<i64, _>("today")? >= i64::from(per_day)
    {
        return Err(ApiError::TooMany("this agent has sent all it can for now"));
    }
    if !has_room_to_queue(&host.db, envelope, recipient_host, false).await? {
        return Err(ApiError::TooMany(QUEUE_FULL));
    }
    Ok(())
}

/// Whether the sender has room to queue this message: in all, and in the share of that one recipient
/// host and one recipient can each hold. A repeat of one already taken always has room. Receipts for
/// notes received have the same room again, apart, so a peer that never takes them fills only theirs.
async fn has_room_to_queue<'e>(
    db: impl sqlx::PgExecutor<'e>,
    envelope: &VerifiedEnvelope,
    recipient_host: &str,
    receipt: bool,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT EXISTS (SELECT 1 FROM outbound WHERE message_id = $2 AND sender = $1) AS here,
             count(*) AS messages,
             coalesce(sum(octet_length(envelope)), 0)::bigint AS bytes,
             count(*) FILTER (WHERE recipient_host = $3) AS to_host,
             coalesce(sum(octet_length(envelope)) FILTER (WHERE recipient_host = $3), 0)::bigint
                 AS to_host_bytes,
             count(*) FILTER (WHERE recipient = $4) AS to_recipient,
             coalesce(sum(octet_length(envelope)) FILTER (WHERE recipient = $4), 0)::bigint
                 AS to_recipient_bytes
         FROM outbound WHERE sender = $1 AND status IN ('pending', 'peer_removed')
             AND (receipt_of IS NOT NULL) = $5",
    )
    .bind(envelope.sender().as_str())
    .bind(envelope.id().as_str())
    .bind(recipient_host)
    .bind(envelope.recipient().as_str())
    .bind(receipt)
    .fetch_one(db)
    .await?;
    let size = i64::try_from(envelope.compact().len()).unwrap_or(i64::MAX);
    let fits = |messages: &str, bytes: &str, share: i64| -> Result<bool, sqlx::Error> {
        let messages = row.try_get::<i64, _>(messages)?;
        let bytes = row.try_get::<i64, _>(bytes)?.saturating_add(size);
        Ok(messages < MAX_QUEUED_PER_AGENT / share && bytes <= MAX_QUEUED_BYTES_PER_AGENT / share)
    };
    let here = row.try_get::<bool, _>("here")?;
    let to_host = fits("to_host", "to_host_bytes", HOST_SHARE_OF_QUEUE)?;
    let to_recipient = fits(
        "to_recipient",
        "to_recipient_bytes",
        RECIPIENT_SHARE_OF_QUEUE,
    )?;
    Ok(here || (fits("messages", "bytes", 1)? && to_host && to_recipient))
}

/// Ends everything this agent still has waiting, as its retirement takes effect. An attempt already
/// out can still land, because a call to a peer can't be recalled. A retired agent can't ask about
/// its messages, so `retired` is only ever read here. A notice goes on: it's what tells a contact
/// about this, and it can say nothing but a history that checks out.
pub async fn end_queued_from(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
) -> Result<(), sqlx::Error> {
    guest::end_links_of(transaction, agent).await?;
    sqlx::query(
        "UPDATE outbound SET status = 'retired', envelope = '', sender_identity = ''
         WHERE sender = $1 AND status IN ('pending', 'peer_removed') AND NOT is_notice",
    )
    .bind(agent.as_str())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Lets a sender find out what happened to its message, including if it was refused. This is the
/// host's own report for now. Signed receipts come with managed requests.
async fn status(
    State(host): State<Arc<Host>>,
    Path(message_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DeliveryStatus>, ApiError> {
    let path = format!("/v0/outbound/{message_id}");
    let agent = inbox::authenticated_agent(&host, &headers, "GET", &path, b"").await?;
    let row = sqlx::query(
        "SELECT status, attempts, last_failure FROM outbound WHERE message_id = $1 AND sender = $2",
    )
    .bind(&message_id)
    .bind(agent.as_str())
    .fetch_optional(&host.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(DeliveryStatus {
        status: DeliveryState::from_word(row.try_get("status")?).ok_or(ApiError::Unavailable)?,
        attempts: row.try_get("attempts")?,
        last_failure: row
            .try_get::<Option<String>, _>("last_failure")?
            .as_deref()
            .and_then(DeliveryFailure::from_word),
    }))
}

#[derive(Serialize, Deserialize)]
struct Delivery {
    envelope: String,
    sender_identity: String,
    from_host: String,
    proof: String,
    /// What the sender's owner signed, so an owner can see who a stranger says they are.
    #[serde(default)]
    sender_owner_identity: String,
    #[serde(default)]
    sender_binding: String,
}

impl Delivery {
    /// The owner's signed word for who this sender is, on the host that relayed it. A sending host
    /// can leave it out or get it wrong, which only leaves an owner without an address to reply to.
    fn sender_record(&self, sender: &Identity) -> SenderRecord {
        let checks_out = || -> Option<()> {
            if self.sender_binding.len() > MAX_SENDER_RECORD_BYTES {
                return None;
            }
            let owner = Identity::from_encoded(&self.sender_owner_identity).ok()?;
            let binding = VerifiedBinding::verify(&self.sender_binding, &owner, sender).ok()?;
            let (_, domain) = parse_address(binding.address()).ok()?;
            (domain == self.from_host).then_some(())
        };
        let proof_fits = self.proof.len() <= MAX_SENDER_RECORD_BYTES;
        let relay_proof = if proof_fits {
            self.proof.clone()
        } else {
            String::new()
        };
        let (owner_identity, binding) = match checks_out() {
            Some(()) => (
                self.sender_owner_identity.clone(),
                self.sender_binding.clone(),
            ),
            None => (String::new(), String::new()),
        };
        SenderRecord {
            owner_identity,
            binding,
            relayed_by: self.from_host.clone(),
            relay_proof,
        }
    }
}

/// A delivery from a peer, once that peer's key is known. The proof goes first: it's one signature,
/// and only that peer can make one, so a call from anyone else gets no further.
fn checked(
    delivery: &Delivery,
    message: &MessageId,
    peer_key: &PublicKey,
    named: bool,
    to_host: &str,
    now: u64,
) -> Result<(Identity, VerifiedEnvelope), ApiError> {
    DeliveryProof::verify(
        &delivery.proof,
        peer_key,
        message,
        &delivery.from_host,
        to_host,
        now,
    )
    .inspect_err(|_| {
        // Noise from anyone, or a peer that changed its key, which is followed if it publishes a
        // valid successor of its pinned ID, and otherwise needs a `repin` line in the peers file. Each named peer is counted apart, and only the operator names one, so noise
        // naming one can't hide another. Hosts nobody named share one count, which can't grow.
        let counted_as = if named {
            delivery.from_host.as_str()
        } else {
            ""
        };
        if let Some(count) = REFUSED_PROOFS.due_for(counted_as) {
            tracing::warn!(
                peer = %delivery.from_host,
                count,
                "deliveries whose proof doesn't match this peer's pinned key, since the last line"
            );
        }
    })?;
    let identity =
        Identity::from_encoded(&delivery.sender_identity).map_err(ApiError::malformed)?;
    let envelope = VerifiedEnvelope::verify(&delivery.envelope, &identity, now)
        .map_err(ApiError::malformed)?;
    if envelope.id() != message {
        return Err(ApiError::malformed(splint_core::Error::ProofMismatch));
    }
    Ok((identity, envelope))
}

/// Takes a message from another host. Both the agent's and the sending host's signatures have
/// to verify before anything is stored.
///
/// The sending host's proof goes first: it's one signature, and it names the message by a hash anyone
/// can work out. So a call from anyone but that host costs that, and never the sender's identity, the
/// envelope or a lookup of the recipient. Naming a host proves nothing, as anyone can name any host,
/// this one included. A host met for the first time has its key pinned only once its proof checks out.
async fn receive(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    Json(delivery): Json<Delivery>,
) -> Result<Response, ApiError> {
    let from_host = delivery.from_host.as_str();
    if canonical_domain(from_host).ok().as_deref() != Some(from_host) {
        return Err(ApiError::BadRequest("the sending host isn't a domain"));
    }
    let list = host.peers.current();
    if !list.exchanges_with(from_host) {
        return Err(ApiError::NotAPeer);
    }
    let now = unix_now();
    let message = claimed_message_id(&delivery.envelope).map_err(ApiError::malformed)?;
    let source = registry::source_of(&headers);
    let mut peer_key = host_identity::key_for_delivery(&host, from_host, &source).await?;
    let named = list.names(from_host);
    let check = |key: &PublicKey| checked(&delivery, &message, key, named, &host.domain, now);
    let (identity, envelope) = match check(peer_key.key()) {
        // A proof that doesn't verify under a pinned key may be the peer's new key: what it
        // publishes now is followed if it's a valid successor, and this proof checked under that.
        Err(ApiError::Rejected(splint_core::Error::BadSignature)) => {
            let followed = match peer_key.pin() {
                Some(pin) => host_identity::follow(&host, from_host, pin).await?,
                None => None,
            };
            let Some(followed) = followed else {
                return Err(ApiError::Rejected(splint_core::Error::BadSignature));
            };
            peer_key = followed;
            check(peer_key.key())?
        }
        checked => {
            let checked = checked?;
            if let Some(pin) = peer_key.pin() {
                host_identity::refresh_now_and_then(&host, from_host, pin);
            }
            checked
        }
    };
    if registry::identity_of(&host, envelope.recipient())
        .await?
        .is_none()
    {
        return Err(ApiError::NotFound);
    }
    // Only for a delivery to someone here, so one to nobody spends none of the hour's new hosts.
    host_identity::pin(&host, from_host, &peer_key, &source).await?;

    let answer = Json(Accepted {
        message_id: envelope.id().clone(),
    });
    let record = delivery.sender_record(&identity);
    // Never the inbox or quarantine: an introduction waits in its own box, if there's room.
    if is_introduction_body(envelope.body()) {
        invites::take(&host, &envelope, &identity, &record).await?;
        return Ok(([(ADMISSION_HEADER, QUARANTINED)], answer).into_response());
    }
    let arrival = admission::admit(&host, &envelope, &identity, &record).await?;
    if matches!(arrival.admission, Admission::Deliver | Admission::Wait) {
        inbox::check_room(&host.db, &envelope, arrival.by_reach).await?;
        requests::store_if_step(&host, &envelope, &identity).await?;
        inbox::store_if_room(&host, &envelope, &identity, &record, arrival.by_reach).await?;
    }
    match arrival.admission {
        Admission::Deliver => {
            tracing::info!(
                message_id = %envelope.id(),
                from_host = %delivery.from_host,
                "verified the agent's and host's signatures and stored it in the inbox"
            );
            return Ok(answer.into_response());
        }
        Admission::Wait => {
            tracing::info!(message_id = %envelope.id(), "kept until the rules count again");
        }
        Admission::Quarantine if admission::hold(&host, &envelope, &identity, &record).await? => {
            tracing::info!(message_id = %envelope.id(), "held in quarantine for the owner");
        }
        Admission::Quarantine | Admission::Drop => {
            tracing::info!(message_id = %envelope.id(), "dropped by the owner's rules");
            refused::coming_in(&host, envelope.recipient(), envelope.sender()).await;
        }
    }
    Ok(([(ADMISSION_HEADER, QUARANTINED)], answer).into_response())
}

/// Limits sends in progress, so a hung peer can only hold up its own messages, and hosts that have never
/// taken one can only hold up each other's.
struct Slots {
    total: Arc<Semaphore>,
    unproven: Arc<Semaphore>,
    /// Only hosts with a send in progress, so the hosts agents name can't grow it.
    per_peer: HashMap<String, Arc<Semaphore>>,
}

impl Slots {
    fn new() -> Self {
        Self {
            total: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            unproven: Arc::new(Semaphore::new(MAX_IN_FLIGHT_UNPROVEN)),
            per_peer: HashMap::new(),
        }
    }

    fn for_peer(&mut self, peer: &str) -> Arc<Semaphore> {
        self.per_peer
            .entry(peer.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_IN_FLIGHT_PER_PEER)))
            .clone()
    }

    fn forget_idle(&mut self) {
        self.per_peer
            .retain(|_, slots| slots.available_permits() < MAX_IN_FLIGHT_PER_PEER);
    }
}

pub async fn run_worker(host: Arc<Host>) {
    let mut slots = Slots::new();
    let mut applied: Option<Arc<PeerList>> = None;
    loop {
        // One list for the whole pass. A message already claimed when the list changes is still sent.
        let list = host.peers.current();
        if !applied
            .as_ref()
            .is_some_and(|applied| Arc::ptr_eq(applied, &list))
        {
            match apply_peer_list(&host, &list).await {
                Ok(()) => applied = Some(list.clone()),
                Err(error) => tracing::warn!(%error, "couldn't apply the peer list"),
            }
        }
        if let Err(error) = claim_and_send(&host, &list, &mut slots).await {
            tracing::warn!(%error, "delivery pass failed");
        }
        tokio::time::sleep(WORKER_INTERVAL).await;
    }
}

pub async fn run_cleanup(host: Arc<Host>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        if let Err(error) = clean_up(&host).await {
            tracing::warn!(%error, "outbound cleanup failed");
        }
    }
}

/// Ends what ran out of time, including messages held for a removed peer, which the worker doesn't
/// touch and which can never go out now.
async fn clean_up(host: &Host) -> Result<(), sqlx::Error> {
    let now = host.clock.now_for_sql().await;
    sqlx::query(
        "UPDATE outbound SET status = 'expired', envelope = '', sender_identity = ''
         WHERE status IN ('pending', 'peer_removed') AND expires_at <= $1",
    )
    .bind(now)
    .execute(&host.db)
    .await?;
    sqlx::query("DELETE FROM outbound WHERE expires_at <= $1")
        .bind(now.saturating_sub(KEEP_AFTER_EXPIRY_SECS))
        .execute(&host.db)
        .await?;
    Ok(())
}

struct Claimed {
    message_id: String,
    sender: String,
    envelope: String,
    sender_identity: String,
    recipient_host: String,
    attempts: i32,
    last_failure: Option<String>,
}

impl Claimed {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            message_id: row.try_get("message_id")?,
            sender: row.try_get("sender")?,
            envelope: row.try_get("envelope")?,
            sender_identity: row.try_get("sender_identity")?,
            recipient_host: row.try_get("recipient_host")?,
            attempts: row.try_get("attempts")?,
            last_failure: row.try_get("last_failure")?,
        })
    }
}

/// An operator who removes a peer stops its queued messages here, and they go again if the peer comes
/// back. It runs at start and each time the list changes, not every pass, as it reads every row
/// waiting. It asks the list about each host that has something waiting, so whatever the list's rule
/// is, this follows it. Nothing is claimed for a host off the list either way. The cleanup job ends
/// any that expire.
async fn apply_peer_list(host: &Host, list: &PeerList) -> Result<(), sqlx::Error> {
    let waiting: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT recipient_host FROM outbound WHERE status IN ('pending', 'peer_removed')",
    )
    .fetch_all(&host.db)
    .await?;
    let (allowed, refused): (Vec<String>, Vec<String>) = waiting
        .into_iter()
        .partition(|peer| list.exchanges_with(peer));
    sqlx::query(
        "UPDATE outbound SET status = 'peer_removed'
         WHERE status = 'pending' AND recipient_host = ANY($1)",
    )
    .bind(&refused)
    .execute(&host.db)
    .await?;
    sqlx::query(
        "UPDATE outbound SET status = 'pending', next_attempt_at = now()
         WHERE status = 'peer_removed' AND recipient_host = ANY($1)",
    )
    .bind(&allowed)
    .execute(&host.db)
    .await?;
    Ok(())
}

/// Claims due messages host by host, by pushing their next attempt into the future, then sends each
/// one on its own task. No database lock is held while calling a host, and if this host dies the claim
/// simply runs out and the message is sent again. Which hosts have something due comes from the queue
/// itself, the longest waiting first, then each is claimed by `outbound_due_to_peer`, one host at a
/// time, so a dead host's backlog doesn't slow finding what's due for the others.
async fn claim_and_send(
    host: &Arc<Host>,
    list: &PeerList,
    slots: &mut Slots,
) -> Result<(), sqlx::Error> {
    slots.forget_idle();
    let named: Vec<&str> = list.named().chain([host.domain.as_str()]).collect();
    let proven = due_hosts(host, &named, true).await?;
    // With no place to send them from, there's no use asking which they are.
    let others = if slots.unproven.available_permits() > 0 {
        due_hosts(host, &named, false).await?
    } else {
        Vec::new()
    };
    let due = proven
        .into_iter()
        .map(|peer| (peer, true))
        .chain(others.into_iter().map(|peer| (peer, false)));

    for (peer, proven) in due {
        // Held already when the list refused it. This is for one taken as the list changed.
        if !list.exchanges_with(&peer) {
            continue;
        }
        let unproven = (!proven).then(|| slots.unproven.clone());
        let peer_slots = slots.for_peer(&peer);
        let in_flight = MAX_IN_FLIGHT_PER_PEER.saturating_sub(peer_slots.available_permits());
        let free = slots
            .total
            .available_permits()
            .min(peer_slots.available_permits())
            .min(unproven.as_ref().map_or(usize::MAX, |unproven| {
                unproven
                    .available_permits()
                    .min(MAX_IN_FLIGHT_PER_UNPROVEN_PEER.saturating_sub(in_flight))
            }));
        if free == 0 {
            continue;
        }
        let rows = sqlx::query(
            "UPDATE outbound
             SET next_attempt_at = now() + make_interval(secs => $1), attempts = attempts + 1
             WHERE message_id IN (
                 SELECT message_id FROM outbound
                 WHERE status = 'pending' AND next_attempt_at <= now() AND recipient_host = $3
                 ORDER BY next_attempt_at
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING message_id, sender, envelope, sender_identity, recipient_host, attempts,
                 last_failure",
        )
        .bind(LEASE_SECS)
        .bind(i64::try_from(free).unwrap_or(0))
        .bind(&peer)
        .fetch_all(&host.db)
        .await?;

        for row in &rows {
            let claimed = Claimed::from_row(row)?;
            let (Ok(total_permit), Ok(peer_permit)) = (
                slots.total.clone().acquire_owned().await,
                peer_slots.clone().acquire_owned().await,
            ) else {
                return Ok(());
            };
            let unproven_permit = match &unproven {
                Some(unproven) => match unproven.clone().acquire_owned().await {
                    Ok(permit) => Some(permit),
                    Err(_) => return Ok(()),
                },
                None => None,
            };
            let host = host.clone();
            tokio::spawn(async move {
                let outcome = attempt(&host, &claimed).await;
                if let Err(error) = record(&host, &claimed, outcome).await {
                    tracing::warn!(%error, "couldn't record a delivery attempt");
                }
                drop((total_permit, peer_permit, unproven_permit));
            });
        }
    }
    Ok(())
}

/// The hosts with something due, the longest waiting first, either those that are proven or the rest.
/// A host that took a delivery once and can't be reached now isn't proven until it takes another, so
/// a few that answer once and then hang can't hold every slot.
async fn due_hosts(host: &Host, named: &[&str], proven: bool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "WITH due AS (
             SELECT recipient_host, min(next_attempt_at) AS since FROM outbound
             WHERE status = 'pending' AND next_attempt_at <= now()
             GROUP BY recipient_host
         )
         SELECT due.recipient_host FROM due
         WHERE (due.recipient_host = ANY($2) OR (
             EXISTS (SELECT 1 FROM hosts_sent_to WHERE host = due.recipient_host)
             AND NOT EXISTS (
                 SELECT 1 FROM outbound AS failed
                 WHERE failed.recipient_host = due.recipient_host
                     AND failed.status = 'pending' AND failed.last_failure = 'unreachable'
             )
         )) = $3
         ORDER BY due.since LIMIT $1",
    )
    .bind(MAX_HOSTS_PER_PASS)
    .bind(named)
    .bind(proven)
    .fetch_all(&host.db)
    .await
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Outcome {
    Delivered,
    /// The other host took it and won't say more, because held and dropped must look the same.
    Quarantined,
    Rejected,
    Expired,
    /// The owner's rules no longer let it go to that recipient, so it never left.
    Withdrawn,
    TryAgain(DeliveryFailure),
}

impl Outcome {
    fn status(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Withdrawn => "withdrawn",
            Self::TryAgain(_) => "pending",
        }
    }
}

/// What a peer's answer means for this message. Every refusal keeps it alive, because each of them
/// can be a mistake on the peer's side that gets fixed. That includes an unknown recipient: this
/// address came from that host's own answer, so if it now says otherwise, it may have lost its
/// data. And a host that doesn't take deliveries from this one: its operator can name this host.
fn classify(status: StatusCode, refusal: Option<DeliveryFailure>) -> Outcome {
    let failure = match (status, refusal) {
        (status, _) if status.is_success() => return Outcome::Delivered,
        (StatusCode::BAD_REQUEST, Some(DeliveryFailure::Malformed)) => DeliveryFailure::Malformed,
        (StatusCode::FORBIDDEN, Some(DeliveryFailure::NotAPeer)) => DeliveryFailure::NotAPeer,
        (status, _) => match status {
            StatusCode::NOT_FOUND => DeliveryFailure::RecipientNotFound,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS => {
                DeliveryFailure::PeerBusy
            }
            status if status.is_server_error() => DeliveryFailure::PeerError,
            _ => DeliveryFailure::PeerRefused,
        },
    };
    Outcome::TryAgain(failure)
}

fn backoff_secs(attempts: i32, failure: DeliveryFailure) -> f64 {
    let cap = match failure {
        DeliveryFailure::PeerRefused
        | DeliveryFailure::NotAPeer
        | DeliveryFailure::RecipientNotFound
        | DeliveryFailure::Malformed
        | DeliveryFailure::OtherProtocol => MAX_REFUSED_BACKOFF_SECS,
        DeliveryFailure::Unreachable
        | DeliveryFailure::PeerError
        | DeliveryFailure::PeerBusy
        | DeliveryFailure::LocalError
        | DeliveryFailure::StoppedByRules => MAX_BACKOFF_SECS,
    };
    2_f64.powi(attempts.clamp(0, 16)).min(cap)
}

async fn record(host: &Host, claimed: &Claimed, outcome: Outcome) -> Result<(), sqlx::Error> {
    let failure = match outcome {
        Outcome::Delivered | Outcome::Quarantined | Outcome::Withdrawn => None,
        Outcome::Rejected => Some(DeliveryFailure::Malformed.as_str()),
        Outcome::Expired => claimed.last_failure.as_deref(),
        Outcome::TryAgain(failure) => Some(failure.as_str()),
    };
    tracing::info!(
        message_id = %claimed.message_id,
        status = outcome.status(),
        attempts = claimed.attempts,
        failure = failure.unwrap_or("none"),
        "delivery attempt finished"
    );
    // A message that has already ended while this attempt was out, by expiring, stays ended.
    let done = match outcome {
        Outcome::TryAgain(failure) => sqlx::query(
            "UPDATE outbound
             SET last_failure = $2, last_attempt_at = now(),
                 next_attempt_at = now() + make_interval(secs => $3)
             WHERE message_id = $1 AND status = 'pending'",
        )
        .bind(&claimed.message_id)
        .bind(failure.as_str())
        .bind(backoff_secs(claimed.attempts, failure)),
        Outcome::Delivered
        | Outcome::Quarantined
        | Outcome::Rejected
        | Outcome::Expired
        | Outcome::Withdrawn => sqlx::query(
            "UPDATE outbound
             SET status = $3, last_failure = $2, last_attempt_at = now(),
                 envelope = '', sender_identity = ''
             WHERE message_id = $1 AND status = 'pending'",
        )
        .bind(&claimed.message_id)
        .bind(failure)
        .bind(outcome.status()),
    };
    done.execute(&host.db).await?;
    if matches!(outcome, Outcome::Delivered | Outcome::Quarantined)
        && claimed.recipient_host != host.domain
    {
        note_sent_to(host, &claimed.sender, &claimed.recipient_host).await?;
    }
    if outcome == Outcome::Delivered {
        registry::open_signup::note_delivered(host, &claimed.message_id).await?;
    }
    Ok(())
}

/// Notes that this host took a delivery from this agent, which makes it a host to tell if the agent is
/// retired or recovered, and one that has shown it answers. Each agent keeps its newest hosts only.
async fn note_sent_to(host: &Host, agent: &str, to: &str) -> Result<(), sqlx::Error> {
    let new: Option<bool> = sqlx::query_scalar(
        "INSERT INTO hosts_sent_to (agent, host) VALUES ($1, $2)
         ON CONFLICT (agent, host) DO UPDATE SET at = now()
             WHERE hosts_sent_to.at < now() - interval '1 hour'
         RETURNING xmax = 0",
    )
    .bind(agent)
    .bind(to)
    .fetch_optional(&host.db)
    .await?;
    if new == Some(true) {
        sqlx::query(
            "DELETE FROM hosts_sent_to WHERE agent = $1 AND host NOT IN (
                 SELECT host FROM hosts_sent_to WHERE agent = $1 ORDER BY at DESC LIMIT $2)",
        )
        .bind(agent)
        .bind(MAX_HOSTS_SENT_TO_PER_AGENT)
        .execute(&host.db)
        .await?;
    }
    Ok(())
}

/// The hosts these agents have sent to, which hold their keys as a contact's.
pub async fn hosts_sent_to(
    transaction: &mut Transaction<'_, Postgres>,
    agents: &[&str],
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT DISTINCT host FROM hosts_sent_to WHERE agent = ANY($1)")
        .bind(agents)
        .fetch_all(&mut **transaction)
        .await
}

async fn attempt(host: &Host, claimed: &Claimed) -> Outcome {
    let now = unix_now();
    let Ok(identity) = Identity::from_encoded(&claimed.sender_identity) else {
        return Outcome::Rejected;
    };
    let envelope = match VerifiedEnvelope::verify(&claimed.envelope, &identity, now) {
        Ok(envelope) => envelope,
        // Ending a message clears it for good, so a clock that may be wrong can't be the only word.
        Err(splint_core::Error::Expired) => {
            let measured = host.clock.now().await;
            return match VerifiedEnvelope::verify(&claimed.envelope, &identity, measured) {
                Err(splint_core::Error::Expired) => Outcome::Expired,
                _ => Outcome::TryAgain(DeliveryFailure::LocalError),
            };
        }
        Err(splint_core::Error::FromTheFuture) => {
            return Outcome::TryAgain(DeliveryFailure::LocalError);
        }
        Err(_) => return Outcome::Rejected,
    };
    match admission::queued_message(host, &envelope).await {
        Ok(QueuedMessage::Send) => {}
        Ok(QueuedMessage::Hold) => return Outcome::TryAgain(DeliveryFailure::StoppedByRules),
        Ok(QueuedMessage::Withdraw) => return Outcome::Withdrawn,
        Err(_) => return Outcome::TryAgain(DeliveryFailure::LocalError),
    }
    let Ok(proof) = DeliveryProof::sign(
        host.own.now().key(),
        envelope.id(),
        &host.domain,
        &claimed.recipient_host,
        now,
    ) else {
        return Outcome::TryAgain(DeliveryFailure::LocalError);
    };
    let Ok(record) = registry::record_of(host, envelope.sender()).await else {
        return Outcome::TryAgain(DeliveryFailure::LocalError);
    };
    let delivery = Delivery {
        envelope: claimed.envelope.clone(),
        sender_identity: claimed.sender_identity.clone(),
        from_host: host.domain.clone(),
        proof,
        sender_owner_identity: record.owner_identity,
        sender_binding: record.binding,
    };
    // Refused only for a host queued before this host's rules on where it calls, which can never go.
    let Ok(call) = host.call(&claimed.recipient_host, DELIVER_PATH) else {
        return Outcome::TryAgain(DeliveryFailure::Unreachable);
    };
    let response = call.post().json(&delivery).send().await;
    match response {
        Ok(response) => {
            let refusal = response
                .headers()
                .get(REFUSAL_HEADER)
                .and_then(|word| word.to_str().ok())
                .and_then(DeliveryFailure::from_word);
            let outcome = classify(response.status(), refusal);
            if outcome != Outcome::Delivered {
                if let Some(other) = release::says_other_protocol(response.headers()) {
                    tracing::warn!(peer = %claimed.recipient_host, why = %other, "peer speaks another protocol");
                    return Outcome::TryAgain(DeliveryFailure::OtherProtocol);
                }
                return outcome;
            }
            let admission = response.headers().get(ADMISSION_HEADER);
            let quarantined = admission.is_some_and(|word| word == QUARANTINED);
            if !says_it_took(response, envelope.id()).await {
                return Outcome::TryAgain(DeliveryFailure::PeerError);
            }
            if quarantined {
                Outcome::Quarantined
            } else {
                Outcome::Delivered
            }
        }
        Err(_) => Outcome::TryAgain(DeliveryFailure::Unreachable),
    }
}

/// Whether a success names this message. Marking a message delivered erases the only copy, so a parked
/// domain or a misrouted proxy answering 200 mustn't count. A hostile peer can still say this, and only
/// signed receipts can show more. Stops reading past the limit, as the peer decides how much it sends.
async fn says_it_took(mut response: reqwest::Response, message_id: &MessageId) -> bool {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_ANSWER_BYTES => {
                body.extend_from_slice(&chunk);
            }
            Ok(Some(_)) | Err(_) => return false,
            Ok(None) => return names_message(&body, message_id),
        }
    }
}

fn names_message(answer: &[u8], message_id: &MessageId) -> bool {
    serde_json::from_slice::<Accepted>(answer).is_ok_and(|named| named.message_id == *message_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_limit::logged;
    use splint_core::{RecoveryRule, SealingKey, SigningKey, sign_envelope};

    /// The sending host's proof is checked before the sender's identity or the envelope, so a call
    /// from anyone but a peer costs one signature. The database here is closed, and the peer's key is
    /// the first thing asked of it: the answer shows an identity that would be refused never was read.
    #[tokio::test]
    async fn a_delivery_goes_by_its_proof_before_its_identity_or_envelope() {
        let host = Arc::new(Host::with_closed_database("host.example").await.unwrap());
        let key = SigningKey::generate().unwrap();
        let sender = Identity::create(
            &key,
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        )
        .unwrap();
        let signed =
            sign_envelope(&key, &sender, sender.id(), String::new(), unix_now(), 60).unwrap();
        let delivery = Delivery {
            envelope: signed.compact,
            sender_identity: "not an identity".to_owned(),
            from_host: "host.example".to_owned(),
            proof: "not.a.proof".to_owned(),
            sender_owner_identity: String::new(),
            sender_binding: String::new(),
        };
        assert!(Identity::from_encoded(&delivery.sender_identity).is_err());
        let answer = receive(State(host), HeaderMap::new(), Json(delivery)).await;
        assert!(matches!(answer, Err(ApiError::Unavailable)));
    }

    /// A delivery from `from_host`, with its proof signed by `proof_key` and its sender's identity as
    /// given, and the ID the envelope claims.
    fn delivery(
        from_host: &str,
        proof_key: &SigningKey,
        identity: Option<&str>,
    ) -> (Delivery, MessageId) {
        let key = SigningKey::generate().unwrap();
        let sender = Identity::create(
            &key,
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        )
        .unwrap();
        let now = unix_now();
        let signed = sign_envelope(&key, &sender, sender.id(), String::new(), now, 60).unwrap();
        let message = claimed_message_id(&signed.compact).unwrap();
        let proof =
            DeliveryProof::sign(proof_key, &message, from_host, "host.example", now).unwrap();
        let delivery = Delivery {
            envelope: signed.compact,
            sender_identity: identity.map_or_else(|| sender.encoded(), str::to_owned),
            from_host: from_host.to_owned(),
            proof,
            sender_owner_identity: String::new(),
            sender_binding: String::new(),
        };
        (delivery, message)
    }

    /// Past the peer's key, the proof is still the first thing checked, so a call from anyone but
    /// that peer costs one signature, however bad the rest of it is.
    #[test]
    fn past_the_peers_key_a_delivery_goes_by_its_proof_first() {
        let peer = SigningKey::generate().unwrap();
        let pinned = peer.public_key();
        // It logs a refusal, so it listens the way the test of that does.
        let check = |delivery: &Delivery, message: &MessageId| {
            logged(|| checked(delivery, message, &pinned, true, "host.example", unix_now())).0
        };
        let anyone = SigningKey::generate().unwrap();
        let (bad_all_over, message) = delivery("peer.example", &anyone, Some("not an identity"));
        assert!(matches!(
            check(&bad_all_over, &message),
            Err(ApiError::Rejected(_))
        ));
        // From the peer, what's behind the proof is checked next.
        let (bad_identity, message) = delivery("peer.example", &peer, Some("not an identity"));
        assert!(matches!(
            check(&bad_identity, &message),
            Err(ApiError::Malformed(_))
        ));
        let (good, message) = delivery("peer.example", &peer, None);
        let (_, envelope) = check(&good, &message).ok().unwrap();
        assert_eq!(envelope.id(), &message);
        // A peer's proof for one message carries no other.
        let (other, _) = delivery("peer.example", &peer, None);
        assert!(matches!(
            check(&other, &message),
            Err(ApiError::Rejected(_))
        ));
    }

    /// Anyone can name any host. What they send naming a host the operator named counts against that
    /// host's line alone, so a real peer whose key no longer matches still shows up. Names nobody named
    /// share one line, or made-up names would each get a line, and a place in memory, for good.
    #[test]
    fn noise_naming_one_peer_leaves_room_for_another_and_made_up_names_share_a_line() {
        let pinned = SigningKey::generate().unwrap().public_key();
        let anyone = SigningKey::generate().unwrap();
        let refuse = |from_host: &str, named: bool| {
            let (refused, message) = delivery(from_host, &anyone, None);
            let answer = checked(
                &refused,
                &message,
                &pinned,
                named,
                "host.example",
                unix_now(),
            );
            assert!(matches!(answer, Err(ApiError::Rejected(_))));
        };
        let ((), log) = logged(|| {
            for from_host in ["noisy.example"; 5].into_iter().chain(["quiet.example"]) {
                refuse(from_host, true);
            }
            for number in 0..50 {
                refuse(&format!("made-up-{number}.example"), false);
            }
        });
        assert_eq!(log.matches("peer=noisy.example").count(), 1);
        assert_eq!(log.matches("peer=quiet.example").count(), 1);
        assert_eq!(log.matches("peer=made-up-").count(), 1, "{log}");
    }

    #[test]
    fn only_an_answer_naming_this_message_counts_as_taking_it() {
        let id = |text: &str| -> MessageId {
            serde_json::from_value(serde_json::json!(format!("{text}{}", "0".repeat(31)))).unwrap()
        };
        let ours = id("a");
        let answer = serde_json::to_vec(&Accepted {
            message_id: ours.clone(),
        })
        .unwrap();
        assert!(names_message(&answer, &ours));
        let another = serde_json::to_vec(&Accepted {
            message_id: id("b"),
        })
        .unwrap();
        for wrong in [
            another.as_slice(),
            b"{}",
            b"",
            b"<html>this domain is parked</html>",
            b"null",
        ] {
            assert!(!names_message(wrong, &ours));
        }
    }

    /// Bug: a proxy's or a broken peer's answer read as the envelope at fault, or as a host closed to
    /// this one, when the status says something else.
    #[test]
    fn only_a_400_can_say_malformed_and_only_a_403_not_a_peer() {
        let (malformed, not_a_peer) = (DeliveryFailure::Malformed, DeliveryFailure::NotAPeer);
        assert_eq!(
            classify(StatusCode::BAD_REQUEST, Some(malformed)),
            Outcome::TryAgain(malformed)
        );
        assert_eq!(
            classify(StatusCode::FORBIDDEN, Some(not_a_peer)),
            Outcome::TryAgain(not_a_peer)
        );
        for status in [StatusCode::FORBIDDEN, StatusCode::SERVICE_UNAVAILABLE] {
            assert_ne!(
                classify(status, Some(malformed)),
                Outcome::TryAgain(malformed)
            );
        }
        for status in [StatusCode::BAD_REQUEST, StatusCode::SERVICE_UNAVAILABLE] {
            assert_ne!(
                classify(status, Some(not_a_peer)),
                Outcome::TryAgain(not_a_peer)
            );
        }
        assert_eq!(
            classify(StatusCode::FORBIDDEN, None),
            Outcome::TryAgain(DeliveryFailure::PeerRefused)
        );
        assert_eq!(
            classify(StatusCode::OK, Some(malformed)),
            Outcome::Delivered
        );
    }

    #[test]
    fn backoff_grows_then_stays_capped_however_long_an_outage_lasts() {
        let (outage, refusal) = (DeliveryFailure::Unreachable, DeliveryFailure::PeerRefused);
        assert!((backoff_secs(1, outage) - 2.0).abs() < f64::EPSILON);
        assert!((backoff_secs(1, refusal) - 2.0).abs() < f64::EPSILON);
        for attempts in [100, 5_000, i32::MAX] {
            assert!((backoff_secs(attempts, outage) - MAX_BACKOFF_SECS).abs() < f64::EPSILON);
            assert!(
                (backoff_secs(attempts, refusal) - MAX_REFUSED_BACKOFF_SECS).abs() < f64::EPSILON
            );
        }
    }
}

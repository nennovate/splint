//! Holds messages until the recipient's Signet picks them up.
//!
//! Acknowledging a message clears its content but keeps its ID until it expires, so a replay
//! can't bring it back. An expired message can't pass verification, so its row can then go.
//!
//! Room is kept apart by who a message is from, so strangers let in by the owner's reach setting can
//! fill only their own, and a step that claims an owner's approval has room of its own in either. A
//! step a reader can't take yet goes out of sight for a while, so what's stuck can't hide what isn't.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use splint_core::host_api::{InboxAck, InboxPage, StoredMessage};
use splint_core::requests::{is_step_body, request_of};
use splint_core::{AccessProof, Identity, SplintId, VerifiedEnvelope, claimed_agent, unix_now};
use sqlx::{Postgres, Row, Transaction};

use crate::admission::SenderRecord;
use crate::api_error::ApiError;
use crate::{Host, answers, database, registry};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS inbox (
        seq BIGSERIAL PRIMARY KEY,
        recipient TEXT NOT NULL,
        message_id TEXT NOT NULL,
        envelope TEXT NOT NULL,
        sender_identity TEXT NOT NULL,
        sender_owner_identity TEXT NOT NULL DEFAULT '',
        sender_binding TEXT NOT NULL DEFAULT '',
        expires_at BIGINT NOT NULL DEFAULT 9223372036854775807,
        acked BOOLEAN NOT NULL DEFAULT FALSE,
        UNIQUE (recipient, message_id)
    );
    ALTER TABLE inbox ADD COLUMN IF NOT EXISTS sender TEXT NOT NULL DEFAULT '';
    ALTER TABLE inbox ADD COLUMN IF NOT EXISTS is_step BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE inbox ADD COLUMN IF NOT EXISTS by_reach BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE inbox ADD COLUMN IF NOT EXISTS decides BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE inbox ADD COLUMN IF NOT EXISTS not_before BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE inbox ADD COLUMN IF NOT EXISTS put_off INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE inbox ADD COLUMN IF NOT EXISTS relayed_by TEXT NOT NULL DEFAULT '';
    ALTER TABLE inbox ADD COLUMN IF NOT EXISTS relay_proof TEXT NOT NULL DEFAULT '';
    CREATE INDEX IF NOT EXISTS inbox_waiting ON inbox (recipient, seq) WHERE NOT acked;
";

const INBOX_PATH: &str = "/v0/inbox";
const ACK_PATH: &str = "/v0/inbox/ack";
const LATER_PATH: &str = "/v0/inbox/later";
const AUTH_SCHEME: &str = "Splint ";
/// Messages in one page, where they're small enough for that many to fit.
const PAGE_SIZE: i64 = 100;
/// Waiting to be read by one agent. Past these a host answers 429, and the sending host keeps
/// retrying until the agent has read some or the message expires. A reader gets what waits a page
/// at a time, so the byte limit is how much one agent can leave on this host, not how much one
/// answer holds. Steps have these to themselves, and text has them again, so text an idle agent
/// hasn't read can't keep a request from arriving.
const MAX_WAITING_PER_AGENT: i64 = 1000;
const MAX_WAITING_BYTES_PER_AGENT: i64 = 32 * 1024 * 1024;
/// A reader leaves a step here until the one before it arrives, and a contact can name a `prev` that
/// never comes, so no one contact can fill the limits above alone. It takes 10 together for the rows,
/// and 4 for the bytes.
const MAX_WAITING_PER_SENDER: i64 = 100;
const MAX_WAITING_BYTES_PER_SENDER: i64 = 8 * 1024 * 1024;
/// Far less for someone only the reach setting let in. It's what makes filling their shared room take
/// more new IDs than a day's quota gives, and a Signet that's up clears honest ones as they land.
const MAX_WAITING_PER_REACH_SENDER: i64 = 16;
/// How long a step a reader can't take yet goes out of sight, doubling each time up to this. It comes
/// back at once if another message from its sender gets taken, which is what it's usually waiting on.
const MAX_PUT_OFF_SECS: i64 = 30;
/// About an hour. A step from someone let in by reach that still can't be taken is let go, as nobody
/// the owner named is waiting on it and it would otherwise hold room for up to 30 days.
const MAX_PUT_OFFS_BY_REACH: i32 = 120;
pub const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route(INBOX_PATH, get(pull))
        .route(ACK_PATH, post(ack))
        .route(LATER_PATH, post(later))
}

/// Refuses a message there's no room for, unless it's here already and a resend can't add to it.
pub async fn check_room(
    db: impl sqlx::PgExecutor<'_>,
    envelope: &VerifiedEnvelope,
    by_reach: bool,
) -> Result<(), ApiError> {
    let row = sqlx::query(
        "SELECT count(*) AS waiting, coalesce(sum(octet_length(envelope)), 0)::bigint AS bytes,
             bool_or(message_id = $2) AS here,
             count(*) FILTER (WHERE sender = $4) AS from_sender,
             coalesce(sum(octet_length(envelope)) FILTER (WHERE sender = $4), 0)::bigint
                 AS bytes_from_sender
         FROM inbox WHERE recipient = $1 AND NOT acked AND expires_at > $3 AND is_step = $5
             AND by_reach = $6 AND decides = $7",
    )
    .bind(envelope.recipient().as_str())
    .bind(envelope.id().as_str())
    .bind(i64::try_from(unix_now()).unwrap_or(0))
    .bind(envelope.sender().as_str())
    .bind(is_step_body(envelope.body()))
    .bind(by_reach)
    .bind(decides(envelope))
    .fetch_one(db)
    .await?;
    let size = i64::try_from(envelope.compact().len()).unwrap_or(i64::MAX);
    let over = |column, limit| -> Result<bool, sqlx::Error> {
        Ok(row.try_get::<i64, _>(column)?.saturating_add(size) > limit)
    };
    let per_sender = if by_reach {
        MAX_WAITING_PER_REACH_SENDER
    } else {
        MAX_WAITING_PER_SENDER
    };
    let full = row.try_get::<i64, _>("waiting")? >= MAX_WAITING_PER_AGENT
        || row.try_get::<i64, _>("from_sender")? >= per_sender
        || over("bytes", MAX_WAITING_BYTES_PER_AGENT)?
        || over("bytes_from_sender", MAX_WAITING_BYTES_PER_SENDER)?;
    if full && !row.try_get::<Option<bool>, _>("here")?.unwrap_or(false) {
        return Err(ApiError::TooMany("this agent's inbox is full"));
    }
    Ok(())
}

/// Whether this claims to carry an owner's decision. A host can't check the claim, and it needn't: all
/// this buys is room apart from everything else, which a flood of the claim can fill only for itself.
fn decides(envelope: &VerifiedEnvelope) -> bool {
    request_of(envelope)
        .ok()
        .flatten()
        .is_some_and(|step| step.carries_approval)
}

/// Stores a verified message. Taking this type means unverified bytes can't get here, and a
/// message already seen is ignored, so a resend or replay can't create a duplicate.
pub async fn store(
    db: impl sqlx::PgExecutor<'_>,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
    record: &SenderRecord,
    by_reach: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO inbox (recipient, message_id, envelope, sender_identity, expires_at,
             sender_owner_identity, sender_binding, sender, is_step, by_reach, decides, relayed_by,
             relay_proof)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (recipient, message_id) DO NOTHING",
    )
    .bind(envelope.recipient().as_str())
    .bind(envelope.id().as_str())
    .bind(envelope.compact())
    .bind(sender.encoded())
    .bind(i64::try_from(envelope.expires_at()).unwrap_or(i64::MAX))
    .bind(&record.owner_identity)
    .bind(&record.binding)
    .bind(envelope.sender().as_str())
    .bind(is_step_body(envelope.body()))
    .bind(by_reach)
    .bind(decides(envelope))
    .bind(&record.relayed_by)
    .bind(&record.relay_proof)
    .execute(db)
    .await?;
    Ok(())
}

/// Checks for room again and stores, with one recipient's arrivals taking turns, so deliveries at
/// the same moment can't each see room for one and all go in.
pub async fn store_if_room(
    host: &Host,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
    record: &SenderRecord,
    by_reach: bool,
) -> Result<(), ApiError> {
    let mut held = database::begin(&host.db).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(envelope.recipient().as_str())
        .execute(&mut *held)
        .await?;
    check_room(&mut *held, envelope, by_reach).await?;
    store(&mut *held, envelope, sender, record, by_reach).await?;
    held.commit().await?;
    Ok(())
}

/// How long until a step this agent's Signet put off comes back into sight, if one will.
pub async fn next_put_off_due(host: &Host, agent: &SplintId) -> Result<Option<Duration>, ApiError> {
    let now = i64::try_from(unix_now()).unwrap_or(0);
    let due: Option<i64> = sqlx::query_scalar(
        "SELECT min(not_before) FROM inbox
         WHERE recipient = $1 AND NOT acked AND not_before > $2 AND expires_at > $2",
    )
    .bind(agent.as_str())
    .bind(now)
    .fetch_one(&host.db)
    .await?;
    Ok(due.map(|due| Duration::from_secs(u64::try_from(due.saturating_sub(now)).unwrap_or(0))))
}

/// For when this agent gets a new owner: what was written for the old one is cleared as if read, so a
/// sender's retry of it stays refused and the new owner never sees it.
pub async fn clear_for_new_owner(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE inbox SET acked = TRUE, envelope = '', sender_identity = '',
             sender_owner_identity = '', sender_binding = '', relayed_by = '', relay_proof = ''
         WHERE recipient = $1",
    )
    .bind(agent.as_str())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub async fn run_cleanup(host: Arc<Host>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        let now = host.clock.now_for_sql().await;
        let result = sqlx::query("DELETE FROM inbox WHERE expires_at <= $1")
            .bind(now)
            .execute(&host.db)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "inbox cleanup failed");
        }
    }
}

pub fn access_proof_in(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix(AUTH_SCHEME))
}

pub async fn authenticated_agent(
    host: &Host,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<SplintId, ApiError> {
    authenticated(host, headers, method, path, body, false).await
}

/// [`authenticated_agent`], for an agent its owner may have revoked, only for what it needs to hear
/// from its owner again.
pub async fn authenticated_agent_even_if_revoked(
    host: &Host,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<SplintId, ApiError> {
    authenticated(host, headers, method, path, body, true).await
}

async fn authenticated(
    host: &Host,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    revoked_too: bool,
) -> Result<SplintId, ApiError> {
    let proof = access_proof_in(headers).ok_or(ApiError::Unauthorized)?;
    let agent = claimed_agent(proof).map_err(|_| ApiError::Unauthorized)?;
    let identity = if revoked_too {
        registry::identity_even_if_revoked(host, &agent).await?
    } else {
        registry::identity_of(host, &agent).await?
    }
    .ok_or(ApiError::Unauthorized)?;
    AccessProof::verify(
        proof,
        &identity,
        &host.domain,
        method,
        path,
        body,
        unix_now(),
    )
    .map_err(|_| ApiError::Unauthorized)?;
    Ok(agent)
}

async fn pull(State(host): State<Arc<Host>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let agent = authenticated_agent(&host, &headers, "GET", INBOX_PATH, b"").await?;
    // Expired rows wait for the cleanup job, and until then they mustn't take up the page, because
    // Signet can neither show them nor clear them. Steps Signet put off are out of the way.
    //
    // Contacts' rows and strangers' steps take every other place, so each has half of any page the
    // other would fill while the byte budget lasts. A page always keeps its first row, so a contact's
    // first waiting row is on it whatever number of strangers' steps wait, and no pile of notes an
    // idle agent hasn't cleared can keep a stranger's step from being taken.
    // A page of only one has all of it. Among contacts' rows, steps come before text, since Signet
    // clears them and an idle agent may never clear text. Strangers' text comes after everything.
    // Within each, senders take turns, and each sender's own order stays as it came. A host could
    // still leave out anything, as it can drop anything.
    //
    // Only how long each row is gets read first, so the page can be cut to what fits and room taken
    // for it before any of it is held. A Signet clears or puts off what it took and reads again, so
    // what a page leaves out comes on the next. Within a turn the shortest come first, so a few
    // senders of long messages can't fill every page ahead of someone's short one.
    let sized = sqlx::query(
        "SELECT seq, bytes FROM (
             SELECT seq, bytes, by_reach, is_step,
                 row_number() OVER (PARTITION BY by_reach, by_reach AND NOT is_step
                     ORDER BY is_step DESC, turn, bytes, seq) AS place
             FROM (
                 SELECT seq, is_step, by_reach,
                     (octet_length(envelope) + octet_length(sender_identity)
                         + octet_length(sender_owner_identity) + octet_length(sender_binding)
                         + octet_length(relayed_by) + octet_length(relay_proof))::bigint AS bytes,
                     row_number() OVER (PARTITION BY sender, is_step ORDER BY seq) AS turn
                 FROM inbox
                 WHERE recipient = $1 AND NOT acked AND expires_at > $2 AND not_before <= $2
             ) AS waiting
         ) AS placed
         ORDER BY by_reach AND NOT is_step, place, by_reach, seq LIMIT $3",
    )
    .bind(agent.as_str())
    .bind(i64::try_from(unix_now()).unwrap_or(0))
    .bind(PAGE_SIZE)
    .fetch_all(&host.db)
    .await?;
    // With less room than a page, the part that fits: a reader clears it and asks again, where one
    // told to come back for a whole page hears nothing for as long as others hold the room.
    let page = answers::page_of(
        answers::seq_and_bytes(&sized)?,
        sized.len(),
        host.answers.page_budget(&headers),
        true,
    );
    let room = host.answers.take(&headers, page.bytes)?;
    if page.keys.is_empty() {
        return room.json(&InboxPage { messages: vec![] });
    }
    let rows = sqlx::query(
        "SELECT seq, envelope, sender_identity, sender_owner_identity, sender_binding, relayed_by,
             relay_proof
         FROM inbox WHERE recipient = $1 AND seq = ANY($2) AND NOT acked
         ORDER BY array_position($2, seq)",
    )
    .bind(agent.as_str())
    .bind(&page.keys)
    .fetch_all(&host.db)
    .await?;
    let messages = rows
        .iter()
        .map(|row| {
            Ok(StoredMessage {
                seq: row.try_get("seq")?,
                envelope: row.try_get("envelope")?,
                sender_identity: row.try_get("sender_identity")?,
                sender_owner_identity: row.try_get("sender_owner_identity")?,
                sender_binding: row.try_get("sender_binding")?,
                relayed_by: row.try_get("relayed_by")?,
                relay_proof: row.try_get("relay_proof")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    room.json(&InboxPage { messages })
}

#[derive(Serialize)]
struct Acked {
    acked: u64,
}

/// Acknowledges exactly the messages named, so nothing the agent hasn't seen can be cleared.
async fn ack(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Acked>, ApiError> {
    let agent = authenticated_agent(&host, &headers, "POST", ACK_PATH, &body).await?;
    let ack: InboxAck =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("bad body"))?;
    let result = sqlx::query(
        "WITH taken AS (
             UPDATE inbox SET acked = TRUE, envelope = '', sender_identity = '',
                 sender_owner_identity = '', sender_binding = '', relayed_by = '', relay_proof = ''
             WHERE recipient = $1 AND seq = ANY($2)
             RETURNING sender
         ), woken AS (
             UPDATE inbox SET not_before = 0
             WHERE recipient = $1 AND NOT acked AND not_before > 0
                 AND seq <> ALL($2) AND sender IN (SELECT sender FROM taken)
         )
         SELECT count(*) AS acked FROM taken",
    )
    .bind(agent.as_str())
    .bind(&ack.seqs)
    .fetch_one(&host.db)
    .await?;
    Ok(Json(Acked {
        acked: u64::try_from(result.try_get::<i64, _>("acked")?).unwrap_or(0),
    }))
}

/// Takes steps a reader can't use yet out of sight for a while, each longer than the last. A flood of
/// them can then only cost a reader the odd look, and never hide what's behind them.
async fn later(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Acked>, ApiError> {
    let agent = authenticated_agent(&host, &headers, "POST", LATER_PATH, &body).await?;
    let later: InboxAck =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("bad body"))?;
    let now = i64::try_from(unix_now()).unwrap_or(0);
    let due: Vec<i64> = sqlx::query_scalar(
        "UPDATE inbox SET put_off = put_off + 1,
             not_before = $3 + least(power(2, least(put_off, 16))::bigint, $4)
         WHERE recipient = $1 AND seq = ANY($2) AND is_step AND NOT acked
         RETURNING not_before",
    )
    .bind(agent.as_str())
    .bind(&later.seqs)
    .bind(now)
    .bind(MAX_PUT_OFF_SECS)
    .fetch_all(&host.db)
    .await?;
    sqlx::query(
        "UPDATE inbox SET acked = TRUE, envelope = '', sender_identity = '',
             sender_owner_identity = '', sender_binding = '', relayed_by = '', relay_proof = ''
         WHERE recipient = $1 AND seq = ANY($2) AND by_reach AND NOT acked AND put_off >= $3",
    )
    .bind(agent.as_str())
    .bind(&later.seqs)
    .bind(MAX_PUT_OFFS_BY_REACH)
    .execute(&host.db)
    .await?;
    // A call Signet left held while it looked was told when to end before these were put off.
    host.waits.rehold(&agent);
    let acked = u64::try_from(due.len()).unwrap_or(u64::MAX);
    wake_when_due(&host, &agent, due);
    Ok(Json(Acked { acked }))
}

/// A step coming back into sight is news for its agent, as one arriving is, and nothing in Postgres
/// says when that happens. So its mark moves then. Otherwise a Signet that looked just before a step
/// came due, and asked to wait just after, was held the whole time with nothing new, and looked again
/// only minutes later. One task a call, gone within `MAX_PUT_OFF_SECS` and a second.
fn wake_when_due(host: &Arc<Host>, agent: &SplintId, due: Vec<i64>) {
    let mut seconds: Vec<u64> = due
        .into_iter()
        .filter_map(|second| u64::try_from(second).ok())
        .collect();
    seconds.sort_unstable();
    seconds.dedup();
    if seconds.is_empty() {
        return;
    }
    let host = Arc::clone(host);
    let agent = agent.clone();
    tokio::spawn(async move {
        for second in seconds {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            tokio::time::sleep(Duration::from_secs(second).saturating_sub(now)).await;
            host.waits.wake(&agent);
        }
    });
}

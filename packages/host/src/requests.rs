//! Holds the steps of interactions, for their parties and owners to read back.
//!
//! A host stores signed objects and computes nothing anyone has to believe. It checks a step's
//! general shape and encoding, and has no schema for any type, so what a type's fields can hold is
//! for each reader's Signet to check. The state of an interaction is what each reader finds by
//! walking the steps, so a change to this table can only withhold a step.
//!
//! Steps stay until their envelopes expire, so unlike a delivered message's text they outlast
//! delivery. They hold typed fields, and a subject or note if an owner chose to add one.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use splint_core::SplintId;
use splint_core::changes::is_notice_body;
use splint_core::contact_invites::is_introduction_body;
use splint_core::host_api::{StoredChain, StoredStep};
use splint_core::invites::redeem_proof_in;
use splint_core::requests::request_of;
use splint_core::{Error, Identity, VerifiedEnvelope};
use sqlx::{Postgres, Row, Transaction};

use crate::api_error::ApiError;
use crate::{Host, admission, answers, inbox};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS request_steps (
        seq BIGSERIAL PRIMARY KEY,
        message_id TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        envelope TEXT NOT NULL,
        sender_identity TEXT NOT NULL,
        expires_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS request_steps_request ON request_steps (request_id);
    CREATE INDEX IF NOT EXISTS request_steps_expiry ON request_steps (expires_at);
    CREATE INDEX IF NOT EXISTS request_steps_sender ON request_steps (sender);
    CREATE TABLE IF NOT EXISTS chains_begin (
        agent TEXT PRIMARY KEY,
        after_seq BIGINT NOT NULL
    );
";

/// Above what one side can send on the longest line in `docs/protocol.md`, its own steps and a
/// `received` for each of the other side's. The limit is per sender, so that one party can't use up
/// the space for a request by naming its ID, and it's generous because a sender may also race or
/// misbehave, which readers need to see to report it. It limits this host's copies, and must never
/// block a step that decides a result: see `store_if_step`.
const MAX_STEPS_PER_SENDER: i64 = 400;
/// Steps outlast delivery, so this is what keeps them from adding up. It's well past a few new
/// interactions per contact per day, at a typical length, for a week.
const MAX_STEPS_STORED_PER_SENDER: i64 = 20_000;
/// Steps in one page of a request read back, where they're small enough for that many to fit.
const PAGE_SIZE: i64 = 100;

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route("/v0/requests/{request}", get(read_chain))
        .route(
            "/v0/requests/{request}/after/{after}",
            get(read_chain_after),
        )
}

/// Keeps a copy if this message is a step. If its body presents itself as a step and isn't a valid
/// one, the message is refused, because no reader will ever accept it.
///
/// A sender past the limit has any further step refused, apart from one claiming an owner's approval:
/// a stolen agent key must not be able to block its owner's decision by filling this table. Such a
/// step goes on with no copy kept. This host has no way to check the claim, so a false one is carried
/// like any other message, and the other side's Signet refuses it.
pub async fn store_if_step(
    host: &Host,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
) -> Result<(), ApiError> {
    // A redeem or a notice looks like a step but belongs to no request.
    if redeem_proof_in(envelope.body()).is_some()
        || is_notice_body(envelope.body())
        || is_introduction_body(envelope.body())
    {
        return Ok(());
    }
    let request = request_of(envelope).map_err(|_| ApiError::Malformed(Error::Malformed))?;
    let Some(step) = request else {
        return Ok(());
    };
    // A `received` is kept only for an interaction this host holds between the two, so a note's
    // receipt, or one naming a request made up, can't make two agents look like they've dealt.
    if step.is_receipt
        && !between(
            host,
            step.request.as_str(),
            envelope.sender(),
            envelope.recipient(),
        )
        .await?
    {
        return Ok(());
    }
    let held = sqlx::query(
        "SELECT count(*) AS steps, bool_or(message_id = $2) AS here
         FROM request_steps WHERE sender = $1",
    )
    .bind(envelope.sender().as_str())
    .bind(envelope.id().as_str())
    .fetch_one(&host.db)
    .await?;
    if held.try_get::<i64, _>("steps")? >= MAX_STEPS_STORED_PER_SENDER
        && !held.try_get::<Option<bool>, _>("here")?.unwrap_or(false)
    {
        return Err(ApiError::TooMany("this sender has too many steps stored"));
    }
    let count_and_add = sqlx::query(
        "INSERT INTO request_steps
             (message_id, request_id, sender, recipient, envelope, sender_identity, expires_at)
         SELECT $1, $2, $3, $4, $5, $6, $7
         WHERE (SELECT count(*) FROM request_steps WHERE request_id = $2 AND sender = $3) < $8
         ON CONFLICT (message_id) DO NOTHING",
    )
    .bind(envelope.id().as_str())
    .bind(step.request.as_str())
    .bind(envelope.sender().as_str())
    .bind(envelope.recipient().as_str())
    .bind(envelope.compact())
    .bind(sender.encoded())
    .bind(i64::try_from(envelope.expires_at()).unwrap_or(i64::MAX))
    .bind(MAX_STEPS_PER_SENDER);
    let stored = admission::counted_alone(host, step.request.as_str(), count_and_add).await?;
    if stored.rows_affected() == 0 {
        let already_here = sqlx::query("SELECT 1 FROM request_steps WHERE message_id = $1")
            .bind(envelope.id().as_str())
            .fetch_optional(&host.db)
            .await?;
        if already_here.is_none() && !step.carries_approval {
            return Err(ApiError::Forbidden("too many steps on this request"));
        }
    }
    Ok(())
}

/// Whether these two are the parties to this interaction, by a step of it this host holds. The first
/// can only have been an `open` that passed the owner's rules, so naming a request a sender made up, or
/// someone else's, finds nothing.
pub async fn between(
    host: &Host,
    request: &str,
    one: &SplintId,
    other: &SplintId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM request_steps WHERE request_id = $1
             AND ((sender = $2 AND recipient = $3) OR (sender = $3 AND recipient = $2)))",
    )
    .bind(request)
    .bind(one.as_str())
    .bind(other.as_str())
    .fetch_one(&host.db)
    .await
}

/// For when this agent gets a new owner, who doesn't get to read back what it did for the last one.
/// The rows stay, as the other party may be on this host too and each step is held once.
pub async fn hide_from_new_owner(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO chains_begin (agent, after_seq)
         SELECT $1, coalesce(max(seq), 0) FROM request_steps
         ON CONFLICT (agent) DO UPDATE SET after_seq = EXCLUDED.after_seq",
    )
    .bind(agent.as_str())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The steps this agent is a party to, in the order this host took them in, since its current owner.
async fn read_chain(
    State(host): State<Arc<Host>>,
    Path(request): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let path = format!("/v0/requests/{request}");
    chain_page(&host, &headers, &path, &request, 0).await
}

/// The same, from after the step a page before said to go on from.
async fn read_chain_after(
    State(host): State<Arc<Host>>,
    Path((request, after)): Path<(String, i64)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let path = format!("/v0/requests/{request}/after/{after}");
    chain_page(&host, &headers, &path, &request, after).await
}

/// One page of a request's steps. A request can hold hundreds from each sender, so only how long
/// each is gets read first, and room is taken for the ones that fit before they're read.
async fn chain_page(
    host: &Host,
    headers: &HeaderMap,
    path: &str,
    request: &str,
    after: i64,
) -> Result<Response, ApiError> {
    let agent = inbox::authenticated_agent(host, headers, "GET", path, b"").await?;
    let sized = sqlx::query(
        "SELECT seq, (octet_length(envelope) + octet_length(sender_identity))::bigint AS bytes
         FROM request_steps
         WHERE request_id = $1 AND (sender = $2 OR recipient = $2) AND seq > $3
             AND seq > coalesce((SELECT after_seq FROM chains_begin WHERE agent = $2), 0)
         ORDER BY seq LIMIT $4",
    )
    .bind(request)
    .bind(agent.as_str())
    .bind(after)
    .bind(PAGE_SIZE + 1)
    .fetch_all(&host.db)
    .await?;
    if sized.is_empty() && after <= 0 {
        return Err(ApiError::NotFound);
    }
    let page = answers::page_of(
        answers::seq_and_bytes(&sized)?,
        usize::try_from(PAGE_SIZE).unwrap_or(usize::MAX),
        answers::PAGE_BYTES,
        true,
    );
    let room = host.answers.take(headers, page.bytes)?;
    let rows = sqlx::query(
        "SELECT envelope, sender_identity FROM request_steps WHERE seq = ANY($1) ORDER BY seq",
    )
    .bind(&page.keys)
    .fetch_all(&host.db)
    .await?;
    let steps = rows
        .iter()
        .map(|row| {
            Ok(StoredStep {
                envelope: row.try_get("envelope")?,
                sender_identity: row.try_get("sender_identity")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    let next = page.keys.last().copied().filter(|_| page.more);
    room.json(&StoredChain { steps, next })
}

pub async fn run_cleanup(host: Arc<Host>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        let now = host.clock.now_for_sql().await;
        let result = sqlx::query("DELETE FROM request_steps WHERE expires_at <= $1")
            .bind(now)
            .execute(&host.db)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "request step cleanup failed");
        }
    }
}

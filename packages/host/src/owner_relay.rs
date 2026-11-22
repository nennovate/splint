//! How an owner reaches an agent on another device, with this host between them. A Signet leaves what
//! its owner's device reads, sealed to the owner, and that device leaves what its owner signed, sealed
//! to the agent. A host can read neither, and can hold either back or show an old copy, which only
//! makes an owner wait. What's shown is checked on the owner's device, and what's signed counts only by
//! the owner's signature inside the seal, which the agent's Signet checks.
//!
//! So this host never sees what an owner signed, or which kind of thing it is. It lets owner mail in
//! by who left it: the agent's owner, by an access proof their own key signed or a session of theirs,
//! over the exact sealed bytes. That keeps the room here for the owner, and says nothing of what's
//! inside, which a Signet takes only by the owner's signature on it.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use splint_core::host_api::{
    HeldOwnerView, InboxAck, OWNER_MAIL_ACK_PATH, OWNER_MAIL_PATH, OWNER_VIEW_PATH, OwnerMail,
    OwnerMailKind, OwnerMailPage, OwnerView, StoredOwnerMail,
};
use splint_core::owner_call::{MAX_SEALED_CALL_BYTES, SealedCall, seal_owner_mail};
use splint_core::owner_session::SESSION_HEADER;
use splint_core::{Identity, SplintId, signed_by_owner_now, unix_now};
use sqlx::{PgPool, Row};

use crate::api_error::ApiError;
use crate::owner_api::reader::{owner_of_agent, owner_reading};
use crate::{Host, database, inbox};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS owner_views (
        agent_id TEXT PRIMARY KEY,
        view TEXT NOT NULL,
        at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS owner_mail (
        seq BIGSERIAL PRIMARY KEY,
        agent_id TEXT NOT NULL,
        sealed TEXT NOT NULL,
        by_owner TEXT,
        at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS owner_mail_agent ON owner_mail (agent_id, seq);
    ALTER TABLE owner_mail ADD COLUMN IF NOT EXISTS item BYTEA;
    ALTER TABLE owner_mail ADD COLUMN IF NOT EXISTS taken BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE UNIQUE INDEX IF NOT EXISTS owner_mail_item ON owner_mail (agent_id, item);
    ALTER TABLE owner_mail ADD COLUMN IF NOT EXISTS sealed TEXT;
    ALTER TABLE owner_mail ADD COLUMN IF NOT EXISTS by_owner TEXT;
";

/// More than an owner decides in the time a Signet takes to come for them. Past this they wait and try
/// again, which only costs an owner who's flooding their own agent.
const MAX_MAIL_WAITING: i64 = 64;
/// Long enough for a Signet to come back from being off. An approval is only good for its dates anyway.
/// Something taken is remembered as long, by this host's own clock, so the same sealed bytes left
/// again are already here. Only the owner can leave anything, by a proof good for moments, so nothing
/// that was let in can be put back after it's forgotten but by its owner.
const KEEP_MAIL_SECS: i64 = 7 * 24 * 60 * 60;
const MAX_MAIL_PAGE: i64 = 32;
/// The most this remembers as taken for one agent. A session lasts hours, and whoever held one could
/// otherwise have rows taken and left again for as long as each is kept.
const MAX_TAKEN_REMEMBERED: i64 = 1024;

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        // Under the cap every body has, which Signet fits a view to. One row per agent, so the most this
        // keeps is `MAX_OWNER_VIEW_BYTES` for each agent with an owner elsewhere.
        .route(OWNER_VIEW_PATH, put(leave_view))
        .route(&under_agent(OWNER_VIEW_PATH), get(read_view))
        .route(OWNER_MAIL_PATH, get(take_mail))
        .route(OWNER_MAIL_ACK_PATH, post(ack_mail))
        .route(&under_agent(OWNER_MAIL_PATH), post(leave_mail))
}

fn under_agent(base: &str) -> String {
    format!("{base}/{{agent}}")
}

/// For an agent this host has let go: what it left for its owner, and what was left for it, go too.
pub async fn forget(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    agent: &SplintId,
) -> Result<(), sqlx::Error> {
    for statement in [
        "DELETE FROM owner_views WHERE agent_id = $1",
        "DELETE FROM owner_mail WHERE agent_id = $1",
    ] {
        sqlx::query(statement)
            .bind(agent.as_str())
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

/// What's still waiting for this agent that no key of its owner's that counts now left, once one was
/// removed: by the access proof or the session that let each in, as what's inside is sealed. Its Signet
/// would refuse what a removed key signed anyway, and it shouldn't take up the room its owner has
/// here. One sealed here at an upgrade has neither, so it goes too, and its owner signs it again.
pub async fn drop_unless_signed_by(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    agent: &SplintId,
    owner: &Identity,
) -> Result<(), sqlx::Error> {
    let rows =
        sqlx::query("SELECT seq, by_owner FROM owner_mail WHERE agent_id = $1 AND NOT taken")
            .bind(agent.as_str())
            .fetch_all(&mut **transaction)
            .await?;
    let mut gone = Vec::new();
    for row in rows {
        let by_owner: Option<&str> = row.try_get("by_owner")?;
        if !by_owner.is_some_and(|by_owner| signed_by_owner_now(owner, by_owner)) {
            gone.push(row.try_get::<i64, _>("seq")?);
        }
    }
    sqlx::query("DELETE FROM owner_mail WHERE agent_id = $1 AND seq = ANY($2)")
        .bind(agent.as_str())
        .bind(&gone)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// Only what this agent's Signet proves it sent, so nobody else can show its owner something.
async fn leave_view(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), ApiError> {
    let agent = inbox::authenticated_agent(&host, &headers, "PUT", OWNER_VIEW_PATH, &body).await?;
    let notice: OwnerView =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("bad body"))?;
    let now = i64::try_from(unix_now()).unwrap_or(i64::MAX);
    sqlx::query(
        "INSERT INTO owner_views (agent_id, view, at) VALUES ($1, $2, $3)
         ON CONFLICT (agent_id) DO UPDATE SET view = $2, at = $3",
    )
    .bind(agent.as_str())
    .bind(&notice.view)
    .bind(now)
    .execute(&host.db)
    .await?;
    Ok(())
}

/// For that agent's owner alone, by their page's session or a proof their own key made, since it
/// holds what's between them.
async fn read_view(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    Path(agent): Path<String>,
) -> Result<Json<HeldOwnerView>, ApiError> {
    let owner = owner_of_agent(&host, &agent)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let path = format!("{OWNER_VIEW_PATH}/{agent}");
    owner_reading(&host, &headers, &owner, "GET", &path, b"")?;
    let row = sqlx::query("SELECT view, at FROM owner_views WHERE agent_id = $1")
        .bind(&agent)
        .fetch_optional(&host.db)
        .await?;
    Ok(Json(match row {
        Some(row) => HeldOwnerView {
            view: Some(row.try_get("view")?),
            at: u64::try_from(row.try_get::<i64, _>("at")?).unwrap_or_default(),
        },
        None => HeldOwnerView { view: None, at: 0 },
    }))
}

/// Rows dated before this are let go.
fn oldest_kept(now: i64) -> i64 {
    now.saturating_sub(KEEP_MAIL_SECS)
}

/// Whether this could be a sealed note as it's written, base64url with nothing else in it. This host
/// can't open one, so it's only that what's kept is what a Signet could.
fn written_as_sealed(sealed: &str) -> bool {
    !sealed.is_empty()
        && sealed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Keeps what this agent's owner left for it, sealed to the agent. Only its owner as this host holds
/// them now gets in, by a proof over these exact bytes, and never a stand-in for one who hasn't
/// confirmed, whose key is on the agent's own machine.
async fn leave_mail(
    State(host): State<Arc<Host>>,
    Path(agent): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), ApiError> {
    let owner = owner_of_agent(&host, &agent)
        .await?
        .ok_or(ApiError::NotFound)?;
    if owner.is_unconfirmed_owner() {
        return Err(ApiError::Unauthorized);
    }
    let path = format!("{OWNER_MAIL_PATH}/{agent}");
    owner_reading(&host, &headers, &owner, "POST", &path, &body)?;
    // Nothing but the sealed note, so what an owner signed is never kept here as they signed it.
    let mail: SealedCall = (body.len() <= MAX_SEALED_CALL_BYTES)
        .then(|| serde_json::from_slice(&body).ok())
        .flatten()
        .ok_or(ApiError::BadRequest("bad body"))?;
    if !written_as_sealed(&mail.sealed) {
        return Err(ApiError::BadRequest("bad body"));
    }
    // What the owner's own key signed to leave this: their session, or else their access proof. Never
    // a session key's proof, which says nothing once the session is gone.
    let by_owner = headers
        .get(SESSION_HEADER)
        .and_then(|session| session.to_str().ok())
        .or_else(|| inbox::access_proof_in(&headers))
        .ok_or(ApiError::Unauthorized)?;
    let now = i64::try_from(unix_now()).unwrap_or(i64::MAX);
    sqlx::query("DELETE FROM owner_mail WHERE agent_id = $1 AND at < $2")
        .bind(&agent)
        .bind(oldest_kept(now))
        .execute(&host.db)
        .await?;
    // One row for the same sealed bytes, waiting or taken, so leaving them again changes nothing.
    let kept = sqlx::query(
        "INSERT INTO owner_mail (agent_id, sealed, by_owner, item, at)
         SELECT $1, $2, $3, sha256($4), $5
         WHERE (SELECT count(*) FROM owner_mail WHERE agent_id = $1 AND NOT taken) < $6
         ON CONFLICT (agent_id, item) DO NOTHING",
    )
    .bind(&agent)
    .bind(&mail.sealed)
    .bind(by_owner)
    .bind(mail.sealed.as_bytes())
    .bind(now)
    .bind(MAX_MAIL_WAITING)
    .execute(&host.db)
    .await?;
    if kept.rows_affected() > 0 {
        sqlx::query(
            "DELETE FROM owner_mail WHERE agent_id = $1 AND taken AND seq <= (
                 SELECT seq FROM owner_mail WHERE agent_id = $1 AND taken
                 ORDER BY seq DESC OFFSET $2 LIMIT 1)",
        )
        .bind(&agent)
        .bind(MAX_TAKEN_REMEMBERED)
        .execute(&host.db)
        .await?;
        return Ok(());
    }
    // An honest device retrying gets the same answer as the first time.
    let held: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM owner_mail WHERE agent_id = $1 AND item = sha256($2))",
    )
    .bind(&agent)
    .bind(mail.sealed.as_bytes())
    .fetch_one(&host.db)
    .await?;
    if held {
        return Ok(());
    }
    Err(ApiError::TooMany(
        "this agent hasn't collected what its owner already left for it",
    ))
}

async fn take_mail(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
) -> Result<Json<OwnerMailPage>, ApiError> {
    let agent = inbox::authenticated_agent(&host, &headers, "GET", OWNER_MAIL_PATH, b"").await?;
    let rows = sqlx::query(
        "SELECT seq, sealed FROM owner_mail WHERE agent_id = $1 AND NOT taken
         ORDER BY seq LIMIT $2",
    )
    .bind(agent.as_str())
    .bind(MAX_MAIL_PAGE)
    .fetch_all(&host.db)
    .await?;
    let mut mail = Vec::with_capacity(rows.len());
    for row in rows {
        mail.push(StoredOwnerMail {
            seq: row.try_get("seq")?,
            sealed: row.try_get("sealed")?,
        });
    }
    Ok(Json(OwnerMailPage { mail }))
}

async fn ack_mail(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), ApiError> {
    let agent =
        inbox::authenticated_agent(&host, &headers, "POST", OWNER_MAIL_ACK_PATH, &body).await?;
    let ack: InboxAck =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("bad body"))?;
    // Kept as taken, without what was sealed or who left it, so the same thing left again is
    // already here.
    sqlx::query(
        "UPDATE owner_mail SET taken = TRUE, sealed = '', by_owner = ''
         WHERE agent_id = $1 AND seq = ANY($2)",
    )
    .bind(agent.as_str())
    .bind(&ack.seqs)
    .execute(&host.db)
    .await?;
    Ok(())
}

/// The kinds a row was named by while this host kept owner mail as its owner signed it.
fn kind_before_sealing(word: &str) -> Option<OwnerMailKind> {
    match word {
        "approval" => Some(OwnerMailKind::Approval),
        "acceptance" => Some(OwnerMailKind::Acceptance),
        "person_text" => Some(OwnerMailKind::PersonText),
        "where_paid" => Some(OwnerMailKind::WherePaid),
        "delegation" => Some(OwnerMailKind::Delegation),
        _ => None,
    }
}

/// For a database from before owner mail was sealed, which held each thing as its owner signed it,
/// with its kind: seals what's still waiting to its agent, as its owner's device now would, so nothing
/// waiting is lost, then lets go of the plain columns and what they held. It does nothing once
/// they're gone. Backups made before this still hold what those columns did.
pub async fn seal_what_waited_in_plain(db: &PgPool) -> Result<(), sqlx::Error> {
    let plain: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = 'owner_mail'
           AND column_name = 'signed')",
    )
    .fetch_one(db)
    .await?;
    if !plain {
        return Ok(());
    }
    let mut transaction = database::begin(db).await?;
    let waiting = sqlx::query(
        "SELECT mail.seq, mail.kind, mail.signed, agents.identity FROM owner_mail mail
         JOIN agents ON agents.id = mail.agent_id
         WHERE NOT mail.taken AND mail.sealed IS NULL",
    )
    .fetch_all(&mut *transaction)
    .await?;
    for row in waiting {
        let agent = Identity::from_encoded(row.try_get::<&str, _>("identity")?).ok();
        let kind = kind_before_sealing(row.try_get::<&str, _>("kind")?);
        let signed: String = row.try_get("signed")?;
        let sealed = agent
            .zip(kind)
            .and_then(|(agent, kind)| seal_owner_mail(&agent, &OwnerMail { kind, signed }).ok());
        if let Some(sealed) = sealed {
            sqlx::query("UPDATE owner_mail SET sealed = $2 WHERE seq = $1")
                .bind(row.try_get::<i64, _>("seq")?)
                .bind(sealed.sealed)
                .execute(&mut *transaction)
                .await?;
        }
    }
    // What couldn't be sealed, for an agent that's gone or a kind this doesn't know, isn't kept.
    sqlx::raw_sql(
        "DELETE FROM owner_mail WHERE NOT taken AND sealed IS NULL;
         UPDATE owner_mail SET sealed = '' WHERE sealed IS NULL;
         ALTER TABLE owner_mail ALTER COLUMN sealed SET NOT NULL;
         ALTER TABLE owner_mail DROP COLUMN kind, DROP COLUMN signed;",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    // Dropping a column leaves what it held in the table's file until its rows are written again,
    // which this does at once. It's a small table, and this only ever runs the once.
    if let Err(error) = sqlx::raw_sql("VACUUM FULL owner_mail").execute(db).await {
        tracing::warn!(%error, "couldn't rewrite owner_mail, so what it held in plain stays in its file until it is: run VACUUM FULL owner_mail");
    }
    tracing::warn!(
        "sealed the owner mail that was waiting in plain, and stopped keeping any that way"
    );
    Ok(())
}

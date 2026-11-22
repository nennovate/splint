//! What an agent needs from this host to join, given nothing but its address: a page, served at the
//! bare address and at a path that won't move, and a place for its owner's answer to wait.
//!
//! The page points to Splint's official instructions and says only what this host alone can: its
//! domain, whether signups are open, and its protocol. Whoever runs a host can change these words, so
//! nothing an agent or its owner needs, such as how to install or what to tell the owner, is here: the
//! official copy says how to install, and the agent's own `splint` writes what its owner reads.
//! Nothing here can get an agent past its owner either: an agent that joins on its own acts for a
//! stand-in no reader takes for an owner, and confirming takes what the owner's device signed.
//!
//! An answer is kept under the agent's key and the owner's ID, which the owner tells the agent. So anyone
//! can leave one, and an agent asking for its own owner's finds only what that owner signed. An answer
//! to an agent's ask for its controls is also kept where the ask's ID says, which only the agent and
//! whoever its link reached know, so an agent that doesn't know its owner's ID looks only there. A host
//! can hold one back, and the owner can then give the agent the whole thing themselves.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use splint_core::host_api::{JoinAnswer, JoinAnswers};
use splint_core::release::{AGENT_INSTRUCTIONS, PROTOCOL, REPOSITORY};
use splint_core::{
    ADDRESS_SEPARATOR, AgentKeys, Error, Identity, JoinReply, MoveReply, VerifiedBinding, unix_now,
};
use sqlx::{Postgres, Row, Transaction};

use crate::api_error::ApiError;
use crate::{Host, admission, registry};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS join_answers (
        agent_key TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        answer TEXT NOT NULL,
        source TEXT NOT NULL,
        at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS join_answers_at ON join_answers (at);
    ALTER TABLE join_answers ADD COLUMN IF NOT EXISTS kept_at TEXT NOT NULL DEFAULT '';
    ALTER TABLE join_answers ADD COLUMN IF NOT EXISTS ask_mac TEXT NOT NULL DEFAULT '';
    ALTER TABLE join_answers DROP CONSTRAINT IF EXISTS join_answers_pkey;
    CREATE UNIQUE INDEX IF NOT EXISTS join_answers_each ON join_answers (agent_key, owner_id, kept_at);
";

/// Long enough for someone to pass a line on. Anything older goes when the next one arrives.
const KEEP_ANSWER_SECS: i64 = 24 * 60 * 60;
/// Past this an owner gives the agent the whole answer themselves, so filling this stops nobody.
const MAX_ANSWERS_HELD: i64 = 1000;
/// Two say the link reached more than one owner, and a few more say who, for the agent to ask which is
/// theirs.
const MAX_ANSWERS_SHOWN: i64 = 4;
const MAX_ANSWERS_PER_SOURCE: i64 = 20;
const ANSWERS_PATH: &str = "/v0/join-answers";

const DOCUMENT: &str = include_str!("agents.md");
/// A path that will stay, for an owner to give their agent or a page to link to.
const DOCUMENT_PATH: &str = "/.well-known/splint/agents.md";
const OPEN_WORDS: &str = "open, with no code, for a few new agents an hour from one network";
const CLOSED_WORDS: &str = "need a code from whoever runs this host, good once";
const CLOSING_WORDS: &str = "none: this host is closing, so join another host";

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route("/", get(document))
        .route(DOCUMENT_PATH, get(document))
        .route(ANSWERS_PATH, put(keep_answer))
        .route(
            "/v0/join-answers/{agent_key}/asked/{kept_at}",
            get(read_asked),
        )
        .route("/v0/join-answers/{agent_key}/{owner_id}", get(read_answer))
}

/// Takes only what checks out for this host, so what fills this table costs a signature, and what's
/// in it is what the owner signed. One from the same owner for the same key, at the same place,
/// replaces the last. An answer is public by its owner's ID, so one kept where an ask said is a row of
/// its own: leaving the same answer again with no MAC, or at another place, can't take it away from
/// where the agent looks, and only someone who knows that place can replace it.
/// Throwaway keys cost nothing, so answers for a key nobody has registered fill only their own share:
/// one for an agent here whose owner hasn't confirmed, as every owner's page leaves, is never kept
/// out by them, and counts only against its network's.
async fn keep_answer(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    Json(body): Json<JoinAnswer>,
) -> Result<(), ApiError> {
    let key = AgentKeys::from_encoded(&body.agent_key)?;
    let now = unix_now();
    // Only the agent checks the MAC, as only it and its person know the ask. Here each is in its shape,
    // and comes with the other.
    let asked = match (&body.kept_at, &body.ask_mac) {
        (Some(kept_at), Some(mac)) if lower_hex(kept_at, 32) && lower_hex(mac, 64) => true,
        (None, None) => false,
        _ => return Err(Error::Malformed.into()),
    };
    let (owner, for_an_agent_here) = match JoinReply::decode(&body.answer) {
        Ok(reply) => match confirming_here(&host, &reply, &key, now).await {
            Ok(owner) => (owner, true),
            Err(_) => (reply.check_for_keeping(&key, &host.domain, now)?, false),
        },
        // An owner's approval of a move here, which the agent takes up before it's registered.
        Err(_) => (
            MoveReply::decode(&body.answer)?.check_for_keeping(&key, &host.domain)?,
            false,
        ),
    };
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    sqlx::query("DELETE FROM join_answers WHERE at < $1")
        .bind(now.saturating_sub(KEEP_ANSWER_SECS))
        .execute(&host.db)
        .await?;
    let count_and_add = sqlx::query(
        "INSERT INTO join_answers (agent_key, owner_id, answer, source, at, kept_at, ask_mac)
         SELECT $1, $2, $3, $4, $5, $9, $10
         WHERE ($8 OR (SELECT count(*) FROM join_answers) < $6)
           AND (SELECT count(*) FROM join_answers WHERE source = $4) < $7
         ON CONFLICT (agent_key, owner_id, kept_at)
         DO UPDATE SET answer = $3, source = $4, at = $5, ask_mac = $10",
    )
    .bind(key.encoded())
    .bind(owner.id().as_str())
    .bind(&body.answer)
    .bind(registry::source_of(&headers))
    .bind(now)
    .bind(MAX_ANSWERS_HELD)
    .bind(MAX_ANSWERS_PER_SOURCE)
    .bind(for_an_agent_here)
    .bind(
        body.kept_at
            .as_deref()
            .filter(|_| asked)
            .unwrap_or_default(),
    )
    .bind(
        body.ask_mac
            .as_deref()
            .filter(|_| asked)
            .unwrap_or_default(),
    );
    let kept = admission::counted_alone(&host, "join_answers", count_and_add).await?;
    if kept.rows_affected() == 0 {
        return Err(ApiError::TooMany(
            "this host is holding all the answers it can",
        ));
    }
    Ok(())
}

/// An owner confirming an agent here that joined on its own, with this key, and has no controls yet.
async fn confirming_here(
    host: &Host,
    reply: &JoinReply,
    key: &AgentKeys,
    now: u64,
) -> Result<Identity, ApiError> {
    let agent = VerifiedBinding::claimed_agent(&reply.binding)?;
    let row = sqlx::query(
        "SELECT identity, owner_identity, handle FROM agents
         WHERE id = $1 AND retirement IS NULL AND revocation IS NULL",
    )
    .bind(agent.as_str())
    .fetch_optional(&host.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let held = Identity::from_encoded(&row.try_get::<String, _>("identity")?)?;
    let held_owner = Identity::from_encoded(&row.try_get::<String, _>("owner_identity")?)?;
    let ours = held.sole_key().ok() == Some(&key.key) && held.seal_key() == Some(&key.seal);
    if !ours || !held_owner.is_unconfirmed_owner() {
        return Err(Error::ProofMismatch.into());
    }
    let address = format!(
        "{}{ADDRESS_SEPARATOR}{}",
        row.try_get::<String, _>("handle")?,
        host.domain
    );
    Ok(reply.check_confirming_for_keeping(&held, &address, now)?)
}

async fn read_answer(
    State(host): State<Arc<Host>>,
    Path((agent_key, owner_id)): Path<(String, String)>,
) -> Result<Json<JoinAnswer>, ApiError> {
    let answer: String = sqlx::query_scalar(
        "SELECT answer FROM join_answers WHERE agent_key = $1 AND owner_id = $2
         ORDER BY at DESC LIMIT 1",
    )
    .bind(&agent_key)
    .bind(&owner_id)
    .fetch_optional(&host.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(JoinAnswer {
        agent_key,
        answer,
        kept_at: None,
        ask_mac: None,
    }))
}

/// The answers kept where an agent's ask for its controls said, for an agent that asked by link and
/// doesn't know which owner answered. Only someone who saw the ask knows where that is, and each answer
/// carries their MAC by its ID, which the agent checks, so a stranger's answer is never among those it
/// counts. An owner replaces their own, so more than one there means the link reached more than one
/// owner, which the agent takes as none.
async fn read_asked(
    State(host): State<Arc<Host>>,
    Path((agent_key, kept_at)): Path<(String, String)>,
) -> Result<Json<JoinAnswers>, ApiError> {
    if !lower_hex(&kept_at, 32) {
        return Err(ApiError::NotFound);
    }
    let since = i64::try_from(unix_now())
        .unwrap_or(i64::MAX)
        .saturating_sub(KEEP_ANSWER_SECS);
    let rows = sqlx::query(
        "SELECT answer, ask_mac FROM join_answers
         WHERE agent_key = $1 AND kept_at = $2 AND at >= $3 ORDER BY at LIMIT $4",
    )
    .bind(&agent_key)
    .bind(&kept_at)
    .bind(since)
    .bind(MAX_ANSWERS_SHOWN)
    .fetch_all(&host.db)
    .await?;
    let mut answers = Vec::with_capacity(rows.len());
    for row in rows {
        answers.push(JoinAnswer {
            agent_key: agent_key.clone(),
            answer: row.try_get("answer")?,
            kept_at: None,
            ask_mac: Some(row.try_get("ask_mac")?),
        });
    }
    Ok(Json(JoinAnswers { answers }))
}

fn lower_hex(text: &str, digits: usize) -> bool {
    text.len() == digits
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Once an agent is registered, or its owner changes, what was signed for it before stops being kept:
/// an owner's answer is for an agent as it was when they answered.
pub async fn forget_answers(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &Identity,
) -> Result<(), sqlx::Error> {
    let (Some(seal), Ok(key)) = (agent.seal_key(), agent.sole_key()) else {
        return Ok(());
    };
    let keys = AgentKeys {
        key: key.clone(),
        seal: seal.clone(),
    };
    sqlx::query("DELETE FROM join_answers WHERE agent_key = $1")
        .bind(keys.encoded())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn written_for(domain: &str, open_signup: bool, closing: bool) -> String {
    let signups = if closing {
        CLOSING_WORDS
    } else if open_signup {
        OPEN_WORDS
    } else {
        CLOSED_WORDS
    };
    DOCUMENT
        .replace("{instructions}", AGENT_INSTRUCTIONS)
        .replace("{repository}", REPOSITORY)
        .replace("{protocol}", &PROTOCOL.to_string())
        .replace("{domain}", domain)
        .replace("{signups}", signups)
}

async fn document(State(host): State<Arc<Host>>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/markdown; charset=utf-8")],
        written_for(&host.domain, host.open_signup, host.closing.at().is_some()),
    )
}

//! Finds who's at an address for one of this host's agents, so its Signet never calls another
//! domain itself.
//!
//! This host's answer proves nothing: Signet checks it against the ID in the owner's rules, or the ID
//! that signed a message, and the binding the owner signed. Another host is called only where this
//! host may call it (see `destinations`), so a caller can't aim this at its network, and a host the
//! operator blocked, or didn't name on a private host, isn't called at all.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use splint_core::changes::VerifiedHistory;
use splint_core::contact_view::Heard;
use splint_core::host_api::{LOOKUP_PATH, LookupRequest, Resolved};
use splint_core::{SplintId, parse_address};
use sqlx::Row;

use crate::api_error::ApiError;
use crate::destinations::Call;
use crate::{Host, admission, contact_holds, inbox, registry};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS lookups (
        caller TEXT NOT NULL,
        at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS lookups_by_caller ON lookups (caller, at);
";

/// A contact is looked up once and then pinned, so nobody using this for its purpose comes near it.
/// It stops a stolen key using this host to pester its peers.
const MAX_LOOKUPS_PER_HOUR: i64 = 120;
/// Far more than an identity, an owner's identity, a binding and a whole history need.
const MAX_ANSWER_BYTES: usize = 256 * 1024;

pub fn routes() -> Router<Arc<Host>> {
    Router::new().route(LOOKUP_PATH, post(look_up))
}

async fn look_up(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Resolved>, ApiError> {
    let agent = inbox::authenticated_agent(&host, &headers, "POST", LOOKUP_PATH, &body).await?;
    let request: LookupRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("not a lookup"))?;
    count_a_call(&host, agent.as_str()).await?;
    let (handle, domain) =
        parse_address(&request.address).map_err(|_| ApiError::BadRequest("not an address"))?;
    let answer = if domain == host.domain {
        registry::resolved_here(&host, handle).await?
    } else {
        let call = host
            .call(domain, &format!("/.well-known/splint/agents/{handle}"))
            .map_err(|_| ApiError::NotFound)?;
        from_a_peer(call).await?
    };
    note_history(&host, &agent, &answer).await?;
    Ok(Json(answer))
}

/// What a Signet is about to go by when it asks after one of its contacts, which this host's copy of
/// that goes by too. Anything else in an answer says nothing.
async fn note_history(host: &Host, agent: &SplintId, answer: &Resolved) -> Result<(), ApiError> {
    let Ok(history) = VerifiedHistory::read(&answer.history) else {
        return Ok(());
    };
    let named = admission::rules_of(host, agent)
        .await?
        .is_some_and(|rules| rules.names(history.id()));
    if named && !history.is_empty() {
        contact_holds::take_history(host, agent, history, Heard::ByAsking).await?;
    }
    Ok(())
}

async fn count_a_call(host: &Host, caller: &str) -> Result<(), ApiError> {
    let row = sqlx::query(
        "SELECT count(*) AS calls FROM lookups WHERE caller = $1 AND at > now() - interval '1 hour'",
    )
    .bind(caller)
    .fetch_one(&host.db)
    .await?;
    if row.try_get::<i64, _>("calls")? >= MAX_LOOKUPS_PER_HOUR {
        return Err(ApiError::TooMany("too many lookups"));
    }
    sqlx::query("INSERT INTO lookups (caller) VALUES ($1)")
        .bind(caller)
        .execute(&host.db)
        .await?;
    Ok(())
}

/// Stops reading as soon as it passes the limit, because the peer decides how much it sends. A peer
/// that's down is a different answer from one saying nobody's there, so a caller can try again.
async fn from_a_peer(call: Call<'_>) -> Result<Resolved, ApiError> {
    let mut response = call.get().send().await.map_err(|_| ApiError::Unavailable)?;
    if response.status() == StatusCode::NOT_FOUND {
        return Err(ApiError::NotFound);
    }
    if !response.status().is_success() {
        return Err(ApiError::Unavailable);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Unavailable)? {
        if body.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(ApiError::Unavailable);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ApiError::Unavailable)
}

pub async fn run_cleanup(host: Arc<Host>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        let cleared = sqlx::query("DELETE FROM lookups WHERE at < now() - interval '1 hour'")
            .execute(&host.db)
            .await;
        if let Err(error) = cleared {
            tracing::warn!(%error, "couldn't clear old lookups");
        }
    }
}

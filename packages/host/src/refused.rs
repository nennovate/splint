//! What this host refused on an agent's behalf, for its owner to read. It's this host's own word, as a
//! host can leave out anything it likes, so it adds to what Signet writes down and doesn't replace it.
//! It's fixed words and IDs with no content, and a repeat only adds to a count.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use splint_core::host_api::{HostRefusal, HostRefusals};
use splint_core::{SplintId, unix_now};
use sqlx::Row;

use crate::api_error::ApiError;
use crate::owner_api::reader::{owner_of_agent, owner_reading};
use crate::{Host, inbox};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS refused (
        agent TEXT NOT NULL,
        way TEXT NOT NULL,
        from_id TEXT NOT NULL DEFAULT '',
        reason TEXT NOT NULL,
        at BIGINT NOT NULL,
        count BIGINT NOT NULL DEFAULT 1,
        PRIMARY KEY (agent, way, from_id, reason)
    );
";

const REFUSED_PATH: &str = "/v0/refused";
const MAX_KEPT_PER_AGENT: i64 = 200;

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route(REFUSED_PATH, get(read))
        .route(&format!("{REFUSED_PATH}/{{agent}}"), get(read_for_owner))
}

/// Never fails what it's written for: what was refused stays refused whether or not this is saved.
async fn note(host: &Host, agent: &SplintId, way: &str, from: Option<&SplintId>, reason: &str) {
    let now = i64::try_from(unix_now()).unwrap_or(i64::MAX);
    let saved = sqlx::query(
        "WITH kept AS (
             INSERT INTO refused (agent, way, from_id, reason, at) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (agent, way, from_id, reason)
             DO UPDATE SET at = EXCLUDED.at, count = refused.count + 1
         )
         DELETE FROM refused WHERE agent = $1 AND (way, from_id, reason) IN (
             SELECT way, from_id, reason FROM refused WHERE agent = $1
             ORDER BY at DESC OFFSET $6
         )",
    )
    .bind(agent.as_str())
    .bind(way)
    .bind(from.map_or("", SplintId::as_str))
    .bind(reason)
    .bind(now)
    .bind(MAX_KEPT_PER_AGENT)
    .execute(&host.db)
    .await;
    if let Err(error) = saved {
        tracing::warn!(%error, "couldn't write down what was refused");
    }
}

/// Something this agent's key signed, that this host wouldn't send on.
pub async fn going_out(host: &Host, agent: &SplintId, error: &ApiError) {
    if let Some(word) = error.refusal_word() {
        note(host, agent, "out", None, word).await;
    }
}

/// Something that reached this agent's rules and went no further.
pub async fn coming_in(host: &Host, agent: &SplintId, from: &SplintId) {
    note(host, agent, "in", Some(from), "not_admitted").await;
}

async fn read(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
) -> Result<Json<HostRefusals>, ApiError> {
    let agent = inbox::authenticated_agent(&host, &headers, "GET", REFUSED_PATH, b"").await?;
    Ok(Json(refused_for(&host, agent.as_str()).await?))
}

/// The same for that agent's owner, on their page, by its session or their own key.
async fn read_for_owner(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    Path(agent): Path<String>,
) -> Result<Json<HostRefusals>, ApiError> {
    let owner = owner_of_agent(&host, &agent)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let path = format!("{REFUSED_PATH}/{agent}");
    owner_reading(&host, &headers, &owner, "GET", &path, b"")?;
    Ok(Json(refused_for(&host, &agent).await?))
}

async fn refused_for(host: &Host, agent: &str) -> Result<HostRefusals, ApiError> {
    let rows = sqlx::query(
        "SELECT way, from_id, reason, at, count FROM refused WHERE agent = $1
         ORDER BY at DESC LIMIT $2",
    )
    .bind(agent)
    .bind(MAX_KEPT_PER_AGENT)
    .fetch_all(&host.db)
    .await?;
    let refused = rows
        .iter()
        .map(|row| {
            let from: String = row.try_get("from_id")?;
            Ok(HostRefusal {
                at: u64::try_from(row.try_get::<i64, _>("at")?).unwrap_or_default(),
                way: row.try_get("way")?,
                from: (!from.is_empty()).then_some(from),
                reason: row.try_get("reason")?,
                count: row.try_get("count")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    Ok(HostRefusals { refused })
}

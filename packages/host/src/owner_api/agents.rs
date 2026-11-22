//! The list of an owner's agents their computer keeps here, and the owner's ID for a computer that has
//! only its name. See "Owner API" in `docs/protocol.md`.
//!
//! The list is sealed to the owner and signed by them, so this host keeps bytes it can't read and can
//! only hold back the newest. It keeps one per owner, for an owner with an agent here, or an agent here
//! with no controls yet that they're setting up from its link. An owner with no agent here costs
//! nothing to make, so new lists of such owners from one network, or from all, are capped by the day,
//! and nobody can fill this host's room for good.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use splint_core::host_api::{
    HeldOwnerAgents, KnownOwner, ListsByHandle, OWNER_AGENTS_PATH, OWNER_HANDLES_PATH, OWNERS_PATH,
    OwnerAgentsKept, OwnerAgentsNotice,
};
use splint_core::owner_agents::VerifiedOwnerAgents;
use splint_core::{Error, Identity, SplintId, unix_now};
use sqlx::Row;

use super::reader::owner_reading;
use crate::api_error::ApiError;
use crate::{Host, admission, registry};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS owner_agent_lists (
        owner_id TEXT PRIMARY KEY,
        owner_identity TEXT NOT NULL,
        list TEXT NOT NULL,
        seq BIGINT NOT NULL,
        source TEXT NOT NULL,
        handle TEXT NOT NULL
    );
    ALTER TABLE owner_agent_lists ADD COLUMN IF NOT EXISTS kept_at BIGINT NOT NULL DEFAULT 0;
    CREATE INDEX IF NOT EXISTS owner_agent_lists_source ON owner_agent_lists (source);
    CREATE INDEX IF NOT EXISTS owner_agent_lists_handle ON owner_agent_lists (handle);
";

/// Lists given for one handle. Only a list the owner's own key signed counts for whoever looks one up,
/// so others naming the same handle can only crowd it out, which this bounds what it costs to check.
const MAX_LISTS_PER_HANDLE: i64 = 8;

/// New lists of owners with no agent here from one network in a day, which a household never nears.
const NEW_LISTS_WITHOUT_AGENTS_PER_SOURCE_PER_DAY: i64 = 20;
/// And from everywhere, which bounds what a host keeps for owners it has no agent of.
const NEW_LISTS_WITHOUT_AGENTS_PER_DAY: i64 = 2000;
const DAY_SECS: i64 = 24 * 60 * 60;

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route(&format!("{OWNERS_PATH}/{{owner}}"), get(known))
        .route(
            &format!("{OWNER_AGENTS_PATH}/{{owner}}"),
            get(read_list).put(keep_list),
        )
        .route(&format!("{OWNER_HANDLES_PATH}/{{handle}}"), get(by_handle))
}

/// For `splint recover`, which knows only the handle its recovery code gives, and for lists a passkey
/// owner's page kept under their passkey's handle before hosts stopped serving it. A list is sealed, so
/// this tells whoever knows a handle only which owner it's said to be, and their ID is public. Those whose agents are here come first, as a list someone keeps only to crowd out
/// another's has no agent behind it.
async fn by_handle(
    State(host): State<Arc<Host>>,
    Path(handle): Path<String>,
) -> Result<Json<ListsByHandle>, ApiError> {
    let rows = sqlx::query(
        "SELECT owner_identity, list FROM owner_agent_lists lists WHERE handle = $1
         ORDER BY EXISTS (SELECT 1 FROM agents WHERE agents.owner_id = lists.owner_id) DESC, seq DESC
         LIMIT $2",
    )
    .bind(&handle)
    .bind(MAX_LISTS_PER_HANDLE)
    .fetch_all(&host.db)
    .await?;
    let mut lists = Vec::with_capacity(rows.len());
    for row in rows {
        lists.push(HeldOwnerAgents {
            owner_identity: row.try_get("owner_identity")?,
            list: row.try_get("list")?,
        });
    }
    if lists.is_empty() {
        return Err(ApiError::NotFound);
    }
    Ok(Json(ListsByHandle { lists }))
}

/// The newest copy of this owner's ID held here, from the agents acting for them and their list. Two
/// that part ways mean a stolen backup, which nothing here can settle, so neither is given.
pub async fn known_owner(host: &Host, owner: &str) -> Result<Option<Identity>, ApiError> {
    let mut held: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT owner_identity FROM agents WHERE owner_id = $1")
            .bind(owner)
            .fetch_all(&host.db)
            .await?;
    let listed: Option<String> =
        sqlx::query_scalar("SELECT owner_identity FROM owner_agent_lists WHERE owner_id = $1")
            .bind(owner)
            .fetch_optional(&host.db)
            .await?;
    held.extend(listed);
    let mut newest: Option<Identity> = None;
    for text in held {
        let copy = Identity::from_encoded(&text)?;
        newest = Some(match newest {
            Some(newest) => newest.newest_of(&copy).map_err(|_| ApiError::Conflict)?,
            None => copy,
        });
    }
    Ok(newest)
}

/// For a computer that has only the owner's ID, to find their keys and sealing key.
/// An ID is public, and anyone can ask for one by its name.
async fn known(
    State(host): State<Arc<Host>>,
    Path(owner): Path<String>,
) -> Result<Json<KnownOwner>, ApiError> {
    let identity = known_owner(&host, &owner)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(KnownOwner {
        owner_identity: identity.encoded(),
    }))
}

async fn read_list(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    Path(owner): Path<String>,
) -> Result<Json<HeldOwnerAgents>, ApiError> {
    let identity = known_owner(&host, &owner)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let path = format!("{OWNER_AGENTS_PATH}/{owner}");
    owner_reading(&host, &headers, &identity, "GET", &path, b"")?;
    let list: String = sqlx::query_scalar("SELECT list FROM owner_agent_lists WHERE owner_id = $1")
        .bind(&owner)
        .fetch_optional(&host.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(HeldOwnerAgents {
        owner_identity: identity.encoded(),
        list,
    }))
}

/// Kept by the owner's signature alone, under their ID as it is now, if it's later than the one held.
/// The same list again answers as before, so a page can retry.
async fn keep_list(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    Path(owner): Path<String>,
    Json(notice): Json<OwnerAgentsNotice>,
) -> Result<Json<OwnerAgentsKept>, ApiError> {
    let identity = Identity::from_encoded(&notice.owner_identity)?;
    if identity.id().as_str() != owner {
        return Err(Error::WrongSigner.into());
    }
    if let Some(known) = known_owner(&host, &owner).await? {
        if !identity.extends(&known) {
            return Err(ApiError::OutOfDate("that identity is out of date"));
        }
        // A copy with a key added or removed counts for this owner's agents here too, as one
        // carried to `/v0/recoveries` does, so what a removed key signed goes before this is kept.
        if identity.replaces(&known)? {
            match registry::take_identity(&host, &identity).await {
                Ok(()) | Err(ApiError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
    }
    let list = VerifiedOwnerAgents::verify(&notice.list, &identity, &host.domain, unix_now())?;
    let seq = i64::try_from(list.seq()).map_err(|_| Error::Malformed)?;
    let replaced = sqlx::query(
        "UPDATE owner_agent_lists SET owner_identity = $2, list = $3, seq = $4, handle = $5
         WHERE owner_id = $1 AND seq < $4",
    )
    .bind(&owner)
    .bind(identity.encoded())
    .bind(list.compact())
    .bind(seq)
    .bind(list.handle())
    .execute(&host.db)
    .await?;
    if replaced.rows_affected() > 0 {
        return Ok(Json(OwnerAgentsKept { seq: list.seq() }));
    }
    if let Some(held) = held_list(&host, &owner).await? {
        return answer_for_held(&held, &list);
    }
    let room = room_for_owner(&host, &owner, notice.agent.as_ref()).await?;
    let source = registry::source_of(&headers);
    let now = i64::try_from(unix_now()).unwrap_or(i64::MAX);
    // A list with no agent here counts for a day after it was first kept, and not once an agent here
    // acts for its owner.
    let count_and_add = sqlx::query(
        "INSERT INTO owner_agent_lists (owner_id, owner_identity, list, seq, source, handle, kept_at)
         SELECT $1, $2, $3, $4, $5, $7, $8
         WHERE $6 OR (
             (SELECT count(*) FROM owner_agent_lists lists WHERE kept_at > $8 - $11
              AND NOT EXISTS (SELECT 1 FROM agents WHERE agents.owner_id = lists.owner_id)) < $9
             AND (SELECT count(*) FROM owner_agent_lists lists WHERE source = $5
              AND kept_at > $8 - $11
              AND NOT EXISTS (SELECT 1 FROM agents WHERE agents.owner_id = lists.owner_id)) < $10)
         ON CONFLICT (owner_id) DO NOTHING",
    )
    .bind(&owner)
    .bind(identity.encoded())
    .bind(list.compact())
    .bind(seq)
    .bind(&source)
    .bind(room == Room::Agent)
    .bind(list.handle())
    .bind(now)
    .bind(NEW_LISTS_WITHOUT_AGENTS_PER_DAY)
    .bind(NEW_LISTS_WITHOUT_AGENTS_PER_SOURCE_PER_DAY)
    .bind(DAY_SECS);
    let added = admission::counted_alone(&host, "owner_agent_lists", count_and_add).await?;
    if added.rows_affected() > 0 {
        return Ok(Json(OwnerAgentsKept { seq: list.seq() }));
    }
    match held_list(&host, &owner).await? {
        Some(held) => answer_for_held(&held, &list),
        None => Err(ApiError::TooMany(
            "this host is keeping all the lists it can for owners with no agent here",
        )),
    }
}

struct HeldList {
    list: String,
    seq: i64,
}

async fn held_list(host: &Host, owner: &str) -> Result<Option<HeldList>, ApiError> {
    let row = sqlx::query("SELECT list, seq FROM owner_agent_lists WHERE owner_id = $1")
        .bind(owner)
        .fetch_optional(&host.db)
        .await?;
    Ok(match row {
        Some(row) => Some(HeldList {
            list: row.try_get("list")?,
            seq: row.try_get("seq")?,
        }),
        None => None,
    })
}

/// The same list again is taken. Any other at or below what's held would bring back an older one.
fn answer_for_held(
    held: &HeldList,
    list: &VerifiedOwnerAgents,
) -> Result<Json<OwnerAgentsKept>, ApiError> {
    if held.list == list.compact() {
        return Ok(Json(OwnerAgentsKept {
            seq: u64::try_from(held.seq).unwrap_or_default(),
        }));
    }
    Err(ApiError::Conflict)
}

#[derive(PartialEq, Eq)]
enum Room {
    Agent,
    StandInsLink,
}

/// Why this host would keep a new owner's list: an agent here acts for them, or they're setting one up
/// from the link of an agent here whose owner hasn't confirmed. Someone new whom an agent's link
/// brought here has no agent yet, and their list goes first, as it holds the backup their answer
/// commits the agent to. Room is all the agent named gives: its ID is
/// public, and it gets an owner only from an answer to its own ask.
async fn room_for_owner(
    host: &Host,
    owner: &str,
    setting_up: Option<&SplintId>,
) -> Result<Room, ApiError> {
    let row = sqlx::query(
        "SELECT
             EXISTS (SELECT 1 FROM agents WHERE owner_id = $1 AND retirement IS NULL) AS agent,
             EXISTS (SELECT 1 FROM agents WHERE id = $2 AND stand_in
                 AND retirement IS NULL AND revocation IS NULL) AS setting_up",
    )
    .bind(owner)
    .bind(setting_up.map(SplintId::as_str))
    .fetch_one(&host.db)
    .await?;
    if row.try_get("agent")? {
        Ok(Room::Agent)
    } else if row.try_get("setting_up")? {
        Ok(Room::StandInsLink)
    } else {
        Err(ApiError::Forbidden(
            "this host keeps lists for owners with an agent here, or adding one",
        ))
    }
}

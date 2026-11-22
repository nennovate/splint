//! What a host does about an agent's history of material changes. See `docs/protocol.md`.
//!
//! It keeps a copy of each of its agents' histories, so a contact can ask for one and a lost Signet can
//! get it back. It can only withhold: a history checks out with nothing but itself, and one that parts
//! ways from what's held is refused here as it is at a contact.
//!
//! A notice can go to anyone this agent's owner has listed, past or present, even with no rules in
//! force, because a replaced owner key clears them and that's when a contact most needs to hear. It
//! carries only a history that checks out, so it's no way for a stolen key to say anything else.
//!
//! An owner's recovery goes on to the hosts its agents have sent to and the hosts the operator named,
//! so a partner whose rules name that owner hears at once, whether or not anyone writes. Anyone can
//! carry a recovery, and only a backup key can make one.
//!
//! A contact's own host may be hostile, and carry on with a key its owner gave up or retired. So what
//! ends a key also reaches the hosts of those who deal with it, from its own host or from anyone else,
//! and each of them checks it by itself. This is what keeps a stolen key's reach from resting on the
//! code of the host it runs through.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, put};
use splint_core::changes::{Against, HistoryDocument, VerifiedHistory, notice_in};
use splint_core::contact_view::Heard;
use splint_core::host_api::{HistoryNotice, KnownOwners, RetirementNotice};
use splint_core::rules::VerifiedRules;
use splint_core::{
    Error, Identity, SplintId, VerifiedBinding, VerifiedEnvelope, VerifiedStop, parse_address,
};
use sqlx::{Postgres, Row, Transaction};

use crate::admission::{Arrival, SenderRecord};
use crate::api_error::ApiError;
use crate::log_limit::LogLimit;
use crate::{Host, answers, contact_holds, database, delivery, inbox};

pub const SCHEMA: &str = "
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS history TEXT NOT NULL DEFAULT '';
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS moved_away_to TEXT;
    ALTER TABLE outbound ADD COLUMN IF NOT EXISTS is_notice BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS change_audience (
        agent TEXT NOT NULL,
        peer TEXT NOT NULL,
        PRIMARY KEY (agent, peer)
    );
    CREATE TABLE IF NOT EXISTS listed_owners (
        agent TEXT NOT NULL,
        owner TEXT NOT NULL,
        PRIMARY KEY (agent, owner)
    );
    CREATE INDEX IF NOT EXISTS listed_owners_owner ON listed_owners (owner);
    CREATE TABLE IF NOT EXISTS moved_contacts (
        id TEXT PRIMARY KEY,
        domain TEXT NOT NULL,
        history TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS recoveries_to_pass_on (
        peer TEXT NOT NULL,
        id TEXT NOT NULL,
        identity TEXT NOT NULL,
        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        attempts INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (peer, id)
    );
    CREATE TABLE IF NOT EXISTS stops_to_pass_on (
        peer TEXT NOT NULL,
        id TEXT NOT NULL,
        notice TEXT NOT NULL,
        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        attempts INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (peer, id)
    );
    CREATE TABLE IF NOT EXISTS contact_stops (
        agent TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        owner_recoveries INTEGER NOT NULL,
        notice TEXT NOT NULL,
        ended BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS contact_stops_owner ON contact_stops (owner);
";

const KNOWN_OWNERS_PATH: &str = "/v0/known-owners";
const HISTORY_PATH: &str = "/v0/changes";
const RECOVERIES_PATH: &str = "/v0/recoveries";
const RETIREMENTS_PATH: &str = "/v0/retirements";
/// A week of trying, at most every 5 minutes. A peer down for longer hears from the next message.
const MAX_ATTEMPTS: i32 = 2100;
const MAX_BACKOFF_SECS: i32 = 300;
const PASS_ON_INTERVAL: Duration = Duration::from_secs(1);
/// Far past what one owner lists. It's a limit on the table, not a number anyone should reach.
const MAX_AUDIENCE_PER_AGENT: i64 = 10_000;
/// Owners' copies, and stops, in one page of what an agent hears, where that many fit.
const PAGE_SIZE: i64 = 100;
static HISTORY_LOGS: HistoryLogs = HistoryLogs::new();

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route(HISTORY_PATH, put(take_history))
        .route(KNOWN_OWNERS_PATH, get(known_owners))
        .route(
            &format!("{KNOWN_OWNERS_PATH}/after/{{after}}"),
            get(known_owners_after),
        )
        .route(&format!("{RETIREMENTS_PATH}/{{agent}}"), get(retirement_of))
}

/// The retirement this host holds for an agent, as it keeps it for that agent's contacts: what its
/// owner signed, with the owner's ID and binding it checks under. A lookup answers 404 for a retired
/// agent as for one never here, so this is how a retired agent's own side learns why, and it goes by
/// the owner's signature, never by this host's word. It's the same notice every peer was given, so it
/// tells anyone who asks nothing more than those hosts already know. One a recovery of its owner ended
/// is gone.
async fn retirement_of(
    State(host): State<Arc<Host>>,
    Path(agent): Path<String>,
) -> Result<Json<RetirementNotice>, ApiError> {
    let agent: SplintId = serde_json::from_value(serde_json::Value::String(agent))
        .ok()
        .filter(SplintId::is_well_formed)
        .ok_or(ApiError::BadRequest("that isn't an agent's ID"))?;
    let held: Option<String> =
        sqlx::query_scalar("SELECT notice FROM contact_stops WHERE agent = $1 AND NOT ended")
            .bind(agent.as_str())
            .fetch_optional(&host.db)
            .await?;
    let held = held.ok_or(ApiError::NotFound)?;
    let notice: RetirementNotice = serde_json::from_str(&held).map_err(|_| Error::Malformed)?;
    Ok(Json(notice))
}

/// Takes one of this host's agents' histories, from anyone, since it checks out on its own or not at
/// all. A hostile sender can only bring what the agent's keys signed. One whose newest address is on
/// another host marks the agent moved away: it's found here no more, and its mail isn't taken.
///
/// Anyone can send one, as often as their call limit lets them, so nothing is checked until it can
/// change what's held. The ID is a hash of its first event, so one that isn't here costs a lookup, and
/// a copy that adds nothing to what's held costs only the recoveries that really happened.
async fn take_history(
    State(host): State<Arc<Host>>,
    Json(notice): Json<HistoryNotice>,
) -> Result<(), ApiError> {
    let document = HistoryDocument::parse(&notice.history)?;
    let id = Identity::claimed_id(&document.identity)?;
    let mut transaction = database::begin(&host.db).await?;
    let held: Option<String> =
        sqlx::query_scalar("SELECT history FROM agents WHERE id = $1 FOR UPDATE")
            .bind(id.as_str())
            .fetch_optional(&mut *transaction)
            .await?;
    let held = held.ok_or(ApiError::NotFound)?;
    let Some(new) = to_keep(&held, document, &HISTORY_LOGS)? else {
        return Ok(());
    };
    // Set from the newest address on every copy kept, and cleared when that's here, so a copy replayed
    // from a move the agent has since come back from is undone by the agent's own next one.
    let away = new
        .address()
        .filter(|address| parse_address(address).is_ok_and(|(_, domain)| domain != host.domain));
    sqlx::query("UPDATE agents SET history = $2, moved_away_to = $3 WHERE id = $1")
        .bind(new.id().as_str())
        .bind(new.encoded()?)
        .bind(away)
        .execute(&mut *transaction)
        .await?;
    if let Some(address) = away {
        tracing::info!(agent = %new.id(), %address, "an agent here moved to another host");
    }
    transaction.commit().await?;
    Ok(())
}

/// How often refusing a copy of a history is logged. Apart from `to_keep`, so a test can count its own.
struct HistoryLogs {
    /// Anyone can send an older copy of a history they've been shown, or one that doesn't check out.
    refused: LogLimit,
    /// Each hosted agent can mint forks of its own history with its own keys, as often as it likes,
    /// so each is counted for that agent alone, and one agent's can't hide another's.
    forked: LogLimit,
}

impl HistoryLogs {
    const fn new() -> Self {
        Self {
            refused: LogLimit::new(),
            forked: LogLimit::new(),
        }
    }

    fn refused(&self) {
        if let Some(count) = self.refused.due() {
            tracing::warn!(
                count,
                "refused histories that don't follow the one held, since the last line"
            );
        }
    }
}

/// What a copy sent for one of this host's agents makes of what's held for it: nothing, or a history
/// to keep instead. What's held checked out when it was taken, and only `take_history` writes it, so a
/// copy is checked only once it could change that.
fn to_keep(
    held: &str,
    document: HistoryDocument,
    logs: &HistoryLogs,
) -> Result<Option<VerifiedHistory>, ApiError> {
    if !held.is_empty() {
        match HistoryDocument::parse(held)?.against_unchecked(&document)? {
            Against::Same => return Ok(None),
            Against::Extends => {}
            Against::Behind => {
                logs.refused();
                return Err(ApiError::Forbidden("that doesn't follow what's held"));
            }
            Against::Rewrites => {
                // A fork is never kept, so it's never checked in full, however often it comes back.
                // Its newest event carrying this ID's signature is one signature, and enough to say
                // that it took this ID's keys, and isn't noise anyone could send.
                match document.signed_by_its_agent() {
                    Ok(agent) => {
                        if let Some(count) = logs.forked.due_for(agent.id().as_str()) {
                            tracing::warn!(id = %agent.id(), count, "a history that parts ways from the one held, its newest event signed by its keys");
                        }
                    }
                    Err(_) => logs.refused(),
                }
                return Err(ApiError::Forbidden("that doesn't follow what's held"));
            }
        }
    }
    Ok(Some(VerifiedHistory::verify(document)?))
}

/// Copies of the owners this agent's rules' filter names and of those it deals with, and the stops held
/// for them, for a Signet to take in, with its own owner's copy as this host holds it, so a key its
/// owner added or removed reaches it without the owner's device telling it. It can only bring what
/// backup keys and owners signed, and a Signet checks all of it again.
async fn known_owners(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    known_owners_page(&host, &headers, KNOWN_OWNERS_PATH, After::Start).await
}

/// The same, from after the place a page before said to go on from.
async fn known_owners_after(
    State(host): State<Arc<Host>>,
    Path(after): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let from = match after.split_once('.') {
        Some(("o", owner)) => After::Owner(owner.to_owned()),
        Some(("s", agent)) => After::Stop(agent.to_owned()),
        _ => return Err(ApiError::BadRequest("not a place in this list")),
    };
    let path = format!("{KNOWN_OWNERS_PATH}/after/{after}");
    known_owners_page(&host, &headers, &path, from).await
}

/// Where a page of what an agent hears of owners starts: its own owner's copy, then the other owners'
/// by ID, then the stops by the agent each is for.
enum After {
    Start,
    Owner(String),
    Stop(String),
}

/// One page of the owners this agent goes by and the stops that stand for its contacts. Whoever an
/// agent deals with adds to these, as to who hears its changes: who its rules list, who it wrote to
/// or who reached it, and who it agreed with by invite, or a contact agreed by invite would carry on
/// with an agent its owner retired. A copy of an owner can be tens of kilobytes, so only how long each is
/// gets read first, and room is taken for the ones that fit before they're read.
async fn known_owners_page(
    host: &Host,
    headers: &HeaderMap,
    path: &str,
    from: After,
) -> Result<Response, ApiError> {
    // A revoked agent's Signet still hears its owner's keys, so a key removed at the host, which may
    // have signed the revocation, stops counting there too.
    let agent = inbox::authenticated_agent_even_if_revoked(host, headers, "GET", path, b"").await?;
    let most_rows = usize::try_from(PAGE_SIZE).unwrap_or(usize::MAX);
    let mut bytes = 0_usize;
    let first_page = matches!(from, After::Start);
    if first_page {
        let own: Option<i64> = sqlx::query_scalar(
            "SELECT octet_length(owner_identity)::bigint FROM agents WHERE id = $1",
        )
        .bind(agent.as_str())
        .fetch_optional(&host.db)
        .await?;
        bytes = answers::page_of(own.map(|size| ((), size)), 1, usize::MAX, true).bytes;
    }
    let (owners_after, mut stops_after) = match from {
        After::Start => (Some(String::new()), Some(String::new())),
        After::Owner(owner) => (Some(owner), Some(String::new())),
        After::Stop(agent) => (None, Some(agent)),
    };
    let mut owners = Vec::new();
    let mut next = None;
    if let Some(after) = owners_after {
        let sized: Vec<(String, i64)> = sqlx::query_as(
            "SELECT id, octet_length(identity)::bigint FROM known_owners
             WHERE id COLLATE \"C\" > $2 AND id IN (
                 SELECT owner FROM listed_owners WHERE agent = $1
                 UNION SELECT peer FROM change_audience WHERE agent = $1
                 UNION SELECT peer FROM reached WHERE agent = $1
                 UNION SELECT contact_stops.owner FROM contact_stops WHERE contact_stops.agent IN (
                     SELECT peer FROM change_audience WHERE agent = $1
                     UNION SELECT peer FROM reached WHERE agent = $1
                     UNION SELECT peer FROM met WHERE agent = $1
                     UNION SELECT peer FROM agreed_contacts WHERE agent = $1
                 )
             )
             ORDER BY id COLLATE \"C\" LIMIT $3",
        )
        .bind(agent.as_str())
        .bind(&after)
        .bind(PAGE_SIZE + 1)
        .fetch_all(&host.db)
        .await?;
        let room_left = answers::PAGE_BYTES.saturating_sub(bytes);
        let page = answers::page_of(sized, most_rows, room_left, bytes == 0);
        bytes = bytes.saturating_add(page.bytes);
        if page.more {
            let last = page.keys.last().unwrap_or(&after);
            next = Some(format!("o.{last}"));
            stops_after = None;
        }
        owners = page.keys;
    }
    let mut stopped = Vec::new();
    if let Some(after) = stops_after {
        let sized: Vec<(String, i64)> = sqlx::query_as(
            "SELECT agent, octet_length(notice)::bigint FROM contact_stops
             WHERE NOT ended AND agent COLLATE \"C\" > $2 AND agent IN (
                 SELECT peer FROM change_audience WHERE agent = $1
                 UNION SELECT peer FROM reached WHERE agent = $1
                 UNION SELECT peer FROM met WHERE agent = $1
                 UNION SELECT peer FROM agreed_contacts WHERE agent = $1
             )
             ORDER BY agent COLLATE \"C\" LIMIT $3",
        )
        .bind(agent.as_str())
        .bind(&after)
        .bind(PAGE_SIZE + 1)
        .fetch_all(&host.db)
        .await?;
        let room_left = answers::PAGE_BYTES.saturating_sub(bytes);
        let rows_left = most_rows.saturating_sub(owners.len());
        let page = answers::page_of(sized, rows_left, room_left, bytes == 0);
        bytes = bytes.saturating_add(page.bytes);
        if page.more {
            let last = page.keys.last().unwrap_or(&after);
            next = Some(format!("s.{last}"));
        }
        stopped = page.keys;
    }
    let room = host.answers.take(headers, bytes)?;
    let mut identities: Vec<String> =
        sqlx::query_scalar("SELECT identity FROM known_owners WHERE id = ANY($1)")
            .bind(&owners)
            .fetch_all(&host.db)
            .await?;
    if first_page {
        let own: Option<String> =
            sqlx::query_scalar("SELECT owner_identity FROM agents WHERE id = $1")
                .bind(agent.as_str())
                .fetch_optional(&host.db)
                .await?;
        identities.extend(own);
    }
    let stops: Vec<String> =
        sqlx::query_scalar("SELECT notice FROM contact_stops WHERE NOT ended AND agent = ANY($1)")
            .bind(&stopped)
            .fetch_all(&host.db)
            .await?;
    let stops = stops
        .iter()
        .filter_map(|text| serde_json::from_str(text).ok())
        .collect();
    room.json(&KnownOwners {
        identities,
        stops,
        next,
    })
}

/// Keeps who these rules list, so that this agent's contacts can be told of a change later, and which
/// owners their filter names, so that a recovery of one counts here as soon as it's heard.
pub async fn note_rules(
    host: &Host,
    agent: &SplintId,
    rules: &VerifiedRules,
) -> Result<(), sqlx::Error> {
    for peer in rules.listed() {
        add_to_audience(host, agent, peer).await?;
    }
    let mut transaction = database::begin(&host.db).await?;
    sqlx::query("DELETE FROM listed_owners WHERE agent = $1")
        .bind(agent.as_str())
        .execute(&mut *transaction)
        .await?;
    for owner in &rules.reach().inbound.filter.owners {
        sqlx::query(
            "INSERT INTO listed_owners (agent, owner) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(agent.as_str())
        .bind(owner.as_str())
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await
}

async fn add_to_audience(
    host: &Host,
    agent: &SplintId,
    peer: &SplintId,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO change_audience (agent, peer) SELECT $1, $2
         WHERE (SELECT count(*) FROM change_audience WHERE agent = $1) < $3
         ON CONFLICT DO NOTHING",
    )
    .bind(agent.as_str())
    .bind(peer.as_str())
    .bind(MAX_AUDIENCE_PER_AGENT)
    .execute(&host.db)
    .await?;
    Ok(())
}

/// For when an agent gets a new owner, which clears who it dealt with: they still have to be told.
pub async fn keep_audience(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
) -> Result<(), sqlx::Error> {
    for from in ["met", "reached"] {
        sqlx::query(&format!(
            "INSERT INTO change_audience (agent, peer)
             SELECT agent, peer FROM {from} WHERE agent = $1 ON CONFLICT DO NOTHING"
        ))
        .bind(agent.as_str())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

/// Refuses a notice that isn't this agent's own history, or to anyone its owner never listed and it
/// never dealt with, or who's blocked now. So a stolen key has no way to reach a stranger with one.
pub async fn check_may_notify(
    host: &Host,
    rules: Option<&VerifiedRules>,
    envelope: &VerifiedEnvelope,
) -> Result<(), ApiError> {
    let document = notice_in(envelope.body()).ok_or(ApiError::BadRequest("not a notice"))?;
    let history = VerifiedHistory::verify(document)?;
    if history.id() != envelope.sender() {
        return Err(ApiError::Forbidden("that isn't this agent's history"));
    }
    if rules.is_some_and(|rules| rules.blocks(envelope.recipient())) {
        return Err(ApiError::Forbidden("the recipient isn't a contact"));
    }
    // A contact this agent agreed with by itself hears too, written to yet or not.
    let known: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM change_audience WHERE agent = $1 AND peer = $2)
             OR EXISTS (SELECT 1 FROM met WHERE agent = $1 AND peer = $2)
             OR EXISTS (SELECT 1 FROM reached WHERE agent = $1 AND peer = $2)
             OR EXISTS (SELECT 1 FROM agreed_contacts WHERE agent = $1 AND peer = $2)",
    )
    .bind(envelope.sender().as_str())
    .bind(envelope.recipient().as_str())
    .fetch_one(&host.db)
    .await?;
    if known {
        Ok(())
    } else {
        Err(ApiError::Forbidden("the recipient isn't a contact"))
    }
}

/// Takes in what a notice arriving here says, as far as a host goes by any of it. `None` means it's
/// for the normal check to judge, and anything that doesn't check out goes no further.
pub async fn take_notice(
    host: &Host,
    rules: Option<&VerifiedRules>,
    envelope: &VerifiedEnvelope,
    record: &SenderRecord,
    document: HistoryDocument,
) -> Result<Option<Arrival>, ApiError> {
    // Only someone this agent has reason to hear about gets a history checked at all, which is what
    // keeps this from being a way to make a host do work. With no rules nothing can be judged yet.
    let recipient = envelope.recipient();
    let sender = envelope.sender();
    let row = sqlx::query("SELECT owner, binding_seq FROM reached WHERE agent = $1 AND peer = $2")
        .bind(recipient.as_str())
        .bind(sender.as_str())
        .fetch_optional(&host.db)
        .await?;
    let (reached_as, held_seq) = match row {
        Some(row) => (
            Some(row.try_get::<String, _>("owner")?),
            row.try_get::<i64, _>("binding_seq")?,
        ),
        None => (None, 0),
    };
    let named = rules.is_some_and(|rules| rules.names(sender));
    // A contact this agent agreed with by itself is held to its changes as a named one is.
    let agreed = crate::invites::agreed_address(host, recipient, sender)
        .await?
        .is_some();
    if rules.is_some()
        && !named
        && !agreed
        && reached_as.is_none()
        && !invited(host, recipient, sender).await?
    {
        return Ok(Some(Arrival::dropped()));
    }
    let Ok(history) = VerifiedHistory::verify(document) else {
        return Ok(Some(Arrival::dropped()));
    };
    if history.id() != sender {
        return Ok(Some(Arrival::dropped()));
    }
    if named || agreed || invited(host, recipient, sender).await? {
        contact_holds::take_history(host, recipient, history.clone(), Heard::ByNotice).await?;
    }
    // Only from the host it says it's on, since that's the one a contact's owner will now go by.
    let moved_here = history
        .address()
        .and_then(|address| parse_address(address).ok())
        .is_some_and(|(_, domain)| domain == record.relayed_by);
    // A contact agreed by invite, or met by an invitation, is followed as a named one is, or what the
    // new host relays from it is dropped as relayed from elsewhere.
    if moved_here && (named || agreed || invited(host, recipient, sender).await?) {
        learn_move(host, &history).await?;
    }
    let (Some(reached_as), Some(owner), Some(rules)) = (reached_as, history.owner(), rules) else {
        return Ok(None);
    };
    if named || agreed || rules.blocks(sender) {
        return Ok(None);
    }
    // Who they act for now is what a filter goes by, so what this agent may send them follows it. This
    // isn't something they chose to send, so it takes none of their daily quota. Their room on the
    // inbox is still small, and a Signet that's up clears it. A copy older than what's known changes
    // nothing, and neither does one under an owner's key that's been given up since.
    let seq = crate::admission::seq_for_sql(history.binding_seq());
    let acts_for = if history.is_revoked() {
        ""
    } else {
        owner.as_str()
    };
    if seq > 0
        && seq >= held_seq
        && (reached_as != acts_for || seq > held_seq)
        && history.owner_recoveries() >= known_recoveries(host, owner).await?
    {
        sqlx::query(
            "UPDATE reached SET owner = $3, binding_seq = $4,
                 host = CASE WHEN owner = $3 THEN host ELSE '' END
             WHERE agent = $1 AND peer = $2",
        )
        .bind(recipient.as_str())
        .bind(sender.as_str())
        .bind(acts_for)
        .bind(seq)
        .execute(&host.db)
        .await?;
    }
    Ok(Some(Arrival::delivered_by_reach()))
}

/// How many recoveries of this owner's ID this host has seen.
async fn known_recoveries(host: &Host, owner: &SplintId) -> Result<usize, ApiError> {
    let held: Option<String> =
        sqlx::query_scalar("SELECT identity FROM known_owners WHERE id = $1")
            .bind(owner.as_str())
            .fetch_optional(&host.db)
            .await?;
    let held = held.as_deref().map(Identity::from_encoded).transpose()?;
    Ok(held.map_or(0, |held| held.recoveries()))
}

async fn invited(host: &Host, agent: &SplintId, sender: &SplintId) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM redeemed_invites WHERE agent = $1 AND redeemer = $2)",
    )
    .bind(agent.as_str())
    .bind(sender.as_str())
    .fetch_one(&host.db)
    .await
}

/// Keeps where a contact is. The rules name the address it had, and an owner hasn't signed anything
/// since, so this is what says a new host may carry it. A contact that hasn't moved has this row too,
/// and it says what the rules say.
async fn learn_move(host: &Host, history: &VerifiedHistory) -> Result<(), ApiError> {
    let Some((_, domain)) = history.address().and_then(|text| parse_address(text).ok()) else {
        return Ok(());
    };
    let id = history.id().as_str();
    let held: Option<String> =
        sqlx::query_scalar("SELECT history FROM moved_contacts WHERE id = $1")
            .bind(id)
            .fetch_optional(&host.db)
            .await?;
    if let Some(held) = held {
        let follows = VerifiedHistory::read(&held)
            .is_ok_and(|held| held.against(history) == Against::Extends);
        if !follows {
            return Ok(());
        }
    }
    sqlx::query(
        "INSERT INTO moved_contacts (id, domain, history) VALUES ($1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET domain = $2, history = $3",
    )
    .bind(id)
    .bind(domain)
    .bind(history.encoded()?)
    .execute(&host.db)
    .await?;
    Ok(())
}

/// Where a signed move says this contact belongs now, if it has moved.
pub async fn moved_domain(host: &Host, id: &SplintId) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT domain FROM moved_contacts WHERE id = $1")
        .bind(id.as_str())
        .fetch_optional(&host.db)
        .await
}

/// A recovery of an ID someone here has reason to go by: an owner some agent's rules name, the owner of
/// a contact a stop is held for, or a contact itself. It counts at once, and what the key given up
/// signed about anyone stops counting. Two that part ways leave what's held. Says whether it was named,
/// which is what keeps this table to IDs that matter here, as anyone can make one and recover it.
pub async fn learn_listed_owner(host: &Host, new: &Identity) -> Result<Listed, ApiError> {
    let named: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM listed_owners WHERE owner = $1)
             OR EXISTS (SELECT 1 FROM contact_stops WHERE owner = $1)
             OR EXISTS (SELECT 1 FROM change_audience WHERE peer = $1)
             OR EXISTS (SELECT 1 FROM reached WHERE peer = $1)",
    )
    .bind(new.id().as_str())
    .fetch_one(&host.db)
    .await?;
    if !named {
        return Ok(Listed::NotNamed);
    }
    let held: Option<String> =
        sqlx::query_scalar("SELECT identity FROM known_owners WHERE id = $1")
            .bind(new.id().as_str())
            .fetch_optional(&host.db)
            .await?;
    let held = held.as_deref().map(Identity::from_encoded).transpose()?;
    let newest = match &held {
        Some(held) => match held.newest_of(new) {
            Ok(newest) => newest,
            Err(_) => {
                tracing::warn!(id = %new.id(), "two copies of one ID that part ways");
                return Ok(Listed::Forked);
            }
        },
        None => new.clone(),
    };
    crate::owner_keys::keep_if_newer(host, held.as_ref(), &newest).await?;
    // The row stays, so this agent's Signet can still be handed what ended it.
    sqlx::query("UPDATE contact_stops SET ended = TRUE WHERE owner = $1 AND owner_recoveries < $2")
        .bind(new.id().as_str())
        .bind(i32::try_from(newest.recoveries()).unwrap_or(i32::MAX))
        .execute(&host.db)
        .await?;
    Ok(Listed::Taken)
}

/// What [`learn_listed_owner`] made of a copy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Listed {
    /// Nobody here goes by this ID.
    NotNamed,
    /// Held now, or older than what's held.
    Taken,
    /// It parts ways with what's held and doesn't win, so what's held stays.
    Forked,
}

/// Whether this copy of a sender's ID is one a recovery has since replaced, as far as this host has
/// heard. A rival of what's held isn't older, and goes on to be put to an owner.
pub async fn is_given_up(host: &Host, sender: &Identity) -> Result<bool, ApiError> {
    let held: Option<String> =
        sqlx::query_scalar("SELECT identity FROM known_owners WHERE id = $1")
            .bind(sender.id().as_str())
            .fetch_optional(&host.db)
            .await?;
    let Some(held) = held else {
        return Ok(false);
    };
    let held = Identity::from_encoded(&held)?;
    Ok(held.recoveries() > sender.recoveries() && held.extends(sender))
}

/// Takes a retirement of someone this host's agents deal with. It stops them here whatever their own
/// host goes on doing. An ID nobody here has reason to go by is turned away, or anyone could fill this
/// table, and a copy of the owner older than one held is the word of a key given up.
pub async fn take_stop(host: &Host, notice: &RetirementNotice) -> Result<(), ApiError> {
    let stop = VerifiedStop::verify(notice)?;
    let agent = stop.agent().id().as_str();
    let relevant: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM change_audience WHERE peer = $1)
             OR EXISTS (SELECT 1 FROM reached WHERE peer = $1)
             OR EXISTS (SELECT 1 FROM met WHERE peer = $1)
             OR EXISTS (SELECT 1 FROM agreed_contacts WHERE peer = $1)",
    )
    .bind(agent)
    .fetch_one(&host.db)
    .await?;
    if !relevant {
        return Err(ApiError::NotFound);
    }
    let owner = stop.owner();
    let held: Option<String> =
        sqlx::query_scalar("SELECT identity FROM known_owners WHERE id = $1")
            .bind(owner.id().as_str())
            .fetch_optional(&host.db)
            .await?;
    if let Some(held) = held.as_deref().map(Identity::from_encoded).transpose()?
        && held.recoveries() > owner.recoveries()
    {
        return Err(ApiError::OutOfDate("that identity is out of date"));
    }
    keep_stop(&host.db, agent, stop.owner(), notice).await?;
    tracing::warn!(agent, "a contact's owner has retired it");
    Ok(())
}

async fn keep_stop(
    db: impl sqlx::PgExecutor<'_>,
    agent: &str,
    owner: &Identity,
    notice: &RetirementNotice,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO contact_stops (agent, owner, owner_recoveries, notice)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (agent) DO UPDATE SET owner = $2, owner_recoveries = $3, notice = $4,
             ended = FALSE
         WHERE contact_stops.ended",
    )
    .bind(agent)
    .bind(owner.id().as_str())
    .bind(i32::try_from(owner.recoveries()).unwrap_or(i32::MAX))
    .bind(serde_json::to_string(notice).map_err(|_| Error::Malformed)?)
    .execute(db)
    .await?;
    Ok(())
}

/// Whether a stop this host holds still covers this sender, as what came with their message shows
/// them. Their message says nothing if it doesn't check out, which changes nothing here.
pub async fn is_stopped(
    host: &Host,
    sender: &Identity,
    record: &SenderRecord,
) -> Result<bool, ApiError> {
    let held: Option<String> =
        sqlx::query_scalar("SELECT notice FROM contact_stops WHERE agent = $1 AND NOT ended")
            .bind(sender.id().as_str())
            .fetch_optional(&host.db)
            .await?;
    let Some(held) = held else {
        return Ok(false);
    };
    let notice: RetirementNotice = serde_json::from_str(&held).map_err(|_| Error::Malformed)?;
    let stop = VerifiedStop::verify(&notice)?;
    let owner = Identity::from_encoded(&record.owner_identity).ok();
    let binding = owner
        .as_ref()
        .and_then(|owner| VerifiedBinding::verify(&record.binding, owner, sender).ok());
    let shown = owner.as_ref().zip(binding.as_ref());
    Ok(stop.stops_one_showing(shown))
}

/// The hosts to tell of a change to these agents: those they've sent to, which hold their keys as a
/// contact's, and those the operator named. Never this host, nor one it doesn't exchange with.
async fn audience(
    host: &Host,
    transaction: &mut Transaction<'_, Postgres>,
    agents: &[&str],
) -> Result<Vec<String>, sqlx::Error> {
    let list = host.peers.current();
    let mut hosts: BTreeSet<String> = delivery::hosts_sent_to(transaction, agents)
        .await?
        .into_iter()
        .collect();
    hosts.extend(list.named().map(str::to_owned));
    Ok(hosts
        .into_iter()
        .filter(|peer| *peer != host.domain && list.exchanges_with(peer))
        .collect())
}

/// The hosts this agent was on before it moved here, as its own signed history says. Each still keeps
/// it, as moved away, and only that host knows who it sent to from there.
async fn former_hosts(
    host: &Host,
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
) -> Result<Vec<String>, sqlx::Error> {
    let held: Option<String> = sqlx::query_scalar("SELECT history FROM agents WHERE id = $1")
        .bind(agent.as_str())
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(history) = held
        .as_deref()
        .and_then(|text| VerifiedHistory::read(text).ok())
    else {
        return Ok(Vec::new());
    };
    let list = host.peers.current();
    let hosts: BTreeSet<String> = history
        .changes()
        .iter()
        .filter_map(|change| change.address.as_deref())
        .filter_map(|address| parse_address(address).ok())
        .map(|(_, domain)| domain.to_owned())
        .filter(|domain| *domain != host.domain && list.exchanges_with(domain))
        .collect();
    Ok(hosts.into_iter().collect())
}

/// Queues a retirement for the hosts that deal with this agent, in the same transaction that took it,
/// and keeps it here for any agent on this host who deals with this one. For an agent that moved here,
/// that includes the hosts it was on, which tell the hosts it sent to from there.
pub async fn queue_stop(
    host: &Host,
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
    notice: &RetirementNotice,
) -> Result<(), ApiError> {
    let text = serde_json::to_string(notice).map_err(|_| Error::Malformed)?;
    let mut hosts: BTreeSet<String> = audience(host, transaction, &[agent.as_str()])
        .await?
        .into_iter()
        .collect();
    hosts.extend(former_hosts(host, transaction, agent).await?);
    for peer in hosts {
        sqlx::query(
            "INSERT INTO stops_to_pass_on (peer, id, notice) VALUES ($1, $2, $3)
             ON CONFLICT (peer, id) DO UPDATE SET notice = $3, attempts = 0,
                 next_attempt_at = now()",
        )
        .bind(peer)
        .bind(agent.as_str())
        .bind(&text)
        .execute(&mut **transaction)
        .await?;
    }
    if let Ok(stop) = VerifiedStop::verify(notice) {
        keep_stop(&mut **transaction, agent.as_str(), stop.owner(), notice).await?;
    }
    Ok(())
}

/// Queues a recovery for the hosts that deal with the agents it touches, in the same transaction that
/// took it, so a crash can't lose it.
pub async fn queue_recovery(
    host: &Host,
    transaction: &mut Transaction<'_, Postgres>,
    new: &Identity,
    agents: &[&str],
) -> Result<(), sqlx::Error> {
    for peer in audience(host, transaction, agents).await? {
        sqlx::query(
            "INSERT INTO recoveries_to_pass_on (peer, id, identity) VALUES ($1, $2, $3)
             ON CONFLICT (peer, id) DO UPDATE SET identity = $3, attempts = 0,
                 next_attempt_at = now()",
        )
        .bind(peer)
        .bind(new.id().as_str())
        .bind(new.encoded())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

pub async fn run_passing_on(host: Arc<Host>) {
    loop {
        if let Err(error) = pass_on(&host).await {
            tracing::warn!(%error, "couldn't pass on recoveries");
        }
        if let Err(error) = pass_on_stops(&host).await {
            tracing::warn!(%error, "couldn't pass on retirements");
        }
        tokio::time::sleep(PASS_ON_INTERVAL).await;
    }
}

/// The same for retirements, whose answer ends it just the same: a peer nobody there deals with this
/// agent has nothing to go by, and one who writes later brings its binding to a host still refusing it.
async fn pass_on_stops(host: &Host) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT peer, id, notice, attempts FROM stops_to_pass_on
         WHERE next_attempt_at <= now() ORDER BY next_attempt_at LIMIT 32",
    )
    .fetch_all(&host.db)
    .await?;
    for row in &rows {
        let peer: String = row.try_get("peer")?;
        let id: String = row.try_get("id")?;
        let notice: String = row.try_get("notice")?;
        let attempts: i32 = row.try_get("attempts")?;
        // Asked for each one, as a pass lasts as long as its slowest peers take to answer.
        let answered = match host.call(&peer, RETIREMENTS_PATH) {
            Ok(call) => call
                .post()
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(notice)
                .send()
                .await
                .is_ok_and(|response| !response.status().is_server_error()),
            Err(_) => false,
        };
        if answered || attempts >= MAX_ATTEMPTS {
            sqlx::query("DELETE FROM stops_to_pass_on WHERE peer = $1 AND id = $2")
                .bind(&peer)
                .bind(&id)
                .execute(&host.db)
                .await?;
        } else {
            sqlx::query(
                "UPDATE stops_to_pass_on SET attempts = attempts + 1,
                     next_attempt_at = now() + make_interval(secs => $3)
                 WHERE peer = $1 AND id = $2",
            )
            .bind(&peer)
            .bind(&id)
            .bind(backoff_secs(attempts))
            .execute(&host.db)
            .await?;
        }
    }
    Ok(())
}

fn backoff_secs(attempts: i32) -> f64 {
    f64::from(
        2_i32
            .saturating_pow(attempts.clamp(0, 16).unsigned_abs())
            .min(MAX_BACKOFF_SECS),
    )
}

/// Tries what's due, one peer at a time. A peer's answer of any kind ends it, because a peer that says
/// it doesn't care now has no reason to later: a rule naming that owner brings its own copy.
///
/// A host this one may not call now, because the operator has since blocked it or left it out of a
/// private list, isn't called. Its turn counts as a try that failed, so what's queued for it waits,
/// goes once the host is back, and ends after the same week.
async fn pass_on(host: &Host) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT peer, id, identity, attempts FROM recoveries_to_pass_on
         WHERE next_attempt_at <= now() ORDER BY next_attempt_at LIMIT 32",
    )
    .fetch_all(&host.db)
    .await?;
    for row in &rows {
        let peer: String = row.try_get("peer")?;
        let id: String = row.try_get("id")?;
        let identity: String = row.try_get("identity")?;
        let attempts: i32 = row.try_get("attempts")?;
        // Asked for each one, as a pass lasts as long as its slowest peers take to answer.
        let answered = match host.call(&peer, RECOVERIES_PATH) {
            Ok(call) => call
                .post()
                .json(&splint_core::host_api::RecoveryNotice { identity })
                .send()
                .await
                .is_ok_and(|response| !response.status().is_server_error()),
            Err(_) => false,
        };
        if answered || attempts >= MAX_ATTEMPTS {
            sqlx::query("DELETE FROM recoveries_to_pass_on WHERE peer = $1 AND id = $2")
                .bind(&peer)
                .bind(&id)
                .execute(&host.db)
                .await?;
        } else {
            sqlx::query(
                "UPDATE recoveries_to_pass_on SET attempts = attempts + 1,
                     next_attempt_at = now() + make_interval(secs => $3)
                 WHERE peer = $1 AND id = $2",
            )
            .bind(&peer)
            .bind(&id)
            .bind(backoff_secs(attempts))
            .execute(&host.db)
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_limit::logged;
    use splint_core::changes::{Claim, sign_statement};
    use splint_core::{RecoveryRule, SealingKey, SigningKey};

    const NOW: u64 = 1_793_750_400;

    struct Holder {
        key: SigningKey,
        backup: SigningKey,
        identity: Identity,
    }

    fn holder() -> Holder {
        let key = SigningKey::generate().unwrap();
        let backup = SigningKey::generate().unwrap();
        let identity = Identity::create(
            &key,
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&backup.public_key()),
        )
        .unwrap();
        Holder {
            key,
            backup,
            identity,
        }
    }

    fn bound(owner: &Holder, agent: &Holder) -> VerifiedHistory {
        let half = VerifiedBinding::sign(
            &owner.key,
            &agent.backup,
            owner.identity.id(),
            &agent.identity,
            "ana~host.example",
            1,
            NOW,
        )
        .unwrap();
        let binding =
            VerifiedBinding::accept(&agent.key, &half, None, &owner.identity, &agent.identity)
                .unwrap();
        VerifiedHistory::empty(&agent.identity)
            .record_binding(&agent.key, &agent.identity, &owner.identity, &binding, NOW)
            .unwrap()
    }

    fn declared(
        owner: &Holder,
        agent: &Holder,
        on: &VerifiedHistory,
        what: &str,
    ) -> VerifiedHistory {
        let claim = Claim::Declared {
            what: what.to_owned(),
        };
        let statement = sign_statement(
            &owner.key,
            owner.identity.id(),
            agent.identity.id(),
            &on.head(),
            claim,
            NOW,
        )
        .unwrap();
        on.record_statement(
            &agent.key,
            &agent.identity,
            &owner.identity,
            &statement,
            NOW,
        )
        .unwrap()
    }

    /// The same events, with the newest one's signature taken from another event, so it's no longer
    /// one the agent made.
    fn unsigned_newest(history: &VerifiedHistory) -> HistoryDocument {
        let mut document = history.document();
        let first = document.events.first().unwrap().clone();
        let (_, signature) = first.rsplit_once('.').unwrap();
        let newest = document.events.pop().unwrap();
        let (signed, _) = newest.rsplit_once('.').unwrap();
        document.events.push(format!("{signed}.{signature}"));
        document
    }

    /// What's held checked out when it was taken, so a copy is checked only once it could change it,
    /// and a copy that does is checked in full before it's kept.
    #[test]
    fn a_copy_is_checked_only_once_it_could_change_what_is_held() {
        let (owner, agent) = (holder(), holder());
        let first = bound(&owner, &agent);
        let held = declared(&owner, &agent, &first, "one");
        let held_text = held.encoded().unwrap();
        let logs = HistoryLogs::new();

        // The same events, padded with owners that would never check out, cost nothing.
        let mut padded = held.document();
        padded.owners.push("bm90IGFuIGlkZW50aXR5".to_owned());
        assert!(VerifiedHistory::verify(padded.clone()).is_err());
        assert!(matches!(to_keep(&held_text, padded, &logs), Ok(None)));

        // An older copy changes nothing. It logs a refusal, so it listens the way the test of that
        // does.
        let (older, _) = logged(|| to_keep(&held_text, first.document(), &logs));
        assert!(matches!(older, Err(ApiError::Forbidden(_))));

        // A longer one is kept only once it checks out.
        let longer = declared(&owner, &agent, &held, "two");
        let forged = unsigned_newest(&longer);
        assert_eq!(
            held.document().against_unchecked(&forged),
            Ok(Against::Extends)
        );
        assert!(matches!(
            to_keep(&held_text, forged, &logs),
            Err(ApiError::Rejected(Error::BadSignature))
        ));
        let kept = to_keep(&held_text, longer.document(), &logs)
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(kept.head(), longer.head());

        // With nothing held yet, anything that checks out is kept, and only that.
        assert!(to_keep("", unsigned_newest(&held), &logs).is_err());
        let kept = to_keep("", held.document(), &logs).ok().flatten().unwrap();
        assert_eq!(kept.head(), held.head());
    }

    /// Anyone can send copies that don't follow what's held, and they're one line a minute between
    /// them. A fork whose newest event an agent's keys signed is a line of its own, a minute for each
    /// agent, since any agent here can mint forks of its own as often as it likes.
    #[test]
    fn a_fork_is_logged_however_much_noise_comes_before_it() {
        let logs = HistoryLogs::new();
        let (owner, agent, other) = (holder(), holder(), holder());
        let first = bound(&owner, &agent);
        let held = declared(&owner, &agent, &first, "one");
        let rival = declared(&owner, &agent, &first, "another");
        let held_text = held.encoded().unwrap();
        let others_first = bound(&owner, &other);
        let others_held = declared(&owner, &other, &others_first, "one");
        let others_rival = declared(&owner, &other, &others_first, "another");
        let (refusals, log) = logged(|| {
            let mut refusals = Vec::new();
            for _ in 0..5 {
                refusals.push(to_keep(&held_text, first.document(), &logs));
                refusals.push(to_keep(&held_text, unsigned_newest(&rival), &logs));
                refusals.push(to_keep(&held_text, rival.document(), &logs));
            }
            refusals.push(to_keep(
                &others_held.encoded().unwrap(),
                others_rival.document(),
                &logs,
            ));
            refusals
        });
        assert!(
            refusals
                .iter()
                .all(|refusal| matches!(refusal, Err(ApiError::Forbidden(_))))
        );
        assert_eq!(log.matches("refused histories").count(), 1);
        assert_eq!(log.matches("parts ways").count(), 2);
        assert!(log.contains(other.identity.id().as_str()));
    }

    /// A fork is never kept, so anyone shown one can send it again as often as they like. Telling it
    /// from noise takes its newest event's signature alone, so owners that would never check out
    /// aren't read, and it's still that agent's fork.
    #[test]
    fn a_replayed_fork_is_told_apart_without_reading_its_owners() {
        let logs = HistoryLogs::new();
        let (owner, agent) = (holder(), holder());
        let first = bound(&owner, &agent);
        let held = declared(&owner, &agent, &first, "one");
        let mut fork = declared(&owner, &agent, &first, "another").document();
        fork.owners = vec!["bm90IGFuIGlkZW50aXR5".to_owned()];
        assert!(VerifiedHistory::verify(fork.clone()).is_err());
        let (refused, log) = logged(|| to_keep(&held.encoded().unwrap(), fork, &logs));
        assert!(matches!(refused, Err(ApiError::Forbidden(_))));
        assert_eq!(log.matches("parts ways").count(), 1);
        assert_eq!(log.matches("refused histories").count(), 0);
    }

    /// Anyone can send a history naming any ID, and one this host doesn't have has to cost a lookup
    /// and no more. The database here is closed, so the answer shows a history that would fail its
    /// check was never checked: the host asked first.
    #[tokio::test]
    async fn a_history_is_looked_up_before_anything_in_it_is_checked() {
        let host = Arc::new(Host::with_closed_database("host.example").await.unwrap());
        let identity = Identity::create(
            &SigningKey::generate().unwrap(),
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        )
        .unwrap();
        // Its ID is one a hash finds, and reading it would fail on a recovery nobody signed.
        let forged = format!("{}~bm90IHNpZ25lZA", identity.encoded());
        assert!(Identity::from_encoded(&forged).is_err());
        let history = HistoryDocument {
            identity: forged,
            owners: Vec::new(),
            events: vec!["not.an.event".to_owned()],
        };
        assert!(VerifiedHistory::verify(history.clone()).is_err());
        let notice = HistoryNotice {
            history: history.encoded().unwrap(),
        };
        let answer = take_history(State(host), Json(notice)).await;
        assert!(matches!(answer, Err(ApiError::Unavailable)));
    }
}

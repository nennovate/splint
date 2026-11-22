//! Gate 2: the owner's signed rules decide who gets through to an agent. See
//! `docs/protocol.md`.
//!
//! Rules arrive signed by the owner and are kept only if they verify and are newer, so neither an
//! agent nor this host's operator can loosen them, or roll them back without the Signet noticing.
//! Unknown senders wait here in a capped queue, and leave only when a new rule set says so.
//!
//! Free text passes only where the owner signed `text` for that contact, and no more than the
//! owner's daily count each way, which stops two agents answering each other forever.
//!
//! An owner can also let people in who aren't contacts, by their reach setting. Those people get
//! only the types that setting names, no free text unless it says so, and a daily quota shared by
//! all of them, with no one owner or host taking all of it, so an open agent can't be flooded with IDs
//! made for the purpose. Their steps count only within an interaction this host saw start.
//!
//! A contact's address is on the host the owner signed, and only that host may carry its messages,
//! since that's the host that stops a key its owner retired or revoked.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, put};
use axum::{Json, Router};
use splint_core::changes::{is_notice_body, notice_in};
use splint_core::contact_invites::{introduction_in, is_introduction_body};
use splint_core::host_api::{HeldRules, QuarantinePage, Quarantined, RulesApplied, RulesNotice};
use splint_core::invites::{VerifiedRedeem, claimed_invite, redeem_proof_in};
use splint_core::requests::{
    HostChecks, InteractionType, PROPOSALS_PER_CONTACT_PER_DAY, Refused, carries_a_delegates_yes,
    check_at_sending_host, is_step_body, request_of,
};
use splint_core::rules::{
    Admission, Level, Opening, Outbound, Sender, UNCONFIRMED_SHARE_OF_QUOTA, VerifiedRules,
    claimed_owner_part, claimed_rules_agent,
};
use splint_core::{
    Error, Identity, MessageId, SplintId, VerifiedBinding, VerifiedEnvelope, unix_now,
};
use sqlx::{Postgres, Row, Transaction};

use crate::api_error::ApiError;
use crate::owner_api::reader::{owner_of_agent, owner_reading};
use crate::{
    Host, answers, changes, contact_holds, database, inbox, invites, note_receipts, owner_keys,
    requests,
};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS rules (
        agent TEXT PRIMARY KEY,
        seq BIGINT NOT NULL,
        compact TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS quarantine (
        seq BIGSERIAL PRIMARY KEY,
        recipient TEXT NOT NULL,
        sender TEXT NOT NULL,
        message_id TEXT NOT NULL,
        envelope TEXT NOT NULL,
        sender_identity TEXT NOT NULL,
        sender_owner_identity TEXT NOT NULL,
        sender_binding TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        UNIQUE (recipient, message_id)
    );
    CREATE INDEX IF NOT EXISTS quarantine_expiry ON quarantine (expires_at);
    CREATE TABLE IF NOT EXISTS redeemed_invites (
        agent TEXT NOT NULL,
        invite TEXT NOT NULL,
        redeemer TEXT NOT NULL,
        PRIMARY KEY (agent, invite)
    );
    CREATE TABLE IF NOT EXISTS met (
        agent TEXT NOT NULL,
        peer TEXT NOT NULL,
        PRIMARY KEY (agent, peer)
    );
    CREATE TABLE IF NOT EXISTS reached (
        agent TEXT NOT NULL,
        peer TEXT NOT NULL,
        owner TEXT NOT NULL,
        host TEXT NOT NULL,
        PRIMARY KEY (agent, peer)
    );
    CREATE TABLE IF NOT EXISTS reach_arrivals (
        recipient TEXT NOT NULL,
        sender TEXT NOT NULL,
        message_id TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (recipient, message_id)
    );
    CREATE INDEX IF NOT EXISTS reach_arrivals_at ON reach_arrivals (at);
    CREATE TABLE IF NOT EXISTS texts (
        agent TEXT NOT NULL,
        peer TEXT NOT NULL,
        outgoing BOOLEAN NOT NULL,
        message_id TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (agent, outgoing, message_id)
    );
    CREATE INDEX IF NOT EXISTS texts_at ON texts (at);
    CREATE TABLE IF NOT EXISTS new_requests (
        agent TEXT NOT NULL,
        peer TEXT NOT NULL,
        outgoing BOOLEAN NOT NULL,
        message_id TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (agent, outgoing, message_id)
    );
    CREATE INDEX IF NOT EXISTS new_requests_at ON new_requests (at);
    CREATE TABLE IF NOT EXISTS delegated_yeses (
        agent TEXT NOT NULL,
        message_id TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (agent, message_id)
    );
    CREATE INDEX IF NOT EXISTS delegated_yeses_at ON delegated_yeses (at);
    ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS relayed_by TEXT NOT NULL DEFAULT '';
    ALTER TABLE rules DROP COLUMN IF EXISTS expires_at;
    ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS relay_proof TEXT NOT NULL DEFAULT '';
    ALTER TABLE reached ADD COLUMN IF NOT EXISTS at BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE reached ADD COLUMN IF NOT EXISTS binding_seq BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE reach_arrivals ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT '';
    ALTER TABLE reach_arrivals ADD COLUMN IF NOT EXISTS host TEXT NOT NULL DEFAULT '';
    ALTER TABLE reached ADD COLUMN IF NOT EXISTS unconfirmed BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE reach_arrivals ADD COLUMN IF NOT EXISTS unconfirmed BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS known_owners (
        id TEXT PRIMARY KEY,
        identity TEXT NOT NULL
    );
    ALTER TABLE new_requests ADD COLUMN IF NOT EXISTS proposal BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS proposed_types (
        agent TEXT NOT NULL,
        peer TEXT NOT NULL,
        request TEXT NOT NULL,
        proposes TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (agent, request)
    );
    CREATE INDEX IF NOT EXISTS proposed_types_by ON proposed_types (agent, peer, proposes);
";

const MAX_QUARANTINED_BYTES_PER_AGENT: i64 = 4 * 1024 * 1024;
/// Rows in one page of a quarantine read, where they're small enough for that many to fit.
const PAGE_SIZE: i64 = 100;

const QUARANTINE_PATH: &str = "/v0/quarantine";
const RULES_PATH: &str = "/v0/rules";
/// Who an agent has written to, and who reached it by the owner's reach setting. Far past what one
/// agent deals with, and a limit on the table rather than a number anyone should reach.
const MAX_REMEMBERED_PER_AGENT: i64 = 10_000;
const DAY_SECS: i64 = 24 * 60 * 60;
/// How much of the owner's daily limit for others one owner or one host can take. IDs and owners cost
/// nothing to make, so it's the host's share that protects someone arriving from anywhere else.
const OWNER_SHARE_OF_QUOTA: u32 = 4;
const HOST_SHARE_OF_QUOTA: u32 = 2;

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route(RULES_PATH, put(take_rules).get(read_rules))
        .route(
            &format!("{RULES_PATH}/{{agent}}"),
            get(read_rules_for_owner),
        )
        .route(QUARANTINE_PATH, get(read_quarantine))
        .route(
            &format!("{QUARANTINE_PATH}/after/{{after}}"),
            get(read_quarantine_after),
        )
}

/// What a sending host says about the sender, for an owner deciding about a stranger. Only the
/// sender's owner can sign the binding, and a binding that doesn't check out is left out. Which host
/// relayed it was checked against that host's key before it got this far.
#[derive(Default)]
pub struct SenderRecord {
    pub owner_identity: String,
    pub binding: String,
    pub relayed_by: String,
    pub relay_proof: String,
}

/// What happened to a message arriving for an agent, and whether only the reach setting let it in.
pub struct Arrival {
    pub admission: Admission,
    pub by_reach: bool,
}

impl Arrival {
    fn plain(admission: Admission) -> Self {
        Self {
            admission,
            by_reach: false,
        }
    }

    pub fn dropped() -> Self {
        Self::plain(Admission::Drop)
    }

    pub fn delivered_by_reach() -> Self {
        Self {
            admission: Admission::Deliver,
            by_reach: true,
        }
    }
}

/// What this host knows about one sender to one of its agents, owned, so a [`Sender`] can borrow it.
struct Facts {
    agent: SplintId,
    owner: Option<SplintId>,
    host: Option<String>,
    met: bool,
    /// The newest thing an owner has signed about who they act for, as far as this message goes.
    binding_seq: i64,
    /// Whether their owner comes from what this message carries, rather than from what's held here.
    from_this_message: bool,
    /// Their owner hasn't confirmed, which their owner's ID itself shows.
    unconfirmed: bool,
    /// This host checked a pair of invite and acceptance between them and kept it.
    agreed: bool,
}

impl Facts {
    fn sender(&self) -> Sender<'_> {
        Sender {
            agent: &self.agent,
            owner: self.owner.as_ref(),
            host: self.host.as_deref(),
            met: self.met,
            unconfirmed: self.unconfirmed,
            agreed: self.agreed,
        }
    }
}

async fn has_met(host: &Host, agent: &SplintId, peer: &SplintId) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM met WHERE agent = $1 AND peer = $2)")
        .bind(agent.as_str())
        .bind(peer.as_str())
        .fetch_one(&host.db)
        .await
}

/// The newest copy of this owner's ID to go by, or `None` if two recoveries of it part ways. A copy
/// with a recovery in it replaces what's held if the rules' filter names that owner, which is what
/// keeps this table to what owners signed. What an older key signed for an agent stops counting at once.
async fn newest_owner(
    host: &Host,
    rules: Option<&VerifiedRules>,
    presented: Identity,
) -> Result<Option<Identity>, ApiError> {
    let held: Option<String> =
        sqlx::query_scalar("SELECT identity FROM known_owners WHERE id = $1")
            .bind(presented.id().as_str())
            .fetch_optional(&host.db)
            .await?;
    let held = held.as_deref().map(Identity::from_encoded).transpose()?;
    let newest = match &held {
        Some(held) => match held.newest_of(&presented) {
            Ok(newest) => newest,
            Err(_) => return Ok(None),
        },
        None => presented,
    };
    let named =
        rules.is_some_and(|rules| rules.reach().inbound.filter.owners.contains(newest.id()));
    if named {
        owner_keys::keep_if_newer(host, held.as_ref(), &newest).await?;
    }
    Ok(Some(newest))
}

/// A newer copy of an owner some rules here name. What a key it no longer has signed for an agent stops
/// counting, which `takes_away_a_key` says there may be.
pub async fn keep_owner_copy(
    host: &Host,
    newest: &Identity,
    takes_away_a_key: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO known_owners (id, identity) VALUES ($1, $2)
         ON CONFLICT (id) DO UPDATE SET identity = $2",
    )
    .bind(newest.id().as_str())
    .bind(newest.encoded())
    .execute(&host.db)
    .await?;
    if !takes_away_a_key {
        return Ok(());
    }
    // What the key given up signed could have been dated as far ahead as a thief liked.
    sqlx::query("UPDATE reached SET owner = '', host = '', binding_seq = 0 WHERE owner = $1")
        .bind(newest.id().as_str())
        .execute(&host.db)
        .await?;
    Ok(())
}

pub fn seq_for_sql(seq: u64) -> i64 {
    i64::try_from(seq).unwrap_or(i64::MAX)
}

/// An empty one says they act for nobody now: their owner revoked them, or gave up the key that said so.
fn id_from_row(text: String) -> Option<SplintId> {
    if text.is_empty() {
        return None;
    }
    serde_json::from_value(serde_json::Value::String(text)).ok()
}

/// A sender, from the record that came with their message. Their owner counts only under the newest
/// copy of that owner's ID this host knows, so a key given up in a recovery vouches for nobody, and
/// their host only if it signed for this message under the key the rules name. Who someone let in by
/// reach acted for before says nothing once something newer is known: they're judged as they are now.
async fn facts_from_record(
    host: &Host,
    rules: Option<&VerifiedRules>,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
    record: &SenderRecord,
) -> Result<Facts, ApiError> {
    let newest = match Identity::from_encoded(&record.owner_identity) {
        Ok(presented) => newest_owner(host, rules, presented).await?,
        Err(_) => None,
    };
    let binding = newest.and_then(|owner| {
        let unconfirmed = owner.is_unconfirmed_owner();
        VerifiedBinding::verify(&record.binding, &owner, sender)
            .ok()
            .map(|binding| (binding, unconfirmed))
    });
    let row = sqlx::query(
        "SELECT owner, binding_seq, unconfirmed FROM reached WHERE agent = $1 AND peer = $2",
    )
    .bind(envelope.recipient().as_str())
    .bind(sender.id().as_str())
    .fetch_optional(&host.db)
    .await?;
    let held = match row {
        Some(row) => Some((
            row.try_get::<String, _>("owner")?,
            row.try_get::<i64, _>("binding_seq")?,
            row.try_get::<bool, _>("unconfirmed")?,
        )),
        None => None,
    };
    let (owner, binding_seq, from_this_message, unconfirmed) = match (binding, held) {
        (Some((binding, _)), Some((owner, seq, unconfirmed)))
            if binding.is_behind(&owner, u64::try_from(seq).unwrap_or(0)) =>
        {
            (id_from_row(owner), seq, false, unconfirmed)
        }
        (Some((binding, unconfirmed)), _) => (
            Some(binding.owner().clone()),
            seq_for_sql(binding.seq()),
            true,
            unconfirmed,
        ),
        (None, _) => (None, 0, false, false),
    };
    let vouched = rules
        .filter(|_| from_this_message)
        .and_then(|rules| {
            rules.host_that_vouched(
                &record.relayed_by,
                &record.relay_proof,
                envelope.id(),
                &host.domain,
            )
        })
        .map(str::to_owned);
    Ok(Facts {
        agent: sender.id().clone(),
        owner,
        host: vouched,
        met: has_met(host, envelope.recipient(), sender.id()).await?,
        binding_seq,
        from_this_message,
        unconfirmed,
        agreed: invites::agreed_address(host, envelope.recipient(), sender.id())
            .await?
            .is_some(),
    })
}

/// Someone this agent is writing to, from what this host kept when they reached it, if they did.
async fn facts_of_peer(
    host: &Host,
    agent: &SplintId,
    peer: &SplintId,
) -> Result<Facts, sqlx::Error> {
    let row =
        sqlx::query("SELECT owner, host, unconfirmed FROM reached WHERE agent = $1 AND peer = $2")
            .bind(agent.as_str())
            .bind(peer.as_str())
            .fetch_optional(&host.db)
            .await?;
    let (owner, from, unconfirmed) = match row {
        Some(row) => (
            id_from_row(row.try_get("owner")?),
            Some(row.try_get::<String, _>("host")?).filter(|host| !host.is_empty()),
            row.try_get("unconfirmed")?,
        ),
        None => (None, None, false),
    };
    Ok(Facts {
        agent: peer.clone(),
        owner,
        host: from,
        met: has_met(host, agent, peer).await?,
        binding_seq: 0,
        from_this_message: false,
        unconfirmed,
        agreed: invites::agreed_address(host, agent, peer).await?.is_some(),
    })
}

async fn reached_before(
    host: &Host,
    agent: &SplintId,
    peer: &SplintId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM reached WHERE agent = $1 AND peer = $2)")
        .bind(agent.as_str())
        .bind(peer.as_str())
        .fetch_one(&host.db)
        .await
}

/// Notes that this agent wrote to someone, for an owner whose filter takes past exchanges. A
/// `received` or a notice is Signet's, not the agent's, so neither counts.
pub async fn note_met(host: &Host, envelope: &VerifiedEnvelope) -> Result<(), sqlx::Error> {
    let step = request_of(envelope).ok().flatten();
    // Nor an invite: one sent isn't someone written to, or inviting a stranger would let them in.
    if step.is_some_and(|step| step.is_receipt)
        || is_notice_body(envelope.body())
        || is_introduction_body(envelope.body())
    {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO met (agent, peer) SELECT $1, $2
         WHERE (SELECT count(*) FROM met WHERE agent = $1) < $3
         ON CONFLICT DO NOTHING",
    )
    .bind(envelope.sender().as_str())
    .bind(envelope.recipient().as_str())
    .bind(MAX_REMEMBERED_PER_AGENT)
    .execute(&host.db)
    .await?;
    Ok(())
}

/// The rules this agent's owner signed, if there are any that still verify.
pub async fn rules_of(host: &Host, agent: &SplintId) -> Result<Option<VerifiedRules>, ApiError> {
    let row = sqlx::query(
        "SELECT rules.compact, agents.owner_identity FROM rules
         JOIN agents ON agents.id = rules.agent WHERE rules.agent = $1",
    )
    .bind(agent.as_str())
    .fetch_optional(&host.db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let owner = Identity::from_encoded(&row.try_get::<String, _>("owner_identity")?)?;
    Ok(VerifiedRules::reload(&row.try_get::<String, _>("compact")?, &owner).ok())
}

async fn redeemed_invites_of(
    host: &Host,
    agent: &SplintId,
    redeemer: &SplintId,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT invite FROM redeemed_invites WHERE agent = $1 AND redeemer = $2")
        .bind(agent.as_str())
        .bind(redeemer.as_str())
        .fetch_all(&host.db)
        .await
}

/// What the rules say about someone, and whether it's only the reach setting letting them in. An
/// agent with no rules has no contacts, and strangers wait for its owner like anyone else's.
struct Judged {
    admission: Admission,
    by_reach: bool,
    /// The type a `type/1` going through proposes, to note once every limit has let it through, so a
    /// proposal refused for being one too many doesn't count as seen.
    proposes: Option<InteractionType>,
}

async fn admission_of(
    host: &Host,
    rules: Option<&VerifiedRules>,
    agent: &SplintId,
    sender: &Sender<'_>,
) -> Result<Judged, ApiError> {
    let Some(rules) = rules else {
        return Ok(Judged {
            proposes: None,
            admission: Admission::Quarantine,
            by_reach: false,
        });
    };
    let now = unix_now();
    // An owner may have invited them twice, with the first invitation since gone from the rules.
    let redeemed = redeemed_invites_of(host, agent, sender.agent).await?;
    let offered = redeemed.iter().find(|id| rules.invite_lets_in(id, now));
    Ok(Judged {
        admission: rules.admit(sender, offered.map(String::as_str), now),
        by_reach: offered.is_none() && rules.lets_in_by_reach(sender),
        proposes: None,
    })
}

/// The same for one message. A step starting an interaction also has to be of a type the rules list
/// for that sender, which is the one thing about a type a host can check with no schema. Someone let
/// in by reach can send words they chose only if the owner turned `text` on for them, and that goes
/// for a person's words as well as an agent's.
async fn admission_of_message(
    host: &Host,
    rules: Option<&VerifiedRules>,
    agent: &SplintId,
    other: &Sender<'_>,
    envelope: &VerifiedEnvelope,
) -> Result<Judged, ApiError> {
    let judged = admission_of(host, rules, agent, other).await?;
    let (Some(rules), Admission::Deliver) = (rules, judged.admission) else {
        return Ok(judged);
    };
    let step = request_of(envelope).ok().flatten();
    // A redeem presents itself as a step without being one of an interaction, and isn't words.
    let free_text = !is_step_body(envelope.body()) && !rules.allows_text(other);
    let person_text = step.as_ref().is_some_and(|step| step.carries_person_text)
        && !rules.allows_person_text(other);
    let proposes = step.as_ref().and_then(|step| step.proposes.clone());
    let opens = step.and_then(|step| step.opens);
    let listed = match &opens {
        Some(opens) => {
            let redeemed = redeemed_invites_of(host, agent, other.agent).await?;
            let seen_proposed =
                opens.is_agreed() && proposed_between(host, agent, other.agent, opens).await?;
            let opening = Opening {
                interaction: opens,
                proposes: proposes.as_ref(),
                seen_proposed,
            };
            let lets_in = |id: Option<&str>| rules.admits_type(other, &opening, id);
            lets_in(None) || redeemed.iter().any(|id| lets_in(Some(id)))
        }
        None => true,
    };
    let goes = listed && !free_text && !person_text;
    Ok(if goes {
        Judged { proposes, ..judged }
    } else {
        Judged {
            admission: Admission::Drop,
            by_reach: judged.by_reach,
            proposes: None,
        }
    })
}

/// Notes that a `type/1` between this host's agent and `peer` proposed a type, by its ID alone, which
/// is all the outside shows. An `open` of that type between the two is then theirs to agree, which
/// their Signets decide: this host can't tell whether it was accepted. Called only once the step has
/// passed every check and limit, as a proposal that doesn't go can't make its type seen.
async fn note_proposal(
    host: &Host,
    agent: &SplintId,
    peer: &SplintId,
    request: &MessageId,
    judged: &Judged,
) -> Result<(), sqlx::Error> {
    let Some(proposes) = &judged.proposes else {
        return Ok(());
    };
    let now = i64::try_from(unix_now()).unwrap_or(0);
    sqlx::query(
        "INSERT INTO proposed_types (agent, peer, request, proposes, at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING",
    )
    .bind(agent.as_str())
    .bind(peer.as_str())
    .bind(request.as_str())
    .bind(proposes.as_str())
    .bind(now)
    .execute(&host.db)
    .await?;
    Ok(())
}

/// Whether this host saw this type proposed between its agent and `peer`, either way.
async fn proposed_between(
    host: &Host,
    agent: &SplintId,
    peer: &SplintId,
    interaction: &InteractionType,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM proposed_types
             WHERE agent = $1 AND peer = $2 AND proposes = $3)",
    )
    .bind(agent.as_str())
    .bind(peer.as_str())
    .bind(interaction.as_str())
    .fetch_one(&host.db)
    .await
}

/// Whether a step is part of a `type/1` this host saw opened for its agent.
async fn in_a_proposal(
    host: &Host,
    agent: &SplintId,
    request: &MessageId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM proposed_types WHERE agent = $1 AND request = $2)",
    )
    .bind(agent.as_str())
    .bind(request.as_str())
    .fetch_one(&host.db)
    .await
}

/// Runs a statement that counts what's there and adds one if there's room, with any other for this key
/// held off till it's done. Statements running side by side can't see each other's rows, and a hostile
/// peer sends as many at once as it likes, so without this a limit holds only for honest senders.
pub async fn counted_alone(
    host: &Host,
    key: &str,
    count_and_add: sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let mut held = database::begin(&host.db).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(key)
        .execute(&mut *held)
        .await?;
    let done = count_and_add.execute(&mut *held).await?;
    held.commit().await?;
    Ok(done)
}

/// Whether one more message of free text between this agent and `peer`, in this direction, fits the
/// day's cap, counting it if it does. Each host counts for its own agent, so the sender's host and the
/// recipient's both hold the line. A resend of one already counted is free.
async fn within_text_cap(
    host: &Host,
    rules: Option<&VerifiedRules>,
    agent: &SplintId,
    peer: &Sender<'_>,
    outgoing: bool,
    envelope: &VerifiedEnvelope,
) -> Result<bool, sqlx::Error> {
    if is_step_body(envelope.body()) {
        return Ok(true);
    }
    let allowed = rules.map_or(0, |rules| rules.texts_per_day_with(peer));
    let now = i64::try_from(unix_now()).unwrap_or(0);
    let count_and_add = sqlx::query(
        "INSERT INTO texts (agent, peer, outgoing, message_id, at)
         SELECT $1, $2, $7, $3, $4
         WHERE (SELECT count(*) FROM texts
                WHERE agent = $1 AND peer = $2 AND outgoing = $7 AND at > $4 - $6) < $5
         ON CONFLICT (agent, outgoing, message_id) DO NOTHING",
    )
    .bind(agent.as_str())
    .bind(peer.agent.as_str())
    .bind(envelope.id().as_str())
    .bind(now)
    .bind(i64::from(allowed))
    .bind(DAY_SECS)
    .bind(outgoing);
    counted_alone(host, agent.as_str(), count_and_add).await?;
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM texts
             WHERE agent = $1 AND outgoing = $2 AND message_id = $3)",
    )
    .bind(agent.as_str())
    .bind(outgoing)
    .bind(envelope.id().as_str())
    .fetch_one(&host.db)
    .await
}

/// Whether one more interaction started between this agent and `peer`, in this direction, fits the
/// day's limit, counting it if it does. Each host counts for its own agent, so a recipient's owner
/// doesn't rest on the sender's host, and the sums in `docs/protocol.md` don't rest on a Signet. A
/// resend of one already counted is free.
async fn within_new_request_limit(
    host: &Host,
    rules: Option<&VerifiedRules>,
    agent: &SplintId,
    peer: &Sender<'_>,
    outgoing: bool,
    envelope: &VerifiedEnvelope,
) -> Result<bool, sqlx::Error> {
    let Some(step) = request_of(envelope).ok().flatten() else {
        return Ok(true);
    };
    if step.opens.is_none() {
        return Ok(true);
    }
    // A `type/1` counts against two proposals a day each way, apart from new requests, so a key
    // skipping Signet meets the same count here.
    let proposal = step.proposes.is_some();
    let allowed = if proposal {
        u32::try_from(PROPOSALS_PER_CONTACT_PER_DAY).unwrap_or(u32::MAX)
    } else {
        rules.map_or(0, |rules| {
            host.limits
                .now()
                .new_requests_capped(rules.new_requests_per_day_with(peer))
        })
    };
    let now = i64::try_from(unix_now()).unwrap_or(0);
    let count_and_add = sqlx::query(
        "INSERT INTO new_requests (agent, peer, outgoing, message_id, at, proposal)
         SELECT $1, $2, $7, $3, $4, $8
         WHERE (SELECT count(*) FROM new_requests
                WHERE agent = $1 AND peer = $2 AND outgoing = $7 AND proposal = $8
                  AND at > $4 - $6) < $5
         ON CONFLICT (agent, outgoing, message_id) DO NOTHING",
    )
    .bind(agent.as_str())
    .bind(peer.agent.as_str())
    .bind(envelope.id().as_str())
    .bind(now)
    .bind(i64::from(allowed))
    .bind(DAY_SECS)
    .bind(outgoing)
    .bind(proposal);
    counted_alone(host, agent.as_str(), count_and_add).await?;
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM new_requests
             WHERE agent = $1 AND outgoing = $2 AND message_id = $3)",
    )
    .bind(agent.as_str())
    .bind(outgoing)
    .bind(envelope.id().as_str())
    .fetch_one(&host.db)
    .await
}

/// Whether a new interaction or message from someone let in by reach fits the owner's daily limits,
/// counting it if it does. Everyone together has the owner's limit, each sender a contact's, and one
/// owner or one relaying host only a share, so filling it from one place leaves room for the others.
/// A share is never less than one sender's own limit. A resend of one already counted is free. Everyone
/// whose owner hasn't confirmed shares one part between them, however many hosts they come from.
async fn within_reach_quota(
    host: &Host,
    rules: &VerifiedRules,
    envelope: &VerifiedEnvelope,
    owner: &SplintId,
    relayed_by: &str,
    unconfirmed: bool,
) -> Result<bool, sqlx::Error> {
    let limits = host.limits.now();
    let per_sender = limits.new_requests_for(rules.limits());
    let from_others = limits.new_from_others_for(rules.limits());
    let share = |parts: u32| i64::from(from_others.div_ceil(parts).max(per_sender));
    let now = i64::try_from(unix_now()).unwrap_or(0);
    let count_and_add = sqlx::query(
        "INSERT INTO reach_arrivals (recipient, sender, message_id, at, owner, host, unconfirmed)
         SELECT $1, $2, $3, $4, $8, $9, $12
         WHERE (SELECT count(*) FROM reach_arrivals WHERE recipient = $1 AND at > $4 - $7) < $5
           AND (NOT $12 OR (SELECT count(*) FROM reach_arrivals
                WHERE recipient = $1 AND unconfirmed AND at > $4 - $7) < $13)
           AND (SELECT count(*) FROM reach_arrivals
                WHERE recipient = $1 AND sender = $2 AND at > $4 - $7) < $6
           AND (SELECT count(*) FROM reach_arrivals
                WHERE recipient = $1 AND owner = $8 AND at > $4 - $7) < $10
           AND (SELECT count(*) FROM reach_arrivals
                WHERE recipient = $1 AND host = $9 AND at > $4 - $7) < $11
         ON CONFLICT (recipient, message_id) DO NOTHING",
    )
    .bind(envelope.recipient().as_str())
    .bind(envelope.sender().as_str())
    .bind(envelope.id().as_str())
    .bind(now)
    .bind(i64::from(from_others))
    .bind(i64::from(per_sender))
    .bind(DAY_SECS)
    .bind(owner.as_str())
    .bind(relayed_by)
    .bind(share(OWNER_SHARE_OF_QUOTA))
    .bind(share(HOST_SHARE_OF_QUOTA))
    .bind(unconfirmed)
    .bind(share(UNCONFIRMED_SHARE_OF_QUOTA));
    let counted = counted_alone(host, envelope.recipient().as_str(), count_and_add).await?;
    if counted.rows_affected() > 0 {
        return Ok(true);
    }
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM reach_arrivals WHERE recipient = $1 AND message_id = $2)",
    )
    .bind(envelope.recipient().as_str())
    .bind(envelope.id().as_str())
    .fetch_one(&host.db)
    .await
}

/// Keeps who reached this agent by its owner's reach setting, so it can answer them, and only them.
/// When it's full the one who first arrived longest ago makes way, because a full list that refused
/// new people would be a way to turn a business's customers away for good.
async fn note_reached(host: &Host, facts: &Facts, agent: &SplintId) -> Result<(), sqlx::Error> {
    let Some(owner) = &facts.owner else {
        return Ok(());
    };
    let now = i64::try_from(unix_now()).unwrap_or(0);
    sqlx::query(
        "DELETE FROM reached WHERE agent = $1 AND peer IN (
             SELECT peer FROM reached WHERE agent = $1 ORDER BY at, peer
             LIMIT greatest((SELECT count(*) FROM reached WHERE agent = $1) - $3 + 1, 0)
         ) AND NOT EXISTS (SELECT 1 FROM reached WHERE agent = $1 AND peer = $2)",
    )
    .bind(agent.as_str())
    .bind(facts.agent.as_str())
    .bind(MAX_REMEMBERED_PER_AGENT)
    .execute(&host.db)
    .await?;
    sqlx::query(
        "INSERT INTO reached (agent, peer, owner, host, at, binding_seq, unconfirmed)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (agent, peer) DO UPDATE SET owner = $3, host = $4,
             binding_seq = greatest(reached.binding_seq, $6), unconfirmed = $7",
    )
    .bind(agent.as_str())
    .bind(facts.agent.as_str())
    .bind(owner.as_str())
    .bind(facts.host.as_deref().unwrap_or_default())
    .bind(now)
    .bind(facts.binding_seq)
    .bind(facts.unconfirmed)
    .execute(&host.db)
    .await?;
    Ok(())
}

/// Someone remembered from before who now shows a newer owner, whether or not a filter still lets them
/// in, so that what they were can't be shown again to pass it.
async fn follow_new_owner(host: &Host, facts: &Facts, agent: &SplintId) -> Result<(), sqlx::Error> {
    let Some(owner) = facts.owner.as_ref().filter(|_| facts.from_this_message) else {
        return Ok(());
    };
    sqlx::query(
        "UPDATE reached SET owner = $3, host = '', binding_seq = $4, unconfirmed = $5
         WHERE agent = $1 AND peer = $2 AND owner <> $3 AND binding_seq <= $4",
    )
    .bind(agent.as_str())
    .bind(facts.agent.as_str())
    .bind(owner.as_str())
    .bind(facts.binding_seq)
    .bind(facts.unconfirmed)
    .execute(&host.db)
    .await?;
    Ok(())
}

/// Whether the owner's rules name this sender as a contact on some other host than the one relaying
/// it, or the agent agreed with them at an address there, with no signed move to this one to say why.
async fn relayed_elsewhere(
    host: &Host,
    rules: Option<&VerifiedRules>,
    recipient: &SplintId,
    sender: &Identity,
    record: &SenderRecord,
) -> Result<bool, sqlx::Error> {
    let named = rules.filter(|rules| rules.names(sender.id()));
    let agreed_at = match named {
        Some(_) => None,
        None => invites::agreed_address(host, recipient, sender.id()).await?,
    };
    if named.is_none() && agreed_at.is_none() {
        return Ok(false);
    }
    Ok(match changes::moved_domain(host, sender.id()).await? {
        Some(domain) => domain != record.relayed_by,
        None => match (named, agreed_at) {
            (Some(rules), _) => rules.names_elsewhere(sender.id(), &record.relayed_by),
            (None, Some(address)) => splint_core::parse_address(&address)
                .is_ok_and(|(_, domain)| domain != record.relayed_by),
            (None, None) => false,
        },
    })
}

/// The whole check on a message arriving for an agent, from a sender this host has a record of.
async fn admit_arrival(
    host: &Host,
    rules: Option<&VerifiedRules>,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
    record: &SenderRecord,
) -> Result<Arrival, ApiError> {
    if relayed_elsewhere(host, rules, envelope.recipient(), sender, record).await? {
        tracing::warn!(message_id = %envelope.id(), "a contact's message came through another host");
        return Ok(Arrival::plain(Admission::Drop));
    }
    // What's ended a key counts here whatever the sender's host goes on doing. A notice still goes
    // through, since it's only a history, and may be how a real recovery or a new owner gets told.
    if !is_notice_body(envelope.body())
        && (changes::is_given_up(host, sender).await?
            || changes::is_stopped(host, sender, record).await?)
    {
        tracing::warn!(message_id = %envelope.id(), "refused a key that's been given up or retired");
        return Ok(Arrival::plain(Admission::Drop));
    }
    let recipient = envelope.recipient();
    if rules.is_some_and(|rules| rules.names(sender.id()))
        || !redeemed_invites_of(host, recipient, sender.id())
            .await?
            .is_empty()
        || invites::agreed_address(host, recipient, sender.id())
            .await?
            .is_some()
    {
        contact_holds::note_arrival(host, recipient, sender, record).await?;
    }
    // A note's receipt comes from whoever this agent wrote to, whatever let them in, and counts
    // against none of the owner's limits. It holds nothing anyone wrote, and the only place it's
    // taken is its signer's Signet, for a note sent to them. A change to them waiting on the owner's
    // word holds it as it holds anything.
    if let Some(rules) = rules.filter(|rules| rules.in_force(unix_now()))
        && !rules.blocks(sender.id())
        && note_receipts::for_note_sent(host, envelope).await?
        && !contact_holds::is_held(host, rules, recipient, sender.id()).await?
    {
        return Ok(Arrival::plain(Admission::Deliver));
    }
    let facts = facts_from_record(host, rules, envelope, sender, record).await?;
    follow_new_owner(host, &facts, recipient).await?;
    let judged = admission_of_message(host, rules, recipient, &facts.sender(), envelope).await?;
    if judged.admission == Admission::Deliver
        && !within_text_cap(host, rules, recipient, &facts.sender(), false, envelope).await?
    {
        tracing::info!(message_id = %envelope.id(), "over the day's cap on free text");
        return Ok(Arrival::plain(Admission::Drop));
    }
    // Someone let in by reach has quotas of their own, just below.
    if judged.admission == Admission::Deliver
        && !judged.by_reach
        && !within_new_request_limit(host, rules, recipient, &facts.sender(), false, envelope)
            .await?
    {
        tracing::info!(message_id = %envelope.id(), "over the day's limit on new requests");
        return Ok(Arrival::plain(Admission::Drop));
    }
    // A pause keeps what it would deliver, so what it keeps has to pass the same limits.
    let counts = matches!(judged.admission, Admission::Deliver | Admission::Wait);
    let (Some(rules), true) = (rules.filter(|_| judged.by_reach), counts) else {
        note_proposal(host, recipient, envelope.sender(), envelope.id(), &judged).await?;
        return Ok(Arrival::plain(judged.admission));
    };
    // Without a binding there's no address to answer at, and nothing for a filter to go on.
    let Some(owner) = &facts.owner else {
        return Ok(Arrival::plain(Admission::Drop));
    };
    match request_of(envelope).ok().flatten() {
        Some(step) if step.opens.is_none() => {
            let request = step.request.as_str();
            if !requests::between(host, request, envelope.sender(), recipient).await? {
                return Err(ApiError::TooEarly);
            }
        }
        _ => {
            let unconfirmed = facts.unconfirmed;
            if !within_reach_quota(
                host,
                rules,
                envelope,
                owner,
                &record.relayed_by,
                unconfirmed,
            )
            .await?
            {
                tracing::info!(message_id = %envelope.id(), "over the owner's daily limit for others");
                return Ok(Arrival::plain(Admission::Drop));
            }
        }
    }
    note_proposal(host, recipient, envelope.sender(), envelope.id(), &judged).await?;
    note_reached(host, &facts, recipient).await?;
    Ok(Arrival {
        admission: judged.admission,
        by_reach: true,
    })
}

/// Decides what happens to a message arriving for one of this host's agents. A redeem that checks
/// out is the one thing a stranger can send that lets them in.
pub async fn admit(
    host: &Host,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
    record: &SenderRecord,
) -> Result<Arrival, ApiError> {
    let recipient = envelope.recipient();
    let rules = rules_of(host, recipient).await?;
    if let Some(document) = notice_in(envelope.body())
        && let Some(arrival) =
            changes::take_notice(host, rules.as_ref(), envelope, record, document).await?
    {
        return Ok(arrival);
    }
    let elsewhere = relayed_elsewhere(host, rules.as_ref(), recipient, sender, record).await?;
    if let (Some(rules), Some(proof), false) = (&rules, redeem_proof_in(envelope.body()), elsewhere)
    {
        redeem(host, rules, recipient, sender, &proof).await?;
    }
    admit_arrival(host, rules.as_ref(), envelope, sender, record).await
}

/// One use, first come first served, and only by the agent the link's holder named. A redeem that
/// fails is left to the normal check, so it's just a stranger's message. One the rules won't let
/// through doesn't count at all: Signet would never hear of it, so this host would then call later
/// messages delivered that Signet clears, and the invitation would be spent.
async fn redeem(
    host: &Host,
    rules: &VerifiedRules,
    recipient: &SplintId,
    sender: &Identity,
    proof: &str,
) -> Result<(), ApiError> {
    let Some(invite) = claimed_invite(proof)
        .ok()
        .and_then(|id| rules.invite(&id).cloned())
    else {
        return Ok(());
    };
    let now = unix_now();
    if rules.admit(&Sender::only(sender.id()), Some(&invite.id), now) != Admission::Deliver {
        return Ok(());
    }
    let holder: Option<String> = sqlx::query_scalar(
        "SELECT redeemer FROM redeemed_invites WHERE agent = $1 AND invite = $2",
    )
    .bind(recipient.as_str())
    .bind(&invite.id)
    .fetch_optional(&host.db)
    .await?;
    let used = holder.is_some_and(|holder| holder != sender.id().as_str());
    if VerifiedRedeem::verify(proof, &invite, recipient, sender, used, now).is_err() {
        tracing::warn!("refused an invitation redeem");
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO redeemed_invites (agent, invite, redeemer) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
    )
    .bind(recipient.as_str())
    .bind(&invite.id)
    .bind(sender.id().as_str())
    .execute(&host.db)
    .await?;
    Ok(())
}

/// What the sender's rules say about a message it's sending. Someone its owner's reach setting lets
/// in counts only once they've reached it, and then for answers within what they started, unless
/// the owner's outbound setting also lets it follow up with them.
async fn outbound_admission(
    host: &Host,
    rules: Option<&VerifiedRules>,
    envelope: &VerifiedEnvelope,
) -> Result<Judged, ApiError> {
    let sender = envelope.sender();
    let recipient = envelope.recipient();
    let facts = facts_of_peer(host, sender, recipient).await?;
    let judged = admission_of_message(host, rules, sender, &facts.sender(), envelope).await?;
    let (Some(rules), Admission::Deliver, true) = (rules, judged.admission, judged.by_reach) else {
        return Ok(judged);
    };
    let dropped = Judged {
        admission: Admission::Drop,
        by_reach: true,
        proposes: None,
    };
    if !reached_before(host, sender, recipient).await? {
        return Ok(dropped);
    }
    let follows_up = rules.reach().outbound == Outbound::Replies;
    // A receipt for a note they sent answers them as much as a step does.
    let answers = match request_of(envelope).ok().flatten() {
        Some(step) if step.opens.is_none() => {
            started_by(host, step.request.as_str(), recipient, sender).await?
                || (step.is_receipt
                    && note_receipts::for_note_received(host, envelope)
                        .await?
                        .is_some())
        }
        _ => false,
    };
    Ok(if follows_up || answers {
        judged
    } else {
        dropped
    })
}

/// Whether `peer` opened this interaction with `agent`, by the open this host kept.
async fn started_by(
    host: &Host,
    request: &str,
    peer: &SplintId,
    agent: &SplintId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM request_steps
             WHERE message_id = $1 AND request_id = $1 AND sender = $2 AND recipient = $3)",
    )
    .bind(request)
    .bind(peer.as_str())
    .bind(agent.as_str())
    .fetch_one(&host.db)
    .await
}

/// Refuses a message from an agent to anyone its owner's rules don't let it reach, for a stolen key
/// that skips Signet. Rules that are paused or have run out stop everything.
pub async fn check_may_send(
    host: &Host,
    envelope: &VerifiedEnvelope,
) -> Result<Option<VerifiedRules>, ApiError> {
    let rules = rules_of(host, envelope.sender()).await?;
    if is_notice_body(envelope.body()) {
        changes::check_may_notify(host, rules.as_ref(), envelope).await?;
        return Ok(rules);
    }
    // An invite goes to someone who isn't a contact yet, and an acceptance to whoever invited.
    if let Some(introduction) = introduction_in(envelope.body()) {
        invites::check_going_out(host, rules.as_ref(), envelope, &introduction).await?;
        return Ok(rules);
    }
    if is_introduction_body(envelope.body()) {
        return Err(ApiError::Malformed(Error::Malformed));
    }
    let judged = outbound_admission(host, rules.as_ref(), envelope).await?;
    if judged.admission != Admission::Deliver {
        return Err(ApiError::Forbidden("the recipient isn't a contact"));
    }
    if let Some(rules) = &rules
        && contact_holds::is_held(host, rules, envelope.sender(), envelope.recipient()).await?
    {
        return Err(ApiError::Forbidden(
            "a change to this contact waits on its owner's word",
        ));
    }
    let peer = facts_of_peer(host, envelope.sender(), envelope.recipient()).await?;
    if !within_text_cap(
        host,
        rules.as_ref(),
        envelope.sender(),
        &peer.sender(),
        true,
        envelope,
    )
    .await?
    {
        return Err(ApiError::TooMany("too_many_texts"));
    }
    check_outgoing_step(host, rules.as_ref(), envelope).await?;
    if !within_new_request_limit(
        host,
        rules.as_ref(),
        envelope.sender(),
        &peer.sender(),
        true,
        envelope,
    )
    .await?
    {
        return Err(ApiError::TooMany("too_many_new_requests"));
    }
    if let Some(rules) = &rules
        && carries_a_delegates_yes(envelope)
        && !within_delegated_yeses(host, rules, envelope).await?
    {
        return Err(ApiError::TooMany("too_many_delegated_yeses"));
    }
    note_proposal(
        host,
        envelope.sender(),
        envelope.recipient(),
        envelope.id(),
        &judged,
    )
    .await?;
    Ok(rules)
}

/// Whether one more yes by the owner's delegate fits the day's yeses the owner's rules allow, counting
/// it if it does. Signet counts the lower of that and the delegation's own limit, but a delegate key
/// read off the agent's machine can skip Signet, so this host counts too. A resend is free.
async fn within_delegated_yeses(
    host: &Host,
    rules: &VerifiedRules,
    envelope: &VerifiedEnvelope,
) -> Result<bool, sqlx::Error> {
    let allowed = rules.permissions().approvals_allowed_per_day();
    let agent = envelope.sender();
    let now = i64::try_from(unix_now()).unwrap_or(0);
    let count_and_add = sqlx::query(
        "INSERT INTO delegated_yeses (agent, message_id, at)
         SELECT $1, $2, $3
         WHERE (SELECT count(*) FROM delegated_yeses WHERE agent = $1 AND at > $3 - $5) < $4
         ON CONFLICT (agent, message_id) DO NOTHING",
    )
    .bind(agent.as_str())
    .bind(envelope.id().as_str())
    .bind(now)
    .bind(i64::from(allowed))
    .bind(DAY_SECS);
    counted_alone(host, agent.as_str(), count_and_add).await?;
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM delegated_yeses WHERE agent = $1 AND message_id = $2)",
    )
    .bind(agent.as_str())
    .bind(envelope.id().as_str())
    .fetch_one(&host.db)
    .await
}

/// What a sending host holds a step to, whatever signed it. A key skipping Signet is what this is for:
/// that's a stolen key, or an agent sharing an OS user with its Signet. This host has the owner's rules
/// and their key, so an owner's `ask_me` doesn't rest on the Signet, and it doesn't carry a false yes.
async fn check_outgoing_step(
    host: &Host,
    rules: Option<&VerifiedRules>,
    envelope: &VerifiedEnvelope,
) -> Result<(), ApiError> {
    let body = envelope.body();
    if !is_step_body(body) || redeem_proof_in(body).is_some() {
        return Ok(());
    }
    let Some(rules) = rules else {
        return Err(ApiError::Forbidden("the recipient isn't a contact"));
    };
    let (agent, owner): (String, String) =
        sqlx::query_as("SELECT identity, owner_identity FROM agents WHERE id = $1")
            .bind(envelope.sender().as_str())
            .fetch_one(&host.db)
            .await?;
    let (agent, owner) = (
        Identity::from_encoded(&agent)?,
        Identity::from_encoded(&owner)?,
    );
    let facts = facts_of_peer(host, envelope.sender(), envelope.recipient()).await?;
    let agreeing_a_type = match request_of(envelope).ok().flatten() {
        Some(step) if step.opens.is_none() => {
            in_a_proposal(host, envelope.sender(), &step.request).await?
        }
        _ => false,
    };
    let checks = HostChecks {
        ask_me: rules.permissions().level == Level::AskMe,
        named_delegation: rules.named_delegation(),
        text_on: rules.allows_text(&facts.sender()),
        delegate_may_answer: rules.delegate_may_answer(envelope.recipient()),
        agreeing_a_type,
    };
    check_at_sending_host(envelope, &agent, &owner, &checks).map_err(|refused| {
        tracing::info!(message_id = %envelope.id(), %refused, "refused a step going out");
        match refused {
            Refused::Malformed => ApiError::Malformed(Error::Malformed),
            Refused::ApprovalMissing => ApiError::Forbidden("this step needs its owner's yes"),
            Refused::OutsideWindow => ApiError::Forbidden("a date here is out of range"),
            Refused::TypeNotAllowed => ApiError::Forbidden("a field here holds more than a word"),
            Refused::BadPersonText => ApiError::Forbidden("these words aren't its owner's"),
            Refused::BadWherePaid => {
                ApiError::Forbidden("where this asks to be paid isn't its owner's")
            }
            Refused::OverLimit => {
                ApiError::Forbidden("this yes is past what its owner lets their delegate say")
            }
            Refused::DelegateNotForContact => ApiError::Forbidden(
                "its owner hasn't approved this contact, so only their own yes goes to them",
            ),
            _ => ApiError::Forbidden("this step's approval isn't its owner's yes to it"),
        }
    })
}

/// What the sender's rules say now about a message already queued to go out.
pub enum QueuedMessage {
    Send,
    /// Paused, run out or missing: nothing the owner said about this message, and a pause mustn't
    /// lose anything, so it waits. So does a request's step, other than a `received`, that the rules
    /// now refuse for any reason but a block, as one still in Signet does, because the steps after it
    /// name it.
    Hold,
    /// The owner blocked the recipient, or the rules now refuse a note or a `received` to them. A block
    /// is how an owner recalls what a fooled agent queued, and it gives the room in the agent's queue
    /// back.
    Withdraw,
}

/// Rules count on what's queued as well as what's new, so this runs before every attempt to send.
pub async fn queued_message(
    host: &Host,
    envelope: &VerifiedEnvelope,
) -> Result<QueuedMessage, ApiError> {
    // What tells a contact about a replaced key has to go even with the rules gone, or it's silence.
    if is_notice_body(envelope.body()) {
        return Ok(QueuedMessage::Send);
    }
    let sender = envelope.sender();
    if is_introduction_body(envelope.body()) {
        let rules = rules_of(host, sender).await?;
        return Ok(
            match invites::still_goes(rules.as_ref(), envelope.recipient()) {
                None => QueuedMessage::Hold,
                Some(true) => QueuedMessage::Send,
                Some(false) => QueuedMessage::Withdraw,
            },
        );
    }
    let Some(rules) = rules_of(host, sender).await? else {
        return Ok(QueuedMessage::Hold);
    };
    if !rules.in_force(unix_now()) {
        return Ok(QueuedMessage::Hold);
    }
    // A request's step waits rather than ends: ending it parted the two sides' views of the request
    // for good once the owner added the contact back, with each later step put off by the other side's
    // Signet until it expired. A `received` names no step after it, so it ends like a note,
    // and a redeem doesn't parse as a step. A block still ends it, as the owner's recall.
    let a_link = !rules.blocks(envelope.recipient())
        && matches!(request_of(envelope), Ok(Some(step)) if !step.is_receipt);
    let refused = if a_link {
        QueuedMessage::Hold
    } else {
        QueuedMessage::Withdraw
    };
    if outbound_admission(host, Some(&rules), envelope)
        .await?
        .admission
        != Admission::Deliver
    {
        return Ok(refused);
    }
    if contact_holds::is_held(host, &rules, sender, envelope.recipient()).await? {
        return Ok(QueuedMessage::Hold);
    }
    // The rules in force when it goes decide, so a step queued before the owner moved to `ask_me`
    // doesn't go without their yes.
    match check_outgoing_step(host, Some(&rules), envelope).await {
        Ok(()) => Ok(QueuedMessage::Send),
        Err(ApiError::Forbidden(_) | ApiError::Malformed(_)) => Ok(refused),
        Err(other) => Err(other),
    }
}

/// Holds a stranger's message, unless the caps are reached. The caller answers the same either way.
pub async fn hold(
    host: &Host,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
    record: &SenderRecord,
) -> Result<bool, sqlx::Error> {
    let now = i64::try_from(unix_now()).unwrap_or(0);
    let limits = host.limits.now();
    let count_and_add = sqlx::query(
        "INSERT INTO quarantine (recipient, sender, message_id, envelope, sender_identity,
             sender_owner_identity, sender_binding, expires_at, relayed_by, relay_proof)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $13, $14
         WHERE (SELECT count(*) FROM quarantine
                WHERE recipient = $1 AND sender = $2 AND expires_at > $9) < $10
           AND (SELECT count(*) FROM quarantine
                WHERE recipient = $1 AND expires_at > $9) < $11
           AND (SELECT count(*) FROM quarantine
                WHERE recipient = $1 AND relayed_by = $13 AND expires_at > $9) < $15
           AND (SELECT coalesce(sum(octet_length(envelope)), 0) FROM quarantine
                WHERE recipient = $1 AND expires_at > $9) + octet_length($4) <= $12
         ON CONFLICT (recipient, message_id) DO NOTHING",
    )
    .bind(envelope.recipient().as_str())
    .bind(envelope.sender().as_str())
    .bind(envelope.id().as_str())
    .bind(envelope.compact())
    .bind(sender.encoded())
    .bind(&record.owner_identity)
    .bind(&record.binding)
    .bind(i64::try_from(envelope.expires_at()).unwrap_or(i64::MAX))
    .bind(now)
    .bind(i64::from(limits.quarantined_per_sender))
    .bind(i64::from(limits.quarantined_per_agent))
    .bind(MAX_QUARANTINED_BYTES_PER_AGENT)
    .bind(&record.relayed_by)
    .bind(&record.relay_proof)
    // A share, so one relaying host can't fill the quarantine against everyone else's.
    .bind(i64::from(limits.quarantined_per_agent / 2));
    let held = counted_alone(host, envelope.recipient().as_str(), count_and_add).await?;
    Ok(held.rows_affected() > 0)
}

/// Authorized by the owner's signature and nothing else, so anyone can carry rules here and nobody
/// else can write them. Hearing the same rules twice is fine, since Signet can't know what got here,
/// and it's how a release that failed halfway gets finished.
async fn take_rules(
    State(host): State<Arc<Host>>,
    Json(notice): Json<RulesNotice>,
) -> Result<Json<RulesApplied>, ApiError> {
    let agent = claimed_rules_agent(&notice.rules)?;
    let row = sqlx::query(
        "SELECT agents.identity, agents.owner_identity, rules.seq, rules.compact
         FROM agents
         LEFT JOIN rules ON rules.agent = agents.id
         WHERE agents.id = $1 AND agents.retirement IS NULL",
    )
    .bind(agent.as_str())
    .fetch_optional(&host.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let owner = Identity::from_encoded(&row.try_get::<String, _>("owner_identity")?)?;
    // The same rules again, or in the renewed form from before 2026-11-15, whose owner's part is them.
    if row.try_get::<Option<String>, _>("compact")?.as_deref()
        == Some(claimed_owner_part(&notice.rules))
    {
        let rules = VerifiedRules::reload(&notice.rules, &owner)?;
        changes::note_rules(&host, &agent, &rules).await?;
        invites::forget_agreed_named(&host, &agent, &rules).await?;
        apply_to_quarantine(&host, &rules, &agent).await?;
        return Ok(Json(RulesApplied { seq: rules.seq() }));
    }
    // Later by the owner's `seq`, so a host can't bring back what came before.
    let held = row
        .try_get::<Option<i64>, _>("seq")?
        .and_then(|number| u64::try_from(number).ok())
        .unwrap_or(0);
    let identity = Identity::from_encoded(&row.try_get::<String, _>("identity")?)?;
    let rules = VerifiedRules::verify_newer(&notice.rules, &owner, &identity, held, unix_now())?;
    let seq = i64::try_from(rules.seq()).map_err(|_| Error::Malformed)?;
    sqlx::query(
        "INSERT INTO rules (agent, seq, compact) VALUES ($1, $2, $3)
         ON CONFLICT (agent) DO UPDATE SET seq = $2, compact = $3
         WHERE rules.seq < $2",
    )
    .bind(agent.as_str())
    .bind(seq)
    .bind(rules.compact())
    .execute(&host.db)
    .await?;
    changes::note_rules(&host, &agent, &rules).await?;
    invites::forget_agreed_named(&host, &agent, &rules).await?;
    apply_to_quarantine(&host, &rules, &agent).await?;
    tracing::info!(%agent, seq = rules.seq(), "kept rules the owner signed");
    Ok(Json(RulesApplied { seq: rules.seq() }))
}

/// So a Signet hears of rules its owner's device gave this host directly, with no agent in between.
async fn read_rules(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
) -> Result<Json<HeldRules>, ApiError> {
    let agent = inbox::authenticated_agent(&host, &headers, "GET", RULES_PATH, b"").await?;
    let rules = sqlx::query_scalar("SELECT compact FROM rules WHERE agent = $1")
        .bind(agent.as_str())
        .fetch_optional(&host.db)
        .await?;
    Ok(Json(HeldRules { rules }))
}

/// The rules this host holds for an agent, for its owner's page on another device, which signs the next
/// ones from them. Its session only reads them: new rules are the owner's signature, as above.
async fn read_rules_for_owner(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    Path(agent): Path<String>,
) -> Result<Json<HeldRules>, ApiError> {
    let owner = owner_of_agent(&host, &agent)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let path = format!("{RULES_PATH}/{agent}");
    owner_reading(&host, &headers, &owner, "GET", &path, b"")?;
    let rules = sqlx::query_scalar("SELECT compact FROM rules WHERE agent = $1")
        .bind(&agent)
        .fetch_optional(&host.db)
        .await?;
    Ok(Json(HeldRules { rules }))
}

/// Approving or blocking is signing new rules, so this is where a held message finally moves. Rules
/// that stop the agent move nothing, because lifting a pause shouldn't have lost anything.
async fn apply_to_quarantine(
    host: &Host,
    rules: &VerifiedRules,
    agent: &SplintId,
) -> Result<(), ApiError> {
    if !rules.in_force(unix_now()) {
        return Ok(());
    }
    // A page's worth at a time, by how long each row is, as rules can be put here again and again and
    // each call would otherwise hold a whole quarantine while it works through it.
    let mut after = 0_i64;
    loop {
        let sized = sqlx::query(
            "SELECT seq, (octet_length(envelope) + octet_length(sender_identity)
                 + octet_length(sender_owner_identity) + octet_length(sender_binding)
                 + octet_length(relay_proof))::bigint AS bytes
             FROM quarantine WHERE recipient = $1 AND seq > $2 ORDER BY seq LIMIT $3",
        )
        .bind(agent.as_str())
        .bind(after)
        .bind(PAGE_SIZE)
        .fetch_all(&host.db)
        .await?;
        let batch = answers::page_of(
            answers::seq_and_bytes(&sized)?,
            sized.len(),
            answers::PAGE_BYTES,
            true,
        );
        let Some(last) = batch.keys.last().copied() else {
            return Ok(());
        };
        after = last;
        let rows = sqlx::query(
            "SELECT seq, envelope, sender_identity, sender_owner_identity, sender_binding,
                 relayed_by, relay_proof
             FROM quarantine WHERE recipient = $1 AND seq = ANY($2) ORDER BY seq",
        )
        .bind(agent.as_str())
        .bind(&batch.keys)
        .fetch_all(&host.db)
        .await?;
        for row in &rows {
            let seq: i64 = row.try_get("seq")?;
            let released = release(host, rules, agent, row).await?;
            if matches!(released, Admission::Deliver | Admission::Drop) {
                sqlx::query("DELETE FROM quarantine WHERE seq = $1")
                    .bind(seq)
                    .execute(&host.db)
                    .await?;
            }
        }
    }
}

/// What the rules now say about one held message, having moved it to the inbox if that's it.
async fn release(
    host: &Host,
    rules: &VerifiedRules,
    agent: &SplintId,
    row: &sqlx::postgres::PgRow,
) -> Result<Admission, ApiError> {
    let checked =
        Identity::from_encoded(&row.try_get::<String, _>("sender_identity")?).and_then(|sender| {
            let compact = row.try_get::<String, _>("envelope").unwrap_or_default();
            let envelope = VerifiedEnvelope::verify(&compact, &sender, unix_now())?;
            Ok((sender, envelope))
        });
    let Ok((sender, envelope)) = checked else {
        return Ok(Admission::Drop);
    };
    let record = SenderRecord {
        owner_identity: row.try_get("sender_owner_identity")?,
        binding: row.try_get("sender_binding")?,
        relayed_by: row.try_get("relayed_by")?,
        relay_proof: row.try_get("relay_proof")?,
    };
    if envelope.recipient() != agent {
        return Ok(Admission::Drop);
    }
    let arrival = match admit_arrival(host, Some(rules), &envelope, &sender, &record).await {
        Ok(arrival) => arrival,
        // What it follows may be further along this queue, or may never come. It stays until it expires.
        Err(ApiError::TooEarly) => return Ok(Admission::Quarantine),
        Err(error) => return Err(error),
    };
    let admission = arrival.admission;
    if admission == Admission::Deliver {
        match requests::store_if_step(host, &envelope, &sender).await {
            Ok(()) => {}
            // No reader would ever take it. It goes, and doesn't hold up what's behind it.
            Err(ApiError::Malformed(_) | ApiError::Forbidden(_)) => return Ok(Admission::Drop),
            Err(ApiError::TooMany(_)) => return Ok(Admission::Quarantine),
            Err(error) => return Err(error),
        }
        inbox::store(&host.db, &envelope, &sender, &record, arrival.by_reach).await?;
        tracing::info!(message_id = %envelope.id(), "released from quarantine to the inbox");
    }
    Ok(admission)
}

/// What's held for this agent, for its Signet to check and reduce to typed fields for the owner.
async fn read_quarantine(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    quarantine_page(&host, &headers, QUARANTINE_PATH, 0).await
}

/// The same, from after the row a page before said to go on from.
async fn read_quarantine_after(
    State(host): State<Arc<Host>>,
    Path(after): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let path = format!("{QUARANTINE_PATH}/after/{after}");
    quarantine_page(&host, &headers, &path, after).await
}

/// One page of what's held. Strangers fill it, so only how long each row is gets read first, and room
/// is taken for the ones that fit before they're read.
async fn quarantine_page(
    host: &Host,
    headers: &HeaderMap,
    path: &str,
    after: i64,
) -> Result<Response, ApiError> {
    let agent = inbox::authenticated_agent(host, headers, "GET", path, b"").await?;
    let sized = sqlx::query(
        "SELECT seq, (octet_length(envelope) + octet_length(sender_identity)
             + octet_length(sender_owner_identity) + octet_length(sender_binding))::bigint AS bytes
         FROM quarantine WHERE recipient = $1 AND expires_at > $2 AND seq > $3
         ORDER BY seq LIMIT $4",
    )
    .bind(agent.as_str())
    .bind(i64::try_from(unix_now()).unwrap_or(0))
    .bind(after)
    .bind(PAGE_SIZE + 1)
    .fetch_all(&host.db)
    .await?;
    let page = answers::page_of(
        answers::seq_and_bytes(&sized)?,
        usize::try_from(PAGE_SIZE).unwrap_or(usize::MAX),
        answers::PAGE_BYTES,
        true,
    );
    let room = host.answers.take(headers, page.bytes)?;
    let rows = sqlx::query(
        "SELECT envelope, sender_identity, sender_owner_identity, sender_binding FROM quarantine
         WHERE recipient = $1 AND seq = ANY($2) ORDER BY seq",
    )
    .bind(agent.as_str())
    .bind(&page.keys)
    .fetch_all(&host.db)
    .await?;
    let held = rows
        .iter()
        .map(|row| {
            Ok(Quarantined {
                envelope: row.try_get("envelope")?,
                sender_identity: row.try_get("sender_identity")?,
                sender_owner_identity: row.try_get("sender_owner_identity")?,
                sender_binding: row.try_get("sender_binding")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    let next = page.keys.last().copied().filter(|_| page.more);
    room.json(&QuarantinePage { held, next })
}

/// For when this agent gets a new owner: who it dealt with and what strangers left for the old one
/// don't go with it.
pub async fn forget_for_new_owner(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
) -> Result<(), sqlx::Error> {
    for statement in [
        "DELETE FROM quarantine WHERE recipient = $1",
        "DELETE FROM contact_views WHERE agent = $1",
        "DELETE FROM redeemed_invites WHERE agent = $1",
        "DELETE FROM met WHERE agent = $1",
        "DELETE FROM reached WHERE agent = $1",
        "DELETE FROM reach_arrivals WHERE recipient = $1",
        "DELETE FROM texts WHERE agent = $1",
        "DELETE FROM new_requests WHERE agent = $1",
        "DELETE FROM delegated_yeses WHERE agent = $1",
        "DELETE FROM proposed_types WHERE agent = $1",
    ] {
        sqlx::query(statement)
            .bind(agent.as_str())
            .execute(&mut **transaction)
            .await?;
    }
    invites::forget_for_new_owner(transaction, agent).await
}

pub async fn run_cleanup(host: Arc<Host>, every: std::time::Duration) {
    loop {
        tokio::time::sleep(every).await;
        let now = host.clock.now_for_sql().await;
        let result = sqlx::query("DELETE FROM quarantine WHERE expires_at <= $1")
            .bind(now)
            .execute(&host.db)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "quarantine cleanup failed");
        }
        let result = sqlx::query("DELETE FROM reach_arrivals WHERE at <= $1")
            .bind(now.saturating_sub(DAY_SECS))
            .execute(&host.db)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "reach quota cleanup failed");
        }
        let result = sqlx::query("DELETE FROM texts WHERE at <= $1")
            .bind(now.saturating_sub(DAY_SECS))
            .execute(&host.db)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "text count cleanup failed");
        }
        let result = sqlx::query("DELETE FROM new_requests WHERE at <= $1")
            .bind(now.saturating_sub(DAY_SECS))
            .execute(&host.db)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "new request count cleanup failed");
        }
        let result = sqlx::query("DELETE FROM delegated_yeses WHERE at <= $1")
            .bind(now.saturating_sub(DAY_SECS))
            .execute(&host.db)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "delegated yes count cleanup failed");
        }
    }
}

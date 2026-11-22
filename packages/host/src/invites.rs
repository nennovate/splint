//! The invites box: invites from whoever the owner's reach rules let ask, and acceptances of invites
//! this agent sent, held apart from the inbox and from quarantine. Nothing here reaches the agent as a
//! message. Its Signet reads the box and checks everything again, since this host's word is only a
//! hint to it.
//!
//! When the owner's rules let their agent's contacts agreed by itself in, this host keeps its own record
//! of each pair, built from the invite and the acceptance and checked as the owner's side would, so
//! nothing an agent says makes anyone one. It counts them here, 100 a day for each agent, because an
//! agent sharing an OS user with its Signet can read its key and go around Signet's count.
//!
//! An invite can go to anyone, so an agent sends a few a day, and a box holds a few from any one
//! sender or host. An acceptance only answers an invite its recipient sent, by this host's record of
//! what went out, and only once, so nobody can fill a box with acceptances, and a contact the owner
//! removed can't answer the same invite again to be offered back.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use splint_core::contact_invites::{
    Introduction, PendingContact, VerifiedAcceptance, VerifiedInvite, introduction_in,
};
use splint_core::host_api::{
    AGREED_PATH, AgreedPairs, AgreedTaken, HeldIntroduction, INVITES_DONE_PATH, INVITES_PATH,
    IntroductionsDone, IntroductionsPage, MOST_AGREED_IN_ONE_CALL,
};
use splint_core::rules::VerifiedRules;
use splint_core::{Identity, SplintId, VerifiedBinding, VerifiedEnvelope, unix_now};
use sqlx::{Postgres, Row, Transaction};

use crate::admission::{self, SenderRecord};
use crate::api_error::ApiError;
use crate::{Host, answers, changes, inbox, registry};

/// Runs after `waits::SCHEMA`, whose function wakes a Signet waiting on its host.
pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS introductions (
        seq BIGSERIAL PRIMARY KEY,
        recipient TEXT NOT NULL,
        sender TEXT NOT NULL,
        message_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        invite_id TEXT NOT NULL,
        envelope TEXT NOT NULL,
        sender_identity TEXT NOT NULL,
        sender_owner_identity TEXT NOT NULL,
        sender_binding TEXT NOT NULL,
        relayed_by TEXT NOT NULL,
        unconfirmed BOOLEAN NOT NULL,
        done BOOLEAN NOT NULL DEFAULT FALSE,
        expires_at BIGINT NOT NULL,
        UNIQUE (recipient, message_id)
    );
    CREATE INDEX IF NOT EXISTS introductions_expiry ON introductions (expires_at);
    CREATE TABLE IF NOT EXISTS invites_sent (
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        invite_id TEXT NOT NULL,
        at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        PRIMARY KEY (sender, invite_id)
    );
    CREATE INDEX IF NOT EXISTS invites_sent_expiry ON invites_sent (expires_at);
    ALTER TABLE invites_sent ADD COLUMN IF NOT EXISTS accepted BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE invites_sent ADD COLUMN IF NOT EXISTS invite TEXT NOT NULL DEFAULT '';
    CREATE TABLE IF NOT EXISTS agreed_contacts (
        agent TEXT NOT NULL,
        peer TEXT NOT NULL,
        address TEXT NOT NULL,
        invite TEXT NOT NULL,
        acceptance TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (agent, peer)
    );
    CREATE INDEX IF NOT EXISTS agreed_contacts_at ON agreed_contacts (agent, at);
    DROP TRIGGER IF EXISTS splint_wake ON introductions;
    CREATE TRIGGER splint_wake AFTER INSERT ON introductions
        FOR EACH ROW EXECUTE FUNCTION splint_wake_inbox();
";

const INVITE: &str = "invite";
const ACCEPTANCE: &str = "acceptance";
const DAY_SECS: i64 = 24 * 60 * 60;
/// Invites one agent may send in a day: more than a person makes friends, few enough that a fooled
/// agent can't spam. Provisional, for Nenye to overturn.
const INVITES_PER_DAY: i64 = 100;
/// Half that for an agent nobody has set up controls for, which costs nothing to make.
const UNCONFIRMED_INVITES_PER_DAY: i64 = INVITES_PER_DAY / 2;
/// Invites waiting in one box. Each answered or declined one makes room.
const WAITING_PER_AGENT: i64 = 32;
/// From one sender, over an invite's life, answered or not, so declining doesn't invite another.
const PER_SENDER: i64 = 2;
/// Waiting from one relaying host, so one host's IDs can't fill the box against everyone else's.
const WAITING_PER_HOST: i64 = WAITING_PER_AGENT / 2;
/// Waiting from senders nobody has set up controls for, from any number of hosts.
const WAITING_UNCONFIRMED: i64 = WAITING_PER_AGENT / 4;
/// Acceptances waiting, which only answer invites this agent sent.
const ACCEPTANCES_WAITING: i64 = 64;
/// New contacts one agent may agree with by itself in a day, invited or inviting: as many as the
/// invites it may send, so accepting others' can't add more. Past it, a pair waits for the owner.
/// Provisional, for Nenye to overturn.
const AGREED_PER_DAY: i64 = INVITES_PER_DAY;
const PAGE_SIZE: i64 = 100;

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route(INVITES_PATH, get(read_box))
        .route(
            &format!("{INVITES_PATH}/after/{{after}}"),
            get(read_box_after),
        )
        .route(INVITES_DONE_PATH, post(done))
        .route(AGREED_PATH, axum::routing::put(given_back))
}

fn as_sql(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

/// What this host holds an introduction going out to: the sender's rules in force, the recipient not
/// blocked, an invite only while those rules let the agent invite, signed by this agent for the agent it reaches, from its own address here, within
/// the day's count, and an acceptance only of an invite in this agent's box.
pub async fn check_going_out(
    host: &Host,
    rules: Option<&VerifiedRules>,
    envelope: &VerifiedEnvelope,
    introduction: &Introduction,
) -> Result<(), ApiError> {
    let now = unix_now();
    let rules = rules
        .filter(|rules| rules.in_force(now))
        .ok_or(ApiError::Forbidden(
            "the owner's rules have this agent stopped",
        ))?;
    if rules.blocks(envelope.recipient()) {
        return Err(ApiError::Forbidden("the recipient isn't a contact"));
    }
    let sender = registry::identity_of(host, envelope.sender())
        .await?
        .ok_or(ApiError::Forbidden("sender isn't registered here"))?;
    match introduction {
        Introduction::Invite(compact) => {
            // As Signet holds its agent too: a fooled one holding its key goes around Signet.
            if !rules.lets_its_agent_invite() {
                return Err(ApiError::Forbidden(
                    "the owner's rules ask them first, so they add contacts themselves",
                ));
            }
            let invite = VerifiedInvite::verify(compact, &sender, envelope.recipient(), now)
                .map_err(|_| {
                    ApiError::Forbidden(
                        "an invite is signed by its agent, for the agent it reaches",
                    )
                })?;
            // The address its owner bound it to here, which is what the reader checks too, so another
            // of this host's agents can't invite anyone in its name.
            let record = registry::record_of(host, envelope.sender()).await?;
            let bound_here = Identity::from_encoded(&record.owner_identity)
                .ok()
                .and_then(|owner| VerifiedBinding::verify(&record.binding, &owner, &sender).ok())
                .is_some_and(|binding| binding.address() == invite.from_address());
            if !bound_here {
                return Err(ApiError::Forbidden(
                    "an invite is from its agent's own address",
                ));
            }
            take_one_of_the_days_invites(host, envelope, &invite).await
        }
        Introduction::Acceptance(compact) => {
            let accepted = VerifiedAcceptance::verify(compact, &sender, now).map_err(|_| {
                ApiError::Forbidden("an acceptance is signed by the agent it names")
            })?;
            if accepted.inviter() != envelope.recipient() {
                return Err(ApiError::Forbidden("an acceptance goes to whoever invited"));
            }
            let in_the_box: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM introductions WHERE recipient = $1 AND sender = $2
                     AND kind = $3 AND invite_id = $4 AND expires_at > $5)",
            )
            .bind(envelope.sender().as_str())
            .bind(accepted.inviter().as_str())
            .bind(INVITE)
            .bind(accepted.invite())
            .bind(as_sql(now))
            .fetch_one(&host.db)
            .await?;
            if !in_the_box {
                return Err(ApiError::Forbidden(
                    "that invite isn't one this agent was sent",
                ));
            }
            // It goes either way: past the day's count, the pair waits for the owner instead.
            if let Some(pair) = accepted_here(host, envelope, &sender, &accepted, compact).await? {
                note_agreed(host, envelope.sender(), Some(rules), &pair).await?;
            }
            Ok(())
        }
    }
}

/// The two halves of a pair this agent is accepting, from the invite as its box holds it and the
/// acceptance going out, with each agent's binding: the inviter's as its host passed it on, and this
/// agent's as registered here. `None` once the box has nothing of the invite left to show.
async fn accepted_here(
    host: &Host,
    envelope: &VerifiedEnvelope,
    invitee: &Identity,
    accepted: &VerifiedAcceptance,
    acceptance: &str,
) -> Result<Option<PendingContact>, ApiError> {
    let row = sqlx::query(
        "SELECT envelope, sender_identity, sender_owner_identity, sender_binding
         FROM introductions WHERE recipient = $1 AND sender = $2 AND kind = $3 AND invite_id = $4
           AND envelope <> '' ORDER BY seq DESC LIMIT 1",
    )
    .bind(envelope.sender().as_str())
    .bind(accepted.inviter().as_str())
    .bind(INVITE)
    .bind(accepted.invite())
    .fetch_optional(&host.db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let inviter_identity: String = row.try_get("sender_identity")?;
    let carried: String = row.try_get("envelope")?;
    let invite = Identity::from_encoded(&inviter_identity)
        .and_then(|inviter| VerifiedEnvelope::verify(&carried, &inviter, unix_now()))
        .ok()
        .and_then(|carried| match introduction_in(carried.body()) {
            Some(Introduction::Invite(compact)) => Some(compact),
            _ => None,
        });
    let Some(invite) = invite else {
        return Ok(None);
    };
    let own = registry::record_of(host, envelope.sender()).await?;
    Ok(Some(PendingContact {
        invite,
        acceptance: acceptance.to_owned(),
        inviter_identity,
        invitee_identity: invitee.encoded(),
        inviter_owner_identity: row.try_get("sender_owner_identity")?,
        inviter_binding: row.try_get("sender_binding")?,
        invitee_owner_identity: own.owner_identity,
        invitee_binding: own.binding,
    }))
}

/// The same for an invite this agent sent, from what this host kept of it going out and the acceptance
/// arriving, with the acceptor's binding as their host passed it on.
async fn answered_here(
    host: &Host,
    agent: &SplintId,
    invitee: &Identity,
    record: &SenderRecord,
    accepted: &VerifiedAcceptance,
    acceptance: &str,
) -> Result<Option<PendingContact>, ApiError> {
    let invite: Option<String> = sqlx::query_scalar(
        "SELECT invite FROM invites_sent WHERE sender = $1 AND recipient = $2 AND invite_id = $3
             AND invite <> ''",
    )
    .bind(agent.as_str())
    .bind(invitee.id().as_str())
    .bind(accepted.invite())
    .fetch_optional(&host.db)
    .await?;
    let (Some(invite), Some(inviter)) = (invite, registry::identity_of(host, agent).await?) else {
        return Ok(None);
    };
    let own = registry::record_of(host, agent).await?;
    Ok(Some(PendingContact {
        invite,
        acceptance: acceptance.to_owned(),
        inviter_identity: inviter.encoded(),
        invitee_identity: invitee.encoded(),
        inviter_owner_identity: own.owner_identity,
        inviter_binding: own.binding,
        invitee_owner_identity: record.owner_identity.clone(),
        invitee_binding: record.binding.clone(),
    }))
}

/// Keeps a pair this agent agreed by itself, if the owner's rules in force let such contacts in, the
/// agent may add contacts at all, the rules don't name the other already, the pair checks out as the
/// owner's side would check it, and the day's count has room. The count and the record are one
/// statement, held off from any other for this agent, so a flood at once can't pass it.
async fn note_agreed(
    host: &Host,
    agent: &SplintId,
    rules: Option<&VerifiedRules>,
    pair: &PendingContact,
) -> Result<bool, ApiError> {
    let now = unix_now();
    // Each use is judged again by the rules then, but a pair kept now would count once the owner moves
    // off Ask me or turns agreed contacts on, so what these rules say decides whether it's kept at all.
    // `sim/invites.py` shows Ask me.
    let takes_them = rules.filter(|rules| {
        rules.in_force(now) && rules.reach().agreed.is_some() && rules.lets_its_agent_invite()
    });
    let Some(rules) = takes_them else {
        return Ok(false);
    };
    // Not redundant with what this host checked as each half came by: only here are both agents'
    // bindings held to the addresses the invite gives, so a card's spoofed address makes nobody a
    // contact. `sim/invites.py` shows it.
    let Ok(new) = pair.verify(agent) else {
        tracing::warn!("a pair of invite and acceptance that doesn't check out");
        return Ok(false);
    };
    // Defence in depth: a peer the rules name is judged by that entry at every use, and the next rules
    // forget the pair. This keeps a removal standing should the owner later drop the entry.
    if rules.names(&new.agent) {
        return Ok(false);
    }
    let count_and_add = sqlx::query(
        "INSERT INTO agreed_contacts (agent, peer, address, invite, acceptance, at)
         SELECT $1, $2, $3, $4, $5, $6
         WHERE (SELECT count(*) FROM agreed_contacts WHERE agent = $1 AND at > $6 - $7) < $8
         ON CONFLICT (agent, peer) DO NOTHING",
    )
    .bind(agent.as_str())
    .bind(new.agent.as_str())
    .bind(&new.address)
    .bind(&pair.invite)
    .bind(&pair.acceptance)
    .bind(as_sql(now))
    .bind(DAY_SECS)
    .bind(AGREED_PER_DAY);
    let added = admission::counted_alone(host, agent.as_str(), count_and_add).await?;
    if added.rows_affected() == 0 {
        tracing::info!(
            "a contact agreed by the agent waits for its owner: none left today, or known"
        );
    }
    Ok(added.rows_affected() > 0)
}

/// Contacts an agent that moved here agreed by itself at its last host, given back by its own Signet.
/// Each pair is checked as one made here is, both agents' signatures and bindings, under the rules in
/// force here, which its Signet gives first, and counts in the same day's count, so giving pairs back
/// is no way around it for an agent whose key is out. What the count leaves out comes back another day.
async fn given_back(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<AgreedTaken>, ApiError> {
    let agent = inbox::authenticated_agent(&host, &headers, "PUT", AGREED_PATH, &body).await?;
    let given: AgreedPairs =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("bad body"))?;
    if given.pairs.len() > MOST_AGREED_IN_ONE_CALL {
        return Err(ApiError::BadRequest("too many pairs in one call"));
    }
    let rules = admission::rules_of(&host, &agent).await?;
    let mut left_out = false;
    for pair in &given.pairs {
        let kept = note_agreed(&host, &agent, rules.as_ref(), pair).await?;
        left_out = left_out || !kept;
    }
    let today: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agreed_contacts WHERE agent = $1 AND at > $2 - $3",
    )
    .bind(agent.as_str())
    .bind(as_sql(unix_now()))
    .bind(DAY_SECS)
    .fetch_one(&host.db)
    .await?;
    Ok(Json(AgreedTaken {
        full: left_out && today >= AGREED_PER_DAY,
    }))
}

/// Where a contact this agent agreed by itself is, by the invite they signed, if there's one.
pub async fn agreed_address(
    host: &Host,
    agent: &SplintId,
    peer: &SplintId,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT address FROM agreed_contacts WHERE agent = $1 AND peer = $2")
        .bind(agent.as_str())
        .bind(peer.as_str())
        .fetch_optional(&host.db)
        .await
}

/// Forgets pairs the owner's new rules name either way. Whatever the owner signed about them stands,
/// and dropping them later from the rules doesn't bring the agent's own agreement back.
pub async fn forget_agreed_named(
    host: &Host,
    agent: &SplintId,
    rules: &VerifiedRules,
) -> Result<(), sqlx::Error> {
    let named: Vec<&str> = rules.listed().map(SplintId::as_str).collect();
    sqlx::query("DELETE FROM agreed_contacts WHERE agent = $1 AND peer = ANY($2)")
        .bind(agent.as_str())
        .bind(&named)
        .execute(&host.db)
        .await?;
    Ok(())
}

async fn take_one_of_the_days_invites(
    host: &Host,
    envelope: &VerifiedEnvelope,
    invite: &VerifiedInvite,
) -> Result<(), ApiError> {
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_identity FROM agents WHERE id = $1")
            .bind(envelope.sender().as_str())
            .fetch_optional(&host.db)
            .await?;
    let unconfirmed = owner
        .and_then(|owner| Identity::from_encoded(&owner).ok())
        .is_some_and(|owner| owner.is_unconfirmed_owner());
    let allowed = if unconfirmed {
        UNCONFIRMED_INVITES_PER_DAY
    } else {
        INVITES_PER_DAY
    };
    let now = as_sql(unix_now());
    let count_and_add = sqlx::query(
        "INSERT INTO invites_sent (sender, recipient, invite_id, at, expires_at, invite)
         SELECT $1, $2, $3, $4, $5, $8
         WHERE (SELECT count(*) FROM invites_sent WHERE sender = $1 AND at > $4 - $6) < $7
            OR EXISTS (SELECT 1 FROM invites_sent WHERE sender = $1 AND invite_id = $3)
         ON CONFLICT (sender, invite_id) DO NOTHING",
    )
    .bind(envelope.sender().as_str())
    .bind(envelope.recipient().as_str())
    .bind(invite.id())
    .bind(now)
    .bind(as_sql(invite.expires_at()))
    .bind(DAY_SECS)
    .bind(allowed)
    .bind(invite.compact());
    admission::counted_alone(host, envelope.sender().as_str(), count_and_add).await?;
    let kept: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM invites_sent WHERE sender = $1 AND invite_id = $2
             AND recipient = $3)",
    )
    .bind(envelope.sender().as_str())
    .bind(invite.id())
    .bind(envelope.recipient().as_str())
    .fetch_one(&host.db)
    .await?;
    if !kept {
        return Err(ApiError::TooMany(
            "this agent has sent all the invites it can today",
        ));
    }
    Ok(())
}

/// What an introduction already queued comes to under the sender's rules now.
pub fn still_goes(rules: Option<&VerifiedRules>, recipient: &SplintId) -> Option<bool> {
    let rules = rules.filter(|rules| rules.in_force(unix_now()))?;
    Some(!rules.blocks(recipient))
}

/// Puts an arriving introduction in its recipient's box, if the owner's rules let its sender ask and
/// there's room. Whatever happens, the sender's host hears the same as for quarantine.
pub async fn take(
    host: &Host,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
    record: &SenderRecord,
) -> Result<(), ApiError> {
    let recipient = envelope.recipient();
    let rules = admission::rules_of(host, recipient).await?;
    if changes::is_given_up(host, sender).await?
        || changes::is_stopped(host, sender, record).await?
    {
        return Ok(());
    }
    if rules
        .as_ref()
        .is_some_and(|rules| rules.blocks(sender.id()))
    {
        return Ok(());
    }
    let Some(introduction) = introduction_in(envelope.body()) else {
        return Ok(());
    };
    let now = unix_now();
    let kept = match introduction {
        Introduction::Invite(compact) => {
            let Ok(invite) = VerifiedInvite::verify(&compact, sender, recipient, now) else {
                return Ok(());
            };
            // Without a binding there's no address to answer, and nobody to say who they act for.
            let Ok(owner) = Identity::from_encoded(&record.owner_identity) else {
                return Ok(());
            };
            if rules
                .as_ref()
                .is_some_and(|rules| !rules.takes_invites_from(sender.id()))
            {
                return Ok(());
            }
            hold(
                host,
                envelope,
                sender,
                record,
                invite.id(),
                owner.is_unconfirmed_owner(),
            )
            .await?
        }
        Introduction::Acceptance(compact) => {
            let Ok(accepted) = VerifiedAcceptance::verify(&compact, sender, now) else {
                return Ok(());
            };
            let invited: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM invites_sent WHERE sender = $1 AND recipient = $2
                     AND invite_id = $3 AND expires_at > $4)",
            )
            .bind(recipient.as_str())
            .bind(sender.id().as_str())
            .bind(accepted.invite())
            .bind(as_sql(accepted.issued_at()))
            .fetch_one(&host.db)
            .await?;
            if accepted.inviter() != recipient || !invited {
                return Ok(());
            }
            let kept = hold_acceptance(host, envelope, sender, record, accepted.invite()).await?;
            // Only the first acceptance of an invite, which is the one kept.
            if kept
                && let Some(pair) =
                    answered_here(host, recipient, sender, record, &accepted, &compact).await?
            {
                note_agreed(host, recipient, rules.as_ref(), &pair).await?;
            }
            kept
        }
    };
    if kept {
        tracing::info!(message_id = %envelope.id(), "held in the invites box");
    } else {
        tracing::info!(message_id = %envelope.id(), "the invites box didn't keep it: no room, or an invite already answered");
    }
    Ok(())
}

async fn hold(
    host: &Host,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
    record: &SenderRecord,
    invite_id: &str,
    unconfirmed: bool,
) -> Result<bool, ApiError> {
    let count_and_add = sqlx::query(
        "INSERT INTO introductions (recipient, sender, message_id, kind, invite_id, envelope,
             sender_identity, sender_owner_identity, sender_binding, relayed_by, unconfirmed,
             expires_at)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
         WHERE (SELECT count(*) FROM introductions
                WHERE recipient = $1 AND sender = $2 AND kind = $4 AND expires_at > $13) < $14
           AND (SELECT count(*) FROM introductions
                WHERE recipient = $1 AND kind = $4 AND NOT done AND expires_at > $13) < $15
           AND (SELECT count(*) FROM introductions
                WHERE recipient = $1 AND kind = $4 AND relayed_by = $10 AND NOT done
                  AND expires_at > $13) < $16
           AND (NOT $11 OR (SELECT count(*) FROM introductions
                WHERE recipient = $1 AND kind = $4 AND unconfirmed AND NOT done
                  AND expires_at > $13) < $17)
         ON CONFLICT (recipient, message_id) DO NOTHING",
    )
    .bind(envelope.recipient().as_str())
    .bind(sender.id().as_str())
    .bind(envelope.id().as_str())
    .bind(INVITE)
    .bind(invite_id)
    .bind(envelope.compact())
    .bind(sender.encoded())
    .bind(&record.owner_identity)
    .bind(&record.binding)
    .bind(&record.relayed_by)
    .bind(unconfirmed)
    .bind(as_sql(envelope.expires_at()))
    .bind(as_sql(unix_now()))
    .bind(PER_SENDER)
    .bind(WAITING_PER_AGENT)
    .bind(WAITING_PER_HOST)
    .bind(WAITING_UNCONFIRMED);
    let held = admission::counted_alone(host, envelope.recipient().as_str(), count_and_add).await?;
    Ok(held.rows_affected() > 0)
}

/// The first acceptance of an invite is held, and marks the invite answered, in one statement, so two
/// at once can't both get in. Only room in the box decides whether it's taken: an acceptance with no
/// room leaves the invite open.
async fn hold_acceptance(
    host: &Host,
    envelope: &VerifiedEnvelope,
    sender: &Identity,
    record: &SenderRecord,
    invite_id: &str,
) -> Result<bool, ApiError> {
    let count_and_add = sqlx::query(
        "WITH answered AS (
             UPDATE invites_sent SET accepted = TRUE
             WHERE sender = $1 AND recipient = $2 AND invite_id = $5 AND NOT accepted
               AND (SELECT count(*) FROM introductions
                    WHERE recipient = $1 AND kind = $4 AND NOT done AND expires_at > $12) < $13
             RETURNING 1
         )
         INSERT INTO introductions (recipient, sender, message_id, kind, invite_id, envelope,
             sender_identity, sender_owner_identity, sender_binding, relayed_by, unconfirmed,
             expires_at)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, FALSE, $11
         WHERE EXISTS (SELECT 1 FROM answered)
         ON CONFLICT (recipient, message_id) DO NOTHING",
    )
    .bind(envelope.recipient().as_str())
    .bind(sender.id().as_str())
    .bind(envelope.id().as_str())
    .bind(ACCEPTANCE)
    .bind(invite_id)
    .bind(envelope.compact())
    .bind(sender.encoded())
    .bind(&record.owner_identity)
    .bind(&record.binding)
    .bind(&record.relayed_by)
    .bind(as_sql(envelope.expires_at()))
    .bind(as_sql(unix_now()))
    .bind(ACCEPTANCES_WAITING);
    let held = admission::counted_alone(host, envelope.recipient().as_str(), count_and_add).await?;
    Ok(held.rows_affected() > 0)
}

async fn read_box(State(host): State<Arc<Host>>, headers: HeaderMap) -> Result<Response, ApiError> {
    box_page(&host, &headers, INVITES_PATH, 0).await
}

/// The same, from after the row a page before said to go on from.
async fn read_box_after(
    State(host): State<Arc<Host>>,
    Path(after): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let path = format!("{INVITES_PATH}/after/{after}");
    box_page(&host, &headers, &path, after).await
}

/// One page of the box. Others fill it, so only how long each row is gets read first, and room is
/// taken for the ones that fit before they're read. An invite stays until its owner answers, so a
/// reader goes on from where a page stopped rather than waiting for the first ones to go.
async fn box_page(
    host: &Host,
    headers: &HeaderMap,
    path: &str,
    after: i64,
) -> Result<Response, ApiError> {
    let agent = inbox::authenticated_agent(host, headers, "GET", path, b"").await?;
    let sized = sqlx::query(
        "SELECT seq, (octet_length(envelope) + octet_length(sender_identity)
             + octet_length(sender_owner_identity) + octet_length(sender_binding))::bigint AS bytes
         FROM introductions WHERE recipient = $1 AND NOT done AND expires_at > $2 AND seq > $3
         ORDER BY seq LIMIT $4",
    )
    .bind(agent.as_str())
    .bind(as_sql(unix_now()))
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
        "SELECT seq, envelope, sender_identity, sender_owner_identity, sender_binding
         FROM introductions WHERE recipient = $1 AND seq = ANY($2) AND NOT done ORDER BY seq",
    )
    .bind(agent.as_str())
    .bind(&page.keys)
    .fetch_all(&host.db)
    .await?;
    let held = rows
        .iter()
        .map(|row| {
            Ok(HeldIntroduction {
                seq: row.try_get("seq")?,
                envelope: row.try_get("envelope")?,
                sender_identity: row.try_get("sender_identity")?,
                sender_owner_identity: row.try_get("sender_owner_identity")?,
                sender_binding: row.try_get("sender_binding")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    let next = page.keys.last().copied().filter(|_| page.more);
    room.json(&IntroductionsPage { held, next })
}

/// What its Signet has dealt with. The row stays until it would have expired, with nothing in it, so
/// what's declined still counts against its sender.
async fn done(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let agent =
        inbox::authenticated_agent(&host, &headers, "POST", INVITES_DONE_PATH, &body).await?;
    let done: IntroductionsDone =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("bad body"))?;
    sqlx::query(
        "UPDATE introductions SET done = TRUE, envelope = '', sender_identity = '',
             sender_owner_identity = '', sender_binding = ''
         WHERE recipient = $1 AND seq = ANY($2) AND kind = $3",
    )
    .bind(agent.as_str())
    .bind(&done.seqs)
    .bind(INVITE)
    .execute(&host.db)
    .await?;
    // An acceptance is only a hint once read, and keeps no room from anyone.
    sqlx::query("DELETE FROM introductions WHERE recipient = $1 AND seq = ANY($2) AND kind = $3")
        .bind(agent.as_str())
        .bind(&done.seqs)
        .bind(ACCEPTANCE)
        .execute(&host.db)
        .await?;
    Ok(Json(serde_json::json!({})))
}

pub async fn forget_for_new_owner(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
) -> Result<(), sqlx::Error> {
    for statement in [
        "DELETE FROM introductions WHERE recipient = $1",
        "DELETE FROM invites_sent WHERE sender = $1",
        "DELETE FROM agreed_contacts WHERE agent = $1",
    ] {
        sqlx::query(statement)
            .bind(agent.as_str())
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

pub async fn run_cleanup(host: Arc<Host>, every: std::time::Duration) {
    loop {
        tokio::time::sleep(every).await;
        let now = host.clock.now_for_sql().await;
        for statement in [
            "DELETE FROM introductions WHERE expires_at <= $1",
            "DELETE FROM invites_sent WHERE expires_at <= $1",
        ] {
            if let Err(error) = sqlx::query(statement).bind(now).execute(&host.db).await {
                tracing::warn!(%error, "invites cleanup failed");
            }
        }
    }
}

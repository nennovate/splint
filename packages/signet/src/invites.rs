//! Invites over Splint, from the agent's side. An agent invites someone by address or contact card,
//! reads its invites box, and accepts or declines what's there. Accepting signs an acceptance with
//! this agent's key and nothing else. If the owner's rules let in contacts their agent agrees with by
//! itself, whoever it's with is one at once, marked as not approved by the owner, up to 100 a day.
//! Otherwise they become a contact only when its owner's side signs them into the rules, which is a
//! stand-in's own `splint auto`, or the owner on their page.
//!
//! An invite by address trusts the host there once, to say which ID it is. The invite names that ID,
//! and only that ID's key can accept it, so a host can't change its answer afterwards. A card carries
//! the ID itself, so it trusts nobody. An invite carries no words: its sender isn't a contact, and
//! nothing the owner signed lets words out to them.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::{Mutex as ShortLock, PoisonError};

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::contact_invites::{
    ContactCard, Introduction, InviteDraft, MAX_INVITE_LIFETIME_SECS, PendingContact,
    VerifiedAcceptance, VerifiedInvite, acceptance_body, introduction_in, invite_body,
    sign_acceptance, sign_invite,
};
use splint_core::host_api::HeldIntroduction;
use splint_core::rules::ContactStatus;
use splint_core::{
    Identity, SplintId, VerifiedBinding, VerifiedEnvelope, name_parts, parse_address,
    sign_envelope, unix_now,
};

use crate::Signet;
use crate::activity::{Arrival, Kind};
use crate::agent_api::{ApiError, invited_address_named, typed_address, typed_address_named};
use crate::budget::NotTaken;
use crate::contacts::{Controls, SameOwner, controls_of, verified_owner_of};
use crate::ending::{self, Done, Held, IntroductionRows, Proof, Readable};
use crate::host_client::{Found, HostError};
use crate::state_file::{self, StateError};
use crate::who::Who;

/// Invites this agent may try in a day, which a fooled agent can't raise. Its host counts those that
/// go, and this counts every one that could ask another host who's at an address, gone or not.
const INVITES_PER_DAY: u32 = 100;
/// Half that before anyone has set up controls for it, which is all its host allows then.
const UNCONFIRMED_INVITES_PER_DAY: u32 = INVITES_PER_DAY / 2;
/// Contacts waiting for the owner's side at once. Each needed this agent to say yes, or to have
/// invited them, so an honest agent has far fewer.
const MAX_PENDING: usize = 64;
/// What an agent types to name an invite: the start of its ID, as with requests, or the address it's from.
const FEWEST_ID_CHARS: usize = 8;
const SHOWN_ID_CHARS: usize = 16;
/// Invites answered, kept until they'd have ended. A host chooses what's in the box, so it could fill
/// this with invites rules clear; past it, those ending soonest go first.
const MAX_ANSWERED: usize = 10_000;
const ANSWERED_FILE: &str = "invites-answered.json";
const STILL_OPEN: ApiError = ApiError::BadRequest(
    "this agent's invite to them is still open, so no other was sent. It's under sent in the \
     invites box until they accept or it ends",
);

/// An invite this agent sent, until it's answered or over.
#[derive(Clone, Deserialize, Serialize)]
struct Sent {
    to: String,
    agent: SplintId,
    compact: String,
    at: u64,
    expires_at: u64,
    accepted: bool,
}

/// An invite and its acceptance, waiting for the owner's side to sign the other agent in.
#[derive(Clone, Deserialize, Serialize)]
pub struct Pending {
    pub record: PendingContact,
    pub agent: SplintId,
    pub address: String,
    pub at: u64,
}

pub struct Invites {
    sent_path: PathBuf,
    /// By invite ID.
    sent: ShortLock<HashMap<String, Sent>>,
    pending_path: PathBuf,
    /// By the other agent's ID.
    pending: ShortLock<HashMap<String, Pending>>,
    /// The newest box row the agent has been told of, so `wait` wakes it once per new invite.
    told_up_to: ShortLock<i64>,
    answered_path: PathBuf,
    /// Invites declined, accepted, or cleared by the rules, by ID, until each would have ended. Only
    /// the host marks a row done, so a hostile one can put back what was answered, and offering it
    /// again would bring back a contact the owner removed.
    answered: ShortLock<HashMap<String, u64>>,
}

fn locked<T>(lock: &ShortLock<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Invites {
    pub fn load(sent_path: PathBuf, pending_path: PathBuf) -> Result<Self, StateError> {
        let answered_path = sent_path.with_file_name(ANSWERED_FILE);
        Ok(Self {
            answered: ShortLock::new(state_file::load(&answered_path)?),
            answered_path,
            sent: ShortLock::new(state_file::load(&sent_path)?),
            sent_path,
            pending: ShortLock::new(state_file::load(&pending_path)?),
            pending_path,
            told_up_to: ShortLock::new(0),
        })
    }

    fn change_sent(
        &self,
        change: impl FnOnce(&mut HashMap<String, Sent>),
    ) -> Result<(), HostError> {
        let now = unix_now();
        let mut sent = locked(&self.sent);
        sent.retain(|_, one| one.expires_at > now);
        change(&mut sent);
        state_file::save(&self.sent_path, &*sent).map_err(|_| HostError::LocalStorage)
    }

    fn was_answered(&self, id: &str) -> bool {
        locked(&self.answered).contains_key(id)
    }

    fn note_answered(&self, invite: &VerifiedInvite) -> Result<(), HostError> {
        let now = unix_now();
        let mut answered = locked(&self.answered);
        answered.retain(|_, ends| *ends > now);
        answered.insert(invite.id().to_owned(), invite.expires_at());
        while answered.len() > MAX_ANSWERED {
            let soonest = answered
                .iter()
                .min_by_key(|(_, ends)| **ends)
                .map(|(id, _)| id.clone());
            let Some(soonest) = soonest else { break };
            answered.remove(&soonest);
        }
        state_file::save(&self.answered_path, &*answered).map_err(|_| HostError::LocalStorage)
    }

    fn sent_by_id(&self, id: &str) -> Option<Sent> {
        locked(&self.sent).get(id).cloned()
    }

    /// Whether an invite this agent sent, still open, fits: not accepted and not over.
    fn open_one(&self, fits: impl Fn(&Sent) -> bool) -> bool {
        let now = unix_now();
        locked(&self.sent)
            .values()
            .any(|one| !one.accepted && one.expires_at > now && fits(one))
    }

    fn add_pending(&self, pending: Pending) -> Result<(), ApiError> {
        let mut all = locked(&self.pending);
        let key = pending.agent.as_str().to_owned();
        if !all.contains_key(&key) && all.len() >= MAX_PENDING {
            return Err(ApiError::Host(HostError::TooMany));
        }
        all.insert(key, pending);
        state_file::save(&self.pending_path, &*all).map_err(|_| HostError::LocalStorage)?;
        Ok(())
    }

    /// What waits for the owner's side, leaving out whoever the rules have since named, which is
    /// someone dealt with. Each lasts as long as an invite would.
    pub fn pending(&self, named: &[SplintId]) -> Vec<Pending> {
        let now = unix_now();
        locked(&self.pending)
            .values()
            .filter(|one| now.saturating_sub(one.at) < MAX_INVITE_LIFETIME_SECS)
            .filter(|one| !named.contains(&one.agent))
            .cloned()
            .collect()
    }

    /// Drops what the rules now name, or what's over, once new rules have come.
    pub fn settle(&self, named: &[SplintId]) -> Result<(), HostError> {
        let now = unix_now();
        let mut all = locked(&self.pending);
        let before = all.len();
        all.retain(|_, one| {
            now.saturating_sub(one.at) < MAX_INVITE_LIFETIME_SECS && !named.contains(&one.agent)
        });
        if all.len() != before {
            state_file::save(&self.pending_path, &*all).map_err(|_| HostError::LocalStorage)?;
        }
        Ok(())
    }

    /// For when this agent gets a new owner, whose invites none of these are.
    pub fn forget_everything(&self) -> Result<(), HostError> {
        locked(&self.sent).clear();
        locked(&self.pending).clear();
        state_file::save(&self.sent_path, &*locked(&self.sent))
            .map_err(|_| HostError::LocalStorage)?;
        state_file::save(&self.pending_path, &*locked(&self.pending))
            .map_err(|_| HostError::LocalStorage)
    }
}

pub fn agent_routes(signet: Arc<Signet>) -> Router<Arc<Signet>> {
    let sends = Router::new()
        .route("/v0/invites", post(invite))
        .route("/v0/invites/{id}/accept", post(accept))
        .route_layer(axum::middleware::from_fn_with_state(
            signet,
            crate::agent_api::refuse_if_stopped,
        ));
    Router::new()
        .route("/v0/invites", get(list))
        .route("/v0/invites/{id}/decline", post(decline))
        .route("/v0/card", get(card))
        .merge(sends)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteRequest {
    /// An address, or a contact card.
    to: String,
    /// Only so an agent that sends one hears why it isn't taken.
    #[serde(default)]
    note: Option<serde::de::IgnoredAny>,
}

#[derive(Serialize)]
struct InviteSent {
    invite: String,
    to: String,
    expires_at: u64,
    /// How the ID it went to was found: from a card, or from the host at that address.
    found_by: &'static str,
}

/// What an invite is aimed at, as read here without asking anyone.
struct Aim {
    card: Option<ContactCard>,
    address: String,
}

fn aim(to: &str) -> Result<Aim, ApiError> {
    let card = if ContactCard::is_card(to) {
        Some(
            ContactCard::parse(to)
                .map_err(|_| ApiError::BadRequest("that card isn't whole: copy all of it"))?,
        )
    } else {
        None
    };
    let address = match &card {
        Some(card) => card.address.clone(),
        None => typed_address(to)?,
    };
    parse_address(&address).map_err(|_| ApiError::BadRequest("an address is name~domain"))?;
    Ok(Aim { card, address })
}

/// Counts an invite against the day's invites and the owner's actions before anything leaves this
/// machine. Finding who's at an address asks the host there for a handle the agent chose, which it
/// sees whether or not anybody answers, so a lookup counts as an invite even when none is sent.
async fn count_invite(signet: &Signet, who: &Who) -> Result<(), ApiError> {
    let allowed = if who.owner.is_unconfirmed_owner() {
        UNCONFIRMED_INVITES_PER_DAY
    } else {
        INVITES_PER_DAY
    };
    signet
        .budget
        .take_invite(allowed, unix_now())
        .await
        .map_err(|not_taken| match not_taken {
            NotTaken::Spent => ApiError::Host(HostError::TooMany),
            NotTaken::Unsaved => ApiError::Host(HostError::LocalStorage),
        })?;
    crate::budget::spend(signet).await
}

/// The lookup went out, and may have reached the host before it failed, so like any lookup it counts.
const CARD_HOST_UNREACHABLE: &str = "couldn't reach the host at that card's address, so nothing was \
     sent, and the card may well be right. Try again later. The try counts toward today's invites, as \
     the lookup may have reached that host";

/// Whom an invite goes to: the ID a card carries, an ID already pinned at that address, or the one
/// its host names now, which is pinned from then on. Whatever the owner signed at an address holds over
/// a card and a host alike: a block there is refused, and a host naming anyone else is refused, and the
/// owner hears. A card naming another ID than the one signed or pinned there is refused too.
async fn whom(signet: &Signet, aim: Aim) -> Result<(String, SplintId, &'static str), ApiError> {
    let Aim { card, address } = aim;
    // An owner's ID in place of their name becomes the name it stands for, before anything is matched.
    let address = invited_address_named(signet, &address).await?;
    let (handle, domain) =
        parse_address(&address).map_err(|_| ApiError::BadRequest("an address is name~domain"))?;
    let not_who_is_there = ApiError::BadRequest(
        "that card names someone other than who your agent knows at that address, so nothing was sent",
    );
    if let Some(named) = signet.rules.signed_at(&address).await {
        if named.status == ContactStatus::Blocked {
            return Err(ApiError::NotAContact);
        }
        if let Some(card) = card {
            return if card.agent == named.agent {
                Ok((address, card.agent, "card"))
            } else {
                Err(not_who_is_there)
            };
        }
        signet
            .contacts
            .named_by_rules(
                &signet.lookup(&signet.who()),
                &address,
                handle,
                domain,
                &named.agent,
            )
            .await
            .map_err(|_| {
                ApiError::BadRequest(
                    "that address's host doesn't name the contact your owner signed there, so \
                     nothing was sent, and your owner can see it",
                )
            })?;
        return Ok((address, named.agent, "rules"));
    }
    if let Some(pinned) = signet.contacts.pinned_at(&address).await {
        return match card {
            Some(card) if card.agent != pinned => Err(not_who_is_there),
            Some(_) => Ok((address, pinned, "card")),
            None => Ok((address, pinned, "pinned")),
        };
    }
    if let Some(card) = card {
        // A card names the ID itself, but one copied with a character wrong names nobody, and its
        // invite would wait a week unanswered. So its host has to name that same ID at the address:
        // a host can stop a card's invite this way, as it can by not delivering it, but never send it
        // to anyone else. A host that's down says nothing about the card, so that's told apart.
        let found = signet
            .lookup(&signet.who())
            .resolve_saying_why(handle, domain)
            .await
            .map_err(|error| match error {
                HostError::Unreachable => ApiError::CouldntReach(CARD_HOST_UNREACHABLE),
                HostError::TooMany => ApiError::Host(HostError::TooMany),
                _ => ApiError::BadRequest(
                    "nobody answers at that card's address, so nothing was sent. Check the card \
                     was copied whole",
                ),
            })?;
        if found.agent.id() != &card.agent {
            return Err(ApiError::BadRequest(
                "that card's ID isn't the agent its host names at that address, so nothing was \
                 sent. Check the card was copied exactly",
            ));
        }
        return Ok((address, card.agent, "card"));
    }
    let found = signet
        .lookup(&signet.who())
        .resolve(handle, domain)
        .await
        .map_err(|_| ApiError::BadRequest("nobody answers at that address"))?;
    let agent = found.agent.id().clone();
    signet.contacts.pin_found(&address, found).await?;
    Ok((address, agent, "host"))
}

/// Who `whom` would send an invite to without asking anyone: the ID the owner signed or this Signet
/// pinned at that address, if a card names no other, or a card's. `None` where it would refuse or ask.
async fn known_at(signet: &Signet, aim: &Aim) -> Option<SplintId> {
    let held = match signet.rules.signed_at(&aim.address).await {
        Some(named) if named.status == ContactStatus::Blocked => return None,
        Some(named) => Some(named.agent),
        None => signet.contacts.pinned_at(&aim.address).await,
    };
    match (held, &aim.card) {
        (Some(held), Some(card)) => (held == card.agent).then_some(held),
        (Some(held), None) => Some(held),
        (None, card) => card.as_ref().map(|card| card.agent.clone()),
    }
}

async fn invite(
    State(signet): State<Arc<Signet>>,
    Json(request): Json<InviteRequest>,
) -> Result<Json<InviteSent>, ApiError> {
    // Words to someone who isn't a contact are words the owner never let out, and a fooled agent's
    // would be anything it read, so an invite carries none.
    if request.note.is_some() {
        return Err(ApiError::BadRequest(
            "an invite carries no note, as it goes to someone who isn't a contact yet. Once \
             they're one, write to them",
        ));
    }
    if !signet.rules.let_agent_invite().await {
        return Err(ApiError::OwnerInvites);
    }
    // The handle goes to this agent's host to look up, and to a peer's in its path, so a code or a
    // token written as one would leave like any other words.
    crate::secret_egress::refuse_secrets(&signet, &request.to).await?;
    let who = signet.who();
    let own_address = signet.address();
    let own = ApiError::BadRequest("that's this agent's own address");
    let aim = aim(&request.to)?;
    if aim.address == own_address {
        return Err(own);
    }
    // An agent woken twice invites twice, and the other would have two to answer, so one open invite
    // to them is enough. Checked before counting when this Signet already knows who's there, as then
    // nobody is asked anything, and again below once it's found.
    if let Some(known) = known_at(&signet, &aim).await
        && signet
            .invites
            .open_one(|one| one.to == aim.address && one.agent == known)
    {
        return Err(STILL_OPEN);
    }
    count_invite(&signet, &who).await?;
    let (to, agent, found_by) = whom(&signet, aim).await?;
    if &agent == who.identity.id() || to == own_address {
        return Err(own);
    }
    // The owner named them with nothing to use, which an agreement can't get past, so an invite
    // would wait unanswerable for a week. Only the owner adding them back does.
    let taken_out = signet
        .rules
        .signed_for(&agent)
        .await
        .is_some_and(|named| named.status == ContactStatus::Allowed && named.types.is_empty());
    if taken_out {
        return Err(ApiError::BadRequest(
            "your owner took them out of your contacts, so no invite was sent: only your owner \
             adding them back undoes that",
        ));
    }
    if signet.rules.blocks(&agent).await {
        return Err(ApiError::NotAContact);
    }
    let listed = signet.rules.all_contacts().await;
    if let Some(known) = listed
        .iter()
        .find(|one| one.agent == agent || one.address == to)
    {
        if known.agent != agent || known.address != to {
            // A card naming another ID than the one the owner signed there, or their contact elsewhere.
            return Err(ApiError::BadRequest(
                "your owner signed someone else at that address, or that agent at another, so \
                 nothing was sent",
            ));
        }
        return Err(ApiError::BadRequest("that's already one of your contacts"));
    }
    if signet
        .invites
        .open_one(|one| one.to == to && one.agent == agent)
    {
        return Err(STILL_OPEN);
    }
    let now = unix_now();
    let (_, domain) =
        parse_address(&to).map_err(|_| ApiError::BadRequest("an address is name~domain"))?;
    let expires_at = now.saturating_add(MAX_INVITE_LIFETIME_SECS);
    let draft = InviteDraft {
        from_address: &own_address,
        to: &to,
        to_agent: &agent,
        expires_at,
    };
    let compact = sign_invite(&signet.key, &who.identity, &draft, now)?;
    let invite = VerifiedInvite::verify(&compact, &who.identity, &agent, now)?;
    let envelope = sign_envelope(
        &signet.key,
        &who.identity,
        &agent,
        invite_body(&compact)?,
        now,
        MAX_INVITE_LIFETIME_SECS,
    )?;
    signet.host.send(&envelope.compact, domain).await?;
    let id = invite.id().to_owned();
    signet.invites.change_sent(|sent| {
        sent.insert(
            id.clone(),
            Sent {
                to: to.clone(),
                agent,
                compact,
                at: now,
                expires_at,
                accepted: false,
            },
        );
    })?;
    tracing::info!(message_id = %envelope.id, "sent an invite");
    Ok(Json(InviteSent {
        invite: short(&id),
        to,
        expires_at,
        found_by,
    }))
}

fn short(id: &str) -> String {
    id.chars().take(SHOWN_ID_CHARS).collect()
}

/// One row of the box, checked again here: signed by the agent it names, under the newest copy of
/// its ID this Signet has seen, for this agent, with the address its owner signed for it.
struct Checked {
    sender: Identity,
    found: Option<Found>,
    what: Introduction,
    read: Readable<IntroductionRows>,
}

impl Checked {
    fn envelope(&self) -> &VerifiedEnvelope {
        self.read.envelope()
    }
}

/// What to do with a row of the box.
enum Row {
    Checks(Box<Checked>),
    /// Proven bad for good, so it's cleared.
    Clear(Proof<IntroductionRows>),
    /// It can't be read yet, or never by this release, so it stays until it expires at the host.
    Leave(Held),
}

async fn checked_row(signet: &Signet, row: &HeldIntroduction, me: &SplintId) -> Row {
    let read = match ending::check_introduction(signet, row, me).await {
        ending::Checked::Valid(read) => read,
        // Only an inbox row is let go.
        ending::Checked::Held(why) | ending::Checked::LetGo(_, why) => return Row::Leave(why),
        ending::Checked::Bad(proof) => return Row::Clear(proof),
    };
    // Verified under it just now, so only a host changing its copy in between makes this fail.
    let sender = Identity::from_encoded(&row.sender_identity)
        .and_then(|claimed| signet.contacts.known.newest(&claimed));
    let Ok(sender) = sender else {
        return Row::Leave(Held::Unreadable);
    };
    // Its host took it as one, so it may be a kind this release doesn't know.
    let Some(what) = introduction_in(read.envelope().body()) else {
        return Row::Leave(Held::Unreadable);
    };
    let found = Identity::from_encoded(&row.sender_owner_identity)
        .and_then(|presented| signet.contacts.known.newest(&presented))
        .ok()
        .and_then(|owner| {
            let binding = VerifiedBinding::verify(&row.sender_binding, &owner, &sender).ok()?;
            Some((owner, binding))
        })
        .map(|(owner, binding)| Found {
            agent: sender.clone(),
            owner,
            binding: binding.compact().to_owned(),
        });
    Row::Checks(Box::new(Checked {
        sender,
        found,
        what,
        read,
    }))
}

/// An invite in the box that checks out: the address it gives is the one its sender's owner signed.
struct Offered {
    seq: i64,
    /// What clears it at the host once it's answered.
    done: Done<IntroductionRows>,
    invite: VerifiedInvite,
    found: Found,
}

/// `own_address` is where this agent is bound: an invite naming its ID at someone else's address, as a
/// card pairing the two would, is never one to accept.
fn offered(checked: &Checked, me: &SplintId, own_address: &str) -> Option<Offered> {
    let Introduction::Invite(compact) = &checked.what else {
        return None;
    };
    let invite = VerifiedInvite::verify(compact, &checked.sender, me, unix_now()).ok()?;
    if invite.to() != own_address {
        return None;
    }
    let found = checked.found.clone()?;
    let bound = VerifiedBinding::verify(&found.binding, &found.owner, &found.agent).ok()?;
    if bound.address() != invite.from_address() {
        return None;
    }
    Some(Offered {
        seq: checked.read.seq(),
        done: Done::handed_over(&checked.read),
        invite,
        found,
    })
}

/// Whether the address an invite is from is where the owner signed, or this agent pinned, another ID.
/// A host can bind a new agent at an address someone already knows, and offering its invite would pass
/// it off as them. The owner hears, as for a host naming someone else when an invite goes out.
async fn someone_else_known_there(signet: &Signet, offer: &Offered) -> Result<bool, HostError> {
    let address = offer.invite.from_address();
    let from = offer.invite.from();
    if let Some(signed) = signet.rules.signed_at(address).await {
        if &signed.agent == from {
            return Ok(false);
        }
        signet
            .contact_asks
            .note_disagreement(address, &signed.agent)?;
        tracing::warn!("refused an invite from an address the owner signed for another ID");
        return Ok(true);
    }
    match signet.contacts.pinned_at(address).await {
        Some(pinned) if &pinned != from => {
            signet
                .contact_asks
                .note_disagreement_with_pin(address, &pinned)?;
            tracing::warn!("refused an invite from an address pinned to another ID");
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Reads the box: invites that check out, after acceptances of this agent's own invites are taken and
/// anything that can never count is cleared. Anything from someone the rules block goes too, as does
/// an invite the owner's reach rules don't let ask, which its host should have kept out already.
async fn read_box(signet: &Signet) -> Result<Vec<Offered>, ApiError> {
    let who = signet.who();
    let me = who.identity.id();
    let own_address = signet.address();
    let rows = signet.host.introductions(&signet.key, me).await?;
    let mut done = Vec::new();
    let mut offers = Vec::new();
    for row in &rows {
        let checked = match checked_row(signet, row, me).await {
            Row::Checks(checked) => *checked,
            Row::Clear(proof) => {
                done.push(Done::proven_bad(proof));
                continue;
            }
            Row::Leave(why) => {
                tracing::debug!(seq = row.seq, ?why, "an invite waits until it can be read");
                continue;
            }
        };
        if signet.rules.blocks(checked.sender.id()).await {
            done.push(Done::proven_bad(Proof::refused_by_rules(&checked.read)));
            continue;
        }
        match &checked.what {
            Introduction::Invite(_) => {
                let Some(offer) = offered(&checked, me, &own_address) else {
                    done.push(Done::proven_bad(Proof::refused_by_checks(&checked.read)));
                    continue;
                };
                if signet.invites.was_answered(offer.invite.id()) {
                    tracing::warn!("cleared an invite already answered, which its host put back");
                    done.push(Done::proven_bad(Proof::replay(&checked.read)));
                    continue;
                }
                let may_ask = signet.rules.takes_invites_from(checked.sender.id()).await;
                if may_ask && !someone_else_known_there(signet, &offer).await? {
                    offers.push(offer);
                } else {
                    signet.invites.note_answered(&offer.invite)?;
                    done.push(Done::proven_bad(Proof::refused_by_rules(&checked.read)));
                }
            }
            Introduction::Acceptance(compact) => {
                take_acceptance(signet, &who, &checked, compact).await?;
                done.push(Done::handed_over(&checked.read));
            }
        }
    }
    if !done.is_empty() {
        signet
            .host
            .introductions_done(&signet.key, me, &done)
            .await?;
    }
    Ok(offers)
}

/// An acceptance of an invite this agent sent, signed by the key that invite named, by an agent its
/// owner bound to the address the invite went to, becomes a contact waiting for the owner's side.
/// Anything else is dropped. The binding is the one the acceptor's own host passed on, the authority
/// over its handles, so a card pairing one agent's ID with another's address gets nobody in. An
/// invite is answered once: after that, what waited for the owner's side goes when they decide, and a
/// contact they removed can't sign the same invite again to be offered back.
async fn take_acceptance(
    signet: &Signet,
    who: &Who,
    checked: &Checked,
    compact: &str,
) -> Result<(), ApiError> {
    let me = &who.identity;
    let Ok(accepted) = VerifiedAcceptance::verify(compact, &checked.sender, unix_now()) else {
        tracing::warn!(message_id = %checked.envelope().id(), "refused an acceptance that doesn't verify");
        return Ok(());
    };
    let Some(sent) = signet.invites.sent_by_id(accepted.invite()) else {
        tracing::warn!(message_id = %checked.envelope().id(), "refused an acceptance of no invite sent from here");
        return Ok(());
    };
    if sent.accepted {
        tracing::warn!(message_id = %checked.envelope().id(), "refused another acceptance of an invite already accepted");
        return Ok(());
    }
    let answered = VerifiedInvite::verify(&sent.compact, me, &sent.agent, accepted.issued_at())
        .and_then(|invite| accepted.answers(&invite));
    if answered.is_err() || checked.sender.id() != &sent.agent {
        tracing::warn!(message_id = %checked.envelope().id(), "refused an acceptance signed by another key than the invite named");
        return Ok(());
    }
    let bound = checked.found.clone().filter(|found| {
        VerifiedBinding::verify_for(&found.binding, &found.owner, &found.agent, &sent.to).is_ok()
    });
    let Some(found) = bound else {
        tracing::warn!(message_id = %checked.envelope().id(), "refused an acceptance by an agent not bound to the address the invite went to");
        return Ok(());
    };
    let record = PendingContact {
        invite: sent.compact.clone(),
        acceptance: compact.to_owned(),
        inviter_identity: me.encoded(),
        invitee_identity: checked.sender.encoded(),
        inviter_owner_identity: who.owner.encoded(),
        inviter_binding: who.binding.clone(),
        invitee_owner_identity: found.owner.encoded(),
        invitee_binding: found.binding.clone(),
    };
    let now = unix_now();
    let agreed = signet.rules.agree(record.clone(), now).await?;
    if !agreed {
        signet.invites.add_pending(Pending {
            record,
            agent: sent.agent.clone(),
            address: sent.to.clone(),
            at: now,
        })?;
    }
    let id = accepted.invite().to_owned();
    signet.invites.change_sent(|all| {
        // Another still open to the same agent, as a Signet before issue 704 sent, is answered too:
        // they're this agent's contact, or waiting for its owner's side, by this one.
        all.retain(|other, one| other == &id || one.agent != sent.agent || one.accepted);
        if let Some(one) = all.get_mut(&id) {
            one.accepted = true;
        }
    })?;
    signet.contacts.pin_found(&sent.to, found).await?;
    if agreed {
        tracing::info!(agent = %sent.agent, "an invite was accepted, and they're a contact the owner hasn't approved");
        signet.activity.arrived(Arrival::Messages, &sent.agent);
    } else {
        tracing::info!(agent = %sent.agent, "an invite was accepted, and waits for the owner's side");
    }
    signet.activity.note(Kind::Owner);
    Ok(())
}

/// For the loop beside the agent: takes acceptances as they come, accepts an invite from another
/// agent of this same owner by itself, and wakes an agent waiting when any other new invite is in its
/// box.
pub async fn take_box(signet: &Signet) -> Result<(), HostError> {
    let offers = match read_box(signet).await {
        Ok(offers) => offers,
        Err(ApiError::Host(error)) => return Err(error),
        Err(_) => return Ok(()),
    };
    let offers = match accept_the_same_owners(signet, offers).await {
        Ok(offers) => offers,
        Err(ApiError::Host(error)) => return Err(error),
        Err(_) => return Ok(()),
    };
    let mut told = locked(&signet.invites.told_up_to);
    let new: Vec<SplintId> = offers
        .iter()
        .filter(|offer| offer.seq > *told)
        .map(|offer| offer.invite.from().clone())
        .collect();
    *told = offers
        .iter()
        .map(|offer| offer.seq)
        .max()
        .unwrap_or(0)
        .max(*told);
    drop(told);
    for from in &new {
        signet.activity.arrived(Arrival::Messages, from);
    }
    Ok(())
}

/// What an agent can say about who an invite is from, all of it checked against signatures.
fn from_whom(offer: &Offered) -> (String, String) {
    let address = offer.invite.from_address();
    let unconfirmed = offer.found.owner.is_unconfirmed_owner();
    let said = parse_address(address)
        .ok()
        .map(|(name, _)| name_parts(name))
        .and_then(|(agent, owner)| {
            owner
                .filter(|_| !unconfirmed)
                .map(|owner| format!("{owner}'s {agent}"))
        })
        .map_or_else(
            || format!("{address} invites you"),
            |who| format!("{who} ({address}) invites you"),
        );
    (said, controls_of(Controls::of_owner(&offer.found.owner)))
}

/// Who an invite's sender acts for, as this Signet can stand behind it: the binding pinned for them if
/// there is one, which only moves on, or else the one the invite came with, checked again now at the
/// address it gives. Nothing while a change waits on this agent's owner's word about them.
async fn inviter_owner(signet: &Signet, offer: &Offered) -> Option<Identity> {
    let from = offer.invite.from();
    if signet.rules.held_by_a_change(from).await {
        return None;
    }
    match verified_owner_of(signet, from).await {
        Some(pinned) => Some(pinned),
        None => signet
            .contacts
            .owner_by_binding(&offer.found, offer.invite.from_address()),
    }
}

#[derive(Serialize)]
struct InviteView {
    id: String,
    from: String,
    /// Worked out here from what's signed, never the inviter's own words.
    says: String,
    /// Whose agent it is, or that nobody has set up its controls yet.
    controls: String,
    expires_at: u64,
    #[serde(flatten)]
    same_owner: SameOwner,
}

#[derive(Serialize)]
struct SentView {
    id: String,
    to: String,
    accepted: bool,
    expires_at: u64,
}

/// Someone who wrote in and is held, as an agent that adds its own contacts sees them: only who they
/// are, by signatures, so it can invite them. What they wrote stays held, as it may be written to fool.
#[derive(Serialize)]
struct HeldView {
    address: String,
    id: SplintId,
}

#[derive(Serialize)]
struct InvitesBox {
    invites: Vec<InviteView>,
    sent: Vec<SentView>,
    /// Contacts agreed on both sides, waiting for this agent's owner's side to sign them in.
    waiting_for_owner: Vec<String>,
    /// Strangers held at the host, for an agent whose owner lets it add contacts itself. Otherwise
    /// they're its owner's to let in, and this is empty.
    held: Vec<HeldView>,
}

async fn list(State(signet): State<Arc<Signet>>) -> Result<Json<InvitesBox>, ApiError> {
    let mut offers = read_box(&signet).await?;
    // While the owner's rules have it stopped, an agent is shown nothing new, as with its inbox.
    if signet.rules.stopped().await {
        offers.clear();
    }
    // One invite for each agent that sent any, the newest, as answering one answers them all. `from`
    // is the key that signed it, so nobody else's invite can stand in for or hide theirs.
    offers.sort_by_key(|offer| std::cmp::Reverse(offer.invite.issued_at()));
    let mut shown = HashSet::new();
    offers.retain(|offer| shown.insert(offer.invite.from().clone()));
    let mut invites = Vec::new();
    for offer in &offers {
        let (says, controls) = from_whom(offer);
        let owner = inviter_owner(&signet, offer).await;
        invites.push(InviteView {
            id: short(offer.invite.id()),
            from: offer.invite.from_address().to_owned(),
            says,
            controls,
            expires_at: offer.invite.expires_at(),
            same_owner: SameOwner::of(&signet, owner.as_ref()),
        });
    }
    invites.sort_by(|a, b| b.expires_at.cmp(&a.expires_at));
    let now = unix_now();
    let mut sent: Vec<SentView> = locked(&signet.invites.sent)
        .iter()
        .filter(|(_, one)| one.expires_at > now)
        .map(|(id, one)| SentView {
            id: short(id),
            to: one.to.clone(),
            accepted: one.accepted,
            expires_at: one.expires_at,
        })
        .collect();
    sent.sort_by(|a, b| b.expires_at.cmp(&a.expires_at));
    let named: Vec<SplintId> = signet
        .rules
        .all_contacts()
        .await
        .into_iter()
        .map(|one| one.agent)
        .collect();
    let waiting_for_owner = signet
        .invites
        .pending(&named)
        .into_iter()
        .map(|one| one.address)
        .collect();
    let mut held = Vec::new();
    if signet.rules.agent_adds_contacts().await {
        for (address, id) in crate::rules::held_senders(&signet).await? {
            if !named.contains(&id) {
                held.push(HeldView { address, id });
            }
        }
    }
    Ok(Json(InvitesBox {
        invites,
        sent,
        waiting_for_owner,
        held,
    }))
}

/// The one invite an agent named, by the start of its ID or by the address it's from, newest first,
/// and every other in the box from the agent that signed it.
async fn named(signet: &Signet, given: &str) -> Result<(Offered, Vec<Offered>), ApiError> {
    let offers = read_box(signet).await?;
    let by_address = typed_address_named(signet, given).await.ok();
    let fits = |offer: &&Offered| match &by_address {
        Some(address) => offer.invite.from_address() == address,
        None => given.len() >= FEWEST_ID_CHARS && offer.invite.id().starts_with(given),
    };
    if by_address.is_none() && offers.iter().filter(fits).count() > 1 {
        return Err(ApiError::BadRequest(
            "more than one invite starts like that",
        ));
    }
    let seq = offers
        .iter()
        .filter(fits)
        .max_by_key(|offer| offer.invite.issued_at())
        .map(|offer| offer.seq)
        .ok_or(ApiError::NotFound)?;
    let (chosen, rest): (Vec<Offered>, Vec<Offered>) =
        offers.into_iter().partition(|offer| offer.seq == seq);
    let chosen = chosen.into_iter().next().ok_or(ApiError::NotFound)?;
    let from_them = rest
        .into_iter()
        .filter(|offer| offer.invite.from() == chosen.invite.from())
        .collect();
    Ok((chosen, from_them))
}

/// Answers an invite and every other from the same agent, as answered for good, so none outlives the
/// answer. Only invites signed by that agent's key are its, so a stranger's invite can't
/// clear theirs, or theirs a stranger's.
async fn answer_all(
    signet: &Signet,
    me: &SplintId,
    offer: &Offered,
    from_them: &[Offered],
) -> Result<(), ApiError> {
    let mut done = Vec::with_capacity(from_them.len().saturating_add(1));
    for one in std::iter::once(offer).chain(from_them) {
        signet.invites.note_answered(&one.invite)?;
        done.push(one.done.clone());
    }
    signet
        .host
        .introductions_done(&signet.key, me, &done)
        .await?;
    Ok(())
}

#[derive(Serialize)]
struct Accepted {
    contact: String,
    /// Whether this agent's owner still has to sign them in. A stand-in's side does it by itself.
    waiting_for_owner: bool,
    /// The same mark as in its contacts: whether a value with them goes as the owner's settings say.
    approved_by_owner: bool,
    #[serde(flatten)]
    same_owner: SameOwner,
}

/// Accepts, as the agent would, the newest invite from each agent whose owner, worked out from the
/// two owners' signed bindings and never a host's word, is this agent's own, and gives back the rest.
/// The same owner's bindings stand behind both, so the agent isn't woken to decide (Nenye, 2026-11-14).
/// What follows is as for any acceptance, so where the owner's rules don't let the agent add contacts
/// by itself the pair still waits for the owner's yes, pending Nenye's call. Nothing while the rules have this agent stopped, and never for a
/// stand-in on either side, as [`SameOwner`] says.
async fn accept_the_same_owners(
    signet: &Signet,
    mut offers: Vec<Offered>,
) -> Result<Vec<Offered>, ApiError> {
    if offers.is_empty() || signet.rules.stopped().await {
        return Ok(offers);
    }
    offers.sort_by_key(|offer| std::cmp::Reverse(offer.invite.issued_at()));
    let mut answered = HashSet::new();
    let mut left = Vec::new();
    let mut offers = offers.into_iter();
    while let Some(offer) = offers.next() {
        let from = offer.invite.from().clone();
        if answered.contains(&from) {
            continue;
        }
        let owner = inviter_owner(signet, &offer).await;
        if !SameOwner::of(signet, owner.as_ref()).same_owner {
            left.push(offer);
            continue;
        }
        let (from_them, rest): (Vec<Offered>, Vec<Offered>) =
            offers.partition(|other| other.invite.from() == &from);
        let from_them = left
            .extract_if(.., |other: &mut Offered| other.invite.from() == &from)
            .chain(from_them)
            .collect::<Vec<_>>();
        // One that fails is left for the agent, as any other invite is, and tried again next time,
        // so it can't keep every other new invite from waking the agent until it expires.
        match accept_offer(signet, &offer, &from_them).await {
            Ok(_) => {
                tracing::info!(agent = %from, "accepted an invite from another agent of this same owner");
            }
            Err(_) => {
                tracing::warn!(agent = %from, "couldn't accept an invite from another agent of this same owner, so it's left for the agent");
                left.push(offer);
                left.extend(from_them);
            }
        }
        answered.insert(from);
        offers = rest.into_iter();
    }
    Ok(left)
}

async fn accept(
    State(signet): State<Arc<Signet>>,
    Path(id): Path<String>,
) -> Result<Json<Accepted>, ApiError> {
    let (offer, from_them) = named(&signet, &id).await?;
    Ok(Json(accept_offer(&signet, &offer, &from_them).await?))
}

/// Signs and sends an acceptance of `offer`, answering every other invite `from_them` too.
async fn accept_offer(
    signet: &Signet,
    offer: &Offered,
    from_them: &[Offered],
) -> Result<Accepted, ApiError> {
    let who = signet.who();
    let now = unix_now();
    let compact = sign_acceptance(&signet.key, &who.identity, &offer.invite, now)?;
    let (_, domain) = parse_address(offer.invite.from_address())
        .map_err(|_| ApiError::BadRequest("an address is name~domain"))?;
    let lifetime = offer.invite.expires_at().saturating_sub(now).max(1);
    let envelope = sign_envelope(
        &signet.key,
        &who.identity,
        offer.invite.from(),
        acceptance_body(&compact)?,
        now,
        lifetime,
    )?;
    signet.host.send(&envelope.compact, domain).await?;
    let address = offer.invite.from_address().to_owned();
    signet
        .contacts
        .pin_found(&address, offer.found.clone())
        .await?;
    let record = PendingContact {
        invite: offer.invite.compact().to_owned(),
        acceptance: compact,
        inviter_identity: offer.found.agent.encoded(),
        invitee_identity: who.identity.encoded(),
        inviter_owner_identity: offer.found.owner.encoded(),
        inviter_binding: offer.found.binding.clone(),
        invitee_owner_identity: who.owner.encoded(),
        invitee_binding: who.binding.clone(),
    };
    let agreed = signet.rules.agree(record.clone(), now).await?;
    if !agreed {
        signet.invites.add_pending(Pending {
            record,
            agent: offer.invite.from().clone(),
            address: address.clone(),
            at: now,
        })?;
    }
    answer_all(signet, who.identity.id(), offer, from_them).await?;
    tracing::info!(message_id = %envelope.id, "accepted an invite");
    signet.activity.note(Kind::Owner);
    let types = match signet.rules.contact_of(offer.invite.from()).await {
        Some(contact) if agreed => contact.types,
        _ => Vec::new(),
    };
    let owner = inviter_owner(signet, offer).await;
    let approved_by_owner = signet
        .rules
        .approves(
            offer.invite.from(),
            owner.as_ref().map(Identity::id),
            &types,
        )
        .await;
    Ok(Accepted {
        contact: address,
        waiting_for_owner: !agreed && !who.owner.is_unconfirmed_owner(),
        approved_by_owner,
        same_owner: SameOwner::of(signet, owner.as_ref()),
    })
}

/// Clears an invite, and any other from the same agent, and tells its sender nothing.
async fn decline(
    State(signet): State<Arc<Signet>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (offer, from_them) = named(&signet, &id).await?;
    let me = signet.who().identity.id().clone();
    answer_all(&signet, &me, &offer, &from_them).await?;
    Ok(Json(serde_json::json!({ "declined": true })))
}

#[derive(Serialize)]
struct CardView {
    card: String,
    address: String,
}

/// This agent's card, for its person to hand on however they like.
async fn card(State(signet): State<Arc<Signet>>) -> Json<CardView> {
    let address = signet.address();
    let card = ContactCard {
        address: address.clone(),
        agent: signet.who().identity.id().clone(),
    };
    Json(CardView {
        card: card.encode(),
        address,
    })
}

//! The interactions this agent is part of, kept across restarts.
//!
//! A record holds signed steps and nothing derived from them: state is never saved, because it
//! would be one more thing to trust.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use splint_core::requests::{
    ApprovalDraft, Chain, Decision, HeldMove, InteractionKind, Operation, PauseReason,
    RequestState, Side, StepKind,
};
use splint_core::{Identity, MessageId, SignedEnvelope, SplintId, VerifiedBinding, unix_now};
use tokio::sync::{Mutex, MutexGuard};

use crate::Signet;
use crate::host_client::HostError;
use crate::requests::parties_of;
use crate::state_file::{self, StateError};

/// How many of a contact's finished interactions a new one can name as what it replaces, which is what
/// the sums in `docs/protocol.md` take it to be.
const SUPERSEDES_FROM: usize = 16;
/// What stands for an address in a readable record, as a guest has none.
pub const GUEST_ADDRESS: &str = "a guest";

/// An owner's answer this Signet couldn't use, as when what they said yes to had changed before it got
/// here, so they and their agent aren't left believing it took. It's fixed words from this
/// program and what the owner signed, with nothing from a counterparty in it. Nothing about the
/// request changes: what waits on them still waits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotUsed {
    /// The request it named, so a device that matches it to what's waiting needn't walk the steps.
    pub request: MessageId,
    pub operation: Operation,
    pub decision: Decision,
    /// The version it named.
    pub version: u32,
    /// `changed` where what waits on them now isn't what they signed, `not_now` where this Signet
    /// couldn't save or send it just then, and otherwise the refusal's own fixed word, such as
    /// `type_not_allowed` after the owner's rules changed.
    pub why: String,
    /// When this Signet heard it, by its own clock.
    pub at: u64,
}

/// A signed step waiting to reach this agent's host. It's saved before it's sent, so a crash or an
/// outage can't lose a step already counted in the chain, or lead to signing a second one in its
/// place, which the other side would report as the key misbehaving.
#[derive(Clone, Serialize, Deserialize)]
pub struct Outgoing {
    pub compact: String,
    pub message_id: MessageId,
    pub expires_at: u64,
    /// A `received` this side signs for the other's step, which is never this side's head, so
    /// handing it on isn't noted in `handed`, where it would push out the steps that are.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub receipt: bool,
}

/// Why a step this agent signed hasn't reached its host yet, as the last try found, so an agent isn't
/// left to tell its person it went. Each goes by itself once what holds it lifts, before it expires.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldBecause {
    /// Its host is at a limit on what this agent sends, for the hour or the day, or its queue is full.
    HostLimit,
    /// Its host refused it for another reason.
    HostRefused,
    /// Its host couldn't be reached.
    HostUnreachable,
    /// This computer's clock is too far from its host's for the host to take what it signs.
    ClockOff,
    /// The owner's rules let nothing go to the other side now.
    NotAContactNow,
}

impl HeldBecause {
    /// Fixed words on what it means and what lifts it, for the agent.
    pub fn words(self) -> &'static str {
        match self {
            Self::HostLimit => {
                "Signed, but your host is holding what you send at its limit for the hour or the \
                 day, or with its queue full, so it hasn't gone. It goes by itself once your host \
                 takes it: within the hour at the hourly limit, within a day at the daily one. Don't \
                 tell your person it went until requests shows its reach past queued."
            }
            Self::HostRefused => {
                "Signed, but your host refused it, so it hasn't gone. It's tried again until it \
                 expires, and may never go, so don't tell your person it went."
            }
            Self::HostUnreachable => {
                "Signed, but your host couldn't be reached, so it hasn't gone. It goes once your \
                 host can be reached."
            }
            Self::ClockOff => {
                "Signed, but this computer's clock is too far from your host's, so your host won't \
                 take it and it hasn't gone. It goes once the clock is set right; splint status \
                 says how far off it is."
            }
            Self::NotAContactNow => {
                "Signed, but your person's rules let nothing go to them now, so it waits here and \
                 goes only if your person adds them back."
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub role: Side,
    pub peer_address: String,
    pub peer_identity: String,
    pub peer_owner: String,
    /// The statement that they acted for that owner, for an outcome's bundle.
    pub peer_binding: String,
    /// In the order they were applied here, which a walk repeats.
    pub steps: Vec<String>,
    pub outbox: Vec<Outgoing>,
    /// The agent asked to cancel a completed request, which only its owner can do.
    pub cancel_wanted: bool,
    /// A move the agent asked for at `ask_me`, which nothing has signed. A later one replaces it.
    #[serde(default)]
    pub held: Option<HeldMove>,
    /// Whether `held` waits only for the other side's person to set up their controls, as it commits
    /// this owner to a value and nothing in their rules holds it, so it goes by itself once they have
    ///. The rules are asked again then.
    #[serde(default)]
    pub held_until_they_confirm: bool,
    /// Why `held`, which waited only for the other side's person, didn't go by itself once they'd set
    /// up their controls, as a refusal's fixed word, until the next move here. It's left to this owner.
    #[serde(default)]
    pub held_not_sent: Option<String>,
    /// What the owner last said no to, so the agent can find out, until its next move.
    #[serde(default)]
    pub owner_said_no: Option<StepKind>,
    /// The owner's last answer here that couldn't be used, until one of theirs is.
    #[serde(default)]
    pub owner_answer_not_used: Option<NotUsed>,
    /// When this Signet last took a step, by its own clock, so an owner's device gets recent work first
    /// whatever dates a counterparty puts on its steps.
    #[serde(default)]
    pub last_at: u64,
    /// The other side is someone answering a one-use link, with no owner and no address.
    #[serde(default)]
    pub guest: bool,
    /// The held open this started from, saved in the same write as the `open` it became, sealed as it
    /// went. A yes to that hold heard again, after a crash or from a second caller, finds this and
    /// resends those bytes, rather than sealing a second `open` with an ID of its own.
    #[serde(default)]
    pub from_hold: Option<MessageId>,
    /// The pause for information a note from the requester came after, as far as this Signet saw. A
    /// note is how the information goes, as no step carries it, so from then the recipient, who alone
    /// can resume, is the one to move. Kept by the pause's ID, so it ends with that pause.
    #[serde(default)]
    pub noted_after_pause: Option<MessageId>,
    /// Why what's in `outbox` is still here, from the last try to hand it on.
    #[serde(default)]
    pub held_because: Option<HeldBecause>,
    /// This side's steps its host took, newest last, written when it took them. A step leaves
    /// `outbox` unsent too, so being gone from there says nothing.
    #[serde(default)]
    pub handed: Vec<MessageId>,
    /// This side's steps dropped from `outbox` before any host took them, as they ran out or were
    /// signed with a key since replaced. Newest last.
    #[serde(default)]
    pub never_sent: Vec<MessageId>,
    /// False for a record saved before `handed` was written down, whose steps went with nothing noted.
    /// Only those go by what's left in `outbox`, as they always did.
    #[serde(default)]
    pub handed_noted: bool,
}

/// How many of a record's own steps it remembers handing on or dropping, which is more than its head
/// and the receipts after it.
const STEPS_REMEMBERED: usize = 16;

/// Notes `id` at the end of `list`, keeping only the newest few.
fn remember(list: &mut Vec<MessageId>, id: MessageId) {
    list.retain(|kept| kept != &id);
    list.push(id);
    let over = list.len().saturating_sub(STEPS_REMEMBERED);
    list.drain(..over);
}

impl Record {
    pub fn new(
        role: Side,
        peer_address: String,
        peer_identity: String,
        peer_owner: String,
        peer_binding: String,
    ) -> Self {
        Self {
            role,
            peer_address,
            peer_identity,
            peer_owner,
            peer_binding,
            steps: Vec::new(),
            outbox: Vec::new(),
            cancel_wanted: false,
            held: None,
            held_until_they_confirm: false,
            held_not_sent: None,
            owner_said_no: None,
            owner_answer_not_used: None,
            last_at: unix_now(),
            guest: false,
            from_hold: None,
            noted_after_pause: None,
            held_because: None,
            handed: Vec::new(),
            never_sent: Vec::new(),
            handed_noted: true,
        }
    }

    /// A link this agent's owner made. A guest has nothing but a key.
    pub fn for_guest(guest: &Identity) -> Self {
        let mut record = Self::new(
            Side::Requester,
            GUEST_ADDRESS.to_owned(),
            guest.encoded(),
            guest.encoded(),
            String::new(),
        );
        record.guest = true;
        record
    }

    /// Who the other side is, by the identity saved when this started.
    pub fn peer_agent(&self) -> Result<Identity, splint_core::Error> {
        if self.guest {
            Identity::guest_from_encoded(&self.peer_identity)
        } else {
            Identity::from_encoded(&self.peer_identity)
        }
    }

    /// Who the other agent acted for when this started, as its parties have it: a guest stands for
    /// itself.
    pub fn peer_owner_id(&self) -> Result<SplintId, splint_core::Error> {
        if self.guest {
            return Ok(self.peer_agent()?.id().clone());
        }
        Ok(Identity::from_encoded(&self.peer_owner)?.id().clone())
    }

    /// What the owner is being asked about this record's held move, if the chain would still take it.
    pub fn held_draft(&self, chain: &Chain, now: u64) -> Option<ApprovalDraft> {
        let held = self.held.as_ref()?;
        chain.held_draft(self.role, held, now).ok()
    }

    pub fn chain(&self, signet: &Signet) -> Result<Chain, HostError> {
        // Everything saved here passed a walk when it was added, so a walk can only fail now if the
        // state file changed under us.
        let parties = parties_of(signet, self)?;
        let types = &signet.requests.types;
        // A one-use link's offer is one its owner signed for exactly, of a type agreed with anyone.
        let schemas = if self.guest {
            types.schemas_with_anyone()
        } else {
            // By who they acted for when it started, so a request made under an earlier owner is
            // still read by what was agreed then.
            let theirs = match self.role {
                Side::Requester => &parties.recipient,
                Side::Recipient => &parties.requester,
            };
            types.schemas_with(theirs.agent.id(), theirs.owner.id())
        };
        Chain::walk(parties, schemas, &self.steps).map_err(|_| HostError::LocalStorage)
    }

    /// Adds a step this agent just signed to the chain, with a sealed body's opening so it can be read
    /// back, and queues what goes over the wire.
    pub fn add_own(&mut self, signed: &SignedEnvelope) {
        self.steps.push(signed.kept.clone());
        self.last_at = unix_now();
        self.queue(signed, false);
    }

    /// Queues the `received` this side signed for the other's step.
    pub fn queue_receipt(&mut self, signed: &SignedEnvelope) {
        self.queue(signed, true);
    }

    fn queue(&mut self, signed: &SignedEnvelope, receipt: bool) {
        self.outbox.push(Outgoing {
            compact: signed.compact.clone(),
            message_id: signed.id.clone(),
            expires_at: signed.expires_at,
            receipt,
        });
    }

    /// A host would refuse these, so there's no use in retrying them. Says whether any went.
    pub fn drop_expired_outgoing(&mut self) -> bool {
        let now = unix_now();
        let (live, expired) = std::mem::take(&mut self.outbox)
            .into_iter()
            .partition(|outgoing| outgoing.expires_at > now);
        self.outbox = live;
        self.dropped_unsent(expired)
    }

    /// Takes every step out of `outbox`, unsent. Says whether there were any.
    pub fn drop_all_outgoing(&mut self) -> bool {
        let all = std::mem::take(&mut self.outbox);
        self.dropped_unsent(all)
    }

    fn dropped_unsent(&mut self, dropped: Vec<Outgoing>) -> bool {
        let any = !dropped.is_empty();
        for outgoing in dropped.into_iter().filter(|out| !out.receipt) {
            remember(&mut self.never_sent, outgoing.message_id);
        }
        any
    }

    /// Notes that its host took this step, which is the only way `delivery.handed_to_host` is said.
    pub fn handed_to_host(&mut self, message_id: &MessageId) {
        let step = self
            .outbox
            .iter()
            .any(|out| out.message_id == *message_id && !out.receipt);
        self.outbox.retain(|out| out.message_id != *message_id);
        if step {
            remember(&mut self.handed, message_id.clone());
        }
    }
}

/// Notes that a note passed between this agent and `peer`, dated `sent_at`, on each request with them
/// paused for information whose requester wrote it: `by_this_agent` for one this agent sent. Only one
/// dated after the pause counts, so a note crossing it doesn't read as the answer. It only ever moves
/// whose turn a request reads as: no state or move depends on it.
pub async fn note_after_pause(
    signet: &Signet,
    peer: &SplintId,
    by_this_agent: bool,
    sent_at: u64,
) -> Result<(), HostError> {
    let writer = if by_this_agent {
        Side::Requester
    } else {
        Side::Recipient
    };
    let now = unix_now();
    let mut records = signet.requests.store.lock().await;
    let mut changed = false;
    for record in records.values_mut() {
        let with_peer = record.peer_agent().is_ok_and(|agent| agent.id() == peer);
        if record.guest || record.role != writer || !with_peer {
            continue;
        }
        let Ok(chain) = record.chain(signet) else {
            continue;
        };
        let paused_for_information = chain.state_at(now) == RequestState::Paused
            && chain.pause_reason() == Some(PauseReason::NeedsInformation)
            && sent_at >= chain.head_signed_at();
        if paused_for_information && record.noted_after_pause.as_ref() != chain.head() {
            record.noted_after_pause = chain.head().cloned();
            changed = true;
        }
    }
    if changed {
        signet.requests.store.save(&records)?;
    }
    Ok(())
}

/// Whether a request with `peer` has completed before, as far as this Signet keeps, for the facts an
/// agent reads beside what they send. Their records are few, as a contact's open requests and day are
/// limited, so each is walked.
pub async fn completed_with(signet: &Signet, peer: &SplintId) -> bool {
    let now = unix_now();
    let records = signet.requests.store.lock().await;
    records
        .values()
        .filter(|record| Identity::claimed_id(&record.peer_identity).is_ok_and(|id| &id == peer))
        .any(|record| {
            record
                .chain(signet)
                .is_ok_and(|chain| chain.state_at(now) == RequestState::Completed)
        })
}

/// The request a held open became, if it was ever sent.
pub fn started_from<'a>(
    records: &'a HashMap<String, Record>,
    hold: &MessageId,
) -> Option<(&'a String, &'a Record)> {
    records
        .iter()
        .find(|(_, record)| record.from_hold.as_ref() == Some(hold))
}

/// Whether `supersedes` names one of the latest completed requests, or conversations that grew into
/// this, with this contact. It's a free 256 bits otherwise, and a choice from a long list otherwise, so
/// this applies to what an agent sends and to what a counterparty's does.
pub fn may_supersede(
    signet: &Signet,
    records: &HashMap<String, Record>,
    peer_identity: &str,
    supersedes: &MessageId,
) -> bool {
    let now = unix_now();
    let mut finished: Vec<(u64, &str)> = records
        .iter()
        .filter(|(_, record)| record.peer_identity == peer_identity)
        .filter_map(|(id, record)| {
            let chain = record.chain(signet).ok()?;
            let conversation = chain
                .interaction_schema()
                .is_some_and(|schema| schema.kind() == InteractionKind::Conversation);
            let done = conversation || chain.state_at(now) == RequestState::Completed;
            done.then(|| (chain.head_signed_at(), id.as_str()))
        })
        .collect();
    finished.sort_unstable_by(|one, other| other.cmp(one));
    finished
        .iter()
        .take(SUPERSEDES_FROM)
        .any(|(_, id)| *id == supersedes.as_str())
}

pub struct Store {
    path: PathBuf,
    records: Mutex<HashMap<String, Record>>,
}

impl Store {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let records = Mutex::new(state_file::load(&path)?);
        Ok(Self { path, records })
    }

    /// Holding this keeps every check-then-sign one step at a time, so Signet can never sign two
    /// steps on one `prev`.
    pub async fn lock(&self) -> MutexGuard<'_, HashMap<String, Record>> {
        self.records.lock().await
    }

    /// For when this agent's key is replaced: steps signed with the old one can't go anywhere now.
    pub async fn drop_outgoing(&self) -> Result<(), HostError> {
        let mut records = self.lock().await;
        for record in records.values_mut() {
            record.drop_all_outgoing();
        }
        self.save(&records)
    }

    /// For when this agent gets a new owner, who doesn't get what it did for the last one.
    pub async fn forget_everything(&self) -> Result<(), HostError> {
        let mut records = self.lock().await;
        records.clear();
        self.save(&records)
    }

    /// Saves one record as a chain now stands, and takes what a `type/1` in it agreed or no longer does.
    pub fn commit_chain(
        &self,
        signet: &Signet,
        records: &mut HashMap<String, Record>,
        request: &str,
        record: Record,
        chain: &Chain,
    ) -> Result<(), HostError> {
        let peer = record.peer_agent().ok().map(|peer| peer.id().clone());
        let owner = record.peer_owner_id().ok();
        self.commit(records, request, record)?;
        if let (Some(peer), Some(owner), Some(id)) = (peer, owner, chain.request()) {
            signet.requests.types.note(&peer, &owner, id, chain);
        }
        Ok(())
    }

    /// An agent this one deals with, whose owner hadn't confirmed, now acts for one who has, which its
    /// stand-in's signed release says. What's under way with it carries on under that owner, so their
    /// yes counts where the stand-in's never would. Nothing else moves an interaction to a new owner.
    /// Says whether any moved.
    pub async fn take_confirmation(
        &self,
        agent: &Identity,
        owner: &Identity,
        binding: &str,
    ) -> Result<bool, HostError> {
        if owner.is_unconfirmed_owner() {
            return Ok(false);
        }
        let encoded_owner = owner.encoded();
        let mut records = self.lock().await;
        // Every message comes through here, so what's cheap goes first, and the binding is checked
        // only once a record is found that it could move.
        let mut confirmed = None;
        let mut changed = false;
        for record in records.values_mut() {
            if record.guest || record.peer_owner == encoded_owner {
                continue;
            }
            let held_unconfirmed = Identity::from_encoded(&record.peer_owner)
                .ok()
                .filter(Identity::is_unconfirmed_owner);
            let Some(held) = held_unconfirmed else {
                continue;
            };
            let same_agent = Identity::from_encoded(&record.peer_identity)
                .is_ok_and(|peer| peer.id() == agent.id());
            if !same_agent {
                continue;
            }
            if confirmed.is_none() {
                match VerifiedBinding::verify(binding, owner, agent) {
                    Ok(verified) => confirmed = Some(verified),
                    Err(_) => return Ok(false),
                }
            }
            let Some(confirmed) = confirmed.as_ref() else {
                continue;
            };
            if confirmed.may_replace(&held, 0).is_err() {
                continue;
            }
            encoded_owner.clone_into(&mut record.peer_owner);
            confirmed.compact().clone_into(&mut record.peer_binding);
            confirmed.address().clone_into(&mut record.peer_address);
            changed = true;
        }
        if changed {
            self.save(&records)?;
        }
        Ok(changed)
    }

    pub fn save(&self, records: &HashMap<String, Record>) -> Result<(), HostError> {
        state_file::save(&self.path, records).map_err(|_| HostError::LocalStorage)
    }

    /// Takes in a changed record only if it reaches the disk. A step that couldn't be saved must
    /// count for nothing: if it stayed in memory it would be sent, and after a restart Signet would
    /// sign another on the same `prev`, which the other side rightly reports as a misbehaving key.
    pub fn commit(
        &self,
        records: &mut HashMap<String, Record>,
        request: &str,
        record: Record,
    ) -> Result<(), HostError> {
        let before = records.insert(request.to_owned(), record);
        let saved = self.save(records);
        if saved.is_err() {
            match before {
                Some(before) => records.insert(request.to_owned(), before),
                None => records.remove(request),
            };
        }
        saved
    }
}

//! What's waiting for the owner, worked out on the owner's own device. Signet hands over signed steps,
//! and this walks and checks them itself against keys the IDs commit to. So a Signet can hold something
//! back, but can't change what the owner is shown or asked to sign.

use splint_core::requests::Schema;
use splint_core::requests::{
    ApprovalDraft, Chain, Decision, HeldMove, Offer, Operation, Parties, Party, Refused,
    RequestState, Schemas, Side, StepKind,
};
use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;
use splint_core::{Identity, MessageId, Sealing, SplintId, VerifiedBinding};

use crate::failure::Failure;

/// What Signet hands over, which is only a claim until it's walked.
#[derive(Deserialize)]
pub struct SignedRequests {
    identity: String,
    requests: Vec<SignedRequest>,
    #[serde(default)]
    held_opens: Vec<SignedOpen>,
    /// What a Signet says it left out to fit, which is only its word.
    #[serde(default)]
    left_out: usize,
    /// What a Signet says each contact chose, sealed or unsealed, which is only its word, and decides
    /// nothing here: it's how the page says why a contact is sealed.
    #[serde(default)]
    pub their_sealing: BTreeMap<String, Sealing>,
}

impl SignedRequests {
    /// For an agent elsewhere that hasn't said anything yet.
    pub fn none_yet(identity: &str) -> Self {
        Self {
            identity: identity.to_owned(),
            requests: Vec::new(),
            held_opens: Vec::new(),
            left_out: 0,
            their_sealing: BTreeMap::new(),
        }
    }
}

#[derive(Deserialize)]
struct SignedRequest {
    #[serde(default)]
    guest: bool,
    role: Side,
    peer_identity: String,
    peer_owner: String,
    peer_binding: String,
    steps: Vec<String>,
    cancel_wanted: bool,
    #[serde(default)]
    held: Option<HeldMove>,
    #[serde(default)]
    not_used: Option<NotUsed>,
}

/// What a Signet says of the owner's last answer on a request that it couldn't use. It's
/// only its word, and decides nothing here: what to sign is worked out from the steps all the same.
#[derive(Clone, Deserialize)]
pub struct NotUsed {
    /// The step it answered, which says which of the drafts waiting here it's about.
    operation: Operation,
    decision: Decision,
    why: String,
}

impl NotUsed {
    /// Fixed words, as a lying Signet could write anything in `why`: one that isn't a short plain word
    /// is left out.
    fn words(&self) -> String {
        let answer = match self.decision {
            Decision::Approve => "yes",
            Decision::Deny => "no",
        };
        let plain = (1..=40).contains(&self.why.len())
            && self
                .why
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
        match self.why.as_str() {
            "changed" => format!(
                "Your last {answer} to this wasn't used: what you were shown had changed before it \
                 reached your agent's Signet, so nothing went. This is what's waiting now."
            ),
            "not_now" => format!(
                "Your last {answer} to this wasn't used: your agent's Signet couldn't take it just \
                 then, so nothing went. It's still waiting, and you can answer again."
            ),
            why if plain => format!(
                "Your last {answer} to this wasn't used: your agent's Signet refused it ({why}), so \
                 nothing went. It's still waiting."
            ),
            _ => format!(
                "Your last {answer} to this wasn't used: your agent's Signet refused it, so nothing \
                 went. It's still waiting."
            ),
        }
    }
}

/// An interaction the agent asked to start, and who it says that's for.
#[derive(Deserialize)]
struct SignedOpen {
    peer_identity: String,
    peer_owner: String,
    peer_binding: String,
    offer: Offer,
    nonce: String,
}

/// One interaction, after everything in it checked out here.
pub struct Walked {
    /// The other side is someone answering a one-use link.
    pub guest: bool,
    pub chain: Chain,
    pub request: MessageId,
    pub role: Side,
    pub them: SplintId,
    pub their_owner: SplintId,
    /// The address their owner signed for them.
    pub their_address: String,
    cancel_wanted: bool,
    held: Option<HeldMove>,
    not_used: Option<NotUsed>,
}

/// An interaction the agent asked to start, once who it's for has checked out here.
pub struct WalkedOpen {
    chain: Chain,
    offer: Offer,
    nonce: String,
    pub them: SplintId,
    pub their_owner: SplintId,
    pub their_address: String,
}

impl WalkedOpen {
    /// What this owner is being asked to sign. It's gone once the offer can't be sent any more.
    pub fn draft(&self, now: u64) -> Option<ApprovalDraft> {
        self.chain.open_draft(&self.offer, &self.nonce, now).ok()
    }

    pub fn schema(&self, schemas: &Schemas) -> Option<std::sync::Arc<Schema>> {
        schemas.get(&self.offer.interaction).cloned()
    }
}

pub struct WalkedAll {
    /// The types these were walked with: those the Signet said it agreed, and those this device read from
    /// the `type/1`s it walked, each by its own fingerprint.
    pub schemas: Schemas,
    pub walked: Vec<Walked>,
    pub starting: Vec<WalkedOpen>,
    /// What didn't check out, which is a Signet lying or its files changing under it.
    pub unreadable: usize,
    /// What didn't fit in what a Signet handed over.
    pub left_out: usize,
    pub their_sealing: BTreeMap<String, Sealing>,
}

impl Walked {
    /// Everything this owner is being asked to sign on this request, each with its own exact terms: their
    /// own `confirm`, a cancel their agent wants, and a move their agent holds for them can all wait at
    /// once. Showing only the first hid the agent's move, and a yes to the confirm then dropped it.
    pub fn drafts(&self, now: u64) -> Vec<ApprovalDraft> {
        let confirm = if self.chain.state_at(now) == RequestState::Expired {
            None
        } else {
            self.chain.confirm_draft(self.role, now)
        };
        let cancel = self
            .cancel_wanted
            .then(|| self.chain.cancel_draft(self.role, now))
            .flatten();
        let held = self
            .held
            .as_ref()
            .and_then(|held| self.chain.held_draft(self.role, held, now).ok());
        confirm.into_iter().chain(cancel).chain(held).collect()
    }

    /// A move the agent asked for that would commit this owner to a value, which waits until the other
    /// side's person sets up their controls before anyone is asked to sign it.
    pub fn held_for_their_controls(&self, now: u64) -> Option<StepKind> {
        let held = self.held.as_ref()?;
        matches!(
            self.chain.held_draft(self.role, held, now),
            Err(Refused::TheirOwnerUnconfirmed)
        )
        .then(|| held.kind())
    }

    /// Where its Signet says the owner's last answer here wasn't used, the words and the step of the draft
    /// they go beside: the one that answer was for, as a note about a held move on the confirm beside it
    /// told the owner the wrong terms had changed. Only where no draft for that step still waits does it
    /// go beside the first.
    pub fn not_used_beside(&self, now: u64) -> Option<(Operation, String)> {
        let said = self.not_used.as_ref()?;
        let drafts = self.drafts(now);
        let beside = drafts
            .iter()
            .find(|draft| draft.operation == said.operation)
            .or_else(|| drafts.first())?;
        Some((beside.operation, said.words()))
    }
}

/// Who a Signet says the other side is, checked against the keys their IDs commit to.
fn party_of(identity: &str, owner: &str, binding: &str) -> Option<(Party, Identity, String)> {
    let their_agent = Identity::from_encoded(identity).ok()?;
    let their_owner = Identity::from_encoded(owner).ok()?;
    // Without this, a Signet could name any owner as theirs and show that owner's yes as theirs too.
    let verified = VerifiedBinding::verify_history(binding, &their_owner, &their_agent).ok()?;
    let address = verified.address().to_owned();
    let party = Party {
        agent: their_agent,
        owner: their_owner.clone(),
        binding: binding.to_owned(),
    };
    Some((party, their_owner, address))
}

fn walk_open(signed: &SignedOpen, mine: &Party, schemas: &Schemas) -> Option<WalkedOpen> {
    let (theirs, their_owner, their_address) = party_of(
        &signed.peer_identity,
        &signed.peer_owner,
        &signed.peer_binding,
    )?;
    let them = theirs.agent.id().clone();
    let parties = Parties {
        requester: mine.clone(),
        recipient: theirs,
    };
    Some(WalkedOpen {
        chain: Chain::new(parties, schemas.clone()),
        offer: signed.offer.clone(),
        nonce: signed.nonce.clone(),
        them,
        their_owner: their_owner.id().clone(),
        their_address,
    })
}

fn walk_one(signed: &SignedRequest, mine: &Party, schemas: &Schemas) -> Option<Walked> {
    let (theirs, their_owner, their_address) = if signed.guest {
        // A guest has only a key, which is what the owner signed for: the walk compares the two.
        let guest = Identity::guest_from_encoded(&signed.peer_identity).ok()?;
        (Party::guest(guest.clone()), guest, "A guest".to_owned())
    } else {
        party_of(
            &signed.peer_identity,
            &signed.peer_owner,
            &signed.peer_binding,
        )?
    };
    let them = theirs.agent.id().clone();
    let parties = match signed.role {
        Side::Requester => Parties {
            requester: mine.clone(),
            recipient: theirs,
        },
        Side::Recipient => Parties {
            requester: theirs,
            recipient: mine.clone(),
        },
    };
    let chain = Chain::walk(parties, schemas.clone(), &signed.steps).ok()?;
    Some(Walked {
        guest: signed.guest,
        request: chain.request()?.clone(),
        chain,
        role: signed.role,
        them,
        their_owner: their_owner.id().clone(),
        their_address,
        cancel_wanted: signed.cancel_wanted,
        held: signed.held.clone(),
        not_used: signed.not_used.clone(),
    })
}

/// A Signet that answers for some other agent is refused outright, as nothing it says then applies.
pub fn walk_all(
    signed: &SignedRequests,
    agent: &SplintId,
    owner: &Identity,
    schemas: &Schemas,
) -> Result<WalkedAll, Failure> {
    let identity = Identity::from_encoded(&signed.identity)
        .ok()
        .filter(|identity| identity.id() == agent)
        .ok_or_else(|| Failure::refused("this Signet isn't the agent this page is for"))?;
    let mine = Party {
        agent: identity,
        owner: owner.clone(),
        binding: String::new(),
    };
    // A `type/1` carries the type it proposes, so what was agreed is read from those first, and the
    // Signet's word on the rest only adds what this device has no `type/1` for.
    let mut every: BTreeMap<_, _> = schemas
        .all()
        .map(|schema| (schema.name().clone(), Arc::new(schema.clone())))
        .collect();
    for request in &signed.requests {
        if let Some(proposed) = walk_one(request, &mine, &Schemas::default())
            .and_then(|one| one.chain.proposed_schema().cloned())
        {
            every.insert(proposed.name().clone(), proposed);
        }
    }
    let schemas = &Schemas::of(every.into_values()).unwrap_or_default();
    let walked: Vec<Walked> = signed
        .requests
        .iter()
        .filter_map(|request| walk_one(request, &mine, schemas))
        .collect();
    let starting: Vec<WalkedOpen> = signed
        .held_opens
        .iter()
        .filter_map(|open| walk_open(open, &mine, schemas))
        .collect();
    let handed_over = signed
        .requests
        .len()
        .saturating_add(signed.held_opens.len());
    Ok(WalkedAll {
        schemas: schemas.clone(),
        unreadable: handed_over.saturating_sub(walked.len().saturating_add(starting.len())),
        walked,
        starting,
        left_out: signed.left_out,
        their_sealing: signed.their_sealing.clone(),
    })
}

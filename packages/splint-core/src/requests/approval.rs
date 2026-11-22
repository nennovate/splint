//! An owner's signed yes or no, bound to exact terms. See `docs/protocol.md`.
//!
//! Checking is comparing: a reader rebuilds the terms from the chain as a typed value, and compares
//! them with what the owner signed. There's no canonical form to get wrong.

use serde::{Deserialize, Serialize};

use super::Refused;
use super::schema::{FieldValue, Fields, InteractionType, Schema, has_hidden_characters};
use super::step::StepKind;
use crate::delegation::{Delegated, PART_SEPARATOR, VerifiedDelegation, is_its_one_encoding};
use crate::{Error, Identity, MessageId, SigningKey, SplintId, jws};

const APPROVAL_TYPE: &str = "splint-approval";
const APPROVAL_VERSION: u8 = 1;
const MAX_SUBJECT_CHARS: usize = 120;
const MAX_NOTE_CHARS: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermsParty {
    pub agent: SplintId,
    pub owner: SplintId,
}

/// What both owners agree to, carried by value so a signing device can show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    /// Left out for core's plain conversation, as on its `open`.
    #[serde(
        rename = "type",
        default = "InteractionType::conversation",
        skip_serializing_if = "InteractionType::is_conversation"
    )]
    pub interaction: InteractionType,
    pub requester: TermsParty,
    pub recipient: TermsParty,
    /// The latest offer and what was picked from it, which the type's schema says the shape of.
    pub agreed: Fields,
    /// What was delivered, for a type that has a result.
    pub result: Fields,
    pub subject: Option<String>,
    pub note: Option<String>,
    pub supersedes: Option<MessageId>,
}

impl Terms {
    /// One hash of what an owner is asked to agree to, but for the subject and note they may set as
    /// they sign, so an ask can name the exact terms of the draft it was made for.
    pub fn digest(&self) -> Option<MessageId> {
        let mut agreed = self.clone();
        agreed.subject = None;
        agreed.note = None;
        serde_json::to_vec(&agreed)
            .ok()
            .map(|bytes| MessageId::of(&bytes))
    }

    /// Whether anything here holds words someone can't see all of. A subject or note can come from the
    /// other owner, and a lying Signet could put anything in any of this, so an owner is never asked to
    /// say yes to it and no reader takes that yes.
    pub fn hides_text(&self) -> bool {
        let in_fields = |fields: &Fields| {
            fields.iter().any(|(name, value)| {
                has_hidden_characters(name)
                    || matches!(value, FieldValue::Text(text) if has_hidden_characters(text))
            })
        };
        in_fields(&self.agreed)
            || in_fields(&self.result)
            || self.subject.as_deref().is_some_and(has_hidden_characters)
            || self.note.as_deref().is_some_and(has_hidden_characters)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Confirm,
    Cancel,
    /// A yes to a step the agent asked to send, at the owner's `ask_me`. Each names the one exact step.
    Open,
    Counter,
    Accept,
    Deliver,
    /// A yes to one one-use link: this offer, to this guest key, under this nonce.
    OfferToGuest,
}

impl Operation {
    /// The approval a step of this kind carries, if it's a kind that can carry one.
    pub(super) fn of(kind: StepKind) -> Option<Self> {
        match kind {
            StepKind::Confirm => Some(Self::Confirm),
            StepKind::Cancel => Some(Self::Cancel),
            StepKind::Open => Some(Self::Open),
            StepKind::Counter => Some(Self::Counter),
            StepKind::Accept => Some(Self::Accept),
            StepKind::Deliver => Some(Self::Deliver),
            _ => None,
        }
    }

    /// A yes to a step the agent asked to send, rather than to something already agreed.
    pub fn releases_a_step(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Counter | Self::Accept | Self::Deliver
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalPayload {
    pub(super) v: u8,
    pub(super) owner: SplintId,
    pub(super) agent: SplintId,
    pub(super) decision: Decision,
    pub(super) operation: Operation,
    pub(super) request: MessageId,
    pub(super) version: u32,
    pub(super) prev: MessageId,
    pub(super) terms: Terms,
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
}

/// An approval whose signature under one owner's key has been checked, or their delegate's yes checked
/// against the caps the owner signed for it. The only way to get one is to pass that check, so nothing
/// an agent makes up can stand in for an owner's decision.
#[derive(Clone, Debug)]
pub struct VerifiedApproval {
    compact: String,
    payload: ApprovalPayload,
    signed: MessageId,
    /// The owner's delegation, when their delegate signed this and not the owner.
    delegation: Option<VerifiedDelegation>,
}

/// How a reader holds a delegate's yes to the caps the owner gave it.
#[derive(Clone, Copy)]
pub(crate) enum CapsBy<'a> {
    /// By the type's schema, which says which fields are values and in what unit. Every reader of a
    /// chain or an outcome has it.
    Schema(&'a Schema),
    /// A sending host has no schema, so it checks everything else and leaves the values to the reader.
    NoSchemaAtHost,
}

impl VerifiedApproval {
    /// A decision arriving now, so it has to be signed by the key this owner holds now.
    /// An owner who hasn't confirmed is a key the agent's own machine holds, so nothing it signs is an
    /// owner's yes, here or read back.
    pub fn verify(compact: &str, owner: &Identity) -> Result<Self, Refused> {
        if owner.is_unconfirmed_owner() {
            return Err(Refused::OwnerUnconfirmed);
        }
        let bytes = owner
            .verify(compact, APPROVAL_TYPE)
            .map_err(|_| Refused::ApprovalBadSignature)?;
        Self::checked(compact, &bytes)
    }

    /// A decision in a chain or a bundle, which may date from before this owner's recovery.
    pub(super) fn verify_history(compact: &str, owner: &Identity) -> Result<Self, Refused> {
        if owner.is_unconfirmed_owner() {
            return Err(Refused::OwnerUnconfirmed);
        }
        let bytes = owner
            .verify_under_any_key(compact, APPROVAL_TYPE)
            .map_err(|_| Refused::ApprovalBadSignature)?;
        Self::checked(compact, &bytes)
    }

    /// An approval a step carries, arriving now: its owner's, or their delegate's within the caps they
    /// signed. Every reader of a step checks one this way, so a delegate's yes counts wherever an
    /// owner's does and nowhere it can't.
    pub fn verify_carried(
        compact: &str,
        owner: &Identity,
        agent: &Identity,
        schema: &Schema,
    ) -> Result<Self, Refused> {
        Self::on_step(compact, owner, agent, CapsBy::Schema(schema), false)
    }

    /// The same, for a step in a chain or a bundle being read back, which may date from before a
    /// recovery of the owner. Its delegation counts under any key the owner has had, as their own yes
    /// read back does.
    #[cfg(test)]
    pub(crate) fn read_back_carried(
        compact: &str,
        owner: &Identity,
        agent: &Identity,
        schema: &Schema,
    ) -> Result<Self, Refused> {
        Self::on_step(compact, owner, agent, CapsBy::Schema(schema), true)
    }

    /// The same, for a step being read back, which may date from before a recovery of the owner, or
    /// for a host, which has no schema.
    pub(crate) fn on_step(
        compact: &str,
        owner: &Identity,
        agent: &Identity,
        caps: CapsBy<'_>,
        history: bool,
    ) -> Result<Self, Refused> {
        // One key, one job: a yes arriving now whose owner's part, the yes itself or the delegation
        // behind a delegate's, the agent's own key signed is refused. Only whoever holds that key outside
        // Signet could have added it to the owner's ID, as an addition needs the added key's signature.
        // It turns on this one object, never on a copy of either ID, and what's read back stays as it
        // was signed.
        let owners_part = compact
            .split_once(PART_SEPARATOR)
            .map_or(compact, |(_, delegation)| delegation);
        if !history && agent.signed_now(owners_part) {
            return Err(Refused::ApprovalBadSignature);
        }
        let Some((approval, delegation)) = compact.split_once(PART_SEPARATOR) else {
            return if history {
                Self::verify_history(compact, owner)
            } else {
                Self::verify(compact, owner)
            };
        };
        if owner.is_unconfirmed_owner() {
            return Err(Refused::OwnerUnconfirmed);
        }
        let delegation =
            VerifiedDelegation::carried(delegation, owner, agent.id(), Some(agent), history)
                .map_err(|_| Refused::ApprovalBadSignature)?;
        if !delegation.may(Delegated::ApproveWithinCaps) {
            return Err(Refused::ApprovalBadSignature);
        }
        let bytes = delegation
            .signed(approval, APPROVAL_TYPE)
            .map_err(|_| Refused::ApprovalBadSignature)?;
        let mut verified = Self::checked(compact, &bytes)?;
        let payload = &verified.payload;
        if !is_its_one_encoding(payload, &bytes) {
            return Err(Refused::ApprovalMismatch);
        }
        // Only a yes to a confirm, by this owner for this agent, signed while the delegation held and
        // ending by when it does.
        let names_it = payload.decision == Decision::Approve
            && payload.operation == Operation::Confirm
            && &payload.owner == delegation.owner()
            && &payload.agent == delegation.agent()
            && delegation.covers(payload.issued_at, payload.expires_at);
        if !names_it {
            return Err(Refused::ApprovalMismatch);
        }
        let within = match caps {
            CapsBy::Schema(schema) => delegation.caps_fit(schema, &payload.terms),
            // The type the delegation caps still has to be this one, which needs no schema.
            CapsBy::NoSchemaAtHost => delegation
                .permissions()
                .caps
                .contains_key(&payload.terms.interaction),
        };
        if !within {
            return Err(Refused::OverLimit);
        }
        verified.delegation = Some(delegation);
        Ok(verified)
    }

    /// Whether the owner's delegate said this yes, within the limits the owner signed for it.
    pub fn by_delegate(&self) -> bool {
        self.delegation.is_some()
    }

    /// The name of the delegation a delegate's yes was said under, which the owner's rules have to name.
    pub fn delegation_name(&self) -> Option<String> {
        self.delegation.as_ref().map(VerifiedDelegation::name)
    }

    fn checked(compact: &str, bytes: &[u8]) -> Result<Self, Refused> {
        let payload: ApprovalPayload =
            serde_json::from_slice(bytes).map_err(|_| Refused::ApprovalMismatch)?;
        let subject_fits = fits(payload.terms.subject.as_deref(), MAX_SUBJECT_CHARS);
        let note_fits = fits(payload.terms.note.as_deref(), MAX_NOTE_CHARS);
        let hidden = payload.decision == Decision::Approve && payload.terms.hides_text();
        if payload.v != APPROVAL_VERSION || !subject_fits || !note_fits || hidden {
            return Err(Refused::ApprovalMismatch);
        }
        Ok(Self {
            compact: compact.to_owned(),
            payload,
            signed: MessageId::of(bytes),
            delegation: None,
        })
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn decision(&self) -> Decision {
        self.payload.decision
    }

    pub fn operation(&self) -> Operation {
        self.payload.operation
    }

    pub fn request(&self) -> &MessageId {
        &self.payload.request
    }

    pub fn version(&self) -> u32 {
        self.payload.version
    }

    pub fn prev(&self) -> &MessageId {
        &self.payload.prev
    }

    pub fn agent(&self) -> &SplintId {
        &self.payload.agent
    }

    pub fn terms(&self) -> &Terms {
        &self.payload.terms
    }

    pub fn issued_at(&self) -> u64 {
        self.payload.issued_at
    }

    pub fn has_expired(&self, now: u64) -> bool {
        now >= self.payload.expires_at
    }

    pub(super) fn payload(&self) -> &ApprovalPayload {
        &self.payload
    }

    /// The hash of the bytes the owner signed. It's the same for every copy of this one decision,
    /// however the signature over it or a step carrying it was made, so it's what tells copies apart
    /// from a second decision.
    pub(super) fn signed_hash(&self) -> &MessageId {
        &self.signed
    }
}

/// Short, with nothing in it that could hide what an owner signed from whoever reads it.
fn fits(text: Option<&str>, limit: usize) -> bool {
    text.is_none_or(|text| text.chars().count() <= limit && !has_hidden_characters(text))
}

/// What an owner is asked to sign. It's computed from the chain, so there's at most one per request
/// at a time, and a counter replaces it. Signing it is up to the owner's own device.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDraft {
    pub owner: SplintId,
    pub agent: SplintId,
    pub operation: Operation,
    pub request: MessageId,
    pub version: u32,
    pub prev: MessageId,
    pub terms: Terms,
    /// An approval to confirm can't outlast the request's deadline, though one to cancel a completed
    /// request can. Either way the step carrying it has to fit in one envelope.
    pub latest_expiry: u64,
}

impl ApprovalDraft {
    /// The owner's device signs a draft after showing it. A subject is for the requester's owner to
    /// set, so it's the one term this can change, and the recipient's owner signs it as it stands.
    pub fn sign(
        &self,
        key: &SigningKey,
        decision: Decision,
        subject: Option<String>,
        now: u64,
    ) -> Result<String, Error> {
        let mut terms = self.terms.clone();
        if subject.is_some() {
            terms.subject = subject;
        }
        let hidden = decision == Decision::Approve && terms.hides_text();
        let readable = fits(terms.subject.as_deref(), MAX_SUBJECT_CHARS)
            && fits(terms.note.as_deref(), MAX_NOTE_CHARS);
        if hidden || !readable {
            return Err(Error::Malformed);
        }
        let payload = serde_json::to_vec(&ApprovalPayload {
            v: APPROVAL_VERSION,
            owner: self.owner.clone(),
            agent: self.agent.clone(),
            decision,
            operation: self.operation,
            request: self.request.clone(),
            version: self.version,
            prev: self.prev.clone(),
            terms,
            issued_at: now,
            expires_at: self.latest_expiry,
        })
        .map_err(|_| Error::Malformed)?;
        jws::sign(key, APPROVAL_TYPE, &payload)
    }
}

#[cfg(test)]
pub(super) fn signed(key: &crate::SigningKey, payload: &ApprovalPayload) -> String {
    jws::sign(key, APPROVAL_TYPE, &serde_json::to_vec(payload).unwrap()).unwrap()
}

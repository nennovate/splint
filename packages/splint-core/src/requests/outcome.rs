//! A finished request's proof: a bundle, not a new signature. Each part is already signed, so
//! nobody has to be trusted to assemble it. See `docs/protocol.md`.

use serde::{Deserialize, Serialize};

use super::approval::{CapsBy, Decision, Operation, Terms, TermsParty, VerifiedApproval};
use super::schema::{Schema, Schemas, Signers};
use super::step::{Step, hold_of};
use crate::{Error, Identity, MessageId, VerifiedBinding, VerifiedEnvelope};

const OUTCOME_VERSION: u8 = 1;

/// Who stands behind a result. It follows from the type's schema, so a result only an agent's key
/// signed can't pose as one an owner did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    /// Both owners signed.
    Owner,
    /// The requester's owner signed.
    RequesterOwner,
    /// Only the recipient's agent key signed, which is all this type asks for.
    Agent,
    /// The requester's owner signed the offer, and a one-use link's key answered it. A link's key
    /// proves someone held the link, and says nothing about who they are.
    Link,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OutcomeResult {
    Completed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OutcomeApprovals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) requester: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) recipient: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OutcomeParty {
    pub(super) agent_identity: String,
    pub(super) owner_identity: String,
    /// What says this agent acted for this owner, since an ID doesn't.
    pub(super) binding: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OutcomeParties {
    pub(super) requester: OutcomeParty,
    pub(super) recipient: OutcomeParty,
}

/// Proves who agreed, as of signing. It can't show that the last step was delivered, that the
/// requester's owner hasn't since signed a later version, or that no later `cancel` exists: only the
/// chain shows those. The bundle leaves out lists a pick chose from, which show what was turned down.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub(super) v: u8,
    pub(super) request: MessageId,
    pub(super) result: OutcomeResult,
    pub(super) assurance: Assurance,
    pub(super) terms: Terms,
    pub(super) approvals: OutcomeApprovals,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) requester_confirm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) deliver: Option<String>,
    /// On a link, the `open` that carries the owner's yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) open: Option<String>,
    /// On a link, what the guest's key signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) guest_accept: Option<String>,
    pub(super) parties: OutcomeParties,
}

impl Outcome {
    pub fn assurance(&self) -> Assurance {
        self.assurance
    }

    /// Checks the bundle on its own, and returns the terms it proves. The caller still has to
    /// compare the owner IDs in those terms with the ones it has pinned.
    pub fn verify(&self, schemas: &Schemas) -> Result<&Terms, Error> {
        let requester = Identity::from_encoded(&self.parties.requester.agent_identity)?;
        let recipient = if self.assurance == Assurance::Link {
            Identity::guest_from_encoded(&self.parties.recipient.agent_identity)?
        } else {
            Identity::from_encoded(&self.parties.recipient.agent_identity)?
        };
        self.verify_for(&requester, &recipient, schemas)
    }

    pub(crate) fn verify_for(
        &self,
        requester: &Identity,
        recipient: &Identity,
        schemas: &Schemas,
    ) -> Result<&Terms, Error> {
        if self.v != OUTCOME_VERSION {
            return Err(Error::Malformed);
        }
        // A link's answer can't be presented as an owner's, nor the other way round.
        if recipient.is_guest() != (self.assurance == Assurance::Link) {
            return Err(Error::ProofMismatch);
        }
        if recipient.is_guest() {
            return self.verify_link(requester, recipient, schemas);
        }
        let requester_owner = Identity::from_encoded(&self.parties.requester.owner_identity)?;
        let recipient_owner = Identity::from_encoded(&self.parties.recipient.owner_identity)?;
        // Both of them signed that one acts for the other, so a bundle can't pair an agent with
        // someone else. It may date from before a transfer or a recovery of either.
        let acted_for = |party: &OutcomeParty, owner: &Identity, agent: &Identity| {
            VerifiedBinding::verify_history(&party.binding, owner, agent)
                .map(|_| ())
                .map_err(|_| Error::WrongSigner)
        };
        acted_for(&self.parties.requester, &requester_owner, requester)?;
        acted_for(&self.parties.recipient, &recipient_owner, recipient)?;
        let expected_party = |agent: &Identity, owner: &Identity| TermsParty {
            agent: agent.id().clone(),
            owner: owner.id().clone(),
        };
        if self.terms.requester != expected_party(requester, &requester_owner)
            || self.terms.recipient != expected_party(recipient, &recipient_owner)
        {
            return Err(Error::ProofMismatch);
        }
        let schema = schemas
            .get(&self.terms.interaction)
            .ok_or(Error::ProofMismatch)?;
        // The type says who must stand behind a result, so a bundle can't claim less or more.
        match (self.assurance, schema.sign()) {
            (Assurance::Owner, Signers::Both) => {
                let by_requester = self.requester_approval(&requester_owner, requester, schema)?;
                let compact = self.approvals.recipient.as_deref();
                let by_recipient = self.checked_approval(
                    compact.ok_or(Error::ProofMismatch)?,
                    &recipient_owner,
                    recipient,
                    schema,
                )?;
                let confirm = self.tied_confirm(&by_requester, requester, recipient)?;
                let tied = by_requester.version() == by_recipient.version()
                    && by_recipient.prev() == confirm.id();
                tied.then_some(()).ok_or(Error::ProofMismatch)?;
            }
            (Assurance::RequesterOwner, Signers::Requester) => {
                let by_requester = self.requester_approval(&requester_owner, requester, schema)?;
                self.tied_confirm(&by_requester, requester, recipient)?;
                if self.approvals.recipient.is_some() {
                    return Err(Error::ProofMismatch);
                }
            }
            (Assurance::Agent, Signers::None) => self.check_deliver(requester, recipient)?,
            _ => return Err(Error::ProofMismatch),
        }
        Ok(&self.terms)
    }

    /// Every piece is signed, and each has to name the others, so nobody has to be trusted to have
    /// put them together. The terms have to be the offer the owner signed plus the guest's pick.
    fn verify_link(
        &self,
        requester: &Identity,
        guest: &Identity,
        schemas: &Schemas,
    ) -> Result<&Terms, Error> {
        let owner = Identity::from_encoded(&self.parties.requester.owner_identity)?;
        VerifiedBinding::verify_history(&self.parties.requester.binding, &owner, requester)
            .map_err(|_| Error::WrongSigner)?;
        let piece = |piece: &Option<String>| piece.clone().ok_or(Error::ProofMismatch);
        let compact = piece(&self.approvals.requester)?;
        let approval =
            VerifiedApproval::verify_history(&compact, &owner).map_err(|_| Error::BadSignature)?;
        let payload = approval.payload();
        let opened = VerifiedEnvelope::verify_ignoring_clock(&piece(&self.open)?, requester)?;
        let accepted = VerifiedEnvelope::verify_ignoring_clock(&piece(&self.guest_accept)?, guest)?;
        let confirmed =
            VerifiedEnvelope::verify_ignoring_clock(&piece(&self.requester_confirm)?, requester)?;
        let (
            Ok(Step::Open {
                approval: on_open, ..
            }),
            Ok(Step::Accept {
                request: of_accept,
                prev: accept_prev,
                pick,
                ..
            }),
            Ok(Step::Confirm {
                request: of_confirm,
                prev: confirm_prev,
                approval: on_confirm,
            }),
        ) = (
            Step::parse(opened.body()),
            Step::parse(accepted.body()),
            Step::parse(confirmed.body()),
        )
        else {
            return Err(Error::ProofMismatch);
        };
        let offer = &payload.terms;
        let schema = schemas
            .get(&offer.interaction)
            .ok_or(Error::ProofMismatch)?;
        let in_the_offer = schema.check_picked_from(&pick, &offer.agreed).is_ok();
        let mut expected = offer.clone();
        expected.agreed = schema.agreed(&offer.agreed, &pick);
        expected.result.clear();
        let hold = hold_of(opened.nonce());
        let tied = payload.decision == Decision::Approve
            && payload.operation == Operation::OfferToGuest
            && payload.owner == *owner.id()
            && payload.agent == *requester.id()
            && payload.request == hold
            && offer.recipient.agent == *guest.id()
            && offer.recipient.owner == *guest.id()
            && offer.requester.agent == *requester.id()
            && offer.requester.owner == *owner.id()
            && *opened.id() == self.request
            && opened.recipient() == guest.id()
            && on_open.as_ref() == Some(&compact)
            && accepted.recipient() == requester.id()
            && of_accept == self.request
            && accept_prev == self.request
            && in_the_offer
            && confirmed.recipient() == guest.id()
            && of_confirm == self.request
            && on_confirm == compact
            && confirm_prev == *accepted.id()
            && self.terms == expected;
        tied.then_some(&self.terms).ok_or(Error::ProofMismatch)
    }

    fn requester_approval(
        &self,
        owner: &Identity,
        agent: &Identity,
        schema: &Schema,
    ) -> Result<VerifiedApproval, Error> {
        let compact = self.approvals.requester.as_deref();
        self.checked_approval(compact.ok_or(Error::ProofMismatch)?, owner, agent, schema)
    }

    /// The owner's yes, or their delegate's within the caps they signed for it, as a chain reads one.
    fn checked_approval(
        &self,
        compact: &str,
        owner: &Identity,
        agent: &Identity,
        schema: &Schema,
    ) -> Result<VerifiedApproval, Error> {
        let approval =
            VerifiedApproval::on_step(compact, owner, agent, CapsBy::Schema(schema), true)
                .map_err(|_| Error::BadSignature)?;
        let payload = approval.payload();
        let matches = payload.decision == Decision::Approve
            && payload.operation == Operation::Confirm
            && payload.owner == *owner.id()
            && payload.agent == *agent.id()
            && payload.request == self.request
            && payload.terms == self.terms;
        if matches {
            Ok(approval)
        } else {
            Err(Error::ProofMismatch)
        }
    }

    /// The step that carries the requester's owner's approval. Without this, a recipient's approval
    /// naming any `prev` or `version` would prove a result that no chain holds.
    fn tied_confirm(
        &self,
        by_requester: &VerifiedApproval,
        requester: &Identity,
        recipient: &Identity,
    ) -> Result<VerifiedEnvelope, Error> {
        let compact = self.requester_confirm.as_deref();
        let compact = compact.ok_or(Error::ProofMismatch)?;
        let confirm = VerifiedEnvelope::verify_ignoring_clock(compact, requester)?;
        let Ok(Step::Confirm {
            request,
            prev,
            approval,
        }) = Step::parse(confirm.body())
        else {
            return Err(Error::ProofMismatch);
        };
        let tied = request == self.request
            && Some(&approval) == self.approvals.requester.as_ref()
            && prev == *by_requester.prev()
            && confirm.recipient() == recipient.id();
        if tied {
            Ok(confirm)
        } else {
            Err(Error::ProofMismatch)
        }
    }

    /// The recipient's agent signed this result for this request, and that's all this proves. No
    /// owner stands behind it, which is what `Assurance::Agent` says.
    fn check_deliver(&self, requester: &Identity, recipient: &Identity) -> Result<(), Error> {
        let compact = self.deliver.as_deref().ok_or(Error::ProofMismatch)?;
        let holds_no_approval = self.approvals.requester.is_none()
            && self.approvals.recipient.is_none()
            && self.requester_confirm.is_none();
        let deliver = VerifiedEnvelope::verify_ignoring_clock(compact, recipient)?;
        let Ok(Step::Deliver {
            request, result, ..
        }) = Step::parse(deliver.body())
        else {
            return Err(Error::ProofMismatch);
        };
        let tied = holds_no_approval
            && request == self.request
            && result == self.terms.result
            && deliver.recipient() == requester.id();
        tied.then_some(()).ok_or(Error::ProofMismatch)
    }
}

//! What an owner signs to set up their controls for an agent that joined on its own: the binding, the
//! agent's backup vouching for them, their first rules, and the delegation those rules name. See
//! "Setting up your controls" in `docs/protocol.md`.
//!
//! The bytes are made here from what the owner chose, before anything signs, so an owner's file key
//! and a passkey in their browser sign exactly the same thing, and the browser's page can be tested
//! against the vectors this crate passes. A passkey signs the owner's three with one touch, as a
//! batch; a file key signs each. The backup always signs its vouch with ES256.

use crate::delegation::{DELEGATION_TYPE, DelegationDraft, MAX_DELEGATION_CHARS, name_of_input};
use crate::identity::commitment_to;
use crate::jws::{self, Alg};
use crate::passkey::{Challenge, PasskeyAssertion};
use crate::rules::{RULES_TYPE, RulesDraft};
use crate::{
    BINDING_PART_SEPARATOR, Error, Identity, JoinReply, PublicKey, SigningKey, VerifiedBinding,
};

/// What the owner chose for one agent, and what it's signed for.
pub struct ControlsDraft {
    /// The agent as it is now, with no controls yet, which moves its ID to `backup` on taking this.
    pub agent: Identity,
    /// What the binding names: the agent's address, keeping its handle and host.
    pub address: String,
    /// The agent's next backup, which the owner keeps, and which vouches for them.
    pub backup: PublicKey,
    pub rules: RulesDraft,
    /// A delegation to the agent's Signet's delegate key, which the rules then name.
    pub delegation: Option<DelegationDraft>,
    /// The same for all three, as one device signs them at once. The stand-in's release takes the one
    /// before.
    pub seq: u64,
    pub now: u64,
}

/// The signing inputs, made and not yet signed.
pub struct PreparedControls {
    owner_identity: String,
    commitment: String,
    binding: String,
    vouch: String,
    rules: String,
    delegation: Option<String>,
}

impl ControlsDraft {
    /// Each signing input, with the header the owner's identity signs with. Rules naming another
    /// delegation are replaced by those naming this one's, or none.
    pub fn prepare(self, owner: &Identity) -> Result<PreparedControls, Error> {
        let alg = if owner.passkey_rp().is_some() {
            Alg::Wa256
        } else {
            Alg::Es256
        };
        let agent_id = self.agent.id();
        let (binding, vouch) = VerifiedBinding::inputs_ahead(
            alg,
            &self.backup,
            owner.id(),
            &self.agent,
            &self.address,
            self.seq,
            self.now,
        )?;
        let delegation = self
            .delegation
            .map(|draft| {
                let payload = draft.payload(owner.id(), agent_id, self.seq, self.now)?;
                jws::signing_input(alg, DELEGATION_TYPE, &payload)
            })
            .transpose()?;
        let mut rules = self.rules;
        rules.delegation = delegation.as_deref().map(name_of_input);
        let rules = rules.payload(owner.id(), agent_id, self.seq, self.now)?;
        Ok(PreparedControls {
            owner_identity: owner.encoded(),
            commitment: commitment_to(&self.backup),
            binding,
            vouch,
            rules: jws::signing_input(alg, RULES_TYPE, &rules)?,
            delegation,
        })
    }
}

impl PreparedControls {
    /// What the owner's key signs, in this order: the binding, the rules, and the delegation if any.
    pub fn owner_inputs(&self) -> Vec<&str> {
        let mut inputs = vec![self.binding.as_str(), self.rules.as_str()];
        inputs.extend(self.delegation.as_deref());
        inputs
    }

    /// What the agent's backup signs, with ES256.
    pub fn vouch_input(&self) -> &str {
        &self.vouch
    }

    /// What the agent's ID moves to commit to: the backup the owner keeps.
    pub fn commitment(&self) -> &str {
        &self.commitment
    }

    /// What one touch of a passkey signs, for all of [`Self::owner_inputs`].
    pub fn challenge(&self) -> Result<Challenge, Error> {
        Challenge::for_inputs(&self.owner_inputs())
    }

    /// Signed by an owner's file key, and the agent's backup.
    pub fn signed_by_file_key(
        &self,
        key: &SigningKey,
        backup: &SigningKey,
    ) -> Result<JoinReply, Error> {
        let signed = self
            .owner_inputs()
            .into_iter()
            .map(|input| jws::sign_input(key, input))
            .collect::<Result<Vec<_>, _>>()?;
        self.joined(signed, &jws::sign_input(backup, &self.vouch)?)
    }

    /// Signed by one touch of an owner's passkey, and the agent's backup.
    pub fn signed_by_passkey(
        &self,
        assertion: &PasskeyAssertion,
        backup: &SigningKey,
    ) -> Result<JoinReply, Error> {
        let inputs = self.owner_inputs();
        let signed = self.challenge()?.signed(&inputs, assertion)?;
        self.joined(signed, &jws::sign_input(backup, &self.vouch)?)
    }

    /// The answer an agent takes up, the binding being the owner's half and the vouch joined. Whoever
    /// takes it checks every signature, so nothing is checked here but its size.
    fn joined(&self, signed: Vec<String>, vouch: &str) -> Result<JoinReply, Error> {
        let mut signed = signed.into_iter();
        let (Some(binding), Some(rules)) = (signed.next(), signed.next()) else {
            return Err(Error::Malformed);
        };
        let delegation = signed.next();
        if delegation
            .as_ref()
            .is_some_and(|delegation| delegation.len() > MAX_DELEGATION_CHARS)
        {
            return Err(Error::Malformed);
        }
        let mut reply = JoinReply::new(
            self.owner_identity.clone(),
            self.commitment.clone(),
            format!("{binding}{BINDING_PART_SEPARATOR}{vouch}"),
            rules,
        );
        reply.delegation = delegation;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::Delegated;
    use crate::passkey::authenticator::Authenticator;
    use crate::rules::{Level, RulesLimits};
    use crate::{RecoveryRule, SealingKey};

    const NOW: u64 = 1_793_750_400;
    const SEQ: u64 = 1_793_750_400_000;
    const ADDRESS: &str = "muse~host.example";

    fn first_rules() -> RulesDraft {
        RulesDraft {
            paused: false,
            reach: Default::default(),
            permissions: Default::default(),
            changes: Default::default(),
            sealing: Default::default(),
            delegation: None,
            ends_at: None,
            contacts: Vec::new(),
            invites: Vec::new(),
            limits: RulesLimits {
                new_requests_per_contact_per_day: 3,
                open_requests_per_contact: 3,
                open_approvals: 10,
                new_from_others_per_day: 50,
                texts_per_contact_per_day: 20,
                agreed_texts_per_day: None,
                agreed_new_requests_per_day: None,
                sends_per_hour: None,
                sends_per_day: None,
            },
        }
    }

    fn controls(agent: &Identity, backup: &SigningKey, delegate: &PublicKey) -> ControlsDraft {
        ControlsDraft {
            agent: agent.clone(),
            address: ADDRESS.to_owned(),
            backup: backup.public_key(),
            rules: first_rules(),
            delegation: Some(DelegationDraft {
                delegate: delegate.clone(),
                may: vec![Delegated::ApproveWithinCaps],
                level: Level::AutoWithinLimits,
                caps: Default::default(),
                actions_per_day: 50,
                lasts_secs: 365 * 24 * 60 * 60,
            }),
            seq: SEQ,
            now: NOW,
        }
    }

    /// An owner whose key is a passkey sets up their controls for an agent that joined on its own with
    /// one touch: the agent's host keeps it, and the agent takes it up once its stand-in has moved its ID
    /// to the owner's backup. A delegation the rules don't name can't ride along with them.
    #[test]
    fn one_touch_sets_up_controls_and_carries_only_the_delegation_the_rules_name() {
        let authenticator = Authenticator::new("host.example");
        let owner = authenticator.identity(
            &crate::test_seal(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        );
        let (agent_key, agent_seal) = (
            SigningKey::generate().unwrap(),
            SealingKey::generate().unwrap(),
        );
        let stand_ins_backup = SigningKey::generate().unwrap();
        let agent = Identity::create(
            &agent_key,
            &agent_seal.public_key(),
            RecoveryRule::backup_key(&stand_ins_backup.public_key()),
        )
        .unwrap();
        let backup = SigningKey::generate().unwrap();
        let delegate = SigningKey::generate().unwrap().public_key();

        let prepared = controls(&agent, &backup, &delegate)
            .prepare(&owner)
            .unwrap();
        assert_eq!(prepared.owner_inputs().len(), 3);
        let challenge = prepared.challenge().unwrap();
        let reply = prepared
            .signed_by_passkey(&authenticator.assert(challenge.challenge()), &backup)
            .unwrap();
        assert!(reply.delegation.is_some());
        let reply = JoinReply::decode(&reply.encode().unwrap()).unwrap();
        assert_eq!(
            reply
                .check_confirming_for_keeping(&agent, ADDRESS, NOW)
                .err(),
            None
        );
        let moved = agent
            .recover(
                &stand_ins_backup,
                agent.sole_key().unwrap(),
                &agent_seal.public_key(),
                RecoveryRule::committed_to(&reply.commitment).unwrap(),
                NOW,
            )
            .unwrap();
        let (confirmed, address) = reply.check_confirming(&moved, ADDRESS, NOW).unwrap();
        assert_eq!((confirmed.id(), address.as_str()), (owner.id(), ADDRESS));

        // The same owner's delegation from another touch, to another key, which these rules don't name.
        let other = controls(
            &agent,
            &backup,
            &SigningKey::generate().unwrap().public_key(),
        )
        .prepare(&owner)
        .unwrap();
        let other_challenge = other.challenge().unwrap();
        let other = other
            .signed_by_passkey(&authenticator.assert(other_challenge.challenge()), &backup)
            .unwrap();
        let swapped = JoinReply {
            delegation: other.delegation,
            ..reply
        };
        assert_eq!(
            swapped
                .check_confirming_for_keeping(&agent, ADDRESS, NOW)
                .err(),
            Some(Error::ProofMismatch)
        );
        assert_eq!(
            swapped.check_confirming(&moved, ADDRESS, NOW).err(),
            Some(Error::ProofMismatch)
        );
    }
}

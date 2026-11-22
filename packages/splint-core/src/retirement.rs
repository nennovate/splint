//! An owner's signed stop signal for an agent, such as one whose key was stolen. See
//! `docs/protocol.md`.

use serde::{Deserialize, Serialize};

use crate::host_api::RetirementNotice;
use crate::{Error, Identity, SigningKey, SplintId, VerifiedBinding, jws};

/// How long a recovery of the owner's ID can still undo what its old key signed: a retirement, or a
/// move to a new owner. A thief with a stolen owner key can sign either, so neither is final until the
/// real owner has had time to notice. Long enough to cover a holiday, and a real owner who wants it
/// sooner has already stopped the agent. Provisional, for Nenye to overturn.
pub const RECOVERY_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

const RETIREMENT_TYPE: &str = "splint-retirement";
const RETIREMENT_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementReason {
    KeyLost,
    Finished,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementPayload {
    v: u8,
    owner: SplintId,
    agent: SplintId,
    reason: RetirementReason,
    issued_at: u64,
}

/// A retirement whose signature under the agent's owner has been checked, so an agent can't retire
/// itself or a sibling.
pub struct VerifiedRetirement {
    compact: String,
    agent: SplintId,
}

impl VerifiedRetirement {
    pub fn sign(
        key: &SigningKey,
        owner: &SplintId,
        agent: &SplintId,
        reason: RetirementReason,
        now: u64,
    ) -> Result<String, Error> {
        let payload = serde_json::to_vec(&RetirementPayload {
            v: RETIREMENT_VERSION,
            owner: owner.clone(),
            agent: agent.clone(),
            reason,
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)?;
        jws::sign(key, RETIREMENT_TYPE, &payload)
    }

    pub fn verify(compact: &str, owner: &Identity) -> Result<Self, Error> {
        let bytes = owner.verify(compact, RETIREMENT_TYPE)?;
        let payload: RetirementPayload =
            serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        if payload.v != RETIREMENT_VERSION {
            return Err(Error::Malformed);
        }
        if &payload.owner != owner.id() {
            return Err(Error::WrongSigner);
        }
        Ok(Self {
            compact: compact.to_owned(),
            agent: payload.agent,
        })
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn agent(&self) -> &SplintId {
        &self.agent
    }
}

/// A retirement as a contact checks it, with no word from any host: signed by whoever the agent's
/// backup vouched for. So a stolen agent key can't make one, or a stranger, and a host handing a retired
/// key along can't keep it from a contact whose own host or Signet has heard.
pub struct VerifiedStop {
    agent: Identity,
    owner: Identity,
}

impl VerifiedStop {
    pub fn verify(notice: &RetirementNotice) -> Result<Self, Error> {
        let agent = Identity::from_encoded(&notice.agent_identity)?;
        let owner = Identity::from_encoded(&notice.owner_identity)?;
        let retirement = VerifiedRetirement::verify(&notice.retirement, &owner)?;
        if retirement.agent() != agent.id() {
            return Err(Error::ProofMismatch);
        }
        VerifiedBinding::verify_history(&notice.binding, &owner, &agent)?;
        Ok(Self { agent, owner })
    }

    pub fn agent(&self) -> &Identity {
        &self.agent
    }

    pub fn owner(&self) -> &Identity {
        &self.owner
    }

    /// Whether this copy of the owner's ID has recovered past the key that signed this, which undoes
    /// it. It takes no binding, as a recovery leaves the agent with none until the owner signs again.
    /// Whoever stole the old key can add a statement to a copy of their own, which no recovered copy
    /// extends, and the recovery still wins over that. A rival recovery wins over nothing, however many
    /// recoveries it counts.
    pub fn undone_by(&self, owner: &Identity) -> bool {
        owner.id() == self.owner.id()
            && owner.recoveries() > self.owner.recoveries()
            && owner.replaces(&self.owner).unwrap_or(false)
    }

    /// Whether an agent is retired after its host hands it this, going by the copy of its owner's ID it
    /// holds and whether it's retired now. A stop counts only on one line with the copy held, one
    /// extending the other. One that parts from it is the word of some other copy, which says nothing
    /// either way.
    pub fn leaves_retired(&self, held: &Identity, retired: bool) -> bool {
        if !held.extends(&self.owner) && !self.owner.extends(held) {
            return retired;
        }
        !self.undone_by(held)
    }

    /// Whether this still stops a message showing this owner and binding, if it shows any. A later
    /// copy of the same owner's ID means the key that signed this was given up, and an owner this one
    /// really released the agent to is someone else's to stop. Showing nothing changes nothing, so a
    /// host can't get past this by leaving out who its agent acts for.
    pub fn stops_one_showing(&self, shown: Option<(&Identity, &VerifiedBinding)>) -> bool {
        let Some((owner, binding)) = shown else {
            return true;
        };
        if owner.id() == self.owner.id() {
            return !self.undone_by(owner);
        }
        binding.may_replace(&self.owner, 0).is_err()
    }
}

/// Which agent a retirement says it's for, before verification. Use this only to look up the owner
/// to verify against.
pub fn claimed_retired_agent(compact: &str) -> Result<SplintId, Error> {
    let payload = jws::unverified_payload(compact, RETIREMENT_TYPE)?;
    let payload: RetirementPayload =
        serde_json::from_slice(&payload).map_err(|_| Error::Malformed)?;
    Ok(payload.agent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RecoveryRule, VerifiedRelease};

    const NOW: u64 = 1_793_750_400;
    const ADDRESS: &str = "ana~host.example";

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
            &crate::test_seal(),
            RecoveryRule::backup_key(&backup.public_key()),
        )
        .unwrap();
        Holder {
            key,
            backup,
            identity,
        }
    }

    fn binding(owner: &Holder, agent: &Holder, seq: u64, release: Option<&str>) -> VerifiedBinding {
        let half = VerifiedBinding::sign(
            &owner.key,
            &agent.backup,
            owner.identity.id(),
            &agent.identity,
            ADDRESS,
            seq,
            NOW,
        )
        .unwrap();
        VerifiedBinding::accept(&agent.key, &half, release, &owner.identity, &agent.identity)
            .unwrap()
    }

    fn notice(signer: &Holder, owner: &Holder, agent: &Holder) -> RetirementNotice {
        RetirementNotice {
            retirement: VerifiedRetirement::sign(
                &signer.key,
                signer.identity.id(),
                agent.identity.id(),
                RetirementReason::KeyLost,
                NOW,
            )
            .unwrap(),
            owner_identity: signer.identity.encoded(),
            agent_identity: agent.identity.encoded(),
            binding: binding(owner, agent, 1, None).compact().to_owned(),
        }
    }

    #[test]
    fn only_who_the_agents_backup_vouched_for_can_stop_it() {
        let (owner, agent, stranger) = (holder(), holder(), holder());
        assert!(VerifiedStop::verify(&notice(&owner, &owner, &agent)).is_ok());
        // Their own signature, and a binding that isn't theirs.
        assert!(VerifiedStop::verify(&notice(&stranger, &owner, &agent)).is_err());
        // The agent's own key, naming itself.
        assert!(VerifiedStop::verify(&notice(&agent, &owner, &agent)).is_err());
    }

    #[test]
    fn showing_nothing_changes_nothing_and_a_real_recovery_or_transfer_ends_it() {
        let (owner, agent, next) = (holder(), holder(), holder());
        let stop = VerifiedStop::verify(&notice(&owner, &owner, &agent)).unwrap();
        let bound = binding(&owner, &agent, 2, None);
        assert!(stop.stops_one_showing(None));
        assert!(stop.stops_one_showing(Some((&owner.identity, &bound))));

        let recovered = owner
            .identity
            .recover(
                &owner.backup,
                &SigningKey::generate().unwrap().public_key(),
                &crate::test_seal(),
                RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
                NOW,
            )
            .unwrap();
        assert!(!stop.stops_one_showing(Some((&recovered, &bound))));

        // Someone it was never released to can't step round it by naming themselves.
        let unreleased = binding(&next, &agent, 9, None);
        assert!(stop.stops_one_showing(Some((&next.identity, &unreleased))));
        let release = VerifiedRelease::sign(
            &owner.key,
            owner.identity.id(),
            agent.identity.id(),
            Some(next.identity.id()),
            8,
            NOW,
        )
        .unwrap();
        let released = binding(&next, &agent, 9, Some(&release));
        assert!(!stop.stops_one_showing(Some((&next.identity, &released))));
    }

    /// Bug caught: a thief with the old owner key added a statement to a copy of their own, which no
    /// recovered copy extends, so the retirement they signed on it outlasted the owner's recovery.
    #[test]
    fn a_recovery_undoes_a_stop_signed_on_a_copy_the_thief_added_to() {
        let (owner, agent) = (holder(), holder());
        let thiefs_copy = owner
            .identity
            .add_key(&owner.key, &SigningKey::generate().unwrap(), NOW)
            .unwrap();
        let stop = VerifiedStop::verify(&RetirementNotice {
            owner_identity: thiefs_copy.encoded(),
            ..notice(&owner, &owner, &agent)
        })
        .unwrap();
        let recovered = owner
            .identity
            .recover(
                &owner.backup,
                &SigningKey::generate().unwrap().public_key(),
                &crate::test_seal(),
                RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
                NOW,
            )
            .unwrap();
        assert!(!recovered.extends(&thiefs_copy), "control: the copies part");
        assert!(stop.undone_by(&recovered));
        assert!(
            !stop.undone_by(&thiefs_copy),
            "control: no recovery, no undoing"
        );
    }

    /// Bug caught: a retirement signed under a rival recovery with as many recoveries as the real one
    /// retired the real owner's agent, and one with more undid the real owner's own retirement.
    #[test]
    fn a_stop_on_a_copy_that_parts_from_the_one_held_counts_for_nothing() {
        let (owner, agent) = (holder(), holder());
        let recover =
            |from: &Identity, backup: &SigningKey, key: &SigningKey, next: &SigningKey| {
                from.recover(
                    backup,
                    &key.public_key(),
                    &crate::test_seal(),
                    RecoveryRule::backup_key(&next.public_key()),
                    NOW,
                )
                .unwrap()
            };
        let stop_under = |key: &SigningKey, copy: &Identity| {
            VerifiedStop::verify(&RetirementNotice {
                retirement: VerifiedRetirement::sign(
                    key,
                    copy.id(),
                    agent.identity.id(),
                    RetirementReason::KeyLost,
                    NOW,
                )
                .unwrap(),
                owner_identity: copy.encoded(),
                ..notice(&owner, &owner, &agent)
            })
            .unwrap()
        };
        let (real_key, real_backup) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        let (rival_key, rival_backup) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        let real = recover(&owner.identity, &owner.backup, &real_key, &real_backup);
        let rival = recover(&owner.identity, &owner.backup, &rival_key, &rival_backup);
        let later_key = SigningKey::generate().unwrap();
        let rival_again = recover(
            &rival,
            &rival_backup,
            &later_key,
            &SigningKey::generate().unwrap(),
        );

        for (stop, retired) in [
            (stop_under(&rival_key, &rival), false),
            (stop_under(&rival_key, &rival), true),
            (stop_under(&later_key, &rival_again), false),
            (stop_under(&later_key, &rival_again), true),
        ] {
            assert_eq!(stop.leaves_retired(&real, retired), retired);
        }

        let real_stop = stop_under(&real_key, &real);
        assert!(
            real_stop.leaves_retired(&real, false),
            "control: the real owner's stop counts"
        );
        assert!(!real_stop.undone_by(&rival_again));
        let recovered_again = recover(
            &real,
            &real_backup,
            &later_key,
            &SigningKey::generate().unwrap(),
        );
        assert!(
            !real_stop.leaves_retired(&recovered_again, true),
            "a real recovery still undoes it with nobody acting"
        );
    }
}

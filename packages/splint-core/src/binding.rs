//! The signed statement that an agent acts for an owner, at one address. See `docs/protocol.md`.
//!
//! An ID says nothing about who it acts for, so this is what ties them, and it can change. It takes
//! both signatures: the owner's, because nobody else can say an agent is theirs, and the agent's,
//! because an owner can't claim an agent that never agreed. It doesn't prove a handle is unique,
//! because a host is the authority over its own handles.
//!
//! Whoever holds the agent's backup vouches for each owner it acts for, so a stolen agent key can't
//! name an owner for an agent, even one that has none yet. The owner's device holds that backup, and
//! a handover moves it to the new owner. The vouch names the agent's keys as they were when its ID
//! committed to that backup, so whoever held the backup before can't recover the ID onto keys of
//! their own, committing to this one, and pass the owner's binding off as theirs.
//!
//! A later statement replaces an earlier one. One naming a new owner has to carry the old owner's
//! release too, so nobody holding only an old backup can move an agent.

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::{
    AgentKeys, Error, Identity, PublicKey, RecoveryRule, SigningKey, SplintId, jws, parse_address,
};

const BINDING_TYPE: &str = "splint-binding";
const BINDING_VERSION: u8 = 2;
const ACCEPT_TYPE: &str = "splint-binding-accept";
const ACCEPT_VERSION: u8 = 1;
const VOUCH_TYPE: &str = "splint-binding-vouch";
const VOUCH_VERSION: u8 = 2;
const RELEASE_TYPE: &str = "splint-release";
const RELEASE_VERSION: u8 = 1;
/// Isn't in a JWS, so a binding's text splits one way.
pub const PART_SEPARATOR: char = '~';

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingPayload {
    v: u8,
    owner: SplintId,
    agent: SplintId,
    address: String,
    seq: u64,
    issued_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptPayload {
    v: u8,
    binding: String,
}

/// Signed by a backup key the agent's rule commits to, which names itself, as a recovery does, and the
/// agent's keys when the rule committed to it, as [`AgentKeys::encoded`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VouchPayload {
    v: u8,
    agent: SplintId,
    owner: SplintId,
    backup: String,
    keys: String,
}

fn vouch(
    backup: &SigningKey,
    agent: &SplintId,
    owner: &SplintId,
    keys: &AgentKeys,
) -> Result<String, Error> {
    let payload = vouch_payload(&backup.public_key(), agent, owner, keys)?;
    jws::sign(backup, VOUCH_TYPE, &payload)
}

/// What an agent's backup signs to vouch for an owner, for the keys the agent has when its ID commits
/// to that backup.
fn vouch_payload(
    backup: &PublicKey,
    agent: &SplintId,
    owner: &SplintId,
    keys: &AgentKeys,
) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&VouchPayload {
        v: VOUCH_VERSION,
        agent: agent.clone(),
        owner: owner.clone(),
        backup: backup.encoded(),
        keys: keys.encoded(),
    })
    .map_err(|_| Error::Malformed)
}

fn acceptance_of(signed_by_owner: &str) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&AcceptPayload {
        v: ACCEPT_VERSION,
        binding: hex(digest::digest(&digest::SHA256, signed_by_owner.as_bytes()).as_ref()),
    })
    .map_err(|_| Error::Malformed)
}

/// A binding whose owner and agent signatures have been checked against these two identities. The
/// only way to get one is to pass that check, so nothing a stranger makes up can register a handle.
#[derive(Debug)]
pub struct VerifiedBinding {
    compact: String,
    release: Option<String>,
    payload: BindingPayload,
}

impl VerifiedBinding {
    /// The owner's half, and the agent's backup vouching for that owner. `seq` only has to rise, as
    /// with rules. The backup is checked the way a reader will check it, so a device that doesn't
    /// hold it finds out here.
    pub fn sign(
        key: &SigningKey,
        backup: &SigningKey,
        owner: &SplintId,
        agent: &Identity,
        address: &str,
        seq: u64,
        now: u64,
    ) -> Result<String, Error> {
        agent.check_backup(&backup.public_key())?;
        let keys = agent
            .keys_when_committed_to(&backup.public_key())
            .ok_or(Error::ProofMismatch)?;
        let signed_by_owner = Self::sign_owner_half(key, owner, agent.id(), address, seq, now)?;
        let vouch = vouch(backup, agent.id(), owner, &keys)?;
        Ok(format!("{signed_by_owner}{PART_SEPARATOR}{vouch}"))
    }

    /// The same with a vouch the agent's backup has already signed for this owner, so the backup can
    /// be somewhere safer than where the owner's key is. It's checked the way a reader will check it,
    /// before the owner's key signs anything, so a key that asks for its person never asks for a
    /// binding that can't be used.
    pub fn sign_with_vouch(
        key: &SigningKey,
        vouch: &str,
        owner: &SplintId,
        agent: &Identity,
        address: &str,
        seq: u64,
        now: u64,
    ) -> Result<String, Error> {
        check_vouch(vouch, owner, agent)?;
        let signed_by_owner = Self::sign_owner_half(key, owner, agent.id(), address, seq, now)?;
        Ok(format!("{signed_by_owner}{PART_SEPARATOR}{vouch}"))
    }

    /// Whether a vouch kept from before counts for this owner and this copy of the agent's ID, as
    /// [`Self::sign_with_vouch`] and every reader check it. One for a backup the ID never committed
    /// to doesn't.
    pub fn vouch_counts(vouch: &str, owner: &SplintId, agent: &Identity) -> bool {
        check_vouch(vouch, owner, agent).is_ok()
    }

    /// The owner's half and a vouch for an agent whose ID doesn't commit to this backup yet: one that
    /// joined before its owner confirmed, and whose stand-in moves its rule to this backup on the
    /// agent's own machine, keeping the keys it has now. Readers check it as usual once that move is
    /// part of the ID, and until then it vouches for nothing, so it can be signed ahead and passed on.
    /// It names those keys, so a copy of the ID moved to this backup onto any others gets nothing.
    pub fn sign_ahead(
        key: &SigningKey,
        backup: &SigningKey,
        owner: &SplintId,
        agent: &Identity,
        address: &str,
        seq: u64,
        now: u64,
    ) -> Result<String, Error> {
        let keys = agent.agent_keys().ok_or(Error::Malformed)?;
        let signed_by_owner = Self::sign_owner_half(key, owner, agent.id(), address, seq, now)?;
        let vouch = vouch(backup, agent.id(), owner, &keys)?;
        Ok(format!("{signed_by_owner}{PART_SEPARATOR}{vouch}"))
    }

    /// Whether what [`Self::sign_ahead`] made is this owner's for this agent as it is now, vouched for
    /// by the backup `commitment` names, and the address it names. For holding it until the agent takes
    /// it up, by someone who can't yet check it against the agent's moved ID.
    pub fn check_ahead(
        from_owner: &str,
        owner: &Identity,
        agent: &Identity,
        commitment: &str,
    ) -> Result<String, Error> {
        let (signed_by_owner, vouch) = from_owner
            .split_once(PART_SEPARATOR)
            .ok_or(Error::Malformed)?;
        let payload = checked_owner_half(signed_by_owner, Signed::Now, owner, agent)?;
        let claimed = jws::unverified_payload(vouch, VOUCH_TYPE)?;
        let vouched: VouchPayload =
            serde_json::from_slice(&claimed).map_err(|_| Error::Malformed)?;
        if vouched.v != VOUCH_VERSION {
            return Err(Error::Malformed);
        }
        let backup = PublicKey::from_encoded(&vouched.backup)?;
        if !RecoveryRule::committed_to(commitment)?.accepts(&backup) {
            return Err(Error::WrongSigner);
        }
        jws::verify(vouch, &backup, VOUCH_TYPE)?;
        let keys_now = agent.agent_keys().map(|keys| keys.encoded());
        if &vouched.agent != agent.id()
            || &vouched.owner != owner.id()
            || keys_now.as_ref() != Some(&vouched.keys)
        {
            return Err(Error::ProofMismatch);
        }
        Ok(payload.address)
    }

    fn sign_owner_half(
        key: &SigningKey,
        owner: &SplintId,
        agent: &SplintId,
        address: &str,
        seq: u64,
        now: u64,
    ) -> Result<String, Error> {
        let payload = Self::owner_half_payload(owner, agent, address, seq, now)?;
        jws::sign(key, BINDING_TYPE, &payload)
    }

    /// What the owner's key signs, whichever way it signs.
    fn owner_half_payload(
        owner: &SplintId,
        agent: &SplintId,
        address: &str,
        seq: u64,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        parse_address(address)?;
        if owner == agent {
            return Err(Error::WrongSigner);
        }
        serde_json::to_vec(&BindingPayload {
            v: BINDING_VERSION,
            owner: owner.clone(),
            agent: agent.clone(),
            address: address.to_owned(),
            seq,
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)
    }

    /// The signing inputs of what [`Self::sign_ahead`] signs, for a device that signs them some other
    /// way, such as a passkey in a browser: the owner's half with `alg`, and the backup's vouch, always
    /// ES256. Signed, the two are joined as [`Self::sign_ahead`] joins them.
    pub(crate) fn inputs_ahead(
        alg: jws::Alg,
        backup: &PublicKey,
        owner: &SplintId,
        agent: &Identity,
        address: &str,
        seq: u64,
        now: u64,
    ) -> Result<(String, String), Error> {
        let keys = agent.agent_keys().ok_or(Error::Malformed)?;
        let half = Self::owner_half_payload(owner, agent.id(), address, seq, now)?;
        let vouched = vouch_payload(backup, agent.id(), owner, &keys)?;
        Ok((
            jws::signing_input(alg, BINDING_TYPE, &half)?,
            jws::signing_input(jws::Alg::Es256, VOUCH_TYPE, &vouched)?,
        ))
    }

    /// The agent's half, added to what its owner's device signed, and to the old owner's release if
    /// this moves the agent. An agent's key signs this only for an owner's half and a vouch that
    /// check out, so a fooled agent can't get a signature on something an owner never said.
    pub fn accept(
        agent_key: &SigningKey,
        from_owner: &str,
        release: Option<&str>,
        owner: &Identity,
        agent: &Identity,
    ) -> Result<Self, Error> {
        let (signed_by_owner, vouch) = from_owner
            .split_once(PART_SEPARATOR)
            .ok_or(Error::Malformed)?;
        checked_owner_half(signed_by_owner, Signed::Now, owner, agent)?;
        check_vouch(vouch, owner.id(), agent)?;
        let accepted = jws::sign(agent_key, ACCEPT_TYPE, &acceptance_of(signed_by_owner)?)?;
        let mut compact =
            format!("{signed_by_owner}{PART_SEPARATOR}{accepted}{PART_SEPARATOR}{vouch}");
        if let Some(release) = release {
            compact.push(PART_SEPARATOR);
            compact.push_str(release);
        }
        Self::verify(&compact, owner, agent)
    }

    pub fn verify(compact: &str, owner: &Identity, agent: &Identity) -> Result<Self, Error> {
        Self::verify_when(compact, owner, agent, Signed::Now)
    }

    /// The same for one in an agent's history, under each ID as it stood in the epoch its event names,
    /// as it was signed then.
    pub(crate) fn verify_in_epoch(
        compact: &str,
        owner: &Identity,
        agent: &Identity,
    ) -> Result<Self, Error> {
        Self::verify_when(compact, owner, agent, Signed::InEpoch)
    }

    fn verify_when(
        compact: &str,
        owner: &Identity,
        agent: &Identity,
        when: Signed,
    ) -> Result<Self, Error> {
        let (signed_by_owner, accepted, vouch, release) = parts_of(compact)?;
        let payload = checked_owner_half(signed_by_owner, when, owner, agent)?;
        let bytes = agent.verify(accepted, ACCEPT_TYPE)?;
        check_acceptance(&bytes, signed_by_owner)?;
        check_vouch(vouch, owner.id(), agent)?;
        Ok(Self {
            compact: compact.to_owned(),
            release: release.map(str::to_owned),
            payload,
        })
    }

    /// The same for one in a finished request's bundle, which may date from before a recovery of
    /// either side. It says who this agent acted for then.
    pub fn verify_history(
        compact: &str,
        owner: &Identity,
        agent: &Identity,
    ) -> Result<Self, Error> {
        let (signed_by_owner, accepted, vouch, release) = parts_of(compact)?;
        let payload = checked_owner_half(signed_by_owner, Signed::Then, owner, agent)?;
        let bytes = agent.verify_under_any_key(accepted, ACCEPT_TYPE)?;
        check_acceptance(&bytes, signed_by_owner)?;
        check_vouch(vouch, owner.id(), agent)?;
        Ok(Self {
            compact: compact.to_owned(),
            release: release.map(str::to_owned),
            payload,
        })
    }

    /// What the owner's device signed for a binding, which outlasts a recovery of the agent's key.
    pub fn from_owner(compact: &str) -> Result<String, Error> {
        parts_of(compact).map(|(signed_by_owner, _, vouch, _)| {
            format!("{signed_by_owner}{PART_SEPARATOR}{vouch}")
        })
    }

    /// Whether an owner's half and a vouch check out for this agent, before the agent has added its own
    /// half, and the address they name. So a reply can be checked before anything starts on the strength
    /// of it.
    pub fn check_from_owner(
        from_owner: &str,
        owner: &Identity,
        agent: &Identity,
    ) -> Result<String, Error> {
        let (signed_by_owner, vouch) = from_owner
            .split_once(PART_SEPARATOR)
            .ok_or(Error::Malformed)?;
        let payload = checked_owner_half(signed_by_owner, Signed::Now, owner, agent)?;
        check_vouch(vouch, owner.id(), agent)?;
        Ok(payload.address)
    }

    /// Checks a binding for the exact address asked about, so one can't be reused at another.
    pub fn verify_for(
        compact: &str,
        owner: &Identity,
        agent: &Identity,
        address: &str,
    ) -> Result<Self, Error> {
        let binding = Self::verify(compact, owner, agent)?;
        if binding.address() == address {
            Ok(binding)
        } else {
            Err(Error::ProofMismatch)
        }
    }

    /// Whether this can take over from what a reader holds now: the same owner at the same point or
    /// later, or a new owner the current one released this agent to. A host and a Signet both ask
    /// this, so they can't differ. A release older than what's held says nothing, because the owner
    /// has signed since.
    pub fn may_replace(&self, current_owner: &Identity, current_seq: u64) -> Result<(), Error> {
        if &self.payload.owner == current_owner.id() {
            return if self.payload.seq >= current_seq {
                Ok(())
            } else {
                Err(Error::Stale)
            };
        }
        let release = self.release.as_deref().ok_or(Error::WrongSigner)?;
        let release = VerifiedRelease::verify(release, current_owner, &self.payload.agent)?;
        if release.to() != Some(&self.payload.owner) {
            return Err(Error::WrongSigner);
        }
        if release.seq() < current_seq || self.payload.seq <= release.seq() {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Whether a reader already knows something newer than this about who the agent acts for. `seq`
    /// rises across a transfer as well as within an owner, so an old owner's statement is behind what
    /// the new one signed, and showing it again says nothing.
    pub fn is_behind(&self, held_owner: &str, held_seq: u64) -> bool {
        if self.payload.owner.as_str() == held_owner {
            self.payload.seq < held_seq
        } else {
            held_seq > 0 && self.payload.seq <= held_seq
        }
    }

    /// Which agent an owner's half says it's for, before verification. Use this only to look up the
    /// agent to verify against.
    pub fn claimed_agent(from_owner: &str) -> Result<SplintId, Error> {
        Ok(Self::claimed(from_owner)?.agent)
    }

    /// The `seq` an owner's half claims, before verification, for dating what has to come before it.
    pub fn claimed_seq(from_owner: &str) -> Result<u64, Error> {
        Ok(Self::claimed(from_owner)?.seq)
    }

    /// When an owner's half claims it was signed, before verification, for saying what became of one
    /// that Signet, which does verify it, refused.
    pub fn claimed_issued_at(from_owner: &str) -> Result<u64, Error> {
        Ok(Self::claimed(from_owner)?.issued_at)
    }

    fn claimed(from_owner: &str) -> Result<BindingPayload, Error> {
        let signed_by_owner = from_owner
            .split(PART_SEPARATOR)
            .next()
            .ok_or(Error::Malformed)?;
        let claimed = jws::unverified_payload(signed_by_owner, BINDING_TYPE)?;
        serde_json::from_slice(&claimed).map_err(|_| Error::Malformed)
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn address(&self) -> &str {
        &self.payload.address
    }

    pub fn owner(&self) -> &SplintId {
        &self.payload.owner
    }

    pub fn seq(&self) -> u64 {
        self.payload.seq
    }

    /// When the owner's half says it was signed.
    pub fn issued_at(&self) -> u64 {
        self.payload.issued_at
    }
}

type Parts<'a> = (&'a str, &'a str, &'a str, Option<&'a str>);

fn parts_of(compact: &str) -> Result<Parts<'_>, Error> {
    let mut parts = compact.split(PART_SEPARATOR);
    let signed_by_owner = parts.next().ok_or(Error::Malformed)?;
    let accepted = parts.next().ok_or(Error::Malformed)?;
    let vouch = parts.next().ok_or(Error::Malformed)?;
    let release = parts.next();
    if parts.next().is_some() {
        return Err(Error::Malformed);
    }
    Ok((signed_by_owner, accepted, vouch, release))
}

/// A backup this agent's rule has committed to, at any point, vouching for this owner, for the keys
/// the agent had when it did. One the rule has since moved on from still counts for what it vouched
/// for then, because a new owner also needs the old one's release. A copy of the ID that an earlier
/// backup moved to this one onto other keys is a fork, and gets nothing from it.
fn check_vouch(vouch: &str, owner: &SplintId, agent: &Identity) -> Result<(), Error> {
    let claimed = jws::unverified_payload(vouch, VOUCH_TYPE)?;
    let payload: VouchPayload = serde_json::from_slice(&claimed).map_err(|_| Error::Malformed)?;
    if payload.v != VOUCH_VERSION {
        return Err(Error::Malformed);
    }
    let backup = PublicKey::from_encoded(&payload.backup)?;
    let keys = agent
        .keys_when_committed_to(&backup)
        .ok_or(Error::WrongSigner)?;
    jws::verify(vouch, &backup, VOUCH_TYPE)?;
    if &payload.agent != agent.id() || &payload.owner != owner || payload.keys != keys.encoded() {
        return Err(Error::ProofMismatch);
    }
    Ok(())
}

/// Which keys an owner's half is checked under.
#[derive(Clone, Copy)]
enum Signed {
    /// Arriving now: the keys that count now.
    Now,
    /// In an agent's history: the keys of the epoch its event names, as it was signed then.
    InEpoch,
    /// In a finished request's bundle: any key the owner has had.
    Then,
}

/// The owner's half, checked as that owner's key signs. An agent whose key is a passkey is refused
/// first, as only an owner's may be.
fn checked_owner_half(
    signed_by_owner: &str,
    when: Signed,
    owner: &Identity,
    agent: &Identity,
) -> Result<BindingPayload, Error> {
    if !agent.may_act_as_agent() {
        return Err(Error::WrongSigner);
    }
    let bytes = match when {
        Signed::Now | Signed::InEpoch => owner.verify(signed_by_owner, BINDING_TYPE)?,
        Signed::Then => owner.verify_under_any_key(signed_by_owner, BINDING_TYPE)?,
    };
    let payload: BindingPayload = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
    if payload.v != BINDING_VERSION {
        return Err(Error::Malformed);
    }
    if &payload.owner != owner.id() || &payload.agent != agent.id() || owner.id() == agent.id() {
        return Err(Error::ProofMismatch);
    }
    // One key, one job. Only whoever holds the agent's key outside Signet can add it to an owner's ID,
    // as an addition needs the added key's signature, but an owner's half arriving now that the agent's
    // own key signed is refused all the same. It turns on this one object, never on a copy of either
    // ID, so it holds back no recovery, and what's read back stays as it was signed.
    if matches!(when, Signed::Now) && agent.signed_now(signed_by_owner) {
        return Err(Error::WrongSigner);
    }
    parse_address(&payload.address)?;
    Ok(payload)
}

fn check_acceptance(bytes: &[u8], signed_by_owner: &str) -> Result<(), Error> {
    if bytes == acceptance_of(signed_by_owner)? {
        Ok(())
    } else {
        Err(Error::ProofMismatch)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasePayload {
    v: u8,
    owner: SplintId,
    agent: SplintId,
    /// Who it's released to. With nobody named this is a revocation: the agent acts for nobody until
    /// its owner signs another binding.
    to: Option<SplintId>,
    seq: u64,
    issued_at: u64,
}

/// An owner's signed word that an agent no longer acts for them, checked under that owner's key.
#[derive(Debug)]
pub struct VerifiedRelease {
    compact: String,
    agent: SplintId,
    to: Option<SplintId>,
    seq: u64,
}

impl VerifiedRelease {
    pub fn sign(
        key: &SigningKey,
        owner: &SplintId,
        agent: &SplintId,
        to: Option<&SplintId>,
        seq: u64,
        now: u64,
    ) -> Result<String, Error> {
        let payload = serde_json::to_vec(&ReleasePayload {
            v: RELEASE_VERSION,
            owner: owner.clone(),
            agent: agent.clone(),
            to: to.cloned(),
            seq,
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)?;
        jws::sign(key, RELEASE_TYPE, &payload)
    }

    pub fn verify(compact: &str, owner: &Identity, agent: &SplintId) -> Result<Self, Error> {
        let bytes = owner.verify(compact, RELEASE_TYPE)?;
        let payload: ReleasePayload =
            serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        if payload.v != RELEASE_VERSION {
            return Err(Error::Malformed);
        }
        if &payload.owner != owner.id() {
            return Err(Error::WrongSigner);
        }
        if &payload.agent != agent {
            return Err(Error::ProofMismatch);
        }
        Ok(Self {
            compact: compact.to_owned(),
            agent: payload.agent,
            to: payload.to,
            seq: payload.seq,
        })
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn agent(&self) -> &SplintId {
        &self.agent
    }

    pub fn to(&self) -> Option<&SplintId> {
        self.to.as_ref()
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

/// Which agent a release says it's for, before verification. Use this only to look up the owner to
/// verify against.
pub fn claimed_released_agent(compact: &str) -> Result<SplintId, Error> {
    let payload = jws::unverified_payload(compact, RELEASE_TYPE)?;
    let payload: ReleasePayload = serde_json::from_slice(&payload).map_err(|_| Error::Malformed)?;
    Ok(payload.agent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecoveryRule;

    const NOW: u64 = 1_000_000;
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

    fn owner_half(owner: &Holder, agent: &Holder, seq: u64) -> String {
        VerifiedBinding::sign(
            &owner.key,
            &agent.backup,
            owner.identity.id(),
            &agent.identity,
            ADDRESS,
            seq,
            NOW,
        )
        .unwrap()
    }

    fn bound(owner: &Holder, agent: &Holder, seq: u64, release: Option<&str>) -> VerifiedBinding {
        VerifiedBinding::accept(
            &agent.key,
            &owner_half(owner, agent, seq),
            release,
            &owner.identity,
            &agent.identity,
        )
        .unwrap()
    }

    #[test]
    fn it_takes_the_owner_and_the_agent() {
        let (ana, mallory, agent) = (holder(), holder(), holder());
        let good = bound(&ana, &agent, 1, None);
        assert!(
            VerifiedBinding::verify_for(good.compact(), &ana.identity, &agent.identity, ADDRESS)
                .is_ok()
        );
        assert_eq!(good.owner(), ana.identity.id());

        // Mallory can sign that the agent is hers, and it isn't, without the agent's half.
        let hers = VerifiedBinding::sign_owner_half(
            &mallory.key,
            mallory.identity.id(),
            agent.identity.id(),
            ADDRESS,
            1,
            NOW,
        )
        .unwrap();
        let (_, accepted, vouch, _) = parts_of(good.compact()).unwrap();
        assert_eq!(
            VerifiedBinding::verify(
                &format!("{hers}~{accepted}~{vouch}"),
                &mallory.identity,
                &agent.identity
            )
            .err(),
            Some(Error::ProofMismatch)
        );
        // And the agent's key can't sign the owner's half of someone else's.
        let forged = VerifiedBinding::sign_owner_half(
            &agent.key,
            ana.identity.id(),
            agent.identity.id(),
            ADDRESS,
            1,
            NOW,
        )
        .unwrap();
        let from_ana = format!("{forged}~{vouch}");
        assert_eq!(
            VerifiedBinding::accept(&agent.key, &from_ana, None, &ana.identity, &agent.identity)
                .err(),
            Some(Error::BadSignature)
        );
    }

    /// Without this, a stolen agent key could name an owner of its own for an agent with none yet.
    #[test]
    fn only_the_agents_backup_can_vouch_for_an_owner() {
        let (thief, agent) = (holder(), holder());
        let theirs = |backup: &SigningKey| {
            VerifiedBinding::sign(
                &thief.key,
                backup,
                thief.identity.id(),
                &agent.identity,
                ADDRESS,
                1,
                NOW,
            )
        };
        assert_eq!(theirs(&thief.backup).err(), Some(Error::ProofMismatch));
        let (half, real_vouch) = theirs(&agent.backup)
            .map(|text| {
                let (half, vouch) = text.split_once('~').unwrap();
                (half.to_owned(), vouch.to_owned())
            })
            .unwrap();
        let vouch = serde_json::to_vec(&VouchPayload {
            v: VOUCH_VERSION,
            agent: agent.identity.id().clone(),
            owner: thief.identity.id().clone(),
            backup: thief.backup.public_key().encoded(),
            keys: agent.identity.agent_keys().unwrap().encoded(),
        })
        .unwrap();
        let by_the_thief = jws::sign(&thief.backup, VOUCH_TYPE, &vouch).unwrap();
        let accept = |from_owner: &str| {
            VerifiedBinding::accept(
                &agent.key,
                from_owner,
                None,
                &thief.identity,
                &agent.identity,
            )
            .err()
        };
        assert_eq!(
            accept(&format!("{half}~{by_the_thief}")),
            Some(Error::WrongSigner)
        );
        assert_eq!(accept(&half), Some(Error::Malformed));
        assert_eq!(accept(&format!("{half}~{real_vouch}")), None);
    }

    fn commitment(rule: &RecoveryRule) -> String {
        let RecoveryRule::BackupKey { commitment } = rule else {
            panic!("a backup key's rule names a commitment");
        };
        commitment.clone()
    }

    /// An agent that joined on its own held its first backup on its own machine. Whoever copied it
    /// can recover the ID from before its owner confirmed, onto keys of their own and the owner's
    /// backup, and without this the owner's binding would count for that copy too.
    #[test]
    fn an_earlier_backup_cant_move_the_owners_binding_onto_other_keys() {
        let (owner, agent) = (holder(), holder());
        let owners_backup = SigningKey::generate().unwrap();
        let rule = RecoveryRule::backup_key(&owners_backup.public_key());
        let from_owner = VerifiedBinding::sign_ahead(
            &owner.key,
            &owners_backup,
            owner.identity.id(),
            &agent.identity,
            ADDRESS,
            2,
            NOW,
        )
        .unwrap();
        let held = |identity: &Identity| {
            VerifiedBinding::check_ahead(&from_owner, &owner.identity, identity, &commitment(&rule))
                .err()
        };
        assert_eq!(held(&agent.identity), None);
        let seal = agent.identity.seal_key().unwrap();
        let moved = agent
            .identity
            .recover(
                &agent.backup,
                agent.identity.sole_key().unwrap(),
                seal,
                rule.clone(),
                NOW,
            )
            .unwrap();
        assert!(
            VerifiedBinding::accept(&agent.key, &from_owner, None, &owner.identity, &moved).is_ok()
        );

        let thief = SigningKey::generate().unwrap();
        let thiefs_seal = crate::test_seal();
        let forked = agent
            .identity
            .recover(
                &agent.backup,
                &thief.public_key(),
                &thiefs_seal,
                rule.clone(),
                NOW + 1,
            )
            .unwrap();
        assert_eq!(forked.id(), moved.id());
        assert_eq!(
            VerifiedBinding::accept(&thief, &from_owner, None, &owner.identity, &forked).err(),
            Some(Error::ProofMismatch)
        );
        assert_eq!(held(&forked), Some(Error::ProofMismatch));
        // By way of a backup of the thief's own first, it's the same.
        let thiefs_backup = SigningKey::generate().unwrap();
        let by_way_of = agent
            .identity
            .recover(
                &agent.backup,
                &thief.public_key(),
                &thiefs_seal,
                RecoveryRule::backup_key(&thiefs_backup.public_key()),
                NOW + 1,
            )
            .unwrap()
            .recover(
                &thiefs_backup,
                &thief.public_key(),
                &thiefs_seal,
                rule,
                NOW + 2,
            )
            .unwrap();
        assert_eq!(
            VerifiedBinding::accept(&thief, &from_owner, None, &owner.identity, &by_way_of).err(),
            Some(Error::ProofMismatch)
        );
    }

    #[test]
    fn an_agent_cant_act_for_itself() {
        let agent = holder();
        assert_eq!(
            VerifiedBinding::sign(
                &agent.key,
                &agent.backup,
                agent.identity.id(),
                &agent.identity,
                ADDRESS,
                1,
                NOW
            )
            .err(),
            Some(Error::WrongSigner)
        );
    }

    /// A binding signed before a recovery stops counting, or a thief's would go on counting too.
    #[test]
    fn what_a_lost_key_signed_stops_counting_except_as_history() {
        let (ana, agent) = (holder(), holder());
        let binding = bound(&ana, &agent, 5, None);
        let recovered = ana
            .identity
            .recover(
                &ana.backup,
                &SigningKey::generate().unwrap().public_key(),
                &crate::test_seal(),
                RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
                NOW,
            )
            .unwrap();
        assert_eq!(
            VerifiedBinding::verify(binding.compact(), &recovered, &agent.identity).err(),
            Some(Error::BadSignature)
        );
        assert!(
            VerifiedBinding::verify_history(binding.compact(), &recovered, &agent.identity).is_ok()
        );
    }

    #[test]
    fn the_same_owner_only_moves_forward() {
        let (ana, agent) = (holder(), holder());
        let binding = bound(&ana, &agent, 5, None);
        assert!(binding.may_replace(&ana.identity, 5).is_ok());
        assert_eq!(
            binding.may_replace(&ana.identity, 6).err(),
            Some(Error::Stale)
        );
    }
}

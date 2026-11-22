//! The owner's list of their agents, which their page keeps at its host so a new device finds every
//! agent. See "Owner API" in `docs/protocol.md`.
//!
//! The list is sealed to the owner's own sealing key, so the host keeping it learns only its size, and
//! signed by the owner, so the host can only hold back the newest or show an older one. A page shows
//! what it opens as the owner's own words about their own agents, and looks each one up before
//! trusting anything about it.
//!
//! It also carries each agent's backup, which vouches for its owner in every binding, so the page that
//! made it can sign a later one. A second copy is sealed to the owner's own backup key, which their
//! recovery code derives, so losing the passkey, and with it the sealing key its PRF gave, doesn't lose
//! the agents' backups too.

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::keys::SCALAR_LEN;
use crate::requests::has_hidden_characters;
use crate::{
    CLOCK_TOLERANCE_SECS, Error, Identity, PublicKey, SealPublicKey, SealingKey, SigningKey,
    SplintId, canonical_address, canonical_domain, jws, seal_note,
};

pub(crate) const LIST_TYPE: &str = "splint-owner-agents";
const VERSION: u8 = 1;
/// More agents than one person runs. A list past it is refused before it's sealed.
pub const MAX_LISTED_AGENTS: usize = 64;
/// A name a person gives an agent, such as "Muse on my laptop".
pub const MAX_LABEL_CHARS: usize = 64;
/// Room for every agent the list can hold, sealed, signed by a passkey.
pub const MAX_LIST_CHARS: usize = 32 * 1024;
/// A sealed note's encapsulated key and its tag, the least a sealed list can be.
const MIN_SEALED_BYTES: usize = 65 + 16;
/// A passkey's user handle, which a page makes as 32 random bytes.
const HANDLE_BYTES: usize = 32;

/// An agent's backup, the private scalar in base64url. It's only ever written into a list that's sealed
/// at once, and has no `Debug` or `Display`, so it can't reach a log or an error by accident.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ListedBackup(String);

impl ListedBackup {
    pub fn of(scalar: &[u8; SCALAR_LEN]) -> Self {
        Self(jws::encode(scalar))
    }

    /// The same, from a backup key held in software, as an owner's computer holds one.
    pub fn of_key(key: &SigningKey) -> Result<Self, Error> {
        Ok(Self::of(&key.scalar()?))
    }

    /// The backup key, which signs a vouch for each later binding, and recovers the agent.
    pub fn key(&self) -> Result<SigningKey, Error> {
        let scalar: [u8; SCALAR_LEN] = jws::decode(&self.0)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        SigningKey::from_scalar(&scalar)
    }
}

/// One of the owner's agents, as they listed it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListedAgent {
    pub agent: SplintId,
    pub address: String,
    pub label: String,
    pub backup: ListedBackup,
    /// Whether this agent's Signet runs on the computer whose sign-in wrote the list, so recovering
    /// after losing that computer brings it back there: 1 if so, 0 if not, on every entry a computer
    /// writes, so the sealed size doesn't say how many. Left out by a page and by older lists.
    #[serde(
        default,
        deserialize_with = "a_digit_if_there",
        skip_serializing_if = "Option::is_none"
    )]
    pub beside_owner: Option<u8>,
}

/// A field that's left out or a number, so a null reads as malformed, as it does on the page.
fn a_digit_if_there<'de, D: serde::Deserializer<'de>>(from: D) -> Result<Option<u8>, D::Error> {
    u8::deserialize(from).map(Some)
}

impl ListedAgent {
    fn check(&self) -> Result<(), Error> {
        let label_fits = !self.label.is_empty()
            && self.label.chars().count() <= MAX_LABEL_CHARS
            && !has_hidden_characters(&self.label);
        if !self.agent.is_well_formed()
            || self.agent.is_guest()
            || canonical_address(&self.address)? != self.address
            || !label_fits
            || self.beside_owner.is_some_and(|beside| beside > 1)
        {
            return Err(Error::Malformed);
        }
        self.backup.key().map(|_| ())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contents {
    v: u8,
    /// The owner's own backup key, whose commitment their ID holds, which the recovery copy is sealed to,
    /// or empty while their recovery code is set later, when that copy is sealed to their reading key.
    backup: String,
    agents: Vec<ListedAgent>,
    /// Whether the owner has said their recovery code is saved, or that they don't want to be told
    /// again, kept here so every device of theirs knows: 1 if so and 0 before, one digit either way so
    /// the sealed size doesn't say which, or left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code_saved: Option<u8>,
}

impl Contents {
    fn check(&self, owner: &Identity) -> Result<(), Error> {
        if self.v != VERSION
            || self.agents.len() > MAX_LISTED_AGENTS
            || self.code_saved.is_some_and(|saved| saved > 1)
        {
            return Err(Error::Malformed);
        }
        // Until the owner sets their recovery code there's no backup, and the list names none.
        if owner.recovery_is_later() {
            if !self.backup.is_empty() {
                return Err(Error::Malformed);
            }
        } else {
            owner.check_backup(&PublicKey::from_encoded(&self.backup)?)?;
        }
        for (index, listed) in self.agents.iter().enumerate() {
            listed.check()?;
            let earlier = self.agents.get(..index).unwrap_or_default();
            if earlier.iter().any(|other| other.agent == listed.agent) {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListPayload {
    v: u8,
    owner: SplintId,
    host: String,
    handle: String,
    seq: u64,
    issued_at: u64,
    agents: String,
    recovery: String,
}

/// What a sealed list is bound to, so it opens only as this owner's list.
fn sealed_about(owner: &SplintId) -> Vec<u8> {
    format!("splint owner agents for {owner}").into_bytes()
}

/// The same for the copy sealed to the owner's backup.
fn recovery_about(owner: &SplintId) -> Vec<u8> {
    format!("splint owner agents for {owner}, for recovery").into_bytes()
}

fn is_sealed_note(text: &str) -> bool {
    jws::decode(text)
        .is_ok_and(|sealed| sealed.len() >= MIN_SEALED_BYTES && jws::encode(&sealed) == text)
}

fn is_handle(text: &str) -> bool {
    text.len() == 2 * HANDLE_BYTES
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// What a computer's sign-in names its list by, which `GET /v0/owner-handles` finds: the lowercase hex
/// SHA-256 of `splint owner list handle v1` then the owner's backup's 65-byte point. Only the recovery
/// code gives that point, as the ID holds only its hash, so a person with nothing but their code finds
/// their list, and nobody else learns it from the ID.
pub fn recovery_handle(backup: &PublicKey) -> String {
    let mut named = b"splint owner list handle v1".to_vec();
    named.extend_from_slice(backup.as_bytes());
    hex(digest::digest(&digest::SHA256, &named).as_ref())
}

/// What an owner signs, `typ` `splint-owner-agents`: every agent, in the order they're shown.
pub struct OwnerAgentsDraft {
    pub agents: Vec<ListedAgent>,
    /// The owner's backup key, which the recovery copy is sealed to.
    pub backup: PublicKey,
    /// The user handle of the owner's passkey, in lowercase hex, by which a new device finds this list.
    pub handle: String,
    /// Higher than the list the host holds, which it replaces.
    pub seq: u64,
    pub now: u64,
    /// Whether the owner has their recovery code: `Some(1)` from a computer, which set it in front of
    /// them, or left out.
    pub code_saved: Option<u8>,
}

impl OwnerAgentsDraft {
    /// The bytes an owner's key signs, the list sealed to their own sealing key and to their backup,
    /// for `host`.
    pub fn payload(&self, owner: &Identity, host: &str) -> Result<Vec<u8>, Error> {
        let contents = Contents {
            v: VERSION,
            backup: self.backup.encoded(),
            agents: self.agents.clone(),
            code_saved: self.code_saved,
        };
        contents.check(owner)?;
        if !is_handle(&self.handle) {
            return Err(Error::Malformed);
        }
        let seal = owner.seal_key().ok_or(Error::Malformed)?;
        let backup = SealPublicKey::from_bytes(self.backup.as_bytes())?;
        let plain = serde_json::to_vec(&contents).map_err(|_| Error::Malformed)?;
        let payload = ListPayload {
            v: VERSION,
            owner: owner.id().clone(),
            host: canonical_domain(host)?,
            handle: self.handle.clone(),
            seq: self.seq,
            issued_at: self.now,
            agents: seal_note(seal, &plain, &sealed_about(owner.id()))?,
            recovery: seal_note(&backup, &plain, &recovery_about(owner.id()))?,
        };
        serde_json::to_vec(&payload).map_err(|_| Error::Malformed)
    }

    /// Signed by an owner's file key.
    pub fn sign(&self, key: &SigningKey, owner: &Identity, host: &str) -> Result<String, Error> {
        let signed = jws::sign(key, LIST_TYPE, &self.payload(owner, host)?)?;
        if signed.len() > MAX_LIST_CHARS {
            return Err(Error::Malformed);
        }
        Ok(signed)
    }
}

/// A list whose owner's signature has been checked, for one host. What's in it is the owner's to open.
pub struct VerifiedOwnerAgents {
    compact: String,
    payload: ListPayload,
}

impl VerifiedOwnerAgents {
    /// Signed by this owner as they are now, naming them and this host, and not dated ahead.
    pub fn verify(compact: &str, owner: &Identity, host: &str, now: u64) -> Result<Self, Error> {
        if compact.len() > MAX_LIST_CHARS {
            return Err(Error::Malformed);
        }
        // Only a link reads a guest's ID, so one handed over as an owner's isn't read.
        if owner.is_guest() {
            return Err(Error::Malformed);
        }
        if owner.is_unconfirmed_owner() {
            return Err(Error::WrongSigner);
        }
        let bytes = owner.verify(compact, LIST_TYPE)?;
        let payload: ListPayload = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        let encoded = serde_json::to_vec(&payload).map_err(|_| Error::Malformed)?;
        // One spelling, so the bytes the owner signed are the only ones kept.
        let sealed_fits = is_sealed_note(&payload.agents) && is_sealed_note(&payload.recovery);
        if payload.v != VERSION || encoded != bytes || !sealed_fits || !is_handle(&payload.handle) {
            return Err(Error::Malformed);
        }
        if &payload.owner != owner.id() {
            return Err(Error::WrongSigner);
        }
        if payload.host != host {
            return Err(Error::ProofMismatch);
        }
        if payload.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        Ok(Self {
            compact: compact.to_owned(),
            payload,
        })
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn seq(&self) -> u64 {
        self.payload.seq
    }

    pub fn handle(&self) -> &str {
        &self.payload.handle
    }

    pub fn issued_at(&self) -> u64 {
        self.payload.issued_at
    }

    /// What the owner listed, opened with their sealing key. Anything not as a page writes it is
    /// refused, as it's shown to the owner.
    pub fn open(&self, key: &SealingKey, owner: &Identity) -> Result<Vec<ListedAgent>, Error> {
        let plain = key.open_note(&self.payload.agents, &sealed_about(&self.payload.owner))?;
        Self::contents(&plain, owner)
    }

    /// The same list from the copy sealed to the owner's backup, for after their passkey is lost.
    pub fn open_for_recovery(
        &self,
        backup: &SigningKey,
        owner: &Identity,
    ) -> Result<Vec<ListedAgent>, Error> {
        let key = SealingKey::from_scalar_of(backup)?;
        let plain = key.open_note(&self.payload.recovery, &recovery_about(&self.payload.owner))?;
        Self::contents(&plain, owner)
    }

    fn contents(plain: &[u8], owner: &Identity) -> Result<Vec<ListedAgent>, Error> {
        let contents: Contents = serde_json::from_slice(plain).map_err(|_| Error::Malformed)?;
        contents.check(owner)?;
        Ok(contents.agents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_code::RecoveryCode;
    use crate::{RecoveryRule, unix_now};

    const HANDLE: &str = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";

    /// The host can't read the list, the owner opens exactly what they listed, and once their sealing
    /// key is gone with their passkey, their recovery code still opens the copy sealed to their backup,
    /// with each agent's backup key in it.
    #[test]
    fn only_the_owner_opens_their_list_and_their_recovery_code_opens_the_copy() {
        let key = SigningKey::generate().unwrap();
        let seal = SealingKey::generate().unwrap();
        let code = RecoveryCode::parse("abcd-efgh-ijkl-mnop-qrst-uvwx-yq").unwrap();
        let backup = code.backup_key().unwrap();
        let owner = Identity::create(
            &key,
            &seal.public_key(),
            RecoveryRule::backup_key(&backup.public_key()),
        )
        .unwrap();
        let agents_backup = SigningKey::generate().unwrap();
        let listed = ListedAgent {
            agent: test_agent_id(),
            address: "muse~host.example".to_owned(),
            label: "Muse".to_owned(),
            backup: ListedBackup::of(&agents_backup.scalar().unwrap()),
            beside_owner: None,
        };
        let now = unix_now();
        let draft = OwnerAgentsDraft {
            agents: vec![listed.clone()],
            backup: backup.public_key(),
            handle: HANDLE.to_owned(),
            seq: 1,
            now,
            code_saved: None,
        };
        let signed = draft.sign(&key, &owner, "host.example").unwrap();
        let list = VerifiedOwnerAgents::verify(&signed, &owner, "host.example", now).unwrap();
        assert!(list.open(&seal, &owner).unwrap() == vec![listed.clone()]);
        let stranger = SealingKey::generate().unwrap();
        assert_eq!(list.open(&stranger, &owner).err(), Some(Error::CantOpen));

        let recovered = list
            .open_for_recovery(
                &RecoveryCode::parse("ABCD EFGH IJKL MNOP QRST UVWX YQ")
                    .unwrap()
                    .backup_key()
                    .unwrap(),
                &owner,
            )
            .unwrap();
        assert!(recovered == vec![listed]);
        let kept = recovered.first().unwrap().backup.key().unwrap();
        assert_eq!(kept.public_key(), agents_backup.public_key());
        let other_code = RecoveryCode::parse("bbcd-efgh-ijkl-mnop-qrst-uvwx-yq").unwrap();
        assert_eq!(
            list.open_for_recovery(&other_code.backup_key().unwrap(), &owner)
                .err(),
            Some(Error::CantOpen)
        );
    }

    fn test_agent_id() -> SplintId {
        crate::test_identity(&SigningKey::generate().unwrap())
            .id()
            .clone()
    }
}

//! The owner's reading key, the sealing key their ID names, which opens what agents seal for them. It
//! belongs to the ID, not to one sign-in: each sign-in keeps its own locked copy, at the owner's host
//! and on its own device. See "The reading key, with many sign-ins" in `docs/protocol.md`.
//!
//! A copy is locked to a key only that sign-in's device can use, and it checks itself: whatever opens
//! counts only if it's the reading key the ID names now. So a host keeping copies can hold one back,
//! but can't read one or swap in its own.

use serde::{Deserialize, Serialize};

use crate::identity::Identity;
use crate::sealing::{SealPublicKey, SealingKey, seal_note};
use crate::{Error, PublicKey, SigningKey, SplintId, jws};

const COPY_VERSION: u8 = 1;
/// Far more than a copy is: its fields, a point, and a 32-byte key sealed with its 65-byte
/// encapsulation and 16-byte tag.
pub const MAX_COPY_CHARS: usize = 1024;
/// A reading key's scalar, which is what a copy seals.
const SCALAR_LEN: usize = 32;
const SEALED_LEN: usize = 65 + SCALAR_LEN + 16;

/// One sign-in's locked copy of an owner's reading key, in its one spelling.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadingKeyCopy {
    v: u8,
    owner: SplintId,
    /// The name of the sign-in it's for, as a key statement names one.
    key: String,
    /// The point it's sealed to, which only that sign-in's device can open.
    lock: String,
    sealed: String,
}

/// What a copy is bound to, so it opens only as this owner's reading key, for this sign-in.
fn about(owner: &SplintId, key: &str) -> Vec<u8> {
    format!("splint reading key for {owner} by {key}").into_bytes()
}

impl ReadingKeyCopy {
    /// Locks `reading` to `lock` for the sign-in named `key`, which has to count now.
    pub fn seal(
        owner: &Identity,
        key: &str,
        lock: &SealPublicKey,
        reading: &SealingKey,
    ) -> Result<String, Error> {
        if owner.seal_key() != Some(&reading.public_key()) {
            return Err(Error::ProofMismatch);
        }
        let copy = Self {
            v: COPY_VERSION,
            owner: owner.id().clone(),
            key: key.to_owned(),
            lock: lock.encoded(),
            sealed: seal_note(lock, &reading.private_bytes(), &about(owner.id(), key))?,
        };
        let text = serde_json::to_string(&copy).map_err(|_| Error::Malformed)?;
        Self::read(&text, owner)?;
        Ok(text)
    }

    /// A copy in its one spelling, for this owner and a sign-in that counts now. That's all a host can
    /// check: what's inside is sealed.
    pub fn read(text: &str, owner: &Identity) -> Result<Self, Error> {
        if text.len() > MAX_COPY_CHARS {
            return Err(Error::Malformed);
        }
        let copy: Self = serde_json::from_str(text).map_err(|_| Error::Malformed)?;
        let sealed_len = jws::decode(&copy.sealed).map(|sealed| sealed.len());
        if copy.v != COPY_VERSION
            || serde_json::to_string(&copy).map_err(|_| Error::Malformed)? != text
            || sealed_len != Ok(SEALED_LEN)
            || !copy.owner.is_well_formed()
            || !crate::identity::is_sha256_hex(&copy.key)
        {
            return Err(Error::Malformed);
        }
        SealPublicKey::from_encoded(&copy.lock)?;
        if &copy.owner != owner.id() {
            return Err(Error::ProofMismatch);
        }
        if !owner
            .keys()
            .iter()
            .any(|counting| counting.name() == copy.key)
        {
            return Err(Error::WrongSigner);
        }
        Ok(copy)
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    /// The reading key, opened with the sign-in's lock, and only if it's the one the ID names now.
    pub fn open(&self, lock: &SealingKey, owner: &Identity) -> Result<SealingKey, Error> {
        if lock.public_key().encoded() != self.lock {
            return Err(Error::WrongSigner);
        }
        let scalar = lock.open_note(&self.sealed, &about(&self.owner, &self.key))?;
        let reading = SealingKey::from_scalar_bytes(&scalar)?;
        if owner.seal_key() != Some(&reading.public_key()) {
            return Err(Error::ProofMismatch);
        }
        Ok(reading)
    }
}

const LOCK_TYPE: &str = "splint-sign-in-lock";
const LOCK_VERSION: u8 = 1;

/// A new sign-in's lock, signed by that sign-in's own key as it offers itself, so whoever carries the
/// offer to a computer that counts can't swap in a lock of their own and be sealed the reading key.
/// Only `owner-key` makes and reads one. Provisional, for Nenye to overturn.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockPayload {
    v: u8,
    owner: SplintId,
    key: String,
    lock: String,
}

/// Signs `lock` as the one this new sign-in, `key`, opens its copy with, for this owner.
pub fn sign_lock(
    key: &SigningKey,
    owner: &SplintId,
    lock: &SealPublicKey,
) -> Result<String, Error> {
    let payload = LockPayload {
        v: LOCK_VERSION,
        owner: owner.clone(),
        key: crate::OwnerKey::name_of(&key.public_key()),
        lock: lock.encoded(),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| Error::Malformed)?;
    jws::sign(key, LOCK_TYPE, &bytes)
}

/// The lock a sign-in signed for this owner, checked under the key it offers: in its one spelling,
/// for this owner, and naming that key.
pub fn verified_lock(
    signed: &str,
    key: &PublicKey,
    owner: &SplintId,
) -> Result<SealPublicKey, Error> {
    let bytes = jws::verify(signed, key, LOCK_TYPE)?;
    let payload: LockPayload = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
    if serde_json::to_vec(&payload).map_err(|_| Error::Malformed)? != bytes
        || payload.v != LOCK_VERSION
    {
        return Err(Error::Malformed);
    }
    if &payload.owner != owner || payload.key != crate::OwnerKey::name_of(key) {
        return Err(Error::WrongSigner);
    }
    SealPublicKey::from_encoded(&payload.lock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RecoveryRule, SigningKey};

    /// A host keeping copies can't swap in a key of its own: a copy that opens to anything but the
    /// reading key the ID names is refused, however well it's locked.
    #[test]
    fn a_copy_opens_only_to_the_reading_key_the_id_names() {
        let key = SigningKey::generate().unwrap();
        let reading = SealingKey::generate().unwrap();
        let later = RecoveryRule::later(&key.public_key());
        let owner = Identity::create(&key, &reading.public_key(), later).unwrap();
        let name = owner.keys()[0].name();
        let lock = SealingKey::generate().unwrap();
        let copy = ReadingKeyCopy::seal(&owner, &name, &lock.public_key(), &reading).unwrap();
        let read = ReadingKeyCopy::read(&copy, &owner).unwrap();
        let opened = read.open(&lock, &owner).unwrap();
        assert_eq!(opened.public_key(), reading.public_key());
        // A device holding a reading key the ID no longer names, as after a recovery elsewhere, doesn't
        // hand its host a copy no sign-in could use.
        let stale = SealingKey::generate().unwrap();
        assert_eq!(
            ReadingKeyCopy::seal(&owner, &name, &lock.public_key(), &stale).err(),
            Some(Error::ProofMismatch)
        );
        // A host knows the owner, the sign-in's name and the lock's point, so it can lock a key of its
        // own the same way.
        let hosts = SealingKey::generate().unwrap();
        let theirs = serde_json::to_string(&ReadingKeyCopy {
            v: COPY_VERSION,
            owner: owner.id().clone(),
            key: name.clone(),
            lock: lock.public_key().encoded(),
            sealed: seal_note(
                &lock.public_key(),
                &hosts.private_bytes(),
                &about(owner.id(), &name),
            )
            .unwrap(),
        })
        .unwrap();
        let read = ReadingKeyCopy::read(&theirs, &owner).unwrap();
        assert_eq!(read.open(&lock, &owner).err(), Some(Error::ProofMismatch));
        // Nor is a copy for another owner taken.
        let stranger = SigningKey::generate().unwrap();
        let rule = RecoveryRule::later(&stranger.public_key());
        let other = Identity::create(&stranger, &reading.public_key(), rule).unwrap();
        assert_eq!(
            ReadingKeyCopy::read(&copy, &other).err(),
            Some(Error::ProofMismatch)
        );
    }

    /// Bug caught: a lock taken as a new sign-in's when another key signed it, though it names that
    /// sign-in, or when it's for another owner.
    #[test]
    fn a_lock_counts_only_signed_by_the_sign_in_it_names() {
        let offered = SigningKey::generate().unwrap();
        let carrier = SigningKey::generate().unwrap();
        let owner = crate::test_identity(&SigningKey::generate().unwrap());
        let lock = SealingKey::generate().unwrap().public_key();
        let signed = sign_lock(&offered, owner.id(), &lock).unwrap();
        assert_eq!(
            verified_lock(&signed, &offered.public_key(), owner.id()).unwrap(),
            lock
        );
        let forged = serde_json::to_vec(&LockPayload {
            v: LOCK_VERSION,
            owner: owner.id().clone(),
            key: crate::OwnerKey::name_of(&offered.public_key()),
            lock: lock.encoded(),
        })
        .unwrap();
        let forged = jws::sign(&carrier, LOCK_TYPE, &forged).unwrap();
        assert!(verified_lock(&forged, &offered.public_key(), owner.id()).is_err());
        let elsewhere = crate::test_identity(&SigningKey::generate().unwrap());
        assert!(verified_lock(&signed, &offered.public_key(), elsewhere.id()).is_err());
    }
}

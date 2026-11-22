//! A host's ID, and the statement that ties it to the host's name.
//!
//! A host's ID is the one kind every ID is, committed to a recovery rule, so its key can change and
//! hosts that pinned it follow by themselves: a key that counts names the next one, or the backup a
//! recovery code makes does. The ID's event needs a sealing key, and nothing is ever sealed to a host,
//! so a host's is a fresh point nobody holds.
//!
//! An ID's event isn't signed, so anyone could make one naming a host's public key under a rule whose
//! backup they hold. `splint-host-id`, signed by the one key that counts now, is that host saying
//! which ID is its own, at which name. See "Host IDs" in docs/protocol.md.

use serde::{Deserialize, Serialize};

use crate::{Error, Identity, PublicKey, SigningKey, SplintId, jws};

const HOST_ID_TYPE: &str = "splint-host-id";
const HOST_ID_VERSION: u8 = 1;

/// No date: it's a binding, not an event, so showing it again says nothing new.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostIdPayload {
    v: u8,
    domain: String,
    id: SplintId,
}

/// The one key a host's ID counts now, as a host's is always a file key that signs ES256.
fn sole_file_key(identity: &Identity) -> Result<&PublicKey, Error> {
    let key = identity.sole_key()?;
    if identity.passkey_rp().is_some() {
        return Err(Error::WrongSigner);
    }
    Ok(key)
}

/// `identity` is this host's, at `domain`, signed by the key it counts now, which `key` has to be.
pub fn sign(key: &SigningKey, domain: &str, identity: &Identity) -> Result<String, Error> {
    if sole_file_key(identity)? != &key.public_key() {
        return Err(Error::WrongSigner);
    }
    let payload = serde_json::to_vec(&HostIdPayload {
        v: HOST_ID_VERSION,
        domain: domain.to_owned(),
        id: identity.id().clone(),
    })
    .map_err(|_| Error::Malformed)?;
    jws::sign(key, HOST_ID_TYPE, &payload)
}

/// What a host's page says it is, checked: an ID whose one key is the page's key, and that key's
/// statement that the ID is the host at this name. It's made only by [`Self::verify`].
pub struct PublishedHost {
    key: PublicKey,
    identity: Identity,
}

impl PublishedHost {
    /// Checks a page fetched from `domain`: its `key`, its encoded `identity` and the
    /// `splint-host-id` statement beside them. A proof by a key the ID no longer counts, or naming
    /// another name or another ID, is refused, so nobody can serve one host's ID as another's.
    pub fn verify(
        domain: &str,
        key: &PublicKey,
        identity: &str,
        proof: &str,
    ) -> Result<Self, Error> {
        let identity = Identity::from_encoded(identity)?;
        if sole_file_key(&identity)? != key {
            return Err(Error::ProofMismatch);
        }
        let payload = jws::verify(proof, key, HOST_ID_TYPE)?;
        let payload: HostIdPayload =
            serde_json::from_slice(&payload).map_err(|_| Error::Malformed)?;
        if payload.v != HOST_ID_VERSION {
            return Err(Error::Malformed);
        }
        if payload.domain != domain || &payload.id != identity.id() {
            return Err(Error::ProofMismatch);
        }
        Ok(Self {
            key: key.clone(),
            identity,
        })
    }

    pub const fn key(&self) -> &PublicKey {
        &self.key
    }

    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Whether a host that pinned `held` takes this in its place: the same ID, moved on by a key that
    /// counted, or by the backup. An older copy, or a rival with no recovery since they part ways,
    /// is refused, so whoever serves the name for a while can't move it anywhere.
    pub fn follows(&self, held: &Identity) -> bool {
        self.identity.replaces(held) == Ok(true)
    }

    /// The same for a pin made before the host had an ID, which holds only its key: this is that key's
    /// ID, or one whose history that key began.
    pub fn follows_bare(&self, held: &PublicKey) -> bool {
        &self.key == held || self.identity.rooted_in(held)
    }
}

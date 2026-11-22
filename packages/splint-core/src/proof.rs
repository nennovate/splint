use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::{
    CLOCK_TOLERANCE_SECS, Error, Identity, MessageId, PublicKey, SigningKey, SplintId, jws,
};

const DELIVERY_TYPE: &str = "splint-delivery";
pub(crate) const ACCESS_TYPE: &str = "splint-access";

pub(crate) fn check_fresh(issued_at: u64, now: u64) -> Result<(), Error> {
    if issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
        return Err(Error::FromTheFuture);
    }
    if now > issued_at.saturating_add(CLOCK_TOLERANCE_SECS) {
        return Err(Error::Expired);
    }
    Ok(())
}

/// A sending host's signature on one delivery, bound to the message and the receiving host.
/// It proves which host relayed a message. It doesn't let a host speak for an agent.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryProof {
    message: MessageId,
    from_host: String,
    to_host: String,
    issued_at: u64,
}

impl DeliveryProof {
    pub fn sign(
        key: &SigningKey,
        message: &MessageId,
        from_host: &str,
        to_host: &str,
        now: u64,
    ) -> Result<String, Error> {
        let proof = serde_json::to_vec(&Self {
            message: message.clone(),
            from_host: from_host.to_owned(),
            to_host: to_host.to_owned(),
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)?;
        jws::sign(key, DELIVERY_TYPE, &proof)
    }

    pub fn verify(
        compact: &str,
        key: &PublicKey,
        message: &MessageId,
        from_host: &str,
        to_host: &str,
        now: u64,
    ) -> Result<(), Error> {
        check_fresh(
            Self::signed_for(compact, key, message, from_host, to_host)?,
            now,
        )
    }

    /// Whether this host signed for this message on this route, however long ago. It's for a reader
    /// who can't see the delivery happen, so a message waiting on its host isn't refused for waiting.
    /// Says when it was signed.
    pub fn signed_for(
        compact: &str,
        key: &PublicKey,
        message: &MessageId,
        from_host: &str,
        to_host: &str,
    ) -> Result<u64, Error> {
        let bytes = jws::verify(compact, key, DELIVERY_TYPE)?;
        let proof: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        if &proof.message != message || proof.from_host != from_host || proof.to_host != to_host {
            return Err(Error::ProofMismatch);
        }
        Ok(proof.issued_at)
    }
}

/// An agent's signature on one request to its host, covering the body as well as the path, so a
/// captured proof can't be reused to do something else.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessProof {
    signer: SplintId,
    host: String,
    method: String,
    path: String,
    body_sha256: String,
    issued_at: u64,
}

pub(crate) fn body_digest(body: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, body).as_ref())
}

impl AccessProof {
    pub fn sign(
        key: &SigningKey,
        agent: &SplintId,
        host: &str,
        method: &str,
        path: &str,
        body: &[u8],
        now: u64,
    ) -> Result<String, Error> {
        let proof = serde_json::to_vec(&Self {
            signer: agent.clone(),
            host: host.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            body_sha256: body_digest(body),
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)?;
        jws::sign(key, ACCESS_TYPE, &proof)
    }

    pub fn verify(
        compact: &str,
        identity: &Identity,
        host: &str,
        method: &str,
        path: &str,
        body: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        let bytes = identity.verify(compact, ACCESS_TYPE)?;
        let proof: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        if &proof.signer != identity.id()
            || proof.host != host
            || proof.method != method
            || proof.path != path
            || proof.body_sha256 != body_digest(body)
        {
            return Err(Error::ProofMismatch);
        }
        check_fresh(proof.issued_at, now)
    }
}

/// Whether one of an owner's keys that count now signed what let owner mail in at a host: a session,
/// or an access proof, which is no owner object, so `signed_now` alone says no to it. It's only for
/// going back over what was checked in full when it was let in, once a key stopped counting, to drop
/// what that key left. It never lets anything in.
pub fn signed_by_owner_now(owner: &Identity, by_owner: &str) -> bool {
    owner.signed_now(by_owner) || owner.verify(by_owner, ACCESS_TYPE).is_ok()
}

/// Which agent a proof says it's from, before verification. Use this only to look up the
/// identity to verify against.
pub fn claimed_agent(compact: &str) -> Result<SplintId, Error> {
    let payload = jws::unverified_payload(compact, ACCESS_TYPE)?;
    let proof: AccessProof = serde_json::from_slice(&payload).map_err(|_| Error::Malformed)?;
    Ok(proof.signer)
}

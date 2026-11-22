//! An owner's session: a key their page holds for up to 12 hours, which reads what their agents left
//! for them, and opens pairing mailboxes, without a touch for each. See "Owner API" in
//! `docs/protocol.md`.
//!
//! An owner signs a `splint-owner-session` naming the key and the one host it's for. Each read then
//! carries the session and a proof the session key signed for that one call. A session reads, opens a
//! pairing mailbox, and leaves owner mail at its host, sealed to an agent, which gives nobody
//! anything: mail only takes up the owner's room there, and nothing in it counts until the agent's
//! Signet finds the owner's own signature inside. It signs `splint-owner-access` and `splint-pairing`
//! and nothing else, ES256 under a bare key, so nothing an owner's key signs can be made with it.
//! Binding, rules, approvals, grants and delegations each stay an object the owner signs, checked under
//! their own key, so a host or a Signet never takes a session key as the owner.

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::proof::{body_digest, check_fresh};
use crate::{
    AccessProof, CLOCK_TOLERANCE_SECS, Error, Identity, PublicKey, SigningKey, SplintId, jws,
};

pub(crate) const SESSION_TYPE: &str = "splint-owner-session";
const ACCESS_TYPE: &str = "splint-owner-access";
const VERSION: u8 = 1;
/// A working day. A page asks for a touch again after this, so a key left in a browser stops reading.
pub const MAX_SESSION_SECS: u64 = 12 * 60 * 60;
/// A passkey's signature and a few fields, with room to spare, so a header holding one stays small.
pub const MAX_SESSION_CHARS: usize = 4096;
/// The header a read carries its session in, beside `Authorization: Splint <proof>`.
pub const SESSION_HEADER: &str = "splint-owner-session";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionPayload {
    v: u8,
    owner: SplintId,
    key: String,
    host: String,
    issued_at: u64,
    expires_at: u64,
}

/// A session whose owner's signature has been checked, for one host, in date.
pub struct VerifiedOwnerSession {
    name: String,
    owner: SplintId,
    key: PublicKey,
    expires_at: u64,
}

impl VerifiedOwnerSession {
    /// Signed by this owner as they are now, naming them and this host, lasting at most 12 hours, and
    /// not over. An owner who hasn't confirmed has a key on their agent's machine, so they have none.
    pub fn verify(compact: &str, owner: &Identity, host: &str, now: u64) -> Result<Self, Error> {
        if compact.len() > MAX_SESSION_CHARS {
            return Err(Error::Malformed);
        }
        // Only a link reads a guest's ID, so one handed over as an owner's isn't read.
        if owner.is_guest() {
            return Err(Error::Malformed);
        }
        if owner.is_unconfirmed_owner() {
            return Err(Error::WrongSigner);
        }
        let bytes = owner.verify(compact, SESSION_TYPE)?;
        let payload: SessionPayload =
            serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        let lasts = payload.expires_at.checked_sub(payload.issued_at);
        let encoded = serde_json::to_vec(&payload).map_err(|_| Error::Malformed)?;
        if payload.v != VERSION
            || !lasts.is_some_and(|lasts| lasts > 0 && lasts <= MAX_SESSION_SECS)
            || encoded != bytes
        {
            return Err(Error::Malformed);
        }
        let key = PublicKey::from_encoded(&payload.key)?;
        if &payload.owner != owner.id() {
            return Err(Error::WrongSigner);
        }
        if payload.host != host {
            return Err(Error::ProofMismatch);
        }
        if payload.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        if now >= payload.expires_at {
            return Err(Error::Expired);
        }
        Ok(Self {
            name: name_of(compact)?,
            owner: payload.owner,
            key,
            expires_at: payload.expires_at,
        })
    }

    pub fn owner(&self) -> &SplintId {
        &self.owner
    }

    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// A session's name in a proof: the hex SHA-256 of its signing input, which every spelling of its
/// signature shares.
fn name_of(compact: &str) -> Result<String, Error> {
    let (signing_input, _) = compact.rsplit_once('.').ok_or(Error::Malformed)?;
    Ok(hex(digest::digest(
        &digest::SHA256,
        signing_input.as_bytes(),
    )
    .as_ref()))
}

/// A session for the key `key` at `host`, as an ES256 signing input for the owner's own sign-in to
/// sign, such as Splint on their computer prepares and keeps the key of while the session lasts.
pub fn session_input(
    owner: &SplintId,
    key: &PublicKey,
    host: &str,
    issued_at: u64,
    lasts: u64,
) -> Result<String, Error> {
    if lasts == 0 || lasts > MAX_SESSION_SECS {
        return Err(Error::Malformed);
    }
    let payload = SessionPayload {
        v: VERSION,
        owner: owner.clone(),
        key: key.encoded(),
        host: host.to_owned(),
        issued_at,
        expires_at: issued_at.saturating_add(lasts),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| Error::Malformed)?;
    jws::signing_input(jws::Alg::Es256, SESSION_TYPE, &bytes)
}

/// A session the owner signed, read for what its keeper needs: its name in a proof, and when it ends.
pub fn session_name_and_end(
    compact: &str,
    owner: &Identity,
    host: &str,
    now: u64,
) -> Result<(String, u64), Error> {
    let session = VerifiedOwnerSession::verify(compact, owner, host, now)?;
    Ok((session.name, session.expires_at))
}

/// The session key's proof for one call, as a page makes it, so whatever keeps a session reads with it.
pub fn session_proof(
    session_key: &SigningKey,
    session_name: &str,
    call: &ReadCall<'_>,
) -> Result<String, Error> {
    let access = OwnerAccess {
        session: session_name.to_owned(),
        host: call.host.to_owned(),
        method: call.method.to_owned(),
        path: call.path.to_owned(),
        body_sha256: body_digest(call.body),
        issued_at: call.now,
    };
    let bytes = serde_json::to_vec(&access).map_err(|_| Error::Malformed)?;
    jws::sign(session_key, ACCESS_TYPE, &bytes)
}

/// The session key's signature on one call, as an agent's access proof is, naming the session it's
/// under in place of a signer.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerAccess {
    session: String,
    host: String,
    method: String,
    path: String,
    body_sha256: String,
    issued_at: u64,
}

/// One call to this host for one call only.
pub struct ReadCall<'a> {
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    pub now: u64,
}

/// That this call is the owner's, by a live session or their own key. Owner reads take only this. What
/// writes takes it only for room at a host, as for sealed owner mail, never as the owner's signature
/// on what's written, so a session can't be made to stand for that signature.
#[derive(Debug)]
pub struct OwnerReader {
    owner: SplintId,
}

impl OwnerReader {
    /// By a session this owner signed for this host, and its key's proof for exactly this call.
    pub fn by_session(
        session: &str,
        proof: &str,
        owner: &Identity,
        call: &ReadCall<'_>,
    ) -> Result<Self, Error> {
        let session = VerifiedOwnerSession::verify(session, owner, call.host, call.now)?;
        let bytes = jws::verify(proof, session.key(), ACCESS_TYPE)?;
        let access: OwnerAccess = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        if access.session != session.name
            || access.host != call.host
            || access.method != call.method
            || access.path != call.path
            || access.body_sha256 != body_digest(call.body)
        {
            return Err(Error::ProofMismatch);
        }
        check_fresh(access.issued_at, call.now)?;
        Ok(Self {
            owner: session.owner,
        })
    }

    /// By an access proof the owner's own file key signed, as `splint` on their device makes. A
    /// passkey signs no access proofs, so it reads by a session.
    pub fn by_owner_key(proof: &str, owner: &Identity, call: &ReadCall<'_>) -> Result<Self, Error> {
        AccessProof::verify(
            proof,
            owner,
            call.host,
            call.method,
            call.path,
            call.body,
            call.now,
        )?;
        Ok(Self {
            owner: owner.id().clone(),
        })
    }

    pub fn owner(&self) -> &SplintId {
        &self.owner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prepared::Prepared;

    const NOW: u64 = 1_793_750_400;

    /// Bug caught: a session Splint on a computer prepares, or the proof it reads with, in a spelling
    /// no host takes, so the person's controls there read nothing.
    #[test]
    fn a_session_prepared_for_an_owners_sign_in_reads_at_its_host() {
        let owner_key = SigningKey::generate().unwrap();
        let owner = crate::test_identity(&owner_key);
        let session_key = SigningKey::generate().unwrap();
        let input = session_input(
            owner.id(),
            &session_key.public_key(),
            "host.example",
            NOW,
            3600,
        )
        .unwrap();
        let session = Prepared::read(&input).unwrap().sign(&owner_key).unwrap();
        let (name, ends) = session_name_and_end(&session, &owner, "host.example", NOW).unwrap();
        assert_eq!(ends, NOW + 3600);
        let call = ReadCall {
            host: "host.example",
            method: "GET",
            path: "/v0/owner-agents/x",
            body: b"",
            now: NOW + 5,
        };
        let proof = session_proof(&session_key, &name, &call).unwrap();
        let reader = OwnerReader::by_session(&session, &proof, &owner, &call).unwrap();
        assert_eq!(reader.owner(), owner.id());
        let elsewhere = ReadCall {
            host: "other.example",
            ..call
        };
        assert!(OwnerReader::by_session(&session, &proof, &owner, &elsewhere).is_err());
    }
}

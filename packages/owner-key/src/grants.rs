//! Gate 5 from the owner's side: signing grants and revocations, and the check a resource runs.
//!
//! A resource in any language can run `owner-key check-grant` for each call, with the owner's public
//! identity from its own config. It needs no owner key, so it can run where the key isn't. The record
//! of revocations and use is a file the resource names, read and written under a lock, so two calls
//! at once can't both take the last call of an hour.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use splint_core::grants::{
    Call, GrantDraft, GrantId, GrantLimits, Ledger, Refusal, SignedGrant, VerifiedRevocation,
};
use splint_core::{Error, Identity, SplintId, unix_now};

use crate::device::Device;

pub fn sign(
    device: &Device,
    holder: SplintId,
    resource: String,
    operations: Vec<String>,
    calls_per_hour: u32,
    life_secs: u64,
) -> Result<SignedGrant, Error> {
    GrantDraft {
        holder,
        resource,
        operations,
        limits: GrantLimits { calls_per_hour },
        life_secs,
    }
    .sign(&device.key, device.identity.id(), unix_now())
}

pub fn revoke(device: &Device, grant: &GrantId) -> Result<String, Error> {
    VerifiedRevocation::sign(&device.key, device.identity.id(), grant, unix_now())
}

/// One call as the resource received it. The body is the exact bytes the proof covers, as text.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInput {
    grant: String,
    identity: String,
    proof: String,
    operation: String,
    method: String,
    path: String,
    body: String,
}

/// What the resource gets back. A refusal is one fixed word.
#[derive(Serialize)]
#[serde(untagged)]
pub enum Verdict {
    Granted {
        ok: bool,
        grant: GrantId,
        holder: SplintId,
        operation: String,
    },
    Refused {
        ok: bool,
        reason: Refusal,
    },
}

impl Verdict {
    pub fn granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// A record that can't be read could be hiding a revocation, so nothing passes until it's fixed.
    #[error("the grant record can't be read, so nothing is granted")]
    Unreadable,
    #[error("couldn't write the grant record")]
    Io(#[from] io::Error),
}

/// The record, held under its lock for as long as this lives.
struct Held {
    path: PathBuf,
    _lock: File,
    ledger: Ledger,
}

impl Held {
    fn open(path: &Path) -> Result<Self, LedgerError> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path.with_extension("lock"))?;
        lock.lock()?;
        let ledger = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| LedgerError::Unreadable)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ledger::default(),
            Err(_) => return Err(LedgerError::Unreadable),
        };
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
            ledger,
        })
    }

    /// Written whole to a new file and moved into place, so a crash leaves the old record or the new.
    fn save(&self) -> Result<(), LedgerError> {
        let bytes = serde_json::to_vec(&self.ledger).map_err(|_| LedgerError::Unreadable)?;
        let next = self.path.with_extension("next");
        // Synced through the handle that wrote it, as Windows won't flush a file opened only to read.
        let mut file = File::create(&next)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&next, &self.path)?;
        Ok(())
    }
}

/// Checks one call and counts it. The count is saved before the answer is given, so a call that
/// passed is never forgotten by a crash.
pub fn check(
    owner: &Identity,
    resource: &str,
    record: &Path,
    input: &CallInput,
) -> Result<Verdict, LedgerError> {
    let mut held = Held::open(record)?;
    let call = Call {
        identity: &input.identity,
        proof: &input.proof,
        resource,
        operation: &input.operation,
        method: &input.method,
        path: &input.path,
        body: input.body.as_bytes(),
        now: unix_now(),
    };
    let verdict = match held.ledger.check(&input.grant, owner, &call) {
        Ok(granted) => Verdict::Granted {
            ok: true,
            grant: granted.grant().clone(),
            holder: granted.holder().clone(),
            operation: granted.operation().to_owned(),
        },
        Err(reason) => Verdict::Refused { ok: false, reason },
    };
    // A newer copy of a holder's ID counts once it's been seen, whatever the call that brought it.
    if verdict.granted() || held.ledger.heard_a_new_copy() {
        held.save()?;
    }
    Ok(verdict)
}

/// Takes a newer copy of an ID from anyone, since only a backup key can make one. This is how a resource
/// hears at once that a key it would go on taking has been replaced.
pub fn record_identity(
    record: &Path,
    copy: &Identity,
) -> Result<Result<bool, Refusal>, LedgerError> {
    let mut held = Held::open(record)?;
    let learned = held.ledger.learn_copy(copy);
    if learned == Ok(true) {
        held.save()?;
    }
    Ok(learned)
}

/// Takes a revocation from anyone, since the owner's signature is what counts.
pub fn record_revocation(
    owner: &Identity,
    record: &Path,
    revocation: &str,
) -> Result<Result<GrantId, Refusal>, LedgerError> {
    let mut held = Held::open(record)?;
    let owner = held.ledger.newest_owner(owner);
    let verified = match VerifiedRevocation::verify(revocation, &owner) {
        Ok(verified) => verified,
        Err(refusal) => return Ok(Err(refusal)),
    };
    held.ledger.revoke(&verified, unix_now());
    held.save()?;
    Ok(Ok(verified.grant().clone()))
}

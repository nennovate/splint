//! Gate 5: a grant record, and the check any resource calls before it acts. See `docs/protocol.md`.
//!
//! A resource is whatever the owner's side controls, such as a tool, an API or data. Splint doesn't
//! know what any operation means: it checks that the owner signed this holder this operation at this
//! resource, that the caller holds the holder's key, and that the grant is in date, unrevoked and
//! under its rate. What the operation then does, and any limit inside it, is the resource's job.
//!
//! A grant is signed by the owner key alone, so neither a host nor an agent can make or widen one.
//! It isn't a secret: without the holder's key to sign a proof for each call, it's useless.
//!
//! [`Granted`] is the only thing that says a call passed, and only [`VerifiedGrant::check_call`]
//! makes one, so code that acts without the check won't compile:
//!
//! ```compile_fail
//! # use splint_core::SplintId;
//! # use splint_core::grants::{GrantId, Granted};
//! fn forged(grant: GrantId, holder: SplintId) -> Granted {
//!     Granted { grant, holder, operation: String::new() }
//! }
//! ```
//!
//! And one check buys one action, so a passed call can't be kept and used again:
//!
//! ```compile_fail
//! # use splint_core::grants::Granted;
//! fn twice(granted: &Granted) -> Granted {
//!     granted.clone()
//! }
//! ```

use std::collections::BTreeMap;

use aws_lc_rs::digest;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::{AccessProof, CLOCK_TOLERANCE_SECS, Error, Identity, SigningKey, SplintId, jws};

const GRANT_TYPE: &str = "splint-grant";
const REVOCATION_TYPE: &str = "splint-grant-revocation";
const FORMAT_VERSION: u8 = 1;
const HOUR_SECS: u64 = 60 * 60;
const DAY_SECS: u64 = 24 * HOUR_SECS;
const MAX_RESOURCE_LEN: usize = 253;
const MAX_OPERATION_LEN: usize = 64;
const MAX_OPERATIONS: usize = 16;
const GRANT_ID_HEX_LEN: usize = 64;
const NONCE_BYTES: usize = 16;
pub const MAX_CALLS_PER_HOUR: u32 = 1000;
pub const DEFAULT_GRANT_LIFE_SECS: u64 = 7 * DAY_SECS;
pub const MAX_GRANT_LIFE_SECS: u64 = 30 * DAY_SECS;
/// The proof sits in `Authorization: Splint <proof>`, as on a call to a host. These carry the rest.
pub const GRANT_HEADER: &str = "splint-grant";
pub const IDENTITY_HEADER: &str = "splint-identity";

/// Why a resource said no. This is the whole set, as fixed words, so a refusal carries nothing of
/// the resource or of what was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    #[error("no_grant")]
    NoGrant,
    #[error("malformed")]
    Malformed,
    #[error("bad_signature")]
    BadSignature,
    #[error("expired")]
    Expired,
    #[error("revoked")]
    Revoked,
    #[error("wrong_holder")]
    WrongHolder,
    #[error("wrong_resource")]
    WrongResource,
    #[error("bad_proof")]
    BadProof,
    #[error("over_rate")]
    OverRate,
}

impl From<Error> for Refusal {
    fn from(error: Error) -> Self {
        match error {
            Error::BadSignature => Self::BadSignature,
            _ => Self::Malformed,
        }
    }
}

/// The hex SHA-256 of a grant's payload bytes, which is what a revocation names. Re-signing the same
/// words gives the same ID, and any change gives another.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantId(String);

impl GrantId {
    fn of(payload: &[u8]) -> Self {
        Self(hex(digest::digest(&digest::SHA256, payload).as_ref()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_well_formed(&self) -> bool {
        self.0.len() == GRANT_ID_HEX_LEN
            && self
                .0
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }
}

impl std::fmt::Display for GrantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for GrantId {
    type Error = Error;

    fn try_from(text: String) -> Result<Self, Error> {
        let id = Self(text);
        if id.is_well_formed() {
            Ok(id)
        } else {
            Err(Error::Malformed)
        }
    }
}

/// A resource is named like a host, which is what an access proof's `host` field holds.
fn is_valid_resource(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_RESOURCE_LEN
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
}

/// An operation is a word the resource chose, such as `docs.read`. Splint gives it no meaning.
fn is_valid_operation(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_OPERATION_LEN
        && name
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.'))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantLimits {
    pub calls_per_hour: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantPayload {
    v: u8,
    owner: SplintId,
    holder: SplintId,
    resource: String,
    operations: Vec<String>,
    limits: GrantLimits,
    issued_at: u64,
    expires_at: u64,
    /// So two grants an owner signs alike in one second are still two, and revoking one leaves the
    /// other.
    nonce: String,
}

impl GrantPayload {
    fn is_sound(&self) -> bool {
        let mut sorted = self.operations.clone();
        sorted.sort();
        sorted.dedup();
        self.v == FORMAT_VERSION
            && is_valid_resource(&self.resource)
            && !self.operations.is_empty()
            && self.operations.len() <= MAX_OPERATIONS
            && self.operations.iter().all(|name| is_valid_operation(name))
            // Sorted with no repeats, so one set of operations has one encoding and one ID.
            && sorted == self.operations
            && (1..=MAX_CALLS_PER_HOUR).contains(&self.limits.calls_per_hour)
            && self.expires_at > self.issued_at
            && self.expires_at - self.issued_at <= MAX_GRANT_LIFE_SECS
            && jws::decode(&self.nonce).is_ok_and(|bytes| bytes.len() == NONCE_BYTES)
    }
}

fn random_nonce() -> Result<String, Error> {
    let mut bytes = [0_u8; NONCE_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Crypto)?;
    Ok(jws::encode(&bytes))
}

/// What an owner decides. The owner's device adds the dates and a nonce.
pub struct GrantDraft {
    pub holder: SplintId,
    pub resource: String,
    pub operations: Vec<String>,
    pub limits: GrantLimits,
    pub life_secs: u64,
}

/// A signed grant, and the ID to revoke it by.
#[derive(Debug, Serialize)]
pub struct SignedGrant {
    pub id: GrantId,
    pub grant: String,
}

impl GrantDraft {
    /// Refuses here what a resource would refuse later, so an owner finds out on their own device.
    pub fn sign(&self, key: &SigningKey, owner: &SplintId, now: u64) -> Result<SignedGrant, Error> {
        let mut operations = self.operations.clone();
        operations.sort();
        operations.dedup();
        let payload = GrantPayload {
            v: FORMAT_VERSION,
            owner: owner.clone(),
            holder: self.holder.clone(),
            resource: self.resource.clone(),
            operations,
            limits: self.limits,
            issued_at: now,
            expires_at: now.saturating_add(self.life_secs),
            nonce: random_nonce()?,
        };
        if !payload.is_sound() || &payload.holder == owner {
            return Err(Error::Malformed);
        }
        let bytes = serde_json::to_vec(&payload).map_err(|_| Error::Malformed)?;
        Ok(SignedGrant {
            id: GrantId::of(&bytes),
            grant: jws::sign(key, GRANT_TYPE, &bytes)?,
        })
    }
}

/// A grant whose signature is the owner's newest key. Nothing here says the caller is its holder, or
/// that it's still in force: [`Self::check_call`] does that.
#[derive(Debug)]
pub struct VerifiedGrant {
    id: GrantId,
    payload: GrantPayload,
}

impl VerifiedGrant {
    /// `owner` comes from the resource's own config, never from the caller or a host. A grant the
    /// owner's old key signed stops counting after a recovery, like anything else it signed.
    pub fn verify(compact: &str, owner: &Identity, now: u64) -> Result<Self, Refusal> {
        let bytes = owner.verify(compact, GRANT_TYPE)?;
        let payload: GrantPayload =
            serde_json::from_slice(&bytes).map_err(|_| Refusal::Malformed)?;
        if !payload.is_sound() {
            return Err(Refusal::Malformed);
        }
        if &payload.owner != owner.id()
            || payload.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS)
        {
            return Err(Refusal::NoGrant);
        }
        Ok(Self {
            id: GrantId::of(&bytes),
            payload,
        })
    }

    pub fn id(&self) -> &GrantId {
        &self.id
    }

    pub fn holder(&self) -> &SplintId {
        &self.payload.holder
    }

    pub fn resource(&self) -> &str {
        &self.payload.resource
    }

    pub fn operations(&self) -> &[String] {
        &self.payload.operations
    }

    pub fn expires_at(&self) -> u64 {
        self.payload.expires_at
    }

    pub fn limits(&self) -> GrantLimits {
        self.payload.limits
    }

    /// The rest of the check, in the order the protocol states. Revocations and the rate are the
    /// resource's own records, so it brings them in `record`.
    pub fn check_call(&self, call: &Call<'_>, record: Record) -> Result<Granted, Refusal> {
        let grant = &self.payload;
        if grant.resource != call.resource {
            return Err(Refusal::WrongResource);
        }
        if !grant.operations.iter().any(|name| name == call.operation) {
            return Err(Refusal::NoGrant);
        }
        if call.now >= grant.expires_at {
            return Err(Refusal::Expired);
        }
        if record.revoked {
            return Err(Refusal::Revoked);
        }
        let identity = Identity::from_encoded(call.identity).map_err(|_| Refusal::BadProof)?;
        if identity.id() != &grant.holder {
            return Err(Refusal::WrongHolder);
        }
        AccessProof::verify(
            call.proof,
            &identity,
            call.resource,
            call.method,
            call.path,
            call.body,
            call.now,
        )
        .map_err(|_| Refusal::BadProof)?;
        if record.calls_this_hour >= grant.limits.calls_per_hour {
            return Err(Refusal::OverRate);
        }
        Ok(Granted {
            grant: self.id.clone(),
            holder: grant.holder.clone(),
            operation: call.operation.to_owned(),
        })
    }
}

/// One call to a resource, as it arrived. `resource` and `operation` are the resource's own: its
/// name, and the operation it maps this method and path to.
pub struct Call<'a> {
    pub identity: &'a str,
    pub proof: &'a str,
    pub resource: &'a str,
    pub operation: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    pub now: u64,
}

/// What the resource knows about one grant.
#[derive(Clone, Copy, Debug, Default)]
pub struct Record {
    pub revoked: bool,
    pub calls_this_hour: u32,
}

/// Proof that one call passed every check. Its fields are private and it can't be cloned, so one
/// check buys one action.
#[derive(Debug)]
pub struct Granted {
    grant: GrantId,
    holder: SplintId,
    operation: String,
}

impl Granted {
    pub fn grant(&self) -> &GrantId {
        &self.grant
    }

    pub fn holder(&self) -> &SplintId {
        &self.holder
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationPayload {
    v: u8,
    owner: SplintId,
    grant: GrantId,
    issued_at: u64,
}

/// An owner's word that a grant is over. The signature is what counts, so a resource takes it from
/// anyone, and no host can hold it back. It stops every later call, and can't recall what was done.
pub struct VerifiedRevocation(RevocationPayload);

impl VerifiedRevocation {
    pub fn sign(
        key: &SigningKey,
        owner: &SplintId,
        grant: &GrantId,
        now: u64,
    ) -> Result<String, Error> {
        let bytes = serde_json::to_vec(&RevocationPayload {
            v: FORMAT_VERSION,
            owner: owner.clone(),
            grant: grant.clone(),
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)?;
        jws::sign(key, REVOCATION_TYPE, &bytes)
    }

    pub fn verify(compact: &str, owner: &Identity) -> Result<Self, Refusal> {
        let bytes = owner.verify(compact, REVOCATION_TYPE)?;
        let revocation: RevocationPayload =
            serde_json::from_slice(&bytes).map_err(|_| Refusal::Malformed)?;
        if revocation.v != FORMAT_VERSION
            || &revocation.owner != owner.id()
            || !revocation.grant.is_well_formed()
        {
            return Err(Refusal::Malformed);
        }
        Ok(Self(revocation))
    }

    pub fn grant(&self) -> &GrantId {
        &self.0.grant
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Uses {
    hour: u64,
    count: u32,
}

/// A resource's own record of revocations and use, which it keeps durably and brings to every check.
/// It serializes, so a resource with no database can keep it in a file.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    /// Each revoked grant, and when it can be forgotten because no grant it could name is in date.
    revoked: BTreeMap<GrantId, u64>,
    uses: BTreeMap<GrantId, Uses>,
    /// The newest copy seen of each ID that's been recovered, a holder's or the owner's. A resource
    /// can't hear of a replaced key any other way, and a caller picks the copy it shows, so one that's
    /// gone from here can't bring a key back.
    #[serde(default)]
    newest: BTreeMap<String, String>,
    /// Whether a new copy came in since this was read, which a resource keeps even for a call refused.
    #[serde(skip)]
    heard_a_new_copy: bool,
}

impl Ledger {
    /// Kept until any grant it could name has run out. A grant is signed before it can be revoked,
    /// so it ends at most a grant's life after the later of the two clocks.
    pub fn revoke(&mut self, revocation: &VerifiedRevocation, now: u64) {
        let from = now.max(revocation.0.issued_at);
        let until = from.saturating_add(MAX_GRANT_LIFE_SECS + CLOCK_TOLERANCE_SECS);
        self.revoked.insert(revocation.grant().clone(), until);
        self.uses.remove(revocation.grant());
    }

    /// Checks a call and counts it if it passes, so a caller can't use one check twice.
    pub fn check(
        &mut self,
        compact_grant: &str,
        owner: &Identity,
        call: &Call<'_>,
    ) -> Result<Granted, Refusal> {
        self.forget_what_has_ended(call.now);
        let owner = self.newest_owner(owner);
        let grant = VerifiedGrant::verify(compact_grant, &owner, call.now)?;
        let identity = self.newest_copy(grant.holder(), call.identity)?;
        let call = &Call {
            identity: &identity,
            ..*call
        };
        let hour = call.now / HOUR_SECS;
        let calls_this_hour = self
            .uses
            .get(grant.id())
            .filter(|uses| uses.hour == hour)
            .map_or(0, |uses| uses.count);
        let record = Record {
            revoked: self.revoked.contains_key(grant.id()),
            calls_this_hour,
        };
        let granted = grant.check_call(call, record)?;
        self.uses.insert(
            grant.id().clone(),
            Uses {
                hour,
                count: calls_this_hour.saturating_add(1),
            },
        );
        Ok(granted)
    }

    /// Takes in a newer copy of an ID from anyone, since only a backup key can make one. An owner can
    /// bring it here themselves: their own after a recovery, which the resource's config can't say by
    /// itself, or an agent's, so a thief's next call doesn't have to wait for the agent's.
    pub fn learn_copy(&mut self, copy: &Identity) -> Result<bool, Refusal> {
        let held = self.held(copy.id());
        let newest = match &held {
            Some(held) => held.newest_of(copy).map_err(|_| Refusal::BadProof)?,
            None => copy.clone(),
        };
        let learned = newest.recoveries() > held.map_or(0, |held| held.recoveries());
        if learned {
            self.newest
                .insert(newest.id().as_str().to_owned(), newest.encoded());
            self.heard_a_new_copy = true;
        }
        Ok(learned)
    }

    pub fn heard_a_new_copy(&self) -> bool {
        self.heard_a_new_copy
    }

    fn held(&self, id: &SplintId) -> Option<Identity> {
        self.newest
            .get(id.as_str())
            .and_then(|text| Identity::from_encoded(text).ok())
    }

    /// The owner's ID as this record knows it, which can be newer than the resource's config. Two
    /// recoveries that part ways leave what's held, as the config can't be asked to choose.
    pub fn newest_owner(&self, config: &Identity) -> Identity {
        match self.held(config.id()) {
            Some(held) => held.newest_of(config).unwrap_or(held),
            None => config.clone(),
        }
    }

    /// What this call goes by: the copy it came with, or the newer one held. That's the holder's only,
    /// so someone else's ID goes on to be refused as that.
    fn newest_copy(&mut self, holder: &SplintId, presented: &str) -> Result<String, Refusal> {
        let copy = Identity::from_encoded(presented).map_err(|_| Refusal::BadProof)?;
        if copy.id() != holder {
            return Ok(presented.to_owned());
        }
        self.learn_copy(&copy)?;
        Ok(self
            .held(holder)
            .map_or_else(|| presented.to_owned(), |held| held.encoded()))
    }

    fn forget_what_has_ended(&mut self, now: u64) {
        let hour = now / HOUR_SECS;
        self.revoked.retain(|_, until| *until > now);
        self.uses.retain(|_, uses| uses.hour >= hour);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_identity;

    const NOW: u64 = 1_793_750_400;
    const RESOURCE: &str = "files.ana.example";

    struct Parties {
        owner_key: SigningKey,
        owner: Identity,
        agent_key: SigningKey,
        agent: Identity,
    }

    fn parties() -> Parties {
        let owner_key = SigningKey::generate().unwrap();
        let agent_key = SigningKey::generate().unwrap();
        Parties {
            owner: test_identity(&owner_key),
            agent: test_identity(&agent_key),
            owner_key,
            agent_key,
        }
    }

    fn draft(parties: &Parties) -> GrantDraft {
        GrantDraft {
            holder: parties.agent.id().clone(),
            resource: RESOURCE.to_owned(),
            operations: vec!["docs.read".to_owned()],
            limits: GrantLimits { calls_per_hour: 3 },
            life_secs: DEFAULT_GRANT_LIFE_SECS,
        }
    }

    fn grant(parties: &Parties) -> SignedGrant {
        draft(parties)
            .sign(&parties.owner_key, parties.owner.id(), NOW)
            .unwrap()
    }

    fn call_at(
        ledger: &mut Ledger,
        parties: &Parties,
        grant: &str,
        now: u64,
    ) -> Result<Granted, Refusal> {
        let body = br#"{"doc":"q4"}"#;
        let proof = AccessProof::sign(
            &parties.agent_key,
            parties.agent.id(),
            RESOURCE,
            "POST",
            "/docs",
            body,
            now,
        )
        .unwrap();
        ledger.check(
            grant,
            &parties.owner,
            &Call {
                identity: &parties.agent.encoded(),
                proof: &proof,
                resource: RESOURCE,
                operation: "docs.read",
                method: "POST",
                path: "/docs",
                body,
                now,
            },
        )
    }

    #[test]
    fn a_call_passes_only_up_to_the_rate_and_the_next_hour_starts_again() {
        let parties = parties();
        let signed = grant(&parties);
        let mut ledger = Ledger::default();
        for _ in 0..3 {
            let granted = call_at(&mut ledger, &parties, &signed.grant, NOW).unwrap();
            assert_eq!(granted.grant(), &signed.id);
            assert_eq!(granted.holder(), parties.agent.id());
        }
        assert_eq!(
            call_at(&mut ledger, &parties, &signed.grant, NOW).err(),
            Some(Refusal::OverRate)
        );
        assert!(call_at(&mut ledger, &parties, &signed.grant, NOW + HOUR_SECS).is_ok());
    }

    #[test]
    fn a_revocation_stops_every_later_call_and_outlives_the_grant() {
        let parties = parties();
        let signed = grant(&parties);
        let mut ledger = Ledger::default();
        assert!(call_at(&mut ledger, &parties, &signed.grant, NOW).is_ok());
        let compact =
            VerifiedRevocation::sign(&parties.owner_key, parties.owner.id(), &signed.id, NOW)
                .unwrap();
        let revocation = VerifiedRevocation::verify(&compact, &parties.owner).unwrap();
        ledger.revoke(&revocation, NOW);
        // Through a saved copy too, since a resource keeps it in a file.
        let mut ledger: Ledger =
            serde_json::from_str(&serde_json::to_string(&ledger).unwrap()).unwrap();
        for at in [
            NOW,
            NOW + 1,
            NOW + HOUR_SECS,
            NOW + DEFAULT_GRANT_LIFE_SECS - 1,
        ] {
            assert_eq!(
                call_at(&mut ledger, &parties, &signed.grant, at).err(),
                Some(Refusal::Revoked),
                "{at}"
            );
        }
        // A new grant is a new ID, even one alike signed in the same second, and works.
        let again = draft(&parties)
            .sign(&parties.owner_key, parties.owner.id(), NOW)
            .unwrap();
        assert_ne!(again.id, signed.id);
        assert!(call_at(&mut ledger, &parties, &again.grant, NOW + 1).is_ok());
        assert_ne!(again.grant, signed.grant);
    }

    #[test]
    fn a_draft_a_resource_would_refuse_cant_be_signed() {
        let parties = parties();
        let sign = |change: &dyn Fn(&mut GrantDraft)| {
            let mut draft = draft(&parties);
            change(&mut draft);
            draft
                .sign(&parties.owner_key, parties.owner.id(), NOW)
                .err()
        };
        let unsound: [&dyn Fn(&mut GrantDraft); 7] = [
            &|draft| draft.life_secs = MAX_GRANT_LIFE_SECS + 1,
            &|draft| draft.life_secs = 0,
            &|draft| draft.limits.calls_per_hour = 0,
            &|draft| draft.limits.calls_per_hour = MAX_CALLS_PER_HOUR + 1,
            &|draft| draft.operations = Vec::new(),
            &|draft| draft.operations = vec!["Read Everything".to_owned()],
            &|draft| draft.resource = "a b".to_owned(),
        ];
        for change in unsound {
            assert_eq!(sign(change), Some(Error::Malformed));
        }
        let to_self = |draft: &mut GrantDraft| draft.holder = parties.owner.id().clone();
        assert_eq!(sign(&to_self), Some(Error::Malformed));
    }

    #[test]
    fn a_replaced_holder_key_stops_working_once_the_resource_has_seen_the_new_copy() {
        let owner_key = SigningKey::generate().unwrap();
        let owner = test_identity(&owner_key);
        let stolen = SigningKey::generate().unwrap();
        let backup = SigningKey::generate().unwrap();
        let old = Identity::create(
            &stolen,
            &crate::test_seal(),
            crate::RecoveryRule::backup_key(&backup.public_key()),
        )
        .unwrap();
        let new_key = SigningKey::generate().unwrap();
        let next_backup = SigningKey::generate().unwrap();
        let new = old
            .recover(
                &backup,
                &new_key.public_key(),
                &crate::test_seal(),
                crate::RecoveryRule::backup_key(&next_backup.public_key()),
                NOW,
            )
            .unwrap();
        let signed = GrantDraft {
            holder: old.id().clone(),
            resource: RESOURCE.to_owned(),
            operations: vec!["docs.read".to_owned()],
            limits: GrantLimits {
                calls_per_hour: 100,
            },
            life_secs: DAY_SECS,
        }
        .sign(&owner_key, owner.id(), NOW)
        .unwrap();
        let call = |ledger: &mut Ledger, key: &SigningKey, copy: &Identity| {
            let proof =
                AccessProof::sign(key, copy.id(), RESOURCE, "POST", "/docs", b"", NOW).unwrap();
            ledger.check(
                &signed.grant,
                &owner,
                &Call {
                    identity: &copy.encoded(),
                    proof: &proof,
                    resource: RESOURCE,
                    operation: "docs.read",
                    method: "POST",
                    path: "/docs",
                    body: b"",
                    now: NOW,
                },
            )
        };
        let mut ledger = Ledger::default();
        assert!(
            call(&mut ledger, &stolen, &old).is_ok(),
            "nothing heard yet"
        );
        assert!(call(&mut ledger, &new_key, &new).is_ok());
        assert_eq!(
            call(&mut ledger, &stolen, &old).err(),
            Some(Refusal::BadProof),
            "the old copy can't bring the old key back"
        );
        assert_eq!(
            call(&mut ledger, &stolen, &new).err(),
            Some(Refusal::BadProof)
        );
        let mut saved: Ledger =
            serde_json::from_str(&serde_json::to_string(&ledger).unwrap()).unwrap();
        assert_eq!(
            call(&mut saved, &stolen, &old).err(),
            Some(Refusal::BadProof),
            "a saved record keeps it"
        );
        assert!(call(&mut saved, &new_key, &new).is_ok());

        // Told directly, before the agent has called at all.
        let mut told = Ledger::default();
        assert_eq!(told.learn_copy(&new), Ok(true));
        assert_eq!(told.learn_copy(&old), Ok(false));
        assert_eq!(
            call(&mut told, &stolen, &old).err(),
            Some(Refusal::BadProof)
        );
    }

    #[test]
    fn a_grant_from_an_owner_key_since_recovered_away_counts_for_nothing() {
        let owner_key = SigningKey::generate().unwrap();
        let backup = SigningKey::generate().unwrap();
        let owner = Identity::create(
            &owner_key,
            &crate::test_seal(),
            crate::RecoveryRule::backup_key(&backup.public_key()),
        )
        .unwrap();
        let agent = test_identity(&SigningKey::generate().unwrap());
        let signed = GrantDraft {
            holder: agent.id().clone(),
            resource: RESOURCE.to_owned(),
            operations: vec!["docs.read".to_owned()],
            limits: GrantLimits { calls_per_hour: 3 },
            life_secs: DAY_SECS,
        }
        .sign(&owner_key, owner.id(), NOW)
        .unwrap();
        assert!(VerifiedGrant::verify(&signed.grant, &owner, NOW).is_ok());
        let next = SigningKey::generate().unwrap();
        let next_backup = SigningKey::generate().unwrap();
        let recovered = owner
            .recover(
                &backup,
                &next.public_key(),
                &crate::test_seal(),
                crate::RecoveryRule::backup_key(&next_backup.public_key()),
                NOW,
            )
            .unwrap();
        assert_eq!(
            VerifiedGrant::verify(&signed.grant, &recovered, NOW).err(),
            Some(Refusal::BadSignature)
        );

        // A resource whose config still holds the old copy has to be told, and then it holds there.
        let agent_key = SigningKey::generate().unwrap();
        let agent = test_identity(&agent_key);
        let thiefs = GrantDraft {
            holder: agent.id().clone(),
            resource: RESOURCE.to_owned(),
            operations: vec!["docs.read".to_owned()],
            limits: GrantLimits { calls_per_hour: 3 },
            life_secs: DAY_SECS,
        }
        .sign(&owner_key, owner.id(), NOW)
        .unwrap();
        let call = |ledger: &mut Ledger| {
            let proof =
                AccessProof::sign(&agent_key, agent.id(), RESOURCE, "GET", "/x", b"", NOW).unwrap();
            ledger.check(
                &thiefs.grant,
                &owner,
                &Call {
                    identity: &agent.encoded(),
                    proof: &proof,
                    resource: RESOURCE,
                    operation: "docs.read",
                    method: "GET",
                    path: "/x",
                    body: b"",
                    now: NOW,
                },
            )
        };
        let mut ledger = Ledger::default();
        assert!(call(&mut ledger).is_ok(), "nothing heard yet");
        assert_eq!(ledger.learn_copy(&recovered), Ok(true));
        assert_eq!(call(&mut ledger).err(), Some(Refusal::BadSignature));
    }
}

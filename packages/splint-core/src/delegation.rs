//! A key Signet holds that its owner lets sign for them, within limits they set, while they're away.
//! See `docs/protocol.md`.
//!
//! An owner whose key is a passkey can't leave it signing by itself on a machine, and shouldn't have to
//! touch every confirm within their limits. So they sign a delegation once: this agent's Signet's
//! delegate key may say yes to a `confirm` whose every value has a cap here and fits it.
//!
//! An agent sharing an OS user with its Signet can read this key. So what the delegate signs always
//! travels with the delegation, joined by `~`, and every reader checks it against the caps the owner
//! signed, not against Signet's word. A fooled agent holding the key gets no further than the caps.
//!
//! The owner's rules name the one delegation they allow, by its hash, and it counts at Signet and at
//! the sending host only while the rules in force name it. So new rules end a delegation at once,
//! wherever those rules have reached, and a lower cap binds as soon as the rules naming a new
//! delegation with it do.

use std::collections::BTreeMap;
use std::path::Path;

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::requests::{ApprovalDraft, Decision, InteractionType, Operation, Schema, Terms};
use crate::rules::{Level, Permissions, QuotedPrices};
use crate::{CLOCK_TOLERANCE_SECS, Error, Identity, PublicKey, SigningKey, SplintId, jws};

pub(crate) const DELEGATION_TYPE: &str = "splint-delegation";
const VERSION: u8 = 1;
const DAY_SECS: u64 = 24 * 60 * 60;
/// What joins something a delegate signed to the delegation it's signed under.
pub const PART_SEPARATOR: char = '~';
/// Long enough that an owner signs once a year, and short enough that a key they've forgotten ends.
pub const MAX_DELEGATION_LIFE_SECS: u64 = 365 * DAY_SECS;
/// Big enough for a passkey's signature and caps on a few types, and small enough that a `confirm`
/// carrying one still fits a step.
pub const MAX_DELEGATION_CHARS: usize = 2560;

/// The key Signet signs with for its owner, kept apart from its agent key, so nothing the agent key
/// signs can count as the owner's, and it can be replaced without a new ID. It can't be printed.
pub struct DelegateKey(SigningKey);

impl DelegateKey {
    pub fn generate() -> Result<Self, Error> {
        SigningKey::generate().map(Self)
    }

    /// Kept like any key file: made once, readable only by its user, and refused if anyone else can.
    pub fn load_or_create(path: &Path) -> Result<Self, Error> {
        SigningKey::load_or_create(path).map(Self)
    }

    /// The key at `path` as it is now, which must be there already.
    pub fn load(path: &Path) -> Result<Self, Error> {
        SigningKey::load(path).map(Self)
    }

    /// A fresh key in place of the one at `path`. What the old one signs counts only under a
    /// delegation the owner's rules still name, so the owner names a new one to end it.
    pub fn replace(path: &Path) -> Result<Self, Error> {
        SigningKey::replace(path).map(Self)
    }

    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// For looking for this key in what an agent writes, which never prints it.
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.0
    }
}

/// What an owner lets a delegate do. Nothing else can be delegated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delegated {
    /// Say yes to a `confirm` whose every value has a cap in the delegation and fits it.
    ApproveWithinCaps,
    /// Carried the owner's rules on past their 30 days, before rules lasted until replaced. Still read
    /// in delegations signed then, and lets the delegate do nothing.
    RenewRules,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationPayload {
    v: u8,
    owner: SplintId,
    agent: SplintId,
    delegate: String,
    may: Vec<Delegated>,
    level: Level,
    caps: BTreeMap<InteractionType, BTreeMap<String, u64>>,
    actions_per_day: u32,
    seq: u64,
    issued_at: u64,
    expires_at: u64,
}

impl DelegationPayload {
    /// A delegate only ever says yes to a `confirm`, never to a price an agent quotes, so a delegation
    /// carries no `quoted_prices` and reads as the default.
    fn permissions(&self) -> Permissions {
        Permissions {
            level: self.level,
            actions_per_day: self.actions_per_day,
            caps: self.caps.clone(),
            quoted_prices: QuotedPrices::default(),
        }
    }

    /// One spelling of `may`, sorted with no repeats, and no more than the owner could sign: never
    /// full auto, and approvals only within limits.
    fn check_fields(&self) -> Result<PublicKey, Error> {
        let dates_fit = self.expires_at > self.issued_at
            && self.expires_at - self.issued_at <= MAX_DELEGATION_LIFE_SECS;
        let may_fits = !self.may.is_empty() && self.may.is_sorted_by(|one, next| one < next);
        let level_fits = match self.level {
            Level::FullAuto => false,
            Level::AskMe => !self.may.contains(&Delegated::ApproveWithinCaps),
            Level::AutoWithinLimits => true,
        };
        if self.v != VERSION || !dates_fit || !may_fits || !level_fits {
            return Err(Error::Malformed);
        }
        self.permissions().check()?;
        PublicKey::from_encoded(&self.delegate)
    }
}

/// What an owner signs on their own device: which key, what it may do, and how far.
#[derive(Clone, Debug)]
pub struct DelegationDraft {
    pub delegate: PublicKey,
    pub may: Vec<Delegated>,
    pub level: Level,
    pub caps: BTreeMap<InteractionType, BTreeMap<String, u64>>,
    pub actions_per_day: u32,
    pub lasts_secs: u64,
}

impl DelegationDraft {
    /// The payload an owner's key signs, whichever way it signs. A delegation a reader would refuse is
    /// refused here, so an owner finds out on their own device.
    pub fn payload(
        &self,
        owner: &SplintId,
        agent: &SplintId,
        seq: u64,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let mut may = self.may.clone();
        may.sort();
        may.dedup();
        let payload = DelegationPayload {
            v: VERSION,
            owner: owner.clone(),
            agent: agent.clone(),
            delegate: self.delegate.encoded(),
            may,
            level: self.level,
            caps: self.caps.clone(),
            actions_per_day: self.actions_per_day,
            seq,
            issued_at: now,
            expires_at: now.saturating_add(self.lasts_secs),
        };
        payload.check_fields()?;
        serde_json::to_vec(&payload).map_err(|_| Error::Malformed)
    }

    /// Signed by an owner's file key.
    pub fn sign(
        &self,
        key: &SigningKey,
        owner: &SplintId,
        agent: &SplintId,
        seq: u64,
        now: u64,
    ) -> Result<String, Error> {
        let signed = jws::sign(key, DELEGATION_TYPE, &self.payload(owner, agent, seq, now)?)?;
        if signed.len() > MAX_DELEGATION_CHARS {
            return Err(Error::Malformed);
        }
        Ok(signed)
    }
}

/// A delegation whose owner's signature has been checked, for one agent. The only way to get one is to
/// pass that check, and nothing a delegate signs counts without one.
#[derive(Clone, Debug)]
pub struct VerifiedDelegation {
    compact: String,
    payload: DelegationPayload,
    delegate: PublicKey,
}

impl VerifiedDelegation {
    /// A delegation arriving now: signed by the key this owner holds now, for this agent, in date, and
    /// no older than `newest_seq_seen`. Signet holds one delegation, and takes only a newer one, so one
    /// handed back can't displace the one the owner's rules name.
    pub fn verify(
        compact: &str,
        owner: &Identity,
        agent: &Identity,
        newest_seq_seen: u64,
        now: u64,
    ) -> Result<Self, Error> {
        let delegation = Self::carried(compact, owner, agent.id(), Some(agent), false)?;
        let payload = &delegation.payload;
        if payload.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        if now >= payload.expires_at {
            return Err(Error::Expired);
        }
        if payload.seq < newest_seq_seen {
            return Err(Error::Stale);
        }
        Ok(delegation)
    }

    /// One read back from storage, which may have ended since. A recovery of the owner ends it, since
    /// it's checked under the key they hold now.
    pub fn reload(compact: &str, owner: &Identity, agent: &Identity) -> Result<Self, Error> {
        Self::carried(compact, owner, agent.id(), Some(agent), false)
    }

    /// One a host keeps as owner mail for an agent it knows only by ID. The agent's Signet checks it
    /// again in full, against its own keys, before it takes it.
    pub fn relayed(compact: &str, owner: &Identity, agent: &SplintId) -> Result<Self, Error> {
        Self::carried(compact, owner, agent, None, false)
    }

    /// One carried with what a delegate signed. Read back, it may date from before a recovery of the
    /// owner, and arriving it can't. Without the agent's identity, as when stored rules are read back,
    /// the delegate key isn't compared with the agent's, which was done when they arrived.
    pub(crate) fn carried(
        compact: &str,
        owner: &Identity,
        agent_id: &SplintId,
        agent: Option<&Identity>,
        history: bool,
    ) -> Result<Self, Error> {
        if compact.len() > MAX_DELEGATION_CHARS {
            return Err(Error::Malformed);
        }
        // Only a link reads a guest's ID, so one handed over as an owner's isn't read.
        if owner.is_guest() {
            return Err(Error::Malformed);
        }
        // An owner who hasn't confirmed is a key the agent's own machine holds.
        if owner.is_unconfirmed_owner() {
            return Err(Error::WrongSigner);
        }
        let bytes = if history {
            owner.verify_under_any_key(compact, DELEGATION_TYPE)?
        } else {
            owner.verify(compact, DELEGATION_TYPE)?
        };
        let payload: DelegationPayload =
            serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        // One encoding, as an owner's device writes it, so every reader parses it alike.
        if !is_its_one_encoding(&payload, &bytes) {
            return Err(Error::Malformed);
        }
        let delegate = payload.check_fields()?;
        if &payload.owner != owner.id() {
            return Err(Error::WrongSigner);
        }
        if &payload.agent != agent_id || agent.is_some_and(|agent| agent.id() != agent_id) {
            return Err(Error::ProofMismatch);
        }
        // One key, one job: an owner's or an agent's key signing as a delegate would make anything it
        // signed for itself look like the owner's yes.
        let reused =
            owner.has_had_key(&delegate) || agent.is_some_and(|agent| agent.has_had_key(&delegate));
        if reused {
            return Err(Error::Malformed);
        }
        Ok(Self {
            compact: compact.to_owned(),
            payload,
            delegate,
        })
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn seq(&self) -> u64 {
        self.payload.seq
    }

    /// What rules name this delegation by. See [`name_of`].
    pub fn name(&self) -> String {
        name_of(&self.compact)
    }

    pub fn issued_at(&self) -> u64 {
        self.payload.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.payload.expires_at
    }

    pub fn may(&self, what: Delegated) -> bool {
        self.payload.may.contains(&what)
    }

    pub fn actions_per_day(&self) -> u32 {
        self.payload.actions_per_day
    }

    pub fn owner(&self) -> &SplintId {
        &self.payload.owner
    }

    pub fn agent(&self) -> &SplintId {
        &self.payload.agent
    }

    /// The level and caps the owner signed, which bound what the delegate says yes to.
    pub fn permissions(&self) -> Permissions {
        self.payload.permissions()
    }

    /// Whether this is the key that may sign under it.
    pub fn names(&self, key: &DelegateKey) -> bool {
        key.public_key() == self.delegate
    }

    pub fn delegate(&self) -> &PublicKey {
        &self.delegate
    }

    fn signed_while_in_date(&self, at: u64) -> bool {
        self.payload.issued_at <= at && at < self.payload.expires_at
    }

    /// The payload of something this delegate signed.
    pub(crate) fn signed(&self, compact: &str, typ: &str) -> Result<Vec<u8>, Error> {
        jws::verify_delegated(compact, &self.delegate, typ)
    }

    /// The delegate's yes to a `confirm` within the caps, joined to this delegation. Anything else
    /// is the owner's to sign, and a reader would refuse it anyway.
    pub fn approve(
        &self,
        key: &DelegateKey,
        draft: &ApprovalDraft,
        schema: &Schema,
        now: u64,
    ) -> Result<String, Error> {
        // A yes can't outlast the delegation it's said under, so nothing it carries arrives after.
        let mut draft = draft.clone();
        draft.latest_expiry = draft.latest_expiry.min(self.payload.expires_at);
        let fits = self.may(Delegated::ApproveWithinCaps)
            && self.names(key)
            && draft.latest_expiry > now
            && self.covers(now, draft.latest_expiry)
            && draft.operation == Operation::Confirm
            && draft.owner == self.payload.owner
            && draft.agent == self.payload.agent
            && !draft.terms.hides_text()
            && self.caps_fit(schema, &draft.terms);
        if !fits {
            return Err(Error::ProofMismatch);
        }
        let signed = draft.sign(&key.0, Decision::Approve, None, now)?;
        Ok(format!("{signed}{PART_SEPARATOR}{}", self.compact))
    }

    /// Whether a delegate's yes was signed while this delegation held, and ends by the time it does.
    /// A step carrying it can't be dated past the yes's end, and the yes's start is the signer's word,
    /// so its end is what keeps a yes backdated into an ended delegation from arriving after it.
    pub(crate) fn covers(&self, issued_at: u64, expires_at: u64) -> bool {
        self.signed_while_in_date(issued_at) && expires_at <= self.payload.expires_at
    }

    /// Whether the owner capped this type, and every value these terms carry has a cap there, in its
    /// unit, and fits it. A type the owner never named gets no yes, even one with no values.
    pub(crate) fn caps_fit(&self, schema: &Schema, terms: &Terms) -> bool {
        self.payload.caps.contains_key(&terms.interaction)
            && self.permissions().within_caps(schema, terms)
    }
}

/// The name of a delegation carried with a delegate's yes, unchecked, for a sealed step's outside. A
/// sending host holds it to the delegation its owner's rules name, and a reader holds the outside to
/// what's inside and checks the delegation itself.
pub(crate) fn claimed_name(delegation: &str) -> Result<String, Error> {
    if delegation.len() > MAX_DELEGATION_CHARS {
        return Err(Error::Malformed);
    }
    let bytes = jws::unverified_payload(delegation, DELEGATION_TYPE)?;
    serde_json::from_slice::<DelegationPayload>(&bytes).map_err(|_| Error::Malformed)?;
    Ok(name_of(delegation))
}

/// How rules name a delegation: the hex SHA-256 of its signing input, its header and payload as they
/// travel, joined by `.`. It names one delegation, caps, dates and key included, so nothing else signed
/// with the same `seq` or to the same key can stand in for it. It leaves out the signature, which a
/// passkey makes over the hashes of everything it signs with one touch, rules naming this included, so
/// naming the whole JWS would make rules and their delegation two touches.
pub fn name_of(delegation: &str) -> String {
    let signing_input = delegation
        .rsplit_once('.')
        .map_or(delegation, |(signing_input, _)| signing_input);
    name_of_input(signing_input)
}

/// The same, for a delegation not yet signed, from its signing input.
pub(crate) fn name_of_input(signing_input: &str) -> String {
    hex(digest::digest(&digest::SHA256, signing_input.as_bytes()).as_ref())
}

/// Whether text can be a delegation's name: 64 lowercase hex digits, one spelling of one hash.
pub(crate) fn is_a_name(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether bytes a delegate key signed are exactly what this payload encodes to: compact, in the
/// protocol's field order, with the fields of `terms` sorted. A fooled agent can read that key, so
/// anything else is refused, or a reader taking any order would take what the Go verifier refuses.
pub(crate) fn is_its_one_encoding<T: Serialize>(payload: &T, bytes: &[u8]) -> bool {
    serde_json::to_vec(payload).is_ok_and(|encoded| encoded == bytes)
}

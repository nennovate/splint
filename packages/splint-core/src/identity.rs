use std::fmt;

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};

use crate::jws::Signature;
use crate::passkey::{self, RpId};
use crate::{Error, PublicKey, SealPublicKey, SigningKey, jws};

const EVENT_VERSION: u8 = 4;
const ALG: &str = "ES256";
/// An owner's ID whose key is a passkey, which names the RP ID it's tied to.
const PASSKEY_EVENT_VERSION: u8 = 5;
const PASSKEY_ALG: &str = "webauthn-es256";
pub(crate) const ID_PREFIX: &str = "splint1";
const SHA256_HEX_LEN: usize = 64;
const RECOVERY_TYPE: &str = "splint-recovery";
const RECOVERY_VERSION: u8 = 2;
/// A recovery naming a passkey as the next key. One naming a file key stays version 2.
const PASSKEY_RECOVERY_VERSION: u8 = 3;
const GUEST_EVENT_VERSION: u8 = 2;
const GUEST_ROLE: &str = "guest";
const GUEST_ID_PREFIX: &str = "splint1g";
/// What an owner who hasn't confirmed yet commits to in place of a backup. It's 24 bytes longer than
/// a key, so no backup key can hash to it, and anyone can work it out from the key alone.
const UNCONFIRMED_OWNER_TAG: &[u8] = b"splint-unconfirmed-owner";
/// What an owner who hasn't set up a recovery code yet commits to, the same way: no backup key can
/// hash to it, and a [`StatementKind::RecoveryRule`] by a key that counts sets the real one later.
const RECOVERY_LATER_TAG: &[u8] = b"splint-recovery-later";
/// An identity travels with every message, so its history can't grow without limit. Past this an ID
/// can't be recovered again, and its holder starts a new one.
pub const MAX_RECOVERIES: usize = 8;
const KEY_ADD_TYPE: &str = "splint-key-add";
const KEY_REMOVE_TYPE: &str = "splint-key-remove";
/// Adds a file key. A key statement's version also names its kind, apart from a recovery's.
const KEY_ADD_VERSION: u8 = 4;
const PASSKEY_ADD_VERSION: u8 = 5;
const KEY_REMOVE_VERSION: u8 = 6;
/// Sets the recovery rule of an ID that was made without one, once.
const RECOVERY_RULE_TYPE: &str = "splint-recovery-rule";
const RECOVERY_RULE_VERSION: u8 = 7;
/// The most keys an owner's ID has at once.
pub const MAX_KEYS: usize = 4;
/// The most keys an ID adds between one recovery and the next. A recovery starts the count again, so a
/// thief holding a stolen sign-in who spends them all leaves the owner nothing worse than recovering.
pub const MAX_ADDITIONS: usize = 8;
/// Past this nothing is worth parsing. Key statements stop short of it by [`RECOVERY_ROOM`] for each
/// recovery the ID has left, so whatever a thief adds and removes, every recovery still fits.
const MAX_ENCODED_CHARS: usize = 80 * 1024;
/// The most one recovery adds to an encoded ID, its separator included: its longest fields, a passkey's
/// RP ID at 253 characters among them, come to under 1,400.
const RECOVERY_ROOM: usize = 1600;
/// Isn't in base64url or a JWS, so an encoded identity splits one way.
const STATEMENT_SEPARATOR: char = '~';
/// A statement's `issued_at` fits a signed 64-bit integer, as every reader can hold one.
const MAX_ISSUED_AT: u64 = i64::MAX.unsigned_abs();

/// A permanent ID: the hash of the raw identity event, so nobody has to hand it out. People,
/// businesses and agents all have this one kind. Who an agent acts for is a separate statement,
/// [`crate::VerifiedBinding`], so the ID stays the same when that changes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SplintId(String);

impl fmt::Display for SplintId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl SplintId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this names someone answering a one-use link. It's only a name's shape, so it says who to
    /// show, and nothing that counts goes by it.
    pub fn is_guest(&self) -> bool {
        self.0.starts_with(GUEST_ID_PREFIX)
    }

    /// Whether this is shaped like an ID: the prefix, then a lowercase hex SHA-256. A guest's ID adds
    /// a `g`. It says nothing about whether such an ID exists.
    pub fn is_well_formed(&self) -> bool {
        self.0.strip_prefix(ID_PREFIX).is_some_and(|rest| {
            let hash = rest.strip_prefix('g').unwrap_or(rest);
            is_sha256_hex(hash)
        })
    }
}

pub(crate) fn is_sha256_hex(text: &str) -> bool {
    text.len() == SHA256_HEX_LEN
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A statement's signing input: its header and payload, without its signature, or an addition's two.
/// An ES256 signature can be respelled without the key, so nothing may turn on its exact bytes, or a
/// host could make one real recovery look like two.
fn signed_part(statement: &str) -> &str {
    statement
        .match_indices('.')
        .nth(1)
        .and_then(|(at, _)| statement.get(..at))
        .unwrap_or(statement)
}

fn id_of(raw_event: &[u8]) -> SplintId {
    SplintId(format!("{ID_PREFIX}{}", sha256_hex(raw_event)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

/// What it takes to name this ID's next key. An ID commits to one of these, and each recovery names
/// the next, so a new method can be added here later and an ID can move to it without changing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryRule {
    /// Whoever holds the key whose public half hashes to this.
    BackupKey { commitment: String },
    /// A guest's key lasts one request and has no successor. This never goes on the wire, so nothing
    /// that arrives can claim it, and a guest's ID can't be recovered or moved to another key.
    #[serde(skip)]
    NoRecovery,
}

impl RecoveryRule {
    pub fn backup_key(backup: &PublicKey) -> Self {
        Self::BackupKey {
            commitment: commitment_to(backup),
        }
    }

    /// A rule someone else's device made, such as an agent's backup, whose key this side never sees.
    pub fn committed_to(commitment: &str) -> Result<Self, Error> {
        let rule = Self::BackupKey {
            commitment: commitment.to_owned(),
        };
        rule.check()?;
        Ok(rule)
    }

    fn check(&self) -> Result<(), Error> {
        match self {
            Self::BackupKey { commitment } if is_sha256_hex(commitment) => Ok(()),
            Self::BackupKey { .. } | Self::NoRecovery => Err(Error::Malformed),
        }
    }

    /// What an agent joining on its own commits its stand-in to: no backup key can satisfy it, so that
    /// ID can never be recovered, and whoever holds its key can't take back what the owner confirms
    /// later. Anyone can tell one from the key, which is how a reader knows.
    pub fn unconfirmed_owner(key: &PublicKey) -> Self {
        let mut bytes = UNCONFIRMED_OWNER_TAG.to_vec();
        bytes.extend_from_slice(key.as_bytes());
        Self::BackupKey {
            commitment: sha256_hex(&bytes),
        }
    }

    /// What an owner made without a recovery code commits to until a key that counts sets one: no
    /// backup can satisfy it, and anyone can tell one from the key the event or a recovery names.
    pub fn later(key: &PublicKey) -> Self {
        let mut bytes = RECOVERY_LATER_TAG.to_vec();
        bytes.extend_from_slice(key.as_bytes());
        Self::BackupKey {
            commitment: sha256_hex(&bytes),
        }
    }

    /// Whether this backup key satisfies the rule.
    pub fn accepts(&self, backup: &PublicKey) -> bool {
        match self {
            Self::BackupKey { commitment } => commitment_to(backup) == *commitment,
            Self::NoRecovery => false,
        }
    }

    /// The key that signs day to day can't also be the one that replaces it, or stealing one would
    /// be stealing both.
    fn check_apart_from(&self, key: &PublicKey) -> Result<(), Error> {
        if self.accepts(key) {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

pub(crate) fn commitment_to(key: &PublicKey) -> String {
    sha256_hex(key.as_bytes())
}

/// How an ID's key signs: as an ES256 key anywhere, or as a passkey through WebAuthn, tied to its RP
/// ID. Only an owner's key may be a passkey.
#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyKind {
    Es256,
    Passkey(RpId),
}

impl KeyKind {
    /// What an event says, whose version, `alg` and `rp` have to agree.
    fn of_event(v: u8, alg: &str, rp: Option<&str>) -> Result<Self, Error> {
        match (v, alg, rp) {
            (EVENT_VERSION, ALG, None) => Ok(Self::Es256),
            (PASSKEY_EVENT_VERSION, PASSKEY_ALG, Some(rp)) => Ok(Self::Passkey(RpId::new(rp)?)),
            _ => Err(Error::Malformed),
        }
    }

    /// The same for an added key: a file key, or a passkey made for a host's name.
    fn of_addition(v: u8, alg: Option<&str>, rp: Option<&str>) -> Result<Self, Error> {
        match (v, alg, rp) {
            (KEY_ADD_VERSION, None, None) => Ok(Self::Es256),
            (PASSKEY_ADD_VERSION, Some(PASSKEY_ALG), Some(rp)) => Ok(Self::Passkey(RpId::new(rp)?)),
            _ => Err(Error::Malformed),
        }
    }

    /// The same for a recovery, where a file key's version names neither, so it has one spelling.
    fn of_recovery(v: u8, alg: Option<&str>, rp: Option<&str>) -> Result<Self, Error> {
        match (v, alg, rp) {
            (RECOVERY_VERSION, None, None) => Ok(Self::Es256),
            (PASSKEY_RECOVERY_VERSION, Some(PASSKEY_ALG), Some(rp)) => {
                Ok(Self::Passkey(RpId::new(rp)?))
            }
            _ => Err(Error::Malformed),
        }
    }
}

/// An identity event. A file key's has no `rp`, and a passkey's has one.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityEvent {
    v: u8,
    alg: String,
    key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rp: Option<String>,
    /// What others seal to, apart from the key that signs.
    seal: String,
    recovery: RecoveryRule,
}

/// A guest's event: no owner, no recovery, nothing else. It has an ID of its own shape, so it can't be
/// taken for an agent's, and only [`Identity::guest_from_encoded`] reads one, so nothing that reads an
/// agent or an owner can be handed one.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestEvent {
    v: u8,
    role: String,
    alg: String,
    key: String,
}

/// Names an ID's next key and next rule, signed by the backup key its current rule commits to. It's
/// the only thing that can change an ID's key, so a thief holding the current key can't.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryPayload {
    v: u8,
    id: SplintId,
    seq: usize,
    /// The hash of what this follows, so a statement fits only one place in one history.
    prev: String,
    backup: String,
    /// Only in a version 3, which names a passkey, as `rp` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rp: Option<String>,
    seal: String,
    recovery: RecoveryRule,
    issued_at: u64,
}

/// Adds a key to an owner's ID, signed by a key that counts now and by the key it adds, over the same
/// signing input. Every key that counts can sign everything an owner key signs, so one person can sign
/// in from more than one device without copying a key. A version 4 adds a key that signs ES256, such as
/// one a computer's security chip holds, and a version 5 a passkey, made for a host's name, where a
/// phone signs in.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyAddPayload {
    v: u8,
    id: SplintId,
    seq: usize,
    prev: String,
    /// The name of the key that signed, which is the only one the signature is checked under.
    by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rp: Option<String>,
    issued_at: u64,
}

/// Takes a key out of the ones that count, signed by any key that counts now, that one included.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRemovePayload {
    v: u8,
    id: SplintId,
    seq: usize,
    prev: String,
    by: String,
    /// The name of the key that stops counting.
    key: String,
    issued_at: u64,
}

/// Sets the recovery rule of an ID made without one, signed by any key that counts now. It's taken
/// once, while the rule is still [`RecoveryRule::later`], so a key that counts can't move a recovery
/// code that's set, and the code is made only when the person saves it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRulePayload {
    v: u8,
    id: SplintId,
    seq: usize,
    prev: String,
    by: String,
    recovery: RecoveryRule,
    issued_at: u64,
}

/// One of an owner's keys, and how it signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerKey {
    point: PublicKey,
    kind: KeyKind,
}

impl OwnerKey {
    pub fn point(&self) -> &PublicKey {
        &self.point
    }

    /// The RP ID it's tied to, if it's a passkey.
    pub fn passkey_rp(&self) -> Option<&RpId> {
        match &self.kind {
            KeyKind::Passkey(rp) => Some(rp),
            KeyKind::Es256 => None,
        }
    }

    /// What a key statement calls it: the lowercase hex SHA-256 of its 65-byte point.
    pub fn name(&self) -> String {
        commitment_to(&self.point)
    }

    /// The name a key statement would give `point`.
    pub fn name_of(point: &PublicKey) -> String {
        commitment_to(point)
    }
}

/// What an ID's event or one recovery named, and every key added while it was the newest.
#[derive(Clone, Debug)]
struct Epoch {
    key: OwnerKey,
    /// A guest has none, as nothing is ever sealed to a link.
    seal: Option<SealPublicKey>,
    rule: RecoveryRule,
    /// Every key added in this epoch, whether or not it was removed since.
    added: Vec<OwnerKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatementKind {
    Recovery,
    KeyAdd,
    KeyRemove,
    RecoveryRule,
}

impl StatementKind {
    /// A statement's kind is its header's `typ`, and nothing else, so its `v` is held to that kind. An
    /// addition carries the added key's signature after the one its header names, and one without it
    /// is no statement at all.
    fn of(statement: &str) -> Result<Self, Error> {
        if let Some((signed, _)) = statement.rsplit_once('.')
            && jws::parse(signed, KEY_ADD_TYPE).is_ok()
        {
            return Ok(Self::KeyAdd);
        }
        [
            (RECOVERY_TYPE, Self::Recovery),
            (KEY_REMOVE_TYPE, Self::KeyRemove),
            (RECOVERY_RULE_TYPE, Self::RecoveryRule),
        ]
        .into_iter()
        .find(|(typ, _)| jws::parse(statement, typ).is_ok())
        .map(|(_, kind)| kind)
        .ok_or(Error::Malformed)
    }
}

#[derive(Clone, Debug)]
struct Statement {
    compact: String,
    kind: StatementKind,
}

/// An ID's event and each statement since, all checked. Anyone can check one with nothing but itself,
/// so a host's word adds nothing: it can only show an older one, which is why a reader keeps the
/// newest it has seen with [`Self::newest_of`].
#[derive(Clone, Debug)]
pub struct Identity {
    raw: Vec<u8>,
    id: SplintId,
    current: Epoch,
    earlier: Vec<Epoch>,
    /// The keys that count now, in order: the current epoch's key unless it was removed, then each
    /// added key still counting.
    keys: Vec<OwnerKey>,
    statements: Vec<Statement>,
}

impl Identity {
    pub fn create(
        key: &SigningKey,
        seal: &SealPublicKey,
        recovery: RecoveryRule,
    ) -> Result<Self, Error> {
        Self::for_key(&key.public_key(), seal, recovery)
    }

    /// The same ID from the public half alone, since nothing in the event is signed. An owner's device
    /// uses this to authorize an agent whose private key it never sees.
    pub fn for_key(
        key: &PublicKey,
        seal: &SealPublicKey,
        recovery: RecoveryRule,
    ) -> Result<Self, Error> {
        let raw = serde_json::to_vec(&IdentityEvent {
            v: EVENT_VERSION,
            alg: ALG.to_owned(),
            key: jws::encode(key.as_bytes()),
            rp: None,
            seal: seal.encoded(),
            recovery,
        })
        .map_err(|_| Error::Malformed)?;
        Self::parse(&raw)
    }

    /// An owner's ID whose key is a passkey made for `rp`. What it signs verifies only as a WebAuthn
    /// assertion for that RP ID, and it can't act as an agent.
    pub fn for_passkey(
        key: &PublicKey,
        rp: &RpId,
        seal: &SealPublicKey,
        recovery: RecoveryRule,
    ) -> Result<Self, Error> {
        let raw = serde_json::to_vec(&IdentityEvent {
            v: PASSKEY_EVENT_VERSION,
            alg: PASSKEY_ALG.to_owned(),
            key: jws::encode(key.as_bytes()),
            rp: Some(rp.as_str().to_owned()),
            seal: seal.encoded(),
            recovery,
        })
        .map_err(|_| Error::Malformed)?;
        Self::parse(&raw)
    }

    fn starting(raw: &[u8], id: SplintId, epoch: Epoch) -> Self {
        Self {
            raw: raw.to_vec(),
            id,
            keys: vec![epoch.key.clone()],
            current: epoch,
            earlier: Vec::new(),
            statements: Vec::new(),
        }
    }

    /// An event with nothing after it. Only the exact bytes `create` writes are valid, so a key has
    /// one ID and every event is the same small size. A sender's identity is stored with each of its
    /// messages, so one it could pad would make a page of the recipient's inbox too large for Signet
    /// to read.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let event: IdentityEvent = serde_json::from_slice(raw).map_err(|_| Error::Malformed)?;
        let kind = KeyKind::of_event(event.v, &event.alg, event.rp.as_deref())?;
        event.recovery.check()?;
        let key = PublicKey::from_bytes(&jws::decode(&event.key)?)?;
        event.recovery.check_apart_from(&key)?;
        let seal = sealing_key_apart(&event.seal, &key)?;
        if serde_json::to_vec(&event).map_err(|_| Error::Malformed)? != raw {
            return Err(Error::Malformed);
        }
        let epoch = Epoch {
            key: OwnerKey { point: key, kind },
            seal: Some(seal),
            rule: event.recovery,
            added: Vec::new(),
        };
        Ok(Self::starting(raw, id_of(raw), epoch))
    }

    /// The identity a one-use link's key has, from its public half.
    pub fn guest(key: &PublicKey) -> Result<Self, Error> {
        let raw = serde_json::to_vec(&GuestEvent {
            v: GUEST_EVENT_VERSION,
            role: GUEST_ROLE.to_owned(),
            alg: ALG.to_owned(),
            key: jws::encode(key.as_bytes()),
        })
        .map_err(|_| Error::Malformed)?;
        Self::parse_guest(&raw)
    }

    /// Only the exact bytes [`Self::guest`] writes are valid, so a key has one guest ID.
    pub fn parse_guest(raw: &[u8]) -> Result<Self, Error> {
        let event: GuestEvent = serde_json::from_slice(raw).map_err(|_| Error::Malformed)?;
        if event.v != GUEST_EVENT_VERSION || event.role != GUEST_ROLE || event.alg != ALG {
            return Err(Error::Malformed);
        }
        let key = PublicKey::from_bytes(&jws::decode(&event.key)?)?;
        if serde_json::to_vec(&event).map_err(|_| Error::Malformed)? != raw {
            return Err(Error::Malformed);
        }
        let epoch = Epoch {
            key: OwnerKey {
                point: key,
                kind: KeyKind::Es256,
            },
            seal: None,
            rule: RecoveryRule::NoRecovery,
            added: Vec::new(),
        };
        let id = SplintId(format!("{GUEST_ID_PREFIX}{}", sha256_hex(raw)));
        Ok(Self::starting(raw, id, epoch))
    }

    pub fn guest_from_encoded(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_ENCODED_CHARS {
            return Err(Error::Malformed);
        }
        Self::parse_guest(&jws::decode(text)?)
    }

    /// Whether this ID stands in for an owner who hasn't confirmed yet: its rule commits to no backup
    /// anyone can hold, so it was never recovered and never can be. An agent acting for one acts for
    /// nobody who has signed anything, so no owner's signature of its counts anywhere.
    pub fn is_unconfirmed_owner(&self) -> bool {
        self.statements.is_empty()
            && self.current.rule == RecoveryRule::unconfirmed_owner(&self.current.key.point)
    }

    /// Whether this ID has no recovery code yet: its rule is still [`RecoveryRule::later`], so nothing
    /// can recover it until a key that counts sets one.
    pub fn recovery_is_later(&self) -> bool {
        self.current.rule == RecoveryRule::later(&self.current.key.point)
    }

    /// Whether whoever holds `key` began this ID's history: its event names `key`, as a file key, and
    /// its first statement is one only a key that counts signs, which at that point is `key` alone.
    /// Nothing in an event is signed, so anyone can make one naming any key under a rule of their own,
    /// and a first statement that's a recovery is signed by that rule's backup, which says nothing of
    /// `key`. So is an event with nothing after it.
    pub fn rooted_in(&self, key: &PublicKey) -> bool {
        let event = self.earlier.first().unwrap_or(&self.current);
        event.key.point == *key
            && event.key.kind == KeyKind::Es256
            && self
                .statements
                .first()
                .is_some_and(|first| first.kind != StatementKind::Recovery)
    }

    /// Whether this answers one request through a link, with no owner behind it.
    pub fn is_guest(&self) -> bool {
        self.current.rule == RecoveryRule::NoRecovery
    }

    /// Whether this ID can be taken as an agent's. Only an owner's key may be a passkey, only an
    /// owner's ID may have more than one key, and only an owner's sets a recovery rule later, so an ID
    /// with any statement but a recovery is an owner's.
    pub fn may_act_as_agent(&self) -> bool {
        self.current.key.kind == KeyKind::Es256 && !self.has_key_statements()
    }

    fn has_key_statements(&self) -> bool {
        self.statements
            .iter()
            .any(|statement| statement.kind != StatementKind::Recovery)
    }

    /// What an agent signs is refused from an ID that added or removed a key, whatever key signed it,
    /// so a key an owner added never signs as an agent, even where no binding is read. An access proof
    /// is the exception, as any key of an owner's signs one to read what a host keeps for them. It
    /// moves nothing, and a host takes an agent's copy with a key statement only after a recovery its
    /// backup signed, which already makes whoever holds that backup the agent.
    fn signs_as(&self, typ: &str) -> Result<(), Error> {
        if !jws::is_owner_type(typ) && typ != crate::proof::ACCESS_TYPE && self.has_key_statements()
        {
            return Err(Error::WrongSigner);
        }
        Ok(())
    }

    pub fn from_encoded(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_ENCODED_CHARS {
            return Err(Error::Malformed);
        }
        let mut parts = text.split(STATEMENT_SEPARATOR);
        let event = parts.next().ok_or(Error::Malformed)?;
        let mut identity = Self::parse(&jws::decode(event)?)?;
        for statement in parts {
            identity.take_statement(statement)?;
        }
        Ok(identity)
    }

    /// The ID an encoded identity names, from its event's bytes alone, before any of it is checked.
    /// It's only for finding what to check it against, so a lookup that finds nothing ends it with no
    /// signature checked. It's the ID [`Self::from_encoded`] gives, whenever that succeeds.
    pub fn claimed_id(text: &str) -> Result<SplintId, Error> {
        if text.len() > MAX_ENCODED_CHARS {
            return Err(Error::Malformed);
        }
        let event = text
            .split(STATEMENT_SEPARATOR)
            .next()
            .ok_or(Error::Malformed)?;
        Ok(id_of(&jws::decode(event)?))
    }

    pub fn encoded(&self) -> String {
        let mut text = jws::encode(&self.raw);
        for statement in &self.statements {
            text.push(STATEMENT_SEPARATOR);
            text.push_str(&statement.compact);
        }
        text
    }

    pub fn id(&self) -> &SplintId {
        &self.id
    }

    /// The keys that count now, the event's or newest recovery's first unless it was removed.
    pub fn keys(&self) -> &[OwnerKey] {
        &self.keys
    }

    /// The one key that counts now, for an ID that has one: every agent's, and an owner's who hasn't
    /// added a key. An owner with more than one is `WrongSigner`, so code that assumes one key fails
    /// rather than picking one.
    pub fn sole_key(&self) -> Result<&PublicKey, Error> {
        match self.keys.as_slice() {
            [only] => Ok(&only.point),
            _ => Err(Error::WrongSigner),
        }
    }

    /// The event's and each recovery's, oldest first.
    fn epochs(&self) -> impl Iterator<Item = &Epoch> {
        self.earlier.iter().chain([&self.current])
    }

    /// Every key this copy's chain has had, oldest first: each epoch's own, then what it added.
    fn every_key(&self) -> impl Iterator<Item = &OwnerKey> {
        self.epochs()
            .flat_map(|epoch| std::iter::once(&epoch.key).chain(&epoch.added))
    }

    /// The name of each sign-in since the newest recovery, or the event if there's none: the one it
    /// named, then every one added since, removed or not. A contact's 48-hour guard goes by these, so
    /// a thief who adds a sign-in, moves the agent with it and removes it is still seen.
    pub fn sign_ins_since_recovery(&self) -> Vec<String> {
        std::iter::once(&self.current.key)
            .chain(&self.current.added)
            .map(OwnerKey::name)
            .collect()
    }

    /// Whether this ID's key is, or ever was, this one, so a key one job uses can't be given another.
    pub(crate) fn has_had_key(&self, key: &PublicKey) -> bool {
        self.every_key().any(|had| &had.point == key)
    }

    /// The RP ID of the first key that counts now, if it's a passkey, which says how what's prepared
    /// for an owner to sign is headed. It's the key the event or newest recovery named unless that was
    /// removed, so an owner left with a file key isn't handed inputs only a passkey signs. Only an
    /// owner's may be a passkey: anything that takes an ID as an agent refuses one through
    /// [`Self::may_act_as_agent`].
    pub fn passkey_rp(&self) -> Option<&RpId> {
        self.keys.first().and_then(OwnerKey::passkey_rp)
    }

    /// The payload of something one of this ID's keys signed, checked the one way that key signs: an
    /// ES256 signature for a file key, a WebAuthn assertion for a passkey. The header has to say the
    /// same, and the signer's ID decides, so no caller can choose the check. Anything arriving now is
    /// checked with this, under the keys that count now.
    pub(crate) fn verify(&self, compact: &str, typ: &str) -> Result<Vec<u8>, Error> {
        self.signs_as(typ)?;
        let parts = jws::parse(compact, typ)?;
        signed_by_one_of(&parts, &self.keys)?;
        Ok(parts.payload)
    }

    /// The same under any key this copy's chain has had, for re-reading what was signed before a
    /// recovery or a removal. A stolen key can date a signature as it likes, so this is only for
    /// history a reader already took in.
    pub(crate) fn verify_under_any_key(&self, compact: &str, typ: &str) -> Result<Vec<u8>, Error> {
        self.signs_as(typ)?;
        let parts = jws::parse(compact, typ)?;
        if self.every_key().any(|key| {
            signed_by(parts.signing_input, &parts.signature, &key.point, &key.kind).is_ok()
        }) {
            return Ok(parts.payload);
        }
        Err(Error::BadSignature)
    }

    /// The key to seal to now. A guest has none.
    pub fn seal_key(&self) -> Option<&SealPublicKey> {
        self.current.seal.as_ref()
    }

    pub fn rule(&self) -> &RecoveryRule {
        &self.current.rule
    }

    /// The keys this ID had when its rule committed to this backup, or `None` if it never has. A vouch
    /// by that backup names them, so whoever held an earlier backup can't recover the ID onto keys of
    /// their own, committing to this backup, and have what it vouched for count for their copy.
    pub(crate) fn keys_when_committed_to(&self, backup: &PublicKey) -> Option<AgentKeys> {
        self.epochs()
            .find(|epoch| epoch.rule.accepts(backup))
            .and_then(|epoch| {
                Some(AgentKeys {
                    key: epoch.key.point.clone(),
                    seal: epoch.seal.clone()?,
                })
            })
    }

    /// The keys that count now, as one. Only an ID that may act as an agent has them.
    pub fn agent_keys(&self) -> Option<AgentKeys> {
        if !self.may_act_as_agent() {
            return None;
        }
        Some(AgentKeys {
            key: self.current.key.point.clone(),
            seal: self.current.seal.clone()?,
        })
    }

    pub fn recoveries(&self) -> usize {
        self.count(StatementKind::Recovery)
    }

    /// How many more keys this ID can add before its next recovery.
    pub fn additions_left(&self) -> usize {
        MAX_ADDITIONS.saturating_sub(self.current.added.len())
    }

    /// Every statement after the event, of any kind.
    pub fn statements(&self) -> usize {
        self.statements.len()
    }

    fn count(&self, kind: StatementKind) -> usize {
        self.statements
            .iter()
            .filter(|statement| statement.kind == kind)
            .count()
    }

    /// Whether a backup key is the one this ID's rule commits to. An untested backup isn't recovery.
    pub fn check_backup(&self, backup: &PublicKey) -> Result<(), Error> {
        if self.current.rule.accepts(backup) {
            Ok(())
        } else {
            Err(Error::ProofMismatch)
        }
    }

    /// Names this ID's next key and rule. It's signed by the backup key, and the result is checked
    /// the way a reader will check it, so a key that isn't the backup gets nothing.
    pub fn recover(
        &self,
        backup: &SigningKey,
        key: &PublicKey,
        seal: &SealPublicKey,
        recovery: RecoveryRule,
        now: u64,
    ) -> Result<Self, Error> {
        self.recover_to(backup, key, None, seal, recovery, now)
    }

    /// The same, naming a passkey made for `rp` as the next key, so an owner with a file key can move
    /// to one. [`Self::recover`] moves back. The backup stays a file key either way.
    pub fn recover_to_passkey(
        &self,
        backup: &SigningKey,
        key: &PublicKey,
        rp: &RpId,
        seal: &SealPublicKey,
        recovery: RecoveryRule,
        now: u64,
    ) -> Result<Self, Error> {
        self.recover_to(backup, key, Some(rp), seal, recovery, now)
    }

    fn recover_to(
        &self,
        backup: &SigningKey,
        key: &PublicKey,
        rp: Option<&RpId>,
        seal: &SealPublicKey,
        recovery: RecoveryRule,
        now: u64,
    ) -> Result<Self, Error> {
        let payload = serde_json::to_vec(&RecoveryPayload {
            v: rp.map_or(RECOVERY_VERSION, |_| PASSKEY_RECOVERY_VERSION),
            id: self.id.clone(),
            seq: self.next_seq(),
            prev: self.head_hash(),
            backup: jws::encode(backup.public_key().as_bytes()),
            alg: rp.map(|_| PASSKEY_ALG.to_owned()),
            key: jws::encode(key.as_bytes()),
            rp: rp.map(|rp| rp.as_str().to_owned()),
            seal: seal.encoded(),
            recovery,
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)?;
        self.with_statement(&jws::sign(backup, RECOVERY_TYPE, &payload)?)
    }

    /// What adding `key` signs, for a passkey to sign as WA256 or a file key as ES256. `rp` names a
    /// passkey.
    pub fn key_add_payload(
        &self,
        by: &OwnerKey,
        key: &PublicKey,
        rp: Option<&RpId>,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&KeyAddPayload {
            v: rp.map_or(KEY_ADD_VERSION, |_| PASSKEY_ADD_VERSION),
            id: self.id.clone(),
            seq: self.next_seq(),
            prev: self.head_hash(),
            by: by.name(),
            alg: rp.map(|_| PASSKEY_ALG.to_owned()),
            key: jws::encode(key.as_bytes()),
            rp: rp.map(|rp| rp.as_str().to_owned()),
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)
    }

    /// What removing the key named `key` signs.
    pub fn key_remove_payload(&self, by: &OwnerKey, key: &str, now: u64) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&KeyRemovePayload {
            v: KEY_REMOVE_VERSION,
            id: self.id.clone(),
            seq: self.next_seq(),
            prev: self.head_hash(),
            by: by.name(),
            key: key.to_owned(),
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)
    }

    /// Adds the file key `key`, signed by `signer`, a file key that counts now, and by `key` itself.
    pub fn add_key(&self, signer: &SigningKey, key: &SigningKey, now: u64) -> Result<Self, Error> {
        let by = self.counting(signer)?;
        let payload = self.key_add_payload(by, &key.public_key(), None, now)?;
        let signed = jws::sign(signer, KEY_ADD_TYPE, &payload)?;
        let added = jws::signature_over(key, signed_part(&signed))?;
        self.with_statement(&format!("{signed}.{added}"))
    }

    /// What a new sign-in on another device hands a key that counts: the addition of `key`, naming
    /// the key `by` names to sign it, as its signing input and `key`'s own signature over that,
    /// `header.payload.added`. It adds nothing until [`Self::add_offered`] signs it.
    pub fn offer_key(&self, by: &str, key: &SigningKey, now: u64) -> Result<String, Error> {
        let by = self
            .keys
            .iter()
            .find(|counting| counting.name() == by)
            .ok_or(Error::WrongSigner)?;
        let payload = self.key_add_payload(by, &key.public_key(), None, now)?;
        let input = jws::signing_input(jws::Alg::Es256, KEY_ADD_TYPE, &payload)?;
        Ok(format!("{input}.{}", jws::signature_over(key, &input)?))
    }

    /// The key an offer would add, read from it unchecked, so a person is shown what they'd sign
    /// for before anything is.
    pub fn offered_key(offer: &str) -> Result<PublicKey, Error> {
        let payload: KeyAddPayload =
            serde_json::from_slice(&jws::unverified_payload(offer, KEY_ADD_TYPE)?)
                .map_err(|_| Error::Malformed)?;
        if payload.rp.is_some() {
            return Err(Error::Malformed);
        }
        PublicKey::from_encoded(&payload.key)
    }

    /// Signs an addition [`Self::offer_key`] made, with `signer`, a key that counts now, which the
    /// offer has to name, and checks the whole as a reader does. So a key is added only by a device
    /// that holds it and one that already counts, each signing the same bytes.
    pub fn add_offered(&self, signer: &SigningKey, offer: &str) -> Result<Self, Error> {
        let by = self.counting(signer)?;
        let input = signed_part(offer);
        let added = offer
            .get(input.len()..)
            .and_then(|rest| rest.strip_prefix('.'))
            .filter(|added| !added.is_empty() && !added.contains('.'))
            .ok_or(Error::Malformed)?;
        let payload: KeyAddPayload =
            serde_json::from_slice(&jws::unverified_payload(offer, KEY_ADD_TYPE)?)
                .map_err(|_| Error::Malformed)?;
        if payload.by != by.name() {
            return Err(Error::WrongSigner);
        }
        let signed = jws::sign_input(signer, input)?;
        self.with_statement(&format!("{signed}.{added}"))
    }

    /// What setting the recovery rule signs, for a passkey to sign as WA256 or a file key as ES256.
    pub fn recovery_rule_payload(
        &self,
        by: &OwnerKey,
        recovery: &RecoveryRule,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&RecoveryRulePayload {
            v: RECOVERY_RULE_VERSION,
            id: self.id.clone(),
            seq: self.next_seq(),
            prev: self.head_hash(),
            by: by.name(),
            recovery: recovery.clone(),
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)
    }

    /// Sets the recovery rule of an ID made without one, signed by `signer`, a file key that counts.
    pub fn set_recovery_rule(
        &self,
        signer: &SigningKey,
        recovery: &RecoveryRule,
        now: u64,
    ) -> Result<Self, Error> {
        let by = self.counting(signer)?;
        let payload = self.recovery_rule_payload(by, recovery, now)?;
        self.with_statement(&jws::sign(signer, RECOVERY_RULE_TYPE, &payload)?)
    }

    /// Removes the key named `key`, signed by `signer`, a file key that counts now.
    pub fn remove_key(&self, signer: &SigningKey, key: &str, now: u64) -> Result<Self, Error> {
        let by = self.counting(signer)?;
        let payload = self.key_remove_payload(by, key, now)?;
        self.with_statement(&jws::sign(signer, KEY_REMOVE_TYPE, &payload)?)
    }

    fn counting(&self, signer: &SigningKey) -> Result<&OwnerKey, Error> {
        let point = signer.public_key();
        self.keys
            .iter()
            .find(|key| key.point == point)
            .ok_or(Error::WrongSigner)
    }

    /// This ID with one more statement, of any kind, checked as a reader checks it.
    pub fn with_statement(&self, compact: &str) -> Result<Self, Error> {
        let mut next = self.clone();
        next.take_statement(compact)?;
        Ok(next)
    }

    fn next_seq(&self) -> usize {
        self.statements.len().saturating_add(1)
    }

    /// The hash of this ID's own event, which is what its ID is made of and what a history starts from.
    pub(crate) fn event_hash(&self) -> String {
        sha256_hex(&self.raw)
    }

    /// This ID as it was after `recoveries` of them, for checking what was signed then. Its keys are
    /// every key that counted at any point before the next recovery, so it's only for reading back
    /// history. Everything in it was checked when it was read, so nothing needs checking again.
    pub(crate) fn as_of(&self, recoveries: usize) -> Option<Self> {
        let epochs: Vec<&Epoch> = self.epochs().collect();
        let current = (*epochs.get(recoveries)?).clone();
        let mut seen = 0_usize;
        let statements = self
            .statements
            .iter()
            .take_while(|statement| {
                if statement.kind == StatementKind::Recovery {
                    seen = seen.saturating_add(1);
                }
                seen <= recoveries
            })
            .cloned()
            .collect();
        Some(Self {
            raw: self.raw.clone(),
            id: self.id.clone(),
            keys: std::iter::once(&current.key)
                .chain(&current.added)
                .cloned()
                .collect(),
            earlier: epochs
                .iter()
                .take(recoveries)
                .map(|&epoch| epoch.clone())
                .collect(),
            current,
            statements,
        })
    }

    /// The hash of its newest statement, which names this copy of an ID among any others that part ways.
    pub fn head_hash(&self) -> String {
        match self.statements.last() {
            Some(statement) => sha256_hex(signed_part(&statement.compact).as_bytes()),
            None => sha256_hex(&self.raw),
        }
    }

    /// The hash of its newest recovery, or of its event if it has none, as `prev` names either. It's
    /// what a history's `key` event names, so an owner adding or removing a key after a recovery
    /// leaves that event as it was.
    pub fn recovery_head(&self) -> String {
        match self
            .statements
            .iter()
            .rev()
            .find(|statement| statement.kind == StatementKind::Recovery)
        {
            Some(statement) => sha256_hex(signed_part(&statement.compact).as_bytes()),
            None => sha256_hex(&self.raw),
        }
    }

    fn take_statement(&mut self, statement: &str) -> Result<(), Error> {
        match StatementKind::of(statement)? {
            StatementKind::Recovery => self.take_recovery(statement),
            StatementKind::KeyAdd => self.take_key_add(statement),
            StatementKind::KeyRemove => self.take_key_remove(statement),
            StatementKind::RecoveryRule => self.take_recovery_rule(statement),
        }
    }

    /// Whether a statement names this ID and follows this copy's newest, which every kind has to.
    fn follows(&self, id: &SplintId, seq: usize, prev: &str) -> Result<(), Error> {
        if id != &self.id || seq != self.next_seq() || prev != self.head_hash() {
            return Err(Error::ProofMismatch);
        }
        Ok(())
    }

    /// Whether a key statement leaves room in the encoded ID for every recovery it has left, so adding
    /// and removing sign-ins, however often a thief does it, never fills an ID its owner can't recover.
    fn leaves_room_after(&self, statement: &str) -> Result<(), Error> {
        let left = MAX_RECOVERIES.saturating_sub(self.recoveries());
        let used = self
            .statements
            .iter()
            .fold(jws::encode(&self.raw).len(), |sum, one| {
                sum.saturating_add(one.compact.len()).saturating_add(1)
            });
        let after = used
            .saturating_add(statement.len())
            .saturating_add(1)
            .saturating_add(left.saturating_mul(RECOVERY_ROOM));
        if after > MAX_ENCODED_CHARS {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn push(&mut self, statement: &str, kind: StatementKind) {
        self.statements.push(Statement {
            compact: statement.to_owned(),
            kind,
        });
    }

    fn take_recovery(&mut self, statement: &str) -> Result<(), Error> {
        if self.recoveries() >= MAX_RECOVERIES {
            return Err(Error::Malformed);
        }
        let claimed = jws::unverified_payload(statement, RECOVERY_TYPE)?;
        let payload: RecoveryPayload =
            serde_json::from_slice(&claimed).map_err(|_| Error::Malformed)?;
        if serde_json::to_vec(&payload).map_err(|_| Error::Malformed)? != claimed {
            return Err(Error::Malformed);
        }
        if payload.issued_at > MAX_ISSUED_AT {
            return Err(Error::Malformed);
        }
        let kind = KeyKind::of_recovery(payload.v, payload.alg.as_deref(), payload.rp.as_deref())?;
        self.follows(&payload.id, payload.seq, &payload.prev)?;
        let backup = PublicKey::from_encoded(&payload.backup)?;
        if !self.current.rule.accepts(&backup) {
            return Err(Error::WrongSigner);
        }
        jws::verify(statement, &backup, RECOVERY_TYPE)?;
        payload.recovery.check()?;
        let key = PublicKey::from_encoded(&payload.key)?;
        payload.recovery.check_apart_from(&key)?;
        // Whoever recovers holds the code, so the next rule is a real one: only an ID's event goes
        // without, which keeps a rule statement to one per ID.
        if payload.recovery == RecoveryRule::later(&key) {
            return Err(Error::Malformed);
        }
        let seal = sealing_key_apart(&payload.seal, &key)?;
        // A key replaced because it was lost or stolen went with the sealing key beside it, so a new
        // signing key needs a sealing key this ID has never had, or a thief could still read what's
        // sealed to it. A transfer keeping the signing key may keep the sealing key too. Both are read
        // against the key the event or the newest recovery named, whatever was added since.
        let new_signer = key != self.current.key.point;
        // One point is one key, held one way: a passkey's can't also be a file's.
        if !new_signer && kind != self.current.key.kind {
            return Err(Error::Malformed);
        }
        if new_signer
            && self
                .epochs()
                .any(|epoch| epoch.seal.as_ref() == Some(&seal))
        {
            return Err(Error::Malformed);
        }
        // A backup key has shown its public half, and might have been copied while it was in use,
        // so each recovery has to name one this ID has never had.
        if self.epochs().any(|epoch| epoch.rule == payload.recovery) {
            return Err(Error::Malformed);
        }
        // Nor commit to a key this ID has had, or seal to one, so a key's name and a commitment never
        // mean the same key, and a device that held a key never holds the backup or the sealing key.
        if self.every_key().any(|had| {
            payload.recovery.accepts(&had.point) || had.point.as_bytes() == seal.as_bytes()
        }) {
            return Err(Error::Malformed);
        }
        let key = OwnerKey { point: key, kind };
        let next = Epoch {
            key: key.clone(),
            seal: Some(seal),
            rule: payload.recovery,
            added: Vec::new(),
        };
        // The backup overrides every key: only the one it names counts after it.
        self.earlier
            .push(std::mem::replace(&mut self.current, next));
        self.keys = vec![key];
        self.push(statement, StatementKind::Recovery);
        Ok(())
    }

    /// The key that counts now that a key statement names as its signer, checked under that key alone.
    fn signer_of(&self, statement: &str, typ: &str, by: &str) -> Result<&OwnerKey, Error> {
        // A stand-in's key is on its agent's own machine, and no owner has signed for it.
        if self.is_unconfirmed_owner() {
            return Err(Error::Malformed);
        }
        let signer = self
            .keys
            .iter()
            .find(|key| key.name() == by)
            .ok_or(Error::WrongSigner)?;
        let parts = jws::parse(statement, typ)?;
        signed_by(
            parts.signing_input,
            &parts.signature,
            &signer.point,
            &signer.kind,
        )?;
        Ok(signer)
    }

    fn take_key_add(&mut self, statement: &str) -> Result<(), Error> {
        // The key that counts signs as any statement's does, and the added key signs the same input.
        let (signed, added_signature) = statement.rsplit_once('.').ok_or(Error::Malformed)?;
        let claimed = jws::unverified_payload(signed, KEY_ADD_TYPE)?;
        let payload: KeyAddPayload =
            serde_json::from_slice(&claimed).map_err(|_| Error::Malformed)?;
        if serde_json::to_vec(&payload).map_err(|_| Error::Malformed)? != claimed
            || !is_sha256_hex(&payload.by)
            || payload.issued_at > MAX_ISSUED_AT
        {
            return Err(Error::Malformed);
        }
        let kind = KeyKind::of_addition(payload.v, payload.alg.as_deref(), payload.rp.as_deref())?;
        let point = PublicKey::from_encoded(&payload.key)?;
        // The same curve check a sealing key gets: a signing key that isn't on the curve verifies
        // nothing, and an ID shouldn't carry one.
        SealPublicKey::from_bytes(point.as_bytes())?;
        self.follows(&payload.id, payload.seq, &payload.prev)?;
        // Any key that counts adds one, a passkey at a host's name included: an owner who signs in
        // on a host's page already trusts whoever serves it with everything that passkey signs.
        self.signer_of(signed, KEY_ADD_TYPE, &payload.by)?;
        // Nobody adds a key they don't hold. A key that counts alone could add any point, an agent's own
        // key among them, which anyone can read; this way only whoever holds that key outside Signet
        // can, and Signet signs nothing an owner signs with it.
        let alg = match kind {
            KeyKind::Es256 => jws::Alg::Es256,
            KeyKind::Passkey(_) => jws::Alg::Wa256,
        };
        let added = jws::signature_segment(added_signature, alg)?;
        signed_by(signed_part(signed), &added, &point, &kind)?;
        // A point this ID has had, or the backup it commits to now, would give one key two jobs.
        let sealed_to = self.epochs().any(|epoch| {
            epoch.seal.as_ref().map(SealPublicKey::as_bytes) == Some(point.as_bytes())
        });
        if self.has_had_key(&point) || sealed_to || self.current.rule.accepts(&point) {
            return Err(Error::Malformed);
        }
        if self.keys.len() >= MAX_KEYS || self.current.added.len() >= MAX_ADDITIONS {
            return Err(Error::Malformed);
        }
        self.leaves_room_after(statement)?;
        let key = OwnerKey { point, kind };
        self.current.added.push(key.clone());
        self.keys.push(key);
        self.push(statement, StatementKind::KeyAdd);
        Ok(())
    }

    fn take_key_remove(&mut self, statement: &str) -> Result<(), Error> {
        let claimed = jws::unverified_payload(statement, KEY_REMOVE_TYPE)?;
        let payload: KeyRemovePayload =
            serde_json::from_slice(&claimed).map_err(|_| Error::Malformed)?;
        if serde_json::to_vec(&payload).map_err(|_| Error::Malformed)? != claimed
            || payload.v != KEY_REMOVE_VERSION
            || !is_sha256_hex(&payload.by)
            || !is_sha256_hex(&payload.key)
            || payload.issued_at > MAX_ISSUED_AT
        {
            return Err(Error::Malformed);
        }
        self.follows(&payload.id, payload.seq, &payload.prev)?;
        self.signer_of(statement, KEY_REMOVE_TYPE, &payload.by)?;
        let at = self
            .keys
            .iter()
            .position(|key| key.name() == payload.key)
            .ok_or(Error::Malformed)?;
        if self.keys.len() < 2 {
            return Err(Error::Malformed);
        }
        self.leaves_room_after(statement)?;
        self.keys.remove(at);
        self.push(statement, StatementKind::KeyRemove);
        Ok(())
    }

    fn take_recovery_rule(&mut self, statement: &str) -> Result<(), Error> {
        let claimed = jws::unverified_payload(statement, RECOVERY_RULE_TYPE)?;
        let payload: RecoveryRulePayload =
            serde_json::from_slice(&claimed).map_err(|_| Error::Malformed)?;
        if serde_json::to_vec(&payload).map_err(|_| Error::Malformed)? != claimed
            || payload.v != RECOVERY_RULE_VERSION
            || !is_sha256_hex(&payload.by)
            || payload.issued_at > MAX_ISSUED_AT
        {
            return Err(Error::Malformed);
        }
        payload.recovery.check()?;
        self.follows(&payload.id, payload.seq, &payload.prev)?;
        self.signer_of(statement, RECOVERY_RULE_TYPE, &payload.by)?;
        // Once, while there's none: a key that counts can't move a recovery code that's set, or a
        // thief holding one could take the ID from the owner for good.
        if !self.recovery_is_later() {
            return Err(Error::Malformed);
        }
        // Nor commit to a rule this ID has had, a key it has had or a key it seals to, so a device
        // that held a key never holds the backup, as a recovery's next rule can't.
        let commits_to = |bytes: &[u8]| matches!(&payload.recovery, RecoveryRule::BackupKey { commitment } if *commitment == sha256_hex(bytes));
        if self.epochs().any(|epoch| {
            epoch.rule == payload.recovery
                || epoch
                    .seal
                    .as_ref()
                    .is_some_and(|seal| commits_to(seal.as_bytes()))
        }) || self.every_key().any(|had| commits_to(had.point.as_bytes()))
        {
            return Err(Error::Malformed);
        }
        self.leaves_room_after(statement)?;
        self.current.rule = payload.recovery;
        self.push(statement, StatementKind::RecoveryRule);
        Ok(())
    }

    /// Whether this copy went through a head with this hash on its way here, so an older copy of it
    /// isn't a rival to it.
    pub fn was_at(&self, head: &str) -> bool {
        sha256_hex(&self.raw) == head
            || self
                .statements
                .iter()
                .any(|statement| sha256_hex(signed_part(&statement.compact).as_bytes()) == head)
    }

    /// Whether this is `older`, or `older` with more statements after it.
    pub fn extends(&self, older: &Self) -> bool {
        self.id == older.id
            && self.statements.len() >= older.statements.len()
            && self.shared_with(older) == older.statements.len()
    }

    /// How many statements two copies share before they part ways.
    fn shared_with(&self, other: &Self) -> usize {
        self.statements
            .iter()
            .zip(&other.statements)
            .take_while(|(a, b)| signed_part(&a.compact) == signed_part(&b.compact))
            .count()
    }

    fn recovered_after(&self, shared: usize) -> bool {
        self.statements
            .iter()
            .skip(shared)
            .any(|statement| statement.kind == StatementKind::Recovery)
    }

    /// Whether a reader holding `held` takes this copy in its place: it extends `held`, or parts ways
    /// with it and has the only recovery since. The same copy changes nothing. One `held` extends is
    /// `Stale`, as it names a key given up or leaves one out. One that parts ways with `held` and
    /// doesn't win is `Forked`, which a host answers with a conflict, keeping what it holds, until it's
    /// signed again on top of that or a recovery settles it.
    pub fn replaces(&self, held: &Self) -> Result<bool, Error> {
        if self.id != held.id {
            return Err(Error::ProofMismatch);
        }
        if held.extends(self) {
            return if self.statements.len() == held.statements.len() {
                Ok(false)
            } else {
                Err(Error::Stale)
            };
        }
        if self.extends(held) {
            return Ok(true);
        }
        let shared = self.shared_with(held);
        match (self.recovered_after(shared), held.recovered_after(shared)) {
            (true, false) => Ok(true),
            (false, true) | (true, true) | (false, false) => Err(Error::Forked),
        }
    }

    /// When the newest removal of a key was signed, by the owner's clock, if this copy has one. Every
    /// statement here was checked as it was read, so only its date is read again.
    pub fn last_key_removed_at(&self) -> Option<u64> {
        self.statements
            .iter()
            .rev()
            .filter(|statement| statement.kind == StatementKind::KeyRemove)
            .find_map(|statement| {
                let claimed = jws::unverified_payload(&statement.compact, KEY_REMOVE_TYPE).ok()?;
                serde_json::from_slice::<KeyRemovePayload>(&claimed).ok()
            })
            .map(|payload| payload.issued_at)
    }

    /// Whether a key that counted in `older` doesn't count in this copy, so what only it signed has to
    /// go, as what a recovery replaced goes.
    pub fn removed_since(&self, older: &Self) -> bool {
        older.keys.iter().any(|key| !self.keys.contains(key))
    }

    /// The key that counts now that signed this owner object, the first part of one in parts, if any.
    pub fn signer_of_object(&self, compact: &str) -> Option<&OwnerKey> {
        let owners = compact
            .split(crate::binding::PART_SEPARATOR)
            .next()
            .unwrap_or_default();
        let typ = jws::owner_type_of(owners)?;
        self.signs_as(typ).ok()?;
        let parts = jws::parse(owners, typ).ok()?;
        self.keys.iter().find(|key| {
            signed_by(parts.signing_input, &parts.signature, &key.point, &key.kind).is_ok()
        })
    }

    /// Whether one of the keys that count now signed this owner object, of whatever kind it is. Of one
    /// in parts, such as a binding, the first is the owner's and the one checked. It's only for going
    /// back over what was checked in full when it was taken in, once a key stopped counting, to drop
    /// what that key signed, for deciding to ask for a newer copy, and for refusing what an agent's own
    /// key signed as its owner's. It never lets anything in.
    pub fn signed_now(&self, compact: &str) -> bool {
        let owners = compact
            .split(crate::binding::PART_SEPARATOR)
            .next()
            .unwrap_or_default();
        jws::owner_type_of(owners).is_some_and(|typ| self.verify(owners, typ).is_ok())
    }

    /// Which of two copies of one ID to believe. An older copy changes nothing, so a host can't bring
    /// a stolen key back by showing one. Of two that part ways, the one with a recovery after they
    /// part wins, as the backup overrides any key. Otherwise nothing here can say which is real: two
    /// recoveries took the backup, and two branches of key statements took two keys of the owner's.
    pub fn newest_of(&self, other: &Self) -> Result<Self, Error> {
        if self.id != other.id {
            return Err(Error::ProofMismatch);
        }
        if other.extends(self) {
            return Ok(other.clone());
        }
        if self.extends(other) {
            return Ok(self.clone());
        }
        let shared = self.shared_with(other);
        match (self.recovered_after(shared), other.recovered_after(shared)) {
            (true, false) => Ok(self.clone()),
            (false, true) => Ok(other.clone()),
            (true, true) | (false, false) => Err(Error::Forked),
        }
    }
}

/// How `splint-signet look-at-keys` ends where an agent's key is gone or can't be used, which only new
/// keys put right. Anything else it can't start on it says in words, and new keys wouldn't help.
pub const AGENT_KEYS_LOST_EXIT: u8 = 3;

/// An agent's two public keys, as one word: the signing key, a dot, and the sealing key. It's what an
/// agent hands its owner to be authorized, and what an ID made by someone else's device commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentKeys {
    pub key: PublicKey,
    pub seal: SealPublicKey,
}

const AGENT_KEYS_SEPARATOR: char = '.';

impl AgentKeys {
    pub fn encoded(&self) -> String {
        format!(
            "{}{AGENT_KEYS_SEPARATOR}{}",
            self.key.encoded(),
            self.seal.encoded()
        )
    }

    pub fn from_encoded(text: &str) -> Result<Self, Error> {
        let (key, seal) = text
            .split_once(AGENT_KEYS_SEPARATOR)
            .ok_or(Error::Malformed)?;
        let key = PublicKey::from_encoded(key)?;
        let seal = sealing_key_apart(seal, &key)?;
        Ok(Self { key, seal })
    }

    /// The ID these keys have under this rule.
    pub fn identity(&self, recovery: RecoveryRule) -> Result<Identity, Error> {
        Identity::for_key(&self.key, &self.seal, recovery)
    }
}

/// Which of the keys that count made this signature: each is tried in turn. A malformed assertion is
/// malformed under every passkey alike, so the reason doesn't turn on which keys an ID has.
fn signed_by_one_of(parts: &jws::Parts<'_>, keys: &[OwnerKey]) -> Result<(), Error> {
    let mut refused = Error::BadSignature;
    for key in keys {
        match signed_by(parts.signing_input, &parts.signature, &key.point, &key.kind) {
            Ok(()) => return Ok(()),
            Err(Error::BadSignature) => {}
            Err(other) => refused = other,
        }
    }
    Err(refused)
}

/// Whether `key`, held as `kind` says, made this signature, and the header says it signs that way.
fn signed_by(
    input: &str,
    signature: &Signature<'_>,
    key: &PublicKey,
    kind: &KeyKind,
) -> Result<(), Error> {
    match (signature, kind) {
        (Signature::Es256(raw), KeyKind::Es256) => key.verify(input.as_bytes(), raw),
        (Signature::Passkey(segment), KeyKind::Passkey(rp)) => {
            passkey::verify(input, segment, key, rp)
        }
        (Signature::Es256(_) | Signature::Passkey(_), _) => Err(Error::BadSignature),
    }
}

/// A sealing key that isn't the signing key's own point, so one key never does both jobs.
fn sealing_key_apart(encoded: &str, key: &PublicKey) -> Result<SealPublicKey, Error> {
    let seal = SealPublicKey::from_encoded(encoded)?;
    if seal.as_bytes() == key.as_bytes() {
        return Err(Error::Malformed);
    }
    Ok(seal)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::authenticator::Authenticator;

    const NOW: u64 = 1_793_750_400;

    struct Holder {
        key: SigningKey,
        backup: SigningKey,
        identity: Identity,
    }

    fn holder() -> Holder {
        let key = SigningKey::generate().unwrap();
        let backup = SigningKey::generate().unwrap();
        let rule = RecoveryRule::backup_key(&backup.public_key());
        let identity = Identity::create(&key, &crate::test_seal(), rule).unwrap();
        Holder {
            key,
            backup,
            identity,
        }
    }

    fn fresh_rule() -> RecoveryRule {
        RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key())
    }

    /// A host looks an ID up by what it claims before checking anything, so the claim has to be the
    /// ID a check gives, recoveries and all, or a real agent would go unfound.
    #[test]
    fn the_id_an_identity_claims_is_the_one_it_checks_out_as() {
        let ana = holder();
        let recovered = ana
            .identity
            .recover(
                &ana.backup,
                &SigningKey::generate().unwrap().public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW,
            )
            .unwrap();
        for identity in [&ana.identity, &recovered] {
            let text = identity.encoded();
            assert_eq!(&Identity::claimed_id(&text).unwrap(), identity.id());
            assert_eq!(Identity::from_encoded(&text).unwrap().id(), identity.id());
        }
        // It's only a claim: a recovery nobody's backup signed leaves it, and fails the check.
        let forged = format!("{}~{}", ana.identity.encoded(), jws::encode(b"not signed"));
        assert_eq!(&Identity::claimed_id(&forged).unwrap(), ana.identity.id());
        assert!(Identity::from_encoded(&forged).is_err());
    }

    /// A stand-in for an owner who hasn't confirmed can't be recovered by anyone, even whoever holds
    /// its key, so it can never take back an agent its owner confirmed.
    #[test]
    fn an_unconfirmed_owner_is_known_by_its_key_alone_and_never_recovers() {
        let key = SigningKey::generate().unwrap();
        let rule = RecoveryRule::unconfirmed_owner(&key.public_key());
        let stand_in = Identity::create(&key, &crate::test_seal(), rule).unwrap();
        assert!(stand_in.is_unconfirmed_owner());
        assert!(!holder().identity.is_unconfirmed_owner());
        let read_back = Identity::from_encoded(&stand_in.encoded()).unwrap();
        assert!(read_back.is_unconfirmed_owner());
        // Someone else's tag names nobody's stand-in, and is just a backup nobody holds.
        let other = SigningKey::generate().unwrap().public_key();
        let borrowed = RecoveryRule::unconfirmed_owner(&other);
        let not_one = Identity::create(&key, &crate::test_seal(), borrowed).unwrap();
        assert!(!not_one.is_unconfirmed_owner());
        for signer in [&key, &SigningKey::generate().unwrap()] {
            let tried = stand_in.recover(
                signer,
                &key.public_key(),
                stand_in.seal_key().unwrap(),
                fresh_rule(),
                NOW,
            );
            assert_eq!(tried.err(), Some(Error::WrongSigner));
        }
    }

    /// Whoever took a key may hold the sealing key beside it, so replacing one replaces both.
    #[test]
    fn a_new_key_needs_a_new_sealing_key_and_a_transfer_may_keep_both() {
        let ana = holder();
        let old_seal = ana.identity.seal_key().unwrap().clone();
        let new_key = SigningKey::generate().unwrap().public_key();
        assert_eq!(
            ana.identity
                .recover(&ana.backup, &new_key, &old_seal, fresh_rule(), NOW)
                .err(),
            Some(Error::Malformed)
        );
        let new_seal = crate::test_seal();
        let recovered = ana
            .identity
            .recover(&ana.backup, &new_key, &new_seal, fresh_rule(), NOW)
            .unwrap();
        assert_eq!(recovered.seal_key(), Some(&new_seal));
        assert_eq!(recovered.id(), ana.identity.id());
        let kept = ana
            .identity
            .recover(
                &ana.backup,
                ana.identity.sole_key().unwrap(),
                &old_seal,
                fresh_rule(),
                NOW,
            )
            .unwrap();
        assert_eq!(kept.seal_key(), Some(&old_seal));
        // Read back from what travels, the same holds.
        let swapped = Identity::from_encoded(&recovered.encoded()).unwrap();
        assert_eq!(swapped.seal_key(), Some(&new_seal));
    }

    #[test]
    fn a_stolen_key_cant_recover() {
        let ana = holder();
        let thief = SigningKey::generate().unwrap();
        for signer in [&ana.key, &thief] {
            assert_eq!(
                ana.identity
                    .recover(
                        signer,
                        &thief.public_key(),
                        &crate::test_seal(),
                        fresh_rule(),
                        NOW
                    )
                    .err(),
                Some(Error::WrongSigner)
            );
        }
    }

    #[test]
    fn a_backup_works_once_and_the_next_rule_takes_over() {
        let ana = holder();
        let next_backup = SigningKey::generate().unwrap();
        let new_key = SigningKey::generate().unwrap();
        let once = ana
            .identity
            .recover(
                &ana.backup,
                &new_key.public_key(),
                &crate::test_seal(),
                RecoveryRule::backup_key(&next_backup.public_key()),
                NOW,
            )
            .unwrap();
        assert_eq!(
            once.recover(
                &ana.backup,
                &new_key.public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW
            )
            .err(),
            Some(Error::WrongSigner)
        );
        let twice = once
            .recover(
                &next_backup,
                &new_key.public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW,
            )
            .unwrap();
        assert_eq!(twice.recoveries(), 2);

        let same_rule = RecoveryRule::backup_key(&next_backup.public_key());
        assert_eq!(
            once.recover(
                &next_backup,
                &new_key.public_key(),
                &crate::test_seal(),
                same_rule,
                NOW
            )
            .err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn an_older_copy_cant_undo_a_recovery_and_a_fork_is_refused() {
        let ana = holder();
        let (first, second) = (
            SigningKey::generate().unwrap().public_key(),
            SigningKey::generate().unwrap().public_key(),
        );
        let recovered = ana
            .identity
            .recover(&ana.backup, &first, &crate::test_seal(), fresh_rule(), NOW)
            .unwrap();
        let older = Identity::from_encoded(&ana.identity.encoded()).unwrap();
        assert_eq!(
            recovered.newest_of(&older).unwrap().sole_key().unwrap(),
            &first
        );
        assert_eq!(
            older.newest_of(&recovered).unwrap().sole_key().unwrap(),
            &first
        );
        assert!(recovered.extends(&older) && !older.extends(&recovered));

        let forked = ana
            .identity
            .recover(&ana.backup, &second, &crate::test_seal(), fresh_rule(), NOW)
            .unwrap();
        assert_eq!(recovered.newest_of(&forked).err(), Some(Error::Forked));
        let other = holder();
        assert_eq!(
            recovered.newest_of(&other.identity).err(),
            Some(Error::ProofMismatch)
        );
    }

    #[test]
    fn an_id_can_be_recovered_only_so_many_times() {
        let ana = holder();
        let mut backup = ana.backup;
        let mut identity = ana.identity;
        let key = SigningKey::generate().unwrap().public_key();
        for _ in 0..MAX_RECOVERIES {
            let next = SigningKey::generate().unwrap();
            identity = identity
                .recover(
                    &backup,
                    &key,
                    &crate::test_seal(),
                    RecoveryRule::backup_key(&next.public_key()),
                    NOW,
                )
                .unwrap();
            backup = next;
        }
        assert_eq!(
            identity
                .recover(&backup, &key, &crate::test_seal(), fresh_rule(), NOW)
                .err(),
            Some(Error::Malformed)
        );
        let text = identity.encoded();
        assert!(text.len() < MAX_ENCODED_CHARS, "{}", text.len());
        assert!(Identity::from_encoded(&text).is_ok());
    }

    #[test]
    fn the_key_that_signs_cant_also_be_the_backup() {
        let key = SigningKey::generate().unwrap();
        assert_eq!(
            Identity::create(
                &key,
                &crate::test_seal(),
                RecoveryRule::backup_key(&key.public_key())
            )
            .err(),
            Some(Error::Malformed)
        );
        let ana = holder();
        let next = SigningKey::generate().unwrap().public_key();
        assert_eq!(
            ana.identity
                .recover(
                    &ana.backup,
                    &next,
                    &crate::test_seal(),
                    RecoveryRule::backup_key(&next),
                    NOW
                )
                .err(),
            Some(Error::Malformed)
        );
    }

    /// Something an owner key signs, to see which keys count.
    fn owner_object(key: &SigningKey) -> String {
        jws::sign(key, "splint-rules", br#"{"v":1}"#).unwrap()
    }

    fn counts_now(identity: &Identity, key: &SigningKey) -> bool {
        identity.verify(&owner_object(key), "splint-rules").is_ok()
    }

    fn owner_key_of(identity: &Identity, key: &SigningKey) -> OwnerKey {
        identity
            .keys()
            .iter()
            .find(|counting| counting.point() == &key.public_key())
            .unwrap()
            .clone()
    }

    /// An addition signed by any key at all, with no builder's check first, as a reader takes it.
    fn addition(
        identity: &Identity,
        signer: &SigningKey,
        by: &OwnerKey,
        key: &SigningKey,
    ) -> Result<Identity, Error> {
        let payload = identity
            .key_add_payload(by, &key.public_key(), None, NOW)
            .unwrap();
        let signed = jws::sign(signer, KEY_ADD_TYPE, &payload).unwrap();
        let added = jws::signature_over(key, signed_part(&signed)).unwrap();
        identity.with_statement(&format!("{signed}.{added}"))
    }

    /// A key added by one that counts signs at once, everywhere the copy travels; a removed key stops
    /// counting for what arrives now, and still reads back for what was signed before.
    #[test]
    fn an_added_key_counts_at_once_and_a_removed_one_only_reads_back() {
        let ana = holder();
        let laptop = SigningKey::generate().unwrap();
        let added = ana.identity.add_key(&ana.key, &laptop, NOW).unwrap();
        let read = Identity::from_encoded(&added.encoded()).unwrap();
        assert!(counts_now(&read, &ana.key) && counts_now(&read, &laptop));
        assert_eq!(read.sole_key().err(), Some(Error::WrongSigner));
        assert!(!read.may_act_as_agent() && read.agent_keys().is_none());

        let first = owner_key_of(&read, &ana.key).name();
        let removed = read.remove_key(&laptop, &first, NOW).unwrap();
        let read = Identity::from_encoded(&removed.encoded()).unwrap();
        assert!(!counts_now(&read, &ana.key) && counts_now(&read, &laptop));
        assert_eq!(read.sole_key().unwrap(), &laptop.public_key());
        assert!(
            read.verify_under_any_key(&owner_object(&ana.key), "splint-rules")
                .is_ok()
        );
        assert_eq!(read.recoveries(), 0);
        assert_eq!(read.statements(), 2);
        // Nor can it sign another statement: it names a key that doesn't count.
        let gone = owner_key_of(&added, &ana.key);
        let stranger = SigningKey::generate().unwrap();
        assert_eq!(
            addition(&read, &ana.key, &gone, &stranger).err(),
            Some(Error::WrongSigner)
        );
        // And a key that counts can't sign as another one that does.
        let laptops = owner_key_of(&added, &laptop);
        assert_eq!(
            addition(&added, &ana.key, &laptops, &stranger).err(),
            Some(Error::BadSignature)
        );
    }

    /// The backup overrides every key: after a recovery only the key it names counts, its `seq` counts
    /// the key statements before it, and keys added after it count again.
    #[test]
    fn a_recovery_drops_every_added_key() {
        let ana = holder();
        let laptop = SigningKey::generate().unwrap();
        let added = ana.identity.add_key(&ana.key, &laptop, NOW).unwrap();
        let new_key = SigningKey::generate().unwrap();
        let recovered = added
            .recover(
                &ana.backup,
                &new_key.public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW,
            )
            .unwrap();
        let read = Identity::from_encoded(&recovered.encoded()).unwrap();
        assert_eq!(read.keys().len(), 1);
        assert!(counts_now(&read, &new_key) && !counts_now(&read, &laptop));
        assert_eq!((read.recoveries(), read.statements()), (1, 2));
        // A history read back under the epoch before the recovery still has both keys.
        let then = read.as_of(0).unwrap();
        assert!(counts_now(&then, &ana.key) && counts_now(&then, &laptop));
        let again = read.add_key(&new_key, &laptop, NOW).err();
        assert_eq!(again, Some(Error::Malformed), "a key this ID had");
        let phone = SigningKey::generate().unwrap();
        let back = read.add_key(&new_key, &phone, NOW).unwrap();
        assert!(counts_now(&back, &phone));
    }

    #[test]
    fn keys_are_limited_at_once_and_between_recoveries_and_one_always_counts() {
        let ana = holder();
        let mut identity = ana.identity.clone();
        for _ in 1..MAX_KEYS {
            identity = identity
                .add_key(&ana.key, &SigningKey::generate().unwrap(), NOW)
                .unwrap();
        }
        let fifth = SigningKey::generate().unwrap();
        assert_eq!(
            identity.add_key(&ana.key, &fifth, NOW).err(),
            Some(Error::Malformed)
        );
        // Removing makes room, and removals never count against the additions.
        let names: Vec<String> = identity.keys().iter().map(OwnerKey::name).collect();
        for name in names.iter().skip(1) {
            identity = identity.remove_key(&ana.key, name, NOW).unwrap();
        }
        let last = names.first().unwrap();
        assert_eq!(
            identity.remove_key(&ana.key, last, NOW).err(),
            Some(Error::Malformed)
        );
        // A thief holding a stolen sign-in spends every addition left until the next recovery.
        for _ in MAX_KEYS..=MAX_ADDITIONS {
            let key = SigningKey::generate().unwrap();
            identity = identity.add_key(&ana.key, &key, NOW).unwrap();
            let name = identity.keys().last().unwrap().name();
            identity = identity.remove_key(&ana.key, &name, NOW).unwrap();
        }
        assert_eq!(
            identity.add_key(&ana.key, &fifth, NOW).err(),
            Some(Error::Malformed)
        );
        // The bug: additions were counted over the ID's life, so the owner's recovery left them
        // spent and no new phone could ever be added. A recovery starts the count again.
        let new_key = SigningKey::generate().unwrap();
        identity = identity
            .recover(
                &ana.backup,
                &new_key.public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW,
            )
            .unwrap();
        let phone = identity.add_key(&new_key, &fifth, NOW).unwrap();
        assert!(Identity::from_encoded(&phone.encoded()).is_ok());
    }

    /// Two branches of key statements took two of the owner's keys, so nothing says which is real
    /// until a recovery settles it, whichever copy a reader held first.
    #[test]
    fn key_branches_stay_forked_until_a_recovery_after_the_split() {
        let ana = holder();
        let laptop = SigningKey::generate().unwrap();
        let both = ana.identity.add_key(&ana.key, &laptop, NOW).unwrap();
        // The removed key's branch: the laptop removes the first key, while it adds a key of its own.
        let first = owner_key_of(&both, &ana.key).name();
        let laptops = both.remove_key(&laptop, &first, NOW).unwrap();
        let thiefs = both
            .add_key(&ana.key, &SigningKey::generate().unwrap(), NOW)
            .unwrap();
        assert_eq!(laptops.newest_of(&thiefs).err(), Some(Error::Forked));
        assert_eq!(thiefs.newest_of(&laptops).err(), Some(Error::Forked));
        assert_eq!(laptops.newest_of(&both).unwrap().statements(), 2);

        let new_key = SigningKey::generate().unwrap();
        let recovered = thiefs
            .recover(
                &ana.backup,
                &new_key.public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW,
            )
            .unwrap();
        for (held, shown) in [(&laptops, &recovered), (&recovered, &laptops)] {
            let newest = held.newest_of(shown).unwrap();
            assert_eq!(newest.head_hash(), recovered.head_hash());
            assert!(!counts_now(&newest, &laptop));
        }
        // Two recoveries took the backup, and stay forked as they always have.
        let other = laptops
            .recover(
                &ana.backup,
                &new_key.public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW,
            )
            .unwrap();
        assert_eq!(recovered.newest_of(&other).err(), Some(Error::Forked));
    }

    /// An addition of a passkey, signed by a file key that counts and by the passkey it adds, with one
    /// touch over the same signing input.
    fn passkey_addition(signer: &SigningKey, payload: &[u8], added: &Authenticator) -> String {
        let signed = jws::sign(signer, KEY_ADD_TYPE, payload).unwrap();
        let input = signed_part(&signed);
        let challenge = crate::passkey::Challenge::for_inputs(&[input]).unwrap();
        let assertion = added.assert(challenge.challenge());
        let touched = challenge.signed(&[input], &assertion).unwrap();
        let (_, segment) = touched.first().unwrap().rsplit_once('.').unwrap();
        format!("{signed}.{segment}")
    }

    /// A stand-in's key is on its agent's machine, so it adds nothing. An owner who confirmed adds a
    /// passkey made on their own computer or at a host's name, where a phone signs in, and that
    /// passkey's assertion counts only from that host's own https origin.
    #[test]
    fn only_a_real_owner_adds_keys_and_a_passkey_at_a_host_counts_only_from_its_origin() {
        let key = SigningKey::generate().unwrap();
        let rule = RecoveryRule::unconfirmed_owner(&key.public_key());
        let stand_in = Identity::create(&key, &crate::test_seal(), rule).unwrap();
        let other = SigningKey::generate().unwrap();
        assert_eq!(
            stand_in.add_key(&key, &other, NOW).err(),
            Some(Error::Malformed)
        );

        let ana = holder();
        let by = owner_key_of(&ana.identity, &ana.key);
        for rp in ["host.example", "owner.splint.example"] {
            let passkey = Authenticator::new(rp);
            let payload = ana
                .identity
                .key_add_payload(&by, &passkey.key.public_key(), Some(&passkey.rp), NOW)
                .unwrap();
            let with_passkey = ana
                .identity
                .with_statement(&passkey_addition(&ana.key, &payload, &passkey))
                .unwrap();
            let rules = passkey.resign(&owner_object(&ana.key));
            assert!(with_passkey.verify(&rules, "splint-rules").is_ok(), "{rp}");
            assert_eq!(
                ana.identity.verify(&rules, "splint-rules").err(),
                Some(Error::BadSignature)
            );
            // And a passkey at a host's name adds a key in turn, as an owner with only a phone does.
            let laptop = SigningKey::generate().unwrap();
            let next_by = owner_key_of(&with_passkey, &passkey.key);
            let payload = with_passkey
                .key_add_payload(&next_by, &laptop.public_key(), None, NOW)
                .unwrap();
            let input = jws::signing_input(jws::Alg::Wa256, KEY_ADD_TYPE, &payload).unwrap();
            let touched = passkey.sign_together(&[input.as_str()]);
            let signed = touched.first().unwrap();
            let added = jws::signature_over(&laptop, signed_part(signed)).unwrap();
            let three = with_passkey
                .with_statement(&format!("{signed}.{added}"))
                .unwrap();
            assert!(counts_now(&three, &laptop), "{rp}");
        }
        // A host's passkey's touch counts only from that host's own page.
        let at_a_host = Authenticator::new("host.example");
        let payload = ana
            .identity
            .key_add_payload(&by, &at_a_host.key.public_key(), Some(&at_a_host.rp), NOW)
            .unwrap();
        let with_host = ana
            .identity
            .with_statement(&passkey_addition(&ana.key, &payload, &at_a_host))
            .unwrap();
        let elsewhere = at_a_host.resign_with(&owner_object(&ana.key), |made| {
            made.client_data["origin"] = "https://other.example".into();
        });
        assert_eq!(
            with_host.verify(&elsewhere, "splint-rules").err(),
            Some(Error::BadSignature)
        );
    }

    /// Nobody adds a key they don't hold: an addition carries the added key's own signature over the
    /// same signing input. An agent's key is public, so without this a thief with one owner key could
    /// add it and have the agent sign as its own owner. Signet's agent key signs no owner type and no
    /// input made elsewhere, so nothing asking Signet gets that signature.
    #[test]
    fn an_addition_needs_the_added_keys_own_signature() {
        let ana = holder();
        let by = owner_key_of(&ana.identity, &ana.key);
        let laptop = SigningKey::generate().unwrap();
        let payload = ana
            .identity
            .key_add_payload(&by, &laptop.public_key(), None, NOW)
            .unwrap();
        let signed = jws::sign(&ana.key, KEY_ADD_TYPE, &payload).unwrap();
        assert_eq!(
            ana.identity.with_statement(&signed).err(),
            Some(Error::Malformed),
            "without it"
        );
        let by_signer_again = jws::signature_over(&ana.key, signed_part(&signed)).unwrap();
        assert_eq!(
            ana.identity
                .with_statement(&format!("{signed}.{by_signer_again}"))
                .err(),
            Some(Error::BadSignature),
            "the signer's again"
        );
        let proof = jws::signature_over(&laptop, signed_part(&signed)).unwrap();
        assert!(
            ana.identity
                .with_statement(&format!("{signed}.{proof}"))
                .is_ok()
        );

        let folder = std::env::temp_dir().join(format!("splint-agent-key-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        let agents = SigningKey::load_or_create_for_agent(&folder.join("agent.key")).unwrap();
        let payload = ana
            .identity
            .key_add_payload(&by, &agents.public_key(), None, NOW)
            .unwrap();
        let signed = jws::sign(&ana.key, KEY_ADD_TYPE, &payload).unwrap();
        assert_eq!(
            jws::signature_over(&agents, signed_part(&signed)).err(),
            Some(Error::WrongSigner)
        );
        assert_eq!(
            jws::sign(&agents, KEY_ADD_TYPE, &payload).err(),
            Some(Error::WrongSigner)
        );
        assert_eq!(
            jws::sign(&agents, "splint-rules", br#"{"v":1}"#).err(),
            Some(Error::WrongSigner)
        );
        std::fs::remove_dir_all(&folder).unwrap();
    }

    /// Bug caught: a second computer's sign-in added by a device that doesn't count, or under a
    /// name other than the key that signs, or a different key than the one that offered.
    #[test]
    fn a_sign_in_another_device_offers_is_added_only_by_a_key_that_counts() {
        let ana = holder();
        let laptop = SigningKey::generate().unwrap();
        let name = owner_key_of(&ana.identity, &ana.key).name();
        let offer = ana.identity.offer_key(&name, &laptop, NOW).unwrap();
        assert_eq!(Identity::offered_key(&offer).unwrap(), laptop.public_key());

        let stranger = SigningKey::generate().unwrap();
        assert_eq!(
            ana.identity.add_offered(&stranger, &offer).err(),
            Some(Error::WrongSigner)
        );
        let swapped = format!(
            "{}.{}",
            signed_part(&offer),
            jws::signature_over(&stranger, signed_part(&offer)).unwrap()
        );
        assert_eq!(
            ana.identity.add_offered(&ana.key, &swapped).err(),
            Some(Error::BadSignature)
        );
        assert_eq!(
            ana.identity
                .add_offered(&ana.key, signed_part(&offer))
                .err(),
            Some(Error::Malformed)
        );
        let added = ana.identity.add_offered(&ana.key, &offer).unwrap();
        let read = Identity::from_encoded(&added.encoded()).unwrap();
        assert!(
            read.keys()
                .iter()
                .any(|key| key.point == laptop.public_key())
        );
        assert_eq!(
            read.add_offered(&ana.key, &offer).err(),
            Some(Error::ProofMismatch),
            "an offer is good once"
        );
    }

    /// An owner made without a recovery code sets one later, once, with any key that counts, and only
    /// then can recover. A thief holding a key can't move a code that's set.
    #[test]
    fn a_recovery_code_set_later_works_once_and_only_then() {
        let key = SigningKey::generate().unwrap();
        let later = RecoveryRule::later(&key.public_key());
        let ana = Identity::create(&key, &crate::test_seal(), later).unwrap();
        assert!(ana.recovery_is_later() && !ana.is_unconfirmed_owner());
        let backup = SigningKey::generate().unwrap();
        let next = SigningKey::generate().unwrap();
        assert_eq!(
            ana.recover(
                &backup,
                &next.public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW
            )
            .err(),
            Some(Error::WrongSigner),
            "no backup recovers an ID with none yet"
        );
        let rule = RecoveryRule::backup_key(&backup.public_key());
        let set = ana.set_recovery_rule(&key, &rule, NOW).unwrap();
        let read = Identity::from_encoded(&set.encoded()).unwrap();
        assert!(!read.recovery_is_later() && !read.may_act_as_agent());
        assert_eq!(read.rule(), &rule);
        assert_eq!(
            read.set_recovery_rule(&key, &fresh_rule(), NOW).err(),
            Some(Error::Malformed),
            "once"
        );
        let recovered = read
            .recover(
                &backup,
                &next.public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW,
            )
            .unwrap();
        assert!(counts_now(&recovered, &next) && !counts_now(&recovered, &key));
        // Nor does a rule commit to a key the ID has, so a device that held a key never holds the backup.
        let own = RecoveryRule::backup_key(&key.public_key());
        assert_eq!(
            ana.set_recovery_rule(&key, &own, NOW).err(),
            Some(Error::Malformed)
        );
        // An ID with a backup from the start has nothing to set.
        let ben = holder();
        assert_eq!(
            ben.identity
                .set_recovery_rule(&ben.key, &fresh_rule(), NOW)
                .err(),
            Some(Error::Malformed)
        );
    }

    /// What a host or Signet holding one copy does with another. Taking an older copy would bring a
    /// removed key back, and taking a copy that parted ways with keys alone would let either device
    /// undo the other, so only a longer copy or one with the only recovery since replaces what's held.
    #[test]
    fn only_a_later_copy_or_a_recovery_since_replaces_the_one_held() {
        let ana = holder();
        let laptop = SigningKey::generate().unwrap();
        let added = ana.identity.add_key(&ana.key, &laptop, NOW).unwrap();
        let removed = added
            .remove_key(&laptop, &owner_key_of(&added, &ana.key).name(), NOW)
            .unwrap();
        assert_eq!(removed.replaces(&added), Ok(true));
        assert_eq!(removed.replaces(&removed), Ok(false));
        assert_eq!(added.replaces(&removed), Err(Error::Stale));
        let tablet = SigningKey::generate().unwrap();
        let branch = added.add_key(&ana.key, &tablet, NOW).unwrap();
        assert_eq!(branch.replaces(&removed), Err(Error::Forked));
        let recovered = branch
            .recover(
                &ana.backup,
                &SigningKey::generate().unwrap().public_key(),
                &crate::test_seal(),
                fresh_rule(),
                NOW,
            )
            .unwrap();
        assert_eq!(recovered.replaces(&removed), Ok(true));
        assert_eq!(removed.replaces(&recovered), Err(Error::Forked));
        // And what a removed key signed, alone or first in parts, no longer counts as signed now.
        assert!(removed.removed_since(&added) && !added.removed_since(&ana.identity));
        let rules = owner_object(&ana.key);
        assert!(added.signed_now(&rules) && !removed.signed_now(&rules));
        assert!(removed.signed_now(&format!("{}~anything", owner_object(&laptop))));
    }
}

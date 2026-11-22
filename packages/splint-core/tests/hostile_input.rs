//! Feeds hostile bytes to every parser and verifier in splint-core, from a small seeded generator.
//!
//! Ignored by default because it runs for minutes. `make test-hostile-input` runs it in release mode. It checks:
//! - nothing panics or hangs,
//! - nothing tampered with ever verifies unless its signed content is byte-identical,
//! - anything re-signed with the real key that does verify still obeys every rule, checked here
//!   by code that doesn't share the parser's types.
//!
//! The same seed gives the same keys and the same mutations. Only the original signatures differ,
//! because the signing library draws its own randomness. A failure prints its input whole.
//!
//! Set `SPLINT_FUZZ_SEED`, `SPLINT_FUZZ_SECS`, or `SPLINT_FUZZ_ONLY` to replay one iteration.

use std::collections::BTreeMap;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use splint_core::{
    AccessProof, CLOCK_TOLERANCE_SECS, DeliveryFailure, DeliveryProof, Error, Identity,
    MAX_MESSAGE_LIFETIME_SECS, MessageId, PublicKey, RecoveryRule, SealFor, Sealing, SealingKey,
    SigningKey, SplintId, VerifiedEnvelope, canonical_address, claimed_agent, claimed_sender,
    is_valid_handle, parse_address, sign_sealed_envelope,
};

#[path = "hostile_input/documents.rs"]
mod documents;

const NOW: u64 = 1_800_000_000;
const LIFETIME: u64 = 3_600;
const ALG: &str = "ES256";
const ENVELOPE_TYPE: &str = "splint-envelope";
const DELIVERY_TYPE: &str = "splint-delivery";
const ACCESS_TYPE: &str = "splint-access";
const HOST_A: &str = "a.example:7001";
const HOST_B: &str = "b.example:7002";
const ACCESS_METHOD: &str = "POST";
const ACCESS_PATH: &str = "/v0/inbox/ack";
const ACCESS_BODY: &[u8] = b"{\"seqs\":[1]}";
const MAX_COMPACT_LEN: usize = 256 * 1024;
const DEFAULT_SECS: u64 = 600;
/// No call here should take more than a moment, even on a busy machine.
const HANG_AFTER: Duration = Duration::from_secs(60);
const MAX_REPORTED_FAILURES: usize = 20;
const MAX_REPORTED_INPUT_BYTES: usize = 2048;
const GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
/// The P-256 group order, which a signature's parts must stay below.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
/// A P-256 PKCS#8 document around a private scalar, so that a seed fixes the keys.
const PKCS8_PREFIX: [u8; 35] = [
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
    0x01, 0x04, 0x20,
];

/// Spliced in as bytes and used as field values, so each is valid JSON or a JSON trap.
const TOKENS: &[&str] = &[
    "null",
    "true",
    "0",
    "-1",
    "1.0",
    "1e400",
    "-0",
    "18446744073709551615",
    "18446744073709551616",
    "340282366920938463463374607431768211456",
    "\"\"",
    "\"\\u0000\"",
    "\"\\ud800\"",
    "\"\\udc00\\ud800\"",
    "\"\\ud83d\\ude00\"",
    "\"\\u202e\\u200b\\ufeff\"",
    "\"\u{202e}\u{200b}\u{feff}\"",
    "\"a\\",
    "\"",
    "[]",
    "{}",
    "[1,2,3]",
    "{\"a\":1}",
    "{\"v\":1,\"v\":1}",
    "[[[[[[[[",
    "]]]]]]]]",
    "}{",
    ",",
    ":",
    "\"alg\":\"none\",",
    "\"typ\":\"splint-envelope\",",
    "\"v\":2,",
    "\"extra\":1,",
    "..",
    "=",
    "==",
    "%00",
    "%2f..%2f",
    "/admin?a=",
    "@",
    "::",
    "~",
    "~@",
    "#",
    "\\",
    "\u{feff}",
    "\t\r\n ",
];
const RAW_BYTES: &[u8] = &[
    0x00, 0x01, 0x0a, 0x22, 0x2e, 0x2f, 0x3a, 0x3d, 0x40, 0x5c, 0x7b, 0x7d, 0x7f, 0x80, 0xc0, 0xc1,
    0xed, 0xf4, 0xf5, 0xfe, 0xff,
];
const DEEP_NESTING: &[usize] = &[129, 1_000, 100_000];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Kind {
    Envelope,
    Delivery,
    Access,
}

const KINDS: [Kind; 3] = [Kind::Envelope, Kind::Delivery, Kind::Access];

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Envelope => "envelope",
            Self::Delivery => "delivery proof",
            Self::Access => "access proof",
        })
    }
}

impl Kind {
    fn typ(self) -> &'static str {
        match self {
            Self::Envelope => ENVELOPE_TYPE,
            Self::Delivery => DELIVERY_TYPE,
            Self::Access => ACCESS_TYPE,
        }
    }
}

struct Rng(u64);

impl Rng {
    fn for_iteration(seed: u64, iteration: u64) -> Self {
        Self(seed ^ iteration.wrapping_mul(GOLDEN_GAMMA))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(GOLDEN_GAMMA);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(limit.max(1)).unwrap_or(1)).unwrap_or(0)
    }

    fn pick<'a, T: ?Sized>(&mut self, items: &'a [&'a T]) -> Option<&'a T> {
        items.get(self.below(items.len())).copied()
    }
}

/// A key the tests can sign anything with, which the public API rightly doesn't allow.
struct Signer {
    pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
    public: PublicKey,
    seal: SealingKey,
    identity: Identity,
}

impl Signer {
    fn from_seed(rng: &mut Rng) -> Result<Self, String> {
        let mut pkcs8 = PKCS8_PREFIX.to_vec();
        for _ in 0..4 {
            pkcs8.extend_from_slice(&rng.next().to_be_bytes());
        }
        let pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8)
            .map_err(|_| "the signing library refused a seeded key".to_owned())?;
        let key = SigningKey::from_pkcs8(&pkcs8).map_err(|error| error.to_string())?;
        let seal = SealingKey::generate().map_err(|error| error.to_string())?;
        let identity = Identity::create(
            &key,
            &seal.public_key(),
            RecoveryRule::committed_to(&"ab".repeat(32)).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            pair,
            pkcs8,
            public: key.public_key(),
            seal,
            identity,
        })
    }

    /// The same key with another way back, for a document that has to name a backup key it holds.
    fn with_recovery(mut self, recovery: RecoveryRule) -> Result<Self, String> {
        let key = SigningKey::from_pkcs8(&self.pkcs8).map_err(|error| error.to_string())?;
        self.identity = Identity::create(&key, &self.seal.public_key(), recovery)
            .map_err(|error| error.to_string())?;
        Ok(self)
    }

    fn sign_parts(&self, header: &[u8], payload: &[u8]) -> Result<String, String> {
        let signing_input = format!("{}.{}", encode(header), encode(payload));
        let signature = self
            .pair
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(|_| "the signing library failed".to_owned())?;
        Ok(format!("{signing_input}.{}", encode(signature.as_ref())))
    }

    fn sign(&self, typ: &str, payload: &[u8]) -> Result<String, String> {
        self.sign_parts(canonical_header(typ).as_bytes(), payload)
    }
}

fn canonical_header(typ: &str) -> String {
    format!(r#"{{"alg":"{ALG}","typ":"{typ}"}}"#)
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A payload as ordered fields of raw JSON, so a test can write what serde never would.
type Fields = Vec<(String, String)>;

fn to_json(fields: &Fields) -> String {
    let inner: Vec<String> = fields
        .iter()
        .map(|(name, value)| format!("\"{name}\":{value}"))
        .collect();
    format!("{{{}}}", inner.join(","))
}

fn quoted(text: &str) -> String {
    format!("\"{text}\"")
}

/// The valid objects everything here starts from, and a clock they're all valid at.
struct World {
    documents: documents::Documents,
    ana: Signer,
    mallory: Signer,
    message_id: MessageId,
    raw_identity: Vec<u8>,
    fields: BTreeMap<Kind, Fields>,
    payloads: BTreeMap<Kind, String>,
    compacts: BTreeMap<Kind, String>,
    signature: Vec<u8>,
    /// Ana's words to Mallory, sealed: as sent, and as Ana's Signet keeps them.
    sealed: String,
    sealed_kept: String,
}

const SEALED_WORDS: &str = "the sealed words";

impl World {
    fn new(seed: u64) -> Result<Self, String> {
        let mut rng = Rng::for_iteration(seed, u64::MAX);
        let documents = documents::Documents::new(&mut rng)?;
        let ana = Signer::from_seed(&mut rng)?;
        let mallory = Signer::from_seed(&mut rng)?;
        let raw_identity = URL_SAFE_NO_PAD
            .decode(ana.identity.encoded())
            .map_err(|_| "an identity isn't base64".to_owned())?;

        let envelope_fields: Fields = [
            ("v", "1".to_owned()),
            ("sender", quoted(ana.identity.id().as_str())),
            ("recipient", quoted(mallory.identity.id().as_str())),
            ("body", quoted("hello")),
            ("created_at", NOW.to_string()),
            ("expires_at", (NOW + LIFETIME).to_string()),
            ("nonce", quoted("AAAAAAAAAAAAAAAAAAAAAA")),
        ]
        .map(|(name, value)| (name.to_owned(), value))
        .into();
        let envelope = to_json(&envelope_fields);
        let message_id = sha256_hex(envelope.as_bytes());

        let delivery_fields: Fields = [
            ("message", quoted(&message_id)),
            ("from_host", quoted(HOST_A)),
            ("to_host", quoted(HOST_B)),
            ("issued_at", NOW.to_string()),
        ]
        .map(|(name, value)| (name.to_owned(), value))
        .into();
        let access_fields: Fields = [
            ("signer", quoted(ana.identity.id().as_str())),
            ("host", quoted(HOST_A)),
            ("method", quoted(ACCESS_METHOD)),
            ("path", quoted(ACCESS_PATH)),
            ("body_sha256", quoted(&sha256_hex(ACCESS_BODY))),
            ("issued_at", NOW.to_string()),
        ]
        .map(|(name, value)| (name.to_owned(), value))
        .into();

        let mut fields = BTreeMap::new();
        fields.insert(Kind::Envelope, envelope_fields);
        fields.insert(Kind::Delivery, delivery_fields);
        fields.insert(Kind::Access, access_fields);
        let mut payloads = BTreeMap::new();
        let mut compacts = BTreeMap::new();
        for (kind, these) in &fields {
            let payload = to_json(these);
            compacts.insert(*kind, ana.sign(kind.typ(), payload.as_bytes())?);
            payloads.insert(*kind, payload);
        }

        let envelope_compact = compacts.get(&Kind::Envelope).ok_or("no envelope")?;
        let signature = envelope_compact
            .rsplit_once('.')
            .and_then(|(_, part)| URL_SAFE_NO_PAD.decode(part).ok())
            .ok_or("no signature")?;
        let verified = VerifiedEnvelope::verify(envelope_compact, &ana.identity, NOW)
            .map_err(|error| format!("control envelope: {error}"))?;
        let ana_key = SigningKey::from_pkcs8(&ana.pkcs8).map_err(|error| error.to_string())?;
        let signed = sign_sealed_envelope(
            &ana_key,
            &ana.identity,
            mallory.identity.id(),
            SEALED_WORDS.to_owned(),
            NOW,
            LIFETIME,
            &SealFor {
                recipient: &mallory.seal.public_key(),
                own: &ana.seal.public_key(),
                sender_chose: Sealing::Sealed,
            },
        )
        .map_err(|error| format!("control sealed: {error}"))?;
        let world = Self {
            sealed: signed.compact,
            sealed_kept: signed.kept,
            message_id: verified.id().clone(),
            ana,
            mallory,
            raw_identity,
            fields,
            payloads,
            compacts,
            signature,
            documents,
        };
        for kind in KINDS {
            world
                .verify(kind, world.compact(kind), NOW)
                .map_err(|error| format!("control {kind}: {error}"))?;
        }
        Ok(world)
    }

    fn compact(&self, kind: Kind) -> &str {
        self.compacts.get(&kind).map_or("", String::as_str)
    }

    fn payload(&self, kind: Kind) -> &str {
        self.payloads.get(&kind).map_or("", String::as_str)
    }

    /// The real verifier, and for the kinds that have one, the real pre-verification parser.
    fn verify(&self, kind: Kind, compact: &str, now: u64) -> Result<(), Error> {
        match kind {
            Kind::Envelope => {
                let _ = claimed_sender(compact);
                VerifiedEnvelope::verify(compact, &self.ana.identity, now).map(|_| ())
            }
            Kind::Delivery => DeliveryProof::verify(
                compact,
                &self.ana.public,
                &self.message_id,
                HOST_A,
                HOST_B,
                now,
            ),
            Kind::Access => {
                let _ = claimed_agent(compact);
                AccessProof::verify(
                    compact,
                    &self.ana.identity,
                    HOST_A,
                    ACCESS_METHOD,
                    ACCESS_PATH,
                    ACCESS_BODY,
                    now,
                )
            }
        }
    }
}

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    for _ in 0..=rng.below(4) {
        let at = rng.below(out.len() + 1);
        match rng.below(9) {
            0 => {
                let bit = rng.below(8);
                if let Some(byte) = out.get_mut(at) {
                    *byte ^= 1 << bit;
                }
            }
            1 => {
                let raw = RAW_BYTES.get(rng.below(RAW_BYTES.len())).copied();
                if let (Some(byte), Some(raw)) = (out.get_mut(at), raw) {
                    *byte = raw;
                }
            }
            2 => {
                let end = (at + rng.below(16) + 1).min(out.len());
                out.drain(at..end);
            }
            3 => {
                let token = rng.pick(TOKENS).unwrap_or("").as_bytes();
                out.splice(at..at, token.iter().copied());
            }
            4 => out.truncate(at),
            5 => {
                let end = (at + rng.below(32) + 1).min(out.len());
                let chunk: Vec<u8> = out.get(at..end).unwrap_or_default().to_vec();
                out.splice(at..at, chunk);
            }
            6 => {
                let end = (at + rng.below(32) + 1).min(out.len());
                let token = rng.pick(TOKENS).unwrap_or("").as_bytes();
                out.splice(at..end, token.iter().copied());
            }
            7 => {
                let other = rng.below(out.len() + 1);
                if at < out.len() && other < out.len() {
                    out.swap(at, other);
                }
            }
            _ => {
                if rng.below(64) == 0 {
                    let depth = DEEP_NESTING.get(rng.below(DEEP_NESTING.len())).copied();
                    let opener = if rng.below(2) == 0 { "[" } else { "{\"a\":" };
                    let deep = opener.repeat(depth.unwrap_or(1));
                    out.splice(at..at, deep.bytes());
                }
            }
        }
    }
    // A mutation that changed nothing would count as a pass it didn't earn.
    if out == input {
        out.push(b'A');
    }
    out
}

/// Rewrites a payload field by field, including the forms a parser most often gets wrong.
fn mutate_fields(rng: &mut Rng, world: &World, kind: Kind) -> Vec<u8> {
    let mut fields = world.fields.get(&kind).cloned().unwrap_or_default();
    for _ in 0..=rng.below(3) {
        let at = rng.below(fields.len());
        match rng.below(8) {
            0 => {
                let token = rng.pick(TOKENS).unwrap_or("null");
                if let Some(field) = fields.get_mut(at) {
                    field.1 = token.to_owned();
                }
            }
            1 => {
                let value = date_near_now(rng).to_string();
                if let Some(field) = fields.get_mut(at) {
                    field.1 = value;
                }
            }
            2 => {
                if at < fields.len() {
                    fields.remove(at);
                }
            }
            3 => {
                if let Some(field) = fields.get(at).cloned() {
                    fields.push(field);
                }
            }
            4 => {
                if let Some(field) = fields.get_mut(at) {
                    field.0 = field
                        .0
                        .chars()
                        .map(|c| format!("\\u{:04x}", c as u32))
                        .collect();
                }
            }
            5 => {
                let other = rng.below(fields.len());
                if at < fields.len() && other < fields.len() {
                    fields.swap(at, other);
                }
            }
            6 => fields.push(("extra".to_owned(), "1".to_owned())),
            _ => {
                let id = quoted(world.mallory.identity.id().as_str());
                if let Some(field) = fields.get_mut(at) {
                    field.1 = id;
                }
            }
        }
    }
    let json = to_json(&fields);
    if rng.below(8) == 0 {
        mutate(rng, json.as_bytes())
    } else {
        json.into_bytes()
    }
}

fn date_near_now(rng: &mut Rng) -> u64 {
    let edges = [
        0,
        1,
        NOW - CLOCK_TOLERANCE_SECS - 1,
        NOW - CLOCK_TOLERANCE_SECS,
        NOW - 1,
        NOW,
        NOW + 1,
        NOW + CLOCK_TOLERANCE_SECS,
        NOW + CLOCK_TOLERANCE_SECS + 1,
        NOW + MAX_MESSAGE_LIFETIME_SECS,
        NOW + MAX_MESSAGE_LIFETIME_SECS + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    edges.get(rng.below(edges.len())).copied().unwrap_or(NOW)
}

fn signed_content(compact: &str) -> &str {
    compact
        .rsplit_once('.')
        .map_or(compact, |(content, _)| content)
}

/// A JSON object's keys as parsed, including repeats, which `serde_json::Value` would hide.
struct RepeatedKeys(Vec<String>);

impl<'de> Deserialize<'de> for RepeatedKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Keys;
        impl<'de> Visitor<'de> for Keys {
            type Value = Vec<String>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Vec<String>, A::Error> {
                let mut keys = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    map.next_value::<serde::de::IgnoredAny>()?;
                    keys.push(key);
                }
                Ok(keys)
            }
        }
        deserializer.deserialize_map(Keys).map(Self)
    }
}

/// What a verified object's bytes have to look like, read without the parser's own types.
fn independent_read(bytes: &[u8], expected: &[&str]) -> Result<serde_json::Value, String> {
    let keys = serde_json::from_slice::<RepeatedKeys>(bytes)
        .map_err(|error| format!("verified, but not a JSON object: {error}"))?
        .0;
    let mut sorted = keys.clone();
    sorted.sort();
    let mut wanted: Vec<String> = expected.iter().map(|name| (*name).to_owned()).collect();
    wanted.sort();
    if sorted != wanted {
        return Err(format!("verified with fields {keys:?}"));
    }
    serde_json::from_slice(bytes).map_err(|error| format!("verified, but unreadable: {error}"))
}

fn field_u64(value: &serde_json::Value, name: &str) -> Result<u64, String> {
    value
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("verified without a number for {name}"))
}

fn field_str<'a>(value: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("verified without a string for {name}"))
}

fn expect_equal(name: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("verified with the wrong {name}"))
    }
}

fn check_issued_at(value: &serde_json::Value, now: u64) -> Result<(), String> {
    let issued_at = field_u64(value, "issued_at")?;
    if issued_at.abs_diff(now) > CLOCK_TOLERANCE_SECS {
        return Err(format!("verified at {now} with issued_at {issued_at}"));
    }
    Ok(())
}

/// Every rule a signed payload has to obey, for one the real key really did sign.
fn check_verified_payload(
    world: &World,
    kind: Kind,
    payload: &[u8],
    tally: &mut Tally,
) -> Result<(), String> {
    match kind {
        Kind::Envelope => {
            let names = [
                "v",
                "sender",
                "recipient",
                "body",
                "created_at",
                "expires_at",
                "nonce",
            ];
            let value = independent_read(payload, &names)?;
            if field_u64(&value, "v")? != 1 {
                return Err("verified with another version".to_owned());
            }
            expect_equal(
                "sender",
                field_str(&value, "sender")?,
                world.ana.identity.id().as_str(),
            )?;
            let created_at = field_u64(&value, "created_at")?;
            let expires_at = field_u64(&value, "expires_at")?;
            if expires_at.saturating_sub(created_at) > MAX_MESSAGE_LIFETIME_SECS
                || NOW >= expires_at
                || created_at > NOW + CLOCK_TOLERANCE_SECS
            {
                return Err(format!("verified with dates {created_at} to {expires_at}"));
            }
            if expires_at < created_at {
                tally.note("accepted: envelope expires before it was created");
            }
            if field_str(&value, "nonce")?.is_empty() {
                tally.note("accepted: envelope with an empty nonce");
            }
        }
        Kind::Delivery => {
            let names = ["message", "from_host", "to_host", "issued_at"];
            let value = independent_read(payload, &names)?;
            expect_equal(
                "message",
                field_str(&value, "message")?,
                world.message_id.as_str(),
            )?;
            expect_equal("from_host", field_str(&value, "from_host")?, HOST_A)?;
            expect_equal("to_host", field_str(&value, "to_host")?, HOST_B)?;
            check_issued_at(&value, NOW)?;
        }
        Kind::Access => {
            let names = [
                "signer",
                "host",
                "method",
                "path",
                "body_sha256",
                "issued_at",
            ];
            let value = independent_read(payload, &names)?;
            expect_equal(
                "signer",
                field_str(&value, "signer")?,
                world.ana.identity.id().as_str(),
            )?;
            expect_equal("host", field_str(&value, "host")?, HOST_A)?;
            expect_equal("method", field_str(&value, "method")?, ACCESS_METHOD)?;
            expect_equal("path", field_str(&value, "path")?, ACCESS_PATH)?;
            expect_equal(
                "body",
                field_str(&value, "body_sha256")?,
                &sha256_hex(ACCESS_BODY),
            )?;
            check_issued_at(&value, NOW)?;
        }
    }
    if payload != world.payload(kind).as_bytes() {
        tally.note("accepted: a re-signed payload with different bytes");
    }
    Ok(())
}

#[derive(Default)]
struct Tally {
    /// What each action came to, which shows the run reached past each check it means to test.
    outcomes: BTreeMap<String, u64>,
    notes: BTreeMap<String, u64>,
    /// What's being tried now, kept so a panic can report it.
    input: Vec<u8>,
}

impl Tally {
    fn outcome(&mut self, action: &str, kind: &str, result: &Result<(), Error>) {
        let word = match result {
            Ok(()) => "verified".to_owned(),
            Err(error) => format!("{error:?}"),
        };
        *self
            .outcomes
            .entry(format!("{action:<20} {kind:<15} {word}"))
            .or_default() += 1;
    }

    fn note(&mut self, note: &str) {
        *self.notes.entry(note.to_owned()).or_default() += 1;
    }
}

/// Not re-signed: the whole compact form changed as bytes.
fn tamper_compact(
    world: &World,
    rng: &mut Rng,
    tally: &mut Tally,
    kind: Kind,
) -> Result<(), String> {
    let original = world.compact(kind);
    let bytes = mutate(rng, original.as_bytes());
    tally.input.clone_from(&bytes);
    let text = String::from_utf8_lossy(&bytes);
    let result = world.verify(kind, &text, NOW);
    tally.outcome("tamper compact", &kind.to_string(), &result);
    if result.is_ok() && signed_content(&text) != signed_content(original) {
        return Err(format!("tampered {kind} verified"));
    }
    Ok(())
}

/// Not re-signed: one part decoded, changed and encoded again, so the base64 stays valid.
fn tamper_part(world: &World, rng: &mut Rng, tally: &mut Tally, kind: Kind) -> Result<(), String> {
    let original = world.compact(kind);
    let parts: Vec<&str> = original.split('.').collect();
    let index = rng.below(parts.len());
    let decoded = parts
        .get(index)
        .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
        .unwrap_or_default();
    let changed = encode(&mutate(rng, &decoded));
    let rebuilt: Vec<&str> = parts
        .iter()
        .enumerate()
        .map(|(at, part)| if at == index { changed.as_str() } else { *part })
        .collect();
    let text = rebuilt.join(".");
    tally.input.clone_from(&text.clone().into_bytes());
    let result = world.verify(kind, &text, NOW);
    tally.outcome("tamper part", &kind.to_string(), &result);
    if result.is_ok() && signed_content(&text) != signed_content(original) {
        return Err(format!("{kind} with a changed part verified"));
    }
    Ok(())
}

/// Re-signed with the real key, so hostile JSON gets past the signature to the parser and the rules.
fn resign_payload(
    world: &World,
    rng: &mut Rng,
    tally: &mut Tally,
    kind: Kind,
) -> Result<(), String> {
    let payload = mutate_fields(rng, world, kind);
    tally.input.clone_from(&payload);
    let compact = world.ana.sign(kind.typ(), &payload)?;
    let result = world.verify(kind, &compact, NOW);
    tally.outcome("re-signed payload", &kind.to_string(), &result);
    if result.is_ok() {
        check_verified_payload(world, kind, &payload, tally)?;
    }
    Ok(())
}

/// Re-signed with the real key, so only the header's own checks stand in the way.
fn resign_header(
    world: &World,
    rng: &mut Rng,
    tally: &mut Tally,
    kind: Kind,
) -> Result<(), String> {
    let canonical = canonical_header(kind.typ());
    let header = mutate(rng, canonical.as_bytes());
    tally.input.clone_from(&header);
    let compact = world
        .ana
        .sign_parts(&header, world.payload(kind).as_bytes())?;
    let result = world.verify(kind, &compact, NOW);
    tally.outcome("re-signed header", &kind.to_string(), &result);
    if result.is_ok() {
        let value = independent_read(&header, &["alg", "typ"])?;
        expect_equal("alg", field_str(&value, "alg")?, ALG)?;
        expect_equal("typ", field_str(&value, "typ")?, kind.typ())?;
        if header != canonical.as_bytes() {
            tally.note("accepted: a re-signed header with different bytes");
        }
    }
    Ok(())
}

/// The right content under the wrong key, or a signature made for another kind of object.
fn wrong_signer_or_type(
    world: &World,
    rng: &mut Rng,
    tally: &mut Tally,
    kind: Kind,
) -> Result<(), String> {
    let payload = world.payload(kind).as_bytes();
    let wrong_key = world.mallory.sign(kind.typ(), payload)?;
    tally.input.clone_from(&wrong_key.clone().into_bytes());
    let result = world.verify(kind, &wrong_key, NOW);
    tally.outcome("wrong key", &kind.to_string(), &result);
    if result.is_ok() {
        return Err(format!("{kind} verified under another key"));
    }
    let other = KINDS.get(rng.below(KINDS.len())).copied().unwrap_or(kind);
    if other != kind {
        let wrong_type = world.ana.sign(other.typ(), payload)?;
        tally.input.clone_from(&wrong_type.clone().into_bytes());
        let result = world.verify(kind, &wrong_type, NOW);
        tally.outcome("wrong type", &kind.to_string(), &result);
        if result.is_ok() {
            return Err(format!("{other} signature verified as {kind}"));
        }
    }
    Ok(())
}

fn subtract_from_order(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; value.len()];
    let mut borrow = 0_i16;
    for (at, slot) in out.iter_mut().enumerate().rev() {
        let order = i16::from(P256_ORDER.get(at).copied().unwrap_or(0));
        let byte = i16::from(value.get(at).copied().unwrap_or(0));
        let digit = order - byte - borrow;
        borrow = i16::from(digit < 0);
        *slot = u8::try_from(digit.rem_euclid(256)).unwrap_or(0);
    }
    out
}

/// The other valid signature ECDSA allows, whose signed content is the same, and the edge values
/// that have to fail however the arithmetic underneath treats them.
fn signature_edges(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let compact = world.compact(Kind::Envelope);
    let content = signed_content(compact);
    let (r, s) = world.signature.split_at(32);
    let flipped: Vec<u8> = [r, subtract_from_order(s).as_slice()].concat();
    let result = world.verify(
        Kind::Envelope,
        &format!("{content}.{}", encode(&flipped)),
        NOW,
    );
    tally.outcome("signature twin", "envelope", &result);

    let one = [[0_u8; 31].as_slice(), [1_u8].as_slice()].concat();
    let edges: [&[u8]; 5] = [&[0; 32], &one, &P256_ORDER, &[0xff; 32], r];
    let pick = |rng: &mut Rng| edges.get(rng.below(edges.len())).copied().unwrap_or(r);
    let forged = [pick(rng), pick(rng)].concat();
    tally.input.clone_from(&forged);
    let result = world.verify(
        Kind::Envelope,
        &format!("{content}.{}", encode(&forged)),
        NOW,
    );
    tally.outcome("signature edge", "envelope", &result);
    if result.is_ok() {
        return Err("an edge-value signature verified".to_owned());
    }
    Ok(())
}

/// A changed identity is never the same identity, and the real message never verifies under it.
fn hostile_identity(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let raw = if rng.below(2) == 0 {
        mutate(rng, &world.raw_identity)
    } else {
        // Keeps the shape, so a changed key gets through to signature checks.
        let text = String::from_utf8_lossy(&world.raw_identity).into_owned();
        let key = world.ana.public.encoded();
        let mut changed = key.clone().into_bytes();
        let at = rng.below(changed.len());
        if let Some(byte) = changed.get_mut(at) {
            *byte = b'A' + u8::try_from(rng.below(26)).unwrap_or(0);
        }
        text.replacen(&key, &String::from_utf8_lossy(&changed), 1)
            .into_bytes()
    };
    tally.input.clone_from(&raw);
    let encoded_text =
        String::from_utf8_lossy(&mutate(rng, world.ana.identity.encoded().as_bytes())).into_owned();
    let _ = Identity::from_encoded(&encoded_text);
    let _ = Identity::guest_from_encoded(&encoded_text);
    let _ = Identity::parse_guest(&raw);

    let Ok(identity) = Identity::parse(&raw) else {
        tally.outcome("identity", "parse", &Err(Error::Malformed));
        return Ok(());
    };
    tally.outcome("identity", "parse", &Ok(()));
    if identity.encoded() != encode(&raw) {
        return Err("an identity doesn't round-trip".to_owned());
    }
    let id = format!("splint1{}", sha256_hex(&raw));
    if identity.id().as_str() != id {
        return Err("an identity has an ID that isn't its hash".to_owned());
    }
    if raw == world.raw_identity {
        return Ok(());
    }
    let result =
        VerifiedEnvelope::verify(world.compact(Kind::Envelope), &identity, NOW).map(|_| ());
    tally.outcome("under changed identity", "envelope", &result);
    if result.is_ok() {
        return Err("a message verified under a changed identity".to_owned());
    }
    let result = AccessProof::verify(
        world.compact(Kind::Access),
        &identity,
        HOST_A,
        ACCESS_METHOD,
        ACCESS_PATH,
        ACCESS_BODY,
        NOW,
    );
    tally.outcome("under changed identity", "access proof", &result);
    if result.is_ok() {
        return Err("a proof verified under a changed identity".to_owned());
    }
    Ok(())
}

fn hostile_public_key(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let bytes = mutate(rng, world.ana.public.as_bytes());
    tally.input.clone_from(&bytes);
    let text =
        String::from_utf8_lossy(&mutate(rng, world.ana.public.encoded().as_bytes())).into_owned();
    let _ = PublicKey::from_encoded(&text);
    let Ok(key) = PublicKey::from_bytes(&bytes) else {
        return Ok(());
    };
    let result = DeliveryProof::verify(
        world.compact(Kind::Delivery),
        &key,
        &world.message_id,
        HOST_A,
        HOST_B,
        NOW,
    );
    tally.outcome("under changed key", "delivery proof", &result);
    if result.is_ok() && bytes != world.ana.public.as_bytes() {
        return Err("a proof verified under a changed key".to_owned());
    }
    Ok(())
}

/// An address ends up in a URL, so what passes must be nothing but a handle and a host name.
fn hostile_address(rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let address = mutate(rng, b"ana.jeff~host.example:7001");
    tally.input.clone_from(&address);
    let text = String::from_utf8_lossy(&address);
    let _ = is_valid_handle(&text);
    let Ok((name, domain)) = parse_address(&text) else {
        tally.outcome("address", "parse", &Err(Error::Malformed));
        return Ok(());
    };
    tally.outcome("address", "parse", &Ok(()));
    let name_ok = !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name.matches('.').count() <= 1
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b));
    let domain_ok = !domain.is_empty()
        && domain.len() <= 255
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"[].-:".contains(&b));
    let one_spelling = canonical_address(&text).as_deref() == Ok(&*text);
    if !name_ok || !domain_ok || !one_spelling || format!("{name}~{domain}") != text {
        return Err("a hostile address passed".to_owned());
    }
    Ok(())
}

/// Every other type a host or Signet reads straight from the wire.
fn hostile_wire_types(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let seeds = [
        r#""peer_refused""#.to_owned(),
        quoted(world.message_id.as_str()),
        world.payload(Kind::Delivery).to_owned(),
        world.payload(Kind::Access).to_owned(),
    ];
    let seed = seeds.get(rng.below(seeds.len())).map_or("", String::as_str);
    let bytes = mutate(rng, seed.as_bytes());
    tally.input.clone_from(&bytes);
    let _ = serde_json::from_slice::<MessageId>(&bytes);
    let _ = serde_json::from_slice::<SplintId>(&bytes);
    let _ = serde_json::from_slice::<DeliveryProof>(&bytes);
    let _ = serde_json::from_slice::<AccessProof>(&bytes);
    if let Ok(failure) = serde_json::from_slice::<DeliveryFailure>(&bytes) {
        let word: String = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if word != failure.as_str() {
            return Err("a delivery failure parsed from some other word".to_owned());
        }
        tally.note("parsed: a delivery failure from mutated bytes");
    }
    Ok(())
}

fn hostile_key_document(world: &World, rng: &mut Rng, tally: &mut Tally) {
    let bytes = mutate(rng, &world.ana.pkcs8);
    tally.input.clone_from(&bytes);
    let accepted = SigningKey::from_pkcs8(&bytes).is_ok();
    let result = if accepted {
        Ok(())
    } else {
        Err(Error::Malformed)
    };
    tally.outcome("key document", "parse", &result);
}

/// The limit and the clock, against a model of what each should do at its edge.
fn clock_and_size_edges(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let kind = KINDS
        .get(rng.below(KINDS.len()))
        .copied()
        .unwrap_or(Kind::Envelope);
    let now = date_near_now(rng).saturating_add(if rng.below(2) == 0 { 0 } else { LIFETIME });
    let result = world.verify(kind, world.compact(kind), now);
    tally.outcome("clock edge", &kind.to_string(), &result);
    let should_pass = match kind {
        Kind::Envelope => now < NOW + LIFETIME && NOW <= now.saturating_add(CLOCK_TOLERANCE_SECS),
        Kind::Delivery | Kind::Access => NOW.abs_diff(now) <= CLOCK_TOLERANCE_SECS,
    };
    if result.is_ok() != should_pass {
        return Err(format!("{kind} at clock {now} gave {result:?}"));
    }
    if rng.below(64) == 0 {
        let padding = MAX_COMPACT_LEN.saturating_sub(world.compact(kind).len());
        let oversized = format!(
            "{}{}",
            world.compact(kind),
            "A".repeat(padding + 1 + rng.below(16))
        );
        let result = world.verify(kind, &oversized, NOW);
        tally.outcome("over the size limit", &kind.to_string(), &result);
        if result != Err(Error::Malformed) {
            return Err(format!("{kind} over the limit gave {result:?}"));
        }
    }
    Ok(())
}

/// What a stolen key does to a sealed body: changes any of it and signs it again, or what anyone does to
/// the opening a Signet kept. Nothing opens to other words than the sender sealed, and a kept form never
/// passes for one off the wire. A host can't sign, so what it changes is the tampering cases above.
fn hostile_sealed(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let mallory = world.mallory.identity.id();
    // A body the change left no longer sealed is a stolen key's own words in the open, which is
    // nothing the sealing could have kept from it.
    let opened = |envelope: VerifiedEnvelope| {
        if !envelope.is_sealed() {
            return Err(Error::Malformed);
        }
        envelope
            .open(mallory, &world.mallory.seal)
            .map(|open| open.body() == SEALED_WORDS)
    };
    if rng.below(2) == 0 {
        let original = signed_content(&world.sealed);
        let payload = URL_SAFE_NO_PAD
            .decode(original.split('.').nth(1).unwrap_or_default())
            .map_err(|_| "a sealed payload isn't base64".to_owned())?;
        let changed = mutate(rng, &payload);
        tally.input.clone_from(&changed);
        let compact = world.ana.sign(ENVELOPE_TYPE, &changed)?;
        // Re-signed, so this is a stolen key's doing. It can change the sender's own copy, which the
        // recipient never opens, but whatever opens has to be the words the commitment names.
        let words = VerifiedEnvelope::verify(&compact, &world.ana.identity, NOW).and_then(opened);
        let outcome = match &words {
            Ok(_) => Ok(()),
            Err(error) => Err(error.clone()),
        };
        tally.outcome("re-signed sealed", "envelope", &outcome);
        if words.is_ok_and(|same| !same) {
            return Err("a sealed body opened to other words".to_owned());
        }
    } else {
        let (compact, opening) = world.sealed_kept.split_once('~').ok_or("no opening kept")?;
        let changed = mutate(rng, opening.as_bytes());
        tally.input.clone_from(&changed);
        let kept = format!("{compact}~{}", String::from_utf8_lossy(&changed));
        let words = VerifiedEnvelope::verify_ignoring_clock(&kept, &world.ana.identity)
            .map(|envelope| envelope.body() == SEALED_WORDS);
        let outcome = match &words {
            Ok(_) => Ok(()),
            Err(error) => Err(error.clone()),
        };
        tally.outcome("changed opening", "kept envelope", &outcome);
        if words.is_ok_and(|same| !same) {
            return Err("a changed opening read as other words".to_owned());
        }
        if VerifiedEnvelope::verify(&kept, &world.ana.identity, NOW).is_ok() {
            return Err("a kept form passed for one off the wire".to_owned());
        }
    }
    Ok(())
}

fn one_iteration(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let kind = KINDS
        .get(rng.below(KINDS.len()))
        .copied()
        .unwrap_or(Kind::Envelope);
    match rng.below(26) {
        24..=25 => hostile_sealed(world, rng, tally),
        14..=23 => documents::one_iteration(world, rng, tally),
        0..=1 => tamper_compact(world, rng, tally, kind),
        2..=3 => tamper_part(world, rng, tally, kind),
        4..=6 => resign_payload(world, rng, tally, kind),
        7 => resign_header(world, rng, tally, kind),
        8 => wrong_signer_or_type(world, rng, tally, kind),
        9 => signature_edges(world, rng, tally),
        10 => hostile_identity(world, rng, tally).and(hostile_public_key(world, rng, tally)),
        11 => hostile_address(rng, tally),
        12 => {
            hostile_key_document(world, rng, tally);
            hostile_wire_types(world, rng, tally)
        }
        _ => clock_and_size_edges(world, rng, tally),
    }
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse().ok()
}

fn hex(bytes: &[u8]) -> String {
    let shown = bytes.get(..MAX_REPORTED_INPUT_BYTES).unwrap_or(bytes);
    shown.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
#[ignore = "runs for minutes: make test-hostile-input"]
fn nothing_hostile_panics_hangs_or_verifies() {
    let seed = env_u64("SPLINT_FUZZ_SEED").unwrap_or_else(|| {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        elapsed.as_nanos() as u64
    });
    let only = env_u64("SPLINT_FUZZ_ONLY");
    let budget = Duration::from_secs(env_u64("SPLINT_FUZZ_SECS").unwrap_or(DEFAULT_SECS));
    println!(
        "seed {seed}: replay with SPLINT_FUZZ_SEED={seed}, one iteration with SPLINT_FUZZ_ONLY=<n>"
    );

    // Every refusal below would mean nothing if the valid objects were refused too.
    let world = World::new(seed).expect("the valid objects should verify");

    let progress = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let worker = {
        let (progress, stop) = (progress.clone(), stop.clone());
        thread::spawn(move || {
            let mut tally = Tally::default();
            let mut failures = Vec::new();
            let mut iteration = only.unwrap_or(0);
            while !stop.load(Ordering::Relaxed) {
                let mut rng = Rng::for_iteration(seed, iteration);
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    one_iteration(&world, &mut rng, &mut tally)
                }));
                let problem = match outcome {
                    Ok(Ok(())) => None,
                    Ok(Err(problem)) => Some(problem),
                    Err(_) => Some("panicked".to_owned()),
                };
                if let Some(problem) = problem
                    && failures.len() < MAX_REPORTED_FAILURES
                {
                    failures.push(format!(
                        "iteration {iteration}: {problem}; input hex {}",
                        hex(&tally.input)
                    ));
                }
                iteration += 1;
                progress.store(iteration, Ordering::Relaxed);
                if only.is_some() {
                    break;
                }
            }
            (tally, failures)
        })
    };

    let started = Instant::now();
    let mut last_seen = (0, Instant::now());
    while !worker.is_finished() && started.elapsed() < budget {
        thread::sleep(Duration::from_millis(250));
        let now_at = progress.load(Ordering::Relaxed);
        if now_at != last_seen.0 {
            last_seen = (now_at, Instant::now());
        }
        assert!(
            last_seen.1.elapsed() < HANG_AFTER,
            "hung: seed {seed} iteration {now_at} made no progress for {HANG_AFTER:?}"
        );
    }
    stop.store(true, Ordering::Relaxed);
    let (tally, failures) = worker.join().expect("the worker catches its own panics");

    let iterations = progress.load(Ordering::Relaxed);
    println!(
        "seed {seed}: {iterations} iterations in {:.0}s, in release mode: {}",
        started.elapsed().as_secs_f64(),
        !cfg!(debug_assertions)
    );
    for (outcome, count) in &tally.outcomes {
        println!("{count:>10}  {outcome}");
    }
    println!("accepted or parsed without breaking a rule, for a person to judge:");
    for (note, count) in &tally.notes {
        println!("{count:>10}  {note}");
    }
    assert!(failures.is_empty(), "seed {seed}:\n{}", failures.join("\n"));
}

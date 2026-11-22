//! An owner's key held in a passkey, signing through WebAuthn. See "Owner keys in a passkey" in
//! `docs/protocol.md`.
//!
//! A passkey never signs bytes it's handed: it signs its own `authenticatorData` and a hash of the
//! browser's `clientDataJSON`, which carries a challenge. So a WA256 object's challenge is the hash of
//! the exact JWS signing input, and the assertion stands in for an ES256 signature. Nothing here makes
//! one: the owner's browser does, and only tests fake an authenticator.
//!
//! One touch can sign several objects at once, such as a binding, rules and a delegation, which an
//! owner setting up their controls signs together. The assertion's challenge then hashes the list of
//! their signing inputs' hashes, which each object carries, and each still verifies alone.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::identity::hex;
use crate::{Error, PublicKey, canonical_domain, jws};

/// Past this a WA256 signature segment is refused unread. A real assertion is a few hundred bytes.
pub(crate) const MAX_SEGMENT_CHARS: usize = 2048;
const RP_ID_HASH_LEN: usize = 32;
/// The RP ID hash, the flags byte and the 4-byte sign counter. Anything after is signed and ignored.
const MIN_AUTHENTICATOR_DATA_LEN: usize = RP_ID_HASH_LEN + 1 + 4;
const FLAGS_AT: usize = RP_ID_HASH_LEN;
/// Someone touched the authenticator.
const USER_PRESENT: u8 = 0x01;
/// And it checked who: a fingerprint, a face or a PIN. Every passkey store does, and the page asks.
const USER_VERIFIED: u8 = 0x04;
const GET_TYPE: &str = "webauthn.get";
const ORIGIN_SCHEME: &str = "https://";
/// Names that only ever reach this machine, so any program on it can serve a page there.
const LOCALHOST: &str = "localhost";
const UNDER_LOCALHOST: &str = ".localhost";
/// Begins what a batch's challenge hashes, so it can't be any one object's challenge, which hashes a
/// signing input, and every signing input begins with base64url.
const BATCH_TAG: &[u8] = b"splint wa256 batch v1";
/// A batch is several objects: one alone is signed without one.
const MIN_BATCH: usize = 2;
/// Enough for everything setting up controls signs together, with room, and small enough that the
/// segment stays well inside its limit.
pub const MAX_BATCH: usize = 8;
const HASH_HEX_LEN: usize = 64;

/// The WebAuthn relying party a passkey is tied to: a lowercase hostname, spelled as an address's
/// domain is, with no port and no IP address. A passkey made for one RP ID signs for no other, so a
/// page elsewhere can't use it. Never `localhost` or a name under it: any program on the owner's
/// machine can serve a page there, on any port, and have their touch sign what it likes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpId(String);

impl RpId {
    pub fn new(text: &str) -> Result<Self, Error> {
        let is_ip = text.parse::<Ipv4Addr>().is_ok();
        let one_spelling = canonical_domain(text).is_ok_and(|domain| domain == text);
        let local = text == LOCALHOST || text.ends_with(UNDER_LOCALHOST);
        if !one_spelling || is_ip || local || text.contains([':', '[']) {
            return Err(Error::Malformed);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn origin(&self) -> String {
        format!("{ORIGIN_SCHEME}{}", self.0)
    }

    /// Whether a page at `origin` may sign for this RP: `https://` and the RP ID, with no port.
    fn allows_origin(&self, origin: &str) -> bool {
        origin == self.origin()
    }

    fn hash(&self) -> digest::Digest {
        digest::digest(&digest::SHA256, self.0.as_bytes())
    }
}

/// A WA256 signature segment: an assertion's three parts, each base64url, and the batch it signed if
/// it signed several objects, in this order and no other.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Assertion {
    /// `authenticatorData`.
    pub(crate) a: String,
    /// The hashes of the signing inputs of every object this one touch signed, in order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) b: Option<Vec<String>>,
    /// `clientDataJSON`, as the browser wrote it.
    pub(crate) c: String,
    /// The ECDSA signature, in DER as WebAuthn returns it.
    pub(crate) s: String,
}

/// What an owner's browser hands back from one `navigator.credentials.get`, raw.
pub struct PasskeyAssertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// ASN.1 DER, as WebAuthn returns it.
    pub signature: Vec<u8>,
}

/// What one touch signs: one signing input, or several, whose hashes every one of them carries.
pub struct Challenge {
    batch: Option<Vec<String>>,
    challenge: String,
}

impl Challenge {
    /// For signing inputs, `header.payload` with a WA256 header each, in the order given. One alone
    /// is signed as it always was, and up to [`MAX_BATCH`] together with one touch.
    pub fn for_inputs(inputs: &[&str]) -> Result<Self, Error> {
        match inputs {
            [] => Err(Error::Malformed),
            [one] => Ok(Self {
                batch: None,
                challenge: challenge_for(one),
            }),
            several => {
                let batch: Vec<String> = several.iter().map(|input| input_hash(input)).collect();
                let challenge = batch_challenge(&batch)?;
                Ok(Self {
                    batch: Some(batch),
                    challenge,
                })
            }
        }
    }

    /// What the page passes to `navigator.credentials.get` as the challenge, base64url.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Each signing input made whole with the one assertion, in the order given. Nothing is
    /// checked here: whoever takes these verifies each, as every reader does.
    pub fn signed(
        &self,
        inputs: &[&str],
        assertion: &PasskeyAssertion,
    ) -> Result<Vec<String>, Error> {
        let segment = serde_json::to_vec(&Assertion {
            a: jws::encode(&assertion.authenticator_data),
            b: self.batch.clone(),
            c: jws::encode(&assertion.client_data_json),
            s: jws::encode(&assertion.signature),
        })
        .map_err(|_| Error::Malformed)?;
        let segment = jws::encode(&segment);
        Ok(inputs
            .iter()
            .map(|input| format!("{input}.{segment}"))
            .collect())
    }
}

/// How a batch lists a signing input: the lowercase hex SHA-256 of its bytes.
fn input_hash(signing_input: &str) -> String {
    hex(digest::digest(&digest::SHA256, signing_input.as_bytes()).as_ref())
}

/// The challenge for a batch: the tag, then each hash's 32 raw bytes in order, hashed. The list has to
/// be 2 to 8 distinct hashes in their one spelling, or it's malformed.
fn batch_challenge(batch: &[String]) -> Result<String, Error> {
    if !(MIN_BATCH..=MAX_BATCH).contains(&batch.len()) {
        return Err(Error::Malformed);
    }
    let distinct: BTreeSet<&String> = batch.iter().collect();
    if distinct.len() != batch.len() {
        return Err(Error::Malformed);
    }
    let mut hashed = digest::Context::new(&digest::SHA256);
    hashed.update(BATCH_TAG);
    for hash in batch {
        hashed.update(&hash_bytes(hash)?);
    }
    Ok(jws::encode(hashed.finish().as_ref()))
}

/// A hash written as 64 lowercase hex digits, and no other way.
fn hash_bytes(text: &str) -> Result<Vec<u8>, Error> {
    let lower_hex = |byte: &u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    if text.len() != HASH_HEX_LEN || !text.as_bytes().iter().all(lower_hex) {
        return Err(Error::Malformed);
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .ok_or(Error::Malformed)
        })
        .collect()
}

/// The fields of `clientDataJSON` a verifier reads. Browsers add others, which are allowed, but no
/// key may appear twice, as parsers disagree on which one wins.
struct ClientData {
    kind: String,
    challenge: String,
    origin: String,
    cross_origin: Option<bool>,
}

impl<'de> Deserialize<'de> for ClientData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ClientDataVisitor)
    }
}

struct ClientDataVisitor;

impl<'de> Visitor<'de> for ClientDataVisitor {
    type Value = ClientData;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("clientDataJSON")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ClientData, A::Error> {
        let mut seen = BTreeSet::new();
        let (mut kind, mut challenge, mut origin, mut cross_origin) = (None, None, None, None);
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate key"));
            }
            match key.as_str() {
                "type" => kind = Some(map.next_value::<String>()?),
                "challenge" => challenge = Some(map.next_value::<String>()?),
                "origin" => origin = Some(map.next_value::<String>()?),
                "crossOrigin" => cross_origin = Some(map.next_value::<bool>()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(ClientData {
            kind: kind.ok_or_else(|| de::Error::missing_field("type"))?,
            challenge: challenge.ok_or_else(|| de::Error::missing_field("challenge"))?,
            origin: origin.ok_or_else(|| de::Error::missing_field("origin"))?,
            cross_origin,
        })
    }
}

/// What a verifier's challenge has to be: the hash of the exact header and payload segments.
pub(crate) fn challenge_for(signing_input: &str) -> String {
    jws::encode(digest::digest(&digest::SHA256, signing_input.as_bytes()).as_ref())
}

/// Checks a WA256 signature segment over `signing_input`, made by the passkey `key` for `rp`.
pub(crate) fn verify(
    signing_input: &str,
    segment: &str,
    key: &PublicKey,
    rp: &RpId,
) -> Result<(), Error> {
    if segment.len() > MAX_SEGMENT_CHARS {
        return Err(Error::Malformed);
    }
    let bytes = jws::decode(segment)?;
    let assertion: Assertion = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
    if serde_json::to_vec(&assertion).map_err(|_| Error::Malformed)? != bytes {
        return Err(Error::Malformed);
    }
    let authenticator_data = jws::decode(&assertion.a)?;
    let client_data_json = jws::decode(&assertion.c)?;
    let signature = jws::decode(&assertion.s)?;
    let challenge = match &assertion.b {
        None => challenge_for(signing_input),
        Some(batch) => {
            let challenge = batch_challenge(batch)?;
            if !batch.contains(&input_hash(signing_input)) {
                return Err(Error::BadSignature);
            }
            challenge
        }
    };
    // JSON is UTF-8, and serde_json doesn't check strings it skips, so a field a verifier doesn't read
    // could hold bytes another reader refuses.
    let client_data_text = std::str::from_utf8(&client_data_json).map_err(|_| Error::Malformed)?;
    // Nor does it check escapes there, so every string is decoded once, which refuses half a
    // character, as every other reader does.
    serde_json::from_str::<serde_json::Value>(client_data_text).map_err(|_| Error::Malformed)?;
    let client_data: ClientData =
        serde_json::from_str(client_data_text).map_err(|_| Error::Malformed)?;
    if client_data.kind != GET_TYPE
        || client_data.challenge != challenge
        || !rp.allows_origin(&client_data.origin)
        || client_data.cross_origin == Some(true)
    {
        return Err(Error::BadSignature);
    }
    if authenticator_data.len() < MIN_AUTHENTICATOR_DATA_LEN {
        return Err(Error::BadSignature);
    }
    let rp_id_hash = authenticator_data.get(..RP_ID_HASH_LEN);
    let flags = authenticator_data
        .get(FLAGS_AT)
        .copied()
        .unwrap_or_default();
    let present_and_verified = USER_PRESENT | USER_VERIFIED;
    if rp_id_hash != Some(rp.hash().as_ref())
        || flags & present_and_verified != present_and_verified
    {
        return Err(Error::BadSignature);
    }
    let mut signed = authenticator_data;
    signed.extend_from_slice(digest::digest(&digest::SHA256, &client_data_json).as_ref());
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, key.as_bytes())
        .verify(&signed, &signature)
        .map_err(|_| Error::BadSignature)
}

/// A software key acting as an authenticator in a browser, for tests. It builds `authenticatorData`
/// and `clientDataJSON` as a browser would, and each case can change any part before it signs.
#[cfg(test)]
pub(crate) mod authenticator {
    use super::*;
    use crate::{Identity, RecoveryRule, SealPublicKey, SigningKey};

    /// What the browser and authenticator put in, before signing, for a test to change.
    pub(crate) struct Made {
        pub(crate) client_data: serde_json::Value,
        /// Written instead of `client_data` when set, for spellings `serde_json` wouldn't write.
        pub(crate) client_data_text: Option<String>,
        pub(crate) rp_id_hash: Vec<u8>,
        pub(crate) flags: u8,
        pub(crate) counter: Vec<u8>,
    }

    pub(crate) struct Authenticator {
        pub(crate) key: SigningKey,
        pub(crate) rp: RpId,
    }

    impl Authenticator {
        pub(crate) fn new(rp: &str) -> Self {
            Self {
                key: SigningKey::generate().unwrap(),
                rp: RpId::new(rp).unwrap(),
            }
        }

        pub(crate) fn identity(&self, seal: &SealPublicKey, recovery: RecoveryRule) -> Identity {
            Identity::for_passkey(&self.key.public_key(), &self.rp, seal, recovery).unwrap()
        }

        /// The same object an ES256 key signed, signed here instead: the header becomes WA256, the
        /// payload stays byte for byte.
        pub(crate) fn resign(&self, es256: &str) -> String {
            self.resign_with(es256, |_| {})
        }

        pub(crate) fn resign_with(&self, es256: &str, change: impl FnOnce(&mut Made)) -> String {
            let signing_input = as_wa256_input(es256);
            let assertion = self.assert_with(&challenge_for(&signing_input), change);
            let segment = serde_json::to_vec(&Assertion {
                a: jws::encode(&assertion.authenticator_data),
                b: None,
                c: jws::encode(&assertion.client_data_json),
                s: jws::encode(&assertion.signature),
            })
            .unwrap();
            format!("{signing_input}.{}", jws::encode(&segment))
        }

        /// Several signing inputs signed with one touch, as an owner's page signs them.
        pub(crate) fn sign_together(&self, inputs: &[&str]) -> Vec<String> {
            let challenge = Challenge::for_inputs(inputs).unwrap();
            let assertion = self.assert(challenge.challenge());
            challenge.signed(inputs, &assertion).unwrap()
        }

        /// What a browser and this authenticator return for a challenge.
        pub(crate) fn assert(&self, challenge: &str) -> PasskeyAssertion {
            self.assert_with(challenge, |_| {})
        }

        fn assert_with(&self, challenge: &str, change: impl FnOnce(&mut Made)) -> PasskeyAssertion {
            let mut made = Made {
                client_data: serde_json::json!({
                    "type": GET_TYPE,
                    "challenge": challenge,
                    "origin": self.rp.origin(),
                    "crossOrigin": false,
                }),
                client_data_text: None,
                rp_id_hash: self.rp.hash().as_ref().to_vec(),
                flags: USER_PRESENT | USER_VERIFIED,
                counter: vec![0; 4],
            };
            change(&mut made);
            let client_data_json = made
                .client_data_text
                .unwrap_or_else(|| made.client_data.to_string())
                .into_bytes();
            let mut authenticator_data = made.rp_id_hash;
            authenticator_data.push(made.flags);
            authenticator_data.extend_from_slice(&made.counter);
            let mut signed = authenticator_data.clone();
            signed.extend_from_slice(digest::digest(&digest::SHA256, &client_data_json).as_ref());
            PasskeyAssertion {
                signature: self.key.sign_der(&signed).unwrap(),
                authenticator_data,
                client_data_json,
            }
        }
    }

    /// The signing input an ES256 object would have with a WA256 header, its payload byte for byte.
    pub(crate) fn as_wa256_input(es256: &str) -> String {
        let mut parts = es256.split('.');
        let header = jws::decode(parts.next().unwrap()).unwrap();
        let payload = parts.next().unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
        let typ = header["typ"].as_str().unwrap();
        let wa256 = format!(r#"{{"alg":"WA256","typ":"{typ}"}}"#);
        format!("{}.{payload}", jws::encode(wa256.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::authenticator::{Authenticator, Made};
    use super::*;
    use crate::changes::VerifiedAcceptance;
    use crate::grants::{GrantDraft, GrantLimits, VerifiedGrant, VerifiedRevocation};
    use crate::identity::hex;
    use crate::requests::{PersonTextFor, VerifiedPersonText};
    use crate::rules::{RulesDraft, VerifiedRules};
    use crate::{
        Identity, RecoveryRule, RetirementReason, SigningKey, VerifiedBinding, VerifiedRelease,
        VerifiedRetirement,
    };

    const NOW: u64 = 1_793_750_400;
    const RP: &str = "host.example";
    const ADDRESS: &str = "ana~host.example";

    fn backed_up(key: &SigningKey) -> (SigningKey, Identity) {
        let backup = SigningKey::generate().unwrap();
        let rule = RecoveryRule::backup_key(&backup.public_key());
        let identity = Identity::create(key, &crate::test_seal(), rule).unwrap();
        (backup, identity)
    }

    /// An agent and its backup, which vouches for whichever owner a binding names.
    struct Agent {
        key: SigningKey,
        backup: SigningKey,
        identity: Identity,
    }

    fn agent() -> Agent {
        let key = SigningKey::generate().unwrap();
        let (backup, identity) = backed_up(&key);
        Agent {
            key,
            backup,
            identity,
        }
    }

    impl Agent {
        /// The owner's half as `signer` would sign it with ES256 for `owner`, and the vouch.
        fn halves(&self, signer: &SigningKey, owner: &Identity) -> (String, String) {
            let from_owner = VerifiedBinding::sign(
                signer,
                &self.backup,
                owner.id(),
                &self.identity,
                ADDRESS,
                1,
                NOW,
            )
            .unwrap();
            let (half, vouch) = from_owner.split_once('~').unwrap();
            (half.to_owned(), vouch.to_owned())
        }

        /// The whole binding, the agent's half signed whatever the owner's half holds, so a refusal
        /// is the owner's half's.
        fn binding(&self, owner_half: &str, vouch: &str) -> String {
            let digest = digest::digest(&digest::SHA256, owner_half.as_bytes());
            let payload = format!(r#"{{"v":1,"binding":"{}"}}"#, hex(digest.as_ref()));
            let accepted =
                jws::sign(&self.key, "splint-binding-accept", payload.as_bytes()).unwrap();
            format!("{owner_half}~{accepted}~{vouch}")
        }
    }

    fn passkey_owner() -> (Authenticator, Identity) {
        let authenticator = Authenticator::new(RP);
        let identity = authenticator.identity(
            &crate::test_seal(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        );
        (authenticator, identity)
    }

    /// Every part of an assertion a verifier reads, changed in turn and signed again by the passkey,
    /// so each refusal is for that part and not the signature. Through a binding, as a host and a
    /// Signet check one.
    #[test]
    fn each_checked_part_of_a_passkey_signature_is_refused_when_changed() {
        let (authenticator, owner) = passkey_owner();
        let agent = agent();
        let throwaway = SigningKey::generate().unwrap();
        let (half, vouch) = agent.halves(&throwaway, &owner);
        let verify = |owner_half: &str, owner: &Identity, bound: &Agent| {
            VerifiedBinding::verify(
                &bound.binding(owner_half, vouch.as_str()),
                owner,
                &bound.identity,
            )
            .err()
        };
        assert_eq!(verify(&authenticator.resign(&half), &owner, &agent), None);
        // Browsers add fields of their own, and those are signed too.
        let with_more = authenticator.resign_with(&half, |made| {
            made.client_data["other_keys_can_be_added_here"] =
                json!("do not compare clientDataJSON");
        });
        assert_eq!(verify(&with_more, &owner, &agent), None);

        type Change = fn(&mut Made);
        let changes: [(&str, Change, Error); 12] = [
            (
                "another challenge",
                |made| made.client_data["challenge"] = json!(challenge_for("x.y")),
                Error::BadSignature,
            ),
            (
                "another origin",
                |made| made.client_data["origin"] = json!("https://evil.example"),
                Error::BadSignature,
            ),
            (
                "the origin with a port",
                |made| made.client_data["origin"] = json!("https://host.example:8443"),
                Error::BadSignature,
            ),
            (
                "a passkey being made",
                |made| made.client_data["type"] = json!("webauthn.create"),
                Error::BadSignature,
            ),
            (
                "inside another site's frame",
                |made| made.client_data["crossOrigin"] = json!(true),
                Error::BadSignature,
            ),
            (
                "another RP ID's hash",
                |made| {
                    made.rp_id_hash = digest::digest(&digest::SHA256, b"evil.example")
                        .as_ref()
                        .to_vec()
                },
                Error::BadSignature,
            ),
            (
                "nobody present",
                |made| made.flags &= !USER_PRESENT,
                Error::BadSignature,
            ),
            (
                "nobody verified",
                |made| made.flags &= !USER_VERIFIED,
                Error::BadSignature,
            ),
            (
                "an authenticatorData with its counter cut short",
                |made| made.counter.truncate(3),
                Error::BadSignature,
            ),
            (
                "no challenge",
                |made| {
                    made.client_data = json!({"type": GET_TYPE, "origin": "https://host.example"})
                },
                Error::Malformed,
            ),
            (
                "a key twice",
                |made| {
                    let challenge = made.client_data["challenge"].as_str().unwrap().to_owned();
                    made.client_data_text = Some(format!(
                        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://evil.example","origin":"https://host.example"}}"#
                    ));
                },
                Error::Malformed,
            ),
            (
                "a segment past 2 KiB",
                |made| made.client_data["padding"] = json!("x".repeat(MAX_SEGMENT_CHARS)),
                Error::Malformed,
            ),
        ];
        for (name, change, refused) in changes {
            let changed = authenticator.resign_with(&half, change);
            assert_eq!(verify(&changed, &owner, &agent), Some(refused), "{name}");
        }

        // Another passkey's signature, and the passkey's point signing as a file key, are refused.
        let other = Authenticator::new(RP);
        assert_eq!(
            verify(&other.resign(&half), &owner, &agent),
            Some(Error::BadSignature)
        );
        let (as_file_key, _) = agent.halves(&authenticator.key, &owner);
        assert_eq!(
            verify(&as_file_key, &owner, &agent),
            Some(Error::BadSignature)
        );
        // A file key's ID takes no assertion, even from the same point, and even one made for an
        // empty RP ID, which is what a file key's would be if only origin and RP hash refused it.
        let (_, file_owner) = backed_up(&authenticator.key);
        let (for_file_owner, file_vouch) = agent.halves(&throwaway, &file_owner);
        let for_no_rp = authenticator.resign_with(&for_file_owner, |made| {
            made.client_data["origin"] = json!(ORIGIN_SCHEME);
            made.rp_id_hash = digest::digest(&digest::SHA256, b"").as_ref().to_vec();
        });
        let file_binding = agent.binding(&for_no_rp, &file_vouch);
        assert_eq!(
            VerifiedBinding::verify(&file_binding, &file_owner, &agent.identity).err(),
            Some(Error::BadSignature)
        );

        // Only an owner's key may be a passkey, so an agent whose key is one can't be bound.
        let passkey_agent = Authenticator::new(RP);
        let backup = SigningKey::generate().unwrap();
        let bound = Agent {
            identity: passkey_agent.identity(
                &crate::test_seal(),
                RecoveryRule::backup_key(&backup.public_key()),
            ),
            key: passkey_agent.key,
            backup,
        };
        let (half, vouch) = bound.halves(&throwaway, &owner);
        let binding = bound.binding(&authenticator.resign(&half), &vouch);
        assert_eq!(
            VerifiedBinding::verify(&binding, &owner, &bound.identity).err(),
            Some(Error::WrongSigner)
        );
    }

    /// Whatever an owner signs, a passkey can sign, and only as a passkey: the same point signing as a
    /// file key is refused for each, as each is checked through the owner's identity.
    #[test]
    fn a_passkey_signs_every_kind_of_owner_statement_and_only_as_a_passkey() {
        let (authenticator, owner) = passkey_owner();
        let key = &authenticator.key;
        let (agent, contact) = (agent().identity, agent().identity);
        let draft: RulesDraft = serde_json::from_value(json!({
            "paused": false,
            "contacts": [],
            "invites": [],
            "limits": {"new_requests_per_contact_per_day": 3, "open_requests_per_contact": 3, "open_approvals": 10},
        }))
        .unwrap();
        let grant = GrantDraft {
            holder: agent.id().clone(),
            resource: "docs.example".to_owned(),
            operations: vec!["docs.read".to_owned()],
            limits: GrantLimits { calls_per_hour: 10 },
            life_secs: 3600,
        }
        .sign(key, owner.id(), NOW)
        .unwrap();
        let to = PersonTextFor {
            agent: agent.id(),
            to: contact.id(),
            request: None,
        };
        let head = hex(&[7; 32]);
        type Check<'a> = Box<dyn Fn(&str) -> bool + 'a>;
        let signed: Vec<(&str, String, Check<'_>)> = vec![
            (
                "rules",
                draft.sign(key, owner.id(), agent.id(), 1, NOW).unwrap(),
                Box::new(|c| VerifiedRules::verify(c, &owner, 0, NOW).is_ok()),
            ),
            (
                "release",
                VerifiedRelease::sign(key, owner.id(), agent.id(), None, 1, NOW).unwrap(),
                Box::new(|c| VerifiedRelease::verify(c, &owner, agent.id()).is_ok()),
            ),
            (
                "retirement",
                VerifiedRetirement::sign(
                    key,
                    owner.id(),
                    agent.id(),
                    RetirementReason::Finished,
                    NOW,
                )
                .unwrap(),
                Box::new(|c| VerifiedRetirement::verify(c, &owner).is_ok()),
            ),
            (
                "grant",
                grant.grant.clone(),
                Box::new(|c| VerifiedGrant::verify(c, &owner, NOW).is_ok()),
            ),
            (
                "revocation",
                VerifiedRevocation::sign(key, owner.id(), &grant.id, NOW).unwrap(),
                Box::new(|c| VerifiedRevocation::verify(c, &owner).is_ok()),
            ),
            (
                "person text",
                VerifiedPersonText::sign(key, owner.id(), to, "Afternoons work", NOW).unwrap(),
                Box::new(|c| VerifiedPersonText::verify(c, &owner).is_ok()),
            ),
            (
                "acceptance",
                VerifiedAcceptance::sign(key, owner.id(), agent.id(), contact.id(), &head, 1, NOW)
                    .unwrap(),
                Box::new(|c| VerifiedAcceptance::verify(c, &owner, agent.id()).is_ok()),
            ),
        ];
        for (name, as_file_key, verifies) in signed {
            assert!(!verifies(&as_file_key), "{name} as a file key");
            assert!(verifies(&authenticator.resign(&as_file_key)), "{name}");
        }
    }

    /// An owner with a file key can move to a passkey by recovery, and back. What each key signed
    /// counts while it's the newest, and is read back as history after.
    #[test]
    fn an_owner_moves_from_a_file_key_to_a_passkey_and_back() {
        let file_key = SigningKey::generate().unwrap();
        let (backup, owner) = backed_up(&file_key);
        let agent = agent();
        let authenticator = Authenticator::new(RP);
        let next_backup = SigningKey::generate().unwrap();
        let moved = owner
            .recover_to_passkey(
                &backup,
                &authenticator.key.public_key(),
                &authenticator.rp,
                &crate::test_seal(),
                RecoveryRule::backup_key(&next_backup.public_key()),
                NOW,
            )
            .unwrap();
        let moved = Identity::from_encoded(&moved.encoded()).unwrap();
        assert_eq!(
            (moved.id(), moved.passkey_rp()),
            (owner.id(), Some(&authenticator.rp))
        );

        let (by_file, vouch) = agent.halves(&file_key, &owner);
        let by_file = agent.binding(&by_file, &vouch);
        let (by_passkey, vouch) = agent.halves(&authenticator.key, &owner);
        let by_passkey = agent.binding(&authenticator.resign(&by_passkey), &vouch);
        let now = |binding: &str, owner: &Identity| {
            VerifiedBinding::verify(binding, owner, &agent.identity).is_ok()
        };
        let then = |binding: &str, owner: &Identity| {
            VerifiedBinding::verify_history(binding, owner, &agent.identity).is_ok()
        };
        assert!(!now(&by_file, &moved) && then(&by_file, &moved));
        assert!(now(&by_passkey, &moved));

        // The passkey's point can't stay on as a file key.
        let kept = moved.recover(
            &next_backup,
            &authenticator.key.public_key(),
            moved.seal_key().unwrap(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
            NOW,
        );
        assert_eq!(kept.err(), Some(Error::Malformed));

        let new_file_key = SigningKey::generate().unwrap();
        let back = moved
            .recover(
                &next_backup,
                &new_file_key.public_key(),
                &crate::test_seal(),
                RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
                NOW,
            )
            .unwrap();
        let back = Identity::from_encoded(&back.encoded()).unwrap();
        assert_eq!(back.passkey_rp(), None);
        let (by_new_file, vouch) = agent.halves(&new_file_key, &owner);
        let by_new_file = agent.binding(&by_new_file, &vouch);
        assert!(now(&by_new_file, &back));
        assert!(!now(&by_passkey, &back) && then(&by_passkey, &back) && then(&by_file, &back));
    }

    /// A segment for `input` whose list is `batch`, spelled however it's given, and whose assertion is
    /// over the challenge that list would have, so a refusal is for the list and not the signature.
    fn with_batch(authenticator: &Authenticator, input: &str, batch: Vec<String>) -> String {
        let mut hashed = digest::Context::new(&digest::SHA256);
        hashed.update(BATCH_TAG);
        for hash in &batch {
            let raw: Vec<u8> = hash
                .as_bytes()
                .chunks(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            hashed.update(&raw);
        }
        let assertion = authenticator.assert(&jws::encode(hashed.finish().as_ref()));
        let segment = serde_json::to_vec(&Assertion {
            a: jws::encode(&assertion.authenticator_data),
            b: Some(batch),
            c: jws::encode(&assertion.client_data_json),
            s: jws::encode(&assertion.signature),
        })
        .unwrap();
        format!("{input}.{}", jws::encode(&segment))
    }

    /// One touch signs a binding, rules and a release together, and each verifies alone, through the
    /// checks a host and a Signet run. A list that doesn't hold an object's own hash, or holds it in
    /// another order or spelling, or twice, or with too few or too many others, is refused.
    #[test]
    fn one_touch_signs_several_objects_and_each_stands_alone() {
        let (authenticator, owner) = passkey_owner();
        let agent = agent();
        let throwaway = SigningKey::generate().unwrap();
        let (half, vouch) = agent.halves(&throwaway, &owner);
        let draft: RulesDraft = serde_json::from_value(json!({
            "paused": false,
            "contacts": [],
            "invites": [],
            "limits": {"new_requests_per_contact_per_day": 3, "open_requests_per_contact": 3, "open_approvals": 10},
        }))
        .unwrap();
        let id = agent.identity.id();
        let rules = draft.sign(&throwaway, owner.id(), id, 1, NOW).unwrap();
        let release = VerifiedRelease::sign(&throwaway, owner.id(), id, None, 2, NOW).unwrap();
        let inputs: Vec<String> = [&half, &rules, &release]
            .into_iter()
            .map(|es256| authenticator::as_wa256_input(es256))
            .collect();
        let inputs: Vec<&str> = inputs.iter().map(String::as_str).collect();
        let signed = authenticator.sign_together(&inputs);
        let binding_is = |owner_half: &str| {
            VerifiedBinding::verify(&agent.binding(owner_half, &vouch), &owner, &agent.identity)
                .err()
        };
        assert_eq!(binding_is(&signed[0]), None);
        assert!(VerifiedRules::verify(&signed[1], &owner, 0, NOW).is_ok());
        assert!(VerifiedRelease::verify(&signed[2], &owner, id).is_ok());

        // The same touch over an object it didn't list.
        let (_, segment) = signed[0].rsplit_once('.').unwrap();
        let retirement =
            VerifiedRetirement::sign(&throwaway, owner.id(), id, RetirementReason::Finished, NOW)
                .unwrap();
        let outsider = format!("{}.{segment}", authenticator::as_wa256_input(&retirement));
        assert_eq!(
            VerifiedRetirement::verify(&outsider, &owner).err(),
            Some(Error::BadSignature)
        );

        let own = input_hash(inputs[0]);
        let others: Vec<String> = (1..=8).map(|n| input_hash(&format!("other.{n}"))).collect();
        let lists: [(&str, Vec<String>, Error); 6] = [
            (
                "without its own hash",
                others[..3].to_vec(),
                Error::BadSignature,
            ),
            ("its own hash alone", vec![own.clone()], Error::Malformed),
            (
                "its own hash twice",
                vec![own.clone(), others[0].clone(), own.clone()],
                Error::Malformed,
            ),
            (
                "nine hashes",
                [vec![own.clone()], others.clone()].concat(),
                Error::Malformed,
            ),
            (
                "a hash in capitals",
                vec![own.to_uppercase(), others[0].clone()],
                Error::Malformed,
            ),
            (
                "a hash cut short",
                vec![own.clone(), others[0].chars().take(62).collect()],
                Error::Malformed,
            ),
        ];
        for (name, list, refused) in lists {
            let changed = if name == "a hash cut short" {
                // No challenge hashes a short hash, so the assertion is over the whole one.
                let mut whole = with_batch(
                    &authenticator,
                    inputs[0],
                    vec![own.clone(), others[0].clone()],
                );
                let (input, segment) = whole.rsplit_once('.').unwrap();
                let mut assertion: Assertion =
                    serde_json::from_slice(&jws::decode(segment).unwrap()).unwrap();
                assertion.b = Some(list);
                whole = format!(
                    "{input}.{}",
                    jws::encode(&serde_json::to_vec(&assertion).unwrap())
                );
                whole
            } else {
                with_batch(&authenticator, inputs[0], list)
            };
            assert_eq!(binding_is(&changed), Some(refused), "{name}");
        }

        // The list the touch signed, in another order.
        let (input, segment) = signed[0].rsplit_once('.').unwrap();
        let mut assertion: Assertion =
            serde_json::from_slice(&jws::decode(segment).unwrap()).unwrap();
        assertion.b.as_mut().unwrap().reverse();
        let reordered = format!(
            "{input}.{}",
            jws::encode(&serde_json::to_vec(&assertion).unwrap())
        );
        assert_eq!(binding_is(&reordered), Some(Error::BadSignature));
    }

    #[test]
    fn an_rp_id_is_a_hostname_in_its_one_spelling() {
        for good in ["host.example", "1-2-3-4.sslip.io", "localhost.example"] {
            assert!(RpId::new(good).is_ok(), "{good}");
        }
        for bad in [
            "Host.example",
            "host.example.",
            "host.example:443",
            "127.0.0.1",
            "[::1]",
            "",
            "host example",
            "https://host.example",
            // Bug caught: a passkey any program on the owner's machine can serve a page for.
            "localhost",
            "owner.localhost",
        ] {
            assert_eq!(RpId::new(bad).err(), Some(Error::Malformed), "{bad}");
        }
    }
}

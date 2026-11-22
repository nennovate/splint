//! Pairing an agent with its owner's page by a code the owner pastes to it. See "Pairing by code" in
//! `docs/protocol.md`.
//!
//! The owner's page makes a secret and opens a mailbox at its host with its owner's session, and shows
//! the person a code holding both.
//! The person pastes the code to their agent, which answers at the mailbox with its ID, address and
//! delegate key, under a MAC only the code's secret can make. The page takes only an answer that MAC
//! checks, and refuses if two came. The secret never reaches the host, so a host can't answer in an
//! agent's place. The code also names the owner who made it, by the first half of their ID's hash, so
//! whoever opens its mailbox, a host or anyone else who has the code, can't name another owner to the
//! agent, even once the owner's own mailbox has closed.
//!
//! What the code can't do: an agent that's been fooled into passing the code on lets whoever it gave it
//! to answer first, and the page then shows that agent's address, which the person has to read. If
//! both answer, the page refuses.

use std::fmt;

use aws_lc_rs::digest;
use aws_lc_rs::hmac;
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::owner_session::VerifiedOwnerSession;
use crate::{
    CLOCK_TOLERANCE_SECS, Error, Identity, PublicKey, SplintId, canonical_address,
    canonical_domain, jws,
};

/// What a code starts with, so an agent can tell one from anything else a person pastes.
pub const CODE_PREFIX: &str = "splint-pair:";
/// The longest a pairing lasts, from the page making it to the owner signing.
pub const MAX_PAIRING_SECS: u64 = 15 * 60;
const PAIRING_TYPE: &str = "splint-pairing";
const VERSION: u8 = 1;
const SECRET_LEN: usize = 16;
const ID_BYTES: usize = 16;
/// How much of the owner's ID hash a code carries: enough that nobody can make another ID with the same.
const OWNER_BYTES: usize = 16;
const CLOSE_LEN: usize = 32;
const ID_TAG: &[u8] = b"splint pairing id v1";
const ANSWER_TAG: &[u8] = b"splint pairing v1";
const OWNER_TAG: &[u8] = b"splint pairing owner v1";
/// RFC 4648's base32 alphabet in lower case. 16 bytes are 26 characters, the last carrying 3 bits.
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const SECRET_CHARS: usize = 26;
/// Past these an answer is refused unread. An identity with every recovery it may carry is well under.
const MAX_IDENTITY_CHARS: usize = 16 * 1024;
const MAX_ADDRESS_CHARS: usize = 320;

/// The secret in a code: 128 random bits, which only the owner's page and the agent the person pastes
/// it to hold. It can't be printed or serialized, and leaves only inside a code.
pub struct PairingSecret([u8; SECRET_LEN]);

impl fmt::Debug for PairingSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingSecret(..)")
    }
}

impl PairingSecret {
    /// The mailbox's name: the first 16 bytes of SHA-256 of a tag and the secret, in hex. Anyone with
    /// the code can work it out, and nobody can work the secret out from it.
    pub fn id(&self) -> PairingId {
        let mut hashed = digest::Context::new(&digest::SHA256);
        hashed.update(ID_TAG);
        hashed.update(&self.0);
        let hash = hashed.finish();
        PairingId(hex(hash.as_ref().get(..ID_BYTES).unwrap_or_default()))
    }

    fn key(&self) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, &self.0)
    }

    /// That this owner opened the mailbox this secret names, which only someone holding the secret can
    /// say, so a host that doesn't can't name another owner to the agent.
    fn check_owner_proof(&self, owner: &SplintId, proof: &str) -> Result<(), Error> {
        let mut signed = OWNER_TAG.to_vec();
        signed.extend_from_slice(self.id().0.as_bytes());
        signed.extend_from_slice(owner.as_str().as_bytes());
        hmac::verify(&self.key(), &signed, &hash_bytes(proof)?).map_err(|_| Error::BadSignature)
    }

    fn answer_input(&self, answer: &AnswerFields<'_>) -> Vec<u8> {
        let mut signed = ANSWER_TAG.to_vec();
        signed.extend_from_slice(self.id().0.as_bytes());
        for field in [answer.agent_identity, answer.address, answer.delegate] {
            let length = u32::try_from(field.len()).unwrap_or(u32::MAX);
            signed.extend_from_slice(&length.to_be_bytes());
            signed.extend_from_slice(field.as_bytes());
        }
        signed
    }
}

/// A hex HMAC or hash in its one spelling: 64 lowercase hex digits.
fn hash_bytes(text: &str) -> Result<Vec<u8>, Error> {
    let lower_hex = |byte: &u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    if text.len() != 64 || !text.as_bytes().iter().all(lower_hex) {
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

/// A mailbox's name, 32 lowercase hex digits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingId(String);

impl PairingId {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let lower_hex = |byte: &u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
        if text.len() != ID_BYTES * 2 || !text.as_bytes().iter().all(lower_hex) {
            return Err(Error::Malformed);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PairingId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(|_| serde::de::Error::custom("not a pairing id"))
    }
}

/// What a person pastes to their agent: `splint-pair:<host>/<secret>/<owner>`, each part after the host
/// 16 bytes in base32. The host is where the mailbox is, the owner page's own, and may not be the
/// agent's. The owner part is the first 16 bytes of the hash the code's maker's ID names, so the agent
/// takes only that owner, whoever opens the mailbox.
#[derive(Debug)]
pub struct PairingCode {
    host: String,
    secret: PairingSecret,
    owner: [u8; OWNER_BYTES],
}

impl PairingCode {
    /// In its one spelling, with only the whitespace a chat window may add around it ignored.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let rest = text
            .trim()
            .strip_prefix(CODE_PREFIX)
            .ok_or(Error::Malformed)?;
        let (host, rest) = rest.split_once('/').ok_or(Error::Malformed)?;
        let (secret, owner) = rest.split_once('/').ok_or(Error::Malformed)?;
        if canonical_domain(host)? != host {
            return Err(Error::Malformed);
        }
        Ok(Self {
            host: host.to_owned(),
            secret: PairingSecret(from_base32(secret)?),
            owner: from_base32(owner)?,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn secret(&self) -> &PairingSecret {
        &self.secret
    }

    pub fn id(&self) -> PairingId {
        self.secret.id()
    }

    /// The owner part, in hex, as the first 32 hex digits of the ID it names.
    pub fn owner(&self) -> String {
        hex(&self.owner)
    }

    /// Whether this is the owner whose ID the code names.
    fn names(&self, owner: &SplintId) -> bool {
        owner
            .as_str()
            .strip_prefix(crate::identity::ID_PREFIX)
            .and_then(|hash| hash.get(..OWNER_BYTES * 2))
            .is_some_and(|start| start == self.owner())
    }
}

pub(crate) fn to_base32(bytes: &[u8; SECRET_LEN]) -> String {
    let mut out = String::with_capacity(SECRET_CHARS);
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(base32_char(buffer >> bits));
        }
    }
    if bits > 0 {
        out.push(base32_char(buffer << (5 - bits)));
    }
    out
}

fn base32_char(value: u32) -> char {
    let index = usize::try_from(value & 0x1f).unwrap_or_default();
    BASE32.get(index).map_or('a', |byte| char::from(*byte))
}

/// Lower case, no padding, and the 2 bits left over in the last character zero, so a secret has one
/// spelling.
pub(crate) fn from_base32(text: &str) -> Result<[u8; SECRET_LEN], Error> {
    if text.len() != SECRET_CHARS {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(SECRET_LEN);
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for character in text.bytes() {
        let value = BASE32
            .iter()
            .position(|known| *known == character)
            .ok_or(Error::Malformed)?;
        buffer = (buffer << 5) | u32::try_from(value).map_err(|_| Error::Malformed)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).map_err(|_| Error::Malformed)?);
        }
    }
    if buffer & ((1 << bits) - 1) != 0 {
        return Err(Error::Malformed);
    }
    out.try_into().map_err(|_| Error::Malformed)
}

/// Whether a token sent to close a mailbox is the one its pairing named.
pub fn closes(token: &str, pairing: &VerifiedPairing) -> bool {
    jws::decode(token)
        .ok()
        .filter(|raw| raw.len() == CLOSE_LEN)
        .is_some_and(|raw| {
            let hash = hex(digest::digest(&digest::SHA256, &raw).as_ref());
            crate::secrets_match(hash.as_bytes(), pairing.payload.close.as_bytes())
        })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingPayload {
    v: u8,
    id: PairingId,
    owner: SplintId,
    host: String,
    proof: String,
    close: String,
    issued_at: u64,
    expires_at: u64,
}

/// A pairing whose session has been checked, for one host, in date. A session, not the owner's own key,
/// opens a mailbox, as opening one gives nobody anything: the agent takes only the owner its code names,
/// and then only what that owner signs.
#[derive(Debug)]
pub struct VerifiedPairing {
    compact: String,
    session: String,
    payload: PairingPayload,
}

impl VerifiedPairing {
    /// A host's check of a mailbox being opened: under a session this owner signed for this host, as
    /// they are now, by that session's key, naming them and this host, lasting at most 15 minutes and
    /// no longer than the session, and not over.
    pub fn verify(
        compact: &str,
        session: &str,
        owner: &Identity,
        host: &str,
        now: u64,
    ) -> Result<Self, Error> {
        let verified = VerifiedOwnerSession::verify(session, owner, host, now)?;
        let bytes = jws::verify(compact, verified.key(), PAIRING_TYPE)?;
        let payload: PairingPayload =
            serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        let lasts = payload.expires_at.checked_sub(payload.issued_at);
        let encoded = serde_json::to_vec(&payload).map_err(|_| Error::Malformed)?;
        if payload.v != VERSION
            || !lasts.is_some_and(|lasts| lasts > 0 && lasts <= MAX_PAIRING_SECS)
            || hash_bytes(&payload.proof).is_err()
            || hash_bytes(&payload.close).is_err()
            || encoded != bytes
        {
            return Err(Error::Malformed);
        }
        // A session that ends first can't keep a mailbox open in its owner's name past its end.
        if payload.expires_at > verified.expires_at() {
            return Err(Error::Malformed);
        }
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
            compact: compact.to_owned(),
            session: session.to_owned(),
            payload,
        })
    }

    /// An agent's check of who made the code it was given: the host's check, for the code's host, the
    /// owner the code names, and the proof only the code's secret makes, for the mailbox the code names.
    pub fn verify_for_agent(
        compact: &str,
        session: &str,
        owner: &Identity,
        code: &PairingCode,
        now: u64,
    ) -> Result<Self, Error> {
        let pairing = Self::verify(compact, session, owner, code.host(), now)?;
        if pairing.payload.id != code.id() {
            return Err(Error::ProofMismatch);
        }
        // Anyone with the code can make the proof for an owner of their own, once the mailbox the
        // code's maker opened has closed and its name is free.
        if !code.names(owner.id()) {
            return Err(Error::WrongSigner);
        }
        code.secret()
            .check_owner_proof(owner.id(), &pairing.payload.proof)?;
        Ok(pairing)
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn id(&self) -> &PairingId {
        &self.payload.id
    }

    pub fn owner(&self) -> &SplintId {
        &self.payload.owner
    }

    pub fn expires_at(&self) -> u64 {
        self.payload.expires_at
    }
}

/// `PUT /v0/pairings/{id}`: the owner's identity, their session at this host, and the pairing its key
/// signed.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenPairing {
    pub owner_identity: String,
    pub session: String,
    pub pairing: String,
}

/// `DELETE /v0/pairings/{id}`: the token whose hash the pairing named.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosePairing {
    pub close: String,
}

/// What an agent's answer covers, before its MAC.
struct AnswerFields<'a> {
    agent_identity: &'a str,
    address: &'a str,
    delegate: &'a str,
}

/// `POST /v0/pairings/{id}/answer`: the agent's ID as it is now, its address, its Signet's delegate key,
/// and a MAC over them under the code's secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingAnswer {
    pub agent_identity: String,
    pub address: String,
    pub delegate: String,
    pub mac: String,
}

impl PairingAnswer {
    /// An agent answering the code it was given.
    pub fn new(
        code: &PairingCode,
        agent: &Identity,
        address: &str,
        delegate: &PublicKey,
    ) -> Result<Self, Error> {
        let address = canonical_address(address)?;
        let agent_identity = agent.encoded();
        let delegate = delegate.encoded();
        let fields = AnswerFields {
            agent_identity: &agent_identity,
            address: &address,
            delegate: &delegate,
        };
        let mac =
            hex(hmac::sign(&code.secret().key(), &code.secret().answer_input(&fields)).as_ref());
        Ok(Self {
            agent_identity,
            address,
            delegate,
            mac,
        })
    }

    /// What a host checks before keeping an answer it can't check the MAC of: that each part could be
    /// what it says, so what it keeps is bounded and readable.
    pub fn check_shape(&self) -> Result<(), Error> {
        if self.agent_identity.len() > MAX_IDENTITY_CHARS || self.address.len() > MAX_ADDRESS_CHARS
        {
            return Err(Error::Malformed);
        }
        Identity::from_encoded(&self.agent_identity)?;
        if canonical_address(&self.address)? != self.address {
            return Err(Error::Malformed);
        }
        PublicKey::from_encoded(&self.delegate)?;
        hash_bytes(&self.mac).map(|_| ())
    }
}

/// `GET /v0/pairings/{id}`: the first answer, if one came, and whether another came after it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingState {
    pub answer: Option<PairingAnswer>,
    pub second_answer: bool,
    pub expires_at: u64,
}

/// What the host gives an agent that answered: who opened the mailbox, for its own check.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingOpener {
    pub owner_identity: String,
    pub session: String,
    pub pairing: String,
}

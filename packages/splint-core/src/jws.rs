//! A deliberately small JWS profile: compact form, ES256, or WA256 for an owner's passkey, and an
//! exact `typ`.
//!
//! The header can't choose the algorithm: each is spelled one way, and the signer's identity says which
//! it has to be (see `Identity::verify`). `typ` stops one kind of signed object being replayed as
//! another.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use crate::passkey::MAX_SEGMENT_CHARS;
use crate::{Error, PublicKey, SigningKey};

const ES256: &str = "ES256";
const WA256: &str = "WA256";
const P256_SIGNATURE_LEN: usize = 64;
pub(crate) const MAX_COMPACT_LEN: usize = 256 * 1024;

/// What an owner key signs, and nothing else may be signed by a passkey. Each is verified only through
/// the owner's identity, never under a bare key, so nothing can check one the wrong way.
const OWNER_TYPES: [&str; 17] = [
    "splint-binding",
    "splint-release",
    "splint-change-statement",
    "splint-change-accept",
    "splint-retirement",
    "splint-rules",
    "splint-approval",
    "splint-person-text",
    "splint-grant",
    "splint-grant-revocation",
    "splint-delegation",
    "splint-owner-session",
    "splint-owner-agents",
    "splint-where-paid",
    "splint-key-add",
    "splint-key-remove",
    "splint-recovery-rule",
];

/// Whether only an owner's key signs this, so an ID that isn't an agent's may sign it.
pub(crate) fn is_owner_type(typ: &str) -> bool {
    OWNER_TYPES.contains(&typ)
}

/// The owner type this object's header names, either way an owner signs, if it names one.
pub(crate) fn owner_type_of(compact: &str) -> Option<&'static str> {
    let header = decode(compact.split_once('.')?.0).ok()?;
    OWNER_TYPES.into_iter().find(|typ| {
        [ES256, WA256]
            .iter()
            .any(|alg| header_bytes(alg, typ).is_ok_and(|bytes| bytes == header))
    })
}

#[derive(Serialize)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
}

/// The one header a signed object can have for each algorithm. It's compared as bytes, so its
/// spacing and field order can't vary, which would otherwise leave a free channel outside the
/// signed payload.
fn header_bytes(alg: &str, typ: &str) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&Header { alg, typ }).map_err(|_| Error::Malformed)
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn decode(text: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| Error::Malformed)
}

/// The other spelling of an ES256 signature, `s` as `n - s`, which verifies too and which anyone
/// can work out from the first.
#[cfg(test)]
pub(crate) fn respelled(compact: &str) -> String {
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let (signed, signature) = compact.rsplit_once('.').unwrap();
    let mut raw = decode(signature).unwrap();
    let mut borrow = 0;
    for index in (0..32).rev() {
        let digit = i16::from(ORDER[index]) - i16::from(raw[32 + index]) - borrow;
        borrow = i16::from(digit < 0);
        raw[32 + index] = u8::try_from(digit.rem_euclid(256)).unwrap();
    }
    format!("{signed}.{}", encode(&raw))
}

/// An agent's key, as Signet holds it, signs no owner type, so nothing that asks Signet to sign can
/// have the agent's key say anything as its owner, or prove it holds a key an owner's ID adds.
pub(crate) fn sign(key: &SigningKey, typ: &str, payload: &[u8]) -> Result<String, Error> {
    if key.is_agents() && is_owner_type(typ) {
        return Err(Error::WrongSigner);
    }
    let input = signing_input(Alg::Es256, typ, payload)?;
    Ok(format!("{input}.{}", signature(key, &input)?))
}

/// How a key signs: ES256 for every key but an owner's passkey, which signs WA256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alg {
    Es256,
    Wa256,
}

/// The header and payload segments, joined by `.`, which is what a key signs.
pub(crate) fn signing_input(alg: Alg, typ: &str, payload: &[u8]) -> Result<String, Error> {
    let alg = match alg {
        Alg::Es256 => ES256,
        Alg::Wa256 => WA256,
    };
    Ok(format!(
        "{}.{}",
        encode(&header_bytes(alg, typ)?),
        encode(payload)
    ))
}

/// An ES256 signature over a signing input already made, for one prepared ahead.
pub(crate) fn sign_input(key: &SigningKey, signing_input: &str) -> Result<String, Error> {
    Ok(format!(
        "{signing_input}.{}",
        signature_over(key, signing_input)?
    ))
}

/// The ES256 signature segment alone, over a signing input made elsewhere, such as the one an
/// addition's added key signs beside the key that counts. An agent's key signs only through [`sign`],
/// by type, so it signs no input made elsewhere.
pub(crate) fn signature_over(key: &SigningKey, signing_input: &str) -> Result<String, Error> {
    if key.is_agents() {
        return Err(Error::WrongSigner);
    }
    signature(key, signing_input)
}

fn signature(key: &SigningKey, signing_input: &str) -> Result<String, Error> {
    Ok(encode(&key.sign(signing_input.as_bytes())?))
}

/// A signature, as its header says it was made. Which one counts is the signer's identity's to say.
pub(crate) enum Signature<'a> {
    /// `r` then `s`, 64 bytes.
    Es256(Vec<u8>),
    /// A passkey's assertion, still encoded, as `passkey::verify` reads it.
    Passkey(&'a str),
}

pub(crate) struct Parts<'a> {
    pub(crate) signing_input: &'a str,
    pub(crate) payload: Vec<u8>,
    pub(crate) signature: Signature<'a>,
}

pub(crate) fn parse<'a>(compact: &'a str, typ: &str) -> Result<Parts<'a>, Error> {
    if compact.len() > MAX_COMPACT_LEN {
        return Err(Error::Malformed);
    }
    let (signing_input, signature) = compact.rsplit_once('.').ok_or(Error::Malformed)?;
    let (header, payload) = signing_input.split_once('.').ok_or(Error::Malformed)?;
    if payload.contains('.') {
        return Err(Error::Malformed);
    }
    let header = decode(header)?;
    let signature = if header == header_bytes(ES256, typ)? {
        signature_segment(signature, Alg::Es256)?
    } else if OWNER_TYPES.contains(&typ) && header == header_bytes(WA256, typ)? {
        signature_segment(signature, Alg::Wa256)?
    } else {
        return Err(Error::Malformed);
    };
    Ok(Parts {
        signing_input,
        payload: decode(payload)?,
        signature,
    })
}

/// Reads a payload without checking its signature. Only use this to find out which key to
/// verify with, and never act on the result.
/// A signature segment read the way `alg` signs, whatever a header says: 64 bytes for ES256, a
/// passkey's assertion no longer than a segment may be for WA256. Otherwise it's malformed.
pub(crate) fn signature_segment(segment: &str, alg: Alg) -> Result<Signature<'_>, Error> {
    match alg {
        Alg::Es256 => {
            let raw = decode(segment)?;
            if raw.len() != P256_SIGNATURE_LEN {
                return Err(Error::Malformed);
            }
            Ok(Signature::Es256(raw))
        }
        Alg::Wa256 if segment.len() <= MAX_SEGMENT_CHARS => Ok(Signature::Passkey(segment)),
        Alg::Wa256 => Err(Error::Malformed),
    }
}

pub(crate) fn unverified_payload(compact: &str, typ: &str) -> Result<Vec<u8>, Error> {
    Ok(parse(compact, typ)?.payload)
}

/// Checks what a delegate key signed on its owner's behalf, which is always ES256, as the key is
/// Signet's. Only a [`crate::delegation::VerifiedDelegation`] calls this, under the key its owner named,
/// and checks what was signed against the limits they set.
pub(crate) fn verify_delegated(
    compact: &str,
    key: &PublicKey,
    typ: &str,
) -> Result<Vec<u8>, Error> {
    let parts = parse(compact, typ)?;
    match &parts.signature {
        Signature::Es256(raw) => key.verify(parts.signing_input.as_bytes(), raw)?,
        Signature::Passkey(_) => return Err(Error::BadSignature),
    }
    Ok(parts.payload)
}

/// Checks an ES256 signature by a key that isn't an ID's: a backup, a host's or an invitation's. What
/// an ID signs is checked by [`crate::Identity`], which knows how its key signs, and what an owner
/// signs is refused here, so it can't be checked as though a file key made it.
pub(crate) fn verify(compact: &str, key: &PublicKey, typ: &str) -> Result<Vec<u8>, Error> {
    if OWNER_TYPES.contains(&typ) {
        return Err(Error::Malformed);
    }
    let parts = parse(compact, typ)?;
    match &parts.signature {
        Signature::Es256(raw) => key.verify(parts.signing_input.as_bytes(), raw)?,
        Signature::Passkey(_) => return Err(Error::BadSignature),
    }
    Ok(parts.payload)
}

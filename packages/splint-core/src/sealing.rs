//! Sealed bodies: a message or a step only its two agents can read. See "Sealed and unsealed" in
//! `docs/protocol.md`.
//!
//! The sender's Signet encrypts the body with HPKE (RFC 9180: DHKEM P-256 with HKDF-SHA256, HKDF-SHA256
//! and AES-128-GCM, in base mode) once to the recipient's sealing key and once to its own, then signs the
//! envelope as it does any other. A host sees only what delivery and limits need, which is what
//! [`Outside`] holds, and every reader checks that it says the same as what's inside.
//!
//! The body is also committed to with a hash and a secret salt inside it, which the signature covers.
//! AES-GCM doesn't commit to its key, so without this a sender could make the two copies open to
//! different things. With it, both copies open to one body, and whoever holds a body and its salt can
//! show it to anyone, with the signature to prove it's real, while a host can't test guesses at it.

use std::path::Path;

use aws_lc_rs::digest;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use crate::delegation::is_a_name;
use crate::identity::hex;
use crate::keys::{create_new, derived_scalar, read_secret, write_new};
use crate::requests::{InteractionType, StepKind, outside_of};
use crate::{Error, MessageId, SigningKey, SplintId, jws};

type Kem = DhP256HkdfSha256;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;
type PublicPoint = <Kem as hpke::Kem>::PublicKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

const SEALED_VERSION: u8 = 1;
const PRIVATE_KEY_LEN: usize = 32;
const POINT_LEN: usize = 65;
const SALT_LEN: usize = 32;
const TAG_LEN: usize = 16;
const INFO_TO: &[u8] = b"splint sealed body v1: to the recipient";
const INFO_OWN: &[u8] = b"splint sealed body v1: the sender's own copy";
const COMMITMENT_CONTEXT: &[u8] = b"splint sealed body v1: commitment\0";
/// Between an envelope's compact form and its opening, in what a Signet keeps. It isn't in base64url
/// or a JWS, so a kept form splits one way, and a host can't take one for a compact form.
pub(crate) const OPENING_SEPARATOR: char = '~';

/// Whether what an owner's agent says can be read by the hosts it passes through. Sealed is the
/// default: only the two agents can read it. Unsealed leaves it readable by both hosts, so a host can
/// look at it live, as a third party. Between two agents, the stricter of their owners' choices
/// counts, both ways.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sealing {
    #[default]
    Sealed,
    Unsealed,
}

impl Sealing {
    /// What goes between two agents: sealed unless both owners chose unsealed. `theirs` is `None`
    /// until the other side has said, which counts as sealed.
    pub fn between(mine: Self, theirs: Option<Self>) -> Self {
        match (mine, theirs) {
            (Self::Unsealed, Some(Self::Unsealed)) => Self::Unsealed,
            _ => Self::Sealed,
        }
    }
}

/// The private half of an agent's or an owner's sealing key. Like [`crate::SigningKey`], it has no
/// `Debug`, `Display` or `Serialize`, so it can't end up in a log, an error or a response by accident:
///
/// ```compile_fail
/// # fn wrong(key: splint_core::SealingKey) -> String {
/// format!("{key:?}")
/// # }
/// ```
pub struct SealingKey {
    private: PrivateKey,
    public: SealPublicKey,
}

impl SealingKey {
    /// From 32 random bytes, by RFC 9180's DeriveKeyPair.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0_u8; PRIVATE_KEY_LEN];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| Error::Crypto)?;
        let (private, _) = Kem::derive_keypair(&seed);
        Self::from_private(private)
    }

    fn from_private(private: PrivateKey) -> Result<Self, Error> {
        let public = SealPublicKey::from_bytes(&Kem::sk_to_pk(&private).to_bytes())?;
        Ok(Self { private, public })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_private(PrivateKey::from_bytes(bytes).map_err(|_| Error::Malformed)?)
    }

    /// The key whose private scalar is these 32 bytes, as a reading key's copy holds it.
    pub(crate) fn from_scalar_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }

    /// The sealing key on a signing key's own scalar, so what's sealed to an owner's backup point opens
    /// with the backup their recovery code derives.
    pub(crate) fn from_scalar_of(key: &SigningKey) -> Result<Self, Error> {
        Self::from_bytes(&key.scalar()?)
    }

    /// An owner's sealing key from what their passkey's PRF gave for the salt `splint owner sealing
    /// v1`, as "Keys an owner's page derives" in `docs/protocol.md` has it. So any device the passkey
    /// signs on opens what's sealed to its owner, and the key is never stored.
    pub fn from_prf(output: &[u8]) -> Result<Self, Error> {
        if output.len() != PRF_OUTPUT_LEN {
            return Err(Error::Malformed);
        }
        Self::from_bytes(&derived_scalar(output, PRF_SEALING_SALT)?)
    }

    /// Loads the key at `path`, or makes one readable only by this user.
    pub fn load_or_create(path: &Path) -> Result<Self, Error> {
        match read_secret(path)? {
            Some(bytes) => Self::from_bytes(&bytes),
            None => {
                let key = Self::generate()?;
                write_new(path, &key.private.to_bytes()).map_err(|_| Error::KeyStorage)?;
                Ok(key)
            }
        }
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::from_bytes(&read_secret(path)?.ok_or(Error::KeyStorage)?)
    }

    /// Makes a key at `path`, and refuses if there's one there already.
    pub fn create_new(path: &Path) -> Result<Self, Error> {
        let key = Self::generate()?;
        create_new(path, &key.private.to_bytes())?;
        Ok(key)
    }

    /// Keeps this key at `path`, readable only by this user, refusing a file already there. For a
    /// reading key a new sign-in opened from its copy, which then lives beside that sign-in.
    pub fn keep_new(&self, path: &Path) -> Result<(), Error> {
        create_new(path, &self.private.to_bytes())
    }

    pub fn public_key(&self) -> SealPublicKey {
        self.public.clone()
    }

    /// The private scalar, for looking for this key in what an agent writes, which never prints it.
    pub(crate) fn private_bytes(&self) -> Vec<u8> {
        self.private.to_bytes().to_vec()
    }

    /// Opens something sealed to this key on its own, outside an envelope, such as the view a Signet
    /// leaves at its host for its owner.
    pub fn open_note(&self, sealed: &str, about: &[u8]) -> Result<Vec<u8>, Error> {
        open_one(&self.private, sealed, INFO_NOTE, about)
    }
}

const INFO_NOTE: &[u8] = b"splint sealed note v1";
/// What a page asks a passkey's PRF for, and the salt that turns its answer into a sealing key.
const PRF_SEALING_SALT: &[u8] = b"splint owner sealing v1";
const PRF_OUTPUT_LEN: usize = 32;

/// Seals something on its own, outside an envelope, to one key. `about` is bound to it, so it opens
/// only for the same purpose.
pub fn seal_note(to: &SealPublicKey, plaintext: &[u8], about: &[u8]) -> Result<String, Error> {
    seal_one(to, INFO_NOTE, plaintext, about)
}

/// A sealing key's public half: a P-256 point, uncompressed. It's apart from the signing key, and the
/// ID commits to it, so a host can't swap in another one without the ID changing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealPublicKey(Vec<u8>);

impl SealPublicKey {
    /// Refuses anything that isn't a point on the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != POINT_LEN {
            return Err(Error::Malformed);
        }
        PublicPoint::from_bytes(bytes).map_err(|_| Error::Malformed)?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn encoded(&self) -> String {
        jws::encode(&self.0)
    }

    pub fn from_encoded(text: &str) -> Result<Self, Error> {
        Self::from_bytes(&jws::decode(text)?)
    }

    fn point(&self) -> Result<PublicPoint, Error> {
        PublicPoint::from_bytes(&self.0).map_err(|_| Error::Malformed)
    }
}

/// Who a body is sealed to, and what the sender's owner chose, which the other side goes by.
pub struct SealFor<'a> {
    pub recipient: &'a SealPublicKey,
    pub own: &'a SealPublicKey,
    pub sender_chose: Sealing,
}

/// What a host can see of a sealed body, and all it can go by: whether it's a step, and of what kind,
/// which interaction, the type an `open` starts, whether it claims an owner's yes or a person's words,
/// and for a yes their delegate said, the delegation's name. A reader holds every one of these to
/// what's inside.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outside {
    /// `None` for an agent's own words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<StepKind>,
    /// For every step but an `open`, whose envelope's ID is the interaction's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<MessageId>,
    /// The type an `open` starts, absent for core's plain conversation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opens: Option<InteractionType>,
    /// On a `type/1`'s `open` only, the ID of the type it proposes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposes: Option<InteractionType>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub approval: bool,
    /// So a sending host can refuse a delegate's yes at `ask_me`, or under a delegation the owner's
    /// rules don't name, without reading what's sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub person_text: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// The field order here is the wire order, because the only valid encoding is this one.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    v: u8,
    outside: Outside,
    sender_chose: Sealing,
    /// Hex SHA-256 of a context, the salt and the body.
    commitment: String,
    /// The encapsulated key and the ciphertext, for the recipient's key, in base64url.
    to: String,
    /// The same for the sender's own key, so it can read back what it sent.
    own: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedBody {
    sealed: Sealed,
}

#[derive(Deserialize)]
struct Probe {
    sealed: Option<IgnoredAny>,
}

/// Whether a body presents itself as sealed, whatever is wrong with it. Anything that does has to
/// parse as one, so words can't pose as a sealed step to get past a check, or the reverse.
pub fn is_sealed_body(body: &str) -> bool {
    body.trim_start().starts_with('{')
        && serde_json::from_str::<Probe>(body).is_ok_and(|probe| probe.sealed.is_some())
}

fn parse(body: &str) -> Result<Sealed, Error> {
    let parsed: SealedBody = serde_json::from_str(body).map_err(|_| Error::Malformed)?;
    let sealed = parsed.sealed;
    let one_encoding = serde_json::to_string(&SealedBody {
        sealed: copy(&sealed),
    })
    .is_ok_and(|encoded| encoded == body);
    let fits = sealed.v == SEALED_VERSION
        && is_sha256_hex(&sealed.commitment)
        && sealed.outside.fits()
        && sealed_part_fits(&sealed.to)
        && sealed_part_fits(&sealed.own);
    if one_encoding && fits {
        Ok(sealed)
    } else {
        Err(Error::Malformed)
    }
}

fn copy(sealed: &Sealed) -> Sealed {
    Sealed {
        v: sealed.v,
        outside: sealed.outside.clone(),
        sender_chose: sealed.sender_chose,
        commitment: sealed.commitment.clone(),
        to: sealed.to.clone(),
        own: sealed.own.clone(),
    }
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// An encapsulated key and at least a tag and a salt after it.
fn sealed_part_fits(text: &str) -> bool {
    jws::decode(text).is_ok_and(|bytes| bytes.len() >= POINT_LEN + TAG_LEN + SALT_LEN)
}

impl Outside {
    fn fits(&self) -> bool {
        let request_fits = self.request.as_ref().is_none_or(MessageId::is_well_formed);
        let shape_fits = match self.step {
            None => {
                self.request.is_none()
                    && self.opens.is_none()
                    && self.proposes.is_none()
                    && !self.approval
                    && !self.person_text
            }
            // A `type/1` says what it proposes, and only it does.
            Some(StepKind::Open) => {
                self.request.is_none()
                    && self
                        .opens
                        .as_ref()
                        .is_some_and(InteractionType::is_proposal)
                        == self.proposes.is_some()
                    && self
                        .proposes
                        .as_ref()
                        .is_none_or(InteractionType::is_agreed)
            }
            Some(_) => self.request.is_some() && self.opens.is_none() && self.proposes.is_none(),
        };
        // Only a delegate's yes carries a delegation, and only to a `confirm`, named one way.
        let delegation_fits = self.delegation.as_deref().is_none_or(|name| {
            is_a_name(name) && self.approval && self.step == Some(StepKind::Confirm)
        });
        request_fits && shape_fits && delegation_fits
    }
}

/// What a sealed body is bound to besides itself, so a sealed body can't be moved to another envelope.
#[derive(Serialize)]
pub(crate) struct Bound<'a> {
    pub sender: &'a SplintId,
    pub recipient: &'a SplintId,
    pub created_at: u64,
    pub expires_at: u64,
    pub nonce: &'a str,
}

#[derive(Serialize)]
struct AssociatedData<'a> {
    bound: &'a Bound<'a>,
    outside: &'a Outside,
    sender_chose: Sealing,
    commitment: &'a str,
}

fn associated_data(
    bound: &Bound,
    outside: &Outside,
    sender_chose: Sealing,
    commitment: &str,
) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&AssociatedData {
        bound,
        outside,
        sender_chose,
        commitment,
    })
    .map_err(|_| Error::Malformed)
}

fn commitment_to(salt: &[u8], body: &[u8]) -> String {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(COMMITMENT_CONTEXT);
    context.update(salt);
    context.update(body);
    hex(context.finish().as_ref())
}

fn seal_one(
    to: &SealPublicKey,
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<String, Error> {
    let (encapped, ciphertext) = hpke::single_shot_seal::<AesGcm128, HkdfSha256, Kem>(
        &OpModeS::Base,
        &to.point()?,
        info,
        plaintext,
        aad,
    )
    .map_err(|_| Error::Crypto)?;
    let mut sealed = encapped.to_bytes().to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(jws::encode(&sealed))
}

fn open_one(private: &PrivateKey, sealed: &str, info: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes = jws::decode(sealed)?;
    let (encapped, ciphertext) = bytes.split_at_checked(POINT_LEN).ok_or(Error::Malformed)?;
    let encapped = EncappedKey::from_bytes(encapped).map_err(|_| Error::Malformed)?;
    hpke::single_shot_open::<AesGcm128, HkdfSha256, Kem>(
        &OpModeR::Base,
        private,
        &encapped,
        info,
        ciphertext,
        aad,
    )
    .map_err(|_| Error::CantOpen)
}

/// Seals `body` to both keys. What the outside says is worked out from the body itself, so it can't
/// say anything else.
pub(crate) fn seal_body(body: &str, bound: &Bound, seal_for: &SealFor) -> Result<Opened, Error> {
    let outside = outside_of(body).map_err(|_| Error::Malformed)?;
    let mut salt = [0_u8; SALT_LEN];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| Error::Crypto)?;
    let commitment = commitment_to(&salt, body.as_bytes());
    let aad = associated_data(bound, &outside, seal_for.sender_chose, &commitment)?;
    let mut plaintext = salt.to_vec();
    plaintext.extend_from_slice(body.as_bytes());
    let sealed = Sealed {
        v: SEALED_VERSION,
        outside,
        sender_chose: seal_for.sender_chose,
        to: seal_one(seal_for.recipient, INFO_TO, &plaintext, &aad)?,
        own: seal_one(seal_for.own, INFO_OWN, &plaintext, &aad)?,
        commitment,
    };
    Ok(Opened {
        body: serde_json::to_string(&SealedBody { sealed }).map_err(|_| Error::Malformed)?,
        opening: jws::encode(&plaintext),
    })
}

/// A sealed body's outside, checked as a host checks it, or `None` for a body that isn't sealed.
pub(crate) fn outside(raw: &str) -> Result<Option<(Outside, Sealing)>, Error> {
    if !is_sealed_body(raw) {
        return Ok(None);
    }
    let sealed = parse(raw)?;
    Ok(Some((sealed.outside, sealed.sender_chose)))
}

/// Which copy to open: the recipient's, or the sender's own.
#[derive(Clone, Copy)]
pub(crate) enum Slot {
    To,
    Own,
}

/// A body opened, and what proves it to someone without the key: the salt and the body. From
/// [`seal_body`], `body` is the sealed body instead.
pub(crate) struct Opened {
    pub body: String,
    pub opening: String,
}

pub(crate) fn open_body(
    raw: &str,
    bound: &Bound,
    slot: Slot,
    key: &SealingKey,
) -> Result<Opened, Error> {
    let sealed = parse(raw)?;
    let aad = associated_data(
        bound,
        &sealed.outside,
        sealed.sender_chose,
        &sealed.commitment,
    )?;
    let (part, info) = match slot {
        Slot::To => (&sealed.to, INFO_TO),
        Slot::Own => (&sealed.own, INFO_OWN),
    };
    let plaintext = open_one(&key.private, part, info, &aad)?;
    let body = held_to(&sealed, &plaintext)?;
    Ok(Opened {
        body,
        opening: jws::encode(&plaintext),
    })
}

/// Checks an opening a Signet kept against the sealed body it came from, for anyone without the key,
/// such as an owner's page or whoever a party shows it to.
pub(crate) fn check_opening(raw: &str, opening: &str) -> Result<String, Error> {
    held_to(&parse(raw)?, &jws::decode(opening)?)
}

/// The body inside, once it's shown to be the one the sender committed to and to say what its outside
/// says. A sender lying on the outside to get past a host's check gets nothing past a reader.
fn held_to(sealed: &Sealed, plaintext: &[u8]) -> Result<String, Error> {
    let (salt, body) = plaintext
        .split_at_checked(SALT_LEN)
        .ok_or(Error::Malformed)?;
    if commitment_to(salt, body) != sealed.commitment {
        return Err(Error::ProofMismatch);
    }
    let body = String::from_utf8(body.to_vec()).map_err(|_| Error::Malformed)?;
    if outside_of(&body).ok().as_ref() != Some(&sealed.outside) {
        return Err(Error::ProofMismatch);
    }
    Ok(body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Seals as a lying sender's Signet could: `inside` sealed, `committed` committed to, and `outside`
    /// on the outside, each bound in as an honest Signet binds it, so both copies open. All that stands
    /// between this and a reader is what the reader checks once it's open.
    pub(crate) fn seal_lying(
        inside: &str,
        committed: &str,
        outside: Outside,
        bound: &Bound,
        seal_for: &SealFor,
    ) -> String {
        let salt = [7_u8; SALT_LEN];
        let commitment = commitment_to(&salt, committed.as_bytes());
        let aad = associated_data(bound, &outside, seal_for.sender_chose, &commitment).unwrap();
        let mut plaintext = salt.to_vec();
        plaintext.extend_from_slice(inside.as_bytes());
        let sealed = Sealed {
            v: SEALED_VERSION,
            outside,
            sender_chose: seal_for.sender_chose,
            to: seal_one(seal_for.recipient, INFO_TO, &plaintext, &aad).unwrap(),
            own: seal_one(seal_for.own, INFO_OWN, &plaintext, &aad).unwrap(),
            commitment,
        };
        serde_json::to_string(&SealedBody { sealed }).unwrap()
    }

    fn bound<'a>(sender: &'a SplintId, recipient: &'a SplintId) -> Bound<'a> {
        Bound {
            sender,
            recipient,
            created_at: 10,
            expires_at: 20,
            nonce: "",
        }
    }

    fn id(byte: char) -> SplintId {
        serde_json::from_value::<SplintId>(serde_json::json!(format!(
            "splint1{}",
            byte.to_string().repeat(64)
        )))
        .unwrap()
    }

    fn ids() -> (SplintId, SplintId) {
        (id('a'), id('b'))
    }

    fn to_both(key: &SealingKey, sender_chose: Sealing) -> (SealPublicKey, SealPublicKey, Sealing) {
        (key.public_key(), key.public_key(), sender_chose)
    }

    fn seal_for(keys: &(SealPublicKey, SealPublicKey, Sealing)) -> SealFor<'_> {
        SealFor {
            recipient: &keys.0,
            own: &keys.1,
            sender_chose: keys.2,
        }
    }

    fn reencoded(raw: &str, change: impl FnOnce(&mut Sealed)) -> String {
        let mut sealed = parse(raw).unwrap();
        change(&mut sealed);
        serde_json::to_string(&SealedBody { sealed }).unwrap()
    }

    fn confirm_step() -> String {
        let request = MessageId::of(b"request");
        format!(
            r#"{{"step":"confirm","request":"{request}","prev":"{request}","approval":"x"}}"#,
            request = request.as_str()
        )
    }

    #[test]
    fn only_the_two_keys_open_it_and_both_open_the_same_body() {
        let (ana, ben) = ids();
        let (to, own, stranger) = (
            SealingKey::generate().unwrap(),
            SealingKey::generate().unwrap(),
            SealingKey::generate().unwrap(),
        );
        let seal_for = SealFor {
            recipient: &to.public_key(),
            own: &own.public_key(),
            sender_chose: Sealing::Sealed,
        };
        let raw = seal_body("are you free", &bound(&ana, &ben), &seal_for)
            .unwrap()
            .body;
        assert!(!raw.contains("free"));
        let opened = open_body(&raw, &bound(&ana, &ben), Slot::To, &to).unwrap();
        assert_eq!(opened.body, "are you free");
        let mine = open_body(&raw, &bound(&ana, &ben), Slot::Own, &own).unwrap();
        assert_eq!(mine.body, "are you free");
        assert_eq!(
            check_opening(&raw, &opened.opening).unwrap(),
            "are you free"
        );
        for (slot, key) in [(Slot::To, &stranger), (Slot::Own, &to), (Slot::To, &own)] {
            assert_eq!(
                open_body(&raw, &bound(&ana, &ben), slot, key).err(),
                Some(Error::CantOpen)
            );
        }
        // Moved to another envelope, it doesn't open.
        assert_eq!(
            open_body(&raw, &bound(&ben, &ana), Slot::To, &to).err(),
            Some(Error::CantOpen)
        );
    }

    #[test]
    fn a_sealed_body_has_one_encoding() {
        let (ana, ben) = ids();
        let key = SealingKey::generate().unwrap();
        let seal_for = SealFor {
            recipient: &key.public_key(),
            own: &key.public_key(),
            sender_chose: Sealing::Unsealed,
        };
        let raw = seal_body("hi", &bound(&ana, &ben), &seal_for).unwrap().body;
        assert!(outside(&raw).unwrap().is_some());
        for other in [
            format!("{raw} "),
            raw.replacen(':', ": ", 1),
            raw.replacen(r#""v":1"#, r#""v":2"#, 1),
            raw.replacen(r#""unsealed""#, r#""open""#, 1),
            r#"{"sealed":{}}"#.to_owned(),
        ] {
            assert_eq!(outside(&other).err(), Some(Error::Malformed), "{other}");
        }
        assert_eq!(outside("just words").unwrap(), None);
    }

    /// A sending host goes by an outside's delegation to refuse a delegate's yes the owner's rules don't
    /// allow, so an outside naming one anywhere but on a `confirm` that claims a yes, or naming it any
    /// other way, isn't a sealed body at all.
    #[test]
    fn an_outside_names_a_delegation_only_on_a_confirm_claiming_a_yes() {
        const NAME: &str = "abababababababababababababababababababababababababababababababab";
        let (ana, ben) = ids();
        let key = SealingKey::generate().unwrap();
        let seal_for = SealFor {
            recipient: &key.public_key(),
            own: &key.public_key(),
            sender_chose: Sealing::Sealed,
        };
        let raw = seal_body(&confirm_step(), &bound(&ana, &ben), &seal_for)
            .unwrap()
            .body;
        let named = |sealed: &mut Sealed| sealed.outside.delegation = Some(NAME.to_owned());
        assert!(outside(&reencoded(&raw, named)).is_ok(), "control");
        for lie in [
            (|sealed: &mut Sealed| {
                sealed.outside.delegation = Some(NAME.to_owned());
                sealed.outside.approval = false;
            }) as fn(&mut Sealed),
            |sealed| {
                sealed.outside.delegation = Some(NAME.to_owned());
                sealed.outside.step = Some(StepKind::Accept);
            },
            |sealed| sealed.outside.delegation = Some(NAME.to_uppercase()),
            |sealed| sealed.outside.delegation = Some("ab".repeat(31)),
            |sealed| sealed.outside.delegation = Some("ab".repeat(33)),
        ] {
            assert_eq!(outside(&reencoded(&raw, lie)).err(), Some(Error::Malformed));
        }
    }

    #[test]
    fn the_stricter_choice_counts_both_ways() {
        use Sealing::{Sealed, Unsealed};
        assert_eq!(Sealing::between(Unsealed, Some(Unsealed)), Unsealed);
        assert_eq!(Sealing::between(Unsealed, Some(Sealed)), Sealed);
        assert_eq!(Sealing::between(Sealed, Some(Unsealed)), Sealed);
        assert_eq!(Sealing::between(Unsealed, None), Sealed);
    }

    /// Sealed once, by this code, to two fixed keys. Sealing and opening change together, so without a
    /// body from before, a changed `info`, commitment context or associated data would pass every test
    /// here and fail only against another implementation, or against what Signets already hold.
    const KNOWN_BODY: &str = r#"{"sealed":{"v":1,"outside":{},"sender_chose":"sealed","commitment":"541c1c67aa1b28f1e3ea859fe83328bf7c2cf6bf948cc7264f840295bc0f2925","to":"BJUGiVi5QJw8AsPAhIBeajNa1LySbrsxzFJs0ac_Qy1TuboLkuJa4vhDoKA0usTsbtrSQqB5wRvf0GJOFjLuCNCDNY49YavrgJGtD4CD7r-N4nQAR7K1TYlB1WHaXZiwXAktAubeNJsBQ9Mxl0V5mwBgFhBkBbnZSfaCttw","own":"BLKwyjRAem2T19EqP8U1h4tJ1frmS4IQJlHsQLrtaOfVsLPEDWgrk_vwoqhD4Hj_LIJ_G2Us2mUv2ewU72OrI45s5oZepOqVTvmiOP3q71Ysau9TyEyzp6xzHc5Vls7z18gyggEY6BwE4W5V78IiJcL5UR9NG58GvRCsQBI"}}"#;
    const KNOWN_NOTE: &str = "BBJckyTXeNk48n95h9IMWcyidmQoPaNcz-Nu3KltPKDxR-YlXihT1FvSOfMDr9FNNV671v7cmO9OEn0sCZ1xpLuOM4teH_Vj4-YhV8a1IkxrZh4tTWtN";

    #[test]
    fn what_was_sealed_before_still_opens_to_the_same_body() {
        let (ana, ben) = ids();
        let to = SealingKey::from_bytes(&[1; 32]).unwrap();
        let own = SealingKey::from_bytes(&[2; 32]).unwrap();
        let theirs = open_body(KNOWN_BODY, &bound(&ana, &ben), Slot::To, &to).unwrap();
        assert_eq!(theirs.body, "are you free");
        let mine = open_body(KNOWN_BODY, &bound(&ana, &ben), Slot::Own, &own).unwrap();
        assert_eq!(mine.body, "are you free");
        assert_eq!(
            check_opening(KNOWN_BODY, &theirs.opening).unwrap(),
            "are you free"
        );
        // Each copy has its own purpose, so one can't be opened as the other.
        assert_eq!(
            open_body(KNOWN_BODY, &bound(&ana, &ben), Slot::Own, &to).err(),
            Some(Error::CantOpen)
        );
        assert_eq!(to.open_note(KNOWN_NOTE, b"about").unwrap(), b"a note");
        assert_eq!(
            to.open_note(KNOWN_NOTE, b"other").err(),
            Some(Error::CantOpen)
        );
        // A note isn't a body's copy, nor the reverse.
        let part = parse(KNOWN_BODY).unwrap().to;
        assert_eq!(to.open_note(&part, b"").err(), Some(Error::CantOpen));
    }

    /// The dates and the nonce are bound in as much as who it's between, or a stolen key could put
    /// a body sealed for one envelope into another.
    #[test]
    fn a_body_opens_only_in_the_envelope_it_was_sealed_for() {
        let (ana, ben) = ids();
        let key = SealingKey::generate().unwrap();
        let seal_for = SealFor {
            recipient: &key.public_key(),
            own: &key.public_key(),
            sender_chose: Sealing::Sealed,
        };
        let sealed_for = Bound {
            nonce: "first",
            ..bound(&ana, &ben)
        };
        let raw = seal_body("yes", &sealed_for, &seal_for).unwrap().body;
        assert!(open_body(&raw, &sealed_for, Slot::To, &key).is_ok());
        for other in [
            Bound {
                nonce: "second",
                ..bound(&ana, &ben)
            },
            Bound {
                created_at: 11,
                nonce: "first",
                ..bound(&ana, &ben)
            },
            Bound {
                expires_at: 21,
                nonce: "first",
                ..bound(&ana, &ben)
            },
        ] {
            assert_eq!(
                open_body(&raw, &other, Slot::To, &key).err(),
                Some(Error::CantOpen)
            );
        }
    }

    /// Every part of the outside is something a host goes by, so a reader holds each one to what's
    /// inside, not only the step's kind.
    #[test]
    fn every_part_of_a_lying_outside_is_refused_by_a_reader() {
        use crate::requests::InteractionType;
        let (ana, ben) = ids();
        let key = SealingKey::generate().unwrap();
        let seal_for = SealFor {
            recipient: &key.public_key(),
            own: &key.public_key(),
            sender_chose: Sealing::Sealed,
        };
        let request = MessageId::of(b"request");
        let confirm = format!(
            r#"{{"step":"confirm","request":"{request}","prev":"{request}","approval":"x"}}"#,
            request = request.as_str()
        );
        let any = format!("any/1@{}", "a".repeat(52));
        let open = format!(r#"{{"step":"open","type":"{any}","terms":{{"a":1}},"deadline":7200}}"#);
        let open = open.as_str();
        let proposal = r#"{"step":"open","type":"type/1","schema":{"kind":"request","sign":"both","type":"x/1"},"deadline":7200}"#;
        for (body, lie) in [
            (
                confirm.as_str(),
                (|outside: &mut Outside| outside.approval = false) as fn(&mut Outside),
            ),
            (confirm.as_str(), |outside| outside.person_text = true),
            (confirm.as_str(), |outside| {
                outside.request = Some(MessageId::of(b"another"));
            }),
            (confirm.as_str(), |outside| {
                outside.step = Some(StepKind::Progress)
            }),
            (open, |outside| {
                outside.opens =
                    Some(InteractionType::try_from(format!("other/1@{}", "a".repeat(52))).unwrap());
            }),
            (open, |outside| outside.approval = true),
            // A plain conversation's `open` names no type outside, which a host goes by for `text`.
            (open, |outside| outside.opens = None),
            // What a host may see opened between the two next is the type a `type/1` proposes.
            (proposal, |outside| {
                outside.proposes =
                    Some(InteractionType::try_from(format!("x/1@{}", "a".repeat(52))).unwrap());
            }),
        ] {
            let raw = seal_body(body, &bound(&ana, &ben), &seal_for).unwrap().body;
            let opened = open_body(&raw, &bound(&ana, &ben), Slot::To, &key).unwrap();
            let mut sealed = parse(&raw).unwrap();
            lie(&mut sealed.outside);
            assert!(sealed.outside.fits(), "{:?}", sealed.outside);
            // Sealed by a lying sender, bound in as an honest one binds it, it reaches the reader.
            let sealed_lying = seal_lying(
                body,
                body,
                sealed.outside.clone(),
                &bound(&ana, &ben),
                &seal_for,
            );
            for (slot, opener) in [(Slot::To, &key), (Slot::Own, &key)] {
                assert_eq!(
                    open_body(&sealed_lying, &bound(&ana, &ben), slot, opener).err(),
                    Some(Error::ProofMismatch),
                    "{body}"
                );
            }
            let lying = serde_json::to_string(&SealedBody { sealed }).unwrap();
            assert_eq!(
                check_opening(&lying, &opened.opening).err(),
                Some(Error::ProofMismatch),
                "{body}"
            );
        }
    }

    #[test]
    fn a_point_off_the_curve_isnt_a_sealing_key() {
        let mut bytes = SealingKey::generate()
            .unwrap()
            .public_key()
            .as_bytes()
            .to_vec();
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
        assert_eq!(SealPublicKey::from_bytes(&bytes), Err(Error::Malformed));
        assert_eq!(SealPublicKey::from_bytes(&[4; 64]), Err(Error::Malformed));
    }

    #[test]
    fn a_key_file_reads_back_as_the_same_key() {
        let directory = std::env::temp_dir().join(format!("splint-seal-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.seal");
        let made = SealingKey::load_or_create(&path).unwrap();
        let read = SealingKey::load(&path).unwrap();
        assert_eq!(made.public_key(), read.public_key());
        assert_eq!(SealingKey::create_new(&path).err(), Some(Error::KeyStorage));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A fixed salt would let a host test guesses at a short body against its commitment, and a fixed
    /// ephemeral key would make two sealings to one key look alike. So nothing in two sealings of one
    /// body between the same two agents, in the same envelope, is the same.
    #[test]
    fn two_sealings_of_one_body_share_no_salt_key_or_commitment() {
        let (ana, ben) = ids();
        let (to, own) = (
            SealingKey::generate().unwrap(),
            SealingKey::generate().unwrap(),
        );
        let seal_for = SealFor {
            recipient: &to.public_key(),
            own: &own.public_key(),
            sender_chose: Sealing::Sealed,
        };
        let seal = || seal_body("yes", &bound(&ana, &ben), &seal_for).unwrap();
        let (first, second) = (seal(), seal());
        let (one, two) = (parse(&first.body).unwrap(), parse(&second.body).unwrap());
        assert_ne!(one.commitment, two.commitment);
        let salt = |opened: &Opened| {
            let plaintext = jws::decode(&opened.opening).unwrap();
            plaintext.split_at(SALT_LEN).0.to_vec()
        };
        assert_ne!(salt(&first), salt(&second));
        let encapped = |part: &str| jws::decode(part).unwrap().split_at(POINT_LEN).0.to_vec();
        assert_ne!(encapped(&one.to), encapped(&two.to));
        assert_ne!(encapped(&one.own), encapped(&two.own));
        assert_ne!(encapped(&one.to), encapped(&one.own));
    }

    /// Each thing a sealed body is bound to, changed alone, keeps it from opening, so none of them can
    /// be moved or altered by a host. The outside, what the sender chose and the commitment are what
    /// a host goes by, and the copies' labels keep one copy from being read as the other.
    #[test]
    fn each_thing_a_sealed_body_is_bound_to_has_to_match_for_it_to_open() {
        let (ana, ben) = ids();
        let key = SealingKey::generate().unwrap();
        let keys = to_both(&key, Sealing::Sealed);
        let confirm = confirm_step();
        let raw = seal_body(&confirm, &bound(&ana, &ben), &seal_for(&keys))
            .unwrap()
            .body;
        for slot in [Slot::To, Slot::Own] {
            assert!(open_body(&raw, &bound(&ana, &ben), slot, &key).is_ok());
        }
        let another_commitment = commitment_to(&[0; SALT_LEN], b"another body");
        let changed: [(&str, String); 5] = [
            (
                "outside",
                reencoded(&raw, |sealed| sealed.outside.approval = false),
            ),
            (
                "sender_chose",
                reencoded(&raw, |sealed| sealed.sender_chose = Sealing::Unsealed),
            ),
            (
                "commitment",
                reencoded(&raw, |sealed| sealed.commitment = another_commitment),
            ),
            (
                "labels",
                reencoded(&raw, |sealed| {
                    std::mem::swap(&mut sealed.to, &mut sealed.own)
                }),
            ),
            ("nothing", raw.clone()),
        ];
        let cara = id('c');
        for (what, other) in changed {
            let opens = |bound: &Bound, slot| open_body(&other, bound, slot, &key).err();
            for slot in [Slot::To, Slot::Own] {
                if what == "nothing" {
                    // Only who it's between, each alone.
                    assert_eq!(opens(&bound(&cara, &ben), slot), Some(Error::CantOpen));
                    assert_eq!(opens(&bound(&ana, &cara), slot), Some(Error::CantOpen));
                } else {
                    assert!(outside(&other).unwrap().is_some(), "{what}");
                    assert_eq!(
                        opens(&bound(&ana, &ben), slot),
                        Some(Error::CantOpen),
                        "{what}"
                    );
                }
            }
        }
    }

    /// What a host checks of a sealed body before it goes by its outside: one that can't be true of
    /// any body, or parts too short to hold a key, a tag and a salt, never gets that far.
    #[test]
    fn a_host_refuses_a_sealed_body_whose_shape_cant_be_true() {
        let (ana, ben) = ids();
        let key = SealingKey::generate().unwrap();
        let keys = to_both(&key, Sealing::Sealed);
        let seal = |body: &str| {
            seal_body(body, &bound(&ana, &ben), &seal_for(&keys))
                .unwrap()
                .body
        };
        let words = seal("plain words");
        let confirm = seal(&confirm_step());
        let any = format!("any/1@{}", "a".repeat(52));
        let open = seal(&format!(
            r#"{{"step":"open","type":"{any}","terms":{{"a":1}},"deadline":7200}}"#
        ));
        for raw in [&words, &confirm, &open] {
            assert!(outside(raw).unwrap().is_some());
        }
        let request = || Some(MessageId::of(b"request"));
        let opens = || Some(crate::requests::InteractionType::try_from(any.clone()).unwrap());
        let ill_formed: MessageId = serde_json::from_value(serde_json::json!("ABC")).unwrap();
        let shortest = jws::encode(&[0; POINT_LEN + TAG_LEN + SALT_LEN]);
        let too_short = jws::encode(&[0; POINT_LEN + TAG_LEN + SALT_LEN - 1]);
        let fits = [
            reencoded(&words, |sealed| sealed.to.clone_from(&shortest)),
            reencoded(&words, |sealed| sealed.own.clone_from(&shortest)),
        ];
        for raw in &fits {
            assert!(outside(raw).unwrap().is_some());
        }
        let cant_be_true = [
            reencoded(&words, |sealed| sealed.outside.request = request()),
            reencoded(&words, |sealed| sealed.outside.opens = opens()),
            reencoded(&words, |sealed| sealed.outside.approval = true),
            reencoded(&words, |sealed| sealed.outside.person_text = true),
            reencoded(&open, |sealed| sealed.outside.request = request()),
            reencoded(&open, |sealed| sealed.outside.proposes = opens()),
            reencoded(&open, |sealed| {
                sealed.outside.opens = Some(crate::requests::InteractionType::proposal());
            }),
            reencoded(&words, |sealed| sealed.outside.proposes = opens()),
            reencoded(&confirm, |sealed| sealed.outside.request = None),
            reencoded(&confirm, |sealed| sealed.outside.opens = opens()),
            reencoded(&confirm, |sealed| sealed.outside.request = Some(ill_formed)),
            reencoded(&words, |sealed| sealed.to.clone_from(&too_short)),
            reencoded(&words, |sealed| sealed.own.clone_from(&too_short)),
            reencoded(&words, |sealed| sealed.to = "not*base64url".to_owned()),
            reencoded(&words, |sealed| {
                sealed.commitment = sealed.commitment.to_uppercase();
            }),
            reencoded(&words, |sealed| {
                sealed.commitment.pop();
            }),
        ];
        for raw in &cant_be_true {
            assert_eq!(outside(raw).err(), Some(Error::Malformed), "{raw}");
        }
    }
}

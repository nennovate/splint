use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use std::num::NonZeroU32;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::constant_time;
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::hkdf;
use aws_lc_rs::pbkdf2;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::{Error, jws, private_files};

/// Compares two secrets, such as API tokens, without leaking where they differ.
pub fn secrets_match(left: &[u8], right: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(left, right).is_ok()
}

/// A P-256 private key. It deliberately has no `Debug`, `Display` or `Serialize`,
/// so it can't end up in a log, an error or a response by accident. None of these compile:
///
/// ```compile_fail
/// # fn wrong(key: splint_core::SigningKey) -> String {
/// format!("{key:?}")
/// # }
/// ```
///
/// ```compile_fail
/// # fn wrong(key: splint_core::SigningKey) -> String {
/// format!("{key}")
/// # }
/// ```
///
/// ```compile_fail
/// # fn wrong(key: splint_core::SigningKey) -> Vec<u8> {
/// serde_json::to_vec(&key).unwrap()
/// # }
/// ```
pub struct SigningKey {
    held: Held,
    /// An agent's key as Signet holds it, which signs nothing an owner signs. See
    /// [`Self::load_or_create_for_agent`].
    agents: bool,
}

enum Held {
    /// In this process, read from a file only this user can read.
    Here { pair: EcdsaKeyPair, pkcs8: Vec<u8> },
    /// By the device, such as a computer's security chip, which signs and never hands the key out.
    Device {
        key: Box<dyn HeldKey>,
        public: PublicKey,
    },
}

/// A P-256 key a device holds outside this process, such as a computer's security chip, which signs
/// only what it's handed and never gives out its private half. A chip may ask the person first, and
/// the person may say no, which is [`Error::NotApproved`].
pub trait HeldKey: Send + Sync {
    /// The 65-byte uncompressed point.
    fn public_point(&self) -> Vec<u8>;
    /// ECDSA P-256 with SHA-256 over `message`, in ASN.1 DER, as chips give it.
    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

impl SigningKey {
    pub fn generate() -> Result<Self, Error> {
        let document = EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &SystemRandom::new(),
        )
        .map_err(|_| Error::Crypto)?;
        Self::from_pkcs8(document.as_ref())
    }

    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, Error> {
        let pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, bytes)
            .map_err(|_| Error::Malformed)?;
        Ok(Self {
            held: Held::Here {
                pair,
                pkcs8: bytes.to_vec(),
            },
            agents: false,
        })
    }

    /// A key a device holds, which signs here as any owner key does. Only an owner's sign-in is held
    /// this way, never an agent's.
    pub fn held(key: Box<dyn HeldKey>) -> Result<Self, Error> {
        let public = PublicKey::from_bytes(&key.public_point())?;
        Ok(Self {
            held: Held::Device { key, public },
            agents: false,
        })
    }

    /// The key's PKCS#8 bytes, which only a key held in this process has.
    fn pkcs8(&self) -> Result<&[u8], Error> {
        match &self.held {
            Held::Here { pkcs8, .. } => Ok(pkcs8),
            Held::Device { .. } => Err(Error::Crypto),
        }
    }

    /// The key whose private scalar is `scalar`, which [`derived_scalar`] makes.
    pub(crate) fn from_scalar(scalar: &[u8; SCALAR_LEN]) -> Result<Self, Error> {
        // RFC 5915's ECPrivateKey with no public key, which aws-lc works out from the scalar.
        let mut sec1 = SEC1_BEFORE_SCALAR.to_vec();
        sec1.extend_from_slice(scalar);
        sec1.extend_from_slice(&SEC1_AFTER_SCALAR);
        let pair =
            EcdsaKeyPair::from_private_key_der(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &sec1)
                .map_err(|_| Error::Malformed)?;
        let pkcs8 = pair.to_pkcs8v1().map_err(|_| Error::Crypto)?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// The private scalar, for a sealing key on the same scalar: an owner's backup opens what was
    /// sealed to its point, as a recovery code is all that's left of it.
    pub(crate) fn scalar(&self) -> Result<[u8; SCALAR_LEN], Error> {
        let Held::Here { pair, .. } = &self.held else {
            return Err(Error::Crypto);
        };
        let bytes = pair
            .private_key()
            .as_be_bytes()
            .map_err(|_| Error::Crypto)?;
        bytes.as_ref().try_into().map_err(|_| Error::Crypto)
    }

    /// This key as text, for an invitation link, which is the one place a private key is meant to
    /// travel. Only `invites` may call this, and that key signs nothing but one redeem.
    pub(crate) fn invitation_text(&self) -> Result<String, Error> {
        Ok(jws::encode(self.pkcs8()?))
    }

    pub(crate) fn from_invitation_text(text: &str) -> Result<Self, Error> {
        Self::from_pkcs8(&jws::decode(text)?)
    }

    /// Loads the key at `path`, or creates it readable only by this user. This is the software
    /// storage level: the file can be copied if the machine is breached.
    pub fn load_or_create(path: &Path) -> Result<Self, Error> {
        match read_secret(path)? {
            Some(bytes) => Self::from_pkcs8(&bytes),
            None => {
                let key = Self::generate()?;
                write_new(path, key.pkcs8()?).map_err(|_| Error::KeyStorage)?;
                Ok(key)
            }
        }
    }

    /// The same, for an agent's own key, as Signet holds it. It signs only what an agent signs, by
    /// type: no owner type, and no signing input made elsewhere. So nothing that asks Signet to sign
    /// gets the agent's key to say yes or set rules as its owner, or to sign an addition of the
    /// agent's own key to an owner's ID, which needs the added key's signature.
    pub fn load_or_create_for_agent(path: &Path) -> Result<Self, Error> {
        let mut key = Self::load_or_create(path)?;
        key.agents = true;
        Ok(key)
    }

    pub(crate) fn is_agents(&self) -> bool {
        self.agents
    }

    /// The agent's own key at `path`, which must be there already, held as
    /// [`Self::load_or_create_for_agent`] holds it. For a Signet whose agent has an ID, as a new key
    /// in place of a lost file would leave it unable to speak for that ID.
    pub fn load_for_agent(path: &Path) -> Result<Self, Error> {
        let mut key = Self::load(path)?;
        key.agents = true;
        Ok(key)
    }

    /// A new key in place of the one at `path`, written whole before it replaces it, so a crash leaves
    /// one or the other. Only a delegate key is ever replaced: an agent's or an owner's is their ID's.
    pub(crate) fn replace(path: &Path) -> Result<Self, Error> {
        let key = Self::generate()?;
        write_new(path, key.pkcs8()?).map_err(|_| Error::KeyStorage)?;
        Ok(key)
    }

    /// Loads the key at `path`, which must exist and be readable only by this user.
    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::from_pkcs8(&read_secret(path)?.ok_or(Error::KeyStorage)?)
    }

    /// Makes a key at `path`, and refuses if there's one there already: replacing an owner's key
    /// would lose their identity, and everything that pinned it.
    pub fn create_new(path: &Path) -> Result<Self, Error> {
        let key = Self::generate()?;
        create_new(path, key.pkcs8()?)?;
        Ok(key)
    }

    /// Keeps this key at `path`, which mustn't hold one already, readable only by this user, as an
    /// agent's backup taken from its owner's list is kept on their new computer.
    pub fn save_new(&self, path: &Path) -> Result<(), Error> {
        create_new(path, self.pkcs8()?)
    }

    /// Makes a key at `path` as [`Self::create_new`] does, locked with a passphrase the person
    /// chose, so a copy of the file alone signs nothing. See [`Locked`].
    pub fn create_locked(path: &Path, passphrase: &[u8]) -> Result<Self, Error> {
        let key = Self::generate()?;
        let locked = Locked::lock(key.pkcs8()?, passphrase)?;
        let text = serde_json::to_vec(&locked).map_err(|_| Error::Crypto)?;
        create_new(path, &text)?;
        Ok(key)
    }

    /// Locks the plain key file at `path` with a passphrase the person chose, keeping the key, so the
    /// ID it signs for stays theirs. The locked file is written whole before it takes the plain
    /// one's place, so a crash leaves one or the other. A file that's locked already isn't a plain
    /// key, which is [`Error::Malformed`]. A copy of the plain file made before this stays usable.
    pub fn lock_file(path: &Path, passphrase: &[u8]) -> Result<Self, Error> {
        let key = Self::load(path)?;
        let locked = Locked::lock(key.pkcs8()?, passphrase)?;
        let text = serde_json::to_vec(&locked).map_err(|_| Error::Crypto)?;
        write_new(path, &text).map_err(|_| Error::KeyStorage)?;
        Self::load_locked(path, passphrase)
    }

    /// Loads a key [`Self::create_locked`] made. A wrong passphrase is [`Error::CantOpen`].
    pub fn load_locked(path: &Path, passphrase: &[u8]) -> Result<Self, Error> {
        let text = read_secret(path)?.ok_or(Error::KeyStorage)?;
        let locked: Locked = serde_json::from_slice(&text).map_err(|_| Error::Malformed)?;
        Self::from_pkcs8(&locked.open(passphrase)?)
    }

    pub fn public_key(&self) -> PublicKey {
        match &self.held {
            Held::Here { pair, .. } => PublicKey(pair.public_key().as_ref().to_vec()),
            Held::Device { public, .. } => public.clone(),
        }
    }

    /// `r` then `s`, 64 bytes. A device's signature is checked under its own point before it's used,
    /// so a chip that signed with some other key fails here, not at every reader.
    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.held {
            Held::Here { pair, .. } => {
                let signature = pair
                    .sign(&SystemRandom::new(), message)
                    .map_err(|_| Error::Crypto)?;
                Ok(signature.as_ref().to_vec())
            }
            Held::Device { key, public } => {
                let raw = es256_from_der(&key.sign_der(message)?)?.to_vec();
                public.verify(message, &raw).map_err(|_| Error::Crypto)?;
                Ok(raw)
            }
        }
    }

    /// A signature in DER, as an authenticator returns one, for tests that stand in for a passkey.
    #[cfg(test)]
    pub(crate) fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let pair =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, self.pkcs8()?)
                .map_err(|_| Error::Malformed)?;
        let signature = pair
            .sign(&SystemRandom::new(), message)
            .map_err(|_| Error::Crypto)?;
        Ok(signature.as_ref().to_vec())
    }
}

pub(crate) const SCALAR_LEN: usize = 32;
/// `SEQUENCE { INTEGER 1, OCTET STRING (32 bytes) ...`
const SEC1_BEFORE_SCALAR: [u8; 7] = [0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20];
/// `... [0] OID prime256v1 }`
const SEC1_AFTER_SCALAR: [u8; 12] = [
    0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];
const DERIVED_INFO: &[u8] = b"p256 scalar";
const DERIVED_LEN: usize = 48;
/// The order of P-256, less one, as four 64-bit words, least significant first.
const ORDER_LESS_ONE: [u64; 4] = [
    0xF3B9_CAC2_FC63_2550,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

struct DerivedLen;

impl hkdf::KeyType for DerivedLen {
    fn len(&self) -> usize {
        DERIVED_LEN
    }
}

/// A P-256 private scalar from a secret, as "Keys an owner's page derives" in `docs/protocol.md` has
/// it: 48 bytes of HKDF-SHA256 under `salt` with the info `p256 scalar`, read as a big-endian number,
/// then that modulo the curve's order less one, plus one. So it's never zero or past the order, and
/// the 128 extra bits leave no bias anyone could see.
pub(crate) fn derived_scalar(secret: &[u8], salt: &[u8]) -> Result<[u8; SCALAR_LEN], Error> {
    let mut okm = [0_u8; DERIVED_LEN];
    hkdf::Salt::new(hkdf::HKDF_SHA256, salt)
        .extract(secret)
        .expand(&[DERIVED_INFO], DerivedLen)
        .and_then(|expanded| expanded.fill(&mut okm))
        .map_err(|_| Error::Crypto)?;
    let mut remainder = [0_u64; 5];
    for byte in okm {
        for shift in (0..8).rev() {
            let bit = u64::from((byte >> shift) & 1);
            shift_in(&mut remainder, bit);
            take_order_if_over(&mut remainder);
        }
    }
    let mut plus_one = 1_u64;
    let mut scalar = [0_u8; SCALAR_LEN];
    for (index, word) in remainder.iter().take(4).enumerate() {
        let (sum, carry) = word.overflowing_add(plus_one);
        plus_one = u64::from(carry);
        let at = SCALAR_LEN - 8 * (index + 1);
        if let Some(place) = scalar.get_mut(at..at + 8) {
            place.copy_from_slice(&sum.to_be_bytes());
        }
    }
    Ok(scalar)
}

fn shift_in(words: &mut [u64; 5], bit: u64) {
    let mut carry = bit;
    for word in words.iter_mut() {
        let next = *word >> 63;
        *word = (*word << 1) | carry;
        carry = next;
    }
}

/// Subtracts the order less one when the number is at least that, choosing by a mask rather than a
/// branch, so how long this takes says nothing about the secret.
fn take_order_if_over(words: &mut [u64; 5]) {
    let mut less = [0_u64; 5];
    let mut borrow = 0_u64;
    for (index, word) in words.iter().enumerate() {
        let order = ORDER_LESS_ONE.get(index).copied().unwrap_or(0);
        let (step, under_one) = word.overflowing_sub(order);
        let (step, under_two) = step.overflowing_sub(borrow);
        if let Some(place) = less.get_mut(index) {
            *place = step;
        }
        borrow = u64::from(under_one | under_two);
    }
    // No borrow means it was at least the order less one, so the subtraction stands.
    let keep_less = borrow.wrapping_sub(1);
    for (word, smaller) in words.iter_mut().zip(less) {
        *word = (smaller & keep_less) | (*word & !keep_less);
    }
}

/// A secret file's bytes, or `None` if there's no file. One others can read is refused.
pub(crate) fn read_secret(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match private_files::others_can_open(path) {
        Ok(true) => Err(Error::KeyStorage),
        Ok(false) => fs::read(path).map(Some).map_err(|_| Error::KeyStorage),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::KeyStorage),
    }
}

pub(crate) fn write_new(path: &Path, secret: &[u8]) -> std::io::Result<()> {
    fs::rename(write_temporary(path, secret)?, path)
}

/// Refuses if there's a file there already.
pub(crate) fn create_new(path: &Path, secret: &[u8]) -> Result<(), Error> {
    let temporary = write_temporary(path, secret).map_err(|_| Error::KeyStorage)?;
    let placed = fs::hard_link(&temporary, path);
    let removed = fs::remove_file(&temporary);
    placed.and(removed).map_err(|_| Error::KeyStorage)
}

/// Writes to a temporary file first, so a crash can't leave an empty key behind.
fn write_temporary(path: &Path, secret: &[u8]) -> std::io::Result<PathBuf> {
    let temporary = path.with_extension("tmp");
    match fs::remove_file(&temporary) {
        Err(error) if error.kind() != ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = private_files::open(
        fs::OpenOptions::new().write(true).create_new(true),
        &temporary,
    )?;
    file.write_all(secret)?;
    file.sync_all()?;
    Ok(temporary)
}

/// The key in a one-use link. It's the other place a private key is meant to travel, as it signs nothing
/// but one guest's answer to one offer, and its owner's device makes a new one for each link.
pub struct GuestKey {
    public: PublicKey,
    pkcs8: Vec<u8>,
}

impl GuestKey {
    pub fn generate() -> Result<Self, Error> {
        let key = SigningKey::generate()?;
        Ok(Self {
            public: key.public_key(),
            pkcs8: key.pkcs8()?.to_vec(),
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    /// What goes after the `#` in a link, in a form a browser's own crypto takes.
    pub fn link_text(&self) -> String {
        jws::encode(&self.pkcs8)
    }
}

/// An ECDSA signature in strict ASN.1 DER, `SEQUENCE { INTEGER r, INTEGER s }` with short lengths and
/// minimal, positive, non-zero integers, as `r` then `s`, 32 bytes each. Anything looser is
/// [`Error::Malformed`], so a chip's signature has one reading.
pub fn es256_from_der(der: &[u8]) -> Result<[u8; 64], Error> {
    let body = match der {
        [0x30, length, body @ ..] if usize::from(*length) == body.len() && *length < 0x80 => body,
        _ => return Err(Error::Malformed),
    };
    let (r, rest) = der_integer(body)?;
    let (s, rest) = der_integer(rest)?;
    if !rest.is_empty() {
        return Err(Error::Malformed);
    }
    let mut raw = [0_u8; 64];
    raw.get_mut(32 - r.len()..32)
        .ok_or(Error::Malformed)?
        .copy_from_slice(r);
    raw.get_mut(64 - s.len()..)
        .ok_or(Error::Malformed)?
        .copy_from_slice(s);
    Ok(raw)
}

/// One DER INTEGER's value without its sign byte, at most 32 bytes, and what follows it.
fn der_integer(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let [0x02, length, rest @ ..] = bytes else {
        return Err(Error::Malformed);
    };
    let length = usize::from(*length);
    let value = rest.get(..length).ok_or(Error::Malformed)?;
    let after = rest.get(length..).ok_or(Error::Malformed)?;
    let digits = match value {
        // A leading zero only where the next byte's top bit would otherwise make it negative.
        [0, next, ..] if *next >= 0x80 => value.get(1..).ok_or(Error::Malformed)?,
        [first, ..] if *first != 0 && *first < 0x80 => value,
        _ => return Err(Error::Malformed),
    };
    if digits.len() > 32 {
        return Err(Error::Malformed);
    }
    Ok((digits, after))
}

/// A key file locked with a passphrase: AES-256-GCM under 32 bytes of PBKDF2-HMAC-SHA256 from the
/// passphrase, with a fresh salt and nonce each time it's written. It's a file on one device, read
/// only by the program that wrote it, never sent, so the format is this device's own.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Locked {
    v: u8,
    rounds: u32,
    salt: String,
    nonce: String,
    sealed: String,
}

const LOCKED_VERSION: u8 = 1;
/// OWASP's 2023 figure for PBKDF2-HMAC-SHA256.
const LOCK_ROUNDS: u32 = 600_000;
/// A file asking for more makes opening it take minutes, so it's refused.
const MOST_LOCK_ROUNDS: u32 = 10_000_000;
const LOCK_SALT_LEN: usize = 16;
const LOCK_AAD: &[u8] = b"splint locked key v1";

impl Locked {
    fn lock(pkcs8: &[u8], passphrase: &[u8]) -> Result<Self, Error> {
        if passphrase.is_empty() {
            return Err(Error::Malformed);
        }
        let random = SystemRandom::new();
        let mut salt = [0_u8; LOCK_SALT_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        random.fill(&mut salt).map_err(|_| Error::Crypto)?;
        random.fill(&mut nonce).map_err(|_| Error::Crypto)?;
        let key = Self::key(passphrase, &salt, LOCK_ROUNDS)?;
        let mut sealed = pkcs8.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(LOCK_AAD),
            &mut sealed,
        )
        .map_err(|_| Error::Crypto)?;
        Ok(Self {
            v: LOCKED_VERSION,
            rounds: LOCK_ROUNDS,
            salt: jws::encode(&salt),
            nonce: jws::encode(&nonce),
            sealed: jws::encode(&sealed),
        })
    }

    fn open(&self, passphrase: &[u8]) -> Result<Vec<u8>, Error> {
        if self.v != LOCKED_VERSION || !(LOCK_ROUNDS..=MOST_LOCK_ROUNDS).contains(&self.rounds) {
            return Err(Error::Malformed);
        }
        let nonce: [u8; NONCE_LEN] = jws::decode(&self.nonce)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let key = Self::key(passphrase, &jws::decode(&self.salt)?, self.rounds)?;
        let mut sealed = jws::decode(&self.sealed)?;
        let opened = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(LOCK_AAD),
                &mut sealed,
            )
            .map_err(|_| Error::CantOpen)?;
        Ok(opened.to_vec())
    }

    fn key(passphrase: &[u8], salt: &[u8], rounds: u32) -> Result<LessSafeKey, Error> {
        let rounds = NonZeroU32::new(rounds).ok_or(Error::Malformed)?;
        let mut secret = [0_u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            rounds,
            salt,
            passphrase,
            &mut secret,
        );
        let key = UnboundKey::new(&AES_256_GCM, &secret).map_err(|_| Error::Crypto)?;
        Ok(LessSafeKey::new(key))
    }
}

/// A P-256 public key, as an uncompressed point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(Vec<u8>);

const UNCOMPRESSED_POINT_LEN: usize = 65;
const UNCOMPRESSED_POINT_TAG: u8 = 4;

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let tag = bytes.first().copied();
        if bytes.len() != UNCOMPRESSED_POINT_LEN || tag != Some(UNCOMPRESSED_POINT_TAG) {
            return Err(Error::Malformed);
        }
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

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &self.0)
            .verify(message, signature)
            .map_err(|_| Error::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[cfg(unix)]
    #[test]
    fn a_key_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!("splint-key-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.key");
        let created = SigningKey::load_or_create(&path).unwrap();
        let loaded = SigningKey::load_or_create(&path).unwrap();
        assert_eq!(created.public_key(), loaded.public_key());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            SigningKey::load_or_create(&path).err(),
            Some(Error::KeyStorage)
        );
        assert_eq!(SigningKey::load(&path).err(), Some(Error::KeyStorage));
        fs::remove_dir_all(&directory).unwrap();
    }

    /// A device's key, played by a key in this process, which signs as a chip does: in DER.
    struct Chip {
        signs: SigningKey,
        point: PublicKey,
    }

    impl HeldKey for Chip {
        fn public_point(&self) -> Vec<u8> {
            self.point.as_bytes().to_vec()
        }
        fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            self.signs.sign_der(message)
        }
    }

    /// Bug caught: a chip's DER read wrongly, or a chip signing under a key other than the one its ID
    /// names, which every reader would refuse only later and far away.
    #[test]
    fn a_device_key_signs_what_readers_take_and_nothing_under_another_key() {
        let inner = SigningKey::generate().unwrap();
        let held = SigningKey::held(Box::new(Chip {
            point: inner.public_key(),
            signs: inner,
        }))
        .unwrap();
        let owner = crate::test_identity(&held);
        let phone = SigningKey::generate().unwrap();
        let added = owner.add_key(&held, &phone, 1_793_750_400).unwrap();
        assert_eq!(
            Identity::from_encoded(&added.encoded())
                .unwrap()
                .keys()
                .len(),
            2
        );

        let liar = SigningKey::held(Box::new(Chip {
            point: SigningKey::generate().unwrap().public_key(),
            signs: SigningKey::generate().unwrap(),
        }))
        .unwrap();
        assert_eq!(liar.sign(b"anything").err(), Some(Error::Crypto));
        assert_eq!(held.scalar().err(), Some(Error::Crypto));
    }

    /// Bug caught: a signature read two ways, as DER that's long-form, padded, negative, zero or
    /// trailed by more bytes taken as if it were strict.
    #[test]
    fn only_strict_der_becomes_a_signature() {
        let key = SigningKey::generate().unwrap();
        let der = key.sign_der(b"signed").unwrap();
        let raw = es256_from_der(&der).unwrap();
        key.public_key().verify(b"signed", &raw).unwrap();

        let integer = |value: &[u8]| [&[0x02, u8::try_from(value.len()).unwrap()], value].concat();
        let sequence =
            |body: Vec<u8>| [vec![0x30, u8::try_from(body.len()).unwrap()], body].concat();
        let one = integer(&[1]);
        assert_eq!(
            es256_from_der(&sequence([one.clone(), one.clone()].concat())).unwrap()[31],
            1
        );
        let refused = [
            [vec![0x30, 0x81, 6], one.clone(), one.clone()].concat(),
            [sequence([one.clone(), one.clone()].concat()), vec![0]].concat(),
            sequence([integer(&[0x80]), one.clone()].concat()),
            sequence([integer(&[0, 1]), one.clone()].concat()),
            sequence([integer(&[0]), one.clone()].concat()),
            sequence([integer(&[]), one.clone()].concat()),
            sequence([integer(&[1; 33]), one.clone()].concat()),
            sequence([one.clone(), one.clone(), one.clone()].concat()),
            sequence(one.clone()),
        ];
        for der in refused {
            assert_eq!(es256_from_der(&der), Err(Error::Malformed), "{der:02x?}");
        }
    }

    /// Bug caught: a locked key file opened with the wrong passphrase, or readable by others.
    #[test]
    fn a_locked_key_opens_only_with_its_passphrase() {
        let directory = std::env::temp_dir().join(format!("splint-locked-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("owner.key");
        let made = SigningKey::create_locked(&path, b"correct horse").unwrap();
        assert_eq!(
            SigningKey::load_locked(&path, b"correct horse")
                .unwrap()
                .public_key(),
            made.public_key()
        );
        assert_eq!(
            SigningKey::load_locked(&path, b"correct horsf").err(),
            Some(Error::CantOpen)
        );
        assert_eq!(
            SigningKey::create_locked(&path, b"again").err(),
            Some(Error::KeyStorage)
        );
        assert_eq!(
            SigningKey::create_locked(&directory.join("other.key"), b"").err(),
            Some(Error::Malformed)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                SigningKey::load_locked(&path, b"correct horse").err(),
                Some(Error::KeyStorage)
            );
        }
        fs::remove_dir_all(&directory).unwrap();
    }

    /// Bug caught: locking a plain key file making a new key, so the owner's ID is lost, or leaving it
    /// readable with no passphrase.
    #[test]
    fn locking_a_plain_key_file_keeps_the_key_and_ends_the_plain_one() {
        let directory = std::env::temp_dir().join(format!("splint-lock-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("owner.key");
        let plain = SigningKey::create_new(&path).unwrap();
        let locked = SigningKey::lock_file(&path, b"correct horse").unwrap();
        assert_eq!(locked.public_key(), plain.public_key());
        assert_eq!(SigningKey::load(&path).err(), Some(Error::Malformed));
        assert_eq!(
            SigningKey::load_locked(&path, b"correct horse")
                .unwrap()
                .public_key(),
            plain.public_key()
        );
        assert_eq!(
            SigningKey::lock_file(&path, b"another one").err(),
            Some(Error::Malformed)
        );
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_new_key_never_replaces_one_already_there() {
        let directory = std::env::temp_dir().join(format!("splint-new-key-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("owner.key");
        let created = SigningKey::create_new(&path).unwrap();
        assert_eq!(SigningKey::create_new(&path).err(), Some(Error::KeyStorage));
        assert_eq!(
            SigningKey::load(&path).unwrap().public_key(),
            created.public_key()
        );
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(&directory).unwrap();
    }
}

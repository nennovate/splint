//! An owner's sign-in held by the Mac's security chip, the Secure Enclave. The key is made inside the
//! chip and never leaves it: what's kept in a file is the chip's own handle for it, which no other Mac
//! can use. Each signature needs the person there, with Touch ID or their login password, and one
//! prompt covers every signature one run of this program makes, in words this program writes from what
//! it's about to sign.
//!
//! What it doesn't do yet: tie the key to Splint's own signed program, which needs an app bundle. So
//! another program running as the same person could ask the chip to sign with a prompt of its own, and
//! would still need their touch.

mod bridge;

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use security_framework::access_control::SecAccessControl;
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use splint_core::{Error, HeldKey};

use crate::sign_in::{read_private, write_private};

/// `kSecAccessControlPrivateKeyUsage`: the key signs inside the chip.
const PRIVATE_KEY_USAGE: usize = 1 << 30;
/// `kSecAccessControlUserPresence`: only with Touch ID or the login password, each time.
const USER_PRESENCE: usize = 1;
/// `errSecUserCanceled`, and the domain whose every error means the person didn't get through.
const USER_CANCELED: isize = -128;
const LOCAL_AUTHENTICATION: &str = "com.apple.LocalAuthentication";

/// Whether the chip asks for the person on each use. Only tests make a key it doesn't ask for, so no
/// test ever puts a prompt on the screen of the Mac it runs on.
#[derive(Clone, Copy)]
pub enum Presence {
    Required,
    #[cfg(test)]
    NotRequired,
}

pub struct Chip {
    handle: Vec<u8>,
    point: Vec<u8>,
    reason: String,
    /// The key with this run's prompt context, made at the first signature and kept for the rest.
    signing: Mutex<Option<SecKey>>,
}

/// What the chip is told a key needs to sign: always that it signs inside the chip, and the person,
/// each time, unless a test made it.
fn access_flags(presence: Presence) -> usize {
    match presence {
        Presence::Required => PRIVATE_KEY_USAGE | USER_PRESENCE,
        #[cfg(test)]
        Presence::NotRequired => PRIVATE_KEY_USAGE,
    }
}

/// Makes a key in the chip and keeps its handle at `path`, refusing one already there.
pub fn create(path: &Path, presence: Presence) -> Result<(), Error> {
    let access =
        SecAccessControl::create_with_flags(access_flags(presence)).map_err(|_| Error::Crypto)?;
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_access_control(access);
    let key = SecKey::new(&options).map_err(|_| Error::KeyStorage)?;
    let handle = bridge::token_object(&key).ok_or(Error::KeyStorage)?;
    write_private(path, &handle)
}

/// The chip's key whose handle is at `path`. Opening it asks nothing: only signing does, with
/// `reason` as the prompt's words.
pub fn open(path: &Path, reason: &str) -> Result<Chip, Error> {
    let handle = read_private(path)?.ok_or(Error::KeyStorage)?;
    let key = restore(&handle, None)?;
    let point = key
        .public_key()
        .and_then(|public| public.external_representation())
        .ok_or(Error::KeyStorage)?
        .bytes()
        .to_vec();
    Ok(Chip {
        handle,
        point,
        reason: reason.to_owned(),
        signing: Mutex::new(None),
    })
}

/// The key a handle names, as the chip gives it back. `SecKeyCreateRandomKey` with a token handle
/// and no permanence restores that key rather than making one, which is how Apple's own tools do it.
#[allow(deprecated)]
fn restore(handle: &[u8], context: Option<CFType>) -> Result<SecKey, Error> {
    let mut attributes = CFMutableDictionary::<CFString, CFType>::new();
    let mut set = |name: &'static str, value: CFType| {
        attributes.set(CFString::from_static_string(name), value);
    };
    // `kSecAttrKeyTypeECSECPrimeRandom`, `kSecAttrTokenIDSecureEnclave`, as their values.
    set("type", CFString::from_static_string("73").as_CFType());
    set("bsiz", CFNumber::from(256).as_CFType());
    set(
        "tkid",
        CFString::from_static_string("com.apple.setoken").as_CFType(),
    );
    set("toid", CFData::from_buffer(handle).as_CFType());
    set("perm", CFBoolean::false_value().as_CFType());
    if let Some(context) = context {
        // `kSecUseAuthenticationContext`.
        set("u_AuthCtx", context);
    }
    SecKey::generate(attributes.to_untyped().to_immutable()).map_err(|_| Error::KeyStorage)
}

fn refusal(error: &CFError) -> Error {
    if error.code() == USER_CANCELED || error.domain() == LOCAL_AUTHENTICATION {
        Error::NotApproved
    } else {
        Error::Crypto
    }
}

impl HeldKey for Chip {
    fn public_point(&self) -> Vec<u8> {
        self.point.clone()
    }

    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signing = self.signing.lock().unwrap_or_else(PoisonError::into_inner);
        if signing.is_none() {
            *signing = Some(restore(
                &self.handle,
                Some(bridge::prompt_context(&self.reason)),
            )?);
        }
        let key = signing.as_ref().ok_or(Error::Crypto)?;
        key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|error| refusal(&error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use splint_core::SigningKey;

    /// Bug caught: a chip key every sign-in makes that signs for any program running as the person,
    /// with nobody there, as the chip is never told to ask for them. What the chip then does with the
    /// flag needs the hardware, which no test here touches.
    #[test]
    fn a_sign_in_in_the_chip_asks_for_the_person_each_time() {
        let flags = access_flags(Presence::Required);
        assert_ne!(flags & USER_PRESENCE, 0);
        assert_ne!(flags & PRIVATE_KEY_USAGE, 0);
    }

    /// Bug caught: a chip key whose handle doesn't come back as the same key after a restart, or
    /// whose signatures readers refuse. It needs a Mac with a Secure Enclave, so it runs on demand,
    /// with a key that never asks for the person.
    #[test]
    #[ignore = "needs a Mac with a Secure Enclave: cargo test -p owner-key -- --ignored"]
    fn a_chip_key_comes_back_from_its_handle_and_signs_what_readers_take() {
        let dir = std::env::temp_dir().join(format!("owner-key-chip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::sign_in::make_private_dir(&dir).unwrap();
        let path = dir.join("owner.chip");
        create(&path, Presence::NotRequired).unwrap();
        assert!(create(&path, Presence::NotRequired).is_err());
        let first = SigningKey::held(Box::new(open(&path, "test").unwrap())).unwrap();
        let again = SigningKey::held(Box::new(open(&path, "test").unwrap())).unwrap();
        assert_eq!(first.public_key(), again.public_key());
        let phone = SigningKey::generate().unwrap();
        let owner = splint_core::Identity::create(
            &first,
            &splint_core::SealingKey::generate().unwrap().public_key(),
            splint_core::RecoveryRule::later(&first.public_key()),
        )
        .unwrap();
        let added = owner.add_key(&again, &phone, 1_793_750_400).unwrap();
        assert!(splint_core::Identity::from_encoded(&added.encoded()).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

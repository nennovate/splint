//! Signing with this computer's sign-in for what Splint on the computer or the owner's page prepared,
//! and adding a second computer's sign-in to the same owner ID. Each signs only after one prompt this
//! program writes from exactly what it signs.

use std::path::Path;

use serde::{Deserialize, Serialize};
use splint_core::prepared::Prepared;
use splint_core::reading_key::{self, ReadingKeyCopy};
use splint_core::rules::VerifiedRules;
use splint_core::{Error, Identity, SealingKey, unix_now};

use crate::device::{self, Device};
use crate::prompt;
use crate::sign_in::{self, Holding, make_private_dir};

/// The lock a new sign-in's copy of the reading key is sealed to, beside it.
const LOCK: &str = "owner.lock";
/// One touch's objects, taken whole, however many there are.
const MOST_INPUT_BYTES: usize = 256 * 1024;
/// What has its own command, which shows the person exactly that: adding or removing a sign-in or
/// setting the recovery code moves the owner ID itself, and giving an agent away or retiring it moves
/// the agent, and each lasts, so a page, which never makes them, never has them signed in a batch.
const NOT_FROM_A_PAGE: [&str; 5] = [
    "splint-key-add",
    "splint-key-remove",
    "splint-recovery-rule",
    "splint-release",
    "splint-retirement",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    inputs: Vec<String>,
}

#[derive(Serialize)]
pub struct Signed {
    signed: Vec<String>,
    code: String,
}

pub fn sign_inputs(dir: &Path, given: Inputs) -> Result<Signed, Error> {
    let size: usize = given.inputs.iter().map(String::len).sum();
    if given.inputs.is_empty() || size > MOST_INPUT_BYTES {
        return Err(Error::Malformed);
    }
    let prepared = given
        .inputs
        .iter()
        .map(|input| Prepared::read(input))
        .collect::<Result<Vec<_>, _>>()?;
    if prepared
        .iter()
        .any(|one| NOT_FROM_A_PAGE.contains(&one.typ()))
    {
        return Err(Error::Malformed);
    }
    let device = Device::open(dir, prompt::for_objects(&prepared)?)?;
    let signed = prepared
        .iter()
        .map(|one| one.sign(&device.key))
        .collect::<Result<Vec<_>, _>>()?;
    // Rules a page here signs are the newest this device has signed for that agent, so an agent's ask
    // approved later starts from them, never from older ones that would undo the page's change.
    for (one, signed) in prepared.iter().zip(&signed) {
        if one.typ() == "splint-rules"
            && let Ok(rules) = VerifiedRules::reload(signed, &device.identity)
        {
            device.remember_rules(rules.agent(), &rules.draft(), rules.seq())?;
        }
    }
    Ok(Signed {
        signed,
        code: device.code().unwrap_or_default().to_owned(),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    offer: String,
    /// The lock its copy of the reading key is sealed to, signed by the key offered, so whoever
    /// carries the offer can't put a lock of their own in its place.
    lock: String,
}

/// A second computer's sign-in, made in `dir`, offered to the computer whose sign-in `by` names.
pub fn offer(dir: &Path, identity: &Identity, by: &str, holding: Holding) -> Result<Offer, Error> {
    make_private_dir(dir).map_err(|_| Error::KeyStorage)?;
    let key = sign_in::create(
        dir,
        holding,
        &prompt::for_command("offer this computer as a sign-in"),
    )?;
    let lock = SealingKey::create_new(&dir.join(LOCK))?;
    Ok(Offer {
        offer: identity.offer_key(by, &key, unix_now())?,
        lock: reading_key::sign_lock(&key, identity.id(), &lock.public_key())?,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Added {
    identity: String,
    copy: String,
}

pub fn add(dir: &Path, offered: Offer) -> Result<Added, Error> {
    let key = Identity::offered_key(&offered.offer)?;
    let lock = reading_key::verified_lock(&offered.lock, &key, device::identity_in(dir)?.id())?;
    let name = splint_core::OwnerKey::name_of(&key);
    let device = Device::open(
        dir,
        prompt::for_command(&format!(
            "add the sign-in {} to your owner ID",
            name.get(..8).unwrap_or_default()
        )),
    )?;
    let next = device.identity.add_offered(&device.key, &offered.offer)?;
    let copy = ReadingKeyCopy::seal(&next, &name, &lock, &device.seal_key)?;
    let device = device.keep_identity(&next)?;
    Ok(Added {
        identity: device.identity.encoded(),
        copy,
    })
}

pub fn take(dir: &Path, added: Added) -> Result<Device, Error> {
    let identity = Identity::from_encoded(&added.identity)?;
    let key = sign_in::open(
        dir,
        &prompt::for_command("take up this sign-in for your owner ID"),
    )?;
    if !identity
        .keys()
        .iter()
        .any(|counting| counting.point() == &key.public_key())
    {
        return Err(Error::WrongSigner);
    }
    sign_in::warn_if_plain(dir);
    let lock = SealingKey::load(&dir.join(LOCK))?;
    let reading = ReadingKeyCopy::read(&added.copy, &identity)?.open(&lock, &identity)?;
    Device::take_up(dir, &identity, &reading)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("owner-key-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Bug caught: a second computer that can sign for the ID but can't read what's sealed to it, or
    /// one added without the first computer's sign-in.
    #[test]
    fn a_second_computer_signs_and_reads_as_the_first_does() {
        let first = scratch("first-computer");
        let made = Device::init_signed_in(&first, Holding::PlainFile).unwrap();
        let second = scratch("second-computer");
        let offered = offer(
            &second,
            &made.identity,
            &made.key_name(),
            Holding::PlainFile,
        )
        .unwrap();

        let stranger = scratch("stranger-computer");
        Device::init_signed_in(&stranger, Holding::PlainFile).unwrap();
        let wrong = Offer {
            offer: offered.offer.clone(),
            lock: offered.lock.clone(),
        };
        assert!(add(&stranger, wrong).is_err());

        let added = add(&first, offered).unwrap();
        let taken = take(&second, added).unwrap();
        assert_eq!(taken.identity.id(), made.identity.id());
        assert_eq!(taken.seal_key.public_key(), made.seal_key.public_key());
        assert_eq!(
            Device::open(&first, prompt::for_command("test"))
                .unwrap()
                .identity
                .keys()
                .len(),
            2
        );
        for dir in [first, second, stranger] {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    /// Bug caught: a page getting a key of its own added, a sign-in removed, a recovery code set, or
    /// an agent given away or retired, in a batch the person reads as something else; or a batch
    /// signed after a prompt other than the one written from it, whose code the page then doesn't see.
    #[test]
    fn a_page_never_has_the_owner_id_or_an_agent_moved() {
        let dir = scratch("page-batch");
        Device::init_signed_in(&dir, Holding::PlainFile).unwrap();
        let header = |typ: &str| {
            use base64::Engine as _;
            let encode =
                |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            format!(
                "{}.{}",
                encode(format!(r#"{{"alg":"ES256","typ":"{typ}"}}"#).as_bytes()),
                encode(br#"{"v":1}"#)
            )
        };
        for typ in [
            "splint-key-add",
            "splint-key-remove",
            "splint-recovery-rule",
            "splint-release",
            "splint-retirement",
        ] {
            let given = Inputs {
                inputs: vec![header("splint-rules"), header(typ)],
            };
            assert_eq!(sign_inputs(&dir, given).err(), Some(Error::Malformed));
        }
        let fine = Inputs {
            inputs: vec![header("splint-rules")],
        };
        let signed = sign_inputs(&dir, fine).unwrap();
        assert_eq!(signed.signed.len(), 1);
        let shown = [Prepared::read(&header("splint-rules")).unwrap()];
        assert_eq!(signed.code, splint_core::prepared::touch_code(&shown));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Bug caught: whoever carries the offer between the two computers swapping its lock for their
    /// own, so the computer that counts seals them the owner's reading key and adds the sign-in anyway.
    #[test]
    fn a_carrier_cant_swap_the_offers_lock() {
        let first = scratch("lock-first");
        let made = Device::init_signed_in(&first, Holding::PlainFile).unwrap();
        let second = scratch("lock-second");
        let offered = offer(
            &second,
            &made.identity,
            &made.key_name(),
            Holding::PlainFile,
        )
        .unwrap();
        let carriers = SealingKey::generate().unwrap();
        let carrier = splint_core::SigningKey::generate().unwrap();
        for lock in [
            carriers.public_key().encoded(),
            reading_key::sign_lock(&carrier, made.identity.id(), &carriers.public_key()).unwrap(),
        ] {
            let swapped = Offer {
                offer: offered.offer.clone(),
                lock,
            };
            assert!(add(&first, swapped).is_err());
        }
        assert_eq!(
            Device::open(&first, prompt::for_command("test"))
                .unwrap()
                .identity
                .keys()
                .len(),
            1
        );
        for dir in [first, second] {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

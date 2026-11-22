//! The recovery code an owner's page shows its person once, in place of a backup file. Their backup key
//! is derived from it, so the code on paper or in a password manager recovers their ID when their
//! passkey is gone. See "Keys an owner's page derives" in `docs/protocol.md`.

use crate::keys::derived_scalar;
use crate::pairing::{from_base32, to_base32};
use crate::{Error, SigningKey};

const CODE_LEN: usize = 16;
const BACKUP_SALT: &[u8] = b"splint backup v1";
/// How the page groups the 26 characters, so a person can copy them by hand.
const GROUP_CHARS: usize = 4;

/// 128 random bits. Like a key, it has no `Debug`, `Display` or `Serialize`, so it can't reach a log,
/// an error or a response by accident:
///
/// ```compile_fail
/// # fn wrong(code: splint_core::recovery_code::RecoveryCode) -> String {
/// format!("{code:?}")
/// # }
/// ```
pub struct RecoveryCode([u8; CODE_LEN]);

impl RecoveryCode {
    /// 128 fresh random bits, for an owner setting their code from a terminal.
    pub fn generate() -> Result<Self, Error> {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0_u8; CODE_LEN];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| Error::Crypto)?;
        Ok(Self(bytes))
    }

    /// As a person may type it: in either case, with spaces, dashes or line breaks anywhere. What's left
    /// has to be the code's one spelling, 26 characters whose last 2 spare bits are zero.
    pub fn parse(typed: &str) -> Result<Self, Error> {
        let plain: String = typed
            .chars()
            .filter(|character| !character.is_whitespace() && *character != '-')
            .map(|character| character.to_ascii_lowercase())
            .collect();
        from_base32(&plain).map(Self)
    }

    /// The owner's backup key, which their ID commits to.
    pub fn backup_key(&self) -> Result<SigningKey, Error> {
        SigningKey::from_scalar(&derived_scalar(&self.0, BACKUP_SALT)?)
    }

    /// How a page shows it: groups of 4, joined by dashes.
    pub fn spelled(&self) -> String {
        let plain = to_base32(&self.0);
        let groups: Vec<String> = plain
            .chars()
            .collect::<Vec<char>>()
            .chunks(GROUP_CHARS)
            .map(|group| group.iter().collect())
            .collect();
        groups.join("-")
    }
}

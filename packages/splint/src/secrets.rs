//! Tokens and the private files that hold them.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use splint_core::private_files;

use crate::failure::Failure;

const TOKEN_BYTES: usize = 32;

/// A generated secret. It's saved to private files and handed to programs through their environment,
/// and `Debug` is all it can print, so a mistake can't put one in a terminal or a log.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Token(String);

impl Token {
    pub fn generate() -> Result<Self, Failure> {
        let mut raw = [0u8; TOKEN_BYTES];
        SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| Failure::refused("this machine couldn't make a random token"))?;
        Ok(Self(raw.iter().map(|byte| format!("{byte:02x}")).collect()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(hidden)")
    }
}

/// Writes a new file and renames it into place, so a crash leaves the old one and nobody else can
/// read it at any point.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    // A file left by a crash might have other permissions, and `mode` only counts when creating.
    match fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file =
        private_files::open(OpenOptions::new().write(true).create_new(true), &temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_long_and_never_printed() {
        let token = Token::generate().unwrap();
        assert_eq!(token.expose().len(), TOKEN_BYTES * 2);
        assert_ne!(token.expose(), Token::generate().unwrap().expose());
        assert!(!format!("{token:?}").contains(token.expose()));
    }
}

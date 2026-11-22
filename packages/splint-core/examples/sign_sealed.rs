//! Seals and signs one envelope with a key file, as a stolen key could, for tests that put sealed
//! content a sender's Signet would never make in front of a reader. Nothing that ships has this.
//!
//! It reads JSON on stdin: `key` (a file holding a PKCS#8 P-256 key), `sender` and `recipient`
//! (encoded identities), `body`, `created_at`, `expires_at`, `nonce` and `sender_chose`. It writes the
//! compact envelope, and with `"to"` set to another encoded identity, seals it to that one's key instead
//! of the recipient's.

use std::error::Error;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::Deserialize;
use splint_core::{Identity, SealFor, Sealing, SigningKey, sign_with_nonce};

#[derive(Deserialize)]
struct Input {
    key: PathBuf,
    sender: String,
    recipient: String,
    body: String,
    created_at: u64,
    expires_at: u64,
    nonce: String,
    sender_chose: Sealing,
    #[serde(default)]
    to: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text)?;
    let input: Input = serde_json::from_str(&text)?;
    let key = SigningKey::load(&input.key)?;
    let sender = Identity::from_encoded(&input.sender)?;
    let recipient = Identity::from_encoded(&input.recipient)?;
    let sealed_to = match &input.to {
        Some(other) => Identity::from_encoded(other)?,
        None => recipient.clone(),
    };
    let missing = || io::Error::other("an identity here has no sealing key");
    let seal_for = SealFor {
        recipient: sealed_to.seal_key().ok_or_else(missing)?,
        own: sender.seal_key().ok_or_else(missing)?,
        sender_chose: input.sender_chose,
    };
    let signed = sign_with_nonce(
        &key,
        &sender,
        recipient.id(),
        input.body,
        input.created_at,
        input.expires_at.saturating_sub(input.created_at),
        Some(input.nonce),
        Some(&seal_for),
    )?;
    io::stdout().write_all(signed.compact.as_bytes())?;
    Ok(())
}

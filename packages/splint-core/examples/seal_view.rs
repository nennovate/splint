//! Seals text to an owner's sealing key, as a Signet seals the view it leaves at its host, for tests
//! that play an agent holding its Signet's key and leaving whatever it likes there. The owner's sealing
//! key is public, so this is no more than anyone can do. Nothing that ships has this.
//!
//! It reads JSON on stdin: `owner` (an encoded identity), `agent` (the agent's ID) and `view`, and
//! writes the sealed view.

use std::error::Error;
use std::io::{self, Read, Write};

use serde::Deserialize;
use splint_core::host_api::owner_view_about;
use splint_core::{Identity, SplintId, seal_note};

#[derive(Deserialize)]
struct Input {
    owner: String,
    agent: SplintId,
    view: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text)?;
    let input: Input = serde_json::from_str(&text)?;
    let owner = Identity::from_encoded(&input.owner)?;
    let to = owner
        .seal_key()
        .ok_or_else(|| io::Error::other("that owner has no sealing key"))?;
    let sealed = seal_note(to, input.view.as_bytes(), &owner_view_about(&input.agent))?;
    io::stdout().write_all(sealed.as_bytes())?;
    Ok(())
}

//! Seals a call's body to an agent, as an owner's device does for owner network access, for tests that
//! play someone on the network replaying or redirecting what they saw. An agent's sealing key is
//! public, so this is no more than anyone can do. Nothing that ships has this.
//!
//! It reads JSON on stdin: `agent` (the agent's encoded identity), `method`, `path` and `body`, the
//! call's own JSON body, or `raw`, text sealed as it is, and writes the sealed call, `{"sealed"}`.

use std::error::Error;
use std::io::{self, Read, Write};

use serde::Deserialize;
use splint_core::Identity;
use splint_core::owner_call::seal_owner_call;

#[derive(Deserialize)]
struct Input {
    agent: String,
    method: String,
    path: String,
    #[serde(default)]
    body: serde_json::Value,
    /// Sealed as it is, for a body that isn't JSON.
    raw: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text)?;
    let input: Input = serde_json::from_str(&text)?;
    let agent = Identity::from_encoded(&input.agent)?;
    let body = match input.raw {
        Some(raw) => raw.into_bytes(),
        None => serde_json::to_vec(&input.body)?,
    };
    let sealed = seal_owner_call(&agent, &input.method, &input.path, &body)?;
    io::stdout().write_all(serde_json::to_string(&sealed)?.as_bytes())?;
    Ok(())
}

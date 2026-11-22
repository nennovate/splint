//! Opens the copy of an owner's list of agents sealed to their backup, with the recovery code a page
//! showed them, as a person who lost their passkey would. For tests that check what a page keeps can
//! be recovered by the protocol's rules, not the page's own. Nothing that ships has this.
//!
//! It reads JSON on stdin: `owner_identity` (encoded), `list` (the signed list a host keeps), `host`
//! and `code` (the recovery code, typed any way), and writes the agents it lists, each with its backup's
//! public point, as JSON.

use std::error::Error;
use std::io::{self, Read, Write};

use serde::Deserialize;
use serde_json::json;
use splint_core::owner_agents::VerifiedOwnerAgents;
use splint_core::recovery_code::RecoveryCode;
use splint_core::{Identity, unix_now};

#[derive(Deserialize)]
struct Input {
    owner_identity: String,
    list: String,
    host: String,
    code: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text)?;
    let input: Input = serde_json::from_str(&text)?;
    let owner = Identity::from_encoded(&input.owner_identity)?;
    let list = VerifiedOwnerAgents::verify(&input.list, &owner, &input.host, unix_now())?;
    let backup = RecoveryCode::parse(&input.code)?.backup_key()?;
    let mut agents = Vec::new();
    for listed in list.open_for_recovery(&backup, &owner)? {
        agents.push(json!({
            "agent": listed.agent,
            "address": listed.address,
            "label": listed.label,
            "backup": listed.backup.key()?.public_key().encoded(),
        }));
    }
    io::stdout().write_all(serde_json::to_string(&agents)?.as_bytes())?;
    Ok(())
}

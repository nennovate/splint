//! Seals something to an agent as owner mail, as an owner's device does before leaving it at the
//! agent's host, or opens owner mail with an agent's sealing key, as its Signet does, for tests that
//! leave what an owner never signed, and that read what a page sent on its way to a host. An agent's
//! sealing key is public, so sealing is no more than anyone can do, and opening takes the key file a
//! test's own Signet keeps. Nothing that ships has this.
//!
//! It reads JSON on stdin. To seal: `agent` (the agent's encoded identity), `kind` and `signed`, and
//! it writes the body an owner's device posts, `{"sealed"}`. To open: `key` (the path of the agent's
//! sealing key), `agent_id` and `body`, that body, and it writes what was inside, `{"kind","signed"}`.

use std::error::Error;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::Deserialize;
use splint_core::host_api::{OwnerMail, OwnerMailKind};
use splint_core::owner_call::{SealedCall, mail_body, open_owner_mail, seal_owner_mail};
use splint_core::{Identity, SealingKey, SplintId};

#[derive(Deserialize)]
#[serde(untagged)]
enum Input {
    Seal {
        agent: String,
        kind: OwnerMailKind,
        signed: String,
    },
    Open {
        key: PathBuf,
        agent_id: SplintId,
        body: String,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text)?;
    let out = match serde_json::from_str(&text)? {
        Input::Seal {
            agent,
            kind,
            signed,
        } => {
            let agent = Identity::from_encoded(&agent)?;
            mail_body(&seal_owner_mail(&agent, &OwnerMail { kind, signed })?)?
        }
        Input::Open {
            key,
            agent_id,
            body,
        } => {
            let call: SealedCall = serde_json::from_str(&body)?;
            let opened = open_owner_mail(&SealingKey::load(&key)?, &agent_id, &call.sealed)?;
            serde_json::to_vec(&opened)?
        }
    };
    io::stdout().write_all(&out)?;
    Ok(())
}

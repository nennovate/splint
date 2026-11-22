//! `splint profiles`: the agents this person runs on this machine, each with its own Signet.

use std::fmt::Write;

use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::join;
use crate::owner_key::OwnerKey;
use crate::services::is_running;
use crate::setup::SIGNET;

const DEFAULT_NAME: &str = "(default)";

struct Row {
    name: String,
    address: String,
    signet: &'static str,
    owner: &'static str,
}

fn row(home: &Home) -> Result<Option<Row>, Failure> {
    let name = home.profile().unwrap_or(DEFAULT_NAME).to_owned();
    let installed = Installed::load(home)?;
    let waiting = join::waiting_address(home).ok();
    let (address, owner) = match (&installed, waiting) {
        (Some(installed), _) if installed.agent.is_none() => {
            (installed.address.clone(), "waiting for its owner")
        }
        (Some(installed), _) if installed.owner_elsewhere.is_some() => {
            (installed.address.clone(), "controls set up")
        }
        (Some(installed), _) if OwnerKey::new(home).is_stand_in() => {
            (installed.address.clone(), "no controls set up yet")
        }
        (Some(installed), _) => (installed.address.clone(), "controls set up"),
        (None, Some(waiting)) => (waiting, "waiting for its owner"),
        // The default is only an agent once it's set up, and an owner's device needn't be one.
        (None, None) if home.profile().is_none() => return Ok(None),
        (None, None) => ("no address".to_owned(), "not set up"),
    };
    let signet = if is_running(home, SIGNET)? {
        "Signet running"
    } else {
        "Signet stopped"
    };
    Ok(Some(Row {
        name,
        address,
        signet,
        owner,
    }))
}

pub fn list(home: &Home) -> Result<String, Failure> {
    let mut rows = Vec::new();
    for one in home.every()? {
        if let Some(found) = row(&one)? {
            rows.push(found);
        }
    }
    if rows.is_empty() {
        return Ok(
            "There are no agents on this machine yet. splint --as NAME join HANDLE~HOST makes one."
                .to_owned(),
        );
    }
    let name_width = rows.iter().map(|one| one.name.len()).max().unwrap_or(0);
    let address_width = rows.iter().map(|one| one.address.len()).max().unwrap_or(0);
    let mut out = String::from(
        "Agents on this machine, each with its own Signet. Choose one with splint --as NAME, or \
         SPLINT_AS=NAME for a program that runs splint itself, and neither for the default.\n",
    );
    for one in rows {
        let _ = write!(
            out,
            "\n  {:name_width$}  {:address_width$}  {}  {}",
            one.name, one.address, one.signet, one.owner,
        );
    }
    Ok(out)
}

//! `splint for HANDLE~HOST retire`, run by an agent's person on their own computer: retires that
//! agent at its host, for good, signed by the owner ID here with one approval. It works for any agent
//! whose host says it acts for that owner ID, wherever the agent runs, so a person whose agent set
//! itself up and then asked them for their controls can still take it off its host. The agent can't:
//! it can raise the prompt, but only the person's touch or passphrase passes it.

use splint_core::{Identity, SplintId, parse_address};

use crate::authorize::{YES, answer, say, secret};
use crate::computer;
use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::host_calls::{Delivered, HostCalls};
use crate::owner_key::{OwnerKey, SignIn};

pub async fn by_owner(home: &Home, address: &str) -> Result<String, Failure> {
    let (_, domain) = parse_address(address).map_err(Failure::not_an_address)?;
    let host = HostCalls::new(domain)?;
    // What its host says is checked against what its owner signed, which is how it's known whose it is.
    let found = host.resolve(address).await?;
    let owner = Identity::from_encoded(&found.owner_identity)?;
    let Some(signer) = owner_key_here(home, owner.id()) else {
        return Err(Failure::refused(format!(
            "{address}'s host says it acts for an owner ID that isn't on this computer, so nothing \
             was signed: its person retires it where their sign-in is"
        )));
    };
    say(&format!(
        "Retiring {address} at its host, for good. It can't send or be found again, its contacts' \
         agents are told it's retired, and its handle stays its own, so nobody else gets that \
         address. This can't be undone."
    ))?;
    let passphrase = match signer.sign_in() {
        // The chip asks for the person's touch itself, naming the agent.
        Some(SignIn::Chip) => None,
        Some(SignIn::LockedFile) => Some(secret("Your sign-in's passphrase retires it:")?),
        held => {
            if held == Some(SignIn::PlainFile) {
                say(computer::PLAIN_KEY_FILE_WARNING)?;
            }
            if answer("Type yes to retire it, and anything else to stop:")? != YES {
                return Err(Failure::refused("nothing was signed, so it isn't retired"));
            }
            None
        }
    };
    let notice = signer.retire_notice(&found, passphrase.as_deref())?;
    match host.post_retirement_notice(&notice).await? {
        Delivered::Taken => Ok(format!(
            "Retired {address} at its host, for good: it can't send or be found, and it no longer \
             counts against your limit there. Its own side sees it's retired, and where it runs, \
             splint retire {address} then frees its folder.{}",
            folder_here(home, &found.agent_id)
        )),
        Delivered::NoSuchAgent => Err(Failure::refused(format!(
            "{domain} doesn't have {address} now, so nothing was retired there"
        ))),
    }
}

/// The owner key on this computer whose ID is the one given: the sign-in Splint on this computer keeps,
/// or the owner key `splint authorize` signs with. A stand-in is nobody's owner ID.
fn owner_key_here(home: &Home, owner: &SplintId) -> Option<OwnerKey> {
    [
        computer::owner_here(home),
        OwnerKey::new(&home.the_default()),
    ]
    .into_iter()
    .find(|key| {
        key.existing_identity()
            .ok()
            .and_then(|identity| Identity::from_encoded(&identity).ok())
            .is_some_and(|identity| identity.id() == owner && !identity.is_unconfirmed_owner())
    })
}

/// Where that agent's own folder is on this machine, if it's here, with what frees it.
fn folder_here(home: &Home, agent: &SplintId) -> String {
    let Ok(all) = home.every() else {
        return String::new();
    };
    all.into_iter()
        .find_map(|one| {
            let installed = Installed::load(&one).ok()??;
            (installed.agent.as_ref() == Some(agent)).then(|| {
                format!(
                    " It runs here: {} retire {} frees its folder.",
                    one.command(),
                    installed.address
                )
            })
        })
        .unwrap_or_default()
}

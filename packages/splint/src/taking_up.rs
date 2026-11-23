//! An agent taking up its person's answer to its ask for controls, by itself: `splint auto` as soon as
//! it's at the agent's host, and `splint finish` with nothing after it. Only an answer to an ask the
//! agent's Signet holds as still waiting counts, so an answer nobody asked for is never taken.

use std::fs::{File, OpenOptions};

use serde::Deserialize;
use splint_core::{JoinReply, private_files};

use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::join;
use crate::owner_key::OwnerKey;
use crate::signet_api::SignetApi;

/// Held by the one command taking up an owner's answer for this agent, as a second at the same time
/// would find the stand-in gone, or going, and refuse. Only `take_up_lock` makes one, and
/// `join::finish` and `join::finish_kept` take one, so every taker holds the lock: `splint finish`,
/// with an answer or without, `splint ask` and `splint auto`. `splint ask` once took one up without
/// it, so `splint auto` taking the same one up meanwhile left the agent told it had no key (issue
/// 1125).
pub struct TakingUp {
    _lock: File,
}

fn take_up_lock(home: &Home) -> Result<TakingUp, Failure> {
    Home::make_private(&home.run_dir())?;
    let file = private_files::open(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
        &home.lock_file("controls-answer"),
    )?;
    file.lock()?;
    Ok(TakingUp { _lock: file })
}

/// `splint finish ANSWER`: the answer given, taken up as the one taker at a time. Running it again
/// does what it always did, finishing what failed or taking a newer answer.
pub async fn finish_given(home: &Home, answer: &str, with_code: bool) -> Result<String, Failure> {
    let held = take_up_lock(home)?;
    join::finish(home, &held, answer, with_code).await
}

/// The answer to this agent's ask for controls that Splint on this computer handed back, taken up as
/// the one taker at a time. Which way it goes is decided only once the lock is held, from what the
/// taker before left. Once that one took up this very answer, its stand-in, which signs the handover,
/// is gone, and there's nothing left to do but say so. It's this answer only if the backup it names is
/// the one the agent now commits to, as each approval makes a new one, so a newer answer from the same
/// owner is taken up as any is. And only once that taker's clean-up is done, as one that stopped
/// partway leaves the stand-in's folder behind.
pub async fn take_up(home: &Home, answer: &str) -> Result<String, Failure> {
    let held = take_up_lock(home)?;
    if let Some(installed) = Installed::load(home)?
        && installed.agent.is_some()
        && !OwnerKey::new(home).is_stand_in()
        && !home.stand_in_dir().exists()
        && let Some(owner) = installed.owner_elsewhere.as_deref()
        && JoinReply::decode(answer).is_ok_and(|reply| {
            reply.owner_identity == owner && reply.commitment == installed.backup.commitment
        })
    {
        return Ok(format!(
            "Your person set up their controls for you, and that's taken up: you're {}. {} status \
             shows how things stand.",
            installed.address,
            home.command()
        ));
    }
    join::finish(home, &held, answer, false).await
}

/// For `splint auto`: an agent that asked by link for its controls takes up the answer to that ask its
/// host keeps once one owner its link reached has approved, so nobody has to run `splint finish`. Only
/// while that ask is waiting, and only an answer naming it, so an answer nobody asked for is never
/// taken by itself, and with two such owners' answers it takes neither, as `splint finish` doesn't.
pub async fn take_up_kept_if_asked(home: &Home) -> Result<Option<String>, Failure> {
    if !asking_for_controls(home).await? {
        return Ok(None);
    }
    let held = take_up_lock(home)?;
    join::finish_kept(home, &held).await
}

/// Whether this agent's ask for its controls, as its link makes, is waiting.
async fn asking_for_controls(home: &Home) -> Result<bool, Failure> {
    Ok(!controls_asks_waiting(home).await?.is_empty())
}

/// The IDs of this agent's asks for its controls still waiting, as its Signet holds them. Only an
/// answer naming one of these is one it asked for: anyone can leave one for its key, as that's public,
/// but only whoever its link reached knows an ask's ID.
pub async fn controls_asks_waiting(home: &Home) -> Result<Vec<String>, Failure> {
    let (installed, _) = Installed::require(home)?;
    let listed: AsksListed = serde_json::from_value(
        SignetApi::new(home, &installed)?
            .agent_get("/v0/asks")
            .await?,
    )
    .map_err(|_| Failure::refused("Signet's asks can't be read"))?;
    Ok(listed
        .asks
        .into_iter()
        .filter(|one| {
            one.status == "waiting" && splint_core::asks::controls_delegate(&one.changes).is_some()
        })
        .map(|one| one.id)
        .collect())
}

#[derive(Deserialize)]
struct AsksListed {
    asks: Vec<AskListed>,
}

#[derive(Deserialize)]
struct AskListed {
    id: String,
    status: String,
    changes: Vec<splint_core::asks::Change>,
}

/// `splint finish` with nothing after it: with its link's ask waiting, the one answer to that ask its
/// host keeps. An agent that didn't ask takes nobody's, as whoever left one for its key may be a
/// stranger.
pub async fn finish_pending(home: &Home) -> Result<String, Failure> {
    if matches!(asking_for_controls(home).await, Ok(true)) {
        let held = take_up_lock(home)?;
        if let Some(said) = join::finish_kept(home, &held).await? {
            return Ok(said);
        }
        return Err(Failure::refused(
            "your person hasn't approved you yet. Once they open computer_link from splint controls \
             and approve, you take it up by yourself",
        ));
    }
    Err(Failure::refused(
        "nothing is waiting: run splint controls, and give your person its computer_link",
    ))
}

/// The binding its person signed giving this agent's name their owner part, taken up: its Signet
/// registers under the new name, its host keeps the old one pointing there, and this folder notes the
/// new address, so everything here starts there next time. Taking one up twice says so.
pub async fn take_up_owner_part(home: &Home, binding: &str) -> Result<String, Failure> {
    let _held = take_up_lock(home)?;
    let (installed, _) = Installed::require(home)?;
    let api = SignetApi::new(home, &installed)?;
    let before = api.who().await?.address;
    let named = |address: &str| {
        splint_core::parse_address(address)
            .is_ok_and(|(name, _)| splint_core::name_parts(name).1.is_some())
    };
    if !named(&before) {
        api.put_binding(binding)
            .await
            .map_err(|failure| match failure {
                Failure::Refused(why) => Failure::refused(format!(
                    "your host didn't take the name your person signed, so nothing changed: {why}"
                )),
                typed => typed,
            })?;
    }
    let address = api.who().await?.address;
    if !named(&address) {
        return Err(Failure::refused(
            "your Signet still runs under your old name, so nothing changed: ask your person again",
        ));
    }
    Installed {
        address: address.clone(),
        owner_part: None,
        ..installed
    }
    .save(home)?;
    Ok(if address == before {
        format!("You're {address} already.")
    } else {
        format!(
            "Your person added their name to yours: you're {address} now. Anyone who has {before} \
             still reaches you, as your host says where it went. Give your new address from here on."
        )
    })
}

/// For `splint ask ID` on an ask to add its person's name: their answer, once they've approved it, from
/// Splint on this computer, or kept at its host for an agent on another one, taken up. Only a binding
/// their own key signed for this agent at its name with an owner part added is taken.
pub async fn take_up_owner_part_if_answered(
    home: &Home,
    ask: &str,
) -> Result<Option<String>, Failure> {
    let here = match crate::computer::Client::new(home)?.outcome(ask).await {
        Ok(Some(crate::computer::Outcome::Done {
            answer: Some(binding),
        })) => Some(binding),
        _ => None,
    };
    let binding = match here {
        Some(binding) => Some(binding),
        None => kept_owner_part(home).await?,
    };
    match binding {
        Some(binding) => take_up_owner_part(home, &binding).await.map(Some),
        None => Ok(None),
    }
}

/// A binding adding the owner's part to this agent's name, which Splint on their computer left at its
/// host, as it does for a move, for an agent it can't hand it to.
async fn kept_owner_part(home: &Home) -> Result<Option<String>, Failure> {
    let (installed, _) = Installed::require(home)?;
    let Some(owner) = installed.owner_elsewhere.as_deref() else {
        return Ok(None);
    };
    let owner = splint_core::Identity::from_encoded(owner)?.id().clone();
    let who = SignetApi::new(home, &installed)?.who().await?;
    let (_, domain) = splint_core::parse_address(&installed.address)?;
    let Some(kept) = crate::host_calls::HostCalls::new(domain)?
        .answer_from(&who.key, owner.as_str())
        .await?
    else {
        return Ok(None);
    };
    let Ok(reply) = splint_core::MoveReply::decode(&kept) else {
        return Ok(None);
    };
    let agent = splint_core::Identity::from_encoded(&who.identity)?;
    let adds_owner_part = reply.check(&agent, &owner).is_ok_and(|at| {
        splint_core::parse_address(&at)
            .ok()
            .and_then(|(name, _)| splint_core::name_parts(name).1)
            .and_then(|part| splint_core::with_owner_part(&installed.address, part).ok())
            .is_some_and(|named| named == at)
    });
    Ok(adds_owner_part.then_some(reply.binding))
}

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

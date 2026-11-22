//! What runs on the owner's side so a level above ask me means something: it reads what's waiting for
//! each agent this device signs for, works out the drafts here from what's signed, and has `owner-key
//! auto` sign what the owner's own rules allow. It holds no key and makes no decision of its own.
//!
//! It's only ever what the owner chose: at ask me it signs nothing, and everything else waits for them
//! as it did. It stops with `splint stop`, and by itself once the folder it serves has gone.
//!
//! For an agent nobody has set up controls for, it signs with the stand-in on this machine, and only
//! contacts both agents agreed to by invite. It also takes up the person's answer to the agent's ask
//! for controls once they approve, however long after `splint controls` stopped waiting.
//!
//! It also sends to each agent's host again what only a straight answer took, until the host takes it.

use std::io::{self, Write};
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use splint_core::Identity;
use splint_core::requests::{ApprovalDraft, Schema};
use splint_core::rules::Level;
use splint_core::unix_now;

use crate::direct::{self, SentAgain};
use crate::failure::Failure;
use crate::home::{HOME_SETTING, Home, PROFILE_SETTING};
use crate::invites;
use crate::owner_key::{ForAgent, OwnerKey};
use crate::owner_side::{OwnerSide, OwnerSigned};
use crate::page::walk::walk_all;
use crate::services::{self, Keep, Service, Started};
use crate::taking_up;

pub const AUTO: &str = "splint-auto";
const THIS_PROGRAM: &str = "splint";
const EVERY: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
struct Signed {
    approvals: Vec<ForAgent>,
}

/// Starts this for whoever holds an owner key here. Starting it twice does nothing. A profile's signs
/// for its own agent, and the default's for the agents authorized from this machine too.
pub fn start(home: &Home) -> Result<Started, Failure> {
    let home_dir = std::env::var(HOME_SETTING)
        .map_err(|_| Failure::refused(format!("{HOME_SETTING} isn't set")))?;
    let mut env = vec![(HOME_SETTING, home_dir.as_str())];
    if let Some(profile) = home.profile() {
        env.push((PROFILE_SETTING, profile));
    }
    services::start(
        home,
        &Service {
            name: AUTO,
            binary: THIS_PROGRAM,
            args: &["auto"],
            env,
            keep: Keep::AcrossRestarts,
        },
    )
}

pub async fn stop(home: &Home) -> Result<(), Failure> {
    services::stop(home, AUTO, THIS_PROGRAM).await
}

pub fn is_running(home: &Home) -> Result<bool, Failure> {
    services::is_running(home, AUTO)
}

/// Stops one from an older install, so the next start runs this build.
pub async fn stop_older(home: &Home) -> Result<(), Failure> {
    services::stop_older(home, AUTO, THIS_PROGRAM).await
}

/// Runs until it's stopped, as the one copy here, so `splint stop` stops whatever signs. A failure for
/// one agent is for the next pass.
pub async fn run(home: &Home) -> Result<String, Failure> {
    let Some(_only_copy) = services::the_only_copy(home, AUTO)? else {
        return Ok("splint auto is already running here.".to_owned());
    };
    while home.exists() {
        if let Err(failure) = once(home).await {
            let _ = writeln!(io::stderr(), "splint auto: {failure}");
        }
        tokio::time::sleep(EVERY).await;
    }
    Ok("The folder this looks after has gone.".to_owned())
}

/// One pass over every agent this device signs for, for anyone who'd rather run it on a schedule.
pub async fn once(home: &Home) -> Result<String, Failure> {
    for sent in direct::send_again(home, direct::Proves::NobodyThere).await {
        let said = match sent {
            SentAgain::Taken(agent, kind) => {
                format!("{agent}'s host took {} at last", kind.words())
            }
            SentAgain::Refused(agent, kind, failure) => format!(
                "{agent}'s host refused {what} kept for it, which it would again, so this stops \
                 sending {them}: {failure}",
                what = kind.words(),
                them = kind.them(),
            ),
            SentAgain::StillAway => continue,
        };
        let _ = writeln!(io::stderr(), "splint auto: {said}");
    }
    let mut signed = 0_usize;
    for side in OwnerSide::all(home)? {
        match for_one_agent(home, &side).await {
            Ok(count) => signed = signed.saturating_add(count),
            Err(failure) => {
                let _ = writeln!(io::stderr(), "splint auto: {}: {failure}", side.address());
            }
        }
    }
    Ok(format!("Signed {signed} by the rules you signed."))
}

async fn for_one_agent(home: &Home, side: &OwnerSide) -> Result<usize, Failure> {
    // A stand-in signs no approval that would count, and signs in only what both agents agreed to.
    // Its person's answer to its ask for controls is taken up as it lands.
    if OwnerKey::new(home).is_stand_in() {
        // Two owners' answers are said, and what both agents agreed still goes.
        match taking_up::take_up_kept_if_asked(home).await {
            Ok(Some(_)) => {
                let _ = writeln!(
                    io::stderr(),
                    "splint auto: {}: took up the controls its person set up",
                    side.address()
                );
                return Ok(1);
            }
            Ok(None) => {}
            Err(failure) => {
                let _ = writeln!(io::stderr(), "splint auto: {}: {failure}", side.address());
            }
        }
        return invites::sign_agreed(home, side).await;
    }
    // Only whether to ask owner-key at all, which signs by its own copy and changes no rules.
    let rules = side.rules_kept_here(home)?;
    if rules.draft.permissions.level == Level::AskMe {
        return Ok(0);
    }
    let owner_key = OwnerKey::new(home);
    let owner = Identity::from_encoded(&owner_key.existing_identity()?)?;
    let view = side.read(home).await?;
    let walked = walk_all(&view.requests, side.agent(), &owner, &view.schemas)?;
    let now = unix_now();
    let drafts: Vec<ApprovalDraft> = walked
        .walked
        .iter()
        // One per request, the first of what waits: once that's signed the chain has moved on, and a yes
        // to a second, worked out from where it was, would be refused.
        .filter_map(|one| one.drafts(now).into_iter().next())
        .chain(walked.starting.iter().filter_map(|open| open.draft(now)))
        .collect();
    if drafts.is_empty() {
        return Ok(0);
    }
    let schemas: Vec<&Schema> = view.schemas.all().collect();
    let waiting = json!({ "drafts": drafts, "schemas": schemas }).to_string();
    let at = side.at_host().await?;
    let signed: Signed =
        serde_json::from_str(&owner_key.auto(side.agent(), &waiting, at.as_ref())?)
            .map_err(|_| Failure::refused("the owner key didn't say what it signed"))?;
    let count = signed.approvals.len();
    for approval in signed.approvals {
        match side.hand_over(home, OwnerSigned::Approval(approval)).await {
            Ok(()) => {}
            // Its Signet said it took this one, and it's kept for its host, so the rest still go.
            Err(Failure::NotYetAtHost(said)) => {
                let _ = writeln!(io::stderr(), "splint auto: {}: {said}", side.address());
            }
            Err(failure) => return Err(failure),
        }
    }
    Ok(count)
}

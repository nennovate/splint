//! `splint switch-host`: moves this agent to another host under the same ID. Its owner's side signs a
//! binding at the new address, with one approval where a person set up controls, or by itself for a
//! stand-in or an owner key kept in this folder. Then Signet starts again at that address, registers
//! there as anyone joining does, writes the move in its signed history and tells every contact, whose
//! own owners' rules decide what they do about it. The host it leaves is never needed, and hears when
//! it can, after which it says where the agent went and takes no more of its mail.
//!
//! Nothing a host or a contact says can start one: only a shell on this machine runs this, and nothing
//! moves without what the owner signed for exactly that address.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use splint_core::asks::move_approval_lapsed;
use splint_core::{
    Identity, MoveReply, VerifiedBinding, canonical_address, name_parts, parse_address, unix_now,
};

use crate::asks::{self, LOOK_EVERY, Signed, WAIT_FOR_TOUCH};
use crate::computer::{Asked, Client, Outcome, set_up_here};
use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::host_calls::HostCalls;
use crate::owner_key::OwnerKey;
use crate::secrets::write_private;
use crate::services;
use crate::setup::{self, SIGNET};
use crate::signet_api::{RETIRED_WORDS, SignetApi, Who};

const WITH_CODE: &str = "--with-code";
const LEAVE_MAIL: &str = "--leave-mail";
/// Looks at what waits at the host left this many times, for rows its Signet had just put off.
const MOST_LOOKS_FOR_MAIL: usize = 3;

/// A move under way, kept in the agent's own folder until it's done.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    to: String,
    /// The ask its person was asked, while their answer hasn't come.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ask: Option<String>,
    /// What the owner's side signed: their half of a binding at `to`, and the backup's vouch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<String>,
    /// The agent said to move without what waits at the host it leaves, which can't be read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    leave_mail: bool,
}

impl Pending {
    fn load(home: &Home) -> Result<Option<Self>, Failure> {
        match std::fs::read(home.move_file()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| Failure::refused("move.json in the Splint folder can't be read")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, home: &Home) -> Result<(), Failure> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| Failure::refused("couldn't write down the move"))?;
        Ok(write_private(&home.move_file(), &bytes)?)
    }

    fn forget(home: &Home) -> Result<(), Failure> {
        match std::fs::remove_file(home.move_file()) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }
}

/// Where a move under way is to, for `status`.
pub fn under_way(home: &Home) -> Option<String> {
    Pending::load(home).ok().flatten().map(|pending| pending.to)
}

/// What a move came to, for the agent.
pub struct Moving {
    /// moved, waiting or not_approved.
    pub status: &'static str,
    pub address: String,
    pub said: String,
    pub ask: Option<String>,
    /// Opens the ask on Splint on the person's own computer.
    pub computer_link: Option<String>,
}

impl Moving {
    pub fn json(&self) -> Value {
        json!({
            "status": self.status, "address": self.address, "said": self.said, "ask": self.ask,
            "computer_link": self.computer_link,
        })
    }

    /// What was said, then the link on a line of its own.
    pub fn in_words(&self) -> String {
        match &self.computer_link {
            Some(link) => format!("{}\n\ncomputer_link: {link}", self.said),
            None => self.said.clone(),
        }
    }
}

/// Whether this is an owner's approval of a move, rather than an answer to a join.
pub fn is_a_move_reply(answer: &str) -> bool {
    MoveReply::decode(answer).is_ok()
}

/// The binding in an owner's approval, only if it's this agent's owner's, for this agent, at `to`.
fn approved_at(answer: &str, who: &Who, to: &str) -> Result<String, Failure> {
    let refused = || {
        Failure::refused("that approval isn't this agent's owner's for this move, so nothing moved")
    };
    let reply = MoveReply::decode(answer).map_err(|_| refused())?;
    let agent = Identity::from_encoded(&who.identity).map_err(|_| refused())?;
    let owner = who.owner_id.as_ref().ok_or_else(refused)?;
    match reply.check(&agent, owner) {
        Ok(address) if address == to => Ok(reply.binding),
        _ => Err(refused()),
    }
}

/// `splint finish ANSWER` with an approval its person passed on by hand, as the new host didn't keep it.
pub async fn finish(home: &Home, answer: &str) -> Result<Moving, Failure> {
    let (installed, _) = Installed::require(home)?;
    let mut pending = Pending::load(home)?.ok_or_else(|| {
        Failure::refused("no move is under way: splint switch-host HANDLE~HOST starts one")
    })?;
    let who = SignetApi::new(home, &installed)?.who().await?;
    pending.binding = Some(approved_at(answer, &who, &pending.to)?);
    pending.save(home)?;
    go_on(home, false, false).await
}

/// What's waiting at the host this agent is leaving, taken into its Signet, or why that couldn't be
/// done, before anything changes: that host answers for it no more after a move.
async fn carry_mail(signet: &SignetApi<'_>, from: &str) -> Result<(), Failure> {
    let unread = |why: String| {
        Failure::refused(format!(
            "nothing moved: what's waiting for you at {from} can't be read now ({why}), and moving \
             would lose it. Try again once that host answers. If it's gone for good, run the same \
             command with {LEAVE_MAIL}, which moves without whatever is waiting there."
        ))
    };
    for look in 1..=MOST_LOOKS_FOR_MAIL {
        let said = signet
            .agent_post("/v0/inbox/carry", &json!({}))
            .await
            .map_err(|failure| unread(failure.to_string()))?;
        if said.get("full").and_then(Value::as_bool) == Some(true) {
            return Err(unread(
                "more is waiting than this agent's Signet has room for: read your inbox and ack \
                 what you've read first"
                    .to_owned(),
            ));
        }
        match said.get("again_after").and_then(Value::as_u64) {
            Some(seconds) if seconds > 0 && look < MOST_LOOKS_FOR_MAIL => {
                tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
            }
            Some(seconds) if seconds > 0 => break,
            _ => return Ok(()),
        }
    }
    // Some of it was still out of sight at the last look. Moving now would say it came along, and the
    // host it left would answer for it no more.
    Err(unread(
        "some of it was still put off for a while at the last look".to_owned(),
    ))
}

/// `splint switch-host [ADDRESS] [--with-code] [--hours N] [--leave-mail]`.
pub async fn run(home: &Home, words: &[&str]) -> Result<Moving, Failure> {
    let mut to = None;
    let mut with_code = false;
    let mut hours = None;
    let mut leave_mail = false;
    let mut rest = words.iter();
    while let Some(word) = rest.next() {
        match *word {
            WITH_CODE => with_code = true,
            LEAVE_MAIL => leave_mail = true,
            "--hours" => {
                hours = Some(
                    rest.next()
                        .and_then(|hours| hours.parse::<u64>().ok())
                        .ok_or_else(|| Failure::refused("--hours is a number from 1 to 24"))?,
                );
            }
            word if !word.starts_with('-') && to.is_none() => to = Some(word),
            _ => return Err(Failure::Usage),
        }
    }
    match to {
        Some(to) => start(home, to, with_code, hours, leave_mail).await,
        None => go_on(home, with_code, leave_mail).await,
    }
}

/// Whether this agent can have `to` there: free, or already this agent's, as when it comes back. Taken
/// is by the handle before any owner part, as a host keeps one agent to each. Room and an owner part
/// can only be known by registering, so those are said only after the approval.
async fn name_free(
    host: &HostCalls,
    to: &str,
    agent: &splint_core::SplintId,
) -> Result<(), Failure> {
    let (name, domain) = parse_address(to)?;
    let (handle, _) = name_parts(name);
    for asked in [name, handle] {
        if !host.handle_taken(asked).await? {
            continue;
        }
        // By the ID alone, which proves itself: the host this agent left still shows it, with a history
        // that says it's elsewhere, and coming back is how that stops being true.
        let ours = host
            .agent_as_held(&format!("{asked}~{domain}"), Some(agent))
            .await
            .is_ok();
        if !ours {
            return Err(Failure::HandleTaken {
                handle: handle.to_owned(),
                domain: domain.to_owned(),
            });
        }
    }
    Ok(())
}

async fn start(
    home: &Home,
    to: &str,
    with_code: bool,
    hours: Option<u64>,
    leave_mail: bool,
) -> Result<Moving, Failure> {
    let (installed, agent) = Installed::require(home)?;
    let to = canonical_address(to).map_err(Failure::not_an_address)?;
    let (_, to_domain) = parse_address(&to)?;
    if installed.host_domain()? == to_domain {
        return Err(Failure::refused(
            "that's the host this agent is on now: a move is to another host",
        ));
    }
    let signet = SignetApi::new(home, &installed)?;
    let who = signet.who_settled().await?;
    if signet.retired().await {
        return Err(Failure::refused(RETIRED_WORDS));
    }
    // What its host says of it now never decides this: one that doesn't take it back, or that gave
    // its handle to someone else, is who this command is for. Its owner's own retirement, above, does.
    if !who.holds_a_binding() {
        return Err(Failure::refused(
            "this agent holds no binding its owner signed, so it has nothing to move: splint \
             status says why",
        ));
    }
    let host = HostCalls::new(to_domain)?;
    let open = host.says_open_to_a_move().await?;
    name_free(&host, &to, &agent).await?;
    // Read now, before anyone is asked, so a host that needs one doesn't cost a second approval.
    let code = if with_code || !open {
        Some(setup::read_signup_code()?)
    } else {
        None
    };
    // Before anyone is asked, so a host that can't be read doesn't cost an approval.
    if !leave_mail {
        carry_mail(&signet, &installed.address).await?;
    }
    // A stand-in, or an owner key its person keeps in this folder, signs here, as at join.
    if installed.owner_elsewhere.is_none() {
        let binding = OwnerKey::new(home).bind(&who.identity, &to, &installed.backup)?;
        let pending = Pending {
            to,
            ask: None,
            binding: Some(binding),
            leave_mail,
        };
        pending.save(home)?;
        return take_up(home, installed, pending, code.as_deref()).await;
    }
    let body = json!({"changes": [{"change": "host", "to": to}], "hours": hours});
    let signed: Signed = serde_json::from_value(signet.agent_post("/v0/asks", &body).await?)
        .map_err(|_| Failure::refused("Signet's answer can't be read"))?;
    Pending {
        to: to.clone(),
        ask: Some(signed.id.clone()),
        binding: None,
        leave_mail,
    }
    .save(home)?;
    let asked = Asked {
        ask: signed.ask,
        identity: who.identity,
        address: who.address,
        draft: None,
        schema: None,
        linked: false,
        kinds: Vec::new(),
        agreed: Vec::new(),
        in_words: Default::default(),
    };
    let client = Client::new(home)?;
    let computer_link = asks::link_for(&asked.ask, &asked.address);
    let here = asks::hand_here(home, &client, &asked).await;
    // Its person approves on this computer only if this computer set it up. Anyone else needs the link
    // first, so this comes back at once with it.
    if !here || !set_up_here(home, &agent) {
        return Ok(Moving {
            status: "waiting",
            address: installed.address,
            said: format!(
                "Asked. Give your person computer_link: it opens this move in their controls on \
                 Splint on their own computer, where they approve it. Once they've approved, run \
                 {splint} switch-host or {splint} finish, which takes it up with nothing to paste. \
                 Nothing has moved yet, and it ends unapproved after its hours.",
                splint = home.command(),
            ),
            ask: Some(signed.id),
            computer_link: Some(computer_link),
        });
    }
    let started = std::time::Instant::now();
    while started.elapsed() < WAIT_FOR_TOUCH {
        match client.outcome(&signed.id).await? {
            Some(Outcome::Done {
                answer: Some(binding),
            }) => {
                let pending = Pending {
                    to,
                    ask: None,
                    binding: Some(binding),
                    leave_mail,
                };
                pending.save(home)?;
                return take_up(home, installed, pending, code.as_deref()).await;
            }
            Some(Outcome::NotApproved { .. }) => {
                Pending::forget(home)?;
                return Ok(not_approved(installed.address));
            }
            _ => tokio::time::sleep(LOOK_EVERY).await,
        }
    }
    Ok(Moving {
        status: "waiting",
        address: installed.address,
        said: format!(
            "Asked, and still waiting for your person's approval. If they aren't at this computer, \
             give them computer_link. Run {} switch-host later to take it up once they have. Nothing has \
             moved yet.",
            home.command(),
        ),
        ask: Some(signed.id),
        computer_link: Some(computer_link),
    })
}

fn not_approved(address: String) -> Moving {
    Moving {
        status: "not_approved",
        address,
        said: "Not approved, so nothing moved.".to_owned(),
        ask: None,
        computer_link: None,
    }
}

/// Goes on with a move under way: takes up the approval once it's come, or tries again what a new
/// host refused, with no second approval.
async fn go_on(home: &Home, with_code: bool, leave_mail: bool) -> Result<Moving, Failure> {
    let (installed, _) = Installed::require(home)?;
    let mut pending = Pending::load(home)?.ok_or_else(|| {
        Failure::refused("no move is under way: splint switch-host HANDLE~HOST starts one")
    })?;
    pending.leave_mail |= leave_mail;
    if pending.binding.is_none() {
        let id = pending.ask.clone().unwrap_or_default();
        let client = Client::new(home)?;
        let outcome = if client.is_up().await {
            client.outcome(&id).await?
        } else {
            None
        };
        match outcome {
            Some(Outcome::Done {
                answer: Some(binding),
            }) => {
                pending.binding = Some(binding);
                pending.save(home)?;
            }
            Some(Outcome::NotApproved { .. }) => {
                Pending::forget(home)?;
                return Ok(not_approved(installed.address));
            }
            _ => match kept_at_the_new_host(home, &installed, &pending).await {
                Some(binding) => {
                    pending.binding = Some(binding);
                    pending.save(home)?;
                }
                None => {
                    return Ok(Moving {
                        status: "waiting",
                        address: installed.address,
                        said: "Still waiting for your person to approve the move. Nothing has \
                               moved yet."
                            .to_owned(),
                        ask: pending.ask,
                        computer_link: None,
                    });
                }
            },
        }
    }
    let (_, to_domain) = parse_address(&pending.to)?;
    let open = HostCalls::new(to_domain)?.says_open_to_a_move().await?;
    let code = if with_code || !open {
        Some(setup::read_signup_code()?)
    } else {
        None
    };
    take_up(home, installed, pending, code.as_deref()).await
}

/// The owner's approval, where their device left it at the new host for this agent to take up. Anything
/// else there, such as an approval of some other address, is no answer to this move.
async fn kept_at_the_new_host(
    home: &Home,
    installed: &Installed,
    pending: &Pending,
) -> Option<String> {
    let who = SignetApi::new(home, installed).ok()?.who().await.ok()?;
    let owner = who.owner_id.clone()?;
    let (_, domain) = parse_address(&pending.to).ok()?;
    let kept = HostCalls::new(domain)
        .ok()?
        .answer_from(&who.key, owner.as_str())
        .await
        .ok()??;
    approved_at(&kept, &who, &pending.to).ok()
}

/// Starts Signet at the new address with what the owner signed, which registers it there and does the
/// rest itself. Anything the new host refuses puts it back where it was, still holding what was
/// signed, so trying again needs no second approval.
async fn take_up(
    home: &Home,
    installed: Installed,
    pending: Pending,
    code: Option<&str>,
) -> Result<Moving, Failure> {
    let binding = pending.binding.clone().unwrap_or_default();
    let agent = installed.agent.clone();
    if VerifiedBinding::claimed_agent(&binding).ok() != agent {
        Pending::forget(home)?;
        return Err(Failure::refused(
            "what was signed for this move isn't for this agent, so nothing moved",
        ));
    }
    let from = installed.address.clone();
    // What was approved before its owner retired it goes nowhere.
    if SignetApi::new(home, &installed)?.retired().await {
        Pending::forget(home)?;
        return Err(Failure::refused(RETIRED_WORDS));
    }
    // Last, as what came while its person approved has to go along too.
    if !pending.leave_mail {
        carry_mail(&SignetApi::new(home, &installed)?, &from).await?;
    }
    services::stop(home, SIGNET, SIGNET).await?;
    let moving = Installed {
        address: pending.to.clone(),
        ..installed
    };
    moving.save(home)?;
    let taken = match setup::start_signet(home, &moving, code).await {
        Ok(()) => match SignetApi::new(home, &moving) {
            Ok(api) => api.put_binding(&binding).await,
            Err(failure) => Err(failure),
        },
        Err(failure) => Err(failure),
    };
    if let Err(failure) = taken {
        services::stop(home, SIGNET, SIGNET).await?;
        let back = Installed {
            address: from.clone(),
            ..moving
        };
        back.save(home)?;
        // Its old host may be why it's moving, and what the new host said is what its person needs.
        match setup::start_signet(home, &back, None).await {
            Err(trouble) if !setup::up_without_its_host(&trouble) => return Err(trouble),
            _ => {}
        }
        // Its Signet heard only now, from the host it was leaving, and nothing took it anywhere.
        if SignetApi::new(home, &back)?.retired().await {
            Pending::forget(home)?;
            return Err(Failure::refused(RETIRED_WORDS));
        }
        // By the date in what was signed, which is what Signet goes by, and not when it got here.
        let too_old = VerifiedBinding::claimed_issued_at(&binding)
            .is_ok_and(|issued_at| move_approval_lapsed(issued_at, unix_now()));
        if too_old {
            Pending::forget(home)?;
        }
        return Err(refused_there(&failure, &pending.to, &from, too_old));
    }
    // The code is spent, so Signet runs on without it in what keeps it running.
    if code.is_some() {
        services::stop(home, SIGNET, SIGNET).await?;
        // The move is done, and a host that blinks now is signed on with again by itself.
        match setup::start_signet(home, &moving, None).await {
            Err(trouble) if !setup::up_without_its_host(&trouble) => return Err(trouble),
            _ => {}
        }
    }
    Pending::forget(home)?;
    Ok(Moving {
        status: "moved",
        address: pending.to.clone(),
        said: format!(
            "You're {to} now, with the same ID, and {mail}. Your contacts are told by themselves, \
             and each one's side does what its owner's rules say, which by default is carry on. \
             Your host at {from} is told when it can be reached, and then says where you went and \
             takes no more of your mail: requests under way to that address, and agents that \
             reached you by your reach setting rather than as contacts, don't move with you.",
            to = pending.to,
            mail = if pending.leave_mail {
                "anything waiting at your old host stayed there, as you chose"
            } else {
                "what was waiting for you came along, to read as usual"
            },
        ),
        ask: None,
        computer_link: None,
    })
}

/// Why the new host didn't take this agent, with what to do, by kind.
fn refused_there(failure: &Failure, to: &str, from: &str, too_old: bool) -> Failure {
    let next = if too_old {
        "What your person signed is more than a day old, so it can't be used again: run splint \
         switch-host with the address to ask them afresh."
    } else {
        "What your person signed is kept, so running splint switch-host again tries once more with \
         no second approval, and a signup code again if one is needed."
    };
    let why = match failure {
        Failure::HandleTaken { .. } => {
            "someone there already has that name, so ask your person to approve a move to another \
             name"
                .to_owned()
        }
        Failure::TryLater(said) => format!("{said}."),
        Failure::HostUnreachable(said) => format!("{said}."),
        failure => format!("it said: {failure}."),
    };
    let said = format!("{to} didn't take this agent, so it's still {from}: {why} {next}");
    match failure {
        Failure::HandleTaken { handle, domain } => Failure::HandleTaken {
            handle: handle.clone(),
            domain: domain.clone(),
        },
        Failure::TryLater(_) => Failure::TryLater(said),
        Failure::HostUnreachable(_) => Failure::HostUnreachable(said),
        _ => Failure::refused(said),
    }
}

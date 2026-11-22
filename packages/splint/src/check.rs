//! `splint check`: one fixed line counting what waits on this agent's move, for whatever runs it to
//! read at the start of a turn, or nothing at all when nothing waits.
//!
//! The line is built only from a closed set of kinds and numbers, and with `--here` the agent's own
//! address and folder. No address, ID, name or word anyone else wrote is ever in it, so a
//! counterparty can't put an instruction in front of an agent this way.
//! It says what waits on the agent, what waits on its person or the other side's, and, once each, an
//! invite it sent that was accepted and a request it opened that ended, for it to pass on.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use splint_core::requests::{Side, StepKind};

use crate::failure::Failure;
use crate::home::{Home, Installed, PROFILE_SETTING};
use crate::owner_key::OwnerKey;
use crate::secrets::write_private;
use crate::signet_api::{Changed, SignetApi};

/// What an agent does each time it's woken, in the words every guide for agents uses, with each
/// command as `splint` is run for this agent.
pub fn each_wake(splint: &str) -> String {
    format!(
        "Each time you're woken: {splint} check counts what waits now. Answer {splint} invites by \
         your judgment. Read {splint} inbox, and {splint} ack each message once you've taken it in: \
         Signet stops counting it and it's yours to handle, and until then it waits, so nothing is \
         lost if you stop partway. Then handle what came: reply with {splint} send, take your move \
         with {splint} requests and {splint} move, or decide to leave it. When check says a request \
         you opened has ended, tell whoever asked you for it how it ended, as {splint} requests \
         shows it. What you tell your person is your judgment, shaped by them. Each command takes \
         --json, for the same answer as the adapter's tool of its name, and check's gives the counts."
    )
}

/// What to do about what a line from `check` or `listen` counted, whether by shell or by tool.
pub fn handle_them(splint: &str) -> String {
    format!(
        "handle them with {splint} invites, inbox and requests, or the tools of those names, and ack \
         each message once you've taken it in."
    )
}

/// What's said when this agent's Signet doesn't answer, so a runtime never takes its silence for
/// nothing waiting. One the person stopped is theirs to start, so only Signet that isn't answering is
/// sent to `start`, which keeps its keeper through an outage (issues 714 and 734).
pub fn unanswered(failure: &Failure, splint: &str) -> String {
    match failure {
        Failure::Stopped => "Splint: your person stopped Splint here with splint stop, so nothing \
                             new for this agent is heard or counted until they start it again, \
                             which only they do."
            .to_owned(),
        // Signet answered, and it's the host that's away, in Signet's own words.
        Failure::HostUnreachable(said) => format!("Splint: {said}"),
        _ => format!(
            "Splint: this agent's Signet can't be reached: it isn't running, or isn't answering, so \
             what waits for it can't be counted and nothing new is heard until it answers again. \
             Start it with {splint} start, and {splint} status says where it stands."
        ),
    }
}

/// What an agent is told while its host says it closes, from the date alone. Moving keeps its ID and
/// contacts, and whether and where is its own and its person's call, so this names the way and no more.
pub fn host_closing(at: u64, splint: &str) -> String {
    let when = crate::agent_commands::times::shown_time(&serde_json::json!(at));
    format!(
        "Your host says it closes at {when} and takes no new agents. Moving to another host before \
         then keeps your ID and contacts: {splint} switch-host HANDLE~HOST, with your person's \
         approval. Whether and where to move is yours and your person's to decide."
    )
}

/// For a line said where sessions for other projects may run too: which agent it's for, and the
/// folder it keeps watch from, as one machine may run several.
pub fn whose(installed: &Installed) -> String {
    match &installed.joined_from {
        Some(folder) => format!(
            " It's for {}, the agent that joined from {}.",
            installed.address,
            folder.display()
        ),
        None => format!(" It's for {}.", installed.address),
    }
}

/// Where check keeps the invites it has said were accepted, beside the listeners' marks, by a name no
/// mark can have.
const TOLD_FILE: &str = "check.accepted.json";
/// Where it keeps the requests this agent opened that it has said ended, the same way.
const ENDED_FILE: &str = "check.ended.json";
/// How a request this agent opened can end, each said in its own word. Disputed isn't an end anyone
/// can pass on.
const ENDINGS: [&str; 4] = ["completed", "declined", "cancelled", "expired"];

/// What waits, counted. Each is a number, and nothing else from Signet is kept, so `check --json` is
/// as safe to read as the line.
#[derive(Default, PartialEq, Eq, Serialize)]
pub struct Waiting {
    invites: usize,
    unread: usize,
    your_move: usize,
    /// Requests, and requests to start, whose next step is the owner's yes.
    owner_requests: usize,
    /// Contacts agreed on both sides that wait for the owner's side to sign them in.
    owner_contacts: usize,
    /// Requests whose next step is the other side's owner's yes, so they aren't settled yet.
    their_owner: usize,
    /// Invites this agent sent that were accepted since check last said so, and are contacts now.
    new_contacts: usize,
    /// Requests whose yes can't come until the other side's person sets up their controls.
    their_controls: usize,
    /// Requests this agent opened that ended since check last said so, by how, for it to pass on to
    /// whoever asked. It ended none of these itself.
    opened_completed: usize,
    opened_declined: usize,
    opened_cancelled: usize,
    opened_expired: usize,
    /// Of the requests counted as waiting on a person, this side's or the other's, those agreed and not
    /// completed, so the line says agreed isn't settled. Never a reason for the line by itself.
    #[serde(skip)]
    agreed_waiting: usize,
}

#[derive(Deserialize)]
struct InvitesBox {
    invites: Vec<IgnoredAny>,
    #[serde(default)]
    sent: Vec<SentSeen>,
    /// Only compared with `sent`, never shown.
    #[serde(default)]
    waiting_for_owner: Vec<String>,
}

#[derive(Deserialize)]
struct SentSeen {
    id: String,
    to: String,
    accepted: bool,
}

#[derive(Deserialize)]
struct Inbox {
    messages: Vec<IgnoredAny>,
}

#[derive(Deserialize)]
struct Requests {
    requests: Vec<RequestSeen>,
    #[serde(default)]
    held_opens: Vec<HeldOpenSeen>,
}

#[derive(Deserialize)]
struct RequestSeen {
    /// Only compared with what was said before, never shown.
    #[serde(default)]
    request: Option<String>,
    role: Side,
    /// One of a closed set, only compared.
    #[serde(default)]
    state: String,
    your_moves: Vec<StepKind>,
    waiting_for_owner: Option<StepKind>,
    #[serde(default)]
    waiting_for_their_owner: Option<StepKind>,
    #[serde(default)]
    owner_said_no: Option<StepKind>,
    #[serde(default)]
    signatures: SignaturesSeen,
    /// Signet's `settled: false`, there while terms are agreed and it isn't completed.
    #[serde(default)]
    settled: Option<bool>,
    delivery: DeliverySeen,
    /// One of a closed set, only compared.
    #[serde(default)]
    pause_reason: Option<String>,
    #[serde(default)]
    noted_since_pause: bool,
}

/// Each side's yes, in Signet's closed set of words, only compared.
#[derive(Default, Deserialize)]
struct SignaturesSeen {
    #[serde(default)]
    yours: Option<String>,
    #[serde(default)]
    theirs: Option<String>,
}

#[derive(Deserialize)]
struct DeliverySeen {
    head_by: Option<Side>,
}

#[derive(Deserialize)]
struct HeldOpenSeen {
    status: String,
}

impl RequestSeen {
    /// The other side moved last, and this agent has more to do than call it off. Paused for
    /// information, it's the requester's, whose note is what it waits on, until one has come since,
    /// and then the recipient's, who alone resumes: the rule `splint requests` goes by.
    fn is_your_move(&self) -> bool {
        if self.state == "paused" && self.pause_reason.as_deref() == Some("needs_information") {
            return self.waiting_for_owner.is_none()
                && !self.your_moves.is_empty()
                && ((self.role == Side::Requester) != self.noted_since_pause);
        }
        self.waiting_for_owner.is_none()
            && self.delivery.head_by.is_some_and(|by| by != self.role)
            && self.your_moves.iter().any(|kind| *kind != StepKind::Cancel)
    }

    /// It's the recipient with the work to do, whose own deliver is what's next, so agreed-not-settled
    /// is no reason for it to hold off: told to wait, it would leave the work undone.
    fn does_the_work(&self) -> bool {
        self.role == Side::Recipient && matches!(self.state.as_str(), "working" | "paused")
    }

    /// Its person's yes waits, and not one their delegate gives by itself.
    fn waits_on_person(&self) -> bool {
        self.waiting_for_owner.is_some()
            && self.signatures.yours.as_deref() != Some("delegate_signs")
    }

    /// How a request this agent opened ended, unless it ended it itself, which it needn't be told. An
    /// owner's no goes as a decline from this side, and is theirs, not the agent's.
    fn ending(&self) -> Option<&str> {
        let ended = ENDINGS.iter().find(|word| **word == self.state)?;
        let by_itself = matches!(*ended, "declined" | "cancelled")
            && self.delivery.head_by == Some(self.role)
            && self.owner_said_no.is_none();
        (self.role == Side::Requester && !by_itself).then_some(*ended)
    }
}

/// What check has already said, from one of its files, which it says once.
fn told(home: &Home, file: &str) -> BTreeSet<String> {
    fs::read(home.marks_dir().join(file))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn note_told(home: &Home, file: &str, said: &BTreeSet<String>) -> Result<(), Failure> {
    let dir = home.marks_dir();
    Home::make_private(&dir)?;
    let bytes = serde_json::to_vec(said)
        .map_err(|_| Failure::refused("couldn't write down what check has said"))?;
    write_private(&dir.join(file), &bytes)?;
    Ok(())
}

/// What's now said once, by its IDs, for check to note as said.
struct Said {
    accepted: BTreeSet<String>,
    ended: BTreeSet<String>,
}

/// What waits, and what's now said once, for check to note.
async fn look(api: &SignetApi<'_>, home: &Home) -> Result<(Waiting, Said), Failure> {
    let unexpected = |_| Failure::refused("what this agent's Signet sent doesn't make sense");
    let invites: InvitesBox =
        serde_json::from_value(api.agent_get("/v0/invites").await?).map_err(unexpected)?;
    let inbox: Inbox =
        serde_json::from_value(api.agent_get("/v0/inbox").await?).map_err(unexpected)?;
    let requests: Requests =
        serde_json::from_value(api.agent_get("/v0/requests").await?).map_err(unexpected)?;
    let asked = requests
        .requests
        .iter()
        .filter(|one| one.waits_on_person())
        .count();
    let held = requests
        .held_opens
        .iter()
        .filter(|one| one.status == "waiting")
        .count();
    // One still waiting for the owner's side isn't a contact yet, and is counted as theirs till then.
    let accepted: BTreeSet<String> = invites
        .sent
        .into_iter()
        .filter(|one| one.accepted && !invites.waiting_for_owner.contains(&one.to))
        .map(|one| one.id)
        .collect();
    let new_contacts = accepted.difference(&told(home, TOLD_FILE)).count();
    let ended: Vec<(&str, &str)> = requests
        .requests
        .iter()
        .filter_map(|one| Some((one.request.as_deref()?, one.ending()?)))
        .collect();
    let told_ended = told(home, ENDED_FILE);
    let newly_ended = |how: &str| {
        ended
            .iter()
            .filter(|(id, ended)| *ended == how && !told_ended.contains(*id))
            .count()
    };
    let their_controls =
        |one: &&RequestSeen| one.signatures.theirs.as_deref() == Some("no_controls");
    // Either side's person may be the one whose yes is still to come: the requester's agent read an
    // accepted meeting as settled as readily as the recipient's.
    let agreed_waiting = requests
        .requests
        .iter()
        .filter(|one| one.settled == Some(false) && !one.does_the_work())
        .filter(|one| {
            one.waits_on_person()
                || (one.waiting_for_owner.is_none() && one.waiting_for_their_owner.is_some())
                || their_controls(one)
        })
        .count();
    let waiting = Waiting {
        invites: invites.invites.len(),
        unread: inbox.messages.len(),
        your_move: requests
            .requests
            .iter()
            .filter(|one| one.is_your_move())
            .count(),
        owner_requests: asked.saturating_add(held),
        owner_contacts: invites.waiting_for_owner.len(),
        their_owner: requests
            .requests
            .iter()
            .filter(|one| one.waiting_for_owner.is_none() && one.waiting_for_their_owner.is_some())
            .filter(|one| !their_controls(one))
            .count(),
        new_contacts,
        their_controls: requests
            .requests
            .iter()
            .filter(|one| !ENDINGS.contains(&one.state.as_str()))
            .filter(their_controls)
            .count(),
        opened_completed: newly_ended("completed"),
        opened_declined: newly_ended("declined"),
        opened_cancelled: newly_ended("cancelled"),
        opened_expired: newly_ended("expired"),
        agreed_waiting,
    };
    let ended = ended.into_iter().map(|(id, _)| id.to_owned()).collect();
    Ok((waiting, Said { accepted, ended }))
}

/// Counts what waits, through the agent's own calls.
pub async fn waiting(api: &SignetApi<'_>, home: &Home) -> Result<Waiting, Failure> {
    Ok(look(api, home).await?.0)
}

/// Counts what waits, and notes what's said once as said, as a plain `check` does, so `check --json`
/// gives an accepted invite or an ended request once too.
pub async fn waiting_said(api: &SignetApi<'_>, home: &Home) -> Result<Waiting, Failure> {
    let (waiting, said) = look(api, home).await?;
    if waiting.new_contacts > 0 {
        note_told(home, TOLD_FILE, &said.accepted)?;
    }
    if waiting.opened_ended() > 0 {
        note_told(home, ENDED_FILE, &said.ended)?;
    }
    Ok(waiting)
}

fn counted(count: usize, one: &str, many: &str) -> Option<String> {
    match count {
        0 => None,
        1 => Some(format!("1 {one}")),
        _ => Some(format!("{count} {many}")),
    }
}

/// A verb that agrees with what it follows: one thing, or more.
fn agreeing(count: usize, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 { one } else { many }
}

impl Waiting {
    /// Whether anything waits. That some of it is only agreed adds words to the line, not a reason
    /// for one.
    pub fn is_empty(&self) -> bool {
        *self
            == Self {
                agreed_waiting: self.agreed_waiting,
                ..Self::default()
            }
    }

    fn opened_ended(&self) -> usize {
        [
            self.opened_completed,
            self.opened_declined,
            self.opened_cancelled,
            self.opened_expired,
        ]
        .into_iter()
        .fold(0, usize::saturating_add)
    }

    /// The kinds a change to these would have been, in Signet's words.
    pub fn kinds(&self) -> Vec<Changed> {
        let mut kinds = Vec::new();
        if self.your_move > 0
            || self.their_owner > 0
            || self.their_controls > 0
            || self.opened_ended() > 0
        {
            kinds.push(Changed::Requests);
        }
        if self.invites > 0 || self.unread > 0 || self.new_contacts > 0 {
            kinds.push(Changed::Messages);
        }
        if self.owner_requests > 0 || self.owner_contacts > 0 {
            kinds.push(Changed::Owner);
        }
        kinds
    }

    /// One line, or none when nothing waits. What waits on a person is named, with the agent's part in
    /// it, rather than counted among what the agent handles. `splint` is how this agent runs it.
    pub fn line(&self, splint: &str, no_controls: bool) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let mut said = Vec::new();
        let yours: Vec<String> = [
            counted(self.invites, "invite", "invites"),
            counted(self.unread, "unread message", "unread messages"),
            counted(
                self.your_move,
                "request at your move",
                "requests at your move",
            ),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !yours.is_empty() {
            said.push(format!(
                "waiting on you: {}. Now {}",
                yours.join(", "),
                handle_them(splint)
            ));
        }
        let owners: Vec<String> = [
            counted(self.owner_requests, "request", "requests"),
            counted(self.owner_contacts, "contact", "contacts"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !owners.is_empty() {
            let total = self.owner_requests.saturating_add(self.owner_contacts);
            let controls = if no_controls {
                format!(
                    " They need controls set up first, which {splint} status says how to do, and \
                     {splint} ask-owner gives a message for them."
                )
            } else {
                String::new()
            };
            said.push(format!(
                "{} {} on your person's sign-off, which only they can give, so your part is telling \
                 them: {splint} requests shows each step under asked_owner, and {splint} ask --step \
                 ID STEP puts one in front of them.{controls}",
                owners.join(" and "),
                agreeing(total, "waits", "wait"),
            ));
        }
        if let Some(theirs) = counted(self.their_owner, "request", "requests") {
            said.push(format!(
                "{theirs} {} on the other side's sign-off, so it isn't settled yet: {splint} \
                 requests says whose.",
                agreeing(self.their_owner, "waits", "wait"),
            ));
        }
        if let Some(theirs) = counted(self.their_controls, "request", "requests") {
            said.push(format!(
                "{theirs} can't be settled until the other side's person sets up their controls, \
                 as no yes counts for their side till then: {splint} requests says which.",
            ));
        }
        // An agent booked its person's calendar for an accepted meeting that wasn't settled.
        if self.agreed_waiting > 0 {
            said.push(
                "Agreed isn't settled: act on what's agreed for real only once it's completed, or \
                 mark what you do as tentative and tell your person."
                    .to_owned(),
            );
        }
        let ended = self.opened_ended();
        if ended > 0 {
            let how: Vec<String> = [
                (self.opened_completed, "completed"),
                (self.opened_declined, "declined"),
                (self.opened_cancelled, "cancelled"),
                (self.opened_expired, "expired"),
            ]
            .into_iter()
            .filter(|(count, _)| *count > 0)
            .map(|(count, how)| format!("{count} {how}"))
            .collect();
            said.push(format!(
                "{} you opened {} ended: {}. Tell whoever asked you for {} how it ended, as {splint} \
                 requests shows it.",
                agreeing(ended, "A request", "Requests"),
                agreeing(ended, "has", "have"),
                how.join(", "),
                agreeing(ended, "it", "each"),
            ));
        }
        if let Some(accepted) = counted(self.new_contacts, "invite", "invites") {
            said.push(format!(
                "{accepted} you sent {} accepted, so they're a contact now, in {splint} contacts.",
                agreeing(self.new_contacts, "was", "were"),
            ));
        }
        Some(format!("Splint: {}", said.join(" ")))
    }
}

/// Whether a runtime started here is one this agent keeps watch from: the folder it joined from, or
/// anywhere a profile was chosen, as only a runtime set up for that agent chooses one.
fn is_here(chosen: bool, installed: &Installed) -> bool {
    if chosen
        || env::var(PROFILE_SETTING)
            .ok()
            .is_some_and(|name| !name.is_empty())
    {
        return true;
    }
    let current = env::current_dir().and_then(|dir| dir.canonicalize());
    match (&installed.joined_from, current) {
        (Some(joined), Ok(current)) => Path::new(joined) == current,
        _ => false,
    }
}

/// The agent, ready to call, unless `--here` says to keep quiet: elsewhere, or before it has joined.
pub fn agent_here(home: &Home, chosen: bool, here: bool) -> Result<Option<Installed>, Failure> {
    if here {
        return Ok(Installed::load(home)?
            .filter(|installed| installed.agent.is_some())
            .filter(|installed| is_here(chosen, installed)));
    }
    Ok(Some(Installed::require(home)?.0))
}

/// The line, or nothing when nothing waits or `--here` keeps it quiet. With `--here`, as a hook runs
/// it, the line names the agent and its folder, and a Signet that doesn't answer is said on it too,
/// as a hook shows only that.
pub async fn check(home: &Home, chosen: bool, here: bool) -> Result<Option<String>, Failure> {
    let Some(installed) = agent_here(home, chosen, here)? else {
        return Ok(None);
    };
    let api = SignetApi::new(home, &installed)?;
    // Nothing waits on a retired agent's move, and its host no longer answers it.
    if api.retired().await {
        let stopped = api.stopped().await.unwrap_or_default();
        let whose = if here {
            whose(&installed)
        } else {
            String::new()
        };
        return Ok(Some(format!("Splint: {stopped}{whose}")));
    }
    let waiting = match waiting_said(&api, home).await {
        Ok(waiting) => waiting,
        Err(
            failure @ (Failure::SignetUnreachable | Failure::SignetNoAnswer | Failure::Stopped),
        ) if here => {
            let line = unanswered(&failure, &home.command());
            return Ok(Some(format!("{line}{}", whose(&installed))));
        }
        Err(Failure::HostUnreachable(said)) if here => {
            return Ok(Some(format!("Splint: {said}{}", whose(&installed))));
        }
        Err(failure) => return Err(failure),
    };
    let no_controls = installed.owner_elsewhere.is_none() && OwnerKey::new(home).is_stand_in();
    let line = waiting.line(&home.command(), no_controls);
    // Said even with nothing waiting, as an agent that's stopped can't act on anything that comes.
    let line = match (api.stopped().await, line) {
        (Some(stopped), Some(line)) => Some(format!("{line} {stopped}")),
        (Some(stopped), None) => Some(format!("Splint: {stopped}")),
        (None, line) => line,
    };
    // Said every time, like a stop, as it waits on the agent until it has moved.
    let line = match (api.host_closing_at().await, line) {
        (Some(at), Some(line)) => Some(format!("{line} {}", host_closing(at, &home.command()))),
        (Some(at), None) => Some(format!("Splint: {}", host_closing(at, &home.command()))),
        (None, line) => line,
    };
    Ok(if here {
        line.map(|line| format!("{line}{}", whose(&installed)))
    } else {
        line
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bug this catches: a request paused for information counted as nobody's move, as the recipient
    // paused it last and the requester can only cancel, so check never woke the requester to answer.
    #[test]
    fn a_pause_for_information_is_the_requesters_move_till_a_note_comes() {
        let paused = |role: &str, moves: &[&str], noted: bool| -> Result<bool, serde_json::Error> {
            let seen: RequestSeen = serde_json::from_value(serde_json::json!({
                "role": role,
                "state": "paused",
                "pause_reason": "needs_information",
                "noted_since_pause": noted,
                "your_moves": moves,
                "delivery": { "head_by": "recipient" },
            }))?;
            Ok(seen.is_your_move())
        };
        assert!(paused("requester", &["cancel"], false).unwrap());
        assert!(!paused("recipient", &["resume", "cancel"], false).unwrap());
        assert!(!paused("requester", &["cancel"], true).unwrap());
        assert!(paused("recipient", &["resume", "cancel"], true).unwrap());
    }

    // Bug this catches: the inviter's check printed nothing for an accepted invite, or for a request
    // it opened that ended, so its agent never knew. The sim counts these through `check --json`.
    #[test]
    fn an_accepted_invite_and_an_ended_request_each_make_a_line() {
        let accepted = Waiting {
            new_contacts: 1,
            ..Waiting::default()
        }
        .line("splint", false)
        .unwrap();
        assert!(
            accepted.contains("1 invite you sent was accepted") && accepted.contains("contact")
        );
        let ended = Waiting {
            opened_cancelled: 1,
            ..Waiting::default()
        }
        .line("splint", false)
        .unwrap();
        assert!(ended.contains("A request you opened has ended: 1 cancelled"));
        assert!(ended.contains("whoever asked"));
    }
}

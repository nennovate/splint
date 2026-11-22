//! Every note this agent sends, kept by its Signet with the words it wrote, so a note never vanishes
//! without a record. It's `delivered` only once the reader's Signet says it opened and checked it, in a
//! receipt signed by the agent it went to. Until then it's what this agent's host says, which is only
//! that host's word. Nothing is sent again by itself: the agent sends the words again if they matter.
//!
//! A note is kept until it's delivered or has ended, and then 30 days more as history.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::host_api::DeliveryStatus;
use splint_core::requests::note_receipt_of;
use splint_core::{DeliveryFailure, DeliveryState, MessageId, SignedEnvelope, SplintId, unix_now};
use tokio::sync::Mutex;

use crate::Signet;
use crate::agent_api::ApiError;
use crate::ending::{InboxRows, Readable};
use crate::host_client::HostError;
use crate::state_file::{self, StateError};

/// How long a note is kept as history once it's delivered or has ended.
const KEPT_AFTER_ENDING_SECS: u64 = 30 * 24 * 60 * 60;
/// Far past what a host lets an agent send in the time a note is kept.
const MAX_NOTES: usize = 10_000;
/// What all their words come to, as a note's can be large and this file is written on each send. Past
/// it, ended notes' words go first, then the oldest waiting ones', and every record stays. Provisional.
const MAX_WORDS_BYTES: usize = 32 * 1024 * 1024;
/// Notes in a page of history. Each still waiting asks its host, so it's kept small.
const PAGE_SIZE: usize = 20;

#[derive(Clone, Serialize, Deserialize)]
struct Note {
    to: String,
    to_agent: SplintId,
    body: String,
    /// The words were let go to keep within the cap on what all of them come to. The record stays.
    #[serde(default)]
    body_dropped: bool,
    sent_at: u64,
    /// The order this Signet sent them in, which seconds can't give for two in the same one. Records
    /// kept before it have none, and come before every newer one.
    #[serde(default)]
    seq: u64,
    expires_at: u64,
    /// When the reader's Signet signed that it opened and checked it, by its own clock.
    #[serde(default)]
    delivered_at: Option<u64>,
    /// What this agent's own host said ended it before it reached the other side, and when.
    #[serde(default)]
    ended: Option<(Why, u64)>,
}

impl Note {
    /// When it stopped waiting on anything, which is when it can't open any more at the latest.
    fn ended_at(&self) -> u64 {
        let ended = self.delivered_at.or(self.ended.map(|(_, at)| at));
        ended.map_or(self.expires_at, |at| at.min(self.expires_at))
    }

    fn has_ended(&self, now: u64) -> bool {
        self.delivered_at.is_some() || self.ended.is_some() || now >= self.expires_at
    }
}

pub struct Sent {
    path: PathBuf,
    /// By message ID.
    notes: Mutex<HashMap<String, Note>>,
}

fn next_seq(notes: &HashMap<String, Note>) -> u64 {
    notes
        .values()
        .map(|note| note.seq)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

impl Sent {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let mut notes: HashMap<String, Note> = state_file::load(&path)?;
        keep_within_bounds(&mut notes, unix_now());
        Ok(Self {
            path,
            notes: Mutex::new(notes),
        })
    }

    /// Written down before it goes to the host, so one whose answer is lost still has a record.
    pub async fn record(
        &self,
        envelope: &SignedEnvelope,
        to: &str,
        to_agent: &SplintId,
        body: String,
        sent_at: u64,
    ) -> Result<(), HostError> {
        let mut notes = self.notes.lock().await;
        // From what's kept, under the lock, so it rises across restarts without a file of its own.
        let seq = next_seq(&notes);
        notes.insert(
            envelope.id.as_str().to_owned(),
            Note {
                to: to.to_owned(),
                to_agent: to_agent.clone(),
                body,
                body_dropped: false,
                sent_at,
                seq,
                expires_at: envelope.expires_at,
                delivered_at: None,
                ended: None,
            },
        );
        keep_within_bounds(&mut notes, sent_at);
        state_file::save(&self.path, &notes).map_err(|_| HostError::LocalStorage)
    }

    /// For a note its host refused outright, which didn't go.
    pub async fn forget(&self, id: &MessageId) -> Result<(), HostError> {
        let mut notes = self.notes.lock().await;
        if notes.remove(id.as_str()).is_some() {
            state_file::save(&self.path, &notes).map_err(|_| HostError::LocalStorage)?;
        }
        Ok(())
    }

    /// For a new owner, who doesn't get to read what the agent wrote for the last one.
    pub async fn forget_everything(&self) -> Result<(), HostError> {
        let mut notes = self.notes.lock().await;
        notes.clear();
        state_file::save(&self.path, &notes).map_err(|_| HostError::LocalStorage)
    }

    async fn note_ended(&self, id: &str, why: Why, now: u64) {
        let mut notes = self.notes.lock().await;
        let Some(note) = notes.get_mut(id).filter(|note| !note.has_ended(now)) else {
            return;
        };
        note.ended = Some((why, now));
        if state_file::save(&self.path, &notes).is_err() {
            tracing::debug!("couldn't save that a note ended, so its host is asked again");
        }
    }
}

/// Past the time each is kept, and within the caps. Over the count, the oldest that have ended go
/// first, and one still waiting only when no ended one is left. Over the words, only words go, never a
/// record: ended notes' first, oldest first, then waiting ones', each marked as let go.
fn keep_within_bounds(notes: &mut HashMap<String, Note>, now: u64) {
    notes.retain(|_, note| note.ended_at().saturating_add(KEPT_AFTER_ENDING_SECS) > now);
    let oldest_first = |notes: &HashMap<String, Note>| {
        let mut ids: Vec<(bool, u64, u64, String)> = notes
            .iter()
            .map(|(id, note)| (!note.has_ended(now), note.seq, note.sent_at, id.clone()))
            .collect();
        ids.sort();
        ids
    };
    if notes.len() > MAX_NOTES {
        for (_, _, _, id) in oldest_first(notes) {
            if notes.len() <= MAX_NOTES {
                break;
            }
            notes.remove(&id);
        }
    }
    let mut bytes: usize = notes.values().map(|note| note.body.len()).sum();
    if bytes <= MAX_WORDS_BYTES {
        return;
    }
    for (_, _, _, id) in oldest_first(notes) {
        if bytes <= MAX_WORDS_BYTES {
            break;
        }
        if let Some(note) = notes.get_mut(&id).filter(|note| !note.body.is_empty()) {
            bytes = bytes.saturating_sub(note.body.len());
            note.body = String::new();
            note.body_dropped = true;
        }
    }
}

/// Takes a `received` for a note this Signet sent, from the agent it went to. The row's checks went by
/// the newest copy of the signer's ID held here, so neither host, nor anyone but that agent, can make
/// a note look delivered. Says whether it was one, as anything else goes on to the request state
/// machine, where a `received` of an `open` names itself the same way.
pub async fn take_receipt(signet: &Signet, read: &Readable<InboxRows>) -> Result<bool, HostError> {
    let receipt = read.envelope();
    let Some(note) = note_receipt_of(receipt) else {
        return Ok(false);
    };
    let mut notes = signet.sent.notes.lock().await;
    let Some(kept) = notes
        .get_mut(note.as_str())
        .filter(|kept| &kept.to_agent == receipt.sender())
    else {
        return Ok(false);
    };
    // A replay or a second receipt changes nothing.
    if kept.delivered_at.is_some() {
        return Ok(true);
    }
    kept.delivered_at = Some(receipt.created_at());
    kept.ended = None;
    tracing::info!(message_id = %note, "the reader's Signet says it opened and checked it");
    state_file::save(&signet.sent.path, &notes).map_err(|_| HostError::LocalStorage)?;
    Ok(true)
}

/// Where a note stands, as one word an agent acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    /// The reader's Signet signed that it opened and checked it. Not that anyone read it.
    Delivered,
    /// Still being handed over, and tried again.
    Sending,
    /// Held unsent, because this host's operator blocked their host, or keeps this host private and
    /// doesn't name it.
    HeldUnsent,
    /// Their host took it, by this host's word, and nothing from their Signet yet says it has it.
    AtTheirHost,
    /// Held or dropped by their owner's rules, which a sender can't tell apart.
    Quarantined,
    /// This agent's own host says it ended unsent.
    NotDelivered,
    /// It expired with no receipt from their Signet, which may have opened it without saying so, as
    /// one from before receipts does. Not that it failed.
    NotConfirmed,
    /// This host couldn't say.
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Why {
    /// Their host refused it.
    Rejected,
    /// It expired before it was handed over.
    Expired,
    /// The owner's rules stopped it before it left.
    Withdrawn,
    /// This agent was retired while it waited.
    Retired,
    /// It expired with no receipt from their Signet.
    NoReceipt,
    /// This host couldn't be reached.
    NoAnswer,
    /// This host's answer didn't check out.
    BadAnswer,
    /// This host has no such message from this agent.
    NotFound,
}

#[derive(Debug, PartialEq, Eq)]
struct Judged {
    status: Status,
    why: Option<Why>,
    attempts: i32,
    last_failure: Option<DeliveryFailure>,
}

impl Judged {
    fn of(status: Status, why: Option<Why>) -> Self {
        Self {
            status,
            why,
            attempts: 0,
            last_failure: None,
        }
    }
}

/// What a note comes to, from its record and its host's word. A receipt always wins, and a note that
/// expired with none wasn't delivered, whatever its host says it did with it.
fn judge(note: Option<&Note>, said: Option<Result<DeliveryStatus, HostError>>, now: u64) -> Judged {
    if let Some(note) = note {
        if note.delivered_at.is_some() {
            return Judged::of(Status::Delivered, None);
        }
        if let Some((why, _)) = note.ended {
            return Judged::of(Status::NotDelivered, Some(why));
        }
    }
    let expired = note.is_some_and(|note| now >= note.expires_at);
    let no_receipt = Judged::of(Status::NotConfirmed, Some(Why::NoReceipt));
    let said = match said {
        Some(Ok(said)) => said,
        Some(Err(_)) | None if expired => return no_receipt,
        Some(Err(HostError::NotFound)) => return Judged::of(Status::Unknown, Some(Why::NotFound)),
        Some(Err(HostError::BadAnswer)) => {
            return Judged::of(Status::Unknown, Some(Why::BadAnswer));
        }
        Some(Err(_)) | None => return Judged::of(Status::Unknown, Some(Why::NoAnswer)),
    };
    let (status, why) = match said.status {
        DeliveryState::Pending => (Status::Sending, None),
        DeliveryState::PeerRemoved => (Status::HeldUnsent, None),
        DeliveryState::Delivered | DeliveryState::Quarantined if expired => return no_receipt,
        DeliveryState::Delivered => (Status::AtTheirHost, None),
        DeliveryState::Quarantined => (Status::Quarantined, None),
        DeliveryState::Rejected => (Status::NotDelivered, Some(Why::Rejected)),
        DeliveryState::Expired => (Status::NotDelivered, Some(Why::Expired)),
        DeliveryState::Withdrawn => (Status::NotDelivered, Some(Why::Withdrawn)),
        DeliveryState::Retired => (Status::NotDelivered, Some(Why::Retired)),
    };
    Judged {
        status,
        why,
        attempts: said.attempts,
        last_failure: said.last_failure,
    }
}

/// Asks this agent's host only while a note may still be on its way. Of a message with no record here,
/// such as a request's step, all there is to say is its host's word, so one its host can't give is the
/// host's error, as it says what to do about it.
async fn judged(
    signet: &Signet,
    id: &str,
    note: Option<&Note>,
    now: u64,
) -> Result<Judged, HostError> {
    let settled = note.is_some_and(|note| note.delivered_at.is_some() || note.ended.is_some());
    let said = if settled {
        None
    } else {
        let said = signet
            .host
            .delivery_status(&signet.key, signet.who().identity.id(), id)
            .await;
        match said {
            Err(error) if note.is_none() => return Err(error),
            said => Some(said),
        }
    };
    let judged = judge(note, said, now);
    if note.is_some()
        && judged.status == Status::NotDelivered
        && let Some(why) = judged.why
    {
        signet.sent.note_ended(id, why, now).await;
    }
    Ok(judged)
}

#[derive(Serialize)]
struct SentView {
    message_id: String,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    why: Option<Why>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivered_at: Option<u64>,
    attempts: i32,
    last_failure: Option<DeliveryFailure>,
    /// Where it went and what this agent wrote, so it can send the words again. Missing for a message
    /// sent before this Signet kept them, or one of a request.
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    /// Its words were let go to keep within this Signet's cap on them. Its record stays.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    body_dropped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sent_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
}

pub fn agent_routes() -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/sent", get(history))
        .route("/v0/sent/{message_id}", get(one))
}

/// What became of a message this agent sent: `delivered` once the reader's Signet says it opened and
/// checked it, `sending`, `held_unsent`, `at_their_host` or `quarantined` as this agent's host says
/// until then, `not_delivered` with why where this agent's host says it ended unsent, `not_confirmed`
/// where it expired with no receipt, or `unknown` with why where its host couldn't say.
async fn one(
    State(signet): State<Arc<Signet>>,
    Path(message_id): Path<String>,
) -> Result<Json<SentView>, ApiError> {
    if !message_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("not a message ID"));
    }
    let note = signet.sent.notes.lock().await.get(&message_id).cloned();
    let judged = judged(&signet, &message_id, note.as_ref(), unix_now()).await?;
    Ok(Json(SentView {
        message_id,
        status: judged.status,
        why: judged.why,
        attempts: judged.attempts,
        last_failure: judged.last_failure,
        delivered_at: note.as_ref().and_then(|note| note.delivered_at),
        sent_at: note.as_ref().map(|note| note.sent_at),
        expires_at: note.as_ref().map(|note| note.expires_at),
        to: note.as_ref().map(|note| note.to.clone()),
        body_dropped: note.as_ref().is_some_and(|note| note.body_dropped),
        body: note.filter(|note| !note.body_dropped).map(|note| note.body),
    }))
}

#[derive(Deserialize)]
struct HistoryQuery {
    /// The `more` of the page before, for the page after it.
    before: Option<String>,
}

#[derive(Serialize)]
struct HistoryLine {
    message_id: String,
    to: String,
    sent_at: u64,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    why: Option<Why>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivered_at: Option<u64>,
}

#[derive(Serialize)]
struct History {
    sent: Vec<HistoryLine>,
    /// Pass as `before` for older ones, where there are more.
    #[serde(skip_serializing_if = "Option::is_none")]
    more: Option<String>,
}

/// The notes this agent sent lately, newest first, a page at a time, each with where it stands.
async fn history(
    State(signet): State<Arc<Signet>>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<History>, ApiError> {
    let mut newest_first: Vec<(String, Note)> = signet
        .sent
        .notes
        .lock()
        .await
        .iter()
        .map(|(id, note)| (id.clone(), note.clone()))
        .collect();
    newest_first.sort_by(|a, b| (b.1.seq, b.1.sent_at, &b.0).cmp(&(a.1.seq, a.1.sent_at, &a.0)));
    let start = match &query.before {
        Some(before) => {
            newest_first
                .iter()
                .position(|(id, _)| id == before)
                .ok_or(ApiError::BadRequest(
                    "before takes a message_id from the page before",
                ))?
                + 1
        }
        None => 0,
    };
    let page: Vec<(String, Note)> = newest_first
        .into_iter()
        .skip(start)
        .take(PAGE_SIZE + 1)
        .collect();
    let more = (page.len() > PAGE_SIZE)
        .then(|| page.get(PAGE_SIZE - 1).map(|(id, _)| id.clone()))
        .flatten();
    let now = unix_now();
    let mut sent = Vec::with_capacity(PAGE_SIZE);
    for (id, note) in page.into_iter().take(PAGE_SIZE) {
        let judged = judged(&signet, &id, Some(&note), now).await?;
        sent.push(HistoryLine {
            status: judged.status,
            why: judged.why,
            delivered_at: note.delivered_at,
            message_id: id,
            to: note.to,
            sent_at: note.sent_at,
        });
    }
    Ok(Json(History { sent, more }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(expires_at: u64) -> Note {
        Note {
            to: "ben~b.example".to_owned(),
            to_agent: serde_json::from_value(serde_json::json!(format!("sp1{}", "a".repeat(52))))
                .unwrap(),
            body: "Are you free Tuesday?".to_owned(),
            body_dropped: false,
            sent_at: 0,
            seq: 0,
            expires_at,
            delivered_at: None,
            ended: None,
        }
    }

    fn host_says(status: DeliveryState) -> Option<Result<DeliveryStatus, HostError>> {
        Some(Ok(DeliveryStatus {
            status,
            attempts: 1,
            last_failure: None,
        }))
    }

    // Bug caught: a note their host took and their Signet never confirmed read as at their host for
    // good, or as failed, which had agents resend notes an older Signet had opened, while a receipt
    // that came read as less.
    #[test]
    fn a_note_their_host_took_is_not_confirmed_once_it_expires_unless_their_signet_said_so() {
        let mut kept = note(1_000);
        let before = judge(Some(&kept), host_says(DeliveryState::Delivered), 999);
        assert_eq!(before.status, Status::AtTheirHost);
        for said in [
            host_says(DeliveryState::Delivered),
            host_says(DeliveryState::Quarantined),
            Some(Err(HostError::NotFound)),
            Some(Err(HostError::Unreachable)),
        ] {
            let after = judge(Some(&kept), said, 1_000);
            assert_eq!(
                (after.status, after.why),
                (Status::NotConfirmed, Some(Why::NoReceipt))
            );
        }
        kept.delivered_at = Some(990);
        let confirmed = judge(Some(&kept), host_says(DeliveryState::Delivered), 5_000);
        assert_eq!(confirmed.status, Status::Delivered);
    }

    // Bug caught: the cap on words dropped whole records of notes still waiting, and dropped waiting
    // ones while ended ones were kept.
    #[test]
    fn the_words_cap_lets_ended_notes_words_go_first_and_never_a_record() {
        let now = 1_000;
        let big = "x".repeat(MAX_WORDS_BYTES / 2 + 1);
        let mut notes = HashMap::new();
        for (id, seq, ended) in [("a", 1, false), ("b", 2, true), ("c", 3, false)] {
            let mut kept = note(now + 100);
            kept.seq = seq;
            kept.body = big.clone();
            if ended {
                kept.delivered_at = Some(now);
            }
            notes.insert(id.to_owned(), kept);
        }
        keep_within_bounds(&mut notes, now);
        let dropped = |id: &str| notes.get(id).map(|kept| kept.body_dropped);
        assert_eq!(notes.len(), 3);
        assert_eq!(
            (dropped("a"), dropped("b"), dropped("c")),
            (Some(true), Some(true), Some(false))
        );
    }
}

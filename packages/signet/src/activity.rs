//! Something an agent, or whatever runs it, can wait on, so it hears of a step, a note or its owner's
//! word as it comes, with no polling.
//!
//! Signet never starts or wakes an agent. It answers a call that's waiting, and what happens next is
//! for whoever made it. The answer is a mark and fixed words for what changed, with nothing anyone
//! else wrote in it, so it can't carry an instruction.
//!
//! How often to wake is the runtime's call, as each answer can cost it a model run, so by default a
//! wait answers as soon as anything comes, and a runtime that wants fewer runs asks a wait to gather
//! for a while. Two agents answering each other are never slowed by Signet (Nenye, 2026-11-15).
//!
//! Only floods from senders this agent has no exchange with are capped here, as nobody the agent
//! chose should cost it a run each time they like. A sender is in an exchange when this agent wrote to
//! them in the last day, by a note, an open or a move, or wrote and hasn't heard back since. From
//! anyone else, what one sender sends within 30 seconds of what started a burst is one burst. A sender
//! starts a new burst at once a few times, and after that once every few minutes, and all of them
//! together start at most a budget of bursts an hour. What's held back answers once there's room, so
//! nothing is lost, only gathered. The owner's word is never held back. What's counted and held is
//! kept across a restart, so restarting Signet neither resets a sender's bursts nor loses what was
//! held. It's kept beside delivery, never on its way: a file that can't be written is logged, and only
//! means a restart forgets.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as ShortLock, PoisonError};
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use splint_core::{SplintId, unix_now};
use tokio::sync::{Semaphore, watch};

use crate::Signet;
use crate::agent_api::ApiError;
use crate::state_file::{self, StateError};

const DEFAULT_WAIT_SECS: u64 = 30;
/// Longer than most runtimes give a call, so it's theirs to pick.
const MAX_WAIT_SECS: u64 = 300;
/// A fooled agent could open waits until Signet runs out of room, and none of them needs more.
const MAX_WAITING: usize = 16;
/// How long after this agent last wrote to someone what they send is an exchange, never held.
/// Provisional.
const EXCHANGE_SECS: u64 = 24 * 60 * 60;
/// What a sender with no exchange sends this soon after what started a burst is part of it.
/// Provisional.
const BURST_SECS: u64 = 30;
/// Bursts a sender with no exchange can start at once, before they're held to one every
/// `REGAIN_SECS`. Provisional.
const BURSTS_AT_ONCE: u32 = 3;
const REGAIN_SECS: u64 = 3 * 60;
/// Bursts in an hour, from every sender with no exchange together. Provisional.
const WAKES_PER_HOUR: usize = 120;
const HOUR_SECS: u64 = 60 * 60;
/// Contacts whose last answer is remembered. Past this the longest quiet go, which only lets one of
/// them answer a little sooner.
const MAX_REMEMBERED: usize = 4096;
/// The one entry in the file the wakes are kept in.
const WAKES_KEY: &str = "wakes";

#[derive(Clone, Copy)]
pub enum Kind {
    /// A step arrived on a request, from a contact or a guest.
    Requests,
    /// A note arrived in the inbox.
    Messages,
    /// The owner decided, signed new rules or anything else, here or through their host.
    Owner,
}

/// What arrived from another agent, which is all that's capped. The owner's word isn't one, so it
/// can't be held back.
#[derive(Clone, Copy)]
pub enum Arrival {
    /// A step arrived on a request, from a contact or a guest.
    Requests,
    /// A note arrived in the inbox.
    Messages,
}

#[derive(Clone, Copy)]
struct Marks {
    /// When this Signet started, in milliseconds, so a mark from before a restart reads as unknown.
    first: u64,
    now: u64,
    requests: u64,
    messages: u64,
    owner: u64,
    /// The latest arrival from someone this agent wrote to and hadn't heard back from since, which a
    /// wait that gathers answers at once, as the agent may be waiting on it.
    answer: u64,
}

pub struct Activity {
    marks: watch::Sender<Marks>,
    waiting: Arc<Semaphore>,
    wakes: ShortLock<Wakes>,
    path: PathBuf,
    /// When a wait was last held, and when what waits was last read, in seconds since 1970, or 0 for
    /// not since this Signet started. Facts for the agent's own side, so they aren't kept across a
    /// restart.
    last_wait: AtomicU64,
    last_read: AtomicU64,
}

/// Whether anything is listening for this agent, as Signet sees it: facts for its own side, which
/// never go to anyone who writes to it.
#[derive(Serialize)]
pub struct Listening {
    /// A wait is held right now, as by `splint listen` or an agent's own wait.
    pub wait_held: bool,
    /// When a wait was last held, or null for not since this Signet started.
    pub last_wait_at: Option<u64>,
    /// When the inbox, the invites or the requests were last read, the same way.
    pub last_read_at: Option<u64>,
}

/// What was said for each contact, and what's held back to say.
#[derive(Default, Serialize, Deserialize)]
struct Wakes {
    by_contact: HashMap<SplintId, Batched>,
    /// When each answer for an arrival in the last hour was given.
    recent: VecDeque<u64>,
}

#[derive(Default, Serialize, Deserialize)]
struct Batched {
    /// When their latest burst started, or 0 before any.
    burst_at: u64,
    /// Bursts they can still start before they wait for one to come back, and when one last did.
    left: u32,
    regained_at: u64,
    /// This agent wrote to them after what they last sent, so their next arrival is an answer it's
    /// waiting on.
    wrote_since: bool,
    /// When this agent last wrote to them, or 0 before it has, as kept before this was.
    #[serde(default)]
    wrote_at: u64,
    requests: bool,
    messages: bool,
}

impl Batched {
    fn held(&self) -> bool {
        self.requests || self.messages
    }

    fn regain(&mut self, now: u64) {
        if self.regained_at == 0 {
            self.left = BURSTS_AT_ONCE;
            self.regained_at = now;
            return;
        }
        let back = now.saturating_sub(self.regained_at) / REGAIN_SECS;
        if back > 0 {
            let back = u32::try_from(back).unwrap_or(u32::MAX);
            self.left = self.left.saturating_add(back).min(BURSTS_AT_ONCE);
            self.regained_at = now;
        }
    }

    fn in_burst(&self, now: u64) -> bool {
        self.burst_at != 0 && now < self.burst_at.saturating_add(BURST_SECS)
    }

    /// The agent wrote to them lately, or wrote and hasn't heard back, so nothing they send is held.
    fn in_exchange(&self, now: u64) -> bool {
        self.wrote_since
            || (self.wrote_at != 0 && now < self.wrote_at.saturating_add(EXCHANGE_SECS))
    }
}

impl Wakes {
    fn trim(&mut self, now: u64) {
        while self
            .recent
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= HOUR_SECS)
        {
            self.recent.pop_front();
        }
        if self.by_contact.len() > MAX_REMEMBERED {
            let quiet = |one: &Batched| !one.held();
            let mut stale: Vec<(u64, SplintId)> = self
                .by_contact
                .iter()
                .filter(|(_, one)| quiet(one))
                .map(|(id, one)| (one.burst_at.max(one.wrote_at), id.clone()))
                .collect();
            stale.sort_by_key(|(at, _)| *at);
            let extra = self.by_contact.len().saturating_sub(MAX_REMEMBERED);
            for (_, id) in stale.into_iter().take(extra) {
                self.by_contact.remove(&id);
            }
        }
    }

    fn has_room(&self) -> bool {
        self.recent.len() < WAKES_PER_HOUR
    }

    /// How what `from` sent may answer now, if it may, and says so if it does. In an exchange it's
    /// always at once, and counts towards nothing. From anyone else it's part of their burst or a new
    /// one, which spends one of theirs and needs room in the hour's.
    fn wake(&mut self, from: &SplintId, now: u64) -> Option<Woke> {
        let room = self.has_room();
        let one = self.by_contact.entry(from.clone()).or_default();
        if one.in_exchange(now) {
            let woke = if one.wrote_since {
                Woke::Answer
            } else {
                Woke::Plain
            };
            one.wrote_since = false;
            one.requests = false;
            one.messages = false;
            return Some(woke);
        }
        one.regain(now);
        if one.in_burst(now) {
            one.requests = false;
            one.messages = false;
            return Some(Woke::Plain);
        }
        if !(room && one.left > 0) {
            return None;
        }
        one.left = one.left.saturating_sub(1);
        one.burst_at = now;
        one.requests = false;
        one.messages = false;
        self.recent.push_back(now);
        Some(Woke::Plain)
    }
}

/// How an arrival woke the agent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Woke {
    Plain,
    /// From someone the agent wrote to and hadn't heard back from since.
    Answer,
}

impl Activity {
    /// What was counted and held before a restart is read back from `path`.
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let mut saved = state_file::load::<Wakes>(&path)?;
        let wakes = saved.remove(WAKES_KEY).unwrap_or_default();
        let first = unix_now().saturating_mul(1000);
        let (marks, _) = watch::channel(Marks {
            first,
            now: first,
            requests: first,
            messages: first,
            owner: first,
            answer: first,
        });
        Ok(Self {
            marks,
            waiting: Arc::new(Semaphore::new(MAX_WAITING)),
            wakes: ShortLock::new(wakes),
            path,
            last_wait: AtomicU64::new(0),
            last_read: AtomicU64::new(0),
        })
    }

    /// The agent's side read what waits for it: its inbox, its invites or its requests.
    pub fn note_read(&self) {
        self.last_read.store(unix_now(), Ordering::Relaxed);
    }

    fn note_wait(&self) {
        self.last_wait.store(unix_now(), Ordering::Relaxed);
    }

    pub fn listening(&self) -> Listening {
        let since_start = |at: &AtomicU64| Some(at.load(Ordering::Relaxed)).filter(|at| *at != 0);
        Listening {
            wait_held: self.waiting.available_permits() < MAX_WAITING,
            last_wait_at: since_start(&self.last_wait),
            last_read_at: since_start(&self.last_read),
        }
    }

    fn wakes(&self) -> std::sync::MutexGuard<'_, Wakes> {
        self.wakes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps what's counted and held for a restart. Only facts about waking, so a file that can't be
    /// written is logged and nothing waits on it.
    fn save(&self, wakes: &Wakes) {
        let saved = HashMap::from([(WAKES_KEY, wakes)]);
        if state_file::save(&self.path, &saved).is_err() {
            tracing::warn!("couldn't save which wakes were held, so a restart may forget them");
        }
    }

    /// Something arrived from `from`: said now, or held back with what else they sent until their
    /// gap is up or the hour's budget has room, as [`Self::release_due`] says.
    pub fn arrived(&self, arrival: Arrival, from: &SplintId) {
        self.arrived_at(arrival, from, unix_now());
    }

    fn arrived_at(&self, arrival: Arrival, from: &SplintId, now: u64) {
        let mut wakes = self.wakes();
        wakes.trim(now);
        let woke = wakes.wake(from, now);
        if woke.is_none() {
            let one = wakes.by_contact.entry(from.clone()).or_default();
            match arrival {
                Arrival::Requests => one.requests = true,
                Arrival::Messages => one.messages = true,
            }
        }
        self.save(&wakes);
        drop(wakes);
        if let Some(woke) = woke {
            self.noted(
                match arrival {
                    Arrival::Requests => Kind::Requests,
                    Arrival::Messages => Kind::Messages,
                },
                woke == Woke::Answer,
            );
        }
    }

    /// This agent wrote to `to`, so it's in an exchange with them, and what they send next is an
    /// answer it may be waiting on, even from someone it never heard from before. What was held back
    /// from them is said now, as nothing of theirs is held in an exchange.
    pub fn wrote_to(&self, to: &SplintId) {
        self.wrote_to_at(to, unix_now());
    }

    fn wrote_to_at(&self, to: &SplintId, now: u64) {
        let mut wakes = self.wakes();
        let one = wakes.by_contact.entry(to.clone()).or_default();
        // Kept at most once a minute, as a busy exchange writes often and a minute moves nothing.
        if one.wrote_since && !one.held() && now.saturating_sub(one.wrote_at) < 60 {
            return;
        }
        let (requests, messages) = (one.requests, one.messages);
        one.wrote_since = true;
        one.wrote_at = now;
        one.requests = false;
        one.messages = false;
        self.save(&wakes);
        drop(wakes);
        if requests {
            self.note(Kind::Requests);
        }
        if messages {
            self.note(Kind::Messages);
        }
    }

    /// Says what was held back for each contact whose gap is up, while the hour's budget has room,
    /// those held longest first. Run every few seconds beside the agent.
    pub fn release_due(&self) {
        self.release_due_at(unix_now());
    }

    fn release_due_at(&self, now: u64) {
        let mut said = Vec::new();
        {
            let mut wakes = self.wakes();
            wakes.trim(now);
            let mut due: Vec<(u64, SplintId, bool, bool)> = wakes
                .by_contact
                .iter()
                .filter(|(_, one)| one.held())
                .map(|(id, one)| (one.burst_at, id.clone(), one.requests, one.messages))
                .collect();
            due.sort_by_key(|(at, ..)| *at);
            for (_, id, requests, messages) in due {
                if wakes.wake(&id, now).is_some() {
                    said.push((requests, messages));
                }
            }
            if !said.is_empty() {
                self.save(&wakes);
            }
        }
        for (requests, messages) in said {
            if requests {
                self.note(Kind::Requests);
            }
            if messages {
                self.note(Kind::Messages);
            }
        }
    }

    pub fn note(&self, kind: Kind) {
        self.noted(kind, false);
    }

    fn noted(&self, kind: Kind, answer: bool) {
        self.marks.send_modify(|marks| {
            marks.now = marks.now.saturating_add(1);
            match kind {
                Kind::Requests => marks.requests = marks.now,
                Kind::Messages => marks.messages = marks.now,
                Kind::Owner => marks.owner = marks.now,
            }
            if answer {
                marks.answer = marks.now;
            }
        });
    }

    pub fn now(&self) -> u64 {
        self.marks.borrow().now
    }

    pub fn owner_now(&self) -> u64 {
        self.marks.borrow().owner
    }

    /// Until the owner's word is noted after `mark`, which is what the loop beside the host listens
    /// for. What arrives from the host it hears of from the host.
    pub async fn owner_changed_from(&self, mark: u64) {
        let mut marks = self.marks.subscribe();
        // The sender lives as long as Signet, so this only ends when something changes.
        let _ = marks.wait_for(|marks| marks.owner != mark).await;
    }
}

impl Marks {
    /// What changed after `since`. A mark this Signet never gave, such as one from before a restart,
    /// could be hiding anything, so then it's everything.
    fn new_since(&self, since: u64) -> Vec<&'static str> {
        let known = (self.first..=self.now).contains(&since);
        [
            ("requests", self.requests),
            ("messages", self.messages),
            ("owner", self.owner),
        ]
        .into_iter()
        .filter(|(_, at)| !known || *at > since)
        .map(|(kind, _)| kind)
        .collect()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitBody {
    since: Option<u64>,
    seconds: Option<u64>,
    /// The runtime's own pacing: once something comes while this waits, how long to wait on for more
    /// before answering. None by default.
    gather: Option<u64>,
}

#[derive(Serialize)]
pub struct Waited {
    since: u64,
    new: Vec<&'static str>,
}

/// Returns as soon as anything changes after `since`, or from now without it, or after `seconds`.
/// An empty body waits from now for the usual time. With `gather`, what comes while it waits is
/// gathered for that many seconds before it answers, apart from the owner's word and an answer the
/// agent may be waiting on, which end it at once, as does anything already there when it's called.
pub async fn wait(
    State(signet): State<Arc<Signet>>,
    body: Bytes,
) -> Result<Json<Waited>, ApiError> {
    let body: WaitBody = if body.iter().all(u8::is_ascii_whitespace) {
        WaitBody {
            since: None,
            seconds: None,
            gather: None,
        }
    } else {
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("bad body"))?
    };
    let Ok(_waiting) = signet.activity.waiting.clone().try_acquire_owned() else {
        return Err(ApiError::TooManyWaits);
    };
    let seconds = body.seconds.unwrap_or(DEFAULT_WAIT_SECS).min(MAX_WAIT_SECS);
    let gather = body.gather.unwrap_or(0).min(MAX_WAIT_SECS);
    signet.activity.note_wait();
    let waited = signet
        .activity
        .waited(
            body.since,
            Duration::from_secs(seconds),
            Duration::from_secs(gather),
        )
        .await;
    // Again as it ends, so a wait held for minutes counts up to when it stopped being held.
    signet.activity.note_wait();
    Ok(Json(waited))
}

impl Activity {
    async fn waited(&self, since: Option<u64>, seconds: Duration, gather: Duration) -> Waited {
        let mut marks = self.marks.subscribe();
        let since = since.unwrap_or_else(|| marks.borrow().now);
        let already = marks.borrow().now != since;
        let changed = marks.wait_for(|marks| marks.now != since);
        let came = tokio::time::timeout(seconds, changed)
            .await
            .is_ok_and(|changed| changed.is_ok());
        if came && !already && !gather.is_zero() {
            let at_once = marks.wait_for(|marks| marks.owner > since || marks.answer > since);
            let _ = tokio::time::timeout(gather, at_once).await;
        }
        let marks = *marks.borrow();
        Waited {
            since: marks.now,
            new: marks.new_since(since),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Signet's wakes in a folder of this test's own, kept at the same path for a restart.
    fn at(name: &str) -> PathBuf {
        let folder =
            std::env::temp_dir().join(format!("signet-wakes-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir_all(&folder).unwrap();
        folder.join("wakes.json")
    }

    #[test]
    fn an_answer_names_only_what_changed_and_an_unknown_mark_names_everything() {
        let activity = Activity::load(at("marks")).unwrap();
        let start = activity.now();
        activity.note(Kind::Requests);
        let after_step = activity.now();
        activity.note(Kind::Owner);
        let marks = *activity.marks.borrow();
        assert_eq!(marks.new_since(start), ["requests", "owner"]);
        assert_eq!(marks.new_since(after_step), ["owner"]);
        assert!(marks.new_since(marks.now).is_empty());
        assert_eq!(
            marks.new_since(start - 1),
            ["requests", "messages", "owner"],
            "from before this Signet started"
        );
        assert_eq!(
            marks.new_since(marks.now + 1),
            ["requests", "messages", "owner"]
        );
    }

    fn id_of(n: usize) -> SplintId {
        serde_json::from_value(serde_json::Value::String(format!("splint1{n:064x}"))).unwrap()
    }

    /// Bugs caught: a burst of notes from a sender the agent never wrote to costing a runtime a run
    /// each, so fifty cost fifty; such a sender writing all day costing a run each time; what was held
    /// back never being said, so it waited until something else came; and what was held back staying
    /// held once the agent wrote to them.
    #[test]
    fn a_strangers_bursts_are_said_a_few_at_once_then_one_every_few_minutes() {
        let activity = Activity::load(at("bursts")).unwrap();
        let (ben, kit) = (id_of(0xb), id_of(0xc));
        let start = 1_793_750_400;
        let bursts = |activity: &Activity, from: &SplintId, at: u64| {
            let before = activity.wakes().recent.len();
            for second in 0..50 {
                activity.arrived_at(Arrival::Messages, from, at + second % BURST_SECS);
            }
            activity.wakes().recent.len() - before
        };
        assert_eq!(
            bursts(&activity, &ben, start),
            1,
            "fifty notes in one burst are one"
        );
        assert_eq!(bursts(&activity, &ben, start + 40), 1);
        assert_eq!(bursts(&activity, &ben, start + 80), 1);
        assert_eq!(
            bursts(&activity, &ben, start + 120),
            0,
            "past a few, ben waits"
        );
        assert_eq!(
            bursts(&activity, &kit, start + 120),
            1,
            "kit isn't held back by ben"
        );
        let said = activity.now();
        activity.release_due_at(start + REGAIN_SECS - 1);
        assert_eq!(activity.now(), said, "nothing more until one comes back");
        activity.release_due_at(start + REGAIN_SECS);
        assert_eq!(
            activity.now(),
            said + 1,
            "what ben sent is said once one comes back"
        );
        assert_eq!(
            bursts(&activity, &ben, start + REGAIN_SECS + BURST_SECS),
            0,
            "then he waits again"
        );
        let said = activity.now();
        activity.wrote_to_at(&ben, start + REGAIN_SECS + 2 * BURST_SECS);
        assert_eq!(
            activity.now(),
            said + 1,
            "once the agent writes to ben, what he sent is said"
        );
    }

    /// Bug caught: an agent's contact sending a follow-up in each turn, more than half a minute after
    /// their answer, spent a burst each time, so from the fourth turn on their follow-up waited three
    /// minutes, though the agent was in the middle of talking to them.
    #[test]
    fn an_exchange_is_never_held_however_many_turns_it_takes() {
        let activity = Activity::load(at("exchange")).unwrap();
        let ben = id_of(0xb);
        let start = 1_793_750_400;
        for turn in 0..20 {
            let at = start + turn * 90;
            activity.wrote_to_at(&ben, at);
            for (after, arrival) in [(20, Arrival::Messages), (60, Arrival::Requests)] {
                let said = activity.now();
                activity.arrived_at(arrival, &ben, at + after);
                assert_eq!(activity.now(), said + 1, "turn {turn}, {after} s in");
            }
        }
        let said = activity.now();
        let a_day_on = start + 20 * 90 + EXCHANGE_SECS;
        for burst in 0..=u64::from(BURSTS_AT_ONCE) {
            activity.arrived_at(Arrival::Messages, &ben, a_day_on + burst * BURST_SECS);
        }
        assert_eq!(
            activity.now(),
            said + u64::from(BURSTS_AT_ONCE),
            "control: a day after the agent last wrote, ben is capped as anyone is"
        );
    }

    /// Bug caught: a wait that gathers holding back what the agent is waiting on, its owner's word or
    /// an answer to what it wrote, as long as it holds back a stranger's note.
    #[tokio::test]
    async fn a_wait_that_gathers_ends_at_once_for_an_answer() {
        let activity = Arc::new(Activity::load(at("gather")).unwrap());
        let (ben, kit) = (id_of(0xb), id_of(0xc));
        let since = activity.now();
        let waiting = tokio::spawn({
            let activity = activity.clone();
            async move {
                activity
                    .waited(
                        Some(since),
                        Duration::from_secs(60),
                        Duration::from_secs(60),
                    )
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        activity.arrived(Arrival::Messages, &kit);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "a stranger's note is gathered");
        activity.wrote_to(&ben);
        activity.arrived(Arrival::Messages, &ben);
        let waited = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(waited.new, ["messages"]);
        assert_eq!(waited.since, activity.now());
    }

    /// Bugs caught: a restart giving every contact its bursts back, so restarting Signet, which a
    /// crash or an update does, let a flood through at a run each; and what was held back before it
    /// lost, so it waited until something else came.
    #[test]
    fn a_restart_neither_resets_a_contacts_bursts_nor_loses_what_was_held() {
        let path = at("restart");
        let ben = id_of(0xb);
        let start = 1_793_750_400;
        let before = {
            let activity = Activity::load(path.clone()).unwrap();
            for burst in 0..=u64::from(BURSTS_AT_ONCE) {
                activity.arrived_at(Arrival::Messages, &ben, start + burst * BURST_SECS);
            }
            activity.wakes().recent.len()
        };
        assert_eq!(
            before, BURSTS_AT_ONCE as usize,
            "control: the last was held"
        );
        let activity = Activity::load(path).unwrap();
        let said = activity.now();
        activity.arrived_at(Arrival::Messages, &ben, start + 5 * BURST_SECS);
        assert_eq!(activity.now(), said, "after a restart ben still waits");
        activity.release_due_at(start + REGAIN_SECS);
        assert_eq!(
            activity.now(),
            said + 1,
            "and what he sent before it is said once one comes back"
        );
    }

    #[test]
    fn the_hours_budget_holds_what_comes_from_everyone_past_it_until_there_is_room() {
        let activity = Activity::load(at("hour")).unwrap();
        let start = 1_793_750_400;
        let before = activity.now();
        let many: Vec<SplintId> = (0..=WAKES_PER_HOUR).map(id_of).collect();
        for one in &many {
            activity.arrived_at(Arrival::Messages, one, start);
        }
        assert_eq!(activity.now(), before + WAKES_PER_HOUR as u64);
        activity.release_due_at(start + HOUR_SECS);
        assert_eq!(
            activity.now(),
            before + WAKES_PER_HOUR as u64 + 1,
            "the last is said once there's room"
        );
    }

    /// Bug caught: a hundred and twenty throwaway senders, one note each, spending the hour's wakes,
    /// so the answer the agent was waiting on, to what it wrote, wasn't said for an hour. That holds for
    /// someone the agent wrote to first, before hearing anything from them.
    #[test]
    fn strangers_spending_the_hour_dont_hold_back_an_answer_the_agent_waits_on() {
        let activity = Activity::load(at("answers")).unwrap();
        let start = 1_793_750_400;
        let (ben, kit) = (id_of(0xffff), id_of(0xfffe));
        activity.arrived_at(Arrival::Requests, &ben, start - 600);
        activity.wrote_to(&ben);
        activity.wrote_to(&kit);
        for n in 0..WAKES_PER_HOUR {
            activity.arrived_at(Arrival::Messages, &id_of(n), start + 1);
        }
        let said = activity.now();
        activity.arrived_at(Arrival::Messages, &id_of(WAKES_PER_HOUR), start + 5);
        assert_eq!(activity.now(), said, "control: the hour is spent");
        activity.arrived_at(Arrival::Requests, &ben, start + 10);
        assert_eq!(activity.now(), said + 1, "ben's answer is said at once");
        activity.arrived_at(Arrival::Messages, &kit, start + 10);
        assert_eq!(
            activity.now(),
            said + 2,
            "and kit's, who was written to first"
        );
    }

    #[tokio::test]
    async fn the_loop_beside_the_host_hears_the_owner_and_not_what_it_noted_itself() {
        let activity = Arc::new(Activity::load(at("owner")).unwrap());
        let mark = activity.owner_now();
        let waiting = tokio::spawn({
            let activity = activity.clone();
            async move { activity.owner_changed_from(mark).await }
        });
        activity.note(Kind::Requests);
        activity.note(Kind::Messages);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished());
        activity.note(Kind::Owner);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
    }
}

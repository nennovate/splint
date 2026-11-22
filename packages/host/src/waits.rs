//! Lets an agent's Signet hear as soon as something comes for it, instead of asking every few seconds.
//!
//! A Signet calls with the mark from its last answer. If anything has come for its agent since, the
//! answer is at once. If not, the call is held until something does, a step it put off comes back, or
//! 25 seconds pass, which is under every deadline between it and the Signet. A held call has done its
//! work, so it gives back its place among the calls in progress, and has limits of its own instead:
//! two for one agent, half the total for one source, and a total for the host. Past those it's
//! refused, and the Signet asks as before, so a flood of them can cost an agent its quick news and
//! nothing else.
//!
//! The answer says only that there may be something to read. Signet goes by what it reads after, so a
//! host that wakes it for nothing, or never, can make it slower and can't make it believe anything.
//! Postgres says when something has come: a trigger on each table that takes something for an agent
//! notifies once the row is committed, so no way of adding a row, now or later, can forget to wake
//! anyone. Marks live in this process, which is the whole host. After a restart, or while it can't
//! hear Postgres, every mark is new, and each Signet looks once.
//!
//! An agent's mark counts only what came for that agent, and steps its Signet put off coming back into
//! sight, from a starting point picked at random, so the difference between two of its marks says
//! nothing about anyone else's traffic, and a mark says nothing about when the host started.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use splint_core::SplintId;
use splint_core::host_api::{WAIT_PATH, WaitAnswer, WaitRequest};
use sqlx::postgres::PgListener;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::api_error::ApiError;
use crate::overload::CallPlace;
use crate::{Host, inbox, registry};

/// Under the 30 seconds a call has here, the 40 the proxy waits for an answer and the 45 a connection
/// has for a request, so a held call always ends with an answer. One a minute was the plan's sum, and
/// this is a little over two, at about the cost of an empty look each.
pub const HOLD: Duration = Duration::from_secs(25);
/// A wait says one number. A held call keeps its body's room among those held for as long as it's
/// held, so a padded one would take that room from everyone for the price of a call.
const MAX_WAIT_BYTES: usize = 256;
/// Room for a Signet that's restarting while its last call is still held. More would let a captured
/// proof, replayed, take more of the total.
pub const HELD_PER_AGENT: usize = 2;

const CHANNEL: &str = "splint_wake";
/// Before trying Postgres again, after it couldn't be heard.
const LISTEN_AGAIN_AFTER: Duration = Duration::from_secs(1);

/// What comes for an agent: a message in its inbox, from a delivery or out of quarantine, what its
/// owner left it, and a guest's step on one of its links. Each wakes it once the row is committed.
pub const SCHEMA: &str = "
    CREATE OR REPLACE FUNCTION splint_wake_inbox() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        PERFORM pg_notify('splint_wake', NEW.recipient);
        RETURN NULL;
    END $$;
    CREATE OR REPLACE FUNCTION splint_wake_owner_mail() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        PERFORM pg_notify('splint_wake', NEW.agent_id);
        RETURN NULL;
    END $$;
    CREATE OR REPLACE FUNCTION splint_wake_guest_step() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.from_guest THEN
            PERFORM pg_notify('splint_wake', agent) FROM guest_links WHERE request_id = NEW.request_id;
        END IF;
        RETURN NULL;
    END $$;
    DROP TRIGGER IF EXISTS splint_wake ON inbox;
    CREATE TRIGGER splint_wake AFTER INSERT ON inbox
        FOR EACH ROW EXECUTE FUNCTION splint_wake_inbox();
    DROP TRIGGER IF EXISTS splint_wake ON owner_mail;
    CREATE TRIGGER splint_wake AFTER INSERT ON owner_mail
        FOR EACH ROW EXECUTE FUNCTION splint_wake_owner_mail();
    DROP TRIGGER IF EXISTS splint_wake ON guest_steps;
    CREATE TRIGGER splint_wake AFTER INSERT ON guest_steps
        FOR EACH ROW EXECUTE FUNCTION splint_wake_guest_step();
";

/// Hears from Postgres what has come for whom, for as long as the host runs.
pub async fn run_listener(host: Arc<Host>) {
    loop {
        match PgListener::connect_with(&host.db).await {
            Ok(mut listener) => match listener.listen(CHANNEL).await {
                Ok(()) => hear(&host, &mut listener).await,
                Err(error) => tracing::warn!(%error, "couldn't listen for what comes for agents"),
            },
            Err(error) => tracing::warn!(%error, "couldn't listen for what comes for agents"),
        }
        tokio::time::sleep(LISTEN_AGAIN_AFTER).await;
    }
}

async fn hear(host: &Host, listener: &mut PgListener) {
    // Anything that came before this was listening woke nobody.
    host.waits.wake_everyone();
    loop {
        match listener.try_recv().await {
            Ok(Some(notice)) => {
                let named = serde_json::Value::String(notice.payload().to_owned());
                if let Ok(agent) = serde_json::from_value::<SplintId>(named) {
                    host.waits.wake(&agent);
                }
            }
            // The connection went, and comes back on the next call, with nothing that came meanwhile.
            Ok(None) => host.waits.wake_everyone(),
            Err(error) => {
                tracing::warn!(%error, "lost what comes for agents");
                return;
            }
        }
    }
}

pub fn routes() -> Router<Arc<Host>> {
    Router::new().route(WAIT_PATH, post(wait))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Full {
    Agent,
    Source,
    Host,
}

pub struct Waits {
    inner: Mutex<Inner>,
    most: usize,
}

struct Inner {
    /// What an agent nothing has come for is at. It's picked afresh at start and whenever every mark
    /// moves, so a mark from before is almost never one that's still current.
    first: u64,
    /// Only agents something came for, which only an agent here can be. Each counts up from `first`
    /// by what came for it alone.
    latest: HashMap<SplintId, u64>,
    held: HashMap<SplintId, Vec<(u64, Arc<Notify>)>>,
    holding: usize,
    /// Only sources holding a call now, by what `registry::source_of` reads.
    from_source: HashMap<String, usize>,
    next_hold: u64,
}

/// Not a secret: a mark only has to say nothing about the host and not come round again. Below 2^52,
/// so counting up from it can't wrap and any JSON reader keeps it exact.
fn fresh_first() -> u64 {
    RandomState::new().hash_one(()) >> 12
}

impl Waits {
    pub fn new(most: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                first: fresh_first(),
                latest: HashMap::new(),
                held: HashMap::new(),
                holding: 0,
                from_source: HashMap::new(),
                next_hold: 0,
            }),
            most,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Where this agent is now. It changes each time something comes for it.
    pub fn mark(&self, agent: &SplintId) -> u64 {
        let inner = self.lock();
        inner.latest.get(agent).copied().unwrap_or(inner.first)
    }

    /// Something came for this agent: anything held for it answers, and the next call sees a new mark.
    /// Postgres says so only once what came is committed, so a Signet that looks then finds it.
    pub fn wake(&self, agent: &SplintId) {
        let mut inner = self.lock();
        let mark = inner
            .latest
            .get(agent)
            .copied()
            .unwrap_or(inner.first)
            .wrapping_add(1);
        inner.latest.insert(agent.clone(), mark);
        for (_, woken) in inner.held.get(agent).into_iter().flatten() {
            // Kept for one that hasn't started waiting yet, so a wake in between isn't lost.
            woken.notify_one();
        }
    }

    /// What this agent's Signet put off changed, so a call held for it works out again when to end,
    /// and nothing has come, so its mark stays.
    pub fn rehold(&self, agent: &SplintId) {
        let inner = self.lock();
        for (_, woken) in inner.held.get(agent).into_iter().flatten() {
            woken.notify_one();
        }
    }

    /// For when something may have come unheard: every mark moves, so each Signet looks once.
    pub fn wake_everyone(&self) {
        let mut inner = self.lock();
        inner.first = fresh_first();
        inner.latest.clear();
        for (_, woken) in inner.held.values().flatten() {
            woken.notify_one();
        }
    }

    /// A place among those held, which goes when this is dropped, however the call ends. A call with
    /// no source didn't come through the proxy, so as in `overload` it counts only towards the total.
    pub fn hold(&self, agent: &SplintId, source: &str) -> Result<Held<'_>, Full> {
        let mut inner = self.lock();
        let already = inner.held.get(agent).map_or(0, Vec::len);
        if already >= HELD_PER_AGENT {
            return Err(Full::Agent);
        }
        if inner.holding >= self.most {
            return Err(Full::Host);
        }
        // One source with many agents could otherwise take every place, and every other Signet would
        // be back to asking every few seconds.
        let share = (self.most / 2).max(1);
        if !source.is_empty() {
            let from_source = inner.from_source.entry(source.to_owned()).or_default();
            if *from_source >= share {
                return Err(Full::Source);
            }
            *from_source += 1;
        }
        inner.next_hold = inner.next_hold.wrapping_add(1);
        let id = inner.next_hold;
        let woken = Arc::new(Notify::new());
        inner
            .held
            .entry(agent.clone())
            .or_default()
            .push((id, woken.clone()));
        inner.holding += 1;
        Ok(Held {
            waits: self,
            agent: agent.clone(),
            source: source.to_owned(),
            id,
            woken,
        })
    }

    #[cfg(test)]
    fn holding(&self) -> usize {
        self.lock().holding
    }
}

pub struct Held<'a> {
    waits: &'a Waits,
    agent: SplintId,
    source: String,
    id: u64,
    woken: Arc<Notify>,
}

impl Held<'_> {
    /// Until something comes for this agent after this place was taken.
    pub async fn woken(&self) {
        self.woken.notified().await;
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let mut inner = self.waits.lock();
        if let Some(held) = inner.held.get_mut(&self.agent) {
            held.retain(|(id, _)| *id != self.id);
            if held.is_empty() {
                inner.held.remove(&self.agent);
            }
        }
        inner.holding = inner.holding.saturating_sub(1);
        if let Some(from_source) = inner.from_source.get_mut(&self.source) {
            *from_source = from_source.saturating_sub(1);
            if *from_source == 0 {
                inner.from_source.remove(&self.source);
            }
        }
    }
}

/// How long to hold a wait, and whether it ends with something to see, given when the next step put
/// off comes back into sight and how much of the hold is `left`. One due just as the hold ends is in
/// sight then, and the next wait won't count it, as it's no longer put off.
fn hold_for(due: Option<Duration>, left: Duration) -> (Duration, bool) {
    match due {
        Some(due) if due <= left => (due, true),
        _ => (left, false),
    }
}

async fn wait(
    State(host): State<Arc<Host>>,
    place: Option<Extension<CallPlace>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<WaitAnswer>, ApiError> {
    if body.len() > MAX_WAIT_BYTES {
        return Err(ApiError::BadRequest("bad body"));
    }
    let agent = inbox::authenticated_agent(&host, &headers, "POST", WAIT_PATH, &body).await?;
    let asked: WaitRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("bad body"))?;
    // Taken before the mark is read, so whatever comes after the read wakes this.
    let source = registry::source_of(&headers);
    let held = host
        .waits
        .hold(&agent, &source)
        .map_err(|full| match full {
            Full::Agent => ApiError::TooMany("this agent is already waiting"),
            Full::Source => ApiError::TooMany("too many waits from here"),
            Full::Host => ApiError::Unavailable,
        })?;
    let mark = host.waits.mark(&agent);
    if asked.since != Some(mark) {
        return Ok(Json(WaitAnswer {
            since: mark,
            new: true,
        }));
    }
    let ends = Instant::now() + HOLD;
    let mut due = inbox::next_put_off_due(&host, &agent).await?;
    if let Some(Extension(place)) = place {
        place.give_back();
    }
    let new = loop {
        let (hold, comes_due) = hold_for(due, ends.saturating_duration_since(Instant::now()));
        if tokio::time::timeout(hold, held.woken()).await.is_err() {
            break comes_due;
        }
        if host.waits.mark(&agent) != mark {
            break true;
        }
        // Only what Signet put off changed, which it may have done while this was held.
        due = inbox::next_put_off_due(&host, &agent).await?;
    };
    Ok(Json(WaitAnswer {
        since: host.waits.mark(&agent),
        new,
    }))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use tokio::net::TcpListener;

    use super::*;
    use crate::limits::Limits;
    use crate::overload::{CallGuard, limit_calls};

    fn agent(name: &str) -> SplintId {
        serde_json::from_value(serde_json::Value::String(format!("splint1{name}"))).unwrap()
    }

    #[tokio::test]
    async fn a_wake_reaches_what_is_held_and_moves_the_mark() {
        let waits = Waits::new(8);
        let ana = agent("ana");
        let before = waits.mark(&ana);
        let held = waits.hold(&ana, "").unwrap();
        waits.wake(&agent("ben"));
        assert_eq!(
            waits.mark(&ana),
            before,
            "only ana's own news moves her mark"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), held.woken())
                .await
                .is_err()
        );
        waits.wake(&ana);
        assert_ne!(waits.mark(&ana), before);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), held.woken())
                .await
                .is_ok(),
            "a wake before the wait started still counts"
        );
    }

    #[tokio::test]
    async fn after_a_gap_in_what_was_heard_every_mark_moves_and_everything_held_answers() {
        let waits = Waits::new(8);
        let (ana, ben) = (agent("ana"), agent("ben"));
        waits.wake(&ana);
        let before = (waits.mark(&ana), waits.mark(&ben));
        let held = waits.hold(&ben, "").unwrap();
        waits.wake_everyone();
        assert_ne!(waits.mark(&ana), before.0);
        assert_ne!(waits.mark(&ben), before.1, "even one nothing came for");
        assert!(
            tokio::time::timeout(Duration::from_secs(1), held.woken())
                .await
                .is_ok()
        );
    }

    #[test]
    fn an_agent_gets_two_a_source_half_and_the_host_its_total_and_each_comes_back() {
        let waits = Waits::new(4);
        let (ana, ben, carol) = (agent("ana"), agent("ben"), agent("carol"));
        let first = waits.hold(&ana, "198.51.100.1").unwrap();
        let _second = waits.hold(&ana, "").unwrap();
        assert_eq!(waits.hold(&ana, "").err(), Some(Full::Agent));
        let _third = waits.hold(&ben, "198.51.100.1").unwrap();
        assert_eq!(
            waits.hold(&carol, "198.51.100.1").err(),
            Some(Full::Source),
            "one source with many agents can't take every place"
        );
        let _fourth = waits.hold(&carol, "198.51.100.2").unwrap();
        assert_eq!(waits.hold(&agent("dan"), "").err(), Some(Full::Host));
        drop(first);
        assert_eq!(waits.holding(), 3);
        assert!(waits.hold(&carol, "198.51.100.1").is_ok());
    }

    /// Review of PR 593: one due exactly as the hold ended was answered as nothing new, and the
    /// next wait no longer counted it, so it waited for a look up to 5 minutes later.
    #[test]
    fn a_step_due_just_as_a_hold_ends_still_says_there_is_something() {
        assert_eq!(hold_for(Some(HOLD), HOLD), (HOLD, true));
        assert!(hold_for(Some(Duration::from_secs(2)), HOLD).1);
        assert_eq!(
            hold_for(Some(HOLD + Duration::from_secs(1)), HOLD),
            (HOLD, false)
        );
        assert_eq!(hold_for(None, HOLD), (HOLD, false));
    }

    /// A real server with the real guard in front, and a route that holds as the wait does.
    async fn serving(limits: &Limits, waits: Arc<Waits>) -> SocketAddr {
        let held = waits.clone();
        let app = Router::new()
            .route(
                "/hold/{name}",
                get(
                    move |axum::extract::Path(name): axum::extract::Path<String>,
                          Extension(place): Extension<CallPlace>| {
                        let waits = held.clone();
                        async move {
                            let Ok(held) = waits.hold(&agent(&name), "") else {
                                return axum::http::StatusCode::TOO_MANY_REQUESTS;
                            };
                            place.give_back();
                            let _ =
                                tokio::time::timeout(Duration::from_secs(20), held.woken()).await;
                            axum::http::StatusCode::OK
                        }
                    },
                ),
            )
            .route("/fast", get(|| async { "answered" }))
            .layer(from_fn_with_state(
                Arc::new(CallGuard::new(limits, 1024)),
                limit_calls,
            ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        address
    }

    /// The status a call is answered with. A busy machine can drop a connection before the server
    /// sees it: macOS lets only 128 wait to be accepted and resets the rest, and local ports run out.
    /// Neither is the host, and every answer the host gives is a status, so the call goes again.
    async fn status_of(client: &reqwest::Client, url: &str) -> u16 {
        loop {
            match client.get(url).send().await {
                Ok(answer) => return answer.status().as_u16(),
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn far_more_held_than_calls_at_once_leaves_the_host_answering_and_the_total_holds() {
        const AGENTS: usize = 600;
        // Each held call is a connection at both ends here.
        rlimit::increase_nofile_limit(u64::MAX).unwrap();
        let limits = Limits {
            calls_at_once: 16,
            ..Limits::for_tests()
        };
        let waits = Arc::new(Waits::new(AGENTS));
        let address = serving(&limits, waits.clone()).await;
        let client = reqwest::Client::new();
        let mut holding = Vec::new();
        for number in 0..AGENTS {
            let client = client.clone();
            holding.push(tokio::spawn(async move {
                status_of(&client, &format!("http://{address}/hold/{number}")).await
            }));
        }
        // A deadline only for a hang: a loaded machine can take far longer than usual to connect 600,
        // and the check is that every one is held, not how fast.
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        while waits.holding() < AGENTS && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(waits.holding(), AGENTS, "every one is held at once");
        assert_eq!(
            status_of(&client, &format!("http://{address}/fast")).await,
            200,
            "and other calls still get through"
        );
        assert_eq!(
            status_of(&client, &format!("http://{address}/hold/one-more")).await,
            429,
            "past the total"
        );
        for number in 0..AGENTS {
            waits.wake(&agent(&number.to_string()));
        }
        for held in holding {
            assert_eq!(held.await.unwrap(), 200);
        }
        assert_eq!(waits.holding(), 0, "every place came back");
    }
}

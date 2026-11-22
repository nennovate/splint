//! Limits on calls before anything is read, so that verifying signatures for strangers can't stop a host.
//!
//! Per-agent limits only start once a signature checks out, so anyone can make a host do that work.
//! Past these limits a call is refused at once with a retry, rather than waiting until every caller
//! times out, which is what happens with no limit at all. A sending host treats that as busy and tries
//! again, and nothing is lost.
//!
//! A call waiting for its body costs a source its own share and does no work, so it doesn't take a
//! place among the calls in progress, or a few callers sending nothing could fill those for everyone.
//! Bodies are read here, against a deadline and a limit on how much is held, in all and from one
//! source, and only a whole request goes on to take a place. What's held is counted as it's set
//! aside and until the call ends, so with what a connection reads ahead, in `connections`, it's what
//! callers can make a host hold before a route has seen anything. What a route answers with has room
//! of its own, in `answers`.
//!
//! A call that only waits, once it's checked, gives its places back while it waits, through the
//! `CallPlace` it's handed, so held calls can't take room from calls doing work. They have limits of
//! their own, in `waits`.
//!
//! A source is what `registry::source_of` reads, the proxy's word for where a call came from. A call
//! with no such word didn't come through the proxy, so it's from this machine or a test setup, and
//! it counts only towards the total. A host with other machines' traffic listens only on loopback.

use std::collections::HashMap;
use std::future::poll_fn;
use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Json;
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::RETRY_AFTER;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::limits::Limits;
use crate::registry;

/// As long as a client's answer is worth waiting for. A call past this is cancelled, as if its caller had
/// hung up, which the handlers already have to survive.
const CALL_DEADLINE: Duration = Duration::from_secs(30);
/// Plenty for the largest body on a slow line, and a caller holding one back has its own share to spend.
const BODY_DEADLINE: Duration = Duration::from_secs(10);
/// Enough sources for a very busy host. Past this a new source waits for an old one to go quiet.
const MAX_SOURCES: usize = 65_536;
const SWEEP_EVERY: Duration = Duration::from_secs(1);
/// How many seconds' worth of calls can come at once, so a burst isn't taken for a flood.
const BURST_SECS: f64 = 2.0;

pub struct CallGuard {
    total: Arc<Semaphore>,
    body_room: Arc<Semaphore>,
    body_bytes_per_source: usize,
    sources: Mutex<Sources>,
    at_once_per_source: usize,
    per_second: f64,
    max_body_bytes: usize,
    body_deadline: Duration,
}

struct Sources {
    seen: HashMap<String, Source>,
    swept_at: Instant,
}

struct Source {
    calls_left: f64,
    refilled_at: Instant,
    at_once: usize,
    /// Of bodies held now. A call that gives its place back still holds its body.
    body_bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum Over {
    SourceLimit,
    TooManySources,
}

fn as_count(limit: u32) -> usize {
    usize::try_from(limit).unwrap_or(usize::MAX)
}

impl CallGuard {
    pub fn new(limits: &Limits, max_body_bytes: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(as_count(limits.calls_at_once))),
            body_room: Arc::new(Semaphore::new(as_count(limits.body_bytes_at_once))),
            body_bytes_per_source: as_count(limits.body_bytes_at_once_per_source),
            max_body_bytes,
            body_deadline: BODY_DEADLINE,
            sources: Mutex::new(Sources {
                seen: HashMap::new(),
                swept_at: Instant::now(),
            }),
            at_once_per_source: as_count(limits.calls_at_once_per_source),
            per_second: f64::from(limits.calls_per_source_per_second),
        }
    }

    fn enter(&self, source: &str, now: Instant) -> Result<(), Over> {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        if sources.seen.len() >= MAX_SOURCES && !sources.seen.contains_key(source) {
            sources.sweep(self.per_second, now);
            if sources.seen.len() >= MAX_SOURCES {
                return Err(Over::TooManySources);
            }
        }
        let burst = self.per_second * BURST_SECS;
        let entry = sources.seen.entry(source.to_owned()).or_insert(Source {
            calls_left: burst,
            refilled_at: now,
            at_once: 0,
            body_bytes: 0,
        });
        let waited = now.duration_since(entry.refilled_at).as_secs_f64();
        entry.calls_left = (entry.calls_left + waited * self.per_second).min(burst);
        entry.refilled_at = now;
        if entry.at_once >= self.at_once_per_source || entry.calls_left < 1.0 {
            return Err(Over::SourceLimit);
        }
        entry.calls_left -= 1.0;
        entry.at_once += 1;
        Ok(())
    }

    fn leave(&self, source: &str) {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = sources.seen.get_mut(source) {
            entry.at_once = entry.at_once.saturating_sub(1);
        }
    }
}

impl Sources {
    /// Forgets a source once it's idle and its allowance is whole, as a new entry would be the same.
    /// At most once a second, so a flood of new sources can't make every call walk the whole map.
    fn sweep(&mut self, per_second: f64, now: Instant) {
        if now.duration_since(self.swept_at) < SWEEP_EVERY {
            return;
        }
        self.swept_at = now;
        self.seen.retain(|_, source| {
            let waited = now.duration_since(source.refilled_at).as_secs_f64();
            source.at_once > 0
                || source.body_bytes > 0
                || waited * per_second < per_second * BURST_SECS
        });
    }
}

/// Gives a source's place back however the call ends, including when its caller hangs up.
struct InFlight {
    guard: Arc<CallGuard>,
    source: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.guard.leave(&self.source);
    }
}

/// A call's places among those in progress, in all and from its source. They go when the call ends,
/// or sooner if it gives them back.
#[derive(Clone)]
pub struct CallPlace(Arc<Mutex<Option<Places>>>);

struct Places {
    _total: OwnedSemaphorePermit,
    _source: Option<InFlight>,
}

impl CallPlace {
    /// For a call that's done its work and only waits now, so it no longer counts among those working.
    pub fn give_back(&self) {
        let places = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        drop(places);
    }
}

fn refused(status: StatusCode) -> Response {
    let words = Json(json!({"error": "couldn't read that request"}));
    (status, words).into_response()
}

/// What a caller past a limit is told, whichever limit: to come back in a second.
pub fn busy(status: StatusCode) -> Response {
    (
        status,
        [(RETRY_AFTER, "1")],
        Json(json!({"error": "try again"})),
    )
        .into_response()
}

#[derive(Debug, PartialEq, Eq)]
enum NoBody {
    TooLarge,
    TooMuchHeld,
    SourceHoldsTooMuch,
    /// The caller hung up, or the framing was wrong.
    Unreadable,
}

/// What a call's body takes of the room, in all and of its source's share. It goes when the call
/// ends, however that is.
struct HeldBody {
    guard: Arc<CallGuard>,
    source: String,
    bytes: usize,
    in_all: Option<OwnedSemaphorePermit>,
}

impl HeldBody {
    fn more(&mut self, bytes: usize) -> Result<(), NoBody> {
        let asked = u32::try_from(bytes).map_err(|_| NoBody::TooLarge)?;
        let mut sources = self
            .guard
            .sources
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // It's there for a call that has a source: the call came in through it, and one with a call or
        // a body is never swept. Its own share goes first, so a source over it hears that it's the one.
        let mut source = sources.seen.get_mut(&self.source);
        if let Some(source) = &source
            && source.body_bytes + bytes > self.guard.body_bytes_per_source
        {
            return Err(NoBody::SourceHoldsTooMuch);
        }
        let room = self.guard.body_room.clone();
        let place = room
            .try_acquire_many_owned(asked)
            .map_err(|_| NoBody::TooMuchHeld)?;
        if let Some(source) = &mut source {
            source.body_bytes += bytes;
        }
        self.bytes += bytes;
        match &mut self.in_all {
            Some(all) => all.merge(place),
            None => self.in_all = Some(place),
        }
        Ok(())
    }
}

impl Drop for HeldBody {
    fn drop(&mut self) {
        if self.bytes == 0 || self.source.is_empty() {
            return;
        }
        let mut sources = self
            .guard
            .sources
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(source) = sources.seen.get_mut(&self.source) {
            source.body_bytes = source.body_bytes.saturating_sub(self.bytes);
        }
    }
}

/// The whole body, with room taken for it in `held` before each part is kept.
async fn read_body(body: Body, held: &mut HeldBody, limit: usize) -> Result<Bytes, NoBody> {
    if body.size_hint().exact() == Some(0) {
        return Ok(Bytes::new());
    }
    // How long it says it is, when it says.
    let most = body
        .size_hint()
        .upper()
        .map_or(limit, |size| usize::try_from(size).unwrap_or(usize::MAX));
    if most > limit {
        return Err(NoBody::TooLarge);
    }
    let mut body = pin!(body);
    let mut read = Vec::new();
    while let Some(frame) = poll_fn(|context| body.as_mut().poll_frame(context)).await {
        let Ok(data) = frame.map_err(|_| NoBody::Unreadable)?.into_data() else {
            continue;
        };
        let whole = read.len() + data.len();
        if whole > limit {
            return Err(NoBody::TooLarge);
        }
        if whole > read.capacity() {
            // Room is taken for what's set aside, not for what has come, so the count is what this
            // really holds. An eighth more each time, up to the body's length, so one that comes in
            // small parts isn't copied once a part, and a caller never takes much more room than it
            // has sent: twice as much each time let anyone fill the room by sending half of it.
            let ahead = read.capacity() / 8;
            let grown = whole.max((read.capacity() + ahead).min(most));
            held.more(grown - read.capacity())?;
            read.reserve_exact(grown - read.len());
        }
        read.extend_from_slice(&data);
    }
    Ok(read.into())
}

pub async fn limit_calls(
    State(guard): State<Arc<CallGuard>>,
    request: Request,
    next: Next,
) -> Response {
    let source = registry::source_of(request.headers());
    let mut held = HeldBody {
        guard: guard.clone(),
        source: source.clone(),
        bytes: 0,
        in_all: None,
    };
    let in_flight = if source.is_empty() {
        None
    } else {
        if guard.enter(&source, Instant::now()).is_err() {
            return busy(StatusCode::TOO_MANY_REQUESTS);
        }
        Some(InFlight {
            guard: guard.clone(),
            source,
        })
    };
    let (parts, body) = request.into_parts();
    let reading = read_body(body, &mut held, guard.max_body_bytes);
    let body = match tokio::time::timeout(guard.body_deadline, reading).await {
        Ok(Ok(read)) => read,
        Ok(Err(NoBody::TooLarge)) => return refused(StatusCode::PAYLOAD_TOO_LARGE),
        Ok(Err(NoBody::TooMuchHeld)) => return busy(StatusCode::SERVICE_UNAVAILABLE),
        Ok(Err(NoBody::SourceHoldsTooMuch)) => return busy(StatusCode::TOO_MANY_REQUESTS),
        Ok(Err(NoBody::Unreadable)) => return refused(StatusCode::BAD_REQUEST),
        Err(_) => return busy(StatusCode::REQUEST_TIMEOUT),
    };
    let Ok(permit) = guard.total.clone().try_acquire_owned() else {
        return busy(StatusCode::SERVICE_UNAVAILABLE);
    };
    let place = CallPlace(Arc::new(Mutex::new(Some(Places {
        _total: permit,
        _source: in_flight,
    }))));
    let mut request = Request::from_parts(parts, Body::from(body));
    request.extensions_mut().insert(place.clone());
    match tokio::time::timeout(CALL_DEADLINE, next.run(request)).await {
        Ok(response) => response,
        Err(_) => busy(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::middleware::from_fn_with_state;
    use axum::routing::{get, post};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Notify;

    use super::*;

    fn guard(at_once: u32, per_second: u32) -> CallGuard {
        CallGuard::new(
            &Limits {
                calls_at_once_per_source: at_once,
                calls_per_source_per_second: per_second,
                ..Limits::for_tests()
            },
            1024,
        )
    }

    fn calls_at_once(calls_at_once: u32) -> Limits {
        Limits {
            calls_at_once,
            ..Limits::for_tests()
        }
    }

    /// A real server with these limits, a route that waits until told, one that reads a body, one
    /// that reads a body and then waits until told, and one that says how many bodies that one has had.
    async fn serving(limits: Limits, deadline: Duration) -> (SocketAddr, Arc<Notify>) {
        let release = Arc::new(Notify::new());
        let waiting = release.clone();
        let keeping = release.clone();
        let kept = Arc::new(AtomicUsize::new(0));
        let counted = kept.clone();
        let mut guard = CallGuard::new(&limits, 1024);
        guard.body_deadline = deadline;
        let app = Router::new()
            .route(
                "/wait",
                get(move || {
                    let waiting = waiting.clone();
                    async move {
                        waiting.notified().await;
                        "done"
                    }
                }),
            )
            .route("/fast", get(|| async { "answered" }))
            .route("/upload", post(|body: String| async move { body }))
            .route(
                "/keep",
                post(move |body: String| {
                    let (keeping, kept) = (keeping.clone(), kept.clone());
                    async move {
                        kept.fetch_add(1, Ordering::SeqCst);
                        keeping.notified().await;
                        body
                    }
                }),
            )
            .route(
                "/kept",
                get(move || async move { counted.load(Ordering::SeqCst).to_string() }),
            )
            .layer(from_fn_with_state(Arc::new(guard), limit_calls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (address, release)
    }

    async fn status_of(address: SocketAddr, path: &str) -> u16 {
        reqwest::get(format!("http://{address}{path}"))
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    async fn sent(address: SocketAddr, bytes: &[u8]) -> TcpStream {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream
    }

    /// Whole bodies sent to one server, by one client, as making a client is slow on a busy machine.
    struct Uploads {
        client: reqwest::Client,
        address: SocketAddr,
    }

    impl Uploads {
        /// What the server said to a whole body of this length from this source.
        async fn status(&self, source: &str, length: usize) -> u16 {
            self.client
                .post(format!("http://{}/upload", self.address))
                .header("x-forwarded-for", source)
                .body(vec![b'x'; length])
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }

        /// The same, once it's told this or the tries run out. The server reads what's held back
        /// in its own time, so the first answer can come before it has.
        async fn told(&self, source: &str, length: usize, wanted: u16) -> u16 {
            let mut status = 0;
            for _ in 0..150 {
                status = self.status(source, length).await;
                if status == wanted {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            status
        }
    }

    /// All of a body from this source but its last byte, on a connection that then says nothing.
    async fn holding_back(address: SocketAddr, source: &str, length: usize) -> TcpStream {
        let head = format!(
            "POST /upload HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {source}\r\nContent-Length: {length}\r\n\r\n"
        );
        let most = vec![b'x'; length - 1];
        sent(address, &[head.as_bytes(), &most].concat()).await
    }

    const HALF_A_BODY: &[u8] =
        b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\npart";

    #[tokio::test(flavor = "multi_thread")]
    async fn past_the_total_a_call_is_refused_at_once_and_a_place_comes_back() {
        let (address, release) = serving(calls_at_once(2), BODY_DEADLINE).await;
        let mut waits = [
            tokio::spawn(status_of(address, "/wait")),
            tokio::spawn(status_of(address, "/wait")),
        ];
        let mut third = 0;
        for _ in 0..100 {
            third = status_of(address, "/fast").await;
            if third == 503 {
                break;
            }
            // Whichever of three calls comes last is the one refused, and nothing makes that this
            // one. A wait that came while this was being answered was refused instead and ended,
            // which left a place free for good, so it's made again.
            for wait in &mut waits {
                if wait.is_finished() {
                    *wait = tokio::spawn(status_of(address, "/wait"));
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(third, 503);
        while waits.iter().any(|wait| !wait.is_finished()) {
            release.notify_waiters();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(status_of(address, "/fast").await, 200);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn calls_waiting_for_a_body_take_no_place_from_anyone_else() {
        let (address, _release) = serving(calls_at_once(2), Duration::from_secs(30)).await;
        let mut holding = Vec::new();
        for _ in 0..8 {
            holding.push(sent(address, HALF_A_BODY).await);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(status_of(address, "/fast").await, 200);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_body_that_stops_coming_is_told_so_and_a_whole_one_goes_through() {
        let (address, _release) = serving(calls_at_once(2), Duration::from_millis(100)).await;
        let mut stream = sent(address, HALF_A_BODY).await;
        let mut answer = vec![0; 512];
        let read = stream.read(&mut answer).await.unwrap();
        assert!(answer.get(..read).unwrap().starts_with(b"HTTP/1.1 408"));

        let mut stream = sent(
            address,
            b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nwhole",
        )
        .await;
        let mut answer = vec![0; 512];
        let read = stream.read(&mut answer).await.unwrap();
        let answer = answer.get(..read).unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 200"));
        assert!(answer.ends_with(b"whole"));
    }

    /// Bug: nothing but the number of its calls kept one source from most of the room for bodies,
    /// and what was held past the room was only what a setting nobody could change allowed.
    #[tokio::test(flavor = "multi_thread")]
    async fn bodies_held_stop_at_the_room_and_at_one_sources_share_and_come_back() {
        let limits = Limits {
            body_bytes_at_once: 1500,
            body_bytes_at_once_per_source: 800,
            ..Limits::for_tests()
        };
        // Long enough that what's held back here is never given up on, however busy the machine.
        let (address, _release) = serving(limits, Duration::from_secs(3600)).await;
        let uploads = Uploads {
            client: reqwest::Client::new(),
            address,
        };
        assert_eq!(uploads.status("192.0.2.9", 1025).await, 413);

        let one_source = holding_back(address, "192.0.2.1", 700).await;
        let _another = holding_back(address, "192.0.2.2", 700).await;
        assert_eq!(uploads.told("192.0.2.1", 700, 429).await, 429);
        assert_eq!(uploads.told("192.0.2.3", 700, 503).await, 503);
        assert_eq!(
            uploads.status("192.0.2.3", 100).await,
            200,
            "what room is left is still anyone's"
        );

        drop(one_source);
        assert_eq!(uploads.told("192.0.2.3", 700, 200).await, 200);
        assert_eq!(uploads.told("192.0.2.1", 700, 200).await, 200);
    }

    /// Bugs: room given back once a body was read, with its route still holding it. Room taken only
    /// for what had come, with more set aside, so a host held more than it counted. Room taken for
    /// twice what had come, so filling it cost half the bytes it holds.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_body_takes_the_room_set_aside_for_it_and_little_more_until_its_call_ends() {
        let limits = Limits {
            body_bytes_at_once: 1250,
            body_bytes_at_once_per_source: 1024,
            ..Limits::for_tests()
        };
        let (address, release) = serving(limits, BODY_DEADLINE).await;
        let uploads = Uploads {
            client: reqwest::Client::new(),
            address,
        };
        // A whole body of 310 bytes that comes as parts of 300 and 10, to a route that keeps it. Room
        // runs an eighth ahead of the 300, so 337 are set aside for it.
        let head = b"POST /keep HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 192.0.2.1\r\nTransfer-Encoding: chunked\r\n\r\n12c\r\n";
        let rest = b"\r\na\r\nxxxxxxxxxx\r\n0\r\n\r\n";
        let mut kept = sent(address, &[head.as_slice(), &[b'x'; 300], rest].concat()).await;
        let mut keeping = String::new();
        for _ in 0..150 {
            keeping = reqwest::get(format!("http://{address}/kept"))
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            if keeping == "1" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(keeping, "1", "control: the route has the body");

        assert_eq!(
            uploads.status("192.0.2.2", 930).await,
            503,
            "what's set aside for a body its route still has is counted"
        );
        assert_eq!(
            uploads.status("192.0.2.2", 900).await,
            200,
            "and that's little more than has come, not twice as much"
        );

        let mut answer = vec![0; 512];
        let mut read = 0;
        for _ in 0..150 {
            if read > 0 {
                break;
            }
            release.notify_waiters();
            let waiting = Duration::from_millis(20);
            read = tokio::time::timeout(waiting, kept.read(&mut answer))
                .await
                .map_or(0, Result::unwrap);
        }
        assert!(answer.starts_with(b"HTTP/1.1 200"));
        assert_eq!(uploads.status("192.0.2.2", 930).await, 200);
    }

    #[test]
    fn a_source_past_its_rate_waits_and_nobody_else_does() {
        let guard = guard(1000, 10);
        let now = Instant::now();
        for _ in 0..20 {
            assert_eq!(guard.enter("a", now), Ok(()));
            guard.leave("a");
        }
        assert_eq!(guard.enter("a", now), Err(Over::SourceLimit));
        assert_eq!(guard.enter("b", now), Ok(()));
        let later = now + Duration::from_millis(500);
        for _ in 0..5 {
            assert_eq!(guard.enter("a", later), Ok(()));
            guard.leave("a");
        }
        assert_eq!(guard.enter("a", later), Err(Over::SourceLimit));
    }

    #[test]
    fn a_source_can_only_hold_its_share_at_once_and_gets_it_back() {
        let guard = guard(2, 1000);
        let now = Instant::now();
        assert_eq!(guard.enter("a", now), Ok(()));
        assert_eq!(guard.enter("a", now), Ok(()));
        assert_eq!(guard.enter("a", now), Err(Over::SourceLimit));
        assert_eq!(guard.enter("b", now), Ok(()));
        guard.leave("a");
        assert_eq!(guard.enter("a", now), Ok(()));
    }

    #[test]
    fn a_flood_of_new_sources_stops_at_the_table_and_quiet_ones_make_room() {
        let guard = guard(2, 10);
        let now = Instant::now();
        for source in 0..MAX_SOURCES {
            assert_eq!(guard.enter(&source.to_string(), now), Ok(()));
            guard.leave(&source.to_string());
        }
        assert_eq!(guard.enter("new", now), Err(Over::TooManySources));
        assert_eq!(
            guard.enter("0", now),
            Ok(()),
            "one already there still gets in"
        );
        guard.leave("0");
        let later = now + Duration::from_secs(5);
        assert_eq!(guard.enter("new", later), Ok(()));
    }
}

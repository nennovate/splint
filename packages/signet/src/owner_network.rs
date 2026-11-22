//! Owner network access: an owner's device on another machine reaching this Signet straight, rather
//! than by way of its host. It's off unless this machine's operator names an address for it, and
//! warned of whenever it's on.
//!
//! Anyone who can reach that address can call it, so it holds nothing anyone could use. It takes only
//! what the owner signed, each checked exactly as on Signet's own socket, and gives back only the view
//! the agent signed and sealed to the owner. Every body sent is sealed to this agent, as
//! `splint_core::owner_call` says, so nobody on the way reads the owner's rules. Nothing the agent
//! itself calls is there, and no token is taken or needed, so none can be heard. A success says
//! nothing but that it went, and everything else is a refusal in fixed words.
//!
//! What it can't stop: whoever can reach it sees that an owner's device called, when, and how big each
//! call and view was, and can flood it, which only slows the owner's device, as it goes by way of the
//! host when this doesn't answer.

use std::env;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::serve::Listener;
use splint_core::owner_call::{MAX_SEALED_CALL_BYTES, OWNER_VIEW_CALL_PATH, open_owner_call};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Sleep;

use crate::agent_api::{ApiError, fixed_words_only, note_owner_change};
use crate::{Signet, binding, changes, delegation, grants, owner_relay, release, requests, rules};

/// The address to listen on for owner network access, which turns it on.
pub const SETTING: &str = "SPLINT_OWNER_NETWORK";
/// `yes` lets that be every address this machine has, which is otherwise refused.
pub const EVERY_NETWORK_SETTING: &str = "SPLINT_OWNER_NETWORK_EVERY_NETWORK";

/// An owner's device makes a call or two at a time, and a page reads a view every few seconds.
const MAX_CONNECTIONS: usize = 16;
/// From connecting, however busy, so a caller that sends a byte at a time can't keep one open.
const CONNECTION_LIFETIME: Duration = Duration::from_secs(30);
/// Calls anyone can make at once, then a few each second, as each can cost opening a sealed body or
/// sealing a view.
const BURST: u64 = 20;
const PER_SECOND: u64 = 4;
const MILLIS_PER_CALL: u64 = 1000;
/// Something no key of the owner's held here signed has Signet ask its host for the owner's newest keys,
/// so one the owner added a moment ago works at once. Anyone can seal that to this agent, so from the
/// network it's let through this often, and no more, to spend its standing with its host.
const UNKNOWN_KEYS_EVERY: Duration = Duration::from_secs(60);

#[derive(thiserror::Error)]
pub enum Refused {
    #[error("{SETTING} is an IP address and a port, such as 192.168.1.20:7491, and {0} isn't")]
    NotAnAddress(String),
    #[error(
        "{SETTING}={0} listens on every network this machine is ever on, such as a café's Wi-Fi, not \
         only the one you meant: name this machine's address on your LAN or VPN instead, or set \
         {EVERY_NETWORK_SETTING}=yes if every network is what you mean"
    )]
    EveryNetwork(String),
}

/// `main` prints what it returns with `Debug`, and the log should read as the reason.
impl fmt::Debug for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Where owner network access listens, checked as Signet starts, before it does anything else.
pub struct Setting {
    at: SocketAddr,
}

impl Setting {
    /// Nothing, unless its operator turned it on.
    pub fn from_env() -> Result<Option<Self>, Refused> {
        let named = env::var(SETTING).unwrap_or_default();
        if named.is_empty() {
            return Ok(None);
        }
        Self::named(
            &named,
            env::var(EVERY_NETWORK_SETTING).as_deref() == Ok("yes"),
        )
        .map(Some)
    }

    /// An IP address, never a name, so what's listened on is exactly what the operator named.
    fn named(named: &str, every_network: bool) -> Result<Self, Refused> {
        let at: SocketAddr = named
            .parse()
            .ok()
            .filter(|at: &SocketAddr| at.port() != 0)
            .ok_or_else(|| Refused::NotAnAddress(named.to_owned()))?;
        // `[::ffff:0.0.0.0]` listens on every address too, though `is_unspecified` says it isn't.
        if at.ip().to_canonical().is_unspecified() && !every_network {
            return Err(Refused::EveryNetwork(named.to_owned()));
        }
        Ok(Self { at })
    }

    pub async fn bind(&self) -> io::Result<TcpListener> {
        let listener = TcpListener::bind(self.at).await?;
        tracing::warn!(
            at = %self.at,
            every_network = self.at.ip().to_canonical().is_unspecified(),
            "owner network access is on: anyone who can reach this address can ask this Signet to \
             take what the owner signed and for the view sealed to them, and sees when the owner's \
             device calls. Unset {SETTING} unless the owner's device is on another machine"
        );
        Ok(listener)
    }
}

pub async fn serve(listener: TcpListener, signet: Arc<Signet>) -> io::Result<()> {
    axum::serve(Guarded::new(listener), routes(signet)).await
}

/// Only what the owner signed, and their view. Everything else here isn't found.
fn routes(signet: Arc<Signet>) -> Router {
    let bucket = Arc::new(Bucket::full());
    let unsealing = Unsealing {
        signet: signet.clone(),
        unknown_keys_at: Arc::new(Mutex::new(None)),
    };
    Router::new()
        .route("/v0/owner/rules", put(rules::take_rules))
        .route("/v0/owner/binding", put(binding::take_binding))
        .route("/v0/owner/delegation", put(delegation::take))
        .route("/v0/owner/grants", put(grants::take))
        .route("/v0/owner/approvals", post(requests::owner_api::decide))
        .route("/v0/owner/changes/accept", post(changes::take_acceptance))
        .route("/v0/owner/person-text", post(requests::person_text::hold))
        .route("/v0/owner/where-paid", post(requests::payments::set))
        .route(OWNER_VIEW_CALL_PATH, get(owner_relay::current_view))
        .route_layer(middleware::from_fn_with_state(unsealing, unseal))
        .route_layer(middleware::from_fn_with_state(
            signet.clone(),
            note_owner_change,
        ))
        .fallback(|| async { ApiError::NotFound })
        .layer(middleware::from_fn(went_or_refused))
        .layer(middleware::map_response(fixed_words_only))
        .layer(middleware::from_fn(release::one_protocol))
        .layer(middleware::from_fn_with_state(bucket, within_rate))
        .with_state(signet)
}

#[derive(Clone)]
struct Unsealing {
    signet: Arc<Signet>,
    /// When something no key held here signed was last let through.
    unknown_keys_at: Arc<Mutex<Option<Instant>>>,
}

impl Unsealing {
    /// Whether what was opened may go on: at once unless one of its fields is something no key of the
    /// owner's held here signed, and then once in `UNKNOWN_KEYS_EVERY`. Every call here takes one field,
    /// what the owner signed, and anything else is refused by the call itself, asking nobody.
    fn may_go_on(&self, opened: &[u8], now: Instant) -> bool {
        let owner = self.signet.who().owner.clone();
        let unknown = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(opened)
            .is_ok_and(|fields| {
                fields.values().any(|field| {
                    field
                        .as_str()
                        .is_some_and(|signed| !owner.signed_now(signed))
                })
            });
        if !unknown {
            return true;
        }
        let Ok(mut last) = self.unknown_keys_at.lock() else {
            return false;
        };
        if last.is_some_and(|at| now.saturating_duration_since(at) < UNKNOWN_KEYS_EVERY) {
            return false;
        }
        *last = Some(now);
        true
    }
}

/// Opens the sealed body of a call that sends something, bound to that call and this agent, and hands
/// on what was sealed as the call's own body. A read has no body.
async fn unseal(State(unsealing): State<Unsealing>, request: Request, next: Next) -> Response {
    let signet = &unsealing.signet;
    if request.method() == Method::GET {
        return next.run(request).await;
    }
    let (mut parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_SEALED_CALL_BYTES).await else {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "that's more than a call here can be" })),
        )
            .into_response();
    };
    let Ok(opened) = open_owner_call(
        &signet.seal_key,
        signet.who().identity.id(),
        parts.method.as_str(),
        parts.uri.path(),
        &bytes,
    ) else {
        return ApiError::BadRequest(ONLY_SEALED).into_response();
    };
    if !unsealing.may_go_on(&opened, Instant::now()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": UNKNOWN_KEYS })),
        )
            .into_response();
    }
    parts
        .headers
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    parts.headers.remove(CONTENT_LENGTH);
    next.run(Request::from_parts(parts, Body::from(opened)))
        .await
}

const UNKNOWN_KEYS: &str = "no key of the owner's held here signed that, and that's asked about only \
once a minute";

const ONLY_SEALED: &str = "a call here sends what the owner signed sealed to this agent for that \
call, as {\"sealed\"}";

/// A call that went says only that, as what it took is the caller's own. What's read is sealed, and a
/// refusal is in fixed words.
async fn went_or_refused(request: Request, next: Next) -> Response {
    let reads = request.method() == Method::GET;
    let response = next.run(request).await;
    if reads || !response.status().is_success() {
        return response;
    }
    (response.status(), Json(serde_json::json!({}))).into_response()
}

async fn within_rate(State(bucket): State<Arc<Bucket>>, request: Request, next: Next) -> Response {
    if !bucket.take(Instant::now()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "too many calls here just now" })),
        )
            .into_response();
    }
    next.run(request).await
}

/// Calls left, in thousandths, and when it was last filled.
struct Bucket {
    held: Mutex<(u64, Instant)>,
}

impl Bucket {
    fn full() -> Self {
        Self {
            held: Mutex::new((BURST * MILLIS_PER_CALL, Instant::now())),
        }
    }

    fn take(&self, now: Instant) -> bool {
        let Ok(mut held) = self.held.lock() else {
            return false;
        };
        let (left, filled) = *held;
        let since =
            u64::try_from(now.saturating_duration_since(filled).as_millis()).unwrap_or(u64::MAX);
        let left = left
            .saturating_add(since.saturating_mul(PER_SECOND))
            .min(BURST * MILLIS_PER_CALL);
        if left < MILLIS_PER_CALL {
            *held = (left, now);
            return false;
        }
        *held = (left - MILLIS_PER_CALL, now);
        true
    }
}

/// Takes connections up to a cap, each for a fixed time at most, so idle or slow callers can't hold
/// what an owner's device needs.
struct Guarded {
    inner: TcpListener,
    room: Arc<Semaphore>,
}

impl Guarded {
    fn new(inner: TcpListener) -> Self {
        Self {
            inner,
            room: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }
}

impl Listener for Guarded {
    type Io = Lifetimed;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, peer)) => {
                    // Dropping the stream closes it, and a caller past the cap gets nothing else.
                    if let Ok(slot) = self.room.clone().try_acquire_owned() {
                        return (Lifetimed::new(stream, slot), peer);
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, "couldn't take a connection for owner network access");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// A connection that ends a fixed time after it began, whatever it's doing.
struct Lifetimed {
    stream: TcpStream,
    ends: Pin<Box<Sleep>>,
    _slot: OwnedSemaphorePermit,
}

impl Lifetimed {
    fn new(stream: TcpStream, slot: OwnedSemaphorePermit) -> Self {
        Self {
            stream,
            ends: Box::pin(tokio::time::sleep(CONNECTION_LIFETIME)),
            _slot: slot,
        }
    }

    fn ended(&mut self, cx: &mut Context<'_>) -> bool {
        self.ends.as_mut().poll(cx).is_ready()
    }
}

fn over() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "connection lasted its time")
}

impl AsyncRead for Lifetimed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.ended(cx) {
            return Poll::Ready(Err(over()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Lifetimed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.ended(cx) {
            return Poll::Ready(Err(over()));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug caught: an operator naming 0.0.0.0 or [::] would open this on every network the machine
    /// ever joins, a café's Wi-Fi included, without meaning to.
    #[test]
    fn every_network_is_refused_unless_meant() {
        // Bug caught: the IPv4-mapped form got past, as Rust's `is_unspecified` is true only for `::`.
        for every in ["0.0.0.0:7491", "[::]:7491", "[::ffff:0.0.0.0]:7491"] {
            assert!(matches!(
                Setting::named(every, false),
                Err(Refused::EveryNetwork(_))
            ));
            assert!(Setting::named(every, true).is_ok(), "{every}");
        }
        for not_one in [
            "laptop.local:7491",
            "192.168.1.20",
            "192.168.1.20:0",
            "nonsense",
        ] {
            assert!(matches!(
                Setting::named(not_one, true),
                Err(Refused::NotAnAddress(_))
            ));
        }
        assert!(Setting::named("192.168.1.20:7491", false).is_ok());
    }
}

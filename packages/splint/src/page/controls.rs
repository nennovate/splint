//! Your controls on your own computer: Splint here serves the owner page from this release, at
//! `http://localhost:PORT/owner`, and signs what it prepares with this computer's own sign-in, so the
//! page makes no passkey. No host serves it: Nenye decided on 2026-11-21 that owners sign only on their
//! own computers (issue 635). `splint controls HOST --port N` serves the page and its relay
//! by themselves, and that page signs nothing: a passkey for `localhost` is one any program on this
//! computer, run by any user, could serve its own page for on another port and have the person's touch
//! sign what it likes, so no verifier takes one.
//!
//! The page reaches hosts through `/relay/DOMAIN/...` here, as hosts don't let other origins read
//! their answers. The relay adds nothing: what the page sends is already signed, and every host checks
//! it as it would from anywhere. It carries no owner mail, what an owner signs for an agent's Signet:
//! that goes to a host only sealed to the agent, with the owner's proof, and a body the relay was
//! handed would go as it is. While your controls run they hold the port on both of `localhost`'s
//! addresses, so nothing else answers there.
//!
//! Your controls run once for each port, as the page there remembers its owners for that origin alone.
//! Running them again while they run opens the ones running, known by the lock they hold in your own
//! Splint folder for as long as they hold the port, never by whatever answers there.

use std::future::IntoFuture;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};

use aws_lc_rs::digest;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST,
    REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use splint_core::canonical_domain;

use splint_core::host_api::{HeldOwnerView, RulesNotice};
use splint_core::rules::claimed_rules_agent;
use splint_core::{SplintId, unix_now};

use crate::direct::{self, Direct, ForHost, Route, Sent};
use crate::failure::Failure;
use crate::home::Home;
use crate::services;

const TEMPLATE: &str = include_str!("web/owner.html");
const SCRIPT: &str = include_str!("web/owner.js");
const KEYS_SCRIPT: &str = include_str!("web/keys.js");
const TERMS_SCRIPT: &str = include_str!("terms.js");
const STYLE: &str = include_str!("web/owner.css");
/// Splint's tokens, shared by every page a person sees, and the controls' components.
const TOKENS: &str = include_str!("../../../style/tokens.css");
const SHARED_STYLE: &str = include_str!("../../../style/splint.css");
/// Preact with htm, kept in the repo as it came: what the page draws with.
const DRAWING_SCRIPT: &str = include_str!("web/preact.js");

/// One fixed port, so the page's origin, and what it remembers on this browser, stays the same.
pub const DEFAULT_PORT: u16 = 7480;
/// The one name the page is served at, so its origin stays the same.
const LOCALHOST: &str = "localhost";
/// What a page sends a host is small: signed objects, never files.
const MAX_BODY_BYTES: usize = 256 * 1024;
const RELAY_TIMEOUT_SECS: u64 = 30;
/// What a host answers the page is lists and signed objects. A host the page reaches by a
/// counterparty's address could otherwise stream gigabytes into this process.
const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;

static PAGE: LazyLock<String> = LazyLock::new(|| {
    TEMPLATE
        .replace("{script_integrity}", &integrity(SCRIPT))
        .replace("{keys_integrity}", &integrity(KEYS_SCRIPT))
        .replace("{terms_integrity}", &integrity(TERMS_SCRIPT))
        .replace("{style_integrity}", &integrity(STYLE))
        .replace("{tokens_integrity}", &integrity(TOKENS))
        .replace("{shared_style_integrity}", &integrity(SHARED_STYLE))
        .replace("{drawing_integrity}", &integrity(DRAWING_SCRIPT))
});

/// The page reaches only this server, which relays to hosts.
const POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; \
object-src 'none'; connect-src 'self'; base-uri 'none'; form-action 'none'; \
frame-ancestors 'none'; require-trusted-types-for 'script'";
/// No passkey here either: Splint on the computer signs, and a passkey for `localhost` is one any
/// program on this computer could serve its own page for and ask to sign.
const PERMISSIONS: &str = "publickey-credentials-get=(), publickey-credentials-create=(), \
camera=(), microphone=(), geolocation=(), payment=(), usb=()";

pub(crate) struct Controls {
    /// The host that keeps your list of agents.
    home_host: HomeHost,
    /// Served by Splint on this computer, which signs with the person's sign-in here, so the page signs
    /// ES256 through it and makes no passkey.
    computer: bool,
    /// `localhost:PORT`, the only Host header taken, so a page elsewhere can't reach this by renaming
    /// itself to this address.
    here: String,
    http: reqwest::Client,
    /// For a host on this machine, over plain HTTP, which never goes to a proxy.
    on_this_machine: reqwest::Client,
    /// The person's own Splint folder, where their agents on this computer are, and the addresses
    /// they named for reaching others' Signets straight.
    folder: Option<Home>,
    /// Whether what's kept for agents' hosts is being sent again now, so calls don't pile up behind it.
    sending_again: AtomicBool,
    /// Splint on this computer, where it serves the page: its sessions at hosts prove what's kept
    /// for one and sent again, with no prompt.
    sessions_here: Option<Arc<crate::computer::Computer>>,
}

/// Which host keeps the person's list: the one `splint controls HOST` names, or for Splint on this
/// computer, the one it keeps in a file, which the first agent it sets up names, and none before that.
enum HomeHost {
    Fixed(String),
    Kept(std::path::PathBuf),
}

impl HomeHost {
    fn now(&self) -> Option<String> {
        match self {
            Self::Fixed(host) => Some(host.clone()),
            Self::Kept(file) => std::fs::read_to_string(file)
                .ok()
                .map(|host| host.trim().to_owned())
                .filter(|host| host_url(host).is_some()),
        }
    }
}

impl Controls {
    /// The page as Splint on this computer serves it, at `here`, with the home host kept in `file`.
    pub(crate) fn for_computer(
        here: String,
        file: std::path::PathBuf,
        computer: Arc<crate::computer::Computer>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            home_host: HomeHost::Kept(file),
            computer: true,
            here,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(RELAY_TIMEOUT_SECS))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            on_this_machine: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(RELAY_TIMEOUT_SECS))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()?,
            folder: Home::from_env(None).ok().map(|home| home.the_default()),
            sending_again: AtomicBool::new(false),
            sessions_here: Some(computer),
        })
    }

    /// A client for a host at this base URL: one that never goes through a proxy for this machine.
    pub(crate) fn client_for(&self, base: &str) -> &reqwest::Client {
        if base.starts_with("https://") {
            &self.http
        } else {
            &self.on_this_machine
        }
    }
}

fn integrity(file: &str) -> String {
    use base64::Engine;
    let hash = digest::digest(&digest::SHA384, file.as_bytes());
    format!(
        "sha384-{}",
        base64::engine::general_purpose::STANDARD.encode(hash.as_ref())
    )
}

/// The port and whether to open the browser, from `[--port N] [--no-open]` in any order.
pub fn flags(given: &[&str]) -> Result<(u16, bool), Failure> {
    let (mut port, mut open) = (DEFAULT_PORT, true);
    let mut rest = given.iter();
    while let Some(flag) = rest.next() {
        match *flag {
            "--no-open" => open = false,
            "--port" => {
                port = rest
                    .next()
                    .and_then(|number| number.parse::<u16>().ok())
                    .filter(|number| *number != 0)
                    .ok_or(Failure::Usage)?;
            }
            _ => return Err(Failure::Usage),
        }
    }
    Ok((port, open))
}

/// Opens the person's browser at their controls, by the system's own opener and never through a
/// shell. Where there's none, the link printed above is enough. Windows's opens a link it's handed as
/// the default browser would, with nothing read as a command.
pub(crate) fn open_browser(url: &str) {
    let (opener, before): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("open", &[])
    } else if cfg!(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd"
    )) {
        ("xdg-open", &[])
    } else if cfg!(windows) {
        ("rundll32", &["url.dll,FileProtocolHandler"])
    } else {
        return;
    };
    let started = std::process::Command::new(opener)
        .args(before)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if let Ok(mut child) = started {
        // Reaped when it exits, so it never lingers as a zombie.
        std::thread::spawn(move || child.wait());
    }
}

/// The lock your controls hold while they serve a port, in the person's own Splint folder.
fn lock_name(port: u16) -> String {
    format!("controls-{port}")
}

/// Which home host the controls holding that lock serve.
fn host_file(folder: &Home, port: u16) -> std::path::PathBuf {
    folder.run_dir().join(format!("{}.host", lock_name(port)))
}

/// Why the port can't be had, in words. Never another port: the page remembers its owners for its
/// origin alone, so one there would offer to set up controls again.
fn unusable(port: u16, error: &io::Error) -> Failure {
    Failure::refused(match error.kind() {
        io::ErrorKind::AddrInUse => format!(
            "another program is using port {port} on this computer, so it isn't safe to open your \
             controls there. Stop that program, then run splint controls again"
        ),
        io::ErrorKind::PermissionDenied => format!(
            "this computer doesn't let splint use port {port}, so your controls can't open there"
        ),
        _ => format!("your controls can't open on port {port}: {error}"),
    })
}

/// Serves your controls until stopped, or opens the ones already serving this port.
pub async fn serve(home_host: &str, port: u16, open: bool) -> Result<String, Failure> {
    let home_host = canonical_domain(home_host)
        .ok()
        .filter(|domain| domain == home_host)
        .ok_or_else(|| Failure::refused("that isn't a host's address, such as host.example"))?;
    let here = format!("{LOCALHOST}:{port}");
    // The person's own folder, whichever agent asked, as a port is the person's.
    let folder = Home::from_env(None).map(|home| home.the_default());
    // Only ever loopback: there's no setting to change this. `localhost` is both 127.0.0.1 and ::1,
    // and browsers try ::1 first, so both are held, or another program on either has this origin.
    let v4 = match tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
        Ok(listener) => listener,
        Err(error) => {
            // Taken only once both addresses are held, and let go only as they are, so the lock held
            // means these are your controls, whatever answers at the port.
            let ours = error.kind() == io::ErrorKind::AddrInUse
                && folder.as_ref().is_ok_and(|folder| {
                    services::is_running(folder, &lock_name(port)).unwrap_or(false)
                });
            if !ours {
                return Err(unusable(port, &error));
            }
            // Those running may be for another home host, whose page would keep the person's list
            // and open their codes there.
            let serving = folder
                .as_ref()
                .ok()
                .and_then(|folder| std::fs::read_to_string(host_file(folder, port)).ok());
            if serving.as_deref() != Some(home_host.as_str()) {
                return Err(Failure::refused(format!(
                    "your controls on port {port} are already open for {}, not {home_host}. Stop \
                     them, then run splint controls {home_host} again, or give another --port",
                    serving.as_deref().map_or_else(
                        || "another host".to_owned(),
                        splint_core::requests::with_hidden_shown
                    )
                )));
            }
            if open {
                open_browser(&format!("http://{here}/owner"));
            }
            return Ok(format!(
                "Your controls are already open on this computer:\n\n  http://{here}/owner"
            ));
        }
    };
    let v6 = match tokio::net::TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
        Ok(listener) => Some(listener),
        // A computer with no ::1 at all: nothing can answer there, so `localhost` is 127.0.0.1 alone.
        Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => None,
        Err(error) => return Err(unusable(port, &error)),
    };
    // With no folder to hold it in, these still serve, and running them again says the port is taken.
    let _running = folder.ok().and_then(|folder| {
        let held = services::the_only_copy(&folder, &lock_name(port))
            .ok()
            .flatten()?;
        // Beside the lock, so running them again says which host these are for. Without it, that
        // run refuses rather than open these for another host.
        let _ = std::fs::write(host_file(&folder, port), &home_host);
        Some(held)
    });
    let controls = Arc::new(Controls {
        home_host: HomeHost::Fixed(home_host),
        computer: false,
        here: here.clone(),
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(RELAY_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        on_this_machine: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(RELAY_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?,
        folder: Home::from_env(None).ok().map(|home| home.the_default()),
        sending_again: AtomicBool::new(false),
        sessions_here: None,
    });
    let mut out = io::stdout();
    writeln!(
        out,
        "Your controls are open on this computer until you stop this:\n\n  http://{here}/owner"
    )?;
    out.flush()?;
    if open {
        open_browser(&format!("http://{here}/owner"));
    }
    let app = routes(controls);
    match v6 {
        Some(v6) => {
            tokio::try_join!(
                axum::serve(v4, app.clone()).into_future(),
                axum::serve(v6, app).into_future()
            )?;
        }
        None => axum::serve(v4, app).await?,
    }
    Ok("Your controls have stopped.".to_owned())
}

pub(crate) fn routes(controls: Arc<Controls>) -> Router {
    let page_html = || async { file("text/html; charset=utf-8", PAGE.as_str()) };
    let page = Router::new()
        // One page: the controls, each request waiting for the person, and an agent's link to one.
        .route("/owner", get(page_html))
        .route("/ask", get(page_html))
        .route("/requests", get(page_html))
        .route("/requests/{id}", get(page_html))
        .route(
            "/owner.js",
            get(|| async { file("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/owner-keys.js",
            get(|| async { file("text/javascript; charset=utf-8", KEYS_SCRIPT) }),
        )
        .route(
            "/owner-terms.js",
            get(|| async { file("text/javascript; charset=utf-8", TERMS_SCRIPT) }),
        )
        .route(
            "/owner.css",
            get(|| async { file("text/css; charset=utf-8", STYLE) }),
        )
        .route(
            "/tokens.css",
            get(|| async { file("text/css; charset=utf-8", TOKENS) }),
        )
        .route(
            "/splint.css",
            get(|| async { file("text/css; charset=utf-8", SHARED_STYLE) }),
        )
        .route(
            "/preact.js",
            get(|| async { file("text/javascript; charset=utf-8", DRAWING_SCRIPT) }),
        )
        .route("/.well-known/splint/host", get(describe))
        .route("/relay/{domain}/{*path}", any(relay));
    page.route_layer(middleware::from_fn_with_state(
        controls.clone(),
        only_this_address,
    ))
    .route_layer(middleware::from_fn(with_safety_headers))
    .with_state(controls)
}

fn file(kind: &'static str, content: &str) -> Response {
    ([(CONTENT_TYPE, kind)], content.to_owned()).into_response()
}

/// What the page reads first: which host is its home, and that it reaches hosts through this server.
/// It names no RP ID, as no passkey is made or taken here.
async fn describe(State(controls): State<Arc<Controls>>) -> Response {
    axum::Json(serde_json::json!({
        "domain": controls.home_host.now(),
        "relay": true,
        "computer": controls.computer,
    }))
    .into_response()
}

/// Headers the owner API reads, and nothing else, so no cookie or browser detail reaches a host.
fn forwarded(name: &HeaderName) -> bool {
    *name == CONTENT_TYPE || *name == AUTHORIZATION || name.as_str().starts_with("splint-")
}

/// Whether a call came from your controls page itself, as a `fetch` and not a page to show. A browser
/// says where a call came from, so a website you visit, or a page on another port here, can't use
/// this to reach hosts or this machine. A call that says nothing is refused, so this never rests on a
/// browser remembering to say it; a program here that says it all can reach them anyway.
fn from_this_page(request: &Request, here: &str) -> bool {
    let headers = request.headers();
    let site = headers.get("sec-fetch-site").map(HeaderValue::as_bytes);
    let dest = headers.get("sec-fetch-dest").map(HeaderValue::as_bytes);
    let origin = headers.get("origin").map(HeaderValue::as_bytes);
    site == Some(b"same-origin".as_slice())
        && dest.is_none_or(|dest| dest == b"empty")
        && origin.is_none_or(|origin| origin == format!("http://{here}").as_bytes())
}

/// The answer, read up to `MAX_ANSWER_BYTES`, or nothing past that.
pub(crate) async fn bounded(mut answer: reqwest::Response) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = answer.chunk().await.ok()? {
        if bytes.len().saturating_add(chunk.len()) > MAX_ANSWER_BYTES {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    Some(bytes)
}

async fn relay(
    State(controls): State<Arc<Controls>>,
    Path((domain, path)): Path<(String, String)>,
    request: Request,
) -> Response {
    if !from_this_page(&request, &controls.here) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(base) = host_url(&domain) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    send_again_meanwhile(&controls);
    let method = request.method().clone();
    if ![Method::GET, Method::POST, Method::PUT, Method::DELETE].contains(&method) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    // Before anything is read or sent on, so nothing an owner signed for their agent's Signet leaves
    // here for a host as the page handed it over.
    if method == Method::POST && path.split('/').take(2).eq(["v0", "owner-mail"]) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": NO_OWNER_MAIL })),
        )
            .into_response();
    }
    let query = request
        .uri()
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    let headers: Vec<(HeaderName, HeaderValue)> = request
        .headers()
        .iter()
        .filter(|(name, _)| forwarded(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let Ok(body) = to_bytes(request.into_body(), MAX_BODY_BYTES).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let only_host = request_says_host(&headers);
    let (straight, keep) = match straight(&controls, &method, &path, &body, only_host).await {
        Straight::Answered(answer) => return answer,
        Straight::AlsoToHost(route, keep) => (route, Some(keep)),
        Straight::ToHost => (None, None),
    };
    let client = controls.client_for(&base);
    let mut outgoing = client
        .request(method, format!("{base}/{path}{query}"))
        .body(body);
    for (name, value) in headers {
        outgoing = outgoing.header(name, value);
    }
    let answer = outgoing.send().await.ok();
    // Done only once the host takes it, as what answered straight could be anyone. Where only that
    // said yes, and the host couldn't be reached or was at its limit for now, it's kept and sent to
    // the host again until it takes it, and the page is told so.
    if let (Some(keep), Some(folder)) = (&keep, &controls.folder) {
        let away = answer.as_ref().is_none_or(|answer| {
            answer.status().is_server_error() || answer.status() == StatusCode::TOO_MANY_REQUESTS
        });
        if answer
            .as_ref()
            .is_some_and(|answer| answer.status().is_success())
        {
            direct::taken_by_host(folder, &keep.agent, keep.kind, &keep.signed);
        } else if let Some(route) = &straight
            && away
        {
            let sent = Sent {
                kind: keep.kind,
                signed: &keep.signed,
                sealed: None,
            };
            let kept = direct::keep_for_host(folder, &keep.agent, &domain, &sent);
            return answered(
                if kept.is_ok() {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
                &serde_json::json!({ "error": NOT_YET_AT_HOST }),
                route,
            );
        }
    }
    let Some(answer) = answer else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let status = answer.status();
    // The page reads only JSON. Anything else goes back as text, so a host's HTML or script never
    // runs at this page's origin.
    let json = answer
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|kind| kind.to_str().ok())
        .is_some_and(|kind| kind.starts_with("application/json"));
    let Some(bytes) = bounded(answer).await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(if json {
            "application/json"
        } else {
            "text/plain; charset=utf-8"
        }),
    );
    headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    if let Some(route) = straight {
        headers.insert(ROUTE_HEADER, HeaderValue::from_static(route.word()));
    }
    response
}

/// Said to a page that hands the relay owner mail for a host, which it never carries.
const NO_OWNER_MAIL: &str = "what you sign for your agent goes to its host only sealed to the agent, \
which this relay doesn't do, so nothing was sent";

/// Said when only a straight answer took something the owner signed, and its host couldn't be reached
/// or was at its limit for now. The page says it in its own words.
const NOT_YET_AT_HOST: &str = "its Signet said it took that, but its host couldn't take it just now \
to confirm it, so it's kept here and sent again until the host takes it";

/// What the page sends or reads that goes to an agent's Signet straight from here.
enum Straight {
    /// Signet's answer, or what it left, which is the whole answer.
    Answered(Response),
    /// What the owner signed, which goes to the host as well, whatever Signet said, and is done once
    /// it takes it: how Signet took it if it did, and what to keep for the host.
    AlsoToHost(Option<Route>, KeepForHost),
    /// None of that, or Signet couldn't be reached straight, so only the host has it.
    ToHost,
}

struct KeepForHost {
    agent: SplintId,
    kind: ForHost,
    signed: String,
}

/// The page asks for its host's answer alone, with `splint-route: host`, when a view read straight was
/// older than Signet would sign one now.
fn request_says_host(headers: &[(HeaderName, HeaderValue)]) -> bool {
    headers
        .iter()
        .any(|(name, value)| *name == ROUTE_HEADER && value.as_bytes() == b"host")
}

/// Sends what's kept for agents' hosts to them again, once at a time, without holding up the page.
fn send_again_meanwhile(controls: &Arc<Controls>) {
    if controls.folder.is_none() || controls.sending_again.swap(true, Ordering::SeqCst) {
        return;
    }
    let controls = controls.clone();
    tokio::spawn(async move {
        if let Some(folder) = &controls.folder {
            let proves = match &controls.sessions_here {
                Some(computer) => direct::Proves::Computer(computer),
                None => direct::Proves::NobodyThere,
            };
            direct::send_again(folder, proves).await;
        }
        controls.sending_again.store(false, Ordering::SeqCst);
    });
}

/// Rules, and the view an agent left its owner, straight to and from the
/// agent's Signet, where it runs on this computer or its owner named where it listens on their network,
/// as `crate::direct` says. Only the host has anything else the page asks for.
async fn straight(
    controls: &Controls,
    method: &Method,
    path: &str,
    body: &[u8],
    only_host: bool,
) -> Straight {
    let Some(folder) = &controls.folder else {
        return Straight::ToHost;
    };
    let parts: Vec<&str> = path.split('/').collect();
    match (method.as_str(), parts.as_slice()) {
        ("PUT", ["v0", "rules"]) => {
            let Some(rules) = serde_json::from_slice::<RulesNotice>(body)
                .ok()
                .map(|notice| notice.rules)
            else {
                return Straight::ToHost;
            };
            let Ok(agent) = claimed_rules_agent(&rules) else {
                return Straight::ToHost;
            };
            let keep = KeepForHost {
                agent: agent.clone(),
                kind: ForHost::Rules,
                signed: rules.clone(),
            };
            let Ok(Some(found)) = Direct::find(folder, &agent) else {
                direct::note(folder, &agent, Route::Host);
                return Straight::AlsoToHost(None, keep);
            };
            let route = found.put_rules(&rules).await.ok().map(|()| found.route());
            direct::note(folder, &agent, route.clone().unwrap_or(Route::Host));
            Straight::AlsoToHost(route, keep)
        }
        ("GET", ["v0", "owner-view", agent]) => {
            let Some(agent) = id_in(agent) else {
                return Straight::ToHost;
            };
            if only_host {
                return Straight::ToHost;
            }
            let Ok(Some(found)) = Direct::find(folder, &agent) else {
                return Straight::ToHost;
            };
            match found.view().await {
                // The page opens and checks it as one from the host, by the view's own date.
                Some(view) => Straight::Answered(answered(
                    StatusCode::OK,
                    &serde_json::to_value(HeldOwnerView {
                        view: Some(view),
                        at: unix_now(),
                    })
                    .unwrap_or_default(),
                    &found.route(),
                )),
                None => Straight::ToHost,
            }
        }
        _ => Straight::ToHost,
    }
}

/// An agent's ID as a path names it, or nothing.
fn id_in(part: &str) -> Option<SplintId> {
    serde_json::from_value::<SplintId>(serde_json::Value::String(part.to_owned()))
        .ok()
        .filter(SplintId::is_well_formed)
}

/// An answer from here, as the page reads one from a host, saying which way it went.
fn answered(status: StatusCode, body: &serde_json::Value, route: &Route) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    headers.insert(ROUTE_HEADER, HeaderValue::from_static(route.word()));
    response
}

/// Says which way something went: `this-computer`, `network` or `host`.
const ROUTE_HEADER: HeaderName = HeaderName::from_static("splint-route");

/// A host's base URL: HTTPS, or plain HTTP only for a host on this machine, as the page has it.
pub(crate) fn host_url(domain: &str) -> Option<String> {
    let name = domain.rsplit_once(':').map_or(domain, |(name, _)| name);
    let spelled = canonical_domain(domain)
        .ok()
        .filter(|canonical| canonical == domain);
    let local = name == "localhost"
        || name == "127.0.0.1"
        || name == "[::1]"
        || name.ends_with(".localhost");
    if spelled.is_none() && !(local && domain.parse::<std::net::SocketAddr>().is_ok()) {
        return None;
    }
    Some(format!(
        "{}://{domain}",
        if local { "http" } else { "https" }
    ))
}

async fn only_this_address(
    State(controls): State<Arc<Controls>>,
    request: Request,
    next: Next,
) -> Response {
    let named = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok());
    if named != Some(controls.here.as_str()) {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    next.run(request).await
}

async fn with_safety_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let fixed: [(HeaderName, &'static str); 8] = [
        (CONTENT_SECURITY_POLICY, POLICY),
        (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (X_FRAME_OPTIONS, "DENY"),
        (REFERRER_POLICY, "no-referrer"),
        (CACHE_CONTROL, "no-store"),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
        (HeaderName::from_static("permissions-policy"), PERMISSIONS),
    ];
    for (name, value) in fixed {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

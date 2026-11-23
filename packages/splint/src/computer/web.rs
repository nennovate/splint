//! What a browser reaches Splint on this computer at: `http://localhost:7480`, where it serves the
//! person's controls (`/owner`), each request waiting for them (`/requests/ID`) and an agent's link
//! (`/ask`), all one page from [`crate::page::controls`]. An agent's link carries one signed ask after
//! the `#`, which no browser sends anywhere: the page hands it here only once the person clicks to see
//! it, as any website can open a link, and it then waits for an approval of it on the page, never going
//! into a prompt by itself. The page shows each ask in its own fixed words, from the ask's typed
//! changes, never the agent's. The controls sign through this computer's sign-in with no passkey, read
//! through the sessions this keeps, open what's sealed to the person here, and leave what they sign for
//! an agent at its host only through `/local/mail`, which seals it to the agent.
//!
//! A request header proves nothing about who sent it, so every call under `/local` needs the page key,
//! but handing over a link's ask, trading an opening for the key, and unlocking: a secret made at each
//! start, which only a page opened from a one-time opening, or one the person unlocked with their
//! passphrase or the chip's prompt, gets. Only a program run as the person gets an opening, on the
//! socket. So another of the computer's users, or a program that reaches the port but not the person's
//! files, gets nothing without the passphrase, and wrong tries at it wait. A call from another site
//! carries no `Sec-Fetch-Site: same-origin`, or an `Origin` of its own, and is refused, and one naming
//! any other host is refused, so a site the person visits can't rename itself to reach it. What a
//! program running as the person can do, it can do anyway: ask the socket for an opening.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Json, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, ORIGIN, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};

use super::owner_page::NotLeft;
use super::{Asked, Computer, port};
use crate::failure::Failure;

const POLICY: &str =
    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub fn routes(computer: Arc<Computer>) -> Router {
    let local = Router::new()
        .route("/local/asks", post(hand).get(waiting))
        .route("/local/approve", post(approve))
        .route("/local/here", get(here))
        .route("/local/opened", post(opened))
        .route("/local/owner", post(make_owner))
        .route("/local/sign", post(sign))
        .route("/local/unlock", post(unlock).get(unlock_asks))
        .route("/local/lock", post(lock))
        .route("/local/session", post(start_sessions))
        .route("/local/read", post(read))
        .route("/local/mail", post(leave_mail))
        .route("/local/open", post(open))
        .route("/local/viewing", post(set_viewing))
        .route("/local/sign-out", post(sign_out))
        .route("/local/recovery", post(recovery))
        .route("/local/page", post(page_key))
        .route_layer(middleware::from_fn_with_state(
            computer.clone(),
            only_with_the_page_key,
        ))
        .route_layer(middleware::from_fn(only_from_this_page));
    let owner_page = crate::page::controls::Controls::for_computer(
        format!("localhost:{}", port()),
        computer.home_host_file(),
        computer.clone(),
    )
    .map(|controls| crate::page::controls::routes(Arc::new(controls)))
    .unwrap_or_default();
    Router::new()
        .merge(local)
        .layer(middleware::from_fn(only_this_address))
        .layer(middleware::from_fn(with_safety_headers))
        .with_state(computer)
        .merge(owner_page)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Linked {
    ask: String,
    address: String,
}

/// An ask from an agent's link, handed over once the person clicked to see it. Its ID is looked up at
/// the address's own host, and the ask is taken only if that ID is the one that signed it. It's shown
/// back in the page's own words, and waits for the person to approve it there.
async fn hand(State(computer): State<Arc<Computer>>, Json(linked): Json<Linked>) -> Response {
    if splint_core::parse_address(&linked.address).is_err() {
        return refused("that link doesn't name an agent's address");
    }
    let asked = Asked {
        ask: linked.ask,
        identity: String::new(),
        address: linked.address,
        draft: None,
        schema: None,
        linked: true,
        kinds: Vec::new(),
        agreed: Vec::new(),
        in_words: Default::default(),
    };
    let Ok(asked) = computer.as_its_host_says(asked).await else {
        return refused("that agent's host couldn't be reached, so try again");
    };
    let id = splint_core::asks::payload_id(&asked.ask).ok();
    match computer.take(asked).await {
        Ok(outcome) => {
            let mut answer = json!(outcome);
            if let (Some(id), Some(fields)) = (id, answer.as_object_mut()) {
                fields.insert("ask".to_owned(), json!(computer.shown_by_id(&id).await));
            }
            Json(answer).into_response()
        }
        // Only a failed check of the ask itself means that. take's other refusals are its own fixed
        // words, such as a full queue or a step no longer held, which say what to do instead.
        Err(Failure::Core(_)) => refused("that ask isn't one its agent signed, or it has ended"),
        Err(failure) => refused(&failure.to_string()),
    }
}

/// What's waiting, in the approvals it goes in, so the page shows exactly what its Approve signs, with
/// the code that approval checks.
async fn waiting(State(computer): State<Arc<Computer>>) -> Json<super::Waiting> {
    Json(computer.listed().await)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Opening {
    opening: String,
}

/// The page key, for a one-time opening the socket handed out, which the page holds from then on.
async fn page_key(State(computer): State<Arc<Computer>>, Json(body): Json<Opening>) -> Response {
    match computer.trade_opening(&body.opening).await {
        Some(key) => Json(json!({ "key": key })).into_response(),
        None => refused(
            "that opening has been used or has ended: open your controls again with splint \
             controls HOST",
        ),
    }
}

use super::ApproveBody;
use crate::owner_key::SignIn;

/// Whether signing here asks for the person itself: the chip's prompt, or a key file's passphrase,
/// given. A plain key file asks for nothing, so a page alone never signs with it, and the person
/// locks it or signs in a terminal. With no sign-in made yet, off the chip, there's nothing to sign
/// with: only an approval or making the owner ID goes on, to make one locked with a passphrase.
fn gated(computer: &Computer, passphrase: Option<&str>) -> Result<(), &'static str> {
    if computer.prompts_by_itself() {
        return Ok(());
    }
    let given = passphrase.is_some_and(|given| !given.is_empty());
    match computer.owner.sign_in() {
        Some(SignIn::Chip) => Ok(()),
        Some(SignIn::LockedFile) if given => Ok(()),
        Some(SignIn::LockedFile) => Err(ITS_PASSPHRASE),
        Some(SignIn::PlainFile) => Err(IN_A_TERMINAL),
        None => Err(NO_SIGN_IN),
    }
}

const ITS_PASSPHRASE: &str = "your sign-in here is a key file locked with a passphrase, so type it to \
     approve";
const IN_A_TERMINAL: &str = "your sign-in here is a key file with no passphrase, which signs with \
     nobody there, so this page can't use it: lock it with splint computer lock in a terminal on this \
     computer, or approve there with splint computer approve";
const RECOVERY_IN_A_TERMINAL: &str = "your sign-in here is a key file with no passphrase, so this page \
     can't use it: lock it with splint computer lock in a terminal on this computer, or set your \
     recovery code there with splint computer recovery";
const NO_SIGN_IN: &str = "there's no sign-in on this computer yet, so nothing was signed";

/// Approve, where the sign-in asks for the person itself.
async fn approve(State(computer): State<Arc<Computer>>, Json(body): Json<ApproveBody>) -> Response {
    // The first approval makes the sign-in: off the chip, a key file locked with the passphrase
    // given, and nothing without one.
    let makes_one = computer.owner.sign_in_described().is_none();
    if !makes_one && let Err(why) = gated(&computer, body.passphrase.as_deref()) {
        return refused(why);
    }
    match computer
        .approve(body.passphrase, &body.ids, body.code.as_deref())
        .await
    {
        Ok(approval) => Json(json!(approval)).into_response(),
        Err(failure) => refused(&failure.to_string()),
    }
}

/// Who's here, for both pages: the owner ID, how its sign-in is held, the sessions kept for the owner
/// page, the viewing setting, and the agents this computer set up.
async fn here(State(computer): State<Arc<Computer>>) -> Json<Value> {
    Json(json!({
        "here": computer.here(),
        "identity": computer.owner.kept_identity(),
        "sessions": computer.sessions_shown().await,
        "viewing": computer.viewing(),
        "agents": computer.agents_here(),
    }))
}

/// The owner page opened, which with `every_time` means viewing needs a touch again.
async fn opened(State(computer): State<Arc<Computer>>) -> Json<Value> {
    computer.page_opened().await;
    here(State(computer)).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Passphrase {
    #[serde(default)]
    passphrase: Option<String>,
}

/// The owner ID here, made the first time around a new sign-in: off the chip, a key file locked with
/// the passphrase given, and nothing without one.
async fn make_owner(
    State(computer): State<Arc<Computer>>,
    Json(body): Json<Passphrase>,
) -> Response {
    match computer.make_owner(body.passphrase).await {
        Ok(identity) => Json(json!({ "identity": identity })).into_response(),
        Err(failure) => refused(&failure.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToSign {
    inputs: Vec<String>,
    #[serde(default)]
    passphrase: Option<String>,
    /// The token of the signing session the page unlocked, in place of the passphrase.
    #[serde(default)]
    session: Option<String>,
}

/// The passphrase to sign with: the one given, or the one the page's signing session holds, for
/// what a session signs. `Err` with the response to give, for a session that has ended.
async fn passphrase_for(
    computer: &Computer,
    passphrase: Option<String>,
    session: Option<String>,
) -> Result<Option<String>, Response> {
    match (passphrase, session) {
        (Some(given), _) => Ok(Some(given)),
        (None, Some(token)) => computer.unlocked_with(&token).await.ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": LOCKED }))).into_response()
        }),
        (None, None) => Ok(None),
    }
}

const LOCKED: &str = "your controls locked, so unlock them again";
const ALWAYS_ASKS: &str = "where you get paid, your keys and your recovery are signed only with your passphrase, so type it";

/// What the page prepared, signed after the owner key's own prompt, written from exactly that.
async fn sign(State(computer): State<Arc<Computer>>, Json(body): Json<ToSign>) -> Response {
    if body.passphrase.is_none()
        && body.session.is_some()
        && !super::unlock::session_signs(&body.inputs)
    {
        return refused(ALWAYS_ASKS);
    }
    let passphrase = match passphrase_for(&computer, body.passphrase, body.session).await {
        Ok(passphrase) => passphrase,
        Err(locked) => return locked,
    };
    if let Err(why) = gated(&computer, passphrase.as_deref()) {
        return refused(why);
    }
    match computer.sign(body.inputs, passphrase).await {
        Ok(signed) => Json(signed).into_response(),
        Err(failure) => refused(&failure.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionsAt {
    hosts: Vec<String>,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    session: Option<String>,
}

async fn start_sessions(
    State(computer): State<Arc<Computer>>,
    Json(body): Json<SessionsAt>,
) -> Response {
    let passphrase = match passphrase_for(&computer, body.passphrase, body.session).await {
        Ok(passphrase) => passphrase,
        Err(locked) => return locked,
    };
    if let Err(why) = gated(&computer, passphrase.as_deref()) {
        return refused(why);
    }
    match computer.start_sessions(body.hosts, passphrase).await {
        Ok((sessions, code)) => Json(json!({ "sessions": sessions, "code": code })).into_response(),
        Err(failure) => refused(&failure.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadAt {
    domain: String,
    path: String,
}

/// A read at a host under the session kept here, answered with the host's own status and JSON.
async fn read(State(computer): State<Arc<Computer>>, Json(body): Json<ReadAt>) -> Response {
    match computer.read(&body.domain, &body.path).await {
        Ok(read) => {
            let status = StatusCode::from_u16(read.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response = (status, read.json).into_response();
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response
        }
        Err(_) => StatusCode::UNAUTHORIZED.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailFor {
    agent: splint_core::SplintId,
    address: String,
    kind: splint_core::host_api::OwnerMailKind,
    signed: String,
}

/// Something the page had this computer's sign-in sign for an agent's Signet: sealed here to the
/// agent and left at its host under the session kept there, and handed to its Signet straight where
/// that's reached from here. It answers as the relay answers for rules: 502 with the way it went
/// when only a straight answer took it and it's kept for the host, and 401 with no session at that
/// host, for the page to sign in again. Only this leaves owner mail anywhere for the page, as the
/// relay carries none.
async fn leave_mail(State(computer): State<Arc<Computer>>, Json(body): Json<MailFor>) -> Response {
    let left = computer
        .leave_mail(&body.agent, &body.address, body.kind, &body.signed)
        .await;
    match left {
        Ok(()) => Json(json!({})).into_response(),
        Err(NotLeft::NoSession) => StatusCode::UNAUTHORIZED.into_response(),
        Err(NotLeft::Failed(Failure::NotYetAtHost(_))) => {
            let route = crate::direct::last_reached(&computer.home, &body.agent)
                .map_or(crate::direct::Route::ThisComputer, |(route, _)| route);
            let mut response = (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": NOT_YET_AT_HOST })),
            )
                .into_response();
            response.headers_mut().insert(
                HeaderName::from_static("splint-route"),
                HeaderValue::from_static(route.word()),
            );
            response
        }
        Err(NotLeft::Failed(failure)) => refused(&failure.to_string()),
    }
}

/// Said when only a straight answer took something the owner signed, and its host couldn't take it
/// just now. The page says it in its own words.
const NOT_YET_AT_HOST: &str = "its Signet said it took that, but its host couldn't take it just now \
     to confirm it, so it's kept here and sent again until the host takes it";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    about: String,
    sealed: String,
}

/// What's sealed to the owner, opened here with the reading key, which never leaves this computer.
async fn open(State(computer): State<Arc<Computer>>, Json(body): Json<Sealed>) -> Response {
    match computer.open(body.about, body.sealed).await {
        Ok(plain) => Json(json!({ "plain": plain })).into_response(),
        Err(_) => refused("that doesn't open here"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewingBody {
    every: super::Viewing,
}

async fn set_viewing(
    State(computer): State<Arc<Computer>>,
    Json(body): Json<ViewingBody>,
) -> Response {
    match computer.set_viewing(body.every).await {
        Ok(()) => Json(json!({})).into_response(),
        Err(failure) => refused(&failure.to_string()),
    }
}

/// Unlocks the controls for the page that asks, with the passphrase or the chip's own prompt: sessions
/// at the hosts this computer knows, the page key, and a signing session whose token only this page
/// gets. It's how a page with no page key gets one, so it needs none, and wrong tries wait. A
/// chip's prompt turned down counts as a wrong try, so anything reaching this port can put the
/// prompt up only so often. That it can at all is a known gap: a person who touches a prompt they
/// didn't ask for gives the page key and reading, though each signature still asks again.
async fn unlock(State(computer): State<Arc<Computer>>, Json(body): Json<Passphrase>) -> Response {
    if computer.owner.kept_identity().is_none() {
        return refused("there's no owner ID on this computer yet, so set it up first");
    }
    // Before anything asks the sign-in, which starts the owner key.
    if computer.unlock_waits().await {
        return refused(super::unlock::TOO_MANY);
    }
    if let Err(why) = gated(&computer, body.passphrase.as_deref()) {
        return refused(why);
    }
    match computer.unlock(body.passphrase).await {
        Ok((sessions, session)) => Json(json!({
            "key": computer.page_key.expose(),
            "session": session,
            "sessions": sessions,
        }))
        .into_response(),
        Err(failure) => refused(&failure.to_string()),
    }
}

/// What unlocking will ask for, before a page has its key: whether there's a Splint ID here to unlock,
/// and whether the chip asks for itself. Nothing more, and it opens no prompt.
async fn unlock_asks(State(computer): State<Arc<Computer>>) -> Json<Value> {
    Json(json!({
        "set_up": computer.owner.kept_identity().is_some(),
        "chip": computer.owner.sign_in() == Some(SignIn::Chip) || computer.prompts_by_itself(),
    }))
}

/// Ends the signing session, so the next change asks again.
async fn lock(State(computer): State<Arc<Computer>>) -> Json<Value> {
    computer.lock().await;
    Json(json!({}))
}

async fn sign_out(State(computer): State<Arc<Computer>>) -> Json<Value> {
    computer.sign_out().await;
    Json(json!({}))
}

/// The recovery code, set now and shown to the page once, after the owner key's own prompt.
async fn recovery(State(computer): State<Arc<Computer>>, Json(body): Json<Passphrase>) -> Response {
    if let Err(why) = gated(&computer, body.passphrase.as_deref()) {
        // The terminal sets the code with a plain key file, which this page can't use.
        let plain = computer.owner.sign_in() == Some(SignIn::PlainFile);
        return refused(if plain { RECOVERY_IN_A_TERMINAL } else { why });
    }
    match computer.set_recovery(body.passphrase).await {
        Ok((code, identity)) => Json(json!({ "code": code, "identity": identity })).into_response(),
        Err(failure) => refused(&failure.to_string()),
    }
}

fn refused(why: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"error": why})),
    )
        .into_response()
}

async fn only_from_this_page(request: Request, next: Next) -> Response {
    let same_origin = request
        .headers()
        .get("sec-fetch-site")
        .is_some_and(|site| site == "same-origin");
    // A browser sends the page's own origin on a POST; any other is a page elsewhere.
    let origin_elsewhere = request.headers().get(ORIGIN).is_some_and(|origin| {
        origin.as_bytes() != format!("http://localhost:{}", port()).as_bytes()
    });
    if !same_origin
        || origin_elsewhere
        || (request.method() != Method::GET && request.method() != Method::POST)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

/// The header the page sends the page key in.
const PAGE_KEY: &str = "splint-page";

/// Every call under `/local` needs the page key, but handing over a link's ask, which only puts it in
/// front of the person, trading an opening for the key, and unlocking, which takes the passphrase.
async fn only_with_the_page_key(
    State(computer): State<Arc<Computer>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let open_to_any_page = path == "/local/unlock"
        || (request.method() == Method::POST && (path == "/local/asks" || path == "/local/page"));
    let keyed = request
        .headers()
        .get(PAGE_KEY)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|given| computer.is_page_key(given));
    if !(open_to_any_page || keyed) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

/// A request naming another host is a page elsewhere that renamed itself to reach this.
async fn only_this_address(request: Request, next: Next) -> Response {
    let named = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok());
    if named != Some(format!("localhost:{}", port()).as_str()) {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    next.run(request).await
}

async fn with_safety_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let fixed: [(HeaderName, &'static str); 6] = [
        (CONTENT_SECURITY_POLICY, POLICY),
        (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (X_FRAME_OPTIONS, "DENY"),
        (REFERRER_POLICY, "no-referrer"),
        (CACHE_CONTROL, "no-store"),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
    ];
    for (name, value) in fixed {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

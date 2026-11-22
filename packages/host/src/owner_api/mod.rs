//! The Owner API: what Splint on an owner's computer uses to reach their agents. See "Owner API" in
//! `docs/protocol.md`, which lists every call and which module serves it.
//!
//! Every call is authorized by a signature, never by where it comes from, so a page at any origin may
//! make one, and a browser is told so: the controls page on an owner's computer is at `localhost`.
//! Reads of what's kept for an owner take their session or their own key ([`reader`]), and what
//! changes anything takes an object the owner signed.
//!
//! A host serves no owner page of its own. Nenye decided on 2026-11-21 that owners sign only on their
//! own computers, as whoever serves the page a passkey signs on chooses what a touch signs (issue 635).

pub mod agents;
pub mod reader;

use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, CACHE_CONTROL, CONTENT_SECURITY_POLICY,
    CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::Host;

/// The paths an owner's page calls, at its own host and at each of its agents' hosts. A path here is
/// open to scripts on any origin, which changes nothing, as each call stands on its signature.
const OWNER_API_PATHS: [&str; 15] = [
    "/.well-known/splint/host",
    "/.well-known/splint/agents/",
    "/v0/release",
    "/v0/join-answers",
    "/v0/owners/",
    "/v0/owner-agents/",
    "/v0/owner-handles/",
    "/v0/owner-view/",
    "/v0/owner-mail/",
    "/v0/rules",
    "/v0/refused/",
    "/v0/retirements",
    "/v0/revocations",
    "/v0/recoveries",
    "/v0/changes/accepted",
];

/// What hosts kept only for the page they no longer serve: pairing codes' mailboxes, which last
/// minutes, and copies of a reading key sealed to a passkey's PRF, which only that page could open.
pub const RETIRED_SCHEMA: &str = "
    DROP TABLE IF EXISTS pairings;
    DROP TABLE IF EXISTS owner_reading_keys;
";

/// Where the page was, plain words for whoever follows a link an older agent gave them. Plain text
/// runs nothing, and the policy asks the browser for nothing either, a passkey least of all.
const OLD_PAGE_WORDS: &str = "Splint hosts no longer serve an owner page. Your controls are in \
Splint on your own computer. Ask your agent for its link to them, with the line that installs \
Splint if you don't have it yet.\n";

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .merge(agents::routes())
        .route("/owner", get(old_page))
}

async fn old_page() -> Response {
    (
        [
            (CONTENT_TYPE, "text/plain; charset=utf-8"),
            (
                CONTENT_SECURITY_POLICY,
                "default-src 'none'; frame-ancestors 'none'",
            ),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (CACHE_CONTROL, "no-store"),
        ],
        OLD_PAGE_WORDS,
    )
        .into_response()
}

fn is_owner_api(path: &str) -> bool {
    OWNER_API_PATHS.iter().any(|open| path.starts_with(open))
}

/// Says to a browser that a page anywhere may call the Owner API, with no cookies, as none are used,
/// and answers its question first for calls that carry a signature in a header.
pub async fn open_to_any_page(request: Request, next: Next) -> Response {
    let open = is_owner_api(request.uri().path());
    let mut response = if open && request.method() == Method::OPTIONS {
        let mut asked = StatusCode::NO_CONTENT.into_response();
        let headers = asked.headers_mut();
        headers.insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, PUT, POST, DELETE"),
        );
        headers.insert(
            ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(
                "authorization, content-type, splint-owner-session, splint-protocol",
            ),
        );
        headers.insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
        asked
    } else {
        next.run(request).await
    };
    if open {
        let headers = response.headers_mut();
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        headers.insert(
            ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("splint-protocol, splint-refusal"),
        );
    }
    response
}

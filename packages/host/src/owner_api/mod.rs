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

/// Where the page was, in plain words, for whoever follows a link an older agent gave them. It's styled
/// like every page a person sees, from the host's own stylesheets, and runs nothing: the policy lets in
/// nothing but those, and asks the browser for nothing, a passkey least of all.
const OLD_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<title>Splint</title>
<link rel="stylesheet" href="/tokens.css">
<link rel="stylesheet" href="/guest.css">
</head>
<body>
<main>
<p class="brand"><svg class="mark" viewBox="0 0 31.86 48.00" width="20" height="30" aria-hidden="true"><path class="k1" d="M11.34 36.40L11.40 36.42L11.46 36.43L11.53 36.42L11.59 36.40L11.64 36.36L11.68 36.31L11.70 36.25L11.71 36.18L11.71 32.32L11.70 32.26L11.68 32.20L11.64 32.15L11.59 32.11L6.26 29.03L6.19 29.00L6.13 28.99L6.07 29.00L6.01 29.03L5.95 29.07L5.91 29.12L5.89 29.18L5.88 29.24L5.88 33.10L5.89 33.17L5.91 33.23L5.95 33.28L6.01 33.32Z"/><path class="k1" d="M17.97 45.59L18.03 45.62L18.10 45.62L18.16 45.62L18.22 45.59L18.27 45.55L18.31 45.50L18.34 45.44L18.35 45.37L18.35 36.15L18.34 36.09L18.31 36.03L18.27 35.98L18.22 35.94L12.89 32.86L12.83 32.83L12.76 32.82L12.70 32.83L12.64 32.86L12.59 32.90L12.55 32.95L12.52 33.01L12.51 33.07L12.51 42.29L12.52 42.36L12.55 42.42L12.59 42.47L12.64 42.51Z"/><path class="k2" d="M19.15 45.37L19.16 45.44L19.18 45.50L19.22 45.55L19.27 45.59L19.33 45.62L19.40 45.62L19.46 45.62L19.52 45.59L25.85 41.94L25.90 41.90L25.94 41.85L25.97 41.79L25.98 41.72L25.98 32.50L25.97 32.43L25.94 32.37L25.90 32.32L25.85 32.28L25.79 32.26L25.73 32.25L25.66 32.26L25.60 32.28L19.27 35.94L19.22 35.98L19.18 36.03L19.16 36.09L19.15 36.15Z"/><path class="t3" d="M27.15 20.79L27.09 20.77L27.03 20.76L26.96 20.77L26.90 20.79L26.85 20.83L26.81 20.88L26.78 20.94L26.78 21.01L26.78 22.41L18.75 27.05L11.91 23.10L5.08 19.16L5.08 17.75L5.07 17.69L5.05 17.63L5.01 17.58L4.96 17.54L4.89 17.51L4.83 17.50L4.77 17.51L4.71 17.54L2.68 18.71L2.62 18.75L2.58 18.80L2.56 18.86L2.55 18.93L2.56 18.99L2.58 19.05L2.62 19.10L2.68 19.14L18.62 28.35L18.68 28.37L18.75 28.38L18.81 28.37L18.87 28.35L29.18 22.40L29.23 22.36L29.27 22.31L29.30 22.25L29.31 22.18L29.30 22.12L29.27 22.06L29.23 22.00L29.18 21.96Z"/><path class="t1" d="M17.97 34.87L18.03 34.89L18.10 34.90L18.16 34.89L18.22 34.87L18.27 34.83L18.31 34.78L18.34 34.72L18.35 34.65L18.35 29.26L18.34 29.19L18.31 29.13L18.27 29.08L18.22 29.04L2.27 19.83L2.21 19.81L2.15 19.80L2.09 19.81L2.02 19.83L1.97 19.87L1.93 19.93L1.91 19.99L1.90 20.05L1.90 25.44L1.91 25.51L1.93 25.57L1.97 25.62L2.02 25.66Z"/><path class="t2" d="M29.96 23.31L29.95 23.24L29.92 23.18L29.88 23.13L29.83 23.09L29.77 23.07L29.71 23.06L29.64 23.07L29.58 23.09L19.27 29.04L19.22 29.08L19.18 29.13L19.16 29.19L19.15 29.26L19.15 34.65L19.16 34.72L19.18 34.78L19.22 34.83L19.27 34.87L19.33 34.89L19.40 34.90L19.46 34.89L19.52 34.87L29.83 28.92L29.88 28.88L29.92 28.82L29.95 28.76L29.96 28.70Z"/><path class="k1" d="M11.34 21.85L11.40 21.87L11.46 21.88L11.53 21.87L11.59 21.85L11.64 21.81L11.68 21.75L11.70 21.69L11.71 21.63L11.71 10.11L11.70 10.04L11.68 9.98L11.64 9.93L11.59 9.89L6.26 6.81L6.19 6.79L6.13 6.78L6.07 6.79L6.01 6.81L5.95 6.85L5.91 6.91L5.89 6.97L5.88 7.03L5.88 18.55L5.89 18.61L5.91 18.68L5.95 18.73L6.01 18.77Z"/><path class="k2" d="M12.51 13.97L12.52 14.03L12.55 14.09L12.59 14.15L12.64 14.19L12.70 14.21L12.76 14.22L12.83 14.21L12.89 14.19L19.22 10.53L19.27 10.49L19.31 10.44L19.33 10.38L19.34 10.32L19.34 6.46L19.33 6.39L19.31 6.33L19.27 6.28L19.22 6.24L19.16 6.21L19.09 6.21L19.03 6.21L18.97 6.24L12.64 9.89L12.59 9.93L12.55 9.98L12.52 10.04L12.51 10.11Z"/><path class="k3" d="M6.66 5.69L6.60 5.73L6.56 5.78L6.54 5.84L6.53 5.90L6.54 5.97L6.56 6.03L6.60 6.08L6.66 6.12L11.99 9.20L12.05 9.22L12.11 9.23L12.18 9.22L12.24 9.20L18.57 5.55L18.62 5.51L18.66 5.45L18.68 5.39L18.69 5.33L18.68 5.27L18.66 5.20L18.62 5.15L18.57 5.11L13.23 2.03L13.17 2.01L13.11 2.00L13.04 2.01L12.98 2.03Z"/><path class="k1" d="M17.97 25.68L18.03 25.70L18.10 25.71L18.16 25.70L18.22 25.68L18.27 25.64L18.31 25.58L18.34 25.52L18.35 25.46L18.35 19.30L18.34 19.24L18.31 19.18L18.27 19.12L18.22 19.08L12.89 16.01L12.83 15.98L12.76 15.97L12.70 15.98L12.64 16.01L12.59 16.04L12.55 16.10L12.52 16.16L12.51 16.22L12.51 22.38L12.52 22.44L12.55 22.51L12.59 22.56L12.64 22.60Z"/><path class="k2" d="M19.15 25.46L19.16 25.52L19.18 25.58L19.22 25.64L19.27 25.68L19.33 25.70L19.40 25.71L19.46 25.70L19.52 25.68L25.85 22.02L25.90 21.98L25.94 21.93L25.97 21.87L25.98 21.81L25.98 15.65L25.97 15.58L25.94 15.52L25.90 15.47L25.85 15.43L25.79 15.41L25.73 15.40L25.66 15.41L25.60 15.43L19.27 19.08L19.22 19.12L19.18 19.18L19.16 19.24L19.15 19.30Z"/><path class="k3" d="M19.87 11.23L19.81 11.20L19.74 11.19L19.68 11.20L19.62 11.23L13.29 14.88L13.24 14.92L13.20 14.97L13.17 15.03L13.16 15.10L13.17 15.16L13.20 15.22L13.24 15.27L13.29 15.31L18.62 18.39L18.68 18.42L18.75 18.42L18.81 18.42L18.87 18.39L25.20 14.74L25.25 14.70L25.29 14.65L25.32 14.59L25.33 14.52L25.32 14.46L25.29 14.40L25.25 14.34L25.20 14.30Z"/></svg>Splint</p>
<h1>Your controls are on your own computer</h1>
<p class="hint">Hosts don't serve them. Ask your agent to open your Splint controls. If Splint isn't on your computer yet, your agent gives you the line that installs it.</p>
</main>
</body>
</html>
"#;

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .merge(agents::routes())
        .route("/owner", get(old_page))
}

async fn old_page() -> Response {
    (
        [
            (CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; \
                 frame-ancestors 'none'",
            ),
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (CACHE_CONTROL, "no-store"),
        ],
        OLD_PAGE,
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

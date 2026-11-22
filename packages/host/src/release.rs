//! What this host says it runs, and the protocol it holds callers to. Kept apart from the routes that
//! carry messages, as it only concerns compatibility: a changed host can say anything here, so
//! nothing that protects anyone rests on it.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use splint_core::release::{
    Behind, OtherProtocol, PROTOCOL, PROTOCOL_HEADER, PROTOCOLS_HEADER, RELEASE_PATH, Release,
    SPOKEN, check_protocol,
};

use crate::Host;
use crate::api_error::REFUSAL_HEADER;

/// The refusal word for a caller on another protocol.
const OTHER_PROTOCOL: &str = "other_protocol";

pub fn routes(release: Release) -> Router<Arc<Host>> {
    Router::new().route(RELEASE_PATH, get(move || async move { Json(release) }))
}

/// Sent on every call this host makes, so a peer on another protocol can refuse it.
pub fn caller_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    say_protocol(&mut headers, PROTOCOL);
    headers
}

/// The number a call or answer is written in, and every protocol this host speaks.
fn say_protocol(headers: &mut HeaderMap, written: u32) {
    headers.insert(
        HeaderName::from_static(PROTOCOL_HEADER),
        HeaderValue::from(written),
    );
    if let Ok(spoken) = HeaderValue::try_from(SPOKEN.header_value()) {
        headers.insert(HeaderName::from_static(PROTOCOLS_HEADER), spoken);
    }
}

/// What the other side said of its protocol, as [`check_protocol`] reads it.
fn said(headers: &HeaderMap) -> Result<u32, OtherProtocol> {
    check_protocol(
        headers.get(PROTOCOL_HEADER).map(HeaderValue::as_bytes),
        headers.get(PROTOCOLS_HEADER).map(HeaderValue::as_bytes),
    )
}

/// Whether a peer's answer says it speaks another protocol.
pub fn says_other_protocol(headers: &HeaderMap) -> Option<OtherProtocol> {
    said(headers).err()
}

#[derive(Serialize)]
struct Refusal {
    error: String,
    protocol: u32,
}

/// Refuses a caller that says it speaks another protocol, before any route reads its body, and says
/// on every answer which protocols this host speaks. An answer is written in the caller's number,
/// so a caller from before ranges, which checks for its own number, reads it.
pub async fn one_protocol(request: Request, next: Next) -> Response {
    let (mut response, written) = match said(request.headers()) {
        Ok(written) => (next.run(request).await, written),
        Err(other) => {
            let refusal = Refusal {
                error: refused(other),
                protocol: PROTOCOL,
            };
            let response = (
                StatusCode::BAD_REQUEST,
                [(REFUSAL_HEADER, OTHER_PROTOCOL)],
                Json(refusal),
            )
                .into_response();
            (response, PROTOCOL)
        }
    };
    say_protocol(response.headers_mut(), written);
    response
}

/// Words a caller's agent can pass to its person, or to whoever runs this host, saying who updates.
fn refused(other: OtherProtocol) -> String {
    match other {
        OtherProtocol::NoneShared {
            theirs,
            behind: Behind::Ours,
        } => format!(
            "this host speaks Splint protocol {SPOKEN} and the caller only newer protocol {theirs}, \
             so this host is behind and has to update: tell whoever runs it"
        ),
        OtherProtocol::NoneShared {
            theirs,
            behind: Behind::Theirs,
        } => format!(
            "this host speaks Splint protocol {SPOKEN} and the caller only older protocol {theirs}, \
             so the caller is behind and has to update to a newer Splint release"
        ),
        OtherProtocol::WrittenInAnother { written, shared } => format!(
            "this host doesn't read Splint protocol {written}, and both speak protocol {shared}, so \
             send it again in that"
        ),
        OtherProtocol::Unreadable => format!("{other}, so one of them has to update first"),
    }
}

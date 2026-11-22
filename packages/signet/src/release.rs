//! What this Signet says it runs, and the protocol it holds its callers and its host to. Only for
//! compatibility: a changed Signet can say anything here, so nothing that protects anyone rests on it.

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

/// Needs no token, as it's what any program on this machine could read from the file.
pub fn routes(release: Release) -> Router {
    Router::new().route(RELEASE_PATH, get(move || async move { Json(release) }))
}

/// Sent on every call to the host, so a host on another protocol refuses it.
pub fn caller_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    say_protocol(&mut headers, PROTOCOL);
    headers
}

/// The number a call or answer is written in, and every protocol this Signet speaks.
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

/// Whether the host's answer says it speaks another protocol.
pub fn host_speaks_other(headers: &HeaderMap) -> Option<OtherProtocol> {
    said(headers).err()
}

#[derive(Serialize)]
struct Refusal {
    error: String,
    protocol: u32,
}

/// Refuses a caller that says it speaks another protocol, such as a `splint` from a newer release
/// while this Signet still runs the old one, and says on every answer which protocols this speaks.
/// An answer is written in the caller's number, so a caller from before ranges reads it.
pub async fn one_protocol(request: Request, next: Next) -> Response {
    let (mut response, written) = match said(request.headers()) {
        Ok(written) => (next.run(request).await, written),
        Err(other) => {
            let refusal = Refusal {
                error: refused(other),
                protocol: PROTOCOL,
            };
            (
                (StatusCode::BAD_REQUEST, Json(refusal)).into_response(),
                PROTOCOL,
            )
        }
    };
    say_protocol(response.headers_mut(), written);
    response
}

/// A Signet and its callers come from one release, so restarting from the newest settles it.
fn refused(other: OtherProtocol) -> String {
    match other {
        OtherProtocol::NoneShared {
            theirs,
            behind: Behind::Ours,
        } => format!(
            "this Signet speaks Splint protocol {SPOKEN} and its caller only newer protocol \
             {theirs}, so this Signet is behind: restart it from the newest release"
        ),
        OtherProtocol::NoneShared {
            theirs,
            behind: Behind::Theirs,
        } => format!(
            "this Signet speaks Splint protocol {SPOKEN} and its caller only older protocol \
             {theirs}, so the caller is behind: use the splint installed beside this Signet"
        ),
        OtherProtocol::WrittenInAnother { .. } | OtherProtocol::Unreadable => {
            format!("{other}, so restart Signet from the same release as its caller")
        }
    }
}

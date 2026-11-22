//! How much of its callers' bodies Signet holds at once.
//!
//! Every route reads its whole body before it checks anything inside, and an owner's route checks the
//! owner's signature from the body, so any program that can reach the socket makes Signet read. Each
//! body has a limit, and so do all of them together: past that a call is told to try again, rather
//! than Signet holding as many as come at once. A body has a deadline too, so one held back gives its
//! room back.
//!
//! This is the same as a host does for its callers, scaled to the one agent and owner a Signet
//! serves.

use std::future::poll_fn;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::RETRY_AFTER;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// What the web framework allowed a route anyway, and more than any call of an agent or owner needs.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Eight of the largest bodies at once, which an agent and an owner don't come near. Provisional.
const MAX_BODY_BYTES_HELD: usize = 16 * 1024 * 1024;
/// Plenty for the largest body from a program on the same machine.
const BODY_DEADLINE: Duration = Duration::from_secs(10);

/// The room for bodies, shared by every call.
#[derive(Clone)]
pub struct BodyRoom(Arc<Semaphore>);

impl Default for BodyRoom {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(MAX_BODY_BYTES_HELD)))
    }
}

enum NoBody {
    TooLarge,
    TooMuchHeld,
    /// The caller hung up, or the framing was wrong.
    Unreadable,
}

/// Reads the whole body, within its share of the room, and keeps that share until the call is answered.
pub async fn hold_bodies(State(room): State<BodyRoom>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let (body, _held) = match tokio::time::timeout(BODY_DEADLINE, read_body(body, &room.0)).await {
        Ok(Ok(read)) => read,
        Ok(Err(NoBody::TooLarge)) => return refused(StatusCode::PAYLOAD_TOO_LARGE),
        Ok(Err(NoBody::TooMuchHeld)) => return busy(StatusCode::SERVICE_UNAVAILABLE),
        Ok(Err(NoBody::Unreadable)) => return refused(StatusCode::BAD_REQUEST),
        Err(_) => return busy(StatusCode::REQUEST_TIMEOUT),
    };
    next.run(Request::from_parts(parts, Body::from(body))).await
}

/// A body that says its length takes its room for all of it before any of it is read, so a caller past
/// the room is answered before Signet reads anything, and what's read is never copied to grow. One that
/// doesn't say takes room as it comes.
async fn read_body(
    body: Body,
    room: &Arc<Semaphore>,
) -> Result<(Bytes, Option<OwnedSemaphorePermit>), NoBody> {
    let declared = body.size_hint().exact();
    if declared == Some(0) {
        return Ok((Bytes::new(), None));
    }
    if body
        .size_hint()
        .upper()
        .is_some_and(|size| usize::try_from(size).unwrap_or(usize::MAX) > MAX_BODY_BYTES)
    {
        return Err(NoBody::TooLarge);
    }
    let take = |bytes: usize| {
        let bytes = u32::try_from(bytes).map_err(|_| NoBody::TooLarge)?;
        room.clone()
            .try_acquire_many_owned(bytes)
            .map_err(|_| NoBody::TooMuchHeld)
    };
    let declared = declared.and_then(|size| usize::try_from(size).ok());
    let (mut read, mut held) = match declared {
        Some(size) => (Vec::with_capacity(size), Some(take(size)?)),
        None => (Vec::new(), None),
    };
    let limit = declared.unwrap_or(MAX_BODY_BYTES);
    let mut body = pin!(body);
    while let Some(frame) = poll_fn(|context| body.as_mut().poll_frame(context)).await {
        let Ok(data) = frame.map_err(|_| NoBody::Unreadable)?.into_data() else {
            continue;
        };
        if read.len() + data.len() > limit {
            return Err(NoBody::TooLarge);
        }
        if declared.is_none() {
            let place = take(data.len())?;
            match &mut held {
                Some(all) => all.merge(place),
                None => held = Some(place),
            }
        }
        read.extend_from_slice(&data);
    }
    Ok((read.into(), held))
}

fn refused(status: StatusCode) -> Response {
    (status, Json(json!({"error": "couldn't read that request"}))).into_response()
}

fn busy(status: StatusCode) -> Response {
    (
        status,
        [(RETRY_AFTER, "1")],
        Json(json!({"error": "try again"})),
    )
        .into_response()
}

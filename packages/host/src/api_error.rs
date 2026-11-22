use axum::Json;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use splint_core::DeliveryFailure;

/// Set when a host says the envelope itself is at fault, or that it doesn't take deliveries from the
/// sending host, and not on any other refusal. A status alone can't say this: a 400 can also mean a
/// proof that doesn't fit, which is usually a setup mistake, and either can come from a proxy. A
/// sending host shows it to the sender as the reason and goes on retrying.
pub const REFUSAL_HEADER: &str = "splint-refusal";

/// Set when a message was taken but won't reach the agent yet, or at all. Held and dropped look the
/// same from outside, so a sender can't detect a block.
pub const ADMISSION_HEADER: &str = "splint-admission";
pub const QUARANTINED: &str = "quarantined";

/// Postgres's code for text it can't hold, which is a NUL anywhere in a string.
const INVALID_TEXT: &str = "22021";

/// A refusal from the web framework is plain text, and can quote the request back, types and all. This
/// is the one place that sees all of them, so a new route can't forget. Ours are always JSON.
pub async fn fixed_words_only(response: Response) -> Response {
    let plain = HeaderValue::from_static("text/plain; charset=utf-8");
    if response.status().is_success() || response.headers().get(CONTENT_TYPE) != Some(&plain) {
        return response;
    }
    let error = ErrorBody {
        error: "couldn't read that request".to_owned(),
    };
    (response.status(), Json(error)).into_response()
}

/// What a caller is told when a request fails. It never includes message content.
pub enum ApiError {
    Rejected(splint_core::Error),
    /// An envelope or sender identity that can't be valid, whenever it's retried.
    Malformed(splint_core::Error),
    BadRequest(&'static str),
    Unauthorized,
    Forbidden(&'static str),
    /// A delivery from a host this one doesn't exchange with: it's private and doesn't name that host,
    /// or it blocks it. Said with a fixed word, so the sending agent learns this host is closed to it.
    NotAPeer,
    NotFound,
    Conflict,
    /// A copy of an owner's ID that parts ways with the one held and doesn't win: it has to be signed
    /// again on top of what's held, or settled by a recovery.
    Stale,
    /// What this agent's Signet holds is behind what this host holds, after a recovery or a revocation
    /// its owner hasn't told it about. Its Signet has to stay up to hear, unlike a retired agent's.
    OutOfDate(&'static str),
    /// A limit in `docs/protocol.md`, which time or an owner clearing a backlog will lift.
    TooMany(&'static str),
    /// A limit on new agents, said by which, in fixed words, so the agent can tell its person.
    AtJoinLimit(splint_core::host_api::JoinLimit),
    /// A signup code with no unused match here, said in a fixed word, so the agent can ask for another.
    SignupCodeRefused,
    /// Part of an interaction this host hasn't seen start, from someone who isn't a contact. Either it
    /// overtook what came before, which time fixes, or there's nothing before it. Its sending host keeps
    /// trying until it expires, so the cost of a made-up one stays with the host that carried it.
    TooEarly,
    Unavailable,
    /// The room for answers is full, in all or for this caller, which a moment lifts.
    NoRoomToAnswer(crate::answers::Full),
    /// The dates on a message or proof don't fit this host's clock. That can be fixed by time
    /// or by correcting a clock, so the sender should retry rather than give up.
    ClockSkew,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl From<splint_core::Error> for ApiError {
    fn from(error: splint_core::Error) -> Self {
        match error {
            splint_core::Error::Expired | splint_core::Error::FromTheFuture => Self::ClockSkew,
            other => Self::Rejected(other),
        }
    }
}

impl ApiError {
    /// What went wrong, for an owner's record, if it's a refusal of what was sent. These are this
    /// program's own words.
    pub fn refusal_word(&self) -> Option<&'static str> {
        match self {
            Self::Forbidden(word) | Self::TooMany(word) => Some(word),
            Self::Malformed(_) => Some("malformed"),
            _ => None,
        }
    }

    /// For an error from checking the envelope itself. Its dates can still come to fit, so those
    /// stay retryable like any others.
    pub fn malformed(error: splint_core::Error) -> Self {
        match Self::from(error) {
            Self::Rejected(error) => Self::Malformed(error),
            retryable => retryable,
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        // Only ever what a caller sent, so nothing here is wrong and trying again won't help.
        let code = error.as_database_error().and_then(|error| error.code());
        if code.as_deref() == Some(INVALID_TEXT) {
            return Self::BadRequest("that isn't valid text");
        }
        tracing::error!(%error, "database error");
        Self::Unavailable
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Malformed(error) => {
                let refusal = [(REFUSAL_HEADER, DeliveryFailure::Malformed.as_str())];
                let body = Json(ErrorBody {
                    error: error.to_string(),
                });
                return (StatusCode::BAD_REQUEST, refusal, body).into_response();
            }
            Self::NotAPeer => {
                let refusal = [(REFUSAL_HEADER, DeliveryFailure::NotAPeer.as_str())];
                let body = Json(ErrorBody {
                    error: "this host doesn't take deliveries from yours".to_owned(),
                });
                return (StatusCode::FORBIDDEN, refusal, body).into_response();
            }
            Self::Rejected(error) => (StatusCode::BAD_REQUEST, error.to_string()),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message.to_owned()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_owned()),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, message.to_owned()),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".to_owned()),
            Self::Conflict => (StatusCode::CONFLICT, "already taken".to_owned()),
            Self::Stale => (StatusCode::CONFLICT, "stale".to_owned()),
            Self::OutOfDate(message) => (StatusCode::LOCKED, message.to_owned()),
            Self::TooMany(message) => (StatusCode::TOO_MANY_REQUESTS, message.to_owned()),
            Self::AtJoinLimit(limit) => {
                let which = [(splint_core::host_api::JoinLimit::HEADER, limit.word())];
                let body = Json(ErrorBody {
                    error: limit.sentence().to_owned(),
                });
                return (StatusCode::TOO_MANY_REQUESTS, which, body).into_response();
            }
            Self::SignupCodeRefused => {
                use splint_core::host_api::SignupCodeRefused;
                let which = [(SignupCodeRefused::HEADER, SignupCodeRefused::WORD)];
                let body = Json(ErrorBody {
                    error: SignupCodeRefused::SENTENCE.to_owned(),
                });
                return (StatusCode::FORBIDDEN, which, body).into_response();
            }
            Self::NoRoomToAnswer(full) => return full.into_response(),
            Self::TooEarly => (StatusCode::TOO_EARLY, "try again".to_owned()),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "try again".to_owned()),
            Self::ClockSkew => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dates don't fit".to_owned(),
            ),
        };
        (status, Json(ErrorBody { error: message })).into_response()
    }
}

//! One-use links: someone with no account and no agent answers one request.
//!
//! A host carries these and judges nothing a reader has to believe. It serves the page, keeps the steps
//! of each link and hands a guest's to the agent that made it, whose Signet checks them under the key
//! the owner signed for. They never touch the inbox, its rules or its quotas, as a guest is nobody's
//! contact, and what a guest may do is settled by the owner's signature on this one offer.
//!
//! The page comes from a host, so a host that lies can take the key in the link's fragment, and answer
//! as the guest. That gets it no more than the offer the owner signed, and a result that says `link`.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use splint_core::host_api::{GuestAnswer, GuestLink, GuestOutbound, GuestStepRow, GuestSteps};
use splint_core::requests::{
    GuestForm, StepKind, check_agents_step_on_a_link, guest_open_at_host, guest_step_of,
};
use splint_core::{Identity, VerifiedEnvelope, claimed_sender, unix_now};
use sqlx::{Postgres, Row, Transaction};

use crate::api_error::ApiError;
use crate::{Host, answers, database, inbox, registry};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS guest_links (
        request_id TEXT PRIMARY KEY,
        agent TEXT NOT NULL,
        guest TEXT NOT NULL,
        guest_identity TEXT NOT NULL,
        form TEXT NOT NULL,
        open_envelope TEXT NOT NULL,
        deadline BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS guest_links_agent ON guest_links (agent);
    CREATE INDEX IF NOT EXISTS guest_links_deadline ON guest_links (deadline);
    CREATE TABLE IF NOT EXISTS guest_steps (
        seq BIGSERIAL PRIMARY KEY,
        message_id TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL REFERENCES guest_links (request_id) ON DELETE CASCADE,
        from_guest BOOLEAN NOT NULL,
        kind TEXT NOT NULL,
        envelope TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS guest_steps_link ON guest_steps (request_id, seq);
";

const PAGE: &str = include_str!("page.html");
const SCRIPT: &str = include_str!("guest.js");
const STYLE: &str = include_str!("guest.css");

/// Nothing runs or loads unless it's this page's own script and style, and it talks only to this host.
const CONTENT_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; \
require-trusted-types-for 'script'";

/// Waiting for answers at once from one agent. Each one is a page anyone holding its link can read, so
/// this keeps a host from being used to serve many. An owner can wait for a good few.
const MAX_LIVE_LINKS_PER_AGENT: i64 = 32;
/// An answer, and a `cancel` after it.
const MAX_STEPS_FROM_A_GUEST: i64 = 2;
/// A `confirm`, or a `decline` or `cancel`, and anything a stolen key adds is stopped here.
const MAX_STEPS_FROM_THE_AGENT: i64 = 8;
/// Past any step a link can carry, as a step is 4 KiB at most.
const MAX_ENVELOPE_CHARS: usize = 16 * 1024;
/// How long a page can still show how things ended, after which the link just isn't there.
const KEEP_AFTER_DEADLINE_SECS: i64 = 7 * 24 * 60 * 60;
const PAGE_SIZE: i64 = 100;

pub fn routes() -> Router<Arc<Host>> {
    let page = Router::new()
        .route(
            "/g/{request}",
            get(|| async { file("text/html; charset=utf-8", PAGE) }),
        )
        .route(
            "/guest.js",
            get(|| async { file("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/guest.css",
            get(|| async { file("text/css; charset=utf-8", STYLE) }),
        )
        .route("/v0/guest/links/{request}", get(read_link).post(answer))
        .route_layer(middleware::from_fn(with_safety_headers));
    Router::new()
        .merge(page)
        .route("/v0/guest/outbound", post(from_agent))
        .route("/v0/guest/steps/{after}", get(steps_for_agent))
}

fn file(kind: &'static str, content: &'static str) -> Response {
    ([(CONTENT_TYPE, kind)], content).into_response()
}

/// The key is in the fragment, which a browser never sends, and this keeps the address itself from
/// going anywhere too.
async fn with_safety_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let fixed: [(HeaderName, &'static str); 5] = [
        (CONTENT_SECURITY_POLICY, CONTENT_POLICY),
        (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (X_FRAME_OPTIONS, "DENY"),
        (REFERRER_POLICY, "no-referrer"),
        (CACHE_CONTROL, "no-store"),
    ];
    for (name, value) in fixed {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

fn word_of(kind: StepKind) -> Result<String, ApiError> {
    let word = serde_json::to_value(kind).map_err(|_| ApiError::Unavailable)?;
    Ok(word.as_str().unwrap_or_default().to_owned())
}

/// Takes a step on a link from the agent that made it. The first has to be an `open` carrying its owner's
/// yes, checked here under the key this host holds for that owner, so nothing an agent can do alone
/// gets a page served.
async fn from_agent(
    State(host): State<Arc<Host>>,
    Json(step): Json<GuestOutbound>,
) -> Result<StatusCode, ApiError> {
    if step.envelope.len() > MAX_ENVELOPE_CHARS {
        return Err(ApiError::BadRequest("that's too long for a link"));
    }
    let sender = claimed_sender(&step.envelope)?;
    let identity = registry::identity_of(&host, &sender)
        .await?
        .ok_or(ApiError::Forbidden("sender isn't registered here"))?;
    let envelope = VerifiedEnvelope::verify(&step.envelope, &identity, unix_now())?;
    let opens = splint_core::requests::request_of(&envelope)
        .map_err(|_| ApiError::BadRequest("that isn't a step"))?
        .is_some_and(|step| step.opens.is_some());
    if opens {
        open_link(&host, &envelope, &step, &identity).await?;
    } else {
        agent_step(&host, &envelope, &identity).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn open_link(
    host: &Host,
    envelope: &VerifiedEnvelope,
    step: &GuestOutbound,
    agent: &Identity,
) -> Result<(), ApiError> {
    let guest = Identity::guest_from_encoded(&step.guest_identity)
        .map_err(|_| ApiError::BadRequest("that isn't a guest's identity"))?;
    if !step.form.fits() {
        return Err(ApiError::BadRequest(
            "that isn't what a link's page can draw",
        ));
    }
    let form = serde_json::to_string(&step.form).map_err(|_| ApiError::Unavailable)?;
    let owner: String = sqlx::query_scalar("SELECT owner_identity FROM agents WHERE id = $1")
        .bind(envelope.sender().as_str())
        .fetch_one(&host.db)
        .await?;
    let owner = Identity::from_encoded(&owner)?;
    let open = guest_open_at_host(envelope, &guest, &owner).map_err(|refused| {
        tracing::info!(message_id = %envelope.id(), %refused, "refused a link");
        ApiError::Forbidden("a link needs its owner's yes to exactly this offer")
    })?;
    let now = i64::try_from(unix_now()).unwrap_or(i64::MAX);
    let deadline = i64::try_from(open.deadline).unwrap_or(i64::MAX);
    let mut transaction = database::begin(&host.db).await?;
    if !registry::hold_off_retirement(&mut transaction, agent).await? {
        return Err(ApiError::Forbidden("sender isn't registered here"));
    }
    let stored = sqlx::query(
        "INSERT INTO guest_links
             (request_id, agent, guest, guest_identity, form, open_envelope, deadline)
         SELECT $1, $2, $3, $4, $5, $6, $7
         WHERE (SELECT count(*) FROM guest_links WHERE agent = $2 AND deadline > $8) < $9
         ON CONFLICT (request_id) DO NOTHING",
    )
    .bind(open.request.as_str())
    .bind(envelope.sender().as_str())
    .bind(guest.id().as_str())
    .bind(guest.encoded())
    .bind(&form)
    .bind(envelope.compact())
    .bind(deadline)
    .bind(now)
    .bind(MAX_LIVE_LINKS_PER_AGENT)
    .execute(&mut *transaction)
    .await?;
    if stored.rows_affected() == 0 {
        let here: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM guest_links WHERE request_id = $1)")
                .bind(open.request.as_str())
                .fetch_one(&mut *transaction)
                .await?;
        if !here {
            return Err(ApiError::TooMany("this agent has too many links waiting"));
        }
    }
    transaction.commit().await?;
    Ok(())
}

/// A later step from the agent's side: a `confirm`, or a `decline` or `cancel`. A `received` isn't one,
/// as a guest has nothing to do with it. A reader judges the rest.
async fn agent_step(
    host: &Host,
    envelope: &VerifiedEnvelope,
    agent: &Identity,
) -> Result<(), ApiError> {
    let request = guest_step_of(envelope)
        .map_err(|_| ApiError::BadRequest("that isn't a step"))?
        .request;
    let row = sqlx::query(
        "SELECT l.open_envelope, a.owner_identity
         FROM guest_links l JOIN agents a ON a.id = l.agent
         WHERE l.request_id = $1 AND l.agent = $2",
    )
    .bind(request.as_str())
    .bind(envelope.sender().as_str())
    .fetch_optional(&host.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let open = VerifiedEnvelope::verify_ignoring_clock(
        &row.try_get::<String, _>("open_envelope")?,
        agent,
    )?;
    let owner = Identity::from_encoded(&row.try_get::<String, _>("owner_identity")?)?;
    let step = check_agents_step_on_a_link(envelope, &open, &owner)
        .map_err(|_| ApiError::Forbidden("that's not a step for a link"))?;
    keep_step(host, envelope, request.as_str(), false, step.kind).await
}

/// Keeps a step, up to what its sender can have on one link. A repeat of one held is free.
async fn keep_step(
    host: &Host,
    envelope: &VerifiedEnvelope,
    request: &str,
    from_guest: bool,
    kind: StepKind,
) -> Result<(), ApiError> {
    let limit = if from_guest {
        MAX_STEPS_FROM_A_GUEST
    } else {
        MAX_STEPS_FROM_THE_AGENT
    };
    let stored = sqlx::query(
        "INSERT INTO guest_steps (message_id, request_id, from_guest, kind, envelope)
         SELECT $1, $2, $3, $4, $5
         WHERE (SELECT count(*) FROM guest_steps WHERE request_id = $2 AND from_guest = $3) < $6
         ON CONFLICT (message_id) DO NOTHING",
    )
    .bind(envelope.id().as_str())
    .bind(request)
    .bind(from_guest)
    .bind(word_of(kind)?)
    .bind(envelope.compact())
    .bind(limit)
    .execute(&host.db)
    .await?;
    if stored.rows_affected() == 0 {
        let here: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM guest_steps WHERE message_id = $1)")
                .bind(envelope.id().as_str())
                .fetch_one(&host.db)
                .await?;
        if !here {
            return Err(ApiError::Conflict);
        }
    }
    Ok(())
}

/// What the page holding a link needs. The request's ID is a hash nobody has been told but whoever
/// holds the link, as a guest's steps go nowhere else.
async fn read_link(
    State(host): State<Arc<Host>>,
    Path(request): Path<String>,
) -> Result<Json<GuestLink>, ApiError> {
    let row = sqlx::query(
        "SELECT l.guest_identity, l.form, l.open_envelope, l.deadline, a.handle
         FROM guest_links l JOIN agents a ON a.id = l.agent
         WHERE l.request_id = $1",
    )
    .bind(&request)
    .fetch_optional(&host.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let steps =
        sqlx::query_scalar("SELECT envelope FROM guest_steps WHERE request_id = $1 ORDER BY seq")
            .bind(&request)
            .fetch_all(&host.db)
            .await?;
    let form: GuestForm = serde_json::from_str(&row.try_get::<String, _>("form")?)
        .map_err(|_| ApiError::Unavailable)?;
    let handle: String = row.try_get("handle")?;
    Ok(Json(GuestLink {
        address: format!("{handle}~{}", host.domain),
        now: unix_now(),
        guest_identity: row.try_get("guest_identity")?,
        form,
        deadline: u64::try_from(row.try_get::<i64, _>("deadline")?).unwrap_or_default(),
        open: row.try_get("open_envelope")?,
        steps,
    }))
}

/// A guest's click. It has to be signed by the key this link names, and it's one answer, and a `cancel`
/// after that. Whether it fits the offer is for the requester's Signet to say. The link's rights end
/// at its deadline, by this host's clock as well as by the date on the step.
async fn answer(
    State(host): State<Arc<Host>>,
    Path(request): Path<String>,
    Json(body): Json<GuestAnswer>,
) -> Result<StatusCode, ApiError> {
    if body.envelope.len() > MAX_ENVELOPE_CHARS {
        return Err(ApiError::BadRequest("that's too long for a link"));
    }
    let row = sqlx::query(
        "SELECT agent, guest_identity, deadline FROM guest_links WHERE request_id = $1",
    )
    .bind(&request)
    .fetch_optional(&host.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let guest = Identity::guest_from_encoded(&row.try_get::<String, _>("guest_identity")?)?;
    let now = unix_now();
    if i64::try_from(now).unwrap_or(i64::MAX) >= row.try_get::<i64, _>("deadline")? {
        return Err(ApiError::Forbidden("this link has ended"));
    }
    let envelope = VerifiedEnvelope::verify(&body.envelope, &guest, now)?;
    let step = guest_step_of(&envelope).map_err(|_| ApiError::BadRequest("that isn't a step"))?;
    let for_this_link = step.request.as_str() == request
        && envelope.recipient().as_str() == row.try_get::<String, _>("agent")?;
    if !for_this_link {
        return Err(ApiError::Forbidden("that's not for this link"));
    }
    match step.kind {
        StepKind::Accept | StepKind::Decline | StepKind::Clarify => {
            let answered: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM guest_steps WHERE request_id = $1 AND from_guest
                     AND message_id <> $2 AND kind <> 'cancel')",
            )
            .bind(&request)
            .bind(envelope.id().as_str())
            .fetch_one(&host.db)
            .await?;
            if answered {
                return Err(ApiError::Conflict);
            }
        }
        StepKind::Cancel => {}
        _ => return Err(ApiError::Forbidden("that's not a guest's to send")),
    }
    keep_step(&host, &envelope, &request, true, step.kind).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// What guests have sent this agent, for its Signet to check for itself. A page is cut to what fits,
/// with room taken for it first, and a Signet reads on from the last step it took.
async fn steps_for_agent(
    State(host): State<Arc<Host>>,
    Path(after): Path<i64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let path = format!("/v0/guest/steps/{after}");
    let agent = inbox::authenticated_agent(&host, &headers, "GET", &path, b"").await?;
    let sized = sqlx::query(
        "SELECT s.seq, (octet_length(s.envelope) + octet_length(s.request_id))::bigint AS bytes
         FROM guest_steps s JOIN guest_links l ON l.request_id = s.request_id
         WHERE l.agent = $1 AND s.from_guest AND s.seq > $2
         ORDER BY s.seq LIMIT $3",
    )
    .bind(agent.as_str())
    .bind(after)
    .bind(PAGE_SIZE)
    .fetch_all(&host.db)
    .await?;
    let page = answers::page_of(
        answers::seq_and_bytes(&sized)?,
        sized.len(),
        answers::PAGE_BYTES,
        true,
    );
    let room = host.answers.take(&headers, page.bytes)?;
    let rows = sqlx::query(
        "SELECT seq, request_id, envelope FROM guest_steps WHERE seq = ANY($1) ORDER BY seq",
    )
    .bind(&page.keys)
    .fetch_all(&host.db)
    .await?;
    let steps = rows
        .iter()
        .map(|row| {
            Ok(GuestStepRow {
                seq: row.try_get("seq")?,
                request: row.try_get("request_id")?,
                envelope: row.try_get("envelope")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    room.json(&GuestSteps { steps })
}

/// For when an agent retires or gets a new owner: what it offered ends, for whoever holds the link.
pub async fn end_links_of(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &splint_core::SplintId,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM guest_links WHERE agent = $1")
        .bind(agent.as_str())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub async fn run_cleanup(host: Arc<Host>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        let now = host.clock.now_for_sql().await;
        let result = sqlx::query("DELETE FROM guest_links WHERE deadline <= $1")
            .bind(now.saturating_sub(KEEP_AFTER_DEADLINE_SECS))
            .execute(&host.db)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "guest link cleanup failed");
        }
    }
}

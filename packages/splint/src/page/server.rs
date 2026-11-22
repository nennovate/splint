//! The page's HTTP side, for a browser on this device. Everything it signs is worked out again from
//! signed steps at the moment of signing, so a stale page, or a script that's been tampered with, can
//! only fail to match.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use splint_core::changes::ChangeRules;
use splint_core::requests::{
    Chain, Deadline, Decision, Fields, InteractionType, MAX_PLACES, Offer, Operation, Parties,
    Party, Schemas, Side, Terms, has_hidden_characters, with_hidden_shown,
};
use splint_core::rules::{ContactStatus, InboundFrom, Permissions, Reach};
use splint_core::transport::stays_on_this_machine;
use splint_core::{GuestKey, Identity, MessageId, Sealing, SplintId, parse_address, unix_now};

use crate::contacts;
use crate::failure::Failure;
use crate::owner_commands::{place_from, signed_where_paid};
use crate::owner_key::{ForAgent, OwnerKey};
use crate::owner_side::{OwnerSide, OwnerSigned};
use crate::rules;
use crate::signet_api::{RulesAtHost, SignetApi};

use super::guard::Refusal;
use super::state::{self, PageState, Read, SavedLink, Settings};
use super::walk::{Walked, WalkedAll, walk_all};
use super::{Page, guest_links};

const INDEX: &str = include_str!("index.html");
const SCRIPT: &str = include_str!("page.js");
/// What this page draws the same way as the owner page on this computer.
const SHARED_SCRIPT: &str = include_str!("terms.js");
const STYLE: &str = include_str!("page.css");
/// Splint's tokens, shared by every page a person sees.
const TOKENS: &str = include_str!("../../../style/tokens.css");

/// Nothing here runs or loads unless it's this page's own script and style, so text that somehow
/// became markup still couldn't do anything.
const CONTENT_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; \
require-trusted-types-for 'script'";
/// Terms come back with a click, and they have to fit in a signed step.
const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_LINK_DAYS: u64 = 14;
const DAY_SECS: u64 = 24 * 60 * 60;
const HOUR_SECS: u64 = 60 * 60;

/// Fixed words, with nothing from a counterparty in them.
#[derive(Debug, thiserror::Error)]
enum PageError {
    #[error("The terms have changed, so nothing was signed. Look at them again.")]
    TermsChanged,
    #[error("These terms hold text that can't all be shown, so they can't be approved.")]
    HiddenText,
    #[error("{0}")]
    BadInput(&'static str),
    #[error("That's no longer waiting.")]
    Gone,
    #[error("This sender gave no address, so they can only be blocked.")]
    NoAddress,
    #[error("{0}")]
    Failed(#[from] Failure),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for PageError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::TermsChanged => StatusCode::CONFLICT,
            Self::HiddenText | Self::BadInput(_) | Self::NoAddress => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::Gone => StatusCode::NOT_FOUND,
            Self::Failed(Failure::SignetUnreachable | Failure::SignetNoAnswer) => {
                StatusCode::BAD_GATEWAY
            }
            Self::Failed(Failure::Refused(_) | Failure::HostRefused(_)) => StatusCode::CONFLICT,
            Self::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let error = match &self {
            Self::Failed(Failure::Http(_) | Failure::Io(_) | Failure::Core(_)) => {
                "Something on this device couldn't be read or reached, so nothing changed."
                    .to_owned()
            }
            other => other.to_string(),
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}

fn refusal_response(refusal: Refusal) -> Response {
    let status = match refusal {
        Refusal::WrongHost | Refusal::OtherOrigin => StatusCode::FORBIDDEN,
        Refusal::NoSecret => StatusCode::UNAUTHORIZED,
    };
    status.into_response()
}

async fn guard_files(State(page): State<Arc<Page>>, request: Request, next: Next) -> Response {
    match page.guard.check_request(request.headers()) {
        Ok(()) => next.run(request).await,
        Err(refusal) => refusal_response(refusal),
    }
}

async fn guard_calls(State(page): State<Arc<Page>>, request: Request, next: Next) -> Response {
    match page.guard.check_call(request.method(), request.headers()) {
        Ok(()) => next.run(request).await,
        Err(refusal) => refusal_response(refusal),
    }
}

async fn with_safety_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let fixed: [(HeaderName, &'static str); 7] = [
        (CONTENT_SECURITY_POLICY, CONTENT_POLICY),
        (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (X_FRAME_OPTIONS, "DENY"),
        (REFERRER_POLICY, "no-referrer"),
        (CACHE_CONTROL, "no-store"),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
    ];
    for (name, value) in fixed {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

fn file(kind: &'static str, content: &'static str) -> Response {
    ([(CONTENT_TYPE, kind)], content).into_response()
}

pub fn routes(page: Arc<Page>) -> Router {
    let calls = Router::new()
        .route("/api/state", get(read_state))
        .route("/api/decide", post(decide))
        .route("/api/let-in", post(let_in))
        .route("/api/block", post(block))
        .route("/api/unblock", post(unblock))
        .route("/api/forget", post(forget))
        .route("/api/accept-change", post(accept_change))
        .route("/api/settings", post(settings))
        .route("/api/approve-kind", post(approve_kind))
        .route("/api/words", post(words))
        .route("/api/guest-link", post(guest_link))
        .route("/api/get-paid", post(get_paid))
        .route_layer(middleware::from_fn_with_state(page.clone(), guard_calls));
    Router::new()
        .route(
            "/",
            get(|| async { file("text/html; charset=utf-8", INDEX) }),
        )
        .route(
            "/page.js",
            get(|| async { file("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/terms.js",
            get(|| async { file("text/javascript; charset=utf-8", SHARED_SCRIPT) }),
        )
        .route(
            "/page.css",
            get(|| async { file("text/css; charset=utf-8", STYLE) }),
        )
        .route(
            "/tokens.css",
            get(|| async { file("text/css; charset=utf-8", TOKENS) }),
        )
        .merge(calls)
        // A preflight from another site reaches this too, and gets no answer that lets it go ahead.
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(page.clone(), guard_files))
        .layer(middleware::from_fn(with_safety_headers))
        .with_state(page)
}

impl Page {
    fn side(&self) -> Result<OwnerSide, Failure> {
        OwnerSide::resolve(&self.home, self.named.as_deref(), "open the owner's page")
    }

    async fn walked(&self, side: &OwnerSide) -> Result<WalkedAll, Failure> {
        let view = side.read(&self.home).await?;
        walk_all(&view.requests, side.agent(), &self.owner, &view.schemas)
    }
}

async fn read_state(State(page): State<Arc<Page>>) -> Result<Json<PageState>, PageError> {
    let side = page.side()?;
    let signed = side.rules(&page.home).await?;
    let view = side.read(&page.home).await?;
    let walked = walk_all(&view.requests, side.agent(), &page.owner, &view.schemas)?;
    let schemas = view.schemas.clone();
    // Only the contacts the owner signed: the page never uses the agent's token, which is what lists
    // the ones the agent added by itself.
    let everyone = signed.draft.contacts.clone();
    let read = Read {
        kinds: view.kinds,
        everyone,
        address: side.address().to_owned(),
        agent: side.agent().clone(),
        elsewhere: side.is_elsewhere(),
        heard_at: view.heard_at,
        owner: page.owner.clone(),
        signed,
        walked,
        held: view.held,
        changes: view.changes,
        words: view.words,
        refused: view.refused,
        links: guest_links::kept(&page.home, unix_now())?,
        usage: view.usage,
    };
    Ok(Json(state::page_state(read, &schemas, unix_now())?))
}

#[derive(Serialize)]
struct Done {
    said: String,
    /// The host refused the rules just signed, so the page keeps saying so rather than letting it go.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    host_refused: bool,
}

fn done(said: impl Into<String>) -> Json<Done> {
    Json(Done {
        said: said.into(),
        host_refused: false,
    })
}

/// What's said once rules are signed, with what the host did with them.
fn rules_done(said: impl Into<String>, at_host: Option<RulesAtHost>) -> Json<Done> {
    Json(Done {
        said: rules::told(said, at_host),
        host_refused: rules::host_refused(at_host),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideBody {
    request: MessageId,
    operation: Operation,
    version: u32,
    prev: MessageId,
    terms: Terms,
    decision: Decision,
    subject: Option<String>,
}

/// Signs only what's still the terms, worked out again now from signed steps and compared by value.
/// A `counter` or anything else that changes them means the owner hasn't seen what would be signed,
/// so nothing is (invariant 6).
async fn decide(
    State(page): State<Arc<Page>>,
    Json(body): Json<DecideBody>,
) -> Result<Json<Done>, PageError> {
    let side = page.side()?;
    let walked = page.walked(&side).await?;
    let now = unix_now();
    let found = walked
        .walked
        .iter()
        .find(|walked| walked.request == body.request);
    // What the agent asked to start has no request yet, only what it waits under.
    // Each draft on a request is its own yes, found by its step, so a yes to one never signs another.
    let draft = match found {
        Some(found) => found
            .drafts(now)
            .into_iter()
            .find(|draft| draft.operation == body.operation),
        None => walked
            .starting
            .iter()
            .filter_map(|open| open.draft(now))
            .find(|draft| draft.request == body.request),
    }
    .ok_or(PageError::TermsChanged)?;
    let role = found.map_or(Side::Requester, |found| found.role);
    let still_the_terms = draft.operation == body.operation
        && draft.version == body.version
        && draft.prev == body.prev
        && draft.terms == body.terms;
    if !still_the_terms {
        return Err(PageError::TermsChanged);
    }
    if body.decision == Decision::Approve && draft.terms.hides_text() {
        return Err(PageError::HiddenText);
    }
    let subject = body
        .subject
        .as_deref()
        .filter(|text| !text.trim().is_empty());
    if let Some(text) = subject {
        if !state::can_set_subject(draft.operation, role) {
            return Err(PageError::BadInput(
                "Only the side that asked sets a subject.",
            ));
        }
        if text.chars().count() > state::MAX_SUBJECT_CHARS || has_hidden_characters(text) {
            return Err(PageError::BadInput(
                "A subject has to be short plain text on one line.",
            ));
        }
    }
    let at = side.at_host().await?;
    let approval =
        OwnerKey::new(&page.home).approve(&draft, body.decision, subject, at.as_ref())?;
    side.hand_over(&page.home, OwnerSigned::Approval(approval))
        .await?;
    Ok(done(match body.decision {
        Decision::Approve => side.signed_words(
            "Signed yes to exactly those terms.",
            "Signed yes to exactly those terms, and left at its host. This clears once its Signet has taken it, within a few seconds.",
        ),
        Decision::Deny => side.signed_words(
            "Signed no.",
            "Signed no, and left at its host. This clears once its Signet has taken it, within a few seconds.",
        ),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestLinkBody {
    #[serde(rename = "type")]
    interaction: InteractionType,
    terms: Fields,
    /// In days from now, up to what a deadline can be.
    days: u64,
    subject: Option<String>,
    note: Option<String>,
}

#[derive(Serialize)]
struct LinkMade {
    said: String,
    url: String,
}

#[derive(Deserialize)]
struct LinkOpened {
    request: MessageId,
    waiting: bool,
}

fn words_of(text: Option<String>, limit: usize) -> Result<Option<String>, PageError> {
    let text = text.filter(|text| !text.trim().is_empty());
    if text
        .as_deref()
        .is_some_and(|text| text.chars().count() > limit || has_hidden_characters(text))
    {
        return Err(PageError::BadInput(
            "That has to be short plain text on one line.",
        ));
    }
    Ok(text)
}

/// A new one-use link: a key made here, this owner's yes to exactly this offer for that key, and an
/// `open` from Signet carrying it. Signet and the host only ever see the key's public half, and the
/// link with the private half is for the owner to pass on.
async fn guest_link(
    State(page): State<Arc<Page>>,
    Json(body): Json<GuestLinkBody>,
) -> Result<Json<LinkMade>, PageError> {
    let subject = words_of(body.subject, state::MAX_SUBJECT_CHARS)?;
    let note = words_of(body.note, state::MAX_NOTE_CHARS)?;
    if !(1..=MAX_LINK_DAYS).contains(&body.days) {
        return Err(PageError::BadInput("A link lasts from 1 to 14 days."));
    }
    let OwnerSide::Beside { installed, agent } = page.side()? else {
        return Err(PageError::BadInput(
            "Make a link on the device your agent runs on, as only its Signet can send one.",
        ));
    };
    let api = SignetApi::new(&page.home, &installed)?;
    let who = Identity::from_encoded(&api.who().await?.identity)
        .ok()
        .filter(|identity| identity.id() == &agent)
        .ok_or_else(|| Failure::refused("this Signet isn't the agent this page is for"))?;
    let key = GuestKey::generate().map_err(Failure::from)?;
    let guest = Identity::guest(&key.public_key()).map_err(Failure::from)?;
    let now = unix_now();
    // Down to the hour, which is all a deadline can name, so it's never past two weeks.
    let at = now
        .saturating_add(body.days.saturating_mul(DAY_SECS))
        .saturating_div(HOUR_SECS)
        .saturating_mul(HOUR_SECS);
    let unusable = || PageError::BadInput("That doesn't fit this type of request.");
    let offer = Offer {
        interaction: body.interaction,
        schema: None,
        terms: body.terms,
        deadline: Deadline::try_from(at).map_err(|_| unusable())?,
        supersedes: None,
    };
    let parties = Parties {
        requester: Party {
            agent: who,
            owner: page.owner.clone(),
            binding: String::new(),
        },
        recipient: Party::guest(guest.clone()),
    };
    let nonce = splint_core::random_nonce().map_err(Failure::from)?;
    let schemas = Schemas::of(api.schemas().await?.into_iter().map(Arc::new)).unwrap_or_default();
    let draft = Chain::new(parties, schemas)
        .guest_offer_draft(&offer, &nonce, subject, note, now)
        .map_err(|_| unusable())?;
    // For the Signet beside this page, which makes the link, so it's left at no host.
    let ForAgent::Beside(approval) =
        OwnerKey::new(&page.home).approve(&draft, Decision::Approve, None, None)?
    else {
        return Err(unusable());
    };
    let opened: LinkOpened = api
        .owner_ask(
            "/v0/owner/guest-links",
            &json!({
                "approval": approval,
                "nonce": nonce,
                "offer": offer,
                "guest_identity": guest.encoded(),
            }),
        )
        .await?;
    let opened_waiting = opened.waiting;
    let (_, domain) = parse_address(&installed.address).map_err(Failure::from)?;
    let scheme = if stays_on_this_machine(domain) {
        "http"
    } else {
        "https"
    };
    let url = format!(
        "{scheme}://{domain}/g/{}#k={}",
        opened.request,
        key.link_text()
    );
    guest_links::keep(
        &page.home,
        SavedLink {
            request: opened.request,
            url: url.clone(),
            interaction: offer.interaction.as_str().to_owned(),
            deadline: at,
        },
        now,
    )?;
    Ok(Json(LinkMade {
        said: if opened_waiting {
            "Signed, but your host hasn't taken it yet, so the link won't work until it does. It's still being tried."
        } else {
            "Signed. Anyone holding this link can answer this one request, once."
        }
        .to_owned(),
        url,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WhoBody {
    agent: SplintId,
}

/// A yes to someone held. It names the ID that signed what's held, and only that, so it signs that ID
/// in at the address its owner gave. A false address gets them nothing: a contact's messages have to
/// come through that address's own host. For an invite both agents agreed to, the address and ID are
/// the ones the two agents signed, checked here, whatever a Signet says beside them.
async fn let_in(
    State(page): State<Arc<Page>>,
    Json(body): Json<WhoBody>,
) -> Result<Json<Done>, PageError> {
    let _changing = page.changing_rules.lock().await;
    let side = page.side()?;
    let held = side.held(&page.home).await?;
    let theirs: Vec<_> = held
        .iter()
        .filter(|message| message.sender == body.agent)
        .collect();
    if theirs.is_empty() {
        return Err(PageError::Gone);
    }
    let agreed = theirs
        .iter()
        .filter_map(|message| message.invite.as_ref())
        .filter_map(|record| record.verify(side.agent()).ok())
        .find(|new| new.agent == body.agent);
    if let Some(new) = agreed {
        let said = side
            .add_contact(&page.home, &new.address, new.agent.as_str())
            .await?;
        return Ok(done(said));
    }
    let address = theirs
        .iter()
        .filter(|message| message.kind != "invite")
        .find_map(|message| message.address.as_deref())
        .ok_or(PageError::NoAddress)?;
    let said = side
        .add_contact(&page.home, address, body.agent.as_str())
        .await?;
    Ok(done(said))
}

/// Someone can be blocked if the owner has any reason to know of them: they're in the rules, or held,
/// or in an exchange. So nothing else can use this page to fill the rules.
async fn block(
    State(page): State<Arc<Page>>,
    Json(body): Json<WhoBody>,
) -> Result<Json<Done>, PageError> {
    let _changing = page.changing_rules.lock().await;
    let side = page.side()?;
    let listed = side
        .rules(&page.home)
        .await?
        .draft
        .contacts
        .iter()
        .any(|contact| contact.agent == body.agent);
    let claimed = if listed {
        None
    } else {
        let view = side.read(&page.home).await?;
        let held_as = view
            .held
            .iter()
            .flatten()
            .find(|message| message.sender == body.agent);
        let walked = walk_all(&view.requests, side.agent(), &page.owner, &view.schemas)?;
        let met_as = walked
            .walked
            .iter()
            .find(|walked: &&Walked| walked.them == body.agent);
        if held_as.is_none() && met_as.is_none() {
            return Err(PageError::Gone);
        }
        held_as
            .and_then(|message| message.address.clone())
            .or_else(|| met_as.map(|walked| walked.their_address.clone()))
    };
    let at_host = contacts::block(&page.home, &side, &body.agent, claimed.as_deref()).await?;
    Ok(rules_done(
        "Blocked. Your rules are signed and on their way.",
        at_host,
    ))
}

async fn unblock(
    State(page): State<Arc<Page>>,
    Json(body): Json<WhoBody>,
) -> Result<Json<Done>, PageError> {
    let _changing = page.changing_rules.lock().await;
    let at_host = contacts::unblock(&page.home, &page.side()?, &body.agent).await?;
    Ok(rules_done(
        "They're a contact again. Your rules are signed.",
        at_host,
    ))
}

async fn forget(
    State(page): State<Arc<Page>>,
    Json(body): Json<WhoBody>,
) -> Result<Json<Done>, PageError> {
    let _changing = page.changing_rules.lock().await;
    let at_host = contacts::forget(&page.home, &page.side()?, &body.agent).await?;
    Ok(rules_done(
        "Taken off your contacts, so they're a stranger again. Your rules are signed.",
        at_host,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptBody {
    contact: SplintId,
    head: String,
}

/// A yes to one contact's history as far as the head on the screen, and only if that's still a head
/// it could be, so a later change needs a later yes.
async fn accept_change(
    State(page): State<Arc<Page>>,
    Json(body): Json<AcceptBody>,
) -> Result<Json<Done>, PageError> {
    let side = page.side()?;
    let notices = side.read(&page.home).await?.changes;
    let still_there = notices.changes.iter().any(|notice| {
        notice.contact == body.contact
            && (notice.head == body.head || notice.rewritten_head.as_ref() == Some(&body.head))
    });
    if !still_there {
        return Err(PageError::TermsChanged);
    }
    let at = side.at_host().await?;
    let acceptance = OwnerKey::new(&page.home).accept_change(
        side.agent(),
        &body.contact,
        &body.head,
        at.as_ref(),
    )?;
    side.hand_over(&page.home, OwnerSigned::Acceptance(acceptance))
        .await?;
    Ok(done(side.signed_words(
        "Signed yes to that contact's history, this far.",
        "Signed yes to that contact's history, this far, and left at its host.",
    )))
}

/// Every part of a reach setting has to mean something, so what's hidden on the form doesn't count.
fn tidied(mut settings: Settings) -> Result<Settings, PageError> {
    let inbound = &mut settings.reach.inbound;
    match inbound.from {
        InboundFrom::Contacts => {
            inbound.filter = Default::default();
            inbound.types = Vec::new();
            inbound.text = false;
        }
        InboundFrom::Open => inbound.filter = Default::default(),
        InboundFrom::Filter => {
            let filter = &inbound.filter;
            if filter.owners.is_empty() && filter.hosts.is_empty() && !filter.past {
                return Err(PageError::BadInput(
                    "Name who fits the filter, or choose something else.",
                ));
            }
            if !filter.owners.iter().all(SplintId::is_well_formed) {
                return Err(PageError::BadInput(
                    "An owner's ID looks like splint1 and 64 more characters.",
                ));
            }
        }
    }
    // Words alone are enough, as core's own plain conversation names no type.
    if inbound.from != InboundFrom::Contacts && inbound.types.is_empty() && !inbound.text {
        return Err(PageError::BadInput(
            "Name at least one type they may use, or let them send words, or they couldn't do anything.",
        ));
    }
    Ok(settings)
}

/// Settings as the page signs them. Where they'd take out contacts the agent added by itself, as Ask
/// me first does, `added` names the ones the page showed and the owner's choice for them, which the page
/// asks before anything's signed, with one chosen for them that the page shows first.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsBody {
    paused: bool,
    reach: Reach,
    permissions: Permissions,
    changes: ChangeRules,
    sealing: Sealing,
    #[serde(default)]
    added: Option<AddedChoice>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddedChoice {
    shown: Vec<SplintId>,
    choice: Keeping,
}

/// Whether contacts the agent added by itself stay, as the owner's own, or go.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Keeping {
    Keep,
    Drop,
}

async fn settings(
    State(page): State<Arc<Page>>,
    Json(body): Json<SettingsBody>,
) -> Result<Json<Done>, PageError> {
    let settings = tidied(Settings {
        paused: body.paused,
        reach: body.reach,
        permissions: body.permissions,
        changes: body.changes,
        sealing: body.sealing,
    })?;
    let _changing = page.changing_rules.lock().await;
    let side = page.side()?;
    let mut signed = side.rules(&page.home).await?;
    let old = signed.draft.clone();
    signed.draft.paused = settings.paused;
    signed.draft.reach = settings.reach;
    signed.draft.permissions = settings.permissions;
    signed.draft.changes = settings.changes;
    signed.draft.sealing = settings.sealing;
    // Who these take out is read again here, and has to be who the page showed, so the owner's choice
    // is about exactly those.
    let Some(added) = side.added_taken_out(&page.home, &old, &signed.draft).await else {
        return Err(Failure::refused(
            "Splint couldn't check which contacts your agent added by itself these settings would \
             take out, so nothing was signed. Try again.",
        )
        .into());
    };
    let signed_words = "Signed. Your agent and its host go by these now.";
    let going: HashSet<&SplintId> = added.iter().map(|one| &one.agent).collect();
    let said = match body.added {
        None if added.is_empty() => signed_words.to_owned(),
        // The page didn't say who these take out, so the owner hasn't chosen.
        None => {
            return Err(Failure::refused(format!(
                "{}, so these settings take out the contacts your agent added by itself: {}. \
                 Nothing was signed. Look again, and choose whether to keep them.",
                rules::why_added_go(&signed.draft),
                rules::added_addresses(&added),
            ))
            .into());
        }
        Some(chosen) if chosen.shown.iter().collect::<HashSet<_>>() != going => {
            return Err(Failure::refused(format!(
                "The contacts your agent added by itself that these settings take out aren't the ones \
                 the page showed. They're {} now. Nothing was signed. Look again, and choose for them.",
                if added.is_empty() {
                    "none".to_owned()
                } else {
                    rules::added_addresses(&added)
                },
            ))
            .into());
        }
        Some(_) if added.is_empty() => signed_words.to_owned(),
        Some(AddedChoice {
            choice: Keeping::Keep,
            ..
        }) => {
            rules::keep_added(&mut signed.draft, &old, &added)?;
            format!(
                "{signed_words} The contacts your agent added are your own now: {}.",
                rules::added_addresses(&added)
            )
        }
        Some(AddedChoice {
            choice: Keeping::Drop,
            ..
        }) => format!(
            "{signed_words} They took out the contacts your agent added by itself: {}. Contacts \
             lists any of them for you to add back.",
            rules::added_addresses(&added)
        ),
    };
    let at_host = side.apply_rules(&page.home, signed.draft).await?;
    let said = match at_host {
        None | Some(RulesAtHost::Taken) => said,
        // Its host goes by older rules until it takes these, which the note after says.
        Some(_) => said.replacen(
            signed_words,
            "Signed. Your agent's Signet goes by these now.",
            1,
        ),
    };
    Ok(rules_done(said, at_host))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KindBody {
    agent: SplintId,
    #[serde(rename = "type")]
    interaction: InteractionType,
}

/// The owner's approval of one kind with currency for one contact, which their agent can't use before
/// it (Nenye, 2026-11-15). It names the kind's ID, its fingerprint included, in that contact's entry, so
/// it's the exact kind the page showed: the Signet has to say it agreed that ID with them, and the ID is
/// this device's own fingerprint of the schema it handed over. It's for a contact the owner's rules
/// name: one the agent added by itself is approved as a contact first, and the page never uses the
/// agent's token to list those.
async fn approve_kind(
    State(page): State<Arc<Page>>,
    Json(body): Json<KindBody>,
) -> Result<Json<Done>, PageError> {
    let _changing = page.changing_rules.lock().await;
    let side = page.side()?;
    let view = side.read(&page.home).await?;
    let agreed = view
        .kinds
        .iter()
        .any(|(agent, schema)| agent == &body.agent && schema.name() == &body.interaction);
    if !agreed {
        return Err(PageError::Gone);
    }
    let mut signed = side.rules(&page.home).await?;
    let entry = signed
        .draft
        .contacts
        .iter_mut()
        .find(|entry| entry.agent == body.agent && entry.status == ContactStatus::Allowed)
        .ok_or(PageError::Gone)?;
    if entry.types.contains(&body.interaction) {
        return Err(PageError::Gone);
    }
    entry.types.push(body.interaction.clone());
    let label = entry.label.clone();
    let at_host = side.apply_rules(&page.home, signed.draft).await?;
    Ok(rules_done(
        format!(
            "Approved {} for {}. Your rules are signed. A price you'd pay in it still waits for you, \
             and one your agent quotes follows your setting for quotes.",
            body.interaction.name(),
            with_hidden_shown(&label),
        ),
        at_host,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WordsBody {
    request: MessageId,
    text: String,
}

/// Words a person writes, signed here, for the agent's next step to carry. They're marked untrusted
/// to whoever reads them, and move nothing.
async fn words(
    State(page): State<Arc<Page>>,
    Json(body): Json<WordsBody>,
) -> Result<Json<Done>, PageError> {
    let side = page.side()?;
    let walked = page.walked(&side).await?;
    let found = walked
        .walked
        .iter()
        .find(|walked| walked.request == body.request)
        .ok_or(PageError::Gone)?;
    if body.text.trim().is_empty()
        || body.text.chars().count() > state::MAX_WORDS_CHARS
        || has_hidden_characters(&body.text)
    {
        return Err(PageError::BadInput(
            "Words have to be short plain text on one line.",
        ));
    }
    let at = side.at_host().await?;
    let signed = OwnerKey::new(&page.home).person_text(
        side.agent(),
        &found.them,
        Some(&body.request),
        &body.text,
        at.as_ref(),
    )?;
    side.hand_over(&page.home, OwnerSigned::PersonText(signed))
        .await?;
    Ok(done(
        "Signed. They go with your agent's next step on this, and not before.",
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetPaidBody {
    /// Each place as the person typed it, one a line.
    places: Vec<String>,
}

/// Where the owner gets paid, signed here with their key as `splint get-paid` signs it. Their agent's
/// Signet puts it on its asks to be paid, so a payer sees the place this owner chose.
async fn get_paid(
    State(page): State<Arc<Page>>,
    Json(body): Json<GetPaidBody>,
) -> Result<Json<Done>, PageError> {
    if body.places.is_empty() || body.places.len() > MAX_PLACES {
        return Err(PageError::BadInput("Give 1 to 4 places, one a line."));
    }
    let places = body
        .places
        .iter()
        .map(|place| place_from(place.trim()))
        .collect::<Result<Vec<_>, Failure>>()?;
    let side = page.side()?;
    let key = OwnerKey::new(&page.home);
    if key.is_stand_in() {
        return Err(PageError::BadInput(
            "Only the person an agent acts for says where they get paid, with their own key.",
        ));
    }
    let at = side.at_host().await?;
    let signed = key.where_paid(&places, at.as_ref())?;
    side.hand_over(&page.home, OwnerSigned::WherePaid(signed))
        .await?;
    Ok(done(signed_where_paid(&places)))
}

#[cfg(test)]
mod tests {
    use splint_core::changes::ChangeRules;
    use splint_core::rules::{Permissions, Reach};

    use super::*;

    fn quote() -> splint_core::requests::InteractionType {
        splint_core::requests::Schema::parse(include_bytes!(
            "../../../../spec/schemas/quote-1.json"
        ))
        .unwrap()
        .name()
        .clone()
    }

    fn settings_with(change: impl FnOnce(&mut Reach)) -> Settings {
        let mut reach = Reach::default();
        change(&mut reach);
        Settings {
            paused: false,
            reach,
            permissions: Permissions::default(),
            changes: ChangeRules::default(),
            sealing: splint_core::Sealing::default(),
        }
    }

    #[test]
    fn what_a_form_hid_doesnt_count_for_contacts_only() {
        let settings = tidied(settings_with(|reach| {
            reach.inbound.types = vec![quote()];
            reach.inbound.text = true;
            reach.inbound.filter.past = true;
        }))
        .unwrap();
        assert!(settings.reach.inbound.types.is_empty());
        assert!(!settings.reach.inbound.text);
        assert!(!settings.reach.inbound.filter.past);
    }

    #[test]
    fn letting_people_in_needs_a_type_or_words_for_them_to_use_and_someone_to_fit() {
        let open_no_types = settings_with(|reach| reach.inbound.from = InboundFrom::Open);
        assert!(matches!(tidied(open_no_types), Err(PageError::BadInput(_))));
        let empty_filter = settings_with(|reach| {
            reach.inbound.from = InboundFrom::Filter;
            reach.inbound.types = vec![quote()];
        });
        assert!(matches!(tidied(empty_filter), Err(PageError::BadInput(_))));
        // The page refused this once core's plain conversation replaced chat/1, so an owner with no
        // agreed types couldn't let anyone in at all.
        let words_only = settings_with(|reach| {
            reach.inbound.from = InboundFrom::Open;
            reach.inbound.text = true;
        });
        assert!(tidied(words_only).is_ok());
        let open = settings_with(|reach| {
            reach.inbound.from = InboundFrom::Open;
            reach.inbound.types = vec![quote()];
            reach.inbound.filter.past = true;
        });
        let open = tidied(open).unwrap();
        assert!(!open.reach.inbound.filter.past);
        assert_eq!(open.reach.inbound.types, vec![quote()]);
    }
}

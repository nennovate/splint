//! What an owner's device asks of Signet. Each decision takes effect only if the owner's signature
//! verifies against the owner this agent's ID commits to, so a fooled agent, which can reach this API
//! too, can't forge or twist one.

use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::host_api::HostRefusal;
use splint_core::requests::{
    Action, ApprovalDraft, Audience, Chain, Decision, Dialogue, HeldMove, Offer, Operation,
    Outcome, Refused, RequestState, Side, VerifiedApproval,
};
use splint_core::{Identity, MessageId, secrets_match, unix_now};

use crate::Signet;
use crate::agent_api::{ApiError, BEARER};
use crate::host_client::HostError;
use crate::requests::agent_api::{Made, make_move, new_record, record_of, send_open};
use crate::requests::contact_at;
use crate::requests::held_opens::{HeldOpen, HoldStatus};
use crate::requests::refusals::Refusal;
use crate::requests::store::{NotUsed, Record, started_from};
use crate::requests::sync;

/// Reading is by a token kept apart from the agent's, because drafts carry a subject and note that
/// no agent may see.
pub fn routes(signet: Arc<Signet>) -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/owner/approvals", get(drafts))
        .route("/v0/owner/requests", get(handed_over))
        .route("/v0/owner/requests/{request}/outcome", get(outcome))
        .route("/v0/owner/requests/{request}/record", get(record))
        .route("/v0/owner/refused", get(refused))
        // What the agent agreed, for the owner's own device to read without the agent's token.
        .route("/v0/owner/types", get(super::types::list))
        .route("/v0/owner/guest-links", post(make_guest_link))
        .route_layer(middleware::from_fn_with_state(signet, require_owner_token))
        .route("/v0/owner/approvals", post(decide))
}

pub async fn require_owner_token(
    State(signet): State<Arc<Signet>>,
    request: Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix(BEARER));
    let expected = signet.requests.owner_token.as_deref();
    match (token, expected) {
        (Some(token), Some(expected)) if secrets_match(token.as_bytes(), expected.as_bytes()) => {
            next.run(request).await
        }
        _ => ApiError::Unauthorized.into_response(),
    }
}

/// Everything refused that this Signet knows of, and what its host says it refused, which is only the
/// host's word. A host that's down leaves its half out and says so.
#[derive(Serialize)]
struct RefusedList {
    refused: Vec<Refusal>,
    at_host: Vec<HostRefusal>,
    host_unknown: bool,
}

async fn refused(State(signet): State<Arc<Signet>>) -> Json<RefusedList> {
    let at_host = signet
        .host
        .refused(&signet.key, signet.who().identity.id())
        .await;
    let host_unknown = at_host.is_err();
    Json(RefusedList {
        refused: signet.requests.refused.all().await,
        at_host: at_host.unwrap_or_default(),
        host_unknown,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestLinkBody {
    approval: String,
    nonce: String,
    offer: Offer,
    guest_identity: String,
}

#[derive(Serialize)]
struct GuestLinkMade {
    request: String,
    /// The host hasn't taken it yet, so the link shows nothing until it has. It's still being tried.
    waiting: bool,
}

/// Makes a link's `open` under the owner's yes. The chain compares every part of what was signed with
/// this offer and this guest, and one yes names one nonce, so a second call makes the same step or none.
/// The guest's private key never comes here.
async fn make_guest_link(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<GuestLinkBody>,
) -> Result<Json<GuestLinkMade>, ApiError> {
    crate::recovery::hear_of_new_keys(&signet, &body.approval).await;
    let approval = VerifiedApproval::verify(&body.approval, &signet.who().owner)?;
    if approval.operation() != Operation::OfferToGuest || approval.decision() != Decision::Approve {
        return Err(Refused::ApprovalMismatch.into());
    }
    let guest = Identity::guest_from_encoded(&body.guest_identity)
        .map_err(|_| ApiError::BadRequest("that isn't a guest's identity"))?;
    let now = unix_now();
    let mut record = Record::for_guest(&guest);
    let chain = record.chain(&signet)?;
    let checked = chain.released_open(&body.offer, &body.nonce, &approval, now)?;
    // A link's page comes from a host, which could take its key, so nothing on a link is sealed.
    let signed = checked.sign(&signet.key, &signet.who().identity, now)?;
    let request = signed.id.as_str().to_owned();
    record.add_own(&signed);
    {
        let mut records = signet.requests.store.lock().await;
        if !records.contains_key(&request) {
            signet
                .requests
                .store
                .commit(&mut records, &request, record)?;
        }
    }
    if let Err(error) = sync::flush(&signet).await {
        tracing::debug!(%error, "a link is waiting to reach our host");
    }
    let waiting = signet
        .requests
        .store
        .lock()
        .await
        .get(&request)
        .is_none_or(|record| !record.outbox.is_empty());
    Ok(Json(GuestLinkMade { request, waiting }))
}

#[derive(Serialize)]
struct Drafts {
    drafts: Vec<ApprovalDraft>,
}

async fn drafts(State(signet): State<Arc<Signet>>) -> Result<Json<Drafts>, ApiError> {
    Ok(Json(Drafts {
        drafts: drafts_of(&signet).await,
    }))
}

/// What waits on the owner's yes or no, computed from each chain, so there's at most one per request
/// and a counter replaces it. Only a Signet's word: an owner's device that can walk the steps itself
/// does, and one that can't shows these, as every reader holds an approval to the chain.
pub async fn drafts_of(signet: &Signet) -> Vec<ApprovalDraft> {
    let records = signet.requests.store.lock().await;
    let mut drafts = Vec::new();
    let now = unix_now();
    // One that can't be read, such as one whose schema has been taken away, leaves the others alone.
    for record in records.values() {
        let Ok(chain) = record.chain(signet) else {
            continue;
        };
        drafts.extend(drafts_on(record, &chain, now));
    }
    drop(records);
    let contacts_of = signet.requests.held_opens.waiting(now).await;
    for open in contacts_of {
        // Nothing is on record yet, so this walks no steps, only the offer against who it's for.
        if let Some(contact) = contact_at(signet, &open.address).await.ok().flatten() {
            let draft = new_record(&contact)
                .chain(signet)
                .ok()
                .and_then(|chain| chain.open_draft(&open.offer, &open.nonce, now).ok());
            drafts.extend(draft);
        }
    }
    drafts
}

/// What waits on the owner in one interaction.
fn drafts_on(record: &Record, chain: &Chain, now: u64) -> Vec<ApprovalDraft> {
    let mut drafts = Vec::new();
    let live = chain.state_at(now) != RequestState::Expired;
    if live {
        drafts.extend(chain.confirm_draft(record.role, now));
    }
    if record.cancel_wanted {
        drafts.extend(chain.cancel_draft(record.role, now));
    }
    drafts.extend(record.held_draft(chain, now));
    drafts
}

/// One interaction as what was signed, with nothing worked out from it.
#[derive(Serialize)]
struct SignedRequest {
    guest: bool,
    role: Side,
    peer_identity: String,
    peer_owner: String,
    peer_binding: String,
    steps: Vec<String>,
    cancel_wanted: bool,
    /// A move the agent asked for. Only the owner's device says what it would commit them to.
    held: Option<HeldMove>,
    /// Their last answer here that this Signet couldn't use, while something here waits on them. It's
    /// only this Signet's word, and decides nothing: what to sign is still worked out from the steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_used: Option<NotUsed>,
}

/// An `open` the agent asked for, and who it's for, for the owner's device to check for itself.
#[derive(Serialize)]
struct SignedOpen {
    peer_identity: String,
    peer_owner: String,
    peer_binding: String,
    offer: Offer,
    nonce: String,
}

#[derive(Serialize)]
pub struct SignedRequests {
    identity: String,
    requests: Vec<SignedRequest>,
    held_opens: Vec<SignedOpen>,
    /// What didn't fit, which is always the oldest of what's waiting on nobody.
    left_out: usize,
    /// What each contact last said its owner chose, sealed or unsealed, which the owner's page shows.
    their_sealing: std::collections::BTreeMap<String, splint_core::Sealing>,
}

impl SignedRequests {
    pub fn left_out(&self) -> usize {
        self.left_out
    }
}

/// How many interactions an owner's device gets at once, which is more than a person scans.
const MAX_REQUESTS_HANDED_OVER: usize = 200;
/// What fits through a reply on this device. One that's further away gets less, to fit its host.
const MAX_HANDED_OVER_BYTES: usize = 8 * 1024 * 1024;
/// A deadline falls within two weeks of the step that set it, so nothing older still needs a signature
/// unless it says so itself, as a held move or a wanted cancel does.
const CAN_STILL_NEED_SIGNING_SECS: u64 = 15 * 24 * 60 * 60;

async fn handed_over(State(signet): State<Arc<Signet>>) -> Json<SignedRequests> {
    Json(signed_requests(&signet, MAX_HANDED_OVER_BYTES).await)
}

/// Whether this record has something for its owner to sign now, or a move of their agent's that waits
/// on the other side's person first. A held move the request has gone past, as when the other side
/// called it off, waits on nobody.
fn waits_on_owner(signet: &Signet, record: &Record, now: u64) -> bool {
    if record.cancel_wanted {
        return true;
    }
    let recent = now.saturating_sub(record.last_at) <= CAN_STILL_NEED_SIGNING_SECS;
    if !recent && record.held.is_none() {
        return false;
    }
    let Ok(chain) = record.chain(signet) else {
        return record.held.is_some();
    };
    let held_waits = record.held.as_ref().is_some_and(|held| {
        matches!(
            chain.held_draft(record.role, held, now),
            Ok(_) | Err(Refused::TheirOwnerUnconfirmed)
        )
    });
    if held_waits {
        return true;
    }
    recent
        && chain.state_at(now) != RequestState::Expired
        && chain.confirm_draft(record.role, now).is_some()
}

/// Everything an owner's device needs to walk each interaction for itself, so a Signet that lies can
/// leave things out, but can't change what its owner is shown or asked to sign. What's waiting on them
/// comes first and the rest newest first, so a long history costs them old exchanges and nothing else.
pub async fn signed_requests(signet: &Signet, max_bytes: usize) -> SignedRequests {
    let waiting = signet.requests.held_opens.waiting(unix_now()).await;
    let mut held_opens = Vec::with_capacity(waiting.len());
    for open in waiting {
        if let Some(contact) = contact_at(signet, &open.address).await.ok().flatten() {
            held_opens.push(SignedOpen {
                peer_identity: contact.agent.encoded(),
                peer_owner: contact.owner.encoded(),
                peer_binding: contact.binding,
                offer: open.offer,
                nonce: open.nonce,
            });
        }
    }
    let known = &signet.contacts.known;
    let newest = |encoded: &str| {
        Identity::from_encoded(encoded)
            .map(|identity| known.newest_or_same(&identity).encoded())
            .ok()
    };
    let now = unix_now();
    let records = signet.requests.store.lock().await;
    let mut ordered: Vec<(bool, u64, &Record)> = records
        .values()
        .map(|record| (waits_on_owner(signet, record, now), record.last_at, record))
        .collect();
    ordered.sort_by_key(|(waits, at, _)| (!*waits, u64::MAX.saturating_sub(*at)));
    let mut requests = Vec::new();
    let mut room = max_bytes;
    let mut left_out = 0_usize;
    for (waits, _, record) in ordered {
        let size: usize = record.steps.iter().map(String::len).sum();
        let found = (requests.len() < MAX_REQUESTS_HANDED_OVER && size <= room)
            .then(|| {
                let (peer_identity, peer_owner) = if record.guest {
                    (record.peer_identity.clone(), record.peer_owner.clone())
                } else {
                    (newest(&record.peer_identity)?, newest(&record.peer_owner)?)
                };
                Some(SignedRequest {
                    guest: record.guest,
                    role: record.role,
                    peer_identity,
                    peer_owner,
                    peer_binding: record.peer_binding.clone(),
                    steps: record.steps.clone(),
                    cancel_wanted: record.cancel_wanted,
                    held: record.held.clone(),
                    not_used: record.owner_answer_not_used.clone().filter(|_| waits),
                })
            })
            .flatten();
        match found {
            Some(found) => {
                room = room.saturating_sub(size);
                requests.push(found);
            }
            None => left_out = left_out.saturating_add(1),
        }
    }
    SignedRequests {
        identity: signet.who().identity.encoded(),
        requests,
        held_opens,
        left_out,
        their_sealing: signet.their_sealing.all().await,
    }
}

async fn outcome(
    State(signet): State<Arc<Signet>>,
    Path(request): Path<String>,
) -> Result<Json<Outcome>, ApiError> {
    let records = signet.requests.store.lock().await;
    let record = records.get(&request).ok_or(ApiError::NotFound)?;
    let chain = record.chain(&signet)?;
    let outcome = chain.outcome().ok_or(ApiError::NotFound)?;
    let schemas = match chain.interaction_schema() {
        Some(schema) if !schema.is_built_in() => {
            splint_core::requests::Schemas::of([std::sync::Arc::new(schema.clone())])?
        }
        _ => splint_core::requests::Schemas::default(),
    };
    outcome.verify(&schemas)?;
    Ok(Json(outcome))
}

/// The whole exchange, for a person to read, with what only owners see.
async fn record(
    State(signet): State<Arc<Signet>>,
    Path(request): Path<String>,
) -> Result<Json<Dialogue>, ApiError> {
    Ok(Json(record_of(&signet, &request, Audience::Owner).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideBody {
    pub approval: String,
}

#[derive(Serialize)]
pub struct Decided {
    message_id: Option<MessageId>,
}

/// Signet sends the matching step itself: `confirm` for yes and `decline` for no. An agent has no
/// call for either, so it can't forge, suppress or twist what the owner decided.
///
/// One answer counts once. The owner's device leaves the same answer at this agent's host as it hands
/// here straight, and a yes goes out inside the step it released, so the same one comes again. A copy
/// of one already used finds nothing waiting for it: it isn't noted as an answer that couldn't be
/// used, and a no doesn't take away the same move the agent asked for again since.
pub async fn decide(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<DecideBody>,
) -> Result<Json<Decided>, ApiError> {
    if signet.owner_signed.has(&body.approval).await {
        return Err(ApiError::NotFound);
    }
    crate::recovery::hear_of_new_keys(&signet, &body.approval).await;
    let approval = VerifiedApproval::verify(&body.approval, &signet.who().owner)?;
    let decided = decide_verified(&signet, approval.clone()).await;
    match &decided {
        Ok(_) => signet.owner_signed.note(&body.approval).await,
        Err(error) => note_not_used(&signet, &approval, error).await,
    }
    decided
}

/// Keeps an owner's answer that couldn't be used on its request, for their next view and their agent's,
/// while something there still waits on them. Where nothing does, it went, as a yes heard twice, or the
/// request moved on without them, which their view shows. Only a verified answer gets here, so nobody
/// else can write to it, and it changes nothing about the request.
async fn note_not_used(signet: &Signet, approval: &VerifiedApproval, error: &ApiError) {
    // One for another agent of the same owner says nothing about this one's requests.
    if approval.agent() != signet.who().identity.id() {
        return;
    }
    let request = approval.request().as_str();
    let mut records = signet.requests.store.lock().await;
    let Some(mut record) = records.get(request).cloned() else {
        return;
    };
    let Ok(chain) = record.chain(signet) else {
        return;
    };
    let waiting = drafts_on(&record, &chain, unix_now());
    if waiting.is_empty() {
        return;
    }
    let names_one = waiting.iter().any(|draft| {
        draft.operation == approval.operation()
            && &draft.prev == approval.prev()
            && draft.version == approval.version()
            && &draft.terms == approval.terms()
    });
    let why = if !names_one {
        "changed".to_owned()
    } else if let Some(word) = error.refused_word() {
        word
    } else if matches!(
        error,
        ApiError::Host(_) | ApiError::CouldntReach(_) | ApiError::TooManyWaits
    ) {
        // Nothing refused it: this Signet couldn't save or send it just then, and it still waits.
        "not_now".to_owned()
    } else {
        "refused".to_owned()
    };
    record.owner_answer_not_used = Some(NotUsed {
        request: approval.request().clone(),
        operation: approval.operation(),
        decision: approval.decision(),
        version: approval.version(),
        why,
        at: unix_now(),
    });
    if let Err(error) = signet.requests.store.commit(&mut records, request, record) {
        tracing::warn!(%error, "couldn't keep that an owner's answer wasn't used");
    }
}

async fn decide_verified(
    signet: &Arc<Signet>,
    approval: VerifiedApproval,
) -> Result<Json<Decided>, ApiError> {
    let request = approval.request().as_str().to_owned();
    if approval.operation() == Operation::Open {
        return decide_open(signet, approval).await;
    }
    if approval.operation().releases_a_step() {
        return decide_held(signet, &request, approval).await;
    }
    let action = match (approval.operation(), approval.decision()) {
        (Operation::Confirm, Decision::Approve) => Action::Confirm(approval),
        (Operation::Confirm, Decision::Deny) => Action::ConfirmDenied(approval),
        // Only a cancel its agent asked for, so a view replayed or made up elsewhere can't get an
        // owner's yes to one nobody wanted.
        (Operation::Cancel, Decision::Approve) => {
            let records = signet.requests.store.lock().await;
            let wanted = records
                .get(&request)
                .ok_or(ApiError::NotFound)?
                .cancel_wanted;
            if !wanted {
                return Err(Refused::ApprovalMismatch.into());
            }
            Action::CancelApproved(approval)
        }
        (Operation::Cancel, Decision::Deny) => {
            let mut records = signet.requests.store.lock().await;
            let mut record = records.get(&request).ok_or(ApiError::NotFound)?.clone();
            record.cancel_wanted = false;
            // Written down now, as the agent reads it and an ask for it is answered from it.
            record.owner_said_no = Some(splint_core::requests::StepKind::Cancel);
            signet
                .requests
                .store
                .commit(&mut records, &request, record)?;
            return Ok(Json(Decided { message_id: None }));
        }
        (_, _) => return Err(Refused::ApprovalMismatch.into()),
    };
    sent(make_move(signet, &request, action).await?)
}

fn sent(made: Made) -> Result<Json<Decided>, ApiError> {
    match made {
        Made::Sent { id, .. } => Ok(Json(Decided {
            message_id: Some(id),
        })),
        // Only an agent's own move can wait, and this is the owner's.
        Made::Held { .. } => Err(Refused::OutOfTurn.into()),
    }
}

/// An owner's word on a move their agent asked for. A yes makes the step, carrying that yes, and the
/// chain compares what it signed with what's held. A no is only heard here, as nothing ever went: it
/// has to name what's held now, so an old no can't take away something the owner hasn't seen.
async fn decide_held(
    signet: &Signet,
    request: &str,
    approval: VerifiedApproval,
) -> Result<Json<Decided>, ApiError> {
    let held = {
        let mut records = signet.requests.store.lock().await;
        let mut record = records.get(request).ok_or(ApiError::NotFound)?.clone();
        let held = record.held.clone().ok_or(Refused::ApprovalMismatch)?;
        if approval.decision() == Decision::Deny {
            let chain = record.chain(signet)?;
            let draft = chain.held_draft(record.role, &held, unix_now())?;
            let names_it = draft.operation == approval.operation()
                && &draft.prev == approval.prev()
                && &draft.terms == approval.terms()
                && approval.agent() == signet.who().identity.id();
            if !names_it {
                return Err(Refused::ApprovalMismatch.into());
            }
            record.held = None;
            record.held_until_they_confirm = false;
            record.held_not_sent = None;
            record.owner_said_no = Some(held.kind());
            record.owner_answer_not_used = None;
            signet
                .requests
                .store
                .commit(&mut records, request, record)?;
            return Ok(Json(Decided { message_id: None }));
        }
        held
    };
    sent(make_move(signet, request, Action::Released(held, approval)).await?)
}

/// The same for an `open`, which has no chain yet to work anything out from. One yes makes one `open`:
/// the held one is claimed before anything here waits, and a sealed `open` is saved with the hold it
/// came from, so a yes heard again goes as the same bytes with the same ID, never sealed afresh.
async fn decide_open(
    signet: &Signet,
    approval: VerifiedApproval,
) -> Result<Json<Decided>, ApiError> {
    let held_opens = &signet.requests.held_opens;
    let claimed = held_opens
        .claim(approval.request())
        .await
        .ok_or(ApiError::NotFound)?;
    let open: &HeldOpen = claimed.open();
    // It went, and a crash or a failed save stopped it being settled. That's asked first, so a rule,
    // a contact or the yes's dates changing since can't leave it waiting for a decision already made.
    // Nothing new is signed here: it stays in the outbox until its host has it, so flushing sends
    // those same bytes, and a no can't call it back.
    if let Some((request, message_id)) = sent_from(signet, &open.hold).await? {
        held_opens
            .settle(&claimed, HoldStatus::Signed { request })
            .await?;
        if approval.decision() == Decision::Deny {
            return Err(ApiError::NotFound);
        }
        if let Err(error) = sync::flush(signet).await {
            tracing::debug!(%error, "a step is waiting to reach our host");
        }
        return Ok(Json(Decided {
            message_id: Some(message_id),
        }));
    }
    let now = unix_now();
    let contact = contact_at(signet, &open.address)
        .await?
        .ok_or(ApiError::NotAContact)?;
    let chain = new_record(&contact).chain(signet)?;
    if approval.decision() == Decision::Deny {
        let draft = chain.open_draft(&open.offer, &open.nonce, now)?;
        let names_it =
            &draft.terms == approval.terms() && approval.agent() == signet.who().identity.id();
        if !names_it {
            return Err(Refused::ApprovalMismatch.into());
        }
        held_opens.settle(&claimed, HoldStatus::OwnerSaidNo).await?;
        return Ok(Json(Decided { message_id: None }));
    }
    // The rules may have changed since the agent asked, and its host would only refuse it.
    let schemas = signet
        .requests
        .types
        .schemas_with(contact.agent.id(), contact.owner.id());
    let schema = schemas
        .get(&open.offer.interaction)
        .ok_or(Refused::UnknownType)?;
    if !contact.rule.may_use(schema) || !signet.rules.may_start_with(&open.address).await {
        return Err(Refused::TypeNotAllowed.into());
    }
    let checked = chain.released_open(&open.offer, &open.nonce, &approval, now)?;
    let supersedes = open.offer.supersedes.as_ref();
    let (request, message_id) =
        send_open(signet, contact, checked, supersedes, Some(&open.hold)).await?;
    held_opens
        .settle(&claimed, HoldStatus::Signed { request })
        .await?;
    Ok(Json(Decided {
        message_id: Some(message_id),
    }))
}

/// The request a held open became, and the ID its `open` went with.
async fn sent_from(
    signet: &Signet,
    hold: &MessageId,
) -> Result<Option<(String, MessageId)>, ApiError> {
    let records = signet.requests.store.lock().await;
    let Some((request, record)) = started_from(&records, hold) else {
        return Ok(None);
    };
    let message_id = record
        .chain(signet)?
        .request()
        .cloned()
        .ok_or(HostError::LocalStorage)?;
    Ok(Some((request.clone(), message_id)))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::RwLock;
    use std::time::Duration;

    use serde_json::{Value, json};
    use splint_core::VerifiedEnvelope;
    use splint_core::requests::{
        Action, Chain, CheckedStep, Deadline, Fields, InteractionType, Parties, Party,
        ProposedSchema, Schema, Schemas, hold_of,
    };
    use splint_core::rules::{
        ContactStatus, Permissions, PinnedBy, Reach, RulesContact, RulesDraft, RulesLimits,
    };
    use splint_core::transport::Scheme;
    use splint_core::{RecoveryRule, Sealing, SealingKey, SigningKey, SplintId};
    use tokio::sync::Mutex;

    use super::*;
    use crate::binding::Registered;
    use crate::budget::Budget;
    use crate::contacts::{Contacts, Known};
    use crate::host_client::HostClient;
    use crate::requests::Requests;
    use crate::requests::held_opens::HeldOpens;
    use crate::requests::store::Store;
    use crate::rules::RulesStore;
    use crate::who::Who;
    use crate::{changes, contact_asks, grants, requests, sealing, seen, state_file};

    const BEN: &str = "ben~localhost";
    const HOUR: u64 = 60 * 60;
    const TAKEN_FILE: &str = "owner-signed-taken.json";

    fn identity_for(key: &SigningKey, seal: &SealingKey) -> Identity {
        let backup = SigningKey::generate().unwrap();
        Identity::create(
            key,
            &seal.public_key(),
            RecoveryRule::backup_key(&backup.public_key()),
        )
        .unwrap()
    }

    /// Ana's state folder: her owner's signed rules, with Ben as a contact for quotes, and Ben's IDs
    /// pinned, so nothing has to be looked up. Each owner left sealing at its default.
    struct Ana {
        state: PathBuf,
        owner_key: SigningKey,
        who: Who,
        ben: SplintId,
        /// Nothing listens here, so every step stays in the outbox, as it would with a host that's down.
        host: String,
    }

    fn quote() -> Schema {
        Schema::parse(include_bytes!("../../../../spec/schemas/quote-1.json")).unwrap()
    }

    /// Ana's agent and Ben's agreeing quotes with `type/1`, as their Signets would, saved where her
    /// Signet reads what's agreed from as it starts.
    fn agree_quotes(
        state: &Path,
        ana: (&SigningKey, &Identity, &Identity),
        ben: (&SigningKey, &Identity, &Identity),
    ) {
        let party = |agent: &Identity, owner: &Identity| Party {
            agent: agent.clone(),
            owner: owner.clone(),
            binding: String::new(),
        };
        let parties = Parties {
            requester: party(ana.1, ana.2),
            recipient: party(ben.1, ben.2),
        };
        let now = unix_now();
        let offer = Offer {
            interaction: InteractionType::proposal(),
            schema: Some(ProposedSchema::new(quote()).unwrap()),
            terms: Fields::new(),
            deadline: Deadline::try_from((now / HOUR + 24) * HOUR).unwrap(),
            supersedes: None,
        };
        let mut chain = Chain::new(parties, Schemas::default());
        let open = CheckedStep::open(offer, &Schemas::default(), ben.1.id(), now)
            .unwrap()
            .sign(ana.0, ana.1, now)
            .unwrap();
        chain
            .apply(&VerifiedEnvelope::verify(&open.compact, ana.1, now).unwrap())
            .unwrap();
        let accept = chain
            .propose(
                Side::Recipient,
                Action::Accept {
                    pick: Fields::new(),
                },
                now,
            )
            .unwrap()
            .sign(ben.0, ben.1, now)
            .unwrap();
        chain
            .apply(&VerifiedEnvelope::verify(&accept.compact, ben.1, now).unwrap())
            .unwrap();
        let mut record = crate::requests::store::Record::new(
            Side::Requester,
            BEN.to_owned(),
            ben.1.encoded(),
            ben.2.encoded(),
            String::new(),
        );
        record.steps = chain.steps();
        let records = HashMap::from([(open.id.as_str().to_owned(), record)]);
        state_file::save(&state.join("requests.json"), &records).unwrap();
    }

    /// One open her agent asked for at `ask_me`, and her owner's yes and no to it.
    struct Asked {
        hold: MessageId,
        yes: String,
        no: String,
    }

    impl Ana {
        fn new(name: &str) -> Self {
            let state = std::env::temp_dir().join(format!("signet-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&state);
            std::fs::create_dir_all(&state).unwrap();
            let key = SigningKey::load_or_create(&state.join("agent.key")).unwrap();
            let seal = SealingKey::load_or_create(&state.join("agent.seal")).unwrap();
            let owner_key = SigningKey::generate().unwrap();
            let owner = identity_for(&owner_key, &SealingKey::generate().unwrap());
            let identity = identity_for(&key, &seal);
            let ben_key = SigningKey::generate().unwrap();
            let ben = identity_for(&ben_key, &SealingKey::generate().unwrap());
            let ben_owner = identity_for(
                &SigningKey::generate().unwrap(),
                &SealingKey::generate().unwrap(),
            );
            let pinned = HashMap::from([(
                BEN,
                json!({"identity": ben.encoded(), "owner": ben_owner.encoded(), "binding": ""}),
            )]);
            state_file::save(&state.join("contacts.json"), &pinned).unwrap();
            agree_quotes(
                &state,
                (&key, &identity, &owner),
                (&ben_key, &ben, &ben_owner),
            );
            let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let host = format!("localhost:{}", closed.local_addr().unwrap().port());
            let ana = Self {
                state,
                owner_key,
                who: Who {
                    identity,
                    owner,
                    binding: String::new(),
                },
                ben: ben.id().clone(),
                host,
            };
            ana.sign_rules(1, &[quote().name().clone()]);
            ana
        }

        /// Her owner's rules, letting Ben have `types` with her, and no others.
        fn sign_rules(&self, seq: u64, types: &[InteractionType]) {
            let rules = RulesDraft {
                paused: false,
                reach: Reach::default(),
                permissions: Permissions::default(),
                changes: splint_core::changes::ChangeRules::default(),
                sealing: Sealing::Sealed,
                delegation: None,
                ends_at: None,
                contacts: vec![RulesContact {
                    agent: self.ben.clone(),
                    address: BEN.to_owned(),
                    label: "Ben".to_owned(),
                    status: ContactStatus::Allowed,
                    types: types.to_vec(),
                    text: false,
                    agree_types: false,
                    pinned_by: PinnedBy::Owner,
                }],
                invites: Vec::new(),
                limits: RulesLimits {
                    new_requests_per_contact_per_day: 10,
                    open_requests_per_contact: 3,
                    open_approvals: 10,
                    new_from_others_per_day: 50,
                    texts_per_contact_per_day: 20,
                    agreed_texts_per_day: None,
                    agreed_new_requests_per_day: None,
                    sends_per_hour: None,
                    sends_per_day: None,
                },
            }
            .sign(
                &self.owner_key,
                self.who.owner.id(),
                self.who.identity.id(),
                seq,
                unix_now(),
            )
            .unwrap();
            state_file::save(
                &self.state.join("rules.json"),
                &HashMap::from([("rules", rules)]),
            )
            .unwrap();
        }

        /// Her Signet, as it starts from what's in her state folder.
        async fn restarted(&self) -> Arc<Signet> {
            let signet = self.loaded().await;
            signet.requests.settle_held_opens().await.unwrap();
            signet
        }

        /// The same, before it has squared its held opens with what it sent. That's the state a call
        /// cut short leaves behind while Signet runs: the `open` saved, and its hold still waiting.
        async fn loaded(&self) -> Arc<Signet> {
            let state = &self.state;
            let at = |file: &str| state.join(file);
            let known = Arc::new(Known::load(at("known.json")).unwrap());
            let seen_changes = Arc::new(changes::Seen::load(at("seen-changes.json")).unwrap());
            let contact_asks =
                Arc::new(contact_asks::ContactAsks::load(at("contact-asks.json")).unwrap());
            let who = &self.who;
            let signet = Arc::new(Signet {
                key: SigningKey::load_or_create(&at("agent.key")).unwrap(),
                seal_key: SealingKey::load_or_create(&at("agent.seal")).unwrap(),
                who: RwLock::new(Arc::new(who.clone())),
                who_path: at("who.json"),
                changing_who: Mutex::new(()),
                started_at: "ana~localhost".to_owned(),
                address: RwLock::new("ana~localhost".to_owned()),
                api_token: String::new(),
                invites: crate::invites::Invites::load(
                    at("invites-sent.json"),
                    at("invites-pending.json"),
                )
                .unwrap(),
                host: HostClient {
                    domain: self.host.clone(),
                    scheme: Scheme::PlainHttpForTests,
                    http: reqwest::Client::builder()
                        .timeout(Duration::from_secs(5))
                        .build()
                        .unwrap(),
                    closing: Default::default(),
                },
                contacts: Contacts::load(
                    at("contacts.json"),
                    known.clone(),
                    seen_changes.clone(),
                    contact_asks.clone(),
                )
                .unwrap(),
                seen: seen::Seen::load(at("seen.json")).unwrap(),
                requests: Requests {
                    store: Store::load(at("requests.json")).unwrap(),
                    person_texts: requests::person_text::Waiting::load(
                        at("person-texts.json"),
                        at("person-texts-taken.json"),
                    )
                    .unwrap(),
                    where_paid: requests::payments::WherePaid::load(at("where-paid.json")).unwrap(),
                    held_opens: HeldOpens::load(at("held-opens.json")).unwrap(),
                    owner_token: None,
                    types: requests::types::AgreedTypes::default(),
                    refused: requests::refusals::Refusals::load(at("refused.json")).unwrap(),
                    guest_steps_read: 0.into(),
                },
                rules: RulesStore::load(
                    at("rules.json"),
                    state,
                    &who.owner,
                    who.identity.id(),
                    known,
                    seen_changes.clone(),
                )
                .unwrap(),
                registered: Registered::new(String::new()),
                budget: Budget::load(at("budget.json")).unwrap(),
                grants: grants::Grants::load(at("grants.json")).unwrap(),
                own_changes: changes::Own::load(
                    at("history.json"),
                    at("listeners.json"),
                    &who.identity,
                )
                .unwrap(),
                seen_changes,
                contact_asks,
                asks: crate::asks::Asks::load(at("asks.json")).unwrap(),
                their_sealing: sealing::TheirSealing::load(at("their-sealing.json")).unwrap(),
                activity: crate::activity::Activity::load(self.state.join("wakes.json")).unwrap(),
                delegation: crate::delegation::Delegation::load(&self.state).unwrap(),
                arrivals: crate::arrivals::Arrivals::load(
                    self.state.join("arrivals.json"),
                    self.state.join("arrivals-notes.json"),
                )
                .unwrap(),
                owner_signed: crate::owner_relay::TakenOnce::load(at(TAKEN_FILE)).unwrap(),
                retired: crate::retired::Retired::kept_at(at("retirement.json")),
                carried: crate::carried::Carried::load(state.join("carried-mail.json")).unwrap(),
                sent: crate::sent::Sent::load(state.join("sent.json")).unwrap(),
                receipts: crate::receipts::Receipts::load(state.join("receipts.json")).unwrap(),
            });
            requests::types::read_all(&signet).await;
            signet
        }

        /// An open her agent asked for at `ask_me`, for `quantity` catering, and her owner's yes and
        /// no to it.
        async fn ask(&self, signet: &Signet, quantity: u32) -> Asked {
            let offer_of = |quantity| {
                serde_json::from_value::<Offer>(json!({
                    "type": quote().name(),
                    "terms": {"currency": "usd", "item": "catering", "quantity": quantity},
                    "deadline": (unix_now() / HOUR + 48) * HOUR,
                    "supersedes": null,
                }))
                .unwrap()
            };
            let offer = offer_of(quantity);
            let nonce = splint_core::random_nonce().unwrap();
            let hold = hold_of(&nonce);
            let open = HeldOpen {
                hold: hold.clone(),
                nonce: nonce.clone(),
                offer: offer.clone(),
                address: BEN.to_owned(),
                status: HoldStatus::Waiting,
            };
            signet
                .requests
                .held_opens
                .keep(open, 10)
                .await
                .ok()
                .unwrap();
            let contact = contact_at(signet, BEN).await.unwrap().unwrap();
            let now = unix_now();
            let chain = new_record(&contact).chain(signet).unwrap();
            let draft = chain.open_draft(&offer, &nonce, now).unwrap();
            let sign = |decision| draft.sign(&self.owner_key, decision, None, now).unwrap();
            let (yes, no) = (sign(Decision::Approve), sign(Decision::Deny));

            // Why this needs the sealed form: sealing is fresh each time, so the same yes signs to
            // a new ID every time, unlike an unsealed open.
            let verified = VerifiedApproval::verify(&yes, &self.who.owner).unwrap();
            let sign = || async {
                let checked = chain.released_open(&offer, &nonce, &verified, now).unwrap();
                signet
                    .sign_step(checked, &contact.agent, now)
                    .await
                    .ok()
                    .unwrap()
            };
            assert_ne!(sign().await.id, sign().await.id);
            Asked { hold, yes, no }
        }

        /// A no from her owner that names the right hold but other terms than the agent asked for.
        async fn no_to_other_terms(&self, signet: &Signet, asked: &Asked) -> String {
            let open = signet.requests.held_opens.claim(&asked.hold).await.unwrap();
            let mut offer = serde_json::to_value(&open.open().offer).unwrap();
            offer["terms"]["quantity"] = json!(999);
            let offer: Offer = serde_json::from_value(offer).unwrap();
            let contact = contact_at(signet, BEN).await.unwrap().unwrap();
            let chain = new_record(&contact).chain(signet).unwrap();
            let now = unix_now();
            let draft = chain.open_draft(&offer, &open.open().nonce, now).unwrap();
            draft
                .sign(&self.owner_key, Decision::Deny, None, now)
                .unwrap()
        }
    }

    async fn decide_with(
        signet: &Arc<Signet>,
        approval: &str,
    ) -> Result<Option<MessageId>, ApiError> {
        let body = DecideBody {
            approval: approval.to_owned(),
        };
        let decided = decide(State(signet.clone()), Json(body)).await?;
        Ok(decided.0.message_id)
    }

    /// Each request this Signet has, with the steps still to reach its host, but for the `type/1` that
    /// agreed quotes, which went before the test began.
    async fn outboxes(signet: &Signet) -> Vec<(String, Vec<String>)> {
        let records = signet.requests.store.lock().await;
        records
            .iter()
            .filter(|(_, record)| {
                let agreeing = record
                    .chain(signet)
                    .is_ok_and(|chain| chain.proposed_schema().is_some());
                !agreeing
            })
            .map(|(request, record)| {
                let outbox = record.outbox.iter().map(|out| out.compact.clone());
                (request.clone(), outbox.collect())
            })
            .collect()
    }

    /// What the agent reads became of the open it asked to start as `hold`.
    async fn agent_reads(signet: &Signet, hold: &MessageId) -> Value {
        let views = signet.requests.held_opens.views(unix_now()).await;
        let views = serde_json::to_value(views).unwrap();
        let view = views.as_array().unwrap().iter();
        let mut view = view.filter(|view| view["hold"] == hold.as_str());
        let view = view.next().unwrap().clone();
        json!({"status": view["status"], "request": view["request"]})
    }

    fn went_as(id: &MessageId) -> Value {
        json!({"status": "signed", "request": id.as_str()})
    }

    #[tokio::test]
    async fn two_decisions_at_once_on_one_yes_send_one_sealed_open() {
        let ana = Ana::new("one-yes-at-once");
        let signet = ana.restarted().await;
        let asked = ana.ask(&signet, 40).await;

        let (one, two) = tokio::join!(
            decide_with(&signet, &asked.yes),
            decide_with(&signet, &asked.yes)
        );
        let sent: Vec<MessageId> = [one, two]
            .into_iter()
            .filter_map(|decided| match decided {
                Ok(id) => Some(id.unwrap()),
                Err(ApiError::NotFound) => None,
                Err(_) => panic!("refused for a reason other than being decided already"),
            })
            .collect();
        assert_eq!(sent.len(), 1, "one yes makes one open");
        let outboxes = outboxes(&signet).await;
        assert_eq!(outboxes.len(), 1);
        assert_eq!(outboxes[0].0, sent[0].as_str());
        assert_eq!(agent_reads(&signet, &asked.hold).await, went_as(&sent[0]));
        assert!(matches!(
            decide_with(&signet, &asked.yes).await,
            Err(ApiError::NotFound)
        ));
        std::fs::remove_dir_all(&ana.state).unwrap();
    }

    #[tokio::test]
    async fn a_decision_while_another_is_deciding_is_told_nothing_waits() {
        let ana = Ana::new("one-yes-claimed");
        let signet = ana.restarted().await;
        let asked = ana.ask(&signet, 40).await;

        // As a call partway through deciding it holds it, whether or not the two calls overlap by
        // chance as they run.
        let deciding = signet.requests.held_opens.claim(&asked.hold).await.unwrap();
        assert!(matches!(
            decide_with(&signet, &asked.yes).await,
            Err(ApiError::NotFound)
        ));
        assert!(matches!(
            decide_with(&signet, &asked.no).await,
            Err(ApiError::NotFound)
        ));
        assert!(outboxes(&signet).await.is_empty());
        drop(deciding);
        let sent = decide_with(&signet, &asked.yes)
            .await
            .ok()
            .unwrap()
            .unwrap();
        assert_eq!(agent_reads(&signet, &asked.hold).await, went_as(&sent));
        std::fs::remove_dir_all(&ana.state).unwrap();
    }

    #[tokio::test]
    async fn a_refused_decision_leaves_the_open_to_decide() {
        let ana = Ana::new("one-yes-refused-first");
        let signet = ana.restarted().await;
        let asked = ana.ask(&signet, 40).await;
        let wrong_no = ana.no_to_other_terms(&signet, &asked).await;

        assert!(matches!(
            decide_with(&signet, &wrong_no).await,
            Err(ApiError::Refused(Refused::ApprovalMismatch))
        ));
        let sent = decide_with(&signet, &asked.yes)
            .await
            .ok()
            .unwrap()
            .unwrap();
        assert_eq!(agent_reads(&signet, &asked.hold).await, went_as(&sent));
        std::fs::remove_dir_all(&ana.state).unwrap();
    }

    #[tokio::test]
    async fn each_of_two_held_opens_sends_its_own() {
        let ana = Ana::new("one-yes-two-holds");
        let signet = ana.restarted().await;
        let forty = ana.ask(&signet, 40).await;
        let forty_one = ana.ask(&signet, 41).await;

        let first = decide_with(&signet, &forty.yes)
            .await
            .ok()
            .unwrap()
            .unwrap();
        let second = decide_with(&signet, &forty_one.yes)
            .await
            .ok()
            .unwrap()
            .unwrap();
        assert_ne!(
            first, second,
            "a second hold's yes sent the first one's open"
        );
        assert_eq!(outboxes(&signet).await.len(), 2);
        assert_eq!(agent_reads(&signet, &forty.hold).await, went_as(&first));
        assert_eq!(
            agent_reads(&signet, &forty_one.hold).await,
            went_as(&second)
        );
        std::fs::remove_dir_all(&ana.state).unwrap();
    }

    /// The hold put back to waiting on disk, as if Signet stopped after saving its `open` but before
    /// marking the hold sent, which is before the yes was remembered as taken.
    fn crash_before_settling(ana: &Ana) {
        let path = ana.state.join("held-opens.json");
        let mut held = state_file::load::<Value>(&path).unwrap();
        for open in held.values_mut() {
            open["status"] = json!({"status": "waiting"});
        }
        state_file::save(&path, &held).unwrap();
        std::fs::remove_file(ana.state.join(TAKEN_FILE)).unwrap();
    }

    #[tokio::test]
    async fn after_a_crash_a_restart_marks_what_went_as_sent() {
        let ana = Ana::new("one-yes-restart");
        let signet = ana.restarted().await;
        let asked = ana.ask(&signet, 40).await;
        let first = decide_with(&signet, &asked.yes)
            .await
            .ok()
            .unwrap()
            .unwrap();
        let before = outboxes(&signet).await;
        drop(signet);
        crash_before_settling(&ana);

        let restarted = ana.restarted().await;
        // Nothing has to say the same yes again for the owner and the agent to see it went.
        assert!(
            restarted
                .requests
                .held_opens
                .waiting(unix_now())
                .await
                .is_empty(),
            "the owner's device still lists it as waiting for a decision already made"
        );
        assert_eq!(agent_reads(&restarted, &asked.hold).await, went_as(&first));
        assert!(matches!(
            decide_with(&restarted, &asked.yes).await,
            Err(ApiError::NotFound)
        ));
        assert_eq!(
            outboxes(&restarted).await,
            before,
            "the same bytes, still to go"
        );
        std::fs::remove_dir_all(&ana.state).unwrap();
    }

    #[tokio::test]
    async fn a_yes_heard_again_before_it_was_settled_resends_the_same_open() {
        let ana = Ana::new("one-yes-again");
        let signet = ana.restarted().await;
        let asked = ana.ask(&signet, 40).await;
        let first = decide_with(&signet, &asked.yes)
            .await
            .ok()
            .unwrap()
            .unwrap();
        let before = outboxes(&signet).await;
        drop(signet);
        crash_before_settling(&ana);
        // And the owner stopped letting Ben have quotes since, which would refuse a new open.
        ana.sign_rules(2, &[]);

        let signet = ana.loaded().await;
        let again = decide_with(&signet, &asked.yes)
            .await
            .ok()
            .unwrap()
            .unwrap();
        assert_eq!(again, first, "the same open, by the same ID");
        assert_eq!(
            outboxes(&signet).await,
            before,
            "and the same bytes, still to go"
        );
        assert_eq!(agent_reads(&signet, &asked.hold).await, went_as(&first));
        assert!(matches!(
            decide_with(&signet, &asked.yes).await,
            Err(ApiError::NotFound)
        ));
        std::fs::remove_dir_all(&ana.state).unwrap();
    }

    #[tokio::test]
    async fn a_no_heard_after_it_went_marks_it_sent() {
        let ana = Ana::new("one-yes-then-no");
        let signet = ana.restarted().await;
        let asked = ana.ask(&signet, 40).await;
        let first = decide_with(&signet, &asked.yes)
            .await
            .ok()
            .unwrap()
            .unwrap();
        drop(signet);
        crash_before_settling(&ana);

        let signet = ana.loaded().await;
        assert!(matches!(
            decide_with(&signet, &asked.no).await,
            Err(ApiError::NotFound)
        ));
        assert_eq!(
            agent_reads(&signet, &asked.hold).await,
            went_as(&first),
            "the agent read that its owner said no to an interaction that started"
        );
        std::fs::remove_dir_all(&ana.state).unwrap();
    }
}

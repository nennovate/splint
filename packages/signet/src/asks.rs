//! An agent's asks of its owner: exact changes to how it deals with other agents, which this Signet
//! signs with the agent's key and keeps, and leaves in the owner's view at its host. An ask changes
//! nothing and hands the agent nothing it could use again: only the owner's signature on new rules
//! does, delivered by whatever route. So an ask is done when the rules in force hold all of it, and
//! has ended when it runs out first. See "An agent's ask" in `docs/protocol.md`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as ShortLock, PoisonError};

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::asks::{Change, MAX_ASK_SECS, VerifiedAsk, sign_ask};
use splint_core::unix_now;

use crate::Signet;
use crate::agent_api::ApiError;
use crate::budget::NotTaken;
use crate::host_client::HostError;
use crate::state_file::{self, StateError};

/// Shared with asks for a contact: more than an honest agent asks in a day, few enough to read.
pub const ASKS_PER_DAY: u32 = 10;
const MAX_ON_FILE: usize = 32;
/// An hour, unless the agent says longer, up to a day for a person who's away.
const DEFAULT_HOURS: u64 = 1;
/// The most an ask for controls lasts: whoever approves first by its link becomes this agent's owner,
/// so a link that went astray has to stop working soon, and the agent can always ask again.
const MAX_CONTROLS_HOURS: u64 = 1;
/// How long an ask's outcome is kept for the agent to read after it's done or over.
const KEEP_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Deserialize, Serialize)]
struct Entry {
    compact: String,
    expires_at: u64,
    /// When the rules in force first held all of it, or, for a step, when the chain first held the
    /// step carrying the owner's yes, which stands whatever is signed later.
    done_at: Option<u64>,
    /// When Signet first saw the owner's no to the step it asks for, which stands too.
    #[serde(default)]
    owner_said_no_at: Option<u64>,
    /// When Signet first saw the request end without the owner's yes to the step it asks for.
    #[serde(default)]
    ended_at: Option<u64>,
    /// For a step, the exact draft held for the owner when it was asked, so only a yes to that one
    /// counts, never one to an earlier step of the same kind. An ask kept before this has none, and
    /// is never read as done from the chain.
    #[serde(default)]
    draft: Option<ForDraft>,
}

/// The draft a step's ask was made for: the step it follows, its version, and its terms' `digest`.
#[derive(Clone, Deserialize, Serialize)]
struct ForDraft {
    prev: splint_core::MessageId,
    version: u32,
    terms: splint_core::MessageId,
}

impl Entry {
    /// Still for the owner to answer: nothing settled it and it hasn't run out.
    fn open(&self, now: u64) -> bool {
        self.done_at.is_none()
            && self.owner_said_no_at.is_none()
            && self.ended_at.is_none()
            && now < self.expires_at
    }
}

pub struct Asks {
    path: PathBuf,
    /// By ID.
    entries: ShortLock<HashMap<String, Entry>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Waiting,
    /// What it asked for is in force. A step is done only once the chain holds it with the owner's yes.
    Done,
    /// It ran out before the owner signed it, which is all a no to rules ever is: nothing is signed for
    /// one.
    NotApproved,
    /// The owner said no to the step it asks for, as the chain or this Signet shows.
    OwnerSaidNo,
    /// The request ended without the owner's yes to the step it asks for.
    Ended,
}

impl Asks {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        Ok(Self {
            entries: ShortLock::new(state_file::load::<Entry>(&path)?),
            path,
        })
    }

    fn write_down(
        &self,
        change: impl FnOnce(&mut HashMap<String, Entry>),
    ) -> Result<(), HostError> {
        let now = unix_now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|_, entry| now < entry.expires_at.saturating_add(KEEP_SECS));
        change(&mut entries);
        state_file::save(&self.path, &*entries).map_err(|_| HostError::LocalStorage)
    }

    /// The asks still open, as signed, for the owner's view. A step's is read from its chain first, so
    /// one the owner refused or whose request ended is left out, and doesn't count toward the cap.
    pub async fn waiting(signet: &Signet, now: u64) -> Vec<String> {
        for entry in signet.asks.all() {
            let for_a_step = splint_core::asks::payload_changes(&entry.compact)
                .is_ok_and(|changes| splint_core::asks::step_of(&changes).is_some());
            if entry.open(now)
                && for_a_step
                && let Ok(id) = id_of(signet, &entry)
            {
                // One that can't be written down now is read again next time.
                let _ = shown(signet, &id, entry).await;
            }
        }
        let entries = signet
            .asks
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut open: Vec<&Entry> = entries.values().filter(|entry| entry.open(now)).collect();
        open.sort_by_key(|entry| entry.expires_at);
        open.into_iter()
            .map(|entry| entry.compact.clone())
            .collect()
    }

    fn all(&self) -> Vec<Entry> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }
}

/// Ends every ask for controls still waiting, as a new one replaces them: a link to one makes whoever
/// approves first this agent's owner, so only the newest can still do that.
fn end_asks_for_controls(entries: &mut HashMap<String, Entry>, now: u64) {
    for entry in entries.values_mut() {
        let waiting = entry.open(now);
        let for_controls = || {
            splint_core::asks::payload_changes(&entry.compact)
                .is_ok_and(|changes| splint_core::asks::controls_delegate(&changes).is_some())
        };
        if waiting && for_controls() {
            entry.expires_at = now;
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskBody {
    changes: Vec<Change>,
    #[serde(default)]
    hours: Option<u64>,
}

/// One ask as the agent reads it back: what it asked for, and where it stands.
#[derive(Serialize)]
pub struct Shown {
    id: String,
    ask: String,
    changes: Vec<Change>,
    expires_at: u64,
    status: Status,
}

#[derive(Serialize)]
pub struct Listed {
    asks: Vec<Shown>,
}

pub fn agent_routes() -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/asks", post(ask).get(list))
        .route("/v0/asks/{id}", get(one))
}

/// Signs and keeps an ask, after checking each type it names is one this agent agreed: with that
/// contact for a contact, or with anyone for who else may reach it, so the owner's side has its schema
/// to show, and a type's ID never stands for words nobody here has seen.
async fn ask(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<AskBody>,
) -> Result<Json<Shown>, ApiError> {
    let agreed = &signet.requests.types;
    let with_anyone = agreed.schemas_with_anyone();
    let names_unknown_type = body.changes.iter().any(|change| match change {
        Change::Contact { agent, types, .. } => {
            types.iter().any(|named| !agreed.seen_with(agent, named))
        }
        Change::Reach { types, .. } => types.iter().any(|named| with_anyone.get(named).is_none()),
        _ => false,
    });
    if names_unknown_type {
        return Err(ApiError::BadRequest(
            "a type this agent hasn't agreed with them",
        ));
    }
    // No owner has signed where a stand-in gets paid, so only an owner who confirmed is asked.
    if let Some(places) = splint_core::asks::where_paid_of(&body.changes) {
        if signet.who().owner.is_unconfirmed_owner() {
            return Err(ApiError::BadRequest(
                "your person sets up your controls before saying where they get paid",
            ));
        }
        // Each place goes to every payer under the owner's signature, so nothing this Signet holds,
        // such as the agent's own token, rides out in one, as it wouldn't in a note.
        let places =
            serde_json::to_string(places).map_err(|_| ApiError::Host(HostError::LocalStorage))?;
        crate::secret_egress::refuse_secrets(&signet, &places).await?;
    }
    // A contact or a block is shown to the person by its address, and signed by its ID, so the two
    // have to be the same agent, as its host names it now.
    for change in &body.changes {
        if let Change::Contact { agent, address, .. } | Change::Block { agent, address } = change {
            at_address(&signet, agent, address).await?;
        }
    }
    // A move is asked of an owner who confirmed, as a stand-in's agent moves by itself, for an agent
    // registered at an address on another host, and only while its history has room to say so.
    if let Some(to) = splint_core::asks::host_of(&body.changes) {
        may_ask_to_move(&signet, to).await?;
    }
    // An owner part goes after this agent's handle here, so it's one that fits, for a name that has
    // none yet, and one a host gives out with no code, so it can't pass for the host or for Splint.
    if let Some(owner_part) = splint_core::asks::owner_part_of(&body.changes) {
        may_name_owner_part(&signet, &body.changes, owner_part)?;
    }
    // A step is asked for only while it's held for the owner, and the ask names that exact draft.
    let draft = match splint_core::asks::step_of(&body.changes) {
        Some((request, operation)) => {
            let held =
                held_draft(&signet, request, operation)
                    .await
                    .ok_or(ApiError::BadRequest(
                        "no step of that request is waiting for your owner",
                    ))?;
            Some(ForDraft {
                terms: held
                    .terms
                    .digest()
                    .ok_or(ApiError::Host(HostError::LocalStorage))?,
                prev: held.prev,
                version: held.version,
            })
        }
        None => None,
    };
    // Controls name the delegate key this Signet holds, whatever the agent wrote, so the delegation
    // the owner signs with them is one this Signet can use.
    let delegate = signet.delegation.held().await.key.public_key().encoded();
    let mut changes = body.changes;
    for change in &mut changes {
        if let Change::Controls {
            delegate: named, ..
        } = change
        {
            named.clone_from(&delegate);
        }
    }
    let hours = body.hours.unwrap_or(DEFAULT_HOURS);
    let lasts = hours.saturating_mul(60 * 60);
    if hours == 0 || lasts > MAX_ASK_SECS {
        return Err(ApiError::BadRequest("an ask lasts 1 to 24 hours"));
    }
    let for_controls = splint_core::asks::controls_delegate(&changes).is_some();
    if for_controls && hours > MAX_CONTROLS_HOURS {
        return Err(ApiError::BadRequest("an ask for controls lasts 1 hour"));
    }
    if Asks::waiting(&signet, unix_now()).await.len() >= MAX_ON_FILE {
        return Err(ApiError::TooManyAsks);
    }
    let now = unix_now();
    let who = signet.who();
    let compact = sign_ask(
        &signet.key,
        who.identity.id(),
        who.owner.id(),
        changes,
        now,
        lasts,
    )
    .map_err(|_| ApiError::BadRequest("not an ask an owner could sign"))?;
    let verified = VerifiedAsk::verify(&compact, &who.identity, now)
        .map_err(|_| ApiError::BadRequest("not an ask an owner could sign"))?;
    signet
        .budget
        .take_contact_ask(ASKS_PER_DAY, now)
        .await
        .map_err(|not_taken| match not_taken {
            NotTaken::Spent => ApiError::TooManyAsks,
            NotTaken::Unsaved => ApiError::Host(HostError::LocalStorage),
        })?;
    let entry = Entry {
        compact,
        expires_at: verified.expires_at(),
        done_at: None,
        owner_said_no_at: None,
        ended_at: None,
        draft,
    };
    signet.asks.write_down(|entries| {
        if for_controls {
            end_asks_for_controls(entries, now);
        }
        entries.insert(verified.id().to_owned(), entry.clone());
    })?;
    Ok(Json(shown(&signet, verified.id(), entry).await?))
}

async fn list(State(signet): State<Arc<Signet>>) -> Result<Json<Listed>, ApiError> {
    let mut asks = Vec::new();
    let mut all = signet.asks.all();
    all.sort_by_key(|entry| std::cmp::Reverse(entry.expires_at));
    for entry in all {
        let Ok(id) = id_of(&signet, &entry) else {
            continue;
        };
        asks.push(shown(&signet, &id, entry).await?);
    }
    Ok(Json(Listed { asks }))
}

async fn one(
    State(signet): State<Arc<Signet>>,
    Path(id): Path<String>,
) -> Result<Json<Shown>, ApiError> {
    let entry = signet
        .asks
        .all()
        .into_iter()
        .find(|entry| id_of(&signet, entry).is_ok_and(|found| found == id))
        .ok_or(ApiError::NotFound)?;
    Ok(Json(shown(&signet, &id, entry).await?))
}

/// An ask this Signet signed and kept, so its ID is read as written, unless it was this agent's
/// before a move to another ID, which isn't this one's to show.
fn id_of(signet: &Signet, entry: &Entry) -> Result<String, splint_core::Error> {
    if &VerifiedAsk::claimed_agent(&entry.compact)? != signet.who().identity.id() {
        return Err(splint_core::Error::WrongSigner);
    }
    splint_core::asks::payload_id(&entry.compact)
}

/// Where an ask stands, from the rules in force and who this agent acts for, marked done once it is.
/// A step's is read from the chain even after the ask ran out, as the owner's yes may have come in
/// time and been read only now.
async fn shown(signet: &Signet, id: &str, entry: Entry) -> Result<Shown, ApiError> {
    let changes = splint_core::asks::payload_changes(&entry.compact)
        .map_err(|_| ApiError::Host(HostError::LocalStorage))?;
    let now = unix_now();
    let mut done_at = entry.done_at;
    let mut owner_said_no_at = entry.owner_said_no_at;
    let mut ended_at = entry.ended_at;
    if done_at.is_none() && owner_said_no_at.is_none() && ended_at.is_none() {
        let found = match splint_core::asks::step_of(&changes) {
            Some((request, operation)) => {
                step_stands(signet, request, operation, entry.draft.as_ref()).await
            }
            None if now < entry.expires_at && holds_now(signet, &changes).await => Step::Signed,
            None => Step::Open,
        };
        match found {
            Step::Signed => done_at = Some(now),
            Step::SaidNo => owner_said_no_at = Some(now),
            Step::Ended => ended_at = Some(now),
            Step::Open => {}
        }
        if done_at.is_some() || owner_said_no_at.is_some() || ended_at.is_some() {
            signet.asks.write_down(|entries| {
                if let Some(kept) = entries.get_mut(id) {
                    kept.done_at = done_at;
                    kept.owner_said_no_at = owner_said_no_at;
                    kept.ended_at = ended_at;
                }
            })?;
        }
    }
    let status = if done_at.is_some() {
        Status::Done
    } else if owner_said_no_at.is_some() {
        Status::OwnerSaidNo
    } else if ended_at.is_some() {
        Status::Ended
    } else if now >= entry.expires_at {
        Status::NotApproved
    } else {
        Status::Waiting
    };
    Ok(Shown {
        id: id.to_owned(),
        ask: entry.compact,
        changes,
        expires_at: entry.expires_at,
        status,
    })
}

/// Refuses an ID that isn't the agent the host at that address names, as the person reads the address
/// and the owner signs the ID. A host that can't be reached says so, as that says nothing about who's
/// there.
async fn at_address(
    signet: &Signet,
    agent: &splint_core::SplintId,
    address: &str,
) -> Result<(), ApiError> {
    let (handle, domain) = splint_core::parse_address(address)
        .map_err(|_| ApiError::BadRequest("an address is name~domain"))?;
    let found = signet
        .lookup(&signet.who())
        .resolve_saying_why(handle, domain)
        .await
        .map_err(|error| match error {
            HostError::Unreachable => ApiError::CouldntReach(
                "that contact's host can't be reached now, so ask again later",
            ),
            HostError::TooMany => ApiError::Host(HostError::TooMany),
            _ => ApiError::BadRequest("nobody answers at that address"),
        })?;
    if found.agent.id() != agent {
        return Err(ApiError::BadRequest(
            "that ID isn't the agent its host names at that address",
        ));
    }
    Ok(())
}

/// Whether this agent may ask its owner to move it to `to`.
async fn may_ask_to_move(signet: &Signet, to: &str) -> Result<(), ApiError> {
    if signet.retired.is() {
        return Err(ApiError::Retired);
    }
    let who = signet.who();
    if who.owner.is_unconfirmed_owner() {
        return Err(ApiError::BadRequest(
            "no person has set up controls for this agent, so it moves itself with splint switch-host",
        ));
    }
    // A host that's gone for good never takes it back, and that's when a move matters most.
    if signet.recovering() || who.binding.is_empty() || !signet.registered.has_a_place() {
        return Err(ApiError::BadRequest(
            "this agent isn't registered at its host now, so there's no move to ask for",
        ));
    }
    let domain =
        |address: &str| splint_core::parse_address(address).map(|(_, domain)| domain.to_owned());
    let from = match (domain(&signet.address()), domain(to)) {
        (Ok(from), Ok(to)) if from != to => from,
        _ => {
            return Err(ApiError::BadRequest(
                "a move is to an address on another host",
            ));
        }
    };
    if !signet.own_changes.current().has_room_for_a_choice() {
        return Err(ApiError::BadRequest(crate::binding::NO_ROOM_TO_MOVE));
    }
    // Before anyone is asked, for a retirement that hasn't reached this Signet yet.
    if crate::retired::before_leaving(signet, &from).await {
        return Err(ApiError::Retired);
    }
    Ok(())
}

/// Whether this agent may ask for `owner_part` after its handle: with its controls, or alone once its
/// person has set those up, while it's registered, so the binding they sign has a place to go.
fn may_name_owner_part(
    signet: &Signet,
    changes: &[Change],
    owner_part: &str,
) -> Result<(), ApiError> {
    if splint_core::with_owner_part(&signet.address(), owner_part).is_err() {
        return Err(ApiError::BadRequest(
            "that name won't go after this agent's handle: it has an owner part already, or the two \
             wouldn't fit in an address",
        ));
    }
    if !splint_core::may_be_owner_name(owner_part) {
        return Err(ApiError::BadRequest(
            "a person's name after the dot has at least 3 letters, digits or hyphens, isn't one a host \
             keeps back, such as admin or support, and doesn't read as a temporary name or an owner's ID",
        ));
    }
    if splint_core::asks::adds_owner_part(changes).is_none() {
        return Ok(());
    }
    if signet.retired.is() {
        return Err(ApiError::Retired);
    }
    if signet.who().owner.is_unconfirmed_owner() {
        return Err(ApiError::BadRequest(
            "no person has set up controls for this agent yet, so ask for those with the name instead",
        ));
    }
    if signet.recovering() || signet.who().binding.is_empty() || !signet.registered.is_done() {
        return Err(ApiError::BadRequest(
            "this agent isn't registered at its host now, so there's no name to add to",
        ));
    }
    Ok(())
}

/// The owner's draft for this step of this request, while it's held for them.
async fn held_draft(
    signet: &Signet,
    request: &splint_core::MessageId,
    operation: splint_core::requests::Operation,
) -> Option<splint_core::requests::ApprovalDraft> {
    crate::requests::owner_api::drafts_of(signet)
        .await
        .into_iter()
        .find(|draft| &draft.request == request && draft.operation == operation)
}

/// What became of the step an ask is for, each from something written down when it happened, never
/// from the step no longer waiting, as a no, the request's end or a chain that can't be read now all
/// take it away too.
enum Step {
    /// The chain holds this side's step carrying the owner's yes, or the held `open` was signed with it.
    Signed,
    SaidNo,
    /// The request is over without that yes.
    Ended,
    /// Nothing says yet.
    Open,
}

async fn step_stands(
    signet: &Signet,
    request: &splint_core::MessageId,
    operation: splint_core::requests::Operation,
    draft: Option<&ForDraft>,
) -> Step {
    use crate::requests::held_opens::HoldStatus;
    use splint_core::requests::{Operation, RequestState, StepKind};
    // An `open` the owner is asked for has no request yet, only its hold, which is its own.
    if operation == Operation::Open {
        return match signet.requests.held_opens.status_of(request).await {
            Some(HoldStatus::Signed { .. }) => Step::Signed,
            Some(HoldStatus::OwnerSaidNo) => Step::SaidNo,
            _ => Step::Open,
        };
    }
    let kind = match operation {
        Operation::Confirm => StepKind::Confirm,
        Operation::Cancel => StepKind::Cancel,
        Operation::Counter => StepKind::Counter,
        Operation::Accept => StepKind::Accept,
        Operation::Deliver => StepKind::Deliver,
        Operation::Open | Operation::OfferToGuest => return Step::Open,
    };
    // An ask kept before it named its draft can't be told from one for an earlier step.
    let Some(draft) = draft else {
        return Step::Open;
    };
    // Read before the store is locked, as the drafts are worked out under that lock.
    let still_held = held_draft(signet, request, operation)
        .await
        .is_some_and(|held| held.prev == draft.prev && held.version == draft.version);
    let records = signet.requests.store.lock().await;
    let Some(record) = records.get(request.as_str()) else {
        return Step::Open;
    };
    let Ok(chain) = record.chain(signet) else {
        return Step::Open;
    };
    // A step dropped before any host took it never went, though it stays in this Signet's chain.
    let signed = chain
        .approved_steps(
            record.role,
            operation,
            &draft.prev,
            draft.version,
            &draft.terms,
        )
        .into_iter()
        .any(|step| !record.never_sent.contains(step));
    if signed {
        return Step::Signed;
    }
    // While the very draft it asked for is held, nothing else answers it, as a completed request
    // still waits on its owner's cancel.
    if still_held {
        return Step::Open;
    }
    if record.owner_said_no == Some(kind) {
        return Step::SaidNo;
    }
    match chain.state_at(unix_now()) {
        RequestState::Completed
        | RequestState::Declined
        | RequestState::Cancelled
        | RequestState::Expired => Step::Ended,
        _ => Step::Open,
    }
}

/// Whether what's in force holds every change: rules signed by an owner who confirmed, for controls,
/// and the rules' own settings for the rest. A move is done once this agent is registered there. Where
/// the owner gets paid is done once the statement in force names exactly those places, in that order.
/// A step is read from its chain instead, by `step_stands`.
async fn holds_now(signet: &Signet, changes: &[Change]) -> bool {
    // A move is done once this agent runs at that address and its host there has taken it.
    if let Some(to) = splint_core::asks::host_of(changes) {
        return signet.address() == to && signet.registered.is_done();
    }
    // An owner part is done once this agent runs under that name and its host has taken it.
    if let Some(owner_part) = splint_core::asks::adds_owner_part(changes) {
        let address = signet.address();
        return splint_core::parse_address(&address)
            .is_ok_and(|(name, _)| splint_core::name_parts(name).1 == Some(owner_part))
            && signet.registered.is_done();
    }
    if let Some(places) = splint_core::asks::where_paid_of(changes) {
        let owner = &signet.who().owner;
        return signet
            .requests
            .where_paid
            .current(owner)
            .await
            .is_some_and(|statement| statement.places() == places);
    }
    let Some(rules) = signet.rules.current().await else {
        return false;
    };
    if splint_core::asks::controls_delegate(changes).is_some()
        && signet.who().owner.is_unconfirmed_owner()
    {
        return false;
    }
    splint_core::asks::all_held_in(changes, &rules.draft())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealing::tests::signet_and_owner;
    use crate::who::Who;
    use splint_core::{Identity, RecoveryRule, SealingKey, SigningKey};

    /// The delegate key's scalar in hex, read from its file, as an agent on the same account could.
    fn delegate_in_hex(directory: &std::path::Path) -> String {
        const SCALAR_STARTS_AFTER: [u8; 5] = [0x02, 0x01, 0x01, 0x04, 0x20];
        let pkcs8 = std::fs::read(directory.join("delegate.key")).unwrap();
        let start = pkcs8
            .windows(SCALAR_STARTS_AFTER.len())
            .position(|window| window == SCALAR_STARTS_AFTER)
            .unwrap()
            + SCALAR_STARTS_AFTER.len();
        let scalar = pkcs8.get(start..start + 32).unwrap();
        scalar.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn paid_at(url: &str) -> AskBody {
        serde_json::from_value(serde_json::json!({
            "changes": [{"change": "where_paid", "places": [{"kind": "payment_page", "url": url}]}],
        }))
        .unwrap()
    }

    /// Bug caught: a where_paid ask carrying the agent's own token to every payer under its owner's
    /// signature, or one asked for a stand-in before its owner confirmed.
    #[tokio::test]
    async fn a_where_paid_ask_carries_no_secret_and_needs_a_confirmed_owner() {
        let (signet, directory, _) = signet_and_owner(None, "asks-where-paid").await;
        let signet = Arc::new(signet);
        let held = signet.who();
        let secret = format!(
            "https://pay.example.com/ana?k={}",
            delegate_in_hex(&directory)
        );
        let refused = ask(State(signet.clone()), Json(paid_at(&secret))).await;
        assert!(matches!(refused, Err(ApiError::HoldsSecret(_))));
        let stand_in = SigningKey::generate().unwrap();
        signet
            .replace_who(Who {
                identity: held.identity.clone(),
                owner: Identity::create(
                    &stand_in,
                    &SealingKey::generate().unwrap().public_key(),
                    RecoveryRule::unconfirmed_owner(&stand_in.public_key()),
                )
                .unwrap(),
                binding: String::new(),
            })
            .unwrap();
        let refused = ask(
            State(signet.clone()),
            Json(paid_at("https://pay.example.com/ana")),
        )
        .await;
        assert!(matches!(refused, Err(ApiError::BadRequest(_))));
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Bug caught: an agent out of asks for the day told its host had a limit, which sends it to look
    /// at the wrong thing, as this count is its own Signet's.
    #[tokio::test]
    async fn an_agent_out_of_asks_hears_it_is_its_own_count() {
        let (signet, directory, _) = signet_and_owner(None, "asks-out-of-asks").await;
        let signet = Arc::new(signet);
        let pause = || -> AskBody {
            serde_json::from_value(serde_json::json!({
                "changes": [{"change": "paused", "to": true}],
            }))
            .unwrap()
        };
        for _ in 0..ASKS_PER_DAY {
            assert!(ask(State(signet.clone()), Json(pause())).await.is_ok());
        }
        let refused = ask(State(signet.clone()), Json(pause())).await;
        assert!(matches!(refused, Err(ApiError::TooManyAsks)));
        std::fs::remove_dir_all(directory).unwrap();
    }
}

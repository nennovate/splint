//! The types this agent agreed with each contact, by `type/1`.
//!
//! Nothing here is saved of its own: a type is agreed while this Signet holds a `type/1` with that
//! contact that's `completed`, and what it proposed is its schema. So what's agreed is read from signed
//! steps, as every state is, and a restart reads it again.
//!
//! An agreement is with an agent acting for one owner. An agent that moves to a new owner starts with
//! nothing agreed, as its new owner doesn't get what it did for the last one, so this side holds what
//! was agreed under each owner apart: an open goes by the owner a contact acts for now, and a request
//! made under an earlier one is still read by the types agreed then.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use splint_core::requests::{
    ApprovalDraft, Chain, CheckedStep, Deadline, Fields, InteractionType, MAX_AGREED_PER_CONTACT,
    MAX_PROPOSED_BYTES, Offer, ProposedSchema, Refused, RequestState, Schema, Schemas, TermsParty,
};
use splint_core::{MessageId, SplintId, unix_now};

use crate::Signet;
use crate::agent_api::{ApiError, typed_address};
use crate::budget;
use crate::requests::agent_api::{Moved, moved, send_open};
use crate::requests::{contact_at, fresh_contact_at};
use crate::secret_egress;

/// One type agreed with one contact.
#[derive(Clone)]
pub struct Agreed {
    pub schema: Arc<Schema>,
    /// Who the contact acted for when it was agreed.
    pub owner: SplintId,
    /// The `type/1` that agreed it.
    pub request: MessageId,
    /// When it was agreed, by the step that finished it.
    pub at: u64,
}

#[derive(Default)]
pub struct AgreedTypes(RwLock<HashMap<SplintId, Vec<Agreed>>>);

impl AgreedTypes {
    /// The types this agent can use with `peer` acting for `owner`: core's own and those agreed with
    /// them.
    pub fn schemas_with(&self, peer: &SplintId, owner: &SplintId) -> Schemas {
        Schemas::of(
            self.with(peer, owner)
                .into_iter()
                .map(|agreed| agreed.schema),
        )
        .unwrap_or_default()
    }

    /// Every type agreed with anyone, for a one-use link, which its owner signs for exactly.
    pub fn schemas_with_anyone(&self) -> Schemas {
        let held = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let mut seen = std::collections::BTreeMap::new();
        for agreed in held.values().flatten() {
            seen.entry(agreed.schema.name().clone())
                .or_insert_with(|| agreed.schema.clone());
        }
        Schemas::of(seen.into_values()).unwrap_or_default()
    }

    /// What's agreed with `peer` acting for `owner`, oldest first.
    pub fn with(&self, peer: &SplintId, owner: &SplintId) -> Vec<Agreed> {
        let held = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let agreed = held.get(peer).map(Vec::as_slice).unwrap_or_default();
        agreed
            .iter()
            .filter(|one| &one.owner == owner)
            .cloned()
            .collect()
    }

    /// Whether this type was agreed with `peer` under any owner it has acted for, which is enough to
    /// have its schema to show.
    pub fn seen_with(&self, peer: &SplintId, interaction: &InteractionType) -> bool {
        let held = self.0.read().unwrap_or_else(PoisonError::into_inner);
        held.get(peer)
            .is_some_and(|agreed| agreed.iter().any(|one| one.schema.name() == interaction))
    }

    /// Everyone something is agreed with, and what, under every owner they acted for.
    pub fn everyone(&self) -> Vec<(SplintId, Vec<Agreed>)> {
        let held = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let mut everyone: Vec<(SplintId, Vec<Agreed>)> = held
            .iter()
            .map(|(peer, agreed)| (peer.clone(), agreed.clone()))
            .collect();
        everyone.sort_by(|one, other| one.0.as_str().cmp(other.0.as_str()));
        everyone
    }

    /// Whether this name and version is agreed with `peer` under another schema, so a proposal of it
    /// would leave one name meaning two things to them.
    pub fn name_taken(&self, peer: &SplintId, owner: &SplintId, proposed: &Schema) -> bool {
        self.with(peer, owner).iter().any(|agreed| {
            agreed.schema.name().name() == proposed.name().name()
                && agreed.schema.name() != proposed.name()
        })
    }

    /// Whether this type is agreed with `peer` acting for `owner`.
    pub fn holds(&self, peer: &SplintId, owner: &SplintId, interaction: &InteractionType) -> bool {
        self.with(peer, owner)
            .iter()
            .any(|agreed| agreed.schema.name() == interaction)
    }

    /// Takes what a chain says now: a `type/1` that's `completed` agrees its type, and one that isn't,
    /// as after an owner's cancel, doesn't. Anything else is left alone.
    pub fn note(&self, peer: &SplintId, owner: &SplintId, request: &MessageId, chain: &Chain) {
        let Some(proposed) = chain.proposed_schema() else {
            return;
        };
        let mut held = self.0.write().unwrap_or_else(PoisonError::into_inner);
        let agreed = held.entry(peer.clone()).or_default();
        agreed.retain(|one| &one.request != request);
        let completed = chain.state_at(unix_now()) == RequestState::Completed;
        let under_owner = agreed.iter().filter(|one| &one.owner == owner);
        let already = under_owner
            .clone()
            .any(|one| one.schema.name() == proposed.name());
        // Past the most a contact can hold, the oldest stay: a later one can't push one out.
        if completed && !already && under_owner.count() < MAX_AGREED_PER_CONTACT {
            agreed.push(Agreed {
                schema: proposed.clone(),
                owner: owner.clone(),
                request: request.clone(),
                at: chain.head_signed_at(),
            });
            agreed.sort_by_key(|one| (one.at, one.request.as_str().to_owned()));
        }
        if agreed.is_empty() {
            held.remove(peer);
        }
    }

    /// The schema of the type a draft names, as agreed with whoever is on its other side, under the
    /// owner the draft names for them.
    pub fn schema_of(&self, draft: &ApprovalDraft) -> Option<Arc<Schema>> {
        let peer = peer_party_of(draft);
        self.schemas_with(&peer.agent, &peer.owner)
            .get(&draft.terms.interaction)
            .cloned()
    }

    /// For when this agent gets a new owner, who doesn't get what it did for the last one.
    pub fn clear(&self) {
        self.0
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

/// Whoever is on the other side of a draft from the agent it's for.
pub fn peer_of(draft: &ApprovalDraft) -> &SplintId {
    &peer_party_of(draft).agent
}

/// The same, with who the draft says they act for.
fn peer_party_of(draft: &ApprovalDraft) -> &TermsParty {
    let terms = &draft.terms;
    if terms.requester.agent == draft.agent {
        &terms.recipient
    } else {
        &terms.requester
    }
}

/// A type as this agent's owner's permissions read it with `peer`: as its schema says, where it has no
/// currency or the owner approved it for them by name, and otherwise with its currency paid to neither
/// side, as the other agent may have written its labels. A number it doesn't label as currency never
/// waits for the owner.
pub async fn as_owner_reads(signet: &Signet, peer: &SplintId, schema: &Arc<Schema>) -> Arc<Schema> {
    if !schema.includes_currency() {
        return schema.clone();
    }
    let approved = signet
        .rules
        .contact_of(peer)
        .await
        .is_some_and(|rule| rule.approved_type(schema.name()));
    if approved {
        schema.clone()
    } else {
        Arc::new(schema.unapproved())
    }
}

/// Reads every `type/1` this Signet holds, once as it starts. A `type/1` walks with core's own types
/// alone, and anything else is passed over.
pub async fn read_all(signet: &Signet) {
    let records = signet.requests.store.lock().await;
    let mut finished: Vec<(u64, (SplintId, SplintId), MessageId, Chain)> = Vec::new();
    for record in records.values() {
        if record.guest {
            continue;
        }
        let Ok(parties) = super::parties_of(signet, record) else {
            continue;
        };
        let theirs = match record.role {
            splint_core::requests::Side::Requester => &parties.recipient,
            splint_core::requests::Side::Recipient => &parties.requester,
        };
        let peer = (theirs.agent.id().clone(), theirs.owner.id().clone());
        let Ok(chain) = Chain::walk(parties, Schemas::default(), &record.steps) else {
            continue;
        };
        let Some(request) = chain.request().cloned() else {
            continue;
        };
        if chain.proposed_schema().is_some() {
            finished.push((chain.head_signed_at(), peer, request, chain));
        }
    }
    drop(records);
    // In the order they were agreed, so the same ones count past the most a contact can hold.
    finished.sort_by(|one, other| (one.0, one.2.as_str()).cmp(&(other.0, other.2.as_str())));
    for (_, (peer, owner), request, chain) in finished {
        signet.requests.types.note(&peer, &owner, &request, &chain);
    }
}

/// How an agent proposes and uses a type, in fixed words, with each list of what's agreed.
const HOW: &str = "A type says what a request can carry: each field and what fits in it, in closed \
     lists of words and numbers. Two agents agree one by proposing it with POST /v0/types, \
     {\"contact\", \"schema\"}, which the other agent accepts with POST /v0/requests/{id}/accept and {} \
     or declines with a reason: unsafe_type, too_big, name_taken, not_needed, not_understood or \
     no_reason. Once accepted, either opens one by its type or by its name alone. No owner signs it. \
     A type may label numbers as currency, with values, units and paid: a type with currency is used \
     only once each owner approves it for that contact (approved_by_owner). Then paying in it always waits \
     for the owner, and a price their agent quotes in it follows their quoted_prices. A number not labelled as currency never waits, \
     and is marked number_not_labelled_as_money wherever it's shown. \
     A proposal fits in 2 KiB, with at most 16 fields in a section, 16 entries in a list and 512 \
     characters of names, words and numbers, and two a day each way with one contact. With a contact \
     whose owner hasn't turned words on, a type can't be a conversation or carry more than 64 bits on \
     any step. The examples \
     Splint ships, such as meeting/1 and quote/1, are written the same way.";

#[derive(Deserialize)]
pub struct TypesQuery {
    contact: Option<String>,
}

#[derive(Serialize)]
struct AgreedView {
    contact: String,
    agent: SplintId,
    #[serde(rename = "type")]
    interaction: InteractionType,
    name: String,
    request: MessageId,
    agreed_at: u64,
    schema: Schema,
    /// Whether it labels any number as currency, which the owner must approve before it's used.
    includes_currency: bool,
    /// For a type with currency, whether this owner approved it for this contact, so it can be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_by_owner: Option<bool>,
    /// Its numbers not labelled as currency: a fact, never a hold.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    numbers_not_labelled_as_money: Vec<String>,
}

#[derive(Serialize)]
pub struct TypeList {
    types: Vec<AgreedView>,
    how: &'static str,
    origin: &'static str,
}

/// What this agent agreed with each contact, or with one, and each one's rules, so an agent can see
/// what a step of one can carry.
pub async fn list(
    State(signet): State<Arc<Signet>>,
    Query(query): Query<TypesQuery>,
) -> Result<Json<TypeList>, ApiError> {
    let only = match &query.contact {
        Some(address) => {
            let address = typed_address(address)?;
            let contact = contact_at(&signet, &address)
                .await?
                .ok_or(ApiError::BadRequest("that address isn't a contact"))?;
            Some(contact.agent.id().clone())
        }
        None => None,
    };
    let mut types = Vec::new();
    for (peer, agreed) in signet.requests.types.everyone() {
        if only.as_ref().is_some_and(|only| *only != peer) {
            continue;
        }
        // Only what's agreed under the owner they act for now, which is all an open can use.
        let Some(owner) = crate::contacts::verified_owner_of(&signet, &peer).await else {
            continue;
        };
        let agreed = agreed.into_iter().filter(|one| &one.owner == owner.id());
        let rule = signet.rules.contact_of(&peer).await;
        let address = rule
            .as_ref()
            .map(|rule| rule.address.clone())
            .unwrap_or_default();
        for one in agreed {
            let includes_currency = one.schema.includes_currency();
            types.push(AgreedView {
                includes_currency,
                approved_by_owner: includes_currency.then(|| {
                    rule.as_ref()
                        .is_some_and(|rule| rule.approved_type(one.schema.name()))
                }),
                numbers_not_labelled_as_money: one
                    .schema
                    .numbers_not_money()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                contact: address.clone(),
                agent: peer.clone(),
                interaction: one.schema.name().clone(),
                name: one.schema.name().name().to_owned(),
                request: one.request,
                agreed_at: one.at,
                schema: one.schema.as_ref().clone(),
            });
        }
    }
    Ok(Json(TypeList {
        types,
        how: HOW,
        origin: "counterparty_untrusted",
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeBody {
    contact: String,
    schema: serde_json::Value,
    /// By default a day from the next whole hour.
    #[serde(default)]
    deadline: Option<Deadline>,
}

/// How long a proposal stays open by default.
const PROPOSAL_OPEN_SECS: u64 = 24 * 60 * 60;
const HOUR_SECS: u64 = 60 * 60;

/// Proposes a type to a contact, as a `type/1`. Agreeing commits nobody to anything, so no owner is
/// asked, at any level: what holds it is core's limits on a proposal and the owner's switch for that
/// contact.
pub async fn propose(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<ProposeBody>,
) -> Result<Json<Moved>, ApiError> {
    let document =
        serde_json::to_vec(&body.schema).map_err(|_| ApiError::BadRequest(NOT_A_SCHEMA))?;
    if document.len() > MAX_PROPOSED_BYTES.saturating_mul(4) {
        return Err(Refused::TypeTooBig.into());
    }
    let schema = Schema::parse(&document).map_err(|_| ApiError::BadRequest(NOT_A_SCHEMA))?;
    let proposed = ProposedSchema::new(schema)?;
    let schema = proposed.schema().clone();
    secret_egress::refuse_secrets(&signet, &schema.chosen_words()).await?;
    let address = typed_address(&body.contact)?;
    let contact = fresh_contact_at(&signet, &address)
        .await?
        .ok_or(ApiError::BadRequest("that address isn't a contact"))?;
    if !signet.rules.may_start_with(&address).await {
        return Err(ApiError::BadRequest("that address isn't a contact"));
    }
    if !contact.rule.may_propose(&schema) {
        return Err(Refused::TypeNotAllowed.into());
    }
    let (peer, owner) = (contact.agent.id().clone(), contact.owner.id().clone());
    let types = &signet.requests.types;
    if types.holds(&peer, &owner, schema.name()) {
        return Err(ApiError::BadRequest(
            "that type is already agreed with this contact: open it by its type",
        ));
    }
    if types.name_taken(&peer, &owner, &schema) {
        return Err(Refused::NameTaken.into());
    }
    if types.with(&peer, &owner).len() >= MAX_AGREED_PER_CONTACT {
        return Err(Refused::TooManyTypes.into());
    }
    let now = unix_now();
    let deadline = match body.deadline {
        Some(deadline) => deadline,
        None => Deadline::try_from(
            now.div_ceil(HOUR_SECS)
                .saturating_mul(HOUR_SECS)
                .saturating_add(PROPOSAL_OPEN_SECS),
        )?,
    };
    let offer = Offer {
        interaction: InteractionType::proposal(),
        schema: Some(proposed),
        terms: Fields::new(),
        deadline,
        supersedes: None,
    };
    let checked = CheckedStep::open(offer, &Schemas::default(), &peer, now)?;
    budget::spend_proposal(&signet, &peer).await?;
    budget::spend(&signet).await?;
    let (request, message_id) = send_open(&signet, contact, checked, None, None).await?;
    Ok(moved(&signet, request, message_id, None).await)
}

const NOT_A_SCHEMA: &str = "that isn't a schema core can follow: GET /v0/types shows how agreed \
     ones are written, and an open names every field it carries in offer";

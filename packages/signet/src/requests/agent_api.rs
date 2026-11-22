//! What an agent can do with an interaction: typed calls only. It has no `confirm` call and no
//! `received` call, and can't set a lifetime, a nonce or a date.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::host_api::DeliveryStatus;
use splint_core::requests::{
    Action, Audience, Chain, CheckedStep, Deadline, Dialogue, FieldValue, Fields, HeldMove,
    InteractionType, Offer, PROPOSAL, PauseReason, PaymentAsk, PersonSaid, Reader, Refused,
    RequestState, Said, Schema, Schemas, Side, Signers, StepKind, Word, has_hidden_characters,
};
use splint_core::rules::{Commits, Counterparty, PinnedBy, RulesContact, names_currency};
use splint_core::{DeliveryState, Identity, MessageId, SplintId, unix_now};

use crate::Signet;
use crate::agent_api::refuse_if_stopped;
use crate::agent_api::{ASK_YOUR_OWNER, ApiError, typed_address};
use crate::budget;
use crate::contacts::{Controls, controls_of};
use crate::requests::held_opens::{HeldOpen, HeldOpenView};
use crate::requests::person_text::place_of;
use crate::requests::store::{HeldBecause, NotUsed, Record, may_supersede, started_from};
use crate::requests::{Contact, fresh_contact_at, payments, sync, types};
use crate::{rules, secret_egress};

pub fn routes(signet: Arc<Signet>) -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/requests", post(open))
        .route("/v0/requests/{request}/say", post(say))
        .route("/v0/requests/{request}/counter", post(counter))
        .route("/v0/requests/{request}/accept", post(accept))
        .route("/v0/requests/{request}/clarify", post(clarify))
        .route("/v0/requests/{request}/progress", post(progress))
        .route("/v0/requests/{request}/pause", post(pause))
        .route("/v0/requests/{request}/resume", post(resume))
        .route("/v0/requests/{request}/deliver", post(deliver))
        .route("/v0/requests/{request}/decline", post(decline))
        .route("/v0/requests/{request}/cancel", post(cancel))
        .route("/v0/types", post(types::propose))
        .merge(payments::agent_routes())
        .route_layer(middleware::from_fn_with_state(signet, refuse_if_stopped))
        .route("/v0/types", get(types::list))
        .route("/v0/requests", get(list))
        .route("/v0/requests/{request}", get(read))
        .route("/v0/requests/{request}/record", get(record))
}

#[derive(Serialize)]
struct From {
    address: String,
    agent: SplintId,
    known_contact: bool,
    /// Whether a value with them in this request goes as the owner's settings say, by the same rule
    /// the owner's device and Signet's delegate sign by. Where it's false, a value waits for the owner.
    approved_by_owner: bool,
    /// "no controls set up yet" for an agent that joined on its own and whose owner hasn't set up
    /// controls, so no value or owner's signature from it counts, or whose agent it is.
    controls: String,
}

/// What a host says about the head, which is its own word and unsigned. Its `delivered` only means
/// the other side's host stored it, so it shows as `at_their_host`: only `received` says their Signet
/// has it.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HostSays {
    Pending,
    AtTheirHost,
    Rejected,
    Expired,
    PeerRemoved,
    Withdrawn,
}

/// Delivery is a separate axis from request state. Only `received` is evidence, signed by the other
/// side's Signet. It means Signet verified the step, not that the agent read it.
#[derive(Serialize)]
struct Delivery {
    head: Option<MessageId>,
    head_by: Option<Side>,
    /// Only once this side's host took the head, as flushing it found, or for a head the other side
    /// signed.
    handed_to_host: bool,
    /// This side's head left the outbox before any host confirmed taking it, as it ran out or its key
    /// was replaced. A host may still have kept it, so the other side's `received` outranks this.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    never_sent: bool,
    /// Why the head hasn't been handed to the host yet, as the last try found, while it hasn't.
    #[serde(skip_serializing_if = "Option::is_none")]
    held_because: Option<HeldBecause>,
    host_says: Option<HostSays>,
    received: bool,
}

/// Where one side's yes to what was agreed stands, for a type whose owners sign it.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Signature {
    /// Its owner signed it with their own key.
    Owner,
    /// Its owner's delegate signed it, within the limits the owner signed for it.
    Delegate,
    /// Still to come, and this side's delegate gives it by itself on its next pass, within the owner's
    /// limits, so nobody has to do anything. Only ever this side's own, as only it knows.
    DelegateSigns,
    /// Still to come, from a person or a delegate within their limits.
    ToCome,
    /// Can't come until this side's person sets up their controls.
    NoControls,
}

/// Each side's yes, from this agent's side, so a request isn't read as waiting on a person when a
/// delegate signs it, or as two people's yes when one owner stands behind both sides.
#[derive(Serialize)]
pub struct Signatures {
    #[serde(skip_serializing_if = "Option::is_none")]
    yours: Option<Signature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    theirs: Option<Signature>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    same_owner: bool,
}

/// No protocol can make both sides certain of the last message, so this never shows it as settled.
/// `completed` on the recipient's side stays `not_proven` until the requester's `received` arrives.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum OtherSide {
    Proven,
    NotProven,
}

#[derive(Serialize)]
pub struct RequestView {
    request: Option<MessageId>,
    from: From,
    /// Signet's own facts about the other side, as beside a note.
    #[serde(skip_serializing_if = "Option::is_none")]
    facts: Option<crate::arrivals::Facts>,
    role: Side,
    #[serde(rename = "type")]
    interaction: Option<InteractionType>,
    /// The type's name and version alone, as a person reads it. Null for core's plain conversation.
    type_name: Option<String>,
    /// On a `type/1`, the type proposed: its ID and its schema, which the other side may have written.
    #[serde(skip_serializing_if = "Option::is_none")]
    proposes: Option<Proposes>,
    state: RequestState,
    version: Option<u32>,
    deadline: Option<u64>,
    terms: Fields,
    pick: Fields,
    result: Fields,
    status: Option<Word>,
    pause_reason: Option<PauseReason>,
    /// Paused for information, and a note from the requester has come since, as far as this Signet saw,
    /// which is how that information goes. So the recipient, who alone can resume, has the next move.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    noted_since_pause: bool,
    clarify_reason: Option<Word>,
    decline_reason: Option<Word>,
    messages: Vec<Said>,
    /// What people wrote, by their owners' signatures. Each is marked untrusted, whoever wrote it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    person_texts: Vec<PersonSaid>,
    has_subject: bool,
    has_note: bool,
    your_moves: Vec<StepKind>,
    /// The step that waits on the owner's yes: a move of this agent's that nothing has signed yet, or
    /// the owner's own `confirm` or `cancel`, which no move of the agent's can stand in for.
    #[serde(skip_serializing_if = "Option::is_none")]
    waiting_for_owner: Option<StepKind>,
    /// A move of this agent's that commits its owner to a value, held, unsigned, until the other side's
    /// person sets up their controls, with fixed words on what follows.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    held_for_them: Option<HeldForThem>,
    /// A move that waited only for the other side's person, and was refused as it went by itself once
    /// they'd set up their controls, until the agent's next move.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    not_sent_by_itself: Option<NotSentByItself>,
    /// With something waiting on an owner who hasn't set up their controls, which they must do first.
    #[serde(skip_serializing_if = "Option::is_none")]
    ask_your_owner: Option<&'static str>,
    /// The step that waits on the other side's owner's yes, by the same drafts their page shows them, so
    /// the side that accepted isn't left reading the request as settled while it waits on a signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    waiting_for_their_owner: Option<StepKind>,
    /// What the owner said no to, until the agent's next move: a move of the agent's, of which nothing
    /// went anywhere, either refused or passed over by the owner's own step, or the owner's own
    /// `confirm`, whose no went to the other side as a decline.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_said_no: Option<StepKind>,
    /// The owner's last answer that this Signet couldn't use, such as a yes to an amount the agent has
    /// since changed, while what's waiting still waits on them. Their device shows it them too.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_answer_not_used: Option<NotUsed>,
    /// Each side's yes, for a type whose owners sign what was agreed.
    #[serde(skip_serializing_if = "Option::is_none")]
    signatures: Option<Signatures>,
    /// There while terms are agreed and it isn't completed yet, as an agent put an accepted meeting on
    /// its person's calendar that was never settled.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    tentative: Option<Tentative>,
    /// Where its payment stands, once completed and the payee's agent asked or said it arrived. Kept
    /// apart from `state`, which still says only what was agreed.
    #[serde(skip_serializing_if = "Option::is_none")]
    payment: Option<payments::PaymentView>,
    delivery: Delivery,
    other_side: OtherSide,
    /// A reminder for whoever reads this: every field here comes from a counterparty.
    origin: &'static str,
}

#[derive(Serialize)]
struct Proposes {
    #[serde(rename = "type")]
    interaction: InteractionType,
    schema: Schema,
}

/// Said of a request whose terms are agreed and that isn't completed: `settled` is false, with fixed
/// words on what that means for what the agent does outside Splint. Every request type reaches
/// `completed`, as one nobody signs has a result to deliver, so none is settled at `accepted`.
#[derive(Serialize)]
struct Tentative {
    settled: bool,
    tentative: &'static str,
}

/// For the side waiting on others to finish or sign.
const TENTATIVE_WAITING: &str = "Agreed, not settled till completed. Act on it for real outside \
     Splint, such as booking or paying, only once it's completed, or mark it tentative and tell \
     your person.";

/// For the side doing the work: telling it to wait would leave the work undone, as the deliver it
/// waits on is its own.
const TENTATIVE_WORKING: &str = "Agreed, not settled till completed. Doing what was asked and \
     delivering it is your part; only what the deal itself commits, such as booking or paying, \
     waits till then.";

/// Agreed and on its way to `completed`, by the state it's in now and which side reads it.
fn tentative(state: RequestState, role: Side) -> Option<Tentative> {
    let tentative = match (state, role) {
        (RequestState::Working | RequestState::Paused, Side::Recipient) => TENTATIVE_WORKING,
        (
            RequestState::Accepted
            | RequestState::Working
            | RequestState::Paused
            | RequestState::Delivered
            | RequestState::RequesterConfirmed,
            _,
        ) => TENTATIVE_WAITING,
        _ => return None,
    };
    Some(Tentative {
        settled: false,
        tentative,
    })
}

/// What the owner is asked to sign on this request, by the same drafts their page and
/// `/v0/owner/approvals` show, so an agent isn't told it's at its move when only its owner can move it.
fn waiting_for_owner(record: &Record, chain: &Chain, now: u64) -> Option<StepKind> {
    if record.held_draft(chain, now).is_some() {
        return record.held.as_ref().map(HeldMove::kind);
    }
    if record.cancel_wanted && chain.cancel_draft(record.role, now).is_some() {
        return Some(StepKind::Cancel);
    }
    confirm_waits_on(record.role, chain, now)
}

/// Whether this side's owner's `confirm` is what moves the request on now.
fn confirm_waits_on(side: Side, chain: &Chain, now: u64) -> Option<StepKind> {
    let live = chain.state_at(now) != RequestState::Expired;
    (live && chain.confirm_draft(side, now).is_some()).then_some(StepKind::Confirm)
}

/// What the other side's owner is asked to sign on this request. Only their `confirm` is worked out
/// from what's signed: a move their agent holds for them never reaches this side.
fn waiting_for_their_owner(record: &Record, chain: &Chain, now: u64) -> Option<StepKind> {
    let theirs = match record.role {
        Side::Requester => Side::Recipient,
        Side::Recipient => Side::Requester,
    };
    confirm_waits_on(theirs, chain, now)
}

/// Whose sides sign, of a type's: the requester's, and then the recipient's when both do. A guest has no
/// owner, and what the requester's owner signed for a link stands for it.
fn signing_sides(chain: &Chain, guest: bool) -> Vec<Side> {
    match chain.interaction_schema().map(|schema| schema.sign()) {
        Some(Signers::Both) if !guest => vec![Side::Requester, Side::Recipient],
        Some(Signers::Both | Signers::Requester) => vec![Side::Requester],
        _ => Vec::new(),
    }
}

/// Each side's yes, worked out from what's signed. A settled request gets no more, so only what was
/// given shows there. `signs_by_itself` is whether this side's delegate gives this side's yes now.
fn signatures(
    record: &Record,
    chain: &Chain,
    owner_unconfirmed: bool,
    signs_by_itself: bool,
    now: u64,
) -> Option<Signatures> {
    let sides = signing_sides(chain, record.guest);
    if sides.is_empty() {
        return None;
    }
    let settled = matches!(
        chain.state_at(now),
        RequestState::Completed
            | RequestState::Declined
            | RequestState::Cancelled
            | RequestState::Expired
            | RequestState::Disputed
    );
    let of = |side: Side| -> Option<Signature> {
        if !sides.contains(&side) {
            return None;
        }
        let mine = side == record.role;
        Some(match chain.yes_by_delegate(side) {
            Some(true) => Signature::Delegate,
            Some(false) => Signature::Owner,
            None if settled => return None,
            None if mine && owner_unconfirmed => Signature::NoControls,
            None if !mine && chain.other_side_unconfirmed(record.role) => Signature::NoControls,
            None if mine && signs_by_itself => Signature::DelegateSigns,
            None => Signature::ToCome,
        })
    };
    let theirs = match record.role {
        Side::Requester => Side::Recipient,
        Side::Recipient => Side::Requester,
    };
    Some(Signatures {
        yours: of(record.role),
        theirs: of(theirs),
        same_owner: chain.same_owner(),
    })
}

/// Whether this side's delegate gives the yes that waits on this side now, by itself.
async fn delegate_signs(signet: &Signet, record: &Record, chain: &Chain, now: u64) -> bool {
    if record.guest || chain.state_at(now) == RequestState::Expired {
        return false;
    }
    match chain.confirm_draft(record.role, now) {
        Some(draft) => crate::delegation::signs_by_itself(signet, &draft, now).await,
        None => false,
    }
}

/// An agent whose owner hasn't confirmed can't deliver a result that names a value, so it isn't
/// offered the move. A value the offer doesn't hold is one the result does.
fn moves_it_can_make(
    chain: &Chain,
    mut moves: Vec<StepKind>,
    owner_unconfirmed: bool,
) -> Vec<StepKind> {
    let result_names_a_value = chain.interaction_schema().is_some_and(|schema| {
        schema
            .values()
            .any(|value| !schema.offer_rules().contains_key(value))
    });
    if owner_unconfirmed && result_names_a_value {
        moves.retain(|kind| *kind != StepKind::Deliver);
    }
    moves
}

/// What's needed to show a request beside the request itself.
struct Standing {
    host_says: Option<HostSays>,
    pinned_by: Option<PinnedBy>,
    approved_by_owner: bool,
    owner_unconfirmed: bool,
    delegate_signs: bool,
    /// Asks to be paid in other requests with the same owner, for what a payer's told of a place.
    paid_before: Vec<PaymentAsk>,
}

fn view(record: &Record, chain: &Chain, standing: Standing) -> Result<RequestView, ApiError> {
    let Standing {
        host_says,
        pinned_by,
        approved_by_owner,
        owner_unconfirmed,
        delegate_signs,
        paid_before,
    } = standing;
    let now = unix_now();
    let head = chain.head().cloned();
    // Each is what was written down when it happened. A step leaves the outbox unsent too, when it
    // runs out or its key is replaced, so its absence there says nothing. A head the other side signed
    // reached this Signet through a host.
    let mine = chain.head_side() == Some(record.role);
    let handed_to_host = head.as_ref().is_some_and(|head| {
        !mine
            || record.handed.contains(head)
            || (!record.handed_noted && !record.outbox.iter().any(|out| out.message_id == *head))
    });
    let never_sent = mine
        && head
            .as_ref()
            .is_some_and(|head| record.never_sent.contains(head));
    let peer_agent = record.peer_agent()?;
    let waiting_for_owner = waiting_for_owner(record, chain, now);
    let signatures = signatures(record, chain, owner_unconfirmed, delegate_signs, now);
    let yours_need_controls = signatures
        .as_ref()
        .is_some_and(|signed| signed.yours == Some(Signature::NoControls));
    Ok(RequestView {
        request: chain.request().cloned(),
        facts: None,
        from: From {
            address: record.peer_address.clone(),
            agent: peer_agent.id().clone(),
            known_contact: pinned_by.is_some_and(|pinned| pinned != PinnedBy::Reach),
            approved_by_owner,
            controls: controls_of(if chain.other_side_unconfirmed(record.role) {
                Controls::NotSetUp
            } else {
                Controls::Set
            }),
        },
        role: record.role,
        interaction: chain.interaction().cloned(),
        type_name: chain
            .interaction()
            .filter(|interaction| !interaction.is_conversation())
            .map(|interaction| interaction.name().to_owned()),
        proposes: chain.proposed_schema().map(|schema| Proposes {
            interaction: schema.name().clone(),
            schema: schema.as_ref().clone(),
        }),
        state: chain.state_at(now),
        version: chain.version(),
        deadline: chain.deadline(),
        terms: chain.offer().clone(),
        pick: chain.pick().clone(),
        result: chain.result().clone(),
        status: chain.status().cloned(),
        pause_reason: chain.pause_reason(),
        noted_since_pause: chain.state_at(now) == RequestState::Paused
            && chain.pause_reason() == Some(PauseReason::NeedsInformation)
            && record.noted_after_pause.is_some()
            && record.noted_after_pause.as_ref() == chain.head(),
        clarify_reason: chain.clarify_reason().cloned(),
        decline_reason: chain.decline_reason().cloned(),
        messages: chain.messages(),
        person_texts: chain.person_texts(),
        has_subject: chain.has_subject(),
        has_note: chain.has_note(),
        your_moves: moves_it_can_make(chain, chain.moves_for(record.role, now), owner_unconfirmed),
        waiting_for_owner,
        held_for_them: held_for_their_controls(record, chain, now).map(HeldForThem::of),
        not_sent_by_itself: record.held_not_sent.as_deref().map(NotSentByItself::of),
        // Said from the start where this side's yes can't come until then, as on the other side.
        ask_your_owner: ((waiting_for_owner.is_some() || yours_need_controls) && owner_unconfirmed)
            .then_some(ASK_YOUR_OWNER),
        waiting_for_their_owner: waiting_for_their_owner(record, chain, now),
        owner_said_no: record.owner_said_no,
        owner_answer_not_used: record
            .owner_answer_not_used
            .clone()
            .filter(|_| waiting_for_owner.is_some()),
        signatures,
        tentative: tentative(chain.state_at(now), record.role),
        payment: payments::view_of(record, chain, &paid_before, now),
        other_side: if chain.other_side_proven(record.role, now) {
            OtherSide::Proven
        } else {
            OtherSide::NotProven
        },
        delivery: Delivery {
            head,
            head_by: chain.head_side(),
            handed_to_host,
            never_sent,
            held_because: record
                .held_because
                .filter(|_| !handed_to_host && !never_sent),
            host_says,
            received: chain.head_received(),
        },
        origin: "counterparty_untrusted",
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenBody {
    contact: String,
    /// A type agreed with this contact, by its ID or by its name and version alone. Left out for core's
    /// plain conversation.
    #[serde(rename = "type", default)]
    interaction: Option<String>,
    #[serde(default)]
    terms: Fields,
    deadline: Deadline,
    supersedes: Option<MessageId>,
}

/// What became of a call. With `waiting_for_owner`, nothing has been signed or sent.
#[derive(Serialize)]
pub struct Moved {
    request: Option<String>,
    message_id: Option<MessageId>,
    /// What to look for in `GET /v0/requests`, for an `open` that's waiting.
    #[serde(skip_serializing_if = "Option::is_none")]
    hold: Option<MessageId>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    waiting_for_owner: bool,
    /// It commits its owner to a value, and the other side's person hasn't set up their controls, so
    /// it waits, unsigned, until they have, with fixed words on what follows.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    held_for_them: Option<HeldForThem>,
    /// There when the step it signed hasn't reached this agent's host yet, so an agent isn't left to
    /// tell its person it went.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    queued: Option<Queued>,
    /// A move held here, waiting for an owner or the other side's person, that this one did away with,
    /// as it took that one's place or ended the request, so it will never go.
    #[serde(skip_serializing_if = "Option::is_none")]
    held_dropped: Option<StepKind>,
}

/// A move waiting on the other side's person, said the same way wherever an agent reads it.
#[derive(Serialize)]
struct HeldForThem {
    held_for_their_controls: StepKind,
    why_held: &'static str,
}

impl HeldForThem {
    fn of(kind: StepKind) -> Self {
        Self {
            held_for_their_controls: kind,
            why_held: "Held, unsigned: this commits your person to an amount, and the other side's \
                       person hasn't set up their controls yet. Splint \
                       holds it until they have. Then it goes by itself, or waits for your person if \
                       their settings say so, as waiting_for_owner will show. Don't tell your person \
                       it went.",
        }
    }
}

/// A move held for the other side's person that didn't go by itself once they'd set up their controls,
/// with the refusal's fixed word, said the same way wherever an agent reads it.
#[derive(Serialize)]
struct NotSentByItself {
    not_sent_by_itself: String,
    why_not_sent: &'static str,
}

impl NotSentByItself {
    fn of(word: &str) -> Self {
        Self {
            not_sent_by_itself: word.to_owned(),
            why_not_sent: "Your move held for the other side's person didn't go once they'd set up \
                           their controls: it was refused for the reason given, and nothing was \
                           signed or sent. Where waiting_for_owner names it, it waits for your \
                           person now. Otherwise it can't go as it was.",
        }
    }
}

/// A signed step still waiting in Signet: `reach` is `queued`, as `GET /v0/requests` would say, with
/// why, where the last try to hand it on found out, and fixed words on what lifts it.
#[derive(Serialize)]
struct Queued {
    reach: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    held_because: Option<HeldBecause>,
    #[serde(skip_serializing_if = "Option::is_none")]
    why_queued: Option<&'static str>,
}

/// The owner's rules say this kind of step waits for them: by their level, or as it would commit them
/// to a value, unless it's a price their agent quotes that they let go, or their own `confirm` of
/// the outcome will wait for them anyway, as `signs_later` says, with someone they approved.
async fn waits_for_owner(
    signet: &Signet,
    kind: StepKind,
    commits: Commits,
    signs_later: bool,
    counterparty: Counterparty,
) -> bool {
    signet
        .rules
        .permissions()
        .await
        .is_some_and(|permissions| permissions.holds_step(kind, commits, signs_later, counterparty))
}

/// Whether this owner approved the other side for this type, as their device will judge a yes with
/// them, so a step the agent asks for waits exactly where that yes would.
async fn counterparty_of(
    signet: &Signet,
    agent: &SplintId,
    owner: Option<&SplintId>,
    interaction: &InteractionType,
) -> Counterparty {
    let approved = signet
        .rules
        .approves(agent, owner, std::slice::from_ref(interaction))
        .await;
    if approved {
        Counterparty::Approved
    } else {
        Counterparty::NotApproved
    }
}

/// What holds a move the agent asked for: the other side's person, for a value while they haven't set
/// up their controls, and this owner, as their rules say.
struct HeldFor {
    them: bool,
    owner: bool,
}

impl HeldFor {
    async fn of(
        signet: &Signet,
        peer: &SplintId,
        record: &Record,
        chain: &Chain,
        held: &HeldMove,
        now: u64,
    ) -> Self {
        let side = record.role;
        // Agreeing a type commits nobody to anything, so nobody is asked, at any level (Nenye,
        // 2026-11-14).
        if chain.proposed_schema().is_some() {
            return Self {
                them: false,
                owner: false,
            };
        }
        let them = matches!(
            chain.held_draft(side, held, now),
            Err(Refused::TheirOwnerUnconfirmed)
        );
        // Judged on the terms whoever stands behind the other side, or a price this side would be paid,
        // held only for their person, read as the paying side's and waited for this owner too. Terms
        // that can't be worked out count as carrying a value, so the move waits rather than goes.
        let schema = chain.interaction_schema().cloned().map(Arc::new);
        let owners = match &schema {
            Some(schema) => Some(types::as_owner_reads(signet, peer, schema).await),
            None => None,
        };
        let commits = match (chain.held_terms(side, held, now), owners) {
            (Ok(terms), Some(schema)) => Commits::of(&schema, &terms, side),
            _ => Commits::AValue,
        };
        let signs_later = schema.as_ref().is_some_and(|schema| schema.signed_by(side));
        // A record that can't say who's on the other side counts as someone the owner didn't approve.
        let counterparty = match (record.peer_agent(), chain.interaction()) {
            (Ok(peer), Some(interaction)) if !record.guest => {
                let owner = Identity::from_encoded(&record.peer_owner).ok();
                let owner = owner.as_ref().map(Identity::id);
                counterparty_of(signet, peer.id(), owner, interaction).await
            }
            _ => Counterparty::NotApproved,
        };
        let owner = waits_for_owner(signet, held.kind(), commits, signs_later, counterparty).await;
        Self { them, owner }
    }

    fn holds(&self) -> bool {
        self.them || self.owner
    }
}

/// Whether the move held here waits on the other side's person to set up their controls.
fn held_for_their_controls(record: &Record, chain: &Chain, now: u64) -> Option<StepKind> {
    let held = record.held.as_ref()?;
    matches!(
        chain.held_draft(record.role, held, now),
        Err(Refused::TheirOwnerUnconfirmed)
    )
    .then(|| held.kind())
}

async fn open(
    State(signet): State<Arc<Signet>>,
    Json(mut body): Json<OpenBody>,
) -> Result<Json<Moved>, ApiError> {
    secret_egress::refuse_secrets(&signet, &secret_egress::words_in(&body.terms)).await?;
    refuse_hidden_characters(&body.terms)?;
    body.contact = typed_address(&body.contact)?;
    let contact = fresh_contact_at(&signet, &body.contact)
        .await?
        .ok_or(ApiError::BadRequest("that address isn't a contact"))?;
    if !signet.rules.may_start_with(&body.contact).await {
        return Err(ApiError::BadRequest("that address isn't a contact"));
    }
    let peer = contact.agent.id().clone();
    let schemas = signet
        .requests
        .types
        .schemas_with(&peer, contact.owner.id());
    let schema = type_named(&schemas, body.interaction.as_deref())?;
    if !contact.rule.may_use(&schema) {
        return Err(Refused::TypeNotAllowed.into());
    }
    check_approved_for_use(&signet, &contact.rule, &schema, Some(&contact.owner))?;
    let owners = types::as_owner_reads(&signet, &peer, &schema).await;
    check_owner_stands_behind(&signet, &owners, &body.terms)?;
    budget::check_caps(&signet, &owners, &body.terms, &body.terms).await?;
    let priced = names_currency(&owners, &body.terms);
    let now = unix_now();
    let supersedes = body.supersedes.clone();
    let offer = Offer {
        interaction: schema.name().clone(),
        schema: None,
        terms: body.terms,
        deadline: body.deadline,
        supersedes: body.supersedes,
    };
    // An `open` is the paying side's, so one with currency waits for its owner too, and their device is
    // shown it once the other side's person has set up their controls.
    let for_them = priced && contact.owner.is_unconfirmed_owner();
    let commits = if priced {
        Commits::AValue
    } else {
        Commits::Nothing
    };
    let signs_later = schema.signed_by(Side::Requester);
    let counterparty = counterparty_of(
        &signet,
        contact.agent.id(),
        Some(contact.owner.id()),
        &offer.interaction,
    )
    .await;
    if for_them
        || waits_for_owner(&signet, StepKind::Open, commits, signs_later, counterparty).await
    {
        let hold = hold_open(&signet, contact, offer, now).await?;
        return Ok(Json(Moved {
            request: None,
            message_id: None,
            hold: Some(hold),
            waiting_for_owner: true,
            held_for_them: for_them.then(|| HeldForThem::of(StepKind::Open)),
            queued: None,
            held_dropped: None,
        }));
    }
    let checked = CheckedStep::open(offer, &schemas, contact.agent.id(), now)?;
    budget::spend(&signet).await?;
    let (request, message_id) =
        send_open(&signet, contact, checked, supersedes.as_ref(), None).await?;
    Ok(moved(&signet, request, message_id, None).await)
}

/// The type an agent names for an `open`: core's plain conversation where it names none, or one agreed
/// with this contact, by its ID or by its name alone. A `type/1` goes by its own call.
fn type_named(schemas: &Schemas, named: Option<&str>) -> Result<Arc<Schema>, ApiError> {
    let Some(named) = named else {
        return Ok(Schema::conversation());
    };
    if named == PROPOSAL {
        return Err(ApiError::BadRequest(
            "a type is proposed with POST /v0/types, {\"contact\", \"schema\"}",
        ));
    }
    let found = match InteractionType::try_from(named.to_owned()) {
        Ok(id) => schemas.get(&id),
        Err(_) => schemas.named(named),
    };
    found.cloned().ok_or_else(|| Refused::UnknownType.into())
}

/// Checks an `open` as if it were going, and keeps it for the owner. It costs the agent an action now,
/// so asking its owner over and over runs out, and its owner's yes costs it nothing more.
async fn hold_open(
    signet: &Signet,
    contact: Contact,
    offer: Offer,
    now: u64,
) -> Result<MessageId, ApiError> {
    let nonce = splint_core::random_nonce()?;
    let record = new_record(&contact);
    {
        let records = signet.requests.store.lock().await;
        let may_move =
            |supersedes| may_supersede(signet, &records, &record.peer_identity, supersedes);
        if offer.supersedes.as_ref().is_some_and(|id| !may_move(id)) {
            return Err(Refused::Malformed.into());
        }
        // Their person may set up their controls before its deadline, when it's shown to the owner.
        match record.chain(signet)?.open_draft(&offer, &nonce, now) {
            Ok(_) | Err(Refused::TheirOwnerUnconfirmed) => {}
            Err(refused) => return Err(refused.into()),
        }
    }
    budget::spend(signet).await?;
    let open = HeldOpen::new(nonce, offer, &contact);
    let hold = open.hold.clone();
    let allowed = signet.rules.open_approvals().await;
    signet.requests.held_opens.keep(open, allowed).await?;
    Ok(hold)
}

pub fn new_record(contact: &Contact) -> Record {
    Record::new(
        Side::Requester,
        contact.address.clone(),
        contact.agent.encoded(),
        contact.owner.encoded(),
        contact.binding.clone(),
    )
}

/// Signs an `open` and hands it on, whether it went straight off or its owner has just said yes to
/// the one held as `from_hold`.
pub async fn send_open(
    signet: &Signet,
    contact: Contact,
    mut checked: CheckedStep,
    supersedes: Option<&MessageId>,
    from_hold: Option<&MessageId>,
) -> Result<(String, MessageId), ApiError> {
    let now = unix_now();
    // A `type/1` counts against two proposals a day instead, which its own call spent.
    if !checked.proposes() {
        budget::spend_new_request(signet, contact.agent.id()).await?;
    }
    let who = signet.who();
    let place = place_of(contact.agent.id(), None);
    let waiting = &signet.requests.person_texts;
    let carries_words = waiting.put_on(&mut checked, &place, &who).await;
    let signed = signet.sign_step(checked, &contact.agent, now).await?;
    signet.rules.note_met(contact.agent.id()).await?;
    let request = signed.id.as_str().to_owned();
    let mut record = new_record(&contact);
    record.add_own(&signed);
    record.from_hold = from_hold.cloned();
    {
        let mut records = signet.requests.store.lock().await;
        let may_move =
            |supersedes| may_supersede(signet, &records, &record.peer_identity, supersedes);
        if supersedes.is_some_and(|id| !may_move(id)) {
            return Err(Refused::Malformed.into());
        }
        // What's saved is the one word on whether a hold went, so it's asked again where it's written.
        // The caller's claim and its own look before signing mean this can't happen today. It's kept
        // so that one write can never hold two opens from one hold, whatever changes above it.
        if from_hold.is_some_and(|hold| started_from(&records, hold).is_some()) {
            return Err(ApiError::NotFound);
        }
        signet
            .requests
            .store
            .commit(&mut records, &request, record)?;
    }
    if carries_words {
        waiting.went_out(&place).await;
    }
    if let Err(error) = sync::flush(signet).await {
        tracing::debug!(%error, "a step is waiting to reach our host");
    }
    Ok((request, signed.id))
}

/// What a move came to.
pub enum Made {
    /// Signed, with the move held here that it did away with, if it did, as it took that one's place
    /// or ended the request.
    Sent {
        id: MessageId,
        dropped: Option<StepKind>,
    },
    /// It waits, and nothing is signed: for the owner, as their rules say, or for the other side's
    /// person to set up their controls, as it commits the owner to a value, or both. One move is held
    /// at a time, so it names the one held before that it took the place of, if there was one.
    Held {
        kind: StepKind,
        for_owner: bool,
        for_them: bool,
        dropped: Option<StepKind>,
    },
}

/// Whether the agent asks for a move now, or asked for it before and it waited only for the other side's
/// person, who has since set up their controls.
#[derive(Clone, Copy)]
enum Asked<'a> {
    Now,
    /// It goes only if it's still what's held for them when it's signed, so an owner's answer or the
    /// agent's newer move that got there first is never undone by this older copy. It was paid for
    /// when it was held.
    WhenHeld(&'a HeldMove),
}

/// Whether a move does away with the one held here: one that takes its place, the owner's yes to it,
/// or one that ends the request. Anything else, such as `progress`, leaves it waiting where it is. Every
/// kind is named, so a new one can't drop a held move by being left out.
fn does_away_with_held(action: &Action) -> bool {
    match action {
        Action::Counter { .. }
        | Action::Accept { .. }
        | Action::Deliver { .. }
        | Action::Released(..)
        | Action::Decline { .. }
        | Action::Cancel
        | Action::Confirm(_)
        | Action::ConfirmDenied(_)
        | Action::CancelApproved(_) => true,
        Action::Say { .. }
        | Action::Clarify { .. }
        | Action::Progress { .. }
        | Action::Pause { .. }
        | Action::Resume
        | Action::PayRequest { .. }
        | Action::PaymentReceived => false,
    }
}

/// Text no type takes, as it could hide what a reader is shown, refused saying which field and which
/// character, ahead of the schema's own check, which refuses it too but says only `malformed`. Any
/// text field, as a `word` field with one fits no word either.
fn refuse_hidden_characters(fields: &Fields) -> Result<(), ApiError> {
    for (name, value) in fields {
        let FieldValue::Text(text) = value else {
            continue;
        };
        let Some(character) = text
            .chars()
            .find(|c| has_hidden_characters(c.encode_utf8(&mut [0; 4])))
        else {
            continue;
        };
        // Only a name like a type's own is repeated back.
        let plain = (1..=32).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        return Err(ApiError::HiddenCharacter {
            field: plain.then(|| name.clone()),
            character,
        });
    }
    Ok(())
}

/// One move: check it against the chain, sign it and save it, all under the lock, so that two
/// calls can't sign two steps on one `prev`. It reaches the host after that, and a host that's
/// down only delays it.
pub async fn make_move(signet: &Signet, request: &str, action: Action) -> Result<Made, ApiError> {
    move_on(signet, request, action, Asked::Now).await
}

async fn move_on(
    signet: &Signet,
    request: &str,
    action: Action,
    asked: Asked<'_>,
) -> Result<Made, ApiError> {
    secret_egress::refuse_secrets(signet, &secret_egress::words_of(&action)).await?;
    if let Action::Say { fields: given }
    | Action::Counter { terms: given }
    | Action::Accept { pick: given }
    | Action::Deliver { result: given } = &action
    {
        refuse_hidden_characters(given)?;
    }
    let now = unix_now();
    let signed = {
        let mut records = signet.requests.store.lock().await;
        let mut record = records.get(request).ok_or(ApiError::NotFound)?.clone();
        if let Asked::WhenHeld(was) = asked
            && !(record.held_until_they_confirm && record.held.as_ref() == Some(was))
        {
            return Err(ApiError::NotFound);
        }
        // Rules count once signed, so a request already open gives a contact no way round them.
        let peer = record.peer_agent()?;
        let owners = is_owners(&action);
        let may_move = if record.guest {
            true
        } else if owners {
            signet.rules.lists_for_requests(peer.id()).await
        } else {
            signet.rules.may_move_with(peer.id(), record.role).await
        };
        // Ending what's open asks nothing more of anyone, so the owner taking them out of the contacts
        // can't strand it: the agent's cancel, and the owner's own no or cancel. Its step
        // waits here, unsent, unless the owner adds them back. An owner's yes commits them to someone
        // their rules no longer name, so it doesn't go.
        let ends_it = matches!(
            action,
            Action::Cancel | Action::ConfirmDenied(_) | Action::CancelApproved(_)
        );
        let only_ending = !may_move
            && !record.guest
            && ends_it
            && !signet.rules.held_by_a_change(peer.id()).await;
        if !may_move && !only_ending {
            return Err(if owners && !ends_it {
                ApiError::OwnersYesToNoContact
            } else {
                ApiError::NotAContact
            });
        }
        let chain = record.chain(signet)?;
        if !record.guest && !only_ending {
            let their_owner = Identity::from_encoded(&record.peer_owner).ok();
            check_type_still_allowed(signet, peer.id(), their_owner.as_ref(), &chain, &action)
                .await?;
        }
        if let (Some(proposed), Action::Accept { .. }) = (chain.proposed_schema(), &action) {
            check_may_agree(signet, peer.id(), &record.peer_owner_id()?, proposed)?;
        }
        if let Some(schema) = chain.interaction_schema() {
            let schema = Arc::new(schema.clone());
            let owners = if record.guest {
                schema
            } else {
                types::as_owner_reads(signet, peer.id(), &schema).await
            };
            for fields in capped_by(&action, &chain) {
                check_owner_stands_behind(signet, &owners, fields)?;
                budget::check_caps(signet, &owners, fields, chain.offer()).await?;
            }
        }
        let held = HeldMove::of(&action);
        let does_away = does_away_with_held(&action);
        let releases_it = matches!(action, Action::Released(..));
        // An owner's no to their `confirm` goes as a plain decline, which the agent would otherwise read
        // as its own. Only what's shown: the step is the same.
        let owner_denied = matches!(action, Action::ConfirmDenied(_)).then_some(StepKind::Confirm);
        // An owner's own step, such as their `confirm`, its no or an approved cancel, moves the request
        // on past a move their agent held for them, which then never goes. The agent hears it as their
        // no, rather than finding its move gone with nothing said. It comes ahead of a no to
        // their `confirm`, as the decline that no sends already shows as the owner's.
        let passed_over = (owners && !matches!(action, Action::Released(..)))
            .then(|| record.held.as_ref().map(HeldMove::kind))
            .flatten();
        let mut step = chain.propose(record.role, action, now)?;
        if !owners && matches!(asked, Asked::Now) {
            budget::spend(signet).await?;
        }
        record.owner_said_no = passed_over.or(owner_denied);
        record.held_not_sent = None;
        if owners {
            record.owner_answer_not_used = None;
        }
        if let Some(held) = held
            && !owners
        {
            let held_for = HeldFor::of(signet, peer.id(), &record, &chain, &held, now).await;
            if held_for.holds() {
                let kind = held.kind();
                let dropped = record.held.replace(held).map(|was| was.kind());
                // Only what nothing but their person holds goes by itself once they've set up.
                record.held_until_they_confirm = held_for.them && !held_for.owner;
                signet
                    .requests
                    .store
                    .commit(&mut records, request, record)?;
                return Ok(Made::Held {
                    kind,
                    for_owner: held_for.owner,
                    for_them: held_for.them,
                    dropped,
                });
            }
        }
        // Not for one taken out, as a filter on past exchanges would let them back in.
        if !owners && !record.guest && !only_ending {
            signet.rules.note_met(peer.id()).await?;
        }
        let dropped = if does_away {
            record.held_until_they_confirm = false;
            record
                .held
                .take()
                .filter(|_| !releases_it)
                .map(|held| held.kind())
        } else {
            None
        };
        let who = signet.who();
        let waiting = &signet.requests.person_texts;
        // A guest has no agent for an owner's words to reach, and a host wouldn't carry them.
        let carries_words = !record.guest && waiting.put_on(&mut step, request, &who).await;
        let signed = signet.sign_step(step, &peer, now).await?;
        record.add_own(&signed);
        if chain.proposed_schema().is_some() {
            // What this agent just agreed, or no longer does, counts from this step on.
            let moved = record.chain(signet)?;
            signet
                .requests
                .store
                .commit_chain(signet, &mut records, request, record, &moved)?;
        } else {
            signet
                .requests
                .store
                .commit(&mut records, request, record)?;
        }
        if carries_words {
            waiting.went_out(request).await;
        }
        (signed, dropped)
    };
    let (signed, dropped) = signed;
    if let Err(error) = sync::flush(signet).await {
        tracing::debug!(%error, "a step is waiting to reach our host");
    }
    Ok(Made::Sent {
        id: signed.id,
        dropped,
    })
}

/// Sends each move that waited only for the other side's person, now that they've set up their
/// controls, as its agent asked for it. The rules are asked again as it goes, so one they
/// now hold waits for this owner instead. One that's refused is left to this owner, as any held move
/// is, with why it didn't go for the agent to read, and one that couldn't go just then is tried again
/// on the next pass. Whether anything went.
pub async fn send_what_their_controls_held(signet: &Signet) -> bool {
    let freed: Vec<(String, HeldMove)> = {
        let records = signet.requests.store.lock().await;
        records
            .iter()
            .filter(|(_, record)| record.held_until_they_confirm)
            .filter_map(|(request, record)| {
                let chain = record.chain(signet).ok()?;
                let held = record.held.clone()?;
                (!chain.other_side_unconfirmed(record.role)).then(|| (request.clone(), held))
            })
            .collect()
    };
    if freed.is_empty() {
        return false;
    }
    // These go long after the agent asked, so they go by the owner's latest rules, which may so far be
    // only at the host, as when signed from another device. Until those can be read, they wait.
    if let Err(error) = rules::catch_up_with_host(signet).await {
        tracing::debug!(%error, "moves held for the other side's person wait for our owner's rules");
        return false;
    }
    let mut went = false;
    for (request, held) in freed {
        let action = held.clone().into_action();
        match move_on(signet, &request, action, Asked::WhenHeld(&held)).await {
            Ok(Made::Sent { .. }) => went = true,
            Ok(Made::Held { .. }) => {}
            Err(error) if can_come_right(&error) => {
                tracing::debug!("a move held for the other side's person can't go yet");
            }
            Err(error) => not_sent_by_itself(signet, &request, &held, &error).await,
        }
    }
    went
}

/// What can come right with nobody answering anything: this Signet couldn't save, sign or reach
/// something just then, the owner's rules let nothing go for now, as while they're paused, or what was
/// held changed or was answered first, which leaves nothing of this one to try. Not `not_a_contact`:
/// the owner took them out of the contacts, or a change to them waits on the owner, so it's theirs to
/// decide, and trying again every pass left the agent never reading why it didn't go.
fn can_come_right(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Host(_)
            | ApiError::CouldntReach(_)
            | ApiError::TooManyWaits
            | ApiError::Stopped
            | ApiError::NotFound
    )
}

/// Leaves a move that was refused as it went by itself to this owner, as any held move is, with the
/// refusal's fixed word for its agent, while it's still the one held.
async fn not_sent_by_itself(signet: &Signet, request: &str, held: &HeldMove, error: &ApiError) {
    let mut records = signet.requests.store.lock().await;
    let Some(mut record) = records.get(request).cloned() else {
        return;
    };
    if !(record.held_until_they_confirm && record.held.as_ref() == Some(held)) {
        return;
    }
    record.held_until_they_confirm = false;
    record.held_not_sent = Some(error.refused_word().unwrap_or_else(|| "refused".to_owned()));
    if let Err(error) = signet.requests.store.commit(&mut records, request, record) {
        tracing::debug!(%error, "couldn't save a held move");
    }
}

/// An agent whose owner hasn't confirmed can't put a value on the table or take one up, as its owner
/// hasn't signed for it yet. A reader refuses one anyway, and the agent is told here how to bring its
/// owner in.
fn check_owner_stands_behind(
    signet: &Signet,
    schema: &Schema,
    fields: &Fields,
) -> Result<(), ApiError> {
    let names_a_value = fields.keys().any(|name| schema.is_value(name));
    if names_a_value && signet.who().owner.is_unconfirmed_owner() {
        return Err(Refused::OwnerUnconfirmed.into());
    }
    Ok(())
}

/// An owner's decision, which isn't the agent's to count or limit.
fn is_owners(action: &Action) -> bool {
    matches!(
        action,
        Action::Confirm(_)
            | Action::ConfirmDenied(_)
            | Action::CancelApproved(_)
            | Action::Released(..)
    )
}

/// What a move commits this agent to, which the owner's caps apply to. Accepting takes on whatever the
/// other side has on the table, as well as anything the agent picks from it.
fn capped_by<'a>(action: &'a Action, chain: &'a Chain) -> Vec<&'a Fields> {
    match action {
        Action::Say { fields } => vec![fields],
        Action::Counter { terms } => vec![terms],
        Action::Accept { pick } => vec![chain.offer(), pick],
        Action::Deliver { result } => vec![result],
        _ => Vec::new(),
    }
}

/// What holds an agent taking up a proposal: one name means one schema with each contact, and each holds
/// only so many. Its own Signet checks the proposal's limits and the owner's switch as it arrives.
fn check_may_agree(
    signet: &Signet,
    peer: &SplintId,
    owner: &SplintId,
    proposed: &Schema,
) -> Result<(), ApiError> {
    let types = &signet.requests.types;
    if types.name_taken(peer, owner, proposed) {
        return Err(Refused::NameTaken.into());
    }
    if !types.holds(peer, owner, proposed.name())
        && types.with(peer, owner).len() >= splint_core::requests::MAX_AGREED_PER_CONTACT
    {
        return Err(Refused::TooManyTypes.into());
    }
    Ok(())
}

/// Rules count once signed, so a type the owner has since taken away from this contact gets no more
/// moves from an agent. An owner's own decision still goes through, paused or not.
async fn check_type_still_allowed(
    signet: &Signet,
    peer: &SplintId,
    their_owner: Option<&Identity>,
    chain: &Chain,
    action: &Action,
) -> Result<(), ApiError> {
    if is_owners(action) {
        return Ok(());
    }
    let rule = signet.rules.contact_of(peer).await;
    let allowed = chain
        .interaction_schema()
        .zip(rule.as_ref())
        .is_some_and(|(schema, rule)| match chain.proposed_schema() {
            Some(proposed) => rule.may_propose(proposed),
            None => rule.may_use(schema),
        });
    // Only a move that puts terms on the table or takes them up needs the owner's approval of a kind
    // with currency: declining, asking, pausing or cancelling one commits nobody.
    let commits = matches!(
        action,
        Action::Counter { .. } | Action::Accept { .. } | Action::Deliver { .. }
    );
    match (allowed, chain.interaction_schema(), &rule) {
        (true, Some(schema), Some(rule)) if commits && chain.proposed_schema().is_none() => {
            check_approved_for_use(signet, rule, schema, their_owner)
        }
        (true, _, _) => Ok(()),
        _ => Err(Refused::TypeNotAllowed.into()),
    }
}

/// An agent moves in a kind with currency only once its owner approved it for that contact (Nenye,
/// 2026-11-15), with what to do said where it hasn't. An agent that joined without its owner's
/// oversight yet has nobody to approve one, and nothing it sends can carry a value until it has, as
/// every reader refuses one (`owner_unconfirmed`), so it may ask; its owner's approval counts once
/// they've set up their controls. Another agent of the same owner, by a binding, needs none, as the
/// owner stands on both sides and each side's price still waits for them. Provisional, for Nenye.
fn check_approved_for_use(
    signet: &Signet,
    rule: &RulesContact,
    schema: &Schema,
    their_owner: Option<&Identity>,
) -> Result<(), ApiError> {
    if rule.approved_for_use(schema)
        || signet.who().owner.is_unconfirmed_owner()
        || crate::contacts::SameOwner::of(signet, their_owner).same_owner
    {
        Ok(())
    } else {
        Err(ApiError::KindNotApproved)
    }
}

/// A step signed, and, where it hasn't reached the host after the try that follows signing, why.
pub async fn moved(
    signet: &Signet,
    request: String,
    message_id: MessageId,
    held_dropped: Option<StepKind>,
) -> Json<Moved> {
    let queued = {
        let records = signet.requests.store.lock().await;
        // What they send next on it is an answer this agent may be waiting on.
        if let Some(peer) = records
            .get(&request)
            .and_then(|record| Identity::claimed_id(&record.peer_identity).ok())
        {
            signet.activity.wrote_to(&peer);
        }
        records
            .get(&request)
            .filter(|record| record.outbox.iter().any(|out| out.message_id == message_id))
            .map(|record| Queued {
                reach: "queued",
                held_because: record.held_because,
                why_queued: record.held_because.map(HeldBecause::words),
            })
    };
    Json(Moved {
        request: Some(request),
        message_id: Some(message_id),
        hold: None,
        waiting_for_owner: false,
        held_for_them: None,
        queued,
        held_dropped,
    })
}

pub async fn made(signet: &Signet, request: String, made: Made) -> Json<Moved> {
    match made {
        Made::Sent { id, dropped } => moved(signet, request, id, dropped).await,
        Made::Held {
            kind,
            for_owner,
            for_them,
            dropped,
        } => Json(Moved {
            request: Some(request),
            message_id: None,
            hold: None,
            waiting_for_owner: for_owner,
            held_for_them: for_them.then(|| HeldForThem::of(kind)),
            queued: None,
            held_dropped: dropped,
        }),
    }
}

/// One call per move, each with one typed body and no other way in.
macro_rules! move_call {
    ($call:ident, $body:ident { $($field:ident: $kind:ty),* }, |$bound:ident| $action:expr) => {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $body {
            $($field: $kind),*
        }

        async fn $call(
            State(signet): State<Arc<Signet>>,
            Path(request): Path<String>,
            Json($bound): Json<$body>,
        ) -> Result<Json<Moved>, ApiError> {
            let result = make_move(&signet, &request, $action).await?;
            Ok(made(&signet, request, result).await)
        }
    };
}

move_call!(say, SayBody { fields: Fields }, |body| Action::Say {
    fields: body.fields
});
move_call!(counter, CounterBody { terms: Fields }, |body| {
    Action::Counter { terms: body.terms }
});
move_call!(clarify, ClarifyBody { reason: Word }, |body| {
    Action::Clarify {
        reason: body.reason,
    }
});
move_call!(progress, ProgressBody { status: Word }, |body| {
    Action::Progress {
        status: body.status,
    }
});
move_call!(
    pause,
    PauseBody {
        reason: PauseReason
    },
    |body| Action::Pause {
        reason: body.reason
    }
);
move_call!(deliver, DeliverBody { result: Fields }, |body| {
    Action::Deliver {
        result: body.result,
    }
});
move_call!(decline, DeclineBody { reason: Word }, |body| {
    Action::Decline {
        reason: body.reason,
    }
});

/// A type with nothing to pick takes an empty body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptBody {
    #[serde(default)]
    pick: Fields,
}

async fn accept(
    State(signet): State<Arc<Signet>>,
    Path(request): Path<String>,
    Json(body): Json<AcceptBody>,
) -> Result<Json<Moved>, ApiError> {
    let action = Action::Accept { pick: body.pick };
    let result = make_move(&signet, &request, action).await?;
    Ok(made(&signet, request, result).await)
}

async fn resume(
    State(signet): State<Arc<Signet>>,
    Path(request): Path<String>,
) -> Result<Json<Moved>, ApiError> {
    let result = make_move(&signet, &request, Action::Resume).await?;
    Ok(made(&signet, request, result).await)
}

/// Once a request is completed, this only asks the owner: a cancel then needs their signature.
async fn cancel(
    State(signet): State<Arc<Signet>>,
    Path(request): Path<String>,
) -> Result<Json<Moved>, ApiError> {
    {
        let mut records = signet.requests.store.lock().await;
        let mut record = records.get(&request).ok_or(ApiError::NotFound)?.clone();
        let chain = record.chain(&signet)?;
        let now = unix_now();
        if chain.state_at(now) == RequestState::Completed {
            // Only an owner's signature on its terms cancels what's completed. A `type/1` has none: a
            // type two agents agreed stays agreed, and the owner's `agree_types` is what stops it. So
            // there's nothing to ask them, and saying it waits on them would be untrue.
            if chain.cancel_draft(record.role, now).is_none() {
                return Err(Refused::NoMovesLeft.into());
            }
            record.cancel_wanted = true;
            signet
                .requests
                .store
                .commit(&mut records, &request, record)?;
            return Ok(Json(Moved {
                request: Some(request),
                message_id: None,
                hold: None,
                waiting_for_owner: true,
                held_for_them: None,
                queued: None,
                held_dropped: None,
            }));
        }
    }
    let result = make_move(&signet, &request, Action::Cancel).await?;
    Ok(made(&signet, request, result).await)
}

#[derive(Serialize)]
struct RequestList {
    requests: Vec<RequestView>,
    /// Interactions this agent asked to start, which its owner is deciding or has decided.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    held_opens: Vec<HeldOpenView>,
}

async fn list(State(signet): State<Arc<Signet>>) -> Result<Json<RequestList>, ApiError> {
    let unconfirmed = signet.who().owner.is_unconfirmed_owner();
    let now = unix_now();
    // Taken out first, as the delegate's pass holds its key while it reads these, and this asks it.
    let held: Vec<Record> = signet
        .requests
        .store
        .lock()
        .await
        .values()
        .cloned()
        .collect();
    // One that can't be read, such as one whose schema has been taken away, leaves the others alone.
    let read: Vec<(&Record, Chain)> = held
        .iter()
        .filter_map(|record| Some((record, record.chain(&signet).ok()?)))
        .collect();
    let every_ask: Vec<PaymentAsk> = read
        .iter()
        .flat_map(|(_, chain)| {
            chain
                .payment_asks()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect();
    // Who a request has completed with, from the chains already read, for each one's facts.
    let completed: HashSet<String> = read
        .iter()
        .filter(|(_, chain)| chain.state_at(now) == RequestState::Completed)
        .filter_map(|(record, _)| Identity::claimed_id(&record.peer_identity).ok())
        .map(|id| id.as_str().to_owned())
        .collect();
    let mut requests = Vec::with_capacity(read.len());
    for (record, chain) in &read {
        let (pinned_by, approved_by_owner) = standing_of(&signet, record, chain).await;
        let standing = Standing {
            host_says: None,
            pinned_by,
            approved_by_owner,
            owner_unconfirmed: unconfirmed,
            delegate_signs: delegate_signs(&signet, record, chain, now).await,
            paid_before: every_ask.clone(),
        };
        let mut shown = view(record, chain, standing)?;
        let completed_before = completed.contains(shown.from.agent.as_str());
        shown.facts = facts_of(&signet, record, chain, &shown.from.agent, completed_before).await;
        requests.push(shown);
    }
    let held_opens = signet.requests.held_opens.views(unix_now()).await;
    Ok(Json(RequestList {
        requests,
        held_opens,
    }))
}

fn host_says(status: &DeliveryStatus) -> Option<HostSays> {
    match status.status {
        DeliveryState::Pending => Some(HostSays::Pending),
        DeliveryState::Delivered => Some(HostSays::AtTheirHost),
        DeliveryState::Rejected => Some(HostSays::Rejected),
        DeliveryState::Expired => Some(HostSays::Expired),
        DeliveryState::PeerRemoved => Some(HostSays::PeerRemoved),
        DeliveryState::Withdrawn => Some(HostSays::Withdrawn),
        DeliveryState::Quarantined | DeliveryState::Retired => None,
    }
}

async fn read(
    State(signet): State<Arc<Signet>>,
    Path(request): Path<String>,
) -> Result<Json<RequestView>, ApiError> {
    let (record, chain, paid_before) = {
        let records = signet.requests.store.lock().await;
        let record = records.get(&request).ok_or(ApiError::NotFound)?.clone();
        let chain = record.chain(&signet)?;
        let paid_before = if chain.payment().is_some() {
            payments::asks_with_owner(&signet, &records, &record.peer_owner)
        } else {
            Vec::new()
        };
        (record, chain, paid_before)
    };
    let mine = chain.head_side() == Some(record.role);
    let says = match chain.head() {
        Some(head) if mine => signet
            .host
            .delivery_status(&signet.key, signet.who().identity.id(), head.as_str())
            .await
            .ok()
            .as_ref()
            .and_then(host_says),
        _ => None,
    };
    let (pinned_by, approved_by_owner) = standing_of(&signet, &record, &chain).await;
    let standing = Standing {
        host_says: says,
        pinned_by,
        approved_by_owner,
        owner_unconfirmed: signet.who().owner.is_unconfirmed_owner(),
        delegate_signs: delegate_signs(&signet, &record, &chain, unix_now()).await,
        paid_before,
    };
    let mut shown = view(&record, &chain, standing)?;
    let completed_before = crate::requests::store::completed_with(&signet, &shown.from.agent).await;
    shown.facts = facts_of(
        &signet,
        &record,
        &chain,
        &shown.from.agent,
        completed_before,
    )
    .await;
    Ok(Json(shown))
}

/// Signet's own facts about the other side of a request, as beside a note, while they're a contact.
async fn facts_of(
    signet: &Signet,
    record: &Record,
    chain: &Chain,
    peer: &SplintId,
    completed_before: bool,
) -> Option<crate::arrivals::Facts> {
    let contact = signet.rules.contact_of(peer).await?;
    let controls = if chain.other_side_unconfirmed(record.role) {
        Controls::NotSetUp
    } else {
        Controls::Set
    };
    let words = words_on(chain, record.role);
    let about = crate::arrivals::About {
        contact: &contact,
        controls,
        text: Some(words.as_str()),
        number_not_money: number_not_money(chain),
    };
    Some(crate::arrivals::facts_given(signet, about, completed_before).await)
}

/// Whether a request holds a number its type doesn't label as currency, or a `type/1` proposes a type
/// with one, by this Signet's own reading of the schema.
fn number_not_money(chain: &Chain) -> bool {
    if let Some(proposed) = chain.proposed_schema() {
        return !proposed.numbers_not_money().is_empty();
    }
    chain.interaction_schema().is_some_and(|schema| {
        [chain.offer(), chain.pick(), chain.result()]
            .into_iter()
            .any(|fields| schema.numbers_not_money_in(fields).next().is_some())
    })
}

/// The words on a request that could name where to pay: what the other side said in it and their
/// person's words, and the text in its terms, pick and result, whoever wrote those. Only looked
/// through for payment details.
fn words_on(chain: &Chain, role: Side) -> String {
    let said = chain.messages();
    let theirs = said
        .iter()
        .filter(|one| one.by != role)
        .map(|one| &one.fields);
    let mut words: Vec<String> = [chain.offer(), chain.pick(), chain.result()]
        .into_iter()
        .chain(theirs)
        .flat_map(|fields| fields.values())
        .filter_map(|value| match value {
            FieldValue::Text(text) => Some(text.clone()),
            FieldValue::Int(_) | FieldValue::Times(_) => None,
        })
        .collect();
    words.extend(
        chain
            .person_texts()
            .into_iter()
            .filter(|one| one.by != role)
            .map(|one| one.text),
    );
    words.join("\n")
}

/// The whole exchange, unrolled by code from what's signed, without what only owners see.
async fn record(
    State(signet): State<Arc<Signet>>,
    Path(request): Path<String>,
) -> Result<Json<Dialogue>, ApiError> {
    Ok(Json(record_of(&signet, &request, Audience::Agent).await?))
}

pub async fn record_of(
    signet: &Signet,
    request: &str,
    audience: Audience,
) -> Result<Dialogue, ApiError> {
    let records = signet.requests.store.lock().await;
    let record = records.get(request).ok_or(ApiError::NotFound)?;
    let chain = record.chain(signet)?;
    let address = signet.address();
    let (requester, recipient) = match record.role {
        Side::Requester => (address.as_str(), record.peer_address.as_str()),
        Side::Recipient => (record.peer_address.as_str(), address.as_str()),
    };
    let reader = Reader {
        side: record.role,
        audience,
        requester,
        recipient,
    };
    chain.dialogue(reader, unix_now()).ok_or(ApiError::NotFound)
}

/// How the other party came to be one this agent deals with, if they still are: a contact the owner
/// chose, one the agent agreed with, or someone the reach setting let in. A guest is none of these.
/// With it, whether a value with them in this request goes as the owner's settings say.
async fn standing_of(signet: &Signet, record: &Record, chain: &Chain) -> (Option<PinnedBy>, bool) {
    if record.guest {
        return (None, false);
    }
    let Ok(peer) = Identity::from_encoded(&record.peer_identity) else {
        return (None, false);
    };
    let Some(contact) = signet.rules.contact_of(peer.id()).await else {
        return (None, false);
    };
    let owner = Identity::from_encoded(&record.peer_owner).ok();
    let types = chain
        .interaction()
        .map_or(contact.types, |one| vec![one.clone()]);
    let approved = signet
        .rules
        .approves(peer.id(), owner.as_ref().map(Identity::id), &types)
        .await;
    (Some(contact.pinned_by), approved)
}

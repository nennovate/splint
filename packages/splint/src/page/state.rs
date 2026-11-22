//! What the page shows, as plain data for a browser to draw. Every word a person reads is written
//! here from what's signed, with anything that could hide what it says shown as its code.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use splint_core::changes::ChangeRules;
use splint_core::host_api::HostRefusal;
use splint_core::requests::{
    ApprovalDraft, Audience, Dialogue, FieldRule, FieldValue, Fields, InteractionType,
    KindForApproval, Line, LineOrder, Operation, Reader, RequestState, Schema, Schemas, Side,
    StepKind, TermsParty, for_approval, grouped, has_hidden_characters, money, paying_in, utc_time,
    with_hidden_shown,
};
use splint_core::rules::{
    ContactStatus, LeftToOwner, Permissions, PinnedBy, Reach, RulesContact, RulesDraft,
};
use splint_core::{Identity, MessageId, Sealing, SplintId};

use crate::contacts::{line_for, was_never_a_contact};
use crate::failure::Failure;
use crate::rules::Signed;
use crate::signet_api::Held;

use super::walk::{Walked, WalkedAll};

/// Long enough for what a person scans.
const MAX_EXCHANGES_SHOWN: usize = 200;
/// A schema doesn't say a number is a date, so a large one shows both ways. 2001, well past any
/// quantity an owner would misread as a date.
const EARLIEST_TIME_SHOWN: u64 = 1_000_000_000;
pub const MAX_SUBJECT_CHARS: usize = 120;
pub const MAX_NOTE_CHARS: usize = 200;
pub const MAX_WORDS_CHARS: usize = 280;

#[derive(Serialize)]
pub struct PageState {
    me: Me,
    rules: RulesStanding,
    settings: Settings,
    /// Settings that let more through than usual, said beside them in fixed words.
    risky: Vec<crate::rules::Risky>,
    /// Who kept the agent busy today, busiest first, and whether that's far more than usual for them.
    usage: Vec<UsageLine>,
    types: Vec<TypeView>,
    contacts: Vec<ContactView>,
    waiting: Vec<Stranger>,
    /// Contacts both agents agreed to by invite, waiting for the owner's yes.
    invites: Vec<InviteWaiting>,
    /// Kinds with currency the agent agreed with a contact, which it can't use until the owner
    /// approves them.
    kinds: Vec<KindWaiting>,
    /// Held senders are read through the host, so a host that's down only hides those.
    waiting_unknown: bool,
    changes: Vec<Notice>,
    /// What the agent asked to start, and is waiting on the owner for.
    starting: Vec<Starting>,
    exchanges: Vec<Exchange>,
    /// Exchanges past what's shown here.
    exchanges_left_out: usize,
    links: Vec<LinkView>,
    refused: Vec<RefusedLine>,
    /// What a host says it refused is read through it, so a host that's down only hides those.
    refused_unknown: bool,
    /// What Signet sent that doesn't check out.
    unreadable: usize,
    /// Whether this agent runs on another device, and when its host last heard from its Signet.
    elsewhere: bool,
    heard_at: Option<u64>,
    max_subject_chars: usize,
    max_words_chars: usize,
}

#[derive(Serialize)]
struct Me {
    address: String,
    agent: SplintId,
    line: String,
}

/// The part of the rules this page lets the owner change directly. Who's a contact goes by its own
/// calls, so a stale form can't undo someone just added or blocked.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub paused: bool,
    pub reach: Reach,
    pub permissions: Permissions,
    pub changes: ChangeRules,
    pub sealing: Sealing,
}

/// Rules last until the owner signs others, unless they gave them an end.
#[derive(Serialize)]
struct RulesStanding {
    signed_at: u64,
    ends_at: Option<u64>,
    ended: bool,
}

#[derive(Serialize)]
struct TypeView {
    name: String,
    /// The names an owner's caps on it go by, each in one unit where a value has one.
    values: Vec<String>,
    /// What an offer of this type has to say, if a one-use link can offer it.
    link_fields: Option<BTreeMap<String, FieldRule>>,
}

/// A kind with currency agreed with a contact, waiting for the owner's approval before their agent
/// uses it, shown in core's fixed words.
#[derive(Serialize)]
struct KindWaiting {
    agent: SplintId,
    label: String,
    kind: KindForApproval,
}

/// A link this owner made, so it can be copied until it ends.
#[derive(Clone, Deserialize, Serialize)]
pub struct SavedLink {
    pub request: MessageId,
    pub url: String,
    pub interaction: String,
    pub deadline: u64,
}

#[derive(Serialize)]
struct LinkView {
    #[serde(flatten)]
    saved: SavedLink,
    state: Option<RequestState>,
}

/// Who kept the agent busy today, as its Signet counts it, which is only its word.
#[derive(Clone, Deserialize, Serialize)]
pub struct UsageLine {
    agent: SplintId,
    address: String,
    arrivals_today: u32,
    usual_per_day: u32,
    busier_than_usual: bool,
    texts_from: u32,
    texts_to: u32,
    new_requests_from: u32,
    new_requests_to: u32,
}

impl UsageLine {
    /// For an owner at a terminal, only when a contact is far busier than usual: their address, as
    /// their agent's binding has it, and Signet's own counts, in fixed words.
    pub fn busier_words(&self) -> Option<String> {
        self.busier_than_usual.then(|| {
            format!(
                "{} reached your agent {} times today, against about {} on a usual day. If you \
                 don't expect that, look at what came, and remove or block them if it's not right.",
                with_hidden_shown(&self.address),
                self.arrivals_today,
                self.usual_per_day
            )
        })
    }
}

#[derive(Deserialize)]
pub struct Usage {
    pub usage: Vec<UsageLine>,
}

/// What Signet wrote down as refused, and what its host says it refused. It's all fixed words and IDs.
#[derive(Deserialize)]
pub struct Refusals {
    refused: Vec<SignetRefusal>,
    at_host: Vec<HostRefusal>,
    host_unknown: bool,
}

#[derive(Deserialize)]
struct SignetRefusal {
    at: u64,
    way: String,
    call: Option<String>,
    from: Option<String>,
    reason: String,
    count: u32,
}

/// One line of it, for a person.
#[derive(Serialize)]
struct RefusedLine {
    at: u64,
    /// Who refused it: this owner's Signet, or a host by its own word.
    by: &'static str,
    way: String,
    call: Option<String>,
    from: Option<String>,
    reason: String,
    count: i64,
}

#[derive(Serialize)]
struct ContactView {
    agent: SplintId,
    address: String,
    label: String,
    blocked: bool,
    /// Blocked while a stranger, so there's no contact to go back to.
    never_a_contact: bool,
    types: Vec<String>,
    text: bool,
    invited: bool,
    /// Whether what goes between them is sealed, and why, in a few words.
    sealed: bool,
    sealed_why: &'static str,
}

/// Someone waiting in quarantine. None of their words are here, as those may be written to fool
/// whoever reads them.
#[derive(Serialize)]
struct Stranger {
    agent: SplintId,
    owner: Option<SplintId>,
    /// Only their own owner's word.
    claims: Option<String>,
    messages: usize,
    steps: usize,
    /// The owner's own agent asked for them, which is only its word.
    asked: bool,
    /// A contact whose host answers with another ID than the one the owner signed.
    disagreed: bool,
    first_at: u64,
    last_at: u64,
}

/// An invite both agents agreed to, checked here by the two agents' signatures, so the address and
/// ID are what they signed and not a Signet's word.
#[derive(Serialize)]
pub struct InviteWaiting {
    agent: SplintId,
    address: String,
    /// Whether this owner's agent sent it, rather than accepted it.
    invited_by_us: bool,
    /// Whether the owner's rules already let them in as a contact the agent added, so approving only
    /// marks them as chosen.
    added_by_agent: bool,
    at: u64,
}

pub fn invites_waiting(held: &[Held], own: &SplintId) -> Vec<InviteWaiting> {
    held.iter()
        .filter(|one| one.kind == "invite" || one.kind == "agreed")
        .filter_map(|one| {
            let new = one.invite.as_ref()?.verify(own).ok()?;
            Some(InviteWaiting {
                agent: new.agent,
                address: new.address,
                invited_by_us: new.invited_by_us,
                added_by_agent: one.kind == "agreed",
                at: one.created_at,
            })
        })
        .collect()
}

/// A contact's changes, as `GET /v0/owner/changes` gives them. Nothing here is signed for the page
/// to check, and nothing need be: an acceptance only ever lifts a hold in that same Signet.
#[derive(Deserialize, Serialize)]
pub struct Notice {
    pub contact: SplintId,
    label: String,
    address: String,
    pub standing: String,
    pub head: String,
    pub rewritten_head: Option<String>,
    pub since_accepted: Vec<Value>,
    #[serde(default)]
    pub rewritten_since: Vec<Value>,
    /// The signed histories, for a device that isn't beside this Signet to check.
    #[serde(default, skip_serializing)]
    pub history: Option<String>,
    #[serde(default, skip_serializing)]
    pub rewritten_history: Option<String>,
}

#[derive(Deserialize)]
pub struct Notices {
    pub changes: Vec<Notice>,
}

impl Notice {
    pub fn shown_address(&self) -> &str {
        &self.address
    }

    /// Each change as a line for a terminal, from what's been made safe to read.
    pub fn changes_shown(&self) -> Vec<String> {
        self.since_accepted.iter().map(Value::to_string).collect()
    }

    pub fn rewritten_shown(&self) -> Vec<String> {
        self.rewritten_since.iter().map(Value::to_string).collect()
    }

    /// Everything but what an acceptance has to name is for reading.
    pub fn for_reading(mut self) -> Self {
        self.label = with_hidden_shown(&self.label);
        self.address = with_hidden_shown(&self.address);
        self.since_accepted.iter_mut().for_each(show_hidden_in);
        self.rewritten_since.iter_mut().for_each(show_hidden_in);
        self
    }
}

fn show_hidden_in(value: &mut Value) {
    match value {
        Value::String(text) => *text = with_hidden_shown(text),
        Value::Array(items) => items.iter_mut().for_each(show_hidden_in),
        Value::Object(fields) => fields.values_mut().for_each(show_hidden_in),
        _ => {}
    }
}

/// A person's words on their way, waiting for the agent's next step.
#[derive(Deserialize)]
pub struct WordsWaiting {
    pub waiting: Vec<WaitingWords>,
}

#[derive(Deserialize)]
pub struct WaitingWords {
    request: Option<MessageId>,
    text: String,
}

#[derive(Serialize)]
struct Who {
    label: String,
    address: String,
    agent: SplintId,
    owner: SplintId,
    standing: Standing,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Standing {
    Contact,
    Blocked,
    /// In touch only because a reach setting let them in.
    NotInRules,
    /// Answering a link this owner made.
    Guest,
}

#[derive(Serialize)]
struct Exchange {
    request: MessageId,
    #[serde(rename = "type")]
    interaction: String,
    state: RequestState,
    other_side: &'static str,
    order: LineOrder,
    role: Side,
    with: Who,
    /// Everything waiting on this owner here, each its own yes to its own exact terms.
    to_sign: Vec<ToSign>,
    lines: Vec<Line>,
    may_write: bool,
    words_waiting: Vec<String>,
    last_at: u64,
    /// Where the owner's last answer to what's waiting wasn't used, in fixed words.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_used: Option<String>,
    /// The step of the card it goes on: the one that answer was for, or the first where that one no
    /// longer waits.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_used_on: Option<Operation>,
    /// A move the agent asked for that would commit the owner to a value, held until the other side's
    /// person sets up their controls, before anyone is asked to sign it.
    #[serde(skip_serializing_if = "Option::is_none")]
    held_for_their_controls: Option<StepKind>,
    /// Fields in its terms or result holding a number its type doesn't label as money, read here from
    /// the schema: a fact, never a hold.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    numbers_not_money: Vec<String>,
}

/// An interaction the agent wants to start, which nothing has signed.
#[derive(Serialize)]
struct Starting {
    request: MessageId,
    with: Who,
    to_sign: ToSign,
}

/// What the owner is asked to sign. `terms` goes back with a click, and has to match what's worked
/// out again at that moment, so nothing can be signed that wasn't on the screen.
#[derive(Serialize)]
pub struct ToSign {
    operation: Operation,
    version: u32,
    prev: MessageId,
    terms: splint_core::requests::Terms,
    /// The type's `units`: for each value measured in something, such as an amount, the field that
    /// says what, such as its currency.
    units: BTreeMap<String, String>,
    rows: Vec<Row>,
    can_set_subject: bool,
    hidden_text: bool,
    sign_by: u64,
    /// Which of the owner's own settings leaves this to them. The terminal doesn't say.
    left: Option<Left>,
    /// Who wants this step, and who asked for what it's on, in words worked out from the draft itself.
    asking: String,
    /// Who pays whom, and how much, if this goes through: fixed words from the type's `paid` and the
    /// signed terms, never from a field's name, which whoever proposed the type chose.
    pays: Vec<String>,
    /// What else waits on this owner on the same request, by step. A yes signs only its own draft.
    alongside: Vec<Operation>,
}

/// Why something waits for its owner, from the rules they signed, so the page names that setting
/// rather than asking as if Splint wanted something of them.
#[derive(Serialize)]
#[serde(tag = "is", rename_all = "snake_case")]
enum Left {
    AskMe,
    /// A step their agent asked for, or their own `confirm`, that would commit them to a value, which
    /// waits at every level.
    CommitsAValue,
    /// A price their agent quotes as the side that would be paid, which their `quoted_prices` setting
    /// has wait for them.
    QuotedPrice,
    /// A step their agent asked for with no value in it, held while their level was ask me.
    AskedAtAskMe,
    /// It carries a value, with someone their agent added that they haven't approved.
    NotApproved,
    NotAConfirm,
    /// With someone they haven't approved as a contact, which their delegate never answers for them.
    UnapprovedContact,
    /// Their settings let their device sign it, and it hasn't yet.
    DeviceMay,
    /// Its type isn't installed here, so nothing here signs it alone.
    UnknownType,
}

fn left_of(rules: &RulesDraft, schema: Option<&Schema>, draft: &ApprovalDraft) -> Left {
    let Some(schema) = schema else {
        return Left::UnknownType;
    };
    match rules
        .permissions
        .left_to_owner(schema, draft, rules.counterparty(draft))
    {
        Some(LeftToOwner::AskMe) => Left::AskMe,
        Some(LeftToOwner::CommitsAValue) => Left::CommitsAValue,
        Some(LeftToOwner::QuotedPrice) => Left::QuotedPrice,
        Some(LeftToOwner::AskedAtAskMe) => Left::AskedAtAskMe,
        Some(LeftToOwner::NotApproved) => Left::NotApproved,
        Some(LeftToOwner::NotAConfirm) => Left::NotAConfirm,
        None if !rules.delegate_may_answer_in(draft) => Left::UnapprovedContact,
        None => Left::DeviceMay,
    }
}

/// What's waiting, with the setting that leaves it to the owner. `contacts` are the rules' and those
/// the agent agreed with by itself, so neither reads as someone the owner doesn't know.
fn shown_to_owner(
    draft: ApprovalDraft,
    role: Side,
    schema: Option<&Schema>,
    owner: &SplintId,
    rules: &RulesDraft,
    contacts: &[RulesContact],
    them: &str,
) -> ToSign {
    let left = left_of(rules, schema, &draft);
    ToSign {
        left: Some(left),
        ..to_sign(draft, role, schema, owner, contacts, them)
    }
}

/// The contacts the owner's rules name, and after them each the agent agreed with by itself that they
/// don't, from the invite both agents signed, which the page checked. Those are let in by the rules'
/// `reach.agreed`, and named as agreed with, never as the owner's own.
pub fn with_agreed(contacts: &[RulesContact], invites: &[InviteWaiting]) -> Vec<RulesContact> {
    let agreed = invites
        .iter()
        .filter(|one| one.added_by_agent)
        .filter(|one| !contacts.iter().any(|known| known.agent == one.agent))
        .map(|one| RulesContact {
            agent: one.agent.clone(),
            address: one.address.clone(),
            label: one.address.clone(),
            status: ContactStatus::Allowed,
            types: Vec::new(),
            text: false,
            agree_types: false,
            pinned_by: PinnedBy::Agent,
        });
    contacts.iter().cloned().chain(agreed).collect()
}

/// What waits on one request, each told what else does, so an owner sees which yes signs which.
pub fn side_by_side(mut shown: Vec<ToSign>) -> Vec<ToSign> {
    let all: Vec<Operation> = shown.iter().map(|one| one.operation).collect();
    for one in &mut shown {
        one.alongside = all
            .iter()
            .copied()
            .filter(|operation| *operation != one.operation)
            .collect();
    }
    shown
}

#[derive(Serialize)]
pub struct Row {
    /// The row's name exactly as signed, which the page keeps one step away.
    name: String,
    /// The value exactly as signed, in UTC for a time.
    shown: String,
    /// The IDs behind a name, which are what's really signed.
    ids: Option<String>,
    /// Words someone chose, rather than a value from the type's own list.
    chosen: bool,
    /// What the value is, so the page can put it in plain words without guessing.
    shows: Shows,
    /// A field's own name, for the page to label it in words. Rows the page names itself have none.
    field: Option<String>,
    /// Whether the field is part of what was delivered, rather than what was agreed.
    delivered: bool,
    /// The times in a time field, for the page to show in the owner's own time zone.
    times: Vec<u64>,
    /// A field's name and value in words, for a terminal. The page words them itself, in terms.js.
    #[serde(skip)]
    in_words: Option<(String, String)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Shows {
    Type,
    Party,
    Number,
    /// A word from the type's own closed list.
    Word,
    Times,
    /// Words someone chose, shown exactly.
    Words,
    /// An earlier request this one replaces.
    Earlier,
    /// Shown as it is: a large number in a type that's missing, as both a date and a number.
    Plain,
}

impl Row {
    fn fixed(name: &str, shown: String, shows: Shows) -> Self {
        Self {
            name: name.to_owned(),
            shown,
            ids: None,
            chosen: false,
            shows,
            field: None,
            delivered: false,
            times: Vec::new(),
            in_words: None,
        }
    }

    fn chosen(name: &str, words: &str) -> Self {
        Self {
            chosen: true,
            ..Self::fixed(name, with_hidden_shown(words), Shows::Words)
        }
    }
}

/// The last words of a field's name that say its unit, as terms.js's UNITS has them.
const UNIT_WORDS: [&str; 12] = [
    "min", "mins", "minutes", "sec", "secs", "seconds", "hours", "days", "kb", "mb", "pct", "minor",
];

/// The currency a value is in: the word in the field its type's `units` names for it, from the
/// value's own fields first and then the offer's, as the owner's caps read it and terms.js's
/// `currencyOf` does, so the terminal names the same currency the pages do. None without a type.
fn currency_of(
    schema: Option<&Schema>,
    field: &str,
    fields: &Fields,
    agreed: &Fields,
) -> Option<String> {
    let unit = schema?.unit_of(field)?;
    match fields.get(unit).or_else(|| agreed.get(unit)) {
        Some(FieldValue::Text(code))
            if code.len() == 3 && code.chars().all(|c| c.is_ascii_alphabetic()) =>
        {
            Some(code.to_ascii_uppercase())
        }
        _ => None,
    }
}

fn capital(words: &str) -> String {
    let mut chars = words.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// A field's name in words, and the unit its last word names: `duration_min` is "Duration" in min.
fn field_label(name: &str) -> (String, Option<&str>) {
    let words: Vec<&str> = name.split('_').filter(|word| !word.is_empty()).collect();
    match words.split_last() {
        Some((last, rest)) if !rest.is_empty() && UNIT_WORDS.contains(last) => {
            (capital(&rest.join(" ")), Some(*last))
        }
        _ => (capital(&words.join(" ")), None),
    }
}

/// A number in words, with the unit its field's name says, and in `currency` where it's in minor units.
fn number_in_words(field: &str, number: u64, currency: Option<&str>) -> String {
    let shown = grouped(number);
    match (field_label(field).1, currency) {
        (Some("minor"), Some(code)) => money(number, code),
        (Some("minor"), None) => format!("{number} in minor units"),
        (Some("min" | "mins" | "minutes"), _) => format!("{shown} min"),
        (Some("sec" | "secs" | "seconds"), _) => format!("{shown} sec"),
        (Some("hours"), _) => format!("{shown} hr"),
        (Some("days"), _) if number == 1 => "1 day".to_owned(),
        (Some("days"), _) => format!("{shown} days"),
        (Some("kb"), _) => format!("{shown} KB"),
        (Some("mb"), _) => format!("{shown} MB"),
        (Some("pct"), _) => format!("{shown}%"),
        _ => shown,
    }
}

/// What a step does, as the owner reads it before signing, and its word.
fn operation_words(operation: Operation) -> (&'static str, &'static str) {
    match operation {
        Operation::Confirm => ("wants to agree to this", "confirm"),
        Operation::Cancel => ("wants to cancel this", "cancel"),
        Operation::Open => ("wants to start this", "open"),
        Operation::Counter => ("wants to offer this instead", "counter"),
        Operation::Accept => ("wants to accept this", "accept"),
        Operation::Deliver => ("wants to send this", "deliver"),
        Operation::OfferToGuest => (
            "wants to offer this to whoever holds your one-use link",
            "offer_to_guest",
        ),
    }
}

/// The word for a step that `splint approve ID STEP` takes.
pub fn step_word(operation: Operation) -> &'static str {
    operation_words(operation).1
}

/// Who wants this step and who asked for what it's on, from the draft itself: its `agent` makes the
/// step, which is always this owner's own agent, and its terms say which side asked. Prompts once named
/// the requester "Asked by" whichever side wanted the step, so a cancel the recipient's own agent
/// wanted read as the other side's. The other side is named as the owner's own contacts
/// name them, or else by `them`.
fn asking_words(draft: &ApprovalDraft, contacts: &[RulesContact], them: &str) -> String {
    let (wants, _) = operation_words(draft.operation);
    let terms = &draft.terms;
    let asked_by_mine = terms.requester.agent == draft.agent;
    let others = if asked_by_mine {
        &terms.recipient
    } else {
        &terms.requester
    };
    let them = if others.agent.is_guest() {
        "whoever holds your one-use link".to_owned()
    } else {
        contacts
            .iter()
            .find(|known| known.agent == others.agent)
            .map_or_else(|| them.to_owned(), |known| with_hidden_shown(&known.label))
    };
    match draft.operation {
        Operation::Open => format!("Your agent {wants} with {them}"),
        Operation::OfferToGuest => format!("Your agent {wants}"),
        _ if asked_by_mine => format!("Your agent {wants}, which it asked {them} for"),
        _ => format!("Your agent {wants}, which {them} asked for"),
    }
}

/// Who pays whom in these terms, as "You pay 40.00 USD to ben~host" or "ben~host pays you 40.00 USD".
/// The side comes from the type's `paid` and the amount from the signed terms, so a counterparty who
/// names a field "refund_to_you" can't make paying them read as being paid. The other side is named
/// by their address, which their agent can't choose as it can a label.
fn paying_words(
    draft: &ApprovalDraft,
    role: Side,
    schema: Option<&Schema>,
    contacts: &[RulesContact],
    them: &str,
) -> Vec<String> {
    let Some(schema) = schema else {
        return Vec::new();
    };
    let terms = &draft.terms;
    let others = match role {
        Side::Requester => &terms.recipient,
        Side::Recipient => &terms.requester,
    };
    let them = if others.agent.is_guest() {
        "whoever holds your one-use link".to_owned()
    } else {
        contacts
            .iter()
            .find(|known| known.agent == others.agent)
            .map_or_else(
                || them.to_owned(),
                |known| with_hidden_shown(&known.address),
            )
    };
    let paying = paying_in(terms, schema);
    let several = paying.len() > 1;
    paying
        .into_iter()
        .map(|paying| {
            let amount = amount_words(&paying.value, paying.amount, paying.unit.as_deref());
            let what = if several {
                format!(", for {}", field_label(&with_hidden_shown(&paying.value)).0)
            } else {
                String::new()
            };
            if paying.to == role {
                format!("{them} pays you {amount}{what}")
            } else {
                format!("You pay {amount} to {them}{what}")
            }
        })
        .collect()
}

/// An amount to pay, in its currency where its unit is one, and with its unit's word where that isn't.
fn amount_words(value: &str, amount: u64, unit: Option<&str>) -> String {
    let currency = unit
        .filter(|code| code.len() == 3 && code.chars().all(|c| c.is_ascii_alphabetic()))
        .map(str::to_ascii_uppercase);
    let shown = number_in_words(value, amount, currency.as_deref());
    match (field_label(value).1, currency, unit) {
        (Some("minor"), Some(_), _) => shown,
        (Some("minor"), None, Some(word)) => format!(
            "{} in minor units of {}",
            grouped(amount),
            with_hidden_shown(word)
        ),
        (_, Some(code), _) => format!("{shown} {code}"),
        (_, None, Some(word)) => format!("{shown} {}", with_hidden_shown(word)),
        (_, None, None) => shown,
    }
}

fn field_rows(
    delivered: bool,
    fields: &Fields,
    schema: Option<&Schema>,
    agreed: &Fields,
) -> Vec<Row> {
    let prefix = if delivered { "Delivered: " } else { "" };
    fields
        .iter()
        .map(|(field, value)| {
            let name = format!("{prefix}{}", with_hidden_shown(field));
            let is_time = schema.is_some_and(|schema| schema.is_time_field(field));
            let row = match value {
                FieldValue::Int(number) if is_time => Row {
                    times: vec![*number],
                    ..Row::fixed(&name, utc_time(*number), Shows::Times)
                },
                // A type that's missing doesn't say a number is a date, so a large one shows both ways.
                FieldValue::Int(number) if schema.is_none() && *number >= EARLIEST_TIME_SHOWN => {
                    Row::fixed(
                        &name,
                        format!("{} ({number})", utc_time(*number)),
                        Shows::Plain,
                    )
                }
                FieldValue::Int(number) => Row::fixed(&name, number.to_string(), Shows::Number),
                // A word from the type's own list is no one's choice of words. A schema that's
                // missing says nothing, so what's in it counts as chosen.
                FieldValue::Text(text)
                    if schema.is_some_and(|schema| schema.is_word_field(field))
                        && !has_hidden_characters(text) =>
                {
                    Row::fixed(&name, text.clone(), Shows::Word)
                }
                FieldValue::Text(text) => Row::chosen(&name, text),
                FieldValue::Times(times) => {
                    let shown: Vec<String> = times.iter().map(|time| utc_time(*time)).collect();
                    Row {
                        times: times.clone(),
                        ..Row::fixed(&name, shown.join(", "), Shows::Times)
                    }
                }
            };
            let currency = currency_of(schema, field, fields, agreed);
            let field = with_hidden_shown(field);
            let value = match (value, row.shows) {
                (FieldValue::Int(number), Shows::Number) => {
                    number_in_words(&field, *number, currency.as_deref())
                }
                (_, Shows::Word) => capital(&row.shown.replace('_', " ")),
                _ => row.shown.clone(),
            };
            Row {
                in_words: Some((format!("{prefix}{}", field_label(&field).0), value)),
                field: Some(field),
                delivered,
                ..row
            }
        })
        .collect()
}

fn party_row(name: &str, party: &TermsParty, owner: &SplintId, contacts: &[RulesContact]) -> Row {
    let who = if &party.owner == owner {
        "You".to_owned()
    } else if party.agent.is_guest() {
        "Whoever holds your one-use link".to_owned()
    } else {
        match contacts.iter().find(|known| known.agent == party.agent) {
            Some(known) if known.pinned_by == PinnedBy::Agent => {
                format!(
                    "{}, a contact your agent agreed with",
                    with_hidden_shown(&known.label)
                )
            }
            Some(known) if known.status == ContactStatus::Allowed => {
                format!("{}, from your contacts", with_hidden_shown(&known.label))
            }
            Some(known) => format!("{}, BLOCKED by you", with_hidden_shown(&known.label)),
            None => "NOT IN YOUR CONTACTS".to_owned(),
        }
    };
    Row {
        ids: Some(format!("Agent {}, owner {}", party.agent, party.owner)),
        ..Row::fixed(name, who, Shows::Party)
    }
}

impl ToSign {
    /// What's on the screen, as lines for a terminal. Everything here was written with what could hide
    /// words shown as its code, and a person's or agent's words say so.
    pub fn lines(&self) -> String {
        let mut out = String::new();
        let (_, step) = operation_words(self.operation);
        let _ = writeln!(
            out,
            "    {} ({step}, version {})",
            self.asking, self.version
        );
        for pays in &self.pays {
            let _ = writeln!(out, "    {pays}.");
        }
        if !self.alongside.is_empty() {
            let others: Vec<&str> = self.alongside.iter().map(|one| step_word(*one)).collect();
            let _ = writeln!(
                out,
                "    Also waiting on this, as its own yes: {}. Yes to this signs only this {step}, \
                 and what else waits is then set aside.",
                others.join(", "),
            );
        }
        for row in &self.rows {
            let chosen = if row.chosen {
                " (someone's own words)"
            } else {
                ""
            };
            match (&row.in_words, &row.field) {
                (Some((label, value)), Some(field)) => {
                    let _ = writeln!(out, "    {label}: {value}{chosen}");
                    // A number put in other words, such as an amount in its currency, has what's
                    // signed one line away, as Exact terms on a page.
                    if row.shows == Shows::Number && *value != row.shown {
                        let _ = writeln!(out, "      as signed: {field} = {}", row.shown);
                    }
                }
                _ => {
                    let _ = writeln!(out, "    {}: {}{chosen}", row.name, row.shown);
                }
            }
            if let Some(ids) = &row.ids {
                let _ = writeln!(out, "      {ids}");
            }
        }
        if self.hidden_text {
            let _ = writeln!(
                out,
                "    It holds text that can't all be shown, so it can't be approved."
            );
        }
        out
    }
}

pub fn to_sign(
    draft: ApprovalDraft,
    role: Side,
    schema: Option<&Schema>,
    owner: &SplintId,
    contacts: &[RulesContact],
    them: &str,
) -> ToSign {
    let asking = asking_words(&draft, contacts, them);
    let pays = paying_words(&draft, role, schema, contacts, them);
    let terms = &draft.terms;
    // Who asked for this and who was asked, which says nothing about who wants this step.
    let mut rows = vec![
        Row::fixed("Type", terms.interaction.as_str().to_owned(), Shows::Type),
        party_row("Requester", &terms.requester, owner, contacts),
        party_row("Recipient", &terms.recipient, owner, contacts),
    ];
    rows.extend(field_rows(false, &terms.agreed, schema, &terms.agreed));
    rows.extend(field_rows(true, &terms.result, schema, &terms.agreed));
    // So the page reads each amount's currency as this does.
    let units = schema.map_or_else(BTreeMap::new, |schema| {
        schema
            .values()
            .filter_map(|value| Some((value.to_owned(), schema.unit_of(value)?.to_owned())))
            .collect()
    });
    if let Some(subject) = &terms.subject {
        rows.push(Row::chosen("Subject", subject));
    }
    if let Some(note) = &terms.note {
        rows.push(Row::chosen("Note", note));
    }
    if let Some(earlier) = &terms.supersedes {
        rows.push(Row::fixed(
            "Replaces",
            earlier.as_str().to_owned(),
            Shows::Earlier,
        ));
    }
    ToSign {
        hidden_text: terms.hides_text(),
        can_set_subject: can_set_subject(draft.operation, role),
        rows,
        operation: draft.operation,
        version: draft.version,
        prev: draft.prev,
        sign_by: draft.latest_expiry,
        terms: draft.terms,
        units,
        left: None,
        asking,
        pays,
        alongside: Vec::new(),
    }
}

/// A subject is for the requester's owner to set, and the other owner signs it as it stands.
pub fn can_set_subject(operation: Operation, role: Side) -> bool {
    operation == Operation::Confirm && role == Side::Requester
}

fn who(walked: &Walked, contacts: &[RulesContact]) -> Who {
    let mut who = who_is(
        &walked.them,
        &walked.their_owner,
        &walked.their_address,
        contacts,
    );
    if walked.guest {
        who.standing = Standing::Guest;
    }
    who
}

fn who_is(
    them: &SplintId,
    their_owner: &SplintId,
    their_address: &str,
    contacts: &[RulesContact],
) -> Who {
    let known = contacts.iter().find(|known| known.agent == *them);
    let (label, address, standing) = match known {
        Some(known) => (
            known.label.as_str(),
            known.address.as_str(),
            if known.status == ContactStatus::Allowed {
                Standing::Contact
            } else {
                Standing::Blocked
            },
        ),
        None => (their_address, their_address, Standing::NotInRules),
    };
    Who {
        label: with_hidden_shown(label),
        address: with_hidden_shown(address),
        agent: them.clone(),
        owner: their_owner.clone(),
        standing,
    }
}

fn is_over(state: RequestState) -> bool {
    matches!(
        state,
        RequestState::Completed
            | RequestState::Declined
            | RequestState::Cancelled
            | RequestState::Disputed
            | RequestState::Expired
    )
}

fn exchange(
    walked: &Walked,
    my_address: &str,
    owner: &SplintId,
    rules: &RulesDraft,
    known: &[RulesContact],
    words: &[WaitingWords],
    now: u64,
) -> Option<Exchange> {
    let with = who(walked, &rules.contacts);
    let schema = walked.chain.interaction_schema();
    let (requester, recipient) = match walked.role {
        Side::Requester => (my_address, with.address.as_str()),
        Side::Recipient => (with.address.as_str(), my_address),
    };
    let reader = Reader {
        side: walked.role,
        audience: Audience::Owner,
        requester,
        recipient,
    };
    let Dialogue {
        interaction,
        state,
        other_side,
        order,
        lines,
        ..
    } = walked.chain.dialogue(reader, now)?;
    let to_sign = side_by_side(
        walked
            .drafts(now)
            .into_iter()
            .map(|draft| {
                shown_to_owner(draft, walked.role, schema, owner, rules, known, &with.label)
            })
            .collect(),
    );
    let (not_used_on, not_used) = walked.not_used_beside(now).unzip();
    let numbers_not_money = schema
        .map(|schema| numbers_not_money(schema, &walked.chain))
        .unwrap_or_default();
    Some(Exchange {
        numbers_not_money,
        request: walked.request.clone(),
        interaction: interaction.as_str().to_owned(),
        state,
        other_side,
        order,
        role: walked.role,
        may_write: with.standing == Standing::Contact && !is_over(state),
        with,
        to_sign,
        not_used,
        not_used_on,
        held_for_their_controls: walked.held_for_their_controls(now),
        // A date is only its signer's claim, so a future one can't keep an exchange at the top.
        last_at: lines
            .iter()
            .map(|line| line.at)
            .filter(|at| *at <= now)
            .max()
            .unwrap_or_default(),
        lines,
        words_waiting: words
            .iter()
            .filter(|words| words.request.as_ref() == Some(&walked.request))
            .map(|words| with_hidden_shown(&words.text))
            .collect(),
    })
}

/// Each field holding a number the type doesn't label as money, in the terms or the result, once.
fn numbers_not_money(schema: &Schema, chain: &splint_core::requests::Chain) -> Vec<String> {
    let mut found: Vec<String> = [chain.offer(), chain.pick(), chain.result()]
        .into_iter()
        .flat_map(|fields| schema.numbers_not_money_in(fields))
        .map(with_hidden_shown)
        .collect();
    found.sort();
    found.dedup();
    found
}

/// The kinds with currency agreed with someone the owner's agent deals with, which the owner hasn't
/// approved for them, each with what a person must see to approve it. `everyone` is the contacts the
/// owner's rules name.
fn kinds_waiting(kinds: &[(SplintId, Schema)], everyone: &[RulesContact]) -> Vec<KindWaiting> {
    let all: Vec<&InteractionType> = kinds.iter().map(|(_, schema)| schema.name()).collect();
    kinds
        .iter()
        .filter(|(_, schema)| schema.includes_currency())
        .filter_map(|(agent, schema)| {
            let contact = everyone.iter().find(|contact| {
                &contact.agent == agent && contact.status == ContactStatus::Allowed
            })?;
            (!contact.types.contains(schema.name())).then(|| KindWaiting {
                agent: agent.clone(),
                label: with_hidden_shown(&contact.label),
                kind: for_approval(schema, crate::examples::shipped(), all.iter().copied()),
            })
        })
        .collect()
}

/// Sealed unless both owners chose unsealed. What the contact chose comes from what its Signet signed,
/// and the reader's Signet says what that was.
fn sealing_of(mine: Sealing, theirs: Option<Sealing>) -> (bool, &'static str) {
    let sealed = Sealing::between(mine, theirs) == Sealing::Sealed;
    let why = match (mine, theirs) {
        (Sealing::Sealed, _) => "You chose sealed.",
        (Sealing::Unsealed, Some(Sealing::Sealed)) => {
            "They chose sealed, so it's sealed both ways."
        }
        (Sealing::Unsealed, None) => "Sealed until they say they chose unsealed too.",
        (Sealing::Unsealed, Some(Sealing::Unsealed)) => {
            "You both chose unsealed, so both hosts can read it."
        }
    };
    (sealed, why)
}

fn contact_view(contact: &RulesContact, mine: Sealing, theirs: Option<Sealing>) -> ContactView {
    let (sealed, sealed_why) = sealing_of(mine, theirs);
    ContactView {
        sealed,
        sealed_why,
        agent: contact.agent.clone(),
        address: with_hidden_shown(&contact.address),
        label: with_hidden_shown(&contact.label),
        blocked: contact.status == ContactStatus::Blocked,
        never_a_contact: was_never_a_contact(contact),
        types: contact
            .types
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        text: contact.text,
        invited: contact.pinned_by == PinnedBy::Invite,
    }
}

fn strangers(held: &[Held]) -> Vec<Stranger> {
    let mut found: BTreeMap<&str, Stranger> = BTreeMap::new();
    for message in held
        .iter()
        .filter(|message| message.kind != "invite" && message.kind != "agreed")
    {
        let stranger = found
            .entry(message.sender.as_str())
            .or_insert_with(|| Stranger {
                agent: message.sender.clone(),
                owner: None,
                claims: None,
                messages: 0,
                steps: 0,
                asked: false,
                disagreed: false,
                first_at: message.created_at,
                last_at: message.created_at,
            });
        match message.kind.as_str() {
            "step" => stranger.steps = stranger.steps.saturating_add(1),
            "asked" => stranger.asked = true,
            "disagreed" => stranger.disagreed = true,
            _ => stranger.messages = stranger.messages.saturating_add(1),
        }
        stranger.first_at = stranger.first_at.min(message.created_at);
        stranger.last_at = stranger.last_at.max(message.created_at);
        if stranger.claims.is_none() {
            stranger.owner.clone_from(&message.sender_owner);
            stranger.claims = message.address.as_deref().map(with_hidden_shown);
        }
    }
    found.into_values().collect()
}

fn types_of(schemas: &Schemas) -> Vec<TypeView> {
    schemas
        .all()
        .map(|schema| TypeView {
            name: schema.name().as_str().to_owned(),
            values: schema.cap_names(),
            link_fields: schema
                .can_go_to_a_guest()
                .then(|| schema.offer_rules().clone()),
        })
        .collect()
}

fn standing_of(signed: &Signed, now: u64) -> RulesStanding {
    let ends_at = signed.draft.ends_at;
    RulesStanding {
        signed_at: signed.signed_at,
        ends_at,
        ended: ends_at.is_some_and(|end| now >= end),
    }
}

pub fn settings_of(draft: &RulesDraft) -> Settings {
    Settings {
        paused: draft.paused,
        reach: draft.reach.clone(),
        permissions: draft.permissions.clone(),
        changes: draft.changes,
        sealing: draft.sealing,
    }
}

/// Everything the page reads this time round.
pub struct Read {
    pub address: String,
    pub agent: SplintId,
    pub elsewhere: bool,
    pub heard_at: Option<u64>,
    pub owner: Identity,
    pub signed: Signed,
    pub walked: WalkedAll,
    pub held: Option<Vec<Held>>,
    pub changes: Notices,
    pub words: WordsWaiting,
    pub refused: Option<Refusals>,
    pub links: Vec<SavedLink>,
    pub usage: Vec<UsageLine>,
    /// Each type the Signet says it agreed, with whom, and the contacts the owner's rules name.
    pub kinds: Vec<(SplintId, Schema)>,
    pub everyone: Vec<RulesContact>,
}

fn link_views(saved: Vec<SavedLink>, walked: &[Walked], now: u64) -> Vec<LinkView> {
    saved
        .into_iter()
        .map(|saved| {
            let state = walked
                .iter()
                .find(|walked| walked.request == saved.request)
                .map(|walked| walked.chain.state_at(now));
            LinkView { saved, state }
        })
        .collect()
}

fn refused_lines(refused: Option<Refusals>) -> (Vec<RefusedLine>, bool) {
    let Some(refused) = refused else {
        return (Vec::new(), true);
    };
    let mut lines: Vec<RefusedLine> = refused
        .refused
        .into_iter()
        .map(|line| RefusedLine {
            at: line.at,
            by: "signet",
            way: line.way,
            call: line.call,
            from: line.from,
            reason: line.reason,
            count: i64::from(line.count),
        })
        .chain(refused.at_host.into_iter().map(|line| RefusedLine {
            at: line.at,
            by: "host",
            way: line.way,
            call: None,
            from: line.from,
            reason: line.reason,
            count: line.count,
        }))
        .collect();
    lines.sort_by_key(|line| std::cmp::Reverse(line.at));
    (lines, refused.host_unknown)
}

pub fn page_state(read: Read, schemas: &Schemas, now: u64) -> Result<PageState, Failure> {
    let rules = &read.signed.draft;
    let contacts = &rules.contacts;
    let owner = read.owner.id();
    let invites = read
        .held
        .as_deref()
        .map(|held| invites_waiting(held, &read.agent))
        .unwrap_or_default();
    let known = with_agreed(contacts, &invites);
    let mut exchanges: Vec<Exchange> = read
        .walked
        .walked
        .iter()
        .filter_map(|walked| {
            exchange(
                walked,
                &read.address,
                owner,
                rules,
                &known,
                &read.words.waiting,
                now,
            )
        })
        .collect();
    // What needs a signature can't fall off the end, and the rest goes newest first.
    exchanges.sort_by_key(|exchange| {
        (
            exchange.to_sign.is_empty(),
            u64::MAX.saturating_sub(exchange.last_at),
        )
    });
    let starting = read
        .walked
        .starting
        .iter()
        .filter_map(|open| {
            let draft = open.draft(now)?;
            let schema = open.schema(schemas);
            let with = who_is(&open.them, &open.their_owner, &open.their_address, contacts);
            Some(Starting {
                request: draft.request.clone(),
                to_sign: shown_to_owner(
                    draft,
                    Side::Requester,
                    schema.as_deref(),
                    owner,
                    rules,
                    &known,
                    &with.label,
                ),
                with,
            })
        })
        .collect();
    let exchanges_left_out = exchanges
        .len()
        .saturating_sub(MAX_EXCHANGES_SHOWN)
        .saturating_add(read.walked.left_out);
    exchanges.truncate(MAX_EXCHANGES_SHOWN);
    let (refused, refused_unknown) = refused_lines(read.refused);
    Ok(PageState {
        kinds: kinds_waiting(&read.kinds, &read.everyone),
        links: link_views(read.links, &read.walked.walked, now),
        refused,
        refused_unknown,
        me: Me {
            line: line_for(&read.address, &read.agent),
            address: read.address.clone(),
            agent: read.agent.clone(),
        },
        rules: standing_of(&read.signed, now),
        settings: settings_of(&read.signed.draft),
        risky: crate::rules::risky_settings(&read.signed.draft),
        usage: read
            .usage
            .into_iter()
            .map(|line| UsageLine {
                address: with_hidden_shown(&line.address),
                ..line
            })
            .collect(),
        types: types_of(schemas),
        contacts: contacts
            .iter()
            .map(|contact| {
                let theirs = read
                    .walked
                    .their_sealing
                    .get(contact.agent.as_str())
                    .copied();
                contact_view(contact, read.signed.draft.sealing, theirs)
            })
            .collect(),
        waiting_unknown: read.held.is_none(),
        waiting: read.held.as_deref().map(strangers).unwrap_or_default(),
        invites,
        changes: read
            .changes
            .changes
            .into_iter()
            .map(Notice::for_reading)
            .collect(),
        starting,
        exchanges,
        exchanges_left_out,
        unreadable: read.walked.unreadable,
        elsewhere: read.elsewhere,
        heard_at: read.heard_at,
        max_subject_chars: MAX_SUBJECT_CHARS,
        max_words_chars: MAX_WORDS_CHARS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms(fields: Fields, subject: Option<&str>) -> splint_core::requests::Terms {
        let party = TermsParty {
            agent: serde_json::from_value(Value::String(format!("splint1{}", "a".repeat(64))))
                .unwrap(),
            owner: serde_json::from_value(Value::String(format!("splint1{}", "b".repeat(64))))
                .unwrap(),
        };
        splint_core::requests::Terms {
            interaction: Schema::parse(include_bytes!("../../../../spec/schemas/quote-1.json"))
                .unwrap()
                .name()
                .clone(),
            requester: party.clone(),
            recipient: party,
            agreed: fields,
            result: Fields::new(),
            subject: subject.map(str::to_owned),
            note: None,
            supersedes: None,
        }
    }

    #[test]
    fn terms_with_words_someone_cant_see_are_caught_wherever_they_are() {
        let plain = Fields::from([("item".to_owned(), FieldValue::Text("venue".to_owned()))]);
        assert!(!terms(plain.clone(), Some("Q4 plan")).hides_text());
        assert!(terms(plain, Some("pay \u{202e}tneve")).hides_text());
        let hidden = Fields::from([(
            "item".to_owned(),
            FieldValue::Text("venue\u{200b}".to_owned()),
        )]);
        assert!(terms(hidden, None).hides_text());
    }

    #[test]
    fn a_hidden_character_shows_as_its_code_in_what_a_person_reads() {
        let rows = field_rows(
            false,
            &Fields::from([("item".to_owned(), FieldValue::Text("a\u{202e}b".to_owned()))]),
            None,
            &Fields::new(),
        );
        let shown = &rows.first().unwrap().shown;
        assert!(!shown.contains('\u{202e}'));
        assert!(shown.contains("202e"), "{shown}");
    }

    #[test]
    fn a_large_number_reads_as_a_date_as_well() {
        let rows = field_rows(
            false,
            &Fields::from([("start".to_owned(), FieldValue::Int(1_793_750_400))]),
            None,
            &Fields::new(),
        );
        let shown = &rows.first().unwrap().shown;
        assert!(
            shown.contains("2026-11-04") && shown.contains("1793750400"),
            "{shown}"
        );
    }

    #[test]
    fn a_type_says_which_numbers_are_times() {
        let meeting =
            Schema::parse(include_bytes!("../../../../spec/schemas/meeting-1.json")).unwrap();
        let picked = field_rows(
            false,
            &Fields::from([("start".to_owned(), FieldValue::Int(1_793_750_400))]),
            Some(&meeting),
            &Fields::new(),
        );
        let picked = picked.first().unwrap();
        assert!(picked.shows == Shows::Times && picked.times == [1_793_750_400]);
        let quote = Schema::parse(include_bytes!("../../../../spec/schemas/quote-1.json")).unwrap();
        let amount = field_rows(
            true,
            &Fields::from([("amount_minor".to_owned(), FieldValue::Int(1_793_750_400))]),
            Some(&quote),
            &Fields::new(),
        );
        let amount = amount.first().unwrap();
        assert!(amount.shows == Shows::Number && amount.shown == "1793750400");
        assert!(amount.delivered && amount.times.is_empty());
    }

    /// Bugs caught: a price in cents read as dollars, a fraction losing its leading zero, so 5 cents
    /// reads as 0.5, and a currency of other digits, or none known, read as if it had two.
    #[test]
    fn an_amount_reads_in_its_currencys_own_digits() {
        let cases = [
            (500_000, "USD", "5,000.00 USD"),
            (1_234_505, "USD", "12,345.05 USD"),
            (5, "EUR", "0.05 EUR"),
            (1_500, "JPY", "1,500 JPY"),
            (1_005, "KWD", "1.005 KWD"),
            (u64::MAX, "USD", "184,467,440,737,095,516.15 USD"),
            (500_000, "XYZ", "500000 in minor units of XYZ"),
        ];
        for (minor, code, read) in cases {
            assert_eq!(money(minor, code), read);
        }
    }

    /// Review of issue 729. Bugs caught: an amount read in the field called `currency` whatever the
    /// type's `units` say, so a payout of 100,000 yen read as 1,000.00 dollars; and a delivered amount
    /// in euros read in dollars.
    #[test]
    fn a_delivered_amount_reads_in_the_currency_its_type_names() {
        let payout = Schema::parse(
            br#"{"type":"payout/1","kind":"request",
            "offer":{"currency":{"word":["usd"]},"payout_currency":{"word":["jpy"]}},
            "fixed":["currency","payout_currency"],
            "result":{"amount_minor":{"range":{"min":0,"max":100000000000}},
                      "payout_minor":{"range":{"min":0,"max":100000000000}}},
            "values":["amount_minor","payout_minor"],
            "units":{"amount_minor":"currency","payout_minor":"payout_currency"},
            "sign":"requester"}"#,
        )
        .unwrap();
        let quote = Schema::parse(include_bytes!("../../../../spec/schemas/quote-1.json")).unwrap();
        let text = |word: &str| FieldValue::Text(word.to_owned());
        let cases = [
            (
                &payout,
                [("currency", text("usd")), ("payout_currency", text("jpy"))],
                [("amount_minor", 90_000), ("payout_minor", 100_000)],
                [
                    "Delivered: Amount: 900.00 USD",
                    "Delivered: Payout: 100,000 JPY",
                ],
            ),
            (
                &quote,
                [("currency", text("eur")), ("item", text("venue"))],
                [("amount_minor", 90_000), ("valid_days", 14)],
                ["Delivered: Amount: 900.00 EUR", "Delivered: Valid: 14 days"],
            ),
        ];
        for (schema, agreed, result, read) in cases {
            let mut priced = terms(
                agreed
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value))
                    .collect(),
                None,
            );
            priced.interaction = schema.name().clone();
            priced.result = result
                .into_iter()
                .map(|(name, number)| (name.to_owned(), FieldValue::Int(number)))
                .collect();
            let draft = ApprovalDraft {
                owner: priced.requester.owner.clone(),
                agent: priced.requester.agent.clone(),
                operation: Operation::Confirm,
                request: serde_json::from_value(Value::String("a".repeat(64))).unwrap(),
                version: 1,
                prev: serde_json::from_value(Value::String("b".repeat(64))).unwrap(),
                terms: priced,
                latest_expiry: 0,
            };
            let owner = draft.owner.clone();
            let lines = to_sign(draft, Side::Requester, Some(schema), &owner, &[], "ben").lines();
            for line in read {
                assert!(lines.contains(line), "{line} in {lines}");
            }
        }
    }

    /// Security review, finding 6. Bug caught: who pays whom read only from a field's name, which
    /// whoever proposed the type chose, so a price the owner would pay, named "refund_to_you", read as
    /// money coming to them.
    #[test]
    fn who_pays_whom_is_said_from_the_types_paid_and_never_a_fields_name() {
        let refund = Schema::parse(
            br#"{"type":"refund/1","kind":"request",
            "offer":{"currency":{"word":["usd"]}},
            "fixed":["currency"],
            "result":{"refund_to_you_minor":{"range":{"min":0,"max":100000000000}}},
            "values":["refund_to_you_minor"],
            "units":{"refund_to_you_minor":"currency"},
            "paid":{"refund_to_you_minor":"recipient"},
            "sign":"requester"}"#,
        )
        .unwrap();
        let mut priced = terms(
            Fields::from([("currency".to_owned(), FieldValue::Text("usd".to_owned()))]),
            None,
        );
        priced.interaction = refund.name().clone();
        priced.result = Fields::from([("refund_to_you_minor".to_owned(), FieldValue::Int(4_000))]);
        let draft = ApprovalDraft {
            owner: priced.requester.owner.clone(),
            agent: priced.requester.agent.clone(),
            operation: Operation::Confirm,
            request: serde_json::from_value(Value::String("a".repeat(64))).unwrap(),
            version: 1,
            prev: serde_json::from_value(Value::String("b".repeat(64))).unwrap(),
            terms: priced,
            latest_expiry: 0,
        };
        let owner = draft.owner.clone();
        let read = |role| {
            to_sign(
                draft.clone(),
                role,
                Some(&refund),
                &owner,
                &[],
                "ben~host.example",
            )
            .lines()
        };
        let paying = read(Side::Requester);
        assert!(
            paying.contains("You pay 40.00 USD to ben~host.example."),
            "{paying}"
        );
        assert!(!paying.contains("pays you"), "{paying}");
        let paid = read(Side::Recipient);
        assert!(
            paid.contains("ben~host.example pays you 40.00 USD."),
            "{paid}"
        );
    }

    /// Issue 703. Bug caught: a yes waiting on a contact the agent agreed with by invite saying NOT IN
    /// YOUR CONTACTS on the owner's page, as only the rules' contacts were passed to it, so an owner
    /// read someone their own setting let in as a stranger.
    #[test]
    fn a_yes_with_a_contact_the_agent_agreed_with_names_them_so() {
        let quote = Schema::parse(include_bytes!("../../../../spec/schemas/quote-1.json")).unwrap();
        let rules = crate::rules::first_rules();
        let mut priced = terms(Fields::new(), None);
        let them: SplintId =
            serde_json::from_value(Value::String(format!("splint1{}", "e".repeat(64)))).unwrap();
        priced.recipient.agent = them.clone();
        priced.recipient.owner =
            serde_json::from_value(Value::String(format!("splint1{}", "f".repeat(64)))).unwrap();
        let draft = ApprovalDraft {
            owner: priced.requester.owner.clone(),
            agent: priced.requester.agent.clone(),
            operation: Operation::Confirm,
            request: serde_json::from_value(Value::String("a".repeat(64))).unwrap(),
            version: 1,
            prev: serde_json::from_value(Value::String("b".repeat(64))).unwrap(),
            terms: priced,
            latest_expiry: 0,
        };
        let agreed = InviteWaiting {
            agent: them,
            address: "kit~host.example".to_owned(),
            invited_by_us: true,
            added_by_agent: true,
            at: 0,
        };
        let known = with_agreed(&rules.contacts, std::slice::from_ref(&agreed));
        let owner = draft.owner.clone();
        let lines = shown_to_owner(
            draft,
            Side::Requester,
            Some(&quote),
            &owner,
            &rules,
            &known,
            "kit~host.example",
        )
        .lines();
        assert!(!lines.contains("NOT IN YOUR CONTACTS"), "{lines}");
        assert!(
            lines.contains("kit~host.example, a contact your agent agreed with"),
            "{lines}"
        );
    }

    /// Bugs caught: the page telling an owner their device may sign something by itself with someone
    /// their agent added, when it waits for them, so they don't know why it waits or what to do. A
    /// price waits as one with someone they haven't approved, and a meeting because their delegate
    /// never answers for such a contact.
    #[test]
    fn something_with_someone_the_agent_added_says_why_it_waits_for_the_owner() {
        let quote = Schema::parse(include_bytes!("../../../../spec/schemas/quote-1.json")).unwrap();
        let mut rules = crate::rules::first_rules();
        rules.permissions.level = splint_core::rules::Level::FullAuto;
        rules.reach.agreed = Some(splint_core::rules::Agreed {
            types: vec![quote.name().clone()],
            text: true,
            agree_types: true,
        });
        let price = Fields::from([("amount_minor".to_owned(), FieldValue::Int(100))]);
        for (result, why) in [
            (price, "not_approved"),
            (Fields::new(), "unapproved_contact"),
        ] {
            let mut agreed = terms(Fields::new(), None);
            agreed.result = result;
            let me: SplintId =
                serde_json::from_value(Value::String(format!("splint1{}", "c".repeat(64))))
                    .unwrap();
            agreed.recipient.agent = me.clone();
            // Someone else's agent: another agent of this same owner counts as approved.
            agreed.requester.owner =
                serde_json::from_value(Value::String(format!("splint1{}", "d".repeat(64))))
                    .unwrap();
            let draft = ApprovalDraft {
                owner: agreed.recipient.owner.clone(),
                agent: me,
                operation: Operation::Confirm,
                request: serde_json::from_value(Value::String("a".repeat(64))).unwrap(),
                version: 1,
                prev: serde_json::from_value(Value::String("b".repeat(64))).unwrap(),
                terms: agreed,
                latest_expiry: 0,
            };
            let owner = draft.owner.clone();
            let shown = shown_to_owner(
                draft,
                Side::Recipient,
                Some(&quote),
                &owner,
                &rules,
                &rules.contacts,
                "ben",
            );
            let said = serde_json::to_value(&shown).unwrap();
            assert_eq!(said["left"]["is"], why);
        }
    }
}

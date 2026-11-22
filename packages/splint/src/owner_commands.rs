//! What an owner can do from a terminal without knowing `owner-key` or the Signet API: read what's
//! waiting, say yes or no to exact terms, say yes to a contact's change, and write as a person. It's the
//! same as the owner's page: everything shown is worked out here from what's signed, and nothing is
//! signed until someone at this terminal has read it and typed yes. A closed stdin never does.

use std::fmt::Write as _;

use splint_core::requests::{
    Decision, PaymentAsk, PaymentStatus, Place, Side, StepKind, Word, amount_in_words,
    has_hidden_characters, warnings_for, with_hidden_shown,
};
use splint_core::{Identity, MessageId, SplintId, parse_address, unix_now};

use crate::authorize::{YES, answer, say};
use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::owner_key::OwnerKey;
use crate::owner_side::{OwnerSide, OwnerSigned};
use crate::page::state::{
    MAX_SUBJECT_CHARS, MAX_WORDS_CHARS, Notice, ToSign, UsageLine, can_set_subject, side_by_side,
    step_word, to_sign,
};
use crate::page::walk::{WalkedAll, walk_all};

/// What a person types of a request's ID, and what's shown for it.
const SHORT_ID_CHARS: usize = 12;
const SUBJECT: &str = "--subject";

/// The commands here, or `None` for anything else. `named` is the agent an owner's device was told to
/// look at, from `splint for HANDLE~HOST`.
pub async fn run(
    home: &Home,
    named: Option<&str>,
    words: &[&str],
) -> Result<Option<String>, Failure> {
    Ok(Some(match words {
        ["waiting"] => waiting(home, named).await?,
        ["approve", request] => decide(home, named, request, None, Decision::Approve, None).await?,
        ["approve", request, SUBJECT, subject] => {
            decide(home, named, request, None, Decision::Approve, Some(subject)).await?
        }
        ["approve", request, step] => {
            decide(home, named, request, Some(step), Decision::Approve, None).await?
        }
        ["approve", request, step, SUBJECT, subject] => {
            decide(
                home,
                named,
                request,
                Some(step),
                Decision::Approve,
                Some(subject),
            )
            .await?
        }
        ["deny", request] => decide(home, named, request, None, Decision::Deny, None).await?,
        ["deny", request, step] => {
            decide(home, named, request, Some(step), Decision::Deny, None).await?
        }
        ["accept-change", who] => accept_change(home, named, who, None).await?,
        ["accept-change", who, head] => accept_change(home, named, who, Some(head)).await?,
        ["say", place, text] => person_says(home, named, place, text).await?,
        ["get-paid", places @ ..] if !places.is_empty() => get_paid(home, named, places).await?,
        _ => return Ok(None),
    }))
}

struct Looking {
    side: OwnerSide,
    owner_key: OwnerKey,
    owner: Identity,
}

impl Looking {
    fn new(home: &Home, named: Option<&str>, what: &str) -> Result<Self, Failure> {
        let owner_key = OwnerKey::new(home);
        Ok(Self {
            side: OwnerSide::resolve(home, named, what)?,
            owner: Identity::from_encoded(&owner_key.existing_identity()?)?,
            owner_key,
        })
    }

    /// Walks what the view holds, with the types its Signet says it agreed, which this device reads
    /// for itself.
    fn walked(&self, view: &crate::owner_side::View) -> Result<WalkedAll, Failure> {
        walk_all(
            &view.requests,
            self.side.agent(),
            &self.owner,
            &view.schemas,
        )
    }
}

/// A stand-in's signature counts for nobody, so nothing is shown to sign and no prompt is put up: it
/// says so in a sentence, before reading anything. An agent in its own home was handed approve and deny
/// lines it could only fail at, and a person a prompt that ended in a bare word.
fn refuse_a_stand_in(home: &Home) -> Result<(), Failure> {
    if !OwnerKey::new(home).is_stand_in() {
        return Ok(());
    }
    let elsewhere =
        Installed::load(home)?.is_some_and(|installed| installed.owner_elsewhere.is_some());
    let splint = home.command();
    Err(Failure::refused(if elsewhere {
        "nothing can be signed here: this agent's person signs from their own device, where their \
         controls are"
            .to_owned()
    } else {
        format!(
            "nothing can be signed here yet: this agent's person hasn't set up their controls, and \
             until they do, no yes or no for this side counts, so what waits for one stays waiting \
             until it expires. {splint} status says how they set them up, and {splint} ask-owner \
             gives a message for them"
        )
    }))
}

fn short(id: &str) -> String {
    id.chars().take(SHORT_ID_CHARS).collect()
}

/// One thing to sign, with what's needed to find it and show it.
struct ToDecide {
    request: MessageId,
    with: String,
    draft: splint_core::requests::ApprovalDraft,
    shown: ToSign,
    role: Side,
    /// Something else waits on the same request, so a command names this one by its step.
    beside: bool,
    /// Where its Signet says the owner's last answer to this wasn't used.
    not_used: Option<String>,
}

impl ToDecide {
    /// What a person types to answer this: the request's ID, and its step where there's more than one.
    fn handle(&self) -> String {
        let id = short(self.request.as_str());
        if self.beside {
            format!("{id} {}", step_word(self.draft.operation))
        } else {
            id
        }
    }
}

async fn to_decide(
    walked: &WalkedAll,
    looking: &Looking,
    home: &Home,
    now: u64,
) -> Result<Vec<ToDecide>, Failure> {
    let contacts = looking.side.contacts(home).await?;
    let owner = looking.owner.id();
    let mut found = Vec::new();
    for one in &walked.walked {
        let drafts = one.drafts(now);
        let with = with_hidden_shown(&one.their_address);
        let schema = one.chain.interaction_schema();
        let shown = side_by_side(
            drafts
                .iter()
                .map(|draft| to_sign(draft.clone(), one.role, schema, owner, &contacts, &with))
                .collect(),
        );
        let beside = drafts.len() > 1;
        let not_used = one.not_used_beside(now);
        for (draft, shown) in drafts.into_iter().zip(shown) {
            let not_used = not_used
                .as_ref()
                .filter(|(operation, _)| *operation == draft.operation)
                .map(|(_, words)| words.clone());
            found.push(ToDecide {
                request: one.request.clone(),
                with: with.clone(),
                shown,
                draft,
                role: one.role,
                beside,
                not_used,
            });
        }
    }
    for open in &walked.starting {
        if let Some(draft) = open.draft(now) {
            let schema = open.schema(&walked.schemas);
            let with = with_hidden_shown(&open.their_address);
            found.push(ToDecide {
                request: draft.request.clone(),
                shown: to_sign(
                    draft.clone(),
                    Side::Requester,
                    schema.as_deref(),
                    owner,
                    &contacts,
                    &with,
                ),
                with,
                draft,
                role: Side::Requester,
                beside: false,
                not_used: None,
            });
        }
    }
    Ok(found)
}

fn change_lines(notice: &Notice) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "  {} ({})", notice.shown_address(), notice.standing);
    for change in notice.changes_shown() {
        let _ = writeln!(out, "    {change}");
    }
    if let Some(rival) = &notice.rewritten_head {
        let _ = writeln!(
            out,
            "    Two histories for one ID. Someone holding its keys signed both, so it's held whatever \
             your rules say. This is one, head {}, and head {rival} is the other:",
            notice.head,
        );
        for change in notice.rewritten_shown() {
            let _ = writeln!(out, "    {change}");
        }
    }
    out
}

async fn waiting(home: &Home, named: Option<&str>) -> Result<String, Failure> {
    refuse_a_stand_in(home)?;
    let looking = Looking::new(home, named, "read what's waiting")?;
    let view = looking.side.read(home).await?;
    let walked = looking.walked(&view)?;
    let now = unix_now();
    let to_sign = to_decide(&walked, &looking, home, now).await?;
    let mut out = String::new();
    if let Some(at) = view.heard_at {
        let _ = writeln!(
            out,
            "Last heard from {}'s Signet {} seconds ago.\n",
            looking.side.address(),
            now.saturating_sub(at),
        );
    } else if looking.side.is_elsewhere() {
        let _ = writeln!(
            out,
            "{}'s Signet hasn't said anything yet, so there may be more than this.\n",
            looking.side.address(),
        );
    }
    if to_sign.is_empty() && view.changes.changes.is_empty() {
        let _ = writeln!(out, "Nothing is waiting for you to sign.");
    }
    // Nothing to sign yet, but the owner should know why their agent's step hasn't gone.
    for one in &walked.walked {
        if let Some(kind) = one.held_for_their_controls(now) {
            let _ = writeln!(
                out,
                "\n  {} with {}: your agent's {} commits you to an amount, and their person hasn't \
                 set up their controls yet. It waits, unsigned, until they have, and then goes, or \
                 comes here for you to sign if your settings say so.",
                short(one.request.as_str()),
                with_hidden_shown(&one.their_address),
                step_in_words(kind),
            );
        }
    }
    // What the other side asked to be paid, at the place their owner signed, with what a payer should
    // know of it, worked out here from the signed steps. Splint pays nothing: the person does.
    let every_ask: Vec<PaymentAsk> = walked
        .walked
        .iter()
        .flat_map(|one| one.chain.payment_asks().into_iter().cloned())
        .collect();
    for one in &walked.walked {
        let Some(payment) = one.chain.payment() else {
            continue;
        };
        if payment.status != PaymentStatus::Requested {
            continue;
        }
        for ask in payment
            .asks
            .iter()
            .filter(|ask| ask.owner == one.their_owner)
        {
            let _ = writeln!(
                out,
                "\n  To pay, for {} with {}: {} at {}{}, reference {}.",
                short(one.request.as_str()),
                with_hidden_shown(&one.their_address),
                amount_in_words(ask.value.as_str(), ask.amount, Some(ask.unit.as_str())),
                ask.place.destination(),
                ask.place
                    .asset()
                    .map(|asset| format!(" in {asset}"))
                    .unwrap_or_default(),
                ask.reference,
            );
            for warning in warnings_for(ask, &every_ask, now) {
                let _ = writeln!(out, "  {}", warning.in_words());
            }
        }
    }
    // A situational warning, from Signet's own counts, only for a contact far busier than usual.
    for words in view.usage.iter().filter_map(UsageLine::busier_words) {
        let _ = writeln!(out, "\n  {words}");
    }
    if !to_sign.is_empty() {
        let _ = writeln!(out, "To sign:\n");
    }
    for one in &to_sign {
        let id = short(one.request.as_str());
        let handle = one.handle();
        let _ = writeln!(out, "  {id} with {}", one.with);
        if let Some(words) = &one.not_used {
            let _ = writeln!(out, "  {words}");
        }
        let _ = write!(out, "{}", one.shown.lines());
        let _ = writeln!(out, "  splint approve {handle}, or splint deny {handle}\n");
    }
    if !view.changes.changes.is_empty() {
        let _ = writeln!(out, "A contact changed:\n");
    }
    for notice in view.changes.changes {
        let notice = notice.for_reading();
        let _ = write!(out, "{}", change_lines(&notice));
        let _ = writeln!(out, "  splint accept-change {}\n", notice.contact);
    }
    Ok(out.trim_end().to_owned())
}

/// The one draft a typed ID and step mean. An ID with more than one waiting on it has to name its
/// step, so a yes can't land on a draft other than the one the person read.
fn the_draft<'a>(
    found: &'a [ToDecide],
    typed: &str,
    step: Option<&str>,
    command: &str,
) -> Result<&'a ToDecide, Failure> {
    let on_it: Vec<&ToDecide> = found
        .iter()
        .filter(|one| !typed.is_empty() && one.request.as_str().starts_with(typed))
        .collect();
    let first = on_it.first().ok_or_else(|| {
        Failure::refused("that isn't waiting for you: splint waiting lists what is")
    })?;
    if on_it.iter().any(|one| one.request != first.request) {
        return Err(Failure::refused(
            "more than one fits that, so give more of its ID",
        ));
    }
    let steps: Vec<&str> = on_it
        .iter()
        .map(|one| step_word(one.draft.operation))
        .collect();
    match step {
        Some(step) => on_it
            .into_iter()
            .find(|one| step_word(one.draft.operation) == step)
            .ok_or_else(|| {
                Failure::refused(format!(
                    "nothing for {step} waits for you on that. What does: {}",
                    steps.join(", ")
                ))
            }),
        None if on_it.len() == 1 => Ok(first),
        None => Err(Failure::refused(format!(
            "more than one waits for you on that, each its own yes, so name the one you mean: \
             splint {command} {} {}",
            short(first.request.as_str()),
            steps.join(" or "),
        ))),
    }
}

/// A move an agent asked for, as a person says it.
fn step_in_words(kind: StepKind) -> &'static str {
    match kind {
        StepKind::Open => "request",
        StepKind::Counter => "counter-offer",
        StepKind::Accept => "acceptance",
        _ => "delivery",
    }
}

/// A whole ID or enough of one to mean only one, from what's on the screen.
fn the_one<'a, T>(
    candidates: &'a [T],
    typed: &str,
    id_of: impl Fn(&T) -> &str,
) -> Result<&'a T, Failure> {
    let mut found = candidates
        .iter()
        .filter(|one| id_of(one).starts_with(typed));
    match (typed.is_empty(), found.next(), found.next()) {
        (false, Some(one), None) => Ok(one),
        (false, Some(_), Some(_)) => Err(Failure::refused(
            "more than one fits that, so give more of its ID",
        )),
        _ => Err(Failure::refused(
            "that isn't waiting for you: splint waiting lists what is",
        )),
    }
}

async fn decide(
    home: &Home,
    named: Option<&str>,
    request: &str,
    step: Option<&str>,
    decision: Decision,
    subject: Option<&str>,
) -> Result<String, Failure> {
    refuse_a_stand_in(home)?;
    let looking = Looking::new(home, named, "sign for this agent")?;
    let view = looking.side.read(home).await?;
    let walked = looking.walked(&view)?;
    let found = to_decide(&walked, &looking, home, unix_now()).await?;
    let command = match decision {
        Decision::Approve => "approve",
        Decision::Deny => "deny",
    };
    let one = the_draft(&found, request, step, command)?;
    if decision == Decision::Approve && one.draft.terms.hides_text() {
        return Err(Failure::refused(
            "these terms hold text that can't all be shown, so they can't be approved",
        ));
    }
    if let Some(text) = subject {
        if !can_set_subject(one.draft.operation, one.role) {
            return Err(Failure::refused("only the side that asked sets a subject"));
        }
        if text.chars().count() > MAX_SUBJECT_CHARS || has_hidden_characters(text) {
            return Err(Failure::refused(
                "a subject has to be short plain text on one line",
            ));
        }
    }
    let verb = match decision {
        Decision::Approve => "yes",
        Decision::Deny => "no",
    };
    say(&format!(
        "You're being asked about {} with {}:\n\n{}",
        one.handle(),
        one.with,
        one.shown.lines(),
    ))?;
    let word = answer(&format!(
        "Type yes to sign {verb} to exactly this, and anything else to stop:"
    ))?;
    if word != YES {
        return Err(Failure::refused("nothing was signed"));
    }
    let at = looking.side.at_host().await?;
    let approval = looking
        .owner_key
        .approve(&one.draft, decision, subject, at.as_ref())?;
    looking
        .side
        .hand_over(home, OwnerSigned::Approval(approval))
        .await?;
    Ok(looking
        .side
        .signed_words(
            "Signed, and handed to your agent's Signet.",
            "Signed, and left at its host. Its Signet takes it within a few seconds, and if it \
             can't use it, as when what you were shown has changed since, splint waiting says so.",
        )
        .to_owned())
}

fn id_of_contact(
    side_contacts: &[splint_core::rules::RulesContact],
    who: &str,
) -> Option<SplintId> {
    side_contacts
        .iter()
        .find(|known| known.address == who || known.agent.as_str() == who)
        .map(|known| known.agent.clone())
}

async fn accept_change(
    home: &Home,
    named: Option<&str>,
    who: &str,
    head: Option<&str>,
) -> Result<String, Failure> {
    let looking = Looking::new(home, named, "say yes to a contact's change")?;
    let contacts = looking.side.rules(home).await?.draft.contacts;
    let contact = id_of_contact(&contacts, who)
        .ok_or_else(|| Failure::refused("that isn't one of your agent's contacts"))?;
    let view = looking.side.read(home).await?;
    let notice = view
        .changes
        .changes
        .into_iter()
        .find(|notice| notice.contact == contact)
        .ok_or_else(|| Failure::refused("nothing about that contact is waiting for you"))?;
    let chosen = match (head, &notice.rewritten_head) {
        (Some(head), rival) if head == notice.head || rival.as_deref() == Some(head) => {
            head.to_owned()
        }
        (Some(_), _) => {
            return Err(Failure::refused(
                "that isn't a head of this contact's history",
            ));
        }
        (None, None) => notice.head.clone(),
        (None, Some(_)) => {
            return Err(Failure::refused(
                "this contact has two histories, so name the head you mean: splint waiting lists them",
            ));
        }
    };
    let notice = notice.for_reading();
    say(&format!(
        "What changed:\n\n{}\nA later change would need a later yes.",
        change_lines(&notice)
    ))?;
    let word =
        answer("Type yes to accept this contact's history this far, and anything else to stop:")?;
    if word != YES {
        return Err(Failure::refused("nothing was signed"));
    }
    let at = looking.side.at_host().await?;
    let acceptance =
        looking
            .owner_key
            .accept_change(looking.side.agent(), &contact, &chosen, at.as_ref())?;
    looking
        .side
        .hand_over(home, OwnerSigned::Acceptance(acceptance))
        .await?;
    Ok(looking
        .side
        .signed_words(
            "Signed yes to that contact's history, this far.",
            "Signed yes to that contact's history, this far, and left at its host. Its Signet takes it \
             within a few seconds.",
        )
        .to_owned())
}

/// Where the person gets paid, signed here. Their agent's Signet puts it on its asks to be paid, so a
/// payer sees the place this owner chose, never one an agent or anyone else wrote.
async fn get_paid(home: &Home, named: Option<&str>, given: &[&str]) -> Result<String, Failure> {
    let places = given
        .iter()
        .map(|place| place_from(place))
        .collect::<Result<Vec<Place>, Failure>>()?;
    let looking = Looking::new(home, named, "say where you get paid")?;
    if looking.owner_key.is_stand_in() {
        return Err(Failure::refused(
            "only your person says where they get paid, with their own key, which isn't here",
        ));
    }
    let at = looking.side.at_host().await?;
    let signed = looking.owner_key.where_paid(&places, at.as_ref())?;
    looking
        .side
        .hand_over(home, OwnerSigned::WherePaid(signed))
        .await?;
    Ok(signed_where_paid(&places))
}

/// What a person is told once where they get paid is signed, here and on their page.
pub(crate) fn signed_where_paid(places: &[Place]) -> String {
    let irreversible = places.iter().any(Place::irreversible);
    format!(
        "Signed. Your agent can ask to be paid at {}, once a deal that pays you is done. Splint \
         holds no money: people pay you on their own app or wallet.{}",
        if places.len() == 1 {
            "this place"
        } else {
            "these places"
        },
        if irreversible {
            " A payment by Lightning or on a chain can't be taken back, by you or by them."
        } else {
            ""
        }
    )
}

/// One place as a person types it: a payment page's link, a Lightning address or offer, or
/// `onchain:CHAIN:ADDRESS:ASSET`.
pub(crate) fn place_from(given: &str) -> Result<Place, Failure> {
    let place = if given.starts_with("https://") {
        Place::PaymentPage {
            url: given.to_owned(),
        }
    } else if let Some(rest) = given.strip_prefix("onchain:") {
        let mut parts = rest.rsplitn(3, ':');
        let (asset, address, chain) = (parts.next(), parts.next(), parts.next());
        let (Some(asset), Some(address), Some(chain)) = (asset, address, chain) else {
            return Err(Failure::refused(
                "a chain address is onchain:CHAIN:ADDRESS:ASSET, such as onchain:eip155:8453:0xabc...:usdc",
            ));
        };
        Place::Onchain {
            chain: chain.to_owned(),
            address: address.to_owned(),
            asset: Word::try_from(asset.to_ascii_lowercase())
                .map_err(|_| Failure::refused("an asset is one word, such as usdc"))?,
        }
    } else {
        Place::Lightning {
            to: given.strip_prefix("lightning:").unwrap_or(given).to_owned(),
        }
    };
    if !place.fits() {
        return Err(Failure::refused(
            "that isn't a place Splint takes: an https payment page with no login in it, a \
             Lightning address or offer, or onchain:CHAIN:ADDRESS:ASSET. Bank details aren't taken",
        ));
    }
    Ok(place)
}

/// A person's words, signed here. They go with the agent's next step that can carry them, and they
/// move nothing. `place` is a request, or a contact's address for the next thing opened with them.
async fn person_says(
    home: &Home,
    named: Option<&str>,
    place: &str,
    text: &str,
) -> Result<String, Failure> {
    // An agent that runs this means to pass on what its person said, which goes in its own note. A
    // stand-in's key isn't a person's, so it signs nobody's words.
    let only_theirs = || {
        Failure::refused(format!(
            "only your person signs words as theirs, with their own key, which isn't here. If \
             you're an agent passing on what they said, put it in your own note with {} send NAME \
             WORDS, as your report of what they said",
            home.command()
        ))
    };
    let looking = match Looking::new(home, named, "write as a person") {
        Ok(looking) if looking.owner_key.is_stand_in() => return Err(only_theirs()),
        Ok(looking) => looking,
        // Only for an agent set up here with no person's key beside it. Any other refusal, such as
        // one that isn't set up yet, says what it is.
        Err(Failure::Refused(_))
            if named.is_none()
                && Installed::require(home).is_ok()
                && !OwnerKey::new(home).is_real_owner() =>
        {
            return Err(only_theirs());
        }
        Err(failure) => return Err(failure),
    };
    if text.trim().is_empty()
        || text.chars().count() > MAX_WORDS_CHARS
        || has_hidden_characters(text)
    {
        return Err(Failure::refused(format!(
            "words have to be plain text on one line, up to {MAX_WORDS_CHARS} characters",
        )));
    }
    let agent = looking.side.agent();
    let at = looking.side.at_host().await?;
    let signed = if parse_address(place).is_ok() {
        let contacts = looking.side.rules_or_kept_here(home).await?.draft.contacts;
        let to = id_of_contact(&contacts, place)
            .ok_or_else(|| Failure::refused("that isn't one of your agent's contacts"))?;
        looking
            .owner_key
            .person_text(agent, &to, None, text, at.as_ref())?
    } else {
        let view = looking.side.read(home).await?;
        let walked = looking.walked(&view)?;
        let one = the_one(&walked.walked, place, |one| one.request.as_str())?;
        looking
            .owner_key
            .person_text(agent, &one.them, Some(&one.request), text, at.as_ref())?
    };
    looking
        .side
        .hand_over(home, OwnerSigned::PersonText(signed))
        .await?;
    Ok("Signed. They go with your agent's next step on this, and not before.".to_owned())
}

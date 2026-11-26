//! Approving what agents asked their owner for, in one touch: each ask is checked here under its
//! agent's ID, and only an agent this owner set up here is answered, other than one asking for
//! controls. The prompt is written from the asks as the agents signed them and names every change it
//! approves, so asks past what one prompt names wait for the next. Only then does this device sign:
//! the controls an agent asked to have set up, new rules holding exactly what was asked, a yes to the
//! one step held for the owner that an agent asked them to approve, with its terms and who pays whom
//! in the prompt, or where the owner gets paid.
//! Nothing reusable goes back: each answer is one signed object for one agent.

use std::path::Path;

use serde::{Deserialize, Serialize};
use splint_core::asks::VerifiedAsk;
use splint_core::host_api::OwnerMailKind;
use splint_core::requests::{
    ApprovalDraft, Decision, FieldValue, Schema, Schemas, Side, paying_in,
};
use splint_core::rules::{ContactStatus, RulesDraft, VerifiedRules};
use splint_core::{Error, Identity, PublicKey, SigningKey, SplintId, parse_address, unix_now};

use crate::device::{self, Device};
use crate::prompt::{self, StepTerms};
use crate::recovery;
use crate::signing::{self, Naming};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Given {
    asks: Vec<One>,
    /// Every agent this owner set up from this computer, for the list kept at their home host, which
    /// this touch signs again once it has set one up, so a lost computer doesn't lose its backup.
    #[serde(default)]
    list: Option<recovery::ListGiven>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct One {
    ask: String,
    /// The asking agent's ID, which the ask's agent has to be the hash of.
    identity: String,
    /// The agent's address, which a binding names.
    address: String,
    /// For an ask for controls: the first rules, which Splint on this computer makes from its schemas.
    /// The delegation goes to the delegate key the ask itself names.
    #[serde(default)]
    rules: Option<RulesDraft>,
    /// For an ask for a held step: the draft the agent's Signet left in the owner's view, which has to
    /// be for exactly the step asked.
    #[serde(default)]
    draft: Option<ApprovalDraft>,
    /// The schema of the type that draft names, from the same view. Its ID is worked out here, and it
    /// has to be the draft's type, so who pays whom in the prompt is read from the type's own `paid`.
    #[serde(default)]
    schema: Option<Schema>,
    /// For an ask naming types: each one's schema, from the same view, whose ID is worked out here, so
    /// the prompt says whether each has money and whose it is (Nenye, 2026-11-15).
    #[serde(default)]
    kinds: Vec<Schema>,
    /// For an ask for new rules: the rules in force, as Splint on this computer read them from the
    /// agent's host or Signet, which are checked here and built on where they're newer than this
    /// device's own.
    #[serde(default)]
    in_force: Option<String>,
    /// The owner's ID as the agent's host holds it, which counts only where it carries this device's
    /// copy on, so rules another of the owner's sign-ins signed check out.
    #[serde(default)]
    owner_identity: Option<String>,
    /// For an ask for controls, or to add an owner part: the owner's name the binding names the agent
    /// under, which Splint on this computer chose: their name at that host, or the one the ask names,
    /// once the host said nobody has it. One adding an owner part adds the one it names, or nothing.
    #[serde(default)]
    owner_part: Option<String>,
}

#[derive(Serialize)]
pub struct Answered {
    approved: Vec<Approved>,
    refused: Vec<Refused>,
    code: String,
    /// The owner's list, signed in the same touch, for their home host.
    #[serde(skip_serializing_if = "Option::is_none")]
    list: Option<String>,
}

#[derive(Serialize)]
struct Approved {
    id: String,
    /// The answer an agent asking for controls takes up, as `splint finish` reads it.
    #[serde(skip_serializing_if = "Option::is_none")]
    answer: Option<String>,
    /// New rules for the agent's host.
    #[serde(skip_serializing_if = "Option::is_none")]
    rules: Option<String>,
    /// A yes to a held step, for the agent's Signet.
    #[serde(skip_serializing_if = "Option::is_none")]
    approval: Option<String>,
    /// Where the owner gets paid, for the agent's Signet and its host.
    #[serde(skip_serializing_if = "Option::is_none")]
    where_paid: Option<String>,
    /// With a yes or where the owner gets paid: the exact body that leaves it at the agent's host,
    /// which is it sealed to the agent, so the host can't read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    /// And this owner's proof for posting exactly that body there, signed with the same approval.
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<String>,
}

impl Approved {
    /// An answer that goes to the agent's Signet, with what leaves it at the agent's host, sealed to
    /// the agent whose own key signed the ask, at the host its address names.
    fn for_its_signet(
        device: &Device,
        one: &One,
        identity: &Identity,
        ask: &VerifiedAsk,
        kind: OwnerMailKind,
        signed: String,
    ) -> Result<Self, Error> {
        let (_, domain) = parse_address(&one.address)?;
        let at = signing::AtHost {
            host: domain.to_owned(),
            agent: identity.clone(),
        };
        at.is_of(ask.agent())?;
        let left = signing::for_host(device, &at, kind, signed)?;
        let (approval, where_paid) = match kind {
            OwnerMailKind::WherePaid => (None, Some(left.signed)),
            _ => (Some(left.signed), None),
        };
        Ok(Self {
            id: ask.id().to_owned(),
            answer: None,
            rules: None,
            approval,
            where_paid,
            body: Some(left.body),
            proof: Some(left.proof),
        })
    }
}

#[derive(Serialize)]
struct Refused {
    id: Option<String>,
    reason: &'static str,
}

/// Why one ask can't be approved here, in fixed words.
fn reason(error: &Error) -> &'static str {
    match error {
        Error::Expired => "ended",
        Error::WrongSigner => "not your agent",
        Error::KeyStorage => "not set up from this computer",
        Error::Stale => "no longer waiting",
        _ => "not an ask this computer can sign",
    }
}

/// The longest word a type holds, as splint-core has it.
const MOST_WORD_CHARS: usize = 32;
/// An ask with more changes than one prompt names, which no prompt could show whole.
const TOO_MANY: &str = "too many changes to show in one prompt";
/// A rename or a move for an agent whose ID commits to a backup this device doesn't hold, and whose
/// vouch kept here is for another.
const NOTHING_VOUCHES: &str = "this computer holds no backup for this agent's ID as it is now, so \
     it can't sign its new name or host: its person signs it where that backup is";

/// Whether an ask's answer is a binding signed from what this device kept for its agent, as a rename
/// or a move is, with no backup handed to it.
fn signs_from_memory(ask: &VerifiedAsk) -> bool {
    ask.adds_owner_part().is_some() || ask.host().is_some()
}

/// One ask that checked out, with what the prompt says of its held step.
struct Checked {
    one: One,
    identity: Identity,
    ask: VerifiedAsk,
    terms: Option<StepTerms>,
    /// The address what's signed names the agent at, where that isn't the one it has now.
    becomes: Option<String>,
}

/// Approves, with one prompt, the asks given that it names in full: in order, as many as fit, a held
/// step or where the owner gets paid alone. The rest are neither signed nor refused, so they're still
/// waiting for the next prompt, and nothing is ever signed that the prompt didn't name.
pub fn approve(dir: &Path, schemas: &Schemas, given: Given) -> Result<Answered, Error> {
    let now = unix_now();
    let owner = device::identity_in(dir)?;
    let mut refused = Vec::new();
    let mut this_touch: Vec<Checked> = Vec::new();
    let mut full = false;
    for one in given.asks {
        let id = splint_core::asks::payload_id(&one.ask).ok();
        let checked = Identity::from_encoded(&one.identity).and_then(|identity| {
            let ask = VerifiedAsk::verify(&one.ask, &identity, now)?;
            parse_address(&one.address)?;
            let bound = bound_at(&one, &ask)?;
            mine(dir, &owner, &ask)?;
            kinds_given(&one, &ask)?;
            let terms = step_terms(dir, &one, &ask)?;
            Ok((
                identity,
                ask,
                terms,
                (bound != one.address).then_some(bound),
            ))
        });
        let (identity, ask, terms, becomes) = match checked {
            Ok(checked) => checked,
            Err(error) => {
                refused.push(Refused {
                    id,
                    reason: reason(&error),
                });
                continue;
            }
        };
        if ask.changes().len() > prompt::MOST_NAMED {
            refused.push(Refused {
                id,
                reason: TOO_MANY,
            });
            continue;
        }
        // A rename or a move is signed from what this device kept for the agent, so one it can't sign
        // is refused here, before the prompt, and never after the person approved it.
        if signs_from_memory(&ask) && signing::binds_with(dir, owner.id(), &identity).is_err() {
            refused.push(Refused {
                id,
                reason: NOTHING_VOUCHES,
            });
            continue;
        }
        let with: Vec<&VerifiedAsk> = this_touch.iter().map(|taken| &taken.ask).collect();
        full = full || !prompt::fits(&with, &ask);
        if !full {
            this_touch.push(Checked {
                one,
                identity,
                ask,
                terms,
                becomes,
            });
        }
    }
    if this_touch.is_empty() {
        if refused.iter().any(|refusal| refusal.id.is_some()) {
            return Ok(Answered {
                approved: Vec::new(),
                refused,
                code: String::new(),
                list: None,
            });
        }
        return Err(Error::Malformed);
    }
    let shown: Vec<prompt::AskShown<'_>> = this_touch
        .iter()
        .map(|taken| {
            (
                &taken.ask,
                taken.one.address.as_str(),
                taken.becomes.as_deref(),
                taken.terms.as_ref(),
                taken.one.kinds.as_slice(),
            )
        })
        .collect();
    // Only a touch that sets up an agent keeps the list again, as only that changes what's in it.
    let sets_up = this_touch
        .iter()
        .any(|taken| splint_core::asks::controls_delegate(taken.ask.changes()).is_some());
    let keeps_list = given
        .list
        .as_ref()
        .filter(|_| sets_up && recovery::writes_list(dir));
    let keeping = keeps_list.map(|list| recovery::keeping_words(&list.host));
    let device = Device::open(dir, prompt::for_asks(&shown, keeping.as_deref()))?;
    let code = device.code().unwrap_or_default().to_owned();
    let mut approved = Vec::new();
    for taken in &this_touch {
        match sign_one(&device, schemas, &taken.one, &taken.identity, &taken.ask) {
            Ok(done) => approved.push(done),
            // The person said no to the one prompt, so nothing else is signed either.
            Err(Error::NotApproved) => return Err(Error::NotApproved),
            Err(error) => refused.push(Refused {
                id: Some(taken.ask.id().to_owned()),
                reason: reason(&error),
            }),
        }
    }
    // The list holds only backups this device holds, so one it couldn't sign leaves the asks done.
    let list = keeps_list
        .filter(|_| !approved.is_empty())
        .and_then(|list| recovery::sign_list(&device, list).ok().flatten());
    Ok(Answered {
        approved,
        refused,
        code,
        list,
    })
}

/// What `describe-asks` prints: each ask in the words its prompt will name it by.
#[derive(Serialize)]
pub struct Described {
    asks: Vec<DescribedAsk>,
}

#[derive(Serialize)]
struct DescribedAsk {
    id: String,
    /// Each change, in fixed words, as [`prompt::ask_lines`] has them.
    said: Vec<String>,
    /// For a held step, the words either agent wrote in it, kept apart as the prompt keeps them.
    written: Vec<String>,
}

/// Each ask given, in the words a prompt approving it names it by, from the same checks and the same
/// draft and schema, so the page and the terminal that show them can't say less than the prompt. It
/// opens no sign-in and signs nothing. An ask it can't say whole, or that doesn't check out, is
/// refused, so nothing is shown that its prompt would name differently.
pub fn describe(dir: &Path, given: Given) -> Result<Described, Error> {
    let now = unix_now();
    let mut asks = Vec::new();
    for one in &given.asks {
        let identity = Identity::from_encoded(&one.identity)?;
        let ask = VerifiedAsk::verify(&one.ask, &identity, now)?;
        parse_address(&one.address)?;
        let bound = bound_at(one, &ask)?;
        if ask.changes().len() > prompt::MOST_NAMED {
            return Err(Error::Malformed);
        }
        kinds_given(one, &ask)?;
        let terms = step_terms(dir, one, &ask)?;
        let becomes = (bound != one.address).then_some(bound.as_str());
        asks.push(DescribedAsk {
            id: ask.id().to_owned(),
            said: prompt::ask_lines(&ask, &one.address, becomes, terms.as_ref(), &one.kinds),
            written: terms.map(|terms| terms.written).unwrap_or_default(),
        });
    }
    Ok(Described { asks })
}

/// The address a binding this touch signs for an ask names: the agent's own, or its word with the
/// owner's name after it, which has to fit there, or the ask isn't shown or signed. That's the name
/// Splint on this computer chose for an ask for controls, or the ask's own, and for an ask to add an
/// owner part, the one it names. An owner's agent is never set up under a temporary name.
fn bound_at(one: &One, ask: &VerifiedAsk) -> Result<String, Error> {
    let owner_part = match (ask.adds_owner_part(), one.owner_part.as_deref()) {
        (Some(asked), Some(chosen)) if asked != chosen => return Err(Error::Malformed),
        (_, Some(chosen)) if ask.asks_for_controls() || ask.adds_owner_part().is_some() => {
            Some(chosen)
        }
        _ => ask.owner_part(),
    };
    match owner_part {
        Some(owner_part) if ask.adds_owner_part().is_some() => {
            splint_core::with_owner_part(&one.address, owner_part)
        }
        Some(owner_part) => splint_core::named_under(&one.address, owner_part),
        None if ask.asks_for_controls()
            && parse_address(&one.address)
                .is_ok_and(|(name, _)| splint_core::is_temporary_name(name)) =>
        {
            Err(Error::Malformed)
        }
        None => Ok(one.address.clone()),
    }
}

/// Whether this device signs for the agent behind an ask at all, checked before any prompt names it:
/// an ask for controls from any agent, as its owner is a stand-in until then; anything else only from
/// an agent this owner set up here, so a stranger's ask, such as for where this owner gets paid, is
/// never shown or signed.
fn mine(dir: &Path, owner: &Identity, ask: &VerifiedAsk) -> Result<(), Error> {
    if ask.asks_for_controls() {
        return Ok(());
    }
    if ask.owner() != owner.id() {
        return Err(Error::WrongSigner);
    }
    device::rules_in(dir, ask.agent())
        .map(|_| ())
        .ok_or(Error::KeyStorage)
}

/// Every type an ask names comes with its schema, by the ID worked out here, or nothing is signed: an
/// owner approves a type knowing what it holds, as the page and the terminal show it.
fn kinds_given(one: &One, ask: &VerifiedAsk) -> Result<(), Error> {
    let all_given = splint_core::asks::types_named(ask.changes())
        .into_iter()
        .all(|named| one.kinds.iter().any(|kind| kind.name() == named));
    if all_given { Ok(()) } else { Err(Error::Stale) }
}

/// For an ask to approve a held step: the draft has to be for exactly that step, and the prompt names
/// everything the yes is to. First in fixed words: where it pays anyone, who pays whom and how much,
/// from the type's own `paid` and the terms; who it's with, by the address in this owner's rules or as
/// someone not in them; the type and version; and every number and time agreed and delivered. Then,
/// apart, the words in its fields, subject and note, which either agent wrote, for the prompt to show
/// last as theirs. A type two agents agreed needs its schema, whose ID has to be the one the draft
/// names, or nothing is shown that could be wrong and the ask isn't signed.
fn step_terms(dir: &Path, one: &One, ask: &VerifiedAsk) -> Result<Option<StepTerms>, Error> {
    let Some((request, operation)) = ask.step() else {
        return Ok(None);
    };
    let draft = one.draft.as_ref().ok_or(Error::Stale)?;
    if &draft.request != request || draft.operation != operation || &draft.agent != ask.agent() {
        return Err(Error::Stale);
    }
    let terms = &draft.terms;
    let (mine, theirs) = if terms.requester.agent == draft.agent {
        (Side::Requester, &terms.recipient)
    } else {
        (Side::Recipient, &terms.requester)
    };
    let mut fixed = Vec::new();
    if terms.interaction.is_agreed() {
        let schema = one
            .schema
            .as_ref()
            .filter(|schema| schema.name() == &terms.interaction)
            .ok_or(Error::Malformed)?;
        for paying in paying_in(terms, schema) {
            // A unit is one of the type's words, so anything else beside the amount is refused.
            if !paying.unit.as_deref().is_none_or(is_a_word) {
                return Err(Error::Malformed);
            }
            fixed.push(if paying.to == mine {
                format!("you're paid {}", paying.amount_in_words())
            } else {
                format!("you pay {}", paying.amount_in_words())
            });
        }
    }
    let contacts = device::rules_in(dir, &draft.agent)
        .map(|rules| rules.contacts)
        .unwrap_or_default();
    fixed.push(
        match contacts
            .iter()
            .find(|contact| contact.agent == theirs.agent)
        {
            Some(contact) if contact.status == ContactStatus::Allowed => {
                format!("with {}", contact.address)
            }
            Some(contact) => format!("with {}, whom you blocked", contact.address),
            None => format!("with {}, an agent not in your rules", theirs.agent),
        },
    );
    fixed.push(format!(
        "version {} of a {}",
        draft.version,
        terms.interaction.name()
    ));
    let mut written = Vec::new();
    for (said, fields) in [("agreed", &terms.agreed), ("delivered", &terms.result)] {
        let numbers: Vec<String> = fields
            .iter()
            .filter_map(|(name, value)| signing::shown_number(&prompt::plain(name), value))
            .collect();
        if !numbers.is_empty() {
            fixed.push(format!("{said} {}", numbers.join(", ")));
        }
        written.extend(fields.iter().filter_map(|(name, value)| match value {
            FieldValue::Text(text) => Some(format!(
                "{} {}",
                prompt::written(name),
                prompt::written(text)
            )),
            _ => None,
        }));
    }
    for (said, text) in [("subject", &terms.subject), ("note", &terms.note)] {
        if let Some(text) = text {
            written.push(format!("{said} {}", prompt::written(text)));
        }
    }
    Ok(Some(StepTerms { fixed, written }))
}

/// One of a type's words, as a unit has to be.
fn is_a_word(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MOST_WORD_CHARS
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn sign_one(
    device: &Device,
    schemas: &Schemas,
    one: &One,
    identity: &Identity,
    ask: &VerifiedAsk,
) -> Result<Approved, Error> {
    if let Some(delegate) = splint_core::asks::controls_delegate(ask.changes()) {
        let mut draft = one.rules.clone().ok_or(Error::Malformed)?;
        ask.apply(&mut draft);
        let delegate = PublicKey::from_encoded(delegate)?;
        let made = device.new_agent_backup()?;
        let backup = SigningKey::load(&made.file)?;
        device.remember_backup_of(ask.agent(), &made.commitment)?;
        let answer = signing::controls(
            device,
            identity,
            &bound_at(one, ask)?,
            &backup,
            draft,
            Some(&delegate),
            schemas,
        )?;
        return Ok(Approved {
            id: ask.id().to_owned(),
            answer: Some(answer),
            rules: None,
            approval: None,
            where_paid: None,
            body: None,
            proof: None,
        });
    }
    if ask.owner() != device.identity.id() {
        return Err(Error::WrongSigner);
    }
    if let Some((request, operation)) = ask.step() {
        let draft = one.draft.as_ref().ok_or(Error::Stale)?;
        let exactly = &draft.request == request
            && draft.operation == operation
            && &draft.agent == ask.agent()
            && &draft.owner == device.identity.id();
        if !exactly {
            return Err(Error::Stale);
        }
        let approval = draft.sign(&device.key, Decision::Approve, None, unix_now())?;
        return Approved::for_its_signet(
            device,
            one,
            identity,
            ask,
            OwnerMailKind::Approval,
            approval,
        );
    }
    // A move is the owner's binding at the new address, signed with the vouch this device kept when it
    // set the agent up, so nothing the agent or a host sent decides who's vouched for. The address it
    // moves from is the one this computer set it up at, and the move is to another host.
    if let Some(to) = ask.host() {
        let (_, from) = parse_address(&one.address)?;
        let (_, domain) = parse_address(to)?;
        if from == domain {
            return Err(Error::Malformed);
        }
        let binding = signing::binding_from_memory(device, identity, to)?;
        return Ok(Approved {
            id: ask.id().to_owned(),
            answer: Some(binding),
            rules: None,
            approval: None,
            where_paid: None,
            body: None,
            proof: None,
        });
    }
    // An owner part is the owner's binding at the agent's name with their part after its handle,
    // signed with the vouch kept here as a move is. Its host refuses it unless that part is this
    // owner's there, or free, and the name had none.
    if ask.adds_owner_part().is_some() {
        let binding = signing::binding_from_memory(device, identity, &bound_at(one, ask)?)?;
        return Ok(Approved {
            id: ask.id().to_owned(),
            answer: Some(binding),
            rules: None,
            approval: None,
            where_paid: None,
            body: None,
            proof: None,
        });
    }
    if let Some(places) = ask.where_paid() {
        let signed = signing::where_paid(device, places.to_vec()).map_err(|_| Error::Malformed)?;
        return Approved::for_its_signet(
            device,
            one,
            identity,
            ask,
            OwnerMailKind::WherePaid,
            signed,
        );
    }
    let mut draft = rules_to_change(device, one, ask.agent())?;
    ask.apply(&mut draft);
    // Either base names the delegation it does: this device's own copy names what it signed, and the
    // rules in force may have ended one this copy still names.
    let rules = signing::rules(device, ask.agent(), draft, Naming::AsDrafted)?;
    Ok(Approved {
        id: ask.id().to_owned(),
        answer: None,
        rules: Some(rules),
        approval: None,
        where_paid: None,
        body: None,
        proof: None,
    })
}

/// What an ask for new rules is built on: the newer of the rules in force and those this device last
/// signed, by their `seq`. Rules are replaced whole, so building on this device's own while another of
/// the owner's devices has signed since would undo that change, such as a contact it took out (issue
/// 630). With none read, or ones that aren't this owner's for this agent, nothing is signed. A host or
/// Signet giving older ones changes nothing, as this device's own are newer.
fn rules_to_change(device: &Device, one: &One, agent: &SplintId) -> Result<RulesDraft, Error> {
    let own = device.rules_of(agent).ok_or(Error::KeyStorage)?;
    let held = one.in_force.as_deref().ok_or(Error::Malformed)?;
    let owner = one
        .owner_identity
        .as_deref()
        .and_then(|copy| Identity::from_encoded(copy).ok())
        .and_then(|copy| device.identity.newest_of(&copy).ok())
        .unwrap_or_else(|| device.identity.clone());
    let live = VerifiedRules::reload(held, &owner)?;
    if live.agent() != agent {
        return Err(Error::ProofMismatch);
    }
    Ok(if live.seq() > device.rules_seq(agent) {
        live.draft()
    } else {
        own
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_in::Holding;
    use splint_core::asks::{Change, sign_ask};
    use splint_core::rules::{Level, VerifiedRules};
    use splint_core::{JoinReply, RecoveryRule, SealingKey, SplintId, VerifiedBinding};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("owner-key-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn agent() -> (SigningKey, Identity) {
        let key = SigningKey::generate().unwrap();
        let identity = Identity::create(
            &key,
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        )
        .unwrap();
        (key, identity)
    }

    fn first_rules() -> RulesDraft {
        serde_json::from_str(
            r#"{"paused":false,"contacts":[],"invites":[],"limits":{"new_requests_per_contact_per_day":20,"open_requests_per_contact":3,"open_approvals":10,"new_from_others_per_day":250,"texts_per_contact_per_day":100}}"#,
        )
        .unwrap()
    }

    fn one(ask: String, identity: &Identity, rules: Option<RulesDraft>) -> One {
        One {
            ask,
            identity: identity.encoded(),
            address: "muse~host.example".to_owned(),
            rules,
            draft: None,
            schema: None,
            kinds: Vec::new(),
            in_force: None,
            owner_identity: None,
            owner_part: None,
        }
    }

    /// An ask for new rules, with the rules in force as Splint here read them: those `owner` last
    /// signed for `agent`, unless `held` says otherwise.
    fn for_rules(ask: String, agent: &Identity, owner: &Device, held: Option<String>) -> One {
        let held = held.unwrap_or_else(|| {
            owner
                .rules_of(agent.id())
                .unwrap()
                .sign(
                    &owner.key,
                    owner.identity.id(),
                    agent.id(),
                    owner.rules_seq(agent.id()),
                    unix_now(),
                )
                .unwrap()
        });
        One {
            in_force: Some(held),
            ..one(ask, agent, None)
        }
    }

    /// A device in `dir` with muse set up from it, as its controls ask had it.
    fn with_muse_set_up(dir: &Path) -> (Device, SigningKey, Identity) {
        let owner = Device::init_signed_in(dir, Holding::PlainFile).unwrap();
        let (muse_key, muse) = agent();
        let controls = sign_ask(
            &muse_key,
            muse.id(),
            owner.identity.id(),
            vec![Change::Controls {
                delegate: SigningKey::generate().unwrap().public_key().encoded(),
                owner_part: None,
            }],
            unix_now(),
            3600,
        )
        .unwrap();
        let given = Given {
            asks: vec![one(controls, &muse, Some(first_rules()))],
            list: None,
        };
        assert_eq!(
            approve(dir, &Schemas::default(), given)
                .unwrap()
                .approved
                .len(),
            1
        );
        (owner, muse_key, muse)
    }

    fn asked(key: &SigningKey, agent: &Identity, owner: &Identity, changes: Vec<Change>) -> String {
        sign_ask(key, agent.id(), owner.id(), changes, unix_now(), 3600).unwrap()
    }

    fn approved(dir: &Path, asks: Vec<One>) -> Answered {
        approve(dir, &Schemas::default(), Given { asks, list: None }).unwrap()
    }

    fn id_of(compact: &str) -> String {
        splint_core::asks::payload_id(compact).unwrap()
    }

    /// Bug caught: one touch signing a change its prompt never named, such as where the owner gets
    /// paid behind four harmless changes, or more changes than one prompt names across asks, or an
    /// ask too big for any prompt to show whole; or answering with a code other than the prompt's.
    #[test]
    fn one_touch_signs_only_what_its_prompt_names() {
        use splint_core::rules::{Outbound, QuotedPrices};
        let dir = scratch("named-asks");
        let (owner, muse_key, muse) = with_muse_set_up(&dir);
        let harmless = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![
                Change::Level { to: Level::AskMe },
                Change::QuotedPrices {
                    to: QuotedPrices::Wait,
                },
                Change::Writes {
                    to: Outbound::Contacts,
                },
                Change::Paused { to: false },
            ],
        );
        let thief = vec![splint_core::requests::Place::PaymentPage {
            url: "https://thief.example.com/pay".to_owned(),
        }];
        let paid = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![Change::WherePaid { places: thief }],
        );
        let answered = approved(
            &dir,
            vec![
                for_rules(harmless.clone(), &muse, &owner, None),
                one(paid.clone(), &muse, None),
            ],
        );
        assert_eq!(answered.approved.len(), 1);
        assert_eq!(answered.approved[0].id, id_of(&harmless));
        assert!(answered.approved[0].where_paid.is_none());
        assert!(answered.refused.is_empty(), "left waiting, not refused");
        let shown = VerifiedAsk::verify(&harmless, &muse, unix_now()).unwrap();
        assert_eq!(
            answered.code,
            splint_core::prepared::touch_code_of([shown.compact()])
        );
        let answered = approved(&dir, vec![one(paid.clone(), &muse, None)]);
        assert_eq!(answered.approved[0].id, id_of(&paid));
        assert!(answered.approved[0].where_paid.is_some());

        let contacts = |count: usize| -> Vec<Change> {
            (0..count)
                .map(|n| Change::Contact {
                    agent: agent().1.id().clone(),
                    address: format!("agent{n}~other.example"),
                    types: Vec::new(),
                    text: false,
                })
                .collect()
        };
        let (five, five_more) = (
            asked(&muse_key, &muse, &owner.identity, contacts(5)),
            asked(&muse_key, &muse, &owner.identity, contacts(5)),
        );
        let answered = approved(
            &dir,
            vec![
                for_rules(five.clone(), &muse, &owner, None),
                for_rules(five_more, &muse, &owner, None),
            ],
        );
        assert_eq!(answered.approved.len(), 1, "ten changes across two asks");
        assert_eq!(answered.approved[0].id, id_of(&five));
        assert!(answered.refused.is_empty(), "left waiting, not refused");
        let too_many = asked(&muse_key, &muse, &owner.identity, contacts(9));
        let answered = approved(&dir, vec![one(too_many, &muse, None)]);
        assert!(answered.approved.is_empty());
        assert_eq!(answered.refused[0].reason, TOO_MANY);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bug caught: an agent nobody set up here getting this owner to sign where they're paid, or a
    /// yes to a step, by naming this owner's ID in its ask.
    #[test]
    fn a_strangers_ask_is_never_shown_or_signed() {
        let dir = scratch("strangers-ask");
        let (owner, _, _) = with_muse_set_up(&dir);
        let (mallory_key, mallory) = agent();
        let evil = vec![splint_core::requests::Place::PaymentPage {
            url: "https://pay.evil.example/x".to_owned(),
        }];
        let paid = asked(
            &mallory_key,
            &mallory,
            &owner.identity,
            vec![Change::WherePaid { places: evil }],
        );
        let answered = approved(&dir, vec![one(paid, &mallory, None)]);
        assert!(answered.approved.is_empty());
        assert_eq!(answered.refused[0].reason, "not set up from this computer");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn quote() -> Schema {
        let schemas = crate::auto::load_schemas(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/schemas"),
        )
        .unwrap();
        schemas.named("quote/1").unwrap().as_ref().clone()
    }

    fn step_draft(owner: &SplintId, agent: &SplintId, request: &str) -> ApprovalDraft {
        serde_json::from_value(serde_json::json!({
            "owner": owner, "agent": agent, "operation": "confirm",
            "request": request, "version": 3, "prev": request, "latest_expiry": unix_now() + 3600,
            "terms": {
                "type": quote().name(),
                "requester": {"agent": agent, "owner": owner},
                "recipient": {"agent": stranger_id(), "owner": stranger_id()},
                "agreed": {"currency": "usd", "item": "catering", "quantity": 10},
                "result": {"amount_minor": 125_000, "valid_days": 7},
                "subject": null, "note": null, "supersedes": null,
            },
        }))
        .unwrap()
    }

    /// Bug caught: a yes signed to a draft other than the one held for exactly the step asked, for
    /// another request, agent or owner.
    #[test]
    fn a_held_step_is_signed_only_for_its_exact_draft() {
        let dir = scratch("exact-step");
        let (owner, muse_key, muse) = with_muse_set_up(&dir);
        let request = "d".repeat(64);
        let step = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![Change::Step {
                request: serde_json::from_value(serde_json::json!(request)).unwrap(),
                operation: splint_core::requests::Operation::Confirm,
            }],
        );
        let exact = step_draft(owner.identity.id(), muse.id(), &request);
        let mut other_request = exact.clone();
        other_request.request = serde_json::from_value(serde_json::json!("e".repeat(64))).unwrap();
        let mut other_agent = exact.clone();
        other_agent.agent = agent().1.id().clone();
        let mut other_owner = exact.clone();
        other_owner.owner = agent().1.id().clone();
        for draft in [other_request.clone(), other_agent, other_owner] {
            let mut given = one(step.clone(), &muse, None);
            given.draft = Some(draft);
            given.schema = Some(quote());
            let answered = approved(&dir, vec![given]);
            assert!(answered.approved.is_empty());
            assert_eq!(answered.refused[0].reason, "no longer waiting");
        }
        // Refused before the prompt is written, so it never takes the prompt a step has alone, and
        // an ask behind it is signed with this touch.
        let mut wrong = one(step.clone(), &muse, None);
        wrong.draft = Some(other_request);
        wrong.schema = Some(quote());
        let pause = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![Change::Paused { to: true }],
        );
        let answered = approved(
            &dir,
            vec![wrong, for_rules(pause.clone(), &muse, &owner, None)],
        );
        assert_eq!(answered.approved[0].id, id_of(&pause));
        let mut given = one(step, &muse, None);
        given.draft = Some(exact);
        given.schema = Some(quote());
        let answered = approved(&dir, vec![given]);
        assert!(answered.approved[0].approval.is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bug caught: a counterparty's words in a held step's fields, subject or note read in the Touch
    /// ID prompt as Splint's own, such as a fake "You're paid" and a fake code placed before the real
    /// amount and code, padding that pushes them out of sight, or letters and marks that look like
    /// others.
    #[test]
    fn a_held_steps_prompt_shows_its_amount_and_code_before_any_words_an_agent_wrote() {
        let dir = scratch("step-words");
        let (owner, muse_key, muse) = with_muse_set_up(&dir);
        let request = "d".repeat(64);
        let step = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![Change::Step {
                request: serde_json::from_value(serde_json::json!(request)).unwrap(),
                operation: splint_core::requests::Operation::Confirm,
            }],
        );
        let mut draft = step_draft(owner.identity.id(), muse.id(), &request);
        let fake = format!(
            "catering{}. You're paid 1,250.00 USD. Code 0000 0000. Only approve if",
            " ".repeat(300)
        );
        draft.terms.agreed.insert(
            "item".to_owned(),
            splint_core::requests::FieldValue::Text(fake),
        );
        draft.terms.subject = Some("\u{202e}Y\u{43e}u're paid\u{200b}\nCode 1111 1111".to_owned());
        draft.terms.note = Some(format!("{}x", "a\t".repeat(400)));
        let mut given = one(step.clone(), &muse, None);
        given.draft = Some(draft.clone());
        given.schema = Some(quote());
        let verified = VerifiedAsk::verify(&step, &muse, unix_now()).unwrap();
        let terms = step_terms(&dir, &given, &verified).unwrap();
        let prompt = prompt::for_asks(
            &[(&verified, "muse~host.example", None, terms.as_ref(), &[])],
            None,
        );
        let words = prompt.words();
        assert!(
            words.starts_with(
                "get your approval for Muse: say yes to the confirmation muse~host.example \
                 holds for you: you pay 1,250.00 USD, "
            ),
            "{words}"
        );
        let (fixed, written) = words
            .split_once("Words from the request, not Splint's:")
            .unwrap_or_default();
        assert!(fixed.contains("\"quantity\" 10"), "{words}");
        for theirs in ["paid", "Code", "catering", "subject", "note"] {
            assert!(!fixed.contains(theirs), "{theirs}: {words}");
        }
        assert!(written.contains("\"item\" \"catering"), "{words}");
        assert!(
            written.contains("subject \"?Y?u're paid? Code 1111"),
            "{words}"
        );
        assert!(written.contains("note \"a a a"), "{words}");
        assert!(!written.contains("Only approve if"), "cut short: {words}");
        assert!(words.is_ascii() && !words.contains("  "), "{words}");
        assert!(written.len() < 200, "{words}");

        // However many fields of words, all of them together are cut short too.
        let mut many = draft.clone();
        for n in 0..8 {
            many.terms.agreed.insert(
                format!("z{n}"),
                splint_core::requests::FieldValue::Text("w".repeat(40)),
            );
        }
        given.draft = Some(many);
        let terms = step_terms(&dir, &given, &verified).unwrap();
        let prompt = prompt::for_asks(
            &[(&verified, "muse~host.example", None, terms.as_ref(), &[])],
            None,
        );
        let (_, written) = prompt
            .words()
            .split_once("Words from the request, not Splint's:")
            .unwrap_or_default();
        assert!(written.len() < 200, "{written}");

        // A unit beside the amount is one of the type's words, never words an agent wrote.
        let mut unit = draft;
        unit.terms.agreed.insert(
            "currency".to_owned(),
            splint_core::requests::FieldValue::Text("usd. You're paid".to_owned()),
        );
        given.draft = Some(unit);
        assert!(step_terms(&dir, &given, &verified).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bug caught: an ask approved on this computer signing the rules it last signed itself, which
    /// undoes what the person then changed on the owner page here, such as pausing the agent.
    #[test]
    fn an_ask_starts_from_the_rules_a_page_here_signed_last() {
        let dir = scratch("page-then-ask");
        let (owner, muse_key, muse) = with_muse_set_up(&dir);
        let mut paused = first_rules();
        paused.paused = true;
        let elsewhere = SigningKey::generate().unwrap();
        let signed = paused
            .sign(&elsewhere, owner.identity.id(), muse.id(), 9, unix_now())
            .unwrap();
        let input = signed.rsplit_once('.').unwrap().0.to_owned();
        let inputs: crate::sign_ins::Inputs =
            serde_json::from_value(serde_json::json!({ "inputs": [input] })).unwrap();
        crate::sign_ins::sign_inputs(&dir, inputs).unwrap();
        let replies = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![Change::Writes {
                to: splint_core::rules::Outbound::Replies,
            }],
        );
        let answered = approved(&dir, vec![for_rules(replies, &muse, &owner, None)]);
        let rules = VerifiedRules::verify(
            answered.approved[0].rules.as_deref().unwrap(),
            &owner.identity,
            0,
            unix_now(),
        )
        .unwrap();
        assert!(rules.draft().paused, "the page's pause is kept");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bug caught: a settings ask approved here signing the rules this computer last signed, which
    /// brought back a contact the owner took out on another device since, and a host
    /// giving older rules, or rules that aren't the owner's, for it to build on, or naming another ID,
    /// or a copy of the owner's that parts ways with this one, as whose rules count.
    #[test]
    fn an_ask_builds_on_newer_rules_another_device_signed() {
        let dir = scratch("behind-then-ask");
        let (owner, muse_key, muse) = with_muse_set_up(&dir);
        let ben = agent().1;
        let mut with_ben = owner.rules_of(muse.id()).unwrap();
        with_ben.contacts.push(splint_core::rules::RulesContact {
            agent: ben.id().clone(),
            address: "ben~host.example".to_owned(),
            label: "ben".to_owned(),
            status: ContactStatus::Allowed,
            types: Vec::new(),
            text: true,
            agree_types: false,
            pinned_by: splint_core::rules::PinnedBy::Owner,
        });
        signing::rules(&owner, muse.id(), with_ben.clone(), Naming::AsBefore).unwrap();
        let own_seq = owner.rules_seq(muse.id());
        let sign = |draft: RulesDraft, key: &SigningKey, seq: u64| {
            draft
                .sign(key, owner.identity.id(), muse.id(), seq, unix_now())
                .unwrap()
        };
        let mut without_ben = with_ben.clone();
        without_ben.contacts.clear();
        let ask = || {
            asked(
                &muse_key,
                &muse,
                &owner.identity,
                vec![Change::Paused { to: false }],
            )
        };
        let names_ben = |answered: &Answered| {
            let signed = answered.approved[0].rules.as_deref().unwrap();
            let rules = VerifiedRules::verify(signed, &owner.identity, 0, unix_now()).unwrap();
            rules
                .draft()
                .contacts
                .iter()
                .any(|one| &one.agent == ben.id())
        };

        let newer = sign(without_ben.clone(), &owner.key, own_seq + 1);
        let answered = approved(&dir, vec![for_rules(ask(), &muse, &owner, Some(newer))]);
        assert!(!names_ben(&answered), "the newer removal is kept");

        signing::rules(&owner, muse.id(), with_ben, Naming::AsBefore).unwrap();
        let older = sign(without_ben.clone(), &owner.key, 1);
        let answered = approved(&dir, vec![for_rules(ask(), &muse, &owner, Some(older))]);
        assert!(
            names_ben(&answered),
            "older rules held elsewhere change nothing"
        );

        let forged = sign(without_ben, &SigningKey::generate().unwrap(), u64::MAX / 2);
        let answered = approved(&dir, vec![for_rules(ask(), &muse, &owner, Some(forged))]);
        assert!(
            answered.approved.is_empty(),
            "rules that aren't the owner's"
        );
        let answered = approved(&dir, vec![one(ask(), &muse, None)]);
        assert!(answered.approved.is_empty(), "nothing read, nothing signed");

        // The owner's ID as a host gives it, which may be another ID, or a copy of this owner's that
        // parts ways with this device's, each with rules its own key signed far ahead.
        let from_host = |held: String, copy: &Identity| One {
            owner_identity: Some(copy.encoded()),
            ..for_rules(ask(), &muse, &owner, Some(held))
        };
        let thief_dir = scratch("behind-then-ask-thief");
        let thief = Device::init_signed_in(&thief_dir, Holding::PlainFile).unwrap();
        let theirs = first_rules()
            .sign(
                &thief.key,
                thief.identity.id(),
                muse.id(),
                u64::MAX / 2,
                unix_now(),
            )
            .unwrap();
        let answered = approved(&dir, vec![from_host(theirs, &thief.identity)]);
        assert!(answered.approved.is_empty(), "rules another ID signed");
        let parted_key = SigningKey::generate().unwrap();
        let parted = owner
            .identity
            .add_key(&owner.key, &parted_key, unix_now())
            .unwrap();
        let mine = owner
            .identity
            .add_key(&owner.key, &SigningKey::generate().unwrap(), unix_now())
            .unwrap();
        std::fs::write(dir.join("owner.identity"), mine.encoded()).unwrap();
        let theirs = sign(first_rules(), &parted_key, u64::MAX / 2);
        let answered = approved(&dir, vec![from_host(theirs, &parted)]);
        assert!(
            answered.approved.is_empty(),
            "rules a copy that parts ways signed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&thief_dir).unwrap();
    }

    /// Bug caught: a settings ask approved on a device that's behind, building on newer rules another
    /// device signed naming no delegation, as after a new delegate key, while the owner key filled the
    /// delegation this device last named back in, so a leaked delegate key's yeses counted again.
    #[test]
    fn a_device_behind_leaves_a_delegation_another_ended_ended() {
        let dir = scratch("ended-delegation");
        let (owner, muse_key, muse) = with_muse_set_up(&dir);
        let mut naming = owner.rules_of(muse.id()).unwrap();
        naming.permissions.level = Level::AutoWithinLimits;
        naming.delegation = Some("ab".repeat(32));
        signing::rules(&owner, muse.id(), naming.clone(), Naming::AsBefore).unwrap();
        let mut ended = naming;
        ended.delegation = None;
        let newer = ended
            .sign(
                &owner.key,
                owner.identity.id(),
                muse.id(),
                owner.rules_seq(muse.id()) + 1,
                unix_now(),
            )
            .unwrap();
        let ask = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![Change::Paused { to: false }],
        );
        let answered = approved(&dir, vec![for_rules(ask, &muse, &owner, Some(newer))]);
        let signed = answered.approved[0].rules.as_deref().unwrap();
        let rules = VerifiedRules::verify(signed, &owner.identity, 0, unix_now()).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(rules.named_delegation(), None);
    }

    /// Bug caught: an agent set up, or its rules signed, other than as it asked, or another owner's
    /// agent's ask signed here as if it were this owner's.
    #[test]
    fn one_touch_signs_exactly_what_each_agent_asked_and_nothing_for_strangers() {
        let dir = scratch("approve-asks");
        let owner = Device::init_signed_in(&dir, Holding::PlainFile).unwrap();
        let (muse_key, muse) = agent();
        let stand_in = SigningKey::generate().unwrap().public_key();
        let stand_in = Identity::create(
            &SigningKey::generate().unwrap(),
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::unconfirmed_owner(&stand_in),
        )
        .unwrap();
        let now = unix_now();
        let controls = sign_ask(
            &muse_key,
            muse.id(),
            stand_in.id(),
            vec![Change::Controls {
                delegate: SigningKey::generate().unwrap().public_key().encoded(),
                owner_part: None,
            }],
            now,
            3600,
        )
        .unwrap();
        let answered = approve(
            &dir,
            &Schemas::default(),
            Given {
                asks: vec![one(controls, &muse, Some(first_rules()))],
                list: None,
            },
        )
        .unwrap();
        assert!(answered.approved[0].answer.is_some());
        assert!(owner.rules_of(muse.id()).is_some());

        let full_auto = sign_ask(
            &muse_key,
            muse.id(),
            owner.identity.id(),
            vec![Change::Level {
                to: Level::FullAuto,
            }],
            now,
            3600,
        )
        .unwrap();
        let (stranger_key, stranger) = agent();
        let elsewhere = sign_ask(
            &stranger_key,
            stranger.id(),
            stand_in.id(),
            vec![Change::Paused { to: true }],
            now,
            3600,
        )
        .unwrap();
        let answered = approve(
            &dir,
            &Schemas::default(),
            Given {
                asks: vec![
                    for_rules(full_auto, &muse, &owner, None),
                    one(elsewhere, &stranger, None),
                ],
                list: None,
            },
        )
        .unwrap();
        assert_eq!(answered.approved.len(), 1);
        assert_eq!(answered.refused[0].reason, "not your agent");
        let signed = answered.approved[0].rules.as_deref().unwrap();
        let rules = VerifiedRules::verify(signed, &owner.identity, 0, now).unwrap();
        assert_eq!(rules.agent(), muse.id());
        assert_eq!(rules.permissions().level, Level::FullAuto);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bug caught: where the owner gets paid signed other than as asked, or a yes to a priced step
    /// whose prompt doesn't say who pays, or says it from a schema that isn't the draft's type.
    #[test]
    fn where_paid_is_signed_as_asked_and_a_priced_step_says_who_pays() {
        let dir = scratch("where-paid-ask");
        let (owner, muse_key, muse) = with_muse_set_up(&dir);
        let now = unix_now();
        let places = vec![splint_core::requests::Place::PaymentPage {
            url: "https://pay.example.com/ana".to_owned(),
        }];
        let asked = sign_ask(
            &muse_key,
            muse.id(),
            owner.identity.id(),
            vec![Change::WherePaid {
                places: places.clone(),
            }],
            now,
            3600,
        )
        .unwrap();
        let answered = approve(
            &dir,
            &Schemas::default(),
            Given {
                asks: vec![one(asked, &muse, None)],
                list: None,
            },
        )
        .unwrap();
        let signed = answered.approved[0].where_paid.as_deref().unwrap();
        let statement =
            splint_core::requests::VerifiedWherePaid::verify(signed, &owner.identity).unwrap();
        assert_eq!(statement.places(), places.as_slice());

        let schemas = crate::auto::load_schemas(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/schemas"),
        )
        .unwrap();
        let quote = schemas.named("quote/1").unwrap().as_ref().clone();
        let request = "d".repeat(64);
        let draft: ApprovalDraft = serde_json::from_value(serde_json::json!({
            "owner": owner.identity.id(), "agent": muse.id(), "operation": "confirm",
            "request": request, "version": 3, "prev": request, "latest_expiry": now + 3600,
            "terms": {
                "type": quote.name(),
                "requester": {"agent": muse.id(), "owner": owner.identity.id()},
                "recipient": {"agent": stranger_id(), "owner": stranger_id()},
                "agreed": {"currency": "usd", "item": "catering", "quantity": 10},
                "result": {"amount_minor": 125_000, "valid_days": 7},
                "subject": null, "note": null, "supersedes": null,
            },
        }))
        .unwrap();
        let step = sign_ask(
            &muse_key,
            muse.id(),
            owner.identity.id(),
            vec![Change::Step {
                request: draft.request.clone(),
                operation: draft.operation,
            }],
            now,
            3600,
        )
        .unwrap();
        let verified = VerifiedAsk::verify(&step, &muse, now).unwrap();
        let mut given = one(step, &muse, None);
        given.draft = Some(draft);
        assert!(step_terms(&dir, &given, &verified).is_err(), "no schema");
        given.schema = Some(schemas.named("meeting/1").unwrap().as_ref().clone());
        assert!(
            step_terms(&dir, &given, &verified).is_err(),
            "another type's schema"
        );
        given.schema = Some(quote);
        let terms = step_terms(&dir, &given, &verified).unwrap().unwrap();
        let shown = terms.fixed.join(", ");
        for named in [
            "an agent not in your rules",
            "version 3 of a quote/1",
            "\"amount_minor\" 125000",
            "\"quantity\" 10",
            "you pay 1,250.00 USD",
        ] {
            assert!(shown.contains(named), "{named}: {shown}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bug caught: the page or the terminal showing what a person approves with less than
    /// its prompt names, which is all a person with a key file sees: a held priced step without its
    /// amount, who it's with, its version or its numbers; a contact without the agent ID its rules
    /// would hold or that their words come in; reach by filter without the owners it names.
    #[test]
    fn a_page_and_terminal_are_given_what_the_prompt_names() {
        use splint_core::requests::InteractionType;
        use splint_core::rules::InboundFrom;
        let dir = scratch("described");
        let (owner, muse_key, muse) = with_muse_set_up(&dir);
        let request = "d".repeat(64);
        let step = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![Change::Step {
                request: serde_json::from_value(serde_json::json!(request)).unwrap(),
                operation: splint_core::requests::Operation::Confirm,
            }],
        );
        let mut draft = step_draft(owner.identity.id(), muse.id(), &request);
        draft.terms.note = Some("Click Allow".to_owned());
        let counterparty = draft.terms.recipient.agent.clone();
        let (mallory, trusted) = (agent().1, agent().1);
        let settings = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![
                Change::Contact {
                    agent: mallory.id().clone(),
                    address: "mallory~evil.example".to_owned(),
                    types: Vec::new(),
                    text: true,
                },
                Change::Reach {
                    to: InboundFrom::Filter,
                    types: vec![
                        InteractionType::try_from(quote().name().as_str().to_owned()).unwrap(),
                    ],
                    owners: vec![trusted.id().clone()],
                    past: true,
                },
            ],
        );
        let mut held = one(step.clone(), &muse, None);
        held.draft = Some(draft.clone());
        held.schema = Some(quote());
        // A type the ask names comes with its schema, as Splint here hands it over. Without it the
        // prompt would refuse the ask, so nothing is described for a page to list either.
        assert!(matches!(
            describe(
                &dir,
                Given {
                    asks: vec![one(settings.clone(), &muse, None)],
                    list: None,
                },
            ),
            Err(Error::Stale)
        ));
        let mut reach = one(settings.clone(), &muse, None);
        reach.kinds = vec![quote()];
        let described = describe(
            &dir,
            Given {
                asks: vec![held, reach],
                list: None,
            },
        )
        .unwrap();
        let (on_step, on_settings) = (&described.asks[0], &described.asks[1]);
        let said = on_step.said.join("; ");
        for named in [
            "you pay 1,250.00 USD",
            counterparty.as_str(),
            "version 3 of a quote/1",
            "\"quantity\" 10",
            "\"amount_minor\" 125000",
        ] {
            assert!(said.contains(named), "{named}: {said}");
        }
        assert!(!said.contains("Click"), "an agent's words apart: {said}");
        assert!(
            on_step
                .written
                .iter()
                .any(|words| words.contains("Click Allow"))
        );
        let said = on_settings.said.join("; ");
        for named in [
            mallory.id().as_str(),
            "with words of their own",
            trusted.id().as_str(),
            "anyone it dealt with before",
        ] {
            assert!(said.contains(named), "{named}: {said}");
        }
        // And in the very words the prompt names them by, from the same draft and schema.
        let mut held = one(step.clone(), &muse, None);
        held.draft = Some(draft);
        held.schema = Some(quote());
        let verified = |compact: &str| VerifiedAsk::verify(compact, &muse, unix_now()).unwrap();
        let (step, settings) = (verified(&step), verified(&settings));
        let terms = step_terms(&dir, &held, &step).unwrap();
        let prompt = prompt::for_asks(
            &[
                (&step, "muse~host.example", None, terms.as_ref(), &[]),
                (&settings, "muse~host.example", None, None, &[quote()]),
            ],
            None,
        );
        for line in on_settings.said.iter().chain(&on_step.said) {
            assert!(prompt.words().contains(line.as_str()), "{line}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bug caught: a person's name after the agent's handle signed at the address the agent has now,
    /// or with nothing said of it, an owner's agent set up under a temporary name, or a name added
    /// that isn't the one asked for, or to a name that has an owner part already.
    #[test]
    fn a_name_after_the_handle_is_signed_only_as_its_prompt_names_it() {
        let dir = scratch("owner-part");
        let (owner, muse_key, muse) = with_muse_set_up(&dir);
        let refused_alone = |given: One| {
            let answered = approve(
                &dir,
                &Schemas::default(),
                Given {
                    asks: vec![given],
                    list: None,
                },
            )
            .unwrap();
            answered.approved.is_empty()
                && answered.refused.first().map(|refused| refused.reason)
                    == Some("not an ask this computer can sign")
        };
        let rename = asked(
            &muse_key,
            &muse,
            &owner.identity,
            vec![Change::OwnerPart {
                to: "jeff".to_owned(),
            }],
        );
        let shown = describe(
            &dir,
            Given {
                asks: vec![one(rename.clone(), &muse, None)],
                list: None,
            },
        )
        .unwrap();
        let names = |said: &[String], named: &str| {
            said.iter()
                .any(|line| line.contains(named) && line.contains("jeff as your name"))
        };
        assert!(
            names(&shown.asks[0].said, "muse.jeff~host.example"),
            "{:?}",
            shown.asks[0].said
        );
        // Signing it takes the agent's ID as its handover left it, which sim/agent_asks.py runs.
        assert!(refused_alone(One {
            address: "muse.jeff~host.example".to_owned(),
            ..one(rename.clone(), &muse, None)
        }));
        assert!(refused_alone(One {
            owner_part: Some("mal".to_owned()),
            ..one(rename, &muse, None)
        }));

        // Controls under a temporary name: the binding names the agent's word with the owner's name
        // Splint here chose, and so do the words shown.
        let (lia_key, lia) = agent();
        let controls = sign_ask(
            &lia_key,
            lia.id(),
            agent().1.id(),
            vec![Change::Controls {
                delegate: SigningKey::generate().unwrap().public_key().encoded(),
                owner_part: None,
            }],
            unix_now(),
            3600,
        )
        .unwrap();
        let lia_at = |owner_part: Option<&str>| One {
            address: "lia-7k3p2a~host.example".to_owned(),
            owner_part: owner_part.map(str::to_owned),
            ..one(controls.clone(), &lia, Some(first_rules()))
        };
        let shown = describe(
            &dir,
            Given {
                asks: vec![lia_at(Some("jeff"))],
                list: None,
            },
        )
        .unwrap();
        assert!(
            names(&shown.asks[0].said, "lia.jeff~host.example"),
            "{:?}",
            shown.asks[0].said
        );
        assert!(refused_alone(lia_at(None)));
        let answered = approved(&dir, vec![lia_at(Some("jeff"))]);
        let reply = JoinReply::decode(answered.approved[0].answer.as_deref().unwrap()).unwrap();
        assert_eq!(
            VerifiedBinding::check_ahead(&reply.binding, &owner.identity, &lia, &reply.commitment)
                .unwrap(),
            "lia.jeff~host.example"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An agent this device set up, whose ID commits to a backup kept here, after the device signed
    /// another binding for it that the agent never took up, so the vouch kept is for a backup its ID
    /// doesn't commit to, as for the first agent set up by one touch, on 2026-11-22. Bug caught: its rename
    /// refused as "not your agent" after the person had approved it, as the vouch was checked only
    /// once the owner's key had signed.
    #[test]
    fn a_rename_signs_with_the_backup_its_id_commits_to_when_the_vouch_kept_is_for_another() {
        let dir = scratch("stale-vouch");
        let owner = Device::init_signed_in(&dir, Holding::PlainFile).unwrap();
        let set_up_with = |backup: &SigningKey| {
            let key = SigningKey::generate().unwrap();
            let identity = Identity::create(
                &key,
                &SealingKey::generate().unwrap().public_key(),
                RecoveryRule::backup_key(&backup.public_key()),
            )
            .unwrap();
            owner
                .remember_rules(identity.id(), &first_rules(), 1)
                .unwrap();
            // The vouch kept is for a backup its ID never took.
            let other = SigningKey::load(&owner.new_agent_backup().unwrap().file).unwrap();
            signing::binding_ahead(&owner, &identity, "muse~host.example", &other).unwrap();
            (key, identity)
        };
        let renamed = |key: &SigningKey, identity: &Identity| {
            let rename = asked(
                key,
                identity,
                &owner.identity,
                vec![Change::OwnerPart {
                    to: "jeff".to_owned(),
                }],
            );
            approved(
                &dir,
                vec![One {
                    owner_part: Some("jeff".to_owned()),
                    ..one(rename, identity, None)
                }],
            )
        };

        let held = SigningKey::load(&owner.new_agent_backup().unwrap().file).unwrap();
        let (muse_key, muse) = set_up_with(&held);
        let answered = renamed(&muse_key, &muse);
        let reasons: Vec<&str> = answered
            .refused
            .iter()
            .map(|refused| refused.reason)
            .collect();
        assert!(reasons.is_empty(), "{reasons:?}");
        let binding = answered.approved[0].answer.as_deref().unwrap();
        // As its agent's Signet checks it before taking it up, and every reader once the agent adds its half.
        assert_eq!(
            VerifiedBinding::check_from_owner(binding, &owner.identity, &muse).unwrap(),
            "muse.jeff~host.example"
        );
        let accepted =
            VerifiedBinding::accept(&muse_key, binding, None, &owner.identity, &muse).unwrap();
        assert_eq!(accepted.address(), "muse.jeff~host.example");
        // And what it vouched with is kept, for the next one.
        assert!(matches!(
            signing::binds_with(&dir, owner.identity.id(), &muse),
            Ok(signing::BindsWith::Vouch(_))
        ));

        // One whose backup this device doesn't hold is refused before anyone is asked, with why.
        let (lia_key, lia) = set_up_with(&SigningKey::generate().unwrap());
        let answered = renamed(&lia_key, &lia);
        assert!(answered.approved.is_empty());
        assert_eq!(answered.refused[0].reason, NOTHING_VOUCHES);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn stranger_id() -> String {
        agent().1.id().as_str().to_owned()
    }
}

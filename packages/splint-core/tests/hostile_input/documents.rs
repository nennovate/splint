//! The signed documents an owner's device and a Signet make: rules, bindings, registrations,
//! retirements, histories of change, a person's words, approvals, invitations, where an owner gets
//! paid, and a request's steps and outcome. Each has a control that has to pass, and a
//! check on anything re-signed that verifies, which reads it as plain JSON and shares no parser types.

use std::collections::{BTreeSet, HashSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use splint_core::changes::{
    HistoryDocument, VerifiedHistory, is_notice_body, notice_body, notice_in,
};
use splint_core::invites::{InviteLink, claimed_invite, redeem_body, redeem_proof_in};
use splint_core::requests::{
    Action, Chain, CheckedStep, Offer, Outcome, Parties, Party, Place, Schemas, Side,
    VerifiedApproval, VerifiedPersonText, VerifiedWherePaid, Word, is_step_body, request_of,
};
use splint_core::rules::{RulesDraft, VerifiedRules, claimed_rules_agent};
use splint_core::{
    Error, RecoveryRule, RetirementReason, SigningKey, SplintId, VerifiedBinding, VerifiedEnvelope,
    VerifiedRegistration, VerifiedRelease, VerifiedRetirement, claimed_released_agent,
    claimed_retired_agent,
};

use super::{
    NOW, Rng, Signer, TOKENS, Tally, World, expect_equal, field_str, field_u64, mutate, quoted,
    signed_content,
};

const RULES_TYPE: &str = "splint-rules";
const PERSON_TEXT_TYPE: &str = "splint-person-text";
const APPROVAL_TYPE: &str = "splint-approval";
const RELEASE_TYPE: &str = "splint-release";
const RETIREMENT_TYPE: &str = "splint-retirement";
const WHERE_PAID_TYPE: &str = "splint-where-paid";
/// What the protocol says a statement of where an owner gets paid may hold.
const MAX_PLACES: usize = 4;
const MAX_STATEMENT_BYTES: usize = 1536;
const MAX_PAGE_CHARS: usize = 300;
const HOST: &str = "a.example";
const PART_SEPARATOR: char = '~';
/// The example meeting's ID, its name and the fingerprint of its schema, as `spec/vectors/types.json` has it.
const MEETING: &str = "meeting/1@i7fqx5fcz3sz4svkmv6ctjb2ksrzqknaho42n4nn7gz6qtuz2wqq";
const REQUEST_VECTORS: &str = include_str!("../../../../spec/vectors/requests.json");
const SCHEMAS: [&[u8]; 4] = [
    include_bytes!("../../../../spec/schemas/document-1.json"),
    include_bytes!("../../../../spec/schemas/meeting-1.json"),
    include_bytes!("../../../../spec/schemas/quote-1.json"),
    include_bytes!("../../../../spec/schemas/rsvp-1.json"),
];
const MAX_PERSON_TEXT_CHARS: usize = 280;
const MAX_SUBJECT_CHARS: usize = 120;
const MAX_NOTE_CHARS: usize = 200;
const HOUR_SECS: u64 = 60 * 60;
const MAX_DATE_AHEAD_SECS: u64 = 14 * 24 * 60 * 60;
const MAX_FIELDS_IN_A_STEP: usize = 16;
const CLOCK_TOLERANCE_SECS: u64 = 120;
/// Words that can hide from a person reading, by what the protocol says rather than its code.
const HIDDEN: &[char] = &['\u{202e}', '\u{200b}', '\u{feff}', '\u{0000}', '\u{0007}'];

/// What each document's checks need, built once. Anything wrong here stops the whole run.
pub struct Documents {
    owner: Signer,
    agent: Signer,
    other_agent: Signer,
    other_owner: Signer,
    rules: String,
    rules_payload: String,
    person_text: String,
    person_text_payload: String,
    where_paid: String,
    where_paid_payload: String,
    approval: String,
    approval_payload: String,
    release: String,
    binding: String,
    from_owner: String,
    history: String,
    notice: String,
    schemas: Schemas,
    /// The bodies of an `open`, and of each next step the other side could take, all valid.
    steps: Vec<(Side, String)>,
    open_envelope: String,
    agent_key: SigningKey,
    outcome: Value,
    retirement: String,
    invite_link: String,
    registration: String,
}

fn key_of(signer: &Signer) -> Result<SigningKey, String> {
    SigningKey::from_pkcs8(&signer.pkcs8).map_err(|error| error.to_string())
}

fn payload_of(compact: &str) -> Result<String, String> {
    let part = compact.split('.').nth(1).ok_or("not a compact form")?;
    let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| "not base64")?;
    String::from_utf8(bytes).map_err(|_| "not text".to_owned())
}

fn draft_rules(contact: &SplintId, address: &str) -> Result<RulesDraft, String> {
    serde_json::from_value(json!({
        "paused": false,
        "reach": {
            "inbound": {"from": "contacts", "filter": {"owners": [], "hosts": [], "past": false},
                        "types": [], "text": false, "strangers": "quarantine"},
            "outbound": "contacts",
        },
        "permissions": {"level": "auto_within_limits", "actions_per_day": 50, "caps": {}},
        "contacts": [{"agent": contact, "address": address, "label": "Ben", "status": "allowed",
                      "types": [MEETING], "text": true, "pinned_by": "owner"}],
        "invites": [],
        "limits": {"new_requests_per_contact_per_day": 3, "open_requests_per_contact": 3,
                   "open_approvals": 10, "new_from_others_per_day": 50,
                   "texts_per_contact_per_day": 20, "sends_per_hour": 10, "sends_per_day": 20},
    }))
    .map_err(|error| format!("control rules draft: {error}"))
}

fn fields_of(value: Value) -> Result<splint_core::requests::Fields, String> {
    serde_json::from_value(value).map_err(|error| format!("control fields: {error}"))
}

impl Documents {
    pub fn new(rng: &mut Rng) -> Result<Self, String> {
        let other_owner = Signer::from_seed(rng)?;
        let other_agent = Signer::from_seed(rng)?;
        let backup_key = key_of(&Signer::from_seed(rng)?)?;
        let recovery = RecoveryRule::backup_key(&backup_key.public_key());
        let owner = Signer::from_seed(rng)?.with_recovery(recovery.clone())?;
        let agent = Signer::from_seed(rng)?.with_recovery(recovery)?;
        let (owner_key, agent_key) = (key_of(&owner)?, key_of(&agent)?);

        let rules = draft_rules(other_agent.identity.id(), "ben~other.example")?
            .sign(&owner_key, owner.identity.id(), agent.identity.id(), 7, NOW)
            .map_err(|error| format!("control rules: {error}"))?;
        let rules_payload = payload_of(&rules)?;
        VerifiedRules::verify(&rules, &owner.identity, 0, NOW)
            .map_err(|error| format!("control rules: {error}"))?;

        let person_text_payload = json!({
            "v": 1, "owner": owner.identity.id(), "agent": agent.identity.id(),
            "to": other_agent.identity.id(), "request": null, "text": "hello from a person",
            "issued_at": NOW,
        })
        .to_string();
        let person_text = owner.sign(PERSON_TEXT_TYPE, person_text_payload.as_bytes())?;
        VerifiedPersonText::verify(&person_text, &owner.identity)
            .map_err(|error| format!("control person text: {error:?}"))?;

        let places = vec![
            Place::PaymentPage {
                url: "https://pay.example.com/ana?ref=1".to_owned(),
            },
            Place::Lightning {
                to: "ana@wallet.example".to_owned(),
            },
            Place::Onchain {
                chain: "eip155:8453".to_owned(),
                address: "0xAbC0000000000000000000000000000000000001".to_owned(),
                asset: Word::try_from("usdc".to_owned()).map_err(|_| "control asset".to_owned())?,
            },
        ];
        let where_paid_bytes = VerifiedWherePaid::payload_to_sign(owner.identity.id(), places, NOW)
            .map_err(|error| format!("control where paid: {error:?}"))?;
        let where_paid_payload = String::from_utf8(where_paid_bytes)
            .map_err(|_| "control where paid isn't text".to_owned())?;
        let where_paid = owner.sign(WHERE_PAID_TYPE, where_paid_payload.as_bytes())?;
        VerifiedWherePaid::verify(&where_paid, &owner.identity)
            .map_err(|error| format!("control where paid: {error:?}"))?;

        let id = "ab".repeat(32);
        let approval_payload = json!({
            "v": 1, "owner": owner.identity.id(), "agent": agent.identity.id(),
            "decision": "approve", "operation": "confirm", "request": id, "version": 1, "prev": id,
            "terms": {
                "type": MEETING,
                "requester": {"agent": agent.identity.id(), "owner": owner.identity.id()},
                "recipient": {"agent": other_agent.identity.id(), "owner": other_owner.identity.id()},
                "agreed": {"duration_min": 30}, "result": {}, "subject": "A meeting", "note": null,
                "supersedes": null,
            },
            "issued_at": NOW, "expires_at": NOW + HOUR_SECS,
        })
        .to_string();
        let approval = owner.sign(APPROVAL_TYPE, approval_payload.as_bytes())?;
        VerifiedApproval::verify(&approval, &owner.identity)
            .map_err(|error| format!("control approval: {error:?}"))?;

        let release = VerifiedRelease::sign(
            &owner_key,
            owner.identity.id(),
            agent.identity.id(),
            None,
            8,
            NOW,
        )
        .map_err(|error| format!("control release: {error}"))?;
        VerifiedRelease::verify(&release, &owner.identity, agent.identity.id())
            .map_err(|error| format!("control release: {error}"))?;

        let from_owner = VerifiedBinding::sign(
            &owner_key,
            &backup_key,
            owner.identity.id(),
            &agent.identity,
            "ana~a.example",
            1,
            NOW,
        )
        .map_err(|error| format!("control binding: {error}"))?;
        let binding = VerifiedBinding::accept(
            &agent_key,
            &from_owner,
            None,
            &owner.identity,
            &agent.identity,
        )
        .map_err(|error| format!("control binding: {error}"))?;

        let history = VerifiedHistory::empty(&agent.identity)
            .record_binding(&agent_key, &agent.identity, &owner.identity, &binding, NOW)
            .map_err(|error| format!("control history: {error}"))?;
        let notice =
            notice_body(&history.document()).map_err(|error| format!("control notice: {error}"))?;
        let history = history
            .encoded()
            .map_err(|error| format!("control history: {error}"))?;
        VerifiedHistory::read(&history).map_err(|error| format!("control history: {error}"))?;
        if !is_notice_body(&notice) {
            return Err("control notice isn't one".to_owned());
        }

        let schemas =
            Schemas::parse(SCHEMAS).map_err(|error| format!("control schemas: {error}"))?;
        let outcome = control_outcome(&schemas)?;

        let retirement = VerifiedRetirement::sign(
            &owner_key,
            owner.identity.id(),
            agent.identity.id(),
            RetirementReason::Finished,
            NOW,
        )
        .map_err(|error| format!("control retirement: {error}"))?;
        VerifiedRetirement::verify(&retirement, &owner.identity)
            .map_err(|error| format!("control retirement: {error}"))?;

        let (invite_link, _) = InviteLink::create(
            "ana~a.example",
            agent.identity.id(),
            vec![serde_json::from_value(json!(MEETING)).map_err(|error| error.to_string())?],
            NOW + HOUR_SECS,
        )
        .map_err(|error| format!("control invitation: {error}"))?;
        InviteLink::parse(&invite_link).map_err(|error| format!("control invitation: {error}"))?;

        let registration = json!({
            "owner_identity": owner.identity.encoded(),
            "agent_identity": agent.identity.encoded(),
            "binding": binding.compact(),
            "signup_id": "",
            "signup_mac": "",
        })
        .to_string();
        check_registration_body(&agent, registration.as_bytes(), true)?;

        let mut documents = Self {
            owner,
            agent,
            other_agent,
            other_owner,
            rules,
            rules_payload,
            person_text,
            person_text_payload,
            where_paid,
            where_paid_payload,
            approval,
            approval_payload,
            release,
            binding: binding.compact().to_owned(),
            from_owner,
            history,
            notice,
            schemas,
            steps: Vec::new(),
            open_envelope: String::new(),
            agent_key,
            outcome,
            retirement,
            invite_link,
            registration,
        };
        documents.prepare_steps()?;
        Ok(documents)
    }

    fn parties(&self) -> Parties {
        Parties {
            requester: Party {
                agent: self.agent.identity.clone(),
                owner: self.owner.identity.clone(),
                binding: String::new(),
            },
            recipient: Party {
                agent: self.other_agent.identity.clone(),
                owner: self.other_owner.identity.clone(),
                binding: String::new(),
            },
        }
    }

    /// An `open`, then what the other side could do next, so a mutated step gets past `prev`.
    fn prepare_steps(&mut self) -> Result<(), String> {
        let offer: Offer = serde_json::from_value(json!({
            "type": MEETING,
            "terms": {"duration_min": 30, "purpose": "follow_up", "mode": "video",
                      "slots": [NOW + 24 * HOUR_SECS, NOW + 25 * HOUR_SECS]},
            "deadline": NOW + 48 * HOUR_SECS,
            "supersedes": null,
        }))
        .map_err(|error| format!("control offer: {error}"))?;
        let open = CheckedStep::open(offer, &self.schemas, self.other_agent.identity.id(), NOW)
            .map_err(|error| format!("control open: {error:?}"))?
            .sign(&self.agent_key, &self.agent.identity, NOW)
            .map_err(|error| format!("control open: {error}"))?;
        let compact = open.compact.clone();
        let verified = VerifiedEnvelope::verify(&compact, &self.agent.identity, NOW)
            .map_err(|error| format!("control open: {error}"))?;
        let mut chain = Chain::new(self.parties(), self.schemas.clone());
        chain
            .apply(&verified)
            .map_err(|error| format!("control open applied: {error:?}"))?;
        self.steps
            .push((Side::Requester, verified.body().to_owned()));
        self.open_envelope = compact;

        let word = |text: &str| -> Result<Word, String> {
            serde_json::from_value(json!(text)).map_err(|error| format!("control word: {error}"))
        };
        for action in [
            Action::Decline {
                reason: word("no_times")?,
            },
            Action::Clarify {
                reason: word("other_times")?,
            },
            Action::Counter {
                terms: fields_of(json!({
                    "duration_min": 30, "purpose": "follow_up", "mode": "video",
                    "slots": [NOW + 30 * HOUR_SECS],
                }))?,
            },
            Action::Accept {
                pick: fields_of(json!({"start": NOW + 24 * HOUR_SECS}))?,
            },
        ] {
            if let Ok(step) = chain.propose(Side::Recipient, action, NOW) {
                let sealed = step
                    .sign(&key_of(&self.other_agent)?, &self.other_agent.identity, NOW)
                    .map_err(|error| format!("control step: {error}"))?;
                let verified =
                    VerifiedEnvelope::verify(&sealed.compact, &self.other_agent.identity, NOW)
                        .map_err(|error| format!("control step: {error}"))?;
                self.steps
                    .push((Side::Recipient, verified.body().to_owned()));
            }
        }
        if self.steps.len() < 3 {
            return Err(format!(
                "only {} controls for a request's steps",
                self.steps.len()
            ));
        }
        // What the run does to each step has to work on the step as it stands.
        for (side, body) in &self.steps {
            let mut tally = Tally::default();
            let compact = self.envelope(*side, body, &mut tally)?;
            let verified = VerifiedEnvelope::verify(&compact, &self.signer_of(*side).identity, NOW)
                .map_err(|error| format!("control envelope: {error}"))?;
            let mut chain = Chain::new(self.parties(), self.schemas.clone());
            if *side == Side::Recipient {
                let open = VerifiedEnvelope::verify(&self.open_envelope, &self.agent.identity, NOW)
                    .map_err(|error| error.to_string())?;
                chain
                    .apply(&open)
                    .map_err(|error| format!("control open: {error:?}"))?;
            }
            chain
                .apply(&verified)
                .map_err(|error| format!("control step {body}: {error:?}"))?;
        }
        Ok(())
    }

    fn signer_of(&self, side: Side) -> &Signer {
        match side {
            Side::Requester => &self.agent,
            Side::Recipient => &self.other_agent,
        }
    }

    fn envelope(&self, side: Side, body: &str, tally: &mut Tally) -> Result<String, String> {
        let (from, to) = match side {
            Side::Requester => (&self.agent, &self.other_agent),
            Side::Recipient => (&self.other_agent, &self.agent),
        };
        let payload = format!(
            r#"{{"v":1,"sender":{},"recipient":{},"body":{},"created_at":{NOW},"expires_at":{},"nonce":{}}}"#,
            quoted(from.identity.id().as_str()),
            quoted(to.identity.id().as_str()),
            Value::String(body.to_owned()),
            NOW + 2 * HOUR_SECS,
            quoted(if side == Side::Requester {
                "AAAAAAAAAAAAAAAAAAAAAA"
            } else {
                ""
            }),
        );
        tally.input.clone_from(&payload.clone().into_bytes());
        from.sign(super::ENVELOPE_TYPE, payload.as_bytes())
    }
}

/// Where each string or number in a JSON document is, leaving out field names.
fn value_spans(document: &str) -> Vec<(usize, usize)> {
    let bytes = document.as_bytes();
    let mut spans = Vec::new();
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        let start = at;
        if byte == b'"' {
            at += 1;
            while let Some(&inner) = bytes.get(at) {
                at += if inner == b'\\' { 2 } else { 1 };
                if inner == b'"' {
                    break;
                }
            }
            if bytes.get(at) != Some(&b':') {
                spans.push((start, at.min(bytes.len())));
            }
        } else if byte.is_ascii_digit() || byte == b'-' {
            while bytes
                .get(at)
                .is_some_and(|inner| inner.is_ascii_digit() || b"-+.eE".contains(inner))
            {
                at += 1;
            }
            spans.push((start, at));
        } else {
            at += 1;
        }
    }
    spans
}

/// One value changed and every field left in place, to something the type's schema might well take.
/// A step has only one valid encoding, so this is what gets past that to what the step means.
fn mutate_a_value(rng: &mut Rng, document: &str) -> Vec<u8> {
    let spans = value_spans(document);
    let Some(&(start, end)) = spans.get(rng.below(spans.len())) else {
        return mutate(rng, document.as_bytes());
    };
    let plausible = [
        (NOW + 3_600 * (rng.below(800) as u64)).to_string(),
        (NOW + 1_800 * (rng.below(800) as u64)).to_string(),
        (15 * rng.below(8)).to_string(),
        quoted(
            ["video", "phone", "in_person", "intro", "other"]
                .get(rng.below(5))
                .copied()
                .unwrap_or(""),
        ),
        quoted(
            ["no_times", "other_times", "shorter", "wrong_person"]
                .get(rng.below(4))
                .copied()
                .unwrap_or(""),
        ),
        quoted(&"ab".repeat(32)),
        quoted(&"ab".repeat(64)),
    ];
    let chosen = if rng.below(2) == 0 {
        plausible
            .get(rng.below(plausible.len()))
            .cloned()
            .unwrap_or_default()
    } else {
        rng.pick(TOKENS).unwrap_or("null").to_owned()
    };
    let mut out = document.as_bytes().to_vec();
    out.splice(start..end, chosen.into_bytes());
    out
}

/// A hostile value in a JSON document, wherever it lands, so it fails on the thing changed.
fn mutate_json(rng: &mut Rng, document: &str) -> Vec<u8> {
    if rng.below(2) == 0 {
        return mutate_a_value(rng, document);
    }
    let Ok(mut value) = serde_json::from_str::<Value>(document) else {
        return mutate(rng, document.as_bytes());
    };
    if rng.below(4) == 0 {
        return mutate(rng, document.as_bytes());
    }
    let mut paths = Vec::new();
    collect_paths(&value, &mut Vec::new(), &mut paths);
    if let Some(path) = paths.get(rng.below(paths.len())) {
        let hostile = pick_hostile(rng);
        change_at(&mut value, path, rng, hostile);
    }
    serde_json::to_vec(&value).unwrap_or_default()
}

fn pick_hostile(rng: &mut Rng) -> Value {
    let word = rng.pick(TOKENS).unwrap_or("null");
    serde_json::from_str(word).unwrap_or_else(|_| Value::String(word.to_owned()))
}

#[derive(Clone)]
enum Step {
    Key(String),
    Index(usize),
}

fn collect_paths(value: &Value, path: &mut Vec<Step>, into: &mut Vec<Vec<Step>>) {
    into.push(path.clone());
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                path.push(Step::Key(key.clone()));
                collect_paths(inner, path, into);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, inner) in items.iter().enumerate() {
                path.push(Step::Index(index));
                collect_paths(inner, path, into);
                path.pop();
            }
        }
        _ => {}
    }
}

fn change_at(value: &mut Value, path: &[Step], rng: &mut Rng, hostile: Value) {
    let Some((last, parents)) = path.split_last() else {
        *value = hostile;
        return;
    };
    let mut at = value;
    for step in parents {
        let next = match step {
            Step::Key(key) => at.get_mut(key.as_str()),
            Step::Index(index) => at.get_mut(*index),
        };
        let Some(next) = next else {
            return;
        };
        at = next;
    }
    match (last, rng.below(3), at) {
        (Step::Key(key), 0, Value::Object(map)) => {
            map.remove(key);
        }
        (Step::Key(_), 1, Value::Object(map)) => {
            map.insert("extra".to_owned(), hostile);
        }
        (Step::Key(key), _, Value::Object(map)) => {
            map.insert(key.clone(), hostile);
        }
        (Step::Index(index), 0, Value::Array(items)) if *index < items.len() => {
            items.remove(*index);
        }
        (Step::Index(index), 1, Value::Array(items)) if *index < items.len() => {
            let copy = items.get(*index).cloned().unwrap_or(Value::Null);
            items.push(copy);
        }
        (Step::Index(index), _, Value::Array(items)) => {
            if let Some(item) = items.get_mut(*index) {
                *item = hostile;
            }
        }
        _ => {}
    }
}

fn tampered(rng: &mut Rng, compact: &str, tally: &mut Tally) -> Option<String> {
    let changed = mutate(rng, compact.as_bytes());
    tally.input.clone_from(&changed);
    String::from_utf8(changed).ok()
}

fn keys_of(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

fn only_known_fields(value: &Value, known: &[&str]) -> Result<(), String> {
    let extra: Vec<String> = keys_of(value)
        .into_iter()
        .filter(|key| !known.contains(&key.as_str()))
        .collect();
    if extra.is_empty() {
        Ok(())
    } else {
        Err(format!("verified with unknown fields {extra:?}"))
    }
}

fn read(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("verified, but unreadable: {error}"))
}

fn at_most(value: &Value, name: &str, most: u64) -> Result<(), String> {
    match value.get(name) {
        Some(found) => match found.as_u64() {
            Some(number) if number <= most => Ok(()),
            _ => Err(format!("verified with {name} {found}")),
        },
        None => Ok(()),
    }
}

fn readable_within(value: &Value, name: &str, most: usize) -> Result<(), String> {
    let Some(text) = value.get(name).and_then(Value::as_str) else {
        return Ok(());
    };
    if text.chars().count() > most {
        return Err(format!("verified with a {name} too long"));
    }
    if text.contains(HIDDEN) {
        return Err(format!("verified with hidden characters in {name}"));
    }
    Ok(())
}

fn check_rules(documents: &Documents, bytes: &[u8]) -> Result<(), String> {
    let value = read(bytes)?;
    only_known_fields(
        &value,
        &[
            "v",
            "owner",
            "agent",
            "seq",
            "issued_at",
            "expires_at",
            "ends_at",
            "paused",
            "reach",
            "permissions",
            "changes",
            "sealing",
            "contacts",
            "invites",
            "limits",
        ],
    )?;
    if let Some(sealing) = value.get("sealing")
        && sealing != "sealed"
        && sealing != "unsealed"
    {
        return Err(format!("rules verified with sealing {sealing}"));
    }
    if field_u64(&value, "v")? != 1 {
        return Err("rules verified with another version".to_owned());
    }
    expect_equal(
        "owner",
        field_str(&value, "owner")?,
        documents.owner.identity.id().as_str(),
    )?;
    // Rules last until replaced. Only an end the owner chose, `ends_at`, stops them, and the old
    // `expires_at` is read and not acted on.
    let issued = field_u64(&value, "issued_at")?;
    let ends = value
        .get("ends_at")
        .map(|_| field_u64(&value, "ends_at"))
        .transpose()?;
    if issued > NOW + CLOCK_TOLERANCE_SECS || ends.is_some_and(|ends| ends <= NOW || ends <= issued)
    {
        return Err(format!("rules verified with dates {issued} to {ends:?}"));
    }
    if field_u64(&value, "seq")? == 0 {
        return Err("rules verified with a seq nobody can pass".to_owned());
    }
    let limits = value.get("limits").ok_or("rules verified with no limits")?;
    only_known_fields(
        limits,
        &[
            "new_requests_per_contact_per_day",
            "open_requests_per_contact",
            "open_approvals",
            "new_from_others_per_day",
            "texts_per_contact_per_day",
            "sends_per_hour",
            "sends_per_day",
        ],
    )?;
    at_most(limits, "open_requests_per_contact", 3)?;
    at_most(limits, "open_approvals", 10)?;
    at_most(limits, "texts_per_contact_per_day", 200)?;
    at_most(limits, "new_requests_per_contact_per_day", 100_000)?;
    at_most(limits, "new_from_others_per_day", 100_000)?;
    let contacts = value
        .get("contacts")
        .and_then(Value::as_array)
        .ok_or("rules verified with no contacts")?;
    let mut seen = HashSet::new();
    for contact in contacts {
        if !seen.insert(field_str(contact, "agent")?.to_owned()) {
            return Err("rules verified naming one contact twice".to_owned());
        }
    }
    Ok(())
}

fn check_person_text(documents: &Documents, bytes: &[u8]) -> Result<(), String> {
    let value = read(bytes)?;
    only_known_fields(
        &value,
        &["v", "owner", "agent", "to", "request", "text", "issued_at"],
    )?;
    if field_u64(&value, "v")? != 1 {
        return Err("a person's words verified with another version".to_owned());
    }
    expect_equal(
        "owner",
        field_str(&value, "owner")?,
        documents.owner.identity.id().as_str(),
    )?;
    readable_within(&value, "text", MAX_PERSON_TEXT_CHARS)
}

/// A place's own string, with nothing that could hide words or end it early.
fn plain_place_text(text: &str) -> Result<(), String> {
    if text.is_empty() || text.contains(HIDDEN) || text.chars().any(char::is_whitespace) {
        return Err(format!("a place verified holding {text:?}"));
    }
    Ok(())
}

/// Where an owner gets paid, read as plain JSON: each place is one of three kinds, in its own shape,
/// with no login, prose or hidden character in it.
fn check_where_paid(documents: &Documents, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_STATEMENT_BYTES {
        return Err(format!("a statement of {} bytes verified", bytes.len()));
    }
    let value = read(bytes)?;
    only_known_fields(&value, &["v", "owner", "places", "issued_at"])?;
    if field_u64(&value, "v")? != 1 {
        return Err("a statement verified with another version".to_owned());
    }
    field_u64(&value, "issued_at")?;
    expect_equal(
        "owner",
        field_str(&value, "owner")?,
        documents.owner.identity.id().as_str(),
    )?;
    let places = value
        .get("places")
        .and_then(Value::as_array)
        .ok_or("a statement verified with no list of places")?;
    if places.is_empty() || places.len() > MAX_PLACES {
        return Err(format!("a statement verified with {} places", places.len()));
    }
    let distinct: HashSet<String> = places.iter().map(Value::to_string).collect();
    if distinct.len() != places.len() {
        return Err("a statement verified naming one place twice".to_owned());
    }
    for place in places {
        match field_str(place, "kind")? {
            "payment_page" => {
                only_known_fields(place, &["kind", "url"])?;
                let url = field_str(place, "url")?;
                plain_place_text(url)?;
                let rest = url
                    .strip_prefix("https://")
                    .ok_or_else(|| format!("a page verified at {url:?}"))?;
                let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
                let host = authority.split(':').next().unwrap_or_default();
                if url.chars().count() > MAX_PAGE_CHARS
                    || authority.contains('@')
                    || !host.contains('.')
                    || host
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
                {
                    return Err(format!("a page verified at {url:?}"));
                }
            }
            "lightning" => {
                only_known_fields(place, &["kind", "to"])?;
                let to = field_str(place, "to")?;
                plain_place_text(to)?;
                if to != to.to_ascii_lowercase() || !(to.contains('@') || to.starts_with("lno1")) {
                    return Err(format!("a Lightning place verified as {to:?}"));
                }
            }
            "onchain" => {
                only_known_fields(place, &["kind", "chain", "address", "asset"])?;
                for name in ["chain", "address", "asset"] {
                    plain_place_text(field_str(place, name)?)?;
                }
                if !field_str(place, "chain")?.contains(':') {
                    return Err("a chain verified with no namespace".to_owned());
                }
            }
            kind => return Err(format!("a place of kind {kind} verified")),
        }
    }
    Ok(())
}

fn check_approval(bytes: &[u8]) -> Result<(), String> {
    let value = read(bytes)?;
    only_known_fields(
        &value,
        &[
            "v",
            "owner",
            "agent",
            "decision",
            "operation",
            "request",
            "version",
            "prev",
            "terms",
            "issued_at",
            "expires_at",
        ],
    )?;
    if field_u64(&value, "v")? != 1 {
        return Err("an approval verified with another version".to_owned());
    }
    let terms = value.get("terms").ok_or("an approval with no terms")?;
    readable_within(terms, "subject", MAX_SUBJECT_CHARS)?;
    readable_within(terms, "note", MAX_NOTE_CHARS)?;
    let decision = field_str(&value, "decision")?;
    if !["approve", "deny"].contains(&decision) {
        return Err(format!("an approval verified deciding {decision}"));
    }
    Ok(())
}

/// A step a fresh chain or the one after an `open` took, read as plain JSON.
fn check_step(body: &str) -> Result<(), String> {
    let value = read(body.as_bytes())?;
    let kind = field_str(&value, "step")?;
    if ![
        "open", "say", "counter", "accept", "confirm", "clarify", "progress", "pause", "resume",
        "deliver", "decline", "cancel", "received",
    ]
    .contains(&kind)
    {
        return Err(format!("applied a step of kind {kind}"));
    }
    for name in ["terms", "fields", "pick", "result"] {
        if let Some(fields) = value.get(name) {
            let count = fields.as_object().map_or(0, serde_json::Map::len);
            if count > MAX_FIELDS_IN_A_STEP {
                return Err(format!("applied a step with {count} in {name}"));
            }
        }
    }
    if let Some(deadline) = value.get("deadline") {
        let deadline = deadline.as_u64().ok_or("a deadline that isn't a number")?;
        if deadline % HOUR_SECS != 0 || deadline > NOW + MAX_DATE_AHEAD_SECS + HOUR_SECS {
            return Err(format!("applied a step with deadline {deadline}"));
        }
    }
    if body.contains(HIDDEN) {
        return Err("applied a step with hidden characters".to_owned());
    }
    Ok(())
}

fn rules(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let owner = &documents.owner.identity;
    let result = if rng.below(2) == 0 {
        let Some(text) = tampered(rng, &documents.rules, tally) else {
            return Ok(());
        };
        let _ = claimed_rules_agent(&text);
        let result = VerifiedRules::verify(&text, owner, 0, NOW).map(|_| ());
        if result.is_ok() && signed_content(&text) != signed_content(&documents.rules) {
            return Err("tampered rules verified".to_owned());
        }
        result
    } else {
        let payload = mutate_json(rng, &documents.rules_payload);
        tally.input.clone_from(&payload);
        let compact = documents.owner.sign(RULES_TYPE, &payload)?;
        let result = VerifiedRules::verify(&compact, owner, 0, NOW).map(|_| ());
        if result.is_ok() {
            check_rules(documents, &payload)?;
        }
        result
    };
    tally.outcome("hostile", "rules", &result);
    Ok(())
}

fn person_text(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let owner = &documents.owner.identity;
    let result = if rng.below(2) == 0 {
        let Some(text) = tampered(rng, &documents.person_text, tally) else {
            return Ok(());
        };
        let result = VerifiedPersonText::verify(&text, owner);
        if result.is_ok() && signed_content(&text) != signed_content(&documents.person_text) {
            return Err("tampered words verified".to_owned());
        }
        result.map(|_| ())
    } else {
        let payload = mutate_json(rng, &documents.person_text_payload);
        tally.input.clone_from(&payload);
        let compact = documents.owner.sign(PERSON_TEXT_TYPE, &payload)?;
        let result = VerifiedPersonText::verify(&compact, owner);
        if result.is_ok() {
            check_person_text(documents, &payload)?;
        }
        result.map(|_| ())
    };
    tally.outcome(
        "hostile",
        "person text",
        &result.map_err(|_| Error::Malformed),
    );
    Ok(())
}

fn where_paid(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let owner = &documents.owner.identity;
    let result = if rng.below(2) == 0 {
        let Some(text) = tampered(rng, &documents.where_paid, tally) else {
            return Ok(());
        };
        let result = VerifiedWherePaid::verify(&text, owner);
        if result.is_ok() && signed_content(&text) != signed_content(&documents.where_paid) {
            return Err("a tampered statement of where an owner gets paid verified".to_owned());
        }
        result.map(|_| ())
    } else {
        let payload = mutate_json(rng, &documents.where_paid_payload);
        tally.input.clone_from(&payload);
        let compact = documents.owner.sign(WHERE_PAID_TYPE, &payload)?;
        let result = VerifiedWherePaid::verify(&compact, owner);
        if result.is_ok() {
            check_where_paid(documents, &payload)?;
        }
        result.map(|_| ())
    };
    tally.outcome(
        "hostile",
        "where paid",
        &result.map_err(|_| Error::Malformed),
    );
    Ok(())
}

fn approval(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let owner = &documents.owner.identity;
    let result = if rng.below(2) == 0 {
        let Some(text) = tampered(rng, &documents.approval, tally) else {
            return Ok(());
        };
        let result = VerifiedApproval::verify(&text, owner);
        if result.is_ok() && signed_content(&text) != signed_content(&documents.approval) {
            return Err("a tampered approval verified".to_owned());
        }
        result.map(|_| ())
    } else {
        let payload = mutate_json(rng, &documents.approval_payload);
        tally.input.clone_from(&payload);
        let compact = documents.owner.sign(APPROVAL_TYPE, &payload)?;
        let result = VerifiedApproval::verify(&compact, owner);
        if result.is_ok() {
            check_approval(&payload)?;
        }
        result.map(|_| ())
    };
    tally.outcome("hostile", "approval", &result.map_err(|_| Error::Malformed));
    Ok(())
}

/// A binding is several signed parts. Whichever is changed, one that verifies has the same content.
fn binding(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let (owner, agent) = (&documents.owner.identity, &documents.agent.identity);
    let original = documents.binding.as_str();
    let parts: Vec<&str> = original.split(PART_SEPARATOR).collect();
    let text = match rng.below(3) {
        0 => {
            let Some(text) = tampered(rng, original, tally) else {
                return Ok(());
            };
            text
        }
        1 => {
            let at = rng.below(parts.len());
            let changed = mutate(rng, parts.get(at).copied().unwrap_or("").as_bytes());
            let changed = String::from_utf8_lossy(&changed).into_owned();
            let rebuilt: Vec<&str> = parts
                .iter()
                .enumerate()
                .map(|(here, part)| if here == at { changed.as_str() } else { *part })
                .collect();
            rebuilt.join(&PART_SEPARATOR.to_string())
        }
        _ => {
            // Dropped, repeated and reordered, each still well signed.
            let mut shuffled = parts.clone();
            match rng.below(3) {
                0 => {
                    shuffled.remove(rng.below(parts.len()));
                }
                1 => {
                    let copy = parts.get(rng.below(parts.len())).copied().unwrap_or("");
                    shuffled.push(copy);
                }
                _ => {
                    let last = shuffled.len().saturating_sub(1);
                    shuffled.swap(rng.below(parts.len()), last);
                }
            }
            shuffled.join(&PART_SEPARATOR.to_string())
        }
    };
    tally.input.clone_from(&text.clone().into_bytes());
    let result = VerifiedBinding::verify(&text, owner, agent).map(|_| ());
    let _ = VerifiedBinding::from_owner(&text);
    let _ = VerifiedBinding::check_from_owner(&text, owner, agent);
    if result.is_ok() {
        // A fourth part is an old owner's release, which only moving the agent reads and checks.
        let signed: Vec<&str> = text.split(PART_SEPARATOR).map(signed_content).collect();
        let same = signed
            .iter()
            .take(parts.len())
            .copied()
            .eq(parts.iter().map(|part| signed_content(part)));
        if !same {
            return Err("a changed binding verified".to_owned());
        }
        if signed.len() > parts.len() {
            tally.note("accepted: a binding with a release nothing has read yet");
        }
    }
    tally.outcome("hostile", "binding", &result);
    Ok(())
}

/// What an agent is asked to add its half to. Signed by the owner, so only the checks stand in the way.
fn binding_to_accept(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let (owner, agent) = (&documents.owner.identity, &documents.agent.identity);
    let (half, vouch) = documents
        .from_owner
        .split_once(PART_SEPARATOR)
        .ok_or("no vouch")?;
    let payload = payload_of(half)?;
    let changed = mutate_json(rng, &payload);
    tally.input.clone_from(&changed);
    let signed = documents.owner.sign("splint-binding", &changed)?;
    let from_owner = format!("{signed}{PART_SEPARATOR}{vouch}");
    let result = VerifiedBinding::accept(&documents.agent_key, &from_owner, None, owner, agent);
    if let Ok(accepted) = &result {
        let value = read(&changed)?;
        expect_equal("owner", field_str(&value, "owner")?, owner.id().as_str())?;
        expect_equal("agent", field_str(&value, "agent")?, agent.id().as_str())?;
        expect_equal("address", accepted.address(), field_str(&value, "address")?)?;
        if splint_core::parse_address(accepted.address()).is_err() {
            return Err("a binding verified at no real address".to_owned());
        }
    }
    tally.outcome("hostile", "binding to accept", &result.map(|_| ()));
    let text = String::from_utf8_lossy(&mutate(rng, documents.release.as_bytes())).into_owned();
    let _ = claimed_released_agent(&text);
    let release = VerifiedRelease::verify(&text, owner, agent.id()).map(|_| ());
    if release.is_ok() && signed_content(&text) != signed_content(&documents.release) {
        return Err("a changed release verified".to_owned());
    }
    let payload = mutate_json(rng, &payload_of(&documents.release)?);
    tally.input.clone_from(&payload);
    let compact = documents.owner.sign(RELEASE_TYPE, &payload)?;
    let result = VerifiedRelease::verify(&compact, owner, agent.id());
    if result.is_ok() {
        let value = read(&payload)?;
        expect_equal("agent", field_str(&value, "agent")?, agent.id().as_str())?;
        expect_equal("owner", field_str(&value, "owner")?, owner.id().as_str())?;
    }
    tally.outcome("hostile", "release", &result.map(|_| ()));
    Ok(())
}

/// A history stands on its signed events, so nothing changed in one can verify as anything but what
/// it was, and a reader never gets half of one. A history that verifies is the whole control or the
/// empty one before it, as an agent can always show less, which a reader then finds is behind.
fn history(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let changed = mutate_json(rng, &documents.history);
    tally.input.clone_from(&changed);
    let text = String::from_utf8_lossy(&changed).into_owned();
    let result = VerifiedHistory::read(&text);
    if let Ok(read_back) = &result {
        let control = HistoryDocument::parse(&documents.history).map_err(|e| e.to_string())?;
        let got = read_back.document();
        let events: Vec<&str> = got
            .events
            .iter()
            .map(|event| signed_content(event))
            .collect();
        let wanted: Vec<&str> = control
            .events
            .iter()
            .map(|event| signed_content(event))
            .collect();
        if !events.is_empty() && events != wanted {
            return Err("a changed history verified".to_owned());
        }
        if read_back.identity().encoded() != documents.agent.identity.encoded()
            && !events.is_empty()
        {
            return Err("a history verified for someone else".to_owned());
        }
    }
    tally.outcome("hostile", "history", &result.map(|_| ()));

    let changed = mutate_json(rng, &documents.notice);
    tally.input.clone_from(&changed);
    let body = String::from_utf8_lossy(&changed).into_owned();
    let result = match notice_in(&body) {
        Some(document) => VerifiedHistory::verify(document).map(|_| ()),
        None => Err(Error::Malformed),
    };
    tally.outcome("hostile", "change notice", &result);
    Ok(())
}

/// Steps through a whole envelope with a real signature, so they reach the parser and the state table.
fn step(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let Some((side, control)) = documents.steps.get(rng.below(documents.steps.len())) else {
        return Err("no steps".to_owned());
    };
    let changed = mutate_json(rng, control);
    let body = String::from_utf8_lossy(&changed).into_owned();
    let compact = documents.envelope(*side, &body, tally)?;
    let sender = &documents.signer_of(*side).identity;
    let Ok(envelope) = VerifiedEnvelope::verify(&compact, sender, NOW) else {
        tally.outcome("hostile", "step", &Err(Error::Malformed));
        return Ok(());
    };
    let _ = is_step_body(envelope.body());
    let _ = request_of(&envelope);
    let mut chain = Chain::new(documents.parties(), documents.schemas.clone());
    if *side == Side::Recipient {
        let open =
            VerifiedEnvelope::verify(&documents.open_envelope, &documents.agent.identity, NOW)
                .map_err(|error| error.to_string())?;
        chain
            .apply(&open)
            .map_err(|error| format!("control open: {error:?}"))?;
    }
    let result = chain.apply(&envelope);
    if result.is_ok() {
        check_step(envelope.body())?;
        let _ = chain.outcome();
    }
    tally.outcome(
        "hostile",
        "step",
        &result.map(|_| ()).map_err(|_| Error::Malformed),
    );

    // Read back from storage, where a list of steps is walked with no clock to help.
    let walked = Chain::walk(
        documents.parties(),
        documents.schemas.clone(),
        &[documents.open_envelope.clone(), compact],
    );
    tally.outcome(
        "hostile",
        "chain walk",
        &walked.map(|_| ()).map_err(|_| Error::Malformed),
    );
    Ok(())
}

/// The vector with every signature in a finished request's bundle, as nothing here can make one quickly.
fn control_outcome(schemas: &Schemas) -> Result<Value, String> {
    let vectors: Value =
        serde_json::from_str(REQUEST_VECTORS).map_err(|error| error.to_string())?;
    let outcome = vectors
        .get("vectors")
        .and_then(Value::as_array)
        .and_then(|all| {
            all.iter().find(|vector| {
                vector.get("check").and_then(Value::as_str) == Some("outcome.verify")
                    && vector.get("case").and_then(Value::as_str) == Some("valid")
            })
        })
        .and_then(|vector| vector.pointer("/input/outcome"))
        .cloned()
        .ok_or("no valid outcome in the vectors")?;
    let parsed: Outcome = serde_json::from_value(outcome.clone())
        .map_err(|error| format!("control outcome: {error}"))?;
    parsed
        .verify(schemas)
        .map_err(|error| format!("control outcome: {error}"))?;
    Ok(outcome)
}

/// A null field and no field read the same.
fn without_nulls(value: Option<&Value>) -> Option<Value> {
    fn cleaned(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .filter(|(_, inner)| !inner.is_null())
                    .map(|(key, inner)| (key.clone(), cleaned(inner)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }
    value.map(cleaned)
}

/// What an outcome proves is what its approvals signed, so that can't change whatever else does.
fn outcome(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let control = documents.outcome.to_string();
    let changed = mutate_json(rng, &control);
    tally.input.clone_from(&changed);
    let result = serde_json::from_slice::<Outcome>(&changed)
        .map_err(|_| Error::Malformed)
        .and_then(|parsed| parsed.verify(&documents.schemas).map(|_| ()));
    if result.is_ok() {
        let value = read(&changed)?;
        for name in ["terms", "request"] {
            if without_nulls(value.get(name)) != without_nulls(documents.outcome.get(name)) {
                return Err(format!("an outcome with another {name} verified"));
            }
        }
        if field_u64(&value, "v")? != 1 {
            return Err("an outcome verified with another version".to_owned());
        }
    }
    tally.outcome("hostile", "outcome", &result);
    Ok(())
}

/// An access proof that does fit whatever body it's for, so a mutated body reaches its own checks.
fn check_registration_body(agent: &Signer, body: &[u8], must_pass: bool) -> Result<bool, String> {
    let proof = format!(
        r#"{{"signer":{},"host":{},"method":"POST","path":{},"body_sha256":{},"issued_at":{NOW}}}"#,
        quoted(agent.identity.id().as_str()),
        quoted(HOST),
        quoted(splint_core::REGISTER_PATH),
        quoted(&super::sha256_hex(body)),
    );
    let compact = agent.sign(super::ACCESS_TYPE, proof.as_bytes())?;
    let result = VerifiedRegistration::verify(&compact, body, HOST, NOW);
    if must_pass {
        result.map_err(|error| format!("control registration: {error}"))?;
        return Ok(true);
    }
    Ok(result.is_ok())
}

fn registration(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let changed = mutate_json(rng, &documents.registration);
    tally.input.clone_from(&changed);
    let passed = check_registration_body(&documents.agent, &changed, false)?;
    if passed {
        let value = read(&changed)?;
        only_known_fields(
            &value,
            &[
                "owner_identity",
                "agent_identity",
                "binding",
                "signup_id",
                "signup_mac",
            ],
        )?;
        expect_equal(
            "agent",
            field_str(&value, "agent_identity")?,
            &documents.agent.identity.encoded(),
        )?;
        expect_equal(
            "owner",
            field_str(&value, "owner_identity")?,
            &documents.owner.identity.encoded(),
        )?;
    }
    tally.outcome(
        "hostile",
        "registration",
        &if passed {
            Ok(())
        } else {
            Err(Error::Malformed)
        },
    );
    Ok(())
}

fn retirement(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    let documents = &world.documents;
    let owner = &documents.owner.identity;
    let Some(text) = tampered(rng, &documents.retirement, tally) else {
        return Ok(());
    };
    let _ = claimed_retired_agent(&text);
    let result = VerifiedRetirement::verify(&text, owner).map(|_| ());
    if result.is_ok() && signed_content(&text) != signed_content(&documents.retirement) {
        return Err("a changed retirement verified".to_owned());
    }
    tally.outcome("hostile", "retirement", &result);
    let payload = mutate_json(rng, &payload_of(&documents.retirement)?);
    tally.input.clone_from(&payload);
    let compact = documents.owner.sign(RETIREMENT_TYPE, &payload)?;
    let result = VerifiedRetirement::verify(&compact, owner).map(|_| ());
    if result.is_ok() {
        let value = read(&payload)?;
        expect_equal("owner", field_str(&value, "owner")?, owner.id().as_str())?;
    }
    tally.outcome("hostile", "retirement re-signed", &result);
    Ok(())
}

/// A link is whatever someone pastes, so it's only ever read as data.
fn invite(world: &World, rng: &mut Rng, tally: &mut Tally) {
    let changed = mutate(rng, world.documents.invite_link.as_bytes());
    tally.input.clone_from(&changed);
    let text = String::from_utf8_lossy(&changed);
    let result = InviteLink::parse(&text).and_then(|link| {
        link.redeem_for(world.documents.other_agent.identity.id(), NOW)
            .map(|proof| {
                let _ = redeem_body(&proof).map(|body| redeem_proof_in(&body));
                let _ = claimed_invite(&proof);
            })
    });
    tally.outcome("hostile", "invitation link", &result);
}

/// A schema is the owner's side's word on what fits a type, so it's read as hostile too.
fn schema(rng: &mut Rng, tally: &mut Tally) {
    let original = SCHEMAS
        .get(rng.below(SCHEMAS.len()))
        .copied()
        .unwrap_or(b"{}");
    let changed = mutate_json(rng, &String::from_utf8_lossy(original));
    tally.input.clone_from(&changed);
    let result = Schemas::parse([changed.as_slice()]).map(|_| ());
    tally.outcome("hostile", "schema", &result);
}

pub fn one_iteration(world: &World, rng: &mut Rng, tally: &mut Tally) -> Result<(), String> {
    match rng.below(13) {
        12 => where_paid(world, rng, tally),
        8 => outcome(world, rng, tally),
        9 => registration(world, rng, tally),
        10 => retirement(world, rng, tally),
        11 => {
            invite(world, rng, tally);
            Ok(())
        }
        0 => rules(world, rng, tally),
        1 => binding(world, rng, tally),
        2 => binding_to_accept(world, rng, tally),
        3 => history(world, rng, tally),
        4 => person_text(world, rng, tally),
        5 => approval(world, rng, tally),
        6 => step(world, rng, tally),
        _ => {
            schema(rng, tally);
            Ok(())
        }
    }
}

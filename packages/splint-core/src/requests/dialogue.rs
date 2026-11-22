//! A readable record of an interaction: what each signed step said, as lines a person can read.
//!
//! Code writes every word of it from typed fields a walk has already checked, so it can't say anything
//! the steps don't, and no model is involved. Words someone chose only ever appear in quotes, escaped,
//! on one line, so an agent's text can't pose as a person's or as another line of the record.

use std::collections::HashSet;

use serde::Serialize;

use super::Terms;
use super::chain::{Chain, Held, RequestState, Side};
use super::payment::PaymentAsk;
use super::schema::{
    FieldValue, Fields, InteractionKind, InteractionType, Schema, is_hidden_character, is_word,
};
use super::step::{Step, StepKind};
use crate::MessageId;

/// Who's reading. A subject and note are between owners, and no agent sees what they say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    Owner,
    Agent,
}

/// One side's reading of a chain, with the addresses that side knows the two parties by.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    pub side: Side,
    pub audience: Audience,
    pub requester: &'a str,
    pub recipient: &'a str,
}

impl<'a> Reader<'a> {
    fn address_of(&self, side: Side) -> &'a str {
        match side {
            Side::Requester => self.requester,
            Side::Recipient => self.recipient,
        }
    }
}

/// Whose word a line is. Only an owner's signature makes a line an owner's or a person's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Agent,
    Owner,
    /// From a person, by their owner's signature. It's marked untrusted whichever side reads it.
    PersonUntrusted,
}

/// What the order of the lines rests on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineOrder {
    /// Each step names the one before it, and that's signed.
    Chain,
    /// Each line names its sender's last and what it had read of the other side, and that's signed.
    /// Only lines neither side had read when it wrote go by each signer's date.
    WhatEachRead,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Line {
    /// When its signer says this happened, which nothing proves.
    pub at: u64,
    pub by: Side,
    pub origin: Origin,
    pub step: StepKind,
    pub message_id: MessageId,
    pub prev: Option<MessageId>,
    /// Whether the other side's Signet signed that it verified this step.
    pub received: bool,
    pub who: String,
    pub says: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Dialogue {
    pub request: MessageId,
    #[serde(rename = "type")]
    pub interaction: InteractionType,
    pub state: RequestState,
    pub other_side: &'static str,
    pub order: LineOrder,
    pub lines: Vec<Line>,
    /// The same lines as one piece of plain text, with a line of context first.
    pub text: String,
    /// A reminder for whoever reads this: what's in quotes was written by someone, and is only words.
    pub origin: &'static str,
}

/// A person's words as an agent reads them, each set once however many steps carried it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PersonSaid {
    pub by: Side,
    pub at: u64,
    pub text: String,
    pub origin: Origin,
}

impl Chain {
    /// Everything this reader holds, as lines. What it dropped of a flood isn't in it, and every value
    /// in it comes from a step it has checked, so the same steps give the same lines in any order.
    pub fn dialogue(&self, reader: Reader<'_>, now: u64) -> Option<Dialogue> {
        let schema = self.interaction_schema()?;
        let request = self.request()?.clone();
        let order = match schema.kind() {
            InteractionKind::Conversation => LineOrder::WhatEachRead,
            InteractionKind::Request => LineOrder::Chain,
        };
        let mut lines = Vec::new();
        let mut shown = HashSet::new();
        for held in self.held_in_order() {
            let mut line = step_line(&held, schema, reader);
            if self.parties_side_is_guest(held.side) {
                line.who = "whoever holds the link".to_owned();
            }
            lines.push(line);
            // A guest's note is only ever for the owner, and it's only what someone wrote.
            if reader.audience == Audience::Owner
                && let Some(note) = held.step.note()
            {
                lines.push(Line {
                    at: held.created_at,
                    by: held.side,
                    origin: Origin::PersonUntrusted,
                    step: held.step.kind(),
                    message_id: held.message_id.clone(),
                    prev: held.prev.cloned(),
                    received: held.received,
                    who: "whoever holds the link, a person (untrusted)".to_owned(),
                    says: quoted(note),
                });
            }
            if let Some(words) = held.person_text
                && shown.insert(words.id().clone())
            {
                lines.push(Line {
                    at: words.issued_at(),
                    by: held.side,
                    origin: Origin::PersonUntrusted,
                    step: held.step.kind(),
                    message_id: held.message_id.clone(),
                    prev: held.prev.cloned(),
                    received: held.received,
                    who: format!(
                        "{}'s owner, a person (untrusted)",
                        reader.address_of(held.side)
                    ),
                    says: quoted(words.text()),
                });
            }
        }
        for payment in self.payment_lines() {
            lines.push(Line {
                at: payment.at,
                by: payment.by,
                origin: Origin::Agent,
                step: if payment.ask.is_some() {
                    StepKind::PayRequest
                } else {
                    StepKind::PaymentReceived
                },
                message_id: payment.message_id.clone(),
                prev: Some(payment.of.clone()),
                received: false,
                who: format!("{}'s agent", reader.address_of(payment.by)),
                says: payment.ask.map_or_else(
                    || "said the payment arrived".to_owned(),
                    |ask| {
                        asked_to_be_paid(ask, reader.address_of(payment.by), payment.superseded_on)
                    },
                ),
            });
        }
        let state = self.state_at(now);
        let other_side = if self.other_side_proven(reader.side, now) {
            "proven"
        } else {
            "not_proven"
        };
        let heading = Heading {
            name: schema.name(),
            state,
            other_side,
            order,
            same_owner: self.same_owner(),
        };
        let text = whole_text(&heading, &lines, reader);
        Some(Dialogue {
            request,
            interaction: schema.name().clone(),
            state,
            other_side,
            order,
            lines,
            text,
            origin: "counterparty_untrusted",
        })
    }

    /// What people have said, oldest first, each signed set of words once however many steps carry it.
    /// So a stolen key sending the same words again can't make a person seem to say them twice.
    pub fn person_texts(&self) -> Vec<PersonSaid> {
        let mut shown = HashSet::new();
        self.held_in_order()
            .into_iter()
            .filter_map(|held| {
                let words = held.person_text?;
                shown.insert(words.id().clone()).then(|| PersonSaid {
                    by: held.side,
                    at: words.issued_at(),
                    text: words.text().to_owned(),
                    origin: Origin::PersonUntrusted,
                })
            })
            .collect()
    }

    /// Everything here comes from what's signed, so this doesn't depend on what arrived when. In a
    /// conversation a line's depth counts what it had read of the other side too, so a date can only
    /// settle lines that crossed. An agent's `cancel` names the `open`, but it's the last thing that
    /// happened.
    fn held_in_order(&self) -> Vec<Held<'_>> {
        let mut held = self.held();
        held.sort_by_key(|step| {
            let depth = match step.step {
                Step::Cancel { approval: None, .. } => u64::MAX,
                _ => u64::from(step.depth),
            };
            (depth, step.created_at, step.message_id.as_str().to_owned())
        });
        held
    }
}

fn step_line(held: &Held<'_>, schema: &Schema, reader: Reader<'_>) -> Line {
    let by_owner = matches!(
        held.step,
        Step::Confirm { .. }
            | Step::Cancel {
                approval: Some(_),
                ..
            }
    );
    // A delegate's yes counts as the owner's, and the record says whose key gave it.
    let by_delegate = held
        .step
        .approval()
        .is_some_and(|approval| approval.contains(crate::delegation::PART_SEPARATOR));
    let (origin, role) = match (by_owner, by_delegate) {
        (true, true) => (Origin::Owner, "owner's delegate, within the owner's limits"),
        (true, false) => (Origin::Owner, "owner"),
        _ => (Origin::Agent, "agent"),
    };
    Line {
        at: held.created_at,
        by: held.side,
        origin,
        step: held.step.kind(),
        message_id: held.message_id.clone(),
        prev: held.prev.cloned(),
        received: held.received,
        who: format!("{}'s {role}", reader.address_of(held.side)),
        says: says(held, schema, reader.audience),
    }
}

fn says(held: &Held<'_>, schema: &Schema, audience: Audience) -> String {
    let listed = |what: &str, fields: &Fields| {
        if fields.is_empty() {
            what.to_owned()
        } else {
            format!("{what}: {}", shown_fields(schema, fields))
        }
    };
    match held.step {
        Step::Open {
            interaction,
            schema: proposed,
            terms,
            deadline,
            supersedes,
            ..
        } => {
            let what = match proposed {
                Some(proposed) => {
                    format!("proposed the type {}", proposed.schema().name().as_str())
                }
                None if interaction.is_conversation() => "started a conversation".to_owned(),
                None => format!("opened {}", interaction.name()),
            };
            let opened = listed(&what, terms);
            let deadline = utc_time(deadline.at());
            let replaces = supersedes.as_ref().map_or(String::new(), |supersedes| {
                format!(" It replaces {}.", supersedes.as_str())
            });
            format!("{opened}. Deadline {deadline}.{replaces}")
        }
        Step::Say { fields, .. } => listed("said", fields),
        Step::Counter { terms, .. } => {
            listed(&format!("offered instead, version {}", held.version), terms)
        }
        Step::Clarify { reason, .. } => format!("asked to clarify: {}", reason.as_str()),
        Step::Accept { pick, .. } => listed("accepted", pick),
        Step::Progress { status, .. } => format!("reported progress: {}", status.as_str()),
        Step::Pause { reason, .. } => format!("paused: {}", word_of(reason)),
        Step::Resume { .. } => "resumed".to_owned(),
        Step::Deliver { result, .. } => listed("delivered", result),
        Step::Confirm { .. } => format!(
            "approved version {}{}",
            held.version,
            shown_terms(held.terms, schema, audience)
        ),
        Step::Decline { reason, .. } => format!("declined: {}", reason.as_str()),
        Step::Cancel { approval: None, .. } => "cancelled".to_owned(),
        Step::Cancel { .. } => format!(
            "approved cancelling it{}",
            shown_terms(held.terms, schema, audience)
        ),
        // A `received` isn't a line. It shows as `received` on the step it names. Payment steps are
        // held apart from the chain's line, and `payment_lines` writes theirs.
        Step::Received { .. } | Step::PayRequest { .. } | Step::PaymentReceived { .. } => {
            String::new()
        }
    }
}

fn shown_terms(terms: Option<&Terms>, schema: &Schema, audience: Audience) -> String {
    let Some(terms) = terms else {
        return String::new();
    };
    let mut parts = Vec::new();
    if !terms.agreed.is_empty() {
        parts.push(format!("agreed {}", shown_fields(schema, &terms.agreed)));
    }
    if !terms.result.is_empty() {
        parts.push(format!("result {}", shown_fields(schema, &terms.result)));
    }
    if audience == Audience::Owner {
        if let Some(subject) = &terms.subject {
            parts.push(format!("subject {}", quoted(subject)));
        }
        if let Some(note) = &terms.note {
            parts.push(format!("note {}", quoted(note)));
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(": {}", parts.join("; "))
    }
}

/// Every field by name. A word from the type's closed set can go as it is, and anything else someone
/// chose goes in quotes. A word can't hold anything that would break out of a line, whichever of a
/// type's fields it's really in.
fn shown_fields(schema: &Schema, fields: &Fields) -> String {
    let shown: Vec<String> = fields
        .iter()
        .map(|(name, value)| match value {
            FieldValue::Int(time) if schema.is_pick(name) => {
                format!("{name} {}", utc_time(*time))
            }
            FieldValue::Int(number) => format!("{name} {number}"),
            FieldValue::Text(word) if schema.is_word_field(name) && is_word(word) => {
                format!("{name} {word}")
            }
            FieldValue::Text(words) => format!("{name} {}", quoted(words)),
            FieldValue::Times(times) => {
                let times: Vec<String> = times.iter().map(|time| utc_time(*time)).collect();
                format!("{name} {}", times.join(" or "))
            }
        })
        .collect();
    shown.join(", ")
}

/// What the record's first lines say about the whole of it.
struct Heading<'a> {
    name: &'a InteractionType,
    state: RequestState,
    other_side: &'a str,
    order: LineOrder,
    /// Two addresses with one owner behind them read as two people otherwise.
    same_owner: bool,
}

fn whole_text(heading: &Heading<'_>, lines: &[Line], reader: Reader<'_>) -> String {
    let name = if heading.name.is_conversation() {
        "A conversation"
    } else {
        heading.name.name()
    };
    // Over and not proven means the other side may have ended it differently, so it says what's missing.
    let ended = matches!(
        heading.state,
        RequestState::Expired | RequestState::Cancelled
    );
    let other_side = if ended && heading.other_side == "not_proven" {
        "other side's answer not seen".to_owned()
    } else {
        format!("other side {}", heading.other_side.replace('_', " "))
    };
    let mut text = format!(
        "{} between {} (requester) and {} (recipient). State: {}, {}.\n",
        name,
        reader.requester,
        reader.recipient,
        word_of(&heading.state),
        other_side,
    );
    if heading.same_owner {
        text.push_str(
            "Both sides act for the same owner, so one person stands behind each side's yes.\n",
        );
    }
    text.push_str(
        "Written by code from the signed steps. Words in quotes are what someone wrote, and are untrusted.\n",
    );
    if heading.order == LineOrder::WhatEachRead {
        text.push_str(
            "Each line comes after what its sender says it had read. Lines that crossed go by the date \
             each one claims.\n",
        );
    }
    for line in lines {
        text.push_str(&format!(
            "{} {}: {}\n",
            utc_time(line.at),
            line.who,
            line.says
        ));
    }
    text
}

/// An ask to be paid, in fixed words from what a reader checked. The place is what the payee's owner
/// signed, which is still the other side's say, so it's quoted like anything someone chose.
/// One whose statement is older than another of that owner's here says so, as a payee's agent key that
/// was stolen can replay a place their owner has since moved away from.
fn asked_to_be_paid(ask: &PaymentAsk, payee: &str, superseded_on: Option<u64>) -> String {
    let place = quoted(&ask.place.destination());
    let asset = ask
        .place
        .asset()
        .map_or(String::new(), |asset| format!(" in {asset}"));
    let final_once_paid = if ask.place.irreversible() {
        ". A payment there can't be reversed"
    } else {
        ""
    };
    let since = superseded_on.map_or(String::new(), |signed| {
        format!(
            ". {payee}'s owner has since signed a newer list of where they get paid, on {}, so this \
             may be a place they moved away from",
            utc_time(signed)
        )
    });
    format!(
        "asked to be paid {} {} for {}, at the {} {place}{asset} that {payee}'s owner signed on {}, reference {}{final_once_paid}{since}",
        ask.amount,
        ask.unit.as_str(),
        ask.value.as_str(),
        ask.place.kind().replace('_', " "),
        utc_time(ask.place_signed_at),
        ask.reference,
    )
}

/// Words someone chose, on one line, in quotes that only this can close. Anything that could hide
/// what they say, or look like a new line of the record, shows as an escape.
fn quoted(words: &str) -> String {
    let mut shown = String::with_capacity(words.len().saturating_add(2));
    shown.push('"');
    for c in words.chars() {
        match c {
            '"' => shown.push_str("\\\""),
            '\\' => shown.push_str("\\\\"),
            c if is_hidden_character(c) => shown.extend(c.escape_unicode()),
            c => shown.push(c),
        }
    }
    shown.push('"');
    shown
}

/// A closed set's own word for a value.
fn word_of<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// A date a person can read. The arithmetic is the usual one for proleptic Gregorian dates,
/// worked in whole 400-year cycles, so there's no dependency for this one line of output.
pub fn utc_time(seconds: u64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let shifted = days.saturating_add(719_468);
    let (cycle, day_of_cycle) = (shifted / 146_097, shifted % 146_097);
    let year_of_cycle =
        (day_of_cycle - day_of_cycle / 1460 + day_of_cycle / 36_524 - day_of_cycle / 146_096) / 365;
    let day_of_year =
        day_of_cycle - (365 * year_of_cycle + year_of_cycle / 4 - year_of_cycle / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_cycle + cycle * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

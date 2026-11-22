//! What makes one type of interaction different from another: a small typed document, checked in
//! code. Core knows the chain, the states and the approvals, and nothing about what any type means.
//! See `docs/protocol.md`.
//!
//! A schema names every field a step of that type can carry and what fits in it, so a value that
//! doesn't fit is refused by the same code whatever the type is. Schemas are the operator's to load,
//! and the owner's rules say which of them each contact may use.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};

use super::step::MAX_DATE_AHEAD_SECS;
use super::{Refused, Side};
use crate::Error;

const MAX_WORD_CHARS: usize = 32;
const MAX_TYPE_NAME_CHARS: usize = 24;
const MAX_TYPE_VERSION_DIGITS: usize = 4;
const MAX_FIELDS: usize = 16;
/// SHA-256 in base32.
const FINGERPRINT_CHARS: usize = 52;
const FINGERPRINT_TAG: &[u8] = b"splint type v1";
/// Core's one type of its own, by which two agents agree a type for themselves.
pub const PROPOSAL: &str = "type/1";
/// No schema can be called this, whatever its version.
const RESERVED_WORD: &str = "type";

/// What core holds a proposed schema to, in each side's Signet and in every reader, so that agreeing a
/// type, which no owner signs, says only so much. See "What a fooled agent can still leak" in
/// `docs/protocol.md`. Provisional for Nenye.
pub const MAX_PROPOSED_BYTES: usize = 2 * 1024;
/// Entries in any one list a proposed schema holds, and fields in any one of its sections.
const MAX_PROPOSED_ENTRIES: usize = 16;
/// Every character of a name, word or number a proposed schema holds, together.
pub const MAX_CHOSEN_CHARS: usize = 512;
/// What every language reading a schema holds exactly.
const MAX_PROPOSED_NUMBER: u64 = (1 << 53) - 1;
const MAX_PROPOSED_TEXT_CHARS: usize = 500;
/// Proposals a day each way with one contact, counting each `type/1` opened.
pub const PROPOSALS_PER_CONTACT_PER_DAY: usize = 2;
/// Types one Signet holds agreed with one contact.
pub const MAX_AGREED_PER_CONTACT: usize = 32;
/// Why an agent declines a proposal: core's own words, the same for every agent. `no_reason` is always
/// allowed too.
pub const PROPOSAL_DECLINES: [&str; 5] = [
    "unsafe_type",
    "too_big",
    "name_taken",
    "not_needed",
    "not_understood",
];
/// The longest line of words a plain conversation's `say` carries.
const CONVERSATION_TEXT_CHARS: usize = 500;
/// The most a step of a type can carry, in bits worked out as [`Document::needs_text`] says, for a
/// contact whose owner hasn't signed `text`. Every example in `spec/schemas` fits. Without it, two
/// agents could agree a type of sixteen 53-bit numbers and carry whatever they like in them, which
/// `text` exists to stop. Provisional for Nenye.
pub const MAX_STEP_BITS_WITHOUT_TEXT: u32 = 64;

pub(super) fn is_word(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_WORD_CHARS
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// A short lowercase word. Prose doesn't fit, so a reason or a status can't carry an instruction.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Word(String);

impl Word {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Word {
    type Error = Refused;

    fn try_from(text: String) -> Result<Self, Refused> {
        if is_word(&text) {
            Ok(Self(text))
        } else {
            Err(Refused::Malformed)
        }
    }
}

impl From<Word> for String {
    fn from(word: Word) -> Self {
        word.0
    }
}

/// The name of a schema and its version, a word then a slash and a number, as a schema names itself.
/// Two schemas can share one, so on the wire a type goes by its [`InteractionType`], which adds the
/// fingerprint of its one encoding.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TypeName(String);

impl TypeName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_type_name(text: &str) -> bool {
    text.split_once('/').is_some_and(|(name, version)| {
        is_word(name)
            && name.len() <= MAX_TYPE_NAME_CHARS
            && !version.is_empty()
            && version.len() <= MAX_TYPE_VERSION_DIGITS
            && version.bytes().all(|byte| byte.is_ascii_digit())
    })
}

impl TryFrom<String> for TypeName {
    type Error = Refused;

    fn try_from(text: String) -> Result<Self, Refused> {
        if is_type_name(&text) {
            Ok(Self(text))
        } else {
            Err(Refused::Malformed)
        }
    }
}

impl From<TypeName> for String {
    fn from(name: TypeName) -> Self {
        name.0
    }
}

/// What an interaction's type is: core's own plain conversation, which an `open` names by leaving
/// `type` out, core's own `type/1`, by which two agents agree a type, or a type they agreed, by its
/// name and the fingerprint of its schema's one encoding, as `haircut/1@<52 base32 characters>`. Two
/// different schemas can't share one, so two sides can never read one type two ways.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InteractionType(Named);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Named {
    Conversation,
    Proposal,
    Agreed(String),
}

impl InteractionType {
    /// Core's plain conversation, whose `open` has no `type`.
    pub fn conversation() -> Self {
        Self(Named::Conversation)
    }

    /// Core's `type/1`, which proposes a type.
    pub fn proposal() -> Self {
        Self(Named::Proposal)
    }

    pub fn is_conversation(&self) -> bool {
        self.0 == Named::Conversation
    }

    pub fn is_proposal(&self) -> bool {
        self.0 == Named::Proposal
    }

    /// As it's written on the wire. The plain conversation is written by leaving `type` out, so it's
    /// empty here.
    pub fn as_str(&self) -> &str {
        match &self.0 {
            Named::Conversation => "",
            Named::Proposal => PROPOSAL,
            Named::Agreed(id) => id,
        }
    }

    /// The name and version alone, as a person reads it.
    pub fn name(&self) -> &str {
        let id = self.as_str();
        id.split_once(FINGERPRINT_SEPARATOR)
            .map_or(id, |(name, _)| name)
    }

    /// Whether this is a type two agents agreed, rather than one of core's own.
    pub fn is_agreed(&self) -> bool {
        matches!(self.0, Named::Agreed(_))
    }

    /// The start of its fingerprint, enough for a person to tell it from another type of the same
    /// name and version. Core's own have none.
    pub fn short_fingerprint(&self) -> Option<String> {
        self.as_str()
            .split_once(FINGERPRINT_SEPARATOR)
            .map(|(_, fingerprint)| fingerprint.chars().take(SHORT_FINGERPRINT_CHARS).collect())
    }
}

/// Characters of a fingerprint shown to a person: 40 bits, so a lookalike made to match them takes
/// about 2^40 tries, and a person still reads them at a glance. Provisional.
const SHORT_FINGERPRINT_CHARS: usize = 8;

/// Between a type's name and its fingerprint.
const FINGERPRINT_SEPARATOR: char = '@';

impl TryFrom<String> for InteractionType {
    type Error = Refused;

    fn try_from(text: String) -> Result<Self, Refused> {
        if text == PROPOSAL {
            return Ok(Self::proposal());
        }
        let fits = text
            .split_once(FINGERPRINT_SEPARATOR)
            .is_some_and(|(name, fingerprint)| {
                is_type_name(name) && !is_reserved(name) && is_fingerprint(fingerprint)
            });
        if fits {
            Ok(Self(Named::Agreed(text)))
        } else {
            Err(Refused::Malformed)
        }
    }
}

impl Serialize for InteractionType {
    /// The plain conversation has no name to write, so wherever it can be, it's left out, and a view
    /// shows it as null.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Named::Conversation => serializer.serialize_none(),
            _ => serializer.serialize_str(self.as_str()),
        }
    }
}

impl<'de> Deserialize<'de> for InteractionType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::try_from(text).map_err(serde::de::Error::custom)
    }
}

/// Core's own name, which no schema can take.
fn is_reserved(name: &str) -> bool {
    name.split_once('/')
        .is_some_and(|(word, _)| word == RESERVED_WORD)
}

/// 256 bits in base32, lower case with no padding, the 4 bits left over in the last character zero, so
/// a fingerprint has one spelling.
fn is_fingerprint(text: &str) -> bool {
    text.len() == FINGERPRINT_CHARS
        && text.bytes().all(|byte| BASE32.contains(&byte))
        && text
            .bytes()
            .last()
            .and_then(|last| BASE32.iter().position(|known| *known == last))
            .is_some_and(|value| value & 0xf == 0)
}

/// RFC 4648's base32 alphabet in lower case.
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn to_base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    let mut push = |value: u32| {
        let index = usize::try_from(value & 0x1f).unwrap_or_default();
        out.push(BASE32.get(index).map_or('a', |byte| char::from(*byte)));
    };
    for byte in bytes {
        buffer = ((buffer << 8) | u32::from(*byte)) & 0xffff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            push(buffer >> bits);
        }
    }
    if bits > 0 {
        push(buffer << (5 - bits));
    }
    out
}

/// The fingerprint of a schema's one encoding.
fn fingerprint(encoding: &str) -> String {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(FINGERPRINT_TAG);
    context.update(&[0]);
    context.update(encoding.as_bytes());
    to_base32(context.finish().as_ref())
}

/// A value in a step. Anything else, such as a decimal or a nested object, can't be read at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    Int(u64),
    Text(String),
    Times(Vec<u64>),
}

/// A step's typed fields. A sorted map has one encoding, so field order can't carry anything.
pub type Fields = BTreeMap<String, FieldValue>;

/// What fits in one field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldRule {
    /// One word from a closed set.
    Word(BTreeSet<Word>),
    /// One number from a closed set.
    OneOf(BTreeSet<u64>),
    Range {
        min: u64,
        max: u64,
    },
    /// Times to choose from: ascending, with no repeats, on a grid so low bits can't carry anything.
    Times {
        grid_secs: u64,
        max: usize,
    },
    /// Words someone chose. A type with one of these is only for contacts the owner signed `text` for.
    Text {
        max_chars: usize,
    },
}

impl FieldRule {
    /// A rule nothing could ever fit is a mistake, and shows when the schema is loaded.
    fn can_be_met(&self) -> bool {
        match self {
            Self::Word(words) => !words.is_empty(),
            Self::OneOf(numbers) => !numbers.is_empty(),
            Self::Range { min, max } => min <= max,
            Self::Times { grid_secs, max } => *grid_secs > 0 && *max > 0,
            Self::Text { max_chars } => *max_chars > 0,
        }
    }

    /// Lists no longer than a proposal's, so no one field can say much.
    fn fits_a_proposal(&self) -> bool {
        match self {
            Self::Word(words) => words.len() <= MAX_PROPOSED_ENTRIES,
            Self::OneOf(numbers) => numbers.len() <= MAX_PROPOSED_ENTRIES,
            Self::Times { max, .. } => *max <= MAX_PROPOSED_ENTRIES,
            Self::Range { .. } | Self::Text { .. } => true,
        }
    }

    /// Numbers every reader holds exactly, and a text field no longer than a conversation's line.
    fn numbers_fit_a_proposal(&self) -> bool {
        match self {
            Self::OneOf(numbers) => numbers.iter().all(|number| *number <= MAX_PROPOSED_NUMBER),
            Self::Range { min, max } => *min <= MAX_PROPOSED_NUMBER && *max <= MAX_PROPOSED_NUMBER,
            Self::Times { grid_secs, .. } => *grid_secs <= MAX_PROPOSED_NUMBER,
            Self::Word(_) => true,
            Self::Text { max_chars } => *max_chars <= MAX_PROPOSED_TEXT_CHARS,
        }
    }

    /// The most bits one value of this field can carry, rounded up so it's never less than the
    /// truth, or nothing for words someone chose, which have no bound worth stating. Up to `max` times
    /// from the places on its grid in the next two weeks are fewer than (places + 1) to the `max`.
    fn most_bits(&self) -> Option<u32> {
        match self {
            Self::Word(words) => Some(bits_to_choose_from(words.len())),
            Self::OneOf(numbers) => Some(bits_to_choose_from(numbers.len())),
            Self::Range { min, max } => Some(bit_length(max.saturating_sub(*min))),
            Self::Times { grid_secs, max } => {
                let places = MAX_DATE_AHEAD_SECS
                    .checked_div(*grid_secs)
                    .unwrap_or_default()
                    .saturating_add(1);
                let times = u32::try_from(*max).unwrap_or(u32::MAX);
                Some(bit_length(places).saturating_mul(times))
            }
            Self::Text { .. } => None,
        }
    }

    /// Its words and numbers, which whoever wrote the schema chose.
    fn chosen(&self) -> Vec<String> {
        match self {
            Self::Word(words) => words.iter().map(|word| word.as_str().to_owned()).collect(),
            Self::OneOf(numbers) => numbers.iter().map(u64::to_string).collect(),
            Self::Range { min, max } => vec![min.to_string(), max.to_string()],
            Self::Times { grid_secs, max } => vec![grid_secs.to_string(), max.to_string()],
            Self::Text { max_chars } => vec![max_chars.to_string()],
        }
    }

    /// What fits, in core's fixed words around the type's own words and numbers.
    fn described(&self) -> String {
        let list = |items: Vec<String>| items.join(", ");
        match self {
            Self::Word(words) => format!(
                "one of {}",
                list(words.iter().map(|word| word.as_str().to_owned()).collect())
            ),
            Self::OneOf(numbers) => format!(
                "a number, one of {}",
                list(numbers.iter().map(u64::to_string).collect())
            ),
            Self::Range { min, max } => format!("a number from {min} to {max}"),
            Self::Times { grid_secs, max } => {
                let grid = if grid_secs % 60 == 0 {
                    format!("{}-minute", grid_secs / 60)
                } else {
                    format!("{grid_secs}-second")
                };
                format!("up to {max} times, on a {grid} grid")
            }
            Self::Text { max_chars } => {
                format!("words someone chose, up to {max_chars} characters")
            }
        }
    }

    fn allows(&self, value: &FieldValue) -> bool {
        match (self, value) {
            (Self::Word(words), FieldValue::Text(text)) => {
                words.iter().any(|word| word.as_str() == text)
            }
            (Self::OneOf(numbers), FieldValue::Int(number)) => numbers.contains(number),
            (Self::Range { min, max }, FieldValue::Int(number)) => (*min..=*max).contains(number),
            (Self::Times { grid_secs, max }, FieldValue::Times(times)) => {
                let ascending = times.is_sorted_by(|earlier, later| earlier < later);
                let on_grid = times
                    .iter()
                    .all(|time| time.checked_rem(*grid_secs) == Some(0));
                !times.is_empty() && times.len() <= *max && ascending && on_grid
            }
            (Self::Text { max_chars }, FieldValue::Text(text)) => {
                text.chars().count() <= *max_chars && !has_hidden_characters(text)
            }
            _ => false,
        }
    }
}

/// The bits to write any number up to this one.
fn bit_length(number: u64) -> u32 {
    u64::BITS.saturating_sub(number.leading_zeros())
}

/// The bits to say which of this many things, rounded up.
fn bits_to_choose_from(count: usize) -> u32 {
    bit_length(u64::try_from(count).unwrap_or(u64::MAX).saturating_sub(1))
}

/// Control characters, bidi overrides and invisible format characters could hide what a reader is
/// shown, or carry words nobody sees. The tag block and the variation selectors can each spell out a
/// whole hidden instruction, a line separator could make one line of a record look like two, and
/// private use characters and blank letters draw as whatever a font likes, or as nothing.
pub(crate) fn is_hidden_character(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{AD}' | '\u{34F}' | '\u{600}'..='\u{605}' | '\u{61C}' | '\u{6DD}' | '\u{70F}'
            | '\u{890}'..='\u{891}' | '\u{8E2}' | '\u{115F}'..='\u{1160}' | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}' | '\u{2800}' | '\u{3164}' | '\u{E000}'..='\u{F8FF}'
            | '\u{FDD0}'..='\u{FDEF}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFB}' | '\u{FFFE}'..='\u{FFFF}' | '\u{110BD}' | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D159}'
            | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}' | '\u{F0000}'..='\u{10FFFF}')
}

pub fn has_hidden_characters(text: &str) -> bool {
    text.chars().any(is_hidden_character)
}

/// Words for a person to read, with anything that could hide what they say shown as its code.
pub fn with_hidden_shown(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        if is_hidden_character(c) {
            shown.extend(c.escape_unicode());
        } else {
            shown.push(c);
        }
    }
    shown
}

/// A side, as a person reads which one a type's money is paid to.
fn side_words(side: Side) -> &'static str {
    match side {
        Side::Requester => "whoever opens it",
        Side::Recipient => "whoever it's opened with",
    }
}

/// A conversation has no outcome. A request does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionKind {
    Conversation,
    Request,
}

/// Whose owners must sign before a request of this type is `completed`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signers {
    #[default]
    None,
    Requester,
    Both,
}

impl Signers {
    fn is_none(&self) -> bool {
        *self == Self::None
    }
}

/// Why an agent paused its work. Core's own words, the same for every type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseReason {
    NeedsInformation,
    NeedsApproval,
    Other,
}

/// `clarify` always allows this, so an agent that doesn't understand can say so in any type.
pub(super) const NOT_UNDERSTOOD: &str = "not_understood";
/// `decline` always allows this, and it's what an owner's signed no sends.
pub(super) const NO_REASON: &str = "no_reason";

/// What a guest's page draws for one type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestForm {
    /// Each field to pick, and the list in the offer it comes from.
    pub pick: BTreeMap<String, String>,
    pub clarify: Vec<String>,
    pub decline: Vec<String>,
}

impl GuestForm {
    /// Words and little else, as what goes on a page has to be, since this isn't signed by anyone: a
    /// form can't be how someone gets a sentence in front of a guest.
    pub fn fits(&self) -> bool {
        const MOST_WORDS: usize = MAX_FIELDS;
        let words_fit = |words: &[String]| {
            !words.is_empty() && words.len() <= MOST_WORDS && words.iter().all(|word| is_word(word))
        };
        self.pick.len() <= MOST_WORDS
            && self
                .pick
                .iter()
                .all(|(name, from)| is_word(name) && is_word(from))
            && words_fit(&self.clarify)
            && words_fit(&self.decline)
    }
}

/// What a cap on this value goes by, in this unit if it has one.
pub fn cap_name(value: &str, unit: Option<&str>) -> String {
    match unit {
        Some(word) => format!("{value}{CAP_UNIT_SEPARATOR}{word}"),
        None => value.to_owned(),
    }
}

/// Not a character a field name or word can hold, so a cap's name reads back one way.
pub(crate) const CAP_UNIT_SEPARATOR: char = '.';

/// One interaction type's rules, as a schema document says them. Every collection is left out of the
/// one encoding when it's empty, and `sign` when it's `none`, so a schema has one encoding whoever
/// writes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    #[serde(rename = "type")]
    name: TypeName,
    kind: InteractionKind,
    /// What `open` must carry, and `counter` too, apart from `fixed`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    offer: BTreeMap<String, FieldRule>,
    /// Set by `open` and never changed.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    fixed: BTreeSet<String>,
    /// What `accept` must carry: each field names a list in the offer that its value comes from.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pick: BTreeMap<String, String>,
    /// What `deliver` must carry. A type with a result has work to do once it's accepted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    result: BTreeMap<String, FieldRule>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    progress: BTreeSet<Word>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    clarify: BTreeSet<Word>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    decline: BTreeSet<Word>,
    /// What `say` must carry, in a conversation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    say: BTreeMap<String, FieldRule>,
    #[serde(default, skip_serializing_if = "Signers::is_none")]
    sign: Signers,
    /// Numbers in the offer or result that an owner can cap, such as an amount. Core doesn't know
    /// what any of them means.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    values: BTreeSet<String>,
    /// The fixed word field in the offer that a value is measured in, such as a currency. A cap on
    /// that value then names the word too, so a cap set in one unit is never read in another.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    units: BTreeMap<String, String>,
    /// The type's currency: each value here is money, paid to the side named, such as the recipient
    /// for a quote's amount. A type with any must be approved by the owner before their agent uses it,
    /// and only these wait for an owner when committed to. An owner's `quoted_prices` lets go only a
    /// price their agent names on the side the type says is paid. Core doesn't know what any of it
    /// means, any more than it knows what a value is.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    paid: BTreeMap<String, Side>,
}

/// Which of core's own types a schema is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BuiltIn {
    Conversation,
    Proposal,
}

/// A type's rules with the ID they go by: the fingerprint of the document's one encoding, or core's own
/// name for one of its own.
#[derive(Clone, Debug)]
pub struct Schema {
    document: Document,
    id: InteractionType,
    /// The one encoding, as JSON with every key sorted.
    encoding: serde_json::Value,
    encoded_len: usize,
    built_in: Option<BuiltIn>,
    /// Whether the sides its currency is paid to count, which they do unless the owner hasn't
    /// approved it, as [`Schema::unapproved`] reads it.
    sides_count: bool,
}

impl std::ops::Deref for Schema {
    type Target = Document;

    fn deref(&self) -> &Document {
        &self.document
    }
}

/// A schema is shown, and carried in a proposal, in its one encoding.
impl Serialize for Schema {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.encoding.serialize(serializer)
    }
}

/// A schema document read back, as from a Signet's list of what's agreed: its ID is worked out again
/// from its one encoding, so whoever passed it on can't name it as something else.
impl<'de> Deserialize<'de> for Schema {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = Document::deserialize(deserializer)?;
        Self::from_document(document).map_err(|_| serde::de::Error::custom("malformed"))
    }
}

static CONVERSATION: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    let text = FieldRule::Text {
        max_chars: CONVERSATION_TEXT_CHARS,
    };
    Arc::new(Schema::built_in(
        Document {
            name: TypeName("conversation/1".to_owned()),
            kind: InteractionKind::Conversation,
            say: BTreeMap::from([("text".to_owned(), text)]),
            ..Document::empty()
        },
        BuiltIn::Conversation,
    ))
});

static PROPOSAL_SCHEMA: LazyLock<Arc<Schema>> = LazyLock::new(|| {
    Arc::new(Schema::built_in(
        Document {
            name: TypeName(PROPOSAL.to_owned()),
            kind: InteractionKind::Request,
            decline: PROPOSAL_DECLINES
                .iter()
                .map(|word| Word((*word).to_owned()))
                .collect(),
            ..Document::empty()
        },
        BuiltIn::Proposal,
    ))
});

impl Document {
    fn empty() -> Self {
        Self {
            name: TypeName(String::new()),
            kind: InteractionKind::Request,
            offer: BTreeMap::new(),
            fixed: BTreeSet::new(),
            pick: BTreeMap::new(),
            result: BTreeMap::new(),
            progress: BTreeSet::new(),
            clarify: BTreeSet::new(),
            decline: BTreeSet::new(),
            say: BTreeMap::new(),
            sign: Signers::None,
            values: BTreeSet::new(),
            units: BTreeMap::new(),
            paid: BTreeMap::new(),
        }
    }
}

impl Schema {
    fn built_in(document: Document, built_in: BuiltIn) -> Self {
        let encoding = serde_json::to_value(&document).unwrap_or_default();
        let encoded_len = encoding.to_string().len();
        let id = match built_in {
            BuiltIn::Conversation => InteractionType::conversation(),
            BuiltIn::Proposal => InteractionType::proposal(),
        };
        Self {
            document,
            id,
            encoding,
            encoded_len,
            built_in: Some(built_in),
            sides_count: true,
        }
    }

    /// Core's plain conversation: one line of words someone chose on each `say`, so only for a contact
    /// whose owner signed `text`.
    pub fn conversation() -> Arc<Self> {
        CONVERSATION.clone()
    }

    /// Core's `type/1`, by which two agents agree a type. Its `open` carries the schema proposed, and
    /// the other side accepts it, which finishes it, or declines with one of core's own reasons.
    pub fn proposal() -> Arc<Self> {
        PROPOSAL_SCHEMA.clone()
    }

    pub(super) fn from_document(document: Document) -> Result<Self, Error> {
        if !document.fits_together() || is_reserved(document.name.as_str()) {
            return Err(Error::Malformed);
        }
        // A `serde_json` object keeps its keys sorted, which is the one encoding's order.
        let encoding = serde_json::to_value(&document).map_err(|_| Error::Malformed)?;
        let encoded = encoding.to_string();
        let id = InteractionType(Named::Agreed(format!(
            "{}{FINGERPRINT_SEPARATOR}{}",
            document.name.as_str(),
            fingerprint(&encoded)
        )));
        Ok(Self {
            document,
            id,
            encoding,
            encoded_len: encoded.len(),
            built_in: None,
            sides_count: true,
        })
    }

    /// Refuses a schema no request of its type could follow, so a mistake shows when it's read. It can
    /// be written any way: its ID comes from its one encoding.
    pub fn parse(document: &[u8]) -> Result<Self, Error> {
        let document: Document = serde_json::from_slice(document).map_err(|_| Error::Malformed)?;
        Self::from_document(document)
    }

    /// The ID this type goes by: its name and the fingerprint of its one encoding, or core's own name.
    pub fn name(&self) -> &InteractionType {
        &self.id
    }

    /// The one encoding, which the fingerprint is of.
    pub fn encoding(&self) -> String {
        self.encoding.to_string()
    }

    /// Whether this is core's `type/1`, whose `accept` finishes it.
    pub fn is_proposal(&self) -> bool {
        self.built_in == Some(BuiltIn::Proposal)
    }

    /// Whether this is one of core's own types rather than one two agents agreed.
    pub fn is_built_in(&self) -> bool {
        self.built_in.is_some()
    }

    /// What core holds every proposed schema to, whoever proposes it and whatever the owners set, so
    /// agreeing a type, which no owner signs, says only so much and holds nothing an owner would miss.
    /// Whether text may pass between the two is for each side's Signet, which knows its own owner's
    /// rules. See "Interaction types" in `docs/protocol.md`.
    pub fn check_proposal(&self) -> Result<(), Refused> {
        let document = &self.document;
        let lists_fit = document.offer.len() <= MAX_PROPOSED_ENTRIES
            && document.result.len() <= MAX_PROPOSED_ENTRIES
            && document.say.len() <= MAX_PROPOSED_ENTRIES
            && document.pick.len() <= MAX_PROPOSED_ENTRIES
            && document.progress.len() <= MAX_PROPOSED_ENTRIES
            && document.clarify.len() <= MAX_PROPOSED_ENTRIES
            && document.decline.len() <= MAX_PROPOSED_ENTRIES
            && document.rules().all(FieldRule::fits_a_proposal);
        if self.encoded_len > MAX_PROPOSED_BYTES
            || !lists_fit
            || document.chosen_chars() > MAX_CHOSEN_CHARS
        {
            return Err(Refused::TypeTooBig);
        }
        // A price nobody can tell the currency of is no price anyone can pay or cap.
        let paid_in_a_unit = document
            .paid
            .keys()
            .all(|value| document.units.contains_key(value));
        let numbers_fit = document.rules().all(FieldRule::numbers_fit_a_proposal);
        if self.is_built_in() || !paid_in_a_unit || !numbers_fit {
            return Err(Refused::TypeUnsafe);
        }
        Ok(())
    }

    /// The same type as its owner's own permissions read it, where that owner hasn't approved it: its
    /// currency is still money, but no side it's paid to counts, whatever the schema's labels say, since
    /// the other agent may have written them, so every amount reads as one the owner may be paying. An
    /// agent can't use a type with currency until its owner approves it, so this is only what's held
    /// across a change of rules. A number not labelled as currency is never money. See "Permissions" in
    /// `docs/protocol.md`.
    #[must_use]
    pub fn unapproved(&self) -> Self {
        Self {
            sides_count: false,
            ..self.clone()
        }
    }

    /// The side this value is paid to, where the type says it's currency and whose, and the owner
    /// approved the type.
    pub fn paid_to(&self, value: &str) -> Option<Side> {
        if self.sides_count {
            self.document.paid.get(value).copied()
        } else {
            None
        }
    }
}

fn fits(rules: &BTreeMap<String, FieldRule>, fields: &Fields) -> bool {
    rules.len() == fields.len()
        && fields
            .iter()
            .all(|(name, value)| rules.get(name).is_some_and(|rule| rule.allows(value)))
}

impl Document {
    /// Every field's rule, in every section.
    fn rules(&self) -> impl Iterator<Item = &FieldRule> {
        [&self.offer, &self.result, &self.say]
            .into_iter()
            .flat_map(BTreeMap::values)
    }

    /// Every name, word and number this document holds that whoever wrote it chose, in order, leaving
    /// out the format's own words.
    fn chosen(&self) -> Vec<String> {
        let mut chosen = vec![self.name.as_str().to_owned()];
        for (name, rule) in [&self.offer, &self.result, &self.say]
            .into_iter()
            .flat_map(BTreeMap::iter)
        {
            chosen.push(name.clone());
            chosen.extend(rule.chosen());
        }
        chosen.extend(self.fixed.iter().cloned());
        for (name, from) in &self.pick {
            chosen.extend([name.clone(), from.clone()]);
        }
        chosen.extend(
            self.progress
                .iter()
                .chain(&self.clarify)
                .chain(&self.decline)
                .map(|word| word.as_str().to_owned()),
        );
        chosen.extend(self.values.iter().cloned());
        for (value, unit) in &self.units {
            chosen.extend([value.clone(), unit.clone()]);
        }
        chosen.extend(self.paid.keys().cloned());
        chosen
    }

    fn chosen_chars(&self) -> usize {
        self.chosen().iter().map(String::len).sum()
    }

    /// Every name, word and number in it run together, for a look for an agent's own secrets. It finds
    /// a secret written in this order, across neighbouring words included, and not one split across
    /// parts the one encoding orders otherwise, or scrambled: within its 512 characters a proposal can
    /// carry anything an agent chooses to encode, as "What a fooled agent can still leak" counts.
    pub fn chosen_words(&self) -> String {
        self.chosen().concat()
    }

    fn fits_together(&self) -> bool {
        let named_well = |rules: &BTreeMap<String, FieldRule>| {
            rules.len() <= MAX_FIELDS && rules.keys().all(|name| is_word(name))
        };
        let rules_can_be_met = [&self.offer, &self.result, &self.say]
            .into_iter()
            .flat_map(BTreeMap::values)
            .all(FieldRule::can_be_met);
        // A pick sharing a name with an offer field would overwrite it in the terms.
        let picks_fit = self.pick.iter().all(|(name, from)| {
            is_word(name)
                && !self.offer.contains_key(name)
                && !self.fixed.contains(from)
                && matches!(self.offer.get(from), Some(FieldRule::Times { .. }))
        });
        let fixed_fit = self.fixed.iter().all(|name| self.offer.contains_key(name));
        let values_fit = self.values.iter().all(|name| {
            let rule = self.offer.get(name).or_else(|| self.result.get(name));
            matches!(rule, Some(FieldRule::Range { .. } | FieldRule::OneOf(_)))
        });
        let paid_fit = self.paid.keys().all(|value| self.values.contains(value));
        let units_fit = self.units.iter().all(|(value, unit)| {
            self.values.contains(value)
                && self.fixed.contains(unit)
                && matches!(self.offer.get(unit), Some(FieldRule::Word(_)))
        });
        let by_kind = match self.kind {
            InteractionKind::Conversation => {
                !self.say.is_empty()
                    && self.offer.is_empty()
                    && self.pick.is_empty()
                    && self.result.is_empty()
                    && self.progress.is_empty()
                    && self.clarify.is_empty()
                    && self.decline.is_empty()
                    && self.sign == Signers::None
            }
            // With no result and no owner to sign, nothing could ever finish it.
            InteractionKind::Request => {
                self.say.is_empty() && (self.has_result() || self.sign != Signers::None)
            }
        };
        named_well(&self.offer)
            && named_well(&self.result)
            && named_well(&self.say)
            && rules_can_be_met
            && picks_fit
            && fixed_fit
            && values_fit
            && paid_fit
            && units_fit
            && by_kind
    }

    /// The name and version the document gives itself, which a type's ID starts with.
    pub fn type_name(&self) -> &TypeName {
        &self.name
    }

    pub fn kind(&self) -> InteractionKind {
        self.kind
    }

    pub fn sign(&self) -> Signers {
        self.sign
    }

    /// Whether `side`'s owner signs a `confirm` before a request of this type is `completed`.
    pub fn signed_by(&self, side: Side) -> bool {
        matches!(
            (self.sign, side),
            (Signers::Both, _) | (Signers::Requester, Side::Requester)
        )
    }

    /// The numbers in this type that an owner can cap.
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.values.iter().map(String::as_str)
    }

    /// The field whose word this value is measured in, if it has a unit.
    pub fn unit_of(&self, value: &str) -> Option<&str> {
        self.units.get(value).map(String::as_str)
    }

    /// Every name a cap on this type can go by: a value, or for one with a unit, the value and one
    /// of that unit's words, as `amount_minor.usd`.
    pub fn cap_names(&self) -> Vec<String> {
        self.values
            .iter()
            .flat_map(
                |value| match self.unit_of(value).and_then(|unit| self.offer.get(unit)) {
                    Some(FieldRule::Word(words)) => words
                        .iter()
                        .map(|word| cap_name(value, Some(word.as_str())))
                        .collect(),
                    _ => vec![cap_name(value, None)],
                },
            )
            .collect()
    }

    pub fn is_value(&self, field: &str) -> bool {
        self.values.contains(field)
    }

    /// Whether this type has currency: a value it says is money paid to one side. Such a type must be
    /// approved by the owner before their agent uses it (Nenye, 2026-11-15).
    pub fn includes_currency(&self) -> bool {
        !self.paid.is_empty()
    }

    /// Whether this field is currency, as the type labels it.
    pub fn is_currency(&self, field: &str) -> bool {
        self.paid.contains_key(field)
    }

    /// The type's currency, each with the side it's paid to and the field its unit is in.
    pub fn currency(&self) -> impl Iterator<Item = (&str, Side, Option<&str>)> {
        self.paid
            .iter()
            .map(|(value, side)| (value.as_str(), *side, self.unit_of(value)))
    }

    /// Every number field in the offer or result the type doesn't label as currency, by name: a fact
    /// for whoever reads one, never a hold.
    pub fn numbers_not_money(&self) -> Vec<&str> {
        self.offer
            .iter()
            .chain(self.result.iter())
            .filter(|(name, rule)| {
                matches!(rule, FieldRule::Range { .. } | FieldRule::OneOf(_))
                    && !self.is_currency(name)
            })
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// The fields among these that hold a number this type doesn't label as currency.
    pub fn numbers_not_money_in<'a>(&'a self, fields: &'a Fields) -> impl Iterator<Item = &'a str> {
        fields
            .iter()
            .filter(|(name, value)| matches!(value, FieldValue::Int(_)) && !self.is_currency(name))
            .map(|(name, _)| name.as_str())
    }

    pub fn has_result(&self) -> bool {
        !self.result.is_empty()
    }

    /// Whether only a contact the owner signed `text` for may use this type, because its steps can
    /// carry what an agent likes: a text field; any conversation, since a `say` commits nobody to
    /// anything, waits for no owner and can go 160 times a side; or a step whose fields can carry more
    /// than [`MAX_STEP_BITS_WITHOUT_TEXT`] between them. An `open` or a `counter` carries the offer,
    /// an `accept` the picks and a `deliver` the result. Two agents agree a type with no owner asked,
    /// so this is what holds `text: false` against a type written to get round it.
    pub fn needs_text(&self) -> bool {
        self.kind == InteractionKind::Conversation
            || self
                .most_step_bits()
                .is_none_or(|bits| bits > MAX_STEP_BITS_WITHOUT_TEXT)
    }

    /// The most bits any one step of this type carries in its fields, or nothing where one has a text
    /// field.
    fn most_step_bits(&self) -> Option<u32> {
        let section = |rules: &BTreeMap<String, FieldRule>| {
            rules.values().try_fold(0_u32, |bits, rule| {
                rule.most_bits().map(|more| bits.saturating_add(more))
            })
        };
        let picks = self.pick.values().fold(0_u32, |bits, from| {
            let more = match self.offer.get(from) {
                Some(FieldRule::Times { max, .. }) => bits_to_choose_from(*max),
                _ => 0,
            };
            bits.saturating_add(more)
        });
        let offer = section(&self.offer)?;
        let result = section(&self.result)?;
        let say = section(&self.say)?;
        Some(offer.max(result).max(say).max(picks))
    }

    /// Every part of this type that says what a request of it can carry or commit anyone to, one line
    /// each, in core's own fixed words around the names, words and numbers its writer chose, for an
    /// owner asked to approve it. Nothing in it is anyone's sentence: every name and word is a word.
    pub fn described(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let field = |section: &str, name: &str, rule: &FieldRule| {
            let mut line = format!("{section} {name}: {}", rule.described());
            match (rule, self.paid.get(name)) {
                (FieldRule::Range { .. } | FieldRule::OneOf(_), Some(side)) => {
                    line.push_str(&format!(", money paid to {}", side_words(*side)));
                    if let Some(unit) = self.unit_of(name) {
                        line.push_str(&format!(", in the unit {unit} names"));
                    }
                }
                (FieldRule::Range { .. } | FieldRule::OneOf(_), None) => {
                    line.push_str(", a number not labelled as money");
                }
                _ => {}
            }
            if self.fixed.contains(name) {
                line.push_str(", set when it's opened");
            }
            line
        };
        for (name, rule) in &self.offer {
            lines.push(field("Offer", name, rule));
        }
        for (name, from) in &self.pick {
            lines.push(format!("Accept picks {name}: one time from {from}"));
        }
        for (name, rule) in &self.result {
            lines.push(field("Result", name, rule));
        }
        for (name, rule) in &self.say {
            lines.push(field("Says", name, rule));
        }
        lines.push(
            match self.sign {
                Signers::None => "No owner signs it before it's done",
                Signers::Requester => "The owner of whoever opens it signs before it's done",
                Signers::Both => "Both owners sign before it's done",
            }
            .to_owned(),
        );
        lines
    }

    /// Whether this field holds a word from the type's own closed set, rather than words someone chose.
    pub fn is_word_field(&self, name: &str) -> bool {
        let rule = [&self.offer, &self.result, &self.say]
            .into_iter()
            .find_map(|rules| rules.get(name));
        matches!(rule, Some(FieldRule::Word(_)))
    }

    /// Whether this field holds times: a list of them, or one picked from such a list.
    pub fn is_time_field(&self, name: &str) -> bool {
        let rule = |name: &str| {
            [&self.offer, &self.result, &self.say]
                .into_iter()
                .find_map(|rules| rules.get(name))
        };
        let times = |name: &str| matches!(rule(name), Some(FieldRule::Times { .. }));
        times(name) || self.pick.get(name).is_some_and(|from| times(from))
    }

    /// Every field that holds times, by name, for a reader with no schema to show them as times.
    pub fn time_fields(&self) -> Vec<String> {
        let names = self
            .offer
            .keys()
            .chain(self.result.keys())
            .chain(self.say.keys());
        let mut fields: Vec<String> = names
            .chain(self.pick.keys())
            .filter(|name| self.is_time_field(name))
            .cloned()
            .collect();
        fields.sort();
        fields.dedup();
        fields
    }

    /// What a link can offer: a guest can answer, and has no way to do work or sign as an owner.
    pub fn can_go_to_a_guest(&self) -> bool {
        self.kind == InteractionKind::Request && !self.has_result()
    }

    /// What someone with no agent needs in order to answer this type. It's only what to draw: a pick or
    /// a reason from anywhere else is refused by whoever reads the step.
    pub fn guest_form(&self) -> GuestForm {
        let with = |always: &str, words: &BTreeSet<Word>| {
            words
                .iter()
                .map(|word| word.as_str().to_owned())
                .chain(std::iter::once(always.to_owned()))
                .collect()
        };
        GuestForm {
            pick: self.pick.clone(),
            clarify: with(NOT_UNDERSTOOD, &self.clarify),
            decline: with(NO_REASON, &self.decline),
        }
    }

    /// The fields an offer of this type must carry, and what fits in each.
    pub fn offer_rules(&self) -> &BTreeMap<String, FieldRule> {
        &self.offer
    }

    /// Whether this field is a time picked from a list in the offer.
    pub(super) fn is_pick(&self, name: &str) -> bool {
        self.pick.contains_key(name)
    }

    pub(super) fn has_progress(&self) -> bool {
        !self.progress.is_empty()
    }

    pub(super) fn check_offer(&self, terms: &Fields) -> Result<(), Refused> {
        fits(&self.offer, terms)
            .then_some(())
            .ok_or(Refused::Malformed)
    }

    /// A `counter` carries everything but what `open` fixed.
    pub(super) fn check_revision(&self, terms: &Fields) -> Result<(), Refused> {
        let fits = terms.len() == self.offer.len().saturating_sub(self.fixed.len())
            && terms.iter().all(|(name, value)| {
                !self.fixed.contains(name)
                    && self.offer.get(name).is_some_and(|rule| rule.allows(value))
            });
        fits.then_some(()).ok_or(Refused::Malformed)
    }

    /// The shape of what `accept` carries. Whether it was offered depends on the chain.
    pub(super) fn check_pick_shape(&self, pick: &Fields) -> Result<(), Refused> {
        let fits = pick.len() == self.pick.len()
            && pick.iter().all(|(name, value)| {
                self.pick.contains_key(name) && matches!(value, FieldValue::Int(_))
            });
        fits.then_some(()).ok_or(Refused::Malformed)
    }

    /// Each picked value has to be in the list its field names, in the offer that was accepted.
    pub(super) fn check_picked_from(&self, pick: &Fields, offer: &Fields) -> Result<(), Refused> {
        let offered = pick.iter().all(|(name, value)| {
            let from = self.pick.get(name).and_then(|from| offer.get(from));
            matches!((from, value), (Some(FieldValue::Times(times)), FieldValue::Int(time)) if times.contains(time))
        });
        offered.then_some(()).ok_or(Refused::NotOffered)
    }

    pub(super) fn check_result(&self, result: &Fields) -> Result<(), Refused> {
        (self.has_result() && fits(&self.result, result))
            .then_some(())
            .ok_or(Refused::Malformed)
    }

    pub(super) fn check_say(&self, fields: &Fields) -> Result<(), Refused> {
        fits(&self.say, fields)
            .then_some(())
            .ok_or(Refused::Malformed)
    }

    pub(super) fn check_progress(&self, status: &Word) -> Result<(), Refused> {
        self.progress
            .contains(status)
            .then_some(())
            .ok_or(Refused::Malformed)
    }

    pub(super) fn check_clarify(&self, reason: &Word) -> Result<(), Refused> {
        (reason.as_str() == NOT_UNDERSTOOD || self.clarify.contains(reason))
            .then_some(())
            .ok_or(Refused::Malformed)
    }

    pub(super) fn check_decline(&self, reason: &Word) -> Result<(), Refused> {
        (reason.as_str() == NO_REASON || self.decline.contains(reason))
            .then_some(())
            .ok_or(Refused::Malformed)
    }

    /// What's been agreed: the offer without the lists a pick chose from, plus the pick. The lists
    /// aren't part of it, so an outcome doesn't show what was offered and turned down.
    pub(super) fn agreed(&self, offer: &Fields, pick: &Fields) -> Fields {
        let mut agreed: Fields = offer
            .iter()
            .filter(|(name, _)| !self.pick.values().any(|from| from == *name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        agreed.extend(
            pick.iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        agreed
    }
}

/// The types two agents can use with each other: core's own, and those they agreed. Cheap to clone.
#[derive(Clone, Debug, Default)]
pub struct Schemas(Arc<BTreeMap<InteractionType, Arc<Schema>>>);

impl Schemas {
    /// Schema documents, each written any way. A type listed twice would leave it unclear which rules
    /// count.
    pub fn parse<'a>(documents: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, Error> {
        let mut schemas = Vec::new();
        for document in documents {
            schemas.push(Arc::new(Schema::parse(document)?));
        }
        Self::of(schemas)
    }

    /// Schemas already read, such as those two agents agreed. The same one twice is refused.
    pub fn of(schemas: impl IntoIterator<Item = Arc<Schema>>) -> Result<Self, Error> {
        let mut held = BTreeMap::new();
        for schema in schemas {
            if schema.is_built_in() || held.insert(schema.name().clone(), schema).is_some() {
                return Err(Error::Malformed);
            }
        }
        Ok(Self(Arc::new(held)))
    }

    /// A type by its ID: one of core's own, or one of these.
    pub fn get(&self, name: &InteractionType) -> Option<&Arc<Schema>> {
        if name.is_conversation() {
            Some(&CONVERSATION)
        } else if name.is_proposal() {
            Some(&PROPOSAL_SCHEMA)
        } else {
            self.0.get(name)
        }
    }

    /// The one of these with this name and version, if exactly one has it.
    pub fn named(&self, name: &str) -> Option<&Arc<Schema>> {
        let mut found = self
            .0
            .values()
            .filter(|schema| schema.name().name() == name);
        match (found.next(), found.next()) {
            (Some(one), None) => Some(one),
            _ => None,
        }
    }

    /// These, without core's own.
    pub fn all(&self) -> impl Iterator<Item = &Schema> {
        self.0.values().map(Arc::as_ref)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The example types in `spec/schemas/`, which tests and vectors use. Nothing outside a test names one.
#[cfg(test)]
pub(crate) fn examples() -> Schemas {
    Schemas::parse([
        include_bytes!("../../../../spec/schemas/meeting-1.json").as_slice(),
        include_bytes!("../../../../spec/schemas/quote-1.json").as_slice(),
        include_bytes!("../../../../spec/schemas/document-1.json").as_slice(),
        include_bytes!("../../../../spec/schemas/rsvp-1.json").as_slice(),
    ])
    .unwrap()
}

/// One example type's ID, as tests name it.
#[cfg(test)]
pub(crate) fn example(name: &str) -> InteractionType {
    examples().named(name).unwrap().name().clone()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn schema(document: serde_json::Value) -> Result<Schema, Error> {
        Schema::parse(document.to_string().as_bytes())
    }

    #[test]
    fn a_type_name_is_a_short_word_and_a_version() {
        for good in ["meeting/1", "quote/12"] {
            assert!(TypeName::try_from(good.to_owned()).is_ok(), "{good}");
        }
        for bad in [
            "",
            "meeting",
            "meeting/",
            "/1",
            "Meeting/1",
            "a b/1",
            "x/1/2",
            "x/one",
        ] {
            assert!(TypeName::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    /// Two sides could once hold different schemas under one name, and a step one read one way the other
    /// read another. A type now goes by the fingerprint of its schema's one encoding, so the
    /// same rules written any way have one ID, any change to them is another, and nothing names a type
    /// by a fingerprint that isn't its own.
    #[test]
    fn a_type_goes_by_the_fingerprint_of_its_one_encoding() {
        let quote = include_str!("../../../../spec/schemas/quote-1.json");
        let id = Schema::parse(quote.as_bytes()).unwrap().name().clone();
        assert!(id.as_str().starts_with("quote/1@"), "{}", id.as_str());
        let respelled: serde_json::Value = serde_json::from_str(quote).unwrap();
        let respelled = serde_json::to_string_pretty(&respelled).unwrap();
        assert_eq!(Schema::parse(respelled.as_bytes()).unwrap().name(), &id);
        // `sign` left out says `none`, as written out it does.
        let unsigned = r#"{"type":"x/1","kind":"request","result":{"a":{"one_of":[1]}}}"#;
        let signed_none =
            r#"{"type":"x/1","kind":"request","result":{"a":{"one_of":[1]}},"sign":"none"}"#;
        assert_eq!(
            Schema::parse(unsigned.as_bytes()).unwrap().name(),
            Schema::parse(signed_none.as_bytes()).unwrap().name()
        );
        for changed in [
            quote.replacen("\"usd\", ", "", 1),
            quote.replacen("100000000000", "100000000001", 1),
            quote.replacen("\"recipient\"", "\"requester\"", 1),
        ] {
            let other = Schema::parse(changed.as_bytes()).unwrap();
            assert_ne!(other.name(), &id, "{changed}");
            assert_eq!(other.name().name(), "quote/1");
        }
        for good in [id.as_str(), PROPOSAL] {
            assert!(InteractionType::try_from(good.to_owned()).is_ok(), "{good}");
        }
        let fingerprint = id.as_str().split_once('@').unwrap().1.to_owned();
        for bad in [
            "quote/1".to_owned(),
            format!(
                "quote/1@{}",
                fingerprint.chars().skip(1).collect::<String>()
            ),
            format!("quote/1@{}a", fingerprint),
            format!(
                "quote/1@{}b",
                fingerprint.chars().take(51).collect::<String>()
            ),
            format!("Quote/1@{fingerprint}"),
            format!("type/2@{fingerprint}"),
            "type/2".to_owned(),
            String::new(),
        ] {
            assert!(InteractionType::try_from(bad.clone()).is_err(), "{bad}");
        }
        // The one encoding is what's fingerprinted, and what a proposal carries.
        let schema = Schema::parse(quote.as_bytes()).unwrap();
        let reread = Schema::parse(schema.encoding().as_bytes()).unwrap();
        assert_eq!(reread.encoding(), schema.encoding());
        assert_eq!(reread.name(), schema.name());
    }

    /// Agreeing a type needs no owner, so what a fooled agent can say in one is held to fixed limits in
    /// code, each of which one schema here breaks.
    #[test]
    fn a_proposal_past_any_limit_is_refused() {
        let check = |document: serde_json::Value| {
            Schema::parse(document.to_string().as_bytes())
                .map_err(|_| Refused::Malformed)
                .and_then(|schema| schema.check_proposal())
        };
        let control = json!({"type": "x/1", "kind": "request", "sign": "both"});
        assert_eq!(check(control), Ok(()), "control");
        for example in examples().all() {
            assert_eq!(
                example.check_proposal(),
                Ok(()),
                "{}",
                example.name().as_str()
            );
        }
        let words = |count: usize| -> Vec<String> { (0..count).map(|n| format!("w{n}")).collect() };
        let long = |n: usize| format!("{}{n}", "a".repeat(30));
        let too_big = [
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"a": {"word": words(17)}}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"a": {"one_of": (0..17).collect::<Vec<u64>>()}}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"a": {"times": {"grid_secs": 60, "max": 17}}}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "decline": words(17)}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "progress": words(17)}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "clarify": words(17)}),
            // Under every count, past the characters chosen.
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {
                "a": {"word": (0..16).map(long).collect::<Vec<_>>()},
                "b": {"word": (16..18).map(long).collect::<Vec<_>>()},
            }}),
        ];
        for bad in too_big {
            assert_eq!(check(bad.clone()), Err(Refused::TypeTooBig), "{bad}");
        }
        // Under every count and the characters chosen, past 2 KiB in its one encoding, which only many
        // short words reach.
        let letters: Vec<String> = ('a'..='p').map(String::from).collect();
        let wide = json!({"type": "x/1", "kind": "request", "sign": "both",
            "offer": (0..16).map(|n| (format!("f{n}"), json!({"word": letters}))).collect::<serde_json::Map<_, _>>(),
            "result": (0..16).map(|n| (format!("r{n}"), json!({"range": {"min": 0, "max": 9}}))).collect::<serde_json::Map<_, _>>(),
            "progress": letters, "clarify": letters, "decline": letters,
            "values": (0..16).map(|n| format!("r{n}")).collect::<Vec<_>>(),
        });
        let wide_schema = Schema::parse(wide.to_string().as_bytes()).unwrap();
        assert!(wide_schema.chosen_chars() <= MAX_CHOSEN_CHARS);
        assert!(wide_schema.encoding().len() > MAX_PROPOSED_BYTES);
        assert_eq!(check(wide), Err(Refused::TypeTooBig));
        let unsafe_ones = [
            // A price nobody can tell the currency of.
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"n": {"range": {"min": 1, "max": 2}}}, "values": ["n"], "paid": {"n": "recipient"}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"n": {"range": {"min": 0, "max": 9_007_199_254_740_992_u64}}}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"n": {"one_of": [9_007_199_254_740_992_u64]}}}),
            json!({"type": "x/1", "kind": "conversation", "say": {"t": {"text": {"max_chars": 501}}}}),
        ];
        for bad in unsafe_ones {
            assert_eq!(check(bad.clone()), Err(Refused::TypeUnsafe), "{bad}");
        }
        // Core's own name isn't anyone's to take, whatever the version.
        assert!(Schema::parse(br#"{"type":"type/2","kind":"request","sign":"both"}"#).is_err());
        assert_eq!(
            Schema::proposal().check_proposal(),
            Err(Refused::TypeUnsafe)
        );
    }

    /// The leak table's row for a contact without `text` counts the most such a contact may use, so the
    /// bound falls exactly there: 64 bits on a step goes, and a bit more on any step doesn't.
    #[test]
    fn a_contact_without_text_gets_at_most_64_bits_a_step() {
        let numbers = json!({
            "a": {"range": {"min": 0, "max": (1_u64 << 53) - 1}},
            "b": {"range": {"min": 0, "max": (1_u64 << 11) - 1}},
        });
        let at_the_bound = json!({"type": "worst/1", "kind": "request", "sign": "both",
            "offer": numbers, "result": numbers});
        assert!(!schema(at_the_bound.clone()).unwrap().needs_text());
        for section in ["offer", "result"] {
            let mut over = at_the_bound.clone();
            over[section]["c"] = json!({"one_of": [1, 2]});
            assert!(schema(over).unwrap().needs_text(), "{section}");
        }
        // Five times from a half-hour grid, as an example meeting offers, are 50 bits.
        let slots = |max: u64| {
            json!({"type": "slots/1", "kind": "request", "sign": "both",
            "offer": {"a": {"times": {"grid_secs": 1800, "max": max}}, "b": {"range": {"min": 0, "max": 16383}}}})
        };
        assert!(!schema(slots(5)).unwrap().needs_text());
        assert!(schema(slots(6)).unwrap().needs_text());
        // The leak table's worst type also has 16 picks of 4 bits from 16 times on a grid wider than
        // two weeks, which count a bit each, so it can be agreed and carries 64 bits on an accept.
        let picks: serde_json::Map<String, serde_json::Value> =
            (0..16).map(|n| (format!("p{n}"), json!("t"))).collect();
        let words: Vec<String> = (0..16).map(|n| format!("w{n}")).collect();
        let worst = |range_bits: u32| {
            json!({"type": "worst/1", "kind": "request", "sign": "both",
                "offer": {"t": {"times": {"grid_secs": 1_u64 << 21, "max": 16}},
                    "a": {"range": {"min": 0, "max": (1_u64 << range_bits) - 1}}},
                "pick": picks, "result": numbers,
                "progress": words, "clarify": words, "decline": words})
        };
        let agreed = schema(worst(48)).unwrap();
        assert!(!agreed.needs_text());
        assert_eq!(agreed.check_proposal(), Ok(()));
        assert!(schema(worst(49)).unwrap().needs_text());
    }

    #[test]
    fn a_schema_nothing_could_follow_is_refused_when_loaded() {
        let word = json!({"word": ["a"]});
        let times = json!({"times": {"grid_secs": 60, "max": 2}});
        for bad in [
            json!({"type": "x/1", "kind": "request", "offer": {"a": word}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "fixed": ["a"]}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "pick": {"a": "b"}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"b": word}, "pick": {"a": "b"}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"b": times}, "fixed": ["b"], "pick": {"a": "b"}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"b": {"times": {"grid_secs": 0, "max": 2}}}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"b": {"word": []}}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"b": {"range": {"min": 2, "max": 1}}}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"b": times, "c": word}, "pick": {"c": "b"}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "say": {"a": word}}),
            json!({"type": "x/1", "kind": "conversation"}),
            json!({"type": "x/1", "kind": "conversation", "say": {"a": word}, "sign": "both"}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "extra": true}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"Not a Word": word}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"b": word}, "values": ["b"]}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "values": ["missing"]}),
            // A price paid to a side, named for a number the type doesn't call a value, or to nobody.
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"n": {"range": {"min": 1, "max": 2}}}, "paid": {"n": "recipient"}}),
            json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"n": {"range": {"min": 1, "max": 2}}}, "values": ["n"], "paid": {"n": "seller"}}),
        ] {
            assert!(schema(bad.clone()).is_err(), "{bad}");
        }
        let good = json!({"type": "x/1", "kind": "request", "sign": "both", "offer": {"b": times, "n": {"range": {"min": 1, "max": 2}}}, "pick": {"a": "b"}, "values": ["n"], "paid": {"n": "requester"}});
        assert!(schema(good).is_ok(), "control");
    }

    #[test]
    fn the_same_type_twice_is_refused() {
        let one = br#"{"type":"x/1","kind":"request","sign":"both"}"#.as_slice();
        assert!(Schemas::parse([one]).is_ok(), "control");
        assert!(Schemas::parse([one, one]).is_err());
    }

    #[test]
    fn each_rule_refuses_what_doesnt_fit() {
        let text = |text: &str| FieldValue::Text(text.to_owned());
        let cases = [
            (json!({"word": ["a"]}), text("a"), text("b")),
            (json!({"word": ["a"]}), text("a"), FieldValue::Int(1)),
            (
                json!({"one_of": [15]}),
                FieldValue::Int(15),
                FieldValue::Int(16),
            ),
            (
                json!({"range": {"min": 2, "max": 3}}),
                FieldValue::Int(3),
                FieldValue::Int(4),
            ),
            (
                json!({"range": {"min": 2, "max": 3}}),
                FieldValue::Int(2),
                FieldValue::Int(1),
            ),
            (
                json!({"times": {"grid_secs": 60, "max": 2}}),
                FieldValue::Times(vec![60, 120]),
                FieldValue::Times(vec![120, 60]),
            ),
            (
                json!({"times": {"grid_secs": 60, "max": 2}}),
                FieldValue::Times(vec![60]),
                FieldValue::Times(vec![60, 60]),
            ),
            (
                json!({"times": {"grid_secs": 60, "max": 2}}),
                FieldValue::Times(vec![60]),
                FieldValue::Times(vec![]),
            ),
            (
                json!({"times": {"grid_secs": 60, "max": 2}}),
                FieldValue::Times(vec![60]),
                FieldValue::Times(vec![61]),
            ),
            (
                json!({"times": {"grid_secs": 60, "max": 2}}),
                FieldValue::Times(vec![60]),
                FieldValue::Times(vec![60, 120, 180]),
            ),
            (json!({"text": {"max_chars": 3}}), text("abc"), text("abcd")),
            (
                json!({"text": {"max_chars": 9}}),
                text("abc"),
                text("a\u{202e}b"),
            ),
            (
                json!({"text": {"max_chars": 9}}),
                text("abc"),
                text("a\u{e0041}b"),
            ),
            (json!({"text": {"max_chars": 9}}), text("abc"), text("a\nb")),
        ];
        for (rule, good, bad) in cases {
            let rule: FieldRule = serde_json::from_value(rule).unwrap();
            assert!(rule.allows(&good), "{rule:?} {good:?}");
            assert!(!rule.allows(&bad), "{rule:?} {bad:?}");
        }
    }
}

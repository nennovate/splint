//! How much an agent may do without its owner: a level the owner signs, with general limits.
//!
//! The agent's model decides what to do. This decides only the ceiling, in code: how many actions
//! a day, how high a value a type's schema calls a value may go, and which of the owner's approvals
//! their own device may sign with no person there. What waits for the owner is what a type labels as
//! currency; a number it doesn't label as currency never waits (Nenye, 2026-11-15). Nothing here knows
//! what any type is for.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::requests::{
    ApprovalDraft, FieldValue, Fields, InteractionType, Operation, Schema, Schemas, Side, StepKind,
    Terms, cap_name,
};

/// The most actions any agent can take in a day, whatever its owner signed. It's an abuse limit,
/// so full auto stays under it too.
pub const MAX_ACTIONS_PER_DAY: u32 = 2500;
const DEFAULT_ACTIONS_PER_DAY: u32 = 250;
/// What part of the day's actions the owner's own device, or their delegate, may say yes to by itself.
/// Counted apart, so more sending doesn't mean more yeses. Provisional.
const APPROVALS_PART: u32 = 5;
const MAX_CAPPED_TYPES: usize = 16;
const MAX_CAPS_PER_TYPE: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Every approval waits for a person, and so does anything the agent would commit them to.
    AskMe,
    /// The owner's device signs approvals within the limits, and asks about the rest.
    #[default]
    AutoWithinLimits,
    /// The owner's device signs every approval, under the protocol's own limits.
    FullAuto,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub level: Level,
    /// Steps and messages the agent may send in a day, below full auto.
    pub actions_per_day: u32,
    /// The highest each value may go, by type and field. Only a field the type's schema lists in
    /// `values` can be capped, and a cap applies to what the agent sends and what's auto-approved.
    /// A value with a unit is capped in one unit at a time, as `amount_minor.usd`.
    #[serde(default)]
    pub caps: BTreeMap<InteractionType, BTreeMap<String, u64>>,
    /// Whether a price this owner's agent quotes, on the side its type says is paid, waits for them. Left
    /// out for the default, so rules that don't change it read as they did before it existed, by
    /// readers of either age.
    #[serde(default, skip_serializing_if = "QuotedPrices::is_default")]
    pub quoted_prices: QuotedPrices,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            level: Level::AutoWithinLimits,
            actions_per_day: DEFAULT_ACTIONS_PER_DAY,
            caps: BTreeMap::new(),
            quoted_prices: QuotedPrices::default(),
        }
    }
}

/// What becomes of a price the owner's agent names on the side that would be paid: its own `counter` or
/// `deliver` whose values are all ones its type's schema says that side is paid. Nenye decided on
/// 2026-11-13 that this is the owner's own signed setting. Its default, that it waits, is
/// provisional for Nenye. Anything else that carries a value, an `open` or anyone's `accept` or
/// `confirm` of one included, and any value a type doesn't say is paid to this side, always waits
/// (2026-11-11), as does anything the agent would commit them to at ask me.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotedPrices {
    /// It waits for the owner's yes, at every level.
    #[default]
    Wait,
    /// It goes as anything else does at the owner's level, so under their caps below full auto.
    WithinLimits,
}

impl QuotedPrices {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// What the terms a step leaves standing would commit its owner to, by the currency its type's schema
/// labels, and whom the schema says each amount is paid to. Core doesn't know what any of them means,
/// so an amount the schema doesn't say is paid to this side is one this side may be paying. A number
/// the type doesn't label as currency commits nobody to money, so it's never here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commits {
    /// No currency.
    Nothing,
    /// Currency, at least one amount of which the schema doesn't say is paid to this side.
    AValue,
    /// Only currency the schema says is paid to this side: a price it would be paid.
    ItsOwnPrice,
}

impl Commits {
    /// What these terms commit `side`'s owner to.
    pub fn of(schema: &Schema, terms: &Terms, side: Side) -> Self {
        let mut values = currency_in(schema, &terms.agreed)
            .chain(currency_in(schema, &terms.result))
            .peekable();
        if values.peek().is_none() {
            Self::Nothing
        } else if values.all(|(field, _)| schema.paid_to(field) == Some(side)) {
            Self::ItsOwnPrice
        } else {
            Self::AValue
        }
    }
}

/// Whether a step of this kind names a price, where what it leaves standing is only its own side's.
/// An `open` or an `accept` is never one: it puts on the table or takes up what's to be paid.
fn quotes_a_price(kind: StepKind, commits: Commits) -> bool {
    matches!(kind, StepKind::Counter | StepKind::Deliver) && commits == Commits::ItsOwnPrice
}

/// How high one value may go, in the unit it's in.
enum Ceiling {
    /// The owner set no cap on this value.
    None,
    At(u64),
    /// Capped, but not in this unit, so there's no reading the cap across.
    OtherUnit,
}

/// Whether the owner approved whoever is on the other side of an approval. Every caller says, so
/// nothing signs a value for someone the owner hasn't approved by leaving it out. See
/// [`super::VerifiedRules::counterparty`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counterparty {
    Approved,
    /// Someone the agent agreed with by itself. Anything carrying currency with them waits for the
    /// owner, at every level, and anything without any goes as it would with anyone.
    NotApproved,
}

/// Which of the owner's own settings leaves an approval to them, as `Permissions::decide` goes by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeftToOwner {
    /// Their level is ask me.
    AskMe,
    /// A step their agent asked for, or their own `confirm`, that would commit them to currency, such
    /// as a price, which waits for them at every level.
    CommitsAValue,
    /// A price their agent quotes as the side that would be paid, which their own `quoted_prices`
    /// has wait for them.
    QuotedPrice,
    /// A step their agent asked for with no currency in it, held while their level was ask me, which
    /// still waits for their answer.
    AskedAtAskMe,
    /// It carries currency, with someone their agent added and they haven't approved.
    NotApproved,
    /// Within limits, their device signs only a `confirm` by itself.
    NotAConfirm,
}

/// What the owner's device may do with one approval draft, with nobody there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoDecision {
    Sign,
    /// It waits for the owner.
    Ask,
}

impl Permissions {
    pub(crate) fn check(&self) -> Result<(), Error> {
        let fits = self.actions_per_day <= MAX_ACTIONS_PER_DAY
            && self.caps.len() <= MAX_CAPPED_TYPES
            && self
                .caps
                .values()
                .all(|caps| caps.len() <= MAX_CAPS_PER_TYPE);
        if fits { Ok(()) } else { Err(Error::Malformed) }
    }

    /// Whether a step of this kind waits for its owner's yes before anything is signed: at ask me,
    /// anything their agent would commit them to, and at every level, a step that would leave them
    /// committed to currency, such as a price, their own `confirm` of one included, unless it's a price
    /// their agent quotes on the side its type says is paid and their `quoted_prices` lets those go.
    /// `commits` is what the terms the step leaves standing commit them to, as [`Commits::of`] says.
    /// Nenye's calls on issue 809, of 2026-11-11 and 2026-11-13.
    pub fn waits_for_owner(&self, kind: StepKind, commits: Commits) -> bool {
        if kind.commits() && self.level == Level::AskMe {
            return true;
        }
        let binds = kind.commits() || kind == StepKind::Confirm;
        let let_go =
            quotes_a_price(kind, commits) && self.quoted_prices == QuotedPrices::WithinLimits;
        binds && commits != Commits::Nothing && !let_go
    }

    /// Whether a step the agent asks for waits for its owner before it goes, as
    /// [`Self::waits_for_owner`] says, apart from one place: where this side's owner signs the outcome
    /// anyway, by their own `confirm`, a value on an `open`, `counter`, `accept` or `deliver` doesn't
    /// hold the step too. That `confirm` waits for them at every level with the final terms in full,
    /// so one yes covers what a yes to the step would have, and nothing commits them before it. A
    /// price their agent quotes still goes by `quoted_prices`, ask me still holds everything, and so
    /// does currency with someone the owner hasn't approved, which waits at every level, as
    /// [`Counterparty::NotApproved`] says (Nenye, 2026-11-14). `signs_later` is whether this side's
    /// owner signs the outcome, as [`Schema::signed_by`] says.
    pub fn holds_step(
        &self,
        kind: StepKind,
        commits: Commits,
        signs_later: bool,
        counterparty: Counterparty,
    ) -> bool {
        if signs_later
            && counterparty == Counterparty::Approved
            && kind.commits()
            && self.level != Level::AskMe
            && !quotes_a_price(kind, commits)
        {
            return false;
        }
        self.waits_for_owner(kind, commits)
    }

    /// How many actions the agent may take in a day.
    pub fn actions_allowed_per_day(&self) -> u32 {
        match self.level {
            Level::FullAuto => MAX_ACTIONS_PER_DAY,
            Level::AskMe | Level::AutoWithinLimits => self.actions_per_day,
        }
    }

    /// How many yeses the owner's device, or their delegate, may say by itself in a day: a part of the
    /// day's actions, counted apart from them.
    pub fn approvals_allowed_per_day(&self) -> u32 {
        self.actions_allowed_per_day().div_ceil(APPROVALS_PART)
    }

    /// The cap on this value, in the unit `units` give it. A unit names one of the offer's fixed
    /// words, so it comes from the open's terms when a step doesn't carry it.
    fn ceiling(&self, schema: &Schema, field: &str, units: &[&Fields]) -> Ceiling {
        let Some(caps) = self.caps.get(schema.name()) else {
            return Ceiling::None;
        };
        let Some(unit) = schema.unit_of(field) else {
            return caps
                .get(field)
                .map_or(Ceiling::None, |cap| Ceiling::At(*cap));
        };
        let word = units.iter().find_map(|fields| match fields.get(unit) {
            Some(FieldValue::Text(word)) => Some(word.as_str()),
            _ => None,
        });
        if let Some(cap) = word.and_then(|word| caps.get(&cap_name(field, Some(word)))) {
            return Ceiling::At(*cap);
        }
        let in_some_unit = cap_name(field, Some(""));
        if caps
            .keys()
            .any(|name| name == field || name.starts_with(&in_some_unit))
        {
            Ceiling::OtherUnit
        } else {
            Ceiling::None
        }
    }

    /// Whether fields an agent wants to send stay under the owner's caps. A value with no cap has
    /// none, one capped only in other units is refused, and full auto has none at all. `agreed` is
    /// the offer on the table, which holds a unit a step leaves out.
    pub fn fits_caps(&self, schema: &Schema, fields: &Fields, agreed: &Fields) -> bool {
        if self.level == Level::FullAuto {
            return true;
        }
        values_in(schema, fields).all(|(field, value)| {
            match self.ceiling(schema, field, &[fields, agreed]) {
                Ceiling::None => true,
                Ceiling::At(cap) => value <= cap,
                Ceiling::OtherUnit => false,
            }
        })
    }

    /// The first cap that names a type these schemas don't have, or a value or unit its schema
    /// doesn't list, so it could never apply. The owner's device refuses to sign one.
    pub fn unbound_cap(&self, schemas: &Schemas) -> Option<String> {
        self.caps.iter().find_map(|(interaction, caps)| {
            let names = schemas
                .get(interaction)
                .map(|schema| schema.cap_names())
                .unwrap_or_default();
            caps.keys()
                .find(|name| !names.contains(name))
                .map(|name| format!("{name} on {}", interaction.as_str()))
        })
    }

    /// Whether the owner's device may sign this approval by itself. A `confirm` that carries currency
    /// waits for them at every level, as [`Self::waits_for_owner`] says, so what's left within limits is
    /// a `confirm` with none, and it never undoes a completed request. `signed_today` is what the device
    /// has signed by itself in the last day.
    pub fn decide(
        &self,
        schema: &Schema,
        draft: &ApprovalDraft,
        signed_today: u32,
        counterparty: Counterparty,
    ) -> AutoDecision {
        let terms = &draft.terms;
        if counterparty == Counterparty::NotApproved && carries_currency(schema, terms) {
            return AutoDecision::Ask;
        }
        // A yes to a step the agent asked for is only ever held for a person: at ask me, or for
        // currency it would commit them to, which waits for them at every level.
        if draft.operation.releases_a_step() || self.confirm_waits(schema, draft) {
            return AutoDecision::Ask;
        }
        let under = signed_today < self.approvals_allowed_per_day();
        let fits = match self.level {
            Level::AskMe => false,
            Level::FullAuto => under,
            Level::AutoWithinLimits => draft.operation == Operation::Confirm && under,
        };
        let same_type = &terms.interaction == schema.name();
        if fits && same_type {
            AutoDecision::Sign
        } else {
            AutoDecision::Ask
        }
    }

    /// A `confirm` that would commit its owner to currency, which waits for them at every level, as the
    /// step that named it did.
    fn confirm_waits(&self, schema: &Schema, draft: &ApprovalDraft) -> bool {
        draft.operation == Operation::Confirm
            && self.waits_for_owner(
                StepKind::Confirm,
                Commits::of(schema, &draft.terms, side_of(draft)),
            )
    }

    /// A yes to a price the agent quotes, which the owner's `quoted_prices` holds for them.
    fn holds_a_quote(&self, schema: &Schema, draft: &ApprovalDraft) -> bool {
        let kind = match draft.operation {
            Operation::Counter => StepKind::Counter,
            Operation::Deliver => StepKind::Deliver,
            _ => return false,
        };
        let commits = Commits::of(schema, &draft.terms, side_of(draft));
        quotes_a_price(kind, commits) && self.quoted_prices == QuotedPrices::Wait
    }

    /// Whether every value these terms carry has a cap, in its unit, and fits it, whatever the level.
    /// A value the owner never capped, or capped only in another unit, doesn't fit. This is what a
    /// reader holds a delegate's yes to.
    pub fn within_caps(&self, schema: &Schema, terms: &Terms) -> bool {
        let under_cap = |(field, value): (&str, u64)| matches!(self.ceiling(schema, field, &[&terms.agreed]), Ceiling::At(cap) if value <= cap);
        &terms.interaction == schema.name()
            && values_in(schema, &terms.agreed).all(under_cap)
            && values_in(schema, &terms.result).all(under_cap)
    }

    /// Which setting leaves this approval to its owner, so their page can say so and point at it.
    /// `None` is one their device may sign by itself, which waits only for it, or for the next day once
    /// today's limit is spent. A test holds this to `decide`, so the two can't drift apart.
    pub fn left_to_owner(
        &self,
        schema: &Schema,
        draft: &ApprovalDraft,
        counterparty: Counterparty,
    ) -> Option<LeftToOwner> {
        let carries = carries_currency(schema, &draft.terms);
        match self.level {
            Level::AskMe => Some(LeftToOwner::AskMe),
            // Below ask me, a step the agent asked for is held only for currency, unless it was held
            // while the level was ask me. A price it quotes is held by the owner's own setting.
            _ if draft.operation.releases_a_step()
                && carries
                && self.holds_a_quote(schema, draft) =>
            {
                Some(LeftToOwner::QuotedPrice)
            }
            _ if draft.operation.releases_a_step() && carries => Some(LeftToOwner::CommitsAValue),
            _ if draft.operation.releases_a_step() => Some(LeftToOwner::AskedAtAskMe),
            _ if counterparty == Counterparty::NotApproved && carries => {
                Some(LeftToOwner::NotApproved)
            }
            _ if self.confirm_waits(schema, draft) => Some(LeftToOwner::CommitsAValue),
            Level::FullAuto => None,
            Level::AutoWithinLimits if draft.operation != Operation::Confirm => {
                Some(LeftToOwner::NotAConfirm)
            }
            Level::AutoWithinLimits => None,
        }
    }
}

/// Whose owner a draft asks, by which side's agent it names.
fn side_of(draft: &ApprovalDraft) -> Side {
    if draft.terms.recipient.agent == draft.agent {
        Side::Recipient
    } else {
        Side::Requester
    }
}

/// Whether these terms commit anyone to currency, agreed or delivered.
pub fn carries_currency(schema: &Schema, terms: &Terms) -> bool {
    names_currency(schema, &terms.agreed) || names_currency(schema, &terms.result)
}

/// Whether these fields hold an amount the schema labels as currency.
pub fn names_currency(schema: &Schema, fields: &Fields) -> bool {
    currency_in(schema, fields).next().is_some()
}

/// The fields the schema labels as currency, with their amounts.
fn currency_in<'a>(schema: &'a Schema, fields: &'a Fields) -> impl Iterator<Item = (&'a str, u64)> {
    values_in(schema, fields).filter(|(name, _)| schema.is_currency(name))
}

/// The fields the schema calls values, with their numbers. A value written any other way can't fit
/// the schema, so it's never here.
fn values_in<'a>(schema: &'a Schema, fields: &'a Fields) -> impl Iterator<Item = (&'a str, u64)> {
    fields
        .iter()
        .filter(|(name, _)| schema.is_value(name))
        .filter_map(|(name, value)| match value {
            FieldValue::Int(number) => Some((name.as_str(), *number)),
            FieldValue::Text(_) | FieldValue::Times(_) => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requests::{Terms, TermsParty, examples};
    use crate::{MessageId, SigningKey, SplintId, test_identity};

    fn quote_type() -> InteractionType {
        crate::requests::example("quote/1")
    }

    fn quote() -> Schema {
        examples().get(&quote_type()).unwrap().as_ref().clone()
    }

    fn someone() -> SplintId {
        test_identity(&SigningKey::generate().unwrap()).id().clone()
    }

    fn offer_in(currency: &str) -> Fields {
        Fields::from([
            ("currency".to_owned(), FieldValue::Text(currency.to_owned())),
            ("item".to_owned(), FieldValue::Text("catering".to_owned())),
            ("quantity".to_owned(), FieldValue::Int(40)),
        ])
    }

    fn draft(operation: Operation, amount: u64) -> ApprovalDraft {
        let party = || TermsParty {
            agent: someone(),
            owner: someone(),
        };
        let agreed = offer_in("usd");
        let result = Fields::from([
            ("amount_minor".to_owned(), FieldValue::Int(amount)),
            ("valid_days".to_owned(), FieldValue::Int(14)),
        ]);
        ApprovalDraft {
            owner: someone(),
            agent: someone(),
            operation,
            request: MessageId::of(b"open"),
            version: 1,
            prev: MessageId::of(b"deliver"),
            terms: Terms {
                interaction: quote_type(),
                requester: party(),
                recipient: party(),
                agreed,
                result,
                subject: None,
                note: None,
                supersedes: None,
            },
            latest_expiry: 0,
        }
    }

    fn capped(level: Level, cap: Option<u64>) -> Permissions {
        let mut caps = BTreeMap::new();
        if let Some(cap) = cap {
            caps.insert(
                quote_type(),
                BTreeMap::from([("amount_minor.usd".to_owned(), cap)]),
            );
        }
        Permissions {
            level,
            actions_per_day: 10,
            caps,
            quoted_prices: QuotedPrices::Wait,
        }
    }

    /// The same, with prices its agent quotes let go within those limits.
    fn letting_quotes_go(level: Level) -> Permissions {
        Permissions {
            quoted_prices: QuotedPrices::WithinLimits,
            ..capped(level, None)
        }
    }

    /// A draft asking the recipient's owner, whose agent would be paid.
    fn the_recipients(operation: Operation, amount: u64) -> ApprovalDraft {
        let mut draft = draft(operation, amount);
        draft.agent = draft.terms.recipient.agent.clone();
        draft.owner = draft.terms.recipient.owner.clone();
        draft
    }

    /// The same draft with no value in it, as a quote's confirm would be without its price.
    fn unpriced(operation: Operation) -> ApprovalDraft {
        let mut draft = draft(operation, 0);
        draft.terms.result = Fields::new();
        draft
    }

    #[test]
    fn each_level_signs_only_what_it_says() {
        let schema = quote();
        let confirm = unpriced(Operation::Confirm);
        let decide = |permissions: &Permissions, draft: &ApprovalDraft, today| {
            permissions.decide(&schema, draft, today, Counterparty::Approved)
        };
        let within = capped(Level::AutoWithinLimits, Some(50_000));
        assert_eq!(decide(&within, &confirm, 0), AutoDecision::Sign);
        // Yeses are a part of the day's actions, counted apart, so more sending isn't more yeses.
        assert_eq!(decide(&within, &confirm, 1), AutoDecision::Sign);
        assert_eq!(decide(&within, &confirm, 2), AutoDecision::Ask);
        assert_eq!(
            decide(&within, &unpriced(Operation::Cancel), 0),
            AutoDecision::Ask
        );

        let ask = capped(Level::AskMe, Some(u64::MAX));
        assert_eq!(decide(&ask, &confirm, 0), AutoDecision::Ask);

        let full = capped(Level::FullAuto, None);
        assert_eq!(
            decide(&full, &draft(Operation::Cancel, u64::MAX), 3),
            AutoDecision::Sign
        );
        assert_eq!(decide(&full, &confirm, 3), AutoDecision::Sign);
        assert_eq!(
            decide(&full, &confirm, MAX_ACTIONS_PER_DAY / 5),
            AutoDecision::Ask
        );
    }

    /// Bug caught: the owner's device, or their delegate, signing a `confirm` that commits
    /// them to a price, at full auto or within a cap, where setup and the page tell them anything with
    /// an amount waits for them, Full auto included.
    #[test]
    fn a_confirm_with_a_price_waits_for_its_owner_at_every_level() {
        let schema = quote();
        let priced = draft(Operation::Confirm, 40_000);
        for permissions in [
            capped(Level::AutoWithinLimits, Some(50_000)),
            capped(Level::FullAuto, None),
            capped(Level::FullAuto, Some(u64::MAX)),
        ] {
            assert_eq!(
                permissions.decide(&schema, &priced, 0, Counterparty::Approved),
                AutoDecision::Ask,
                "{permissions:?}"
            );
            assert_eq!(
                permissions.left_to_owner(&schema, &priced, Counterparty::Approved),
                Some(LeftToOwner::CommitsAValue)
            );
            for commits in [Commits::AValue, Commits::ItsOwnPrice] {
                assert!(permissions.waits_for_owner(StepKind::Confirm, commits));
            }
            assert!(!permissions.waits_for_owner(StepKind::Confirm, Commits::Nothing));
        }
    }

    /// Bugs caught (issue 809, Nenye's call of 2026-11-13): a price an owner's agent quotes going
    /// without them where they never let it, or held where they did; the setting letting go what the
    /// paying side takes on, which always waits; and currency in a type the owner hasn't approved taken
    /// as a price it would be paid, by its writer's word, so the side paying it was committed by itself.
    #[test]
    fn only_a_price_its_agent_quotes_goes_and_only_where_its_owner_signed_that() {
        let schema = quote();
        let priced = draft(Operation::Deliver, 40_000).terms;
        assert_eq!(
            Commits::of(&schema, &priced, Side::Recipient),
            Commits::ItsOwnPrice
        );
        assert_eq!(
            Commits::of(&schema, &priced, Side::Requester),
            Commits::AValue
        );
        // Where the owner hasn't approved the type, the side its writer says is paid doesn't count.
        assert_eq!(
            Commits::of(&schema.unapproved(), &priced, Side::Recipient),
            Commits::AValue
        );
        for level in [Level::AutoWithinLimits, Level::FullAuto] {
            let held = capped(level, None);
            let let_go = letting_quotes_go(level);
            for kind in [StepKind::Counter, StepKind::Deliver] {
                assert!(held.waits_for_owner(kind, Commits::ItsOwnPrice), "{kind:?}");
                assert!(
                    !let_go.waits_for_owner(kind, Commits::ItsOwnPrice),
                    "{kind:?}"
                );
                assert!(let_go.waits_for_owner(kind, Commits::AValue), "{kind:?}");
            }
            for kind in [StepKind::Open, StepKind::Accept, StepKind::Confirm] {
                for commits in [Commits::AValue, Commits::ItsOwnPrice] {
                    assert!(
                        let_go.waits_for_owner(kind, commits),
                        "{kind:?} {commits:?}"
                    );
                }
            }
            // What the page says holds a quote is the owner's own setting.
            let deliver = the_recipients(Operation::Deliver, 40_000);
            assert_eq!(
                held.left_to_owner(&schema, &deliver, Counterparty::Approved),
                Some(LeftToOwner::QuotedPrice)
            );
            assert_eq!(
                held.left_to_owner(
                    &schema,
                    &draft(Operation::Deliver, 1),
                    Counterparty::Approved
                ),
                Some(LeftToOwner::CommitsAValue)
            );
            let confirm = the_recipients(Operation::Confirm, 40_000);
            assert_eq!(
                let_go.decide(&schema, &confirm, 0, Counterparty::Approved),
                AutoDecision::Ask
            );
        }
        let ask = letting_quotes_go(Level::AskMe);
        assert!(ask.waits_for_owner(StepKind::Deliver, Commits::ItsOwnPrice));
        assert!(ask.waits_for_owner(StepKind::Deliver, Commits::Nothing));
    }

    #[test]
    fn what_a_page_says_holds_an_approval_is_what_holds_it() {
        let schema = quote();
        let settings = [
            capped(Level::AskMe, Some(u64::MAX)),
            capped(Level::AutoWithinLimits, Some(50_000)),
            capped(Level::AutoWithinLimits, None),
            capped(Level::FullAuto, None),
            letting_quotes_go(Level::AutoWithinLimits),
        ];
        let drafts = [
            draft(Operation::Confirm, 50_000),
            unpriced(Operation::Confirm),
            draft(Operation::Cancel, 1),
            draft(Operation::Accept, 1),
            unpriced(Operation::Accept),
            the_recipients(Operation::Deliver, 1),
            the_recipients(Operation::Confirm, 1),
        ];
        for permissions in &settings {
            for draft in &drafts {
                for party in [Counterparty::Approved, Counterparty::NotApproved] {
                    let said = permissions.left_to_owner(&schema, draft, party);
                    let asked = permissions.decide(&schema, draft, 0, party) == AutoDecision::Ask;
                    assert_eq!(said.is_some(), asked, "{permissions:?} {draft:?} {party:?}");
                }
            }
        }
        let within = &settings[1];
        assert_eq!(
            within.left_to_owner(&schema, &drafts[2], Counterparty::Approved),
            Some(LeftToOwner::NotAConfirm)
        );
        // Bug caught: a move held at ask me, with no value, said to wait for a value it doesn't carry.
        assert_eq!(
            within.left_to_owner(&schema, &drafts[4], Counterparty::Approved),
            Some(LeftToOwner::AskedAtAskMe)
        );
    }

    /// Bugs caught: one yes letting a value go to someone the owner never approved, so a fooled agent
    /// that agreed a contact with anyone could put its owner's money on the table with them untouched;
    /// a price the agent quotes going past `quoted_prices` because the owner signs the outcome later;
    /// ask me letting anything go; and the step a buyer's own confirm covers still held for a yes.
    #[test]
    fn one_yes_covers_a_step_only_with_someone_approved_and_never_past_ask_me_or_a_quote() {
        for level in [Level::AutoWithinLimits, Level::FullAuto] {
            let held = capped(level, None);
            let let_go = letting_quotes_go(level);
            for kind in [StepKind::Open, StepKind::Accept, StepKind::Counter] {
                assert!(
                    !held.holds_step(kind, Commits::AValue, true, Counterparty::Approved),
                    "{level:?} {kind:?}: their own confirm waits for them anyway"
                );
                assert!(
                    held.holds_step(kind, Commits::AValue, false, Counterparty::Approved),
                    "{level:?} {kind:?}: nothing of theirs waits later"
                );
                assert!(
                    held.holds_step(kind, Commits::AValue, true, Counterparty::NotApproved),
                    "{level:?} {kind:?}: a value with someone they didn't approve"
                );
                assert!(
                    !held.holds_step(kind, Commits::Nothing, true, Counterparty::NotApproved),
                    "{level:?} {kind:?}: no value goes as with anyone"
                );
            }
            for kind in [StepKind::Counter, StepKind::Deliver] {
                assert!(
                    held.holds_step(kind, Commits::ItsOwnPrice, true, Counterparty::Approved),
                    "{level:?} {kind:?}: a quote goes by quoted_prices"
                );
                assert!(
                    !let_go.holds_step(kind, Commits::ItsOwnPrice, true, Counterparty::Approved),
                    "{level:?} {kind:?}"
                );
            }
        }
        let ask = capped(Level::AskMe, None);
        for kind in [StepKind::Open, StepKind::Accept, StepKind::Deliver] {
            for commits in [Commits::Nothing, Commits::AValue] {
                assert!(
                    ask.holds_step(kind, commits, true, Counterparty::Approved),
                    "{kind:?} {commits:?}"
                );
            }
        }
    }

    /// Bug caught: a delegate or an owner's device signing a value with someone the owner never
    /// approved, because the owner chose full auto, so a fooled agent that agreed a contact with anyone
    /// could commit its owner to them.
    #[test]
    fn a_value_with_someone_the_owner_hasnt_approved_waits_for_them() {
        let schema = quote();
        let priced = draft(Operation::Cancel, 50_000);
        let free = unpriced(Operation::Confirm);
        let full = capped(Level::FullAuto, None);
        assert_eq!(
            full.decide(&schema, &priced, 0, Counterparty::NotApproved),
            AutoDecision::Ask
        );
        assert_eq!(
            full.left_to_owner(&schema, &priced, Counterparty::NotApproved),
            Some(LeftToOwner::NotApproved)
        );
        assert_eq!(
            full.decide(&schema, &priced, 0, Counterparty::Approved),
            AutoDecision::Sign
        );
        assert_eq!(
            full.decide(&schema, &free, 0, Counterparty::NotApproved),
            AutoDecision::Sign
        );
    }

    #[test]
    fn ask_me_holds_what_commits_an_owner_and_nothing_else() {
        let ask = capped(Level::AskMe, None);
        for kind in [
            StepKind::Open,
            StepKind::Counter,
            StepKind::Accept,
            StepKind::Deliver,
        ] {
            assert!(ask.waits_for_owner(kind, Commits::Nothing), "{kind:?}");
            let within = capped(Level::AutoWithinLimits, None);
            let full = capped(Level::FullAuto, None);
            assert!(!within.waits_for_owner(kind, Commits::Nothing));
            assert!(!full.waits_for_owner(kind, Commits::Nothing));
            // Issue 809: by default a price waits for its owner at every level, as setup and the page
            // say.
            for commits in [Commits::AValue, Commits::ItsOwnPrice] {
                assert!(within.waits_for_owner(kind, commits));
                assert!(full.waits_for_owner(kind, commits));
            }
        }
        for kind in [
            StepKind::Say,
            StepKind::Clarify,
            StepKind::Progress,
            StepKind::Pause,
            StepKind::Resume,
            StepKind::Decline,
            StepKind::Cancel,
        ] {
            assert!(!ask.waits_for_owner(kind, Commits::AValue), "{kind:?}");
        }
    }

    #[test]
    fn a_draft_of_another_type_is_never_judged_by_this_ones_caps() {
        let schema = quote();
        let mut other = unpriced(Operation::Confirm);
        other.terms.interaction =
            InteractionType::try_from(format!("quote/2@{}", "a".repeat(52))).unwrap();
        let within = capped(Level::AutoWithinLimits, Some(50_000));
        assert_eq!(
            within.decide(&schema, &other, 0, Counterparty::Approved),
            AutoDecision::Ask
        );
    }

    #[test]
    fn an_agent_stays_under_its_caps_below_full_auto() {
        let schema = quote();
        let result = |amount| {
            Fields::from([
                ("amount_minor".to_owned(), FieldValue::Int(amount)),
                ("valid_days".to_owned(), FieldValue::Int(14)),
            ])
        };
        let usd = offer_in("usd");
        let within = capped(Level::AutoWithinLimits, Some(100));
        assert!(within.fits_caps(&schema, &result(100), &usd));
        assert!(!within.fits_caps(&schema, &result(101), &usd));
        assert!(!capped(Level::AskMe, Some(100)).fits_caps(&schema, &result(101), &usd));
        assert!(capped(Level::FullAuto, Some(100)).fits_caps(&schema, &result(101), &usd));
        assert!(capped(Level::AutoWithinLimits, None).fits_caps(&schema, &result(u64::MAX), &usd));
    }

    #[test]
    fn a_cap_in_one_currency_is_no_ceiling_in_another() {
        let schema = quote();
        let result = Fields::from([
            ("amount_minor".to_owned(), FieldValue::Int(10_000)),
            ("valid_days".to_owned(), FieldValue::Int(14)),
        ]);
        let within = capped(Level::AutoWithinLimits, Some(50_000));
        assert!(within.fits_caps(&schema, &result, &offer_in("usd")));
        assert!(!within.fits_caps(&schema, &result, &offer_in("gbp")));

        // A delegate's yes is held to its caps by each reader the same way.
        let mut in_gbp = draft(Operation::Confirm, 1);
        in_gbp.terms.agreed = offer_in("gbp");
        assert!(!within.within_caps(&schema, &in_gbp.terms));
        let mut both = within.clone();
        if let Some(caps) = both.caps.get_mut(&quote_type()) {
            caps.insert("amount_minor.gbp".to_owned(), 100);
        }
        assert!(!both.fits_caps(&schema, &result, &offer_in("eur")));
        assert!(both.within_caps(&schema, &in_gbp.terms));
    }

    #[test]
    fn a_cap_that_could_never_apply_is_found_before_it_is_signed() {
        let schemas = examples();
        let id = |interaction: &str| match schemas.named(interaction) {
            Some(schema) => schema.name().clone(),
            None => InteractionType::try_from(format!("{interaction}@{}", "a".repeat(52))).unwrap(),
        };
        let with = |interaction: &str, name: &str| Permissions {
            caps: BTreeMap::from([(id(interaction), BTreeMap::from([(name.to_owned(), 1)]))]),
            ..Permissions::default()
        };
        assert_eq!(
            with("quote/1", "amount_minor.usd").unbound_cap(&schemas),
            None
        );
        for (interaction, name) in [
            ("quote/1", "amount_minor"),
            ("quote/1", "amount_minr.usd"),
            ("quote/1", "amount_minor.jpy"),
            ("quote/1", "quantity"),
            ("quote/9", "amount_minor.usd"),
        ] {
            assert_eq!(
                with(interaction, name).unbound_cap(&schemas),
                Some(format!("{name} on {}", id(interaction).as_str())),
            );
        }
    }
}

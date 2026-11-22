//! An owner's signed rules for one agent. See `docs/protocol.md`.
//!
//! Rules are one whole document, replaced whole, so a host can't drop one change from a series. They
//! take effect only if the owner's signature verifies, so an agent can't change its own limits.
//!
//! A host and Signet each run [`VerifiedRules::admit`] on every message, so what gets through is
//! decided by this one function and the owner's signature, whichever of them is honest.
//!
//! Besides contacts and invitations, the owner sets who else may reach the agent and whom it may
//! write to, in [`Reach`], and how much it may do by itself, in [`Permissions`].

mod permissions;
mod reach;

use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize};

use crate::changes::ChangeRules;
use crate::delegation::{PART_SEPARATOR, VerifiedDelegation, is_a_name};
use crate::requests::{ApprovalDraft, InteractionType, Schema, TermsParty, has_hidden_characters};
use crate::{
    CLOCK_TOLERANCE_SECS, DeliveryProof, Error, Identity, MessageId, PublicKey, Sealing,
    SigningKey, SplintId, jws,
};

pub use permissions::{
    AutoDecision, Commits, Counterparty, LeftToOwner, Level, MAX_ACTIONS_PER_DAY, Permissions,
    QuotedPrices, carries_currency, names_currency,
};
pub use reach::{
    Agreed, Inbound, InboundFilter, InboundFrom, ListedHost, Outbound, Reach, Sender,
    UNCONFIRMED_SHARE_OF_QUOTA, UnknownSenders,
};

pub(crate) const RULES_TYPE: &str = "splint-rules";
const RULES_VERSION: u8 = 1;
/// A fooled agent's leak goes up with this, as `docs/protocol.md` says, so it's the owner's to raise.
/// This only keeps the number sane: the most that counts is what the agent's host allows.
const MAX_NEW_REQUESTS_PER_CONTACT_PER_DAY: u32 = 100_000;
const MAX_OPEN_REQUESTS_PER_CONTACT: u32 = 3;
const MAX_OPEN_APPROVALS: u32 = 10;
/// New interactions and messages a day from everyone the owner's reach setting lets in, together,
/// so an open agent can't be flooded by IDs made for the purpose. The same goes for this number.
const MAX_FROM_OTHERS_PER_DAY: u32 = 100_000;
const DEFAULT_FROM_OTHERS_PER_DAY: u32 = 250;
/// Messages of words an agent chose, per contact per day, each way. Two agents answering each other
/// stop here, and an owner can only lower it.
pub const MAX_TEXTS_PER_CONTACT_PER_DAY: u32 = 200;
const DEFAULT_TEXTS_PER_CONTACT_PER_DAY: u32 = 100;
/// The most messages of words a day, each way, with anyone the owner hasn't named, such as a contact
/// the agent agreed with by itself, whatever the rules say for contacts. Provisional.
pub const UNAPPROVED_TEXTS_PER_DAY: u32 = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactStatus {
    Allowed,
    Blocked,
}

/// How the owner came to trust a contact's IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinnedBy {
    Invite,
    Owner,
    /// Not a contact at all: someone the owner's reach setting let in. Signet uses this for them,
    /// and signed rules can't.
    Reach,
    /// Someone this agent agreed with by itself, an invite one signed and the other accepted, whom the
    /// owner hasn't approved. Signet and hosts make these entries from the two signatures, and signed
    /// rules can't: an owner who approves one names them as `owner` or `invite`.
    Agent,
}

impl PinnedBy {
    /// Whether the owner chose this contact by name: signed them in, or signed them in from an invite.
    pub fn by_owner(self) -> bool {
        matches!(self, Self::Owner | Self::Invite)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesContact {
    /// A contact is one ID. Who it acts for can change, and the rules still name it.
    pub agent: SplintId,
    pub address: String,
    pub label: String,
    pub status: ContactStatus,
    /// The types the owner approved for this contact by name, by their fingerprinted IDs. Others the
    /// two agents agree, where `agree_types` lets them.
    pub types: Vec<InteractionType>,
    pub text: bool,
    /// Whether this contact's agent and this one may agree types between themselves with `type/1`,
    /// which no owner signs. On unless the owner turns it off.
    #[serde(default = "on")]
    pub agree_types: bool,
    pub pinned_by: PinnedBy,
}

pub(crate) fn on() -> bool {
    true
}

impl RulesContact {
    /// A contact with something to use: a type the owner approved, types to agree, or words. One with
    /// none of those is a removal.
    fn can_have_requests(&self) -> bool {
        self.status == ContactStatus::Allowed
            && (!self.types.is_empty() || self.agree_types || self.text)
    }

    /// Whether the owner lets this contact use this type: core's plain conversation with `text`, a
    /// `type/1` where they may agree types, a type the owner approved by name, or one the two agents
    /// agreed where they may. The schema has to come from what this Signet holds agreed with them, as
    /// every schema a Signet holds for a contact does. A type that can carry words someone chose, or
    /// as much as they like in numbers, also needs the owner's `text` for this contact, as
    /// [`Schema::needs_text`] says, so a typed contact can't be moved to prose. This owner's own agent
    /// moves in a type with currency only once they approve it, as [`Self::approved_for_use`] says.
    pub fn may_use(&self, schema: &Schema) -> bool {
        let name = schema.name();
        let allowed = if name.is_conversation() {
            self.text
        } else if name.is_proposal() {
            self.agree_types
        } else {
            self.types.contains(name) || self.agree_types
        };
        self.can_have_requests() && allowed && (self.text || !schema.needs_text())
    }

    /// Whether this owner's own agent may move in this type with this contact, as far as currency goes:
    /// a type with currency only once the owner approved it for them by name, and any other type as
    /// [`Self::may_use`] says (Nenye, 2026-11-15). What the other side sends still arrives, as nothing
    /// it sends commits this owner: their agent's moves wait for this, and a commitment to currency
    /// waits for them anyway.
    pub fn approved_for_use(&self, schema: &Schema) -> bool {
        !schema.includes_currency() || self.types.contains(schema.name())
    }

    /// Whether this contact may propose this type, or be proposed it: always where they may agree
    /// types, and otherwise only a type the owner approved for them by name, which is how someone the
    /// owner lets in for one of those first gets its schema. Agreeing a type with currency commits
    /// nobody, so it needs no approval; using one does, as [`Self::approved_for_use`] says.
    pub fn may_propose(&self, proposed: &Schema) -> bool {
        self.can_have_requests()
            && (self.agree_types || self.types.contains(proposed.name()))
            && (self.text || !proposed.needs_text())
    }

    /// Whether the owner approved this type for this contact by name, so the sides its currency is
    /// paid to count. Core's own types have none.
    pub fn approved_type(&self, interaction: &InteractionType) -> bool {
        !interaction.is_agreed() || self.types.contains(interaction)
    }

    /// Whether a person's words may reach this agent from them. A contact's owner is someone this
    /// owner chose. Anyone can make an owner key, so for someone only a setting let in, those words
    /// are words they chose, and need that setting's `text`.
    pub fn may_carry_person_text(&self) -> bool {
        self.pinned_by.by_owner() || self.text
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesInvite {
    pub id: String,
    pub key: String,
    pub types: Vec<InteractionType>,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesLimits {
    pub new_requests_per_contact_per_day: u32,
    pub open_requests_per_contact: u32,
    pub open_approvals: u32,
    /// For everyone `reach` lets in who isn't a contact, together.
    #[serde(default = "default_from_others_per_day")]
    pub new_from_others_per_day: u32,
    #[serde(default = "default_texts_per_contact_per_day")]
    pub texts_per_contact_per_day: u32,
    /// Messages of words a day, each way, with each contact the agent added by itself and anyone else
    /// the owner hasn't named, at most [`UNAPPROVED_TEXTS_PER_DAY`], which it is when left out. Never
    /// more than `texts_per_contact_per_day`, so it's always the tighter of the two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreed_texts_per_day: Option<u32>,
    /// Interactions started a day, each way, with each of them. Left out, it's
    /// `new_requests_per_contact_per_day`, and never more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreed_new_requests_per_day: Option<u32>,
    /// Everything this agent sends through its host in an hour. Without it, the host's own limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sends_per_hour: Option<u32>,
    /// And in a day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sends_per_day: Option<u32>,
}

fn default_from_others_per_day() -> u32 {
    DEFAULT_FROM_OTHERS_PER_DAY
}

fn default_texts_per_contact_per_day() -> u32 {
    DEFAULT_TEXTS_PER_CONTACT_PER_DAY
}

/// What a host knows of an `open`, from its outside, sealed or not.
#[derive(Clone, Copy, Debug)]
pub struct Opening<'a> {
    pub interaction: &'a InteractionType,
    /// On a `type/1`, the type it proposes.
    pub proposes: Option<&'a InteractionType>,
    /// The host saw this type's ID proposed by a `type/1` between these two agents. It can't tell
    /// whether the other side accepted, which their Signet decides.
    pub seen_proposed: bool,
}

impl<'a> Opening<'a> {
    /// An `open` of this type, with nothing proposed or seen, as most are.
    pub fn named(interaction: &'a InteractionType) -> Self {
        Self {
            interaction,
            proposes: None,
            seen_proposed: false,
        }
    }

    /// Whether an entry with these types, `text` and `agree_types` lets this open in.
    fn fits(&self, types: &[InteractionType], text: bool, agree_types: bool) -> bool {
        let interaction = self.interaction;
        if interaction.is_conversation() {
            text
        } else if interaction.is_proposal() {
            agree_types
                || self
                    .proposes
                    .is_some_and(|proposed| types.contains(proposed))
        } else {
            types.contains(interaction) || (agree_types && self.seen_proposed)
        }
    }
}

/// What happens to a message from one sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Deliver,
    /// From someone who'd be delivered, but the rules have the agent stopped. It stays on the host,
    /// unseen, because a pause mustn't lose what a contact sent. The sender is told the same as for
    /// quarantine, so a pause can't be told from a block.
    Wait,
    /// Held for the owner, and never shown to the agent.
    Quarantine,
    /// Gone. The sender is told the same as for quarantine, so a block can't be detected.
    Drop,
}

/// What an owner decides. The owner's device adds who it's for, the sequence and the dates.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesDraft {
    pub paused: bool,
    /// Contacts only, and nobody else, unless the owner says otherwise.
    #[serde(default)]
    pub reach: Reach,
    /// Auto within limits, unless the owner says otherwise.
    #[serde(default)]
    pub permissions: Permissions,
    /// What follows when a contact's owner, key, Signet or host changes.
    #[serde(default)]
    pub changes: ChangeRules,
    /// Sealed, so no host can read what this agent says or hears, unless the owner says otherwise.
    #[serde(default)]
    pub sealing: Sealing,
    /// The one [delegation](crate::delegation) these rules allow, by its name, or none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<String>,
    /// When the owner wants these rules to stop the agent, if they ever do. Without it they last until
    /// the owner signs others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<u64>,
    pub contacts: Vec<RulesContact>,
    pub invites: Vec<RulesInvite>,
    pub limits: RulesLimits,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesPayload {
    v: u8,
    owner: SplintId,
    agent: SplintId,
    seq: u64,
    issued_at: u64,
    /// The 30 days rules lasted before 2026-11-15, when a device set it on every rules document. It
    /// was never the owner's choice, so it's read and not acted on, and nothing writes it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    /// The end the owner chose, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ends_at: Option<u64>,
    paused: bool,
    reach: Reach,
    permissions: Permissions,
    /// Rules signed before this field existed get the defaults.
    #[serde(default)]
    changes: ChangeRules,
    #[serde(default)]
    sealing: Sealing,
    /// Rules that name no delegation allow none.
    #[serde(
        default,
        deserialize_with = "a_name_if_there",
        skip_serializing_if = "Option::is_none"
    )]
    delegation: Option<String>,
    contacts: Vec<RulesContact>,
    invites: Vec<RulesInvite>,
    limits: RulesLimits,
}

/// A `delegation` that's there is a string. Leaving it out is the one way to name none, so `null`, which
/// the Go verifier refuses, is malformed here too.
fn a_name_if_there<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

impl RulesPayload {
    fn in_force(&self, now: u64) -> bool {
        !self.paused && !self.ended(now)
    }

    fn ended(&self, now: u64) -> bool {
        self.ends_at.is_some_and(|end| now >= end)
    }

    fn invite_lets_in(&self, id: &str, now: u64) -> bool {
        self.invites
            .iter()
            .any(|invite| invite.id == id && now < invite.expires_at && !invite.types.is_empty())
    }

    /// Every type the owner names, which must be one two agents can agree: core's own aren't the
    /// owner's to name.
    fn types_named_well(&self) -> bool {
        self.contacts
            .iter()
            .flat_map(|contact| &contact.types)
            .chain(self.invites.iter().flat_map(|invite| &invite.types))
            .chain(self.permissions.caps.keys())
            .all(InteractionType::is_agreed)
    }

    /// What a contact this agent agreed with by itself gets, if the owner turned that on: never one the
    /// rules name at all, as a block or a removal, which always wins, and never at `ask_me`, where the
    /// agent can't add a contact by itself, as [`VerifiedRules::lets_its_agent_invite`] says.
    fn agreed_lets_in(&self, sender: &Sender) -> Option<&Agreed> {
        let agreed = agreed_counts(&self.reach, &self.permissions)?;
        let lets_in = sender.agreed && self.listed(sender.agent).is_none();
        lets_in.then_some(agreed)
    }

    fn admit(&self, sender: &Sender, redeemed_invite: Option<&str>, now: u64) -> Admission {
        let admission = self.admit_in_force(sender, redeemed_invite, now);
        match (self.in_force(now), admission) {
            (true, _) => admission,
            (false, Admission::Deliver) => Admission::Wait,
            (false, _) => Admission::Drop,
        }
    }

    fn listed(&self, agent: &SplintId) -> Option<&RulesContact> {
        self.contacts.iter().find(|contact| &contact.agent == agent)
    }

    fn blocks(&self, agent: &SplintId) -> bool {
        self.listed(agent)
            .is_some_and(|contact| contact.status == ContactStatus::Blocked)
    }

    /// A contact with types to use. One with none is judged like anyone else.
    fn listed_with_types(&self, agent: &SplintId) -> Option<&RulesContact> {
        self.listed(agent)
            .filter(|contact| contact.can_have_requests())
    }

    fn admit_in_force(
        &self,
        sender: &Sender,
        redeemed_invite: Option<&str>,
        now: u64,
    ) -> Admission {
        if self.blocks(sender.agent) {
            return Admission::Drop;
        }
        if self.listed_with_types(sender.agent).is_some()
            || redeemed_invite.is_some_and(|id| self.invite_lets_in(id, now))
            || self.agreed_lets_in(sender).is_some()
            || self.reach.lets_in(sender)
        {
            return Admission::Deliver;
        }
        // Their owner hasn't confirmed, so there's nobody to ask about them, and holding them would let
        // anyone fill an owner's quarantine with IDs that cost nothing.
        if sender.unconfirmed {
            return Admission::Drop;
        }
        match self.reach.inbound.strangers {
            UnknownSenders::Quarantine => Admission::Quarantine,
            UnknownSenders::Block => Admission::Drop,
        }
    }

    fn check_fields(&self) -> Result<(), Error> {
        let dates_fit = self.ends_at.is_none_or(|end| end > self.issued_at);
        let limits_fit = self.limits.new_requests_per_contact_per_day
            <= MAX_NEW_REQUESTS_PER_CONTACT_PER_DAY
            && self.limits.open_requests_per_contact <= MAX_OPEN_REQUESTS_PER_CONTACT
            && self.limits.open_approvals <= MAX_OPEN_APPROVALS;
        let limits_fit =
            limits_fit && self.limits.new_from_others_per_day <= MAX_FROM_OTHERS_PER_DAY;
        let limits_fit =
            limits_fit && self.limits.texts_per_contact_per_day <= MAX_TEXTS_PER_CONTACT_PER_DAY;
        let limits_fit = limits_fit
            && self
                .limits
                .agreed_texts_per_day
                .is_none_or(|texts| texts <= UNAPPROVED_TEXTS_PER_DAY)
            && self
                .limits
                .agreed_new_requests_per_day
                .is_none_or(|new| new <= MAX_NEW_REQUESTS_PER_CONTACT_PER_DAY);
        let delegation_fits = self.delegation.as_deref().is_none_or(is_a_name);
        if self.v != RULES_VERSION
            || !dates_fit
            || !limits_fit
            || !delegation_fits
            || !self.types_named_well()
        {
            return Err(Error::Malformed);
        }
        self.reach.check()?;
        self.permissions.check()?;
        for invite in &self.invites {
            PublicKey::from_encoded(&invite.key)?;
        }
        // One entry each, so no reader has to guess which of two the owner's signature meant.
        let mut agents = HashSet::new();
        let mut addresses = HashSet::new();
        for contact in &self.contacts {
            crate::parse_address(&contact.address)?;
            // A name the owner reads on every screen, and signs here.
            if matches!(contact.pinned_by, PinnedBy::Reach | PinnedBy::Agent)
                || has_hidden_characters(&contact.label)
                || !agents.insert(&contact.agent)
                || !addresses.insert(&contact.address)
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
}

/// See [`VerifiedRules::counterparty`]. One function, so an owner's device, its page and Signet's
/// delegate and views can't come to different answers. `ours` is the owner on this side, if a real
/// one.
fn counterparty_of(
    contacts: &[RulesContact],
    reach: &Reach,
    draft: &ApprovalDraft,
    ours: Option<&SplintId>,
) -> Counterparty {
    let terms = &draft.terms;
    let Some(other) = other_party(draft) else {
        return Counterparty::NotApproved;
    };
    approval_of(
        contacts,
        reach,
        &other.agent,
        Some(&other.owner),
        ours,
        &terms.interaction,
    )
}

/// Whoever is on the other side of this draft from the agent it's for.
fn other_party(draft: &ApprovalDraft) -> Option<&TermsParty> {
    let terms = &draft.terms;
    [&terms.requester, &terms.recipient]
        .into_iter()
        .find(|party| party.agent != draft.agent)
}

/// Whether a delegate's yes may commit this owner to anything at all with this agent: the owner signed
/// them in with types, or never let their agent add contacts by itself. Not one the agent agreed with,
/// nor anyone the reach setting let in, nor another of the owner's own agents the rules don't name,
/// whatever the type. A sending host sees a sealed step's recipient, but not its type or values, so
/// this goes by who alone, and Signet's delegate holds to the same, so the two can't part. Otherwise a
/// fooled agent reading the delegate key could agree with an attacker's agent and send it a sealed
/// yes within the caps. The owner's own
/// yes still goes.
fn delegate_may_answer(contacts: &[RulesContact], reach: &Reach, agent: &SplintId) -> bool {
    match contacts.iter().find(|contact| &contact.agent == agent) {
        Some(contact) if contact.status == ContactStatus::Blocked => false,
        Some(contact) if contact.can_have_requests() => true,
        _ => reach.agreed.is_none(),
    }
}

/// Which types the owner stands behind a value with someone in, as [`VerifiedRules::counterparty`]
/// says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApprovedIn<'a> {
    /// The owner named them with types, or never let their agent add contacts by itself.
    Every,
    /// Only those the reach setting by itself lets them in for, which for one the agent agreed with
    /// and nobody else let in is none.
    Only(&'a [InteractionType]),
}

impl ApprovedIn<'_> {
    fn covers(self, interaction: &InteractionType) -> bool {
        match self {
            Self::Every => true,
            Self::Only(types) => types.contains(interaction),
        }
    }
}

/// See [`ApprovedIn`]. The reach setting is judged only on what an approval's terms say of them, so
/// every reader answers alike: a filter on hosts or past exchanges needs what only the reader's Signet
/// knows, so under one a value with anyone the rules don't name waits.
///
/// Another agent of this same owner counts as approved, as the owner's own bindings stand behind both
///, provisional for Nenye. `ours` is that
/// owner, given only when they're a real one, never a stand-in, and `owner` must come from a binding
/// the reader checked, as everywhere here.
fn approved_in<'a>(
    contacts: &[RulesContact],
    reach: &'a Reach,
    agent: &SplintId,
    owner: Option<&SplintId>,
    ours: Option<&SplintId>,
) -> ApprovedIn<'a> {
    let listed = contacts.iter().find(|contact| &contact.agent == agent);
    if listed.is_some_and(|contact| contact.status == ContactStatus::Blocked) {
        return ApprovedIn::Only(&[]);
    }
    if ours.is_some() && owner == ours {
        return ApprovedIn::Every;
    }
    if listed.is_some_and(RulesContact::can_have_requests) || reach.agreed.is_none() {
        return ApprovedIn::Every;
    }
    let inbound = &reach.inbound;
    let by_reach = match inbound.from {
        InboundFrom::Contacts => false,
        InboundFrom::Open => true,
        InboundFrom::Filter => owner.is_some_and(|owner| inbound.filter.owners.contains(owner)),
    };
    ApprovedIn::Only(if by_reach { &inbound.types } else { &[] })
}

fn approval_of(
    contacts: &[RulesContact],
    reach: &Reach,
    agent: &SplintId,
    owner: Option<&SplintId>,
    ours: Option<&SplintId>,
    interaction: &InteractionType,
) -> Counterparty {
    if approved_in(contacts, reach, agent, owner, ours).covers(interaction) {
        Counterparty::Approved
    } else {
        Counterparty::NotApproved
    }
}

/// Whether the owner named this type for whoever is on the other side of a draft: in their contact
/// entry, or, for anyone the rules don't name, for contacts the agent adds or for everyone reach lets
/// in. A type with currency is used only once it's named, so only then do the sides it says its
/// currency is paid to count. Core's own types hold no number, so they need nobody's approval.
fn approves_type(contacts: &[RulesContact], reach: &Reach, draft: &ApprovalDraft) -> bool {
    let interaction = &draft.terms.interaction;
    if !interaction.is_agreed() {
        return true;
    }
    let terms = &draft.terms;
    let other = if terms.requester.agent == draft.agent {
        &terms.recipient.agent
    } else {
        &terms.requester.agent
    };
    match contacts.iter().find(|contact| &contact.agent == other) {
        Some(contact) => {
            contact.status == ContactStatus::Allowed && contact.types.contains(interaction)
        }
        None => {
            reach
                .agreed
                .as_ref()
                .is_some_and(|agreed| agreed.types.contains(interaction))
                || reach.inbound.types.contains(interaction)
        }
    }
}

/// A type as an owner's permissions read it for a draft: as its schema says where the owner named it
/// or it has no currency, and otherwise with its currency paid to neither side, as
/// [`Schema::unapproved`] reads it. A number the type doesn't label as currency never waits.
fn as_owner_reads(
    contacts: &[RulesContact],
    reach: &Reach,
    schema: &Schema,
    draft: &ApprovalDraft,
) -> Schema {
    if !schema.includes_currency() || approves_type(contacts, reach, draft) {
        schema.clone()
    } else {
        schema.unapproved()
    }
}

/// What contacts the agent agreed with by itself get, where these settings let any in at all.
fn agreed_counts<'a>(reach: &'a Reach, permissions: &Permissions) -> Option<&'a Agreed> {
    reach
        .agreed
        .as_ref()
        .filter(|_| permissions.level != Level::AskMe)
}

impl RulesDraft {
    /// See [`as_owner_reads`]: what this owner's device and page judge a draft's type by.
    pub fn as_owner_reads(&self, schema: &Schema, draft: &ApprovalDraft) -> Schema {
        as_owner_reads(&self.contacts, &self.reach, schema, draft)
    }

    /// Whether contacts the agent agreed with by itself count under these rules, as signed rules
    /// judge them, for a device to say before signing which ones a change takes out.
    pub fn lets_agreed_in(&self) -> bool {
        agreed_counts(&self.reach, &self.permissions).is_some()
    }

    /// See [`VerifiedRules::counterparty`]. Draft rules don't say whose they are, so the draft's own
    /// owner stands for this side's. A stand-in device can't tell this way that its owner is one, and
    /// nothing a stand-in signs counts as an owner's yes.
    pub fn counterparty(&self, draft: &ApprovalDraft) -> Counterparty {
        counterparty_of(&self.contacts, &self.reach, draft, Some(&draft.owner))
    }

    /// See [`VerifiedRules::delegate_may_answer_in`], so an owner's page can say why their delegate
    /// leaves a yes to them.
    pub fn delegate_may_answer_in(&self, draft: &ApprovalDraft) -> bool {
        other_party(draft)
            .is_some_and(|other| delegate_may_answer(&self.contacts, &self.reach, &other.agent))
    }

    /// Signs these rules for one agent, until the owner signs others or the end they chose. Rules a
    /// reader would refuse are refused here, so an owner finds out on their own device.
    pub fn sign(
        self,
        key: &SigningKey,
        owner: &SplintId,
        agent: &SplintId,
        seq: u64,
        now: u64,
    ) -> Result<String, Error> {
        let bytes = self.payload(owner, agent, seq, now)?;
        jws::sign(key, RULES_TYPE, &bytes)
    }

    /// The bytes an owner's key signs, whichever way it signs. Rules a reader would refuse are refused
    /// here.
    pub fn payload(
        self,
        owner: &SplintId,
        agent: &SplintId,
        seq: u64,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let payload = RulesPayload {
            v: RULES_VERSION,
            owner: owner.clone(),
            agent: agent.clone(),
            seq,
            issued_at: now,
            expires_at: None,
            ends_at: self.ends_at,
            paused: self.paused,
            reach: self.reach,
            permissions: self.permissions,
            changes: self.changes,
            sealing: self.sealing,
            delegation: self.delegation,
            contacts: self.contacts,
            invites: self.invites,
            limits: self.limits,
        };
        payload.check_fields()?;
        serde_json::to_vec(&payload).map_err(|_| Error::Malformed)
    }
}

/// Rules whose owner signature has been checked. The only way to get one is to pass that check, so
/// nothing an agent or a host makes up can stand in for an owner's rules.
///
/// They last until the owner signs newer ones, or until an end the owner chose. Rules a delegate
/// renewed before 2026-11-15 travel as the owner's rules, the renewal and the delegation, joined by
/// `~`. A renewal only moved the end, which nothing reads now, so a reader keeps the owner's part and
/// drops the rest unread.
#[derive(Clone, Debug)]
pub struct VerifiedRules {
    compact: String,
    payload: RulesPayload,
    /// Whether the owner who signed is a real one rather than a stand-in, as their ID shows.
    owner_confirmed: bool,
}

impl VerifiedRules {
    /// Rules arriving now from their owner: signed by them, not already over, and newer than any seen,
    /// so a host can't roll them back.
    pub fn verify(
        compact: &str,
        owner: &Identity,
        highest_seq_seen: u64,
        now: u64,
    ) -> Result<Self, Error> {
        let rules = Self::owner_signed(compact, owner)?;
        rules.check_arriving(now)?;
        if rules.payload.seq <= highest_seq_seen {
            return Err(Error::Stale);
        }
        Ok(rules)
    }

    /// Rules for this agent arriving now from anywhere, newer by the owner's `seq` than `held_seq`, so
    /// nobody can bring back older ones. With none held, as once rules a removed key signed were
    /// dropped with their `seq`, which a thief may have dated far ahead, rules signed before that
    /// removal are refused too: otherwise anyone holding old rules a key that stays signed, a fooled
    /// agent included, could put them back, however old. The owner's clock dates the removal, so a
    /// removal dated ahead counts from now, and a device whose clock is a little behind still signs
    /// rules that count.
    pub fn verify_newer(
        compact: &str,
        owner: &Identity,
        agent: &Identity,
        held_seq: u64,
        now: u64,
    ) -> Result<Self, Error> {
        let rules = Self::read(compact, owner)?;
        rules.check_arriving(now)?;
        if &rules.payload.agent != agent.id() {
            return Err(Error::ProofMismatch);
        }
        if rules.payload.seq <= held_seq {
            return Err(Error::Stale);
        }
        let removed_after = owner
            .last_key_removed_at()
            .map(|at| at.min(now).saturating_sub(CLOCK_TOLERANCE_SECS));
        if held_seq == 0 && removed_after.is_some_and(|floor| rules.payload.issued_at < floor) {
            return Err(Error::Stale);
        }
        Ok(rules)
    }

    /// Rules read back from storage, which may have reached an end the owner chose since they arrived.
    /// They count only under the key the owner holds now.
    pub fn reload(compact: &str, owner: &Identity) -> Result<Self, Error> {
        Self::read(compact, owner)
    }

    fn check_arriving(&self, now: u64) -> Result<(), Error> {
        if self.payload.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        if self.payload.ended(now) {
            return Err(Error::Expired);
        }
        Ok(())
    }

    fn owner_signed(compact: &str, owner: &Identity) -> Result<Self, Error> {
        let bytes = owner.verify(compact, RULES_TYPE)?;
        let payload: RulesPayload = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        payload.check_fields()?;
        if &payload.owner != owner.id() {
            return Err(Error::WrongSigner);
        }
        Ok(Self {
            compact: compact.to_owned(),
            payload,
            owner_confirmed: !owner.is_unconfirmed_owner(),
        })
    }

    /// Plain rules, or the owner's part of rules a delegate renewed before renewals ended, which had
    /// exactly three parts.
    fn read(compact: &str, owner: &Identity) -> Result<Self, Error> {
        let mut parts = compact.split(PART_SEPARATOR);
        let (Some(signed), renewal, delegation, None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::Malformed);
        };
        if renewal.is_some() != delegation.is_some() {
            return Err(Error::Malformed);
        }
        Self::owner_signed(signed, owner)
    }

    /// Everything as it travels, which is only what the owner signed.
    pub fn compact(&self) -> &str {
        &self.compact
    }

    /// The name of the one delegation these rules allow, if they allow one. A delegate's yes under any
    /// other is refused by a sending host holding these rules, and Signet says none.
    pub fn named_delegation(&self) -> Option<&str> {
        self.payload.delegation.as_deref()
    }

    /// Whether these rules allow this delegation.
    pub fn names_delegation(&self, delegation: &VerifiedDelegation) -> bool {
        self.named_delegation() == Some(delegation.name().as_str())
    }

    pub fn seq(&self) -> u64 {
        self.payload.seq
    }

    pub fn agent(&self) -> &SplintId {
        &self.payload.agent
    }

    /// Paused rules stop the agent, and so do rules past an end their owner chose.
    pub fn in_force(&self, now: u64) -> bool {
        self.payload.in_force(now)
    }

    /// Whether these rules have reached the end their owner chose for them.
    pub fn ended(&self, now: u64) -> bool {
        self.payload.ended(now)
    }

    /// The end the owner chose for these rules, if any. Without one they last until replaced.
    pub fn ends_at(&self) -> Option<u64> {
        self.payload.ends_at
    }

    /// Whether these rules let `sender` start an interaction of this type, by a contact entry, the
    /// invitation it redeemed, a contact the agent agreed with, or the reach setting, in that order.
    /// This is all a host can check, with no schema to say more: core's plain conversation needs
    /// `text`, a `type/1` needs `agree_types` or a type the owner approved by name, and a type agreed
    /// between the two needs `agree_types` and that the host saw its ID proposed between them.
    pub fn admits_type(
        &self,
        sender: &Sender,
        opening: &Opening,
        redeemed_invite: Option<&str>,
    ) -> bool {
        if self.payload.blocks(sender.agent) {
            return false;
        }
        if let Some(contact) = self.payload.listed_with_types(sender.agent) {
            return opening.fits(&contact.types, contact.text, contact.agree_types);
        }
        if let Some(invite) = redeemed_invite.and_then(|id| self.invite(id)) {
            return opening.fits(&invite.types, false, false);
        }
        if let Some(agreed) = self.payload.agreed_lets_in(sender) {
            return opening.fits(&agreed.types, agreed.text, agreed.agree_types);
        }
        let inbound = &self.payload.reach.inbound;
        self.lets_in_by_reach(sender) && opening.fits(&inbound.types, inbound.text, false)
    }

    /// What these rules do with a message from `sender`, who may have redeemed one invitation.
    pub fn admit(&self, sender: &Sender, redeemed_invite: Option<&str>, now: u64) -> Admission {
        self.payload.admit(sender, redeemed_invite, now)
    }

    /// Whether `sender` gets in only by the owner's reach setting: no contact entry with types, no
    /// contact the agent agreed with, and no block. Paused or not, since a pause has its own answer.
    pub fn lets_in_by_reach(&self, sender: &Sender) -> bool {
        !self.payload.blocks(sender.agent)
            && self.payload.listed_with_types(sender.agent).is_none()
            && self.payload.agreed_lets_in(sender).is_none()
            && self.payload.reach.lets_in(sender)
    }

    /// Whether `sender` gets in as a contact this agent agreed with by itself. Paused or not, since a
    /// pause has its own answer.
    pub fn lets_in_as_agreed(&self, sender: &Sender) -> bool {
        self.payload.agreed_lets_in(sender).is_some()
    }

    /// Someone this agent agreed with, as an entry it can deal with, using the types and `text` the
    /// owner set for all of them. `address` is the one the invite gave, which their owner signed.
    pub fn agreed_contact(&self, sender: &Sender, address: &str) -> Option<RulesContact> {
        let agreed = self.payload.agreed_lets_in(sender)?;
        Some(RulesContact {
            agent: sender.agent.clone(),
            address: address.to_owned(),
            label: address.to_owned(),
            status: ContactStatus::Allowed,
            types: agreed.types.clone(),
            text: agreed.text,
            agree_types: agreed.agree_types,
            pinned_by: PinnedBy::Agent,
        })
    }

    /// Whether the owner has approved whoever is on the other side of this draft, as far as what it
    /// commits them to goes. Someone the rules name with types was, and so was anyone the reach
    /// setting by itself lets in for this type, which the owner chose. With agreed contacts off there
    /// are none, so nothing changes for anyone. Otherwise anyone else, such as one the agent agreed
    /// with by itself, even where reach lets strangers in for other types, or one who used an
    /// invitation the owner hasn't signed them in from, waits for the owner on currency.
    pub fn counterparty(&self, draft: &ApprovalDraft) -> Counterparty {
        counterparty_of(
            &self.payload.contacts,
            &self.payload.reach,
            draft,
            self.real_owner(),
        )
    }

    /// See [`as_owner_reads`]: what this owner's delegate judges a draft's type by.
    pub fn as_owner_reads(&self, schema: &Schema, draft: &ApprovalDraft) -> Schema {
        as_owner_reads(&self.payload.contacts, &self.payload.reach, schema, draft)
    }

    /// See [`delegate_may_answer`]: what a sending host holds a delegate's yes to, for its recipient.
    pub fn delegate_may_answer(&self, agent: &SplintId) -> bool {
        delegate_may_answer(&self.payload.contacts, &self.payload.reach, agent)
    }

    /// The same, for whoever is on the other side of this draft, which Signet's delegate holds to.
    pub fn delegate_may_answer_in(&self, draft: &ApprovalDraft) -> bool {
        other_party(draft).is_some_and(|other| self.delegate_may_answer(&other.agent))
    }

    /// The owner who signed these, unless they're a stand-in, whose agents count for nothing here.
    fn real_owner(&self) -> Option<&SplintId> {
        self.owner_confirmed.then_some(&self.payload.owner)
    }

    /// Whether everything this agent may use with someone counts as approved by [`Self::counterparty`],
    /// for telling an agent whether a value with them waits for its owner. `owner` is theirs, if known.
    /// `types` may be none, for a contact who uses only what the two agents agree, who's approved only
    /// where the owner approved them for everything.
    pub fn approves(
        &self,
        agent: &SplintId,
        owner: Option<&SplintId>,
        types: &[InteractionType],
    ) -> bool {
        let approved = approved_in(
            &self.payload.contacts,
            &self.payload.reach,
            agent,
            owner,
            self.real_owner(),
        );
        if types.is_empty() {
            return approved == ApprovedIn::Every;
        }
        types.iter().all(|interaction| approved.covers(interaction))
    }

    /// Someone the reach setting lets in, as an entry an agent can deal with, using the types and
    /// `text` the owner set for everyone let in that way. `address` is the one their owner signed.
    pub fn reached_contact(&self, sender: &Sender, address: &str) -> Option<RulesContact> {
        let inbound = &self.payload.reach.inbound;
        self.lets_in_by_reach(sender).then(|| RulesContact {
            agent: sender.agent.clone(),
            address: address.to_owned(),
            label: address.to_owned(),
            status: ContactStatus::Allowed,
            types: inbound.types.clone(),
            text: inbound.text,
            // Strangers use only what the owner approved for everyone.
            agree_types: false,
            pinned_by: PinnedBy::Reach,
        })
    }

    /// Whether words someone chose may pass between this agent and `peer`. A contact's own entry
    /// decides, then the reach setting for someone it let in. An invitation alone carries types, not
    /// words, and a block always wins.
    pub fn allows_text(&self, peer: &Sender) -> bool {
        if self.payload.blocks(peer.agent) {
            return false;
        }
        if let Some(contact) = self.payload.listed_with_types(peer.agent) {
            return contact.text;
        }
        if let Some(agreed) = self.payload.agreed_lets_in(peer) {
            return agreed.text;
        }
        self.lets_in_by_reach(peer) && self.payload.reach.inbound.text
    }

    /// The same for a person's words: a contact's owner is someone this owner chose, whatever `text`
    /// says about their agent. Nobody chose one the agent agreed with, so theirs need that setting's
    /// `text`, as for someone reach let in. See [`RulesContact::may_carry_person_text`].
    pub fn allows_person_text(&self, peer: &Sender) -> bool {
        if self.payload.blocks(peer.agent) {
            return false;
        }
        if self.payload.listed_with_types(peer.agent).is_some() {
            return true;
        }
        if let Some(agreed) = self.payload.agreed_lets_in(peer) {
            return agreed.text;
        }
        self.lets_in_by_reach(peer) && self.payload.reach.inbound.text
    }

    /// What the owner chose in these rules, as a draft, so an agent's ask can be checked against them
    /// and the owner's side can sign the next rules from them.
    pub fn draft(&self) -> RulesDraft {
        let payload = &self.payload;
        RulesDraft {
            paused: payload.paused,
            reach: payload.reach.clone(),
            permissions: payload.permissions.clone(),
            changes: payload.changes,
            sealing: payload.sealing,
            delegation: payload.delegation.clone(),
            ends_at: payload.ends_at,
            contacts: payload.contacts.clone(),
            invites: payload.invites.clone(),
            limits: payload.limits,
        }
    }

    pub fn reach(&self) -> &Reach {
        &self.payload.reach
    }

    pub fn names(&self, agent: &SplintId) -> bool {
        self.payload.listed(agent).is_some()
    }

    /// Every ID these rules name, whatever they say about it.
    pub fn listed(&self) -> impl Iterator<Item = &SplintId> {
        self.payload.contacts.iter().map(|contact| &contact.agent)
    }

    /// Whether this ID is a contact whose address, as the owner signed it, is on some other host than
    /// the one relaying its message. A contact's home host is who stops a key its owner gave up, so
    /// nothing else gets to carry it.
    pub fn names_elsewhere(&self, agent: &SplintId, relayed_by: &str) -> bool {
        self.payload.listed(agent).is_some_and(|contact| {
            crate::parse_address(&contact.address).is_ok_and(|(_, domain)| domain != relayed_by)
        })
    }

    /// The host in the owner's filter that signed for this message, under the key the owner named for
    /// it, if one did. A lying host on this side can't make that signature, so Signet can trust this
    /// as far as a host can.
    pub fn host_that_vouched(
        &self,
        relayed_by: &str,
        proof: &str,
        message: &MessageId,
        to_host: &str,
    ) -> Option<&str> {
        let listed = self
            .payload
            .reach
            .inbound
            .filter
            .hosts
            .iter()
            .find(|listed| listed.domain == relayed_by)?;
        let key = PublicKey::from_encoded(&listed.key).ok()?;
        DeliveryProof::signed_for(proof, &key, message, relayed_by, to_host).ok()?;
        Some(listed.domain.as_str())
    }

    pub fn permissions(&self) -> &Permissions {
        &self.payload.permissions
    }

    /// Whether the owner chose sealed or unsealed for this agent.
    pub fn sealing(&self) -> Sealing {
        self.payload.sealing
    }

    pub fn changes(&self) -> &ChangeRules {
        &self.payload.changes
    }

    pub fn limits(&self) -> &RulesLimits {
        &self.payload.limits
    }

    /// Messages of words a day, each way, with `peer`: what the owner signed for a contact they named,
    /// and with anyone else, such as a contact the agent added by itself, what they signed for those,
    /// never more than [`UNAPPROVED_TEXTS_PER_DAY`] or what they signed for a named one.
    pub fn texts_per_day_with(&self, peer: &Sender) -> u32 {
        let limits = &self.payload.limits;
        let signed = limits.texts_per_contact_per_day;
        if self.payload.listed_with_types(peer.agent).is_some() {
            signed
        } else {
            signed.min(
                limits
                    .agreed_texts_per_day
                    .unwrap_or(UNAPPROVED_TEXTS_PER_DAY)
                    .min(UNAPPROVED_TEXTS_PER_DAY),
            )
        }
    }

    /// Interactions started a day, each way, with `peer`, the same way: what the owner signed for a
    /// contact they named, and for anyone else what they signed for those, never more.
    pub fn new_requests_per_day_with(&self, peer: &Sender) -> u32 {
        let limits = &self.payload.limits;
        let signed = limits.new_requests_per_contact_per_day;
        if self.payload.listed_with_types(peer.agent).is_some() {
            signed
        } else {
            signed.min(limits.agreed_new_requests_per_day.unwrap_or(signed))
        }
    }

    /// An invitation these rules still offer, which only says who may try to redeem it.
    pub fn invite(&self, id: &str) -> Option<&RulesInvite> {
        self.payload.invites.iter().find(|invite| invite.id == id)
    }

    /// Whether a redeemed invitation is still on offer, paused or not. A pause has its own answer.
    pub fn invite_lets_in(&self, id: &str, now: u64) -> bool {
        self.payload.invite_lets_in(id, now)
    }

    /// Everyone an agent can reach now.
    /// Whether these rules say nothing about who this agent knows, whatever their dates.
    pub fn names_nobody(&self) -> bool {
        self.payload.contacts.is_empty() && self.payload.invites.is_empty()
    }

    pub fn contacts(&self, now: u64) -> impl Iterator<Item = &RulesContact> {
        self.allowed(now)
    }

    /// A contact allowed some type of interaction, for as long as these rules are in force.
    fn allowed(&self, now: u64) -> impl Iterator<Item = &RulesContact> {
        let in_force = self.in_force(now);
        self.payload
            .contacts
            .iter()
            .filter(move |contact| in_force && contact.can_have_requests())
    }

    /// What the owner signed for this address, whatever it says about the contact. The agent ID in
    /// it holds even if that contact can't have a request, so no host's answer can change it.
    pub fn named_at(&self, address: &str) -> Option<&RulesContact> {
        self.payload
            .contacts
            .iter()
            .find(|contact| contact.address == address)
    }

    /// What the owner signed for this agent, whatever it says, a block included.
    pub fn named(&self, agent: &SplintId) -> Option<&RulesContact> {
        self.payload.listed(agent)
    }

    pub fn blocks(&self, agent: &SplintId) -> bool {
        self.payload.blocks(agent)
    }

    /// Whether an invite from this agent may reach this one's agent: one the owner blocked can't, and
    /// nor can a stranger while the owner blocks strangers. Whoever the rules name otherwise may ask.
    pub fn takes_invites_from(&self, agent: &SplintId) -> bool {
        !self.payload.blocks(agent)
            && (self.payload.listed(agent).is_some()
                || self.payload.reach.inbound.strangers != UnknownSenders::Block)
    }

    /// Whether the agent may invite someone it doesn't know yet. An invite starts something with a
    /// stranger, which an owner who asks to be asked first hasn't let it do alone, and nothing
    /// signs their yes to one, so at `ask_me` they add contacts themselves.
    pub fn lets_its_agent_invite(&self) -> bool {
        !self.payload.paused && self.payload.permissions.level != Level::AskMe
    }

    /// Whether the owner still lists this agent for requests, paused or not. A pause has its own
    /// answer, and an owner can still decide while one is on.
    pub fn lists_for_requests(&self, agent: &SplintId) -> bool {
        self.payload
            .contacts
            .iter()
            .any(|contact| &contact.agent == agent && contact.can_have_requests())
    }

    pub fn contact_at(&self, address: &str, now: u64) -> Option<&RulesContact> {
        self.allowed(now).find(|contact| contact.address == address)
    }

    pub fn contact_of(&self, agent: &SplintId, now: u64) -> Option<&RulesContact> {
        self.allowed(now).find(|contact| &contact.agent == agent)
    }
}

/// The part of some rules the owner signed, before verification: all of them, or the first of the three
/// parts rules a delegate renewed before 2026-11-15 have. Use this only to compare with rules already
/// verified.
pub fn claimed_owner_part(compact: &str) -> &str {
    compact.split(PART_SEPARATOR).next().unwrap_or(compact)
}

/// Which agent some rules say they're for, before verification. Use this only to look up the owner
/// to verify against.
pub fn claimed_rules_agent(compact: &str) -> Result<SplintId, Error> {
    let owner_signed = claimed_owner_part(compact);
    let payload = jws::unverified_payload(owner_signed, RULES_TYPE)?;
    let payload: RulesPayload = serde_json::from_slice(&payload).map_err(|_| Error::Malformed)?;
    Ok(payload.agent)
}

/// A rules document with no signature, as the spec's vectors state one.
#[cfg(test)]
pub(crate) fn unsigned(rules: serde_json::Value) -> Result<VerifiedRules, Error> {
    let payload: RulesPayload = serde_json::from_value(rules).map_err(|_| Error::Malformed)?;
    payload.check_fields()?;
    Ok(VerifiedRules {
        compact: String::new(),
        payload,
        owner_confirmed: true,
    })
}

/// Runs the admission check on a rules document with no signature, as the spec's vectors state it,
/// and says whether the sender may then use this type.
#[cfg(test)]
pub(crate) fn admit_unsigned(
    rules: serde_json::Value,
    sender: &Sender,
    opening: &Opening,
    redeemed_invite: Option<&str>,
    now: u64,
) -> Result<(Admission, bool), Error> {
    let payload: RulesPayload = serde_json::from_value(rules).map_err(|_| Error::Malformed)?;
    payload.check_fields()?;
    let rules = VerifiedRules {
        compact: String::new(),
        payload,
        owner_confirmed: true,
    };
    Ok((
        rules.admit(sender, redeemed_invite, now),
        rules.admits_type(sender, opening, redeemed_invite),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    const NOW: u64 = 1_793_750_400;

    fn meeting() -> InteractionType {
        crate::requests::example("meeting/1")
    }

    struct Owner {
        key: SigningKey,
        identity: Identity,
    }

    fn owner() -> Owner {
        let key = SigningKey::generate().unwrap();
        let identity = crate::test_identity(&key);
        Owner { key, identity }
    }

    fn agent_of(_owner: &Owner) -> Identity {
        crate::test_identity(&SigningKey::generate().unwrap())
    }

    fn draft(contacts: Vec<RulesContact>, paused: bool) -> RulesDraft {
        RulesDraft {
            paused,
            reach: Reach::default(),
            permissions: Permissions::default(),
            changes: ChangeRules::default(),
            sealing: Sealing::default(),
            delegation: None,
            ends_at: None,
            contacts,
            invites: Vec::new(),
            limits: RulesLimits {
                new_requests_per_contact_per_day: 3,
                open_requests_per_contact: 3,
                open_approvals: 10,
                new_from_others_per_day: 50,
                texts_per_contact_per_day: 20,
                agreed_texts_per_day: None,
                agreed_new_requests_per_day: None,
                sends_per_hour: None,
                sends_per_day: None,
            },
        }
    }

    fn contact(agent: &Identity, status: ContactStatus) -> RulesContact {
        RulesContact {
            agent: agent.id().clone(),
            address: "ben~other.example".to_owned(),
            label: "Ben".to_owned(),
            status,
            types: vec![meeting()],
            text: false,
            agree_types: false,
            pinned_by: PinnedBy::Owner,
        }
    }

    fn signed(owner: &Owner, draft: RulesDraft, seq: u64) -> VerifiedRules {
        let agent = agent_of(owner);
        let compact = draft
            .sign(&owner.key, owner.identity.id(), agent.id(), seq, NOW)
            .unwrap();
        VerifiedRules::verify(&compact, &owner.identity, seq - 1, NOW).unwrap()
    }

    #[test]
    fn a_listed_host_counts_only_by_its_own_signature_under_the_key_the_owner_named() {
        let (host_key, other_key) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        let mut rules = draft(Vec::new(), false);
        rules.reach.inbound.from = InboundFrom::Filter;
        rules.reach.inbound.types = vec![meeting()];
        rules.reach.inbound.filter.hosts = vec![ListedHost {
            domain: "partner.example".to_owned(),
            key: host_key.public_key().encoded(),
        }];
        let rules = signed(&owner(), rules, 1);
        let message = MessageId::of(b"a message");
        let proof = |key: &SigningKey, message: &MessageId, from: &str, to: &str| {
            DeliveryProof::sign(key, message, from, to, NOW).unwrap()
        };
        let vouched = |proof: &str, relayed_by: &str, message: &MessageId| {
            rules.host_that_vouched(relayed_by, proof, message, "me.example")
        };
        let good = proof(&host_key, &message, "partner.example", "me.example");
        assert_eq!(
            vouched(&good, "partner.example", &message),
            Some("partner.example")
        );
        // Waiting on a host for a long time doesn't undo it.
        let old =
            DeliveryProof::sign(&host_key, &message, "partner.example", "me.example", 1).unwrap();
        assert!(vouched(&old, "partner.example", &message).is_some());

        let another_key = proof(&other_key, &message, "partner.example", "me.example");
        assert_eq!(vouched(&another_key, "partner.example", &message), None);
        assert_eq!(vouched("", "partner.example", &message), None);
        assert_eq!(
            vouched(&good, "partner.example", &MessageId::of(b"another")),
            None
        );
        let elsewhere = proof(&host_key, &message, "partner.example", "other.example");
        assert_eq!(vouched(&elsewhere, "partner.example", &message), None);
        let unlisted = proof(&other_key, &message, "other.example", "me.example");
        assert_eq!(vouched(&unlisted, "other.example", &message), None);
    }

    #[test]
    fn a_contact_counts_only_through_the_host_of_its_signed_address() {
        let ben = agent_of(&owner());
        let stranger = agent_of(&owner());
        let rules = signed(
            &owner(),
            draft(vec![contact(&ben, ContactStatus::Allowed)], false),
            1,
        );
        assert!(!rules.names_elsewhere(ben.id(), "other.example"));
        assert!(rules.names_elsewhere(ben.id(), "relay.example"));
        assert!(!rules.names_elsewhere(stranger.id(), "relay.example"));
    }

    #[test]
    fn only_allowed_contacts_count_and_only_while_the_rules_are_in_force() {
        let ana = owner();
        let ben = agent_of(&owner());
        let address = "ben~other.example";

        let allowed = signed(
            &ana,
            draft(vec![contact(&ben, ContactStatus::Allowed)], false),
            1,
        );
        assert!(allowed.contact_at(address, NOW).is_some());
        assert!(allowed.contact_of(ben.id(), NOW).is_some());
        let ending = RulesDraft {
            ends_at: Some(NOW + 10),
            ..draft(vec![contact(&ben, ContactStatus::Allowed)], false)
        };
        let ending = signed(&ana, ending, 5);
        assert!(ending.in_force(NOW + 9));
        assert!(!ending.in_force(NOW + 10));
        assert!(ending.contact_at(address, NOW + 10).is_none());
        assert!(ending.contact_of(ben.id(), NOW + 10).is_none());

        let blocked = signed(
            &ana,
            draft(vec![contact(&ben, ContactStatus::Blocked)], false),
            2,
        );
        assert!(blocked.contact_at(address, NOW).is_none());
        assert!(blocked.blocks(ben.id()));
        assert!(!blocked.lists_for_requests(ben.id()));
        assert_eq!(
            blocked.named_at(address).map(|named| &named.agent),
            Some(ben.id())
        );

        let mut no_types = contact(&ben, ContactStatus::Allowed);
        no_types.types.clear();
        let no_types = signed(&ana, draft(vec![no_types], false), 4);
        assert!(no_types.contact_at(address, NOW).is_none());

        let paused = signed(
            &ana,
            draft(vec![contact(&ben, ContactStatus::Allowed)], true),
            3,
        );
        assert!(!paused.in_force(NOW));
        assert!(paused.contact_at(address, NOW).is_none());
    }

    /// Rules once stopped the agent 30 days after they were signed, which wasn't the owner's choice.
    #[test]
    fn rules_last_until_replaced_even_those_signed_with_the_old_30_day_end() {
        let ana = owner();
        let agent = agent_of(&ana);
        let ben = agent_of(&owner());
        let a_year_on = NOW + 365 * 24 * 60 * 60;
        let new = draft(vec![contact(&ben, ContactStatus::Allowed)], false)
            .sign(&ana.key, ana.identity.id(), agent.id(), 1, NOW)
            .unwrap();
        let new = VerifiedRules::verify(&new, &ana.identity, 0, NOW).unwrap();
        assert!(new.in_force(a_year_on) && new.contact_of(ben.id(), a_year_on).is_some());

        let bytes = draft(vec![contact(&ben, ContactStatus::Allowed)], false)
            .payload(ana.identity.id(), agent.id(), 2, NOW)
            .unwrap();
        let mut legacy: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        legacy["expires_at"] = (NOW + 30 * 24 * 60 * 60).into();
        let legacy =
            jws::sign(&ana.key, RULES_TYPE, &serde_json::to_vec(&legacy).unwrap()).unwrap();
        let old = VerifiedRules::verify_newer(&legacy, &ana.identity, &agent, 1, NOW).unwrap();
        assert!(old.in_force(a_year_on) && old.contact_of(ben.id(), a_year_on).is_some());
        // Renewed back then, it reads as the owner's part, and the rest is dropped, not kept.
        let renewed =
            VerifiedRules::reload(&format!("{legacy}~renewal~delegation"), &ana.identity).unwrap();
        assert_eq!(renewed.compact(), legacy);
        assert!(VerifiedRules::reload(&format!("{legacy}~renewal"), &ana.identity).is_err());
    }

    #[test]
    fn a_block_beats_everything_and_an_invitation_only_counts_while_it_lasts() {
        let ana = owner();
        let ben = agent_of(&owner());
        let invite = |expires_at| RulesInvite {
            id: "inv_1".to_owned(),
            key: SigningKey::generate().unwrap().public_key().encoded(),
            types: vec![meeting()],
            expires_at,
        };
        let with = |contacts, unknown_senders, seq| {
            let mut rules = draft(contacts, false);
            rules.reach.inbound.strangers = unknown_senders;
            rules.invites = vec![invite(NOW + 10)];
            signed(&ana, rules, seq)
        };

        let strangers_wait = with(Vec::new(), UnknownSenders::Quarantine, 1);
        let admit = |rules: &VerifiedRules, redeemed, now| {
            rules.admit(&Sender::only(ben.id()), redeemed, now)
        };
        assert_eq!(admit(&strangers_wait, None, NOW), Admission::Quarantine);
        assert_eq!(
            admit(&strangers_wait, Some("inv_2"), NOW),
            Admission::Quarantine
        );
        assert_eq!(
            admit(&strangers_wait, Some("inv_1"), NOW),
            Admission::Deliver
        );
        assert_eq!(
            admit(&strangers_wait, Some("inv_1"), NOW + 10),
            Admission::Quarantine
        );

        let strangers_go = with(Vec::new(), UnknownSenders::Block, 2);
        assert_eq!(admit(&strangers_go, None, NOW), Admission::Drop);
        assert_eq!(admit(&strangers_go, Some("inv_1"), NOW), Admission::Deliver);

        let blocked = with(
            vec![contact(&ben, ContactStatus::Blocked)],
            UnknownSenders::Quarantine,
            3,
        );
        assert_eq!(admit(&blocked, Some("inv_1"), NOW), Admission::Drop);

        let mut no_types = contact(&ben, ContactStatus::Allowed);
        no_types.types.clear();
        let no_types = with(vec![no_types], UnknownSenders::Quarantine, 4);
        assert_eq!(admit(&no_types, None, NOW), Admission::Quarantine);
    }

    #[test]
    fn stopped_rules_keep_a_contacts_mail_waiting_and_drop_the_rest() {
        let ana = owner();
        let friend = agent_of(&owner());
        let invited = agent_of(&owner());
        let blocked = agent_of(&owner());
        let stranger = agent_of(&owner());
        let blocked_entry = RulesContact {
            address: "cara~other.example".to_owned(),
            ..contact(&blocked, ContactStatus::Blocked)
        };
        let mut paused = draft(
            vec![contact(&friend, ContactStatus::Allowed), blocked_entry],
            true,
        );
        paused.invites = vec![RulesInvite {
            id: "inv_1".to_owned(),
            key: SigningKey::generate().unwrap().public_key().encoded(),
            types: vec![meeting()],
            expires_at: NOW + 10,
        }];
        let mut running = paused.clone();
        running.paused = false;
        running.ends_at = Some(NOW + 20);
        let paused = signed(&ana, paused, 1);
        let running = signed(&ana, running, 2);
        let past_their_expiry = NOW + 20;

        assert_eq!(
            paused.admit(&Sender::only(friend.id()), None, NOW),
            Admission::Wait
        );
        assert_eq!(
            paused.admit(&Sender::only(invited.id()), Some("inv_1"), NOW),
            Admission::Wait
        );
        assert_eq!(
            paused.admit(&Sender::only(blocked.id()), None, NOW),
            Admission::Drop
        );
        assert_eq!(
            paused.admit(&Sender::only(stranger.id()), None, NOW),
            Admission::Drop
        );
        assert_eq!(
            running.admit(&Sender::only(friend.id()), None, past_their_expiry),
            Admission::Wait
        );
        assert_eq!(
            running.admit(&Sender::only(stranger.id()), None, past_their_expiry),
            Admission::Drop
        );
    }

    #[test]
    fn an_open_agent_lets_anyone_in_for_its_types_only_and_a_block_still_wins() {
        let ana = owner();
        let ben = agent_of(&owner());
        let cara = agent_of(&owner());
        let stranger = agent_of(&owner());
        let quote = crate::requests::example("quote/1");
        let cara_blocked = RulesContact {
            address: "cara~other.example".to_owned(),
            ..contact(&cara, ContactStatus::Blocked)
        };
        let mut open = draft(
            vec![contact(&ben, ContactStatus::Allowed), cara_blocked],
            false,
        );
        open.reach.inbound.from = InboundFrom::Open;
        open.reach.inbound.types = vec![quote.clone()];
        let open = signed(&ana, open, 1);
        let anyone = Sender::only(stranger.id());

        assert_eq!(open.admit(&anyone, None, NOW), Admission::Deliver);
        assert!(open.admits_type(&anyone, &Opening::named(&quote), None));
        assert!(!open.admits_type(&anyone, &Opening::named(&meeting()), None));
        let reached = open.reached_contact(&anyone, "x~any.example").unwrap();
        assert_eq!(reached.pinned_by, PinnedBy::Reach);
        assert_eq!(reached.types, vec![quote.clone()]);

        let blocked = Sender::only(cara.id());
        assert_eq!(open.admit(&blocked, None, NOW), Admission::Drop);
        assert!(!open.admits_type(&blocked, &Opening::named(&quote), None));
        assert!(
            open.reached_contact(&blocked, "cara~other.example")
                .is_none()
        );

        let listed = Sender::only(ben.id());
        assert!(!open.lets_in_by_reach(&listed));
        assert!(open.admits_type(&listed, &Opening::named(&meeting()), None));
        assert!(!open.admits_type(&listed, &Opening::named(&quote), None));
    }

    /// An agent whose owner hasn't confirmed reaches only an owner open to anyone, or one who named
    /// it. Anyone else drops it rather than holding it, so IDs made for the purpose can't fill a
    /// quarantine, and a filter that would take its owner's ID or host never does.
    #[test]
    fn an_unconfirmed_owners_agent_reaches_only_the_open_or_whoever_named_it() {
        let ana = owner();
        let named = agent_of(&owner());
        let stranger = agent_of(&owner());
        let quote = crate::requests::example("quote/1");
        fn unconfirmed(agent: &Identity) -> Sender<'_> {
            Sender {
                unconfirmed: true,
                ..Sender::only(agent.id())
            }
        }
        let contacts_only = signed(
            &ana,
            draft(vec![contact(&named, ContactStatus::Allowed)], false),
            1,
        );
        assert_eq!(
            contacts_only.admit(&Sender::only(stranger.id()), None, NOW),
            Admission::Quarantine
        );
        assert_eq!(
            contacts_only.admit(&unconfirmed(&stranger), None, NOW),
            Admission::Drop
        );
        assert_eq!(
            contacts_only.admit(&unconfirmed(&named), None, NOW),
            Admission::Deliver
        );

        let mut open = draft(Vec::new(), false);
        open.reach.inbound.from = InboundFrom::Open;
        open.reach.inbound.types = vec![quote.clone()];
        let open = signed(&ana, open, 2);
        assert_eq!(
            open.admit(&unconfirmed(&stranger), None, NOW),
            Admission::Deliver
        );
        assert!(open.admits_type(&unconfirmed(&stranger), &Opening::named(&quote), None));

        let mut filtered = draft(Vec::new(), false);
        filtered.reach.inbound.from = InboundFrom::Filter;
        filtered.reach.inbound.types = vec![quote];
        filtered.reach.inbound.filter.past = true;
        let filtered = signed(&ana, filtered, 3);
        let met = Sender {
            met: true,
            ..unconfirmed(&stranger)
        };
        assert_eq!(filtered.admit(&met, None, NOW), Admission::Drop);
        assert!(!filtered.lets_in_by_reach(&met));
    }

    /// Bug caught: a delegate signing a price with a contact the agent added by itself, because the
    /// rules' approval check took anyone they don't block as approved, or anyone at all once the owner
    /// let people in beyond contacts, though reach let strangers in for no such type, or the filter
    /// didn't fit them.
    #[test]
    fn only_a_contact_the_owner_named_or_their_reach_lets_in_counts_as_approved() {
        use crate::requests::{FieldValue, Fields, Operation, Terms, TermsParty, examples};
        use std::collections::BTreeMap;
        let quote = crate::requests::example("quote/1");
        let schema = examples().get(&quote).unwrap().as_ref().clone();
        let ana = owner();
        let ben = agent_of(&owner());
        let (stranger, partner) = (owner(), owner());
        let (them, partners) = (agent_of(&stranger), agent_of(&partner));
        let me = agent_of(&ana);
        let with =
            |other: &Identity, their_owner: &Owner, interaction: &InteractionType| ApprovalDraft {
                owner: ana.identity.id().clone(),
                agent: me.id().clone(),
                // A `confirm` with a price waits for the owner whoever it's with, and a `cancel`
                // carrying one waits only for someone they haven't approved.
                operation: Operation::Cancel,
                request: MessageId::of(b"open"),
                version: 1,
                prev: MessageId::of(b"deliver"),
                terms: Terms {
                    interaction: interaction.clone(),
                    requester: TermsParty {
                        agent: other.id().clone(),
                        owner: their_owner.identity.id().clone(),
                    },
                    recipient: TermsParty {
                        agent: me.id().clone(),
                        owner: ana.identity.id().clone(),
                    },
                    agreed: Fields::from([
                        ("currency".to_owned(), FieldValue::Text("usd".to_owned())),
                        ("item".to_owned(), FieldValue::Text("catering".to_owned())),
                        ("quantity".to_owned(), FieldValue::Int(40)),
                    ]),
                    result: Fields::from([
                        ("amount_minor".to_owned(), FieldValue::Int(100)),
                        ("valid_days".to_owned(), FieldValue::Int(14)),
                    ]),
                    subject: None,
                    note: None,
                    supersedes: None,
                },
                latest_expiry: 0,
            };
        let mut named = contact(&ben, ContactStatus::Allowed);
        named.types = vec![meeting(), quote.clone()];
        let mut rules = draft(vec![named], false);
        rules.permissions = Permissions {
            level: Level::FullAuto,
            actions_per_day: 10,
            caps: BTreeMap::new(),
            quoted_prices: QuotedPrices::Wait,
        };
        let signs = |rules: &VerifiedRules, draft: &ApprovalDraft| {
            rules
                .permissions()
                .decide(&schema, draft, 0, rules.counterparty(draft))
                == AutoDecision::Sign
        };
        let off = signed(&ana, rules.clone(), 1);
        assert!(signs(&off, &with(&them, &stranger, &quote)));
        rules.reach.agreed = Some(Agreed {
            types: vec![meeting(), quote.clone()],
            text: true,
            agree_types: false,
        });
        let on = signed(&ana, rules.clone(), 2);
        assert!(signs(&on, &with(&ben, &ana, &quote)));
        assert!(!signs(&on, &with(&them, &stranger, &quote)));
        assert_eq!(
            rules.counterparty(&with(&them, &stranger, &quote)),
            Counterparty::NotApproved
        );
        // Open to anyone, and to anyone for meetings only: a stranger can't open a quote, so one the
        // agent agreed with can't count as approved for one either.
        rules.reach.inbound.from = InboundFrom::Open;
        rules.reach.inbound.types = vec![meeting()];
        let open = signed(&ana, rules.clone(), 3);
        assert!(!signs(&open, &with(&them, &stranger, &quote)));
        assert_eq!(
            open.counterparty(&with(&them, &stranger, &meeting())),
            Counterparty::Approved
        );
        rules.reach.inbound.types = vec![meeting(), quote.clone()];
        let open_for_quotes = signed(&ana, rules.clone(), 4);
        assert!(signs(&open_for_quotes, &with(&them, &stranger, &quote)));
        // A filter lets in the partner's agents, and nobody else counts.
        rules.reach.inbound.from = InboundFrom::Filter;
        rules.reach.inbound.filter.owners = vec![partner.identity.id().clone()];
        let filtered = signed(&ana, rules, 5);
        assert!(signs(&filtered, &with(&partners, &partner, &quote)));
        assert!(!signs(&filtered, &with(&them, &stranger, &quote)));
        assert!(!filtered.approves(them.id(), Some(stranger.identity.id()), &[quote]));
    }

    /// Bug caught: a contact the owner named with no type of their own, using only what the two agents
    /// agree, read as one the owner hadn't approved, so the agent was told to ask its owner about them.
    #[test]
    fn a_named_contact_with_no_type_of_their_own_is_approved() {
        let ana = owner();
        let ben = agent_of(&owner());
        let stranger = agent_of(&owner());
        let mut named = contact(&ben, ContactStatus::Allowed);
        named.types = Vec::new();
        named.agree_types = true;
        let mut rules = draft(vec![named], false);
        rules.reach.agreed = Some(Agreed {
            types: Vec::new(),
            text: true,
            agree_types: true,
        });
        let rules = signed(&ana, rules, 1);
        assert!(rules.approves(ben.id(), None, &[]));
        assert!(!rules.approves(stranger.id(), None, &[]), "control");
    }

    /// Bugs caught: a kind with currency, which the other agent may have written labelling a price as
    /// paid to this side, used with no owner approval, so a fooled agent commits its owner to money with
    /// no touch; and a number the kind doesn't label as currency, such as a meeting's length, held for
    /// the owner every time (Nenye, 2026-11-15). A kind with currency is used only once the owner names
    /// it, its labels count once they have, and a number not labelled as currency never waits.
    #[test]
    fn a_kind_with_currency_waits_for_approval_and_other_numbers_dont_wait() {
        use crate::requests::{
            FieldValue, Fields, Operation, Schema, Side, StepKind, Terms, TermsParty,
        };
        use crate::rules::Commits;
        // Each type has one way to slip a price past its owner, so each check fails on its own bug.
        // Its writer left the price out of `values`, which would make it no value at all.
        let unlabelled = Schema::parse(
            br#"{"type":"tip/1","kind":"request","offer":{"item":{"word":["cut"]}},
                 "result":{"amount":{"range":{"min":0,"max":100000}}},"sign":"requester"}"#,
        )
        .unwrap();
        // The same, as a number from a list.
        let listed = Schema::parse(
            br#"{"type":"tip/2","kind":"request","offer":{"item":{"word":["cut"]}},
                 "result":{"amount":{"one_of":[500,1000]}},"sign":"requester"}"#,
        )
        .unwrap();
        // Its writer says the price is paid to the side delivering it, which `quoted_prices` lets go.
        let paid_to_me = Schema::parse(
            br#"{"type":"tip/3","kind":"request","offer":{"currency":{"word":["usd"]}},
                 "fixed":["currency"],"result":{"amount":{"range":{"min":0,"max":100000}}},
                 "values":["amount"],"units":{"amount":"currency"},"paid":{"amount":"recipient"},
                 "sign":"requester"}"#,
        )
        .unwrap();
        let ana = owner();
        let ben = agent_of(&owner());
        let me = agent_of(&ana);
        let deliver = |schema: &Schema| {
            let text = |word: &str| FieldValue::Text(word.to_owned());
            let agreed: Fields = if schema.name() == paid_to_me.name() {
                [("currency".to_owned(), text("usd"))].into()
            } else {
                [("item".to_owned(), text("cut"))].into()
            };
            ApprovalDraft {
                owner: ana.identity.id().clone(),
                agent: me.id().clone(),
                operation: Operation::Deliver,
                request: MessageId::of(b"open"),
                version: 1,
                prev: MessageId::of(b"accept"),
                terms: Terms {
                    interaction: schema.name().clone(),
                    requester: TermsParty {
                        agent: ben.id().clone(),
                        owner: ben.id().clone(),
                    },
                    recipient: TermsParty {
                        agent: me.id().clone(),
                        owner: ana.identity.id().clone(),
                    },
                    agreed,
                    result: [("amount".to_owned(), FieldValue::Int(500))].into(),
                    subject: None,
                    note: None,
                    supersedes: None,
                },
                latest_expiry: 0,
            }
        };
        let mut agreeing = contact(&ben, ContactStatus::Allowed);
        agreeing.agree_types = true;
        let mut rules = draft(vec![agreeing], false);
        rules.permissions.quoted_prices = QuotedPrices::WithinLimits;
        let waits = |rules: &RulesDraft, schema: &Schema| {
            let draft = deliver(schema);
            let read = rules.as_owner_reads(schema, &draft);
            let commits = Commits::of(&read, &draft.terms, Side::Recipient);
            rules
                .permissions
                .waits_for_owner(StepKind::Deliver, commits)
        };
        // A number not labelled as currency: used with no approval, and never held.
        for schema in [&unlabelled, &listed] {
            assert!(
                rules.contacts[0].approved_for_use(schema),
                "{}",
                schema.encoding()
            );
            assert!(!waits(&rules, schema), "{}", schema.encoding());
        }
        // Currency: the agent can't use it before the owner approves it, though it can agree it, and
        // what's held across a change of rules reads every amount as one the owner may be paying.
        assert!(!rules.contacts[0].approved_for_use(&paid_to_me));
        assert!(rules.contacts[0].may_propose(&paid_to_me));
        assert!(waits(&rules, &paid_to_me));
        // Named by the owner, it's used, and its own labels count.
        rules.contacts[0].types = vec![paid_to_me.name().clone()];
        assert!(rules.contacts[0].approved_for_use(&paid_to_me), "control");
        assert!(!waits(&rules, &paid_to_me), "control");
    }

    /// Review of the v0 stack: with `text` off, two agents agreed a conversation of sixteen 53-bit
    /// numbers and carried 848 bits on every `say`, with no owner asked.
    #[test]
    fn a_type_with_room_for_what_an_agent_likes_needs_text() {
        let ben = agent_of(&owner());
        let parse = |document: serde_json::Value| Schema::parse(document.to_string().as_bytes());
        let numbers = |kind: &str, section: &str| {
            let fields: serde_json::Map<String, serde_json::Value> = ('a'..='p')
                .map(|name| {
                    (
                        name.to_string(),
                        serde_json::json!({"range": {"min": 0, "max": (1_u64 << 53) - 1}}),
                    )
                })
                .collect();
            let mut document = serde_json::json!({"type": "nums/1", "kind": kind, "sign": "both"});
            document[section] = serde_json::Value::Object(fields);
            if kind == "conversation" {
                document["sign"] = "none".into();
            }
            parse(document)
        };
        let small_talk = parse(serde_json::json!({"type": "yes/1", "kind": "conversation",
            "say": {"answer": {"word": ["yes", "no"]}}}))
        .unwrap();
        let note = parse(
            serde_json::json!({"type": "note/1", "kind": "request", "sign": "both",
            "offer": {"note": {"text": {"max_chars": 100}}}}),
        )
        .unwrap();
        // Times on a one-minute grid, which an unapproved type never counts as a value.
        let times: serde_json::Map<String, serde_json::Value> = ('a'..='f')
            .map(|name| {
                (
                    name.to_string(),
                    serde_json::json!({"times": {"grid_secs": 60, "max": 16}}),
                )
            })
            .collect();
        let slots = parse(
            serde_json::json!({"type": "slots/1", "kind": "request", "sign": "both",
                "offer": times}),
        )
        .unwrap();
        let roomy = [
            numbers("conversation", "say").unwrap(),
            numbers("request", "offer").unwrap(),
            numbers("request", "result").unwrap(),
            small_talk,
            note,
            slots,
        ];
        let mut without_text = contact(&ben, ContactStatus::Allowed);
        without_text.agree_types = true;
        for schema in &roomy {
            // Even one the owner named: it still carries what the agent likes.
            without_text.types = vec![schema.name().clone()];
            assert!(!without_text.may_use(schema), "{}", schema.encoding());
            assert!(!without_text.may_propose(schema), "{}", schema.encoding());
        }
        let mut with_text = without_text.clone();
        with_text.text = true;
        for schema in &roomy {
            assert!(with_text.may_use(schema), "control: {}", schema.encoding());
            assert!(
                with_text.may_propose(schema),
                "control: {}",
                schema.encoding()
            );
        }
        without_text.types = Vec::new();
        for example in crate::requests::examples().all() {
            assert!(
                without_text.may_use(example),
                "control: {:?}",
                example.name()
            );
            assert!(
                without_text.may_propose(example),
                "control: {:?}",
                example.name()
            );
        }
    }

    #[test]
    fn only_signet_and_hosts_mark_someone_as_let_in_by_reach_or_added_by_the_agent() {
        let ana = owner();
        let agent = agent_of(&ana);
        let ben = agent_of(&owner());
        for pinned_by in [PinnedBy::Reach, PinnedBy::Agent] {
            let mut entry = contact(&ben, ContactStatus::Allowed);
            entry.pinned_by = pinned_by;
            let refused =
                draft(vec![entry], false).sign(&ana.key, ana.identity.id(), agent.id(), 1, NOW);
            assert_eq!(refused.err(), Some(Error::Malformed));
        }
    }

    #[test]
    fn a_device_wont_sign_rules_a_reader_would_refuse() {
        let ana = owner();
        let agent = agent_of(&ana);
        let mut too_high = draft(Vec::new(), false);
        too_high.limits.open_approvals = 11;
        assert_eq!(
            too_high
                .sign(&ana.key, ana.identity.id(), agent.id(), 1, NOW)
                .err(),
            Some(Error::Malformed)
        );
    }
}

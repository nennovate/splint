//! An agent's ask of its owner: exact changes to how it deals with other agents, which only the owner's
//! signature makes, `typ` `splint-ask`, signed by the agent's key. The ask itself moves nothing and
//! hands the agent nothing it could use again: the owner's side shows the person the changes in its
//! own words and, with their touch, signs new rules holding exactly them. See "An agent's ask" in
//! `docs/protocol.md`. Provisional, for Nenye to overturn.

use std::collections::HashSet;

use aws_lc_rs::digest;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::requests::{InteractionType, Operation, Place, VerifiedWherePaid};
use crate::rules::{
    ContactStatus, InboundFilter, InboundFrom, Level, Outbound, PinnedBy, QuotedPrices,
    RulesContact, RulesDraft,
};
use crate::{
    CLOCK_TOLERANCE_SECS, Error, Identity, MessageId, PublicKey, SigningKey, SplintId,
    canonical_address, jws,
};

const ASK_TYPE: &str = "splint-ask";
const VERSION: u8 = 1;
/// However many changes an ask holds, it's no longer than this, so a person reads it at a glance.
pub const MAX_ASK_CHARS: usize = 16 * 1024;
/// The longest an ask stays open, so an agent on another machine still reaches a person who's away
/// for the day, and an old one is never there to be approved by surprise.
pub const MAX_ASK_SECS: u64 = 24 * 60 * 60;

/// Whether an owner's approval of a move, signed at `issued_at`, has outlasted the ask it answered, so
/// one nobody took up can't move an agent months later, when its owner may want otherwise.
pub fn move_approval_lapsed(issued_at: u64, now: u64) -> bool {
    issued_at
        .saturating_add(MAX_ASK_SECS)
        .saturating_add(CLOCK_TOLERANCE_SECS)
        < now
}
const ID_BYTES: usize = 16;
/// The most changes one approval names: a prompt shows each on its own line, and what doesn't fit
/// waits for the next approval, so nothing is ever signed behind an "and more".
pub const MOST_IN_ONE_APPROVAL: usize = 8;

/// One change, in the protocol's own words for the setting. Nothing in one is free text: an agent
/// explains in its own chat, never on the owner's prompt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    /// Set up the owner's controls for this agent: that it acts for them, under the default rules,
    /// with a delegation to this key, its Signet's delegate key, which the owner's side signs with them.
    Controls {
        delegate: String,
    },
    Level {
        to: Level,
    },
    QuotedPrices {
        to: QuotedPrices,
    },
    /// Who besides contacts may reach it, started afresh as Settings does, with nobody's words let in.
    Reach {
        to: InboundFrom,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        types: Vec<InteractionType>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        owners: Vec<SplintId>,
        #[serde(default, skip_serializing_if = "is_false")]
        past: bool,
    },
    Writes {
        to: Outbound,
    },
    Paused {
        to: bool,
    },
    /// Let this agent in as a contact, for these types, or change what an existing one may use.
    Contact {
        agent: SplintId,
        address: String,
        types: Vec<InteractionType>,
        text: bool,
    },
    Remove {
        agent: SplintId,
    },
    Block {
        agent: SplintId,
        address: String,
    },
    /// Approve one step held for the owner: what the agent asked to send in this request, waiting for
    /// their yes. It changes no rule, so it's alone in its ask, and the owner's side signs a yes to
    /// the exact draft held, as it would from their controls.
    Step {
        request: MessageId,
        operation: Operation,
    },
    /// Where the owner gets paid: exactly these places, which the owner's side signs as a new
    /// `splint-where-paid` in place of the one before. It changes no rule, so it's alone in its ask,
    /// and every place is one a statement takes.
    WherePaid {
        places: Vec<Place>,
    },
    /// Move this agent to another host under the same ID: the owner's side signs a binding at `to`, in
    /// its one spelling and on another domain, which the agent takes up there. It changes no rule, so
    /// it's alone in its ask.
    Host {
        to: String,
    },
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Change {
    /// What it changes, so one ask never says two things about the same setting or contact.
    fn subject(&self) -> String {
        match self {
            Self::Contact { agent, .. } | Self::Remove { agent } | Self::Block { agent, .. } => {
                format!("contact {agent}")
            }
            Self::Controls { .. } => "controls".to_owned(),
            Self::Step { .. } => "step".to_owned(),
            Self::WherePaid { .. } => "where_paid".to_owned(),
            Self::Host { .. } => "host".to_owned(),
            Self::Level { .. } => "level".to_owned(),
            Self::QuotedPrices { .. } => "quoted_prices".to_owned(),
            Self::Reach { .. } => "reach".to_owned(),
            Self::Writes { .. } => "writes".to_owned(),
            Self::Paused { .. } => "paused".to_owned(),
        }
    }

    fn check(&self) -> Result<(), Error> {
        // A type an owner names is one two agents agreed, by its ID. Core's own aren't named: words
        // are `text`, and agreeing types is the contact's own switch.
        let types_agreed = match self {
            Self::Reach { types, .. } | Self::Contact { types, .. } => {
                types.iter().all(InteractionType::is_agreed)
            }
            _ => true,
        };
        let fine = types_agreed
            && match self {
                Self::Reach {
                    to: InboundFrom::Contacts,
                    types,
                    owners,
                    past,
                } => types.is_empty() && owners.is_empty() && !past,
                Self::Reach {
                    to: InboundFrom::Open,
                    types,
                    owners,
                    past,
                } => !types.is_empty() && owners.is_empty() && !past,
                Self::Reach {
                    to: InboundFrom::Filter,
                    types,
                    owners,
                    past,
                } => !types.is_empty() && (*past || !owners.is_empty()) && owners.iter().all(is_id),
                Self::Contact { agent, address, .. } | Self::Block { agent, address } => {
                    is_id(agent) && is_one_spelling(address)
                }
                Self::Remove { agent } => is_id(agent),
                // In its one spelling, and on the curve, as Go and the page check it: a delegation
                // to a point that isn't one could never be used, and the three would disagree.
                Self::Controls { delegate } => PublicKey::from_encoded(delegate).is_ok_and(|key| {
                    key.encoded() == *delegate
                        && crate::SealPublicKey::from_bytes(key.as_bytes()).is_ok()
                }),
                Self::Step { request, .. } => request.is_well_formed(),
                Self::Host { to } => is_one_spelling(to),
                // Its places are checked as the statement the owner's side would sign, below.
                Self::WherePaid { .. } => true,
                Self::Level { .. }
                | Self::QuotedPrices { .. }
                | Self::Writes { .. }
                | Self::Paused { .. } => true,
            };
        if fine { Ok(()) } else { Err(Error::Malformed) }
    }

    /// Whether it lets more in than before, which every place that shows it warns about in the same
    /// fixed words: the page, the terminal and the device's own prompt.
    pub fn lets_more_in(&self) -> bool {
        match self {
            Self::Level { to } => *to == Level::FullAuto,
            Self::Reach { to, .. } => *to != InboundFrom::Contacts,
            Self::QuotedPrices { to } => *to == QuotedPrices::WithinLimits,
            Self::Writes { to } => *to == Outbound::Replies,
            Self::Contact { text, .. } => *text,
            _ => false,
        }
    }

    /// Makes this change to rules an owner is about to sign, and nothing else. Setting up controls
    /// changes no rule: the owner's side signs that with the first rules. Nor does a step, or where
    /// the owner gets paid.
    pub fn apply(&self, draft: &mut RulesDraft) {
        match self {
            Self::Controls { .. }
            | Self::Step { .. }
            | Self::WherePaid { .. }
            | Self::Host { .. } => {}
            Self::Level { to } => draft.permissions.level = *to,
            Self::QuotedPrices { to } => draft.permissions.quoted_prices = *to,
            Self::Reach {
                to,
                types,
                owners,
                past,
            } => {
                let inbound = &mut draft.reach.inbound;
                inbound.from = *to;
                inbound.filter = InboundFilter {
                    owners: owners.clone(),
                    past: *past,
                    ..InboundFilter::default()
                };
                inbound.text = false;
                inbound.types.clone_from(types);
            }
            Self::Writes { to } => draft.reach.outbound = *to,
            Self::Paused { to } => draft.paused = *to,
            Self::Contact {
                agent,
                address,
                types,
                text,
            } => upsert(draft, agent, address, ContactStatus::Allowed, types, *text),
            Self::Block { agent, address } => {
                upsert(draft, agent, address, ContactStatus::Blocked, &[], false);
            }
            Self::Remove { agent } => draft.contacts.retain(|contact| &contact.agent != agent),
        }
    }
}

/// The delegate key an ask for controls names, if it's one.
pub fn controls_delegate(changes: &[Change]) -> Option<&str> {
    changes.iter().find_map(|change| match change {
        Change::Controls { delegate } => Some(delegate.as_str()),
        _ => None,
    })
}

/// The held step an ask names, if it's for one.
pub fn step_of(changes: &[Change]) -> Option<(&MessageId, Operation)> {
    changes.iter().find_map(|change| match change {
        Change::Step { request, operation } => Some((request, *operation)),
        _ => None,
    })
}

/// The address an ask asks to move the agent to, if it's for that.
pub fn host_of(changes: &[Change]) -> Option<&str> {
    changes.iter().find_map(|change| match change {
        Change::Host { to } => Some(to.as_str()),
        _ => None,
    })
}

/// Every type an ask asks the owner to approve, for a contact or for whoever reach lets in, which the
/// owner's side shows them in fixed words before they approve it.
pub fn types_named(changes: &[Change]) -> Vec<&InteractionType> {
    changes
        .iter()
        .flat_map(|change| match change {
            Change::Contact { types, .. } | Change::Reach { types, .. } => types.as_slice(),
            _ => &[],
        })
        .collect()
}

/// The places an ask asks the owner to be paid at, if it's for that.
pub fn where_paid_of(changes: &[Change]) -> Option<&[Place]> {
    changes.iter().find_map(|change| match change {
        Change::WherePaid { places } => Some(places.as_slice()),
        _ => None,
    })
}

/// Whether an ask holding `changes` goes in one approval with asks holding `with`: never past
/// [`MOST_IN_ONE_APPROVAL`] changes, and a held step, where the owner gets paid or a move to another
/// host only alone, so the money, terms or host it moves are never read beside anything else. The owner's prompt and every list of
/// what one approval signs group asks by this alone, so the list shown is the one signed.
pub fn fits_one_approval(with: &[&[Change]], changes: &[Change]) -> bool {
    let alone = |changes: &[Change]| {
        step_of(changes).is_some() || where_paid_of(changes).is_some() || host_of(changes).is_some()
    };
    let named: usize = with.iter().map(|one| one.len()).sum();
    named.saturating_add(changes.len()) <= MOST_IN_ONE_APPROVAL
        && (with.is_empty() || !(alone(changes) || with.iter().any(|one| alone(one))))
}

/// Whether `draft` already holds every change, so making them changes nothing.
pub fn all_held_in(changes: &[Change], draft: &RulesDraft) -> bool {
    let mut applied = draft.clone();
    for change in changes {
        change.apply(&mut applied);
    }
    serde_json::to_value(&applied).ok() == serde_json::to_value(draft).ok()
}

fn upsert(
    draft: &mut RulesDraft,
    agent: &SplintId,
    address: &str,
    status: ContactStatus,
    types: &[InteractionType],
    text: bool,
) {
    let known = draft
        .contacts
        .iter()
        .find(|contact| &contact.agent == agent);
    let label = known.map_or_else(|| address.to_owned(), |known| known.label.clone());
    // An ask names types and words, not the owner's switch for agreeing types, so a contact keeps
    // theirs, and a new one gets what an owner's new contact gets.
    let agree_types = known.is_none_or(|known| known.agree_types);
    draft
        .contacts
        .retain(|contact| &contact.agent != agent && contact.address != address);
    draft.contacts.push(RulesContact {
        agent: agent.clone(),
        address: address.to_owned(),
        label,
        status,
        types: types.to_vec(),
        text,
        agree_types: status == ContactStatus::Allowed && agree_types,
        pinned_by: PinnedBy::Owner,
    });
}

fn is_id(id: &SplintId) -> bool {
    id.is_well_formed() && !id.is_guest()
}

fn is_one_spelling(address: &str) -> bool {
    canonical_address(address).is_ok_and(|canonical| canonical == address)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AskPayload {
    v: u8,
    id: String,
    agent: SplintId,
    owner: SplintId,
    changes: Vec<Change>,
    issued_at: u64,
    expires_at: u64,
}

impl AskPayload {
    fn check(&self, now: u64) -> Result<(), Error> {
        let lasts = self.expires_at.checked_sub(self.issued_at);
        let mut subjects = HashSet::new();
        if self.v != VERSION
            || self.id.len() != 2 * ID_BYTES
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !is_id(&self.agent)
            || !is_id(&self.owner)
            || self.changes.is_empty()
            || !lasts.is_some_and(|lasts| lasts > 0 && lasts <= MAX_ASK_SECS)
            || !self
                .changes
                .iter()
                .all(|change| subjects.insert(change.subject()))
            || (self.changes.len() > 1
                && ["step", "where_paid", "host"]
                    .iter()
                    .any(|alone| subjects.contains(*alone)))
        {
            return Err(Error::Malformed);
        }
        // The statement the owner's side would sign for these places as the ask was made: one a
        // reader takes, so a person is never shown places that can't be signed.
        if let Some(places) = where_paid_of(&self.changes)
            && VerifiedWherePaid::payload_to_sign(&self.owner, places.to_vec(), self.issued_at)
                .is_err()
        {
            return Err(Error::Malformed);
        }
        self.changes.iter().try_for_each(Change::check)?;
        if self.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        if now >= self.expires_at {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

/// Signs an ask from `agent`, who acts for `owner`, for `lasts` seconds from `now`.
pub fn sign_ask(
    key: &SigningKey,
    agent: &SplintId,
    owner: &SplintId,
    changes: Vec<Change>,
    now: u64,
    lasts: u64,
) -> Result<String, Error> {
    let mut id = [0_u8; ID_BYTES];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| Error::Crypto)?;
    let payload = AskPayload {
        v: VERSION,
        id: hex(&id),
        agent: agent.clone(),
        owner: owner.clone(),
        changes,
        issued_at: now,
        expires_at: now.saturating_add(lasts),
    };
    payload.check(now)?;
    let bytes = serde_json::to_vec(&payload).map_err(|_| Error::Malformed)?;
    let compact = jws::sign(key, ASK_TYPE, &bytes)?;
    if compact.len() > MAX_ASK_CHARS {
        return Err(Error::Malformed);
    }
    Ok(compact)
}

/// An ask's ID, read unchecked from one this side signed and kept itself.
pub fn payload_id(compact: &str) -> Result<String, Error> {
    Ok(unchecked(compact)?.id)
}

/// An ask's changes, read unchecked from one this side signed and kept itself.
pub fn payload_changes(compact: &str) -> Result<Vec<Change>, Error> {
    Ok(unchecked(compact)?.changes)
}

/// When an ask ends, read unchecked from one this side keeps after checking it.
pub fn payload_expires_at(compact: &str) -> Result<u64, Error> {
    Ok(unchecked(compact)?.expires_at)
}

fn unchecked(compact: &str) -> Result<AskPayload, Error> {
    serde_json::from_slice(&jws::unverified_payload(compact, ASK_TYPE)?)
        .map_err(|_| Error::Malformed)
}

/// An ask whose signature, spelling, changes and dates all checked out.
#[derive(Clone, Debug)]
pub struct VerifiedAsk {
    compact: String,
    payload: AskPayload,
}

impl VerifiedAsk {
    /// `agent` is the newest copy of the asking agent's ID the reader holds. The agent's own key signs
    /// an ask, so an owner's ID, which may carry key statements, never does.
    pub fn verify(compact: &str, agent: &Identity, now: u64) -> Result<Self, Error> {
        if compact.len() > MAX_ASK_CHARS {
            return Err(Error::Malformed);
        }
        if !agent.may_act_as_agent() {
            return Err(Error::WrongSigner);
        }
        let bytes = agent.verify(compact, ASK_TYPE)?;
        let payload: AskPayload = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        if serde_json::to_vec(&payload).map_err(|_| Error::Malformed)? != bytes {
            return Err(Error::Malformed);
        }
        payload.check(now)?;
        if &payload.agent != agent.id() {
            return Err(Error::WrongSigner);
        }
        Ok(Self {
            compact: compact.to_owned(),
            payload,
        })
    }

    /// The agent an ask claims to be from, unchecked, to find whose ID to verify it under.
    pub fn claimed_agent(compact: &str) -> Result<SplintId, Error> {
        Ok(unchecked(compact)?.agent)
    }

    pub fn id(&self) -> &str {
        &self.payload.id
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn agent(&self) -> &SplintId {
        &self.payload.agent
    }

    /// The owner the agent acted for when it asked: a stand-in, for an agent asking for controls.
    pub fn owner(&self) -> &SplintId {
        &self.payload.owner
    }

    pub fn changes(&self) -> &[Change] {
        &self.payload.changes
    }

    pub fn asks_for_controls(&self) -> bool {
        controls_delegate(&self.payload.changes).is_some()
    }

    /// The one held step asked for, if this ask is for one.
    pub fn step(&self) -> Option<(&MessageId, Operation)> {
        step_of(&self.payload.changes)
    }

    /// The places it asks the owner to be paid at, if it's for that.
    pub fn where_paid(&self) -> Option<&[Place]> {
        where_paid_of(&self.payload.changes)
    }

    /// The address it asks to move the agent to, if it's for that.
    pub fn host(&self) -> Option<&str> {
        host_of(&self.payload.changes)
    }

    pub fn issued_at(&self) -> u64 {
        self.payload.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.payload.expires_at
    }

    /// The hex SHA-256 of its payload.
    pub fn hash(&self) -> String {
        let bytes = serde_json::to_vec(&self.payload).unwrap_or_default();
        hex(digest::digest(&digest::SHA256, &bytes).as_ref())
    }

    /// Every change made to `draft`, for the owner's side to sign.
    pub fn apply(&self, draft: &mut RulesDraft) {
        for change in &self.payload.changes {
            change.apply(draft);
        }
    }

    /// Whether rules the owner signed hold everything asked, apart from controls, which only a
    /// binding shows. So the agent learns it's done from the owner's rules alone, whoever delivered them.
    pub fn holds_in(&self, draft: &RulesDraft) -> bool {
        all_held_in(&self.payload.changes, draft)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RulesDraft;

    const NOW: u64 = 1_793_750_400;

    fn agent() -> (SigningKey, Identity) {
        let key = SigningKey::generate().unwrap();
        let identity = crate::test_identity(&key);
        (key, identity)
    }

    fn controls() -> Change {
        Change::Controls {
            delegate: SigningKey::generate().unwrap().public_key().encoded(),
        }
    }

    fn ben() -> Change {
        Change::Contact {
            agent: crate::test_identity(&SigningKey::generate().unwrap())
                .id()
                .clone(),
            address: "ben~host.example".to_owned(),
            types: vec![crate::requests::example("quote/1")],
            text: false,
        }
    }

    /// Bug caught: an ask taken after it ran out, from another agent's key, with two changes to one
    /// setting, or with room for a field the person isn't shown.
    #[test]
    fn an_ask_is_taken_only_as_its_agent_signed_it_and_while_it_lasts() {
        let (key, muse) = agent();
        let owner = crate::test_identity(&SigningKey::generate().unwrap());
        let changes = vec![
            Change::Level {
                to: Level::FullAuto,
            },
            ben(),
        ];
        let ask = sign_ask(&key, muse.id(), owner.id(), changes, NOW, 3600).unwrap();
        let taken = VerifiedAsk::verify(&ask, &muse, NOW + 10).unwrap();
        assert_eq!(taken.changes().len(), 2);
        assert_eq!(
            VerifiedAsk::verify(&ask, &muse, NOW + 3600).err(),
            Some(Error::Expired)
        );
        let (_, other) = agent();
        assert!(VerifiedAsk::verify(&ask, &other, NOW).is_err());
        let twice = vec![Change::Paused { to: true }, Change::Paused { to: false }];
        assert_eq!(
            sign_ask(&key, muse.id(), owner.id(), twice, NOW, 3600).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            sign_ask(
                &key,
                muse.id(),
                owner.id(),
                vec![controls()],
                NOW,
                MAX_ASK_SECS + 1
            )
            .err(),
            Some(Error::Malformed)
        );
        let padded = jws::sign(
            &key,
            ASK_TYPE,
            serde_json::to_string(&taken.payload)
                .unwrap()
                .replace("\"v\":1", "\"v\": 1")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            VerifiedAsk::verify(&padded, &muse, NOW).err(),
            Some(Error::Malformed)
        );
    }

    /// Bug caught: a move to another host signed beside other changes, so it's read as one line among
    /// many, or naming an address in a spelling a reader takes as another.
    #[test]
    fn a_move_to_another_host_is_alone_and_in_its_one_spelling() {
        let (key, muse) = agent();
        let owner = crate::test_identity(&SigningKey::generate().unwrap());
        let host = |to: &str| Change::Host { to: to.to_owned() };
        let ask = sign_ask(
            &key,
            muse.id(),
            owner.id(),
            vec![host("muse~new.example")],
            NOW,
            3600,
        )
        .unwrap();
        let taken = VerifiedAsk::verify(&ask, &muse, NOW).unwrap();
        assert_eq!(taken.host(), Some("muse~new.example"));
        for refused in [
            vec![host("muse~new.example"), Change::Paused { to: true }],
            vec![host("Muse~NEW.example")],
            vec![host("muse")],
        ] {
            assert_eq!(
                sign_ask(&key, muse.id(), owner.id(), refused, NOW, 3600).err(),
                Some(Error::Malformed)
            );
        }
        let alone: &[Change] = &[host("muse~new.example")];
        assert!(!fits_one_approval(&[&[Change::Paused { to: true }]], alone));
    }

    /// Bug caught: an agent told its ask is done when the rules signed hold only part of it.
    #[test]
    fn an_ask_is_done_only_when_signed_rules_hold_all_of_it() {
        let (key, muse) = agent();
        let owner = crate::test_identity(&SigningKey::generate().unwrap());
        let changes = vec![
            Change::Reach {
                to: InboundFrom::Open,
                types: vec![crate::requests::example("quote/1")],
                owners: Vec::new(),
                past: false,
            },
            ben(),
        ];
        let ask = sign_ask(&key, muse.id(), owner.id(), changes, NOW, 3600).unwrap();
        let ask = VerifiedAsk::verify(&ask, &muse, NOW).unwrap();
        let mut rules: RulesDraft = serde_json::from_str(
            r#"{"paused":false,"contacts":[],"invites":[],"limits":{"new_requests_per_contact_per_day":20,"open_requests_per_contact":3,"open_approvals":10,"new_from_others_per_day":250,"texts_per_contact_per_day":100}}"#,
        )
        .unwrap();
        assert!(!ask.holds_in(&rules));
        ask.changes()[0].apply(&mut rules);
        assert!(!ask.holds_in(&rules), "half of it");
        ask.apply(&mut rules);
        assert!(ask.holds_in(&rules));
    }

    /// Bug caught: an approved "anyone may reach it for a quote" also letting in anyone's words,
    /// because the reach it replaced had words on, which the person isn't told.
    #[test]
    fn a_reach_change_lets_no_words_in() {
        let (key, muse) = agent();
        let owner = crate::test_identity(&SigningKey::generate().unwrap());
        let reach = vec![Change::Reach {
            to: InboundFrom::Open,
            types: vec![crate::requests::example("quote/1")],
            owners: Vec::new(),
            past: false,
        }];
        let ask = sign_ask(&key, muse.id(), owner.id(), reach, NOW, 3600).unwrap();
        let ask = VerifiedAsk::verify(&ask, &muse, NOW).unwrap();
        let mut rules: RulesDraft = serde_json::from_str(
            r#"{"paused":false,"contacts":[],"invites":[],"limits":{"new_requests_per_contact_per_day":20,"open_requests_per_contact":3,"open_approvals":10,"new_from_others_per_day":250,"texts_per_contact_per_day":100}}"#,
        )
        .unwrap();
        rules.reach.inbound.text = true;
        ask.apply(&mut rules);
        assert!(!rules.reach.inbound.text);
        assert!(ask.holds_in(&rules));
    }
}

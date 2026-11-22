//! Who may reach an agent beyond its contacts, and whom it may write to. Both are the owner's
//! settings, signed in their rules, and separate from each other.
//!
//! Splint applies the setting and decides nothing else about a sender: whether a customer is worth
//! answering is the agent's judgment. Someone let in this way gets only the types the owner named,
//! and their words reach the agent marked untrusted like anyone else's.

use serde::{Deserialize, Serialize};

use crate::requests::InteractionType;
use crate::{Error, PublicKey, SplintId, parse_address};

/// Enough for a business's partners or a person's circle, and small enough to check on every message.
const MAX_FILTER_ENTRIES: usize = 64;
const MAX_REACH_TYPES: usize = 16;
/// How much of an owner's daily limit for others all agents whose owners haven't confirmed can take
/// together. Anyone can make as many of those as they like on hosts that work together, so they share
/// one part, and everyone else keeps the rest.
pub const UNCONFIRMED_SHARE_OF_QUOTA: u32 = 2;

/// What happens to a sender nobody let in. There's no `allow`, so a tricked owner or a drafted rule
/// can't remove the floor: letting people in is `from`, which says how.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownSenders {
    Quarantine,
    Block,
}

/// Who, besides contacts and invited people, may reach this agent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundFrom {
    /// Nobody else.
    #[default]
    Contacts,
    /// Anyone, as a business might be.
    Open,
    /// Whoever fits the filter.
    Filter,
}

/// A host the owner lets people in from, and the key it signs deliveries with. The owner's signature on
/// the key is what lets Signet check the claim by itself, with no word from its own host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListedHost {
    pub domain: String,
    pub key: String,
}

/// Each part lets more people in, and a sender needs to fit one of them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundFilter {
    /// Agents acting for these owners, by their owner's signed statement.
    #[serde(default)]
    pub owners: Vec<SplintId>,
    /// Agents whose message this host signed for, on an address there their owner signed.
    #[serde(default)]
    pub hosts: Vec<ListedHost>,
    /// Anyone this agent has written to before.
    #[serde(default)]
    pub past: bool,
}

impl InboundFilter {
    fn is_empty(&self) -> bool {
        self.owners.is_empty() && self.hosts.is_empty() && !self.past
    }

    fn fits(&self, sender: &Sender) -> bool {
        let owner = sender
            .owner
            .is_some_and(|owner| self.owners.contains(owner));
        let host = sender
            .host
            .is_some_and(|host| self.hosts.iter().any(|listed| listed.domain == host));
        owner || host || (self.past && sender.met)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    pub from: InboundFrom,
    #[serde(default)]
    pub filter: InboundFilter,
    /// What someone let in this way may use. Contacts and invitations have their own.
    #[serde(default)]
    pub types: Vec<InteractionType>,
    /// Whether they may send words they chose, which is off unless the owner turns it on.
    #[serde(default)]
    pub text: bool,
    pub strangers: UnknownSenders,
}

/// Whom this agent may start something with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outbound {
    /// Only its contacts. It can still answer within an interaction someone let in started.
    #[default]
    Contacts,
    /// Also anyone `inbound` let in who has written to it, so it can follow up.
    Replies,
}

/// What a contact gets that this agent agreed on with another agent by itself: an invite one signed
/// and the other accepted, with no owner's signature on it. The owner turns this on, and Signet and the
/// host each check the two agents' signatures before anyone counts as one. Rules without it give these
/// contacts nothing until their owner signs them in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agreed {
    /// Types the owner approved for all of them, which may be none.
    pub types: Vec<InteractionType>,
    pub text: bool,
    /// Whether their agent and this one may agree types between themselves with `type/1`, which no
    /// owner signs. On unless the owner turns it off.
    #[serde(default = "super::on")]
    pub agree_types: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reach {
    pub inbound: Inbound,
    pub outbound: Outbound,
    /// Off unless it's there, so rules signed before it existed don't widen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreed: Option<Agreed>,
}

impl Default for Reach {
    fn default() -> Self {
        Self {
            inbound: Inbound {
                from: InboundFrom::Contacts,
                filter: InboundFilter::default(),
                types: Vec::new(),
                text: false,
                strangers: UnknownSenders::Quarantine,
            },
            outbound: Outbound::Contacts,
            agreed: None,
        }
    }
}

/// What a reader knows about a sender. The owner comes from a statement the sender's owner signed, the
/// host from that host's own signature under the key the rules name, so nobody else can claim either,
/// and `met` from the reader's own record. `unconfirmed` is from the owner's ID itself, which anyone
/// can check, so a host can't add or hide it.
#[derive(Clone, Copy, Debug)]
pub struct Sender<'a> {
    pub agent: &'a SplintId,
    pub owner: Option<&'a SplintId>,
    pub host: Option<&'a str>,
    pub met: bool,
    /// They act for an owner who hasn't confirmed yet: only an owner open to anyone hears from them,
    /// unless an owner named them, and nobody holds them for their owner to judge.
    pub unconfirmed: bool,
    /// This agent and they agreed to be contacts, an invite one signed and the other accepted, by the
    /// reader's own record of a pair whose signatures it checked. Nothing the sender sends can set it.
    pub agreed: bool,
}

impl<'a> Sender<'a> {
    /// A sender known only by the ID that signed, which fits no filter.
    pub fn only(agent: &'a SplintId) -> Self {
        Self {
            agent,
            owner: None,
            host: None,
            met: false,
            unconfirmed: false,
            agreed: false,
        }
    }
}

impl Reach {
    /// Whether this setting lets the sender in. An owner who lets people in without naming a type or
    /// turning on words lets nobody in, because they'd have nothing to use: someone let in this way
    /// can't agree a type of their own.
    pub fn lets_in(&self, sender: &Sender) -> bool {
        let inbound = &self.inbound;
        let fits = match inbound.from {
            InboundFrom::Contacts => false,
            InboundFrom::Open => true,
            // A filter names owners and hosts it knows, and nobody has confirmed this one.
            InboundFrom::Filter => !sender.unconfirmed && inbound.filter.fits(sender),
        };
        fits && (!inbound.types.is_empty() || inbound.text)
    }

    /// Every part of a setting means something, so no reader has to guess what an unused part does.
    pub(super) fn check(&self) -> Result<(), Error> {
        let inbound = &self.inbound;
        let filter = &inbound.filter;
        let shape_fits = match inbound.from {
            InboundFrom::Contacts => filter.is_empty() && inbound.types.is_empty() && !inbound.text,
            InboundFrom::Open => filter.is_empty() && (!inbound.types.is_empty() || inbound.text),
            InboundFrom::Filter => {
                !filter.is_empty() && (!inbound.types.is_empty() || inbound.text)
            }
        };
        let sizes_fit = filter.owners.len() <= MAX_FILTER_ENTRIES
            && filter.hosts.len() <= MAX_FILTER_ENTRIES
            && inbound.types.len() <= MAX_REACH_TYPES;
        let hosts_fit = filter.hosts.iter().all(|host| {
            parse_address(&format!("x~{}", host.domain)).is_ok()
                && PublicKey::from_encoded(&host.key).is_ok()
        });
        // A type named twice would leave a reader guessing whether the owner meant something by it. Core's
        // own types aren't the owner's to name: words are `text`, and agreeing types `agree_types`.
        let agreed_fits = self.agreed.as_ref().is_none_or(|agreed| {
            let mut types: Vec<&InteractionType> = agreed.types.iter().collect();
            types.sort();
            types.dedup();
            let named_well = agreed.types.iter().all(InteractionType::is_agreed);
            agreed.types.len() <= MAX_REACH_TYPES && types.len() == agreed.types.len() && named_well
        });
        let inbound_named_well = inbound.types.iter().all(InteractionType::is_agreed);
        if shape_fits && sizes_fit && hosts_fit && agreed_fits && inbound_named_well {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SigningKey, test_identity};

    fn someone() -> SplintId {
        test_identity(&SigningKey::generate().unwrap()).id().clone()
    }

    fn a_host(domain: &str) -> ListedHost {
        ListedHost {
            domain: domain.to_owned(),
            key: SigningKey::generate().unwrap().public_key().encoded(),
        }
    }

    fn quote() -> InteractionType {
        crate::requests::example("quote/1")
    }

    fn reach(from: InboundFrom, filter: InboundFilter) -> Reach {
        Reach {
            inbound: Inbound {
                from,
                filter,
                types: vec![quote()],
                text: false,
                strangers: UnknownSenders::Quarantine,
            },
            outbound: Outbound::Contacts,
            agreed: None,
        }
    }

    #[test]
    fn a_filter_lets_in_by_owner_host_or_a_past_exchange_and_nothing_a_sender_says() {
        let partner = someone();
        let filter = InboundFilter {
            owners: vec![partner.clone()],
            hosts: vec![a_host("corp.example")],
            past: true,
        };
        let filtered = reach(InboundFrom::Filter, filter);
        let agent = someone();
        let stranger = someone();
        let by = |owner, host, met| Sender {
            agent: &agent,
            owner,
            host,
            met,
            unconfirmed: false,
            agreed: false,
        };
        assert!(filtered.lets_in(&by(Some(&partner), None, false)));
        assert!(filtered.lets_in(&by(None, Some("corp.example"), false)));
        assert!(filtered.lets_in(&by(None, None, true)));
        assert!(!filtered.lets_in(&by(Some(&stranger), Some("other.example"), false)));
        assert!(!filtered.lets_in(&Sender::only(&agent)));

        let open = reach(InboundFrom::Open, InboundFilter::default());
        assert!(open.lets_in(&Sender::only(&agent)));
        assert!(!Reach::default().lets_in(&by(Some(&partner), None, true)));
    }

    #[test]
    fn a_setting_with_a_part_that_means_nothing_is_refused() {
        assert!(Reach::default().check().is_ok());
        assert!(
            reach(InboundFrom::Open, InboundFilter::default())
                .check()
                .is_ok()
        );
        let mut no_types = reach(InboundFrom::Open, InboundFilter::default());
        no_types.inbound.types.clear();
        assert!(no_types.check().is_err());
        assert!(
            reach(InboundFrom::Filter, InboundFilter::default())
                .check()
                .is_err()
        );
        let past = InboundFilter {
            past: true,
            ..InboundFilter::default()
        };
        assert!(reach(InboundFrom::Open, past.clone()).check().is_err());
        assert!(reach(InboundFrom::Filter, past).check().is_ok());
        let mut contacts_with_types = Reach::default();
        contacts_with_types.inbound.types = vec![quote()];
        assert!(contacts_with_types.check().is_err());
        let bad_host = InboundFilter {
            hosts: vec![a_host("corp.example/path")],
            ..InboundFilter::default()
        };
        assert!(reach(InboundFrom::Filter, bad_host).check().is_err());
        let no_key = InboundFilter {
            hosts: vec![ListedHost {
                domain: "corp.example".to_owned(),
                key: "not-a-key".to_owned(),
            }],
            ..InboundFilter::default()
        };
        assert!(reach(InboundFrom::Filter, no_key).check().is_err());
    }
}

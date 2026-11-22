//! Interactions, as one agent's Signet runs them.
//!
//! Signet keeps each one's signed steps and recomputes its state by walking them on every read,
//! so nothing a host stores or says can change what the agent or its owner is told.
//!
//! Who a contact is comes from the rules this agent's owner signed, and never from a host. Who it acts
//! for is pinned when first found, and only a release by that owner moves it. That's what stops a
//! hostile host forging a result: it can answer a lookup with whatever it likes, but it can't change
//! an ID the owner signed, or sign as that ID's owner.

pub mod agent_api;
pub mod held_opens;
pub mod owner_api;
pub mod payments;
pub mod person_text;
pub mod refusals;
pub mod store;
pub mod sync;
pub mod types;

use std::sync::atomic::AtomicI64;

use splint_core::requests::{Parties, Party, Side};
use splint_core::rules::RulesContact;
use splint_core::{Identity, SplintId, parse_address};

use crate::Signet;
use crate::host_client::HostError;
use crate::requests::held_opens::HeldOpens;
use crate::requests::person_text::Waiting;
use crate::requests::refusals::Refusals;
use crate::requests::store::{Record, Store};

pub struct Requests {
    pub store: Store,
    pub person_texts: Waiting,
    /// Where this agent's owner gets paid, as they signed it.
    pub where_paid: payments::WherePaid,
    pub held_opens: HeldOpens,
    pub owner_token: Option<String>,
    /// The types agreed with each contact. Core's own come with every chain.
    pub types: types::AgreedTypes,
    pub refused: Refusals,
    /// The last guest's step read from the host. A restart reads them again, and a repeat is a replay.
    pub guest_steps_read: AtomicI64,
}

impl Requests {
    /// Run once as Signet starts: squares what it holds for its owner with what it sent.
    pub async fn settle_held_opens(&self) -> Result<(), HostError> {
        let records = self.store.lock().await;
        self.held_opens.settle_what_went(&records).await
    }
}

/// A contact found by address or agent, with its identity pinned.
pub struct Contact {
    pub address: String,
    pub agent: Identity,
    pub owner: Identity,
    pub binding: String,
    /// What the owner's rules say about them, as of this lookup.
    pub rule: RulesContact,
}

/// A contact by the address an agent named. An address the owner's rules don't list isn't a contact.
pub async fn contact_at(signet: &Signet, address: &str) -> Result<Option<Contact>, HostError> {
    let Some(named) = signet.rules.contact_at(address).await else {
        return Ok(None);
    };
    let Ok((handle, domain)) = parse_address(address) else {
        return Ok(None);
    };
    let found = signet
        .contacts
        .named_by_rules(
            &signet.lookup(&signet.who()),
            address,
            handle,
            domain,
            &named.agent,
        )
        .await?;
    Ok(Some(Contact {
        address: address.to_owned(),
        agent: found.agent,
        owner: found.owner,
        binding: found.binding,
        rule: named,
    }))
}

/// The same, having first asked their host what it says now, for starting something new with them,
/// so what's pinned doesn't lag behind a transfer. Nothing is looked up for an address the rules don't
/// list.
pub async fn fresh_contact_at(
    signet: &Signet,
    address: &str,
) -> Result<Option<Contact>, HostError> {
    if signet.rules.contact_at(address).await.is_some()
        && let Ok((handle, domain)) = parse_address(address)
    {
        signet
            .contacts
            .refresh(&signet.lookup(&signet.who()), address, handle, domain)
            .await?;
    }
    contact_at(signet, address).await
}

/// A contact by the agent that signed something. `None` means it's no contact of ours. An error
/// means a contact couldn't be looked up, so this agent might be that contact: nobody knows yet.
pub async fn contact_of(signet: &Signet, agent: &SplintId) -> Result<Option<Contact>, HostError> {
    let Some(named) = signet.rules.contact_of(agent).await else {
        return Ok(None);
    };
    contact_at(signet, &named.address).await
}

/// The two parties to a record's request, from what was pinned when it started.
pub fn parties_of(signet: &Signet, record: &Record) -> Result<Parties, HostError> {
    let who = signet.who();
    let mine = Party {
        agent: who.identity.clone(),
        owner: who.owner.clone(),
        binding: who.binding.clone(),
    };
    if record.guest {
        return Ok(Parties {
            requester: mine,
            recipient: Party::guest(record.peer_agent()?),
        });
    }
    let known = &signet.contacts.known;
    let theirs = Party {
        agent: known.newest_or_same(&Identity::from_encoded(&record.peer_identity)?),
        owner: known.newest_or_same(&Identity::from_encoded(&record.peer_owner)?),
        binding: record.peer_binding.clone(),
    };
    Ok(match record.role {
        Side::Requester => Parties {
            requester: mine,
            recipient: theirs,
        },
        Side::Recipient => Parties {
            requester: theirs,
            recipient: mine,
        },
    })
}

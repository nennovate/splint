//! How two agents get to reach each other: each owner runs a line the other gave them. The line names
//! the agent's ID, which hashes its keys, so no host has to be believed about who a first contact is,
//! and there's nothing secret in it.

use splint_core::requests::InteractionType;
use splint_core::rules::{ContactStatus, InboundFrom, PinnedBy, RulesContact, RulesDraft};
use splint_core::{SplintId, parse_address};

use crate::authorize;
use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::host_calls::HostCalls;
use crate::owner_key::OwnerKey;
use crate::owner_side::{self, OwnerSide};
use crate::rules;
use crate::signet_api::RulesAtHost;

/// Someone blocked who was never a contact gets an address that can't be anyone's, as the one they
/// claim is only their word, and may be a real contact's.
const BLOCKED_DOMAIN: &str = "blocked.invalid";
const ID_PREFIX_CHARS: usize = "splint1".len();
const BLOCKED_HANDLE_ID_CHARS: usize = 32;

/// What someone else runs to add this agent.
pub fn line_for(address: &str, agent: &SplintId) -> String {
    format!("splint add {address} {agent}")
}

fn contact(
    address: &str,
    agent: SplintId,
    types: Vec<InteractionType>,
) -> Result<RulesContact, Failure> {
    let (handle, _) = parse_address(address).map_err(Failure::not_an_address)?;
    Ok(RulesContact {
        agent,
        address: address.to_owned(),
        label: handle.to_owned(),
        status: ContactStatus::Allowed,
        types,
        // Running someone's line is the owner saying yes to their agent's words, and to the two agents
        // agreeing what kinds of request they use.
        text: true,
        agree_types: true,
        pinned_by: PinnedBy::Owner,
    })
}

pub fn id_from_line(id: &str) -> Result<SplintId, Failure> {
    serde_json::from_value(serde_json::Value::String(id.to_owned()))
        .ok()
        .filter(SplintId::is_well_formed)
        .ok_or_else(|| {
            Failure::refused("that isn't an agent's ID: the line has one after the address")
        })
}

/// Whether this is new, and so has rules to sign. A line that fits nothing is refused.
pub fn with_contact(
    draft: &mut RulesDraft,
    own: (&str, &SplintId),
    address: &str,
    id: SplintId,
    types: Vec<InteractionType>,
) -> Result<bool, Failure> {
    if &id == own.1 || address == own.0 {
        return Err(Failure::refused(
            "that's your own line. Give it to the person you want your agent to reach",
        ));
    }
    let new = contact(address, id, types)?;
    if let Some(found) = draft
        .contacts
        .iter_mut()
        .find(|known| known.address == new.address || known.agent == new.agent)
    {
        // Named with nothing to use is how `remove` takes out one the agent added, so this adds them
        // back. A block stays: lifting it is its own choice.
        if found.address == new.address && found.agent == new.agent && is_taken_out(found) {
            *found = new;
            return Ok(true);
        }
        if found.address == new.address && found.agent == new.agent {
            return Ok(false);
        }
        // One of these is a changed agent or a wrong line, and which isn't for this command to guess.
        return Err(Failure::refused(format!(
            "you already have {} as {}, which doesn't fit that line",
            found.address.escape_debug(),
            found.agent,
        )));
    }
    draft.contacts.push(new);
    Ok(true)
}

/// An agent whose owner hasn't confirmed adds someone by address alone, going by what that address's
/// host says, which the agent's Signet checks again. Its owner hasn't named anyone, and whoever it
/// writes to decides for themselves whether to hear from it. An owner goes by a line, as above.
pub async fn add_found(home: &Home, address: &str) -> Result<String, Failure> {
    let address = &HostCalls::name_form(address).await?;
    let (installed, _) = Installed::require_owner_here(home, "name a contact")?;
    if !OwnerKey::new(home).is_stand_in() {
        return Err(Failure::refused(
            "an owner adds a contact by their line, with their ID after the address",
        ));
    }
    let (_, domain) = parse_address(address).map_err(Failure::not_an_address)?;
    let found = HostCalls::new(domain)?.resolve(address).await?;
    drop(installed);
    add(home, address, found.agent_id.as_str()).await?;
    Ok(format!(
        "{address} is one of your contacts now, as {id}. If its owner lets anyone reach it, you can \
         write to it at once, for the kinds of interaction it takes. If not, what you send goes \
         nowhere: splint invite {address} asks them first, and replaces splint add.",
        id = found.agent_id,
    ))
}

pub async fn add(home: &Home, address: &str, id: &str) -> Result<String, Failure> {
    let address = &HostCalls::name_form(address).await?;
    if let Some(elsewhere) = authorize::the_agent_elsewhere(home)? {
        return authorize::add(home, &elsewhere, address, id).await;
    }
    let (installed, agent) = Installed::require_owner_here(home, "name a contact")?;
    let id = id_from_line(id)?;
    let mut signed = owner_side::rules_beside(home, &installed, &agent)
        .await?
        .ok_or_else(|| {
            Failure::refused(
                "there are no rules yet: they're signed when the owner sets up their controls for this agent",
            )
        })?;
    let own = (installed.address.as_str(), &agent);
    // The two agents agree what they use, so the owner names no type here.
    if !with_contact(&mut signed.draft, own, address, id, Vec::new())? {
        return Ok(format!(
            "{address} is already one of your agent's contacts."
        ));
    }
    let at_host = rules::sign_and_apply(home, &installed, &agent, signed.draft).await?;
    let said = format!(
        "{address} is now one of your agent's contacts. It can write to them once they've run your \
         line:\n\n  {}",
        line_for(&installed.address, &agent),
    );
    Ok(rules::told(said, at_host))
}

/// Takes a contact out, as the owner, with the agent beside this device or elsewhere. One the rules name
/// goes from them. One the agent agreed with by itself is named with nothing to use, which wins over
/// what the two agents agreed, as Remove on the controls page does.
pub async fn remove(home: &Home, side: &OwnerSide, address: &str) -> Result<String, Failure> {
    let mut signed = side.rules(home).await?;
    let agreed = if signed
        .draft
        .contacts
        .iter()
        .any(|known| known.address == address)
    {
        None
    } else {
        side.agreed_at(home, address).await?
    };
    let add_back = |id: &SplintId| add_back_line(side, address, id);
    let taken = match taken_out(&mut signed.draft.contacts, address, agreed, &add_back) {
        Ok(taken) => taken,
        Err(TakeOut::Refused(failure)) => return Err(failure),
        Err(TakeOut::Blocked) => {
            // Dropping the block would let them back in, by the agents' agreement or the reach setting.
            return Err(Failure::refused(format!(
                "you blocked {address}, and removing them would lift that block. To let them back in, \
                 unblock them on your page: {}",
                page_line(side)
            )));
        }
        Err(TakeOut::NotFound) if side.came_by_invitation(home, address).await? => {
            // Named with nothing, they'd still come in by the invitation they redeemed.
            return Err(Failure::refused(format!(
                "{address} came in by an invitation you gave, which lets them in until it ends, \
                 whatever else your rules say of them. To keep them out, block them on your page: {}",
                page_line(side)
            )));
        }
        Err(TakeOut::NotFound) if side.is_elsewhere() => {
            return Err(Failure::refused(
                "that address isn't one of your agent's contacts. One it added just now can take a \
                 minute to show here, so try again then",
            ));
        }
        Err(TakeOut::NotFound) => {
            return Err(Failure::refused(
                "that address isn't one of your agent's contacts",
            ));
        }
    };
    let reach = signed.draft.reach.inbound.from;
    let at_host = side.apply_rules(home, signed.draft).await?;
    let who = if side.is_elsewhere() {
        side.address()
    } else {
        "your agent"
    };
    let whose = if taken.added {
        format!("{address}, whom {who} added as a contact by itself,")
    } else {
        address.to_owned()
    };
    let line = add_back_line(side, address, &taken.agent);
    let said = match reach {
        InboundFrom::Contacts => format!(
            "{whose} can't reach {who} now, nor it them. What they sent before waits unread, and an \
             open request with them can still be cancelled. To add them back:\n\n  {line}"
        ),
        // They're a stranger again, which this reach setting may still let in.
        InboundFrom::Open | InboundFrom::Filter => format!(
            "{whose} is no longer a contact of {who}, though your reach setting lets in {}, so they \
             may still reach it as a stranger. An open request with them can still be cancelled. To \
             add them back:\n\n  {line}",
            if reach == InboundFrom::Open {
                "anyone"
            } else {
                "whoever fits its filter"
            }
        ),
    };
    Ok(rules::told(said, at_host))
}

struct Taken {
    agent: SplintId,
    /// One the agent agreed with by itself, now named with nothing.
    added: bool,
}

enum TakeOut {
    Refused(Failure),
    Blocked,
    NotFound,
}

/// What `remove` changes in the rules' contacts: `agreed` is whom the agent agreed with by itself at
/// `address`, read only when the rules don't name that address.
fn taken_out(
    contacts: &mut Vec<RulesContact>,
    address: &str,
    agreed: Option<SplintId>,
    add_back: &dyn Fn(&SplintId) -> String,
) -> Result<Taken, TakeOut> {
    if let Some(known) = contacts.iter().find(|known| known.address == address) {
        let agent = known.agent.clone();
        if known.status == ContactStatus::Blocked {
            return Err(TakeOut::Blocked);
        }
        // Taking out again would clear what took them out, and let the agents' own agreement back in.
        if is_taken_out(known) {
            return Err(TakeOut::Refused(Failure::refused(format!(
                "that address isn't one of your agent's contacts: you took them out already. {} \
                 adds them back",
                add_back(&agent)
            ))));
        }
        contacts.retain(|known| known.address != address);
        return Ok(Taken {
            agent,
            added: false,
        });
    }
    let agent = agreed.ok_or(TakeOut::NotFound)?;
    // The rules allow one entry an agent, and a block under another address must stay as it is.
    if let Some(named) = contacts.iter().find(|known| known.agent == agent) {
        let as_what = if named.status == ContactStatus::Blocked {
            "blocked them already"
        } else {
            "name that agent at another address"
        };
        return Err(TakeOut::Refused(Failure::refused(format!(
            "your rules {as_what}, {}, so nothing was signed",
            if was_never_a_contact(named) {
                "as someone who was never a contact".to_owned()
            } else {
                format!("as {}", named.address.escape_debug())
            }
        ))));
    }
    let mut removed = contact(address, agent.clone(), Vec::new()).map_err(TakeOut::Refused)?;
    removed.text = false;
    removed.agree_types = false;
    contacts.push(removed);
    Ok(Taken { agent, added: true })
}

fn add_back_line(side: &OwnerSide, address: &str, id: &SplintId) -> String {
    if side.is_elsewhere() {
        format!("splint for {} add {address} {id}", side.address())
    } else {
        line_for(address, id)
    }
}

fn page_line(side: &OwnerSide) -> String {
    if side.is_elsewhere() {
        format!("splint for {} page", side.address())
    } else {
        "splint page".to_owned()
    }
}

/// Named with nothing to use and not blocked, which is how `remove` takes out one the agent added.
fn is_taken_out(contact: &RulesContact) -> bool {
    contact.status == ContactStatus::Allowed
        && contact.types.is_empty()
        && !contact.agree_types
        && !contact.text
}

pub fn was_never_a_contact(contact: &RulesContact) -> bool {
    parse_address(&contact.address).is_ok_and(|(_, domain)| domain == BLOCKED_DOMAIN)
}

fn blocked_stranger(agent: &SplintId, claimed: Option<&str>) -> RulesContact {
    let id: String = agent
        .as_str()
        .chars()
        .skip(ID_PREFIX_CHARS)
        .take(BLOCKED_HANDLE_ID_CHARS)
        .collect();
    RulesContact {
        agent: agent.clone(),
        address: format!("blocked-{id}~{BLOCKED_DOMAIN}"),
        label: claimed.unwrap_or(&id).to_owned(),
        status: ContactStatus::Blocked,
        types: Vec::new(),
        text: false,
        agree_types: false,
        pinned_by: PinnedBy::Owner,
    }
}

/// Signs the owner's block into the rules. A contact keeps what they had, so it can be undone.
pub async fn block(
    home: &Home,
    side: &OwnerSide,
    who: &SplintId,
    claimed: Option<&str>,
) -> Result<Option<RulesAtHost>, Failure> {
    let mut signed = side.rules(home).await?;
    let contacts = &mut signed.draft.contacts;
    match contacts.iter_mut().find(|known| &known.agent == who) {
        Some(known) => known.status = ContactStatus::Blocked,
        None => contacts.push(blocked_stranger(who, claimed)),
    }
    side.apply_rules(home, signed.draft).await
}

/// Undoes a block on a contact. Someone who was never one can be forgotten instead, which makes them
/// a stranger again, as there are no types or address here to give back.
pub async fn unblock(
    home: &Home,
    side: &OwnerSide,
    who: &SplintId,
) -> Result<Option<RulesAtHost>, Failure> {
    let mut signed = side.rules(home).await?;
    let known = signed
        .draft
        .contacts
        .iter_mut()
        .find(|known| &known.agent == who)
        .filter(|known| !was_never_a_contact(known))
        .ok_or_else(|| Failure::refused("that's not a blocked contact"))?;
    known.status = ContactStatus::Allowed;
    side.apply_rules(home, signed.draft).await
}

pub async fn forget(
    home: &Home,
    side: &OwnerSide,
    who: &SplintId,
) -> Result<Option<RulesAtHost>, Failure> {
    let mut signed = side.rules(home).await?;
    let before = signed.draft.contacts.len();
    signed.draft.contacts.retain(|known| &known.agent != who);
    if signed.draft.contacts.len() == before {
        return Err(Failure::refused("that's not in your agent's contacts"));
    }
    side.apply_rules(home, signed.draft).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blocked_stranger_can_be_written_into_rules_and_claims_no_real_address() {
        let id: SplintId = serde_json::from_value(serde_json::Value::String(format!(
            "splint1{}",
            "a".repeat(64)
        )))
        .unwrap();
        let blocked = blocked_stranger(&id, Some("ben~host.example"));
        assert!(
            parse_address(&blocked.address).is_ok(),
            "{}",
            blocked.address
        );
        assert!(was_never_a_contact(&blocked));
        assert_eq!(blocked.label, "ben~host.example");
        assert_eq!(blocked.status, ContactStatus::Blocked);
        let real = contact("ben~host.example", id, Vec::new()).unwrap();
        assert!(!was_never_a_contact(&real));
    }

    /// Bugs caught: `splint remove` on a blocked contact dropped the block, letting them back in by the
    /// agents' agreement or the reach setting, and naming an agent the rules already had at another
    /// address, a block among them, gave a second entry the rules check refuses with no clear word.
    #[test]
    fn remove_never_lifts_a_block_or_names_an_agent_twice() {
        let id: SplintId = serde_json::from_value(serde_json::Value::String(format!(
            "splint1{}",
            "b".repeat(64)
        )))
        .unwrap();
        let mut blocked = contact("cal~host.example", id.clone(), Vec::new()).unwrap();
        blocked.status = ContactStatus::Blocked;
        let none = |_: &SplintId| String::new();
        let cases = [
            (blocked, "cal~host.example", None),
            (
                blocked_stranger(&id, Some("cal~host.example")),
                "cal~host.example",
                Some(id.clone()),
            ),
            (
                contact("cal~old.example", id.clone(), Vec::new()).unwrap(),
                "cal~host.example",
                Some(id.clone()),
            ),
        ];
        for (entry, address, agreed) in cases {
            let mut contacts = vec![entry.clone()];
            let refused = taken_out(&mut contacts, address, agreed, &none).is_err();
            assert!(refused, "{entry:?}");
            assert_eq!(contacts.len(), 1);
            assert_eq!(contacts[0].status, entry.status);
            assert_eq!(contacts[0].address, entry.address);
        }
    }
}

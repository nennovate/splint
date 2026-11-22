//! The rules this owner last signed, which each change starts from, since rules are replaced whole.

use std::fs;
use std::io::ErrorKind;

use serde::{Deserialize, Serialize};
use splint_core::Sealing;
use splint_core::changes::{ChangeResponse, ChangeRules};
use splint_core::host_api::HeldRules;
use splint_core::requests::{InteractionType, with_hidden_shown};
use splint_core::rules::{
    Agreed, ContactStatus, InboundFrom, Level, PinnedBy, Reach, RulesContact, RulesDraft,
    RulesLimits, VerifiedRules,
};
use splint_core::{Identity, SplintId, parse_address, unix_now};

use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::owner_key::OwnerKey;
use crate::secrets::write_private;
use crate::signet_api::{Held, RulesAtHost, SignetApi};

/// Nobody's a contact, and what new people send waits for the owner, so the safe rules are the ones
/// that need no choices. Contacts the agent agrees with by itself, an invite one signed and the other
/// accepted, may send words and agree types with it. Anything carrying a value with one of them, such
/// as a price, waits for the owner at every level, and so does a yes to it, so a fooled agent can't
/// commit its owner to someone it just met. Nenye chose this on 2026-11-11, over leaving out types with
/// a value or a result nobody signs, and on 2026-11-14 that agents agree types in conversation, with no
/// owner naming any. These limits are the protocol's defaults.
pub fn first_rules() -> RulesDraft {
    let agreed = Some(Agreed {
        types: Vec::new(),
        text: true,
        agree_types: true,
    });
    RulesDraft {
        paused: false,
        reach: Reach {
            agreed,
            ..Reach::default()
        },
        permissions: Default::default(),
        // A contact's agent given a new key by its own owner, as after a recovery, carries on and the
        // owner is told, rather than every contact's owner being asked. A new owner, or a new sign-in
        // to their ID, is still asked about. Nenye's call of 2026-11-14.
        changes: ChangeRules {
            key: ChangeResponse::Continue,
            ..ChangeRules::default()
        },
        sealing: Default::default(),
        delegation: None,
        ends_at: None,
        contacts: Vec::new(),
        invites: Vec::new(),
        limits: RulesLimits {
            new_requests_per_contact_per_day: 20,
            open_requests_per_contact: 3,
            open_approvals: 10,
            new_from_others_per_day: 250,
            texts_per_contact_per_day: 100,
            agreed_texts_per_day: None,
            agreed_new_requests_per_day: None,
            sends_per_hour: None,
            sends_per_day: None,
        },
    }
}

/// What contacts the agent adds by itself get under these rules, said before the owner chooses
/// anything, so what they sign is what they were told.
pub fn agreed_in_words(draft: &RulesDraft) -> String {
    let Some(agreed) = &draft.reach.agreed else {
        return "Contacts your agent adds by itself: none. Whoever it agrees with waits for you."
            .to_owned();
    };
    // Ask me first lets in only contacts the owner chose, whatever the setting says.
    if !draft.lets_agreed_in() {
        return "Contacts your agent adds by itself: none at Ask me first, where only contacts you \
                chose can reach it. It invites nobody, and you add contacts yourself."
            .to_owned();
    }
    let types: Vec<&str> = agreed.types.iter().map(InteractionType::name).collect();
    let uses = match (agreed.agree_types, types.is_empty()) {
        (true, true) => "agree between them what kinds of request they use".to_owned(),
        (true, false) => format!(
            "use {} and agree other kinds between them",
            types.join(", ")
        ),
        (false, true) => "use no kind of request".to_owned(),
        (false, false) => format!("use {}", types.join(", ")),
    };
    format!(
        "Contacts your agent adds by itself: when it and another agent agree to be contacts, by an \
         invite either way, they can reach each other at once, up to 100 new ones a day, and talk{} and \
         {uses}. Until you approve one, nothing with money is agreed with them without your yes, \
         a price it quotes included. splint status marks each one, and splint \
         remove takes one out.",
        if agreed.text {
            ", in their own words too,"
        } else {
            ""
        },
    )
}

/// A contact the agent agreed with by itself, by what the two agents signed, checked on this device.
pub struct Added {
    pub agent: SplintId,
    pub address: String,
}

/// The contacts the agent agreed with by itself that `new` rules would take out, where `old` let them
/// in, as Ask me first or turning those contacts off does. Only the pairs the two agents
/// signed count, checked here, since a Signet can say anything beside them.
pub fn added_taken_out(
    old: &RulesDraft,
    new: &RulesDraft,
    held: &[Held],
    own: &SplintId,
) -> Vec<Added> {
    if !old.lets_agreed_in() || new.lets_agreed_in() {
        return Vec::new();
    }
    let mut taken: Vec<Added> = Vec::new();
    for pair in held
        .iter()
        .filter(|one| one.kind == "agreed")
        .filter_map(|one| one.invite.as_ref()?.verify(own).ok())
    {
        // One the rules name either way already has the owner's word.
        let named = new
            .contacts
            .iter()
            .any(|known| known.agent == pair.agent || known.address == pair.address);
        if !named && !taken.iter().any(|added| added.agent == pair.agent) {
            taken.push(Added {
                agent: pair.agent,
                address: pair.address,
            });
        }
    }
    taken
}

/// Names them in `new` as the owner's own, from the invite both agents signed, with what `old` gave
/// contacts the agent adds, so they keep what they had whatever the level.
pub fn keep_added(new: &mut RulesDraft, old: &RulesDraft, kept: &[Added]) -> Result<(), Failure> {
    let Some(agreed) = &old.reach.agreed else {
        return Ok(());
    };
    for one in kept {
        let (handle, _) = parse_address(&one.address).map_err(Failure::not_an_address)?;
        new.contacts.push(RulesContact {
            agent: one.agent.clone(),
            address: one.address.clone(),
            label: handle.to_owned(),
            status: ContactStatus::Allowed,
            types: agreed.types.clone(),
            text: agreed.text,
            agree_types: agreed.agree_types,
            pinned_by: PinnedBy::Invite,
        });
    }
    Ok(())
}

/// Why `new` rules take out the contacts the agent added by itself, in the owner's terms.
pub fn why_added_go(new: &RulesDraft) -> &'static str {
    if new.reach.agreed.is_some() {
        "At Ask me first, only contacts you chose can reach your agent"
    } else {
        "With contacts your agent adds turned off, only contacts you chose can reach it"
    }
}

/// What keeping or dropping them means, said before anything's signed. Dropping is chosen unless the
/// owner says otherwise, as keeping names them in the owner's rules, so they count as the owner's own,
/// approved contacts, and only the owner's choice should make them so.
pub fn keep_or_drop_words(new: &RulesDraft) -> String {
    let reach = if new.reach.agreed.is_some() {
        "under Ask me first"
    } else {
        "with contacts your agent adds turned off"
    };
    format!(
        "Keep them, and they become your own contacts, as if you'd added them: they can reach your \
         agent {reach}, and amounts with them are treated like amounts with anyone you added, rather \
         than always waiting for you. Drop them, and they're taken out, and you can add any of them \
         back later. They're dropped unless you choose to keep them."
    )
}

/// A setting that lets more through than usual, for the owner's pages to say beside it in fixed words.
/// It's their choice, and nothing here changes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Risky {
    /// Anyone, or anyone a filter fits, can reach the agent without being a contact.
    OpenToAnyone,
    /// Their device says yes to everything it may by itself, under the protocol's limits.
    FullAuto,
    /// What passes with contacts who also chose unsealed can be read by both hosts.
    SealingOff,
    /// People who aren't contacts may send the agent words they chose.
    FreeTextWithStrangers,
}

/// The settings in `draft` that let more through than usual, in the order the pages show them.
pub fn risky_settings(draft: &RulesDraft) -> Vec<Risky> {
    let inbound = &draft.reach.inbound;
    let open = inbound.from != InboundFrom::Contacts;
    [
        (open, Risky::OpenToAnyone),
        (draft.permissions.level == Level::FullAuto, Risky::FullAuto),
        (draft.sealing == Sealing::Unsealed, Risky::SealingOff),
        (open && inbound.text, Risky::FreeTextWithStrangers),
    ]
    .into_iter()
    .filter_map(|(on, risky)| on.then_some(risky))
    .collect()
}

/// Their addresses, for an owner to read before they sign. An address is the other side's word, so
/// anything hidden in it shows.
pub fn added_addresses(added: &[Added]) -> String {
    added
        .iter()
        .map(|one| with_hidden_shown(&one.address))
        .collect::<Vec<_>>()
        .join(", ")
}

/// For signing saved rules again, so an invitation that's over doesn't go on being signed.
pub fn without_ended_invitations(mut draft: RulesDraft, now: u64) -> RulesDraft {
    draft.invites.retain(|invite| invite.expires_at > now);
    draft
}

#[derive(Serialize, Deserialize)]
pub struct Signed {
    pub draft: RulesDraft,
    pub signed_at: u64,
    /// The owner's `seq` on them, so newer rules from another of the owner's devices show as newer.
    /// Rules written down before it was kept read 0, so whatever's in force is taken over them.
    #[serde(default)]
    pub seq: u64,
}

/// Rules are replaced whole, so a change made from a copy that's behind would sign older rules over
/// newer ones another of the owner's devices signed, bringing back a contact they removed.
/// So a change starts from the newest of what the agent's Signet and host hold, checked here as this
/// owner's rules for this agent, and from this device's own only when they're as new. A read that
/// couldn't be made, or holds rules that don't check out, counts as none, and with no read made at all
/// nothing is signed. A host can still hold back newer rules, as it can from the agent, and can't bring
/// back older ones than this device signed.
pub fn newest(
    own: Option<Signed>,
    reads: Vec<Result<HeldRules, Failure>>,
    owner: &Identity,
    agent: &SplintId,
) -> Result<Option<Signed>, Failure> {
    let mut reached = false;
    let mut newest: Option<VerifiedRules> = None;
    for held in reads.into_iter().filter_map(Result::ok) {
        let Some(compact) = held.rules else {
            reached = true;
            continue;
        };
        let Some(rules) = VerifiedRules::reload(&compact, owner)
            .ok()
            .filter(|rules| rules.agent() == agent)
        else {
            continue;
        };
        reached = true;
        if newest
            .as_ref()
            .is_none_or(|known| rules.seq() > known.seq())
        {
            newest = Some(rules);
        }
    }
    if !reached {
        return Err(Failure::refused(
            "couldn't read the rules in force from this agent's Signet or host, so nothing was \
             signed: signing from what this device last had could undo a newer change from another \
             of your devices. Try again once its host answers",
        ));
    }
    Ok(match (own, newest) {
        (Some(own), Some(live)) if live.seq() > own.seq => Some(from_live(&live)),
        // The same rules. What this device wrote down before issue 630 left out the delegation the
        // owner key named in them from its own copy, and a change now names only what its draft does.
        (Some(mut own), Some(live)) if live.seq() == own.seq => {
            own.draft.delegation = live.named_delegation().map(str::to_owned);
            Some(own)
        }
        (Some(own), _) => Some(own),
        (None, live) => live.as_ref().map(from_live),
    })
}

fn from_live(live: &VerifiedRules) -> Signed {
    Signed {
        draft: live.draft(),
        signed_at: unix_now(),
        seq: live.seq(),
    }
}

/// The `seq` this owner signed on these rules, which this device has just signed.
pub fn seq_of(home: &Home, compact: &str) -> Result<u64, Failure> {
    let owner = Identity::from_encoded(&OwnerKey::new(home).existing_identity()?)?;
    VerifiedRules::reload(compact, &owner)
        .map(|rules| rules.seq())
        .map_err(|_| Failure::refused("the owner key signed rules that don't check out"))
}

pub fn last_signed(home: &Home) -> Result<Option<Signed>, Failure> {
    match fs::read(home.rules_file()) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Failure::refused("rules.json in the Splint folder can't be read")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Signs these rules and hands them to Signet. They're written down only once Signet holds them, so a
/// failure leaves the last rules that counted. A host that didn't take them is no failure, since they
/// count in Signet already and Signet keeps offering them, but the owner has to hear of it (issue 411).
pub async fn sign_and_apply(
    home: &Home,
    installed: &Installed,
    agent: &SplintId,
    draft: RulesDraft,
) -> Result<Option<RulesAtHost>, Failure> {
    let api = SignetApi::new(home, installed)?;
    // A cap can name a type the agents agreed, which only their Signet holds.
    let agreed = if draft.permissions.caps.is_empty() {
        Vec::new()
    } else {
        api.schemas().await?
    };
    let compact = OwnerKey::new(home).sign_rules(agent, &draft, &agreed)?;
    let seq = seq_of(home, &compact)?;
    let at_host = api.put_rules(&compact).await?;
    let signed = Signed {
        draft,
        signed_at: unix_now(),
        seq,
    };
    let bytes = serde_json::to_vec(&signed)
        .map_err(|_| Failure::refused("couldn't write down the rules"))?;
    write_private(&home.rules_file(), &bytes)?;
    Ok(at_host)
}

/// What's said after rules are signed, with a note when the host hasn't taken them.
pub fn told(said: impl Into<String>, at_host: Option<RulesAtHost>) -> String {
    let said = said.into();
    match not_at_host(at_host) {
        Some(note) => format!("{said}\n\n{note}"),
        None => said,
    }
}

/// Whether the host said no to the newest rules, as against not having answered yet.
pub fn host_refused(at_host: Option<RulesAtHost>) -> bool {
    matches!(
        at_host,
        Some(RulesAtHost::Refused | RulesAtHost::OtherProtocol | RulesAtHost::OutOfDate)
    )
}

fn not_at_host(at_host: Option<RulesAtHost>) -> Option<String> {
    const HOLDS_OLD: &str = "This agent's Signet goes by them, but its host goes by the last rules it \
                             took, if any, and refuses what the agent sends that those don't allow.";
    let (why, next) = match at_host? {
        RulesAtHost::Taken => return None,
        RulesAtHost::NotYet => (
            "This agent's host hasn't taken these rules yet: it couldn't be reached, or doesn't know \
             this agent yet.",
            "Signet hands them over when it can.",
        ),
        RulesAtHost::Refused => (
            "This agent's host refused these rules.",
            "Signet offers them again every 30 seconds, so a host that's fixed or updated takes them \
             by itself, and splint status says while it hasn't. If it goes on, ask whoever runs the \
             host.",
        ),
        RulesAtHost::OtherProtocol => (
            "This agent's host speaks another Splint protocol, so it couldn't take these rules.",
            "Update splint, or ask whoever runs the host to update it. Signet offers them again by \
             itself, and splint status says while the host hasn't taken them.",
        ),
        RulesAtHost::OutOfDate => (
            "This agent's host holds a later recovery or revocation for it, so it didn't take these \
             rules.",
            "That has to be settled first.",
        ),
    };
    Some(format!("{why} {HOLDS_OLD} {next}"))
}

/// One line for `splint status`, when the host refused the newest rules. Not having reached it yet
/// isn't one, as a Signet that just started hasn't tried.
pub fn status_line(at_host: Option<RulesAtHost>) -> Option<String> {
    let why = match at_host? {
        RulesAtHost::Taken | RulesAtHost::NotYet => return None,
        RulesAtHost::Refused => "refused the newest rules",
        RulesAtHost::OtherProtocol => {
            "speaks another Splint protocol, so it can't take the newest rules"
        }
        RulesAtHost::OutOfDate => {
            "holds a later recovery or revocation, so it didn't take the newest rules"
        }
    };
    Some(format!(
        "Host      {why}, so it goes by the last ones it took, if any, and refuses what this agent \
         sends beyond them. Signet keeps offering them"
    ))
}

#[cfg(test)]
mod tests {
    use splint_core::rules::ContactStatus;
    use splint_core::{RecoveryRule, SealingKey, SigningKey};

    use super::*;

    struct Owner {
        key: SigningKey,
        identity: Identity,
    }

    fn owner() -> Result<Owner, Failure> {
        let key = SigningKey::generate()?;
        let backup = SigningKey::generate()?;
        let identity = Identity::create(
            &key,
            &SealingKey::generate()?.public_key(),
            RecoveryRule::backup_key(&backup.public_key()),
        )?;
        Ok(Owner { key, identity })
    }

    fn with_contact(address: &str, agent: &SplintId) -> RulesDraft {
        let mut draft = first_rules();
        draft.contacts.push(RulesContact {
            agent: agent.clone(),
            address: address.to_owned(),
            label: address.to_owned(),
            status: ContactStatus::Allowed,
            types: Vec::new(),
            text: true,
            agree_types: false,
            pinned_by: PinnedBy::Owner,
        });
        draft
    }

    fn held(signed: &str) -> Result<HeldRules, Failure> {
        Ok(HeldRules {
            rules: Some(signed.to_owned()),
        })
    }

    fn names(signed: &Option<Signed>, address: &str) -> bool {
        signed.as_ref().is_some_and(|signed| {
            signed
                .draft
                .contacts
                .iter()
                .any(|one| one.address == address)
        })
    }

    /// Bug caught: a device that's behind changing the rules from its own older copy, which brought
    /// back a contact another of the owner's devices had taken out, and a host bringing
    /// back older rules or making some up for the change to start from.
    #[test]
    fn a_change_starts_from_the_newest_rules_the_owner_signed() -> Result<(), Failure> {
        let dana = owner()?;
        let dan = owner()?.identity.id().clone();
        let ben = owner()?.identity.id().clone();
        let now = unix_now();
        let sign = |draft: RulesDraft, by: &Owner, seq: u64| -> Result<String, Failure> {
            Ok(draft.sign(&by.key, by.identity.id(), &dan, seq, now)?)
        };
        let with_ben = with_contact("ben~host.example", &ben);
        let behind = Signed {
            draft: with_ben.clone(),
            signed_at: now,
            seq: 10,
        };
        let removed = sign(first_rules(), &dana, 20)?;
        let started = newest(Some(behind), vec![held(&removed)], &dana.identity, &dan)?;
        assert!(started.is_some() && !names(&started, "ben~host.example"));

        // A host holding older rules than this device signed can't take it back to them.
        let own = Signed {
            draft: first_rules(),
            signed_at: now,
            seq: 30,
        };
        let older = sign(with_ben.clone(), &dana, 20)?;
        let started = newest(Some(own), vec![held(&older)], &dana.identity, &dan)?;
        assert!(started.is_some() && !names(&started, "ben~host.example"));

        // Rules someone else signed, or for another agent, count as no read at all.
        let forged = sign(with_ben.clone(), &owner()?, 40)?;
        let other_agent = with_ben
            .clone()
            .sign(&dana.key, dana.identity.id(), &ben, 40, now)?;
        for made_up in [forged, other_agent] {
            let own = Signed {
                draft: first_rules(),
                signed_at: now,
                seq: 30,
            };
            assert!(newest(Some(own), vec![held(&made_up)], &dana.identity, &dan).is_err());
        }

        // With nothing read, nothing is signed from this device's copy.
        let own = Signed {
            draft: with_ben,
            signed_at: now,
            seq: 10,
        };
        let away = Err(Failure::refused("unreachable"));
        assert!(newest(Some(own), vec![away], &dana.identity, &dan).is_err());
        Ok(())
    }

    /// Bug caught: rules this device wrote down without the delegation the owner key named in them,
    /// as it did before issue 630, ending that delegation at the next change, now that a change names
    /// only what its draft does.
    #[test]
    fn rules_written_down_without_their_delegation_keep_it() -> Result<(), Failure> {
        let dana = owner()?;
        let dan = owner()?.identity.id().clone();
        let now = unix_now();
        let mut naming = first_rules();
        naming.delegation = Some("ab".repeat(32));
        let signed = naming.sign(&dana.key, dana.identity.id(), &dan, 30, now)?;
        let written = Signed {
            draft: first_rules(),
            signed_at: now,
            seq: 30,
        };
        let started = newest(Some(written), vec![held(&signed)], &dana.identity, &dan)?;
        let named = started.and_then(|signed| signed.draft.delegation);
        assert_eq!(named, Some("ab".repeat(32)));
        Ok(())
    }
}

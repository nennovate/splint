//! Keeping an owner's agents recoverable from the computer that set them up, and bringing them back
//! on a new computer with the recovery code alone.
//!
//! The computer's sign-in keeps the owner's list at their home host, as a page does, with each agent's
//! backup in it, sealed to the owner's reading key and again to the backup their recovery code gives.
//! It's named by that backup's point ([`recovery_handle`]), so the code alone finds it. It's written
//! only while the owner ID has a code and this sign-in is its only key: a passkey of the same owner
//! finds its list by its own handle, which this would replace.
//!
//! On a new computer the code recovers the owner ID onto that computer's sign-in, opens the list's
//! recovery copy, and keeps the agents' backups here. Then one prompt recovers each agent that ran on
//! the lost computer onto a new Signet, with a new backup, and signs its binding, default rules and a
//! delegation, and the list again under the new backup.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use splint_core::owner_agents::{
    ListedAgent, ListedBackup, MAX_LABEL_CHARS, OwnerAgentsDraft, VerifiedOwnerAgents,
    recovery_handle,
};
use splint_core::requests::Schemas;
use splint_core::rules::RulesDraft;
use splint_core::{
    AgentKeys, Error, Identity, PublicKey, RecoveryRule, SigningKey, SplintId, canonical_address,
    canonical_domain, unix_now,
};

use crate::device::{self, Device};
use crate::prompt;
use crate::sign_in::Holding;
use crate::signing;

/// What a recovery here kept of the agents in the owner's list, public alone, so a run that stopped
/// partway carries on with no code: the backups are in `agent-backups`, and Splint on this computer
/// reads this.
const RECOVERED: &str = "recovered.json";
/// The most agents one prompt brings back, each named by its address.
pub const MOST_BROUGHT_BACK: usize = 8;

/// One of the owner's agents, for the list.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToList {
    pub agent: SplintId,
    pub address: String,
    pub label: String,
    /// Its ID as its host gives it now, to find the backup it commits to, for an agent set up before
    /// this device noted which backup is whose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Whether its Signet runs on this computer.
    pub beside_owner: bool,
}

/// What Splint on this computer gives for writing the list: the home host that keeps it, every agent,
/// and the `seq` of the last list written here, which the next has to pass.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListGiven {
    pub host: String,
    pub agents: Vec<ToList>,
    #[serde(default)]
    pub after: u64,
}

/// Whether a list will be written from this folder, read without opening the sign-in, so a prompt
/// says so only when it is: the ID has a recovery code whose backup's point is kept here, and this
/// sign-in is its only key.
pub fn writes_list(dir: &Path) -> bool {
    device::identity_in(dir).is_ok_and(|identity| identity.keys().len() == 1)
        && device::backup_point_in(dir).is_some()
}

/// The words a prompt adds when it also keeps the list.
pub fn keeping_words(host: &str) -> String {
    format!(
        "keep your agents' backups at {}, sealed to you",
        prompt::plain(host)
    )
}

/// The owner's list of these agents, each with the backup this device holds for it, signed by the open
/// sign-in for `host`, or `None` where none is written. An agent whose backup isn't here is left out,
/// as nothing here could recover it.
pub fn sign_list(device: &Device, given: &ListGiven) -> Result<Option<String>, Error> {
    if device.identity.keys().len() != 1 {
        return Ok(None);
    }
    let Some(backup) = device.backup_point() else {
        return Ok(None);
    };
    let mut agents: Vec<ListedAgent> = Vec::new();
    for one in &given.agents {
        if agents.iter().any(|listed| listed.agent == one.agent) {
            continue;
        }
        let identity = one
            .identity
            .as_deref()
            .and_then(|text| Identity::from_encoded(text).ok())
            .filter(|identity| identity.id() == &one.agent);
        let Some(key) = device.agent_backup_of(&one.agent, identity.as_ref()) else {
            continue;
        };
        agents.push(ListedAgent {
            agent: one.agent.clone(),
            address: canonical_address(&one.address)?,
            label: label_of(one),
            backup: ListedBackup::of_key(&key)?,
            beside_owner: Some(u8::from(one.beside_owner)),
        });
    }
    if agents.is_empty() {
        return Ok(None);
    }
    let draft = OwnerAgentsDraft {
        agents,
        handle: recovery_handle(&backup),
        backup,
        seq: signing::next_seq().max(given.after.saturating_add(1)),
        now: unix_now(),
        code_saved: Some(1),
    };
    draft
        .sign(
            &device.key,
            &device.identity,
            &canonical_domain(&given.host)?,
        )
        .map(Some)
}

/// A label as a list holds one: the one given where it fits, or else the agent's handle.
fn label_of(one: &ToList) -> String {
    let fits = !one.label.is_empty()
        && one.label.chars().count() <= MAX_LABEL_CHARS
        && !splint_core::requests::has_hidden_characters(&one.label);
    if fits {
        return one.label.clone();
    }
    one.address
        .split_once('~')
        .map_or_else(|| one.address.clone(), |(handle, _)| handle.to_owned())
}

/// The handle a computer's sign-in keeps the owner's list under, from the backup the code gives.
pub fn list_handle(code: &SigningKey) -> String {
    recovery_handle(&code.public_key())
}

/// What a person brings to a new computer, besides their code: every copy of their owner ID the hosts
/// gave, and every list found under the handle the code names, at `host`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverGiven {
    pub identities: Vec<String>,
    #[serde(default)]
    pub lists: Vec<String>,
    pub host: String,
}

#[derive(Serialize)]
pub struct Recovered {
    /// The owner ID recovered onto this computer's sign-in, for every host.
    identity: String,
    /// What the list held, with each agent's backup kept here.
    agents: Vec<ToList>,
    /// Whether a list that the code opens was found.
    list_found: bool,
    /// The new recovery code, shown to the person once.
    code: String,
}

/// Why a recovery here didn't start, as `owner-key` says it.
pub enum NotRecovered {
    /// No copy given commits to this code's backup.
    NotThisCode,
    /// A newer copy than the one this code recovers has moved on, as when it was recovered already.
    AlreadyRecovered,
    /// The host gave lists under this code's handle, and none could be opened with it.
    ListUnreadable,
    Failed(Error),
}

impl From<Error> for NotRecovered {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// Recovers the owner's ID onto a new sign-in in `dir` with the backup the code gave, from the copy
/// given that commits to it, and keeps the agents the newest list that copy signed holds. Nothing is
/// signed with the new sign-in, so no prompt asks for the person.
pub fn recover(
    dir: &Path,
    holding: Holding,
    code: &SigningKey,
    given: &RecoverGiven,
) -> Result<Recovered, NotRecovered> {
    let point = code.public_key();
    let copies: Vec<Identity> = given
        .identities
        .iter()
        .filter_map(|text| Identity::from_encoded(text).ok())
        .collect();
    let mut committing: Option<Identity> = None;
    for copy in copies
        .iter()
        .filter(|copy| copy.check_backup(&point).is_ok())
    {
        committing = Some(match committing {
            Some(held) => held.newest_of(copy).unwrap_or(held),
            None => copy.clone(),
        });
    }
    let Some(identity) = committing else {
        return Err(NotRecovered::NotThisCode);
    };
    if copies.iter().any(|copy| {
        copy.id() == identity.id() && copy.check_backup(&point).is_err() && copy.extends(&identity)
    }) {
        return Err(NotRecovered::AlreadyRecovered);
    }
    let host = canonical_domain(&given.host)?;
    let now = unix_now();
    let mut best: Option<(u64, Vec<ListedAgent>)> = None;
    for list in &given.lists {
        let opened = VerifiedOwnerAgents::verify(list, &identity, &host, now).and_then(|list| {
            let seq = list.seq();
            list.open_for_recovery(code, &identity)
                .map(|agents| (seq, agents))
        });
        if let Ok((seq, agents)) = opened
            && best.as_ref().is_none_or(|(held, _)| seq > *held)
        {
            best = Some((seq, agents));
        }
    }
    // The code is spent by what follows, and a list that's there but can't be opened may be the only
    // copy of the agents' backups, so a host's bad answer has to leave the code working.
    if best.is_none() && !given.lists.is_empty() {
        return Err(NotRecovered::ListUnreadable);
    }
    let list_found = best.is_some();
    let listed = best.map(|(_, agents)| agents).unwrap_or_default();
    let (device, new_code) = Device::recover_signed_in(dir, holding, &identity, code)?;
    let mut agents = Vec::with_capacity(listed.len());
    for one in &listed {
        device.keep_agent_backup(&one.agent, &one.backup.key()?)?;
        agents.push(ToList {
            agent: one.agent.clone(),
            address: one.address.clone(),
            label: one.label.clone(),
            identity: None,
            beside_owner: one.beside_owner == Some(1),
        });
    }
    let kept = serde_json::to_vec(&agents).map_err(|_| Error::Malformed)?;
    fs::write(dir.join(RECOVERED), kept).map_err(|_| Error::KeyStorage)?;
    Ok(Recovered {
        identity: device.identity.encoded(),
        agents,
        list_found,
        code: new_code.spelled(),
    })
}

/// An agent to bring back on this computer: its ID as its host gives it, which commits to the backup
/// kept here, and its new Signet's keys and delegate key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BringBack {
    identity: String,
    address: String,
    new_key: String,
    delegate: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreGiven {
    /// The home host, which keeps the list.
    host: String,
    /// The rules each agent brought back starts with, from Splint on this computer, as for controls.
    rules: RulesDraft,
    here: Vec<BringBack>,
    /// Every agent the list is to hold.
    list: Vec<ToList>,
    #[serde(default)]
    after: u64,
}

#[derive(Serialize)]
pub struct Restored {
    agents: Vec<RestoredOne>,
    /// Those given whose ID, as their host holds it, commits to no backup kept here, so nothing was
    /// signed for them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    not_ours: Vec<SplintId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    list: Option<String>,
}

#[derive(Serialize)]
struct RestoredOne {
    agent: SplintId,
    /// Its ID recovered onto its new Signet's keys, for that Signet's `PUT /v0/owner/recovery`.
    identity: String,
    commitment: String,
    #[serde(flatten)]
    signed: signing::Restored,
}

/// One agent checked before the prompt names it.
struct Checked<'a> {
    given: &'a BringBack,
    identity: Identity,
    backup: SigningKey,
    keys: AgentKeys,
    delegate: PublicKey,
}

/// Brings back each agent given on its new Signet, after one prompt naming every one by its address,
/// and signs the list again with their new backups. Only an agent whose ID commits to a backup kept
/// here is named or signed for; any other is said to be left out, and the rest still come back. With
/// no agent given, it signs the list alone, as a recovery that brought none back here still owes one
/// the new code can find.
pub fn restore(dir: &Path, schemas: &Schemas, given: &RestoreGiven) -> Result<Restored, Error> {
    if given.here.len() > MOST_BROUGHT_BACK || (given.here.is_empty() && given.list.is_empty()) {
        return Err(Error::Malformed);
    }
    let owner = device::identity_in(dir)?;
    let mut checked = Vec::with_capacity(given.here.len());
    let mut not_ours = Vec::new();
    for one in &given.here {
        let identity = Identity::from_encoded(&one.identity)?;
        if canonical_address(&one.address)? != one.address {
            return Err(Error::Malformed);
        }
        let Some(backup) = device::agent_backup_committed_to(dir, &identity) else {
            not_ours.push(identity.id().clone());
            continue;
        };
        checked.push(Checked {
            given: one,
            identity,
            backup,
            keys: AgentKeys::from_encoded(&one.new_key)?,
            delegate: PublicKey::from_encoded(&one.delegate)?,
        });
    }
    let keeps_list = owner.keys().len() == 1 && device::backup_point_in(dir).is_some();
    if checked.is_empty() && !keeps_list {
        return Ok(Restored {
            agents: Vec::new(),
            not_ours,
            list: None,
        });
    }
    let named: Vec<String> = checked
        .iter()
        .map(|one| prompt::plain(&one.given.address))
        .collect();
    let bringing = format!(
        "bring back your agents {} on this computer, with default rules",
        named.join(", ")
    );
    let words = match (named.is_empty(), keeps_list) {
        (true, _) => keeping_words(&given.host),
        (false, true) => format!("{bringing}, and {}", keeping_words(&given.host)),
        (false, false) => bringing,
    };
    let device = Device::open(dir, prompt::for_command(&words))?;
    let mut agents = Vec::with_capacity(checked.len());
    for one in &checked {
        let next = device.new_agent_backup()?;
        let next_key = SigningKey::load(&next.file)?;
        let recovered = one.identity.recover(
            &one.backup,
            &one.keys.key,
            &one.keys.seal,
            RecoveryRule::committed_to(&next.commitment)?,
            unix_now(),
        )?;
        device.remember_backup_of(recovered.id(), &next.commitment)?;
        let signed = signing::restored(
            &device,
            &recovered,
            &one.given.address,
            &next_key,
            given.rules.clone(),
            &one.delegate,
            schemas,
        )?;
        agents.push(RestoredOne {
            agent: recovered.id().clone(),
            identity: recovered.encoded(),
            commitment: next.commitment,
            signed,
        });
    }
    let mut listing: Vec<ToList> = given.list.clone();
    for back in &agents {
        if let Some(one) = listing.iter_mut().find(|one| one.agent == back.agent) {
            one.beside_owner = true;
        }
    }
    let list = sign_list(
        &device,
        &ListGiven {
            host: given.host.clone(),
            agents: listing,
            after: given.after,
        },
    )?;
    Ok(Restored {
        agents,
        not_ours,
        list,
    })
}

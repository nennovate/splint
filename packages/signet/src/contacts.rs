//! The full identities of contacts the owner's rules name by ID, pinned once found.
//!
//! Once a contact is pinned, sending doesn't need their host at all, so a message can be queued
//! while that host is down. Only an address in the rules is ever looked up, and only the agent the
//! rules name there is accepted, so a host can't swap in a different agent or a new key.
//!
//! The rules name one ID, so who that ID acts for is pinned here when first found, and changes only
//! if the owner pinned here released it to the new one. A contact's key changes only by a recovery
//! anyone can check, and an older copy of its identity can't bring back a key it gave up.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::sync::{Mutex as ShortLock, PoisonError};

use serde::{Deserialize, Serialize};
use splint_core::contact_view::Copies;
use splint_core::rules::VerifiedRules;
use splint_core::{
    DEFAULT_MESSAGE_LIFETIME_SECS, Error, Identity, SplintId, VerifiedBinding, unix_now,
};
use tokio::sync::Mutex;

use crate::Signet;
use crate::changes::Seen;
use crate::contact_asks::ContactAsks;
use crate::host_client::{Found, HostError, Lookup};
use crate::state_file::{self, StateError};

/// Said of an agent whose owner hasn't set up controls yet, by the rule any reader can work out from
/// their owner's ID.
pub const NO_CONTROLS: &str = "no controls set up yet";
/// Said of an agent this Signet hasn't pinned yet, so it can't say either way.
pub const NOT_KNOWN_YET: &str = "not known yet";

/// What this Signet can say of another agent's owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Controls {
    /// Its owner set up its controls, as what's pinned and what came with it both say.
    Set,
    /// A stand-in signs for it, as its owner hasn't set up its controls yet.
    NotSetUp,
    /// Nothing pinned here says, or what's pinned and what came with it part ways.
    NotKnownYet,
}

impl Controls {
    /// From an owner's ID that was checked with what it came with.
    pub fn of_owner(owner: &Identity) -> Self {
        if owner.is_unconfirmed_owner() {
            Self::NotSetUp
        } else {
            Self::Set
        }
    }
}

/// What an agent is told of another's owner, wherever it's shown one: that someone has set up controls
/// for it, that nobody has yet, or that this Signet doesn't know yet. Never a name: the owner part of
/// an address is whatever its host let someone claim, and beside a check mark it would read as checked.
pub fn controls_of(controls: Controls) -> String {
    match controls {
        Controls::NotSetUp => NO_CONTROLS.to_owned(),
        Controls::NotKnownYet => NOT_KNOWN_YET.to_owned(),
        Controls::Set => "their owner's agent ✓".to_owned(),
    }
}

/// Who another agent acts for, as this Signet can stand behind it: the binding pinned for them, checked
/// again now. Nothing for one held by a change their owner's word is waiting on, whose owner isn't
/// settled.
pub async fn verified_owner_of(signet: &Signet, agent: &SplintId) -> Option<Identity> {
    if signet.rules.held_by_a_change(agent).await {
        return None;
    }
    signet.contacts.bound_owner_of(agent).await
}

/// Marked on a contact, an invite or a message's `from` when the other agent acts for this agent's own
/// owner, by owner ID. The ID is shown only
/// then, as it's this agent's own owner's, until Nenye decides whether others see it too
///. Empty otherwise, so it adds nothing.
#[derive(Clone, Default, Serialize)]
pub struct SameOwner {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub same_owner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<SplintId>,
}

impl SameOwner {
    /// From who the other agent acts for, checked by a binding: never for a stand-in on either side,
    /// and never before this agent's own owner has bound it.
    pub fn of(signet: &Signet, theirs: Option<&Identity>) -> Self {
        let who = signet.who();
        let same = theirs.is_some_and(|theirs| {
            theirs.id() == who.owner.id()
                && !who.owner.is_unconfirmed_owner()
                && !theirs.is_unconfirmed_owner()
                && !who.binding.is_empty()
        });
        if same {
            Self {
                same_owner: true,
                owner: Some(who.owner.id().clone()),
            }
        } else {
            Self::default()
        }
    }
}

/// Long enough that a dead contact can't tie up an agent that keeps retrying it, and short enough
/// that one that comes back isn't refused for long.
const REMEMBER_FAILURE_FOR: Duration = Duration::from_secs(30);
/// Rules can name any number of addresses. Past this one that fails is just tried again.
const MAX_REMEMBERED_FAILURES: usize = 1024;
/// Beside the pins, so a Signet's state stays in one folder.
const TAKEN_OUT_FILE: &str = "contacts-taken-out.json";
/// Far more than an owner takes out in the week a note lasts. Past it, what's sent before a removal
/// is cleared as anyone else's is.
const MAX_TAKEN_OUT: usize = 4096;

/// The newest copy this Signet has seen of each ID that's been recovered or had keys added or removed,
/// so an older one can't bring back a key that ID gave up. An ID with nothing after its event has
/// nothing to remember. Nothing is dropped, since a copy forgotten is a key given up that counts again.
pub struct Known {
    path: PathBuf,
    newest: ShortLock<HashMap<String, String>>,
}

impl Known {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let newest = ShortLock::new(state_file::load(&path)?);
        Ok(Self { path, newest })
    }

    fn held(&self, id: &SplintId) -> Option<Identity> {
        let newest = self.newest.lock().unwrap_or_else(PoisonError::into_inner);
        newest
            .get(id.as_str())
            .and_then(|text| Identity::from_encoded(text).ok())
    }

    /// How many recoveries of this ID this Signet has seen.
    pub fn recoveries_of(&self, id: &SplintId) -> usize {
        self.held(id).map_or(0, |held| held.recoveries())
    }

    /// What to believe about this ID, given this copy. Two recoveries of one ID are refused.
    pub fn newest(&self, identity: &Identity) -> Result<Identity, Error> {
        match self.held(identity.id()) {
            Some(held) => held.newest_of(identity),
            None => Ok(identity.clone()),
        }
    }

    /// The same where there's no refusing, such as reading back a chain. Of a copy that parts ways
    /// with the one held, the one held stands, so what only the other branch's keys signed doesn't
    /// count here.
    pub fn newest_or_same(&self, identity: &Identity) -> Identity {
        match self.held(identity.id()) {
            Some(held) => held.newest_of(identity).unwrap_or(held),
            None => identity.clone(),
        }
    }

    /// The copies an owner chose between two that parted ways, whatever was held before.
    pub fn adopt(&self, identity: &Identity, owners: &[Identity]) -> Result<(), Error> {
        let mut held = self.newest.lock().unwrap_or_else(PoisonError::into_inner);
        for copy in std::iter::once(identity).chain(owners) {
            let id = copy.id().as_str().to_owned();
            let replaces = match held
                .get(&id)
                .and_then(|text| Identity::from_encoded(text).ok())
            {
                Some(on_file) => on_file.newest_of(copy).is_err() || copy.extends(&on_file),
                None => copy.statements() > 0,
            };
            if replaces {
                held.insert(id, copy.encoded());
            }
        }
        state_file::save(&self.path, &held).map_err(|_| Error::KeyStorage)
    }

    /// Takes in a copy newer than the one held: a recovery, or a key its owner added or removed. Only
    /// call this for an ID the owner's rules let in, so what fills it is bounded by those rules.
    pub fn learn(&self, identity: &Identity) -> Result<(), HostError> {
        if identity.statements() == 0 {
            return Ok(());
        }
        let Ok(newest) = self.newest(identity) else {
            tracing::warn!(id = %identity.id(), "two copies of one ID that part ways");
            return Ok(());
        };
        let mut held = self.newest.lock().unwrap_or_else(PoisonError::into_inner);
        held.insert(identity.id().as_str().to_owned(), newest.encoded());
        state_file::save(&self.path, &held).map_err(|_| HostError::LocalStorage)
    }
}

impl Copies for Known {
    fn recoveries_of(&self, id: &SplintId) -> usize {
        Self::recoveries_of(self, id)
    }

    fn newest_or_same(&self, identity: &Identity) -> Identity {
        Self::newest_or_same(self, identity)
    }

    fn held_copy(&self, id: &SplintId) -> Option<Identity> {
        self.held(id)
    }
}

/// A pinned agent, who it acts for and the statement that says so.
#[derive(Clone, Serialize, Deserialize)]
struct Pinned {
    identity: String,
    owner: String,
    binding: String,
}

impl Pinned {
    fn of(found: &Found) -> Self {
        Self {
            identity: found.agent.encoded(),
            owner: found.owner.encoded(),
            binding: found.binding.clone(),
        }
    }

    fn read(&self) -> Result<Found, HostError> {
        Ok(Found {
            agent: Identity::from_encoded(&self.identity)?,
            owner: Identity::from_encoded(&self.owner)?,
            binding: self.binding.clone(),
        })
    }
}

pub struct Contacts {
    pub known: Arc<Known>,
    seen_changes: Arc<Seen>,
    asks: Arc<ContactAsks>,
    path: PathBuf,
    /// Address to what's pinned there.
    pinned: Mutex<HashMap<String, Pinned>>,
    failures: Mutex<RecentFailures>,
    taken_out_path: PathBuf,
    /// Contacts the owner's rules have taken out, by ID, to when. What they sent before that waits on
    /// the host unseen rather than being cleared, so adding them back loses nothing. It's kept as long
    /// as a note lasts, as nothing of theirs from before is left after that.
    taken_out: ShortLock<HashMap<String, u64>>,
}

/// Addresses whose first contact failed just now. It's per address, not per host, so a mistyped
/// handle doesn't block everyone else on a working host.
#[derive(Default)]
struct RecentFailures {
    failed_at: HashMap<String, Instant>,
}

impl RecentFailures {
    fn is_recent(&self, address: &str, now: Instant) -> bool {
        self.failed_at
            .get(address)
            .is_some_and(|failed| now.duration_since(*failed) < REMEMBER_FAILURE_FOR)
    }

    fn remember(&mut self, address: &str, now: Instant) {
        self.failed_at
            .retain(|_, failed| now.duration_since(*failed) < REMEMBER_FAILURE_FOR);
        if self.failed_at.len() < MAX_REMEMBERED_FAILURES {
            self.failed_at.insert(address.to_owned(), now);
        }
    }
}

impl Contacts {
    pub fn load(
        path: PathBuf,
        known: Arc<Known>,
        seen_changes: Arc<Seen>,
        asks: Arc<ContactAsks>,
    ) -> Result<Self, StateError> {
        let pinned = Mutex::new(state_file::load(&path)?);
        let failures = Mutex::default();
        let taken_out_path = path.with_file_name(TAKEN_OUT_FILE);
        Ok(Self {
            known,
            seen_changes,
            asks,
            taken_out: ShortLock::new(state_file::load(&taken_out_path)?),
            taken_out_path,
            path,
            pinned,
            failures,
        })
    }

    /// Notes whom new rules take out: anyone this agent dealt with under the old ones, `before`, that
    /// the new ones neither let it deal with nor block. A block clears what they sent, as it always
    /// has, and anyone the new rules let in again is a contact once more.
    pub fn note_taken_out(
        &self,
        before: &[SplintId],
        after: &VerifiedRules,
    ) -> Result<(), HostError> {
        let now = unix_now();
        let named: HashSet<&str> = after
            .listed()
            .filter(|id| after.lists_for_requests(id) || after.blocks(id))
            .map(SplintId::as_str)
            .collect();
        let mut taken_out = self
            .taken_out
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let held = taken_out.len();
        taken_out.retain(|id, at| {
            now.saturating_sub(*at) < DEFAULT_MESSAGE_LIFETIME_SECS && !named.contains(id.as_str())
        });
        let mut changed = taken_out.len() != held;
        for id in before {
            if !named.contains(id.as_str()) && taken_out.len() < MAX_TAKEN_OUT {
                changed |= taken_out.insert(id.as_str().to_owned(), now).is_none();
            }
        }
        if !changed {
            return Ok(());
        }
        state_file::save(&self.taken_out_path, &taken_out).map_err(|_| HostError::LocalStorage)
    }

    /// When the owner's rules took this agent out of the contacts, if that was within the last week.
    pub fn taken_out_at(&self, agent: &SplintId) -> Option<u64> {
        let taken_out = self
            .taken_out
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        taken_out
            .get(agent.as_str())
            .copied()
            .filter(|at| unix_now().saturating_sub(*at) < DEFAULT_MESSAGE_LIFETIME_SECS)
    }

    /// Pins someone the reach setting let in from their own signed message, which says all a lookup
    /// through this agent's host would. So a host that's slow to answer for a stranger's address can't
    /// hold up anything, and nobody's pin is moved: an address already pinned stays as it is. Who made
    /// way for them in the list of who's reached is let go here too.
    pub async fn pin_reached(
        &self,
        address: &str,
        found: Found,
        made_way: Option<&str>,
    ) -> Result<(), HostError> {
        let mut pinned = self.pinned.lock().await;
        let gone = made_way.is_some_and(|address| pinned.remove(address).is_some());
        if !gone && pinned.contains_key(address) {
            return Ok(());
        }
        pinned
            .entry(address.to_owned())
            .or_insert_with(|| Pinned::of(&found));
        state_file::save(&self.path, &pinned).map_err(|_| HostError::LocalStorage)
    }

    /// The ID pinned at an address, whatever pinned it.
    pub async fn pinned_at(&self, address: &str) -> Option<SplintId> {
        let pinned = self.pinned.lock().await;
        let found = pinned.get(address)?.read().ok()?;
        Some(found.agent.id().clone())
    }

    /// Pins who an invite found at an address, by its host or by its own signed message, if nothing
    /// is pinned there yet and its owner's binding names that address. An address already pinned
    /// stays as it is, so a later answer can't move it.
    pub async fn pin_found(&self, address: &str, found: Found) -> Result<(), HostError> {
        if VerifiedBinding::verify_for(&found.binding, &found.owner, &found.agent, address).is_err()
        {
            return Ok(());
        }
        let mut pinned = self.pinned.lock().await;
        if pinned.contains_key(address) {
            return Ok(());
        }
        self.known.learn(&found.agent)?;
        self.known.learn(&found.owner)?;
        pinned.insert(address.to_owned(), Pinned::of(&found));
        state_file::save(&self.path, &pinned).map_err(|_| HostError::LocalStorage)
    }

    /// What's pinned here says of the owner of the agent with this ID: nothing, if it isn't pinned.
    pub async fn controls_of(&self, agent: &SplintId) -> Controls {
        let pinned = self.pinned.lock().await;
        let found = pinned
            .values()
            .filter_map(|pinned| pinned.read().ok())
            .find(|found| found.agent.id() == agent);
        found.map_or(Controls::NotKnownYet, |found| {
            Controls::of_owner(&found.owner)
        })
    }

    /// Who the agent pinned with this ID acts for, by its binding checked again now under the newest
    /// copies of both IDs this Signet has seen, so a key given up in a recovery vouches for nobody.
    /// What's pinned only moves on to a binding that may follow it, so a host can't bring back one
    /// older. Nothing, if they aren't pinned, it doesn't check out, or they're pinned at two addresses
    /// whose bindings name different owners, as an older one could.
    async fn bound_owner_of(&self, agent: &SplintId) -> Option<Identity> {
        let pinned = self.pinned.lock().await;
        let mut owners = pinned.iter().filter_map(|(address, pinned)| {
            let found = pinned.read().ok()?;
            (found.agent.id() == agent).then(|| self.owner_by_binding(&found, address))
        });
        let first = owners.next()??;
        owners
            .all(|other| other.is_some_and(|other| other.id() == first.id()))
            .then_some(first)
    }

    /// Who `found` acts for at `address`, if its owner's binding checks out under the newest copies of
    /// both IDs, with no recovery of either that parts ways. The binding names the agent at that host,
    /// under the name its owner gave it then, which a new owner changes, as `ana-7k3p2a` becomes
    /// `ana.jeff` when jeff sets up controls, so an address it went by before still counts.
    pub fn owner_by_binding(&self, found: &Found, address: &str) -> Option<Identity> {
        let owner = self.known.newest(&found.owner).ok()?;
        let agent = self.known.newest(&found.agent).ok()?;
        let bound = VerifiedBinding::verify(&found.binding, &owner, &agent).ok()?;
        splint_core::same_host(bound.address(), address).then_some(owner)
    }

    /// The address of a contact pinned here that an address with an owner's ID in place of their name
    /// stands for: the same handle and host, for an owner whose ID starts as the form says. Asked of
    /// nobody, so naming one tells no host anything.
    pub async fn named_by_id_form(&self, typed: &str) -> Option<String> {
        let pinned = self.pinned.lock().await;
        pinned.iter().find_map(|(address, pinned)| {
            let found = pinned.read().ok()?;
            let owner = self.known.newest_or_same(&found.owner);
            splint_core::address_named(typed, address, owner.id())
                .ok()
                .filter(|named| named == address)
        })
    }

    /// Every other address an agent is pinned at, at the same host, follows a newer statement of who it
    /// acts for, so they all say the same and none goes on naming an owner it has left.
    fn carry_over(pinned: &mut HashMap<String, Pinned>, address: &str, found: &Found) {
        let Ok(next) = VerifiedBinding::verify(&found.binding, &found.owner, &found.agent) else {
            return;
        };
        for (other, held) in pinned.iter_mut() {
            let Ok(was) = held.read() else {
                continue;
            };
            let behind = was.agent.id() == found.agent.id()
                && other != address
                && splint_core::same_host(other, address)
                && was.binding != found.binding
                && next
                    .may_replace(
                        &was.owner,
                        VerifiedBinding::verify_history(&was.binding, &was.owner, &was.agent)
                            .map_or(0, |binding| binding.seq()),
                    )
                    .is_ok();
            if behind {
                *held = Pinned::of(found);
            }
        }
    }

    /// For when this agent gets a new owner, whose contacts these aren't.
    pub async fn forget_everything(&self) -> Result<(), HostError> {
        {
            let mut taken_out = self
                .taken_out
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            taken_out.clear();
            state_file::save(&self.taken_out_path, &taken_out)
                .map_err(|_| HostError::LocalStorage)?;
        }
        let mut pinned = self.pinned.lock().await;
        pinned.clear();
        state_file::save(&self.path, &pinned).map_err(|_| HostError::LocalStorage)
    }

    /// Takes in what a contact's own host says about it now, which it passes on with every message.
    /// Only a statement that checks out and may follow the pinned one changes anything, so a host can
    /// say what it likes here. Without a pin there's nothing to compare it with, so it waits for one.
    pub async fn note(
        &self,
        address: &str,
        sender: &Identity,
        owner: &str,
        binding: &str,
    ) -> Result<(), HostError> {
        self.note_shown(sender, owner, binding)?;
        self.known.learn(sender)?;
        let mut pinned = self.pinned.lock().await;
        let Some(found) = pinned.get(address).map(Pinned::read).transpose()? else {
            return Ok(());
        };
        if found.agent.id() != sender.id() {
            return Ok(());
        }
        let Ok(owner) = Identity::from_encoded(owner) else {
            return Ok(());
        };
        if owner.id() == found.owner.id() {
            self.known.learn(&owner)?;
        }
        let pinned_owner = self.known.newest_or_same(&found.owner);
        let agent = self.known.newest_or_same(sender);
        let owner = self.known.newest_or_same(&owner);
        // At this address, or at the same host under a name a new owner gave it.
        let Ok(next) = VerifiedBinding::verify(binding, &owner, &agent) else {
            return Ok(());
        };
        if !splint_core::same_host(next.address(), address) {
            return Ok(());
        }
        if next.compact() == found.binding {
            return Ok(());
        }
        // What a replaced key signed could be dated as far ahead as a thief liked, so it holds nothing
        // back. A new key's statement goes by its own signature, like any other.
        let current_seq = if pinned_owner.recoveries() > found.owner.recoveries()
            || !pinned_owner.signed_now(&found.binding)
        {
            0
        } else {
            VerifiedBinding::verify_history(&found.binding, &found.owner, &found.agent)
                .map_or(0, |binding| binding.seq())
        };
        if let Err(error) = next.may_replace(&pinned_owner, current_seq) {
            tracing::warn!(%error, %address, "kept who a contact acts for, over a new claim");
            return Ok(());
        }
        if next.owner() != found.owner.id() {
            tracing::warn!(%address, owner = %next.owner(), "a contact now acts for a new owner");
        }
        let found = Found {
            agent,
            owner,
            binding: next.compact().to_owned(),
        };
        pinned.insert(address.to_owned(), Pinned::of(&found));
        Self::carry_over(&mut pinned, address, &found);
        state_file::save(&self.path, &pinned).map_err(|_| HostError::LocalStorage)
    }

    /// Writes down what a contact has shown, before any of it moves what's held here. A copy of the
    /// owner's ID that's come through a recovery counts only for the owner already on file, so nobody
    /// can fill this with made-up owners.
    fn note_shown(&self, sender: &Identity, owner: &str, binding: &str) -> Result<(), HostError> {
        let agent = self.known.newest_or_same(sender);
        let shown = Identity::from_encoded(owner).ok().and_then(|owner| {
            let owner = self.known.newest_or_same(&owner);
            let bound = VerifiedBinding::verify(binding, &owner, &agent).ok()?;
            Some((owner, bound))
        });
        let as_shown = shown.as_ref().map(|(owner, bound)| (owner, bound));
        self.seen_changes
            .note_shown(&agent, as_shown, &self.known)?;
        if let Some((owner, _)) =
            as_shown.filter(|(owner, _)| self.seen_changes.first_owner_is(sender, owner))
        {
            self.known.learn(owner)?;
        }
        Ok(())
    }

    /// Asks a contact's host what it says now, before starting something with them. If it can't say,
    /// what's pinned stands, since that's the point of pinning.
    pub async fn refresh(
        &self,
        host: &Lookup<'_>,
        address: &str,
        handle: &str,
        domain: &str,
    ) -> Result<(), HostError> {
        if self
            .failures
            .lock()
            .await
            .is_recent(address, Instant::now())
        {
            return Ok(());
        }
        match host.resolve(handle, domain).await {
            Ok(found) => {
                self.note(
                    address,
                    &found.agent,
                    &found.owner.encoded(),
                    &found.binding,
                )
                .await
            }
            Err(_) => {
                self.failures.lock().await.remember(address, Instant::now());
                Ok(())
            }
        }
    }

    /// The agent the owner's rules name at this address. Their signature outranks whatever got
    /// pinned from a host's answer before, and a host that answers with anyone else finds nobody.
    pub async fn named_by_rules(
        &self,
        host: &Lookup<'_>,
        address: &str,
        handle: &str,
        domain: &str,
        named: &SplintId,
    ) -> Result<Found, HostError> {
        if let Some(pinned) = self.pinned.lock().await.get(address) {
            let found = pinned.read()?;
            if found.agent.id() == named {
                return Ok(Found {
                    agent: self.known.newest_or_same(&found.agent),
                    owner: self.known.newest_or_same(&found.owner),
                    binding: found.binding,
                });
            }
        }
        // No lock is held while calling the host, so a slow address only holds up its own send.
        let started = Instant::now();
        if self.failures.lock().await.is_recent(address, started) {
            return Err(HostError::NoSuchContact);
        }
        // A host can't undo a recovery this Signet knows of, by answering with what came before it.
        let found = match host.resolve(handle, domain).await {
            Ok(found) if found.agent.id() == named => found,
            Ok(_) => {
                self.asks.note_disagreement(address, named)?;
                return Err(HostError::NoSuchContact);
            }
            Err(error) => {
                let now = Instant::now();
                self.failures.lock().await.remember(address, now);
                return Err(error);
            }
        };
        self.note_shown(&found.agent, &found.owner.encoded(), &found.binding)?;
        self.known.learn(&found.agent)?;
        self.known.learn(&found.owner)?;
        self.asks.note_agreement(address)?;
        let mut pinned = self.pinned.lock().await;
        pinned.insert(address.to_owned(), Pinned::of(&found));
        Self::carry_over(&mut pinned, address, &found);
        state_file::save(&self.path, &pinned).map_err(|_| HostError::LocalStorage)?;
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use splint_core::{RecoveryRule, SigningKey};

    /// The bug: a copy that parted ways was used as shown, so what a removed key signed on its own
    /// branch counted wherever a contact's binding, parties or confirmations were checked.
    #[test]
    fn a_copy_that_parts_ways_is_read_as_the_one_held() {
        let folder = std::env::temp_dir().join(format!("signet-known-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        let known = Known::load(folder.join("known.json")).unwrap();
        let (first, laptop, phone) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        let backup = SigningKey::generate().unwrap();
        let owner = Identity::create(
            &first,
            &splint_core::SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&backup.public_key()),
        )
        .unwrap();
        let held = owner.add_key(&first, &laptop, 1).unwrap();
        let first_name = held.keys()[0].name();
        let held = held.remove_key(&laptop, &first_name, 1).unwrap();
        known.learn(&held).unwrap();
        // The removed key's own branch, from before its removal.
        let branch = owner.add_key(&first, &phone, 1).unwrap();
        assert_eq!(known.newest_or_same(&branch).encoded(), held.encoded());
        // A copy that follows on is still taken.
        let later = held
            .add_key(&laptop, &SigningKey::generate().unwrap(), 1)
            .unwrap();
        assert_eq!(known.newest_or_same(&later).encoded(), later.encoded());
        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn a_failure_is_remembered_only_for_a_short_time() {
        let mut failures = RecentFailures::default();
        let now = Instant::now();
        failures.remember("gone~host.example", now);
        assert!(failures.is_recent("gone~host.example", now + REMEMBER_FAILURE_FOR / 2));
        assert!(!failures.is_recent("gone~host.example", now + REMEMBER_FAILURE_FOR));
        assert!(!failures.is_recent("other~host.example", now));
    }

    #[test]
    fn a_flood_of_failures_stays_bounded_and_makes_room_once_they_age() {
        let mut failures = RecentFailures::default();
        let now = Instant::now();
        for number in 0..MAX_REMEMBERED_FAILURES + 10 {
            failures.remember(&format!("a{number}~host.example"), now);
        }
        assert_eq!(failures.failed_at.len(), MAX_REMEMBERED_FAILURES);
        assert!(!failures.is_recent("a-new-one~host.example", now));

        let later = now + REMEMBER_FAILURE_FOR;
        failures.remember("a-new-one~host.example", later);
        assert!(failures.is_recent("a-new-one~host.example", later));
        assert_eq!(failures.failed_at.len(), 1);
    }
}

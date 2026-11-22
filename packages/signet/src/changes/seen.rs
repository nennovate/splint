//! What this agent has seen of each contact's history, from `splint_core::contact_view`, kept in a file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex as ShortLock, PoisonError};
use std::time::{Duration, Instant};

use splint_core::changes::{ChangeRules, VerifiedAcceptance, VerifiedHistory};
use splint_core::contact_view::{ContactView, Heard, OnFile, SavedView, Standing, Taken};
use splint_core::host_api::RetirementNotice;
use splint_core::{Error, Identity, SplintId, VerifiedBinding, unix_now};

use crate::contacts::Known;
use crate::host_client::HostError;
use crate::state_file::{self, StateError};

/// Long enough that a contact who isn't there yet doesn't use up this agent's lookups.
const ASK_AGAIN_FOR_A_FIRST_COPY: Duration = Duration::from_secs(300);
/// Short enough that a message waiting on a history doesn't wait for long once it's there.
const ASK_AGAIN_WHEN_BEHIND: Duration = Duration::from_secs(5);

/// Everyone this agent hears from is written down and never dropped, since a contact left out would
/// be measured from nothing and its replaced key or new owner would get through without a hold. What
/// bounds it is who the owner's rules let in, and how many a day reach lets in.
pub struct Seen {
    path: PathBuf,
    entries: ShortLock<HashMap<String, ContactView>>,
    asked: ShortLock<HashMap<String, Instant>>,
}

impl Seen {
    /// One that no longer checks out counts as none, and the next history stands in for it.
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let saved = state_file::load::<SavedView>(&path)?;
        let entries = saved
            .into_iter()
            .filter_map(|(id, saved)| Some((id, ContactView::load(&saved)?)))
            .collect();
        Ok(Self {
            path,
            entries: ShortLock::new(entries),
            asked: ShortLock::default(),
        })
    }

    fn save(&self, entries: &HashMap<String, ContactView>) -> Result<(), HostError> {
        let saved = entries
            .iter()
            .map(|(id, entry)| Ok((id.clone(), entry.saved()?)))
            .collect::<Result<HashMap<_, _>, Error>>()?;
        state_file::save(&self.path, &saved).map_err(|_| HostError::LocalStorage)
    }

    /// Takes a history that's been verified, and goes by the IDs in it unless it's a rival.
    pub fn take(&self, new: VerifiedHistory, heard: Heard, known: &Known) -> Result<(), HostError> {
        let id = new.id().as_str().to_owned();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let taken = match entries.get_mut(&id) {
            None => {
                entries.insert(
                    id.clone(),
                    ContactView::from_history(new.clone(), heard, unix_now()),
                );
                Taken::Followed
            }
            Some(entry) => entry.take(new.clone(), unix_now()),
        };
        // Before anything here is learned from it, as it's the copy held that this is measured against.
        let parted = entries
            .get_mut(&id)
            .is_some_and(|entry| entry.note_parted_owners(&new, known));
        if parted {
            tracing::warn!(
                id,
                "a history names an owner that parts ways, so messages are held"
            );
        }
        if taken == Taken::Unchanged && !parted {
            return Ok(());
        }
        if taken == Taken::Rival {
            tracing::warn!(id, "a history rewrites what was seen, so messages are held");
        }
        self.save(&entries)?;
        drop(entries);
        if taken == Taken::Followed {
            known.learn(new.identity())?;
            for owner in new.owners() {
                known.learn(owner)?;
            }
        }
        Ok(())
    }

    /// Writes down who a contact showed itself to be, from what's signed.
    pub fn note_shown(
        &self,
        identity: &Identity,
        shown: Option<(&Identity, &VerifiedBinding)>,
        known: &Known,
    ) -> Result<(), HostError> {
        let id = identity.id().as_str().to_owned();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let mut changed = false;
        let entry = entries.entry(id).or_insert_with(|| {
            changed = true;
            ContactView::from_identity(identity)
        });
        if entry.note_shown(identity, shown, known, unix_now()) {
            changed = true;
        }
        if changed {
            self.save(&entries)?;
        }
        Ok(())
    }

    /// Takes a contact's owner's stop, once it checks out. One that doesn't is only a lying host's.
    pub fn take_stop(&self, notice: &RetirementNotice, known: &Known) -> Result<(), HostError> {
        let Ok(stop) = splint_core::VerifiedStop::verify(notice) else {
            tracing::warn!("refused a stop that doesn't check out");
            return Ok(());
        };
        let id = stop.agent().id().as_str().to_owned();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries
            .entry(id.clone())
            .or_insert_with(|| ContactView::from_identity(stop.agent()));
        if entry.take_stop(notice, known).unwrap_or(false) {
            tracing::warn!(id, "a contact's owner has retired it");
            self.save(&entries)?;
        }
        Ok(())
    }

    /// Who signed the stops on file, whose recoveries are what ends them.
    pub fn stop_owners(&self) -> Vec<SplintId> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .values()
            .filter_map(ContactView::stopped_by)
            .cloned()
            .collect()
    }

    /// Whether this is the owner this reader first knew this contact under.
    pub fn first_owner_is(&self, contact: &Identity, owner: &Identity) -> bool {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(contact.id().as_str())
            .is_some_and(|entry| entry.first_owner_is(owner))
    }

    /// Two copies of an ID parted ways on a message, before any history said so.
    pub fn mark_forked(&self, identity: &Identity) -> Result<(), HostError> {
        let id = identity.id().as_str().to_owned();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries
            .entry(id)
            .or_insert_with(|| ContactView::from_identity(identity));
        if !entry.mark_forked(identity) {
            return Ok(());
        }
        tracing::warn!(id = %identity.id(), "two copies of an ID part ways, so messages are held");
        self.save(&entries)
    }

    /// Whether the owner has chosen against this copy of an ID, so what comes with it is simply refused.
    pub fn refuses_copy(&self, identity: &Identity) -> bool {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(identity.id().as_str())
            .is_some_and(|entry| entry.refuses_copy(identity))
    }

    /// For when this agent gets a new owner, whose word none of this is.
    pub fn forget_everything(&self) -> Result<(), HostError> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.clear();
        self.save(&entries)
    }

    /// An owner's yes, to the exact head named, of what's held or of its rival.
    pub fn accept(&self, acceptance: &VerifiedAcceptance, known: &Known) -> Result<(), Error> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries
            .get_mut(acceptance.contact().as_str())
            .ok_or(Error::ProofMismatch)?;
        entry.accept(acceptance, known, |chosen| {
            known.adopt(chosen.identity(), chosen.owners())
        })?;
        self.save(&entries).map_err(|_| Error::KeyStorage)
    }

    pub fn standing(&self, id: &SplintId, rules: &ChangeRules, known: &Known) -> Standing {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(id.as_str())
            .map_or(Standing::Continue, |entry| entry.standing(rules, known))
    }

    /// The changes in this contact's history this Signet took `since` or later, as facts for its agent.
    pub fn changed_since(
        &self,
        id: &SplintId,
        since: u64,
    ) -> Vec<splint_core::changes::VerifiedChange> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id.as_str())
            .map(|entry| entry.changed_since(since))
            .unwrap_or_default()
    }

    /// Where this contact is now, by its newest history. Nothing here says nobody else is there.
    pub fn address_of(&self, id: &SplintId) -> Option<String> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(id.as_str())
            .and_then(|entry| entry.address().map(str::to_owned))
    }

    pub fn on_file(&self, id: &SplintId) -> Option<OnFile> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        Some(entries.get(id.as_str())?.on_file())
    }

    /// The histories an owner's word about this contact can name, for that word to reach this agent's
    /// host together with them.
    pub fn histories_of(&self, id: &SplintId) -> Vec<String> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(id.as_str())
            .and_then(|entry| entry.histories().ok())
            .unwrap_or_default()
    }

    /// Whether to ask after this contact now, counting this as the asking if so.
    pub fn due_for_asking(&self, id: &SplintId, known: &Known) -> bool {
        let wait = {
            let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
            match entries.get(id.as_str()) {
                None => ASK_AGAIN_FOR_A_FIRST_COPY,
                Some(entry)
                    if entry.is_forked()
                        || entry
                            .standing(&ChangeRules::default(), known)
                            .eq(&Standing::WaitingForHistory) =>
                {
                    ASK_AGAIN_WHEN_BEHIND
                }
                Some(entry) if entry.has_no_history() => ASK_AGAIN_FOR_A_FIRST_COPY,
                Some(_) => return false,
            }
        };
        let mut asked = self.asked.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if asked
            .get(id.as_str())
            .is_some_and(|at| now.duration_since(*at) < wait)
        {
            return false;
        }
        asked.insert(id.as_str().to_owned(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use splint_core::{RecoveryRule, SigningKey};

    use super::*;

    /// Far past any limit either file ever had, as an owner with open reach gets to in time.
    const MANY: usize = 10_000;

    fn new_identity() -> (Identity, SigningKey) {
        let backup = SigningKey::generate().unwrap();
        let rule = RecoveryRule::backup_key(&backup.public_key());
        (
            Identity::create(
                &SigningKey::generate().unwrap(),
                &splint_core::SealingKey::generate().unwrap().public_key(),
                rule,
            )
            .unwrap(),
            backup,
        )
    }

    #[test]
    fn a_contact_met_after_many_others_is_still_held_on_a_replaced_key() {
        let directory = std::env::temp_dir().join(format!("signet-seen-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let (filler, _) = new_identity();
        let one = ContactView::from_identity(&filler).saved().unwrap();
        let others = (0..MANY)
            .map(|number| (format!("other{number}"), one.clone()))
            .collect::<HashMap<_, _>>();
        state_file::save(&directory.join("seen-changes.json"), &others).unwrap();
        let recovered = (0..MANY)
            .map(|number| (format!("other{number}"), filler.encoded()))
            .collect::<HashMap<_, _>>();
        state_file::save(&directory.join("known.json"), &recovered).unwrap();
        let known = Known::load(directory.join("known.json")).unwrap();
        let seen = Seen::load(directory.join("seen-changes.json")).unwrap();

        let (contact, backup) = new_identity();
        seen.note_shown(&contact, None, &known).unwrap();
        let next = SigningKey::generate().unwrap();
        let replaced = contact
            .recover(
                &backup,
                &next.public_key(),
                &splint_core::SealingKey::generate().unwrap().public_key(),
                RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
                1_800_000_000,
            )
            .unwrap();
        known.learn(&replaced).unwrap();
        seen.note_shown(&replaced, None, &known).unwrap();

        let standing = seen.standing(contact.id(), &ChangeRules::default(), &known);
        std::fs::remove_dir_all(&directory).unwrap();
        assert_eq!(standing, Standing::WaitingForHistory);
    }

    /// Bug caught: a rival recovery of a contact's owner read as that owner recovering, so a reader
    /// holding the real recovery went on dealing with whoever made the rival.
    #[test]
    fn a_rival_recovery_of_a_contacts_owner_holds_them_and_the_real_one_carries_on() {
        const NOW: u64 = 1_800_000_000;
        let (agent_key, agent_backup) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        let agent = Identity::create(
            &agent_key,
            &splint_core::SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&agent_backup.public_key()),
        )
        .unwrap();
        let (owner_key, owner_backup) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        let owner = Identity::create(
            &owner_key,
            &splint_core::SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&owner_backup.public_key()),
        )
        .unwrap();
        let recovered = || {
            owner
                .recover(
                    &owner_backup,
                    &SigningKey::generate().unwrap().public_key(),
                    &splint_core::SealingKey::generate().unwrap().public_key(),
                    RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
                    NOW,
                )
                .unwrap()
        };
        let (real, rival) = (recovered(), recovered());
        let half = VerifiedBinding::sign(
            &owner_key,
            &agent_backup,
            owner.id(),
            &agent,
            "ana~host.example",
            1,
            NOW,
        )
        .unwrap();
        let binding = VerifiedBinding::accept(&agent_key, &half, None, &owner, &agent).unwrap();
        let started = VerifiedHistory::empty(&agent)
            .record_binding(&agent_key, &agent, &owner, &binding, NOW)
            .unwrap();
        let rules = ChangeRules {
            key: splint_core::changes::ChangeResponse::Continue,
            ..ChangeRules::default()
        };

        let standing_after = |name: &str, copy: &Identity| {
            let directory = std::env::temp_dir()
                .join(format!("signet-seen-rival-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&directory).unwrap();
            let known = Known::load(directory.join("known.json")).unwrap();
            let seen = Seen::load(directory.join("seen-changes.json")).unwrap();
            seen.take(started.clone(), Heard::ByAsking, &known).unwrap();
            known.learn(&real).unwrap();
            let next = started.record_keys(&agent_key, &agent, copy, NOW).unwrap();
            seen.take(next, Heard::ByNotice, &known).unwrap();
            let standing = seen.standing(agent.id(), &rules, &known);
            let reloaded = Seen::load(directory.join("seen-changes.json")).unwrap();
            let kept = reloaded.standing(agent.id(), &rules, &known);
            std::fs::remove_dir_all(&directory).unwrap();
            (standing, kept)
        };

        assert_eq!(
            standing_after("real", &real),
            (Standing::Continue, Standing::Continue)
        );
        assert_eq!(
            standing_after("rival", &rival),
            (Standing::Rewritten, Standing::Rewritten)
        );
    }
}

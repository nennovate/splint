//! This agent's own history, and who has heard of it so far.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex as ShortLock, PoisonError};

use serde::{Deserialize, Serialize};
use splint_core::changes::VerifiedHistory;
use splint_core::rules::RulesContact;
use splint_core::{Identity, SplintId};

use crate::host_client::HostError;
use crate::state_file::{self, StateError};

const SAVED_HISTORY: &str = "history";
const SAVED_LEFT: &str = "left";
/// Someone listed once stays on this, because they still have to hear what happens next, even after a
/// new owner whose rules don't name them. This is a limit on the file, not a number anyone should reach.
const MAX_LISTENERS: usize = 8192;

/// Someone to tell, and the newest head they've been told.
#[derive(Clone, Serialize, Deserialize)]
struct Listener {
    address: String,
    told: String,
}

/// The host this agent left by a move, until it has the history that says so and the new host has the
/// contacts agreed there back, or a week has gone.
#[derive(Clone, Serialize, Deserialize)]
pub struct Left {
    pub domain: String,
    pub until: u64,
    /// Whether the host left has taken the history that names the new one.
    pub told: bool,
    /// When to give the new host back the contacts agreed by invite next, while any are owed.
    pub pairs_due: Option<u64>,
}

pub struct Own {
    history_path: PathBuf,
    left_path: PathBuf,
    left: ShortLock<Option<Left>>,
    history: ShortLock<VerifiedHistory>,
    listeners_path: PathBuf,
    listeners: ShortLock<HashMap<String, Listener>>,
    /// Whether this history came back from a host after this Signet lost its folder. Who it had told
    /// went with the folder, so everyone named now has to hear, including of what was before.
    restored: AtomicBool,
    /// The newest head this agent's host has answered for. It isn't saved, because hearing the same
    /// history again costs a host nothing.
    host_head: ShortLock<String>,
}

impl Own {
    /// A file that no longer checks out, or is for another ID, counts as none, and the host's copy
    /// brings it back.
    pub fn load(
        history_path: PathBuf,
        listeners_path: PathBuf,
        identity: &Identity,
    ) -> Result<Self, StateError> {
        let mut saved = state_file::load::<String>(&history_path)?;
        let history = saved
            .remove(SAVED_HISTORY)
            .and_then(|text| VerifiedHistory::read(&text).ok())
            .filter(|history| history.id() == identity.id())
            .unwrap_or_else(|| VerifiedHistory::empty(identity));
        let left_path = history_path.with_file_name("left.json");
        let left = state_file::load::<Left>(&left_path)?.remove(SAVED_LEFT);
        Ok(Self {
            history_path,
            left_path,
            left: ShortLock::new(left),
            history: ShortLock::new(history),
            listeners: ShortLock::new(state_file::load(&listeners_path)?),
            listeners_path,
            restored: AtomicBool::new(false),
            host_head: ShortLock::new(String::new()),
        })
    }

    pub fn current(&self) -> VerifiedHistory {
        self.history
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Saved before it counts, so a crash can't send a notice for something that's then forgotten,
    /// which a contact would later see as a rewrite.
    pub fn replace(&self, next: VerifiedHistory) -> Result<(), HostError> {
        let text = next.encoded()?;
        let saved = HashMap::from([(SAVED_HISTORY, text)]);
        state_file::save(&self.history_path, &saved).map_err(|_| HostError::LocalStorage)?;
        *self.history.lock().unwrap_or_else(PoisonError::into_inner) = next;
        Ok(())
    }

    /// The host this agent left, while there's still something to do about it.
    pub fn left(&self) -> Option<Left> {
        self.left
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_left(&self, left: Option<Left>) -> Result<(), HostError> {
        let saved: HashMap<&str, Left> = left.iter().map(|one| (SAVED_LEFT, one.clone())).collect();
        state_file::save(&self.left_path, &saved).map_err(|_| HostError::LocalStorage)?;
        *self.left.lock().unwrap_or_else(PoisonError::into_inner) = left;
        Ok(())
    }

    pub fn restored_from_host(&self, history: VerifiedHistory) -> Result<(), HostError> {
        self.replace(history)?;
        self.restored.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn host_has(&self, head: &str) -> bool {
        *self
            .host_head
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            == head
    }

    pub fn host_took(&self, head: &str) {
        head.clone_into(
            &mut self
                .host_head
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Adds who's new, as having nothing to hear yet, and notes who has moved.
    pub fn note_listeners(&self, contacts: &[RulesContact], head: &str) -> Result<(), HostError> {
        let mut listeners = self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let restored = self.restored.load(Ordering::Relaxed);
        let mut changed = false;
        for contact in contacts {
            let full = listeners.len() >= MAX_LISTENERS;
            match listeners.get_mut(contact.agent.as_str()) {
                Some(listener) if listener.address == contact.address => {}
                Some(listener) => {
                    listener.address.clone_from(&contact.address);
                    changed = true;
                }
                None if full => {}
                None => {
                    let told = if restored { "" } else { head };
                    listeners.insert(
                        contact.agent.as_str().to_owned(),
                        Listener {
                            address: contact.address.clone(),
                            told: told.to_owned(),
                        },
                    );
                    changed = true;
                }
            }
        }
        if changed {
            state_file::save(&self.listeners_path, &listeners)
                .map_err(|_| HostError::LocalStorage)?;
        }
        Ok(())
    }

    pub fn not_yet_told(&self, head: &str) -> Vec<(SplintId, String)> {
        let listeners = self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        listeners
            .iter()
            .filter(|(_, listener)| listener.told != head)
            .filter_map(|(agent, listener)| {
                let agent = serde_json::Value::String(agent.clone());
                let agent = serde_json::from_value(agent).ok()?;
                Some((agent, listener.address.clone()))
            })
            .collect()
    }

    pub fn told(&self, agent: &SplintId, head: &str) -> Result<(), HostError> {
        let mut listeners = self
            .listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(listener) = listeners.get_mut(agent.as_str()) {
            head.clone_into(&mut listener.told);
        }
        state_file::save(&self.listeners_path, &listeners).map_err(|_| HostError::LocalStorage)
    }
}

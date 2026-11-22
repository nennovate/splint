//! What an agent asks its owner's side to add as a contact, and where a contact's host named someone
//! other than the ID the owner signed. Only an owner's signature adds a contact, so an ask does nothing
//! by itself: `owner-key auto`'s hook, or the owner, says yes or doesn't. An agent whose owner lets it
//! add contacts by an invite invites instead, and its ask is refused.
//!
//! An ask makes no call, so an agent naming addresses tells nobody outside this machine anything, at any
//! speed. An address is first looked up once it's in signed rules, and a host answering with any other
//! ID than the one signed finds nobody, so a host lying at either end gets only a stopped contact, which
//! its owner hears about here.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as ShortLock, PoisonError};

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use splint_core::{SplintId, unix_now};

use crate::Signet;
use crate::agent_api::{ApiError, typed_address};
use crate::asks::ASKS_PER_DAY;
use crate::budget::NotTaken;
use crate::host_client::HostError;
use crate::state_file::{self, StateError};

const MAX_ASKS_ON_FILE: usize = 32;
pub const KEEP_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Deserialize, Serialize)]
pub struct Entry {
    pub agent: SplintId,
    pub at: u64,
    /// That address's host answered with another ID than this one, which the owner signed.
    pub disagreed: bool,
    /// What it disagreed with was only pinned, from the first answer at that address, not signed.
    #[serde(default)]
    pub pinned_only: bool,
}

pub struct ContactAsks {
    path: PathBuf,
    /// By address.
    entries: ShortLock<HashMap<String, Entry>>,
}

impl ContactAsks {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        Ok(Self {
            entries: ShortLock::new(state_file::load::<Entry>(&path)?),
            path,
        })
    }

    fn write_down(
        &self,
        change: impl FnOnce(&mut HashMap<String, Entry>) -> bool,
    ) -> Result<(), HostError> {
        let now = unix_now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|_, entry| now.saturating_sub(entry.at) < KEEP_SECS);
        if change(&mut entries) {
            state_file::save(&self.path, &*entries).map_err(|_| HostError::LocalStorage)?;
        }
        Ok(())
    }

    fn ask(&self, address: &str, agent: &SplintId) -> Result<(), ApiError> {
        let mut full = false;
        self.write_down(|entries| {
            let asks = entries.values().filter(|entry| !entry.disagreed).count();
            full = asks >= MAX_ASKS_ON_FILE;
            if full || entries.contains_key(address) {
                return false;
            }
            entries.insert(
                address.to_owned(),
                Entry {
                    agent: agent.clone(),
                    at: unix_now(),
                    disagreed: false,
                    pinned_only: false,
                },
            );
            true
        })?;
        if full {
            return Err(ApiError::TooManyAsks);
        }
        Ok(())
    }

    /// That address's host named someone other than the ID the owner signed.
    pub fn note_disagreement(&self, address: &str, signed: &SplintId) -> Result<(), HostError> {
        self.disagree(address, signed, false)
    }

    /// Someone other than the ID pinned at an address came from there, with a binding naming it.
    pub fn note_disagreement_with_pin(
        &self,
        address: &str,
        pinned: &SplintId,
    ) -> Result<(), HostError> {
        self.disagree(address, pinned, true)
    }

    fn disagree(
        &self,
        address: &str,
        known: &SplintId,
        pinned_only: bool,
    ) -> Result<(), HostError> {
        self.write_down(|entries| {
            if entries.get(address).is_some_and(|entry| {
                entry.disagreed && &entry.agent == known && entry.pinned_only == pinned_only
            }) {
                return false;
            }
            entries.insert(
                address.to_owned(),
                Entry {
                    agent: known.clone(),
                    at: unix_now(),
                    disagreed: true,
                    pinned_only,
                },
            );
            true
        })
    }

    pub fn note_agreement(&self, address: &str) -> Result<(), HostError> {
        self.write_down(|entries| entries.remove(address).is_some())
    }

    /// For when this agent gets a new owner, whose word none of this is.
    pub fn forget_everything(&self) -> Result<(), HostError> {
        self.write_down(|entries| {
            entries.clear();
            true
        })
    }

    /// Everything on file, by address, for its owner to go through.
    pub fn listed(&self) -> Vec<(String, Entry)> {
        let now = unix_now();
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .iter()
            .filter(|(_, entry)| now.saturating_sub(entry.at) < KEEP_SECS)
            .map(|(address, entry)| (address.clone(), entry.clone()))
            .collect()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskRequest {
    address: String,
    id: SplintId,
}

#[derive(Serialize)]
pub struct Asked {
    asked: bool,
}

/// Writes down that this agent would like a contact, with nothing looked up and nothing added.
pub async fn ask(
    State(signet): State<Arc<Signet>>,
    Json(mut body): Json<AskRequest>,
) -> Result<Json<Asked>, ApiError> {
    // An agent that can invite needs nobody's yes for a contact, so an ask would only be a card for
    // its owner to answer. One whose owner asks first, or whose rules predate agreed contacts, still asks.
    if signet.rules.agent_adds_contacts().await {
        return Err(ApiError::InviteInstead);
    }
    body.address = typed_address(&body.address)?;
    if !body.id.is_well_formed() {
        return Err(ApiError::BadRequest("not an agent's ID"));
    }
    signet
        .budget
        .take_contact_ask(ASKS_PER_DAY, unix_now())
        .await
        .map_err(|not_taken| match not_taken {
            NotTaken::Spent => ApiError::TooManyAsks,
            NotTaken::Unsaved => ApiError::Host(HostError::LocalStorage),
        })?;
    signet.contact_asks.ask(&body.address, &body.id)?;
    Ok(Json(Asked { asked: true }))
}

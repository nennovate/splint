//! Interactions an agent asked to start at its owner's `ask_me`. Nothing about one is signed or sent
//! until the owner's device signs a yes to exactly that offer, so it waits here.
//!
//! Only the agent can add to this, up to the owner's `open_approvals`, and each one costs it an action.
//! What it says here counts for nothing: the owner's device works out what it's asked to sign from the
//! offer and the contact's own signed IDs.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex as ShortLock, PoisonError};

use serde::{Deserialize, Serialize};
use splint_core::requests::{InteractionType, Offer, Refused, hold_of};
use splint_core::{MessageId, unix_now};
use tokio::sync::Mutex;

use crate::agent_api::ApiError;
use crate::host_client::HostError;
use crate::requests::Contact;
use crate::requests::store::{Record, started_from};
use crate::state_file::{self, StateError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum HoldStatus {
    Waiting,
    OwnerSaidNo,
    /// Its `open` is signed with the owner's yes and kept to go. Whether its host has it is the
    /// request's `delivery`, as only flushing it learns that. Saved as `sent` before, so read that too.
    #[serde(alias = "sent")]
    Signed {
        request: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HeldOpen {
    pub hold: MessageId,
    pub nonce: String,
    pub offer: Offer,
    pub address: String,
    pub status: HoldStatus,
}

impl HeldOpen {
    pub fn new(nonce: String, offer: Offer, contact: &Contact) -> Self {
        Self {
            hold: hold_of(&nonce),
            nonce,
            offer,
            address: contact.address.clone(),
            status: HoldStatus::Waiting,
        }
    }
}

/// What an agent can read of one: what it asked for itself, and how that went.
#[derive(Serialize)]
pub struct HeldOpenView {
    hold: MessageId,
    contact: String,
    #[serde(rename = "type")]
    interaction: InteractionType,
    deadline: u64,
    #[serde(flatten)]
    status: HoldStatus,
}

pub struct HeldOpens {
    path: PathBuf,
    opens: Mutex<HashMap<String, HeldOpen>>,
    /// Holds an owner's decision is being worked through for. Kept only in memory, so a crash
    /// releases each one, and what it had sent is found again by the record that names its hold.
    claimed: ShortLock<HashSet<String>>,
}

/// One caller's sole right to decide a held open, until it's dropped. Sending takes several waits, and
/// a second decision on the same open must find nothing waiting during them, as it would once this one
/// is settled, or one yes could seal and send two opens with two different IDs.
pub struct Claimed<'a> {
    open: HeldOpen,
    claimed: &'a ShortLock<HashSet<String>>,
}

impl Claimed<'_> {
    pub fn open(&self) -> &HeldOpen {
        &self.open
    }
}

impl Drop for Claimed<'_> {
    fn drop(&mut self) {
        let mut claimed = self.claimed.lock().unwrap_or_else(PoisonError::into_inner);
        claimed.remove(self.open.hold.as_str());
    }
}

impl HeldOpens {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let opens = Mutex::new(state_file::load(&path)?);
        Ok(Self {
            path,
            opens,
            claimed: ShortLock::default(),
        })
    }

    fn save(&self, opens: &HashMap<String, HeldOpen>) -> Result<(), HostError> {
        state_file::save(&self.path, opens).map_err(|_| HostError::LocalStorage)
    }

    /// Keeps one, unless that's more than the owner said can wait for them at once. What's past its
    /// deadline can't start any more, so it goes now.
    pub async fn keep(&self, open: HeldOpen, allowed: u32) -> Result<(), ApiError> {
        let now = unix_now();
        let mut opens = self.opens.lock().await;
        opens.retain(|_, open| open.offer.deadline.at() > now);
        let waiting = opens
            .values()
            .filter(|open| open.status == HoldStatus::Waiting)
            .count();
        if waiting >= usize::try_from(allowed).unwrap_or(usize::MAX) {
            return Err(Refused::OverLimit.into());
        }
        opens.insert(open.hold.as_str().to_owned(), open);
        Ok(self.save(&opens)?)
    }

    pub async fn waiting(&self, now: u64) -> Vec<HeldOpen> {
        let opens = self.opens.lock().await;
        opens
            .values()
            .filter(|open| open.status == HoldStatus::Waiting && open.offer.deadline.at() > now)
            .cloned()
            .collect()
    }

    /// What became of the open held as `hold`, while it's kept.
    pub async fn status_of(&self, hold: &MessageId) -> Option<HoldStatus> {
        let opens = self.opens.lock().await;
        opens.get(hold.as_str()).map(|open| open.status.clone())
    }

    /// The open waiting as `hold`, unless another caller is deciding it now.
    pub async fn claim(&self, hold: &MessageId) -> Option<Claimed<'_>> {
        let opens = self.opens.lock().await;
        let open = opens
            .get(hold.as_str())
            .filter(|open| open.status == HoldStatus::Waiting)?;
        let mut claimed = self.claimed.lock().unwrap_or_else(PoisonError::into_inner);
        claimed.insert(hold.as_str().to_owned()).then(|| Claimed {
            open: open.clone(),
            claimed: &self.claimed,
        })
    }

    /// Only the caller deciding one can say how it went.
    pub async fn settle(&self, claimed: &Claimed<'_>, status: HoldStatus) -> Result<(), HostError> {
        let mut opens = self.opens.lock().await;
        if let Some(open) = opens.get_mut(claimed.open.hold.as_str()) {
            open.status = status;
        }
        self.save(&opens)
    }

    /// For when Signet starts, before anything can claim one. A hold whose `open` was saved, but which
    /// a crash stopped being marked sent, says so now. Otherwise the owner's device would list it as
    /// waiting for a decision already made, and it would count against `open_approvals`, until that
    /// same decision was heard again, which nothing may ever send.
    pub async fn settle_what_went(
        &self,
        records: &HashMap<String, Record>,
    ) -> Result<(), HostError> {
        let mut opens = self.opens.lock().await;
        let mut changed = false;
        for open in opens.values_mut() {
            if open.status != HoldStatus::Waiting {
                continue;
            }
            if let Some((request, _)) = started_from(records, &open.hold) {
                open.status = HoldStatus::Signed {
                    request: request.clone(),
                };
                changed = true;
            }
        }
        if changed {
            self.save(&opens)?;
        }
        Ok(())
    }

    pub async fn views(&self, now: u64) -> Vec<HeldOpenView> {
        let opens = self.opens.lock().await;
        opens
            .values()
            .filter(|open| open.offer.deadline.at() > now)
            .map(|open| HeldOpenView {
                hold: open.hold.clone(),
                contact: open.address.clone(),
                interaction: open.offer.interaction.clone(),
                deadline: open.offer.deadline.at(),
                status: open.status.clone(),
            })
            .collect()
    }

    /// For when this agent gets a new owner, who didn't ask for any of these.
    pub async fn forget_everything(&self) -> Result<(), HostError> {
        let mut opens = self.opens.lock().await;
        opens.clear();
        self.save(&opens)
    }
}

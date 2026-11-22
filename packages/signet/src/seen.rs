//! Messages this agent has already acknowledged.
//!
//! A signature can't tell a replay from the original, and a host could re-insert an old message.
//! Remembering IDs here stops that without trusting the host. An ID is only needed until its
//! message expires, because an expired message fails verification anyway.

use std::collections::HashMap;
use std::path::PathBuf;

use splint_core::{MessageId, SplintId, unix_now};
use tokio::sync::Mutex;

use crate::ending::{Done, InboxRows};
use crate::state_file::{self, StateError};

/// More than a host holds waiting for one agent, so only a host showing what it shouldn't gets here.
const MAX_SHOWN: usize = 4096;

pub struct Seen {
    path: PathBuf,
    /// Message ID to when it expires.
    ids: Mutex<HashMap<String, u64>>,
    /// What the agent was shown and hasn't acknowledged, by message ID. Only in memory, as an ack
    /// after a restart finds the row by reading again.
    shown: Mutex<HashMap<String, Shown>>,
}

/// A message the agent was shown: what clears the row its host keeps it in once the agent acks it,
/// when it expires and who sent it.
#[derive(Clone)]
pub struct Shown {
    pub done: Done<InboxRows>,
    pub expires_at: u64,
    pub sender: SplintId,
}

impl Seen {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let now = unix_now();
        let mut ids: HashMap<String, u64> = state_file::load(&path)?;
        ids.retain(|_, expires_at| *expires_at > now);
        Ok(Self {
            path,
            ids: Mutex::new(ids),
            shown: Mutex::new(HashMap::new()),
        })
    }

    /// Keeps where the host has each message the agent was just shown, so its ack finds them
    /// wherever they are on the host's page by then. A host cuts a page by length and puts a new
    /// sender's first message ahead of an old sender's fifth, so what was shown can be off the page
    /// an ack would read, and would stay to be shown again.
    pub async fn note_shown(&self, rows: Vec<(MessageId, Shown)>) {
        let now = unix_now();
        let mut shown = self.shown.lock().await;
        shown.retain(|_, one| one.expires_at > now);
        if shown.len().saturating_add(rows.len()) > MAX_SHOWN {
            shown.clear();
        }
        for (id, one) in rows {
            shown.insert(id.as_str().to_owned(), one);
        }
    }

    pub async fn shown_at(&self, id: &MessageId) -> Option<Shown> {
        self.shown.lock().await.get(id.as_str()).cloned()
    }

    /// Once the host has cleared them.
    pub async fn forget_shown(&self, ids: &[(MessageId, u64)]) {
        let mut shown = self.shown.lock().await;
        for (id, _) in ids {
            shown.remove(id.as_str());
        }
    }

    /// Where the rows were has changed, so an ack finds each again by reading.
    pub async fn forget_where_shown(&self) {
        self.shown.lock().await.clear();
    }

    pub async fn contains(&self, id: &MessageId) -> bool {
        self.ids.lock().await.contains_key(id.as_str())
    }

    /// Saved before the host is told, so a crash in between can only show a message again, and
    /// never lets a replay through later.
    pub async fn record(&self, messages: &[(MessageId, u64)]) -> Result<(), StateError> {
        let mut ids = self.ids.lock().await;
        for (id, expires_at) in messages {
            ids.insert(id.as_str().to_owned(), *expires_at);
        }
        state_file::save(&self.path, &ids)
    }
}

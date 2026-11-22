//! What was refused, for this agent's owner to read. It's a record of fixed words and IDs Signet has
//! checked, with nothing from a message in it, so a counterparty can't reach an owner through it. A
//! flood can't grow it: repeats add to a count, and only so many are kept.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use splint_core::{SplintId, unix_now};
use tokio::sync::Mutex;

use crate::state_file::{self, StateError};

const MAX_KEPT: usize = 200;
const THE_FILE_KEY: &str = "refused";

/// Which way the refused thing was going.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Way {
    /// This agent tried to send it.
    Out,
    /// It came to this agent.
    In,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Refusal {
    pub at: u64,
    pub way: Way,
    /// The route the agent called, for what went out. It comes from this program, not the agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call: Option<String>,
    /// Who signed it, for what came in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<SplintId>,
    pub reason: String,
    pub count: u32,
}

impl Refusal {
    fn same_as(&self, other: &Self) -> bool {
        self.way == other.way
            && self.call == other.call
            && self.from == other.from
            && self.reason == other.reason
    }
}

pub struct Refusals {
    path: PathBuf,
    kept: Mutex<VecDeque<Refusal>>,
}

impl Refusals {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let mut saved: HashMap<String, VecDeque<Refusal>> = state_file::load(&path)?;
        let kept = saved.remove(THE_FILE_KEY).unwrap_or_default();
        Ok(Self {
            path,
            kept: Mutex::new(kept),
        })
    }

    /// Saved as well as it can be. Failing to write this down mustn't let what was refused through,
    /// or stop the next step being read.
    async fn note(&self, mut refusal: Refusal) {
        let mut kept = self.kept.lock().await;
        if let Some(same) = kept.iter_mut().find(|held| held.same_as(&refusal)) {
            refusal.count = same.count.saturating_add(1);
            *same = refusal;
        } else {
            kept.push_back(refusal);
            while kept.len() > MAX_KEPT {
                kept.pop_front();
            }
        }
        let whole = HashMap::from([(THE_FILE_KEY, kept.clone())]);
        if state_file::save(&self.path, &whole).is_err() {
            tracing::warn!("couldn't write down what was refused");
        }
    }

    pub async fn out(&self, call: &str, reason: String) {
        self.note(Refusal {
            at: unix_now(),
            way: Way::Out,
            call: Some(call.to_owned()),
            from: None,
            reason,
            count: 1,
        })
        .await;
    }

    pub async fn came_in(&self, from: &SplintId, reason: String) {
        self.note(Refusal {
            at: unix_now(),
            way: Way::In,
            call: None,
            from: Some(from.clone()),
            reason,
            count: 1,
        })
        .await;
    }

    /// Newest first.
    pub async fn all(&self) -> Vec<Refusal> {
        let kept = self.kept.lock().await;
        let mut all: Vec<Refusal> = kept.iter().cloned().collect();
        all.sort_by_key(|refusal| std::cmp::Reverse(refusal.at));
        all
    }
}

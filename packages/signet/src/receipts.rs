//! What this Signet owes the senders of notes it opened: a signed `received` naming the note, which is
//! what lets a sender's Signet show `delivered`. Only background code makes one, from a row the checks
//! in `ending` read, so no agent call can send one or hold one back.
//!
//! One goes for each note it will show its agent, from anyone the owner's rules let in with words,
//! strangers let in by reach included (provisional: a business open to anyone confirms to its
//! customers). Never for mail it couldn't open, mail the rules hold or refuse, or a blocked sender's.
//! It says only that this Signet was running and opened the note, not that anyone read it.
//!
//! Each is signed and saved before it's sent, and sent again until its host takes it, so a restart
//! neither loses nor repeats one: a resend is the same bytes, which a host keeps once.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use splint_core::requests::{CheckedStep, is_step_body};
use splint_core::rules::Admission;
use splint_core::{parse_address, unix_now};
use tokio::sync::Mutex;

use crate::Signet;
use crate::ending::{InboxRows, Readable};
use crate::host_client::HostError;
use crate::state_file::{self, StateError};

#[derive(Clone, Serialize, Deserialize)]
struct Owed {
    /// Emptied once its host has it, as only the note's ID is needed then, to send none again.
    compact: String,
    /// The note's sender's host, as the rules said when it was made, so a contact taken out later
    /// doesn't strand it.
    domain: String,
    expires_at: u64,
}

pub struct Receipts {
    path: PathBuf,
    /// By the note's ID, until the receipt expires.
    owed: Mutex<HashMap<String, Owed>>,
}

impl Receipts {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let now = unix_now();
        let mut owed: HashMap<String, Owed> = state_file::load(&path)?;
        owed.retain(|_, one| one.expires_at > now);
        Ok(Self {
            path,
            owed: Mutex::new(owed),
        })
    }

    /// Whether any wait to go, so the loop beside the agent looks again soon.
    pub async fn owing(&self) -> bool {
        self.owed
            .lock()
            .await
            .values()
            .any(|one| !one.compact.is_empty())
    }

    /// For a new owner, who isn't owed what the last one's agent read.
    pub async fn forget_everything(&self) -> Result<(), HostError> {
        let mut owed = self.owed.lock().await;
        owed.clear();
        state_file::save(&self.path, &owed).map_err(|_| HostError::LocalStorage)
    }
}

/// Owes the sender of a note this Signet opened and checked its receipt, once. The caller has found
/// the note fits the day's limits, so it's shown today: the inbox read as it shows it, and a sync pass
/// for a contact's, as the agent may read it only later.
pub async fn owe(signet: &Signet, read: &Readable<InboxRows>) -> Result<(), HostError> {
    let note = read.envelope();
    let sender = note.sender();
    if signet
        .receipts
        .owed
        .lock()
        .await
        .contains_key(note.id().as_str())
    {
        return Ok(());
    }
    if is_step_body(note.body())
        || !signet.rules.exist().await
        || signet.rules.stopped().await
        || signet.recovering()
        || signet.rules.admission_of(sender).await != Admission::Deliver
    {
        return Ok(());
    }
    let Some(contact) = signet.rules.contact_of(sender).await.filter(|c| c.text) else {
        return Ok(());
    };
    let mut owed = signet.receipts.owed.lock().await;
    if owed.contains_key(note.id().as_str()) {
        return Ok(());
    }
    let (_, domain) = parse_address(&contact.address)?;
    let now = unix_now();
    let signed = CheckedStep::note_receipt(note, now)
        .map_err(|_| HostError::LocalStorage)?
        .sign(&signet.key, &signet.who().identity, now)?;
    owed.insert(
        note.id().as_str().to_owned(),
        Owed {
            compact: signed.compact,
            domain: domain.to_owned(),
            expires_at: signed.expires_at,
        },
    );
    state_file::save(&signet.receipts.path, &owed).map_err(|_| HostError::LocalStorage)
}

/// Hands what's owed to this agent's host, beside the steps waiting to go. A host that can't take any
/// now only delays them, and one it refuses for good, such as one the owner's rules now withdraw, is
/// let go. While the rules say stop they stay here, as steps do.
pub async fn flush(signet: &Signet) -> Result<(), HostError> {
    if signet.rules.stopped().await {
        return Ok(());
    }
    let now = unix_now();
    let waiting: Vec<(String, Owed)> = {
        let owed = signet.receipts.owed.lock().await;
        owed.iter()
            .filter(|(_, one)| !one.compact.is_empty() && one.expires_at > now)
            .map(|(id, one)| (id.clone(), one.clone()))
            .collect()
    };
    let mut given = Vec::new();
    let mut refused = Vec::new();
    for (id, one) in &waiting {
        match signet.host.send(&one.compact, &one.domain).await {
            Ok(()) => given.push(id),
            Err(error) if error.try_later() => break,
            Err(HostError::TooMany) => {}
            Err(_) => refused.push(id),
        }
    }
    let mut owed = signet.receipts.owed.lock().await;
    let before = owed.len();
    owed.retain(|_, one| one.expires_at > now);
    let mut changed = owed.len() != before;
    for id in given.iter().chain(&refused) {
        if let Some(one) = owed.get_mut(id.as_str()) {
            one.compact.clear();
            changed = true;
        }
    }
    if changed {
        state_file::save(&signet.receipts.path, &owed).map_err(|_| HostError::LocalStorage)?;
    }
    Ok(())
}

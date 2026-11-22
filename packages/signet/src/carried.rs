//! Mail carried away from a host this agent is leaving. What waits for an agent lives at its host until
//! it's read, and the host it left stops answering for it, so before the address changes every row
//! there is written down here and only then cleared there. From then on those rows are read with
//! whatever its host holds, and go through every check an arrival goes through, as they're still only
//! what a host handed over.
//!
//! No host clears these once they're here, so nothing else would clear one that has expired. A row is
//! let go by its dates, whatever else is wrong with it, as a row the checks can't judge would otherwise
//! stay for good. Those dates are only what the row says, and the host that handed it over could have
//! kept it back anyway, so believing them costs nothing it couldn't already do.
//!
//! A carried row is known by a negative `seq`, which no host row has, never used twice, so an ID shown
//! once can't later clear another row.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use splint_core::host_api::StoredMessage;
use splint_core::{Error, SplintId, claimed_dates_fit, unix_now};
use tokio::sync::Mutex;

use crate::Signet;
use crate::ending::{Done, HeldOff, InboxRows, PutOff};
use crate::host_client::{HostClient, HostError};
use crate::state_file::{self, StateError};

/// Well past what a host holds for one agent, so only a host stuffing this folder reaches them.
const MOST_ROWS: usize = 5_000;
const MOST_BYTES: usize = 128 * 1024 * 1024;
/// Pages read from one host in one go. A host that goes on past this is feeding rows in.
const MOST_PAGES: usize = 100;
/// A host keeps a row put off out of its pages for at most 30 seconds.
const PUT_OFF_SECS: u64 = 31;
const FILE_KEY: &str = "carried";

#[derive(Default, Serialize, Deserialize)]
struct Held {
    /// The last `seq` given out, counting down from zero.
    last: i64,
    rows: Vec<StoredMessage>,
}

fn bytes_of(row: &StoredMessage) -> usize {
    row.envelope
        .len()
        .saturating_add(row.sender_identity.len())
        .saturating_add(row.sender_owner_identity.len())
        .saturating_add(row.sender_binding.len())
        .saturating_add(row.relay_proof.len())
}

fn has_expired(row: &StoredMessage, now: u64) -> bool {
    matches!(claimed_dates_fit(&row.envelope, now), Err(Error::Expired))
}

/// Too late to read, or dated further ahead than any clock could be wrong by.
fn dated_out_of_reach(row: &StoredMessage, now: u64) -> bool {
    matches!(
        claimed_dates_fit(&row.envelope, now),
        Err(Error::Expired | Error::FromTheFuture)
    )
}

/// A host's row that's now written down here, which only [`Carried::keep`] makes, so its host may
/// clear it.
pub struct WrittenDown {
    seq: i64,
}

impl WrittenDown {
    pub fn seq(&self) -> i64 {
        self.seq
    }
}

pub struct Carried {
    path: PathBuf,
    held: Mutex<Held>,
    /// When this Signet last asked its host to put rows off, which hides them from a page for a while.
    put_off_at: AtomicU64,
    /// Until when a move is taking what waits at the host, so nothing there is put off out of its sight.
    carrying_until: AtomicU64,
    /// Which of those it held, unread, and why.
    pub held_off: HeldOff,
}

impl Carried {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let held = state_file::load::<Held>(&path)?
            .remove(FILE_KEY)
            .unwrap_or_default();
        Ok(Self {
            path,
            held: Mutex::new(held),
            put_off_at: AtomicU64::new(0),
            carrying_until: AtomicU64::new(0),
            held_off: HeldOff::default(),
        })
    }

    fn save(&self, held: &Held) -> Result<(), StateError> {
        state_file::save(&self.path, &HashMap::from([(FILE_KEY, held)]))
    }

    /// Writes these down, each once, before anyone clears them at the host, leaving out any dated out
    /// of reach, which take up no room and stay at the host. The host's rows it holds now, or None,
    /// with nothing written, where they wouldn't fit.
    async fn keep(
        &self,
        rows: Vec<StoredMessage>,
        now: u64,
    ) -> Result<Option<Vec<WrittenDown>>, StateError> {
        let mut held = self.held.lock().await;
        let known: HashSet<&str> = held.rows.iter().map(|row| row.envelope.as_str()).collect();
        let readable: Vec<StoredMessage> = rows
            .into_iter()
            .filter(|row| !dated_out_of_reach(row, now))
            .collect();
        let holds: Vec<WrittenDown> = readable
            .iter()
            .map(|row| WrittenDown { seq: row.seq })
            .collect();
        let fresh: Vec<StoredMessage> = readable
            .into_iter()
            .filter(|row| !known.contains(row.envelope.as_str()))
            .collect();
        let bytes = held
            .rows
            .iter()
            .chain(&fresh)
            .map(bytes_of)
            .fold(0, usize::saturating_add);
        if held.rows.len().saturating_add(fresh.len()) > MOST_ROWS || bytes > MOST_BYTES {
            return Ok(None);
        }
        for mut row in fresh {
            held.last = held.last.saturating_sub(1);
            row.seq = held.last;
            held.rows.push(row);
        }
        self.save(&held)?;
        Ok(Some(holds))
    }

    /// What's held, once whatever has expired is cleared.
    async fn rows(&self, now: u64) -> Result<Vec<StoredMessage>, StateError> {
        let mut held = self.held.lock().await;
        let before = held.rows.len();
        held.rows.retain(|row| !has_expired(row, now));
        if held.rows.len() != before {
            self.save(&held)?;
        }
        Ok(held
            .rows
            .iter()
            .map(|row| StoredMessage {
                seq: row.seq,
                envelope: row.envelope.clone(),
                sender_identity: row.sender_identity.clone(),
                sender_owner_identity: row.sender_owner_identity.clone(),
                sender_binding: row.sender_binding.clone(),
                relayed_by: row.relayed_by.clone(),
                relay_proof: row.relay_proof.clone(),
            })
            .collect())
    }

    async fn clear(&self, done: &[Done<InboxRows>]) -> Result<(), StateError> {
        let mut held = self.held.lock().await;
        let before = held.rows.len();
        held.rows
            .retain(|row| !done.iter().any(|one| one.seq() == row.seq));
        if held.rows.len() == before {
            return Ok(());
        }
        self.save(&held)
    }

    /// A move is taking what waits at the host, and looks again within [`PUT_OFF_SECS`]. Until a while
    /// past then, nothing is put off: a step put off on every pass, such as one that can't open yet,
    /// was hidden from every look a move took, and stayed behind at the host it left.
    pub fn carrying(&self, now: u64) {
        self.carrying_until
            .store(now.saturating_add(2 * PUT_OFF_SECS), Ordering::Relaxed);
    }

    /// How long until every row this Signet put off shows on a page again.
    pub fn again_after(&self) -> u64 {
        let at = self.put_off_at.load(Ordering::Relaxed);
        at.saturating_add(PUT_OFF_SECS)
            .saturating_sub(unix_now())
            .min(PUT_OFF_SECS)
    }
}

/// What's waiting for this agent: what it carried here, then its host's page. A host's own row is never
/// taken for a carried one, so a host can't have one cleared. Every read of the inbox and every sync
/// pass comes through here, which is where a carried row that has expired is cleared.
pub async fn pull(signet: &Signet, me: &SplintId) -> Result<Vec<StoredMessage>, HostError> {
    let at_host = signet.host.pull(&signet.key, me).await?;
    let mut rows = signet
        .carried
        .rows(unix_now())
        .await
        .map_err(|_| HostError::LocalStorage)?;
    rows.extend(at_host.into_iter().filter(|row| row.seq > 0));
    Ok(rows)
}

/// Clears these, each from where it's kept.
pub async fn ack(
    signet: &Signet,
    me: &SplintId,
    done: &[Done<InboxRows>],
) -> Result<(), HostError> {
    let (carried, at_host): (Vec<Done<InboxRows>>, Vec<Done<InboxRows>>) =
        done.iter().cloned().partition(|one| one.seq() < 0);
    signet
        .carried
        .clear(&carried)
        .await
        .map_err(|_| HostError::LocalStorage)?;
    if at_host.is_empty() {
        return Ok(());
    }
    signet.host.ack(&signet.key, me, &at_host).await?;
    signet.carried.held_off.forget(&at_host);
    Ok(())
}

/// Puts these off, and says whether any went out of sight at the host. One carried here is simply
/// looked at again on the next pass.
pub async fn later(
    signet: &Signet,
    me: &SplintId,
    put_off: &[PutOff<InboxRows>],
) -> Result<bool, HostError> {
    let at_host: Vec<&PutOff<InboxRows>> = put_off.iter().filter(|one| one.seq() > 0).collect();
    // They're looked at again on the next pass, as a carried one is, and a move takes them meanwhile.
    if at_host.is_empty() || unix_now() < signet.carried.carrying_until.load(Ordering::Relaxed) {
        return Ok(false);
    }
    signet
        .carried
        .put_off_at
        .store(unix_now(), Ordering::Relaxed);
    signet.host.later(&signet.key, me, &at_host).await?;
    Ok(true)
}

/// What taking the mail from a host came to.
pub struct Took {
    pub carried: usize,
    /// Rows are left there, as there's no room here for them.
    pub full: bool,
}

/// Takes everything a host shows as waiting for this agent, a page at a time, each written down here
/// before it's cleared there, so a failure at any point loses nothing. A row dated out of reach is
/// neither written down nor cleared: dates that don't fit this clock prove nothing, so it stays at
/// that host until it expires there. Once a page holds nothing new to write down, the rest is those.
pub async fn take_from(signet: &Signet, host: &HostClient) -> Result<Took, HostError> {
    let who = signet.who();
    let me = who.identity.id();
    let mut carried = 0_usize;
    for _ in 0..MOST_PAGES {
        let rows = host.pull(&signet.key, me).await?;
        let Some(holds) = signet
            .carried
            .keep(rows, unix_now())
            .await
            .map_err(|_| HostError::LocalStorage)?
        else {
            return Ok(Took {
                carried,
                full: true,
            });
        };
        if holds.is_empty() {
            return Ok(Took {
                carried,
                full: false,
            });
        }
        signet.seen.forget_where_shown().await;
        let done: Vec<Done<InboxRows>> = holds.iter().map(Done::written_down).collect();
        host.ack(&signet.key, me, &done).await?;
        carried = carried.saturating_add(holds.len());
    }
    Ok(Took {
        carried,
        full: true,
    })
}

#[cfg(test)]
mod tests {
    use splint_core::{
        CLOCK_TOLERANCE_SECS, Identity, RecoveryRule, SealingKey, SigningKey, sign_envelope,
    };

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const LIFE: u64 = 3_600;

    fn written_at(created_at: u64) -> StoredMessage {
        let key = SigningKey::generate().unwrap();
        let backup = RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key());
        let seal = SealingKey::generate().unwrap().public_key();
        let sender = Identity::create(&key, &seal, backup).unwrap();
        let signed = sign_envelope(
            &key,
            &sender,
            sender.id(),
            "hello".to_owned(),
            created_at,
            LIFE,
        )
        .unwrap();
        StoredMessage {
            seq: 7,
            envelope: signed.compact,
            sender_identity: sender.encoded(),
            sender_owner_identity: String::new(),
            sender_binding: String::new(),
            relayed_by: String::new(),
            relay_proof: String::new(),
        }
    }

    /// A host being left could plant mail that no check clears, and that no host would ever clear here.
    #[tokio::test]
    async fn mail_out_of_date_is_never_kept_and_what_expires_here_leaves_the_file() {
        let directory = std::env::temp_dir().join(format!("signet-carried-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("carried-mail.json");
        let carried = Carried::load(path.clone()).unwrap();

        let expired = written_at(NOW - LIFE);
        let too_far_ahead = written_at(NOW + CLOCK_TOLERANCE_SECS + 1);
        let live = written_at(NOW);
        let just_ahead = written_at(NOW + CLOCK_TOLERANCE_SECS);
        let (live_envelope, ahead_envelope) = (live.envelope.clone(), just_ahead.envelope.clone());
        let holds = carried
            .keep(vec![expired, too_far_ahead, live, just_ahead], NOW)
            .await
            .unwrap()
            .map(|holds| holds.len());
        assert_eq!(holds, Some(2));
        let envelopes = |rows: Vec<StoredMessage>| -> Vec<String> {
            rows.into_iter().map(|row| row.envelope).collect()
        };
        assert_eq!(
            envelopes(carried.rows(NOW).await.unwrap()),
            [live_envelope.clone(), ahead_envelope.clone()]
        );

        // The second it ends it's gone, and stays gone once Signet restarts.
        carried.rows(NOW + LIFE).await.unwrap();
        let restarted = Carried::load(path).unwrap();
        assert_eq!(
            envelopes(restarted.rows(NOW).await.unwrap()),
            [ahead_envelope]
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

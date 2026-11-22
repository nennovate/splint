//! Whether this agent's owner has retired it, for good. A retired agent's host refuses its proofs, and
//! a lookup answers 404 for a retired agent as for one never there, so on its own a refusal says
//! nothing. What counts is the retirement itself, signed by this agent's owner, which its host keeps
//! for its contacts and hands to anyone. A host can withhold one, but never make one up.
//!
//! Once this agent holds one it's kept here, so it counts after a restart with its host gone, and at
//! whatever address this Signet is started at. No host's answer takes it away: only a recovery of the
//! owner's ID past the key that signed it does, which the owner's backup signs and no host can forge.
//!
//! What this can't know is a retirement that never reached it: one signed while its host was already
//! away, or that its host withholds. It's asked of the host it's leaving as it moves, and a host that
//! doesn't answer can't hold an agent there.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::{Duration, Instant};

use splint_core::host_api::RetirementNotice;
use splint_core::{Identity, VerifiedStop};

use crate::Signet;
use crate::host_client::HostClient;
use crate::state_file::{self, StateError};
use crate::who::Who;

/// A refusal comes on every pass while retired, so its host is asked at most this often.
const ASK_AGAIN_AFTER: Duration = Duration::from_secs(60);
const HELD: &str = "retirement";

pub struct Retired {
    path: PathBuf,
    held: Mutex<Option<RetirementNotice>>,
    asked_at: Mutex<Option<Instant>>,
}

impl Retired {
    /// Nothing held yet, and kept at `path` once something is.
    pub fn kept_at(path: PathBuf) -> Self {
        Self {
            path,
            held: Mutex::new(None),
            asked_at: Mutex::new(None),
        }
    }

    /// What was kept, checked again as it was when it came. A file that doesn't check out has been
    /// changed, so Signet doesn't start on it and go on as an agent nobody retired.
    pub fn load(path: PathBuf, who: &Who) -> Result<Self, StateError> {
        let held = state_file::load::<RetirementNotice>(&path)?.remove(HELD);
        let retired = Self::kept_at(path);
        if let Some(notice) = held {
            let stop = VerifiedStop::verify(&notice)
                .ok()
                .filter(|stop| is_this_agents(stop, who))
                .ok_or(StateError)?;
            if stop.leaves_retired(&who.owner, false) {
                *retired.lock_held() = Some(notice);
            } else {
                retired.forget();
            }
        }
        Ok(retired)
    }

    fn lock_held(&self) -> std::sync::MutexGuard<'_, Option<RetirementNotice>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn is(&self) -> bool {
        self.lock_held().is_some()
    }

    /// Its owner's ID recovered, which undoes what the key given up signed. One the new key signed
    /// goes on counting.
    pub fn owner_recovered(&self, owner: &Identity) {
        let undone = self.lock_held().as_ref().is_some_and(|notice| {
            VerifiedStop::verify(notice).map_or(true, |stop| !stop.leaves_retired(owner, false))
        });
        if undone {
            *self.lock_held() = None;
            self.forget();
        }
    }

    /// Written down before it counts, and it counts even if it can't be: its host can say so again.
    fn hold(&self, notice: RetirementNotice) {
        if state_file::save(&self.path, &HashMap::from([(HELD, &notice)])).is_err() {
            tracing::warn!("couldn't write down this agent's retirement, so a restart asks again");
        }
        *self.lock_held() = Some(notice);
    }

    fn forget(&self) {
        let nothing: HashMap<&str, RetirementNotice> = HashMap::new();
        if state_file::save(&self.path, &nothing).is_err() {
            tracing::warn!("couldn't clear a retirement a recovery undid, so the next start will");
        }
    }

    /// Whether it's time to ask the host again, noting that it's being asked now.
    fn due(&self) -> bool {
        let mut asked_at = self.asked_at.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if asked_at.is_some_and(|at| now.duration_since(at) < ASK_AGAIN_AFTER) {
            return false;
        }
        *asked_at = Some(now);
        true
    }
}

fn is_this_agents(stop: &VerifiedStop, who: &Who) -> bool {
    stop.agent().id() == who.identity.id() && stop.owner().id() == who.owner.id()
}

/// Asks a host for this agent's retirement, and keeps one that counts: only one this agent's own owner
/// signed for this agent, and that the copy of the owner's ID held here hasn't recovered past. Anything
/// else a host answers, or its not answering, changes nothing.
async fn ask(signet: &Signet, host: &HostClient) {
    let who = signet.who();
    let notice = match host.retirement_of(who.identity.id()).await {
        Ok(notice) => notice,
        Err(error) => {
            tracing::debug!(%error, "couldn't ask a host whether this agent is retired");
            return;
        }
    };
    let stop = VerifiedStop::verify(&notice)
        .ok()
        .filter(|stop| is_this_agents(stop, &who));
    let Some(stop) = stop else {
        tracing::warn!("a host gave a retirement that doesn't check out, so it counts for nothing");
        return;
    };
    if stop.leaves_retired(&who.owner, false) && !signet.retired.is() {
        tracing::warn!("this agent's owner has retired it, for good");
        signet.retired.hold(notice);
    }
}

/// Asks this agent's host for its retirement, after the host refused it, and says whether it's retired.
pub async fn learn(signet: &Signet) -> bool {
    if signet.retired.due() {
        ask(signet, &signet.host).await;
    }
    signet.retired.is()
}

/// Whether this agent is retired, asking the host it's leaving at once, for one that hasn't reached it
/// yet. A host that's gone says nothing, so it can't keep an agent from leaving.
pub async fn before_leaving(signet: &Signet, domain: &str) -> bool {
    if !signet.retired.is()
        && let Ok(host) = HostClient::new(domain.to_owned(), signet.host.scheme)
    {
        ask(signet, &host).await;
    }
    signet.retired.is()
}

/// Takes a newer copy of the owner's ID from this agent's host, which proves itself, so a recovery that
/// undid this retirement counts here with nobody having to bring it. The caller doesn't hold `changing_who`.
pub async fn hear_of_a_recovery(signet: &Signet) {
    let owner = signet.who().owner.id().clone();
    if let Ok(copy) = signet.host.known_owner(&owner).await {
        crate::recovery::hear_of_owner(signet, &copy).await;
    }
}

/// As [`hear_of_a_recovery`], at most once a minute, as a retired agent's passes go on for good.
pub async fn now_and_then_hear_of_a_recovery(signet: &Signet) {
    if signet.retired.due() {
        hear_of_a_recovery(signet).await;
    }
}

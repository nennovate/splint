//! How many actions this agent has taken in the last day, against the ceiling its owner signed, and
//! how many messages of its own words it has sent each contact, against the protocol's cap.
//!
//! An action is a step or message the agent chose to send. A `received` and an owner's own decision
//! aren't the agent's, so they don't count. What's counted is saved before the action goes, so a
//! restart can't hand an agent a fresh day.

use std::collections::HashMap;
use std::path::PathBuf;

use splint_core::outbound::TextRefused;
use splint_core::requests::{Fields, Refused, Schema};
use splint_core::{MessageId, SplintId, unix_now};
use tokio::sync::Mutex;

use crate::Signet;
use crate::agent_api::ApiError;
use crate::host_client::HostError;
use crate::state_file::{self, StateError};

const DAY_SECS: u64 = 24 * 60 * 60;
const HOUR_SECS: u64 = 60 * 60;
const SAVED: &str = "taken";
const TEXTS_TO: &str = "texts_to:";
const NEW_REQUESTS_TO: &str = "new_requests_to:";
const NEW_REQUESTS_FROM: &str = "new_requests_from:";
const TEXTS_FROM: &str = "texts_from:";
const NEW_FROM_OTHERS: &str = "new_from_others";
const NEW_FROM_UNCONFIRMED: &str = "new_from_unconfirmed";
const COUNTED_ONCE: &str = "counted:";
const CONTACT_ASKS: &str = "contact_asks";
const DELEGATED: &str = "delegated";
const INVITES: &str = "invites";
const PROPOSALS_TO: &str = "proposals_to:";
const PROPOSALS_FROM: &str = "proposals_from:";

/// What's passed with one contact in the last day, each way, by the counters every limit uses.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct Today {
    pub texts_from: u32,
    pub texts_to: u32,
    pub new_requests_from: u32,
    pub new_requests_to: u32,
}

pub struct Budget {
    path: PathBuf,
    /// When each action in the last day was taken, under `taken`, and each message of free text sent
    /// to a contact, under that contact.
    taken: Mutex<HashMap<String, Vec<u64>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NotTaken {
    Spent,
    /// The count couldn't be saved, so the action can't go: a restart would forget it.
    Unsaved,
}

use NotTaken::{Spent, Unsaved};

impl Budget {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        Ok(Self {
            taken: Mutex::new(state_file::load::<Vec<u64>>(&path)?),
            path,
        })
    }

    /// Counts one action, unless `allowed` have been taken in the last day.
    pub async fn take(&self, allowed: u32, now: u64) -> Result<(), NotTaken> {
        self.take_from(SAVED, allowed, None, now).await
    }

    /// The same, and unless `per_hour` have been taken in the last hour.
    pub async fn take_within_hour(
        &self,
        allowed: u32,
        per_hour: Option<u32>,
        now: u64,
    ) -> Result<(), NotTaken> {
        self.take_from(SAVED, allowed, per_hour, now).await
    }

    /// Counts one interaction started with this contact, unless `allowed` have in the last day.
    pub async fn take_new_request_to(
        &self,
        to: &SplintId,
        allowed: u32,
        now: u64,
    ) -> Result<(), NotTaken> {
        let key = format!("{NEW_REQUESTS_TO}{to}");
        self.take_from(&key, allowed, None, now).await
    }

    /// Counts one `type/1` this agent proposes to this contact, unless the day's are spent.
    pub async fn take_proposal_to(&self, to: &SplintId, now: u64) -> Result<(), NotTaken> {
        let key = format!("{PROPOSALS_TO}{to}");
        self.take_from(&key, proposals_per_day(), None, now).await
    }

    /// The same for one this contact proposes to this agent, which their Signet is meant to hold to the
    /// same count, and may not.
    pub async fn take_proposal_from(&self, from: &SplintId, now: u64) -> Result<(), NotTaken> {
        let key = format!("{PROPOSALS_FROM}{from}");
        self.take_from(&key, proposals_per_day(), None, now).await
    }

    /// The same for one this contact started with us.
    pub async fn take_new_request_from(
        &self,
        from: &SplintId,
        allowed: u32,
        now: u64,
    ) -> Result<(), NotTaken> {
        let key = format!("{NEW_REQUESTS_FROM}{from}");
        self.take_from(&key, allowed, None, now).await
    }

    /// Counts one yes the owner's delegate says by itself, unless `allowed` have been in the last day,
    /// and says whether it counted it now. The same draft seen again doesn't count again.
    pub async fn take_delegated(
        &self,
        draft: &str,
        allowed: u32,
        now: u64,
    ) -> Result<bool, NotTaken> {
        let counted = format!("{COUNTED_ONCE}{DELEGATED}:{draft}");
        if self.taken.lock().await.contains_key(&counted) {
            return Ok(false);
        }
        self.take_from(DELEGATED, allowed, None, now).await?;
        self.take_from(&counted, u32::MAX, None, now).await?;
        Ok(true)
    }

    /// Whether [`Self::take_delegated`] would count this draft now, or already has, counting nothing.
    pub async fn has_room_delegated(&self, draft: &str, allowed: u32, now: u64) -> bool {
        let all = self.taken.lock().await;
        if all.contains_key(&format!("{COUNTED_ONCE}{DELEGATED}:{draft}")) {
            return true;
        }
        let today = all.get(DELEGATED).map_or(0, |times| {
            times
                .iter()
                .filter(|at| now.saturating_sub(**at) < DAY_SECS)
                .count()
        });
        today < usize::try_from(allowed).unwrap_or(usize::MAX)
    }

    /// Gives back the yes [`Self::take_delegated`] just counted for this draft, when it didn't go. It
    /// was saved before it could go, so a restart can't hand out a fresh day, and nothing that went is
    /// ever given back. A give-back that can't be saved leaves it counted, which errs the safe way.
    pub async fn give_back_delegated(&self, draft: &str, taken_at: u64) {
        let counted = format!("{COUNTED_ONCE}{DELEGATED}:{draft}");
        let mut all = self.taken.lock().await;
        let mut given_back = all.clone();
        if given_back.remove(&counted).is_none() {
            return;
        }
        if let Some(times) = given_back.get_mut(DELEGATED)
            && let Some(at) = times.iter().rposition(|at| *at == taken_at)
        {
            times.remove(at);
        }
        match state_file::save(&self.path, &given_back) {
            Ok(()) => *all = given_back,
            Err(_) => {
                tracing::warn!("couldn't save a delegated yes given back, so it stays counted")
            }
        }
    }

    /// Counts one invite this agent tried, unless `allowed` have been in the last day.
    pub async fn take_invite(&self, allowed: u32, now: u64) -> Result<(), NotTaken> {
        self.take_from(INVITES, allowed, None, now).await
    }

    /// Counts one contact this agent asked for, unless `allowed` have been in the last day.
    pub async fn take_contact_ask(&self, allowed: u32, now: u64) -> Result<(), NotTaken> {
        self.take_from(CONTACT_ASKS, allowed, None, now).await
    }

    /// Counts one message of a contact's words as it first comes to be shown, unless `allowed` have
    /// been in the last day. A message is shown again until it's acked, and that doesn't count again.
    pub async fn take_text_from(
        &self,
        from: &SplintId,
        message: &MessageId,
        allowed: u32,
        now: u64,
    ) -> Result<(), NotTaken> {
        let key = format!("{TEXTS_FROM}{from}");
        self.take_once(message, &key, allowed, now).await
    }

    /// Whether a message of a contact's words would be shown today, counting nothing: one already
    /// counted always is, and any other only while fewer than `allowed` have been in the last day.
    pub async fn text_from_fits(
        &self,
        from: &SplintId,
        message: &MessageId,
        allowed: u32,
        now: u64,
    ) -> bool {
        let key = format!("{TEXTS_FROM}{from}");
        let all = self.taken.lock().await;
        if all.contains_key(&format!("{COUNTED_ONCE}{key}:{message}")) {
            return true;
        }
        let today = all.get(&key).map_or(0, |times| {
            times
                .iter()
                .filter(|at| now.saturating_sub(**at) < DAY_SECS)
                .count()
        });
        today < usize::try_from(allowed).unwrap_or(usize::MAX)
    }

    /// How many of each have come from `from`, and gone to them, in the last day, counting nothing.
    pub async fn today_with(&self, peer: &SplintId, now: u64) -> Today {
        let all = self.taken.lock().await;
        let count = |prefix: &str| -> u32 {
            all.get(&format!("{prefix}{peer}")).map_or(0, |times| {
                let within = times
                    .iter()
                    .filter(|at| now.saturating_sub(**at) < DAY_SECS)
                    .count();
                u32::try_from(within).unwrap_or(u32::MAX)
            })
        };
        Today {
            texts_from: count(TEXTS_FROM),
            texts_to: count(TEXTS_TO),
            new_requests_from: count(NEW_REQUESTS_FROM),
            new_requests_to: count(NEW_REQUESTS_TO),
        }
    }

    /// Counts one thing from someone let in by reach, against the owner's total for all of them.
    pub async fn take_new_from_others(
        &self,
        message: &MessageId,
        allowed: u32,
        now: u64,
    ) -> Result<(), NotTaken> {
        self.take_once(message, NEW_FROM_OTHERS, allowed, now).await
    }

    /// Counts one thing from someone whose owner hasn't confirmed, against one part of that total for
    /// all of them together, so IDs that cost nothing to make can't use up what's left for everyone else.
    /// `others` is the whole total, which takes this too.
    pub async fn take_new_from_unconfirmed(
        &self,
        message: &MessageId,
        others: u32,
        now: u64,
    ) -> Result<(), NotTaken> {
        let share = others
            .div_ceil(splint_core::rules::UNCONFIRMED_SHARE_OF_QUOTA)
            .max(1);
        self.take_once(message, NEW_FROM_UNCONFIRMED, share, now)
            .await?;
        self.take_new_from_others(message, others, now).await
    }

    async fn take_once(
        &self,
        message: &MessageId,
        key: &str,
        allowed: u32,
        now: u64,
    ) -> Result<(), NotTaken> {
        let counted = format!("{COUNTED_ONCE}{key}:{message}");
        if self.taken.lock().await.contains_key(&counted) {
            return Ok(());
        }
        self.take_from(key, allowed, None, now).await?;
        self.take_from(&counted, u32::MAX, None, now).await
    }

    async fn take_from(
        &self,
        key: &str,
        allowed: u32,
        per_hour: Option<u32>,
        now: u64,
    ) -> Result<(), NotTaken> {
        self.take_each(&[(key, allowed, per_hour)], now)
            .await
            .map_err(|(_, not_taken)| not_taken)
    }

    /// Counts one against each of `counts`, a key with its day's and hour's limits, or against none:
    /// a refusal of one costs nothing on the others. Says which was spent by its place.
    async fn take_each(
        &self,
        counts: &[(&str, u32, Option<u32>)],
        now: u64,
    ) -> Result<(), (usize, NotTaken)> {
        let mut all = self.taken.lock().await;
        for times in all.values_mut() {
            times.retain(|at| now.saturating_sub(*at) < DAY_SECS);
        }
        all.retain(|_, times| !times.is_empty());
        for (place, (key, allowed, per_hour)) in counts.iter().enumerate() {
            let taken = all.get(*key).map_or(&[][..], Vec::as_slice);
            if taken.len() >= usize::try_from(*allowed).unwrap_or(usize::MAX) {
                return Err((place, Spent));
            }
            if let Some(per_hour) = per_hour {
                let this_hour = taken
                    .iter()
                    .filter(|at| now.saturating_sub(**at) < HOUR_SECS)
                    .count();
                if this_hour >= usize::try_from(*per_hour).unwrap_or(usize::MAX) {
                    return Err((place, Spent));
                }
            }
        }
        for (key, ..) in counts {
            all.entry((*key).to_owned()).or_default().push(now);
        }
        if state_file::save(&self.path, &*all).is_err() {
            for (key, ..) in counts {
                if let Some(times) = all.get_mut(*key) {
                    times.pop();
                }
            }
            return Err((0, Unsaved));
        }
        Ok(())
    }

    /// Counts one message of free text to this contact and the action it costs, or neither: unless
    /// `texts` have gone to them in the last day, or the day's or hour's actions are used up.
    pub async fn take_text_and_action(
        &self,
        to: &SplintId,
        texts: u32,
        actions: u32,
        actions_per_hour: Option<u32>,
        now: u64,
    ) -> Result<(), TextNotTaken> {
        let key = format!("{TEXTS_TO}{to}");
        self.take_each(
            &[(&key, texts, None), (SAVED, actions, actions_per_hour)],
            now,
        )
        .await
        .map_err(|refused| match refused {
            (0, Spent) => TextNotTaken::TooManyTexts,
            (_, Spent) => TextNotTaken::OverLimit,
            (_, Unsaved) => TextNotTaken::Unsaved,
        })
    }
}

/// Why a message of words wasn't counted, which also says it cost nothing.
#[derive(Debug, PartialEq, Eq)]
pub enum TextNotTaken {
    TooManyTexts,
    OverLimit,
    Unsaved,
}

/// Counts one message of this agent's own words to a contact against the owner's daily limit on
/// words, and the action it is against the day's actions, both or neither.
pub async fn spend_text_and_action(signet: &Signet, to: &SplintId) -> Result<(), ApiError> {
    let texts = signet.rules.texts_per_day_with(to).await;
    let (actions, per_hour) = actions_allowed(signet).await;
    signet
        .budget
        .take_text_and_action(to, texts, actions, per_hour, unix_now())
        .await
        .map_err(|not_taken| match not_taken {
            TextNotTaken::TooManyTexts => ApiError::Text(TextRefused::TooManyTexts),
            TextNotTaken::OverLimit => Refused::OverLimit.into(),
            TextNotTaken::Unsaved => ApiError::Host(HostError::LocalStorage),
        })
}

/// Counts one interaction going to a contact, against the owner's daily limit. The sums in
/// `docs/protocol.md` rest on this.
fn proposals_per_day() -> u32 {
    u32::try_from(splint_core::requests::PROPOSALS_PER_CONTACT_PER_DAY).unwrap_or(u32::MAX)
}

/// Counts one `type/1` this agent proposes to `to`, unless two have gone to them in the last day.
pub async fn spend_proposal(signet: &Signet, to: &SplintId) -> Result<(), ApiError> {
    match signet.budget.take_proposal_to(to, unix_now()).await {
        Ok(()) => Ok(()),
        Err(Spent) => Err(Refused::TooManyProposals.into()),
        Err(Unsaved) => Err(HostError::LocalStorage.into()),
    }
}

pub async fn spend_new_request(signet: &Signet, to: &SplintId) -> Result<(), ApiError> {
    let allowed = signet.rules.new_requests_per_day_with(to).await;
    signet
        .budget
        .take_new_request_to(to, allowed, unix_now())
        .await
        .map_err(|not_taken| match not_taken {
            Spent => Refused::OverLimit.into(),
            Unsaved => ApiError::Host(HostError::LocalStorage),
        })
}

/// Counts one action by this agent against what its owner's level allows in a day, and any limit the
/// owner signed on what it sends. Its host counts those too, but a host can be modified to ignore them.
pub async fn spend(signet: &Signet) -> Result<(), ApiError> {
    let (allowed, per_hour) = actions_allowed(signet).await;
    signet
        .budget
        .take_within_hour(allowed, per_hour, unix_now())
        .await
        .map_err(|not_taken| match not_taken {
            Spent => Refused::OverLimit.into(),
            Unsaved => ApiError::Host(HostError::LocalStorage),
        })
}

/// The day's actions and the hour's sends the owner signed.
async fn actions_allowed(signet: &Signet) -> (u32, Option<u32>) {
    let allowed = signet
        .rules
        .permissions()
        .await
        .map_or(0, |permissions| permissions.actions_allowed_per_day());
    let (per_hour, per_day) = signet.rules.sends_signed().await;
    (
        per_day.map_or(allowed, |per_day| allowed.min(per_day)),
        per_hour,
    )
}

/// Refuses fields over a cap the owner set on this type, below full auto. `agreed` is the offer on
/// the table, for the unit a value is in when the step doesn't carry it.
pub async fn check_caps(
    signet: &Signet,
    schema: &Schema,
    fields: &Fields,
    agreed: &Fields,
) -> Result<(), ApiError> {
    let fits = signet
        .rules
        .permissions()
        .await
        .is_some_and(|permissions| permissions.fits_caps(schema, fields, agreed));
    if fits {
        Ok(())
    } else {
        Err(Refused::OverLimit.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_day_of_actions_runs_out_and_comes_back_and_a_restart_doesnt_reset_it() {
        let directory = std::env::temp_dir().join(format!("signet-budget-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("budget.json");
        let now = 1_793_750_400;
        let budget = Budget::load(path.clone()).unwrap();
        assert_eq!(budget.take(2, now).await, Ok(()));
        assert_eq!(budget.take(2, now + 1).await, Ok(()));
        assert_eq!(budget.take(2, now + 2).await, Err(Spent));

        let restarted = Budget::load(path).unwrap();
        assert_eq!(restarted.take(2, now + 3).await, Err(Spent));
        assert_eq!(restarted.take(2, now + DAY_SECS).await, Ok(()));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[tokio::test]
    async fn a_signed_hourly_limit_stops_actions_until_the_hour_has_passed() {
        let directory = std::env::temp_dir().join(format!("signet-hour-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("budget.json");
        let now = 1_793_750_400;
        let budget = Budget::load(path).unwrap();
        assert_eq!(budget.take_within_hour(50, Some(2), now).await, Ok(()));
        assert_eq!(budget.take_within_hour(50, Some(2), now + 1).await, Ok(()));
        assert_eq!(
            budget.take_within_hour(50, Some(2), now + 2).await,
            Err(Spent)
        );
        assert_eq!(budget.take_within_hour(50, None, now + 3).await, Ok(()));
        assert_eq!(
            budget.take_within_hour(50, Some(3), now + 4).await,
            Err(Spent)
        );
        assert_eq!(
            budget
                .take_within_hour(50, Some(3), now + HOUR_SECS + 4)
                .await,
            Ok(())
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// Bugs caught: words past one contact's cap costing an action, and words the day's actions refuse
    /// using up that contact's words, so an agent retrying at its limit is refused early tomorrow.
    #[tokio::test]
    async fn words_and_their_actions_count_together_or_not_at_all() {
        use TextNotTaken::{OverLimit, TooManyTexts};
        let directory = std::env::temp_dir().join(format!("signet-texts-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("budget.json");
        let now = 1_793_750_400;
        let ben: SplintId =
            serde_json::from_value(serde_json::json!(format!("splint1{}", "b".repeat(64))))
                .unwrap();
        let cy: SplintId =
            serde_json::from_value(serde_json::json!(format!("splint1{}", "c".repeat(64))))
                .unwrap();
        let budget = Budget::load(path.clone()).unwrap();
        for at in 0..20 {
            let taken = budget.take_text_and_action(&ben, 20, 100, None, now + at);
            assert_eq!(taken.await, Ok(()));
        }
        let past_the_cap = budget.take_text_and_action(&ben, 20, 100, None, now + 100);
        assert_eq!(past_the_cap.await, Err(TooManyTexts));
        let restarted = Budget::load(path).unwrap();
        let after_restart = restarted.take_text_and_action(&ben, 20, 100, None, now + 101);
        assert_eq!(after_restart.await, Err(TooManyTexts));
        let to_cy = restarted.take_text_and_action(&cy, 20, 100, None, now + 101);
        assert_eq!(to_cy.await, Ok(()));
        // 21 actions so far: the refused words cost none.
        assert_eq!(restarted.take(22, now + 101).await, Ok(()));
        let no_actions_left = restarted.take_text_and_action(&cy, 20, 22, None, now + 102);
        assert_eq!(no_actions_left.await, Err(OverLimit));
        // Cy has had one message, so a cap of two still lets the next through.
        let cy_again = restarted.take_text_and_action(&cy, 2, 100, None, now + 103);
        assert_eq!(cy_again.await, Ok(()));
        let next_day = restarted.take_text_and_action(&ben, 20, 100, None, now + DAY_SECS);
        assert_eq!(next_day.await, Ok(()));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[tokio::test]
    async fn an_action_that_cant_be_saved_isnt_counted() {
        let directory =
            std::env::temp_dir().join(format!("signet-budget-unsaved-{}", std::process::id()));
        let path = directory.join("budget.json");
        let budget = Budget::load(path).unwrap();
        let now = 1_793_750_400;
        assert_eq!(budget.take(1, now).await, Err(Unsaved));

        std::fs::create_dir_all(&directory).unwrap();
        assert_eq!(budget.take(1, now + 1).await, Ok(()));
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

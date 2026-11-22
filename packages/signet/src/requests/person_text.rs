//! A person's words on their way out. The owner's device signs them, and this holds them until the
//! agent's next step that can carry them, which Signet puts them on itself. The agent API has no field
//! for them, and reading them back here takes the owner's token, so a fooled agent can't write or copy
//! them. All it can do is choose which of its own moves they go out on.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::requests::{CheckedStep, Refused, RequestState, VerifiedPersonText};
use splint_core::{CLOCK_TOLERANCE_SECS, Identity, MessageId, SplintId, unix_now};
use tokio::sync::Mutex;

use crate::Signet;
use crate::agent_api::ApiError;
use crate::host_client::HostError;
use crate::requests::owner_api::require_owner_token;
use crate::state_file::{self, StateError};
use crate::who::Who;

/// By the request they're for, or for an `open`, by the contact. Only an owner's signature adds to
/// this, so nobody else can grow it, and newer words for the same place replace older ones.
pub struct Waiting {
    path: PathBuf,
    texts: Mutex<HashMap<String, String>>,
    taken_path: PathBuf,
    /// Words taken in the last week, by ID, with when they were signed, kept after they've gone. Words
    /// that go out reach the contact, and anyone between, signed, so without this they could be handed
    /// back to go again. Nothing signed before that is taken at all, so this is all it needs.
    taken: Mutex<HashMap<String, u64>>,
}

/// How long words taken are remembered, and so how old words can be to be taken. As long as a host
/// keeps what an owner signed for its Signet to collect.
const REMEMBER_TAKEN_SECS: u64 = 7 * 24 * 60 * 60;

/// Whether words signed then are recent enough to be taken. Both what's taken and what's forgotten
/// ask this, so nothing is forgotten while its date would still let it back in.
fn recent_enough(issued_at: u64, now: u64) -> bool {
    issued_at.saturating_add(REMEMBER_TAKEN_SECS) >= now
}

/// Whether these words were taken before, or are too old to tell. By ID rather than by date, so an
/// owner's other device, with a clock behind this one, can still speak.
fn taken_before(taken: &HashMap<String, u64>, words: &VerifiedPersonText, now: u64) -> bool {
    !recent_enough(words.issued_at(), now) || taken.contains_key(words.id().as_str())
}

/// Where a person's words wait: an ID can't be mistaken for a request, which has no prefix.
pub fn place_of(to: &SplintId, request: Option<&MessageId>) -> String {
    request.map_or_else(|| to.as_str().to_owned(), |id| id.as_str().to_owned())
}

impl Waiting {
    pub fn load(path: PathBuf, taken_path: PathBuf) -> Result<Self, StateError> {
        let texts = Mutex::new(state_file::load(&path)?);
        let taken = Mutex::new(state_file::load(&taken_path)?);
        Ok(Self {
            path,
            texts,
            taken_path,
            taken,
        })
    }

    /// Puts what's waiting for this place on this step, if anything fits it. Says whether it did, so
    /// it comes off the list once the step is saved. What the owner's old key signed stops counting
    /// after a recovery, and stays here until words signed by the new one replace it.
    pub async fn put_on(&self, step: &mut CheckedStep, place: &str, who: &Who) -> bool {
        let texts = self.texts.lock().await;
        let Some(compact) = texts.get(place) else {
            return false;
        };
        let Ok(words) = VerifiedPersonText::verify(compact, &who.owner) else {
            return false;
        };
        words.agent() == who.identity.id() && step.carry(&words)
    }

    /// Words a saved step now carries. A failure here can only mean the next step carries them again,
    /// which a reader shows once, so it doesn't stop the step they went out on.
    pub async fn went_out(&self, place: &str) {
        let mut texts = self.texts.lock().await;
        texts.remove(place);
        if state_file::save(&self.path, &texts).is_err() {
            tracing::warn!("couldn't save that a person's words have gone");
        }
    }

    /// Holds these words for their place, in place of older ones there, unless they were taken before.
    async fn keep(
        &self,
        place: String,
        words: &VerifiedPersonText,
        owner: &Identity,
        now: u64,
    ) -> Result<(), ApiError> {
        let mut texts = self.texts.lock().await;
        let holding = texts
            .get(&place)
            .and_then(|held| VerifiedPersonText::verify(held, owner).ok());
        // The owner's device trying again, which changes nothing.
        if holding.as_ref().is_some_and(|held| held.id() == words.id()) {
            return Ok(());
        }
        // Only a replay can come with an older date, and it can't bring back what the owner replaced.
        if holding.is_some_and(|held| held.issued_at() > words.issued_at()) {
            return Err(Refused::BadPersonText.into());
        }
        let mut taken = self.taken.lock().await;
        if taken_before(&taken, words, now) {
            return Err(Refused::BadPersonText.into());
        }
        let before = taken.clone();
        taken.retain(|_, issued_at| recent_enough(*issued_at, now));
        taken.insert(words.id().as_str().to_owned(), words.issued_at());
        // Taken is saved first, so words held are always words it remembers taking.
        let before_text = texts.insert(place.clone(), words.compact().to_owned());
        let saved = state_file::save(&self.taken_path, &*taken).is_ok()
            && state_file::save(&self.path, &*texts).is_ok();
        if !saved {
            match before_text {
                Some(before) => texts.insert(place, before),
                None => texts.remove(&place),
            };
            *taken = before;
            return Err(HostError::LocalStorage.into());
        }
        Ok(())
    }

    /// For when this agent gets a new owner, who doesn't get to speak with the last one's words.
    pub async fn forget_everything(&self) -> Result<(), HostError> {
        let mut texts = self.texts.lock().await;
        let mut taken = self.taken.lock().await;
        texts.clear();
        taken.clear();
        state_file::save(&self.path, &texts).map_err(|_| HostError::LocalStorage)?;
        state_file::save(&self.taken_path, &taken).map_err(|_| HostError::LocalStorage)
    }
}

pub fn routes(signet: Arc<Signet>) -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/owner/person-text", get(waiting))
        .route_layer(middleware::from_fn_with_state(signet, require_owner_token))
        .route("/v0/owner/person-text", post(hold))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldBody {
    pub person_text: String,
}

#[derive(Serialize)]
pub struct Held {
    to: SplintId,
    request: Option<MessageId>,
}

/// Authorized by the owner's signature, so a fooled agent, which can reach this too, can't add to it.
pub async fn hold(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<HoldBody>,
) -> Result<Json<Held>, ApiError> {
    crate::recovery::hear_of_new_keys(&signet, &body.person_text).await;
    let who = signet.who();
    let words = VerifiedPersonText::verify(&body.person_text, &who.owner)?;
    let dated_ahead = words.issued_at() > unix_now().saturating_add(CLOCK_TOLERANCE_SECS);
    if words.agent() != who.identity.id() || dated_ahead {
        return Err(Refused::BadPersonText.into());
    }
    if signet.rules.contact_of(words.to()).await.is_none() {
        return Err(ApiError::NotAContact);
    }
    if let Some(request) = words.request() {
        check_request_can_carry(&signet, request, words.to()).await?;
    }
    let place = place_of(words.to(), words.request());
    let held = Json(Held {
        to: words.to().clone(),
        request: words.request().cloned(),
    });
    signet
        .requests
        .person_texts
        .keep(place, &words, &who.owner, unix_now())
        .await?;
    signet.owner_signed.note(&body.person_text).await;
    Ok(held)
}

/// Words for a request that's over would wait for a step that can never come.
async fn check_request_can_carry(
    signet: &Signet,
    request: &MessageId,
    to: &SplintId,
) -> Result<(), ApiError> {
    let records = signet.requests.store.lock().await;
    let record = records.get(request.as_str()).ok_or(ApiError::NotFound)?;
    if Identity::from_encoded(&record.peer_identity)?.id() != to {
        return Err(Refused::BadPersonText.into());
    }
    let over = matches!(
        record.chain(signet)?.state_at(unix_now()),
        RequestState::Completed
            | RequestState::Declined
            | RequestState::Cancelled
            | RequestState::Disputed
            | RequestState::Expired
    );
    if over {
        return Err(Refused::OutOfTurn.into());
    }
    Ok(())
}

#[derive(Serialize)]
pub struct WaitingList {
    pub(crate) waiting: Vec<WaitingWords>,
}

#[derive(Serialize)]
pub(crate) struct WaitingWords {
    to: SplintId,
    request: Option<MessageId>,
    text: String,
    issued_at: u64,
}

/// What hasn't gone yet, for the owner to see. It goes out when the agent next moves, and not before.
async fn waiting(State(signet): State<Arc<Signet>>) -> Json<WaitingList> {
    Json(waiting_list(&signet).await)
}

pub async fn waiting_list(signet: &Signet) -> WaitingList {
    let who = signet.who();
    let texts = signet.requests.person_texts.texts.lock().await;
    let waiting = texts
        .values()
        .filter_map(|held| VerifiedPersonText::verify(held, &who.owner).ok())
        .map(|words| WaitingWords {
            to: words.to().clone(),
            request: words.request().cloned(),
            text: words.text().to_owned(),
            issued_at: words.issued_at(),
        })
        .collect();
    WaitingList { waiting }
}

#[cfg(test)]
mod tests {
    use splint_core::requests::PersonTextFor;
    use splint_core::{RecoveryRule, SealingKey, SigningKey, random_nonce};

    use super::*;

    fn identity(key: &SigningKey) -> Identity {
        let backup = SigningKey::generate().unwrap().public_key();
        Identity::create(
            key,
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&backup),
        )
        .unwrap()
    }

    /// A folder of this test's own, removed however the test ends, so nothing it leaves can change
    /// what a later run finds.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("signet-person-texts-{}", random_nonce().unwrap()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn load(&self) -> Waiting {
            Waiting::load(self.0.join("texts.json"), self.0.join("taken.json")).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// An owner signing words for its agent to say to one contact.
    struct Owner {
        key: SigningKey,
        identity: Identity,
        agent: Identity,
        contact: Identity,
    }

    impl Owner {
        fn new() -> Self {
            let key = SigningKey::generate().unwrap();
            Self {
                identity: identity(&key),
                key,
                agent: identity(&SigningKey::generate().unwrap()),
                contact: identity(&SigningKey::generate().unwrap()),
            }
        }

        fn words(&self, text: &str, issued_at: u64) -> VerifiedPersonText {
            let for_step = PersonTextFor {
                agent: self.agent.id(),
                to: self.contact.id(),
                request: None,
            };
            let signed =
                VerifiedPersonText::sign(&self.key, self.identity.id(), for_step, text, issued_at)
                    .unwrap();
            VerifiedPersonText::verify(&signed, &self.identity).unwrap()
        }
    }

    /// Words go out to the contact signed, so the contact, or a host between, can hand the same words
    /// back, dated exactly as they were, and after Signet has restarted.
    #[tokio::test]
    async fn words_that_went_out_are_never_taken_again() {
        let owner = Owner::new();
        let scratch = Scratch::new();
        let now = 1_000_000_000;
        let first = owner.words("Only mornings, please.", now);
        let waiting = scratch.load();
        assert!(
            waiting
                .keep("place".into(), &first, &owner.identity, now)
                .await
                .is_ok()
        );
        assert!(
            waiting
                .keep("place".into(), &first, &owner.identity, now)
                .await
                .is_ok(),
            "the owner's device trying again"
        );
        waiting.went_out("place").await;

        let restarted = scratch.load();
        assert!(
            restarted
                .keep("place".into(), &first, &owner.identity, now)
                .await
                .is_err(),
            "words that went out, handed back"
        );
        let from_a_clock_behind = owner.words("Or Friday.", now - 300);
        assert!(
            restarted
                .keep("place".into(), &from_a_clock_behind, &owner.identity, now)
                .await
                .is_ok()
        );
        let older_than_remembered = owner.words("Any time.", now - REMEMBER_TAKEN_SECS - 1);
        assert!(
            restarted
                .keep(
                    "elsewhere".into(),
                    &older_than_remembered,
                    &owner.identity,
                    now
                )
                .await
                .is_err()
        );

        let week_later = now + REMEMBER_TAKEN_SECS + 301;
        let newest = owner.words("Afternoons now.", week_later);
        assert!(
            restarted
                .keep("elsewhere".into(), &newest, &owner.identity, week_later)
                .await
                .is_ok()
        );
        assert_eq!(
            restarted.taken.lock().await.len(),
            1,
            "what's past a week is let go"
        );
        assert!(
            restarted
                .keep("third".into(), &first, &owner.identity, week_later)
                .await
                .is_err(),
            "and refused by its date instead"
        );
    }

    /// Letting go of what was taken mustn't come before the date stops letting it in, or the words
    /// could go out twice in between.
    #[tokio::test]
    async fn words_are_remembered_for_as_long_as_their_date_lets_them_in() {
        let owner = Owner::new();
        let scratch = Scratch::new();
        let now = 1_000_000_000;
        let waiting = scratch.load();
        let first = owner.words("Only mornings, please.", now);
        assert!(
            waiting
                .keep("place".into(), &first, &owner.identity, now)
                .await
                .is_ok()
        );
        waiting.went_out("place").await;

        let last_moment = now + REMEMBER_TAKEN_SECS;
        let later = owner.words("Or Friday.", last_moment);
        assert!(
            waiting
                .keep("elsewhere".into(), &later, &owner.identity, last_moment)
                .await
                .is_ok(),
            "taking these lets go of what's past remembering"
        );
        assert!(
            waiting
                .keep("place".into(), &first, &owner.identity, last_moment)
                .await
                .is_err(),
            "words that went out, handed back on the last day they'd be let in"
        );
    }
}

//! This agent's place on its host. A Signet registers once its owner has signed a binding for it.
//!
//! The binding can't come first: it names the agent's ID, and that hashes a key only Signet holds.
//! So Signet starts with the owner's identity, shows its own, and waits for the owner's signature.
//! It adds its own half of the statement, for an owner's half that checks out and nothing else.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::routing::put;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::asks::move_approval_lapsed;
use splint_core::registration_state::RegistrationState;
use splint_core::{Error, Identity, VerifiedBinding, parse_address, unix_now};
use tokio::sync::watch;

use crate::Signet;
use crate::agent_api::ApiError;
use crate::changes;
use crate::host_client::HostError;
use crate::who::Who;

/// Said when a move can't be written in this agent's history, which holds a few dozen owner's choices.
pub const NO_ROOM_TO_MOVE: &str =
    "this agent's history holds as many owner's choices as it can, so it can't move host";
/// How soon a host that didn't answer is tried again, so a blip is over before anyone sees it.
const FIRST_RETRY: Duration = Duration::from_millis(500);
/// The longest a host that doesn't answer waits for the next try, which is how long an agent can stay
/// away after its host is back. Every agent on a host that was down comes back at about this pace.
const LONGEST_RETRY: Duration = Duration::from_secs(15);
/// A host that answered no, or that's at a limit, won't change its mind in a moment.
const AFTER_A_REFUSAL: Duration = Duration::from_secs(60);

struct Standing {
    state: RegistrationState,
    /// What its host last said, in Signet's fixed words, while it hasn't taken this agent.
    problem: Option<String>,
}

pub struct Registered {
    signup_code: String,
    standing: watch::Sender<Standing>,
    /// Whether the last look at its host found nobody there, which can come long after it signed on.
    host_away: AtomicBool,
}

impl Registered {
    pub fn new(signup_code: String) -> Self {
        Self {
            signup_code,
            standing: watch::Sender::new(Standing {
                state: RegistrationState::NotBound,
                problem: None,
            }),
            host_away: AtomicBool::new(false),
        }
    }

    /// What the last call to its host came to.
    pub fn heard_from_host(&self, answered: bool) {
        self.host_away.store(!answered, Ordering::Relaxed);
    }

    pub fn host_answering(&self) -> bool {
        !self.host_away.load(Ordering::Relaxed)
    }

    fn set(&self, state: RegistrationState, problem: Option<String>) -> RegistrationState {
        self.standing
            .send_replace(Standing { state, problem })
            .state
    }

    pub fn state(&self) -> RegistrationState {
        self.standing.borrow().state
    }

    pub fn problem(&self) -> Option<String> {
        self.standing.borrow().problem.clone()
    }

    pub fn is_done(&self) -> bool {
        self.state() == RegistrationState::Registered
    }

    /// Still going to its host with a binding it hasn't taken, so what needs that host has to wait.
    pub fn is_trying(&self) -> bool {
        self.state().keeps_trying()
    }

    /// Returns once this Signet has stopped going to its host to sign on, at once if it never was. What
    /// runs beside it waits here, as its host would refuse all of it until then, and goes on the moment
    /// its host takes this agent back, however seldom it otherwise looks.
    pub async fn until_settled(&self) {
        let mut standing = self.standing.subscribe();
        // The sender lives as long as this does, so this can only end by being settled.
        let _ = standing.wait_for(|now| !now.state.keeps_trying()).await;
    }

    /// It holds what gave it a place at a host, so it can ask to move from there, whatever that host
    /// says of it now.
    pub fn has_a_place(&self) -> bool {
        self.state().holds_a_binding()
    }

    /// What it held no longer counts, so its owner has to sign again.
    pub fn lost_its_binding(&self) {
        self.set(RegistrationState::NotBound, None);
    }
}

/// The binding saved here, while it's one this agent can sign on with. With none there's nothing to say
/// yet, and one that no longer fits is left alone, because the owner has to sign a new one. That's also
/// what keeps an old binding from going anywhere once this agent runs at another address.
fn who_can_sign_on(signet: &Signet) -> Option<Arc<Who>> {
    let who = signet.who();
    if who.binding.is_empty() || signet.recovering() {
        return None;
    }
    VerifiedBinding::verify_for(&who.binding, &who.owner, &who.identity, &signet.address())
        .is_ok()
        .then_some(who)
}

/// Writes down whether this agent has anything to sign back on with after a restart, and says so.
pub fn note_what_is_saved(signet: &Signet) -> bool {
    if who_can_sign_on(signet).is_some() {
        signet.registered.set(RegistrationState::Starting, None);
        return true;
    }
    if !signet.who().binding.is_empty() && !signet.recovering() {
        tracing::warn!("the saved binding doesn't fit this agent, so it needs a new one");
    }
    false
}

/// Signs back on after a restart, for as long as it takes, beside everything else this Signet does. Who
/// this agent is gets read afresh under `changing_who` for each try, so a try can't cross an owner's
/// statement going through, and it ends once what's saved can't be used any more.
pub async fn keep_registering(signet: Arc<Signet>) {
    let mut wait = FIRST_RETRY;
    loop {
        let pause = {
            let _changing = signet.changing_who.lock().await;
            if signet.registered.is_done() {
                return;
            }
            let Some(who) = who_can_sign_on(&signet) else {
                signet.registered.lost_its_binding();
                return;
            };
            match register(&signet, &who.identity, &who.owner, &who.binding).await {
                Ok(()) => return,
                Err(error) => after_a_failed_try(&signet, &error, &mut wait).await,
            }
        };
        let Some(pause) = pause else {
            return;
        };
        tokio::time::sleep(pause).await;
    }
}

/// What a try came to, and how long until the next, or `None` where trying again can't help. It's
/// logged when it changes, as a host can stay away for a long time.
async fn after_a_failed_try(
    signet: &Signet,
    error: &HostError,
    wait: &mut Duration,
) -> Option<Duration> {
    let soon = *wait;
    let (state, pause) = match error {
        HostError::Unreachable => (RegistrationState::HostUnreachable, Some(soon)),
        // Waiting won't set a clock right, but someone can, and then this signs on by itself.
        HostError::ClockOff(_) => (RegistrationState::ClockOff, Some(soon)),
        HostError::TooMany | HostError::AtJoinLimit(_) => {
            (RegistrationState::HostBusy, Some(AFTER_A_REFUSAL))
        }
        HostError::OtherProtocol(_) => (RegistrationState::OtherProtocol, Some(AFTER_A_REFUSAL)),
        HostError::SignupCodeRefused => (RegistrationState::SignupCodeRefused, None),
        HostError::NameTaken => (RegistrationState::NameTaken, None),
        // Its owner reaches it here, so it stays up to hear from them.
        HostError::OutOfDate => (RegistrationState::NeedsOwner, None),
        // Retired, it stays up to say so, and never tries again.
        HostError::Refused if crate::retired::learn(signet).await => {
            (RegistrationState::NeedsOwner, None)
        }
        // What answers at a host that's gone can say anything, so this agent stays able to move away.
        _ => (RegistrationState::HostRefused, Some(AFTER_A_REFUSAL)),
    };
    *wait = soon.saturating_mul(2).min(LONGEST_RETRY);
    if signet.registered.set(state, Some(error.to_string())) != state {
        tracing::warn!(%error, ?state, "our host hasn't taken this agent back yet");
    }
    pause
}

pub async fn register(
    signet: &Signet,
    identity: &Identity,
    owner: &Identity,
    binding: &str,
) -> Result<(), HostError> {
    // Here for every way an agent signs on, at any host: what its owner ended stays ended.
    if signet.retired.is() {
        return Err(HostError::Refused);
    }
    signet
        .host
        .register(
            &signet.key,
            identity,
            owner,
            binding,
            &signet.registered.signup_code,
        )
        .await?;
    signet.registered.set(RegistrationState::Registered, None);
    signet.registered.heard_from_host(true);
    tracing::info!(agent = %identity.id(), address = %signet.address(), "signet registered");
    Ok(())
}

/// For a binding on another host than the one this agent was bound at, the host it leaves. Such a move
/// is refused here, before anything is registered there, if the history this agent keeps has no room
/// to say so, as contacts would then never hear and drop what the new host relays; or if the owner
/// approved it longer ago than an ask lasts, so an approval nobody took up can't be used months later.
fn host_left(
    signet: &Signet,
    who: &Who,
    binding: &VerifiedBinding,
) -> Result<Option<String>, ApiError> {
    if who.binding.is_empty() {
        return Ok(None);
    }
    let Ok(before) = VerifiedBinding::verify(&who.binding, &who.owner, &who.identity) else {
        return Ok(None);
    };
    let domain = |address: &str| {
        parse_address(address)
            .map(|(_, domain)| domain.to_owned())
            .map_err(ApiError::NotBound)
    };
    let (from, to) = (domain(before.address())?, domain(binding.address())?);
    if from == to {
        return Ok(None);
    }
    let now = unix_now();
    if move_approval_lapsed(binding.issued_at(), now) {
        return Err(ApiError::NotBound(Error::Stale));
    }
    let next = signet
        .own_changes
        .current()
        .record_keys(&signet.key, &who.identity, &who.owner, now)
        .and_then(|next| next.record_binding(&signet.key, &who.identity, &who.owner, binding, now));
    if next.is_err() {
        return Err(ApiError::BadRequest(NO_ROOM_TO_MOVE));
    }
    Ok(Some(from))
}

pub fn routes() -> Router<Arc<Signet>> {
    Router::new().route("/v0/owner/binding", put(take_binding))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingBody {
    binding: String,
}

#[derive(Serialize)]
pub(crate) struct Bound {
    agent_id: splint_core::SplintId,
    address: String,
}

/// Authorized by the owner's signature, like every owner call that changes something. A fooled agent
/// can reach this and can't forge one, or use one made for another address or agent.
pub(crate) async fn take_binding(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<BindingBody>,
) -> Result<Json<Bound>, ApiError> {
    if signet.recovering() {
        return Err(ApiError::Stopped);
    }
    crate::recovery::hear_of_new_keys(&signet, &body.binding).await;
    // A recovery of its owner is the one thing that undoes a retirement, and they may have just made one.
    if signet.retired.is() {
        crate::retired::hear_of_a_recovery(&signet).await;
    }
    let _changing = signet.changing_who.lock().await;
    if signet.retired.is() {
        return Err(ApiError::Retired);
    }
    let who = signet.who();
    let binding =
        VerifiedBinding::accept(&signet.key, &body.binding, None, &who.owner, &who.identity)
            .map_err(ApiError::NotBound)?;
    if binding.address() != signet.address() {
        return Err(ApiError::NotBound(Error::ProofMismatch));
    }
    binding
        .may_replace(&who.owner, who.binding_seq())
        .map_err(ApiError::NotBound)?;
    let left = host_left(&signet, &who, &binding)?;
    // Asked of the host it's leaving at the last moment, for a retirement that hasn't reached it yet.
    if let Some(domain) = &left
        && crate::retired::before_leaving(&signet, domain).await
    {
        return Err(ApiError::Retired);
    }
    register(&signet, &who.identity, &who.owner, binding.compact()).await?;
    // Written down before the binding counts, so nothing that cuts this short can leave an agent moved
    // with the host it left never told.
    if let Some(domain) = &left {
        changes::moved_from(&signet, domain)?;
    }
    let bound = signet.replace_who(Who {
        identity: who.identity.clone(),
        owner: who.owner.clone(),
        binding: binding.compact().to_owned(),
    });
    if let Err(error) = bound {
        if left.is_some() {
            let _ = signet.own_changes.set_left(None);
        }
        return Err(error.into());
    }
    if left.is_some() {
        changes::follow_up_a_move(Arc::clone(&signet));
    } else {
        changes::bring_up_to_date(&signet).await?;
        changes::publish_now(&signet).await;
    }
    Ok(Json(Bound {
        agent_id: who.identity.id().clone(),
        address: signet.address(),
    }))
}

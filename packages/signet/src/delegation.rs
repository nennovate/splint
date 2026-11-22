//! What this Signet does for its owner while they're away, under the delegation they signed: say yes
//! to a `confirm` within the caps they set.
//!
//! The delegate key is made here on first start and never leaves this folder. No call returns it. An
//! agent sharing an OS user with this Signet can still read it, so nothing here is what holds the
//! owner's limits: every reader checks what the delegate signed against the delegation it carries.
//! This Signet keeps to the owner's rules as well, acts only while the rules in force name the
//! delegation it holds, and counts the day's yeses, which no reader can.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::middleware;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::delegation::{DelegateKey, Delegated, VerifiedDelegation};
use splint_core::requests::{Action, ApprovalDraft, RequestState, Schema, VerifiedApproval};
use splint_core::rules::{AutoDecision, Level, VerifiedRules};
use splint_core::unix_now;
use tokio::sync::{Mutex, MutexGuard};

use crate::Signet;
use crate::agent_api::ApiError;
use crate::host_client::HostError;
use crate::requests::agent_api::make_move;
use crate::requests::owner_api::require_owner_token;
use crate::requests::types;
use crate::state_file::{self, StateError};
use crate::who::Who;

const KEY_FILE: &str = "delegate.key";
const SAVED_FILE: &str = "delegation.json";
const SAVED: &str = "delegation";
/// Long enough for a pass that only looks, and short enough that an inbox read isn't held up by one
/// waiting on a host.
const WAIT_FOR_A_PASS: std::time::Duration = std::time::Duration::from_secs(1);

pub struct Delegation {
    key_path: PathBuf,
    path: PathBuf,
    /// The key and the delegation held for it, under one lock, so a new key drops the delegation in
    /// the same step, and one pass of [`act`] runs at a time, which the day's count relies on.
    held: Mutex<Held>,
}

pub(crate) struct Held {
    pub(crate) key: DelegateKey,
    delegation: Option<String>,
}

impl Held {
    /// The delegation, while the owner's signature on it holds under who they are now, it's in date,
    /// it names this key, and the rules in force name it. A recovery, a new owner, or rules naming
    /// another delegation or none end it, with nothing else to do.
    fn in_force(&self, who: &Who, rules: &VerifiedRules, now: u64) -> Option<VerifiedDelegation> {
        let held = self.delegation.as_deref()?;
        VerifiedDelegation::reload(held, &who.owner, &who.identity)
            .ok()
            .filter(|delegation| {
                now < delegation.expires_at()
                    && delegation.names(&self.key)
                    && rules.names_delegation(delegation)
            })
    }

    /// The one held, whatever the rules say, if it still verifies and names this key.
    fn taken(&self, who: &Who) -> Option<VerifiedDelegation> {
        let held = self.delegation.as_deref()?;
        VerifiedDelegation::reload(held, &who.owner, &who.identity)
            .ok()
            .filter(|delegation| delegation.names(&self.key))
    }
}

impl Delegation {
    /// The key is made the first time, readable only by whoever runs Signet.
    pub fn load(state: &Path) -> Result<Self, StateError> {
        let key_path = state.join(KEY_FILE);
        let key = DelegateKey::load_or_create(&key_path).map_err(|_| StateError)?;
        let path = state.join(SAVED_FILE);
        let delegation = state_file::load::<String>(&path)?.remove(SAVED);
        Ok(Self {
            key_path,
            path,
            held: Mutex::new(Held { key, delegation }),
        })
    }

    /// Whether the delegation held still verifies for who this agent acts for, and names this key.
    pub(crate) async fn counts_for(&self, who: &Who) -> bool {
        self.held.lock().await.taken(who).is_some()
    }

    /// Where the key is kept, which a replacement writes whole before it's used.
    pub(crate) fn key_file(&self) -> &Path {
        &self.key_path
    }

    /// The key, held until the guard goes, so it can't change under a check made with it.
    pub(crate) async fn held(&self) -> MutexGuard<'_, Held> {
        self.held.lock().await
    }
}

/// Says yes to what the delegation allows. Says whether it did anything.
pub async fn act(signet: &Signet, now: u64) -> bool {
    let who = signet.who();
    let held = signet.delegation.held.lock().await;
    let Some(rules) = signet.rules.current().await else {
        return false;
    };
    let Some(delegation) = held.in_force(&who, &rules, now) else {
        return false;
    };
    approve_within_caps(signet, &who, &held.key, &delegation, now).await
}

/// Every `confirm` the owner's rules let their device sign by itself that also fits the delegation's
/// caps, up to the smaller of the two daily limits, with someone the owner approved. Everything else
/// waits for the owner.
async fn approve_within_caps(
    signet: &Signet,
    who: &Who,
    key: &DelegateKey,
    delegation: &VerifiedDelegation,
    now: u64,
) -> bool {
    if !delegation.may(Delegated::ApproveWithinCaps) {
        return false;
    }
    let Some(current) = signet.rules.current().await else {
        return false;
    };
    let permissions = current.permissions();
    if !current.in_force(now) || permissions.level == Level::AskMe {
        return false;
    }
    let allowed = delegation
        .actions_per_day()
        .min(permissions.approvals_allowed_per_day());
    let mut acted = false;
    for (request, draft) in confirm_drafts(signet, now).await {
        let Some(schema) = signet.requests.types.schema_of(&draft) else {
            continue;
        };
        let owners = types::as_owner_reads(signet, types::peer_of(&draft), &schema).await;
        let Some(signed) = signed_within(who, key, delegation, &current, &owners, &draft, now)
        else {
            continue;
        };
        let approval =
            match VerifiedApproval::verify_carried(&signed, &who.owner, &who.identity, &schema) {
                Ok(approval) => approval,
                Err(refused) => {
                    tracing::warn!(%refused, "our own delegated yes doesn't check out");
                    continue;
                }
            };
        // Counted, and saved, only once there's a yes that verifies, and before it can go, so a
        // restart can't hand out a fresh day. The same draft seen again doesn't count again.
        let counted = counted_as(&draft);
        let Ok(newly) = signet.budget.take_delegated(&counted, allowed, now).await else {
            continue;
        };
        match make_move(signet, &request, Action::Confirm(approval)).await {
            Ok(_) => {
                tracing::info!(%request, "said yes within the owner's caps");
                acted = true;
            }
            Err(_) => {
                tracing::debug!(%request, "a delegated yes didn't go");
                // Nothing went, so the day's count is for a yes that's still to come.
                if newly {
                    signet.budget.give_back_delegated(&counted, now).await;
                }
            }
        }
    }
    acted
}

/// How the day's count knows a draft, so the same one seen again doesn't count again.
fn counted_as(draft: &ApprovalDraft) -> String {
    format!(
        "{}:{}:{}",
        draft.request.as_str(),
        draft.prev.as_str(),
        draft.version
    )
}

/// The delegate's yes to this draft, if the owner's rules let their device sign it by itself and it
/// fits the delegation's caps, with someone the owner approved.
fn signed_within(
    who: &Who,
    key: &DelegateKey,
    delegation: &VerifiedDelegation,
    current: &VerifiedRules,
    schema: &Schema,
    draft: &ApprovalDraft,
    now: u64,
) -> Option<String> {
    let ours = &draft.agent == who.identity.id() && &draft.owner == who.owner.id();
    // A value with someone the owner hasn't approved waits for them, whatever the caps say, and so
    // does anything with a contact the agent made itself, which the sending host refuses a delegate.
    let counterparty = current.counterparty(draft);
    if !ours
        || !current.delegate_may_answer_in(draft)
        || current.permissions().decide(schema, draft, 0, counterparty) != AutoDecision::Sign
    {
        return None;
    }
    delegation.approve(key, draft, schema, now).ok()
}

/// Whether the delegate's next pass says yes to this draft by itself, by the checks that pass makes,
/// so an agent isn't told its person has to sign what signs itself. A pass under way holds the key, and
/// past a short wait this says no, which only means the agent tells its person when it needn't.
pub(crate) async fn signs_by_itself(signet: &Signet, draft: &ApprovalDraft, now: u64) -> bool {
    let Ok(held) = tokio::time::timeout(WAIT_FOR_A_PASS, signet.delegation.held.lock()).await
    else {
        return false;
    };
    let who = signet.who();
    let Some(current) = signet.rules.current().await else {
        return false;
    };
    let Some(delegation) = held.in_force(&who, &current, now) else {
        return false;
    };
    let permissions = current.permissions();
    if !delegation.may(Delegated::ApproveWithinCaps)
        || !current.in_force(now)
        || permissions.level == Level::AskMe
    {
        return false;
    }
    let Some(schema) = signet.requests.types.schema_of(draft) else {
        return false;
    };
    let owners = types::as_owner_reads(signet, types::peer_of(draft), &schema).await;
    let allowed = delegation
        .actions_per_day()
        .min(permissions.approvals_allowed_per_day());
    signed_within(&who, &held.key, &delegation, &current, &owners, draft, now).is_some()
        && signet
            .budget
            .has_room_delegated(&counted_as(draft), allowed, now)
            .await
}

async fn confirm_drafts(signet: &Signet, now: u64) -> Vec<(String, ApprovalDraft)> {
    let records = signet.requests.store.lock().await;
    let mut drafts = Vec::new();
    for (request, record) in records.iter() {
        let Ok(chain) = record.chain(signet) else {
            continue;
        };
        if chain.state_at(now) == RequestState::Expired {
            continue;
        }
        if let Some(draft) = chain.confirm_draft(record.role, now) {
            drafts.push((request.clone(), draft));
        }
    }
    drafts
}

pub fn routes(signet: Arc<Signet>) -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/owner/delegation", get(shown))
        .route("/v0/owner/delegate-key", post(rotate))
        .route_layer(middleware::from_fn_with_state(signet, require_owner_token))
        .route("/v0/owner/delegation", put(take))
}

#[derive(Serialize)]
pub(crate) struct Shown {
    /// The public half, for the owner to sign a delegation to.
    delegate: String,
    delegation: Option<Showing>,
}

#[derive(Serialize)]
pub(crate) struct Showing {
    seq: u64,
    /// What rules name it by.
    name: String,
    may: Vec<Delegated>,
    /// The types it caps, which are all its delegate can say yes to.
    types: Vec<splint_core::requests::InteractionType>,
    expires_at: u64,
    /// Whether it counts here now: in date, to this key, and named by the rules in force, which it
    /// also needs at the host.
    counts: bool,
}

/// What an owner's device signs a delegation for. The key itself never leaves.
async fn shown(State(signet): State<Arc<Signet>>) -> Json<Shown> {
    Json(shown_at(&signet, unix_now()).await)
}

pub(crate) async fn shown_at(signet: &Signet, now: u64) -> Shown {
    let who = signet.who();
    let rules = signet.rules.current().await;
    let held = signet.delegation.held.lock().await;
    let counts = rules
        .as_ref()
        .is_some_and(|rules| held.in_force(&who, rules, now).is_some());
    let showing = held
        .taken(&who)
        .filter(|delegation| now < delegation.expires_at())
        .map(|delegation| Showing {
            seq: delegation.seq(),
            name: delegation.name(),
            may: [Delegated::ApproveWithinCaps]
                .into_iter()
                .filter(|what| delegation.may(*what))
                .collect(),
            types: delegation.permissions().caps.into_keys().collect(),
            expires_at: delegation.expires_at(),
            counts,
        });
    Shown {
        delegate: held.key.public_key().encoded(),
        delegation: showing,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DelegationBody {
    delegation: String,
}

#[derive(Serialize)]
pub(crate) struct Taken {
    seq: u64,
    name: String,
    expires_at: u64,
}

/// Authorized by the owner's signature and nothing else, so a fooled agent can reach this and still
/// can't give itself a delegation. It has to name this Signet's key, and be newer than the one held,
/// which it replaces. It counts once the rules in force name it.
pub(crate) async fn take(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<DelegationBody>,
) -> Result<Json<Taken>, ApiError> {
    take_at(&signet, &body.delegation, unix_now())
        .await
        .map(Json)
}

pub(crate) async fn take_at(signet: &Signet, compact: &str, now: u64) -> Result<Taken, ApiError> {
    crate::recovery::hear_of_new_keys(signet, compact).await;
    let who = signet.who();
    let delegations = &signet.delegation;
    let mut held = delegations.held.lock().await;
    let newest = held
        .taken(&who)
        .map_or(0, |delegation| delegation.seq().saturating_add(1));
    let delegation = VerifiedDelegation::verify(compact, &who.owner, &who.identity, newest, now)
        .map_err(ApiError::RulesRefused)?;
    if !delegation.names(&held.key) {
        return Err(ApiError::RulesRefused(splint_core::Error::ProofMismatch));
    }
    let saved = HashMap::from([(SAVED, delegation.compact())]);
    state_file::save(&delegations.path, &saved).map_err(|_| HostError::LocalStorage)?;
    held.delegation = Some(delegation.compact().to_owned());
    drop(held);
    signet.owner_signed.note(compact).await;
    tracing::info!(seq = delegation.seq(), "took a delegation the owner signed");
    signet.activity.note(crate::activity::Kind::Owner);
    Ok(Taken {
        seq: delegation.seq(),
        name: delegation.name(),
        expires_at: delegation.expires_at(),
    })
}

#[derive(Serialize)]
struct Rotated {
    /// The new key's public half, for the next delegation.
    delegate: String,
}

/// A fresh delegate key, and the delegation held for the old one dropped, for an owner who thinks the
/// old key got out. It only takes something away, so the owner token is enough, as for a transfer.
/// What the old key signs stops counting here at once, at the host once the owner's rules name a
/// delegation to the new key, or none, and at a reader only when its delegation ends.
async fn rotate(State(signet): State<Arc<Signet>>) -> Result<Json<Rotated>, ApiError> {
    let delegations = &signet.delegation;
    let mut held = delegations.held.lock().await;
    // Dropped first: a crash before the new key is in place leaves no delegation, which is safe.
    state_file::save(&delegations.path, &HashMap::<&str, String>::new())
        .map_err(|_| HostError::LocalStorage)?;
    held.delegation = None;
    held.key = DelegateKey::replace(&delegations.key_path).map_err(|_| HostError::LocalStorage)?;
    let delegate = held.key.public_key().encoded();
    drop(held);
    tracing::info!("made a new delegate key, and dropped the delegation for the old one");
    signet.activity.note(crate::activity::Kind::Owner);
    Ok(Json(Rotated { delegate }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use splint_core::delegation::DelegationDraft;
    use splint_core::rules::{Permissions, Reach, RulesDraft, RulesLimits};
    use splint_core::{Sealing, SigningKey};

    use super::*;
    use crate::rules;
    use crate::sealing::tests::signet_and_owner;

    const DAY: u64 = 24 * 60 * 60;

    trait Taken {
        fn taken_or_panic(self);
    }

    impl<T> Taken for Result<T, ApiError> {
        fn taken_or_panic(self) {
            assert!(self.is_ok(), "Signet refused the owner's");
        }
    }
    /// Every clock here is passed in, starting from this.
    const NOW: u64 = 1_800_000_000;

    fn delegation_to(key: &DelegateKey, owner_key: &SigningKey, who: &Who, seq: u64) -> String {
        DelegationDraft {
            delegate: key.public_key(),
            may: vec![Delegated::ApproveWithinCaps],
            level: Level::AutoWithinLimits,
            caps: BTreeMap::new(),
            actions_per_day: 10,
            lasts_secs: 365 * DAY,
        }
        .sign(owner_key, who.owner.id(), who.identity.id(), seq, NOW)
        .unwrap()
    }

    /// The owner's rules, naming the delegation they allow, or none.
    fn rules_naming(
        owner_key: &SigningKey,
        who: &Who,
        seq: u64,
        delegation: Option<&str>,
    ) -> String {
        let name = delegation.map(|compact| {
            VerifiedDelegation::reload(compact, &who.owner, &who.identity)
                .unwrap()
                .name()
        });
        RulesDraft {
            paused: false,
            reach: Reach::default(),
            permissions: Permissions::default(),
            changes: splint_core::changes::ChangeRules::default(),
            sealing: Sealing::Sealed,
            delegation: name,
            ends_at: None,
            contacts: Vec::new(),
            invites: Vec::new(),
            limits: RulesLimits {
                new_requests_per_contact_per_day: 3,
                open_requests_per_contact: 3,
                open_approvals: 10,
                new_from_others_per_day: 50,
                texts_per_contact_per_day: 20,
                agreed_texts_per_day: None,
                agreed_new_requests_per_day: None,
                sends_per_hour: None,
                sends_per_day: None,
            },
        }
        .sign(owner_key, who.owner.id(), who.identity.id(), seq, NOW)
        .unwrap()
    }

    async fn delegate_key(signet: &Signet) -> String {
        shown_at(signet, NOW).await.delegate
    }

    /// A delegation counts here only while the rules in force name it, so rules naming none end it at
    /// once, though it's in date and still held. An older one can't be handed back in its place.
    #[tokio::test]
    async fn a_delegation_counts_only_while_the_owners_rules_name_it() {
        let (signet, directory, owner_key) =
            signet_and_owner(Some(Sealing::Sealed), "delegation-named").await;
        let who = signet.who();
        let (older, newer) = {
            let held = signet.delegation.held.lock().await;
            (
                delegation_to(&held.key, &owner_key, &who, 1),
                delegation_to(&held.key, &owner_key, &who, 2),
            )
        };
        assert!(take_at(&signet, &newer, NOW).await.is_ok());
        assert!(
            take_at(&signet, &older, NOW).await.is_err(),
            "an older one is refused"
        );
        assert!(
            take_at(&signet, &newer, NOW).await.is_err(),
            "and the same one again"
        );

        let counts = || async { shown_at(&signet, NOW).await.delegation.unwrap().counts };
        let unnamed = rules_naming(&owner_key, &who, 2, None);
        rules::adopt(&signet, &unnamed, NOW).await.taken_or_panic();
        assert!(!counts().await, "rules naming none allow none");

        let named = rules_naming(&owner_key, &who, 3, Some(&newer));
        rules::adopt(&signet, &named, NOW).await.taken_or_panic();
        assert!(counts().await, "control: named, it counts");

        // New rules naming another end it.
        let elsewhere = rules_naming(&owner_key, &who, 4, Some(&older));
        rules::adopt(&signet, &elsewhere, NOW)
            .await
            .taken_or_panic();
        assert!(!counts().await);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// An owner who thinks the delegate key got out has Signet make a new one. Nothing the old key
    /// signs counts here from then on, before the owner signs anything else: its delegation goes and
    /// can't be handed back, though the rules in force still name it. Only one to the new key counts,
    /// once the owner's rules name it.
    #[tokio::test]
    async fn a_new_delegate_key_ends_the_old_ones_delegation() {
        let (signet, directory, owner_key) =
            signet_and_owner(Some(Sealing::Sealed), "delegation-rotate").await;
        let signet = Arc::new(signet);
        let who = signet.who();
        let old = {
            let held = signet.delegation.held.lock().await;
            delegation_to(&held.key, &owner_key, &who, 1)
        };
        take_at(&signet, &old, NOW).await.taken_or_panic();
        let owners = rules_naming(&owner_key, &who, 2, Some(&old));
        rules::adopt(&signet, &owners, NOW).await.taken_or_panic();
        assert!(shown_at(&signet, NOW).await.delegation.unwrap().counts);
        let before = delegate_key(&signet).await;

        let Ok(Json(rotated)) = rotate(State(signet.clone())).await else {
            panic!("rotating the key failed");
        };
        assert_ne!(rotated.delegate, before);
        assert_eq!(delegate_key(&signet).await, rotated.delegate);
        assert!(shown_at(&signet, NOW).await.delegation.is_none());
        assert!(!act(&signet, NOW).await, "nothing held, nothing done");
        assert!(
            take_at(&signet, &old, NOW).await.is_err(),
            "the old one can't come back"
        );
        let reloaded = Delegation::load(&directory).unwrap();
        assert_eq!(
            reloaded.held.lock().await.key.public_key().encoded(),
            rotated.delegate,
            "the new key is the one saved"
        );

        let new = {
            let held = signet.delegation.held.lock().await;
            delegation_to(&held.key, &owner_key, &who, 2)
        };
        take_at(&signet, &new, NOW).await.taken_or_panic();
        let counts = || async { shown_at(&signet, NOW).await.delegation.unwrap().counts };
        assert!(!counts().await, "not until the rules name it");
        let named = rules_naming(&owner_key, &who, 3, Some(&new));
        rules::adopt(&signet, &named, NOW).await.taken_or_panic();
        assert!(counts().await, "control: the new one counts");
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

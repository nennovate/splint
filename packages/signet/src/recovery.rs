//! Taking in a recovery or a transfer, which is how who this agent is can change.
//!
//! A recovery is authorized by the backup key's signature and nothing else, so anyone can carry one
//! here and a fooled agent can't forge one. It's a host that has to hear next, so the old key stops
//! working everywhere that matters as soon as it can.

use std::sync::Arc;

use axum::extract::State;
use axum::middleware;
use axum::routing::put;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::rules::VerifiedRules;
use splint_core::{Error, Identity, VerifiedBinding, same_handle_and_host, unix_now};

use crate::Signet;
use crate::agent_api::ApiError;
use crate::binding::register;
use crate::changes;
use crate::host_client::HostError;
use crate::requests::owner_api::require_owner_token;
use crate::who::Who;

pub fn routes(signet: Arc<Signet>) -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/owner/transfer", put(take_transfer))
        .route_layer(middleware::from_fn_with_state(signet, require_owner_token))
        .route("/v0/owner/recovery", put(take_recovery))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryBody {
    identity: String,
}

#[derive(Serialize)]
struct Taken {
    id: splint_core::SplintId,
    /// What the owner has to sign again before this agent can act, if anything.
    needs: Vec<&'static str>,
}

async fn take_recovery(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<RecoveryBody>,
) -> Result<Json<Taken>, ApiError> {
    let new = Identity::from_encoded(&body.identity).map_err(ApiError::IdentityRefused)?;
    let _changing = signet.changing_who.lock().await;
    let who = signet.who();
    if new.id() == who.owner.id() {
        recover_owner(&signet, &who, new).await
    } else if new.id() == who.identity.id() {
        recover_agent(&signet, &who, new).await
    } else {
        Err(ApiError::IdentityRefused(Error::ProofMismatch))
    }
}

/// A host that hasn't heard of this agent has nothing to stop.
fn tolerate_unregistered(result: Result<(), HostError>) -> Result<(), HostError> {
    match result {
        Err(HostError::NotFound) => Ok(()),
        other => other,
    }
}

/// Takes a newer copy of the owner's ID, then tells this agent's host, as a host that was down gets told
/// by hearing the same copy again, which changes nothing here.
async fn recover_owner(signet: &Signet, who: &Who, new: Identity) -> Result<Json<Taken>, ApiError> {
    let needs = take_owner_copy(signet, who, &new).await?;
    tolerate_unregistered(signet.host.recover(&new.encoded()).await)?;
    changes::bring_up_to_date(signet).await?;
    changes::publish_now(signet).await;
    Ok(Json(Taken {
        id: new.id().clone(),
        needs,
    }))
}

/// A recovery: whatever the old key signed stops counting, including what a thief signed before now, so
/// this agent's rules and binding go with it and it's stopped until its owner signs again. A copy that
/// only added or removed keys counts at once, and a removed key is treated as a key a recovery replaced:
/// what only it signed goes, and nothing else. Says what the owner has to sign again. The caller holds
/// `changing_who`.
async fn take_owner_copy(
    signet: &Signet,
    who: &Who,
    new: &Identity,
) -> Result<Vec<&'static str>, ApiError> {
    let newer = new
        .replaces(&who.owner)
        .map_err(ApiError::IdentityRefused)?;
    let mut needs = take_owner_keys(signet, who, new, newer).await?;
    // Where the owner gets paid is checked under the copy held each time, so one only an old key
    // signed stops counting with nothing to drop, and the owner hears it went.
    let where_paid = &signet.requests.where_paid;
    if where_paid.current(&who.owner).await.is_some() && where_paid.current(new).await.is_none() {
        needs.push("where_paid");
    }
    Ok(needs)
}

async fn take_owner_keys(
    signet: &Signet,
    who: &Who,
    new: &Identity,
    newer: bool,
) -> Result<Vec<&'static str>, ApiError> {
    if newer && new.recoveries() > who.owner.recoveries() {
        signet.rules.clear().await?;
        signet.registered.lost_its_binding();
        signet.replace_who(Who {
            identity: who.identity.clone(),
            owner: new.clone(),
            binding: String::new(),
        })?;
        signet.retired.owner_recovered(new);
        tracing::warn!(owner = %new.id(), "the owner's key was replaced");
    } else if newer {
        return owner_keys_changed(signet, who, new).await;
    }
    Ok(if signet.who().binding.is_empty() {
        vec!["binding", "rules"]
    } else {
        Vec::new()
    })
}

async fn owner_keys_changed(
    signet: &Signet,
    who: &Who,
    new: &Identity,
) -> Result<Vec<&'static str>, ApiError> {
    let mut needs = Vec::new();
    let mut binding = who.binding.clone();
    if new.removed_since(&who.owner) {
        if !binding.is_empty() && !new.signed_now(&binding) {
            binding.clear();
            signet.registered.lost_its_binding();
            needs.push("binding");
        }
        let rules = signet.rules.current().await;
        if rules.is_some_and(|rules| VerifiedRules::reload(rules.compact(), new).is_err()) {
            signet.rules.clear().await?;
            needs.push("rules");
        }
    }
    let now = unix_now();
    let delegated = signet.delegation.counts_for(who).await;
    let granted = signet.grants.counting(&who.owner, now).await;
    signet.replace_who(Who {
        identity: who.identity.clone(),
        owner: new.clone(),
        binding,
    })?;
    // A delegation and grants are checked under who the owner is each time they're used, so what a
    // removed key signed stops counting with nothing to drop. The owner still hears what went.
    if delegated && !signet.delegation.counts_for(&signet.who()).await {
        needs.push("delegation");
    }
    if signet.grants.counting(new, now).await < granted {
        needs.push("grants");
    }
    tracing::warn!(owner = %new.id(), ?needs, "the owner's keys changed");
    Ok(needs)
}

/// Before an owner object is checked: if no key of the owner's that counts here signed it, asks this
/// agent's host once for the owner's newest copy and takes it if it's newer, so a key the owner added a
/// moment ago works here at once. The host can only show what the owner's keys and backup signed, or an
/// older copy, which changes nothing. The object is then checked as it would have been. An agent that
/// sends what no key signed gets one call to its own host for each, as any call of its own costs.
pub async fn hear_of_new_keys(signet: &Signet, compact: &str) {
    if signet.who().owner.signed_now(compact) {
        return;
    }
    let who = signet.who();
    let Ok(heard) = signet
        .host
        .known_owners(&signet.key, who.identity.id())
        .await
    else {
        return;
    };
    for text in heard.identities {
        if let Ok(copy) = Identity::from_encoded(&text) {
            hear_of_owner(signet, &copy).await;
        }
    }
}

/// A copy of this agent's owner from its host, taken if it's newer than the one held.
pub async fn hear_of_owner(signet: &Signet, copy: &Identity) {
    let _changing = signet.changing_who.lock().await;
    let who = signet.who();
    if copy.id() != who.owner.id() || !matches!(copy.replaces(&who.owner), Ok(true)) {
        return;
    }
    if take_owner_copy(signet, &who, copy).await.is_err() {
        tracing::warn!("couldn't take a newer copy of the owner's ID from the host");
    }
}

/// Steps signed with the old key and still waiting here can never reach anyone, so they go. A chain
/// they left hanging runs out at its deadline.
async fn recover_agent(signet: &Signet, who: &Who, new: Identity) -> Result<Json<Taken>, ApiError> {
    if !new.extends(&who.identity) {
        return Err(ApiError::IdentityRefused(Error::Stale));
    }
    // A statement naming some other key isn't for this Signet, whose key couldn't speak for it, or
    // open what's sealed to it.
    if !signet.holds_keys_of(&new) {
        return Err(ApiError::IdentityRefused(Error::ProofMismatch));
    }
    let mut next = Who {
        identity: new.clone(),
        owner: who.owner.clone(),
        binding: String::new(),
    };
    // What the owner's device signed still stands, so only the agent's half needs signing again.
    let accepted = VerifiedBinding::from_owner(&who.binding).and_then(|from_owner| {
        VerifiedBinding::accept(&signet.key, &from_owner, None, &who.owner, &new)
    });
    if let Ok(binding) = &accepted {
        next.binding = binding.compact().to_owned();
    }
    signet.replace_who(next)?;
    signet.requests.store.drop_outgoing().await?;
    tolerate_unregistered(signet.host.recover(&new.encoded()).await)?;
    match &accepted {
        Ok(binding) => register(signet, &new, &who.owner, binding.compact()).await?,
        Err(_) => signet.registered.lost_its_binding(),
    }
    tracing::warn!(agent = %new.id(), "this agent's key was replaced");
    changes::bring_up_to_date(signet).await?;
    changes::publish_now(signet).await;
    Ok(Json(Taken {
        id: new.id().clone(),
        needs: if accepted.is_ok() {
            Vec::new()
        } else {
            vec!["binding"]
        },
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferBody {
    /// This agent's identity, with the recovery that moved its backup to the new owner.
    identity: String,
    new_owner_identity: String,
    /// The current owner's word, naming the new one.
    release: String,
    /// The new owner's half of the statement.
    binding: String,
}

/// Moves this agent to a new owner, with its ID unchanged. It takes the owner token as well as the
/// signatures, so a stolen owner key alone can't take the agent. What this agent held for its old
/// owner doesn't go with it: rules, contacts and interactions all start empty, and the new owner signs
/// new rules. The host hears first, so a refusal there changes nothing here. An owner confirming an
/// agent that joined on its own is the exception: it carries on with whoever it was dealing with.
async fn take_transfer(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<TransferBody>,
) -> Result<Json<Taken>, ApiError> {
    let refused = ApiError::IdentityRefused;
    let new_agent = Identity::from_encoded(&body.identity).map_err(refused)?;
    let new_owner = Identity::from_encoded(&body.new_owner_identity).map_err(refused)?;
    let _changing = signet.changing_who.lock().await;
    // Its owner ended it for good, so nobody can hand it on.
    if signet.retired.is() {
        return Err(ApiError::Retired);
    }
    let who = signet.who();
    if !new_agent.extends(&who.identity) {
        return Err(refused(Error::Stale));
    }
    if !signet.holds_keys_of(&new_agent) {
        return Err(refused(Error::ProofMismatch));
    }
    let binding = VerifiedBinding::accept(
        &signet.key,
        &body.binding,
        Some(&body.release),
        &new_owner,
        &new_agent,
    )
    .map_err(ApiError::NotBound)?;
    // A new owner can give the name their own owner part, and nothing else about the address.
    let address = signet.address();
    let renamed =
        new_owner.id() != who.owner.id() && same_handle_and_host(binding.address(), &address);
    if binding.address() != address && !renamed {
        return Err(ApiError::NotBound(Error::ProofMismatch));
    }
    binding
        .may_replace(&who.owner, who.binding_seq())
        .map_err(ApiError::NotBound)?;
    tolerate_unregistered(signet.host.recover(&new_agent.encoded()).await)?;
    register(&signet, &new_agent, &new_owner, binding.compact()).await?;
    // An owner confirming an agent that joined on its own takes up what it was doing, as nothing was
    // held for anyone else. Its stand-in's rules still go, as only the owner signs from here.
    let confirming = who.owner.is_unconfirmed_owner() && !new_owner.is_unconfirmed_owner();
    if confirming {
        // Whoever the stand-in named hears of the owner who confirmed, as the owner names nobody yet.
        let named = signet.rules.contacts_by_name().await;
        let head = signet.own_changes.current().head();
        signet.own_changes.note_listeners(&named, &head)?;
        signet.rules.clear().await?;
        signet.grants.forget_everything().await?;
    } else if new_owner.id() != who.owner.id() {
        signet.rules.forget_everything().await?;
        signet.contacts.forget_everything().await?;
        signet.requests.store.forget_everything().await?;
        signet.requests.types.clear();
        signet.requests.person_texts.forget_everything().await?;
        signet.requests.where_paid.forget_everything().await?;
        signet.requests.held_opens.forget_everything().await?;
        signet.grants.forget_everything().await?;
        signet.seen_changes.forget_everything()?;
        signet.contact_asks.forget_everything()?;
        signet.invites.forget_everything()?;
        signet.arrivals.forget_everything()?;
        signet.sent.forget_everything().await?;
        signet.receipts.forget_everything().await?;
    }
    signet.replace_who(Who {
        identity: new_agent.clone(),
        owner: new_owner.clone(),
        binding: binding.compact().to_owned(),
    })?;
    tracing::warn!(agent = %new_agent.id(), owner = %new_owner.id(), "this agent has a new owner");
    changes::bring_up_to_date(&signet).await?;
    changes::publish_now(&signet).await;
    Ok(Json(Taken {
        id: new_agent.id().clone(),
        needs: vec!["rules"],
    }))
}

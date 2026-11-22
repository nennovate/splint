//! Grants this agent holds, and proofs for calling a resource under one. See `docs/protocol.md`.
//!
//! The agent's runtime calls the resource itself, since Signet calls only its own host. What Signet
//! adds is the one thing the agent can't do: sign with the agent key. It signs only for a grant its
//! owner signed for this agent, still in date, and never for this agent's own host, where an access
//! proof would let the agent act as Signet. The resource runs the real check, so a Signet that signs
//! wrongly still gets nothing past it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::middleware;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::grants::{GRANT_HEADER, IDENTITY_HEADER, VerifiedGrant};
use splint_core::{AccessProof, Identity, unix_now};
use tokio::sync::Mutex;

use crate::Signet;
use crate::agent_api::{ApiError, refuse_if_stopped};
use crate::host_client::HostError;
use crate::state_file::{self, StateError};

const MAX_PATH_LEN: usize = 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_GRANTS: usize = 64;
const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/// Each grant's compact form, by its ID.
pub struct Grants {
    path: PathBuf,
    held: Mutex<HashMap<String, String>>,
}

impl Grants {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        Ok(Self {
            held: Mutex::new(state_file::load(&path)?),
            path,
        })
    }

    /// For when this agent gets a new owner. What the old one granted can't verify under the new one
    /// anyway, and it's still theirs: where it pointed is nothing for the new owner to read.
    pub async fn forget_everything(&self) -> Result<(), HostError> {
        let mut held = self.held.lock().await;
        held.clear();
        state_file::save(&self.path, &*held).map_err(|_| HostError::LocalStorage)
    }
}

impl Grants {
    /// How many of the grants held still verify under this owner, as they are checked when used.
    pub async fn counting(&self, owner: &Identity, now: u64) -> usize {
        let held = self.held.lock().await;
        held.values()
            .filter(|compact| VerifiedGrant::verify(compact, owner, now).is_ok())
            .count()
    }
}

pub fn agent_routes(signet: Arc<Signet>) -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/grants/{id}/proof", post(proof))
        .route_layer(middleware::from_fn_with_state(signet, refuse_if_stopped))
        .route("/v0/grants", get(list))
}

pub fn owner_routes() -> Router<Arc<Signet>> {
    Router::new().route("/v0/owner/grants", put(take))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantBody {
    grant: String,
}

#[derive(Serialize)]
pub(crate) struct Taken {
    id: String,
}

/// Authorized by the owner's signature and nothing else, like rules. A grant naming another holder,
/// or this agent's own host, is refused, so a fooled agent can't hand itself one.
pub(crate) async fn take(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<GrantBody>,
) -> Result<Json<Taken>, ApiError> {
    crate::recovery::hear_of_new_keys(&signet, &body.grant).await;
    let now = unix_now();
    let grant = VerifiedGrant::verify(&body.grant, &signet.who().owner, now)
        .map_err(|_| ApiError::RulesRefused(splint_core::Error::BadSignature))?;
    if grant.holder() != signet.who().identity.id() || grant.resource() == signet.host.domain {
        return Err(ApiError::RulesRefused(splint_core::Error::ProofMismatch));
    }
    let mut held = signet.grants.held.lock().await;
    let owner = &signet.who().owner;
    held.retain(|_, compact| {
        VerifiedGrant::verify(compact, owner, now).is_ok_and(|kept| kept.expires_at() > now)
    });
    if held.len() >= MAX_GRANTS && !held.contains_key(grant.id().as_str()) {
        return Err(ApiError::Host(HostError::TooMany));
    }
    held.insert(grant.id().to_string(), body.grant);
    state_file::save(&signet.grants.path, &*held).map_err(|_| HostError::LocalStorage)?;
    tracing::info!(grant = %grant.id(), "took a grant the owner signed");
    Ok(Json(Taken {
        id: grant.id().to_string(),
    }))
}

#[derive(Serialize)]
struct GrantView {
    id: String,
    resource: String,
    operations: Vec<String>,
    expires_at: u64,
}

#[derive(Serialize)]
struct GrantList {
    grants: Vec<GrantView>,
}

/// What this agent may call, and where. A grant whose owner key has since been recovered away, or
/// that has run out, isn't shown.
async fn list(State(signet): State<Arc<Signet>>) -> Json<GrantList> {
    let now = unix_now();
    let owner = &signet.who().owner;
    let held = signet.grants.held.lock().await;
    let mut grants: Vec<GrantView> = held
        .values()
        .filter_map(|compact| VerifiedGrant::verify(compact, owner, now).ok())
        .filter(|grant| grant.expires_at() > now)
        .map(|grant| GrantView {
            id: grant.id().to_string(),
            resource: grant.resource().to_owned(),
            operations: grant.operations().to_vec(),
            expires_at: grant.expires_at(),
        })
        .collect();
    grants.sort_by(|left, right| left.id.cmp(&right.id));
    Json(GrantList { grants })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofRequest {
    method: String,
    path: String,
    #[serde(default)]
    body: String,
}

/// What the agent's runtime sends with its call, as headers named here.
#[derive(Serialize)]
struct CallHeaders {
    resource: String,
    authorization: String,
    grant_header: &'static str,
    grant: String,
    identity_header: &'static str,
    identity: String,
}

/// A proof for one call: this method, path and exact body, at the grant's resource, for 120 seconds.
async fn proof(
    State(signet): State<Arc<Signet>>,
    Path(id): Path<String>,
    Json(request): Json<ProofRequest>,
) -> Result<Json<CallHeaders>, ApiError> {
    let fits = METHODS.contains(&request.method.as_str())
        && request.path.starts_with('/')
        && request.path.len() <= MAX_PATH_LEN
        && request.path.bytes().all(|byte| byte.is_ascii_graphic())
        && request.body.len() <= MAX_BODY_BYTES;
    if !fits {
        return Err(ApiError::BadRequest(
            "a call is a method, a path and a body",
        ));
    }
    let now = unix_now();
    let who = signet.who();
    let compact = signet
        .grants
        .held
        .lock()
        .await
        .get(&id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let grant = VerifiedGrant::verify(&compact, &who.owner, now).map_err(|_| ApiError::NotFound)?;
    if grant.expires_at() <= now || grant.resource() == signet.host.domain {
        return Err(ApiError::NotFound);
    }
    let proof = AccessProof::sign(
        &signet.key,
        who.identity.id(),
        grant.resource(),
        &request.method,
        &request.path,
        request.body.as_bytes(),
        now,
    )?;
    tracing::info!(grant = %grant.id(), "signed a proof for one call");
    Ok(Json(CallHeaders {
        resource: grant.resource().to_owned(),
        authorization: format!("Splint {proof}"),
        grant_header: GRANT_HEADER,
        grant: compact,
        identity_header: IDENTITY_HEADER,
        identity: who.identity.encoded(),
    }))
}

//! Who may read what this host keeps for an owner: that owner, by a session their page holds or by an
//! access proof their own key signed. Every owner read goes through [`owner_reading`]. One route that
//! writes calls it too, owner mail, sealed to an agent, which only buys room here: nothing in it
//! counts until the agent's Signet finds the owner's own signature inside. What changes anything is
//! checked by the owner's signature on it, so a session never stands for that signature.

use axum::http::HeaderMap;
use splint_core::owner_session::{OwnerReader, ReadCall, SESSION_HEADER};
use splint_core::{Identity, unix_now};

use crate::api_error::ApiError;
use crate::{Host, inbox};

/// The owner the agent named acts for, as this host holds them now, so a recovery's new key reads at
/// once and the key it replaced doesn't.
pub async fn owner_of_agent(host: &Host, agent: &str) -> Result<Option<Identity>, ApiError> {
    let row: Option<String> = sqlx::query_scalar("SELECT owner_identity FROM agents WHERE id = $1")
        .bind(agent)
        .fetch_optional(&host.db)
        .await?;
    Ok(match row {
        Some(text) => Some(Identity::from_encoded(&text)?),
        None => None,
    })
}

/// That this call, to `path` with `body`, is by `owner`. Any failure is the same 401, so a caller
/// learns nothing about a session it holds but whether it reads.
pub fn owner_reading(
    host: &Host,
    headers: &HeaderMap,
    owner: &Identity,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<OwnerReader, ApiError> {
    let proof = inbox::access_proof_in(headers).ok_or(ApiError::Unauthorized)?;
    let call = ReadCall {
        host: &host.domain,
        method,
        path,
        body,
        now: unix_now(),
    };
    let reader = match headers.get(SESSION_HEADER) {
        Some(session) => {
            let session = session.to_str().map_err(|_| ApiError::Unauthorized)?;
            OwnerReader::by_session(session, proof, owner, &call)
        }
        None => OwnerReader::by_owner_key(proof, owner, &call),
    };
    reader.map_err(|_| ApiError::Unauthorized)
}

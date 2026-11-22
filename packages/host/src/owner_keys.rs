//! An owner's newer copy that only added or removed keys since the one held. It counts here at once, so
//! what an added key signs is taken straight away. A removed key is treated as a key a recovery
//! replaced: what only it signed for an agent here goes, with any `seq` it set, so nothing it dated
//! ahead holds back what a key that stays signs next. Unlike a recovery, nothing else stops, and what a
//! key that stays signed goes on counting. A retirement or a move already taken stands, which only the
//! recovery code undoes (see "An owner's keys" in `docs/protocol.md`).

use splint_core::rules::VerifiedRules;
use splint_core::{Identity, SplintId};
use sqlx::{Postgres, Row, Transaction};

use crate::api_error::ApiError;
use crate::{admission, owner_relay, registry};

/// Whether `new` replaces the copy of an owner held for an agent here. An older copy is refused, and one
/// that parts ways and doesn't win is `409 stale`, for the page to sign again on top of what's held.
pub fn replaces(new: &Identity, held: &Identity) -> Result<bool, ApiError> {
    match new.replaces(held) {
        Ok(newer) => Ok(newer),
        Err(splint_core::Error::Forked) => Err(ApiError::Stale),
        Err(_) => Err(ApiError::Forbidden("that isn't later than what's held")),
    }
}

/// Takes `new` as the copy of this agent's owner, which replaces `held` and has no recovery since it.
pub async fn agent_owner_changed(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
    held: &Identity,
    new: &Identity,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE agents SET owner_identity = $2 WHERE id = $1")
        .bind(agent.as_str())
        .bind(new.encoded())
        .execute(&mut **transaction)
        .await?;
    if new.removed_since(held) {
        drop_what_removed_keys_signed(transaction, agent, new).await?;
    }
    Ok(())
}

/// The owner's half of the binding, the rules, and owner mail still waiting, each if a key that counts
/// now didn't sign it. A revocation one signed stays, so a removal never brings an agent back, but its
/// `seq` goes, so whatever key stays can sign the agent back.
async fn drop_what_removed_keys_signed(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
    owner: &Identity,
) -> Result<(), ApiError> {
    let row = sqlx::query("SELECT binding, revocation FROM agents WHERE id = $1")
        .bind(agent.as_str())
        .fetch_one(&mut **transaction)
        .await?;
    let binding: String = row.try_get("binding")?;
    if !binding.is_empty() && !owner.signed_now(&binding) {
        sqlx::query("UPDATE agents SET binding_seq = 0 WHERE id = $1")
            .bind(agent.as_str())
            .execute(&mut **transaction)
            .await?;
    }
    let revocation: Option<String> = row.try_get("revocation")?;
    if revocation.is_some_and(|revocation| !owner.signed_now(&revocation)) {
        sqlx::query("UPDATE agents SET revoked_seq = 0 WHERE id = $1")
            .bind(agent.as_str())
            .execute(&mut **transaction)
            .await?;
    }
    let rules: Option<String> = sqlx::query_scalar("SELECT compact FROM rules WHERE agent = $1")
        .bind(agent.as_str())
        .fetch_optional(&mut **transaction)
        .await?;
    if rules.is_some_and(|rules| VerifiedRules::reload(&rules, owner).is_err()) {
        registry::forget_rules(transaction, agent).await?;
    }
    owner_relay::drop_unless_signed_by(transaction, agent, owner).await?;
    tracing::warn!(%agent, "what a key its owner removed signed has gone");
    Ok(())
}

/// The owner's list kept here, for a newer copy of them that only added or removed keys. A list a
/// removed key signed loses its `seq`, so the next one any key that stays signs replaces it, whatever
/// it was dated. It stays readable meanwhile, as it holds what the owner's page needs to find their
/// agents. A recovery leaves the list to the owner's next one, as it always has.
pub async fn list_owner_changed(
    transaction: &mut Transaction<'_, Postgres>,
    new: &Identity,
) -> Result<bool, ApiError> {
    let row = sqlx::query(
        "SELECT owner_identity, list FROM owner_agent_lists WHERE owner_id = $1 FOR UPDATE",
    )
    .bind(new.id().as_str())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let held = Identity::from_encoded(&row.try_get::<String, _>("owner_identity")?)?;
    // The list's copy can be behind the agents', so an older copy here changes nothing.
    let newer = match new.replaces(&held) {
        Ok(newer) => newer,
        Err(splint_core::Error::Forked) => return Err(ApiError::Stale),
        Err(_) => false,
    };
    if !newer || new.recoveries() > held.recoveries() {
        return Ok(false);
    }
    let list: String = row.try_get("list")?;
    let signed_now = !new.removed_since(&held) || new.signed_now(&list);
    sqlx::query(
        "UPDATE owner_agent_lists SET owner_identity = $2, seq = CASE WHEN $3 THEN seq ELSE 0 END
         WHERE owner_id = $1",
    )
    .bind(new.id().as_str())
    .bind(new.encoded())
    .bind(signed_now)
    .execute(&mut **transaction)
    .await?;
    Ok(true)
}

/// Whether this copy of an owner some rules here name should replace the one kept, and so whether what
/// was held for them has to be gone over: a recovery, or a key gone.
pub fn takes_away_a_key(held: Option<&Identity>, newest: &Identity) -> bool {
    held.is_none_or(|held| newest.recoveries() > held.recoveries() || newest.removed_since(held))
}

/// Keeps a newer copy of an owner some rules here name, if it is one. A recovery or a removed key also
/// ends what the key given up signed about reaching this host's agents.
pub async fn keep_if_newer(
    host: &crate::Host,
    held: Option<&Identity>,
    newest: &Identity,
) -> Result<(), sqlx::Error> {
    let newer = match held {
        Some(held) => newest.replaces(held).unwrap_or(false),
        None => newest.statements() > 0,
    };
    if newer {
        admission::keep_owner_copy(host, newest, takes_away_a_key(held, newest)).await?;
    }
    Ok(())
}

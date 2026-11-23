//! Signing up with no code, which `deploy/` and `splint host start` turn on unless told not to. Anyone
//! can make an owner key, so what stands against a flood is here: a few signups an hour and a day from
//! one network, and a few held from it at once, a cap on agents nobody has used yet, no short or
//! official-looking handles that way, and letting go of any agent that joined without a code and was
//! never used, whoever it acts for.
//!
//! Used means a message it sent was let in by the rules of an agent acting for another owner: on this
//! host, where this host checked both owners and ran the recipient's rules itself, or on a peer host,
//! on that host's word. Not one delivered to its own owner's agents, nor held or refused, nor an
//! invite, nor a notice, and not anything it was sent, which only its own owner's rules let in. An
//! owner who sets up controls doesn't count either: an owner key costs nothing to make.
//!
//! An agent let go keeps its name for good, as a retired one does. Its contacts go by its ID, so one
//! who pinned it would refuse a newcomer at that name anyway. Someone given only the address, on a
//! card or in a chat, has nothing pinned, and would reach a newcomer and take it for the agent they
//! were told about. So a name given out here names one ID for good, and that ID can come back to it.
//! A temporary name is the exception: it was never anyone's to give out, so it goes with the agent.
//! What goes is everything else the host held for the agent.

use std::sync::Arc;
use std::time::Duration;

use splint_core::{
    Identity, MIN_HANDLE_CHARS_WITHOUT_CODE, SplintId, VerifiedRegistration, is_temporary_name,
};
use sqlx::{Postgres, Row, Transaction};

use crate::api_error::ApiError;
use crate::{Host, admission, database, delivery, inbox, owner_relay};

pub const HANDLE_KEPT_BACK: &str = "with no signup code this host gives out handles of 3 characters \
     or more, and none that would pass for the host or for Splint, so choose another";
// The words above say the number.
const _: () = assert!(MIN_HANDLE_CHARS_WITHOUT_CODE == 3);

/// How long an agent that joined without a code has to be used before it's let go. Provisional.
const UNUSED_FOR_SECS: i64 = 30 * 24 * 60 * 60;
/// So one pass, on a schedule or as someone signs up, does a bounded amount of work.
const RELEASED_PER_PASS: i64 = 20;
/// Joined with no code and never used. An operator's code vouched for the others, and a retired agent
/// keeps its row as it is. `$1` is the cutoff.
const UNUSED: &str = "NOT has_sent AND open_source IS NOT NULL
    AND retirement IS NULL AND created_at < to_timestamp($1::double precision)";

/// Lets go of agents that have been unused too long, a few at a time, oldest first.
pub async fn release_unused(host: &Host) -> Result<(), ApiError> {
    let cutoff = host
        .clock
        .now_for_sql()
        .await
        .saturating_sub(UNUSED_FOR_SECS);
    let due: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT id FROM agents WHERE {UNUSED} ORDER BY created_at LIMIT $2"
    ))
    .bind(cutoff)
    .bind(RELEASED_PER_PASS)
    .fetch_all(&host.db)
    .await?;
    for id in due {
        release(host, &id, cutoff).await?;
    }
    // Temporary names agents left, once they've pointed to the new ones long enough.
    sqlx::query("DELETE FROM moved_names WHERE until_at IS NOT NULL AND until_at <= $1")
        .bind(host.clock.now_for_sql().await)
        .execute(&host.db)
        .await?;
    Ok(())
}

/// Checked again under the handle's lock and the row's, so an agent used as this runs is kept, and
/// nobody takes the handle between the two.
async fn release(host: &Host, id: &str, cutoff: i64) -> Result<(), ApiError> {
    let mut transaction = database::begin(&host.db).await?;
    let handle: Option<String> = sqlx::query_scalar("SELECT handle FROM agents WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(handle) = handle else {
        return Ok(());
    };
    super::lock_handle(&mut transaction, &handle).await?;
    let row = sqlx::query(&format!(
        "SELECT handle, identity FROM agents WHERE id = $2 AND {UNUSED} FOR UPDATE"
    ))
    .bind(cutoff)
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        return Ok(());
    };
    let handle: String = row.try_get("handle")?;
    let agent = Identity::from_encoded(&row.try_get::<String, _>("identity")?)?
        .id()
        .clone();
    if !is_temporary_name(&handle) {
        sqlx::query(
            "INSERT INTO released_handles (handle, agent_id) VALUES ($1, $2)
             ON CONFLICT (handle) DO NOTHING",
        )
        .bind(&handle)
        .bind(agent.as_str())
        .execute(&mut *transaction)
        .await?;
    }
    super::forget_rules(&mut transaction, &agent).await?;
    admission::forget_for_new_owner(&mut transaction, &agent).await?;
    inbox::clear_for_new_owner(&mut transaction, &agent).await?;
    delivery::end_queued_from(&mut transaction, &agent).await?;
    owner_relay::forget(&mut transaction, &agent).await?;
    sqlx::query("DELETE FROM agents WHERE id = $1")
        .bind(agent.as_str())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    tracing::info!(%agent, "let go of an agent that joined without a code and was never used");
    Ok(())
}

/// A name held for an agent let go is that agent's alone. Run under the name's lock.
pub async fn check_not_held(
    transaction: &mut Transaction<'_, Postgres>,
    registration: &VerifiedRegistration,
) -> Result<(), ApiError> {
    let held: Option<String> =
        sqlx::query_scalar("SELECT agent_id FROM released_handles WHERE handle = $1")
            .bind(registration.name())
            .fetch_optional(&mut **transaction)
            .await?;
    match held {
        Some(held) if held != registration.agent().id().as_str() => Err(ApiError::Conflict),
        _ => Ok(()),
    }
}

/// An agent back at its handle is held there by its row again.
pub async fn stop_holding(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM released_handles WHERE agent_id = $1")
        .bind(agent.as_str())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// Called once a message is delivered: its sender is in use, so it stays. Only a message the other side
/// let in counts, not one queued, refused or held, and not an invite, which waits apart and can go to
/// anyone, so one invite each to nobody can't keep a flood of agents. Nor does a notice or a note's
/// receipt, which Signet sends by itself, nor one to an agent here acting for the same owner, which
/// that owner's own rules let in.
pub async fn note_delivered(host: &Host, message_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agents SET has_sent = TRUE
         WHERE NOT has_sent AND id = (SELECT sender FROM outbound
             WHERE message_id = $1 AND status = 'delivered' AND NOT is_notice
                 AND receipt_of IS NULL)
           AND NOT EXISTS (SELECT 1 FROM outbound JOIN agents AS recipient
               ON recipient.id = outbound.recipient
               WHERE outbound.message_id = $1 AND recipient.owner_id = agents.owner_id)",
    )
    .bind(message_id)
    .execute(&host.db)
    .await?;
    Ok(())
}

pub async fn run_cleanup(host: Arc<Host>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        // A database error is logged where it's turned into this.
        if release_unused(&host).await.is_err() {
            tracing::warn!("letting go of unused agents failed, so it's tried again next time");
        }
    }
}

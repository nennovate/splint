//! A reader's Signet confirms each note it opened and checked with a `received` naming the note as
//! both `request` and `of`, signed by the reader's agent key, so neither host can make one. What a host
//! does with one is only about cost: a receipt for a note this host holds for its agent goes out free
//! of that agent's limits, at most one per note, and one for a note its agent sent comes back in from
//! whoever the note went to.

use splint_core::requests::note_receipt_of;
use splint_core::{MessageId, VerifiedEnvelope};

use crate::Host;

/// The note a receipt going out confirms, if this host took that note for the receipt's signer from
/// the one it goes to. A receipt naming anything else, such as a note carried from another host, is
/// an ordinary send.
pub async fn for_note_received(
    host: &Host,
    envelope: &VerifiedEnvelope,
) -> Result<Option<MessageId>, sqlx::Error> {
    let Some(note) = note_receipt_of(envelope) else {
        return Ok(None);
    };
    let held: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM inbox
             WHERE recipient = $1 AND message_id = $2 AND sender = $3 AND NOT is_step)",
    )
    .bind(envelope.sender().as_str())
    .bind(note.as_str())
    .bind(envelope.recipient().as_str())
    .fetch_one(&host.db)
    .await?;
    Ok(held.then_some(note))
}

/// Whether a receipt coming in confirms a message this host's agent sent to whoever signed it.
pub async fn for_note_sent(host: &Host, envelope: &VerifiedEnvelope) -> Result<bool, sqlx::Error> {
    let Some(note) = note_receipt_of(envelope) else {
        return Ok(false);
    };
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM outbound
             WHERE message_id = $1 AND sender = $2 AND recipient = $3)",
    )
    .bind(note.as_str())
    .bind(envelope.recipient().as_str())
    .bind(envelope.sender().as_str())
    .fetch_one(&host.db)
    .await
}

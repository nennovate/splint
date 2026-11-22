//! Gate 4 for an agent's own words. See `docs/protocol.md`.
//!
//! Every agent counts as fooled all the time, so this runs wherever a message that isn't a step
//! passes: in Signet before signing, in the sender's host before it goes, and in the recipient's host
//! and Signet when it arrives. Steps have their own check, against their type's schema and the chain's
//! caps, so this is only about free text.
//!
//! Words are off unless the owner signed `text` for that contact, and even then two agents answering
//! each other stop at a daily count, 100 unless the owner's rules lower it or raise it to at most 200,
//! and at most 40 with anyone the owner hasn't named.

use serde::Serialize;

use crate::requests::is_step_body;
use crate::rules::{Admission, Sender, VerifiedRules};

/// Why words didn't pass. These are fixed, so a record of them holds nothing an agent wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum TextRefused {
    #[error("not_a_contact")]
    NotAContact,
    /// It presents itself as a step, so it goes through the state machine or nowhere.
    #[error("not_text")]
    NotText,
    #[error("text_off")]
    TextOff,
    #[error("too_many_texts")]
    TooManyTexts,
}

/// Whether this body may pass between this agent and `peer`, the other side either way, when
/// `texts_today` have already passed between them in the last day.
pub fn check_text(
    rules: &VerifiedRules,
    peer: &Sender,
    body: &str,
    texts_today: u32,
    now: u64,
) -> Result<(), TextRefused> {
    if is_step_body(body) {
        return Err(TextRefused::NotText);
    }
    if rules.admit(peer, None, now) != Admission::Deliver {
        return Err(TextRefused::NotAContact);
    }
    if !rules.allows_text(peer) {
        return Err(TextRefused::TextOff);
    }
    if texts_today >= rules.texts_per_day_with(peer) {
        return Err(TextRefused::TooManyTexts);
    }
    Ok(())
}

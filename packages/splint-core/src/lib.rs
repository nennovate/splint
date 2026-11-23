//! Splint's core objects: keys, identities, signed envelopes, proofs and requests.
//!
//! Wire formats here are working versions and can change until the owner freezes them.

use std::time::{SystemTime, UNIX_EPOCH};

mod address;
pub mod asks;
mod binding;
pub mod changes;
pub mod contact_invites;
pub mod contact_view;
pub mod controls;
pub mod delegation;
mod delivery;
mod envelope;
mod error;
pub mod grants;
pub mod host_api;
pub mod host_clock;
pub mod host_id;
mod identity;
pub mod invites;
mod join;
mod jws;
mod keys;
pub mod outbound;
pub mod owner_agents;
pub mod owner_call;
pub mod owner_session;
pub mod owner_view;
pub mod pairing;
mod passkey;
pub mod prepared;
pub mod private_files;
mod proof;
pub mod reading_key;
pub mod recovery_code;
mod registration;
pub mod registration_state;
pub mod release;
pub mod requests;
mod retirement;
pub mod rules;
mod sealing;
pub mod secrets_in_text;
#[cfg(test)]
mod spec_vectors;
pub mod transport;
#[cfg(test)]
mod wycheproof;

pub use address::{
    ADDRESS_SEPARATOR, LINK_SCHEME, MIN_HANDLE_CHARS_WITHOUT_CODE, OWNER_ID_FORM_CHARS,
    OWNER_SEPARATOR, TYPED_SEPARATOR, address_named, agent_word, canonical_address,
    canonical_domain, email_form, from_link, in_link, is_temporary_name, is_valid_handle,
    is_valid_name, link_form, may_be_owner_name, may_be_owner_name_with_code,
    may_take_without_code, name_parts, named_under, owner_id_form, owner_id_start, parse_address,
    same_handle_and_host, same_host, temporary_name, with_owner_part,
};
pub use binding::{
    PART_SEPARATOR as BINDING_PART_SEPARATOR, VerifiedBinding, VerifiedRelease,
    claimed_released_agent,
};
pub use delivery::{DeliveryFailure, DeliveryState};
pub use envelope::{
    MessageId, SignedEnvelope, VerifiedEnvelope, claimed_dates_fit, claimed_message_id,
    claimed_sender, random_nonce, sign_envelope, sign_sealed_envelope, sign_with_nonce,
};
pub use error::Error;
pub use identity::{
    AGENT_KEYS_LOST_EXIT, AgentKeys, Identity, MAX_ADDITIONS, MAX_KEYS, MAX_RECOVERIES, OwnerKey,
    RecoveryRule, SplintId,
};
pub use join::{JoinReply, MoveReply, answer_to_ask, answering_ask, ask_kept_at, check_ask_mac};
pub use keys::{GuestKey, HeldKey, PublicKey, SigningKey, es256_from_der, secrets_match};
pub use passkey::{Challenge, MAX_BATCH, PasskeyAssertion, RpId};
pub use proof::{AccessProof, DeliveryProof, claimed_agent, signed_by_owner_now};
pub use registration::{MIN_SIGNUP_CODE_CHARS, REGISTER_PATH, VerifiedRegistration, signup_id};
pub use retirement::{
    RECOVERY_WINDOW_SECS, RetirementReason, VerifiedRetirement, VerifiedStop, claimed_retired_agent,
};
pub use sealing::{
    Outside, SealFor, SealPublicKey, Sealing, SealingKey, is_sealed_body, seal_note,
};

/// How long a message stays deliverable when its sender doesn't say otherwise.
pub const DEFAULT_MESSAGE_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;

/// The longest a message can stay valid. Hosts remember a message until it expires, to refuse
/// replays, so this also bounds how long they keep that record.
pub const MAX_MESSAGE_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;

/// How far a sender's clock can run ahead, and how long a proof stays valid.
pub const CLOCK_TOLERANCE_SECS: u64 = 120;

/// The current time in seconds. A clock set before 1970 reads as 0, which fails freshness checks.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// An identity whose backup nobody kept, for tests that aren't about recovery.
#[cfg(test)]
pub(crate) fn test_identity(key: &SigningKey) -> Identity {
    let backup = SigningKey::generate().unwrap();
    Identity::create(
        key,
        &test_seal(),
        RecoveryRule::backup_key(&backup.public_key()),
    )
    .unwrap()
}

/// A sealing key's public half whose private half nobody kept, for tests that seal nothing.
#[cfg(test)]
pub(crate) fn test_seal() -> SealPublicKey {
    SealingKey::generate().unwrap().public_key()
}

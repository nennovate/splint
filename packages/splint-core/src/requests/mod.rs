//! Interactions: conversations and requests, each a chain of signed steps. Core handles the chain,
//! states, versions, deadlines, approvals, outcomes and receipts for any type, and a small schema for
//! each type says what its fields can hold. See `docs/protocol.md`.
//!
//! State is a function of which valid steps a reader holds, and nothing anyone signs or stores says
//! what it is, so a host can only withhold steps. It can't forge, reorder or replay its way to
//! another state.
//!
//! Wrong use doesn't compile. A chain only moves on a [`VerifiedEnvelope`], its state has no setter,
//! and what the state is worked out from can't be reached:
//!
//! ```compile_fail
//! # use splint_core::requests::{Chain, Parties};
//! # fn wrong(chain: &mut Chain) {
//! chain.apply("a string from the network");
//! # }
//! ```
//!
//! ```compile_fail
//! # use splint_core::requests::{Chain, RequestState};
//! # fn wrong(chain: &mut Chain) {
//! chain.positions.clear();
//! # }
//! ```
//!
//! A step can only be signed once the chain has allowed it, so there's no way to build one by hand:
//!
//! ```compile_fail
//! # use splint_core::requests::CheckedStep;
//! let step = CheckedStep { step: todo!(), to: todo!(), deadline: 0, copied_dates: None };
//! ```
//!
//! And an approval is only a [`VerifiedApproval`] once an owner's signature on it has checked out:
//!
//! ```compile_fail
//! # use splint_core::requests::{Action, VerifiedApproval};
//! let action = Action::Confirm("a JWS an agent made up".to_owned());
//! ```
//!
//! [`VerifiedEnvelope`]: crate::VerifiedEnvelope

mod approval;
mod approving;
mod chain;
mod dialogue;
#[cfg(test)]
mod link_tests;
mod outcome;
mod payment;
mod person_text;
mod schema;
pub(crate) use schema::is_hidden_character;
mod step;

pub use approval::{ApprovalDraft, Decision, Operation, Terms, TermsParty, VerifiedApproval};
pub use approving::{KindForApproval, SameName, for_approval};
pub use chain::{
    Action, Applied, Chain, CheckedStep, HeldMove, Parties, Party, Payment, RequestState, Said,
    Side, WalkRefused,
};
pub use dialogue::{Audience, Dialogue, Line, LineOrder, Origin, PersonSaid, Reader, utc_time};
pub use outcome::{Assurance, Outcome};
pub use payment::{
    ASKS_PER_VALUE, CHANGED_WITHIN_SECS, MAX_PLACES, Paying, PaymentAsk, PaymentStatus,
    PaymentWarning, Place, VerifiedWherePaid, amount_in_words, grouped, money, paying_in,
    reference_of, warnings_for,
};
pub use person_text::{PersonTextFor, VerifiedPersonText};
pub use schema::{
    Document, FieldRule, FieldValue, Fields, GuestForm, InteractionKind, InteractionType,
    MAX_AGREED_PER_CONTACT, MAX_CHOSEN_CHARS, MAX_PROPOSED_BYTES, PROPOSAL, PROPOSAL_DECLINES,
    PROPOSALS_PER_CONTACT_PER_DAY, PauseReason, Schema, Schemas, Signers, TypeName, Word, cap_name,
    has_hidden_characters, with_hidden_shown,
};
#[cfg(test)]
pub(crate) use schema::{example, examples};
pub(crate) use step::outside_of;
pub use step::{
    Deadline, GuestOpen, GuestStep, HostChecks, MAX_DATE_AHEAD_SECS, Offer, ProposedSchema,
    StepKind, StepOf, carries_a_delegates_yes, check_agents_step_on_a_link, check_at_sending_host,
    guest_open_at_host, guest_step_of, hold_of, is_step_body, note_receipt_of, request_of,
};

use serde::Serialize;

/// Offers per side per request, counting `open`. Each of these caps bounds how long a line can get.
pub const OFFERS_PER_SIDE: u8 = 3;
/// Progress reports per request, whatever happens to its version.
pub const PROGRESS_REPORTS: u8 = 8;
/// Pauses per request, each with its `resume`.
pub const PAUSES: u8 = 3;
/// Messages per side per conversation. A longer talk starts a new one, naming this one in `supersedes`.
pub const SAYS_PER_SIDE: u8 = 160;
const MAX_STEP_BYTES: usize = 4 * 1024;

/// Why a step can't join a chain. These are fixed words, with no counterparty content in them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Refused {
    #[error("not a party to this request")]
    WrongParty,
    #[error("the step's signature doesn't verify")]
    BadSignature,
    #[error("this step is already in the chain")]
    Replay,
    #[error("not a valid step")]
    Malformed,
    #[error("the step belongs to another request")]
    WrongRequest,
    #[error("the step follows one that hasn't arrived")]
    UnknownPrev,
    #[error("this request holds too many steps")]
    TooManySteps,
    #[error("it isn't this party's turn to make this move")]
    OutOfTurn,
    #[error("the request's deadline has passed")]
    AfterDeadline,
    #[error("this side has no offers left")]
    NoOffersLeft,
    #[error("this side has no more of those moves left")]
    NoMovesLeft,
    #[error("that value isn't in the latest offer")]
    NotOffered,
    #[error(
        "this type isn't agreed between these two agents: propose it with type/1 first, or use one they agreed"
    )]
    UnknownType,
    #[error(
        "a proposed type has to fit in 2 KiB, with at most 16 fields in a section, 16 entries in a list and 512 characters of names, words and numbers"
    )]
    TypeTooBig,
    #[error(
        "a proposed type can't be core's own, name a paid value without its currency or other unit, hold a number past 2^53, or a text field longer than 500 characters"
    )]
    TypeUnsafe,
    #[error(
        "a type with this name and version is already agreed with this contact, with other rules: give the new one a new version"
    )]
    NameTaken,
    #[error("32 types are already agreed with this contact")]
    TooManyTypes,
    #[error("two types have already been proposed to or by this contact today")]
    TooManyProposals,
    #[error("the owner's rules don't let this contact use this type")]
    TypeNotAllowed,
    #[error("this move needs an owner's approval")]
    ApprovalMissing,
    #[error("the approval isn't signed by this party's owner")]
    ApprovalBadSignature,
    #[error("the approval doesn't match this step")]
    ApprovalMismatch,
    #[error("the approval had expired when this step was signed")]
    ApprovalExpired,
    #[error("this is past what the owner lets this agent do by itself")]
    OverLimit,
    #[error("a person's words on this step aren't signed for it by this party's owner")]
    BadPersonText,
    #[error(
        "where this party gets paid isn't signed by its owner, or isn't in a shape Splint takes"
    )]
    BadWherePaid,
    #[error(
        "this request can't be paid this way: it isn't completed, the value isn't paid to this side, or the payer's owner didn't sign the terms"
    )]
    NotPayable,
    #[error("the amount, unit, reference or place doesn't match the agreed terms")]
    PaymentMismatch,
    #[error("a time or a deadline here isn't within two weeks after the step")]
    OutsideWindow,
    #[error("a one-use link has one offer, so a new offer is a new link")]
    GuestCounter,
    #[error(
        "this agent's person hasn't set up their controls yet, so it can't commit to a value or carry an owner's signature"
    )]
    OwnerUnconfirmed,
    #[error(
        "the other side's person hasn't set up their controls yet, so nothing that commits an owner to a value can be signed with them"
    )]
    TheirOwnerUnconfirmed,
    #[error(
        "the owner hasn't approved this contact, so only their own yes can commit them to anything with them"
    )]
    DelegateNotForContact,
}

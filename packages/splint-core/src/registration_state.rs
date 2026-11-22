//! How far a Signet has got with signing on at its host, as its API says it to `splint` and to whatever
//! runs the agent. Signet answers before its host does, so "it answers" says nothing about this.

use serde::{Deserialize, Serialize};

/// The word Signet refuses an agent's call with while its host hasn't taken it back yet.
pub const NOT_REGISTERED_YET: &str = "not_registered_yet";
/// The word Signet refuses an agent's call with when its host didn't answer that call.
pub const HOST_UNREACHABLE: &str = "host_unreachable";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    /// Its host has taken it since this Signet started.
    Registered,
    /// It holds no binding that fits it, so its owner has to sign one before there's anything to say.
    NotBound,
    /// It holds a binding, and its first try at its host hasn't ended yet.
    Starting,
    /// Its host doesn't answer, or answers that it can't take anything now. Tried again by itself.
    HostUnreachable,
    /// Its host refuses this computer's dates. Tried again by itself, as a clock can be set right.
    ClockOff,
    /// One of its host's limits, which time lifts. Tried again by itself.
    HostBusy,
    /// Its host, or whatever answers at its address now, said no. Tried again by itself, slowly.
    HostRefused,
    /// Its host speaks another Splint protocol until one side updates. Tried again by itself, slowly.
    OtherProtocol,
    /// The signup code it was given is wrong or spent. Not tried again.
    SignupCodeRefused,
    /// Someone else has this agent's handle there. Not tried again.
    NameTaken,
    /// Its host holds a later recovery, a revocation or its retirement. Only its owner can act.
    NeedsOwner,
    /// A word from a later release.
    #[serde(other)]
    Unknown,
}

impl RegistrationState {
    /// Whether it holds a binding its host hasn't taken yet, and is still going to its host with it.
    #[must_use]
    pub fn keeps_trying(self) -> bool {
        matches!(
            self,
            Self::Starting
                | Self::HostUnreachable
                | Self::ClockOff
                | Self::HostBusy
                | Self::HostRefused
                | Self::OtherProtocol
        )
    }

    /// Whether it holds a binding that fits it, whatever its host made of that. What a host answers
    /// never decides whether an agent may leave it, so this is what a move goes by. The one thing that
    /// stops a move is a retirement its owner signed, which Signet holds and checks apart from this.
    #[must_use]
    pub fn holds_a_binding(self) -> bool {
        self.keeps_trying()
            || matches!(
                self,
                Self::Registered | Self::SignupCodeRefused | Self::NameTaken | Self::NeedsOwner
            )
    }
}

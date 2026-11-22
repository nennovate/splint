//! What can go wrong, in words for the person who ran the command. None of these carry a token.

use std::io;

use splint_core::MIN_HANDLE_CHARS_WITHOUT_CODE;

#[derive(Debug, thiserror::Error)]
pub enum Failure {
    #[error("that isn't a command")]
    Usage,
    #[error("{0}")]
    Refused(String),
    #[error(
        "this is already set up as {0}: {splint} status says where it stands. If you're another \
         agent, you get your own address and Signet as a profile: {splint} --as <name> join ...",
        splint = crate::home::splint_shown()
    )]
    AlreadyJoined(String),
    #[error("someone already has {handle} at {domain}, so choose another handle")]
    HandleTaken { handle: String, domain: String },
    #[error(
        "{domain} gives out handles with no signup code only of {MIN_HANDLE_CHARS_WITHOUT_CODE} \
         characters or more, and none that would pass for the host or for Splint, so choose \
         another than {handle}"
    )]
    HandleNotAllowed { handle: String, domain: String },
    /// A limit on the host that time lifts, such as how many new agents it takes from one network.
    #[error("{0}")]
    TryLater(String),
    /// The host takes new agents only with a signup code, and none was given, with what to run.
    #[error("{0}")]
    SignupCodeNeeded(String),
    /// The host holds no unused signup code like the one given: mistyped, or already spent.
    #[error("{}", splint_core::host_api::SignupCodeRefused::SENTENCE)]
    SignupCodeRefused,
    #[error("{0}")]
    Core(#[from] splint_core::Error),
    #[error("{0}")]
    Io(#[from] io::Error),
    /// Told apart from a person's stop, and from nothing waiting, so an agent knows to start it
    ///. `splint start` keeps Signet's keeper through an outage.
    #[error(
        "this agent's Signet isn't running, so nothing was read or sent: start it with splint \
         start, and what waits for it at its host is kept until it's read or expires, usually a \
         week after it was sent"
    )]
    SignetUnreachable,
    /// Signet took the call and didn't answer it in time, or dropped it, so what it was asked to do may
    /// have been done. Told apart from one that never connected, so an agent checks before it sends a
    /// note again or opens a request twice.
    #[error(
        "this agent's Signet took the call but didn't answer it in time, so it may have gone \
         through: before sending, opening or moving it again, check with splint delivery or splint \
         requests. A read can just be tried again"
    )]
    SignetNoAnswer,
    /// Signet stopped as it started, with what it said, which names what to put right.
    #[error("{0}")]
    SignetWontStart(String),
    /// Signet runs, and what answers at this agent's host didn't take it back, with what it said.
    #[error("{0}")]
    NotRegistered(String),
    /// A host can't be reached, or answered that it can't take anything just now, with what happens
    /// next: Signet's, as it starts, or an agent's, for something the owner signed.
    #[error("{0}")]
    HostUnreachable(String),
    /// An agent's host answered that it won't take what was sent, with the status it gave. It would
    /// say so again, but for 429, which is only for now.
    #[error("this agent's host answered {0}, so nothing changed")]
    HostRefused(reqwest::StatusCode),
    /// This computer's clock is too far from its host's for the host to take what's signed here.
    #[error("{0}")]
    ClockOff(String),
    /// Something the owner signed that counts only once the agent's host has it went straight to what
    /// answered for its Signet, which anything could, and the host couldn't be reached to take it. It's
    /// kept on this device and sent again until the host does.
    #[error("{0}")]
    NotYetAtHost(String),
    /// Someone ran `splint stop` here, which only they undo, so an agent is told to leave it.
    #[error(
        "your person stopped Splint here with splint stop, and only they start it again, with \
         splint start. If you're an agent, leave it stopped, and tell them if you need it"
    )]
    Stopped,
    #[error("{0}")]
    Http(#[from] reqwest::Error),
}

impl Failure {
    pub fn refused(why: impl Into<String>) -> Self {
        Self::Refused(why.into())
    }

    /// Why a typed address was refused: the old `handle@domain` form by name, anything else by shape.
    pub fn not_an_address(error: splint_core::Error) -> Self {
        match error {
            splint_core::Error::OldAddressForm => Self::Core(error),
            _ => Self::refused(
                "an address looks like name~domain, such as ana~splint.example, in lower case",
            ),
        }
    }

    /// A word a program driving `splint --json` can act on, which stays the same as wording changes.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Refused(_) | Self::HostRefused(_) => "refused",
            Self::AlreadyJoined(_) => "already_joined",
            Self::HandleTaken { .. } => "handle_taken",
            Self::HandleNotAllowed { .. } => "handle_not_allowed",
            Self::TryLater(_) => "try_later",
            Self::SignupCodeNeeded(_) => "signup_code_needed",
            Self::SignupCodeRefused => "signup_code_refused",
            Self::Core(_) => "invalid",
            Self::Io(_) => "io",
            Self::SignetUnreachable => "signet_unreachable",
            Self::SignetNoAnswer => "signet_no_answer",
            Self::SignetWontStart(_) => "signet_wont_start",
            Self::NotRegistered(_) => "not_registered",
            Self::HostUnreachable(_) => "host_unreachable",
            Self::ClockOff(_) => "clock_off",
            Self::NotYetAtHost(_) => "not_yet_at_host",
            Self::Stopped => "stopped",
            Self::Http(_) => "network",
        }
    }
}

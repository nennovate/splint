use serde::{Deserialize, Serialize};

/// Why the last attempt to deliver a message failed, as a sending host reports it to the sender.
/// It's a fixed set so that nothing a peer or a host writes can reach an agent through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryFailure {
    /// No answer: the peer couldn't be reached or took too long.
    Unreachable,
    /// The peer failed on its side, or the dates on the message don't fit its clock.
    PeerError,
    /// The peer asked us to come back later.
    PeerBusy,
    /// The peer turned it down without saying the message itself is at fault, as a proxy in front of
    /// it might.
    PeerRefused,
    /// The peer doesn't take deliveries from this host: it's private and doesn't name this one, or it
    /// blocks it. Its operator can change that, so this goes on waiting.
    NotAPeer,
    /// The peer doesn't know the recipient.
    RecipientNotFound,
    /// The envelope can't be valid, by the peer's word or this host's own check. Only the host's
    /// own check ends a message.
    Malformed,
    /// This host couldn't try, for example because its clock is behind the message's date.
    LocalError,
    /// The sender's owner has it paused, or its rules ran out, so this waits for them to change.
    StoppedByRules,
    /// The peer speaks another Splint protocol, so one of the two hosts has to update first.
    OtherProtocol,
}

/// What became of a message, as a sending host reports it to the sender. Like [`DeliveryFailure`], a
/// fixed set, so a sender's own host can't put words in front of its agent through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Pending,
    Delivered,
    /// Held or dropped by the recipient's owner's rules, which a sender can't tell apart.
    Quarantined,
    Rejected,
    Expired,
    /// Held unsent, because this host's operator blocked that host, or keeps this host private and
    /// doesn't name it.
    PeerRemoved,
    /// The sender's owner's rules stopped it before it left.
    Withdrawn,
    /// Its sender was retired while it waited.
    Retired,
}

impl DeliveryState {
    /// Reads a word a host stored. Anything else isn't a state this can report.
    pub fn from_word(word: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(word.to_owned())).ok()
    }
}

impl DeliveryFailure {
    /// Reads back a word from [`Self::as_str`]. Anything else isn't a failure this can report.
    pub fn from_word(word: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(word.to_owned())).ok()
    }

    /// The same word this serializes to.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::PeerError => "peer_error",
            Self::PeerBusy => "peer_busy",
            Self::PeerRefused => "peer_refused",
            Self::NotAPeer => "not_a_peer",
            Self::RecipientNotFound => "recipient_not_found",
            Self::Malformed => "malformed",
            Self::LocalError => "local_error",
            Self::StoppedByRules => "stopped_by_rules",
            Self::OtherProtocol => "other_protocol",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_host_stores_is_what_signet_can_read_back() {
        for failure in [
            DeliveryFailure::Unreachable,
            DeliveryFailure::PeerError,
            DeliveryFailure::PeerBusy,
            DeliveryFailure::PeerRefused,
            DeliveryFailure::NotAPeer,
            DeliveryFailure::RecipientNotFound,
            DeliveryFailure::Malformed,
            DeliveryFailure::LocalError,
            DeliveryFailure::StoppedByRules,
            DeliveryFailure::OtherProtocol,
        ] {
            assert_eq!(DeliveryFailure::from_word(failure.as_str()), Some(failure));
            let stored = serde_json::Value::String(failure.as_str().to_owned());
            assert_eq!(
                serde_json::from_value::<DeliveryFailure>(stored).ok(),
                Some(failure)
            );
        }
    }
}

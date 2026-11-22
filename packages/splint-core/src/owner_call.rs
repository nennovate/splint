//! An owner's device calling their agent's Signet straight, over a network the agent's operator opted
//! into, rather than by way of its host.
//!
//! What goes there is already signed by the owner, and what comes back is a view the agent signed and
//! sealed to the owner, so nobody on the way can forge either. They could still read what's signed:
//! rules name every contact, with their labels. So the body of each call is sealed to the agent's own
//! sealing key, which its ID commits to, bound to the call it's for. Anyone on the way sees only who
//! talked to whom, when and how much, as a host does.
//!
//! Sealing authorizes nothing: anyone can seal to an agent. Signet opens the body, then takes what's in
//! it by the owner's signature alone, as it would on its own socket, so a call replayed takes nothing
//! that the same signed object given again wouldn't.
//!
//! What an owner signs for an agent that isn't on their own machine is left at that agent's host for
//! its Signet to take, and is sealed the same way, as owner mail: bound to the call that leaves it
//! there, which no call to a Signet shares, so the host between them holds only what it can't open.

use serde::{Deserialize, Serialize};

use crate::host_api::{OWNER_MAIL_PATH, OwnerMail};
use crate::sealing::{SealingKey, seal_note};
use crate::{Error, Identity, SplintId};

/// Where an owner's device reads its agent's view straight from Signet, signed and sealed to them.
pub const OWNER_VIEW_CALL_PATH: &str = "/v0/owner/view";

/// The most a sealed call can be, written out: the biggest signed object, in its field, sealed and
/// written in base64url, with room to spare. Signet reads no more of a body on the network.
pub const MAX_SEALED_CALL_BYTES: usize = 360 * 1024;

/// What owner mail is filled out to a multiple of before it's sealed, with spaces after its JSON, so
/// its size doesn't say which kind of thing it is: only an answer whose terms run long is bigger.
const OWNER_MAIL_PAD_BYTES: usize = 1024;

/// The body of every call that sends something on the network, in place of the call's own body.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedCall {
    pub sealed: String,
}

/// What a sealed call is bound to: its method and path, and the agent, so a body sealed for one call
/// can't be opened as another, or by another agent's Signet.
pub fn owner_call_about(agent: &SplintId, method: &str, path: &str) -> Vec<u8> {
    format!("splint owner call {method} {path} for {agent}").into_bytes()
}

/// Seals a call's JSON body to the agent, for `method` and `path`.
pub fn seal_owner_call(
    agent: &Identity,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<SealedCall, Error> {
    let to = agent.seal_key().ok_or(Error::Malformed)?;
    let sealed = seal_note(to, body, &owner_call_about(agent.id(), method, path))?;
    Ok(SealedCall { sealed })
}

/// Opens what a call sent on the network, as the agent's Signet does: `{"sealed"}` and nothing else, no
/// bigger than [`MAX_SEALED_CALL_BYTES`], sealed to this agent's sealing key for exactly this method and
/// path. What comes out is the call's own body, for Signet to check as it checks one on its own socket.
pub fn open_owner_call(
    key: &SealingKey,
    agent: &SplintId,
    method: &str,
    path: &str,
    call: &[u8],
) -> Result<Vec<u8>, Error> {
    if call.len() > MAX_SEALED_CALL_BYTES {
        return Err(Error::Malformed);
    }
    let call: SealedCall = serde_json::from_slice(call).map_err(|_| Error::Malformed)?;
    key.open_note(&call.sealed, &owner_call_about(agent, method, path))
}

/// Where an owner's device leaves what they signed for `agent`, at its host.
pub fn owner_mail_path(agent: &SplintId) -> String {
    format!("{OWNER_MAIL_PATH}/{agent}")
}

/// Seals something the owner signed for their agent, to leave at its host, which can't open it. It's
/// the call's JSON with spaces after it up to the next kibibyte, bound to the call that leaves it.
pub fn seal_owner_mail(agent: &Identity, mail: &OwnerMail) -> Result<SealedCall, Error> {
    let mut plain = serde_json::to_vec(mail).map_err(|_| Error::Malformed)?;
    let padded = plain
        .len()
        .div_ceil(OWNER_MAIL_PAD_BYTES)
        .saturating_mul(OWNER_MAIL_PAD_BYTES);
    plain.resize(padded, b' ');
    seal_owner_call(agent, "POST", &owner_mail_path(agent.id()), &plain)
}

/// Sealed owner mail as it's sent, the bytes an owner's proof to the host is over.
pub fn mail_body(mail: &SealedCall) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(mail).map_err(|_| Error::Malformed)
}

/// Opens owner mail a host kept, as the agent's Signet does, for it to check by the owner's signature
/// as it checks the same thing on its own socket. Nothing sealed for a call to Signet itself, or for
/// another agent, opens as this.
pub fn open_owner_mail(
    key: &SealingKey,
    agent: &SplintId,
    sealed: &str,
) -> Result<OwnerMail, Error> {
    if sealed.len() > MAX_SEALED_CALL_BYTES {
        return Err(Error::Malformed);
    }
    let about = owner_call_about(agent, "POST", &owner_mail_path(agent));
    let plain = key.open_note(sealed, &about)?;
    serde_json::from_slice(&plain).map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_api::OwnerMailKind;
    use crate::{RecoveryRule, SigningKey};

    fn agent() -> (SealingKey, Identity) {
        let seal = SealingKey::generate().unwrap();
        let identity = Identity::create(
            &SigningKey::generate().unwrap(),
            &seal.public_key(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        )
        .unwrap();
        (seal, identity)
    }

    /// Bugs caught: the spaces that fill owner mail out stopping its Signet reading it, mail whose
    /// size says which kind of thing it is, and mail that opens as a call to Signet's own listener,
    /// or at another agent's Signet.
    #[test]
    fn owner_mail_opens_for_its_agent_alone_and_is_the_same_size_whatever_it_is() {
        let (seal, identity) = agent();
        let words = OwnerMail {
            kind: OwnerMailKind::PersonText,
            signed: "a.b.c".to_owned(),
        };
        let paid = OwnerMail {
            kind: OwnerMailKind::WherePaid,
            signed: "x".repeat(700),
        };
        let sealed_words = seal_owner_mail(&identity, &words).unwrap();
        let sealed_paid = seal_owner_mail(&identity, &paid).unwrap();
        assert_eq!(sealed_words.sealed.len(), sealed_paid.sealed.len());

        let opened = open_owner_mail(&seal, identity.id(), &sealed_paid.sealed).unwrap();
        assert_eq!(opened.kind, OwnerMailKind::WherePaid);
        assert_eq!(opened.signed, paid.signed);

        let body = mail_body(&sealed_words).unwrap();
        let at_listener =
            open_owner_call(&seal, identity.id(), "POST", "/v0/owner/person-text", &body);
        assert!(matches!(at_listener, Err(Error::CantOpen)));
        let (other_seal, other) = agent();
        assert!(open_owner_mail(&other_seal, other.id(), &sealed_words.sealed).is_err());
        assert!(open_owner_mail(&seal, other.id(), &sealed_words.sealed).is_err());
    }
}

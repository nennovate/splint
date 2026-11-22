//! Invitations: how a first contact is made without trusting a host. See `docs/protocol.md`.
//!
//! The link holds a private key, so whoever opens it can name who may use it, and a host that relays
//! the redeem can't change that name or use it for an agent of its own. The owner's rules hold the
//! public key.

use serde::{Deserialize, Serialize};

use crate::requests::{InteractionType, is_step_body};
use crate::rules::RulesInvite;
use crate::{CLOCK_TOLERANCE_SECS, Error, Identity, PublicKey, SigningKey, SplintId, jws};

const REDEEM_TYPE: &str = "splint-invite-redeem";
const REDEEM_VERSION: u8 = 1;
const REDEEM_STEP: &str = "redeem_invite";
const LINK_PREFIX: &str = "splint:invite?a=";
const INVITE_ID_CHARS: usize = 16;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemPayload {
    v: u8,
    invite: String,
    inviter: SplintId,
    redeemer: SplintId,
    issued_at: u64,
}

/// What a link says, once opened. It holds the invitation's private key, and so has no `Debug`.
pub struct InviteLink {
    pub address: String,
    pub agent: SplintId,
    pub id: String,
    key: SigningKey,
}

impl InviteLink {
    /// Makes a new invitation: the link to pass on outside Splint, and the entry for the rules. Its
    /// ID comes from its key, so a new invitation can't inherit an old one's redeemer.
    pub fn create(
        address: &str,
        agent: &SplintId,
        types: Vec<InteractionType>,
        expires_at: u64,
    ) -> Result<(String, RulesInvite), Error> {
        crate::parse_address(address)?;
        let key = SigningKey::generate()?;
        let public = key.public_key().encoded();
        let id: String = public.chars().rev().take(INVITE_ID_CHARS).collect();
        let link = format!(
            "{LINK_PREFIX}{}#g={}&i={id}&k={}",
            crate::in_link(address),
            agent.as_str(),
            key.invitation_text()?,
        );
        let invite = RulesInvite {
            id,
            key: public,
            types,
            expires_at,
        };
        Ok((link, invite))
    }

    pub fn parse(link: &str) -> Result<Self, Error> {
        let rest = link.strip_prefix(LINK_PREFIX).ok_or(Error::Malformed)?;
        let (address, fragment) = rest.split_once('#').ok_or(Error::Malformed)?;
        let address = crate::from_link(address);
        crate::parse_address(&address)?;
        let field = |name: &str| {
            fragment
                .split('&')
                .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
                .ok_or(Error::Malformed)
        };
        let id_of = |text: &str| serde_json::Value::String(text.to_owned());
        Ok(Self {
            address,
            agent: serde_json::from_value(id_of(field("g")?)).map_err(|_| Error::Malformed)?,
            id: field("i")?.to_owned(),
            key: SigningKey::from_invitation_text(field("k")?)?,
        })
    }

    /// Names who may use this invitation, in the body their Signet sends.
    pub fn redeem_for(&self, redeemer: &SplintId, now: u64) -> Result<String, Error> {
        let payload = serde_json::to_vec(&RedeemPayload {
            v: REDEEM_VERSION,
            invite: self.id.clone(),
            inviter: self.agent.clone(),
            redeemer: redeemer.clone(),
            issued_at: now,
        })
        .map_err(|_| Error::Malformed)?;
        jws::sign(&self.key, REDEEM_TYPE, &payload)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemBody {
    step: String,
    proof: String,
}

pub fn redeem_body(proof: &str) -> Result<String, Error> {
    serde_json::to_string(&RedeemBody {
        step: REDEEM_STEP.to_owned(),
        proof: proof.to_owned(),
    })
    .map_err(|_| Error::Malformed)
}

/// The proof in a message's body, if the body is a redeem. It isn't part of any request's chain.
/// Every redeem is a step body, which an agent can't send. Without that check serde would also read
/// `["redeem_invite","<proof>"]` as a redeem, and that passes for free text.
pub fn redeem_proof_in(body: &str) -> Option<String> {
    if !is_step_body(body) {
        return None;
    }
    let body: RedeemBody = serde_json::from_str(body).ok()?;
    (body.step == REDEEM_STEP).then_some(body.proof)
}

/// Which invitation a proof claims to redeem, to find its key with. Never act on the result.
pub fn claimed_invite(compact: &str) -> Result<String, Error> {
    let payload = jws::unverified_payload(compact, REDEEM_TYPE)?;
    let payload: RedeemPayload = serde_json::from_slice(&payload).map_err(|_| Error::Malformed)?;
    Ok(payload.invite)
}

/// A redeem signed by the invitation's key, for the agent it was offered by, from the agent it names.
#[derive(Debug)]
pub struct VerifiedRedeem {
    redeemer: SplintId,
}

impl VerifiedRedeem {
    /// `recipient` is who the redeem reached and `sender` who sent it. Every check is here so that a
    /// host and Signet can't differ, and the spec's vectors hold them all.
    pub fn verify(
        compact: &str,
        invite: &RulesInvite,
        recipient: &SplintId,
        sender: &Identity,
        used: bool,
        now: u64,
    ) -> Result<Self, Error> {
        let key = PublicKey::from_encoded(&invite.key)?;
        let bytes = jws::verify(compact, &key, REDEEM_TYPE)?;
        let payload: RedeemPayload =
            serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        if payload.v != REDEEM_VERSION {
            return Err(Error::Malformed);
        }
        if payload.invite != invite.id || &payload.inviter != recipient {
            return Err(Error::ProofMismatch);
        }
        if &payload.redeemer != sender.id() {
            return Err(Error::WrongRedeemer);
        }
        if now >= invite.expires_at {
            return Err(Error::Expired);
        }
        if payload.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        if used {
            return Err(Error::AlreadyUsed);
        }
        Ok(Self {
            redeemer: payload.redeemer,
        })
    }

    pub fn redeemer(&self) -> &SplintId {
        &self.redeemer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    const NOW: u64 = 1_793_750_400;

    fn meeting() -> Vec<InteractionType> {
        vec![crate::requests::example("meeting/1")]
    }

    fn agent() -> Identity {
        crate::test_identity(&SigningKey::generate().unwrap())
    }

    #[test]
    fn a_link_names_one_invitation_and_only_its_key_can_redeem_it() {
        let (ana, ben) = (agent(), agent());
        let (link, invite) =
            InviteLink::create("ana~host.example", ana.id(), meeting(), NOW + 60).unwrap();
        let opened = InviteLink::parse(&link).unwrap();
        assert_eq!(opened.address, "ana~host.example");
        assert_eq!(&opened.agent, ana.id());

        let proof = opened.redeem_for(ben.id(), NOW).unwrap();
        let redeem = VerifiedRedeem::verify(&proof, &invite, ana.id(), &ben, false, NOW).unwrap();
        assert_eq!(redeem.redeemer(), ben.id());
        let elsewhere = VerifiedRedeem::verify(&proof, &invite, ben.id(), &ben, false, NOW);
        assert_eq!(elsewhere.err(), Some(Error::ProofMismatch));

        let body = redeem_body(&proof).unwrap();
        assert!(crate::requests::is_step_body(&body));
        assert_eq!(redeem_proof_in(&body), Some(proof));
        assert_eq!(redeem_proof_in("{\"step\":\"open\",\"proof\":\"x\"}"), None);
        assert_eq!(redeem_proof_in("plain words"), None);
    }

    /// A URI's query can't hold brackets, so an IPv6 address's are encoded, and only those.
    #[test]
    fn a_link_carries_an_address_and_gives_it_back_as_it_was() {
        let ana = agent();
        for address in ["ana~host.example:7001", "ana.jeff~[::1]:7001"] {
            let (link, _) = InviteLink::create(address, ana.id(), meeting(), NOW).unwrap();
            let query = link.strip_prefix(LINK_PREFIX).unwrap().split('#').next();
            assert!(
                query.is_some_and(|query| !query.contains(['[', ']'])),
                "{link}"
            );
            assert_eq!(InviteLink::parse(&link).unwrap().address, address);
        }
        let (link, _) = InviteLink::create("ana~host.example", ana.id(), meeting(), NOW).unwrap();
        assert!(
            link.starts_with("splint:invite?a=ana~host.example#"),
            "{link}"
        );
        for other_spelling in [
            link.replace("host.example", "HOST.example"),
            link.replace("host.example", "host.example."),
            link.replace('~', "::"),
            link.replace('~', "%7E"),
            link.replace('~', "@"),
        ] {
            assert!(
                InviteLink::parse(&other_spelling).is_err(),
                "{other_spelling}"
            );
        }
    }

    /// Serde also reads a struct from a list, and a list isn't a step, so an agent could send one.
    #[test]
    fn only_what_counts_as_a_step_can_be_a_redeem() {
        let list = serde_json::json!(["redeem_invite", "a proof"]).to_string();
        assert!(!crate::requests::is_step_body(&list));
        assert_eq!(redeem_proof_in(&list), None);
        assert_eq!(redeem_proof_in(&format!(" {list}")), None);

        let spaced = format!(" {}", redeem_body("a proof").unwrap());
        assert!(crate::requests::is_step_body(&spaced));
        assert_eq!(redeem_proof_in(&spaced), Some("a proof".to_owned()));
    }

    #[test]
    fn a_damaged_link_is_refused() {
        let ana = agent();
        let (link, _) = InviteLink::create("ana~host.example", ana.id(), meeting(), NOW).unwrap();
        for damaged in [
            link.replace("splint:invite", "splint:other"),
            link.replace('#', "?"),
            link.replace("&k=", "&x="),
            format!("{link}!"),
        ] {
            assert!(InviteLink::parse(&damaged).is_err(), "{}", damaged.len());
        }
    }
}

//! Invites over Splint: one agent asks another to be contacts, by address or by contact card, and the
//! other's agent answers with an acceptance naming that exact invite. See `docs/protocol.md`.
//!
//! The invite names the agent ID it's for, which comes from a lookup through that address's host or
//! from a card. So the acceptance has to be signed by that ID's key, and a host can't answer for
//! someone else after the invite has gone. Both halves together are a pending contact, which an
//! owner's side checks for itself before it signs anyone into the rules.

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::requests::is_step_body;
use crate::{
    CLOCK_TOLERANCE_SECS, Error, Identity, SigningKey, SplintId, VerifiedBinding,
    canonical_address, from_link, in_link, jws, random_nonce,
};

const INVITE_TYPE: &str = "splint-invite";
const ACCEPTANCE_TYPE: &str = "splint-invite-accept";
const VERSION: u8 = 1;
const INVITE_STEP: &str = "invite";
const ACCEPTANCE_STEP: &str = "invite_accept";
/// An invite nobody answers in a week is over. Hosts keep one no longer than its envelope.
pub const MAX_INVITE_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;
/// 16 random bytes, in base64url.
const NONCE_CHARS: usize = 22;
const CARD_PREFIX: &str = "splint:card?a=";
const CARD_ID_FIELD: &str = "&g=";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitePayload {
    v: u8,
    from: SplintId,
    from_address: String,
    to: String,
    to_agent: SplintId,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptancePayload {
    v: u8,
    invite: String,
    inviter: SplintId,
    invitee: SplintId,
    issued_at: u64,
}

/// What an inviting agent's Signet fills in. `to_agent` is the ID it found at `to`, or a card gave.
pub struct InviteDraft<'a> {
    pub from_address: &'a str,
    pub to: &'a str,
    pub to_agent: &'a SplintId,
    pub expires_at: u64,
}

/// An address in the one spelling every lookup and every rule uses, and nothing else.
fn is_one_spelling(address: &str) -> bool {
    canonical_address(address).is_ok_and(|canonical| canonical == address)
}

fn is_an_agents_id(id: &SplintId) -> bool {
    id.is_well_formed() && !id.is_guest()
}

/// A payload only in the bytes this module writes, fields in their order, so it has no room for
/// anything else and every reader parses it the same way.
fn in_its_one_encoding<T: Serialize + serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, Error> {
    let payload: T = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
    if serde_json::to_vec(&payload).map_err(|_| Error::Malformed)? != bytes {
        return Err(Error::Malformed);
    }
    Ok(payload)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

/// Signs an invite from `from` to the agent the draft names. Its ID is the hash of its payload.
pub fn sign_invite(
    key: &SigningKey,
    from: &Identity,
    draft: &InviteDraft<'_>,
    now: u64,
) -> Result<String, Error> {
    let payload = InvitePayload {
        v: VERSION,
        from: from.id().clone(),
        from_address: draft.from_address.to_owned(),
        to: draft.to.to_owned(),
        to_agent: draft.to_agent.clone(),
        issued_at: now,
        expires_at: draft.expires_at,
        nonce: random_nonce()?,
    };
    payload.check(now)?;
    if &payload.to_agent == from.id() || payload.to == payload.from_address {
        return Err(Error::ProofMismatch);
    }
    let bytes = serde_json::to_vec(&payload).map_err(|_| Error::Malformed)?;
    jws::sign(key, INVITE_TYPE, &bytes)
}

impl InvitePayload {
    /// Everything about an invite but who signed it and whom it reached.
    fn check(&self, now: u64) -> Result<(), Error> {
        let nonce_fits = self.nonce.len() == NONCE_CHARS
            && jws::decode(&self.nonce).is_ok_and(|raw| raw.len() == 16);
        if self.v != VERSION
            || !is_an_agents_id(&self.from)
            || !is_an_agents_id(&self.to_agent)
            || !is_one_spelling(&self.from_address)
            || !is_one_spelling(&self.to)
            || !nonce_fits
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_INVITE_LIFETIME_SECS
        {
            return Err(Error::Malformed);
        }
        if self.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        if now >= self.expires_at {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

/// An invite signed by the agent it says it's from, for the agent reading it, still in date.
pub struct VerifiedInvite {
    id: String,
    compact: String,
    payload: InvitePayload,
}

impl VerifiedInvite {
    /// `inviter` is the newest copy of the sender's ID the reader holds, and `invitee` the reader. An
    /// invite meant for another agent is refused, so nobody can pass one on as their own.
    pub fn verify(
        compact: &str,
        inviter: &Identity,
        invitee: &SplintId,
        now: u64,
    ) -> Result<Self, Error> {
        Self::verified_with(compact, false, inviter, invitee, now)
    }

    /// `history` reads it under any key the inviter has had, for a pending contact read back later.
    fn verified_with(
        compact: &str,
        history: bool,
        inviter: &Identity,
        invitee: &SplintId,
        now: u64,
    ) -> Result<Self, Error> {
        let bytes = if history {
            inviter.verify_under_any_key(compact, INVITE_TYPE)?
        } else {
            inviter.verify(compact, INVITE_TYPE)?
        };
        let payload: InvitePayload = in_its_one_encoding(&bytes)?;
        payload.check(now)?;
        if &payload.from != inviter.id() {
            return Err(Error::WrongSigner);
        }
        if &payload.to_agent != invitee {
            return Err(Error::ProofMismatch);
        }
        Ok(Self {
            id: sha256_hex(&bytes),
            compact: compact.to_owned(),
            payload,
        })
    }

    /// The hex SHA-256 of its payload, which is what an acceptance names.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn from(&self) -> &SplintId {
        &self.payload.from
    }

    /// Where the inviter says it can be reached. A reader holds this against the binding its host
    /// passed on, and a false one only sends answers where its messages aren't taken from.
    pub fn from_address(&self) -> &str {
        &self.payload.from_address
    }

    pub fn to(&self) -> &str {
        &self.payload.to
    }

    pub fn to_agent(&self) -> &SplintId {
        &self.payload.to_agent
    }

    pub fn issued_at(&self) -> u64 {
        self.payload.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.payload.expires_at
    }
}

/// Which invite an acceptance says it answers, to find that invite with. Never act on the result.
pub fn claimed_invite(compact: &str) -> Result<String, Error> {
    let bytes = jws::unverified_payload(compact, ACCEPTANCE_TYPE)?;
    let payload: AcceptancePayload =
        serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
    Ok(payload.invite)
}

/// The invited agent's yes to one exact invite, signed by the key the invite named.
pub fn sign_acceptance(
    key: &SigningKey,
    invitee: &Identity,
    invite: &VerifiedInvite,
    now: u64,
) -> Result<String, Error> {
    if invite.to_agent() != invitee.id() {
        return Err(Error::ProofMismatch);
    }
    if now >= invite.expires_at() {
        return Err(Error::Expired);
    }
    let payload = AcceptancePayload {
        v: VERSION,
        invite: invite.id().to_owned(),
        inviter: invite.from().clone(),
        invitee: invitee.id().clone(),
        issued_at: now,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| Error::Malformed)?;
    jws::sign(key, ACCEPTANCE_TYPE, &bytes)
}

/// An acceptance signed by the agent it names, for an invite it names. Whether that invite is one
/// the reader sent, to that agent, is [`VerifiedAcceptance::answers`].
pub struct VerifiedAcceptance {
    payload: AcceptancePayload,
}

impl VerifiedAcceptance {
    /// `invitee` is the newest copy of the sender's ID the reader holds.
    pub fn verify(compact: &str, invitee: &Identity, now: u64) -> Result<Self, Error> {
        let accepted = Self::verified_with(compact, false, invitee)?;
        if accepted.payload.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        Ok(accepted)
    }

    fn verified_with(compact: &str, history: bool, invitee: &Identity) -> Result<Self, Error> {
        let bytes = if history {
            invitee.verify_under_any_key(compact, ACCEPTANCE_TYPE)?
        } else {
            invitee.verify(compact, ACCEPTANCE_TYPE)?
        };
        let payload: AcceptancePayload = in_its_one_encoding(&bytes)?;
        if payload.v != VERSION
            || !is_an_agents_id(&payload.inviter)
            || payload.invite.len() != 64
            || !payload
                .invite
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::Malformed);
        }
        if &payload.invitee != invitee.id() {
            return Err(Error::WrongSigner);
        }
        Ok(Self { payload })
    }

    /// That this answers exactly this invite: the one it names, from that inviter, to the agent the
    /// invite named, and before the invite ran out.
    pub fn answers(&self, invite: &VerifiedInvite) -> Result<(), Error> {
        if self.payload.invite != invite.id()
            || &self.payload.inviter != invite.from()
            || &self.payload.invitee != invite.to_agent()
        {
            return Err(Error::ProofMismatch);
        }
        if self.payload.issued_at >= invite.expires_at() {
            return Err(Error::Expired);
        }
        Ok(())
    }

    pub fn invite(&self) -> &str {
        &self.payload.invite
    }

    pub fn inviter(&self) -> &SplintId {
        &self.payload.inviter
    }

    pub fn invitee(&self) -> &SplintId {
        &self.payload.invitee
    }

    pub fn issued_at(&self) -> u64 {
        self.payload.issued_at
    }
}

/// An invite and the acceptance answering it, as one agent's Signet hands them to its owner's side,
/// with each agent's binding at the address the invite gives for it. Everything that counts is signed
/// by one of the two agents or their owners, so whoever carries it can't change it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingContact {
    pub invite: String,
    pub acceptance: String,
    pub inviter_identity: String,
    pub invitee_identity: String,
    pub inviter_owner_identity: String,
    /// Binds the inviter to the invite's `from_address`.
    pub inviter_binding: String,
    pub invitee_owner_identity: String,
    /// Binds the invitee to the invite's `to`, so a card naming someone else's address gets nothing.
    pub invitee_binding: String,
}

/// Who an owner would be signing in, from a pending contact that checked out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewContact {
    pub agent: SplintId,
    pub address: String,
    /// Whether this agent sent the invite, rather than accepted it.
    pub invited_by_us: bool,
}

impl PendingContact {
    /// The contact `own` would get, if each half is signed by the key of the ID it names and they
    /// answer each other. An owner reads this days later, so the invite's dates go by when it was
    /// accepted, and a signature by a key an ID has since replaced still counts.
    pub fn verify(&self, own: &SplintId) -> Result<NewContact, Error> {
        let inviter = Identity::from_encoded(&self.inviter_identity)?;
        let invitee = Identity::from_encoded(&self.invitee_identity)?;
        let accepted = VerifiedAcceptance::verified_with(&self.acceptance, true, &invitee)?;
        let invite = VerifiedInvite::verified_with(
            &self.invite,
            true,
            &inviter,
            invitee.id(),
            accepted.issued_at(),
        )?;
        accepted.answers(&invite)?;
        bound_at(
            &self.inviter_binding,
            &self.inviter_owner_identity,
            &inviter,
            invite.from_address(),
        )?;
        bound_at(
            &self.invitee_binding,
            &self.invitee_owner_identity,
            &invitee,
            invite.to(),
        )?;
        if own == inviter.id() {
            Ok(NewContact {
                agent: invitee.id().clone(),
                address: invite.to().to_owned(),
                invited_by_us: true,
            })
        } else if own == invitee.id() {
            Ok(NewContact {
                agent: inviter.id().clone(),
                address: invite.from_address().to_owned(),
                invited_by_us: false,
            })
        } else {
            Err(Error::ProofMismatch)
        }
    }
}

/// That this agent's owner put it at this address. Anyone can sign a binding for an agent of their own,
/// so this says what the agent's side claimed, which its own host vouched for when it was taken. It's
/// checked under every key either ID has held, as an owner may read this after a recovery.
fn bound_at(
    binding: &str,
    owner_identity: &str,
    agent: &Identity,
    address: &str,
) -> Result<(), Error> {
    let owner = Identity::from_encoded(owner_identity)?;
    let bound = VerifiedBinding::verify_history(binding, &owner, agent)?;
    if bound.address() == address {
        Ok(())
    } else {
        Err(Error::ProofMismatch)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteBody {
    step: String,
    invite: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceBody {
    step: String,
    acceptance: String,
}

/// What a message body is, when it's one half of an introduction. Neither is part of any request's
/// chain, and both are step bodies, which an agent can't send for itself.
#[derive(Debug, PartialEq, Eq)]
pub enum Introduction {
    Invite(String),
    Acceptance(String),
}

pub fn invite_body(compact: &str) -> Result<String, Error> {
    serde_json::to_string(&InviteBody {
        step: INVITE_STEP.to_owned(),
        invite: compact.to_owned(),
    })
    .map_err(|_| Error::Malformed)
}

pub fn acceptance_body(compact: &str) -> Result<String, Error> {
    serde_json::to_string(&AcceptanceBody {
        step: ACCEPTANCE_STEP.to_owned(),
        acceptance: compact.to_owned(),
    })
    .map_err(|_| Error::Malformed)
}

/// The introduction in a body, only in the one encoding these functions write, so it has no room
/// for anything else.
pub fn introduction_in(body: &str) -> Option<Introduction> {
    if !is_step_body(body) {
        return None;
    }
    if let Ok(invite) = serde_json::from_str::<InviteBody>(body)
        && invite.step == INVITE_STEP
        && invite_body(&invite.invite).ok().as_deref() == Some(body)
    {
        return Some(Introduction::Invite(invite.invite));
    }
    if let Ok(accepted) = serde_json::from_str::<AcceptanceBody>(body)
        && accepted.step == ACCEPTANCE_STEP
        && acceptance_body(&accepted.acceptance).ok().as_deref() == Some(body)
    {
        return Some(Introduction::Acceptance(accepted.acceptance));
    }
    None
}

/// Whether a body presents itself as an introduction, whatever is in it. Something that only claims
/// to be one is refused where it's read, as no reader takes it.
pub fn is_introduction_body(body: &str) -> bool {
    #[derive(Deserialize)]
    struct Probe {
        step: String,
    }
    is_step_body(body)
        && serde_json::from_str::<Probe>(body)
            .is_ok_and(|probe| probe.step == INVITE_STEP || probe.step == ACCEPTANCE_STEP)
}

/// An address and the agent ID behind it, to hand on by any means, so a first contact needs no host
/// to say who's there. Nothing in it is secret, and it fits a QR code as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactCard {
    pub address: String,
    pub agent: SplintId,
}

impl ContactCard {
    pub fn encode(&self) -> String {
        format!(
            "{CARD_PREFIX}{}{CARD_ID_FIELD}{}",
            in_link(&self.address),
            self.agent
        )
    }

    /// Only the exact form `encode` writes, so a card has one spelling and carries nothing else.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let rest = text
            .trim()
            .strip_prefix(CARD_PREFIX)
            .ok_or(Error::Malformed)?;
        let (address, id) = rest.split_once(CARD_ID_FIELD).ok_or(Error::Malformed)?;
        let address = from_link(address);
        let agent: SplintId = serde_json::from_value(serde_json::Value::String(id.to_owned()))
            .map_err(|_| Error::Malformed)?;
        if !is_one_spelling(&address) || !is_an_agents_id(&agent) {
            return Err(Error::Malformed);
        }
        let card = Self { address, agent };
        if card.encode() != text.trim() {
            return Err(Error::Malformed);
        }
        Ok(card)
    }

    pub fn is_card(text: &str) -> bool {
        text.trim().starts_with(CARD_PREFIX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_793_750_400;
    const DAY: u64 = 24 * 60 * 60;

    struct Agent {
        key: SigningKey,
        identity: Identity,
        address: &'static str,
        backup: SigningKey,
        owner_key: SigningKey,
        owner: Identity,
        /// Its owner's binding at `address`.
        binding: String,
    }

    fn binding_at(agent: &Agent, address: &str) -> String {
        let half = VerifiedBinding::sign(
            &agent.owner_key,
            &agent.backup,
            agent.owner.id(),
            &agent.identity,
            address,
            1,
            NOW,
        )
        .unwrap();
        VerifiedBinding::accept(&agent.key, &half, None, &agent.owner, &agent.identity)
            .unwrap()
            .compact()
            .to_owned()
    }

    fn agent(address: &'static str) -> Agent {
        let key = SigningKey::generate().unwrap();
        let backup = SigningKey::generate().unwrap();
        let identity = Identity::create(
            &key,
            &crate::test_seal(),
            crate::RecoveryRule::backup_key(&backup.public_key()),
        )
        .unwrap();
        let owner_key = SigningKey::generate().unwrap();
        let owner = crate::test_identity(&owner_key);
        let mut made = Agent {
            key,
            identity,
            address,
            backup,
            owner_key,
            owner,
            binding: String::new(),
        };
        made.binding = binding_at(&made, address);
        made
    }

    fn invite_from(ana: &Agent, ben: &Agent) -> String {
        let draft = InviteDraft {
            from_address: ana.address,
            to: ben.address,
            to_agent: ben.identity.id(),
            expires_at: NOW + DAY,
        };
        sign_invite(&ana.key, &ana.identity, &draft, NOW).unwrap()
    }

    fn pending(ana: &Agent, ben: &Agent, invite: &str, acceptance: &str) -> PendingContact {
        PendingContact {
            invite: invite.to_owned(),
            acceptance: acceptance.to_owned(),
            inviter_identity: ana.identity.encoded(),
            invitee_identity: ben.identity.encoded(),
            inviter_owner_identity: ana.owner.encoded(),
            inviter_binding: ana.binding.clone(),
            invitee_owner_identity: ben.owner.encoded(),
            invitee_binding: ben.binding.clone(),
        }
    }

    /// Re-encodes a payload with one field changed, keeping the signature it came with.
    fn with_field(compact: &str, field: &str, value: serde_json::Value) -> String {
        let mut parts = compact.split('.');
        let (header, payload, signature) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let mut json: serde_json::Value =
            serde_json::from_slice(&jws::decode(payload).unwrap()).unwrap();
        json[field] = value;
        // Back through the payload's own type, so its fields stay in their one order.
        let bytes = if json.get("to_agent").is_some() {
            serde_json::to_vec(&serde_json::from_value::<InvitePayload>(json).unwrap())
        } else {
            serde_json::to_vec(&serde_json::from_value::<AcceptancePayload>(json).unwrap())
        };
        let payload = jws::encode(&bytes.unwrap());
        format!("{header}.{payload}.{signature}")
    }

    fn resigned(
        key: &SigningKey,
        compact: &str,
        typ: &str,
        field: &str,
        value: serde_json::Value,
    ) -> String {
        let altered = with_field(compact, field, value);
        let payload = jws::decode(altered.split('.').nth(1).unwrap()).unwrap();
        jws::sign(key, typ, &payload).unwrap()
    }

    #[test]
    fn both_sides_get_each_other_from_one_invite_and_its_acceptance() {
        let (ana, ben) = (agent("ana~a.example"), agent("ben~b.example"));
        let compact = invite_from(&ana, &ben);
        let invite =
            VerifiedInvite::verify(&compact, &ana.identity, ben.identity.id(), NOW).unwrap();
        let acceptance = sign_acceptance(&ben.key, &ben.identity, &invite, NOW + 60).unwrap();
        let record = pending(&ana, &ben, &compact, &acceptance);
        let for_ana = record.verify(ana.identity.id()).unwrap();
        assert_eq!(
            (
                for_ana.agent,
                for_ana.address.as_str(),
                for_ana.invited_by_us
            ),
            (ben.identity.id().clone(), "ben~b.example", true)
        );
        let for_ben = record.verify(ben.identity.id()).unwrap();
        assert_eq!(
            (
                for_ben.agent,
                for_ben.address.as_str(),
                for_ben.invited_by_us
            ),
            (ana.identity.id().clone(), "ana~a.example", false)
        );
        let mallory = agent("mallory~a.example");
        assert_eq!(
            record.verify(mallory.identity.id()),
            Err(Error::ProofMismatch)
        );
    }

    /// Bug caught: a host answering a later lookup, or a forwarder, gets an acceptance in from an
    /// agent other than the one the invite named.
    #[test]
    fn only_the_key_the_invite_named_can_accept_it() {
        let (ana, ben, mallory) = (
            agent("ana~a.example"),
            agent("ben~b.example"),
            agent("mallory~b.example"),
        );
        let compact = invite_from(&ana, &ben);
        assert_eq!(
            VerifiedInvite::verify(&compact, &ana.identity, mallory.identity.id(), NOW).err(),
            Some(Error::ProofMismatch)
        );
        let invite =
            VerifiedInvite::verify(&compact, &ana.identity, ben.identity.id(), NOW).unwrap();
        assert_eq!(
            sign_acceptance(&mallory.key, &mallory.identity, &invite, NOW).err(),
            Some(Error::ProofMismatch)
        );
        // Signed by Mallory's key, naming Ben: no key but Ben's verifies as Ben.
        let ben_accepts = sign_acceptance(&ben.key, &ben.identity, &invite, NOW).unwrap();
        let forged = resigned(
            &mallory.key,
            &ben_accepts,
            ACCEPTANCE_TYPE,
            "v",
            serde_json::json!(1),
        );
        assert_eq!(
            pending(&ana, &ben, &compact, &forged).verify(ana.identity.id()),
            Err(Error::BadSignature)
        );
        // Mallory's own acceptance, under her own ID, answers an invite that named Ben.
        let hers = resigned(
            &mallory.key,
            &ben_accepts,
            ACCEPTANCE_TYPE,
            "invitee",
            serde_json::json!(mallory.identity.id()),
        );
        let swapped = PendingContact {
            invitee_identity: mallory.identity.encoded(),
            ..pending(&ana, &ben, &compact, &hers)
        };
        assert_eq!(swapped.verify(ana.identity.id()), Err(Error::ProofMismatch));
    }

    /// Bug caught: a card pairing Dora's address with Carol's ID. Carol accepts, and both owners
    /// would sign Carol in at Dora's address, where she'd then write as Dora.
    #[test]
    fn the_invited_address_has_to_be_where_the_accepting_agent_is_bound() {
        let (ana, carol) = (agent("ana~a.example"), agent("carol~b.example"));
        let draft = InviteDraft {
            from_address: ana.address,
            to: "dora~b.example",
            to_agent: carol.identity.id(),
            expires_at: NOW + DAY,
        };
        let compact = sign_invite(&ana.key, &ana.identity, &draft, NOW).unwrap();
        let invite =
            VerifiedInvite::verify(&compact, &ana.identity, carol.identity.id(), NOW).unwrap();
        let acceptance = sign_acceptance(&carol.key, &carol.identity, &invite, NOW).unwrap();
        let record = pending(&ana, &carol, &compact, &acceptance);
        for own in [ana.identity.id(), carol.identity.id()] {
            assert_eq!(record.verify(own), Err(Error::ProofMismatch));
        }
        // The same goes for an inviter giving an address it isn't bound to.
        let honest = invite_from(&ana, &carol);
        let invite =
            VerifiedInvite::verify(&honest, &ana.identity, carol.identity.id(), NOW).unwrap();
        let acceptance = sign_acceptance(&carol.key, &carol.identity, &invite, NOW).unwrap();
        let mut record = pending(&ana, &carol, &honest, &acceptance);
        assert!(record.verify(ana.identity.id()).is_ok());
        record.inviter_binding = binding_at(&ana, "ana~elsewhere.example");
        assert_eq!(
            record.verify(carol.identity.id()),
            Err(Error::ProofMismatch)
        );
    }

    /// Each field either side signed, changed in turn: without the key the signature fails, and with
    /// the signer's own key the change names some other invite, agent or time, and fails all the same.
    #[test]
    fn every_signed_field_of_an_invite_and_an_acceptance_is_held_to() {
        let (ana, ben, carol) = (
            agent("ana~a.example"),
            agent("ben~b.example"),
            agent("carol~b.example"),
        );
        let compact = invite_from(&ana, &ben);
        let invite =
            VerifiedInvite::verify(&compact, &ana.identity, ben.identity.id(), NOW).unwrap();
        let acceptance = sign_acceptance(&ben.key, &ben.identity, &invite, NOW + 60).unwrap();
        assert!(
            pending(&ana, &ben, &compact, &acceptance)
                .verify(ana.identity.id())
                .is_ok()
        );

        let other_id = serde_json::json!(carol.identity.id());
        let invite_changes = [
            ("v", serde_json::json!(2)),
            ("from", other_id.clone()),
            ("from_address", serde_json::json!("carol~b.example")),
            ("to", serde_json::json!("carol~b.example")),
            ("to_agent", other_id.clone()),
            ("issued_at", serde_json::json!(NOW - 1)),
            ("expires_at", serde_json::json!(NOW + 2 * DAY)),
            ("nonce", serde_json::json!("BBBBBBBBBBBBBBBBBBBBBB")),
        ];
        for (field, value) in &invite_changes {
            let unsigned = with_field(&compact, field, value.clone());
            let record = pending(&ana, &ben, &unsigned, &acceptance);
            assert_eq!(
                record.verify(ana.identity.id()),
                Err(Error::BadSignature),
                "{field}"
            );
            // Ana re-signs it changed: Ben's acceptance named the invite as it was.
            let resigned_invite = resigned(&ana.key, &compact, INVITE_TYPE, field, value.clone());
            let record = pending(&ana, &ben, &resigned_invite, &acceptance);
            assert!(record.verify(ana.identity.id()).is_err(), "{field}");
        }
        let acceptance_changes = [
            ("v", serde_json::json!(2)),
            ("invite", serde_json::json!("0".repeat(64))),
            ("inviter", other_id.clone()),
            ("invitee", other_id),
            ("issued_at", serde_json::json!(NOW + 2 * DAY)),
        ];
        for (field, value) in &acceptance_changes {
            let unsigned = with_field(&acceptance, field, value.clone());
            let record = pending(&ana, &ben, &compact, &unsigned);
            assert_eq!(
                record.verify(ana.identity.id()),
                Err(Error::BadSignature),
                "{field}"
            );
            let resigned_acceptance =
                resigned(&ben.key, &acceptance, ACCEPTANCE_TYPE, field, value.clone());
            let record = pending(&ana, &ben, &compact, &resigned_acceptance);
            assert!(record.verify(ana.identity.id()).is_err(), "{field}");
        }
    }

    #[test]
    fn an_invite_out_of_date_or_from_the_future_is_refused() {
        let (ana, ben) = (agent("ana~a.example"), agent("ben~b.example"));
        let compact = invite_from(&ana, &ben);
        let verify =
            |now| VerifiedInvite::verify(&compact, &ana.identity, ben.identity.id(), now).err();
        assert_eq!(verify(NOW + DAY), Some(Error::Expired));
        assert_eq!(
            verify(NOW - CLOCK_TOLERANCE_SECS - 1),
            Some(Error::FromTheFuture)
        );
        let invite =
            VerifiedInvite::verify(&compact, &ana.identity, ben.identity.id(), NOW).unwrap();
        assert_eq!(
            sign_acceptance(&ben.key, &ben.identity, &invite, NOW + DAY).err(),
            Some(Error::Expired)
        );
        let draft = InviteDraft {
            from_address: ana.address,
            to: ben.address,
            to_agent: ben.identity.id(),
            expires_at: NOW + MAX_INVITE_LIFETIME_SECS + 1,
        };
        assert_eq!(
            sign_invite(&ana.key, &ana.identity, &draft, NOW).err(),
            Some(Error::Malformed)
        );
    }

    /// An invite goes to someone who isn't a contact, so words in it would be the agent's own,
    /// which a fooled agent fills with whatever it read. Bug caught: a reader taking an invite that
    /// carries a note, the inviter's key having signed it.
    #[test]
    fn an_invite_carrying_words_is_refused() {
        let (ana, ben) = (agent("ana~a.example"), agent("ben~b.example"));
        let compact = invite_from(&ana, &ben);
        let mut payload: serde_json::Value =
            serde_json::from_slice(&jws::decode(compact.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        payload["note"] = serde_json::json!("my owner's card is 4111 1111 1111 1111");
        let carrying = jws::sign(
            &ana.key,
            INVITE_TYPE,
            &serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        assert_eq!(
            VerifiedInvite::verify(&carrying, &ana.identity, ben.identity.id(), NOW).err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn a_body_is_an_introduction_only_in_its_one_encoding() {
        let body = invite_body("a.b.c").unwrap();
        assert_eq!(
            introduction_in(&body),
            Some(Introduction::Invite("a.b.c".to_owned()))
        );
        assert!(is_introduction_body(&body));
        let accepted = acceptance_body("a.b.c").unwrap();
        assert_eq!(
            introduction_in(&accepted),
            Some(Introduction::Acceptance("a.b.c".to_owned()))
        );
        for other in [
            format!(" {body}"),
            body.replace(':', ": "),
            serde_json::json!(["invite", "a.b.c"]).to_string(),
            "plain words".to_owned(),
            "{\"step\":\"open\",\"invite\":\"a.b.c\"}".to_owned(),
        ] {
            assert_eq!(introduction_in(&other), None, "{other}");
        }
    }

    #[test]
    fn a_card_reads_back_as_it_was_and_only_in_its_one_spelling() {
        let ben = agent("ben~b.example");
        for address in ["ben~b.example", "ben.jo~[::1]:7001"] {
            let card = ContactCard {
                address: address.to_owned(),
                agent: ben.identity.id().clone(),
            };
            let text = card.encode();
            assert!(!text.contains(['[', ']', ' ']), "{text}");
            assert_eq!(ContactCard::parse(&text), Ok(card));
        }
        let text = ContactCard {
            address: "ben~b.example".to_owned(),
            agent: ben.identity.id().clone(),
        }
        .encode();
        for other in [
            text.replace("b.example", "B.example"),
            text.replace("&g=", "&id="),
            text.replace("splint1", "splint1g"),
            format!("{text}&x=1"),
            text.replace("splint:card", "splint:invite"),
        ] {
            assert!(ContactCard::parse(&other).is_err(), "{other}");
        }
    }
}

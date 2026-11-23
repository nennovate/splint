//! What an owner's device hands back to an agent that asked to join, for the agent to carry to its
//! Signet. See `docs/protocol.md`.
//!
//! The agent only carries this, and everything in it counts because of what the owner signed. So a
//! fooled agent that changes any of it gets a refusal, and one that writes its own gets an address
//! under an owner key it made, which nobody who named its owner or its agent's ID will take.

use aws_lc_rs::{digest, hmac};
use serde::{Deserialize, Serialize};

use crate::delegation::VerifiedDelegation;
use crate::host_api::JoinAnswer;
use crate::identity::hex;
use crate::rules::VerifiedRules;
use crate::{
    AgentKeys, Error, Identity, RecoveryRule, SplintId, VerifiedBinding, jws, parse_address,
    same_host,
};

const VERSION: u8 = 1;
/// Well past two signed statements and two identities, and small enough to refuse before decoding.
const MAX_ENCODED_CHARS: usize = 64 * 1024;
const ASK_KEPT_AT_TAG: &[u8] = b"splint ask kept at v1";
const ASK_ANSWER_TAG: &[u8] = b"splint ask answer v1";
const ASK_ID_BYTES: usize = 16;
const KEPT_AT_BYTES: usize = 16;
const MAC_BYTES: usize = 32;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinReply {
    pub v: u8,
    pub owner_identity: String,
    /// What the agent's ID commits to: a backup key the owner's device holds and the agent never sees.
    pub commitment: String,
    /// The owner's half and the backup's vouch. The agent's Signet adds its half.
    pub binding: String,
    pub rules: String,
    /// The delegation the rules name, for the agent's Signet to hold, when the owner signed one with
    /// them, as their page does when they set up their controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<String>,
}

impl JoinReply {
    pub fn new(owner_identity: String, commitment: String, binding: String, rules: String) -> Self {
        Self {
            v: VERSION,
            owner_identity,
            commitment,
            binding,
            rules,
            delegation: None,
        }
    }

    /// One unbroken word, so it survives being pasted between a person and an agent.
    pub fn encode(&self) -> Result<String, Error> {
        Ok(jws::encode(
            &serde_json::to_vec(self).map_err(|_| Error::Malformed)?,
        ))
    }

    /// Whitespace is ignored, as a chat window may have wrapped it.
    pub fn decode(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_ENCODED_CHARS {
            return Err(Error::Malformed);
        }
        let joined: String = text.split_whitespace().collect();
        let reply: Self =
            serde_json::from_slice(&jws::decode(&joined)?).map_err(|_| Error::Malformed)?;
        if reply.v != VERSION {
            return Err(Error::Malformed);
        }
        Ok(reply)
    }

    /// Whether the owner signed this for exactly this key at exactly this address. A Signet goes by
    /// the first owner it's told, so this comes first: a bad reply must cost nothing.
    pub fn check(&self, agent_key: &AgentKeys, address: &str, now: u64) -> Result<Identity, Error> {
        let (owner, signed_for, _) = self.checked(agent_key, now)?;
        if signed_for != address {
            return Err(Error::ProofMismatch);
        }
        Ok(owner)
    }

    /// The same for a host keeping this until the agent asks for it. It has to be for this host, and
    /// name no contacts: anyone holding the agent's key and the owner's ID can read it there, and an
    /// agent's contacts are nobody else's business.
    pub fn check_for_keeping(
        &self,
        agent_key: &AgentKeys,
        domain: &str,
        now: u64,
    ) -> Result<Identity, Error> {
        let (owner, signed_for, rules) = self.checked(agent_key, now)?;
        if parse_address(&signed_for)?.1 != domain || !rules.names_nobody() {
            return Err(Error::ProofMismatch);
        }
        Ok(owner)
    }

    /// The same for an agent that joined before its owner confirmed, so it already has an ID and an
    /// address. `moved` is that ID once its stand-in has moved the rule to the backup the owner's
    /// device made, which the agent's machine signs first and sends nowhere unless this passes. Says
    /// who the owner is and the address they signed, at the same host, under a name of their choosing.
    pub fn check_confirming(
        &self,
        moved: &Identity,
        address_now: &str,
        now: u64,
    ) -> Result<(Identity, String), Error> {
        let owner = self.confirming_owner()?;
        if moved.rule() != &RecoveryRule::committed_to(&self.commitment)? {
            return Err(Error::ProofMismatch);
        }
        let address = VerifiedBinding::check_from_owner(&self.binding, &owner, moved)?;
        if !same_host(&address, address_now) {
            return Err(Error::ProofMismatch);
        }
        let rules = VerifiedRules::verify(&self.rules, &owner, 0, now)?;
        if rules.agent() != moved.id() {
            return Err(Error::ProofMismatch);
        }
        self.check_delegation(&owner, moved, &rules, now)?;
        Ok((owner, address))
    }

    /// The same for a host keeping a confirmation for one of its own agents, `held` as it is now,
    /// before the move. It names no contacts, for the reason [`Self::check_for_keeping`] gives.
    pub fn check_confirming_for_keeping(
        &self,
        held: &Identity,
        held_address: &str,
        now: u64,
    ) -> Result<Identity, Error> {
        let owner = self.confirming_owner()?;
        let address = VerifiedBinding::check_ahead(&self.binding, &owner, held, &self.commitment)?;
        let rules = VerifiedRules::verify(&self.rules, &owner, 0, now)?;
        if !same_host(&address, held_address) || rules.agent() != held.id() || !rules.names_nobody()
        {
            return Err(Error::ProofMismatch);
        }
        self.check_delegation(&owner, held, &rules, now)?;
        Ok(owner)
    }

    /// Confirming hands an agent to an owner who set up controls, so a stand-in can't confirm for
    /// another.
    fn confirming_owner(&self) -> Result<Identity, Error> {
        let owner = Identity::from_encoded(&self.owner_identity)?;
        if owner.is_unconfirmed_owner() {
            return Err(Error::WrongSigner);
        }
        Ok(owner)
    }

    fn checked(
        &self,
        agent_key: &AgentKeys,
        now: u64,
    ) -> Result<(Identity, String, VerifiedRules), Error> {
        let owner = Identity::from_encoded(&self.owner_identity)?;
        let agent = agent_key.identity(RecoveryRule::committed_to(&self.commitment)?)?;
        let address = VerifiedBinding::check_from_owner(&self.binding, &owner, &agent)?;
        let rules = VerifiedRules::verify(&self.rules, &owner, 0, now)?;
        if rules.agent() != agent.id() {
            return Err(Error::ProofMismatch);
        }
        self.check_delegation(&owner, &agent, &rules, now)?;
        Ok((owner, address, rules))
    }

    /// A delegation carried here is the owner's, for this agent, and the one these rules name, so
    /// nothing rides along that the owner's rules don't allow.
    fn check_delegation(
        &self,
        owner: &Identity,
        agent: &Identity,
        rules: &VerifiedRules,
        now: u64,
    ) -> Result<(), Error> {
        let Some(delegation) = &self.delegation else {
            return Ok(());
        };
        let delegation = VerifiedDelegation::verify(delegation, owner, agent, 0, now)?;
        if !rules.names_delegation(&delegation) {
            return Err(Error::ProofMismatch);
        }
        Ok(())
    }
}

/// An owner's approval of a move to another host, kept at the new host for the agent to take up, for an
/// owner who isn't at the agent's computer. It only carries: everything in it counts by what the owner
/// signed, their half of a binding at the new address, with the vouch of the agent's backup.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveReply {
    pub v: u8,
    pub agent_identity: String,
    pub owner_identity: String,
    pub binding: String,
}

impl MoveReply {
    pub fn new(agent_identity: String, owner_identity: String, binding: String) -> Self {
        Self {
            v: VERSION,
            agent_identity,
            owner_identity,
            binding,
        }
    }

    pub fn encode(&self) -> Result<String, Error> {
        Ok(jws::encode(
            &serde_json::to_vec(self).map_err(|_| Error::Malformed)?,
        ))
    }

    /// Whitespace is ignored, as a chat window may have wrapped it.
    pub fn decode(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_ENCODED_CHARS {
            return Err(Error::Malformed);
        }
        let joined: String = text.split_whitespace().collect();
        let reply: Self =
            serde_json::from_slice(&jws::decode(&joined)?).map_err(|_| Error::Malformed)?;
        if reply.v != VERSION {
            return Err(Error::Malformed);
        }
        Ok(reply)
    }

    /// The address this owner approved for exactly this agent, or a refusal. A stand-in approves no
    /// move, as it's nobody's word.
    pub fn check(&self, agent: &Identity, owner: &SplintId) -> Result<String, Error> {
        let signer = Identity::from_encoded(&self.owner_identity)?;
        if signer.id() != owner || signer.is_unconfirmed_owner() {
            return Err(Error::WrongSigner);
        }
        if Identity::from_encoded(&self.agent_identity)?.id() != agent.id() {
            return Err(Error::ProofMismatch);
        }
        VerifiedBinding::check_from_owner(&self.binding, &signer, agent)
    }

    /// The same for a host keeping this for the agent with these keys, which has to be a move to this
    /// host. Says whose it is, as that's where the agent looks for it.
    pub fn check_for_keeping(
        &self,
        agent_key: &AgentKeys,
        domain: &str,
    ) -> Result<Identity, Error> {
        let agent = Identity::from_encoded(&self.agent_identity)?;
        if agent.agent_keys().as_ref().map(AgentKeys::encoded) != Some(agent_key.encoded()) {
            return Err(Error::ProofMismatch);
        }
        let owner = Identity::from_encoded(&self.owner_identity)?;
        let address = self.check(&agent, owner.id())?;
        if parse_address(&address)?.1 != domain {
            return Err(Error::ProofMismatch);
        }
        Ok(owner)
    }
}

/// The ID of an agent's ask for its controls, which its link carries. It's the secret that ties an
/// owner's answer to that ask: only the agent and whoever its link reached know it, so the agent takes
/// an answer its host keeps only from them, never from a stranger who knows its address. Provisional.
struct AskSecret([u8; ASK_ID_BYTES]);

impl AskSecret {
    fn of(ask_id: &str) -> Result<Self, Error> {
        let bytes: [u8; ASK_ID_BYTES] = lower_hex(ask_id, ASK_ID_BYTES)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        Ok(Self(bytes))
    }

    /// Where its host keeps answers to it: the first 16 bytes of SHA-256 of a tag and the ID, in hex,
    /// from which nobody works the ID out.
    fn kept_at(&self) -> String {
        let mut hashed = digest::Context::new(&digest::SHA256);
        hashed.update(ASK_KEPT_AT_TAG);
        hashed.update(&self.0);
        hex(hashed
            .finish()
            .as_ref()
            .get(..KEPT_AT_BYTES)
            .unwrap_or_default())
    }

    fn key(&self) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, &self.0)
    }

    fn mac_input(owner: &SplintId) -> Vec<u8> {
        let mut signed = ASK_ANSWER_TAG.to_vec();
        signed.extend_from_slice(owner.as_str().as_bytes());
        signed
    }
}

/// What an owner's side leaves at the agent's host with its answer to the agent's ask for controls:
/// where the agent looks, and the MAC that says this owner saw the ask.
pub fn answer_to_ask(agent_key: String, answer: String, ask_id: &str) -> Result<JoinAnswer, Error> {
    let secret = AskSecret::of(ask_id)?;
    let reply = JoinReply::decode(&answer)?;
    let owner = Identity::from_encoded(&reply.owner_identity)?;
    let mac = hmac::sign(&secret.key(), &AskSecret::mac_input(owner.id()));
    Ok(JoinAnswer {
        agent_key,
        answer,
        kept_at: Some(secret.kept_at()),
        ask_mac: Some(hex(mac.as_ref())),
    })
}

/// Where an agent looks for answers to its ask.
pub fn ask_kept_at(ask_id: &str) -> Result<String, Error> {
    Ok(AskSecret::of(ask_id)?.kept_at())
}

/// That `mac` says `owner` answered this ask, which only someone who saw it can say.
pub fn check_ask_mac(ask_id: &str, owner: &SplintId, mac: &str) -> Result<(), Error> {
    let secret = AskSecret::of(ask_id)?;
    hmac::verify(
        &secret.key(),
        &AskSecret::mac_input(owner),
        &lower_hex(mac, MAC_BYTES)?,
    )
    .map_err(|_| Error::BadSignature)
}

/// A kept answer to this agent's ask, from an owner who saw the ask, with the delegation the ask named
/// a key for. Anything else kept there is nobody's answer to it. The answer itself is checked as any
/// is, when it's taken up.
pub fn answering_ask(kept: &JoinAnswer, ask_id: &str) -> Result<(JoinReply, Identity), Error> {
    let reply = JoinReply::decode(&kept.answer)?;
    let owner = Identity::from_encoded(&reply.owner_identity)?;
    check_ask_mac(
        ask_id,
        owner.id(),
        kept.ask_mac.as_deref().unwrap_or_default(),
    )?;
    if reply.delegation.is_none() {
        return Err(Error::Malformed);
    }
    Ok((reply, owner))
}

/// Lowercase hex of exactly `bytes` bytes, its one spelling.
pub(crate) fn lower_hex(text: &str, bytes: usize) -> Result<Vec<u8>, Error> {
    let lower = |byte: &u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    if text.len() != bytes.saturating_mul(2) || !text.as_bytes().iter().all(lower) {
        return Err(Error::Malformed);
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .ok_or(Error::Malformed)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKey;
    use crate::rules::{ContactStatus, PinnedBy, RulesContact, RulesDraft, RulesLimits};

    const NOW: u64 = 1_793_750_400;
    const ADDRESS: &str = "ana~host.example";
    const SEQ: u64 = 1_793_750_400_000;

    struct Made {
        reply: JoinReply,
        agent_key: AgentKeys,
    }

    fn draft() -> RulesDraft {
        RulesDraft {
            paused: false,
            reach: Default::default(),
            permissions: Default::default(),
            changes: Default::default(),
            sealing: Default::default(),
            delegation: None,
            ends_at: None,
            contacts: Vec::new(),
            invites: Vec::new(),
            limits: RulesLimits {
                new_requests_per_contact_per_day: 3,
                open_requests_per_contact: 3,
                open_approvals: 10,
                new_from_others_per_day: 50,
                texts_per_contact_per_day: 20,
                agreed_texts_per_day: None,
                agreed_new_requests_per_day: None,
                sends_per_hour: None,
                sends_per_day: None,
            },
        }
    }

    fn signed_for(owner_key: &SigningKey, address: &str) -> Made {
        let backup = SigningKey::generate().unwrap();
        let owner = Identity::create(
            owner_key,
            &crate::test_seal(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        )
        .unwrap();
        let agent_key = AgentKeys {
            key: SigningKey::generate().unwrap().public_key(),
            seal: crate::test_seal(),
        };
        let rule = RecoveryRule::backup_key(&backup.public_key());
        let agent = agent_key.identity(rule).unwrap();
        let RecoveryRule::BackupKey { commitment } = RecoveryRule::backup_key(&backup.public_key())
        else {
            panic!("a backup key's rule names a commitment");
        };
        let binding =
            VerifiedBinding::sign(owner_key, &backup, owner.id(), &agent, address, SEQ, NOW)
                .unwrap();
        let rules = draft()
            .sign(owner_key, owner.id(), agent.id(), SEQ, NOW)
            .unwrap();
        Made {
            reply: JoinReply::new(owner.encoded(), commitment, binding, rules),
            agent_key,
        }
    }

    /// Bug caught: an agent asking for its controls by link taking a stranger's answer kept for its
    /// public key, one owner's MAC moved onto another's answer, or an answer with no delegation.
    #[test]
    fn a_kept_answer_counts_for_an_ask_only_with_its_owners_mac_by_that_asks_id() {
        let ask = "0123456789abcdef0123456789abcdef";
        let answered = |delegation: bool| {
            let mut reply = signed_for(&SigningKey::generate().unwrap(), ADDRESS).reply;
            reply.delegation = delegation.then(|| "delegation".to_owned());
            reply.encode().unwrap()
        };
        let kept = |answer: String, mac: Option<String>| JoinAnswer {
            agent_key: "key".to_owned(),
            answer,
            kept_at: Some(ask_kept_at(ask).unwrap()),
            ask_mac: mac,
        };
        let pats = answer_to_ask("key".to_owned(), answered(true), ask).unwrap();
        assert!(answering_ask(&pats, ask).is_ok());
        assert!(matches!(
            answering_ask(&pats, "fedcba9876543210fedcba9876543210"),
            Err(Error::BadSignature)
        ));
        let moved = kept(answered(true), pats.ask_mac.clone());
        assert!(matches!(
            answering_ask(&moved, ask),
            Err(Error::BadSignature)
        ));
        assert!(answering_ask(&kept(answered(true), None), ask).is_err());
        let without = answer_to_ask("key".to_owned(), answered(false), ask).unwrap();
        assert!(answering_ask(&without, ask).is_err());
    }

    #[test]
    fn a_reply_survives_being_pasted_and_checks_out_only_for_its_key_and_address() {
        let owner_key = SigningKey::generate().unwrap();
        let made = signed_for(&owner_key, ADDRESS);
        let word = made.reply.encode().unwrap();
        let (start, end) = word.split_at(word.len() / 2);
        let pasted = JoinReply::decode(&format!(" {start}\n  {end}\n")).unwrap();
        assert!(pasted.check(&made.agent_key, ADDRESS, NOW).is_ok());

        assert!(
            pasted
                .check(&made.agent_key, "ben~host.example", NOW)
                .is_err()
        );
        let other_key = AgentKeys {
            key: SigningKey::generate().unwrap().public_key(),
            seal: made.agent_key.seal.clone(),
        };
        assert!(pasted.check(&other_key, ADDRESS, NOW).is_err());
        // The same signing key with another sealing key is another ID, so a host can't swap it in.
        let other_seal = AgentKeys {
            key: made.agent_key.key.clone(),
            seal: crate::test_seal(),
        };
        assert!(pasted.check(&other_seal, ADDRESS, NOW).is_err());
    }

    #[test]
    fn nothing_in_a_reply_can_be_swapped() {
        let owner_key = SigningKey::generate().unwrap();
        let made = signed_for(&owner_key, ADDRESS);
        let other = signed_for(&owner_key, ADDRESS);
        let stranger = signed_for(&SigningKey::generate().unwrap(), ADDRESS);

        let swapped = [
            // Rules signed for another agent of the same owner.
            JoinReply::new(
                made.reply.owner_identity.clone(),
                made.reply.commitment.clone(),
                made.reply.binding.clone(),
                other.reply.rules.clone(),
            ),
            // Someone else's owner put in, over what the real one signed.
            JoinReply::new(
                stranger.reply.owner_identity.clone(),
                made.reply.commitment.clone(),
                made.reply.binding.clone(),
                made.reply.rules.clone(),
            ),
            // Another backup, which would be another ID.
            JoinReply::new(
                made.reply.owner_identity.clone(),
                other.reply.commitment.clone(),
                made.reply.binding.clone(),
                made.reply.rules.clone(),
            ),
        ];
        for reply in swapped {
            assert!(reply.check(&made.agent_key, ADDRESS, NOW).is_err());
        }
    }

    #[test]
    fn a_host_keeps_only_what_is_for_it_and_names_nobody() {
        let owner_key = SigningKey::generate().unwrap();
        let made = signed_for(&owner_key, ADDRESS);
        assert!(
            made.reply
                .check_for_keeping(&made.agent_key, "host.example", NOW)
                .is_ok()
        );
        assert!(
            made.reply
                .check_for_keeping(&made.agent_key, "other.example", NOW)
                .is_err()
        );
        let owner = Identity::from_encoded(&made.reply.owner_identity).unwrap();
        let agent = made
            .agent_key
            .identity(RecoveryRule::committed_to(&made.reply.commitment).unwrap())
            .unwrap();
        let mut knows_someone = draft();
        knows_someone.contacts.push(RulesContact {
            agent: agent.id().clone(),
            address: "ben~host.example".to_owned(),
            label: "ben".to_owned(),
            status: ContactStatus::Allowed,
            types: Vec::new(),
            text: false,
            agree_types: false,
            pinned_by: PinnedBy::Owner,
        });
        let rules = knows_someone
            .sign(&owner_key, owner.id(), agent.id(), SEQ, NOW)
            .unwrap();
        let reply = JoinReply::new(
            made.reply.owner_identity.clone(),
            made.reply.commitment.clone(),
            made.reply.binding.clone(),
            rules,
        );
        assert!(reply.check(&made.agent_key, ADDRESS, NOW).is_ok());
        assert!(
            reply
                .check_for_keeping(&made.agent_key, "host.example", NOW)
                .is_err()
        );
    }

    #[test]
    fn junk_is_refused_before_anything_reads_it() {
        assert!(JoinReply::decode("").is_err());
        assert!(JoinReply::decode("not a reply").is_err());
        assert!(JoinReply::decode(&"a".repeat(MAX_ENCODED_CHARS + 1)).is_err());
        let unknown = jws::encode(
            br#"{"v":1,"owner_identity":"","commitment":"","binding":"","rules":"","extra":""}"#,
        );
        assert!(JoinReply::decode(&unknown).is_err());
        let later =
            jws::encode(br#"{"v":2,"owner_identity":"","commitment":"","binding":"","rules":""}"#);
        assert!(JoinReply::decode(&later).is_err());
    }

    /// An agent that joined on its own, with a stand-in for its owner on its machine, and the owner's
    /// device confirming it later. What the owner signs counts only once the stand-in has moved the
    /// agent's ID to the backup the owner holds, so an agent that keeps its own backup gets nothing.
    #[test]
    fn a_confirmation_counts_only_once_the_owner_holds_the_backup() {
        let stand_in_key = SigningKey::generate().unwrap();
        let stand_in = Identity::create(
            &stand_in_key,
            &crate::test_seal(),
            RecoveryRule::unconfirmed_owner(&stand_in_key.public_key()),
        )
        .unwrap();
        let agent_signing = SigningKey::generate().unwrap();
        let agent_seal = crate::test_seal();
        let kept_backup = SigningKey::generate().unwrap();
        let agent = Identity::create(
            &agent_signing,
            &agent_seal,
            RecoveryRule::backup_key(&kept_backup.public_key()),
        )
        .unwrap();
        let joined = VerifiedBinding::sign(
            &stand_in_key,
            &kept_backup,
            stand_in.id(),
            &agent,
            ADDRESS,
            SEQ,
            NOW,
        )
        .unwrap();
        let joined =
            VerifiedBinding::accept(&agent_signing, &joined, None, &stand_in, &agent).unwrap();

        let owner_key = SigningKey::generate().unwrap();
        let owner = crate::test_identity(&owner_key);
        let owners_backup = SigningKey::generate().unwrap();
        let RecoveryRule::BackupKey { commitment } =
            RecoveryRule::backup_key(&owners_backup.public_key())
        else {
            panic!("a backup key's rule names a commitment");
        };
        let confirmed_at = "ana.jeff~host.example";
        let binding = VerifiedBinding::sign_ahead(
            &owner_key,
            &owners_backup,
            owner.id(),
            &agent,
            confirmed_at,
            SEQ + 1,
            NOW,
        )
        .unwrap();
        let rules = draft()
            .sign(&owner_key, owner.id(), agent.id(), SEQ + 1, NOW)
            .unwrap();
        let reply = JoinReply::new(owner.encoded(), commitment.clone(), binding.clone(), rules);
        assert!(
            reply
                .check_confirming_for_keeping(&agent, ADDRESS, NOW)
                .is_ok()
        );
        assert!(
            reply
                .check_confirming_for_keeping(&agent, "ana~elsewhere.example", NOW)
                .is_err()
        );

        // Kept by the agent, its own backup moves the ID nowhere the owner signed for.
        let kept = agent
            .recover(
                &kept_backup,
                agent.sole_key().unwrap(),
                &agent_seal,
                RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
                NOW,
            )
            .unwrap();
        assert!(reply.check_confirming(&kept, ADDRESS, NOW).is_err());
        assert!(reply.check_confirming(&agent, ADDRESS, NOW).is_err());

        let moved = agent
            .recover(
                &kept_backup,
                agent.sole_key().unwrap(),
                &agent_seal,
                RecoveryRule::committed_to(&commitment).unwrap(),
                NOW,
            )
            .unwrap();
        let (confirmed, address) = reply.check_confirming(&moved, ADDRESS, NOW).unwrap();
        assert_eq!(
            (confirmed.id(), address.as_str()),
            (owner.id(), confirmed_at)
        );
        assert!(
            reply
                .check_confirming(&moved, "ana~elsewhere.example", NOW)
                .is_err()
        );

        // The stand-in lets it go to that owner, and the agent's Signet takes it as any reader will.
        let release = crate::VerifiedRelease::sign(
            &stand_in_key,
            stand_in.id(),
            agent.id(),
            Some(owner.id()),
            SEQ,
            NOW,
        )
        .unwrap();
        let taken =
            VerifiedBinding::accept(&agent_signing, &binding, Some(&release), &owner, &moved)
                .unwrap();
        assert!(taken.may_replace(&stand_in, joined.seq()).is_ok());

        // A stand-in can't confirm anyone: that would be the agent vouching for itself.
        let by_stand_in = JoinReply::new(
            stand_in.encoded(),
            commitment,
            reply.binding.clone(),
            reply.rules.clone(),
        );
        assert!(by_stand_in.check_confirming(&moved, ADDRESS, NOW).is_err());
    }

    /// Bug: an approval counting for an agent, an owner or a host other than the one it was signed for.
    #[test]
    fn a_move_reply_counts_only_for_the_agent_owner_and_host_it_was_signed_for() {
        let holder = || {
            let (key, backup) = (
                SigningKey::generate().unwrap(),
                SigningKey::generate().unwrap(),
            );
            let identity = Identity::create(
                &key,
                &crate::test_seal(),
                RecoveryRule::backup_key(&backup.public_key()),
            )
            .unwrap();
            (key, backup, identity)
        };
        let (owner_key, _, owner) = holder();
        let (_, backup, agent) = holder();
        let (_, _, stranger) = holder();
        let binding =
            VerifiedBinding::sign(&owner_key, &backup, owner.id(), &agent, ADDRESS, SEQ, NOW)
                .unwrap();
        let reply = MoveReply::new(agent.encoded(), owner.encoded(), binding.clone());
        let keys = agent.agent_keys().unwrap();
        let read = MoveReply::decode(&reply.encode().unwrap()).unwrap();

        assert_eq!(read.check(&agent, owner.id()).unwrap(), ADDRESS);
        assert!(read.check_for_keeping(&keys, "host.example").is_ok());

        assert!(read.check(&stranger, owner.id()).is_err(), "another agent");
        assert!(read.check(&agent, stranger.id()).is_err(), "another owner");
        assert!(
            read.check_for_keeping(&keys, "other.example").is_err(),
            "another host"
        );
        let others = stranger.agent_keys().unwrap();
        assert!(
            read.check_for_keeping(&others, "host.example").is_err(),
            "another agent's keys"
        );
        let (signed, _) = binding.split_once(crate::BINDING_PART_SEPARATOR).unwrap();
        let unvouched = MoveReply::new(agent.encoded(), owner.encoded(), signed.to_owned());
        assert!(unvouched.check(&agent, owner.id()).is_err(), "no vouch");
    }
}

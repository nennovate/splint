//! A person's words, carried on a step. See "A person's words" in `docs/protocol.md`.
//!
//! The label "from a person" is only ever the owner's signature, so an agent can't claim it, whatever
//! it writes. A reader always gets these words marked untrusted: they unlock nothing, move nothing and
//! widen nothing an agent can send, because a person can be fooled too and an owner's key can be stolen.

use serde::{Deserialize, Serialize};

use super::Refused;
use super::schema::has_hidden_characters;
use crate::{Identity, MessageId, SigningKey, SplintId, jws};

const PERSON_TEXT_TYPE: &str = "splint-person-text";
const PERSON_TEXT_VERSION: u8 = 1;
const MAX_PERSON_TEXT_CHARS: usize = 280;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonTextPayload {
    v: u8,
    owner: SplintId,
    agent: SplintId,
    to: SplintId,
    /// Null when it's for an `open`, which has no ID yet.
    request: Option<MessageId>,
    text: String,
    issued_at: u64,
}

/// A person's words whose signature under one owner's key has been checked. The only way to get one
/// is to pass that check, so nothing an agent writes can stand in for it.
#[derive(Clone, Debug)]
pub struct VerifiedPersonText {
    compact: String,
    /// The hash of its payload, never its signature, so a respelled signature is the same words.
    id: MessageId,
    payload: PersonTextPayload,
}

impl VerifiedPersonText {
    /// Words arriving now, so they have to be signed by the key this owner holds now.
    /// Nobody has confirmed an unconfirmed owner, so no person's words come from one.
    pub fn verify(compact: &str, owner: &Identity) -> Result<Self, Refused> {
        if owner.is_unconfirmed_owner() {
            return Err(Refused::OwnerUnconfirmed);
        }
        let bytes = owner
            .verify(compact, PERSON_TEXT_TYPE)
            .map_err(|_| Refused::BadPersonText)?;
        Self::checked(compact, &bytes, owner)
    }

    /// Words in a chain, which may date from before this owner's recovery.
    pub(super) fn verify_history(compact: &str, owner: &Identity) -> Result<Self, Refused> {
        if owner.is_unconfirmed_owner() {
            return Err(Refused::OwnerUnconfirmed);
        }
        let bytes = owner
            .verify_under_any_key(compact, PERSON_TEXT_TYPE)
            .map_err(|_| Refused::BadPersonText)?;
        Self::checked(compact, &bytes, owner)
    }

    fn checked(compact: &str, bytes: &[u8], owner: &Identity) -> Result<Self, Refused> {
        let payload: PersonTextPayload =
            serde_json::from_slice(bytes).map_err(|_| Refused::BadPersonText)?;
        if payload.v != PERSON_TEXT_VERSION
            || payload.owner != *owner.id()
            || !text_fits(&payload.text)
        {
            return Err(Refused::BadPersonText);
        }
        Ok(Self {
            compact: compact.to_owned(),
            id: MessageId::of(bytes),
            payload,
        })
    }

    /// What an owner's device signs. It refuses here what a reader would refuse later.
    pub fn sign(
        key: &SigningKey,
        owner: &SplintId,
        for_step: PersonTextFor<'_>,
        text: &str,
        now: u64,
    ) -> Result<String, Refused> {
        if !text_fits(text) {
            return Err(Refused::BadPersonText);
        }
        let payload = serde_json::to_vec(&PersonTextPayload {
            v: PERSON_TEXT_VERSION,
            owner: owner.clone(),
            agent: for_step.agent.clone(),
            to: for_step.to.clone(),
            request: for_step.request.cloned(),
            text: text.to_owned(),
            issued_at: now,
        })
        .map_err(|_| Refused::BadPersonText)?;
        jws::sign(key, PERSON_TEXT_TYPE, &payload).map_err(|_| Refused::BadPersonText)
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn id(&self) -> &MessageId {
        &self.id
    }

    pub fn agent(&self) -> &SplintId {
        &self.payload.agent
    }

    pub fn to(&self) -> &SplintId {
        &self.payload.to
    }

    pub fn request(&self) -> Option<&MessageId> {
        self.payload.request.as_ref()
    }

    pub fn text(&self) -> &str {
        &self.payload.text
    }

    pub fn issued_at(&self) -> u64 {
        self.payload.issued_at
    }
}

/// Which agent carries these words, to whom, and on which request.
#[derive(Clone, Copy, Debug)]
pub struct PersonTextFor<'a> {
    pub agent: &'a SplintId,
    pub to: &'a SplintId,
    pub request: Option<&'a MessageId>,
}

fn text_fits(text: &str) -> bool {
    !text.is_empty()
        && text.chars().count() <= MAX_PERSON_TEXT_CHARS
        && !has_hidden_characters(text)
}

//! What an agent's Signet leaves at its host for its owner's device. See "Owner calls" in
//! `docs/protocol.md`.
//!
//! It's sealed to the owner's sealing key, which their ID names, so anyone can seal something to it:
//! sealing says who may read, not who wrote. So the agent's key signs it inside the seal, naming the
//! agent, the owner and when, and a device shows nothing from a view that doesn't verify under the
//! agent's ID. A host carrying it can withhold it or give an older one, and can't write one.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CLOCK_TOLERANCE_SECS, Error, Identity, SigningKey, SplintId, jws};

const VIEW_TYPE: &str = "splint-owner-view";
const VERSION: u8 = 1;
/// The most a signed view can be and still verify, as any signed object. A host takes more than this
/// once it's sealed, so a Signet fitting a view to its host has to keep it within this too.
pub const MAX_SIGNED_VIEW_BYTES: usize = jws::MAX_COMPACT_LEN;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewPayload {
    v: u8,
    agent: SplintId,
    owner: SplintId,
    issued_at: u64,
    view: Value,
}

#[derive(Serialize)]
struct Named<'a> {
    v: u8,
    agent: &'a SplintId,
    owner: &'a SplintId,
    issued_at: u64,
}

/// A view, signed by the agent's key, ready to seal: `{"v":1,"agent","owner","issued_at","view"}`, with
/// `view` the JSON object given, as given.
pub fn sign_owner_view(
    key: &SigningKey,
    agent: &SplintId,
    owner: &SplintId,
    view: &[u8],
    now: u64,
) -> Result<String, Error> {
    let named = serde_json::to_vec(&Named {
        v: VERSION,
        agent,
        owner,
        issued_at: now,
    })
    .map_err(|_| Error::Malformed)?;
    // The fields above, then the view as it was written, so a big view isn't parsed again to sign it.
    let mut payload = named.strip_suffix(b"}").ok_or(Error::Malformed)?.to_vec();
    payload.extend_from_slice(b",\"view\":");
    payload.extend_from_slice(view);
    payload.push(b'}');
    jws::sign(key, VIEW_TYPE, &payload)
}

/// A view whose agent's signature checked, for this owner, not dated ahead.
pub struct VerifiedOwnerView {
    issued_at: u64,
    view: Value,
}

impl VerifiedOwnerView {
    /// Signed by `agent`'s key as it is now, naming it and `owner`.
    pub fn verify(
        compact: &str,
        agent: &Identity,
        owner: &SplintId,
        now: u64,
    ) -> Result<Self, Error> {
        if !agent.may_act_as_agent() || agent.is_guest() {
            return Err(Error::WrongSigner);
        }
        let bytes = agent.verify(compact, VIEW_TYPE)?;
        let payload: ViewPayload = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        // Its fields in their one order, ahead of the view, which is as its Signet wrote it.
        let head = serde_json::to_vec(&Named {
            v: payload.v,
            agent: &payload.agent,
            owner: &payload.owner,
            issued_at: payload.issued_at,
        })
        .map_err(|_| Error::Malformed)?;
        let head = head.strip_suffix(b"}").ok_or(Error::Malformed)?;
        let in_order = bytes
            .strip_prefix(head)
            .is_some_and(|rest| rest.starts_with(b",\"view\":"));
        if payload.v != VERSION || !payload.view.is_object() || !in_order {
            return Err(Error::Malformed);
        }
        if &payload.agent != agent.id() || &payload.owner != owner {
            return Err(Error::WrongSigner);
        }
        if payload.issued_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        Ok(Self {
            issued_at: payload.issued_at,
            view: payload.view,
        })
    }

    /// When the agent's Signet signed it, by its clock.
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn into_view(self) -> Value {
        self.view
    }
}

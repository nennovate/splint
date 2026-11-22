//! Checks a request to register an agent on a host. See `docs/protocol.md`.
//!
//! The proof covers the whole body, and the handle comes from the address the owner signed in the
//! binding, so a captured request can only repeat the registration its owner wanted.
//!
//! A signup code never travels. The body carries a MAC over the binding, keyed with the code, so
//! someone reading traffic learns nothing they can use with an owner, agent or handle of their own.
//!
//! A host can also take new agents with no code, if whoever runs it opts in. Both fields are then
//! empty, and the binding is all that's asked. Anyone can make an owner key, so that proves only that
//! someone holding one signed: the host's limits on open signups are what stop a flood.

use aws_lc_rs::hmac;

use crate::host_api::Registration;
use crate::{AccessProof, Error, Identity, VerifiedBinding, jws, parse_address};

pub const REGISTER_PATH: &str = "/v0/agents";

/// A captured MAC lets someone test guesses at the code offline, so a guessable one isn't safe. 32
/// characters is what `openssl rand -hex 16` writes.
pub const MIN_SIGNUP_CODE_CHARS: usize = 32;

const SIGNUP_ID_CONTEXT: &[u8] = b"splint-signup-id-v1";
const SIGNUP_MAC_CONTEXT: &[u8] = b"splint-signup-mac-v1\0";

fn keyed_with(code: &str) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, code.as_bytes())
}

/// How a host finds a code without it being sent. It reveals nothing about the code.
pub fn signup_id(code: &str) -> String {
    jws::encode(hmac::sign(&keyed_with(code), SIGNUP_ID_CONTEXT).as_ref())
}

fn signed_binding(binding: &str) -> Vec<u8> {
    [SIGNUP_MAC_CONTEXT, binding.as_bytes()].concat()
}

impl Registration {
    pub fn new(
        owner_identity: String,
        agent_identity: String,
        binding: String,
        signup_code: &str,
    ) -> Self {
        if signup_code.is_empty() {
            return Self {
                owner_identity,
                agent_identity,
                binding,
                signup_id: String::new(),
                signup_mac: String::new(),
            };
        }
        let mac = hmac::sign(&keyed_with(signup_code), &signed_binding(&binding));
        Self {
            owner_identity,
            agent_identity,
            binding,
            signup_id: signup_id(signup_code),
            signup_mac: jws::encode(mac.as_ref()),
        }
    }
}

/// A registration whose proof, owner and binding all check out for this host. The only way to get
/// one is to pass those checks, so a host can't store an unchecked agent by accident.
pub struct VerifiedRegistration {
    agent: Identity,
    owner: Identity,
    binding: VerifiedBinding,
    signup_id: String,
    signup_mac: String,
}

impl VerifiedRegistration {
    pub fn verify(proof: &str, body: &[u8], host: &str, now: u64) -> Result<Self, Error> {
        let registration: Registration =
            serde_json::from_slice(body).map_err(|_| Error::Malformed)?;
        let agent = Identity::from_encoded(&registration.agent_identity)?;
        let owner = Identity::from_encoded(&registration.owner_identity)?;
        AccessProof::verify(proof, &agent, host, "POST", REGISTER_PATH, body, now)?;
        let binding = VerifiedBinding::verify(&registration.binding, &owner, &agent)?;
        let (_, domain) = parse_address(binding.address())?;
        if domain != host {
            return Err(Error::ProofMismatch);
        }
        Ok(Self {
            agent,
            owner,
            binding,
            signup_id: registration.signup_id,
            signup_mac: registration.signup_mac,
        })
    }

    pub fn agent(&self) -> &Identity {
        &self.agent
    }

    pub fn owner(&self) -> &Identity {
        &self.owner
    }

    pub fn binding(&self) -> &VerifiedBinding {
        &self.binding
    }

    /// What's before the `~` in the address the owner signed: the agent's handle, and its owner's if
    /// the address has one.
    pub fn name(&self) -> &str {
        self.binding
            .address()
            .split_once(crate::ADDRESS_SEPARATOR)
            .map_or("", |(name, _)| name)
    }

    pub fn signup_id(&self) -> &str {
        &self.signup_id
    }

    /// Whether this came with no code at all, which only a host open to signups takes.
    pub fn has_no_code(&self) -> bool {
        self.signup_id.is_empty()
    }

    /// Whether whoever holds this code made this binding's MAC. It ties the code to the owner, the
    /// agent and the handle at once, since the binding names all three.
    pub fn paid_with(&self, code: &str) -> bool {
        jws::decode(&self.signup_mac).is_ok_and(|mac| {
            hmac::verify(
                &keyed_with(code),
                &signed_binding(self.binding.compact()),
                &mac,
            )
            .is_ok()
        })
    }
}

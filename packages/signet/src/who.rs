//! Who this agent is right now: its identity, who it acts for, and the statement that says so. These
//! change by a recovery or a transfer, and all three change together, so they're read and replaced
//! as one and saved before they count.

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, PoisonError};

use splint_core::{Identity, RecoveryRule, SealingKey, SigningKey, VerifiedBinding, same_host};

use crate::Signet;
use crate::host_client::HostError;
use crate::state_file;

const SAVED_IDENTITY: &str = "identity";
const SAVED_OWNER: &str = "owner";
const SAVED_BINDING: &str = "binding";

#[derive(Clone)]
pub struct Who {
    pub identity: Identity,
    pub owner: Identity,
    /// Empty until the owner has signed one.
    pub binding: String,
}

impl Who {
    /// The identity saved here, if this agent has one yet, as `load` would take it. Read apart from the
    /// rest, as which keys a start may use depends on it, and they come first.
    pub fn saved_identity(path: &Path) -> Result<Option<Identity>, Box<dyn Error>> {
        let mut saved = state_file::load::<String>(path)?;
        let (Some(identity), Some(_)) = (saved.remove(SAVED_IDENTITY), saved.remove(SAVED_OWNER))
        else {
            return Ok(None);
        };
        Ok(Some(Identity::from_encoded(&identity)?))
    }

    /// The setup settings count once, on the first start. After that this Signet goes by what it was
    /// told since, so restarting it with the same settings can't undo a recovery or a transfer.
    ///
    /// An ID commits to its backup when it's made, so its commitment has to be here from the start.
    /// The owner's device holds that key, and this Signet never sees it. To replace a lost Signet,
    /// `SPLINT_RECOVERING` names the ID to take up in place of making a new one.
    pub fn load(
        path: &Path,
        key: &SigningKey,
        seal_key: &SealingKey,
    ) -> Result<Self, Box<dyn Error>> {
        let mut saved = state_file::load::<String>(path)?;
        if let (Some(identity), Some(owner)) =
            (saved.remove(SAVED_IDENTITY), saved.remove(SAVED_OWNER))
        {
            return Ok(Self {
                identity: Identity::from_encoded(&identity)?,
                owner: Identity::from_encoded(&owner)?,
                binding: saved.remove(SAVED_BINDING).unwrap_or_default(),
            });
        }
        let identity = match env::var(crate::own_keys::RECOVERING_SETTING) {
            Ok(identity) => Identity::from_encoded(&identity)?,
            Err(_) => {
                let commitment = env::var("SPLINT_RECOVERY_COMMITMENT")?;
                Identity::create(
                    key,
                    &seal_key.public_key(),
                    RecoveryRule::committed_to(&commitment)?,
                )?
            }
        };
        let who = Self {
            identity,
            owner: Identity::from_encoded(&env::var("SPLINT_OWNER_IDENTITY")?)?,
            binding: String::new(),
        };
        who.save(path)?;
        Ok(who)
    }

    fn save(&self, path: &Path) -> Result<(), state_file::StateError> {
        let values = HashMap::from([
            (SAVED_IDENTITY, self.identity.encoded()),
            (SAVED_OWNER, self.owner.encoded()),
            (SAVED_BINDING, self.binding.clone()),
        ]);
        state_file::save(path, &values)
    }

    /// How far this owner's say over this agent has gone, which a later statement has to pass.
    pub fn binding_seq(&self) -> u64 {
        VerifiedBinding::verify_history(&self.binding, &self.owner, &self.identity)
            .map_or(0, |binding| binding.seq())
    }
}

/// The address a binding names, when it's at the host this Signet was started at, as a new owner's
/// binding is, naming the agent under their own name. Otherwise the one it was started at.
pub fn address_now(who: &Who, started_at: &str) -> String {
    VerifiedBinding::verify(&who.binding, &who.owner, &who.identity)
        .ok()
        .map(|binding| binding.address().to_owned())
        .filter(|bound| same_host(bound, started_at))
        .unwrap_or_else(|| started_at.to_owned())
}

impl Signet {
    /// A lock is never held across anything that can fail, so a poisoned one still holds a whole value.
    pub fn who(&self) -> Arc<Who> {
        self.who
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn replace_who(&self, who: Who) -> Result<(), HostError> {
        who.save(&self.who_path)
            .map_err(|_| HostError::LocalStorage)?;
        // The next start does this too, so a file that can't be moved now costs nothing.
        if let Some(state) = self.who_path.parent()
            && crate::own_keys::settle_recovered_keys(state, &who.identity).is_err()
        {
            tracing::warn!(
                "couldn't move this agent's new keys into place, so its next start will"
            );
        }
        *self.address.write().unwrap_or_else(PoisonError::into_inner) =
            address_now(&who, &self.started_at);
        *self.who.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(who);
        Ok(())
    }

    /// This agent's address now, which its binding names.
    pub fn address(&self) -> String {
        self.address
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether this Signet's key isn't the one its ID says counts now. It's waiting for a recovery
    /// naming it, and nothing it signs would verify, so it signs nothing.
    pub fn recovering(&self) -> bool {
        self.who().identity.sole_key().ok() != Some(&self.key.public_key())
    }
}

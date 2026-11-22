//! This agent's two keys in their files, and who may make new ones.
//!
//! What contacts sealed to this agent opens only with the sealing key its ID names, and a host clears
//! what its Signet reads, so a Signet that quietly made a new key after a partial restore or a clean-up
//! would turn everything waiting for it into mail nobody can open, with its senders told it arrived. So
//! keys are made only before this agent has an ID, or while a recovery is taking its ID up with new
//! ones, and no start ever removes one. From then on a key file that's gone or isn't this agent's stops
//! Signet, and what waits at its host stays there, unread, until the real file is back.
//!
//! A recovery's keys wait in files of their own until the ID names them, and take the old files' places
//! then. A recovery that's cut off before that, or a real key that turns up again, finds them as they were.

use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use splint_core::{Error as CoreError, Identity, SealingKey, SigningKey};

use crate::who::Who;

const KEY_FILE: &str = "agent.key";
const SEAL_KEY_FILE: &str = "agent.seal";
const NEW_KEY_FILE: &str = "agent.key.new";
const NEW_SEAL_KEY_FILE: &str = "agent.seal.new";
pub const WHO_FILE: &str = "who.json";
/// Set by what brings an agent back with new keys, naming the ID it takes up.
pub const RECOVERING_SETTING: &str = "SPLINT_RECOVERING";
/// Set once this agent has joined, so a folder that lost what says who it is can't start as someone new.
const JOINED_SETTING: &str = "SPLINT_JOINED";

/// What's left for a key that's gone for good, which depends on where the owner's sign-in is.
const IF_LOST_FOR_GOOD: &str = "If it's lost for good and the owner's sign-in is on this computer, \
     splint recover HANDLE~HOST puts this agent on new keys. With their sign-in on another computer \
     that can't be done from there: they can run splint for HANDLE~HOST retire there, and have a new \
     agent join";

#[derive(thiserror::Error)]
pub enum KeysRefused {
    #[error(
        "{file} is missing from {dir}, so this Signet won't start: a new key couldn't open what's \
         sealed to this agent. Nothing waiting at its host was touched. Put the real file back and \
         start it again. {IF_LOST_FOR_GOOD}"
    )]
    Missing { file: &'static str, dir: PathBuf },
    #[error(
        "agent.seal in {dir} is missing or can't be used and agent.key beside it is still this \
         agent's, so this Signet won't start, and a recovery makes no key while one of the pair is \
         good. Nothing waiting at its host was touched. Put the real file back and start it again. \
         If it's lost for good, move agent.key out of that folder too and run splint recover \
         HANDLE~HOST again"
    )]
    SealLostBesideItsKey { dir: PathBuf },
    #[error(
        "{file} in {dir} can't be opened, or other users can read it, so this Signet won't start. \
         The key itself may be fine, and nothing waiting at its host was touched. Make the file \
         readable only by this user, and start it again"
    )]
    Unreadable { file: &'static str, dir: PathBuf },
    #[error(
        "{file} in {dir} can't be read as this agent's key, so this Signet won't start. Nothing \
         waiting at its host was touched. Put the real file back and start it again. \
         {IF_LOST_FOR_GOOD}"
    )]
    Damaged { file: &'static str, dir: PathBuf },
    #[error(
        "{file} in {dir} isn't the key this agent's ID names, so this Signet won't start. Nothing \
         waiting at its host was touched. Put the real file back and start it again. \
         {IF_LOST_FOR_GOOD}"
    )]
    NotThisAgents { file: &'static str, dir: PathBuf },
    #[error(
        "who.json is missing from {dir}, though this agent has joined, so this Signet won't start: \
         it says which ID these keys are for. Nothing waiting at its host was touched. Put the real \
         file back and start it again"
    )]
    WhoMissing { dir: PathBuf },
    #[error(
        "who.json in {dir} can't be read, so this Signet won't start: it says which ID these keys \
         are for. Nothing waiting at its host was touched. Put the real file back and start it again"
    )]
    WhoUnreadable { dir: PathBuf },
}

impl KeysRefused {
    /// Whether a key is gone or can't be used, which only new keys put right. A file nobody can open
    /// or others can read is still the key, and a folder that lost its who.json still holds its keys.
    pub fn lost_for_good(&self) -> bool {
        matches!(
            self,
            Self::Missing { .. } | Self::Damaged { .. } | Self::NotThisAgents { .. }
        )
    }

    fn is_about_the_seal(&self) -> bool {
        matches!(
            self,
            Self::Missing { file, .. } | Self::Damaged { file, .. } | Self::NotThisAgents { file, .. }
                if *file == SEAL_KEY_FILE
        )
    }
}

/// `main` prints what it returns with `Debug`, and the log should read as the reason.
impl fmt::Debug for KeysRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An agent's first keys, made together. One file without the other is what's left of an agent that
/// had both, and a new key beside it would part it from the ID it belongs to.
fn first_keys(state: &Path) -> Result<(SigningKey, SealingKey), Box<dyn Error>> {
    let (key_path, seal_path) = (state.join(KEY_FILE), state.join(SEAL_KEY_FILE));
    let dir = state.to_owned();
    match (key_path.exists(), seal_path.exists()) {
        (true, false) => Err(KeysRefused::Missing {
            file: SEAL_KEY_FILE,
            dir,
        }
        .into()),
        (false, true) => Err(KeysRefused::Missing {
            file: KEY_FILE,
            dir,
        }
        .into()),
        _ => Ok((
            SigningKey::load_or_create_for_agent(&key_path)?,
            SealingKey::load_or_create(&seal_path)?,
        )),
    }
}

/// Both keys as they are, with nothing made or removed.
fn load_held(state: &Path) -> Result<(SigningKey, SealingKey), KeysRefused> {
    let dir = || state.to_owned();
    for file in [KEY_FILE, SEAL_KEY_FILE] {
        if !state.join(file).exists() {
            return Err(KeysRefused::Missing { file, dir: dir() });
        }
    }
    let key = SigningKey::load_for_agent(&state.join(KEY_FILE))
        .map_err(|error| wont_load(KEY_FILE, dir(), &error))?;
    let seal = SealingKey::load(&state.join(SEAL_KEY_FILE))
        .map_err(|error| wont_load(SEAL_KEY_FILE, dir(), &error))?;
    Ok((key, seal))
}

/// A file that couldn't be opened, or that others can read, is told apart from one that was opened and
/// holds no key, as only the second is past putting right.
fn wont_load(file: &'static str, dir: PathBuf, error: &CoreError) -> KeysRefused {
    match error {
        CoreError::KeyStorage => KeysRefused::Unreadable { file, dir },
        _ => KeysRefused::Damaged { file, dir },
    }
}

/// The keys held here, if they're the ones this ID names.
fn load_named(state: &Path, id: &Identity) -> Result<(SigningKey, SealingKey), KeysRefused> {
    let (key, seal) = load_held(state)?;
    let dir = || state.to_owned();
    if id.sole_key().ok() != Some(&key.public_key()) {
        return Err(KeysRefused::NotThisAgents {
            file: KEY_FILE,
            dir: dir(),
        });
    }
    if id
        .seal_key()
        .is_some_and(|named| *named != seal.public_key())
    {
        return Err(KeysRefused::NotThisAgents {
            file: SEAL_KEY_FILE,
            dir: dir(),
        });
    }
    Ok((key, seal))
}

/// The ID saved here, if this folder holds one yet. A file that says nothing usable is a damaged file,
/// as Signet only ever writes it whole, so it's never read as an agent that has no ID yet.
fn saved_identity(state: &Path) -> Result<Option<Identity>, KeysRefused> {
    let path = state.join(WHO_FILE);
    if !path.exists() {
        return Ok(None);
    }
    match Who::saved_identity(&path) {
        Ok(Some(identity)) => Ok(Some(identity)),
        _ => Err(KeysRefused::WhoUnreadable {
            dir: state.to_owned(),
        }),
    }
}

/// What this agent's keys come to, for whoever is about to replace them, with nothing made, moved or
/// removed. A signing key that's still good is never replaced, so a sealing key lost beside it says so.
/// A folder that lost who.json is judged against the ID a recovery names, which is what it would start on.
pub fn look_at(state: &Path) -> Result<(), KeysRefused> {
    let dir = || state.to_owned();
    let Some(saved) = saved_identity(state)?.or_else(recovery_named) else {
        return Err(KeysRefused::WhoMissing { dir: dir() });
    };
    let Err(refused) = load_named(state, &saved) else {
        return Ok(());
    };
    let signing_key_is_good = SigningKey::load_for_agent(&state.join(KEY_FILE))
        .is_ok_and(|key| saved.sole_key().ok() == Some(&key.public_key()));
    if signing_key_is_good && refused.is_about_the_seal() {
        return Err(KeysRefused::SealLostBesideItsKey { dir: dir() });
    }
    Err(refused)
}

/// Once the ID names what a recovery made, those are this agent's keys, and they take the old files'
/// places. Each moves by itself, so whatever is cut off between the two is finished at the next start.
pub fn settle_recovered_keys(state: &Path, saved: &Identity) -> std::io::Result<()> {
    let (new_key, new_seal) = (state.join(NEW_KEY_FILE), state.join(NEW_SEAL_KEY_FILE));
    let key_named = SigningKey::load_for_agent(&new_key)
        .is_ok_and(|key| saved.sole_key().ok() == Some(&key.public_key()));
    if key_named {
        fs::rename(new_key, state.join(KEY_FILE))?;
    }
    let seal_named =
        SealingKey::load(&new_seal).is_ok_and(|seal| saved.seal_key() == Some(&seal.public_key()));
    if seal_named {
        fs::rename(new_seal, state.join(SEAL_KEY_FILE))?;
    }
    Ok(())
}

/// The ID a recovery says this start takes up, if it says one.
fn recovery_named() -> Option<Identity> {
    env::var(RECOVERING_SETTING)
        .ok()
        .and_then(|named| Identity::from_encoded(&named).ok())
}

/// Whether a recovery naming `named` is still taking up `saved`. Once it has named this Signet's keys
/// the ID has gone past the copy the setting names, so a setting left behind by a run that was cut off
/// makes no key in place of those.
fn still_taking_up(named: &Identity, saved: &Identity) -> bool {
    named.id() == saved.id() && saved.recoveries() <= named.recoveries()
}

/// What a recovery taking up `id` starts on: a signing key that's still this ID's stays, with the
/// sealing key it belongs with. A key file that's there and won't open may well be that key, so it stops
/// this start until it's put right. With no such key this Signet waits on new keys of its own, signing
/// and reading nothing until the ID names them, and whatever else is in this folder stays as it is.
fn for_taking_up(state: &Path, id: &Identity) -> Result<(SigningKey, SealingKey), Box<dyn Error>> {
    let key_path = state.join(KEY_FILE);
    let held = SigningKey::load_for_agent(&key_path);
    if key_path.exists() && matches!(held, Err(CoreError::KeyStorage)) {
        return Err(KeysRefused::Unreadable {
            file: KEY_FILE,
            dir: state.to_owned(),
        }
        .into());
    }
    let still_this_agents = held.is_ok_and(|key| id.sole_key().ok() == Some(&key.public_key()));
    if still_this_agents {
        if !state.join(SEAL_KEY_FILE).exists() {
            return Err(KeysRefused::SealLostBesideItsKey {
                dir: state.to_owned(),
            }
            .into());
        }
        return Ok(load_named(state, id)?);
    }
    Ok((
        SigningKey::load_or_create_for_agent(&state.join(NEW_KEY_FILE))?,
        SealingKey::load_or_create(&state.join(NEW_SEAL_KEY_FILE))?,
    ))
}

/// What `signet prepare` works from: keys made if this agent has no ID yet, and otherwise those it has.
pub fn for_preparing(state: &Path) -> Result<(SigningKey, SealingKey), Box<dyn Error>> {
    let Some(saved) = saved_identity(state)? else {
        return first_keys(state);
    };
    settle_recovered_keys(state, &saved)?;
    Ok(load_held(state)?)
}

/// What a start works from. An agent with an ID starts only on the keys that ID names.
pub fn for_starting(state: &Path) -> Result<(SigningKey, SealingKey), Box<dyn Error>> {
    let named = recovery_named();
    let Some(saved) = saved_identity(state)? else {
        if let Some(named) = named {
            return for_taking_up(state, &named);
        }
        if env::var_os(JOINED_SETTING).is_some() {
            return Err(KeysRefused::WhoMissing {
                dir: state.to_owned(),
            }
            .into());
        }
        return first_keys(state);
    };
    settle_recovered_keys(state, &saved)?;
    if named.is_some_and(|named| still_taking_up(&named, &saved)) {
        return for_taking_up(state, &saved);
    }
    Ok(load_named(state, &saved)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use splint_core::{Error as CoreError, RetirementReason, SplintId, VerifiedRetirement};

    /// The key Signet loads for its agent signs nothing an owner signs, however it comes to be loaded.
    /// Were it loaded as any other key, a caller that got Signet to sign an owner's object, or a thief
    /// adding the agent's public key to the owner's ID, which needs that key's own signature, would
    /// have the agent sign as its own owner.
    #[test]
    fn the_agents_key_as_signet_loads_it_signs_no_owner_object() {
        let state = std::env::temp_dir().join(format!("signet-keys-{}", std::process::id()));
        fs::create_dir_all(&state).unwrap();
        let made = first_keys(&state).unwrap().0;
        let held = load_held(&state).unwrap().0;
        let someone: SplintId =
            serde_json::from_str(&format!("\"splint1{}\"", "a".repeat(64))).unwrap();
        for key in [made, held] {
            let retired =
                VerifiedRetirement::sign(&key, &someone, &someone, RetirementReason::Finished, 1);
            assert_eq!(retired.err(), Some(CoreError::WrongSigner));
        }
        fs::remove_dir_all(&state).unwrap();
    }
}

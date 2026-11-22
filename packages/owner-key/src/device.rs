//! What an owner's device keeps: the owner key, the backup key until it's moved, and the public
//! identity they make.
//!
//! The owner key is a sign-in (`sign_in`): held by the computer's security chip where Splint can use
//! one, or a key file only this user can read, locked with a passphrase unless the person asked for a
//! plain one. The sealing key and backups are software keys in such files, so a breached device can
//! copy them, and reports have to say so.
//!
//! [`Device::init`], [`Device::init_later`] and [`Device::recover`] make a plain owner key, for a
//! device the person keeps apart from their agents: `splint authorize` refuses on a machine an agent
//! runs on, and `splint setup` there needs `--owner-key-here`, which warns each time. That key isn't
//! a sign-in: `splint` uses it with no passphrase, so it's never locked, or warned about as one.

use std::fs;
use std::path::{Path, PathBuf};

use splint_core::recovery_code::RecoveryCode;
use splint_core::rules::{RulesContact, RulesDraft};
use splint_core::{
    Error, Identity, PublicKey, RecoveryRule, SealingKey, SigningKey, SplintId, unix_now,
};

use crate::prompt::{self, Prompt};
use crate::sign_in::{self, Holding, make_private_dir};

const OWNER_KEY: &str = sign_in::KEY_FILE;
/// What an owner's Signets seal to, such as the view left at a host for this device.
const OWNER_SEAL_KEY: &str = "owner.seal";
const BACKUP_KEY: &str = "backup.key";
const IDENTITY: &str = "owner.identity";
const AGENT_BACKUPS: &str = "agent-backups";
const VOUCH: &str = "vouch";
const RULES_SEQ: &str = "rules-seq";
/// The public point of the backup a recovery code gives, kept so a list can be sealed to it while the
/// code itself is kept nowhere. Checked against the ID's commitment each time it's read.
const BACKUP_POINT: &str = "backup.point";
/// The owner's ID as it was before a recovery here, for the agents whose IDs were bound under it.
const IDENTITY_BEFORE: &str = "identity-before";
/// Which backup in `agent-backups` is an agent's, by its commitment, so a list can carry it.
const BACKUP_OF: &str = "backup";
/// What a prompt says when this device makes an owner ID, or takes one up.
const MAKING: &str = "make your Splint owner ID";
const TAKING_UP: &str = "take up your Splint owner ID on this computer";

/// A new backup key for an agent: the commitment to give its Signet, and where the key is.
#[derive(serde::Serialize)]
pub struct AgentBackup {
    pub commitment: String,
    pub file: PathBuf,
}

pub struct Device {
    pub key: SigningKey,
    pub seal_key: SealingKey,
    pub identity: Identity,
    dir: PathBuf,
    /// What the sign-in's prompt shows for everything this device signs while open.
    prompt: Prompt,
}

impl Device {
    /// Makes both keys and the identity that commits to them, then reads them back and proves the
    /// backup matches, because an untested backup isn't recovery. It refuses a directory that
    /// already holds a key: replacing one would lose this owner's identity.
    pub fn init(dir: &Path) -> Result<Self, Error> {
        make_private_dir(dir).map_err(|_| Error::KeyStorage)?;
        let key = SigningKey::create_new(&dir.join(OWNER_KEY))?;
        let seal_key = SealingKey::create_new(&dir.join(OWNER_SEAL_KEY))?;
        let backup = SigningKey::create_new(&dir.join(BACKUP_KEY))?;
        let identity = Identity::create(
            &key,
            &seal_key.public_key(),
            RecoveryRule::backup_key(&backup.public_key()),
        )?;
        Self::settle(dir, &identity, prompt::for_command(MAKING))
    }

    /// The same with no backup yet, so the person isn't asked to keep one before using anything. Nothing
    /// can recover the ID until [`Self::set_recovery`] sets one.
    pub fn init_later(dir: &Path) -> Result<Self, Error> {
        make_private_dir(dir).map_err(|_| Error::KeyStorage)?;
        let key = SigningKey::create_new(&dir.join(OWNER_KEY))?;
        let seal_key = SealingKey::create_new(&dir.join(OWNER_SEAL_KEY))?;
        let identity = Identity::create(
            &key,
            &seal_key.public_key(),
            RecoveryRule::later(&key.public_key()),
        )?;
        fs::write(dir.join(IDENTITY), identity.encoded()).map_err(|_| Error::KeyStorage)?;
        Self::open(dir, prompt::for_command(MAKING))
    }

    /// A new owner ID made around this computer's sign-in, held as `holding` says, with no recovery
    /// code yet, as the person sets one later from a reminder. Its event is the one an owner key file
    /// makes, version 4, as a chip's key signs ES256 too.
    pub fn init_signed_in(dir: &Path, holding: Holding) -> Result<Self, Error> {
        make_private_dir(dir).map_err(|_| Error::KeyStorage)?;
        if dir.join(IDENTITY).exists() {
            return Err(Error::KeyStorage);
        }
        let prompt = prompt::for_command(MAKING);
        let key = sign_in::create(dir, holding, &prompt)?;
        let seal_key = SealingKey::create_new(&dir.join(OWNER_SEAL_KEY))?;
        let identity = Identity::create(
            &key,
            &seal_key.public_key(),
            RecoveryRule::later(&key.public_key()),
        )?;
        fs::write(dir.join(IDENTITY), identity.encoded()).map_err(|_| Error::KeyStorage)?;
        Self::open(dir, prompt)
    }

    /// This owner's ID as it is now, kept here in place of the copy before, such as after another
    /// computer's sign-in was added. It has to be a newer copy of the same ID with this sign-in in it.
    pub fn keep_identity(self, newer: &Identity) -> Result<Self, Error> {
        if newer.id() != self.identity.id() || !newer.extends(&self.identity) {
            return Err(Error::ProofMismatch);
        }
        fs::write(self.dir.join(IDENTITY), newer.encoded()).map_err(|_| Error::KeyStorage)?;
        Self::open(&self.dir, self.prompt)
    }

    /// Takes up an owner ID on a computer whose sign-in an addition just added, with the reading key
    /// its copy opened to, so `dir` then holds all a device does.
    pub fn take_up(dir: &Path, identity: &Identity, reading: &SealingKey) -> Result<Self, Error> {
        if dir.join(IDENTITY).exists() || identity.seal_key() != Some(&reading.public_key()) {
            return Err(Error::KeyStorage);
        }
        reading.keep_new(&dir.join(OWNER_SEAL_KEY))?;
        fs::write(dir.join(IDENTITY), identity.encoded()).map_err(|_| Error::KeyStorage)?;
        Self::open(dir, prompt::for_command(TAKING_UP))
    }

    /// Makes the backup an ID made without one now commits to, and signs that, once. The backup is
    /// made only now, so it's never kept anywhere before the person keeps it.
    pub fn set_recovery(self) -> Result<Self, Error> {
        if !self.identity.recovery_is_later() {
            return Err(Error::Malformed);
        }
        let backup = SigningKey::create_new(&self.dir.join(BACKUP_KEY))?;
        let set = self.identity.set_recovery_rule(
            &self.key,
            &RecoveryRule::backup_key(&backup.public_key()),
            unix_now(),
        )?;
        Self::settle(&self.dir, &set, self.prompt)
    }

    /// The same, with the backup derived from a recovery code made here, which only the person keeps:
    /// nothing is written that the code alone doesn't give back. The code comes back once, to show them.
    pub fn set_recovery_code(self) -> Result<(Self, RecoveryCode), Error> {
        if !self.identity.recovery_is_later() {
            return Err(Error::Malformed);
        }
        let code = RecoveryCode::generate()?;
        let backup = code.backup_key()?;
        let set = self.identity.set_recovery_rule(
            &self.key,
            &RecoveryRule::backup_key(&backup.public_key()),
            unix_now(),
        )?;
        set.check_backup(&backup.public_key())?;
        fs::write(self.dir.join(BACKUP_POINT), backup.public_key().encoded())
            .map_err(|_| Error::KeyStorage)?;
        fs::write(self.dir.join(IDENTITY), set.encoded()).map_err(|_| Error::KeyStorage)?;
        Ok((Self::open(&self.dir, self.prompt)?, code))
    }

    /// A stand-in for an owner who hasn't confirmed yet, on the machine of an agent that joined on its
    /// own. Its ID can never be recovered, and readers can tell, so nothing it signs counts as an
    /// owner's, and whoever holds it can't take back what the owner confirms later. It has no
    /// backup to make or move.
    pub fn init_unconfirmed(dir: &Path) -> Result<Self, Error> {
        make_private_dir(dir).map_err(|_| Error::KeyStorage)?;
        let key = SigningKey::create_new(&dir.join(OWNER_KEY))?;
        let seal_key = SealingKey::create_new(&dir.join(OWNER_SEAL_KEY))?;
        let identity = Identity::create(
            &key,
            &seal_key.public_key(),
            RecoveryRule::unconfirmed_owner(&key.public_key()),
        )?;
        fs::write(dir.join(IDENTITY), identity.encoded()).map_err(|_| Error::KeyStorage)?;
        Self::open(dir, prompt::for_command(MAKING))
    }

    /// Takes up an owner's ID on a new device, after the old key was lost or stolen. It makes a new key
    /// and a new backup, and the old backup's signature says the ID has moved to them. The ID doesn't
    /// change, and neither does anything that names it.
    pub fn recover(
        dir: &Path,
        identity: &Identity,
        old_backup: &SigningKey,
    ) -> Result<Self, Error> {
        identity.check_backup(&old_backup.public_key())?;
        make_private_dir(dir).map_err(|_| Error::KeyStorage)?;
        let key = SigningKey::create_new(&dir.join(OWNER_KEY))?;
        let seal_key = SealingKey::create_new(&dir.join(OWNER_SEAL_KEY))?;
        let backup = SigningKey::create_new(&dir.join(BACKUP_KEY))?;
        let recovered = identity.recover(
            old_backup,
            &key.public_key(),
            &seal_key.public_key(),
            RecoveryRule::backup_key(&backup.public_key()),
            unix_now(),
        )?;
        Self::settle(dir, &recovered, prompt::for_command(MAKING))
    }

    /// Takes up an owner's ID on a new computer's sign-in, made here as `holding` says, with the backup
    /// their recovery code gave. It makes a reading key and a new recovery code, and the old backup's
    /// signature moves the ID to them; nothing is signed with the new sign-in yet, so it asks for
    /// nobody. The ID before is kept, as the agents' IDs were bound under it. The new code comes back
    /// once, to show the person.
    pub fn recover_signed_in(
        dir: &Path,
        holding: Holding,
        identity: &Identity,
        old_backup: &SigningKey,
    ) -> Result<(Self, RecoveryCode), Error> {
        identity.check_backup(&old_backup.public_key())?;
        make_private_dir(dir).map_err(|_| Error::KeyStorage)?;
        if dir.join(IDENTITY).exists() {
            return Err(Error::KeyStorage);
        }
        let prompt = prompt::for_command(TAKING_UP);
        let key = sign_in::create(dir, holding, &prompt)?;
        let seal_key = SealingKey::create_new(&dir.join(OWNER_SEAL_KEY))?;
        let code = RecoveryCode::generate()?;
        let backup = code.backup_key()?;
        let recovered = identity.recover(
            old_backup,
            &key.public_key(),
            &seal_key.public_key(),
            RecoveryRule::backup_key(&backup.public_key()),
            unix_now(),
        )?;
        recovered.check_backup(&backup.public_key())?;
        fs::write(dir.join(IDENTITY_BEFORE), identity.encoded()).map_err(|_| Error::KeyStorage)?;
        fs::write(dir.join(BACKUP_POINT), backup.public_key().encoded())
            .map_err(|_| Error::KeyStorage)?;
        fs::write(dir.join(IDENTITY), recovered.encoded()).map_err(|_| Error::KeyStorage)?;
        let device = Self {
            key,
            seal_key,
            identity: recovered,
            dir: dir.to_owned(),
            prompt,
        };
        Ok((device, code))
    }

    /// Writes the identity down, then reads it all back and proves the backup matches, because an
    /// untested backup isn't recovery.
    fn settle(dir: &Path, identity: &Identity, prompt: Prompt) -> Result<Self, Error> {
        fs::write(dir.join(IDENTITY), identity.encoded()).map_err(|_| Error::KeyStorage)?;
        let device = Self::open(dir, prompt)?;
        let backup = SigningKey::load(&dir.join(BACKUP_KEY))?;
        device.check_backup(&backup.public_key())?;
        Ok(device)
    }

    /// Makes a backup key for an agent, kept on this device and away from its Signet, which has to
    /// know only the commitment. A Signet holding both would lose both to one thief.
    pub fn new_agent_backup(&self) -> Result<AgentBackup, Error> {
        let folder = self.dir.join(AGENT_BACKUPS);
        make_private_dir(&folder).map_err(|_| Error::KeyStorage)?;
        let temporary = folder.join(format!("new-{}.key", std::process::id()));
        let backup = SigningKey::create_new(&temporary)?;
        let RecoveryRule::BackupKey { commitment } = RecoveryRule::backup_key(&backup.public_key())
        else {
            return Err(Error::KeyStorage);
        };
        let file = folder.join(format!("{commitment}.key"));
        fs::rename(&temporary, &file).map_err(|_| Error::KeyStorage)?;
        Ok(AgentBackup { commitment, file })
    }
}

/// Whether this device kept what an agent's backup signed, read before the sign-in asks for anyone.
pub fn has_vouch(dir: &Path, agent: &SplintId) -> bool {
    agent_file_in(dir, VOUCH, agent).is_file()
}

/// What an owner's agents sealed to them, opened by the reading key alone, with no sign-in, so a
/// computer whose sign-in asks for the person every time still opens what it reads: only the owner's
/// list of agents, and what an agent's Signet left them, by what each is sealed about.
pub fn open_note(dir: &Path, sealed: &str, about: &str) -> Result<Vec<u8>, Error> {
    let text = fs::read_to_string(dir.join(IDENTITY)).map_err(|_| Error::KeyStorage)?;
    let identity = Identity::from_encoded(text.trim())?;
    let owner = identity.id().as_str();
    let list = format!("splint owner agents for {owner}");
    let view = about
        .strip_prefix("splint owner view for ")
        .is_some_and(|agent| {
            serde_json::from_value::<SplintId>(serde_json::Value::String(agent.to_owned()))
                .is_ok_and(|id| id.is_well_formed())
        });
    if about != list && !view {
        return Err(Error::Malformed);
    }
    let seal_key = SealingKey::load(&dir.join(OWNER_SEAL_KEY))?;
    if identity.seal_key() != Some(&seal_key.public_key()) {
        return Err(Error::KeyStorage);
    }
    seal_key.open_note(sealed, about.as_bytes())
}

/// The point of the backup the owner's recovery code gives, kept in `dir` when the code was set, if
/// it's the one the ID there commits to. Read without opening the sign-in.
pub fn backup_point_in(dir: &Path) -> Option<PublicKey> {
    let identity = identity_in(dir).ok()?;
    let text = fs::read_to_string(dir.join(BACKUP_POINT)).ok()?;
    let point = PublicKey::from_encoded(text.trim()).ok()?;
    identity.check_backup(&point).ok().map(|()| point)
}

/// The backup noted here as this agent's, read without opening the sign-in.
pub fn agent_backup_in(dir: &Path, agent: &SplintId) -> Option<SigningKey> {
    let commitment = fs::read_to_string(agent_file_in(dir, BACKUP_OF, agent)).ok()?;
    let commitment = commitment.trim();
    let named = commitment.len() == 64 && commitment.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !named {
        return None;
    }
    SigningKey::load(&dir.join(AGENT_BACKUPS).join(format!("{commitment}.key"))).ok()
}

/// The backup kept here that this copy of an agent's ID commits to, whichever one the note names, as
/// the note moves on when a recovery is signed, before anyone has taken it.
pub fn agent_backup_committed_to(dir: &Path, identity: &Identity) -> Option<SigningKey> {
    if let Some(noted) = agent_backup_in(dir, identity.id())
        && identity.check_backup(&noted.public_key()).is_ok()
    {
        return Some(noted);
    }
    fs::read_dir(dir.join(AGENT_BACKUPS))
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "key"))
        .filter_map(|path| SigningKey::load(&path).ok())
        .find(|backup| identity.check_backup(&backup.public_key()).is_ok())
}

/// This device's owner ID, read without opening the sign-in, so what's about to be signed can be
/// checked and shown before the prompt is written.
pub fn identity_in(dir: &Path) -> Result<Identity, Error> {
    let text = fs::read_to_string(dir.join(IDENTITY)).map_err(|_| Error::KeyStorage)?;
    Identity::from_encoded(text.trim())
}

/// The rules last signed here for this agent, read without opening the sign-in, or `None` if there
/// aren't any: so this device knows which agents it set up before any prompt names one.
pub fn rules_in(dir: &Path, agent: &SplintId) -> Option<RulesDraft> {
    let text = fs::read(agent_file_in(dir, "rules", agent)).ok()?;
    serde_json::from_slice(&text).ok()
}

/// A file this device keeps about one agent. The ID in a draft comes from Signet, so it goes in a file
/// name only as hex and can't point anywhere else.
fn agent_file_in(dir: &Path, kind: &str, agent: &SplintId) -> PathBuf {
    let name: String = agent
        .as_str()
        .bytes()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    dir.join(format!("{kind}-{name}.json"))
}

/// What this device holds, from its public ID alone, so reading it opens no sign-in: no chip prompt,
/// and no passphrase for a locked key file. A sign-in's plain key file is said to be one each time
/// it's listed.
pub fn summary_unopened(dir: &Path) -> Result<String, Error> {
    let text = fs::read_to_string(dir.join(IDENTITY)).map_err(|_| Error::KeyStorage)?;
    let identity = Identity::from_encoded(text.trim())?;
    sign_in::warn_if_plain(dir);
    Ok(format!(
        "owner id: {}\nowner identity: {}\nsign-in: {}\nrecovery: {}",
        identity.id(),
        identity.encoded(),
        sign_in::described(dir),
        if identity.recovery_is_later() {
            "not set"
        } else {
            "set"
        },
    ))
}

impl Device {
    /// Holds the device's keys and ID, opened with the prompt written from exactly what's about to be
    /// signed. Only [`crate::prompt`] writes one, so nothing opens the sign-in without one.
    pub fn open(dir: &Path, prompt: Prompt) -> Result<Self, Error> {
        let key = sign_in::open(dir, &prompt)?;
        let seal_key = SealingKey::load(&dir.join(OWNER_SEAL_KEY))?;
        let text = fs::read_to_string(dir.join(IDENTITY)).map_err(|_| Error::KeyStorage)?;
        let identity = Identity::from_encoded(text.trim())?;
        if !identity
            .keys()
            .iter()
            .any(|counting| counting.point() == &key.public_key())
            || identity.seal_key() != Some(&seal_key.public_key())
        {
            return Err(Error::KeyStorage);
        }
        // Each time a sign-in's plain key file is opened to sign, it says what it is.
        sign_in::warn_if_plain(dir);
        Ok(Self {
            key,
            seal_key,
            identity,
            dir: dir.to_owned(),
            prompt,
        })
    }

    /// The point of the backup the owner's recovery code gives, where it was kept here when the code
    /// was set, and only if it's the one the ID commits to now.
    pub fn backup_point(&self) -> Option<PublicKey> {
        backup_point_in(&self.dir)
    }

    /// Notes which backup is this agent's, so a list can carry it, whatever its ID says by then.
    pub fn remember_backup_of(&self, agent: &SplintId, commitment: &str) -> Result<(), Error> {
        fs::write(self.agent_file(BACKUP_OF, agent), commitment).map_err(|_| Error::KeyStorage)
    }

    /// This agent's backup, if this device holds it: the one noted for it, or, for an agent set up
    /// before that was noted, the one in `agent-backups` its ID, as given, commits to.
    pub fn agent_backup_of(
        &self,
        agent: &SplintId,
        identity: Option<&Identity>,
    ) -> Option<SigningKey> {
        if let Some(noted) = agent_backup_in(&self.dir, agent) {
            return Some(noted);
        }
        agent_backup_committed_to(&self.dir, identity?)
    }

    /// An agent's backup taken from the owner's list, kept here as one made here is.
    pub fn keep_agent_backup(&self, agent: &SplintId, backup: &SigningKey) -> Result<(), Error> {
        let RecoveryRule::BackupKey { commitment } = RecoveryRule::backup_key(&backup.public_key())
        else {
            return Err(Error::KeyStorage);
        };
        let folder = self.dir.join(AGENT_BACKUPS);
        make_private_dir(&folder).map_err(|_| Error::KeyStorage)?;
        let file = folder.join(format!("{commitment}.key"));
        if !file.exists() {
            backup.save_new(&file)?;
        }
        self.remember_backup_of(agent, &commitment)
    }

    /// The touch code the prompt it opened with showed, for one over objects or asks.
    pub fn code(&self) -> Option<&str> {
        self.prompt.code()
    }

    pub fn check_backup(&self, backup: &PublicKey) -> Result<(), Error> {
        self.identity.check_backup(backup)
    }

    /// A file this device keeps about one agent.
    pub fn agent_file(&self, kind: &str, agent: &SplintId) -> PathBuf {
        agent_file_in(&self.dir, kind, agent)
    }

    /// What this agent's backup signed for this owner, so the backup can live somewhere else.
    pub fn remember_vouch(&self, agent: &SplintId, vouch: &str) -> Result<(), Error> {
        fs::write(self.agent_file(VOUCH, agent), vouch).map_err(|_| Error::KeyStorage)
    }

    pub fn vouch_for(&self, agent: &SplintId) -> Option<String> {
        fs::read_to_string(self.agent_file(VOUCH, agent)).ok()
    }

    /// Kept so an approval can name who it's with, and so the device knows the level it signed.
    fn rules_path(&self, agent: &SplintId) -> PathBuf {
        self.agent_file("rules", agent)
    }

    /// With the `seq` they were signed at, so rules signed since on another device show as newer.
    pub fn remember_rules(
        &self,
        agent: &SplintId,
        draft: &RulesDraft,
        seq: u64,
    ) -> Result<(), Error> {
        let text = serde_json::to_vec(draft).map_err(|_| Error::Malformed)?;
        fs::write(self.rules_path(agent), text).map_err(|_| Error::KeyStorage)?;
        fs::write(self.agent_file(RULES_SEQ, agent), seq.to_string()).map_err(|_| Error::KeyStorage)
    }

    /// The `seq` of the rules last signed here for this agent, or 0 for rules kept before it was, so
    /// any the owner signed elsewhere count as newer.
    pub fn rules_seq(&self, agent: &SplintId) -> u64 {
        fs::read_to_string(self.agent_file(RULES_SEQ, agent))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    }

    /// The contacts in the rules last signed here for this agent, or `None` if there aren't any.
    pub fn contacts_of(&self, agent: &SplintId) -> Option<Vec<RulesContact>> {
        Some(self.rules_of(agent)?.contacts)
    }

    /// The rules last signed here for this agent, or `None` if there aren't any.
    pub fn rules_of(&self, agent: &SplintId) -> Option<RulesDraft> {
        rules_in(&self.dir, agent)
    }

    pub fn summary(&self) -> String {
        format!(
            "owner id: {}\nowner identity: {}\nsign-in: {}\nsign-in key: {}\nrecovery: {}",
            self.identity.id(),
            self.identity.encoded(),
            sign_in::described(&self.dir),
            self.key_name(),
            if self.identity.recovery_is_later() {
                "not set"
            } else {
                "set"
            },
        )
    }

    /// This sign-in's name, the hex SHA-256 of its point, as an ID's key statements name it.
    pub fn key_name(&self) -> String {
        self.identity
            .keys()
            .iter()
            .find(|counting| counting.point() == &self.key.public_key())
            .map(splint_core::OwnerKey::name)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("owner-key-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_device_keeps_one_identity_and_wont_be_made_twice() {
        let dir = scratch("twice");
        let made = Device::init(&dir).unwrap();
        assert!(Device::init(&dir).is_err());
        assert_eq!(
            Device::open(&dir, prompt::for_command("test"))
                .unwrap()
                .identity
                .id(),
            made.identity.id()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_device_wont_use_keys_or_a_directory_others_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let open = scratch("open-dir");
        fs::create_dir_all(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Device::init(&open).is_err());
        assert_eq!(fs::read_dir(&open).unwrap().count(), 0);
        fs::remove_dir_all(&open).unwrap();

        let dir = scratch("open-key");
        Device::init(&dir).unwrap();
        assert!(Device::open(&dir, prompt::for_command("test")).is_ok());
        let key = dir.join(OWNER_KEY);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(Device::open(&dir, prompt::for_command("test")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_new_device_takes_up_the_same_id_and_the_old_key_is_out() {
        let old = scratch("recover-old");
        let device = Device::init(&old).unwrap();
        let backup = SigningKey::load(&old.join(BACKUP_KEY)).unwrap();
        let new = scratch("recover-new");
        let recovered = Device::recover(&new, &device.identity, &backup).unwrap();
        assert_eq!(recovered.identity.id(), device.identity.id());
        assert_ne!(
            recovered.identity.sole_key().unwrap(),
            device.identity.sole_key().unwrap()
        );
        assert_eq!(
            Device::open(&new, prompt::for_command("test"))
                .unwrap()
                .identity
                .id(),
            device.identity.id()
        );

        // A thief holding the old device's owner key holds nothing a recovery will take.
        let stolen = SigningKey::load(&old.join(OWNER_KEY)).unwrap();
        assert!(Device::recover(&scratch("recover-thief"), &device.identity, &stolen).is_err());
        assert!(Device::recover(&new, &device.identity, &backup).is_err());
        fs::remove_dir_all(&old).unwrap();
        fs::remove_dir_all(&new).unwrap();
    }

    /// Bug caught: a recovery code shown to a person that doesn't get their ID back, or one set twice.
    #[test]
    fn a_code_set_later_recovers_the_id_and_is_set_once() {
        let dir = scratch("code-later");
        let made = Device::init_signed_in(&dir, Holding::PlainFile).unwrap();
        let (device, code) = made.set_recovery_code().unwrap();
        assert!(!dir.join(BACKUP_KEY).exists());
        let typed = RecoveryCode::parse(&code.spelled()).unwrap();
        let new = scratch("code-later-new");
        let recovered =
            Device::recover(&new, &device.identity, &typed.backup_key().unwrap()).unwrap();
        assert_eq!(recovered.identity.id(), device.identity.id());
        assert!(
            Device::open(&dir, prompt::for_command("test"))
                .unwrap()
                .set_recovery_code()
                .is_err()
        );
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&new).unwrap();
    }

    #[test]
    fn a_backup_is_checked_against_what_the_identity_committed_to() {
        let dir = scratch("backup");
        let device = Device::init(&dir).unwrap();
        let real = SigningKey::load(&dir.join(BACKUP_KEY)).unwrap();
        assert!(device.check_backup(&real.public_key()).is_ok());
        let other = SigningKey::generate().unwrap();
        assert_eq!(
            device.check_backup(&other.public_key()),
            Err(Error::ProofMismatch)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_identity_file_that_doesnt_fit_the_key_is_refused() {
        let dir = scratch("swapped");
        Device::init(&dir).unwrap();
        let another = scratch("swapped-other");
        let other = Device::init(&another).unwrap();
        fs::write(dir.join(IDENTITY), other.identity.encoded()).unwrap();
        assert!(Device::open(&dir, prompt::for_command("test")).is_err());
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&another).unwrap();
    }
}

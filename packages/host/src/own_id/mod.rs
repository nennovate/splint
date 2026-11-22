//! This host's own ID and the key it counts now.
//!
//! Both live in files: the key where `SPLINT_HOST_KEY_FILE` says, the ID beside it with `.identity`
//! after the name. A copy of the ID is kept in Postgres too, so losing the file while the database
//! survives loses nothing. The host makes its ID at its first start with an ID, around the key it
//! already had, so hosts that pinned that key go on matching it.
//!
//! The ID changes only by the operator's `splint-host key` commands (see `commands`), which take a
//! lock on `.lock` and are the only things besides a start that rename a key file. The running host
//! reads the files again every couple of seconds and takes a newer ID, with no restart. A rotation
//! writes the new key whole to `.next` first, then the ID naming it, then renames `.next` over the
//! key, so a crash at any point leaves files a start puts right.

pub mod commands;

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use splint_core::{Identity, RecoveryRule, SealingKey, SigningKey, host_id, private_files};
use sqlx::PgPool;

use crate::Host;
use crate::log_limit::LogLimit;

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS own_host_id (
        one BOOLEAN PRIMARY KEY DEFAULT true CHECK (one),
        identity TEXT NOT NULL
    );
";

pub const KEY_FILE_SETTING: &str = "SPLINT_HOST_KEY_FILE";
/// Lets a host whose key file is gone make a new key, and so a new ID, over a database that's
/// already been used. Off unless it's yes, as every host that pinned the old one refuses the new.
pub const NEW_KEY_SETTING: &str = "SPLINT_NEW_HOST_KEY";
const REREAD_EVERY: Duration = Duration::from_secs(2);
/// Far more than an ID, which is at most 80 K characters.
const MAX_ID_FILE_BYTES: u64 = 256 * 1024;
static UNUSABLE_FILES: LogLimit = LogLimit::new();
static UNKEPT: LogLimit = LogLimit::new();

#[derive(thiserror::Error)]
pub enum OwnIdError {
    #[error("{KEY_FILE_SETTING} isn't set, and a host needs it")]
    NoKeyFileSetting,
    #[error("{0} can't be read or written ({1})")]
    File(String, ErrorKind),
    #[error("{0} isn't a host ID that can be read")]
    UnreadableId(String),
    #[error("{0} isn't a host key that can be read, or others can read it")]
    UnreadableKey(String),
    #[error(
        "{KEY_FILE_SETTING} names {0}, and there's no key there, though this host has an ID or its \
         database already holds agents or other hosts' keys. A new key isn't this host to any host \
         that pinned the old one: they'd refuse everything it sends. Put the key file back, from a \
         backup if it's lost, or run `sudo splint-hostctl key recover` with this host's recovery code. To \
         make a new key and ID anyway, start once with {NEW_KEY_SETTING}=yes, and then whoever runs \
         each of those hosts has to accept the new key"
    )]
    KeyGone(String),
    #[error(
        "the host key doesn't match this host's ID. If the key is lost, run `sudo splint-hostctl \
         key recover` with the recovery code; if the code is lost too, this is a new host, and \
         docs/run-a-host.md says how to start one"
    )]
    KeyDoesntMatch,
    #[error(
        "{0} and the copy in this host's database are two different IDs, so neither is taken. If \
         the file holds the ID other hosts know, delete the database's copy with `DELETE FROM \
         own_host_id`; if the database's copy is that ID, put its file back. docs/run-a-host.md \
         has the steps"
    )]
    OtherId(String),
    #[error("{0} is an older copy of this host's ID than the one it runs with, so it's not taken")]
    OlderId(String),
    #[error(
        "two copies of this host's ID part ways, and neither has a recovery since, so neither is taken"
    )]
    Forked,
    #[error("there's no host ID at {0} yet: start the host once, and it makes one")]
    NoIdYet(String),
    #[error("a recovery code is set already, and it can't be changed; each recovery sets the next")]
    CodeSetAlready,
    #[error(
        "this host's ID can't add another key before a recovery: run `sudo splint-hostctl key \
         recover` with the recovery code, which rotates the key too"
    )]
    NoRotationsLeft,
    #[error(
        "this host's ID has had all the recoveries an ID can, so the next key is a new host's: \
         docs/run-a-host.md says how to start one"
    )]
    NoRecoveriesLeft,
    #[error("that isn't this host's recovery code, or this copy of its ID has no code set")]
    WrongCode,
    #[error("that isn't a recovery code: it's 26 letters and digits, in groups or not")]
    NotACode,
    #[error("couldn't make or sign the host's ID ({0})")]
    Core(splint_core::Error),
    #[error("{0}")]
    Usage(&'static str),
}

/// A `main` that returns an error prints it this way, and the operator reading needs the sentence.
impl std::fmt::Debug for OwnIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl From<splint_core::Error> for OwnIdError {
    fn from(error: splint_core::Error) -> Self {
        Self::Core(error)
    }
}

/// The files a host's key and ID are kept in.
pub struct Files {
    key: PathBuf,
    identity: PathBuf,
    next: PathBuf,
    lock: PathBuf,
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

fn file_error(path: &Path) -> impl Fn(io::Error) -> OwnIdError + '_ {
    move |error| OwnIdError::File(path.display().to_string(), error.kind())
}

impl Files {
    pub fn beside(key: &Path) -> Self {
        Self {
            key: key.to_owned(),
            identity: with_suffix(key, ".identity"),
            next: with_suffix(key, ".next"),
            lock: with_suffix(key, ".lock"),
        }
    }

    pub fn from_env() -> Result<Self, OwnIdError> {
        let key = std::env::var_os(KEY_FILE_SETTING).ok_or(OwnIdError::NoKeyFileSetting)?;
        Ok(Self::beside(Path::new(&key)))
    }

    pub fn identity_path(&self) -> &Path {
        &self.identity
    }

    /// Moves the key and ID here out of the way of another host's, keeping them beside it in case
    /// that was the wrong one to replace them with. Only under the lock.
    fn set_aside(&self) -> Result<(), OwnIdError> {
        for path in [&self.key, &self.identity] {
            match fs::rename(path, with_suffix(path, ".replaced")) {
                Err(error) if error.kind() != ErrorKind::NotFound => {
                    return Err(file_error(path)(error));
                }
                _ => {}
            }
        }
        remove_if_there(&self.next)
    }

    fn open_lock(&self) -> Result<File, OwnIdError> {
        private_files::open(
            OpenOptions::new().read(true).write(true).create(true),
            &self.lock,
        )
        .map_err(file_error(&self.lock))
    }

    /// Waits for any key command, or a start, to finish. Held until the file is dropped.
    fn lock_waiting(&self) -> Result<File, OwnIdError> {
        let file = self.open_lock()?;
        file.lock().map_err(file_error(&self.lock))?;
        Ok(file)
    }

    /// The lock if nobody holds it, without waiting.
    fn lock_if_free(&self) -> Result<Option<File>, OwnIdError> {
        let file = self.open_lock()?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(file_error(&self.lock)(error)),
        }
    }

    fn read_identity(&self) -> Result<Option<Identity>, OwnIdError> {
        read_identity_at(&self.identity)
    }

    /// Written whole to a file beside it, then renamed over it, so a reader sees the old or the new.
    fn write_identity(&self, identity: &Identity) -> Result<(), OwnIdError> {
        let temporary = with_suffix(&self.identity, ".tmp");
        let written = (|| {
            match fs::remove_file(&temporary) {
                Err(error) if error.kind() != ErrorKind::NotFound => return Err(error),
                _ => {}
            }
            let mut file =
                private_files::open(OpenOptions::new().write(true).create_new(true), &temporary)?;
            file.write_all(identity.encoded().as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, &self.identity)
        })();
        written.map_err(file_error(&self.identity))
    }
}

pub fn read_identity_at(path: &Path) -> Result<Option<Identity>, OwnIdError> {
    let unreadable = || OwnIdError::UnreadableId(path.display().to_string());
    match fs::metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(file_error(path)(error)),
        Ok(metadata) if metadata.len() > MAX_ID_FILE_BYTES => return Err(unreadable()),
        Ok(_) => {}
    }
    let text = match fs::read_to_string(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        read => read.map_err(|_| unreadable())?,
    };
    Identity::from_encoded(text.trim())
        .map(Some)
        .map_err(|_| unreadable())
}

fn read_key(path: &Path) -> Result<Option<SigningKey>, OwnIdError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(file_error(path)(error)),
        Ok(_) => {}
    }
    SigningKey::load(path)
        .map(Some)
        .map_err(|_| OwnIdError::UnreadableKey(path.display().to_string()))
}

fn remove_if_there(path: &Path) -> Result<(), OwnIdError> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => Err(file_error(path)(error)),
        _ => Ok(()),
    }
}

/// The key `identity` counts now, from the key file, or from `.next` if a rotation or recovery
/// stopped before its last step, which this finishes. Only under the lock, as it renames.
fn settled_key(files: &Files, identity: &Identity) -> Result<SigningKey, OwnIdError> {
    let counted = identity
        .sole_key()
        .map_err(|_| OwnIdError::UnreadableId(files.identity.display().to_string()))?;
    if let Some(key) = read_key(&files.key)?
        && key.public_key() == *counted
    {
        remove_if_there(&files.next)?;
        return Ok(key);
    }
    if let Some(next) = read_key(&files.next)?
        && next.public_key() == *counted
    {
        fs::rename(&files.next, &files.key).map_err(file_error(&files.key))?;
        return Ok(next);
    }
    Err(OwnIdError::KeyDoesntMatch)
}

/// A host's ID around `key`, with no recovery code yet, and a sealing key nobody holds, as nothing is
/// ever sealed to a host.
fn new_id(key: &SigningKey) -> Result<Identity, OwnIdError> {
    let seal = SealingKey::generate()?.public_key();
    Ok(Identity::create(
        key,
        &seal,
        RecoveryRule::later(&key.public_key()),
    )?)
}

/// This host's key, its ID, and the key's statement that the ID is this host, signed once.
pub struct Own {
    key: SigningKey,
    identity: Identity,
    proof: String,
}

impl Own {
    pub(crate) fn new(
        key: SigningKey,
        identity: Identity,
        domain: &str,
    ) -> Result<Self, OwnIdError> {
        let proof = host_id::sign(&key, domain, &identity)?;
        Ok(Self {
            key,
            identity,
            proof,
        })
    }

    /// A new key and ID, for a host that's only ever made in a test.
    #[cfg(test)]
    pub(crate) fn fresh(domain: &str) -> Result<Self, OwnIdError> {
        let key = SigningKey::generate()?;
        let identity = new_id(&key)?;
        Self::new(key, identity, domain)
    }

    pub const fn key(&self) -> &SigningKey {
        &self.key
    }

    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn proof(&self) -> &str {
        &self.proof
    }
}

/// What this host signs with and publishes now. Each reader takes the whole of one, so a delivery's
/// proof and the page always agree.
pub struct OwnId {
    now: RwLock<Arc<Own>>,
}

impl OwnId {
    pub fn new(own: Own) -> Self {
        Self {
            now: RwLock::new(Arc::new(own)),
        }
    }

    pub fn now(&self) -> Arc<Own> {
        // Replaced whole, so it can't be left half done across a panic.
        self.now
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn replace(&self, own: Own) {
        *self.now.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(own);
    }
}

/// Whether a start whose key file is gone may make a new key: only where nothing could have met this
/// host under the old one, or where its operator said so.
#[derive(Clone, Copy)]
pub struct NewKey {
    /// Whether this host's database holds agents or other hosts' keys.
    pub used: bool,
    /// Whether its operator set `SPLINT_NEW_HOST_KEY=yes`.
    pub allowed: bool,
}

/// The one ID the file and the database's copy agree on, if either has one: two copies of one ID
/// take the newer, and two copies that part ways are refused. So are two different IDs, unless the
/// database has never been used: then nothing ever met this host under its copy, as on a server set
/// up afresh before the operator recovered the ID other hosts know into the file.
fn chosen(
    files: &Files,
    file: Option<Identity>,
    kept: Option<Identity>,
    used: bool,
) -> Result<Option<Identity>, OwnIdError> {
    match (file, kept) {
        (Some(file), Some(kept)) if file.id() == kept.id() => file
            .newest_of(&kept)
            .map(Some)
            .map_err(|_| OwnIdError::Forked),
        (Some(_), Some(_)) if used => {
            Err(OwnIdError::OtherId(files.identity.display().to_string()))
        }
        (Some(file), Some(_)) => {
            tracing::warn!(
                file = %files.identity.display(),
                "this host's database held another ID, which nothing ever met, so the file's is taken"
            );
            Ok(Some(file))
        }
        (file, kept) => Ok(file.or(kept)),
    }
}

/// The ID and key a start goes by, with the files and the database's copy put in agreement.
///
/// The ID is made only when there's none in either: a file lost while the database survives is
/// written back, and two copies of one ID take the newer. Two different IDs over a database that's
/// been used, or two copies that part ways, refuse, as do a key that isn't the one the ID counts, so
/// a lost key is never replaced by a new one every host that met this one would refuse, unless the
/// operator said to with `new_key`.
pub fn at_start(
    files: &Files,
    kept: Option<Identity>,
    domain: &str,
    new_key: NewKey,
) -> Result<Own, OwnIdError> {
    let _lock = files.lock_waiting()?;
    let file = files.read_identity()?;
    let in_file = file.as_ref().map(Identity::encoded);
    let Some(identity) = chosen(files, file, kept, new_key.used)? else {
        return first_id(files, domain, new_key.used, new_key.allowed);
    };
    if in_file.as_deref() != Some(identity.encoded().as_str()) {
        files.write_identity(&identity)?;
        if in_file.is_some() {
            tracing::warn!(
                file = %files.identity.display(),
                "the database held a newer copy of this host's ID than its file, so the file is \
                 that copy now"
            );
        } else {
            tracing::warn!(
                file = %files.identity.display(),
                "this host's ID file was missing, so it's written back from the database's copy"
            );
        }
    }
    match settled_key(files, &identity) {
        Err(OwnIdError::KeyDoesntMatch) if read_key(&files.key)?.is_none() => {
            // An ID means something may have met this host, so its key is never quietly replaced.
            first_id(files, domain, true, new_key.allowed)
        }
        settled => Own::new(settled?, identity, domain),
    }
}

/// A new ID around the key in the key file, or around a new key when there's none and making one
/// is safe or the operator said to. Only under the lock.
fn first_id(files: &Files, domain: &str, used: bool, allowed: bool) -> Result<Own, OwnIdError> {
    let held = read_key(&files.key)?.is_some();
    if !held && used && !allowed {
        return Err(OwnIdError::KeyGone(files.key.display().to_string()));
    }
    remove_if_there(&files.next)?;
    let key = SigningKey::load_or_create(&files.key)
        .map_err(|_| OwnIdError::UnreadableKey(files.key.display().to_string()))?;
    if !held && used {
        tracing::warn!(
            file = %files.key.display(),
            "made a new host key and ID over a database that's been used: every host that pinned \
             the old one refuses this one until whoever runs it accepts the new key"
        );
    } else if !held {
        tracing::info!(file = %files.key.display(), "made this host's key");
    }
    let identity = new_id(&key)?;
    files.write_identity(&identity)?;
    tracing::info!(id = %identity.id(), "this host has an ID now, around the key it had");
    Own::new(key, identity, domain)
}

/// What a start would find of this host's ID and key, changing nothing, so `splint-host check` can
/// run it beside the running host. It refuses what a start would refuse.
pub fn check(files: &Files, kept: Option<Identity>, new_key: NewKey) -> Result<(), OwnIdError> {
    let key = read_key(&files.key)?;
    let Some(identity) = chosen(files, files.read_identity()?, kept, new_key.used)? else {
        return if key.is_none() && new_key.used && !new_key.allowed {
            Err(OwnIdError::KeyGone(files.key.display().to_string()))
        } else {
            Ok(())
        };
    };
    let counted = identity
        .sole_key()
        .map_err(|_| OwnIdError::UnreadableId(files.identity.display().to_string()))?;
    let next = read_key(&files.next)?;
    if [key.as_ref(), next.as_ref()]
        .into_iter()
        .flatten()
        .any(|key| key.public_key() == *counted)
    {
        return Ok(());
    }
    match key {
        Some(_) => Err(OwnIdError::KeyDoesntMatch),
        None if new_key.allowed => Ok(()),
        None => Err(OwnIdError::KeyGone(files.key.display().to_string())),
    }
}

/// Each table that says this host has been used, and how to ask whether anything is in it.
const USED_IF_ANY: [(&str, &str); 2] = [
    ("agents", "SELECT EXISTS (SELECT 1 FROM agents)"),
    ("peer_keys", "SELECT EXISTS (SELECT 1 FROM peer_keys)"),
];

/// Whether anything was ever here under a key: an agent, or another host's key, which is pinned at
/// the first exchange with it. A database no host has started on yet has neither table.
pub async fn has_been_used(db: &PgPool) -> Result<bool, sqlx::Error> {
    for (table, any) in USED_IF_ANY {
        if made(db, table).await? && sqlx::query_scalar(any).fetch_one(db).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn made(db: &PgPool, table: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(db)
        .await
}

/// Says at every start, until it's done, what having no recovery code means.
pub fn warn_while_no_code(own: &Own) {
    if own.identity().recovery_is_later() {
        tracing::warn!(
            "this host has no recovery code: if its key is lost, every host that met it has to be \
             told by hand. Set one with `sudo splint-hostctl key code`, and keep it off this server"
        );
    }
}

/// The database's copy of this host's ID, if it has one that can be read.
pub async fn kept(db: &PgPool) -> Result<Option<Identity>, sqlx::Error> {
    // `splint-host check` asks before any start has made the table, and makes none.
    if !made(db, "own_host_id").await? {
        return Ok(None);
    }
    let text: Option<String> = sqlx::query_scalar("SELECT identity FROM own_host_id")
        .fetch_optional(db)
        .await?;
    Ok(text.and_then(|text| match Identity::from_encoded(&text) {
        Ok(identity) => Some(identity),
        Err(_) => {
            tracing::warn!("the database's copy of this host's ID can't be read, so it's not used");
            None
        }
    }))
}

pub async fn keep(db: &PgPool, identity: &Identity) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO own_host_id (identity) VALUES ($1)
         ON CONFLICT (one) DO UPDATE SET identity = EXCLUDED.identity",
    )
    .bind(identity.encoded())
    .execute(db)
    .await?;
    Ok(())
}

/// What one reading of the files changes. It renames nothing, so it never races a key command: an
/// ID naming a key still in `.next` is taken with that key, which the command then renames. A file
/// that's gone is written back from what's running, when no command holds the lock. Only a newer copy
/// of this host's own ID is taken, so a file put back from an old backup changes nothing.
fn reread(files: &Files, current: &Own, domain: &str) -> Result<Option<Own>, OwnIdError> {
    let Some(file) = files.read_identity()? else {
        if let Some(_lock) = files.lock_if_free()? {
            files.write_identity(current.identity())?;
            tracing::warn!(
                file = %files.identity.display(),
                "this host's ID file was gone, so it's written back from the ID it runs with"
            );
        }
        return Ok(None);
    };
    match file.replaces(current.identity()) {
        Ok(true) => {}
        // The same copy, however its signatures are spelled.
        Ok(false) => return Ok(None),
        Err(splint_core::Error::Stale) => {
            return Err(OwnIdError::OlderId(files.identity.display().to_string()));
        }
        Err(splint_core::Error::Forked) => return Err(OwnIdError::Forked),
        Err(_) => return Err(OwnIdError::OtherId(files.identity.display().to_string())),
    }
    let counted = file
        .sole_key()
        .map_err(|_| OwnIdError::UnreadableId(files.identity.display().to_string()))?;
    // `.next` first: a command renames it over the key, so if it's gone by then, the key is it.
    for path in [&files.next, &files.key] {
        if let Some(key) = read_key(path)?
            && key.public_key() == *counted
        {
            return Own::new(key, file, domain).map(Some);
        }
    }
    Err(OwnIdError::KeyDoesntMatch)
}

/// Reads the files again every two seconds, and runs with a newer ID from then on: deliveries are
/// signed with the key it counts, and the page publishes it. Each change is kept in the database too.
pub async fn run_rereading(host: Arc<Host>, files: Files) {
    let files = Arc::new(files);
    let mut kept_copy = String::new();
    loop {
        let current = host.own.now();
        if kept_copy != current.identity().encoded() {
            match keep(&host.db, current.identity()).await {
                Ok(()) => kept_copy = current.identity().encoded(),
                Err(error) => {
                    if let Some(count) = UNKEPT.due() {
                        tracing::warn!(%error, count, "couldn't keep this host's ID in the database yet");
                    }
                }
            }
        }
        tokio::time::sleep(REREAD_EVERY).await;
        let (reading, domain, running) = (files.clone(), host.domain.clone(), current.clone());
        let Ok(read) =
            tokio::task::spawn_blocking(move || reread(&reading, &running, &domain)).await
        else {
            continue;
        };
        match read {
            Ok(Some(next)) => {
                let (old, new) = (current.key().public_key(), next.key().public_key());
                if old == new {
                    tracing::info!("this host's ID changed, with its key as it was");
                } else {
                    tracing::info!(
                        old = %old.encoded(),
                        new = %new.encoded(),
                        "this host's key changed, and hosts that pinned its ID follow it by themselves"
                    );
                }
                warn_while_no_code(&next);
                host.own.replace(next);
            }
            Ok(None) => {}
            Err(error) => {
                if let Some(count) = UNUSABLE_FILES.due() {
                    tracing::warn!(
                        %error,
                        count,
                        "this host's ID or key files can't be used, so it runs with the ID it had"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &str = "here.example";
    const FRESH: NewKey = NewKey {
        used: false,
        allowed: false,
    };

    /// A folder of its own for one test, gone when the test ends, as it holds a private key.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("splint-own-id-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            private_files::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn files(&self) -> Files {
            Files::beside(&self.0.join("host.key"))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rotated(files: &Files, own: &Own) -> (SigningKey, Identity) {
        let next = SigningKey::create_new(&files.next).unwrap();
        let name = splint_core::OwnerKey::name_of(&own.key().public_key());
        let identity = own
            .identity()
            .add_key(own.key(), &next, 1)
            .unwrap()
            .remove_key(&next, &name, 1)
            .unwrap();
        (next, identity)
    }

    /// A rotation cut short at any step, or a file lost, must leave files that a start or a reading
    /// puts right without a new ID or a new key, which every host that pinned this one would refuse.
    #[test]
    fn every_state_the_files_can_be_left_in_settles_to_the_one_id() {
        // Nothing yet: an ID is made around the key there, and only then.
        let scratch = Scratch::new("settle");
        let files = scratch.files();
        let first = at_start(&files, None, DOMAIN, FRESH).unwrap();
        let again = at_start(&files, None, DOMAIN, FRESH).unwrap();
        assert_eq!(again.identity().encoded(), first.identity().encoded());

        // Cut after `.next` was written: the ID still counts the old key, and `.next` goes.
        rotated(&files, &first);
        let own = at_start(&files, None, DOMAIN, FRESH).unwrap();
        assert_eq!(own.key().public_key(), first.key().public_key());
        assert!(!files.next.exists());

        // Cut after the ID was written, before the rename: a reading signs with `.next`, renaming
        // nothing, and a start finishes the rename.
        let (next, newer_too) = rotated(&files, &first);
        files.write_identity(&newer_too).unwrap();
        let read = reread(&files, &first, DOMAIN).unwrap().unwrap();
        assert_eq!(read.key().public_key(), next.public_key());
        assert!(files.next.exists());
        let own = at_start(&files, None, DOMAIN, FRESH).unwrap();
        assert_eq!(own.key().public_key(), next.public_key());
        assert!(!files.next.exists());

        // The ID file lost while the database kept a copy: written back, not made again.
        fs::remove_file(&files.identity).unwrap();
        let own = at_start(&files, Some(newer_too.clone()), DOMAIN, FRESH).unwrap();
        assert_eq!(own.identity().encoded(), newer_too.encoded());

        // An older ID file put back, with the database's newer copy: the newer wins.
        files.write_identity(first.identity()).unwrap();
        at_start(&files, Some(newer_too.clone()), DOMAIN, FRESH).unwrap();
        assert_eq!(
            files.read_identity().unwrap().unwrap().encoded(),
            newer_too.encoded()
        );

        // A reading never takes an older copy, and writes a lost file back from what's running.
        files.write_identity(first.identity()).unwrap();
        assert!(matches!(
            reread(&files, &own, DOMAIN),
            Err(OwnIdError::OlderId(_))
        ));
        fs::remove_file(&files.identity).unwrap();
        assert!(reread(&files, &own, DOMAIN).unwrap().is_none());
        assert_eq!(
            files.read_identity().unwrap().unwrap().encoded(),
            own.identity().encoded()
        );

        // A different key put in the key file with the ID kept: refused, with the ID as it was, so
        // an old backup's key never turns into a new host every peer refuses.
        fs::remove_file(&files.key).unwrap();
        SigningKey::create_new(&files.key).unwrap();
        let before = files.read_identity().unwrap().unwrap().encoded();
        assert!(matches!(
            at_start(&files, None, DOMAIN, FRESH),
            Err(OwnIdError::KeyDoesntMatch)
        ));
        assert!(matches!(
            check(&files, None, FRESH),
            Err(OwnIdError::KeyDoesntMatch)
        ));
        assert_eq!(files.read_identity().unwrap().unwrap().encoded(), before);
        fs::remove_file(&files.key).unwrap();
        own.key().save_new(&files.key).unwrap();

        // The key lost with the ID kept: refused, never a new key, though nothing else was used.
        fs::remove_file(&files.key).unwrap();
        assert!(matches!(
            at_start(&files, None, DOMAIN, FRESH),
            Err(OwnIdError::KeyGone(_))
        ));
        assert!(matches!(
            check(&files, None, FRESH),
            Err(OwnIdError::KeyGone(_))
        ));
        assert!(!files.key.exists());

        // Another ID in a used database than in the file: refused.
        let stranger = Own::fresh(DOMAIN).unwrap();
        let used = NewKey {
            used: true,
            allowed: false,
        };
        assert!(matches!(
            at_start(&files, Some(stranger.identity().clone()), DOMAIN, used),
            Err(OwnIdError::OtherId(_))
        ));

        // Only the operator's word makes a new key over a held ID, and then it's a new host's ID.
        let allowed = NewKey {
            used: true,
            allowed: true,
        };
        let new_host = at_start(&files, None, DOMAIN, allowed).unwrap();
        assert_ne!(new_host.identity().id(), own.identity().id());
        assert!(check(&files, None, FRESH).is_ok());
    }

    /// A restore that put a backup's key beside an ID that doesn't count it left a host that wouldn't
    /// start, on a rebuilt server, or after rolling a database back past a rotation.
    #[test]
    fn a_backup_goes_back_as_a_pair_and_never_over_a_newer_one() {
        let scratch = Scratch::new("restore");
        let files = scratch.files();
        let backup = at_start(&files, None, DOMAIN, FRESH).unwrap();
        let (key_from_backup, id_from_backup) = (scratch.0.join("k"), scratch.0.join("i"));
        let saved_backup = || {
            let _ = fs::remove_file(&key_from_backup);
            backup.key().save_new(&key_from_backup).unwrap();
            fs::write(&id_from_backup, backup.identity().encoded()).unwrap();
        };
        let restoring = || {
            saved_backup();
            commands::put_back(&files, &key_from_backup, Some(&id_from_backup)).unwrap()
        };

        // Rolled back past a rotation: the rotated pair stays, and the host starts on it.
        let (next, newer) = rotated(&files, &backup);
        files.write_identity(&newer).unwrap();
        fs::rename(&files.next, &files.key).unwrap();
        assert_eq!(restoring(), commands::PutBack::Kept);
        // A backup from before host IDs, of the key this ID began with, is no newer either.
        assert_eq!(
            commands::put_back(&files, &key_from_backup, None).unwrap(),
            commands::PutBack::Kept
        );
        let own = at_start(&files, Some(backup.identity().clone()), DOMAIN, FRESH).unwrap();
        assert_eq!(own.key().public_key(), next.public_key());

        // The key lost as well: the backup's doesn't count now, so a recovery is what's left.
        fs::remove_file(&files.key).unwrap();
        assert_eq!(restoring(), commands::PutBack::KeyTooOld);

        // A fresh install's first start made another ID: the backup's pair replaces it.
        fs::remove_file(&files.identity).unwrap();
        let throwaway = at_start(&files, None, DOMAIN, FRESH).unwrap();
        assert_ne!(throwaway.identity().id(), backup.identity().id());
        assert_eq!(restoring(), commands::PutBack::Backup);
        let used = NewKey {
            used: true,
            allowed: false,
        };
        let own = at_start(&files, Some(backup.identity().clone()), DOMAIN, used).unwrap();
        assert_eq!(own.identity().id(), backup.identity().id());
        assert_eq!(own.key().public_key(), backup.key().public_key());
    }
}

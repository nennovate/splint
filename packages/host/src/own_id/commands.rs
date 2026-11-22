//! `splint-host key`: what an operator types to set this host's recovery code, rotate its key, or
//! recover it with the code.
//!
//! Each runs beside a running host, as the user it runs as, with its `SPLINT_HOST_KEY_FILE`, and
//! touches only the files: the running host takes the change within a few seconds, with no restart,
//! and hosts that pinned its ID follow by themselves. None makes an ID: that's a start's, which also
//! checks the database's copy. Like `owner-key`, these write to stdout because a person is reading,
//! and a recovery code goes there once and nowhere else: no log, no file, no error.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use splint_core::recovery_code::RecoveryCode;
use splint_core::{
    Identity, MAX_ADDITIONS, OwnerKey, RecoveryRule, SealingKey, SigningKey, unix_now,
};

use super::{Files, OwnIdError, read_identity_at, read_key, remove_if_there, settled_key};

pub const USAGE: &str = "\
splint-host key code        Sets this host's recovery code, once, and prints it. Keep it off this
                            server: with it, a lost or stolen key is replaced and every host that
                            met this one follows. --if-unset says nothing when one is set already.
splint-host key rotate      Gives this host a new key. Every host that pinned its ID follows by
                            itself, and nothing restarts.
splint-host key recover     Replaces this host's key with the recovery code, read from stdin, and
                            prints the next code. --identity FILE recovers from a saved copy of
                            host.key.identity, on a server rebuilt without it, and setting aside
                            any other ID it made meanwhile. Restart the host after that.
splint-host key restore     Puts a backup's key back, with --key FILE and, if the backup has one,
                            --identity FILE, each in the key's folder. splint-restore runs this. A key
                            and ID here that are newer than the backup's stay.";

/// Runs `splint-host key ...` and says how it went.
pub fn run(args: &[&str]) -> Result<(), OwnIdError> {
    match args {
        ["key", "code"] => code(false),
        ["key", "code", "--if-unset"] => code(true),
        ["key", "rotate"] => rotate(),
        ["key", "recover"] => recover(None),
        ["key", "recover", "--identity", file] => recover(Some(Path::new(file))),
        ["key", "restore", "--key", key] => restore(Path::new(key), None),
        ["key", "restore", "--key", key, "--identity", identity] => {
            restore(Path::new(key), Some(Path::new(identity)))
        }
        _ => Err(OwnIdError::Usage(USAGE)),
    }
}

fn say(text: &str) -> Result<(), OwnIdError> {
    let mut out = io::stdout().lock();
    out.write_all(text.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .map_err(|error| OwnIdError::File("stdout".to_owned(), error.kind()))
}

/// This host's ID as its file holds it, and the key it counts, with any rotation cut short put right.
fn held(files: &Files) -> Result<(Identity, SigningKey), OwnIdError> {
    let identity = files
        .read_identity()?
        .ok_or_else(|| OwnIdError::NoIdYet(files.identity.display().to_string()))?;
    let key = settled_key(files, &identity)?;
    Ok((identity, key))
}

fn code(if_unset: bool) -> Result<(), OwnIdError> {
    let files = Files::from_env()?;
    let _lock = files.lock_waiting()?;
    let (identity, key) = held(&files)?;
    if !identity.recovery_is_later() {
        return if if_unset {
            Ok(())
        } else {
            Err(OwnIdError::CodeSetAlready)
        };
    }
    let code = RecoveryCode::generate()?;
    let rule = RecoveryRule::backup_key(&code.backup_key()?.public_key());
    let coded = identity.set_recovery_rule(&key, &rule, unix_now())?;
    files.write_identity(&coded)?;
    say(&code_words(
        &code,
        &files,
        "This host's recovery code, shown this once:",
    ))
}

fn rotate() -> Result<(), OwnIdError> {
    let files = Files::from_env()?;
    let _lock = files.lock_waiting()?;
    let (identity, key) = held(&files)?;
    if identity.additions_left() == 0 {
        return Err(OwnIdError::NoRotationsLeft);
    }
    // The new key is written whole before the ID names it, and the ID before the key file is
    // replaced, so a cut at any point leaves files that a start or the next command puts right.
    remove_if_there(&files.next)?;
    let next = SigningKey::create_new(&files.next)?;
    let now = unix_now();
    let rotated = identity
        .add_key(&key, &next, now)
        .and_then(|added| added.remove_key(&next, &OwnerKey::name_of(&key.public_key()), now))
        .map_err(|_| OwnIdError::NoRotationsLeft)?;
    files.write_identity(&rotated)?;
    fs::rename(&files.next, &files.key).map_err(super::file_error(&files.key))?;
    let left = rotated.additions_left();
    let no_code = if rotated.recovery_is_later() {
        " This host still has no recovery code: set one with `sudo splint-hostctl key code`."
    } else {
        ""
    };
    let rotations = if left == 1 {
        "rotation is"
    } else {
        "rotations are"
    };
    say(&format!(
        "This host has a new key. The running host signs with it within a few seconds, and every \
         host that pinned its ID follows by itself. {left} more {rotations} left of {MAX_ADDITIONS} \
         before a recovery, which starts the count again.{no_code}"
    ))
}

/// The backup key the code an operator types gives. Asked for before any lock is taken, as a prompt
/// left open would otherwise hold up every start of the host with nothing to say why.
fn typed_backup() -> Result<SigningKey, OwnIdError> {
    let mut asking = io::stderr().lock();
    asking
        .write_all(b"Type this host's recovery code, then press Enter:\n")
        .and_then(|()| asking.flush())
        .map_err(|error| OwnIdError::File("stderr".to_owned(), error.kind()))?;
    drop(asking);
    let mut typed = String::new();
    io::stdin()
        .lock()
        .read_line(&mut typed)
        .map_err(|error| OwnIdError::File("stdin".to_owned(), error.kind()))?;
    Ok(RecoveryCode::parse(&typed)
        .map_err(|_| OwnIdError::NotACode)?
        .backup_key()?)
}

fn recover(saved: Option<&Path>) -> Result<(), OwnIdError> {
    let files = Files::from_env()?;
    let backup = typed_backup()?;
    let _lock = files.lock_waiting()?;
    // A saved copy of another ID than the file's is the one the code decides on: a rebuilt server's
    // first start made the file's, which is set aside only once the code has proved this one.
    let (identity, replacing) = match (files.read_identity()?, saved) {
        (Some(file), None) => (file, false),
        (None, None) => return Err(OwnIdError::NoIdYet(files.identity.display().to_string())),
        (file, Some(path)) => {
            let saved = read_identity_at(path)?
                .ok_or_else(|| OwnIdError::NoIdYet(path.display().to_string()))?;
            match file {
                None => (saved, false),
                Some(file) if file.id() == saved.id() => (
                    file.newest_of(&saved).map_err(|_| OwnIdError::Forked)?,
                    false,
                ),
                Some(_) => (saved, true),
            }
        }
    };
    identity
        .check_backup(&backup.public_key())
        .map_err(|_| OwnIdError::WrongCode)?;
    if identity.recoveries() >= splint_core::MAX_RECOVERIES {
        return Err(OwnIdError::NoRecoveriesLeft);
    }
    let next_code = RecoveryCode::generate()?;
    if replacing {
        files.set_aside()?;
    }
    remove_if_there(&files.next)?;
    let next = SigningKey::create_new(&files.next)?;
    // A new sealing key nobody holds, as a recovery needs one the ID never had.
    let seal = SealingKey::generate()?.public_key();
    let recovered = identity.recover(
        &backup,
        &next.public_key(),
        &seal,
        RecoveryRule::backup_key(&next_code.backup_key()?.public_key()),
        unix_now(),
    )?;
    files.write_identity(&recovered)?;
    fs::rename(&files.next, &files.key).map_err(super::file_error(&files.key))?;
    say(&code_words(
        &next_code,
        &files,
        if replacing {
            "This host has its ID back with a new key, and the ID this server made meanwhile is set \
             aside. Restart the host now, and every host that pinned its ID follows. The code you \
             typed is spent. This host's next recovery code, shown this once:"
        } else {
            "This host has a new key, and every host that pinned its ID follows it, whoever held the \
             old one. The code you typed is spent. This host's next recovery code, shown this once:"
        },
    ))
}

/// What a backup's key and ID did to what this disk holds.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum PutBack {
    /// The backup's key, and its ID if it has one, are this host's now.
    Backup,
    /// The ID here stays, and the backup's key is the one it counts.
    KeyOnly,
    /// The key and ID here are at least as new as the backup's, so they stay.
    Kept,
    /// The ID here has moved past the backup's key, and no key it counts is here.
    KeyTooOld,
}

fn restore(backup_key: &Path, backup_id: Option<&Path>) -> Result<(), OwnIdError> {
    let files = Files::from_env()?;
    let _lock = files.lock_waiting()?;
    say(match put_back(&files, backup_key, backup_id)? {
        PutBack::Backup => "This host's key and ID are the backup's now.",
        PutBack::KeyOnly => "This host's key is the backup's now, and its ID stays.",
        PutBack::Kept => "This host's key and ID are newer than the backup's, so they stay.",
        PutBack::KeyTooOld => {
            "This host's ID has moved past the backup's key, and the key it counts isn't here, so \
             the host won't start until `sudo splint-hostctl key recover` replaces it."
        }
    })
}

/// Puts a backup in place as a pair, so a key never lands beside an ID that doesn't count it. An ID
/// here that's another one than the backup's was made on this server since, as a fresh install's
/// first start makes one, and is set aside. A newer copy of the backup's own ID stays with its key,
/// as rolling a database back doesn't undo a rotation other hosts have followed.
pub(super) fn put_back(
    files: &Files,
    backup_key: &Path,
    backup_id: Option<&Path>,
) -> Result<PutBack, OwnIdError> {
    let key = read_key(backup_key)?
        .ok_or_else(|| OwnIdError::UnreadableKey(backup_key.display().to_string()))?;
    let backup = backup_id.map(read_identity_at).transpose()?.flatten();
    let move_key = || fs::rename(backup_key, &files.key).map_err(super::file_error(&files.key));
    let here = files.read_identity()?;
    let backup_wins = match (&here, &backup) {
        (None, _) => true,
        (Some(here), Some(backup)) if here.id() != backup.id() => true,
        (Some(here), Some(backup)) => match backup.replaces(here) {
            Ok(newer) => newer,
            Err(splint_core::Error::Stale) => false,
            Err(_) => return Err(OwnIdError::Forked),
        },
        // A backup from before host IDs holds a key alone, and an ID that key began is its own.
        (Some(here), None) => {
            here.sole_key().ok() != Some(&key.public_key()) && !here.rooted_in(&key.public_key())
        }
    };
    if backup_wins {
        files.set_aside()?;
        move_key()?;
        if let Some(backup) = &backup {
            files.write_identity(backup)?;
        }
        return Ok(PutBack::Backup);
    }
    let Some(here) = here else {
        return Ok(PutBack::Kept);
    };
    let counted = here
        .sole_key()
        .map_err(|_| OwnIdError::UnreadableId(files.identity.display().to_string()))?;
    // A key file that can't be read is as good as gone, which is what a restore is for.
    let holds_it = |path: &Path| {
        read_key(path)
            .ok()
            .flatten()
            .is_some_and(|held| held.public_key() == *counted)
    };
    if holds_it(&files.key) || holds_it(&files.next) {
        return Ok(PutBack::Kept);
    }
    if key.public_key() == *counted {
        move_key()?;
        return Ok(PutBack::KeyOnly);
    }
    Ok(PutBack::KeyTooOld)
}

fn code_words(code: &RecoveryCode, files: &Files, opening: &str) -> String {
    format!(
        "{opening}\n\n    {}\n\nCopy it off this server now, with a copy of {} (which is public). \
         If this host's key is ever lost or stolen, `sudo splint-hostctl key recover` with this code \
         replaces it, and every host that met this one follows. Nothing else can.",
        code.spelled(),
        files.identity_path().display(),
    )
}

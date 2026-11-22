//! The owner's sign-in on this computer: the key that signs for their owner ID here. It's held by the
//! security chip where Splint can use one, the Mac's Secure Enclave today, and is otherwise a key file
//! only this computer user can read, locked with a passphrase the person chose, as Nenye decided on
//! 2026-11-17: a plain file is as safe as the computer user's account, where anything running as
//! them, such as their own agent, can copy it or sign with it. A plain one is made only when the
//! person asks for exactly that, and says so every time it's used or listed. One made before then
//! still opens, and [`lock`] locks it without changing the key.
//!
//! A key file made as a sign-in has a mark beside it, [`MADE_AS_SIGN_IN`]. The owner key `init` and
//! `recover` make with no `--sign-in`, for a device the person keeps apart from their agents, has
//! none: `splint authorize` and `setup` use that one and give no passphrase, so it's never warned
//! about as a sign-in, and never locked.

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::OnceLock;

use splint_core::{Error, SigningKey, private_files};

use crate::prompt::Prompt;

/// The chip's handle for the key, which only this computer's chip can use.
pub const CHIP: &str = "owner.chip";
/// A key file, plain or locked.
pub const KEY_FILE: &str = "owner.key";
/// Beside a key file made as this computer's sign-in, and empty. It keeps nothing safe, and only says
/// which of the two the key file is, so a person is never told to lock the other.
pub const MADE_AS_SIGN_IN: &str = "owner.sign-in";

/// How a sign-in that's there is held.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Chip,
    File,
}

impl Kind {
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "chip" => Some(Self::Chip),
            "file" => Some(Self::File),
            _ => None,
        }
    }

    /// The chip wherever Splint can use one.
    pub fn best_here() -> Self {
        if cfg!(target_os = "macos") {
            Self::Chip
        } else {
            Self::File
        }
    }
}

/// The fewest characters a passphrase for a key file has. Provisional.
pub const FEWEST_CHARACTERS: usize = 8;

/// A passphrase a person chose to lock a key file with, long enough to be taken. It has no `Debug`,
/// so it can't be printed by accident.
pub struct NewPassphrase(Vec<u8>);

impl NewPassphrase {
    /// `None` for one shorter than [`FEWEST_CHARACTERS`], an empty one included.
    pub fn chosen(typed: &str) -> Option<Self> {
        (typed.chars().count() >= FEWEST_CHARACTERS).then(|| Self(typed.as_bytes().to_vec()))
    }
}

/// How a new sign-in is to be held. A key file has no default: whoever makes one names its passphrase
/// or says in so many words that it's plain, so none is ever plain because a passphrase was left out.
pub enum Holding {
    Chip,
    LockedFile(NewPassphrase),
    /// A key file with no passphrase, which anything running as this computer user can sign with.
    /// Only for a person who asked for exactly that: nothing an agent hands over chooses it.
    PlainFile,
}

/// The passphrase the person gave this run, if any, for a locked key file.
static PASSPHRASE: OnceLock<Vec<u8>> = OnceLock::new();

pub fn give_passphrase(passphrase: Vec<u8>) {
    let _ = PASSPHRASE.set(passphrase);
}

fn passphrase() -> Option<&'static [u8]> {
    PASSPHRASE.get().map(Vec::as_slice)
}

/// Why a locked key file didn't open this run, for the person: no passphrase, or not its own.
static LOCKED_OUT: OnceLock<&'static str> = OnceLock::new();

pub fn locked_out() -> Option<&'static str> {
    LOCKED_OUT.get().copied()
}

/// Makes this computer's sign-in in `dir`, refusing if one is there. A chip's prompt shows `prompt`.
pub fn create(dir: &Path, holding: Holding, prompt: &Prompt) -> Result<SigningKey, Error> {
    if kind_in(dir).is_some() {
        return Err(Error::KeyStorage);
    }
    let made_as_sign_in =
        || fs::write(dir.join(MADE_AS_SIGN_IN), "").map_err(|_| Error::KeyStorage);
    match holding {
        Holding::Chip => create_chip(dir, prompt),
        Holding::LockedFile(NewPassphrase(chosen)) => {
            made_as_sign_in()?;
            let key = SigningKey::create_locked(&dir.join(KEY_FILE), &chosen)?;
            // The rest of this run opens it with the passphrase that made it.
            give_passphrase(chosen);
            Ok(key)
        }
        Holding::PlainFile => {
            made_as_sign_in()?;
            SigningKey::create_new(&dir.join(KEY_FILE))
        }
    }
}

/// Whether the key file in `dir` was made as a sign-in, and so not as the owner key of a device kept
/// apart from agents, which `splint authorize` and `setup` use with no passphrase.
pub fn made_as_sign_in(dir: &Path) -> bool {
    dir.join(MADE_AS_SIGN_IN).exists()
}

/// What [`lock`] takes to lock a key file: that it's a sign-in, by its mark, or by the word of a caller
/// that keeps the folder as one, for a sign-in from before they were marked. The owner key of a device
/// kept apart from agents has neither, so a slip never locks what `splint` uses with no passphrase.
pub struct IsASignIn(());

impl IsASignIn {
    pub fn by_its_mark(dir: &Path) -> Option<Self> {
        made_as_sign_in(dir).then_some(Self(()))
    }

    /// For `--unmarked-sign-in yes`, which `splint computer lock` gives for the folder it keeps.
    pub fn as_told() -> Self {
        Self(())
    }
}

/// Locks the plain key file in `dir` with a passphrase, keeping its key, so the owner ID it signs for
/// doesn't change. One that's locked already, or held by the chip, is refused, and it takes an
/// [`IsASignIn`], so the owner key of a device kept apart from agents is never locked by a slip.
pub fn lock(dir: &Path, _: IsASignIn, NewPassphrase(chosen): NewPassphrase) -> Result<(), Error> {
    if !is_plain_file(dir) {
        return Err(Error::KeyStorage);
    }
    SigningKey::lock_file(&dir.join(KEY_FILE), &chosen)?;
    Ok(())
}

/// Whether the sign-in in `dir` is a key file with no passphrase.
pub fn is_plain_file(dir: &Path) -> bool {
    kind_in(dir) == Some(Kind::File) && !is_locked(dir)
}

/// Says, on stderr, that the sign-in in `dir` is a plain key file, if it is: every time one signs or
/// is listed, as a setting that weakens a check has to. Only for a key file made as a sign-in: never
/// for a stand-in's key, which is on its agent's machine by design and signs nothing that counts as an
/// owner's, nor for the owner key of a device kept apart from agents, which locking would stop
/// `splint authorize` and `setup` from using.
pub fn warn_if_plain(dir: &Path) {
    if is_plain_file(dir) && made_as_sign_in(dir) {
        let _ = writeln!(
            io::stderr(),
            "{PLAIN_WARNING} owner-key lock-sign-in --dir {} --passphrase -",
            dir.display()
        );
    }
}

/// What a plain key file means, in plain words, ending where the command that locks it goes.
pub const PLAIN_WARNING: &str = "Warning: this sign-in is a key file with no passphrase, so anything \
     running as you on this computer, your agent included, can sign as you. Lock it with a passphrase:";

#[cfg(target_os = "macos")]
fn create_chip(dir: &Path, prompt: &Prompt) -> Result<SigningKey, Error> {
    crate::chip::create(&dir.join(CHIP), crate::chip::Presence::Required)?;
    open(dir, prompt)
}

#[cfg(not(target_os = "macos"))]
fn create_chip(_dir: &Path, _prompt: &Prompt) -> Result<SigningKey, Error> {
    Err(Error::KeyStorage)
}

/// This computer's sign-in in `dir`, whose chip prompt, if it has one, shows `prompt`, which only
/// [`crate::prompt`] writes. A locked file without its passphrase is [`Error::CantOpen`].
pub fn open(dir: &Path, prompt: &Prompt) -> Result<SigningKey, Error> {
    match kind_in(dir) {
        Some(Kind::Chip) => open_chip(dir, prompt),
        Some(Kind::File) if is_locked(dir) => {
            let Some(given) = passphrase() else {
                let _ = LOCKED_OUT.set(
                    "this sign-in's key file is locked, and signs only with its passphrase: give \
                     it with --passphrase -, as the first line of standard input",
                );
                return Err(Error::CantOpen);
            };
            SigningKey::load_locked(&dir.join(KEY_FILE), given).inspect_err(|error| {
                if *error == Error::CantOpen {
                    let _ = LOCKED_OUT
                        .set("that isn't this sign-in's passphrase, so nothing was signed");
                }
            })
        }
        Some(Kind::File) => SigningKey::load(&dir.join(KEY_FILE)),
        None => Err(Error::KeyStorage),
    }
}

#[cfg(target_os = "macos")]
fn open_chip(dir: &Path, prompt: &Prompt) -> Result<SigningKey, Error> {
    SigningKey::held(Box::new(crate::chip::open(
        &dir.join(CHIP),
        prompt.words(),
    )?))
}

#[cfg(not(target_os = "macos"))]
fn open_chip(_dir: &Path, _prompt: &Prompt) -> Result<SigningKey, Error> {
    Err(Error::KeyStorage)
}

pub fn kind_in(dir: &Path) -> Option<Kind> {
    if dir.join(CHIP).exists() {
        Some(Kind::Chip)
    } else if dir.join(KEY_FILE).exists() {
        Some(Kind::File)
    } else {
        None
    }
}

/// A locked file is JSON, and a plain key is DER, which never starts with `{`.
pub fn is_locked(dir: &Path) -> bool {
    fs::read(dir.join(KEY_FILE)).is_ok_and(|bytes| bytes.first() == Some(&b'{'))
}

/// How the sign-in is held, in words for a summary.
pub fn described(dir: &Path) -> &'static str {
    match kind_in(dir) {
        Some(Kind::Chip) => "this computer's security chip",
        Some(Kind::File) if is_locked(dir) => "a key file locked with a passphrase",
        Some(Kind::File) => "a plain key file",
        None => "none",
    }
}

/// A directory already there must be private too, since it's about to hold keys.
pub fn make_private_dir(dir: &Path) -> io::Result<()> {
    private_files::create_dir_all(dir)?;
    if private_files::others_can_open(dir)? {
        return Err(io::Error::other("this directory is readable by others"));
    }
    Ok(())
}

/// Writes a file only this user can read, refusing one already there. Only the chip's handle is
/// written this way, so only where there's a chip Splint uses.
#[cfg(target_os = "macos")]
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write as _;
    let mut file = private_files::open(fs::OpenOptions::new().write(true).create_new(true), path)
        .map_err(|_| Error::KeyStorage)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::KeyStorage)
}

/// A file's bytes, or `None` if there's none. One others can read is refused.
#[cfg(target_os = "macos")]
pub fn read_private(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match private_files::others_can_open(path) {
        Ok(true) => Err(Error::KeyStorage),
        Ok(false) => fs::read(path).map(Some).map_err(|_| Error::KeyStorage),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::KeyStorage),
    }
}

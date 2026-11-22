//! Files and folders only this user can open, wherever Splint runs.
//!
//! On Unix a private file has mode 0600 and a private folder 0700. On Windows both get a protected ACL
//! that names this user alone, so nothing inherited from the folder above lets anyone else in. Either
//! way it's private from the moment it's made, not once it's been tightened, as someone who opened it
//! in between would keep what they opened. Each program asks for these here rather than setting modes
//! itself, so the two systems can't drift.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
const FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const FOLDER_MODE: u32 = 0o700;
#[cfg(unix)]
const OTHERS_ACCESS: u32 = 0o077;

/// Opens a file as `options` say, which create it if it isn't there. One it creates is private from the
/// start, and on Windows one that was there is made private.
pub fn open(options: &mut OpenOptions, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE).open(path)
    }
    #[cfg(windows)]
    {
        // Made private first, then opened as asked. A file that was there already stays as it was
        // for `create_new` to refuse.
        let mut options = options.clone();
        if windows::create_private_file(path)? {
            options.create_new(false);
        }
        let file = options.open(path)?;
        windows::restrict(path, false)?;
        Ok(file)
    }
}

/// Makes what's at `path` private, a file or a folder, whatever it allowed before.
pub fn restrict(path: &Path) -> io::Result<()> {
    let folder = fs::metadata(path)?.is_dir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if folder { FOLDER_MODE } else { FILE_MODE };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        windows::restrict(path, folder)
    }
}

/// Creates the folders that are missing, each one private, and leaves one already there as it was.
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(FOLDER_MODE)
            .create(path)
    }
    #[cfg(windows)]
    {
        let mut missing = Vec::new();
        let mut at = path;
        while !at.is_dir() {
            missing.push(at);
            match at.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => at = parent,
                _ => break,
            }
        }
        for folder in missing.into_iter().rev() {
            match windows::create_private_dir(folder) {
                // Made meanwhile by something else, which is left as it was.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && folder.is_dir() => {}
                done => done?,
            }
        }
        Ok(())
    }
}

/// Creates the folders that are missing, and makes this one private even if it was there already.
pub fn make_private_dir(path: &Path) -> io::Result<()> {
    create_dir_all(path)?;
    restrict(path)
}

/// Creates exactly this folder, private, and fails if anything is there already.
pub fn new_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(FOLDER_MODE).create(path)
    }
    #[cfg(windows)]
    {
        windows::create_private_dir(path)
    }
}

/// Whether anyone but this user, and on Windows the system and its administrators, who can read
/// anything anyway, could open what's at `path`.
pub fn others_can_open(path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(fs::metadata(path)?.permissions().mode() & OTHERS_ACCESS != 0)
    }
    #[cfg(windows)]
    {
        let (acl, user) = windows::acl_of(path)?;
        Ok(!acl_lets_in_only(&acl, &user))
    }
}

/// Whether an owner and ACL, in Windows's text form (SDDL), let in nobody but `user`, the system and
/// its administrators. The owner counts, as an owner can always change the ACL. Read conservatively:
/// anything it can't place counts as letting someone in.
#[cfg(any(windows, test))]
fn acl_lets_in_only(sddl: &str, user: &str) -> bool {
    let trusted = |who: &str| who == user || matches!(who, "SY" | "BA");
    // "O:" and the owner, then "D:" with the ACL's flags, then each entry in brackets.
    let Some((owner, acl)) = sddl
        .strip_prefix("O:")
        .and_then(|rest| rest.split_once("D:"))
    else {
        return false;
    };
    if !trusted(owner) {
        return false;
    }
    let (flags, entries) = acl.split_once('(').unwrap_or((acl, ""));
    // No ACL at all lets everyone in.
    if flags.contains("NO_ACCESS_CONTROL") {
        return false;
    }
    if entries.is_empty() {
        return flags.chars().all(|c| matches!(c, 'P' | 'A' | 'I' | 'R'));
    }
    let Some(entries) = entries.strip_suffix(')') else {
        return false;
    };
    entries.split(")(").all(|entry| {
        let fields: Vec<&str> = entry.split(';').collect();
        let (Some(kind), Some(entry_flags), Some(who)) =
            (fields.first(), fields.get(1), fields.get(5))
        else {
            return false;
        };
        let denies = matches!(*kind, "D" | "OD" | "XD");
        // An entry for whoever makes something inside, which only those let in here can, and which
        // grants nothing here itself. One inherited by anyone else lets them into what's made inside.
        let for_its_maker = entry_flags.as_bytes().chunks(2).any(|flag| flag == b"IO")
            && matches!(*who, "CO" | "CG");
        denies || for_its_maker || trusted(who)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    /// The bug this catches: a key file Windows lets someone else read taken as private, as an entry
    /// for another account, for everyone, or for what anyone makes inside a folder, an owner who can
    /// rewrite the ACL, or no ACL at all read as only this user's.
    #[test]
    fn only_an_acl_naming_this_user_the_system_and_administrators_counts_as_private() {
        for private in [
            format!("O:{ME}D:P(A;;FA;;;{ME})"),
            format!("O:BAD:PAI(A;OICI;FA;;;{ME})(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)"),
            format!("O:SYD:(A;OICIID;FA;;;{ME})(D;;FA;;;WD)"),
            format!("O:{ME}D:P(A;;FA;;;{ME})(A;OICIIO;GA;;;CO)"),
            // Allowed to this user alone, when a condition holds.
            format!("O:{ME}D:P(XA;;FA;;;{ME};(WIN://SYSAPPID Contains \"x\"))"),
            format!("O:{ME}D:P"),
        ] {
            assert!(acl_lets_in_only(&private, ME), "{private}");
        }
        for open in [
            format!("O:{ME}D:P(A;;FA;;;{ME})(A;;FR;;;WD)"),
            format!("O:{ME}D:AI(A;OICIID;FA;;;{ME})(A;OICIID;0x1200a9;;;BU)"),
            format!("O:{ME}D:P(A;;FA;;;{ME})(A;;FA;;;S-1-5-21-1-2-3-1002)"),
            format!("O:{ME}D:P(A;;FA;;;{ME})(OA;;FA;;;AU)"),
            // Everyone gets all of whatever is made inside.
            format!("O:{ME}D:P(A;OICI;FA;;;{ME})(A;OICIIO;FA;;;WD)"),
            // Allowed to everyone, when a condition holds.
            format!("O:{ME}D:P(A;;FA;;;{ME})(XA;;FA;;;WD;(Member_of {{SID(BA)}}))"),
            // Another user owns it, so they can let themselves in.
            format!("O:S-1-5-21-1-2-3-1002D:P(A;;FA;;;{ME})"),
            format!("O:WDD:P(A;;FA;;;{ME})"),
            format!("D:P(A;;FA;;;{ME})"),
            format!("O:{ME}D:NO_ACCESS_CONTROL"),
            format!("O:{ME}"),
            String::new(),
            format!("O:{ME}D:P(A;;FA;;;{ME}"),
            format!("O:{ME}D:P(A;;FA)"),
        ] {
            assert!(!acl_lets_in_only(&open, ME), "{open}");
        }
    }

    /// The bug this catches: a folder `make install` or an older install left open to others taken
    /// as the agent's private folder because it was already there. What's made inside would then be
    /// open to them too, as it inherits the folder's access on Windows.
    #[test]
    fn a_folder_made_private_is_private_even_if_it_was_there_open() {
        let directory =
            std::env::temp_dir().join(format!("splint-open-dir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        widen(&directory);
        assert!(others_can_open(&directory).unwrap());
        make_private_dir(&directory).unwrap();
        assert!(!others_can_open(&directory).unwrap());
        fs::remove_dir_all(&directory).unwrap();
    }

    /// The bug this catches: a file or folder made through here that someone else could open, as one
    /// made in a folder that lets them in and restricted only afterwards, so a handle they opened in
    /// between stays theirs, or a folder `create_dir_all` made on the way to the last one. Or a file
    /// widened later taken as still private. Unix's modes are set as each is made, so this is for the
    /// calls into Windows.
    #[cfg(windows)]
    #[test]
    fn what_is_made_here_is_private_from_the_start_and_a_widened_one_is_seen() {
        let directory = std::env::temp_dir().join(format!("splint-private-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        widen(&directory);
        let folders = directory.join("made").join("inside");
        create_dir_all(&folders).unwrap();
        assert!(!others_can_open(&directory.join("made")).unwrap());
        assert!(!others_can_open(&folders).unwrap());

        // Before anything restricts it.
        let fresh = directory.join("fresh");
        assert!(windows::create_private_file(&fresh).unwrap());
        assert!(!others_can_open(&fresh).unwrap());

        let path = directory.join("secret");
        let new_file = || open(OpenOptions::new().write(true).create_new(true), &path);
        new_file().unwrap();
        assert!(!others_can_open(&path).unwrap());
        assert_eq!(
            new_file().map(|_| ()).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );

        widen(&path);
        assert!(others_can_open(&path).unwrap());
        restrict(&path).unwrap();
        assert!(!others_can_open(&path).unwrap());
        fs::remove_dir_all(&directory).unwrap();
    }

    /// Everyone may read it, and a folder's access passes to what's made inside, as a person widening
    /// it with icacls would.
    #[cfg(windows)]
    fn widen(path: &Path) {
        let grant = if path.is_dir() {
            "*S-1-1-0:(OI)(CI)F"
        } else {
            "*S-1-1-0:R"
        };
        let done = std::process::Command::new("icacls")
            .arg(path)
            .args(["/grant", grant])
            .output()
            .unwrap();
        assert!(done.status.success());
    }

    /// Everyone may read and list it, as a umask of 022 leaves a folder.
    #[cfg(unix)]
    fn widen(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

//! A named pipe only this user can open, kept theirs for as long as a program serves it, and how a
//! client tells that program still serves it before it sends anything. Signet's pipe and Splint on
//! the computer's both go through this, so the two can't drift.
//!
//! Windows has no private folder for a pipe: every pipe's name is in one list any user can read, and
//! while nothing serves a name, any user can make a pipe with it and hear what a client sends there.
//! So the serving program takes the name as its first instance, refused if anything has it, keeps an
//! instance waiting for as long as it runs, and only then holds a lock file open with no write sharing.
//! A client sends only while that file can't be opened to write: then the name is the program's.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

use super::windows::private_pipe;

/// What Windows says when the name is taken and this is to be its first instance.
const ACCESS_DENIED: i32 = 5;
/// ERROR_PIPE_BUSY, which a first instance gets only when whatever has the name allowed it no more
/// instances than it has: taken, as surely as with [`ACCESS_DENIED`].
const PIPE_BUSY: i32 = 231;
/// FILE_SHARE_READ: others may read the lock, and may not open it to write.
const READ_ONLY_SHARING: u32 = 0x1;
/// ERROR_SHARING_VIOLATION, as the serving program has the lock open.
const SHARING_VIOLATION: i32 = 32;

/// A pipe's instances, one always waiting, so the name stays this program's while it runs.
pub struct PrivatePipe {
    name: OsString,
    waiting: NamedPipeServer,
}

impl PrivatePipe {
    /// The first instance, refused with `AddrInUse` if anything has the name: another copy of the
    /// program, or another program waiting for clients to send it what they'd send this one.
    pub fn first(name: OsString) -> io::Result<Self> {
        let waiting = private_pipe(ServerOptions::new().first_pipe_instance(true), &name).map_err(
            |error| {
                if matches!(error.raw_os_error(), Some(ACCESS_DENIED | PIPE_BUSY)) {
                    io::Error::new(io::ErrorKind::AddrInUse, "the pipe's name is taken")
                } else {
                    error
                }
            },
        )?;
        Ok(Self { name, waiting })
    }

    /// The next connected instance. The one after it is made before this is handed over, so there's
    /// never a moment with none and the name free.
    pub async fn accept(&mut self) -> io::Result<NamedPipeServer> {
        self.waiting.connect().await?;
        let next = private_pipe(&ServerOptions::new(), &self.name)?;
        Ok(std::mem::replace(&mut self.waiting, next))
    }

    pub fn name(&self) -> &OsStr {
        &self.name
    }
}

/// Opens `lock`, made private if it's new, so nothing else can open it to write for as long as the
/// file is kept: what [`is_held`] looks for. Taken only once the pipe's first instance is made, as a
/// client that sees it held sends at once. A second copy's open fails with a sharing violation.
pub fn hold(lock: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).write(true);
    options.share_mode(READ_ONLY_SHARING);
    super::open(&mut options, lock)
}

/// Whether the program serving a pipe holds its lock: it keeps the file open so nothing else can open
/// it to write, and lets go only when it stops. A lock file that isn't there is a program that never
/// started.
pub fn is_held(lock: &Path) -> bool {
    match OpenOptions::new().write(true).open(lock) {
        Ok(_) => false,
        Err(error) => error.raw_os_error() == Some(SHARING_VIOLATION),
    }
}

/// Whether a failed [`hold`] was another copy holding it already.
pub fn held_elsewhere(error: &io::Error) -> bool {
    error.raw_os_error() == Some(SHARING_VIOLATION)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this catches: a pipe made with Windows's default access, which lets everyone read from
    /// it, or with an entry or owner that lets another user in to hear what's sent or add an instance.
    /// Windows keeps one security descriptor per pipe name, set by its first instance, so later
    /// instances have the same access and checking the first is checking them all.
    #[tokio::test]
    async fn only_this_user_can_open_the_pipe() {
        let name = OsString::from(format!(
            r"\\.\pipe\splint-pipe-acl-test-{}",
            std::process::id()
        ));
        let _pipe = PrivatePipe::first(name.clone()).unwrap();
        assert!(!super::super::others_can_open(Path::new(&name)).unwrap());
    }

    /// The bug this catches: a program that took the name first and allowed it one instance makes
    /// Windows refuse the first instance as busy rather than denied, which was shown to the person as
    /// "all pipe instances are busy" rather than that another program has the pipe.
    #[tokio::test]
    async fn a_name_taken_with_one_instance_is_in_use() {
        let name = OsString::from(format!(
            r"\\.\pipe\splint-pipe-busy-test-{}",
            std::process::id()
        ));
        let _squatter = ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(1)
            .create(&name)
            .unwrap();
        let refused = PrivatePipe::first(name).err().unwrap();
        assert_eq!(refused.kind(), io::ErrorKind::AddrInUse);
    }
}

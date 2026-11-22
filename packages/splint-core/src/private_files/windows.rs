//! The one place Splint calls Windows's own API, for who may open a file, a folder or a pipe,
//! which the standard library has no way to say. Each call crosses into C, so each is `unsafe`, and
//! this module and the Mac security chip's bridge in owner-key are the only ones allowed to be:
//! tools/checks/check_repo_rules.py refuses `unsafe` in any other file. Nothing here reads, holds
//! or passes a key. What it builds is text Windows parses, an ACL naming this user alone, so the code
//! that decides what's private stays in safe Rust.

#![allow(unsafe_code)]

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Console::FreeConsole;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Memory Windows handed back, freed once with `LocalFree`.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Windows call that says to free it with LocalFree, and
        // nothing else frees it.
        unsafe { LocalFree(self.0) };
    }
}

/// A handle Windows opened, closed once when dropped.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: an open handle, from OpenProcessToken or CreateFileW, closed only here.
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// A zero-ended string of UTF-16 from Windows, as Rust text.
///
/// # Safety
/// `text` points at a zero-ended UTF-16 string that stays alive for the call.
unsafe fn from_wide(text: *const u16) -> String {
    let mut len = 0;
    // SAFETY: the string is zero-ended, so every unit up to and including the zero can be read.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the zero were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
}

fn failed() -> io::Error {
    io::Error::last_os_error()
}

/// This user's security ID, as text such as `S-1-5-21-…-1001`, which an ACL names them by.
pub fn current_user() -> io::Result<String> {
    let mut handle: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess gives a handle that needs no closing, and `handle` is written only on
    // success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
        return Err(failed());
    }
    let token = Handle(handle);
    let mut needed = 0_u32;
    // SAFETY: an empty buffer only asks how big it has to be, which fails by design.
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
    // Of u64s, so it's aligned for TOKEN_USER, which holds a pointer.
    let mut buffer = vec![
        0_u64;
        usize::try_from(needed)
            .map_err(io::Error::other)?
            .div_ceil(8)
    ];
    let size = u32::try_from(buffer.len() * 8).map_err(io::Error::other)?;
    // SAFETY: the buffer is `size` bytes, writable and aligned.
    let got = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut needed,
        )
    };
    if got == 0 {
        return Err(failed());
    }
    // SAFETY: Windows wrote a TOKEN_USER at the start, and its SID points into the same buffer, which
    // outlives this.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text = ptr::null_mut();
    // SAFETY: `sid` is valid, and `text` is written only on success.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(failed());
    }
    let _free = Local(text.cast());
    // SAFETY: Windows gave a zero-ended string, freed only when `_free` goes.
    Ok(unsafe { from_wide(text) })
}

/// A security descriptor Windows parsed from SDDL, freed when dropped.
struct Descriptor(Local);

impl Descriptor {
    fn parse(sddl: &str) -> io::Result<Self> {
        let text = wide(OsStr::new(sddl));
        let mut descriptor = ptr::null_mut();
        // SAFETY: `text` is zero-ended, and `descriptor` is written only on success.
        let done = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if done == 0 {
            return Err(failed());
        }
        Ok(Self(Local(descriptor)))
    }
}

/// An ACL naming this user alone, and nothing inherited from above. A folder's passes to what's made
/// inside it.
fn only_this_user(folder: bool) -> io::Result<Descriptor> {
    let user = current_user()?;
    let inherited = if folder { "OICI" } else { "" };
    Descriptor::parse(&format!("D:P(A;{inherited};FA;;;{user})"))
}

/// That ACL, for Windows to give something as it makes it, so it's private from the moment it's there
/// rather than once it's restricted: another user who opened it in between would keep what they
/// opened.
struct Private {
    attributes: SECURITY_ATTRIBUTES,
    /// What `attributes` points to, kept alive with it.
    _descriptor: Descriptor,
}

impl Private {
    fn new(folder: bool) -> io::Result<Self> {
        let descriptor = only_this_user(folder)?;
        Ok(Self {
            attributes: SECURITY_ATTRIBUTES {
                nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                    .map_err(io::Error::other)?,
                lpSecurityDescriptor: descriptor.0.0,
                bInheritHandle: 0,
            },
            _descriptor: descriptor,
        })
    }
}

/// Makes an empty file at `path` that only this user can open from the start. False, with nothing
/// changed, if something is there already.
pub fn create_private_file(path: &Path) -> io::Result<bool> {
    let private = Private::new(false)?;
    let name = wide(path.as_os_str());
    // SAFETY: `name` is zero-ended, and the attributes and the descriptor they point to live until this
    // returns. Windows copies the ACL into the file.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &private.attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = failed();
        return match error.kind() {
            io::ErrorKind::AlreadyExists => Ok(false),
            _ => Err(error),
        };
    }
    drop(Handle(handle));
    Ok(true)
}

/// Makes exactly the folder at `path`, which only this user can open from the start, and what's made
/// inside it after. Fails if anything is there already.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let private = Private::new(true)?;
    let name = wide(path.as_os_str());
    // SAFETY: `name` is zero-ended, and the attributes and the descriptor they point to live until this
    // returns. Windows copies the ACL into the folder.
    if unsafe { CreateDirectoryW(name.as_ptr(), &private.attributes) } == 0 {
        return Err(failed());
    }
    Ok(())
}

/// Gives what's at `path` an ACL naming this user alone, and nothing inherited from above. A folder's
/// passes to what's made inside it.
pub fn restrict(path: &Path, folder: bool) -> io::Result<()> {
    let descriptor = only_this_user(folder)?;
    let (mut present, mut defaulted) = (0, 0);
    let mut acl = ptr::null_mut();
    // SAFETY: the descriptor is valid, and the ACL it gives points into it, which outlives its use.
    let got = unsafe {
        GetSecurityDescriptorDacl(descriptor.0.0, &mut present, &mut acl, &mut defaulted)
    };
    if got == 0 || present == 0 {
        return Err(io::Error::other("Windows didn't make the ACL"));
    }
    let name = wide(path.as_os_str());
    // SAFETY: `name` is zero-ended and `acl` is valid; no owner, group or audit list is changed.
    let done = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if done != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(done).unwrap_or(i32::MAX),
        ));
    }
    Ok(())
}

/// The owner and ACL of what's at `path`, as SDDL, and this user's ID as that SDDL names them, for safe
/// code to read. The owner counts, as Windows lets an owner change the ACL whatever it says.
pub fn acl_of(path: &Path) -> io::Result<(String, String)> {
    let name = wide(path.as_os_str());
    let mut descriptor = ptr::null_mut();
    // SAFETY: `name` is zero-ended; only the descriptor is asked for, written only on success.
    let done = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if done != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(done).unwrap_or(i32::MAX),
        ));
    }
    let descriptor = Local(descriptor);
    let acl = sddl_of(
        &descriptor,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    )?;
    Ok((acl, user_as_sddl_names()?))
}

/// This user as SDDL writes them. SDDL gives some accounts a short name in place of their ID, such
/// as `LA` for the machine's built-in administrator, the account a cloud machine's first user often
/// is, so an ACL naming them alone would otherwise read as naming someone else.
fn user_as_sddl_names() -> io::Result<String> {
    let owner = Descriptor::parse(&format!("O:{}", current_user()?))?;
    let text = sddl_of(&owner.0, OWNER_SECURITY_INFORMATION)?;
    text.strip_prefix("O:")
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("Windows wrote an owner it didn't name"))
}

/// The parts of a security descriptor that `info` asks for, as SDDL.
fn sddl_of(descriptor: &Local, info: OBJECT_SECURITY_INFORMATION) -> io::Result<String> {
    let mut text = ptr::null_mut();
    // SAFETY: the descriptor is valid while `descriptor` lives, and `text` is written only on
    // success.
    let done = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            info,
            &mut text,
            ptr::null_mut(),
        )
    };
    if done == 0 {
        return Err(failed());
    }
    let _free = Local(text.cast());
    // SAFETY: Windows gave a zero-ended string, freed only when `_free` goes.
    Ok(unsafe { from_wide(text) })
}

/// One instance of a named pipe that only this user can open or add instances to, owned by them even
/// in a process run as administrator. Windows's default would let everyone read from it.
pub fn private_pipe(options: &ServerOptions, name: &OsStr) -> io::Result<NamedPipeServer> {
    let user = current_user()?;
    let descriptor = Descriptor::parse(&format!("O:{user}D:P(A;;GA;;;{user})"))?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` and the descriptor it points to are valid until this returns, and Windows
    // copies what it needs into the pipe.
    unsafe {
        options.create_with_security_attributes_raw(name, (&raw mut attributes).cast::<c_void>())
    }
}

/// Lets go of the console window a program started at login opens for it, so nothing stays on the
/// person's screen. One with no console has nothing to let go of.
pub fn leave_console() {
    // SAFETY: takes no arguments, and failing only means there was no console.
    unsafe { FreeConsole() };
}

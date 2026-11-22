//! Where Signet's API listens: a Unix socket in a folder only this user can open, or on Windows a
//! named pipe only this user can open.
//!
//! The API carries the agent's token and the owner's. On a loopback port, any program on this machine,
//! another user's included, could take the port while Signet was stopped and hear whatever a client
//! sent there. A socket in a private folder can't be reached by another user at all, and a client that
//! finds no Signet there sends nothing. TCP stays as a setting, off unless set, for an agent that can't
//! reach a socket, such as one in another container, and it's warned of whenever it's on.
//!
//! Windows has no private folder for a pipe: every pipe's name is in one list any user can read. So
//! this Signet's pipe lets only its own user open it or add an instance, and takes the name before it
//! takes its folder's lock, keeping an instance waiting for as long as it runs. A client sends only
//! while that lock is held, so a pipe another user made while Signet was stopped hears nothing.

use std::env;
use std::fmt;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use axum::Router;
#[cfg(unix)]
use splint_core::private_files;
use splint_core::transport::Scheme;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;

/// Where a client finds the socket, so only this user's programs can open it.
pub const SOCKET_SETTING: &str = "SPLINT_LISTEN_SOCKET";
/// The loopback port, which weakens that, so it's only for an agent that can't reach the socket.
pub const TCP_SETTING: &str = "SPLINT_LISTEN";

#[derive(thiserror::Error)]
pub enum Refused {
    #[error("set {SOCKET_SETTING} to where this Signet listens")]
    NowhereToListen,
    #[cfg(windows)]
    #[error("{SOCKET_SETTING} must name a pipe, such as \\\\.\\pipe\\splint-signet")]
    NotAPipe,
    #[cfg(unix)]
    #[error(
        "Signet's socket folder {0} can be opened by other users: make it 0700, then start again"
    )]
    FolderOpen(PathBuf),
    #[cfg(unix)]
    #[error("Signet's socket {0} has no folder")]
    NoFolder(PathBuf),
    #[error("something is already listening on {0}: stop it, then start this Signet")]
    InUse(PathBuf),
    #[cfg(unix)]
    #[error("{0} is in the way of Signet's socket and isn't one")]
    InTheWay(PathBuf),
}

/// `main` prints what it returns with `Debug`, and the log should read as the reason.
impl fmt::Debug for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Where this Signet is to listen, checked as it starts, before it does anything else. On Windows
/// the pipe's first instance is made then too, so its name is this Signet's from the start.
pub struct Where {
    #[cfg(unix)]
    socket: Option<PathBuf>,
    #[cfg(windows)]
    socket: Option<pipe::PipeListener>,
    tcp: Option<String>,
}

impl Where {
    pub fn from_env(scheme: Scheme) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = env::var_os(SOCKET_SETTING).map(PathBuf::from);
        let tcp = env::var(TCP_SETTING).ok();
        if socket.is_none() && tcp.is_none() {
            return Err(Refused::NowhereToListen.into());
        }
        #[cfg(unix)]
        if let Some(path) = &socket {
            private_folder_of(path)?;
        }
        #[cfg(windows)]
        let socket = match socket {
            Some(name) => Some(pipe::PipeListener::first(name.into_os_string())?),
            None => None,
        };
        if let Some(listen) = &tcp {
            scheme.check_listen_address(listen)?;
            tracing::warn!(
                "{TCP_SETTING} serves this agent's API on a port, where any program that takes it \
                 while Signet is stopped hears the tokens sent to it: use {SOCKET_SETTING} unless \
                 the agent can't reach a socket"
            );
        }
        Ok(Self { socket, tcp })
    }

    /// The socket's folder is checked again, as it may have changed since.
    pub async fn bind(self) -> Result<Listening, Box<dyn std::error::Error>> {
        #[cfg(unix)]
        let socket = match &self.socket {
            Some(path) => Some(bind_private(path)?),
            None => None,
        };
        #[cfg(windows)]
        let socket = self.socket;
        let tcp = match self.tcp {
            Some(listen) => Some(TcpListener::bind(listen).await?),
            None => None,
        };
        Ok(Listening { socket, tcp })
    }
}

/// What this Signet listens on.
pub struct Listening {
    #[cfg(unix)]
    socket: Option<UnixListener>,
    #[cfg(windows)]
    socket: Option<pipe::PipeListener>,
    tcp: Option<TcpListener>,
}

impl Listening {
    pub async fn serve(self, api: Router) -> std::io::Result<()> {
        let socket = async {
            match self.socket {
                Some(listener) => axum::serve(listener, api.clone()).await,
                None => std::future::pending().await,
            }
        };
        let tcp = async {
            match self.tcp {
                Some(listener) => axum::serve(listener, api.clone()).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            done = socket => done,
            done = tcp => done,
        }
    }
}

/// Another user who could open the folder could connect to the socket, or put their own in its place.
#[cfg(unix)]
fn private_folder_of(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let folder = path
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty())
        .ok_or_else(|| Refused::NoFolder(path.to_owned()))?;
    let found = fs::metadata(folder)?;
    if !found.is_dir() || private_files::others_can_open(folder)? {
        return Err(Refused::FolderOpen(folder.to_owned()).into());
    }
    Ok(())
}

#[cfg(unix)]
fn bind_private(path: &Path) -> Result<UnixListener, Box<dyn std::error::Error>> {
    private_folder_of(path)?;
    clear_stale(path)?;
    let listener = UnixListener::bind(path)?;
    // Nobody else can reach it through its folder anyway. This holds if the folder is ever opened.
    private_files::restrict(path)?;
    Ok(listener)
}

/// A socket left by a Signet that stopped, which nothing answers on. One something answers on is
/// another program's, as this Signet holds its folder's lock, so it's left alone.
#[cfg(unix)]
fn clear_stale(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let found = match fs::symlink_metadata(path) {
        Ok(found) => found,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !found.file_type().is_socket() {
        return Err(Refused::InTheWay(path.to_owned()).into());
    }
    if UnixStream::connect(path).is_ok() {
        return Err(Refused::InUse(path.to_owned()).into());
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(windows)]
mod pipe {
    use std::ffi::OsString;
    use std::io;
    use std::time::Duration;

    use splint_core::private_files::pipe::PrivatePipe;
    use tokio::net::windows::named_pipe::NamedPipeServer;

    use super::Refused;

    const PIPE_PREFIX: &str = r"\\.\pipe\";
    /// After a failed accept, such as instances running out, before trying again.
    const RETRY: Duration = Duration::from_millis(100);

    /// Signet's pipe, made only as `splint_core::private_files::pipe` makes one, so it's the same as
    /// Splint on the computer's.
    pub struct PipeListener(PrivatePipe);

    impl PipeListener {
        /// The first instance, refused if anything has the name: another Signet, or another program
        /// waiting for clients to send it what they'd send Signet.
        pub fn first(name: OsString) -> Result<Self, Box<dyn std::error::Error>> {
            let text = name.to_string_lossy();
            let rest = text
                .get(..PIPE_PREFIX.len())
                .filter(|prefix| prefix.eq_ignore_ascii_case(PIPE_PREFIX))
                .and_then(|_| text.get(PIPE_PREFIX.len()..));
            if rest.is_none_or(str::is_empty) {
                return Err(Refused::NotAPipe.into());
            }
            match PrivatePipe::first(name.clone()) {
                Ok(pipe) => Ok(Self(pipe)),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    Err(Refused::InUse(name.into()).into())
                }
                Err(error) => Err(error.into()),
            }
        }
    }

    impl axum::serve::Listener for PipeListener {
        type Io = NamedPipeServer;
        type Addr = String;

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            loop {
                match self.0.accept().await {
                    Ok(connected) => {
                        return (connected, self.0.name().to_string_lossy().into_owned());
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Signet's pipe couldn't take a connection");
                        tokio::time::sleep(RETRY).await;
                    }
                }
            }
        }

        fn local_addr(&self) -> io::Result<Self::Addr> {
            Ok(self.0.name().to_string_lossy().into_owned())
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// The bug this catches: a Signet starting on a pipe name something else already serves, where
    /// that program would go on hearing what clients send this Signet.
    #[tokio::test]
    async fn a_pipe_name_already_served_is_refused() {
        let name = std::ffi::OsString::from(format!(
            r"\\.\pipe\splint-signet-test-{}",
            std::process::id()
        ));
        let _first = pipe::PipeListener::first(name.clone()).unwrap();
        let second = pipe::PipeListener::first(name).err().unwrap();
        assert!(matches!(
            second.downcast_ref::<Refused>(),
            Some(Refused::InUse(_))
        ));
    }
}

//! On Windows, where Signet and Splint on the computer serve their APIs on named pipes: sending down
//! one only while the program that should serve it holds its lock, and serving one. Both are made
//! only by `splint_core::private_files::pipe`, so Signet's and the computer's can't drift.

use std::fs::File;
use std::io::{self, Write as _};
use std::path::Path;
use std::time::Duration;

use reqwest::{RequestBuilder, Response};
use splint_core::private_files::pipe::{PrivatePipe, is_held};
use tokio::net::windows::named_pipe::NamedPipeServer;

/// When every instance of a pipe is busy for a moment, how often and how long to try again.
const BUSY_RETRY: (Duration, u32) = (Duration::from_millis(50), 20);
/// After a failed accept, such as instances running out, before trying again.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Sends one call down a pipe, only while `lock` is held: any user can make a pipe with that name
/// while its program is stopped, and while it runs no other user can make an instance. A pipe with
/// every instance busy for a moment is tried again, as the program makes the next one at once. `None`
/// is a call that surely never reached the program.
pub async fn send_while_served(
    lock: &Path,
    call: RequestBuilder,
) -> Result<Response, Option<reqwest::Error>> {
    let (wait, tries) = BUSY_RETRY;
    for _ in 0..tries {
        if !is_held(lock) {
            return Err(None);
        }
        let Some(call) = call.try_clone() else {
            return Err(None);
        };
        match call.send().await {
            Ok(response) => return Ok(response),
            Err(error) if error.is_connect() => tokio::time::sleep(wait).await,
            Err(error) => return Err(Some(error)),
        }
    }
    Err(None)
}

/// A private pipe served by axum, with the lock that tells clients it's served, so the lock goes only
/// when the pipe does, and saying in the keeper's log when it can't take a connection.
pub struct Served {
    pipe: PrivatePipe,
    _held: File,
}

impl Served {
    /// `held` is the lock taken by `pipe::hold`, only once `pipe` is this program's.
    pub fn new(pipe: PrivatePipe, held: File) -> Self {
        Self { pipe, _held: held }
    }
}

impl axum::serve::Listener for Served {
    type Io = NamedPipeServer;
    type Addr = String;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.pipe.accept().await {
                Ok(connected) => {
                    return (connected, self.pipe.name().to_string_lossy().into_owned());
                }
                Err(error) => {
                    let _ = writeln!(
                        io::stderr(),
                        "a pipe couldn't take a connection, so it tries again: {error}"
                    );
                    tokio::time::sleep(ACCEPT_RETRY).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.pipe.name().to_string_lossy().into_owned())
    }
}

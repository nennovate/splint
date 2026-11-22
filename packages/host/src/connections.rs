//! Takes connections for a host, so idle or slow callers can't use up what it has.
//!
//! Nothing here reads a request. It caps how many connections are open, keeping files back for the
//! database and for delivery, and closes a connection that isn't getting on with a request. Bytes
//! arriving start a request's clock and only an answer stops it, so sending one byte at a time buys
//! nothing. Who holds how many is the proxy's and the firewall's to limit: everything reaching a real
//! host comes from its proxy, on loopback, so only the proxy knows the caller.
//!
//! It also caps what one connection reads ahead of the call that takes it. Left alone that grows to
//! 400 KB on a connection that has carried one large body and stays until it closes, so callers could
//! make a host hold that for every connection it has, with none of it counted as a body.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

/// Pausing when the process is out of files gives other connections time to finish.
const PAUSE_AFTER_ACCEPT_ERROR: Duration = Duration::from_millis(100);
/// If the limit can't be read, this is the lowest any system here starts with.
const ASSUMED_FILE_LIMIT: u64 = 256;
/// For everything but callers: the database, peers being delivered to, the key and logs.
const FILES_KEPT_BACK: u64 = 128;
/// Past what a call can take: its body's deadline and its own, so those are what a caller hears from.
const REQUEST_DEADLINE: Duration = Duration::from_secs(45);
/// Longer than the proxy keeps an idle connection, so it's the proxy that closes one it's about to use.
const IDLE_DEADLINE: Duration = Duration::from_secs(75);
/// What a connection reads ahead of the call taking it, which is also the longest a request's first
/// line and headers can be. A caller's are a few hundred bytes and a browser's a few thousand.
const MAX_READ_AHEAD: usize = 16 * 1024;

#[derive(Clone, Copy)]
struct Deadlines {
    /// From a request's first byte to its answer, and from connecting to that first byte.
    request: Duration,
    /// How long a connection can wait for its next request after an answer.
    idle: Duration,
}

/// How many connections this process can really hold, after raising its file limit as far as it's
/// allowed. A flood of callers then can't stop it reaching its database or sending what it has queued.
pub fn within_file_limit(wanted: u32) -> usize {
    let limit = rlimit::increase_nofile_limit(u64::MAX).unwrap_or(ASSUMED_FILE_LIMIT);
    fit_to_files(wanted, limit)
}

fn fit_to_files(wanted: u32, file_limit: u64) -> usize {
    let wanted = usize::try_from(wanted).unwrap_or(usize::MAX);
    let room = usize::try_from(file_limit.saturating_sub(FILES_KEPT_BACK)).unwrap_or(usize::MAX);
    if room < wanted {
        tracing::warn!(
            room,
            wanted,
            "the file limit leaves room for fewer connections than planned"
        );
    }
    room.min(wanted).max(1)
}

pub struct GuardedListener {
    inner: TcpListener,
    deadlines: Deadlines,
    total: Arc<Semaphore>,
}

impl GuardedListener {
    pub fn new(inner: TcpListener, connections: usize) -> Self {
        Self::with_deadlines(
            inner,
            connections,
            Deadlines {
                request: REQUEST_DEADLINE,
                idle: IDLE_DEADLINE,
            },
        )
    }

    fn with_deadlines(inner: TcpListener, connections: usize, deadlines: Deadlines) -> Self {
        Self {
            inner,
            deadlines,
            total: Arc::new(Semaphore::new(connections)),
        }
    }
}

impl GuardedListener {
    async fn accept(&mut self) -> GuardedStream<TcpStream> {
        loop {
            match self.inner.accept().await {
                Ok((stream, _)) => {
                    // Dropping the stream closes it, and a caller at the limit gets nothing else.
                    if let Ok(slot) = self.total.clone().try_acquire_owned() {
                        return GuardedStream::new(stream, slot, self.deadlines);
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "couldn't accept a connection");
                    tokio::time::sleep(PAUSE_AFTER_ACCEPT_ERROR).await;
                }
            }
        }
    }
}

/// Answers every connection the listener takes, for good. This is `axum::serve` with the one setting
/// it doesn't have: how much a connection reads ahead.
pub async fn serve(mut listener: GuardedListener, app: Router) {
    loop {
        let stream = listener.accept().await;
        let calls = TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let mut server = Builder::new(TokioExecutor::new());
            server.http1().max_buf_size(MAX_READ_AHEAD);
            // What ends a connection is its caller hanging up, a deadline, or bytes that aren't a
            // request, and none of those is this host's to act on.
            let _ = server.serve_connection(TokioIo::new(stream), calls).await;
        });
    }
}

#[derive(PartialEq, Eq)]
enum Phase {
    WaitingForARequest,
    InARequest,
}

pub struct GuardedStream<S> {
    inner: S,
    deadline: Pin<Box<Sleep>>,
    phase: Phase,
    deadlines: Deadlines,
    _slot: OwnedSemaphorePermit,
}

impl<S> GuardedStream<S> {
    fn new(inner: S, slot: OwnedSemaphorePermit, deadlines: Deadlines) -> Self {
        Self {
            inner,
            deadline: Box::pin(tokio::time::sleep(deadlines.request)),
            phase: Phase::WaitingForARequest,
            deadlines,
            _slot: slot,
        }
    }

    fn restart_clock(&mut self, allowed: Duration) {
        self.deadline.as_mut().reset(Instant::now() + allowed);
    }

    /// Pending until the deadline, and registers for a wake then, so a silent connection still ends.
    fn out_of_time<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        ready!(self.deadline.as_mut().poll(cx));
        Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GuardedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before && this.phase == Phase::WaitingForARequest {
                    this.phase = Phase::InARequest;
                    this.restart_clock(this.deadlines.request);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => this.out_of_time(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GuardedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, data) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.phase = Phase::WaitingForARequest;
                    this.restart_clock(this.deadlines.idle);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => this.out_of_time(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, data) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.phase = Phase::WaitingForARequest;
                    this.restart_clock(this.deadlines.idle);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => this.out_of_time(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => this.out_of_time(cx),
            done => done,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => this.out_of_time(cx),
            done => done,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream as BlockingStream};

    use axum::routing::{get, post};

    use super::*;

    const DEADLINE: Duration = Duration::from_millis(300);
    const REQUEST: &[u8] = b"GET /fast HTTP/1.1\r\nHost: x\r\n\r\n";
    const PLENTY: Duration = Duration::from_secs(5);

    fn quick() -> Deadlines {
        Deadlines {
            request: DEADLINE,
            idle: DEADLINE,
        }
    }

    async fn serving(connections: usize, deadlines: Deadlines) -> SocketAddr {
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = inner.local_addr().unwrap();
        let app = Router::new()
            .route("/fast", get(|| async { "answered" }))
            .route("/upload", post(|_: String| async { "taken" }));
        tokio::spawn(serve(
            GuardedListener::with_deadlines(inner, connections, deadlines),
            app,
        ));
        address
    }

    /// Everything until the other side hangs up, and how long that took.
    fn read_to_close(mut stream: BlockingStream) -> (Vec<u8>, Duration) {
        // This fails only on a socket already closed, and the read then ends at once anyway.
        let _ = stream.set_read_timeout(Some(PLENTY));
        let started = std::time::Instant::now();
        let mut everything = Vec::new();
        let _ = stream.read_to_end(&mut everything);
        (everything, started.elapsed())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_connection_that_never_sends_anything_is_closed() {
        let address = serving(8, quick()).await;
        tokio::task::spawn_blocking(move || {
            let (_, took) = read_to_close(BlockingStream::connect(address).unwrap());
            assert!(took >= DEADLINE / 2 && took < PLENTY, "{took:?}");
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sending_a_request_a_byte_at_a_time_buys_no_extra_time() {
        let address = serving(8, quick()).await;
        tokio::task::spawn_blocking(move || {
            let mut stream = BlockingStream::connect(address).unwrap();
            let started = std::time::Instant::now();
            for byte in b"GET /fast HTTP/1.1\r\nHost: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(DEADLINE / 5);
            }
            let (answer, _) = read_to_close(stream);
            assert!(started.elapsed() < DEADLINE * 8, "{:?}", started.elapsed());
            assert!(
                !answer.starts_with(b"HTTP/1.1 200"),
                "it was never a whole request"
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_body_that_stops_coming_is_closed() {
        let address = serving(8, quick()).await;
        tokio::task::spawn_blocking(move || {
            let mut stream = BlockingStream::connect(address).unwrap();
            stream
                .write_all(b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npart")
                .unwrap();
            let (_, took) = read_to_close(stream);
            assert!(took < PLENTY, "{took:?}");
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_connection_in_use_goes_on_past_the_deadline_and_a_request_after_idling_gets_its_own()
    {
        let address = serving(8, quick()).await;
        tokio::task::spawn_blocking(move || {
            let mut stream = BlockingStream::connect(address).unwrap();
            stream.set_read_timeout(Some(PLENTY)).unwrap();
            for _ in 0..4 {
                stream.write_all(REQUEST).unwrap();
                let mut answer = [0; 512];
                let read = stream.read(&mut answer).unwrap();
                assert!(answer.get(..read).unwrap().starts_with(b"HTTP/1.1 200"));
                std::thread::sleep(DEADLINE * 2 / 3);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn past_the_total_a_new_connection_is_closed_and_a_slot_comes_back() {
        let generous = Deadlines {
            request: PLENTY,
            idle: PLENTY,
        };
        let address = serving(2, generous).await;
        tokio::task::spawn_blocking(move || {
            let first = BlockingStream::connect(address).unwrap();
            let second = BlockingStream::connect(address).unwrap();
            // Let the server accept both, in order, before asking for a third.
            std::thread::sleep(DEADLINE);
            let (_, took) = read_to_close(BlockingStream::connect(address).unwrap());
            assert!(
                took < PLENTY / 2,
                "it should be closed at once, took {took:?}"
            );
            drop((first, second));
            std::thread::sleep(DEADLINE);
            let mut again = BlockingStream::connect(address).unwrap();
            again.write_all(REQUEST).unwrap();
            again.set_read_timeout(Some(PLENTY)).unwrap();
            let mut answer = [0; 512];
            let read = again.read(&mut answer).unwrap();
            assert!(answer.get(..read).unwrap().starts_with(b"HTTP/1.1 200"));
        })
        .await
        .unwrap();
    }

    #[test]
    fn files_are_kept_back_for_everything_but_callers() {
        assert_eq!(fit_to_files(2048, 65_536), 2048);
        assert_eq!(fit_to_files(2048, 1024), 1024 - 128);
        assert_eq!(fit_to_files(2048, 64), 1, "it still answers someone");
    }
}

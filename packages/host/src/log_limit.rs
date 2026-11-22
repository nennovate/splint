//! Keeps a warning anyone can cause to one line a minute.
//!
//! A refusal anyone can bring about, as often as their call limit lets them, would otherwise be a line
//! each. Enough of those make the system's log drop lines, and a host's other warnings with them.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const EVERY: Duration = Duration::from_secs(60);

pub struct LogLimit {
    windows: Mutex<BTreeMap<String, Window>>,
}

struct Window {
    logged_at: Instant,
    unlogged: u64,
}

impl LogLimit {
    pub const fn new() -> Self {
        Self {
            windows: Mutex::new(BTreeMap::new()),
        }
    }

    /// How many there have been since the last line, this one included, when it's time for another.
    pub fn due(&self) -> Option<u64> {
        self.due_for("")
    }

    /// The same for each source a caller can't make up, such as a peer fixed by config or an agent
    /// this host holds, counted apart, so noise from one can't keep another out of the log. Anything
    /// else would let a caller grow the count.
    pub fn due_for(&self, source: &str) -> Option<u64> {
        self.due_at(source, Instant::now())
    }

    fn due_at(&self, source: &str, now: Instant) -> Option<u64> {
        // Nothing here can be left half done, so a panic elsewhere while it was held changes nothing.
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(window) = windows.get_mut(source) else {
            windows.insert(
                source.to_owned(),
                Window {
                    logged_at: now,
                    unlogged: 0,
                },
            );
            return Some(1);
        };
        window.unlogged = window.unlogged.saturating_add(1);
        if now.saturating_duration_since(window.logged_at) < EVERY {
            return None;
        }
        window.logged_at = now;
        Some(std::mem::take(&mut window.unlogged))
    }
}

/// What a test logs while `run` runs on this thread, as text.
///
/// Whether a line is wanted is worked out once for each place that logs, for every thread at once, so
/// a listener set for one thread alone can miss the first line from a place another thread reached
/// first. One listener for the whole process, writing only for a thread that asked, can't.
#[cfg(test)]
pub fn logged<T>(run: impl FnOnce() -> T) -> (T, String) {
    use std::cell::RefCell;
    use std::sync::Once;

    thread_local! {
        static CAPTURED: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    }

    struct ToThisThread;

    impl std::io::Write for ToThisThread {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            CAPTURED.with_borrow_mut(|captured| {
                if let Some(captured) = captured {
                    captured.extend_from_slice(bytes);
                }
            });
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    static LISTENING: Once = Once::new();
    LISTENING.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(|| ToThisThread)
            .finish();
        // Nothing else in these tests sets one.
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
    CAPTURED.set(Some(Vec::new()));
    let result = run();
    let text = CAPTURED.take().unwrap();
    (result, String::from_utf8(text).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flood_is_one_line_a_minute_that_counts_it() {
        let limit = LogLimit::new();
        let start = Instant::now();
        let seconds = EVERY.as_secs();
        assert_eq!(limit.due_at("", start), Some(1));
        for second in 1..seconds {
            assert_eq!(limit.due_at("", start + Duration::from_secs(second)), None);
        }
        assert_eq!(limit.due_at("", start + EVERY), Some(seconds));
        assert_eq!(limit.due_at("", start + EVERY * 3), Some(1));
    }
}

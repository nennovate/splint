//! Limits on what a host holds of its own answers, so callers who read slowly can't run it out of memory.
//!
//! A call's place and its body's room go back when its route returns, which is before its answer is
//! written. A caller who reads slowly, or not at all, leaves the answer here until its connection
//! ends, and one source can hold many connections. So answers have room of their own, in all and from
//! one source, as bodies have in `overload`, and past it a call is told at once to come back.
//!
//! An answer callers can grow is cut into pages of about `PAGE_BYTES`. Its route asks Postgres how
//! long each row is, takes room for the rows that fit, and only then reads them, so nothing large is
//! read for a caller there's no room to answer. Any other answer takes room once it's built, here, on
//! its way out. Those are a fixed size at most, and each is built by a call in progress, which
//! `overload` limits. An answer of `UNCOUNTED_BYTES` or less takes none, a page or not.
//!
//! Whoever fills the room stops readers of anything longer for as long as they hold it. An inbox is
//! what a Signet has to keep reading, and it clears what it took and asks again, so a page of one is
//! cut to the room that's left, and with none left to what takes no room. A row longer than what's
//! left still waits, with what's behind it.
//!
//! Room goes back when the answer's bytes do, not when its route returns: it's kept by the bytes
//! themselves, which a connection holds until it has written the last of them or has gone.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::{Body, Bytes, HttpBody, to_bytes};
use axum::extract::{Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::api_error::ApiError;
use crate::limits::Limits;
use crate::{overload, registry};

/// About what one page holds. Enough for hundreds of ordinary messages, and small enough that a
/// source's share is several pages, so one slow reader doesn't stop the Signets beside it.
pub const PAGE_BYTES: usize = 1024 * 1024;
/// An answer this small takes no room. It's what a connection sets aside for writing anyway, and
/// refusing it would turn a call that did its work into one its caller tries again. It also means
/// that with the room full, a Signet still reads a page of a few ordinary messages.
const UNCOUNTED_BYTES: usize = 16 * 1024;
/// What a row adds to a page beyond what it holds: its field names, quotes and commas.
const ROW_FRAMING_BYTES: usize = 256;

pub struct AnswerRoom {
    in_all: Arc<Semaphore>,
    most: usize,
    per_source: usize,
    /// Only sources holding an answer now, by what `registry::source_of` reads.
    held_by: Mutex<HashMap<String, usize>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Full {
    Source,
    Host,
}

impl From<Full> for ApiError {
    fn from(full: Full) -> Self {
        Self::NoRoomToAnswer(full)
    }
}

impl IntoResponse for Full {
    fn into_response(self) -> Response {
        overload::busy(match self {
            Self::Source => StatusCode::TOO_MANY_REQUESTS,
            Self::Host => StatusCode::SERVICE_UNAVAILABLE,
        })
    }
}

fn as_count(limit: u32) -> usize {
    usize::try_from(limit).unwrap_or(usize::MAX)
}

impl AnswerRoom {
    pub fn new(limits: &Limits) -> Arc<Self> {
        let most = as_count(limits.answer_bytes_at_once);
        Arc::new(Self {
            in_all: Arc::new(Semaphore::new(most)),
            most,
            per_source: as_count(limits.answer_bytes_at_once_per_source),
            held_by: Mutex::new(HashMap::new()),
        })
    }

    /// Room for an answer of this many bytes to whoever these headers say is calling, taken before
    /// any of it is read. A call with no source came from this machine and counts only in all.
    pub fn take(self: &Arc<Self>, headers: &HeaderMap, bytes: usize) -> Result<Taken, Full> {
        self.take_for(registry::source_of(headers), bytes)
    }

    /// How long a page can be for whoever these headers say is calling: a whole one while there's
    /// room for it, and what's left of the room and of its source's share when there's less, so a
    /// reader who clears what it took and asks again is given the part that fits, not told to come
    /// back for all of it. Never less than what takes no room, which always goes. A page's first row
    /// goes in however long, and that one still has to find room.
    pub fn page_budget(&self, headers: &HeaderMap) -> usize {
        let source = registry::source_of(headers);
        let held = self.held_by().get(&source).copied().unwrap_or(0);
        // A source holding nothing isn't held to its share, as `fit` has it.
        let of_share = if held == 0 {
            usize::MAX
        } else {
            self.per_source.saturating_sub(held)
        };
        PAGE_BYTES
            .min(self.in_all.available_permits())
            .min(of_share)
            .max(UNCOUNTED_BYTES)
    }

    fn take_for(self: &Arc<Self>, source: String, bytes: usize) -> Result<Taken, Full> {
        let mut taken = Taken {
            room: Arc::clone(self),
            source,
            bytes: 0,
            in_all: None,
        };
        taken.fit(bytes)?;
        Ok(taken)
    }

    fn held_by(&self) -> std::sync::MutexGuard<'_, HashMap<String, usize>> {
        self.held_by.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What one answer takes of the room, in all and of its source's share, until it's dropped.
pub struct Taken {
    room: Arc<AnswerRoom>,
    source: String,
    bytes: usize,
    in_all: Option<OwnedSemaphorePermit>,
}

impl Taken {
    /// Makes this the room for an answer of `bytes`, more or less than it has. An answer that isn't
    /// cut into pages can be larger than a source's share, or than all the room. One like that still
    /// goes while its source holds nothing else, taking what room there is, or it could never be read.
    fn fit(&mut self, bytes: usize) -> Result<(), Full> {
        let bytes = if bytes <= UNCOUNTED_BYTES { 0 } else { bytes };
        let mut held_by = self.room.held_by();
        let others = held_by
            .get(&self.source)
            .copied()
            .unwrap_or(0)
            .saturating_sub(self.bytes);
        if bytes > 0 && others > 0 && others.saturating_add(bytes) > self.room.per_source {
            return Err(Full::Source);
        }
        let wanted = bytes.min(self.room.most);
        let has = self.in_all.as_ref().map_or(0, |held| held.num_permits());
        if wanted > has {
            let more = u32::try_from(wanted - has).unwrap_or(u32::MAX);
            let more = Arc::clone(&self.room.in_all)
                .try_acquire_many_owned(more)
                .map_err(|_| Full::Host)?;
            match &mut self.in_all {
                Some(held) => held.merge(more),
                None => self.in_all = Some(more),
            }
        } else if let Some(held) = &mut self.in_all {
            drop(held.split(has - wanted));
        }
        self.bytes = bytes;
        if !self.source.is_empty() {
            if others.saturating_add(bytes) == 0 {
                held_by.remove(&self.source);
            } else {
                held_by.insert(self.source.clone(), others.saturating_add(bytes));
            }
        }
        Ok(())
    }

    /// The answer this room was taken for. The room is then exactly what the answer came to, and it's
    /// kept until the last of the answer has been written.
    pub fn json<T: Serialize>(mut self, answer: &T) -> Result<Response, ApiError> {
        let bytes = serde_json::to_vec(answer).map_err(|_| ApiError::Unavailable)?;
        self.fit(bytes.len())?;
        let json = HeaderValue::from_static("application/json");
        let mut response = ([(CONTENT_TYPE, json)], held(bytes.into(), self)).into_response();
        response.extensions_mut().insert(Counted);
        Ok(response)
    }
}

impl Drop for Taken {
    fn drop(&mut self) {
        if self.bytes == 0 || self.source.is_empty() {
            return;
        }
        let mut held_by = self.room.held_by();
        let left = held_by
            .get(&self.source)
            .copied()
            .unwrap_or(0)
            .saturating_sub(self.bytes);
        if left == 0 {
            held_by.remove(&self.source);
        } else {
            held_by.insert(self.source.clone(), left);
        }
    }
}

/// An answer's bytes with the room they take. A connection keeps these until it has written them, so
/// the room goes back then, or when the connection does.
struct Held {
    bytes: Bytes,
    _room: Taken,
}

impl AsRef<[u8]> for Held {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn held(bytes: Bytes, room: Taken) -> Body {
    Body::from(Bytes::from_owner(Held { bytes, _room: room }))
}

/// Says an answer has its room already, so it isn't counted again on its way out.
#[derive(Clone)]
struct Counted;

/// Takes room for an answer whose route took none, once it's built, or tells its caller to come back.
/// What's refused here is dropped at once, so it's held no longer than it took to build.
pub async fn count(State(room): State<Arc<AnswerRoom>>, request: Request, next: Next) -> Response {
    let source = registry::source_of(request.headers());
    let response = next.run(request).await;
    let small = |most: Option<u64>| {
        most.is_some_and(|most| usize::try_from(most).unwrap_or(usize::MAX) <= UNCOUNTED_BYTES)
    };
    if response.extensions().get::<Counted>().is_some()
        || small(response.body().size_hint().upper())
    {
        return response;
    }
    let (parts, body) = response.into_parts();
    // Every route builds its answer whole, so this waits for nothing and copies nothing.
    let Ok(bytes) = to_bytes(body, usize::MAX).await else {
        return ApiError::Unavailable.into_response();
    };
    match room.take_for(source, bytes.len()) {
        Ok(taken) => Response::from_parts(parts, held(bytes, taken)),
        Err(full) => full.into_response(),
    }
}

/// The rows of one page, by what finds each again, and what they come to.
pub struct Page<K> {
    pub keys: Vec<K>,
    pub bytes: usize,
    /// Whether rows were left for a later page.
    pub more: bool,
}

/// Cuts rows, in order, into a page: at most `most_rows`, and as many as fit in `budget` bytes with
/// their framing. With `at_least_one` the first row goes in however large, so one large row still
/// moves. A caller asks for one row more than a page holds, to know whether more are left.
pub fn page_of<K>(
    sized: impl IntoIterator<Item = (K, i64)>,
    most_rows: usize,
    budget: usize,
    at_least_one: bool,
) -> Page<K> {
    let mut page = Page {
        keys: Vec::new(),
        bytes: 0,
        more: false,
    };
    for (key, size) in sized {
        let size = usize::try_from(size)
            .unwrap_or(usize::MAX)
            .saturating_add(ROW_FRAMING_BYTES);
        let fits = page.bytes.saturating_add(size) <= budget;
        let first = page.keys.is_empty() && at_least_one;
        if page.keys.len() >= most_rows || !(fits || first) {
            page.more = true;
            break;
        }
        page.keys.push(key);
        page.bytes = page.bytes.saturating_add(size);
    }
    page
}

/// What a route's first query reads of each row: its handle and how long it is.
pub fn seq_and_bytes(rows: &[sqlx::postgres::PgRow]) -> Result<Vec<(i64, i64)>, sqlx::Error> {
    use sqlx::Row;
    rows.iter()
        .map(|row| Ok((row.try_get("seq")?, row.try_get("bytes")?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room_for_two_pages() -> Arc<AnswerRoom> {
        let two_pages = u32::try_from(2 * PAGE_BYTES).unwrap();
        AnswerRoom::new(&Limits {
            answer_bytes_at_once: two_pages,
            answer_bytes_at_once_per_source: two_pages / 2,
            ..Limits::for_tests()
        })
    }

    fn from(source: &'static str) -> HeaderMap {
        HeaderMap::from_iter([(
            axum::http::HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static(source),
        )])
    }

    /// Bug: with the room full of unread answers, a Signet couldn't read even a page of a few
    /// ordinary messages, so whoever filled it stopped every agent on the host hearing anything.
    #[test]
    fn with_the_room_full_a_small_answer_still_goes_and_a_larger_one_waits() {
        let room = room_for_two_pages();
        let _one = room.take(&from("192.0.2.1"), PAGE_BYTES).unwrap();
        let _another = room.take(&from("192.0.2.2"), PAGE_BYTES).unwrap();
        let larger = room.take(&from("192.0.2.3"), UNCOUNTED_BYTES + 1);
        assert_eq!(larger.err(), Some(Full::Host));
        assert!(room.take(&from("192.0.2.3"), UNCOUNTED_BYTES).is_ok());
        assert!(
            room.take(&from("192.0.2.1"), UNCOUNTED_BYTES).is_ok(),
            "nor is one stopped by its source's share"
        );
    }

    /// Bug: with less room left than a page, a reader of an inbox was told to come back for all of
    /// it, so whoever filled the room stopped every agent on the host hearing anything.
    #[test]
    fn a_page_is_cut_to_the_room_thats_left_and_to_what_takes_none_when_its_full() {
        let room = room_for_two_pages();
        let (reader, another) = (from("192.0.2.1"), from("192.0.2.2"));
        assert_eq!(room.page_budget(&reader), PAGE_BYTES, "a whole page fits");
        let _held = room.take(&another, PAGE_BYTES + PAGE_BYTES / 2).unwrap();
        let left = room.page_budget(&reader);
        assert_eq!(left, PAGE_BYTES / 2, "what's left of the room");
        let part = room.take(&reader, left).unwrap();
        let none_left = room.page_budget(&reader);
        assert!(none_left > 0 && room.take(&reader, none_left).is_ok());
        assert_eq!(room.take(&reader, none_left + 1).err(), Some(Full::Host));
        drop(part);

        // Its own share, when that's what is short.
        let room = room_for_two_pages();
        let _held = room.take(&reader, PAGE_BYTES / 2).unwrap();
        let left = room.page_budget(&reader);
        assert!(room.take(&reader, left).is_ok());
        assert_eq!(room.take(&reader, left + 1).err(), Some(Full::Source));
        assert_eq!(room.page_budget(&another), PAGE_BYTES, "and nobody else's");
    }

    /// Bug: an answer larger than a source's share, as a page of owner mail can be, was refused for
    /// good, so it could never be read or cleared.
    #[test]
    fn an_answer_larger_than_a_share_goes_alone_and_nothing_goes_beside_it() {
        let room = room_for_two_pages();
        let large = room.take(&from("192.0.2.1"), PAGE_BYTES + PAGE_BYTES / 2);
        assert!(large.is_ok());
        let beside = room.take(&from("192.0.2.1"), UNCOUNTED_BYTES + 1);
        assert_eq!(beside.err(), Some(Full::Source));
        assert!(room.take(&from("192.0.2.1"), UNCOUNTED_BYTES).is_ok());
        drop(large);
        assert!(room.take(&from("192.0.2.1"), PAGE_BYTES).is_ok());
        let more_than_all_of_it = room.take(&from("192.0.2.2"), 3 * PAGE_BYTES);
        assert!(
            more_than_all_of_it.is_ok(),
            "alone, it takes what room there is"
        );
    }

    /// Bugs: a page that stopped at a row too large for it and so never moved, one that took a row
    /// past its room, and one that said nothing was left when it had cut rows off.
    #[test]
    fn a_page_takes_what_fits_in_order_and_says_when_it_left_rows() {
        let row = 1000 - i64::try_from(ROW_FRAMING_BYTES).unwrap();
        let rows =
            |sizes: &[i64]| -> Vec<(usize, i64)> { sizes.iter().copied().enumerate().collect() };

        let page = page_of(rows(&[row, row, row]), 10, 2500, true);
        assert_eq!((page.keys, page.bytes, page.more), (vec![0, 1], 2000, true));
        let page = page_of(rows(&[row, row]), 10, 2000, true);
        assert_eq!(
            (page.keys, page.more),
            (vec![0, 1], false),
            "all of it fits"
        );
        let page = page_of(rows(&[row, row, row]), 2, 9000, true);
        assert_eq!((page.keys, page.more), (vec![0, 1], true), "cut by rows");

        let page = page_of(rows(&[5 * row, row]), 10, 2500, true);
        assert_eq!(
            (page.keys, page.more),
            (vec![0], true),
            "one too large still moves"
        );
        let page = page_of(rows(&[5 * row, row]), 10, 2500, false);
        assert_eq!(
            (page.keys, page.bytes, page.more),
            (vec![], 0, true),
            "unless told not to"
        );
    }
}

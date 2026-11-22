//! Which release a program is, and the protocol it speaks. See "What a release proves" in
//! `docs/how-it-works.md`.
//!
//! A program reports this about itself, and a changed binary can report anything, so nothing here
//! is ever a reason to trust a counterparty. The protocol is only for compatibility: two honest
//! programs that would misread each other's formats stop with a clear reason, rather than fail in
//! some way nobody can explain.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use aws_lc_rs::digest;
use serde::{Deserialize, Serialize};

use crate::identity::hex;

/// The newest protocol this code speaks, which it writes its own calls in. It goes up whenever a
/// format or an API changes in a way an older program would misread.
pub const PROTOCOL: u32 = 1;

/// The oldest protocol this code still reads and writes, so a peer that hasn't updated yet keeps
/// working with it. See "Protocol version" in `docs/protocol.md` for how long one is kept.
pub const OLDEST_PROTOCOL: u32 = 1;

/// Every protocol this code speaks.
pub const SPOKEN: ProtocolRange = ProtocolRange {
    oldest: OLDEST_PROTOCOL,
    newest: PROTOCOL,
};

/// The number a call or an answer is written in. Every Splint program sends it on each call it
/// makes, and answers with it. It stays one plain number, as programs from before ranges refuse
/// anything else. A caller that doesn't send it, such as `curl` or an adapter, is taken to speak
/// [`PROTOCOL`].
pub const PROTOCOL_HEADER: &str = "splint-protocol";

/// The range a program speaks, as `OLDEST-NEWEST`, sent beside [`PROTOCOL_HEADER`] on every call
/// and answer. A program that doesn't send it speaks only the one number it sent.
pub const PROTOCOLS_HEADER: &str = "splint-protocols";

/// Where a host and a Signet report what they are.
pub const RELEASE_PATH: &str = "/v0/release";

/// The only place Splint's releases come from. Fixed in each program, so nothing a host serves can
/// change where an agent or its owner is told to install from.
pub const REPOSITORY: &str = "nennovate/splint";

/// The official copy of what an agent needs to install and join, attached to every release beside
/// `install.sh` and listed in its signed `SHA256SUMS`. Its source is `docs/agents.md`. A host's own
/// page only points here, and says what only that host can.
pub const AGENT_INSTRUCTIONS: &str =
    "https://github.com/nennovate/splint/releases/latest/download/agents.md";

/// A release build sets these. A build from source has neither.
const VERSION: Option<&str> = option_env!("SPLINT_VERSION");
const COMMIT: Option<&str> = option_env!("SPLINT_COMMIT");

/// What `--version` prints.
pub fn version() -> &'static str {
    VERSION.unwrap_or("built from source")
}

/// The release this program was built as, if it was built as one.
pub fn release_version() -> Option<&'static str> {
    VERSION
}

/// The commit a release was built from.
pub fn commit() -> Option<&'static str> {
    COMMIT
}

/// What a program says it is. A modified program can say anything here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub version: String,
    pub commit: Option<String>,
    /// The SHA-256 of the program's file, read as it started, so a release's `SHA256SUMS` lists it.
    pub build: Option<String>,
    pub protocol: u32,
}

impl Release {
    /// This program, hashed now. Called as it starts, before an update can replace the file.
    pub fn of_this_program() -> Self {
        let build = std::env::current_exe()
            .ok()
            .and_then(|path| sha256_of_file(&path).ok());
        Self {
            version: version().to_owned(),
            commit: COMMIT.map(str::to_owned),
            build,
            protocol: PROTOCOL,
        }
    }
}

/// The SHA-256 of a file, in lowercase hex, as `sha256sum` prints it.
pub fn sha256_of_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        let Some(chunk) = buffer.get(..read) else {
            return Err(io::Error::other("read past the buffer"));
        };
        if chunk.is_empty() {
            return Ok(hex(context.finish().as_ref()));
        }
        context.update(chunk);
    }
}

/// The lowest and highest protocol a program speaks, both included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolRange {
    oldest: u32,
    newest: u32,
}

impl ProtocolRange {
    /// Reads `OLDEST-NEWEST`, plain digits each, with the oldest no higher than the newest.
    pub fn parse(said: &[u8]) -> Option<Self> {
        let said = std::str::from_utf8(said).ok()?;
        let (oldest, newest) = said.split_once('-')?;
        let (oldest, newest) = (number(oldest)?, number(newest)?);
        (oldest <= newest).then_some(Self { oldest, newest })
    }

    /// Only the one number.
    fn only(number: u32) -> Self {
        Self {
            oldest: number,
            newest: number,
        }
    }

    /// As [`PROTOCOLS_HEADER`] and the well-known page carry it.
    pub fn header_value(self) -> String {
        format!("{}-{}", self.oldest, self.newest)
    }

    fn contains(self, number: u32) -> bool {
        (self.oldest..=self.newest).contains(&number)
    }

    /// The protocol two programs use: the highest both speak. With none in common, which of the
    /// two is behind, and so has to update.
    pub fn highest_shared(self, theirs: Self) -> Result<u32, Behind> {
        if theirs.newest < self.oldest {
            Err(Behind::Theirs)
        } else if theirs.oldest > self.newest {
            Err(Behind::Ours)
        } else {
            Ok(self.newest.min(theirs.newest))
        }
    }
}

/// Words for a range: `1`, or `1 to 2`.
impl std::fmt::Display for ProtocolRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.oldest == self.newest {
            write!(f, "{}", self.oldest)
        } else {
            write!(f, "{} to {}", self.oldest, self.newest)
        }
    }
}

fn number(digits: &str) -> Option<u32> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Which side of a pair with no protocol in common has to update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behind {
    /// This program: the other side speaks only newer protocols.
    Ours,
    /// The other side: it speaks only older protocols.
    Theirs,
}

/// The other side speaks another protocol. Only its numbers are kept, never the words it sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OtherProtocol {
    /// The two share no protocol, and `behind` is the one that has to update.
    #[error(
        "this speaks Splint protocol {SPOKEN}, and the other side speaks protocol {theirs}, so {} has to update",
        match behind { Behind::Ours => "this side", Behind::Theirs => "the other side" }
    )]
    NoneShared {
        theirs: ProtocolRange,
        behind: Behind,
    },
    /// Both speak `shared`, but the other side wrote in a number this doesn't read.
    #[error(
        "both sides speak Splint protocol {shared}, and the other side wrote in protocol {written}, which this doesn't read"
    )]
    WrittenInAnother { written: u32, shared: u32 },
    #[error(
        "this speaks Splint protocol {SPOKEN}, and the other side named something that isn't a protocol"
    )]
    Unreadable,
}

impl OtherProtocol {
    /// Which side has to update, when that's what it comes to.
    pub fn behind(self) -> Option<Behind> {
        match self {
            Self::NoneShared { behind, .. } => Some(behind),
            Self::WrittenInAnother { .. } | Self::Unreadable => None,
        }
    }
}

/// Checks what the other side put in [`PROTOCOL_HEADER`] and [`PROTOCOLS_HEADER`], on a call or an
/// answer, and gives the number it's written in, which this reads. Saying nothing counts as
/// [`PROTOCOL`], so a plain HTTP caller still works, and a plain number with no range counts as a
/// range of that one number, as an older program sends. It's for compatibility only: a hostile peer
/// can send any numbers, and every other check here still meets what it sends.
pub fn check_protocol(said: Option<&[u8]>, range: Option<&[u8]>) -> Result<u32, OtherProtocol> {
    let written = said
        .map(|said| {
            std::str::from_utf8(said)
                .ok()
                .and_then(number)
                .ok_or(OtherProtocol::Unreadable)
        })
        .transpose()?;
    let range = range
        .map(|range| ProtocolRange::parse(range).ok_or(OtherProtocol::Unreadable))
        .transpose()?;
    let (written, theirs) = match (written, range) {
        (None, None) => return Ok(PROTOCOL),
        (Some(written), None) => (written, ProtocolRange::only(written)),
        // A program that writes in a number it says it doesn't speak can't be read either way.
        (Some(written), Some(range)) if !range.contains(written) => {
            return Err(OtherProtocol::Unreadable);
        }
        (Some(written), Some(range)) => (written, range),
        // A range with no number is written in the highest both speak.
        (None, Some(range)) => (
            SPOKEN
                .highest_shared(range)
                .map_err(|behind| OtherProtocol::NoneShared {
                    theirs: range,
                    behind,
                })?,
            range,
        ),
    };
    if SPOKEN.contains(written) {
        return Ok(written);
    }
    match SPOKEN.highest_shared(theirs) {
        Ok(shared) => Err(OtherProtocol::WrittenInAnother { written, shared }),
        Err(behind) => Err(OtherProtocol::NoneShared { theirs, behind }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(said: &str) -> ProtocolRange {
        ProtocolRange::parse(said.as_bytes()).unwrap()
    }

    /// Catches a pair settling on a number one side doesn't speak, or blaming the wrong side.
    #[test]
    fn a_pair_uses_the_highest_both_speak_or_names_who_is_behind() {
        for (ours, theirs, met) in [
            ("1-1", "1-1", Ok(1)),
            ("1-3", "2-5", Ok(3)),
            ("2-5", "1-3", Ok(3)),
            ("1-2", "2-2", Ok(2)),
            ("2-3", "1-1", Err(Behind::Theirs)),
            ("1-1", "2-3", Err(Behind::Ours)),
        ] {
            assert_eq!(
                range(ours).highest_shared(range(theirs)),
                met,
                "{ours} with {theirs}"
            );
        }
    }

    /// Catches a range header read loosely, so two programs disagree on what was said.
    #[test]
    fn a_range_reads_only_as_oldest_dash_newest() {
        assert_eq!(range("0-7").header_value(), "0-7");
        for unreadable in [
            &b""[..],
            b"1",
            b"1-",
            b"-1",
            b"2-1",
            b" 1-1",
            b"1-1 ",
            b"1--2",
            b"+1-2",
            b"1-2-3",
            b"a-b",
            b"99999999999-99999999999",
            b"1-\xff",
        ] {
            assert_eq!(ProtocolRange::parse(unreadable), None, "{unreadable:?}");
        }
    }

    /// Catches a newer program that still speaks this one being refused, which made every bump a
    /// flag day, and a mismatch said as the wrong side's fault.
    #[test]
    fn a_call_is_read_when_its_number_is_spoken_here() {
        let ours = PROTOCOL.to_string();
        let next = (PROTOCOL + 1).to_string();
        let newer_and_ours = format!("{OLDEST_PROTOCOL}-{next}");
        let only_newer = format!("{next}-{}", PROTOCOL + 2);
        let older = (OLDEST_PROTOCOL - 1).to_string();
        let check = |said: Option<&str>, range: Option<&str>| {
            check_protocol(said.map(str::as_bytes), range.map(str::as_bytes))
        };

        assert_eq!(check(None, None), Ok(PROTOCOL));
        assert_eq!(check(Some(&ours), None), Ok(PROTOCOL));
        assert_eq!(check(Some(&ours), Some(&newer_and_ours)), Ok(PROTOCOL));
        assert_eq!(check(None, Some(&newer_and_ours)), Ok(PROTOCOL));
        assert_eq!(
            check(Some(&next), Some(&newer_and_ours)),
            Err(OtherProtocol::WrittenInAnother {
                written: PROTOCOL + 1,
                shared: PROTOCOL
            })
        );
        let ahead = check(Some(&next), Some(&only_newer)).err();
        assert_eq!(ahead.and_then(OtherProtocol::behind), Some(Behind::Ours));
        let ahead = check(Some(&next), None).err();
        assert_eq!(ahead.and_then(OtherProtocol::behind), Some(Behind::Ours));
        let behind = check(Some(&older), None).err();
        assert_eq!(behind.and_then(OtherProtocol::behind), Some(Behind::Theirs));

        // Written in a number its own range leaves out.
        assert_eq!(
            check(Some(&ours), Some(&only_newer)),
            Err(OtherProtocol::Unreadable)
        );
        for unreadable in ["", " 1", "1.0", "+1", "one", "99999999999"] {
            assert_eq!(
                check(Some(unreadable), None),
                Err(OtherProtocol::Unreadable),
                "{unreadable:?}"
            );
        }
        assert_eq!(
            check(Some(&ours), Some("1")),
            Err(OtherProtocol::Unreadable)
        );
        assert_eq!(
            check_protocol(Some(b"\xff"), None),
            Err(OtherProtocol::Unreadable)
        );
    }

    #[test]
    fn a_file_longer_than_one_read_hashes_whole() -> io::Result<()> {
        let dir = std::env::temp_dir().join(format!("splint-release-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("program");
        let bytes: Vec<u8> = (0..150_000_u32).map(|n| (n % 251) as u8).collect();
        std::fs::write(&path, &bytes)?;
        let hashed = sha256_of_file(&path);
        std::fs::remove_dir_all(&dir)?;
        assert_eq!(
            hashed?,
            hex(digest::digest(&digest::SHA256, &bytes).as_ref())
        );
        Ok(())
    }
}

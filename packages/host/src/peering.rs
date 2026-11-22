//! Which other hosts this one exchanges with, as its operator's peers file says.
//!
//! Every host, unless the file says `private`: then only the hosts it names with `peer`. A `block`
//! line refuses a host either way. Where this host may then call, and how far it goes for a host it
//! hasn't met, is `destinations` and `host_identity`.
//!
//! The file is read again while the host runs, so naming, removing or blocking a host, or taking a
//! peer's new key, never needs a restart, which would cut off every agent here. A file that can't be
//! used changes nothing: the last list that could be read stays.

use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use splint_core::canonical_domain;
use splint_core::transport::{Scheme, TransportRefused};

use crate::log_limit::LogLimit;
use crate::operator::SettingError;
use crate::{Host, host_identity};

/// Names the file. With it unset the list is fixed while the host runs.
pub const FILE_SETTING: &str = "SPLINT_PEERS_FILE";
/// Where the list was before the file: host names with commas between, read once at start.
const OLD_SETTING: &str = "SPLINT_PEERS";
const REREAD_EVERY: Duration = Duration::from_secs(2);
/// Far more than any list of hosts needs, so a wrong path can't have the host read something huge.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// A file that stays unusable is read every two seconds, and would otherwise be a line each time.
static UNUSABLE_FILE: LogLimit = LogLimit::new();
/// The same while the database can't be reached to take a change.
static UNTAKEN_CHANGE: LogLimit = LogLimit::new();

#[derive(PartialEq, Eq, thiserror::Error)]
pub enum PeersFileError {
    #[error("it can't be read ({0})")]
    Unreadable(io::ErrorKind),
    #[error("it's over {MAX_FILE_BYTES} bytes")]
    TooLong,
    #[error("line {0} isn't `private`, `peer HOST`, `block HOST` or `repin HOST`")]
    UnknownLine(usize),
    #[error("line {0} names a host that isn't a domain")]
    NotADomain(usize),
    #[error("line {0} blocks this host itself")]
    BlocksThisHost(usize),
    #[error("line {line}: {refused}")]
    CantBeCalled {
        line: usize,
        refused: TransportRefused,
    },
}

/// A `main` that returns an error prints it this way, and the operator reading needs the sentence.
impl fmt::Debug for PeersFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(thiserror::Error)]
#[error("the peers file {file} can't be used: {error}")]
pub struct UnusablePeersFile {
    file: String,
    error: PeersFileError,
}

impl fmt::Debug for UnusablePeersFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// What one reading of the file says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerList {
    /// This host, which is always its own peer.
    domain: String,
    private: bool,
    peers: BTreeSet<String>,
    blocked: BTreeSet<String>,
    repin: BTreeSet<String>,
}

impl PeerList {
    /// Open to every host, naming none, as with no file.
    pub fn naming_none(domain: &str) -> Self {
        Self {
            domain: domain.to_owned(),
            private: false,
            peers: BTreeSet::new(),
            blocked: BTreeSet::new(),
            repin: BTreeSet::new(),
        }
    }

    /// One line each, with `#` starting a comment: `private`, `peer HOST`, `block HOST` or
    /// `repin HOST`. A host is taken into its one spelling, as an address is. Anything else refuses
    /// the whole file, because half a list could leave out the line that mattered.
    pub fn parse(text: &str, domain: &str, scheme: Scheme) -> Result<Self, PeersFileError> {
        let mut list = Self::naming_none(domain);
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            let said = line.split('#').next().unwrap_or(line);
            let mut words = said.split_whitespace();
            let (word, host, extra) = (words.next(), words.next(), words.next());
            let host = host
                .map(canonical_domain)
                .transpose()
                .map_err(|_| PeersFileError::NotADomain(number))?;
            match (word, host, extra) {
                (None, _, _) => {}
                (Some("private"), None, _) => list.private = true,
                (Some("peer"), Some(host), None) => {
                    // The same check a peer got at start when the list was a setting.
                    scheme.check_destination(&host).map_err(|refused| {
                        PeersFileError::CantBeCalled {
                            line: number,
                            refused,
                        }
                    })?;
                    if host != domain {
                        list.peers.insert(host);
                    }
                }
                (Some("block"), Some(host), None) if host == domain => {
                    return Err(PeersFileError::BlocksThisHost(number));
                }
                (Some("block"), Some(host), None) => {
                    list.blocked.insert(host);
                }
                (Some("repin"), Some(host), None) => {
                    list.repin.insert(host);
                }
                _ => return Err(PeersFileError::UnknownLine(number)),
            }
        }
        Ok(list)
    }

    /// The old setting's list, which meant only these hosts.
    fn from_old_setting(peers: &str, domain: &str, scheme: Scheme) -> Result<Self, SettingError> {
        let mut list = Self::naming_none(domain);
        list.private = true;
        for peer in peers.split(',').filter(|peer| !peer.is_empty()) {
            let peer =
                canonical_domain(peer).map_err(|_| SettingError::NotHostNames(OLD_SETTING))?;
            scheme
                .check_destination(&peer)
                .map_err(|refused| SettingError::refused(OLD_SETTING, refused))?;
            if peer != domain {
                list.peers.insert(peer);
            }
        }
        Ok(list)
    }

    /// Whether this host sends to that one, takes deliveries from it and asks it about addresses.
    /// Every place that decides goes by this. A blocked host is refused even when it's also named.
    pub fn exchanges_with(&self, host: &str) -> bool {
        host == self.domain
            || (!self.blocked.contains(host) && (!self.private || self.peers.contains(host)))
    }

    /// Whether the operator named that host with `peer` and didn't block it. A named host may be
    /// anywhere, and is spared the limits on hosts met for the first time.
    pub fn names(&self, host: &str) -> bool {
        self.peers.contains(host) && !self.blocked.contains(host)
    }

    /// The other hosts the operator named and didn't block.
    pub fn named(&self) -> impl Iterator<Item = &str> {
        self.peers
            .iter()
            .filter(|peer| !self.blocked.contains(*peer))
            .map(String::as_str)
    }

    /// The hosts whose pinned key the operator says to let go of.
    pub const fn repin(&self) -> &BTreeSet<String> {
        &self.repin
    }
}

/// The list in force. Each call reads it once and goes by that, so one call never sees two lists.
pub struct Peers(RwLock<Arc<PeerList>>);

impl Peers {
    pub fn new(list: PeerList) -> Self {
        Self(RwLock::new(Arc::new(list)))
    }

    pub fn current(&self) -> Arc<PeerList> {
        // The lock only ever guards a pointer being swapped, so a panic elsewhere leaves it whole.
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn replace(&self, list: PeerList) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(list);
    }
}

/// The list this host starts with, and the file to keep reading when there is one. A file that's
/// missing or can't be used stops the host starting, since there's no earlier list to keep.
pub fn at_start(domain: &str, scheme: Scheme) -> Result<(PeerList, Option<PathBuf>), SettingError> {
    scheme
        .check_destination(domain)
        .map_err(|refused| SettingError::refused("SPLINT_DOMAIN", refused))?;
    let file = env::var_os(FILE_SETTING)
        .filter(|file| !file.is_empty())
        .map(PathBuf::from);
    let old = env::var(OLD_SETTING).unwrap_or_default();
    let Some(file) = file else {
        if old.is_empty() {
            return Ok((PeerList::naming_none(domain), None));
        }
        tracing::warn!(
            "{OLD_SETTING} is read once, at start, as `private` and a `peer` line for each host. \
             The list lives in the file {FILE_SETTING} names now, which a running host reads again"
        );
        return Ok((PeerList::from_old_setting(&old, domain, scheme)?, None));
    };
    if !old.is_empty() {
        tracing::warn!(
            file = %file.display(),
            "{OLD_SETTING} and {FILE_SETTING} are both set: the file is the list, and \
             {OLD_SETTING} is ignored"
        );
    }
    let list = load(&file, domain, scheme).map_err(|error| {
        SettingError::refused(
            FILE_SETTING,
            UnusablePeersFile {
                file: file.display().to_string(),
                error,
            },
        )
    })?;
    Ok((list, Some(file)))
}

fn load(file: &Path, domain: &str, scheme: Scheme) -> Result<PeerList, PeersFileError> {
    let mut text = String::new();
    File::open(file)
        .and_then(|opened| {
            opened
                .take(MAX_FILE_BYTES.saturating_add(1))
                .read_to_string(&mut text)
        })
        .map_err(|error| PeersFileError::Unreadable(error.kind()))?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(PeersFileError::TooLong);
    }
    PeerList::parse(&text, domain, scheme)
}

/// The reading before this one, when it differed from the list in force. A list is taken only once
/// two readings in a row agree on it, so a file caught half written, or emptied a moment before it's
/// filled, is never the list.
#[derive(Default)]
struct Readings {
    last: Option<PeerList>,
}

impl Readings {
    /// Whether to take this reading now. It stays true for the same reading, so one that couldn't be
    /// taken is tried again.
    fn agree_on(&mut self, read: Option<&PeerList>, current: &PeerList) -> bool {
        match read {
            Some(list) if list != current => {
                let agreed = self.last.as_ref() == Some(list);
                if !agreed {
                    self.last = Some(list.clone());
                }
                agreed
            }
            _ => {
                self.last = None;
                false
            }
        }
    }
}

/// Reads the file again every two seconds, and takes a list that differs once the next reading says
/// the same. So a change is in force within about four seconds.
///
/// The delivery worker sees the new list on its next pass and re-applies it to what's queued.
pub async fn run_rereading(host: Arc<Host>, file: PathBuf) {
    let mut readings = Readings::default();
    loop {
        tokio::time::sleep(REREAD_EVERY).await;
        let (path, domain, scheme) = (file.clone(), host.domain.clone(), host.scheme);
        let Ok(read) = tokio::task::spawn_blocking(move || load(&path, &domain, scheme)).await
        else {
            continue;
        };
        if let Err(error) = &read
            && let Some(count) = UNUSABLE_FILE.due()
        {
            tracing::warn!(
                file = %file.display(),
                %error,
                count,
                "the peers file can't be used, so the list stays as it was"
            );
        }
        let current = host.peers.current();
        let Some(list) = read
            .ok()
            .filter(|list| readings.agree_on(Some(list), &current))
        else {
            continue;
        };
        // Before the list changes, so a failure here leaves all of it to try again.
        if let Err(error) = host_identity::accept_new_keys_named(&host.db, list.repin()).await {
            if let Some(count) = UNTAKEN_CHANGE.due() {
                tracing::warn!(
                    %error,
                    count,
                    "couldn't take the peers file's `repin` lines, so the list stays as it was for now"
                );
            }
            continue;
        }
        log_change(&current, &list);
        host.peers.replace(list);
    }
}

fn log_change(old: &PeerList, new: &PeerList) {
    fn only_in<'a>(one: &'a BTreeSet<String>, other: &'a BTreeSet<String>) -> Vec<&'a String> {
        one.difference(other).collect()
    }
    tracing::info!(
        private = new.private,
        named = ?only_in(&new.peers, &old.peers),
        no_longer_named = ?only_in(&old.peers, &new.peers),
        blocked = ?only_in(&new.blocked, &old.blocked),
        no_longer_blocked = ?only_in(&old.blocked, &new.blocked),
        "the peers file changed, and this host goes by it from now"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const HERE: &str = "here.example";

    fn parsed(text: &str) -> Result<PeerList, PeersFileError> {
        PeerList::parse(text, HERE, Scheme::Https)
    }

    /// A parser that read a comment or a blank line as a host, or missed a line, would give a list
    /// the operator never wrote.
    #[test]
    fn each_kind_of_line_is_read_and_comments_are_not() {
        let list = parsed(
            "# who this host talks to\n\
             private\n\
             \n\
             peer one.example   # a friend\n\
             \tpeer two.example:8443\n\
             block bad.example\n\
             repin one.example\n\
             #peer commented.example\n",
        )
        .unwrap();
        assert!(list.private);
        assert_eq!(
            list.named().collect::<Vec<_>>(),
            ["one.example", "two.example:8443"]
        );
        assert!(list.exchanges_with("one.example"));
        assert!(list.exchanges_with("two.example:8443"));
        assert!(!list.exchanges_with("two.example"));
        assert!(!list.exchanges_with("commented.example"));
        assert!(!list.exchanges_with("bad.example"));
        assert_eq!(list.repin().iter().collect::<Vec<_>>(), ["one.example"]);
    }

    /// A host typed in another spelling has to match the one spelling a delivery names it by, or the
    /// operator's peer is refused.
    #[test]
    fn a_host_is_taken_into_its_one_spelling() {
        let list = parsed("private\npeer One.Example.\npeer [::0001]:0443\n").unwrap();
        assert!(list.exchanges_with("one.example"));
        assert!(list.exchanges_with("[::1]"));
    }

    /// Reading on past a line it can't use would drop a `block`, or a peer, without a word.
    #[test]
    fn one_bad_line_refuses_the_whole_file() {
        for (text, refused) in [
            (
                "peer one.example\nallow two.example\n",
                PeersFileError::UnknownLine(2),
            ),
            ("peer\n", PeersFileError::UnknownLine(1)),
            (
                "peer one.example two.example\n",
                PeersFileError::UnknownLine(1),
            ),
            ("private one.example\n", PeersFileError::UnknownLine(1)),
            ("one.example\n", PeersFileError::UnknownLine(1)),
            ("Peer one.example\n", PeersFileError::UnknownLine(1)),
            ("\n\nblock not_a_host\n", PeersFileError::NotADomain(3)),
            ("peer https://one.example\n", PeersFileError::NotADomain(1)),
            ("peer one.example:0\n", PeersFileError::NotADomain(1)),
            (
                "peer one.example,two.example\n",
                PeersFileError::NotADomain(1),
            ),
            ("block here.example\n", PeersFileError::BlocksThisHost(1)),
        ] {
            assert_eq!(parsed(text).err(), Some(refused), "{text:?}");
        }
    }

    /// A host that's both named and blocked must stay refused, whichever line comes first, and must
    /// not be told of retirements either.
    #[test]
    fn a_block_wins_over_a_peer_line() {
        for text in [
            "peer one.example\nblock one.example\n",
            "block one.example\npeer one.example\n",
        ] {
            let list = parsed(text).unwrap();
            assert!(!list.exchanges_with("one.example"), "{text:?}");
            assert_eq!(list.named().count(), 0, "{text:?}");
        }
    }

    /// Nothing in the file can cut a host off from its own agents. With no `private` line a host
    /// exchanges with every host it doesn't block, and with one, only with those it names.
    #[test]
    fn open_unless_private_and_never_cut_off_from_itself() {
        for (text, open) in [
            ("", true),
            ("# nothing\n", true),
            ("peer here.example\n", true),
            ("block one.example\n", false),
            ("private\n", false),
            ("private\npeer here.example\n", false),
        ] {
            let list = parsed(text).unwrap();
            assert!(list.exchanges_with(HERE), "{text:?}");
            assert_eq!(list.exchanges_with("one.example"), open, "{text:?}");
            assert!(!list.names("one.example"), "{text:?}");
            assert_eq!(list.named().count(), 0, "{text:?}");
        }
        let open = parsed("peer one.example\nblock two.example\n").unwrap();
        assert!(open.exchanges_with("three.example"));
        assert!(open.names("one.example"));
        assert!(!open.names("three.example"));
        assert!(!open.exchanges_with("two.example"));
    }

    /// Under the plain-HTTP test scheme a peer anywhere but this machine would get host keys and
    /// first contacts in the clear. The setting refused that at start, and the file must too.
    #[test]
    fn a_peer_plain_http_cant_reach_is_refused() {
        let plain = Scheme::PlainHttpForTests;
        let refused = PeerList::parse("peer 127.0.0.1:7001\npeer host.example\n", HERE, plain);
        assert!(
            matches!(refused, Err(PeersFileError::CantBeCalled { line: 2, .. })),
            "{refused:?}"
        );
        assert!(PeerList::parse("peer 127.0.0.1:7001\n", HERE, plain).is_ok());
        assert!(PeerList::parse("block host.example\n", HERE, plain).is_ok());
    }

    /// A file read while it was being written, emptied or half filled, would be the list until the
    /// next reading: every peer cut off, or a `block` gone.
    #[test]
    fn a_reading_is_taken_only_once_the_next_one_agrees() {
        let current = parsed("peer one.example\n").unwrap();
        let emptied = parsed("").unwrap();
        let wanted = parsed("peer one.example\npeer two.example\n").unwrap();

        let mut readings = Readings::default();
        assert!(!readings.agree_on(Some(&emptied), &current));
        assert!(!readings.agree_on(Some(&wanted), &current));
        assert!(readings.agree_on(Some(&wanted), &current));
        assert!(
            readings.agree_on(Some(&wanted), &current),
            "one that couldn't be taken is tried again"
        );

        for between in [None, Some(&current), Some(&emptied)] {
            let mut readings = Readings::default();
            assert!(!readings.agree_on(Some(&wanted), &current));
            assert!(!readings.agree_on(between, &current));
            assert!(!readings.agree_on(Some(&wanted), &current), "{between:?}");
        }
    }

    /// The old setting has to go on meaning what it meant, or a host upgraded with it set would
    /// lose its peers.
    #[test]
    fn the_old_setting_is_a_private_list_of_those_hosts() {
        let list =
            PeerList::from_old_setting("One.Example,,two.example", HERE, Scheme::Https).unwrap();
        assert!(list.private);
        assert_eq!(
            list.named().collect::<Vec<_>>(),
            ["one.example", "two.example"]
        );
        assert!(PeerList::from_old_setting("not a host", HERE, Scheme::Https).is_err());
    }
}

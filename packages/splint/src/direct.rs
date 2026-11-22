//! Reaching an agent's Signet straight from its owner's side, rather than by way of its host: on this
//! computer through the Signet's own socket, or over a network its operator opted into, at the address
//! the owner named for it. Either way the host stays in the path for rules, as it enforces them.
//!
//! Nothing that comes back is believed for more than the host's answer would be. A program on this
//! computer could stand in for a Signet's socket, and anyone on the network for its address, and
//! either can withhold what's sent, or say something was taken that wasn't. So everything the owner
//! signs goes to the host as well, whatever this says, and is done only once the host takes it: rules
//! and where the owner gets paid, as an agent mustn't be able to keep a change from counting, and an
//! answer, a yes to a change, their words or a delegation, as the host is how each reaches the agent
//! whoever answered here. When only a straight answer said yes, the owner is told it isn't confirmed,
//! and it's kept here and sent to the host again until it takes it. An agent's Signet that got
//! something both ways takes it once. What goes to the host for an agent's Signet goes sealed to the
//! agent, with the owner's proof for leaving exactly that, so the host can't read it, and what's kept
//! to send again is those sealed bytes, which go with a fresh proof each time: a session Splint on
//! this computer keeps at that host, or the owner key's own, which a chip signs only with its person
//! there. A view read here is checked as one from
//! the host is, and as Signet signs one as it's asked, one that's older than a moment, or than one
//! read before, is someone's copy, and the host's is read instead.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode, redirect};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use splint_core::host_api::{
    HeldRules, MAX_OWNER_VIEW_BYTES, OwnerMail, OwnerMailKind, OwnerView, owner_mail_item,
};
use splint_core::owner_call::{
    OWNER_VIEW_CALL_PATH, mail_body, owner_mail_path, seal_owner_call, seal_owner_mail,
};
use splint_core::{Identity, SplintId, unix_now};

use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::host_calls::{Delivered, HostCalls, SealedMail};
use crate::owner_key::{OwnerKey, SignIn};
use crate::release::{other_protocol, speaking_ours};
use crate::secrets::write_private;
use crate::signet_api::SignetApi;

/// Where an owner's device reads the rules the agent's Signet goes by.
pub const RULES_AT_SIGNET: &str = "/v0/owner/rules";
/// A Signet on the network answers at once or not at all, and the host is there if it doesn't.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);
/// What a view can be, written out, with room for the rest of the answer.
const MAX_VIEW_ANSWER_BYTES: usize = MAX_OWNER_VIEW_BYTES + 1024;
/// Signet signs a view as it's asked for one, so one read straight that's older than this, by the
/// agent's clock, is a copy someone kept, and the host's is read instead. Machines whose clocks are
/// further apart than this go by way of the host, which costs only the straight route.
pub const STRAIGHT_VIEW_SECS: u64 = 30;
/// How long a splint command waits on hosts for what's kept for them, before doing what it was asked.
const SEND_AGAIN_WAIT: Duration = Duration::from_secs(5);
/// How long something for an agent's Signet is kept for its host, which keeps one no longer itself.
/// Rules are kept until the host takes them, as nothing ends them but newer ones.
const KEEP_MAIL_SECS: u64 = 7 * 24 * 60 * 60;

/// How the owner's side reached an agent's Signet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "way", content = "at")]
pub enum Route {
    /// Through its own socket, on this computer.
    ThisComputer,
    /// Over the network, at the address the owner named.
    Network(String),
    /// By way of its host.
    Host,
}

impl Route {
    /// For a header, in a word.
    pub fn word(&self) -> &'static str {
        match self {
            Self::ThisComputer => "this-computer",
            Self::Network(_) => "network",
            Self::Host => "host",
        }
    }

    pub fn words(&self) -> String {
        match self {
            Self::ThisComputer => "straight to its Signet on this computer".to_owned(),
            Self::Network(at) => format!("straight to its Signet at {at}"),
            Self::Host => "by way of its host".to_owned(),
        }
    }
}

/// An agent's Signet that the owner's side can reach without its host.
pub struct Direct {
    way: Way,
}

enum Way {
    /// One of the person's own agents on this computer, as a profile or the default.
    Socket {
        home: Home,
        installed: Box<Installed>,
    },
    /// At the address the owner named, sealed to the agent named there.
    Network {
        at: SocketAddr,
        agent: Box<Identity>,
        http: reqwest::Client,
    },
}

/// What a refusal straight from Signet means: on its own socket it's Signet's answer, and on the
/// network it might be anyone's, so it's as if nothing answered.
pub enum NotTaken {
    Refused(Failure),
    Unanswered,
}

/// An address the owner named for reaching an agent's Signet over the network.
#[derive(Clone, Serialize, Deserialize)]
struct Named {
    address: String,
    identity: String,
    at: String,
}

/// Whether this agent's Signet is reached here: by its socket, or on Windows, where its pipe is no
/// file to look for, by the lock it holds while it runs, which is what every call there checks first.
fn signet_listens_here(home: &Home) -> bool {
    #[cfg(unix)]
    {
        home.signet_socket().exists()
    }
    #[cfg(windows)]
    {
        splint_core::private_files::pipe::is_held(&home.signet_lock())
    }
}

#[derive(Serialize, Deserialize)]
struct Reached {
    route: Route,
    at: u64,
}

impl Direct {
    /// The agent's Signet on this computer, or else at the address its owner named, if either.
    pub fn find(home: &Home, agent: &SplintId) -> Result<Option<Self>, Failure> {
        for one in home.every()? {
            // Another profile's setup that can't be read isn't this one.
            let Ok(Some(installed)) = Installed::load(&one) else {
                continue;
            };
            if installed.agent.as_ref() == Some(agent) && signet_listens_here(&one) {
                return Ok(Some(Self {
                    way: Way::Socket {
                        home: one,
                        installed: Box::new(installed),
                    },
                }));
            }
        }
        let Some(named) = named(home)?.remove(agent.as_str()) else {
            return Ok(None);
        };
        // Checked again here, so a file changed by hand can't name another agent's keys.
        let identity = Identity::from_encoded(&named.identity)
            .ok()
            .filter(|identity| identity.id() == agent);
        let (Some(identity), Ok(at)) = (identity, named.at.parse::<SocketAddr>()) else {
            return Ok(None);
        };
        Ok(Some(Self {
            way: Way::Network {
                at,
                agent: Box::new(identity),
                http: reqwest::Client::builder()
                    .timeout(NETWORK_TIMEOUT)
                    .redirect(redirect::Policy::none())
                    // It's plain HTTP, and what a proxy would see is only sealed, but it'd see it.
                    .no_proxy()
                    .default_headers(speaking_ours())
                    .build()?,
            },
        }))
    }

    pub fn route(&self) -> Route {
        match &self.way {
            Way::Socket { .. } => Route::ThisComputer,
            Way::Network { at, .. } => Route::Network(at.to_string()),
        }
    }

    pub async fn put_rules(&self, rules: &str) -> Result<(), NotTaken> {
        self.send(Method::PUT, "/v0/owner/rules", &json!({ "rules": rules }))
            .await
    }

    pub async fn hand_over(&self, kind: OwnerMailKind, signed: &str) -> Result<(), NotTaken> {
        let (method, path, body) = match kind {
            OwnerMailKind::Approval => (
                Method::POST,
                "/v0/owner/approvals",
                json!({ "approval": signed }),
            ),
            OwnerMailKind::Acceptance => (
                Method::POST,
                "/v0/owner/changes/accept",
                json!({ "acceptance": signed }),
            ),
            OwnerMailKind::PersonText => (
                Method::POST,
                "/v0/owner/person-text",
                json!({ "person_text": signed }),
            ),
            OwnerMailKind::Delegation => (
                Method::PUT,
                "/v0/owner/delegation",
                json!({ "delegation": signed }),
            ),
            OwnerMailKind::WherePaid => (
                Method::POST,
                "/v0/owner/where-paid",
                json!({ "where_paid": signed }),
            ),
        };
        self.send(method, path, &body).await
    }

    /// The rules its Signet goes by, for a change to start from, read only from a Signet on this
    /// computer: they're the owner's signature alone, which the caller checks, and nothing on the
    /// network hands them out unsealed.
    pub async fn rules(&self) -> Option<Result<HeldRules, Failure>> {
        match &self.way {
            Way::Socket { home, installed } => Some(match SignetApi::new(home, installed) {
                Ok(api) => api.owner_read::<HeldRules>(RULES_AT_SIGNET).await,
                Err(failure) => Err(failure),
            }),
            Way::Network { .. } => None,
        }
    }

    /// The view as its Signet would leave it at its host now, signed and sealed to the owner, for the
    /// caller to open and check.
    pub async fn view(&self) -> Option<String> {
        match &self.way {
            Way::Socket { home, installed } => SignetApi::new(home, installed)
                .ok()?
                .owner_view()
                .await
                .ok(),
            Way::Network { at, http, .. } => {
                let mut answer = http
                    .get(format!("http://{at}{OWNER_VIEW_CALL_PATH}"))
                    .send()
                    .await
                    .ok()?;
                if !answer.status().is_success() || !same_protocol(&answer) {
                    return None;
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = answer.chunk().await.ok()? {
                    bytes.extend_from_slice(&chunk);
                    if bytes.len() > MAX_VIEW_ANSWER_BYTES {
                        return None;
                    }
                }
                let view: OwnerView = serde_json::from_slice(&bytes).ok()?;
                Some(view.view)
            }
        }
    }

    async fn send(&self, method: Method, path: &str, body: &Value) -> Result<(), NotTaken> {
        match &self.way {
            Way::Socket { home, installed } => {
                let api = SignetApi::new(home, installed).map_err(|_| NotTaken::Unanswered)?;
                api.owner_send(method, path, body)
                    .await
                    .map_err(|failure| match failure {
                        Failure::Refused(_) => NotTaken::Refused(failure),
                        _ => NotTaken::Unanswered,
                    })
            }
            Way::Network { at, agent, http } => {
                let plain = serde_json::to_vec(body).map_err(|_| NotTaken::Unanswered)?;
                let sealed = seal_owner_call(agent, method.as_str(), path, &plain)
                    .map_err(|_| NotTaken::Unanswered)?;
                let answer = http
                    .request(method, format!("http://{at}{path}"))
                    .json(&sealed)
                    .send()
                    .await
                    .map_err(|_| NotTaken::Unanswered)?;
                if answer.status().is_success() && same_protocol(&answer) {
                    Ok(())
                } else {
                    Err(NotTaken::Unanswered)
                }
            }
        }
    }
}

fn same_protocol(answer: &reqwest::Response) -> bool {
    other_protocol(answer.headers()).is_none()
}

fn named(home: &Home) -> Result<BTreeMap<String, Named>, Failure> {
    match fs::read(home.direct_file()) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| Failure::refused("direct.json in the Splint folder can't be read")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error.into()),
    }
}

/// Names where the owner's side reaches `agent`'s Signet over the network, or with `None`, stops.
/// The address is the operator's, and only a LAN or VPN address they turned on makes sense here.
pub fn name_address(
    home: &Home,
    agent: &Identity,
    address: &str,
    at: Option<SocketAddr>,
) -> Result<(), Failure> {
    let mut all = named(home)?;
    match at {
        Some(at) => {
            all.insert(
                agent.id().to_string(),
                Named {
                    address: address.to_owned(),
                    identity: agent.encoded(),
                    at: at.to_string(),
                },
            );
        }
        None => {
            all.remove(agent.id().as_str());
        }
    }
    let bytes = serde_json::to_vec_pretty(&all)
        .map_err(|_| Failure::refused("couldn't write down where your agents' Signets are"))?;
    write_private(&home.direct_file(), &bytes)?;
    Ok(())
}

/// Writes down how `agent` was reached just now, for `splint agents` to say. Only a convenience, so
/// a failure to write it changes nothing.
pub fn note(home: &Home, agent: &SplintId, route: Route) {
    let mut all: BTreeMap<String, Reached> = fs::read(home.routes_file())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    all.insert(
        agent.to_string(),
        Reached {
            route,
            at: unix_now(),
        },
    );
    if let Ok(bytes) = serde_json::to_vec_pretty(&all) {
        let _ = write_private(&home.routes_file(), &bytes);
    }
}

/// How `agent` was last reached, and when.
pub fn last_reached(home: &Home, agent: &SplintId) -> Option<(Route, u64)> {
    let mut all: BTreeMap<String, Reached> = fs::read(home.routes_file())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())?;
    all.remove(agent.as_str())
        .map(|reached| (reached.route, reached.at))
}

/// `splint for HANDLE~HOST direct IP:PORT`, or `direct off`: where the owner's side reaches that
/// agent's Signet over the network first, as its operator turned on, and whether it answers there now.
pub async fn name_for(home: &Home, address: &str, at: &str) -> Result<String, Failure> {
    let at = match at {
        "off" => None,
        at => Some(
            at.parse::<SocketAddr>()
                .ok()
                .filter(|at| at.port() != 0 && !every_address(at.ip()))
                .ok_or_else(|| {
                    Failure::refused(
                        "that isn't an IP address and a port, such as 192.168.1.20:7491, so nothing \
                         changed",
                    )
                })?,
        ),
    };
    // What this device signed for is known here. Any other is looked up, and its ID checks its keys,
    // so a host naming the wrong agent only names an address nothing here goes to for this one.
    let identity = match crate::authorize::named(home, address) {
        Ok(record) => Identity::from_encoded(record.identity())?,
        Err(_) => {
            let (_, domain) = splint_core::parse_address(address)?;
            let found = crate::host_calls::HostCalls::new(domain)?
                .resolve(address)
                .await?;
            Identity::from_encoded(&found.identity)?
        }
    };
    name_address(home, &identity, address, at)?;
    let Some(at) = at else {
        return Ok(format!(
            "Your side reaches {address} by way of its host now, unless it runs on this computer."
        ));
    };
    let answers = match Direct::find(home, identity.id())? {
        Some(direct) if direct.route() == Route::Network(at.to_string()) => {
            direct.view().await.is_some()
        }
        _ => false,
    };
    Ok(if answers {
        format!(
            "Your side reaches {address}'s Signet at {at} first now, and it answers there. What you \
             sign goes to its host as well, and is done once the host has it, and what you read comes \
             from its host when {at} doesn't answer."
        )
    } else {
        format!(
            "Your side tries {address}'s Signet at {at} first now, though nothing answers there yet: \
             its operator turns that on with splint network-access on {at}. Until then everything goes \
             by way of its host, as before."
        )
    })
}

/// How long ago, roughly, in words.
pub fn ago(secs: u64) -> String {
    let (count, unit) = match secs {
        0..120 => (secs, "second"),
        120..7200 => (secs / 60, "minute"),
        7200..172_800 => (secs / 3600, "hour"),
        _ => (secs / 86_400, "day"),
    };
    format!("{count} {unit}{}", if count == 1 { "" } else { "s" })
}

/// Whether an address is every one a machine has, `[::ffff:0.0.0.0]` too, which listens on all of
/// them though Rust's `is_unspecified` says it isn't.
pub fn every_address(ip: IpAddr) -> bool {
    ip.to_canonical().is_unspecified()
}

/// Whether a view read straight just now, signed at `issued_at` by the agent's clock, is one its Signet
/// signed as it was asked, and no older than one read here before. Anyone on the way could hand back a
/// copy they kept.
pub fn fresh_enough(home: &Home, agent: &SplintId, issued_at: u64) -> bool {
    fresh(issued_at, newest_view(home, agent), unix_now())
}

/// Each half refuses a copy the other can't: the age one kept after the newest read here, and the
/// newest-read one kept within the last moment.
fn fresh(issued_at: u64, newest: Option<u64>, now: u64) -> bool {
    issued_at.saturating_add(STRAIGHT_VIEW_SECS) >= now
        && newest.is_none_or(|newest| issued_at >= newest)
}

fn views(home: &Home) -> BTreeMap<String, u64> {
    fs::read(home.views_file())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn newest_view(home: &Home, agent: &SplintId) -> Option<u64> {
    views(home).remove(agent.as_str())
}

/// Writes down when the newest view read here for `agent` was signed. Only ever later.
pub fn saw_view(home: &Home, agent: &SplintId, issued_at: u64) {
    let mut all = views(home);
    if all
        .get(agent.as_str())
        .is_some_and(|newest| *newest >= issued_at)
    {
        return;
    }
    all.insert(agent.to_string(), issued_at);
    if let Ok(bytes) = serde_json::to_vec_pretty(&all) {
        let _ = write_private(&home.views_file(), &bytes);
    }
}

/// What the owner signs for an agent, all of which goes to its host whatever answered straight. Rules
/// and where the owner gets paid count only once the host has them, and the rest reaches the agent for
/// sure only by way of its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForHost {
    Rules,
    WherePaid,
    Approval,
    Acceptance,
    PersonText,
    Delegation,
}

impl ForHost {
    pub fn of(kind: OwnerMailKind) -> Self {
        match kind {
            OwnerMailKind::Approval => Self::Approval,
            OwnerMailKind::Acceptance => Self::Acceptance,
            OwnerMailKind::PersonText => Self::PersonText,
            OwnerMailKind::Delegation => Self::Delegation,
            OwnerMailKind::WherePaid => Self::WherePaid,
        }
    }

    /// What a host takes it as, for its agent's Signet to collect. Rules have a call of their own.
    fn mail(self) -> Option<OwnerMailKind> {
        match self {
            Self::Rules => None,
            Self::WherePaid => Some(OwnerMailKind::WherePaid),
            Self::Approval => Some(OwnerMailKind::Approval),
            Self::Acceptance => Some(OwnerMailKind::Acceptance),
            Self::PersonText => Some(OwnerMailKind::PersonText),
            Self::Delegation => Some(OwnerMailKind::Delegation),
        }
    }

    /// Where one is kept. A newer one of these replaces an older one of its kind for that agent, as it
    /// does wherever it's taken. An answer, a yes to a change and words are each for their own
    /// request, contact or place, so each is kept by what was signed.
    fn file(self, home: &Home, agent: &SplintId, signed: &str) -> PathBuf {
        let name = match self {
            Self::Rules => format!("{agent}.rules.json"),
            Self::WherePaid => format!("{agent}.where-paid.json"),
            Self::Delegation => format!("{agent}.delegation.json"),
            Self::Approval => format!("{agent}.approval.{}.json", owner_mail_item(signed)),
            Self::Acceptance => format!("{agent}.acceptance.{}.json", owner_mail_item(signed)),
            Self::PersonText => format!("{agent}.person-text.{}.json", owner_mail_item(signed)),
        };
        home.not_at_host_dir().join(name)
    }

    pub fn words(self) -> &'static str {
        match self {
            Self::Rules => "the rules",
            Self::WherePaid => "where you get paid",
            Self::Approval => "what you answered",
            Self::Acceptance => "your yes to a contact's change",
            Self::PersonText => "your words",
            Self::Delegation => "the delegation",
        }
    }

    pub fn them(self) -> &'static str {
        match self {
            Self::Rules | Self::PersonText => "them",
            Self::WherePaid | Self::Approval | Self::Acceptance | Self::Delegation => "it",
        }
    }

    /// Why its host has to have it, whatever answered straight.
    fn why_its_host(self) -> &'static str {
        match self {
            Self::Rules | Self::WherePaid => "which is what counts",
            Self::Approval | Self::Acceptance | Self::PersonText | Self::Delegation => {
                "which is what reaches your agent whoever answered there"
            }
        }
    }
}

/// One thing the owner signed, as it went: what it is, what was signed, and for an agent's Signet, the
/// body that leaves it at its host, which is it sealed to the agent. Rules go to a host as they're
/// signed, as a host enforces them, so they have none.
pub struct Sent<'a> {
    pub kind: ForHost,
    pub signed: &'a str,
    pub sealed: Option<&'a str>,
}

/// One thing kept for an agent's host, with where that host is.
#[derive(Serialize, Deserialize)]
struct Kept {
    agent: SplintId,
    kind: ForHost,
    domain: String,
    /// What was signed, which names the file and tells one kept thing from a newer one.
    signed: String,
    /// For an agent's Signet: the body that leaves it at the host, sealed to the agent, which is all
    /// that's sent there. The proof it went with isn't kept, as one is good only for moments.
    #[serde(default)]
    sealed: Option<String>,
}

/// Keeps what only a straight answer took, until its host takes it.
pub fn keep_for_host(
    home: &Home,
    agent: &SplintId,
    domain: &str,
    sent: &Sent<'_>,
) -> Result<(), Failure> {
    Home::make_private(&home.not_at_host_dir())?;
    let kept = Kept {
        agent: agent.clone(),
        kind: sent.kind,
        domain: domain.to_owned(),
        signed: sent.signed.to_owned(),
        sealed: sent.sealed.map(str::to_owned),
    };
    let bytes = serde_json::to_vec(&kept)
        .map_err(|_| Failure::refused("couldn't keep that for the agent's host"))?;
    write_private(&sent.kind.file(home, agent, sent.signed), &bytes)?;
    Ok(())
}

/// The host took this for `agent`, so it isn't kept, nor is an older one it replaces.
pub fn taken_by_host(home: &Home, agent: &SplintId, kind: ForHost, signed: &str) {
    let _ = fs::remove_file(kind.file(home, agent, signed));
}

/// Everything kept for hosts, with the file each is in. A file named for another agent, kind or thing
/// signed than it holds isn't one this wrote.
fn all_kept(home: &Home) -> Vec<(PathBuf, Kept)> {
    let Ok(entries) = fs::read_dir(home.not_at_host_dir()) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let kept: Kept = serde_json::from_slice(&fs::read(&path).ok()?).ok()?;
            (path == kept.kind.file(home, &kept.agent, &kept.signed)).then_some((path, kept))
        })
        .collect()
}

/// What's kept for `agent`'s host, of each kind.
pub fn not_at_host(home: &Home, agent: &SplintId) -> Vec<ForHost> {
    let mut kinds: Vec<ForHost> = all_kept(home)
        .into_iter()
        .filter(|(_, kept)| &kept.agent == agent)
        .map(|(_, kept)| kept.kind)
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

/// What became of one thing kept for a host, sent again.
pub enum SentAgain {
    Taken(SplintId, ForHost),
    /// The host said no, which it would say again, so it isn't kept. Newer rules than these is one
    /// reason, and so is something for its Signet that was kept here longer than anything is.
    Refused(SplintId, ForHost, Failure),
    StillAway,
}

/// Whether something kept in this file for an agent's Signet has been there longer than its host
/// would take it, by when the file was written, which is when it was signed.
fn kept_too_long(path: &std::path::Path, kind: ForHost, now: u64) -> bool {
    let written = fs::metadata(path)
        .and_then(|file| file.modified())
        .ok()
        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|since| since.as_secs());
    kind.mail().is_some()
        && written.is_some_and(|written| written.saturating_add(KEEP_MAIL_SECS) < now)
}

/// What became of sending one kept thing to its host again.
enum Again {
    Said(Result<(), Failure>),
    /// Nothing here could sign for leaving it there just now, so it's still kept.
    NoProofYet,
}

/// Who's there to sign a fresh proof for leaving kept owner mail at its host again. A proof is good
/// only for moments, so none is kept with the sealed bytes, and each is over those same bytes.
#[derive(Clone, Copy)]
pub enum Proves<'a> {
    /// Nobody: something running by itself, as `splint auto` does. Only an owner key that signs with
    /// nobody there does, a plain key file, as `splint authorize` and `setup` keep one.
    NobodyThere,
    /// The person, who just ran a command at a terminal here, and what their sign-in signed when it
    /// asked them, as the chip does: the one thing `asked_of_person` says.
    PersonHere(&'a ByPerson),
    /// Splint on this computer, for its page: a session it keeps at that host, which costs no
    /// prompt, or else a key file here that signs with nobody there.
    Computer(&'a crate::computer::Computer),
}

/// What the person's sign-in signed, once it had asked them, to leave one kept thing at its host again.
pub struct ByPerson {
    /// What that kept thing is, signed, which tells it from the rest.
    signed: String,
    mail: SealedMail,
}

/// A proof by the owner key in `owner_key` for leaving these sealed bytes at their host again, where
/// it signs with nobody there. The chip asks for the person, and a locked file's passphrase is theirs
/// to type, into something that asks them for it.
fn by_owner_key(owner_key: &OwnerKey, kept: &Kept, body: &str) -> Option<SealedMail> {
    if owner_key.sign_in()? != SignIn::PlainFile {
        return None;
    }
    let proof = owner_key
        .leaving_again(&kept.domain, &owner_mail_path(&kept.agent), body)
        .ok()?;
    Some(SealedMail {
        body: body.to_owned(),
        proof,
        session: None,
    })
}

/// Every proof made with nobody asked that could leave these sealed bytes at their host again, in the
/// order they're tried: one a host answers 401 isn't its owner's as that host has them, and the next
/// may be.
async fn proofs_to_leave_again(
    home: &Home,
    kept: &Kept,
    body: &str,
    proves: Proves<'_>,
) -> Vec<SealedMail> {
    let mut proofs = Vec::new();
    let path = owner_mail_path(&kept.agent);
    if let Proves::Computer(computer) = proves {
        if let Some(mail) = computer.mail_by_session(&kept.domain, &path, body).await {
            proofs.push(mail);
        }
        proofs.extend(by_owner_key(&computer.owner_key(), kept, body));
    }
    proofs.extend(by_owner_key(&OwnerKey::new(home), kept, body));
    proofs
}

/// The first thing kept for a host that the person at a terminal could be asked to sign for leaving
/// there again, with the sealed bytes that would leave it. Only where the sign-in here asks for them,
/// as the chip does, only for an agent this device signs for, as something another sign-in kept would
/// be refused and ask them again at every command, and only once its host has answered, so they
/// aren't asked to sign for a host that's away, which would ask them again at every command until
/// it's back.
async fn to_ask_person_for(home: &Home) -> Option<(Kept, String)> {
    if OwnerKey::new(home).sign_in()? != SignIn::Chip {
        return None;
    }
    let records = crate::authorize::all(home).ok()?;
    let mut away: Vec<String> = Vec::new();
    for (path, kept) in all_kept(home) {
        let Some(kind) = kept.kind.mail() else {
            continue;
        };
        if kept_too_long(&path, kept.kind, unix_now())
            || away.contains(&kept.domain)
            || !records.iter().any(|record| record.agent == kept.agent)
        {
            continue;
        }
        let answers = match HostCalls::new(&kept.domain) {
            Ok(host) => host.answers().await,
            Err(_) => false,
        };
        if !answers {
            away.push(kept.domain);
            continue;
        }
        let body = match kept.sealed.clone() {
            Some(body) => Some(body),
            None => sealed_now(home, &kept, kind).await,
        };
        if let Some(body) = body {
            return Some((kept, body));
        }
    }
    None
}

/// Asks the person to sign for leaving that one kept thing at its host again, in words that say what
/// for. Once a run at most, so however much is kept, a command asks for one touch. One they don't
/// give leaves it kept.
fn asked_of_person(home: &Home, kept: Kept, body: String) -> Option<ByPerson> {
    let proof = OwnerKey::new(home)
        .leaving_again(&kept.domain, &owner_mail_path(&kept.agent), &body)
        .ok()?;
    Some(ByPerson {
        signed: kept.signed,
        mail: SealedMail {
            body,
            proof,
            session: None,
        },
    })
}

/// What an owner signed for an agent's Signet, kept by a release from before owner mail was sealed,
/// sealed now as their device would seal it: to the ID this device holds for that agent, or a newer
/// one its host gives that carries it on. With no copy of the ID here there's nothing to hold a
/// host's answer to, so it isn't sealed to one.
async fn sealed_now(home: &Home, kept: &Kept, kind: OwnerMailKind) -> Option<String> {
    let record = crate::authorize::all(home)
        .ok()?
        .into_iter()
        .find(|record| record.agent == kept.agent)?;
    let here = Identity::from_encoded(record.identity()).ok()?;
    let found = match HostCalls::new(&kept.domain) {
        Ok(host) => tokio::time::timeout(SEND_AGAIN_WAIT, host.resolve(&record.address))
            .await
            .ok()
            .and_then(Result::ok),
        Err(_) => None,
    };
    let agent = crate::owner_side::agent_to_seal_to(
        here,
        found.as_ref().map(|found| found.identity.as_str()),
    );
    let mail = OwnerMail {
        kind,
        signed: kept.signed.clone(),
    };
    let sealed = seal_owner_mail(&agent, &mail).ok()?;
    String::from_utf8(mail_body(&sealed).ok()?).ok()
}

/// What a host said to one thing kept for it, sent again. One with no such agent took nothing.
async fn at_its_host(home: &Home, kept: &Kept, proves: Proves<'_>) -> Again {
    let host = match HostCalls::new(&kept.domain) {
        Ok(host) => host,
        Err(failure) => return Again::Said(Err(failure)),
    };
    let said = match kept.kind.mail() {
        None => host.put_rules(&kept.signed).await,
        Some(kind) => {
            let by_person = match proves {
                Proves::PersonHere(by_person) if by_person.signed == kept.signed => {
                    Some(by_person.mail.clone())
                }
                _ => None,
            };
            let proofs = match by_person {
                // Over the bytes the person signed for, which are these sealed.
                Some(mail) => vec![mail],
                None => {
                    let body = match &kept.sealed {
                        Some(body) => Some(body.clone()),
                        None => sealed_now(home, kept, kind).await,
                    };
                    let Some(body) = body else {
                        return Again::Said(Err(Failure::refused(
                            "it was kept before what's left at a host was sealed, and this device \
                             has no copy of that agent's ID to seal it to, so sign it again if it's \
                             still wanted",
                        )));
                    };
                    proofs_to_leave_again(home, kept, &body, proves).await
                }
            };
            let mut said = None;
            for mail in proofs {
                match host.leave_owner_mail(&kept.agent, &mail).await {
                    // That proof wasn't taken, which says nothing of what's kept: another of the
                    // owner's sign-ins may have left it, whose proof this one's isn't.
                    Err(Failure::HostRefused(StatusCode::UNAUTHORIZED)) => {}
                    other => {
                        said = Some(other);
                        break;
                    }
                }
            }
            match said {
                Some(said) => said,
                None => return Again::NoProofYet,
            }
        }
    };
    Again::Said(match said {
        Ok(Delivered::Taken) => Ok(()),
        Ok(Delivered::NoSuchAgent) => Err(Failure::refused(
            "its host doesn't have that agent, so nothing changed",
        )),
        Err(failure) => Err(failure),
    })
}

/// Sends everything kept for a host to it again, and keeps only what it still couldn't take.
pub async fn send_again(home: &Home, proves: Proves<'_>) -> Vec<SentAgain> {
    let mut done = Vec::new();
    // A host that didn't answer for one thing isn't asked again for the rest this time round.
    let mut away: Vec<String> = Vec::new();
    for (path, kept) in all_kept(home) {
        // Before whether its host is there, so one too old goes whether or not it is.
        let at_host = if kept_too_long(&path, kept.kind, unix_now()) {
            Err(Failure::refused(
                "it was signed more than 7 days ago, and nothing is kept for a host that long, so \
                 sign it again if it's still wanted",
            ))
        } else if away.contains(&kept.domain) {
            done.push(SentAgain::StillAway);
            continue;
        } else {
            match at_its_host(home, &kept, proves).await {
                Again::Said(said) => said,
                Again::NoProofYet => {
                    done.push(SentAgain::StillAway);
                    continue;
                }
            }
        };
        // Only if it's still what was sent, as a newer one kept meanwhile has yet to go.
        let still_this = || {
            fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Kept>(&bytes).ok())
                .is_some_and(|now| now.signed == kept.signed)
        };
        done.push(match at_host {
            Err(Failure::HostUnreachable(_)) => {
                away.push(kept.domain);
                SentAgain::StillAway
            }
            // At its limit for now, which may be for this agent alone, so the rest are still sent.
            Err(Failure::HostRefused(StatusCode::TOO_MANY_REQUESTS)) => SentAgain::StillAway,
            Ok(()) => {
                if still_this() {
                    let _ = fs::remove_file(&path);
                }
                note(home, &kept.agent, Route::Host);
                SentAgain::Taken(kept.agent, kept.kind)
            }
            Err(failure) => {
                if still_this() {
                    let _ = fs::remove_file(&path);
                }
                SentAgain::Refused(kept.agent, kept.kind, failure)
            }
        });
    }
    done
}

/// `send_again`, waiting on hosts only a moment, for a command the person ran, which is about to do
/// something else. A person at a terminal whose sign-in asks for them is asked once at most, and the
/// time they take isn't counted as a host's, so what they signed is still sent however long that was.
pub async fn send_again_briefly(home: &Home) {
    if !fs::read_dir(home.not_at_host_dir()).is_ok_and(|mut entries| entries.next().is_some()) {
        return;
    }
    let started = Instant::now();
    // Only a terminal has a person at it: an agent or a script running splint here isn't asked.
    let to_ask = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        tokio::time::timeout(SEND_AGAIN_WAIT, to_ask_person_for(home))
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let left = SEND_AGAIN_WAIT.saturating_sub(started.elapsed());
    let by_person = to_ask.and_then(|(kept, body)| asked_of_person(home, kept, body));
    // What a person just signed for gets the whole wait, whatever finding its host there took.
    let (proves, wait) = match &by_person {
        Some(by_person) => (Proves::PersonHere(by_person), SEND_AGAIN_WAIT),
        None => (Proves::NobodyThere, left),
    };
    let _ = tokio::time::timeout(wait, send_again(home, proves)).await;
}

/// What the owner's side makes of sending something the owner signed straight and to the agent's host:
/// done once the host takes it, whichever way it went first. Where only a straight answer said yes,
/// that answer could be anyone's, so the owner is told what the host said too. A host that couldn't be
/// reached, or was at its limit for now, gets it again: it's kept, and the owner is told it isn't
/// confirmed. A host that refused it would again, so nothing is kept, and the owner is told that it
/// went straight and that its host refused it, never that nothing changed. With no straight answer,
/// it's the host's answer alone.
pub fn settle(
    home: &Home,
    agent: &SplintId,
    address: &str,
    sent: &Sent<'_>,
    straight: Option<Route>,
    at_host: Result<Delivered, Failure>,
) -> Result<Route, Failure> {
    let (_, domain) = splint_core::parse_address(address)?;
    let kind = sent.kind;
    let not_taken = match at_host {
        Ok(Delivered::Taken) => {
            taken_by_host(home, agent, kind, sent.signed);
            let route = straight.unwrap_or(Route::Host);
            note(home, agent, route.clone());
            return Ok(route);
        }
        // Rules count only at the host, and it has none of an agent that's yet to finish joining.
        Ok(Delivered::NoSuchAgent) if kind.mail().is_none() => {
            return Err(Failure::refused(
                "that agent hasn't finished joining yet, so nothing changed: ask it to run the \
                 line you gave it",
            ));
        }
        Ok(Delivered::NoSuchAgent) => Failure::HostRefused(StatusCode::NOT_FOUND),
        Err(failure) => failure,
    };
    let Some(route) = straight else {
        return Err(match not_taken {
            Failure::HostRefused(StatusCode::NOT_FOUND) => {
                Failure::refused("that agent's host doesn't have it, so nothing changed")
            }
            // It went sealed, with the owner's proof, and is never sent any other way.
            Failure::HostRefused(status)
                if kind.mail().is_some() && status != StatusCode::TOO_MANY_REQUESTS =>
            {
                Failure::refused(format!(
                    "this agent's host answered {status}: it refused that, or is older than this \
                     release, so nothing was left there"
                ))
            }
            failure => failure,
        });
    };
    let (what, how, them) = (kind.words(), route.words(), kind.them());
    let said = match not_taken {
        Failure::HostUnreachable(_) => Err("couldn't be reached"),
        Failure::HostRefused(StatusCode::TOO_MANY_REQUESTS) => Err("is at its limit for now"),
        Failure::HostRefused(StatusCode::NOT_FOUND) => Ok("doesn't have that agent".to_owned()),
        Failure::HostRefused(status) => Ok(format!("answered {status}")),
        // Nothing the host said about what was sent, such as a host this splint can't work with.
        failure => return Err(failure),
    };
    note(home, agent, route);
    match said {
        Err(for_now) => {
            keep_for_host(home, agent, domain, sent)?;
            Err(Failure::NotYetAtHost(format!(
                "signed, but not confirmed yet: {what} went {how}, where whatever answered said \
                 it took {them}, which anything answering there could say. {address}'s host, \
                 {why}, {for_now}, so this device sends {them} to it again each time splint runs \
                 here, and while splint auto runs, until it takes {them}. splint agents says \
                 what's still waiting",
                why = kind.why_its_host(),
            )))
        }
        Ok(said) => Err(Failure::refused(format!(
            "signed, but {address}'s host {said}, and would say so again, so nothing is kept to \
             send {them} again: {what} went {how} first, where whatever answered said it took \
             {them}. If that was your agent's Signet, it has {them}, and if it wasn't, nothing \
             does"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bugs caught (by mutation): either half of the check dropped, as the other alone let through the
    // copy only it refuses.
    #[test]
    fn a_view_read_straight_is_taken_only_if_just_signed_and_not_older_than_one_seen() {
        let now = 1_800_000_000;
        assert!(fresh(now - STRAIGHT_VIEW_SECS, None, now));
        assert!(fresh(now, Some(now), now));
        // Kept after the newest read here, and handed back more than a moment later.
        assert!(!fresh(now - STRAIGHT_VIEW_SECS - 1, None, now));
        assert!(!fresh(now - STRAIGHT_VIEW_SECS - 1, Some(now - 100), now));
        // Kept within the moment, but a newer one has been read here since.
        assert!(!fresh(now - 2, Some(now - 1), now));
    }
}

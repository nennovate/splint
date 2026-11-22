//! The calls this program makes to its own Signet, from `docs/protocol.md`.

use std::path::PathBuf;
use std::time::Duration;

use reqwest::{Method, RequestBuilder, Response, StatusCode, redirect};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use splint_core::contact_invites::PendingContact;
use splint_core::host_api::{JoinLimit, OwnerView, SignupCodeRefused};
use splint_core::owner_call::OWNER_VIEW_CALL_PATH;
use splint_core::registration_state::{HOST_UNREACHABLE, NOT_REGISTERED_YET, RegistrationState};
use splint_core::release::{Behind, RELEASE_PATH, Release};
use splint_core::requests::{InteractionType, Schema};
use splint_core::rules::PinnedBy;
use splint_core::{SplintId, parse_address};

use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::release::{other_protocol, speaking_ours};

/// Signet may be calling its host, which may be down, and has 5 seconds a try.
const TIMEOUT: Duration = Duration::from_secs(20);
/// For the agent's calls that Signet answers by reading a host page as it goes: up to two pages in one
/// call, such as its inbox and its invites box, with 133 seconds each, as a flooded inbox's 32 MiB
/// takes that long on a slow line. Under this, such a call ran out on every try, though Signet itself
/// could still read the page, and the agent could never read or clear its inbox. Provisional.
const PAGE_TIMEOUT: Duration = Duration::from_secs(300);
/// As long as a Signet's first try at its host can take: the host's own 5 seconds, and as long again
/// for a statement from its owner that was going through.
const FIRST_TRY: Duration = Duration::from_secs(15);
const LOOK_AGAIN: Duration = Duration::from_millis(100);
/// What an owner's device takes from one read, so a Signet can't use one to fill its memory.
const MAX_OWNER_READ_BYTES: usize = 32 * 1024 * 1024;

/// Only names the request: the socket is where it goes, and nothing resolves this.
const ORIGIN: &str = "http://signet";

pub struct SignetApi<'a> {
    installed: &'a Installed,
    http: reqwest::Client,
    /// Left by `splint stop`, which is why Signet isn't there to answer, while it's there.
    stopped_mark: PathBuf,
    /// Held by Signet while it runs, which on Windows is checked before anything is sent.
    #[cfg(windows)]
    signet_lock: PathBuf,
}

/// Why a call got no answer: only one that never reached Signet surely did nothing there.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Unanswered {
    NeverReached,
    /// It timed out or was dropped after it went, so it may have gone through.
    MayHaveGone,
}

impl Unanswered {
    fn of(error: &reqwest::Error) -> Self {
        if error.is_connect() {
            Self::NeverReached
        } else {
            Self::MayHaveGone
        }
    }
}

#[derive(Deserialize)]
pub struct Who {
    pub identity: String,
    pub agent_id: SplintId,
    pub registered: bool,
    /// How far signing on has got. A Signet from before this was said doesn't say.
    #[serde(default)]
    pub registration: Option<RegistrationState>,
    /// What its host last said while it hasn't taken this agent, in Signet's own fixed words.
    #[serde(default)]
    pub registration_problem: Option<String>,
    /// Whether its host answered the last look. A Signet from before this was said doesn't say.
    #[serde(default = "said_set")]
    pub host_answering: bool,
    /// Who it acts for now.
    #[serde(default)]
    pub owner_id: Option<SplintId>,
    /// False while its owner's ID has no recovery code. An older Signet doesn't say, which counts as set.
    #[serde(default = "said_set")]
    pub owner_recovery_set: bool,
    /// Whether its key isn't the one its ID holds now, so it waits for a recovery naming it.
    #[serde(default)]
    pub recovering: bool,
    /// Why its owner's rules stop it, as Signet's word, when they do.
    #[serde(default)]
    pub stopped: Option<String>,
    /// Its signing and sealing keys, as an owner's device takes them.
    pub key: String,
    pub address: String,
    /// Its Signet's delegate key, for the owner to sign a delegation to.
    pub delegate: String,
    #[serde(default, deserialize_with = "rules_at_host")]
    pub rules_at_host: Option<RulesAtHost>,
    /// When its host says it closes, as seconds since 1970. A Signet from before this says nothing.
    #[serde(default)]
    pub host_closing_at: Option<u64>,
}

fn said_set() -> bool {
    true
}

impl Who {
    /// Whether it holds a binding its host hasn't taken yet, and is still going to its host with it.
    pub fn keeps_trying(&self) -> bool {
        self.registration
            .is_some_and(RegistrationState::keeps_trying)
    }

    /// Whether it holds a binding that fits it, which is all that leaving its host takes.
    pub fn holds_a_binding(&self) -> bool {
        self.registered
            || self
                .registration
                .is_some_and(RegistrationState::holds_a_binding)
    }
}

/// What a Signet says its host did with the newest rules, as the host holds the agent's sends to the
/// last ones it took.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RulesAtHost {
    Taken,
    /// Down, busy, or not knowing this agent yet.
    NotYet,
    /// It said no, as an older host that can't read them does.
    Refused,
    OtherProtocol,
    /// It holds a later recovery or revocation for this agent.
    OutOfDate,
}

/// A word this release doesn't know counts as none, so a Signet can't put its own on an owner's screen.
fn rules_at_host<'de, D: Deserializer<'de>>(found: D) -> Result<Option<RulesAtHost>, D::Error> {
    let found: Option<String> = Option::deserialize(found)?;
    Ok(match found.as_deref() {
        Some("taken") => Some(RulesAtHost::Taken),
        Some("not_yet") => Some(RulesAtHost::NotYet),
        Some("refused") => Some(RulesAtHost::Refused),
        Some("other_protocol") => Some(RulesAtHost::OtherProtocol),
        Some("out_of_date") => Some(RulesAtHost::OutOfDate),
        _ => None,
    })
}

#[derive(Deserialize)]
struct RulesApplied {
    #[serde(default, deserialize_with = "rules_at_host")]
    host: Option<RulesAtHost>,
}

#[derive(Deserialize)]
pub struct Contact {
    pub address: String,
    #[serde(default)]
    pub agent: Option<SplintId>,
    /// A Signet from before this was said only had contacts the owner chose.
    #[serde(default = "chosen")]
    pub approved_by_owner: bool,
    /// False for someone the reach setting let in. A Signet from before this was said is taken to
    /// have none the agent agreed with, as before.
    #[serde(default)]
    pub known_contact: bool,
    /// How they came to be a contact. A Signet from before this was said is taken to mean the agent.
    #[serde(default)]
    pub pinned_by: Option<PinnedBy>,
}

fn chosen() -> bool {
    true
}

#[derive(Deserialize)]
struct ContactList {
    contacts: Vec<Contact>,
}

#[derive(Deserialize)]
struct TypeList {
    types: Vec<Agreed>,
}

/// One type agreed with one contact. Its schema is read, and its ID is worked out from it here.
#[derive(Deserialize)]
struct Agreed {
    agent: SplintId,
    schema: Schema,
}

/// Someone waiting for the owner, in a message held at the host. The address is what their owner
/// signed, when that checks out.
#[derive(Deserialize)]
pub struct Held {
    pub sender: SplintId,
    pub sender_owner: Option<SplintId>,
    #[serde(deserialize_with = "only_an_address")]
    pub address: Option<String>,
    pub kind: String,
    pub created_at: u64,
    /// For an invite both agents agreed to, what each signed. Nothing about it counts until it's
    /// checked here, as a Signet can say anything.
    #[serde(default)]
    pub invite: Option<PendingContact>,
}

/// Signet's word for an agent its owner retired at its host, once their signature there checks out.
const RETIRED: &str = "retired";
pub const RETIRED_WORDS: &str = "Your person retired you at your host, for good: you can't send or be \
     found, and nothing comes in. Running splint retire with your own address frees this folder for \
     another agent to join from.";

/// Anything that isn't an address counts as no address, so what a Signet says here can't put words on
/// an owner's screen or in a block's label.
fn only_an_address<'de, D: Deserializer<'de>>(found: D) -> Result<Option<String>, D::Error> {
    let found: Option<String> = Option::deserialize(found)?;
    Ok(found.filter(|address| parse_address(address).is_ok()))
}

#[derive(Deserialize)]
struct HeldPage {
    held: Vec<Held>,
}

/// What changed, in Signet's fixed words. These are the only ones, so nothing else a Signet says can
/// reach anyone woken by them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Changed {
    Requests,
    Messages,
    Owner,
}

impl Changed {
    pub fn word(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::Messages => "messages",
            Self::Owner => "owner",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        [Self::Requests, Self::Messages, Self::Owner]
            .into_iter()
            .find(|kind| kind.word() == word)
    }
}

/// Whether anything listens for this agent, as its Signet sees it, and how long its oldest unread
/// note has waited. Times are seconds since 1970, by Signet's own clock.
#[derive(Deserialize)]
pub struct Listening {
    pub wait_held: bool,
    pub last_wait_at: Option<u64>,
    pub last_read_at: Option<u64>,
    pub oldest_unread_at: Option<u64>,
    /// What waits at the host unread because Signet can't open or check it yet.
    #[serde(default)]
    pub held: Vec<HeldMail>,
}

/// Messages of one kind that wait at the host unread, as Signet counts them, with its fixed words on
/// why. Nothing of what they say is in it.
#[derive(Clone, Deserialize, serde::Serialize)]
pub struct HeldMail {
    pub kind: String,
    pub count: u64,
    pub why: String,
}

impl HeldMail {
    /// Each kind as one line, with only plain printable characters of what Signet said.
    pub fn lines(held: &[Self]) -> Vec<String> {
        let plain = |text: &str| -> String {
            text.chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .collect()
        };
        held.iter()
            .map(|one| {
                let wait = if one.count == 1 { "waits" } else { "wait" };
                format!(
                    "{} {wait} at your host unread ({}): {}.",
                    one.count,
                    plain(&one.kind),
                    plain(&one.why)
                )
            })
            .collect()
    }
}

/// A wait's answer: the mark to wait from next, and what changed since the one given.
pub struct Waited {
    pub since: u64,
    pub new: Vec<Changed>,
}

#[derive(Deserialize)]
struct WaitAnswer {
    since: u64,
    new: Vec<String>,
}

/// Room past a wait's own seconds for Signet's answer to come back.
const WAIT_SLACK: Duration = Duration::from_secs(15);

/// A refusal's word, and Signet's own fixed words on what to do about it, which go with it.
#[derive(Deserialize)]
struct Refusal {
    error: String,
    #[serde(default)]
    ask_your_owner: Option<String>,
    #[serde(default)]
    invite_with: Option<String>,
    #[serde(default)]
    what_to_do: Option<String>,
}

impl Refusal {
    fn said(self) -> String {
        match self.ask_your_owner.or(self.invite_with).or(self.what_to_do) {
            Some(what_to_do) => format!("{}: {what_to_do}", self.error),
            None => self.error,
        }
    }
}

impl<'a> SignetApi<'a> {
    /// Over this agent's socket, which only this user can reach. Nothing here calls a port, so no other
    /// program can be sent a token by taking one.
    pub fn new(home: &Home, installed: &'a Installed) -> Result<Self, Failure> {
        #[cfg(unix)]
        let api = Self::over(home.signet_socket(), home.stopped_mark(), installed);
        #[cfg(windows)]
        let api = Self::over(
            home.signet_socket(),
            home.stopped_mark(),
            home.signet_lock(),
            installed,
        );
        api
    }

    fn over(
        socket: PathBuf,
        stopped_mark: PathBuf,
        #[cfg(windows)] signet_lock: PathBuf,
        installed: &'a Installed,
    ) -> Result<Self, Failure> {
        let builder = reqwest::Client::builder();
        #[cfg(unix)]
        let builder = builder.unix_socket(socket);
        #[cfg(windows)]
        let builder = builder.windows_named_pipe(socket.into_os_string());
        Ok(Self {
            installed,
            http: builder
                // A proxy isn't used on a socket, but its password would still ride along in a header.
                .no_proxy()
                .timeout(TIMEOUT)
                .redirect(redirect::Policy::none())
                .default_headers(speaking_ours())
                .build()?,
            stopped_mark,
            #[cfg(windows)]
            signet_lock,
        })
    }

    /// Sends one call, or says whether it never reached Signet or may have.
    #[cfg(unix)]
    async fn sent(&self, call: RequestBuilder) -> Result<Response, Unanswered> {
        call.send().await.map_err(|error| Unanswered::of(&error))
    }

    /// On Windows any user can make a pipe with Signet's name while Signet is stopped, so this sends
    /// only while Signet's lock is held: then no other user can make an instance of its pipe.
    #[cfg(windows)]
    async fn sent(&self, call: RequestBuilder) -> Result<Response, Unanswered> {
        crate::pipes::send_while_served(&self.signet_lock, call)
            .await
            .map_err(|error| {
                error
                    .as_ref()
                    .map_or(Unanswered::NeverReached, Unanswered::of)
            })
    }

    fn call(&self, method: Method, path: &str) -> RequestBuilder {
        self.http.request(method, format!("{ORIGIN}{path}"))
    }

    fn as_agent(&self, path: &str) -> RequestBuilder {
        self.call(Method::GET, path)
            .bearer_auth(self.installed.api_token.expose())
            .timeout(deadline(&Method::GET, path))
    }

    /// Signet's own words on a refusal are fixed text, with nothing from a counterparty in them. One
    /// that isn't there because its person stopped it says so, so an agent leaves starting it to them.
    async fn answered(&self, sent: Result<Response, Unanswered>) -> Result<Response, Failure> {
        // Only a call that never reached Signet was surely not read, so only that one is said to be
        // safe to make again. A timeout or a dropped call may have reached Signet and gone through.
        let response = sent.map_err(|unanswered| {
            if self.stopped_mark.exists() {
                Failure::Stopped
            } else if unanswered == Unanswered::NeverReached {
                Failure::SignetUnreachable
            } else {
                Failure::SignetNoAnswer
            }
        })?;
        if let Some(other) = other_protocol(response.headers()) {
            // A Signet keeps running across an update, so an older one is the usual case.
            return Err(Failure::refused(match other.behind() {
                Some(Behind::Ours) => {
                    "this splint is from an older release than this agent's Signet, so use the \
                     splint installed beside it, or install the newest release"
                }
                _ => {
                    "this agent's Signet is from another release, so run splint stop, then \
                     splint start"
                }
            }));
        }
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let refusal = response.json::<Refusal>().await;
        if let Ok(refusal) = &refusal
            && (refusal.error == NOT_REGISTERED_YET || refusal.error == HOST_UNREACHABLE)
        {
            return Err(Failure::HostUnreachable(
                refusal.what_to_do.clone().unwrap_or_default(),
            ));
        }
        let why = refusal.map(Refusal::said);
        Err(Failure::refused(match (status, why) {
            (_, Ok(why)) => why,
            (StatusCode::UNAUTHORIZED, _) => "Signet refused this agent's token".to_owned(),
            (status, _) => format!("Signet answered {status}"),
        }))
    }

    /// What Signet says it runs. A changed Signet can say anything, so this is only for diagnosis.
    pub async fn release(&self) -> Result<Release, Failure> {
        let call = self.call(Method::GET, RELEASE_PATH);
        Ok(self.answered(self.sent(call).await).await?.json().await?)
    }

    /// Why nothing this agent sends goes out, in fixed words, when its owner paused it, their rules
    /// reached the end they gave them, or its key is being replaced. Only Signet's own words count, so nothing else it says
    /// reaches an agent this way.
    pub async fn stopped(&self) -> Option<&'static str> {
        match self.who().await.ok()?.stopped.as_deref()? {
            "paused" => Some(
                "Your person paused you from their controls, so nothing you send, invite, open or \
                 move goes out until they resume you.",
            ),
            "rules_ended" => Some(
                "Your person's rules for you reached the end they gave them, so nothing you send, \
                 invite, open or move goes out until they sign new ones.",
            ),
            "key_being_replaced" => Some(
                "Your key is being replaced, so nothing you send, invite, open or move goes out \
                 until your person's recovery names this Signet's key.",
            ),
            RETIRED => Some(RETIRED_WORDS),
            _ => None,
        }
    }

    /// When this agent's host says it closes, as its Signet last heard, if it does.
    pub async fn host_closing_at(&self) -> Option<u64> {
        self.who().await.ok()?.host_closing_at
    }

    /// Whether its owner retired this agent at its host, as Signet found their signature there says.
    /// A host's refusal alone never says so.
    pub async fn retired(&self) -> bool {
        self.who()
            .await
            .is_ok_and(|who| who.stopped.as_deref() == Some(RETIRED))
    }

    pub async fn is_up(&self) -> bool {
        self.who().await.is_ok()
    }

    pub async fn who(&self) -> Result<Who, Failure> {
        let call = self.as_agent("/v0/identity");
        Ok(self.answered(self.sent(call).await).await?.json().await?)
    }

    /// Who it is once its first try at its host has ended, as a Signet answers before its host does.
    pub async fn who_settled(&self) -> Result<Who, Failure> {
        let deadline = std::time::Instant::now() + FIRST_TRY;
        loop {
            let who = self.who().await?;
            if who.registration != Some(RegistrationState::Starting)
                || std::time::Instant::now() >= deadline
            {
                return Ok(who);
            }
            tokio::time::sleep(LOOK_AGAIN).await;
        }
    }

    /// A Signet from before this was added answers that there's no such call, which is no answer.
    pub async fn listening(&self) -> Result<Listening, Failure> {
        let call = self.as_agent("/v0/listening");
        Ok(self.answered(self.sent(call).await).await?.json().await?)
    }

    pub async fn contacts(&self) -> Result<Vec<Contact>, Failure> {
        let call = self.as_agent("/v0/contacts");
        let list: ContactList = self.answered(self.sent(call).await).await?.json().await?;
        Ok(list.contacts)
    }

    /// The schemas of the types this Signet says it agreed with anyone, each read here, so its ID is
    /// this device's own fingerprint of it.
    pub async fn schemas(&self) -> Result<Vec<Schema>, Failure> {
        let mut once = std::collections::BTreeMap::new();
        for (_, schema) in self.agreed_kinds().await? {
            once.insert(schema.name().clone(), schema);
        }
        Ok(once.into_values().collect())
    }

    /// Each type agreed with each contact, by the contact's agent and the type's ID, as this device
    /// works the ID out from the schema.
    pub async fn agreed_types(&self) -> Result<Vec<(SplintId, InteractionType)>, Failure> {
        Ok(self
            .agreed()
            .await?
            .types
            .into_iter()
            .map(|found| (found.agent, found.schema.name().clone()))
            .collect())
    }

    /// The types this Signet says it agreed, with whom, each schema read here, so its ID is this
    /// device's own fingerprint of it. A lying Signet can leave one out or name it for someone else,
    /// and an owner's approval still names exactly the kind and contact they were shown.
    pub async fn agreed_kinds(&self) -> Result<Vec<(SplintId, Schema)>, Failure> {
        Ok(self
            .agreed()
            .await?
            .types
            .into_iter()
            .map(|found| (found.agent, found.schema))
            .collect())
    }

    /// By the owner's token, as only an owner's device asks this, so it never needs the agent's.
    async fn agreed(&self) -> Result<TypeList, Failure> {
        let call = self
            .call(Method::GET, "/v0/owner/types")
            .bearer_auth(self.installed.owner_token.expose());
        Ok(self.answered(self.sent(call).await).await?.json().await?)
    }

    pub async fn held(&self) -> Result<Vec<Held>, Failure> {
        let call = self
            .call(Method::GET, "/v0/owner/quarantine")
            .bearer_auth(self.installed.owner_token.expose());
        let page: HeldPage = self.answered(self.sent(call).await).await?.json().await?;
        Ok(page.held)
    }

    /// A read only an owner's token gets. A failure leaves nothing half read.
    pub async fn owner_read<T: DeserializeOwned>(&self, path: &str) -> Result<T, Failure> {
        let call = self
            .call(Method::GET, path)
            .bearer_auth(self.installed.owner_token.expose());
        self.owner_read_with(call).await
    }

    async fn owner_read_with<T: DeserializeOwned>(
        &self,
        call: RequestBuilder,
    ) -> Result<T, Failure> {
        let mut response = self.answered(self.sent(call).await).await?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > MAX_OWNER_READ_BYTES {
                return Err(Failure::refused(
                    "this agent's Signet sent more than this page can read at once",
                ));
            }
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| Failure::refused("what this agent's Signet sent doesn't make sense"))
    }

    /// Hands over something the owner signed, whose signature is what authorizes it.
    pub async fn owner_post(&self, path: &str, body: &Value) -> Result<(), Failure> {
        let call = self.call(Method::POST, path).json(body);
        self.answered(self.sent(call).await).await?;
        Ok(())
    }

    /// What only an owner's token asks for, with an answer.
    pub async fn owner_ask<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T, Failure> {
        let call = self
            .call(Method::POST, path)
            .bearer_auth(self.installed.owner_token.expose())
            .json(body);
        Ok(self.answered(self.sent(call).await).await?.json().await?)
    }

    /// A taken handle and a host at a limit time lifts say so by their kind, so a program can act.
    pub async fn put_binding(&self, binding: &str) -> Result<(), Failure> {
        let call = self
            .call(Method::PUT, "/v0/owner/binding")
            .json(&json!({ "binding": binding }));
        let sent = self.sent(call).await;
        let status = sent
            .as_ref()
            .ok()
            .filter(|response| other_protocol(response.headers()).is_none())
            .map(Response::status);
        match (self.answered(sent).await, status) {
            (Err(Failure::Refused(_)), Some(StatusCode::CONFLICT)) => {
                let (name, domain) = parse_address(&self.installed.address)?;
                Err(Failure::HandleTaken {
                    handle: name.to_owned(),
                    domain: domain.to_owned(),
                })
            }
            // Signet says which of its host's limits it was, in words from a closed set, and
            // anything else gets the general words.
            (Err(Failure::Refused(said)), Some(StatusCode::TOO_MANY_REQUESTS)) => {
                Err(Failure::TryLater(
                    JoinLimit::from_sentence(&said)
                        .map_or(
                            "the host isn't taking more new agents like this one for now, so try \
                             again later, or with a signup code from whoever runs it",
                            JoinLimit::sentence,
                        )
                        .to_owned(),
                ))
            }
            // Only Signet's own fixed sentence for its host's fixed word, so no other words count.
            (Err(Failure::Refused(said)), Some(StatusCode::FORBIDDEN))
                if said == SignupCodeRefused::SENTENCE =>
            {
                Err(Failure::SignupCodeRefused)
            }
            (answer, _) => answer.map(|_| ()),
        }
    }

    /// Hands this agent to the owner who confirmed it, with what its stand-in and that owner signed.
    pub async fn take_owner(
        &self,
        identity: &str,
        owner_identity: &str,
        release: &str,
        binding: &str,
    ) -> Result<(), Failure> {
        let call = self
            .call(Method::PUT, "/v0/owner/transfer")
            .bearer_auth(self.installed.owner_token.expose())
            .json(&json!({
                "identity": identity,
                "new_owner_identity": owner_identity,
                "release": release,
                "binding": binding,
            }));
        self.answered(self.sent(call).await).await?;
        Ok(())
    }

    /// Asks the owner for a contact, which waits for them with nothing looked up.
    pub async fn ask_for(&self, address: &str, id: &SplintId) -> Result<(), Failure> {
        let call = self
            .call(Method::POST, "/v0/contacts/ask")
            .bearer_auth(self.installed.api_token.expose())
            .json(&json!({ "address": address, "id": id }));
        self.answered(self.sent(call).await).await?;
        Ok(())
    }

    /// One of the agent's own calls, whose answer goes on as Signet gave it.
    pub async fn agent_get(&self, path: &str) -> Result<Value, Failure> {
        let call = self.as_agent(path);
        Ok(self.answered(self.sent(call).await).await?.json().await?)
    }

    pub async fn agent_post(&self, path: &str, body: &Value) -> Result<Value, Failure> {
        let call = self
            .call(Method::POST, path)
            .bearer_auth(self.installed.api_token.expose())
            .timeout(deadline(&Method::POST, path))
            .json(body);
        Ok(self.answered(self.sent(call).await).await?.json().await?)
    }

    /// Until something changes after `since`, or from now without it, or `seconds` pass.
    pub async fn wait(&self, since: Option<u64>, seconds: u64) -> Result<Waited, Failure> {
        self.wait_gathering(since, seconds, 0).await
    }

    /// The same, with what comes while it waits gathered for `gather` seconds, as Signet says. A
    /// body without it is what a Signet from before `gather` takes, so a listener goes on working
    /// through an upgrade.
    pub async fn wait_gathering(
        &self,
        since: Option<u64>,
        seconds: u64,
        gather: u64,
    ) -> Result<Waited, Failure> {
        let body = if gather == 0 {
            json!({ "since": since, "seconds": seconds })
        } else {
            json!({ "since": since, "seconds": seconds, "gather": gather })
        };
        let call = self
            .call(Method::POST, "/v0/wait")
            .bearer_auth(self.installed.api_token.expose())
            .timeout(Duration::from_secs(seconds.saturating_add(gather)).saturating_add(WAIT_SLACK))
            .json(&body);
        let answer: WaitAnswer = self.answered(self.sent(call).await).await?.json().await?;
        let mut new: Vec<Changed> = answer
            .new
            .iter()
            .filter_map(|word| Changed::from_word(word))
            .collect();
        new.sort();
        new.dedup();
        Ok(Waited {
            since: answer.since,
            new,
        })
    }

    /// A recovery of this agent's ID, which its backup signed, so anyone can hand it over.
    pub async fn put_recovery(&self, identity: &str) -> Result<(), Failure> {
        let call = self
            .call(Method::PUT, "/v0/owner/recovery")
            .json(&json!({ "identity": identity }));
        self.answered(self.sent(call).await).await?;
        Ok(())
    }

    /// A delegation its owner signed, which Signet takes by their signature alone.
    pub async fn put_delegation(&self, delegation: &str) -> Result<(), Failure> {
        let call = self
            .call(Method::PUT, "/v0/owner/delegation")
            .json(&json!({ "delegation": delegation }));
        self.answered(self.sent(call).await).await?;
        Ok(())
    }

    /// Something the owner signed, sent as `method` to `path`, whose signature is what authorizes it.
    pub async fn owner_send(
        &self,
        method: Method,
        path: &str,
        body: &Value,
    ) -> Result<(), Failure> {
        let call = self.call(method, path).json(body);
        self.answered(self.sent(call).await).await?;
        Ok(())
    }

    /// The view this Signet would leave its owner at its host, signed by the agent and sealed to the
    /// owner, which needs no token.
    pub async fn owner_view(&self) -> Result<String, Failure> {
        let view: OwnerView = self
            .owner_read_with(self.call(Method::GET, OWNER_VIEW_CALL_PATH))
            .await?;
        Ok(view.view)
    }

    /// Signet holds them once this returns, and says whether its host took them too.
    pub async fn put_rules(&self, rules: &str) -> Result<Option<RulesAtHost>, Failure> {
        let call = self
            .call(Method::PUT, "/v0/owner/rules")
            .json(&json!({ "rules": rules }));
        let answer = self.answered(self.sent(call).await).await?;
        // They count already, so an answer that can't be read only means not knowing about the host.
        Ok(answer
            .json::<RulesApplied>()
            .await
            .ok()
            .and_then(|applied| applied.host))
    }
}

/// How long the agent's call to `path` may take: longer for one Signet answers by reading a host page.
fn deadline(method: &Method, path: &str) -> Duration {
    let reads_a_page = match *method {
        Method::GET => matches!(path, "/v0/inbox" | "/v0/invites"),
        Method::POST => {
            matches!(path, "/v0/inbox/ack" | "/v0/inbox/carry")
                || path
                    .strip_prefix("/v0/invites/")
                    .is_some_and(|rest| rest.ends_with("/accept") || rest.ends_with("/decline"))
        }
        _ => false,
    };
    if reads_a_page { PAGE_TIMEOUT } else { TIMEOUT }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held_saying(address: &str) -> Held {
        serde_json::from_value(json!({
            "sender": format!("splint1{}", "a".repeat(64)),
            "sender_owner": null,
            "address": address,
            "kind": "text",
            "created_at": 1,
        }))
        .unwrap()
    }

    /// A flooded inbox's page on a slow line takes Signet minutes to read, and the agent's call ran out
    /// after 20 seconds every time, so `splint inbox` and `splint ack` could never get through it.
    /// The clock is paused: it moves only when nothing else can, so nothing waits on the real one.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn the_agent_waits_while_signet_reads_a_page_on_a_slow_line() {
        use splint_core::release::{PROTOCOL, PROTOCOL_HEADER};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::owner_key::AgentBackup;

        let dir = std::env::temp_dir().join(format!("splint-slow-page-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("signet.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            // 32 MiB at 256 KiB a second, as Signet's own page deadline allows.
            tokio::time::sleep(Duration::from_secs(130)).await;
            let body = br#"{"messages":[]}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 {PROTOCOL_HEADER}: {PROTOCOL}\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });
        let backup = AgentBackup {
            commitment: String::new(),
            file: PathBuf::new(),
        };
        let installed = Installed::create("ana~host.example", backup).unwrap();
        let api = SignetApi::over(socket, dir.join("stopped"), &installed).unwrap();
        let page = api.agent_get("/v0/inbox").await;
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(page.is_ok_and(|page| page["messages"] == json!([])));
    }

    /// Issue 734's words told an agent "nothing was read or sent, call again" when Signet had taken the
    /// whole call and only its answer failed, so a slow send went out twice.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_call_signet_took_but_never_answered_isnt_said_to_have_sent_nothing() {
        use tokio::io::AsyncReadExt;

        use crate::owner_key::AgentBackup;

        let dir = std::env::temp_dir().join(format!("splint-no-answer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("signet.sock");
        let _ = std::fs::remove_file(&socket);
        let backup = AgentBackup {
            commitment: String::new(),
            file: PathBuf::new(),
        };
        let installed = Installed::create("ana~host.example", backup).unwrap();
        let api = SignetApi::over(socket.clone(), dir.join("stopped"), &installed).unwrap();
        let not_running = api.agent_get("/v0/inbox").await;

        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            // Taken in, then dropped with no answer, as a Signet that stops mid-call does.
        });
        let dropped = api.agent_get("/v0/inbox").await;
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(matches!(not_running, Err(Failure::SignetUnreachable)));
        assert!(matches!(dropped, Err(Failure::SignetNoAnswer)));
    }

    #[test]
    fn what_isnt_an_address_counts_as_none() {
        assert_eq!(
            held_saying("ben~host.example").address.as_deref(),
            Some("ben~host.example")
        );
        for words in [
            "your bank, who says to sign this",
            "ben~host.example now",
            "",
            "BEN~host",
        ] {
            assert_eq!(held_saying(words).address, None, "{words}");
        }
    }
}

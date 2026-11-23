//! How Signet talks to hosts. A host's answers are never trusted without checking them.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use splint_core::host_api::{
    AcceptanceNotice, DeliveryStatus, GuestOutbound, GuestStepRow, GuestSteps, HeldIntroduction,
    HeldRules, HistoryNotice, HostRefusal, HostRefusals, INVITES_DONE_PATH, INVITES_PATH, InboxAck,
    InboxPage, IntroductionsPage, KnownOwner, KnownOwners, LOOKUP_PATH, LookupRequest,
    OWNER_MAIL_ACK_PATH, OWNER_MAIL_PATH, OWNER_VIEW_PATH, OWNERS_PATH, OutboundRequest,
    OwnerMailPage, OwnerView, QuarantinePage, Quarantined, RecoveryNotice, Registration, Resolved,
    RetirementNotice, RevocationNotice, RulesNotice, StoredMessage, StoredOwnerMail, WAIT_PATH,
    WaitAnswer, WaitRequest,
};
use splint_core::transport::Scheme;
use splint_core::{
    AccessProof, Identity, REGISTER_PATH, SigningKey, SplintId, VerifiedBinding, unix_now,
};

use crate::ending::{Done, InboxRows, IntroductionRows, OwnerMailRows, PutOff};

const OUTBOUND_PATH: &str = "/v0/outbound";
const INBOX_PATH: &str = "/v0/inbox";
const ACK_PATH: &str = "/v0/inbox/ack";
const LATER_PATH: &str = "/v0/inbox/later";
const RULES_PATH: &str = "/v0/rules";
const QUARANTINE_PATH: &str = "/v0/quarantine";
const RECOVERIES_PATH: &str = "/v0/recoveries";
const REVOCATIONS_PATH: &str = "/v0/revocations";
const RETIREMENTS_PATH: &str = "/v0/retirements";
const HISTORY_PATH: &str = "/v0/changes";
const KNOWN_OWNERS_PATH: &str = "/v0/known-owners";
const GUEST_OUTBOUND_PATH: &str = "/v0/guest/outbound";
const GUEST_STEPS_PATH: &str = "/v0/guest/steps";
const REFUSED_PATH: &str = "/v0/refused";

/// Far more than an identity, a whole history or a delivery status needs.
const MAX_SHORT_ANSWER_BYTES: usize = 256 * 1024;
/// A host cuts a page at about 1 MiB. One from before it did was at most 100 messages of at most
/// 256 KiB, each with identities of a small bounded size, with room for the fields around them, so
/// this is what Signet reads of one page, and of all the pages of one listing together. A page over
/// this can't be read or cleared, so it would jam the inbox if a sender could cause one. Every field
/// a sender controls has to stay bounded for that reason: the e2e run checks the real routes refuse
/// an envelope one character over 256 KiB and an identity with padding, and reads a flood of the
/// largest messages through them.
const MAX_INBOX_PAGE_BYTES: usize = 32 * 1024 * 1024;
/// How many pages of one listing Signet follows. A host cuts a page at about 1 MiB, so this is past
/// anything it holds for one agent. A host that still says there's more isn't taken at its word for
/// the part it gave, as a listing cut short would pass for the whole of it.
const MAX_PAGES: usize = 64;
/// A place a host says to read on from goes into the next call's path, so it's short and plain.
const MAX_NEXT_CHARS: usize = 128;
/// A host holds a wait for up to 25 seconds, so this leaves room for the network either side.
const WAIT_TIMEOUT: Duration = Duration::from_secs(35);
/// How long a host has to answer a call, and, once an answer is coming, how long it can go quiet.
const HOST_TIMEOUT: Duration = Duration::from_secs(5);
/// A page can be as large as `MAX_INBOX_PAGE_BYTES`, more than a slow line brings in `HOST_TIMEOUT`,
/// so a page that keeps coming has this long in all: 32 MiB at 256 KiB a second, and the time to
/// start. Provisional.
const PAGE_TIMEOUT: Duration = Duration::from_secs(133);

pub enum HostError {
    Unreachable,
    Refused,
    NotFound,
    BadAnswer,
    LocalStorage,
    /// Every way a first contact can fail, so that failing says nothing about what's at an address.
    NoSuchContact,
    /// A limit on what this agent can do on its host, which time lifts.
    TooMany,
    /// One of a host's limits on new agents, which it named in fixed words.
    AtJoinLimit(splint_core::host_api::JoinLimit),
    /// The host holds a later recovery or a revocation, which this agent's owner has to act on.
    OutOfDate,
    /// The host speaks another Splint protocol, so this Signet or the host has to update, and which
    /// one, where the two share none.
    OtherProtocol(Option<splint_core::release::Behind>),
    /// Someone else has this agent's handle on its host, or it's kept for someone who had it.
    NameTaken,
    /// The host holds no unused signup code like the one this Signet was given: mistyped, or spent.
    SignupCodeRefused,
    /// The host refused dates, and its own clock is this many seconds behind this computer's, or ahead
    /// of it when negative, by more than a host takes. Like a host that's down, it's tried again, as
    /// a clock can be set right, but it's said as what it is.
    ClockOff(i64),
}

impl HostError {
    /// The host can't take anything now, for a reason time or a person can fix, so what was being
    /// tried waits and goes again, and nothing is given up on.
    pub fn try_later(&self) -> bool {
        matches!(self, Self::Unreachable | Self::ClockOff(_))
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ClockOff(off) => return f.write_str(&splint_core::host_clock::described(*off)),
            Self::Unreachable => "host is unreachable",
            Self::Refused => "host refused the request",
            Self::NotFound => "not found",
            Self::BadAnswer => "host gave an answer that doesn't check out",
            Self::LocalStorage => "couldn't save Signet's state",
            Self::NoSuchContact => "couldn't find an agent at that address",
            Self::TooMany => "this agent is at a limit on its host, so try again later",
            Self::AtJoinLimit(limit) => limit.sentence(),
            Self::OutOfDate => "the host holds something later, which the owner has to act on",
            Self::OtherProtocol(Some(splint_core::release::Behind::Ours)) => {
                "the host speaks only newer Splint protocols, so this agent's Splint is behind and \
                 has to update to the newest release"
            }
            Self::OtherProtocol(Some(splint_core::release::Behind::Theirs)) => {
                "the host speaks only older Splint protocols, so the host is behind and whoever runs \
                 it has to update it"
            }
            Self::OtherProtocol(None) => {
                "the host speaks another Splint protocol, so this Signet or the host has to update"
            }
            Self::NameTaken => "someone else has that handle on this host",
            Self::SignupCodeRefused => splint_core::host_api::SignupCodeRefused::SENTENCE,
        })
    }
}

/// Signet's `main` prints a startup failure this way, and whoever reads it needs the sentence.
impl fmt::Debug for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for HostError {}

/// A step Signet applied can always have a `received`, so this means its own state is wrong.
impl From<splint_core::requests::Refused> for HostError {
    fn from(_: splint_core::requests::Refused) -> Self {
        Self::LocalStorage
    }
}

impl From<splint_core::Error> for HostError {
    fn from(_: splint_core::Error) -> Self {
        Self::BadAnswer
    }
}

/// An agent and its owner, checked against each other and the address they were found at.
#[derive(Clone)]
pub struct Found {
    pub agent: Identity,
    pub owner: Identity,
    pub binding: String,
}

pub struct HostClient {
    pub domain: String,
    pub scheme: Scheme,
    pub http: reqwest::Client,
    /// When the host last said it closes, as seconds since 1970, or 0 while it said nothing.
    pub closing: AtomicU64,
}

impl HostClient {
    pub fn new(domain: String, scheme: Scheme) -> reqwest::Result<Self> {
        let builder = reqwest::Client::builder()
            .timeout(HOST_TIMEOUT)
            // A redirect from our own host would send us somewhere the owner never chose.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(scheme.is_https())
            .default_headers(crate::release::caller_headers());
        // Plain HTTP is only for a host on this machine, so it never goes to a proxy, which would read it.
        let builder = if scheme.is_https() {
            builder
        } else {
            builder.no_proxy()
        };
        Ok(Self {
            domain,
            scheme,
            http: builder.build()?,
            closing: AtomicU64::new(0),
        })
    }

    /// When this agent's host says it closes, as it said on the last answer heard, for the agent to
    /// decide what to do. It's the host's word.
    pub fn closing_at(&self) -> Option<u64> {
        Some(self.closing.load(Ordering::Relaxed)).filter(|at| *at > 0)
    }

    /// Takes what an answer from the host says of its closing. Only an answer the host gave counts,
    /// not a proxy's when it's down, so a date isn't forgotten while the host can't be reached. The
    /// calls Signet makes on its own, as it starts and as it syncs, are enough to hear a change.
    fn heard(&self, response: &reqwest::Response) {
        if crate::release::host_speaks_other(response.headers()).is_none()
            && response.status().is_success()
        {
            let said = splint_core::host_api::closing_in(
                response
                    .headers()
                    .get(splint_core::host_api::CLOSING_HEADER)
                    .map(reqwest::header::HeaderValue::as_bytes),
            );
            self.closing.store(said.unwrap_or(0), Ordering::Relaxed);
        }
    }
}

/// A lookup made by this agent through its own host, which is the only machine Signet calls.
pub struct Lookup<'a> {
    pub host: &'a HostClient,
    pub key: &'a SigningKey,
    pub me: &'a SplintId,
}

impl Lookup<'_> {
    /// Finds who's at an address, and checks their identity, their owner's and the owner's binding
    /// for this exact address together. A host could still answer with a different agent, and only
    /// an ID the owner's rules name, or one that signed a message, settles that.
    pub async fn resolve(&self, handle: &str, domain: &str) -> Result<Found, HostError> {
        self.host
            .look_up(self.key, self.me, handle, domain)
            .await
            .map_err(|_| HostError::NoSuchContact)
    }

    /// As `resolve`, except that a host that couldn't be reached, or a limit on this agent's lookups,
    /// says so, as each is about a host and says nothing about who is at the address.
    pub async fn resolve_saying_why(&self, handle: &str, domain: &str) -> Result<Found, HostError> {
        self.host
            .look_up(self.key, self.me, handle, domain)
            .await
            .map_err(|error| match error {
                HostError::Unreachable | HostError::TooMany => error,
                _ => HostError::NoSuchContact,
            })
    }

    /// The address an owner's ID in place of their name stands for, as its host gives it and the
    /// binding there names, or any other address as it is, once someone answers there.
    pub async fn name_form(&self, handle: &str, domain: &str) -> Result<String, HostError> {
        self.host
            .look_up_named(self.key, self.me, handle, domain)
            .await
            .map(|(_, address)| address)
            .map_err(|error| match error {
                HostError::Unreachable | HostError::TooMany => error,
                _ => HostError::NoSuchContact,
            })
    }

    /// What's at an address says about its history, for the reader to check for itself.
    pub async fn history(&self, handle: &str, domain: &str) -> Result<String, HostError> {
        Ok(self
            .host
            .resolved(self.key, self.me, handle, domain)
            .await?
            .history)
    }
}

/// A host refuses dates that don't fit its clock as 503, and a proof's as 401 on some paths. When its
/// `Date` says the two clocks are further apart than a host takes, that's the reason, whatever else
/// the answer says.
fn clock_off(response: &reqwest::Response) -> Option<i64> {
    let refused_dates = matches!(
        response.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE | reqwest::StatusCode::UNAUTHORIZED
    );
    let date = response
        .headers()
        .get(reqwest::header::DATE)?
        .to_str()
        .ok()?;
    refused_dates
        .then(|| splint_core::host_clock::off_by(date, unix_now()))
        .flatten()
}

fn accepted(response: reqwest::Response) -> Result<reqwest::Response, HostError> {
    // Checked first, as even a success from another protocol may mean something else.
    if let Some(other) = crate::release::host_speaks_other(response.headers()) {
        Err(HostError::OtherProtocol(other.behind()))
    } else if let Some(off) = clock_off(&response) {
        Err(HostError::ClockOff(off))
    } else if response.status().is_success() {
        Ok(response)
    } else if response.status() == reqwest::StatusCode::NOT_FOUND {
        Err(HostError::NotFound)
    } else if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        // Only a word from the closed set counts, so nothing else a host writes is passed on.
        let limit = response
            .headers()
            .get(splint_core::host_api::JoinLimit::HEADER)
            .and_then(|word| word.to_str().ok())
            .and_then(splint_core::host_api::JoinLimit::from_word);
        Err(limit.map_or(HostError::TooMany, HostError::AtJoinLimit))
    } else if response.status() == reqwest::StatusCode::LOCKED {
        Err(HostError::OutOfDate)
    } else if response.status() == reqwest::StatusCode::FORBIDDEN
        && response
            .headers()
            .get(splint_core::host_api::SignupCodeRefused::HEADER)
            .is_some_and(|word| word == splint_core::host_api::SignupCodeRefused::WORD)
    {
        Err(HostError::SignupCodeRefused)
    } else if response.status().is_server_error() {
        Err(HostError::Unreachable)
    } else {
        Err(HostError::Refused)
    }
}

/// Sends a call whose answer is a page. It has `HOST_TIMEOUT` to start answering, as any call has, and
/// then as long as it keeps coming, up to `PAGE_TIMEOUT`.
async fn page_answer(request: reqwest::RequestBuilder) -> Result<reqwest::Response, HostError> {
    tokio::time::timeout(HOST_TIMEOUT, request.timeout(PAGE_TIMEOUT).send())
        .await
        .map_err(|_| HostError::Unreachable)?
        .map_err(|_| HostError::Unreachable)
}

/// Parses an answer, and stops reading as soon as it passes the limit, because the machine at the
/// other end decides how much it sends. An answer that goes quiet for `HOST_TIMEOUT` ends there.
async fn read_capped<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
) -> Result<T, HostError> {
    let body = body_capped(response, limit).await?;
    serde_json::from_slice(&body).map_err(|_| HostError::BadAnswer)
}

async fn body_capped(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, HostError> {
    let mut body = Vec::new();
    while let Some(chunk) = tokio::time::timeout(HOST_TIMEOUT, response.chunk())
        .await
        .map_err(|_| HostError::BadAnswer)?
        .map_err(|_| HostError::BadAnswer)?
    {
        if body.len() + chunk.len() > limit {
            return Err(HostError::BadAnswer);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The path of the page after `next`, if that's a place a host could mean: a number, or an ID with a
/// letter and a dot before it. Dots alone would name the path above this one.
fn path_after(path: &str, next: &str) -> Result<String, HostError> {
    let plain = next.len() <= MAX_NEXT_CHARS
        && next.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && next
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.');
    if plain {
        Ok(format!("{path}/after/{next}"))
    } else {
        Err(HostError::BadAnswer)
    }
}

impl HostClient {
    /// Reads a listing a host gives in pages: the first from `path`, and each one after from where the
    /// last said to go on, until one says nothing more. An older host answers whole, with nothing
    /// more to say. All the pages together are held to `MAX_INBOX_PAGE_BYTES`, as one answer was, and
    /// to `MAX_PAGES`, and a listing past either is refused whole.
    async fn pages<P: DeserializeOwned>(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        path: &str,
        next_of: fn(&P) -> Option<String>,
    ) -> Result<Vec<P>, HostError> {
        let mut pages = Vec::new();
        let mut left = MAX_INBOX_PAGE_BYTES;
        let mut at = path.to_owned();
        loop {
            let proof = self.proof(key, agent, "GET", &at, b"")?;
            let response = page_answer(
                self.http
                    .get(self.url(&at))
                    .header(AUTHORIZATION, format!("Splint {proof}")),
            )
            .await?;
            let body = body_capped(accepted(response)?, left).await?;
            left = left.saturating_sub(body.len());
            let page: P = serde_json::from_slice(&body).map_err(|_| HostError::BadAnswer)?;
            let next = next_of(&page);
            pages.push(page);
            match next {
                Some(next) if pages.len() < MAX_PAGES => at = path_after(path, &next)?,
                Some(_) => return Err(HostError::BadAnswer),
                None => return Ok(pages),
            }
        }
    }

    /// Only ever this agent's own host, so nothing an agent names can send Signet anywhere else.
    fn url(&self, path: &str) -> String {
        format!("{}://{}{path}", self.scheme.as_str(), self.domain)
    }

    fn proof(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<String, HostError> {
        Ok(AccessProof::sign(
            key,
            agent,
            &self.domain,
            method,
            path,
            body,
            unix_now(),
        )?)
    }

    /// The proof covers the whole body, so a captured one can't name another handle or code, and the
    /// code itself isn't sent.
    pub async fn register(
        &self,
        key: &SigningKey,
        identity: &Identity,
        owner: &Identity,
        binding: &str,
        signup_code: &str,
    ) -> Result<(), HostError> {
        let body = serde_json::to_vec(&Registration::new(
            owner.encoded(),
            identity.encoded(),
            binding.to_owned(),
            signup_code,
        ))
        .map_err(|_| HostError::BadAnswer)?;
        let proof = self.proof(key, identity.id(), "POST", REGISTER_PATH, &body)?;
        let response = self
            .http
            .post(self.url(REGISTER_PATH))
            .header(AUTHORIZATION, format!("Splint {proof}"))
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        let taken = response.status() == reqwest::StatusCode::CONFLICT;
        self.heard(&response);
        match accepted(response) {
            Err(HostError::Refused) if taken => Err(HostError::NameTaken),
            answer => answer.map(|_| ()),
        }
    }

    async fn look_up(
        &self,
        key: &SigningKey,
        me: &SplintId,
        handle: &str,
        domain: &str,
    ) -> Result<Found, HostError> {
        Ok(self.look_up_named(key, me, handle, domain).await?.0)
    }

    /// Who's at an address, with the address its binding names: the one looked up, or for one with an
    /// owner's ID in place of their name, the name it stands for there.
    async fn look_up_named(
        &self,
        key: &SigningKey,
        me: &SplintId,
        handle: &str,
        domain: &str,
    ) -> Result<(Found, String), HostError> {
        let typed = format!("{handle}~{domain}");
        let resolved = self.resolved(key, me, handle, domain).await?;
        let agent = Identity::from_encoded(&resolved.identity)?;
        if agent.id() != &resolved.agent_id {
            return Err(HostError::BadAnswer);
        }
        let owner = Identity::from_encoded(&resolved.owner_identity)?;
        // An owner's ID in place of their name stands for the name the host gives, for that owner.
        let address = splint_core::address_named(&typed, &resolved.moved_to, owner.id())
            .map_err(|_| HostError::BadAnswer)?;
        VerifiedBinding::verify_for(&resolved.binding, &owner, &agent, &address)?;
        // A host it left can still show its binding there, but its own signed history says where it
        // is, and a contact made at the old address would be dropped as relayed from elsewhere.
        if splint_core::changes::moved_elsewhere(&resolved.history, &agent, domain).is_some() {
            return Err(HostError::NotFound);
        }
        Ok((
            Found {
                agent,
                owner,
                binding: resolved.binding,
            },
            address,
        ))
    }

    async fn resolved(
        &self,
        key: &SigningKey,
        me: &SplintId,
        handle: &str,
        domain: &str,
    ) -> Result<Resolved, HostError> {
        let address = format!("{handle}~{domain}");
        let body = serde_json::to_vec(&LookupRequest {
            address: address.clone(),
        })
        .map_err(|_| HostError::BadAnswer)?;
        let proof = self.proof(key, me, "POST", LOOKUP_PATH, &body)?;
        let response = self
            .http
            .post(self.url(LOOKUP_PATH))
            .header(AUTHORIZATION, format!("Splint {proof}"))
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await
    }

    pub async fn send(&self, envelope: &str, recipient_host: &str) -> Result<(), HostError> {
        let response = self
            .http
            .post(self.url(OUTBOUND_PATH))
            .json(&OutboundRequest {
                envelope: envelope.to_owned(),
                recipient_host: recipient_host.to_owned(),
            })
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        accepted(response).map(|_| ())
    }

    /// A step on a one-use link. Its signature is the proof, as with any other step.
    pub async fn send_to_guest(&self, step: &GuestOutbound) -> Result<(), HostError> {
        let response = self
            .http
            .post(self.url(GUEST_OUTBOUND_PATH))
            .json(step)
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        accepted(response).map(|_| ())
    }

    /// What guests have sent this agent since the last one read.
    pub async fn guest_steps(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        after: i64,
    ) -> Result<Vec<GuestStepRow>, HostError> {
        let path = format!("{GUEST_STEPS_PATH}/{after}");
        let proof = self.proof(key, agent, "GET", &path, b"")?;
        // A host cuts these pages by bytes, as it cuts the inbox, so they're read the same way.
        let response = page_answer(
            self.http
                .get(self.url(&path))
                .header(AUTHORIZATION, format!("Splint {proof}")),
        )
        .await?;
        let page: GuestSteps = read_capped(accepted(response)?, MAX_INBOX_PAGE_BYTES).await?;
        Ok(page.steps)
    }

    /// What the host says it refused for this agent, by its own word.
    pub async fn refused(
        &self,
        key: &SigningKey,
        agent: &SplintId,
    ) -> Result<Vec<HostRefusal>, HostError> {
        let proof = self.proof(key, agent, "GET", REFUSED_PATH, b"")?;
        let response = self
            .http
            .get(self.url(REFUSED_PATH))
            .header(AUTHORIZATION, format!("Splint {proof}"))
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        let page: HostRefusals = read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await?;
        Ok(page.refused)
    }

    /// Signed by the owner, so no proof of ours adds anything.
    pub async fn put_rules(&self, rules: &str) -> Result<(), HostError> {
        let response = self
            .http
            .put(self.url(RULES_PATH))
            .json(&RulesNotice {
                rules: rules.to_owned(),
            })
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        accepted(response).map(|_| ())
    }

    /// The newest rules this host holds for this agent. An owner whose device isn't beside this Signet
    /// gives them to the host, so an agent can't keep a change from counting by not passing it on.
    pub async fn rules(&self, key: &SigningKey, agent: &SplintId) -> Result<HeldRules, HostError> {
        let proof = self.proof(key, agent, "GET", RULES_PATH, b"")?;
        let response = self
            .http
            .get(self.url(RULES_PATH))
            .header(AUTHORIZATION, format!("Splint {proof}"))
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await
    }

    /// Who this host says has a name as their own, by owner ID: an owner whose name it is or whose
    /// agent goes by it alone, `None` for nobody, and `Refused` for a name nobody can have here. A host
    /// from before names were owners' says nothing, which reads as nobody.
    pub async fn name_holder(&self, name: &str) -> Result<Option<String>, HostError> {
        let response = self
            .http
            .get(self.url(&format!("{}/{name}", splint_core::host_api::NAMES_PATH)))
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        match response.status() {
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            reqwest::StatusCode::FORBIDDEN => Err(HostError::Refused),
            _ => {
                let held: splint_core::host_api::NameHolder =
                    read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await?;
                Ok(Some(held.owner))
            }
        }
    }

    /// An owner's name at this host, as it says, if they have one.
    pub async fn owners_name(&self, owner: &SplintId) -> Result<Option<String>, HostError> {
        let path = format!(
            "{}/{}/name",
            splint_core::host_api::OWNERS_NAME_PATH,
            owner.as_str()
        );
        let response = self
            .http
            .get(self.url(&path))
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let named: splint_core::host_api::OwnersName =
            read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await?;
        Ok(Some(named.name))
    }

    /// Signed by the backup key, so no proof of ours adds anything, and a proof by a stolen key
    /// mustn't be what it takes.
    pub async fn recover(&self, identity: &str) -> Result<(), HostError> {
        let response = self
            .http
            .post(self.url(RECOVERIES_PATH))
            .json(&RecoveryNotice {
                identity: identity.to_owned(),
            })
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        accepted(response).map(|_| ())
    }

    /// Signed by the owner, so no proof of ours adds anything.
    pub async fn revoke(&self, revocation: &str) -> Result<(), HostError> {
        let response = self
            .http
            .post(self.url(REVOCATIONS_PATH))
            .json(&RevocationNotice {
                revocation: revocation.to_owned(),
            })
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        accepted(response).map(|_| ())
    }

    /// The owner's signature counts here, so no proof of ours adds anything.
    pub async fn put_acceptance(
        &self,
        acceptance: &str,
        histories: Vec<String>,
    ) -> Result<(), HostError> {
        let response = self
            .http
            .put(self.url("/v0/changes/accepted"))
            .json(&AcceptanceNotice {
                acceptance: acceptance.to_owned(),
                histories,
            })
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        accepted(response).map(|_| ())
    }

    /// Gives back contacts this agent agreed by itself at the host it left, as their pairs. Says whether
    /// the day's count left some out.
    pub async fn put_agreed(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        pairs: Vec<splint_core::contact_invites::PendingContact>,
    ) -> Result<bool, HostError> {
        let path = splint_core::host_api::AGREED_PATH;
        let body = serde_json::to_vec(&splint_core::host_api::AgreedPairs { pairs })
            .map_err(|_| HostError::BadAnswer)?;
        let proof = self.proof(key, agent, "PUT", path, &body)?;
        let response = self
            .http
            .put(self.url(path))
            .header(AUTHORIZATION, format!("Splint {proof}"))
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        let taken: splint_core::host_api::AgreedTaken =
            read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await?;
        Ok(taken.full)
    }

    /// The retirement this host holds for this agent, which counts only where its owner's signature
    /// checks out. No proof of ours could be made once it's retired, and none is needed to read it.
    pub async fn retirement_of(&self, agent: &SplintId) -> Result<RetirementNotice, HostError> {
        let response = self
            .http
            .get(self.url(&format!("{RETIREMENTS_PATH}/{agent}")))
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await
    }

    /// The newest copy of this owner's ID this host holds, which proves itself to whoever takes it. A
    /// retired agent's proofs are refused, and an ID is public.
    pub async fn known_owner(&self, owner: &SplintId) -> Result<Identity, HostError> {
        let response = self
            .http
            .get(self.url(&format!("{OWNERS_PATH}/{owner}")))
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        let known: KnownOwner = read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await?;
        Identity::from_encoded(&known.owner_identity).map_err(|_| HostError::Refused)
    }

    /// It checks out on its own or not at all, so no proof of ours adds anything.
    pub async fn put_history(&self, history: &str) -> Result<(), HostError> {
        let response = self
            .http
            .put(self.url(HISTORY_PATH))
            .json(&HistoryNotice {
                history: history.to_owned(),
            })
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        accepted(response).map(|_| ())
    }

    pub async fn known_owners(
        &self,
        key: &SigningKey,
        agent: &SplintId,
    ) -> Result<KnownOwners, HostError> {
        let pages = self
            .pages(key, agent, KNOWN_OWNERS_PATH, |page: &KnownOwners| {
                page.next.clone()
            })
            .await?;
        let mut known = KnownOwners {
            identities: Vec::new(),
            stops: Vec::new(),
            next: None,
        };
        for page in pages {
            known.identities.extend(page.identities);
            known.stops.extend(page.stops);
        }
        Ok(known)
    }

    pub async fn quarantine(
        &self,
        key: &SigningKey,
        agent: &SplintId,
    ) -> Result<Vec<Quarantined>, HostError> {
        let pages = self
            .pages(key, agent, QUARANTINE_PATH, |page: &QuarantinePage| {
                page.next.map(|next| next.to_string())
            })
            .await?;
        Ok(pages.into_iter().flat_map(|page| page.held).collect())
    }

    /// The agent's invites box, for this Signet to check every row of again.
    pub async fn introductions(
        &self,
        key: &SigningKey,
        agent: &SplintId,
    ) -> Result<Vec<HeldIntroduction>, HostError> {
        let pages = self
            .pages(key, agent, INVITES_PATH, |page: &IntroductionsPage| {
                page.next.map(|next| next.to_string())
            })
            .await?;
        Ok(pages.into_iter().flat_map(|page| page.held).collect())
    }

    pub async fn introductions_done(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        done: &[Done<IntroductionRows>],
    ) -> Result<(), HostError> {
        let seqs: Vec<i64> = done.iter().map(Done::seq).collect();
        self.about_rows(key, agent, INVITES_DONE_PATH, &seqs).await
    }

    pub async fn delivery_status(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        message_id: &str,
    ) -> Result<DeliveryStatus, HostError> {
        let path = format!("{OUTBOUND_PATH}/{message_id}");
        let proof = self.proof(key, agent, "GET", &path, b"")?;
        let response = self
            .http
            .get(self.url(&path))
            .header(AUTHORIZATION, format!("Splint {proof}"))
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await
    }

    pub async fn pull(
        &self,
        key: &SigningKey,
        agent: &SplintId,
    ) -> Result<Vec<StoredMessage>, HostError> {
        let proof = self.proof(key, agent, "GET", INBOX_PATH, b"")?;
        let response = page_answer(
            self.http
                .get(self.url(INBOX_PATH))
                .header(AUTHORIZATION, format!("Splint {proof}")),
        )
        .await?;
        self.heard(&response);
        let page: InboxPage = read_capped(accepted(response)?, MAX_INBOX_PAGE_BYTES).await?;
        Ok(page.messages)
    }

    /// Returns once something may have come for this agent since `since`, or after a while if nothing
    /// has. What the host says is only a hint: what counts is what's read after.
    pub async fn wait(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        since: Option<u64>,
    ) -> Result<WaitAnswer, HostError> {
        let body = serde_json::to_vec(&WaitRequest { since }).map_err(|_| HostError::BadAnswer)?;
        let proof = self.proof(key, agent, "POST", WAIT_PATH, &body)?;
        let response = self
            .http
            .post(self.url(WAIT_PATH))
            .timeout(WAIT_TIMEOUT)
            .header(AUTHORIZATION, format!("Splint {proof}"))
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        self.heard(&response);
        read_capped(accepted(response)?, MAX_SHORT_ANSWER_BYTES).await
    }

    /// Clears rows for good, so only what was handed over or proven bad can be named.
    pub async fn ack(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        done: &[Done<InboxRows>],
    ) -> Result<(), HostError> {
        let seqs: Vec<i64> = done.iter().map(Done::seq).collect();
        self.about_rows(key, agent, ACK_PATH, &seqs).await
    }

    /// Asks the host to keep these out of the next few pages, as this Signet can't use them yet. The
    /// host lets a step from someone let in by reach go after enough of these, so only a [`PutOff`] can
    /// be named.
    pub async fn later(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        put_off: &[&PutOff<InboxRows>],
    ) -> Result<(), HostError> {
        let seqs: Vec<i64> = put_off.iter().map(|one| one.seq()).collect();
        self.about_rows(key, agent, LATER_PATH, &seqs).await
    }

    /// Leaves what this agent's owner reads from another device, for the host to give only to them.
    pub async fn leave_owner_view(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        view: String,
    ) -> Result<(), HostError> {
        let body = serde_json::to_vec(&OwnerView { view }).map_err(|_| HostError::BadAnswer)?;
        let proof = self.proof(key, agent, "PUT", OWNER_VIEW_PATH, &body)?;
        let response = self
            .http
            .put(self.url(OWNER_VIEW_PATH))
            .header(AUTHORIZATION, format!("Splint {proof}"))
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        accepted(response).map(|_| ())
    }

    /// What this agent's owner left for it, each sealed to this agent. Nothing in one counts until it
    /// opens here and their signature inside checks out.
    pub async fn owner_mail(
        &self,
        key: &SigningKey,
        agent: &SplintId,
    ) -> Result<Vec<StoredOwnerMail>, HostError> {
        let proof = self.proof(key, agent, "GET", OWNER_MAIL_PATH, b"")?;
        let response = page_answer(
            self.http
                .get(self.url(OWNER_MAIL_PATH))
                .header(AUTHORIZATION, format!("Splint {proof}")),
        )
        .await?;
        let page: OwnerMailPage = read_capped(accepted(response)?, MAX_INBOX_PAGE_BYTES).await?;
        Ok(page.mail)
    }

    pub async fn ack_owner_mail(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        done: &[Done<OwnerMailRows>],
    ) -> Result<(), HostError> {
        let seqs: Vec<i64> = done.iter().map(Done::seq).collect();
        self.about_rows(key, agent, OWNER_MAIL_ACK_PATH, &seqs)
            .await
    }

    async fn about_rows(
        &self,
        key: &SigningKey,
        agent: &SplintId,
        path: &str,
        seqs: &[i64],
    ) -> Result<(), HostError> {
        let body = serde_json::to_vec(&InboxAck {
            seqs: seqs.to_vec(),
        })
        .map_err(|_| HostError::BadAnswer)?;
        let proof = self.proof(key, agent, "POST", path, &body)?;
        let response = self
            .http
            .post(self.url(path))
            .header(AUTHORIZATION, format!("Splint {proof}"))
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| HostError::Unreachable)?;
        accepted(response).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use splint_core::release::{PROTOCOL, PROTOCOL_HEADER};
    use splint_core::{RecoveryRule, SealingKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// A host on this machine whose first answer is `page`, sent `piece` bytes at a time, `every` apart,
    /// and that then goes quiet. `None` for a page is a host that never starts answering.
    async fn host_sending(page: Option<Vec<u8>>, piece: usize, every: Duration) -> HostClient {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            if let Some(page) = page {
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                     {PROTOCOL_HEADER}: {PROTOCOL}\r\n\r\n",
                    page.len()
                );
                stream.write_all(head.as_bytes()).await.unwrap();
                for part in page.chunks(piece) {
                    if stream.write_all(part).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(every).await;
                }
            }
            tokio::time::sleep(Duration::from_secs(600)).await;
        });
        HostClient::new(at, Scheme::PlainHttpForTests).unwrap()
    }

    /// A host on this machine that answers every call with what `page` makes of how many calls came
    /// before it, and counts them. It gives up after `at_most`, so a reader that never stops fails.
    async fn host_answering(
        page: fn(usize) -> Vec<u8>,
        at_most: usize,
    ) -> (HostClient, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        tokio::spawn(async move {
            while counted.load(Ordering::Relaxed) < at_most {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let _ = stream.read(&mut request).await.unwrap();
                let page = page(counted.fetch_add(1, Ordering::Relaxed));
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                     connection: close\r\n{PROTOCOL_HEADER}: {PROTOCOL}\r\n\r\n",
                    page.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&page).await;
            }
        });
        let host = HostClient::new(at, Scheme::PlainHttpForTests).unwrap();
        (host, calls)
    }

    fn agent() -> (SigningKey, SplintId) {
        let key = SigningKey::generate().unwrap();
        let backup = RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key());
        let seal = SealingKey::generate().unwrap().public_key();
        let id = Identity::create(&key, &seal, backup).unwrap().id().clone();
        (key, id)
    }

    /// A flooded inbox's page on a slow line took longer than the 5 seconds Signet gave the whole call,
    /// so every read of it failed and the inbox could never be read or cleared.
    #[tokio::test]
    async fn a_large_page_on_a_slow_line_is_read_whole() {
        let mut page = br#"{"messages":[]}"#.to_vec();
        page.resize(4 * 1024 * 1024, b' ');
        let host = host_sending(Some(page), 64 * 1024, Duration::from_millis(100)).await;
        let (key, id) = agent();
        let started = Instant::now();
        let read = host.pull(&key, &id).await;
        assert!(read.is_ok_and(|messages| messages.is_empty()));
        assert!(started.elapsed() > HOST_TIMEOUT, "the line was slow enough");
    }

    /// Bugs: a host that says there's more on every page kept Signet calling it for good, or reading
    /// until it ran out of memory, and a listing it cut short at either limit passed for all of it.
    #[tokio::test]
    async fn a_host_that_always_says_theres_more_is_left_and_its_listing_refused() {
        let (key, id) = agent();
        let short = |_: usize| br#"{"held":[],"next":7}"#.to_vec();
        let (host, calls) = host_answering(short, 4 * MAX_PAGES).await;
        let read = host.quarantine(&key, &id).await;
        assert!(matches!(read, Err(HostError::BadAnswer)));
        assert_eq!(calls.load(Ordering::Relaxed), MAX_PAGES);

        let long = |_: usize| {
            let mut page = br#"{"held":[],"next":7}"#.to_vec();
            page.resize(MAX_INBOX_PAGE_BYTES / 8, b' ');
            page
        };
        let (host, calls) = host_answering(long, 4 * MAX_PAGES).await;
        let read = host.quarantine(&key, &id).await;
        assert!(matches!(read, Err(HostError::BadAnswer)));
        assert!(
            calls.load(Ordering::Relaxed) <= 9,
            "stopped by how much it read"
        );
    }

    /// Bug: a listing in pages was read only as far as its first, so what a host held past that
    /// never reached Signet.
    #[tokio::test]
    async fn every_page_of_a_listing_is_read_from_where_the_last_said() {
        let (key, id) = agent();
        let pages = |before: usize| match before {
            0 => br#"{"identities":["first"],"next":"o.splint1ab"}"#.to_vec(),
            1 => br#"{"identities":["second"],"stops":[],"next":"s."}"#.to_vec(),
            _ => br#"{"identities":["third"]}"#.to_vec(),
        };
        let (host, calls) = host_answering(pages, 8).await;
        let known = host.known_owners(&key, &id).await.unwrap();
        assert_eq!(known.identities, ["first", "second", "third"]);
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    /// Bug: what a host says to read on from goes into the next call's path, and dots alone, a slash
    /// or a question mark there would have Signet sign for and call some other path on its host.
    #[test]
    fn only_a_plain_place_to_read_on_from_is_followed() {
        for plain in ["17", "o.splint1ab", "s."] {
            let path = path_after("/v0/known-owners", plain);
            assert!(path.is_ok_and(|path| path.ends_with(plain)), "{plain:?}");
        }
        let too_long = "a".repeat(MAX_NEXT_CHARS + 1);
        for not_a_place in ["", ".", "..", "a/b", "a?b", "a%2fb", "a b", "-1", &too_long] {
            assert!(
                path_after("/v0/known-owners", not_a_place).is_err(),
                "{not_a_place:?}"
            );
        }
    }

    /// A page's longer time in all mustn't let a host that stops answering hold Signet that long.
    #[tokio::test]
    async fn a_page_that_stops_coming_ends_once_it_goes_quiet() {
        let started = Instant::now();
        let silent = host_sending(None, 1, Duration::ZERO).await;
        let mut page = br#"{"messages":[]}"#.to_vec();
        page.resize(1024 * 1024, b' ');
        let stops = host_sending(Some(page), 512 * 1024, Duration::from_secs(600)).await;
        let (key, id) = agent();
        let (silent, stops) = tokio::join!(silent.pull(&key, &id), stops.pull(&key, &id));
        assert!(matches!(silent, Err(HostError::Unreachable)));
        assert!(matches!(stops, Err(HostError::BadAnswer)));
        assert!(started.elapsed() < HOST_TIMEOUT * 3);
    }
}

//! What this program asks a host directly, and what an owner's device hands it. Nothing a host answers
//! here is believed for anything that matters: it only saves asking an owner for what would be refused,
//! and what goes the other way counts by the owner's signature, whoever carries it.

use std::time::Duration;

use reqwest::{Response, StatusCode, redirect};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use splint_core::host_api::{
    HeldOwnerView, HeldRules, JoinAnswer, JoinAnswers, JoinLimit, KnownOwner, ListsByHandle,
    OWNER_AGENTS_PATH, OWNER_HANDLES_PATH, OWNERS_PATH, OwnerAgentsNotice, RecoveryNotice,
    Resolved, RetirementNotice, RevocationNotice, RulesNotice,
};
use splint_core::owner_call::owner_mail_path;
use splint_core::owner_session::SESSION_HEADER;
use splint_core::release::{Behind, REPOSITORY};
use splint_core::transport::stays_on_this_machine;
use splint_core::{Identity, SplintId, VerifiedBinding, parse_address};

use crate::failure::Failure;
use crate::release::{other_protocol, speaking_ours};

const TIMEOUT: Duration = Duration::from_secs(10);
/// A host keeps at most 2 MiB of this, and the machine at the other end decides how much it sends.
const MAX_OWNER_VIEW_BYTES: usize = 3 * 1024 * 1024;
/// Far past the largest rules an owner signs, as a Signet reading them from its host allows.
const MAX_HELD_RULES_BYTES: usize = 256 * 1024;

#[derive(Deserialize)]
struct HostInfo {
    #[serde(default)]
    open_signup: bool,
    /// Set while the host is closing, when it takes no new agents.
    #[serde(default)]
    closing_at: Option<u64>,
}

/// A host on another protocol is named as that, rather than as a host that answers strangely.
fn same_protocol(answer: &Response) -> Result<(), Failure> {
    let Some(other) = other_protocol(answer.headers()) else {
        return Ok(());
    };
    let next = match other.behind() {
        Some(Behind::Ours) => format!(
            "This splint is the one behind: install the newest release, only from \
             github.com/{REPOSITORY}"
        ),
        Some(Behind::Theirs) => {
            "The host is the one behind: ask whoever runs it to update it".to_owned()
        }
        None => format!(
            "Install the newest release, only from github.com/{REPOSITORY}, or ask whoever runs \
             the host to update"
        ),
    };
    Err(Failure::refused(format!(
        "that host can't work with this splint: {other}. {next}"
    )))
}

pub struct HostCalls {
    base: String,
    http: reqwest::Client,
}

/// What leaves something an owner signed at their agent's host: the exact body, which is it sealed to
/// the agent, and the owner's proof for posting exactly that, which is all the host can check. The
/// proof is their own key's, or the key's of a session of theirs at that host, which then goes with it.
#[derive(Clone)]
pub struct SealedMail {
    pub body: String,
    pub proof: String,
    pub session: Option<String>,
}

/// What a host said to a change: taken, or it hasn't heard of this agent yet.
pub enum Delivered {
    Taken,
    NoSuchAgent,
}

impl HostCalls {
    /// Anything but this machine is HTTPS, with no setting to change that.
    pub fn new(domain: &str) -> Result<Self, Failure> {
        let here = stays_on_this_machine(domain);
        let scheme = if here { "http" } else { "https" };
        let builder = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(redirect::Policy::none())
            .https_only(!here)
            .default_headers(speaking_ours());
        // Plain HTTP is only for this machine, so it never goes to a proxy, which would read it.
        let builder = if here { builder.no_proxy() } else { builder };
        Ok(Self {
            base: format!("{scheme}://{domain}"),
            http: builder.build()?,
        })
    }

    async fn info(&self) -> Result<HostInfo, Failure> {
        let url = format!("{}/.well-known/splint/host", self.base);
        let unreachable = |_| Failure::refused("couldn't reach that host, so check its address");
        let answer = self.http.get(&url).send().await.map_err(unreachable)?;
        same_protocol(&answer)?;
        if !answer.status().is_success() {
            return Err(Failure::refused(
                "that doesn't answer like a Splint host, so check its address",
            ));
        }
        answer.json().await.map_err(|_| {
            Failure::refused("that doesn't answer like a Splint host, so check its address")
        })
    }

    /// How far this computer's clock is ahead of the host's, by the `Date` it answers with, when that's
    /// more than a host takes. It only says what to tell a person, so not hearing is none.
    pub async fn clock_off(&self) -> Option<i64> {
        let url = format!("{}/.well-known/splint/host", self.base);
        let answer = self.http.get(&url).send().await.ok()?;
        let date = answer.headers().get(reqwest::header::DATE)?.to_str().ok()?;
        splint_core::host_clock::off_by(date, splint_core::unix_now())
    }

    /// Whether a host answers here at all, whatever it says. One that's down behind its proxy answers
    /// 5xx, which is as good as not answering.
    pub async fn answers(&self) -> bool {
        let url = format!("{}/.well-known/splint/host", self.base);
        let answer = self.http.get(&url).send().await;
        answer.is_ok_and(|answer| !answer.status().is_server_error())
    }

    /// Whether this host says it takes agents with no code. Not hearing counts as no.
    pub async fn is_open(&self) -> bool {
        self.info().await.is_ok_and(|info| info.open_signup)
    }

    /// Whether it says so, for someone who has to hear when a host can't be reached.
    pub async fn says_open(&self) -> Result<bool, Failure> {
        Ok(self.info().await?.open_signup)
    }

    /// Whether it says so, for an agent moving there, refused in the words its registration would
    /// be when it says it's closing, before anyone is asked to approve a move it won't take.
    pub async fn says_open_to_a_move(&self) -> Result<bool, Failure> {
        let info = self.info().await?;
        if info.closing_at.is_some() {
            return Err(Failure::TryLater(
                JoinLimit::HostClosing.sentence().to_owned(),
            ));
        }
        Ok(info.open_signup)
    }

    /// Whether someone already has this handle, as far as anyone can look up.
    pub async fn handle_taken(&self, handle: &str) -> Result<bool, Failure> {
        let url = format!("{}/.well-known/splint/agents/{handle}", self.base);
        let answer = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|_| Failure::refused("couldn't reach that host, so check its address"))?;
        match answer.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            status => Err(Failure::refused(format!(
                "that host answered {status}, so try again"
            ))),
        }
    }

    /// An address as someone typed it, where an owner's ID in place of their name becomes the name it
    /// stands for at that host, checked against the binding there: the one spelling that's kept and
    /// shown. Any other address is as it is, with nothing asked.
    pub async fn name_form(address: &str) -> Result<String, Failure> {
        let (name, domain) = parse_address(address).map_err(Failure::not_an_address)?;
        let (_, part) = splint_core::name_parts(name);
        if part.and_then(splint_core::owner_id_start).is_none() {
            return Ok(address.to_owned());
        }
        Ok(Self::new(domain)?.resolve(address).await?.moved_to)
    }

    /// Who has this name here, as the host says. The ID checks out against what's signed, and an agent
    /// that goes by it still has its Signet check it again before anything is sent.
    pub async fn resolve(&self, address: &str) -> Result<Resolved, Failure> {
        let (name, domain) = parse_address(address).map_err(Failure::not_an_address)?;
        let url = format!("{}/.well-known/splint/agents/{name}", self.base);
        let answer = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|_| Failure::refused("couldn't reach that host, so check the address"))?;
        same_protocol(&answer)?;
        if !answer.status().is_success() {
            return Err(Failure::refused(format!(
                "nobody answers to {address} there, so check the address"
            )));
        }
        let found: Resolved = answer
            .json()
            .await
            .map_err(|_| Failure::refused("that host's answer doesn't make sense"))?;
        let agent = Identity::from_encoded(&found.identity)?;
        let owner = Identity::from_encoded(&found.owner_identity)?;
        // An owner's ID in place of their name stands for the name the host gives, for that owner.
        let at = splint_core::address_named(address, &found.moved_to, owner.id())
            .map_err(|_| Failure::refused("that host's answer doesn't check out"))?;
        VerifiedBinding::verify_for(&found.binding, &owner, &agent, &at)?;
        if agent.id() != &found.agent_id {
            return Err(Failure::refused("that host's answer doesn't check out"));
        }
        // A host an agent left can still show its binding there. Its own signed history says where
        // it is now, and a contact named at the old address would be dropped as relayed from elsewhere.
        if let Some(now_at) = splint_core::changes::moved_elsewhere(&found.history, &agent, domain)
        {
            return Err(Failure::refused(format!(
                "the agent at {address} has moved to {now_at}, as its own signed history says, so \
                 use that address"
            )));
        }
        Ok(found)
    }

    /// Who's at an address as this host holds it, with nothing checked but that the ID is the one
    /// given, which an ID proves by itself: after an owner recovers, the binding the host still shows
    /// is one their old key signed, which no longer checks out.
    pub async fn agent_as_held(
        &self,
        address: &str,
        agent: Option<&SplintId>,
    ) -> Result<Resolved, Failure> {
        let (name, _) = parse_address(address).map_err(Failure::not_an_address)?;
        let url = format!("{}/.well-known/splint/agents/{name}", self.base);
        let answer = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|_| Failure::refused("couldn't reach that host, so check the address"))?;
        same_protocol(&answer)?;
        if !answer.status().is_success() {
            return Err(Failure::refused(format!(
                "nobody answers to {address} there, so check the address"
            )));
        }
        let found: Resolved = answer
            .json()
            .await
            .map_err(|_| Failure::refused("that host's answer doesn't make sense"))?;
        let id = Identity::from_encoded(&found.identity)?.id().clone();
        if id != found.agent_id || agent.is_some_and(|agent| agent != &id) {
            return Err(Failure::refused("that host's answer doesn't check out"));
        }
        Ok(found)
    }

    async fn hand_over(&self, request: reqwest::RequestBuilder) -> Result<Delivered, Failure> {
        let answer = request.send().await.map_err(|_| {
            Failure::HostUnreachable(
                "couldn't reach this agent's host, so nothing changed".to_owned(),
            )
        })?;
        same_protocol(&answer)?;
        // A host that's down behind its proxy answers 5xx, which is as good as not answering, and
        // unlike a refusal says nothing about what was sent.
        match answer.status() {
            status if status.is_success() => Ok(Delivered::Taken),
            StatusCode::NOT_FOUND => Ok(Delivered::NoSuchAgent),
            status if status.is_server_error() => Err(Failure::HostUnreachable(format!(
                "this agent's host answered {status}, so nothing changed"
            ))),
            status => Err(Failure::HostRefused(status)),
        }
    }

    /// Leaves an owner's answer for their agent. A host that won't only means passing it on by hand.
    pub async fn keep_answer(&self, agent_key: &str, answer: &str) -> bool {
        self.keep(&JoinAnswer {
            agent_key: agent_key.to_owned(),
            answer: answer.to_owned(),
            kept_at: None,
            ask_mac: None,
        })
        .await
    }

    /// Leaves an owner's answer, as it is, with what ties it to an ask when it's an answer to one.
    pub async fn keep(&self, body: &JoinAnswer) -> bool {
        let url = format!("{}/v0/join-answers", self.base);
        self.http
            .put(url)
            .json(body)
            .send()
            .await
            .is_ok_and(|answer| answer.status().is_success())
    }

    /// The answers kept where this agent's ask said. Only the MAC by the ask's ID makes one an answer
    /// to it, and the agent checks each, and then the answer itself, as any.
    pub async fn answers_to(
        &self,
        agent_key: &str,
        kept_at: &str,
    ) -> Result<Vec<JoinAnswer>, Failure> {
        let url = format!("{}/v0/join-answers/{agent_key}/asked/{kept_at}", self.base);
        let answer = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| Failure::refused("couldn't reach this agent's host, so try again"))?;
        if !answer.status().is_success() {
            return Ok(Vec::new());
        }
        let kept: JoinAnswers = answer.json().await?;
        Ok(kept.answers)
    }

    /// What's waiting for this agent from this owner. Only the owner's signature makes it count.
    pub async fn answer_from(
        &self,
        agent_key: &str,
        owner: &str,
    ) -> Result<Option<String>, Failure> {
        let url = format!("{}/v0/join-answers/{agent_key}/{owner}", self.base);
        let answer = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| Failure::refused("couldn't reach this agent's host, so try again"))?;
        if !answer.status().is_success() {
            return Ok(None);
        }
        let kept: JoinAnswer = answer.json().await?;
        Ok(Some(kept.answer))
    }

    /// What an agent's Signet left for its owner, by a proof only that owner's key can make.
    pub async fn owner_view(&self, path: &str, proof: &str) -> Result<HeldOwnerView, Failure> {
        self.owner_read(path, proof, MAX_OWNER_VIEW_BYTES).await
    }

    /// The rules this host holds for an agent, read as its owner, for a change to start from. Nothing
    /// here counts until the owner's signature checks out on this device.
    pub async fn held_rules(&self, agent: &SplintId, proof: &str) -> Result<HeldRules, Failure> {
        self.owner_read(&rules_path(agent), proof, MAX_HELD_RULES_BYTES)
            .await
    }

    async fn owner_read<T: DeserializeOwned>(
        &self,
        path: &str,
        proof: &str,
        most: usize,
    ) -> Result<T, Failure> {
        let unreachable = |_| Failure::refused("couldn't reach this agent's host, so try again");
        let url = format!("{}{path}", self.base);
        let call = self
            .http
            .get(url)
            .header("Authorization", format!("Splint {proof}"));
        let mut answer = call.send().await.map_err(unreachable)?;
        if !answer.status().is_success() {
            return Err(Failure::refused(format!(
                "this agent's host answered {}, so there's nothing to show",
                answer.status()
            )));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = answer.chunk().await.map_err(unreachable)? {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > most {
                return Err(Failure::refused(
                    "this agent's host sent more than it should",
                ));
            }
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| Failure::refused("what this agent's host sent doesn't make sense"))
    }

    /// Leaves what an owner signed for that agent's Signet to take, sealed to the agent on the owner's
    /// device, by the proof signed there for exactly these bytes. Nothing here can leave one unsealed.
    pub async fn leave_owner_mail(
        &self,
        agent: &SplintId,
        mail: &SealedMail,
    ) -> Result<Delivered, Failure> {
        let url = format!("{}{}", self.base, owner_mail_path(agent));
        let mut call = self
            .http
            .post(url)
            .header("Authorization", format!("Splint {}", mail.proof))
            .header("Content-Type", "application/json")
            .body(mail.body.clone());
        if let Some(session) = &mail.session {
            call = call.header(SESSION_HEADER, session);
        }
        self.hand_over(call).await
    }

    pub async fn put_rules(&self, rules: &str) -> Result<Delivered, Failure> {
        let notice = RulesNotice {
            rules: rules.to_owned(),
        };
        let url = format!("{}/v0/rules", self.base);
        self.hand_over(self.http.put(url).json(&notice)).await
    }

    pub async fn post_revocation(&self, revocation: &str) -> Result<Delivered, Failure> {
        let notice = RevocationNotice {
            revocation: revocation.to_owned(),
        };
        let url = format!("{}/v0/revocations", self.base);
        self.hand_over(self.http.post(url).json(&notice)).await
    }

    /// The agent's own host goes by the owner it holds, so the retirement is all it needs.
    pub async fn post_retirement(&self, retirement: &str) -> Result<Delivered, Failure> {
        let notice = RetirementNotice {
            retirement: retirement.to_owned(),
            owner_identity: String::new(),
            agent_identity: String::new(),
            binding: String::new(),
        };
        self.post_retirement_notice(&notice).await
    }

    /// A retirement with what any host checks it by, so it counts wherever it's taken.
    pub async fn post_retirement_notice(
        &self,
        notice: &RetirementNotice,
    ) -> Result<Delivered, Failure> {
        let url = format!("{}/v0/retirements", self.base);
        self.hand_over(self.http.post(url).json(notice)).await
    }
}

/// What a home host said to the owner's list from this computer.
pub enum ListKept {
    Kept,
    /// It holds a newer one, or the ID it names moved on, so this one is never sent again.
    Superseded,
    /// It couldn't be reached, or wouldn't keep it just now, so it's sent again later.
    NotYet,
}

impl HostCalls {
    /// Leaves the owner's signed, sealed list here, under their ID as it is now. `agent` is one here
    /// they're setting up, which makes room for a first list.
    pub async fn put_owner_list(
        &self,
        owner_identity: &str,
        list: &str,
        agent: Option<&SplintId>,
    ) -> ListKept {
        let Ok(owner) = Identity::from_encoded(owner_identity) else {
            return ListKept::Superseded;
        };
        let url = format!("{}{OWNER_AGENTS_PATH}/{}", self.base, owner.id());
        let notice = OwnerAgentsNotice {
            owner_identity: owner_identity.to_owned(),
            list: list.to_owned(),
            agent: agent.cloned(),
        };
        match self.http.put(url).json(&notice).send().await {
            Ok(answer) if answer.status().is_success() => ListKept::Kept,
            Ok(answer) if answer.status() == StatusCode::CONFLICT => ListKept::Superseded,
            // A refusal of what was signed, as out of date, won't change by sending it again.
            Ok(answer)
                if answer.status().is_client_error()
                    && answer.status() != StatusCode::TOO_MANY_REQUESTS
                    && answer.status() != StatusCode::FORBIDDEN =>
            {
                ListKept::Superseded
            }
            _ => ListKept::NotYet,
        }
    }

    /// The lists kept here under this handle, for a person with only their recovery code. Nothing
    /// here is believed: each is checked under the owner's ID and opened with the code. None only when
    /// the host says it holds none: an answer it couldn't give is a failure, as recovering on it would
    /// spend the code and leave the agents behind.
    pub async fn lists_by_handle(&self, handle: &str) -> Result<Vec<String>, Failure> {
        let unread = || {
            Failure::refused(format!(
                "{} couldn't say whether it holds your agents' list just now, so nothing changed and \
                 your recovery code still works: run this again in a little while",
                self.base
            ))
        };
        let url = format!("{}{OWNER_HANDLES_PATH}/{handle}", self.base);
        let answer = self.http.get(url).send().await.map_err(|_| unread())?;
        if answer.status() == StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if !answer.status().is_success() {
            return Err(unread());
        }
        let found = answer.json::<ListsByHandle>().await.map_err(|_| unread())?;
        Ok(found.lists.into_iter().map(|held| held.list).collect())
    }

    /// The newest copy of an owner's ID this host holds, or none. A copy is checked by whoever uses it.
    pub async fn known_owner(&self, owner: &SplintId) -> Option<String> {
        let url = format!("{}{OWNERS_PATH}/{owner}", self.base);
        let answer = self.http.get(url).send().await.ok()?;
        if !answer.status().is_success() {
            return None;
        }
        answer
            .json::<KnownOwner>()
            .await
            .ok()
            .map(|known| known.owner_identity)
    }

    /// Hands a newer copy of an ID, a recovery or a code set, to this host, which counts it by the
    /// signatures in it alone. Whether it took it, or had no use for it.
    pub async fn post_recovery(&self, identity: &str) -> Result<Delivered, Failure> {
        let notice = RecoveryNotice {
            identity: identity.to_owned(),
        };
        let url = format!("{}/v0/recoveries", self.base);
        self.hand_over(self.http.post(url).json(&notice)).await
    }
}

/// Where an agent's owner reads the rules its host holds.
pub fn rules_path(agent: &SplintId) -> String {
    format!("/v0/rules/{agent}")
}

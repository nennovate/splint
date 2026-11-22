//! What the owner page on this computer asks of Splint here, which holds the person's sign-in: it signs
//! what the page prepares, after its own prompt; it keeps the page's sessions at hosts, so viewing needs
//! a touch only as often as the person chose; it opens what agents sealed to them with the reading key,
//! which never leaves this computer; it seals what the page had signed for an agent to that agent, and
//! leaves it at the agent's host under the session kept there, so nothing an owner signs for their
//! agent leaves this computer for a host unsealed; and it sets the recovery code when the person asks.
//!
//! How often viewing needs a touch is a setting of this computer's, never signed: a session lasts 12
//! hours at most, as hosts take, so `never` means once a session ends, `hourly` makes sessions of an
//! hour, and `every_time` drops them each time the page opens. Viewing with no touch at all past 12
//! hours would need a read-only grant hosts take, which isn't built.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use splint_core::host_api::{HeldRules, OwnerMail, OwnerMailKind};
use splint_core::owner_call::{mail_body, owner_mail_path, seal_owner_mail};
use splint_core::owner_session::{
    MAX_SESSION_SECS, ReadCall, SESSION_HEADER, session_input, session_name_and_end, session_proof,
};
use splint_core::rules::VerifiedRules;
use splint_core::{Identity, SigningKey, SplintId, canonical_domain, unix_now};

use super::Computer;
use crate::failure::Failure;
use crate::host_calls::SealedMail;
use crate::page::controls::{bounded, host_url};

/// The most hosts one prompt makes sessions for, as the page signs in at.
const MOST_HOSTS: usize = 6;
const HOUR: u64 = 60 * 60;
const READ_TIMEOUT_SECS: u64 = 30;

/// How often viewing needs the person's touch here.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Viewing {
    /// Once each session ends, every 12 hours.
    #[default]
    Never,
    Hourly,
    /// Each time the page opens.
    EveryTime,
}

impl Viewing {
    fn lasts(self) -> u64 {
        match self {
            Self::Hourly => HOUR,
            Self::Never | Self::EveryTime => MAX_SESSION_SECS,
        }
    }
}

/// A session this computer keeps for the page, whose key it made and holds in memory alone.
pub struct KeptSession {
    compact: String,
    key: SigningKey,
    name: String,
    expires_at: u64,
}

/// A session as the page is told of it: never its key, which stays here.
#[derive(Serialize)]
pub struct SessionShown {
    domain: String,
    name: String,
    expires_at: u64,
}

/// An agent this computer set up, which the page shows beside the list its home host keeps.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetUpHere {
    pub agent: String,
    pub address: String,
    /// The agent's ID as this computer last held it, which what the owner signs for it is sealed to,
    /// so its host can't have that sealed to a key the agent has since replaced. One set up by a
    /// release from before this has none until something is first left for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// Why nothing was left for an agent from the page here.
pub enum NotLeft {
    /// There's no session at that agent's host just now, so the page signs in again.
    NoSession,
    Failed(Failure),
}

impl From<Failure> for NotLeft {
    fn from(failure: Failure) -> Self {
        Self::Failed(failure)
    }
}

impl From<splint_core::Error> for NotLeft {
    fn from(error: splint_core::Error) -> Self {
        Self::Failed(error.into())
    }
}

/// What the page reads back from a host, as the host answered it.
pub struct Read {
    pub status: u16,
    pub json: Vec<u8>,
}

impl Computer {
    fn viewing_file(&self) -> std::path::PathBuf {
        self.home.computer_dir().join("viewing.json")
    }

    pub(super) fn home_host_file(&self) -> std::path::PathBuf {
        self.home.computer_dir().join("home-host")
    }

    fn agents_file(&self) -> std::path::PathBuf {
        self.home.computer_dir().join("agents.json")
    }

    pub fn viewing(&self) -> Viewing {
        std::fs::read(self.viewing_file())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Kept for the next time, and sessions longer than it now allows are dropped at once.
    pub async fn set_viewing(&self, viewing: Viewing) -> Result<(), Failure> {
        let bytes = serde_json::to_vec(&viewing)
            .map_err(|_| Failure::refused("that setting can't be written"))?;
        std::fs::write(self.viewing_file(), bytes)?;
        let longest = unix_now().saturating_add(viewing.lasts());
        self.sessions
            .lock()
            .await
            .retain(|_, kept| kept.expires_at <= longest && viewing != Viewing::EveryTime);
        Ok(())
    }

    /// The page opened: with `every_time`, what it viewed with before needs a touch again.
    pub async fn page_opened(&self) {
        if self.viewing() == Viewing::EveryTime {
            self.sessions.lock().await.clear();
        }
    }

    pub async fn sign_out(&self) {
        self.sessions.lock().await.clear();
    }

    pub async fn sessions_shown(&self) -> Vec<SessionShown> {
        let now = unix_now();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, kept| now < kept.expires_at);
        sessions
            .iter()
            .map(|(domain, kept)| SessionShown {
                domain: domain.clone(),
                name: kept.name.clone(),
                expires_at: kept.expires_at,
            })
            .collect()
    }

    /// The owner ID here, made around a new sign-in the first time, in the chip where there is one.
    pub async fn make_owner(&self, passphrase: Option<String>) -> Result<String, Failure> {
        let _one = self.approving.lock().await;
        if let Some(identity) = self.owner.kept_identity() {
            return Ok(identity);
        }
        let owner = self.owner_key();
        tokio::task::spawn_blocking(move || super::make_sign_in(&owner, passphrase.as_deref()))
            .await
            .map_err(|_| Failure::refused("making your sign-in stopped partway"))?
    }

    /// Owner objects the page prepared, signed after the one prompt the owner key writes from them.
    pub async fn sign(
        &self,
        inputs: Vec<String>,
        passphrase: Option<String>,
    ) -> Result<serde_json::Value, Failure> {
        let _one = self.approving.lock().await;
        let owner = self.owner_key();
        let signed =
            tokio::task::spawn_blocking(move || owner.sign_inputs(&inputs, passphrase.as_deref()))
                .await
                .map_err(|_| Failure::refused("signing stopped partway"))??;
        serde_json::from_str(&signed)
            .map_err(|_| Failure::refused("the owner key's answer can't be read"))
    }

    /// Sessions at these hosts, for as long as the viewing setting lets one last, signed with one
    /// prompt. Their keys stay here: the page reads through [`Self::read`].
    pub async fn start_sessions(
        &self,
        hosts: Vec<String>,
        passphrase: Option<String>,
    ) -> Result<(Vec<SessionShown>, String), Failure> {
        let identity = self
            .owner
            .kept_identity()
            .ok_or_else(|| Failure::refused("there's no owner ID on this computer yet"))?;
        let owner = Identity::from_encoded(&identity)?;
        let mut hosts: Vec<String> = hosts
            .into_iter()
            .filter(|host| host_url(host).is_some())
            .collect();
        hosts.dedup();
        if hosts.is_empty() || hosts.len() > MOST_HOSTS {
            return Err(Failure::refused("a session is for 1 to 6 hosts"));
        }
        let now = unix_now();
        let lasts = self.viewing().lasts();
        let mut made = Vec::new();
        for host in &hosts {
            let key = SigningKey::generate()?;
            let input = session_input(owner.id(), &key.public_key(), host, now, lasts)?;
            made.push((host.clone(), key, input));
        }
        let inputs = made.iter().map(|(_, _, input)| input.clone()).collect();
        let answer = self.sign(inputs, passphrase).await?;
        let answered: SignedInputs = serde_json::from_value(answer)
            .map_err(|_| Failure::refused("the owner key's answer can't be read"))?;
        let (signed, code) = (answered.signed, answered.code);
        let mut sessions = self.sessions.lock().await;
        for ((host, key, _), compact) in made.into_iter().zip(signed) {
            let (name, expires_at) = session_name_and_end(&compact, &owner, &host, now)?;
            sessions.insert(
                host,
                KeptSession {
                    compact,
                    key,
                    name,
                    expires_at,
                },
            );
        }
        drop(sessions);
        Ok((self.sessions_shown().await, code))
    }

    /// One read at a host the page has a session at, with this session's proof for exactly that call.
    pub async fn read(&self, domain: &str, path: &str) -> Result<Read, Failure> {
        let named = canonical_domain(domain)
            .ok()
            .is_some_and(|canonical| canonical == domain)
            || host_url(domain).is_some_and(|url| url.starts_with("http://"));
        let base = host_url(domain).filter(|_| named);
        let fits = path.starts_with("/v0/")
            && path.len() <= 512
            && path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/-_.".contains(&byte));
        let (Some(base), true) = (base, fits) else {
            return Err(Failure::refused("that isn't a read at a host"));
        };
        let now = unix_now();
        let (proof, session) = {
            let sessions = self.sessions.lock().await;
            let kept = sessions
                .get(domain)
                .filter(|kept| now < kept.expires_at)
                .ok_or_else(|| Failure::refused("no session at that host"))?;
            let call = ReadCall {
                host: domain,
                method: "GET",
                path,
                body: b"",
                now,
            };
            (
                session_proof(&kept.key, &kept.name, &call)?,
                kept.compact.clone(),
            )
        };
        let mut client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(READ_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none());
        if base.starts_with("http://") {
            client = client.no_proxy();
        }
        let answer = client
            .build()?
            .get(format!("{base}{path}"))
            .header("Authorization", format!("Splint {proof}"))
            .header(SESSION_HEADER, session)
            .send()
            .await
            .map_err(|_| Failure::refused("that host couldn't be reached"))?;
        let status = answer.status().as_u16();
        let json = bounded(answer)
            .await
            .ok_or_else(|| Failure::refused("that host answered too much"))?;
        Ok(Read { status, json })
    }

    /// The session kept at this host proving one call that leaves exactly these sealed bytes there
    /// for an agent, as its key proves a read: the proof, and the session it's under. A session buys
    /// only room at a host, as what's inside counts by the owner's own signature alone.
    pub(crate) async fn mail_by_session(
        &self,
        domain: &str,
        path: &str,
        body: &str,
    ) -> Option<SealedMail> {
        let now = unix_now();
        let sessions = self.sessions.lock().await;
        let kept = sessions.get(domain).filter(|kept| now < kept.expires_at)?;
        let call = ReadCall {
            host: domain,
            method: "POST",
            path,
            body: body.as_bytes(),
            now,
        };
        Some(SealedMail {
            body: body.to_owned(),
            proof: session_proof(&kept.key, &kept.name, &call).ok()?,
            session: Some(kept.compact.clone()),
        })
    }

    /// The agent's ID to seal to. For an agent this computer set up it's the copy kept here, or a
    /// newer one its host gives that carries that copy on, which is then the one kept, so its host
    /// can't have something sealed to a key the agent has since replaced. One set up by a release
    /// from before a copy was kept gets the host's the first time. For any other agent it's the
    /// host's copy, checked only to be that agent's ID, as the page a host serves goes by.
    async fn agent_to_seal_to(&self, agent: &SplintId, address: &str) -> Result<Identity, Failure> {
        let (_, domain) = splint_core::parse_address(address)?;
        let here = self
            .agents_here()
            .into_iter()
            .find(|known| known.agent == agent.as_str())
            .and_then(|known| known.identity)
            .and_then(|identity| Identity::from_encoded(&identity).ok())
            .filter(|identity| identity.id() == agent);
        let found = match crate::host_calls::HostCalls::new(domain) {
            Ok(host) => host.resolve(address).await.ok(),
            Err(_) => None,
        };
        let from_host = found.as_ref().map(|found| found.identity.as_str());
        let identity = match here {
            Some(here) => crate::owner_side::agent_to_seal_to(here, from_host),
            None => from_host
                .and_then(|identity| Identity::from_encoded(identity).ok())
                .filter(|identity| identity.id() == agent)
                .ok_or_else(|| {
                    Failure::refused(
                        "that agent's ID couldn't be read at its host, so nothing was sealed to it \
                         or sent",
                    )
                })?,
        };
        self.keep_identity(agent.as_str(), &identity.encoded());
        Ok(identity)
    }

    /// Something the page had this computer's sign-in sign for an agent, sealed here to the agent
    /// and left at its host under the session kept there, and handed straight to its Signet where
    /// that's reached from here, as everything the owner signs for an agent elsewhere goes. The
    /// page holds no session key, so only this can leave it, and nothing leaves here unsealed.
    pub async fn leave_mail(
        &self,
        agent: &SplintId,
        address: &str,
        kind: OwnerMailKind,
        signed: &str,
    ) -> Result<(), NotLeft> {
        let (_, domain) = splint_core::parse_address(address)?;
        if !agent.is_well_formed() {
            return Err(Failure::refused("that isn't an agent's ID").into());
        }
        if !self.session_at(domain).await {
            return Err(NotLeft::NoSession);
        }
        let identity = self.agent_to_seal_to(agent, address).await?;
        let mail = OwnerMail {
            kind,
            signed: signed.to_owned(),
        };
        let body = String::from_utf8(mail_body(&seal_owner_mail(&identity, &mail)?)?)
            .map_err(|_| Failure::refused("that couldn't be sealed"))?;
        let mail = self
            .mail_by_session(domain, &owner_mail_path(agent), &body)
            .await
            .ok_or(NotLeft::NoSession)?;
        crate::owner_side::hand_over_elsewhere(&self.home, agent, address, kind, signed, mail)
            .await?;
        Ok(())
    }

    /// What agents sealed to this owner about `about`, opened here with the reading key.
    pub async fn open(&self, about: String, sealed: String) -> Result<String, Failure> {
        let owner = self.owner_key();
        tokio::task::spawn_blocking(move || owner.open_note(&about, &sealed))
            .await
            .map_err(|_| Failure::refused("opening stopped partway"))?
    }

    /// The recovery code, made and set now, after the owner key's own prompt, with the owner ID as it
    /// is after it, so the page can seal the list again to the new backup. Shown to the page once.
    pub async fn set_recovery(
        &self,
        passphrase: Option<String>,
    ) -> Result<(String, String), Failure> {
        let _one = self.approving.lock().await;
        let owner = self.owner_key();
        if !owner.recovery_not_set() {
            return Err(Failure::refused("your recovery code is set already"));
        }
        let given = self.list_given(Vec::new()).await;
        let list_text = given.as_ref().map(serde_json::Value::to_string);
        let (code, identity, list) = tokio::task::spawn_blocking(move || {
            let (code, list) =
                owner.set_recovery_code(passphrase.as_deref(), list_text.as_deref())?;
            let identity = owner
                .kept_identity()
                .ok_or_else(|| Failure::refused("the owner ID here can't be read"))?;
            Ok::<_, Failure>((code, identity, list))
        })
        .await
        .map_err(|_| Failure::refused("setting the code stopped partway"))??;
        self.code_was_set(&identity, given.as_ref(), list).await;
        Ok((code, identity))
    }

    /// The agents this computer set up, for the page.
    pub fn agents_here(&self) -> Vec<SetUpHere> {
        std::fs::read(self.agents_file())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// The newest ID this computer has held for an agent it set up, kept for sealing to next time.
    pub(super) fn keep_identity(&self, agent: &str, identity: &str) {
        let mut agents = self.agents_here();
        let Some(known) = agents.iter_mut().find(|known| known.agent == agent) else {
            return;
        };
        if known.identity.as_deref() == Some(identity) {
            return;
        }
        known.identity = Some(identity.to_owned());
        if let Ok(bytes) = serde_json::to_vec(&agents) {
            let _ = std::fs::write(self.agents_file(), bytes);
        }
    }

    /// The address kept for an agent set up here, once it has moved there under the same ID.
    pub(super) fn move_kept_address(&self, agent: &str, address: &str) {
        let mut agents = self.agents_here();
        let Some(known) = agents.iter_mut().find(|known| known.agent == agent) else {
            return;
        };
        address.clone_into(&mut known.address);
        if let Ok(bytes) = serde_json::to_vec(&agents) {
            let _ = std::fs::write(self.agents_file(), bytes);
        }
    }

    /// An agent set up here, kept for the page with its ID as it was signed for, and its host as the
    /// person's home host if there's none.
    pub(crate) fn remember_agent(&self, agent: &str, address: &str, identity: &str) {
        let mut agents = self.agents_here();
        agents.retain(|known| known.agent != agent);
        agents.push(SetUpHere {
            agent: agent.to_owned(),
            address: address.to_owned(),
            identity: Some(identity.to_owned()),
        });
        if let Ok(bytes) = serde_json::to_vec(&agents) {
            let _ = std::fs::write(self.agents_file(), bytes);
        }
        if !self.home_host_file().exists()
            && let Ok((_, domain)) = splint_core::parse_address(address)
        {
            let _ = std::fs::write(self.home_host_file(), domain);
        }
    }

    /// Asks waiting in the views the agents set up here left their owner at their hosts, taken as
    /// any ask is, for one approval with the rest: so an ask a remote agent made reaches this computer
    /// without its link. Only while a session is kept at that host, so reading needs no touch beyond
    /// what the viewing setting allows. A held step's draft comes from the same view, which the agent
    /// signed, never from whoever handed the ask over.
    pub(super) async fn take_asks_from_views(&self) {
        let Some(owner) = self
            .owner
            .kept_identity()
            .and_then(|identity| Identity::from_encoded(&identity).ok())
        else {
            return;
        };
        for here in self.agents_here() {
            let Ok((_, domain)) = splint_core::parse_address(&here.address) else {
                continue;
            };
            if !self.session_at(domain).await {
                continue;
            }
            let Some(asks) = self.waiting_in_view(&owner, &here, domain).await else {
                continue;
            };
            for asked in asks {
                // One that doesn't check out under the agent's ID is left: it can only be refused.
                let _ = self.take(asked).await;
            }
        }
    }

    async fn waiting_in_view(
        &self,
        owner: &Identity,
        here: &SetUpHere,
        domain: &str,
    ) -> Option<Vec<super::Asked>> {
        let path = format!("{}/{}", splint_core::host_api::OWNER_VIEW_PATH, here.agent);
        let read = self.read(domain, &path).await.ok()?;
        let held: splint_core::host_api::HeldOwnerView = serde_json::from_slice(&read.json).ok()?;
        let sealed = held.view?;
        let about = format!("splint owner view for {}", here.agent);
        let signed = self.open(about, sealed).await.ok()?;
        let identity = crate::host_calls::HostCalls::new(domain)
            .ok()?
            .resolve(&here.address)
            .await
            .ok()?
            .identity;
        let agent = Identity::from_encoded(&identity).ok()?;
        if agent.id().as_str() != here.agent {
            return None;
        }
        let view = splint_core::owner_view::VerifiedOwnerView::verify(
            &signed,
            &agent,
            owner.id(),
            unix_now(),
        )
        .ok()?
        .into_view();
        let shown: InView = serde_json::from_value(view).ok()?;
        Some(
            shown
                .asks
                .iter()
                .map(|ask| {
                    let (draft, schema) = shown.step_of(ask);
                    super::Asked {
                        ask: ask.clone(),
                        identity: identity.clone(),
                        address: here.address.clone(),
                        draft,
                        schema,
                        kinds: shown.kinds_of(ask),
                        agreed: shown.types.clone(),
                        linked: false,
                        in_words: Default::default(),
                    }
                })
                .collect(),
        )
    }

    /// For a held step's ask handed over with no draft, as from an agent on this computer or by a
    /// link: the draft and its type's schema from the view the agent's Signet signs now, read straight
    /// from it where it can be reached from here, and checked as one from its host is.
    pub(super) async fn step_from_signet(
        &self,
        asked: &mut super::Asked,
        agent: &Identity,
    ) -> Option<()> {
        let owner = self
            .owner
            .kept_identity()
            .and_then(|identity| Identity::from_encoded(&identity).ok())?;
        let direct = crate::direct::Direct::find(&self.home, agent.id()).ok()??;
        let sealed = direct.view().await?;
        let about = format!("splint owner view for {}", agent.id());
        let signed = self.open(about, sealed).await.ok()?;
        let view = splint_core::owner_view::VerifiedOwnerView::verify(
            &signed,
            agent,
            owner.id(),
            unix_now(),
        )
        .ok()?
        .into_view();
        let shown: InView = serde_json::from_value(view).ok()?;
        let (draft, schema) = shown.step_of(&asked.ask);
        asked.kinds = shown.kinds_of(&asked.ask);
        asked.agreed.clone_from(&shown.types);
        asked.draft = draft;
        asked.schema = schema;
        Some(())
    }

    /// The rules in force for the agent behind an ask for new rules, for `owner-key` to build on (issue
    /// 630): the newest that check out as this owner's for that agent, of what its Signet on this
    /// computer and its host, read with the page's session there, hold. With neither read nothing is
    /// signed, as building on this computer's own copy could undo what another device signed since.
    /// The owner's ID goes with them as the agent's host holds it, where it carries this computer's
    /// copy on, so rules another sign-in of theirs signed check out.
    pub(super) async fn rules_in_force(
        &self,
        address: &str,
        agent: &SplintId,
    ) -> Result<super::InForce, Failure> {
        let here = self
            .owner
            .kept_identity()
            .and_then(|identity| Identity::from_encoded(&identity).ok())
            .ok_or_else(|| Failure::refused("the owner ID here can't be read"))?;
        let (_, domain) = splint_core::parse_address(address)?;
        let found = match crate::host_calls::HostCalls::new(domain) {
            Ok(host) => host.resolve(address).await.ok(),
            Err(_) => None,
        };
        let owner = crate::owner_side::owner_to_check_by(
            here,
            found.as_ref().map(|found| found.owner_identity.as_str()),
        );
        let mut held = Vec::new();
        if let Some(direct) = crate::direct::Direct::find(&self.home, agent)?
            && let Some(Ok(read)) = direct.rules().await
        {
            held.extend(read.rules);
        }
        if self.session_at(domain).await
            && let Ok(read) = self
                .read(domain, &crate::host_calls::rules_path(agent))
                .await
            && read.status == 200
            && let Ok(found) = serde_json::from_slice::<HeldRules>(&read.json)
        {
            held.extend(found.rules);
        }
        let newest = held
            .iter()
            .filter_map(|compact| VerifiedRules::reload(compact, &owner).ok())
            .filter(|rules| rules.agent() == agent)
            .max_by_key(VerifiedRules::seq)
            .ok_or_else(|| {
                Failure::refused(format!(
                    "couldn't read the rules in force for {address}, from its Signet on this computer \
                     or its host, so nothing was signed: open your controls page here so it can read \
                     them at its host, then approve again"
                ))
            })?;
        Ok(super::InForce {
            rules: newest.compact().to_owned(),
            owner_identity: owner.encoded(),
        })
    }

    pub(super) async fn session_at(&self, domain: &str) -> bool {
        let now = unix_now();
        self.sessions
            .lock()
            .await
            .get(domain)
            .is_some_and(|kept| now < kept.expires_at)
    }

    /// The sign-in Splint on this computer keeps, to run `owner-key` with.
    pub(crate) fn owner_key(&self) -> crate::owner_key::OwnerKey {
        crate::owner_key::OwnerKey::at(self.owner.dir_path().to_owned(), self.home.schemas())
    }
}

/// What `owner-key sign-inputs` prints.
#[derive(Deserialize)]
struct SignedInputs {
    signed: Vec<String>,
    code: String,
}

/// What of a view this reads: the asks waiting, and the drafts a held step's ask names.
#[derive(Deserialize)]
struct InView {
    #[serde(default)]
    asks: Vec<String>,
    #[serde(default)]
    drafts: Vec<serde_json::Value>,
    /// Each read on its own, so one this device can't read leaves the rest.
    #[serde(default)]
    schemas: Vec<serde_json::Value>,
    /// Every type its Signet says the agent agreed, by ID.
    #[serde(default)]
    types: Vec<splint_core::requests::InteractionType>,
}

impl InView {
    /// The schema here of each type an ask names, by the ID this computer works out for it, so one a
    /// Signet names wrongly is simply not there.
    fn kinds_of(&self, ask: &str) -> Vec<splint_core::requests::Schema> {
        let Ok(changes) = splint_core::asks::payload_changes(ask) else {
            return Vec::new();
        };
        let named = splint_core::asks::types_named(&changes);
        self.schemas
            .iter()
            .filter_map(|schema| {
                serde_json::from_value::<splint_core::requests::Schema>(schema.clone()).ok()
            })
            .filter(|schema| named.contains(&schema.name()))
            .collect()
    }

    /// The draft this view holds for the step an ask names, if it's for one, and the schema here whose
    /// ID, worked out on this computer, is that draft's type.
    fn step_of(
        &self,
        ask: &str,
    ) -> (
        Option<splint_core::requests::ApprovalDraft>,
        Option<splint_core::requests::Schema>,
    ) {
        let draft = splint_core::asks::payload_changes(ask)
            .ok()
            .and_then(|changes| {
                let (request, operation) = splint_core::asks::step_of(&changes)?;
                self.drafts
                    .iter()
                    .filter_map(|draft| {
                        serde_json::from_value::<splint_core::requests::ApprovalDraft>(
                            draft.clone(),
                        )
                        .ok()
                    })
                    .find(|draft| &draft.request == request && draft.operation == operation)
            });
        let schema = draft.as_ref().and_then(|draft| {
            self.schemas
                .iter()
                .filter_map(|schema| {
                    serde_json::from_value::<splint_core::requests::Schema>(schema.clone()).ok()
                })
                .find(|schema| schema.name() == &draft.terms.interaction)
        });
        (draft, schema)
    }
}

/// Every session kept, by host.
pub type Sessions = HashMap<String, KeptSession>;

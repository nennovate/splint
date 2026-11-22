//! Splint on your computer: what a person's own computer runs for them, kept running by the same
//! keepers as Signet, so from login, or on Windows from the next `splint` command. It holds their
//! sign-in for their owner ID, made the first time it's needed, in the security chip where Splint can
//! use one. Agents ask it for exactly what they want changed, as
//! asks their own keys signed, and it puts the asks waiting into as few approvals as one prompt's rule
//! allows: on a Mac, one Touch ID prompt each, which `owner-key` writes from the asks themselves;
//! elsewhere, `splint computer approve` in a terminal, or Approve on the page, with the passphrase
//! of the key file, which is locked with one unless the person asked for a plain file (Nenye,
//! 2026-11-17). The page and terminal list asks by the same rule, so what they show with its
//! code is what one approval signs, and a link's ask always has an approval of its own. Nothing it hands an
//! agent can be used again: each answer is one signed object, delivered to the agent's host, and an
//! agent asking for controls takes up its answer itself.
//!
//! Programs reach it on a socket in the person's own Splint folder, which only they can open. A
//! browser reaches it at `http://localhost:7480`, where an agent's link opens one ask, which waits only
//! once the person clicks to see it, and never goes into a prompt the person didn't ask for. Anything
//! can hand it an ask, as an ask only puts a prompt in front of the person, and only an agent's own key
//! signs one: what it can't stop is a person approving what they didn't ask for, which is why the
//! prompt for controls says to approve only if they asked that agent. An approval signs exactly the
//! asks the person was shown, by their IDs and the code shown with them, never one that came in after.

mod agents_list;
mod moves;
mod owner_page;
mod unlock;
mod web;

pub(crate) use agents_list::{after_recovery, list_kept_here};

pub use moves::set_up_here;
pub use owner_page::Viewing;

use std::collections::HashMap;
use std::future::IntoFuture;
use std::io::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use splint_core::asks::{Change, VerifiedAsk};
use splint_core::requests::ApprovalDraft;
use splint_core::{Identity, parse_address, unix_now};
use tokio::sync::{Mutex, Notify};

use crate::failure::Failure;
use crate::home::{HOME_SETTING, Home};
use crate::host_calls::{HostCalls, SealedMail};
use crate::owner_key::{NewSignIn, OwnerKey, SignIn};
use crate::rules::first_rules;
use crate::secrets::Token;
use crate::services::{self, Keep, Service, Started};

pub const SERVICE: &str = "splint-computer";
const THIS_PROGRAM: &str = "splint";
/// Asks that come together, such as an agent's controls and its first settings, share one prompt.
const TOGETHER_WITHIN: Duration = Duration::from_secs(2);
/// The address a browser reaches it at, the same every time, so a link an agent gives works.
const PORT: u16 = 7480;
/// For a computer where something else holds 7480 for good, and for tests run beside a person's own.
const PORT_SETTING: &str = "SPLINT_COMPUTER_PORT";
/// `file` makes the sign-in a key file even where the chip could hold it, which is weaker, so it's
/// off unless set and said whenever it's on: for a Mac whose chip Splint can't use, and for tests,
/// which never put a prompt on a screen.
const SIGN_IN_SETTING: &str = "SPLINT_COMPUTER_SIGN_IN";

/// What a person chooses a plain key file with, at a terminal: never an ask, the socket or a page.
pub const PLAIN_KEY_FILE: &str = "--plain-key-file";
/// The fewest characters a key file's passphrase has, as `owner-key` holds one to. Provisional.
pub const FEWEST_PASSPHRASE_CHARACTERS: usize = 8;
/// What's said every time a plain key file signs or is listed here, as a setting that weakens a
/// check has to be.
pub const PLAIN_KEY_FILE_WARNING: &str = "Warning: your sign-in on this computer is a key file with no \
     passphrase, so anything running as you on this computer, your agent included, can sign as you. \
     Lock it with a passphrase: splint computer lock";
/// Why a key file isn't made with no passphrase, and where its person chooses one.
const CHOOSE_A_PASSPHRASE: &str = "your sign-in on this computer isn't made yet. It's a key file locked \
     with a passphrase you choose, at least 8 characters, so nothing else running as you, your agent \
     included, can sign as you: choose one on your controls page, or with splint computer approve in a \
     terminal";

/// Whether the sign-in, once made, is the chip's.
pub(crate) fn chip_here() -> bool {
    cfg!(target_os = "macos") && std::env::var(SIGN_IN_SETTING).as_deref() != Ok("file")
}

/// The port the page is on: 7480, unless `SPLINT_COMPUTER_PORT` says another.
pub fn port() -> u16 {
    std::env::var(PORT_SETTING)
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(PORT)
}
/// More than an honest set of agents has waiting at once.
const MOST_WAITING: usize = 64;
/// The socket's own mode, though its folder already keeps everyone else out.
#[cfg(unix)]
const ONLY_THIS_USER: u32 = 0o600;

/// One ask, with what's needed to check and answer it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asked {
    pub ask: String,
    /// The asking agent's ID, which the ask's agent is the hash of.
    pub identity: String,
    pub address: String,
    /// For an ask for a held step: the draft its Signet left in the owner's view, found there by this
    /// computer, never taken from whoever handed the ask over.
    #[serde(skip)]
    pub draft: Option<ApprovalDraft>,
    /// The schema of that draft's type, from the same view, so the prompt says who pays whom.
    #[serde(skip)]
    pub schema: Option<splint_core::requests::Schema>,
    /// For an ask naming types for a contact or for reach: the schema of each, from the same view,
    /// whose ID this computer works out, so the person sees what each holds before approving it.
    #[serde(skip)]
    pub kinds: Vec<splint_core::requests::Schema>,
    /// Every type the view says the agent agreed, by ID, which a lookalike is named after.
    #[serde(skip)]
    pub agreed: Vec<splint_core::requests::InteractionType>,
    /// Handed over by a link a browser opened, so possibly by any website: it goes into no prompt by
    /// itself, only into an approval the person asked for with it in front of them.
    #[serde(skip)]
    pub linked: bool,
    /// The ask in the words its prompt names it by, which `owner-key` writes once it's taken, from the
    /// ask and the draft and schema above, so the page and terminal show what the prompt does.
    #[serde(skip)]
    pub in_words: InWords,
}

/// One ask in the words its prompt names it by, as `owner-key describe-asks` prints them.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct InWords {
    /// Each change in fixed words: for a held step, who pays whom and how much, who it's with, its
    /// type and version, and every number agreed and delivered; for a contact, the agent ID signed and
    /// whether their words come in; for reach by filter, the owners it names.
    pub said: Vec<String>,
    /// The words either agent wrote in a held step, quoted, for a page to show apart and last.
    #[serde(default)]
    pub written: Vec<String>,
}

/// Where an ask stands here.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Waiting,
    /// Signed and delivered. An agent that asked for controls takes up `answer` itself.
    Done {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answer: Option<String>,
    },
    NotApproved {
        reason: String,
    },
}

/// What an approval did, for whoever asked for it, or why it didn't happen.
#[derive(Default, Serialize, Deserialize)]
pub struct Approval {
    pub approved: usize,
    pub refused: usize,
    /// The code the prompt showed, so a page or terminal can show the same.
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Answers to asks for controls that the agent's host didn't keep, such as one too old for where
    /// they're kept, so the person gives the agent the whole answer to finish with, as nothing else
    /// reaches an agent elsewhere.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pass_on: Vec<PassOn>,
}

/// An answer for the person to give the agent at `address` themselves, for `splint finish`.
#[derive(Serialize, Deserialize)]
pub struct PassOn {
    pub address: String,
    pub answer: String,
}

/// One ask waiting, as a page or terminal lists it: the agent's address and its changes, never words
/// of the agent's own.
#[derive(Serialize, Deserialize)]
pub struct Shown {
    pub id: String,
    pub address: String,
    pub changes: Vec<Change>,
    pub expires_at: u64,
    /// Each type the ask names, in core's fixed words, from its schema, for the person to approve
    /// knowing what it holds (Nenye, 2026-11-15).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<splint_core::requests::KindForApproval>,
    /// The ask in the words its prompt names it by, written by `owner-key` from what it signs.
    #[serde(flatten)]
    pub in_words: InWords,
    /// Whether it lets more in than before, which the prompt warns of, and so do the page and terminal.
    #[serde(default)]
    pub lets_more_in: bool,
    /// Handed over by a link a browser opened, rather than by an agent here or its view.
    #[serde(default)]
    pub from_link: bool,
}

/// The asks one approval signs, as a page or terminal lists them, with the code that approval checks.
#[derive(Serialize, Deserialize)]
pub struct OneApproval {
    pub asks: Vec<Shown>,
    pub code: String,
}

/// What's waiting, as a page or terminal lists it: the asks the next approval signs and its code, and
/// the approvals after it, each listed whole, as a held step, a new place to be paid and a link's ask
/// each go alone and a prompt names at most a few changes.
#[derive(Serialize, Deserialize)]
pub struct Waiting {
    pub asks: Vec<Shown>,
    pub code: Option<String>,
    #[serde(default)]
    pub later: Vec<OneApproval>,
    pub prompts_by_itself: bool,
}

/// Who this computer's person is to Splint, once they have a sign-in here.
#[derive(Serialize, Deserialize)]
pub struct Here {
    pub owner: Option<String>,
    pub sign_in: Option<String>,
    /// Whether the device asks for the person itself, with Touch ID or their password.
    pub prompts_by_itself: bool,
    /// Whether the owner ID here still has no recovery code, which a reminder asks for.
    pub recovery_not_set: bool,
    /// Whether the sign-in is a key file with no passphrase, which a page and terminal warn of.
    #[serde(default)]
    pub plain_key_file: bool,
}

pub struct Computer {
    home: Home,
    owner: OwnerKey,
    waiting: Mutex<Vec<Asked>>,
    outcomes: Mutex<HashMap<String, Outcome>>,
    /// One prompt at a time.
    approving: Mutex<()>,
    arrived: Notify,
    /// The owner page's sessions at hosts, whose keys only this process holds.
    sessions: Mutex<owner_page::Sessions>,
    /// What the page opened by the person holds and sends on every call under `/local`, made at each
    /// start and kept in this process alone, so another program on this computer reaching the port
    /// by TCP, such as another of its users, gets nothing.
    page_key: Token,
    /// One-time openings the socket hands out, which a page trades once for `page_key`.
    openings: Mutex<Vec<(Token, u64)>>,
    /// The signing session a page unlocked, if one is live. See [`unlock`].
    unlocked: Mutex<Option<unlock::Unlocked>>,
    /// Wrong tries at unlocking, which hold the next one back.
    tries: Mutex<unlock::Tries>,
}

impl Computer {
    fn new(home: &Home) -> Result<Self, Failure> {
        let home = home.the_default();
        let owner = OwnerKey::at(home.computer_dir().join("owner"), home.schemas());
        Ok(Self {
            home,
            owner,
            waiting: Mutex::new(Vec::new()),
            outcomes: Mutex::new(HashMap::new()),
            approving: Mutex::new(()),
            arrived: Notify::new(),
            sessions: Mutex::new(HashMap::new()),
            page_key: Token::generate()?,
            openings: Mutex::new(Vec::new()),
            unlocked: Mutex::new(None),
            tries: Mutex::new(unlock::Tries::default()),
        })
    }

    /// A one-time opening for a page the person opens, good for a few minutes.
    async fn opening(&self) -> Result<String, Failure> {
        let opening = Token::generate()?;
        let now = unix_now();
        let mut openings = self.openings.lock().await;
        openings.retain(|(_, until)| now < *until);
        if openings.len() >= MOST_OPENINGS {
            openings.remove(0);
        }
        openings.push((opening.clone(), now.saturating_add(OPENING_LASTS_SECS)));
        Ok(opening.expose().to_owned())
    }

    /// The page key, for an opening the socket handed out, which can't be traded again.
    async fn trade_opening(&self, given: &str) -> Option<String> {
        let now = unix_now();
        let mut openings = self.openings.lock().await;
        let found = openings
            .iter()
            .position(|(opening, until)| now < *until && same_secret(opening.expose(), given))?;
        openings.remove(found);
        Some(self.page_key.expose().to_owned())
    }

    fn is_page_key(&self, given: &str) -> bool {
        same_secret(self.page_key.expose(), given)
    }

    /// Takes an ask once it checks out under the agent's ID, and says so to whatever waits for asks.
    /// An ask for a held step is taken only with the draft its agent signed for exactly that step, and
    /// for a type two agents agreed, the schema whose ID is the draft's, as `owner-key` checks before
    /// its prompt, so the page lists and codes the same asks the prompt does.
    async fn take(&self, mut asked: Asked) -> Result<Outcome, Failure> {
        let identity = Identity::from_encoded(&asked.identity)?;
        let ask = VerifiedAsk::verify(&asked.ask, &identity, unix_now())?;
        parse_address(&asked.address)?;
        let names_types = !splint_core::asks::types_named(ask.changes()).is_empty();
        if (ask.step().is_some() && asked.draft.is_none())
            || (names_types && asked.kinds.is_empty())
        {
            // Nothing is taken from whoever handed it over: only the view the agent signed.
            let _ = self.step_from_signet(&mut asked, &identity).await;
        }
        if let Some(known) = self.outcomes.lock().await.get(ask.id()) {
            return Ok(known.clone());
        }
        if !step_held(&ask, &asked) {
            return Err(Failure::refused(
                "that step isn't held for its owner now, so there's nothing to say yes to",
            ));
        }
        if !kinds_held(&ask, &asked) {
            return Err(Failure::refused(
                "what a type it names holds can't be shown from here, so it isn't asked: its \
                 agent's view has to hold each one's schema",
            ));
        }
        let known = self
            .waiting
            .lock()
            .await
            .iter()
            .any(|kept| kept.ask == asked.ask);
        if !known {
            asked.in_words = self.in_words(&asked).await?;
        }
        let linked = asked.linked;
        let mut waiting = self.waiting.lock().await;
        let now = unix_now();
        waiting.retain(|kept| expires_at(&kept.ask).is_some_and(|end| now < end));
        if !waiting.iter().any(|kept| kept.ask == asked.ask) {
            if waiting.len() >= MOST_WAITING {
                return Err(Failure::TryLater(
                    "as many asks are waiting here as it holds, so ask again later".to_owned(),
                ));
            }
            waiting.push(asked);
        }
        self.outcomes
            .lock()
            .await
            .insert(ask.id().to_owned(), Outcome::Waiting);
        // A link's ask puts no prompt up by itself, so it wakes nothing.
        if !linked {
            self.arrived.notify_one();
        }
        Ok(Outcome::Waiting)
    }

    /// An ask in the words its prompt will name it by, from `owner-key`, which writes the prompt. One it
    /// can't say whole isn't taken, so nothing is listed that a prompt would name differently.
    async fn in_words(&self, asked: &Asked) -> Result<InWords, Failure> {
        let given = json!({ "asks": [ToSign {
            ask: &asked.ask,
            identity: &asked.identity,
            address: &asked.address,
            rules: None,
            draft: asked.draft.as_ref(),
            schema: asked.schema.as_ref(),
            kinds: &asked.kinds,
            in_force: None,
            owner_identity: None,
        }] })
        .to_string();
        let dir = self.owner.dir_path().to_owned();
        let schemas = self.home.schemas();
        let printed =
            tokio::task::spawn_blocking(move || OwnerKey::at(dir, schemas).describe_asks(&given))
                .await
                .map_err(|_| Failure::refused("couldn't put that ask in words"))?
                .map_err(|_| {
                    Failure::refused(
                        "that ask can't be put in words here, so it isn't shown or signed",
                    )
                })?;
        #[derive(Deserialize)]
        struct Described {
            asks: Vec<InWords>,
        }
        let described: Described = serde_json::from_str(&printed)
            .map_err(|_| Failure::refused("the owner key's words can't be read"))?;
        described
            .asks
            .into_iter()
            .next()
            .ok_or_else(|| Failure::refused("the owner key put nothing in words"))
    }

    async fn outcome(&self, id: &str) -> Option<Outcome> {
        self.outcomes.lock().await.get(id).cloned()
    }

    /// What's waiting, in the approvals it goes in, each with the code that approval checks.
    async fn listed(&self) -> Waiting {
        let now = unix_now();
        let waiting = self.waiting.lock().await;
        let mut approvals = in_approvals(&waiting, now)
            .into_iter()
            .map(|asks| OneApproval {
                code: splint_core::prepared::touch_code_of(
                    asks.iter().map(|asked| asked.ask.as_str()),
                ),
                asks: asks
                    .iter()
                    .filter_map(|asked| shown_one(asked, now))
                    .collect(),
            });
        let next = approvals.next();
        Waiting {
            code: next.as_ref().map(|next| next.code.clone()),
            asks: next.map(|next| next.asks).unwrap_or_default(),
            later: approvals.collect(),
            prompts_by_itself: self.prompts_by_itself(),
        }
    }

    async fn shown_by_id(&self, id: &str) -> Option<Shown> {
        let now = unix_now();
        self.waiting
            .lock()
            .await
            .iter()
            .find_map(|asked| shown_one(asked, now).filter(|shown| shown.id == id))
    }

    /// The IDs of the next approval the device's own prompt may put in front of the person by itself:
    /// never one with an ask a link handed over, which waits for the person to approve it on the page.
    async fn next_by_itself(&self) -> Option<Vec<String>> {
        let waiting = self.waiting.lock().await;
        in_approvals(&waiting, unix_now())
            .into_iter()
            .next()
            .filter(|asks| asks.iter().all(|asked| !asked.linked))
            .map(|asks| {
                asks.iter()
                    .filter_map(|asked| splint_core::asks::payload_id(&asked.ask).ok())
                    .collect()
            })
    }

    fn here(&self) -> Here {
        let held = self.owner.sign_in_described();
        Here {
            owner: self
                .owner
                .existing_identity()
                .ok()
                .and_then(|identity| Identity::from_encoded(&identity).ok())
                .map(|identity| identity.id().to_string()),
            prompts_by_itself: match &held {
                Some(held) => held.contains("chip"),
                None => chip_here(),
            },
            recovery_not_set: self.owner.recovery_not_set(),
            plain_key_file: held.as_deref().and_then(SignIn::from_words) == Some(SignIn::PlainFile),
            sign_in: held,
        }
    }

    /// Whether a prompt of the device's own asks for the person, so asks can go straight to it: a
    /// sign-in in the chip, or none yet where the first will be.
    fn prompts_by_itself(&self) -> bool {
        match self.owner.sign_in_described() {
            Some(held) => held.contains("chip"),
            None => chip_here(),
        }
    }

    /// The asks with these IDs, the ones the person was shown, in one approval: never one that came
    /// in after, and nothing at all if one of them has gone meanwhile, as the person then saw a list
    /// that's no longer what's waiting. They have to be one approval's worth by the rule the prompt
    /// names asks by, so it signs every one, and where a code was shown with them, theirs. The sign-in
    /// is made the first time, in the chip where there is one. Each answer goes to its agent's host,
    /// and an agent asking for controls also takes its answer from here. A prompt the person turned
    /// down ends the asks in it, and only those.
    async fn approve(
        &self,
        passphrase: Option<String>,
        ids: &[String],
        code: Option<&str>,
    ) -> Result<Approval, Failure> {
        let _one = self.approving.lock().await;
        if ids.is_empty() {
            return Ok(Approval::default());
        }
        let now = unix_now();
        let waiting: Vec<Asked> = self
            .waiting
            .lock()
            .await
            .iter()
            .filter(|asked| shown_one(asked, now).is_some_and(|shown| ids.contains(&shown.id)))
            .cloned()
            .collect();
        if waiting.len() != ids.len() {
            return Err(Failure::refused(
                "what's waiting changed since it was shown, so nothing was signed: look again",
            ));
        }
        if in_approvals(&waiting, now).len() != 1 {
            return Err(Failure::refused(
                "those go in more than one approval, so nothing was signed: look again",
            ));
        }
        let theirs =
            splint_core::prepared::touch_code_of(waiting.iter().map(|asked| asked.ask.as_str()));
        if code.is_some_and(|shown| shown != theirs) {
            return Err(Failure::refused(
                "the code shown isn't those asks' code, so nothing was signed: look again",
            ));
        }
        // Read before the prompt, so the person is never asked to approve what can't be signed.
        let owner_id = self
            .owner
            .kept_identity()
            .and_then(|identity| Identity::from_encoded(&identity).ok())
            .map(|identity| identity.id().clone());
        let mut in_force = Vec::with_capacity(waiting.len());
        for asked in &waiting {
            in_force.push(match asks_for_rules(asked, owner_id.as_ref(), now) {
                Some(agent) => Some(self.rules_in_force(&asked.address, &agent).await?),
                None => None,
            });
        }
        let owner = &self.owner;
        let passphrase_given = passphrase.clone();
        let first = first_rules();
        let asks: Vec<ToSign> = waiting
            .iter()
            .zip(&in_force)
            .map(|(asked, in_force)| {
                let controls = splint_core::asks::payload_changes(&asked.ask)
                    .is_ok_and(|changes| splint_core::asks::controls_delegate(&changes).is_some());
                ToSign {
                    ask: &asked.ask,
                    identity: &asked.identity,
                    address: &asked.address,
                    rules: controls.then_some(&first),
                    draft: asked.draft.as_ref(),
                    schema: asked.schema.as_ref(),
                    kinds: &asked.kinds,
                    in_force: in_force.as_ref().map(|found| found.rules.as_str()),
                    owner_identity: in_force.as_ref().map(|found| found.owner_identity.as_str()),
                }
            })
            .collect();
        // An agent set up in this touch goes into the owner's list at their home host, signed with it.
        let setting_up: Vec<agents_list::ToList> = waiting
            .iter()
            .filter(|asked| {
                splint_core::asks::payload_changes(&asked.ask)
                    .is_ok_and(|changes| splint_core::asks::controls_delegate(&changes).is_some())
            })
            .filter_map(|asked| {
                let agent = VerifiedAsk::claimed_agent(&asked.ask).ok()?;
                Some(agents_list::ToList {
                    beside_owner: agents_list::runs_here(&self.home, agent.as_str()),
                    label: parse_address(&asked.address)
                        .map(|(handle, _)| handle.to_owned())
                        .ok()?,
                    identity: Some(asked.identity.clone()),
                    agent: agent.as_str().to_owned(),
                    address: asked.address.clone(),
                })
            })
            .collect();
        // Room for a first list at its host: an agent there that this owner is setting up now.
        let first_set_up = setting_up
            .first()
            .and_then(|one| serde_json::from_value(Value::String(one.agent.clone())).ok());
        let list_given = if setting_up.is_empty() {
            None
        } else {
            self.list_given(setting_up).await
        };
        let given = match &list_given {
            Some(list) => json!({ "asks": asks, "list": list }),
            None => json!({ "asks": asks }),
        }
        .to_string();
        let dir = owner.dir_path().to_owned();
        let schemas = self.home.schemas();
        let answered = tokio::task::spawn_blocking(move || {
            let owner = OwnerKey::at(dir, schemas);
            if owner.sign_in_described().is_none() {
                make_sign_in(&owner, passphrase_given.as_deref())?;
            }
            warn_if_plain(&owner);
            owner.approve_asks(&given, passphrase_given.as_deref())
        })
        .await
        .map_err(|_| Failure::refused("the approval stopped partway"))?;
        let answered = match answered {
            Err(Failure::Core(splint_core::Error::NotApproved)) => {
                self.turned_down(ids).await;
                return Err(Failure::refused(
                    "you didn't approve them, so nothing was signed",
                ));
            }
            other => other?,
        };
        let answered: Answered = serde_json::from_str(&answered)
            .map_err(|_| Failure::refused("the owner key's answer can't be read"))?;
        // The list first: it holds the backup the answers below bind the agent to.
        if let (Some(list), Some(given)) = (answered.list.clone(), list_given.as_ref()) {
            self.keep_list(given, list, first_set_up).await;
        }
        let mut pass_on = Vec::new();
        for done in &answered.approved {
            let Some(asked) = waiting.iter().find(|asked| {
                splint_core::asks::payload_id(&asked.ask).ok().as_deref() == Some(&done.id)
            }) else {
                continue;
            };
            let (outcome, kept) = self.deliver(asked, done).await;
            if let (
                Outcome::Done {
                    answer: Some(answer),
                },
                false,
            ) = (&outcome, kept)
            {
                pass_on.push(PassOn {
                    address: asked.address.clone(),
                    answer: answer.clone(),
                });
            }
            let controls = splint_core::asks::payload_changes(&asked.ask)
                .is_ok_and(|changes| splint_core::asks::controls_delegate(&changes).is_some());
            if controls
                && matches!(outcome, Outcome::Done { answer: Some(_) })
                && let Ok(agent) = VerifiedAsk::claimed_agent(&asked.ask)
            {
                self.remember_agent(agent.as_str(), &asked.address, &asked.identity);
            }
            self.outcomes.lock().await.insert(done.id.clone(), outcome);
        }
        for refused in &answered.refused {
            if let Some(id) = &refused.id {
                self.outcomes.lock().await.insert(
                    id.clone(),
                    Outcome::NotApproved {
                        reason: refused.reason.clone(),
                    },
                );
            }
        }
        let handled: Vec<String> = answered
            .approved
            .iter()
            .map(|done| done.id.clone())
            .chain(
                answered
                    .refused
                    .iter()
                    .filter_map(|refused| refused.id.clone()),
            )
            .collect();
        self.waiting.lock().await.retain(|asked| {
            splint_core::asks::payload_id(&asked.ask).is_ok_and(|id| !handled.contains(&id))
        });
        Ok(Approval {
            approved: answered.approved.len(),
            refused: answered.refused.len(),
            code: Some(answered.code),
            error: None,
            pass_on,
        })
    }

    /// The asks of a prompt the person turned down, ended, so their agents hear no and none of them
    /// rides along in the next prompt.
    async fn turned_down(&self, ids: &[String]) {
        let mut outcomes = self.outcomes.lock().await;
        for id in ids {
            outcomes.insert(
                id.clone(),
                Outcome::NotApproved {
                    reason: "turned down".to_owned(),
                },
            );
        }
        drop(outcomes);
        self.waiting.lock().await.retain(|asked| {
            splint_core::asks::payload_id(&asked.ask).is_ok_and(|id| !ids.contains(&id))
        });
    }
}

/// How long an opening the socket hands out stays good, long enough for a browser to start.
const OPENING_LASTS_SECS: u64 = 5 * 60;
/// More openings than a person opens pages in a few minutes.
const MOST_OPENINGS: usize = 8;

/// Two secrets compared in time that doesn't depend on where they differ.
fn same_secret(kept: &str, given: &str) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(kept.as_bytes(), given.as_bytes()).is_ok()
}

/// The asks waiting, in the approvals they go in, in order: the asks agents here handed over, as many
/// together as one prompt names by [`fits_one_approval`], then each ask a link handed over alone, as
/// any website can open a link, so a stranger's ask is never signed with the person's own. One that
/// has ended or can't be read is in none.
///
/// [`fits_one_approval`]: splint_core::asks::fits_one_approval
fn in_approvals(waiting: &[Asked], now: u64) -> Vec<Vec<&Asked>> {
    let mut approvals: Vec<Vec<&Asked>> = Vec::new();
    let mut together: Vec<&Asked> = Vec::new();
    let mut named: Vec<Vec<Change>> = Vec::new();
    let live = waiting
        .iter()
        .filter(|asked| shown_one(asked, now).is_some());
    let (linked, own): (Vec<&Asked>, Vec<&Asked>) = live.partition(|asked| asked.linked);
    for asked in own {
        let Ok(changes) = splint_core::asks::payload_changes(&asked.ask) else {
            continue;
        };
        let with: Vec<&[Change]> = named.iter().map(Vec::as_slice).collect();
        if !together.is_empty() && !splint_core::asks::fits_one_approval(&with, &changes) {
            approvals.push(std::mem::take(&mut together));
            named.clear();
        }
        together.push(asked);
        named.push(changes);
    }
    if !together.is_empty() {
        approvals.push(together);
    }
    approvals.extend(linked.into_iter().map(|asked| vec![asked]));
    approvals
}

fn shown_one(asked: &Asked, now: u64) -> Option<Shown> {
    let changes = splint_core::asks::payload_changes(&asked.ask).ok()?;
    let expires_at = expires_at(&asked.ask).filter(|end| now < *end)?;
    let lets_more_in = changes.iter().any(Change::lets_more_in);
    Some(Shown {
        id: splint_core::asks::payload_id(&asked.ask).ok()?,
        address: asked.address.clone(),
        changes,
        expires_at,
        kinds: asked
            .kinds
            .iter()
            .map(|schema| {
                splint_core::requests::for_approval(
                    schema,
                    crate::examples::shipped(),
                    asked.agreed.iter(),
                )
            })
            .collect(),
        in_words: asked.in_words.clone(),
        lets_more_in,
        from_link: asked.linked,
    })
}

/// Whether every type an ask names comes with its schema, whose ID this computer worked out, so what
/// each holds is shown before anyone approves it, as `owner-key` checks before its prompt.
fn kinds_held(ask: &VerifiedAsk, asked: &Asked) -> bool {
    splint_core::asks::types_named(ask.changes())
        .into_iter()
        .all(|named| asked.kinds.iter().any(|schema| schema.name() == named))
}

/// Whether an ask for a held step comes with the draft for exactly that step, by its agent, and for a
/// type two agents agreed, its schema, as `owner-key` needs before it signs. Any other ask passes.
fn step_held(ask: &VerifiedAsk, asked: &Asked) -> bool {
    let Some((request, operation)) = ask.step() else {
        return true;
    };
    let Some(draft) = &asked.draft else {
        return false;
    };
    let interaction = &draft.terms.interaction;
    &draft.request == request
        && draft.operation == operation
        && &draft.agent == ask.agent()
        && (!interaction.is_agreed()
            || asked
                .schema
                .as_ref()
                .is_some_and(|schema| schema.name() == interaction))
}

/// The chip where this computer has one Splint can use, and otherwise a key file locked with the
/// passphrase given. A chip that can't make one is said, never quietly replaced by a key file, and
/// a key file is never made with no passphrase here: whatever reaches this, a page or a program on
/// the socket, can't choose a plain one, which only [`make_plain_sign_in`] makes.
fn make_sign_in(owner: &OwnerKey, passphrase: Option<&str>) -> Result<String, Failure> {
    if chip_here() {
        return owner.make_sign_in(NewSignIn::Chip).map_err(|_| {
            Failure::refused(format!(
                "couldn't make your sign-in in this Mac's chip: set {SIGN_IN_SETTING}=file to use a \
                 key file, locked with a passphrase you choose"
            ))
        });
    }
    if cfg!(target_os = "macos") {
        let _ = writeln!(
            std::io::stderr(),
            "{SIGN_IN_SETTING}=file: your sign-in is a key file, not in this Mac's chip"
        );
    }
    let passphrase = passphrase
        .filter(|given| !given.is_empty())
        .ok_or_else(|| Failure::refused(CHOOSE_A_PASSPHRASE))?;
    owner.make_sign_in(NewSignIn::LockedFile { passphrase })
}

/// Says in the keeper's log, each time a plain key file is about to sign, what it is.
fn warn_if_plain(owner: &OwnerKey) {
    if owner.sign_in() == Some(SignIn::PlainFile) {
        let _ = writeln!(std::io::stderr(), "{PLAIN_KEY_FILE_WARNING}");
    }
}

/// The owner key folder Splint on this computer keeps.
pub(crate) fn owner_here(home: &Home) -> OwnerKey {
    let home = home.the_default();
    OwnerKey::at(home.computer_dir().join("owner"), home.schemas())
}

/// `splint computer approve --plain-key-file`, run by the person where no sign-in is made yet: makes
/// it a key file with no passphrase, because they asked for exactly that, and says what that means.
/// It's made here, by the command they ran, so nothing Splint on the computer takes from a page or
/// its socket ever chooses it.
pub fn make_plain_sign_in(home: &Home) -> Result<(), Failure> {
    Home::make_private(&home.the_default().computer_dir())?;
    owner_here(home).make_sign_in(NewSignIn::PlainFile)?;
    Ok(())
}

/// `splint computer lock`, run by the person: locks a plain key file sign-in with a passphrase they
/// choose, typed twice, keeping its key, so their owner ID doesn't change. A copy of the plain file
/// made before this still signs, which locking can't undo, so the person is told.
pub fn lock_sign_in(home: &Home) -> Result<String, Failure> {
    let owner = owner_here(home);
    match owner.sign_in() {
        Some(SignIn::PlainFile) => {}
        Some(SignIn::LockedFile) => {
            return Ok("Your sign-in's key file is locked with a passphrase already.".to_owned());
        }
        Some(SignIn::Chip) => {
            return Ok(
                "Your sign-in is in this computer's security chip, so there's no key file to lock."
                    .to_owned(),
            );
        }
        None => {
            return Err(Failure::refused(
                "there's no sign-in on this computer yet: splint computer approve makes it, locked \
                 with a passphrase you choose",
            ));
        }
    }
    let passphrase = choose_passphrase()?;
    owner.lock_sign_in(&passphrase)?;
    Ok(
        "Your sign-in's key file is locked. You type its passphrase for each approval from now on, \
         and your owner ID is the same. If the plain file was copied before now, that copy still \
         signs as you."
            .to_owned(),
    )
}

/// A passphrase the person chooses for their key file, typed twice with echo off, so a slip doesn't
/// lock them out of their own owner ID. With no terminal, as when a program pipes it, two lines.
pub fn choose_passphrase() -> Result<String, Failure> {
    let chosen = crate::authorize::secret(&format!(
        "Choose a passphrase, at least {FEWEST_PASSPHRASE_CHARACTERS} characters:"
    ))?;
    if chosen.chars().count() < FEWEST_PASSPHRASE_CHARACTERS {
        return Err(Failure::refused(format!(
            "a passphrase has at least {FEWEST_PASSPHRASE_CHARACTERS} characters, so nothing was \
             made or signed"
        )));
    }
    if crate::authorize::secret("The same passphrase again:")? != chosen {
        return Err(Failure::refused(
            "those two weren't the same, so nothing was made or signed",
        ));
    }
    Ok(chosen)
}

/// The rules in force for an agent asking for new ones, and the owner's ID they were checked under.
pub struct InForce {
    rules: String,
    owner_identity: String,
}

/// The agent an ask is for, where it asks this owner for new rules: not its controls, a held step,
/// where its owner gets paid or a move to another host, which build on no rules, nor another owner's agent's, which `owner-key`
/// refuses as not theirs.
fn asks_for_rules(
    asked: &Asked,
    owner: Option<&splint_core::SplintId>,
    now: u64,
) -> Option<splint_core::SplintId> {
    let identity = Identity::from_encoded(&asked.identity).ok()?;
    let ask = VerifiedAsk::verify(&asked.ask, &identity, now).ok()?;
    let other = ask.asks_for_controls()
        || ask.step().is_some()
        || ask.where_paid().is_some()
        || ask.host().is_some();
    (!other && Some(ask.owner()) == owner).then(|| ask.agent().clone())
}

/// One ask as `owner-key approve-asks` takes it.
#[derive(Serialize)]
struct ToSign<'a> {
    ask: &'a str,
    identity: &'a str,
    address: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rules: Option<&'a splint_core::rules::RulesDraft>,
    #[serde(skip_serializing_if = "Option::is_none")]
    draft: Option<&'a ApprovalDraft>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<&'a splint_core::requests::Schema>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    kinds: &'a [splint_core::requests::Schema],
    #[serde(skip_serializing_if = "Option::is_none")]
    in_force: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_identity: Option<&'a str>,
}

#[derive(Deserialize)]
struct Answered {
    approved: Vec<Done>,
    refused: Vec<RefusedOne>,
    code: String,
    /// The owner's list, signed in the same touch, for their home host.
    #[serde(default)]
    list: Option<String>,
}

#[derive(Deserialize)]
struct Done {
    id: String,
    #[serde(default)]
    answer: Option<String>,
    #[serde(default)]
    rules: Option<String>,
    #[serde(default)]
    approval: Option<String>,
    #[serde(default)]
    where_paid: Option<String>,
    /// With a yes or where the owner gets paid: what leaves it at the agent's host, which is it
    /// sealed to the agent, and the owner's proof for posting exactly that, signed in the same
    /// approval. Nothing else of either goes to a host.
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    proof: Option<String>,
}

#[derive(Deserialize)]
struct RefusedOne {
    id: Option<String>,
    reason: String,
}

impl Computer {
    /// What leaves a yes or where the owner gets paid at the agent's host: the body the sign-in
    /// sealed to the agent in that approval, under the session kept at that host where there's one,
    /// whose proof is made as it's sent, and otherwise by the proof the sign-in signed with it, which
    /// is good for moments. With many answers handed on one by one, the last could outlast that.
    async fn sealed_for_host(
        &self,
        domain: &str,
        agent: &splint_core::SplintId,
        done: &Done,
    ) -> Option<SealedMail> {
        let body = done.body.clone()?;
        let path = splint_core::owner_call::owner_mail_path(agent);
        if let Some(mail) = self.mail_by_session(domain, &path, &body).await {
            return Some(mail);
        }
        Some(SealedMail {
            body,
            proof: done.proof.clone()?,
            session: None,
        })
    }

    /// Something the sign-in signed for the agent's Signet, to it straight where it's reached from
    /// here and to its host as well, as everything the owner signs goes, so an answer from something
    /// else on the socket can't keep it from the agent. One its Signet took while its host couldn't
    /// be reached is kept and sent to the host again, so it's on its way.
    async fn hand_on(
        &self,
        asked: &Asked,
        domain: &str,
        kind: splint_core::host_api::OwnerMailKind,
        signed: &str,
        done: &Done,
    ) -> bool {
        let Ok(agent) = VerifiedAsk::claimed_agent(&asked.ask) else {
            return false;
        };
        let Some(mail) = self.sealed_for_host(domain, &agent, done).await else {
            return false;
        };
        matches!(
            crate::owner_side::hand_over_elsewhere(
                &self.home,
                &agent,
                &asked.address,
                kind,
                signed,
                mail
            )
            .await,
            Ok(()) | Err(Failure::NotYetAtHost(_))
        )
    }

    /// Hands each answer on: new rules to the agent's Signet straight where it can be reached from
    /// here, and to its host either way, a yes or where the owner gets paid the same way, sealed to
    /// the agent, or the answer to an ask for controls, kept at its host for it to take up as well as
    /// handed back here. Whether its host kept that answer comes back with it.
    async fn deliver(&self, asked: &Asked, done: &Done) -> (Outcome, bool) {
        let home = &self.home;
        let Ok((_, domain)) = parse_address(&asked.address) else {
            return (
                Outcome::NotApproved {
                    reason: "not an address".to_owned(),
                },
                false,
            );
        };
        let Ok(host) = HostCalls::new(domain) else {
            return (
                Outcome::NotApproved {
                    reason: "not an address".to_owned(),
                },
                false,
            );
        };
        if let Some(rules) = &done.rules {
            let agent = VerifiedAsk::claimed_agent(&asked.ask);
            // Rules its Signet took while its host couldn't be reached are kept and sent to the host
            // again, so they're approved and on their way, never "not approved".
            let sent = match agent {
                Ok(agent) => matches!(
                    crate::authorize::send_rules(home, &agent, &asked.address, rules).await,
                    Ok(_) | Err(Failure::NotYetAtHost(_))
                ),
                Err(_) => false,
            };
            return (
                if sent {
                    Outcome::Done { answer: None }
                } else {
                    Outcome::NotApproved {
                        reason: "neither its Signet nor its host took the rules".to_owned(),
                    }
                },
                sent,
            );
        }
        let for_signet = [
            (
                &done.approval,
                splint_core::host_api::OwnerMailKind::Approval,
                "neither its Signet nor its host took the yes",
            ),
            (
                &done.where_paid,
                splint_core::host_api::OwnerMailKind::WherePaid,
                "neither its Signet nor its host took where you get paid",
            ),
        ];
        for (signed, kind, not_taken) in for_signet {
            let Some(signed) = signed else {
                continue;
            };
            let sent = self.hand_on(asked, domain, kind, signed, done).await;
            return (
                if sent {
                    Outcome::Done { answer: None }
                } else {
                    Outcome::NotApproved {
                        reason: not_taken.to_owned(),
                    }
                },
                sent,
            );
        }
        let Some(answer) = &done.answer else {
            return (Outcome::Done { answer: None }, true);
        };
        // A move's answer is the owner's binding at the new address, which the agent takes up from
        // here: its new host doesn't know it yet, and the one it leaves may be gone.
        if let Some(to) = splint_core::asks::payload_changes(&asked.ask)
            .ok()
            .as_deref()
            .and_then(splint_core::asks::host_of)
        {
            if let Ok(agent) = VerifiedAsk::claimed_agent(&asked.ask) {
                self.note_moving(agent.as_str(), to);
            }
            self.keep_move_at(asked, to, answer).await;
            return (
                Outcome::Done {
                    answer: Some(answer.clone()),
                },
                true,
            );
        }
        let keys = Identity::from_encoded(&asked.identity)
            .ok()
            .and_then(|identity| identity.agent_keys())
            .map(|keys| keys.encoded());
        // Kept where the ask's ID says, with a MAC by it, so the agent tells it from a stranger's
        // answer.
        let kept = keys.and_then(|keys| {
            let ask = splint_core::asks::payload_id(&asked.ask).ok()?;
            splint_core::answer_to_ask(keys, answer.clone(), &ask).ok()
        });
        // A host that won't keep it, such as one from before answers were kept where an ask says,
        // leaves an agent here to take it from here, and one elsewhere to have it passed on by its
        // person.
        let kept = match kept {
            Some(kept) => host.keep(&kept).await,
            None => false,
        };
        (
            Outcome::Done {
                answer: Some(answer.clone()),
            },
            kept,
        )
    }
}

fn expires_at(ask: &str) -> Option<u64> {
    splint_core::asks::payload_expires_at(ask).ok()
}

fn socket_routes(computer: Arc<Computer>) -> Router {
    Router::new()
        .route("/v0/asks", post(take_ask).get(list_asks))
        .route("/v0/asks/{id}", get(one_ask))
        .route("/v0/approve", post(approve_now))
        .route("/v0/here", get(who_is_here))
        .route("/v0/page", post(page_opening))
        .with_state(computer)
}

async fn take_ask(State(computer): State<Arc<Computer>>, Json(asked): Json<Asked>) -> Json<Value> {
    let taken = match computer.as_its_host_says(asked).await {
        Ok(asked) => computer.take(asked).await,
        Err(failure) => Err(failure),
    };
    Json(match taken {
        Ok(outcome) => json!(outcome),
        Err(failure) => json!({"status": "refused", "reason": failure.to_string()}),
    })
}

/// A one-time opening for the page the person opens, which only a program run as them gets.
async fn page_opening(State(computer): State<Arc<Computer>>) -> Json<Value> {
    Json(match computer.opening().await {
        Ok(opening) => json!({ "opening": opening }),
        Err(failure) => json!({ "error": failure.to_string() }),
    })
}

async fn list_asks(State(computer): State<Arc<Computer>>) -> Json<Waiting> {
    Json(computer.listed().await)
}

async fn one_ask(
    State(computer): State<Arc<Computer>>,
    Path(id): Path<String>,
) -> Json<Option<Outcome>> {
    Json(computer.outcome(&id).await)
}

/// An approval of exactly the asks shown, by their IDs, and the code shown with them, if one was.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveBody {
    #[serde(default)]
    pub passphrase: Option<String>,
    pub ids: Vec<String>,
    #[serde(default)]
    pub code: Option<String>,
}

async fn approve_now(
    State(computer): State<Arc<Computer>>,
    Json(body): Json<ApproveBody>,
) -> Json<Approval> {
    Json(
        match computer
            .approve(body.passphrase, &body.ids, body.code.as_deref())
            .await
        {
            Ok(approval) => approval,
            Err(failure) => Approval {
                error: Some(failure.to_string()),
                ..Approval::default()
            },
        },
    )
}

async fn who_is_here(State(computer): State<Arc<Computer>>) -> Json<Here> {
    Json(computer.here())
}

/// Puts asks in front of the person as they come, a moment apart so several share one prompt, where
/// the device prompts by itself: one prompt for each approval's worth, until the person turns one
/// down, which ends only the asks it named. An ask a link handed over never goes in, as any website
/// can open a link: it waits for the person to approve it on the page.
async fn prompt_as_asks_come(computer: Arc<Computer>) {
    loop {
        computer.arrived.notified().await;
        if !computer.prompts_by_itself() {
            continue;
        }
        tokio::time::sleep(TOGETHER_WITHIN).await;
        // However many came, never more prompts than asks can wait here.
        for _ in 0..MOST_WAITING {
            let Some(ids) = computer.next_by_itself().await else {
                break;
            };
            if let Err(failure) = computer.approve(None, &ids, None).await {
                // The keeper's log is the one place this can be said.
                let _ = writeln!(
                    std::io::stderr(),
                    "asks waiting weren't approved: {failure}"
                );
                break;
            }
        }
    }
}

/// How often the views at hosts are read for asks, which costs a read at each agent's host.
const VIEWS_EVERY: Duration = Duration::from_secs(60);

/// Reads the views agents set up here left at their hosts for asks waiting, while sessions last, and
/// forgets a signing session that has ended.
async fn take_asks_as_they_wait(computer: Arc<Computer>) {
    loop {
        computer.forget_ended_unlock().await;
        computer.follow_moves().await;
        computer.send_list_again().await;
        computer.take_asks_from_views().await;
        tokio::time::sleep(VIEWS_EVERY).await;
    }
}

/// What the keeper runs: the socket for programs, the page for browsers, and the prompt loop.
pub async fn run(home: &Home) -> Result<String, Failure> {
    let computer = Arc::new(Computer::new(home)?);
    let dir = computer.home.computer_dir();
    Home::make_private(&dir)?;
    #[cfg(unix)]
    let socket = bind_socket(&computer.home.computer_socket())?;
    #[cfg(windows)]
    let socket = serve_pipe(
        computer.home.computer_socket().into_os_string(),
        &computer.home.computer_lock(),
    )?;
    let v4 = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port())).await;
    let v6 = tokio::net::TcpListener::bind((Ipv6Addr::LOCALHOST, port())).await;
    let page = web::routes(computer.clone());
    tokio::spawn(prompt_as_asks_come(computer.clone()));
    tokio::spawn(take_asks_as_they_wait(computer.clone()));
    let programs = axum::serve(socket, socket_routes(computer));
    let browser = async {
        match (v4, v6) {
            (Ok(v4), Ok(v6)) => {
                let both = tokio::try_join!(
                    axum::serve(v4, page.clone()).into_future(),
                    axum::serve(v6, page).into_future()
                );
                both.map(|_| ())
            }
            // Another program holds the address, so only programs reach Splint here.
            _ => std::future::pending().await,
        }
    };
    tokio::select! {
        done = programs => done?,
        done = browser => done?,
    }
    Ok("Splint on this computer stopped".to_owned())
}

/// The socket in the person's own Splint folder, which nobody else can open. One left by a copy that
/// stopped is cleared, and one something answers on is another copy's, so this one doesn't start.
#[cfg(unix)]
fn bind_socket(path: &std::path::Path) -> Result<tokio::net::UnixListener, Failure> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    if let Some(folder) = path.parent() {
        Home::make_private(folder)?;
    }
    if let Ok(found) = std::fs::symlink_metadata(path) {
        if !found.file_type().is_socket() {
            return Err(Failure::refused(format!(
                "{} is in the way of Splint's socket",
                path.display()
            )));
        }
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(Failure::refused(
                "Splint on this computer is running already",
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(ONLY_THIS_USER))?;
    Ok(listener)
}

/// On Windows, the pipe only this user can open, as Signet's is: taken as its first instance, so one
/// another copy or another program serves already stops this one, and only then the lock held while
/// it runs, which a client checks before it sends anything, as any user can make a pipe of that name
/// while this is stopped. The lock is kept with the pipe, so it goes only when the pipe does.
#[cfg(windows)]
fn serve_pipe(
    name: std::ffi::OsString,
    lock: &std::path::Path,
) -> Result<crate::pipes::Served, Failure> {
    use splint_core::private_files::pipe::{PrivatePipe, held_elsewhere, hold, is_held};
    let running_already = || Failure::refused("Splint on this computer is running already");
    let pipe = PrivatePipe::first(name.clone()).map_err(|error| {
        if error.kind() != std::io::ErrorKind::AddrInUse {
            error.into()
        } else if is_held(lock) {
            running_already()
        } else {
            // Any user can take a pipe's name while nothing serves it, and its name is no secret, so
            // this says so rather than that Splint is running, which would be false: nothing is sent
            // there, as clients see no lock held.
            Failure::refused(format!(
                "another program, possibly another user's on this computer, has Splint's pipe {}, \
                 so Splint here won't start until that program ends, and nothing is sent to it",
                name.to_string_lossy()
            ))
        }
    })?;
    let held = hold(lock).map_err(|error| {
        if held_elsewhere(&error) {
            running_already()
        } else {
            error.into()
        }
    })?;
    Ok(crate::pipes::Served::new(pipe, held))
}

/// Sets the recovery code of the owner ID on this computer, once, and shows it once, in the terminal of
/// the person who ran this. Nothing keeps it: it's theirs to write down. Run with no terminal, as an
/// agent's shell runs a command, it makes nothing, so the code doesn't land in a program's output, or
/// an agent's transcript, by accident. That's all it guards: a program running as the person can run
/// this in a terminal of its own, or set the code through the page with the passphrase or the chip's
/// touch, and with a plain key file it can sign anything anyway. Only the passphrase or the chip
/// stands between such a program and the code.
pub async fn set_recovery_code(home: &Home) -> Result<String, Failure> {
    use std::io::IsTerminal as _;
    if !(std::io::stdout().is_terminal() && std::io::stdin().is_terminal()) {
        return Err(Failure::refused(
            "your recovery code is shown only in a terminal you type in, so run splint computer \
             recovery yourself, or set it on your controls page",
        ));
    }
    let owner = owner_here(home);
    if !owner.recovery_not_set() {
        return Err(Failure::refused(
            "there's no owner ID on this computer without a recovery code, so nothing was made",
        ));
    }
    // A locked key file signs only with its passphrase, which a person at this terminal types.
    let passphrase = match owner.sign_in() {
        Some(SignIn::LockedFile) => Some(crate::authorize::secret("Your sign-in's passphrase:")?),
        Some(SignIn::PlainFile) => {
            crate::authorize::say(PLAIN_KEY_FILE_WARNING)?;
            None
        }
        _ => None,
    };
    // The list of agents set up here goes to the home host signed in the same run, so losing this
    // computer doesn't lose them, and every host hears the code is set.
    let computer = Computer::new(home)?;
    let given = computer.list_given(Vec::new()).await;
    let list_text = given.as_ref().map(Value::to_string);
    let (code, list) = owner.set_recovery_code(passphrase.as_deref(), list_text.as_deref())?;
    if let Some(identity) = owner.kept_identity() {
        computer.code_was_set(&identity, given.as_ref(), list).await;
    }
    Ok(format!(
        "Your recovery code, shown this once:\n\n  {code}\n\nWrite it down, or save it in a password \
         manager by hand. It gets your owner ID back if you lose every sign-in. Never give it to anyone, \
         your agents included, whoever asks."
    ))
}

/// `splint controls HOST`, run by the person: their controls on this computer, served by Splint here,
/// which signs with their sign-in here. `HOST` keeps the list of their agents, unless an agent set up
/// here named one first. Started if it isn't running, unless they ran `splint stop`, and opened in
/// their browser.
pub async fn open_controls(home: &Home, host: &str, open: bool) -> Result<String, Failure> {
    let home = home.the_default();
    if crate::page::controls::host_url(host).is_none() {
        return Err(Failure::refused(
            "that isn't a host's address, such as host.example",
        ));
    }
    let dir = home.computer_dir();
    Home::make_private(&dir)?;
    let kept = dir.join("home-host");
    if !kept.exists() {
        std::fs::write(&kept, host)?;
    }
    let client = Client::new(&home)?;
    if !client.is_up().await {
        // Its own words on why, such as another user having its pipe on Windows, which a keeper
        // there starting it again and again would otherwise leave unsaid. Only words said since this
        // start, as one from before is no reason now.
        let before = services::log_end(&home, SERVICE);
        let wont_start = |failure| match services::refusal_since(&home, SERVICE, before) {
            Some(said) => Failure::refused(format!("Splint on this computer won't start: {said}")),
            None => failure,
        };
        if let Started::LeftStopped = start(&home).map_err(wont_start)? {
            return Err(Failure::refused(
                "Splint here is stopped, as you ran splint stop, so run splint start first",
            ));
        }
        for _ in 0..20 {
            if client.is_up().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if !client.is_up().await {
            return Err(wont_start(Failure::refused(
                "Splint on this computer didn't start in time",
            )));
        }
    }
    let url = format!("http://localhost:{}/owner", port());
    let opening = client.page_opening().await?;
    if open {
        crate::page::controls::open_browser(&format!("{url}#open={opening}"));
        return Ok(format!(
            "Your controls are open on this computer, kept by Splint here:\n\n  {url}"
        ));
    }
    // Given to whatever ran this, an agent included, as anything running as the person gets an
    // opening on the socket anyway: what the page then signs needs their passphrase or the chip's
    // touch.
    Ok(format!(
        "Open your controls on this computer, kept by Splint here, within 5 minutes; the link works \
         once:\n\n  {url}#open={opening}"
    ))
}

/// Keeps Splint on this computer running and brings it back as Signet comes back. Starting it twice
/// does nothing.
pub fn start(home: &Home) -> Result<Started, Failure> {
    let home = home.the_default();
    let home_dir = std::env::var(HOME_SETTING)
        .map_err(|_| Failure::refused(format!("{HOME_SETTING} isn't set")))?;
    let port = port().to_string();
    let file_chosen = std::env::var(SIGN_IN_SETTING)
        .ok()
        .filter(|chosen| chosen == "file");
    services::start(
        &home,
        &Service {
            name: SERVICE,
            binary: THIS_PROGRAM,
            args: &["computer", "run"],
            env: [
                (HOME_SETTING, home_dir.as_str()),
                (PORT_SETTING, port.as_str()),
            ]
            .into_iter()
            .chain(file_chosen.as_deref().map(|file| (SIGN_IN_SETTING, file)))
            .collect(),
            keep: Keep::AcrossRestarts,
        },
    )
}

/// How a program run by this person reaches Splint on their computer.
pub struct Client {
    http: reqwest::Client,
    /// Held by Splint on this computer while it runs, which on Windows is checked before anything is
    /// sent down its pipe.
    #[cfg(windows)]
    lock: std::path::PathBuf,
}

const ORIGIN: &str = "http://splint-computer";

impl Client {
    pub fn new(home: &Home) -> Result<Self, Failure> {
        let home = home.the_default();
        Self::over(
            home.computer_socket(),
            #[cfg(windows)]
            home.computer_lock(),
        )
    }

    fn over(
        socket: std::path::PathBuf,
        #[cfg(windows)] lock: std::path::PathBuf,
    ) -> Result<Self, Failure> {
        let builder = reqwest::Client::builder();
        #[cfg(unix)]
        let builder = builder.unix_socket(socket);
        #[cfg(windows)]
        let builder = builder.windows_named_pipe(socket.into_os_string());
        Ok(Self {
            http: builder
                .no_proxy()
                .timeout(Duration::from_secs(120))
                .build()?,
            #[cfg(windows)]
            lock,
        })
    }

    #[cfg(unix)]
    async fn sent(&self, call: reqwest::RequestBuilder) -> Result<reqwest::Response, Failure> {
        Ok(call.send().await?)
    }

    /// On Windows any user can make a pipe with this one's name while Splint here is stopped, so this
    /// sends only while its lock is held: then no other user can make an instance of its pipe.
    #[cfg(windows)]
    async fn sent(&self, call: reqwest::RequestBuilder) -> Result<reqwest::Response, Failure> {
        match crate::pipes::send_while_served(&self.lock, call).await {
            Ok(response) => Ok(response),
            Err(Some(error)) => Err(error.into()),
            Err(None) => Err(Failure::refused(
                "Splint on this computer isn't running, so nothing was sent to it",
            )),
        }
    }

    pub async fn is_up(&self) -> bool {
        self.here().await.is_ok()
    }

    pub async fn here(&self) -> Result<Here, Failure> {
        Ok(self
            .sent(self.http.get(format!("{ORIGIN}/v0/here")))
            .await?
            .json()
            .await?)
    }

    pub async fn hand(&self, asked: &Asked) -> Result<Value, Failure> {
        Ok(self
            .sent(self.http.post(format!("{ORIGIN}/v0/asks")).json(asked))
            .await?
            .json()
            .await?)
    }

    pub async fn outcome(&self, id: &str) -> Result<Option<Outcome>, Failure> {
        Ok(self
            .sent(self.http.get(format!("{ORIGIN}/v0/asks/{id}")))
            .await?
            .json()
            .await?)
    }

    /// What the person here did with an ask, looked for every `every` until `limit` has passed, or
    /// nothing if it still waits then. It looks once more once `limit` has passed, as a process held
    /// up past it, by a slow or sleeping machine, would otherwise miss an answer given meanwhile.
    pub async fn answer_within(
        &self,
        id: &str,
        limit: Duration,
        every: Duration,
    ) -> Result<Option<Outcome>, Failure> {
        let started = tokio::time::Instant::now();
        loop {
            match self.outcome(id).await? {
                Some(Outcome::Waiting) | None if started.elapsed() < limit => {
                    tokio::time::sleep(every).await;
                }
                Some(Outcome::Waiting) | None => return Ok(None),
                ended => return Ok(ended),
            }
        }
    }

    pub async fn waiting(&self) -> Result<Waiting, Failure> {
        Ok(self
            .sent(self.http.get(format!("{ORIGIN}/v0/asks")))
            .await?
            .json()
            .await?)
    }

    /// Approves exactly the asks with these IDs, the ones shown with this code.
    pub async fn approve(
        &self,
        passphrase: Option<&str>,
        ids: &[String],
        code: &str,
    ) -> Result<Approval, Failure> {
        Ok(self
            .sent(
                self.http
                    .post(format!("{ORIGIN}/v0/approve"))
                    .json(&json!({"passphrase": passphrase, "ids": ids, "code": code})),
            )
            .await?
            .json()
            .await?)
    }

    /// A one-time opening for the page, for the person's browser alone.
    pub async fn page_opening(&self) -> Result<String, Failure> {
        #[derive(Deserialize)]
        struct Opened {
            opening: String,
        }
        let opened: Opened = self
            .sent(self.http.post(format!("{ORIGIN}/v0/page")))
            .await?
            .json()
            .await
            .map_err(|_| Failure::refused("Splint on this computer gave no opening"))?;
        Ok(opened.opening)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use splint_core::asks::sign_ask;
    use splint_core::requests::Schema;
    use splint_core::{RecoveryRule, SealingKey, SigningKey};

    fn identity() -> (SigningKey, Identity) {
        let key = SigningKey::generate().unwrap();
        let identity = Identity::create(
            &key,
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        )
        .unwrap();
        (key, identity)
    }

    fn schema(file: &str) -> Schema {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/schemas")
            .join(file);
        Schema::parse(&std::fs::read(path).unwrap()).unwrap()
    }

    /// Bug caught: a yes to a held step taken with a draft for another step or a schema that isn't its
    /// type, so the page lists an ask the prompt then drops. What it's shown with is `owner-key`'s.
    #[test]
    fn a_held_step_is_taken_only_with_its_own_draft() {
        let (key, agent) = identity();
        let (_, owner) = identity();
        let (_, other) = identity();
        let now = unix_now();
        let quote = schema("quote-1.json");
        let request = "d".repeat(64);
        let draft: ApprovalDraft = serde_json::from_value(json!({
            "owner": owner.id(), "agent": agent.id(), "operation": "confirm",
            "request": request, "version": 3, "prev": request, "latest_expiry": now + 3600,
            "terms": {
                "type": quote.name(),
                "requester": {"agent": agent.id(), "owner": owner.id()},
                "recipient": {"agent": other.id(), "owner": other.id()},
                "agreed": {"currency": "usd", "item": "catering", "quantity": 10},
                "result": {"amount_minor": 125_000, "valid_days": 7},
                "subject": null, "note": null, "supersedes": null,
            },
        }))
        .unwrap();
        let ask = sign_ask(
            &key,
            agent.id(),
            owner.id(),
            vec![Change::Step {
                request: draft.request.clone(),
                operation: draft.operation,
            }],
            now,
            3600,
        )
        .unwrap();
        let verified = VerifiedAsk::verify(&ask, &agent, now).unwrap();
        let mut asked = Asked {
            ask,
            identity: agent.encoded(),
            address: "muse~host.example".to_owned(),
            draft: None,
            schema: None,
            linked: false,
            kinds: Vec::new(),
            agreed: Vec::new(),
            in_words: Default::default(),
        };
        assert!(!step_held(&verified, &asked), "no draft");
        let mut other_step = draft.clone();
        other_step.operation = splint_core::requests::Operation::Accept;
        asked.draft = Some(other_step);
        asked.schema = Some(quote.clone());
        assert!(!step_held(&verified, &asked), "a draft for another step");
        asked.draft = Some(draft);
        asked.schema = Some(schema("meeting-1.json"));
        assert!(!step_held(&verified, &asked), "another type's schema");
        asked.schema = Some(quote);
        assert!(step_held(&verified, &asked));
    }
}

#[cfg(test)]
#[cfg(windows)]
mod windows_tests {
    use super::*;
    use splint_core::private_files::pipe::PrivatePipe;

    /// A pipe name and a private folder for its lock, this test's own.
    fn scratch(what: &str) -> (std::ffi::OsString, std::path::PathBuf) {
        let id = std::process::id();
        let dir = std::env::temp_dir().join(format!("splint-computer-{what}-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        splint_core::private_files::make_private_dir(&dir).unwrap();
        let name = format!(r"\\.\pipe\splint-computer-test-{what}-{id}");
        (name.into(), dir.join("computer.lock"))
    }

    /// The bug this catches: a program asking Splint here, or approving with a passphrase, down a pipe
    /// another user made with its name while Splint here was stopped, which would hear all of it.
    #[tokio::test]
    async fn nothing_goes_down_a_pipe_splint_here_doesnt_hold() {
        let (name, lock) = scratch("squatted");
        let mut squatter = PrivatePipe::first(name.clone()).unwrap();
        let client = Client::over(name.into(), lock).unwrap();
        assert!(!client.is_up().await);
        let ids = ["x".to_owned()];
        assert!(
            client
                .approve(Some("a passphrase"), &ids, "code")
                .await
                .is_err()
        );
        let heard = tokio::time::timeout(Duration::from_millis(500), squatter.accept()).await;
        assert!(heard.is_err(), "the squatter was reached");
    }

    /// The bug this catches: Splint here starting on a pipe something else serves, another copy or a
    /// program waiting to hear what's sent to it, or holding its lock then, so clients send to that.
    #[tokio::test]
    async fn splint_here_wont_serve_a_pipe_something_else_has() {
        let (name, lock) = scratch("taken");
        let _squatter = PrivatePipe::first(name.clone()).unwrap();
        let refused = serve_pipe(name, &lock).err().unwrap();
        // Never taken, not only let go, as a client checking meanwhile would send to the squatter.
        assert!(!lock.exists(), "the lock was taken");
        // Not mistaken for another copy, so the person isn't told Splint here runs when it doesn't.
        assert!(!refused.to_string().contains("running already"));
    }

    /// The bug this catches: a client that takes Splint here for stopped while it serves its pipe, or
    /// a second copy starting beside it, so asks go nowhere or two copies answer.
    #[tokio::test]
    async fn a_client_reaches_splint_here_on_its_pipe() {
        let (name, lock) = scratch("served");
        let served = serve_pipe(name.clone(), &lock).unwrap();
        let second = serve_pipe(name.clone(), &lock).err().unwrap();
        assert!(
            second.to_string().contains("running already"),
            "a second copy"
        );
        let answering = Router::new().route(
            "/v0/here",
            get(|| async {
                Json(Here {
                    owner: None,
                    sign_in: None,
                    prompts_by_itself: false,
                    recovery_not_set: false,
                    plain_key_file: false,
                })
            }),
        );
        let serving = tokio::spawn(axum::serve(served, answering).into_future());
        let client = Client::over(name.into(), lock.clone()).unwrap();
        assert!(client.is_up().await);
        serving.abort();
        let _ = serving.await;
        assert!(
            !client.is_up().await,
            "stopped, and its lock gone with its pipe"
        );
    }
}

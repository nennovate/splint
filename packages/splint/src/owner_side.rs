//! The agent an owner looks after from this device, wherever it runs. Beside it, what they read comes
//! from its Signet and what they sign goes to it. With the agent on another device both go by way of its
//! host, which can hold them up or show old copies and can't do any more: what's read is checked here,
//! and what's signed counts only by the owner's signature.

use std::time::Duration;

use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use splint_core::changes::VerifiedHistory;
use splint_core::host_api::{HeldRules, OwnerMailKind};
use splint_core::owner_view::VerifiedOwnerView;
use splint_core::requests::{Schema, Schemas};
use splint_core::rules::{ContactStatus, PinnedBy, RulesContact, RulesDraft};
use splint_core::{Identity, SplintId, parse_address, unix_now};

use crate::authorize::{self, Authorized};
use crate::direct::{self, Direct, ForHost, NotTaken, RULES_AT_SIGNET, Route, Sent};
use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::host_calls::{self, HostCalls, SealedMail};
use crate::owner_key::{AtHost, ForAgent, OwnerKey};
use crate::page::state::{
    Notice, Notices, Refusals, Usage, UsageLine, WordsWaiting, invites_waiting, with_agreed,
};
use crate::page::walk::SignedRequests;
use crate::rules::{self, Added, Signed};
use crate::signet_api::{Held, RulesAtHost, SignetApi};

/// Who's held is read through the host, which may be away, and that shouldn't hold up the rest.
const HOST_WAIT: Duration = Duration::from_secs(6);

pub enum OwnerSide {
    Beside {
        installed: Box<Installed>,
        agent: SplintId,
    },
    Elsewhere(Box<Authorized>),
}

/// Everything an owner reads about their agent, none of it believed until it's walked.
pub struct View {
    pub requests: SignedRequests,
    pub changes: Notices,
    pub words: WordsWaiting,
    pub held: Option<Vec<Held>>,
    /// What was refused, which only a Signet beside this device hands over.
    pub refused: Option<Refusals>,
    /// When its host says it last heard from its Signet, with the agent elsewhere.
    pub heard_at: Option<u64>,
    /// The types its Signet says it agreed, each read here from its schema, so its ID is this device's
    /// own fingerprint of it whatever the Signet said, and a lying Signet can only leave one out.
    pub schemas: Schemas,
    /// Who kept the agent busy today, as its Signet counts it. Empty where it didn't say.
    pub usage: Vec<UsageLine>,
    /// Each type its Signet says it agreed, with whom, for the owner to approve one with currency.
    /// Only a Signet beside this device hands these over.
    pub kinds: Vec<(SplintId, Schema)>,
}

/// What a Signet with its owner elsewhere leaves at its host.
#[derive(Deserialize)]
struct Relayed {
    requests: SignedRequests,
    changes: Notices,
    words: WordsWaiting,
    held: Option<Vec<Held>>,
    /// Only those a draft names, to fit.
    #[serde(default)]
    schemas: Vec<Schema>,
    /// Left out by a Signet from before it was there.
    #[serde(default)]
    usage: Vec<UsageLine>,
}

/// Each schema once, by the ID this device works out for it.
fn schemas_of(schemas: Vec<Schema>) -> Schemas {
    let mut once = std::collections::BTreeMap::new();
    for schema in schemas {
        once.insert(schema.name().clone(), std::sync::Arc::new(schema));
    }
    Schemas::of(once.into_values()).unwrap_or_default()
}

/// Something the owner signed, on its way to their agent's Signet: as `owner-key` handed it back for
/// where the agent is, which [`OwnerSide::at_host`] says.
pub enum OwnerSigned {
    Approval(ForAgent),
    Acceptance(ForAgent),
    PersonText(ForAgent),
    WherePaid(ForAgent),
}

/// What's said when something was signed for one place and handed over for the other, which nothing
/// here does. It's never sent to a host as it was signed.
const NOT_SEALED: &str = "that wasn't signed for where this agent is, so nothing was sent: an agent \
     elsewhere takes only what was sealed for it";

impl OwnerSide {
    /// The agent named, or the only one this could mean. `what` is what the owner's trying to do.
    pub fn resolve(home: &Home, named: Option<&str>, what: &str) -> Result<Self, Failure> {
        if let Some(address) = named {
            return Ok(Self::Elsewhere(Box::new(authorize::named(home, address)?)));
        }
        if let Some(record) = authorize::the_agent_elsewhere(home)? {
            return Ok(Self::Elsewhere(Box::new(record)));
        }
        let (installed, agent) = Installed::require_owner_here(home, what)?;
        Ok(Self::Beside {
            installed: Box::new(installed),
            agent,
        })
    }

    /// Every agent this device signs for. The agents authorized from here go with the default profile
    /// alone, so two profiles never both sign for one.
    pub fn all(home: &Home) -> Result<Vec<Self>, Failure> {
        let mut sides: Vec<Self> = if home.profile().is_none() {
            authorize::all(home)?
                .into_iter()
                .map(|record| Self::Elsewhere(Box::new(record)))
                .collect()
        } else {
            Vec::new()
        };
        if let Some(installed) = Installed::load(home)?
            && installed.owner_elsewhere.is_none()
            && let Some(agent) = installed.agent.clone()
        {
            sides.push(Self::Beside {
                installed: Box::new(installed),
                agent,
            });
        }
        Ok(sides)
    }

    pub fn address(&self) -> &str {
        match self {
            Self::Beside { installed, .. } => &installed.address,
            Self::Elsewhere(record) => &record.address,
        }
    }

    pub fn agent(&self) -> &SplintId {
        match self {
            Self::Beside { agent, .. } => agent,
            Self::Elsewhere(record) => &record.agent,
        }
    }

    pub fn is_elsewhere(&self) -> bool {
        matches!(self, Self::Elsewhere(_))
    }

    /// Where what the owner signs for this agent is left, with it elsewhere: its host, and the agent's
    /// ID to seal to. That's this device's copy of the ID, or a newer one its host gives, as after the
    /// agent's keys were recovered, which counts only where it carries this copy on. So a host can't
    /// have something sealed to a key it chose, or to one the agent has since replaced.
    pub async fn at_host(&self) -> Result<Option<AtHost>, Failure> {
        let Self::Elsewhere(record) = self else {
            return Ok(None);
        };
        let (_, domain) = parse_address(&record.address)?;
        let here = Identity::from_encoded(record.identity())?;
        let found = match HostCalls::new(domain) {
            Ok(host) => tokio::time::timeout(HOST_WAIT, host.resolve(&record.address))
                .await
                .ok()
                .and_then(Result::ok),
            Err(_) => None,
        };
        let agent = agent_to_seal_to(here, found.as_ref().map(|found| found.identity.as_str()));
        Ok(Some(AtHost {
            domain: domain.to_owned(),
            agent: agent.encoded(),
        }))
    }

    /// The rules in force, which every change starts from: the newest this owner signed on any of
    /// their devices, as this agent's Signet and host hold them, checked here, or this device's own when
    /// they're as new. With neither reachable nothing is read, and nothing is signed.
    pub async fn rules(&self, home: &Home) -> Result<Signed, Failure> {
        self.rules_if_any(home).await?.ok_or_else(|| {
            Failure::refused(
                "there are no rules yet: they're signed when the owner sets up their controls for this agent",
            )
        })
    }

    /// As [`Self::rules`], or none when nobody has signed any for this agent yet.
    pub async fn rules_if_any(&self, home: &Home) -> Result<Option<Signed>, Failure> {
        match self {
            Self::Beside { installed, agent } => rules_beside(home, installed, agent).await,
            Self::Elsewhere(record) => {
                let owner = owner_now(home, &record.address).await?;
                let mut reads = vec![held_at_host(home, &record.address, &record.agent).await];
                // Rules its Signet took straight from here, while its host couldn't, count too.
                if let Some(direct) = Direct::find(home, &record.agent)?
                    && let Some(read) = direct.rules().await
                {
                    reads.push(read);
                }
                rules::newest(Some(record.signed_rules()), reads, &owner, &record.agent)
            }
        }
    }

    /// The rules in force where they can be read, or else the ones this device signed last, for what
    /// signs no rules and only names who's who, such as what's waiting and whom the owner's words go
    /// to. With the agent's host away and its Signet reached only over the network, nothing hands the
    /// rules in force out, and reading shouldn't stop for that. A change never starts from these.
    pub async fn rules_or_kept_here(&self, home: &Home) -> Result<Signed, Failure> {
        match self.rules(home).await {
            Ok(rules) => Ok(rules),
            Err(_) => self.rules_kept_here(home),
        }
    }

    /// The rules this device last signed, for what only goes by them and signs no rules: they may be
    /// behind another of the owner's devices.
    pub fn rules_kept_here(&self, home: &Home) -> Result<Signed, Failure> {
        match self {
            Self::Beside { .. } => rules::last_signed(home)?.ok_or_else(|| {
                Failure::refused(
                    "there are no rules yet: they're signed when the owner sets up their controls for this agent",
                )
            }),
            Self::Elsewhere(record) => Ok(record.signed_rules()),
        }
    }

    /// Who the agent deals with, as its Signet's `/v0/contacts` has them: the rules' contacts, then the
    /// ones no rules name yet, who redeemed the owner's invitation or whom the agent agreed with by
    /// itself. With the agent elsewhere its host doesn't hand over what Signet keeps for the agent, so
    /// those it agreed with are the ones whose invite both agents signed, checked here.
    pub async fn contacts(&self, home: &Home) -> Result<Vec<RulesContact>, Failure> {
        // Only to name who's who, so it doesn't wait on the rules in force being readable.
        let rules = self.rules_or_kept_here(home).await?.draft;
        let Self::Beside { installed, .. } = self else {
            // Who's held may not be there to read, and the rules' contacts still are.
            let held = tokio::time::timeout(HOST_WAIT, self.held(home))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
            return Ok(with_agreed(
                &rules.contacts,
                &invites_waiting(&held, self.agent()),
            ));
        };
        let mut contacts = rules.contacts;
        let agreed: Vec<RulesContact> = SignetApi::new(home, installed)?
            .contacts()
            .await?
            .into_iter()
            .filter_map(|contact| {
                let agent = contact.agent?;
                let named = contacts.iter().any(|known| known.agent == agent);
                (!named && contact.known_contact).then(|| RulesContact {
                    agent,
                    label: contact.address.clone(),
                    address: contact.address,
                    status: ContactStatus::Allowed,
                    types: Vec::new(),
                    text: false,
                    agree_types: false,
                    // Anything but the owner's own invitation reads as the agent's choice, the
                    // cautious way round.
                    pinned_by: match contact.pinned_by {
                        Some(PinnedBy::Invite) => PinnedBy::Invite,
                        _ => PinnedBy::Agent,
                    },
                })
            })
            .collect();
        contacts.extend(agreed);
        Ok(contacts)
    }

    /// Whom the agent agreed with by itself at `address`, for the owner to take out, as Remove on the
    /// controls page goes by: only an invite both agents signed counts, checked here, so a host can't
    /// make one up. A Signet, or a host replaying an older signed pair, still can; the worst is naming the
    /// address for the wrong agent with nothing to use, which lets nobody new in.
    pub async fn agreed_at(&self, home: &Home, address: &str) -> Result<Option<SplintId>, Failure> {
        Ok(self
            .held(home)
            .await?
            .iter()
            .filter(|one| one.kind == "agreed")
            .filter_map(|one| one.invite.as_ref()?.verify(self.agent()).ok())
            .find(|pair| pair.address == address)
            .map(|pair| pair.agent))
    }

    /// Whether the agent's Signet beside this device says `address` came in by the owner's own
    /// invitation, only for the words of a refusal. With the agent elsewhere its host doesn't say.
    pub async fn came_by_invitation(&self, home: &Home, address: &str) -> Result<bool, Failure> {
        let Self::Beside { installed, .. } = self else {
            return Ok(false);
        };
        Ok(SignetApi::new(home, installed)?
            .contacts()
            .await?
            .iter()
            .any(|contact| {
                contact.address == address && contact.pinned_by == Some(PinnedBy::Invite)
            }))
    }

    /// Says what the host did with them when Signet is beside this device. From elsewhere they go to
    /// the host itself, whose refusal is a failure, so there's nothing more to say.
    pub async fn apply_rules(
        &self,
        home: &Home,
        draft: RulesDraft,
    ) -> Result<Option<RulesAtHost>, Failure> {
        match self {
            Self::Beside { installed, agent } => {
                rules::sign_and_apply(home, installed, agent, draft).await
            }
            Self::Elsewhere(record) => authorize::sign_and_send(home, record, draft)
                .await
                .map(|_| None),
        }
    }

    pub async fn add_contact(
        &self,
        home: &Home,
        address: &str,
        id: &str,
    ) -> Result<String, Failure> {
        match self {
            Self::Beside { .. } => crate::contacts::add(home, address, id).await,
            Self::Elsewhere(record) => authorize::add(home, record, address, id).await,
        }
    }

    pub async fn read(&self, home: &Home) -> Result<View, Failure> {
        match self {
            Self::Beside { installed, .. } => {
                let api = SignetApi::new(home, installed)?;
                let requests = api.owner_read("/v0/owner/requests").await?;
                let changes = api.owner_read("/v0/owner/changes").await?;
                let words = api.owner_read("/v0/owner/person-text").await?;
                let held = tokio::time::timeout(HOST_WAIT, api.held())
                    .await
                    .ok()
                    .and_then(Result::ok);
                let refused = tokio::time::timeout(
                    HOST_WAIT,
                    api.owner_read::<Refusals>("/v0/owner/refused"),
                )
                .await
                .ok()
                .and_then(Result::ok);
                let kinds = api.agreed_kinds().await?;
                let schemas = schemas_of(kinds.iter().map(|(_, schema)| schema.clone()).collect());
                // Only something to read, so a Signet from before it was there leaves it empty.
                let usage = api
                    .owner_read::<Usage>("/v0/owner/usage")
                    .await
                    .map(|read| read.usage)
                    .unwrap_or_default();
                Ok(View {
                    requests,
                    changes,
                    words,
                    held,
                    refused,
                    heard_at: None,
                    schemas,
                    usage,
                    kinds,
                })
            }
            Self::Elsewhere(record) => read_elsewhere(home, record).await,
        }
    }

    /// Who's held right now, for something that signs on the strength of it.
    pub async fn held(&self, home: &Home) -> Result<Vec<Held>, Failure> {
        match self {
            Self::Beside { installed, .. } => SignetApi::new(home, installed)?.held().await,
            Self::Elsewhere(record) => read_elsewhere(home, record)
                .await?
                .held
                .ok_or_else(|| Failure::refused("this agent's Signet hasn't said who's waiting")),
        }
    }

    /// The contacts the agent agreed with by itself that `new` rules would take out, where `old` let
    /// them in, for the owner to hear before they sign. `None` where who they are couldn't
    /// be read in time.
    pub async fn added_taken_out(
        &self,
        home: &Home,
        old: &RulesDraft,
        new: &RulesDraft,
    ) -> Option<Vec<Added>> {
        if !old.lets_agreed_in() || new.lets_agreed_in() {
            return Some(Vec::new());
        }
        let held = tokio::time::timeout(HOST_WAIT, self.held(home))
            .await
            .ok()?
            .ok()?;
        Some(rules::added_taken_out(old, new, &held, self.agent()))
    }

    pub async fn hand_over(&self, home: &Home, signed: OwnerSigned) -> Result<(), Failure> {
        match self {
            Self::Beside { installed, .. } => {
                let api = SignetApi::new(home, installed)?;
                let (path, field, ForAgent::Beside(signed)) = (match signed {
                    OwnerSigned::Approval(signed) => ("/v0/owner/approvals", "approval", signed),
                    OwnerSigned::Acceptance(signed) => {
                        ("/v0/owner/changes/accept", "acceptance", signed)
                    }
                    OwnerSigned::PersonText(signed) => {
                        ("/v0/owner/person-text", "person_text", signed)
                    }
                    OwnerSigned::WherePaid(signed) => {
                        ("/v0/owner/where-paid", "where_paid", signed)
                    }
                }) else {
                    return Err(Failure::refused(NOT_SEALED));
                };
                api.owner_post(path, &json!({ field: signed })).await
            }
            Self::Elsewhere(record) => {
                let (kind, ForAgent::Elsewhere(sealed)) = (match signed {
                    OwnerSigned::Approval(signed) => (OwnerMailKind::Approval, signed),
                    OwnerSigned::Acceptance(signed) => (OwnerMailKind::Acceptance, signed),
                    OwnerSigned::PersonText(signed) => (OwnerMailKind::PersonText, signed),
                    OwnerSigned::WherePaid(signed) => (OwnerMailKind::WherePaid, signed),
                }) else {
                    return Err(Failure::refused(NOT_SEALED));
                };
                let mail = SealedMail {
                    body: sealed.body,
                    proof: sealed.proof,
                    session: None,
                };
                hand_over_elsewhere(
                    home,
                    &record.agent,
                    &record.address,
                    kind,
                    &sealed.signed,
                    mail,
                )
                .await
            }
        }
    }

    /// What a person's told once something's handed over, as with the agent elsewhere it takes a moment.
    pub fn signed_words(&self, beside: &'static str, elsewhere: &'static str) -> &'static str {
        if self.is_elsewhere() {
            elsewhere
        } else {
            beside
        }
    }
}

/// The rules in force for the agent beside this device, as [`OwnerSide::rules_if_any`] reads them:
/// from its Signet and its host at once, so a host that's away holds up nothing for long.
pub async fn rules_beside(
    home: &Home,
    installed: &Installed,
    agent: &SplintId,
) -> Result<Option<Signed>, Failure> {
    let owner = owner_now(home, &installed.address).await?;
    let signet = async {
        SignetApi::new(home, installed)?
            .owner_read::<HeldRules>(RULES_AT_SIGNET)
            .await
    };
    let host = tokio::time::timeout(HOST_WAIT, held_at_host(home, &installed.address, agent));
    let (signet, host) = tokio::join!(signet, host);
    let host =
        host.unwrap_or_else(|_| Err(Failure::refused("this agent's host didn't answer in time")));
    rules::newest(rules::last_signed(home)?, vec![signet, host], &owner, agent)
}

/// The owner's ID as it is now, to check rules by: this device's copy, or a newer one the agent's host
/// gives, as after a sign-in on another device was added, which counts only where it carries this
/// copy's chain on by the owner's own signatures. Anything else, or no answer, leaves this copy, so a
/// host can't choose whose rules count.
pub async fn owner_now(home: &Home, address: &str) -> Result<Identity, Failure> {
    let here = Identity::from_encoded(&OwnerKey::new(home).existing_identity()?)?;
    let (_, domain) = parse_address(address)?;
    let found = match HostCalls::new(domain) {
        Ok(host) => tokio::time::timeout(HOST_WAIT, host.resolve(address))
            .await
            .ok()
            .and_then(Result::ok),
        Err(_) => None,
    };
    Ok(owner_to_check_by(
        here,
        found.as_ref().map(|found| found.owner_identity.as_str()),
    ))
}

/// Whose rules count, by the owner's ID: this device's copy, or the one a host gives where it carries
/// this copy's chain on by the owner's own signatures. Another ID, or a copy that parts ways with this
/// one, leaves this copy, or a host would choose the rules every change starts from, and the owner's
/// own key would sign what they name.
pub fn owner_to_check_by(here: Identity, from_host: Option<&str>) -> Identity {
    from_host
        .and_then(|copy| Identity::from_encoded(copy).ok())
        .and_then(|copy| here.newest_of(&copy).ok())
        .unwrap_or(here)
}

/// What this agent's host holds as its rules, read as its owner.
async fn held_at_host(home: &Home, address: &str, agent: &SplintId) -> Result<HeldRules, Failure> {
    let (_, domain) = parse_address(address)?;
    let proof = OwnerKey::new(home).access_proof(domain, "GET", &host_calls::rules_path(agent))?;
    HostCalls::new(domain)?.held_rules(agent, &proof).await
}

/// The agent's ID to seal to: this device's copy, or the one a host gives where it carries this copy
/// on. Another ID, or a copy that parts ways with this one, leaves this copy, or a host would choose
/// the key what the owner signs is sealed to.
pub fn agent_to_seal_to(here: Identity, from_host: Option<&str>) -> Identity {
    from_host
        .and_then(|copy| Identity::from_encoded(copy).ok())
        .and_then(|copy| here.newest_of(&copy).ok())
        .unwrap_or(here)
}

/// Something the owner signed for an agent elsewhere, straight to its Signet where it can be reached
/// from here, and left at its host whatever that said. An answer from a Signet is nobody's signature,
/// and whatever answers at an address the owner named, on whichever network this device has joined,
/// could say yes and keep it. So it's done only once the host takes it, as rules are: one that only a
/// straight answer took is `Failure::NotYetAtHost`, and kept for the host. Its Signet takes what
/// reaches it both ways once. A refusal from a Signet on this computer is its answer, and said.
///
/// What goes to the host is only `mail`: what was signed, sealed to the agent on this device, with
/// the owner's proof for leaving exactly that, so the host holds nothing it can read. A host that
/// won't take it sealed is told nothing more: it's never sent any other way.
pub async fn hand_over_elsewhere(
    home: &Home,
    agent: &SplintId,
    address: &str,
    kind: OwnerMailKind,
    signed: &str,
    mail: SealedMail,
) -> Result<(), Failure> {
    let mut straight = None;
    if let Some(direct) = Direct::find(home, agent)? {
        match direct.hand_over(kind, signed).await {
            Ok(()) => straight = Some(direct.route()),
            Err(NotTaken::Refused(failure)) => return Err(failure),
            Err(NotTaken::Unanswered) => {}
        }
    }
    let (_, domain) = parse_address(address)?;
    let at_host = match HostCalls::new(domain) {
        Ok(host) => match host.leave_owner_mail(agent, &mail).await {
            // The owner's proof is good only for moments by the host's clock, so a clock here
            // that's off is why, and is what the person can put right.
            Err(Failure::HostRefused(StatusCode::UNAUTHORIZED)) => {
                Err(match host.clock_off().await {
                    Some(off) => Failure::ClockOff(format!(
                        "{domain} didn't take that, as {}",
                        splint_core::host_clock::described(off)
                    )),
                    None => Failure::HostRefused(StatusCode::UNAUTHORIZED),
                })
            }
            said => said,
        },
        Err(failure) => Err(failure),
    };
    let sent = Sent {
        kind: ForHost::of(kind),
        signed,
        sealed: Some(&mail.body),
    };
    direct::settle(home, agent, address, &sent, straight, at_host).map(|_| ())
}

/// What an agent elsewhere left its owner, read straight from its Signet where it can be reached from
/// here, or else from its host. Either is checked the same way, as either could be old or not its.
async fn read_elsewhere(home: &Home, record: &Authorized) -> Result<View, Failure> {
    if let Some(direct) = Direct::find(home, &record.agent)?
        && let Some(sealed) = direct.view().await
        && let Ok(view) = opened_view(home, record, &sealed)
        && view
            .heard_at
            .is_some_and(|at| direct::fresh_enough(home, &record.agent, at))
    {
        direct::note(home, &record.agent, direct.route());
        if let Some(at) = view.heard_at {
            direct::saw_view(home, &record.agent, at);
        }
        return Ok(view);
    }
    let (_, domain) = parse_address(&record.address)?;
    let path = format!(
        "{}/{}",
        splint_core::host_api::OWNER_VIEW_PATH,
        record.agent
    );
    let proof = OwnerKey::new(home).access_proof(domain, "GET", &path)?;
    let held = HostCalls::new(domain)?.owner_view(&path, &proof).await?;
    direct::note(home, &record.agent, Route::Host);
    let Some(view) = held.view else {
        return Ok(View {
            requests: SignedRequests::none_yet(record.identity()),
            changes: Notices {
                changes: Vec::new(),
            },
            words: WordsWaiting {
                waiting: Vec::new(),
            },
            held: None,
            refused: None,
            heard_at: None,
            schemas: Schemas::default(),
            usage: Vec::new(),
            kinds: Vec::new(),
        });
    };
    let view = opened_view(home, record, &view)?;
    if let Some(at) = view.heard_at {
        direct::saw_view(home, &record.agent, at);
    }
    Ok(view)
}

/// A view sealed to the owner, opened and checked as the agent's own.
fn opened_view(home: &Home, record: &Authorized, view: &str) -> Result<View, Failure> {
    let owner_key = OwnerKey::new(home);
    let signed = owner_key.open_view(&record.agent, view)?;
    // Anyone can seal to an owner, so only what the agent's own key signed is its view.
    let owner = Identity::from_encoded(&owner_key.identity()?)?;
    let agent = Identity::from_encoded(record.identity())?;
    let verified = VerifiedOwnerView::verify(&signed, &agent, owner.id(), unix_now())
        .ok()
        .filter(|_| agent.id() == &record.agent)
        .ok_or_else(|| {
            Failure::refused("what this agent's host holds for you isn't signed by your agent")
        })?;
    let heard_at = verified.issued_at();
    let relayed: Relayed = serde_json::from_value(verified.into_view())
        .map_err(|_| Failure::refused("what this agent's host holds for you doesn't make sense"))?;
    Ok(View {
        requests: relayed.requests,
        changes: Notices {
            changes: relayed
                .changes
                .changes
                .into_iter()
                .filter_map(checked_notice)
                .collect(),
        },
        words: relayed.words,
        held: relayed.held,
        refused: None,
        heard_at: Some(heard_at),
        schemas: schemas_of(relayed.schemas),
        usage: relayed.usage,
        kinds: Vec::new(),
    })
}

/// A yes to a change lifts a hold, so with a host between them an owner reads only what's signed. What
/// they've already said yes to shows again, as that's only a Signet's word from here.
fn checked_notice(mut notice: Notice) -> Option<Notice> {
    let history = VerifiedHistory::read(notice.history.as_deref()?).ok()?;
    if history.id() != &notice.contact || history.head() != notice.head {
        return None;
    }
    notice.since_accepted = serde_json::to_value(history.changes())
        .ok()
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let rival = notice
        .rewritten_history
        .as_deref()
        .and_then(|text| VerifiedHistory::read(text).ok())
        .filter(|rival| {
            rival.id() == &notice.contact && Some(rival.head()) == notice.rewritten_head
        });
    match rival {
        Some(rival) => {
            notice.rewritten_since = serde_json::to_value(rival.changes())
                .ok()
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default();
        }
        None => {
            notice.rewritten_head = None;
            notice.rewritten_since = Vec::new();
        }
    }
    Some(notice)
}

#[cfg(test)]
mod tests {
    use splint_core::{RecoveryRule, SealingKey, SigningKey};

    use super::*;

    fn owner() -> Result<(SigningKey, Identity), Failure> {
        let key = SigningKey::generate()?;
        let identity = Identity::create(
            &key,
            &SealingKey::generate()?.public_key(),
            RecoveryRule::backup_key(&SigningKey::generate()?.public_key()),
        )?;
        Ok((key, identity))
    }

    /// Bug caught: a host's answer choosing whose rules a change starts from, with another ID or a
    /// copy of the owner's that parts ways with this device's, so the owner's own key signed the
    /// contacts and permissions rules a key of the host's choosing signed.
    #[test]
    fn a_host_cant_choose_whose_rules_count() -> Result<(), Failure> {
        let (key, here) = owner()?;
        let (_, someone_else) = owner()?;
        let chosen = owner_to_check_by(here.clone(), Some(&someone_else.encoded()));
        assert_eq!(chosen.encoded(), here.encoded());

        let mine = here.add_key(&key, &SigningKey::generate()?, unix_now())?;
        let parted = here.add_key(&key, &SigningKey::generate()?, unix_now())?;
        let chosen = owner_to_check_by(mine.clone(), Some(&parted.encoded()));
        assert_eq!(chosen.encoded(), mine.encoded());

        // A sign-in another of the owner's devices added counts.
        let chosen = owner_to_check_by(here, Some(&mine.encoded()));
        assert_eq!(chosen.encoded(), mine.encoded());
        Ok(())
    }

    /// Bugs caught: a host's answer choosing the key what an owner signs is sealed to, by naming
    /// another agent's ID, and one sealed to a key the agent replaced, which its Signet can't open
    /// and whoever took the old key can.
    #[test]
    fn a_host_cant_choose_the_key_owner_mail_is_sealed_to() -> Result<(), Failure> {
        let agent = || -> Result<(SigningKey, SigningKey, Identity), Failure> {
            let (key, backup) = (SigningKey::generate()?, SigningKey::generate()?);
            let identity = Identity::create(
                &key,
                &SealingKey::generate()?.public_key(),
                RecoveryRule::backup_key(&backup.public_key()),
            )?;
            Ok((key, backup, identity))
        };
        let (_, backup, here) = agent()?;
        let (_, _, another) = agent()?;
        let sealed_to = agent_to_seal_to(here.clone(), Some(&another.encoded()));
        assert_eq!(sealed_to.encoded(), here.encoded());

        let recovered = here.recover(
            &backup,
            &SigningKey::generate()?.public_key(),
            &SealingKey::generate()?.public_key(),
            RecoveryRule::backup_key(&SigningKey::generate()?.public_key()),
            unix_now(),
        )?;
        assert_ne!(recovered.seal_key(), here.seal_key());
        // The host's newer copy, after a recovery this device hasn't heard of, is the one sealed to.
        let sealed_to = agent_to_seal_to(here.clone(), Some(&recovered.encoded()));
        assert_eq!(sealed_to.seal_key(), recovered.seal_key());
        // And a host showing the copy from before it changes nothing here.
        let sealed_to = agent_to_seal_to(recovered.clone(), Some(&here.encoded()));
        assert_eq!(sealed_to.seal_key(), recovered.seal_key());
        Ok(())
    }
}

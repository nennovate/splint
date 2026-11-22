//! The owner's signed rules for this agent, kept here and read on every decision they affect.
//!
//! There's no way to change them except a newer document the owner signed, so an agent can't touch
//! its own limits or contacts, and a host can't roll them back. Signet checks them again on
//! everything its host hands over, so a host can't push a stranger through to the agent.
//!
//! Someone the owner's reach setting lets in isn't a contact. Signet remembers them from their own
//! signed messages, so it knows where to answer, and the rules decide again on every use whether
//! they still count. It also remembers whom this agent has written to, for a filter on past exchanges.
//!
//! A contact this agent agreed with by itself, an invite one signed and the other accepted, counts only
//! if the owner's rules let such contacts in. Signet keeps each pair whose signatures it checked, and
//! the rules decide again on every use, so a block or a removal the owner signs always wins.
//!
//! Who they are goes by what's signed, and never by this agent's host: their owner under the newest
//! copy of that owner's ID seen here, and their host only by that host's own signature, under the key
//! the owner's rules name for it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::middleware;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::changes::{ChangeRules, VerifiedHistory};
use splint_core::contact_invites::{MAX_INVITE_LIFETIME_SECS, PendingContact};
use splint_core::contact_view::Standing;
use splint_core::host_api::{HeldRules, StoredMessage};
use splint_core::invites::{VerifiedRedeem, claimed_invite, redeem_body};
use splint_core::requests::Side;
use splint_core::requests::{InteractionType, is_step_body};
use splint_core::rules::{
    Admission, ContactStatus, Outbound, Permissions, PinnedBy, RulesContact, Sender, VerifiedRules,
    claimed_owner_part,
};
use splint_core::{
    DEFAULT_MESSAGE_LIFETIME_SECS, Identity, MessageId, Sealing, SplintId, VerifiedBinding,
    VerifiedEnvelope, parse_address, sign_envelope, unix_now,
};
use tokio::sync::Mutex;

use crate::Signet;
use crate::agent_api::ApiError;
use crate::changes::Seen;
use crate::contact_asks;
use crate::contacts::Known;
use crate::host_client::{Found, HostError};
use crate::requests::owner_api::require_owner_token;
use crate::state_file::{self, StateError};

const SAVED_RULES: &str = "rules";
/// New contacts this agent may agree with by itself in a day, as its host counts too. The host is the
/// count a fooled agent with this Signet's key can't skip. This one is for the honest path.
const AGREED_PER_DAY: usize = 100;
const DAY_SECS_AGREED: u64 = 24 * 60 * 60;
/// Far past what one agent deals with. Past this, whoever first wrote longest ago makes way, because a
/// list that stayed full would turn new people away for good. At the daily limit it takes weeks.
const MAX_REMEMBERED: usize = 4096;
/// A host that refused the current rules is offered them again after this, so one that's fixed or
/// upgraded takes them without the owner signing again, and one that goes on refusing is asked twice a
/// minute rather than on every pass.
const OFFER_REFUSED_RULES_AFTER: Duration = Duration::from_secs(30);

/// What this agent's host did with the newest rules, which an owner is told. It holds no word of the
/// host's own, as a host could write anything there.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RulesAtHost {
    /// It holds them, or ones the owner signed later.
    Taken,
    /// It hasn't answered for them yet: it's down, busy, its clock is off, or it doesn't know this
    /// agent yet.
    NotYet,
    /// It said no. An older host that can't read them does, and so does one holding rules these don't
    /// follow on from.
    Refused,
    /// It speaks another Splint protocol, so it or this Signet has to update.
    OtherProtocol,
    /// It holds a later recovery or revocation for this agent, which the owner has to act on.
    OutOfDate,
}

/// The host's last refusal of rules, kept so the owner hears of it and they're offered again.
struct HostRefusal {
    seq: u64,
    why: RulesAtHost,
    at: Instant,
}

/// Who redeemed an invitation, until the owner folds them into `contacts`.
#[derive(Clone, Serialize, Deserialize)]
struct Redeemed {
    agent: SplintId,
    address: String,
}

impl Redeemed {
    fn as_contact(&self, types: Vec<InteractionType>) -> RulesContact {
        RulesContact {
            agent: self.agent.clone(),
            address: self.address.clone(),
            label: self.address.clone(),
            status: ContactStatus::Allowed,
            types,
            text: false,
            // Only the types the invitation named, until their owner names them.
            agree_types: false,
            pinned_by: PinnedBy::Invite,
        }
    }
}

/// Someone who reached this agent by the owner's reach setting, as their own owner signed them.
#[derive(Clone, Serialize, Deserialize)]
struct Reached {
    address: String,
    owner: SplintId,
    /// How many recoveries of their owner's ID there had been. Past that, the key that signed for them
    /// has been given up, so they count for nothing until the new one signs.
    #[serde(default)]
    owner_recoveries: usize,
    /// A listed host, if it signed for their message under the key the owner's rules name.
    #[serde(default)]
    host: Option<String>,
    /// When they first got here, which decides who makes way when the list is full.
    #[serde(default)]
    at: u64,
    /// The newest thing an owner has signed about who they act for that's been seen here. It only
    /// rises, so a host can't bring back an old owner by showing what they signed before.
    #[serde(default)]
    binding_seq: u64,
    /// Their owner has said they act for nobody, and hasn't signed since.
    #[serde(default)]
    nobody: bool,
    /// Their owner hasn't confirmed them yet, as that owner's ID shows.
    #[serde(default)]
    unconfirmed: bool,
}

impl Reached {
    fn is_the_same_as(&self, other: &Self) -> bool {
        self.address == other.address
            && self.owner == other.owner
            && self.owner_recoveries == other.owner_recoveries
            && self.host == other.host
            && self.binding_seq == other.binding_seq
            && self.nobody == other.nobody
            && self.unconfirmed == other.unconfirmed
    }
}

/// A contact this agent agreed with by itself, as both agents signed it.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgreedPair {
    pub record: PendingContact,
    /// Where the invite says they are, which their owner's binding put them.
    pub address: String,
    pub at: u64,
}

/// What Signet learned about a sender just let in, for pinning them.
struct NewlyReached {
    address: String,
    owner: Identity,
    made_way: Option<String>,
}

pub struct RulesStore {
    known: Arc<Known>,
    seen_changes: Arc<Seen>,
    path: PathBuf,
    current: Mutex<Option<VerifiedRules>>,
    redeemed_path: PathBuf,
    /// Invitation ID to who used it. The rules still decide whether that counts for anything.
    redeemed: Mutex<HashMap<String, Redeemed>>,
    reached_path: PathBuf,
    /// Agent ID to who they are. The rules still decide whether that counts for anything.
    reached: Mutex<HashMap<SplintId, Reached>>,
    met_path: PathBuf,
    /// Everyone this agent has written to, by its own choice.
    met: Mutex<HashSet<SplintId>>,
    agreed_path: PathBuf,
    /// Contacts this agent agreed with by itself, by their ID. The rules still decide whether that
    /// counts for anything.
    agreed: Mutex<HashMap<SplintId, AgreedPair>>,
    /// This agent, which every pair kept here has to name.
    own: SplintId,
    /// The newest `seq` this agent's host has taken. It isn't saved, because hearing the same rules
    /// again costs a host nothing.
    pushed: AtomicU64,
    /// Nor is this, because the first pass after a restart offers the rules again and finds out.
    refused: Mutex<Option<HostRefusal>>,
}

impl RulesStore {
    /// Rules on disk are checked again, so a file that no longer fits this owner counts as none.
    pub fn load(
        path: PathBuf,
        state: &Path,
        owner: &Identity,
        agent: &SplintId,
        known: Arc<Known>,
        seen_changes: Arc<Seen>,
    ) -> Result<Self, StateError> {
        let redeemed_path = state.join("redeemed.json");
        let reached_path = state.join("reached.json");
        let met_path = state.join("met.json");
        let agreed_path = state.join("invites-agreed.json");
        // Checked again, so a file edited to name someone counts for nothing.
        let agreed = by_id(state_file::load::<AgreedPair>(&agreed_path)?)
            .into_iter()
            .filter(|(id, pair)| {
                pair.record
                    .verify(agent)
                    .is_ok_and(|new| &new.agent == id && new.address == pair.address)
            })
            .collect();
        let mut saved = state_file::load::<String>(&path)?;
        let current = saved.remove(SAVED_RULES).and_then(|compact| {
            VerifiedRules::reload(&compact, owner)
                .ok()
                .filter(|rules| rules.agent() == agent)
        });
        Ok(Self {
            known,
            seen_changes,
            path,
            current: Mutex::new(current),
            redeemed: Mutex::new(state_file::load(&redeemed_path)?),
            redeemed_path,
            reached: Mutex::new(by_id(state_file::load(&reached_path)?)),
            reached_path,
            met: Mutex::new(
                by_id(state_file::load::<bool>(&met_path)?)
                    .into_keys()
                    .collect(),
            ),
            met_path,
            agreed: Mutex::new(agreed),
            agreed_path,
            own: agent.clone(),
            pushed: AtomicU64::new(0),
            refused: Mutex::new(None),
        })
    }

    /// What a replaced owner key signed stops counting, including anything a thief signed with it, so
    /// the owner signs new ones. `seq` starts over, since nothing here can vouch for the old high.
    pub async fn clear(&self) -> Result<(), HostError> {
        let mut current = self.current.lock().await;
        let none = HashMap::<&str, String>::new();
        state_file::save(&self.path, &none).map_err(|_| HostError::LocalStorage)?;
        *current = None;
        self.pushed.store(0, Ordering::Relaxed);
        *self.refused.lock().await = None;
        Ok(())
    }

    /// For when this agent gets a new owner, whose rules and invitations these aren't.
    pub async fn forget_everything(&self) -> Result<(), HostError> {
        self.clear().await?;
        let mut redeemed = self.redeemed.lock().await;
        redeemed.clear();
        state_file::save(&self.redeemed_path, &*redeemed).map_err(|_| HostError::LocalStorage)?;
        let mut reached = self.reached.lock().await;
        reached.clear();
        state_file::save(&self.reached_path, &*reached).map_err(|_| HostError::LocalStorage)?;
        let mut agreed = self.agreed.lock().await;
        agreed.clear();
        state_file::save(&self.agreed_path, &*agreed).map_err(|_| HostError::LocalStorage)?;
        let mut met = self.met.lock().await;
        met.clear();
        save_met(&self.met_path, &met)
    }

    /// Keeps a contact this agent agreed with by itself, if the owner's rules in force let such
    /// contacts in and the agent add contacts at all, they don't name the other already, the pair
    /// checks out, and today's count has room. Says whether it was kept: if not, the pair waits for
    /// the owner's side as before.
    pub async fn agree(&self, record: PendingContact, now: u64) -> Result<bool, HostError> {
        let Ok(new) = record.verify(&self.own) else {
            return Ok(false);
        };
        // Signet's own gate 2, as the host's: the host's record is what a fooled agent holding this
        // Signet's key can't skip, and this one is for the honest path, so these are defence in depth.
        let takes_them = self.current.lock().await.as_ref().is_some_and(|rules| {
            rules.in_force(now)
                && rules.reach().agreed.is_some()
                && rules.lets_its_agent_invite()
                && !rules.names(&new.agent)
        });
        if !takes_them {
            return Ok(false);
        }
        let mut agreed = self.agreed.lock().await;
        if agreed.contains_key(&new.agent) {
            return Ok(true);
        }
        let today = agreed
            .values()
            .filter(|pair| now.saturating_sub(pair.at) < DAY_SECS_AGREED)
            .count();
        if today >= AGREED_PER_DAY {
            tracing::info!(
                "this agent has agreed all the contacts it can today, so one waits for its owner"
            );
            return Ok(false);
        }
        agreed.insert(
            new.agent,
            AgreedPair {
                record,
                address: new.address,
                at: now,
            },
        );
        state_file::save(&self.agreed_path, &*agreed).map_err(|_| HostError::LocalStorage)?;
        Ok(true)
    }

    /// Forgets pairs the owner's rules now name either way, as the host does. What the owner signed
    /// about them stands, and dropping them later doesn't bring back what the agent agreed.
    fn settle_agreed(
        &self,
        agreed: &mut HashMap<SplintId, AgreedPair>,
        named: &[SplintId],
    ) -> Result<(), HostError> {
        let before = agreed.len();
        agreed.retain(|agent, _| !named.contains(agent));
        if agreed.len() == before {
            return Ok(());
        }
        state_file::save(&self.agreed_path, &*agreed).map_err(|_| HostError::LocalStorage)
    }

    /// Contacts this agent agreed with by itself that the owner's rules don't name, with what both
    /// signed, for the owner to approve, remove or block.
    pub async fn agreed_pairs(&self) -> Vec<(SplintId, AgreedPair)> {
        let rules = self.current.lock().await.clone();
        self.agreed
            .lock()
            .await
            .iter()
            .filter(|(agent, _)| rules.as_ref().is_none_or(|rules| !rules.names(agent)))
            .map(|(agent, pair)| (agent.clone(), pair.clone()))
            .collect()
    }

    /// Notes that this agent chose to write to someone, for a filter on past exchanges.
    pub async fn note_met(&self, peer: &SplintId) -> Result<(), HostError> {
        let mut met = self.met.lock().await;
        if met.contains(peer) || met.len() >= MAX_REMEMBERED {
            return Ok(());
        }
        met.insert(peer.clone());
        save_met(&self.met_path, &met)
    }

    /// A sender as this Signet knows them. What a key their owner has since given up said about them
    /// doesn't count, so an old key can't go on fitting a filter.
    fn sender_from<'a>(
        &self,
        agent: &'a SplintId,
        reached: Option<&'a Reached>,
        met: bool,
        agreed: bool,
    ) -> Sender<'a> {
        let current = reached.filter(|one| {
            !one.nobody && self.known.recoveries_of(&one.owner) <= one.owner_recoveries
        });
        Sender {
            agent,
            owner: current.map(|one| &one.owner),
            host: current.and_then(|one| one.host.as_deref()),
            met,
            unconfirmed: reached.is_some_and(|one| one.unconfirmed),
            agreed,
        }
    }

    /// Judges a sender by what this Signet kept when they reached it, and its own record of whom
    /// this agent has written to.
    async fn judged_as<T>(&self, agent: &SplintId, judge: impl FnOnce(&Sender) -> T) -> T {
        let reached = self.reached.lock().await.get(agent).cloned();
        let met = self.met.lock().await.contains(agent);
        let agreed = self.agreed.lock().await.contains_key(agent);
        judge(&self.sender_from(agent, reached.as_ref(), met, agreed))
    }

    /// The people the reach setting lets in now, as entries the agent can deal with.
    async fn reached_contacts(&self, rules: &VerifiedRules) -> Vec<RulesContact> {
        let reached = self.reached.lock().await.clone();
        let met = self.met.lock().await.clone();
        let agreed = self.agreed.lock().await.clone();
        reached
            .iter()
            .filter_map(|(agent, reached)| {
                let sender = self.sender_from(
                    agent,
                    Some(reached),
                    met.contains(agent),
                    agreed.contains_key(agent),
                );
                rules.reached_contact(&sender, &reached.address)
            })
            .collect()
    }

    /// Whether someone let in by reach acts for an owner who hasn't confirmed, as far as this Signet
    /// has seen.
    pub async fn is_unconfirmed(&self, agent: &SplintId) -> bool {
        self.reached
            .lock()
            .await
            .get(agent)
            .is_some_and(|one| one.unconfirmed)
    }

    /// The newest rules the owner signed that this Signet has seen.
    pub async fn current(&self) -> Option<VerifiedRules> {
        self.current.lock().await.clone()
    }

    /// What this agent's host did with the newest rules. None until there are rules.
    pub async fn at_host(&self) -> Option<RulesAtHost> {
        let seq = self.current.lock().await.as_ref()?.seq();
        if self.pushed.load(Ordering::Relaxed) >= seq {
            return Some(RulesAtHost::Taken);
        }
        let refused = self.refused.lock().await;
        let why = refused.as_ref().filter(|refusal| refusal.seq == seq);
        Some(why.map_or(RulesAtHost::NotYet, |refusal| refusal.why))
    }

    /// Whether this agent's host has the newest rules, which it does trivially when there are none.
    pub async fn host_holds_the_newest(&self) -> bool {
        self.current
            .lock()
            .await
            .as_ref()
            .is_none_or(|rules| self.pushed.load(Ordering::Relaxed) >= rules.seq())
    }

    /// Whether the host refused the current rules long enough ago that they're due another offer, so a
    /// quiet agent's Signet doesn't wait for something to arrive before trying.
    pub async fn due_another_offer(&self) -> bool {
        matches!(self.offer_again_at().await, Some(at) if at <= Instant::now())
    }

    /// When the current rules, which the host refused, may be offered again.
    async fn offer_again_at(&self) -> Option<Instant> {
        let seq = self.current.lock().await.as_ref()?.seq();
        if self.pushed.load(Ordering::Relaxed) >= seq {
            return None;
        }
        let refused = self.refused.lock().await;
        let refusal = refused.as_ref().filter(|refusal| refusal.seq == seq)?;
        Some(refusal.at + OFFER_REFUSED_RULES_AFTER)
    }

    /// With no rules yet, an agent has no contacts, so it can't take part in requests.
    pub async fn exist(&self) -> bool {
        self.current.lock().await.is_some()
    }

    /// Whether the rules let this agent act now. An agent no owner has written rules for yet
    /// isn't stopped: it just has no contacts.
    pub async fn stopped(&self) -> bool {
        self.current
            .lock()
            .await
            .as_ref()
            .is_some_and(|rules| !rules.in_force(unix_now()))
    }

    /// What this agent's owner signed about contacts' changes, or the defaults with no rules yet.
    pub async fn change_rules(&self) -> ChangeRules {
        let rules = self.current.lock().await;
        rules
            .as_ref()
            .map_or_else(ChangeRules::default, |rules| *rules.changes())
    }

    /// Where a contact stands, whatever has changed about them. Someone let in by reach was never
    /// vouched for by name, and the filter that let them in is judged again on what they are now, so
    /// nobody is asked about them, and only a history that's been rewritten stops them.
    pub async fn standing_of(&self, agent: &SplintId) -> Standing {
        let rules = self.change_rules().await;
        let standing = self.seen_changes.standing(agent, &rules, &self.known);
        if matches!(
            standing,
            Standing::Continue | Standing::Rewritten | Standing::Stopped
        ) {
            return standing;
        }
        let by_reach = self
            .named_contacts()
            .await
            .iter()
            .any(|contact| &contact.agent == agent && contact.pinned_by == PinnedBy::Reach);
        if by_reach {
            Standing::Continue
        } else {
            standing
        }
    }

    /// Whether a change to this contact has things waiting on it.
    pub async fn held_by_a_change(&self, agent: &SplintId) -> bool {
        self.standing_of(agent).await != Standing::Continue
    }

    /// With no rules, a sender is a stranger, and a stranger waits for the owner. Someone who'd be
    /// delivered but has a change waiting on their owner's word stays on the host, unseen.
    pub async fn admission_of(&self, sender: &SplintId) -> Admission {
        let admission = self.admission_by_rules(sender).await;
        if admission == Admission::Deliver && self.held_by_a_change(sender).await {
            return Admission::Wait;
        }
        admission
    }

    async fn admission_by_rules(&self, sender: &SplintId) -> Admission {
        let rules = self.current.lock().await.clone();
        let Some(rules) = rules else {
            return Admission::Quarantine;
        };
        let now = unix_now();
        // An owner may have invited them twice, with the first invitation since gone from the rules.
        let invite = self
            .redeemed
            .lock()
            .await
            .iter()
            .find(|(invite, redeemed)| {
                &redeemed.agent == sender && rules.invite_lets_in(invite, now)
            })
            .map(|(invite, _)| invite.clone());
        self.judged_as(sender, |judged| rules.admit(judged, invite.as_deref(), now))
            .await
    }

    /// Everyone this agent can deal with now, which leaves out anyone a change has waiting. So whatever
    /// goes by this list stops for them, and an agent can't get round that by naming them.
    pub async fn contacts(&self) -> Vec<RulesContact> {
        let mut contacts = self.all_contacts().await;
        let rules = self.change_rules().await;
        contacts.retain(|contact| {
            let standing = self
                .seen_changes
                .standing(&contact.agent, &rules, &self.known);
            standing == Standing::Continue
                || (contact.pinned_by == PinnedBy::Reach
                    && !matches!(standing, Standing::Rewritten | Standing::Stopped))
        });
        contacts
    }

    /// Everyone this agent deals with, whether or not a change has them waiting: who the rules list,
    /// who redeemed an invitation they still offer and doesn't appear in them, and who the reach setting
    /// lets in. A contact's address is the newest its own history gives.
    pub async fn all_contacts(&self) -> Vec<RulesContact> {
        self.named_contacts().await
    }

    /// Everyone the owner has named or invited, and anyone this agent agreed with by itself while the
    /// owner lets it, as opposed to anyone a setting let in, so this agent's history can be sure of
    /// them however many that setting lets in. The agent agrees with 100 a day at most.
    pub async fn contacts_by_name(&self) -> Vec<RulesContact> {
        let now = unix_now();
        let rules = self.current.lock().await.clone();
        let Some(rules) = rules.as_ref() else {
            return Vec::new();
        };
        let mut contacts: Vec<RulesContact> = rules.contacts(now).cloned().collect();
        let redeemed = self.redeemed.lock().await;
        for (invite, redeemed) in redeemed.iter() {
            let lets_in = rules.admit(&Sender::only(&redeemed.agent), Some(invite), now)
                == Admission::Deliver;
            let offered = rules.invite(invite).map(|offered| offered.types.clone());
            if let (true, Some(types)) = (lets_in, offered)
                && !contacts.iter().any(|c| c.agent == redeemed.agent)
            {
                contacts.push(redeemed.as_contact(types));
            }
        }
        drop(redeemed);
        if rules.in_force(now) {
            let agreed = self.agreed.lock().await;
            for (agent, pair) in agreed.iter() {
                let sender = Sender {
                    agreed: true,
                    ..Sender::only(agent)
                };
                let taken = contacts
                    .iter()
                    .any(|c| &c.agent == agent || c.address == pair.address);
                if let (false, Some(contact)) =
                    (taken, rules.agreed_contact(&sender, &pair.address))
                {
                    contacts.push(contact);
                }
            }
        }
        self.apply_moves(&mut contacts);
        contacts
    }

    /// Puts each contact at the address its own history gives, unless another contact is there, by the
    /// rules or by a move. A signed move says where this agent is, not that nobody else is: anyone can
    /// sign one, and the owner named the other contact at that address.
    fn apply_moves(&self, contacts: &mut [RulesContact]) {
        let as_named: Vec<(SplintId, String)> = contacts
            .iter()
            .map(|contact| (contact.agent.clone(), contact.address.clone()))
            .collect();
        for index in 0..contacts.len() {
            let Some(contact) = contacts.get(index) else {
                continue;
            };
            let agent = contact.agent.clone();
            let Some(address) = self.seen_changes.address_of(&agent) else {
                continue;
            };
            let taken = as_named
                .iter()
                .any(|(other, named)| other != &agent && named == &address)
                || contacts
                    .iter()
                    .any(|other| other.agent != agent && other.address == address);
            if let (false, Some(contact)) = (taken, contacts.get_mut(index)) {
                contact.address = address;
            }
        }
    }

    async fn named_contacts(&self) -> Vec<RulesContact> {
        let now = unix_now();
        let mut contacts = self.contacts_by_name().await;
        let rules = self.current.lock().await.clone();
        let Some(rules) = rules.as_ref() else {
            return contacts;
        };
        if rules.in_force(now) {
            for reached in self.reached_contacts(rules).await {
                let taken = contacts
                    .iter()
                    .any(|c| c.agent == reached.agent || c.address == reached.address);
                if !taken {
                    contacts.push(reached);
                }
            }
        }
        contacts
    }

    /// Whether a value with this agent in these types goes as the owner's settings say, rather than
    /// waiting for the owner to approve them, by the same rule the owner's device, page and Signet's
    /// delegate sign by, so what an agent is told and what happens can't part. Their owner, if not
    /// given, is the one pinned when reach let them in.
    pub async fn approves(
        &self,
        agent: &SplintId,
        owner: Option<&SplintId>,
        types: &[InteractionType],
    ) -> bool {
        let Some(rules) = self.current.lock().await.clone() else {
            return false;
        };
        let pinned = self
            .reached
            .lock()
            .await
            .get(agent)
            .map(|one| one.owner.clone());
        rules.approves(agent, owner.or(pinned.as_ref()), types)
    }

    /// Whether this agent may start something with whoever is at this address: a contact, or someone
    /// let in by reach when the owner's outbound setting lets it follow up with them.
    pub async fn may_start_with(&self, address: &str) -> bool {
        let Some(contact) = self.contact_at(address).await else {
            return false;
        };
        contact.pinned_by != PinnedBy::Reach || self.outbound().await == Some(Outbound::Replies)
    }

    async fn outbound(&self) -> Option<Outbound> {
        let rules = self.current.lock().await;
        rules.as_ref().map(|rules| rules.reach().outbound)
    }

    /// Whether this agent may move an interaction with `peer`, on this side of it. Someone let in by
    /// reach can be answered in what they started, and followed up with only if the owner says so.
    pub async fn may_move_with(&self, peer: &SplintId, role: Side) -> bool {
        if !self.lists_for_requests(peer).await || self.held_by_a_change(peer).await {
            return false;
        }
        let by_reach = self
            .contact_of(peer)
            .await
            .is_some_and(|contact| contact.pinned_by == PinnedBy::Reach);
        !by_reach || role == Side::Recipient || self.outbound().await == Some(Outbound::Replies)
    }

    /// How many messages of words may pass with `peer` in a day, each way, or none without rules.
    pub async fn texts_per_day_with(&self, peer: &SplintId) -> u32 {
        let Some(rules) = self.current().await else {
            return 0;
        };
        self.judged_as(peer, |sender| rules.texts_per_day_with(sender))
            .await
    }

    /// What the owner signed on how much this agent sends in an hour and a day, if anything.
    pub async fn sends_signed(&self) -> (Option<u32>, Option<u32>) {
        let rules = self.current.lock().await;
        rules.as_ref().map_or((None, None), |rules| {
            (rules.limits().sends_per_hour, rules.limits().sends_per_day)
        })
    }

    /// How much may come in a day from everyone let in by reach together, or none without rules.
    pub async fn new_from_others_per_day(&self) -> u32 {
        let rules = self.current.lock().await;
        rules
            .as_ref()
            .map_or(0, |rules| rules.limits().new_from_others_per_day)
    }

    /// How many interactions may start with `peer` in a day, each way, as the owner signed for a
    /// contact they named, or for one the agent added by itself, or none without rules.
    pub async fn new_requests_per_day_with(&self, peer: &SplintId) -> u32 {
        let Some(rules) = self.current().await else {
            return 0;
        };
        self.judged_as(peer, |sender| rules.new_requests_per_day_with(sender))
            .await
    }

    /// How many `open`s may wait for the owner at once, or none without rules.
    pub async fn open_approvals(&self) -> u32 {
        let rules = self.current.lock().await;
        rules
            .as_ref()
            .map_or(0, |rules| rules.limits().open_approvals)
    }

    /// What the owner chose. Without rules, the default, so nothing goes unsealed on no one's word.
    pub async fn sealing(&self) -> Sealing {
        let rules = self.current.lock().await;
        rules
            .as_ref()
            .map(VerifiedRules::sealing)
            .unwrap_or_default()
    }

    pub async fn permissions(&self) -> Option<Permissions> {
        let rules = self.current.lock().await;
        rules.as_ref().map(|rules| rules.permissions().clone())
    }

    pub async fn contact_at(&self, address: &str) -> Option<RulesContact> {
        let mut contacts = self.contacts().await.into_iter();
        contacts.find(|contact| contact.address == address)
    }

    pub async fn contact_of(&self, agent: &SplintId) -> Option<RulesContact> {
        let mut contacts = self.contacts().await.into_iter();
        contacts.find(|contact| &contact.agent == agent)
    }

    /// The same, whether or not a change has them waiting.
    pub async fn all_contact_of(&self, agent: &SplintId) -> Option<RulesContact> {
        let mut contacts = self.all_contacts().await.into_iter();
        contacts.find(|contact| &contact.agent == agent)
    }

    /// What the owner signed at this address, whatever it says, a block included, so a card or a host
    /// can't name someone else there.
    pub async fn signed_at(&self, address: &str) -> Option<RulesContact> {
        let rules = self.current.lock().await;
        rules.as_ref()?.named_at(address).cloned()
    }

    /// What the owner signed for this agent, a block included.
    pub async fn signed_for(&self, agent: &SplintId) -> Option<RulesContact> {
        let rules = self.current.lock().await;
        rules.as_ref()?.named(agent).cloned()
    }

    pub async fn blocks(&self, agent: &SplintId) -> bool {
        let rules = self.current.lock().await;
        rules.as_ref().is_some_and(|rules| rules.blocks(agent))
    }

    /// Whether an invite from this agent may reach this one's, by the owner's rules, as its host
    /// judged it too. With no rules yet, nobody has said no.
    pub async fn takes_invites_from(&self, agent: &SplintId) -> bool {
        let rules = self.current.lock().await;
        rules
            .as_ref()
            .is_none_or(|rules| rules.takes_invites_from(agent))
    }

    /// Whether the owner's rules let the agent invite anyone. With none, its host takes no invite.
    pub async fn let_agent_invite(&self) -> bool {
        let rules = self.current.lock().await;
        rules
            .as_ref()
            .is_some_and(VerifiedRules::lets_its_agent_invite)
    }

    /// Whether the agent adds contacts itself: its owner lets in those it agrees with by an invite, and
    /// lets it invite. Then it invites rather than asking its owner for one.
    pub async fn agent_adds_contacts(&self) -> bool {
        let rules = self.current.lock().await;
        rules.as_ref().is_some_and(|rules| {
            rules.lets_its_agent_invite()
                && rules.reach().agreed.is_some()
                && rules.in_force(unix_now())
        })
    }

    pub async fn has_reached(&self, agent: &SplintId) -> bool {
        self.reached.lock().await.contains_key(agent)
    }

    /// The owners this agent's filter names.
    pub async fn listed_owners(&self) -> Vec<SplintId> {
        let rules = self.current.lock().await;
        rules.as_ref().map_or_else(Vec::new, |rules| {
            rules.reach().inbound.filter.owners.clone()
        })
    }

    /// What a filter goes by follows who someone let in by reach acts for now, so an owner's filter
    /// stops letting them in the moment they've gone to someone it doesn't name. A copy older than what's
    /// known changes nothing. One under an owner's key given up since counts for nothing when it's read.
    pub async fn note_who_they_act_for(&self, history: &VerifiedHistory) -> Result<(), HostError> {
        let mut reached = self.reached.lock().await;
        let Some(one) = reached.get_mut(history.id()) else {
            return Ok(());
        };
        let Some(owner) = history.owner() else {
            return Ok(());
        };
        if history.binding_seq() == 0 || history.binding_seq() < one.binding_seq {
            return Ok(());
        }
        if &one.owner != owner {
            one.host = None;
            if let Some(address) = history.address() {
                address.clone_into(&mut one.address);
            }
        }
        one.owner = owner.clone();
        one.owner_recoveries = history.owner_recoveries();
        one.binding_seq = history.binding_seq();
        one.nobody = history.is_revoked();
        // A history carries the owners it names, and only a stand-in's ID shows it hasn't confirmed.
        one.unconfirmed = history
            .owners()
            .iter()
            .any(|named| named.id() == owner && named.is_unconfirmed_owner());
        state_file::save(&self.reached_path, &*reached).map_err(|_| HostError::LocalStorage)
    }

    /// Whether this agent can have requests, paused or not, by the rules or an invitation they offer.
    pub async fn lists_for_requests(&self, agent: &SplintId) -> bool {
        let rules = self.current.lock().await.clone();
        let Some(rules) = rules.as_ref() else {
            return false;
        };
        if rules.lists_for_requests(agent) {
            return true;
        }
        let now = unix_now();
        let invited = self.redeemed.lock().await.iter().any(|(invite, redeemed)| {
            &redeemed.agent == agent && rules.invite_lets_in(invite, now)
        });
        let known = self.reached.lock().await.contains_key(agent);
        let by_reach = known && self.judged_as(agent, |s| rules.lets_in_by_reach(s)).await;
        let agreed = self.judged_as(agent, |s| rules.lets_in_as_agreed(s)).await;
        !rules.blocks(agent) && (invited || by_reach || agreed)
    }

    /// Takes in a recovery of an owner the rules' filter names, from one of that owner's agents, so
    /// what the key they gave up signed stops counting here.
    async fn learn_listed_owner(&self, row: &StoredMessage) -> Result<(), HostError> {
        let rules = self.current.lock().await.clone();
        let Some(rules) = rules else {
            return Ok(());
        };
        let Ok(owner) = Identity::from_encoded(&row.sender_owner_identity) else {
            return Ok(());
        };
        if rules.reach().inbound.filter.owners.contains(owner.id()) {
            self.known.learn(&owner)?;
        }
        Ok(())
    }

    /// Remembers a sender the reach setting lets in, from what their own owner signed, so this agent
    /// can answer them. Anyone else, and anyone with no binding that checks out, is left alone.
    async fn note_reached(
        &self,
        sender: &Identity,
        envelope: &VerifiedEnvelope,
        row: &StoredMessage,
        me: &str,
    ) -> Result<Option<NewlyReached>, HostError> {
        let Some(rules) = self.current.lock().await.clone() else {
            return Ok(None);
        };
        let owner = Identity::from_encoded(&row.sender_owner_identity)
            .and_then(|presented| self.known.newest(&presented));
        let Ok(owner) = owner else {
            return Ok(None);
        };
        let Ok(binding) = VerifiedBinding::verify(&row.sender_binding, &owner, sender) else {
            return Ok(None);
        };
        let Ok((_, domain)) = parse_address(binding.address()) else {
            return Ok(None);
        };
        // A host names only itself in a binding it relays, so one naming another isn't vouched for.
        let host = (domain == row.relayed_by)
            .then(|| rules.host_that_vouched(&row.relayed_by, &row.relay_proof, envelope.id(), me))
            .flatten();
        let met = self.met.lock().await.contains(sender.id());
        let agreed = self.agreed.lock().await.contains_key(sender.id());
        let judged = Sender {
            agent: sender.id(),
            owner: Some(owner.id()),
            host,
            met,
            unconfirmed: owner.is_unconfirmed_owner(),
            agreed,
        };
        let mut reached = self.reached.lock().await;
        let held = reached.get(sender.id()).cloned();
        // Older than what's known about them: it's what they were, and says nothing about now.
        let held_key_gone = held
            .as_ref()
            .is_some_and(|one| self.known.recoveries_of(&one.owner) > one.owner_recoveries);
        if held.as_ref().is_some_and(|one| {
            !held_key_gone && binding.is_behind(one.owner.as_str(), one.binding_seq)
        }) {
            return Ok(None);
        }
        let now = Reached {
            address: binding.address().to_owned(),
            owner: owner.id().clone(),
            owner_recoveries: owner.recoveries(),
            host: host.map(str::to_owned),
            at: held.as_ref().map_or_else(unix_now, |one| one.at),
            binding_seq: binding.seq(),
            nobody: false,
            unconfirmed: owner.is_unconfirmed_owner(),
        };
        if !rules.lets_in_by_reach(&judged) {
            // They've moved on to someone the filter doesn't name, so that's who they are from here.
            if held.is_some() {
                reached.insert(sender.id().clone(), now);
                state_file::save(&self.reached_path, &*reached)
                    .map_err(|_| HostError::LocalStorage)?;
            }
            return Ok(None);
        }
        if held.as_ref().is_some_and(|one| one.is_the_same_as(&now)) {
            return Ok(None);
        }
        let mut made_way = None;
        if held.is_none() && reached.len() >= MAX_REMEMBERED {
            let oldest = reached
                .iter()
                .min_by_key(|(id, one)| (one.at, id.as_str()))
                .map(|(id, _)| id.clone());
            made_way = oldest
                .and_then(|id| reached.remove(&id))
                .map(|one| one.address);
        }
        reached.insert(sender.id().clone(), now);
        state_file::save(&self.reached_path, &*reached).map_err(|_| HostError::LocalStorage)?;
        Ok(Some(NewlyReached {
            address: binding.address().to_owned(),
            owner,
            made_way,
        }))
    }
}

/// What's saved is keyed by ID as text. One that no longer reads as an ID is left out.
fn by_id<T>(saved: HashMap<String, T>) -> HashMap<SplintId, T> {
    saved
        .into_iter()
        .filter_map(|(id, value)| {
            let id = serde_json::from_value(serde_json::Value::String(id)).ok()?;
            Some((id, value))
        })
        .collect()
}

fn save_met(path: &Path, met: &HashSet<SplintId>) -> Result<(), HostError> {
    let saved: HashMap<&str, bool> = met.iter().map(|id| (id.as_str(), true)).collect();
    state_file::save(path, &saved).map_err(|_| HostError::LocalStorage)
}

/// Hands the newest rules to this agent's host, which enforces them on what arrives while this
/// Signet is off, and checks this agent's sends against them. A host that's down or hasn't registered
/// us yet gets them on a later pass, and so does one that refused them, after a while.
pub async fn push_to_host(signet: &Signet) {
    let (seq, compact) = {
        let rules = signet.rules.current.lock().await;
        let Some(rules) = rules.as_ref() else {
            return;
        };
        (rules.seq(), rules.compact().to_owned())
    };
    if signet.rules.pushed.load(Ordering::Relaxed) >= seq {
        return;
    }
    if signet
        .rules
        .offer_again_at()
        .await
        .is_some_and(|at| at > Instant::now())
    {
        return;
    }
    let why = match signet.host.put_rules(&compact).await {
        Ok(()) => {
            signet.rules.pushed.fetch_max(seq, Ordering::Relaxed);
            *signet.rules.refused.lock().await = None;
            return;
        }
        // A host that's down, can't read our dates or doesn't know us yet hasn't said no.
        Err(error) if error.try_later() => return,
        Err(HostError::NotFound | HostError::TooMany) => return,
        Err(HostError::OtherProtocol(_)) => RulesAtHost::OtherProtocol,
        Err(HostError::OutOfDate) => RulesAtHost::OutOfDate,
        Err(_) => RulesAtHost::Refused,
    };
    let mut refused = signet.rules.refused.lock().await;
    let heard_before = refused
        .as_ref()
        .is_some_and(|refusal| refusal.seq == seq && refusal.why == why);
    if heard_before {
        tracing::debug!(seq, ?why, "our host still won't take the rules");
    } else {
        tracing::warn!(
            seq,
            ?why,
            "our host won't take the rules, so it holds our sends to older ones or none"
        );
    }
    *refused = Some(HostRefusal {
        seq,
        why,
        at: Instant::now(),
    });
}

/// Takes in what a contact's host says about it now, with one of its messages: a recovery, or a new
/// statement of who it acts for. Nobody but a contact gets remembered.
pub async fn note_sender(signet: &Signet, row: &StoredMessage) -> Result<(), HostError> {
    let Ok(sender) = Identity::from_encoded(&row.sender_identity) else {
        return Ok(());
    };
    // Only a message that verifies says anything about who it's from.
    let me = signet.who().identity.id().clone();
    let verified = VerifiedEnvelope::verify(&row.envelope, &sender, unix_now())
        .ok()
        .filter(|envelope| envelope.recipient() == &me);
    if let Some(envelope) = &verified {
        signet.rules.learn_listed_owner(row).await?;
        let named = signet
            .rules
            .contacts_by_name()
            .await
            .iter()
            .any(|contact| contact.agent == *sender.id());
        if !named {
            let noted = signet
                .rules
                .note_reached(&sender, envelope, row, &signet.host.domain)
                .await?;
            if let Some(noted) = noted {
                let found = Found {
                    agent: sender.clone(),
                    owner: noted.owner,
                    binding: row.sender_binding.clone(),
                };
                signet
                    .contacts
                    .pin_reached(&noted.address, found, noted.made_way.as_deref())
                    .await?;
            }
        }
    }
    if verified.is_some()
        && let Ok(owner) = Identity::from_encoded(&row.sender_owner_identity)
    {
        let owner = signet.contacts.known.newest_or_same(&owner);
        let moved = signet
            .requests
            .store
            .take_confirmation(&sender, &owner, &row.sender_binding)
            .await?;
        // What was agreed with the stand-in carries on under that owner too.
        if moved {
            crate::requests::types::read_all(signet).await;
        }
    }
    let Some(contact) = signet.rules.all_contact_of(sender.id()).await else {
        return Ok(());
    };
    if matches!(
        signet.contacts.known.newest(&sender),
        Err(splint_core::Error::Forked)
    ) {
        signet.seen_changes.mark_forked(&sender)?;
    }
    signet
        .contacts
        .note(
            &contact.address,
            &sender,
            &row.sender_owner_identity,
            &row.sender_binding,
        )
        .await
}

/// Records a redeem its host passed on, after checking it all again. One use, first come first
/// served, and it counts only while the rules still offer that invitation.
pub async fn take_redeem(
    signet: &Signet,
    row: &StoredMessage,
    envelope: &VerifiedEnvelope,
    proof: &str,
) -> Result<(), HostError> {
    let Some(redeemed) = checked_redeem(signet, row, proof).await else {
        tracing::warn!(message_id = %envelope.id(), "refused an invitation redeem");
        return Ok(());
    };
    let (invite, redeemed) = redeemed;
    let mut all = signet.rules.redeemed.lock().await;
    all.entry(invite).or_insert(redeemed);
    state_file::save(&signet.rules.redeemed_path, &*all).map_err(|_| HostError::LocalStorage)?;
    tracing::info!(message_id = %envelope.id(), "took an invitation redeem");
    Ok(())
}

async fn checked_redeem(
    signet: &Signet,
    row: &StoredMessage,
    proof: &str,
) -> Option<(String, Redeemed)> {
    let sender = Identity::from_encoded(&row.sender_identity).ok()?;
    let invite_id = claimed_invite(proof).ok()?;
    let invite = {
        let rules = signet.rules.current.lock().await;
        rules.as_ref()?.invite(&invite_id)?.clone()
    };
    let used = signet
        .rules
        .redeemed
        .lock()
        .await
        .get(&invite_id)
        .is_some_and(|holder| &holder.agent != sender.id());
    let who = signet.who();
    let me = who.identity.id();
    VerifiedRedeem::verify(proof, &invite, me, &sender, used, unix_now()).ok()?;
    let owner = Identity::from_encoded(&row.sender_owner_identity).ok()?;
    let binding = VerifiedBinding::verify(&row.sender_binding, &owner, &sender).ok()?;
    let redeemed = Redeemed {
        agent: sender.id().clone(),
        address: binding.address().to_owned(),
    };
    Some((invite_id, redeemed))
}

pub fn routes(signet: Arc<Signet>) -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/owner/quarantine", get(quarantine))
        .route("/v0/owner/rules", get(rules_held))
        .route("/v0/owner/invites/redeem", post(redeem_invite))
        .route_layer(middleware::from_fn_with_state(signet, require_owner_token))
        .route("/v0/owner/rules", put(take_rules))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RulesBody {
    rules: String,
}

#[derive(Serialize)]
pub(crate) struct Applied {
    seq: u64,
    /// Whether the host took them too, as it holds this agent's sends to the last ones it took.
    host: RulesAtHost,
}

/// Authorized by the owner's signature and nothing else, so a fooled agent can reach this and still
/// can't change a rule. They're saved before they count, so a crash can't roll them back.
pub(crate) async fn take_rules(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<RulesBody>,
) -> Result<Json<Applied>, ApiError> {
    crate::recovery::hear_of_new_keys(&signet, &body.rules).await;
    let seq = adopt(&signet, &body.rules, unix_now()).await?;
    tracing::info!(seq, "applied rules the owner signed");
    push_to_host(&signet).await;
    let host = signet.rules.at_host().await.unwrap_or(RulesAtHost::NotYet);
    Ok(Json(Applied { seq, host }))
}

/// Rules the owner signed, newer by their `seq` than those held, which they replace. Older ones are
/// refused, so a host can hold new rules back but can't bring old ones back.
pub(crate) async fn adopt(signet: &Signet, compact: &str, now: u64) -> Result<u64, ApiError> {
    let who = signet.who();
    let mut current = signet.rules.current.lock().await;
    let held = current.as_ref().map_or(0, VerifiedRules::seq);
    let rules = VerifiedRules::verify_newer(compact, &who.owner, &who.identity, held, now)
        .map_err(ApiError::RulesRefused)?;
    let saved = HashMap::from([(SAVED_RULES, rules.compact().to_owned())]);
    state_file::save(&signet.rules.path, &saved).map_err(|_| HostError::LocalStorage)?;
    let seq = rules.seq();
    // Whoever the owner has named now has been dealt with, so an invite with them is over. Signing
    // them in and later taking them out leaves nothing to sign them in again.
    let named: Vec<SplintId> = rules.listed().cloned().collect();
    let mut before: Vec<SplintId> = current.as_ref().map_or_else(Vec::new, |old| {
        old.listed()
            .filter(|id| old.lists_for_requests(id))
            .cloned()
            .collect()
    });
    // One the agent agreed with is taken out by the owner naming them with nothing to use.
    let agreed = signet.rules.agreed.lock().await;
    before.extend(agreed.keys().filter(|id| rules.names(id)).cloned());
    drop(agreed);
    if signet.contacts.note_taken_out(&before, &rules).is_err() {
        tracing::warn!(
            "couldn't note whom the new rules take out, so what they sent may be cleared"
        );
    }
    *current = Some(rules);
    if signet.invites.settle(&named).is_err() {
        tracing::warn!("couldn't clear invites the new rules settle, so they're cleared next time");
    }
    let mut agreed = signet.rules.agreed.lock().await;
    if signet.rules.settle_agreed(&mut agreed, &named).is_err() {
        tracing::warn!("couldn't save the agreed contacts the new rules settle");
    }
    Ok(seq)
}

/// Takes newer rules an owner's device gave the host directly. The owner's signature and a rising `seq`
/// are what count, so a host can hold them back but can't change or roll back anything.
pub async fn catch_up_with_host(signet: &Signet) -> Result<(), HostError> {
    let who = signet.who();
    let held = signet.host.rules(&signet.key, who.identity.id()).await?;
    let Some(compact) = held.rules else {
        return Ok(());
    };
    let known = signet
        .rules
        .current
        .lock()
        .await
        .as_ref()
        .is_some_and(|rules| rules.compact() == claimed_owner_part(&compact));
    if known {
        return Ok(());
    }
    match adopt(signet, &compact, unix_now()).await {
        Ok(seq) => {
            signet.rules.pushed.fetch_max(seq, Ordering::Relaxed);
            signet.activity.note(crate::activity::Kind::Owner);
            tracing::info!(seq, "took rules the owner signed from our host");
        }
        Err(_) => tracing::debug!("our host holds rules that don't follow what's here"),
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemRequest {
    to: String,
    proof: String,
}

#[derive(Serialize)]
struct RedeemSent {
    message_id: MessageId,
}

/// Sends the redeem an owner's device made. The owner token keeps an agent from using this to send
/// whatever it likes as a proof. It only goes to someone the owner's rules list as met by invitation,
/// so a leaked token and a link can't start a first contact, and the rules name the inviter's IDs, so
/// a host can't answer the lookup with another agent.
async fn redeem_invite(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<RedeemRequest>,
) -> Result<Json<RedeemSent>, ApiError> {
    if signet.rules.stopped().await {
        return Err(ApiError::Stopped);
    }
    let named = signet
        .rules
        .contact_at(&body.to)
        .await
        .filter(|contact| contact.pinned_by == PinnedBy::Invite)
        .ok_or(ApiError::NotAContact)?;
    let (handle, domain) = parse_address(&body.to).map_err(|_| ApiError::NotAContact)?;
    let found = signet
        .contacts
        .named_by_rules(
            &signet.lookup(&signet.who()),
            &body.to,
            handle,
            domain,
            &named.agent,
        )
        .await?;
    let envelope = sign_envelope(
        &signet.key,
        &signet.who().identity,
        found.agent.id(),
        redeem_body(&body.proof)?,
        unix_now(),
        DEFAULT_MESSAGE_LIFETIME_SECS,
    )?;
    tracing::info!(message_id = %envelope.id, "signed, handing to our host");
    signet.host.send(&envelope.compact, domain).await?;
    Ok(Json(RedeemSent {
        message_id: envelope.id,
    }))
}

/// A held message as its owner sees it: who it's from, and no words of theirs, because those may be
/// written to fool whoever reads them.
#[derive(Serialize)]
pub struct Held {
    /// None for what's on file here rather than held at the host.
    message_id: Option<MessageId>,
    sender: SplintId,
    /// Only if the sender and its owner both signed it, which is the only way to know who it is.
    sender_owner: Option<SplintId>,
    /// The same. An owner needs this to approve them.
    address: Option<String>,
    kind: &'static str,
    created_at: u64,
    expires_at: u64,
    /// For an invite both agents agreed to: what each signed, for the owner's side to check itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    invite: Option<PendingContact>,
}

#[derive(Serialize)]
pub struct HeldPage {
    pub held: Vec<Held>,
}

/// The rules this Signet goes by, for its owner's device to build the next ones from, since another of
/// their devices may have signed newer ones than it last did. Only what the owner signed, which their
/// device checks again.
async fn rules_held(State(signet): State<Arc<Signet>>) -> Json<HeldRules> {
    let current = signet.rules.current.lock().await;
    Json(HeldRules {
        rules: current.as_ref().map(|rules| rules.compact().to_owned()),
    })
}

/// Checks each one again, so a host can't show its owner a sender who never signed anything.
async fn quarantine(State(signet): State<Arc<Signet>>) -> Result<Json<HeldPage>, ApiError> {
    Ok(Json(held_page(&signet).await?))
}

pub async fn held_page(signet: &Signet) -> Result<HeldPage, ApiError> {
    let who = signet.who();
    let me = who.identity.id();
    let stored = signet.host.quarantine(&signet.key, me).await?;
    let mut held = Vec::new();
    for row in &stored {
        let Ok(sender) = Identity::from_encoded(&row.sender_identity) else {
            continue;
        };
        let Ok(envelope) = VerifiedEnvelope::verify(&row.envelope, &sender, unix_now()) else {
            continue;
        };
        if envelope.recipient() != me {
            continue;
        }
        // Under the newest copy of that owner's ID, so a key given up can't show as who they are.
        let binding = Identity::from_encoded(&row.sender_owner_identity)
            .and_then(|presented| signet.contacts.known.newest(&presented))
            .ok()
            .and_then(|owner| VerifiedBinding::verify(&row.sender_binding, &owner, &sender).ok());
        let kind = if is_step_body(envelope.body()) {
            "step"
        } else {
            "text"
        };
        held.push(Held {
            message_id: Some(envelope.id().clone()),
            sender: sender.id().clone(),
            sender_owner: binding.as_ref().map(|binding| binding.owner().clone()),
            address: binding.as_ref().map(|binding| binding.address().to_owned()),
            kind,
            created_at: envelope.created_at(),
            expires_at: envelope.expires_at(),
            invite: None,
        });
    }
    held.extend(on_file_here(signet).await);
    Ok(HeldPage { held })
}

/// Who wrote in and is held at the host, by the address their owner bound them to and their ID, each
/// once. Only what their signatures show, never a word they wrote, for an agent to invite them by.
pub async fn held_senders(signet: &Signet) -> Result<Vec<(String, SplintId)>, ApiError> {
    let mut found: Vec<(String, SplintId)> = Vec::new();
    for held in held_page(signet).await?.held {
        if let (Some(_), Some(address)) = (&held.message_id, held.address)
            && !found.iter().any(|(_, sender)| sender == &held.sender)
        {
            found.push((address, held.sender));
        }
    }
    Ok(found)
}

/// What the agent asked for that the rules don't have yet, contacts their host wouldn't name, invites
/// both agents agreed to that wait for the owner, and contacts the agent agreed with by itself, for the
/// owner to approve, remove or block. An address here that the owner has since signed, or since
/// dropped, has been dealt with, as has an invite with someone the rules name either way.
async fn on_file_here(signet: &Signet) -> Vec<Held> {
    // Only who the owner's side chose: a contact the agent agreed with still waits for their yes.
    let mut contacts = signet.rules.all_contacts().await;
    contacts.retain(|one| one.pinned_by != PinnedBy::Agent);
    let ends = signet
        .rules
        .current()
        .await
        .map_or(0, |rules| rules.ends_at().unwrap_or(u64::MAX));
    let agreed = signet
        .rules
        .agreed_pairs()
        .await
        .into_iter()
        .map(|(agent, pair)| Held {
            message_id: None,
            sender: agent,
            sender_owner: None,
            address: Some(pair.address),
            kind: "agreed",
            created_at: pair.at,
            // As long as the rules that let them in, which with no end the owner chose is until replaced.
            expires_at: ends,
            invite: Some(pair.record),
        })
        .collect::<Vec<_>>();
    let named: Vec<SplintId> = contacts.iter().map(|one| one.agent.clone()).collect();
    let invites = signet.invites.pending(&named).into_iter().map(|one| Held {
        message_id: None,
        sender: one.agent,
        sender_owner: None,
        address: Some(one.address),
        kind: "invite",
        created_at: one.at,
        expires_at: one.at.saturating_add(MAX_INVITE_LIFETIME_SECS),
        invite: Some(one.record),
    });
    let asks = signet
        .contact_asks
        .listed()
        .into_iter()
        .filter(|(address, entry)| {
            let signed = contacts
                .iter()
                .any(|one| &one.address == address && one.agent == entry.agent);
            let named = contacts
                .iter()
                .any(|one| &one.address == address || one.agent == entry.agent);
            // A disagreement with a pin lasts until the owner signs someone at that address.
            if entry.disagreed {
                signed || (entry.pinned_only && !named)
            } else {
                !named
            }
        })
        .map(|(address, entry)| Held {
            message_id: None,
            sender: entry.agent,
            sender_owner: None,
            address: Some(address),
            kind: if entry.disagreed {
                "disagreed"
            } else {
                "asked"
            },
            created_at: entry.at,
            expires_at: entry.at.saturating_add(contact_asks::KEEP_SECS),
            invite: None,
        });
    asks.chain(invites).chain(agreed).collect()
}

#[cfg(test)]
mod tests {
    use splint_core::SigningKey;
    use splint_core::rules::{Reach, RulesDraft, RulesLimits};
    use splint_core::{Identity, RecoveryRule};

    use super::*;

    fn signed_for(key: &SigningKey, owner: &SplintId, agent: &SplintId, paused: bool) -> String {
        let draft = RulesDraft {
            paused,
            reach: Reach::default(),
            permissions: Permissions::default(),
            changes: splint_core::changes::ChangeRules::default(),
            sealing: Sealing::default(),
            delegation: None,
            ends_at: None,
            contacts: Vec::new(),
            invites: Vec::new(),
            limits: RulesLimits {
                new_requests_per_contact_per_day: 3,
                open_requests_per_contact: 3,
                open_approvals: 10,
                new_from_others_per_day: 50,
                texts_per_contact_per_day: 20,
                agreed_texts_per_day: None,
                agreed_new_requests_per_day: None,
                sends_per_hour: None,
                sends_per_day: None,
            },
        };
        draft.sign(key, owner, agent, 7, unix_now()).unwrap()
    }

    #[tokio::test]
    async fn rules_on_disk_count_only_for_the_agent_they_were_signed_for() {
        let rule = || RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key());
        let key = SigningKey::generate().unwrap();
        let owner = Identity::create(
            &key,
            &splint_core::SealingKey::generate().unwrap().public_key(),
            rule(),
        )
        .unwrap();
        let this = Identity::create(
            &SigningKey::generate().unwrap(),
            &splint_core::SealingKey::generate().unwrap().public_key(),
            rule(),
        )
        .unwrap();
        let sibling = Identity::create(
            &SigningKey::generate().unwrap(),
            &splint_core::SealingKey::generate().unwrap().public_key(),
            rule(),
        )
        .unwrap();
        let directory = std::env::temp_dir().join(format!("signet-rules-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("rules.json");
        let known = Arc::new(Known::load(directory.join("known.json")).unwrap());
        let save = |compact: String| {
            state_file::save(&path, &HashMap::from([(SAVED_RULES, compact)])).unwrap();
        };

        save(signed_for(&key, owner.id(), sibling.id(), false));
        let seen = Arc::new(Seen::load(directory.join("seen-changes.json")).unwrap());
        let store = RulesStore::load(
            path.clone(),
            &directory,
            &owner,
            this.id(),
            known.clone(),
            seen.clone(),
        )
        .unwrap();
        assert!(!store.exist().await);

        save(signed_for(&key, owner.id(), this.id(), false));
        let store =
            RulesStore::load(path.clone(), &directory, &owner, this.id(), known, seen).unwrap();
        assert!(store.exist().await);
        assert!(!store.stopped().await);

        std::fs::remove_dir_all(&directory).unwrap();
    }
}

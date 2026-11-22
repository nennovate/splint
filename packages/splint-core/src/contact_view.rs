//! What a reader has seen of one contact's history, which only ever grows, and what its owner has said
//! about it. A Signet goes by this for everything its agent does. Its host keeps one too, built from what
//! passes through it, so a stolen key calling the host directly gets stopped the same way.
//!
//! A reader goes by what's here, and never by what a host or a sender says. A contact whose changes
//! need an owner's word gets nothing through and can be sent nothing, in either direction, until that
//! word comes, and a history that rewrites what's here is held whatever the rules say.

use serde::{Deserialize, Serialize};

use crate::changes::{
    Against, ChangeAnswer, ChangeResponse, ChangeRules, FirstSeen, VerifiedAcceptance,
    VerifiedChange, VerifiedHistory,
};
use crate::host_api::RetirementNotice;
use crate::{Error, Identity, SplintId, VerifiedBinding, VerifiedStop};

/// Rivals to one contact's history that an owner has chosen against. A rival takes keys to make, and
/// one past this is only put to the owner again.
const MAX_REFUSED: usize = 32;
/// A move of host, or a return from revocation, that a reader takes while one of the owner's sign-ins is
/// newer to it than this is asked about as a new owner would be: a thief who took one sign-in adds their
/// own and moves the agent with it, and an owner's other devices show the addition within this time.
/// Provisional, for Nenye to overturn.
pub const NEW_SIGN_IN_SECS: u64 = 48 * 3600;

/// When this reader first saw each sign-in of a contact's owners since their newest recovery, by name.
/// Whoever signs an addition dates it as they like, so a reader goes by its own clock alone.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SignInsSeen(Vec<SignInSeen>);

#[derive(Clone, Serialize, Deserialize)]
struct SignInSeen {
    name: String,
    at: u64,
}

impl SignInsSeen {
    /// What a reader first meets a contact under, as known from before: that's how things stood.
    pub fn known_before<'a>(owners: impl IntoIterator<Item = &'a Identity>) -> Self {
        let mut seen = Self::default();
        seen.note(owners, 0);
        seen
    }

    /// Notes the key each of these owners' newest event or recovery named as seen before, where nothing
    /// says when the sign-ins added since were: what a reader meets a contact's owner under first.
    fn epoch_keys_known<'a>(&mut self, owners: impl IntoIterator<Item = &'a Identity>) {
        for owner in owners {
            if let Some(name) = owner.sign_ins_since_recovery().into_iter().next()
                && !self.0.iter().any(|seen| seen.name == name)
            {
                self.0.push(SignInSeen { name, at: 0 });
            }
        }
    }

    /// Notes each sign-in since these owners' newest recoveries not seen before as first seen `now`,
    /// and says whether there was one.
    pub fn note<'a>(&mut self, owners: impl IntoIterator<Item = &'a Identity>, now: u64) -> bool {
        let mut noted = false;
        for name in owners
            .into_iter()
            .flat_map(Identity::sign_ins_since_recovery)
        {
            if !self.0.iter().any(|seen| seen.name == name) {
                self.0.push(SignInSeen { name, at: now });
                noted = true;
            }
        }
        noted
    }

    /// The hashes of the changes here that a reader taking them `now` answers as a new owner: each move
    /// of host or return from revocation while one of that owner's sign-ins since its newest recovery
    /// is new to it. Sign-ins in the history it hadn't seen are first seen now.
    pub fn asked_as_new_owner(
        &mut self,
        history: &VerifiedHistory,
        changes: &[VerifiedChange],
        now: u64,
    ) -> Vec<String> {
        self.note(history.owners(), now);
        changes
            .iter()
            .filter(|change| change.rebinds())
            .filter(|change| {
                history
                    .owners()
                    .iter()
                    .find(|owner| owner.id() == &change.owner)
                    .is_some_and(|owner| self.any_new(owner, now))
            })
            .map(|change| change.hash.clone())
            .collect()
    }

    fn any_new(&self, owner: &Identity, now: u64) -> bool {
        let names = owner.sign_ins_since_recovery();
        self.0.iter().any(|seen| {
            names.contains(&seen.name) && now < seen.at.saturating_add(NEW_SIGN_IN_SECS)
        })
    }
}

/// When this reader first took a change it learned of after it first knew the contact, by its own clock.
/// Whoever signs a change dates it as they like, so a thief who replaced a key could date it days back
/// and look settled.
#[derive(Clone, Serialize, Deserialize)]
struct ChangeTaken {
    hash: String,
    at: u64,
}

/// What a reader holds of IDs that have been recovered, so an older copy can't bring back a key.
pub trait Copies {
    fn recoveries_of(&self, id: &SplintId) -> usize;
    /// What to believe about this ID, given this copy. A fork leaves this copy.
    fn newest_or_same(&self, identity: &Identity) -> Identity;
    /// The copy this reader goes by now, if it has had reason to keep one.
    fn held_copy(&self, id: &SplintId) -> Option<Identity>;
}

/// How a history arrived, which decides what counts as already known the first time. Someone asking
/// gets what a contact is now, as they would at first contact. A notice is about a change.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Heard {
    ByAsking,
    ByNotice,
}

/// Where a contact stands for this reader now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    Continue,
    /// Held, and put to the owner.
    Ask,
    /// Held, until the owner says otherwise.
    Hold,
    /// A key is in use that no history has explained yet, so it waits until one arrives.
    WaitingForHistory,
    /// Two histories part ways, which someone holding keys signed. The rules have no say in this.
    Rewritten,
    /// Their own owner has retired them. Nobody here can lift that, and a recovery of that owner can.
    Stopped,
}

/// Why a stop was believed, which is checked again whenever it's read.
#[derive(Clone, Serialize, Deserialize)]
pub struct Stop {
    notice: RetirementNotice,
    owner: SplintId,
    owner_recoveries: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SavedView {
    history: String,
    accepted: String,
    #[serde(default)]
    rewritten: Option<String>,
    #[serde(default)]
    forked: bool,
    #[serde(default)]
    acceptance_seq: u64,
    #[serde(default)]
    fork_heads: Vec<String>,
    #[serde(default)]
    refused: Vec<String>,
    #[serde(default)]
    first_seen: Option<FirstSeen>,
    #[serde(default)]
    first_owner: Option<String>,
    #[serde(default)]
    unexplained_owner: Option<SplintId>,
    #[serde(default)]
    stop: Option<Stop>,
    #[serde(default)]
    asks_as_owner: Vec<String>,
    #[serde(default)]
    sign_ins_seen: SignInsSeen,
    #[serde(default)]
    taken: Vec<ChangeTaken>,
}

#[derive(Clone)]
pub struct ContactView {
    history: VerifiedHistory,
    /// How far the owner has said yes, or what this reader first saw.
    accepted: String,
    /// The first rival to arrive, kept so that an owner can choose it by its head.
    rewritten: Option<VerifiedHistory>,
    /// Two copies of the ID itself have parted ways, on a message or a notice.
    forked: bool,
    acceptance_seq: u64,
    /// The copies of the ID that have parted ways from this one, as far as anyone's shown.
    fork_heads: Vec<String>,
    /// Rivals the owner has been shown and chose against, which stay refused and hold nothing again,
    /// or a stolen key could undo the owner's word by sending the same rival once more.
    refused: Vec<String>,
    /// What this reader knew before any history came. A host can hold one back, so this is what the
    /// first to come is placed against, and what a replaced key or a new owner is measured from.
    first_seen: Option<FirstSeen>,
    /// The copy of the ID of the owner first seen, since a release is checked under it.
    first_owner: Option<Identity>,
    /// An owner the one before released them to, and no history here has them acting for yet.
    unexplained_owner: Option<SplintId>,
    /// That contact's owner's signed stop, whatever their own host is doing about it.
    stop: Option<Stop>,
    /// Changes answered as a new owner is, as one of the owner's sign-ins was new to this reader when
    /// it took them. Fixed when taken, so an owner's question doesn't lapse by waiting.
    asks_as_owner: Vec<String>,
    sign_ins_seen: SignInsSeen,
    /// When this reader took each change it learned of after it first knew the contact.
    taken: Vec<ChangeTaken>,
}

/// What an owner reads about one contact.
pub struct OnFile {
    pub head: String,
    pub since_accepted: Vec<VerifiedChange>,
    pub rewritten_head: Option<String>,
    pub rewritten_since: Vec<VerifiedChange>,
    /// The signed histories themselves, for an owner's device to check what it's shown.
    pub history: String,
    pub rewritten_history: Option<String>,
    /// Their own owner says they act for nobody now.
    pub revoked: bool,
}

/// What taking a history came to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Taken {
    Unchanged,
    /// Held, and the IDs in it are the ones to go by now.
    Followed,
    /// Kept beside what's held, and it says nothing about what to go by.
    Rival,
}

impl ContactView {
    /// A contact heard of for the first time through a history.
    pub fn from_history(new: VerifiedHistory, heard: Heard, now: u64) -> Self {
        let accepted = match heard {
            Heard::ByAsking => new.head(),
            Heard::ByNotice => new
                .changes()
                .first()
                .map_or_else(|| new.head(), |first| first.hash.clone()),
        };
        let mut view = Self::starting_from(new, accepted);
        // Someone asking gets how a contact stands, sign-ins and all. A notice is about a change, and
        // only the key each owner's newest event or recovery named was there before any addition.
        view.sign_ins_seen = match heard {
            Heard::ByAsking => SignInsSeen::known_before(view.history.owners()),
            Heard::ByNotice => {
                let mut seen = SignInsSeen::default();
                seen.epoch_keys_known(view.history.owners());
                seen
            }
        };
        let since = view
            .history
            .since(&view.accepted)
            .unwrap_or_default()
            .to_vec();
        view.mark_new_sign_ins(&since, now);
        view.note_taken(&since, now);
        view
    }

    /// Notes these changes as taken `now`, the first time each is, and forgets what's in neither the
    /// history held nor its rival, which nothing reads again.
    fn note_taken(&mut self, changes: &[VerifiedChange], now: u64) {
        for change in changes {
            if !self.taken.iter().any(|taken| taken.hash == change.hash) {
                self.taken.push(ChangeTaken {
                    hash: change.hash.clone(),
                    at: now,
                });
            }
        }
        let held: Vec<&String> = self
            .history
            .changes()
            .iter()
            .chain(self.rewritten.iter().flat_map(VerifiedHistory::changes))
            .map(|change| &change.hash)
            .collect();
        self.taken.retain(|taken| held.contains(&&taken.hash));
    }

    /// Notes when this reader first saw each of the owners' sign-ins, and each change here it answers
    /// as a new owner for it.
    fn mark_new_sign_ins(&mut self, changes: &[VerifiedChange], now: u64) {
        for hash in self
            .sign_ins_seen
            .asked_as_new_owner(&self.history, changes, now)
        {
            if !self.asks_as_owner.contains(&hash) {
                self.asks_as_owner.push(hash);
            }
        }
        // Only what's in the history held is ever answered, so nothing else needs keeping.
        let held: Vec<&String> = self.history.changes().iter().map(|c| &c.hash).collect();
        self.asks_as_owner.retain(|hash| held.contains(&hash));
    }

    /// A contact heard of for the first time some other way, with nothing yet to go on.
    pub fn from_identity(identity: &Identity) -> Self {
        let history = VerifiedHistory::empty(identity);
        let accepted = history.head();
        Self::starting_from(history, accepted)
    }

    fn starting_from(history: VerifiedHistory, accepted: String) -> Self {
        Self {
            history,
            accepted,
            rewritten: None,
            forked: false,
            acceptance_seq: 0,
            fork_heads: Vec::new(),
            refused: Vec::new(),
            first_seen: None,
            first_owner: None,
            unexplained_owner: None,
            stop: None,
            asks_as_owner: Vec::new(),
            sign_ins_seen: SignInsSeen::default(),
            taken: Vec::new(),
        }
    }

    pub fn load(saved: &SavedView) -> Option<Self> {
        Some(Self {
            history: VerifiedHistory::read(&saved.history).ok()?,
            accepted: saved.accepted.clone(),
            rewritten: saved
                .rewritten
                .as_deref()
                .and_then(|text| VerifiedHistory::read(text).ok()),
            forked: saved.forked,
            acceptance_seq: saved.acceptance_seq,
            fork_heads: saved.fork_heads.clone(),
            refused: saved.refused.clone(),
            first_seen: saved.first_seen.clone(),
            first_owner: saved
                .first_owner
                .as_deref()
                .and_then(|text| Identity::from_encoded(text).ok()),
            unexplained_owner: saved.unexplained_owner.clone(),
            stop: saved
                .stop
                .clone()
                .filter(|stop| VerifiedStop::verify(&stop.notice).is_ok()),
            asks_as_owner: saved.asks_as_owner.clone(),
            sign_ins_seen: saved.sign_ins_seen.clone(),
            taken: saved.taken.clone(),
        })
    }

    pub fn saved(&self) -> Result<SavedView, Error> {
        Ok(SavedView {
            history: self.history.encoded()?,
            accepted: self.accepted.clone(),
            rewritten: self
                .rewritten
                .as_ref()
                .map(VerifiedHistory::encoded)
                .transpose()?,
            forked: self.forked,
            acceptance_seq: self.acceptance_seq,
            fork_heads: self.fork_heads.clone(),
            refused: self.refused.clone(),
            first_seen: self.first_seen.clone(),
            first_owner: self.first_owner.as_ref().map(Identity::encoded),
            unexplained_owner: self.unexplained_owner.clone(),
            stop: self.stop.clone(),
            asks_as_owner: self.asks_as_owner.clone(),
            sign_ins_seen: self.sign_ins_seen.clone(),
            taken: self.taken.clone(),
        })
    }

    fn refuse(&mut self, head: String) {
        if self.refused.len() >= MAX_REFUSED {
            self.refused.remove(0);
        }
        self.refused.push(head);
    }

    /// Takes a history that's been verified. An older copy changes nothing. A later one counts, and
    /// the owner's rules decide what follows. One that parts ways is kept beside what's held, and what's
    /// held stands until the owner signs for one of them.
    pub fn take(&mut self, new: VerifiedHistory, now: u64) -> Taken {
        match self.history.against(&new) {
            Against::Same | Against::Behind => Taken::Unchanged,
            Against::Extends => {
                let first = self.history.is_empty();
                if let (true, Some(seen)) = (first, &self.first_seen) {
                    self.accepted = new.head_as_first_seen(seen);
                }
                // The first history of a contact met with no owner shown, as by a notice.
                if first {
                    self.sign_ins_seen.epoch_keys_known(new.owners());
                }
                let since = new.since(&self.history.head()).unwrap_or_default().to_vec();
                // A first history only tells this reader what came after what it first saw of them. Met
                // with nothing seen, all of it is how they stood.
                let learned = match (first, &self.first_seen) {
                    (false, _) => since.clone(),
                    (true, Some(_)) => new.since(&self.accepted).unwrap_or_default().to_vec(),
                    (true, None) => Vec::new(),
                };
                self.history = new;
                self.mark_new_sign_ins(&since, now);
                self.note_taken(&learned, now);
                Taken::Followed
            }
            Against::Rewrites if self.refused.contains(&new.head()) => Taken::Unchanged,
            Against::Rewrites => {
                if self.rewritten.is_none() {
                    let parted: Vec<VerifiedChange> = new
                        .changes()
                        .iter()
                        .filter(|change| {
                            !self
                                .history
                                .changes()
                                .iter()
                                .any(|held| held.hash == change.hash)
                        })
                        .cloned()
                        .collect();
                    self.rewritten = Some(new);
                    self.note_taken(&parted, now);
                }
                Taken::Rival
            }
        }
    }

    /// Writes down who a contact showed itself to be, from what's signed, and says whether that changed
    /// anything. The first time, that's how things already stood for this reader, whatever a history that
    /// comes later says. After that, a new owner the one before released them to keeps this contact
    /// waiting for a history that says so. One with no release says nothing, as all that takes is a
    /// stolen key and a backup.
    pub fn note_shown(
        &mut self,
        identity: &Identity,
        shown: Option<(&Identity, &VerifiedBinding)>,
        copies: &impl Copies,
        now: u64,
    ) -> bool {
        // A copy the owner chose against shows nothing, or showing the same thing again would undo
        // the owner's word.
        if self.refuses_copy(identity) {
            return false;
        }
        let mut changed = false;
        if self.history.is_empty() {
            let seen = self.first_seen.get_or_insert_with(|| {
                changed = true;
                FirstSeen {
                    agent_recoveries: identity.recoveries(),
                    owner: None,
                    owner_recoveries: 0,
                    address: None,
                    binding_seq: 0,
                }
            });
            if let (None, Some((owner, binding))) = (&seen.owner, shown) {
                seen.owner = Some(owner.id().clone());
                seen.owner_recoveries = owner.recoveries();
                seen.address = Some(binding.address().to_owned());
                seen.binding_seq = binding.seq();
                self.first_owner = Some(owner.clone());
                self.sign_ins_seen = SignInsSeen::known_before([owner]);
                changed = true;
            }
        }
        // Each sign-in of the owner's is new from the first time this reader sees it, which an owner's
        // other devices show them too, so a contact who sees a new phone in time doesn't ask later.
        if let Some((owner, _)) = shown
            && self.sign_ins_seen.note([owner], now)
        {
            changed = true;
        }
        if let Some((owner, binding)) = shown
            && self.unexplained_owner.as_ref() != Some(owner.id())
            && self.shows_an_unexplained_transfer(owner, binding, copies)
        {
            self.unexplained_owner = Some(owner.id().clone());
            changed = true;
        }
        changed
    }

    /// Whether this binding moves the contact on from the owner held to one no history here names.
    fn shows_an_unexplained_transfer(
        &self,
        owner: &Identity,
        binding: &VerifiedBinding,
        copies: &impl Copies,
    ) -> bool {
        let held = if self.history.is_empty() {
            let seq = self.first_seen.as_ref().map_or(0, |seen| seen.binding_seq);
            self.first_owner.clone().map(|owner| (owner, seq))
        } else {
            let id = self.history.owner();
            let copy = self
                .history
                .owners()
                .iter()
                .find(|one| Some(one.id()) == id);
            copy.cloned()
                .map(|owner| (owner, self.history.binding_seq()))
        };
        let Some((held, seq)) = held else {
            return false;
        };
        held.id() != owner.id()
            && !self.history.acted_for(owner.id())
            && binding
                .may_replace(&copies.newest_or_same(&held), seq)
                .is_ok()
    }

    /// Whether something signed has been seen that the history held doesn't explain: a replaced key, or
    /// a new owner. Those check out on their own, and they're what an owner's rules are about, so they
    /// wait for the history that says what happened. A host keeping it back only keeps them waiting.
    fn is_behind(&self, copies: &impl Copies) -> bool {
        let id = self.history.id();
        if self.history.is_empty() {
            let Some(seen) = &self.first_seen else {
                return false;
            };
            return copies.recoveries_of(id) > seen.agent_recoveries
                || seen
                    .owner
                    .as_ref()
                    .is_some_and(|owner| copies.recoveries_of(owner) > seen.owner_recoveries)
                || self
                    .unexplained_owner
                    .as_ref()
                    .is_some_and(|owner| seen.owner.as_ref() != Some(owner));
        }
        let owner_recoveries = self
            .history
            .owner()
            .map_or(0, |owner| copies.recoveries_of(owner));
        self.history
            .is_behind(copies.recoveries_of(id), owner_recoveries)
            || self
                .unexplained_owner
                .as_ref()
                .is_some_and(|owner| !self.history.acted_for(owner))
    }

    /// Who this contact acts for as far as this reader knows, which is who can stop it.
    fn owner_now(&self) -> Option<&SplintId> {
        self.history
            .owner()
            .or_else(|| self.first_seen.as_ref()?.owner.as_ref())
    }

    fn is_stopped(&self, copies: &impl Copies) -> bool {
        self.stop.as_ref().is_some_and(|stop| {
            self.owner_now().is_none_or(|owner| owner == &stop.owner)
                && copies.recoveries_of(&stop.owner) <= stop.owner_recoveries
        })
    }

    /// Whose stop is on file, standing or not, as only a recovery of theirs can end it.
    pub fn stopped_by(&self) -> Option<&SplintId> {
        self.stop.as_ref().map(|stop| &stop.owner)
    }

    /// Takes an owner's signed stop for this contact, once it checks out.
    pub fn take_stop(
        &mut self,
        notice: &RetirementNotice,
        copies: &impl Copies,
    ) -> Result<bool, Error> {
        let stop = VerifiedStop::verify(notice)?;
        if stop.agent().id() != self.history.id() {
            return Err(Error::ProofMismatch);
        }
        // One that's still standing isn't replaced, or a past owner's word could lift it.
        if self.is_stopped(copies) {
            return Ok(false);
        }
        self.stop = Some(Stop {
            notice: notice.clone(),
            owner: stop.owner().id().clone(),
            owner_recoveries: stop.owner().recoveries(),
        });
        Ok(true)
    }

    pub fn standing(&self, rules: &ChangeRules, copies: &impl Copies) -> Standing {
        if self.is_stopped(copies) {
            return Standing::Stopped;
        }
        if self.rewritten.is_some() || self.forked {
            return Standing::Rewritten;
        }
        if self.is_behind(copies) {
            return Standing::WaitingForHistory;
        }
        match rules.answer_treating_as_owner(&self.history, &self.accepted, &self.asks_as_owner) {
            ChangeAnswer::Stopped => Standing::Stopped,
            ChangeAnswer::Rewritten => Standing::Rewritten,
            ChangeAnswer::Respond(ChangeResponse::Continue) => Standing::Continue,
            ChangeAnswer::Respond(ChangeResponse::Ask) => Standing::Ask,
            ChangeAnswer::Respond(ChangeResponse::Hold) => Standing::Hold,
        }
    }

    /// Whether this is the owner this reader first knew this contact under.
    pub fn first_owner_is(&self, owner: &Identity) -> bool {
        self.first_seen
            .as_ref()
            .is_some_and(|seen| seen.owner.as_ref() == Some(owner.id()))
    }

    /// Two copies of an ID parted ways on a message, before any history said so. Says whether that's
    /// news.
    pub fn mark_forked(&mut self, identity: &Identity) -> bool {
        let head = identity.head_hash();
        if self.refused.contains(&head) || (self.forked && self.fork_heads.contains(&head)) {
            return false;
        }
        self.forked = true;
        self.fork_heads.push(head);
        true
    }

    /// Marks this contact forked over any owner in this history whose copy parts ways with the one
    /// held and doesn't win, as a rival recovery does. A real recovery wins, so it never lands here. A
    /// history the owner chose against holds nothing again. Says whether that's news.
    pub fn note_parted_owners(&mut self, history: &VerifiedHistory, copies: &impl Copies) -> bool {
        if self.refused.contains(&history.head()) {
            return false;
        }
        let mut news = false;
        for owner in history.owners() {
            let parted = copies
                .held_copy(owner.id())
                .is_some_and(|held| matches!(held.newest_of(owner), Err(Error::Forked)));
            news |= parted && self.mark_forked(owner);
        }
        news
    }

    /// Whether the owner has chosen against this copy of an ID, so what comes with it is simply refused.
    pub fn refuses_copy(&self, identity: &Identity) -> bool {
        self.refused.contains(&identity.head_hash())
    }

    /// An owner's yes, to the exact head named, of what's held or of its rival. Nothing else on file
    /// gets moved. A yes makes that the ID this reader goes by, which `adopt` takes in first, and whatever
    /// other copy of the ID was seen goes on being refused, however it's shown again.
    pub fn accept(
        &mut self,
        acceptance: &VerifiedAcceptance,
        copies: &impl Copies,
        adopt: impl FnOnce(&VerifiedHistory) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if acceptance.seq() <= self.acceptance_seq {
            return Err(Error::Stale);
        }
        let head = acceptance.head();
        let gone_by = copies.held_copy(self.history.id());
        let had_a_rival = self.rewritten.is_some();
        match self.rewritten.take() {
            Some(rival) if rival.head() == head => {
                adopt(&rival)?;
                self.refuse(self.history.head());
                let held_copy = self.history.identity().head_hash();
                self.refuse(held_copy);
                self.history = rival;
            }
            kept if self.history.head() == head => {
                adopt(&self.history)?;
                if let Some(rival) = kept {
                    self.refuse(rival.head());
                    self.refuse(rival.identity().head_hash());
                }
            }
            kept => {
                self.rewritten = kept;
                return Err(Error::ProofMismatch);
            }
        }
        let chosen = self.history.identity().head_hash();
        let others = std::mem::take(&mut self.fork_heads)
            .into_iter()
            .chain(gone_by.map(|copy| copy.head_hash()));
        let chosen_against = others
            .filter(|copy| *copy != chosen && !self.history.identity().was_at(copy))
            .collect::<Vec<_>>();
        // A new owner that a copy chosen against showed is as void as that copy, or an honest contact
        // would wait for good on a history that only a thief could write. One the chosen copy shows
        // again is noted again.
        if (had_a_rival || !chosen_against.is_empty())
            && self
                .unexplained_owner
                .as_ref()
                .is_some_and(|owner| !self.history.acted_for(owner))
        {
            self.unexplained_owner = None;
        }
        for copy in chosen_against {
            self.refuse(copy);
        }
        head.clone_into(&mut self.accepted);
        self.forked = false;
        self.acceptance_seq = acceptance.seq();
        Ok(())
    }

    /// Where this contact is now, by its newest history. Nothing here says nobody else is there.
    pub fn address(&self) -> Option<&str> {
        self.history.address()
    }

    /// The changes in this contact's history this reader took `since` or later, by its own clock, as
    /// a thief would date theirs back. One already in the history when this reader first met them goes
    /// by the date it was signed, as nothing else says when it happened. The move from the stand-in an
    /// agent joined under to its owner, the first time they set up controls, isn't one, as no owner had
    /// signed for it before. Only
    /// facts for an agent to weigh, never a check.
    pub fn changed_since(&self, since: u64) -> Vec<VerifiedChange> {
        self.history
            .changes()
            .iter()
            .filter(|change| {
                let at = self
                    .taken
                    .iter()
                    .find(|taken| taken.hash == change.hash)
                    .map_or(change.issued_at, |taken| taken.at);
                at >= since && !change.confirms_stand_in
            })
            .cloned()
            .collect()
    }

    pub fn on_file(&self) -> OnFile {
        let rival = self.rewritten.as_ref();
        OnFile {
            head: self.history.head(),
            since_accepted: self
                .history
                .since(&self.accepted)
                .map_or_else(|| self.history.changes().to_vec(), <[_]>::to_vec),
            rewritten_head: rival.map(VerifiedHistory::head),
            rewritten_since: rival.map_or_else(Vec::new, |rival| rival.changes().to_vec()),
            history: self.history.encoded().unwrap_or_default(),
            rewritten_history: rival.and_then(|rival| rival.encoded().ok()),
            revoked: self.history.is_revoked(),
        }
    }

    /// The history held, and its rival if there is one, which are what an owner's word can name.
    pub fn histories(&self) -> Result<Vec<String>, Error> {
        std::iter::once(&self.history)
            .chain(&self.rewritten)
            .map(VerifiedHistory::encoded)
            .collect()
    }

    /// Every ID this goes by the copies of.
    pub fn ids(&self) -> Vec<SplintId> {
        let mut ids = vec![self.history.id().clone()];
        ids.extend(self.history.owners().iter().map(|owner| owner.id().clone()));
        ids.extend(self.first_owner.iter().map(|owner| owner.id().clone()));
        ids.extend(self.unexplained_owner.iter().cloned());
        ids.extend(self.stop.iter().map(|stop| stop.owner.clone()));
        ids
    }

    pub fn has_no_history(&self) -> bool {
        self.history.is_empty()
    }

    pub fn is_forked(&self) -> bool {
        self.forked
    }

    /// Whether anything here could ever have a reader stop, under the strictest rules an owner could
    /// sign. A host checks this first, so a contact with nothing on file costs it nothing to send to.
    pub fn could_hold(&self, copies: &impl Copies) -> bool {
        let strictest = ChangeRules {
            owner: ChangeResponse::Hold,
            key: ChangeResponse::Hold,
            signet: ChangeResponse::Hold,
            host: ChangeResponse::Hold,
            revocation: ChangeResponse::Hold,
            declared: ChangeResponse::Hold,
        };
        self.standing(&strictest, copies) != Standing::Continue
    }
}

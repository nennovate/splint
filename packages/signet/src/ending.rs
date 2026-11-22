//! What ends a message at its host. A host clears a row once Signet says it's done, and that erases
//! the only copy while its sender's record still says delivered. So Signet says it only of a row it
//! handed over, to its agent, its owner's side or the request state machine, or one proven bad for
//! good: a signature that fails against the key that counts for its sender, something addressed to
//! someone else, a sealed body that opened and lies, a replay, something the owner's signed rules
//! refuse, or a copy of a forked ID the owner chose against.
//!
//! "It doesn't open", "it's sealed to a key this Signet doesn't hold", "its sender's key isn't known
//! yet" and "this Signet's own state is broken" prove nothing. Such a row from someone the owner
//! named, invited or this agent agreed with stays at its host, unread, until it can be read or it
//! expires there, and the agent is told how many wait and why. One from someone let in by reach is
//! put off and not counted: its host lets a step go after about an hour of that, and a page gives
//! contacts' rows every other place ahead of strangers' steps, so strangers can't hide a contact's mail.
//!
//! The host calls that clear a row take a [`Done`], which only a [`Readable`] a check here produced, a
//! [`Proof`] the same checks produced, or a row written into this Signet's own keeping can make. So no
//! code can end a row it couldn't read, and a row of one box can't end a row of another.

use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;
use std::sync::{Mutex as ShortLock, MutexGuard, PoisonError};

use serde::Serialize;
use splint_core::changes::is_notice_body;
use splint_core::contact_view::Standing;
use splint_core::host_api::{HeldIntroduction, OwnerMail, StoredMessage, StoredOwnerMail};
use splint_core::rules::PinnedBy;
use splint_core::{Error, Identity, SplintId, VerifiedEnvelope, claimed_sender, unix_now};

use crate::Signet;

/// The agent's inbox at its host, and mail carried here from a host it left.
#[derive(Clone, Copy)]
pub struct InboxRows;
/// The invites box at its host.
#[derive(Clone, Copy)]
pub struct IntroductionRows;
/// What the agent's owner left at its host, sealed to it.
#[derive(Clone, Copy)]
pub struct OwnerMailRows;

/// A row that verified and opened here, so whoever it's handed to can judge it.
pub struct Readable<B> {
    seq: i64,
    envelope: VerifiedEnvelope,
    at: PhantomData<B>,
}

impl<B> Readable<B> {
    fn new(seq: i64, envelope: VerifiedEnvelope) -> Self {
        Self {
            seq,
            envelope,
            at: PhantomData,
        }
    }

    pub fn seq(&self) -> i64 {
        self.seq
    }

    pub fn envelope(&self) -> &VerifiedEnvelope {
        &self.envelope
    }
}

/// Why a row stays at its host unread. Each kind is a fixed word an agent or a program acts on. All but
/// the last come from the inbox: a row the checks here can't read, or one that verified and waits on
/// the owner's word about its sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Held {
    /// Sealed to a key this Signet doesn't hold, such as one it lost or one from before a recovery.
    SealedToAnotherKey,
    /// Signed by a key its sender's ID hasn't been seen to hold, while a history that may name it is
    /// awaited.
    SenderKeyNotKnownYet,
    /// Its sender's ID has two rival histories, and its owner hasn't chosen.
    SenderForked,
    /// Its sender's key, owner or host changed, and the owner's rules have that wait for their word.
    SenderChangeWaitsForOwner,
    /// Its dates don't fit this machine's clock, which could be this clock's fault.
    DatedOffThisClock,
    /// In a form this Signet can't read, or with a copy of its sender's ID that isn't theirs.
    Unreadable,
    /// What the owner left for this agent at its host, sealed to a key this Signet doesn't hold.
    OwnerMailSealedToAnotherKey,
}

impl Held {
    /// Plain words for an agent, with nothing from the message itself.
    pub fn why(self) -> &'static str {
        match self {
            Self::SealedToAnotherKey => {
                "sealed to a key this Signet doesn't hold, such as one it lost: they wait at your \
                 host and open by themselves once that key is back, or end when they expire there"
            }
            Self::SenderKeyNotKnownYet => {
                "signed by a key of their sender's that this Signet hasn't heard of yet: they open \
                 once the sender's history arrives, or end when they expire"
            }
            Self::SenderForked => {
                "from an ID with two rival histories: they wait until your person chooses between them"
            }
            Self::SenderChangeWaitsForOwner => {
                "from a contact whose key, owner or host changed, which waits on your person's \
                 word: they show once your person accepts the change"
            }
            Self::DatedOffThisClock => {
                "dated outside this computer's clock: they show once the clocks agree, or end when \
                 they expire"
            }
            Self::Unreadable => {
                "in a form this Signet can't read: a newer release may read them, and otherwise \
                 they end when they expire"
            }
            Self::OwnerMailSealedToAnotherKey => {
                "left by your person for this agent, sealed to a key this Signet doesn't hold: they \
                 open by themselves once that key is back"
            }
        }
    }
}

/// How many wait, of each kind.
#[derive(Default)]
pub struct Tally(BTreeMap<Held, usize>);

#[derive(Serialize)]
pub struct HeldLine {
    pub kind: Held,
    pub count: usize,
    pub why: &'static str,
}

impl Tally {
    pub fn add(&mut self, held: Held) {
        self.add_many(held, 1);
    }

    pub fn add_many(&mut self, held: Held, count: usize) {
        if count > 0 {
            let counted = self.0.entry(held).or_default();
            *counted = counted.saturating_add(count);
        }
    }

    pub fn lines(&self) -> Vec<HeldLine> {
        self.0
            .iter()
            .map(|(kind, count)| HeldLine {
                kind: *kind,
                count: *count,
                why: kind.why(),
            })
            .collect()
    }
}

#[derive(Debug)]
enum Bad {
    /// The signature fails against every key its sender's ID has held, and no history is awaited.
    Forged,
    /// Signed by a key its sender's ID has given up.
    KeyGivenUp,
    /// Signed for another agent.
    NotForThisAgent,
    /// Its sealed body opened with this agent's key and isn't what its outside and signature say.
    Lies,
    /// From a copy of a forked ID the owner chose against.
    ChosenAgainst,
    Replay,
    RefusedByRules,
    /// It read, and what's inside fails a check no key or history arriving changes.
    RefusedByChecks,
}

/// That a row is bad for good. Only the checks here, or a judgment of a [`Readable`], make one.
pub struct Proof<B> {
    seq: i64,
    why: Bad,
    at: PhantomData<B>,
}

impl<B> Proof<B> {
    fn new(seq: i64, why: Bad) -> Self {
        Self {
            seq,
            why,
            at: PhantomData,
        }
    }

    pub fn replay(read: &Readable<B>) -> Self {
        Self::new(read.seq, Bad::Replay)
    }

    pub fn refused_by_rules(read: &Readable<B>) -> Self {
        Self::new(read.seq, Bad::RefusedByRules)
    }

    pub fn refused_by_checks(read: &Readable<B>) -> Self {
        Self::new(read.seq, Bad::RefusedByChecks)
    }
}

/// A row its host may clear.
pub struct Done<B> {
    seq: i64,
    at: PhantomData<B>,
}

impl<B> Clone for Done<B> {
    fn clone(&self) -> Self {
        Self {
            seq: self.seq,
            at: PhantomData,
        }
    }
}

impl<B> Done<B> {
    /// Handed to the agent, the owner's side or the request state machine, which judged it.
    pub fn handed_over(read: &Readable<B>) -> Self {
        Self {
            seq: read.seq,
            at: PhantomData,
        }
    }

    pub fn proven_bad(proof: Proof<B>) -> Self {
        tracing::warn!(seq = proof.seq, why = ?proof.why, "a message proven bad, cleared");
        Self {
            seq: proof.seq,
            at: PhantomData,
        }
    }

    pub fn seq(&self) -> i64 {
        self.seq
    }
}

impl Done<InboxRows> {
    /// Written into this Signet's own keeping before a move, where it's read as any arrival is.
    pub fn written_down(row: &crate::carried::WrittenDown) -> Self {
        Self {
            seq: row.seq(),
            at: PhantomData,
        }
    }
}

impl Done<OwnerMailRows> {
    /// Opened here and judged by the owner's side.
    pub fn taken(mail: &OpenedOwnerMail) -> Self {
        Self {
            seq: mail.seq,
            at: PhantomData,
        }
    }
}

/// A row its host is asked to keep off its pages for a while. A host lets a step from someone let in
/// by reach go after about an hour of these, with no proof, so a row that can't be read is put off
/// only as [`check`] says: held, from someone the owner named, invited or this agent agreed with, or
/// let go, from anyone else.
pub struct PutOff<B> {
    seq: i64,
    held: Option<Held>,
    at: PhantomData<B>,
}

impl<B> PutOff<B> {
    pub fn seq(&self) -> i64 {
        self.seq
    }
}

impl PutOff<InboxRows> {
    /// Read here, and waiting on something, such as the step before it.
    pub fn read(read: &Readable<InboxRows>) -> Self {
        Self {
            seq: read.seq,
            held: None,
            at: PhantomData,
        }
    }

    /// What [`check`] held, which a read counts while it's off the page.
    pub fn held(row: &StoredMessage, why: Held) -> Self {
        Self {
            seq: row.seq,
            held: Some(why),
            at: PhantomData,
        }
    }
}

/// Whether this row's sender is someone the rules let in by reach, not by name, as its host judges by
/// the same signed rules. With no rules, nothing is judged, and it's held. Its sender is only what the
/// envelope claims, which is what its host judged: a host that lies about it could drop the row anyway.
async fn from_a_stranger(signet: &Signet, row: &StoredMessage) -> bool {
    if !signet.rules.exist().await {
        return false;
    }
    let Ok(sender) = claimed_sender(&row.envelope) else {
        return true;
    };
    !signet
        .rules
        .contacts_by_name()
        .await
        .iter()
        .any(|contact| contact.agent == sender && contact.pinned_by != PinnedBy::Reach)
}

/// Held rows this Signet put off at its host, which a page leaves out for up to 30 seconds at a time,
/// so a read counts them from here as well as from its page.
#[derive(Default)]
pub struct HeldOff(ShortLock<BTreeMap<i64, (Held, u64)>>);

/// A row put off comes back on a page within 30 seconds, and a sync pass then notes it again, so one
/// not noted for twice that has opened, been cleared or expired.
const HELD_OFF_SECS: u64 = 60;

impl HeldOff {
    fn rows(&self) -> MutexGuard<'_, BTreeMap<i64, (Held, u64)>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// After a pass over a page: what it put off of what it held, in place of what it knew of that page.
    pub fn after_pass(&self, page: &[i64], put_off: &[PutOff<InboxRows>], now: u64) {
        let mut rows = self.rows();
        for seq in page {
            rows.remove(seq);
        }
        for one in put_off {
            if let (Some(held), true) = (one.held, one.seq > 0) {
                rows.insert(one.seq, (held, now));
            }
        }
    }

    pub fn forget(&self, done: &[Done<InboxRows>]) {
        let mut rows = self.rows();
        for one in done {
            rows.remove(&one.seq);
        }
    }

    /// Adds those off the page just read, which counts its own.
    pub fn count_into(&self, tally: &mut Tally, page: &HashSet<i64>, now: u64) {
        let mut rows = self.rows();
        rows.retain(|_, (_, noted)| noted.saturating_add(HELD_OFF_SECS) >= now);
        for (seq, (held, _)) in rows.iter() {
            if !page.contains(seq) {
                tally.add(*held);
            }
        }
    }
}

pub enum Checked<B> {
    Valid(Readable<B>),
    /// It can't be read yet, and it stays until it can be or it expires.
    Held(Held),
    /// An inbox row that can't be read, from someone let in by reach. It isn't held: it's put off, and
    /// its host lets a step go after about an hour of that, so cheap stranger IDs can't keep a page
    /// full of steps that never open and hide every contact's mail behind them. Nothing ends it here.
    LetGo(PutOff<B>, Held),
    Bad(Proof<B>),
}

/// Goes by the newest copy of the sender's identity this Signet has seen, not the one that came with
/// the message, so a key given up in a recovery signs nothing that counts here, whatever a host shows.
/// A sealed body is opened here, before anything reads it. This is the one place that says whether
/// a row that can't be read is held or let go, from its sender's standing.
pub async fn check(signet: &Signet, row: &StoredMessage, me: &SplintId) -> Checked<InboxRows> {
    match read_or_prove(signet, row, me).await {
        Checked::Held(why) if from_a_stranger(signet, row).await => Checked::LetGo(
            PutOff {
                seq: row.seq,
                held: None,
                at: PhantomData,
            },
            why,
        ),
        checked => checked,
    }
}

async fn read_or_prove(signet: &Signet, row: &StoredMessage, me: &SplintId) -> Checked<InboxRows> {
    let envelope = match verified(signet, row.seq, &row.envelope, &row.sender_identity, me).await {
        Ok(envelope) => envelope,
        Err(not) => return not,
    };
    let sender = envelope.sender().clone();
    match envelope.open(me, &signet.seal_key) {
        Ok(opened) => Checked::Valid(Readable::new(row.seq, opened)),
        // Its signature checked out, so who sent it is known, and the owner's block refuses them for
        // good whatever it says.
        Err(Error::CantOpen | Error::Crypto) if blocked(signet, &sender).await => {
            Checked::Bad(Proof::new(row.seq, Bad::RefusedByRules))
        }
        // Nothing in a sealed body says which key it was sealed to, so one that won't open waits.
        Err(Error::CantOpen | Error::Crypto) => Checked::Held(Held::SealedToAnotherKey),
        // It opened with this agent's key, and its sender signed what doesn't match.
        Err(_) => Checked::Bad(Proof::new(row.seq, Bad::Lies)),
    }
}

/// Whether rules in force block this sender. As with a message that opened, newer rules its host holds
/// are taken first, as the owner may have lifted the block from another device, and until they can be
/// it waits.
async fn blocked(signet: &Signet, sender: &SplintId) -> bool {
    let in_force = || async { signet.rules.exist().await && !signet.rules.stopped().await };
    if !(in_force().await && signet.rules.blocks(sender).await) {
        return false;
    }
    crate::rules::catch_up_with_host(signet).await.is_ok()
        && in_force().await
        && signet.rules.blocks(sender).await
}

/// The same for a row of the invites box, which is never sealed.
pub async fn check_introduction(
    signet: &Signet,
    row: &HeldIntroduction,
    me: &SplintId,
) -> Checked<IntroductionRows> {
    match verified(signet, row.seq, &row.envelope, &row.sender_identity, me).await {
        Ok(envelope) if envelope.is_sealed() => Checked::Held(Held::Unreadable),
        Ok(envelope) => Checked::Valid(Readable::new(row.seq, envelope)),
        Err(not) => not,
    }
}

async fn verified<B>(
    signet: &Signet,
    seq: i64,
    envelope: &str,
    sender_identity: &str,
    me: &SplintId,
) -> Result<VerifiedEnvelope, Checked<B>> {
    let Ok(claimed) = Identity::from_encoded(sender_identity) else {
        return Err(Checked::Held(Held::Unreadable));
    };
    let sender = match signet.contacts.known.newest(&claimed) {
        Ok(sender) => sender,
        Err(Error::Forked) if signet.seen_changes.refuses_copy(&claimed) => {
            return Err(Checked::Bad(Proof::new(seq, Bad::ChosenAgainst)));
        }
        Err(Error::Forked) => return Err(Checked::Held(Held::SenderForked)),
        Err(_) => return Err(Checked::Held(Held::Unreadable)),
    };
    match VerifiedEnvelope::verify(envelope, &sender, unix_now()) {
        Ok(envelope) if envelope.recipient() == me => Ok(envelope),
        Ok(_) => Err(Checked::Bad(Proof::new(seq, Bad::NotForThisAgent))),
        Err(Error::Expired | Error::FromTheFuture) => Err(Checked::Held(Held::DatedOffThisClock)),
        Err(Error::BadSignature) if VerifiedEnvelope::signed_by_a_key_of(envelope, &sender) => {
            Err(Checked::Bad(Proof::new(seq, Bad::KeyGivenUp)))
        }
        // A signature names no key, so one that fails against every key its sender has held reads the
        // same as one by a key nobody has heard of. While a history that could name it is awaited
        // it waits. Otherwise it fails against every key this Signet knows the sender has.
        Err(Error::BadSignature)
            if claimed_sender(envelope).is_ok_and(|said| &said == sender.id()) =>
        {
            if signet.rules.standing_of(sender.id()).await == Standing::WaitingForHistory {
                Err(Checked::Held(Held::SenderKeyNotKnownYet))
            } else {
                Err(Checked::Bad(Proof::new(seq, Bad::Forged)))
            }
        }
        // A copy of someone else's ID came with it, or a form this release can't read. An honest host
        // checked it under that copy before taking it, so this is a host's doing, and it waits.
        Err(_) => Err(Checked::Held(Held::Unreadable)),
    }
}

/// A notice whose sender's ID has forked can't pass under the copy held, so it's read under the one it
/// came with. That's fine for a notice, which counts for nothing until an owner signs for its head.
pub fn notice_on_a_fork(row: &StoredMessage, me: &SplintId) -> Option<Readable<InboxRows>> {
    let sender = Identity::from_encoded(&row.sender_identity).ok()?;
    let envelope = VerifiedEnvelope::verify(&row.envelope, &sender, unix_now()).ok()?;
    (envelope.recipient() == me && is_notice_body(envelope.body()))
        .then(|| Readable::new(row.seq, envelope))
}

/// Owner mail opened here. Nothing in it counts until the owner's signature inside checks out.
pub struct OpenedOwnerMail {
    seq: i64,
    pub mail: OwnerMail,
}

/// Only the owner's own sign-ins can leave owner mail, so one that doesn't open is theirs, sealed to a
/// key this Signet doesn't hold, and it waits.
pub fn open_owner_mail(
    signet: &Signet,
    row: &StoredOwnerMail,
    me: &SplintId,
) -> Result<OpenedOwnerMail, Held> {
    splint_core::owner_call::open_owner_mail(&signet.seal_key, me, &row.sealed)
        .map(|mail| OpenedOwnerMail { seq: row.seq, mail })
        .map_err(|_| Held::OwnerMailSealedToAnotherKey)
}

//! Moves steps between this Signet and its host in the background, whatever the agent is doing, so
//! no agent call can send or suppress a `received`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use splint_core::changes::is_notice_body;
use splint_core::host_api::{GuestOutbound, GuestStepRow, WaitAnswer};
use splint_core::invites::redeem_proof_in;
use splint_core::requests::{
    Action, Applied, Refused, RequestState, Side, StepKind, is_step_body, request_of,
};
use splint_core::rules::{Admission, PinnedBy};
use splint_core::{MessageId, VerifiedEnvelope, parse_address, unix_now};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::Signet;
use crate::activity::Arrival;
use crate::ending::{self, Checked, Done, Held, InboxRows, PutOff};
use crate::host_client::HostError;
use crate::requests::store::{HeldBecause, Record, may_supersede};
use crate::requests::{Contact, agent_api, contact_of};
use crate::{budget, changes, invites, owner_relay, rules};

/// After every pass, so a host that always has more can't spin this.
const PASS_GAP: Duration = Duration::from_millis(50);
/// A clock that's off is logged again only once it has moved this far, so its log says what changed.
const CLOCK_SAID_AGAIN_SECS: u64 = 60;
/// Held calls that ended with nothing new before a look anyway: about 5 minutes on a host that holds
/// each for 25 seconds. It's what a message would wait if it reached the inbox some way that didn't
/// wake this, and costs one look in 12.
const LOOK_AT_LEAST_AFTER: u32 = 12;
/// A host holds a wait with nothing new for 25 seconds, and never less than a second. One that answers
/// with nothing new sooner isn't holding it, and taking it at its word would call it without a pause.
const QUICKEST_QUIET_HOLD: Duration = Duration::from_secs(1);

enum Taken {
    /// Applied or refused for good, so the host can clear it.
    Done,
    /// The rules listing its sender aren't in force. It stays on the host until they are or the
    /// envelope expires, and nothing else can be judged meanwhile.
    Wait,
    /// It follows a step that hasn't arrived, its sender can't be told from a contact yet, or its
    /// chain can't be read. Each is only a delay, but there may be a page of them, so the host keeps
    /// it out of sight for a while and what's behind it gets read.
    Later,
}

/// Between looks this waits on the host, which answers as soon as something comes for this agent, and
/// on the owner, whose word may have to reach the host. A host that can't hold the call, such as an
/// older one, gets a look every `every` instead, as does anything still queued to go. The held call
/// runs on its own, so a look meanwhile doesn't drop it and make another.
pub async fn run(signet: Arc<Signet>, every: Duration, owner_away: Option<Arc<Notify>>) {
    let mut since = None;
    let mut look = true;
    let mut quiet_holds = 0_u32;
    let mut held: Option<JoinHandle<(Result<WaitAnswer, HostError>, Duration)>> = None;
    let mut clock_said: Option<i64> = None;
    loop {
        // Its host would refuse everything here until it has taken this agent back, and a refusal
        // read in that gap could be taken for a retirement.
        signet.registered.until_settled().await;
        let owner_mark = signet.activity.owner_now();
        if look {
            quiet_holds = 0;
            // A recovery of its owner can undo a retirement, and nothing else can.
            if signet.retired.is() {
                crate::retired::now_and_then_hear_of_a_recovery(&signet).await;
            }
            let result = pass(&signet, owner_away.as_ref()).await;
            note_what_its_host_did(&signet, &result).await;
            // However quickly a host answers, so one that always says there's more can't spin this.
            tokio::time::sleep(PASS_GAP).await;
            if result.is_ok() {
                clock_said = None;
            }
            match result {
                // There may be more where that came from, or behind it.
                Ok(true) => continue,
                Ok(false) => {}
                Err(HostError::ClockOff(off)) => {
                    // Said when it starts or changes, not on every pass, as only a person fixes it.
                    if clock_said.is_none_or(|said| said.abs_diff(off) >= CLOCK_SAID_AGAIN_SECS) {
                        let error = HostError::ClockOff(off);
                        tracing::warn!(%error, "our host refuses this agent's dates");
                        clock_said = Some(off);
                    }
                    tokio::time::sleep(every).await;
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%error, "couldn't sync requests with our host");
                    // A host refuses a retired agent's proofs, which its owner's signature explains.
                    if matches!(error, HostError::Refused) {
                        crate::retired::learn(&signet).await;
                    }
                    tokio::time::sleep(every).await;
                    continue;
                }
            }
        }
        // Nothing to sync, and nothing from the host counts, until the owner does something.
        if !signet.rules.exist().await || signet.recovering() {
            tokio::select! {
                () = tokio::time::sleep(every) => look = false,
                () = signet.activity.owner_changed_from(owner_mark) => look = true,
            }
            continue;
        }
        let waiting = held.get_or_insert_with(|| tokio::spawn(wait_on_host(signet.clone(), since)));
        tokio::select! {
            ended = waiting => {
                held = None;
                match ended {
                    Ok((Ok(answer), took)) if answer.new || took >= QUICKEST_QUIET_HOLD => {
                        since = Some(answer.since);
                        quiet_holds = quiet_holds.saturating_add(1);
                        // Now and then anyway, in case something came by a way that didn't wake this.
                        look = answer.new || quiet_holds >= LOOK_AT_LEAST_AFTER;
                    }
                    Ok((Ok(_), _)) => {
                        tracing::debug!("our host answered a wait at once with nothing, so this asks as before");
                        tokio::time::sleep(every).await;
                        look = true;
                    }
                    Ok((Err(error), _)) => {
                        tracing::debug!(%error, "our host didn't hold a wait, so this asks as before");
                        tokio::time::sleep(every).await;
                        look = true;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "waiting on our host stopped");
                        tokio::time::sleep(every).await;
                        look = true;
                    }
                }
            }
            // What's queued is tried again this often, whatever the host is holding, including what an
            // agent's call queued just now, and so are rules the host refused a while ago.
            () = tokio::time::sleep(every) => {
                look = queued(&signet).await || signet.rules.due_another_offer().await;
            }
            () = signet.activity.owner_changed_from(owner_mark) => look = true,
        }
    }
}

/// One held call, and how long it took to answer.
async fn wait_on_host(
    signet: Arc<Signet>,
    since: Option<u64>,
) -> (Result<WaitAnswer, HostError>, Duration) {
    let me = signet.who().identity.id().clone();
    let asked = Instant::now();
    let answer = signet.host.wait(&signet.key, &me, since).await;
    (answer, asked.elapsed())
}

/// Whether anything this pass did means another may find more.
async fn pass(signet: &Arc<Signet>, owner_away: Option<&Arc<Notify>>) -> Result<bool, HostError> {
    // Before syncing, so a yes within the caps goes out on this pass.
    let acted = !signet.recovering() && crate::delegation::act(signet, unix_now()).await;
    let mut took = sync_once(signet).await? || acted;
    // After syncing, as what this pass took in may say the other side's person has set up their
    // controls, which is what these wait for.
    if !signet.recovering() && agent_api::send_what_their_controls_held(signet).await {
        took = true;
    }
    if let Some(mail_taken) = owner_away
        && !signet.recovering()
        && owner_relay::take_what_the_owner_signed(signet).await
    {
        mail_taken.notify_one();
        took = true;
    }
    Ok(took)
}

/// Steps waiting to go, which a pass tries again, unless the rules have them held here.
async fn queued(signet: &Signet) -> bool {
    if signet.rules.stopped().await {
        return false;
    }
    if signet.receipts.owing().await {
        return true;
    }
    let records = signet.requests.store.lock().await;
    records.values().any(|record| !record.outbox.is_empty())
}

/// Whether its host answered this pass, for whoever asks how this agent stands. With no rules, or a key
/// waiting for a recovery, a pass doesn't go to its host, so it says nothing either way.
async fn note_what_its_host_did(signet: &Signet, result: &Result<bool, HostError>) {
    if signet.rules.exist().await && !signet.recovering() {
        signet
            .registered
            .heard_from_host(!matches!(result, Err(HostError::Unreachable)));
    }
}

/// Whether it took anything, so there may be more.
async fn sync_once(signet: &Signet) -> Result<bool, HostError> {
    // With no rules there are no contacts, so nothing to sync and no reason to call the host. A key
    // waiting for a recovery can't sign anything that would count.
    if !signet.rules.exist().await || signet.recovering() {
        return Ok(false);
    }
    rules::push_to_host(signet).await;
    flush(signet).await?;
    crate::receipts::flush(signet).await?;
    let who = signet.who();
    let me = who.identity.id();
    let rows = crate::carried::pull(signet, me).await?;
    let mut done: Vec<Done<InboxRows>> = Vec::new();
    let mut later: Vec<PutOff<InboxRows>> = Vec::new();
    // Rows that can't be read yet. The host keeps a step of these out of sight for a while, so one
    // sender's page of them can't hide what's behind, and ignores a note, which doesn't hold up steps.
    // Neither counts as anything taken, or a note that never opens would have this pass again at once,
    // for good. One from someone let in by reach is let go by its host after about an hour of these.
    let mut held = Vec::new();
    // Whether this pass has asked its host for newer rules yet. It asks at most once.
    let mut caught_up: Option<bool> = None;
    for row in &rows {
        rules::note_sender(signet, row).await?;
        // What's proven bad is left for the agent's next inbox call to report and clear.
        let checked = match ending::check(signet, row, me).await {
            Checked::Valid(read) => Ok(read),
            Checked::Held(why) => Err((PutOff::held(row, why), why)),
            Checked::LetGo(put_off, why) => Err((put_off, why)),
            Checked::Bad(_) => continue,
        };
        let read = match checked {
            Ok(read) => read,
            Err((put_off, why)) => {
                // Its sender's ID has forked, so this may be the notice saying how.
                let notice = (why == Held::SenderForked)
                    .then(|| ending::notice_on_a_fork(row, me))
                    .flatten();
                if let Some(notice) = notice {
                    changes::take_notice(signet, notice.envelope()).await?;
                    done.push(Done::handed_over(&notice));
                    continue;
                }
                tracing::debug!(seq = row.seq, ?why, "a row put off until it can be read");
                held.push(put_off);
                continue;
            }
        };
        let envelope = read.envelope();
        signet
            .their_sealing
            .note(envelope)
            .await
            .map_err(|_| HostError::LocalStorage)?;
        if !is_step_body(envelope.body()) {
            // The agent reads and clears notes itself, so only a new one is news, and that holds
            // across a restart. One whose pause can't be noted stays new, for the next pass.
            if !signet.arrivals.counted(envelope.id()) {
                note_one_shown(signet, envelope).await?;
                signet
                    .arrivals
                    .count_note(envelope.sender(), envelope.id(), unix_now());
                if !over_the_days_texts(signet, envelope).await {
                    signet
                        .activity
                        .arrived(Arrival::Messages, envelope.sender());
                }
            }
            // A contact's, the day it's shown, even before the agent reads it. Someone let in by reach
            // has a daily quota the inbox read takes from, so theirs goes as it's shown.
            if !by_reach(signet, envelope).await
                && takes_the_days_text(signet, envelope).await
                && crate::receipts::owe(signet, &read).await.is_err()
            {
                tracing::debug!("couldn't owe a note's receipt yet, so the next pass does");
            }
            continue;
        }
        // A note's receipt only changes what this Signet kept of the note.
        if crate::sent::take_receipt(signet, &read).await? {
            done.push(Done::handed_over(&read));
            continue;
        }
        if is_notice_body(envelope.body()) {
            changes::take_notice(signet, envelope).await?;
            done.push(Done::handed_over(&read));
            continue;
        }
        if let Some(proof) = redeem_proof_in(envelope.body()) {
            rules::take_redeem(signet, row, envelope, &proof).await?;
            done.push(Done::handed_over(&read));
            continue;
        }
        // The state machine applied it or refused it for good, and either way it has been judged.
        match take_step(signet, envelope, &mut caught_up).await? {
            Taken::Done => done.push(Done::handed_over(&read)),
            Taken::Wait => {}
            Taken::Later => later.push(PutOff::read(&read)),
        }
    }
    if !done.is_empty() {
        crate::carried::ack(signet, me, &done).await?;
    }
    let from_host = later.iter().any(|one| one.seq() > 0);
    later.append(&mut held);
    let put_off = !later.is_empty() && crate::carried::later(signet, me, &later).await?;
    // Only a step put off out of sight leaves something new behind it for the next pass. A carried
    // one, or one a move is taking, shows again at once, and a pass straight after spun on it every
    // 50 ms until it expired.
    let took = !done.is_empty() || (from_host && put_off);
    let page: Vec<i64> = rows.iter().map(|row| row.seq).collect();
    signet
        .carried
        .held_off
        .after_pass(&page, &later, unix_now());
    let guests = take_guest_steps(signet).await?;
    // Acceptances of this agent's invites go to its owner's side as they come, whatever the agent does.
    // A host that has no box, such as an older one, holds up nothing else.
    if let Err(error) = invites::take_box(signet).await {
        tracing::debug!(%error, "couldn't read the invites box");
    }
    flush(signet).await?;
    crate::receipts::flush(signet).await?;
    Ok(took || guests)
}

async fn by_reach(signet: &Signet, envelope: &VerifiedEnvelope) -> bool {
    signet
        .rules
        .contact_of(envelope.sender())
        .await
        .is_none_or(|contact| contact.pinned_by == PinnedBy::Reach)
}

/// A note from a contact past the day's words its owner signed for them, which waits on the host
/// unseen until tomorrow, so it wakes nobody. The inbox counts it when it's shown, not here.
async fn over_the_days_texts(signet: &Signet, envelope: &VerifiedEnvelope) -> bool {
    let sender = envelope.sender();
    if signet.rules.admission_of(sender).await != Admission::Deliver {
        return false;
    }
    let allowed = signet.rules.texts_per_day_with(sender).await;
    !signet
        .budget
        .text_from_fits(sender, envelope.id(), allowed, unix_now())
        .await
}

/// Counts a contact's note against the day's limit on their words, as the inbox read will show it, so
/// one pass can't owe receipts for more of them than the day lets the agent see. A note counted once
/// fits again, so the read that shows it later costs nothing more. One the rules don't let through
/// with words is counted for nothing and owes nothing.
async fn takes_the_days_text(signet: &Signet, envelope: &VerifiedEnvelope) -> bool {
    let sender = envelope.sender();
    let with_words = signet.rules.admission_of(sender).await == Admission::Deliver
        && signet
            .rules
            .contact_of(sender)
            .await
            .is_some_and(|contact| contact.text);
    if !with_words {
        return false;
    }
    let allowed = signet.rules.texts_per_day_with(sender).await;
    signet
        .budget
        .take_text_from(sender, envelope.id(), allowed, unix_now())
        .await
        .is_ok()
}

/// A note the agent will be shown, from a contact whose words it takes, may be the information a
/// request it paused waits on. One it won't be shown moves nothing.
async fn note_one_shown(signet: &Signet, envelope: &VerifiedEnvelope) -> Result<(), HostError> {
    let sender = envelope.sender();
    let shown = signet.rules.admission_of(sender).await == Admission::Deliver
        && signet
            .rules
            .contact_of(sender)
            .await
            .is_some_and(|contact| contact.text);
    if !shown {
        return Ok(());
    }
    crate::requests::store::note_after_pause(signet, sender, false, envelope.created_at()).await
}

/// What's come in through this agent's one-use links. These never go near the inbox or its rules: a
/// guest's key counts only on a link the owner signed for, and it's checked under the key that link
/// names, not one a host gives. While the rules say stop they wait on the host.
async fn take_guest_steps(signet: &Signet) -> Result<bool, HostError> {
    {
        let records = signet.requests.store.lock().await;
        if !records.values().any(|record| record.guest) {
            return Ok(false);
        }
    }
    if signet.rules.stopped().await {
        return Ok(false);
    }
    let who = signet.who();
    let read = &signet.requests.guest_steps_read;
    let steps = signet
        .host
        .guest_steps(&signet.key, who.identity.id(), read.load(Ordering::Relaxed))
        .await?;
    for row in &steps {
        take_guest_step(signet, row).await?;
        read.fetch_max(row.seq, Ordering::Relaxed);
    }
    Ok(!steps.is_empty())
}

async fn take_guest_step(signet: &Signet, row: &GuestStepRow) -> Result<(), HostError> {
    let mut records = signet.requests.store.lock().await;
    let Some(mut record) = records
        .get(&row.request)
        .filter(|record| record.guest)
        .cloned()
    else {
        return Ok(());
    };
    let guest = record.peer_agent()?;
    let now = unix_now();
    let envelope = match VerifiedEnvelope::verify(&row.envelope, &guest, now) {
        Ok(envelope) => envelope,
        Err(_) => {
            drop(records);
            signet
                .requests
                .refused
                .came_in(guest.id(), "bad_signature_or_dates".to_owned())
                .await;
            return Ok(());
        }
    };
    let mut chain = record.chain(signet)?;
    let kind = match chain.apply(&envelope) {
        Ok(Applied::Kept(kind)) => kind,
        Ok(Applied::Dropped) | Err(Refused::Replay) => return Ok(()),
        Err(reason) => {
            drop(records);
            refuse(signet, &envelope, reason).await;
            return Ok(());
        }
    };
    record.steps = chain.steps();
    // The owner already signed for whatever the guest picks from the offer, so nobody else is asked.
    if kind == StepKind::Accept
        && let Some(approval) = chain.guest_offer_approval()
    {
        match chain.propose(Side::Requester, Action::Confirm(approval), now) {
            Ok(step) => {
                let signed = step.sign(&signet.key, &signet.who().identity, now)?;
                record.add_own(&signed);
            }
            Err(reason) => {
                tracing::warn!(%reason, "couldn't finish a link's request");
            }
        }
    }
    tracing::info!(
        message_id = %envelope.id(),
        sender = %envelope.sender(),
        state = ?chain.state_at(now),
        "a guest's step, verified and applied"
    );
    signet
        .requests
        .store
        .commit(&mut records, &row.request, record)?;
    drop(records);
    signet.activity.arrived(Arrival::Requests, guest.id());
    Ok(())
}

async fn refuse(signet: &Signet, envelope: &VerifiedEnvelope, reason: Refused) -> Taken {
    tracing::warn!(
        message_id = %envelope.id(),
        sender = %envelope.sender(),
        %reason,
        "refused a step"
    );
    let word = serde_json::to_value(reason)
        .ok()
        .and_then(|word| word.as_str().map(str::to_owned))
        .unwrap_or_default();
    signet
        .requests
        .refused
        .came_in(envelope.sender(), word)
        .await;
    Taken::Done
}

/// The contact to start a record with, if this step is for a request we've never seen and comes
/// from someone the owner's rules list. It looks the contact up with nothing locked, since that can mean
/// a call to another domain.
async fn new_contact(
    signet: &Signet,
    request: &MessageId,
    envelope: &VerifiedEnvelope,
) -> Result<Option<Contact>, HostError> {
    if signet
        .requests
        .store
        .lock()
        .await
        .contains_key(request.as_str())
    {
        return Ok(None);
    }
    contact_of(signet, envelope.sender()).await
}

async fn take_step(
    signet: &Signet,
    envelope: &VerifiedEnvelope,
    caught_up: &mut Option<bool>,
) -> Result<Taken, HostError> {
    // Checked here too, so a host can't push a stranger's step at an agent. While the rules have it
    // stopped nothing can be judged, so a step waits on the host for them to lift.
    let mut admission = signet.rules.admission_of(envelope.sender()).await;
    // Its host let it in, so the owner may have signed rules there that haven't reached here yet, as
    // when they name someone from another device and the host lets what that one sent out of
    // quarantine, such as a price that went the moment this agent's owner confirmed. Those
    // are taken first, once a pass as the inbox does, and until they can be, the step stays on the host
    // rather than being refused for good.
    if !matches!(admission, Admission::Deliver | Admission::Wait) && !signet.rules.stopped().await {
        if caught_up.is_none() {
            *caught_up = Some(rules::catch_up_with_host(signet).await.is_ok());
        }
        if *caught_up == Some(false) {
            return Ok(Taken::Later);
        }
        admission = signet.rules.admission_of(envelope.sender()).await;
    }
    match admission {
        Admission::Deliver => {}
        // Waiting on the owner's word about a change to this sender, and what's behind it shouldn't.
        Admission::Wait if !signet.rules.stopped().await => return Ok(Taken::Later),
        _ if signet.rules.stopped().await => return Ok(Taken::Wait),
        _ => return Ok(refuse(signet, envelope, Refused::WrongParty).await),
    }
    let (request, carries_person_text) = match request_of(envelope) {
        Ok(Some(step)) => (step.request, step.carries_person_text),
        Ok(None) => return Ok(Taken::Done),
        Err(reason) => return Ok(refuse(signet, envelope, reason).await),
    };
    let contact = new_contact(signet, &request, envelope).await;

    let mut records = signet.requests.store.lock().await;
    let mut record = match (records.get(request.as_str()), contact) {
        (Some(record), _) => record.clone(),
        (None, Ok(Some(contact))) => Record::new(
            Side::Recipient,
            contact.address,
            contact.agent.encoded(),
            contact.owner.encoded(),
            contact.binding,
        ),
        // Rules stopped since the check above give no contacts at all, and that mustn't lose a
        // contact's new request for good. It stays on the host until they count again or it expires.
        (None, Ok(None)) if signet.rules.lists_for_requests(envelope.sender()).await => {
            let stopped = signet.rules.stopped().await;
            return Ok(if stopped { Taken::Wait } else { Taken::Later });
        }
        // Taken off the rules since the check above. Nothing is lost: the sender can send again.
        (None, Ok(None)) => {
            drop(records);
            return Ok(refuse(signet, envelope, Refused::WrongParty).await);
        }
        // Refusing would clear it from the host for good, over what may be a passing outage.
        (None, Err(error)) => {
            tracing::debug!(%error, "a step waits until its sender can be looked up");
            return Ok(Taken::Later);
        }
    };
    // One interaction that can't be read, such as one whose schema has been taken away, stays on the
    // host and mustn't hold up everything behind it.
    let Ok(mut chain) = record.chain(signet) else {
        tracing::warn!(message_id = %envelope.id(), "a step waits for a chain that can't be read");
        return Ok(Taken::Later);
    };
    let kind = match chain.apply(envelope) {
        Ok(Applied::Kept(kind)) => kind,
        // What can't matter, out of a flood. Nothing is stored, and no `received` goes back.
        Ok(Applied::Dropped) => return Ok(Taken::Done),
        Err(Refused::UnknownPrev) => return Ok(Taken::Later),
        // An `open` of a type its sender has just agreed with this agent can come before the step that
        // agreed it, so it waits on the host until that's here or it expires.
        Err(Refused::UnknownType) => return Ok(Taken::Later),
        // Already in the chain, which is what a crash before an ack and a replay both look like.
        Err(Refused::Replay) => return Ok(Taken::Done),
        Err(reason) => return Ok(refuse(signet, envelope, reason).await),
    };
    // The owner's rules say which types this contact may use. A host only checks the list, so the
    // words a type can carry are checked here, on every step, since rules can change midway.
    let rule = signet.rules.contact_of(envelope.sender()).await;
    let may_use = chain
        .interaction_schema()
        .zip(rule.as_ref())
        .is_some_and(|(schema, rule)| match chain.proposed_schema() {
            Some(proposed) => rule.may_propose(proposed),
            None => rule.may_use(schema),
        });
    if !may_use {
        return Ok(refuse(signet, envelope, Refused::TypeNotAllowed).await);
    }
    // Someone let in by reach has quotas of their own at the host, which share out the whole day, and
    // a total here, in case that host lies.
    let is_contact = rule
        .as_ref()
        .is_some_and(|rule| rule.pinned_by != PinnedBy::Reach);
    // A host is meant to stop these, and may lie. Anyone can make an owner key to sign words with.
    if carries_person_text && !rule.is_some_and(|rule| rule.may_carry_person_text()) {
        return Ok(refuse(signet, envelope, Refused::BadPersonText).await);
    }
    // A host is meant to stop these too, and may lie. So can whoever runs the other side's Signet.
    // A `type/1` counts against its own two a day, just below.
    let proposes = chain.proposed_schema().is_some();
    if kind == StepKind::Open && is_contact && !proposes {
        let allowed = signet
            .rules
            .new_requests_per_day_with(envelope.sender())
            .await;
        let counted = signet
            .budget
            .take_new_request_from(envelope.sender(), allowed, unix_now())
            .await;
        match counted {
            Ok(()) => {}
            Err(budget::NotTaken::Spent) => {
                return Ok(refuse(signet, envelope, Refused::OverLimit).await);
            }
            Err(budget::NotTaken::Unsaved) => return Err(HostError::LocalStorage),
        }
    }
    // Two proposals a day each way, which their Signet holds them to too, and may not.
    if kind == StepKind::Open && chain.proposed_schema().is_some() {
        match signet
            .budget
            .take_proposal_from(envelope.sender(), unix_now())
            .await
        {
            Ok(()) => {}
            Err(budget::NotTaken::Spent) => {
                return Ok(refuse(signet, envelope, Refused::TooManyProposals).await);
            }
            Err(budget::NotTaken::Unsaved) => return Err(HostError::LocalStorage),
        }
    }
    if kind == StepKind::Open && !is_contact {
        let allowed = signet.rules.new_from_others_per_day().await;
        let counted = if signet.rules.is_unconfirmed(envelope.sender()).await {
            signet
                .budget
                .take_new_from_unconfirmed(envelope.id(), allowed, unix_now())
                .await
        } else {
            signet
                .budget
                .take_new_from_others(envelope.id(), allowed, unix_now())
                .await
        };
        match counted {
            Ok(()) => {}
            Err(budget::NotTaken::Spent) => {
                return Ok(refuse(signet, envelope, Refused::OverLimit).await);
            }
            Err(budget::NotTaken::Unsaved) => return Err(HostError::LocalStorage),
        }
    }
    let moves_a_stranger = chain.supersedes().is_some_and(|supersedes| {
        kind == StepKind::Open
            && !may_supersede(signet, &records, &record.peer_identity, supersedes)
    });
    if moves_a_stranger {
        return Ok(refuse(signet, envelope, Refused::Malformed).await);
    }
    record.steps = chain.steps();
    record.last_at = unix_now();
    // A fork means a key misbehaved, and one key mustn't be able to fill this side's room on its
    // host by making it answer each step. It's also no use: a disputed chain has no head to prove.
    let disputed = chain.state_at(unix_now()) == RequestState::Disputed;
    // A payment step doesn't move the chain, and what it asks for is answered by the next one, so it
    // gets no `received` of its own.
    let gets_a_receipt = !matches!(
        kind,
        StepKind::Received | StepKind::PayRequest | StepKind::PaymentReceived
    );
    if gets_a_receipt && !disputed && !record.guest {
        let receipt = chain.receipt(record.role, envelope.id())?.sign(
            &signet.key,
            &signet.who().identity,
            unix_now(),
        )?;
        record.queue_receipt(&receipt);
    }
    tracing::info!(
        message_id = %envelope.id(),
        sender = %envelope.sender(),
        state = ?chain.state_at(unix_now()),
        "verified and applied to the request"
    );
    // If this fails the step stays unacknowledged on the host, and comes round again.
    signet
        .requests
        .store
        .commit_chain(signet, &mut records, request.as_str(), record, &chain)?;
    drop(records);
    // A receipt only says the other side has what this agent sent, which is this agent's own move.
    if kind != StepKind::Received {
        signet.arrivals.note(envelope.sender(), unix_now());
        signet
            .activity
            .arrived(Arrival::Requests, envelope.sender());
    }
    Ok(Taken::Done)
}

/// Where this record's contact is now, if the owner's rules let anything go to them. It's asked at the
/// moment of sending, because a step can wait here long after the rules it was signed under, and they
/// may have moved to another host since.
async fn reachable_at(signet: &Signet, record: &Record) -> Option<String> {
    let peer = record.peer_agent().ok()?;
    let contact = signet.rules.contact_of(peer.id()).await?;
    Some(contact.address)
}

/// A link lives on this agent's own host, so that's the only place these go. While the rules say stop
/// they stay here, like any other step.
async fn flush_to_guest(
    signet: &Signet,
    request: &str,
    record: &Record,
) -> Result<Vec<(String, MessageId)>, HostError> {
    if signet.rules.stopped().await {
        return Ok(Vec::new());
    }
    let chain = record.chain(signet)?;
    let schema = chain.interaction_schema().ok_or(HostError::LocalStorage)?;
    let mut went = Vec::new();
    for outgoing in &record.outbox {
        let step = GuestOutbound {
            envelope: outgoing.compact.clone(),
            guest_identity: record.peer_identity.clone(),
            form: schema.guest_form(),
        };
        match signet.host.send_to_guest(&step).await {
            Ok(()) => went.push((request.to_owned(), outgoing.message_id.clone())),
            Err(error) if error.try_later() => return Err(error),
            // One a host won't take stays queued until it expires, and mustn't hold up the rest.
            Err(_) => {}
        }
    }
    Ok(went)
}

/// Hands waiting steps to this agent's host, each request's in order. A host that's down only delays
/// them. Sending one twice is harmless, because its ID stays the same and a host keeps one copy.
/// While the rules say stop, steps stay here, receipts and what the owner signed included, and go
/// if the owner lifts that before they expire.
pub async fn flush(signet: &Signet) -> Result<(), HostError> {
    let waiting: Vec<(String, Record)> = {
        let records = signet.requests.store.lock().await;
        let with_steps = records
            .iter()
            .filter(|(_, record)| !record.outbox.is_empty());
        with_steps
            .map(|(id, record)| (id.clone(), record.clone()))
            .collect()
    };
    let mut sent: Vec<(String, MessageId)> = Vec::new();
    // Why each record tried still holds a step, kept so the agent is told rather than left to think
    // it went. A host's refusal used to be dropped here.
    let mut held: Vec<(String, HeldBecause)> = Vec::new();
    let mut tried: Vec<&String> = Vec::new();
    'requests: for (request, record) in &waiting {
        if record.guest {
            match flush_to_guest(signet, request, record).await {
                Ok(went) => sent.extend(went),
                Err(error) if error.try_later() => break 'requests,
                Err(_) => {}
            }
            continue;
        }
        tried.push(request);
        let Some(address) = reachable_at(signet, record).await else {
            held.push((request.clone(), HeldBecause::NotAContactNow));
            continue;
        };
        let (_, domain) = parse_address(&address)?;
        for outgoing in &record.outbox {
            match signet.host.send(&outgoing.compact, domain).await {
                Ok(()) => {}
                // There's one host, so a hung one needn't time out once per request.
                Err(error) if error.try_later() => {
                    let why = if matches!(error, HostError::ClockOff(_)) {
                        HeldBecause::ClockOff
                    } else {
                        HeldBecause::HostUnreachable
                    };
                    held.push((request.clone(), why));
                    break 'requests;
                }
                // One step a host won't take stays queued, and mustn't hold up the rest: a reader
                // goes by what a step names, not by when it came.
                Err(HostError::TooMany) => {
                    held.push((request.clone(), HeldBecause::HostLimit));
                    continue;
                }
                Err(_) => {
                    held.push((request.clone(), HeldBecause::HostRefused));
                    continue;
                }
            }
            let message_id = &outgoing.message_id;
            tracing::info!(%message_id, "signed, handing to our host");
            sent.push((request.clone(), message_id.clone()));
        }
    }
    let mut records = signet.requests.store.lock().await;
    for (request, message_id) in &sent {
        if let Some(record) = records.get_mut(request) {
            record.handed_to_host(message_id);
        }
    }
    let mut changed = false;
    for (request, record) in records.iter_mut() {
        changed |= record.drop_expired_outgoing();
        let now_held = if record.outbox.is_empty() {
            None
        } else if tried.contains(&request) {
            held.iter()
                .rev()
                .find(|(id, _)| id == request)
                .map(|(_, why)| *why)
        } else {
            record.held_because
        };
        if record.held_because != now_held {
            record.held_because = now_held;
            changed = true;
        }
    }
    if changed || !sent.is_empty() {
        signet.requests.store.save(&records)?;
    }
    Ok(())
}

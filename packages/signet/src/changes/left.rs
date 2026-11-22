//! What's left to do after this agent moved to another host under the same ID: telling the host it
//! left, which then stops taking its mail and says where it went, and giving its new host back the
//! contacts it agreed by itself there, which only the host where they were agreed held.
//!
//! Until it's told, mail can still land there, so what waits is taken each time before telling it.
//! Both go on by themselves, on the changes pass, until done or for a week, so a host that's down at
//! the moment of the move still hears. The host left is the one other host Signet ever calls, and it's
//! given only this agent's public, signed history.

use std::sync::Arc;

use splint_core::contact_invites::PendingContact;
use splint_core::host_api::MOST_AGREED_IN_ONE_CALL;
use splint_core::{parse_address, unix_now};

use super::own::Left;
use crate::Signet;
use crate::host_client::{HostClient, HostError};

/// How long a move is followed up, after which a host that's still down hears from nobody.
const FOLLOW_UP_SECS: u64 = 7 * 24 * 60 * 60;
/// Pairs the day's count left out wait this long before they're given back again.
const PAIRS_AGAIN_SECS: u64 = 60 * 60;

/// Notes the host this agent is leaving, for what's owed once it has gone.
pub fn moved_from(signet: &Signet, domain: &str) -> Result<(), HostError> {
    let now = unix_now();
    signet.own_changes.set_left(Some(Left {
        domain: domain.to_owned(),
        until: now.saturating_add(FOLLOW_UP_SECS),
        told: false,
        pairs_due: Some(now),
    }))
}

/// Does at once what a move leaves to do, apart from the call that made it. Telling every contact and
/// a host that may be gone can outlast whoever made that call, and what a call was still doing when its
/// caller gave up is dropped with it.
pub fn follow_up_a_move(signet: Arc<Signet>) {
    tokio::spawn(async move {
        // The new host enforces the owner's rules from the start, so what contacts send isn't held
        // as a stranger's, and it has them before it's given the contacts agreed by invite back.
        crate::rules::push_to_host(&signet).await;
        {
            let _changing = signet.changing_who.lock().await;
            if let Err(error) = super::bring_up_to_date(&signet).await {
                tracing::warn!(%error, "couldn't write this agent's move in its history yet");
            }
        }
        super::publish_now(&signet).await;
        catch_up(&signet).await;
    });
}

/// One go at whatever is still owed for a move, if there was one.
pub async fn catch_up(signet: &Signet) {
    let Some(mut left) = signet.own_changes.left() else {
        return;
    };
    let now = unix_now();
    if now >= left.until {
        tracing::warn!(host = %left.domain, "gave up following up a move after a week");
        let _ = signet.own_changes.set_left(None);
        return;
    }
    // Noted before the history says so, and until it does the host left has nothing to learn from it.
    let says_moved = signet
        .own_changes
        .current()
        .address()
        .and_then(|address| parse_address(address).ok().map(|(_, at)| at != left.domain))
        .unwrap_or(false);
    if !says_moved {
        return;
    }
    // Mail still landing there until it hears is taken first, as it answers for this agent no more after.
    if !left.told && took_what_waits_there(signet, &left.domain).await {
        left.told = tell_the_host_left(signet, &left.domain).await;
    }
    // Each pair is judged by the rules the new host holds, so one given back before it has them is
    // left out for good.
    if left.pairs_due.is_some_and(|due| due <= now) && signet.rules.host_holds_the_newest().await {
        left.pairs_due = match give_back_pairs(signet).await {
            Ok(false) => None,
            Ok(true) => Some(now.saturating_add(PAIRS_AGAIN_SECS)),
            Err(_) => left.pairs_due,
        };
    }
    let done = left.told && left.pairs_due.is_none();
    if let Err(error) = signet.own_changes.set_left((!done).then_some(left)) {
        tracing::warn!(%error, "couldn't note what's left of a move");
    }
}

/// Whether nothing is left waiting at the host left that could still be read there. One that no longer
/// knows this agent has nothing to give.
async fn took_what_waits_there(signet: &Signet, domain: &str) -> bool {
    let Ok(left) = HostClient::new(domain.to_owned(), signet.host.scheme) else {
        return false;
    };
    match crate::carried::take_from(signet, &left).await {
        Ok(took) => !took.full,
        Err(HostError::LocalStorage | HostError::TooMany) => false,
        Err(error) => !error.try_later(),
    }
}

/// Whether the host left has the history naming the new one, or never will: one that doesn't hold
/// this agent, or refuses it, has nothing to learn from it.
async fn tell_the_host_left(signet: &Signet, domain: &str) -> bool {
    let history = signet.own_changes.current();
    let Ok(text) = history.encoded() else {
        return false;
    };
    let Ok(left) = HostClient::new(domain.to_owned(), signet.host.scheme) else {
        return false;
    };
    match left.put_history(&text).await {
        Ok(()) => {
            tracing::info!(host = %domain, "told the host this agent left where it is now");
            true
        }
        Err(error) if error.try_later() || matches!(error, HostError::TooMany) => false,
        Err(error) => {
            tracing::warn!(%error, host = %domain, "the host this agent left won't take its history");
            true
        }
    }
}

/// Gives the new host back every pair agreed by invite that the owner's rules don't name, in calls of
/// a bounded size. Says whether the day's count left any out.
async fn give_back_pairs(signet: &Signet) -> Result<bool, HostError> {
    let pairs: Vec<PendingContact> = signet
        .rules
        .agreed_pairs()
        .await
        .into_iter()
        .map(|(_, pair)| pair.record)
        .collect();
    let who = signet.who();
    let mut full = false;
    for some in pairs.chunks(MOST_AGREED_IN_ONE_CALL) {
        full = signet
            .host
            .put_agreed(&signet.key, who.identity.id(), some.to_vec())
            .await?
            || full;
    }
    Ok(full)
}

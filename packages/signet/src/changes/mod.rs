//! Telling contacts when this agent's owner, key, Signet or host changes, and hearing when theirs do.
//!
//! This runs by itself, beside whatever the agent is doing. An agent has no call that writes a history,
//! holds back a notice or lifts a hold, so a fooled one can't change what its contacts hear or what
//! its owner decided.
//!
//! The history is worked out from who this agent is now, so a crash halfway through a change is put
//! right on the next pass. Only what an owner says about something Splint can't see has to be told.

mod left;
mod own;
mod seen;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::middleware;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splint_core::changes::{VerifiedAcceptance, VerifiedChange, VerifiedHistory, notice_in};
use splint_core::contact_view::{Heard, Standing};
use splint_core::{
    DEFAULT_MESSAGE_LIFETIME_SECS, Error, Identity, SplintId, VerifiedBinding, VerifiedEnvelope,
    VerifiedRelease, parse_address, sign_envelope, unix_now,
};

pub use left::{follow_up_a_move, moved_from};
pub use own::Own;
pub use seen::Seen;

use crate::Signet;
use crate::agent_api::ApiError;
use crate::host_client::HostError;
use crate::requests::owner_api::require_owner_token;
use crate::rules;
use crate::who::Who;

/// Owners named in a filter rarely recover, so this needn't ask its host on every pass.
const PASSES_BETWEEN_ASKING_FOR_OWNERS: u32 = 30;
/// About every 30 seconds. The host enforces new rules from the moment it has them, so this is only how
/// soon Signet agrees, and a call for every Signet every pass is what a host's limit is measured in.
const PASSES_BETWEEN_ASKING_FOR_RULES: u32 = 15;

pub async fn run(signet: Arc<Signet>, every: Duration) {
    let mut passes = 0_u32;
    loop {
        // A host that hasn't taken this agent back has nothing to say to it yet.
        signet.registered.until_settled().await;
        if !signet.recovering()
            && let Err(error) = pass(&signet, passes).await
        {
            tracing::debug!(%error, "couldn't finish telling and asking about changes");
        }
        passes = passes.wrapping_add(1);
        tokio::time::sleep(every).await;
    }
}

/// Each part runs whatever another met. Once a contact's host was down long enough to fill what this
/// agent may queue for them, our host refused each notice of a change, and that ended every pass
/// before the owner's new rules were read.
async fn pass(signet: &Signet, passes: u32) -> Result<(), HostError> {
    let told = tell_about_changes(signet).await;
    let owners = if passes.is_multiple_of(PASSES_BETWEEN_ASKING_FOR_OWNERS) {
        take_listed_owners(signet).await
    } else {
        Ok(())
    };
    let rules = if passes.is_multiple_of(PASSES_BETWEEN_ASKING_FOR_RULES) {
        rules::catch_up_with_host(signet).await
    } else {
        Ok(())
    };
    let contacts = catch_up_on_contacts(signet).await;
    if passes.is_multiple_of(PASSES_BETWEEN_ASKING_FOR_RULES) {
        left::catch_up(signet).await;
    }
    told.and(owners).and(rules).and(contacts)
}

async fn tell_about_changes(signet: &Signet) -> Result<(), HostError> {
    // An owner's call can be adding to the history right now. Two adding at once would race to save it,
    // refusing the owner's call, and could sign two versions of one entry, which reads as a rewrite.
    {
        let _changing = signet.changing_who.lock().await;
        bring_up_to_date(signet).await?;
    }
    publish(signet).await
}

/// Adds to this agent's history whatever has changed about who it is. Asking again changes nothing.
pub async fn bring_up_to_date(signet: &Signet) -> Result<(), HostError> {
    let who = signet.who();
    if signet.recovering() {
        return Ok(());
    }
    restore_if_lost(signet, &who).await;
    let held = signet.own_changes.current();
    let now = unix_now();
    let keys = held.record_keys(&signet.key, &who.identity, &who.owner, now);
    let next = keys.and_then(|next| match bound_now(signet, &who) {
        Some(binding) => next.record_binding(&signet.key, &who.identity, &who.owner, &binding, now),
        None => Ok(next),
    });
    match next {
        Ok(next) if next.head() != held.head() => {
            tracing::warn!(agent = %who.identity.id(), "this agent's history has a new entry");
            signet.own_changes.replace(next)
        }
        Ok(_) => Ok(()),
        Err(error) => {
            tracing::warn!(%error, "couldn't add to this agent's history");
            Ok(())
        }
    }
}

fn bound_now(signet: &Signet, who: &Who) -> Option<VerifiedBinding> {
    if who.binding.is_empty() {
        return None;
    }
    VerifiedBinding::verify_for(&who.binding, &who.owner, &who.identity, &signet.address()).ok()
}

/// A Signet that's lost its folder takes up its ID again with nothing behind it, and starting a new
/// history would look to every contact like a rewrite. So it asks its host, whose copy checks out or
/// doesn't. A host that keeps it back can only cause a hold, which an owner can see and settle.
async fn restore_if_lost(signet: &Signet, who: &Who) {
    if !signet.own_changes.current().is_empty() || who.binding.is_empty() {
        return;
    }
    let address = signet.address();
    let Ok((handle, domain)) = parse_address(&address) else {
        return;
    };
    let Ok(text) = signet.lookup(who).history(handle, domain).await else {
        return;
    };
    match VerifiedHistory::read(&text) {
        Ok(history) if history.id() == who.identity.id() => {
            if signet.own_changes.restored_from_host(history).is_err() {
                tracing::warn!("couldn't save this agent's history");
            }
        }
        _ => {}
    }
}

/// Gives this agent's host its history, then every contact who hasn't heard. Anyone who joined since
/// the newest change has nothing to hear. Someone a setting let in isn't a contact: an open business
/// could have thousands, and they hear from its next message. It stops at a host that's down or at a
/// limit, and goes on next time from where it stopped.
pub async fn publish(signet: &Signet) -> Result<(), HostError> {
    let history = signet.own_changes.current();
    if history.is_empty() {
        return Ok(());
    }
    let head = history.head();
    if !signet.own_changes.host_has(&head) {
        match signet.host.put_history(&history.encoded()?).await {
            Ok(()) => signet.own_changes.host_took(&head),
            Err(HostError::NotFound) => return Ok(()),
            Err(error) if error.try_later() => return Err(error),
            // A host that won't take it doesn't get to decide who hears.
            Err(error) => tracing::warn!(%error, "our host wouldn't take this agent's history"),
        }
    }
    signet
        .own_changes
        .note_listeners(&signet.rules.contacts_by_name().await, &head)?;
    let who = signet.who();
    for (agent, address) in signet.own_changes.not_yet_told(&head) {
        let (_, domain) = parse_address(&address)?;
        let notice = sign_envelope(
            &signet.key,
            &who.identity,
            &agent,
            splint_core::changes::notice_body(&history.document())?,
            unix_now(),
            DEFAULT_MESSAGE_LIFETIME_SECS,
        )?;
        match signet.host.send(&notice.compact, domain).await {
            Ok(()) => {
                tracing::info!(message_id = %notice.id, recipient = %agent, "told a contact of a change");
                signet.own_changes.told(&agent, &head)?;
            }
            Err(error) if error.try_later() || matches!(error, HostError::TooMany) => {
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(%error, recipient = %agent, "a notice wasn't taken, so it'll be tried again");
            }
        }
    }
    Ok(())
}

/// Takes in what this agent's host heard directly about those it goes by: a recovery of an owner the
/// rules' filter names or of a contact, and a contact's owner retiring it. It can show only what backup
/// keys and owners signed, or an older copy, which changes nothing, so a contact's own host carrying on
/// regardless doesn't decide this.
async fn take_listed_owners(signet: &Signet) -> Result<(), HostError> {
    let who = signet.who();
    let mut names = signet.rules.listed_owners().await;
    names.push(who.owner.id().clone());
    names.extend(
        signet
            .rules
            .all_contacts()
            .await
            .into_iter()
            .map(|contact| contact.agent),
    );
    names.extend(signet.seen_changes.stop_owners());
    if names.is_empty() {
        return Ok(());
    }
    let heard = signet
        .host
        .known_owners(&signet.key, who.identity.id())
        .await?;
    for text in heard.identities {
        let Ok(copy) = Identity::from_encoded(&text) else {
            continue;
        };
        if copy.id() == who.owner.id() {
            crate::recovery::hear_of_owner(signet, &copy).await;
        } else if names.contains(copy.id()) {
            signet.contacts.known.learn(&copy)?;
        }
    }
    for stop in heard.stops {
        if Identity::from_encoded(&stop.agent_identity).is_ok_and(|one| names.contains(one.id())) {
            signet
                .seen_changes
                .take_stop(&stop, &signet.contacts.known)?;
        }
    }
    Ok(())
}

/// Asks after any contact with nothing on file yet, so a later change has something to be compared
/// with, or one known to have changed with no history to explain it. This is on its own beat, so a
/// host that hangs holds up nothing else.
async fn catch_up_on_contacts(signet: &Signet) -> Result<(), HostError> {
    let who = signet.who();
    // Nobody's asked about someone let in by reach, so there's nothing to ask their host for.
    for contact in signet.rules.contacts_by_name().await {
        if !signet
            .seen_changes
            .due_for_asking(&contact.agent, &signet.contacts.known)
        {
            continue;
        }
        let Ok((handle, domain)) = parse_address(&contact.address) else {
            continue;
        };
        let lookup = signet.lookup(&who);
        let Ok(text) = lookup.history(handle, domain).await else {
            continue;
        };
        let Ok(history) = VerifiedHistory::read(&text) else {
            continue;
        };
        if history.id() == &contact.agent && !history.is_empty() {
            signet
                .seen_changes
                .take(history, Heard::ByAsking, &signet.contacts.known)?;
        }
    }
    Ok(())
}

/// Takes a notice, in the same place a step is taken, so no agent's call can clear or see one. Only
/// someone this agent deals with gets written down, so nobody else can fill this.
pub async fn take_notice(signet: &Signet, envelope: &VerifiedEnvelope) -> Result<(), HostError> {
    let Some(document) = notice_in(envelope.body()) else {
        return Ok(());
    };
    let Ok(history) = VerifiedHistory::verify(document) else {
        tracing::warn!(message_id = %envelope.id(), "refused a notice that doesn't check out");
        return Ok(());
    };
    if history.id() != envelope.sender() {
        tracing::warn!(message_id = %envelope.id(), "refused a notice about someone else");
        return Ok(());
    }
    let sender = envelope.sender();
    let deals_with = signet.rules.all_contact_of(sender).await.is_some()
        || signet.rules.has_reached(sender).await;
    if !deals_with {
        return Ok(());
    }
    signet
        .seen_changes
        .take(history.clone(), Heard::ByNotice, &signet.contacts.known)?;
    signet.rules.note_who_they_act_for(&history).await
}

pub fn routes(signet: Arc<Signet>) -> Router<Arc<Signet>> {
    Router::new()
        .route("/v0/owner/changes", get(changes_view))
        .route_layer(middleware::from_fn_with_state(signet, require_owner_token))
        .route("/v0/owner/change", put(take_statement))
        .route("/v0/owner/revocation", put(take_revocation))
        .route("/v0/owner/changes/accept", post(take_acceptance))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementBody {
    statement: String,
}

#[derive(Serialize)]
struct Recorded {
    head: String,
}

/// An owner's word about where this agent's Signet runs, or something Splint can't see. It's authorized
/// by the owner's signature and goes in under this Signet's key, so it takes both.
async fn take_statement(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<StatementBody>,
) -> Result<Json<Recorded>, ApiError> {
    if signet.recovering() {
        return Err(ApiError::Stopped);
    }
    let _changing = signet.changing_who.lock().await;
    bring_up_to_date(&signet).await?;
    let who = signet.who();
    let next = signet
        .own_changes
        .current()
        .record_statement(
            &signet.key,
            &who.identity,
            &who.owner,
            &body.statement,
            unix_now(),
        )
        .map_err(ApiError::IdentityRefused)?;
    let head = next.head();
    signet.own_changes.replace(next)?;
    publish_now(&signet).await;
    Ok(Json(Recorded { head }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationBody {
    revocation: String,
}

/// An owner's word that this agent acts for nobody until they sign again. Contacts hear first, because
/// a host then won't take anything more from it. An owner who can't reach a Signet they no longer trust
/// can go to the host directly, and then its contacts aren't told.
async fn take_revocation(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<RevocationBody>,
) -> Result<Json<Recorded>, ApiError> {
    if signet.recovering() {
        return Err(ApiError::Stopped);
    }
    crate::recovery::hear_of_new_keys(&signet, &body.revocation).await;
    let _changing = signet.changing_who.lock().await;
    bring_up_to_date(&signet).await?;
    let who = signet.who();
    let release = VerifiedRelease::verify(&body.revocation, &who.owner, who.identity.id())
        .map_err(ApiError::IdentityRefused)?;
    if release.to().is_some() {
        return Err(ApiError::IdentityRefused(Error::ProofMismatch));
    }
    let next = signet
        .own_changes
        .current()
        .record_revocation(&signet.key, &who.identity, &who.owner, &release, unix_now())
        .map_err(ApiError::IdentityRefused)?;
    let head = next.head();
    signet.own_changes.replace(next)?;
    signet.replace_who(Who {
        identity: who.identity.clone(),
        owner: who.owner.clone(),
        binding: String::new(),
    })?;
    publish_now(&signet).await;
    signet.host.revoke(&body.revocation).await?;
    signet.registered.lost_its_binding();
    Ok(Json(Recorded { head }))
}

/// Tries at once, so a contact needn't wait for the next pass. A host that's down leaves it to that pass.
pub async fn publish_now(signet: &Signet) {
    if let Err(error) = publish(signet).await {
        tracing::debug!(%error, "couldn't tell everyone yet");
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceBody {
    pub acceptance: String,
}

#[derive(Serialize)]
pub struct Accepted {
    contact: SplintId,
    head: String,
}

/// An owner's yes to one contact's history, as far as one exact head. Only their signature counts, so
/// a fooled agent, which can reach this, can't lift a hold.
pub async fn take_acceptance(
    State(signet): State<Arc<Signet>>,
    Json(body): Json<AcceptanceBody>,
) -> Result<Json<Accepted>, ApiError> {
    crate::recovery::hear_of_new_keys(&signet, &body.acceptance).await;
    let who = signet.who();
    let acceptance = VerifiedAcceptance::verify(&body.acceptance, &who.owner, who.identity.id())
        .map_err(ApiError::IdentityRefused)?;
    // The host hears first, because it would hold what goes to this contact while this Signet didn't.
    let histories = signet.seen_changes.histories_of(acceptance.contact());
    match signet
        .host
        .put_acceptance(&body.acceptance, histories)
        .await
    {
        Err(error) if error.try_later() => return Err(ApiError::Host(error)),
        Err(error) => tracing::warn!(%error, "our host wouldn't take the owner's word on a change"),
        Ok(()) => {}
    }
    signet
        .seen_changes
        .accept(&acceptance, &signet.contacts.known)
        .map_err(ApiError::IdentityRefused)?;
    signet.owner_signed.note(&body.acceptance).await;
    tracing::warn!(contact = %acceptance.contact(), "the owner accepted a contact's changes");
    Ok(Json(Accepted {
        contact: acceptance.contact().clone(),
        head: acceptance.head().to_owned(),
    }))
}

/// One contact's changes as an owner sees them. A claim is the other owner's words, and no agent sees
/// this.
#[derive(Serialize)]
pub(crate) struct ChangeView {
    contact: SplintId,
    label: String,
    address: String,
    standing: Standing,
    /// What an acceptance has to name.
    head: String,
    /// The history that parts ways from the one held, if one has arrived, and its head.
    #[serde(skip_serializing_if = "Option::is_none")]
    rewritten_head: Option<String>,
    since_accepted: Vec<VerifiedChange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rewritten_since: Vec<VerifiedChange>,
    /// The signed histories themselves, so a device this isn't beside can check what it's shown.
    history: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rewritten_history: Option<String>,
}

#[derive(Serialize)]
pub struct ChangesPage {
    pub(crate) changes: Vec<ChangeView>,
}

async fn changes_view(State(signet): State<Arc<Signet>>) -> Json<ChangesPage> {
    Json(changes_page(&signet).await)
}

pub async fn changes_page(signet: &Signet) -> ChangesPage {
    let mut changes = Vec::new();
    for contact in signet.rules.all_contacts().await {
        let Some(on_file) = signet.seen_changes.on_file(&contact.agent) else {
            continue;
        };
        let standing = signet.rules.standing_of(&contact.agent).await;
        // A revoked contact is stopped by itself, and nobody here can lift it, so it's no card.
        let stopped_by_their_owner = standing == Standing::Stopped && on_file.revoked;
        if (standing == Standing::Continue && on_file.since_accepted.is_empty())
            || stopped_by_their_owner
        {
            continue;
        }
        changes.push(ChangeView {
            contact: contact.agent,
            label: contact.label,
            address: contact.address,
            standing,
            head: on_file.head,
            rewritten_head: on_file.rewritten_head,
            since_accepted: on_file.since_accepted,
            rewritten_since: on_file.rewritten_since,
            history: on_file.history,
            rewritten_history: on_file.rewritten_history,
        });
    }
    ChangesPage { changes }
}

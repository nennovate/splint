//! A host's own copy of what each of its agents has seen of its contacts' histories, so a stolen agent
//! key calling this host directly, past Signet, is held to what an honest Signet holds its agent to:
//! nothing goes to a contact while a change to them waits on the owner's word.
//!
//! It runs the same core logic as Signet, on the same things, because everything a Signet learns about
//! a contact comes through its host. It's an extra check, since a Signet doesn't rest on it, and this
//! host's own operator can always ignore it. So it protects an owner against a stolen key, not against
//! a host they chose badly. Nothing goes through here on the way in, because Signet checks that side.
//!
//! An owner's word reaches it signed, through their Signet or from anyone, so it can't be forged here.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::put;
use axum::{Json, Router};
use splint_core::changes::{VerifiedAcceptance, VerifiedHistory, claimed_accepting_agent};
use splint_core::contact_view::{ContactView, Copies, Heard, SavedView, Standing, Taken};
use splint_core::host_api::AcceptanceNotice;
use splint_core::rules::VerifiedRules;
use splint_core::{Error, Identity, SplintId, VerifiedBinding, unix_now};
use sqlx::Row;

use crate::admission::SenderRecord;
use crate::api_error::ApiError;
use crate::{Host, changes};

pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS contact_views (
        agent TEXT NOT NULL,
        contact TEXT NOT NULL,
        view TEXT NOT NULL,
        shown_agent_recoveries INTEGER NOT NULL,
        shown_owner TEXT NOT NULL,
        shown_owner_recoveries INTEGER NOT NULL,
        pending BOOLEAN NOT NULL,
        PRIMARY KEY (agent, contact)
    );
";

const ACCEPTED_PATH: &str = "/v0/changes/accepted";

pub fn routes() -> Router<Arc<Host>> {
    Router::new().route(ACCEPTED_PATH, put(take_acceptance))
}

/// The copies this host holds of the IDs a view goes by.
struct HostCopies(HashMap<String, Identity>);

impl HostCopies {
    async fn of(host: &Host, ids: &[SplintId]) -> Result<Self, ApiError> {
        let names: Vec<&str> = ids.iter().map(SplintId::as_str).collect();
        let held: Vec<String> =
            sqlx::query_scalar("SELECT identity FROM known_owners WHERE id = ANY($1)")
                .bind(&names)
                .fetch_all(&host.db)
                .await?;
        let copies = held
            .iter()
            .filter_map(|text| Identity::from_encoded(text).ok())
            .map(|copy| (copy.id().as_str().to_owned(), copy))
            .collect();
        Ok(Self(copies))
    }

    fn is_forked(&self, identity: &Identity) -> bool {
        self.0
            .get(identity.id().as_str())
            .is_some_and(|held| held.newest_of(identity).is_err())
    }

    fn learn(&mut self, identity: &Identity) {
        if identity.statements() > 0 && !self.is_forked(identity) {
            let newest = self.newest_or_same(identity);
            self.0.insert(identity.id().as_str().to_owned(), newest);
        }
    }
}

impl Copies for HostCopies {
    fn recoveries_of(&self, id: &SplintId) -> usize {
        self.0.get(id.as_str()).map_or(0, Identity::recoveries)
    }

    /// Of a copy that parts ways with the one held, the one held stands.
    fn newest_or_same(&self, identity: &Identity) -> Identity {
        match self.0.get(identity.id().as_str()) {
            Some(held) => held.newest_of(identity).unwrap_or_else(|_| held.clone()),
            None => identity.clone(),
        }
    }

    fn held_copy(&self, id: &SplintId) -> Option<Identity> {
        self.0.get(id.as_str()).cloned()
    }
}

async fn view_of(
    host: &Host,
    agent: &SplintId,
    contact: &SplintId,
) -> Result<Option<ContactView>, ApiError> {
    let text: Option<String> =
        sqlx::query_scalar("SELECT view FROM contact_views WHERE agent = $1 AND contact = $2")
            .bind(agent.as_str())
            .bind(contact.as_str())
            .fetch_optional(&host.db)
            .await?;
    let Some(text) = text else {
        return Ok(None);
    };
    let saved: SavedView = serde_json::from_str(&text).map_err(|_| Error::Malformed)?;
    Ok(ContactView::load(&saved))
}

/// What the last message showed, which spares reading a view for every message that shows the same.
#[derive(Default)]
struct Shown {
    agent_recoveries: i32,
    owner: String,
    owner_recoveries: i32,
}

fn as_sql_count(count: usize) -> i32 {
    i32::try_from(count).unwrap_or(i32::MAX)
}

async fn save(
    host: &Host,
    agent: &SplintId,
    contact: &SplintId,
    view: &ContactView,
    copies: &HostCopies,
    shown: Option<&Shown>,
) -> Result<(), ApiError> {
    let text = serde_json::to_string(&view.saved()?).map_err(|_| Error::Malformed)?;
    let none = Shown::default();
    sqlx::query(
        "INSERT INTO contact_views (agent, contact, view, shown_agent_recoveries, shown_owner,
             shown_owner_recoveries, pending)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (agent, contact) DO UPDATE SET view = $3, pending = $7,
             shown_agent_recoveries = CASE WHEN $8 THEN $4
                 ELSE contact_views.shown_agent_recoveries END,
             shown_owner = CASE WHEN $8 THEN $5 ELSE contact_views.shown_owner END,
             shown_owner_recoveries = CASE WHEN $8 THEN $6
                 ELSE contact_views.shown_owner_recoveries END",
    )
    .bind(agent.as_str())
    .bind(contact.as_str())
    .bind(text)
    .bind(shown.unwrap_or(&none).agent_recoveries)
    .bind(&shown.unwrap_or(&none).owner)
    .bind(shown.unwrap_or(&none).owner_recoveries)
    .bind(view.could_hold(copies))
    .bind(shown.is_some())
    .execute(&host.db)
    .await?;
    Ok(())
}

/// Writes down what a message from a contact shows, as their Signet would. It comes before a contact is
/// let in, so what's noted stands whatever is decided about the message.
pub async fn note_arrival(
    host: &Host,
    recipient: &SplintId,
    sender: &Identity,
    record: &SenderRecord,
) -> Result<(), ApiError> {
    let owner = Identity::from_encoded(&record.owner_identity).ok();
    let binding = owner
        .as_ref()
        .and_then(|owner| VerifiedBinding::verify(&record.binding, owner, sender).ok());
    let shown = owner.as_ref().zip(binding.as_ref());
    let now_shown = Shown {
        agent_recoveries: as_sql_count(sender.recoveries()),
        owner: shown.map_or_else(String::new, |(owner, _)| owner.id().as_str().to_owned()),
        owner_recoveries: shown.map_or(0, |(owner, _)| as_sql_count(owner.recoveries())),
    };
    let row = sqlx::query(
        "SELECT shown_agent_recoveries, shown_owner, shown_owner_recoveries FROM contact_views
         WHERE agent = $1 AND contact = $2",
    )
    .bind(recipient.as_str())
    .bind(sender.id().as_str())
    .fetch_optional(&host.db)
    .await?;
    if let Some(row) = &row
        && row.try_get::<i32, _>("shown_agent_recoveries")? == now_shown.agent_recoveries
        && row.try_get::<String, _>("shown_owner")? == now_shown.owner
        && row.try_get::<i32, _>("shown_owner_recoveries")? == now_shown.owner_recoveries
    {
        return Ok(());
    }
    let mut view = view_of(host, recipient, sender.id())
        .await?
        .unwrap_or_else(|| ContactView::from_identity(sender));
    let mut ids = view.ids();
    ids.extend(owner.iter().map(|owner| owner.id().clone()));
    let mut copies = HostCopies::of(host, &ids).await?;
    if copies.is_forked(sender) {
        view.mark_forked(sender);
    }
    let agent = copies.newest_or_same(sender);
    // A copy of the owner that parts ways with the one held is read as the one held, so what only the
    // other branch's keys signed doesn't count here.
    let owner = owner.map(|owner| copies.newest_or_same(&owner));
    let binding = owner
        .as_ref()
        .and_then(|owner| VerifiedBinding::verify(&record.binding, owner, sender).ok());
    let shown = owner.as_ref().zip(binding.as_ref());
    view.note_shown(&agent, shown, &copies, unix_now());
    copies.learn(sender);
    changes::learn_listed_owner(host, sender).await?;
    if let Some((owner, _)) = shown.filter(|(owner, _)| view.first_owner_is(owner)) {
        let held = copies.held_copy(owner.id());
        copies.learn(owner);
        let newest = copies.newest_or_same(owner);
        crate::owner_keys::keep_if_newer(host, held.as_ref(), &newest).await?;
    }
    save(
        host,
        recipient,
        sender.id(),
        &view,
        &copies,
        Some(&now_shown),
    )
    .await
}

/// What a history comes to against the view held, measured against the copies held before anything is
/// learned from it. The last part says whether an owner in it parts ways with the copy held.
fn taken_into(
    view: Option<ContactView>,
    history: &VerifiedHistory,
    heard: Heard,
    copies: &HostCopies,
    now: u64,
) -> (ContactView, Taken, bool) {
    let (mut view, taken) = match view {
        Some(mut view) => {
            let taken = view.take(history.clone(), now);
            (view, taken)
        }
        None => (
            ContactView::from_history(history.clone(), heard, now),
            Taken::Followed,
        ),
    };
    let parted = view.note_parted_owners(history, copies);
    (view, taken, parted)
}

/// Takes a contact's history that came through here, by a notice or an answer to its Signet's asking.
pub async fn take_history(
    host: &Host,
    agent: &SplintId,
    history: VerifiedHistory,
    heard: Heard,
) -> Result<(), ApiError> {
    let contact = history.id().clone();
    let view = view_of(host, agent, &contact).await?;
    let mut ids = view.as_ref().map_or_else(Vec::new, ContactView::ids);
    ids.push(contact.clone());
    ids.extend(history.owners().iter().map(|owner| owner.id().clone()));
    let mut copies = HostCopies::of(host, &ids).await?;
    let (view, taken, parted) = taken_into(view, &history, heard, &copies, unix_now());
    if taken == Taken::Unchanged && !parted {
        return Ok(());
    }
    if taken == Taken::Followed {
        copies.learn(history.identity());
        for owner in history.owners() {
            let held = copies.held_copy(owner.id());
            copies.learn(owner);
            let newest = copies.newest_or_same(owner);
            crate::owner_keys::keep_if_newer(host, held.as_ref(), &newest).await?;
        }
        changes::learn_listed_owner(host, history.identity()).await?;
    }
    save(host, agent, &contact, &view, &copies, None).await
}

/// Whether a change to this contact waits on this agent's owner's word. A contact with nothing that
/// could hold them costs one row's look.
pub async fn is_held(
    host: &Host,
    rules: &VerifiedRules,
    agent: &SplintId,
    contact: &SplintId,
) -> Result<bool, ApiError> {
    let text: Option<String> = sqlx::query_scalar(
        "SELECT view FROM contact_views WHERE agent = $1 AND contact = $2 AND pending",
    )
    .bind(agent.as_str())
    .bind(contact.as_str())
    .fetch_optional(&host.db)
    .await?;
    let Some(text) = text else {
        return Ok(false);
    };
    let saved: SavedView = serde_json::from_str(&text).map_err(|_| Error::Malformed)?;
    let Some(view) = ContactView::load(&saved) else {
        return Ok(false);
    };
    let copies = HostCopies::of(host, &view.ids()).await?;
    Ok(view.standing(rules.changes(), &copies) != Standing::Continue)
}

/// Takes an owner's yes to a contact's history, from their Signet or anyone else, since their signature
/// is what counts. It comes with the histories it could name, so what this host had or hadn't heard
/// doesn't stop it counting here.
async fn take_acceptance(
    State(host): State<Arc<Host>>,
    Json(notice): Json<AcceptanceNotice>,
) -> Result<(), ApiError> {
    let agent = claimed_accepting_agent(&notice.acceptance)?;
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_identity FROM agents WHERE id = $1")
            .bind(agent.as_str())
            .fetch_optional(&host.db)
            .await?;
    let owner = Identity::from_encoded(&owner.ok_or(ApiError::NotFound)?)?;
    let acceptance = VerifiedAcceptance::verify(&notice.acceptance, &owner, &agent)?;
    let contact = acceptance.contact().clone();
    let mut view = view_of(&host, &agent, &contact).await?;
    for text in &notice.histories {
        let history = VerifiedHistory::read(text)?;
        if history.id() != &contact {
            return Err(ApiError::Malformed(Error::ProofMismatch));
        }
        match &mut view {
            Some(view) => {
                view.take(history, unix_now());
            }
            None => {
                view = Some(ContactView::from_history(
                    history,
                    Heard::ByNotice,
                    unix_now(),
                ))
            }
        }
    }
    let mut view = view.ok_or(ApiError::NotFound)?;
    let mut chosen = None;
    let before = HostCopies::of(&host, &view.ids()).await?;
    view.accept(&acceptance, &before, |history| {
        chosen = Some(history.clone());
        Ok(())
    })?;
    if let Some(history) = &chosen {
        for copy in std::iter::once(history.identity()).chain(history.owners()) {
            let held = HostCopies::of(&host, std::slice::from_ref(copy.id()))
                .await?
                .held_copy(copy.id());
            crate::owner_keys::keep_if_newer(&host, held.as_ref(), copy).await?;
        }
    }
    let copies = HostCopies::of(&host, &view.ids()).await?;
    save(&host, &agent, &contact, &view, &copies, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use splint_core::{RecoveryRule, SealingKey, SigningKey};

    /// The bug: a contact's binding was checked under their owner's copy as shown, so a removed key's
    /// own branch, from before its removal, counted here.
    #[test]
    fn a_copy_that_parts_ways_is_read_as_the_one_held() {
        let (first, laptop, phone) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        let owner = Identity::create(
            &first,
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        )
        .unwrap();
        let held = owner.add_key(&first, &laptop, 1).unwrap();
        let first_name = held.keys()[0].name();
        let held = held.remove_key(&laptop, &first_name, 1).unwrap();
        let mut copies = HostCopies(HashMap::new());
        copies.learn(&held);
        let branch = owner.add_key(&first, &phone, 1).unwrap();
        assert_eq!(copies.newest_or_same(&branch).encoded(), held.encoded());
    }

    /// The bug: a rival recovery of a contact's owner read as that owner recovering, so an agent's
    /// stolen key could go on sending to whoever made the rival, past this host's own check.
    #[test]
    fn a_rival_recovery_of_a_contacts_owner_is_held_and_the_real_one_is_not() {
        const NOW: u64 = 1_800_000_000;
        let new_seal = || SealingKey::generate().unwrap().public_key();
        let new_rule = || RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key());
        let (agent_key, agent_backup) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        let agent = Identity::create(
            &agent_key,
            &new_seal(),
            RecoveryRule::backup_key(&agent_backup.public_key()),
        )
        .unwrap();
        let (owner_key, owner_backup) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        let owner = Identity::create(
            &owner_key,
            &new_seal(),
            RecoveryRule::backup_key(&owner_backup.public_key()),
        )
        .unwrap();
        let recovered = || {
            let key = SigningKey::generate().unwrap().public_key();
            owner
                .recover(&owner_backup, &key, &new_seal(), new_rule(), NOW)
                .unwrap()
        };
        let (real, rival) = (recovered(), recovered());
        let half = VerifiedBinding::sign(
            &owner_key,
            &agent_backup,
            owner.id(),
            &agent,
            "ana~host.example",
            1,
            NOW,
        )
        .unwrap();
        let binding = VerifiedBinding::accept(&agent_key, &half, None, &owner, &agent).unwrap();
        let started = VerifiedHistory::empty(&agent)
            .record_binding(&agent_key, &agent, &owner, &binding, NOW)
            .unwrap();
        let rules = splint_core::changes::ChangeRules {
            key: splint_core::changes::ChangeResponse::Continue,
            ..Default::default()
        };
        let mut copies = HostCopies(HashMap::new());
        copies.learn(&real);
        let held = ContactView::from_history(started.clone(), Heard::ByAsking, NOW);

        let next = started.record_keys(&agent_key, &agent, &real, NOW).unwrap();
        let (view, _, parted) =
            taken_into(Some(held.clone()), &next, Heard::ByNotice, &copies, NOW);
        assert!(!parted);
        assert_eq!(view.standing(&rules, &copies), Standing::Continue);

        let next = started
            .record_keys(&agent_key, &agent, &rival, NOW)
            .unwrap();
        let (view, _, parted) = taken_into(Some(held), &next, Heard::ByNotice, &copies, NOW);
        assert!(parted);
        assert_eq!(view.standing(&rules, &copies), Standing::Rewritten);
        assert!(view.could_hold(&copies), "or the check at sending skips it");
    }
}

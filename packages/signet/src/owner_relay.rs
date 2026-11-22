//! For an owner whose device isn't beside this Signet. It can't call in, so this leaves what the owner's
//! device reads at this agent's host, sealed to the owner, and takes what the owner signed from there,
//! which their device sealed to this agent, through the same calls as an owner beside it. Every one of
//! those is authorized by the owner's signature alone: what the host let in, and that it opened here,
//! say nothing of who signed what's inside.
//!
//! No agent can read or change what goes by here, except by holding this Signet's key. Then it can
//! withhold or lie about what's shown, as a Signet can, and the owner's device checks what's signed.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use splint_core::host_api::{
    MAX_OWNER_VIEW_BYTES, OwnerMail, OwnerMailKind, OwnerView, owner_mail_item, owner_view_about,
};
use splint_core::owner_view::{MAX_SIGNED_VIEW_BYTES, sign_owner_view};
use splint_core::{Identity, SigningKey, SplintId, seal_note, unix_now};
use tokio::sync::{Mutex, Notify};

use crate::Signet;
use crate::activity::Kind;
use crate::agent_api::ApiError;
use crate::changes::{AcceptanceBody, changes_page, take_acceptance};
use crate::delegation::{self, Shown};
use crate::ending::{Done, open_owner_mail};
use crate::host_client::HostError;
use crate::requests::owner_api::{DecideBody, decide, drafts_of, signed_requests};
use crate::requests::person_text::{HoldBody, hold, waiting_list};
use crate::rules::held_page;
use crate::state_file::{self, StateError};

/// What each part beside the requests can take of a view, before it's signed. Signing writes it out in
/// base64, a third more, and the owner's device verifies no more than `MAX_SIGNED_VIEW_BYTES` of that,
/// which is less than a host takes sealed. So a contact with a long history, or many senders waiting,
/// can't push out the requests waiting on the owner, and the four of them leave half of what can be
/// signed for the rest, however full each is.
const MAX_PART_BYTES: usize = MAX_SIGNED_VIEW_BYTES / 4 * 3 / 8;
const VIEW_EVERY: Duration = Duration::from_secs(10);
/// So an owner's device can tell this Signet is still there when nothing has changed.
const VIEW_AT_LEAST_EVERY: Duration = Duration::from_secs(5 * 60);

/// How long something the owner signed is remembered as taken: longer than a host keeps one for this
/// Signet, than an owner's device goes on sending one to that host, and than an answer lasts.
const REMEMBER_TAKEN_SECS: u64 = 15 * 24 * 60 * 60;

/// What the owner signed that this Signet has taken, by the hash of what they signed. An owner's device
/// that reaches this Signet straight leaves the same thing at its host as well, as whatever answered it
/// could be anyone, and what an owner signs goes out inside steps, so a contact or a fooled agent can
/// hand it back. So the same thing comes again, and is taken once: a copy does nothing, whichever way
/// it comes. Only something whose owner's signature checked and that was taken is remembered, so
/// nobody else can add to this or keep anything out with it.
pub struct TakenOnce {
    path: PathBuf,
    /// The hash of what was signed, to when it was taken.
    taken: Mutex<HashMap<String, u64>>,
    /// How many left for this agent didn't open here at the last look. They stay at the host.
    unopened: AtomicUsize,
}

impl TakenOnce {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let taken = Mutex::new(state_file::load(&path)?);
        Ok(Self {
            path,
            taken,
            unopened: AtomicUsize::new(0),
        })
    }

    /// What the owner left that waits at the host unopened, as of the last look.
    pub fn unopened(&self) -> usize {
        self.unopened.load(Ordering::Relaxed)
    }

    /// Whether this was taken here before, however its signature is spelled this time.
    pub async fn has(&self, signed: &str) -> bool {
        let taken = self.taken.lock().await;
        taken
            .get(&owner_mail_item(signed))
            .is_some_and(|at| at.saturating_add(REMEMBER_TAKEN_SECS) >= unix_now())
    }

    /// Remembers something just taken. One that can't be saved is only forgotten by a restart, and a
    /// copy that comes after is then checked as it always was, by what each kind holds.
    pub async fn note(&self, signed: &str) {
        let now = unix_now();
        let mut taken = self.taken.lock().await;
        taken.retain(|_, at| at.saturating_add(REMEMBER_TAKEN_SECS) >= now);
        taken.insert(owner_mail_item(signed), now);
        if state_file::save(&self.path, &taken).is_err() {
            tracing::warn!("couldn't save that something this agent's owner signed was taken");
        }
    }
}

/// Leaves the owner's view when it changes, looking every 10 seconds and whenever the owner's mail
/// was taken. Taking the mail is the sync loop's, which waits on the host and hears when it comes.
pub async fn run(signet: Arc<Signet>, mail_taken: Arc<Notify>) {
    let mut last_view = None;
    let mut last_left = None::<Instant>;
    let mut refused_before = false;
    loop {
        tokio::select! {
            () = tokio::time::sleep(VIEW_EVERY) => {}
            () = mail_taken.notified() => {}
        }
        signet.registered.until_settled().await;
        if signet.recovering() {
            continue;
        }
        let Some(fitted) = view_of(&signet).await else {
            continue;
        };
        let changed = last_view.as_ref() != Some(&fitted.view);
        let stale = last_left.is_none_or(|left| left.elapsed() >= VIEW_AT_LEAST_EVERY);
        if !(changed || stale) {
            continue;
        }
        if changed && fitted.left_out.any() {
            let left_out = &fitted.left_out;
            tracing::warn!(
                requests = left_out.requests,
                changes = left_out.changes,
                words = left_out.words,
                held = left_out.held,
                "left some out of what this agent's owner reads, to fit through its host"
            );
        }
        let who = signet.who();
        match signet
            .host
            .leave_owner_view(&signet.key, who.identity.id(), fitted.sealed)
            .await
        {
            Ok(()) => {
                last_view = Some(fitted.view);
                last_left = Some(Instant::now());
                refused_before = false;
            }
            // Tried again each time round, so once is enough to say so.
            Err(error @ HostError::Refused) if !refused_before => {
                refused_before = true;
                tracing::warn!(%error, "this agent's host refused what its owner reads");
            }
            Err(error) => {
                tracing::debug!(%error, "couldn't leave this agent's owner what they read")
            }
        }
    }
}

/// The view as this Signet would leave it at its host now, for an owner's device that reaches it
/// straight: on this machine, or over a network its operator opted into. It's signed by the agent's key
/// and sealed to the owner, so it needs no token, and an agent or a stranger who asks gets only that.
pub(crate) async fn current_view(
    State(signet): State<Arc<Signet>>,
) -> Result<Json<OwnerView>, ApiError> {
    if signet.recovering() {
        return Err(ApiError::Stopped);
    }
    let fitted = view_of(&signet)
        .await
        .ok_or(ApiError::CouldntReach(NO_VIEW))?;
    Ok(Json(OwnerView {
        view: fitted.sealed,
    }))
}

/// Said when there's no view to give, which the log says more of.
const NO_VIEW: &str = "this agent's Signet couldn't make its owner's view just now";

/// Says whether anything was taken, so the owner's device can see it straight away. Only what opens
/// here and is judged is cleared at the host: what doesn't open was sealed to a key this Signet doesn't
/// hold, as only the owner's own sign-ins can leave it, and what failed for a reason time fixes is
/// tried again on the next look.
pub async fn take_what_the_owner_signed(signet: &Arc<Signet>) -> bool {
    let who = signet.who();
    let me = who.identity.id();
    let mail = match signet.host.owner_mail(&signet.key, me).await {
        Ok(mail) => mail,
        Err(error) => {
            tracing::debug!(%error, "couldn't ask for what this agent's owner signed");
            return false;
        }
    };
    let mut taken = Vec::with_capacity(mail.len());
    let mut unopened = 0_usize;
    for one in &mail {
        match open_owner_mail(signet, one, me) {
            Ok(opened) => {
                let done = Done::taken(&opened);
                if apply(signet, opened.mail).await {
                    taken.push(done);
                }
            }
            Err(_) => unopened = unopened.saturating_add(1),
        }
    }
    signet
        .owner_signed
        .unopened
        .store(unopened, Ordering::Relaxed);
    if unopened > 0 {
        tracing::warn!(
            unopened,
            "something this agent's owner left doesn't open here, so it waits at the host"
        );
    }
    if taken.is_empty() {
        return false;
    }
    if let Err(error) = signet.host.ack_owner_mail(&signet.key, me, &taken).await {
        tracing::debug!(%error, "couldn't tell the host what was taken");
    }
    true
}

/// A refusal that time or a host coming back can lift, which leaves what was signed to be tried again.
fn for_now(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Host(_) | ApiError::CouldntReach(_) | ApiError::TooManyWaits
    )
}

/// What's refused here stays as it was, so it's still there for the owner to see and decide again.
/// Whether it was judged, taken or refused for good, so it can leave the host.
async fn apply(signet: &Arc<Signet>, mail: OwnerMail) -> bool {
    // The copy of something that came straight from the owner's device, which is no refusal.
    if signet.owner_signed.has(&mail.signed).await {
        return true;
    }
    let state = State(signet.clone());
    let refused = match mail.kind {
        OwnerMailKind::Approval => decide(
            state,
            Json(DecideBody {
                approval: mail.signed,
            }),
        )
        .await
        .err(),
        OwnerMailKind::Acceptance => take_acceptance(
            state,
            Json(AcceptanceBody {
                acceptance: mail.signed,
            }),
        )
        .await
        .err(),
        OwnerMailKind::PersonText => hold(
            state,
            Json(HoldBody {
                person_text: mail.signed,
            }),
        )
        .await
        .err(),
        OwnerMailKind::Delegation => delegation::take_at(signet, &mail.signed, unix_now())
            .await
            .err(),
        OwnerMailKind::WherePaid => crate::requests::payments::take(signet, &mail.signed)
            .await
            .err(),
    };
    match refused {
        Some(error) if for_now(&error) => {
            tracing::debug!(kind = ?mail.kind, "something this agent's owner signed waits to be tried again");
            false
        }
        Some(_) => {
            tracing::warn!(kind = ?mail.kind, "refused something this agent's owner signed");
            true
        }
        None => {
            signet.activity.note(Kind::Owner);
            true
        }
    }
}

/// What's beside the requests in a view, written out as `ChangesPage`, `WaitingList` and `HeldPage`
/// are, so an owner's device reads it as an owner beside this Signet reads those.
#[derive(Serialize)]
struct Beside<C, W, H, D> {
    changes: Changes<C>,
    words: Words<W>,
    // The host answers this, so asking it can fail where the rest doesn't.
    held: Option<Vec<H>>,
    /// What waits on the owner, as `GET /v0/owner/approvals` has it, for a device that can't walk the
    /// requests itself, such as a page in a browser. Each is only this Signet's word, and an approval
    /// of other terms than the chain's is refused by every reader.
    drafts: Vec<D>,
    /// The interaction types this Signet holds its agent to, which a page lets a new contact use.
    types: Vec<splint_core::requests::InteractionType>,
    /// The fields of each of those types that hold times, so a page with no schema shows a time as one.
    times: BTreeMap<splint_core::requests::InteractionType, Vec<String>>,
    /// Each of those types' `units`, so a page with no schema shows an amount in its own currency.
    units: BTreeMap<splint_core::requests::InteractionType, BTreeMap<String, String>>,
    /// The schema of each type a draft names, in its one encoding. Only this Signet's word: a device
    /// takes one only where its own fingerprint of it is the type's ID, so it can't be shown a type as
    /// other than the two agents agreed it.
    schemas: Vec<splint_core::requests::Schema>,
    /// This Signet's delegate key and the delegation it holds, as `GET /v0/owner/delegation` has them,
    /// so a page can sign a fresh delegation with new rules. Only this Signet's word, which can cost
    /// its owner a touch, and no reader takes a delegate's yes beyond what the owner signed.
    delegation: Option<Shown>,
    /// What the agent asked its owner to change, each signed by its key, still open. Each is checked
    /// on its own by whoever shows it, so the owner sees an ask that reached them by any route.
    asks: Vec<String>,
    /// Who kept the agent busy today, as `GET /v0/owner/usage` has it, at most 20 lines.
    usage: Vec<crate::arrivals::UsageLine>,
}

#[derive(Serialize)]
struct Changes<C> {
    changes: Vec<C>,
}

#[derive(Serialize)]
struct Words<W> {
    waiting: Vec<W>,
}

/// The same as an owner beside this Signet reads, in one piece, with what doesn't fit through the host
/// left out.
async fn view_of(signet: &Signet) -> Option<Fitted> {
    let changes = changes_page(signet).await.changes;
    let words = waiting_list(signet).await.waiting;
    let held = held_page(signet).await.ok().map(|page| page.held);
    let drafts = drafts_of(signet).await;
    // Every type agreed with anyone, once each, and the schema of each one a draft names, so a page shows
    // and signs an approval with no file of its own. A page takes a schema only where its own fingerprint
    // of it is the type's ID.
    let mut agreed = BTreeMap::new();
    for (_, with_them) in signet.requests.types.everyone() {
        for one in with_them {
            agreed.insert(one.schema.name().clone(), one.schema);
        }
    }
    let types = agreed.keys().cloned().collect();
    let times = agreed
        .iter()
        .map(|(id, schema)| (id.clone(), schema.time_fields()))
        .collect();
    let units = agreed
        .iter()
        .map(|(id, schema)| {
            let units = schema
                .values()
                .filter_map(|value| Some((value.to_owned(), schema.unit_of(value)?.to_owned())))
                .collect();
            (id.clone(), units)
        })
        .collect();
    let now = unix_now();
    let asks = crate::asks::Asks::waiting(signet, now).await;
    let mut schemas = BTreeMap::new();
    for draft in &drafts {
        if let Some(schema) = signet.requests.types.schema_of(draft) {
            schemas.insert(schema.name().clone(), schema.as_ref().clone());
        }
    }
    // And of each type an ask waiting names, so the owner's side shows what it holds before they
    // approve it, as a kind with money needs (Nenye, 2026-11-15).
    for ask in &asks {
        let Ok(changes) = splint_core::asks::payload_changes(ask) else {
            continue;
        };
        for named in splint_core::asks::types_named(&changes) {
            if let Some(schema) = agreed.get(named) {
                schemas.insert(named.clone(), schema.as_ref().clone());
            }
        }
    }
    let schemas = schemas.into_values().collect();
    let delegation = delegation::shown_at(signet, now).await;
    let who = signet.who();
    let about = owner_view_about(who.identity.id());
    // Signed by this agent's key, as anyone can seal to an owner, and sealed to the owner's device, as
    // it carries what's sealed between agents, opened.
    let seal = |view: &[u8]| {
        signed_and_sealed(
            &signet.key,
            who.identity.id(),
            &who.owner,
            &about,
            view,
            now,
        )
    };
    let requests_within = |budget| async move {
        let requests = signed_requests(signet, budget).await;
        let left_out = requests.left_out();
        (requests, left_out)
    };
    match fit_view(
        changes,
        words,
        held,
        drafts,
        About {
            asks,
            types,
            times,
            units,
            schemas,
            delegation: Some(delegation),
            usage: crate::arrivals::usage(signet).await,
        },
        requests_within,
        seal,
    )
    .await
    {
        Ok(fitted) => Some(fitted),
        Err(Unfit::CantSeal) => {
            tracing::warn!("couldn't seal what this agent's owner reads");
            None
        }
        Err(Unfit::TooBig) => {
            tracing::warn!(
                "what this agent's owner reads doesn't fit through its host, even with no requests"
            );
            None
        }
    }
}

struct Fitted {
    view: String,
    sealed: String,
    left_out: LeftOut,
}

/// How many of each were left out of a view to fit it, which is all that's said about them.
struct LeftOut {
    requests: usize,
    changes: usize,
    words: usize,
    held: usize,
    drafts: usize,
}

impl LeftOut {
    fn any(&self) -> bool {
        self.requests + self.changes + self.words + self.held + self.drafts > 0
    }
}

/// What a view says of the agent itself, beside what waits.
struct About {
    asks: Vec<String>,
    types: Vec<splint_core::requests::InteractionType>,
    times: BTreeMap<splint_core::requests::InteractionType, Vec<String>>,
    units: BTreeMap<splint_core::requests::InteractionType, BTreeMap<String, String>>,
    schemas: Vec<splint_core::requests::Schema>,
    delegation: Option<Shown>,
    usage: Vec<crate::arrivals::UsageLine>,
}

/// Signs a view with the agent's key and seals it to its owner's device, unless signed it's more than
/// any reader verifies.
fn signed_and_sealed(
    key: &SigningKey,
    agent: &SplintId,
    owner: &Identity,
    about: &[u8],
    view: &[u8],
    now: u64,
) -> Sealed {
    let Ok(signed) = sign_owner_view(key, agent, owner.id(), view, now) else {
        return Sealed::Failed;
    };
    if signed.len() > MAX_SIGNED_VIEW_BYTES {
        return Sealed::TooBig;
    }
    owner
        .seal_key()
        .and_then(|seal_key| seal_note(seal_key, signed.as_bytes(), about).ok())
        .map_or(Sealed::Failed, Sealed::Done)
}

/// A view signed and sealed for the owner's device, or why not.
enum Sealed {
    Done(String),
    /// Signed, it's more than any reader verifies, so it has to carry less.
    TooBig,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
enum Unfit {
    CantSeal,
    TooBig,
}

#[derive(Serialize)]
struct View<'a, R, B> {
    requests: R,
    #[serde(flatten)]
    beside: &'a B,
}

/// Cuts each part beside the requests to its share, then fits as many requests as go in what's left.
async fn fit_view<C, W, H, D, R, Asked>(
    mut changes: Vec<C>,
    mut words: Vec<W>,
    mut held: Option<Vec<H>>,
    mut drafts: Vec<D>,
    about: About,
    requests_within: impl FnMut(usize) -> Asked,
    seal: impl Fn(&[u8]) -> Sealed,
) -> Result<Fitted, Unfit>
where
    C: Serialize,
    W: Serialize,
    H: Serialize,
    D: Serialize,
    R: Serialize,
    Asked: Future<Output = (R, usize)>,
{
    let left_out = LeftOut {
        requests: 0,
        changes: keep_within(&mut changes, MAX_PART_BYTES),
        words: keep_within(&mut words, MAX_PART_BYTES),
        held: held
            .as_mut()
            .map_or(0, |held| keep_within(held, MAX_PART_BYTES)),
        drafts: keep_within(&mut drafts, MAX_PART_BYTES),
    };
    let beside = Beside {
        changes: Changes { changes },
        words: Words { waiting: words },
        held,
        drafts,
        types: about.types,
        times: about.times,
        units: about.units,
        schemas: about.schemas,
        delegation: about.delegation,
        asks: about.asks,
        usage: about.usage,
    };
    fit(&beside, requests_within, seal, left_out).await
}

/// Keeps what fits in `max_bytes`, written out, smallest first, in the order given, and says how many it
/// left out. So one contact's huge entry is the first to go, rather than taking everyone else's room.
fn keep_within<T: Serialize>(items: &mut Vec<T>, max_bytes: usize) -> usize {
    let mut by_size: Vec<(usize, usize)> = items
        .iter()
        .map(|item| serde_json::to_vec(item).map_or(usize::MAX, |written| written.len()))
        .enumerate()
        .collect();
    by_size.sort_by_key(|&(_, size)| size);
    let mut keep = vec![false; items.len()];
    let mut room = max_bytes;
    for (index, size) in by_size {
        if size > room {
            break;
        }
        room -= size;
        if let Some(kept) = keep.get_mut(index) {
            *kept = true;
        }
    }
    let before = items.len();
    let mut keep = keep.into_iter();
    items.retain(|_| keep.next().unwrap_or(false));
    before - items.len()
}

/// Closer than this to the most a view can carry is close enough, which is less than any request.
const BUDGET_PRECISION: usize = 256;

/// Asks `requests_within` for requests whose steps fit a budget, as `signed_requests` gives them, and
/// keeps the biggest budget whose view fits what a host takes once it's sealed. A budget counts only
/// steps, and the rest of each request and sealing add to them by however much, so each try is measured
/// sealed, halving the gap between a budget that fits and one that doesn't. That takes a dozen tries at
/// most, and only when a view doesn't fit as it is.
async fn fit<R: Serialize, B: Serialize, Asked: Future<Output = (R, usize)>>(
    beside: &B,
    mut requests_within: impl FnMut(usize) -> Asked,
    seal: impl Fn(&[u8]) -> Sealed,
    mut left_out: LeftOut,
) -> Result<Fitted, Unfit> {
    let mut fits = sealed_within(beside, &mut requests_within, &seal, MAX_OWNER_VIEW_BYTES).await?;
    if fits.is_none() {
        // No more steps than the host takes in all could fit.
        let (mut fits_at, mut too_big_at) = (0, MAX_OWNER_VIEW_BYTES);
        while too_big_at.saturating_sub(fits_at) > BUDGET_PRECISION {
            let budget = fits_at + too_big_at.saturating_sub(fits_at) / 2;
            match sealed_within(beside, &mut requests_within, &seal, budget).await? {
                Some(tried) => {
                    fits = Some(tried);
                    fits_at = budget;
                }
                None => too_big_at = budget,
            }
        }
        if fits.is_none() {
            fits = sealed_within(beside, &mut requests_within, &seal, 0).await?;
        }
    }
    let tried = fits.ok_or(Unfit::TooBig)?;
    left_out.requests = tried.left_out;
    Ok(Fitted {
        view: tried.view,
        sealed: tried.sealed,
        left_out,
    })
}

struct Tried {
    view: String,
    sealed: String,
    left_out: usize,
}

/// The view with what fits this budget, sealed, if that fits what a host takes and, signed, what the
/// owner's device verifies.
async fn sealed_within<R: Serialize, B: Serialize, Asked: Future<Output = (R, usize)>>(
    beside: &B,
    requests_within: &mut impl FnMut(usize) -> Asked,
    seal: &impl Fn(&[u8]) -> Sealed,
    budget: usize,
) -> Result<Option<Tried>, Unfit> {
    let (requests, left_out) = requests_within(budget).await;
    let view = serde_json::to_string(&View { requests, beside }).map_err(|_| Unfit::TooBig)?;
    let sealed = match seal(view.as_bytes()) {
        Sealed::Done(sealed) => OwnerView { view: sealed },
        Sealed::TooBig => return Ok(None),
        Sealed::Failed => return Err(Unfit::CantSeal),
    };
    let size = serde_json::to_vec(&sealed)
        .map_err(|_| Unfit::TooBig)?
        .len();
    Ok((size <= MAX_OWNER_VIEW_BYTES).then_some(Tried {
        view,
        sealed: sealed.view,
        left_out,
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use splint_core::owner_view::VerifiedOwnerView;
    use splint_core::{RecoveryRule, SealingKey};

    use super::*;

    /// Shaped as `signed_requests` writes them out, with a contact's identities and binding beside the
    /// steps, which is most of a short exchange.
    fn requests(count: usize) -> Vec<Value> {
        (0..count)
            .map(|number| {
                json!({
                    "guest": false,
                    "role": "requester",
                    "peer_identity": "i".repeat(436),
                    "peer_owner": "o".repeat(436),
                    "peer_binding": "b".repeat(900),
                    "steps": (0..3)
                        .map(|step| format!("{number:04}{step}{}", "s".repeat(745)))
                        .collect::<Vec<_>>(),
                    "cancel_wanted": false,
                    "held": null,
                })
            })
            .collect()
    }

    /// As `signed_requests` does: in the order given, while their steps fit the budget.
    fn within(all: &[Value], budget: usize) -> (Vec<Value>, usize) {
        let mut room = budget;
        let mut kept = Vec::new();
        for request in all {
            let size: usize = request["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|step| step.as_str().unwrap().len())
                .sum();
            if size <= room {
                room -= size;
                kept.push(request.clone());
            }
        }
        let left_out = all.len() - kept.len();
        (kept, left_out)
    }

    fn sealed_size(owner: &SealingKey, view: &Value) -> usize {
        let view = serde_json::to_vec(view).unwrap();
        let sealed = seal_note(&owner.public_key(), &view, b"about").unwrap();
        serde_json::to_vec(&OwnerView { view: sealed })
            .unwrap()
            .len()
    }

    fn bytes_of(items: &Value) -> usize {
        items
            .as_array()
            .unwrap()
            .iter()
            .map(|item| serde_json::to_vec(item).unwrap().len())
            .sum()
    }

    /// A long-lived agent: 200 exchanges, a hostile contact whose history alone is bigger than a host
    /// takes, and change notices, words and held senders each coming to three times their share.
    #[tokio::test]
    async fn a_view_bigger_than_a_host_takes_keeps_as_many_requests_as_fit() {
        let all = requests(200);
        let requests_within = |budget: usize| {
            let answer = within(&all, budget);
            async move { answer }
        };
        let mut changes = vec![json!({"contact": "hostile", "history": "h".repeat(300 * 1024)})];
        changes
            .extend((0..100).map(
                |number| json!({"contact": format!("{number}"), "history": "h".repeat(2048)}),
            ));
        let words: Vec<Value> = (0..100)
            .map(|_| json!({"text": "w".repeat(2048)}))
            .collect();
        let held: Vec<Value> = (0..100)
            .map(|_| json!({"sender": "s".repeat(2048)}))
            .collect();
        let owner = SealingKey::generate().unwrap();
        let seal = |view: &[u8]| {
            seal_note(&owner.public_key(), view, b"about").map_or(Sealed::Failed, Sealed::Done)
        };

        let fitted = fit_view(
            changes,
            words,
            Some(held),
            Vec::<Value>::new(),
            About {
                asks: Vec::new(),
                types: Vec::new(),
                times: BTreeMap::new(),
                units: BTreeMap::new(),
                schemas: Vec::new(),
                usage: Vec::new(),
                delegation: None,
            },
            requests_within,
            seal,
        )
        .await
        .unwrap();

        let body = serde_json::to_vec(&OwnerView {
            view: fitted.sealed.clone(),
        })
        .unwrap();
        assert!(body.len() <= MAX_OWNER_VIEW_BYTES, "{} bytes", body.len());
        let mut opened: Value =
            serde_json::from_slice(&owner.open_note(&fitted.sealed, b"about").unwrap()).unwrap();
        assert!(opened == serde_json::from_str::<Value>(&fitted.view).unwrap());
        for part in [
            &opened["changes"]["changes"],
            &opened["words"]["waiting"],
            &opened["held"],
        ] {
            let size = bytes_of(part);
            assert!(size <= MAX_PART_BYTES, "a part came to {size} bytes");
            assert!(
                size > MAX_PART_BYTES / 2,
                "a part came to only {size} bytes"
            );
        }
        let contacts = opened["changes"]["changes"].as_array().unwrap();
        assert!(contacts.iter().all(|change| change["contact"] != "hostile"));
        assert_eq!(fitted.left_out.changes, 101 - contacts.len());
        assert_eq!(
            fitted.left_out.words,
            100 - opened["words"]["waiting"].as_array().unwrap().len()
        );
        assert_eq!(
            fitted.left_out.held,
            100 - opened["held"].as_array().unwrap().len()
        );

        let kept = opened["requests"].as_array().unwrap().len();
        assert_eq!(fitted.left_out.requests, all.len() - kept);
        // Two more wouldn't have fitted, so it kept as many as it could, give or take the last one.
        opened["requests"] = Value::Array(all.iter().take(kept + 2).cloned().collect());
        assert!(
            sealed_size(&owner, &opened) > MAX_OWNER_VIEW_BYTES,
            "kept {kept}"
        );
        assert!(kept > 0);
    }

    /// Bugs caught: a view a host takes, sealed, whose signature is bigger than any reader verifies, so
    /// the owner's device said its agent's host held nothing its agent signed, and showed nothing
    /// waiting; and the four parts beside the requests, each at its share, coming to more than can be
    /// signed even with no requests, which senders and drafts others can fill would do, so the owner's
    /// device got no new view at all.
    #[tokio::test]
    async fn a_view_is_kept_to_what_the_owners_device_verifies() {
        let all = requests(120);
        let requests_within = |budget: usize| {
            let answer = within(&all, budget);
            async move { answer }
        };
        let backup = || RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key());
        let owner = SealingKey::generate().unwrap();
        let agent_key = SigningKey::generate().unwrap();
        let agent = Identity::create(&agent_key, &owner.public_key(), backup()).unwrap();
        let owner_key = SigningKey::generate().unwrap();
        let owner_identity = Identity::create(&owner_key, &owner.public_key(), backup()).unwrap();
        let owner_id = owner_identity.id().clone();
        let seal = |view: &[u8]| {
            signed_and_sealed(&agent_key, agent.id(), &owner_identity, b"about", view, 1)
        };
        let full = |key: &str| -> Vec<Value> {
            (0..200).map(|_| json!({ key: "x".repeat(1024) })).collect()
        };

        let fitted = fit_view(
            full("history"),
            full("text"),
            Some(full("sender")),
            full("draft"),
            About {
                asks: Vec::new(),
                types: Vec::new(),
                times: BTreeMap::new(),
                units: BTreeMap::new(),
                schemas: Vec::new(),
                usage: Vec::new(),
                delegation: None,
            },
            requests_within,
            seal,
        )
        .await
        .unwrap();

        let signed = String::from_utf8(owner.open_note(&fitted.sealed, b"about").unwrap()).unwrap();
        assert!(VerifiedOwnerView::verify(&signed, &agent, &owner_id, 1).is_ok());
        assert!(fitted.left_out.requests > 0, "all {} fitted", all.len());
        assert!(fitted.left_out.requests < all.len(), "no requests fitted");
        assert!(fitted.left_out.held > 0);
    }

    #[test]
    fn one_contacts_huge_notice_cant_take_the_others_room() {
        let mut changes = vec![
            json!({"contact": "hostile", "history": "h".repeat(62 * 1024)}),
            json!({"contact": "first", "history": "h".repeat(4 * 1024)}),
            json!({"contact": "second", "history": "h".repeat(4 * 1024)}),
        ];

        let left_out = keep_within(&mut changes, 64 * 1024);

        assert_eq!(left_out, 1);
        let contacts: Vec<&str> = changes
            .iter()
            .map(|change| change["contact"].as_str().unwrap())
            .collect();
        assert_eq!(contacts, ["first", "second"]);
    }

    #[tokio::test]
    async fn a_view_that_cant_fit_even_with_no_requests_is_left_unsent() {
        let all = requests(10);
        let requests_within = |budget: usize| {
            let answer = within(&all, budget);
            async move { answer }
        };
        let beside = json!({"changes": "c".repeat(MAX_OWNER_VIEW_BYTES)});
        let owner = SealingKey::generate().unwrap();
        let seal = |view: &[u8]| {
            seal_note(&owner.public_key(), view, b"about").map_or(Sealed::Failed, Sealed::Done)
        };
        let left_out = LeftOut {
            requests: 0,
            changes: 0,
            words: 0,
            held: 0,
            drafts: 0,
        };

        let fitted = fit(&beside, requests_within, seal, left_out).await;

        assert_eq!(fitted.err(), Some(Unfit::TooBig));
    }
}

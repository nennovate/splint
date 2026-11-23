//! Registers agents and resolves their handles.
//!
//! A host is the authority over its own handles, so it decides who can claim one: registering
//! takes the owner's binding and a one-time signup code from whoever runs this host. Whoever runs it
//! can also open signups, so a binding is enough, under limits of its own, as [`open_signup`] says.
//! Anyone can make an owner key, so those limits are all that stands against a flood, and they're
//! kept apart from the agents who hold codes, so filling them shuts out only others signing up the
//! same way.

pub mod kept_names;
pub mod open_signup;

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use splint_core::host_api::{
    JoinLimit, NAMES_PATH, NameHolder, OWNERS_NAME_PATH, OwnersName, RecoveryNotice, Resolved,
    RetirementNotice, RetirementTaken, RevocationNotice,
};
use splint_core::{
    ADDRESS_SEPARATOR, Error, Identity, MIN_SIGNUP_CODE_CHARS, RECOVERY_WINDOW_SECS, SplintId,
    VerifiedRegistration, VerifiedRelease, VerifiedRetirement, claimed_released_agent,
    claimed_retired_agent, is_temporary_name, may_be_owner_name, may_take_without_code, name_parts,
    owner_id_start, signup_id, unix_now,
};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::admission::SenderRecord;
use crate::api_error::ApiError;
use crate::{Host, admission, changes, database, delivery, inbox, join, owner_keys, requests};

// `handle` holds the whole name before the `~`, with any owner part, and names one agent here. Names
// are their owners': an owner's name belongs to the first owner ID whose binding used it here, for
// good, and each owner has one, so `.jeff` here always means the same owner, and `jeff` alone can only
// be that owner's own agent. Their agents are named under it, as `claude.jeff`, so two owners' agents
// can share a handle. An agent nobody has set up controls for has a temporary name, the word it chose
// and a code, as `claude-7k3p2a`, which no owner's name can be. A name an agent left when its owner
// changed, or when its owner added their part to a name that had none, stays its own, and answers
// with where it went, so nobody else can take it and be reached by mistake: for good, or until
// `until_at` for a temporary one. Before names were owners', a host kept one agent to each handle,
// and agents named then keep their names.
// A retired agent keeps its row, so its ID and handle can't be registered again. A revoked one keeps
// its row too, and its owner can sign it back in. The columns after `open_source` are what a recovery
// of the owner's ID can still undo, and for how long.
pub const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        handle TEXT NOT NULL UNIQUE,
        identity TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        owner_identity TEXT NOT NULL,
        binding TEXT NOT NULL,
        binding_seq BIGINT NOT NULL,
        revocation TEXT,
        revoked_seq BIGINT,
        retirement TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS agents_owner ON agents (owner_id);
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS open_source TEXT;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS retirement_final_at BIGINT;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS moved_from_owner TEXT;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS moved_from_owner_identity TEXT;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS moved_from_identity TEXT;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS moved_at BIGINT;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS identity_before_recovery TEXT;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS identity_recovered_at BIGINT;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS won_back BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE INDEX IF NOT EXISTS agents_moved_from ON agents (moved_from_owner);
    DROP INDEX IF EXISTS agents_one_per_handle;
    CREATE TABLE IF NOT EXISTS owner_names (
        name TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL UNIQUE
    );
    CREATE TABLE IF NOT EXISTS moved_names (
        name TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL
    );
    ALTER TABLE moved_names ADD COLUMN IF NOT EXISTS until_at BIGINT;
    CREATE TABLE IF NOT EXISTS signup_codes (
        id TEXT PRIMARY KEY,
        code TEXT NOT NULL,
        used_by TEXT
    );
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS stand_in BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE agents ADD COLUMN IF NOT EXISTS has_sent BOOLEAN NOT NULL DEFAULT FALSE;
    DROP INDEX IF EXISTS agents_unused_stand_ins;
    CREATE INDEX IF NOT EXISTS agents_unused_open ON agents (created_at)
        WHERE NOT has_sent AND open_source IS NOT NULL;
    CREATE TABLE IF NOT EXISTS released_handles (
        handle TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL
    );
";

/// One lock for all open signups, as a limit that counts first has to stop others counting at once.
const OPEN_SIGNUP_LOCK: i64 = 0x6f70_656e;
/// Taken with a handle's own number, so taking a handle and letting one go can't cross.
const HANDLE_LOCK: i32 = 0x6861_6e64;
const OPEN_SIGNUP_YES: &str = "yes";
/// What stands in for a signed revocation when a recovery undid something: the agent stays stopped until
/// its owner signs for it under their new key, whatever got it stopped, and however it comes back.
const STOPPED_UNTIL_SIGNED: &str = "stopped-until-its-owner-signs-again";
const FORWARDED_FOR: &str = "x-forwarded-for";
/// An IPv6 network hands out this many leading groups to one customer, so counting whole addresses
/// would let one customer have as many sources as they like.
const IPV6_GROUPS_OF_ONE_NETWORK: usize = 4;

pub fn routes() -> Router<Arc<Host>> {
    Router::new()
        .route(splint_core::REGISTER_PATH, post(register))
        .route("/v0/retirements", post(retire))
        .route("/v0/recoveries", post(recover))
        .route("/v0/revocations", post(revoke))
        .route("/.well-known/splint/agents/{handle}", get(resolve))
        .route(&format!("{NAMES_PATH}/{{name}}"), get(name_holder))
        .route(&format!("{OWNERS_NAME_PATH}/{{owner}}/name"), get(owners_name))
}

#[derive(Debug, thiserror::Error)]
#[error("SPLINT_OPEN_SIGNUP is either yes or not set")]
pub struct OpenSignupSettingError;

/// Off unless it's exactly yes, and a mistyped word stops the host rather than leaving this unclear.
pub fn open_signup_from(setting: Option<&str>) -> Result<bool, OpenSignupSettingError> {
    match setting {
        None | Some("") => Ok(false),
        Some(OPEN_SIGNUP_YES) => Ok(true),
        Some(_) => Err(OpenSignupSettingError),
    }
}

/// Which network a call came from. A host with other machines' traffic listens only on loopback behind
/// its proxy, which writes this header itself from the connection and ignores what a caller sent. So
/// the last entry is the proxy's word. With no proxy there's no way to tell, and everything counts as
/// one source, which errs on the side of fewer signups.
pub fn source_of(headers: &HeaderMap) -> String {
    let last = headers
        .get(FORWARDED_FOR)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|value| value.trim().parse::<IpAddr>().ok());
    match last {
        Some(IpAddr::V4(address)) => address.to_string(),
        Some(IpAddr::V6(address)) => match address.to_ipv4_mapped() {
            Some(mapped) => mapped.to_string(),
            None => address
                .segments()
                .iter()
                .take(IPV6_GROUPS_OF_ONE_NETWORK)
                .map(|group| format!("{group:x}"))
                .collect::<Vec<_>>()
                .join(":"),
        },
        None => String::new(),
    }
}

/// Codes named here are added at each start, and one already held keeps whatever use it has. It's
/// how codes reached a host before `splint-host codes add`, which needs no restart and leaves no
/// code in a settings file, and it stays for a host set up that way.
pub const SIGNUP_CODES_SETTING: &str = "SPLINT_SIGNUP_CODES";

#[derive(Debug, thiserror::Error)]
pub enum SignupCodesError {
    #[error(
        "a signup code in {SIGNUP_CODES_SETTING} is shorter than {MIN_SIGNUP_CODE_CHARS} characters"
    )]
    TooShort,
    #[error("couldn't store signup codes: {0}")]
    Database(#[from] sqlx::Error),
}

/// A short code could be guessed offline from one captured request, so it's refused at startup.
pub fn usable_signup_codes(codes: &str) -> Result<Vec<&str>, SignupCodesError> {
    let codes: Vec<&str> = codes.split(',').filter(|code| !code.is_empty()).collect();
    if codes
        .iter()
        .any(|code| code.chars().count() < MIN_SIGNUP_CODE_CHARS)
    {
        return Err(SignupCodesError::TooShort);
    }
    Ok(codes)
}

/// Whoever runs this host hands these out. A code already in the table keeps whatever use it has.
pub async fn add_signup_codes(db: &PgPool, codes: &str) -> Result<(), SignupCodesError> {
    for code in usable_signup_codes(codes)? {
        sqlx::query("INSERT INTO signup_codes (id, code) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(signup_id(code))
            .bind(code)
            .execute(db)
            .await?;
    }
    Ok(())
}

/// A captured request can only repeat the registration its owner wanted, which is harmless, and a
/// repeat from an agent already here doesn't spend a code, so Signet can do this on every start. An
/// agent already here can also bring a newer statement of who it acts for, which goes in if it may
/// follow the one held.
async fn register(
    State(host): State<Arc<Host>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Resolved>, ApiError> {
    let proof = inbox::access_proof_in(&headers).ok_or(ApiError::Unauthorized)?;
    let registration = VerifiedRegistration::verify(proof, &body, &host.domain, unix_now())?;
    let agent = registration.agent();
    // On access as well as on a schedule, so room a newcomer needs is there when they ask.
    if host.open_signup {
        open_signup::release_unused(&host).await?;
    }

    let existing = sqlx::query(
        "SELECT id, handle, identity, owner_identity, binding_seq, revoked_seq, retirement,
             moved_from_owner, moved_at, identity_before_recovery, identity_recovered_at,
             moved_away_to
         FROM agents WHERE id = $1 OR handle = $2",
    )
    .bind(agent.id().as_str())
    .bind(registration.name())
    .fetch_all(&host.db)
    .await?;
    let left_by: Option<String> = sqlx::query_scalar(&format!(
        "SELECT agent_id FROM moved_names WHERE name = $1 AND {STILL_HELD}"
    ))
    .bind(registration.name())
    .bind(host.clock.now_for_sql().await)
    .fetch_optional(&host.db)
    .await?;
    if left_by.is_some_and(|left_by| left_by != agent.id().as_str()) {
        return Err(ApiError::Conflict);
    }
    match existing.as_slice() {
        // An agent here already keeps registering as it starts, and an agent moving here is new.
        [] if host.closing.at().is_some() => {
            return Err(ApiError::AtJoinLimit(JoinLimit::HostClosing));
        }
        [] => claim_handle(&host, &registration, &source_of(&headers)).await?,
        [row] if row.try_get::<String, _>("id")? == agent.id().as_str() => {
            if row.try_get::<Option<String>, _>("retirement")?.is_some() {
                return Err(ApiError::Forbidden("this agent has been retired"));
            }
            // One that moved to another host and is moving back is a new agent here too.
            if host.closing.at().is_some()
                && row.try_get::<Option<String>, _>("moved_away_to")?.is_some()
            {
                return Err(ApiError::AtJoinLimit(JoinLimit::HostClosing));
            }
            take_newer_statement(&host, &registration, row).await?;
        }
        _ => return Err(ApiError::Conflict),
    }
    Ok(Json(Resolved {
        agent_id: agent.id().clone(),
        identity: agent.encoded(),
        owner_identity: registration.owner().encoded(),
        binding: registration.binding().compact().to_owned(),
        history: String::new(),
        moved_to: String::new(),
    }))
}

/// What a registration from an agent already here changes. A stale identity can't bring back a key
/// given up in a recovery, and only the owner on record can let a new owner in. What the old owner
/// signed for this agent's rules goes with them. What a move to a new owner replaces is kept for a
/// while, as a recovery of the owner it left may undo it. A chain of moves goes back to the first, so a
/// thief can't move an agent on twice to get away from that.
async fn take_newer_statement(
    host: &Host,
    registration: &VerifiedRegistration,
    row: &sqlx::postgres::PgRow,
) -> Result<(), ApiError> {
    let agent = registration.agent();
    let owner = registration.owner();
    let binding = registration.binding();
    let held_agent = Identity::from_encoded(&row.try_get::<String, _>("identity")?)?;
    let held_owner = Identity::from_encoded(&row.try_get::<String, _>("owner_identity")?)?;
    if !agent.extends(&held_agent) || (owner.id() == held_owner.id() && !owner.extends(&held_owner))
    {
        return Err(ApiError::OutOfDate("that identity is out of date"));
    }
    let held_seq = u64::try_from(row.try_get::<i64, _>("binding_seq")?).unwrap_or(u64::MAX);
    binding
        .may_replace(&held_owner, held_seq)
        .map_err(|_| ApiError::Forbidden("that statement can't replace the one held"))?;
    let revoked_seq = row.try_get::<Option<i64>, _>("revoked_seq")?;
    let seq = i64::try_from(binding.seq()).map_err(|_| Error::Malformed)?;
    if revoked_seq.is_some_and(|revoked| seq <= revoked) {
        return Err(ApiError::OutOfDate("this agent was revoked since that"));
    }
    // A new owner names the agent under their own name here, as `claude-7k3p2a` set up by jeff becomes
    // `claude.jeff`. The same owner can only add theirs, once, to a name that has none, as for an agent
    // set up before names were owners'. An owner's agent never keeps a temporary name.
    let held_name: String = row.try_get("handle")?;
    let renamed = held_name != registration.name();
    let (held_handle, held_part) = name_parts(&held_name);
    let (handle, part) = name_parts(registration.name());
    let may_rename = owner.id() != held_owner.id()
        || (held_handle == handle && held_part.is_none() && part.is_some());
    if renamed && !may_rename {
        return Err(ApiError::Forbidden(
            "a name changes with a new owner, who names the agent under their own, or once by its \
             owner, adding theirs to a name that has none",
        ));
    }
    if !owner.is_unconfirmed_owner() && is_temporary_name(registration.name()) {
        return Err(ApiError::Forbidden(NAMED_UNDER_AN_OWNER));
    }
    let now = host.clock.now_for_sql().await;
    let mut transaction = database::begin(&host.db).await?;
    if renamed {
        may_take_new_name(&mut transaction, host, registration, now).await?;
        // A temporary name points to the new one for a while, and then anyone can have it again.
        let until =
            is_temporary_name(&held_name).then(|| now.saturating_add(TEMPORARY_NAME_KEPT_SECS));
        rename(
            &mut transaction,
            agent.id(),
            (&held_name, registration.name()),
            until,
            now,
        )
        .await?;
    } else {
        take_owner_name(&mut transaction, registration, now).await?;
    }
    if owner.id() != held_owner.id() && !moved_recently(row, now)? {
        let before = recent_identity(row, now)?.unwrap_or_else(|| held_agent.encoded());
        sqlx::query(
            "UPDATE agents SET moved_from_owner = $2, moved_from_owner_identity = $3,
                 moved_from_identity = $4, moved_at = $5
             WHERE id = $1",
        )
        .bind(agent.id().as_str())
        .bind(held_owner.id().as_str())
        .bind(held_owner.encoded())
        .bind(before)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "UPDATE agents SET identity = $2, owner_id = $3, owner_identity = $4, binding = $5,
             binding_seq = $6, revocation = NULL, revoked_seq = NULL, won_back = FALSE,
             moved_away_to = NULL,
             identity_before_recovery = CASE WHEN $3 = owner_id THEN identity_before_recovery END,
             identity_recovered_at = CASE WHEN $3 = owner_id THEN identity_recovered_at END,
             stand_in = $7
         WHERE id = $1 AND retirement IS NULL",
    )
    .bind(agent.id().as_str())
    .bind(agent.encoded())
    .bind(owner.id().as_str())
    .bind(owner.encoded())
    .bind(binding.compact())
    .bind(seq)
    .bind(owner.is_unconfirmed_owner())
    .execute(&mut *transaction)
    .await?;
    // An owner confirming an agent that joined on its own takes up what it was doing: nobody else's
    // was held for it. Only the stand-in's rules go, as only the owner signs from here.
    let confirming = held_owner.is_unconfirmed_owner() && !owner.is_unconfirmed_owner();
    if confirming {
        forget_rules(&mut transaction, agent.id()).await?;
        tracing::info!(agent = %agent.id(), owner = %owner.id(), "an owner set up their controls for this agent");
    } else if owner.id() != held_owner.id() {
        forget_rules(&mut transaction, agent.id()).await?;
        changes::keep_audience(&mut transaction, agent.id()).await?;
        admission::forget_for_new_owner(&mut transaction, agent.id()).await?;
        inbox::clear_for_new_owner(&mut transaction, agent.id()).await?;
        requests::hide_from_new_owner(&mut transaction, agent.id()).await?;
        delivery::end_queued_from(&mut transaction, agent.id()).await?;
        tracing::warn!(agent = %agent.id(), owner = %owner.id(), "this agent has a new owner");
    }
    // A newer copy of the same owner that removed a key ends what only that key signed, as one
    // arriving at `/v0/recoveries` does. The new binding is a key's that counts, or it wasn't taken.
    if owner.id() == held_owner.id() && owner.recoveries() == held_owner.recoveries() {
        owner_keys::agent_owner_changed(&mut transaction, agent.id(), &held_owner, owner).await?;
    }
    join::forget_answers(&mut transaction, agent).await?;
    transaction.commit().await?;
    Ok(())
}

fn window_secs() -> i64 {
    i64::try_from(RECOVERY_WINDOW_SECS).unwrap_or(i64::MAX)
}

fn is_within_window(at: Option<i64>, now: i64) -> bool {
    at.is_some_and(|at| at.saturating_add(window_secs()) > now)
}

fn moved_recently(row: &sqlx::postgres::PgRow, now: i64) -> Result<bool, sqlx::Error> {
    Ok(row
        .try_get::<Option<String>, _>("moved_from_owner")?
        .is_some()
        && is_within_window(row.try_get("moved_at")?, now))
}

/// The copy of this agent's ID from before a recovery of it that a recovery of its owner may undo.
fn recent_identity(row: &sqlx::postgres::PgRow, now: i64) -> Result<Option<String>, sqlx::Error> {
    if is_within_window(row.try_get("identity_recovered_at")?, now) {
        row.try_get("identity_before_recovery")
    } else {
        Ok(None)
    }
}

pub(crate) async fn forget_rules(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
) -> Result<(), sqlx::Error> {
    for statement in [
        "DELETE FROM rules WHERE agent = $1",
        "DELETE FROM listed_owners WHERE agent = $1",
    ] {
        sqlx::query(statement)
            .bind(agent.as_str())
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

/// A copy of an owner's ID older than one this host holds names a key that owner gave up, so nothing
/// new gets registered under it.
async fn check_owner_is_current(host: &Host, owner: &Identity) -> Result<(), ApiError> {
    let held: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT owner_identity FROM agents WHERE owner_id = $1")
            .bind(owner.id().as_str())
            .fetch_all(&host.db)
            .await?;
    let newer = held
        .iter()
        .filter_map(|held| Identity::from_encoded(held).ok())
        .any(|held| !owner.extends(&held));
    if newer {
        return Err(ApiError::OutOfDate("that identity is out of date"));
    }
    Ok(())
}

/// Spends the code, or a place among open signups, and takes the handle together, so losing a race for
/// a handle costs nothing.
async fn claim_handle(
    host: &Host,
    registration: &VerifiedRegistration,
    source: &str,
) -> Result<(), ApiError> {
    let agent = registration.agent();
    check_owner_is_current(host, registration.owner()).await?;
    let open = registration.has_no_code();
    if open && !host.open_signup {
        return Err(ApiError::Forbidden("this host needs a signup code"));
    }
    if open && !may_take_without_code(registration.name()) {
        return Err(ApiError::Forbidden(open_signup::HANDLE_KEPT_BACK));
    }
    let stand_in = registration.owner().is_unconfirmed_owner();
    let mut transaction = database::begin(&host.db).await?;
    if open {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(OPEN_SIGNUP_LOCK)
            .execute(&mut *transaction)
            .await?;
    }
    lock_handle(&mut transaction, registration.name()).await?;
    open_signup::check_not_held(&mut transaction, registration).await?;
    let counts = sqlx::query(
        "SELECT count(*) FILTER (WHERE retirement IS NULL) AS agents,
             count(*) FILTER (WHERE retirement IS NULL AND owner_id = $1) AS of_owner,
             count(*) FILTER (WHERE created_at > now() - interval '1 hour'
                 AND open_source IS NULL) AS this_hour,
             count(*) FILTER (WHERE retirement IS NULL AND open_source IS NOT NULL) AS open_agents,
             count(*) FILTER (WHERE created_at > now() - interval '1 hour'
                 AND open_source IS NOT NULL) AS open_this_hour,
             count(*) FILTER (WHERE created_at > now() - interval '1 day'
                 AND open_source = $2) AS open_from_source,
             count(*) FILTER (WHERE created_at > now() - interval '1 hour'
                 AND open_source = $2) AS open_from_source_this_hour,
             count(*) FILTER (WHERE retirement IS NULL AND open_source = $2)
                 AS open_held_from_source,
             count(*) FILTER (WHERE retirement IS NULL AND open_source IS NOT NULL AND stand_in
                 AND NOT has_sent) AS unused_stand_ins,
             count(*) FILTER (WHERE retirement IS NULL AND open_source IS NOT NULL AND stand_in)
                 AS open_stand_ins
         FROM agents",
    )
    .bind(registration.owner().id().as_str())
    .bind(source)
    .fetch_one(&mut *transaction)
    .await?;
    let limits = host.limits.now();
    let reached = |count: &str, limit: u32| -> Result<bool, sqlx::Error> {
        Ok(counts.try_get::<i64, _>(count)? >= i64::from(limit))
    };
    if open
        && (reached("open_from_source", limits.open_agents_per_source_per_day)?
            || reached(
                "open_from_source_this_hour",
                limits.open_agents_per_source_per_hour,
            )?)
    {
        return Err(ApiError::AtJoinLimit(JoinLimit::FromOneNetwork));
    }
    if open && reached("open_held_from_source", limits.open_agents_per_source)? {
        return Err(ApiError::AtJoinLimit(JoinLimit::OneNetworkHoldsAll));
    }
    if open && stand_in && reached("unused_stand_ins", limits.unused_stand_ins)? {
        return Err(ApiError::AtJoinLimit(JoinLimit::UnusedStandIns));
    }
    if open && stand_in && reached("open_stand_ins", limits.open_stand_ins)? {
        return Err(ApiError::AtJoinLimit(JoinLimit::StandIns));
    }
    // Each says which it is, so an owner at their cap isn't told to wait for nothing.
    if reached("agents", limits.agents)? {
        return Err(ApiError::AtJoinLimit(JoinLimit::HostFull));
    }
    if reached("of_owner", limits.agents_per_owner)? {
        return Err(ApiError::AtJoinLimit(JoinLimit::OwnersAgents));
    }
    if open
        && (reached("open_agents", limits.open_agents)?
            || reached("open_this_hour", limits.open_agents_per_hour)?)
    {
        return Err(ApiError::AtJoinLimit(JoinLimit::WithoutACode));
    }
    if !open && reached("this_hour", limits.new_agents_per_hour)? {
        return Err(ApiError::AtJoinLimit(JoinLimit::ThisHour));
    }
    if !open {
        spend_code(&mut transaction, registration).await?;
    }
    let now = host.clock.now_for_sql().await;
    may_take_new_name(&mut transaction, host, registration, now).await?;
    let inserted = sqlx::query(
        "INSERT INTO agents (id, handle, identity, owner_id, owner_identity, binding, binding_seq,
             open_source, stand_in)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT DO NOTHING",
    )
    .bind(agent.id().as_str())
    .bind(registration.name())
    .bind(agent.encoded())
    .bind(registration.owner().id().as_str())
    .bind(registration.owner().encoded())
    .bind(registration.binding().compact())
    .bind(i64::try_from(registration.binding().seq()).map_err(|_| Error::Malformed)?)
    .bind(open.then_some(source))
    .bind(stand_in)
    .execute(&mut *transaction)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::Conflict);
    }
    open_signup::stop_holding(&mut transaction, agent.id()).await?;
    join::forget_answers(&mut transaction, agent).await?;
    transaction.commit().await?;
    if open {
        tracing::info!(agent = %agent.id(), "took an open signup");
    }
    Ok(())
}

/// Waits for whoever else is taking or letting go of this name, until the transaction ends.
async fn lock_handle(
    transaction: &mut Transaction<'_, Postgres>,
    name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(HANDLE_LOCK)
        .bind(name)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// How long a temporary name an agent left points to its new one before anyone can have it. Provisional.
const TEMPORARY_NAME_KEPT_SECS: i64 = 30 * 24 * 60 * 60;
/// A moved name that hasn't run out, with `$2` the time now.
const STILL_HELD: &str = "(until_at IS NULL OR until_at > $2)";
const TEMPORARY_NAMES_ONLY: &str = "an agent nobody has set up controls for joins under a temporary \
     name, the word it chose and a code, so update Splint and join again";
const NAMED_UNDER_AN_OWNER: &str = "an owner's agent is named under their name, as handle.name, or \
     by it alone, which has 3 or more characters, isn't a temporary name or an owner's ID, and isn't \
     one this host keeps back";
const NAMES_ANOTHER_OWNER: &str =
    "that name is another owner's here, or this owner has another, or an agent goes by it alone";

/// Whether this registration may take its name here as a new one. An agent nobody has set up controls
/// for takes only a temporary name, and none an owner holds. An owner's agent takes their own name
/// alone, or a handle and their name after it, as `claude.jeff`, never a temporary name or one this
/// host keeps back, and that name has to be theirs or free, as `claim_owner_name` says. A name another
/// agent left, or a handle an agent let go holds, is refused before this.
async fn may_take_new_name(
    transaction: &mut Transaction<'_, Postgres>,
    host: &Host,
    registration: &VerifiedRegistration,
    now: i64,
) -> Result<(), ApiError> {
    let name = registration.name();
    if registration.owner().is_unconfirmed_owner() {
        if !is_temporary_name(name) {
            return Err(ApiError::Forbidden(TEMPORARY_NAMES_ONLY));
        }
        let owned: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM owner_names WHERE name = $1")
                .bind(name)
                .fetch_optional(&mut **transaction)
                .await?;
        return if owned.is_some() {
            Err(ApiError::Conflict)
        } else {
            Ok(())
        };
    }
    let (handle, part) = name_parts(name);
    let owner_name = part.unwrap_or(handle);
    if is_temporary_name(name)
        || !may_be_owner_name(owner_name)
        || host.kept_names.holds(owner_name)
    {
        return Err(ApiError::Forbidden(NAMED_UNDER_AN_OWNER));
    }
    claim_owner_name(transaction, registration.owner().id(), owner_name, now).await
}

/// An owner part held already, as an agent registering again under its name brings it. It has to be
/// its owner's, as a new name's does, and an agent nobody has set up controls for has none.
async fn take_owner_name(
    transaction: &mut Transaction<'_, Postgres>,
    registration: &VerifiedRegistration,
    now: i64,
) -> Result<(), ApiError> {
    let (_, Some(owner_name)) = name_parts(registration.name()) else {
        return Ok(());
    };
    // An owner part says who an agent acts for, and nobody has said yet.
    if registration.owner().is_unconfirmed_owner() {
        return Err(ApiError::Forbidden(
            "an agent whose person hasn't set up their controls has no owner part",
        ));
    }
    claim_owner_name(transaction, registration.owner().id(), owner_name, now).await
}

/// An owner's name is theirs on this host: the first owner ID to use it takes it, and an owner has one,
/// so nobody can claim to act for someone, and `.jeff` names one owner for good. A name another owner's
/// agent goes by alone, a temporary one or one from before names were owners', can't be taken while it
/// does, so `jeff` alone is never someone else's agent.
async fn claim_owner_name(
    transaction: &mut Transaction<'_, Postgres>,
    owner: &SplintId,
    name: &str,
    now: i64,
) -> Result<(), ApiError> {
    let owner = owner.as_str();
    let held: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM owner_names WHERE name = $1")
            .bind(name)
            .fetch_optional(&mut **transaction)
            .await?;
    match held {
        Some(held) if held == owner => return Ok(()),
        Some(_) => return Err(ApiError::Forbidden(NAMES_ANOTHER_OWNER)),
        None => {}
    }
    let gone_by_alone: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM agents WHERE handle = $1 AND owner_id <> $3)
             OR EXISTS (SELECT 1 FROM moved_names JOIN agents ON agents.id = moved_names.agent_id
                 WHERE name = $1 AND agents.owner_id <> $3 AND {STILL_HELD})"
    ))
    .bind(name)
    .bind(now)
    .bind(owner)
    .fetch_one(&mut **transaction)
    .await?;
    if gone_by_alone {
        return Err(ApiError::Forbidden(NAMES_ANOTHER_OWNER));
    }
    sqlx::query("INSERT INTO owner_names (name, owner_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(name)
        .bind(owner)
        .execute(&mut **transaction)
        .await?;
    let held: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM owner_names WHERE name = $1")
            .bind(name)
            .fetch_optional(&mut **transaction)
            .await?;
    if held.as_deref() == Some(owner) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(NAMES_ANOTHER_OWNER))
    }
}

/// An agent takes its new name. The old one stays the agent's, and answers with where it went: for
/// good, or `until` then for a temporary one.
async fn rename(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
    (from, to): (&str, &str),
    until: Option<i64>,
    now: i64,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM moved_names WHERE name = $1 AND agent_id = $2")
        .bind(to)
        .bind(agent.as_str())
        .execute(&mut **transaction)
        .await?;
    // A temporary name that ran out is anyone's again, which taking it back here makes this agent's.
    sqlx::query(
        "INSERT INTO moved_names (name, agent_id, until_at) VALUES ($1, $2, $3)
         ON CONFLICT (name) DO UPDATE SET agent_id = $2, until_at = $3
         WHERE moved_names.until_at IS NOT NULL AND moved_names.until_at <= $4",
    )
    .bind(from)
    .bind(agent.as_str())
    .bind(until)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    let renamed = sqlx::query("UPDATE agents SET handle = $2 WHERE id = $1")
        .bind(agent.as_str())
        .bind(to)
        .execute(&mut **transaction)
        .await;
    match renamed {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Err(ApiError::Conflict),
        Err(error) => Err(error.into()),
    }
}

async fn spend_code(
    transaction: &mut Transaction<'_, Postgres>,
    registration: &VerifiedRegistration,
) -> Result<(), ApiError> {
    let code: Option<String> = sqlx::query_scalar(
        "SELECT code FROM signup_codes WHERE id = $1 AND used_by IS NULL FOR UPDATE",
    )
    .bind(registration.signup_id())
    .fetch_optional(&mut **transaction)
    .await?;
    if !code.is_some_and(|code| registration.paid_with(&code)) {
        return Err(ApiError::SignupCodeRefused);
    }
    sqlx::query("UPDATE signup_codes SET used_by = $1 WHERE id = $2")
        .bind(registration.agent().id().as_str())
        .bind(registration.signup_id())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn resolve(
    State(host): State<Arc<Host>>,
    Path(handle): Path<String>,
) -> Result<Json<Resolved>, ApiError> {
    Ok(Json(resolved_here(&host, &handle).await?))
}

/// Who has a name here as their own, so an owner's side can say before anyone signs whether it's free:
/// an owner whose name it is, or whose agent goes by it alone. One nobody can have here is 403.
async fn name_holder(
    State(host): State<Arc<Host>>,
    Path(name): Path<String>,
) -> Result<Json<NameHolder>, ApiError> {
    if !may_be_owner_name(&name) || host.kept_names.holds(&name) {
        return Err(ApiError::Forbidden(NAMED_UNDER_AN_OWNER));
    }
    let owner: Option<String> = sqlx::query_scalar(&format!(
        "SELECT owner_id FROM owner_names WHERE name = $1
         UNION ALL SELECT owner_id FROM agents WHERE handle = $1
         UNION ALL SELECT agents.owner_id FROM moved_names
             JOIN agents ON agents.id = moved_names.agent_id WHERE name = $1 AND {STILL_HELD}
         LIMIT 1"
    ))
    .bind(&name)
    .bind(host.clock.now_for_sql().await)
    .fetch_optional(&host.db)
    .await?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    Ok(Json(NameHolder { owner }))
}

/// An owner's name here, which their agents here are named under.
async fn owners_name(
    State(host): State<Arc<Host>>,
    Path(owner): Path<String>,
) -> Result<Json<OwnersName>, ApiError> {
    let name: Option<String> =
        sqlx::query_scalar("SELECT name FROM owner_names WHERE owner_id = $1")
            .bind(&owner)
            .fetch_optional(&host.db)
            .await?;
    Ok(Json(OwnersName {
        name: name.ok_or(ApiError::NotFound)?,
    }))
}

/// Who's registered at this name here, as anyone can ask. A name an agent left with its owner answers
/// with that agent as it is now, and where it went, as does one whose agent moved to another host. A
/// handle with an owner's ID in place of their name, as `claude.<ID form>`, answers as the name it
/// stands for here, `claude.jeff`, with that as where it is, for the asker to keep and show from then
/// on: it checks the owner's ID in the binding starts as the ID form says, as nothing here is signed.
pub async fn resolved_here(host: &Host, name: &str) -> Result<Resolved, ApiError> {
    let named = match name_parts(name) {
        (handle, Some(part)) => match owner_id_start(part) {
            Some(start) => {
                let owner_name: Option<String> = sqlx::query_scalar(
                    "SELECT name FROM owner_names WHERE starts_with(owner_id, $1) LIMIT 1",
                )
                .bind(start)
                .fetch_optional(&host.db)
                .await?;
                format!("{handle}.{}", owner_name.ok_or(ApiError::NotFound)?)
            }
            None => name.to_owned(),
        },
        (_, None) => name.to_owned(),
    };
    let row = sqlx::query(&format!(
        "SELECT a.identity, a.owner_identity, a.binding, a.history, a.moved_away_to,
             CASE WHEN a.handle = $3 THEN '' ELSE a.handle END AS moved_to
         FROM agents a
         WHERE (a.handle = $1
                OR a.id = (SELECT agent_id FROM moved_names WHERE name = $1 AND {STILL_HELD}))
             AND a.retirement IS NULL AND a.revocation IS NULL"
    ))
    .bind(&named)
    .bind(host.clock.now_for_sql().await)
    .bind(name)
    .fetch_optional(&host.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let moved_to: String = row.try_get("moved_to")?;
    let away: Option<String> = row.try_get("moved_away_to")?;
    let identity = Identity::from_encoded(&row.try_get::<String, _>("identity")?)?;
    Ok(Resolved {
        agent_id: identity.id().clone(),
        identity: identity.encoded(),
        owner_identity: row.try_get("owner_identity")?,
        binding: row.try_get("binding")?,
        history: row.try_get("history")?,
        // Another host, which its own signed history says, is where it is now. Nothing follows this
        // unsigned hint: a reader goes by that history.
        moved_to: match away {
            Some(away) => away,
            None if moved_to.is_empty() => moved_to,
            None => format!("{moved_to}{ADDRESS_SEPARATOR}{}", host.domain),
        },
    })
}

/// Takes an owner's stop signal. From here on the agent can't authenticate, send or be found, and
/// neither its ID nor its handle can be registered again. What it queued before this ends with it,
/// or a stolen key could load the queue and go on delivering after the stop.
///
/// The stop counts at once and is final after a while. Until then a recovery of the owner's ID undoes
/// it, because a thief with the owner's key can sign one too.
///
/// A host that doesn't hold this agent takes it for a contact of its own agents, and every peer hears,
/// so a host carrying on regardless can't keep it from them.
async fn retire(
    State(host): State<Arc<Host>>,
    Json(notice): Json<RetirementNotice>,
) -> Result<Json<RetirementTaken>, ApiError> {
    let agent = claimed_retired_agent(&notice.retirement)?;
    let row = sqlx::query(
        "SELECT owner_identity, identity, binding, retirement_final_at FROM agents WHERE id = $1",
    )
    .bind(agent.as_str())
    .fetch_optional(&host.db)
    .await?;
    let Some(row) = row else {
        changes::take_stop(&host, &notice).await?;
        return Ok(Json(RetirementTaken { final_at: None }));
    };
    let owner_identity: String = row.try_get("owner_identity")?;
    let owner = Identity::from_encoded(&owner_identity)?;
    let retirement = VerifiedRetirement::verify(&notice.retirement, &owner)?;
    let final_at = host.clock.now_for_sql().await.saturating_add(window_secs());
    let mut transaction = database::begin(&host.db).await?;
    let taken = sqlx::query(
        "UPDATE agents SET retirement = $1, retirement_final_at = $3
         WHERE id = $2 AND retirement IS NULL",
    )
    .bind(retirement.compact())
    .bind(retirement.agent().as_str())
    .bind(final_at)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        > 0;
    delivery::end_queued_from(&mut transaction, retirement.agent()).await?;
    // Passed on only the first time it's taken. A moved agent is held on the host it left as well as
    // this one, and each passes it to the other, so passing on a repeat would go back and forth.
    if taken {
        let carried = RetirementNotice {
            retirement: retirement.compact().to_owned(),
            owner_identity,
            agent_identity: row.try_get("identity")?,
            binding: row.try_get("binding")?,
        };
        changes::queue_stop(&host, &mut transaction, retirement.agent(), &carried).await?;
    }
    transaction.commit().await?;
    let final_at = row
        .try_get::<Option<i64>, _>("retirement_final_at")?
        .unwrap_or(final_at);
    Ok(Json(RetirementTaken {
        final_at: u64::try_from(final_at).ok(),
    }))
}

/// Takes a recovery of an ID this host has an agent or an owner for, or any newer copy of an owner's ID.
/// A recovery is authorized by the backup key the ID committed to, and a key added or removed by a key
/// that counted, and nothing else, so anyone can carry one here and nobody else can make one. A copy of
/// an owner that parts ways with the one held and doesn't win is `409 stale`: the page signs again on
/// top of what's held. A copy that only adds or removes keys goes through [`owner_keys`].
///
/// A recovered owner's old key stops counting at once, along with the rules it signed, which may be a
/// thief's. A recovered agent's old key stops at once too, and what it had queued ends with it, as with
/// a retirement. Hearing the same one twice changes nothing.
///
/// A recovery of an owner also undoes what their old key can't be trusted to have meant, for as long as
/// [`RECOVERY_WINDOW_SECS`] has not passed: a retirement, a move of one of their agents to someone else,
/// and a replaced key on an agent, which takes the agent's backup, kept on the same device. The agent
/// stays stopped until the owner's new key signs for it, so one retired for a stolen key doesn't come
/// back by itself.
async fn recover(
    State(host): State<Arc<Host>>,
    Json(notice): Json<RecoveryNotice>,
) -> Result<(), ApiError> {
    take_identity(&host, &Identity::from_encoded(&notice.identity)?).await
}

/// [`recover`], for a newer copy of an ID that arrived some other way, such as with an owner's list.
pub async fn take_identity(host: &Host, new: &Identity) -> Result<(), ApiError> {
    let id = new.id().as_str();
    let listed = changes::learn_listed_owner(host, new).await?;
    let now = host.clock.now_for_sql().await;
    let mut transaction = database::begin(&host.db).await?;
    let list_changed = owner_keys::list_owner_changed(&mut transaction, new).await?;
    let rows = sqlx::query(
        "SELECT id, owner_id, identity, owner_identity, retirement_final_at, moved_from_owner,
             moved_from_owner_identity, moved_from_identity, moved_at, identity_before_recovery,
             identity_recovered_at, won_back
         FROM agents
         WHERE (id = $1 OR owner_id = $1 OR moved_from_owner = $1)
             AND (retirement IS NULL OR retirement_final_at > $2) FOR UPDATE",
    )
    .bind(id)
    .bind(now)
    .fetch_all(&mut *transaction)
    .await?;
    if rows.is_empty() {
        transaction.commit().await?;
        return match listed {
            // As for an agent's owner here: the page signs again on top of what's held.
            changes::Listed::Forked => Err(ApiError::Stale),
            changes::Listed::Taken => Ok(()),
            changes::Listed::NotNamed if list_changed => Ok(()),
            changes::Listed::NotNamed => Err(ApiError::NotFound),
        };
    }
    let mut anything_new = list_changed;
    let mut touched = Vec::new();
    for row in &rows {
        let agent: SplintId = serde_json::from_value(serde_json::Value::String(row.try_get("id")?))
            .map_err(|_| Error::Malformed)?;
        anything_new |= if agent.as_str() == id {
            agent_recovered(&mut transaction, &agent, new, row, now).await?
        } else if row.try_get::<String, _>("owner_id")? == id {
            owner_recovered(&mut transaction, &agent, new, row, now).await?
        } else {
            moved_from_owner_recovered(&mut transaction, &agent, new, row, now).await?
        };
        touched.push(agent);
    }
    if anything_new {
        let touched: Vec<&str> = touched.iter().map(SplintId::as_str).collect();
        changes::queue_recovery(host, &mut transaction, new, &touched).await?;
    }
    transaction.commit().await?;
    tracing::warn!(id, "took a recovery");
    Ok(())
}

/// A stop waiting to become final goes on regardless, and so does the place a recovery of the owner put
/// this agent back to, or a thief with its backup could take it again by asking twice. Whoever comes
/// back under the owner's new key brings their copy of the ID then.
async fn agent_recovered(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
    new: &Identity,
    row: &sqlx::postgres::PgRow,
    now: i64,
) -> Result<bool, ApiError> {
    if row.try_get::<bool, _>("won_back")?
        || row
            .try_get::<Option<i64>, _>("retirement_final_at")?
            .is_some()
    {
        return Ok(false);
    }
    let held_text: String = row.try_get("identity")?;
    let held = Identity::from_encoded(&held_text)?;
    if !new.extends(&held) {
        return Err(ApiError::Forbidden("that isn't later than what's held"));
    }
    if new.recoveries() <= held.recoveries() {
        return Ok(false);
    }
    let before = recent_identity(row, now)?;
    let window_open = before.is_some();
    sqlx::query(
        "UPDATE agents SET identity = $2, identity_before_recovery = $3,
             identity_recovered_at = CASE WHEN $4 THEN identity_recovered_at ELSE $5 END
         WHERE id = $1",
    )
    .bind(agent.as_str())
    .bind(new.encoded())
    .bind(before.unwrap_or(held_text))
    .bind(window_open)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    // A move that keeps the key, as when an owner takes up an agent, leaves nothing it signed in doubt.
    if new.sole_key().ok() != held.sole_key().ok() {
        delivery::end_queued_from(transaction, agent).await?;
    }
    Ok(true)
}

async fn owner_recovered(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
    new: &Identity,
    row: &sqlx::postgres::PgRow,
    now: i64,
) -> Result<bool, ApiError> {
    let held = Identity::from_encoded(&row.try_get::<String, _>("owner_identity")?)?;
    // A copy that parts ways with the one held and doesn't win is signed again on top of it, or
    // settled by a recovery.
    if !owner_keys::replaces(new, &held)? {
        return Ok(false);
    }
    if new.recoveries() <= held.recoveries() {
        owner_keys::agent_owner_changed(transaction, agent, &held, new).await?;
        return Ok(true);
    }
    let retiring = row
        .try_get::<Option<i64>, _>("retirement_final_at")?
        .is_some();
    let key_replaced = recent_identity(row, now)?;
    let undid_something = retiring || key_replaced.is_some();
    // A thief could have signed a statement or a revocation dated as far ahead as they liked, so
    // nothing the old key signed gets to hold back what the new one signs.
    sqlx::query(
        "UPDATE agents SET owner_identity = $2, binding_seq = 0, retirement = NULL,
             retirement_final_at = NULL,
             revocation = CASE WHEN $3 THEN $4 END,
             revoked_seq = CASE WHEN $3 THEN 0::BIGINT END,
             identity = COALESCE($5, identity),
             history = CASE WHEN $5 IS NULL THEN history ELSE '' END,
             won_back = $5 IS NOT NULL,
             identity_before_recovery = NULL, identity_recovered_at = NULL
         WHERE id = $1",
    )
    .bind(agent.as_str())
    .bind(new.encoded())
    .bind(undid_something)
    .bind(STOPPED_UNTIL_SIGNED)
    .bind(key_replaced)
    .execute(&mut **transaction)
    .await?;
    forget_rules(transaction, agent).await?;
    if undid_something {
        delivery::end_queued_from(transaction, agent).await?;
        tracing::warn!(%agent, "a recovery of its owner undid what their old key signed");
    }
    Ok(true)
}

/// An owner's recovery in time takes back an agent their old key moved to someone else, with whatever
/// has been signed for it since, and puts its ID back as it was before that. Whoever it was moved to
/// keeps nothing here. So a real sale is only sure once this has run out, and a seller who recovers
/// within it gets the agent back stopped, and needs the backup they gave away to go any further.
async fn moved_from_owner_recovered(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &SplintId,
    new: &Identity,
    row: &sqlx::postgres::PgRow,
    now: i64,
) -> Result<bool, ApiError> {
    if !is_within_window(row.try_get("moved_at")?, now) {
        return Ok(false);
    }
    let held = Identity::from_encoded(&row.try_get::<String, _>("moved_from_owner_identity")?)?;
    if !new.replaces(&held).unwrap_or(false) || new.recoveries() <= held.recoveries() {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE agents SET owner_id = $2, owner_identity = $3, binding = '', binding_seq = 0,
             identity = moved_from_identity, history = '', retirement = NULL,
             retirement_final_at = NULL, revocation = $4, revoked_seq = 0, won_back = TRUE,
             moved_from_owner = NULL, moved_from_owner_identity = NULL,
             moved_from_identity = NULL, moved_at = NULL,
             identity_before_recovery = NULL, identity_recovered_at = NULL
         WHERE id = $1",
    )
    .bind(agent.as_str())
    .bind(new.id().as_str())
    .bind(new.encoded())
    .bind(STOPPED_UNTIL_SIGNED)
    .execute(&mut **transaction)
    .await?;
    forget_rules(transaction, agent).await?;
    admission::forget_for_new_owner(transaction, agent).await?;
    inbox::clear_for_new_owner(transaction, agent).await?;
    requests::hide_from_new_owner(transaction, agent).await?;
    delivery::end_queued_from(transaction, agent).await?;
    tracing::warn!(%agent, "a recovery of its old owner took back an agent moved away");
    Ok(true)
}

/// Takes an owner's word that this agent acts for nobody now. It can't authenticate, send or be found
/// until its owner signs a newer statement, and what it queued ends with it, as with a retirement.
async fn revoke(
    State(host): State<Arc<Host>>,
    Json(notice): Json<RevocationNotice>,
) -> Result<(), ApiError> {
    let agent = claimed_released_agent(&notice.revocation)?;
    let row = sqlx::query("SELECT owner_identity, binding_seq FROM agents WHERE id = $1")
        .bind(agent.as_str())
        .fetch_optional(&host.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let owner = Identity::from_encoded(&row.try_get::<String, _>("owner_identity")?)?;
    let release = VerifiedRelease::verify(&notice.revocation, &owner, &agent)?;
    let held_seq = u64::try_from(row.try_get::<i64, _>("binding_seq")?).unwrap_or(u64::MAX);
    if release.to().is_some() || release.seq() <= held_seq {
        return Err(ApiError::Forbidden("that doesn't revoke what's held"));
    }
    let mut transaction = database::begin(&host.db).await?;
    sqlx::query(
        "UPDATE agents SET revocation = $2, revoked_seq = $3
         WHERE id = $1 AND (revoked_seq IS NULL OR revoked_seq < $3)",
    )
    .bind(agent.as_str())
    .bind(release.compact())
    .bind(i64::try_from(release.seq()).map_err(|_| Error::Malformed)?)
    .execute(&mut *transaction)
    .await?;
    delivery::end_queued_from(&mut transaction, &agent).await?;
    transaction.commit().await?;
    Ok(())
}

/// What an owner signed about one of this host's agents, to pass on with its messages.
pub async fn record_of(host: &Host, agent: &SplintId) -> Result<SenderRecord, sqlx::Error> {
    let row = sqlx::query("SELECT owner_identity, binding FROM agents WHERE id = $1")
        .bind(agent.as_str())
        .fetch_optional(&host.db)
        .await?;
    let Some(row) = row else {
        return Ok(SenderRecord::default());
    };
    Ok(SenderRecord {
        owner_identity: row.try_get("owner_identity")?,
        binding: row.try_get("binding")?,
        ..SenderRecord::default()
    })
}

/// Whether this agent is still as it was when its message was checked, with the same identity and
/// neither retired nor revoked, keeping it that way until the transaction ends. So a message accepted
/// under this is in the table by the time a retirement or a recovery goes looking for it.
pub async fn hold_off_retirement(
    transaction: &mut Transaction<'_, Postgres>,
    agent: &Identity,
) -> Result<bool, sqlx::Error> {
    let row =
        sqlx::query(
            "SELECT 1 AS here FROM agents
             WHERE id = $1 AND identity = $2 AND retirement IS NULL AND revocation IS NULL FOR SHARE",
        )
        .bind(agent.id().as_str())
        .bind(agent.encoded())
        .fetch_optional(&mut **transaction)
        .await?;
    Ok(row.is_some())
}

/// The identity of an agent registered on this host, if it is one, is neither retired nor revoked, and
/// hasn't moved to another host. This is the copy that counts, so a key its ID gave up can't sign
/// anything in here, and mail for an agent that left isn't taken to sit unread.
pub async fn identity_of(host: &Host, agent: &SplintId) -> Result<Option<Identity>, ApiError> {
    identity_where(host, agent, false).await
}

/// The same for an agent its owner revoked, which stays up to hear from them, so its Signet can still
/// learn what its owner's keys are now.
pub async fn identity_even_if_revoked(
    host: &Host,
    agent: &SplintId,
) -> Result<Option<Identity>, ApiError> {
    identity_where(host, agent, true).await
}

async fn identity_where(
    host: &Host,
    agent: &SplintId,
    revoked_too: bool,
) -> Result<Option<Identity>, ApiError> {
    let row = sqlx::query(
        "SELECT identity FROM agents
         WHERE id = $1 AND retirement IS NULL AND ($2 OR revocation IS NULL)
             AND moved_away_to IS NULL",
    )
    .bind(agent.as_str())
    .bind(revoked_too)
    .fetch_optional(&host.db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(Identity::from_encoded(
        &row.try_get::<String, _>("identity")?,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_signup_is_off_unless_its_exactly_yes() {
        assert!(!open_signup_from(None).unwrap());
        assert!(!open_signup_from(Some("")).unwrap());
        assert!(open_signup_from(Some("yes")).unwrap());
        assert!(open_signup_from(Some("true")).is_err());
    }

    #[test]
    fn a_source_is_what_the_proxy_wrote_and_one_network_counts_once() {
        let from = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(FORWARDED_FOR, value.parse().unwrap());
            source_of(&headers)
        };
        assert_eq!(source_of(&HeaderMap::new()), "");
        assert_eq!(from("203.0.113.9"), "203.0.113.9");
        // Only the proxy writes the last entry.
        assert_eq!(from("198.51.100.1, 203.0.113.9"), "203.0.113.9");
        assert_eq!(from("not an address"), "");
        assert_eq!(from("2001:db8:1:2:3:4:5:6"), from("2001:db8:1:2:9:9:9:9"));
        assert_ne!(from("2001:db8:1:2::1"), from("2001:db8:1:3::1"));
        assert_eq!(from("::ffff:203.0.113.9"), "203.0.113.9");
    }

    #[test]
    fn a_host_wont_take_a_signup_code_short_enough_to_guess() {
        let long = "a".repeat(MIN_SIGNUP_CODE_CHARS);
        assert_eq!(usable_signup_codes(&long).unwrap(), [long.as_str()]);
        assert!(usable_signup_codes("").unwrap().is_empty());
        let short = "a".repeat(MIN_SIGNUP_CODE_CHARS - 1);
        assert!(usable_signup_codes(&format!("{long},{short}")).is_err());
    }
}

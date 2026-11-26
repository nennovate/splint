//! What whoever runs a host types at it, and what it says back: `check`, `codes`, `counts`, `key` and
//! `close`, and the sentence a host stops with.
//!
//! Like `owner-key` and `splint`, the one-shots write to stdout because someone is reading. Each
//! runs beside a running host, with that host's settings, and none of them restarts it: `check`
//! and `counts` change nothing, `codes` writes rows the running host reads on every join, and `key` (in
//! `own_id::commands`) changes files the running host reads again every couple of seconds, and
//! `close` (in `closing`) writes the one row the running host reads every couple of seconds too.

use std::env;
use std::error::Error;
use std::fmt;
use std::io::{self, Write};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use splint_core::signup_id;
use splint_core::transport::Scheme;
use sqlx::PgPool;

use crate::closing::USAGE as CLOSE_USAGE;
use crate::own_id::commands::USAGE as KEY_USAGE;
use crate::{closing, counts, database, own_id, registry};

pub const USAGE: &str = "\
splint-host                 Runs the host, with the settings in its environment.
splint-host check           Reads every setting as a start does, and says which is wrong and why.
                            It changes nothing, so it's safe beside a running host.
splint-host codes add N     Makes N signup codes and prints them, one a line. The running host
                            takes them at once, with no restart. Each lets one agent in, once.
splint-host codes list      Prints every signup code: those still unused first, one a line, then
                            the spent ones, each followed by the word spent.
splint-host counts          Prints how many agents, owners and other hosts use this host, each
                            number under a fixed label. It reads only this host's database, writes
                            nothing and calls out to nothing, and never prints an ID or a name.";

/// A code is 16 random bytes in hex, which is the shortest a host takes.
const CODE_BYTES: usize = 16;
/// More at once than anyone hands out, and few enough to read.
const MAX_CODES_AT_ONCE: u32 = 1000;
const SPENT: &str = "spent";

/// Why the host or a one-shot stopped. A `main` that returns an error prints it in debug form, and
/// the person reading needs the sentence, so this prints whatever it holds as its sentence.
pub struct Stopped(Box<dyn Error>);

impl fmt::Debug for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<E: Error + 'static> From<E> for Stopped {
    fn from(error: E) -> Self {
        Self(Box::new(error))
    }
}

/// What's wrong with one setting, by its name. A value is never repeated here, as some are secret.
#[derive(Debug, thiserror::Error)]
pub enum SettingError {
    #[error("{0} isn't set, and a host needs it")]
    NotSet(&'static str),
    #[error(
        "{0} has to be host names with commas between them and nothing else, such as host.example"
    )]
    NotHostNames(&'static str),
    #[error("{0} has to be this host's name and nothing else, such as host.example")]
    NotAHostName(&'static str),
    #[error("{0}: {1}")]
    Refused(&'static str, Box<dyn Error>),
    #[error("{0} has to be a whole number of seconds, at least 1")]
    NotSeconds(&'static str),
    #[error("{0} is either yes or not set")]
    NotYes(&'static str),
    #[error("{0} names {1}, and that couldn't be listened on: {2}")]
    CantListen(&'static str, String, io::Error),
}

impl SettingError {
    pub fn refused(setting: &'static str, why: impl Error + 'static) -> Self {
        Self::Refused(setting, Box::new(why))
    }
}

/// A setting a host can't start without.
pub fn required(setting: &'static str) -> Result<String, SettingError> {
    env::var(setting).map_err(|_| SettingError::NotSet(setting))
}

/// Off unless it's exactly yes, and a mistyped word stops the host rather than leaving it unclear.
pub fn yes_or_unset(setting: &'static str) -> Result<bool, SettingError> {
    match env::var(setting).ok().as_deref() {
        None | Some("") => Ok(false),
        Some("yes") => Ok(true),
        Some(_) => Err(SettingError::NotYes(setting)),
    }
}

#[derive(Debug, thiserror::Error)]
enum CommandError {
    #[error("that isn't something splint-host does:\n\n{USAGE}\n{KEY_USAGE}\n{CLOSE_USAGE}")]
    Usage,
    #[error("codes add takes how many to make, from 1 to {MAX_CODES_AT_ONCE}")]
    HowMany,
    #[error(
        "this host hasn't started on its database yet, so there's nothing there yet: start it \
         once, then run this again"
    )]
    NeverStarted,
    #[error("this machine couldn't make a random code")]
    NoRandomness,
    #[error("couldn't write to the terminal: {0}")]
    Output(#[from] io::Error),
    #[error("the database refused that: {0}")]
    Database(#[from] sqlx::Error),
}

pub async fn run(command: &[&str]) -> Result<(), Stopped> {
    match command {
        ["check"] => check().await,
        ["codes", "add", count] => {
            let count = count
                .parse()
                .ok()
                .filter(|count| (1..=MAX_CODES_AT_ONCE).contains(count))
                .ok_or(CommandError::HowMany)?;
            Ok(add_codes(&started_database().await?, count).await?)
        }
        ["codes", "list"] => Ok(list_codes(&started_database().await?).await?),
        ["counts"] => Ok(say(&counts::lines(&started_database().await?)
            .await
            .map_err(CommandError::Database)?)?),
        ["key", ..] => Ok(own_id::commands::run(command)?),
        ["close", ..] => Ok(closing::run(command).await?),
        ["help" | "--help" | "-h"] => Ok(say(&format!("{USAGE}\n{KEY_USAGE}\n{CLOSE_USAGE}"))?),
        _ => Err(CommandError::Usage.into()),
    }
}

fn say(line: &str) -> Result<(), CommandError> {
    Ok(writeln!(io::stdout(), "{line}")?)
}

/// Everything a start reads and refuses, in the order a start does, and nothing a start changes: no
/// table is made, no key is written and no port is taken, so the host running beside it carries on.
async fn check() -> Result<(), Stopped> {
    let settings = crate::settings()?;
    registry::usable_signup_codes(&env::var(registry::SIGNUP_CODES_SETTING).unwrap_or_default())?;
    let db = database::connect(
        &settings.database_url,
        settings.scheme,
        database::ONE_SHOT_PATIENCE,
    )
    .await?;
    own_id::check(
        &own_id::Files::beside(&settings.key_file),
        own_id::kept(&db).await?,
        own_id::NewKey {
            used: own_id::has_been_used(&db).await?,
            allowed: settings.new_host_key,
        },
    )?;
    Ok(say("Every setting is one this host can start with.")?)
}

/// Only what reaching the database takes, so a one-shot says nothing about settings it doesn't use.
/// The host makes its tables as it starts, so one that never has has nothing to read or add to.
async fn started_database() -> Result<PgPool, Stopped> {
    let scheme = Scheme::from_env()?;
    let db = database::connect(
        &required(database::SETTING)?,
        scheme,
        database::ONE_SHOT_PATIENCE,
    )
    .await?;
    let started: bool = sqlx::query_scalar("SELECT to_regclass('signup_codes') IS NOT NULL")
        .fetch_one(&db)
        .await
        .map_err(CommandError::Database)?;
    if !started {
        return Err(CommandError::NeverStarted.into());
    }
    Ok(db)
}

fn new_code() -> Result<String, CommandError> {
    let mut raw = [0u8; CODE_BYTES];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| CommandError::NoRandomness)?;
    Ok(raw.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// All of them or none, so what's printed is exactly what the host now takes.
async fn add_codes(db: &PgPool, count: u32) -> Result<(), CommandError> {
    let codes: Vec<String> = (0..count).map(|_| new_code()).collect::<Result<_, _>>()?;
    let mut adding = database::begin(db).await?;
    for code in &codes {
        sqlx::query("INSERT INTO signup_codes (id, code) VALUES ($1, $2)")
            .bind(signup_id(code))
            .bind(code)
            .execute(&mut *adding)
            .await?;
    }
    adding.commit().await?;
    say(&codes.join("\n"))
}

async fn list_codes(db: &PgPool) -> Result<(), CommandError> {
    let codes: Vec<(String, bool)> = sqlx::query_as(
        "SELECT code, used_by IS NOT NULL FROM signup_codes ORDER BY used_by IS NOT NULL, id",
    )
    .fetch_all(db)
    .await?;
    for (code, spent) in codes {
        if spent {
            say(&format!("{code}\t{SPENT}"))?;
        } else {
            say(&code)?;
        }
    }
    Ok(())
}

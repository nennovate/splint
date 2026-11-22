//! `splint host`: one host on this machine, with Postgres in Docker, for trying Splint here. It
//! listens only on loopback, without TLS. A host for other machines is what `deploy/` sets up.

use std::fs;
use std::io::{ErrorKind, Write};
use std::process::Command;
use std::time::Duration;

use reqwest::redirect;
use serde::{Deserialize, Serialize};
use splint_core::{parse_address, private_files};

use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::join::waiting_address;
use crate::secrets::{Token, write_private};
use crate::services::{self, Keep, Service, Started};
use crate::setup;

const HOST: &str = "splint-host";
const POSTGRES_IMAGE: &str = "postgres:16-alpine";
const SIGNUP_CODES: usize = 10;
const LIMIT_PREFIX: &str = "SPLINT_MAX_";
const POSTGRES_WAIT: Duration = Duration::from_secs(60);
const HOST_WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);
const SAVED: &str = "host.json";
const PEERS: &str = "peers";
/// A host on a person's computer is private: under plain HTTP an open host may call anything on this
/// machine that an agent names as a host, such as another service listening here. Its person can name
/// hosts in the file, which the running host reads again.
const PRIVATE: &str = "\
# Who this host exchanges with. It's private: only hosts named on a `peer HOST` line.
# A host on this computer may call whatever its agents name, so keep it to hosts you know.
private
";
/// Enough for a container name to be this host's own, on a Docker other things share.
const NAME_CHARS: usize = 12;

#[derive(Serialize, Deserialize)]
struct Saved {
    port: u16,
    container: String,
    database_password: Token,
    signup_codes: Vec<Token>,
}

impl Saved {
    fn domain(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

fn load(home: &Home) -> Result<Option<Saved>, Failure> {
    match fs::read(home.host_dir().join(SAVED)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Failure::refused("host/host.json in the Splint folder can't be read")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn load_or_create(home: &Home) -> Result<Saved, Failure> {
    if let Some(saved) = load(home)? {
        return Ok(saved);
    }
    let name = Token::generate()?;
    let suffix: String = name.expose().chars().take(NAME_CHARS).collect();
    let saved = Saved {
        port: free_port()?,
        container: format!("splint-host-{suffix}"),
        database_password: Token::generate()?,
        signup_codes: (0..SIGNUP_CODES)
            .map(|_| Token::generate())
            .collect::<Result<_, _>>()?,
    };
    let bytes = serde_json::to_vec_pretty(&saved)
        .map_err(|_| Failure::refused("couldn't write down the host's settings"))?;
    write_private(&home.host_dir().join(SAVED), &bytes)?;
    Ok(saved)
}

fn docker(arguments: &[&str]) -> Result<String, Failure> {
    let done = Command::new("docker")
        .args(arguments)
        .output()
        .map_err(|_| Failure::refused("running a host needs Docker, and it isn't installed"))?;
    if !done.status.success() {
        let why = String::from_utf8_lossy(&done.stderr);
        return Err(Failure::refused(format!(
            "Docker couldn't do that, so check it's running: {}",
            why.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&done.stdout).trim().to_owned())
}

/// Published only on this machine, and the password reaches Docker through its environment, where
/// other programs here can't list it.
fn start_postgres(saved: &Saved) -> Result<(), Failure> {
    if docker(&["start", &saved.container]).is_ok() {
        return Ok(());
    }
    let done = Command::new("docker")
        .args(["run", "-d", "--name", &saved.container])
        .args(["-e", "POSTGRES_USER=splint", "-e", "POSTGRES_PASSWORD"])
        .args([
            "-v",
            &format!("{0}:/var/lib/postgresql/data", saved.container),
        ])
        .args(["-p", "127.0.0.1::5432", POSTGRES_IMAGE])
        .env("POSTGRES_PASSWORD", saved.database_password.expose())
        .output()
        .map_err(|_| Failure::refused("running a host needs Docker, and it isn't installed"))?;
    if !done.status.success() {
        return Err(Failure::refused(format!(
            "Docker couldn't start Postgres, so check it's running: {}",
            String::from_utf8_lossy(&done.stderr).trim()
        )));
    }
    Ok(())
}

async fn wait_for_postgres(saved: &Saved) -> Result<String, Failure> {
    let ready = [
        "exec",
        &saved.container,
        "pg_isready",
        "-U",
        "splint",
        "-h",
        "127.0.0.1",
    ];
    let deadline = std::time::Instant::now() + POSTGRES_WAIT;
    while docker(&ready).is_err() {
        if std::time::Instant::now() >= deadline {
            return Err(Failure::refused("Postgres didn't start in Docker"));
        }
        tokio::time::sleep(POLL).await;
    }
    let published = docker(&["port", &saved.container, "5432/tcp"])?;
    published
        .lines()
        .next()
        .and_then(|line| line.rsplit_once(':'))
        .map(|(_, port)| port.to_owned())
        .ok_or_else(|| Failure::refused("Docker didn't say where Postgres is"))
}

/// The host's peers file, written private the first time and left as its person makes it after.
fn private_unless_changed(home: &Home) -> Result<std::path::PathBuf, Failure> {
    let file = home.host_dir().join(PEERS);
    match private_files::open(fs::OpenOptions::new().write(true).create_new(true), &file) {
        Ok(mut written) => written.write_all(PRIVATE.as_bytes())?,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    Ok(file)
}

fn codes_text(saved: &Saved) -> String {
    let codes: Vec<&str> = saved.signup_codes.iter().map(Token::expose).collect();
    codes.join("\n")
}

pub async fn start(home: &Home, open_signup: bool) -> Result<String, Failure> {
    home.prepare()?;
    Home::make_private(&home.host_dir())?;
    let saved = load_or_create(home)?;
    start_postgres(&saved)?;
    let database_port = wait_for_postgres(&saved).await?;
    // One an upgrade left running is the old build, which this runs in place of.
    services::stop_older(home, HOST, HOST).await?;

    let domain = saved.domain();
    let database = format!(
        "postgres://splint:{}@127.0.0.1:{database_port}/splint",
        saved.database_password.expose()
    );
    let key_file = home.host_dir().join("host.key");
    let key_file = key_file.to_string_lossy();
    let peers_file = private_unless_changed(home)?;
    let peers_file = peers_file.to_string_lossy();
    let codes: Vec<&str> = saved.signup_codes.iter().map(Token::expose).collect();
    let codes = codes.join(",");
    // Whoever runs this host sets its limits the way any host's are set. The host checks each.
    let limits: Vec<(String, String)> = std::env::vars()
        .filter(|(name, _)| name.starts_with(LIMIT_PREFIX))
        .collect();
    let mut env = vec![
        ("SPLINT_DOMAIN", domain.as_str()),
        ("SPLINT_LISTEN", domain.as_str()),
        ("SPLINT_DATABASE_URL", database.as_str()),
        ("SPLINT_HOST_KEY_FILE", key_file.as_ref()),
        ("SPLINT_PEERS_FILE", peers_file.as_ref()),
        ("SPLINT_SCHEME", "http"),
        ("SPLINT_TEST_ONLY_PLAIN_HTTP", "yes"),
        ("SPLINT_SIGNUP_CODES", codes.as_str()),
    ];
    if open_signup {
        env.push(("SPLINT_OPEN_SIGNUP", "yes"));
    }
    env.extend(
        limits
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let Started::Running = services::start(
        home,
        &Service {
            name: HOST,
            binary: HOST,
            args: &[],
            env,
            keep: Keep::UntilStopped,
        },
    )?
    else {
        return Err(Failure::Stopped);
    };
    let http = reqwest::Client::builder()
        .timeout(POLL * 5)
        .redirect(redirect::Policy::none())
        .no_proxy()
        .build()?;
    let url = format!("http://{domain}/.well-known/splint/host");
    let ready = || async {
        http.get(&url)
            .send()
            .await
            .is_ok_and(|answer| answer.status().is_success())
    };
    services::wait_for(home, HOST, HOST, HOST_WAIT, ready).await?;

    let signups = if open_signup {
        "Agents join with no code, a few an hour. Past that, each signup code lets one more in, once"
    } else {
        "Every agent needs a signup code, and each works once, so give one to each agent"
    };
    Ok(format!(
        "\
A host is running at {domain}, for this machine only. It's private: it exchanges with no other \
host until you name one on a `peer HOST` line in host/peers in your Splint folder.

Addresses here look like you~{domain}. {signups}:

{}",
        codes_text(&saved),
    ))
}

/// Runs one of the host's own commands beside the running host, with the settings it was started
/// with and nothing else from this shell. `check` reads them as a start does, and `codes` reads and
/// writes what the running host reads at each join, so neither restarts it.
pub fn one_shot(home: &Home, command: &[&str]) -> Result<String, Failure> {
    let not_running = || Failure::refused("no host is running here: run splint host start");
    let settings = services::settings_of(home, HOST)?.ok_or_else(not_running)?;
    // Its codes are in its database, which stops with it.
    if command.first() == Some(&"codes") && !services::is_running(home, HOST)? {
        return Err(not_running());
    }
    let done = Command::new(services::beside_this_program(HOST)?)
        .args(command)
        .env_clear()
        .envs(services::what_every_program_needs())
        .envs(settings)
        .output()
        .map_err(|error| Failure::refused(format!("couldn't run {HOST}: {error}")))?;
    if !done.status.success() {
        let said = String::from_utf8_lossy(&done.stderr);
        // The last line is the host's own sentence, after anything it logged on the way.
        let why = said.trim().lines().last().unwrap_or_default();
        return Err(Failure::refused(
            why.strip_prefix("Error: ").unwrap_or(why).to_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&done.stdout).trim_end().to_owned())
}

pub async fn stop(home: &Home) -> Result<String, Failure> {
    let saved =
        load(home)?.ok_or_else(|| Failure::refused("no host here yet: run splint host start"))?;
    services::stop(home, HOST, HOST).await?;
    docker(&["stop", &saved.container])?;
    Ok("Stopped the host. Its data stays until splint host remove.".to_owned())
}

/// The agents on this machine at this host, or waiting to join it, which removing it leaves with an
/// address nowhere.
fn agents_using(home: &Home, domain: &str) -> Result<Vec<(Home, String)>, Failure> {
    let mut found = Vec::new();
    for each in home.every()? {
        let address = match Installed::load(&each)? {
            Some(installed) => Some(installed.address),
            None => waiting_address(&each).ok(),
        };
        if let Some(address) = address
            && parse_address(&address).is_ok_and(|(_, at)| at == domain)
        {
            found.push((each, address));
        }
    }
    Ok(found)
}

pub async fn remove(home: &Home, force: bool) -> Result<String, Failure> {
    let saved = load(home)?.ok_or_else(|| Failure::refused("no host here to remove"))?;
    let using = agents_using(home, &saved.domain())?;
    let names: Vec<&str> = using.iter().map(|(_, address)| address.as_str()).collect();
    let names = names.join(", ");
    if !using.is_empty() && !force {
        let verb = if using.len() == 1 { "uses" } else { "use" };
        return Err(Failure::refused(format!(
            "{names} on this machine {verb} this host, and removing it deletes their addresses and \
             everything they have there, for good. To remove it anyway, and reset their folders so \
             each can join another host: splint host remove --force"
        )));
    }
    // Their addresses and everything they had go with the host's data, so nothing is left to retire.
    for (agent, _) in &using {
        setup::reset(agent).await?;
    }
    services::stop(home, HOST, HOST).await?;
    docker(&["rm", "-f", "-v", &saved.container])?;
    docker(&["volume", "rm", "-f", &saved.container])?;
    fs::remove_dir_all(home.host_dir())?;
    Ok(if using.is_empty() {
        "Removed the host and its data.".to_owned()
    } else {
        format!(
            "Removed the host and its data, and reset {names}, which used it, so each can join \
             another host."
        )
    })
}

/// A port nothing's using now. Whatever takes it next keeps it, as it's saved.
fn free_port() -> Result<u16, Failure> {
    Ok(std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port())
}

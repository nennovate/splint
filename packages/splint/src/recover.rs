//! `splint recover ADDRESS`, typed by a person on a new computer after losing the one their sign-in
//! was on: with their recovery code, their owner ID comes back on this computer's sign-in, and each
//! agent that ran on the lost computer comes back here at its old ID and address.
//!
//! The code is typed at this terminal, hidden, and goes only to `owner-key`, which keeps it nowhere.
//! The owner's ID is found by the agent's address at its host; the owner's list, which the lost
//! computer kept at that host, by the handle the code gives. Hosts hear of the owner's recovery
//! before any agent's, so none undoes an agent's. Each agent brought back gets a new Signet, which
//! takes up its ID with new keys once its backup, from the list, signs a recovery naming them. One
//! prompt then signs, for every one of them, a new backup, its binding, default rules and a delegation,
//! and the list again. It only counts as back once its Signet says it's registered under the
//! recovered owner, and a run again does what's missing, with no code.
//!
//! Where the owner's sign-in is still here and only an agent's keys are gone, the same command puts that
//! agent on new keys, keeping its ID, address, rules and contacts, with no recovery code. Only Signet
//! can say a key is gone: anything that can be put right is refused in its words, and replacing what's
//! lost takes a typed yes, or `--replace-keys` with the address typed out again. A recovery of the owner
//! asks the same of any folder here that already holds an agent, and of the agent named on the command
//! line before the code is spent.
//!
//! Not built here: an agent that ran on another machine isn't signed for again. Its owner's recovery
//! stops it there until it is, so it's named, in those words, with its backup unchanged. Contacts in an
//! agent's rules don't come back (it starts with the defaults).

use std::io::IsTerminal as _;
use std::process::Command;

use serde::Deserialize;
use serde_json::json;
use splint_core::{AGENT_KEYS_LOST_EXIT, Identity, SplintId, canonical_address, parse_address};

use crate::authorize::{self, YES};
use crate::computer;
use crate::failure::Failure;
use crate::home::{Home, Installed, is_profile_name};
use crate::host_calls::{Delivered, HostCalls};
use crate::owner_key::{AgentBackup, OwnerKey, SignIn};
use crate::rules::first_rules;
use crate::services;
use crate::setup;
use crate::signet_api::SignetApi;

/// Why `splint recover` runs only in a terminal: the code it takes and the new one it shows own the ID.
const TERMINAL_ONLY: &str = "splint recover takes your recovery code, and shows you a new one, only in \
     a terminal you type in yourself. If you're an agent: your person runs this in their own terminal, \
     and never gives you their code";

/// Said on `splint recover` where no terminal can say yes, with the agent's address typed out again.
const REPLACE_KEYS: &str = "--replace-keys";

/// What `owner-key recover` printed.
#[derive(Deserialize)]
struct Recovered {
    identity: String,
    agents: Vec<Listed>,
    list_found: bool,
    code: String,
}

/// An agent the owner's list held, as `owner-key` kept it.
#[derive(Clone, Deserialize, serde::Serialize)]
struct Listed {
    agent: SplintId,
    address: String,
    label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    beside_owner: bool,
}

/// What `owner-key restore-agents` printed.
#[derive(Deserialize)]
struct Restored {
    agents: Vec<RestoredOne>,
    /// Those whose ID at their host commits to no backup kept here.
    #[serde(default)]
    not_ours: Vec<SplintId>,
    #[serde(default)]
    list: Option<String>,
}

#[derive(Deserialize)]
struct RestoredOne {
    agent: SplintId,
    identity: String,
    commitment: String,
    binding: String,
    rules: String,
    #[serde(default)]
    delegation: Option<String>,
}

/// One agent to bring back here, with the folder and Signet it now has.
struct Coming {
    listed: Listed,
    home: Home,
    installed: Installed,
    key: String,
    delegate: String,
    held: String,
}

pub async fn recover(
    home: &Home,
    address: &str,
    here: &[&str],
    replacing: Option<&str>,
) -> Result<String, Failure> {
    if replacing.is_none() && !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return Err(Failure::refused(TERMINAL_ONLY));
    }
    let home = home.the_default();
    let address = canonical_address(address).map_err(Failure::not_an_address)?;
    let (_, domain) = parse_address(&address).map_err(Failure::not_an_address)?;
    if replacing.is_some_and(|typed| typed != address) {
        return Err(Failure::refused(format!(
            "to replace this agent's keys, which can't be undone, type its own address: {} recover \
             {address} {REPLACE_KEYS} {address}",
            home.command()
        )));
    }
    if let Some(here) = with_its_owner_here(&home, &address)?
        && only_its_keys_are_lost(&here, &address).await
    {
        return new_keys(here, replacing.is_some()).await;
    }
    if replacing.is_some() {
        return Err(Failure::refused(format!(
            "{REPLACE_KEYS} is for an agent set up here with its owner's sign-in here too, so nothing \
             was replaced"
        )));
    }
    keys_of_the_one_named(&home, &address, domain).await?;
    let calls = HostCalls::new(domain)?;
    let owner = computer::owner_here(&home);
    Home::make_private(&home.computer_dir())?;
    let mut said = Vec::new();
    let (identity, agents, passphrase) = match owner.kept_identity() {
        Some(identity) => {
            let agents = kept_agents(&owner);
            if agents.is_empty() {
                return Err(Failure::refused(format!(
                    "this computer has an owner ID already, and no recovery to carry on with. If \
                     {address} lost its key files, this can only replace them on a computer that \
                     holds both that agent and your sign-in. Where it runs, put the real files back \
                     if you have them. If you don't, run splint for {address} retire on this \
                     computer, which takes it off its host for good, and have a new agent join"
                )));
            }
            said.push("Your owner ID is on this computer already, so this carries on.".to_owned());
            let passphrase = match owner.sign_in() {
                Some(SignIn::LockedFile) => Some(authorize::secret("Your sign-in's passphrase:")?),
                _ => None,
            };
            (identity, agents, passphrase)
        }
        None => {
            let (recovered, passphrase) = recover_owner(&owner, &calls, &address, domain).await?;
            // At once, before anything else can fail, so the person has it whatever happens next.
            authorize::say(&format!(
                "\nYour owner ID is on this computer now. Your new recovery code, shown this once:\n\n  \
                 {}\n\nWrite it down: your old code no longer works. Never give it to anyone, your \
                 agents included.\n",
                recovered.code
            ))?;
            if !recovered.list_found {
                said.push(format!(
                    "No list of your agents was found at {domain} for that code, so none was \
                     brought back. Your owner ID is recovered."
                ));
            }
            (recovered.identity, recovered.agents, passphrase)
        }
    };
    // The owner's recovery reaches every host before any agent's, or a host would undo the agent's, so
    // an agent waits for a host that couldn't be told.
    let mut hosts: Vec<String> = agents
        .iter()
        .filter_map(|one| {
            parse_address(&one.address)
                .ok()
                .map(|(_, at)| at.to_owned())
        })
        .chain([domain.to_owned()])
        .collect();
    hosts.sort();
    hosts.dedup();
    let mut untold = Vec::new();
    for host in hosts {
        let told = match HostCalls::new(&host) {
            Ok(at) => at.post_recovery(&identity).await,
            Err(failure) => Err(failure),
        };
        if !matches!(told, Ok(Delivered::Taken | Delivered::NoSuchAgent)) {
            said.push(format!(
                "{host} couldn't be told of your recovery just now: run this again later."
            ));
            untold.push(host);
        }
    }
    let recovered = Identity::from_encoded(&identity)?;
    let owner_id = recovered.id().clone();
    let mut coming = Vec::new();
    let mut back = Vec::new();
    for listed in &agents {
        let wanted = listed.beside_owner || here.contains(&listed.address.as_str());
        if !wanted {
            said.push(format!(
                "{} ran on another computer, so it wasn't brought back here, and it's stopped there \
                 until it's signed for again, which this can't do yet. Its backup wasn't changed, so \
                 whoever has your lost computer could still use it to take that agent. To move it \
                 here, where it works again and its copy on the other computer stops for good: \
                 splint recover {address} --here {}.",
                listed.address, listed.address
            ));
            continue;
        }
        if parse_address(&listed.address).is_ok_and(|(_, at)| untold.iter().any(|host| host == at))
        {
            said.push(format!(
                "{} wasn't brought back yet, as its host hasn't heard of your recovery.",
                listed.address
            ));
            continue;
        }
        if let Some(held) = is_back(&listed.address, &recovered).await {
            said.push(format!("{} is back already.", listed.address));
            back.push((listed.agent.clone(), listed.address.clone(), held));
            continue;
        }
        match bring_up(&home, listed, &identity).await {
            Ok(one) => coming.push(one),
            Err(failure) => said.push(format!("{} wasn't brought back: {failure}", listed.address)),
        }
    }
    let mut list = None;
    for batch in coming.chunks(MOST_IN_ONE_PROMPT) {
        let restored = restore_batch(&owner, domain, batch, &agents, passphrase.as_deref())?;
        for one in batch {
            if restored.not_ours.contains(&one.listed.agent) {
                said.push(format!(
                    "{} wasn't brought back: its ID at its host doesn't commit to the backup your \
                     list holds. Someone else may have recovered it, or its host is showing an old \
                     copy.",
                    one.listed.address
                ));
                continue;
            }
            let Some(signed) = restored
                .agents
                .iter()
                .find(|signed| signed.agent == one.listed.agent)
            else {
                continue;
            };
            match hand_back(one, signed, &identity, &owner_id).await {
                Ok(()) => {
                    let place = one
                        .home
                        .profile()
                        .map(|name| format!(", as the profile {name}"))
                        .unwrap_or_default();
                    said.push(format!(
                        "{} is back on this computer{place}.",
                        one.listed.address
                    ));
                    back.push((
                        one.listed.agent.clone(),
                        one.listed.address.clone(),
                        signed.identity.clone(),
                    ));
                }
                Err(failure) => said.push(format!(
                    "{} isn't confirmed back yet: {failure}. Run this again to finish.",
                    one.listed.address
                )),
            }
        }
        list = restored.list.or(list);
    }
    // A run cut off once its agents were back signed no list the new code finds, and this one has no
    // agent left to sign one with.
    if list.is_none() && !agents.is_empty() && !computer::list_kept_here(&home) {
        list = restore_batch(&owner, domain, &[], &agents, passphrase.as_deref())?.list;
    }
    computer::after_recovery(&home, domain, &back, list).await?;
    if !back.is_empty() {
        said.push(
            "Each agent brought back starts with your default rules and no contacts. Its contacts \
             see that your owner ID was recovered, and each one's person may need to approve that \
             once before their agent deals with yours again."
                .to_owned(),
        );
    }
    Ok(said.join("\n"))
}

/// An agent set up in a folder here, with the sign-in of the owner it acts for here too.
struct WithItsOwner {
    folder: Home,
    installed: Installed,
    agent: SplintId,
    owner: OwnerKey,
}

/// Whether what's wrong here is this agent's keys. The list of agents a recovery of its owner brought
/// back stays on this computer afterwards, so with one here it counts only once this agent is back
/// under that owner, and its Signet can't run on the keys it has. Anything else carries that recovery on.
async fn only_its_keys_are_lost(here: &WithItsOwner, address: &str) -> bool {
    if kept_agents(&here.owner).is_empty() {
        return true;
    }
    let owner = here.owner.kept_identity();
    let owner = owner.and_then(|identity| Identity::from_encoded(&identity).ok());
    let Some(owner) = owner else {
        return false;
    };
    if is_back(address, &owner).await.is_none() {
        return false;
    }
    match setup::start_signet(&here.folder, &here.installed, None).await {
        Err(Failure::SignetWontStart(_)) => true,
        Err(failure) if !setup::up_without_its_host(&failure) => false,
        _ => match SignetApi::new(&here.folder, &here.installed) {
            Ok(api) => api.who().await.is_ok_and(|who| who.recovering),
            Err(_) => false,
        },
    }
}

/// The agent at this address, if its owner's sign-in is here too.
fn with_its_owner_here(home: &Home, address: &str) -> Result<Option<WithItsOwner>, Failure> {
    let id_of = |identity: &str| {
        Identity::from_encoded(identity)
            .ok()
            .map(|id| id.id().clone())
    };
    for folder in home.every()? {
        let Some(installed) = Installed::load(&folder)? else {
            continue;
        };
        let Some(agent) = installed
            .agent
            .clone()
            .filter(|_| installed.address == address)
        else {
            continue;
        };
        let owner = match &installed.owner_elsewhere {
            Some(_) => computer::owner_here(home),
            None => OwnerKey::new(&folder),
        };
        let held = owner.kept_identity().and_then(|identity| id_of(&identity));
        let theirs = match &installed.owner_elsewhere {
            Some(identity) => held.is_some() && held == id_of(identity),
            None => held.is_some(),
        };
        if theirs {
            return Ok(Some(WithItsOwner {
                folder,
                installed,
                agent,
                owner,
            }));
        }
    }
    Ok(None)
}

/// Said of an agent whose keys turned out to be fine, so nothing of theirs was replaced.
fn keys_are_here(address: &str) -> String {
    format!("{address} still has its keys, so nothing was replaced.")
}

/// What Signet makes of the keys in a folder, asked before anything is replaced.
enum KeysThere {
    Fine,
    LostForGood,
    /// Something a person can put right, in Signet's own words.
    CanBePutRight(String),
}

/// Asks the program that holds the keys, as this one has no code to open them. `taking_up` is the ID a
/// recovery would start them on, which is what counts where the folder lost its own copy.
fn keys_there(folder: &Home, taking_up: Option<&str>) -> Result<KeysThere, Failure> {
    let mut asking = Command::new(services::beside_this_program(setup::SIGNET)?);
    asking
        .arg("look-at-keys")
        .env_clear()
        .envs(services::what_every_program_needs())
        .env("SPLINT_STATE_DIR", folder.signet_dir())
        .env("NO_COLOR", "1");
    if let Some(identity) = taking_up {
        asking.env("SPLINT_RECOVERING", identity);
    }
    let done = asking
        .output()
        .map_err(|_| Failure::refused("couldn't run splint-signet: is it installed?"))?;
    if done.status.success() {
        return Ok(KeysThere::Fine);
    }
    if done.status.code() == Some(i32::from(AGENT_KEYS_LOST_EXIT)) {
        return Ok(KeysThere::LostForGood);
    }
    let said = String::from_utf8_lossy(&done.stderr);
    let said = said.lines().last().unwrap_or_default();
    Ok(KeysThere::CanBePutRight(
        said.strip_prefix("Error: ").unwrap_or(said).to_owned(),
    ))
}

/// Says what replacing this agent's keys loses, and goes on only on a yes. The address typed out on the
/// command line is that yes, for where there's no terminal.
fn replacing_is_confirmed(address: &str, typed_out: bool) -> Result<(), Failure> {
    authorize::say(&format!(
        "{address}'s keys are gone or can't be used, so this puts it on new ones under the same ID. \
         Whatever was sealed to the old keys and still waits for it can never be opened, and this \
         can't be undone. If you have the real key files somewhere, stop and put them back instead."
    ))?;
    if typed_out
        || authorize::answer("Type yes to replace them, and anything else to stop:")? == YES
    {
        return Ok(());
    }
    Err(Failure::refused("nothing was replaced"))
}

/// Puts an agent whose keys are lost on new ones, under the same ID. Its Signet only makes keys while
/// it's told it's taking that ID up, and a run that's cut off carries on from there.
async fn new_keys(here: WithItsOwner, typed_out: bool) -> Result<String, Failure> {
    let WithItsOwner {
        folder,
        installed,
        agent,
        owner,
    } = here;
    let address = installed.address.clone();
    let replacing_keys = match keys_there(&folder, None)? {
        KeysThere::CanBePutRight(said) => return Err(Failure::SignetWontStart(said)),
        KeysThere::LostForGood => {
            if !installed.replacing_keys {
                replacing_is_confirmed(&address, typed_out)?;
            }
            true
        }
        KeysThere::Fine if installed.recovering.is_none() => {
            return match setup::start_signet(&folder, &installed, None).await {
                Err(failure) if !setup::up_without_its_host(&failure) => Err(failure),
                _ => Ok(keys_are_here(&address)),
            };
        }
        KeysThere::Fine => installed.replacing_keys,
    };
    let (_, domain) = parse_address(&address).map_err(Failure::not_an_address)?;
    let held = HostCalls::new(domain)?
        .agent_as_held(&address, Some(&agent))
        .await?
        .identity;
    let taking = Installed {
        recovering: installed.recovering.clone().or_else(|| Some(held.clone())),
        replacing_keys,
        ..clone_installed(&installed)?
    };
    if let Err(refused) = setup::start_signet(&folder, &taking, None).await {
        // Nothing was taken up, so no later start should go on as if it were.
        installed.save(&folder)?;
        return Err(refused);
    }
    let api = SignetApi::new(&folder, &taking)?;
    let who = api.who().await?;
    if who.agent_id != agent {
        return Err(Failure::refused(
            "the Signet in its folder here is another agent's",
        ));
    }
    if !who.recovering {
        let backup = taking.backup.clone();
        back_on_what_is_saved(&folder, &taking, backup).await?;
        return Ok(keys_are_here(&address));
    }
    let passphrase = match owner.sign_in() {
        Some(SignIn::LockedFile) => Some(authorize::secret("Your sign-in's passphrase:")?),
        _ => None,
    };
    let signed = owner.recover_agent(
        &newer_of(held, &who.identity),
        &who.key,
        passphrase.as_deref(),
    )?;
    api.put_recovery(&signed.identity).await?;
    drop(api);
    let backup = AgentBackup {
        commitment: signed.commitment,
        file: signed.file,
    };
    back_on_what_is_saved(&folder, &taking, backup).await?;
    Ok(format!(
        "{address} is on new keys, under the same ID, and its contacts are told by themselves. What \
         was sealed to its old key and still waited can't be opened."
    ))
}

/// Its Signet started again as an agent that's taking nothing up. A host that's away by then is signed
/// on with by itself.
async fn back_on_what_is_saved(
    folder: &Home,
    taking: &Installed,
    backup: AgentBackup,
) -> Result<(), Failure> {
    let settled = Installed {
        recovering: None,
        replacing_keys: false,
        backup,
        ..clone_installed(taking)?
    };
    settled.save(folder)?;
    services::stop(folder, setup::SIGNET, setup::SIGNET).await?;
    match setup::start_signet(folder, &settled, None).await {
        Err(trouble) if !setup::up_without_its_host(&trouble) => Err(trouble),
        _ => Ok(()),
    }
}

/// One prompt for these agents, and the owner's list signed again with every agent in it.
fn restore_batch(
    owner: &OwnerKey,
    domain: &str,
    batch: &[Coming],
    agents: &[Listed],
    passphrase: Option<&str>,
) -> Result<Restored, Failure> {
    let given = json!({
        "host": domain,
        "rules": first_rules(),
        "here": batch.iter().map(|one| json!({
            "identity": one.held,
            "address": one.listed.address,
            "new_key": one.key,
            "delegate": one.delegate,
        })).collect::<Vec<_>>(),
        "list": agents,
    });
    serde_json::from_str(&owner.restore_agents(&given.to_string(), passphrase)?)
        .map_err(|_| Failure::refused("the owner key's answer can't be read"))
}

/// The most agents one prompt names, as `owner-key` takes them.
const MOST_IN_ONE_PROMPT: usize = 8;

/// The agents a recovery here kept, for a run that carries on.
fn kept_agents(owner: &OwnerKey) -> Vec<Listed> {
    std::fs::read(owner.dir_path().join("recovered.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// The code typed here, the owner's ID found by the agent's address, their list found by the handle
/// the code gives, and the ID recovered onto this computer's sign-in.
async fn recover_owner(
    owner: &OwnerKey,
    calls: &HostCalls,
    address: &str,
    domain: &str,
) -> Result<(Recovered, Option<String>), Failure> {
    let mut copies = Vec::new();
    let (name, _) = parse_address(address).map_err(Failure::not_an_address)?;
    // Only the ID it acts for is read here, which checks itself, and the code has to fit it.
    if let Ok(found) = calls.resolve(address).await {
        copies.push(found.owner_identity);
    } else if let Ok(found) = calls.agent_as_held(address, None).await {
        copies.push(found.owner_identity);
    }
    let Some(first) = copies.first() else {
        return Err(Failure::refused(format!(
            "couldn't find {name} at {domain}, or who it acts for, so check the address"
        )));
    };
    let owner_id = Identity::from_encoded(first)?.id().clone();
    copies.extend(calls.known_owner(&owner_id).await);
    let code = authorize::secret("Your recovery code:")?;
    let handle = owner.list_handle(&code)?;
    let lists = calls.lists_by_handle(&handle).await?;
    // Going on spends the code, and the list is what holds the agents' backups.
    if lists.is_empty() {
        authorize::say(&format!(
            "{domain} holds no list of your agents for that code. The code may be mistyped, or your \
             list may be at another host. If you go on and the code is right, it's used up and no \
             agent comes back."
        ))?;
        if authorize::answer("Type yes to go on:")? != "yes" {
            return Err(Failure::refused(
                "nothing changed, and your recovery code still works: check it, or run this with the \
                 address of an agent at the host that holds your list",
            ));
        }
    }
    let chip = computer::chip_here();
    let passphrase = if chip {
        None
    } else {
        authorize::say("Your sign-in on this computer is a key file, locked with a passphrase.")?;
        Some(computer::choose_passphrase()?)
    };
    let given = json!({ "identities": copies, "lists": lists, "host": domain });
    let printed =
        owner.recover_signed_in(chip, passphrase.as_deref(), &code, &given.to_string())?;
    let recovered: Recovered = serde_json::from_str(&printed)
        .map_err(|_| Failure::refused("the owner key's answer can't be read"))?;
    Ok((recovered, passphrase))
}

/// The agent's ID as its host holds it, if its host shows it bound under the owner's ID as it is now,
/// which is what counts as back: the ID never changes on a recovery, so it's the copy that's compared.
async fn is_back(address: &str, owner: &Identity) -> Option<String> {
    let (_, domain) = parse_address(address).ok()?;
    let found = HostCalls::new(domain).ok()?.resolve(address).await.ok()?;
    Identity::from_encoded(&found.owner_identity)
        .is_ok_and(|held| held.extends(owner))
        .then_some(found.identity)
}

/// What's in a folder that already holds an agent coming back, before a recovery starts its Signet there:
/// keys that can be put right stop it, and replacing lost ones takes a yes, which the setup returned keeps.
fn keys_may_go(folder: &Home, installed: Installed, held: &str) -> Result<Installed, Failure> {
    let replacing_keys = match keys_there(folder, Some(held))? {
        KeysThere::Fine => false,
        KeysThere::CanBePutRight(said) => {
            return Err(Failure::SignetWontStart(format!(
                "{said}. Then run this again"
            )));
        }
        KeysThere::LostForGood => {
            if !installed.replacing_keys {
                replacing_is_confirmed(&installed.address, false)?;
            }
            true
        }
    };
    Ok(Installed {
        replacing_keys,
        ..installed
    })
}

/// The agent named on the command line, where a folder here holds it, is asked about first, as a person
/// who stops here still has their recovery code. A host that can't say stops this further on.
async fn keys_of_the_one_named(home: &Home, address: &str, domain: &str) -> Result<(), Failure> {
    for folder in home.every()? {
        let Some(installed) = Installed::load(&folder)? else {
            continue;
        };
        let Some(agent) = installed
            .agent
            .clone()
            .filter(|_| installed.address == address)
        else {
            continue;
        };
        let calls = HostCalls::new(domain)?;
        if let Ok(found) = calls.agent_as_held(address, Some(&agent)).await {
            keys_may_go(&folder, installed, &found.identity)?.save(&folder)?;
        }
        break;
    }
    Ok(())
}

/// A folder and a Signet here for an agent coming back: the folder that holds it already, or else the
/// default one if it's free, or a profile named by its handle. Its Signet starts taking up its ID,
/// as its host holds it, with new keys of its own.
async fn bring_up(home: &Home, listed: &Listed, owner: &str) -> Result<Coming, Failure> {
    let (_, domain) = parse_address(&listed.address).map_err(Failure::not_an_address)?;
    let held = HostCalls::new(domain)?
        .agent_as_held(&listed.address, Some(&listed.agent))
        .await?
        .identity;
    let (folder, installed) = folder_for(home, listed)?;
    let installed = match installed {
        Some(installed) => keys_may_go(&folder, installed, &held)?,
        None => {
            folder.prepare_for_agent()?;
            let mut made = Installed::create(
                &listed.address,
                AgentBackup {
                    commitment: String::new(),
                    file: std::path::PathBuf::new(),
                },
            )?;
            made.agent = Some(listed.agent.clone());
            made.recovering = Some(held.clone());
            made.replacing_keys = true;
            made
        }
    };
    // Said for a folder that was here already too: only a Signet told it's taking up its ID makes keys
    // in place of files that are gone.
    let installed = Installed {
        owner_elsewhere: Some(owner.to_owned()),
        recovering: installed.recovering.or_else(|| Some(held.clone())),
        ..installed
    };
    installed.save(&folder)?;
    setup::start_signet(&folder, &installed, None).await?;
    let who = SignetApi::new(&folder, &installed)?.who().await?;
    if who.agent_id != listed.agent {
        return Err(Failure::refused(
            "the Signet in its folder here is another agent's",
        ));
    }
    // A run cut off after its Signet took a recovery, before its host did, goes on from that copy, as
    // a Signet refuses one that parts from what it holds.
    let held = newer_of(held, &who.identity);
    Ok(Coming {
        listed: listed.clone(),
        key: who.key,
        delegate: who.delegate,
        held,
        home: folder,
        installed,
    })
}

/// Whichever of the host's copy of an agent's ID and its Signet's goes further.
fn newer_of(at_host: String, at_signet: &str) -> String {
    let newer = Identity::from_encoded(&at_host)
        .and_then(|host| host.newest_of(&Identity::from_encoded(at_signet)?))
        .map(|newest| newest.encoded());
    newer.unwrap_or(at_host)
}

/// Where an agent coming back lives here.
fn folder_for(home: &Home, listed: &Listed) -> Result<(Home, Option<Installed>), Failure> {
    for one in home.every()? {
        if let Some(installed) = Installed::load(&one)?
            && installed.agent.as_ref() == Some(&listed.agent)
        {
            return Ok((one, Some(installed)));
        }
    }
    let default = home.the_default();
    if Installed::load(&default)?.is_none() && !default.join_file().exists() {
        return Ok((default, None));
    }
    let (handle, _) = parse_address(&listed.address).map_err(Failure::not_an_address)?;
    let name = handle.split('.').next().unwrap_or(handle);
    if !is_profile_name(name) {
        return Err(Failure::refused(
            "its handle can't name a profile here, so it has no folder",
        ));
    }
    let profile = Home::from_env(Some(name))?;
    if Installed::load(&profile)?.is_some() {
        return Err(Failure::refused(format!(
            "the profile {name} here holds another agent"
        )));
    }
    Ok((profile, None))
}

/// What one prompt signed for an agent, handed to its Signet here: the recovery naming its new keys,
/// then its binding, rules and delegation. It's back once its Signet says it's registered under the
/// recovered owner. A folder that was here already holds the owner as they were before, so it hears of
/// their recovery first, or the binding it holds would go to a host that has moved past it.
async fn hand_back(
    one: &Coming,
    signed: &RestoredOne,
    owner_identity: &str,
    owner: &SplintId,
) -> Result<(), Failure> {
    let api = SignetApi::new(&one.home, &one.installed)?;
    api.put_recovery(owner_identity).await?;
    api.put_recovery(&signed.identity).await?;
    api.put_binding(&signed.binding).await?;
    match authorize::send_rules(&one.home, &signed.agent, &one.listed.address, &signed.rules).await
    {
        Ok(_) | Err(Failure::NotYetAtHost(_)) => {}
        Err(failure) => return Err(failure),
    }
    if let Some(delegation) = &signed.delegation {
        api.put_delegation(delegation).await?;
    }
    let who = api.who().await?;
    drop(api);
    // Its Signet holds its ID now, so a later start reads that, never the one it took up.
    let settled = Installed {
        recovering: None,
        replacing_keys: false,
        backup: AgentBackup {
            commitment: signed.commitment.clone(),
            file: std::path::PathBuf::new(),
        },
        ..clone_installed(&one.installed)?
    };
    settled.save(&one.home)?;
    if who.recovering || !who.registered || who.owner_id.as_ref() != Some(owner) {
        return Err(Failure::refused(
            "its Signet isn't registered under your recovered owner ID yet",
        ));
    }
    Ok(())
}

/// The setup a folder keeps, read again, as it's written whole.
fn clone_installed(installed: &Installed) -> Result<Installed, Failure> {
    serde_json::to_vec(installed)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| Failure::refused("couldn't write down the setup"))
}

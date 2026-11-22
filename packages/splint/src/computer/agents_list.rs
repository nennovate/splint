//! The owner's list of agents this computer set up, kept at their home host so losing this computer
//! doesn't lose them: each agent's backup, sealed to the owner and to the backup their recovery code
//! gives, signed by this computer's sign-in in the touch that's happening anyway, as an agent is set up
//! or the code is set. `owner-key` decides whether one is written at all: only once there's a code,
//! and only while this sign-in is the owner ID's only key, as a passkey of theirs finds its list by its
//! own handle.
//!
//! A list the home host won't take now is kept here and sent again each minute, until it's taken or
//! the host holds a newer one.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use splint_core::owner_agents::VerifiedOwnerAgents;
use splint_core::{Identity, SplintId, parse_address, unix_now};

use super::Computer;
use crate::home::{Home, Installed};
use crate::host_calls::{HostCalls, ListKept};
use crate::secrets::write_private;

/// A list signed here that its home host hasn't taken yet.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Unsent {
    host: String,
    owner_identity: String,
    list: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent: Option<SplintId>,
}

/// One agent the list holds, as `owner-key` takes it.
#[derive(Serialize)]
pub(super) struct ToList {
    pub agent: String,
    pub address: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub beside_owner: bool,
}

/// Whether a Splint folder on this computer holds this agent, so its Signet runs here and a recovery
/// after losing this computer brings it back here.
pub(super) fn runs_here(home: &Home, agent: &str) -> bool {
    home.every().is_ok_and(|every| {
        every.iter().any(|one| {
            Installed::load(one)
                .ok()
                .flatten()
                .and_then(|installed| installed.agent)
                .is_some_and(|id| id.as_str() == agent)
        })
    })
}

/// Whether Splint on this computer has signed the owner's list, which on a computer that was recovered
/// onto means since that recovery, so the list the new code finds is there or on its way.
pub(crate) fn list_kept_here(home: &Home) -> bool {
    Computer::new(home).is_ok_and(|computer| computer.list_seq_file().exists())
}

/// After `splint recover` here: the agents it brought back noted as set up here, the list it signed
/// handed to the home host, which becomes this computer's home host, and Splint on this computer
/// started, so what comes next is approved here as before.
pub(crate) async fn after_recovery(
    home: &Home,
    host: &str,
    back: &[(SplintId, String, String)],
    list: Option<String>,
) -> Result<(), crate::failure::Failure> {
    let computer = Computer::new(home)?;
    Home::make_private(&computer.home.computer_dir())?;
    write_private(&computer.home_host_file(), host.as_bytes())?;
    for (agent, address, identity) in back {
        computer.remember_agent(agent.as_str(), address, identity);
    }
    if let Some(list) = list {
        let given = json!({ "host": host });
        computer.keep_list(&given, list, None).await;
    }
    let _started = super::start(home)?;
    Ok(())
}

/// The handle part of an address, which labels an agent in the list.
fn label_of(address: &str) -> String {
    parse_address(address).map_or_else(|_| address.to_owned(), |(handle, _)| handle.to_owned())
}

impl Computer {
    fn unsent_file(&self) -> PathBuf {
        self.home.computer_dir().join("list-unsent.json")
    }

    fn list_seq_file(&self) -> PathBuf {
        self.home.computer_dir().join("list-seq")
    }

    /// The home host, or else the host of the first agent being set up, as it becomes the home host.
    fn list_host(&self, setting_up: &[ToList]) -> Option<String> {
        std::fs::read_to_string(self.home_host_file())
            .ok()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
            .or_else(|| {
                setting_up.iter().find_map(|one| {
                    parse_address(&one.address)
                        .ok()
                        .map(|(_, domain)| domain.to_owned())
                })
            })
    }

    /// What `owner-key` takes to sign the list: every agent set up here, with its ID as its host gives
    /// it now where that answers, and those being set up in this touch.
    pub(super) async fn list_given(&self, setting_up: Vec<ToList>) -> Option<Value> {
        let host = self.list_host(&setting_up)?;
        let mut agents = setting_up;
        for known in self.agents_here() {
            if agents.iter().any(|one| one.agent == known.agent) {
                continue;
            }
            let found = match parse_address(&known.address) {
                Ok((_, domain)) => match HostCalls::new(domain) {
                    Ok(calls) => calls.resolve(&known.address).await.ok(),
                    Err(_) => None,
                },
                Err(_) => None,
            };
            agents.push(ToList {
                beside_owner: runs_here(&self.home, &known.agent),
                label: label_of(&known.address),
                identity: found.map(|found| found.identity).or(known.identity),
                agent: known.agent,
                address: known.address,
            });
        }
        let after = std::fs::read_to_string(self.list_seq_file())
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .unwrap_or(0);
        Some(json!({ "host": host, "agents": agents, "after": after }))
    }

    /// Hands a list just signed to the home host, or keeps it to send again.
    pub(super) async fn keep_list(&self, given: &Value, list: String, agent: Option<SplintId>) {
        let (Some(host), Some(owner_identity)) = (
            given.get("host").and_then(Value::as_str),
            self.owner.kept_identity(),
        ) else {
            return;
        };
        if let Some(seq) = list_seq(&list, &owner_identity, host) {
            let _ = write_private(&self.list_seq_file(), seq.to_string().as_bytes());
        }
        let unsent = Unsent {
            host: host.to_owned(),
            owner_identity,
            list,
            agent,
        };
        if let Ok(bytes) = serde_json::to_vec(&unsent) {
            let _ = write_private(&self.unsent_file(), &bytes);
        }
        self.send_list_again().await;
    }

    /// Once the recovery code is set: the list signed with it to the home host, and the owner's ID as
    /// it is now to each host an agent set up here is at, so its Signet hears the code is set.
    pub(super) async fn code_was_set(
        &self,
        identity: &str,
        given: Option<&Value>,
        list: Option<String>,
    ) {
        if let (Some(list), Some(given)) = (list, given) {
            self.keep_list(given, list, None).await;
        }
        let mut hosts: Vec<String> = self
            .agents_here()
            .iter()
            .filter_map(|known| {
                parse_address(&known.address)
                    .ok()
                    .map(|(_, domain)| domain.to_owned())
            })
            .collect();
        hosts.extend(self.list_host(&[]));
        hosts.sort();
        hosts.dedup();
        for host in hosts {
            if let Ok(calls) = HostCalls::new(&host) {
                let _ = calls.post_recovery(identity).await;
            }
        }
    }

    /// The list kept here, sent again, and forgotten once it's taken or the host holds a newer one.
    pub(super) async fn send_list_again(&self) {
        let Some(unsent) = std::fs::read(self.unsent_file())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Unsent>(&bytes).ok())
        else {
            return;
        };
        let Ok(calls) = HostCalls::new(&unsent.host) else {
            let _ = std::fs::remove_file(self.unsent_file());
            return;
        };
        let kept = calls
            .put_owner_list(&unsent.owner_identity, &unsent.list, unsent.agent.as_ref())
            .await;
        match kept {
            ListKept::Kept | ListKept::Superseded => {
                let _ = std::fs::remove_file(self.unsent_file());
            }
            ListKept::NotYet => {}
        }
    }
}

/// The `seq` of a list signed here, read back under the owner's ID, so the next one is above it.
fn list_seq(list: &str, owner_identity: &str, host: &str) -> Option<u64> {
    let owner = Identity::from_encoded(owner_identity).ok()?;
    VerifiedOwnerAgents::verify(list, &owner, host, unix_now())
        .ok()
        .map(|list| list.seq())
}

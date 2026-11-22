//! Agents this computer set up moving to another host under the same ID. An ask to move is taken by
//! what this computer holds of the agent, never only by the host it's leaving, which may be gone for
//! good, answer 404 on purpose, or now serve someone else. Once signed, the address kept for it here
//! follows as soon as its new host names that same ID there, with no session and no touch.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use splint_core::asks::{MAX_ASK_SECS, VerifiedAsk};
use splint_core::{Identity, MoveReply, SplintId, parse_address, unix_now};

use super::owner_page::SetUpHere;
use super::{Asked, Computer};
use crate::failure::Failure;
use crate::home::Home;
use crate::host_calls::HostCalls;

/// A move signed here, waiting for the agent's new host to name it.
#[derive(Clone, Serialize, Deserialize)]
struct Moving {
    to: String,
    since: u64,
}

/// Whether Splint on this computer set this agent up, so its person approves a move here.
pub fn set_up_here(home: &Home, agent: &SplintId) -> bool {
    std::fs::read(home.computer_dir().join("agents.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Vec<SetUpHere>>(&bytes).ok())
        .is_some_and(|agents| agents.iter().any(|known| known.agent == agent.as_str()))
}

impl Computer {
    /// Leaves what the owner signed for a move at the new host, for an agent on another computer to
    /// take up, as nothing else reaches it from here.
    pub(super) async fn keep_move_at(&self, asked: &Asked, to: &str, binding: &str) {
        let Ok(owner) = super::owner_here(&self.home).identity() else {
            return;
        };
        let reply = MoveReply::new(asked.identity.clone(), owner, binding.to_owned());
        let keys = Identity::from_encoded(&asked.identity)
            .ok()
            .and_then(|identity| identity.agent_keys());
        let (Some(keys), Ok(answer), Ok((_, domain))) = (keys, reply.encode(), parse_address(to))
        else {
            return;
        };
        if let Ok(host) = HostCalls::new(domain) {
            host.keep_answer(&keys.encoded(), &answer).await;
        }
    }

    fn moves_file(&self) -> std::path::PathBuf {
        self.home.computer_dir().join("moves.json")
    }

    fn moves(&self) -> HashMap<String, Moving> {
        std::fs::read(self.moves_file())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn keep_moves(&self, moves: &HashMap<String, Moving>) {
        if let Ok(bytes) = serde_json::to_vec(moves) {
            let _ = std::fs::write(self.moves_file(), bytes);
        }
    }

    /// An ask with its agent's ID as its own host gives it for the address named, so an ask can't be
    /// shown under another agent's address: whoever hands it over names only the address. An ask to
    /// move an agent this computer set up goes instead by the newest copy of its ID among the one kept
    /// here, the one handed over and its host's, and by the address kept here, so the host it's
    /// leaving is never needed and can't choose either.
    pub(super) async fn as_its_host_says(&self, mut asked: Asked) -> Result<Asked, Failure> {
        if let Some(moving) = self.moving_as_kept_here(&asked).await? {
            return Ok(moving);
        }
        let (_, domain) = parse_address(&asked.address)?;
        asked.identity = HostCalls::new(domain)?
            .resolve(&asked.address)
            .await?
            .identity;
        Ok(asked)
    }

    async fn moving_as_kept_here(&self, asked: &Asked) -> Result<Option<Asked>, Failure> {
        let changes = splint_core::asks::payload_changes(&asked.ask).unwrap_or_default();
        if splint_core::asks::host_of(&changes).is_none() {
            return Ok(None);
        }
        let agent = VerifiedAsk::claimed_agent(&asked.ask)?;
        let Some(here) = self
            .agents_here()
            .into_iter()
            .find(|known| known.agent == agent.as_str())
        else {
            return Ok(None);
        };
        let from_host = match parse_address(&here.address).map(|(_, domain)| HostCalls::new(domain))
        {
            Ok(Ok(host)) => host
                .resolve(&here.address)
                .await
                .ok()
                .map(|found| found.identity),
            _ => None,
        };
        let copies = [
            here.identity.as_deref(),
            Some(asked.identity.as_str()),
            from_host.as_deref(),
        ];
        let mut newest: Option<Identity> = None;
        for copy in copies.into_iter().flatten() {
            let Ok(copy) = Identity::from_encoded(copy) else {
                continue;
            };
            if copy.id() != &agent {
                continue;
            }
            newest = Some(match newest {
                None => copy,
                Some(held) => held.newest_of(&copy).map_err(|_| {
                    Failure::refused(
                        "the copies of that agent's ID part ways, so its move isn't shown or signed",
                    )
                })?,
            });
        }
        let newest = newest.ok_or_else(|| {
            Failure::refused("that agent's ID can't be read here, so its move isn't shown")
        })?;
        self.keep_identity(agent.as_str(), &newest.encoded());
        Ok(Some(Asked {
            identity: newest.encoded(),
            address: here.address,
            ..asked.clone()
        }))
    }

    /// Notes a move signed here, for the address kept to follow once the new host names the agent.
    pub(super) fn note_moving(&self, agent: &str, to: &str) {
        let mut moves = self.moves();
        moves.insert(
            agent.to_owned(),
            Moving {
                to: to.to_owned(),
                since: unix_now(),
            },
        );
        self.keep_moves(&moves);
    }

    /// The address kept for each agent moving, replaced once its new host names the same ID there, as
    /// anyone can look up. One its agent never took up is forgotten once the binding signed for it
    /// would no longer be taken.
    pub(super) async fn follow_moves(&self) {
        let moves = self.moves();
        if moves.is_empty() {
            return;
        }
        let now = unix_now();
        let mut still = HashMap::new();
        for (agent, moving) in moves {
            let arrived = match parse_address(&moving.to).map(|(_, domain)| HostCalls::new(domain))
            {
                Ok(Ok(host)) => host
                    .resolve(&moving.to)
                    .await
                    .is_ok_and(|found| found.agent_id.as_str() == agent),
                _ => false,
            };
            if arrived {
                self.move_kept_address(&agent, &moving.to);
            } else if now < moving.since.saturating_add(MAX_ASK_SECS) {
                still.insert(agent, moving);
            }
        }
        self.keep_moves(&still);
    }
}

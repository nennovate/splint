//! Unlocking your controls in a page, once a visit. The passphrase, or the chip's own prompt, starts the
//! sessions this computer keeps at hosts for reading, gives the page its page key, and starts a signing
//! session, so a change after that needs no passphrase again while the person keeps using the page
//! (Nenye, 2026-11-22: "if you've already signed in to your session, you should be able to just change
//! things freely").
//!
//! The session's token is held in this process and in the page's memory alone, never in the
//! browser's storage, so a program on this computer that reads the browser's files doesn't find it:
//! reloading the page asks again. It ends 30 minutes after it was last used, 12 hours after it began
//! whatever happens, when the person locks or signs out, and when Splint here stops. What a key file's
//! passphrase opens is held here for that time, as it has to be for a change to sign with nobody
//! typing it: that's the cost of not typing it each time. A chip holds nothing here, and asks for
//! Touch ID or the login password for each change, as before.
//!
//! Some things ask again whatever the session. Where the person gets paid is a statement people are
//! told to pay to, so it's never signed by a session. Setting the recovery code and approving an
//! agent's ask take no session at all, by their own calls. A payment the person would make is the
//! page's to ask again about: the owner key names objects a page prepared only by their kind, so this
//! process can't tell a yes to $12 from a yes to $48,000.
//!
//! Unlocking needs no page key, as it's how a page with none gets one, so wrong tries are limited:
//! after 5 in a row, each try waits a minute after the last.

use std::fmt;

use splint_core::prepared::Prepared;
use splint_core::unix_now;

use super::owner_page::{MOST_HOSTS, SessionShown};
use super::{Computer, same_secret};
use crate::failure::Failure;
use crate::owner_key::SignIn;
use crate::secrets::Token;

/// How long a signing session lasts with nothing signed or read through it.
const IDLE_SECS: u64 = 30 * 60;
/// How long one lasts whatever happens, as long as a session at a host can.
const MOST_SECS: u64 = 12 * 60 * 60;
/// Wrong tries in a row before each further one waits.
const WRONG_BEFORE_WAITING: u32 = 5;
const WAIT_SECS: u64 = 60;
/// What a signing session never signs, by the owner type a page prepared: where the person gets
/// paid, as people are told to pay there.
const ALWAYS_ASKS: &[&str] = &["splint-where-paid"];

/// A signing session a page holds the token for.
pub struct Unlocked {
    token: Token,
    passphrase: Option<Held>,
    started: u64,
    last_used: u64,
}

impl Unlocked {
    fn live(&self, now: u64) -> bool {
        now < self.last_used.saturating_add(IDLE_SECS)
            && now < self.started.saturating_add(MOST_SECS)
    }
}

/// A key file's passphrase, held while the session lasts. It's never printed, logged or serialized.
struct Held(String);

impl fmt::Debug for Held {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Held(hidden)")
    }
}

/// Wrong tries at unlocking, in a row, and when the next may come.
#[derive(Default)]
pub struct Tries {
    wrong: u32,
    next_at: u64,
}

const TOO_MANY: &str = "that passphrase was wrong several times, so wait a minute and try again";
const NOTHING_YET: &str =
    "there's nothing to unlock yet: once an agent asks you, open its link here";

/// Whether a signing session may sign these inputs: anything but what always asks again.
pub fn session_signs(inputs: &[String]) -> bool {
    inputs.iter().all(|input| {
        Prepared::read(input).is_ok_and(|prepared| !ALWAYS_ASKS.contains(&prepared.typ()))
    })
}

impl Computer {
    /// Unlocks the controls for a page: sessions at the hosts this computer knows, signed with one
    /// prompt, and a signing session whose token only that page gets.
    pub async fn unlock(
        &self,
        passphrase: Option<String>,
    ) -> Result<(Vec<SessionShown>, String), Failure> {
        let now = unix_now();
        if now < self.tries.lock().await.next_at {
            return Err(Failure::refused(TOO_MANY));
        }
        let hosts = self.unlock_hosts();
        if hosts.is_empty() {
            return Err(Failure::refused(NOTHING_YET));
        }
        let kept = (self.owner.sign_in() == Some(SignIn::LockedFile))
            .then(|| passphrase.clone())
            .flatten();
        match self.start_sessions(hosts, passphrase).await {
            Ok((sessions, _)) => {
                *self.tries.lock().await = Tries::default();
                let token = Token::generate()?;
                let shown = token.expose().to_owned();
                *self.unlocked.lock().await = Some(Unlocked {
                    token,
                    passphrase: kept.map(Held),
                    started: now,
                    last_used: now,
                });
                Ok((sessions, shown))
            }
            Err(failure) => {
                let mut tries = self.tries.lock().await;
                tries.wrong = tries.wrong.saturating_add(1);
                if tries.wrong >= WRONG_BEFORE_WAITING {
                    tries.next_at = unix_now().saturating_add(WAIT_SECS);
                }
                Err(failure)
            }
        }
    }

    /// For a call carrying a session's token, while the session lasts: the passphrase it holds, or
    /// `Some(None)` for a sign-in that holds none here. `None` for a token that isn't the session's,
    /// or a session that has ended, which is forgotten then and there.
    pub async fn unlocked_with(&self, token: &str) -> Option<Option<String>> {
        let now = unix_now();
        let mut unlocked = self.unlocked.lock().await;
        if unlocked.as_ref().is_some_and(|one| !one.live(now)) {
            *unlocked = None;
        }
        let one = unlocked
            .as_mut()
            .filter(|one| same_secret(one.token.expose(), token))?;
        one.last_used = now;
        Some(one.passphrase.as_ref().map(|held| held.0.clone()))
    }

    /// Ends the signing session, so the next change asks again.
    pub async fn lock(&self) {
        *self.unlocked.lock().await = None;
    }

    /// The hosts unlocking starts sessions at: the home host, and each agent's this computer set up.
    fn unlock_hosts(&self) -> Vec<String> {
        let home = std::fs::read_to_string(self.home_host_file())
            .ok()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty());
        let agents = self.agents_here().into_iter().filter_map(|one| {
            splint_core::parse_address(&one.address)
                .ok()
                .map(|(_, domain)| domain.to_owned())
        });
        let mut hosts: Vec<String> = Vec::new();
        for host in home.into_iter().chain(agents) {
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        hosts.truncate(MOST_HOSTS);
        hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(typ: &str) -> String {
        use base64::Engine as _;
        let encode = |text: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
        format!(
            "{}.{}",
            encode(&format!(r#"{{"alg":"ES256","typ":"{typ}"}}"#)),
            encode("{}")
        )
    }

    /// The bug this catches: a session signing where the person gets paid, which people are told to
    /// pay to, with nobody typing anything.
    #[test]
    fn a_session_never_signs_where_the_person_gets_paid() {
        assert!(session_signs(&[
            input("splint-rules"),
            input("splint-approval")
        ]));
        assert!(!session_signs(&[
            input("splint-rules"),
            input("splint-where-paid")
        ]));
        assert!(!session_signs(&["not an input".to_owned()]));
    }
}

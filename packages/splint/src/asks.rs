//! What an agent runs to ask its person for exactly what it wants changed: `splint ask`, and
//! `splint controls`, which asks them to set up their controls for it. The agent's Signet signs the
//! ask with the agent's key and leaves it in the person's view at its host. Where the person has Splint
//! on this computer, the ask goes straight there too, so one touch approves it, and an agent asking for
//! controls takes up the answer itself, with nothing to paste. An ask still waiting always comes back
//! with a link to it on Splint on the person's own computer, which the agent hands its person, as the
//! agent can't tell whether anyone is at this computer. No link opens on a host's page: Nenye decided
//! on 2026-11-21 that owners sign only on their own computers (issue 635). Nothing the agent gets back
//! can be used again: it learns only whether its ask was done.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use splint_core::SplintId;
use splint_core::asks::Change;
use splint_core::requests::{InteractionType, Operation};
use splint_core::rules::{InboundFrom, Level, Outbound, QuotedPrices};

use crate::computer::{self, Asked, Client, Outcome};
use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::host_calls::HostCalls;
use crate::signet_api::SignetApi;
use crate::taking_up;

/// Long enough for a person to see a prompt and touch, and short enough to end before the 120 seconds
/// a connector gives one call, so an agent whose person didn't answer still gets its ask and its link.
pub(crate) const WAIT_FOR_TOUCH: Duration = Duration::from_secs(90);
pub(crate) const LOOK_EVERY: Duration = Duration::from_secs(1);
/// How long an ask for controls lasts, the most Signet lets one: whoever approves first by its link
/// becomes the owner, and the agent can hand over a fresh link at any time.
const CONTROLS_HOURS: u64 = 1;
/// Said with every link to an ask for controls, as nothing but the link says who its person is.
const WHO_A_LINK_REACHES: &str = "Whoever approves first by a link becomes your owner, so send one \
                                  only where your person alone reads it. If one went anywhere else, \
                                  run splint controls again: a new link ends the one before.";

/// What one ask came to, for the agent.
pub struct Asking {
    pub id: String,
    /// waiting, done, not_approved, or for a step, owner_said_no or ended.
    pub status: String,
    /// Where the person approves it.
    pub approve_at: &'static str,
    pub said: String,
    /// While it waits: a link that opens this ask on Splint on the person's own computer, holding
    /// nothing secret, for the agent to give its person however suits it.
    pub computer_link: Option<String>,
}

impl Asking {
    pub fn json(&self) -> Value {
        json!({
            "id": self.id, "status": self.status, "approve_at": self.approve_at, "said": self.said,
            "computer_link": self.computer_link,
        })
    }

    /// The same for an agent that reads words: what was said, then the link on a line of its own.
    pub fn in_words(&self) -> String {
        match &self.computer_link {
            Some(link) => format!("{}\n\ncomputer_link: {link}", self.said),
            None => self.said.clone(),
        }
    }
}

/// The link that opens an ask on Splint on the person's own computer, at the address it always has.
/// What follows the `#` never leaves their browser.
pub(crate) fn link_for(ask: &str, address: &str) -> String {
    format!("http://localhost:7480/ask#ask={ask}&at={address}")
}

/// Where an ask waits for its person, besides its link.
#[derive(Clone, Copy, PartialEq)]
enum Waits {
    /// Splint on this computer didn't take it, so only its link and their controls show it.
    ByLinkOnly,
    /// Splint on this computer holds it, and puts nothing in front of anyone by itself.
    Here,
    /// This computer's own prompt asks for whoever is at it.
    AtAPrompt,
}

impl Waits {
    fn approve_at(self) -> &'static str {
        match self {
            Self::ByLinkOnly => "their_controls",
            Self::Here => "this_computer",
            Self::AtAPrompt => "this_computer_prompt",
        }
    }
}

/// What an agent is told of an ask that's still waiting: where it's asked for on this computer, if
/// it is, the link to hand over, how to install Splint where it isn't yet, and how the answer reaches
/// it. `controls` is how many hours an ask
/// for controls lasts, and `waited` how long nobody answered.
fn waiting_words(
    home: &Home,
    id: &str,
    controls: Option<u64>,
    waits: Waits,
    waited: Option<Duration>,
    address: &str,
) -> String {
    let splint = home.command();
    let host = splint_core::parse_address(address)
        .map(|(_, domain)| domain)
        .unwrap_or_default();
    let unanswered = match waited {
        Some(waited) => format!(" Nobody answered in {} seconds.", waited.as_secs()),
        None => String::new(),
    };
    let here = match waits {
        Waits::ByLinkOnly => "Asked.".to_owned(),
        Waits::Here => format!(
            "Asked. Where your person uses this computer, open it for them: run {splint} controls \
             {host}, which opens their controls in their browser with this waiting at the top, \
             ready to approve. Never hand them a bare localhost address instead: a page Splint \
             didn't open can't approve until they unlock it. In a terminal, splint computer approve \
             approves it too.{unanswered}"
        ),
        Waits::AtAPrompt => format!(
            "Asked. This Mac asks whoever is at it for Touch ID or their password, and that one \
             touch approves it.{unanswered}"
        ),
    };
    let give = if waits == Waits::ByLinkOnly {
        "Give your person"
    } else {
        "If they aren't at this computer, give them"
    };
    let on_their_computer = "they approve it in the browser their Splint controls open in, \
                             unlocking with their passphrase if it asks, or with splint computer \
                             approve in a terminal";
    let by_link = format!(
        "{give} computer_link: it opens on Splint on their own computer, where {on_their_computer}. \
         If Splint isn't there yet, controls.install in {splint} status --json is the line that \
         installs it and opens their controls, and controls.install_on_windows the one for Windows: \
         guide them through it, then they open computer_link in that browser."
    );
    let then = if controls.is_some() {
        format!(
            "{WHO_A_LINK_REACHES} You take up their answer by yourself, with nothing to paste: \
             splint auto does as soon as it's there, and so does {splint} ask {id}, which says \
             where it stands. It and its link last an hour, and then it ends unapproved: run \
             {splint} controls again for a fresh one."
        )
    } else {
        format!(
            "It also waits in their controls, and ends unapproved after its hours. {splint} ask \
             {id} says where it stands."
        )
    };
    // Agents can join on their own, so a person is told to check their agent's chat shows it joining
    // at the address their controls name, rather than whether they asked: it has to be said there.
    let say = if controls.is_some() {
        format!(
            " Tell your person in your chat that you joined Splint as {address}: their controls ask \
             them to check that before they approve."
        )
    } else {
        String::new()
    };
    format!("{here} {by_link} {then}{say}")
}

/// The changes the flags name, each with its value, in the protocol's own words.
fn value<'a>(word: Option<&&'a str>) -> Result<&'a str, Failure> {
    word.copied().ok_or(Failure::Usage)
}

/// Each type named, by its ID as it stands, or by its name and version where exactly one type agreed
/// with `with`, or with anyone where that's `None`, goes by it. Signet checks each again.
fn types_named(
    words: &[String],
    agreed: &[(SplintId, InteractionType)],
    with: Option<&SplintId>,
) -> Result<Vec<InteractionType>, Failure> {
    words
        .iter()
        .map(|word| {
            if let Ok(id) = InteractionType::try_from(word.clone())
                && id.is_agreed()
            {
                return Ok(id);
            }
            let mut found: Vec<&InteractionType> = agreed
                .iter()
                .filter(|(agent, id)| with.is_none_or(|with| with == agent) && id.name() == word)
                .map(|(_, id)| id)
                .collect();
            found.sort();
            found.dedup();
            match found.as_slice() {
                [one] => Ok((*one).clone()),
                [] => Err(Failure::refused(format!(
                    "{word:?} isn't a type agreed with them: agree it first, or name it by its ID from \
                     splint types"
                ))),
                _ => Err(Failure::refused(format!(
                    "{word:?} was agreed differently with different contacts: name it by its ID from \
                     splint types"
                ))),
            }
        })
        .collect()
}

async fn changes_from(
    signet: &SignetApi<'_>,
    flags: &[&str],
) -> Result<(Vec<Change>, Option<u64>, bool), Failure> {
    let mut changes = Vec::new();
    let mut hours = None;
    let mut wait = false;
    let mut type_words: Vec<String> = Vec::new();
    let mut text = false;
    let mut reach = None;
    let mut owners = Vec::new();
    let mut past = false;
    let mut paid_at = Vec::new();
    let mut words = flags.iter();
    while let Some(flag) = words.next() {
        match *flag {
            // Signet names its own delegate key here, whatever this says.
            "--controls" => changes.push(Change::Controls {
                delegate: String::new(),
            }),
            "--step" => {
                // The ID as the tools show it, or whole, as `move` takes it.
                let request =
                    crate::agent_commands::held_step_id(value(words.next())?, signet).await?;
                let request = serde_json::from_value(json!(request))
                    .map_err(|_| Failure::refused("--step takes a request's ID and a step"))?;
                let operation = match value(words.next())? {
                    "open" => Operation::Open,
                    "counter" => Operation::Counter,
                    "accept" => Operation::Accept,
                    "deliver" => Operation::Deliver,
                    "confirm" => Operation::Confirm,
                    "cancel" => Operation::Cancel,
                    _ => return Err(Failure::Usage),
                };
                changes.push(Change::Step { request, operation });
            }
            // Each place once, as `splint get-paid` takes them, for the person to sign in one statement.
            "--paid-at" => paid_at.push(crate::owner_commands::place_from(value(words.next())?)?),
            "--pause" => changes.push(Change::Paused { to: true }),
            "--resume" => changes.push(Change::Paused { to: false }),
            "--wait" => wait = true,
            "--text" => text = true,
            "--level" => changes.push(Change::Level {
                to: match value(words.next())? {
                    "ask-me" => Level::AskMe,
                    "auto" => Level::AutoWithinLimits,
                    "full-auto" => Level::FullAuto,
                    _ => return Err(Failure::Usage),
                },
            }),
            "--quoted-prices" => changes.push(Change::QuotedPrices {
                to: match value(words.next())? {
                    "wait" => QuotedPrices::Wait,
                    "within-limits" => QuotedPrices::WithinLimits,
                    _ => return Err(Failure::Usage),
                },
            }),
            "--writes" => changes.push(Change::Writes {
                to: match value(words.next())? {
                    "contacts" => Outbound::Contacts,
                    "replies" => Outbound::Replies,
                    _ => return Err(Failure::Usage),
                },
            }),
            "--reach" => {
                reach = Some(match value(words.next())? {
                    "contacts" => InboundFrom::Contacts,
                    "open" => InboundFrom::Open,
                    "filter" => InboundFrom::Filter,
                    _ => return Err(Failure::Usage),
                });
            }
            "--types" => {
                type_words = value(words.next())?
                    .split(',')
                    .map(|name| name.trim().to_owned())
                    .collect();
            }
            "--filter" => {
                for word in value(words.next())?.split(',') {
                    match word.trim() {
                        "past" => past = true,
                        id => {
                            owners.push(serde_json::from_value::<SplintId>(json!(id)).map_err(
                                |_| Failure::refused("--filter takes owners' IDs or past"),
                            )?)
                        }
                    }
                }
            }
            "--hours" => {
                hours = Some(
                    value(words.next())?
                        .parse()
                        .map_err(|_| Failure::refused("--hours is a number from 1 to 24"))?,
                );
            }
            "--contact" | "--remove" | "--block" => {
                let address = value(words.next())?;
                let address =
                    splint_core::canonical_address(address).map_err(Failure::not_an_address)?;
                let (_, domain) =
                    splint_core::parse_address(&address).map_err(Failure::not_an_address)?;
                let agent = HostCalls::new(domain)?.resolve(&address).await?.agent_id;
                changes.push(match *flag {
                    "--contact" => Change::Contact {
                        agent,
                        address,
                        types: Vec::new(),
                        text: false,
                    },
                    "--remove" => Change::Remove { agent },
                    _ => Change::Block { agent, address },
                });
            }
            _ => return Err(Failure::Usage),
        }
    }
    // --types and --text go with --reach, or with a contact, whichever was named. A type named by its
    // name alone is the one agreed under that name: with that contact, or for reach, with anyone.
    let agreed = if type_words.is_empty() {
        Vec::new()
    } else {
        signet.agreed_types().await?
    };
    for change in &mut changes {
        if let Change::Contact {
            agent,
            types: contact_types,
            text: contact_text,
            ..
        } = change
        {
            *contact_types = types_named(&type_words, &agreed, Some(agent))?;
            *contact_text = text;
        }
    }
    if let Some(to) = reach {
        let types = types_named(&type_words, &agreed, None)?;
        let named = |list: &[InteractionType]| list.to_vec();
        changes.push(match to {
            InboundFrom::Contacts => Change::Reach {
                to,
                types: Vec::new(),
                owners: Vec::new(),
                past: false,
            },
            _ => Change::Reach {
                to,
                types: named(&types),
                owners: owners.clone(),
                past,
            },
        });
    }
    if !paid_at.is_empty() {
        changes.push(Change::WherePaid { places: paid_at });
    }
    if changes.is_empty() {
        return Err(Failure::Usage);
    }
    Ok((changes, hours, wait))
}

#[derive(Deserialize)]
struct StatusOnly {
    status: String,
    #[serde(default)]
    changes: Vec<Change>,
    /// The ask as the agent's key signed it, which its link carries.
    #[serde(default)]
    ask: String,
}

#[derive(Deserialize)]
pub(crate) struct Signed {
    pub(crate) id: String,
    pub(crate) ask: String,
    status: String,
}

/// Hands an ask to Splint on this computer, starting it if this is the person's computer and it isn't
/// running. Whether it took it: one Splint here refused, as when the agent's host can't vouch for its
/// address, goes by link.
pub(crate) async fn hand_here(home: &Home, client: &Client, asked: &Asked) -> bool {
    if !client.is_up().await && computer::start(home).is_ok() {
        for _ in 0..20 {
            if client.is_up().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    client.is_up().await
        && client
            .hand(asked)
            .await
            .is_ok_and(|taken| taken.get("status").and_then(Value::as_str) != Some("refused"))
}

/// The answer already left for an ask for controls still waiting, taken up, as a new ask would end
/// that one and lose what its person approved.
async fn answered_already(home: &Home) -> Result<Option<Asking>, Failure> {
    let Some(id) = taking_up::controls_asks_waiting(home)
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let Some(said) = taking_up::take_up_kept_if_asked(home).await? else {
        return Ok(None);
    };
    Ok(Some(Asking {
        id,
        status: "done".to_owned(),
        approve_at: Waits::ByLinkOnly.approve_at(),
        said,
        computer_link: None,
    }))
}

/// Asks, and hands the ask to Splint on this computer if the person has it here, starting it if this
/// is their computer and it isn't running. It waits for an answer here only where that can come with
/// nothing more from the agent: with `wait`, or for controls where this computer's own prompt asks
/// for its person by itself. Anywhere else nobody knows to answer until the agent hands the link
/// over, so it comes back at once. An ask still waiting comes back with its link either way. One
/// for controls lasts an hour and ends the one before it, and any other lasts as long as Signet gives
/// it.
pub async fn ask(home: &Home, flags: &[&str]) -> Result<Asking, Failure> {
    let installed =
        Installed::load(home)?.ok_or_else(|| Failure::refused("join first, with splint join"))?;
    let signet = SignetApi::new(home, &installed)?;
    let (changes, hours, wait) = changes_from(&signet, flags).await?;
    let controls = splint_core::asks::controls_delegate(&changes).is_some();
    if controls && let Some(answered) = answered_already(home).await? {
        return Ok(answered);
    }
    let hours = hours.or(controls.then_some(CONTROLS_HOURS));
    let who = signet.who().await?;
    let body = json!({"changes": changes, "hours": hours});
    let signed: Signed = serde_json::from_value(signet.agent_post("/v0/asks", &body).await?)
        .map_err(|_| Failure::refused("Signet's answer can't be read"))?;
    let asked = Asked {
        ask: signed.ask,
        identity: who.identity,
        address: who.address,
        draft: None,
        schema: None,
        linked: false,
        kinds: Vec::new(),
        agreed: Vec::new(),
        in_words: Default::default(),
    };
    let client = Client::new(home)?;
    let here = hand_here(home, &client, &asked).await;
    let waits = if !here {
        Waits::ByLinkOnly
    } else if client.here().await.is_ok_and(|here| here.prompts_by_itself) {
        Waits::AtAPrompt
    } else {
        Waits::Here
    };
    let approve_at = waits.approve_at();
    let waited = match waits {
        Waits::AtAPrompt if wait || controls => Some(WAIT_FOR_TOUCH),
        Waits::Here if wait => Some(WAIT_FOR_TOUCH),
        _ => None,
    };
    if let Some(limit) = waited {
        match client.answer_within(&signed.id, limit, LOOK_EVERY).await? {
            // A step is done only once its chain holds the owner's yes, which only Signet reads:
            // this computer handing the yes on says nothing of whether Signet took it.
            Some(Outcome::Done { answer: None })
                if splint_core::asks::step_of(&changes).is_some() =>
            {
                return status(home, &signed.id).await;
            }
            Some(Outcome::Done { answer }) => {
                let said = match answer {
                    Some(answer) => taking_up::take_up(home, &answer).await?,
                    None => "Done: your person approved it, and it's in force once your host passes it on."
                        .to_owned(),
                };
                return Ok(Asking {
                    id: signed.id,
                    status: "done".to_owned(),
                    approve_at,
                    said,
                    computer_link: None,
                });
            }
            Some(Outcome::NotApproved { .. }) => {
                return Ok(Asking {
                    id: signed.id,
                    status: "not_approved".to_owned(),
                    approve_at,
                    said: "Not approved, so nothing changed.".to_owned(),
                    computer_link: None,
                });
            }
            Some(Outcome::Waiting) | None => {}
        }
    }
    let controls = hours.filter(|_| controls);
    Ok(Asking {
        said: waiting_words(home, &signed.id, controls, waits, waited, &asked.address),
        id: signed.id,
        // What Signet said of one only it holds, and waiting for one Splint here just took.
        status: if here {
            "waiting".to_owned()
        } else {
            signed.status
        },
        approve_at,
        computer_link: Some(link_for(&asked.ask, &asked.address)),
    })
}

/// Where one ask stands, as this agent's Signet says.
pub async fn status(home: &Home, id: &str) -> Result<Asking, Failure> {
    let installed =
        Installed::load(home)?.ok_or_else(|| Failure::refused("join first, with splint join"))?;
    if !id.chars().all(|c| c.is_ascii_hexdigit()) || id.len() != 32 {
        return Err(Failure::refused("that isn't an ask's ID"));
    }
    let signet = SignetApi::new(home, &installed)?;
    let shown: StatusOnly =
        serde_json::from_value(signet.agent_get(&format!("/v0/asks/{id}")).await?)
            .map_err(|_| Failure::refused("Signet's answer can't be read"))?;
    let mut status = shown.status;
    let controls = splint_core::asks::controls_delegate(&shown.changes).is_some();
    // An ask for controls is answered at the agent's host, by whichever owner approved it, where the
    // agent takes it up itself, as it may not know its owner's ID until then. One approved on this
    // computer is handed back here too, which is all there is where its host didn't keep it.
    let finished = if status == "waiting" && controls {
        match Client::new(home)?.outcome(id).await {
            Ok(Some(Outcome::Done {
                answer: Some(answer),
            })) => Some(taking_up::take_up(home, &answer).await?),
            _ => taking_up::take_up_kept_if_asked(home).await?,
        }
    } else {
        None
    };
    if finished.is_some() {
        status = "done".to_owned();
    }
    // The same link the ask came back with, for as long as it waits, as the agent may not have kept
    // it.
    let computer_link = if status == "waiting" && !shown.ask.is_empty() {
        Some(link_for(&shown.ask, &signet.who().await?.address))
    } else {
        None
    };
    let opens = if computer_link.is_some() {
        " computer_link still opens it for them, on Splint on their own computer."
    } else {
        ""
    };
    let step = splint_core::asks::step_of(&shown.changes).is_some();
    let said = match status.as_str() {
        "done" if step => "Done: your person signed that step. Whether the request stands is its state, which a later step can change.".to_owned(),
        "done" => "Done: what you asked for is in force.".to_owned(),
        "not_approved" => {
            "Not approved: it ended before your person signed it, so nothing changed.".to_owned()
        }
        "owner_said_no" => "Your person said no to that step, so it didn't go.".to_owned(),
        "ended" => {
            "Ended: the request ended without your person's yes to that step, so it didn't go."
                .to_owned()
        }
        _ if controls && computer_link.is_some() => {
            format!("Still waiting for your person.{opens} {WHO_A_LINK_REACHES}")
        }
        _ => format!("Still waiting for your person.{opens}"),
    };
    Ok(Asking {
        id: id.to_owned(),
        status,
        approve_at: "their_controls",
        said: finished.unwrap_or(said),
        computer_link,
    })
}

/// What the first approval at a terminal says before it asks for a new passphrase.
const WHY_A_PASSPHRASE: &str = "This approval makes your sign-in on this computer: a key file, locked \
     with a passphrase you choose, so nothing else running as you, your agent included, can sign as \
     you. You type it for each approval. Keep it safe: nothing here can reset it.";
/// What choosing a plain key file means, said before it's made.
const MAKES_A_PLAIN_KEY_FILE: &str = "Warning: --plain-key-file makes your sign-in on this computer a \
     key file with no passphrase. Anything running as you on this computer, your agent included, can \
     then sign as you.";

/// The person's own approval of what's waiting, at a terminal on this computer, one approval's worth
/// at a time, as one prompt would name them: each in fixed words with its code, then their passphrase,
/// asked once, or for a plain key file their typed yes. Each signs exactly the asks listed, by
/// their IDs and code, never one that came in while the person read them, and what's next is listed
/// only once that's done. A held step, a new place to be paid and a link's ask each come alone. The
/// first approval off the chip makes the sign-in, a key file locked with a passphrase chosen then,
/// or with `plain_key_file`, which only the person's own `--plain-key-file` sets, a plain one.
pub async fn approve_here(home: &Home, plain_key_file: bool) -> Result<String, Failure> {
    let client = Client::new(home)?;
    if !client.is_up().await {
        return Err(Failure::refused(
            "Splint on this computer isn't running, so nothing is waiting here",
        ));
    }
    let here = client.here().await?;
    let locked = here
        .sign_in
        .as_deref()
        .is_some_and(|held| held.contains("passphrase"));
    let none_yet = here.sign_in.is_none() && !here.prompts_by_itself;
    if plain_key_file && !none_yet {
        let why = if here.sign_in.is_none() {
            "this computer's security chip keeps your sign-in"
        } else {
            "your sign-in on this computer is made already"
        };
        return Err(Failure::refused(format!(
            "{why}, so {} changes nothing: run splint computer approve",
            computer::PLAIN_KEY_FILE
        )));
    }
    let mut waiting = client.waiting().await?;
    if waiting.asks.is_empty() {
        return Ok("Nothing is waiting for you.".to_owned());
    }
    let mut make_plain = plain_key_file;
    if make_plain {
        crate::authorize::say(MAKES_A_PLAIN_KEY_FILE)?;
    } else if here.plain_key_file {
        crate::authorize::say(computer::PLAIN_KEY_FILE_WARNING)?;
    }
    let mut passphrase: Option<String> = None;
    let (mut approved, mut refused) = (0, 0);
    let mut then = String::new();
    let mut pass_on = String::new();
    // Never more approvals than were waiting at the start, so asks that keep coming can't keep the
    // person here.
    for turn in 0..=waiting.later.len() {
        let Some(code) = waiting.code.clone().filter(|_| !waiting.asks.is_empty()) else {
            break;
        };
        crate::authorize::say(&one_approval_in_words(&waiting.asks))?;
        let go = if here.prompts_by_itself {
            // The chip asks for the person's touch itself, from the exact bytes it signs.
            true
        } else if none_yet && !plain_key_file && passphrase.is_none() {
            crate::authorize::say(WHY_A_PASSPHRASE)?;
            passphrase = Some(computer::choose_passphrase()?);
            true
        } else if locked && passphrase.is_none() {
            passphrase = Some(crate::authorize::secret("Your sign-in's passphrase:")?);
            true
        } else {
            let asked = if turn == 0 {
                "Type yes to sign these, and anything else to stop:"
            } else {
                "Type yes to sign these too, and anything else to stop:"
            };
            crate::authorize::answer(asked)? == crate::authorize::YES
        };
        if !go {
            break;
        }
        // Made here, by the command the person ran, only once they've typed yes.
        if std::mem::take(&mut make_plain) {
            computer::make_plain_sign_in(home)?;
        }
        let ids: Vec<String> = waiting.asks.iter().map(|shown| shown.id.clone()).collect();
        let done = client.approve(passphrase.as_deref(), &ids, &code).await?;
        if let Some(error) = done.error {
            if approved + refused == 0 {
                return Err(Failure::refused(error));
            }
            then = format!(" Then: {error}.");
            break;
        }
        approved += done.approved;
        refused += done.refused;
        for unkept in &done.pass_on {
            pass_on.push_str(&format!(
                "\n\n{}'s host didn't keep your answer, so it can't take it up from there. Send it \
                 this line, all of it:\n\n  splint finish {}",
                unkept.address, unkept.answer
            ));
        }
        waiting = client.waiting().await?;
    }
    if approved + refused == 0 {
        return Ok("Nothing was signed.".to_owned());
    }
    let left = waiting.asks.len()
        + waiting
            .later
            .iter()
            .map(|later| later.asks.len())
            .sum::<usize>();
    let more = if left > 0 {
        let (wait, them) = if left == 1 {
            ("waits", "it")
        } else {
            ("wait", "them")
        };
        format!(
            " {left} more {wait} for an approval: run splint computer approve again to see {them}."
        )
    } else {
        String::new()
    };
    let reminder = if client.here().await.is_ok_and(|here| here.recovery_not_set) {
        "\n\nYour owner ID has no recovery code yet, so losing this computer would lose it. When you can \
         write one down, run splint computer recovery."
    } else {
        ""
    };
    Ok(format!(
        "Approved {approved} and refused {refused}. Your agents hear it from their hosts.{then}{pass_on}{more}{reminder}"
    ))
}

/// One approval's worth, as the terminal lists it: each ask in the words its prompt names it by, which
/// `owner-key` wrote from what it signs, a link's ask with its warning, the words agents wrote in a
/// held step apart and marked as theirs, and the warning when something lets more in.
fn one_approval_in_words(asks: &[computer::Shown]) -> String {
    let mut lines = vec!["Your agents ask you to:".to_owned()];
    for shown in asks {
        for said in &shown.in_words.said {
            lines.push(format!("  - {said}"));
        }
        // What each type named holds, in core's fixed words, so it's approved knowing.
        for kind in &shown.kinds {
            lines.extend(kind.lines.iter().map(|line| format!("    {line}")));
        }
        if shown.from_link {
            lines.push(format!(
                "  That came by a link, which any website can open: approve it only if {} is your agent \
                 and gave it to you in its chat.",
                shown.address
            ));
        } else if shown
            .changes
            .iter()
            .any(|change| matches!(change, splint_core::asks::Change::Controls { .. }))
        {
            lines.push(
                "  Approve this only if it's your agent and its chat shows it joining Splint."
                    .to_owned(),
            );
        }
    }
    let written: Vec<&str> = asks
        .iter()
        .flat_map(|shown| shown.in_words.written.iter().map(String::as_str))
        .collect();
    if !written.is_empty() {
        lines.push(format!(
            "Words from the request, not Splint's: {}",
            written.join(", ")
        ));
    }
    // The same warning the prompt and the page give, in fixed words, only when something lets more in.
    if asks.iter().any(|shown| shown.lets_more_in) {
        lines.push(
            "This lets more in than before. Only approve it if you asked for it, or it's what you \
             want."
                .to_owned(),
        );
    }
    lines.join("\n")
}

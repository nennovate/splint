//! The owner's side of an agent signing itself up: on the owner's own device, says what they're agreeing
//! to, asks their choices, and signs. After that it changes the agent's rules straight at its host, so
//! nothing an owner decides waits on the agent passing it on.
//!
//! The agent named only an address and a key. Everything else here comes from this device, so an agent
//! that's been fooled can't choose anything for its owner, or word what they're shown.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, ErrorKind, Write as _};

use serde::{Deserialize, Serialize};
use splint_core::requests::{InteractionType, Schema};
use splint_core::rules::{
    InboundFilter, InboundFrom, Level, Outbound, Permissions, QuotedPrices, RulesDraft,
};
use splint_core::{AgentKeys, Identity, JoinReply, SplintId, name_parts, parse_address, unix_now};

use crate::auto;
use crate::contacts::{self, line_for};
use crate::direct::{self, Direct, ForHost, Route, Sent};
use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::host_calls::{Delivered, HostCalls};
use crate::owner_key::{AgentBackup, OwnerKey};
use crate::owner_side::OwnerSide;
use crate::rules::{self, Signed, first_rules, without_ended_invitations};
use crate::secrets::write_private;
use crate::services::Started;
use crate::setup;

/// An owner's answer that means they mean it. A closed stdin never says this.
pub const YES: &str = "yes";
/// The owner's two answers where settings take out contacts the agent added by itself.
const KEEP: &str = "keep";
const DROP: &str = "drop";

/// An agent this device has signed for, which runs somewhere else. None of this is secret, but it's the
/// only record of what the owner last signed, since rules are replaced whole.
#[derive(Clone, Serialize, Deserialize)]
pub struct Authorized {
    pub address: String,
    key: String,
    identity: String,
    pub agent: SplintId,
    backup: AgentBackup,
    draft: RulesDraft,
    pub signed_at: u64,
    /// The owner's `seq` on the rules this device last signed, so newer ones another device signed show.
    #[serde(default)]
    seq: u64,
}

fn load(home: &Home) -> Result<Vec<Authorized>, Failure> {
    match fs::read(home.authorized_file()) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| Failure::refused("authorized.json in the Splint folder can't be read")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn save(home: &Home, all: &[Authorized]) -> Result<(), Failure> {
    let bytes = serde_json::to_vec_pretty(all)
        .map_err(|_| Failure::refused("couldn't write down the agents authorized here"))?;
    write_private(&home.authorized_file(), &bytes)?;
    Ok(())
}

fn remember(home: &Home, record: &Authorized) -> Result<(), Failure> {
    let mut all = load(home)?;
    all.retain(|known| known.address != record.address && known.key != record.key);
    all.push(record.clone());
    save(home, &all)
}

/// The agent `splint add` and the like mean, on a device with no Signet of its own and one agent
/// authorized. A device that has its own goes on working as it did, unless its owner authorized it
/// from this machine, as one of their profiles, when it's that record. A profile that isn't set up
/// means no agent at all.
pub fn the_agent_elsewhere(home: &Home) -> Result<Option<Authorized>, Failure> {
    if let Some(installed) = Installed::load(home)? {
        let Some(agent) = installed
            .agent
            .filter(|_| installed.owner_elsewhere.is_some())
        else {
            return Ok(None);
        };
        return Ok(load(home)?.into_iter().find(|known| known.agent == agent));
    }
    if home.profile().is_some() {
        return Ok(None);
    }
    let mut all = load(home)?;
    match all.len() {
        0 => Ok(None),
        1 => Ok(all.pop()),
        _ => Err(Failure::refused(
            "you've authorized several agents from here, so say which: splint for HANDLE~HOST ...",
        )),
    }
}

impl Authorized {
    pub fn signed_rules(&self) -> Signed {
        Signed {
            draft: self.draft.clone(),
            signed_at: self.signed_at,
            seq: self.seq,
        }
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }
}

pub fn all(home: &Home) -> Result<Vec<Authorized>, Failure> {
    load(home)
}

pub fn named(home: &Home, address: &str) -> Result<Authorized, Failure> {
    load(home)?
        .into_iter()
        .find(|known| known.address == address)
        .ok_or_else(|| Failure::refused("you haven't authorized that agent from this device"))
}

pub fn say(text: &str) -> Result<(), Failure> {
    let mut err = io::stderr();
    writeln!(err, "{text}")?;
    err.flush()?;
    Ok(())
}

/// A secret typed at the terminal, such as a key file's passphrase, read from the terminal itself with
/// echo off, so it never shows on screen. Where standard input isn't a terminal, as when a program
/// pipes it, its next line, whether or not there's a terminal elsewhere.
pub fn secret(prompt: &str) -> Result<String, Failure> {
    use std::io::IsTerminal as _;
    let piped = || {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).map(|_| line)
    };
    let typed = if io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{prompt} ")).or_else(|_| piped())?
    } else {
        piped()?
    };
    Ok(typed.trim_end_matches(['\r', '\n']).to_owned())
}

/// One line from whoever's answering, trimmed. A closed stdin answers nothing, which takes the default.
pub fn answer(prompt: &str) -> Result<String, Failure> {
    let mut err = io::stderr();
    write!(err, "{prompt} ")?;
    err.flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

/// Types the owner can name here by name: those in schema files they keep in this device's schemas
/// folder, such as Splint's examples, which give each one's ID. Nothing is installed from them, and
/// with none, contacts get no type by name, as the two agents agree what they use.
fn known_types(home: &Home) -> Result<Vec<InteractionType>, Failure> {
    Ok(known_schemas(home)?
        .iter()
        .map(|schema| schema.name().clone())
        .collect())
}

fn known_schemas(home: &Home) -> Result<Vec<Schema>, Failure> {
    let unreadable = || Failure::refused("the schema files here can't be read");
    let entries = match fs::read_dir(home.schemas()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(unreadable()),
    };
    let mut schemas = Vec::new();
    for entry in entries {
        let path = entry.map_err(|_| unreadable())?.path();
        if path.extension().is_some_and(|found| found == "json") {
            let bytes = fs::read(path).map_err(|_| unreadable())?;
            schemas.push(Schema::parse(&bytes).map_err(|_| unreadable())?);
        }
    }
    schemas.sort_by(|one, other| one.name().cmp(other.name()));
    Ok(schemas)
}

/// Each type the owner names, by its whole ID or by its name and version alone, as a person types it,
/// where only one schema here has that name.
fn types_from(words: &str, known: &[InteractionType]) -> Result<Vec<InteractionType>, Failure> {
    if words.is_empty() {
        return Ok(known.to_vec());
    }
    words
        .split(',')
        .map(|word| {
            let word = word.trim();
            let mut fits = known
                .iter()
                .filter(|found| found.as_str() == word || found.name() == word);
            match (fits.next(), fits.next()) {
                (Some(one), None) => Ok(one.clone()),
                (Some(_), Some(_)) => Err(Failure::refused(
                    "more than one type here has that name, so give its whole ID, and nothing was signed",
                )),
                _ => Err(Failure::refused(
                    "that isn't one of the types listed, so nothing was signed",
                )),
            }
        })
        .collect()
}

fn filter_from(words: &str) -> Result<InboundFilter, Failure> {
    let mut filter = InboundFilter::default();
    for word in words
        .split(',')
        .map(str::trim)
        .filter(|word| !word.is_empty())
    {
        if word == "past" {
            filter.past = true;
        } else {
            filter
                .owners
                .push(contacts::id_from_line(word).map_err(|_| {
                    Failure::refused(
                        "that isn't an owner's ID or the word past, so nothing was signed",
                    )
                })?);
        }
    }
    Ok(filter)
}

/// What an owner chooses on the command line rather than by answering questions, so authorizing is one
/// screen and one typed yes, and the same flags change an agent's settings later. Nothing here comes
/// from the agent.
#[derive(Default)]
pub struct Choices<'a> {
    reach: Option<InboundFrom>,
    types: Option<&'a str>,
    filter: Option<&'a str>,
    writes: Option<Outbound>,
    level: Option<Level>,
    quoted_prices: Option<QuotedPrices>,
    name: Option<&'a str>,
}

/// The flags, each once with its value after it, or nothing is signed.
pub fn choices_from<'a>(flags: &[&'a str]) -> Result<Choices<'a>, Failure> {
    let unknown = || {
        Failure::refused(
            "that isn't one of the settings: --reach contacts|open|filter, --types, --filter, \
             --writes contacts|replies, --level ask-me|auto|full-auto, --quoted-prices \
             wait|within-limits, or --name, so nothing was signed",
        )
    };
    let mut choices = Choices::default();
    let mut rest = flags.iter();
    while let Some(flag) = rest.next() {
        let value = *rest.next().ok_or_else(unknown)?;
        let twice = match *flag {
            "--reach" => choices
                .reach
                .replace(match value {
                    "contacts" => InboundFrom::Contacts,
                    "open" => InboundFrom::Open,
                    "filter" => InboundFrom::Filter,
                    _ => return Err(unknown()),
                })
                .is_some(),
            "--types" => choices.types.replace(value).is_some(),
            "--filter" => choices.filter.replace(value).is_some(),
            "--writes" => choices
                .writes
                .replace(match value {
                    "contacts" => Outbound::Contacts,
                    "replies" => Outbound::Replies,
                    _ => return Err(unknown()),
                })
                .is_some(),
            "--level" => choices
                .level
                .replace(match value {
                    "ask-me" => Level::AskMe,
                    "auto" => Level::AutoWithinLimits,
                    "full-auto" => Level::FullAuto,
                    _ => return Err(unknown()),
                })
                .is_some(),
            "--quoted-prices" => choices
                .quoted_prices
                .replace(match value {
                    "wait" => QuotedPrices::Wait,
                    "within-limits" => QuotedPrices::WithinLimits,
                    _ => return Err(unknown()),
                })
                .is_some(),
            "--name" => choices.name.replace(value).is_some(),
            _ => return Err(unknown()),
        };
        if twice {
            return Err(unknown());
        }
    }
    Ok(choices)
}

impl Choices<'_> {
    pub fn is_empty(&self) -> bool {
        self.reach.is_none()
            && self.types.is_none()
            && self.filter.is_none()
            && self.writes.is_none()
            && self.level.is_none()
            && self.quoted_prices.is_none()
            && self.name.is_none()
    }

    /// Changes what was chosen and nothing else. Choosing who can reach the agent starts that setting
    /// afresh, with nobody's words let in, as it was when this was asked question by question.
    fn apply(&self, draft: &mut RulesDraft, known: &[InteractionType]) -> Result<(), Failure> {
        match self.reach {
            None if self.types.is_some() || self.filter.is_some() => {
                return Err(Failure::refused(
                    "--types and --filter go with --reach open or --reach filter, so nothing was signed",
                ));
            }
            None => {}
            Some(reach) => {
                draft.reach.inbound.from = reach;
                draft.reach.inbound.filter = InboundFilter::default();
                draft.reach.inbound.text = false;
                draft.reach.inbound.types = Vec::new();
                if reach == InboundFrom::Contacts {
                    if self.types.is_some() || self.filter.is_some() {
                        return Err(Failure::refused(
                            "--reach contacts lets in nobody else, so it takes no --types or \
                             --filter, and nothing was signed",
                        ));
                    }
                } else {
                    if reach == InboundFrom::Filter {
                        draft.reach.inbound.filter = filter_from(self.filter.unwrap_or_default())?;
                        if draft.reach.inbound.filter == InboundFilter::default() {
                            return Err(Failure::refused(
                                "--reach filter needs --filter with owners' IDs or the word past, so \
                                 nothing was signed",
                            ));
                        }
                    } else if self.filter.is_some() {
                        return Err(Failure::refused(
                            "--filter goes with --reach filter, so nothing was signed",
                        ));
                    }
                    draft.reach.inbound.types = types_from(self.types.unwrap_or_default(), known)?;
                }
            }
        }
        if let Some(writes) = self.writes {
            draft.reach.outbound = writes;
        }
        if let Some(level) = self.level {
            draft.permissions.level = level;
        }
        if let Some(quoted) = self.quoted_prices {
            draft.permissions.quoted_prices = quoted;
        }
        Ok(())
    }
}

/// The flags, said where an owner can use them.
const THE_FLAGS: &str = "--reach contacts|open|filter, --types with commas, --filter with owners' IDs \
     or past, --writes contacts|replies, --level ask-me|auto, --quoted-prices wait|within-limits";

/// The settings an owner signs, in this device's words.
fn settings_in_words(draft: &RulesDraft) -> String {
    let types = |types: &[InteractionType]| {
        types
            .iter()
            .map(InteractionType::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let inbound = &draft.reach.inbound;
    let reach = match inbound.from {
        InboundFrom::Contacts if draft.lets_agreed_in() => {
            "contacts you name and those it adds. Anyone else waits for you.".to_owned()
        }
        InboundFrom::Contacts => "contacts you name. Anyone else waits for you.".to_owned(),
        InboundFrom::Open => format!("anyone, for {}.", types(&inbound.types)),
        InboundFrom::Filter => format!(
            "owners you named, or people it has dealt with, for {}.",
            types(&inbound.types)
        ),
    };
    let writes = match draft.reach.outbound {
        Outbound::Contacts => "only its contacts.",
        Outbound::Replies => "its contacts, and anyone let in who wrote to it first.",
    };
    // Amounts are said once, below, by side and by the owner's own setting, so no line here says
    // every amount waits beside a setting that lets their quotes go.
    let level = match draft.permissions.level {
        Level::AskMe => "Ask me: nothing you'd be held to goes out until you say yes.",
        Level::AutoWithinLimits => {
            "Go ahead: it acts by itself under the limits, and while splint auto runs here this \
             device gives the final yes on a kind you sign, where there's no amount in it."
        }
        Level::FullAuto => {
            "Full auto, wider than go ahead: it acts by itself, up to 2,500 actions a day, and \
             this device also signs its cancels."
        }
    };
    format!(
        "\
Your settings
  Who can reach your agent: {reach}
  Whom it can write to: {writes}
  With nobody there: {level} It decides what to do, and code holds it to what you sign.
{amounts}
  {agreed}",
        amounts = amounts_in_words(&draft.permissions),
        agreed = rules::agreed_in_words(draft),
    )
}

/// What waits for the owner where there's an amount, by which side would pay, as their settings
/// hold it: a price they'd pay waits at every level, and one their agent quotes, where they'd be paid,
/// as their `quoted_prices` says (Nenye's call of 2026-11-13, issue 809). Every line is true whichever
/// they chose, so none can contradict the setting beside it.
fn amounts_in_words(permissions: &Permissions) -> String {
    let quoted = match (permissions.level, permissions.quoted_prices) {
        (Level::AskMe, _) => "waits for you, as everything does at Ask me.",
        (_, QuotedPrices::Wait) => {
            "waits for you too, unless you set --quoted-prices within-limits."
        }
        (_, QuotedPrices::WithinLimits) => {
            "goes by itself, within the limits above, as you set with --quoted-prices."
        }
    };
    format!(
        "  A price you'd pay: always waits for you.
  A price it quotes, where you'd be the one paid: {quoted}
  A kind with money: used with a contact only once you approve it for them.
  A number not labelled as money: marked, never held."
    )
}

/// What the owner agrees to, in this device's words and none of the agent's. The address and key are
/// the only things the agent chose, and both have been parsed, so neither can carry anything else.
fn what_youre_agreeing_to(
    home: &Home,
    address: &str,
    key: &str,
    agent: &SplintId,
    backup: &AgentBackup,
) -> String {
    let owner = home.owner_dir();
    format!(
        "\
An agent asks to act for you on Splint.

  Address  {address}
  Its key  {key}
  Its ID   {agent}

What you're agreeing to
  Whoever holds that key acts for you at that address, under the rules you sign here, until you
  change them. Say yes only if you asked your agent to join, and it gave you this itself. If
  someone else got you to run this, say no: anyone who holds that key could write in your name to
  whoever you let it reach, and to anyone who trusts you by name.
  You can change the rules or stop it at any time from here, without its help.

Where your keys are
  Your owner key   {owner}/owner.key, which signs for you
  Your backup      {owner}/backup.key, which gets your ID back if that's lost or stolen
  Its backup       {backup}, which does the same for this agent's ID
  Move the two backups off this device. Your agent never sees any of these. Never give them to it or
  anyone else, whoever asks.",
        owner = owner.display(),
        backup = backup.file.display(),
    )
}

/// What signs by the owner's rules for the agents authorized here runs with the default profile, from
/// whichever profile the owner authorized one. After `splint stop` there it stays stopped, and says so.
fn start_signing(home: &Home) -> Result<&'static str, Failure> {
    let signer = home.the_default();
    signer.prepare()?;
    Ok(match auto::start(&signer)? {
        Started::Running => "",
        Started::LeftStopped => {
            "\n\nSigning here is stopped, as you ran splint stop, so nothing is signed by itself until \
             you run splint start."
        }
    })
}

/// Whether any agent runs from this machine's Splint folder, the default or a profile. They all run as
/// this computer user, so each could read an owner key made here.
fn an_agent_on_this_machine(home: &Home) -> Result<bool, Failure> {
    for one in home.every()? {
        if Installed::load(&one)?.is_some()
            || one.join_file().exists()
            || one.agent_public_key().exists()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Asks, and signs. Nothing is signed before the owner has typed yes, and the agent has no address until
/// it takes this up.
pub async fn authorize(
    home: &Home,
    address: &str,
    key: &str,
    choices: &Choices<'_>,
) -> Result<String, Failure> {
    parse_address(address).map_err(Failure::not_an_address)?;
    // An agent that joined on its own keeps its stand-in here, which can't confirm anyone. And where any
    // agent runs from this machine's Splint folder, an owner key made here would be within its reach,
    // unless its owner already chose to keep theirs here with splint setup.
    let owner_key = OwnerKey::new(home);
    let beside_an_agent = an_agent_on_this_machine(home)?;
    if owner_key.is_stand_in()
        || fs::read_to_string(home.agent_public_key()).is_ok_and(|here| here.trim() == key)
        || (beside_an_agent && !OwnerKey::new(&home.the_default()).is_real_owner())
    {
        return Err(Failure::refused(
            "this is the machine that agent runs on. Run this on your own device, or as another user, \
             so it can't reach your keys",
        ));
    }
    if beside_an_agent {
        say(&setup::owner_key_here_warning(&home.the_default()))?;
    }
    // The owner's key and what they authorized are the same for every profile here.
    home.the_default().prepare()?;
    if let Some(joined) = joined_on_its_own(address, key).await? {
        return confirm(home, address, key, &joined, choices).await;
    }
    let owner_identity = owner_key.identity()?;
    let earlier = load(home)?;
    let same_key = earlier.iter().find(|known| known.key == key);
    let backup = match same_key {
        Some(known) => known.backup.clone(),
        None => owner_key.new_agent_backup()?,
    };
    let agent = owner_key
        .agent_identity(key, &backup.commitment)
        .map_err(|_| Failure::refused("that isn't an agent's key, so nothing was signed"))?;
    let known = known_types(home)?;

    say(&what_youre_agreeing_to(
        home,
        address,
        key,
        &agent.agent_id,
        &backup,
    ))?;
    if let Some(other) = earlier
        .iter()
        .find(|found| found.address == address && found.key != key)
    {
        say(&format!(
            "\nYou already authorized a different agent at this address, with ID {}. This replaces that \
             record here, and the host decides who holds the address.",
            other.agent
        ))?;
    }
    if choices.name.is_some() {
        return Err(Failure::refused(
            "--name is for an agent that joined on its own, so nothing was signed",
        ));
    }
    let mut draft = same_key.map_or_else(first_rules, |found| found.draft.clone());
    choices.apply(&mut draft, &known)?;
    say(&format!(
        "\n{}\n\nTo sign others, stop here and run this again with any of {THE_FLAGS}. splint for \
         {address} settings changes them later.",
        settings_in_words(&draft)
    ))?;
    let word =
        answer("\nType yes to sign this for that key at that address, and anything else to stop:")?;
    if word != YES {
        return Err(Failure::refused("nothing was signed"));
    }

    let binding = owner_key.bind(&agent.identity, address, &backup)?;
    // A new agent here has agreed nothing yet.
    let rules = owner_key.sign_rules(&agent.agent_id, &draft, &[])?;
    let seq = rules::seq_of(home, &rules)?;
    let owner_id = Identity::from_encoded(&owner_identity)?.id().clone();
    let reply = JoinReply::new(owner_identity, backup.commitment.clone(), binding, rules);
    remember(
        home,
        &Authorized {
            address: address.to_owned(),
            key: key.to_owned(),
            identity: agent.identity,
            agent: agent.agent_id.clone(),
            backup,
            draft,
            signed_at: unix_now(),
            seq,
        },
    )?;
    // Saves anyone copying it by hand, and a host that won't keep it only means they have to.
    let signing = start_signing(home)?;
    let whole = reply.encode()?;
    let (_, domain) = parse_address(address)?;
    let kept = HostCalls::new(domain)?.keep_answer(key, &whole).await;
    let answer_line = if kept { owner_id.to_string() } else { whole };
    Ok(format!(
        "\
Signed. The address isn't taken until your agent finishes. Send it this line, all of it:

  splint finish {answer_line}

Your agent's line, for anyone it should reach. They run it, and you run theirs here:

  {line}

From here you can run splint add, splint remove, splint renew and splint agents, and
splint for {address} revoke stops it at its host at once. None of these needs your agent's help.

splint page and splint waiting show what's waiting for you, wherever your agent runs. What your rules
allow gets signed here by itself, for as long as this device is on, unless you chose ask me.{signing}",
        line = line_for(address, &agent.agent_id),
    ))
}

/// The agent at this address, if it has these keys and joined on its own, with no controls yet. Its
/// host could lie about that, and gains nothing: what's signed here counts only for this ID, once its
/// stand-in has moved it to a backup only this device holds.
async fn joined_on_its_own(address: &str, key: &str) -> Result<Option<Identity>, Failure> {
    let keys = AgentKeys::from_encoded(key)
        .map_err(|_| Failure::refused("that isn't an agent's key, so nothing was signed"))?;
    let (_, domain) = parse_address(address)?;
    let Ok(found) = HostCalls::new(domain)?.resolve(address).await else {
        return Ok(None);
    };
    let agent = Identity::from_encoded(&found.identity)?;
    let owner = Identity::from_encoded(&found.owner_identity)?;
    let ours = agent.sole_key().ok() == Some(&keys.key) && agent.seal_key() == Some(&keys.seal);
    Ok((ours && owner.is_unconfirmed_owner()).then_some(agent))
}

/// The owner's name on this host, which goes after the agent's handle. An owner who's confirmed an
/// agent there before has one already, and the host holds them to it. Otherwise it's `--name`, or none.
fn owner_part(home: &Home, address: &str, given: Option<&str>) -> Result<String, Failure> {
    let (name, domain) = parse_address(address)?;
    let known = load(home)?.into_iter().find_map(|record| {
        let (name, there) = parse_address(&record.address).ok()?;
        (there == domain).then(|| name_parts(name).1.map(str::to_owned))?
    });
    if let Some(known) = known {
        return Ok(format!("{name}.{known}~{domain}"));
    }
    let Some(word) = given else {
        return Ok(address.to_owned());
    };
    let named = format!("{name}.{word}~{domain}");
    parse_address(&named).map_err(|_| {
        Failure::refused("that name won't fit in an address, so nothing was signed")
    })?;
    Ok(named)
}

/// Sets up controls for an agent that joined on its own: says what that means, asks the same choices
/// as for a new one, and signs. The agent's stand-in hands it over once it takes this up, moving its ID to a backup
/// made here, and what's signed here counts only after that.
async fn confirm(
    home: &Home,
    address: &str,
    key: &str,
    agent: &Identity,
    choices: &Choices<'_>,
) -> Result<String, Failure> {
    let owner_key = OwnerKey::new(home);
    let owner_identity = owner_key.identity()?;
    let known = known_types(home)?;
    // The backup is made only on a yes, so saying no leaves nothing behind.
    let to_be = AgentBackup {
        commitment: String::new(),
        file: home.owner_dir().join("agent-backups"),
    };
    say(&format!(
        "{}\n\n  This agent joined on its own, and has been dealing with agents open to anyone \
         and with agents that accepted its invites, under tight limits, committing nobody to \
         anything. Setting up your controls for it signs that it acts for you, under your rules \
         and your contacts, with this device holding the backup that can recover its ID.",
        what_youre_agreeing_to(home, address, key, agent.id(), &to_be)
    ))?;
    let confirmed_at = owner_part(home, address, choices.name)?;
    let mut draft = first_rules();
    choices.apply(&mut draft, &known)?;
    let (name, domain) = parse_address(address)?;
    let naming = if confirmed_at == address {
        format!(
            "\n  It'll be {confirmed_at}. To have your name after its handle, as {name}.NAME~{domain}, \
             which is yours there for good, add --name NAME."
        )
    } else {
        format!("\n  It'll be {confirmed_at}.")
    };
    say(&format!(
        "{naming}\n\n{}\n\nTo sign others, stop here and run this again with any of {THE_FLAGS}. \
         splint for {confirmed_at} settings changes them later.",
        settings_in_words(&draft)
    ))?;
    let word = answer(
        "\nType yes to sign that this agent acts for you, under these controls, and anything else to stop:",
    )?;
    if word != YES {
        return Err(Failure::refused("nothing was signed"));
    }
    let backup = owner_key.new_agent_backup()?;
    let text = serde_json::to_string(&draft)
        .map_err(|_| Failure::refused("couldn't write down the rules"))?;
    let whole = owner_key.set_up(agent, &confirmed_at, &backup, &text)?;
    let owner_id = Identity::from_encoded(&owner_identity)?.id().clone();
    remember(
        home,
        &Authorized {
            address: confirmed_at.clone(),
            key: key.to_owned(),
            identity: agent.encoded(),
            agent: agent.id().clone(),
            backup,
            draft,
            signed_at: unix_now(),
            // Signed inside the confirmation, so the rules its host holds once the agent takes it up
            // are taken over these, and they're the same.
            seq: 0,
        },
    )?;
    let signing = start_signing(home)?;
    let (_, domain) = parse_address(address)?;
    let kept = HostCalls::new(domain)?.keep_answer(key, &whole).await;
    let answer_line = if kept { owner_id.to_string() } else { whole };
    Ok(format!(
        "\
Signed. Your controls are set up for your agent once it takes this up. Send it this line, all of it:

  splint finish {answer_line}

It'll be {confirmed_at}. Its contacts are told, and the agents it had added wait for your yes again.
Your agent's line, for anyone it should reach:

  {line}

From here you can run splint add, splint remove, splint renew and splint agents, and
splint for {confirmed_at} revoke stops it at its host at once. None of these needs your agent's help.

splint page and splint waiting show what's waiting for you, wherever your agent runs. What your rules
allow gets signed here by itself, for as long as this device is on, unless you chose ask me.{signing}",
        line = line_for(&confirmed_at, agent.id()),
    ))
}

/// Signs and hands the rules to the agent's Signet straight, where it can be reached from here, and to
/// its host whatever happened there. So an agent can't keep a change from counting by not passing it
/// on, or by standing in for its Signet, and one its host can't be reached for has it at once.
pub async fn sign_and_send(
    home: &Home,
    record: &Authorized,
    draft: RulesDraft,
) -> Result<Route, Failure> {
    // A cap can name a type the agents agreed, which only what the agent's Signet left here says.
    let agreed: Vec<Schema> = if draft.permissions.caps.is_empty() {
        Vec::new()
    } else {
        crate::owner_side::OwnerSide::Elsewhere(Box::new(record.clone()))
            .read(home)
            .await?
            .schemas
            .all()
            .cloned()
            .collect()
    };
    let rules = OwnerKey::new(home).sign_rules(&record.agent, &draft, &agreed)?;
    let seq = rules::seq_of(home, &rules)?;
    let sent = send_rules(home, &record.agent, &record.address, &rules).await;
    // Rules only a straight answer took are kept and go to the host until it takes them, so they're
    // what this device signed last, and the next change starts from them.
    if matches!(sent, Ok(_) | Err(Failure::NotYetAtHost(_))) {
        remember(
            home,
            &Authorized {
                draft,
                signed_at: unix_now(),
                seq,
                ..record.clone()
            },
        )?;
    }
    sent
}

/// Rules the owner signed, to the agent's Signet straight if it can be reached from here, and to its
/// host whatever that said. Done only once the host takes them, as a straight answer could be anyone's:
/// one that only says yes is `Failure::NotYetAtHost`, and the rules are kept for the host.
pub async fn send_rules(
    home: &Home,
    agent: &SplintId,
    address: &str,
    rules: &str,
) -> Result<Route, Failure> {
    let straight = match Direct::find(home, agent)? {
        Some(direct) => match direct.put_rules(rules).await {
            Ok(()) => Some(direct.route()),
            Err(_) => None,
        },
        None => None,
    };
    let (_, domain) = parse_address(address)?;
    let at_host = HostCalls::new(domain)?.put_rules(rules).await;
    let sent = Sent {
        kind: ForHost::Rules,
        signed: rules,
        sealed: None,
    };
    direct::settle(home, agent, address, &sent, straight, at_host)
}

/// An authorized agent's settings, or, with flags, those changes signed on one typed yes.
pub async fn settings(
    home: &Home,
    record: &Authorized,
    choices: &Choices<'_>,
) -> Result<String, Failure> {
    let address = &record.address;
    let side = OwnerSide::Elsewhere(Box::new(record.clone()));
    let current = side.rules(home).await?.draft;
    if choices.is_empty() {
        return Ok(format!(
            "{}\n\nsplint for {address} settings with any of {THE_FLAGS} signs others.",
            settings_in_words(&current)
        ));
    }
    if choices.name.is_some() {
        return Err(Failure::refused(
            "--name is chosen once, when an agent that joined on its own is authorized, so nothing \
             was signed",
        ));
    }
    let mut draft = current.clone();
    choices.apply(&mut draft, &known_types(home)?)?;
    say(&settings_in_words(&draft))?;
    // Who these take out is said before anything's signed, with what's chosen for them unless the
    // owner says otherwise.
    let taken_out = side.added_taken_out(home, &current, &draft).await;
    let ask = match &taken_out {
        Some(added) if !added.is_empty() => {
            say(&format!(
                "\n{}, so these take out the contacts {address} added by itself: {}.\n{}",
                rules::why_added_go(&draft),
                rules::added_addresses(added),
                rules::keep_or_drop_words(&draft),
            ))?;
            format!(
                "\nType yes to sign these for {address} and take them out, keep to keep them \
                 instead, and anything else to stop:"
            )
        }
        Some(_) => format!("\nType yes to sign these for {address}, and anything else to stop:"),
        None => {
            say(&format!(
                "\n{}, and {address}'s host didn't say in time which contacts it added by itself, \
                 so any it has go. splint for {address} page lists them afterwards, to add back.",
                rules::why_added_go(&draft),
            ))?;
            format!("\nType yes to sign these for {address}, and anything else to stop:")
        }
    };
    let word = answer(&ask)?;
    let kept = match (word.as_str(), &taken_out) {
        (KEEP, Some(added)) if !added.is_empty() => {
            rules::keep_added(&mut draft, &current, added)?;
            added.len()
        }
        (YES | DROP, Some(added)) if !added.is_empty() => 0,
        (YES, Some(added)) if added.is_empty() => 0,
        (YES, None) => 0,
        _ => return Err(Failure::refused("nothing was signed")),
    };
    let route = sign_and_send(home, record, draft).await?;
    let said = match kept {
        0 => format!("Signed. {address} goes by these now."),
        1 => format!("Signed. {address} goes by these now, and the contact it added is your own."),
        _ => format!(
            "Signed. {address} goes by these now, and the {kept} contacts it added are your own."
        ),
    };
    Ok(format!("{said} They went {}.", route.words()))
}

pub async fn add(
    home: &Home,
    record: &Authorized,
    address: &str,
    id: &str,
) -> Result<String, Failure> {
    let id = contacts::id_from_line(id)?;
    let mut draft = OwnerSide::Elsewhere(Box::new(record.clone()))
        .rules(home)
        .await?
        .draft;
    let own = (record.address.as_str(), &record.agent);
    if !contacts::with_contact(&mut draft, own, address, id, known_types(home)?)? {
        return Ok(format!(
            "{address} is already one of that agent's contacts."
        ));
    }
    sign_and_send(home, record, draft).await?;
    Ok(format!(
        "{address} is now one of {agent}'s contacts. Its Signet hears within a minute, and it can write to \
         them once they've run its line:\n\n  {line}",
        agent = record.address,
        line = line_for(&record.address, &record.agent),
    ))
}

pub async fn renew(home: &Home, record: &Authorized) -> Result<String, Failure> {
    let draft = OwnerSide::Elsewhere(Box::new(record.clone()))
        .rules(home)
        .await?
        .draft;
    let draft = without_ended_invitations(draft, unix_now());
    let route = sign_and_send(home, record, draft).await?;
    Ok(format!(
        "Signed {}'s rules again. They last until you sign others. They went {}.",
        record.address,
        route.words()
    ))
}

/// Stops it at its host, by the owner's signature alone. Authorizing it again brings it back.
pub async fn revoke(home: &Home, record: &Authorized) -> Result<String, Failure> {
    let revocation = OwnerKey::new(home).revoke(&record.agent)?;
    let (_, domain) = parse_address(&record.address)?;
    match HostCalls::new(domain)?.post_revocation(&revocation).await? {
        Delivered::Taken => Ok(format!(
            "{} acts for nobody now, and can't send or be found. Run splint authorize again to bring it back.",
            record.address
        )),
        Delivered::NoSuchAgent => Err(Failure::refused(
            "that agent's host doesn't have it, so there's nothing to stop there",
        )),
    }
}

/// How an agent was last reached from here, and how it's reached first now.
fn reached_words(home: &Home, agent: &SplintId, now: u64) -> Result<String, Failure> {
    let first = match Direct::find(home, agent)? {
        Some(direct) => direct.route(),
        None => Route::Host,
    };
    let last = match direct::last_reached(home, agent) {
        Some((route, at)) => format!(
            "last {}, {} ago",
            route.words(),
            direct::ago(now.saturating_sub(at))
        ),
        None => "not yet from here".to_owned(),
    };
    let first = match first {
        Route::Host => "by way of its host".to_owned(),
        route => format!(
            "{} first, and its host as well for what you sign",
            route.words()
        ),
    };
    Ok(format!("{first}; {last}"))
}

pub fn agents(home: &Home) -> Result<String, Failure> {
    let all = load(home)?;
    if all.is_empty() {
        return Ok("You haven't authorized any agents from this device.".to_owned());
    }
    let mut out = String::new();
    let now = unix_now();
    for record in all {
        let _ = writeln!(
            out,
            "{}\n  Its line  {}\n  Rules     in force until you sign others\n  Contacts  {}",
            record.address,
            line_for(&record.address, &record.agent),
            record.draft.contacts.len(),
        );
        let _ = writeln!(
            out,
            "  Reached   {}",
            reached_words(home, &record.agent, now)?
        );
        for kind in direct::not_at_host(home, &record.agent) {
            let _ = writeln!(
                out,
                "  Waiting   {what}, signed here, which its host hasn't taken yet: splint sends {them} \
                 again each time it runs here, and splint auto while it runs",
                what = kind.words(),
                them = kind.them(),
            );
        }
    }
    Ok(out.trim_end().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example(file: &str) -> InteractionType {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/schemas")
            .join(file);
        Schema::parse(&fs::read(path).unwrap())
            .unwrap()
            .name()
            .clone()
    }

    // Bug caught: --types quote/1 was refused even with quote/1 kept here, as only a whole ID matched.
    #[test]
    fn an_owner_names_a_kept_type_by_its_name_and_signs_its_whole_id() {
        let (meeting, quote) = (example("meeting-1.json"), example("quote-1.json"));
        let known = [meeting.clone(), quote.clone()];
        assert_eq!(
            types_from("quote/1", &known).unwrap(),
            std::slice::from_ref(&quote)
        );
        assert_eq!(
            types_from(&format!("{}, meeting/1", quote.as_str()), &known).unwrap(),
            [quote, meeting]
        );
        assert!(types_from("not/1", &known).is_err());
    }
}

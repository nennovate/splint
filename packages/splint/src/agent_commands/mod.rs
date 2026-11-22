//! What an agent with only a shell runs in place of an adapter's tools: `inbox`, `ack`,
//! `contacts`, `send`, `delivery`, `wait`, `types`, `requests`, `open`, `move`, `propose` and
//! `where-paid`. Each makes the same calls to this agent's Signet with arguments of the same names,
//! and with `--json` prints what the tool returns, so an agent learns one model whichever way it
//! reaches Splint. Every check that matters is Signet's: these only rename fields, shorten IDs and
//! write times both ways.
//!
//! In words, whatever anyone else wrote is quoted, escaped and marked untrusted, so none of it can
//! pass for a line of Splint's own.

mod messages;
mod requests;
mod shown;
pub mod times;

pub(crate) use requests::held_step_id;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use serde_json::{Map, Value};

use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::invites::Said;
use crate::signet_api::SignetApi;

const COMMANDS: [&str; 12] = [
    "inbox",
    "ack",
    "contacts",
    "send",
    "delivery",
    "wait",
    "types",
    "requests",
    "open",
    "move",
    "propose",
    "where-paid",
];

/// IDs are 64 characters, about 40 tokens each time. An agent cut one down to note it, then couldn't
/// use it. 16 is far beyond what anyone can make two of on purpose, and two that fit are refused.
const SHOWN_ID_CHARS: usize = 16;
const FULL_ID_CHARS: usize = 64;
const FEWEST_ID_CHARS: usize = 8;
const MOST_ID_CHARS: usize = 128;
/// Words for `send` given on stdin, so a runaway pipe can't fill memory.
const MOST_STDIN_BYTES: u64 = 64 * 1024;
const FROM_STDIN: &str = "-";

/// What follows a command: its own words, and each `--name value`, named as the tool's arguments are.
#[derive(Default)]
struct Given<'a> {
    words: Vec<&'a str>,
    named: HashMap<&'a str, &'a str>,
    record: bool,
}

impl<'a> Given<'a> {
    /// `takes` names the `--name value` arguments this command has.
    fn of(args: &[&'a str], takes: &[&str]) -> Result<Self, Failure> {
        let mut given = Self::default();
        let mut rest = args.iter();
        while let Some(word) = rest.next() {
            match word.strip_prefix("--") {
                Some("record") if takes.contains(&"record") => given.record = true,
                Some(name) if takes.contains(&name) => {
                    let value = rest.next().ok_or(Failure::Usage)?;
                    if given.named.insert(name, value).is_some() {
                        return Err(Failure::Usage);
                    }
                }
                Some(_) => return Err(Failure::Usage),
                None => given.words.push(word),
            }
        }
        Ok(given)
    }

    fn named(&self, name: &str) -> Option<&'a str> {
        self.named.get(name).copied()
    }
}

/// An ID goes into a URL path, so it can't be allowed to name a different call.
fn id_from(given: &str) -> Result<&str, Failure> {
    let fits = (1..=MOST_ID_CHARS).contains(&given.len())
        && given
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if fits {
        Ok(given)
    } else {
        Err(Failure::refused("not an id"))
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(SHOWN_ID_CHARS).collect()
}

/// The whole ID that one as shown stands for, among those the agent can name. Never a guess.
fn whole_id(given: &str, known: &[String]) -> Result<String, Failure> {
    let id = id_from(given)?;
    if id.len() >= FULL_ID_CHARS {
        return Ok(id.to_owned());
    }
    one_of(id, known)?.ok_or_else(|| Failure::refused("no such id"))
}

/// Which of `among` an ID, whole or as shown, is, if any.
fn one_of(given: &str, among: &[String]) -> Result<Option<String>, Failure> {
    let id = id_from(given)?;
    let mut fits = among
        .iter()
        .filter(|whole| id.len() >= FEWEST_ID_CHARS && whole.starts_with(id));
    match (fits.next(), fits.next()) {
        (Some(only), None) => Ok(Some(only.clone())),
        (Some(_), Some(_)) => Err(Failure::refused("more than one id starts like that")),
        (None, _) => Ok(None),
    }
}

/// A field of what Signet answered, or nothing.
fn text_at<'v>(value: &'v Value, pointer: &str) -> &'v str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn list_at<'v>(value: &'v Value, pointer: &str) -> &'v [Value] {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Whether a value says nothing, so an answer only pays for what's there.
fn says_nothing(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => true,
        Value::String(text) => text.is_empty(),
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
        Value::Bool(true) => false,
    }
}

/// The fields that say something, as the adapter's `compact` leaves them.
fn compact<'k>(fields: impl IntoIterator<Item = (&'k str, Value)>) -> Map<String, Value> {
    fields
        .into_iter()
        .filter(|(_, value)| !says_nothing(value))
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// An answer of Signet's with only the fields that say something.
fn compacted(value: Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .filter(|(_, value)| !says_nothing(value))
                .collect(),
        ),
        other => other,
    }
}

/// Said only when it's no, which is what an agent has to act on: its person hasn't approved them.
fn unapproved(from: &Value, into: &mut Map<String, Value>) {
    if from.pointer("/approved_by_owner") == Some(&Value::Bool(false)) {
        into.insert("approved_by_owner".to_owned(), Value::Bool(false));
    }
}

/// Signet's own facts about the other side, who they are to the owner and any warnings, in its fixed
/// words, passed on as the adapter's tools give them, so a model triages on them and not on what was
/// written. The rest of the facts stay with Signet, to keep what a model reads short.
fn facts(of: &Value, into: &mut Map<String, Value>) {
    if let Some(contact) = of.pointer("/facts/contact") {
        into.insert("contact".to_owned(), contact.clone());
    }
    if let Some(warnings) = of
        .pointer("/facts/warnings")
        .filter(|warnings| warnings.as_array().is_some_and(|all| !all.is_empty()))
    {
        into.insert("warnings".to_owned(), warnings.clone());
    }
}

/// Said only when they act for this agent's own person, as Signet checked by owner ID, with that ID.
fn same_owner(from: &Value, into: &mut Map<String, Value>) {
    if from.pointer("/same_owner") == Some(&Value::Bool(true)) {
        into.insert("same_owner".to_owned(), Value::Bool(true));
        if let Some(owner) = from.get("owner") {
            into.insert("owner".to_owned(), owner.clone());
        }
    }
}

/// What the agent calls each contact: the label its owner signed, or the address when that label could
/// mean anyone else. A name leads to one address, whatever its case, so it can't send to the wrong
/// person.
#[derive(Default)]
struct Names {
    by_address: HashMap<String, String>,
    by_name: HashMap<String, String>,
}

impl Names {
    fn new(contacts: &[Value]) -> Self {
        let mut uses: HashMap<String, usize> = HashMap::new();
        for contact in contacts {
            let label = text_at(contact, "/label").to_lowercase();
            let count = uses.entry(label).or_default();
            *count = count.saturating_add(1);
        }
        let addresses: Vec<String> = contacts
            .iter()
            .map(|contact| text_at(contact, "/address").to_lowercase())
            .collect();
        let mut names = Self::default();
        for contact in contacts {
            let (label, address) = (text_at(contact, "/label"), text_at(contact, "/address"));
            let folded = label.to_lowercase();
            let own = folded == address.to_lowercase();
            let clear = !label.is_empty()
                && uses.get(&folded) == Some(&1)
                && (own || !addresses.contains(&folded));
            let shown = if clear { label } else { address };
            names
                .by_address
                .insert(address.to_owned(), shown.to_owned());
            if clear {
                names.by_name.insert(folded, address.to_owned());
            }
        }
        names
    }

    async fn of(api: &SignetApi<'_>) -> Result<Self, Failure> {
        let contacts = api.agent_get("/v0/contacts").await?;
        Ok(Self::new(list_at(&contacts, "/contacts")))
    }

    fn name(&self, address: &str) -> String {
        self.by_address
            .get(address)
            .cloned()
            .unwrap_or_else(|| address.to_owned())
    }

    /// An address goes on as it was typed, in any of its spellings, for Signet to judge.
    fn address(&self, name: &str) -> Result<String, Failure> {
        if self.by_address.contains_key(name) {
            return Ok(name.to_owned());
        }
        if let Some(address) = self.by_name.get(&name.to_lowercase()) {
            return Ok(address.clone());
        }
        if name.contains('~') || name.contains("::") || name.contains('@') {
            return Ok(name.to_owned());
        }
        Err(Failure::refused(
            "no contact has that name: see splint contacts",
        ))
    }
}

/// Words for `send`, from stdin when they're given as `-`, where quotes and newlines need no escaping.
/// Past the limit it's refused, not cut, as a note sent short would read to its sender as all of it.
fn words_or_stdin(words: &[&str]) -> Result<String, Failure> {
    if words == [FROM_STDIN] {
        let mut bytes = Vec::new();
        io::stdin()
            .take(MOST_STDIN_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::refused("couldn't read stdin"))?;
        if u64::try_from(bytes.len()).map_or(true, |read| read > MOST_STDIN_BYTES) {
            return Err(Failure::refused(format!(
                "what came on stdin is over {MOST_STDIN_BYTES} bytes, more than splint send takes"
            )));
        }
        let mut text = String::from_utf8(bytes)
            .map_err(|_| Failure::refused("what came on stdin isn't text"))?;
        // `echo` and editors end with a newline nobody meant as part of the note.
        if text.ends_with('\n') {
            text.pop();
            if text.ends_with('\r') {
                text.pop();
            }
        }
        return Ok(text);
    }
    Ok(words.join(" "))
}

async fn run(
    home: &Home,
    command: &str,
    args: &[&str],
    flag_in_note: bool,
) -> Result<Said, Failure> {
    let splint = &home.command();
    // A note's words could be --json or --as themselves, so neither is taken from among them and the
    // note cut, or sent by another agent. Refused before anything's looked up, as --as may name none.
    if command == "send" && flag_in_note && args.get(1..) != Some(&[FROM_STDIN][..]) {
        return Err(Failure::refused(format!(
            "a note's words could hold --json, --as or --help, so give those before NAME, or the words on \
             stdin: {splint} send NAME - --json"
        )));
    }
    let (installed, _) = Installed::require(home)?;
    let api = SignetApi::new(home, &installed)?;
    let api = &api;
    match (command, args) {
        ("inbox", []) => messages::inbox(api, splint, None).await,
        ("inbox", [id]) => messages::inbox(api, splint, Some(id)).await,
        ("ack", ids) if !ids.is_empty() => messages::ack(api, home, ids).await,
        ("contacts", []) => messages::contacts(api, splint).await,
        ("send", [to, words @ ..]) if !words.is_empty() => {
            messages::send(api, home, to, &words_or_stdin(words)?).await
        }
        ("delivery", []) => messages::recent(api).await,
        ("delivery", [id]) => messages::delivery(api, home, id).await,
        ("wait", args) => {
            messages::wait(api, home, splint, &Given::of(args, &["since", "gather"])?).await
        }
        ("types", []) => requests::types(api, None).await,
        ("where-paid", []) => requests::where_paid(api).await,
        ("types", [kind]) => requests::types(api, Some(kind)).await,
        ("requests", args) => {
            let given = Given::of(args, &["skip", "record"])?;
            requests::requests(api, splint, &given).await
        }
        ("open", args) => {
            let given = Given::of(args, &["terms", "hours", "supersedes"])?;
            requests::open(api, splint, &given).await
        }
        ("move", args) => {
            let given = Given::of(args, &requests::MOVE_INPUTS)?;
            requests::make_move(api, splint, &given).await
        }
        ("propose", args) => {
            let given = Given::of(args, &["schema"])?;
            requests::propose(api, splint, &given).await
        }
        _ => Err(Failure::Usage),
    }
}

/// Runs one of these commands, if the words name one. Like `check`, its words are the agent's own,
/// so none of them is respelled as an address: a note's words go to Signet as they were typed.
pub async fn dispatch(typed: &crate::Typed<'_>) -> Option<ExitCode> {
    let [command, args @ ..] = typed.words.as_slice() else {
        return None;
    };
    if !COMMANDS.contains(command) {
        return None;
    }
    let said = async {
        let home = Home::from_env(typed.chosen)?;
        run(&home, command, args, typed.flag_in_note).await
    }
    .await;
    Some(match (said, typed.json) {
        (said, true) => crate::printed_json(said.map(|said| said.json), Some(command)),
        (Ok(said), false) if writeln!(io::stdout(), "{}", said.text).is_ok() => ExitCode::SUCCESS,
        (Ok(_), false) => ExitCode::FAILURE,
        (Err(failure), false) => crate::failed(&failure, Some(command)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bug this catches: a short or shared start acking, reading or moving whichever came first, so a
    // message the agent never read leaves its inbox.
    #[test]
    fn an_id_as_shown_stands_for_one_whole_id_or_none() {
        let known = vec![
            "6a1b2c3d4e5f".repeat(6),
            "6a1b2c3d9999".repeat(6),
            "f00dfeed".repeat(8),
        ];
        let refused = |given: &str| matches!(whole_id(given, &known), Err(Failure::Refused(_)));
        assert!(
            refused("f00dfee"),
            "under 8 characters, though only one fits"
        );
        assert!(refused("6a1b2c3d"), "fits both");
        assert!(refused("77777777"), "fits none");
        assert_eq!(whole_id("6a1b2c3d4e", &known).ok().as_ref(), known.first());
    }
}

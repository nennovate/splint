//! Notes: `inbox`, `ack`, `send` and `delivery`, with `contacts`, who they go to, and `wait`.
//!
//! `inbox` acknowledges nothing by itself. A note stays unread until the agent acks it, so one that
//! stops partway through reading loses nothing. A long note is cut in the list, and `inbox ID` gives
//! that one whole, as Signet holds all of it until it's acked.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use serde_json::{Map, Value, json};
use splint_core::private_files;

use super::times::shown_time;
use super::{
    FULL_ID_CHARS, Given, Names, compact, compacted, id_from, list_at, one_of, same_owner,
    short_id, shown, text_at, unapproved,
};
use crate::check;
use crate::failure::Failure;
use crate::home::Home;
use crate::invites::Said;
use crate::secrets::write_private;
use crate::signet_api::{HeldMail, SignetApi};

const MAX_MESSAGES: usize = 10;
/// Counted as the adapter counts, in UTF-16 units, so both cut a note at the same place.
const MAX_TEXT_UNITS: usize = 2000;
/// Well under what an agent's runtime gives one command.
const WAIT_SECS: u64 = 30;
/// The most Signet gathers for.
const MAX_GATHER_SECS: u64 = 300;

/// The whole IDs of notes sent and acknowledged with these commands, kept so an ID as shown finds its
/// whole one for `delivery`, and an ack that's done already says so rather than that the ID is wrong.
/// They're only for wording: Signet checks every ID it's given, and acking stays Signet's to decide.
const SENT: &str = "sent-ids";
const ACKED: &str = "acked-ids";
/// The latest this many of each, which is far more than an agent has in hand at once.
const KEPT_IDS: usize = 500;

fn kept_path(home: &Home, which: &str) -> PathBuf {
    home.run_dir().join(which)
}

/// What's kept, with anything that isn't a whole ID left out.
fn kept(home: &Home, which: &str) -> Vec<String> {
    let text = fs::read_to_string(kept_path(home, which)).unwrap_or_default();
    text.lines()
        .filter(|id| id.len() == FULL_ID_CHARS && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_owned)
        .collect()
}

/// Added by appending, so two commands at once lose neither's, and cut back to the latest now and
/// then. Whether it was kept, as a shown ID is no use unless it was.
fn keep(home: &Home, which: &str, ids: &[String]) -> bool {
    if ids.is_empty() {
        return true;
    }
    let path = kept_path(home, which);
    let lines: String = ids.iter().map(|id| format!("{id}\n")).collect();
    let appended = private_files::open(OpenOptions::new().append(true).create(true), &path)
        .and_then(|mut file| file.write_all(lines.as_bytes()));
    if appended.is_err() {
        return false;
    }
    let all = kept(home, which);
    if all.len() > KEPT_IDS.saturating_mul(2) {
        let latest: String = all
            .iter()
            .skip(all.len().saturating_sub(KEPT_IDS))
            .map(|id| format!("{id}\n"))
            .collect();
        // Cutting back is only tidying: if it fails, the IDs are all still there.
        let _ = write_private(&path, latest.as_bytes());
    }
    true
}

/// A note's words up to the cut, and how many units were left out. Half a character at the cut
/// becomes U+FFFD, as it does through the adapter.
fn cut(text: &str) -> (String, usize) {
    let mut kept = String::new();
    let mut units = 0_usize;
    for c in text.chars() {
        let next = units.saturating_add(c.len_utf16());
        if next > MAX_TEXT_UNITS {
            if units < MAX_TEXT_UNITS {
                kept.push('\u{FFFD}');
            }
            break;
        }
        kept.push(c);
        units = next;
    }
    let all: usize = text.chars().map(char::len_utf16).sum();
    (kept, all.saturating_sub(MAX_TEXT_UNITS))
}

/// `whole` for a note asked for by its ID, which is given uncut.
fn message_view(message: &Value, names: &Names, whole: bool) -> Value {
    let body = text_at(message, "/untrusted/body");
    let (words, left_out) = if whole {
        (body.to_owned(), 0)
    } else {
        cut(body)
    };
    let from = message.pointer("/verified/from").unwrap_or(&Value::Null);
    let mut view = Map::new();
    view.insert(
        "id".to_owned(),
        json!(short_id(text_at(message, "/verified/message_id"))),
    );
    view.insert(
        "from".to_owned(),
        json!(names.name(text_at(from, "/address"))),
    );
    if let Some(controls) = from.get("controls") {
        view.insert("controls".to_owned(), controls.clone());
    }
    let at = message
        .pointer("/verified/created_at")
        .unwrap_or(&Value::Null);
    view.insert("at".to_owned(), json!(shown_time(at)));
    view.insert("untrusted".to_owned(), json!(words));
    let stranger = from.get("known_contact") != Some(&Value::Bool(true));
    view.extend(compact([
        ("stranger", json!(stranger)),
        ("cut", json!(left_out)),
    ]));
    unapproved(from, &mut view);
    same_owner(from, &mut view);
    super::facts(message, &mut view);
    Value::Object(view)
}

/// How a note reads in a terminal: its id and who it's from on one line, its words quoted under it.
fn message_lines(message: &Value, splint: &str, lines: &mut Vec<String>) {
    let mut about = vec![format!(
        "from {}",
        shown::defanged(text_at(message, "/from"))
    )];
    about.push(format!("at {}", text_at(message, "/at")));
    if let Some(controls) = message.get("controls").and_then(Value::as_str) {
        about.push(format!("controls: {}", shown::defanged(controls)));
    }
    if message.get("stranger") == Some(&Value::Bool(true)) {
        about.push("a stranger".to_owned());
    }
    if message.get("approved_by_owner") == Some(&Value::Bool(false)) {
        about.push("not approved by your person".to_owned());
    }
    if message.get("same_owner") == Some(&Value::Bool(true)) {
        about.push("your person's other agent".to_owned());
    }
    // Fixed words from Signet's closed set, shown as words a person reads.
    for warning in list_at(message, "/warnings") {
        if let Some(word) = warning.as_str() {
            about.push(shown::defanged(&word.replace('_', " ")));
        }
    }
    lines.push(format!(
        "  {}  {}",
        shown::defanged(text_at(message, "/id")),
        about.join(", ")
    ));
    let mut words = format!(
        "    untrusted: {}",
        shown::quoted(text_at(message, "/untrusted"))
    );
    if let Some(left_out) = message.get("cut").and_then(Value::as_u64) {
        words.push_str(&format!(
            " (cut: {left_out} more characters. {splint} inbox {} gives it whole)",
            shown::defanged(text_at(message, "/id"))
        ));
    }
    lines.push(words);
}

/// The unread notes, each cut to what a reader takes in at once, or with an ID, that one note whole.
pub async fn inbox(api: &SignetApi<'_>, splint: &str, id: Option<&str>) -> Result<Said, Failure> {
    let page = api.agent_get("/v0/inbox").await?;
    let mut messages = list_at(&page, "/messages").to_vec();
    if let Some(id) = id {
        let unread: Vec<String> = messages
            .iter()
            .map(|message| text_at(message, "/verified/message_id").to_owned())
            .collect();
        let whole = one_of(id, &unread)?.ok_or_else(|| {
            Failure::refused(format!(
                "{id} isn't one of your unread messages: {splint} inbox lists them"
            ))
        })?;
        messages.retain(|message| text_at(message, "/verified/message_id") == whole);
    }
    let names = if messages.is_empty() {
        Names::default()
    } else {
        Names::of(api).await?
    };
    let shown: Vec<Value> = messages
        .iter()
        .take(MAX_MESSAGES)
        .map(|message| message_view(message, &names, id.is_some()))
        .collect();
    let more = messages.len().saturating_sub(shown.len());
    // Once, at the top, rather than on each note.
    let reminder = page
        .get("reminder")
        .and_then(Value::as_str)
        .map(shown::defanged);
    let mut lines = Vec::new();
    if let Some(said) = &reminder {
        lines.push(said.clone());
    }
    if shown.is_empty() {
        lines.push("No unread messages.".to_owned());
    } else {
        lines.push(format!(
            "{} unread. `untrusted` is what the sender wrote.",
            shown.len()
        ));
        for message in &shown {
            message_lines(message, splint, &mut lines);
        }
        let ids: Vec<String> = shown
            .iter()
            .map(|message| shown::defanged(text_at(message, "/id")))
            .collect();
        lines.push(format!(
            "Each stays unread until you ack it, so nothing is lost if you stop partway. Once \
             you've taken them in: {splint} ack {}. Then Signet stops counting them, and they're \
             yours to handle: reply, move, or leave them, by your judgment.",
            ids.join(" ")
        ));
    }
    if more > 0 {
        let (wait, them) = if more == 1 {
            ("waits", "it")
        } else {
            ("wait", "them")
        };
        lines.push(format!(
            "{more} more {wait} behind these: ack these to see {them}."
        ));
    }
    let dropped = page.get("dropped").cloned().unwrap_or(Value::Null);
    if dropped.as_u64().is_some_and(|count| count > 0) {
        lines.push(format!(
            "{dropped} more were cleared, as they were proven forged, were replays or came from \
             someone the rules don't let in."
        ));
    }
    let held = page.get("held").cloned().unwrap_or(Value::Null);
    let held_mail: Vec<HeldMail> = serde_json::from_value(held.clone()).unwrap_or_default();
    if !held_mail.is_empty() {
        lines.push(
            "Some can't be opened or checked yet, so they stay at your host, and nothing is lost:"
                .to_owned(),
        );
        lines.extend(
            HeldMail::lines(&held_mail)
                .into_iter()
                .map(|line| format!("  {line}")),
        );
    }
    let removed = page
        .get("from_removed_contacts")
        .cloned()
        .unwrap_or(Value::Null);
    if removed.as_u64().is_some_and(|count| count > 0) {
        lines.push(format!(
            "{removed} more came from someone since taken out of your contacts, before that. They \
             wait unread and unseen: adding them back as a contact shows them, and otherwise they \
             end within a week."
        ));
    }
    let mut json = Map::new();
    if let Some(said) = reminder {
        json.insert("reminder".to_owned(), json!(said));
    }
    json.insert("messages".to_owned(), Value::Array(shown));
    json.extend(compact([
        ("more", json!(more)),
        ("dropped", dropped),
        ("held", held),
        ("from_removed_contacts", removed),
    ]));
    Ok(Said {
        text: lines.join("\n"),
        json: Value::Object(json),
    })
}

async fn unread(api: &SignetApi<'_>) -> Result<Vec<String>, Failure> {
    let page = api.agent_get("/v0/inbox").await?;
    Ok(list_at(&page, "/messages")
        .iter()
        .map(|message| text_at(message, "/verified/message_id").to_owned())
        .collect())
}

/// An ID acked before is told so and asks nothing of Signet, so an agent resuming partway through
/// can ack again safely. One that's neither unread nor acked here is refused before anything is
/// acked, as it may be a mistyped one.
pub async fn ack(api: &SignetApi<'_>, home: &Home, ids: &[&str]) -> Result<Said, Failure> {
    let unread_before = unread(api).await?;
    let acked_here = kept(home, ACKED);
    let (mut wanted, mut already) = (Vec::new(), Vec::new());
    for id in ids {
        let (into, whole) = if let Some(whole) = one_of(id, &unread_before)? {
            (&mut wanted, whole)
        } else if let Some(whole) = one_of(id, &acked_here)? {
            (&mut already, short_id(&whole))
        } else {
            return Err(Failure::refused(format!(
                "{} isn't one of your unread messages: splint inbox lists them",
                id_from(id)?
            )));
        };
        if !into.contains(&whole) {
            into.push(whole);
        }
    }
    let asked = !wanted.is_empty();
    let mut count = 0;
    if asked {
        let acked = api
            .agent_post("/v0/inbox/ack", &json!({ "message_ids": wanted }))
            .await?;
        count = acked.get("acked").and_then(Value::as_u64).unwrap_or(0);
        // Signet leaves what it won't let an agent clear, which stays unread.
        let left = if usize::try_from(count).ok() == Some(wanted.len()) {
            Vec::new()
        } else {
            unread(api).await?
        };
        wanted.retain(|id| !left.contains(id));
        keep(home, ACKED, &wanted);
    }
    let mut said = Vec::new();
    if asked || already.is_empty() {
        said.push(format!("Acknowledged {count}. They're off your inbox."));
    }
    if !already.is_empty() {
        said.push(format!(
            "Already acknowledged: {}, so there's nothing more to do for them.",
            already.join(" ")
        ));
    }
    let mut json = Map::new();
    json.insert("acked".to_owned(), json!(count));
    json.extend(compact([("already_acknowledged", json!(already))]));
    Ok(Said {
        text: said.join(" "),
        json: Value::Object(json),
    })
}

pub async fn contacts(api: &SignetApi<'_>, splint: &str) -> Result<Said, Failure> {
    let answer = api.agent_get("/v0/contacts").await?;
    let contacts = list_at(&answer, "/contacts");
    let names = Names::new(contacts);
    let listed: Vec<Value> = contacts
        .iter()
        .map(|contact| {
            let mut view = compact([
                ("name", json!(names.name(text_at(contact, "/address")))),
                (
                    "types",
                    contact.get("types").cloned().unwrap_or(Value::Null),
                ),
                ("text", contact.get("text").cloned().unwrap_or(Value::Null)),
            ]);
            unapproved(contact, &mut view);
            same_owner(contact, &mut view);
            Value::Object(view)
        })
        .collect();
    let json = Value::Array(listed);
    let text = if contacts.is_empty() {
        format!("No contacts yet. {splint} invite HANDLE~HOST invites someone.")
    } else {
        let mut lines = vec![
            "Who you can reach, the types each may use, and whether splint send reaches them (text). \
             approved_by_owner: false means ask your person before sharing their details or \
             committing them. same_owner: true means it acts for your person too."
                .to_owned(),
        ];
        lines.extend(shown::lines(&json));
        lines.join("\n")
    };
    Ok(Said { text, json })
}

/// In words, the ID as `inbox` shows one, which `delivery` takes. As JSON, the whole one the adapter's
/// tool gives, for a program that passes it on.
pub async fn send(api: &SignetApi<'_>, home: &Home, to: &str, text: &str) -> Result<Said, Failure> {
    let names = Names::of(api).await?;
    let sent = api
        .agent_post(
            "/v0/send",
            &json!({ "to": names.address(to)?, "body": text }),
        )
        .await?;
    let id = text_at(&sent, "/message_id").to_owned();
    let shown_id = if keep(home, SENT, std::slice::from_ref(&id)) {
        short_id(&id)
    } else {
        id.clone()
    };
    Ok(Said {
        text: format!(
            "Sent {0}. {splint} delivery {0} says what became of it.",
            shown::defanged(&shown_id),
            splint = home.command(),
        ),
        json: json!({ "id": id }),
    })
}

pub async fn delivery(api: &SignetApi<'_>, home: &Home, id: &str) -> Result<Said, Failure> {
    let id = id_from(id)?;
    let id = if id.len() >= FULL_ID_CHARS {
        id.to_owned()
    } else {
        one_of(id, &kept(home, SENT))?.ok_or_else(|| {
            Failure::refused(format!(
                "{id} isn't the id of a note sent from here: splint delivery takes what splint \
                 send gave"
            ))
        })?
    };
    let answer = api.agent_get(&format!("/v0/sent/{id}")).await?;
    let json = compacted(answer);
    Ok(Said {
        text: shown::lines(&json).join("\n"),
        json,
    })
}

/// The notes sent lately, newest first, each with where it stands.
pub async fn recent(api: &SignetApi<'_>) -> Result<Said, Failure> {
    let json = compacted(api.agent_get("/v0/sent").await?);
    let text = shown::lines(&json).join("\n");
    let text = if text.is_empty() {
        "No notes sent from here yet.".to_owned()
    } else {
        text
    };
    Ok(Said { text, json })
}

/// Until anything changes, or 30 seconds. With no `--since`, what already waits is said at once, as
/// nothing new would come for it and an agent that just started would sit on it.
pub async fn wait(
    api: &SignetApi<'_>,
    home: &Home,
    splint: &str,
    given: &Given<'_>,
) -> Result<Said, Failure> {
    let since = match given.named("since") {
        None => None,
        Some(since) => Some(
            since
                .parse::<u64>()
                .map_err(|_| Failure::refused("since is what the last wait gave"))?,
        ),
    };
    let gather = match given.named("gather") {
        None => 0,
        Some(gather) => gather
            .parse::<u64>()
            .ok()
            .filter(|gather| *gather <= MAX_GATHER_SECS)
            .ok_or_else(|| {
                Failure::refused(format!("--gather is seconds, up to {MAX_GATHER_SECS}"))
            })?,
    };
    if !given.words.is_empty() {
        return Err(Failure::Usage);
    }
    let since = match since {
        Some(since) => since,
        None => {
            // The mark first, so whatever comes while what waits is counted is new after it.
            let mark = api.wait(None, 0).await?.since;
            let kinds = check::waiting(api, home).await?.kinds();
            if !kinds.is_empty() {
                let waiting: Vec<&str> = kinds.iter().map(|kind| kind.word()).collect();
                return Ok(Said {
                    text: format!(
                        "Already waiting: {}. {splint} wait --since {mark} waits on from here.",
                        waiting.join(", ")
                    ),
                    json: json!({ "since": mark, "new": waiting }),
                });
            }
            mark
        }
    };
    let waited = api.wait_gathering(Some(since), WAIT_SECS, gather).await?;
    let new: Vec<&str> = waited.new.iter().map(|kind| kind.word()).collect();
    let text = if new.is_empty() {
        format!(
            "Nothing new in {WAIT_SECS} seconds. {splint} wait --since {} waits on from here.",
            waited.since
        )
    } else {
        format!(
            "New: {}. {splint} wait --since {} waits on from here.",
            new.join(", "),
            waited.since
        )
    };
    Ok(Said {
        text,
        json: json!({ "since": waited.since, "new": new }),
    })
}

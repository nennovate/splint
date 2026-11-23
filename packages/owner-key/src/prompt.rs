//! The words a sign-in's prompt shows, written here from the exact objects about to be signed, never
//! from anything the program or page that asked says about them. A Mac shows them after "Splint is
//! trying to", so they start with a verb.
//!
//! A prompt over an agent's asks names every change and its terms, so a person reads it alone and it
//! shows no code. A prompt over objects a page prepared names each only by its kind, so a $12 approval
//! and a $48,000 one read the same: it shows the touch code, which the page shows too, so a person can
//! tell that what reached the sign-in is what the page prepared. The code can't show that a page told
//! the truth about what it prepared. Either way the programs compare it after signing.

use serde_json::Value;
use splint_core::asks::{Change, VerifiedAsk};
use splint_core::prepared::{Prepared, touch_code, touch_code_of};
use splint_core::requests::{InteractionType, Operation, Place, Schema};
use splint_core::rules::{InboundFrom, Level, Outbound, QuotedPrices};
use splint_core::{Error, SplintId, parse_address};

/// The most lines one prompt holds. Every object and change signed is named on one: what doesn't fit
/// isn't signed with this touch, so nothing is ever signed behind an "and more".
pub const MOST_NAMED: usize = splint_core::asks::MOST_IN_ONE_APPROVAL;
/// What every prompt says, in the same fixed words as the page and the terminal, when something it
/// approves lets more in than before.
const LETS_MORE_IN: &str = "This lets more in than before";
/// Said once in a prompt setting up an agent among other asks. Agents can join on their own, so
/// whether the person asked isn't the test: whether it's theirs is, which its chat shows.
const CHECK_CHAT: &str =
    "Only set up an agent if it's your agent and its chat shows it joining Splint";

/// The most characters of one value an agent wrote that a prompt shows, and of all of them in one
/// prompt, so they can't push what's in fixed words out of sight.
const MOST_WRITTEN_PER_VALUE: usize = 40;
const MOST_WRITTEN: usize = 160;
/// What marks the words an agent wrote, which a prompt shows last, after the amount and everything in
/// fixed words, so nothing in them reads as the prompt's own.
const WRITTEN: &str = "Words from the request, not Splint's:";

/// What a sign-in's prompt shows. Only this module writes one, and the sign-in opens only with one, so
/// no command can open it without words written from what it's about to sign.
pub struct Prompt {
    /// Only a chip shows them, and Splint uses one only on a Mac.
    #[cfg(any(target_os = "macos", test))]
    words: String,
    /// The touch code of what it's over, for a prompt over objects or asks, which a command that signs
    /// them answers with, so a page can check that what was signed is what it prepared.
    code: Option<String>,
}

impl Prompt {
    fn new(words: String, code: Option<String>) -> Self {
        #[cfg(not(any(target_os = "macos", test)))]
        drop(words);
        Self {
            #[cfg(any(target_os = "macos", test))]
            words,
            code,
        }
    }

    #[cfg(any(target_os = "macos", test))]
    pub fn words(&self) -> &str {
        &self.words
    }

    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
}

/// A held step's terms as its prompt shows them: what's in fixed words and numbers, read first, and
/// the words either agent wrote in its fields, subject and note, kept apart to be shown last.
pub struct StepTerms {
    pub fixed: Vec<String>,
    pub written: Vec<String>,
}

/// Words an agent wrote, as a prompt shows them, quoted, as [`plain`] has them.
pub fn written(text: &str) -> String {
    format!("{:?}", plain(text))
}

/// Words an agent wrote, as a prompt shows them unquoted: printable ASCII alone, so no control
/// character, direction mark or letter that looks like another can make them read as the prompt's
/// own; each run of spaces as one, so padding can't push anything out of sight; and cut short past
/// [`MOST_WRITTEN_PER_VALUE`].
pub fn plain(text: &str) -> String {
    let mut plain = String::new();
    let mut space = false;
    for character in text.chars() {
        if character.is_whitespace() || character.is_control() {
            space = !plain.is_empty();
            continue;
        }
        if space {
            plain.push(' ');
            space = false;
        }
        plain.push(if character.is_ascii_graphic() {
            character
        } else {
            '?'
        });
    }
    let mut shown: String = plain.chars().take(MOST_WRITTEN_PER_VALUE).collect();
    if shown.len() < plain.len() {
        shown.push_str("...");
    }
    shown
}

/// One object, in a few fixed words.
fn described(prepared: &Prepared) -> String {
    let payload: Value = serde_json::from_slice(prepared.payload()).unwrap_or(Value::Null);
    let text = |path: &[&str]| {
        path.iter()
            .try_fold(&payload, |value, key| value.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let address = || {
        text(&["address"])
            .filter(|address| parse_address(address).is_ok())
            .unwrap_or_else(|| "an agent".to_owned())
    };
    match prepared.typ() {
        "splint-binding" => format!("let {} act for you", address()),
        "splint-rules" => {
            let paused = payload.get("paused").and_then(Value::as_bool) == Some(true);
            let level = match text(&["permissions", "level"]).as_deref() {
                Some("ask_me") => "ask me",
                Some("full_auto") => "full auto",
                _ => "go ahead",
            };
            let reach = match text(&["reach", "inbound", "from"]).as_deref() {
                Some("open") => "anyone may reach it",
                Some("filter") => "some owners may reach it",
                _ => "contacts reach it",
            };
            if paused {
                "pause an agent".to_owned()
            } else {
                format!("set an agent's rules: {level}, {reach}")
            }
        }
        "splint-delegation" => "let an agent's Signet say yes within your limits".to_owned(),
        "splint-approval" => match text(&["decision"]).as_deref() {
            Some("deny") => "say no to a request".to_owned(),
            _ => "say yes to a request".to_owned(),
        },
        "splint-owner-session" => "read what a host keeps for you".to_owned(),
        "splint-owner-agents" => "keep your list of agents".to_owned(),
        "splint-key-add" => "add a sign-in to your owner ID".to_owned(),
        "splint-key-remove" => "remove a sign-in from your owner ID".to_owned(),
        "splint-recovery-rule" => "set your recovery code".to_owned(),
        "splint-release" => "give an agent to another owner".to_owned(),
        "splint-retirement" => "retire an agent".to_owned(),
        "splint-change-accept" => "accept a contact's change".to_owned(),
        "splint-change-statement" => "say where an agent runs".to_owned(),
        "splint-person-text" => "send words of yours".to_owned(),
        "splint-where-paid" => {
            // The exact destinations, as a page signs them, for the person to check are theirs.
            let places: Vec<String> = payload
                .get("places")
                .and_then(Value::as_array)
                .map(|places| {
                    places
                        .iter()
                        .filter_map(|place| {
                            serde_json::from_value::<splint_core::requests::Place>(place.clone())
                                .ok()
                                .filter(splint_core::requests::Place::fits)
                        })
                        .map(|place| place.destination())
                        .collect()
                })
                .unwrap_or_default();
            format!("say people pay you at {}", places.join("; "))
        }
        "splint-grant" => "grant an agent a resource".to_owned(),
        "splint-grant-revocation" => "end a grant".to_owned(),
        other => format!("sign {other}"),
    }
}

/// The whole prompt for one touch over every object, each kind named once with how many, in the
/// order they come. More kinds than one prompt names is [`Error::Malformed`], and nothing is signed.
pub fn for_objects(prepared: &[Prepared]) -> Result<Prompt, Error> {
    let mut named: Vec<(String, usize)> = Vec::new();
    for one in prepared {
        let words = described(one);
        match named.iter_mut().find(|(said, _)| *said == words) {
            Some((_, count)) => *count = count.saturating_add(1),
            None => named.push((words, 1)),
        }
    }
    if named.len() > MOST_NAMED {
        return Err(Error::Malformed);
    }
    let lines: Vec<String> = named
        .into_iter()
        .map(|(words, count)| {
            if count > 1 {
                format!("{words}, {count} times")
            } else {
                words
            }
        })
        .collect();
    let code = touch_code(prepared);
    Ok(Prompt::new(
        format!("get your signature, code {code}: {}", lines.join("; ")),
        Some(code),
    ))
}

/// A type an ask names, as the prompt says it: its name, the start of its fingerprint, whether it has
/// money, and whether it's the example of that name or someone's own kind named like it.
/// Whoever handed the ask over gave each one's schema, and only one whose ID this device works out is
/// read.
fn kind_named(id: &InteractionType, kinds: &[Schema]) -> String {
    let mut about = vec![format!(
        "fingerprint {}",
        id.short_fingerprint().unwrap_or_default()
    )];
    if kinds
        .iter()
        .any(|kind| kind.name() == id && kind.includes_currency())
    {
        about.push("with money".to_owned());
    }
    match crate::examples::shipped().named(id.name()) {
        Some(example) if example.name() == id => about.push("the example".to_owned()),
        Some(_) => about.push("their own kind, not the example".to_owned()),
        None => {}
    }
    format!("{} ({})", id.name(), about.join(", "))
}

/// One change an agent asked for, in fixed words, naming the agent by the address its owner set up,
/// with who pays whom for a held step that pays anyone, and each type it names as [`kind_named`] says.
fn change_described(
    change: &Change,
    agent: &str,
    becomes: Option<&str>,
    terms: Option<&StepTerms>,
    kinds: &[Schema],
) -> String {
    let types = |types: &[InteractionType]| {
        types
            .iter()
            .map(|id| kind_named(id, kinds))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match change {
        Change::Step { operation, .. } => format!(
            "say yes to the {} {agent} holds for you{}",
            match operation {
                Operation::Open => "request",
                Operation::Counter => "counter-offer",
                Operation::Accept => "acceptance",
                Operation::Deliver => "delivery",
                Operation::Confirm => "confirmation",
                Operation::Cancel => "cancellation",
                Operation::OfferToGuest => "offer by link",
            },
            terms
                .filter(|terms| !terms.fixed.is_empty())
                .map(|terms| format!(": {}", terms.fixed.join(", ")))
                .unwrap_or_default()
        ),
        // The name the binding names is whole, with what it makes the person's at that host for good.
        Change::Controls { .. } => match becomes {
            Some(named) => format!("let {agent} act for you as {named}, {}", for_good(named)),
            None => format!("let {agent} act for you"),
        },
        Change::OwnerPart { to } => match becomes {
            Some(named) => format!("rename {agent} to {named}, {}", for_good(named)),
            None => format!("add {to} after {agent}'s handle"),
        },
        // The new host is the one thing approved, and a lookalike domain is the risk, so it's named
        // whole with what that host then holds.
        Change::Host { to } => format!(
            "move {agent} to {to}, a host that from then on carries its messages and sees who it \
             deals with and when. Only approve this if you asked {agent} to move there"
        ),
        Change::WherePaid { places } => format!(
            "{}, as {agent} asks, in place of where they paid you before. Only approve places \
             that are yours",
            places_described(places)
        ),
        // Each setting by the name the controls page gives it, so a person knows which one changes.
        Change::Level { to } => format!(
            "set {agent} to {}",
            match to {
                Level::AskMe => "Ask me first: it acts only once you say yes",
                Level::AutoWithinLimits => "Go ahead: it acts by itself within your limits",
                Level::FullAuto => "Full auto: it acts by itself on anything without an amount",
            }
        ),
        Change::QuotedPrices { to } => format!(
            "set prices {agent} quotes to {}",
            match to {
                QuotedPrices::Wait => "Wait for me: each waits for your yes",
                QuotedPrices::WithinLimits => "Go ahead within its limits: it sends them by itself",
            }
        ),
        Change::Reach {
            to,
            types: named,
            owners,
            past,
        } => match to {
            InboundFrom::Contacts => format!("let only contacts reach {agent}"),
            InboundFrom::Open => format!("let anyone reach {agent} for {}", types(named)),
            InboundFrom::Filter => {
                let mut who: Vec<String> = Vec::new();
                if !owners.is_empty() {
                    let ids: Vec<&str> = owners.iter().map(SplintId::as_str).collect();
                    who.push(format!("the owners {}", ids.join(", ")));
                }
                if *past {
                    who.push("anyone it dealt with before".to_owned());
                }
                if who.is_empty() {
                    who.push("nobody".to_owned());
                }
                format!(
                    "let {} reach {agent} for {}",
                    who.join(" and "),
                    types(named)
                )
            }
        },
        Change::Writes { to } => match to {
            Outbound::Contacts => format!("let {agent} write only to contacts"),
            Outbound::Replies => format!("let {agent} also answer whoever wrote to it"),
        },
        Change::Paused { to: true } => format!("pause {agent}"),
        Change::Paused { to: false } => format!("turn {agent} back on"),
        Change::Contact {
            agent: contact,
            address,
            types: named,
            text,
        } => {
            let mut what = Vec::new();
            if !named.is_empty() {
                what.push(format!("for {}", types(named)));
            }
            if *text {
                what.push("with words of their own".to_owned());
            }
            if what.is_empty() {
                what.push("for nothing yet".to_owned());
            }
            format!(
                "let {address}, agent {}, reach {agent} {}",
                contact.as_str(),
                what.join(" and ")
            )
        }
        Change::Remove { agent: contact } => {
            format!("remove {} from {agent}'s contacts", contact.as_str())
        }
        Change::Block {
            agent: contact,
            address,
        } => format!("block {address}, agent {}, from {agent}", contact.as_str()),
    }
}

/// What naming an agent under its owner's name makes theirs: that name at that host, for good, and the
/// only one they have there.
fn for_good(named: &str) -> String {
    match parse_address(named) {
        Ok((name, host)) => match splint_core::name_parts(name).1 {
            Some(owner_part) => format!("with {owner_part} as your name at {host} for good"),
            None => format!("with {name} as your name at {host} for good"),
        },
        Err(_) => "with that as your name at its host for good".to_owned(),
    }
}

/// One ask's changes, each in the fixed words every place a person approves it shows: the prompt, the
/// page and the terminal, which take them from here, so none can say less than another. A held step
/// comes with its terms; an agent's address that isn't one is "your agent".
pub fn ask_lines(
    ask: &VerifiedAsk,
    agent: &str,
    becomes: Option<&str>,
    terms: Option<&StepTerms>,
    kinds: &[Schema],
) -> Vec<String> {
    let agent = if parse_address(agent).is_ok() {
        agent
    } else {
        "your agent"
    };
    ask.changes()
        .iter()
        .map(|change| change_described(change, agent, becomes, terms, kinds))
        .collect()
}

/// The prompt for one touch approving every ask given, each with its agent's address, the address it
/// becomes where what's signed names it under its owner, and for a held step, its terms. Every change is named, so the words show no code, and the code over the asks as
/// the agents signed them is for the programs. A caller hands no more than [`MOST_NAMED`], which
/// [`fits`] says. Words an agent wrote come last of all, marked as theirs and bounded, so they can't
/// pass for the amount or Splint's own words.
pub fn for_asks(
    asks: &[(&VerifiedAsk, &str, Option<&str>, Option<&StepTerms>, &[Schema])],
    also: Option<&str>,
) -> Prompt {
    let named: Vec<String> = asks
        .iter()
        .flat_map(|(ask, agent, becomes, terms, kinds)| {
            ask_lines(ask, agent, *becomes, *terms, kinds)
        })
        .collect();
    let warning = if asks
        .iter()
        .any(|(ask, ..)| ask.changes().iter().any(Change::lets_more_in))
    {
        format!(". {LETS_MORE_IN}")
    } else {
        String::new()
    };
    let written: Vec<&str> = asks
        .iter()
        .filter_map(|(_, _, _, terms, _)| *terms)
        .flat_map(|terms| terms.written.iter().map(String::as_str))
        .collect();
    let written = if written.is_empty() {
        String::new()
    } else {
        let all = written.join(", ");
        let mut shown: String = all.chars().take(MOST_WRITTEN).collect();
        if shown.len() < all.len() {
            shown.push_str("...");
        }
        format!(". {WRITTEN} {shown}")
    };
    let code = touch_code_of(asks.iter().map(|(ask, ..)| ask.compact()));
    // What else this touch signs, in fixed words, before anything an agent wrote.
    let also = also.map(|also| format!("; and {also}")).unwrap_or_default();
    let asking = asks
        .first()
        .map(|(_, agent, ..)| *agent)
        .filter(|first| asks.iter().all(|(_, agent, ..)| agent == first))
        .and_then(spoken_name)
        .map(|name| format!(" for {name}"))
        .unwrap_or_default();
    // An agent asking only to be set up reads as just that, with the address that says which agent
    // and how to tell it's theirs: agents can join on their own, so whether the person asked isn't
    // the test, and its chat showing it joining at that address is.
    let opening = match asks {
        [(ask, agent, becomes, ..)] if matches!(ask.changes(), [Change::Controls { .. }]) => {
            let named = becomes.map(|named| format!(" {named}, {}", for_good(named)));
            spoken_name(agent).map(|name| {
                format!(
                    "set up {name} ({agent}) as your agent{}, if its chat shows it joining Splint",
                    named.unwrap_or_default()
                )
            })
        }
        _ => None,
    }
    .unwrap_or_else(|| format!("get your approval{asking}: {}", named.join("; ")));
    // Alone, the opening says it; among other asks, it's said once after them all.
    let check = if !opening.starts_with("set up ")
        && asks.iter().any(|(ask, ..)| {
            ask.changes()
                .iter()
                .any(|change| matches!(change, Change::Controls { .. }))
        }) {
        format!(". {CHECK_CHAT}")
    } else {
        String::new()
    };
    Prompt::new(
        format!("{opening}{also}{check}{warning}{written}"),
        Some(code),
    )
}

/// An agent's name as a person says it: "rae" for `rae.ana~host.example`, with a capital. It only
/// opens the prompt. Each line still gives the whole address, as a name says nothing of whose it is.
fn spoken_name(address: &str) -> Option<String> {
    let (name, _) = parse_address(address).ok()?;
    let mut letters = name.split('.').next()?.chars();
    let first = letters.next()?;
    Some(first.to_uppercase().chain(letters).collect())
}

/// Whether one more ask goes in a prompt with these, by the one rule Splint on the computer also
/// lists asks by, so the page and terminal show what this prompt names.
pub fn fits(with: &[&VerifiedAsk], ask: &VerifiedAsk) -> bool {
    let with: Vec<&[Change]> = with.iter().map(|one| one.changes()).collect();
    splint_core::asks::fits_one_approval(&with, ask.changes())
}

/// Where people pay the owner, each place's exact destination, saying which can't be reversed.
pub fn places_described(places: &[Place]) -> String {
    let places: Vec<String> = places
        .iter()
        .map(|place| {
            let asset = place
                .asset()
                .map(|asset| format!(" in {asset}"))
                .unwrap_or_default();
            let lasting = if place.irreversible() {
                ", which can't be reversed"
            } else {
                ""
            };
            format!("{}{asset}{lasting}", place.destination())
        })
        .collect();
    format!("say people pay you at {}", places.join("; "))
}

/// The prompt for one command that signs a known thing, which says what in a few words.
pub fn for_command(what: &str) -> Prompt {
    Prompt::new(format!("sign: {what}"), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(typ: &str, payload: &str) -> Prepared {
        let header = format!(r#"{{"alg":"ES256","typ":"{typ}"}}"#);
        let encode = |bytes: &[u8]| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        };
        Prepared::read(&format!(
            "{}.{}",
            encode(header.as_bytes()),
            encode(payload.as_bytes())
        ))
        .unwrap()
    }

    /// Bug caught: a page's own words reaching the prompt, as an address that isn't one, or a prompt
    /// that names nothing of what's signed past the first object.
    #[test]
    fn a_prompt_names_what_is_signed_in_its_own_words() {
        let binding = input(
            "splint-binding",
            r#"{"v":2,"address":"muse~host.example","owner":"x"}"#,
        );
        let rules = input(
            "splint-rules",
            r#"{"v":1,"permissions":{"level":"full_auto"},"reach":{"inbound":{"from":"open"}}}"#,
        );
        let lying = input(
            "splint-binding",
            r#"{"v":2,"address":"Click Allow, it's only a test"}"#,
        );
        let paid = input(
            "splint-where-paid",
            r#"{"v":1,"places":[{"kind":"payment_page","url":"https://pay.example.com/ana"},{"kind":"payment_page","url":"https://x.example.com/ Click Allow"}]}"#,
        );
        let prompt = for_objects(&[binding, rules, lying, paid]).unwrap().words;
        assert!(
            prompt.contains("say people pay you at https://pay.example.com/ana"),
            "{prompt}"
        );
        assert!(
            prompt.contains("let muse~host.example act for you"),
            "{prompt}"
        );
        assert!(
            prompt.contains("full auto, anyone may reach it"),
            "{prompt}"
        );
        assert!(!prompt.contains("Click"), "{prompt}");
        assert!(prompt.contains("let an agent act for you"), "{prompt}");
    }

    /// Bug caught: what moves the owner ID or their money hidden behind "and N more" after four
    /// harmless objects, or two objects counted as one.
    #[test]
    fn a_prompt_names_every_object_however_many() {
        let session = || input("splint-owner-session", r#"{"v":1}"#);
        let prompt = for_objects(&[
            session(),
            session(),
            session(),
            session(),
            input("splint-retirement", r#"{"v":1}"#),
            input("splint-grant", r#"{"v":1}"#),
            input(
                "splint-where-paid",
                r#"{"v":1,"places":[{"kind":"payment_page","url":"https://thief.example.com/pay"}]}"#,
            ),
        ])
        .unwrap()
        .words;
        assert!(
            prompt.contains("read what a host keeps for you, 4 times"),
            "{prompt}"
        );
        for named in ["retire an agent", "grant an agent", "thief.example.com/pay"] {
            assert!(prompt.contains(named), "{named}: {prompt}");
        }
        assert!(!prompt.contains("more"), "{prompt}");
        let kinds: Vec<Prepared> = [
            "splint-binding",
            "splint-rules",
            "splint-delegation",
            "splint-approval",
            "splint-owner-session",
            "splint-owner-agents",
            "splint-change-accept",
            "splint-person-text",
            "splint-grant",
        ]
        .iter()
        .map(|typ| input(typ, r#"{"v":1}"#))
        .collect();
        assert_eq!(for_objects(&kinds).err().unwrap(), Error::Malformed);
    }

    /// Bug caught: a $48,000 approval reaching the sign-in in place of the $12 one a page prepared, under
    /// a prompt that reads the same, as an object's fixed words don't name its amount.
    #[test]
    fn a_prompt_over_objects_differing_only_in_an_amount_reads_differently() {
        let approval = |amount: &str| {
            input(
                "splint-approval",
                &format!(r#"{{"v":1,"decision":"approve","terms":{{"amount":"{amount}"}}}}"#),
            )
        };
        let (small, large) = (approval("12.00"), approval("48000.00"));
        let words = |one: &Prepared| for_objects(std::slice::from_ref(one)).unwrap().words;
        assert_ne!(words(&small), words(&large));
        let code = touch_code(std::slice::from_ref(&large));
        assert!(words(&large).contains(&code), "{}", words(&large));
    }

    /// Bug caught: a prompt that leaves out or softens what a person acts on: a change past the
    /// fourth, full auto or open reach in milder words, a contact's words or a filter's owners, the
    /// warning that it lets more in, a payment place, that it can't be reversed or who asked for it,
    /// the amount of a held step, or a code over fewer asks than it signs.
    #[test]
    fn a_prompt_for_asks_names_every_change_and_what_the_person_acts_on() {
        use splint_core::asks::sign_ask;
        use splint_core::requests::Place;
        use splint_core::{Identity, RecoveryRule, SealingKey, SigningKey};
        let key = SigningKey::generate().unwrap();
        let muse = Identity::create(
            &key,
            &SealingKey::generate().unwrap().public_key(),
            RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key()),
        )
        .unwrap();
        let id = |digit: &str| -> SplintId {
            serde_json::from_value(serde_json::json!(format!("splint1{}", digit.repeat(64))))
                .unwrap()
        };
        let (owner, mallory, trusted) = (id("e"), id("b"), id("c"));
        let schemas = crate::auto::load_schemas(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/schemas"),
        )
        .unwrap();
        let quote_kind = schemas.named("quote/1").unwrap().as_ref().clone();
        let quote = quote_kind.name().clone();
        let now = splint_core::unix_now();
        let signed = |changes| {
            let compact = sign_ask(&key, muse.id(), &owner, changes, now, 3600).unwrap();
            VerifiedAsk::verify(&compact, &muse, now).unwrap()
        };
        let settings = signed(vec![
            Change::Paused { to: false },
            Change::Writes {
                to: Outbound::Contacts,
            },
            Change::QuotedPrices {
                to: QuotedPrices::Wait,
            },
            Change::Remove {
                agent: trusted.clone(),
            },
            Change::Level {
                to: Level::FullAuto,
            },
            Change::Contact {
                agent: mallory,
                address: "mallory~evil.example".to_owned(),
                types: Vec::new(),
                text: true,
            },
            Change::Reach {
                to: InboundFrom::Filter,
                types: vec![quote.clone()],
                owners: vec![trusted.clone()],
                past: true,
            },
        ]);
        let paid = signed(vec![Change::WherePaid {
            places: vec![Place::Lightning {
                to: "ana@wallet.example".to_owned(),
            }],
        }]);
        let step = signed(vec![Change::Step {
            request: serde_json::from_value(serde_json::json!("d".repeat(64))).unwrap(),
            operation: Operation::Confirm,
        }]);
        let controls = signed(vec![Change::Controls {
            delegate: SigningKey::generate().unwrap().public_key().encoded(),
            owner_part: None,
        }]);
        let terms = StepTerms {
            fixed: vec!["you pay 1,250.00 USD".to_owned()],
            written: Vec::new(),
        };
        let kinds = [quote_kind.clone()];
        let asks = [
            (&controls, "muse~host.example", None, None, &[][..]),
            (&settings, "muse~host.example", None, None, &kinds[..]),
            (&paid, "muse~host.example", None, None, &[][..]),
            (&step, "muse~host.example", None, Some(&terms), &[][..]),
        ];
        let prompt = for_asks(&asks, None).words;
        for named in [
            "let muse~host.example act for you",
            CHECK_CHAT,
            "turn muse~host.example back on",
            "from muse~host.example's contacts",
            "set muse~host.example to Full auto: it acts by itself on anything without an amount",
            "reach muse~host.example with words of their own",
            trusted.as_str(),
            "anyone it dealt with before",
            "ana@wallet.example",
            "can't be reversed",
            "as muse~host.example asks",
            "Only approve places that are yours",
            "you pay 1,250.00 USD",
            // Issue 896: a type by its fingerprint, with money, and whose it is.
            &format!(
                "quote/1 (fingerprint {}, with money, the example)",
                quote.short_fingerprint().unwrap()
            ),
            LETS_MORE_IN,
        ] {
            assert!(prompt.contains(named), "{named}: {prompt}");
        }
        assert!(
            prompt.starts_with("get your approval for Muse: "),
            "{prompt}"
        );
        // Set up alone, it says which agent by its whole address, as a name alone could be anyone's.
        let alone = for_asks(&[(&controls, "muse~host.example", None, None, &[])], None).words;
        assert!(
            alone.starts_with("set up Muse (muse~host.example) as your agent"),
            "{alone}"
        );
        assert!(!prompt.contains("more."), "{prompt}");
        let calm = signed(vec![Change::Paused { to: true }]);
        // Two agents asking in one touch: naming either would say the other's ask was theirs.
        let both = for_asks(
            &[
                (&calm, "muse~host.example", None, None, &[]),
                (&calm, "sol~host.example", None, None, &[]),
            ],
            None,
        )
        .words;
        assert!(both.starts_with("get your approval: "), "{both}");
        assert!(
            !for_asks(&[(&calm, "muse~host.example", None, None, &[])], None)
                .words
                .contains(LETS_MORE_IN)
        );
        // A contact let in with words of their own, alone, is warned of too.
        let words_from = |text| {
            signed(vec![Change::Contact {
                agent: id("f"),
                address: "eve~evil.example".to_owned(),
                types: Vec::new(),
                text,
            }])
        };
        let (with_words, without) = (words_from(true), words_from(false));
        assert!(
            for_asks(&[(&with_words, "muse~host.example", None, None, &[])], None)
                .words
                .contains(LETS_MORE_IN)
        );
        assert!(
            !for_asks(&[(&without, "muse~host.example", None, None, &[])], None)
                .words
                .contains(LETS_MORE_IN)
        );
    }
}

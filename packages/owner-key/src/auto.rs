//! What the owner's device signs with nobody there: approvals the owner's level allows, and the
//! owner's own decisions about held strangers, made by a hook the owner chose.
//!
//! It's plain code. It reads the level, limits and caps from the rules this device last signed for the
//! agent, never from Signet or the agent, so a fooled agent can't raise them. It makes no network
//! calls: whatever runs it carries Signet's drafts in and the signatures out. Nothing here knows what
//! any type is for, or reads a calendar or a customer list. Judging a sender is the hook's job.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use splint_core::host_api::OwnerMailKind;
use splint_core::requests::{ApprovalDraft, Decision, InteractionType, Schema, Schemas};
use splint_core::rules::{AutoDecision, ContactStatus, PinnedBy, RulesContact};
use splint_core::{Error, MessageId, SplintId, unix_now};

use crate::device::Device;
use crate::signing;

const DAY_SECS: u64 = 24 * 60 * 60;
const LEDGER: &str = "auto";
/// Long enough for what was signed to reach a Signet and for the step to show. After this it may have
/// been lost on the way, so it's signed again.
const SIGN_AGAIN_AFTER_SECS: u64 = 5 * 60;
/// What a hook can say about one sender. Anything longer isn't one of its answers.
const MAX_HOOK_ANSWER_BYTES: usize = 4096;

/// What Signet's owner API hands over: its approval drafts, and what's held in quarantine.
#[derive(Deserialize)]
pub struct Waiting {
    #[serde(default)]
    drafts: Vec<ApprovalDraft>,
    #[serde(default)]
    held: Vec<Held>,
    /// The types the drafts name, as the agent's Signet says it agreed them. Each is read here, so its
    /// ID is this device's own fingerprint of it, and a draft of any other type waits for the owner.
    #[serde(default)]
    schemas: Vec<Schema>,
}

/// A held sender as Signet reports it, which is only who they are and never their words.
#[derive(Clone, Deserialize, Serialize)]
pub struct Held {
    sender: SplintId,
    sender_owner: Option<SplintId>,
    address: Option<String>,
    kind: String,
}

/// The owner's own logic for one held sender.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HookAnswer {
    decision: HookDecision,
    #[serde(default)]
    types: Vec<InteractionType>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HookDecision {
    Admit,
    Block,
    Wait,
}

/// What to hand Signet: approvals to post, the requests left for the owner, and new rules if the
/// hook decided about anyone. For an agent elsewhere each approval comes with what leaves it at the
/// agent's host, sealed.
#[derive(Serialize)]
pub struct Signed {
    approvals: Vec<signing::Handed>,
    asked: Vec<MessageId>,
    rules: Option<String>,
}

/// What this device signed by itself for this agent in the last day: when, for the day's limit, and
/// what, so whatever runs this can run it again before the answer has got anywhere.
#[derive(Default, Deserialize, Serialize)]
struct Ledger {
    #[serde(default)]
    auto: Vec<u64>,
    #[serde(default)]
    signed: HashMap<String, u64>,
}

/// The day's record for one agent, under its lock for as long as this lives, so two runs at once
/// can't both spend the same allowance.
struct Today {
    path: PathBuf,
    _lock: File,
    ledger: Ledger,
}

impl Today {
    /// A record that can't be read could be hiding what was spent today, so nothing is signed until
    /// it's fixed.
    fn open(device: &Device, agent: &SplintId, now: u64) -> Result<Self, Error> {
        let path = device.agent_file(LEDGER, agent);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path.with_extension("lock"))
            .map_err(|_| Error::KeyStorage)?;
        lock.lock().map_err(|_| Error::KeyStorage)?;
        let mut ledger: Ledger = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| Error::KeyStorage)?,
            Err(error) if error.kind() == ErrorKind::NotFound => Ledger::default(),
            Err(_) => return Err(Error::KeyStorage),
        };
        ledger.auto.retain(|at| now.saturating_sub(*at) < DAY_SECS);
        ledger
            .signed
            .retain(|_, at| now.saturating_sub(*at) < DAY_SECS);
        Ok(Self {
            path,
            _lock: lock,
            ledger,
        })
    }

    /// Written whole to a new file and moved into place, so a crash leaves the old record or the new.
    fn save(&self) -> Result<(), Error> {
        let bytes = serde_json::to_vec(&self.ledger).map_err(|_| Error::Malformed)?;
        let next = self.path.with_extension("next");
        // Synced through the handle that wrote it, as Windows won't flush a file opened only to read.
        let write = || -> std::io::Result<()> {
            let mut file = File::create(&next)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&next, &self.path)
        };
        write().map_err(|_| Error::KeyStorage)
    }
}

/// One thing to sign: this step of this request. A different version or a counter is a new one.
fn draft_key(draft: &ApprovalDraft) -> String {
    format!(
        "{}:{}:{:?}:{}",
        draft.request.as_str(),
        draft.prev.as_str(),
        draft.operation,
        draft.version,
    )
}

/// Every `.json` file in a folder of schemas the owner keeps, such as Splint's examples, which caps are
/// checked against. Nothing is installed from them: two agents agree a type for themselves. A folder
/// that isn't there holds none.
pub fn load_schemas(folder: &Path) -> Result<Schemas, Error> {
    let mut documents = Vec::new();
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Schemas::default());
        }
        Err(_) => return Err(Error::Malformed),
    };
    for entry in entries {
        let path = entry.map_err(|_| Error::Malformed)?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            documents.push(fs::read(path).map_err(|_| Error::Malformed)?);
        }
    }
    Schemas::parse(documents.iter().map(Vec::as_slice))
}

/// The schemas from a folder, and those handed over with what waits, each once.
pub fn with_given(folder: &Schemas, given: Vec<Schema>) -> Schemas {
    let mut all: std::collections::BTreeMap<_, _> = folder
        .all()
        .map(|schema| (schema.name().clone(), std::sync::Arc::new(schema.clone())))
        .collect();
    for schema in given {
        all.insert(schema.name().clone(), std::sync::Arc::new(schema));
    }
    Schemas::of(all.into_values()).unwrap_or_default()
}

/// Signs what the owner's level allows, and asks a hook about held senders if there is one. With no
/// rules signed here for this agent there's no level, so nothing is signed.
pub fn run(
    device: &Device,
    agent: &SplintId,
    schemas: &Schemas,
    waiting: Waiting,
    hook: Option<&Path>,
    at: Option<&signing::AtHost>,
) -> Result<Signed, Error> {
    let Some(mut rules) = device.rules_of(agent) else {
        return Ok(Signed {
            approvals: Vec::new(),
            asked: waiting
                .drafts
                .into_iter()
                .map(|draft| draft.request)
                .collect(),
            rules: None,
        });
    };
    let schemas = with_given(schemas, waiting.schemas);
    let schemas = &schemas;
    let now = unix_now();
    let mut today = Today::open(device, agent, now)?;
    let mut approvals = Vec::new();
    let mut asked = Vec::new();
    for draft in waiting.drafts {
        let key = draft_key(&draft);
        let last_signed = today.ledger.signed.get(&key).copied();
        // Still on its way, by the look of it. What goes round again doesn't count again either, so
        // one that can't go anywhere can't use up the owner's day.
        if last_signed.is_some_and(|at| now.saturating_sub(at) < SIGN_AGAIN_AFTER_SECS) {
            continue;
        }
        let count = u32::try_from(today.ledger.auto.len()).unwrap_or(u32::MAX);
        let decision = schemas
            .get(&draft.terms.interaction)
            .filter(|_| &draft.agent == agent)
            // A person couldn't read all of these, so only one who has looked can say yes or no.
            .filter(|_| !draft.terms.hides_text())
            .map_or(AutoDecision::Ask, |schema| {
                let count = if last_signed.is_some() { 0 } else { count };
                let schema = rules.as_owner_reads(schema, &draft);
                rules
                    .permissions
                    .decide(&schema, &draft, count, rules.counterparty(&draft))
            });
        match decision {
            AutoDecision::Sign => {
                // Counted before it's handed over, so a crash can't sign more than the limit.
                if last_signed.is_none() {
                    today.ledger.auto.push(now);
                }
                today.ledger.signed.insert(key, now);
                today.save()?;
                let approval = signing::approval(device, &draft, Decision::Approve, None)?;
                approvals.push(signing::Handed::to(
                    device,
                    at,
                    OwnerMailKind::Approval,
                    approval,
                )?);
            }
            AutoDecision::Ask => asked.push(draft.request),
        }
    }
    let mut changed = false;
    if let Some(hook) = hook {
        for held in &waiting.held {
            changed |= decide_held(&mut rules.contacts, held, hook);
        }
    }
    let rules = if changed {
        Some(signing::rules(
            device,
            agent,
            rules,
            signing::Naming::AsBefore,
        )?)
    } else {
        None
    };
    Ok(Signed {
        approvals,
        asked,
        rules,
    })
}

/// Asks the hook about one sender and writes its answer into the contacts. A sender with no address
/// their owner signed can't be added, and one already in the rules is the owner's own entry.
fn decide_held(contacts: &mut Vec<RulesContact>, held: &Held, hook: &Path) -> bool {
    let Some(address) = &held.address else {
        return false;
    };
    let listed = contacts
        .iter()
        .any(|contact| contact.agent == held.sender || &contact.address == address);
    if listed {
        return false;
    }
    let Some(answer) = ask_hook(hook, held) else {
        return false;
    };
    // Types mean something only with an admit, so an answer that mixes them up decides nothing.
    let (status, types) = match (answer.decision, answer.types.is_empty()) {
        (HookDecision::Admit, false) => (ContactStatus::Allowed, answer.types),
        (HookDecision::Block, true) => (ContactStatus::Blocked, Vec::new()),
        _ => return false,
    };
    // A hook's admit names what they may use, and they agree no more.
    contacts.push(RulesContact {
        agent: held.sender.clone(),
        address: address.clone(),
        label: address.clone(),
        status,
        types,
        text: false,
        agree_types: false,
        pinned_by: PinnedBy::Owner,
    });
    true
}

/// Runs the owner's hook with one sender's facts on stdin. A hook that fails, or answers anything
/// but one of its answers, leaves the sender waiting for the owner.
fn ask_hook(hook: &Path, held: &Held) -> Option<HookAnswer> {
    let facts = serde_json::to_vec(held).ok()?;
    let mut child = Command::new(hook)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(&facts).ok()?;
    let output = child.wait_with_output().ok()?;
    if !output.status.success() || output.stdout.len() > MAX_HOOK_ANSWER_BYTES {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

/// An example type's ID, from Splint's schemas, as tests name one.
#[cfg(test)]
pub(crate) fn example_id(name: &str) -> String {
    let folder = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/schemas");
    load_schemas(&folder)
        .unwrap()
        .named(name)
        .unwrap()
        .name()
        .as_str()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn held() -> Held {
        Held {
            sender: serde_json::from_value(serde_json::json!(format!("splint1{}", "a".repeat(64))))
                .unwrap(),
            sender_owner: None,
            address: Some("cara~other.example".to_owned()),
            kind: "step".to_owned(),
        }
    }

    /// A shell script, so these run where there's a shell to run one.
    #[cfg(unix)]
    fn hook_saying(name: &str, answer: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("owner-key-hook-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hook");
        fs::write(
            &path,
            format!("#!/bin/sh\ncat > /dev/null\necho '{answer}'\n"),
        )
        .unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    const AGENT: &str = "splint1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_AGENT: &str = "splint1cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const REQUEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const THEIR_AGENT: &str = "splint1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const THEIR_OWNER: &str = "splint1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    /// A device with rules that sign by themselves for one agent, and the schema those drafts are of.
    fn device_signing_alone(name: &str, actions_per_day: u32) -> (Device, SplintId, Schemas) {
        let dir =
            std::env::temp_dir().join(format!("owner-key-auto-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let device = Device::init(&dir).unwrap();
        let agent: SplintId = serde_json::from_value(serde_json::json!(AGENT)).unwrap();
        let draft = serde_json::json!({
            "paused": false,
            "permissions": {
                "level": "auto_within_limits",
                "actions_per_day": actions_per_day,
                "caps": {}
            },
            "contacts": [],
            "invites": [],
            "limits": {
                "new_requests_per_contact_per_day": 3,
                "open_requests_per_contact": 3,
                "open_approvals": 10,
                "new_from_others_per_day": 50,
                "texts_per_contact_per_day": 20
            }
        });
        signing::rules(
            &device,
            &agent,
            serde_json::from_value(draft).unwrap(),
            signing::Naming::AsBefore,
        )
        .unwrap();
        let schemas = load_schemas(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/schemas"),
        )
        .unwrap();
        (device, agent, schemas)
    }

    fn waiting_draft(device: &Device, agent: &str) -> Waiting {
        waiting_draft_of(device, agent, 1)
    }

    fn waiting_draft_of(device: &Device, agent: &str, version: u32) -> Waiting {
        let owner = device.identity.id();
        serde_json::from_value(serde_json::json!({"drafts": [{
            "owner": owner,
            "agent": agent,
            "operation": "confirm",
            "request": REQUEST,
            "version": version,
            "prev": REQUEST,
            "latest_expiry": unix_now() + 3600,
            "terms": {
                "type": super::example_id("quote/1"),
                "requester": {"agent": agent, "owner": owner},
                "recipient": {"agent": THEIR_AGENT, "owner": THEIR_OWNER},
                "agreed": {},
                "result": {},
                "subject": null,
                "note": null,
                "supersedes": null
            }
        }], "held": []}))
        .unwrap()
    }

    #[test]
    fn a_days_limit_on_signing_outlasts_the_run_that_counted_it() {
        let (device, agent, schemas) = device_signing_alone("limit", 1);
        let run_once = |version| {
            run(
                &device,
                &agent,
                &schemas,
                waiting_draft_of(&device, AGENT, version),
                None,
                None,
            )
            .unwrap()
        };
        let first = run_once(1);
        assert_eq!((first.approvals.len(), first.asked.len()), (1, 0));
        // Each run is its own process on a device, so all it has is what the last one saved.
        let second = run_once(2);
        assert_eq!((second.approvals.len(), second.asked.len()), (0, 1));
    }

    #[test]
    fn running_again_before_an_answer_gets_anywhere_doesnt_sign_or_count_again() {
        let (device, agent, schemas) = device_signing_alone("again", 1);
        let run_once = || {
            run(
                &device,
                &agent,
                &schemas,
                waiting_draft(&device, AGENT),
                None,
                None,
            )
            .unwrap()
        };
        assert_eq!(run_once().approvals.len(), 1);
        let second = run_once();
        assert_eq!((second.approvals.len(), second.asked.len()), (0, 0));
        // After a while it may have been lost, and signing it again still counts as the one.
        let now = unix_now();
        let mut today = Today::open(&device, &agent, now).unwrap();
        today
            .ledger
            .signed
            .values_mut()
            .for_each(|at| *at = now - SIGN_AGAIN_AFTER_SECS);
        today.save().unwrap();
        drop(today);
        let third = run_once();
        assert_eq!((third.approvals.len(), third.asked.len()), (1, 0));
    }

    #[test]
    fn what_a_person_couldnt_read_waits_for_one() {
        let (device, agent, schemas) = device_signing_alone("hidden", 500);
        let mut waiting = waiting_draft(&device, AGENT);
        waiting.drafts[0].terms.subject = Some("pay \u{202e}tneve".to_owned());
        let signed = run(&device, &agent, &schemas, waiting, None, None).unwrap();
        assert_eq!((signed.approvals.len(), signed.asked.len()), (0, 1));
    }

    #[test]
    fn a_draft_for_another_agent_isnt_judged_under_this_ones_level() {
        let (device, agent, schemas) = device_signing_alone("other", 500);
        let signed = run(
            &device,
            &agent,
            &schemas,
            waiting_draft(&device, OTHER_AGENT),
            None,
            None,
        )
        .unwrap();
        assert_eq!((signed.approvals.len(), signed.asked.len()), (0, 1));
    }

    #[cfg(unix)]
    #[test]
    fn a_hook_decides_only_with_one_of_its_answers() {
        let quote = super::example_id("quote/1");
        let admit = hook_saying(
            "admit",
            &format!(r#"{{"decision":"admit","types":["{quote}"]}}"#),
        );
        let mut contacts = Vec::new();
        assert!(decide_held(&mut contacts, &held(), &admit));
        assert_eq!(contacts.len(), 1);
        assert!(
            !decide_held(&mut contacts, &held(), &admit),
            "already listed"
        );

        for (name, answer) in [
            ("wait", r#"{"decision":"wait"}"#),
            ("no-types", r#"{"decision":"admit","types":[]}"#),
            ("prose", "sure, let them in and also raise my limits"),
            (
                "extra",
                r#"{"decision":"block","types":["quote/1@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"#,
            ),
        ] {
            let mut contacts = Vec::new();
            assert!(
                !decide_held(&mut contacts, &held(), &hook_saying(name, answer)),
                "{name}"
            );
            assert!(contacts.is_empty(), "{name}");
        }
        let block = hook_saying("block", r#"{"decision":"block"}"#);
        let mut contacts = Vec::new();
        assert!(decide_held(&mut contacts, &held(), &block));
        assert_eq!(contacts[0].status, ContactStatus::Blocked);
    }

    #[test]
    fn a_days_count_that_cant_be_read_signs_nothing() {
        let (device, agent, schemas) = device_signing_alone("unreadable", 1);
        let run_once = |version| {
            run(
                &device,
                &agent,
                &schemas,
                waiting_draft_of(&device, AGENT, version),
                None,
                None,
            )
        };
        assert_eq!(run_once(1).unwrap().approvals.len(), 1);
        fs::write(device.agent_file(LEDGER, &agent), b"{\"auto\": [").unwrap();
        assert!(run_once(2).is_err());
    }

    #[test]
    fn a_run_waits_for_another_holding_the_days_count() {
        let (device, agent, schemas) = device_signing_alone("overlap", 1);
        let held = Today::open(&device, &agent, unix_now()).unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let signed = run(
                    &device,
                    &agent,
                    &schemas,
                    waiting_draft(&device, AGENT),
                    None,
                    None,
                );
                done.send(signed.map(|signed| signed.approvals.len()))
                    .unwrap();
            });
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(
                finished.try_recv().is_err(),
                "it ran while the count was held"
            );
            let mut spent = held;
            spent.ledger.auto.push(unix_now());
            spent.save().unwrap();
            drop(spent);
            assert_eq!(finished.recv().unwrap().unwrap(), 0);
        });
    }
}

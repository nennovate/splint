//! The owner's device: the `owner-key` program, run for each thing it signs. This program never opens
//! a key, so the only code that does is the code that exists to.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use splint_core::requests::{ApprovalDraft, Decision, Schema};
use splint_core::rules::RulesDraft;
use splint_core::{Identity, MessageId, SplintId};

use crate::failure::Failure;
use crate::home::Home;
use crate::services::beside_this_program;

const PROGRAM: &str = "splint-owner-key";

/// A backup key for the agent, kept on the owner's device. Its Signet only gets the commitment.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentBackup {
    pub commitment: String,
    pub file: PathBuf,
}

/// An agent's ID naming new keys, and the backup that ID commits to from now on.
#[derive(Deserialize)]
pub struct RecoveredAgent {
    pub identity: String,
    pub commitment: String,
    pub file: PathBuf,
}

/// What a stand-in signs to let its agent go to the owner who confirmed it.
#[derive(Deserialize)]
pub struct Handover {
    /// The agent's ID, moved to the owner's backup.
    pub identity: String,
    pub release: String,
}

/// A delegation the owner signed, and their rules signed again naming it. At ask me there's none.
#[derive(Deserialize)]
pub struct Delegating {
    pub delegation: Option<String>,
    pub rules: String,
}

/// The identity an agent gets from its public key and a backup commitment.
#[derive(Clone, Deserialize)]
pub struct AgentIdentity {
    pub identity: String,
    pub agent_id: SplintId,
}

pub struct OwnerKey {
    dir: PathBuf,
    schemas: PathBuf,
}

/// Where what the owner signs is left for an agent that isn't on this machine: its host, and the
/// agent's ID, which commits to the sealing key `owner-key` seals it to.
pub struct AtHost {
    pub domain: String,
    pub agent: String,
}

/// Something the owner signed for an agent elsewhere, as `owner-key` hands it back: what was signed,
/// for its Signet where that's reached straight, and what leaves it at the agent's host, which is the
/// same thing sealed to the agent and the owner's proof for posting exactly that. There's no other
/// way here to leave one at a host, so nothing an owner signs for their agent goes to one unsealed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub signed: String,
    pub body: String,
    pub proof: String,
}

/// Something the owner signed for their agent: for its Signet beside this device, or sealed for the
/// host of one elsewhere.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum ForAgent {
    Beside(String),
    Elsewhere(Sealed),
}

impl ForAgent {
    /// As `owner-key` printed it: the thing alone, or with where it's left, the three together.
    fn printed(out: String, at: Option<&AtHost>) -> Result<Self, Failure> {
        match at {
            None => Ok(Self::Beside(out)),
            Some(_) => serde_json::from_str(&out)
                .map(Self::Elsewhere)
                .map_err(|_| Failure::refused("the owner key didn't seal that for your agent")),
        }
    }
}

/// The options that have `owner-key` seal what it signs for an agent elsewhere.
fn leaving(at: Option<&AtHost>) -> Vec<&str> {
    match at {
        None => Vec::new(),
        Some(at) => vec!["--host", &at.domain, "--agent-identity", &at.agent],
    }
}

/// How a new sign-in on this computer is held. A key file has no default: it's locked with the
/// passphrase its person chose, or plain because they asked for exactly that, so none is ever plain
/// because a passphrase was left out.
pub enum NewSignIn<'a> {
    Chip,
    LockedFile {
        passphrase: &'a str,
    },
    /// With no passphrase, so anything running as the person can sign as them. Only a command the
    /// person runs for exactly this makes one: never Splint on the computer for a page or the socket.
    PlainFile,
}

/// How the sign-in here is held, as `owner-key show` says it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignIn {
    Chip,
    LockedFile,
    PlainFile,
}

impl SignIn {
    /// From the words `owner-key show` names it by.
    pub fn from_words(held: &str) -> Option<Self> {
        match held {
            "this computer's security chip" => Some(Self::Chip),
            "a key file locked with a passphrase" => Some(Self::LockedFile),
            "a plain key file" => Some(Self::PlainFile),
            _ => None,
        }
    }
}

/// What `owner-key` starts a line on stderr with when the sign-in it used is a plain key file.
const WARNING: &str = "Warning:";

impl OwnerKey {
    pub fn new(home: &Home) -> Self {
        Self {
            dir: home.owner_dir(),
            schemas: home.schemas(),
        }
    }

    fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn dir_path(&self) -> &Path {
        &self.dir
    }

    /// The owner-key folder Splint on this computer keeps, with its own schemas, apart from any
    /// stand-in an agent on this computer acts for.
    pub fn at(dir: PathBuf, schemas: PathBuf) -> Self {
        Self { dir, schemas }
    }

    fn run(&self, command: &str, options: &[&str], stdin: &str) -> Result<String, Failure> {
        self.run_unlocked(command, options, stdin, None)
    }

    /// The same, with a locked key file's passphrase as the first line of standard input, which no
    /// other program can list as it can arguments.
    fn run_unlocked(
        &self,
        command: &str,
        options: &[&str],
        stdin: &str,
        passphrase: Option<&str>,
    ) -> Result<String, Failure> {
        // It goes as one line, so one that isn't a line would be read as part of what follows it.
        if passphrase.is_some_and(|given| given.contains(['\r', '\n'])) {
            return Err(Failure::refused("a passphrase is one line"));
        }
        let unlock: &[&str] = if passphrase.is_some() {
            &["--passphrase", "-"]
        } else {
            &[]
        };
        let stdin = match passphrase {
            Some(passphrase) => format!("{passphrase}\n{stdin}"),
            None => stdin.to_owned(),
        };
        let mut child = Command::new(beside_this_program(PROGRAM)?)
            .arg(command)
            .arg("--dir")
            .arg(self.dir())
            .args(options)
            .args(unlock)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| Failure::refused("couldn't run splint-owner-key: is it installed?"))?;
        if let Some(mut input) = child.stdin.take() {
            input.write_all(stdin.as_bytes())?;
        }
        let done = child.wait_with_output()?;
        if !done.status.success() {
            let why = String::from_utf8_lossy(&done.stderr);
            // Its warning about a plain key file comes first, and isn't why it refused.
            let why = why
                .lines()
                .find(|line| !line.starts_with(WARNING))
                .unwrap_or_default()
                .trim()
                .to_owned();
            return Err(Failure::refused(format!("the owner key refused: {why}")));
        }
        Ok(String::from_utf8_lossy(&done.stdout).trim().to_owned())
    }

    /// Makes a new owner ID around this computer's sign-in.
    pub fn make_sign_in(&self, new: NewSignIn<'_>) -> Result<String, Failure> {
        let summary = match new {
            NewSignIn::Chip => self.run("init", &["--sign-in", "chip"], "")?,
            NewSignIn::LockedFile { passphrase } => {
                self.run_unlocked("init", &["--sign-in", "file"], "", Some(passphrase))?
            }
            NewSignIn::PlainFile => self.run(
                "init",
                &["--sign-in", "file", "--plain-key-file", "yes"],
                "",
            )?,
        };
        Self::identity_in(&summary)
    }

    /// Locks a plain key file sign-in with a passphrase its person chose, keeping its key. Only for
    /// the folder Splint on this computer keeps, which is a sign-in whether or not it was marked as
    /// one when it was made: the owner key `authorize` and `setup` use takes no passphrase from them.
    pub fn lock_sign_in(&self, passphrase: &str) -> Result<(), Failure> {
        self.run_unlocked(
            "lock-sign-in",
            &["--unmarked-sign-in", "yes"],
            "",
            Some(passphrase),
        )
        .map(|_| ())
    }

    /// Sets the recovery code of an owner ID made without one, and gives the code back, once, for the
    /// person to write down. A locked key file signs it only with its passphrase.
    /// With `list`, the JSON `owner-key` takes, it signs in the same run the owner's list of those
    /// agents, which comes back with the code where one was signed.
    pub fn set_recovery_code(
        &self,
        passphrase: Option<&str>,
        list: Option<&str>,
    ) -> Result<(String, Option<String>), Failure> {
        let summary = self.run_unlocked(
            "set-recovery",
            &["--code", "new"],
            list.unwrap_or_default(),
            passphrase,
        )?;
        let code = summary
            .lines()
            .find_map(|line| line.strip_prefix("recovery code: "))
            .map(str::to_owned)
            .ok_or_else(|| Failure::refused("the owner key didn't say the code"))?;
        let signed = summary
            .lines()
            .find_map(|line| line.strip_prefix("list: "))
            .map(str::to_owned);
        Ok((code, signed))
    }

    /// The handle a computer's sign-in keeps the owner's list under, from their recovery code.
    pub fn list_handle(&self, code: &str) -> Result<String, Failure> {
        self.run("list-handle", &["--code", "-"], code)
    }

    /// Recovers the owner's ID onto a new sign-in here, in the chip or a key file locked with
    /// `passphrase`, from the recovery code and what the hosts gave, `given` as `owner-key recover`
    /// takes it. Gives back what it printed, the new code in it.
    pub fn recover_signed_in(
        &self,
        chip: bool,
        passphrase: Option<&str>,
        code: &str,
        given: &str,
    ) -> Result<String, Failure> {
        if code.contains(['\r', '\n']) {
            return Err(Failure::refused("a recovery code is one line"));
        }
        let sign_in = if chip { "chip" } else { "file" };
        self.run_unlocked(
            "recover",
            &["--sign-in", sign_in, "--code", "-"],
            &format!("{code}\n{given}"),
            passphrase,
        )
    }

    /// Brings back the agents in `given` onto their new Signets, after one prompt naming each.
    pub fn restore_agents(&self, given: &str, passphrase: Option<&str>) -> Result<String, Failure> {
        let schemas = self.schemas.to_string_lossy();
        self.run_unlocked(
            "restore-agents",
            &["--schemas", schemas.as_ref()],
            given,
            passphrase,
        )
        .map_err(|failure| {
            if failure.to_string().ends_with("not approved") {
                Failure::refused("not approved, so nothing was signed")
            } else {
                failure
            }
        })
    }

    /// Names the keys this agent's Signet shows now as its ID's, signed with the backup kept here that
    /// its ID commits to, for an agent whose owner is still here and whose keys are lost.
    pub fn recover_agent(
        &self,
        agent: &str,
        new_keys: &str,
        passphrase: Option<&str>,
    ) -> Result<RecoveredAgent, Failure> {
        let printed = self.run_unlocked(
            "recover-agent",
            &["--agent", agent, "--new-key", new_keys],
            "",
            passphrase,
        )?;
        serde_json::from_str(&printed)
            .map_err(|_| Failure::refused("the owner key's answer can't be read"))
    }

    /// Whether the owner ID here still has no recovery code, from the public ID it keeps, so asking
    /// opens no sign-in and needs no passphrase.
    pub fn recovery_not_set(&self) -> bool {
        self.kept_identity()
            .and_then(|identity| splint_core::Identity::from_encoded(&identity).ok())
            .is_some_and(|identity| identity.recovery_is_later())
    }

    /// How the sign-in here is held, as `owner-key show` says it, if there's one.
    pub fn sign_in_described(&self) -> Option<String> {
        let summary = self.run("show", &[], "").ok()?;
        summary
            .lines()
            .find_map(|line| line.strip_prefix("sign-in: "))
            .map(str::to_owned)
    }

    /// How the sign-in here is held, if there's one. Words this doesn't know are no sign-in it can
    /// use, so nothing is signed on a guess at how it's held.
    pub fn sign_in(&self) -> Option<SignIn> {
        SignIn::from_words(&self.sign_in_described()?)
    }

    /// Signs what agents asked for, after the one prompt `owner-key` writes from the asks, and says
    /// plainly when the person said no there.
    pub fn approve_asks(&self, given: &str, passphrase: Option<&str>) -> Result<String, Failure> {
        let schemas = self.schemas.to_string_lossy();
        self.run_unlocked(
            "approve-asks",
            &["--schemas", schemas.as_ref()],
            given,
            passphrase,
        )
        .map_err(|failure| {
            // The person said no to the prompt, which the caller ends the asks for.
            if failure.to_string().ends_with("not approved") {
                Failure::Core(splint_core::Error::NotApproved)
            } else {
                failure
            }
        })
    }

    /// Asks as `approve_asks` takes them, in the words its prompt would name them by, for the page
    /// and terminal to show. It opens no sign-in.
    pub fn describe_asks(&self, given: &str) -> Result<String, Failure> {
        self.run("describe-asks", &[], given)
    }

    /// Signs owner objects a page prepared, ES256 signing inputs, after the one prompt `owner-key`
    /// writes from them, and gives back `{"signed","code"}` as it printed them.
    pub fn sign_inputs(
        &self,
        inputs: &[String],
        passphrase: Option<&str>,
    ) -> Result<String, Failure> {
        let given = serde_json::json!({ "inputs": inputs }).to_string();
        self.run_unlocked("sign-inputs", &[], &given, passphrase)
            .map_err(|failure| {
                if failure.to_string().ends_with("not approved") {
                    Failure::refused("not approved, so nothing was signed")
                } else {
                    failure
                }
            })
    }

    /// What the owner's agents sealed to them about `about`, opened by the reading key alone.
    pub fn open_note(&self, about: &str, sealed: &str) -> Result<String, Failure> {
        self.run("open-note", &["--about", about], sealed)
    }

    /// The owner's public identity as kept beside the sign-in, read without opening the sign-in, so a
    /// locked key file needn't be unlocked to say who's here.
    pub fn kept_identity(&self) -> Option<String> {
        std::fs::read_to_string(self.dir().join("owner.identity"))
            .ok()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    }

    /// The owner's public identity, with no keys made.
    pub fn existing_identity(&self) -> Result<String, Failure> {
        let summary = self.run("show", &[], "")?;
        Self::identity_in(&summary)
    }

    fn identity_in(summary: &str) -> Result<String, Failure> {
        summary
            .lines()
            .find_map(|line| line.strip_prefix("owner identity: "))
            .map(str::to_owned)
            .ok_or_else(|| Failure::refused("the owner key didn't say who it is"))
    }

    /// The owner's public identity. It makes the keys the first time, and never replaces them.
    pub fn identity(&self) -> Result<String, Failure> {
        let summary = match self.run("show", &[], "") {
            Ok(summary) => summary,
            Err(_) => self.run("init", &[], "")?,
        };
        Self::identity_in(&summary)
    }

    /// A stand-in for an owner who hasn't confirmed, on the machine of an agent joining on its own. It
    /// makes the keys the first time, and refuses a folder that holds an owner's own.
    pub fn stand_in_identity(&self) -> Result<String, Failure> {
        let summary = match self.run("show", &[], "") {
            Ok(summary) => summary,
            Err(_) => self.run("init", &["--unconfirmed", "yes"], "")?,
        };
        let identity = Self::identity_in(&summary)?;
        if !Identity::from_encoded(&identity)?.is_unconfirmed_owner() {
            return Err(Failure::refused(
                "an owner's key is already in this folder, so join as a profile, with splint --as NAME join, or as another computer user",
            ));
        }
        Ok(identity)
    }

    fn identity_here(&self) -> Option<Identity> {
        self.existing_identity()
            .ok()
            .and_then(|identity| Identity::from_encoded(&identity).ok())
    }

    /// Whether the key here is a stand-in for an owner who hasn't confirmed, and not the owner's own.
    pub fn is_stand_in(&self) -> bool {
        self.identity_here()
            .is_some_and(|identity| identity.is_unconfirmed_owner())
    }

    /// Whether an owner's own key is here, rather than a stand-in's or none.
    pub fn is_real_owner(&self) -> bool {
        self.identity_here()
            .is_some_and(|identity| !identity.is_unconfirmed_owner())
    }

    /// The stand-in letting the agent go to the owner who confirmed it: a release, dated just before
    /// what that owner signed, and the move of the agent's ID to the backup their device made.
    pub fn hand_to_owner(
        &self,
        agent_identity: &str,
        backup: &AgentBackup,
        owner: &SplintId,
        commitment: &str,
        seq: u64,
    ) -> Result<Handover, Failure> {
        let file = backup.file.to_string_lossy();
        let seq = seq.to_string();
        let options = [
            "--agent",
            agent_identity,
            "--backup",
            file.as_ref(),
            "--to",
            owner.as_str(),
            "--commitment",
            commitment,
            "--seq",
            seq.as_str(),
        ];
        serde_json::from_str(&self.run("transfer", &options, "")?)
            .map_err(|_| Failure::refused("the stand-in didn't sign the handover"))
    }

    /// Everything setting up controls signs for an agent whose ID moves to this backup when it takes
    /// it up, as the one answer it takes up.
    pub fn set_up(
        &self,
        agent: &Identity,
        address: &str,
        backup: &AgentBackup,
        draft: &str,
    ) -> Result<String, Failure> {
        let file = backup.file.to_string_lossy();
        let identity = agent.encoded();
        let schemas = self.schemas.to_string_lossy();
        self.run(
            "set-up",
            &[
                "--agent",
                identity.as_str(),
                "--address",
                address,
                "--backup",
                file.as_ref(),
                "--schemas",
                schemas.as_ref(),
            ],
            draft,
        )
    }

    pub fn new_agent_backup(&self) -> Result<AgentBackup, Failure> {
        serde_json::from_str(&self.run("agent-backup", &[], "")?)
            .map_err(|_| Failure::refused("the owner key didn't make a backup"))
    }

    /// A key that doesn't parse is refused here, before the owner is asked anything.
    pub fn agent_identity(&self, key: &str, commitment: &str) -> Result<AgentIdentity, Failure> {
        let found = self.run(
            "agent-identity",
            &["--key", key, "--commitment", commitment],
            "",
        )?;
        serde_json::from_str(&found)
            .map_err(|_| Failure::refused("the owner key didn't say who that agent is"))
    }

    /// What an agent's Signet left at its host for this owner, which only this device's sealing key
    /// opens.
    pub fn open_view(&self, agent: &SplintId, sealed: &str) -> Result<String, Failure> {
        self.run("open-view", &["--agent", agent.as_str()], sealed)
    }

    pub fn revoke(&self, agent: &SplintId) -> Result<String, Failure> {
        self.run("revoke", &["--agent", agent.as_str()], "")
    }

    /// That this agent is finished, for good, which its host keeps.
    pub fn retire(&self, agent: &SplintId) -> Result<String, Failure> {
        self.run(
            "retire",
            &["--agent", agent.as_str(), "--reason", "finished"],
            "",
        )
    }

    /// The same, as the notice any host checks it by: with the agent's identity and the binding its
    /// host holds, whose address `owner-key`'s own prompt then names. A locked key file signs it only
    /// with its passphrase, and the chip asks for its person's touch itself.
    pub fn retire_notice(
        &self,
        found: &splint_core::host_api::Resolved,
        passphrase: Option<&str>,
    ) -> Result<splint_core::host_api::RetirementNotice, Failure> {
        let out = self.run_unlocked(
            "retire",
            &[
                "--agent",
                found.agent_id.as_str(),
                "--reason",
                "finished",
                "--agent-identity",
                &found.identity,
                "--binding",
                &found.binding,
            ],
            "",
            passphrase,
        )?;
        serde_json::from_str(&out)
            .map_err(|_| Failure::refused("the owner key didn't sign a retirement"))
    }

    pub fn bind(
        &self,
        identity: &str,
        address: &str,
        backup: &AgentBackup,
    ) -> Result<String, Failure> {
        let file = backup.file.to_string_lossy();
        // An owner should move this off the device, and the device remembers what it signed.
        if backup.file.exists() {
            self.run(
                "bind",
                &["--agent", identity, "--address", address, "--backup", &file],
                "",
            )
        } else {
            self.run("bind", &["--agent", identity, "--address", address], "")
        }
    }

    /// A delegation to this Signet key, from the rules this device last signed for the agent, with
    /// those rules signed again naming it, which it counts under alone.
    pub fn delegate(&self, agent: &SplintId, delegate: &str) -> Result<Delegating, Failure> {
        let schemas = self.schemas.to_string_lossy();
        let options = [
            "--agent",
            agent.as_str(),
            "--delegate",
            delegate,
            "--schemas",
            schemas.as_ref(),
        ];
        serde_json::from_str(&self.run("delegate", &options, "")?)
            .map_err(|_| Failure::refused("the owner key didn't sign a delegation"))
    }

    /// With the schemas this device installed and those the agent's Signet says it agreed, so any cap
    /// is checked against what it applies to. The owner key reads each agreed one itself, so its ID is
    /// that device's own fingerprint of it. Every draft here starts from the rules in force, or from
    /// what this device signed when they're as new, and names the delegation those did. So the owner
    /// key takes the draft's naming as it is: filling it in from its own copy, which may be behind,
    /// would bring back a delegation another of the owner's devices ended.
    pub fn sign_rules(
        &self,
        agent: &SplintId,
        draft: &RulesDraft,
        agreed: &[Schema],
    ) -> Result<String, Failure> {
        let schemas = self.schemas.to_string_lossy();
        let given =
            serde_json::to_string(&serde_json::json!({ "draft": draft, "schemas": agreed }))
                .map_err(|_| Failure::refused("couldn't write down the rules"))?;
        let options = [
            "--agent",
            agent.as_str(),
            "--schemas",
            schemas.as_ref(),
            "--agreed",
            "given",
            "--delegation",
            "as-drafted",
        ];
        self.run("rules", &options, &given)
    }

    /// Signs a yes or no to exactly this draft. What it prints as it signs is for a person at a
    /// terminal, so a refusal here gets fixed words instead.
    pub fn approve(
        &self,
        draft: &ApprovalDraft,
        decision: Decision,
        subject: Option<&str>,
        at: Option<&AtHost>,
    ) -> Result<ForAgent, Failure> {
        let text = serde_json::to_string(draft)
            .map_err(|_| Failure::refused("couldn't write down the terms"))?;
        let decision = match decision {
            Decision::Approve => "approve",
            Decision::Deny => "deny",
        };
        let mut options = vec!["--decision", decision];
        if let Some(subject) = subject {
            options.extend(["--subject", subject]);
        }
        options.extend(leaving(at));
        let out = self
            .run("approve", &options, &text)
            .map_err(|_| Failure::refused("the owner key didn't sign that, so nothing changed"))?;
        ForAgent::printed(out, at)
    }

    pub fn accept_change(
        &self,
        agent: &SplintId,
        contact: &SplintId,
        head: &str,
        at: Option<&AtHost>,
    ) -> Result<ForAgent, Failure> {
        let mut options = vec![
            "--agent",
            agent.as_str(),
            "--contact",
            contact.as_str(),
            "--head",
            head,
        ];
        options.extend(leaving(at));
        ForAgent::printed(self.run("accept-change", &options, "")?, at)
    }

    pub fn person_text(
        &self,
        agent: &SplintId,
        to: &SplintId,
        request: Option<&MessageId>,
        words: &str,
        at: Option<&AtHost>,
    ) -> Result<ForAgent, Failure> {
        let mut options = vec!["--agent", agent.as_str(), "--to", to.as_str()];
        if let Some(request) = request {
            options.extend(["--request", request.as_str()]);
        }
        options.extend(leaving(at));
        ForAgent::printed(self.run("person-text", &options, words)?, at)
    }

    /// Where the owner gets paid, signed by their key.
    pub fn where_paid(
        &self,
        places: &[splint_core::requests::Place],
        at: Option<&AtHost>,
    ) -> Result<ForAgent, Failure> {
        let places = serde_json::to_string(places)
            .map_err(|_| Failure::refused("those places can't be written down"))?;
        ForAgent::printed(self.run("where-paid", &leaving(at), &places)?, at)
    }

    /// A fresh proof for leaving at a host again what was sealed for an agent there before, and the
    /// host hasn't taken: over those exact sealed bytes, as the proof made with them was only good for
    /// moments.
    pub fn leaving_again(&self, host: &str, path: &str, body: &str) -> Result<String, Failure> {
        self.run(
            "access",
            &[
                "--host", host, "--method", "POST", "--path", path, "--body", "-",
            ],
            body,
        )
    }

    /// One call to a host as this owner, to read what an agent elsewhere left for them.
    pub fn access_proof(&self, host: &str, method: &str, path: &str) -> Result<String, Failure> {
        self.run(
            "access",
            &["--host", host, "--method", method, "--path", path],
            "",
        )
    }

    /// Signs what the rules this device last signed allow, from drafts worked out here.
    /// `waiting` carries the schemas the drafts name, which owner-key reads for itself. For an agent
    /// elsewhere each approval comes back sealed for its host.
    pub fn auto(
        &self,
        agent: &SplintId,
        waiting: &str,
        at: Option<&AtHost>,
    ) -> Result<String, Failure> {
        let schemas = self.schemas.to_string_lossy();
        let mut options = vec!["--agent", agent.as_str(), "--schemas", schemas.as_ref()];
        options.extend(leaving(at));
        self.run("auto", &options, waiting)
    }
}

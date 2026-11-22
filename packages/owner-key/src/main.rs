//! Holds an owner's key on the owner's own device, and signs what only an owner can sign.
//!
//! It makes no network calls. It reads what it's asked to sign and writes the signed result out, so
//! the only way for a key to leave this device is for someone to copy the file. What it signs is
//! taken to Signet or a host by whoever runs it.
//!
//! This is the one program that writes to stdout and stderr, because a person is reading. Key
//! material can't get there: `SigningKey` can't be printed.

mod asks;
mod auto;
#[cfg(target_os = "macos")]
mod chip;
mod device;
mod examples;
mod grants;
mod prompt;
mod recovery;
mod sign_in;
mod sign_ins;
mod signing;

use std::env;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;
use serde::de::DeserializeOwned;
use splint_core::changes::Claim;
use splint_core::grants::GrantId;
use splint_core::host_api::OwnerMailKind;
use splint_core::recovery_code::RecoveryCode;
use splint_core::requests::{
    ApprovalDraft, Decision, InteractionType, PersonTextFor, Place, Schema, Schemas,
};
use splint_core::rules::RulesDraft;
use splint_core::{
    AgentKeys, Identity, MessageId, PublicKey, RecoveryRule, RetirementReason, SigningKey,
    SplintId, VerifiedBinding,
};

use splint_core::host_api::owner_view_about;

use crate::device::Device;

const USAGE: &str = "\
owner-key: holds an owner's key on this device, and signs what only an owner can sign.

  owner-key init --dir DIR [--unconfirmed yes | --recovery later]
      Makes an owner key and a backup key, and prints the owner's identity and ID.
      Move DIR/backup.key somewhere else afterwards. With --recovery later it makes no backup yet,
      and nothing can recover the ID until set-recovery makes one. With --unconfirmed yes it makes a stand-in for
      an owner who hasn't set up their controls, on the machine of an agent that joined on its own:
      no backup, an ID nobody can recover, and nothing it signs counts as an owner's.
  owner-key init --dir DIR --sign-in chip|file [--passphrase - | --plain-key-file yes]
      Makes a new owner ID around this computer's sign-in, with no recovery code yet: a key in the
      security chip, which signs only with Touch ID or the login password, where this computer has one
      Splint can use (a Mac's Secure Enclave), or a key file. A key file is locked with a passphrase:
      --passphrase - takes it from the first line of standard input, at least 8 characters, and
      every later command then needs it the same way. With --plain-key-file yes it has none, so
      anything running as you on this computer, your agent included, can then sign as you, and every
      command that uses or lists it says so. A key file with neither is refused.
  owner-key lock-sign-in --dir DIR --passphrase - [--unmarked-sign-in yes]
      Locks a plain key file sign-in with a passphrase, the first line of standard input, keeping its
      key, so your owner ID doesn't change. A copy of the plain file made before this still signs.
      Only a key file made as a sign-in, with --sign-in or offer-sign-in, is locked. The owner key
      init and recover make without one is for a device kept apart from your agents, and splint
      authorize and setup use it with no passphrase, so locking it would stop them. A sign-in made
      before they were marked as one takes --unmarked-sign-in yes, as splint computer lock gives.
  owner-key show --dir DIR
      Prints the owner's identity and ID, how the sign-in here is held, and whether the recovery code
      is set, from the public ID alone, so it opens no sign-in.
  owner-key sign-inputs --dir DIR < inputs.json
      Signs owner objects a page or Splint on this computer prepared, {\"inputs\": [\"HEADER.PAYLOAD\"]},
      each with an ES256 header naming an owner type, after one prompt written from them, and prints
      {\"signed\": [...], \"code\": \"ABCD 1234\"}, the code the prompt and the page both show.
  owner-key approve-asks --dir DIR --schemas DIR < asks.json
      Approves what agents asked for, {\"asks\": [{\"ask\", \"identity\", \"address\"}]}, each checked under
      its agent's ID, after one prompt written from the asks: controls for an agent that asked to
      act for you, with \"rules\" and \"delegate\" from Splint on this computer, or new rules holding
      exactly what was asked, from the newer of the ones signed here before and \"in_force\", the
      rules its host or Signet holds, checked under the owner, or \"owner_identity\" where that's a
      newer copy of their ID. Prints each answer, the asks it refused and why, and the code the
      prompt showed.
  owner-key describe-asks --dir DIR < asks.json
      Prints each ask given, as approve-asks takes them, in the words its prompt names it by, for a
      page or terminal to show the same. It opens no sign-in and signs nothing.
  owner-key offer-sign-in --dir NEWDIR --identity IDENTITY --by KEY [--sign-in chip|file] [--passphrase - | --plain-key-file yes]
      On a second computer: makes its sign-in in NEWDIR, a key file as init makes one, and prints what
      a computer whose sign-in KEY counts takes with add-sign-in: the addition, signed by the new key,
      and a lock for the reading key.
  owner-key add-sign-in --dir DIR < offer.json
      Adds the sign-in another computer offered to this owner ID, after a prompt naming it, and prints
      the ID with it and that sign-in's copy of the reading key, for take-sign-in there.
  owner-key take-sign-in --dir NEWDIR < added.json
      Takes up the owner ID on the computer that offered its sign-in, opening its copy of the reading key.
  owner-key set-recovery --dir DIR
      For an ID made with --recovery later: makes DIR/backup.key and signs that the ID commits to it,
      once. Give the identity it prints to your hosts and Signets, then move the backup off this device.
  owner-key set-recovery --dir DIR --code new [< list.json]
      The same, with the backup derived from a new recovery code, which it prints once, last, and keeps
      nowhere: write it down, and never give it to anyone, an agent included. Given {\"host\",
      \"agents\", \"after\"} on standard input, after the passphrase if there is one, it also signs the
      owner's list of those agents with the backups kept here, sealed to the owner and to the new code,
      for that host, and prints it as list:. A list is signed only while this sign-in is the ID's only key.
  owner-key list-handle --code - < recovery-code
      Prints the handle a computer's sign-in keeps the owner's list under, which the recovery code
      gives, for GET /v0/owner-handles/HANDLE.
  owner-key recover --dir NEWDIR --sign-in chip|file [--passphrase - | --plain-key-file yes] --code - < input
      On a new computer, with the recovery code as the line after any passphrase, then JSON:
      {\"identities\": [every copy of the owner ID found], \"lists\": [every list found under the
      handle], \"host\": HOST}. Recovers the ID onto this computer's sign-in from the copy that
      commits to the code, opens the newest list it signed there, and keeps each agent's backup here.
      Prints the recovered identity, the agents, and a new recovery code, once.
  owner-key restore-agents --dir DIR --schemas DIR < input
      After recover: brings back, with one prompt naming each by address, at most 8 agents
      {\"here\": [{\"identity\", \"address\", \"new_key\", \"delegate\"}]} onto the new Signets whose
      keys are given, with \"rules\" and a delegation, and signs the owner's \"list\" again for
      \"host\". Prints each agent's recovered identity, binding, rules and delegation, and the list.
  owner-key open-view --dir DIR --agent ID < sealed
      Opens what this agent's Signet left at its host for this owner, which only this device's
      sealing key can read.
  owner-key open-note --dir DIR --about TEXT < sealed
      Opens, with the reading key alone and no sign-in, the owner's list of agents (TEXT \"splint owner
      agents for OWNER\") or what an agent's Signet left them (\"splint owner view for AGENT\"), and
      prints it, for Splint on this computer to read for the owner's page.
  owner-key check-backup --dir DIR --backup FILE [--agent IDENTITY]
      Checks that a backup key is the one this owner's identity, or this agent's, committed to.
  owner-key recover --dir NEWDIR --identity IDENTITY --backup FILE
  owner-key recover --dir NEWDIR --identity IDENTITY --code - < recovery-code
      After losing the owner key, or having it stolen: makes a new key and backup in NEWDIR, keeping
      the same ID. Give each of your Signets the identity it prints, at PUT /v0/owner/recovery, then
      sign a new binding and new rules for each, because what the old key signed stops counting.
      With --code -, the backup is the recovery code your controls showed you, read from standard
      input so it's in no command line, as when the sign-in that made it is lost.
  owner-key agent-backup --dir DIR
      Makes a backup key for an agent, kept here. Give its Signet the commitment at setup, as
      SPLINT_RECOVERY_COMMITMENT, or give it to the owner handing an agent over to you.
  owner-key agent-identity --key KEYS --commitment HASH
      Prints the identity and ID that an agent holding KEYS, its signing and sealing keys, gets, with this backup commitment, so an
      owner can authorize an agent whose private key only its Signet holds.
  owner-key recover-agent --dir DIR --agent IDENTITY [--backup FILE] --new-key KEYS
      After an agent's key is lost or stolen: names the keys its new Signet shows as this ID's,
      keeping the same ID. Give that Signet the identity it prints, at PUT /v0/owner/recovery.
      With no --backup, the one kept in DIR that this ID commits to.
  owner-key bind --dir DIR --agent IDENTITY --address HANDLE~DOMAIN [--backup FILE]
      Signs that this agent acts for this owner, at this address, with the agent's backup vouching
      for it, so nobody holding only the agent's key can name an owner for it. This device remembers
      what the backup signed, so after the first time FILE can be off this device, where a thief who
      takes the device can't use it to move the agent.
  owner-key bind-ahead --dir DIR --agent IDENTITY --address HANDLE~DOMAIN --backup FILE
      The same, for an agent that joined on its own, whose stand-in moves its ID to FILE's backup
      when it takes this up. It counts once that move is part of the agent's ID.
  owner-key set-up --dir DIR --agent IDENTITY --address HANDLE~DOMAIN --backup FILE [--delegate KEY] [--schemas DIR] < draft.json
      Sets up your controls for an agent that joined on its own, in one go: what bind-ahead signs,
      these rules until you sign others, and with --delegate a delegation to that key in its Signet
      for a year, which the rules name. The bytes are the ones an owner page in a browser makes, from
      Setting up your controls in docs/protocol.md. Prints the answer for the agent to take up.
  owner-key revoke --dir DIR --agent ID
      Signs that this agent acts for nobody, to send to its host, until you bind it again.
  owner-key transfer --dir DIR --agent IDENTITY --backup FILE --to OWNER_ID --commitment HASH [--new-key KEYS] [--seq N]
      Gives an agent to a new owner, with the commitment from their agent-backup. With --new-key it
      moves to their Signet too, so nothing you hold can sign for it afterwards. --seq dates the
      release, which has to come before what the new owner signed.
  owner-key rules --dir DIR --agent ID [--schemas DIR] [--agreed given] [--delegation none|as-drafted] < draft.json
      Signs the full rules for one agent, replacing the ones before, until others are signed. Caps
      need the schemas Signet holds the agent to, and one that names nothing in them isn't signed.
      With --agreed given, stdin is {\"draft\", \"schemas\"}, with the types the agent's Signet
      agreed. Rules with the permissions of those signed before name the same delegation. Other permissions
      name none, which ends it, until owner-key delegate signs one for them. --delegation none
      names none whatever the permissions, as after POST /v0/owner/delegate-key, so the old
      key's yeses stop at the host too. --delegation as-drafted names only what the draft names,
      for a draft built on the rules in force, which another device may have signed since.
  owner-key invite --dir DIR --agent ID --address HANDLE~DOMAIN --types TYPE,TYPE --days N
      Makes an invitation: a link to pass on outside Splint, and an entry for the rules' invites.
      TYPE is an interaction type, such as quote/1, which whoever uses the link may use.
  owner-key redeem --dir DIR --agent ID --types TYPE,TYPE < link
      Opens an invitation for this owner's agent: an entry for the rules' contacts, and a proof
      for Signet to send once those rules are signed. The link holds a private key, so it's read
      from stdin, where other programs on this machine can't list it.
  owner-key approve --dir DIR --decision approve|deny [--subject TEXT] [--host DOMAIN --agent-identity IDENTITY] < draft.json
      Signs a yes or no to a draft from Signet, after printing what it says.
      With --host and --agent-identity, here and on accept-change, person-text, where-paid and auto,
      for an agent that isn't on this machine: it prints {\"signed\", \"body\", \"proof\"}, where body
      is what was signed sealed to that agent, IDENTITY, which only its Signet can open, and proof is
      this owner's proof for posting exactly that body to /v0/owner-mail/AGENT at its host, DOMAIN,
      signed in the same run. A host keeps only what's sealed.
  owner-key delegate --dir DIR --agent ID --delegate KEY --schemas DIR [--days N]
      Signs that this agent's Signet's delegate key, KEY from GET /v0/owner/delegation, may, above
      ask me, say yes to a confirm whose every value has a cap in the rules this device last signed
      for the agent and fits it, up to their daily limit. For 365 days unless --days says less. It
      prints the delegation and those rules signed again naming it, which it counts under alone. At
      ask me there's nothing to delegate, and it prints only the rules, naming none. Give the delegation to PUT /v0/owner/delegation and the rules to
      PUT /v0/owner/rules. Rules naming another delegation, or none, end this one.
  owner-key auto --dir DIR --agent ID --schemas DIR [--hook FILE] [--host DOMAIN --agent-identity IDENTITY] < waiting.json
      Signs with nobody there, from Signet's waiting drafts and held senders as JSON, with the
      fields drafts and held. It signs the approvals the permission level in this agent's rules
      allows, and lists the rest as asked. With --hook it runs FILE for each held sender, with
      their facts on stdin, and signs new rules from its answer, a decision of admit with types,
      block or wait. It makes no network calls.
  owner-key access --dir DIR --host DOMAIN --method METHOD --path PATH [--body -]
      Signs one call to a host as this owner, to read what an agent elsewhere left for them, and prints
      the proof. It's good for moments, for that call alone. With --body -, only for POST to
      /v0/owner-mail/AGENT, the proof is over the body on standard input: what was sealed for that
      agent before and its host hasn't taken, to leave it there again.
  owner-key sign-change --dir DIR --agent ID --prev HEAD --kind signet --location TEXT --protection software_file|hardware
      Signs where this agent's Signet now runs and how its key is held, for PUT /v0/owner/change. HEAD
      is the change_head that Signet shows. Readers see this as unproven, as no device has attested to it.
  owner-key sign-change --dir DIR --agent ID --prev HEAD --kind declared --what TEXT
      Signs a change Splint can't see, such as a new runtime. Readers see this as unverified.
  owner-key accept-change --dir DIR --agent ID --contact ID --head HEAD [--host DOMAIN --agent-identity IDENTITY]
      Signs yes to a contact's history as far as this exact head, for POST /v0/owner/changes/accept.
      HEAD comes from GET /v0/owner/changes. A later change needs a later yes.
  owner-key person-text --dir DIR --agent ID --to ID [--request REQUEST] [--host DOMAIN --agent-identity IDENTITY] < words
      Signs words you wrote, up to 280 characters, for POST /v0/owner/person-text. This agent's Signet
      puts them on its next step that can carry them, to that contact: on that request, or without
      --request on the next one it opens with them. The other agent reads them marked untrusted.
  owner-key where-paid --dir DIR [--host DOMAIN --agent-identity IDENTITY] < places
      Signs where you get paid, for POST /v0/owner/where-paid: a JSON list of up to 4 places, each
      with a kind: payment_page with a url, lightning with to, or onchain with chain, address and
      asset. It replaces what you signed before. Your agent's Signet puts it on its asks to be paid.
  owner-key retire --dir DIR --agent ID --reason key_lost|finished [--agent-identity IDENTITY --binding TEXT]
      Signs a stop signal for an agent, to send to its host, which goes on to its peers. It stops the
      agent at once and is final after 7 days, and until then a recovery of your ID undoes it, in case a
      thief signed it. The agent then stays stopped until you bind it again. With its identity and
      binding it prints a notice any host will take for its own agents' contact, for when the agent's
      own host can't be trusted to carry it, and the prompt names the address you bound it to.
  owner-key grant --dir DIR --holder ID --resource NAME --operations OP,OP --calls-per-hour N [--days N]
      Signs that this agent may do these operations at this resource, for 7 days unless --days says
      otherwise, at most 30. NAME and each OP are the resource's own words. Prints the grant and its ID.
  owner-key revoke-grant --dir DIR --grant GRANT_ID
      Signs that a grant is over, for the resource itself to take with record-revocation.
  owner-key check-grant --owner IDENTITY --resource NAME --record FILE < call.json
      For a resource to run on each call, with the owner's public identity from its own config. Reads
      grant, identity, proof, operation, method, path and body, and prints ok with the grant, holder
      and operation, or a fixed reason. It exits with a failure on a refusal. FILE holds what the
      resource has seen of revocations and use, and is made if it isn't there.
  owner-key record-revocation --owner IDENTITY --record FILE < revocation
      Takes a revocation into a resource's record, from anyone, since the owner's signature counts.
  owner-key record-identity --identity IDENTITY --record FILE
      Takes the newest copy of an agent's or owner's ID into a resource's record, after a recovery. The
      old key then stops working there, without waiting for the agent's next call or a change to the
      resource's config. A backup key made it, so it's taken from anyone.
";

#[derive(Serialize)]
struct AgentIdentity {
    identity: String,
    agent_id: SplintId,
}

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("{0}\n\n{USAGE}")]
    Usage(String),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Core(#[from] splint_core::Error),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Record(#[from] grants::LedgerError),
    /// A resource's no, printed for the resource to read, with a failing exit so a caller that only
    /// looks at that still refuses.
    #[error("{0}")]
    Denied(String),
}

/// `--name value` pairs, after the command. Anything else is a mistake, so a mistyped option can't
/// quietly sign something other than what was meant.
struct Options(Vec<(String, String)>);

impl Options {
    fn parse(mut words: impl Iterator<Item = String>) -> Result<Self, Failure> {
        let mut pairs = Vec::new();
        while let Some(word) = words.next() {
            let name = word
                .strip_prefix("--")
                .ok_or_else(|| Failure::Usage(format!("expected an option, got {word}")))?;
            let value = words
                .next()
                .ok_or_else(|| Failure::Usage(format!("--{name} needs a value")))?;
            pairs.push((name.to_owned(), value));
        }
        Ok(Self(pairs))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(found, _)| found == name)
            .map(|(_, value)| value.as_str())
    }

    fn identity(&self, name: &str) -> Result<Identity, Failure> {
        Ok(Identity::from_encoded(self.required(name)?)?)
    }

    fn signing_key(&self, name: &str) -> Result<SigningKey, Failure> {
        Ok(SigningKey::load(&PathBuf::from(self.required(name)?))?)
    }

    /// An agent's signing key and sealing key, as its Signet writes them: one word with a dot between.
    fn agent_keys(&self, name: &str) -> Result<Option<AgentKeys>, Failure> {
        Ok(self.get(name).map(AgentKeys::from_encoded).transpose()?)
    }

    fn required(&self, name: &str) -> Result<&str, Failure> {
        self.get(name)
            .ok_or_else(|| Failure::Usage(format!("--{name} is required")))
    }

    /// Where what's signed is left for an agent that isn't on this machine, when both are given: its
    /// host, as one is spelled, and the agent's ID, which checks its own keys.
    fn at_host(&self) -> Result<Option<signing::AtHost>, Failure> {
        match (self.get("host"), self.get("agent-identity")) {
            (None, None) => Ok(None),
            (Some(host), Some(_)) => Ok(Some(signing::AtHost {
                host: splint_core::canonical_domain(host)
                    .ok()
                    .filter(|spelled| spelled == host)
                    .ok_or_else(|| Failure::Usage("--host isn't a host's domain".to_owned()))?,
                agent: self.identity("agent-identity")?,
            })),
            _ => Err(Failure::Usage(
                "--host and --agent-identity go together".to_owned(),
            )),
        }
    }

    /// A word from a closed set, such as `approve` or `key_lost`, or an ID, read as the protocol
    /// reads them.
    fn word<T: DeserializeOwned>(&self, name: &str) -> Result<T, Failure> {
        serde_json::from_value(serde_json::Value::String(self.required(name)?.to_owned()))
            .map_err(|_| Failure::Usage(format!("--{name} isn't valid")))
    }
}

impl Options {
    /// A comma-separated list of interaction types, which an owner always names. There's no default,
    /// because the types a contact uses are agreed between agents. Each is its ID, or its name and
    /// version where `--schemas` holds the one schema with that name, which gives its ID.
    fn types(&self) -> Result<Vec<InteractionType>, Failure> {
        let schemas = match self.get("schemas") {
            Some(folder) => auto::load_schemas(&PathBuf::from(folder))?,
            None => Schemas::default(),
        };
        self.required("types")?
            .split(',')
            .map(|name| {
                InteractionType::try_from(name.to_owned())
                    .ok()
                    .or_else(|| schemas.named(name).map(|schema| schema.name().clone()))
                    .ok_or_else(|| Failure::Usage("--types isn't valid".to_owned()))
            })
            .collect()
    }
}

fn read_stdin_json<T: DeserializeOwned>() -> Result<T, Failure> {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text)?;
    serde_json::from_str(&text)
        .map_err(|_| Failure::Refused("that isn't a valid draft to sign".to_owned()))
}

/// A rules draft from stdin, whose caps each name a value the schemas list. A type in it can be named
/// by its name and version where `--schemas` holds the one schema with that name, which gives its ID.
/// With `--agreed given`, stdin is `{"draft", "schemas"}`: the draft, and the types its agent's Signet
/// says it agreed, which no folder holds. Each is read here, so its ID is this device's own fingerprint
/// of it, and a Signet can't pass off one type as another.
fn capped_draft(options: &Options) -> Result<RulesDraft, Failure> {
    let (draft, given) = match options.get("agreed") {
        None => (read_stdin_json()?, Vec::new()),
        Some("given") => {
            let with: WithAgreed = read_stdin_json()?;
            (with.draft, with.schemas)
        }
        Some(_) => return Err(Failure::Usage("--agreed takes given".to_owned())),
    };
    let folder = options
        .get("schemas")
        .map(|folder| auto::load_schemas(&PathBuf::from(folder)))
        .transpose()?;
    let schemas = match (folder, options.get("agreed")) {
        (None, None) => None,
        (folder, _) => Some(auto::with_given(&folder.unwrap_or_default(), given)),
    };
    capped(draft, schemas.as_ref())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WithAgreed {
    draft: serde_json::Value,
    schemas: Vec<Schema>,
}

fn capped(mut draft: serde_json::Value, schemas: Option<&Schemas>) -> Result<RulesDraft, Failure> {
    if let Some(schemas) = schemas {
        named_by_id(&mut draft, schemas);
    }
    let draft: RulesDraft = serde_json::from_value(draft)
        .map_err(|_| Failure::Refused("that isn't a valid draft to sign".to_owned()))?;
    if !draft.permissions.caps.is_empty() {
        let schemas = schemas.ok_or_else(|| {
            Failure::Usage("caps need --schemas, to check what they apply to".to_owned())
        })?;
        if let Some(cap) = draft.permissions.unbound_cap(schemas) {
            return Err(Failure::Usage(format!(
                "the cap {cap} names no value those schemas list, so it would never apply"
            )));
        }
    }
    Ok(draft)
}

/// Each type a draft names by its name and version alone, where these schemas hold one with that name,
/// named by its ID instead: in contacts, invitations, the reach settings and caps.
fn named_by_id(draft: &mut serde_json::Value, schemas: &Schemas) {
    let id_of = |name: &str| {
        schemas
            .named(name)
            .map(|schema| schema.name().as_str().to_owned())
    };
    let in_list = |list: Option<&mut serde_json::Value>| {
        for named in list
            .and_then(serde_json::Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if let Some(id) = named.as_str().and_then(id_of) {
                *named = serde_json::Value::String(id);
            }
        }
    };
    for part in ["contacts", "invites"] {
        for entry in draft
            .get_mut(part)
            .and_then(serde_json::Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            in_list(entry.get_mut("types"));
        }
    }
    if let Some(reach) = draft.get_mut("reach") {
        in_list(reach.pointer_mut("/inbound/types"));
        in_list(reach.pointer_mut("/agreed/types"));
    }
    if let Some(caps) = draft
        .pointer_mut("/permissions/caps")
        .and_then(serde_json::Value::as_object_mut)
    {
        let named: Vec<(String, serde_json::Value)> = std::mem::take(caps).into_iter().collect();
        for (name, value) in named {
            caps.insert(id_of(&name).unwrap_or(name), value);
        }
    }
}

/// The backup key a recovery code names, as a person typed or pasted it.
fn recovery_code_from_stdin() -> Result<SigningKey, Failure> {
    let mut typed = String::new();
    io::stdin().read_to_string(&mut typed)?;
    let code = RecoveryCode::parse(&typed).map_err(|_| {
        Failure::Refused("that isn't a recovery code: check each character".to_owned())
    })?;
    Ok(code.backup_key()?)
}

fn printed<T: Serialize>(value: &T) -> Result<String, Failure> {
    serde_json::to_string(value).map_err(|_| Failure::Refused("couldn't write that".to_owned()))
}

/// The first line of standard input, for `--passphrase -`, leaving the rest for the command.
fn passphrase_from_stdin(options: &Options) -> Result<Option<String>, Failure> {
    match options.get("passphrase") {
        None => Ok(None),
        Some("-") => {
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                return Err(Failure::Refused("the passphrase was empty".to_owned()));
            }
            sign_in::give_passphrase(line.as_bytes().to_vec());
            Ok(Some(line.to_owned()))
        }
        Some(_) => Err(Failure::Usage(
            "--passphrase takes -, and the passphrase comes on standard input".to_owned(),
        )),
    }
}

/// Why `lock-sign-in` leaves an owner key that wasn't made as a sign-in alone.
const NOT_A_SIGN_IN: &str = "the key file in that folder wasn't made as a sign-in, so nothing was \
     locked: splint authorize and setup use it with no passphrase, and locking it would stop them. If \
     it's your sign-in for Splint on this computer, from before sign-ins were marked, lock it with \
     splint computer lock";

/// A passphrase for a new key file, or for locking one, from the one given on standard input.
fn new_passphrase(given: Option<&str>) -> Result<sign_in::NewPassphrase, Failure> {
    let given = given.ok_or_else(|| {
        Failure::Refused(
            "a key file is locked with a passphrase, so nothing else running as you can sign as \
             you: give one with --passphrase -, as the first line of standard input"
                .to_owned(),
        )
    })?;
    sign_in::NewPassphrase::chosen(given).ok_or_else(|| {
        Failure::Refused(format!(
            "a passphrase has at least {} characters, so nothing was made",
            sign_in::FEWEST_CHARACTERS
        ))
    })
}

/// How a new sign-in is to be held, from what the person gave. A key file takes a passphrase, or
/// `--plain-key-file yes`, never neither: so one left out makes nothing, not a plain file.
fn holding(
    options: &Options,
    kind: sign_in::Kind,
    given: Option<&str>,
) -> Result<sign_in::Holding, Failure> {
    let plain = match options.get("plain-key-file") {
        None => false,
        Some("yes") => true,
        Some(_) => return Err(Failure::Usage("--plain-key-file takes yes".to_owned())),
    };
    match (kind, plain) {
        (sign_in::Kind::Chip, false) => Ok(sign_in::Holding::Chip),
        (sign_in::Kind::Chip, true) => Err(Failure::Usage(
            "--plain-key-file is for --sign-in file".to_owned(),
        )),
        (sign_in::Kind::File, true) if given.is_some() => Err(Failure::Usage(
            "a key file takes --passphrase - or --plain-key-file yes, not both".to_owned(),
        )),
        (sign_in::Kind::File, true) => Ok(sign_in::Holding::PlainFile),
        (sign_in::Kind::File, false) => new_passphrase(given).map(sign_in::Holding::LockedFile),
    }
}

/// What a command signs, in the words of its sign-in's prompt. The commands that sign objects made
/// elsewhere write theirs from those objects instead, and making or taking up an owner ID says so.
fn signs(command: &str) -> &'static str {
    match command {
        "set-recovery" => "set your recovery code",
        "bind" | "bind-ahead" => "let your agent act for you",
        "set-up" => "set up your controls for your agent",
        "revoke" => "stop your agent at its host",
        "transfer" => "give your agent to another owner",
        "rules" | "redeem" => "set your agent's rules",
        "approve" => "answer what your agent asked you",
        "delegate" => "let your agent's Signet say yes within your limits",
        "access" => "read what a host keeps for you",
        "sign-change" => "say where your agent runs",
        "accept-change" => "accept a contact's change",
        "person-text" => "send your words through your agent",
        "retire" => "retire your agent",
        "grant" => "grant your agent a resource",
        "revoke-grant" => "end a grant",
        _ => "use your owner ID",
    }
}

/// The address a retirement's prompt names, where it's given the agent's identity and the binding
/// its host holds: the one this owner bound it to, from their own signature, so a caller can't put
/// another of their agents' names on the prompt. A binding signed by a key this device's copy of the
/// ID doesn't know yet names nothing, and the prompt says only that an agent is retired. An identity
/// that isn't the agent given is refused, as what's posted would then say two things.
fn retiring_named(
    dir: &Path,
    options: &Options,
    agent: &SplintId,
) -> Result<Option<String>, Failure> {
    let (Some(_), Some(binding)) = (options.get("agent-identity"), options.get("binding")) else {
        return Ok(None);
    };
    let identity = options.identity("agent-identity")?;
    if identity.id() != agent {
        return Err(Failure::Usage(
            "--agent-identity isn't the agent named by --agent".to_owned(),
        ));
    }
    let owner = device::identity_in(dir)?;
    Ok(VerifiedBinding::verify(binding, &owner, &identity)
        .ok()
        .map(|bound| bound.address().to_owned()))
}

/// What a prompt says of something signed for an agent elsewhere, which this run also seals to that
/// agent and signs a proof for leaving at its host. The proof lets only those sealed bytes in there.
fn and_left(what: &str, at: Option<&signing::AtHost>) -> String {
    match at {
        None => what.to_owned(),
        Some(at) => format!("{what}, and leave it at {} for your agent, sealed", at.host),
    }
}

/// What a command prints for something it signed for an agent: the thing alone, or for an agent
/// elsewhere, it with what leaves it at the agent's host.
fn handed(
    device: &Device,
    at: Option<&signing::AtHost>,
    kind: OwnerMailKind,
    signed: String,
) -> Result<String, Failure> {
    match signing::Handed::to(device, at, kind, signed)? {
        signing::Handed::Beside(signed) => Ok(signed),
        elsewhere @ signing::Handed::Elsewhere(_) => printed(&elsewhere),
    }
}

fn run(mut words: impl Iterator<Item = String>) -> Result<String, Failure> {
    let command = words.next().ok_or_else(|| Failure::Usage(String::new()))?;
    let options = Options::parse(words)?;
    let passphrase = passphrase_from_stdin(&options)?;
    let dir = || options.required("dir").map(PathBuf::from);
    let opened = || -> Result<Device, Failure> {
        Ok(Device::open(&dir()?, prompt::for_command(signs(&command)))?)
    };
    // The same, for what's also sealed and left at an agent's host, which the prompt then says.
    let opened_leaving = |at: Option<&signing::AtHost>| -> Result<Device, Failure> {
        let words = and_left(signs(&command), at);
        Ok(Device::open(&dir()?, prompt::for_command(&words))?)
    };
    Ok(match command.as_str() {
        "init" if options.get("sign-in").is_some() => {
            let kind = sign_in::Kind::parse(options.required("sign-in")?)
                .ok_or_else(|| Failure::Usage("--sign-in takes chip or file".to_owned()))?;
            let holding = holding(&options, kind, passphrase.as_deref())?;
            Device::init_signed_in(&dir()?, holding)
                .map_err(|_| match kind {
                    sign_in::Kind::Chip => Failure::Refused(
                        "couldn't make a key in this computer's security chip: use --sign-in file"
                            .to_owned(),
                    ),
                    sign_in::Kind::File => Failure::Refused(
                        "couldn't make the sign-in: is there one in that folder already?"
                            .to_owned(),
                    ),
                })?
                .summary()
        }
        "sign-inputs" => printed(&sign_ins::sign_inputs(&dir()?, read_stdin_json()?)?)?,
        "approve-asks" => {
            let schemas = auto::load_schemas(&PathBuf::from(options.required("schemas")?))?;
            match asks::approve(&dir()?, &schemas, read_stdin_json()?) {
                Err(splint_core::Error::NotApproved) => {
                    return Err(Failure::Refused("not approved".to_owned()));
                }
                answered => printed(&answered?)?,
            }
        }
        "describe-asks" => printed(&asks::describe(&dir()?, read_stdin_json()?)?)?,
        "offer-sign-in" => {
            let kind = match options.get("sign-in") {
                Some(word) => sign_in::Kind::parse(word)
                    .ok_or_else(|| Failure::Usage("--sign-in takes chip or file".to_owned()))?,
                None => sign_in::Kind::best_here(),
            };
            let holding = holding(&options, kind, passphrase.as_deref())?;
            printed(&sign_ins::offer(
                &dir()?,
                &options.identity("identity")?,
                options.required("by")?,
                holding,
            )?)?
        }
        "lock-sign-in" => {
            let dir = dir()?;
            if !sign_in::is_plain_file(&dir) {
                return Err(Failure::Refused(
                    "there's no plain key file sign-in in that folder to lock".to_owned(),
                ));
            }
            let told = match options.get("unmarked-sign-in") {
                None => None,
                Some("yes") => Some(sign_in::IsASignIn::as_told()),
                Some(_) => return Err(Failure::Usage("--unmarked-sign-in takes yes".to_owned())),
            };
            let is_a_sign_in = told
                .or_else(|| sign_in::IsASignIn::by_its_mark(&dir))
                .ok_or_else(|| Failure::Refused(NOT_A_SIGN_IN.to_owned()))?;
            sign_in::lock(&dir, is_a_sign_in, new_passphrase(passphrase.as_deref())?)?;
            device::summary_unopened(&dir)?
        }
        "add-sign-in" => printed(&sign_ins::add(&dir()?, read_stdin_json()?)?)?,
        "take-sign-in" => sign_ins::take(&dir()?, read_stdin_json()?)?.summary(),
        "init" if options.get("unconfirmed").is_some() => {
            if options.required("unconfirmed")? != "yes" {
                return Err(Failure::Usage("--unconfirmed takes yes".to_owned()));
            }
            Device::init_unconfirmed(&dir()?)?.summary()
        }
        "init" if options.get("recovery").is_some() => {
            if options.required("recovery")? != "later" {
                return Err(Failure::Usage("--recovery takes later".to_owned()));
            }
            Device::init_later(&dir()?)?.summary()
        }
        "init" => {
            let owner = Device::init(&dir()?)?;
            owner.summary()
        }
        "set-recovery" if options.get("code").is_some() => {
            if options.required("code")? != "new" {
                return Err(Failure::Usage("--code takes new".to_owned()));
            }
            let mut text = String::new();
            io::stdin().read_to_string(&mut text)?;
            let list: Option<recovery::ListGiven> = if text.trim().is_empty() {
                None
            } else {
                Some(serde_json::from_str(&text).map_err(|_| {
                    Failure::Refused("that isn't a list of agents to keep".to_owned())
                })?)
            };
            let dir = dir()?;
            let words = match &list {
                Some(list) => format!(
                    "{}, and {}",
                    signs(&command),
                    recovery::keeping_words(&list.host)
                ),
                None => signs(&command).to_owned(),
            };
            let (device, code) =
                Device::open(&dir, prompt::for_command(&words))?.set_recovery_code()?;
            let signed = match &list {
                Some(list) => recovery::sign_list(&device, list)?,
                None => None,
            };
            let list = signed
                .map(|list| format!("\nlist: {list}"))
                .unwrap_or_default();
            format!(
                "{}{list}\nrecovery code: {}",
                device.summary(),
                code.spelled()
            )
        }
        "list-handle" => {
            if options.required("code")? != "-" {
                return Err(Failure::Usage(
                    "--code takes -, and the code comes on standard input".to_owned(),
                ));
            }
            recovery::list_handle(&recovery_code_from_stdin()?)
        }
        "recover" if options.get("sign-in").is_some() => {
            let kind = sign_in::Kind::parse(options.required("sign-in")?)
                .ok_or_else(|| Failure::Usage("--sign-in takes chip or file".to_owned()))?;
            let holding = holding(&options, kind, passphrase.as_deref())?;
            if options.required("code")? != "-" {
                return Err(Failure::Usage(
                    "--code takes -, and the code comes on standard input".to_owned(),
                ));
            }
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            let code = RecoveryCode::parse(&line).map_err(|_| {
                Failure::Refused("that isn't a recovery code: check each character".to_owned())
            })?;
            let given: recovery::RecoverGiven = read_stdin_json()?;
            match recovery::recover(&dir()?, holding, &code.backup_key()?, &given) {
                Ok(recovered) => printed(&recovered)?,
                Err(recovery::NotRecovered::NotThisCode) => {
                    return Err(Failure::Refused(
                        "that recovery code isn't the one this owner ID holds now, so nothing \
                         changed. If it was recovered already, use the code that recovery showed"
                            .to_owned(),
                    ));
                }
                Err(recovery::NotRecovered::AlreadyRecovered) => {
                    return Err(Failure::Refused(
                        "this owner ID was recovered already with that code, so nothing changed \
                         here: use the recovery code that recovery showed"
                            .to_owned(),
                    ));
                }
                Err(recovery::NotRecovered::ListUnreadable) => {
                    return Err(Failure::Refused(
                        "the list of your agents at this host can't be read, so nothing changed \
                         and your recovery code still works. Try again later: going on now would \
                         use up the code and leave your agents behind"
                            .to_owned(),
                    ));
                }
                Err(recovery::NotRecovered::Failed(error)) => return Err(error.into()),
            }
        }
        "restore-agents" => {
            let schemas = auto::load_schemas(&PathBuf::from(options.required("schemas")?))?;
            let given: recovery::RestoreGiven = read_stdin_json()?;
            match recovery::restore(&dir()?, &schemas, &given) {
                Err(splint_core::Error::NotApproved) => {
                    return Err(Failure::Refused("not approved".to_owned()));
                }
                restored => printed(&restored?)?,
            }
        }
        "set-recovery" => opened()?.set_recovery()?.summary(),
        "show" => device::summary_unopened(&dir()?)?,
        "open-view" => {
            let agent: SplintId = options.word("agent")?;
            let mut sealed = String::new();
            io::stdin().read_to_string(&mut sealed)?;
            let opened = opened()?
                .seal_key
                .open_note(sealed.trim(), &owner_view_about(&agent))
                .map_err(|_| {
                    Failure::Refused("that isn't sealed to this owner, or was changed".to_owned())
                })?;
            String::from_utf8(opened)
                .map_err(|_| Failure::Refused("that doesn't read as text".to_owned()))?
        }
        "open-note" => {
            let about = options.required("about")?;
            let mut sealed = String::new();
            io::stdin().read_to_string(&mut sealed)?;
            let opened = device::open_note(&dir()?, sealed.trim(), about).map_err(|_| {
                Failure::Refused(
                    "that isn't sealed to this owner about that, or was changed".to_owned(),
                )
            })?;
            String::from_utf8(opened)
                .map_err(|_| Failure::Refused("that doesn't read as text".to_owned()))?
        }
        "check-backup" => {
            let backup = options.signing_key("backup")?;
            if options.get("agent").is_some() {
                options
                    .identity("agent")?
                    .check_backup(&backup.public_key())?;
                "the backup key matches this agent's identity".to_owned()
            } else {
                opened()?.check_backup(&backup.public_key())?;
                "the backup key matches this owner's identity".to_owned()
            }
        }
        "recover" => {
            let backup = match options.get("code") {
                Some("-") => recovery_code_from_stdin()?,
                Some(_) => {
                    return Err(Failure::Usage(
                        "--code takes -, and the code comes on standard input".to_owned(),
                    ));
                }
                None => options.signing_key("backup")?,
            };
            let recovered = Device::recover(&dir()?, &options.identity("identity")?, &backup)?;
            recovered.summary()
        }
        "agent-backup" => printed(&opened()?.new_agent_backup()?)?,
        "agent-identity" => {
            let keys = options
                .agent_keys("key")?
                .ok_or_else(|| Failure::Usage("--key is required".to_owned()))?;
            let rule = RecoveryRule::committed_to(options.required("commitment")?)?;
            let identity = keys.identity(rule)?;
            printed(&AgentIdentity {
                identity: identity.encoded(),
                agent_id: identity.id().clone(),
            })?
        }
        "recover-agent" => {
            let new_key = options
                .agent_keys("new-key")?
                .ok_or_else(|| Failure::Usage("--new-key is required".to_owned()))?;
            let agent = options.identity("agent")?;
            let backup = if options.get("backup").is_some() {
                options.signing_key("backup")?
            } else {
                device::agent_backup_committed_to(&dir()?, &agent).ok_or_else(|| {
                    Failure::Refused("no backup kept here fits this agent".to_owned())
                })?
            };
            printed(&signing::agent_recovery(
                &opened()?,
                &agent,
                &backup,
                &new_key,
            )?)?
        }
        "bind" => {
            let agent = options.identity("agent")?;
            let address = options.required("address")?;
            if options.get("backup").is_some() {
                let backup = options.signing_key("backup")?;
                signing::binding(&opened()?, &agent, address, &backup)?
            } else if !device::has_vouch(&dir()?, agent.id()) {
                return Err(Failure::Refused(
                    // `splint` reaches this when the backup file isn't where it was kept, and
                    // takes no --backup of its own, so the flag can't be all it says.
                    "this device hasn't bound this agent before, and needs the agent's backup file \
                     to do it (--backup FILE)"
                        .to_owned(),
                ));
            } else {
                signing::binding_from_memory(&opened()?, &agent, address)?
            }
        }
        "bind-ahead" => {
            let agent = options.identity("agent")?;
            let address = options.required("address")?;
            let backup = options.signing_key("backup")?;
            signing::binding_ahead(&opened()?, &agent, address, &backup)?
        }
        "revoke" => {
            let agent: SplintId = options.word("agent")?;
            signing::revocation(&opened()?, &agent)?
        }
        "transfer" => {
            let to: SplintId = options.word("to")?;
            printed(&signing::handover(
                &opened()?,
                &options.identity("agent")?,
                &options.signing_key("backup")?,
                &to,
                options.required("commitment")?,
                options.agent_keys("new-key")?.as_ref(),
                options
                    .get("seq")
                    .map(str::parse)
                    .transpose()
                    .map_err(|_| Failure::Usage("--seq is a number".to_owned()))?,
            )?)?
        }
        "set-up" => {
            let agent = options.identity("agent")?;
            let address = options.required("address")?;
            let backup = options.signing_key("backup")?;
            let delegate = options
                .get("delegate")
                .map(PublicKey::from_encoded)
                .transpose()
                .map_err(|_| Failure::Usage("--delegate isn't a public key".to_owned()))?;
            let draft = capped_draft(&options)?;
            let device = opened()?;
            let schemas = match options.get("schemas") {
                Some(folder) => auto::load_schemas(&PathBuf::from(folder))?,
                None if delegate.is_some() => {
                    return Err(Failure::Usage(
                        "--delegate needs --schemas, for the types its delegate may say yes to"
                            .to_owned(),
                    ));
                }
                None => Schemas::default(),
            };
            signing::controls(
                &device,
                &agent,
                address,
                &backup,
                draft,
                delegate.as_ref(),
                &schemas,
            )?
        }
        "rules" => {
            let agent: SplintId = options.word("agent")?;
            let draft = capped_draft(&options)?;
            let delegation = match options.get("delegation") {
                None => signing::Naming::AsBefore,
                Some("none") => signing::Naming::Nothing,
                Some("as-drafted") => signing::Naming::AsDrafted,
                Some(_) => {
                    return Err(Failure::Usage(
                        "--delegation takes none or as-drafted".to_owned(),
                    ));
                }
            };
            signing::rules(&opened()?, &agent, draft, delegation)?
        }
        "invite" => {
            let agent: SplintId = options.word("agent")?;
            let days: u64 = options
                .required("days")?
                .parse()
                .map_err(|_| Failure::Usage("--days isn't valid".to_owned()))?;
            let made =
                signing::invitation(&agent, options.required("address")?, options.types()?, days)?;
            printed(&made)?
        }
        "redeem" => {
            let agent: SplintId = options.word("agent")?;
            let mut link = String::new();
            io::stdin().read_to_string(&mut link)?;
            printed(&signing::redeem(&agent, link.trim(), options.types()?)?)?
        }
        "approve" => {
            let decision: Decision = options.word("decision")?;
            let draft: ApprovalDraft = read_stdin_json()?;
            let subject = options.get("subject").map(str::to_owned);
            let at = options.at_host()?;
            if let Some(at) = &at {
                at.is_of(&draft.agent)?;
            }
            let device = opened_leaving(at.as_ref())?;
            let contacts = device.contacts_of(&draft.agent);
            let shown = signing::describe_approval(
                &draft,
                decision,
                subject.as_deref(),
                contacts.as_deref(),
            );
            writeln!(io::stderr(), "{shown}")?;
            let approval = signing::approval(&device, &draft, decision, subject)?;
            handed(&device, at.as_ref(), OwnerMailKind::Approval, approval)?
        }
        "delegate" => {
            let agent: SplintId = options.word("agent")?;
            let delegate = PublicKey::from_encoded(options.required("delegate")?)
                .map_err(|_| Failure::Usage("--delegate isn't a public key".to_owned()))?;
            let days: u64 = options
                .get("days")
                .unwrap_or("365")
                .parse()
                .map_err(|_| Failure::Usage("--days isn't valid".to_owned()))?;
            // Checked before the sign-in asks, as core would refuse it after with no reason given.
            let most_days = splint_core::delegation::MAX_DELEGATION_LIFE_SECS / signing::DAY_SECS;
            if !(1..=most_days).contains(&days) {
                return Err(Failure::Usage(format!("--days is 1 to {most_days}")));
            }
            let device = opened()?;
            if device.rules_of(&agent).is_none() {
                return Err(Failure::Refused(
                    "sign rules for this agent here first: a delegation takes its limits from them"
                        .to_owned(),
                ));
            }
            let schemas = auto::load_schemas(&PathBuf::from(options.required("schemas")?))?;
            printed(&signing::delegation(
                &device, &agent, &delegate, days, &schemas,
            )?)?
        }
        "auto" => {
            let agent: SplintId = options.word("agent")?;
            let schemas = auto::load_schemas(&PathBuf::from(options.required("schemas")?))?;
            let waiting: auto::Waiting = read_stdin_json()?;
            let hook = options.get("hook").map(PathBuf::from);
            if sign_in::kind_in(&dir()?) == Some(sign_in::Kind::Chip) {
                return Err(Failure::Refused(
                    "a sign-in in the security chip signs only with you there, so what it would \
                     sign waits for you"
                        .to_owned(),
                ));
            }
            let at = options.at_host()?;
            if let Some(at) = &at {
                at.is_of(&agent)?;
            }
            let device = opened_leaving(at.as_ref())?;
            printed(&auto::run(
                &device,
                &agent,
                &schemas,
                waiting,
                hook.as_deref(),
                at.as_ref(),
            )?)?
        }
        "access" if options.get("body").is_some() => {
            let (host, path) = (options.required("host")?, options.required("path")?);
            if options.required("body")? != "-"
                || !signing::leaves_owner_mail(options.required("method")?, path)
            {
                return Err(Failure::Usage(
                    "--body takes -, and only for POST to /v0/owner-mail/AGENT".to_owned(),
                ));
            }
            let host = splint_core::canonical_domain(host)
                .ok()
                .filter(|spelled| spelled == host)
                .ok_or_else(|| Failure::Usage("--host isn't a host's domain".to_owned()))?;
            let mut body = Vec::new();
            io::stdin().read_to_end(&mut body)?;
            let words = format!(
                "leave at {host} again, sealed, what you signed for your agent that it hasn't taken"
            );
            let device = Device::open(&dir()?, prompt::for_command(&words))?;
            signing::leaving_again(&device, &host, path, &body)?
        }
        "access" => signing::access(
            &opened()?,
            options.required("host")?,
            options.required("method")?,
            options.required("path")?,
        )?,
        "sign-change" => {
            let agent: SplintId = options.word("agent")?;
            let claim = match options.required("kind")? {
                "signet" => Claim::Signet {
                    location: options.required("location")?.to_owned(),
                    protection: options.word("protection")?,
                },
                "declared" => Claim::Declared {
                    what: options.required("what")?.to_owned(),
                },
                _ => return Err(Failure::Usage("--kind isn't valid".to_owned())),
            };
            signing::change_statement(&opened()?, &agent, options.required("prev")?, claim)?
        }
        "accept-change" => {
            let agent: SplintId = options.word("agent")?;
            let contact: SplintId = options.word("contact")?;
            let at = options.at_host()?;
            if let Some(at) = &at {
                at.is_of(&agent)?;
            }
            let device = opened_leaving(at.as_ref())?;
            let acceptance =
                signing::change_acceptance(&device, &agent, &contact, options.required("head")?)?;
            handed(&device, at.as_ref(), OwnerMailKind::Acceptance, acceptance)?
        }
        "person-text" => {
            let agent: SplintId = options.word("agent")?;
            let to: SplintId = options.word("to")?;
            let request: Option<MessageId> = match options.get("request") {
                Some(_) => Some(options.word("request")?),
                None => None,
            };
            let mut words = String::new();
            io::stdin().read_to_string(&mut words)?;
            let at = options.at_host()?;
            if let Some(at) = &at {
                at.is_of(&agent)?;
            }
            let device = opened_leaving(at.as_ref())?;
            let signed = signing::person_text(
                &device,
                PersonTextFor {
                    agent: &agent,
                    to: &to,
                    request: request.as_ref(),
                },
                words.trim_end_matches(['\r', '\n']),
            )
            .map_err(|refused| Failure::Refused(refused.to_string()))?;
            handed(&device, at.as_ref(), OwnerMailKind::PersonText, signed)?
        }
        "where-paid" => {
            let mut given = String::new();
            io::stdin().read_to_string(&mut given)?;
            let places: Vec<Place> = serde_json::from_str(&given)
                .map_err(|_| Failure::Refused("places are a JSON list of places".to_owned()))?;
            // Where an owner gets paid is the same for each of their agents, so it names none, and
            // is sealed to whichever agent's host it's left at.
            let at = options.at_host()?;
            let words = and_left(&prompt::places_described(&places), at.as_ref());
            let device = Device::open(&dir()?, prompt::for_command(&words))?;
            let signed = signing::where_paid(&device, places)
                .map_err(|refused| Failure::Refused(refused.to_string()))?;
            handed(&device, at.as_ref(), OwnerMailKind::WherePaid, signed)?
        }
        "retire" => {
            let agent: SplintId = options.word("agent")?;
            let reason: RetirementReason = options.word("reason")?;
            let device = match retiring_named(&dir()?, &options, &agent)? {
                Some(address) => Device::open(
                    &dir()?,
                    prompt::for_command(&format!("retire {address}, for good")),
                )?,
                None => opened()?,
            };
            let retirement = signing::retirement(&device, &agent, reason)?;
            match options.get("agent-identity") {
                Some(_) => printed(&splint_core::host_api::RetirementNotice {
                    retirement,
                    owner_identity: device.identity.encoded(),
                    agent_identity: options.required("agent-identity")?.to_owned(),
                    binding: options.required("binding")?.to_owned(),
                })?,
                None => retirement,
            }
        }
        "grant" => {
            let holder: SplintId = options.word("holder")?;
            let days: u64 = options
                .get("days")
                .unwrap_or("7")
                .parse()
                .map_err(|_| Failure::Usage("--days isn't valid".to_owned()))?;
            let calls: u32 = options
                .required("calls-per-hour")?
                .parse()
                .map_err(|_| Failure::Usage("--calls-per-hour isn't valid".to_owned()))?;
            // Checked before the sign-in asks, as core would refuse them after with no reason given.
            let most_days = splint_core::grants::MAX_GRANT_LIFE_SECS / signing::DAY_SECS;
            if !(1..=most_days).contains(&days) {
                return Err(Failure::Usage(format!("--days is 1 to {most_days}")));
            }
            let most_calls = splint_core::grants::MAX_CALLS_PER_HOUR;
            if !(1..=most_calls).contains(&calls) {
                return Err(Failure::Usage(format!(
                    "--calls-per-hour is 1 to {most_calls}"
                )));
            }
            let operations = options
                .required("operations")?
                .split(',')
                .map(str::to_owned)
                .collect();
            printed(&grants::sign(
                &opened()?,
                holder,
                options.required("resource")?.to_owned(),
                operations,
                calls,
                days.saturating_mul(signing::DAY_SECS),
            )?)?
        }
        "revoke-grant" => {
            let grant: GrantId = options.word("grant")?;
            grants::revoke(&opened()?, &grant)?
        }
        "check-grant" => {
            let input: grants::CallInput = read_stdin_json()?;
            let verdict = grants::check(
                &options.identity("owner")?,
                options.required("resource")?,
                &PathBuf::from(options.required("record")?),
                &input,
            )?;
            let shown = printed(&verdict)?;
            if !verdict.granted() {
                return Err(Failure::Denied(shown));
            }
            shown
        }
        "record-identity" => {
            let copy = options.identity("identity")?;
            match grants::record_identity(&PathBuf::from(options.required("record")?), &copy)? {
                Ok(learned) => printed(&serde_json::json!({"learned": learned}))?,
                Err(reason) => {
                    return Err(Failure::Denied(printed(
                        &serde_json::json!({"ok": false, "reason": reason}),
                    )?));
                }
            }
        }
        "record-revocation" => {
            let mut revocation = String::new();
            io::stdin().read_to_string(&mut revocation)?;
            match grants::record_revocation(
                &options.identity("owner")?,
                &PathBuf::from(options.required("record")?),
                revocation.trim(),
            )? {
                Ok(grant) => printed(&serde_json::json!({"revoked": grant}))?,
                Err(reason) => {
                    return Err(Failure::Denied(printed(
                        &serde_json::json!({"ok": false, "reason": reason}),
                    )?));
                }
            }
        }
        "help" | "--help" => USAGE.trim_end().to_owned(),
        other => return Err(Failure::Usage(format!("unknown command {other}"))),
    })
}

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(output) => {
            if writeln!(io::stdout(), "{output}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(Failure::Denied(shown)) => {
            let _ = writeln!(io::stdout(), "{shown}");
            ExitCode::FAILURE
        }
        // A locked key file that didn't open says so, in place of the general words for that.
        Err(Failure::Core(splint_core::Error::CantOpen)) if sign_in::locked_out().is_some() => {
            let why = sign_in::locked_out().unwrap_or_default();
            let _ = writeln!(io::stderr(), "owner-key: {why}");
            ExitCode::FAILURE
        }
        Err(failure) => {
            let _ = writeln!(io::stderr(), "owner-key: {failure}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote() -> Schema {
        Schema::parse(include_bytes!("../../../spec/schemas/quote-1.json")).unwrap()
    }

    fn capping(interaction: &str) -> serde_json::Value {
        serde_json::json!({
            "paused": false, "contacts": [], "invites": [],
            "limits": { "new_requests_per_contact_per_day": 5, "open_requests_per_contact": 5, "open_approvals": 5 },
            "permissions": {
                "level": "auto_within_limits", "actions_per_day": 50,
                "caps": { interaction: { "amount_minor.usd": 10000 } },
            },
        })
    }

    /// A cap on a type the agents agreed, which no folder holds, was refused as if it named nothing, so
    /// an owner couldn't cap an agreed type from their page at all.
    #[test]
    fn a_cap_on_an_agreed_type_is_checked_against_what_was_agreed() {
        let quote = quote();
        let id = quote.name().as_str().to_owned();
        let agreed = auto::with_given(&Schemas::default(), vec![quote]);
        assert!(capped(capping(&id), Some(&agreed)).is_ok());
        assert!(capped(capping(&id), Some(&Schemas::default())).is_err());
        let mut wrong_value = capping(&id);
        wrong_value["permissions"]["caps"][&id] = serde_json::json!({ "nothing.usd": 1 });
        assert!(capped(wrong_value, Some(&agreed)).is_err());
    }
}

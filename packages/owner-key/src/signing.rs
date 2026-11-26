//! What an owner signs. Each refuses here what a reader would refuse later, so an owner finds out
//! on their own device rather than from a silent refusal somewhere else.

use std::time::{SystemTime, UNIX_EPOCH};

use splint_core::changes::{Claim, VerifiedAcceptance, sign_statement};
use splint_core::controls::ControlsDraft;
use splint_core::delegation::{Delegated, DelegationDraft, MAX_DELEGATION_LIFE_SECS, name_of};
use splint_core::host_api::{OwnerMail, OwnerMailKind};
use splint_core::invites::InviteLink;
use splint_core::owner_call::{mail_body, owner_mail_path, seal_owner_mail};
use splint_core::requests::{
    ApprovalDraft, Decision, FieldValue, Fields, InteractionType, PersonTextFor, Place, Refused,
    Schemas, Signers, TermsParty, VerifiedPersonText, VerifiedWherePaid, utc_time,
};
use splint_core::rules::{ContactStatus, Level, PinnedBy, RulesContact, RulesDraft, RulesInvite};
use splint_core::{
    AccessProof, AgentKeys, Error, Identity, PublicKey, RecoveryRule, RetirementReason, SigningKey,
    SplintId, VerifiedBinding, VerifiedRelease, VerifiedRetirement, unix_now,
};

use serde::Serialize;

use crate::device::{self, Device};

pub const DAY_SECS: u64 = 24 * 60 * 60;
/// 2001, well past any quantity an owner would misread as a date.
const EARLIEST_TIME_SHOWN: u64 = 1_000_000_000;

/// `seq` only has to rise, so it's this device's clock in milliseconds, with no counter to lose. A
/// clock set back gets a visible refusal, and readers refuse rules dated ahead of theirs, so a bad
/// clock can't raise it out of reach.
pub fn next_seq() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// This agent acts for this owner at this address, vouched for by the agent's backup, which only its
/// owner's device holds. A device that doesn't hold it, such as a new owner's before a handover, finds
/// out here.
pub fn binding(
    device: &Device,
    agent: &Identity,
    address: &str,
    backup: &SigningKey,
) -> Result<String, Error> {
    let signed = VerifiedBinding::sign(
        &device.key,
        backup,
        device.identity.id(),
        agent,
        address,
        next_seq(),
        unix_now(),
    )?;
    if let Some((_, vouch)) = signed.split_once(splint_core::BINDING_PART_SEPARATOR) {
        device.remember_vouch(agent.id(), vouch)?;
    }
    Ok(signed)
}

/// For an agent that joined on its own and whose stand-in moves its ID to `backup` once it has this,
/// keeping the keys `agent` has now: so the agent's ID doesn't commit to that backup yet, and readers
/// check it once it does.
pub fn binding_ahead(
    device: &Device,
    agent: &Identity,
    address: &str,
    backup: &SigningKey,
) -> Result<String, Error> {
    let signed = VerifiedBinding::sign_ahead(
        &device.key,
        backup,
        device.identity.id(),
        agent,
        address,
        next_seq(),
        unix_now(),
    )?;
    if let Some((_, vouch)) = signed.split_once(splint_core::BINDING_PART_SEPARATOR) {
        device.remember_vouch(agent.id(), vouch)?;
    }
    Ok(signed)
}

/// The same with no backup to hand, from what it signed for this owner the last time. A vouch names an
/// owner, an agent and the agent's keys when its ID committed to that backup, which a recovery since
/// doesn't change, so it still counts, and a backup moved off this device stays out of reach of
/// whoever takes it. Where the vouch kept is for a backup the ID never took, the backup kept here that
/// it does commit to signs instead, as [`binds_with`] finds.
pub fn binding_from_memory(
    device: &Device,
    agent: &Identity,
    address: &str,
) -> Result<String, Error> {
    match binds_with(device.dir(), device.identity.id(), agent)? {
        BindsWith::Vouch(vouch) => VerifiedBinding::sign_with_vouch(
            &device.key,
            &vouch,
            device.identity.id(),
            agent,
            address,
            next_seq(),
            unix_now(),
        ),
        BindsWith::Backup(backup) => binding(device, agent, address, &backup),
    }
}

/// What this device signs an agent's binding with when no backup is handed to it.
pub enum BindsWith {
    /// The vouch it kept, which counts for this copy of the agent's ID.
    Vouch(String),
    /// A backup kept here that the ID commits to now, which vouches again, and is kept as the vouch.
    Backup(SigningKey),
}

/// Which of the two this device has for an agent, read without opening the sign-in, so an ask it
/// can't sign is refused before anyone is asked. The vouch kept is the one from the last binding
/// signed here, and one signed for an ask its agent never took up names a backup the ID never
/// committed to, which no reader takes. Neither is `WrongSigner`.
pub fn binds_with(
    dir: &std::path::Path,
    owner: &SplintId,
    agent: &Identity,
) -> Result<BindsWith, Error> {
    if let Some(vouch) = device::vouch_in(dir, agent.id())
        && VerifiedBinding::vouch_counts(&vouch, owner, agent)
    {
        return Ok(BindsWith::Vouch(vouch));
    }
    device::agent_backup_committed_to(dir, agent)
        .map(BindsWith::Backup)
        .ok_or(Error::WrongSigner)
}

/// This agent acts for nobody until this owner signs for it again.
pub fn revocation(device: &Device, agent: &SplintId) -> Result<String, Error> {
    VerifiedRelease::sign(
        &device.key,
        device.identity.id(),
        agent,
        None,
        next_seq(),
        unix_now(),
    )
}

/// What a new agent backup replaces: this ID moves to a new key and the backup this device just made.
#[derive(Serialize)]
pub struct AgentRecovery {
    /// Hand this to the agent's Signet.
    identity: String,
    /// What the agent's ID commits to now, which is that key.
    commitment: String,
    /// The next backup key, which stays on this device.
    file: std::path::PathBuf,
}

pub fn agent_recovery(
    device: &Device,
    agent: &Identity,
    backup: &SigningKey,
    new_keys: &AgentKeys,
) -> Result<AgentRecovery, Error> {
    agent.check_backup(&backup.public_key())?;
    let next = device.new_agent_backup()?;
    let recovered = agent.recover(
        backup,
        &new_keys.key,
        &new_keys.seal,
        RecoveryRule::committed_to(&next.commitment)?,
        unix_now(),
    )?;
    Ok(AgentRecovery {
        identity: recovered.encoded(),
        commitment: next.commitment,
        file: next.file,
    })
}

/// An owner giving an agent up to someone else.
#[derive(Serialize)]
pub struct Handover {
    /// This agent's identity now: the recovery rule is the new owner's, so nobody here can recover it.
    identity: String,
    /// This owner's signed word, naming the new one.
    release: String,
}

/// The agent's next backup is the new owner's, which is what stops the old one taking it back. With
/// `new_key` it moves to a new Signet too, which the new owner can run where the old one can't reach.
pub fn handover(
    device: &Device,
    agent: &Identity,
    backup: &SigningKey,
    to: &SplintId,
    commitment: &str,
    new_keys: Option<&AgentKeys>,
    seq: Option<u64>,
) -> Result<Handover, Error> {
    let seal = agent.seal_key().ok_or(Error::Malformed)?;
    let moved = agent.recover(
        backup,
        new_keys.map_or_else(|| agent.sole_key(), |keys| Ok(&keys.key))?,
        new_keys.map_or(seal, |keys| &keys.seal),
        RecoveryRule::committed_to(commitment)?,
        unix_now(),
    )?;
    let release = VerifiedRelease::sign(
        &device.key,
        device.identity.id(),
        agent.id(),
        Some(to),
        seq.unwrap_or_else(next_seq),
        unix_now(),
    )?;
    Ok(Handover {
        identity: moved.encoded(),
        release,
    })
}

/// Which delegation the rules name.
pub enum Naming {
    /// The one the draft names, or else the one the rules this device last signed named, while the
    /// permissions are the same.
    AsBefore,
    /// The one the draft names, or none, for a draft built on the rules in force. Another of the
    /// owner's devices may have signed those since this one did, ending a delegation, which this
    /// device's own copy would bring back.
    AsDrafted,
    /// None, whatever the draft and the permissions, as after a new delegate key, when the old one
    /// may be out.
    Nothing,
}

/// Rules with the same permissions as those this device last signed name the delegation those did, so
/// adding a contact doesn't end it. Other permissions name none, which ends it at once: a delegation
/// carries its own caps, so lower ones bind only with a new delegation, from `owner-key delegate`.
pub fn rules(
    device: &Device,
    agent: &SplintId,
    mut draft: RulesDraft,
    naming: Naming,
) -> Result<String, Error> {
    match naming {
        Naming::Nothing => draft.delegation = None,
        Naming::AsDrafted => {}
        Naming::AsBefore => {
            if draft.delegation.is_none()
                && let Some(before) = device.rules_of(agent)
                && before.permissions == draft.permissions
            {
                draft.delegation = before.delegation;
            }
        }
    }
    sign_rules(device, agent, draft)
}

fn sign_rules(device: &Device, agent: &SplintId, draft: RulesDraft) -> Result<String, Error> {
    let remembered = draft.clone();
    let seq = next_seq();
    let signed = draft.sign(&device.key, device.identity.id(), agent, seq, unix_now());
    if signed.is_ok() {
        device.remember_rules(agent, &remembered, seq)?;
    }
    signed
}

/// A delegation, and the rules this device last signed for the agent signed again naming it, which it
/// needs to count anywhere. Hand both to the agent's Signet, and the rules to its host. At ask me
/// there's nothing to delegate, so there's no delegation, and the rules name none.
#[derive(Serialize)]
pub struct Delegating {
    #[serde(skip_serializing_if = "Option::is_none")]
    delegation: Option<String>,
    rules: String,
}

/// Lets this agent's Signet's delegate key, above ask me, say yes to a `confirm` within the caps of the
/// rules this device last signed for it, while nobody is here. Its level, caps and daily limit come
/// from those rules, never from Signet or the agent, so a fooled agent can't raise them. The rules are
/// signed again naming it, which ends any other.
pub fn delegation(
    device: &Device,
    agent: &SplintId,
    delegate: &PublicKey,
    days: u64,
    schemas: &Schemas,
) -> Result<Delegating, Error> {
    let mut rules = device.rules_of(agent).ok_or(Error::Malformed)?;
    let delegation = delegation_under(&rules, delegate, days.saturating_mul(DAY_SECS), schemas)
        .map(|draft| {
            draft.sign(
                &device.key,
                device.identity.id(),
                agent,
                next_seq(),
                unix_now(),
            )
        })
        .transpose()?;
    rules.delegation = delegation.as_deref().map(name_of);
    let rules = sign_rules(device, agent, rules)?;
    Ok(Delegating { delegation, rules })
}

/// A delegation whose caps and daily limit come from these rules: approvals within the caps above ask
/// me, at auto within limits, never full auto, and none at ask me, where every yes is the owner's. A
/// delegate says yes only to a type its delegation names, so every type the owner signs that carries
/// no value is named too, with nothing in it, or it would say yes to no meeting, as the owner's own
/// device does by itself.
fn delegation_under(
    rules: &RulesDraft,
    delegate: &PublicKey,
    lasts_secs: u64,
    schemas: &Schemas,
) -> Option<DelegationDraft> {
    if rules.permissions.level == Level::AskMe {
        return None;
    }
    let mut caps = rules.permissions.caps.clone();
    for schema in schemas.all() {
        if schema.values().next().is_none() && schema.sign() != Signers::None {
            caps.entry(schema.name().clone()).or_default();
        }
    }
    Some(DelegationDraft {
        delegate: delegate.clone(),
        may: vec![Delegated::ApproveWithinCaps],
        level: Level::AutoWithinLimits,
        caps,
        actions_per_day: rules.permissions.actions_per_day,
        lasts_secs,
    })
}

/// Setting up controls for an agent that joined on its own: the binding ahead and the backup's
/// vouch, these rules, and a delegation to `delegate` if given, which the rules name. The bytes are
/// made by `splint_core::controls`, as an owner's page makes them, so a file key and a passkey sign
/// the same thing. Gives the answer the agent takes up.
pub fn controls(
    device: &Device,
    agent: &Identity,
    address: &str,
    backup: &SigningKey,
    rules: RulesDraft,
    delegate: Option<&PublicKey>,
    schemas: &Schemas,
) -> Result<String, Error> {
    let delegation = delegate
        .and_then(|delegate| delegation_under(&rules, delegate, MAX_DELEGATION_LIFE_SECS, schemas));
    let seq = next_seq();
    let reply = ControlsDraft {
        agent: agent.clone(),
        address: address.to_owned(),
        backup: backup.public_key(),
        rules: rules.clone(),
        delegation,
        seq,
        now: unix_now(),
    }
    .prepare(&device.identity)?
    .signed_by_file_key(&device.key, backup)?;
    let mut remembered = rules;
    remembered.delegation = reply.delegation.as_deref().map(name_of);
    device.remember_rules(agent.id(), &remembered, seq)?;
    if let Some((_, vouch)) = reply
        .binding
        .split_once(splint_core::BINDING_PART_SEPARATOR)
    {
        device.remember_vouch(agent.id(), vouch)?;
    }
    reply.encode()
}

/// What an owner signs for an agent brought back on their new computer: its binding with its new
/// backup vouching, rules naming a delegation to its new Signet's delegate key, and that delegation.
#[derive(Serialize)]
pub struct Restored {
    pub binding: String,
    pub rules: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<String>,
}

/// For an agent whose ID was just recovered onto a new Signet, under the owner's recovered ID: these
/// rules, from Splint on this computer as for controls, and a delegation to that Signet's delegate key,
/// which the rules name, as setting up controls signs.
pub fn restored(
    device: &Device,
    agent: &Identity,
    address: &str,
    backup: &SigningKey,
    mut rules: RulesDraft,
    delegate: &PublicKey,
    schemas: &Schemas,
) -> Result<Restored, Error> {
    let binding = binding(device, agent, address, backup)?;
    let delegation = delegation_under(&rules, delegate, MAX_DELEGATION_LIFE_SECS, schemas)
        .map(|draft| {
            draft.sign(
                &device.key,
                device.identity.id(),
                agent.id(),
                next_seq(),
                unix_now(),
            )
        })
        .transpose()?;
    rules.delegation = delegation.as_deref().map(name_of);
    let rules = sign_rules(device, agent.id(), rules)?;
    Ok(Restored {
        binding,
        rules,
        delegation,
    })
}

/// One bodiless call to a host as this owner. Only something that holds this owner's identity accepts
/// it, and only for this call, so it can't pass for anything an agent proves.
pub fn access(device: &Device, host: &str, method: &str, path: &str) -> Result<String, Error> {
    AccessProof::sign(
        &device.key,
        device.identity.id(),
        host,
        method,
        path,
        b"",
        unix_now(),
    )
}

/// Whether a call leaves owner mail at a host, the one call this owner's proof is over a body for.
pub fn leaves_owner_mail(method: &str, path: &str) -> bool {
    method == "POST"
        && path
            .strip_prefix(splint_core::host_api::OWNER_MAIL_PATH)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|agent| !agent.is_empty() && !agent.contains('/'))
}

/// A proof for leaving sealed owner mail at a host again, over the exact bytes sealed before, for
/// what a host couldn't take the first time. The proof made with it has gone stale by then, and only
/// gets the same sealed bytes back in: what's inside counts by the signature it already has.
pub fn leaving_again(
    device: &Device,
    host: &str,
    path: &str,
    body: &[u8],
) -> Result<String, Error> {
    AccessProof::sign(
        &device.key,
        device.identity.id(),
        host,
        "POST",
        path,
        body,
        unix_now(),
    )
}

/// Where what the owner signs for an agent that isn't on this machine is left: the agent's host, and
/// the agent's ID, which commits to the sealing key it's sealed to.
pub struct AtHost {
    pub host: String,
    pub agent: Identity,
}

impl AtHost {
    /// That what's about to be signed is for the agent it'll be sealed to, so a mix-up by whatever
    /// ran this can't leave one agent something its Signet can't open, or that was meant for another.
    pub fn is_of(&self, agent: &SplintId) -> Result<(), Error> {
        if self.agent.id() == agent {
            Ok(())
        } else {
            Err(Error::ProofMismatch)
        }
    }
}

/// Something the owner signed for an agent elsewhere, with what leaves it at the agent's host: the
/// exact body to post, which is the thing signed sealed to the agent, and this owner's proof for
/// posting exactly that.
#[derive(Serialize)]
pub struct ForHost {
    pub signed: String,
    pub body: String,
    pub proof: String,
}

/// What a command hands back for something it signed for an agent: the thing alone, for a Signet
/// beside this device, or with what leaves it at the host of an agent elsewhere.
#[derive(Serialize)]
#[serde(untagged)]
pub enum Handed {
    Beside(String),
    Elsewhere(ForHost),
}

impl Handed {
    pub fn to(
        device: &Device,
        at: Option<&AtHost>,
        kind: OwnerMailKind,
        signed: String,
    ) -> Result<Self, Error> {
        match at {
            None => Ok(Self::Beside(signed)),
            Some(at) => for_host(device, at, kind, signed).map(Self::Elsewhere),
        }
    }
}

/// Seals what was just signed to the agent it's for, and signs the proof its host lets it in by, in the
/// same opening of the sign-in, so it costs no second prompt. The proof says only that this owner
/// left these sealed bytes there: the host can't open them, and nobody else can leave any.
pub fn for_host(
    device: &Device,
    at: &AtHost,
    kind: OwnerMailKind,
    signed: String,
) -> Result<ForHost, Error> {
    let sealed = seal_owner_mail(
        &at.agent,
        &OwnerMail {
            kind,
            signed: signed.clone(),
        },
    )?;
    let body = mail_body(&sealed)?;
    let proof = AccessProof::sign(
        &device.key,
        device.identity.id(),
        &at.host,
        "POST",
        &owner_mail_path(at.agent.id()),
        &body,
        unix_now(),
    )?;
    Ok(ForHost {
        signed,
        body: String::from_utf8(body).map_err(|_| Error::Malformed)?,
        proof,
    })
}

/// A new invitation, for one person to use once.
#[derive(Serialize)]
pub struct Invitation {
    /// Pass this on outside Splint. It holds a private key, so anyone holding it can use it.
    link: String,
    /// Add this to `invites` in the rules, and sign them.
    invite: RulesInvite,
}

pub fn invitation(
    agent: &SplintId,
    address: &str,
    types: Vec<InteractionType>,
    days: u64,
) -> Result<Invitation, Error> {
    let expires_at = unix_now().saturating_add(days.saturating_mul(DAY_SECS));
    let (link, invite) = InviteLink::create(address, agent, types, expires_at)?;
    Ok(Invitation { link, invite })
}

/// What an invited owner needs: the signed redeem, and the inviter's entry for their rules. It names
/// the IDs from the link, so a host answering a lookup with anyone else finds nobody.
#[derive(Serialize)]
pub struct Redeem {
    /// Add this to `contacts` in the rules, and sign them, before handing Signet the proof.
    contact: RulesContact,
    to: String,
    proof: String,
}

pub fn redeem(agent: &SplintId, link: &str, types: Vec<InteractionType>) -> Result<Redeem, Error> {
    let link = InviteLink::parse(link)?;
    let proof = link.redeem_for(agent, unix_now())?;
    Ok(Redeem {
        contact: RulesContact {
            agent: link.agent.clone(),
            address: link.address.clone(),
            label: link.address.clone(),
            status: ContactStatus::Allowed,
            types,
            text: false,
            agree_types: true,
            pinned_by: PinnedBy::Invite,
        },
        to: link.address.clone(),
        proof,
    })
}

/// An owner's claim about their agent, for its Signet to add to its history. It names the head it
/// follows, which that Signet shows, so a claim fits one place.
pub fn change_statement(
    device: &Device,
    agent: &SplintId,
    prev: &str,
    claim: Claim,
) -> Result<String, Error> {
    sign_statement(
        &device.key,
        device.identity.id(),
        agent,
        prev,
        claim,
        unix_now(),
    )
}

/// An owner's yes to a contact's history as far as this exact head, and no further.
pub fn change_acceptance(
    device: &Device,
    agent: &SplintId,
    contact: &SplintId,
    head: &str,
) -> Result<String, Error> {
    VerifiedAcceptance::sign(
        &device.key,
        device.identity.id(),
        agent,
        contact,
        head,
        next_seq(),
        unix_now(),
    )
}

/// Words the person writes for this agent to carry to that contact, on that request or on the next
/// one it opens with them. Signet attaches them, and no agent can.
pub fn person_text(
    device: &Device,
    for_step: PersonTextFor<'_>,
    text: &str,
) -> Result<String, Refused> {
    VerifiedPersonText::sign(
        &device.key,
        device.identity.id(),
        for_step,
        text,
        unix_now(),
    )
}

/// Where the owner gets paid, which their agents' Signets put on their asks to be paid.
pub fn where_paid(device: &Device, places: Vec<Place>) -> Result<String, Refused> {
    VerifiedWherePaid::sign(&device.key, device.identity.id(), places, unix_now())
}

pub fn retirement(
    device: &Device,
    agent: &SplintId,
    reason: RetirementReason,
) -> Result<String, Error> {
    VerifiedRetirement::sign(&device.key, device.identity.id(), agent, reason, unix_now())
}

pub fn approval(
    device: &Device,
    draft: &ApprovalDraft,
    decision: Decision,
    subject: Option<String>,
) -> Result<String, Error> {
    if &draft.owner != device.identity.id() {
        return Err(Error::WrongSigner);
    }
    draft.sign(&device.key, decision, subject, unix_now())
}

/// What's about to be signed, from the typed fields, so an owner sees the terms and not an agent's
/// account of them: who it's with, and the subject that will really be signed. Names come from the
/// rules this device signed, and a party that isn't in them says so. `Debug` escapes control
/// characters, so a subject or a label can't rewrite the terminal.
pub fn describe_approval(
    draft: &ApprovalDraft,
    decision: Decision,
    subject: Option<&str>,
    contacts: Option<&[RulesContact]>,
) -> String {
    let terms = &draft.terms;
    let party = |party: &TermsParty| {
        let name = if party.owner == draft.owner {
            "you".to_owned()
        } else {
            named(party, contacts)
        };
        format!(
            "{name}: agent {:?}, owner {:?}",
            party.agent.as_str(),
            party.owner.as_str()
        )
    };
    format!(
        "signing {decision:?} on {:?} of a {:?}, for your agent {:?}\n\
         request {:?}, version {}\n\
         requester, {}\n\
         recipient, {}\n\
         agreed: {}\n\
         result: {}\n\
         subject {}, note {}",
        draft.operation,
        terms.interaction.as_str(),
        draft.agent.as_str(),
        draft.request.as_str(),
        draft.version,
        party(&terms.requester),
        party(&terms.recipient),
        shown_fields(&terms.agreed),
        shown_fields(&terms.result),
        quoted(subject.or(terms.subject.as_deref())),
        quoted(terms.note.as_deref()),
    )
}

/// Every field by name, in the type's own words. `Debug` keeps a value from rewriting the terminal.
pub(crate) fn shown_fields(fields: &Fields) -> String {
    if fields.is_empty() {
        return "none".to_owned();
    }
    let shown: Vec<String> = fields
        .iter()
        .map(|(name, value)| match value {
            FieldValue::Text(text) => format!("{name:?} {text:?}"),
            _ => shown_number(name, value).unwrap_or_default(),
        })
        .collect();
    shown.join(", ")
}

/// One field of numbers or times, as a prompt and the terminal show it, or `None` for one of words.
pub(crate) fn shown_number(name: &str, value: &FieldValue) -> Option<String> {
    match value {
        FieldValue::Int(number) if looks_like_a_time(*number) => {
            Some(format!("{name:?} {number} ({})", utc_time(*number)))
        }
        FieldValue::Int(number) => Some(format!("{name:?} {number}")),
        FieldValue::Times(times) => {
            let times: Vec<String> = times.iter().map(|time| utc_time(*time)).collect();
            Some(format!("{name:?} {times:?}"))
        }
        FieldValue::Text(_) => None,
    }
}

/// A schema doesn't say a number is a date, so a large one shows both ways for an owner to read.
fn looks_like_a_time(number: u64) -> bool {
    number >= EARLIEST_TIME_SHOWN
}

pub(crate) fn quoted(text: Option<&str>) -> String {
    text.map_or("none".to_owned(), |text| format!("{text:?}"))
}

fn named(party: &TermsParty, contacts: Option<&[RulesContact]>) -> String {
    let Some(contacts) = contacts else {
        return "no rules on this device to name them".to_owned();
    };
    let found = contacts.iter().find(|contact| contact.agent == party.agent);
    match found {
        Some(contact) if contact.status == ContactStatus::Allowed => {
            format!("{:?} from your rules", contact.label)
        }
        Some(contact) => format!("{:?}, BLOCKED in your rules", contact.label),
        None => "NOT IN YOUR RULES".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use splint_core::rules::PinnedBy;

    use super::*;

    const AGENT: &str = "splint1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OWNER: &str = "splint1eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const THEIR_AGENT: &str = "splint1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const THEIR_OWNER: &str = "splint1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const OTHER_AGENT: &str = "splint1cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const OTHER_OWNER: &str = "splint1dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const REQUEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn draft(recipient_agent: &str, recipient_owner: &str) -> ApprovalDraft {
        serde_json::from_value(json!({
            "owner": OWNER,
            "agent": AGENT,
            "operation": "confirm",
            "request": REQUEST,
            "version": 3,
            "prev": REQUEST,
            "latest_expiry": 1_793_836_800,
            "terms": {
                "type": crate::auto::example_id("meeting/1"),
                "requester": {"agent": AGENT, "owner": OWNER},
                "recipient": {"agent": recipient_agent, "owner": recipient_owner},
                "agreed": {"start": 1_793_750_400, "duration_min": 30, "purpose": "intro", "mode": "video"},
                "result": {},
                "subject": "from the draft",
                "note": null,
                "supersedes": null,
            },
        }))
        .unwrap()
    }

    fn contact(status: ContactStatus) -> RulesContact {
        RulesContact {
            agent: serde_json::from_value(json!(THEIR_AGENT)).unwrap(),
            address: "ben~host.example".to_owned(),
            label: "Ben\u{1b}[2J".to_owned(),
            status,
            types: Vec::new(),
            text: false,
            agree_types: false,
            pinned_by: PinnedBy::Owner,
        }
    }

    fn shown(
        draft: &ApprovalDraft,
        subject: Option<&str>,
        contacts: Option<&[RulesContact]>,
    ) -> String {
        describe_approval(draft, Decision::Approve, subject, contacts)
    }

    #[test]
    fn an_owner_sees_who_its_with_and_every_field() {
        let ben = shown(&draft(THEIR_AGENT, THEIR_OWNER), None, None);
        let other = shown(&draft(OTHER_AGENT, OTHER_OWNER), None, None);
        assert_ne!(ben, other);
        for id in [THEIR_AGENT, THEIR_OWNER, AGENT, OWNER, REQUEST] {
            assert!(ben.contains(id), "{id} isn't in {ben}");
        }
        assert!(other.contains(OTHER_AGENT) && other.contains(OTHER_OWNER));
        for field in [
            "meeting/1",
            "duration_min",
            "purpose",
            "intro",
            "mode",
            "video",
        ] {
            assert!(ben.contains(field), "{field} isn't in {ben}");
        }
    }

    #[test]
    fn a_field_cant_rewrite_the_terminal() {
        let fields = Fields::from([("note".to_owned(), FieldValue::Text("a\u{1b}[2J".to_owned()))]);
        assert!(!shown_fields(&fields).contains('\u{1b}'));
    }

    #[test]
    fn a_party_is_named_from_the_owners_own_rules_and_a_stranger_is_called_out() {
        let draft = draft(THEIR_AGENT, THEIR_OWNER);
        let known = [contact(ContactStatus::Allowed)];
        let found = shown(&draft, None, Some(&known));
        assert!(found.contains("from your rules"), "{found}");
        assert!(
            !found.contains('\u{1b}'),
            "a label reached the terminal raw: {found}"
        );

        let blocked = [contact(ContactStatus::Blocked)];
        assert!(shown(&draft, None, Some(&blocked)).contains("BLOCKED"));
        assert!(shown(&draft, None, Some(&[])).contains("NOT IN YOUR RULES"));

        // A contact is one ID, so who it acts for now can change, and the owner sees who that is.
        let moved = super::tests::draft(THEIR_AGENT, OTHER_OWNER);
        let shown = shown(&moved, None, Some(&known));
        assert!(shown.contains("from your rules") && shown.contains(OTHER_OWNER));
    }

    #[test]
    fn a_subject_or_note_cant_rewrite_the_terminal() {
        let mut draft = draft(THEIR_AGENT, THEIR_OWNER);
        "the note\u{1b}[2J\nall clear".clone_into(draft.terms.note.get_or_insert_default());
        let page = shown(&draft, Some("the subject\u{1b}[2K\r\u{202e}"), None);
        assert!(!page.contains('\u{1b}'), "{page}");
        assert!(!page.contains('\u{202e}'), "{page}");
        assert!(!page.contains("\nall clear"), "{page}");
        assert!(!page.contains('\r'), "{page}");
        assert!(
            page.contains("the subject") && page.contains("the note"),
            "{page}"
        );
    }

    #[test]
    fn the_subject_shown_is_the_one_signed() {
        let draft = draft(THEIR_AGENT, THEIR_OWNER);
        let text = shown(&draft, Some("what I typed"), None);
        assert!(
            text.contains("what I typed") && !text.contains("from the draft"),
            "{text}"
        );
        assert!(shown(&draft, None, None).contains("from the draft"));
    }

    #[test]
    fn a_start_reads_as_a_date() {
        assert_eq!(utc_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_time(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(utc_time(1_793_750_400 + 3_660), "2026-11-04 01:01 UTC");
        assert_eq!(utc_time(1_798_761_599), "2026-12-31 23:59 UTC");
        assert!(
            shown(&draft(THEIR_AGENT, THEIR_OWNER), None, None).contains("2026-11-04 00:00 UTC")
        );
    }

    /// Bug caught: a delegation copying only the caps in the owner's rules, which by default name no
    /// type, so its delegate says yes to no meeting and an owner away from their device approves
    /// nothing, while a price still waits for them.
    #[test]
    fn a_delegate_says_yes_to_a_meeting_and_not_to_a_price() {
        use splint_core::delegation::{DelegateKey, VerifiedDelegation};

        let dir = std::env::temp_dir().join(format!("owner-key-delegate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = Device::init(&dir).unwrap();
        let agent: SplintId = serde_json::from_value(json!(AGENT)).unwrap();
        let first = json!({"paused": false, "contacts": [], "invites": [], "limits": {
            "new_requests_per_contact_per_day": 3, "open_requests_per_contact": 3, "open_approvals": 10,
            "new_from_others_per_day": 50, "texts_per_contact_per_day": 20}});
        rules(
            &device,
            &agent,
            serde_json::from_value(first).unwrap(),
            Naming::AsBefore,
        )
        .unwrap();
        let schemas = crate::auto::load_schemas(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/schemas"),
        )
        .unwrap();
        let key = DelegateKey::generate().unwrap();
        let made = delegation(&device, &agent, &key.public_key(), 30, &schemas).unwrap();
        let made = made.delegation.unwrap();
        let delegation = VerifiedDelegation::relayed(&made, &device.identity, &agent).unwrap();
        let owner = device.identity.id().to_string();
        let ask = |kind: &str, result: serde_json::Value| -> ApprovalDraft {
            serde_json::from_value(json!({
                "owner": owner, "agent": AGENT, "operation": "confirm", "request": REQUEST,
                "version": 1, "prev": REQUEST, "latest_expiry": unix_now() + 3600,
                "terms": {"type": kind, "requester": {"agent": AGENT, "owner": owner},
                    "recipient": {"agent": THEIR_AGENT, "owner": THEIR_OWNER},
                    "agreed": {}, "result": result, "subject": null, "note": null, "supersedes": null}
            }))
            .unwrap()
        };
        let schema = |kind: &str| {
            schemas
                .get(&serde_json::from_value(json!(kind)).unwrap())
                .unwrap()
                .clone()
        };
        let (meeting, quote) = (
            crate::auto::example_id("meeting/1"),
            crate::auto::example_id("quote/1"),
        );
        let meeting = delegation.approve(
            &key,
            &ask(&meeting, json!({})),
            &schema(&meeting),
            unix_now(),
        );
        assert!(meeting.is_ok(), "{meeting:?}");
        let priced = ask(&quote, json!({"amount_minor": 5000, "valid_days": 14}));
        assert!(
            delegation
                .approve(&key, &priced, &schema(&quote), unix_now())
                .is_err()
        );
    }
}

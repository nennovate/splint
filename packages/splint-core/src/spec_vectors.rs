//! Runs the shared vectors in `spec/vectors/` against this crate.
//!
//! The vectors are written by a separate tool from the spec's formats, so a passing run shows this
//! code and the spec agree. A `pending` vector is for code that doesn't exist yet: until it does,
//! its signatures are checked here, so that it will fail for the reason it states when it runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::RecoveryRule;
use crate::asks::VerifiedAsk;
use crate::changes::{
    Against, ChangeAnswer, ChangeResponse, ChangeRules, HistoryDocument, VerifiedAcceptance,
    VerifiedHistory,
};
use crate::contact_invites::{ContactCard, PendingContact, VerifiedInvite};
use crate::controls::ControlsDraft;
use crate::delegation::{Delegated, DelegationDraft, VerifiedDelegation};
use crate::grants::{Call, GrantId, Record, Refusal, VerifiedGrant, VerifiedRevocation};
use crate::host_id::PublishedHost;
use crate::invites::VerifiedRedeem;
use crate::outbound::check_text;
use crate::owner_agents::VerifiedOwnerAgents;
use crate::owner_call::{SealedCall, open_owner_call, open_owner_mail};
use crate::owner_session::{OwnerReader, ReadCall, VerifiedOwnerSession};
use crate::pairing::{PairingCode, VerifiedPairing};
use crate::recovery_code::RecoveryCode;
use crate::requests::{
    Chain, Decision, InteractionType, Outcome, Parties, Party, Refused, Schema, Schemas,
    VerifiedApproval, examples,
};
use crate::rules::{
    Admission, Opening, RulesInvite, Sender, VerifiedRules, admit_unsigned, unsigned,
};
use crate::{
    AccessProof, DeliveryFailure, DeliveryProof, Error, Identity, MessageId, PublicKey, SealingKey,
    SigningKey, SplintId, VerifiedBinding, VerifiedEnvelope, VerifiedRegistration, VerifiedRelease,
    VerifiedRetirement, claimed_agent, claimed_sender, jws, parse_address,
};

/// Every check this crate can run. A pending vector naming one of these has code waiting for it, so
/// the run fails until the vector is marked checked.
const CHECKS: [&str; 63] = [
    "host_id.verify",
    "host_id.follows",
    "ask.verify",
    "ask.answer",
    "move.reply",
    "touch.code",
    "type.id",
    "type.propose",
    "recovery_code.backup",
    "carried_approval.verify",
    "prf.sealing_key",
    "acceptance.verify",
    "owner_access.verify",
    "owner_agents.open",
    "owner_agents.handle",
    "owner_call.open",
    "owner_mail.open",
    "owner_agents.verify",
    "reading_key.open",
    "owner_session.verify",
    "controls.prepare",
    "pairing.code",
    "pairing.opener",
    "pairing.verify",
    "owner_view.verify",
    "card.parse",
    "access_proof.verify",
    "address.parse",
    "admit.check",
    "approval.verify",
    "binding.replace",
    "binding.verify",
    "delegated_approval.verify",
    "delegation.verify",
    "delivery_failure.parse",
    "protocol.choose",
    "delivery_proof.verify",
    "envelope.verify",
    "grant.check",
    "history.against",
    "history.respond",
    "history.verify",
    "identity.check_backup",
    "identity.keys",
    "identity.newest",
    "identity.newest_keys",
    "identity.parse",
    "identity.read",
    "invite.pending",
    "invite.redeem",
    "invite.verify",
    "outbound.check",
    "outcome.verify",
    "registration.verify",
    "release.verify",
    "request.person_text",
    "request.walk",
    "guest.walk",
    "guest.outcome",
    "guest_identity.parse",
    "retirement.verify",
    "revocation.verify",
    "rules.verify",
];

/// Checks nothing in Rust or the owner page makes any more, as nothing makes a pairing code or derives
/// a passkey's lock since Nenye's decision of 2026-11-21. The Go verifier still runs their vectors, as
/// their formats stay specified until they're removed.
const GO_ONLY_CHECKS: [&str; 2] = ["pairing.answer", "prf.lock_key"];

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct KeysFile {
    keys: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    status: String,
    case: String,
    check: String,
    input: Value,
    expect: Value,
    issue: Option<u32>,
    #[serde(default)]
    signed: Vec<Signed>,
}

#[derive(Deserialize)]
struct Signed {
    at: String,
    typ: String,
    by: String,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn all_vectors() -> Vec<(String, Vector)> {
    let mut all = Vec::new();
    for entry in fs::read_dir(vectors_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let is_vector_file = path.extension().is_some_and(|ext| ext == "json")
            && !name.starts_with("keys")
            && !name.starts_with("manifest");
        if is_vector_file {
            let file: VectorFile = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            all.extend(
                file.vectors
                    .into_iter()
                    .map(|vector| (name.clone(), vector)),
            );
        }
    }
    assert!(!all.is_empty(), "no vectors found");
    all
}

fn text<'a>(input: &'a Value, field: &str) -> &'a str {
    input[field].as_str().unwrap()
}

fn number(input: &Value, field: &str) -> u64 {
    input[field].as_u64().unwrap()
}

fn refused(error: &Error) -> Value {
    let reason = match error {
        Error::Malformed | Error::OldAddressForm => "malformed",
        Error::BadSignature => "bad_signature",
        Error::WrongSigner => "wrong_signer",
        Error::Expired => "expired",
        Error::FromTheFuture => "from_the_future",
        Error::Stale => "stale",
        Error::ProofMismatch => "proof_mismatch",
        Error::WrongRedeemer => "wrong_redeemer",
        Error::AlreadyUsed => "used",
        Error::Forked => "forked",
        Error::CantOpen => "cant_open",
        Error::Crypto | Error::KeyStorage | Error::NotApproved => "local_failure",
    };
    json!({"ok": false, "reason": reason})
}

fn outcome(result: Result<Value, Error>) -> Value {
    result.unwrap_or_else(|error| refused(&error))
}

fn check_identity(input: &Value) -> Result<Value, Error> {
    let identity = Identity::parse(&jws::decode(text(input, "raw"))?)?;
    Ok(json!({"ok": true, "id": identity.id()}))
}

fn check_identity_read(input: &Value) -> Result<Value, Error> {
    let identity = Identity::from_encoded(text(input, "identity"))?;
    Ok(json!({
        "ok": true,
        "id": identity.id(),
        "key": identity.sole_key()?.encoded(),
        "recoveries": identity.recoveries(),
    }))
}

fn check_identity_newest(input: &Value) -> Result<Value, Error> {
    let pinned = Identity::from_encoded(text(input, "pinned"))?;
    let claimed = Identity::from_encoded(text(input, "claimed"))?;
    let newest = pinned.newest_of(&claimed)?;
    Ok(json!({"ok": true, "key": newest.sole_key()?.encoded()}))
}

/// The keys an owner's ID has now, in order, as points.
fn points(identity: &Identity) -> Vec<String> {
    identity
        .keys()
        .iter()
        .map(|key| key.point().encoded())
        .collect()
}

fn check_identity_keys(input: &Value) -> Result<Value, Error> {
    let identity = Identity::from_encoded(text(input, "identity"))?;
    Ok(json!({
        "ok": true,
        "id": identity.id(),
        "keys": points(&identity),
        "recoveries": identity.recoveries(),
        "statements": identity.statements(),
    }))
}

fn check_identity_newest_keys(input: &Value) -> Result<Value, Error> {
    let pinned = Identity::from_encoded(text(input, "pinned"))?;
    let claimed = Identity::from_encoded(text(input, "claimed"))?;
    Ok(json!({"ok": true, "keys": points(&pinned.newest_of(&claimed)?)}))
}

fn history_of(document: &Value) -> Result<VerifiedHistory, Error> {
    let document: HistoryDocument =
        serde_json::from_value(document.clone()).map_err(|_| Error::Malformed)?;
    VerifiedHistory::verify(document)
}

fn check_history(input: &Value) -> Result<Value, Error> {
    let history = history_of(&input["history"])?;
    let (kinds, proofs): (Vec<_>, Vec<_>) = history
        .changes()
        .iter()
        .map(|change| (change.kind, change.proof))
        .unzip();
    Ok(json!({
        "ok": true,
        "head": history.head(),
        "kinds": kinds,
        "proofs": proofs,
        "owner": history.owner(),
        "address": history.address(),
    }))
}

fn check_history_against(input: &Value) -> Result<Value, Error> {
    let against = history_of(&input["seen"])?.against(&history_of(&input["new"])?);
    let word = match against {
        Against::Same => "same",
        Against::Extends => "extends",
        Against::Behind => "behind",
        Against::Rewrites => "rewrites",
    };
    Ok(json!({"ok": true, "against": word}))
}

fn check_history_response(input: &Value) -> Result<Value, Error> {
    let history = history_of(&input["history"])?;
    let rules: ChangeRules =
        serde_json::from_value(input["rules"].clone()).map_err(|_| Error::Malformed)?;
    let accepted = text(input, "accepted");
    // A reader's own record of when it first saw each sign-in, and its clock, turn on the 48-hour guard.
    let asked = match input.get("now") {
        Some(_) => {
            let mut seen: crate::contact_view::SignInsSeen =
                serde_json::from_value(input["sign_ins_seen"].clone())
                    .map_err(|_| Error::Malformed)?;
            let since = history.since(accepted).unwrap_or_default().to_vec();
            seen.asked_as_new_owner(&history, &since, number(input, "now"))
        }
        None => Vec::new(),
    };
    let word = match rules.answer_treating_as_owner(&history, accepted, &asked) {
        ChangeAnswer::Rewritten => "rewritten",
        ChangeAnswer::Stopped => "stopped",
        ChangeAnswer::Respond(ChangeResponse::Continue) => "continue",
        ChangeAnswer::Respond(ChangeResponse::Ask) => "ask",
        ChangeAnswer::Respond(ChangeResponse::Hold) => "hold",
    };
    Ok(json!({"ok": true, "response": word}))
}

fn check_acceptance(input: &Value) -> Result<Value, Error> {
    let agent: SplintId =
        serde_json::from_value(input["agent"].clone()).map_err(|_| Error::Malformed)?;
    let acceptance = VerifiedAcceptance::verify(
        text(input, "acceptance"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        &agent,
    )?;
    Ok(json!({"ok": true, "contact": acceptance.contact(), "head": acceptance.head()}))
}

fn check_backup(input: &Value) -> Result<Value, Error> {
    Identity::from_encoded(text(input, "identity"))?
        .check_backup(&PublicKey::from_encoded(text(input, "backup_key"))?)?;
    Ok(json!({"ok": true}))
}

fn check_binding(input: &Value) -> Result<Value, Error> {
    VerifiedBinding::verify_for(
        text(input, "binding"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        &Identity::from_encoded(text(input, "agent_identity"))?,
        text(input, "address"),
    )?;
    Ok(json!({"ok": true}))
}

fn check_binding_replace(input: &Value) -> Result<Value, Error> {
    VerifiedBinding::verify(
        text(input, "binding"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        &Identity::from_encoded(text(input, "agent_identity"))?,
    )?
    .may_replace(
        &Identity::from_encoded(text(input, "current_owner_identity"))?,
        number(input, "current_seq"),
    )?;
    Ok(json!({"ok": true}))
}

fn check_release(input: &Value) -> Result<Value, Error> {
    let agent: SplintId = serde_json::from_value(input["agent"].clone()).unwrap();
    let release = VerifiedRelease::verify(
        text(input, "release"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        &agent,
    )?;
    Ok(json!({"ok": true, "to": release.to()}))
}

fn check_registration(input: &Value) -> Result<Value, Error> {
    let registration = VerifiedRegistration::verify(
        text(input, "proof"),
        &jws::decode(text(input, "body"))?,
        text(input, "host"),
        number(input, "now"),
    )?;
    if !registration.paid_with(text(input, "signup_code")) {
        return Err(Error::ProofMismatch);
    }
    Ok(json!({"ok": true, "name": registration.name(), "agent": registration.agent().id()}))
}

fn check_retirement(input: &Value) -> Result<Value, Error> {
    let retirement = VerifiedRetirement::verify(
        text(input, "retirement"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
    )?;
    Ok(json!({"ok": true, "agent": retirement.agent()}))
}

/// What an owner's signature on its own says: which word, and which step Signet sends for it.
fn check_approval(input: &Value) -> Value {
    let owner = Identity::from_encoded(text(input, "owner_identity")).unwrap();
    match VerifiedApproval::verify(text(input, "approval"), &owner) {
        Ok(approval) if approval.has_expired(number(input, "now")) => refused(&Error::Expired),
        Ok(approval) => {
            let (decision, emits) = match approval.decision() {
                Decision::Approve => ("approve", "confirm"),
                Decision::Deny => ("deny", "decline"),
            };
            json!({"ok": true, "decision": decision, "emits": emits})
        }
        Err(Refused::ApprovalBadSignature) => refused(&Error::BadSignature),
        Err(_) => refused(&Error::Malformed),
    }
}

fn refused_grant(refusal: Refusal) -> Value {
    json!({"ok": false, "reason": refusal.to_string()})
}

fn check_grant(input: &Value) -> Value {
    let owner = Identity::from_encoded(text(input, "owner_identity")).unwrap();
    let now = number(input, "now");
    let grant = match VerifiedGrant::verify(text(input, "grant"), &owner, now) {
        Ok(grant) => grant,
        Err(refusal) => return refused_grant(refusal),
    };
    let revoked: Vec<GrantId> = serde_json::from_value(input["revoked"].clone()).unwrap();
    let record = Record {
        revoked: revoked.contains(grant.id()),
        calls_this_hour: u32::try_from(number(input, "calls_this_hour")).unwrap(),
    };
    let call = Call {
        identity: text(input, "agent_identity"),
        proof: text(input, "proof"),
        resource: text(input, "resource"),
        operation: text(input, "operation"),
        method: text(input, "method"),
        path: text(input, "path"),
        body: text(input, "body").as_bytes(),
        now,
    };
    match grant.check_call(&call, record) {
        Ok(granted) => json!({
            "ok": true,
            "grant": granted.grant(),
            "holder": granted.holder(),
            "operation": granted.operation(),
        }),
        Err(refusal) => refused_grant(refusal),
    }
}

fn check_revocation(input: &Value) -> Value {
    let owner = Identity::from_encoded(text(input, "owner_identity")).unwrap();
    match VerifiedRevocation::verify(text(input, "revocation"), &owner) {
        Ok(revocation) => json!({"ok": true, "revoked": revocation.grant()}),
        Err(refusal) => refused_grant(refusal),
    }
}

fn check_rules(input: &Value) -> Result<Value, Error> {
    let rules = VerifiedRules::verify(
        text(input, "rules"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        number(input, "highest_seq_seen"),
        number(input, "now"),
    )?;
    Ok(json!({"ok": true, "seq": rules.seq()}))
}

fn check_delegation(input: &Value) -> Result<Value, Error> {
    let delegation = VerifiedDelegation::verify(
        text(input, "delegation"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        &Identity::from_encoded(text(input, "agent_identity"))?,
        number(input, "newest_seq_seen"),
        number(input, "now"),
    )?;
    let may: Vec<Delegated> = [Delegated::ApproveWithinCaps, Delegated::RenewRules]
        .into_iter()
        .filter(|what| delegation.may(*what))
        .collect();
    Ok(json!({"ok": true, "seq": delegation.seq(), "may": may}))
}

/// A delegate's yes, as a reader of a step takes one: against the caps of the delegation it carries.
/// Read back, as in a chain or an outcome, it may date from before a recovery of the owner.
fn check_delegated_approval(input: &Value) -> Value {
    let owner = Identity::from_encoded(text(input, "owner_identity")).unwrap();
    let agent = Identity::from_encoded(text(input, "agent_identity")).unwrap();
    let interaction: InteractionType = serde_json::from_value(input["type"].clone()).unwrap();
    let schemas = examples();
    let schema = schemas.get(&interaction).unwrap();
    let compact = text(input, "approval");
    let read_back = input["read_back"].as_bool().unwrap_or(false);
    let verified = if read_back {
        VerifiedApproval::read_back_carried(compact, &owner, &agent, schema)
    } else {
        VerifiedApproval::verify_carried(compact, &owner, &agent, schema)
    };
    match verified {
        Ok(approval) => {
            assert!(approval.by_delegate());
            json!({"ok": true, "decision": "approve", "emits": "confirm"})
        }
        Err(refused) => json!({"ok": false, "reason": refused}),
    }
}

fn check_carried_approval(input: &Value) -> Value {
    let owner = Identity::from_encoded(text(input, "owner_identity")).unwrap();
    let agent = Identity::from_encoded(text(input, "agent_identity")).unwrap();
    let interaction: InteractionType = serde_json::from_value(input["type"].clone()).unwrap();
    let schemas = examples();
    let schema = schemas.get(&interaction).unwrap();
    let compact = text(input, "approval");
    let verified = if input["read_back"].as_bool().unwrap_or(false) {
        VerifiedApproval::read_back_carried(compact, &owner, &agent, schema)
    } else {
        VerifiedApproval::verify_carried(compact, &owner, &agent, schema)
    };
    match verified {
        Ok(approval) => {
            let (decision, emits) = match approval.decision() {
                Decision::Approve => ("approve", "confirm"),
                Decision::Deny => ("deny", "decline"),
            };
            json!({"ok": true, "decision": decision, "emits": emits, "by_delegate": approval.by_delegate()})
        }
        Err(refused) => json!({"ok": false, "reason": refused}),
    }
}

fn check_admit(input: &Value) -> Result<Value, Error> {
    let agent: SplintId = serde_json::from_value(input["sender"].clone()).unwrap();
    let owner: Option<SplintId> = serde_json::from_value(input["sender_owner"].clone()).unwrap();
    let host = input["sender_host"].as_str();
    let sender = Sender {
        agent: &agent,
        owner: owner.as_ref(),
        host,
        met: input["met"].as_bool().unwrap(),
        unconfirmed: false,
        agreed: input["agreed"].as_bool().unwrap_or(false),
    };
    let shown = json!({"deliver": false, "shown_to_sender": "quarantined"});
    // Core's plain conversation names no type.
    let interaction: InteractionType = match &input["type"] {
        Value::Null => InteractionType::conversation(),
        named => serde_json::from_value(named.clone()).unwrap(),
    };
    let proposes: Option<InteractionType> =
        serde_json::from_value(input["proposes"].clone()).unwrap();
    let opening = Opening {
        interaction: &interaction,
        proposes: proposes.as_ref(),
        seen_proposed: input["seen_proposed"].as_bool().unwrap_or(false),
    };
    let now = number(input, "now");
    Ok(
        match admit_unsigned(
            input["rules"].clone(),
            &sender,
            &opening,
            input["redeemed_invite"].as_str(),
            now,
        )? {
            // Someone let in still has to be let in for this type.
            (Admission::Deliver, true) => json!({"deliver": true}),
            (Admission::Deliver | Admission::Wait | Admission::Quarantine | Admission::Drop, _) => {
                shown
            }
        },
    )
}

/// A type's ID, which every reader works out from its schema's one encoding, however it's written.
fn check_type_id(input: &Value) -> Value {
    let document = serde_json::to_vec(&input["schema"]).unwrap();
    match Schema::parse(&document) {
        Ok(schema) => {
            json!({"ok": true, "type": schema.name().as_str(), "one_encoding": schema.encoding()})
        }
        Err(_) => json!({"ok": false, "reason": "malformed"}),
    }
}

/// What core holds a proposed schema to, whoever proposes it.
fn check_type_propose(input: &Value) -> Value {
    let document = serde_json::to_vec(&input["schema"]).unwrap();
    match Schema::parse(&document).map_err(|_| Refused::Malformed) {
        Ok(schema) => match schema.check_proposal() {
            Ok(()) => json!({"ok": true}),
            Err(refused) => json!({"ok": false, "reason": refused}),
        },
        Err(refused) => json!({"ok": false, "reason": refused}),
    }
}

fn check_outbound(input: &Value) -> Result<Value, Error> {
    let agent: SplintId = serde_json::from_value(input["peer"].clone()).unwrap();
    let owner: Option<SplintId> = serde_json::from_value(input["peer_owner"].clone()).unwrap();
    let peer = Sender {
        agent: &agent,
        owner: owner.as_ref(),
        host: input["peer_host"].as_str(),
        met: false,
        unconfirmed: false,
        agreed: input["agreed"].as_bool().unwrap_or(false),
    };
    let rules = unsigned(input["rules"].clone())?;
    let texts_today = u32::try_from(number(input, "texts_today")).unwrap();
    Ok(
        match check_text(
            &rules,
            &peer,
            text(input, "body"),
            texts_today,
            number(input, "now"),
        ) {
            Ok(()) => json!({"ok": true}),
            Err(refused) => json!({"ok": false, "reason": refused.to_string()}),
        },
    )
}

fn check_invite_redeem(input: &Value) -> Result<Value, Error> {
    let invite = RulesInvite {
        id: text(input, "invite_id").to_owned(),
        key: text(input, "invite_key").to_owned(),
        types: vec![crate::requests::example("meeting/1")],
        expires_at: number(input, "invite_expires_at"),
    };
    let recipient: SplintId = serde_json::from_value(input["recipient"].clone()).unwrap();
    let sender = Identity::from_encoded(text(input, "sender_identity"))?;
    let used = input["used"].as_bool().unwrap();
    let redeem = VerifiedRedeem::verify(
        text(input, "redeem"),
        &invite,
        &recipient,
        &sender,
        used,
        number(input, "now"),
    )?;
    Ok(json!({"ok": true, "admit": redeem.redeemer()}))
}

/// The code a sign-in's prompt shows over the objects one touch signs.
fn check_touch_code(input: &Value) -> Value {
    let inputs: Vec<&str> = input["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|one| one.as_str().unwrap())
        .collect();
    json!({"ok": true, "code": crate::prepared::touch_code_of(inputs)})
}

fn check_ask(input: &Value) -> Result<Value, Error> {
    let agent = Identity::from_encoded(text(input, "agent_identity"))?;
    let ask = VerifiedAsk::verify(text(input, "ask"), &agent, number(input, "now"))?;
    Ok(json!({"ok": true, "id": ask.id(), "changes": ask.changes().len()}))
}

fn check_ask_answer(input: &Value) -> Result<Value, Error> {
    let owner: SplintId = serde_json::from_value(input["owner"].clone()).unwrap();
    if !owner.is_well_formed() {
        return Err(Error::Malformed);
    }
    let ask = text(input, "ask_id");
    crate::check_ask_mac(ask, &owner, text(input, "mac"))?;
    Ok(json!({"ok": true, "kept_at": crate::ask_kept_at(ask)?}))
}

fn check_move_reply(input: &Value) -> Result<Value, Error> {
    let agent = Identity::from_encoded(text(input, "agent_identity"))?;
    let owner: SplintId = serde_json::from_value(input["owner"].clone()).unwrap();
    let reply = crate::MoveReply::decode(text(input, "answer"))?;
    let address = reply.check(&agent, &owner)?;
    if parse_address(&address)?.1 != text(input, "domain") {
        return Err(Error::ProofMismatch);
    }
    Ok(json!({"ok": true, "address": address}))
}

fn check_invite_verify(input: &Value) -> Result<Value, Error> {
    let inviter = Identity::from_encoded(text(input, "inviter_identity"))?;
    let invitee: SplintId = serde_json::from_value(input["invitee"].clone()).unwrap();
    let invite = VerifiedInvite::verify(
        text(input, "invite"),
        &inviter,
        &invitee,
        number(input, "now"),
    )?;
    Ok(json!({"ok": true, "id": invite.id()}))
}

fn check_invite_pending(input: &Value) -> Result<Value, Error> {
    let record = PendingContact {
        invite: text(input, "invite").to_owned(),
        acceptance: text(input, "acceptance").to_owned(),
        inviter_identity: text(input, "inviter_identity").to_owned(),
        invitee_identity: text(input, "invitee_identity").to_owned(),
        inviter_owner_identity: text(input, "inviter_owner_identity").to_owned(),
        inviter_binding: text(input, "inviter_binding").to_owned(),
        invitee_owner_identity: text(input, "invitee_owner_identity").to_owned(),
        invitee_binding: text(input, "invitee_binding").to_owned(),
    };
    let own: SplintId = serde_json::from_value(input["own"].clone()).unwrap();
    let new = record.verify(&own)?;
    Ok(
        json!({"ok": true, "contact": new.agent, "address": new.address, "invited_by_us": new.invited_by_us}),
    )
}

fn check_card(input: &Value) -> Result<Value, Error> {
    let card = ContactCard::parse(text(input, "card"))?;
    Ok(json!({"ok": true, "address": card.address, "agent": card.agent}))
}

fn check_owner_session(input: &Value) -> Result<Value, Error> {
    let session = VerifiedOwnerSession::verify(
        text(input, "session"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        text(input, "host"),
        number(input, "now"),
    )?;
    Ok(json!({
        "ok": true,
        "owner": session.owner(),
        "key": session.key().encoded(),
        "expires_at": session.expires_at(),
    }))
}

fn check_owner_access(input: &Value) -> Result<Value, Error> {
    let body = jws::decode(text(input, "body"))?;
    let reader = OwnerReader::by_session(
        text(input, "session"),
        text(input, "proof"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        &ReadCall {
            host: text(input, "host"),
            method: text(input, "method"),
            path: text(input, "path"),
            body: &body,
            now: number(input, "now"),
        },
    )?;
    Ok(json!({"ok": true, "owner": reader.owner()}))
}

fn check_owner_agents(input: &Value) -> Result<Value, Error> {
    let list = VerifiedOwnerAgents::verify(
        text(input, "list"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        text(input, "host"),
        number(input, "now"),
    )?;
    Ok(json!({"ok": true, "seq": list.seq(), "handle": list.handle()}))
}

fn check_owner_agents_open(input: &Value) -> Result<Value, Error> {
    let owner = Identity::from_encoded(text(input, "owner_identity"))?;
    let list = VerifiedOwnerAgents::verify(
        text(input, "list"),
        &owner,
        text(input, "host"),
        number(input, "now"),
    )?;
    let scalar: [u8; 32] = hex_bytes(text(input, "sealing")).try_into().unwrap();
    let sealing = SealingKey::from_scalar_of(&SigningKey::from_scalar(&scalar)?)?;
    let agents = list.open(&sealing, &owner)?;
    Ok(json!({"ok": true, "agents": serde_json::to_value(agents).unwrap()}))
}

fn check_owner_list_handle(input: &Value) -> Result<Value, Error> {
    let backup = PublicKey::from_encoded(text(input, "backup"))?;
    Ok(json!({"ok": true, "handle": crate::owner_agents::recovery_handle(&backup)}))
}

fn check_owner_call_open(input: &Value) -> Result<Value, Error> {
    let scalar: [u8; 32] = hex_bytes(text(input, "sealing")).try_into().unwrap();
    let sealing = SealingKey::from_scalar_of(&SigningKey::from_scalar(&scalar)?)?;
    let agent: SplintId = serde_json::from_value(input["agent"].clone()).unwrap();
    let body = open_owner_call(
        &sealing,
        &agent,
        text(input, "method"),
        text(input, "path"),
        text(input, "call").as_bytes(),
    )?;
    Ok(json!({"ok": true, "body": String::from_utf8(body).unwrap()}))
}

/// As a Signet opens what its host kept for it: with no method or path given, as owner mail is bound
/// to the one call that leaves it.
fn check_owner_mail_open(input: &Value) -> Result<Value, Error> {
    let scalar: [u8; 32] = hex_bytes(text(input, "sealing")).try_into().unwrap();
    let sealing = SealingKey::from_scalar_of(&SigningKey::from_scalar(&scalar)?)?;
    let agent: SplintId = serde_json::from_value(input["agent"].clone()).unwrap();
    let left: SealedCall =
        serde_json::from_str(text(input, "mail")).map_err(|_| Error::Malformed)?;
    let mail = open_owner_mail(&sealing, &agent, &left.sealed)?;
    Ok(json!({"ok": true, "kind": mail.kind, "signed": mail.signed}))
}

fn check_reading_key_open(input: &Value) -> Result<Value, Error> {
    let owner = Identity::from_encoded(text(input, "owner_identity"))?;
    let copy = crate::reading_key::ReadingKeyCopy::read(text(input, "copy"), &owner)?;
    let scalar: [u8; 32] = hex_bytes(text(input, "lock")).try_into().unwrap();
    let lock = SealingKey::from_scalar_of(&SigningKey::from_scalar(&scalar)?)?;
    let reading = copy.open(&lock, &owner)?;
    Ok(json!({"ok": true, "seal": reading.public_key().encoded()}))
}

fn check_recovery_code(input: &Value) -> Result<Value, Error> {
    let code = RecoveryCode::parse(text(input, "code"))?;
    if let Some(bytes) = input.get("bytes").and_then(Value::as_str) {
        let shown = text(input, "code");
        // The code as a page shows it, for the vectors that give it as shown.
        if !shown.contains(' ') {
            assert_eq!(code.spelled(), shown, "{bytes}");
        }
    }
    let backup = code.backup_key()?.public_key();
    let RecoveryRule::BackupKey { commitment } = RecoveryRule::backup_key(&backup) else {
        return Err(Error::Malformed);
    };
    Ok(json!({"ok": true, "backup": backup.encoded(), "commitment": commitment}))
}

fn hex_bytes(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .chars()
        .map(|digit| u8::try_from(digit.to_digit(16).unwrap()).unwrap())
        .collect();
    digits
        .chunks(2)
        .map(|pair| pair.first().unwrap() * 16 + pair.get(1).unwrap())
        .collect()
}

fn check_prf_sealing(input: &Value) -> Result<Value, Error> {
    let key = SealingKey::from_prf(&hex_bytes(text(input, "prf")))?;
    Ok(json!({"ok": true, "seal": key.public_key().encoded()}))
}

fn check_pairing_code(input: &Value) -> Result<Value, Error> {
    let code = PairingCode::parse(text(input, "code"))?;
    Ok(json!({"ok": true, "host": code.host(), "id": code.id(), "owner": code.owner()}))
}

fn check_pairing(input: &Value) -> Result<Value, Error> {
    let pairing = VerifiedPairing::verify(
        text(input, "pairing"),
        text(input, "session"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        text(input, "host"),
        number(input, "now"),
    )?;
    Ok(json!({"ok": true, "id": pairing.id(), "expires_at": pairing.expires_at()}))
}

fn check_pairing_opener(input: &Value) -> Result<Value, Error> {
    let pairing = VerifiedPairing::verify_for_agent(
        text(input, "pairing"),
        text(input, "session"),
        &Identity::from_encoded(text(input, "owner_identity"))?,
        &PairingCode::parse(text(input, "code"))?,
        number(input, "now"),
    )?;
    Ok(json!({"ok": true, "owner": pairing.owner()}))
}

fn check_owner_view(input: &Value) -> Result<Value, Error> {
    let view = crate::owner_view::VerifiedOwnerView::verify(
        text(input, "view"),
        &Identity::from_encoded(text(input, "agent_identity"))?,
        &serde_json::from_value::<SplintId>(input["owner"].clone()).unwrap(),
        number(input, "now"),
    )?;
    Ok(json!({"ok": true, "issued_at": view.issued_at(), "view": view.into_view()}))
}

fn check_controls(input: &Value) -> Result<Value, Error> {
    let delegation = &input["delegation"];
    let delegation = (!delegation.is_null())
        .then(|| -> Result<DelegationDraft, Error> {
            Ok(DelegationDraft {
                delegate: PublicKey::from_encoded(text(delegation, "delegate"))?,
                may: serde_json::from_value(delegation["may"].clone()).unwrap(),
                level: serde_json::from_value(delegation["level"].clone()).unwrap(),
                caps: serde_json::from_value(delegation["caps"].clone()).unwrap(),
                actions_per_day: u32::try_from(number(delegation, "actions_per_day")).unwrap(),
                lasts_secs: number(delegation, "lasts_secs"),
            })
        })
        .transpose()?;
    let owner = Identity::from_encoded(text(input, "owner_identity"))?;
    let prepared = ControlsDraft {
        agent: Identity::from_encoded(text(input, "agent_identity"))?,
        address: text(input, "address").to_owned(),
        backup: PublicKey::from_encoded(text(input, "backup"))?,
        rules: serde_json::from_value(input["rules"].clone()).unwrap(),
        delegation,
        seq: number(input, "seq"),
        now: number(input, "now"),
    }
    .prepare(&owner)?;
    let challenge = owner
        .passkey_rp()
        .map(|_| prepared.challenge().map(|made| made.challenge().to_owned()))
        .transpose()?;
    Ok(json!({
        "ok": true,
        "inputs": prepared.owner_inputs(),
        "vouch": prepared.vouch_input(),
        "commitment": prepared.commitment(),
        "challenge": challenge,
    }))
}

fn check_envelope(input: &Value) -> Result<Value, Error> {
    let compact = text(input, "compact");
    let sender = Identity::from_encoded(text(input, "sender_identity"))?;
    let envelope = VerifiedEnvelope::verify(compact, &sender, number(input, "now"))?;
    assert_eq!(&claimed_sender(compact)?, envelope.sender());
    Ok(json!({
        "ok": true,
        "id": envelope.id(),
        "sender": envelope.sender(),
        "recipient": envelope.recipient(),
        "body": envelope.body(),
        "created_at": envelope.created_at(),
        "expires_at": envelope.expires_at(),
    }))
}

fn check_access_proof(input: &Value) -> Result<Value, Error> {
    let compact = text(input, "compact");
    AccessProof::verify(
        compact,
        &Identity::from_encoded(text(input, "identity"))?,
        text(input, "host"),
        text(input, "method"),
        text(input, "path"),
        &jws::decode(text(input, "body"))?,
        number(input, "now"),
    )?;
    Ok(json!({"ok": true, "agent": claimed_agent(compact)?}))
}

fn check_delivery_proof(input: &Value) -> Result<Value, Error> {
    let message: MessageId = serde_json::from_value(input["message"].clone()).unwrap();
    DeliveryProof::verify(
        text(input, "compact"),
        &PublicKey::from_encoded(text(input, "host_key"))?,
        &message,
        text(input, "from_host"),
        text(input, "to_host"),
        number(input, "now"),
    )?;
    Ok(json!({"ok": true}))
}

fn published_host(input: &Value) -> Result<PublishedHost, Error> {
    PublishedHost::verify(
        text(input, "domain"),
        &PublicKey::from_encoded(text(input, "key"))?,
        text(input, "identity"),
        text(input, "proof"),
    )
}

fn check_host_id(input: &Value) -> Result<Value, Error> {
    let host = published_host(input)?;
    Ok(json!({"ok": true, "id": host.identity().id()}))
}

fn check_host_id_follows(input: &Value) -> Result<Value, Error> {
    let host = published_host(input)?;
    let follows = match input.get("held_identity").and_then(Value::as_str) {
        Some(held) => host.follows(&Identity::from_encoded(held)?),
        None => host.follows_bare(&PublicKey::from_encoded(text(input, "held_key"))?),
    };
    Ok(json!({"ok": true, "follows": follows}))
}

fn check_address(input: &Value) -> Result<Value, Error> {
    let (name, domain) = parse_address(text(input, "address"))?;
    Ok(json!({"ok": true, "name": name, "domain": domain}))
}

fn check_delivery_failure(input: &Value) -> Result<Value, Error> {
    serde_json::from_value::<DeliveryFailure>(input["word"].clone())
        .map(|_| json!({"ok": true}))
        .map_err(|_| Error::Malformed)
}

fn check_protocol_choose(input: &Value) -> Result<Value, Error> {
    let range = |side: &str| {
        crate::release::ProtocolRange::parse(text(input, side).as_bytes()).ok_or(Error::Malformed)
    };
    Ok(match range("ours")?.highest_shared(range("theirs")?) {
        Ok(uses) => json!({"ok": true, "uses": uses}),
        Err(crate::release::Behind::Ours) => json!({"ok": true, "behind": "ours"}),
        Err(crate::release::Behind::Theirs) => json!({"ok": true, "behind": "theirs"}),
    })
}

fn party_of(input: &Value) -> Party {
    Party {
        agent: Identity::from_encoded(text(input, "agent_identity")).unwrap(),
        owner: Identity::from_encoded(text(input, "owner_identity")).unwrap(),
        // A walk only goes by the two identities. An outcome carries its own.
        binding: String::new(),
    }
}

fn parties_of(input: &Value) -> Parties {
    let recipient = &input["recipient"];
    Parties {
        requester: party_of(&input["requester"]),
        recipient: if recipient["guest_identity"].is_string() {
            Party::guest(Identity::guest_from_encoded(text(recipient, "guest_identity")).unwrap())
        } else {
            party_of(recipient)
        },
    }
}

fn walk_result(chain: &Chain, now: u64, over_cap: usize) -> Value {
    let mut result = json!({
        "state": chain.state_at(now),
        "version": chain.version(),
        "head": chain.head(),
    });
    if over_cap > 0 {
        result["over_cap"] = json!(over_cap);
    }
    if chain.copies_dropped() > 0 {
        result["copies_dropped"] = json!(chain.copies_dropped());
    }
    if let Some(payment) = chain.payment() {
        result["payment"] = json!(payment.status);
    }
    result
}

/// Whether a step that first arrives at this clock has already ended. A step already held has only
/// its signature re-checked, so this applies only to what `last_arrived_at` says just came.
fn expired_on_arrival(parties: &Parties, compact: &str, arrived_at: u64) -> bool {
    let sender = claimed_sender(compact).unwrap();
    let agent = if parties.requester.agent.id() == &sender {
        &parties.requester.agent
    } else {
        &parties.recipient.agent
    };
    matches!(
        VerifiedEnvelope::verify(compact, agent, arrived_at),
        Err(Error::Expired)
    )
}

/// The examples, and any types both sides agreed, as a walk's `schemas` gives them.
fn walk_schemas(input: &Value) -> Schemas {
    let agreed = input["schemas"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|schema| {
            std::sync::Arc::new(Schema::parse(&serde_json::to_vec(schema).unwrap()).unwrap())
        });
    let examples = examples()
        .all()
        .cloned()
        .map(std::sync::Arc::new)
        .collect::<Vec<_>>();
    Schemas::of(examples.into_iter().chain(agreed)).unwrap()
}

fn check_request_walk(input: &Value) -> Result<Value, Error> {
    let parties = parties_of(input);
    let steps: Vec<String> = serde_json::from_value(input["chain"].clone()).unwrap();
    if let Some(arrived_at) = input["last_arrived_at"].as_u64() {
        let last = steps.last().unwrap();
        if expired_on_arrival(&parties, last, arrived_at) {
            let index = steps.len() - 1;
            return Ok(json!({"refused_at": index, "reason": "expired"}));
        }
    }
    let schemas = walk_schemas(input);
    let walked = Chain::walk(parties.clone(), schemas.clone(), &steps);
    // A last step refused read back is refused for the same reason as it arrives, through `apply` as
    // Signet takes one off the wire, so a rule only read-back holds fails here. Arriving can refuse
    // more, as one needs the keys its owner holds now, where read-back takes any they held.
    if let (Err(refused), Some((last, before))) = (&walked, steps.split_last())
        && refused.index == before.len()
    {
        let arrived = arrival(&parties, schemas, before, last);
        if arrived.is_some_and(|arrived| arrived != Some(refused.reason)) {
            return Ok(json!({"arrival": arrived, "read_back": refused.reason}));
        }
    }
    Ok(match walked {
        Ok(chain) => walk_result(&chain, number(input, "now"), chain.over_cap()),
        Err(refused) => json!({"refused_at": refused.index, "reason": refused.reason}),
    })
}

/// What becomes of `last` arriving after `before`, or nothing if its envelope doesn't verify, as one
/// that doesn't never reaches a chain.
fn arrival(
    parties: &Parties,
    schemas: Schemas,
    before: &[String],
    last: &str,
) -> Option<Option<Refused>> {
    let sender = claimed_sender(last).ok()?;
    let agent = [&parties.requester, &parties.recipient]
        .into_iter()
        .find(|party| party.agent.id() == &sender)?;
    let envelope = VerifiedEnvelope::verify_ignoring_clock(last, &agent.agent).ok()?;
    let mut chain = Chain::walk(parties.clone(), schemas, before).unwrap();
    Some(chain.apply(&envelope).err())
}

fn check_outcome(input: &Value) -> Result<Value, Error> {
    let outcome: Outcome =
        serde_json::from_value(input["outcome"].clone()).map_err(|_| Error::Malformed)?;
    let parties = &input["outcome"]["parties"];
    let agent = |side: &str| party_of(&parties[side]).agent;
    let terms = outcome.verify_for(&agent("requester"), &agent("recipient"), &examples())?;
    // A verifier compares the owners with the ones it has pinned, which is what makes this theirs.
    let pinned = &input["pinned"];
    let matches_pin = |party: &crate::requests::TermsParty, side: &str| {
        party.agent.as_str() == text(&pinned[side], "agent_id")
            && party.owner.as_str() == text(&pinned[side], "owner_id")
    };
    if !matches_pin(&terms.requester, "requester") || !matches_pin(&terms.recipient, "recipient") {
        return Err(Error::ProofMismatch);
    }
    Ok(json!({"ok": true}))
}

fn check_guest_outcome(input: &Value) -> Result<Value, Error> {
    let outcome: Outcome =
        serde_json::from_value(input["outcome"].clone()).map_err(|_| Error::Malformed)?;
    let parties = &input["outcome"]["parties"];
    let requester = party_of(&parties["requester"]).agent;
    let guest = Identity::guest_from_encoded(text(&parties["recipient"], "agent_identity"))?;
    let terms = outcome.verify_for(&requester, &guest, &examples())?;
    let pinned = &input["pinned"];
    if terms.requester.owner.as_str() != text(&pinned["requester"], "owner_id")
        || terms.recipient.agent.as_str() != text(&pinned["recipient"], "guest_id")
    {
        return Err(Error::ProofMismatch);
    }
    Ok(json!({"ok": true}))
}

fn check_guest_identity(input: &Value) -> Result<Value, Error> {
    let raw = URL_SAFE_NO_PAD
        .decode(text(input, "raw"))
        .map_err(|_| Error::Malformed)?;
    let identity = Identity::parse_guest(&raw)?;
    Ok(json!({"ok": true, "id": identity.id(), "role": "guest"}))
}

fn run(vector: &Vector) -> Value {
    let input = &vector.input;
    outcome(match vector.check.as_str() {
        "identity.parse" => check_identity(input),
        "envelope.verify" => check_envelope(input),
        "access_proof.verify" => check_access_proof(input),
        "delivery_proof.verify" => check_delivery_proof(input),
        "host_id.verify" => check_host_id(input),
        "host_id.follows" => check_host_id_follows(input),
        "address.parse" => check_address(input),
        "delivery_failure.parse" => check_delivery_failure(input),
        "protocol.choose" => check_protocol_choose(input),
        "request.walk" | "request.person_text" | "guest.walk" => check_request_walk(input),
        "guest.outcome" => check_guest_outcome(input),
        "guest_identity.parse" => check_guest_identity(input),
        "outcome.verify" => check_outcome(input),
        "identity.check_backup" => check_backup(input),
        "identity.read" => check_identity_read(input),
        "identity.newest" => check_identity_newest(input),
        "identity.keys" => check_identity_keys(input),
        "identity.newest_keys" => check_identity_newest_keys(input),
        "history.verify" => check_history(input),
        "history.against" => check_history_against(input),
        "history.respond" => check_history_response(input),
        "acceptance.verify" => check_acceptance(input),
        "approval.verify" => Ok(check_approval(input)),
        "binding.replace" => check_binding_replace(input),
        "release.verify" => check_release(input),
        "binding.verify" => check_binding(input),
        "registration.verify" => check_registration(input),
        "retirement.verify" => check_retirement(input),
        "rules.verify" => check_rules(input),
        "delegation.verify" => check_delegation(input),
        "delegated_approval.verify" => Ok(check_delegated_approval(input)),
        "carried_approval.verify" => Ok(check_carried_approval(input)),
        "admit.check" => check_admit(input),
        "invite.redeem" => check_invite_redeem(input),
        "ask.verify" => check_ask(input),
        "move.reply" => check_move_reply(input),
        "ask.answer" => check_ask_answer(input),
        "touch.code" => Ok(check_touch_code(input)),
        "invite.verify" => check_invite_verify(input),
        "invite.pending" => check_invite_pending(input),
        "card.parse" => check_card(input),
        "pairing.code" => check_pairing_code(input),
        "pairing.verify" => check_pairing(input),
        "pairing.opener" => check_pairing_opener(input),
        "owner_view.verify" => check_owner_view(input),
        "controls.prepare" => check_controls(input),
        "owner_session.verify" => check_owner_session(input),
        "owner_access.verify" => check_owner_access(input),
        "owner_agents.verify" => check_owner_agents(input),
        "owner_agents.open" => check_owner_agents_open(input),
        "owner_agents.handle" => check_owner_list_handle(input),
        "owner_call.open" => check_owner_call_open(input),
        "owner_mail.open" => check_owner_mail_open(input),
        "reading_key.open" => check_reading_key_open(input),
        "recovery_code.backup" => check_recovery_code(input),
        "prf.sealing_key" => check_prf_sealing(input),
        "outbound.check" => check_outbound(input),
        "grant.check" => Ok(check_grant(input)),
        "revocation.verify" => Ok(check_revocation(input)),
        "type.id" => Ok(check_type_id(input)),
        "type.propose" => Ok(check_type_propose(input)),
        other => panic!("{}: no code for check {other}", vector.name),
    })
}

#[test]
fn checked_vectors_give_the_results_the_spec_states() {
    let mut failures = Vec::new();
    for (file, vector) in all_vectors() {
        if vector.status == "checked" && !GO_ONLY_CHECKS.contains(&vector.check.as_str()) {
            let actual = run(&vector);
            if actual != vector.expect {
                failures.push(format!(
                    "{file}/{}: expected {}, got {actual}",
                    vector.name, vector.expect
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Delivers steps in this order, and says how many a cap refused. No other refusal is expected of a
/// step that comes after the one it names.
fn delivered_in_order(parties: Parties, schemas: Schemas, order: &[&String]) -> (Chain, usize) {
    let mut chain = Chain::new(parties, schemas);
    let mut over_cap = 0;
    for step in order {
        match chain.apply_stored(step) {
            Ok(_) => {}
            Err(Refused::TooManySteps) => over_cap += 1,
            Err(other) => panic!("refused for {other:?}, which order can't explain"),
        }
    }
    (chain, over_cap)
}

/// The step this one names, which a host has to deliver first, or `None` for an `open`.
fn named_step(compact: &str) -> Option<String> {
    let payload = jws::unverified_payload(compact, "splint-envelope").unwrap();
    let payload: Value = serde_json::from_slice(&payload).unwrap();
    let body: Value = serde_json::from_str(text(&payload, "body")).unwrap();
    let named = body.get("prev").or_else(|| body.get("of"));
    named.and_then(Value::as_str).map(str::to_owned)
}

fn message_id_of(compact: &str) -> String {
    let payload = jws::unverified_payload(compact, "splint-envelope").unwrap();
    MessageId::of(&payload).as_str().to_owned()
}

/// Every order with each step after the one it names.
fn every_order<'a>(steps: &[&'a String], delivered: &BTreeSet<String>) -> Vec<Vec<&'a String>> {
    if steps.is_empty() {
        return vec![Vec::new()];
    }
    let mut orders = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        if named_step(step).is_some_and(|named| !delivered.contains(&named)) {
            continue;
        }
        let mut others = steps.to_vec();
        others.remove(index);
        let mut then = delivered.clone();
        then.insert(message_id_of(step));
        for mut rest in every_order(&others, &then) {
            rest.insert(0, *step);
            orders.push(rest);
        }
    }
    orders
}

/// One order a host could deliver a flood in, since a flood has too many to try them all.
fn sampled_order<'a>(
    steps: &[&'a String],
    delivered: &BTreeSet<String>,
    random: &mut u64,
) -> Option<Vec<&'a String>> {
    let mut delivered = delivered.clone();
    let mut waiting = steps.to_vec();
    let mut order = Vec::new();
    while !waiting.is_empty() {
        let ready: Vec<usize> = (0..waiting.len())
            .filter(|index| {
                named_step(waiting[*index]).is_none_or(|named| delivered.contains(&named))
            })
            .collect();
        if ready.is_empty() {
            return None;
        }
        // It only has to be repeatable and spread out, so xorshift will do.
        *random ^= *random << 13;
        *random ^= *random >> 7;
        *random ^= *random << 17;
        let chosen = ready[usize::try_from(*random).unwrap() % ready.len()];
        let step = waiting.remove(chosen);
        delivered.insert(message_id_of(step));
        order.push(step);
    }
    Some(order)
}

/// The spec's promise is that a host's order can't choose a result, so this walks each chain that
/// ends in a state in the orders a host could deliver it: every one for a short chain, and a sample
/// for a flood. `keep_first` steps stay where they are, because an owner signs only on a step their
/// own Signet holds, so those arrived before any flood did.
#[test]
fn a_chains_result_doesnt_depend_on_delivery_order() {
    const MAX_STEPS_TO_TRY_EVERY_ORDER: usize = 7;
    const FLOOD_ORDERS: usize = 8;
    let mut walked = 0;
    let mut floods = 0;
    for (_, vector) in all_vectors() {
        let walks = matches!(
            vector.check.as_str(),
            "request.walk" | "request.person_text"
        );
        let finishes = walks && vector.expect.get("state").is_some();
        if vector.status != "checked" || !finishes {
            continue;
        }
        let input = &vector.input;
        let steps: Vec<String> = serde_json::from_value(input["chain"].clone()).unwrap();
        let refs: Vec<&String> = steps.iter().collect();
        let keep_first = input["keep_first"].as_u64().map_or(1, |n| n as usize);
        let (first, rest) = refs.split_at(keep_first);
        let seen: BTreeSet<String> = first.iter().map(|step| message_id_of(step)).collect();
        let orders = if rest.len() <= MAX_STEPS_TO_TRY_EVERY_ORDER {
            every_order(rest, &seen)
        } else {
            floods += 1;
            let mut random = 0x9e37_79b9_7f4a_7c15;
            (0..FLOOD_ORDERS)
                .filter_map(|_| sampled_order(rest, &seen, &mut random))
                .collect()
        };
        assert!(!orders.is_empty(), "{}", vector.name);
        for order in orders {
            let whole: Vec<&String> = first.iter().copied().chain(order).collect();
            let (chain, over_cap) =
                delivered_in_order(parties_of(input), walk_schemas(input), &whole);
            let found = walk_result(&chain, number(input, "now"), over_cap);
            assert_eq!(found, vector.expect, "{}", vector.name);
            walked += 1;
        }
    }
    assert!(walked > 100, "only {walked} orders walked");
    assert!(floods >= 10, "only {floods} floods walked");
}

#[test]
fn every_check_has_valid_and_hostile_cases() {
    let mut cases: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (_, vector) in all_vectors() {
        cases
            .entry(vector.check.clone())
            .or_default()
            .insert(vector.case.clone());
    }
    for check in CHECKS {
        let found = cases
            .get(check)
            .unwrap_or_else(|| panic!("no vectors for {check}"));
        assert!(
            found.contains("valid") && found.contains("hostile"),
            "{check}: {found:?}"
        );
    }
}

#[test]
fn pending_vectors_name_their_issue_and_have_no_code_waiting() {
    for (file, vector) in all_vectors() {
        match vector.status.as_str() {
            "checked" => assert!(
                CHECKS.contains(&vector.check.as_str())
                    || GO_ONLY_CHECKS.contains(&vector.check.as_str()),
                "{file}/{}",
                vector.name
            ),
            "pending" => {
                assert!(vector.issue.is_some(), "{file}/{}: no issue", vector.name);
                assert!(
                    !CHECKS.contains(&vector.check.as_str()),
                    "{file}/{}: this check exists now, so mark the vector checked",
                    vector.name
                );
            }
            other => panic!("{file}/{}: unknown status {other}", vector.name),
        }
    }
}

/// A pending vector stating "refused: wrong holder" is only useful if its signatures are good.
/// Otherwise the code that lands later would refuse it for the wrong reason, and the test would pass.
#[test]
fn signatures_in_pending_vectors_verify_under_the_key_they_name() {
    let keys: KeysFile =
        serde_json::from_slice(&fs::read(vectors_dir().join("keys.json")).unwrap()).unwrap();
    let mut verified = 0;
    for (file, vector) in all_vectors() {
        let document = json!({"input": vector.input});
        for signed in &vector.signed {
            let compact = document
                .pointer(&signed.at)
                .and_then(Value::as_str)
                .unwrap();
            // As the ID of a file key, since what an owner signs is checked only through an ID.
            let key = PublicKey::from_encoded(&keys.keys[&signed.by]).unwrap();
            let signer = Identity::for_key(
                &key,
                &crate::test_seal(),
                RecoveryRule::unconfirmed_owner(&key),
            )
            .unwrap();
            assert!(
                signer.verify(compact, &signed.typ).is_ok(),
                "{file}/{} at {}",
                vector.name,
                signed.at
            );
            verified += 1;
        }
    }
    assert!(verified > 0, "no signatures were checked");
}

/// The runner has to be able to fail. A vector whose signature is changed must give another result.
#[test]
fn a_changed_vector_gives_a_different_result() {
    let (_, mut plain) = all_vectors()
        .into_iter()
        .find(|(file, vector)| file == "envelope.json" && vector.name == "plain")
        .unwrap();
    assert_eq!(run(&plain), plain.expect);
    let compact = text(&plain.input, "compact").to_owned();
    let (signing_input, _) = compact.rsplit_once('.').unwrap();
    plain.input["compact"] = json!(format!("{signing_input}.{}", jws::encode(&[1_u8; 64])));
    assert_eq!(run(&plain), json!({"ok": false, "reason": "bad_signature"}));
}

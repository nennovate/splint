//! The requests and answers of a host's API, shared so the host and Signet can't drift apart.
//! `docs/protocol.md` describes them.

use serde::{Deserialize, Serialize};

use crate::requests::GuestForm;
use crate::{DeliveryFailure, DeliveryState, SplintId};

/// Which of a host's limits on new agents a registration reached, as fixed words in the
/// [`JoinLimit::HEADER`] header beside its 429, so whoever asked can say which, and a person at their
/// owner's cap isn't told to wait for nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinLimit {
    /// New agents without a signup code from one network, this hour or day.
    FromOneNetwork,
    /// Agents without a code that one network holds at once.
    OneNetworkHoldsAll,
    /// Agents without a code that nobody has used yet.
    UnusedStandIns,
    /// Agents without a code whose controls nobody has set up yet.
    StandIns,
    /// Agents without a signup code, in all or in an hour.
    WithoutACode,
    /// New agents this hour, with a code.
    ThisHour,
    /// Every agent this host holds.
    HostFull,
    /// Agents of one owner.
    OwnersAgents,
    /// Any new agent at all, as this host's operator has set a date it closes.
    HostClosing,
}

impl JoinLimit {
    pub const HEADER: &str = "splint-limit";
    const ALL: [Self; 9] = [
        Self::FromOneNetwork,
        Self::OneNetworkHoldsAll,
        Self::UnusedStandIns,
        Self::StandIns,
        Self::WithoutACode,
        Self::ThisHour,
        Self::HostFull,
        Self::OwnersAgents,
        Self::HostClosing,
    ];

    pub fn word(self) -> &'static str {
        match self {
            Self::FromOneNetwork => "from_one_network",
            Self::OneNetworkHoldsAll => "one_network_holds_all",
            Self::UnusedStandIns => "unused_stand_ins",
            Self::StandIns => "stand_ins",
            Self::WithoutACode => "without_a_code",
            Self::ThisHour => "this_hour",
            Self::HostFull => "host_full",
            Self::OwnersAgents => "owners_agents",
            Self::HostClosing => "host_closing",
        }
    }

    pub fn from_word(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|limit| limit.word() == word)
    }

    /// The limit these exact words are said for, for a program reading them from its own Signet.
    pub fn from_sentence(said: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|limit| limit.sentence() == said)
    }

    /// What it means for whoever asked, the same words wherever it's said.
    pub fn sentence(self) -> &'static str {
        match self {
            Self::FromOneNetwork => {
                "this host has taken all the new agents it takes from one network for now, so try \
                 again in an hour, or with a signup code"
            }
            Self::OneNetworkHoldsAll => {
                "this host is holding as many agents that joined without a code from one network as \
                 it takes, so join with a signup code, or on another host"
            }
            Self::UnusedStandIns => {
                "this host is holding as many agents nobody has used yet as it takes, so try again \
                 later, or join with your owner first"
            }
            Self::StandIns => {
                "this host is holding as many agents with no controls set up yet as it takes, so \
                 join with your owner first, or try again later"
            }
            Self::WithoutACode => {
                "this host has taken as many agents without a signup code as it takes for now, so \
                 try again later, or with a signup code from whoever runs it"
            }
            Self::ThisHour => {
                "this host has taken as many new agents as it takes in an hour, so try again in an \
                 hour"
            }
            Self::HostFull => {
                "this host holds as many agents as it takes, so join another host, or ask whoever \
                 runs it"
            }
            Self::OwnersAgents => {
                "this owner has as many agents on this host as it takes for one owner, so retire one \
                 of them first, or use another host. Waiting won't change it"
            }
            Self::HostClosing => {
                "this host is closing, so it takes no new agents: join another host. Waiting won't \
                 change it"
            }
        }
    }
}

/// On every answer from a host whose operator has set a date it closes: that time, as seconds since
/// 1970, the start of the day the operator gave. Its agents' Signets keep what the last answer said.
/// It's the host's word, and all it can do is have an agent move, which its owner signs.
pub const CLOSING_HEADER: &str = "splint-closing";

/// A closing time as the header says it: plain digits, not 0. Anything else counts as none.
pub fn closing_in(header: Option<&[u8]>) -> Option<u64> {
    let said = header?;
    if said.is_empty() || said.len() > 19 || !said.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(said)
        .ok()?
        .parse()
        .ok()
        .filter(|at| *at > 0)
}

/// A registration whose signup code this host holds no unused match for, mistyped or already spent,
/// answered 403 with [`SignupCodeRefused::WORD`] in [`SignupCodeRefused::HEADER`], so whoever asked
/// can say which and what to do. No other refusal carries it.
pub struct SignupCodeRefused;

impl SignupCodeRefused {
    pub const HEADER: &str = "splint-signup";
    pub const WORD: &str = "code_refused";
    /// What it means for whoever asked, the same words wherever it's said.
    pub const SENTENCE: &str = "the host has no unused signup code like that one: it was mistyped, or \
         it's already spent, as each works once. Nothing was taken. Ask your person for another \
         code from whoever runs the host";
}

/// Where an agent asks its own host who's at an address, so its Signet never calls another domain.
pub const LOOKUP_PATH: &str = "/v0/lookup";

/// Who's at an address, asked of the caller's own host.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupRequest {
    pub address: String,
}

/// The handle isn't a field: it comes from the address the owner signed in the binding.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub owner_identity: String,
    pub agent_identity: String,
    pub binding: String,
    pub signup_id: String,
    pub signup_mac: String,
}

/// An agent's identity, its owner's and the binding between them. A reader checks them together with
/// [`crate::VerifiedBinding::verify_for`], because a host's word on any of them proves nothing.
#[derive(Serialize, Deserialize)]
pub struct Resolved {
    pub agent_id: SplintId,
    pub identity: String,
    pub owner_identity: String,
    pub binding: String,
    /// What changed on this ID since it started, which a reader checks for itself. Empty until an
    /// owner has bound it, or if the host doesn't say, which only leaves a reader waiting to hear.
    #[serde(default)]
    pub history: String,
    /// Where the agent once at the name asked about is now, when its owner part moved with a new
    /// owner. Its binding names that address, signed by its new owner, which is what counts.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub moved_to: String,
}

/// Where a host says who has a name there as their own, `GET` with the name after it: an owner whose
/// name it is, or whose agent goes by it alone. 404 is a name nobody has, and 403 one nobody can have
/// there. It's the host's word, for asking before anyone signs, and registering is what settles it.
pub const NAMES_PATH: &str = "/.well-known/splint/names";
/// Where a host says an owner's name there, `GET {OWNERS_NAME_PATH}/{owner ID}/name`, 404 for none.
pub const OWNERS_NAME_PATH: &str = "/.well-known/splint/owners";

/// Who has a name at a host as their own, by owner ID.
#[derive(Serialize, Deserialize)]
pub struct NameHolder {
    pub owner: String,
}

/// An owner's name at a host, which their agents there are named under.
#[derive(Serialize, Deserialize)]
pub struct OwnersName {
    pub name: String,
}

/// An owner's stop signal. The agent's own host goes by the owner it holds, so `retirement` is all it
/// needs. Any other host checks the rest, because it goes by nobody's word: who signed this, and that
/// they're who this agent acts for. [`crate::VerifiedStop`] is that check.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementNotice {
    pub retirement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner_identity: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent_identity: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub binding: String,
}

/// When a retirement can no longer be undone, from the agent's own host. Another host says nothing.
#[derive(Serialize, Deserialize)]
pub struct RetirementTaken {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_at: Option<u64>,
}

/// An ID's event and each recovery since. It checks out on its own, so anyone can carry one.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryNotice {
    pub identity: String,
}

/// An ID's history of material changes. It checks out on its own, so anyone can carry one.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryNotice {
    pub history: String,
}

/// An owner's yes to a contact's history, and the histories it can name, so a host whose agent's owner
/// said yes goes by it too. The owner's signature is what counts, so anyone can carry one.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceNotice {
    pub acceptance: String,
    pub histories: Vec<String>,
}

/// The newest copies a host holds of the owners this agent's rules name and of its contacts, and the
/// stop signals it holds for those contacts, for its Signet to check and take in.
#[derive(Serialize, Deserialize)]
pub struct KnownOwners {
    pub identities: Vec<String>,
    #[serde(default)]
    pub stops: Vec<RetirementNotice>,
    /// There when the host holds more than this page: the reader asks again from after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

/// An owner's release naming nobody: this agent acts for nobody until its owner signs again.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationNotice {
    pub revocation: String,
}

#[derive(Serialize, Deserialize)]
pub struct OutboundRequest {
    pub envelope: String,
    pub recipient_host: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeliveryStatus {
    pub status: DeliveryState,
    pub attempts: i32,
    pub last_failure: Option<DeliveryFailure>,
}

#[derive(Serialize, Deserialize)]
pub struct StoredMessage {
    pub seq: i64,
    pub envelope: String,
    pub sender_identity: String,
    /// Passed on from the sending host for whoever needs the sender's address. Empty if it didn't
    /// check out, and a reader checks it again.
    #[serde(default)]
    pub sender_owner_identity: String,
    #[serde(default)]
    pub sender_binding: String,
    /// The host that said it delivered this, and its signature saying so. Only a reader who holds
    /// that host's key from its owner can check them, and otherwise they say nothing.
    #[serde(default)]
    pub relayed_by: String,
    #[serde(default)]
    pub relay_proof: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesNotice {
    pub rules: String,
}

/// An owner's answer to an agent that asked to join, for a host to keep until the agent asks. It saves
/// a person and a model copying it by hand. It counts by the owner's signature, whoever carries it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinAnswer {
    pub agent_key: String,
    pub answer: String,
    /// For an answer to an agent's ask for its controls: where it's kept, worked out from the ask's
    /// ID, which only the agent and whoever its link reached know. Sent only when leaving it, never
    /// shown back. Provisional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept_at: Option<String>,
    /// With it: a MAC by the ask's ID over the answering owner's ID, so nobody who didn't see the ask
    /// can make one, or move one to another owner. Provisional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_mac: Option<String>,
}

/// The answers a host keeps where an agent's ask said, from whichever owners its link reached, oldest
/// first, so an agent that doesn't know its owner's ID yet finds theirs, and sees when more than one
/// owner answered.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinAnswers {
    pub answers: Vec<JoinAnswer>,
}

/// Where a Signet whose owner is on another device leaves what that device reads, and where the device
/// asks for it, under the agent's ID.
pub const OWNER_VIEW_PATH: &str = "/v0/owner-view";
/// Where an owner's device leaves what it signed, under the agent's ID, for that agent's Signet to take.
pub const OWNER_MAIL_PATH: &str = "/v0/owner-mail";
pub const OWNER_MAIL_ACK_PATH: &str = "/v0/owner-mail/ack";

/// What an owner's device reads about an agent elsewhere. Its Signet seals it to the owner's sealing
/// key, so to a host it's bytes it carries and gives only to that owner. The device checks what's
/// signed in it itself.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerView {
    pub view: String,
}

/// The most an `OwnerView` can be, written out, which a Signet leaves things out of a view to fit. A
/// host reads no body bigger than this before it gets to any route, and nor does what's in front of it,
/// so a view that fits this fits everything on its way.
pub const MAX_OWNER_VIEW_BYTES: usize = 512 * 1024;

/// What a sealed view is bound to, so one agent's can't be shown as another's.
pub fn owner_view_about(agent: &SplintId) -> Vec<u8> {
    format!("splint owner view for {agent}").into_bytes()
}

/// A host's latest copy, and when it took that, which is only the host's word.
#[derive(Serialize, Deserialize)]
pub struct HeldOwnerView {
    pub view: Option<String>,
    pub at: u64,
}

/// Where an owner's page keeps the list of their agents, under the owner's ID, and finds their ID.
pub const OWNER_AGENTS_PATH: &str = "/v0/owner-agents";
pub const OWNERS_PATH: &str = "/v0/owners";
pub const OWNER_HANDLES_PATH: &str = "/v0/owner-handles";

/// `PUT /v0/owner-agents/{owner}`: the owner's ID as it is now, and their signed, sealed list.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAgentsNotice {
    pub owner_identity: String,
    pub list: String,
    /// The agent here, with no controls yet, that this owner is setting up from its link, which makes
    /// room for a new owner's list as a pairing open here does. Its ID is public, so this is room, not
    /// proof: only the answer the agent takes, with the MAC its ask's ID makes, gives it an owner.
    /// Provisional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<SplintId>,
}

/// The list a host holds for an owner, and the ID it was checked under.
#[derive(Serialize, Deserialize)]
pub struct HeldOwnerAgents {
    pub owner_identity: String,
    pub list: String,
}

/// `GET /v0/owner-handles/{handle}`: the lists naming this passkey's user handle, for a new device
/// that has only the passkey. More than one means someone named another's handle, which a page tells
/// apart by checking each against the passkey's own signature.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListsByHandle {
    pub lists: Vec<HeldOwnerAgents>,
}

/// `PUT /v0/owner-agents/{owner}`'s answer: the `seq` now held.
#[derive(Serialize, Deserialize)]
pub struct OwnerAgentsKept {
    pub seq: u64,
}

/// `GET /v0/owners/{owner}`: the newest copy of an owner's ID this host holds.
#[derive(Serialize, Deserialize)]
pub struct KnownOwner {
    pub owner_identity: String,
}

/// What an owner's device signed for its agent's Signet, which only checks out under that owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerMailKind {
    Approval,
    Acceptance,
    PersonText,
    /// A delegation to the agent's Signet's delegate key, which the owner's page signs afresh with
    /// rules naming it, so an agent paired long ago gets new caps and dates without pairing again.
    Delegation,
    /// Where the owner gets paid, which their agent's Signet puts on its asks to be paid.
    WherePaid,
}

/// It goes to the agent's host sealed to the agent, as `owner_call::seal_owner_mail` seals it, so
/// only its Signet reads this.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerMail {
    pub kind: OwnerMailKind,
    pub signed: String,
}

/// What tells one thing an owner signed from another: the hash of what they signed, without the
/// signature, which their key can't make twice the same way and anyone holding it can spell again. A
/// host keeps each thing once by the same hash, and so does whatever gets one thing by two routes.
pub fn owner_mail_item(signed: &str) -> String {
    let signed_part = signed.rsplit_once('.').map_or(signed, |(part, _)| part);
    crate::MessageId::of(signed_part.as_bytes())
        .as_str()
        .to_owned()
}

/// Owner mail as a host keeps it and hands it to the agent's Signet: sealed to the agent, so there's
/// nothing here a host can read, and no way to write one that isn't sealed.
#[derive(Serialize, Deserialize)]
pub struct StoredOwnerMail {
    pub seq: i64,
    pub sealed: String,
}

#[derive(Serialize, Deserialize)]
pub struct OwnerMailPage {
    pub mail: Vec<StoredOwnerMail>,
}

/// What a host holds for an agent, from `GET /v0/rules`. Nothing here counts until the owner's signature
/// checks out, so a host can only leave out something newer.
#[derive(Serialize, Deserialize)]
pub struct HeldRules {
    pub rules: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct RulesApplied {
    pub seq: u64,
}

/// A message held from an unknown sender, for its recipient's Signet to verify.
#[derive(Serialize, Deserialize)]
pub struct Quarantined {
    pub envelope: String,
    pub sender_identity: String,
    pub sender_owner_identity: String,
    pub sender_binding: String,
}

/// `next` is there when the host holds more than this page: the reader asks again from after it.
#[derive(Serialize, Deserialize)]
pub struct QuarantinePage {
    pub held: Vec<Quarantined>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<i64>,
}

/// Where a Signet reads its agent's invites box, and clears what it has dealt with.
pub const INVITES_PATH: &str = "/v0/invites";
pub const INVITES_DONE_PATH: &str = "/v0/invites/done";
/// Where an agent that moved here gives back the contacts it agreed by itself at its last host.
pub const AGREED_PATH: &str = "/v0/agreed";
/// The most pairs one call gives back, so a call is bounded however many an agent has.
pub const MOST_AGREED_IN_ONE_CALL: usize = 100;

/// Contacts an agent agreed by itself elsewhere, each pair as both agents signed it, for its new host
/// to check as it checks one made here, and keep within the same day's count.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgreedPairs {
    pub pairs: Vec<crate::contact_invites::PendingContact>,
}

/// What a host did with pairs given back: `full` when the day's count left some out, which come back
/// on a later day, as nothing else keeps them out that waiting changes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgreedTaken {
    pub full: bool,
}

/// An invite, or an acceptance of one this agent sent, held apart from the inbox for its Signet to
/// check again. `seq` is only the host's handle on it.
#[derive(Serialize, Deserialize)]
pub struct HeldIntroduction {
    pub seq: i64,
    pub envelope: String,
    pub sender_identity: String,
    pub sender_owner_identity: String,
    pub sender_binding: String,
}

/// `next` is there when the box holds more than this page: the reader asks again from after it.
#[derive(Serialize, Deserialize)]
pub struct IntroductionsPage {
    pub held: Vec<HeldIntroduction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<i64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntroductionsDone {
    pub seqs: Vec<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct InboxPage {
    pub messages: Vec<StoredMessage>,
}

#[derive(Serialize, Deserialize)]
pub struct InboxAck {
    pub seqs: Vec<i64>,
}

/// Where a Signet waits for something new for its agent, rather than asking again and again.
pub const WAIT_PATH: &str = "/v0/wait";

/// `since` is what the last answer said, or nothing on a Signet's first wait.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitRequest {
    pub since: Option<u64>,
}

/// `new` says something may have come since `since`, so it's worth looking. It's only a hint: a host
/// can say so of nothing, or keep quiet, as it can drop anything. What counts is what's read after.
#[derive(Serialize, Deserialize)]
pub struct WaitAnswer {
    pub since: u64,
    pub new: bool,
}

#[derive(Serialize, Deserialize)]
pub struct StoredStep {
    pub envelope: String,
    pub sender_identity: String,
}

/// A step on a one-use link, from the agent that made it. The guest's identity and what its page draws
/// count only on the `open`: the identity has to hash to the ID the owner signed for, and the form is
/// only what to draw, as a reader refuses anything that doesn't fit the type.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestOutbound {
    pub envelope: String,
    pub guest_identity: String,
    pub form: GuestForm,
}

/// What a guest's page sends. The key in the link is the only proof there is.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestAnswer {
    pub envelope: String,
}

/// What's on one link, for the page holding it. Everything here is a copy for a person to read: a
/// request's state is what its requester's Signet finds by walking the signed steps.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestLink {
    pub address: String,
    /// This host's clock, which a step is dated by, as a guest's device may be well off.
    pub now: u64,
    pub guest_identity: String,
    pub form: GuestForm,
    pub deadline: u64,
    pub open: String,
    pub steps: Vec<String>,
}

/// A guest's step waiting for the agent it answers.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestStepRow {
    pub seq: i64,
    pub request: String,
    pub envelope: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestSteps {
    pub steps: Vec<GuestStepRow>,
}

/// What a host refused on an agent's behalf, by its own word. There's no content in it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRefusal {
    pub at: u64,
    pub way: String,
    pub from: Option<String>,
    pub reason: String,
    pub count: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRefusals {
    pub refused: Vec<HostRefusal>,
}

/// A request's steps as one host holds them. This is a copy, which a reader has to verify and walk.
/// `next` is there when the host has more: the reader asks again from after it.
#[derive(Serialize, Deserialize)]
pub struct StoredChain {
    pub steps: Vec<StoredStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<i64>,
}

//! Sealed or unsealed, for each contact. This agent's owner chose one in their signed rules, and each
//! contact's Signet says what its owner chose on everything it seals. What goes between the two is
//! sealed unless both chose unsealed, so the stricter side wins, both ways. A contact that hasn't said
//! counts as sealed.
//!
//! A host can't make anything go unsealed: what a contact chose is in what its key signed, and the
//! newest of it counts, so an old message shown again changes nothing.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use splint_core::requests::{CheckedStep, Refused, StepKind, is_step_body};
use splint_core::{
    Identity, SealFor, Sealing, SignedEnvelope, SplintId, VerifiedEnvelope,
    changes::is_notice_body, invites::redeem_proof_in, requests::request_of, sign_envelope,
    sign_sealed_envelope,
};
use tokio::sync::Mutex;

use crate::Signet;
use crate::agent_api::ApiError;
use crate::state_file::{self, StateError};

#[derive(Clone, Copy, Serialize, Deserialize)]
struct Said {
    at: u64,
    chose: Sealing,
}

/// What each contact last said its owner chose.
pub struct TheirSealing {
    path: PathBuf,
    said: Mutex<HashMap<String, Said>>,
}

impl TheirSealing {
    pub fn load(path: PathBuf) -> Result<Self, StateError> {
        let said = state_file::load(&path)?;
        Ok(Self {
            path,
            said: Mutex::new(said),
        })
    }

    /// Everything heard, by ID, for the owner's page.
    pub async fn all(&self) -> BTreeMap<String, Sealing> {
        let said = self.said.lock().await;
        said.iter()
            .map(|(agent, said)| (agent.clone(), said.chose))
            .collect()
    }

    pub async fn of(&self, peer: &SplintId) -> Option<Sealing> {
        let said = self.said.lock().await;
        said.get(peer.as_str()).map(|said| said.chose)
    }

    /// Takes what a verified message says its sender's owner chose. A sealed one says so outright.
    /// Words or a step that came unsealed say unsealed, as an honest Signet sends that only when its
    /// owner chose it. What carries nothing an agent wrote, such as a `received`, says nothing.
    pub async fn note(&self, envelope: &VerifiedEnvelope) -> Result<(), StateError> {
        let chose = match envelope.sender_chose() {
            Some(chose) => chose,
            None if carries_content(envelope) => Sealing::Unsealed,
            None => return Ok(()),
        };
        let mut said = self.said.lock().await;
        let at = envelope.created_at();
        let newer = said
            .get(envelope.sender().as_str())
            .is_none_or(|known| known.at <= at);
        if !newer {
            return Ok(());
        }
        let before = said.insert(envelope.sender().as_str().to_owned(), Said { at, chose });
        if before.is_some_and(|before| before.chose == chose) {
            return Ok(());
        }
        state_file::save(&self.path, &said)
    }
}

/// Words, or a step other than a `received`. A notice and a redeem are for hosts to read, and are
/// never sealed.
fn carries_content(envelope: &VerifiedEnvelope) -> bool {
    let body = envelope.body();
    if is_notice_body(body) || redeem_proof_in(body).is_some() {
        return false;
    }
    if !is_step_body(body) {
        return true;
    }
    request_of(envelope)
        .ok()
        .flatten()
        .is_some_and(|step| !step.is_receipt)
}

impl Signet {
    /// Whether this Signet holds the keys an identity names now, to sign for it and open what's sealed
    /// to it.
    pub fn holds_keys_of(&self, identity: &Identity) -> bool {
        identity.sole_key().ok() == Some(&self.key.public_key())
            && identity.seal_key() == Some(&self.seal_key.public_key())
    }

    /// What this agent's owner chose. With no rules yet, the default: sealed.
    pub async fn own_sealing(&self) -> Sealing {
        self.rules.sealing().await
    }

    /// What goes between this agent and `peer`.
    pub async fn sealing_with(&self, peer: &SplintId) -> Sealing {
        Sealing::between(self.own_sealing().await, self.their_sealing.of(peer).await)
    }

    /// Signs a step for `peer`, sealed unless both owners chose unsealed. A `received` carries nothing
    /// an agent wrote, and a guest's link is served by a host, which could take the key from the page,
    /// so neither is ever sealed. A step no reader would take can't be sealed, and is refused as it
    /// would be once signed.
    pub async fn sign_step(
        &self,
        step: CheckedStep,
        peer: &Identity,
        now: u64,
    ) -> Result<SignedEnvelope, ApiError> {
        let who = self.who();
        let signed = if step.kind() == StepKind::Received || peer.is_guest() {
            step.sign(&self.key, &who.identity, now)
        } else {
            match self.seal_for(peer).await? {
                Some(seal_for) => {
                    step.sign_sealed(&self.key, &who.identity, now, &seal_for.borrowed())
                }
                None => step.sign(&self.key, &who.identity, now),
            }
        };
        signed.map_err(|error| match error {
            splint_core::Error::Malformed => Refused::Malformed.into(),
            error => error.into(),
        })
    }

    /// Signs an agent's own words for `peer`, sealed unless both owners chose unsealed.
    pub async fn sign_words(
        &self,
        peer: &Identity,
        body: String,
        now: u64,
        lifetime_secs: u64,
    ) -> Result<SignedEnvelope, splint_core::Error> {
        let who = self.who();
        match self.seal_for(peer).await? {
            Some(seal_for) => sign_sealed_envelope(
                &self.key,
                &who.identity,
                peer.id(),
                body,
                now,
                lifetime_secs,
                &seal_for.borrowed(),
            ),
            None => sign_envelope(
                &self.key,
                &who.identity,
                peer.id(),
                body,
                now,
                lifetime_secs,
            ),
        }
    }

    /// Who to seal to, or `None` for unsealed. An ID with no sealing key can't be sealed to, so
    /// nothing goes rather than going unsealed.
    async fn seal_for(&self, peer: &Identity) -> Result<Option<Sealed>, splint_core::Error> {
        let own = self.own_sealing().await;
        if self.sealing_with(peer.id()).await == Sealing::Unsealed {
            return Ok(None);
        }
        // The key it holds now, by the newest copy of its ID heard of, as after a recovery the old one
        // is gone with the key it replaced. A copy that parts ways with the one held was signed by
        // whoever held a backup, so nothing is sealed to either until an owner chooses.
        let newest = self.contacts.known.newest(peer)?;
        let recipient = newest
            .seal_key()
            .ok_or(splint_core::Error::Malformed)?
            .clone();
        Ok(Some(Sealed {
            recipient,
            own: self.seal_key.public_key(),
            sender_chose: own,
        }))
    }
}

struct Sealed {
    recipient: splint_core::SealPublicKey,
    own: splint_core::SealPublicKey,
    sender_chose: Sealing,
}

impl Sealed {
    fn borrowed(&self) -> SealFor<'_> {
        SealFor {
            recipient: &self.recipient,
            own: &self.own,
            sender_chose: self.sender_chose,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};

    use splint_core::requests::{Chain, Offer, Parties, Party, Schemas, Side};
    use splint_core::rules::{Permissions, Reach, RulesDraft, RulesLimits};
    use splint_core::transport::Scheme;
    use splint_core::{RecoveryRule, SealingKey, SigningKey, unix_now};

    use crate::binding::Registered;
    use crate::budget::Budget;
    use crate::contact_asks::ContactAsks;
    use crate::contacts::{Contacts, Known};
    use crate::host_client::HostClient;
    use crate::requests::Requests;
    use crate::rules::{RulesStore, adopt};
    use crate::who::Who;
    use crate::{changes, grants, requests, seen};

    const LIFETIME: u64 = 3_600;

    struct Them {
        key: SigningKey,
        identity: Identity,
        seal: SealingKey,
    }

    fn them() -> Them {
        let key = SigningKey::generate().unwrap();
        let seal = SealingKey::generate().unwrap();
        let backup = SigningKey::generate().unwrap();
        let identity = Identity::create(
            &key,
            &seal.public_key(),
            RecoveryRule::backup_key(&backup.public_key()),
        )
        .unwrap();
        Them {
            key,
            identity,
            seal,
        }
    }

    fn arrived(them: &Them, signed: &SignedEnvelope, now: u64) -> VerifiedEnvelope {
        VerifiedEnvelope::verify(&signed.compact, &them.identity, now).unwrap()
    }

    /// A `received` goes unsealed whatever its sender's owner chose, and a host can show an old
    /// message again, so neither may change what a contact last said.
    #[test]
    fn only_what_carries_content_and_is_newer_says_what_a_contact_chose() {
        let directory =
            std::env::temp_dir().join(format!("signet-their-sealing-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let said = TheirSealing::load(directory.join("their-sealing.json")).unwrap();
        let (sender, me) = (them(), them());
        let peer = sender.identity.id().clone();
        let sealed = sign_sealed_envelope(
            &sender.key,
            &sender.identity,
            me.identity.id(),
            "are you free".to_owned(),
            100,
            LIFETIME,
            &SealFor {
                recipient: &me.seal.public_key(),
                own: &sender.seal.public_key(),
                sender_chose: Sealing::Sealed,
            },
        )
        .unwrap();
        let plain = |body: String, now: u64| {
            sign_envelope(
                &sender.key,
                &sender.identity,
                me.identity.id(),
                body,
                now,
                LIFETIME,
            )
            .unwrap()
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            said.note(&arrived(&sender, &sealed, 100)).await.unwrap();
            assert_eq!(said.of(&peer).await, Some(Sealing::Sealed));

            let id = sealed.id.as_str();
            let received = plain(
                format!(r#"{{"step":"received","request":"{id}","of":"{id}"}}"#),
                200,
            );
            let received = arrived(&sender, &received, 200);
            assert!(request_of(&received).unwrap().unwrap().is_receipt);
            said.note(&received).await.unwrap();
            assert_eq!(said.of(&peer).await, Some(Sealing::Sealed));

            let words = plain("yes, tuesday".to_owned(), 300);
            said.note(&arrived(&sender, &words, 300)).await.unwrap();
            assert_eq!(said.of(&peer).await, Some(Sealing::Unsealed));

            said.note(&arrived(&sender, &sealed, 400)).await.unwrap();
            assert_eq!(said.of(&peer).await, Some(Sealing::Unsealed));
        });
        std::fs::remove_dir_all(&directory).unwrap();
    }

    fn backup() -> RecoveryRule {
        RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key())
    }

    /// A Signet in a folder of its own, whose owner signed rules choosing `chose`, or signed none.
    async fn signet(chose: Option<Sealing>, name: &str) -> (Signet, std::path::PathBuf) {
        let (signet, directory, _) = signet_and_owner(chose, name).await;
        (signet, directory)
    }

    /// The same, with its owner's key, to sign more for it.
    pub(crate) async fn signet_and_owner(
        chose: Option<Sealing>,
        name: &str,
    ) -> (Signet, std::path::PathBuf, SigningKey) {
        let directory =
            std::env::temp_dir().join(format!("signet-sealing-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = |file: &str| directory.join(file);
        let key = SigningKey::generate().unwrap();
        let seal_key = SealingKey::generate().unwrap();
        let owner_key = SigningKey::generate().unwrap();
        let owner_seal = SealingKey::generate().unwrap().public_key();
        let owner = Identity::create(&owner_key, &owner_seal, backup()).unwrap();
        let identity = Identity::create(&key, &seal_key.public_key(), backup()).unwrap();
        let known = Arc::new(Known::load(path("known.json")).unwrap());
        let seen_changes = Arc::new(changes::Seen::load(path("seen-changes.json")).unwrap());
        let contact_asks = Arc::new(ContactAsks::load(path("contact-asks.json")).unwrap());
        let rules = RulesStore::load(
            path("rules.json"),
            &directory,
            &owner,
            identity.id(),
            known.clone(),
            seen_changes.clone(),
        )
        .unwrap();
        let signet = Signet {
            own_changes: changes::Own::load(
                path("history.json"),
                path("listeners.json"),
                &identity,
            )
            .unwrap(),
            contacts: Contacts::load(
                path("contacts.json"),
                known,
                seen_changes.clone(),
                contact_asks.clone(),
            )
            .unwrap(),
            rules,
            who: RwLock::new(Arc::new(Who {
                identity: identity.clone(),
                owner: owner.clone(),
                binding: String::new(),
            })),
            key,
            seal_key,
            who_path: path("who.json"),
            changing_who: Mutex::new(()),
            started_at: "me~host.example".to_owned(),
            address: RwLock::new("me~host.example".to_owned()),
            api_token: String::new(),
            host: HostClient {
                domain: "host.example".to_owned(),
                scheme: Scheme::Https,
                http: reqwest::Client::new(),
                closing: Default::default(),
            },
            seen: seen::Seen::load(path("seen.json")).unwrap(),
            requests: Requests {
                store: requests::store::Store::load(path("requests.json")).unwrap(),
                person_texts: requests::person_text::Waiting::load(
                    path("person-texts.json"),
                    path("person-texts-taken.json"),
                )
                .unwrap(),
                where_paid: requests::payments::WherePaid::load(path("where-paid.json")).unwrap(),
                held_opens: requests::held_opens::HeldOpens::load(path("held-opens.json")).unwrap(),
                owner_token: None,
                types: requests::types::AgreedTypes::default(),
                refused: requests::refusals::Refusals::load(path("refused.json")).unwrap(),
                guest_steps_read: 0.into(),
            },
            registered: Registered::new(String::new()),
            budget: Budget::load(path("budget.json")).unwrap(),
            invites: crate::invites::Invites::load(
                path("invites-sent.json"),
                path("invites-pending.json"),
            )
            .unwrap(),
            grants: grants::Grants::load(path("grants.json")).unwrap(),
            seen_changes,
            contact_asks,
            asks: crate::asks::Asks::load(path("asks.json")).unwrap(),
            their_sealing: TheirSealing::load(path("their-sealing.json")).unwrap(),
            activity: crate::activity::Activity::load(directory.join("wakes.json")).unwrap(),
            delegation: crate::delegation::Delegation::load(&directory).unwrap(),
            arrivals: crate::arrivals::Arrivals::load(
                directory.join("arrivals.json"),
                directory.join("arrivals-notes.json"),
            )
            .unwrap(),
            owner_signed: crate::owner_relay::TakenOnce::load(path("owner-signed-taken.json"))
                .unwrap(),
            retired: crate::retired::Retired::kept_at(path("retirement.json")),
            carried: crate::carried::Carried::load(directory.join("carried-mail.json")).unwrap(),
            sent: crate::sent::Sent::load(directory.join("sent.json")).unwrap(),
            receipts: crate::receipts::Receipts::load(directory.join("receipts.json")).unwrap(),
        };
        if let Some(sealing) = chose {
            let draft = RulesDraft {
                paused: false,
                reach: Reach::default(),
                permissions: Permissions::default(),
                changes: splint_core::changes::ChangeRules::default(),
                sealing,
                delegation: None,
                ends_at: None,
                contacts: Vec::new(),
                invites: Vec::new(),
                limits: RulesLimits {
                    new_requests_per_contact_per_day: 3,
                    open_requests_per_contact: 3,
                    open_approvals: 10,
                    new_from_others_per_day: 50,
                    texts_per_contact_per_day: 20,
                    agreed_texts_per_day: None,
                    agreed_new_requests_per_day: None,
                    sends_per_hour: None,
                    sends_per_day: None,
                },
            };
            let signed = draft
                .sign(&owner_key, owner.id(), identity.id(), 1, unix_now())
                .unwrap();
            adopt(&signet, &signed, splint_core::unix_now())
                .await
                .map_err(|_| "refused")
                .unwrap();
        }
        (signet, directory, owner_key)
    }

    /// Core's own types, which every chain has.
    fn schemas() -> Schemas {
        Schemas::default()
    }

    /// Core's plain conversation, whose `open` names no type.
    fn chat_offer(now: u64) -> Offer {
        let deadline = (now / 3600 + 2) * 3600;
        serde_json::from_value(serde_json::json!({
            "terms": {},
            "deadline": deadline,
            "supersedes": null,
        }))
        .unwrap()
    }

    fn open_to(to: &SplintId, now: u64) -> CheckedStep {
        CheckedStep::open(chat_offer(now), &schemas(), to, now).unwrap()
    }

    /// Whether `signed`, as its recipient's Signet would take it in, is sealed, and if so what its
    /// sender said its owner chose. A sealed one has to open with the recipient's key.
    fn as_received(
        signed: &SignedEnvelope,
        sender: &Identity,
        recipient: &Them,
        now: u64,
    ) -> Option<Sealing> {
        let arrived = VerifiedEnvelope::verify(&signed.compact, sender, now).unwrap();
        let chose = arrived.sender_chose();
        let opened = arrived
            .open(recipient.identity.id(), &recipient.seal)
            .unwrap();
        assert_eq!(opened.sender_chose(), chose);
        chose
    }

    /// Sealed is the default and the stricter side wins: steps and words to a contact go sealed unless
    /// both owners chose unsealed, sealed to that contact's key, saying what this owner chose.
    #[tokio::test]
    async fn steps_and_words_go_unsealed_only_when_both_owners_chose_it() {
        use Sealing::{Sealed, Unsealed};
        // What this owner signed (`None`: no rules yet), what the contact last said, and what a sealed
        // message says this owner chose (`None`: it goes unsealed).
        for (mine, theirs, expected) in [
            (None, None, Some(Sealed)),
            (Some(Sealed), None, Some(Sealed)),
            (Some(Unsealed), None, Some(Unsealed)),
            (Some(Unsealed), Some(Sealed), Some(Unsealed)),
            (Some(Sealed), Some(Unsealed), Some(Sealed)),
            (None, Some(Unsealed), Some(Sealed)),
            (Some(Unsealed), Some(Unsealed), None),
        ] {
            let name = format!("{mine:?}-{theirs:?}");
            let (signet, directory) = signet(mine, &name).await;
            let me = signet.who().identity.clone();
            let peer = them();
            let now = unix_now();
            if let Some(theirs) = theirs {
                let words = |body: &str| match theirs {
                    Sealed => sign_sealed_envelope(
                        &peer.key,
                        &peer.identity,
                        me.id(),
                        body.to_owned(),
                        now,
                        LIFETIME,
                        &SealFor {
                            recipient: &signet.seal_key.public_key(),
                            own: &peer.seal.public_key(),
                            sender_chose: Sealed,
                        },
                    ),
                    Unsealed => sign_envelope(
                        &peer.key,
                        &peer.identity,
                        me.id(),
                        body.to_owned(),
                        now,
                        LIFETIME,
                    ),
                };
                let heard =
                    VerifiedEnvelope::verify(&words("hi").unwrap().compact, &peer.identity, now)
                        .unwrap();
                signet.their_sealing.note(&heard).await.unwrap();
            }
            assert_eq!(
                signet.sealing_with(peer.identity.id()).await,
                expected.map_or(Unsealed, |_| Sealed),
                "{name}"
            );
            let words = signet
                .sign_words(&peer.identity, "are you free".to_owned(), now, LIFETIME)
                .await
                .unwrap();
            assert_eq!(as_received(&words, &me, &peer, now), expected, "{name}");
            let step = signet
                .sign_step(open_to(peer.identity.id(), now), &peer.identity, now)
                .await
                .map_err(|_| "refused")
                .unwrap();
            assert_eq!(as_received(&step, &me, &peer, now), expected, "{name}");
            std::fs::remove_dir_all(&directory).unwrap();
        }
    }

    /// A `received` carries nothing an agent wrote, and a guest's link is served by a host, so both go
    /// unsealed whatever was chosen. A guest has no key to seal words to, so words to one are refused
    /// rather than sent unsealed.
    #[tokio::test]
    async fn a_received_and_a_step_to_a_guest_go_unsealed_and_words_to_a_guest_dont_go() {
        let (signet, directory) = signet(Some(Sealing::Sealed), "exceptions").await;
        let me = signet.who().identity.clone();
        let peer = them();
        let now = unix_now();
        let party = |agent: &Identity| Party {
            agent: agent.clone(),
            owner: agent.clone(),
            binding: String::new(),
        };
        let open = open_to(me.id(), now)
            .sign_sealed(
                &peer.key,
                &peer.identity,
                now,
                &SealFor {
                    recipient: &signet.seal_key.public_key(),
                    own: &peer.seal.public_key(),
                    sender_chose: Sealing::Sealed,
                },
            )
            .unwrap();
        let heard = VerifiedEnvelope::verify(&open.compact, &peer.identity, now)
            .unwrap()
            .open(me.id(), &signet.seal_key)
            .unwrap();
        signet.their_sealing.note(&heard).await.unwrap();
        let parties = Parties {
            requester: party(&peer.identity),
            recipient: party(&me),
        };
        let chain = Chain::walk(parties, schemas(), &[heard.kept()]).unwrap();
        let receipt = chain.receipt(Side::Recipient, &open.id).unwrap();
        let received = signet
            .sign_step(receipt, &peer.identity, now)
            .await
            .map_err(|_| "refused")
            .unwrap();
        assert_eq!(as_received(&received, &me, &peer, now), None);
        // The same Signet seals what else it says to this contact.
        let step = signet
            .sign_step(open_to(peer.identity.id(), now), &peer.identity, now)
            .await
            .map_err(|_| "refused")
            .unwrap();
        assert_eq!(as_received(&step, &me, &peer, now), Some(Sealing::Sealed));

        let guest = Identity::guest(&SigningKey::generate().unwrap().public_key()).unwrap();
        let to_guest = signet
            .sign_step(open_to(guest.id(), now), &guest, now)
            .await
            .map_err(|_| "refused")
            .unwrap();
        let arrived = VerifiedEnvelope::verify(&to_guest.compact, &me, now).unwrap();
        assert!(!arrived.is_sealed());
        assert!(
            signet
                .sign_words(&guest, "hello".to_owned(), now, LIFETIME)
                .await
                .is_err()
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[tokio::test]
    async fn a_signet_holds_the_keys_of_its_own_id_only() {
        let (signet, directory) = signet(None, "holds").await;
        let me = signet.who().identity.clone();
        assert!(signet.holds_keys_of(&me));
        let with_other_seal = Identity::create(
            &signet.key,
            &SealingKey::generate().unwrap().public_key(),
            backup(),
        )
        .unwrap();
        assert!(!signet.holds_keys_of(&with_other_seal));
        let with_other_key = Identity::create(
            &SigningKey::generate().unwrap(),
            &signet.seal_key.public_key(),
            backup(),
        )
        .unwrap();
        assert!(!signet.holds_keys_of(&with_other_key));
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

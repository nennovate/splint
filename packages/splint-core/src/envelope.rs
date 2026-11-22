use std::fmt;

use aws_lc_rs::digest;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::identity::hex;
use crate::sealing::{
    self, Bound, OPENING_SEPARATOR, Outside, SealFor, Sealing, SealingKey, Slot, check_opening,
    open_body, seal_body,
};
use crate::{
    CLOCK_TOLERANCE_SECS, Error, Identity, MAX_MESSAGE_LIFETIME_SECS, SigningKey, SplintId, jws,
};

const ENVELOPE_TYPE: &str = "splint-envelope";
const ENVELOPE_VERSION: u8 = 1;
const NONCE_LEN: usize = 16;
const MESSAGE_ID_HEX_LEN: usize = 64;

/// Hash of the signed payload. It never covers the signature, because ECDSA signatures are
/// randomized and can be altered, while the ID has to stay the same across retries.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(String);

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl MessageId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn of(payload: &[u8]) -> Self {
        Self(hex(digest::digest(&digest::SHA256, payload).as_ref()))
    }

    /// A hash in lowercase hex. An ID in a signed field that nothing else reads could hold anything,
    /// so it's checked wherever one comes from a counterparty, or from an agent naming one to ack.
    pub fn is_well_formed(&self) -> bool {
        self.0.len() == MESSAGE_ID_HEX_LEN
            && self
                .0
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    v: u8,
    sender: SplintId,
    recipient: SplintId,
    body: String,
    created_at: u64,
    expires_at: u64,
    nonce: String,
}

impl Payload {
    /// Spare bytes or another field order would be a channel past a host's checks, and would give
    /// one message many IDs. Only what this code would have written itself is accepted.
    fn has_one_encoding(&self, bytes: &[u8]) -> bool {
        serde_json::to_vec(self).is_ok_and(|encoded| encoded == bytes)
    }

    fn dates_fit(&self, now: u64) -> Result<(), Error> {
        if now >= self.expires_at {
            return Err(Error::Expired);
        }
        if self.created_at > now.saturating_add(CLOCK_TOLERANCE_SECS) {
            return Err(Error::FromTheFuture);
        }
        Ok(())
    }

    /// Nothing else reads these two fields' contents, so an unchecked one could hold anything.
    fn fields_fit(&self) -> bool {
        let nonce_fits = self.nonce.is_empty()
            || jws::decode(&self.nonce).is_ok_and(|nonce| nonce.len() == NONCE_LEN);
        nonce_fits && self.recipient.is_well_formed()
    }
}

/// A signed envelope. `compact` is what goes over the wire. `kept` is what its sender's Signet keeps:
/// the same, and for a sealed body, the salt and body after it, so the sender can read it back and
/// show it to its owner without the key.
pub struct SignedEnvelope {
    pub compact: String,
    pub kept: String,
    pub id: MessageId,
    pub expires_at: u64,
}

/// Signs an unsealed envelope, which both hosts can read.
pub fn sign_envelope(
    key: &SigningKey,
    sender: &Identity,
    recipient: &SplintId,
    body: String,
    now: u64,
    lifetime_secs: u64,
) -> Result<SignedEnvelope, Error> {
    sign_with_nonce(key, sender, recipient, body, now, lifetime_secs, None, None)
}

/// Seals the body to the recipient's key and the sender's own, then signs the envelope.
pub fn sign_sealed_envelope(
    key: &SigningKey,
    sender: &Identity,
    recipient: &SplintId,
    body: String,
    now: u64,
    lifetime_secs: u64,
    seal_for: &SealFor,
) -> Result<SignedEnvelope, Error> {
    let nonce = None;
    sign_with_nonce(
        key,
        sender,
        recipient,
        body,
        now,
        lifetime_secs,
        nonce,
        Some(seal_for),
    )
}

/// With no nonce given, this makes a random one. Anything holding a key can sign anything with it, so
/// this is public for tests that act as a stolen key, and what a reader checks is all that counts.
#[allow(clippy::too_many_arguments)]
pub fn sign_with_nonce(
    key: &SigningKey,
    sender: &Identity,
    recipient: &SplintId,
    body: String,
    now: u64,
    lifetime_secs: u64,
    nonce: Option<String>,
    seal_for: Option<&SealFor>,
) -> Result<SignedEnvelope, Error> {
    let nonce = match nonce {
        Some(nonce) => nonce,
        None => random_nonce()?,
    };
    let expires_at = now.saturating_add(lifetime_secs);
    let (body, opening) = match seal_for {
        Some(seal_for) => {
            let bound = Bound {
                sender: sender.id(),
                recipient,
                created_at: now,
                expires_at,
                nonce: &nonce,
            };
            let sealed = seal_body(&body, &bound, seal_for)?;
            (sealed.body, Some(sealed.opening))
        }
        None => (body, None),
    };
    let payload = serde_json::to_vec(&Payload {
        v: ENVELOPE_VERSION,
        sender: sender.id().clone(),
        recipient: recipient.clone(),
        body,
        created_at: now,
        expires_at,
        nonce,
    })
    .map_err(|_| Error::Malformed)?;
    let compact = jws::sign(key, ENVELOPE_TYPE, &payload)?;
    Ok(SignedEnvelope {
        kept: kept_form(&compact, opening.as_deref()),
        compact,
        id: MessageId::of(&payload),
        expires_at,
    })
}

fn kept_form(compact: &str, opening: Option<&str>) -> String {
    match opening {
        Some(opening) => format!("{compact}{OPENING_SEPARATOR}{opening}"),
        None => compact.to_owned(),
    }
}

/// The compact form and any opening after it.
fn split_kept(kept: &str) -> (&str, Option<&str>) {
    match kept.split_once(OPENING_SEPARATOR) {
        Some((compact, opening)) => (compact, Some(opening)),
        None => (kept, None),
    }
}

/// A nonce an `open` can be signed with later. See `Chain::open_draft`.
pub fn random_nonce() -> Result<String, Error> {
    let mut nonce = [0_u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| Error::Crypto)?;
    Ok(jws::encode(&nonce))
}

/// Who an envelope says sent it, before any verification. Use this only to look up the
/// identity to pass to [`VerifiedEnvelope::verify`], and never trust it otherwise.
pub fn claimed_sender(compact: &str) -> Result<SplintId, Error> {
    let (compact, _) = split_kept(compact);
    let payload = jws::unverified_payload(compact, ENVELOPE_TYPE)?;
    let payload: Payload = serde_json::from_slice(&payload).map_err(|_| Error::Malformed)?;
    Ok(payload.sender)
}

/// Whether an envelope's dates fit this clock, by what it says of them, before any verification:
/// [`Error::Expired`] and [`Error::FromTheFuture`] as [`VerifiedEnvelope::verify`] would give them. Only
/// for giving up on a row, which whoever handed it over could have left out anyway, and never for
/// accepting one.
pub fn claimed_dates_fit(compact: &str, now: u64) -> Result<(), Error> {
    let (compact, _) = split_kept(compact);
    let payload = jws::unverified_payload(compact, ENVELOPE_TYPE)?;
    let payload: Payload = serde_json::from_slice(&payload).map_err(|_| Error::Malformed)?;
    payload.dates_fit(now)
}

/// The ID of the message an envelope carries, before any verification. A sending host's proof names
/// it, so that proof can be checked before the envelope is. [`VerifiedEnvelope::verify`] gives this
/// same ID for anything it accepts.
pub fn claimed_message_id(compact: &str) -> Result<MessageId, Error> {
    let (compact, _) = split_kept(compact);
    Ok(MessageId::of(&jws::unverified_payload(
        compact,
        ENVELOPE_TYPE,
    )?))
}

/// What a sealed envelope carried as it came, and once it's opened, how.
struct SealedState {
    raw: String,
    outside: Outside,
    sender_chose: Sealing,
    opening: Option<String>,
}

/// An envelope whose signature, sender and dates have been checked. The only way to get one
/// is to pass verification, so code that takes this type can't receive unverified bytes. The repo's
/// rules check keeps the ways to make one to the verifying calls here, and `open`, which takes one:
///
/// ```compile_fail
/// # use splint_core::{MessageId, VerifiedEnvelope};
/// # fn made_up(id: MessageId) -> VerifiedEnvelope {
/// VerifiedEnvelope { id, compact: String::new(), payload: todo!(), sealed: None }
/// # }
/// ```
pub struct VerifiedEnvelope {
    id: MessageId,
    compact: String,
    payload: Payload,
    sealed: Option<Box<SealedState>>,
}

impl VerifiedEnvelope {
    /// For anything arriving now, so it has to be signed by the key this ID holds now. A key given
    /// up in a recovery signs nothing new. This is what comes over a network, so a body's opening
    /// is refused here: nothing that carries one should ever have left the Signet that kept it.
    pub fn verify(compact: &str, sender: &Identity, now: u64) -> Result<Self, Error> {
        if compact.contains(OPENING_SEPARATOR) {
            return Err(Error::Malformed);
        }
        Self::verify_kept(compact, sender, now)
    }

    /// The same for what a Signet kept, which may carry a sealed body's opening.
    pub fn verify_kept(kept: &str, sender: &Identity, now: u64) -> Result<Self, Error> {
        let (compact, opening) = split_kept(kept);
        let bytes = sender.verify(compact, ENVELOPE_TYPE)?;
        let mut envelope = Self::checked(compact, &bytes, sender)?;
        envelope.payload.dates_fit(now)?;
        if let Some(opening) = opening {
            envelope.take_opening(opening)?;
        }
        Ok(envelope)
    }

    /// Checks everything but the dates, for re-reading a request's chain, whose steps stay part of
    /// its history after they expire, under any key the sender has held. Anything arriving from a
    /// network goes through [`Self::verify`]. A sealed step is read with the opening kept after it.
    pub fn verify_ignoring_clock(kept: &str, sender: &Identity) -> Result<Self, Error> {
        let (compact, opening) = split_kept(kept);
        let bytes = sender.verify_under_any_key(compact, ENVELOPE_TYPE)?;
        let mut envelope = Self::checked(compact, &bytes, sender)?;
        if let Some(opening) = opening {
            envelope.take_opening(opening)?;
        }
        Ok(envelope)
    }

    /// Whether a key this ID has held signed this, for telling a key given up from one a reader hasn't
    /// heard of yet. The first ends there. The second waits for the history that names it.
    pub fn signed_by_a_key_of(compact: &str, sender: &Identity) -> bool {
        let (compact, _) = split_kept(compact);
        sender.verify_under_any_key(compact, ENVELOPE_TYPE).is_ok()
    }

    fn checked(compact: &str, bytes: &[u8], sender: &Identity) -> Result<Self, Error> {
        let payload: Payload = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        if payload.v != ENVELOPE_VERSION {
            return Err(Error::Malformed);
        }
        if &payload.sender != sender.id() {
            return Err(Error::WrongSigner);
        }
        if !payload.has_one_encoding(bytes) || !payload.fields_fit() {
            return Err(Error::Malformed);
        }
        if payload.expires_at <= payload.created_at
            || payload.expires_at.saturating_sub(payload.created_at) > MAX_MESSAGE_LIFETIME_SECS
        {
            return Err(Error::Malformed);
        }
        let sealed = sealing::outside(&payload.body)?.map(|(outside, sender_chose)| {
            Box::new(SealedState {
                raw: payload.body.clone(),
                outside,
                sender_chose,
                opening: None,
            })
        });
        Ok(Self {
            id: MessageId::of(bytes),
            compact: compact.to_owned(),
            payload,
            sealed,
        })
    }

    fn bound(&self) -> Bound<'_> {
        Bound {
            sender: &self.payload.sender,
            recipient: &self.payload.recipient,
            created_at: self.payload.created_at,
            expires_at: self.payload.expires_at,
            nonce: &self.payload.nonce,
        }
    }

    fn take_opening(&mut self, opening: &str) -> Result<(), Error> {
        let Some(sealed) = &mut self.sealed else {
            return Err(Error::Malformed);
        };
        self.payload.body = check_opening(&sealed.raw, opening)?;
        sealed.opening = Some(opening.to_owned());
        Ok(())
    }

    /// Opens a sealed body with this agent's sealing key, as its recipient or as its sender reading its
    /// own copy back, and checks it's the body the signature committed to, with the outside a host
    /// went by saying the same. An unsealed body is as it was.
    pub fn open(mut self, me: &SplintId, key: &SealingKey) -> Result<Self, Error> {
        let slot = if self.payload.recipient == *me {
            Slot::To
        } else if self.payload.sender == *me {
            Slot::Own
        } else {
            return Err(Error::WrongRedeemer);
        };
        let opened = match &self.sealed {
            Some(sealed) if sealed.opening.is_none() => {
                open_body(&sealed.raw, &self.bound(), slot, key)?
            }
            _ => return Ok(self),
        };
        self.payload.body = opened.body;
        if let Some(sealed) = &mut self.sealed {
            sealed.opening = Some(opened.opening);
        }
        Ok(self)
    }

    /// Whether its body was sealed.
    pub fn is_sealed(&self) -> bool {
        self.sealed.is_some()
    }

    /// What a sealed body's sender says its owner chose. A reader seals back unless both chose unsealed.
    pub fn sender_chose(&self) -> Option<Sealing> {
        self.sealed.as_ref().map(|sealed| sealed.sender_chose)
    }

    /// What a host sees of a sealed body it can't open. Once a body is open, its own fields count.
    pub fn outside(&self) -> Option<&Outside> {
        self.sealed
            .as_ref()
            .filter(|sealed| sealed.opening.is_none())
            .map(|sealed| &sealed.outside)
    }

    /// What a Signet keeps: the compact form, and an opened body's salt and body after it. This never
    /// goes to a host, and [`Self::verify`] refuses it.
    pub fn kept(&self) -> String {
        let opening = self
            .sealed
            .as_ref()
            .and_then(|sealed| sealed.opening.as_deref());
        kept_form(&self.compact, opening)
    }

    pub fn id(&self) -> &MessageId {
        &self.id
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn sender(&self) -> &SplintId {
        &self.payload.sender
    }

    pub fn recipient(&self) -> &SplintId {
        &self.payload.recipient
    }

    pub fn body(&self) -> &str {
        &self.payload.body
    }

    pub fn created_at(&self) -> u64 {
        self.payload.created_at
    }

    pub fn expires_at(&self) -> u64 {
        self.payload.expires_at
    }

    pub(crate) fn nonce(&self) -> &str {
        &self.payload.nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;
    const LIFETIME: u64 = 3_600;

    fn agent() -> (SigningKey, Identity) {
        let key = SigningKey::generate().unwrap();
        let identity = crate::test_identity(&key);
        (key, identity)
    }

    fn sealed(key: &SigningKey, sender: &Identity, recipient: &Identity) -> SignedEnvelope {
        sign_envelope(
            key,
            sender,
            recipient.id(),
            "hello".to_owned(),
            NOW,
            LIFETIME,
        )
        .unwrap()
    }

    /// A genuine, correctly signed envelope over 256 KiB is refused and one at it is read, so a sender
    /// can't make a reader decode and verify an object of any size, and a cap that drifts is noticed.
    #[test]
    fn a_genuine_envelope_over_the_size_cap_is_refused() {
        const CAP: usize = 256 * 1024;
        let (key, ana) = agent();
        let (_, ben) = agent();
        let signed = |body_len: usize| {
            sign_envelope(&key, &ana, ben.id(), "a".repeat(body_len), NOW, LIFETIME)
                .unwrap()
                .compact
        };
        // The longest body whose envelope fits, found by halving; base64 skips some lengths.
        let (mut fits, mut over) = (0, CAP);
        while over - fits > 1 {
            let middle = fits + (over - fits) / 2;
            if signed(middle).len() <= CAP {
                fits = middle;
            } else {
                over = middle;
            }
        }
        let (largest, smallest_over) = (signed(fits), signed(over));
        assert!(largest.len() > CAP - 3 && smallest_over.len() <= CAP + 3);
        assert!(VerifiedEnvelope::verify(&largest, &ana, NOW).is_ok());
        assert_eq!(
            VerifiedEnvelope::verify(&smallest_over, &ana, NOW).err(),
            Some(Error::Malformed)
        );
    }

    /// A sending host's proof is checked against this before the envelope is, so it has to be the ID
    /// verifying gives, sealed or not.
    #[test]
    fn the_id_an_envelope_claims_is_the_one_it_verifies_with() {
        let (key, ana) = agent();
        let (_, ben) = agent();
        let to = SealingKey::generate().unwrap().public_key();
        let sealed_one = sign_sealed_envelope(
            &key,
            &ana,
            ben.id(),
            "hello".to_owned(),
            NOW,
            LIFETIME,
            &SealFor {
                recipient: &to,
                own: &to,
                sender_chose: Sealing::Sealed,
            },
        )
        .unwrap();
        for signed in [sealed(&key, &ana, &ben), sealed_one] {
            let verified = VerifiedEnvelope::verify(&signed.compact, &ana, NOW).unwrap();
            assert_eq!(&claimed_message_id(&signed.compact).unwrap(), verified.id());
            assert_eq!(verified.id(), &signed.id);
        }
    }

    /// What a Signet keeps of a sealed body, with the opening that proves it, never comes in from a
    /// network, and is read back only as it was sealed.
    #[test]
    fn a_kept_opening_is_refused_from_a_network_and_read_back_once() {
        let (key, ana) = agent();
        let (_, ben) = agent();
        let (to, own) = (
            SealingKey::generate().unwrap(),
            SealingKey::generate().unwrap(),
        );
        let signed = sign_sealed_envelope(
            &key,
            &ana,
            ben.id(),
            "hello".to_owned(),
            NOW,
            LIFETIME,
            &SealFor {
                recipient: &to.public_key(),
                own: &own.public_key(),
                sender_chose: Sealing::Sealed,
            },
        )
        .unwrap();
        let arrived = VerifiedEnvelope::verify(&signed.compact, &ana, NOW).unwrap();
        assert!(arrived.outside().is_some());
        assert_ne!(arrived.body(), "hello");
        let stranger = SealingKey::generate().unwrap();
        let (_, someone) = agent();
        assert_eq!(
            VerifiedEnvelope::verify(&signed.compact, &ana, NOW)
                .unwrap()
                .open(someone.id(), &stranger)
                .err(),
            Some(Error::WrongRedeemer)
        );
        let opened = arrived.open(ben.id(), &to).unwrap();
        assert_eq!(opened.body(), "hello");
        assert!(opened.outside().is_none());
        let kept = opened.kept();
        assert_ne!(kept, signed.compact);
        assert_eq!(kept, signed.kept);
        assert_eq!(
            VerifiedEnvelope::verify(&kept, &ana, NOW).err(),
            Some(Error::Malformed)
        );
        let read_back = VerifiedEnvelope::verify_kept(&kept, &ana, NOW).unwrap();
        assert_eq!(read_back.body(), "hello");
        assert_eq!(read_back.kept(), kept);
        // Opened already, it isn't opened again, and a second opening after it isn't an opening.
        assert_eq!(read_back.open(ben.id(), &to).unwrap().body(), "hello");
        let opening = kept.rsplit_once(OPENING_SEPARATOR).unwrap().1;
        assert_eq!(
            VerifiedEnvelope::verify_kept(
                &format!("{kept}{OPENING_SEPARATOR}{opening}"),
                &ana,
                NOW
            )
            .err(),
            Some(Error::Malformed)
        );
        // An unsealed body has nothing to open.
        let plain = sealed(&key, &ana, &ben);
        assert_eq!(
            VerifiedEnvelope::verify_kept(
                &format!("{}{OPENING_SEPARATOR}{opening}", plain.compact),
                &ana,
                NOW
            )
            .err(),
            Some(Error::Malformed)
        );
    }

    /// What a lying sender's Signet can sign: a sealed body whose outside says one thing to the hosts
    /// and whose inside is another, or that opens to something other than what it committed to. Each
    /// gets past a host, which can't open it, and stops at the reader that does.
    #[test]
    fn a_sealed_body_that_lies_gets_past_a_host_but_not_the_reader_who_opens_it() {
        use crate::requests::StepKind;
        use crate::sealing::tests::seal_lying;
        let (key, ana) = agent();
        let (_, ben) = agent();
        let (to, own) = (
            SealingKey::generate().unwrap(),
            SealingKey::generate().unwrap(),
        );
        let seal_for = SealFor {
            recipient: &to.public_key(),
            own: &own.public_key(),
            sender_chose: Sealing::Sealed,
        };
        let words = Outside {
            proposes: None,
            step: None,
            request: None,
            opens: None,
            approval: false,
            delegation: None,
            person_text: false,
        };
        let a_step = Outside {
            step: Some(StepKind::Progress),
            request: Some(MessageId::of(b"request")),
            ..words.clone()
        };
        for (inside, committed, outside) in [
            ("plain words", "plain words", a_step),
            ("yes", "no", words.clone()),
            ("yes", "yes", words),
        ] {
            let nonce = random_nonce().unwrap();
            let bound = Bound {
                sender: ana.id(),
                recipient: ben.id(),
                created_at: NOW,
                expires_at: NOW + LIFETIME,
                nonce: &nonce,
            };
            let body = seal_lying(inside, committed, outside.clone(), &bound, &seal_for);
            let signed = sign_with_nonce(
                &key,
                &ana,
                ben.id(),
                body,
                NOW,
                LIFETIME,
                Some(nonce.clone()),
                None,
            )
            .unwrap();
            let arrived = || VerifiedEnvelope::verify(&signed.compact, &ana, NOW).unwrap();
            assert_eq!(arrived().outside(), Some(&outside));
            let as_ben = arrived().open(ben.id(), &to);
            let as_ana = arrived().open(ana.id(), &own);
            let honest = crate::requests::outside_of(inside).ok() == Some(outside);
            if inside == committed && honest {
                assert_eq!(as_ben.unwrap().body(), inside);
                assert_eq!(as_ana.unwrap().body(), inside);
            } else {
                assert_eq!(as_ben.err(), Some(Error::ProofMismatch), "{inside}");
                assert_eq!(as_ana.err(), Some(Error::ProofMismatch), "{inside}");
            }
        }
    }

    /// A Signet reads back what it kept with the opening after it, and anything it shows an owner comes
    /// from there. An opening that isn't the body the signature committed to is refused, whether it's
    /// another body or the same body under another salt.
    #[test]
    fn a_kept_opening_that_isnt_the_signed_body_is_refused() {
        let (key, ana) = agent();
        let (_, ben) = agent();
        let seal = SealingKey::generate().unwrap();
        let seal_for = SealFor {
            recipient: &seal.public_key(),
            own: &seal.public_key(),
            sender_chose: Sealing::Sealed,
        };
        let sign = |body: &str| {
            sign_sealed_envelope(
                &key,
                &ana,
                ben.id(),
                body.to_owned(),
                NOW,
                LIFETIME,
                &seal_for,
            )
            .unwrap()
        };
        let signed = sign("yes");
        let opening = |kept: &str| kept.rsplit_once(OPENING_SEPARATOR).unwrap().1.to_owned();
        let mut changed = jws::decode(&opening(&signed.kept)).unwrap();
        changed.pop();
        changed.extend_from_slice(b"o");
        let mut salt_changed = jws::decode(&opening(&signed.kept)).unwrap();
        if let Some(first) = salt_changed.first_mut() {
            *first ^= 1;
        }
        let other_salt = opening(&sign("yes").kept);
        for other in [
            jws::encode(&changed),
            jws::encode(&salt_changed),
            other_salt,
        ] {
            let kept = format!("{}{OPENING_SEPARATOR}{other}", signed.compact);
            assert_eq!(
                VerifiedEnvelope::verify_kept(&kept, &ana, NOW).err(),
                Some(Error::ProofMismatch)
            );
            assert_eq!(
                VerifiedEnvelope::verify_ignoring_clock(&kept, &ana).err(),
                Some(Error::ProofMismatch)
            );
        }
        let kept = VerifiedEnvelope::verify_kept(&signed.kept, &ana, NOW).unwrap();
        assert_eq!(kept.body(), "yes");
    }
}

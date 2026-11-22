//! Where an owner gets paid, and the steps that ask for and acknowledge a payment once a request is
//! completed. See "Payments" in `docs/protocol.md`.
//!
//! Splint holds no money and nothing that can spend it. The money moves on a rail the payer already
//! uses. What Splint adds is that the place to pay is one the payee's owner signed, so a fooled agent or
//! someone posing as the payee can't slip in their own, and that the amount comes from the agreed terms
//! by code, never from what an agent typed.

use serde::{Deserialize, Serialize};

use super::schema::{FieldValue, Schema, Word};
use super::{Refused, Side, Terms};
use crate::{Identity, MessageId, SigningKey, SplintId, jws};

const WHERE_PAID_TYPE: &str = "splint-where-paid";
const WHERE_PAID_VERSION: u8 = 1;
/// A few rails at once is all a person needs, and each one is a choice a fooled agent makes.
pub const MAX_PLACES: usize = 4;
/// Room for a statement on a step beside the rest, inside the 4 KiB a step has.
const MAX_STATEMENT_BYTES: usize = 1536;
const MAX_PAGE_CHARS: usize = 300;
const MAX_LIGHTNING_ADDRESS_CHARS: usize = 320;
const MAX_OFFER_CHARS: usize = 600;
const MIN_OFFER_CHARS: usize = 20;
/// How many times a payee's agent can ask for one value: once, and twice more for another place.
pub const ASKS_PER_VALUE: usize = 3;
/// A place to pay first seen this recently gets a warning, as a bank warns of a new payee.
pub const CHANGED_WITHIN_SECS: u64 = 7 * 24 * 60 * 60;

/// One rail and where on it. The kinds are generic: a vendor's name never appears in core.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Place {
    /// An https page that takes a payment, such as a payment link.
    PaymentPage { url: String },
    /// A Lightning address, `name@domain`, or a BOLT12 offer, `lno1...`.
    Lightning { to: String },
    /// An address on a chain: the chain as CAIP-2 names it, the address, and the asset as a word.
    Onchain {
        chain: String,
        address: String,
        asset: Word,
    },
}

impl Place {
    /// Code checks the shape of each kind, so no prose, login or hidden character can ride on one.
    pub fn fits(&self) -> bool {
        match self {
            Self::PaymentPage { url } => is_payment_page(url),
            // An `lno1` start is an offer's alone, as every reader takes it, so one string can't
            // read as an address to one reader and be refused by another.
            Self::Lightning { to } if to.starts_with("lno1") => is_bolt12_offer(to),
            Self::Lightning { to } => is_lightning_address(to),
            Self::Onchain { chain, address, .. } => {
                is_caip2_chain(chain) && is_chain_address(address)
            }
        }
    }

    /// A payment on these rails can't be taken back once made: the payer has no chargeback.
    pub fn irreversible(&self) -> bool {
        matches!(self, Self::Lightning { .. } | Self::Onchain { .. })
    }

    /// Its own word, as a view names it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PaymentPage { .. } => "payment_page",
            Self::Lightning { .. } => "lightning",
            Self::Onchain { .. } => "onchain",
        }
    }

    /// Where to pay, as one string, which is what a person checks and what a text is compared with.
    pub fn destination(&self) -> String {
        match self {
            Self::PaymentPage { url } => url.clone(),
            Self::Lightning { to } => to.clone(),
            Self::Onchain { chain, address, .. } => format!("{chain}:{address}"),
        }
    }

    /// The asset, for an address on a chain.
    pub fn asset(&self) -> Option<&str> {
        match self {
            Self::Onchain { asset, .. } => Some(asset.as_str()),
            _ => None,
        }
    }
}

/// `https://`, a DNS name and an optional port, then a path or query. A login in the address (`@`
/// before the host) is refused, so no password can sit in one, and so is an IP address or a name with
/// no dot, which no public payment page has.
fn is_payment_page(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    if url.chars().count() > MAX_PAGE_CHARS || !rest.chars().all(is_url_char) {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return false;
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let port_fits = port.is_none_or(|port| {
        !port.is_empty() && port.len() <= 5 && port.bytes().all(|byte| byte.is_ascii_digit())
    });
    port_fits && is_dns_name(host)
}

/// What RFC 3986 lets a URL hold unescaped, so a space, quote or angle bracket can't end one early.
fn is_url_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'()*+,;=%".contains(c)
}

/// Labels of letters, digits and hyphens, at least two, ending in letters.
fn is_dns_name(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    let label_fits = |label: &&str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    let top_fits = labels
        .last()
        .is_some_and(|top| top.len() >= 2 && top.bytes().all(|byte| byte.is_ascii_alphabetic()));
    host.len() <= 253 && labels.len() >= 2 && labels.iter().all(label_fits) && top_fits
}

/// LUD-16's `name@domain`, in lower case.
fn is_lightning_address(to: &str) -> bool {
    let Some((name, domain)) = to.split_once('@') else {
        return false;
    };
    let name_fits = !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.+".contains(&byte)
        });
    to.len() <= MAX_LIGHTNING_ADDRESS_CHARS
        && name_fits
        && domain == domain.to_ascii_lowercase()
        && is_dns_name(domain)
}

/// A BOLT12 offer: `lno1` and bech32's own characters, in lower case.
fn is_bolt12_offer(to: &str) -> bool {
    const BECH32: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let Some(data) = to.strip_prefix("lno1") else {
        return false;
    };
    (MIN_OFFER_CHARS..=MAX_OFFER_CHARS).contains(&to.len())
        && data.chars().all(|c| BECH32.contains(c))
}

/// CAIP-2: a namespace of 3 to 8 lowercase letters, digits or hyphens, `:`, and a reference of 1 to 32
/// letters, digits, hyphens or underscores, as `eip155:8453` or `bip122:000000000019d6689c085ae165831e93`.
fn is_caip2_chain(chain: &str) -> bool {
    let Some((namespace, reference)) = chain.split_once(':') else {
        return false;
    };
    (3..=8).contains(&namespace.len())
        && namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && (1..=32).contains(&reference.len())
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// CAIP-10's account address: 1 to 128 letters, digits, hyphens, dots or `%`.
fn is_chain_address(address: &str) -> bool {
    (1..=128).contains(&address.len())
        && address
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-.%".contains(&byte))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WherePaidPayload {
    v: u8,
    owner: SplintId,
    places: Vec<Place>,
    issued_at: u64,
}

impl WherePaidPayload {
    fn fits(&self) -> bool {
        let mut sorted = self.places.clone();
        sorted.sort();
        sorted.dedup();
        self.v == WHERE_PAID_VERSION
            && !self.places.is_empty()
            && self.places.len() <= MAX_PLACES
            && sorted.len() == self.places.len()
            && self.places.iter().all(Place::fits)
    }
}

/// Where an owner gets paid, whose signature under that owner's key has been checked. The only way
/// to get one is to pass that check, so nothing an agent writes can stand in for it.
#[derive(Clone, Debug)]
pub struct VerifiedWherePaid {
    compact: String,
    /// The hash of its payload, so a respelled signature is the same statement.
    id: MessageId,
    payload: WherePaidPayload,
}

impl VerifiedWherePaid {
    /// One arriving now, so it has to be signed by the key this owner holds now. An owner who hasn't
    /// confirmed has signed nothing that counts, so nothing says where one gets paid.
    pub fn verify(compact: &str, owner: &Identity) -> Result<Self, Refused> {
        if owner.is_unconfirmed_owner() {
            return Err(Refused::OwnerUnconfirmed);
        }
        let bytes = owner
            .verify(compact, WHERE_PAID_TYPE)
            .map_err(|_| Refused::BadWherePaid)?;
        Self::checked(compact, &bytes, owner)
    }

    /// One in a chain, which may date from before this owner's recovery.
    pub(super) fn verify_history(compact: &str, owner: &Identity) -> Result<Self, Refused> {
        if owner.is_unconfirmed_owner() {
            return Err(Refused::OwnerUnconfirmed);
        }
        let bytes = owner
            .verify_under_any_key(compact, WHERE_PAID_TYPE)
            .map_err(|_| Refused::BadWherePaid)?;
        Self::checked(compact, &bytes, owner)
    }

    fn checked(compact: &str, bytes: &[u8], owner: &Identity) -> Result<Self, Refused> {
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(Refused::BadWherePaid);
        }
        let payload: WherePaidPayload =
            serde_json::from_slice(bytes).map_err(|_| Refused::BadWherePaid)?;
        // One encoding, so spare bytes can't ride on it.
        let one_encoding = serde_json::to_vec(&payload).is_ok_and(|encoded| encoded == bytes);
        if !one_encoding || payload.owner != *owner.id() || !payload.fits() {
            return Err(Refused::BadWherePaid);
        }
        Ok(Self {
            compact: compact.to_owned(),
            id: MessageId::of(bytes),
            payload,
        })
    }

    /// What an owner's device signs. It refuses here what a reader would refuse later.
    pub fn sign(
        key: &SigningKey,
        owner: &SplintId,
        places: Vec<Place>,
        now: u64,
    ) -> Result<String, Refused> {
        let bytes = Self::payload_to_sign(owner, places, now)?;
        jws::sign(key, WHERE_PAID_TYPE, &bytes).map_err(|_| Refused::BadWherePaid)
    }

    /// The bytes an owner signs, for a device that signs some other way, such as a passkey.
    pub fn payload_to_sign(
        owner: &SplintId,
        places: Vec<Place>,
        now: u64,
    ) -> Result<Vec<u8>, Refused> {
        let payload = WherePaidPayload {
            v: WHERE_PAID_VERSION,
            owner: owner.clone(),
            places,
            issued_at: now,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| Refused::BadWherePaid)?;
        if !payload.fits() || bytes.len() > MAX_STATEMENT_BYTES {
            return Err(Refused::BadWherePaid);
        }
        Ok(bytes)
    }

    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub fn id(&self) -> &MessageId {
        &self.id
    }

    pub fn owner(&self) -> &SplintId {
        &self.payload.owner
    }

    pub fn places(&self) -> &[Place] {
        &self.payload.places
    }

    pub fn issued_at(&self) -> u64 {
        self.payload.issued_at
    }
}

/// The reference a payer can put on a payment, from the request's ID, so a payee can match what
/// arrives on their rail to the request it's for. Code writes it, so no agent can choose it.
pub fn reference_of(request: &MessageId) -> String {
    let start: String = request.as_str().chars().take(16).collect();
    format!("SPL-{}", start.to_ascii_uppercase())
}

/// Where a request's payment stands, kept apart from its state: `completed` still means agreed and
/// signed, and nothing here changes that.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    /// The payee's agent asked to be paid, at a place its owner signed.
    Requested,
    /// The payee's agent said the payment arrived. Only this counts as paid.
    Received,
}

/// One ask to be paid, as a reader holds it once every check has passed.
#[derive(Clone, Debug, Serialize)]
pub struct PaymentAsk {
    pub message_id: MessageId,
    /// The request it's on. A view of one request already says which.
    #[serde(skip)]
    pub request: MessageId,
    /// The value this pays, by its name in the type.
    pub value: Word,
    /// What the agreed terms say, which a reader worked out for itself.
    pub amount: u64,
    pub unit: Word,
    pub reference: String,
    pub place: Place,
    /// When the payee's owner signed where they get paid, by their own date.
    pub place_signed_at: u64,
    /// Whose owner signed it.
    pub owner: SplintId,
    /// When the payee's agent asked, by its own date.
    pub asked_at: u64,
}

impl PaymentAsk {
    pub(super) fn of(
        message_id: &MessageId,
        request: &MessageId,
        asked_at: u64,
        due: &Due,
        reference: String,
        statement: &VerifiedWherePaid,
        entry: u8,
    ) -> Option<Self> {
        Some(Self {
            message_id: message_id.clone(),
            request: request.clone(),
            value: due.value.clone(),
            amount: due.amount,
            unit: due.unit.clone(),
            reference,
            place: statement.places().get(usize::from(entry))?.clone(),
            place_signed_at: statement.issued_at(),
            owner: statement.owner().clone(),
            asked_at,
        })
    }
}

/// One value terms would have one side pay the other, worked out by code from the type's `paid` and
/// the signed terms alone, so an approval can say who pays whom in fixed words. A field's name, which
/// whoever proposed the type chose, never says it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paying {
    /// The value's name in the type.
    pub value: String,
    pub amount: u64,
    /// The word its unit field holds in the offer, such as `usd`, where the type gives it one.
    pub unit: Option<String>,
    /// The side the type says it's paid to.
    pub to: Side,
}

/// ISO 4217's minor-unit digits, as terms.js's MINOR_DIGITS has them, so a terminal and both owner
/// pages read an amount alike: the currency, how many minor units make one, and how many digits
/// those are. Any other currency is shown in its minor units rather than guessed.
const MINOR_DIGITS: [(&str, u64, usize); 9] = [
    ("USD", 100, 2),
    ("EUR", 100, 2),
    ("GBP", 100, 2),
    ("CAD", 100, 2),
    ("AUD", 100, 2),
    ("CHF", 100, 2),
    ("JPY", 1, 0),
    ("KWD", 1000, 3),
    ("BHD", 1000, 3),
];

/// A whole number with its thousands grouped, exactly, however large.
pub fn grouped(number: u64) -> String {
    let digits = number.to_string();
    let mut out = String::new();
    for (at, digit) in digits.chars().enumerate() {
        if at > 0 && (digits.len() - at).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// An amount in a currency's minor units as a person reads it, such as 125000 in USD as "1,250.00 USD".
pub fn money(minor: u64, code: &str) -> String {
    match MINOR_DIGITS.iter().find(|(known, _, _)| *known == code) {
        Some((_, _, 0)) => format!("{} {code}", grouped(minor)),
        Some((_, per, digits)) => format!(
            "{}.{:0digits$} {code}",
            grouped(minor / per),
            minor % per,
            digits = *digits
        ),
        None => format!("{minor} in minor units of {code}"),
    }
}

impl Paying {
    /// The amount as a person reads it, as [`amount_in_words`] has it.
    pub fn amount_in_words(&self) -> String {
        amount_in_words(&self.value, self.amount, self.unit.as_deref())
    }
}

/// An amount as a person reads it: in its currency where the value is in minor units of one, as
/// `amount_minor` with `usd` is "1,250.00 USD", and otherwise the number and its unit's word.
pub fn amount_in_words(value: &str, amount: u64, unit: Option<&str>) -> String {
    let currency = unit
        .filter(|code| code.len() == 3 && code.chars().all(|c| c.is_ascii_alphabetic()))
        .map(str::to_ascii_uppercase);
    match (value.ends_with("_minor"), currency, unit) {
        (true, Some(code), _) => money(amount, &code),
        (true, None, Some(word)) => format!("{} in minor units of {word}", grouped(amount)),
        (_, Some(code), _) => format!("{} {code}", grouped(amount)),
        (_, None, Some(word)) => format!("{} {word}", grouped(amount)),
        (_, None, None) => grouped(amount),
    }
}

/// What these terms pay, and to whom, as a payment would be asked for them: the amount from what was
/// delivered and then what was agreed, and the unit from what was agreed, as [`Chain`]'s asks read
/// them. A value the terms don't hold yet pays nothing.
///
/// [`Chain`]: super::Chain
pub fn paying_in(terms: &Terms, schema: &Schema) -> Vec<Paying> {
    schema
        .values()
        .filter_map(|value| {
            let to = schema.paid_to(value)?;
            let amount =
                [&terms.result, &terms.agreed]
                    .into_iter()
                    .find_map(|fields| match fields.get(value) {
                        Some(FieldValue::Int(amount)) => Some(*amount),
                        _ => None,
                    })?;
            let unit = schema
                .unit_of(value)
                .and_then(|field| match terms.agreed.get(field) {
                    Some(FieldValue::Text(word)) => Some(word.clone()),
                    _ => None,
                });
            Some(Paying {
                value: value.to_owned(),
                amount,
                unit,
                to,
            })
        })
        .collect()
}

/// What a payer should know of where they're asked to pay. Code works each out from facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentWarning {
    /// Lightning or a chain: a payment there can't be taken back.
    CantBeReversed,
    /// Their owner signed this place in the last 7 days, or it replaced one asked for before.
    PlaceChangedRecently,
    /// No ask from this owner that came before this one, in another request this Signet holds, named
    /// this place.
    PlaceNew,
    /// This Signet has seen a newer statement of where this owner gets paid than the one on this ask,
    /// so the place may be one they moved away from: what a stolen agent key replaying an old
    /// statement looks like.
    StatementSuperseded,
}

impl PaymentWarning {
    /// The fact in fixed words, for a person.
    pub fn in_words(self) -> &'static str {
        match self {
            Self::CantBeReversed => {
                "A payment there can't be reversed: once it's sent, it's gone, even if it went wrong."
            }
            Self::PlaceChangedRecently => {
                "Their owner signed this place in the last 7 days, or it replaced the place they asked \
                 to be paid at before."
            }
            Self::PlaceNew => "They've never asked to be paid here before.",
            Self::StatementSuperseded => {
                "Their owner has since signed a newer list of where they get paid than the one on \
                 this ask, so this may be a place they moved away from. Check with them another way \
                 before paying it."
            }
        }
    }
}

/// The facts a payer should know of one ask, from the other asks held from the same owner.
pub fn warnings_for(ask: &PaymentAsk, others: &[PaymentAsk], now: u64) -> Vec<PaymentWarning> {
    let theirs: Vec<&PaymentAsk> = others
        .iter()
        .filter(|other| other.owner == ask.owner && other.message_id != ask.message_id)
        .collect();
    // Only an ask that came before, on another request, shows a place was used before. Whoever holds
    // the owner's and the agent's keys could otherwise vouch for a new place by asking twice.
    let before: Vec<&&PaymentAsk> = theirs
        .iter()
        .filter(|other| other.request != ask.request && other.asked_at < ask.asked_at)
        .collect();
    let new = !before.iter().any(|other| other.place == ask.place);
    let replaced = new && !before.is_empty();
    let signed_lately = now.saturating_sub(ask.place_signed_at) < CHANGED_WITHIN_SECS;
    // A newer statement seen anywhere says this place may be one they moved away from.
    let superseded = theirs
        .iter()
        .any(|other| other.place_signed_at > ask.place_signed_at);
    let mut warnings = Vec::new();
    if ask.place.irreversible() {
        warnings.push(PaymentWarning::CantBeReversed);
    }
    if signed_lately || replaced {
        warnings.push(PaymentWarning::PlaceChangedRecently);
    }
    if new {
        warnings.push(PaymentWarning::PlaceNew);
    }
    if superseded {
        warnings.push(PaymentWarning::StatementSuperseded);
    }
    warnings
}

/// What's owed for one value by the agreed terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Due {
    pub(super) value: Word,
    pub(super) amount: u64,
    pub(super) unit: Word,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(url: &str) -> Place {
        Place::PaymentPage {
            url: url.to_owned(),
        }
    }

    fn lightning(to: &str) -> Place {
        Place::Lightning { to: to.to_owned() }
    }

    fn onchain(chain: &str, address: &str) -> Place {
        Place::Onchain {
            chain: chain.to_owned(),
            address: address.to_owned(),
            asset: Word::try_from("usdc".to_owned()).unwrap(),
        }
    }

    // An approval card's "you pay" has to be what an ask can then demand, which is what was delivered,
    // over what was offered.
    #[test]
    fn a_card_pays_the_delivered_amount_over_the_offered_one() {
        let schema = Schema::parse(
            br#"{"type":"job/1","kind":"request","offer":{"currency":{"word":["usd"]},"price":{"range":{"min":1,"max":100000}}},"fixed":["currency"],"result":{"price":{"range":{"min":1,"max":100000}}},"values":["price"],"units":{"price":"currency"},"paid":{"price":"recipient"},"sign":"requester"}"#,
        )
        .unwrap();
        let party = |key: &SigningKey| {
            let id = crate::test_identity(key).id().clone();
            serde_json::json!({"agent": id, "owner": id})
        };
        let key = SigningKey::generate().unwrap();
        let terms: Terms = serde_json::from_value(serde_json::json!({
            "type": schema.name(),
            "requester": party(&key),
            "recipient": party(&key),
            "agreed": {"currency": "usd", "price": 1000},
            "result": {"price": 1200},
            "subject": null,
            "note": null,
            "supersedes": null,
        }))
        .unwrap();
        let paying = paying_in(&terms, &schema);
        assert_eq!(
            paying
                .iter()
                .map(|paying| (paying.amount, paying.unit.as_deref(), paying.to))
                .collect::<Vec<_>>(),
            [(1200, Some("usd"), Side::Recipient)]
        );
    }

    // A place a reader would take with a login, prose or a lookalike in it would put a scammer's
    // words, or a password, in front of a payer as their owner's.
    #[test]
    fn only_a_place_of_its_kinds_shape_fits() {
        let fit = [
            page("https://pay.example.com/ana"),
            page("https://example.com:8443/p?ref=1&amt=2"),
            lightning("ana@wallet.example"),
            lightning(&format!("lno1{}", "q".repeat(40))),
            onchain("eip155:8453", "0xAbC0000000000000000000000000000000000001"),
            onchain("bip122:000000000019d6689c085ae165831e93", "bc1qexample"),
        ];
        for place in fit {
            assert!(place.fits(), "{place:?}");
        }
        let unfit = [
            page("http://pay.example.com/ana"),
            page("https://user:pass@pay.example.com/"),
            page("https://127.0.0.1/pay"),
            page("https://localhost/pay"),
            page("https://pay.example.com/a b"),
            page("https://pay.example.com/\"onclick"),
            page("https://pay.example.com/\u{202e}"),
            page(&format!("https://pay.example.com/{}", "a".repeat(300))),
            lightning("Ana@wallet.example"),
            lightning("ana@wallet"),
            lightning("lno1QQ"),
            lightning("pay me at ana@wallet.example"),
            onchain("eip155", "0xabc"),
            onchain("EIP155:1", "0xabc"),
            onchain("eip155:1", "0x abc"),
            onchain("eip155:1", ""),
        ];
        for place in unfit {
            assert!(!place.fits(), "{place:?}");
        }
    }
}

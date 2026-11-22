//! Gate 4's ceiling on what an agent writes: none of its own secrets, which its Signet knows exactly,
//! and none of Splint's own secret codes, by their spelling. See "An agent's own secrets" in
//! `docs/protocol.md`.
//!
//! It's a ceiling, not a classifier. It looks for what Signet holds and for Splint's own formats,
//! and doesn't guess at passwords or anyone else's keys. A paste is looked at with whitespace, line
//! breaks, their JSON escapes and invisible characters taken out, so wrapping a key or spacing out a
//! code doesn't get it past. Comparisons against a token or key run over every place in the text,
//! each in constant time, so how long a check takes says nothing about how much of a secret matched.

use std::collections::BTreeSet;

use aws_lc_rs::constant_time;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::{Engine, alphabet};
use serde::Serialize;

use crate::delegation::DelegateKey;
use crate::identity::{Identity, RecoveryRule, hex};
use crate::keys::{PublicKey, SCALAR_LEN};
use crate::pairing::CODE_PREFIX;
use crate::requests::is_hidden_character;
use crate::{Error, SealingKey, SigningKey};

/// What kind of secret a text held. It's all a refusal says, so nothing of the text goes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    AccessToken,
    PrivateKey,
    PairingCode,
    RecoveryCode,
    /// A private key Signet doesn't hold: its owner's, or a backup key an ID commits to.
    OwnerKey,
}

impl SecretKind {
    /// What it is, in words for an agent to read.
    pub fn described(self) -> &'static str {
        match self {
            Self::AccessToken => "this agent's access token",
            Self::PrivateKey => "one of this agent's private keys",
            Self::PairingCode => "a Splint pairing code",
            Self::RecoveryCode => "a Splint recovery code",
            Self::OwnerKey => "a private key of this agent's owner, or a backup key",
        }
    }
}

/// Text longer than this can't be in any envelope, so it's refused unread, and an agent can't hold its
/// own Signet up with a scan of something no host would take.
pub const MAX_SCANNED_BYTES: usize = crate::jws::MAX_COMPACT_LEN;
/// A token shorter than this would match ordinary words. Tokens Splint makes are 64 characters.
const MIN_TOKEN_BYTES: usize = 8;
/// A recovery code as the owner's page and `owner-key` spell it: six groups of four, then two.
const RECOVERY_GROUPS: usize = 6;
const RECOVERY_GROUP_CHARS: usize = 4;
const RECOVERY_LAST_CHARS: usize = 2;
const RECOVERY_SPELLED_CHARS: usize =
    RECOVERY_GROUPS * (RECOVERY_GROUP_CHARS + 1) + RECOVERY_LAST_CHARS;
/// A recovery code's characters, however a person groups them.
const RECOVERY_CHARS: usize = RECOVERY_GROUPS * RECOVERY_GROUP_CHARS + RECOVERY_LAST_CHARS;
/// A pairing code's secret, after its host: 16 bytes in base32.
const PAIRING_SECRET_CHARS: usize = 26;
/// The longest a domain can be, which a pairing code's host part is.
const MAX_HOST_CHARS: usize = 253;
const BASE64_BITS: usize = 6;
/// More DER-wrapped places a key could start than any key file has. Padding can make one every few
/// bytes, so text this full of them is refused rather than tried one by one, and a key can't be hidden
/// past what's tried.
const MAX_WRAPPED_CANDIDATES: usize = MAX_SCANNED_BYTES / 64;
/// More runs' ends than the largest envelope of ordinary lines holds. Each run of 43 characters or more
/// gives at most two, so only text made to be nothing but such runs comes near it.
const MAX_RUN_END_CANDIDATES: usize = MAX_SCANNED_BYTES / 16;
/// How many characters of other words can touch a key in one run, before and after it together, with
/// every place in the run still tried, so a short word glued to a key doesn't hide it. A longer run has
/// only its ends tried, as each place costs deriving a public key.
const MAX_BESIDE_KEY_CHARS: usize = 16;
/// Places inside such runs, past their ends, that are tried. Ordinary lists of hashes or tokens a little
/// longer than a key are full of them, so past this many the rest aren't tried, rather than the text
/// being refused, as it was when they counted toward [`MAX_RUN_END_CANDIDATES`].
const MAX_BESIDE_CANDIDATES: usize = MAX_SCANNED_BYTES / 64;
/// The DER that wraps a private scalar in PKCS#8 and SEC1 alike: an OCTET STRING of 32 bytes.
const DER_SCALAR: [u8; 2] = [0x04, 0x20];
/// Base64 of 32 bytes, less its one `=`.
const BASE64_SCALAR_CHARS: usize = 43;
const HEX_SCALAR_CHARS: usize = SCALAR_LEN * 2;
/// Decodes base64 cut at any place, whose last character may carry bits of what was cut off.
const ANY_ALIGNMENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

/// Which spelling of the text a secret is looked for in.
#[derive(Clone, Copy)]
enum Seen {
    /// As written, less whitespace.
    AsWritten,
    /// Lower case, less whitespace and colons, as hex is written in any case or as `ab:cd:..`.
    Hex,
    /// With base64url's two letters turned into standard base64's, so one search finds either.
    Base64,
}

struct Needle {
    kind: SecretKind,
    seen: Seen,
    bytes: Vec<u8>,
}

/// This agent's own secrets, as they could be pasted. Like a key, it has no `Debug`, `Display` or
/// `Serialize`, so what it holds can't reach a log, an error or a response by accident:
///
/// ```compile_fail
/// # fn wrong(secrets: splint_core::secrets_in_text::OwnSecrets) -> String {
/// format!("{secrets:?}")
/// # }
/// ```
#[derive(Default)]
pub struct OwnSecrets {
    needles: Vec<Needle>,
    /// Public keys whose private halves this Signet never holds, and the backups IDs commit to.
    others_keys: Vec<PublicKey>,
    /// The points IDs seal to, whose private halves are files on an owner's device.
    others_seals: Vec<Vec<u8>>,
    backups: Vec<RecoveryRule>,
}

impl OwnSecrets {
    /// A bearer token, as Signet takes it. One in hex is found in either case.
    pub fn token(&mut self, token: &str) {
        let token: Vec<u8> = without_padding(token).into_bytes();
        if token.len() < MIN_TOKEN_BYTES {
            return;
        }
        let needle = if token.iter().all(u8::is_ascii_hexdigit) {
            Needle {
                kind: SecretKind::AccessToken,
                seen: Seen::Hex,
                bytes: token.to_ascii_lowercase(),
            }
        } else {
            Needle {
                kind: SecretKind::AccessToken,
                seen: Seen::AsWritten,
                bytes: token,
            }
        };
        self.needles.push(needle);
    }

    pub fn signing_key(&mut self, key: &SigningKey) -> Result<(), Error> {
        self.scalar(&key.scalar()?);
        Ok(())
    }

    pub fn delegate_key(&mut self, key: &DelegateKey) -> Result<(), Error> {
        self.signing_key(key.signing_key())
    }

    pub fn sealing_key(&mut self, key: &SealingKey) -> Result<(), Error> {
        self.scalar(&key.private_bytes());
        Ok(())
    }

    /// The private keys of an ID this Signet doesn't hold, known by their public halves: the keys it
    /// counts now, the key it seals to, and the backup its rule commits to. With the owner's ID, an
    /// owner's key files beside the agent can't be pasted out, though Signet never reads them. With the
    /// agent's own, nor can its backup, which the owner's device keeps.
    pub fn private_keys_of(&mut self, id: &Identity) {
        self.others_keys
            .extend(id.keys().iter().map(|key| key.point().clone()));
        if let Some(seal) = id.seal_key() {
            self.others_seals.push(seal.as_bytes().to_vec());
        }
        self.backups.push(id.rule().clone());
    }

    /// A private scalar, which every form a key is kept or exported in holds whole: the raw hex, the
    /// JWK `d`, and the DER inside PKCS#8 or SEC1, in base64 or PEM. Base64 of a longer blob spells it
    /// one of three ways, by where it starts, so each is looked for, less the characters at either
    /// end that also hold bits of whatever is beside it.
    fn scalar(&mut self, scalar: &[u8]) {
        self.needles.push(Needle {
            kind: SecretKind::PrivateKey,
            seen: Seen::Hex,
            bytes: hex(scalar).into_bytes(),
        });
        for offset in 0..3 {
            let mut shifted = vec![0_u8; offset];
            shifted.extend_from_slice(scalar);
            let encoded = STANDARD_NO_PAD.encode(&shifted).into_bytes();
            let first_bit = offset * 8;
            let end_bit = first_bit + scalar.len() * 8;
            let whole: Vec<u8> = encoded
                .iter()
                .enumerate()
                .filter(|(at, _)| {
                    let start = at * BASE64_BITS;
                    start >= first_bit && start + BASE64_BITS <= end_bit
                })
                .map(|(_, byte)| *byte)
                .collect();
            self.needles.push(Needle {
                kind: SecretKind::PrivateKey,
                seen: Seen::Base64,
                bytes: whole,
            });
        }
    }

    /// The first secret found in `text`, of this agent's own or in one of Splint's own formats.
    pub fn found_in(&self, text: &str) -> Option<SecretKind> {
        let views = Views::of(text);
        let mut found = None;
        for needle in &self.needles {
            if holds(views.get(needle.seen), &needle.bytes) && found.is_none() {
                found = Some(needle.kind);
            }
        }
        found
            .or_else(|| splint_code_in(&views.lower))
            .or_else(|| regrouped_recovery_code_in(text).then_some(SecretKind::RecoveryCode))
            .or_else(|| self.others_key_in(text, &views))
    }

    /// A private key whose public half is one of [`Self::private_keys_of`]'s, which can't be looked for
    /// as written, as its bytes aren't known here. Each place a key could start is tried instead: the
    /// first and last 32 bytes of each run of hex or base64 in a word, as raw hex, base64 or a JWK's
    /// `d` spells a key, with a field run onto it, `openssl`'s leading `00`, or a word before it, every
    /// place in a run no more than [`MAX_BESIDE_KEY_CHARS`] longer than a key, and the 32 bytes after
    /// the DER that wraps a scalar, in PKCS#8 or SEC1, in hex, base64 or PEM, from any alignment. The
    /// text with whitespace taken out is tried too, for a key wrapped or spaced out over lines.
    fn others_key_in(&self, text: &str, views: &Views) -> Option<SecretKind> {
        if self.others_keys.is_empty() && self.others_seals.is_empty() && self.backups.is_empty() {
            return None;
        }
        let mut scalars = Candidates::default();
        let words = text.split(|c: char| c.is_whitespace() || is_hidden_character(c));
        for word in words {
            let as_base64: Vec<u8> = word.bytes().map(base64url_as_standard).collect();
            for run in as_base64.split(|byte| !is_base64_char(*byte)) {
                base64_scalars(run, true, &mut scalars);
            }
            let as_hex = word.to_ascii_lowercase().replace(':', "");
            for run in as_hex.as_bytes().split(|byte| !byte.is_ascii_hexdigit()) {
                hex_scalars(run, &mut scalars);
            }
        }
        // Whole words of prose run together here, into runs of every length, so only a run's ends are
        // tried, where a key wrapped over lines after or before some words is. Hex runs this long are
        // only ever hex, so every place near a key is tried in them, as in a word.
        for run in views.base64.split(|byte| !is_base64_char(*byte)) {
            base64_scalars(run, false, &mut scalars);
        }
        for run in views.hex.split(|byte| !byte.is_ascii_hexdigit()) {
            hex_scalars(run, &mut scalars);
        }
        if scalars.wrapped.len() > MAX_WRAPPED_CANDIDATES
            || scalars.run_ends.len() > MAX_RUN_END_CANDIDATES
        {
            return Some(SecretKind::OwnerKey);
        }
        scalars
            .run_ends
            .iter()
            .chain(&scalars.wrapped)
            .chain(&scalars.beside)
            .any(|scalar| self.is_others_scalar(scalar))
            .then_some(SecretKind::OwnerKey)
    }

    fn is_others_scalar(&self, scalar: &[u8; SCALAR_LEN]) -> bool {
        let Ok(key) = SigningKey::from_scalar(scalar) else {
            return false;
        };
        let public = key.public_key();
        self.others_keys.contains(&public)
            || self
                .others_seals
                .iter()
                .any(|seal| seal.as_slice() == public.as_bytes())
            || self.backups.iter().any(|rule| rule.accepts(&public))
    }
}

/// Where a key could be in a text, each counted once: a whole run, or a run's first or last 32 bytes,
/// the 32 bytes after DER's wrapping, and the places between a short run's ends, kept apart as each has
/// its own limit.
#[derive(Default)]
struct Candidates {
    run_ends: BTreeSet<[u8; SCALAR_LEN]>,
    wrapped: BTreeSet<[u8; SCALAR_LEN]>,
    beside: BTreeSet<[u8; SCALAR_LEN]>,
}

impl Candidates {
    /// A place between a run's ends, while there's room for more.
    fn beside(&mut self, decoded: &[u8]) {
        if self.beside.len() < MAX_BESIDE_CANDIDATES
            && let Ok(scalar) = <[u8; SCALAR_LEN]>::try_from(decoded)
        {
            self.beside.insert(scalar);
        }
    }
}

/// base64url's two letters as standard base64's, so one decoding reads either.
fn base64url_as_standard(byte: u8) -> u8 {
    match byte {
        b'-' => b'+',
        b'_' => b'/',
        other => other,
    }
}

/// Scalars a run of base64 could hold: at its ends, and every place between them in a word's short run
/// when `every_place`, where a key's 43 characters could be by themselves, and each DER-wrapped one at
/// any alignment.
fn base64_scalars(run: &[u8], every_place: bool, scalars: &mut Candidates) {
    // Hex is base64's letters too. A run of only hex digits is hex, such as an ID or a hash, and read
    // as base64 too it would count each one three times. Base64 of a key is all hex digits about once
    // in 10^25.
    if run.len() < BASE64_SCALAR_CHARS || run.iter().all(u8::is_ascii_hexdigit) {
        return;
    }
    for window in run_ends(run, BASE64_SCALAR_CHARS) {
        if let Ok(decoded) = ANY_ALIGNMENT.decode(window) {
            scalars_in(&decoded, true, scalars);
        }
    }
    if every_place {
        for window in between_ends(run, BASE64_SCALAR_CHARS) {
            if let Ok(decoded) = ANY_ALIGNMENT.decode(window) {
                scalars.beside(&decoded);
            }
        }
    }
    for decoded in base64_from_each_alignment(run) {
        scalars_in(&decoded, false, scalars);
    }
}

/// Scalars a run of hex could hold: at each place near a key's 64 digits could be by themselves, and
/// each DER-wrapped one.
fn hex_scalars(run: &[u8], scalars: &mut Candidates) {
    if run.len() < HEX_SCALAR_CHARS {
        return;
    }
    for window in run_ends(run, HEX_SCALAR_CHARS) {
        for decoded in hex_from_each_alignment(window) {
            scalars_in(&decoded, true, scalars);
        }
    }
    for window in between_ends(run, HEX_SCALAR_CHARS) {
        for decoded in hex_from_each_alignment(window) {
            scalars.beside(&decoded);
        }
    }
    for decoded in hex_from_each_alignment(run) {
        scalars_in(&decoded, false, scalars);
    }
}

/// Where a key `width` characters long could be between a run's ends, when the run is no more than
/// [`MAX_BESIDE_KEY_CHARS`] longer than it, so a short word glued to either side doesn't hide it.
fn between_ends(run: &[u8], width: usize) -> Vec<&[u8]> {
    if run.len() > width + MAX_BESIDE_KEY_CHARS {
        return Vec::new();
    }
    let windows: Vec<&[u8]> = run.windows(width).collect();
    let inner = windows.len().saturating_sub(1);
    windows.into_iter().take(inner).skip(1).collect()
}

/// A run's first and last `width` characters, where a key with a field run onto it, or a word before it,
/// is.
fn run_ends(run: &[u8], width: usize) -> Vec<&[u8]> {
    [run.get(..width), run.get(run.len().saturating_sub(width)..)]
        .into_iter()
        .flatten()
        .filter(|end| end.len() == width)
        .collect()
}

fn is_base64_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

/// `run` as base64 from each of its first four characters, as what's before a key in a run, such as a
/// PEM line's dashes, may leave it at any of them.
fn base64_from_each_alignment(run: &[u8]) -> Vec<Vec<u8>> {
    if run.len() < BASE64_SCALAR_CHARS {
        return Vec::new();
    }
    (0..4)
        .filter_map(|from| {
            let chars = run.get(from..)?;
            // A single character left over holds no whole byte, and decoding refuses it.
            let whole = chars.get(..chars.len() - usize::from(chars.len() % 4 == 1))?;
            ANY_ALIGNMENT.decode(whole).ok()
        })
        .collect()
}

/// `run` as hex from its first and second characters.
fn hex_from_each_alignment(run: &[u8]) -> Vec<Vec<u8>> {
    if run.len() < HEX_SCALAR_CHARS {
        return Vec::new();
    }
    (0..2)
        .filter_map(|from| {
            let digits = run.get(from..)?;
            digits
                .chunks_exact(2)
                .map(|pair| match pair {
                    [high, low] => Some((hex_value(*high)? << 4) | hex_value(*low)?),
                    _ => None,
                })
                .collect()
        })
        .collect()
}

fn hex_value(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// Where a private scalar could be in `decoded`: all of it when it's a key by itself, and after each
/// DER wrapping of one.
fn scalars_in(decoded: &[u8], by_itself: bool, scalars: &mut Candidates) {
    if by_itself && let Ok(scalar) = <[u8; SCALAR_LEN]>::try_from(decoded) {
        scalars.run_ends.insert(scalar);
    }
    for (at, pair) in decoded.windows(DER_SCALAR.len()).enumerate() {
        if pair == DER_SCALAR
            && let Some(scalar) = decoded
                .get(at + DER_SCALAR.len()..at + DER_SCALAR.len() + SCALAR_LEN)
                .and_then(|bytes| <[u8; SCALAR_LEN]>::try_from(bytes).ok())
        {
            scalars.wrapped.insert(scalar);
        }
    }
}

/// The text as each kind of secret is looked for in it.
struct Views {
    as_written: Vec<u8>,
    lower: Vec<u8>,
    hex: Vec<u8>,
    base64: Vec<u8>,
}

impl Views {
    fn of(text: &str) -> Self {
        let as_written = without_padding(text).into_bytes();
        let lower = as_written.to_ascii_lowercase();
        let hex = lower.iter().copied().filter(|byte| *byte != b':').collect();
        let base64 = as_written
            .iter()
            .map(|byte| match byte {
                b'-' => b'+',
                b'_' => b'/',
                other => *other,
            })
            .collect();
        Self {
            as_written,
            lower,
            hex,
            base64,
        }
    }

    fn get(&self, seen: Seen) -> &[u8] {
        match seen {
            Seen::AsWritten => &self.as_written,
            Seen::Hex => &self.hex,
            Seen::Base64 => &self.base64,
        }
    }
}

/// The text less what a paste or a wrapped line adds: whitespace, invisible characters, and the
/// escapes `\n`, `\r` and `\t` written out, as a key copied from JSON has them.
fn without_padding(text: &str) -> String {
    let unescaped = text
        .replace("\\n", "")
        .replace("\\r", "")
        .replace("\\t", "");
    unescaped
        .chars()
        .filter(|c| !c.is_whitespace() && !is_hidden_character(*c))
        .collect()
}

/// Whether `needle` is anywhere in `text`. Every place is compared in full, in constant time, and
/// nothing stops early, so the time taken depends only on the two lengths.
fn holds(text: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut found = false;
    for window in text.windows(needle.len()) {
        found |= constant_time::verify_slices_are_equal(window, needle).is_ok();
    }
    found
}

fn is_base32(byte: u8) -> bool {
    byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte)
}

/// A pairing code or a recovery code, by its one spelling, in text already in lower case.
fn splint_code_in(lower: &[u8]) -> Option<SecretKind> {
    if pairing_code_in(lower) {
        return Some(SecretKind::PairingCode);
    }
    lower
        .windows(RECOVERY_SPELLED_CHARS)
        .any(is_spelled_recovery_code)
        .then_some(SecretKind::RecoveryCode)
}

/// `splint-pair:<host>/<secret>/<owner>`: the prefix, a host, then 26 base32 characters between two
/// slashes. Words that only name the prefix, as a guide to pairing does, carry no secret and pass, and
/// the second slash keeps prose that happens to follow the prefix from reading as a code.
fn pairing_code_in(lower: &[u8]) -> bool {
    let prefix = CODE_PREFIX.as_bytes();
    lower
        .windows(prefix.len())
        .enumerate()
        .filter(|(_, window)| *window == prefix)
        .any(|(at, _)| {
            let rest = lower.get(at + prefix.len()..).unwrap_or_default();
            let Some(slash) = rest.iter().position(|byte| *byte == b'/') else {
                return false;
            };
            let host = rest.get(..slash).unwrap_or_default();
            let after = rest.get(slash + 1..).unwrap_or_default();
            let secret = after.get(..PAIRING_SECRET_CHARS).unwrap_or_default();
            (1..=MAX_HOST_CHARS).contains(&host.len())
                && host.iter().copied().all(is_host_byte)
                && secret.len() == PAIRING_SECRET_CHARS
                && secret.iter().copied().all(is_base32)
                && after.get(PAIRING_SECRET_CHARS) == Some(&b'/')
        })
}

/// What a host part is written with: a domain, an address, and a port.
fn is_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
}

/// `abcd-efgh-ijkl-mnop-qrst-uvwx-yz`, whose last character has its two spare bits zero.
fn is_spelled_recovery_code(window: &[u8]) -> bool {
    window.iter().enumerate().all(|(at, byte)| {
        let in_group = at % (RECOVERY_GROUP_CHARS + 1);
        let last_groups_dash = at < RECOVERY_GROUPS * (RECOVERY_GROUP_CHARS + 1);
        if in_group == RECOVERY_GROUP_CHARS && last_groups_dash {
            *byte == b'-'
        } else {
            is_base32(*byte)
        }
    }) && window
        .last()
        .is_some_and(|last| base32_value(*last).is_multiple_of(4))
}

/// A run of base32 characters, or what stands between two of them in one stretch of text.
enum Piece {
    Chars(Vec<u8>),
    /// Whitespace or dashes, and whether there was a dash.
    Gap {
        dashed: bool,
    },
}

/// A recovery code however a person may have regrouped it, as `RecoveryCode::parse` takes it: its 26
/// characters in groups of one size, the last no longer, split by spaces or dashes, or not split at all.
/// Ordinary words come in groups of every size, and prose in one case with no digit, so what's split
/// only by spaces counts when it's in capitals or holds a digit. A spelling with no letter past `f` is
/// hex, such as an ID, and never counts. The page's own spelling, and one wrapped mid-group, are found
/// by [`is_spelled_recovery_code`].
fn regrouped_recovery_code_in(text: &str) -> bool {
    let unescaped = text
        .replace("\\n", " ")
        .replace("\\r", " ")
        .replace("\\t", " ");
    let mut stretches: Vec<Vec<Piece>> = vec![Vec::new()];
    for c in unescaped.chars().filter(|c| !is_hidden_character(*c)) {
        let Some(stretch) = stretches.last_mut() else {
            continue;
        };
        let byte = u8::try_from(c).ok().filter(u8::is_ascii);
        match byte {
            Some(byte) if is_base32(byte.to_ascii_lowercase()) => match stretch.last_mut() {
                Some(Piece::Chars(chars)) => chars.push(byte),
                _ => stretch.push(Piece::Chars(vec![byte])),
            },
            _ if c.is_whitespace() || c == '-' => match stretch.last_mut() {
                Some(Piece::Gap { dashed }) => *dashed |= c == '-',
                Some(Piece::Chars(_)) => stretch.push(Piece::Gap { dashed: c == '-' }),
                None => {}
            },
            _ => stretches.push(Vec::new()),
        }
    }
    stretches
        .iter()
        .any(|stretch| holds_regrouped_code(stretch))
}

/// Whether a stretch has, starting at some group, groups of one size that make up a code.
fn holds_regrouped_code(stretch: &[Piece]) -> bool {
    let starts = (0..stretch.len()).filter(|at| matches!(stretch.get(*at), Some(Piece::Chars(_))));
    starts.into_iter().any(|start| {
        let mut chars = Vec::with_capacity(RECOVERY_CHARS);
        let mut all_dashed = true;
        let mut groups = 0_usize;
        let mut size = 0_usize;
        for piece in stretch.iter().skip(start) {
            match piece {
                Piece::Gap { dashed } => all_dashed &= *dashed,
                Piece::Chars(group) => {
                    if groups == 0 {
                        size = group.len();
                    }
                    let left = RECOVERY_CHARS.saturating_sub(chars.len());
                    let fits = group.len() == size || (group.len() < size && group.len() == left);
                    if size < 2 || !fits || group.len() > left {
                        return false;
                    }
                    groups += 1;
                    chars.extend_from_slice(group);
                    if chars.len() == RECOVERY_CHARS {
                        return looks_like_a_code(&chars, groups == 1 || all_dashed);
                    }
                }
            }
        }
        false
    })
}

/// 26 characters taken together: in one case, not hex, the last with its spare bits zero, and, unless
/// written whole or split by dashes, in capitals or with a digit, as prose has neither.
fn looks_like_a_code(chars: &[u8], whole_or_dashed: bool) -> bool {
    let lower = chars.to_ascii_lowercase();
    let letters = || chars.iter().filter(|byte| byte.is_ascii_alphabetic());
    let one_case = letters().all(u8::is_ascii_lowercase) || letters().all(u8::is_ascii_uppercase);
    let capitals = letters().all(u8::is_ascii_uppercase);
    let digit = chars.iter().any(u8::is_ascii_digit);
    let past_hex = lower.iter().any(|byte| (b'g'..=b'z').contains(byte));
    let spare_bits_zero = lower
        .last()
        .is_some_and(|last| base32_value(*last).is_multiple_of(4));
    one_case && past_hex && spare_bits_zero && (whole_or_dashed || capitals || digit)
}

fn base32_value(byte: u8) -> u8 {
    if byte.is_ascii_lowercase() {
        byte - b'a'
    } else {
        byte.wrapping_sub(b'2').wrapping_add(26)
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    use super::*;
    use crate::jws;

    const TOKEN: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn secrets_of(key: &SigningKey) -> OwnSecrets {
        let mut secrets = OwnSecrets::default();
        secrets.token(TOKEN);
        secrets.signing_key(key).ok();
        secrets
    }

    fn wrapped(text: &str, every: usize, by: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let lines: Vec<String> = chars
            .chunks(every)
            .map(|line| line.iter().collect())
            .collect();
        lines.join(by)
    }

    fn pkcs8_of(key: &SigningKey) -> Vec<u8> {
        jws::decode(&key.invitation_text().unwrap()).unwrap_or_default()
    }

    /// Every way a fooled agent could paste a key: as a key file's bytes, `openssl` and `base64` print
    /// them, or a JWK holds the scalar.
    fn pasted_forms(key: &SigningKey) -> Vec<(&'static str, String)> {
        let scalar = key.scalar().unwrap();
        let pkcs8 = pkcs8_of(key);
        let mut sec1 = vec![0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20];
        sec1.extend_from_slice(&scalar);
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            wrapped(&STANDARD.encode(&pkcs8), 64, "\n")
        );
        let forms = [
            ("hex", format!("the key is {}", hex(&scalar))),
            (
                "hex upper, spaced",
                wrapped(&hex(&scalar).to_uppercase(), 2, " "),
            ),
            (
                "hex as openssl prints it",
                wrapped(&hex(&scalar), 2, ":\n    "),
            ),
            (
                "jwk d",
                format!("{{\"d\":\"{}\"}}", URL_SAFE_NO_PAD.encode(scalar)),
            ),
            ("base64 scalar", STANDARD.encode(scalar)),
            ("pkcs8 base64", STANDARD.encode(&pkcs8)),
            ("pkcs8 base64url", URL_SAFE_NO_PAD.encode(&pkcs8)),
            ("pem", pem.clone()),
            ("pem with escaped breaks", pem.replace('\n', "\\n")),
            ("sec1 base64", STANDARD.encode(&sec1)),
            ("hex of the key file", hex(&pkcs8)),
            ("zero-width spaced", wrapped(&hex(&scalar), 8, "\u{200B}")),
            ("after a word", format!("key:{}", STANDARD.encode(scalar))),
            // Fields of a move are run together, so a key can touch whatever is next to it.
            (
                // Digits beside it, as words could also read as a recovery code regrouped.
                "run onto the next field",
                format!("{}42", hex(&scalar)),
            ),
            ("after a field", format!("Key{}", STANDARD.encode(scalar))),
            (
                "a jwk split into fields",
                format!("{}EC", URL_SAFE_NO_PAD.encode(scalar)),
            ),
            (
                "openssl with a leading 00",
                format!("priv:\n    00:{}", wrapped(&hex(&scalar), 2, ":")),
            ),
            (
                "hex wrapped after a word ending in a to f",
                format!("private value:\n{}", wrapped(&hex(&scalar), 32, "\n")),
            ),
            (
                "base64url after words",
                format!("the key is {}", URL_SAFE_NO_PAD.encode(scalar)),
            ),
            // "keyfile" ends in an odd number of hex digits, so the file's hex starts at the second.
            (
                "key file hex after an odd word",
                format!("keyfile:{}", hex(&pkcs8)),
            ),
            // Bug caught (issue 946): an owner's key, tried only at a word's ends or as a whole line
            // run together, went out wrapped after words, spaced out, or glued to a word each side.
            (
                "base64 wrapped over lines after words",
                format!(
                    "here it is\n{}",
                    wrapped(&STANDARD_NO_PAD.encode(scalar), 22, "\n")
                ),
            ),
            (
                "base64 spaced in fours after a word",
                format!("key {}", wrapped(&STANDARD.encode(scalar), 4, " ")),
            ),
            (
                "base64url between two words",
                format!("note{}bye", URL_SAFE_NO_PAD.encode(scalar)),
            ),
            (
                "hex between two hex words",
                format!("cafe{}beef", hex(&scalar)),
            ),
            (
                "hex wrapped between words of hex letters",
                format!("added\n{}\nface", wrapped(&hex(&scalar), 32, "\n")),
            ),
        ];
        forms.into()
    }

    /// Bug caught: a key found only in the one encoding Signet keeps it in, so a fooled agent's
    /// `openssl` or `base64` of the key file, or its JWK, goes out.
    #[test]
    fn a_key_is_found_in_every_form_it_could_be_pasted_in() {
        let key = SigningKey::generate().unwrap();
        let secrets = secrets_of(&key);
        for (form, text) in pasted_forms(&key) {
            assert_eq!(
                secrets.found_in(&text),
                Some(SecretKind::PrivateKey),
                "{form}"
            );
        }
    }

    /// Bug caught (issue 946): an owner's key file, or their backup key, beside the agent went out in
    /// any form, as Signet holds neither and looked only for keys it holds. Each is found by its public
    /// half alone, and someone else's key in the same forms still passes.
    #[test]
    fn an_owners_keys_and_backup_are_found_by_their_public_halves() {
        let owner = SigningKey::generate().unwrap();
        let backup = SigningKey::generate().unwrap();
        let seal = SealingKey::generate().unwrap();
        let sealing_scalar = <[u8; SCALAR_LEN]>::try_from(seal.private_bytes().as_slice()).unwrap();
        let seal_as_key = SigningKey::from_scalar(&sealing_scalar).unwrap();
        let rule = RecoveryRule::backup_key(&backup.public_key());
        // A second device's key, as an owner with more than one sign-in has.
        let laptop = SigningKey::generate().unwrap();
        let id = Identity::create(&owner, &seal.public_key(), rule)
            .unwrap()
            .add_key(&owner, &laptop, 1_800_000_000)
            .unwrap();
        let mut secrets = OwnSecrets::default();
        secrets.private_keys_of(&id);
        for (whose, key) in [
            ("owner", &owner),
            ("second device", &laptop),
            ("backup", &backup),
            ("seal", &seal_as_key),
        ] {
            for (form, text) in pasted_forms(key) {
                assert_eq!(
                    secrets.found_in(&text),
                    Some(SecretKind::OwnerKey),
                    "{whose}: {form}"
                );
            }
        }
        let stranger = SigningKey::generate().unwrap();
        for (form, text) in pasted_forms(&stranger) {
            assert_eq!(secrets.found_in(&text), None, "stranger: {form}");
        }
    }

    /// Bug caught: looking for an owner's key refused ordinary content, such as a long list of IDs or
    /// hashes, by counting each place a key could start twice and hitting the limit.
    #[test]
    fn ordinary_content_passes_with_an_owners_keys_known() {
        let owner = SigningKey::generate().unwrap();
        let rule = RecoveryRule::backup_key(&SigningKey::generate().unwrap().public_key());
        let id = Identity::create(&owner, &crate::test_seal(), rule).unwrap();
        let mut secrets = OwnSecrets::default();
        secrets.private_keys_of(&id);
        let hashes: Vec<String> = (0..2_100_u32)
            .map(|at| {
                format!(
                    "\"{}\"",
                    hex(
                        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &at.to_le_bytes())
                            .as_ref()
                    )
                )
            })
            .collect();
        let mut noise = 0x9e37_79b9_u32;
        let mut random_bytes = |count: usize| -> Vec<u8> {
            (0..count)
                .map(|_| {
                    noise ^= noise << 13;
                    noise ^= noise >> 17;
                    noise ^= noise << 5;
                    noise.to_le_bytes().first().copied().unwrap_or_default()
                })
                .collect()
        };
        let ids: Vec<String> = (0..1_200)
            .map(|_| format!("splint1{}", hex(&random_bytes(32))))
            .collect();
        // Bug caught: each run's two ends counted against the limit meant for DER, so an attachment,
        // a certificate bundle or a list of IDs over about 130 KB was refused as holding a key.
        let mime = wrapped(&STANDARD.encode(random_bytes(110_000)), 76, "\r\n");
        let certificates: String = (0..48)
            .map(|_| {
                let body = wrapped(&STANDARD.encode(random_bytes(3_000)), 64, "\n");
                format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
            })
            .collect();
        // Bug caught: every place in runs a little longer than a key counted against the runs' ends
        // limit, so a list of tokens or hashes just longer than a key, over about 60 KB, was refused.
        let tokens: Vec<String> = (0..1_000)
            .map(|_| STANDARD.encode(random_bytes(44)))
            .collect();
        let integrity: Vec<String> = (0..2_100)
            .map(|_| format!("sha256-{}", STANDARD.encode(random_bytes(32))))
            .collect();
        let long_hex: Vec<String> = (0..1_000).map(|_| hex(&random_bytes(40))).collect();
        let texts = [
            tokens.join("\n"),
            integrity.join(" "),
            long_hex.join("\n"),
            format!("[{}]", hashes.join(",")),
            ids.join(","),
            ids.join("\n"),
            mime,
            certificates,
            "Lunch on Tuesday at noon? That will make sure your team is in, and we can plan the rest then.".to_owned(),
            hex(owner.public_key().as_bytes()),
            STANDARD.encode(owner.public_key().as_bytes()),
        ];
        for (place, text) in texts.iter().enumerate() {
            assert_eq!(secrets.found_in(text), None, "text {place}");
        }
        // Bug caught: with no limit, text dense with different places a key could start, still under
        // the size limit, took seconds to look through. Each `0420` here starts a different 32 bytes.
        let dense: String = (0..MAX_SCANNED_BYTES / 10)
            .map(|at| format!("0420{:04x}", at % 0x1_0000))
            .collect();
        assert_eq!(secrets.found_in(&dense), Some(SecretKind::OwnerKey));
    }

    /// Bug caught: a token found only as written, so upper case or a line break gets it past.
    #[test]
    fn a_token_is_found_in_either_case_and_across_line_breaks() {
        let secrets = secrets_of(&SigningKey::generate().unwrap());
        for text in [
            format!("use {TOKEN} please"),
            TOKEN.to_uppercase(),
            wrapped(TOKEN, 20, "\r\n"),
        ] {
            assert_eq!(secrets.found_in(&text), Some(SecretKind::AccessToken));
        }
        let mut other = OwnSecrets::default();
        other.token("token-for-ana");
        assert_eq!(
            other.found_in("it's token-\nfor-ana"),
            Some(SecretKind::AccessToken)
        );
        assert_eq!(other.found_in("it's TOKEN-FOR-ANA"), None);
    }

    /// Bug caught: Splint's own codes going out because a person or the page spelled them a little
    /// differently from how they're parsed.
    #[test]
    fn splint_codes_are_found_however_a_paste_spaces_them() {
        let secrets = OwnSecrets::default();
        let found = [
            (
                "splint-pair:splint.example/abcdefghijklmnopqrstuvwxyz/abcdefghijklmnopqrstuvwxya",
                SecretKind::PairingCode,
            ),
            (
                "here: SPLINT-PAIR: 127.0.0.1:7481/ABCDEFGHIJ\nKLMNOPQRSTUVWXYZ/x",
                SecretKind::PairingCode,
            ),
            ("abcd-efgh-ijkl-mnop-qrst-uvwx-y4", SecretKind::RecoveryCode),
            (
                "my code is ABCD-EFGH-\nIJKL-MNOP - QRST-UVWX-YA thanks",
                SecretKind::RecoveryCode,
            ),
        ];
        for (text, kind) in found {
            assert_eq!(secrets.found_in(text), Some(kind), "{text}");
        }
    }

    /// Bug caught: a recovery code found only with the page's dashes, so one a person spaced, ran
    /// together or regrouped, which `RecoveryCode::parse` still takes, went out.
    #[test]
    fn a_recovery_code_is_found_however_a_person_groups_it() {
        let secrets = OwnSecrets::default();
        let code = "k3vqxw7bnd2hjt5rmpczy4fgsa";
        let grouped = |size: usize, by: &str| wrapped(code, size, by);
        for (form, text) in [
            ("run together", format!("it's {code}")),
            ("run together, in capitals", code.to_uppercase()),
            ("spaced in fours", format!("code: {} ok", grouped(4, " "))),
            (
                "spaced in fours, in capitals",
                grouped(4, " ").to_uppercase(),
            ),
            (
                "in capitals with no digit",
                "ABCD EFGH IJKL MNOP QRST UVWX YA".to_owned(),
            ),
            ("spaced in pairs", grouped(2, " ")),
            ("dashed in fives", grouped(5, "-")),
            ("halves on two lines", grouped(13, "\n")),
            ("escaped breaks", grouped(4, "\\n")),
            ("spaced dashes", grouped(4, " - ")),
        ] {
            assert_eq!(
                secrets.found_in(&text),
                Some(SecretKind::RecoveryCode),
                "{form}"
            );
        }
    }

    /// Bug caught: a ceiling that reads ordinary sentences, lists, IDs or encoded keys as a code
    /// regrouped, so an agent can't say everyday things.
    #[test]
    fn ordinary_sentences_never_read_as_a_recovery_code() {
        let secrets = OwnSecrets::default();
        let mut noise = 0x2545_f491_u32;
        let mut random_bytes = || {
            (0..96)
                .map(|_| {
                    noise ^= noise << 13;
                    noise ^= noise >> 17;
                    noise ^= noise << 5;
                    noise.to_le_bytes().first().copied().unwrap_or_default()
                })
                .collect::<Vec<u8>>()
        };
        let mut encoded = Vec::new();
        for _ in 0..200 {
            encoded.push(STANDARD.encode(random_bytes()));
            encoded.push(URL_SAFE_NO_PAD.encode(random_bytes()));
        }
        let sentences = [
            "they said that this will help me",
            "they said that this will help me with the move next week",
            "Room 5 at the 3rd floor near the lifts, then meet at 2pm on the 24th for 45 minutes.",
            "We could do Tuesday or Wednesday afternoon; anything after 3 works for the team here.",
            "a b c d e f g h i j k l m n o p q r s t u v w x y z",
            "state-of-the-art, well-known and up-to-date: re-enter the as-yet-unnamed one-to-one",
            "https://example.com/blog/how-to-make-good-bread-at-home-in-a-week",
            "Request 7be1c0ffee5a2b4d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5 is waiting",
            "splint1f0e1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f",
            "123e4567-e89b-12d3-a456-426614174000 and 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",
            "Shopping:\n- milk\n- eggs\n- bread\n- butter\n- cheese\n- apples",
            "I'll be there at 5 and we can talk about the 2 quotes and the 7 day plan",
            "OK, SEE YOU AT NOON THEN. BRING THE PAPERS AND THE KEYS PLEASE",
        ];
        let texts = sentences
            .iter()
            .map(|text| (*text).to_owned())
            .chain(encoded);
        for (place, text) in texts.enumerate() {
            assert_eq!(secrets.found_in(&text), None, "text {place}: {text}");
        }
    }

    /// Bug caught: a ceiling so broad that ordinary words, a guide to pairing, or this agent's own
    /// public key can't be sent.
    #[test]
    fn ordinary_words_and_public_halves_pass() {
        let key = SigningKey::generate().unwrap();
        let secrets = secrets_of(&key);
        let public = key.public_key();
        for (place, text) in [
            "Lunch on Tuesday at noon? That will make sure your team is in.".to_owned(),
            "Paste me the code that starts splint-pair: and I'll take it from there".to_owned(),
            "codes look like splint-pair:<host>/<secret>/<owner>".to_owned(),
            "splint-pair: codes. See docs/pairing and then everything else there".to_owned(),
            "abcd-efgh-ijkl-mnop-qrst-uvwx-yb is not a code, its spare bits are set".to_owned(),
            hex(public.as_bytes()),
            STANDARD.encode(public.as_bytes()),
            TOKEN.get(..32).unwrap_or_default().to_owned(),
        ]
        .into_iter()
        .enumerate()
        {
            // By place, so a failure prints no part of the token.
            assert_eq!(secrets.found_in(&text), None, "text {place}");
        }
    }
}

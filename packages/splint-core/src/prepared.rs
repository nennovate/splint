//! What an owner's page or Splint on their computer prepares and hands their sign-in to sign: owner
//! objects as ES256 signing inputs, `header.payload`, made elsewhere. The program holding the key reads
//! each one before anything is signed, so it can tell the person what they are in its own words, and
//! signs only owner types. See "Splint on your computer" in `docs/protocol.md`.

use aws_lc_rs::digest;

use crate::{Error, SigningKey, jws};

/// More than any owner object comes to.
const MAX_INPUT_CHARS: usize = 64 * 1024;
/// What a touch code hashes first, so it's never another hash this protocol takes.
const CODE_TAG: &[u8] = b"splint touch code v1";

/// One owner object, ready to sign.
pub struct Prepared {
    typ: &'static str,
    input: String,
    payload: Vec<u8>,
}

impl Prepared {
    /// A signing input with an ES256 header naming an owner type, and a payload that's JSON. Anything
    /// else is [`Error::Malformed`], so the key never signs what isn't an owner's to sign.
    pub fn read(input: &str) -> Result<Self, Error> {
        if input.len() > MAX_INPUT_CHARS || input.matches('.').count() != 1 {
            return Err(Error::Malformed);
        }
        let typ = jws::owner_type_of(input).ok_or(Error::Malformed)?;
        if jws::signing_input(jws::Alg::Es256, typ, b"")?
            .split('.')
            .next()
            != input.split('.').next()
        {
            return Err(Error::Malformed);
        }
        let (_, payload) = input.split_once('.').ok_or(Error::Malformed)?;
        let payload = jws::decode(payload)?;
        serde_json::from_slice::<serde_json::Value>(&payload).map_err(|_| Error::Malformed)?;
        Ok(Self {
            typ,
            input: input.to_owned(),
            payload,
        })
    }

    pub fn typ(&self) -> &'static str {
        self.typ
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The whole object, signed by `key`.
    pub fn sign(&self, key: &SigningKey) -> Result<String, Error> {
        jws::sign_input(key, &self.input)
    }
}

/// The short code one touch over these objects shows, on the device's own prompt and on the page that
/// prepared them, so a person can see the two are the same: the first 4 bytes of SHA-256 over the tag
/// and each signing input's SHA-256, in order, as 8 capital hex digits in two groups.
pub fn touch_code(inputs: &[Prepared]) -> String {
    touch_code_of(inputs.iter().map(|prepared| prepared.input.as_str()))
}

/// The same code over any signed texts one touch answers, such as the asks an owner approves at once.
pub fn touch_code_of<'a>(texts: impl IntoIterator<Item = &'a str>) -> String {
    let mut whole = CODE_TAG.to_vec();
    for text in texts {
        whole.extend_from_slice(digest::digest(&digest::SHA256, text.as_bytes()).as_ref());
    }
    let hash = digest::digest(&digest::SHA256, &whole);
    let hex: String = hash
        .as_ref()
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02X}"))
        .collect();
    let (first, second) = hex.split_at(4);
    format!("{first} {second}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug caught: a sign-in signing an agent's type, a WA256 header or a second object smuggled in
    /// after the first, for whoever prepared it.
    #[test]
    fn only_one_owner_object_with_an_es256_header_is_signed() {
        let key = SigningKey::generate().unwrap();
        let rules = jws::signing_input(jws::Alg::Es256, "splint-rules", br#"{"v":1}"#).unwrap();
        let prepared = Prepared::read(&rules).unwrap();
        assert_eq!(prepared.typ(), "splint-rules");
        let signed = prepared.sign(&key).unwrap();
        assert!(signed.starts_with(&rules));

        let refused = [
            jws::signing_input(jws::Alg::Es256, "splint-envelope", br#"{"v":1}"#).unwrap(),
            jws::signing_input(jws::Alg::Wa256, "splint-rules", br#"{"v":1}"#).unwrap(),
            jws::signing_input(jws::Alg::Es256, "splint-rules", b"not json").unwrap(),
            format!("{rules}.{rules}"),
            signed,
        ];
        for input in refused {
            assert_eq!(
                Prepared::read(&input).err(),
                Some(Error::Malformed),
                "{input}"
            );
        }
    }
}

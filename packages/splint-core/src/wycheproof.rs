//! Runs Wycheproof's ECDSA P-256 vectors against the signature check every signed object uses.
//!
//! Each case goes through `PublicKey::from_bytes` and `PublicKey::verify`, the calls `jws::verify`
//! makes for envelopes, IDs, bindings and approvals. The JWS layer also refuses any signature that
//! isn't 64 bytes before it gets here, so these run without that guard, to show the check under it
//! is right by itself. The file, its source and its license are in `testdata/wycheproof/`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use aws_lc_rs::digest;
use serde::Deserialize;

use crate::PublicKey;

const FILE: &str = "ecdsa_secp256r1_sha256_p1363_test.json";
/// Recorded in `testdata/wycheproof/README.md` with the commit it came from.
const FILE_SHA256: &str = "c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986";
const VALID_CASES: usize = 173;
const INVALID_CASES: usize = 89;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorFile {
    algorithm: String,
    number_of_tests: usize,
    test_groups: Vec<Group>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    #[serde(rename = "type")]
    kind: String,
    sha: String,
    public_key: GroupKey,
    tests: Vec<Case>,
}

#[derive(Deserialize)]
struct GroupKey {
    curve: String,
    uncompressed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    tc_id: u32,
    comment: String,
    msg: String,
    sig: String,
    result: String,
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex: {text}");
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |byte: u8| char::from(byte).to_digit(16).unwrap();
            u8::try_from(digit(pair[0]) * 16 + digit(pair[1])).unwrap()
        })
        .collect()
}

fn read_vectors() -> VectorFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/wycheproof")
        .join(FILE);
    let bytes = fs::read(&path).unwrap();
    let hash = digest::digest(&digest::SHA256, &bytes);
    assert_eq!(
        hex(FILE_SHA256),
        hash.as_ref(),
        "{FILE} isn't the copy recorded in testdata/wycheproof/README.md"
    );
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn wycheproof_p256_signatures_agree_with_splint() {
    let vectors = read_vectors();
    assert_eq!(vectors.algorithm, "ECDSA");

    let mut results: BTreeMap<String, usize> = BTreeMap::new();
    let mut disagreements = Vec::new();
    for group in &vectors.test_groups {
        assert_eq!(group.kind, "EcdsaP1363Verify");
        assert_eq!(group.sha, "SHA-256");
        assert_eq!(group.public_key.curve, "secp256r1");
        let key = PublicKey::from_bytes(&hex(&group.public_key.uncompressed));
        for case in &group.tests {
            *results.entry(case.result.clone()).or_default() += 1;
            // "acceptable" would need a decision about what Splint should do, so it isn't guessed.
            let expected = match case.result.as_str() {
                "valid" => true,
                "invalid" => false,
                other => panic!(
                    "case {} has result {other}, which needs a decision",
                    case.tc_id
                ),
            };
            let accepted = key
                .as_ref()
                .is_ok_and(|key| key.verify(&hex(&case.msg), &hex(&case.sig)).is_ok());
            if accepted != expected {
                disagreements.push(format!(
                    "case {} ({}): expected {}, Splint {}",
                    case.tc_id,
                    case.comment,
                    case.result,
                    if accepted { "accepted" } else { "refused" }
                ));
            }
        }
    }

    let ran: usize = results.values().sum();
    eprintln!(
        "wycheproof {FILE}: {ran} cases, {results:?}, {} disagreements",
        disagreements.len()
    );
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
    assert_eq!(ran, vectors.number_of_tests);
    assert_eq!(results.get("valid"), Some(&VALID_CASES));
    assert_eq!(results.get("invalid"), Some(&INVALID_CASES));
}

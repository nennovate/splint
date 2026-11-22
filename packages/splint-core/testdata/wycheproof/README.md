# Wycheproof vectors

Third-party test vectors, copied unchanged, that `src/wycheproof.rs` runs against Splint's own signature check in `cargo test`, so in `make check`.

| | |
|---|---|
| File | `ecdsa_secp256r1_sha256_p1363_test.json`: ECDSA on P-256 with SHA-256, signatures as fixed-length `r ‖ s`, the form an ES256 signature takes |
| Cases | 262: 173 valid, 89 invalid |
| Source | https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json |
| Commit | `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` of C2SP/wycheproof, 2026-10-23 |
| SHA-256 | `c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986` |
| License | Apache License 2.0, copied from the same commit into [`LICENSE`](LICENSE) |

The test checks the file's SHA-256 before it reads it, so a changed copy fails rather than quietly running different cases.

To update, download the file from a newer commit, then change the commit, hash and counts here and in `src/wycheproof.rs`.

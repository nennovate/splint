# Test vectors

Signed examples of every format, valid and hostile, so any implementation can be checked against [the protocol](../../docs/protocol.md). An independent verifier can use these with no Splint code.

**Formats are provisional, so these will change without notice until formats are frozen.**

## Reading a vector

```json
{"name":"expired","status":"checked","case":"hostile","check":"envelope.verify","why":"...","input":{},"expect":{"ok":false,"reason":"expired"}}
```

| Field | Meaning |
|---|---|
| `status` | `checked`: Splint's code runs it in `make check`. `pending`: its code doesn't exist yet |
| `case` | `valid` or `hostile` |
| `check` | What to run on `input` |
| `expect` | The result. `reason` is Splint's typed error. Another implementation has to refuse, but can word it differently |
| `issue` | On a pending vector, the issue that builds its code |
| `signed` | On a pending vector, each signature directly in `input`: where it is, its `typ` and which key in `keys.json` made it. An approval inside a step's body isn't listed |

A chain or outcome vector reads each type's rules from the example schemas in [`spec/schemas/`](../schemas/), which core knows nothing about.

Bytes are base64url without padding, except `grant.check`'s `body`, which is the raw JSON text. `now` is the verifier's clock, in unix seconds.

An owner whose key is a [passkey](../../docs/protocol.md#owner-keys-in-a-passkey) has a version 5 identity, `ana-passkey` in `keys.json`, and signs WA256. The generator stands in for an authenticator, building `authenticatorData` and `clientDataJSON` as a browser would, so each hostile WA256 vector is a real assertion with one thing changed: the challenge, the origin, the RP ID's hash, the user present or verified flag, the type, `crossOrigin`, a key twice, `clientDataJSON` that isn't UTF-8, an `authenticatorData` too short, the segment's length, the key, or the header against the ID's kind. The file key's assertion is made for an empty RP ID, so only the header against the ID's kind refuses it. One touch can also sign several objects, each carrying the list of their hashes as `b`: `binding.verify` has a binding from such a batch, and the list without its own hash, with it twice, of nine, of one, in capitals and reordered, and `rules.verify` the rules from the same touch. `binding.verify` holds most of them, `rules.verify` a valid one and two refused, `approval.verify` a valid one, and `identity.parse` and `identity.read` the events and the recoveries to a passkey and back. The Go verifier has no `rules.verify` yet, so it checks the rest.

In a chain vector, the steps in `chain` count as already received, so their envelope dates aren't checked, apart from the last step's if `last_arrived_at` is set, which is the reader's clock when it first arrived. `keep_first` is how many steps have to stay first when trying other orders. A result's `over_cap` counts steps refused at a cap, which a reader carries on past, and `copies_dropped` counts copies of an owner's yes past the two a reader keeps. `head` and `version` are null on a disputed request.

## Files

| File | Contract | Status |
|---|---|---|
| `identity.json`, `addresses.json` | [IDs and addresses](../../docs/protocol.md#ids-and-addresses), owner keys and passkeys, bindings, registration, retirement | Checked |
| `identity-keys.json` | [An owner's keys](../../docs/protocol.md#an-owners-keys): keys an owner's ID adds, each with the added key's own signature, and removes, a recovery code set later, which keys count after each statement (`identity.keys`), which of two copies counts (`identity.newest_keys`), and rules, approvals, bindings, delegations and histories checked under those keys. Keys these vectors name that aren't in `keys.json` come from their labels the same way | Checked |
| `changes.json` | [Changes](../../docs/protocol.md#changes) to an ID: the history, what a reader's rules say, and an owner's yes | Checked |
| `envelope.json` | [Envelope](../../docs/protocol.md#envelope) | Checked |
| `access-proof.json`, `delivery-proof.json`, `delivery-failure.json` | [Host API](../../docs/protocol.md#host-api) | Checked |
| `protocol-range.json` | [Protocol version](../../docs/protocol.md#protocol-version): the range a program says it speaks in `splint-protocols`, and the number a pair uses, or which side is behind when they share none (`protocol.choose`). The Go verifier checks signed objects, so it doesn't run these | Checked |
| `host-id.json` | [Host IDs](../../docs/protocol.md#host-ids) | Checked in Rust; the Go verifier checks no host object |
| `requests.json` | [Interactions](../../docs/protocol.md#interactions), [approvals](../../docs/protocol.md#approvals), outcomes | Checked |
| `approvals.json` | [Approvals](../../docs/protocol.md#approvals) | Checked |
| `contact-rules.json` | [Rules and admission](../../docs/protocol.md#rules-and-admission). An `admit.check` input may carry `agreed`, whether the reader holds its own checked record of an invite and acceptance between the two agents, false when it's left out, as do outbound vectors | `rules.verify`, `admit.check` and `invite.redeem` checked, `rules_applied.verify` pending |
| `outbound-fields.json` | [Messages](../../docs/protocol.md#messages) | Checked |
| `grants.json` | [Grants and the resource check](../../docs/protocol.md#grants-and-the-resource-check) | Checked |
| `payments.json` | [Payments](../../docs/protocol.md#payments): request chains that ask to be paid and say it arrived | Checked |
| `types.json` | [Interaction types](../../docs/protocol.md#interaction-types): a schema's fingerprint (`type.id`) and a proposal of one (`type.propose`) | Checked |
| `invites.json` | [Invites over Splint](../../docs/protocol.md#invites-over-splint): an invite, the pending contact an invite and its acceptance make, and contact cards | Checked |
| `delegation.json` | [Signing within limits while away](../../docs/protocol.md#signing-within-limits-while-away): a delegation, rules renewed under the delegation they name, a delegate's yes, and a chain and an outcome read back across a recovery, each checked against what the owner signed | Checked |
| `pairing.json` | [Pairing by code](../../docs/protocol.md#pairing-by-code), dropped on 2026-11-21: a code, a pairing as a host and as an agent check it, and an agent's answer as a page checked it. Nothing makes or takes one now, so Rust checks the code and the pairing, the Go verifier all of it, and the vectors stay until the format is removed | Checked |
| `controls.json` | [Setting up your controls](../../docs/protocol.md#setting-up-your-controls): the exact signing inputs `owner-key` makes from what the owner chose, and the one touch's challenge. The Go verifier only verifies, so it doesn't run these, and Rust does | Checked |
| `owner-api.json` | [Owner API](../../docs/protocol.md#owner-api): an owner's session as a host checks it, a read its key signs, a yes its key signs as though it were the owner's, and the owner's sealed list of agents, with its passkey's handle and the copy sealed to their backup, and the list opened as the owner's page opens it, and a passkey sign-in's locked copy of the owner's reading key opened with its lock (`reading_key.open`), which hosts no longer keep. And a call's body an owner's device [seals to its agent's Signet](../../docs/protocol.md#reaching-a-signet-straight), opened as that Signet opens it (`owner_call.open`), and what an owner's device leaves at the agent's host for it, opened as owner mail (`owner_mail.open`). Those are sealed with HPKE written out in `generate.py` from RFC 9180, with an ephemeral key from a label, and Rust and the Go verifier each open them with their own HPKE, and the owner page's own test the list and the view | Checked |
| `owner-keys.json` | [Keys an owner's page derives](../../docs/protocol.md#keys-an-owners-page-derives): the backup key from a recovery code, as shown and as typed back, and the sealing key and a sign-in's lock from a passkey's PRF output, which nothing derives now. Rust and the Go verifier run the backup and the sealing key, the Go verifier alone the lock, and the owner page's own test the backup | Checked |
| `asks.json` | [An agent's ask](../../docs/protocol.md#an-agents-ask): exact changes an agent asks its owner for, signed by its own key, as the owner's side reads one before showing it: in date, by that agent, one thing about each setting or contact, no words of the agent's, and short. And [an answer to an ask for controls](../../docs/protocol.md#an-answer-to-an-ask-for-controls) (`ask.answer`): the MAC by the ask's ID over the answering owner's ID, and where its host keeps it. Rust and the Go verifier run these, apart from `move.reply`, which only Rust runs: Splint on the computer reads an ask with Rust, so the owner page doesn't. Provisional | Checked |
| `guest-links.json` | [Guest links](../../docs/protocol.md#guest-links) | `guest.walk`, `guest.outcome` and `guest_identity.parse` checked |
| `keys.json` | Published test public keys | |
| `manifest.json` | Hashes of the tool, the request rules and every file | |

## What runs them

- `packages/splint-core/src/spec_vectors.rs` runs every checked vector. For a pending one, it checks each signature listed in `signed`, so it'll fail for its stated reason once its code lands. It also fails if a pending vector's check is in its hand-kept `CHECKS` list, so remember to add a check there when its code lands. A check nothing in Rust makes any more, though its format stays, is in `GO_ONLY_CHECKS` instead, and only the Go verifier runs it. It walks each chain with a final state in the orders a host could deliver it, every order for a short chain and a sample for a flood, and requires the same result.
- `tools/vectors/test_spec.py` walks the state table in `docs/protocol.md`, checks the numbers it states, and checks `manifest.json`, which catches hand edits, a stale tool and changed request rules.
- The chain and outcome vectors in `requests.json` and `guest-links.json` run against a small reference walk in `make check` too, leaving out those that turn only on a signature, which it doesn't check there. That's Python written from the protocol, so two separate walks agree on `requests.json` and `guest-links.json`. It also walks each chain in the orders a host could deliver it, and an implementation should keep a reader that holds a set of steps, and can run the same check.
- Pending vectors outside those chains state what the protocol says should happen, and no code has run them. Expect the first implementation to find mistakes in them.

## Regenerating

`make vectors` runs `tools/vectors/generate.py`. Keys come from public labels and signatures are deterministic, so the same inputs give the same files. It needs `uv`, for one Python dependency. `make check` doesn't.

When code lands for a check: add it to `CHECKS` in `spec_vectors.rs`, drop the `issue` argument in the generator, and regenerate.

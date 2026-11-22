// The owner page's own crypto against spec/vectors, in node's WebCrypto, which is the browser's API. It
// runs keys.js as the page does, as a plain script, so what's checked is the file Splint on an owner's
// computer serves.
//
//     node packages/splint/src/page/web/keys_test.mjs
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = (name) => JSON.parse(readFileSync(join(here, "../../../../../spec/vectors", name), "utf8")).vectors;
const page = vm.createContext({ crypto, TextEncoder, TextDecoder, btoa, atob, Uint8Array, BigInt });
// The page loads terms.js first, for its check of hidden characters.
vm.runInContext(readFileSync(join(here, "../terms.js"), "utf8"), page);
vm.runInContext(readFileSync(join(here, "keys.js"), "utf8"), page);
const call = (name, ...args) => page[name](...args);

let failures = 0;
let ran = 0;
function check(name, passed, detail) {
  ran += 1;
  if (!passed) {
    failures += 1;
    console.log(`FAIL ${name}: ${JSON.stringify(detail)}`);
  }
}

// What a page can't do refuses with a throw, and the vectors say "malformed".
async function outcome(run) {
  try {
    return await run();
  } catch (error) {
    return { ok: false, reason: error.message };
  }
}

for (const vector of vectors("owner-keys.json")) {
  if (vector.check === "recovery_code.backup") {
    const got = await outcome(async () => {
      const code = call("parseRecoveryCode", vector.input.code);
      if (vector.input.bytes) {
        check(`${vector.name}: the page shows the code as the vector does`, call("hex", code) === vector.input.bytes, call("hex", code));
        if (!vector.input.code.includes(" ")) {
          check(`${vector.name}: spelled in groups of 4`, call("spelledCode", code) === vector.input.code, call("spelledCode", code));
        }
      }
      const backup = await call("backupFromCode", code);
      return { ok: true, backup: call("b64url", backup.point), commitment: backup.commitment };
    });
    check(vector.name, JSON.stringify(got) === JSON.stringify(vector.expect), got);
  } else if (vector.check === "touch.code") {
    // Bug this catches: a page whose code differs from the device's prompt over the same objects, or
    // one over only some of them, so a hidden object wouldn't change what the person compares.
    const got = await outcome(async () => ({ ok: true, code: await call("touchCodeOf", vector.input.inputs) }));
    check(vector.name, JSON.stringify(got) === JSON.stringify(vector.expect), got);
  }
}

// Everything a host hands the page that an owner's passkey signed, before Nenye's decision of 2026-11-21
// that owners sign only on their own computers, it still checks with verifyByOwner: lists, bindings,
// rules. So every passkey-signed object in the vectors goes through it: one that verifies
// must, and one refused for its signature, its assertion or its batch must be refused here too. What a
// vector refuses for its payload, such as a date, is for the page's own checks after this one, and an
// owner read's refusals are of the session key's proof, which the page makes and never checks.
const ALL_FILES = ["approvals.json", "contact-rules.json", "delegation.json", "identity.json", "identity-keys.json", "owner-api.json"];
const SIGNATURE_REASONS = new Set(["bad_signature"]);
// Only identity.json's binding cases change the passkey's signature segment and nothing else, so each
// of its refusals is one this check makes. The page reads clientDataJSON with JSON.parse, which keeps
// the last of a key given twice: only the owner's own browser writes those bytes, which their passkey
// then signs, so nobody else can hand the page one.
const PAGE_TAKES = new Set(["passkey_binding_with_a_key_twice"]);
let passkeyChecks = 0;
for (const file of ALL_FILES) {
  for (const vector of vectors(file)) {
    const input = vector.input || {};
    if (typeof input.owner_identity !== "string") continue;
    for (const value of Object.values(input)) {
      if (typeof value !== "string" || value.split(".").length < 3) continue;
      const compact = value.split("~")[0];
      let header;
      try {
        header = JSON.parse(new TextDecoder().decode(call("fromB64url", compact.split(".")[0])));
      } catch {
        continue;
      }
      if (!header || header.alg !== "WA256") continue;
      const got = await outcome(async () => {
        const owner = await call("readIdentity", input.owner_identity);
        await call("verifyByOwner", compact, header.typ, owner);
        return { ok: true };
      });
      const reason = vector.expect.ok ? null : vector.expect.reason;
      const segmentOnly = file === "identity.json" && vector.check === "binding.verify";
      if (reason === null) {
        passkeyChecks += 1;
        check(`${vector.name}: verifies on the page`, got.ok === true, got);
      } else if ((SIGNATURE_REASONS.has(reason) && vector.check !== "owner_access.verify") || (segmentOnly && !PAGE_TAKES.has(vector.name))) {
        passkeyChecks += 1;
        check(`${vector.name}: refused on the page`, got.ok === false, got);
      }
      break;
    }
  }
}
check("the passkey vectors reach the page's check", passkeyChecks >= 30, passkeyChecks);

// An owner's ID with every statement, which the page reads for the sign-ins that count now. Bug this
// catches: a page refusing an owner who recovered or added a sign-in, or taking a sign-in no
// addition's own key signed for.
let ownerIdentities = 0;
for (const vector of vectors("identity-keys.json")) {
  if (vector.check !== "identity.keys") continue;
  ownerIdentities += 1;
  const got = await outcome(async () => {
    const read = await call("readIdentity", vector.input.identity);
    return { ok: true, id: read.id, keys: read.keys.map((one) => call("b64url", one.key)), recoveries: read.recoveries, statements: read.statements };
  });
  if (vector.expect.ok) {
    check(`${vector.name}: the page reads the sign-ins that count`, JSON.stringify(got) === JSON.stringify(vector.expect), got);
  } else {
    // For the reason Rust and Go give, so a refusal that comes from somewhere else, such as WebCrypto
    // choking on what a check let through, doesn't pass for the check.
    check(`${vector.name}: the page refuses it`, got.ok === false && got.reason === vector.expect.reason, got);
  }
}
check("the owner key vectors reach the page", ownerIdentities >= 60, ownerIdentities);
const keysVector = (name) => vectors("identity-keys.json").find((vector) => vector.name === name).input;
// Bug this catches: an ID that added a sign-in and removed it, one key left, read as an agent's, so a
// key it once had would sign for the agent.
const addedAndRemoved = await outcome(async () => call("readAgentIdentity", keysVector("a_key_removes_itself").identity));
check("an ID that added and removed a sign-in is no agent's", addedAndRemoved.ok === false, addedAndRemoved);
// Bugs this catches: a page that never offers the recovery code to an owner made without one, or
// offers it again once it's set, which a reader then refuses.
const later = await call("readIdentity", keysVector("an_owner_with_no_recovery_code_yet").identity);
const codeSet = await call("readIdentity", keysVector("a_key_that_counts_sets_the_code").identity);
check("the page reads an ID made without a code as waiting for one", later.recoveryLater === true && codeSet.recoveryLater === false, [later.recoveryLater, codeSet.recoveryLater]);
// Bug this catches: the page going by the first sign-in that counts rather than the event's key, so an
// owner who replaced their first device is never offered the code.
const replacedFirst = keysVector("a_code_set_after_the_first_sign_in_was_removed").identity;
const stillLater = await call("readIdentity", replacedFirst.split("~").slice(0, -1).join("~"));
check("an ID whose first sign-in was removed still waits for a code", stillLater.recoveryLater === true, stillLater.recoveryLater);
// Bug this catches: an owner with a passkey and a file key, whose stranger's signature the page refused
// as malformed, by trying it under the sign-in that signs the other way, where Rust and Go say why.
const both = await call("readIdentity", keysVector("a_file_key_adds_a_passkey").identity);
const strangers = keysVector("a_binding_by_an_added_key").binding.split("~")[0];
const refusedAs = await outcome(async () => call("verifyByOwner", strangers, "splint-binding", both));
check("a signature by no sign-in of an owner with both kinds is a bad signature", refusedAs.ok === false && refusedAs.reason === "bad_signature", refusedAs);
for (const vector of vectors("identity-keys.json")) {
  if (vector.check !== "identity.newest_keys") continue;
  const got = await outcome(async () => {
    const pinned = await call("readIdentity", vector.input.pinned);
    const claimed = await call("readIdentity", vector.input.claimed);
    const newest = await call("newestOwnerCopy", pinned, claimed);
    return { ok: true, keys: newest.keys.map((one) => call("b64url", one.key)) };
  });
  // The page keeps what it holds where a reader refuses a fork, so only the copies a reader goes by are its to match.
  if (vector.expect.ok) check(`${vector.name}: the page goes by the same copy`, JSON.stringify(got) === JSON.stringify(vector.expect), got);
}

// An agent's ID with its recoveries, which the page reads for the key that signs its view. An agent's
// key is never a passkey, so the vectors about passkey owners aren't an agent's to read.
let agentIdentities = 0;
for (const vector of vectors("identity.json")) {
  if (vector.check !== "identity.read") continue;
  const parts = vector.input.identity.split("~");
  const passkey = (() => {
    try {
      const event = JSON.parse(new TextDecoder().decode(call("fromB64url", parts[0])));
      return event.alg !== "ES256" || parts.slice(1).some((part) => call("payloadOf", part).v !== 2);
    } catch {
      return false;
    }
  })();
  if (passkey && vector.expect.ok) continue;
  agentIdentities += 1;
  const got = await outcome(async () => {
    const read = await call("readAgentIdentity", vector.input.identity);
    return { ok: true, id: read.id, key: call("b64url", read.key) };
  });
  if (vector.expect.ok) {
    check(`${vector.name}: the page reads the agent's key now`, got.ok && got.id === vector.expect.id && got.key === vector.expect.key, got);
  } else {
    check(`${vector.name}: the page refuses it`, got.ok === false, got);
  }
}
check("the recovery vectors reach the page", agentIdentities >= 15, agentIdentities);

for (const vector of vectors("owner-api.json")) {
  if (vector.check !== "owner_view.verify") continue;
  const got = await outcome(async () => {
    const agent = await call("readAgentIdentity", vector.input.agent_identity);
    const opened = await call("verifyOwnerView", vector.input.view, agent, vector.input.owner, vector.input.now);
    return { ok: true, issued_at: opened.issued_at, view: opened.view };
  });
  check(vector.name, JSON.stringify(got) === JSON.stringify(vector.expect), got);
}

for (const vector of vectors("owner-api.json")) {
  if (vector.check !== "owner_agents.open") continue;
  const got = await outcome(async () => {
    const owner = await call("readIdentity", vector.input.owner_identity);
    const sealing = await call("keyOfScalar", call("fromHex", vector.input.sealing), "ECDH");
    const opened = await call("openOwnerAgents", vector.input.list, owner, vector.input.host, sealing);
    return { ok: true, agents: opened.agents };
  });
  check(vector.name, JSON.stringify(got) === JSON.stringify(vector.expect), got);
}

// Where an owner gets paid, as the payment vectors carry it on an ask to be paid: the page's check of
// the places a person types takes every statement a reader takes, and refuses every one a reader
// refuses for what the page itself would sign. Version, owner, date, spelling and signature are the
// page's own to write, so a statement refused for one of those is for Signet alone. Bug this catches:
// the page letting a person sign places every Signet then refuses, such as lno1name@domain read as a
// Lightning address.
let placesChecked = 0;
let placesRefused = 0;
for (const vector of vectors("payments.json")) {
  if (vector.check !== "request.walk" || vector.status !== "checked") continue;
  const chain = vector.input.chain;
  const refusedAt = Number.isInteger(vector.expect.refused_at) ? vector.expect.refused_at : chain.length;
  for (const [index, envelope] of chain.entries()) {
    if (index > refusedAt) break;
    const signed = call("payloadOf", envelope);
    const step = JSON.parse(signed.body);
    if (step.step !== "pay_request") continue;
    if (index === refusedAt && vector.expect.reason !== "bad_where_paid") continue;
    const sender = [vector.input.requester, vector.input.recipient].find((party) => party.agent_id === signed.sender);
    const statement = step.where_paid;
    const text = new TextDecoder().decode(call("fromB64url", statement.split(".")[1]));
    const payload = JSON.parse(text);
    const signedBy = await outcome(async () => call("verifyByOwner", statement, "splint-where-paid", await call("readIdentity", sender.owner_identity)));
    const pageWouldSign = payload.v === 1 && payload.owner === sender.owner_id && JSON.stringify(payload) === text && signedBy.ok !== false
      && Number.isSafeInteger(payload.issued_at) && payload.issued_at <= signed.created_at + 120;
    if (index === refusedAt && !pageWouldSign) continue;
    const got = await outcome(async () => {
      const made = call("wherePaidPayload", payload.owner, payload.places, payload.issued_at);
      return { ok: JSON.stringify(made) === text };
    });
    placesChecked += 1;
    if (index === refusedAt) {
      placesRefused += 1;
      check(`${vector.name}: the page refuses to sign these places`, got.ok === false, got);
    } else {
      check(`${vector.name}: the page signs these places`, got.ok === true, got);
    }
  }
}
check("the payment vectors reach the page's check of places", placesChecked >= 25 && placesRefused >= 15, [placesChecked, placesRefused]);

// A type's ID, which the page works out for itself before it takes a schema a Signet hands over: the
// same spelled any way, and any change another. Bug this catches: a page showing an approval by a schema
// that isn't the one its type's ID names.
for (const vector of vectors("types.json").filter((one) => one.check === "type.id" && one.case === "valid")) {
  const got = await outcome(async () => ({ ok: true, type: await call("typeId", vector.input.schema), one_encoding: call("schemaEncoding", vector.input.schema) }));
  check(vector.name, JSON.stringify(got) === JSON.stringify(vector.expect), got);
}

// Bug this catches: an amount cap reaching what the page signs, so its delegate says yes to a price.
// The shape of a delegation the vectors sign; which owner key signed it doesn't matter to its bytes.
const delegated = vectors("controls.json").find((vector) => vector.name === "controls_by_a_passkey").input;
const withCaps = await outcome(async () => call("delegationInput", "ES256", { owner: "splint1owner", agent: "splint1agent", seq: delegated.seq, now: delegated.now },
  { ...delegated.delegation, caps: { ...delegated.delegation.caps, "quote/1": { "amount_minor.usd": 1000 } } }));
check("the page signs no amount cap", withCaps.ok === false, withCaps);
const withoutCaps = await outcome(async () => call("delegationInput", "ES256", { owner: "splint1owner", agent: "splint1agent", seq: delegated.seq, now: delegated.now }, delegated.delegation));
check("and signs one with none", typeof withoutCaps === "string", withoutCaps);

// Which view the page takes. Bugs this catches: a view read straight from an agent's Signet taken though
// someone on the way kept it, past a moment old or older than one the page saw before, so the page went
// by what the agent had moved past; and a view from the host that doesn't open taken as none.
{
  const now = 1800000000;
  const open = async (sealed) => {
    if (sealed === "not the agent's") throw new Error("bad_signature");
    return { at: Number(sealed) };
  };
  const take = (read, straight, newestSeen) => outcome(async () => {
    let hostReads = 0;
    const readHost = async () => {
      hostReads += 1;
      return { view: String(now - 5) };
    };
    const view = await call("viewToTake", { view: read }, straight, open, readHost, newestSeen, now);
    return { ok: true, at: view && view.at, hostReads };
  });
  const cases = [
    ["one straight, signed 30 seconds ago, is taken", await take(String(now - 30), true, now - 60), { ok: true, at: now - 30, hostReads: 0 }],
    ["one straight, 31 seconds old, newer than any seen, isn't", await take(String(now - 31), true, 0), { ok: true, at: now - 5, hostReads: 1 }],
    ["one straight, 2 seconds old, older than one seen, isn't", await take(String(now - 2), true, now - 1), { ok: true, at: now - 5, hostReads: 1 }],
    ["one straight that doesn't open isn't", await take("not the agent's", true, 0), { ok: true, at: now - 5, hostReads: 1 }],
    ["one from the host is taken however old", await take(String(now - 600), false, now), { ok: true, at: now - 600, hostReads: 0 }],
  ];
  for (const [name, got, want] of cases) check(`the page's view: ${name}`, JSON.stringify(got) === JSON.stringify(want), got);
  const unopened = await take("not the agent's", false, 0);
  check("the page's view: one from the host that doesn't open is refused", unopened.ok === false, unopened);
}

// Issue 896: a kind named like an example that isn't it read as the example on the page asking its owner
// to approve it. The page's list of the examples is held to spec/schemas here, so it can't drift.
{
  const examples = join(here, "../../../../../spec/schemas");
  for (const file of ["meeting-1.json", "quote-1.json", "document-1.json", "rsvp-1.json", "time-1.json"]) {
    const schema = JSON.parse(readFileSync(join(examples, file), "utf8"));
    const id = await call("typeId", schema);
    const shown = call("kindLines", schema, id, []);
    check(`kinds: ${file} reads as the example`, shown.sameName === "the_example", shown);
  }
  const quote = JSON.parse(readFileSync(join(examples, "quote-1.json"), "utf8"));
  const lookalike = { ...quote, paid: { amount_minor: "requester" } };
  const theirs = await call("typeId", lookalike);
  const ours = await call("typeId", quote);
  const shown = call("kindLines", lookalike, theirs, [ours]);
  const fingerprint = (id) => id.split("@")[1].slice(0, 8);
  check("kinds: a lookalike of an example says it's their own, with both fingerprints", shown.sameName === "like_an_example"
    && shown.lines[0].includes(fingerprint(theirs)) && shown.lines[0].includes(fingerprint(ours)), shown);
  check("kinds: its money is shown with whom it's paid to", shown.includesCurrency
    && shown.lines.some((line) => line.includes("amount_minor") && line.includes("money paid to whoever opens it")), shown);
  check("kinds: a number it doesn't label as money says so", shown.lines.some((line) => line.includes("quantity") && line.includes("not labelled as money")), shown);
}

console.log(`${ran - failures} of ${ran} page key checks passed`);
if (failures) process.exit(1);

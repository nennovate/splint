// @ts-check
// The owner page's crypto, every byte of it from docs/protocol.md, with the browser's own WebCrypto and
// nothing else. The owner's key never comes here: Splint on their computer holds it and signs, and this
// only builds what it signs and checks what others signed, an owner ID made with a passkey before
// Nenye's decision of 2026-11-21 among them, so what such an owner signed still verifies. It makes and
// uses no passkey.
//
// spec/vectors checks the derivations, identities, signatures and the owner's list of agents here, in
// keys_test.mjs.
"use strict";

const ENCODER = new TextEncoder();
// A byte-order mark is kept, so JSON.parse refuses it, as every other reader does.
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
// Half a UTF-16 character, which only an escape can put in a parsed string.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
const SECRET_BYTES = 16;
const SECRET_CHARS = 26;
const BATCH_TAG = "splint wa256 batch v1";
const MAX_BATCH = 8;
const BACKUP_SALT = "splint backup v1";
const MAX_SEGMENT_CHARS = 2048;
// An address in its one spelling, as far as a page needs to tell: a handle, maybe an owner part, a
// tilde and a domain. The agent's host is what says it's theirs.
const AN_ADDRESS = /^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)?~[a-z0-9][a-z0-9.-]*(:[0-9]{1,5})?$/;

/** @param {string} text */
function utf8(text) {
  return ENCODER.encode(text);
}

/** @param {...Uint8Array} parts @returns {Uint8Array<ArrayBuffer>} */
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** @param {Uint8Array} bytes */
function b64url(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** One spelling only: no padding, nothing outside the alphabet, and no spare bits set. */
function fromB64url(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw new Error("malformed");
  }
  const plain = atob(text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (text.length % 4)) % 4));
  const bytes = Uint8Array.from(plain, (char) => char.charCodeAt(0));
  if (b64url(bytes) !== text) throw new Error("malformed");
  return bytes;
}

/** @param {Uint8Array} bytes */
function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(text) {
  if (!/^([0-9a-f]{2})*$/.test(text)) throw new Error("malformed");
  return Uint8Array.from(text.match(/../g) || [], (pair) => parseInt(pair, 16));
}

/** @param {Uint8Array<ArrayBuffer>} bytes */
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** @param {Uint8Array<ArrayBuffer>} key @param {Uint8Array<ArrayBuffer>} data */
async function hmac(key, data) {
  // An empty HMAC key is the same as one of zeros, and WebCrypto takes only the second.
  const usable = key.length ? key : new Uint8Array(32);
  const imported = await crypto.subtle.importKey("raw", usable, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, data));
}

/** RFC 5869, with SHA-256. */
async function hkdfExpand(prk, info, length) {
  const blocks = [];
  let block = new Uint8Array(0);
  for (let counter = 1; blocks.length * 32 < length; counter += 1) {
    block = await hmac(prk, concat(block, info, Uint8Array.of(counter)));
    blocks.push(block);
  }
  return concat(...blocks).slice(0, length);
}

/**
 * A P-256 private scalar, as "Keys an owner's page derives" has it: 48 bytes of HKDF-SHA256 under
 * `salt`, info `p256 scalar`, big-endian, modulo the order less one, plus one.
 * @param {Uint8Array<ArrayBuffer>} secret @param {string} salt
 */
async function derivedScalar(secret, salt) {
  const okm = await hkdfExpand(await hmac(utf8(salt), secret), utf8("p256 scalar"), 48);
  const number = BigInt(`0x${hex(okm)}`) % (P256_ORDER - 1n) + 1n;
  return fromHex(number.toString(16).padStart(64, "0"));
}

/** PKCS#8 for a P-256 scalar with no public key, which a browser works out for itself. */
function pkcs8Of(scalar) {
  const head = Uint8Array.of(0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20);
  return concat(head, scalar);
}

/** @param {JsonWebKey} jwk */
function pointOfJwk(jwk) {
  return concat(Uint8Array.of(4), fromB64url(/** @type {string} */ (jwk.x)), fromB64url(/** @type {string} */ (jwk.y)));
}

/**
 * A key on a scalar, held by WebCrypto so it can't be read back, with its public point.
 * @param {Uint8Array<ArrayBuffer>} scalar @param {"ECDSA" | "ECDH"} use
 */
async function keyOfScalar(scalar, use) {
  const algorithm = { name: use, namedCurve: "P-256" };
  const usages = /** @type {KeyUsage[]} */ (use === "ECDSA" ? ["sign"] : ["deriveBits"]);
  const readable = await crypto.subtle.importKey("pkcs8", pkcs8Of(scalar), algorithm, true, usages);
  const jwk = await crypto.subtle.exportKey("jwk", readable);
  const privateKey = await crypto.subtle.importKey("jwk", jwk, algorithm, false, usages);
  return { privateKey, point: pointOfJwk(jwk) };
}

/** A WebCrypto ECDH key for a point, which only checks it's on the curve: one that isn't is malformed. */
async function ecdhPublic(point) {
  return crypto.subtle.importKey("raw", point, { name: "ECDH", namedCurve: "P-256" }, true, []).catch(() => {
    throw new Error("malformed");
  });
}

// ---------- Recovery code and sealing key ----------

/** Lower-case RFC 4648 base32 of 16 bytes, 26 characters, whose 2 spare bits are zero. */
function base32(bytes) {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(buffer >> bits) & 31];
    }
    buffer &= (1 << bits) - 1;
  }
  return bits > 0 ? out + BASE32[(buffer << (5 - bits)) & 31] : out;
}

// ---------- Agreed types ----------

/**
 * A type's schema in its one encoding: every key sorted, every list sorted with no repeats, numbers in
 * order, and an empty list or object, or a `sign` of `none`, left out. A schema's ID is this one's
 * fingerprint, so the page works it out for itself rather than take a Signet's word for it.
 */
function schemaEncoding(schema) {
  const tidy = (value) => {
    if (Array.isArray(value)) {
      const numbers = value.every((item) => typeof item === "number");
      const once = [...new Map(value.map((item) => [JSON.stringify(item), item])).values()];
      return once.sort((a, b) => (numbers ? a - b : JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
    }
    if (value && typeof value === "object") {
      // With no prototype, a field called __proto__ is kept as a field like any other, as every other
      // reader keeps it, rather than set as this object's prototype and lost from the encoding.
      const out = Object.create(null);
      for (const key of Object.keys(value).sort()) {
        const item = tidy(value[key]);
        const empty = (Array.isArray(item) && !item.length) || (item && typeof item === "object" && !Array.isArray(item) && !Object.keys(item).length);
        if (!empty) out[key] = item;
      }
      return out;
    }
    return value;
  };
  if (!schema || typeof schema !== "object" || Array.isArray(schema) || typeof schema.type !== "string") throw new Error("malformed");
  const tidied = tidy(schema);
  if (tidied.sign === "none") delete tidied.sign;
  return JSON.stringify(tidied);
}

/** A type's ID: its name, `@`, and the base32 SHA-256 of `splint type v1`, a zero byte and its one encoding. */
async function typeId(schema) {
  const encoding = schemaEncoding(schema);
  const digest = await sha256(concat(utf8("splint type v1"), new Uint8Array([0]), utf8(encoding)));
  return `${schema.type}@${base32(digest)}`;
}

function fromBase32(text) {
  if (text.length !== SECRET_CHARS) throw new Error("malformed");
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const char of text) {
    const value = BASE32.indexOf(char);
    if (value < 0) throw new Error("malformed");
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 255);
      buffer &= (1 << bits) - 1;
    }
  }
  if (buffer !== 0 || out.length !== SECRET_BYTES) throw new Error("malformed");
  return Uint8Array.from(out);
}

/** As the page shows a recovery code: groups of 4, joined by dashes. */
function spelledCode(bytes) {
  return (base32(bytes).match(/.{1,4}/g) || []).join("-");
}

/** As a person may type it back. */
function parseRecoveryCode(typed) {
  return fromBase32(String(typed).replace(/[\s-]/g, "").toLowerCase());
}

/** The owner's backup key: its point, which the ID commits to, and the commitment. */
async function backupFromCode(code) {
  const { point } = await keyOfScalar(await derivedScalar(code, BACKUP_SALT), "ECDSA");
  return { point, commitment: hex(await sha256(point)) };
}

// ---------- IDs ----------

async function idOf(eventBytes) {
  return `splint1${hex(await sha256(eventBytes))}`;
}

const MAX_RECOVERIES = 8;
const MAX_KEYS = 4;
/** Between one recovery and the next. */
const MAX_ADDITIONS = 8;
const MAX_IDENTITY_CHARS = 80 * 1024;
/** What a key statement leaves free for each recovery an ID has left: a recovery's fields keep it under this. */
const RECOVERY_ROOM = 1600;
const MAX_STATEMENTS = MAX_RECOVERIES + (MAX_RECOVERIES + 1) * 2 * MAX_ADDITIONS + 1;
const MAX_ISSUED_AT = 2n ** 63n - 1n;
const EVENT_FIELDS = ["v", "alg", "key", "seal", "recovery"];
const PASSKEY_EVENT_FIELDS = ["v", "alg", "key", "rp", "seal", "recovery"];
const RECOVERY_FIELDS = ["v", "id", "seq", "prev", "backup", "key", "seal", "recovery", "issued_at"];
const PASSKEY_RECOVERY_FIELDS = ["v", "id", "seq", "prev", "backup", "alg", "key", "rp", "seal", "recovery", "issued_at"];
const KEY_ADD_FIELDS = ["v", "id", "seq", "prev", "by", "key", "issued_at"];
const PASSKEY_ADD_FIELDS = ["v", "id", "seq", "prev", "by", "alg", "key", "rp", "issued_at"];
const KEY_REMOVE_FIELDS = ["v", "id", "seq", "prev", "by", "key", "issued_at"];
const RECOVERY_RULE_FIELDS = ["v", "id", "seq", "prev", "by", "recovery", "issued_at"];
const HEX_HASH = /^[0-9a-f]{64}$/;
const RP_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * An RP ID: a hostname as an address's domain is spelled, with no port, not an IP address, and never
 * `localhost` or a name under it, where any program on the owner's machine can serve a page.
 */
function isRpId(rp) {
  if (typeof rp !== "string" || rp.length === 0 || rp.length > 253 || /^[0-9.]+$/.test(rp)) return false;
  if (rp === "localhost" || rp.endsWith(".localhost")) return false;
  return rp.split(".").every((label) => RP_LABEL.test(label));
}

/** A payload decoded, only in its one spelling: these fields, in this order, as compact JSON. */
function payloadIn(compact, fields) {
  const text = DECODER.decode(fromB64url(String(compact).split(".")[1]));
  const payload = JSON.parse(text);
  if (!payload || typeof payload !== "object" || JSON.stringify(Object.keys(payload)) !== JSON.stringify(fields)
    || JSON.stringify(payload) !== text) {
    throw new Error("malformed");
  }
  return payload;
}

/** The header's alg, for a statement whose header is exactly this typ's. */
function algOf(compact, typ) {
  const header = String(compact).split(".")[0];
  for (const alg of ["ES256", "WA256"]) {
    if (header === b64url(utf8(JSON.stringify({ alg, typ })))) return alg;
  }
  return null;
}

/** A recovery rule as an ID has one: a backup's commitment. */
function ruleOf(rule) {
  if (!rule || JSON.stringify(Object.keys(rule)) !== JSON.stringify(["rule", "commitment"]) || rule.rule !== "backup_key"
    || typeof rule.commitment !== "string" || !HEX_HASH.test(rule.commitment)) {
    throw new Error("malformed");
  }
  return rule.commitment;
}

/** What an ID made without a recovery code commits to until a key that counts sets one. */
async function laterRule(key) {
  return hex(await sha256(concat(utf8("splint-recovery-later"), key)));
}

/** The signing input's hash, which `prev` names: a statement's header and payload, never a signature. */
async function statementHash(compact) {
  return hex(await sha256(utf8(String(compact).split(".").slice(0, 2).join("."))));
}

function checkIssuedAt(value) {
  if (!Number.isInteger(value) || value < 0 || BigInt(value) > MAX_ISSUED_AT) throw new Error("malformed");
}

/**
 * The payload of what one sign-in signed, the way it signs: ES256, or WA256 for a passkey. A header
 * naming the other way is a signature this sign-in didn't make, a bad signature as Rust and Go say.
 */
async function verifyByKey(compact, typ, signer) {
  const alg = algOf(compact, typ);
  if (!alg) throw new Error("malformed");
  if (alg !== (signer.rp ? "WA256" : "ES256")) throw new Error("bad_signature");
  return signer.rp ? verifyWa256(compact, typ, signer) : verifyEs256(compact, typ, signer.key);
}

/**
 * The payload of what an owner signed now, under any of their sign-ins that count, each the way it
 * signs, as "Reading an ID's keys" has it: the header says which way, and every key that signs that
 * way is tried. Otherwise a throw.
 */
async function verifyByOwner(compact, typ, owner) {
  const alg = algOf(compact, typ);
  if (!alg) throw new Error("malformed");
  const keys = (owner.keys || [{ key: owner.key, rp: owner.rp }]).filter((one) => Boolean(one.rp) === (alg === "WA256"));
  let refused = new Error("bad_signature");
  for (const one of keys) {
    try {
      return await verifyByKey(compact, typ, one);
    } catch (error) {
      if (/** @type {Error} */ (error).message !== "bad_signature") refused = /** @type {Error} */ (error);
    }
  }
  throw refused;
}

/**
 * An encoded ID, its event and every statement after it checked as "IDs and addresses" and "An
 * owner's keys" have them: recoveries, sign-ins added and removed, and a recovery code set later. What
 * the page needs of it is the sign-ins that count now, each with how it signs, and the sealing key now.
 * `key` and `rp` are the first sign-in's, as a page signing for an owner with one sign-in uses.
 */
async function readIdentity(encoded) {
  if (typeof encoded !== "string" || encoded.length > MAX_IDENTITY_CHARS) throw new Error("malformed");
  const parts = encoded.split("~");
  if (parts.length > MAX_STATEMENTS + 1) throw new Error("malformed");
  const bytes = fromB64url(parts[0]);
  const text = DECODER.decode(bytes);
  const event = JSON.parse(text);
  const passkeyEvent = event && event.v === 5;
  const fields = passkeyEvent ? PASSKEY_EVENT_FIELDS : EVENT_FIELDS;
  if (!event || JSON.stringify(Object.keys(event)) !== JSON.stringify(fields) || JSON.stringify(event) !== text
    || event.v !== (passkeyEvent ? 5 : 4) || event.alg !== (passkeyEvent ? "webauthn-es256" : "ES256")
    || (passkeyEvent && !isRpId(event.rp))) {
    throw new Error("malformed");
  }
  const id = await idOf(bytes);
  const first = { key: fromB64url(event.key), rp: passkeyEvent ? event.rp : null, addedAt: null };
  let seal = fromB64url(event.seal);
  await ecdhPublic(first.key);
  await ecdhPublic(seal);
  let rule = ruleOf(event.recovery);
  if (hex(seal) === hex(first.key) || rule === hex(await sha256(first.key))) throw new Error("malformed");
  const standInRule = hex(await sha256(concat(utf8("splint-unconfirmed-owner"), first.key)));
  let epochKey = first;
  let keys = [first];
  const everyKey = [first];
  const seals = [hex(seal)];
  const rules = [rule];
  let additions = 0;
  let recoveries = 0;
  let prev = hex(await sha256(bytes));
  let used = parts[0].length;
  const had = async (point) => everyKey.some((one) => hex(one.key) === hex(point)) || seals.includes(hex(point));
  const nameOf = async (point) => hex(await sha256(point));
  const signerNamed = async (by) => {
    for (const one of keys) if ((await nameOf(one.key)) === by) return one;
    throw new Error("wrong_signer");
  };
  for (const [index, statement] of parts.slice(1).entries()) {
    const seq = index + 1;
    const segments = statement.split(".");
    used += 1 + statement.length;
    // A key statement leaves room for every recovery the ID has left, checked once it's otherwise taken.
    const leavesRoom = () => {
      if (used + (MAX_RECOVERIES - recoveries) * RECOVERY_ROOM > MAX_IDENTITY_CHARS) throw new Error("malformed");
    };
    const follows = (payload) => {
      if (payload.id !== id || payload.seq !== seq || payload.prev !== prev) throw new Error("proof_mismatch");
    };
    if (segments.length === 4 && algOf(statement, "splint-key-add")) {
      // An addition: signed by a sign-in that counts, then by the one it adds, over the same input.
      const signed = segments.slice(0, 3).join(".");
      const passkey = payloadOf(signed).v === 5;
      const payload = payloadIn(signed, passkey ? PASSKEY_ADD_FIELDS : KEY_ADD_FIELDS);
      if (payload.v !== (passkey ? 5 : 4) || (passkey && (payload.alg !== "webauthn-es256" || !isRpId(payload.rp)))
        || !HEX_HASH.test(payload.by)) {
        throw new Error("malformed");
      }
      checkIssuedAt(payload.issued_at);
      const added = { key: fromB64url(payload.key), rp: passkey ? payload.rp : null, addedAt: payload.issued_at };
      await ecdhPublic(added.key);
      follows(payload);
      if (rules.length === 1 && recoveries === 0 && rule === standInRule) throw new Error("malformed");
      await verifyByKey(signed, "splint-key-add", await signerNamed(payload.by));
      const input = segments.slice(0, 2).join(".");
      if (added.rp) {
        await checkAssertion(input, segments[3], added);
      } else {
        const raw = fromB64url(segments[3]);
        if (raw.length !== 64) throw new Error("malformed");
        if (!(await verifiesUnder(added.key, utf8(input), raw))) throw new Error("bad_signature");
      }
      if ((await had(added.key)) || (await nameOf(added.key)) === rule) throw new Error("malformed");
      if (keys.length >= MAX_KEYS || additions >= MAX_ADDITIONS) throw new Error("malformed");
      leavesRoom();
      keys = [...keys, added];
      everyKey.push(added);
      additions += 1;
    } else if (segments.length === 3 && algOf(statement, "splint-key-remove")) {
      const payload = payloadIn(statement, KEY_REMOVE_FIELDS);
      if (payload.v !== 6 || !HEX_HASH.test(payload.by) || !HEX_HASH.test(payload.key)) throw new Error("malformed");
      checkIssuedAt(payload.issued_at);
      follows(payload);
      if (rules.length === 1 && recoveries === 0 && rule === standInRule) throw new Error("malformed");
      await verifyByKey(statement, "splint-key-remove", await signerNamed(payload.by));
      const left = [];
      for (const one of keys) if ((await nameOf(one.key)) !== payload.key) left.push(one);
      if (left.length === keys.length || left.length === 0) throw new Error("malformed");
      leavesRoom();
      keys = left;
    } else if (segments.length === 3 && algOf(statement, "splint-recovery-rule")) {
      const payload = payloadIn(statement, RECOVERY_RULE_FIELDS);
      if (payload.v !== 7 || !HEX_HASH.test(payload.by)) throw new Error("malformed");
      const next = ruleOf(payload.recovery);
      checkIssuedAt(payload.issued_at);
      follows(payload);
      if (rules.length === 1 && recoveries === 0 && rule === standInRule) throw new Error("malformed");
      await verifyByKey(statement, "splint-recovery-rule", await signerNamed(payload.by));
      if (rule !== (await laterRule(epochKey.key)) || rules.includes(next)) throw new Error("malformed");
      // Seals are held as points and keys by name, and the rule is a commitment: compare hashes.
      for (const point of seals) if (hex(await sha256(fromHex(point))) === next) throw new Error("malformed");
      for (const one of everyKey) if ((await nameOf(one.key)) === next) throw new Error("malformed");
      leavesRoom();
      rule = next;
      rules[rules.length - 1] = next;
    } else if (segments.length === 3 && algOf(statement, "splint-recovery") === "ES256") {
      if (recoveries >= MAX_RECOVERIES) throw new Error("malformed");
      const passkey = payloadOf(statement).v === 3;
      const payload = payloadIn(statement, passkey ? PASSKEY_RECOVERY_FIELDS : RECOVERY_FIELDS);
      if (payload.v !== (passkey ? 3 : 2) || (passkey && (payload.alg !== "webauthn-es256" || !isRpId(payload.rp)))) throw new Error("malformed");
      checkIssuedAt(payload.issued_at);
      follows(payload);
      const backup = fromB64url(payload.backup);
      if ((await nameOf(backup)) !== rule) throw new Error("wrong_signer");
      await verifyEs256(statement, "splint-recovery", backup);
      const nextRule = ruleOf(payload.recovery);
      const next = { key: fromB64url(payload.key), rp: passkey ? payload.rp : null, addedAt: null };
      const nextSeal = fromB64url(payload.seal);
      await ecdhPublic(next.key);
      await ecdhPublic(nextSeal);
      const keyChanged = hex(next.key) !== hex(epochKey.key);
      if (nextRule === (await nameOf(next.key)) || nextRule === (await laterRule(next.key)) || hex(nextSeal) === hex(next.key)
        || (!keyChanged && next.rp !== epochKey.rp) || (keyChanged && seals.includes(hex(nextSeal))) || rules.includes(nextRule)) {
        throw new Error("malformed");
      }
      for (const one of everyKey) {
        if ((await nameOf(one.key)) === nextRule || hex(one.key) === hex(nextSeal)) throw new Error("malformed");
      }
      epochKey = next;
      keys = [next];
      everyKey.push(next);
      seal = nextSeal;
      rule = nextRule;
      rules.push(nextRule);
      seals.push(hex(seal));
      recoveries += 1;
      additions = 0;
    } else {
      throw new Error("malformed");
    }
    prev = await statementHash(statement);
  }
  return {
    encoded,
    id,
    event,
    keys,
    key: keys[0].key,
    rp: keys[0].rp,
    seal,
    recoveries,
    statements: parts.length - 1,
    signIns: await Promise.all(keys.map(async (one) => nameOf(one.key))),
    rule,
    recoveryLater: rule === (await laterRule(epochKey.key)),
    standIn: parts.length === 1 && rule === standInRule,
  };
}

/**
 * Which of two copies of one owner's ID the page goes by: one that extends the other, statement for
 * statement, or the one with a recovery after they part ways. Otherwise the one held stands.
 */
async function newestOwnerCopy(held, shown) {
  if (held.id !== shown.id) return held;
  const steps = (copy) => copy.encoded.split("~").slice(1);
  const [ours, theirs] = [steps(held), steps(shown)];
  let shared = 0;
  while (shared < ours.length && shared < theirs.length
    && ours[shared].split(".").slice(0, 2).join(".") === theirs[shared].split(".").slice(0, 2).join(".")) {
    shared += 1;
  }
  if (shared === ours.length) return shown;
  if (shared === theirs.length) return held;
  const recovered = (rest) => rest.slice(shared).some((one) => algOf(one, "splint-recovery") !== null);
  return recovered(theirs) && !recovered(ours) ? shown : held;
}

/**
 * An agent's ID with every recovery it carries, for the key that counts now. A host gives an agent's ID
 * with its address, and only the chain of its backups' signatures says which key is the agent's now.
 * An agent's key is never a passkey, and only an owner's ID carries any other statement.
 */
async function readAgentIdentity(encoded) {
  const read = await readIdentity(encoded);
  if (read.rp || read.keys.length !== 1 || read.statements !== read.recoveries) throw new Error("wrong_signer");
  return read;
}

// ---------- Signing ----------

function signingInput(alg, typ, payload) {
  return `${b64url(utf8(JSON.stringify({ alg, typ })))}.${b64url(utf8(JSON.stringify(payload)))}`;
}

function payloadOf(compact) {
  return JSON.parse(DECODER.decode(fromB64url(compact.split(".")[1])));
}

/** ES256 by a key WebCrypto holds, as a JWS has it: r then s. */
async function es256(privateKey, input) {
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, utf8(input));
  return `${input}.${b64url(new Uint8Array(signature))}`;
}

/** DER's two integers, as the 64 bytes WebCrypto checks. Strict DER only. */
function rawSignature(der) {
  const integer = (at) => {
    if (der[at] !== 0x02) throw new Error("bad_signature");
    const length = der[at + 1];
    const value = der.slice(at + 2, at + 2 + length);
    if (length === 0 || length > 33 || value.length !== length || (value[0] & 0x80) || (length > 1 && value[0] === 0 && !(value[1] & 0x80))) {
      throw new Error("bad_signature");
    }
    const trimmed = value[0] === 0 ? value.slice(1) : value;
    if (trimmed.length > 32) throw new Error("bad_signature");
    const out = new Uint8Array(32);
    out.set(trimmed, 32 - trimmed.length);
    return { out, next: at + 2 + length };
  };
  if (der[0] !== 0x30 || der[1] !== der.length - 2) throw new Error("bad_signature");
  const r = integer(2);
  const s = integer(r.next);
  if (s.next !== der.length) throw new Error("bad_signature");
  return concat(r.out, s.out);
}

async function verifiesUnder(point, message, raw) {
  const key = await crypto.subtle.importKey("raw", point, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, message);
}

/**
 * The payload of an object an owner whose key is a passkey signed, after the checks "Owner keys in a
 * passkey" lists, or a throw.
 */
async function verifyWa256(compact, typ, owner) {
  const [header, payload, segment, extra] = String(compact).split(".");
  if (extra !== undefined || segment === undefined) throw new Error("malformed");
  if (header !== b64url(utf8(JSON.stringify({ alg: "WA256", typ })))) throw new Error("malformed");
  await checkAssertion(`${header}.${payload}`, segment, owner);
  return JSON.parse(DECODER.decode(fromB64url(payload)));
}

/**
 * A passkey's assertion over a signing input, as "Owner keys in a passkey" checks one, or a throw.
 * An addition's added passkey signs the input the key that counts signed, whichever way that one did.
 * @param {string} input @param {string} segment @param {{key: Uint8Array, rp: string | null}} owner
 */
async function checkAssertion(input, segment, owner) {
  if (segment.length > MAX_SEGMENT_CHARS || !owner.rp) throw new Error("malformed");
  const parts = JSON.parse(DECODER.decode(fromB64url(segment)));
  const authenticatorData = fromB64url(parts.a);
  const clientDataJSON = fromB64url(parts.c);
  let challenge = await sha256(utf8(input));
  if (parts.b !== undefined) {
    const entries = parts.b;
    const wellFormed = Array.isArray(entries) && entries.length >= 2 && entries.length <= MAX_BATCH
      && entries.every((entry) => typeof entry === "string" && /^[0-9a-f]{64}$/.test(entry))
      && new Set(entries).size === entries.length;
    if (!wellFormed) throw new Error("malformed");
    if (!entries.includes(hex(challenge))) throw new Error("bad_signature");
    challenge = await sha256(concat(utf8(BATCH_TAG), ...parts.b.map(fromHex)));
  }
  const client = JSON.parse(DECODER.decode(clientDataJSON), (key, value) => {
    if (LONE_SURROGATE.test(key) || (typeof value === "string" && LONE_SURROGATE.test(value))) throw new Error("malformed");
    return value;
  });
  const flags = authenticatorData[32];
  const fits = client.type === "webauthn.get" && client.challenge === b64url(challenge)
    && originAllowed(client.origin, owner.rp) && (client.crossOrigin === undefined || client.crossOrigin === false)
    && authenticatorData.length >= 37 && hex(authenticatorData.slice(0, 32)) === hex(await sha256(utf8(owner.rp)))
    && (flags & 0x05) === 0x05;
  const message = concat(authenticatorData, await sha256(clientDataJSON));
  if (!fits || !(await verifiesUnder(owner.key, message, rawSignature(fromB64url(parts.s))))) {
    throw new Error("bad_signature");
  }
}

const CLOCK_TOLERANCE_SECS = 120;
const VIEW_FIELDS = ["v", "agent", "owner", "issued_at", "view"];

/**
 * What an agent's Signet left its owner, opened: only if the agent's key signed it, naming that agent
 * and this owner, not dated ahead. Anyone can seal to an owner, so the seal says nothing of who wrote it.
 * @param {string} compact @param {{id: string, key: Uint8Array, rp: string | null}} agent @param {string} owner @param {number} now
 */
async function verifyOwnerView(compact, agent, owner, now) {
  if (agent.rp) throw new Error("wrong_signer");
  const signed = await verifyEs256(compact, "splint-owner-view", agent.key);
  if (!signed || JSON.stringify(Object.keys(signed)) !== JSON.stringify(VIEW_FIELDS) || signed.v !== 1
    || !signed.view || typeof signed.view !== "object" || Array.isArray(signed.view)
    || !Number.isSafeInteger(signed.issued_at) || signed.issued_at < 0) {
    throw new Error("malformed");
  }
  if (signed.agent !== agent.id || signed.owner !== owner) throw new Error("wrong_signer");
  if (signed.issued_at > now + CLOCK_TOLERANCE_SECS) throw new Error("from_the_future");
  return { issued_at: signed.issued_at, view: signed.view };
}

// An agent's Signet signs a view as it's asked for one, so one read straight from it that's older than
// this, by the agent's clock, is a copy someone on the way kept. As crate::direct's STRAIGHT_VIEW_SECS.
const STRAIGHT_VIEW_SECS = 30;

/**
 * The view to take from one read: from the host, as it opens, and straight from an agent's Signet only
 * if it opens, was signed in the last moment and is no older than the newest seen, as anything else is
 * a copy someone on the way kept, and then the host's, read afresh. Each check refuses a copy the other
 * can't: the age one kept after the newest seen, and the newest-seen one kept within the moment.
 * @template {{at: number}} T
 * @param {{view?: string}} held @param {boolean} straight @param {(sealed: string) => Promise<T | null>} open
 * @param {() => Promise<{view?: string}>} readHost @param {number} newestSeen @param {number} now
 * @returns {Promise<T | null>}
 */
async function viewToTake(held, straight, open, readHost, newestSeen, now) {
  /** @type {T | null} */
  let opened = null;
  try {
    opened = held.view ? await open(held.view) : null;
  } catch (error) {
    if (!straight) throw error;
  }
  if (!straight || (opened && now - opened.at <= STRAIGHT_VIEW_SECS && opened.at >= newestSeen)) return opened;
  const fromHost = await readHost();
  return fromHost.view ? open(fromHost.view) : null;
}

/** The payload of an ES256 object signed by `point`, or a throw. */
async function verifyEs256(compact, typ, point) {
  const [header, payload, signature, extra] = String(compact).split(".");
  if (extra !== undefined || header !== b64url(utf8(JSON.stringify({ alg: "ES256", typ })))) throw new Error("malformed");
  const raw = fromB64url(signature);
  if (raw.length !== 64 || !(await verifiesUnder(point, utf8(`${header}.${payload}`), raw))) throw new Error("bad_signature");
  return JSON.parse(DECODER.decode(fromB64url(payload)));
}

// ---------- Shapes ----------

/** Whether an object's keys are exactly these, in this order. */
function keysAre(object, fields) {
  return Boolean(object) && typeof object === "object" && !Array.isArray(object) && JSON.stringify(Object.keys(object)) === JSON.stringify(fields);
}

// ---------- Where an owner gets paid, as "Payments" checks a place ----------

const MAX_PLACES = 4;
const MAX_STATEMENT_BYTES = 1536;

const URL_CHARS = /^[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]*$/;
const BECH32 = /^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]*$/;

/** Labels of letters, digits and hyphens, at least two, ending in letters. */
function isDnsName(host) {
  const labels = host.split(".");
  const top = labels[labels.length - 1];
  return host.length <= 253 && labels.length >= 2 && /^[A-Za-z]{2,}$/.test(top)
    && labels.every((label) => /^[A-Za-z0-9-]{1,63}$/.test(label) && !label.startsWith("-") && !label.endsWith("-"));
}

function isPaymentPage(url) {
  if (!url.startsWith("https://") || url.length > 300) return false;
  const rest = url.slice("https://".length);
  if (!URL_CHARS.test(rest)) return false;
  const authority = rest.split(/[/?#]/)[0];
  if (authority.includes("@")) return false;
  const colon = authority.indexOf(":");
  const host = colon < 0 ? authority : authority.slice(0, colon);
  const port = colon < 0 ? null : authority.slice(colon + 1);
  return (port === null || /^[0-9]{1,5}$/.test(port)) && isDnsName(host);
}

function isLightning(to) {
  // A start of lno1 is an offer's alone, as every reader takes it, so one string can't read as an
  // address here and be refused by a Signet.
  if (to.startsWith("lno1")) return to.length >= 20 && to.length <= 600 && BECH32.test(to.slice(4));
  const at = to.indexOf("@");
  if (at < 0) return false;
  const name = to.slice(0, at);
  const domain = to.slice(at + 1);
  return to.length <= 320 && /^[a-z0-9\-_.+]{1,64}$/.test(name) && domain === domain.toLowerCase() && isDnsName(domain);
}

/** One place, in its one encoding, of a shape a statement takes. */
function placeFits(place) {
  if (!place || typeof place !== "object" || Array.isArray(place)) return false;
  const strings = (fields) => keysAre(place, fields) && fields.every((field) => typeof place[field] === "string");
  switch (place.kind) {
    case "payment_page": return strings(["kind", "url"]) && isPaymentPage(place.url);
    case "lightning": return strings(["kind", "to"]) && isLightning(place.to);
    case "onchain": {
      if (!strings(["kind", "chain", "address", "asset"])) return false;
      const colon = place.chain.indexOf(":");
      return colon >= 0 && /^[a-z0-9-]{3,8}$/.test(place.chain.slice(0, colon)) && /^[A-Za-z0-9_-]{1,32}$/.test(place.chain.slice(colon + 1))
        && /^[A-Za-z0-9.%-]{1,128}$/.test(place.address) && /^[a-z0-9_]{1,32}$/.test(place.asset);
    }
    default: return false;
  }
}

/**
 * What an owner signs for where they get paid, held to every Signet's check of one: 1 to 4 places,
 * each once, each of a shape a statement takes, and the whole no larger than a statement may be. So
 * the person never signs places their agents then refuse.
 */
function wherePaidPayload(owner, places, issuedAt) {
  const fits = Array.isArray(places) && places.length > 0 && places.length <= MAX_PLACES && places.every(placeFits)
    && new Set(places.map((place) => JSON.stringify(place))).size === places.length;
  const payload = { v: 1, owner, places, issued_at: issuedAt };
  if (!fits || utf8(JSON.stringify(payload)).length > MAX_STATEMENT_BYTES) throw new Error("malformed");
  return payload;
}

/**
 * The code one touch over these signing inputs shows, the same as Splint on this computer's prompt
 * shows: the first 4 bytes of SHA-256 over the tag and each input's SHA-256, as 8 capital hex digits
 * in two groups.
 * @param {string[]} inputs
 */
async function touchCodeOf(inputs) {
  const hashes = await Promise.all(inputs.map((input) => sha256(utf8(input))));
  const code = hex((await sha256(concat(utf8("splint touch code v1"), ...hashes))).slice(0, 4)).toUpperCase();
  return `${code.slice(0, 4)} ${code.slice(4)}`;
}

// ---------- Sealed notes: HPKE, RFC 9180, DHKEM P-256, HKDF-SHA256, AES-128-GCM, base mode ----------

const KEM_SUITE = concat(utf8("KEM"), Uint8Array.of(0x00, 0x10));
const HPKE_SUITE = concat(utf8("HPKE"), Uint8Array.of(0x00, 0x10, 0x00, 0x01, 0x00, 0x01));
const NOTE_INFO = utf8("splint sealed note v1");

async function labeledExtract(suite, salt, label, ikm) {
  return hmac(salt, concat(utf8("HPKE-v1"), suite, utf8(label), ikm));
}

async function labeledExpand(suite, prk, label, info, length) {
  return hkdfExpand(prk, concat(Uint8Array.of(length >> 8, length & 255), utf8("HPKE-v1"), suite, utf8(label), info), length);
}

async function aeadOf(sharedSecret) {
  const none = new Uint8Array(0);
  const context = concat(Uint8Array.of(0),
    await labeledExtract(HPKE_SUITE, none, "psk_id_hash", none),
    await labeledExtract(HPKE_SUITE, none, "info_hash", NOTE_INFO));
  const secret = await labeledExtract(HPKE_SUITE, sharedSecret, "secret", none);
  const key = await crypto.subtle.importKey("raw", await labeledExpand(HPKE_SUITE, secret, "key", context, 16), "AES-GCM", false, ["encrypt", "decrypt"]);
  return { key, nonce: await labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12) };
}

async function kemSecret(privateKey, theirPoint, enc, recipientPoint) {
  const dh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: await ecdhPublic(theirPoint) }, privateKey, 256));
  const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), "eae_prk", dh);
  return labeledExpand(KEM_SUITE, prk, "shared_secret", concat(enc, recipientPoint), 32);
}

/** What a sealed note to this key holds, or a throw if it was sealed for something else. */
/**
 * What's sealed to an owner, opened with their sealing key: one this page holds, or, on a computer
 * where Splint keeps the reading key, by asking it to.
 * @param {{privateKey?: CryptoKey, point: Uint8Array, open?: (sealed: string, about: Uint8Array) => Promise<Uint8Array>}} sealing
 * @param {string} sealed @param {Uint8Array} about
 */
async function openSealed(sealing, sealed, about) {
  if (sealing.open) return sealing.open(sealed, about);
  return openNote(/** @type {CryptoKey} */ (sealing.privateKey), sealing.point, sealed, about);
}

async function openNote(privateKey, ownPoint, sealed, about) {
  const bytes = fromB64url(sealed);
  const enc = bytes.slice(0, 65);
  const { key, nonce } = await aeadOf(await kemSecret(privateKey, enc, enc, ownPoint));
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: about }, key, bytes.slice(65)));
}

// ---------- The owner's list of their agents ----------

const MAX_LISTED_AGENTS = 64;
const MAX_LABEL_CHARS = 64;

/**
 * The owner's list from what their page's host holds, opened: signed by them, naming them and this
 * host, sealed to their sealing key for them, naming their own backup, with labels they can read in
 * full and no agent twice. Refusals carry the reasons spec/vectors gives.
 * @param {string} list @param {any} owner @param {string} host @param {any} sealing
 */
async function openOwnerAgents(list, owner, host, sealing) {
  const signed = await verifyByOwner(list, "splint-owner-agents", owner);
  if (signed.owner !== owner.id) throw new Error("wrong_signer");
  if (signed.host !== host) throw new Error("proof_mismatch");
  const plain = await openSealed(sealing, signed.agents, utf8(`splint owner agents for ${owner.id}`)).catch(() => {
    throw new Error("cant_open");
  });
  const contents = JSON.parse(DECODER.decode(plain));
  if (!contents || contents.v !== 1 || typeof contents.backup !== "string" || !Array.isArray(contents.agents)
    || contents.agents.length > MAX_LISTED_AGENTS) {
    throw new Error("malformed");
  }
  // Until the owner sets their recovery code there's no backup, and the list names none. Otherwise it
  // names the backup the ID's rule commits to now.
  if (owner.recoveryLater) {
    if (contents.backup !== "") throw new Error("malformed");
  } else if (contents.backup === "") {
    throw new Error("malformed");
  } else if (hex(await sha256(fromB64url(contents.backup))) !== owner.rule) {
    throw new Error("proof_mismatch");
  }
  const seen = new Set();
  for (const listed of contents.agents) {
    const label = listed && typeof listed.label === "string" ? listed.label : "";
    const chars = [...label].length;
    if (chars === 0 || chars > MAX_LABEL_CHARS || hasHiddenCharacters(label) || seen.has(listed.agent)) throw new Error("malformed");
    // A computer's sign-in says whether the agent runs beside it, 1 or 0; a page leaves it out.
    if (Object.hasOwn(listed, "beside_owner") && listed.beside_owner !== 1 && listed.beside_owner !== 0) throw new Error("malformed");
    seen.add(listed.agent);
  }
  // 1 or 0, one width either way, so a host can't tell from a list's size who saved their code.
  if (Object.hasOwn(contents, "code_saved") && contents.code_saved !== 1 && contents.code_saved !== 0) throw new Error("malformed");
  return { seq: signed.seq, backup: contents.backup, agents: contents.agents, codeSaved: contents.code_saved === 1 };
}

// ---------- Signing rules ----------

/**
 * A delegation's signing input. The page caps types only with no amount, `{}`, so its delegate says
 * yes to those alone and never to a price, and writes them in the order Rust and Go read them in.
 */
function delegationInput(alg, { owner, agent, seq, now }, d) {
  const types = Object.keys(d.caps);
  if (d.level === "full_auto" || types.some((type) => !d.caps[type] || Object.keys(d.caps[type]).length !== 0)) throw new Error("malformed");
  const caps = Object.fromEntries(types.sort().map((type) => [type, {}]));
  return signingInput(alg, "splint-delegation", {
    v: 1, owner, agent, delegate: d.delegate, may: [...d.may].sort(), level: d.level, caps,
    actions_per_day: d.actions_per_day, seq, issued_at: now, expires_at: now + d.lasts_secs,
  });
}

/** Rules in their one field order, as "Rules and admission" has them. */
function rulesPayload(draft, { owner, agent, seq, now, delegation }) {
  // No end unless the owner gave one: rules last until replaced.
  const rules = { v: 1, owner, agent, seq, issued_at: now };
  if (draft.ends_at !== undefined) rules.ends_at = draft.ends_at;
  for (const key of ["paused", "reach", "permissions", "changes", "sealing"]) rules[key] = draft[key];
  if (delegation) rules.delegation = delegation;
  for (const key of ["contacts", "invites", "limits"]) rules[key] = draft[key];
  return rules;
}

/** The draft part of signed rules, to sign the next from. */
function draftOf(rules) {
  const draft = {};
  for (const key of ["paused", "reach", "permissions", "changes", "sealing", "contacts", "invites", "limits"]) draft[key] = rules[key];
  if (rules.ends_at !== undefined) draft.ends_at = rules.ends_at;
  return draft;
}

/**
 * Whether a page at `origin` may sign for `rp`: `https://` and the RP ID with no port.
 * @param {string} origin @param {string} rp
 */
function originAllowed(origin, rp) {
  return origin === `https://${rp}`;
}

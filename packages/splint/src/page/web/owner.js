// @ts-check
// Your controls: the page Splint on the person's own computer serves at /owner, /ask and /requests.
// Splint there holds their sign-in, in the computer's security chip or a key file locked with a
// passphrase, and signs only after its own prompt, or within the signing session the person unlocked
// on this page with their passphrase. The page reaches hosts only through the Owner API in
// docs/protocol.md, draws with Preact, and only ever makes elements and sets their text. What it asks
// Splint here to sign is built from the same values it shows. No host serves this page, and it makes
// and uses no passkey: Nenye decided on 2026-11-21 that owners sign only on their own computers, as
// whoever serves the page a passkey signs on chooses what a touch there signs (issue 635).
"use strict";

// What this browser remembers of the owner signed in here, such as whether their recovery code was
// saved, as only this page writes it.
const OWNERS = "splint-owners";
const UPDATE_PUT_OFF = "splint-owner-update-put-off";
// When each agent's newest view was signed, as this browser has seen, so a host giving back an older
// one, as it can since each is signed, is caught after a reload too.
const VIEWS_SEEN = "splint-owner-views-seen";
// A session is used to leave something at a host only with this long to go, so it can't end midway.
const SESSION_ROOM_SECS = 2 * 60;
const REFRESH_MILLIS = 5000;
const DAY = 24 * 60 * 60;
const MAX_SESSIONS = 6;
// What contacts an agent adds by itself get: words, and agreeing kinds of request with it, as two agents
// do in conversation with no owner signing (Nenye, 2026-11-11 and 2026-11-14). Anything carrying an
// amount with them, such as a price, waits for the owner at every level, and Signet and every reader
// hold a yes to it to that. The splint CLI gives the same, in `first_rules`.
const AGREED = { types: [], text: true, agree_types: true };
// The types the agent's delegate says yes to by itself while the owner is away, by ID. None in v0: two
// agents agree their own, and a kind with money is used only once the owner approves it.
const DELEGATED_TYPES = [];
// A delegation this close to its end is signed afresh with the next rules the owner signs, so the
// owner renews it without being asked. The delegate never extends itself.
const FRESH_DELEGATION_WITHIN_SECS = 30 * 24 * 60 * 60;
// A delegation is signed to the key a view names only if the view was signed this recently. Signet
// leaves a view within seconds of a change and at least every 5 minutes, and the page reads every 5
// seconds, so a live agent's is never much over 5 minutes old. Three missed in a row leave room for a
// busy host or a skewed clock, and keep short the time a host can give the view from before a
// delegate key changed, which names the old key, to a page that never saw a newer one.
const VIEW_CURRENT_SECS = 15 * 60;
// What your controls say when only an agent's Signet, straight from here, said it took rules or where
// you get paid, and its host couldn't be reached. Anything answering there could say it.
const NOT_YET_AT_HOST = "Your agent's Signet said it took that, but its host couldn't take it just now to confirm it, so it may not count yet. Your controls send it to the host again until it takes it.";
const DEFAULT_DELEGATION = {
  may: ["approve_within_caps"], level: "auto_within_limits",
  caps: Object.fromEntries(DELEGATED_TYPES.map((type) => [type, {}])), actions_per_day: 50, lasts_secs: 365 * DAY,
};
// Steps and messages a day at full auto: MAX_ACTIONS_PER_DAY in splint-core, which a host's default
// daily sends for an agent with an owner fit.
const FULL_AUTO_PER_DAY = 2500;
const YESES_PART = 5;
const REFUSED_WORDS = {
  400: "That host couldn't take it as it was.",
  401: "That host wants you to sign in again.",
  403: "That host refused it.",
  404: "That host doesn't know of it.",
  409: "That host holds something else there already.",
  413: "That was too big for that host.",
  429: "That host is busy, or at its limit. Try again later.",
};
// What an agent's host refused, as the page says it, by which way it was going. A host's own words
// for why aren't shown, as any host could write anything there.
const REFUSED_WAYS = {
  out: "tried to send something your rules don't allow, and its host stopped it",
  in: "was kept from hearing from someone your rules don't let in",
};
// The page's own words for a view it won't go by, never the host's.
const BEHIND_WORDS = "Its host gave this page an older update than one it already had, so the page waits for a newer one.";
const NOT_RENEWED_WORDS = "This page hasn't had a recent update from it, so what it agrees to by itself wasn't renewed. Save again once it shows as heard from in the last few minutes.";
/** Everything the page knows, none of it a key anyone can read back. */
const me = {
  host: /** @type {{domain: string, relay: boolean} | null} */ (null),
  owner: /** @type {any} */ (null),
  // Splint here holds the reading key and opens what's sealed, by `open`.
  sealing: /** @type {any} */ (null),
  // What Splint on this computer said is here.
  here: /** @type {any} */ (null),
  // The sessions Splint here keeps, by host, as this page goes by them: never their keys.
  sessions: /** @type {Map<string, {name: string, expires_at: number}>} */ (new Map()),
  // `codeSaved` is null while the list can't be opened here, so the page says nothing about the code.
  list: /** @type {{seq: number, backup: string, agents: any[], codeSaved: boolean | null}} */ ({ seq: 0, backup: "", agents: [], codeSaved: null }),
  // The host the owner's list was last read from, when it isn't this page's own.
  listAt: /** @type {string | null} */ (null),
  agents: /** @type {Map<string, any>} */ (new Map()),
  // When each agent's newest view that the page opened was signed, by its own `issued_at`.
  viewsSeen: /** @type {Map<string, number>} */ (new Map()),
  view: "home",
  // What this browser remembers of owners, as OWNERS holds it, each with its `id`.
  known: /** @type {any[]} */ ([]),
  // The owner's sign-ins as this browser last saw them, by name, taken before anything here remembers
  // the owner again, so signing in can't overwrite them before the page says they changed.
  signInsSeen: /** @type {string[] | null} */ (null),
  // Each agent's choices in Settings not yet saved, by its ID, for the rules they were made over, so a
  // redraw shows them as the person left them and Save signs what's shown.
  choices: /** @type {Map<string, any>} */ (new Map()),
  // Where the person gets paid, as they're typing it, kept across redraws until they sign it.
  paidDraft: "",
  // The token of the signing session the person unlocked on this page, in memory alone, so no file
  // the browser keeps holds it. Reloading the page asks again.
  unlock: /** @type {string | null} */ (null),
};
let refreshing = 0;

/**
 * How this owner's sign-in here signs: ES256, by Splint on this computer, which holds the sign-in in the
 * security chip or a key file and signs only after its own prompt.
 */
const OWNER_ALG = "ES256";

// ---------- Talking to hosts ----------

/** A host named as an address's domain is. Plain HTTP only for a host on this machine, in a test setup,
 * and the page's own policy refuses even that anywhere else. */
function urlOf(domain) {
  if (domain === location.host) return location.origin;
  // Your own Splint, serving this page on your computer, reaches hosts for it, as hosts don't let
  // another origin read their answers. What goes through it is signed as from anywhere.
  if (me.host && me.host.relay) return `${location.origin}/relay/${domain}`;
  const name = domain.replace(/:[0-9]+$/, "");
  const local = name === "localhost" || name === "127.0.0.1" || name === "[::1]" || name.endsWith(".localhost");
  return `${local ? "http" : "https"}://${domain}`;
}

/**
 * A host's refusal, in the page's own words for its status. A host's own words are never shown: any
 * host the page reaches can write them, a stranger's included, and on this page they'd read as Splint's.
 */
class Refusal extends Error {
  /** @param {number} status @param {string | null} [route] which way your controls took it, if they did */
  constructor(status, route) {
    const onlyStraight = status === 502 && Boolean(route) && route !== "host";
    super(onlyStraight ? NOT_YET_AT_HOST : REFUSED_WORDS[status] || (status >= 500 ? "That host had a problem. Try again soon." : "That host refused it."));
    this.status = status;
    /** Only the agent's Signet said it took it, and your controls keep it for its host. */
    this.onlyStraight = onlyStraight;
  }
}

async function call(domain, method, path, body, headers) {
  return (await routedCall(domain, method, path, body, headers)).answer;
}

/** A call's answer, and which way your controls took it: `this-computer`, `network`, `host`, or null from a host itself. */
async function routedCall(domain, method, path, body, headers) {
  const response = await fetch(`${urlOf(domain)}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...(headers || {}) },
    body: body === undefined ? undefined : body,
    credentials: "omit",
    cache: "no-store",
  });
  const route = response.headers.get("splint-route");
  if (!response.ok) throw new Refusal(response.status, route);
  return { answer: await response.json().catch(() => ({})), route };
}

const send = (domain, method, path, value) => call(domain, method, path, JSON.stringify(value));

/** Whether this page has a session at a host that lasts long enough to leave something there now. */
function sessionLasts(domain) {
  const session = me.sessions.get(domain);
  return session !== undefined && session.expires_at - now() > SESSION_ROOM_SECS;
}

/**
 * Before an approval that signs something for these agents' Signets: a session at each one's host,
 * which is all the host lets what's left in by. A session that's missing or about to end is made
 * first, as an approval of its own.
 */
async function readyToLeaveFor(agents) {
  const lacks = () => agents.filter((agent) => !sessionLasts(addressParts(agent.address).domain));
  if (!lacks().length) return;
  await moreSessions(lacks().map((agent) => addressParts(agent.address).domain));
  const still = lacks();
  if (still.length) throw new Error(`This page couldn't sign in at ${still[0].label}'s host, so nothing was signed.`);
}

/**
 * Leaves something the owner signed for their agent's Signet at the agent's host, through Splint on
 * this computer, which seals it to the agent's own sealing key, so the host holds only what it can't
 * open, and leaves it under its session there. It answers as a host would, or in its own words.
 */
async function leaveMail(agent, kind, signed) {
  const response = await fetch("/local/mail", {
    method: "POST", headers: computerHeaders(), body: JSON.stringify({ agent: agent.agent, address: agent.address, kind, signed }), credentials: "omit", cache: "no-store",
  });
  if (response.ok) return;
  if (response.status === 403) throw NO_KEY;
  // No session at its host now, or only its Signet took it and it's kept for its host.
  if (response.status === 401 || response.status === 502) throw new Refusal(response.status, response.headers.get("splint-route"));
  const read = await response.json().catch(() => ({}));
  throw new Error(typeof read.error === "string" ? read.error : "Splint on this computer didn't answer.");
}

/**
 * A read under this host's session, which Splint on this computer keeps, and reads with for the page.
 * Splint here asks the host alone, so the answer is the host's.
 */
async function read(domain, path) {
  if (!me.sessions.get(domain)) throw new Refusal(401);
  const response = await fetch("/local/read", {
    method: "POST", headers: computerHeaders(), body: JSON.stringify({ domain, path }), credentials: "omit", cache: "no-store",
  });
  if (!response.ok) throw new Refusal(response.status);
  return response.json().catch(() => ({}));
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function addressParts(address) {
  const [handle, domain] = String(address).split("~");
  return { handle, domain, name: handle.split(".")[0] };
}

// ---------- Signing on this computer ----------

/**
 * One approval on this computer over every input: Splint here signs them with the person's sign-in.
 * With a key file, that's within the signing session they unlocked here, or with a passphrase typed
 * for exactly this; with the chip, after its own prompt, which names objects only by kind, so it shows
 * the code this page shows too. The code it answers with shows they were what it signed.
 * @param {string[]} inputs @param {string | null} [typed]
 */
async function touch(inputs, typed) {
  const code = await touchCodeOf(inputs);
  if (chipHere()) say(`Your computer asks you to approve. Its code should be ${code}.`, false, true);
  const body = () => (typed ? { inputs, passphrase: typed } : chipHere() ? { inputs } : { inputs, session: me.unlock });
  try {
    if (!typed && !chipHere() && !me.unlock) await unlockFor();
    let done;
    try {
      done = await computerCall("/local/sign", body());
    } catch (failure) {
      // The session ended while the page was open: unlock once more, and sign.
      if (failure !== LOCKED || typed) throw failure;
      await unlockFor();
      done = await computerCall("/local/sign", body());
    }
    if (done.code !== code || !Array.isArray(done.signed) || done.signed.length !== inputs.length) {
      throw new Error("What this computer signed isn't what this page prepared, so nothing was sent.");
    }
    return { signed: done.signed };
  } finally {
    if (chipHere()) say("", false);
  }
}

/**
 * Where this page keeps the page key Splint on this computer gave it, for an opening `splint controls`
 * put after the `#` or for unlocking with the passphrase. Every call under `/local` carries it, so only a
 * page the person opened or unlocked reaches them, never another program that only reaches the port.
 * The key is made at each start of Splint here, so an old one is refused, and the page unlocks again.
 */
const PAGE_KEY = "splint-page-key";
/** Splint here refused the page key, as after it started again: the page unlocks, or asks to be opened. */
const NO_KEY = new Error("Unlock your controls to do that.");
/** The signing session ended, so a change needs unlocking again. */
const LOCKED = new Error("Your controls locked, so unlock them again.");

function computerHeaders() {
  /** @type {Record<string, string>} */
  const headers = { "Content-Type": "application/json" };
  try {
    const key = localStorage.getItem(PAGE_KEY);
    if (key) headers["Splint-Page"] = key;
  } catch {
    // No storage here, so no key: Splint here refuses, and the page says how to open it.
  }
  return headers;
}

/** The page key for the opening `splint controls` gave this page, kept for the calls that follow. */
async function takeOpening(opening) {
  const response = await fetch("/local/page", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ opening }), credentials: "omit", cache: "no-store",
  });
  const read = await response.json().catch(() => ({}));
  if (!response.ok || typeof read.key !== "string") return;
  try {
    localStorage.setItem(PAGE_KEY, read.key);
  } catch {
    // Kept nowhere, so this page can't reach Splint here, which it then says.
  }
}

/** A call to Splint on this computer, which serves this page. Its refusals are its own fixed words. */
async function computerCall(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: computerHeaders(),
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
  });
  const read = await response.json().catch(() => ({}));
  if (response.status === 403) throw NO_KEY;
  if (response.status === 401 && (path === "/local/sign" || path === "/local/session")) {
    me.unlock = null;
    throw LOCKED;
  }
  if (!response.ok) throw new Error(typeof read.error === "string" ? `${capital(read.error)}.`.replace(/\.\.$/, ".") : "Splint on this computer didn't answer.");
  return read;
}

/** The fewest characters a key file's passphrase has, as the owner key holds one to. */
const FEWEST_PASSPHRASE_CHARACTERS = 8;

/** The reading key on this computer, which Splint here holds and opens with, never handing it out. */
function sealingHere() {
  return {
    point: me.owner.seal,
    open: async (/** @type {string} */ sealed, /** @type {Uint8Array} */ about) =>
      utf8((await computerCall("/local/open", { sealed, about: new TextDecoder().decode(about) })).plain),
  };
}

/** The owners OWNERS holds, as this page wrote them. */
function storedOwners() {
  try {
    const kept = JSON.parse(localStorage.getItem(OWNERS) || "[]");
    return Array.isArray(kept) ? kept.filter((one) => one && typeof one.id === "string" && typeof one.identity === "string") : [];
  } catch {
    return [];
  }
}

/** What this browser holds for an owner now, read afresh, as another tab may have changed it since this one read it. */
function knownAs(id) {
  return storedOwners().find((one) => one.id === id) || me.known.find((one) => one.id === id) || null;
}

/**
 * This owner, first among those this browser remembers, with their agents' addresses, which tell them
 * apart when there's more than one, and the hosts to sign in at, the one holding their list among
 * them. `extra` is what only setting up or the code adds. Merged with what this browser holds now.
 */
function remember(extra) {
  const before = knownAs(me.owner.id) || {};
  const agents = [...me.agents.values()];
  const hosts = agents.length ? agents.map((agent) => addressParts(agent.address).domain) : (Array.isArray(before.hosts) ? before.hosts : []);
  // Each host whose page kept a list for this owner, so it's still asked for it, and its list can't
  // be lost to an older one at another, once the agents are all at other hosts.
  const listHosts = [...new Set([...(Array.isArray(before.list_hosts) ? before.list_hosts : []), ...((extra && extra.list_hosts) || []), ...(me.listAt ? [me.listAt] : [])])]
    .filter((one) => typeof one === "string").slice(-MAX_SESSIONS);
  const entry = {
    ...before, ...(extra || {}), id: me.owner.id, identity: me.owner.encoded, sign_ins: me.owner.signIns,
    hosts: [...new Set([...hosts, ...listHosts])],
    list_hosts: listHosts,
    agents: agents.length ? agents.map((agent) => agent.address) : (before.agents || []),
  };
  // Another tab may have added an owner since this one read them.
  const others = [...storedOwners(), ...me.known].filter((one, index, all) => one.id !== me.owner.id && all.findIndex((other) => other.id === one.id) === index);
  me.known = [entry, ...others];
  try {
    localStorage.setItem(OWNERS, JSON.stringify(me.known));
  } catch {
    // A private window may keep nothing. The next visit signs in as a new device does.
  }
}

/**
 * Goes by a newer copy of this owner's ID a host shows, one that extends the copy held or recovers
 * after they part ways, and says so if its sign-ins changed. An older copy, or one that parts ways
 * with no recovery, changes nothing: every reader of the ID checks the same.
 */
async function adoptOwnerCopy(shown) {
  const newest = await newestOwnerCopy(me.owner, shown);
  if (newest === me.owner || newest.encoded === me.owner.encoded) return;
  me.owner = newest;
  noteSignIns();
  remember();
}

/**
 * A line, on load, when the sign-ins on this owner's ID aren't the ones this browser last saw: an
 * addition this person didn't make is a thief's, which only their recovery code undoes. Nothing is
 * said the first time, as there's nothing to compare with.
 */
function noteSignIns() {
  const known = knownAs(me.owner.id);
  const before = me.signInsSeen || (known && Array.isArray(known.sign_ins) ? known.sign_ins : null);
  const now = me.owner.signIns;
  me.signInsSeen = now;
  if (!before) return;
  const added = now.filter((name) => !before.includes(name)).length;
  const removed = before.filter((name) => !now.includes(name)).length;
  if (!added && !removed) return;
  const words = [added ? `${added} added` : "", removed ? `${removed} removed` : ""].filter(Boolean).join(" and ");
  say(`The sign-ins on your Splint ID changed since this browser last saw them: ${words}. If that wasn't you, use your recovery code now.`, added > 0, true);
}

/** Starts the page afresh as this owner, so nothing of another it knew carries over to them. */
function becomeOwner(owner) {
  const known = knownAs(owner.id);
  me.signInsSeen = known && Array.isArray(known.sign_ins) ? known.sign_ins : null;
  me.owner = owner;
  me.sealing = null;
  me.sessions = new Map();
  me.list = { seq: 0, backup: "", agents: [], codeSaved: null };
  me.listAt = null;
  me.agents = new Map();
}

// ---------- Signing in ----------

/** An owner ID short enough to read at a glance: its kind, and its first and last few characters. */
function shortId(id) {
  return `${id.slice(0, 11)}…${id.slice(-4)}`;
}

/**
 * How often viewing needs this person's approval, a setting of this computer's, never signed: `never`,
 * as long as a session lasts, 12 hours; `hourly`; or `every_time` the page opens. Splint here keeps it,
 * and the sessions.
 */
function viewingHere() {
  return (me.here && me.here.viewing) || "never";
}

async function setViewing(every) {
  await computerCall("/local/viewing", { every });
  me.here = { ...(me.here || {}), viewing: every };
  say("Saved.", false);
}

/**
 * The backup's point this browser kept at setup, for an owner whose host keeps no list yet, only if it's
 * the one their ID commits to, as whatever else this browser keeps could say any point.
 */
async function backupKeptHere() {
  const known = knownAs(me.owner.id);
  if (me.list.backup || !known || typeof known.backup !== "string") return;
  try {
    if (hex(await sha256(fromB64url(known.backup))) !== me.owner.rule) return;
  } catch {
    return;
  }
  me.list = { ...me.list, backup: known.backup, codeSaved: codeSaved() };
}

/** Whether the owner said their recovery code is saved, or not to be told again, here or on another device. */
function codeSaved() {
  if (me.list.codeSaved) return true;
  const known = knownAs(me.owner.id);
  return Boolean(known && known.code_saved);
}

/**
 * Not to be told about the code again: Splint here keeps the owner's list, and says the code was saved
 * in it.
 */
async function putCodeAside() {
  me.list.codeSaved = true;
  remember({ code_saved: true });
}

/**
 * Sessions at more hosts, such as an agent's that moved, made and kept by Splint on this computer
 * within the signing session, or after unlocking for one.
 * @param {string[]} hosts
 */
async function moreSessions(hosts) {
  const wanted = [...new Set([...me.sessions.keys(), ...hosts])].filter((one) => typeof one === "string" && one).slice(0, MAX_SESSIONS);
  if (!wanted.length) return;
  if (!chipHere() && !me.unlock) await unlockFor();
  const made = await computerCall("/local/session", chipHere() ? { hosts: wanted } : { hosts: wanted, session: me.unlock });
  takeSessionsHere(made.sessions);
}

/**
 * Unlocks with the passphrase or the chip's own prompt: Splint here starts the sessions it reads with,
 * gives this page its key, and starts a signing session whose token this page keeps in memory alone.
 * @param {string | null} typed
 */
async function unlockCall(typed) {
  const response = await fetch("/local/unlock", {
    method: "POST", headers: computerHeaders(), body: JSON.stringify({ passphrase: typed }), credentials: "omit", cache: "no-store",
  });
  const read = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof read.error === "string" ? `${capital(read.error)}.` : "Splint on this computer didn't answer.");
  try {
    localStorage.setItem(PAGE_KEY, String(read.key || ""));
  } catch {
    // Kept for nothing after this call, which the page then says.
  }
  me.unlock = typeof read.session === "string" ? read.session : null;
  takeSessionsHere(read.sessions);
}

/** Unlocks in place, for a change the person just asked for, then lets it go on. */
async function unlockFor() {
  const typed = await confirmSheet({ title: "Unlock to make changes", lead: "Changes then save as you make them, until you stop for 30 minutes.", label: "Unlock" });
  await unlockCall(typed);
}

/** The sessions Splint on this computer keeps, as this page goes by them: never their keys. */
function takeSessionsHere(sessions) {
  me.sessions = new Map();
  for (const one of Array.isArray(sessions) ? sessions : []) {
    if (typeof one.domain === "string" && Number.isSafeInteger(one.expires_at)) {
      me.sessions.set(one.domain, { name: String(one.name || ""), expires_at: one.expires_at });
    }
  }
}

// ---------- The owner's agents ----------

/**
 * The owner's newest list of agents. A host keeps the list its own page last signed, so once
 * `splint controls` has been run for more than one host, each may hold a different one, an older one
 * at this page's own host among them. So every host signed in at is asked, a list that isn't signed by
 * this owner for the host it came from is passed over, and the newest of the rest is taken, never one
 * older than the page holds already. Only where the list was last read does a refusal mean something's
 * wrong.
 */
async function loadList() {
  const host = /** @type {any} */ (me.host).domain;
  // On a computer whose agents haven't named a host yet, there's no list to read.
  if (!host) return;
  const holder = me.listAt || host;
  // Read only where Splint here has a session. With none at all, as after approving in a terminal or
  // at a Mac's prompt, the page shows what waits here and offers to unlock for the rest.
  const reading = [...new Set([holder, host, ...me.sessions.keys()])].filter((at) => me.sessions.get(at));
  if (!reading.length) return;
  const answers = await Promise.all(reading.map(async (at) => {
    try {
      return { at, held: await read(at, `/v0/owner-agents/${me.owner.id}`), error: null };
    } catch (error) {
      // A host holding no agent and no list for this owner has no copy of their ID to check a session
      // against, so it answers as if the session had ended, though nothing is wrong.
      const none = error instanceof Refusal && (error.status === 404 || (error.status === 401 && me.list.seq === 0 && me.agents.size === 0));
      return { at, held: null, error: at === holder && !none ? error : null };
    }
  }));
  const failed = answers.find((one) => one.error);
  if (failed) throw failed.error;
  const signed = [];
  for (const { at, held } of answers) {
    if (!held) continue;
    // A newer copy of the ID, such as one with the recovery code set on another device, before the list
    // that may need it is read. Only one that extends the copy held, as every reader checks.
    if (typeof held.owner_identity === "string") await adoptOwnerCopy(await readIdentity(held.owner_identity)).catch(() => null);
    const said = await verifyByOwner(held.list, "splint-owner-agents", me.owner).catch(() => null);
    if (said && said.owner === me.owner.id && said.host === at && Number.isSafeInteger(said.seq)) {
      signed.push({ at, list: held.list, seq: said.seq });
    } else if (at === holder) {
      throw new Error("That list isn't yours.");
    }
  }
  // Newest first, and this page's own host first of two alike.
  signed.sort((a, b) => b.seq - a.seq || Number(b.at === host) - Number(a.at === host));
  const newest = signed[0];
  if (!newest) {
    await backupKeptHere();
    return;
  }
  // A host can give back an older list than one this page read or kept since it opened.
  if (newest.seq < me.list.seq) return;
  // The owner signed it, so one that doesn't open is never passed over for an older one that does.
  const opened = !me.sealing
    ? { seq: newest.seq, backup: "", agents: [], codeSaved: null }
    : await openOwnerAgents(newest.list, me.owner, newest.at, me.sealing).catch(() => {
      throw new Error("That list isn't yours.");
    });
  me.listAt = newest.at === host ? null : newest.at;
  me.list = opened;
  if (!me.sealing) return;
  for (const listed of opened.agents) {
    // Whether it runs beside the person, as their own sign-in signed in the list, or unknown.
    const beside = listed.beside_owner === 1 ? true : listed.beside_owner === 0 ? false : undefined;
    const known = me.agents.get(listed.agent);
    if (!known) me.agents.set(listed.agent, { agent: listed.agent, address: listed.address, label: listed.label, beside });
    else known.beside = beside;
  }
  remember();
}

/** Who its host says the agent is, and whether this owner's own signature binds it there. */
async function lookUp(agent) {
  const { domain, handle } = addressParts(agent.address);
  try {
    let found = await call(domain, "GET", `/.well-known/splint/agents/${handle}`);
    // An agent that moved: the host left only says where, so what the owner signed there decides.
    if (typeof found.moved_to === "string" && AN_ADDRESS.test(found.moved_to) && found.moved_to !== agent.address) {
      const there = addressParts(found.moved_to);
      const moved = await call(there.domain, "GET", `/.well-known/splint/agents/${there.handle}`).catch(() => null);
      const signed = moved && moved.agent_id === agent.agent
        ? await verifyByOwner(String(moved.binding).split("~")[0], "splint-binding", me.owner).catch(() => null) : null;
      if (signed && signed.owner === me.owner.id && signed.agent === agent.agent && signed.address === found.moved_to) {
        agent.address = found.moved_to;
        found = moved;
      }
    }
    const owner = await readIdentity(found.owner_identity).catch(() => null);
    let mine = false;
    if (owner && owner.id === me.owner.id) await adoptOwnerCopy(owner);
    if (owner && owner.id === me.owner.id && found.agent_id === agent.agent) {
      const signed = await verifyByOwner(String(found.binding).split("~")[0], "splint-binding", me.owner).catch(() => null);
      mine = Boolean(signed && signed.owner === me.owner.id && signed.agent === agent.agent && signed.address === agent.address);
    }
    agent.status = mine ? "mine" : found.agent_id === agent.agent ? "not-yet" : "elsewhere";
    // The agent's key, which signs what its Signet leaves here, from an ID that hashes to the agent's.
    const identity = await readAgentIdentity(found.identity).catch(() => null);
    agent.identity = identity && identity.id === agent.agent && !identity.rp ? identity : null;
  } catch {
    agent.status = "unknown";
  }
}

/**
 * The rules the owner signed, from what a host holds: those alone, or, from before rules lasted until
 * replaced, renewed by the agent's delegate as `<rules>~<renewal>~<delegation>`. A renewal only moved
 * their end, which nothing reads now, so the page reads and builds on the owner's own part.
 */
function ownerSignedPart(held) {
  const parts = String(held).split("~");
  if (parts.length !== 1 && parts.length !== 3) throw new Error("malformed");
  return parts[0];
}

/**
 * Checks, just before signing, that the rules the page builds on are still the newest in force, read
 * again from the agent's host and checked as the owner's. Rules are replaced whole, so signing from
 * older ones would undo what another of the owner's devices signed since, such as a contact it took
 * out. Newer ones are shown and nothing is signed, so the person sees them before choosing
 * again. With the host unreachable, or holding rules that aren't the owner's, nothing is signed either.
 * Older ones than the page has change nothing, so a host can't take it back.
 */
async function inForce(agent) {
  const { domain } = addressParts(agent.address);
  let held = null;
  try {
    ({ rules: held } = await read(domain, `/v0/rules/${agent.agent}`));
  } catch {
    throw new Error(`${agent.label}'s host couldn't be reached to read the rules in force, so nothing was signed. Try again.`);
  }
  if (!held) return;
  const signed = await verifyByOwner(ownerSignedPart(held), "splint-rules", me.owner).catch(() => null);
  if (!signed || signed.owner !== me.owner.id || signed.agent !== agent.agent) {
    throw new Error(`The rules ${agent.label}'s host holds aren't yours, so nothing was signed.`);
  }
  if (agent.rules && signed.seq <= agent.rules.seq) return;
  agent.rules = signed;
  draw(true);
  throw new Error(`${agent.label}'s rules were changed on another device since this page read them, so nothing was signed. Look again, and choose.`);
}

/** What the agent's Signet left for its owner, opened here, and the rules its host holds, checked here. */
async function loadAgent(agent) {
  const { domain } = addressParts(agent.address);
  await lookUp(agent);
  if (agent.status !== "mine" || !me.sessions.has(domain)) return;
  let held = null;
  try {
    ({ rules: held } = await read(domain, `/v0/rules/${agent.agent}`));
  } catch {
    // Not heard this time, so the rules last checked stand.
    held = null;
  }
  if (held) {
    try {
      const signed = await verifyByOwner(ownerSignedPart(held), "splint-rules", me.owner);
      agent.rules = signed.owner === me.owner.id && signed.agent === agent.agent ? signed : undefined;
    } catch {
      // Shown as rules the page couldn't check, which it signs nothing from.
      agent.rules = undefined;
    }
  }
  try {
    const { refused } = await read(domain, `/v0/refused/${agent.agent}`);
    agent.refused = Array.isArray(refused) ? refused : [];
  } catch {
    agent.refused = [];
  }
  if (!me.sealing) return;
  // Reads every 5 seconds can overlap, and one answered after a later one isn't the host going back.
  const asked = agent.viewsAsked = (agent.viewsAsked || 0) + 1;
  try {
    const path = `/v0/owner-view/${agent.agent}`;
    const held = await read(domain, path);
    // The host's own answer, never one straight from an agent's Signet, so there's none to fall back from.
    const opened = await viewToTake(held, false, (sealed) => openView(agent, sealed),
      async () => read(domain, path), newestViewSeen(agent.agent), now());
    if (asked < (agent.viewsAnswered || 0)) return;
    agent.viewsAnswered = asked;
    const newest = newestViewSeen(agent.agent);
    // Every view the agent ever left is signed, so a host can give back an older one, such as one
    // naming a delegate key the owner has since replaced. The page goes on with the newest it has.
    agent.behind = Boolean(opened && opened.at < newest);
    if (agent.behind) {
      if (agent.view && agent.view.at < newest) agent.view = null;
    } else {
      agent.view = opened;
      if (opened) sawView(agent.agent, opened.at);
    }
    agent.parties = await partiesOf(agent.view);
    agent.schemas = await schemasOf(agent.view);
    agent.heardAt = agent.view ? agent.view.at : null;
  } catch {
    agent.view = null;
  }
}

function viewsSeenKept() {
  try {
    const kept = JSON.parse(localStorage.getItem(VIEWS_SEEN) || "{}");
    return kept && typeof kept === "object" && !Array.isArray(kept) ? kept : {};
  } catch {
    return {};
  }
}

function newestViewSeen(id) {
  const kept = viewsSeenKept()[id];
  return Math.max(me.viewsSeen.get(id) || 0, Number.isSafeInteger(kept) ? kept : 0);
}

function sawView(id, at) {
  if (at <= newestViewSeen(id)) return;
  me.viewsSeen.set(id, at);
  try {
    localStorage.setItem(VIEWS_SEEN, JSON.stringify({ ...viewsSeenKept(), [id]: at }));
  } catch {
    // Kept for this visit only, then.
  }
}

/**
 * The agent's view while it's recent enough to sign a delegation from, or null. It has to be the newest
 * this browser has opened too, read afresh, as another tab may have opened a newer one since this tab
 * last heard, such as one naming a new delegate key.
 */
function currentView(agent) {
  const view = agent.view;
  return view && now() - view.at <= VIEW_CURRENT_SECS && view.at >= newestViewSeen(agent.agent) ? view : null;
}

/** Whether the page has a view from the agent's Signet showing its delegation, but none it can sign from now. */
function viewNotCurrent(agent) {
  return !currentView(agent) && (agent.behind || Boolean(agent.view && agent.view.delegation));
}

/**
 * The view an agent's Signet left, only if its own key signed it for this owner. Anyone can seal to the
 * owner, whose sealing key is public, so the seal alone says nothing about who wrote it.
 */
async function openView(agent, sealed) {
  if (!agent.identity) return null;
  const opened = await openSealed(/** @type {any} */ (me.sealing), sealed, utf8(`splint owner view for ${agent.agent}`));
  const signed = await verifyOwnerView(new TextDecoder().decode(opened), agent.identity, me.owner.id, now());
  return { ...signed.view, at: signed.issued_at };
}

async function refresh() {
  const mine = ++refreshing;
  await loadList();
  await Promise.all([...me.agents.values()].map(loadAgent));
  if (mine === refreshing) draw();
}

// ---------- Decisions ----------

// What each binding a view handed over was found to say, so reading every few seconds checks each once.
const PARTIES_CHECKED = new Map();
const MAX_PARTIES_CHECKED = 1000;

/**
 * Who the other side of each of the agent's requests is, keyed by their agent and owner IDs as terms
 * name them: the address in the binding their owner's key signed for that agent, which that agent's key
 * accepted. The view hands each binding over, and is only its Signet's word, so the page takes from it
 * only what those signatures say. Whether a binding replaced another, and its vouch, are left to the
 * agent's Signet, which checked the whole of it before it let any of their messages in.
 */
async function partiesOf(view) {
  const handed = view && view.requests ? view.requests : {};
  const parties = new Map();
  for (const one of [...(Array.isArray(handed.requests) ? handed.requests : []), ...(Array.isArray(handed.held_opens) ? handed.held_opens : [])]) {
    if (!one || one.guest) continue;
    const given = JSON.stringify([one.peer_identity, one.peer_owner, one.peer_binding]);
    if (!PARTIES_CHECKED.has(given)) {
      if (PARTIES_CHECKED.size >= MAX_PARTIES_CHECKED) PARTIES_CHECKED.clear();
      PARTIES_CHECKED.set(given, await checkedParty(one).catch(() => null));
    }
    const party = PARTIES_CHECKED.get(given);
    if (party) parties.set(`${party.agent} ${party.owner}`, party);
  }
  return parties;
}

async function checkedParty(handed) {
  const agent = await readAgentIdentity(handed.peer_identity);
  const owner = await readIdentity(handed.peer_owner);
  const [byOwner, byAgent] = String(handed.peer_binding).split("~");
  const signed = await verifyByOwner(byOwner, "splint-binding", owner);
  const accepted = await verifyEs256(byAgent, "splint-binding-accept", agent.key);
  if (signed.owner !== owner.id || signed.agent !== agent.id || typeof signed.address !== "string" || !AN_ADDRESS.test(signed.address)
    || accepted.binding !== hex(await sha256(utf8(byOwner)))) return null;
  return { agent: agent.id, owner: owner.id, address: signed.address, standIn: owner.standIn };
}

/** The other side of a draft's terms, by the IDs signed in them, and who the page found them to be. */
function otherSide(agent, terms) {
  const side = (terms.requester && terms.requester.agent === agent.agent ? terms.recipient : terms.requester) || {};
  const ids = { agent: String(side.agent || ""), owner: String(side.owner || "") };
  return { ...ids, party: (agent.parties && agent.parties.get(`${ids.agent} ${ids.owner}`)) || null };
}

/**
 * Who a deal is with, on every card: their address and whether their owner's own signature binds them
 * there, as the person has to know whom they're saying yes to. Nothing they chose to call themselves.
 */
function withWhom(agent, other) {
  const line = (dot, who, why) => el("div", { class: "with" },
    el("p", {}, el("span", { class: `dot ${dot}` }), " ", el("strong", {}, who)), el("p", { class: "soft small" }, why));
  if (other.agent.startsWith("splint1g")) return line("warn", "With whoever holds your one-use link", "Not verified: anyone given the link can answer it.");
  const party = other.party;
  if (!party) return line("stop", "With someone this page couldn't check", "Not verified: no signature from the person behind it came with it. Their IDs are under Exact terms.");
  const contact = ((agent.rules && agent.rules.contacts) || []).find((one) => one.agent === party.agent && !hasHiddenCharacters(one.label));
  const agreed = !contact && agreedWith(agent).some((held) => held.sender === party.agent);
  const who = `With ${contact ? `${contact.label} (${party.address})` : party.address}${agreed ? ", a contact your agent agreed with" : ""}`;
  if (party.owner === me.owner.id) return line("good", `${who}, your own agent too`, "Verified: your own signature binds it at that address.");
  if (party.standIn) return line("warn", who, "Not verified: nobody has set up that agent's controls yet.");
  return line("good", who, "Verified: the person behind it signed that it acts for them at that address.");
}

/**
 * What the owner's own signed rules call each agent, which is all that names anyone on this page, and
 * then each contact the agent agreed with by itself, by the address both agents signed.
 */
function namesFor(agent) {
  const names = new Map();
  names.set(agent.agent, `${agent.label}, your agent`);
  for (const contact of (agent.rules && agent.rules.contacts) || []) {
    if (!hasHiddenCharacters(contact.label)) names.set(contact.agent, `${contact.label}, from your contacts`);
  }
  for (const held of agreedWith(agent)) {
    if (!names.has(held.sender)) names.set(held.sender, `${withHiddenShown(String(held.address))}, a contact your agent agreed with`);
  }
  return names;
}

/** Contacts the agent agreed with by itself, by invite, that the owner's rules don't name, from its Signet's view. */
function agreedWith(agent) {
  return ((agent.view && agent.view.held) || []).filter((held) => held.kind === "agreed" && held.sender && held.address);
}

/**
 * Signs exactly the draft that was drawn: the same object, frozen when the card was made, so what's
 * on the screen is what's signed. Its agent's Signet and every other reader hold it to the chain.
 */
async function decide(agent, draft, decision, typed) {
  const payload = {
    v: 1, owner: me.owner.id, agent: agent.agent, decision, operation: draft.operation, request: draft.request,
    version: draft.version, prev: draft.prev, terms: draft.terms, issued_at: now(), expires_at: draft.latest_expiry,
  };
  await readyToLeaveFor([agent]);
  const done = await touch([signingInput(OWNER_ALG, "splint-approval", payload)], typed);
  await leaveMail(agent, "approval", done.signed[0]);
}

/** New rules, from the ones the owner last signed, changed as they chose, with one touch. */
async function signRules(agent, change, fresh) {
  return signRulesFor([{ agent, change, fresh: Boolean(fresh) }]);
}

/** The key the agent's Signet says it signs for its owner with, from a current view, if it named one. */
function delegateOf(agent) {
  const view = currentView(agent);
  const shown = view && view.delegation;
  return shown && typeof shown.delegate === "string" && /^[A-Za-z0-9_-]{1,100}$/.test(shown.delegate) ? shown.delegate : null;
}

/**
 * Whether the delegation the agent holds is due to be signed afresh: there's none that counts, it
 * doesn't name every type the page delegates, or it's in its last 30 days. Only the Signet's word,
 * which can cost the owner a touch and no more, as every reader checks what the delegate signs.
 */
function delegationDue(agent) {
  if (!delegateOf(agent)) return false;
  const held = /** @type {any} */ (currentView(agent)).delegation.delegation;
  if (!held || held.counts !== true || !Number.isSafeInteger(held.expires_at)) return true;
  const types = Array.isArray(held.types) ? held.types : [];
  return held.expires_at - now() <= FRESH_DELEGATION_WITHIN_SECS || DELEGATED_TYPES.some((type) => !types.includes(type));
}

/**
 * New rules for each agent, from the ones the owner last signed, changed as they chose, all with one
 * touch. Where the agent's delegation is due, or `fresh` asks, a new one to its Signet's delegate key
 * is signed in the same touch and the rules name it, so an agent paired long ago gets the page's caps
 * and another year, and the delegate never has to extend itself. Only from a current view, so it gives
 * back the agents whose delegation was asked for afresh and couldn't be, for the page to say so.
 * @param {{agent: any, change: (draft: any) => void, fresh: boolean}[]} changes
 */
async function signRulesFor(changes) {
  for (const { agent } of changes) await inForce(agent);
  const at = now();
  const made = changes.map(({ agent, change, fresh }, index) => {
    const current = agent.rules;
    if (!current) throw new Error("The rules for this agent couldn't be checked, so nothing is signed from them.");
    const draft = JSON.parse(JSON.stringify(draftOf(current)));
    change(draft);
    const seq = Math.max(Date.now() + index, current.seq + 1);
    const delegate = (fresh || delegationDue(agent)) ? delegateOf(agent) : null;
    const delegation = delegate ? delegationInput(OWNER_ALG, { owner: me.owner.id, agent: agent.agent, seq, now: at }, { ...DEFAULT_DELEGATION, delegate }) : null;
    return { agent, fresh, draft, seq, delegation, payload: /** @type {any} */ (null) };
  });
  for (const one of made) {
    const named = one.delegation ? hex(await sha256(utf8(one.delegation))) : (one.agent.rules.delegation || null);
    one.payload = rulesPayload(one.draft, { owner: me.owner.id, agent: one.agent.agent, seq: one.seq, now: at, delegation: named });
  }
  const inputs = made.flatMap((one) => [signingInput(OWNER_ALG, "splint-rules", one.payload), ...(one.delegation ? [one.delegation] : [])]);
  await readyToLeaveFor(made.filter((one) => one.delegation).map((one) => one.agent));
  const done = await touch(inputs);
  let next = 0;
  for (const one of made) {
    const rules = done.signed[next++];
    const domain = addressParts(one.agent.address).domain;
    // The delegation first, so the Signet holds it by the time the rules naming it reach it. One only
    // its Signet took, with its host away, is kept for the host by your controls, so the rules still
    // go, and say the same of themselves.
    if (one.delegation) {
      await leaveMail(one.agent, "delegation", done.signed[next++])
        .catch((error) => { if (!(error instanceof Refusal && error.onlyStraight)) throw error; });
    }
    await send(domain, "PUT", "/v0/rules", { rules });
    one.agent.rules = one.payload;
    // Choices the person made in Settings and hasn't saved stay over rules this page signed itself, as
    // they've seen what changed. Ones they haven't made start again from these.
    const held = me.choices.get(one.agent.agent);
    if (held && held.touched) held.seq = one.payload.seq;
    else me.choices.delete(one.agent.agent);
  }
  return made.filter((one) => one.fresh && !one.delegation && viewNotCurrent(one.agent)).map((one) => one.agent);
}

/** Every type the agent agreed with anyone, by ID, from its view, which anyone it's open to may use. */
function agentTypes(agent) {
  return [...new Set(((agent.view && agent.view.types) || []).filter((type) => typeof type === "string"))].sort();
}

/**
 * Letting someone in who's held: their address, looked up at its own host, has to name the same ID,
 * as the host is the authority on its own handles.
 */
async function letIn(agent, held) {
  if (!held.address) throw new Error("They gave no address, so there's nobody to add.");
  // The two agents agree what kinds of request they use, so the owner names none here.
  const { domain, handle } = addressParts(held.address);
  const found = await call(domain, "GET", `/.well-known/splint/agents/${handle}`);
  if (found.agent_id !== held.sender) throw new Error("That address isn't theirs, so nobody was added.");
  await signRules(agent, (draft) => {
    draft.contacts = draft.contacts.filter((contact) => contact.agent !== held.sender && contact.address !== held.address);
    draft.contacts.push({ agent: held.sender, address: held.address, label: addressParts(held.address).name, status: "allowed", types: [], text: true, agree_types: true, pinned_by: held.kind === "invite" || held.kind === "agreed" ? "invite" : "owner" });
  });
}

/**
 * Removing or blocking a contact the agent added by itself: the owner names them in the rules, which
 * always win over what the agent agreed. A removal names them with nothing to use.
 */
async function keepOut(agent, held, status) {
  if (!held.address) throw new Error("They gave no address, so there's nobody to name.");
  await signRules(agent, (draft) => {
    draft.contacts = draft.contacts.filter((contact) => contact.agent !== held.sender && contact.address !== held.address);
    draft.contacts.push({ agent: held.sender, address: held.address, label: addressParts(held.address).name, status, types: [], text: false, agree_types: false, pinned_by: "owner" });
  });
}

/** Whether a contact entry is a removal: nothing to use, no kinds to agree and no words. */
function isRemoval(contact) {
  return contact.status === "allowed" && Array.isArray(contact.types) && contact.types.length === 0 && contact.agree_types === false && !contact.text;
}

/**
 * One place as a person types it, held to the check an agent's ask for places gets, which is every
 * Signet's, so the person never signs a place their agents then refuse.
 */
function placeFrom(line) {
  const place = typedPlace(line);
  if (!placeFits(place)) throw new Error(`${line.slice(0, 40)} isn't a place Splint takes`);
  return place;
}

/** One place as a person types it, in the order its fields are signed in. */
function typedPlace(line) {
  if (line.startsWith("https://")) {
    if (line.length > 300 || /[\s"<>`{}|\\^]/.test(line) || /^https:\/\/[^/?#]*@/.test(line)) throw new Error(`${line.slice(0, 40)} isn't a payment page Splint takes: no spaces or login in it, up to 300 characters`);
    return { kind: "payment_page", url: line };
  }
  if (line.startsWith("onchain:")) {
    const parts = line.slice("onchain:".length).split(":");
    if (parts.length !== 4) throw new Error("a chain address is onchain:CHAIN:ADDRESS:ASSET, such as onchain:eip155:8453:0xabc...:usdc");
    return { kind: "onchain", chain: `${parts[0]}:${parts[1]}`, address: parts[2], asset: parts[3].toLowerCase() };
  }
  const to = line.startsWith("lightning:") ? line.slice("lightning:".length) : line;
  if (!/^lno1[a-z0-9]+$/.test(to) && !/^[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(to)) throw new Error(`${line.slice(0, 40)} isn't an https payment page, a Lightning address or offer, or onchain:CHAIN:ADDRESS:ASSET`);
  return { kind: "lightning", to };
}

/** Signs where the person gets paid, with one touch, and leaves it for each of their agents. */
async function signWherePaid(agents, typed, passphrase) {
  const lines = typed.split("\n").map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0 || lines.length > 4) throw new Error("Give 1 to 4 places, one a line.");
  const places = lines.map(placeFrom);
  if (new Set(places.map((place) => JSON.stringify(place))).size !== places.length) throw new Error("Each place once.");
  await signPlaces(agents, places, passphrase);
  me.paidDraft = "";
  say("Signed. Your agents can ask to be paid there once a deal that pays you is done.", false);
}

/** One approval: where the owner gets paid, exactly these places, left for each of these agents. */
async function signPlaces(agents, places, passphrase) {
  let payload;
  try {
    payload = wherePaidPayload(me.owner.id, places, now());
  } catch {
    throw new Error("Those places are more than one statement of where you get paid can hold. Give fewer, or shorter ones.");
  }
  await readyToLeaveFor(agents);
  const done = await touch([signingInput(OWNER_ALG, "splint-where-paid", payload)], passphrase);
  for (const agent of agents) {
    await leaveMail(agent, "where_paid", done.signed[0]);
  }
}

/**
 * The owner's yes to a contact's history as far as one exact head, which their agent's Signet holds
 * them to from then on. It leaves as owner mail, as an approval does.
 */
async function acceptChange(agent, notice, head) {
  const payload = { v: 1, owner: me.owner.id, agent: agent.agent, contact: notice.contact, head, seq: Date.now(), issued_at: now() };
  await readyToLeaveFor([agent]);
  const done = await touch([signingInput(OWNER_ALG, "splint-change-accept", payload)]);
  await leaveMail(agent, "acceptance", done.signed[0]);
}


// ---------- Kept for the cards: what they say, worked out from what's signed ----------

/**
 * The schemas in the agent's view whose fingerprint, worked out here, is a type's ID, by that ID. Where
 * there's none, timesOf and unitsOf take the same Signet's `times` and `units`, so what they show is
 * that Signet's word either way.
 */
async function schemasOf(view) {
  const found = new Map();
  for (const schema of (view && Array.isArray(view.schemas) ? view.schemas : [])) {
    try {
      found.set(await typeId(schema), schema);
    } catch {
      // Not a schema: left out.
    }
  }
  return found;
}

/** The fields of a type that hold times: from its schema where the page has it, or as the agent's Signet signed in its view. */
function timesOf(agent, type) {
  const schema = agent.schemas && agent.schemas.get(type);
  if (schema) {
    const timeField = (name) => [schema.offer, schema.result, schema.say].some((section) => section && section[name] && section[name].times);
    const picks = Object.entries(schema.pick || {}).filter(([, from]) => timeField(from)).map(([name]) => name);
    const fields = [schema.offer, schema.result, schema.say].flatMap((section) => Object.keys(section || {})).filter(timeField);
    return [...new Set([...fields, ...picks])].sort();
  }
  const named = agent.view && agent.view.times && Object.hasOwn(agent.view.times, type) ? agent.view.times[type] : [];
  return Array.isArray(named) ? named.filter((name) => typeof name === "string") : [];
}

/** A type's `units`, for an amount, the field naming its currency: from its schema where the page has it, or as the agent's Signet signed in its view. */
function unitsOf(agent, type) {
  const schema = agent.schemas && agent.schemas.get(type);
  const named = schema ? schema.units || {}
    : agent.view && agent.view.units && Object.hasOwn(agent.view.units, type) ? agent.view.units[type] : null;
  if (!named || typeof named !== "object" || Array.isArray(named)) return {};
  return Object.fromEntries(Object.entries(named).filter(([, unit]) => typeof unit === "string"));
}

/** What the other side is called in a sentence: the owner's own name for them, or where the page found them. */
function nameOf(agent, other) {
  if (other.agent.startsWith("splint1g")) return "whoever holds your one-use link";
  if (!other.party) return "someone this page couldn't check";
  const contact = ((agent.rules && agent.rules.contacts) || []).find((one) => one.agent === other.party.agent && !hasHiddenCharacters(one.label));
  return contact ? contact.label : other.party.address;
}

/**
 * Who asked for what a step is on, from the draft itself: its agent makes the step, and its terms say
 * which side asked. A cancel the owner's own agent wanted, on something the other side asked for, read
 * as theirs.
 */
function askedFor(agent, draft, other) {
  if (draft.operation === "open" || draft.operation === "offer_to_guest") return "";
  const name = nameOf(agent, other);
  return draft.terms.requester && draft.terms.requester.agent === draft.agent ? `, which it asked ${name} for` : `, which ${name} asked for`;
}

/**
 * What the agent's Signet says of the owner's last answers it couldn't use, such as a yes to an amount
 * the agent changed before the yes reached it. Only its word: what's signed is still the
 * draft on the card.
 */
function notUsedOf(agent) {
  const handed = agent.view && agent.view.requests && Array.isArray(agent.view.requests.requests) ? agent.view.requests.requests : [];
  return handed.map((one) => one && one.not_used).filter((said) => said && typeof said.request === "string");
}

/**
 * An amount to pay, in its currency where its unit is one and with its unit's word where that isn't, as
 * the page on an owner's own device words it.
 */
function amountWords(value, amount, unit) {
  const currency = typeof unit === "string" && /^[a-z]{3}$/i.test(unit) ? unit.toUpperCase() : null;
  const minor = fieldLabel(value).unit === UNITS.minor;
  const exact = String(amount);
  if (minor && currency) return money(exact, currency);
  if (minor && typeof unit === "string") return `${exact} in minor units of ${withHiddenShown(unit)}`;
  const shown = fieldValue(value, exact);
  if (currency) return `${shown} ${currency}`;
  return typeof unit === "string" ? `${shown} ${withHiddenShown(unit)}` : shown;
}

/**
 * Who pays whom if this goes through, as "You pay 40.00 USD to ben~host": from the type's `paid`, which
 * this page takes only from a schema whose fingerprint it checked, and the signed terms, the amount
 * from what was delivered and then what was agreed. A field's name, which whoever proposed the type
 * chose, never says which way money goes (security review, finding 6). The other side is named by the
 * address their owner's signature binds them to. `null` where this page has no checked schema for a
 * type that has amounts, so it can't say.
 */
function payingLines(agent, draft, other) {
  const terms = draft.terms;
  const schema = agent.schemas && agent.schemas.get(terms.type);
  if (!schema) return Object.keys(unitsOf(agent, terms.type)).length ? null : [];
  const paid = schema.paid && typeof schema.paid === "object" ? schema.paid : {};
  const units = schema.units && typeof schema.units === "object" ? schema.units : {};
  const mine = terms.requester && terms.requester.agent === draft.agent ? "requester" : "recipient";
  const them = other.agent.startsWith("splint1g") ? "whoever holds your one-use link"
    : other.party ? other.party.address : "someone this page couldn't check";
  const amountOf = (value) => [terms.result, terms.agreed]
    .map((fields) => (fields && Object.hasOwn(fields, value) ? fields[value] : undefined))
    .find((found) => typeof found === "number");
  const paying = (Array.isArray(schema.values) ? schema.values : [])
    .filter((value) => Object.hasOwn(paid, value) && (paid[value] === "requester" || paid[value] === "recipient") && amountOf(value) !== undefined);
  return paying.map((value) => {
    const unitField = Object.hasOwn(units, value) ? units[value] : null;
    const unit = unitField && terms.agreed && Object.hasOwn(terms.agreed, unitField) && typeof terms.agreed[unitField] === "string" ? terms.agreed[unitField] : null;
    const amount = amountWords(value, amountOf(value), unit);
    const what = paying.length > 1 ? `, for ${fieldLabel(withHiddenShown(value)).label}` : "";
    return paid[value] === mine ? `${them} pays you ${amount}${what}` : `You pay ${amount} to ${them}${what}`;
  });
}

/**
 * Whether the rules the owner signed already deal with an ask or an invite, which the Signet drops once
 * its rules name that sender: blocked, or let in with types, as a contact with none is judged like
 * anyone else. The Signet takes new rules from its host only every half minute or so, so without this
 * a card the owner just answered stayed until it did. Someone writing in is a message the host still
 * holds, which it lets go only if the rules admit it, so that card is left to the next view, as is a
 * host's warning about another ID at an address.
 */
function settledBy(rules, held) {
  if (held.kind !== "asked" && held.kind !== "invite") return false;
  return Boolean(rules) && Array.isArray(rules.contacts) && rules.contacts.some((contact) => contact && contact.agent === held.sender
    && (contact.status === "blocked" || (contact.status === "allowed" && !isRemoval(contact))));
}

/** Whether a pending invite is one this owner's agent sent, by the invite it carries. */
function invitedByUs(agent, held) {
  try {
    return payloadOf(String(held.invite && held.invite.invite)).from === agent.agent;
  } catch {
    return false;
  }
}

/** Rules open to anyone have to name what they may ask for, or they'd let nobody in. */
function openTypes(agent) {
  const types = agentTypes(agent);
  if (!types.length) throw new Error("Your agent hasn't said what it does yet, so it can't be open to anyone. Try again once it has.");
  return types;
}

// Fixed words for each setting that lets more through than usual, as the page beside the agent says
// them. They say what it means, and the person's choice stands.
/** @type {{on: (rules: any) => boolean, words: string}[]} */
const RISKY = [
  { on: (rules) => rules.reach.inbound.from !== "contacts", words: "Anyone can reach this agent, not only your contacts. Only approve what you asked it for." },
  { on: (rules) => rules.permissions.level === "full_auto", words: "Full auto: this agent says yes by itself to everything it may, up to Splint's limits. A price you'd pay is never agreed without your yes, and one it quotes waits for you unless you let quotes go by themselves." },
  { on: (rules) => rules.sealing === "unsealed", words: "Unsealed: with contacts who also chose it, hosts can read what passes." },
  { on: (rules) => rules.reach.inbound.from !== "contacts" && Boolean(rules.reach.inbound.text), words: "People who aren't your contacts can send this agent their own words, which may be written to fool it." },
];

/**
 * Contacts the agent added by itself that the settings chosen would take out, where the ones signed
 * let them in: at Ask me first, or with those contacts turned off, only contacts the owner chose count
 *. From its Signet's view, which lists only those the rules don't name either way.
 */
function addedTakenOut(agent, level, agreedOn) {
  if (!takesAddedOut(agent, level, agreedOn)) return [];
  return ((agent.view && agent.view.held) || []).filter((held) => held.kind === "agreed" && held.address);
}

/** Whether the settings chosen take out contacts the agent adds by itself, where the ones signed let them in. */
function takesAddedOut(agent, level, agreedOn) {
  const rules = agent.rules;
  const letIn = Boolean(rules.reach.agreed) && rules.permissions.level !== "ask_me";
  return letIn && !(agreedOn && level !== "ask_me");
}

/**
 * The ones kept, each checked at its own host first, as approving one is, since the host is the
 * authority on its own handles. One that doesn't check out stops the save, so nothing is signed.
 */
async function keptAsOwn(going) {
  for (const held of going) {
    const { domain, handle } = addressParts(held.address);
    const found = await call(domain, "GET", `/.well-known/splint/agents/${handle}`);
    if (found.agent_id !== held.sender) throw new Error(`${withHiddenShown(held.address)} isn't theirs now, so nothing was signed. Choose Drop them to sign without them.`);
  }
  return going;
}

// ---------- Drawing ----------
//
// Preact, with htm for the markup: it builds every element itself and sets text as text, so nothing a
// counterparty wrote can become markup. What the page knows stays in `me`, as the code above leaves
// it; what's only about the drawing, such as where the person is and what's half typed, is in `ui`.

const { html, render } = /** @type {any} */ (globalThis).htmPreact;

/** Where the person is on the page, and what's open or half typed there. */
const ui = {
  /** `home` (what needs them), `agent`, `requests`, `request`, `link`, `setup`, `unlock`, `code`, `no-key`, `cant-sign`, `unreachable`, `loading`. */
  view: "loading",
  agent: "",
  tab: "now",
  request: "",
  /** @type {{words: string, bad: boolean} | null} */
  toast: null,
  /** @type {any} */
  sheet: null,
  /** What's opened by an info button or a contact's menu. */
  open: new Set(),
  /** What's typed, by field, which a redraw keeps. Passphrases are emptied once used. */
  typed: /** @type {Record<string, string>} */ ({}),
  /** What one button is doing, so it does one thing at a time. */
  busy: "",
  /** The asks waiting on this computer, in the approvals that sign them, as Splint here lists them. */
  approvals: /** @type {{asks: any[], code: string | null}[]} */ ([]),
  promptsByItself: false,
  /** A link's ask, as `#ask=…&at=…` gave it, until the person clicks to see it. */
  /** @type {{ask: string, address: string} | null} */
  offered: null,
  /** The link's ask once Splint here took it, shown even before the page has its key. */
  /** @type {any} */
  linked: null,
  /** The recovery code just set, shown once. */
  code: "",
  /** Why the page can't go on, in its own words. */
  stopped: "",
  /** Whether this computer has a Splint ID to unlock, as a link's page learns before it has its key. */
  linkSetUp: false,
  /** Where to go once set up or unlocked, such as the request a link opened. */
  /** @type {{view: string, request?: string} | null} */
  after: null,
};

// A redraw can move another card under a click already on its way, and a counterparty can influence
// when one comes, so a button ignores clicks for this long after what's shown changes.
const PAUSE_AFTER_REDRAW_MILLIS = 700;
const TOLD_MILLIS = 5000;
const THEME = "splint-theme";
/** An agent is active when its Signet left a view this recently: it leaves one at least every 5 minutes. */
const ACTIVE_SECS = 7 * 60;
let lastDrawn = 0;
let lastShown = "";
let toldTimer = 0;
const CANCELLED = new Error("cancelled");

// ---------- Small parts ----------

const icon = {
  mark: () => html`<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M2.6 9.6c1-2.6 2.9-3.7 5-2.4 2.2 1.3 4 .3 5.8-2.4" stroke="currentColor" stroke-width="2.1" stroke-linecap="round"/></svg>`,
  check: () => html`<svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3.5 8.5l3 3 6-6.5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  shield: () => html`<svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 1.6l5.2 2v4.1c0 3.2-2.2 5.6-5.2 6.7-3-1.1-5.2-3.5-5.2-6.7V3.6z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M5.6 8l1.7 1.7 3.2-3.3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  chev: () => html`<svg class="chev" width="6" height="10" viewBox="0 0 7 12" fill="none" aria-hidden="true"><path d="M1 1l5 5-5 5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  down: () => html`<svg width="10" height="6" viewBox="0 0 10 6" fill="none" aria-hidden="true"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  info: () => html`<svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6.4" stroke="currentColor" stroke-width="1.3"/><path d="M8 7.2v3.8" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/><circle cx="8" cy="5" r="0.85" fill="currentColor"/></svg>`,
  laptop: () => html`<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="3" y="3.2" width="10" height="7" rx="1.4" stroke="currentColor" stroke-width="1.5"/><path d="M1.5 12.6h13" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  cloud: () => html`<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M4.6 12.4h7a2.9 2.9 0 00.3-5.8 4 4 0 00-7.6-.9A3.4 3.4 0 004.6 12.4z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>`,
  server: () => html`<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="2.5" y="2.5" width="11" height="4.6" rx="1.3" stroke="currentColor" stroke-width="1.5"/><rect x="2.5" y="8.9" width="11" height="4.6" rx="1.3" stroke="currentColor" stroke-width="1.5"/></svg>`,
  clock: () => html`<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/><path d="M8 4.8V8l2 1.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  lock: () => html`<svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="3" y="7" width="10" height="7" rx="1.8" stroke="currentColor" stroke-width="1.5"/><path d="M5.4 7V5.2a2.6 2.6 0 015.2 0V7" stroke="currentColor" stroke-width="1.5"/></svg>`,
  unlocked: () => html`<svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="3" y="7" width="10" height="7" rx="1.8" stroke="currentColor" stroke-width="1.5"/><path d="M5.4 7V5.2a2.6 2.6 0 015-1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  inbox: () => html`<svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M2 9.2l1.8-5.4c.2-.5.6-.8 1.1-.8h6.2c.5 0 .9.3 1.1.8L14 9.2V12a1 1 0 01-1 1H3a1 1 0 01-1-1z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M2 9.2h3.4l.9 1.6h3.4l.9-1.6H14" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>`,
  plus: () => html`<svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 3v10M3 8h10" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>`,
  dots: () => html`<svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="3.5" cy="8" r="1.3" fill="currentColor"/><circle cx="8" cy="8" r="1.3" fill="currentColor"/><circle cx="12.5" cy="8" r="1.3" fill="currentColor"/></svg>`,
  warn: () => html`<svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 2l6.4 11.2H1.6z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 6.6v3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="8" cy="11.4" r="0.85" fill="currentColor"/></svg>`,
  copy: () => html`<svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="5" y="5" width="8.5" height="8.5" rx="1.8" stroke="currentColor" stroke-width="1.6"/><path d="M10.5 3.2A1.5 1.5 0 009 2H3.8A1.8 1.8 0 002 3.8V9a1.5 1.5 0 001.2 1.5" stroke="currentColor" stroke-width="1.6"/></svg>`,
  sun: () => html`<svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="3" stroke="currentColor" stroke-width="1.5"/><path d="M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M3.4 12.6l1.1-1.1M11.5 4.5l1.1-1.1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  moon: () => html`<svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M13.4 9.8A5.6 5.6 0 016.2 2.6a5.6 5.6 0 107.2 7.2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>`,
  auto: () => html`<svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="5.6" stroke="currentColor" stroke-width="1.5"/><path d="M8 2.4a5.6 5.6 0 010 11.2z" fill="currentColor"/></svg>`,
};

function brand() {
  return html`<span class="brand"><span class="mark">${icon.mark()}</span>Splint</span>`;
}

/** Says one thing for a moment, or until the next click when it went wrong or needs reading. */
function say(words, bad, stay) {
  ui.toast = words ? { words, bad: Boolean(bad) } : null;
  clearTimeout(toldTimer);
  if (words && !bad && !stay) toldTimer = setTimeout(() => say("", false), TOLD_MILLIS);
  draw(true);
}

/**
 * What a button does, one thing at a time, with what went wrong said in plain words. A click that
 * lands just after what's shown changed doesn't count, as it may have been meant for something else.
 * @param {string} key @param {(event?: any) => Promise<any> | any} go
 */
function press(key, go) {
  return async (/** @type {any} */ event) => {
    if (performance.now() - lastDrawn < PAUSE_AFTER_REDRAW_MILLIS) {
      say("The page just changed, so that click didn't count. Look again.", true);
      return;
    }
    if (ui.busy) return;
    ui.busy = key;
    ui.toast = null;
    draw(true);
    try {
      await go(event);
    } catch (failure) {
      if (failure === NO_KEY) await unlockOrSetUp();
      else if (failure !== CANCELLED) say(failure.message, true);
    } finally {
      ui.busy = "";
      draw(true);
    }
  };
}

function btn(key, label, kind, go, extra) {
  return html`<button type="button" class=${`btn ${kind || ""}`} disabled=${Boolean(ui.busy) || (extra && extra.disabled)} onClick=${press(key, go)} id=${extra && extra.id}>${ui.busy === key ? "Working…" : label}</button>`;
}

function infoButton(id, about) {
  const open = ui.open.has(id);
  return html`<button type="button" class="i-btn" aria-label=${`About ${about}`} aria-expanded=${String(open)} onClick=${() => { open ? ui.open.delete(id) : ui.open.add(id); draw(true); }}>${icon.info()}</button>`;
}

/** An ID in plain sight: short, and one click copies the whole of it. */
function idChip(id, what) {
  return html`<button type="button" class="id-chip" title=${id} aria-label=${`Copy ${what}`} onClick=${press(`copy-${id}`, async () => {
    await navigator.clipboard.writeText(id);
    say(`Copied ${what}.`, false);
  })}>${shortId(id)}${icon.copy()}</button>`;
}

function field(id, label, input) {
  return html`<div class="field"><label for=${id}>${label}</label>${input}</div>`;
}

function passwordInput(id, extra) {
  return html`<input class="input" type="password" id=${id} autocomplete="off" value=${ui.typed[id] || ""} onInput=${(/** @type {any} */ event) => { ui.typed[id] = event.target.value; }} ...${extra || {}} />`;
}

/** Takes a typed passphrase once, and empties its field, so nothing keeps it. */
function takeTyped(id) {
  const typed = ui.typed[id] || "";
  delete ui.typed[id];
  return typed;
}

function theme() {
  try {
    return localStorage.getItem(THEME) || "auto";
  } catch {
    return "auto";
  }
}

function setTheme(picked) {
  try {
    localStorage.setItem(THEME, picked);
  } catch {
    // This visit only, then.
  }
  applyTheme();
  draw(true);
}

function applyTheme() {
  const picked = theme();
  if (picked === "light" || picked === "dark") document.documentElement.setAttribute("data-theme", picked);
  else document.documentElement.removeAttribute("data-theme");
}

function themeSwitch() {
  const picked = theme();
  const one = (id, glyph, words) => html`<button type="button" aria-pressed=${String(picked === id)} onClick=${() => setTheme(id)}>${glyph}<span>${words}</span></button>`;
  return html`<div class="seg" role="group" aria-label="Appearance">${one("auto", icon.auto(), "Auto")}${one("light", icon.sun(), "Light")}${one("dark", icon.moon(), "Dark")}</div>`;
}

// ---------- The sheet: one question at a time ----------

/**
 * Asks before something that costs money or can't be undone, and for a key file, takes its passphrase
 * for exactly this. Resolves with what was typed, or null where the chip asks for itself.
 * @param {{title: string, lead: string, rows?: [string, string][], label: string, passphrase?: boolean, danger?: boolean}} asked
 * @returns {Promise<string | null>}
 */
function confirmSheet(asked) {
  return new Promise((resolve, reject) => {
    const typedHere = asked.passphrase !== false && !chipHere();
    ui.sheet = {
      kind: "confirm", ...asked, typedHere,
      done: (/** @type {string | null} */ typed) => { ui.sheet = null; draw(true); resolve(typed); },
      cancel: () => { ui.sheet = null; delete ui.typed["sheet-passphrase"]; draw(true); reject(CANCELLED); },
    };
    draw(true);
    setTimeout(() => document.getElementById(typedHere ? "sheet-passphrase" : "sheet-go")?.focus(), 30);
  });
}

function sheetView() {
  const sheet = ui.sheet;
  if (!sheet) return null;
  const close = () => (sheet.cancel ? sheet.cancel() : (ui.sheet = null, draw(true)));
  const body = sheet.kind === "confirm" ? confirmBody(sheet)
    : sheet.kind === "account" ? accountBody()
      : sheet.kind === "agents" ? agentsBody()
        : sheet.kind === "contact" ? contactBody(sheet)
          : sheet.kind === "keep-added" ? keepAddedBody(sheet)
            : sheet.kind === "where-paid" ? wherePaidBody()
              : sheet.kind === "add" ? addAgentBody() : null;
  return html`<div class="scrim" onClick=${(/** @type {any} */ event) => { if (event.target === event.currentTarget) close(); }} onKeyDown=${(/** @type {any} */ event) => { if (event.key === "Escape") close(); }}>
    <div class="sheet" role="dialog" aria-modal="true" id=${`sheet-${sheet.kind}`}><div class="grabber"></div>${body}</div>
  </div>`;
}

function confirmBody(sheet) {
  const go = () => {
    const typed = sheet.typedHere ? takeTyped("sheet-passphrase") : null;
    if (sheet.typedHere && !typed) {
      say("Type your passphrase first.", true);
      return;
    }
    sheet.done(typed);
  };
  return html`
    <h2>${sheet.title}</h2>
    <p class="lead">${sheet.lead}</p>
    ${sheet.rows && sheet.rows.length ? html`<div class="surface list">${sheet.rows.map(([t, d]) => html`<div class="row"><div class="grow"><span class="t">${t}</span>${d ? html`<span class="d">${d}</span>` : null}</div></div>`)}</div>` : null}
    ${sheet.typedHere ? field("sheet-passphrase", "Passphrase", passwordInput("sheet-passphrase", { onKeyDown: (/** @type {any} */ event) => { if (event.key === "Enter") go(); } })) : null}
    <div class="btns" style="justify-content:flex-end">
      <button type="button" class="btn ghost" onClick=${() => sheet.cancel()}>Cancel</button>
      <button type="button" class=${`btn ${sheet.danger ? "danger" : "primary"}`} id="sheet-go" onClick=${go}>${sheet.typedHere ? icon.lock() : null}${sheet.label}</button>
    </div>
    ${sheet.typedHere ? html`<p class="hint">Payments and changes you can't undo always ask for your passphrase.</p>` : chipHere() ? html`<p class="hint">Your computer asks for Touch ID or your password next.</p>` : null}`;
}

// ---------- Agents ----------

function agentsShown() {
  return [...me.agents.values()];
}

function agentById(id) {
  return me.agents.get(id) || null;
}

/** How an agent stands, as a dot and a word: from what its host and its own signed view said. */
function standingOf(agent) {
  if (agent.status === "mine" && agent.rules && agent.rules.paused) return ["waiting", "Paused"];
  if (agent.status === "not-yet") return ["waiting", "Picking up your controls"];
  if (agent.status === "elsewhere") return ["stopped", "Its address names another agent now"];
  if (agent.status !== "mine") return ["", "Its host can't be reached"];
  if (agent.heardAt && now() - agent.heardAt <= ACTIVE_SECS) return ["live", "Active"];
  return ["", agent.heardAt ? `Last heard ${short(agent.heardAt)}` : "Not heard from yet"];
}

/** Everything waiting for the person from one agent, each as its own card. */
function needsOf(agent) {
  const view = agent.view || {};
  const drafts = (view.drafts || []).filter((draft) => draft.owner === me.owner.id && draft.agent === agent.agent);
  const beside = (draft) => drafts.filter((one) => one.request === draft.request && one.operation !== draft.operation).map((one) => one.operation);
  return [
    ...drafts.map((draft, index) => ({ key: `d-${draft.request}-${draft.operation}`, draw: () => decisionCard(agent, draft, beside(draft), drafts.findIndex((one) => one.request === draft.request) === index) })),
    ...(view.held || []).filter((held) => held.kind !== "agreed" && !settledBy(agent.rules, held)).map((held) => ({ key: `h-${held.sender}`, draw: () => heldCard(agent, held) })),
    ...(view.changes && Array.isArray(view.changes.changes) ? view.changes.changes : [])
      .filter((notice) => notice && notice.standing !== "continue").map((notice) => ({ key: `c-${notice.contact}`, draw: () => changeCard(agent, notice) })),
    ...approvalsFor(agent).map((approval) => ({ key: `a-${approval.asks[0].id}`, draw: () => askCard(approval, false) })),
  ];
}

/** The approvals waiting on this computer that this agent asked for. */
function approvalsFor(agent) {
  return ui.approvals.filter((approval) => approval.asks.some((ask) => ask.address === agent.address));
}

/** Approvals from agents this page doesn't list yet, such as one asking for its controls. */
function approvalsUnlisted() {
  const addresses = new Set(agentsShown().map((agent) => agent.address));
  return ui.approvals.filter((approval) => !approval.asks.some((ask) => addresses.has(ask.address)));
}

function countOf(agent) {
  return needsOf(agent).length;
}

function totalCount() {
  return agentsShown().reduce((sum, agent) => sum + countOf(agent), 0) + approvalsUnlisted().length;
}

// ---------- The shell ----------

function go(view, extra) {
  ui.view = view;
  ui.agent = (extra && extra.agent) || "";
  ui.tab = (extra && extra.tab) || "now";
  ui.request = (extra && extra.request) || "";
  const path = view === "agent" ? `/owner?agent=${encodeURIComponent(ui.agent)}${ui.tab !== "now" ? `&tab=${ui.tab}` : ""}`
    : view === "request" ? `/requests/${encodeURIComponent(ui.request)}`
      : view === "requests" ? "/requests" : "/owner";
  if (location.pathname + location.search !== path) history.pushState(null, "", path);
  window.scrollTo(0, 0);
  draw(true);
}

/** Where the address bar says the person is. */
function fromPath() {
  const params = new URLSearchParams(location.search);
  const requested = location.pathname.match(/^\/requests\/([0-9a-f]{1,64})$/);
  if (requested) return { view: "request", request: requested[1] };
  if (location.pathname === "/requests") return { view: "requests" };
  const agent = params.get("agent");
  if (agent && me.agents.has(agent)) return { view: "agent", agent, tab: ["now", "history", "contacts", "permissions"].includes(params.get("tab") || "") ? params.get("tab") : "now" };
  return { view: "home" };
}

function shell(content) {
  const agents = agentsShown();
  const total = totalCount();
  const name = displayName();
  return html`<div class="shell">
    <aside class="rail" aria-label="Your agents">
      ${brand()}
      <nav class="nav">
        <a class="nav-item" href="/owner" aria-current=${ui.view === "home" ? "page" : undefined} onClick=${(/** @type {any} */ event) => { event.preventDefault(); go("home"); }}><span class="nav-icon">${icon.inbox()}</span><span class="name">Needs you</span>${total ? html`<span class="count">${total}</span>` : null}</a>
      </nav>
      <nav class="nav">
        <p class="nav-label">Agents</p>
        ${agents.map((agent) => {
          const [dot] = standingOf(agent);
          const count = countOf(agent);
          return html`<a class="nav-item" href=${`/owner?agent=${encodeURIComponent(agent.agent)}`} id=${`agent-${agent.agent}`} title=${agent.address} aria-current=${ui.view === "agent" && ui.agent === agent.agent ? "page" : undefined} onClick=${(/** @type {any} */ event) => { event.preventDefault(); go("agent", { agent: agent.agent }); }}><span class="nav-icon"><span class=${`dot ${dot}`}></span></span><span class="name">${agent.label}</span>${count ? html`<span class="count">${count}</span>` : null}</a>`;
        })}
        <button type="button" class="nav-item" onClick=${() => { ui.sheet = { kind: "add" }; draw(true); }}><span class="nav-icon">${icon.plus()}</span><span class="name">Add an agent</span></button>
      </nav>
      <div class="rail-foot">
        ${themeSwitch()}
        <button type="button" class="me" id="account" onClick=${() => { ui.sheet = { kind: "account" }; draw(true); }}>
          <span class="grow"><span class="who">${name}</span><span class=${`status ${me.unlock ? "live" : ""}`}>${me.unlock ? icon.unlocked() : icon.lock()}${me.unlock ? "Unlocked" : "Locked"}</span></span>${icon.chev()}
        </button>
      </div>
    </aside>
    <main class="main"><div class="page">
      <div class="topbar">
        <button type="button" class="picker" aria-label="Switch agent" onClick=${() => { ui.sheet = { kind: "agents" }; draw(true); }}>
          ${ui.view === "agent" && agentById(ui.agent) ? html`<span class=${`dot ${standingOf(agentById(ui.agent))[0]}`}></span>` : icon.inbox()}
          <span class="name">${ui.view === "agent" && agentById(ui.agent) ? agentById(ui.agent).label : "Needs you"}</span>${total ? html`<span class="count">${total}</span>` : null}${icon.down()}
        </button>
        <button type="button" class="btn sm ghost" onClick=${() => { ui.sheet = { kind: "account" }; draw(true); }}>${name}</button>
      </div>
      ${content}
    </div></main>
  </div>`;
}

/** The name this person gave themselves on this computer, or a plain word. Never shown to anyone else. */
function displayName() {
  const known = me.owner && knownAs(me.owner.id);
  return (known && typeof known.name === "string" && known.name) || "You";
}

function agentsBody() {
  return html`
    <h2>Switch</h2>
    <div class="surface list">
      <button type="button" class="row" onClick=${() => { ui.sheet = null; go("home"); }}><span class="nav-icon">${icon.inbox()}</span><div class="grow"><span class="t">Needs you</span><span class="d">From every agent</span></div>${totalCount() ? html`<span class="count">${totalCount()}</span>` : null}</button>
      ${agentsShown().map((agent) => {
        const [dot, words] = standingOf(agent);
        return html`<button type="button" class="row" onClick=${() => { ui.sheet = null; go("agent", { agent: agent.agent }); }}><span class="nav-icon"><span class=${`dot ${dot}`}></span></span><div class="grow"><span class="t">${agent.label}</span><span class="d">${words} · <span class="mono">${agent.address}</span></span></div>${icon.chev()}</button>`;
      })}
    </div>
    ${themeSwitch()}`;
}

function addAgentBody() {
  return html`
    <h2>Add an agent</h2>
    <p class="lead">Tell the agent to join Splint. It asks you here, and you approve it.</p>
    <div class="surface list"><div class="row"><div class="grow"><span class="t">Say to your agent</span><span class="d mono">Join Splint and set up my controls</span></div></div></div>
    <button type="button" class="btn block" onClick=${() => { ui.sheet = null; draw(true); }}>Done</button>`;
}

// ---------- What needs the person ----------

function homeView() {
  const agents = agentsShown();
  const cards = [
    ...approvalsUnlisted().map((approval) => ({ key: `a-${approval.asks[0].id}`, draw: () => askCard(approval, true) })),
    ...agents.flatMap((agent) => needsOf(agent).map((one) => ({ ...one, agent }))),
  ];
  const update = updateCard(agents.filter((agent) => agent.status === "mine"));
  return html`
    <div class="head"><h1>Needs you</h1><p>What your agents can't do without your OK. The talking happens in their own chats.</p></div>
    ${plainKeyFileBanner()}
    ${!me.sessions.size && hostsKnown() && !plainKeyFile() ? html`<div class="section"><div class="surface callout" id="unlock-callout">
      <div class="grow"><p class="t">Unlock to see what your agents left you</p><p class="d">Requests waiting on this computer show already. Unlocking reads the rest from your agents' hosts.</p></div>
      ${btn("unlock-here", html`${icon.lock()}Unlock`, "sm primary", async () => { await unlockFor(); await refresh(); })}
    </div></div>` : null}
    ${reminderCard()}
    ${update}
    <div class="section" id="waiting">
      ${cards.length ? cards.map((one) => html`<div key=${one.key}>${one.draw()}</div>`) : emptyBox(agents.length ? "All clear" : "No agents yet", agents.length ? "Your agents carry on within the permissions you set." : "Tell your agent to join Splint and set up your controls. It asks you here.")}
    </div>`;
}

function emptyBox(title, words) {
  return html`<div class="surface empty"><span class="ok">${icon.check()}</span><div><p class="t">${title}</p><p class="d">${words}</p></div></div>`;
}

/** A reminder to set the recovery code, or that one wasn't saved, until it's dealt with. */
function reminderCard() {
  if (me.owner.recoveryLater && !recoveryPutOff) {
    return html`<div class="section"><div class="surface callout" id="recovery-reminder">
      <div class="grow"><p class="t">Save a recovery code</p><p class="d">It gets you back in if you lose this computer. It's shown once, so have paper or a password manager ready.</p></div>
      <div class="btns">${btn("not-now", "Not now", "sm ghost", async () => { recoveryPutOff = true; })}${btn("recovery", "Set up", "sm", setRecoveryCode)}</div>
    </div></div>`;
  }
  if (me.list.codeSaved === false && !codeSaved()) {
    return html`<div class="section"><div class="surface callout" id="code-reminder">
      <div class="grow"><p class="t">No recovery code saved</p><p class="d">It can't be shown again. If you lose this computer, you'd need a new Splint ID, which your contacts would have to accept again.</p></div>
      ${btn("code-aside", "Don't remind me", "sm", putCodeAside)}
    </div></div>`;
  }
  return null;
}

// Put off for this visit only, so the next visit reminds them again.
let recoveryPutOff = false;

/**
 * What brings each agent up to the page's defaults, with one approval for all of them: contacts it
 * adds can message it, for rules signed before that setting existed, and a delegation signed afresh
 * where the one it holds is due. Not now puts it off in this browser until what's offered changes.
 */
function updateCard(agents) {
  const due = agents.filter((agent) => agent.rules && !agent.rules.paused)
    .map((agent) => ({ agent, agreed: !agent.rules.reach.agreed, delegation: DELEGATED_TYPES.length > 0 && agent.rules.permissions.level !== "ask_me" && delegationDue(agent) }))
    .filter((one) => one.agreed || one.delegation);
  if (!due.length) return null;
  const offered = JSON.stringify(due.map((one) => [one.agent.agent, one.agreed, one.delegation]));
  try {
    if (localStorage.getItem(UPDATE_PUT_OFF) === offered) return null;
  } catch {
    // Shown each visit, then.
  }
  const words = (one) => [one.agreed ? "contacts it adds can message it" : null, one.delegation ? "it says yes by itself within your limits" : null].filter(Boolean).join(", and ");
  return html`<div class="section"><div class="surface callout" id="update-agents">
    <div class="grow"><p class="t">${due.length === 1 ? `Let ${due[0].agent.label} do more by itself` : "Let your agents do more by themselves"}</p>
      <p class="d">${due.map((one) => `${one.agent.label}: ${words(one)}.`).join(" ")} A price you'd pay still waits for you.</p></div>
    <div class="btns">
      ${btn("update-later", "Not now", "sm ghost", async () => {
        try {
          localStorage.setItem(UPDATE_PUT_OFF, offered);
        } catch {
          // Nothing kept here.
        }
      })}
      ${btn("update", due.length === 1 ? "Update it" : "Update them", "sm primary", async () => {
        const notRenewed = await signRulesFor(due.map((one) => ({ agent: one.agent, fresh: one.delegation, change: (draft) => { if (one.agreed) draft.reach.agreed = { ...AGREED }; } })));
        say(notRenewed.length ? `Updated. ${notRenewed.map((agent) => agent.label).join(", ")}: ${NOT_RENEWED_WORDS}` : "Updated.", false, notRenewed.length > 0);
      })}
    </div>
  </div></div>`;
}

// The page's own verb for each step, never the agent's words.
const VERBS = { confirm: "Agree to", cancel: "Cancel", open: "Start", counter: "Counter", accept: "Accept", deliver: "Deliver", offer_to_guest: "Offer" };
// Another step waiting on the same exchange, as its own card says it.
const BESIDE = { confirm: "your yes to agree to it", cancel: "your agent's cancel", counter: "your agent's counter", accept: "your agent's accept", deliver: "your agent's delivery" };

/** The terms on a card, as rows the shared helpers worked out: someone's own words are shaded. */
function termsView(toSign) {
  const rows = toSign.rows.filter((row) => row.field || row.chosen || row.shows === "earlier");
  if (!rows.length) return null;
  return html`<dl class="terms">${rows.map((row) => {
    const [label, value] = readableRow(row, toSign.terms, toSign.units);
    return html`<div class=${row.chosen ? "chosen" : ""}><dt>${label}</dt><dd>${value}</dd></div>`;
  })}</dl>`;
}

/** Every field exactly as it's signed, one click away. */
function exactView(toSign) {
  return html`<details class="exact"><summary>${icon.chev()}Exact terms</summary><dl class="exact">
    <dt>Step</dt><dd>${toSign.operation}, version ${toSign.version}</dd>
    ${toSign.rows.map((row) => html`<dt>${row.name}</dt><dd>${row.shown}${row.ids ? html`<span class="soft"> · ${row.ids}</span>` : null}</dd>`)}
    <dt>Sign by</dt><dd>${utc(toSign.sign_by)}</dd>
  </dl></details>`;
}

/**
 * Who a deal is with, on every card: their address and whether their owner's own signature binds them
 * there. Nothing they chose to call themselves.
 */
function withWhomView(agent, other) {
  if (other.agent.startsWith("splint1g")) return html`<p class="from">With whoever holds your one-use link <span class="unverified">${icon.warn()}anyone given the link can answer it</span></p>`;
  const party = other.party;
  if (!party) return html`<p class="from"><span class="unverified">${icon.warn()}With someone this page couldn't check</span> · their IDs are under Exact terms</p>`;
  const contact = ((agent.rules && agent.rules.contacts) || []).find((one) => one.agent === party.agent && !hasHiddenCharacters(one.label));
  const who = contact ? html`${contact.label} <span class="mono">${party.address}</span>` : html`<span class="mono">${party.address}</span>`;
  if (party.owner === me.owner.id) return html`<p class="from">With ${who}, your own agent <span class="verified">${icon.shield()}verified</span></p>`;
  if (party.standIn) return html`<p class="from">With ${who} <span class="unverified">${icon.warn()}nobody has set up its controls yet</span></p>`;
  return html`<p class="from">With ${who} <span class="verified" title="The person behind it signed that it acts for them at that address.">${icon.shield()}Verified: the person behind it signed</span></p>`;
}

/** One card for each draft: several can wait on one exchange, each its own yes to its own terms. */
function decisionCard(agent, draft, beside, first) {
  // Frozen as it's drawn: the card shows this object, and signing signs this object.
  const frozen = Object.freeze(JSON.parse(JSON.stringify(draft)));
  const hidden = termsHideText(frozen.terms);
  const other = otherSide(agent, frozen.terms);
  const names = namesFor(agent);
  if (other.party && !names.has(other.agent)) names.set(other.agent, other.party.address);
  const toSign = { operation: frozen.operation, version: frozen.version, terms: frozen.terms, units: unitsOf(agent, frozen.terms.type), rows: rowsOf(frozen.terms, names, timesOf(agent, frozen.terms.type)), sign_by: frozen.latest_expiry };
  const pays = payingLines(agent, frozen, other);
  const youPay = Array.isArray(pays) && pays.some((line) => line.startsWith("You pay"));
  // A yes asks again where the person would pay, and where this page has no schema it checked for the
  // type, as then only the agent's Signet says whether anything is paid. Splint here can't tell either
  // from what the page prepared, so this is the page's to ask.
  const checked = Boolean(agent.schemas && agent.schemas.get(frozen.terms.type));
  const asksAgain = youPay || !checked;
  const verb = VERBS[frozen.operation] || "Say yes to";
  const kind = typeName(frozen.terms.type);
  const answer = (decision) => async () => {
    /** @type {string | null} */
    let typed = null;
    if (decision === "approve" && youPay) {
      typed = await confirmSheet({
        title: `${verb} this ${kind.toLowerCase()}?`,
        lead: "This agrees to the deal. Nothing is paid now.",
        rows: [[pays.find((line) => line.startsWith("You pay")) || "", `once it's done, ${nameOf(agent, other)}'s agent sends where to pay`]],
        label: "Approve",
      });
    } else if (decision === "approve" && asksAgain) {
      typed = await confirmSheet({
        title: `${verb} this ${kind.toLowerCase()}?`,
        lead: "This page couldn't check this kind's rules, so it can't say whether you'd pay. Allow it only if you know.",
        label: "Allow",
      });
    }
    await decide(agent, frozen, decision, typed);
    say(decision === "approve" ? "Allowed. Your agent goes ahead." : "Not allowed. Your agent is told.", false);
    setTimeout(refresh, 1500);
  };
  const id = beside.length ? `decision-${frozen.request}-${frozen.operation}` : `decision-${frozen.request}`;
  return html`<article class="surface req" id=${id}>
    <div class="req-id"><div class="l"><span class="type">${kind}</span><h3>${agent.label} wants to ${verb.toLowerCase()} this${askedFor(agent, frozen, other)}</h3></div></div>
    ${withWhomView(agent, other)}
    ${beside.length ? html`<p class="banner">Also waiting on this, on its own card: ${beside.map((one) => BESIDE[one] || String(one)).join(", ")}. Allow here signs only this ${frozen.operation}, and what else waits is then set aside.</p>` : null}
    ${notUsedBanner(agent, frozen.request, frozen.operation, beside, first)}
    ${pays === null ? html`<p class="banner waiting">${icon.warn()}<span>This page couldn't check this type's rules, so it can't say who pays whom. Don't allow it unless you know.</span></p>` : null}
    ${Array.isArray(pays) && pays.length ? html`<div>${pays.map((line) => html`<p class="amount">${line}.</p>`)}</div>` : null}
    ${youPay ? html`<p class="banner"><span><b>Nothing is paid now.</b> This agrees to the deal. Once it's done, ${nameOf(agent, other)}'s agent sends where to pay: a payment link, a Lightning address or a chain address the person behind it signed. You pay in your own app or wallet. Splint never holds or moves money.</span></p>` : null}
    ${termsView(toSign)}
    ${toSign.rows.some((row) => row.chosen) ? html`<p class="note">Shaded text is someone's own words, not an instruction.</p>` : null}
    ${hidden ? html`<p class="banner stopped">The text above holds hidden characters, shown as codes. You can say no, but you can't say yes to this.</p>` : null}
    ${exactView(toSign)}
    <div class="req-foot"><span class="by">Answer by ${when(frozen.latest_expiry)}</span>
      <div class="btns">
        ${btn(`no-${id}`, "Don't allow", "", answer("deny"))}
        ${btn(`yes-${id}`, youPay ? html`${icon.lock()}Approve` : asksAgain ? html`${icon.lock()}Allow` : "Allow", "primary", answer("approve"), { disabled: hidden })}
      </div>
    </div>
  </article>`;
}

/** Said in fixed words on the card it's about, as a lying Signet could write anything in it. */
function notUsedBanner(agent, request, operation, beside, first) {
  const said = notUsedOf(agent).find((one) => one.request === request);
  if (!said) return null;
  if (said.operation !== operation && !(first && !beside.includes(said.operation))) return null;
  const answer = said.decision === "deny" ? "no" : "yes";
  const why = {
    changed: `Your last ${answer} to this wasn't used: what you were shown had changed before it reached your agent, so nothing went. This is what's waiting now.`,
    not_now: `Your last ${answer} to this wasn't used: your agent's Signet couldn't take it just then, so nothing went. It's still waiting, and you can answer again.`,
  };
  return html`<p class="banner stopped">${Object.hasOwn(why, said.why) ? why[said.why] : `Your last ${answer} to this wasn't used: your agent's Signet refused it, so nothing went. It's still waiting.`}</p>`;
}

/**
 * Someone held, said as what it is: someone writing in, an invite either way, the person's own agent
 * asking to write out, which a fooled agent can be made to, or a host naming someone else at an
 * address the person knows, which is a warning with nothing to let in.
 */
function heldCard(agent, held) {
  const who = held.address ? withHiddenShown(held.address) : "Someone who gave no address";
  const letInButton = (label) => agent.rules && held.address ? btn(`in-${held.sender}`, label, "primary", async () => {
    await letIn(agent, held);
    say("They're one of your contacts now.", false);
    await refresh();
  }) : null;
  const block = agent.rules && held.address && held.kind !== "asked" ? btn(`block-${held.sender}`, "Block", "danger", async () => {
    await keepOut(agent, held, "blocked");
    say("Blocked.", false);
    await refresh();
  }) : null;
  const card = (tag, title, lead, acts) => html`<article class="surface req" id=${`held-${held.sender}`}>
    <div class="req-id"><div class="l"><span class="type">${tag}</span><h3>${title}</h3></div></div>
    ${lead.map((words) => html`<p class="from">${words}</p>`)}
    ${acts ? html`<div class="req-foot"><span class="by">Waiting since ${short(held.created_at)}</span><div class="btns">${acts}</div></div>` : null}
  </article>`;
  if (held.kind === "disagreed") {
    return card("Warning", `The host of ${who} names someone else there`, ["Its host gave another ID than the one you or your agent already knew there, so your agent won't take them for that contact. Either the host is lying or the address changed hands. Check with them another way."], null);
  }
  if (held.kind === "asked") {
    return card("Contact", `${agent.label} asks to write to ${who}`, ["This is only your agent's word, and it may have been fooled into asking. Allow it only if you know them."], letInButton("Allow"));
  }
  if (held.kind === "invite" && invitedByUs(agent, held)) {
    return card("Contact", `${who} accepted ${agent.label}'s invite`, ["Let them in, and they're one of your contacts."], html`${block}${letInButton("Let them in")}`);
  }
  if (held.kind === "invite") {
    return card("Contact", `${who} invites ${agent.label} to be contacts`, ["Nothing they wrote is shown here."], html`${block}${letInButton("Let them in")}`);
  }
  return card("New", `${who} wants to reach your agent`, [`${agent.label} hasn't seen anything they sent.`], html`${block}${letInButton("Let them in")}`);
}

const CHANGE_KINDS = {
  bound: "someone set up its controls",
  owner: "it acts for someone new",
  key: "its key changed, as after a recovery",
  signet: "its Signet changed",
  host: "it moved to another host",
  revocation: "the person behind it stopped it",
  declared: "the person behind it declared a change",
};
const STANDINGS = {
  ask: "You asked to say yes to changes like this. Until you do, their messages wait, and your agent can't write to them.",
  hold: "The person behind it stopped it. Until you say yes, their messages wait, and your agent can't write to them.",
  waiting_for_history: "Your agent is waiting for the rest of their history before it can say what changed.",
  rewritten: "They showed two different histories, so one was rewritten. Your agent holds them whatever your settings say.",
  continue: "It carries on by your settings, as the same person stands behind it. This is only to tell you.",
};
// A new owner that carried on isn't the same owner standing behind it.
const NEW_OWNER_CARRIED_ON = "It carries on by your settings, for the new person behind it. This is only to tell you.";

/** A contact that changed, in the page's own words for each kind, with a yes signed for the exact head shown. */
function changeCard(agent, notice) {
  const names = namesFor(agent);
  const who = names.get(notice.contact) || (notice.address ? withHiddenShown(String(notice.address)) : "A contact");
  const kinds = [...new Set((Array.isArray(notice.since_accepted) ? notice.since_accepted : []).map((change) => change && change.kind))]
    .filter((kind) => typeof kind === "string" && Object.hasOwn(CHANGE_KINDS, kind)).map((kind) => CHANGE_KINDS[kind]);
  const head = String(notice.head || "");
  const yes = (label) => btn(`change-${notice.contact}`, label, "primary", async () => {
    await acceptChange(agent, notice, head);
    say("Done. Your agent goes by it once its Signet hears.", false);
    setTimeout(refresh, 1500);
  });
  const act = notice.standing === "ask" || notice.standing === "hold" ? yes("Allow")
    : notice.standing === "rewritten" ? yes("Stay with what you've seen")
      : notice.standing === "continue" ? yes("Got it") : null;
  return html`<article class="surface req" id=${`change-${notice.contact}`}>
    <div class="req-id"><div class="l"><span class="type">Changed</span><h3>${who} changed</h3></div></div>
    ${kinds.length ? html`<p class="from">What changed: ${kinds.join("; ")}.</p>` : null}
    <p class="from">${notice.standing === "continue" && kinds.includes(CHANGE_KINDS.owner) ? NEW_OWNER_CARRIED_ON : Object.hasOwn(STANDINGS, notice.standing) ? STANDINGS[notice.standing] : "Your agent holds them for now."}</p>
    ${act ? html`<div class="req-foot"><span></span><div class="btns">${act}</div></div>` : null}
  </article>`;
}

// ---------- An agent's asks, approved on this computer ----------

/** Whether a change lets more in, which the page warns about in its own words. */
function risky(changes) {
  return changes.some((change) => (change.change === "level" && change.to === "full_auto")
    || (change.change === "reach" && change.to !== "contacts") || (change.change === "quoted_prices" && change.to === "within_limits")
    || (change.change === "writes" && change.to === "replies") || (change.change === "contact" && change.text));
}

/** What these asks hold, as a person reads it: a held step is a step to send, not a change to a rule. */
function nounFor(asks) {
  const changes = asks.flatMap((ask) => (Array.isArray(ask.changes) ? ask.changes : []));
  const steps = changes.length > 0 && changes.every((change) => change.change === "step");
  return changes.length === 1 ? (steps ? "this step" : "this change") : (steps ? "these steps" : "these changes");
}

function controlsAsk(asks) {
  return asks.some((ask) => (Array.isArray(ask.changes) ? ask.changes : []).some((change) => change.change === "controls"));
}

/** The words for one ask, in the fixed words its prompt names it by, which the owner key wrote. */
function askLines(ask) {
  return [
    ...(Array.isArray(ask.said) ? ask.said : []),
    ...(ask.kinds || []).flatMap((kind) => (kind.lines || [])),
  ].map((line) => String(line));
}

/**
 * An ask's lines, less the one setting the agent up, which the title says already ("Lia wants to act
 * for you", with its address). The owner key writes one line for each change, in order, so the line
 * left out is exactly that change's; where they don't line up, every line shows.
 */
function linesBeyondJoining(ask) {
  const said = Array.isArray(ask.said) ? ask.said.map(String) : [];
  const changes = Array.isArray(ask.changes) ? ask.changes : [];
  const kept = said.length === changes.length ? said.filter((_, index) => !(changes[index] && changes[index].change === "controls")) : said;
  return [...kept, ...(ask.kinds || []).flatMap((kind) => (kind.lines || [])).map(String)];
}

/**
 * How an approval reads. It names an agent only when every ask in it is that agent's, and leaves out the
 * line setting that agent up only then, as the title says it. Asks from more than one agent, which
 * Splint here can group into one approval, name no one in the title and list every line, each with its
 * agent's address, so one Approve never sets up an agent the screen doesn't show.
 */
function approvalShown(asks) {
  const addresses = [...new Set(asks.map((ask) => String(ask.address)))];
  const one = addresses.length === 1;
  const known = one ? agentsShown().find((agent) => agent.address === addresses[0]) : null;
  const name = !one ? "" : known ? known.label : capital(addressParts(addresses[0]).name);
  const joining = controlsAsk(asks);
  return {
    one,
    name,
    address: one ? addresses[0] : "",
    joining,
    title: !one ? `${addresses.length} agents ask for your approval` : joining ? `${name} wants to act for you` : `${name} asks you for ${nounFor(asks)}`,
    lines: one ? asks.flatMap(linesBeyondJoining) : asks.flatMap(askLines),
  };
}

/** Rows for lines, or nothing where there are none. */
function linesView(lines) {
  return lines.length ? html`<div class="surface list">${lines.map((line) => html`<div class="row"><div class="grow"><span class="t">${line}</span></div></div>`)}</div>` : null;
}

/**
 * What to check before approving an agent's ask. Agents can join Splint on their own, so whether the
 * person asked isn't the test: whether it's their agent is, and its chat shows it joining at the address
 * shown. A link can come from any website, so one by link has to have come from the agent itself.
 */
function checkFirst(name, joining, fromLink) {
  const words = joining
    ? (name ? `Approve only if ${name}'s chat shows it joining Splint as this address.` : "Approve only if each agent's chat shows it joining Splint at the address shown.")
    : fromLink
      ? (name ? `Approve only if ${name} sent you this link in its chat.` : "Approve only if each agent sent you its link in its chat.")
      : "";
  return words ? html`<p class="banner waiting">${icon.warn()}<span>${words}</span></p>` : null;
}

/**
 * One approval's worth of asks, as Splint here groups them: each named in fixed words, with any words
 * an agent wrote apart and marked, and one Approve that signs exactly those shown with that code.
 */
function askCard(approval, standalone) {
  const asks = approval.asks;
  const shown = approvalShown(asks);
  const written = asks.flatMap((ask) => (Array.isArray(ask.written) ? ask.written : []));
  return html`<article class="surface req" id=${`ask-${asks[0].id}`}>
    <div class="req-id"><div class="l"><span class="type">Request</span><h3>${shown.title}</h3></div>${standalone ? null : null}</div>
    ${shown.one ? html`<p class="from"><span class="mono">${shown.address}</span></p>` : null}
    ${shown.lines.length ? html`<ul class="changes">${shown.lines.map((line) => html`<li class="row" style="padding:4px 0;min-height:0">${line}</li>`)}</ul>` : null}
    ${checkFirst(shown.name, shown.joining, asks.some((ask) => ask.from_link))}
    ${written.length ? html`<p class="words">${written.join(", ")} <span class="soft">· the agent's words, not Splint's</span></p>` : null}
    ${asks.some((ask) => ask.lets_more_in) ? html`<p class="banner waiting">${icon.warn()}<span>This lets more in than before. Approve only if you want that.</span></p>` : null}
    <div class="req-foot"><span class="by">${asks.length > 1 ? `${asks.length} asks, one approval` : ""}</span>
      <div class="btns">${btn(`approve-${asks[0].id}`, html`${icon.lock()}Approve`, "primary", () => approveAsks(approval))}</div>
    </div>
  </article>`;
}

/** Approves exactly the asks shown, with the code shown, after the passphrase or the chip's prompt. */
async function approveAsks(approval) {
  const asks = approval.asks;
  const typed = await confirmSheet({
    title: approvalShown(asks).one && controlsAsk(asks) ? "Let this agent act for you?" : `Approve ${nounFor(asks)}?`,
    lead: "Approving signs exactly what's listed, with your key on this computer. It doesn't log you in to any website.",
    rows: asks.flatMap(askLines).map((line) => [line, ""]),
    label: "Approve",
  });
  const done = await computerCall("/local/approve", { passphrase: typed, ids: asks.map((ask) => ask.id), code: approval.code });
  const passOn = Array.isArray(done.pass_on) ? done.pass_on : [];
  ui.linked = null;
  await loadAsks();
  if (passOn.length) {
    ui.sheet = { kind: "confirm", title: "Give your agent this line", lead: `${passOn[0].address}'s host didn't keep your answer, so send it this, all of it:`, rows: passOn.map((one) => [`splint finish ${one.answer}`, one.address]), label: "Done", typedHere: false, done: () => { ui.sheet = null; draw(true); }, cancel: () => { ui.sheet = null; draw(true); } };
  }
  say(done.approved ? "Approved. Your agent hears it from its host." : "Nothing was approved.", !done.approved);
  if (ui.view === "request" || ui.view === "link") go("home");
  await refresh().catch(() => null);
}

/** The asks waiting on this computer, in the approvals they go in. */
async function loadAsks() {
  try {
    const waiting = await computerCall("/local/asks");
    ui.approvals = [{ asks: waiting.asks || [], code: waiting.code || null }, ...(waiting.later || [])].filter((one) => one.asks && one.asks.length);
    ui.promptsByItself = Boolean(waiting.prompts_by_itself);
  } catch {
    // Kept as they were.
  }
}

function requestsView() {
  return html`
    <div class="head"><h1>Requests</h1><p>Each has its own page, so a link always opens the one it names.</p></div>
    <div class="section">${ui.approvals.length ? html`<div class="surface list">${ui.approvals.map((approval) => html`<a class="row" href=${`/requests/${approval.asks[0].id}`} onClick=${(/** @type {any} */ event) => { event.preventDefault(); go("request", { request: approval.asks[0].id }); }}>
      <div class="grow"><span class="t">${approvalShown(approval.asks).title}</span><span class="d mono">${approvalShown(approval.asks).address}</span></div>${icon.chev()}</a>`)}</div>` : emptyBox("Nothing waiting", "When an agent asks you for something, it shows here.")}</div>`;
}

function requestView() {
  const approval = ui.approvals.find((one) => one.asks.some((ask) => ask.id === ui.request));
  return html`<div class="section">
    <a class="textlink" style="justify-self:start" href="/owner" onClick=${(/** @type {any} */ event) => { event.preventDefault(); go("home"); }}>Back to what needs you</a>
    ${approval ? askCard(approval, true) : emptyBox("That request isn't waiting", "It was answered, or it ended. An agent asks again for a fresh one.")}
  </div>`;
}

// ---------- One agent ----------

function agentView() {
  const agent = agentById(ui.agent);
  if (!agent) return homeView();
  const [dot, words] = standingOf(agent);
  const host = addressParts(agent.address).domain;
  const count = countOf(agent);
  const tab = (id, label, n) => html`<button type="button" role="tab" aria-selected=${String(ui.tab === id)} onClick=${() => go("agent", { agent: agent.agent, tab: id })}>${label}${n ? html`<span class="count">${n}</span>` : null}</button>`;
  return html`
    <div class="agent-top">
      <div class="who"><h1>${agent.label}</h1><span class=${`status ${dot}`}><span class=${`dot ${dot}`}></span>${words}</span></div>
      <span class="chip"><span class="mono">${agent.address}</span></span>
    </div>
    <div class="facts">
      ${agent.beside === true ? html`<span class="chip icon">${icon.laptop()}<span>This computer</span></span>` : agent.beside === false ? html`<span class="chip icon">${icon.cloud()}<span>Elsewhere</span></span>` : null}
      <span class="chip icon">${icon.server()}<span>${host}</span></span>
      ${agent.heardAt ? html`<span class="chip icon">${icon.clock()}<span>Heard ${short(agent.heardAt)}</span></span>` : null}
      ${agent.behind ? html`<span class="chip waiting" title=${BEHIND_WORDS}>Older update from its host</span>` : null}
    </div>
    ${statsView(agent)}
    <nav class="tabs" role="tablist" aria-label=${agent.label}>
      ${tab("now", "Now", count)}${tab("history", "History")}${tab("contacts", "Contacts")}${tab("permissions", "Permissions")}
    </nav>
    ${ui.tab === "history" ? historyTab(agent) : ui.tab === "contacts" ? contactsTab(agent) : ui.tab === "permissions" ? permissionsTab(agent) : nowTab(agent)}`;
}

/** Today's numbers, from the counts the agent's Signet signed in its view. */
function statsView(agent) {
  const usage = agent.view && Array.isArray(agent.view.usage) ? agent.view.usage : null;
  if (!usage) return null;
  const sum = (key) => usage.reduce((total, line) => total + (Number.isSafeInteger(line[key]) ? line[key] : 0), 0);
  const received = sum("arrivals_today");
  const usual = sum("usual_per_day");
  const sent = sum("texts_to") + sum("new_requests_to");
  const busiest = usage[0];
  return html`<div class="surface stats" aria-label="Today">
    <div class="stat"><span class="k">Received today</span><span class="n">${received}</span>${usual && received > usual * 1.5 ? html`<span class="vs up">${Math.round((received / usual) * 10) / 10}× a usual day</span>` : html`<span class="vs">usual ${usual}</span>`}</div>
    <div class="stat"><span class="k">Sent today</span><span class="n">${sent}</span><span class="vs">notes and requests</span></div>
    <div class="stat"><span class="k">Busiest</span><span class="n" style="font-size:15px;padding-top:4px">${busiest ? withHiddenShown(String(busiest.address)) : "Nobody yet"}</span><span class="vs">${busiest ? `${busiest.arrivals_today} today` : ""}</span></div>
  </div>`;
}

function nowTab(agent) {
  const needs = needsOf(agent);
  const paused = Boolean(agent.rules && agent.rules.paused);
  return html`
    ${paused ? html`<div class="section"><div class="surface callout"><div class="grow"><p class="t">${agent.label} is paused</p><p class="d">It sends nothing on Splint, and is shown nothing, until you turn it back on.</p></div>${btn("resume", "Turn it back on", "sm primary", () => setPaused(agent, false))}</div></div>` : null}
    ${agent.status === "mine" && !agent.view && me.sealing ? html`<div class="section"><p class="banner">${agent.label} hasn't left you an update yet. It does every few minutes while its Signet runs.</p></div>` : null}
    <div class="section">
      <div class="section-head"><h2>Needs you</h2></div>
      ${needs.length ? needs.map((one) => html`<div key=${one.key}>${one.draw()}</div>`) : emptyBox("Nothing needs you", `${agent.label} carries on within its permissions.`)}
    </div>`;
}

function historyTab(agent) {
  const refused = (agent.refused || []).slice(0, 20);
  const usage = agent.view && Array.isArray(agent.view.usage) ? agent.view.usage : [];
  const told = (agent.view && agent.view.changes && Array.isArray(agent.view.changes.changes) ? agent.view.changes.changes : []).filter((notice) => notice && notice.standing === "continue");
  return html`
    ${usage.length ? html`<div class="section">
      <div class="section-head"><h2>Who kept ${agent.label} busy today</h2><span class="aside">Your limits cap each contact's day</span></div>
      ${usage.filter((line) => line.busier_than_usual).map((line) => html`<p class="banner waiting">${icon.warn()}<span>${withHiddenShown(String(line.address))} sent ${agent.label} ${line.arrivals_today} today, where a usual day is about ${line.usual_per_day}.</span></p>`)}
      <div class="surface table-wrap"><table class="tbl">
        <thead><tr><th>Contact</th><th>Today</th><th>Usual</th><th>Notes in / out</th><th>Requests in / out</th></tr></thead>
        <tbody>${usage.map((line) => html`<tr><td class="mono">${withHiddenShown(String(line.address))}</td><td class=${line.busier_than_usual ? "hot" : ""}>${line.arrivals_today}</td><td>${line.usual_per_day}</td><td>${line.texts_from} / ${line.texts_to}</td><td>${line.new_requests_from} / ${line.new_requests_to}</td></tr>`)}</tbody>
      </table></div>
    </div>` : null}
    <div class="section">
      <div class="section-head"><h2>Stopped by Splint</h2><span class="aside">Nothing anyone wrote is kept</span></div>
      ${refused.length ? html`<div class="surface list">${refused.map((line) => {
        const way = String(line.way || "");
        const said = Object.hasOwn(REFUSED_WAYS, way) ? REFUSED_WAYS[way] : "had something refused";
        return html`<div class="row"><span class="dot stopped"></span><div class="grow"><span class="t">${agent.label} ${said}</span>${typeof line.at === "number" ? html`<span class="d">${short(line.at)}</span>` : null}</div></div>`;
      })}</div>` : emptyBox("Nothing stopped lately", "When your rules stop something, it shows here.")}
    </div>
    ${told.length ? html`<div class="section"><div class="section-head"><h2>What changed</h2></div>${told.map((notice) => changeCard(agent, notice))}</div>` : null}`;
}

function contactsTab(agent) {
  const contacts = ((agent.rules && agent.rules.contacts) || []).filter((contact) => !contact.address.endsWith("~blocked.invalid"));
  const added = ((agent.view && agent.view.held) || []).filter((held) => held.kind === "agreed" && !settledBy(agent.rules, held));
  return html`
    ${added.length ? html`<div class="section">
      <div class="section-head"><h2>Added by ${agent.label}</h2><span class="aside">Not approved by you yet</span></div>
      <p class="note">They can talk with ${agent.label}. A kind of request with money is used with them only once you approve them.</p>
      <div class="surface list">${added.map((held) => html`<div class="row" id=${`added-${held.sender}`}>
        <div class="grow"><span class="t mono">${held.address ? withHiddenShown(held.address) : "Someone who gave no address"}</span></div>
        ${held.address ? html`<div class="btns">
          ${btn(`added-block-${held.sender}`, "Block", "sm danger", async () => { await keepOut(agent, held, "blocked"); say("Blocked.", false); await refresh(); })}
          ${btn(`added-out-${held.sender}`, "Remove", "sm", async () => { await keepOut(agent, held, "allowed"); say("Removed.", false); await refresh(); })}
          ${btn(`added-in-${held.sender}`, "Approve", "sm primary", async () => { await letIn(agent, held); say("Approved. They're one of your contacts.", false); await refresh(); })}
        </div>` : null}
      </div>`)}</div>
    </div>` : null}
    <div class="section" id="contacts">
      <div class="section-head"><h2>Contacts</h2><span class="aside">${contacts.length}</span></div>
      ${contacts.length ? html`<div class="surface list">${contacts.map((contact) => html`<div class="row contact">
        <div class="grow"><span class="t">${withHiddenShown(contact.label)}</span><span class="d mono">${withHiddenShown(contact.address)}</span></div>
        ${contact.status === "blocked" ? html`<span class="chip stopped">Blocked</span>` : isRemoval(contact) ? html`<span class="chip">Removed</span>` : contact.agree_types === false ? html`<span class="chip">Your kinds only</span>` : null}
        <button type="button" class="i-btn" aria-label=${`Options for ${contact.label}`} onClick=${() => { ui.sheet = { kind: "contact", agent: agent.agent, contact: contact.agent }; draw(true); }}>${icon.dots()}</button>
      </div>`)}</div>` : emptyBox("No contacts yet", `Ask ${agent.label} to invite someone, or share its address.`)}
    </div>
    <div class="section">
      <div class="section-head"><h2>Its address</h2><span class="aside">Not secret</span></div>
      <div class="surface list"><div class="row"><div class="grow"><span class="t mono">${agent.address}</span><span class="d">Share it with anyone ${agent.label} should reach.</span></div>
        ${btn(`copy-${agent.agent}`, "Copy", "sm", async () => { await navigator.clipboard.writeText(agent.address); say("Address copied.", false); })}
      </div></div>
    </div>`;
}

function contactBody(sheet) {
  const agent = agentById(sheet.agent);
  const contact = agent && ((agent.rules && agent.rules.contacts) || []).find((one) => one.agent === sheet.contact);
  if (!agent || !contact) return html`<h2>That contact changed</h2><button type="button" class="btn block" onClick=${() => { ui.sheet = null; draw(true); }}>Close</button>`;
  const close = () => { ui.sheet = null; };
  const agrees = contact.agree_types !== false;
  const allowed = contact.status === "allowed" && !isRemoval(contact);
  return html`
    <h2>${withHiddenShown(contact.label)}</h2>
    <p class="lead mono">${withHiddenShown(contact.address)}</p>
    ${allowed ? html`<div class="surface list"><div class="row">
      <div class="grow"><span class="t">Agrees new kinds of request with ${agent.label}</span><span class="d">Off: they use only kinds you named, and those already agreed stop.</span></div>
      <input class="switch" type="checkbox" role="switch" aria-label="Agrees new kinds of request" checked=${agrees} disabled=${Boolean(ui.busy)} onChange=${press(`agree-${contact.agent}`, async () => {
        await signRules(agent, (draft) => { const named = draft.contacts.find((one) => one.agent === contact.agent); if (named) named.agree_types = !agrees; });
        say("Saved.", false);
      })} />
    </div></div>` : null}
    <div class="surface list">
      ${contact.status === "blocked" ? html`<button type="button" class="row act" onClick=${press(`unblock-${contact.agent}`, async () => {
        await signRules(agent, (draft) => { draft.contacts = draft.contacts.filter((one) => one.agent !== contact.agent); });
        close();
        say("Unblocked. They're like anyone else now.", false);
      })}><div class="grow"><span class="t">Unblock</span></div></button>` : html`
        ${allowed ? html`<button type="button" class="row" onClick=${press(`remove-${contact.agent}`, async () => { await keepOut(agent, { sender: contact.agent, address: contact.address }, "allowed"); close(); say("Removed.", false); })}><div class="grow"><span class="t">Remove contact</span></div></button>` : null}
        <button type="button" class="row danger" onClick=${press(`blk-${contact.agent}`, async () => { await keepOut(agent, { sender: contact.agent, address: contact.address }, "blocked"); close(); say("Blocked.", false); })}><div class="grow"><span class="t">Block</span></div></button>`}
    </div>
    <button type="button" class="btn block" onClick=${() => { ui.sheet = null; draw(true); }}>Done</button>`;
}

// ---------- Permissions, which save as they change ----------

const LEVEL_WORDS = {
  ask_me: ["Ask me first", "Nothing that commits you goes out until you say yes."],
  auto_within_limits: ["Act within limits", "It goes ahead by itself within the day's limit. Anything you'd pay always waits for you."],
  full_auto: ["Full auto, set outside this page", `No caps on what it offers, up to ${FULL_AUTO_PER_DAY.toLocaleString("en-US")} steps and messages a day. Anything you'd pay still waits for you.`],
};

const INFO = {
  level: "These are limits, not instructions. Your agent's model decides what to do, and Splint's code stops it going past what you set here.",
  quotes: "A price your agent quotes, where you'd be the one paid. Anything you'd pay always waits for you, whatever you choose here.",
  agreed: "When your agent and another agree to be contacts, they can talk and arrange things at once, up to 100 new ones a day. A kind of request with money is used with them only once you approve them.",
  sealed: "Sealed: only your agent and the one it's talking to can read what's said. Unsealed: hosts can read it too, as a business might need, so they can screen it for you.",
  paid: "Splint never holds or moves money. Once a deal that pays you is done, your agent can ask to be paid at one of these, with the amount from the deal, and people pay you in their own app or wallet. A payment by Lightning or on a chain can't be reversed.",
};

function permissionsTab(agent) {
  const rules = agent.rules;
  if (!rules) return emptyBox("These settings couldn't be checked", "So the page won't change them. They show once its host answers with rules you signed.");
  const level = rules.permissions.level;
  const levels = level === "full_auto" ? ["ask_me", "auto_within_limits", "full_auto"] : ["ask_me", "auto_within_limits"];
  const quoted = rules.permissions.quoted_prices || "wait";
  const open = rules.reach.inbound.from === "open";
  const agreed = Boolean(rules.reach && rules.reach.agreed);
  const sealed = rules.sealing !== "unsealed";
  const choice = (key, value, title, detail, chosen) => html`<button type="button" class="row" role="radio" aria-checked=${String(chosen)} id=${`${key}-${value}-${agent.agent}`} value=${value} disabled=${Boolean(ui.busy)} onClick=${press(`${key}-${value}`, async () => { if (!chosen) await changeSetting(agent, key, value); })}>
    <span class="radio"></span><div class="grow"><span class="t">${title}</span>${detail ? html`<span class="d">${detail}</span>` : null}</div></button>`;
  const toggle = (key, title, on, value) => html`<div class="row"><div class="grow"><span class="t">${title}</span></div>${infoButton(key, title)}
    <input class="switch" type="checkbox" role="switch" aria-label=${title} id=${`${key}-${agent.agent}`} checked=${on} disabled=${Boolean(ui.busy)} onChange=${press(`${key}-switch`, () => changeSetting(agent, key, value(!on)))} /></div>
    ${ui.open.has(key) ? html`<p class="more">${INFO[key]}</p>` : null}`;
  return html`<div id=${`settings-${agent.agent}`}>
    ${RISKY.filter((one) => one.on(rules)).map((one) => html`<p class="banner waiting" style="margin-bottom:10px">${icon.warn()}<span>${one.words}</span></p>`)}
    <div class="section">
      <div class="section-head"><h2>What ${agent.label} can do alone</h2>${infoButton("level", "limits")}</div>
      ${ui.open.has("level") ? html`<p class="note">${INFO.level} ${limitsShort(rules)}</p>` : null}
      <div class="surface list" role="radiogroup" aria-label=${`What ${agent.label} can do alone`}>
        ${levels.map((one) => choice("level", one, LEVEL_WORDS[one][0], LEVEL_WORDS[one][1], level === one))}
        ${toggle("quotes", "Ask me before quoting a price", quoted === "wait", (on) => (on ? "wait" : "within_limits"))}
      </div>
    </div>
    <div class="section">
      <div class="section-head"><h2>Who can reach ${agent.label}</h2></div>
      <div class="surface list" role="radiogroup" aria-label=${`Who can reach ${agent.label}`}>
        ${choice("reach", "contacts", "Only contacts", "Anyone else waits for you.", !open)}
        ${choice("reach", "open", "Anyone", "Useful for a business.", open)}
        ${toggle("agreed", "Contacts it adds can message it", agreed, (on) => on)}
      </div>
    </div>
    <div class="section">
      <div class="section-head"><h2>Privacy</h2></div>
      <div class="surface list">${toggle("sealed", "Seal messages", sealed, (on) => (on ? "sealed" : "unsealed"))}</div>
    </div>
    <div class="section" id="getting-paid">
      <div class="section-head"><h2>Getting paid</h2>${infoButton("paid", "getting paid")}</div>
      ${ui.open.has("paid") ? html`<p class="note">${INFO.paid}</p>` : null}
      <div class="surface list"><button type="button" class="row act" id="where-paid-open" onClick=${() => { ui.sheet = { kind: "where-paid" }; draw(true); }}><div class="grow"><span class="t">Say where you get paid</span><span class="d">A payment link, a Lightning address, or an address on a chain. For all your agents.</span></div><span class="soft">${icon.lock()}</span></button></div>
    </div>
    <div class="section">
      <div class="surface list">
        <button type="button" class=${`row ${rules.paused ? "act" : "danger"}`} id=${`off-switch-${agent.agent}`} disabled=${Boolean(ui.busy)} onClick=${press("pause", () => setPaused(agent, !rules.paused))}>
          <div class="grow"><span class="t">${rules.paused ? `Turn ${agent.label} back on` : `Pause ${agent.label}`}</span><span class="d">${rules.paused ? "It picks up within your settings." : "If you think it's been fooled or taken over: its host and its Signet stop everything it sends, at once."}</span></div>
        </button>
      </div>
    </div>
  </div>`;
}

/** The day's caps, in a few words. */
function limitsShort(rules) {
  const actions = rules.permissions.actions_per_day;
  return Number.isSafeInteger(actions) ? `It takes at most ${actions} steps and messages a day, and agrees to at most ${Math.ceil(actions / YESES_PART)} things a day by itself.` : "";
}

/**
 * One setting changed, signed at once from the rules in force. Taking out contacts the agent added by
 * itself, as Ask me first or turning those off does, asks first whether to keep them.
 */
async function changeSetting(agent, key, value) {
  const rules = agent.rules;
  const level = key === "level" ? value : rules.permissions.level;
  const agreedOn = key === "agreed" ? value : Boolean(rules.reach.agreed);
  const going = addedTakenOut(agent, level, agreedOn);
  // Asked only about contacts it can name. Before the agent's first view it can't see any, which for
  // a new agent is nearly always none, so it saves and says where any would be.
  const unseen = !agent.view && takesAddedOut(agent, level, agreedOn);
  let kept = [];
  if (going.length) {
    const choice = await keepAddedChoice(agent, going, false);
    kept = choice === "keep" ? await keptAsOwn(going) : [];
  }
  const agreedBefore = rules.reach.agreed;
  const notRenewed = await signRules(agent, (draft) => {
    if (key === "level") draft.permissions.level = value;
    if (key === "quotes") {
      // Left out for the default, as Splint leaves it out, so rules that don't change it read alike.
      if (value === "within_limits") draft.permissions.quoted_prices = "within_limits";
      else delete draft.permissions.quoted_prices;
    }
    if (key === "sealed") draft.sealing = value;
    if (key === "reach") {
      draft.reach.inbound = value === "open"
        ? { ...draft.reach.inbound, from: "open", types: draft.reach.inbound.types.length ? draft.reach.inbound.types : openTypes(agent) }
        : { from: "contacts", filter: { owners: [], hosts: [], past: false }, types: [], text: false, strangers: draft.reach.inbound.strangers };
    }
    if (key === "agreed") {
      if (value) draft.reach.agreed = draft.reach.agreed || { ...AGREED };
      else delete draft.reach.agreed;
    }
    for (const held of kept) {
      draft.contacts.push({ agent: held.sender, address: held.address, label: addressParts(held.address).name, status: "allowed", types: [...agreedBefore.types], text: agreedBefore.text, agree_types: agreedBefore.agree_types !== false, pinned_by: "invite" });
    }
  }, true);
  const who = (list) => list.map((held) => withHiddenShown(held.address)).join(", ");
  const contacts = !going.length ? (unseen ? ` Any contacts ${agent.label} added by itself are out too, to add back under Contacts.` : "") : kept.length ? ` ${who(kept)} ${kept.length === 1 ? "is your own contact" : "are your own contacts"} now.` : ` ${who(going)} ${going.length === 1 ? "was" : "were"} taken out. You can add them back under Contacts.`;
  say(`Saved.${contacts}${notRenewed.length ? ` ${NOT_RENEWED_WORDS}` : ""}`, false, Boolean(contacts || notRenewed.length));
}

/** Whether to keep the contacts the agent added, which a change would take out. */
function keepAddedChoice(agent, going, unseen) {
  return new Promise((resolve, reject) => {
    ui.sheet = { kind: "keep-added", agent, going, unseen, done: (choice) => { ui.sheet = null; draw(true); resolve(choice); }, cancel: () => { ui.sheet = null; draw(true); reject(CANCELLED); } };
    draw(true);
  });
}

function keepAddedBody(sheet) {
  if (sheet.unseen) {
    return html`<h2>Contacts ${sheet.agent.label} added</h2>
      <p class="lead">This takes out any contacts ${sheet.agent.label} added by itself. This computer can't see which yet; they'll show under Contacts afterwards, to add back.</p>
      <div class="btns" style="justify-content:flex-end"><button type="button" class="btn ghost" onClick=${() => sheet.cancel()}>Cancel</button><button type="button" class="btn primary" onClick=${() => sheet.done("drop")}>Go on</button></div>`;
  }
  return html`<h2>Keep the contacts ${sheet.agent.label} added?</h2>
    <p class="lead">This takes out ${sheet.going.map((held) => withHiddenShown(held.address)).join(", ")}, unless you keep them.</p>
    <div class="surface list">
      <button type="button" class="row" onClick=${() => sheet.done("keep")}><div class="grow"><span class="t">Keep them</span><span class="d">They become your own contacts, as if you'd added them.</span></div></button>
      <button type="button" class="row" onClick=${() => sheet.done("drop")}><div class="grow"><span class="t">Take them out</span><span class="d">You can add any of them back under Contacts.</span></div></button>
    </div>
    <button type="button" class="btn ghost block" onClick=${() => sheet.cancel()}>Cancel</button>`;
}

async function setPaused(agent, on) {
  await signRules(agent, (draft) => { draft.paused = on; });
  say(on ? `${agent.label} is paused. It sends nothing, and is shown nothing, until you turn it back on.` : `${agent.label} is back on, within your settings.`, false);
}

function wherePaidBody() {
  const agents = agentsShown().filter((agent) => agent.status === "mine");
  return html`
    <h2>Where you get paid</h2>
    <p class="lead">Up to 4 places, one a line. Signing them replaces the ones before, and people you deal with are told they're new.</p>
    <textarea class="input" id="where-paid" rows="4" spellcheck="false" autocomplete="off" placeholder=${"https://pay.example.com/you\nyou@wallet.example\nonchain:eip155:8453:0x…:usdc"} value=${me.paidDraft} onInput=${(/** @type {any} */ event) => { me.paidDraft = event.target.value; }}></textarea>
    <p class="hint">${INFO.paid}</p>
    ${chipHere() ? null : field("paid-passphrase", "Passphrase", passwordInput("paid-passphrase"))}
    <div class="btns" style="justify-content:flex-end" id="getting-paid-acts">
      <button type="button" class="btn ghost" onClick=${() => { ui.sheet = null; draw(true); }}>Cancel</button>
      ${btn("where-paid", html`${icon.lock()}Sign where you get paid`, "primary", async () => {
        if (!agents.length) throw new Error("Once an agent has picked up your controls, you can say where you get paid.");
        await signWherePaid(agents, me.paidDraft, chipHere() ? null : takeTyped("paid-passphrase"));
        ui.sheet = null;
      })}
    </div>`;
}

// ---------- You ----------

function accountBody() {
  const known = knownAs(me.owner.id);
  const viewing = viewingHere();
  return html`<div id="account-panel">
    <h2>You</h2>
    ${field("my-name", "Your name", html`<input class="input" id="my-name" autocomplete="name" placeholder="Only shown on this computer" value=${(known && known.name) || ""} onChange=${(/** @type {any} */ event) => { remember({ name: event.target.value.trim().slice(0, 60) }); draw(true); }} />`)}
    <div class="surface list">
      <div class="row"><div class="grow"><span class="t">Splint ID</span><span class="d">Who you are to every agent. It never changes.</span></div>${idChip(me.owner.id, "your Splint ID")}</div>
      <div class="row"><div class="grow"><span class="t">Approve with</span></div><span class="v">${chipHere() ? "Touch ID or your password" : "Your passphrase"}</span></div>
      <div class="row"><div class="grow"><span class="t">Recovery code</span></div>${me.owner.recoveryLater ? btn("recovery-sheet", "Set up", "sm", async () => { ui.sheet = null; await setRecoveryCode(); }) : html`<span class="v">${codeInWords(known)}</span>`}</div>
      <div class="row"><div class="grow"><span class="t">Reading asks again</span><span class="d">How often seeing what your agents left needs your passphrase.</span></div>
        <select class="input" style="width:auto;min-height:30px" id="viewing" onChange=${(/** @type {any} */ event) => setViewing(event.target.value).catch((failure) => say(failure.message, true))}>
          ${[["never", "Every 12 hours"], ["hourly", "Every hour"], ["every_time", "Every visit"]].map(([value, words]) => html`<option value=${value} selected=${viewing === value}>${words}</option>`)}
        </select></div>
    </div>
    <div class="btns" style="justify-content:space-between">
      <div class="btns">${btn("lock", html`${icon.lock()}Lock`, "", lockNow)}${btn("sign-out", "Sign out", "danger", signOut)}</div>
      <button type="button" class="btn primary" onClick=${() => { ui.sheet = null; draw(true); }}>Done</button>
    </div>
    <p class="hint">Lock ends this visit's unlocking. Sign out also forgets what this computer reads with, in every tab.</p>
  </div>`;
}

/** Whether the recovery code was saved, as far as this browser can tell. */
function codeInWords(known) {
  if (me.owner.recoveryLater) return "Not set yet";
  const here = known && known.code;
  if (here === "saved") return "Saved";
  if (here === "skipped") return codeSaved() ? "Not saved, and you asked not to be reminded" : "Not saved";
  if (codeSaved()) return "Saved";
  return me.list.codeSaved === false ? "Not saved" : "This computer can't tell";
}

/**
 * The recovery code, made only now, when the person has chosen to write it down, and kept nowhere:
 * Splint here makes it, signs that the Splint ID commits to it and seals their list again to its
 * backup, in one prompt, and then it's shown once. It always asks for the passphrase.
 */
async function setRecoveryCode() {
  if (!me.owner.recoveryLater) return;
  const typed = await confirmSheet({ title: "Save a recovery code", lead: "It's shown once, right after this. Have paper or your password manager ready, and never give it to anyone, your agents included.", label: "Show my code" });
  const before = me.list.backup;
  try {
    const made = await computerCall("/local/recovery", { passphrase: typed });
    const code = parseRecoveryCode(made.code);
    me.owner = await readIdentity(made.identity);
    me.list.backup = b64url((await backupFromCode(code)).point);
    remember({ code: "saved", code_saved: true });
    // No Copy or Download: anything running as this person, an agent included, can read the clipboard
    // and the Downloads folder, and the code takes their ID.
    ui.code = spelledCode(code);
    ui.view = "code";
    draw(true);
  } catch (failure) {
    me.list.backup = before;
    throw failure;
  }
}

function codeView() {
  return html`<main class="solo">
    ${brand()}
    <div style="display:grid;gap:6px"><h1>Your recovery code</h1><p class="lead">If you ever lose this computer, this gets your Splint ID back. Write it down, or type it into your password manager. It's shown only now.</p></div>
    <p class="banner stopped" id="recovery-warning">Never give this code to anyone: not your agent, any other agent, or anyone who asks, whatever they say. Never paste it into a chat. Whoever has it can take your Splint ID for good. Splint never asks for it.</p>
    <p class="surface code-shown" id="recovery-code">${ui.code}</p>
    ${btn("written", "I've written it down", "primary block", async () => { ui.code = ""; go("home"); })}
  </main>`;
}

async function lockNow() {
  await computerCall("/local/lock", {}).catch(() => null);
  me.unlock = null;
  ui.sheet = null;
  ui.view = "unlock";
}

// ---------- Setting up, unlocking, and what can't go on ----------

function setupView() {
  const chip = chipHere();
  const waiting = ui.approvals.find((approval) => controlsAsk(approval.asks));
  const make = async () => {
    const chosen = chip ? null : chosenPassphrase();
    const name = (ui.typed["setup-name"] || "").trim().slice(0, 60);
    if (waiting) {
      // The first approval makes the sign-in, with the passphrase just chosen, and approves the ask.
      const done = await computerCall("/local/approve", { passphrase: chosen, ids: waiting.asks.map((ask) => ask.id), code: waiting.code });
      if (!done.approved) throw new Error("Nothing was approved.");
      me.here = await computerCall("/local/here");
      await becomeOwnerHere(me.here.identity);
    } else {
      await oneAtATime(() => makeOwnerHere(chosen));
    }
    if (name) remember({ name });
    if ((me.host && me.host.domain) || (me.here && Array.isArray(me.here.agents) && me.here.agents.length)) await unlockCall(chosen);
    await startHere();
    say(waiting ? "Approved. Your agent picks up its controls in a few seconds." : "You're set up. Tell your agent to join Splint, and it asks you here.", false);
  };
  if (waiting) {
    const shown = approvalShown(waiting.asks);
    return html`<main class="solo" id="welcome">
      ${brand()}
      <div style="display:grid;gap:6px"><h1>${shown.title}</h1>${shown.one ? html`<p class="lead mono">${shown.address}</p>` : null}</div>
      ${linesView(shown.lines)}
      ${checkFirst(shown.name, true, waiting.asks.some((one) => one.from_link))}
      ${nameField()}
      ${chip ? null : passphraseFields()}
      ${btn("make", html`${icon.lock()}${chip ? "Approve with Touch ID" : "Approve"}`, "primary block", make, { id: "approve-first" })}
      <p class="hint">It starts within limits, reached only by your contacts. Change it any time.</p>
    </main>`;
  }
  return html`<main class="solo" id="welcome">
    ${brand()}
    <div style="display:grid;gap:6px"><h1>Set up Splint on this computer</h1><p class="lead">Your agents ask you here before anything that commits you.</p></div>
    ${nameField()}
    ${chip ? null : passphraseFields()}
    ${btn("make", chip ? "Set up with Touch ID" : "Continue", "primary block", make)}
    ${chip ? null : html`<button type="button" class="textlink" aria-expanded=${String(ui.open.has("why"))} onClick=${() => { ui.open.has("why") ? ui.open.delete("why") : ui.open.add("why"); draw(true); }}>Why a passphrase?</button>`}
    ${ui.open.has("why") ? html`<p class="hint">It locks your key on this computer, so nothing else running here, your agents included, can approve as you. Nothing can reset it, so keep it somewhere safe.</p>` : null}
  </main>`;
}

/** A name for the person, kept on this computer only. */
function nameField() {
  return field("setup-name", "Your name", html`<input class="input" id="setup-name" autocomplete="name" placeholder="Optional, kept on this computer" value=${ui.typed["setup-name"] || ""} onInput=${(/** @type {any} */ event) => { ui.typed["setup-name"] = event.target.value; }} />`);
}

/** A new passphrase, typed twice. */
function passphraseFields() {
  return html`
    ${field("new-passphrase", "Choose a passphrase", passwordInput("new-passphrase", { placeholder: `At least ${FEWEST_PASSPHRASE_CHARACTERS} characters`, autocomplete: "new-password" }))}
    ${passwordInput("new-passphrase-again", { placeholder: "Type it again", "aria-label": "Type it again", autocomplete: "new-password" })}
    <p class="hint">Nothing can reset it, so keep it safe.</p>`;
}

/** The passphrase chosen for a new key file, typed twice so a slip doesn't lock the person out. */
function chosenPassphrase() {
  const chosen = ui.typed["new-passphrase"] || "";
  if ([...chosen].length < FEWEST_PASSPHRASE_CHARACTERS) throw new Error(`Choose a passphrase of at least ${FEWEST_PASSPHRASE_CHARACTERS} characters.`);
  if (chosen !== (ui.typed["new-passphrase-again"] || "")) throw new Error("Those two passphrases aren't the same.");
  delete ui.typed["new-passphrase"];
  delete ui.typed["new-passphrase-again"];
  return chosen;
}

function unlockView() {
  const chip = chipHere();
  const name = me.owner ? displayName() : "";
  const doUnlock = async () => {
    const typed = chip ? null : takeTyped("unlock-passphrase");
    if (!chip && !typed) throw new Error("Type your passphrase.");
    await unlockCall(typed);
    await startHere();
  };
  return html`<main class="solo" id="unlock">
    ${brand()}
    <div style="display:grid;gap:6px"><h1>${name && name !== "You" ? `Welcome back, ${name}` : "Welcome back"}</h1><p class="lead">Unlock to see and manage your agents.</p></div>
    ${chip ? null : field("unlock-passphrase", "Passphrase", passwordInput("unlock-passphrase", { autocomplete: "current-password", onKeyDown: (/** @type {any} */ event) => { if (event.key === "Enter") press("unlock", doUnlock)(event); } }))}
    ${btn("unlock", chip ? "Unlock with Touch ID" : "Unlock", "primary block", doUnlock, { id: "unlock-go" })}
    <p class="hint">Stays unlocked while you use it, and locks 30 minutes after you stop. Reloading the page asks again.</p>
  </main>`;
}

function noKeyView() {
  return html`<main class="solo" id="open-from-agent">
    ${brand()}
    <div style="display:grid;gap:6px"><h1>Open Splint from your agent</h1><p class="lead">For your safety, this page works only when Splint on this computer opens it. Ask your agent to open your Splint controls, and it opens them here.</p></div>
    <div class="surface list"><div class="row"><div class="grow"><span class="t">Say to your agent</span><span class="d mono">Open my Splint controls</span></div></div></div>
    <p class="hint">Or in a terminal on this computer: <span class="mono">splint controls</span> and your agent's host.</p>
  </main>`;
}

function stoppedView() {
  return html`<main class="solo" id=${ui.view === "cant-sign" ? "cant-sign-here" : "unreachable"}>
    ${brand()}
    <div style="display:grid;gap:6px"><h1>Splint can't open here</h1><p class="lead">${ui.stopped}</p></div>
  </main>`;
}

/** A link's ask, shown with a button to see it, as opening a link is all a website can do. */
// What each kind of change a link asks for is, in the page's own words, before anything has checked
// it: never a value from the link, as only the agent's host can say the link is the agent's.
const LINKED_KINDS = {
  controls: () => "Act for you on Splint",
  level: () => "Change how much it does by itself",
  quoted_prices: () => "Change whether its quotes wait for you",
  reach: () => "Change who can reach it",
  writes: () => "Change who it can write to",
  paused: (/** @type {any} */ change) => (change.to === false ? "Turn it back on" : "Pause it"),
  contact: () => "Add a contact, or change what one can do",
  remove: () => "Remove a contact",
  block: () => "Block someone",
  step: () => "Say yes to something it's holding for you",
  where_paid: () => "Change where you get paid",
  host: () => "Move it to another host",
};

/**
 * What a link says it asks, read from the link alone, before the person clicks and Splint here checks
 * it with the agent's host: whose address it names and, in fixed words, the kinds of change. Nothing
 * from it is shown as it was written, so a website making up a link can't put words here. `null`
 * where the link can't be read, and the page then says only that an agent sent a request.
 * @param {{ask: string, address: string}} offered
 */
function linkSays(offered) {
  try {
    if (!AN_ADDRESS.test(offered.address)) return null;
    const payload = JSON.parse(DECODER.decode(fromB64url(String(offered.ask).split(".")[1] || "")));
    const changes = (Array.isArray(payload.changes) ? payload.changes.slice(0, 8) : []).filter((change) => change && typeof change === "object" && !Array.isArray(change));
    if (!changes.length) return null;
    const lines = [...new Set(changes.map((change) => {
      const kind = change && typeof change.change === "string" && Object.hasOwn(LINKED_KINDS, change.change) ? LINKED_KINDS[change.change] : null;
      return kind ? kind(change) : "A change this page doesn't know";
    }))];
    const controls = changes.some((change) => change.change === "controls");
    const title = controls ? `${capital(addressParts(offered.address).name)} wants to act for you` : `${capital(addressParts(offered.address).name)} asks you for ${nounFor([{ changes }])}`;
    return { name: capital(addressParts(offered.address).name), address: offered.address, controls, title, lines };
  } catch {
    return null;
  }
}

function linkView() {
  if (ui.linked) {
    return html`<main class="solo wide" id="linked">${brand()}${askCardOrUnlock()}</main>`;
  }
  const says = ui.offered ? linkSays(ui.offered) : null;
  return html`<main class="solo" id="offered">
    ${brand()}
    ${says ? html`
      <div style="display:grid;gap:6px"><h1>${says.title}</h1><p class="lead mono">${says.address}</p></div>
      ${linesView(says.controls ? says.lines.filter((line) => line !== LINKED_KINDS.controls()) : says.lines)}
      <p class="hint" id="link-unchecked">Opening it checks that ${says.name} sent it.</p>`
    : html`<div style="display:grid;gap:6px"><h1>An agent sent you a request</h1><p class="lead">Open it to see which agent it is and what it asks.</p></div>`}
    ${btn("see", "Open request", "primary block", async () => {
      const offered = /** @type {{ask: string, address: string}} */ (ui.offered);
      const taken = await computerCall("/local/asks", { ask: offered.ask, address: offered.address });
      if (!taken.ask) throw new Error("That ask isn't waiting here.");
      ui.linked = taken.ask;
      ui.offered = null;
      if (hasPageKey()) {
        ui.after = { view: "request", request: taken.ask.id };
        await startHere();
        await loadAsks();
        draw(true);
      } else {
        // Only how the sign-in asks, for unlocking in place: never who's here, which needs the key.
        const probe = await fetch("/local/unlock", { credentials: "omit", cache: "no-store" }).then((answer) => answer.json()).catch(() => ({}));
        me.here = { here: { sign_in: probe.chip ? "chip" : "file", prompts_by_itself: Boolean(probe.chip) } };
        ui.linkSetUp = Boolean(probe.set_up);
        draw(true);
      }
    })}
  </main>`;
}

/** The link's ask, and how to approve it: right here once the page has its key, or after unlocking. */
function askCardOrUnlock() {
  const linked = ui.linked;
  const lines = linesBeyondJoining(linked);
  const name = capital(addressParts(linked.address).name);
  return html`${plainKeyFileBanner()}
    <div style="display:grid;gap:6px"><h1>${controlsAsk([linked]) ? `${name} wants to act for you` : `${name} asks you for ${nounFor([linked])}`}</h1><p class="lead mono">${linked.address}</p></div>
    ${linesView(lines)}
    ${checkFirst(name, controlsAsk([linked]), true)}
    ${ui.linkSetUp ? html`
      ${chipHere() ? null : field("link-passphrase", "Passphrase", passwordInput("link-passphrase", { autocomplete: "current-password" }))}
      ${btn("link-unlock", "Unlock to approve", "primary block", async () => {
        const typed = chipHere() ? null : takeTyped("link-passphrase");
        if (!chipHere() && !typed) throw new Error("Type your passphrase.");
        await unlockCall(typed);
        ui.after = { view: "request", request: linked.id };
        await startHere();
        await loadAsks();
        draw(true);
      })}` : html`<p class="hint">Splint on this computer opens this page for you: run the line your agent gave you to install it, or if it runs here, ask it to open your Splint controls.</p>`}`;
}

function hasPageKey() {
  try {
    return Boolean(localStorage.getItem(PAGE_KEY));
  } catch {
    return false;
  }
}

// ---------- Drawing it all ----------

function app() {
  const view = ui.view;
  const body = view === "loading" ? html`<main class="solo"><p class="lead">Loading…</p></main>`
    : view === "setup" ? setupView()
      : view === "unlock" ? unlockView()
        : view === "no-key" ? noKeyView()
          : view === "cant-sign" || view === "unreachable" ? stoppedView()
            : view === "link" ? linkView()
              : view === "code" ? codeView()
                : shell(view === "agent" ? agentView() : view === "requests" ? requestsView() : view === "request" ? requestView() : homeView());
  return html`${body}${sheetView()}${ui.toast ? html`<div class=${`toast ${ui.toast.bad ? "bad" : ""}`} role="status" id="told">${ui.toast.bad ? icon.warn() : icon.check()}<span>${ui.toast.words}</span></div>` : html`<div id="told" role="status" hidden></div>`}`;
}

/**
 * Draws the page from what it knows. What's shown is compared, so a click that lands just after it
 * changes is caught; the drawing itself only touches what changed.
 */
function draw(always) {
  const agents = agentsShown();
  const shown = JSON.stringify([ui.view, ui.agent, ui.tab, ui.request, ui.approvals.map((one) => one.asks.map((ask) => ask.id)), me.list.seq, me.owner && me.owner.recoveryLater, ...agents.map((agent) => [
    agent.agent, agent.status, agent.rules && agent.rules.seq, agent.view && [agent.view.drafts, agent.view.held, agent.view.changes], notUsedOf(agent),
    agent.parties && [...agent.parties.keys()],
  ])]);
  if (shown !== lastShown) {
    lastShown = shown;
    lastDrawn = performance.now();
  } else if (!always) {
    return;
  }
  document.title = ui.view === "agent" && agentById(ui.agent) ? `${agentById(ui.agent).label} · Splint` : totalCount() ? `(${totalCount()}) Splint` : "Splint";
  render(app(), document.getElementById("main"));
}

async function home() {
  ui.view = "home";
  Object.assign(ui, fromPath());
  draw(true);
  await loadAsks();
  await refresh();
}

// ---------- On this computer ----------

/**
 * The page as Splint on this computer serves it: who's here comes from Splint, which holds the sign-in
 * and the reading key, and its sessions, kept as long as the viewing setting allows.
 */
async function startHere() {
  me.here = await computerCall("/local/opened", {});
  // The home host is set when the first agent is, so it's read again each time the page starts here.
  const published = await fetch("/.well-known/splint/host", { cache: "no-store" }).then((answer) => answer.json()).catch(() => null);
  if (published && typeof published.domain === "string") me.host = { domain: published.domain, relay: published.relay === true };
  if (!me.here.identity) {
    // An agent's ask for its controls may be waiting already: setting up and approving it are one step.
    await loadAsks();
    ui.view = "setup";
    draw(true);
    return;
  }
  await becomeOwnerHere(me.here.identity);
  // Reading goes on while the sessions Splint here keeps last. Without them, what waits on this
  // computer still shows, and unlocking reads the rest; a change asks to unlock when it comes.
  const sessions = Array.isArray(me.here.sessions) ? me.here.sessions : [];
  if (sessions.length) takeSessionsHere(sessions);
  await home();
  const after = ui.after;
  ui.after = null;
  if (after) go(after.view, after);
}

/** Whether there's anywhere to read from yet: a home host, or an agent this computer set up. */
function hostsKnown() {
  return Boolean((me.host && me.host.domain) || (me.here && Array.isArray(me.here.agents) && me.here.agents.length));
}

/** Whether this computer's sign-in is a key file with no passphrase, which this page can't sign with. */
function plainKeyFile() {
  return Boolean(me.here && me.here.here && me.here.here.plain_key_file);
}

/** Said wherever an approval could be, for a key file with no passphrase, with how to lock it. */
function plainKeyFileBanner() {
  return plainKeyFile() ? html`<p class="banner stopped" id="plain-key-file">${icon.warn()}<span>Your sign-in on this computer is a key file with no passphrase, so anything running as you here, your agent included, can sign as you. This page can't approve with it. Lock it with a passphrase: run splint computer lock in a terminal.</span></p>` : null;
}

/** This computer's owner, with the agents it set up beside those the list holds. */
async function becomeOwnerHere(identity) {
  becomeOwner(await readIdentity(identity));
  me.sealing = sealingHere();
  for (const one of Array.isArray(me.here && me.here.agents) ? me.here.agents : []) {
    if (typeof one.agent === "string" && typeof one.address === "string" && AN_ADDRESS.test(one.address) && !me.agents.has(one.agent)) {
      me.agents.set(one.agent, { agent: one.agent, address: one.address, label: capital(addressParts(one.address).name) });
    }
  }
}

// Whether Splint here is being asked to make a Splint ID. A second click meanwhile would ask for a
// second one while the first prompt is open.
let becoming = false;

async function oneAtATime(task) {
  if (becoming) throw new Error("Your computer is already asking for your sign-in. Finish or cancel that first.");
  becoming = true;
  try {
    return await task();
  } finally {
    becoming = false;
  }
}

/** The Splint ID, made by Splint on this computer around a new sign-in: in its chip, or a key file locked with the passphrase just chosen. */
async function makeOwnerHere(chosen) {
  const made = await computerCall("/local/owner", { passphrase: chosen });
  me.here = await computerCall("/local/here");
  await becomeOwnerHere(made.identity);
}

/** Whether this computer's chip keeps the sign-in, or will once it's made. */
function chipHere() {
  const here = me.here && me.here.here ? me.here.here : {};
  const held = String(here.sign_in || "");
  return held.includes("chip") || (!held && Boolean(here.prompts_by_itself));
}

// Every tab of this page in this browser hears a Sign out, so none is left signed in behind it.
const SIGNED_OUT = "splint-signed-out";
const JUST_SIGNED_OUT = "splint-just-signed-out";

function reloadSignedOut() {
  try {
    sessionStorage.setItem(JUST_SIGNED_OUT, "1");
  } catch {
    // A tab with no storage reloads without saying it signed out.
  }
  location.reload();
}

/** Ends the sign-in in every tab here: Splint here forgets the sessions it kept and the signing session. */
async function signOut() {
  await computerCall("/local/sign-out", {}).catch(() => null);
  try {
    new BroadcastChannel(SIGNED_OUT).postMessage("");
  } catch {
    // A browser with no BroadcastChannel signs out this tab alone.
  }
  reloadSignedOut();
}

// ---------- Starting ----------

async function start() {
  applyTheme();
  let computer = false;
  try {
    const published = await fetch("/.well-known/splint/host", { cache: "no-store" }).then((answer) => answer.json());
    me.host = { domain: published.domain, relay: published.relay === true };
    computer = published.computer === true;
  } catch {
    ui.stopped = "Splint on this computer can't be reached. Ask your agent to open your Splint controls.";
    ui.view = "unreachable";
    draw(true);
    return;
  }
  // Only Splint on this computer signs for the page. Served by itself with `--port`, it has nothing to
  // sign with, and nothing else serves it.
  if (!computer) {
    ui.stopped = "This copy of your controls can't sign anything. Ask your agent to open your Splint controls, or run splint controls with your agent's host and no --port, which opens the one Splint on this computer serves.";
    ui.view = "cant-sign";
    draw(true);
    return;
  }
  const fragment = new URLSearchParams(location.hash.slice(1));
  // Cleared from the address bar, so a reload or a copied address carries nothing.
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  // An agent's link: an ask it signed, after the `#`, which no browser sends anywhere. It's handed to
  // Splint here only once the person clicks to see it.
  if (fragment.get("ask") && fragment.get("at")) {
    ui.offered = { ask: String(fragment.get("ask")), address: String(fragment.get("at")) };
    if (location.pathname === "/ask") history.replaceState(null, "", "/requests");
    ui.view = "link";
    draw(true);
    return;
  }
  const opening = fragment.get("open");
  if (opening) await takeOpening(opening);
  if (!hasPageKey()) {
    await unlockOrSetUp();
    return;
  }
  await startHere().catch((error) => {
    if (error === NO_KEY) return unlockOrSetUp();
    ui.stopped = error.message;
    ui.view = "unreachable";
    draw(true);
  });
  try {
    if (sessionStorage.getItem(JUST_SIGNED_OUT)) {
      sessionStorage.removeItem(JUST_SIGNED_OUT);
      say("You're signed out in this browser.", false);
    }
  } catch {
    // Nothing kept, so nothing to say.
  }
}

/**
 * With no page key, or a stale one from before Splint here last started: unlocking gets one where there's
 * a Splint ID here, and otherwise the page has to be opened by Splint on this computer.
 */
async function unlockOrSetUp() {
  try {
    localStorage.removeItem(PAGE_KEY);
  } catch {
    // Nothing kept.
  }
  me.unlock = null;
  const here = await fetch("/local/unlock", { credentials: "omit", cache: "no-store" }).then((answer) => answer.json()).catch(() => ({}));
  // Only how the sign-in asks, for the unlock screen to say: never who's here, which needs the key.
  me.here = { here: { sign_in: here.chip ? "chip" : "file", prompts_by_itself: Boolean(here.chip) } };
  ui.view = here.set_up ? "unlock" : "no-key";
  draw(true);
}

try {
  new BroadcastChannel(SIGNED_OUT).onmessage = () => reloadSignedOut();
} catch {
  // Signing out in another tab then leaves this one as it is.
}

window.addEventListener("popstate", () => {
  if (["home", "agent", "requests", "request"].includes(ui.view)) {
    Object.assign(ui, { view: "home", agent: "", tab: "now", request: "" }, fromPath());
    draw(true);
  }
});

setInterval(() => {
  if (!["home", "agent", "requests", "request"].includes(ui.view) || document.hidden) return;
  // What agents left at their hosts is read only while Splint here has sessions there.
  if (me.sessions.size) refresh().catch(() => null);
  // What waits on this computer needs only the page key, so it's looked at with no sessions too, as
  // after approving in a terminal or with viewing set to ask every time. Drawn again only if the asks
  // changed: a refresh draws what it read once it's all read, so nothing taken in halfway is drawn, or
  // signed, before the rest.
  const asked = JSON.stringify(ui.approvals.map((one) => one.asks.map((ask) => ask.id)));
  loadAsks().then(() => {
    if (JSON.stringify(ui.approvals.map((one) => one.asks.map((ask) => ask.id))) !== asked) draw(true);
  }).catch(() => null);
}, REFRESH_MILLIS);

start();

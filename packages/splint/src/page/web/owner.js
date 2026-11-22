// @ts-check
// Your controls: the owner page Splint on the owner's own computer serves at /owner. Splint there holds
// the owner's sign-in, in the computer's security chip or a key file locked with a passphrase, and
// signs only after its own prompt, which shows the code this page shows. The page reaches hosts only
// through the Owner API in docs/protocol.md, and only ever makes elements and sets their text. What it
// asks Splint here to sign is built from the same values it shows. No host serves this page, and it
// makes and uses no passkey: Nenye decided on 2026-11-21 that owners sign only on their own computers,
// as whoever serves the page a passkey signs on chooses what a touch there signs (issue 635).
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
// Two levels, as owners see them. Go ahead signs `auto_within_limits`, today's default on the wire. The
// page signs nothing by itself, so where a kind's outcome is the owner's to sign, or there's a price,
// it waits for their touch at either level.
const LEVELS = [
  ["ask_me", "Ask me first", "Your agent asks you before it agrees to anything."],
  ["auto_within_limits", "Go ahead", (quoted) => `Your agent acts for you by itself, within the day's limit below. A kind of request whose outcome you sign waits for your own yes. ${amountsInWords(quoted)}`],
];
// Rules signed with `full_auto` elsewhere, as `splint authorize --level full-auto` still can, are shown
// as they are, and kept unless the person picks another.
const FULL_AUTO = ["full_auto", "Full auto, set outside this page", (quoted) => `Your agent goes ahead by itself, with no caps on what it offers, up to ${FULL_AUTO_PER_DAY.toLocaleString("en-US")} steps and messages a day. ${amountsInWords(quoted)}`];

/** The levels to offer, with the one these rules hold always among them. */
function levelsFor(rules) {
  return rules.permissions.level === "full_auto" ? [...LEVELS, FULL_AUTO] : LEVELS;
}
// Nenye's call of 2026-11-13: whether a price the agent quotes, where its owner would be
// paid, waits for them is the owner's own signed setting. Waiting is the default, left out of the rules.
const QUOTED_PRICES = [
  ["wait", "Wait for me", "A price your agent quotes, where you'd be the one paid, waits for you. This is the default."],
  ["within_limits", "Go ahead within its limits", "Your agent sends a price it quotes by itself, as it does anything else at your level. Anything you'd pay still waits for you."],
];
/**
 * What waits for the owner where there's an amount, under their setting for a price their agent quotes
 *: a price they'd pay waits at every level, and one their agent quotes waits only if they
 * left that setting at Wait for me. A kind with money is used with a contact only once the owner approves
 * it for them, and a number not labelled as money is marked, never held.
 */
function amountsInWords(quoted) {
  return quoted === "within_limits"
    ? "A price you'd pay is never agreed without your yes, and a price your agent quotes, where you'd be paid, goes by itself within its limits."
    : "A price you'd pay, or a price your agent quotes, is never agreed without your yes.";
}
const REACH = [
  ["contacts", "Contacts only", "Only your contacts can reach your agent. Anyone else waits for you."],
  ["open", "Anyone", "Anyone can reach your agent, as a business might want."],
];
const SEALING = [
  ["sealed", "Sealed", "Only your agent and the one it's talking to can read what they say."],
  ["unsealed", "Unsealed", "Hosts can read what your agent says, as a business might need."],
];
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
const OPERATIONS = {
  confirm: "wants to agree to this",
  cancel: "wants to cancel this",
  open: "wants to start this",
  counter: "wants to offer this instead",
  accept: "wants to accept this",
  deliver: "wants to send this",
};
// Another step waiting on the same exchange, as its own card says it.
const BESIDE = {
  confirm: "your yes to agree to it",
  cancel: "your agent's cancel",
  counter: "your agent's counter",
  accept: "your agent's accept",
  deliver: "your agent's delivery",
};

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
};
let refreshing = 0;
let lastDrawn = 0;
let lastShown = "";
// A redraw can move another card under a click already on its way, and a counterparty can influence
// when one comes, so a button ignores clicks for this long after one.
const PAUSE_AFTER_REDRAW_MILLIS = 700;

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
  await signIn();
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
  if (response.status === 403) throw new Error(NO_PAGE_KEY);
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
 * One approval on this computer over every input: Splint here signs them with the owner's sign-in after
 * its own prompt, which owner-key writes from exactly these. That prompt names objects only by kind, so it
 * shows the code this page shows too, and the code it answers with shows they were what it signed.
 * @param {string[]} inputs
 */
async function touch(inputs) {
  const code = await touchCodeOf(inputs);
  // Only the chip's prompt shows a code to compare. A key file's passphrase is typed into this page.
  say(chipHere() ? `This computer asks you to approve. Its code should be ${code}.` : "Approving with the key file on this computer.", false, true);
  try {
    const done = await computerCall("/local/sign", { inputs, passphrase: passphraseHere() });
    if (done.code !== code || !Array.isArray(done.signed) || done.signed.length !== inputs.length) {
      throw new Error("What this computer signed isn't what this page prepared, so nothing was sent.");
    }
    return { signed: done.signed };
  } finally {
    say("", false);
  }
}

/**
 * Where this page keeps the page key Splint on this computer gave it for the one-time opening that
 * `splint controls` put after the `#`. Every call under `/local` carries it, so only a page the person
 * opened reaches them, never another program on this computer that only reaches its port. The key is
 * made at each start of Splint here, so an old one is simply refused.
 */
const PAGE_KEY = "splint-page-key";
const NO_PAGE_KEY = "Open your controls on this computer with splint controls HOST in a terminal here: only the page that opens can use them.";

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
  if (response.status === 403) throw new Error(NO_PAGE_KEY);
  if (!response.ok) throw new Error(typeof read.error === "string" ? read.error : "Splint on this computer didn't answer.");
  return read;
}

/** The passphrase typed on the page, for a sign-in that's a key file locked with one. Read once. */
function passphraseHere() {
  // The one just chosen opens the first sign-in too, in the same click, so it's typed once then.
  if (passphraseJustChosen) {
    const chosen = passphraseJustChosen;
    passphraseJustChosen = null;
    return chosen;
  }
  const field = /** @type {HTMLInputElement | null} */ (document.getElementById("passphrase-here"));
  const typed = field ? field.value : "";
  if (field) field.value = "";
  return typed || null;
}

/**
 * The passphrase the person just chose for a new key file, held for the one approval the same click
 * goes on to, the first sign-in, and dropped when that takes it or fails.
 * @type {string | null}
 */
let passphraseJustChosen = null;

/** The fewest characters a key file's passphrase has, as the owner key holds one to. */
const FEWEST_PASSPHRASE_CHARACTERS = 8;

/**
 * The passphrase chosen on the welcome page for a new key file, typed twice so a slip doesn't lock the
 * person out. Null where the chip keeps the sign-in, which asks for none.
 */
function newPassphraseHere() {
  const first = /** @type {HTMLInputElement | null} */ (document.getElementById("new-passphrase"));
  const second = /** @type {HTMLInputElement | null} */ (document.getElementById("new-passphrase-again"));
  if (!first || !second) return null;
  const chosen = first.value;
  if ([...chosen].length < FEWEST_PASSPHRASE_CHARACTERS) {
    throw new Error(`Choose a passphrase of at least ${FEWEST_PASSPHRASE_CHARACTERS} characters.`);
  }
  if (chosen !== second.value) throw new Error("Those two passphrases aren't the same.");
  first.value = "";
  second.value = "";
  return chosen;
}

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
  say(`The sign-ins on your owner ID changed since this browser last saw them: ${words}. If that wasn't you, use your recovery code now.`, added > 0, true);
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
 * Sessions at the person's home host and each agent's, made and kept by Splint on this computer, which
 * signs them with one approval and reads with them for this page for as long as the viewing setting
 * lets them last.
 */
async function signIn() {
  const hosts = [...new Set([me.host && me.host.domain, ...[...me.agents.values()].map((agent) => addressParts(agent.address).domain)]
    .filter((one) => typeof one === "string" && one))].slice(0, MAX_SESSIONS);
  if (!hosts.length) return;
  say("This computer asks you to approve, to read what your agents left you.", false, true);
  try {
    const made = await computerCall("/local/session", { hosts, passphrase: passphraseHere() });
    takeSessionsHere(made.sessions);
  } finally {
    say("", false);
  }
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
  const answers = await Promise.all([...new Set([holder, host, ...me.sessions.keys()])].map(async (at) => {
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
    if (!me.agents.has(listed.agent)) me.agents.set(listed.agent, { agent: listed.agent, address: listed.address, label: listed.label });
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
  if (!party) return line("stop", "With someone this page couldn't check", "Not verified: their agent's view gave no binding their owner signed. Their IDs are under Exact terms.");
  const contact = ((agent.rules && agent.rules.contacts) || []).find((one) => one.agent === party.agent && !hasHiddenCharacters(one.label));
  const agreed = !contact && agreedWith(agent).some((held) => held.sender === party.agent);
  const who = `With ${contact ? `${contact.label} (${party.address})` : party.address}${agreed ? ", a contact your agent agreed with" : ""}`;
  if (party.owner === me.owner.id) return line("good", `${who}, your own agent too`, "Verified: your own signature binds it at that address.");
  if (party.standIn) return line("warn", who, "Not verified: that agent's owner hasn't set up its controls yet.");
  return line("good", who, "Verified: their owner signed that this agent acts for them at that address.");
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
async function decide(agent, draft, decision) {
  const payload = {
    v: 1, owner: me.owner.id, agent: agent.agent, decision, operation: draft.operation, request: draft.request,
    version: draft.version, prev: draft.prev, terms: draft.terms, issued_at: now(), expires_at: draft.latest_expiry,
  };
  await readyToLeaveFor([agent]);
  const done = await touch([signingInput(OWNER_ALG, "splint-approval", payload)]);
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

/** Where the person gets paid, which each of their agents can ask to be paid at once a deal is done. */
function gettingPaidCard(agents) {
  const box = el("textarea", {
    id: "where-paid", rows: 4, spellcheck: false, autocomplete: "off", value: me.paidDraft,
    placeholder: "https://pay.example.com/you\nyou@wallet.example\nonchain:eip155:8453:0x...:usdc",
    oninput: () => { me.paidDraft = box.value; },
  });
  return el("div", { class: "card" },
    el("p", {}, "Up to 4 places people can pay you, one a line: a payment link or page, a Lightning address, or onchain:CHAIN:ADDRESS:ASSET. No bank details."),
    box,
    el("p", { class: "soft small" }, "Splint holds no money. Once a deal that pays you is done, your agent can ask to be paid at one of these, with the amount from the deal, and people pay you on their own app or wallet. A payment by Lightning or on a chain can't be reversed. Signing new places replaces the ones before, and the people you deal with are told they're new."),
    el("div", { class: "acts" }, button("Sign where you get paid", "", () => signWherePaid(agents, box.value))));
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
async function signWherePaid(agents, typed) {
  const lines = typed.split("\n").map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0 || lines.length > 4) throw new Error("Give 1 to 4 places, one a line.");
  const places = lines.map(placeFrom);
  if (new Set(places.map((place) => JSON.stringify(place))).size !== places.length) throw new Error("Each place once.");
  await signPlaces(agents, places);
  me.paidDraft = "";
  say("Signed. Your agents can ask to be paid there once a deal that pays you is done.", false);
}

/** One approval: where the owner gets paid, exactly these places, left for each of these agents. */
async function signPlaces(agents, places) {
  let payload;
  try {
    payload = wherePaidPayload(me.owner.id, places, now());
  } catch {
    throw new Error("Those places are more than one statement of where you get paid can hold. Give fewer, or shorter ones.");
  }
  await readyToLeaveFor(agents);
  const done = await touch([signingInput(OWNER_ALG, "splint-where-paid", payload)]);
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

// ---------- Drawing ----------

function main() {
  return /** @type {HTMLElement} */ (document.getElementById("main"));
}

// How long a message that something worked stays up. What went wrong stays until the next click, and a
// message the person has to act on stays until they click something.
const TOLD_MILLIS = 6000;
let toldTimer = 0;

function say(words, bad, stay) {
  const told = /** @type {HTMLElement} */ (document.getElementById("told"));
  told.textContent = words;
  told.className = bad ? "bad" : "";
  told.hidden = !words;
  clearTimeout(toldTimer);
  if (words && !bad && !stay) toldTimer = setTimeout(() => say("", false), TOLD_MILLIS);
}

/** A button that does one thing at a time, and says what went wrong in plain words. */
function button(label, kind, go) {
  const made = el("button", {
    type: "button",
    class: kind,
    onClick: async () => {
      if (performance.now() - lastDrawn < PAUSE_AFTER_REDRAW_MILLIS) {
        say("The page just changed, so that click didn't count. Look again.", true);
        return;
      }
      made.disabled = true;
      say("", false);
      try {
        await go();
      } catch (failure) {
        say(failure.message, true);
      } finally {
        made.disabled = false;
      }
    },
  }, label);
  return made;
}

// Your own Splint serving the page by itself, with `--port`, has nothing to sign with: a passkey for
// `localhost` is one any program on this computer could ask to sign, so none is made.
const ON_THIS_COMPUTER_WORDS = "Your controls on this computer sign with this computer's own sign-in. Run splint controls HOST in a terminal here, without --port, to open them.";

function signedOn() {
  return el("p", { class: "app" }, "Signed on this app: ", el("strong", {}, location.origin), ". Your sign-in names it in every signature.");
}

function show(...kids) {
  document.title = "Your controls";
  main().replaceChildren(...kids.filter((kid) => kid !== null && kid !== undefined));
  lastDrawn = performance.now();
}

// Whether Splint here is being asked to make an owner ID. A second click meanwhile would ask for a
// second one while the first prompt is open.
let becoming = false;

async function oneAtATime(go) {
  if (becoming) throw new Error("Your device is already asking for your sign-in. Finish or cancel that first.");
  becoming = true;
  try {
    return await go();
  } finally {
    becoming = false;
  }
}

/** Makes a new owner ID around a sign-in on this computer, then signs in and goes home. */
async function makeOwner() {
  await oneAtATime(makeOwnerHere);
  try {
    await signIn();
    await home();
  } finally {
    passphraseJustChosen = null;
  }
}

/** A few words for each thing a person has as an owner, the same wherever the page names them. */
function facts(...rows) {
  return el("dl", { class: "facts" }, ...rows.filter(Boolean).flatMap(([name, value]) => [el("dt", {}, name), el("dd", {}, ...[value].flat())]));
}

/**
 * The recovery code, made only now, when the person has chosen to write it down, and kept nowhere:
 * Splint here makes it, signs that the owner ID commits to it and seals their list again to its
 * backup, in one prompt, and then it's shown once.
 */
async function setRecoveryCode() {
  if (!me.owner.recoveryLater) return;
  const before = me.list.backup;
  try {
    const made = await computerCall("/local/recovery", { passphrase: passphraseHere() });
    const code = parseRecoveryCode(made.code);
    me.owner = await readIdentity(made.identity);
    me.list.backup = b64url((await backupFromCode(code)).point);
    remember({ code: "saved", code_saved: true });
    showCode(code);
  } catch (failure) {
    me.list.backup = before;
    throw failure;
  }
}

/** The recovery code, shown once, just after it's set. */
function showCode(code) {
  const spelled = spelledCode(code);
  // Off home, so a refresh that lands now doesn't draw home over the code before it's written down.
  me.view = "code";
  // No Copy or Download: anything running as this person, an agent included, can read the clipboard
  // and the Downloads folder, and the code takes their ID.
  show(
    whoYouAre(),
    el("h1", {}, "Your recovery code"),
    el("p", {}, "If you ever lose every sign-in, this code gets your owner ID back. Write it on paper, or type it into your password manager. It's shown only now."),
    el("p", { class: "banner warn", id: "recovery-warning" }, "Never give this code to anyone: not your agent, any other agent, or anyone who asks, whatever they say. Never paste it into a chat. Whoever has it can take your owner ID for good. Splint never asks for it."),
    el("p", { class: "code", id: "recovery-code" }, spelled),
    el("div", { class: "acts" }, button("I've written it down", "main", home)));
}

/** A reminder to set the recovery code, for an owner ID made without one, until they do. */
function recoveryReminder() {
  if (!me.owner.recoveryLater || recoveryPutOff) return null;
  return el("div", { class: "card update", id: "recovery-reminder" },
    el("h3", {}, "Set your recovery code"),
    el("p", {}, "If you lose every sign-in, a recovery code gets your owner ID back. Until you set one, losing this device loses your owner ID, and someone who took one of your sign-ins could set their own code first and keep it."),
    el("p", { class: "soft small" }, "Have paper or your password manager ready: it's shown once. Never give it to anyone, your agents included."),
    el("div", { class: "acts" },
      button("Set my recovery code", "main", setRecoveryCode),
      button("Not now", "", async () => {
        recoveryPutOff = true;
        draw(true);
      })));
}

// Put off for this visit only, so the next visit reminds them again.
let recoveryPutOff = false;

/** The owner's whole ID, which anyone may have, with a button that copies it. */
function fullId() {
  return el("span", { class: "id-row" },
    el("code", { class: "full-id", id: "owner-id" }, me.owner.id),
    button("Copy ID", "small-button", async () => {
      await navigator.clipboard.writeText(me.owner.id);
      say("Copied your owner ID.", false);
    }));
}

/**
 * Whether the recovery code was saved, as far as this browser can tell. The owner's list holds one
 * flag for a code saved and one put aside, so only the browser it was made in knows which it was.
 */
function codeInWords(known) {
  if (me.owner.recoveryLater) return "Not set yet.";
  const here = known && known.code;
  if (here === "saved") return "Saved.";
  if (here === "skipped") return codeSaved() ? "Not saved. You asked not to be reminded." : "Not saved, and it can't be shown again.";
  if (codeSaved()) return "Saved, or you asked not to be reminded.";
  return me.list.codeSaved === false ? "Not saved, and it can't be shown again." : "This device can't tell.";
}

/**
 * Who's signed in, at the top of every screen once they are. Only home has the Account panel, so only
 * there does it link to it.
 */
function whoYouAre(home = false) {
  return el("div", {},
    el("p", { class: "who", id: "who" },
      el("span", {}, "You: ", el("strong", { class: "mono" }, shortId(me.owner.id)), ", signed in on ", el("strong", {}, "this computer")),
      home ? el("a", { href: "#account" }, "Account") : null),
    passphraseField());
}

/**
 * Where a person types their key file's passphrase, on this computer, when its sign-in has one. A key
 * file with none is said to be one every time, as this page can't sign with it and anything else can.
 */
function passphraseField() {
  const here = me.here && me.here.here ? me.here.here : {};
  if (here.plain_key_file) {
    return el("p", { class: "banner warn", id: "plain-key-file" },
      "Your sign-in on this computer is a key file with no passphrase, so anything running as you on this computer, your agent included, can sign as you. This page can't sign with it. Lock it with a passphrase: run splint computer lock in a terminal.");
  }
  const held = String(here.sign_in || "");
  if (!held.includes("passphrase")) return null;
  return el("div", { class: "field" },
    el("label", { htmlFor: "passphrase-here" }, "Your sign-in's passphrase, to approve"),
    passphraseBox());
}

/** @type {HTMLInputElement | null} */
let passphraseTyped = null;

/**
 * The one box the passphrase is typed in, put into each drawing in turn. A page that draws itself again
 * while the person types then keeps what they typed, and the cursor in it. A new box each time emptied
 * it, and the approval that followed went with no passphrase. It's kept nowhere else, and an approval
 * still reads it once and empties it.
 */
function passphraseBox() {
  const box = passphraseTyped || (passphraseTyped = el("input", { type: "password", id: "passphrase-here", autocomplete: "off" }));
  // Moving the box into the new drawing takes the cursor out of it, so it goes back once that's shown.
  if (document.activeElement === box) queueMicrotask(() => box.focus());
  return box;
}

// Every tab of this page in this browser hears a Sign out, so none is left signed in behind it.
const SIGNED_OUT = "splint-signed-out";
// Set in a tab just before a Sign out reloads it, so the page it reloads to can say so. It's only a
// flag, in that tab's own storage.
const JUST_SIGNED_OUT = "splint-just-signed-out";

/** Reloads this tab after a Sign out, here or in another tab. */
function reloadSignedOut() {
  try {
    sessionStorage.setItem(JUST_SIGNED_OUT, "1");
  } catch {
    // A tab with no storage reloads without saying it signed out.
  }
  location.reload();
}

/** Ends the sign-in in every tab here: Splint here forgets the sessions it kept. */
async function signOut() {
  await computerCall("/local/sign-out", {}).catch(() => null);
  try {
    new BroadcastChannel(SIGNED_OUT).postMessage("");
  } catch {
    // A browser with no BroadcastChannel signs out this tab alone.
  }
  reloadSignedOut();
}

/**
 * Everything the page knows of who's signed in: the owner ID, this computer's sign-in, the recovery
 * code and the agents acting for them.
 */
function accountPanel(agents) {
  const known = knownAs(me.owner.id);
  return el("section", { id: "account" },
    el("h2", {}, "Account"),
    el("div", { class: "card" },
      facts(
        ["Owner ID", [fullId(), el("span", { class: "soft small block" }, "Who you are to every agent. It never changes.")]],
        ["This sign-in", chipHere() ? "This computer's security chip" : "A key file on this computer"],
        ["Recovery code", codeInWords(known)],
        ["Viewing", viewingChoice()],
        ["Agents", agents.length ? el("ul", { class: "plain" }, ...agents.map((agent) => el("li", {}, `${agent.label} `, el("span", { class: "soft" }, agent.address)))) : "None yet."]),
      el("div", { class: "acts" }, button("Sign out", "", signOut)),
      el("p", { class: "soft small" }, "Signs you out in every tab of this browser.")));
}

/** How often viewing what agents left needs a touch, chosen here and kept by this device. */
function viewingChoice() {
  const choices = [["never", "When your sign-in ends, every 12 hours"], ["hourly", "Every hour"], ["every_time", "Every time you open your controls"]];
  const picked = viewingHere();
  const select = el("select", { id: "viewing" }, ...choices.map(([value, words]) => el("option", { value, selected: value === picked }, words)));
  select.addEventListener("change", () => setViewing(select.value).catch((failure) => say(failure.message, true)));
  return [select, el("span", { class: "soft small block" }, "How often seeing what your agents left needs your touch. Approving always does.")];
}

function agentCard(agent) {
  const status = {
    mine: ["good", "Your controls are set up"],
    "not-yet": ["warn", "Picking up your controls. This takes a few seconds while your agent is running."],
    elsewhere: ["stop", "That address names another agent now"],
    unknown: ["", "Its host can't be reached"],
  }[agent.status || "unknown"];
  const shown = agent.status === "mine" && agent.rules && agent.rules.paused ? ["stop", "Paused, by your off switch"] : status;
  return el("div", { class: "card agent", id: `agent-${agent.agent}` },
    el("h3", {}, el("span", { class: `dot ${shown[0]}` }), `${agent.label} `, el("span", { class: "soft" }, agent.address)),
    el("p", {}, shown[1]),
    agent.heardAt ? el("p", { class: "soft small" }, `Last heard from ${short(agent.heardAt)}`) : null,
    agent.behind ? el("p", { class: "soft small" }, BEHIND_WORDS) : null);
}

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
 * Said in fixed words on the card it's about, as a lying Signet could write anything in it: the card for
 * the step that answer was for, or the request's first where no card for that step waits.
 */
function notUsedLine(agent, request, operation, beside, first) {
  const said = notUsedOf(agent).find((one) => one.request === request);
  if (!said) return null;
  if (said.operation !== operation && !(first && !beside.includes(said.operation))) return null;
  const answer = said.decision === "deny" ? "no" : "yes";
  const why = {
    changed: `Your last ${answer} to this wasn't used: what you were shown had changed before it reached your agent, so nothing went. This is what's waiting now.`,
    // Nothing refused it: the Signet couldn't save or send it just then, as when its host was down.
    not_now: `Your last ${answer} to this wasn't used: your agent's Signet couldn't take it just then, so nothing went. It's still waiting, and you can answer again.`,
  };
  return el("p", { class: "banner stop" }, Object.hasOwn(why, said.why)
    ? why[said.why]
    : `Your last ${answer} to this wasn't used: your agent's Signet refused it, so nothing went. It's still waiting.`);
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

/** One card for each draft: several can wait on one exchange, each its own yes to its own terms. */
function decisionCard(agent, draft, beside, first) {
  // Frozen as it's drawn: the card shows this object, and signing signs this object.
  const frozen = Object.freeze(JSON.parse(JSON.stringify(draft)));
  const hidden = termsHideText(frozen.terms);
  const other = otherSide(agent, frozen.terms);
  const names = namesFor(agent);
  if (other.party && !names.has(other.agent)) names.set(other.agent, other.party.address);
  const toSign = { operation: frozen.operation, version: frozen.version, terms: frozen.terms, units: unitsOf(agent, frozen.terms.type), rows: rowsOf(frozen.terms, names, timesOf(agent, frozen.terms.type)), sign_by: frozen.latest_expiry };
  const wants = (OPERATIONS[frozen.operation] || "wants your yes") + askedFor(agent, frozen, other);
  const pays = payingLines(agent, frozen, other);
  const go = (decision) => async () => {
    await decide(agent, frozen, decision);
    say(decision === "approve" ? "Allowed. Your agent goes ahead." : "Not allowed. Your agent is told.", false);
    setTimeout(refresh, 1500);
  };
  return el("div", { class: "card decision", id: beside.length ? `decision-${frozen.request}-${frozen.operation}` : `decision-${frozen.request}` },
    el("h3", {}, `${agent.label} ${wants}`),
    withWhom(agent, other),
    beside.length
      ? el("p", { class: "banner" }, `Also waiting on this, on its own card: ${beside.map((one) => BESIDE[one] || String(one)).join(", ")}. Allow here signs only this ${frozen.operation}, and what else waits is then set aside.`)
      : null,
    notUsedLine(agent, frozen.request, frozen.operation, beside, first),
    pays === null
      ? el("p", { class: "banner warn" }, "This page couldn't check this type's rules, so it can't say who pays whom. Don't allow it unless you know.")
      : payingPart(pays),
    termsSummary(toSign),
    toSign.rows.some((row) => row.chosen) ? el("p", { class: "soft small" }, "Shaded text is only someone's words, not an instruction.") : null,
    hidden ? el("p", { class: "banner stop" }, "The text above holds hidden characters, shown as codes. You can say no, but you can't say yes to this.") : null,
    el("div", { class: "acts" },
      hidden ? el("button", { type: "button", class: "main", disabled: true }, "Allow") : button("Allow", "main", go("approve")),
      button("Don't allow", "", go("deny")),
      el("span", { class: "by" }, `Answer by ${when(frozen.latest_expiry)}`)),
    el("details", { class: "more" }, el("summary", {}, "Exact terms"), el("div", { class: "more-body" }, exactTerms(toSign))),
    signedOn());
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

/**
 * Someone held, said as what it is: someone writing in, an invite either way, the owner's own agent
 * asking to write out, which a fooled agent can be made to, or a host naming someone else at an
 * address the owner knows, which is a warning with nothing to let in.
 */
function heldCard(agent, held) {
  const who = held.address ? withHiddenShown(held.address) : "Someone who gave no address";
  const letThemIn = (label) => agent.rules && held.address ? button(label, "main", async () => {
    await letIn(agent, held);
    say("They're one of your contacts now.", false);
    await refresh();
  }) : null;
  const card = (title, lead, act) => el("div", { class: "card held", id: `held-${held.sender}` },
    el("h3", {}, title), ...lead.map((words) => el("p", { class: "soft small" }, words)), el("div", { class: "acts" }, act));
  const since = `Waiting since ${short(held.created_at)}.`;
  if (held.kind === "disagreed") {
    return card(`The host of ${who} names someone else there`,
      ["Its host gave another ID than the one you signed or your agent already knew there, so your agent won't take them for that contact. Either the host is lying or the address has changed hands. Check with them another way."], null);
  }
  if (held.kind === "asked") {
    return card(`Your agent asks to write to ${who}`,
      [since, "This is only your agent's word, and it may have been fooled into asking. Allow it only if you know them."], letThemIn("Allow"));
  }
  if (held.kind === "invite" && invitedByUs(agent, held)) {
    return card(`${who} accepted your agent's invite`, [since, "Let them in, and they're one of your contacts."], letThemIn("Let them in"));
  }
  if (held.kind === "invite") {
    return card(`${who} invites your agent to be contacts`, [since, "Nothing they wrote is shown here."], letThemIn("Let them in"));
  }
  return card(`${who} wants to reach your agent`, [since, "Nothing they wrote is shown here."], letThemIn("Let them in"));
}

/**
 * The off switch: rules signed from the owner's last, the same but paused, which its host and its
 * Signet hold it to, so it sends nothing and is shown nothing until it's turned back on.
 */
function offSwitch(agent) {
  const paused = Boolean(agent.rules && agent.rules.paused);
  const flip = (on) => async () => {
    await signRules(agent, (draft) => { draft.paused = on; });
    say(on ? `${agent.label} is paused. It sends nothing, and is shown nothing, until you turn it back on.` : `${agent.label} is back on, within your settings.`, false);
    draw(true);
  };
  return el("div", { class: "off-switch", id: `off-switch-${agent.agent}` },
    el("h4", {}, "Off switch"),
    el("p", { class: "soft small" }, paused
      ? "Paused. Its host and its Signet stop everything it sends, and hold what comes for it."
      : "If you think it's been fooled or taken over, pause it. Its host and its Signet stop everything it sends at once."),
    el("div", { class: "acts" }, paused ? button("Turn it back on", "main", flip(false)) : button("Pause it", "stop", flip(true))));
}

const CHANGE_KINDS = {
  bound: "it was bound to an owner",
  owner: "it acts for a new owner",
  key: "its key changed, as after a recovery",
  signet: "its Signet changed",
  host: "it moved to another host",
  revocation: "its owner stopped it",
  declared: "its owner declared a change",
};
const STANDINGS = {
  ask: "You asked to say yes to changes like this. Until you do, their messages wait, and your agent can't write to them.",
  hold: "Their owner stopped them. Until you say yes, their messages wait, and your agent can't write to them.",
  waiting_for_history: "Your agent is waiting for the rest of their history before it can say what changed.",
  rewritten: "They showed two different histories, so one was rewritten. Your agent holds them whatever your settings say.",
  continue: "It carries on by your settings, as the same owner stands behind it. This is only to tell you.",
};
// A new owner that carried on, as a stand-in's first owner does or as `owner: continue` lets it,
// isn't the same owner standing behind it.
const NEW_OWNER_CARRIED_ON = "It carries on by your settings, under its new owner. This is only to tell you.";

/**
 * A contact that changed, from the agent's view: what changed, in the page's own words for each kind
 * the history names, and a yes signed for the exact head shown. No one's own words are drawn.
 */
function changeCard(agent, notice) {
  const names = namesFor(agent);
  const who = names.get(notice.contact) || (notice.address ? withHiddenShown(String(notice.address)) : "A contact");
  const kinds = [...new Set((Array.isArray(notice.since_accepted) ? notice.since_accepted : []).map((change) => change && change.kind))]
    .filter((kind) => typeof kind === "string" && Object.hasOwn(CHANGE_KINDS, kind)).map((kind) => CHANGE_KINDS[kind]);
  const yes = (label, head) => button(label, "main", async () => {
    await acceptChange(agent, notice, head);
    say("Done. Your agent goes by it once its Signet hears.", false);
    setTimeout(refresh, 1500);
  });
  const frozenHead = String(notice.head || "");
  // A change that carried on needs nothing from the person; "Got it" only takes it off this list.
  const act = notice.standing === "ask" || notice.standing === "hold" ? yes("Allow", frozenHead)
    : notice.standing === "rewritten" ? yes("Stay with what you've seen", frozenHead)
      : notice.standing === "continue" ? yes("Got it", frozenHead) : null;
  return el("div", { class: "card change", id: `change-${notice.contact}` },
    el("h3", {}, `${who} changed`),
    kinds.length ? el("p", {}, `What changed: ${kinds.join("; ")}.`) : null,
    el("p", { class: "soft small" }, notice.standing === "continue" && kinds.includes(CHANGE_KINDS.owner) ? NEW_OWNER_CARRIED_ON
      : Object.hasOwn(STANDINGS, notice.standing) ? STANDINGS[notice.standing] : "Your agent holds them for now."),
    el("div", { class: "acts" }, act));
}

/**
 * What the agent may do by itself at a level, in words, from the rules it goes by. While the owner is
 * away, their agent's delegate says yes for them only to the types the page delegates, which have no
 * amount in them, so a price waits for their approval at every level.
 */
function limitsInWords(level, permissions, quoted) {
  if (level === "ask_me") return "Nothing goes ahead without you: it asks you before it agrees to anything.";
  const amounts = quoted === "within_limits"
    ? "A price you'd pay is never agreed without your yes."
    : "A price you'd pay, or one it quotes, is never agreed without your yes.";
  const quotes = quoted === "within_limits" ? " It sends a price it quotes, where you'd be paid, by itself." : "";
  const alone = `By itself it talks with your contacts, agrees new kinds of request with them, and completes the ones nobody signs. A kind whose outcome you sign, such as a meeting both people sign, waits for your yes. A kind with money is used only once you approve it, and a number not labelled as money never waits.${quotes} ${amounts}`;
  if (level === "full_auto") return `${alone} It offers anything with no caps, up to ${FULL_AUTO_PER_DAY.toLocaleString("en-US")} steps and messages a day.`;
  const capped = Object.entries(permissions.caps || {}).flatMap(([type, fields]) =>
    Object.entries(fields || {}).map(([field, most]) => capInWords(type, field, most)));
  const offers = capped.length ? ` It offers no more than ${capped.join("; ")}.` : "";
  const actions = permissions.actions_per_day;
  const day = Number.isSafeInteger(actions)
    ? ` It agrees to at most ${Math.ceil(actions / YESES_PART)} a day by itself, and takes at most ${actions} steps and messages a day.`
    : "";
  return `${alone}${offers}${day}`;
}

/** A cap such as {"quote/1": {"amount_minor.usd": 50000}}: "quote up to 500.00 USD", as `money` says it. */
function capInWords(type, field, most) {
  const kind = withHiddenShown(String(type).split("/")[0]);
  const [name, unit] = String(field).split(".");
  if (name === "amount_minor" && unit && Number.isSafeInteger(most)) return `${kind} up to ${money(most, unit)}`;
  return `${kind} with ${withHiddenShown(String(field))} up to ${Number(most)}`;
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

/** The settings signed now that let more through than usual, said beside them. */
function riskyBanners(rules) {
  return RISKY.filter((risky) => risky.on(rules)).map((risky) => el("p", { class: "banner warn" }, risky.words));
}

/**
 * Who kept each agent busy today, busiest first, from its Signet's own counts in its view, with anyone
 * sending far more than on a usual day said first.
 */
function usageRows(agent) {
  const usage = (agent.view && Array.isArray(agent.view.usage)) ? agent.view.usage : [];
  return usage.map((line) => el("li", { class: line.busier_than_usual ? "busier" : "" },
    `${withHiddenShown(String(line.address))}: ${line.arrivals_today} today for ${agent.label}`,
    el("span", { class: "soft small" }, ` (a usual day is about ${line.usual_per_day}; notes ${line.texts_from} in, ${line.texts_to} out; requests ${line.new_requests_from} in, ${line.new_requests_to} out)`)));
}

function busierBanners(agent) {
  const usage = (agent.view && Array.isArray(agent.view.usage)) ? agent.view.usage : [];
  return usage.filter((line) => line.busier_than_usual).map((line) => el("p", { class: "banner warn" },
    `${withHiddenShown(String(line.address))} sent ${agent.label} ${line.arrivals_today} today, where a usual day is about ${line.usual_per_day}. Your settings limit what they can send in a day.`));
}

function settingsCard(agent) {
  const rules = agent.rules;
  if (!rules) return el("div", { class: "card" }, el("h3", {}, agent.label), el("p", { class: "soft" }, "These settings couldn't be checked, so the page won't change them."));
  if (rules.paused) return el("div", { class: "card settings", id: `settings-${agent.agent}` }, el("h3", {}, `${agent.label}, paused`), offSwitch(agent), signedOn());
  const held = choicesFor(agent);
  const { chosen, agreedOn, keep } = held;
  const limits = el("p", { class: "soft small", id: `limits-${agent.agent}` }, limitsInWords(chosen.level, rules.permissions, chosen.quoted));
  const added = el("div", { id: `added-out-${agent.agent}` });
  const takenOut = () => addedTakenOut(agent, chosen.level, agreedOn.on);
  const showAdded = () => {
    const going = takenOut();
    const shown = idsOf(going);
    // Drop is chosen for the person and shown before they save, as keeping makes them the person's
    // own approved contacts, which only their choice should do.
    if (shown !== keep.shown) keep.choice = going.length ? "drop" : null;
    keep.shown = shown;
    const unseen = !agent.view && takesAddedOut(agent, chosen.level, agreedOn.on);
    added.replaceChildren(...addedNotice(agent, going, agreedOn.on, keep, unseen));
  };
  showAdded();
  // Words that follow the price setting, redone whenever it changes.
  const followQuoted = /** @type {(() => void)[]} */ ([]);
  const following = (attributes, words) => {
    if (typeof words !== "function") return el("span", attributes, words);
    const span = el("span", attributes, words(chosen.quoted));
    followQuoted.push(() => { span.textContent = words(chosen.quoted); });
    return span;
  };
  const choice = (key, options) => el("fieldset", {},
    ...options.map(([value, label, words]) => {
      const input = el("input", { type: "radio", name: `${key}-${agent.agent}`, id: `${key}-${value}-${agent.agent}`, value, checked: chosen[key] === value });
      input.addEventListener("change", () => {
        chosen[key] = value;
        held.touched = true;
        if (key === "level" || key === "quoted") limits.textContent = limitsInWords(chosen.level, rules.permissions, chosen.quoted);
        if (key === "quoted") followQuoted.forEach((redo) => redo());
        if (key === "level") showAdded();
      });
      return el("label", { htmlFor: input.id, class: "option" }, input, el("strong", {}, label), following({ class: "soft small" }, words));
    }));
  return el("div", { class: "card settings", id: `settings-${agent.agent}` },
    // Nenye's name for this, of 2026-11-14.
    el("h3", {}, `Manage how ${agent.label} interacts with other agents`),
    ...riskyBanners(rules),
    el("h4", {}, "What it does without you"), choice("level", levelsFor(rules)),
    el("h4", {}, "A price it quotes, where you'd be the one paid"), choice("quoted", QUOTED_PRICES),
    limits,
    el("h4", {}, "Who can reach it"), choice("reach", REACH),
    agreedToggle(agent, agreedOn, () => {
      held.touched = true;
      showAdded();
    }),
    added,
    el("h4", {}, "Who can read what it says"), choice("sealing", SEALING),
    el("div", { class: "acts" }, button("Save", "main", async () => {
      const going = takenOut();
      if (idsOf(going) !== keep.shown) {
        showAdded();
        throw new Error("The contacts these would take out aren't the ones the page showed, so nothing was signed. Look again, and choose for them.");
      }
      if (going.length && !keep.choice) throw new Error("Choose whether to keep the contacts your agent added, above, so nothing was signed yet.");
      const kept = keep.choice === "keep" ? await keptAsOwn(going) : [];
      const agreedBefore = rules.reach.agreed;
      const notRenewed = await signRules(agent, (draft) => {
        draft.permissions.level = chosen.level;
        // Left out for the default, as Splint leaves it out, so rules that don't change it read alike.
        if (chosen.quoted === "within_limits") draft.permissions.quoted_prices = "within_limits";
        else delete draft.permissions.quoted_prices;
        draft.sealing = chosen.sealing;
        draft.reach.inbound = chosen.reach === "open"
          ? { ...draft.reach.inbound, from: "open", types: draft.reach.inbound.types.length ? draft.reach.inbound.types : openTypes(agent) }
          : { from: "contacts", filter: { owners: [], hosts: [], past: false }, types: [], text: false, strangers: draft.reach.inbound.strangers };
        if (agreedOn.on) draft.reach.agreed = draft.reach.agreed || { ...AGREED };
        else delete draft.reach.agreed;
        for (const held of kept) {
          draft.contacts.push({ agent: held.sender, address: held.address, label: addressParts(held.address).name, status: "allowed", types: [...agreedBefore.types], text: agreedBefore.text, agree_types: agreedBefore.agree_types !== false, pinned_by: "invite" });
        }
      }, true);
      me.choices.delete(agent.agent);
      const who = (list) => list.map((held) => withHiddenShown(held.address)).join(", ");
      const contacts = !going.length ? ""
        : kept.length ? ` ${who(kept)} ${kept.length === 1 ? "is your own contact" : "are your own contacts"} now.`
          : ` They took out ${who(going)}, which you can add back under Contacts.`;
      say(`Saved. Your agent goes by these now.${contacts}${notRenewed.length ? ` ${NOT_RENEWED_WORDS}` : ""}`, false, Boolean(contacts || notRenewed.length));
      draw(true);
    })),
    offSwitch(agent),
    signedOn());
}

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

/** Who they are, in one word, to tell whether the ones a choice was made for are still the ones going. */
function idsOf(going) {
  return going.map((held) => String(held.sender)).sort().join(" ");
}

/**
 * What the person has chosen in an agent's Settings, kept across redraws for as long as the rules they
 * were chosen over are the ones signed. Rules signed since, from another tab or device, start them
 * again from what's signed, so nothing is saved over a change the person hasn't seen.
 */
function choicesFor(agent) {
  const rules = agent.rules;
  const held = me.choices.get(agent.agent);
  if (held && held.seq === rules.seq) return held;
  if (held && held.touched) say(`${agent.label}'s settings were changed somewhere else, so Settings shows them as they are now. Choose again before you save.`, true);
  const made = {
    seq: rules.seq,
    chosen: {
      level: rules.permissions.level, quoted: rules.permissions.quoted_prices || "wait",
      reach: rules.reach.inbound.from === "open" ? "open" : "contacts", sealing: rules.sealing,
    },
    agreedOn: { on: Boolean(rules.reach && rules.reach.agreed) },
    // The owner's choice for contacts the agent added that these would take out, "keep" or "drop", set
    // for them once the page shows who goes, and who the page showed it for.
    keep: { choice: null, shown: "" },
    touched: false,
  };
  me.choices.set(agent.agent, made);
  return made;
}

/**
 * Who the settings chosen take out, said before they're signed, with the choice to keep or drop them,
 * one chosen for the person, and what keeping means: they become the owner's own contacts.
 */
function addedNotice(agent, going, agreedOn, keep, unseen) {
  const why = agreedOn ? "At Ask me first, only contacts you chose can reach it" : "With contacts it adds turned off, only contacts you chose can reach it";
  // Tightening never waits on seeing who goes, so a device that can't open the agent's view says so.
  if (unseen) {
    return [el("p", { class: "banner warn" }, `${why}, so these take out any contacts ${agent.label} added by itself. This device can't see which, and a device that opens what your agents send you lists them under Contacts afterwards, to add back.`)];
  }
  if (!going.length) return [];
  const reach = agreedOn ? "under Ask me first" : "with contacts it adds turned off";
  const option = (word, label, words) => {
    const input = el("input", { type: "radio", name: `added-${agent.agent}`, id: `${word}-added-${agent.agent}`, value: word, checked: keep.choice === word });
    input.addEventListener("change", () => { keep.choice = word; });
    return el("label", { htmlFor: input.id, class: "option" }, input, el("strong", {}, label), el("span", { class: "soft small" }, words));
  };
  return [
    el("p", { class: "banner warn" }, `${why}, so these take out the contacts ${agent.label} added by itself: ${going.map((held) => withHiddenShown(held.address)).join(", ")}. They're dropped unless you choose to keep them before you save.`),
    option("keep", "Keep them", `They become your own contacts, as if you'd added them: they can reach your agent ${reach}, and amounts with them follow your setting for prices, as with anyone you added.`),
    option("drop", "Drop them", "They're taken out, and you can add any of them back under Contacts."),
  ];
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

/** Whether contacts the agent adds by itself, by an invite either way, can message it. */
function agreedToggle(agent, agreedOn, changed) {
  const input = el("input", { type: "checkbox", id: `agreed-${agent.agent}`, checked: agreedOn.on });
  input.addEventListener("change", () => { agreedOn.on = input.checked; changed(); });
  return el("label", { htmlFor: input.id, class: "option" }, input, el("strong", {}, "Contacts your agent adds can message it"),
    el("span", { class: "soft small" }, "When your agent and another agree to be contacts, they can talk and arrange things at once, documents included, up to 100 new ones a day. A kind with money, such as a quote, is used with them only once you approve it for them, and a number not labelled as money is marked, never held. You can approve, remove or block them under Contacts."));
}

/** Contacts the agent agreed with by itself, which the owner hasn't approved, to approve, remove or block. */
function addedRows(agent) {
  return ((agent.view && agent.view.held) || []).filter((held) => held.kind === "agreed" && !settledBy(agent.rules, held)).map((held) => {
    const done = (words) => async () => {
      say(words, false);
      await refresh();
    };
    return el("li", { class: "contact", id: `added-${held.sender}` },
      el("strong", {}, held.address ? withHiddenShown(held.address) : "Someone who gave no address"), " ",
      el("span", { class: "tag warn" }, "Added by your agent"),
      el("span", { class: "soft small" }, " You haven't approved them. They can talk with your agent, and a kind with money, such as a quote, is used with them only once you approve it for them."),
      el("div", { class: "acts" },
        held.address ? button("Approve", "main", async () => { await letIn(agent, held); await done("Approved. They're one of your contacts.")(); }) : null,
        held.address ? button("Remove", "", async () => { await keepOut(agent, held, "allowed"); await done("Removed.")(); }) : null,
        held.address ? button("Block", "stop", async () => { await keepOut(agent, held, "blocked"); await done("Blocked.")(); }) : null));
  });
}

function contactRows(agent) {
  return ((agent.rules && agent.rules.contacts) || []).filter((contact) => !contact.address.endsWith("~blocked.invalid")).map((contact) =>
    el("li", { class: "contact" }, el("strong", {}, withHiddenShown(contact.label)), " ", el("span", { class: "soft" }, withHiddenShown(contact.address)),
      contact.status === "blocked" ? el("span", { class: "tag stop" }, "Blocked")
        : isRemoval(contact) ? el("span", { class: "tag" }, "Removed") : null));
}

/**
 * Each contact's switch for whether their agent and this one agree kinds of request between
 * themselves, which no owner signs: on unless the owner turns it off. Off stops every kind the two
 * agreed, those under way included, since nothing un-agrees one, and leaves only the kinds the owner
 * named. A kind with money is used only once the owner approves it for that contact.
 */
function agreeingRows(agent) {
  return ((agent.rules && agent.rules.contacts) || [])
    .filter((contact) => contact.status === "allowed" && !isRemoval(contact) && !contact.address.endsWith("~blocked.invalid"))
    .map((contact) => {
      const on = contact.agree_types !== false;
      return el("li", { class: "contact" }, el("strong", {}, withHiddenShown(contact.label)), " ",
        el("span", { class: "soft" }, on ? "agrees kinds of request with your agent" : "uses only kinds you named"), " ",
        button(on ? "Turn off" : "Turn on", "", async () => {
          await signRules(agent, (draft) => {
            const named = draft.contacts.find((one) => one.agent === contact.agent);
            if (named) named.agree_types = !on;
          });
          say(on ? "Saved. Kinds their agent and yours agreed are stopped, those under way too. They use only kinds you named." : "Saved. Their agent and yours can agree kinds of request again, and use those already agreed.", false);
          draw(true);
        }));
    });
}

/**
 * What brings each agent up to the page's defaults, with one touch for all of them: contacts it adds
 * can message it, for rules signed before that setting existed, and a delegation signed afresh where
 * the one it holds is due, so it says yes by itself within the owner's limits for another year. An
 * owner who turned the first off can put this off, which this browser remembers until what's offered
 * changes.
 */
function updateCard(agents) {
  const due = agents.filter((agent) => agent.rules && !agent.rules.paused)
    // A delegation lets the agent's Signet say yes only to the types the page delegates, and at ask me
    // to nothing, so with none of those, or at ask me, there's none to offer. Rules last until replaced,
    // so nothing else needs one (Nenye, 2026-11-15).
    .map((agent) => ({ agent, agreed: !agent.rules.reach.agreed, delegation: DELEGATED_TYPES.length > 0 && agent.rules.permissions.level !== "ask_me" && delegationDue(agent) }))
    .filter((one) => one.agreed || one.delegation);
  if (!due.length) return null;
  const offered = JSON.stringify(due.map((one) => [one.agent.agent, one.agreed, one.delegation]));
  try {
    if (localStorage.getItem(UPDATE_PUT_OFF) === offered) return null;
  } catch {
    // Shown each visit, then.
  }
  const words = (one) => [one.agreed ? "contacts it adds can message it" : null, one.delegation ? "it says yes by itself within your limits" : null]
    .filter(Boolean).join(", and ");
  return el("div", { class: "card update", id: "update-agents" },
    el("h3", {}, due.length === 1 ? `Let ${due[0].agent.label} do more by itself` : "Let your agents do more by themselves"),
    el("ul", {}, ...due.map((one) => el("li", {}, `${one.agent.label}: ${words(one)}.`))),
    el("p", { class: "soft small" }, "A price you'd pay still waits for you, and a price your agent quotes follows your setting for it. You can turn these off in Settings."),
    el("div", { class: "acts" },
      button(due.length === 1 ? "Update it" : "Update them", "main", async () => {
        const notRenewed = await signRulesFor(due.map((one) => ({
          agent: one.agent, fresh: one.delegation,
          change: (draft) => { if (one.agreed) draft.reach.agreed = { ...AGREED }; },
        })));
        const updated = due.length === 1 ? "Updated." : "Updated, all of them.";
        say(notRenewed.length ? `${updated} ${notRenewed.map((agent) => agent.label).join(", ")}: ${NOT_RENEWED_WORDS}` : updated, false, notRenewed.length > 0);
        draw(true);
      }),
      button("Not now", "", async () => {
        try {
          localStorage.setItem(UPDATE_PUT_OFF, offered);
        } catch {
          // Nothing kept here.
        }
        draw(true);
      })));
}

function section(id, title, kids, empty) {
  return el("section", { id }, el("h2", {}, title), ...(kids.length ? kids : [el("p", { class: "soft" }, empty)]));
}

function draw(always) {
  // A screen the person is reading, such as their recovery code, isn't drawn over by a refresh.
  if (me.view !== "home") return;
  const agents = [...me.agents.values()];
  // Only what changed is drawn again. A choice half made in Settings is kept in me.choices, so a
  // redraw shows it as the person left it.
  const shown = JSON.stringify([me.list.seq, me.list.codeSaved, me.sealing !== null, me.owner.recoveryLater, recoveryPutOff, ...agents.map((agent) => [
    agent.agent, agent.label, agent.status, agent.rules && agent.rules.seq, agent.refused && agent.refused.length,
    agent.heardAt && short(agent.heardAt), Boolean(agent.behind), agent.view && [agent.view.drafts, agent.view.held, agent.view.changes, agent.view.delegation, agent.view.usage],
    notUsedOf(agent),
    agent.parties && [...agent.parties.keys()],
  ])]);
  if (shown === lastShown && !always) return;
  lastShown = shown;
  const waiting = agents.flatMap((agent) => {
    const drafts = ((agent.view && agent.view.drafts) || []).filter((draft) => draft.owner === me.owner.id && draft.agent === agent.agent);
    const beside = (draft) => drafts.filter((one) => one.request === draft.request && one.operation !== draft.operation).map((one) => one.operation);
    return [
      ...drafts.map((draft, index) => decisionCard(agent, draft, beside(draft), drafts.findIndex((one) => one.request === draft.request) === index)),
    ...(((agent.view && agent.view.held) || []).filter((held) => held.kind !== "agreed" && !settledBy(agent.rules, held)).map((held) => heldCard(agent, held))),
    ...((agent.view && agent.view.changes && Array.isArray(agent.view.changes.changes) ? agent.view.changes.changes : [])
      .filter((notice) => notice && notice.standing !== "continue").map((notice) => changeCard(agent, notice))),
    ];
  });
  const refusedRows = agents.flatMap((agent) => (agent.refused || []).slice(0, 20).map((line) => {
    const way = String(line.way || "");
    const said = Object.hasOwn(REFUSED_WAYS, way) ? REFUSED_WAYS[way] : "had something refused";
    return el("li", {}, `${agent.label} ${said}`, typeof line.at === "number" ? el("span", { class: "soft small" }, ` ${short(line.at)}`) : null);
  }));
  const reminder = me.owner.recoveryLater ? recoveryReminder() : me.list.codeSaved === false && !codeSaved() ? el("div", { class: "banner warn", id: "code-reminder" },
    el("p", {}, "You didn't save a recovery code, and it can't be shown again. If you lose every sign-in, you'd need a new owner ID, which your contacts would have to accept again."),
    el("div", { class: "acts" }, button("Don't remind me", "", async () => {
      await putCodeAside();
      draw(true);
    }))) : null;
  const update = updateCard(agents.filter((agent) => agent.status === "mine"));
  show(
    whoYouAre(true),
    el("h1", {}, "Your controls"),
    reminder,
    section("agents", "Your agents", agents.map(agentCard), "No agents yet. Ask your agent to join Splint and set you up, and it acts for you within the limits you set."),
    el("p", { class: "soft", id: "add-here" }, "To add an agent, ask it to join Splint and set you up. An agent on this computer asks you here by itself. One elsewhere gives you a link to open in this browser."),
    section("waiting", "Waiting for you", update ? [update, ...waiting] : waiting, "Nothing is waiting for you."),
    section("contacts", "Contacts", [
      ...(agents.flatMap(contactRows).length ? [el("ul", {}, ...agents.flatMap(contactRows))] : []),
      ...(agents.flatMap(addedRows).length ? [el("h3", {}, "Added by your agent"), el("ul", {}, ...agents.flatMap(addedRows))] : []),
    ], "No contacts yet."),
    section("settings", "Settings", [
      ...agents.filter((agent) => agent.status === "mine").map(settingsCard),
      ...(agents.filter((agent) => agent.status === "mine").flatMap(agreeingRows).length
        ? [el("h3", {}, "Agreeing new kinds of request, by contact"), el("ul", {}, ...agents.filter((agent) => agent.status === "mine").flatMap(agreeingRows))]
        : []),
    ], "Your agent's settings show here once it has picked up your controls."),
    section("getting-paid", "Getting paid", agents.some((agent) => agent.status === "mine") ? [gettingPaidCard(agents.filter((agent) => agent.status === "mine"))] : [], "Once an agent has picked up your controls, you can say where you get paid."),
    section("changed", "What changed", agents.flatMap((agent) =>
      (agent.view && agent.view.changes && Array.isArray(agent.view.changes.changes) ? agent.view.changes.changes : [])
        .filter((notice) => notice && notice.standing === "continue").map((notice) => changeCard(agent, notice))),
    "No contact of your agents has changed."),
    section("busy", "Who kept your agents busy today", [
      ...agents.flatMap(busierBanners),
      ...(agents.flatMap(usageRows).length ? [el("ul", {}, ...agents.flatMap(usageRows))] : []),
    ], "Nobody has sent your agents anything today."),
    section("activity", "Activity", refusedRows.length ? [el("ul", {}, ...refusedRows)] : [], "Nothing refused lately."),
    accountPanel(agents),
    signedOn());
}

async function home() {
  me.view = "home";
  draw(true);
  await refresh();
}

// ---------- On this computer ----------

/**
 * The page as Splint on this computer serves it: who's here comes from Splint, which holds the sign-in
 * and the reading key, and its sessions, kept as long as the viewing setting allows, mean no approval
 * on a reload until they end.
 */
async function startHere() {
  me.here = await computerCall("/local/opened", {});
  if (!me.here.identity) {
    welcomeHere();
    return;
  }
  await becomeOwnerHere(me.here.identity);
  const sessions = Array.isArray(me.here.sessions) ? me.here.sessions : [];
  if (sessions.length) {
    takeSessionsHere(sessions);
    await home();
    return;
  }
  signInHerePage();
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

/**
 * The owner ID, made by Splint on this computer around a new sign-in: in its security chip, or a key
 * file locked with the passphrase the person just chose, which nothing but this page's own fields gives.
 */
async function makeOwnerHere() {
  const chosen = newPassphraseHere();
  const made = await computerCall("/local/owner", { passphrase: chosen });
  passphraseJustChosen = chosen;
  // makeOwner clears it only once this returns, so a failure here mustn't leave it for a later Approve.
  try {
    me.here = await computerCall("/local/here");
    await becomeOwnerHere(made.identity);
  } catch (error) {
    passphraseJustChosen = null;
    throw error;
  }
}

/** Whether this computer's chip keeps the sign-in, or will once it's made. */
function chipHere() {
  const here = me.here && me.here.here ? me.here.here : {};
  const held = String(here.sign_in || "");
  return held.includes("chip") || (!held && Boolean(here.prompts_by_itself));
}

function chipWords() {
  if (chipHere()) {
    return "This computer's security chip keeps it, and your computer asks for Touch ID or your password each time you approve.";
  }
  return "A key file on this computer keeps it, locked with a passphrase you choose, which you type each time you approve. Without one, anything running as you on this computer, your agent included, could sign as you.";
}

/** Where a person chooses the passphrase for a new key file, typed twice, where no chip keeps the sign-in. */
function newPassphraseFields() {
  if (chipHere()) return null;
  return el("div", {},
    el("div", { class: "field" },
      el("label", { htmlFor: "new-passphrase" }, "Choose a passphrase"),
      el("input", { type: "password", id: "new-passphrase", autocomplete: "off" }),
      el("p", { class: "soft small", id: "new-passphrase-why" }, `At least ${FEWEST_PASSPHRASE_CHARACTERS} characters. It locks your sign-in's key file, so a program that copies the file, or asks Splint here to sign, gets nothing without it. Keep it safe: nothing here can reset it.`)),
    el("div", { class: "field" },
      el("label", { htmlFor: "new-passphrase-again" }, "The same passphrase again"),
      el("input", { type: "password", id: "new-passphrase-again", autocomplete: "off" })));
}

function welcomeHere() {
  show(
    el("h1", {}, "Become a Splint owner"),
    el("p", {}, "Agents you add act for you within limits you set here, and you approve what matters on this computer."),
    facts(
      ["Sign-in", chipWords()],
      ["Owner ID", "Who you are to every agent. It's made with your sign-in and never changes."]),
    newPassphraseFields(),
    el("div", { class: "acts" }, button("Create your owner ID", "main", makeOwner)),
    el("p", { class: "soft small" }, "Already an owner on another computer? Your agent on this computer can still ask you to set it up, and it uses the owner ID made here."),
    signedOn());
}

function signInHerePage() {
  show(
    whoYouAre(),
    el("h1", {}, "Your controls"),
    el("p", {}, "This computer asks you once to read what your agents left you, and keeps that for as long as you chose under Viewing."),
    el("div", { class: "acts" }, button("Show my controls", "main", async () => {
      await signIn();
      await home();
    })),
    signedOn());
}

// ---------- An agent's ask, from its link ----------

/** Whether a change lets more in, which the page warns about in its own words. */
function risky(changes) {
  return changes.some((change) => (change.change === "level" && change.to === "full_auto")
    || (change.change === "reach" && change.to !== "contacts") || (change.change === "quoted_prices" && change.to === "within_limits")
    || (change.change === "writes" && change.to === "replies") || (change.change === "contact" && change.text));
}

async function start() {
  let computer = false;
  try {
    const published = await fetch("/.well-known/splint/host", { cache: "no-store" }).then((answer) => answer.json());
    me.host = { domain: published.domain, relay: published.relay === true };
    computer = published.computer === true;
  } catch {
    show(el("h1", {}, "Your controls"), el("p", { class: "banner stop" }, "Splint on this computer can't be reached. Run splint controls HOST in a terminal here."));
    return;
  }
  // Only Splint on this computer signs for the page. Served by itself with `--port`, it has nothing to
  // sign with, and nothing else serves it.
  if (!computer) {
    show(el("h1", {}, "Your controls"), el("p", { class: "banner stop", id: "cant-sign-here" }, ON_THIS_COMPUTER_WORDS));
    return;
  }
  // An agent's link: an ask it signed, after the `#`, which no browser sends anywhere. Asks go to
  // Splint here, which puts them all in one approval.
  const fragment = new URLSearchParams(location.hash.slice(1));
  if (fragment.get("ask") && fragment.get("at")) {
    location.replace(`/ask${location.hash}`);
    return;
  }
  // Cleared from the address bar, so a reload or a copied address carries nothing.
  const opening = fragment.get("open");
  if (location.hash) history.replaceState(null, "", location.pathname);
  if (opening) await takeOpening(opening);
  await startHere().catch((error) => {
    show(el("h1", {}, "Your controls"), el("p", { class: "banner stop" }, error.message));
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

try {
  new BroadcastChannel(SIGNED_OUT).onmessage = () => reloadSignedOut();
} catch {
  // Signing out in another tab then leaves this one as it is, until it's closed or its sessions end.
}

setInterval(() => {
  if (me.view === "home" && me.sessions.size && !document.hidden) refresh().catch(() => null);
}, REFRESH_MILLIS);

start();

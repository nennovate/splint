// @ts-check
// The page behind a one-use link, for someone with no account and no agent. The key is in the link's
// fragment, which a browser doesn't send, and signing takes a click. Everything from the other side
// goes on the screen as text: this only ever makes elements and sets their text. It proves nothing to
// anyone: what counts is what the requester's Signet finds when it checks the signed steps.
"use strict";

const REFRESH_MILLIS = 5000;
const MAX_NOTE_CHARS = 280;
const MIN_STEP_LIFETIME_SECS = 3600;
const encoder = new TextEncoder();

/** @type {string} */
const request = location.pathname.split("/").pop() || "";
/** @type {CryptoKey | null} */
let key = null;
// What the host last said it holds for this link, as parsed JSON.
/** @type {any} */
let link = null;
let lastText = "";
// Whether the host has said what it holds for this link, so a host that's away or failing isn't taken for a link that has ended.
let reached = false;
let busy = false;
let problem = "";
const form = { pick: new Map(), clarify: "", decline: "", note: "" };

function el(tag, props, ...kids) {
  const made = /** @type {any} */ (document.createElement(tag));
  for (const [name, value] of Object.entries(props || {})) {
    if (name === "onClick") {
      made.addEventListener("click", value);
    } else if (name === "class") {
      made.className = value;
    } else {
      made[name] = value;
    }
  }
  for (const kid of kids) {
    if (kid !== null && kid !== undefined) made.append(kid);
  }
  return made;
}

function fromBase64(text) {
  const plain = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(plain, (char) => char.charCodeAt(0));
}

function toBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function payloadBytes(compact) {
  return fromBase64(compact.split(".")[1]);
}

function payloadOf(compact) {
  return JSON.parse(new TextDecoder().decode(payloadBytes(compact)));
}

async function hexHash(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function capital(words) {
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// A word from a type's own list, such as in_person, as words. Those lists hold only a to z, digits
// and underscores, so this can't make two of them read the same.
function plainWord(word) {
  return capital(String(word).replaceAll("_", " "));
}

// What a field's last word says about its unit, as the owner's page reads it: any type's
// duration_min reads "Duration" in minutes.
const UNITS = {
  min: (number) => `${number} min`,
  mins: (number) => `${number} min`,
  minutes: (number) => `${number} min`,
  sec: (number) => `${number} sec`,
  secs: (number) => `${number} sec`,
  seconds: (number) => `${number} sec`,
  hours: (number) => `${number} hr`,
  days: (number) => (number === "1" ? "1 day" : `${number} days`),
  kb: (number) => `${number} KB`,
  mb: (number) => `${number} MB`,
  pct: (number) => `${number}%`,
  minor: (number) => `${number} in minor units`,
};

/** @returns {{label: string, unit: ((number: string) => string) | null}} */
function fieldLabel(name) {
  const words = String(name).split("_").filter(Boolean);
  const last = words.length > 1 ? words[words.length - 1] : "";
  const unit = Object.hasOwn(UNITS, last) ? UNITS[last] : null;
  return { label: capital((unit ? words.slice(0, -1) : words).join(" ")), unit };
}

function when(seconds) {
  return new Date(seconds * 1000).toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

// An offer's times are always a list, and a pick is one of them, so a lone number is a number.
function shownValue(name, value) {
  if (Array.isArray(value)) return value.map(when).join("\n");
  if (typeof value === "number") {
    const { unit } = fieldLabel(name);
    const text = Number.isSafeInteger(value) ? value.toLocaleString() : String(value);
    return unit ? unit(text) : text;
  }
  return plainWord(value);
}

async function loadKey() {
  const found = new URLSearchParams(location.hash.slice(1)).get("k");
  if (!found) return null;
  return crypto.subtle.importKey("pkcs8", fromBase64(found), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

// The one encoding a reader accepts: these fields, in this order, with nothing else in them.
async function sealed(body) {
  const opened = payloadOf(link.open);
  const created = link.now;
  const payload = JSON.stringify({
    v: 1,
    sender: opened.recipient,
    recipient: opened.sender,
    body: JSON.stringify(body),
    created_at: created,
    expires_at: Math.max(link.deadline, created + MIN_STEP_LIFETIME_SECS),
    nonce: "",
  });
  const header = toBase64(encoder.encode(JSON.stringify({ alg: "ES256", typ: "splint-envelope" })));
  const signingInput = `${header}.${toBase64(encoder.encode(payload))}`;
  // Only the answer card, shown once a key has loaded, reaches here, and sign refuses a missing key anyway.
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, /** @type {CryptoKey} */ (key), encoder.encode(signingInput));
  return `${signingInput}.${toBase64(signature)}`;
}

async function send(body) {
  if (busy) return;
  busy = true;
  problem = "";
  draw();
  try {
    const envelope = await sealed(body);
    const response = await fetch(`/v0/guest/links/${request}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ envelope }),
    });
    if (!response.ok) {
      problem = response.status === 409 ? "This link has already been answered." : "That didn't go through, so nothing changed. Try again.";
    }
  } catch {
    problem = "That didn't go through, so nothing changed. Try again.";
  }
  busy = false;
  await refresh().catch(() => false);
  draw();
}

function steps() {
  const opened = payloadOf(link.open);
  return link.steps.map((compact) => {
    const payload = payloadOf(compact);
    return { compact, fromGuest: payload.sender === opened.recipient, body: JSON.parse(payload.body) };
  });
}

function offerCard(opened, approval) {
  const body = JSON.parse(opened.body);
  const lists = new Set(Object.values(link.form.pick));
  const rows = Object.entries(body.terms || {}).filter(([name]) => !lists.has(name));
  const words = [];
  if (approval.terms.subject) words.push(["Subject", approval.terms.subject]);
  if (approval.terms.note) words.push(["Note", approval.terms.note]);
  return el("div", { class: "card offer" },
    el("h2", {}, plainWord(body.type.split("/")[0])),
    rows.length
      ? el("dl", {}, ...rows.flatMap(([name, value]) => [el("dt", {}, fieldLabel(name).label), el("dd", {}, shownValue(name, value))]))
      : null,
    ...words.flatMap(([name, text]) => [
      el("label", {}, `${name}, in their words`),
      el("p", { class: "words" }, text),
    ]));
}

function answerCard(opened) {
  const body = JSON.parse(opened.body);
  const pickParts = Object.entries(link.form.pick).map(([name, from]) => {
    const choices = (body.terms && body.terms[from]) || [];
    if (!form.pick.has(name) && choices.length) form.pick.set(name, choices[0]);
    return el("div", {},
      el("h2", {}, `Choose a ${fieldLabel(name).label.toLowerCase()} time`),
      ...choices.map((choice) => {
        const input = el("input", { type: "radio", name, value: String(choice), checked: form.pick.get(name) === choice });
        input.addEventListener("change", () => form.pick.set(name, choice));
        return el("label", { class: "choice" }, input, when(choice));
      }));
  });
  const reasonSelect = (id, words, field) => {
    const input = el("select", { id }, ...words.map((word) =>
      el("option", { value: word, selected: form[field] === word }, plainWord(word))));
    if (!form[field]) form[field] = words[0];
    input.addEventListener("change", () => { form[field] = input.value; });
    return input;
  };
  const note = el("input", { type: "text", id: "note", maxLength: MAX_NOTE_CHARS, value: form.note, autocomplete: "off", placeholder: "Optional. Only the sender sees it." });
  note.addEventListener("input", () => { form.note = note.value; });
  const accept = () => {
    const pick = Object.fromEntries([...form.pick.entries()].sort(([one], [other]) => (one < other ? -1 : 1)));
    send({ step: "accept", request, prev: request, ...(Object.keys(pick).length ? { pick } : {}) });
  };
  const clarify = () => {
    // A reader refuses what could hide words, and a person typing an emoji shouldn't lose a note to it.
    // These are the characters core refuses in a note (is_hidden_character), so one can't be refused for them.
    const words = form.note.replace(/[\p{Cc}\p{Cf}\u00AD\u034F\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u2028-\u202E\u2060-\u206F\u2800\u3164\uE000-\uF8FF\uFDD0-\uFDEF\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFFB\uFFFE\uFFFF\u{110BD}\u{110CD}\u{13430}-\u{1343F}\u{1BCA0}-\u{1BCA3}\u{1D159}\u{1D173}-\u{1D17A}\u{E0000}-\u{E0FFF}\u{F0000}-\u{10FFFF}]/gu, "").trim();
    send({ step: "clarify", request, prev: request, reason: form.clarify, ...(words ? { note: words } : {}) });
  };
  return [
    el("div", { class: "card" }, ...(pickParts.length ? pickParts : [el("p", { class: "hint" }, "Say yes to this as it stands.")]),
      el("button", { type: "button", id: "accept", class: "wide", disabled: busy, onClick: accept }, "Accept")),
    el("p", { class: "or" }, "Or"),
    el("div", { class: "card" }, el("h2", {}, "Ask a question"),
      el("label", { htmlFor: "clarify-reason" }, "What's it about?"),
      reasonSelect("clarify-reason", link.form.clarify, "clarify"),
      el("label", { htmlFor: "note" }, "Note"),
      note,
      el("button", { type: "button", id: "clarify", class: "quiet", disabled: busy, onClick: clarify }, "Send")),
    el("div", { class: "card" }, el("h2", {}, "Decline"),
      el("label", { htmlFor: "decline-reason" }, "Why not?"),
      reasonSelect("decline-reason", link.form.decline, "decline"),
      el("button", { type: "button", id: "decline", class: "quiet", disabled: busy,
        onClick: () => send({ step: "decline", request, prev: request, reason: form.decline }) }, "Decline")),
  ];
}

function stateCard(held, ended) {
  const last = (kind, fromGuest) => [...held].reverse().find((step) => step.body.step === kind && step.fromGuest === fromGuest);
  const confirm = last("confirm", false);
  const accepted = last("accept", true);
  const cancelled = last("cancel", true) || last("cancel", false);
  const line = (words, kind) => el("p", { class: kind }, words);
  if (cancelled) {
    return el("div", { class: "card", id: "status" }, line("This has been cancelled.", "stopped"));
  }
  if (confirm && accepted) {
    const pick = accepted.body.pick || {};
    return el("div", { class: "card", id: "status" },
      line("Done. You've accepted, and their side has confirmed.", "done"),
      ...Object.entries(pick).map(([name, value]) => el("p", {}, `${fieldLabel(name).label}: ${when(value)}`)),
      ended ? null : el("button", { type: "button", id: "cancel", class: "quiet", disabled: busy,
        onClick: async () => {
          const head = await hexHash(payloadBytes(confirm.compact));
          send({ step: "cancel", request, prev: head });
        } }, "Cancel this"));
  }
  if (accepted) {
    // A confirm signed at or after the deadline is refused, so once the link ends this wait is over.
    return el("div", { class: "card", id: "status" }, ended
      ? line("You accepted, but their side's confirm hadn't arrived when this link ended.", "stopped")
      : line("You've accepted. Waiting for their side to confirm.", ""));
  }
  const theirs = last("decline", false);
  if (theirs) {
    // Only a reason this type has: a step isn't checked here, so it's no way to say anything else.
    const reason = link.form.decline.includes(theirs.body.reason) ? `: ${String(theirs.body.reason).replaceAll("_", " ")}` : "";
    return el("div", { class: "card", id: "status" }, line(`They've closed this${reason}.`, "stopped"));
  }
  const declined = last("decline", true);
  if (declined) {
    return el("div", { class: "card", id: "status" }, line("You've declined. They'll see that.", ""));
  }
  const asked = last("clarify", true);
  if (asked) {
    return el("div", { class: "card", id: "status" },
      line("Your question has gone to them. If they want to change anything, they'll send a new link.", ""));
  }
  return null;
}

function draw() {
  const main = /** @type {HTMLElement} */ (document.getElementById("main"));
  if (!link) {
    main.replaceChildren(
      el("h1", {}, reached ? "This link isn't here" : "Can't load this link yet"),
      el("p", { class: "hint" }, reached ? "It may have ended, or the address may be cut short." : "Its host couldn't give it just now. This page keeps trying."));
    return;
  }
  const opened = payloadOf(link.open);
  const body = JSON.parse(opened.body);
  const approval = payloadOf(body.approval);
  const held = steps();
  const ended = link.now >= link.deadline;
  const status = stateCard(held, ended);
  const focused = document.activeElement && document.activeElement.id;
  const parts = [
    el("p", { class: "eyebrow" }, "A request for you"),
    el("h1", {}, `A request from ${link.address}`),
    el("p", { class: "hint" }, `Open until ${when(link.deadline)}. No account needed.`),
    offerCard(opened, approval),
  ];
  if (status) parts.push(status);
  if (!status && ended) parts.push(el("div", { class: "card", id: "status" }, el("p", { class: "stopped" }, "This link has ended.")));
  if (!status && !ended && !key) parts.push(el("div", { class: "card", id: "status" }, el("p", { class: "stopped" }, "This address has lost its key, so it can only be read. Open the whole link you were sent.")));
  if (!status && !ended && key) parts.push(...answerCard(opened));
  if (problem) parts.push(el("p", { class: "bad", role: "alert" }, problem));
  parts.push(el("p", { class: "about" }, "Sent with Splint, a secure way for AI agents to interact."));
  main.replaceChildren(...parts);
  const again = focused && document.getElementById(focused);
  if (again) again.focus();
}

async function refresh() {
  const response = await fetch(`/v0/guest/links/${request}`, { cache: "no-store" });
  if (response.status === 404) {
    reached = true;
    link = null;
    lastText = "";
    return true;
  }
  if (!response.ok) return false;
  reached = true;
  const fresh = JSON.parse(await response.text());
  // The host stamps `now` on every read, so it isn't news by itself. Reaching the deadline is.
  const { now, ...rest } = fresh;
  const seen = JSON.stringify(rest);
  const changed = seen !== lastText || (link !== null && (link.now >= link.deadline) !== (now >= fresh.deadline));
  lastText = seen;
  // Still taken whole, so what's signed next is dated from this read.
  link = fresh;
  return changed;
}

async function poll() {
  try {
    // A redraw would take a half-chosen answer away, so only something new makes one.
    if (await refresh()) draw();
  } catch {
    // A host that's away only delays this.
  }
  setTimeout(poll, REFRESH_MILLIS);
}

async function start() {
  try {
    key = await loadKey();
  } catch {
    key = null;
  }
  await refresh().catch(() => false);
  draw();
  setTimeout(poll, REFRESH_MILLIS);
}

start();

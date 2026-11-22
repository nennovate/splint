// Joining and where things stand, before or after there's a Signet to ask. These run the agent's own
// installed `splint`, which does all of it: this checks what's typed has an address's shape, so nothing
// else can reach its command line, and passes its JSON on. It never uses a shell.

import { execFile } from "node:child_process";
import { Refusal, parsed, splintProgram } from "./signet.ts";
import type { Tool } from "./tools.ts";

// Joining starts Signet and waits for its host, which `splint` gives 40 s, and an ask waits up to
// 90 s for a person at this computer's prompt, so it answers before this ends it.
const SPLINT_TIMEOUT_MS = 120_000;
const MAX_ANSWER_BYTES = 1 << 20;
// What "Addresses" in docs/protocol.md allows, in its one spelling. `splint` checks it all again.
const HANDLE = /^[a-z0-9-]{1,63}$/;
const HOST = /^(?:[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*|\[[0-9a-f:.]{2,45}\])(?::[1-9][0-9]{0,4})?$/;
const MAX_HOST_CHARS = 255;
const MAX_PORT = 65_535;

// An agent's address, handle[.owner]~host, and an interaction type, such as quote/1. `splint` checks
// both again, and resolves the address at its own host.
const ADDRESS = new RegExp(`^[a-z0-9-]{1,63}(?:\\.[a-z0-9-]{1,63})?~${HOST.source.slice(1, -1)}$`);
// A type is named by its name and version, or by its ID with the fingerprint `types` shows.
const TYPE = /^[a-z0-9_]{1,24}\/[0-9]{1,4}(?:@[a-z2-7]{52})?$/;
const OWNER_ID = /^splint1[0-9a-f]{64}$/;
const ASK_ID = /^[0-9a-f]{32}$/;
// A place an owner gets paid, as `splint get-paid` takes one: no spaces, no leading `-`, and short.
const PLACE = /^(?!-)[\x21-\x7e]{3,620}$/;
// A request's ID, as the tools show it or whole, and the steps an owner says yes to, as `splint ask
// --step` takes them. `splint` resolves a shown one as `move` does.
const STEP_REQUEST = /^[0-9a-f]{8,64}$/;
// A signup code from whoever runs a host: one line of visible characters. `splint` reads it from stdin.
const SIGNUP_CODE = /^[\x21-\x7e]{1,256}$/;
const STEP_OPERATIONS = ["open", "counter", "accept", "deliver", "confirm", "cancel"];
// Each setting an ask can change, with the words `splint ask` takes for it.
const ASK_CHOICES: Record<string, string[]> = {
  // Ask me first, or go ahead: the two levels owners see. `splint ask --level full-auto` still works.
  level: ["ask-me", "auto"],
  quoted_prices: ["wait", "within-limits"],
  reach: ["contacts", "open", "filter"],
  writes: ["contacts", "replies"],
};

function addressFrom(value: unknown): string {
  if (typeof value !== "string" || !ADDRESS.test(value) || value.length > MAX_HOST_CHARS + 128) {
    throw new Refusal("an address is handle~host, such as ben~splint.example, in lower case");
  }
  return value;
}

/** The words `splint ask` takes for what an agent asks, each checked against its one closed set. */
function askWords(given: Record<string, unknown>): string[] {
  const words: string[] = [];
  for (const [name, allowed] of Object.entries(ASK_CHOICES)) {
    const value = given[name];
    if (value === undefined) continue;
    if (typeof value !== "string" || !allowed.includes(value)) {
      throw new Refusal(`${name} is one of ${allowed.join(", ")}`);
    }
    words.push(`--${name.replace("_", "-")}`, value);
  }
  if (given.types !== undefined) {
    if (!Array.isArray(given.types) || given.types.length === 0 || !given.types.every((type) => typeof type === "string" && TYPE.test(type))) {
      throw new Refusal("types are types you agreed, by name such as quote/1 or by the ID types shows");
    }
    words.push("--types", given.types.join(","));
  }
  if (given.filter !== undefined) {
    if (!Array.isArray(given.filter) || !given.filter.every((one) => one === "past" || (typeof one === "string" && OWNER_ID.test(one)))) {
      throw new Refusal("filter is owners' IDs, or past");
    }
    words.push("--filter", given.filter.join(","));
  }
  for (const name of ["contact", "remove", "block"]) {
    if (given[name] !== undefined) words.push(`--${name}`, addressFrom(given[name]));
  }
  for (const name of ["controls", "text", "wait"]) {
    if (given[name] === true) words.push(`--${name}`);
    else if (given[name] !== undefined && given[name] !== false) throw new Refusal(`${name} is true or false`);
  }
  if (given.step !== undefined) {
    const step = given.step as { request?: unknown; operation?: unknown };
    if (!step || typeof step !== "object" || typeof step.request !== "string" || !STEP_REQUEST.test(step.request)
      || typeof step.operation !== "string" || !STEP_OPERATIONS.includes(step.operation)) {
      throw new Refusal(`step is a request's id, as shown or whole, and one of ${STEP_OPERATIONS.join(", ")}`);
    }
    words.push("--step", step.request, step.operation);
  }
  if (given.paid_at !== undefined) {
    // Places as a person writes them, which `splint` reads as `get-paid` does and checks in full.
    if (!Array.isArray(given.paid_at) || given.paid_at.length === 0 || given.paid_at.length > 4
      || !given.paid_at.every((place) => typeof place === "string" && PLACE.test(place))) {
      throw new Refusal("paid_at is 1 to 4 places: an https payment page, a Lightning address or offer, or onchain:CHAIN:ADDRESS:ASSET");
    }
    for (const place of given.paid_at) words.push("--paid-at", place);
  }
  if (given.paused !== undefined) {
    if (typeof given.paused !== "boolean") throw new Refusal("paused is true or false");
    words.push(given.paused ? "--pause" : "--resume");
  }
  if (given.hours !== undefined) {
    if (!Number.isInteger(given.hours) || (given.hours as number) < 1 || (given.hours as number) > 24) {
      throw new Refusal("hours is a whole number from 1 to 24");
    }
    words.push("--hours", String(given.hours));
  }
  if (words.length === 0) throw new Refusal("say what to ask for");
  return words;
}

/** A word that starts with `-` would read as an option, whatever the protocol allows. */
function handleFrom(value: unknown): string {
  if (typeof value !== "string" || !HANDLE.test(value) || value.startsWith("-")) {
    throw new Refusal("a handle is up to 63 lower-case letters, digits and -, such as ana");
  }
  return value;
}

function hostFrom(value: unknown): string {
  const port = typeof value === "string" ? Number(/:(\d+)$/.exec(value)?.[1] ?? 0) : 0;
  if (typeof value !== "string" || !HOST.test(value) || value.length > MAX_HOST_CHARS || port > MAX_PORT || value.startsWith("-")) {
    throw new Refusal("a host is written as it was given, such as splint.example or 127.0.0.1:7001, in lower case");
  }
  return value;
}

/** A signup code as the person gave it, with only the whitespace a chat window adds taken off. */
function signupCodeFrom(value: unknown): string {
  const code = typeof value === "string" ? value.trim() : "";
  if (!SIGNUP_CODE.test(code)) {
    throw new Refusal("signup_code is the code whoever runs the host gave your person, on one line");
  }
  return code;
}

/**
 * Runs `splint` with fixed words and the adapter's own environment, where SPLINT_AS picks the
 * profile as it does for `splint`. Its stdin holds `input`, if any, and is then closed, so nothing
 * waits on a person. A code goes there, not in the words, as any user of this machine can list a
 * process's arguments.
 */
function splint(words: string[], input?: string): Promise<unknown> {
  const program = splintProgram();
  return new Promise((resolve, reject) => {
    const child = execFile(
      program,
      [...words, "--json"],
      { env: { ...process.env, NO_COLOR: "1" }, timeout: SPLINT_TIMEOUT_MS, maxBuffer: MAX_ANSWER_BYTES, encoding: "utf8" },
      (error, stdout) => {
        const answer = parsed(stdout.trim());
        if (typeof answer === "object" && answer !== null && !Array.isArray(answer)) {
          const failed = answer.error;
          if (failed === undefined) resolve(answer);
          else reject(new Refusal(`${failed?.kind ?? "failed"}: ${failed?.message ?? ""}`));
          return;
        }
        const missing = (error as NodeJS.ErrnoException | null)?.code === "ENOENT";
        reject(new Refusal(missing ? "splint isn't installed in ~/.splint/bin" : "splint gave no answer"));
      },
    );
    child.stdin?.end(input === undefined ? undefined : `${input}\n`);
  });
}

export const joiningTools: Tool[] = [
  {
    name: "join",
    description:
      "Get your address: handle is yours, host exactly as given. signup_code: one your person got from whoever runs a host that needs one, as signup_code_needed says.",
    inputSchema: {
      type: "object",
      properties: { handle: { type: "string" }, host: { type: "string" }, signup_code: { type: "string" } },
    },
    run: async (given) => {
      // A signup code goes on stdin, as `splint join` reads it.
      const signup = given.signup_code === undefined ? undefined : signupCodeFrom(given.signup_code);
      const at = [handleFrom(given.handle), hostFrom(given.host)];
      return signup === undefined ? splint(["join", ...at]) : splint(["join", ...at, "--with-code"], signup);
    },
  },
  {
    name: "status",
    description: "Your address, state, contacts, `next`, and `controls`: whether they're set, and how your person opens them. `listening`: whether anything hears a change for you now (`wait_held`, a `kept` listener), and when you last waited or read. `oldest_unread`: seconds your oldest unread note has waited. `held`: notes waiting at your host that can't be opened yet, and why.",
    inputSchema: { type: "object" },
    run: async () => splint(["status"]),
  },
  {
    name: "check",
    description: "Counts of what waits now: invites, unread notes, requests at your move, and what waits on your person or theirs. {} is nothing. Start here when woken.",
    inputSchema: { type: "object" },
    run: async () => splint(["check"]),
  },
  {
    name: "owner_link",
    description: "How your person opens their controls, as facts to present as suits them. To have them set up, `ask` with controls.",
    inputSchema: { type: "object" },
    run: async () => {
      const standing = (await splint(["status"])) as { controls?: unknown };
      return { controls: standing.controls ?? null };
    },
  },
  {
    name: "ask",
    description:
      "Ask your person for exactly these changes to how you deal with other agents, signed by your key, or with id, where one stands. controls asks them to set up their controls for you, and lasts an hour: ask again for a fresh link. While it waits, the answer has `computer_link` to hand them, which opens on Splint on their own computer; if Splint isn't there yet, guide them through installing it with `controls.install` from `status`, or `controls.install_on_windows`. Whoever approves first by it becomes your owner, and asking again ends the one before. step asks them to approve one step held for them, alone: the request's id as tools show it, or a hold's, and the step, as `ask_with` gives them. paid_at asks them to sign where they get paid, alone. Their one approval signs it, or nothing; you get nothing to use again. Explain why in your own words; nothing you write reaches the approval.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        controls: { type: "boolean" },
        level: { type: "string", enum: ASK_CHOICES.level },
        quoted_prices: { type: "string", enum: ASK_CHOICES.quoted_prices },
        reach: { type: "string", enum: ASK_CHOICES.reach },
        types: { type: "array", items: { type: "string" } },
        filter: { type: "array", items: { type: "string" } },
        writes: { type: "string", enum: ASK_CHOICES.writes },
        paused: { type: "boolean" },
        paid_at: { type: "array", items: { type: "string" }, maxItems: 4 },
        contact: { type: "string" },
        text: { type: "boolean" },
        remove: { type: "string" },
        block: { type: "string" },
        hours: { type: "integer", minimum: 1, maximum: 24 },
        wait: { type: "boolean" },
        step: {
          type: "object",
          properties: { request: { type: "string" }, operation: { type: "string", enum: STEP_OPERATIONS } },
          required: ["request", "operation"],
        },
      },
    },
    run: async (given) => {
      if (given.id !== undefined) {
        if (typeof given.id !== "string" || !ASK_ID.test(given.id)) throw new Refusal("an ask's id is 32 hex digits");
        return splint(["ask", given.id]);
      }
      return splint(["ask", ...askWords(given)]);
    },
  },
  {
    name: "finish",
    description: "After your person approved you on their controls page, take it up.",
    inputSchema: { type: "object" },
    run: async () => splint(["finish"]),
  },
];

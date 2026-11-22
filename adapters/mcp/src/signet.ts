// The adapter's only way out: HTTP to this agent's own Signet, on its socket on this machine.

import { closeSync, existsSync, openSync, readFileSync } from "node:fs";
import { request } from "node:http";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/** A short answer for the agent. It's fixed text or Signet's own, so it can't carry a secret. */
export class Refusal extends Error {}

export type Call = (method: "GET" | "POST", path: string, body?: object, timeoutMs?: number) => Promise<any>;

/**
 * Where this agent's Signet is and its token, or nothing yet. A socket in the agent's own folder is
 * reachable by this user alone. A port is for a Signet that can't serve a socket the agent reaches.
 */
type Found = { socket: string; token: string; lock?: string } | { origin: string; token: string };

/**
 * On Windows Signet's socket is a named pipe, whose name any user can see and, while Signet is stopped,
 * take. Signet holds its lock file open for as long as it runs, and while it does no other user can
 * make an instance of its pipe, so a call goes down the pipe only while that lock is held.
 */
const ON_WINDOWS = process.platform === "win32";

const TIMEOUT_MS = 15_000;
// For the calls Signet answers by reading a host page as it goes: up to two pages in one call, such as
// the inbox and the invites box, with 133 s each, as a flooded inbox's 32 MiB takes that long on a slow
// line. Under this, such a call ran out every time, and the agent could never read or clear its inbox.
const PAGE_TIMEOUT_MS = 300_000;
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);
const PROFILE_NAME = /^[a-z0-9][a-z0-9-]{0,31}$/;
const NOT_JOINED = "not joined yet: call join";
// Each starts with the word `splint --json` gives as its error's kind, so a runtime can act on it
// whatever the words say: "stopped" is the person's to undo, "signet_unreachable" is for starting
// Signet, and "signet_no_answer" is for checking before anything is sent again.
const STOPPED = "stopped: your person stopped Splint here with splint stop: leave it stopped, and tell them if you need it";
const EXPLICIT = ["SPLINT_SIGNET_SOCKET", "SPLINT_SIGNET_URL", "SPLINT_CURL_CONFIG", "SPLINT_API_TOKEN"] as const;

/**
 * `~/.splint`, as `splint` finds it from HOME, or USERPROFILE on Windows, which homedir() reads there,
 * so both name the same agent.
 */
export function splintRoot(): string {
  return join(homedir(), ".splint");
}

/** The installed `splint`, as `splint` itself names it in what it prints. */
export function splintProgram(): string {
  return join(splintRoot(), "bin", ON_WINDOWS ? "splint.exe" : "splint");
}

/**
 * Where this agent's Signet is. Named outright with SPLINT_SIGNET_SOCKET, or SPLINT_SIGNET_URL for a
 * port, it's fixed from the start. Otherwise it's whatever the agent's folder says on each call, the
 * default's or SPLINT_AS's profile's, as `splint` writes it there on joining, so a runtime's settings
 * name no socket and work before the agent has joined. Throws a message naming the setting that's
 * wrong, and never its value.
 */
export function signetFromEnv(env: NodeJS.ProcessEnv): Call {
  if (env.SPLINT_AS) {
    const explicit = EXPLICIT.find((name) => env[name]);
    if (explicit) throw new Error(`set SPLINT_AS or ${explicit}, not both`);
    if (!PROFILE_NAME.test(env.SPLINT_AS)) throw new Error("SPLINT_AS must be a profile's name, as splint profiles lists them");
  }
  if (env.SPLINT_SIGNET_SOCKET && env.SPLINT_SIGNET_URL) {
    throw new Error("set SPLINT_SIGNET_SOCKET or SPLINT_SIGNET_URL, not both");
  }
  if (findsItsOwnAgent(env)) {
    if (env.SPLINT_CURL_CONFIG || env.SPLINT_API_TOKEN) throw new Error("SPLINT_SIGNET_SOCKET is required with a token");
    const folder = env.SPLINT_AS ? join(splintRoot(), "profiles", env.SPLINT_AS) : splintRoot();
    return signetAt(() => foundIn(folder), env.SPLINT_AS ? `--as ${env.SPLINT_AS} start` : "start");
  }
  const token = env.SPLINT_CURL_CONFIG ? tokenIn(env.SPLINT_CURL_CONFIG, Error) : env.SPLINT_API_TOKEN;
  if (!token) throw new Error("SPLINT_API_TOKEN or SPLINT_CURL_CONFIG is required");
  if (env.SPLINT_SIGNET_SOCKET) {
    if (ON_WINDOWS && !env.SPLINT_SIGNET_LOCK) throw new Error("SPLINT_SIGNET_LOCK is required with SPLINT_SIGNET_SOCKET on Windows, as agent.env sets it");
    const found = { socket: env.SPLINT_SIGNET_SOCKET, token, lock: env.SPLINT_SIGNET_LOCK };
    return signetAt(() => found);
  }
  // A token file `splint` wrote names its Signet's socket, so the token goes there and to no port, as
  // curl sends it. Settings from before the socket name a port that anything may hold now.
  const socket = env.SPLINT_CURL_CONFIG ? socketIn(env.SPLINT_CURL_CONFIG) : undefined;
  if (socket && !ON_WINDOWS) {
    process.stderr.write("SPLINT_SIGNET_URL isn't used, as this agent's token file names its Signet's socket. splint connect prints the settings to use now.\n");
    const found = { socket, token };
    return signetAt(() => found);
  }
  const found = { origin: localOrigin(env.SPLINT_SIGNET_URL ?? "", Error), token };
  // A setting that weakens a check is said whenever it's on.
  process.stderr.write(
    "Warning: SPLINT_SIGNET_URL sends this agent's token to a port, where any program that takes it while Signet is stopped hears it. Use SPLINT_SIGNET_SOCKET unless Signet can only listen on a port.\n",
  );
  return signetAt(() => found);
}

/** Whether this adapter finds its agent the way `splint` does, so `splint` can join for it. */
export function findsItsOwnAgent(env: NodeJS.ProcessEnv): boolean {
  return !env.SPLINT_SIGNET_SOCKET && !env.SPLINT_SIGNET_URL;
}

/** Read again on each call, so an agent that just joined is found. */
function foundIn(folder: string): Found {
  let text: string;
  try {
    text = readFileSync(join(folder, "agent.env"), "utf8");
  } catch {
    throw new Refusal(NOT_JOINED);
  }
  const setting = (key: string) => new RegExp(`^export ${key}=(.+)$`, "m").exec(text)?.[1];
  const socket = setting("SPLINT_SIGNET_SOCKET");
  const curl = setting("SPLINT_CURL_CONFIG");
  const lock = setting("SPLINT_SIGNET_LOCK");
  if (!socket || !curl || (ON_WINDOWS && !lock)) throw new Refusal("this agent's agent.env can't be read: run splint start");
  const token = tokenIn(curl, Refusal);
  if (!token) throw new Refusal("this agent's token file can't be read: run splint start");
  return { socket, token, lock };
}

/** The file `splint` writes, so a token never has to sit in a runtime's settings. */
function tokenIn(path: string, Failure: new (message: string) => Error): string | undefined {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new Failure("SPLINT_CURL_CONFIG can't be read");
  }
  return /^header = "Authorization: Bearer ([^"]+)"$/m.exec(text)?.[1];
}

/** The socket a token file names, as `splint` writes it: quoted, with `\` and `"` escaped. */
function socketIn(path: string): string | undefined {
  const quoted = /^unix-socket = "((?:[^"\\]|\\.)*)"$/m.exec(readFileSync(path, "utf8"))?.[1];
  return quoted?.replace(/\\(.)/g, "$1");
}

/** The token goes in plain HTTP, so it may only go to this machine. */
function localOrigin(value: string, Failure: new (message: string) => Error): string {
  const refused = new Failure("SPLINT_SIGNET_URL must be http:// on this machine, such as http://127.0.0.1:7100");
  if (!URL.canParse(value)) throw refused;
  const url = new URL(value);
  const local = url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if (!local || url.username || url.password) throw refused;
  return url.origin;
}

/** One call, with no redirect followed, as a 3xx is only a failed answer here. */
function send(found: Found, method: string, path: string, body: object | undefined, timeoutMs: number): Promise<{ status: number; text: string }> {
  const headers = { Authorization: `Bearer ${found.token}`, "Content-Type": "application/json" };
  let where;
  if ("socket" in found) {
    // The name is only what the request says: the socket is where it goes, and nothing resolves it.
    where = { socketPath: found.socket, host: "signet", path };
  } else {
    const url = new URL(path, found.origin);
    where = { hostname: url.hostname.replace(/^\[|\]$/g, ""), port: url.port, path: url.pathname + url.search };
  }
  return new Promise((resolve, reject) => {
    const call = request({ ...where, method, headers }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("error", reject);
      response.on("end", () => resolve({ status: response.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
    });
    const timer = setTimeout(() => call.destroy(new Error("timed out")), timeoutMs);
    call.on("close", () => clearTimeout(timer));
    call.on("error", reject);
    call.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

/**
 * Whether Signet holds its lock: while it runs nothing else can open the file to write, which Node
 * reports as EBUSY. A file that opens, or isn't there, is a Signet that isn't running.
 */
function signetHolds(lock: string): boolean {
  try {
    closeSync(openSync(lock, "r+"));
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EBUSY";
  }
}

/** How long a call may take: longer for one Signet answers by reading a host page. */
function deadlineFor(method: string, path: string): number {
  const readsAPage =
    method === "GET"
      ? path === "/v0/inbox" || path === "/v0/invites"
      : path === "/v0/inbox/ack" || /^\/v0\/invites\/[^/]+\/(accept|decline)$/.test(path);
  return readsAPage ? PAGE_TIMEOUT_MS : TIMEOUT_MS;
}

/**
 * What an agent is told when its Signet doesn't answer, as distinct from nothing waiting: that it isn't
 * running, and how to start it. `splint start` keeps Signet's keeper through an outage,
 * and a stop by the person is told apart, as `stopped`, so this never sends an agent to undo one.
 */
function unreachableWords(start: string): string {
  // Named as `splint` names itself.
  let program = "splint";
  try {
    program = splintProgram();
  } catch {
    // With no home folder its name alone still says what to run.
  }
  return `signet_unreachable: this agent's Signet isn't running, so nothing was read or sent. Start it with ${program} ${start}, then call again: what waits for you at your host is kept until it's read or expires, usually a week after it was sent.`;
}

/**
 * What an agent is told when Signet took the call and then didn't answer it in time, or dropped it: it may
 * have gone through, so a note or a request isn't sent twice by calling again blind.
 */
const NO_ANSWER =
  "signet_no_answer: this agent's Signet took the call but didn't answer it in time, so it may have gone through: before sending, opening or moving it again, check with delivery or requests. A read can just be tried again.";

/** Only a call that never connected surely wasn't read: Node names `connect` on that error alone. */
function neverConnected(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | undefined)?.syscall === "connect";
}

function signetAt(find: () => Found, start = "start, for this agent"): Call {
  return async (method, path, body, timeoutMs = deadlineFor(method, path)) => {
    const found = find();
    // `splint stop` leaves its mark in the agent's run folder, beside Signet's socket on Unix and
    // beside Signet's own folder on Windows, and only the person who stopped it starts it.
    const stoppedMark = "socket" in found && (ON_WINDOWS ? found.lock && join(dirname(dirname(found.lock)), "run", "stopped") : join(dirname(found.socket), "stopped"));
    const unreachable = () => new Refusal(stoppedMark && existsSync(stoppedMark) ? STOPPED : unreachableWords(start));
    if (ON_WINDOWS && "socket" in found && !(found.lock && signetHolds(found.lock))) throw unreachable();
    let answered: { status: number; text: string };
    try {
      answered = await send(found, method, path, body, timeoutMs);
    } catch (error) {
      const stopped = stoppedMark && existsSync(stoppedMark);
      throw stopped || neverConnected(error) ? unreachable() : new Refusal(NO_ANSWER);
    }
    const answer = parsed(answered.text);
    const ok = answered.status >= 200 && answered.status < 300;
    if (!ok) throw new Refusal(`${answered.status}: ${refusalWords(answer)}`);
    if (answer === undefined) throw new Refusal("Signet's answer can't be read");
    return answer;
  };
}

/** A refusal's word, with Signet's own fixed words on what to do about it when it gives them. */
function refusalWords(answer: any): string {
  const word = typeof answer?.error === "string" ? answer.error : "invalid arguments";
  const whatToDo = [answer?.ask_your_owner, answer?.invite_with, answer?.what_to_do].find((words) => typeof words === "string");
  return whatToDo === undefined ? word : `${word}: ${whatToDo}`;
}

export function parsed(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

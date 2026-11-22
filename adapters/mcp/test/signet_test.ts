// The adapter's own deadlines, against a Signet on a socket here that answers when this test says.
// Timers are mocked, so the clock moves only when the test moves it, and nothing waits on the real one.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mock, test } from "node:test";

import { Refusal, signetFromEnv } from "../src/signet.ts";

// A flooded inbox's page on a slow line takes Signet minutes to read, and the agent's call to it ran
// out after 15 s every time, so the agent could never read or clear its inbox.
test("the agent waits while Signet reads a page on a slow line", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "splint-slow-page-"));
  const socket = join(dir, "signet.sock");
  let came = () => {};
  const arrived = new Promise<void>((resolve) => (came = resolve));
  const server = createServer((_request, response) => {
    came();
    // 32 MiB at 256 KiB a second, as Signet's own page deadline allows.
    setTimeout(() => response.end(JSON.stringify({ messages: [] })), 130_000);
  });
  await new Promise<void>((resolve) => server.listen(socket, resolve));
  mock.timers.enable({ apis: ["setTimeout"] });
  t.after(() => {
    mock.timers.reset();
    server.closeAllConnections();
    server.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const signet = signetFromEnv({ SPLINT_SIGNET_SOCKET: socket, SPLINT_API_TOKEN: "not a real token" });
  const page = signet("GET", "/v0/inbox");
  await arrived;
  mock.timers.tick(130_000);
  assert.deepEqual(await page, { messages: [] });
});

// Issue 734. Bug caught: with Signet not running the agent heard only "can't reach Signet", with
// nothing to act on, and its runtime couldn't tell that from any other refusal.
test("an agent whose Signet isn't running is told so by kind, and how to start it", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "splint-no-signet-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const signet = signetFromEnv({ SPLINT_SIGNET_SOCKET: join(dir, "signet.sock"), SPLINT_API_TOKEN: "not a real token" });
  await assert.rejects(signet("GET", "/v0/inbox"), (refused: Error) => {
    assert.ok(refused instanceof Refusal);
    assert.match(refused.message, /^signet_unreachable: /);
    assert.match(refused.message, /splint start/);
    return true;
  });
});

// Bug caught: an agent was told "nothing was read or sent, call again" when Signet had taken the whole
// send and only its answer failed, so the note went out twice.
test("an agent whose call Signet took but never answered is told it may have gone", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "splint-no-answer-"));
  const socket = join(dir, "signet.sock");
  // Takes the whole call in, then drops it with no answer, as a Signet that stops mid-call does.
  const server = createServer((request) => request.resume().on("end", () => request.socket.destroy()));
  await new Promise<void>((resolve) => server.listen(socket, resolve));
  t.after(() => {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const signet = signetFromEnv({ SPLINT_SIGNET_SOCKET: socket, SPLINT_API_TOKEN: "not a real token" });
  await assert.rejects(signet("POST", "/v0/send", { to: "ben~host.example", text: "hi" }), (refused: Error) => {
    assert.ok(refused instanceof Refusal);
    assert.match(refused.message, /^signet_no_answer: /);
    return true;
  });
});

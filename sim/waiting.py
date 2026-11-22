#!/usr/bin/env python3
"""Hearing of something new as it comes, with real hosts, Signets and Postgres.

Issue 240: every Signet asked its host for its inbox every 2 seconds, however quiet it was. Issue 573: an
agent heard of a step only by asking Signet again and again. Now a host holds a Signet's call until
something comes for its agent, and Signet holds an agent's call until something comes for it.

The agents here ask on their own only every 30 seconds, so anything faster is the held call. Each
claim has a control: the same host made to hold nothing, with everything else the same.

For what a host that misbehaves does to a Signet, a stand-in sits where Signets reach host a and passes
everything through, apart from the one fault a scenario turns on.

What this can't show: hundreds of real Signets holding calls over the internet, through a real proxy.
The Rust test in the host's `waits` holds 600 through the real call limits on one machine.
"""

import contextlib
import hashlib
import http.client
import json
import queue
import sys
import threading
import time
from collections import Counter
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import e2e
from e2e import check, message_id_of, sign_jws, wait_until
from request_driver import hours_from_now, open_request, signed_step, view

# Long enough that a Signet asking on its own can't pass for one that was told.
ASKS_EVERY_MILLIS = 30_000
SOON_SECS = 5
IDLE_SECS = 12
HOLD_SECS = 25
# For the Signets behind the stand-in for their host, so falling back to asking is quick to see.
PROXIED_ASKS_EVERY_MILLIS = 2_000
# Signet waits at least 50 ms between looks, so 5 s holds 100 at most.
WINDOW_SECS = 5


def inbox_reads(net: e2e.Network, host: str) -> int:
    """How often Postgres has read this host's inbox table, which every look at an inbox does."""
    net.postgres.sql(f"host_{host}", "SELECT pg_stat_clear_snapshot()")
    counted = net.postgres.sql(
        f"host_{host}",
        "SELECT coalesce(seq_scan, 0) + coalesce(idx_scan, 0) FROM pg_stat_user_tables WHERE relname = 'inbox'",
    )
    return int(counted)


def reads_while_idle(net: e2e.Network, host: str) -> int:
    # Postgres counts reads a moment after they happen, so the window is generous at both ends.
    time.sleep(2)
    before = inbox_reads(net, host)
    time.sleep(IDLE_SECS)
    return inbox_reads(net, host) - before


def held_wait(net: e2e.Network, key, agent_id: str, since: int | None, source: str | None = None) -> tuple[int, dict, float]:
    """A wait as a Signet sends it, signed with this agent's key: its status, answer and how long it took.
    `source` is what a host's proxy would say it came from."""
    body = json.dumps({"since": since}).encode()
    proof = {
        "signer": agent_id, "host": net.domain["a"], "method": "POST", "path": "/v0/wait",
        "body_sha256": hashlib.sha256(body).hexdigest(), "issued_at": int(time.time()),
    }
    auth = sign_jws(key, "splint-access", json.dumps(proof).encode())
    host, port = net.domain["a"].split(":")
    connection = http.client.HTTPConnection(host, int(port), timeout=HOLD_SECS + 15)
    started = time.monotonic()
    try:
        headers = {"Authorization": f"Splint {auth}", "Content-Type": "application/json"}
        if source:
            headers["X-Forwarded-For"] = source
        connection.request("POST", "/v0/wait", body=body, headers=headers)
        answer = connection.getresponse()
        text = answer.read()
        return answer.status, json.loads(text or b"{}"), time.monotonic() - started
    finally:
        connection.close()


def as_signet(net: e2e.Network, agent: str, method: str, path: str, body: object = None) -> tuple[int, dict, float]:
    """A call to this agent's host as its Signet makes it, signed with the agent's key: its status, answer
    and how long it took."""
    raw = b"" if body is None else json.dumps(body).encode()
    domain = net.domain[net.home[agent]]
    proof = {
        "signer": net.ids[agent], "host": domain, "method": method, "path": path,
        "body_sha256": hashlib.sha256(raw).hexdigest(), "issued_at": int(time.time()),
    }
    auth = sign_jws(net.key_of(agent), "splint-access", json.dumps(proof).encode())
    host, port = domain.split(":")
    connection = http.client.HTTPConnection(host, int(port), timeout=HOLD_SECS + 15)
    started = time.monotonic()
    try:
        connection.request(method, path, body=raw or None, headers={"Authorization": f"Splint {auth}", "Content-Type": "application/json"})
        answer = connection.getresponse()
        text = answer.read()
        return answer.status, json.loads(text or b"{}"), time.monotonic() - started
    finally:
        connection.close()


def restart_with(net: e2e.Network, host: str, settings: dict[str, str]) -> None:
    net.hosts[host].env.update(settings)
    net.restart_host(host)


def wake_on_host_a(net: e2e.Network, agent_id: str) -> None:
    """What Postgres tells host a when something comes for this agent, to end its held calls."""
    net.postgres.sql("host_a", f"SELECT pg_notify('splint_wake', '{agent_id}')")


def agent_waits(net: e2e.Network, agent: str, body: dict) -> queue.Queue:
    """An agent's wait on its Signet, in the background: the answer and when it came."""
    answered: queue.Queue[tuple[float, tuple[int, dict]]] = queue.Queue()
    threading.Thread(target=lambda: answered.put((time.monotonic(), net.agent(agent, "POST", "/v0/wait", body))), daemon=True).start()
    return answered


def register_without_signet(net: e2e.Network, name: str) -> tuple[object, str]:
    owner = e2e.new_owner(net.work / f"{name}-owner")
    key = net.work / f"{name}.key"
    identity, agent_id = e2e.new_identity(key)
    if net.register_on_a(key, owner, name, identity, agent_id) != 200:
        raise RuntimeError(f"{name} didn't register")
    return key, agent_id


class HomeHostStandIn:
    """Stands where Signets reach host a and passes every call to it, apart from what a scenario says
    to do instead: answer waits itself, as a broken or hostile host might, or turn away what Signet
    hands it as busy. With none, it changes nothing."""

    def __init__(self, port: int, behind: str) -> None:
        self.answer_waits = None
        self.busy = False
        self.waits: Counter[str] = Counter()
        self.holding: Counter[str] = Counter()
        stand_in = self
        backend_host, backend_port = behind.split(":")

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def reply(self, status: int, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def forward(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                signer = ""
                if self.path == "/v0/wait":
                    signer = e2e.payload_of(self.headers.get("Authorization", "").removeprefix("Splint ")).get("signer", "")
                    stand_in.waits[signer] += 1
                    if stand_in.answer_waits:
                        self.reply(200, json.dumps(stand_in.answer_waits()).encode())
                        return
                if self.path == "/v0/outbound" and stand_in.busy:
                    self.reply(429, b'{"error":"try again"}')
                    return
                connection = http.client.HTTPConnection(backend_host, int(backend_port), timeout=HOLD_SECS + 15)
                stand_in.holding[signer] += 1
                try:
                    headers = {name: value for name, value in self.headers.items() if name.lower() not in ("connection", "content-length")}
                    connection.request(self.command, self.path, body=body or None, headers=headers)
                    answer = connection.getresponse()
                    data = answer.read()
                except OSError:
                    # Host a is restarting, as a proxy in front of one would see it.
                    self.reply(502, b'{"error":"host unreachable"}')
                    return
                finally:
                    stand_in.holding[signer] -= 1
                    connection.close()
                self.send_response(answer.status)
                for name, value in answer.getheaders():
                    if name.lower() not in ("connection", "content-length", "transfer-encoding"):
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = forward

            def log_message(self, *_args) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def waits_from(self, agent_id: str, seconds: float) -> int:
        before = self.waits[agent_id]
        time.sleep(seconds)
        return self.waits[agent_id] - before

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@contextlib.contextmanager
def host_a_behind_a_stand_in(net: e2e.Network) -> Iterator[HomeHostStandIn]:
    """Host a moves to another port, and a stand-in takes its place, where everyone still reaches it."""
    host, domain = net.hosts["a"], net.domain["a"]
    host.kill_hard()
    behind = f"127.0.0.1:{e2e.free_port()}"
    host.env["SPLINT_LISTEN"] = behind
    stand_in = HomeHostStandIn(net.host_port["a"], behind)
    try:
        host.start()
        net.wait_for_host("a")
        yield stand_in
    finally:
        host.kill_hard()
        stand_in.close()
        host.env["SPLINT_LISTEN"] = domain
        host.start()
        net.wait_for_host("a")


def a_step_arrives_as_soon_as_it_lands(net: e2e.Network) -> None:
    waited: queue.Queue[tuple[float, tuple[int, dict]]] = queue.Queue()
    started = time.monotonic()
    def waiting() -> None:
        answer = net.agent("wben", "POST", "/v0/wait", {"seconds": 9})
        waited.put((time.monotonic(), answer))

    threading.Thread(target=waiting, daemon=True).start()
    time.sleep(1)
    opened = time.monotonic()
    request = open_request(net, "wana", "wben")
    taken = wait_until(lambda: view(net, "wben", request).get("state") == "offered", SOON_SECS)
    check(f"wben's Signet takes wana's request within {SOON_SECS} s, though it asks on its own only every 30", taken, view(net, "wben", request))
    check(
        "and wana's sees it was received, the same way",
        wait_until(lambda: (view(net, "wana", request).get("delivery") or {}).get("received") is True, SOON_SECS),
        view(net, "wana", request),
    )
    ended, (status, answer) = waited.get(timeout=15)
    check(
        f"an agent waiting on wben's Signet hears of it {ended - opened:.1f} s after wana asked to open it, and that it's a request",
        status == 200 and "requests" in answer.get("new", []) and ended - started < 9,
        (status, answer),
    )


def an_agents_own_move_doesnt_wake_it(net: e2e.Network) -> None:
    """Review of PR 593: the receipt for an agent's own move woke it, so a watcher started a turn after
    every turn that moved."""
    answered = agent_waits(net, "wana", {"seconds": 8})
    time.sleep(1)
    request = open_request(net, "wana", "wben")
    received = wait_until(lambda: (view(net, "wana", request).get("delivery") or {}).get("received") is True, SOON_SECS)
    check("control: wana's request reaches wben, and wben's receipt comes back", received, view(net, "wana", request))
    _, (status, answer) = answered.get(timeout=15)
    check("and wana's wait, from before she moved, ends after its time with nothing new", status == 200 and answer.get("new") == [], (status, answer))


def a_note_and_the_owners_word_each_wake_an_agent(net: e2e.Network) -> None:
    """Review of PR 593: nothing showed a note or the owner's word wakes an agent, that a step left on
    the host while the rules said stop is taken as soon as the owner lifts it, or that a step put off
    comes back as soon as it's due rather than when a hold ends, up to 25 s later."""
    answered = agent_waits(net, "wben", {"seconds": 9})
    time.sleep(1)
    net.send("wana", "wben", "w: a note while wben waits")
    _, (status, answer) = answered.get(timeout=15)
    check("a note to wben ends its wait, and says it was a note", status == 200 and answer.get("new") == ["messages"], (status, answer))
    net.ack_all("wben")
    talk = net.agent("wana", "POST", "/v0/requests", {"contact": net.address("wben"), "deadline": hours_from_now(2), "supersedes": None})[1]["request"]
    check("control: wben has wana's conversation", wait_until(lambda: view(net, "wben", talk).get("state") == "talking", SOON_SECS), view(net, "wben", talk))

    stopped = net.put_rules("wben", net.sign_rules("wben", [net.contact_entry("wana")], paused=True))
    check("control: wben's owner stops it", stopped[0] == 200, stopped)
    # Its Signet hears at once, and tells its host, which then holds back what comes.
    time.sleep(2)
    request = open_request(net, "wana", "wben")
    # Two lines, the second first, which wben's Signet takes together once it can, so it has to put the
    # second off until after the first.
    first = signed_step(net, "wana", "wana", "wben", {"step": "say", "request": talk, "prev": talk, "fields": {"text": "first"}})
    second = signed_step(net, "wana", "wana", "wben", {"step": "say", "request": talk, "prev": message_id_of(first), "fields": {"text": "second"}})
    check("control: wana's second line reaches host b before the first it follows", delivered_to_b(net, "wana", second) == 200 and delivered_to_b(net, "wana", first) == 200)
    waiting = lambda: net.postgres.sql("host_b", f"SELECT count(*) FROM inbox WHERE recipient = '{net.ids['wben']}' AND NOT acked")  # noqa: E731
    landed = wait_until(lambda: waiting() == "3", SOON_SECS)
    check("control: wana's next request and both lines wait on host b", landed and view(net, "wben", request).get("state") is None, waiting())
    answered = agent_waits(net, "wben", {"seconds": 9})
    lifting = net.sign_rules("wben", [net.contact_entry("wana")])
    # Just after a second starts, since a host puts a step off until a whole second, so the second
    # line isn't in sight again before wben's Signet has finished its look.
    time.sleep(2 - time.time() % 1)
    lifted = net.put_rules("wben", lifting)
    check("control: the owner lifts the stop", lifted[0] == 200, lifted)
    _, (status, answer) = answered.get(timeout=15)
    check("an agent waiting hears the owner's word", status == 200 and "owner" in answer.get("new", []), (status, answer))
    taken = wait_until(lambda: view(net, "wben", request).get("state") == "offered", SOON_SECS)
    check(f"and wben's Signet takes the request that waited within {SOON_SECS} s, though nothing new came", taken, view(net, "wben", request))
    said = lambda: len(view(net, "wben", talk).get("messages") or [])  # noqa: E731
    check(f"and both lines within {SOON_SECS} s, the one it put off as soon as it was due", wait_until(lambda: said() == 2, SOON_SECS), view(net, "wben", talk))


def a_step_put_off_that_comes_due_before_a_wait_ends_it(net: e2e.Network) -> None:
    """In the final test pass, sim/outbound_text.py saw a step a Signet put off still on its host 30 s
    after it was due: the Signet looked, the step came due, and only then did the Signet ask to wait,
    so its host held the call the whole 25 s with nothing new, and the Signet looked again only after
    12 such quiet holds. This makes that order by wcal's key, with its Signet stopped. Bug caught: a
    step coming back into sight didn't move its agent's mark, so a wait that started after it came due
    never heard of it."""
    net.add_owned_agents({"wdan": "a", "wcal": "b"}, sync_millis=ASKS_EVERY_MILLIS)
    talk = net.agent("wdan", "POST", "/v0/requests", {"contact": net.address("wcal"), "type": "chat/1", "deadline": hours_from_now(2), "supersedes": None})[1]["request"]
    check("control: wcal has wdan's conversation", wait_until(lambda: view(net, "wcal", talk).get("state") == "talking"), view(net, "wcal", talk))
    net.signets["wcal"].kill_hard()
    # A line following one that never comes, so a Signet can only put it off.
    unknown = message_id_of(signed_step(net, "wdan", "wdan", "wcal", {"step": "say", "request": talk, "prev": talk, "fields": {"text": "never sent"}}))
    stuck = signed_step(net, "wdan", "wdan", "wcal", {"step": "say", "request": talk, "prev": unknown, "fields": {"text": "after it"}})
    check("control: a line following one that never came reaches host b", delivered_to_b(net, "wdan", stuck) == 200)
    in_sight = lambda: [row["seq"] for row in as_signet(net, "wcal", "GET", "/v0/inbox")[1].get("messages", []) if row.get("envelope") == stuck]  # noqa: E731
    seqs = in_sight()
    status, _, _ = as_signet(net, "wcal", "POST", "/v0/inbox/later", {"seqs": seqs})
    check("control: wcal's host puts it off as its Signet asks", status == 200 and len(seqs) == 1 and in_sight() == [], (status, seqs))
    status, first, _ = as_signet(net, "wcal", "POST", "/v0/wait", {"since": None})
    check("control: a wait with no mark answers at once with one", status == 200 and isinstance(first.get("since"), int), (status, first))
    # A first put-off lasts until the next whole second, so this is past it.
    time.sleep(2.5)
    status, answer, took = as_signet(net, "wcal", "POST", "/v0/wait", {"since": first.get("since")})
    check(f"a wait that starts after a step it put off came due answers at once, not {HOLD_SECS} s later", status == 200 and answer.get("new") is True and took < SOON_SECS, (status, answer, round(took, 1)))
    check("and the step is in sight again", in_sight() == seqs, in_sight())


def delivered_to_b(net: e2e.Network, sender: str, envelope: str) -> int:
    """What host a does with one of its agents' envelopes, without the agent's Signet."""
    proof = net.host_proof(net.work / "host-a.key", envelope, net.domain["a"], net.domain["b"])
    fields = {"envelope": envelope, "sender_identity": net.agent_identity(sender), "from_host": net.domain["a"], "proof": proof}
    return e2e.http("POST", f"http://{net.domain['b']}/v0/deliver", fields)[0]


def a_quiet_signet_hardly_looks(net: e2e.Network) -> int:
    reads = reads_while_idle(net, "b")
    # Before, Ben's Signet alone looked 10 times a second here. Now each Signet looks once a hold, and
    # the cleanup job reads the table once a second.
    check(f"with nothing coming, host b's inbox was read {reads} times in {IDLE_SECS} s", reads <= 2 * IDLE_SECS, reads)
    return reads


def an_agent_can_hold_only_so_many_waits(net: e2e.Network) -> None:
    """A fooled agent could open waits until its Signet ran out of room."""
    answers = [agent_waits(net, "wben", {"seconds": 3}) for _ in range(16)]
    time.sleep(1)
    status, _ = net.agent("wben", "POST", "/v0/wait", {"seconds": 1})
    check("with 16 of an agent's waits held, Signet turns away the next", status == 429, status)
    check("control: those 16 end as usual", all(answer.get(timeout=10)[1][0] == 200 for answer in answers))
    status, _ = net.agent("wben", "POST", "/v0/wait", {"seconds": 1})
    check("and then another can wait", status == 200, status)


def a_held_call_has_limits_of_its_own(net: e2e.Network) -> None:
    owner = e2e.new_owner(net.work / "holder-owner")
    key = net.work / "holder.key"
    identity, agent_id = e2e.new_identity(key)
    check("an agent with no Signet registers on host a", net.register_on_a(key, owner, "holder", identity, agent_id) == 200)
    # Two calls at once in all, so a held call that kept its place would stop everything.
    restart_with(net, "a", {"SPLINT_MAX_CALLS_AT_ONCE": "2"})
    # A host that has just started moves every mark once it hears from Postgres, which takes a moment.
    time.sleep(2)
    status, first, took = held_wait(net, key, agent_id, None)
    check("a first wait, with no mark, answers at once with one", status == 200 and first.get("new") is True and took < 2, (status, first))
    held: queue.Queue[tuple[int, dict, float]] = queue.Queue()
    for _ in range(2):
        threading.Thread(target=lambda: held.put(held_wait(net, key, agent_id, first["since"])), daemon=True).start()
    time.sleep(2)
    check("waiting from that mark, two are held", held.empty())
    status, _, took = held_wait(net, key, agent_id, first["since"])
    check("a third for the same agent is refused at once", status == 429 and took < 2, status)
    answered = wait_until(lambda: e2e.http("GET", f"http://{net.domain['a']}/.well-known/splint/host")[0] == 200, 3)
    check("and with both held, a host that takes two calls at once still answers others", answered)
    ends = [held.get(timeout=HOLD_SECS + 15) for _ in range(2)]
    check(
        f"with nothing coming, each held one ends after about {HOLD_SECS} s, saying so",
        all(status == 200 and answer.get("new") is False and HOLD_SECS - 2 < took < HOLD_SECS + 5 for status, answer, took in ends),
        ends,
    )
    # Review of PR 593: one count for the whole host made the gap between two of an agent's marks how
    # much had come for everyone else meanwhile, and a mark said when the host started.
    mark = ends[0][1]["since"]
    for _ in range(7):
        wake_on_host_a(net, net.ids["wana"])
    wake_on_host_a(net, agent_id)
    after_others = held_wait(net, key, agent_id, mark)[1]["since"]
    wake_on_host_a(net, agent_id)
    after_none = held_wait(net, key, agent_id, after_others)[1]["since"]
    check("an agent's marks move as much whether 7 things came for another agent or none", after_others - mark == after_none - after_others, (mark, after_others, after_none))
    check("and a mark says nothing of when the host started", abs(mark - time.time() * 1000) > 86_400_000, mark)
    restart_with(net, "a", {"SPLINT_MAX_CALLS_AT_ONCE": "128"})


def held_calls_from_one_source(net: e2e.Network) -> None:
    """Review of PR 593: nothing showed a held call gives back its place among its source's calls, and
    one source holding many agents' calls could take every place."""
    agents = [register_without_signet(net, name) for name in ("giver", "taker", "third")]
    # One call at once from a source, so a held one that kept its place would stop that source. 16
    # connections hold 8 calls at most, whatever SPLINT_MAX_WAITS_AT_ONCE says, so 4 from one source.
    restart_with(net, "a", {"SPLINT_MAX_CALLS_AT_ONCE_PER_SOURCE": "1", "SPLINT_MAX_CONNECTIONS": "16"})
    time.sleep(2)
    here, there = "198.51.100.7", "203.0.113.9"
    marks = {agent: held_wait(net, key, agent, None, there)[1]["since"] for key, agent in agents}
    held: queue.Queue[tuple[int, dict, float]] = queue.Queue()
    for key, agent in agents[:2]:
        for _ in range(2):
            threading.Thread(target=lambda key=key, agent=agent: held.put(held_wait(net, key, agent, marks[agent], here)), daemon=True).start()
            time.sleep(0.3)
    time.sleep(1)
    check("one source can have four calls held, though it may have only one call at once", held.empty(), list(held.queue))
    check("and with them held, other calls from it still get through", status_from(net, here) == 200)
    key, agent = agents[2]
    status, _, took = held_wait(net, key, agent, marks[agent], here)
    check("but past half the calls the host can hold, that source's next is turned away at once", status == 429 and took < 2, status)
    threading.Thread(target=lambda: held.put(held_wait(net, key, agent, marks[agent], there)), daemon=True).start()
    time.sleep(1.5)
    check("and another source's is held", held.empty(), list(held.queue))
    for _, agent in agents:
        wake_on_host_a(net, agent)
    ends = [held.get(timeout=10) for _ in range(5)]
    check("control: something coming ends each at once, saying so", all(status == 200 and answer.get("new") is True for status, answer, _ in ends), ends)
    restart_with(net, "a", {"SPLINT_MAX_CALLS_AT_ONCE_PER_SOURCE": "32", "SPLINT_MAX_CONNECTIONS": "4096"})


def status_from(net: e2e.Network, source: str) -> int:
    """A call to host a that its proxy says came from `source`."""
    connection = http.client.HTTPConnection(*net.domain["a"].split(":"), timeout=10)
    try:
        connection.request("GET", "/.well-known/splint/host", headers={"X-Forwarded-For": source})
        return connection.getresponse().status
    finally:
        connection.close()


def a_signet_behind_a_host_that_misbehaves(net: e2e.Network) -> None:
    """Review of PR 593: a host answering each wait at once with nothing new had Signet call it with
    no pause, and a step its host turned away waited for a hold to end, not SPLINT_SYNC_MILLIS."""
    net.add_owned_agents({"pana": "a", "pben": "b"}, sync_millis=PROXIED_ASKS_EVERY_MILLIS)
    pana = net.ids["pana"]
    with host_a_behind_a_stand_in(net) as stand_in:
        check("control: pana's Signet waits on its host through the stand-in", wait_until(lambda: stand_in.waits[pana] > 0, SOON_SECS), stand_in.waits)
        # A note makes pana's Signet look, so its next held call starts now.
        net.send("pben", "pana", "p: so a hold starts now")
        check("control: the note arrives", wait_until(lambda: "p: so a hold starts now" in net.bodies("pana"), SOON_SECS))
        # Past any look that was still to come, such as one after host a came back, so nothing but the
        # step itself can make pana's Signet look again.
        time.sleep(PROXIED_ASKS_EVERY_MILLIS / 1000 + 0.5)
        check("control: pana's Signet has a call held", stand_in.holding[pana] > 0, stand_in.holding)
        stand_in.busy = True
        request = open_request(net, "pana", "pben")
        time.sleep(3)
        stand_in.busy = False
        tried_again = wait_until(lambda: view(net, "pben", request).get("state") == "offered", SOON_SECS)
        check(f"a step pana's host turned away as busy goes within {SOON_SECS} s of it taking steps again, with pana's call still held", tried_again, view(net, "pben", request))

        stand_in.answer_waits = lambda: {"since": 7, "new": False}
        wake_on_host_a(net, pana)
        time.sleep(1)
        calls = stand_in.waits_from(pana, WINDOW_SECS)
        check(f"a host answering each wait at once with nothing new gets {calls} in {WINDOW_SECS} s, as one that holds none would", calls <= WINDOW_SECS * 1000 // PROXIED_ASKS_EVERY_MILLIS + 1, calls)

        marks = iter(range(10**6))
        stand_in.answer_waits = lambda: {"since": next(marks), "new": True}
        time.sleep(PROXIED_ASKS_EVERY_MILLIS / 1000 + 1)
        calls = stand_in.waits_from(pana, WINDOW_SECS)
        check(f"and one always saying there's something new gets {calls} in {WINDOW_SECS} s, at most one each 50 ms", 0 < calls <= WINDOW_SECS * 20, calls)


def control_a_host_that_holds_nothing(net: e2e.Network, held_reads: int) -> None:
    restart_with(net, "b", {"SPLINT_MAX_WAITS_AT_ONCE": "0"})
    # Each Signet on host b has just lost its held call, so wben's won't ask again for 30 seconds.
    request = open_request(net, "wana", "wben")
    net.retry_now(net.domain["b"])
    landed = wait_until(lambda: any(row["envelope"] for row in net.host_inbox("wben")), SOON_SECS)
    check("control: wana's next request lands on host b", landed)
    taken = wait_until(lambda: view(net, "wben", request).get("state") == "offered", SOON_SECS)
    check(f"control: when host b holds nothing, wben's Signet doesn't take it within {SOON_SECS} s", not taken)
    reads = reads_while_idle(net, "b")
    check(f"control: and Ben's Signet, which asks every 0.1 s on its own, reads host b's inbox {reads} times in {IDLE_SECS} s", reads > 5 * max(held_reads, IDLE_SECS), reads)


def main() -> int:
    e2e.build()
    with e2e.running_network(owned=True) as net:
        net.add_owned_agents({"wana": "a", "wben": "b"}, sync_millis=ASKS_EVERY_MILLIS)
        # Each Signet takes its first look at once, and then waits.
        time.sleep(3)
        print("\na step arrives as soon as it lands", flush=True)
        a_step_arrives_as_soon_as_it_lands(net)
        print("\nan agent's own move doesn't wake it", flush=True)
        an_agents_own_move_doesnt_wake_it(net)
        print("\na note and the owner's word each wake an agent", flush=True)
        a_note_and_the_owners_word_each_wake_an_agent(net)
        print("\na quiet Signet hardly looks", flush=True)
        held_reads = a_quiet_signet_hardly_looks(net)
        print("\nan agent can hold only so many waits", flush=True)
        an_agent_can_hold_only_so_many_waits(net)
        # Before any host restarts, after which a Signet may not look a contact up again for 30 s.
        print("\na step put off that comes due before a wait ends it", flush=True)
        a_step_put_off_that_comes_due_before_a_wait_ends_it(net)
        print("\na held call has limits of its own", flush=True)
        a_held_call_has_limits_of_its_own(net)
        print("\nheld calls from one source", flush=True)
        held_calls_from_one_source(net)
        print("\na Signet behind a host that misbehaves", flush=True)
        a_signet_behind_a_host_that_misbehaves(net)
        print("\ncontrol: a host that holds nothing", flush=True)
        control_a_host_that_holds_nothing(net, held_reads)
        if e2e.failures:
            for process in net.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1500:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

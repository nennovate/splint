#!/usr/bin/env python3
"""Hosts open to each other, as they ship, with real hosts, Signets and Postgres.

A host exchanges with every other host unless its peers file says `private`. So anyone can name any
host to it: as a delivery's sending host, or as where an agent's message goes. Each scenario shows
one of the checks that stand where the peer list used to, and each refusal has a control that gets
past the same check, so a refusal can't be down to the setup.

The hosts in `e2e.Network` run the plain-HTTP test scheme on loopback, where every call stays on this
machine. Where a host may call under HTTPS, which is what ships, is shown on a host of its own,
started with HTTPS and reached here on its plain listener, as its proxy would reach it. Its calls are
refused before any TLS, so no certificate is needed, and a listener shows whether one was made.

What this can't show: a real name in public DNS that resolves to an internal address. A name that
resolves to this machine stands in for one, and only where this machine lets anyone listen on port
443; the resolver's unit test covers it everywhere.
"""

import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

import e2e
from e2e import check, http, wait_until, warn

# A host reads its peers file every 2 seconds and takes a change on the second reading that agrees.
IN_FORCE_SECS = 10
# How long a host waits on another before giving up, and a little more.
CALL_SECS = 4
TLS_HANDSHAKE = 0x16


class Tally:
    """Connections to some listeners: how many in all, and the most open at once."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.taken = 0
        self.open = 0
        self.most = 0
        self.first_bytes: list[int] = []


class Listener:
    """Takes connections, answers nothing, and holds each until the caller hangs up, so a call to it
    lasts as long as the caller waits."""

    def __init__(self, tally: Tally | None = None, address: tuple[str, int] = ("127.0.0.1", 0)) -> None:
        self.tally = tally or Tally()
        self.socket = socket.create_server(address)
        self.port = self.socket.getsockname()[1]
        self.domain = f"127.0.0.1:{self.port}"
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self) -> None:
        while True:
            try:
                connection, _ = self.socket.accept()
            except OSError:
                return
            threading.Thread(target=self.hold, args=(connection,), daemon=True).start()

    def hold(self, connection: socket.socket) -> None:
        tally = self.tally
        with tally.lock:
            tally.taken += 1
            tally.open += 1
            tally.most = max(tally.most, tally.open)
        with connection:
            connection.settimeout(30)
            try:
                first = connection.recv(1)
                if first:
                    with tally.lock:
                        tally.first_bytes.append(first[0])
                while connection.recv(4096):
                    pass
            except OSError:
                pass
        with tally.lock:
            tally.open -= 1

    def close(self) -> None:
        self.socket.close()


def post(url: str, fields: dict, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str]]:
    """A call's status and the headers it answered with."""
    request = urllib.request.Request(url, data=json.dumps(fields).encode(), method="POST")
    request.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, {name.lower(): value for name, value in response.headers.items()}
    except urllib.error.HTTPError as error:
        return error.code, {name.lower(): value for name, value in error.headers.items()}


def forged_delivery(net: e2e.Network, from_host: str, body: str = "a delivery naming a host") -> dict:
    """A delivery naming a host as its sender, with a proof that host never signed. A host has to fetch
    the named host's key before it can tell the proof is no good."""
    envelope = net.envelope_signed_by("mallory", "mallory", "ben", f"{body} {time.monotonic_ns()}")
    return {"envelope": envelope, "sender_identity": net.agent_identity("mallory"), "from_host": from_host, "proof": "x.y.z"}


def at_once(calls) -> list:
    """Runs these calls together, as callers that don't wait for each other would, and their answers."""
    answers: list = [None] * len(calls)
    start = threading.Barrier(len(calls))

    def run(index: int) -> None:
        start.wait()
        answers[index] = calls[index]()

    threads = [threading.Thread(target=run, args=(index,)) for index in range(len(calls))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return answers


def two_hosts_with_no_list_exchange(net: e2e.Network) -> None:
    """Bug: a host with no peers file, or one with no lines, talks only to itself, as every host did."""
    for name in ("a", "b"):
        lines = [line for line in net.peers_file[name].read_text().splitlines() if line and not line.startswith("#")]
        check(f"control: host {name}'s peers file has no lines", lines == [], lines)
    net.send_and_wait("ana", "ben", "from Ana's host to Ben's, which neither names")
    net.send_and_wait("ben", "ana", "and back again")
    check("two hosts that name nobody exchange both ways", True)
    net.ack_all("ana")
    net.ack_all("ben")


def a_private_host_refuses_an_unnamed_one_and_never_calls_it(net: e2e.Network) -> None:
    """Bug: a private host calls a host it doesn't name to fetch its key, or answers it in a way that
    leaves the sender retrying blind. Or an open host calls a host that just failed again and again."""
    listener = Listener()
    url = f"http://{net.domain['b']}/v0/deliver"

    status, _ = post(url, forged_delivery(net, listener.domain))
    check("control: an open host calls a host it hasn't met for its key", wait_until(lambda: listener.tally.taken == 1, CALL_SECS), (status, listener.tally.taken))
    status, _ = post(url, forged_delivery(net, listener.domain))
    time.sleep(1)
    check("a host that just failed isn't called again for a while", listener.tally.taken == 1 and status == 503, (status, listener.tally.taken))

    other = Listener()
    net.write_peers("b", net.private_to(net.named))
    check("control: host b goes private", wait_until(lambda: not net.takes_from("b", other.domain), IN_FORCE_SECS))
    status, headers = post(url, forged_delivery(net, other.domain))
    check("a private host refuses a host it doesn't name", status == 403, status)
    check("and says so with a word the sending host shows its agent", headers.get("splint-refusal") == "not_a_peer", headers)
    status = http("POST", f"http://{net.domain['b']}/v0/outbound", {"envelope": "x", "recipient_host": other.domain})[0]
    check("and takes nothing for an unnamed host from its own agents", status == 403, status)
    time.sleep(1)
    check("and never calls that host", other.tally.taken == 0, other.tally.taken)

    net.write_peers("b", net.first_peers_file("b"))
    check("control: host b is open again", wait_until(lambda: net.takes_from("b", other.domain), IN_FORCE_SECS))
    listener.close()
    other.close()


def a_flood_naming_made_up_hosts_makes_few_calls(net: e2e.Network) -> None:
    """Bug: each delivery naming a host nobody knows makes this host call that host, as many at once as
    callers send, so a few callers naming hosts that never answer hold every place it has for calls."""
    url = f"http://{net.domain['b']}/v0/deliver"
    flood = 12

    one_source = Tally()
    hosts = [Listener(one_source) for _ in range(flood)]
    answers = at_once([lambda host=host: post(url, forged_delivery(net, host.domain))[0] for host in hosts])
    check("control: the flood reached the host", len(answers) == flood, answers)
    check("one source gets two key fetches at once", one_source.taken == 2, one_source.taken)
    check("and the rest are told to come back", answers.count(429) == flood - 2, answers)

    many_sources = Tally()
    hosts += [Listener(many_sources) for _ in range(flood)]
    answers = at_once([
        lambda host=host, number=number: post(url, forged_delivery(net, host.domain), {"X-Forwarded-For": f"198.51.100.{number}"})[0]
        for number, host in enumerate(hosts[flood:])
    ])
    check("many sources together get eight", many_sources.taken == 8, many_sources.taken)
    check("and the rest are told the host is busy", answers.count(503) >= flood - 8, answers)
    later = Listener()
    hosts.append(later)
    post(url, forged_delivery(net, later.domain))
    check("once those end, each has let go of its place", later.tally.taken == 1, later.tally.taken)
    for host in hosts:
        host.close()


class MadeUpHost:
    """A host anyone could set up: it serves a key of its own under the name it's given."""

    def __init__(self, net: e2e.Network, number: str, name: str = "127.0.0.1") -> None:
        self.server = e2e.ScriptedPeer()
        self.domain = f"{name}:{self.server.domain.rsplit(':', 1)[1]}"
        self.key = net.work / f"made-up-{number}.key"
        public = e2e.new_key(self.key)
        self.server.respond = lambda _path, _sent: (200, {}, json.dumps({"domain": self.domain, "key": public}).encode())


def delivery_from(net: e2e.Network, host: MadeUpHost, source: str = "", to: str = "ben", proof: str = "") -> int:
    """A first delivery from that host to host b, with its proof unless given another, from that source."""
    envelope = net.envelope_signed_by("mallory", "mallory", to, f"from a host met for the first time {time.monotonic_ns()}")
    fields = {
        "envelope": envelope, "sender_identity": net.agent_identity("mallory"), "from_host": host.domain,
        "proof": proof or net.host_proof(host.key, envelope, host.domain, net.domain["b"]),
    }
    return post(f"http://{net.domain['b']}/v0/deliver", fields, {"X-Forwarded-For": source} if source else {})[0]


def is_pinned(net: e2e.Network, host: MadeUpHost) -> bool:
    return net.postgres.sql("host_b", f"SELECT count(*) FROM peer_keys WHERE domain = '{host.domain}'") == "1"


def new_hosts_pinned_in_an_hour_are_capped(net: e2e.Network) -> None:
    """Bug: anyone with a domain can make up hosts with keys of their own and valid proofs, and each is a
    pinned row kept for good, as fast as they can call. Or a forged proof spends the hour's limit. Or
    one party, with one wildcard domain, spends all of it, and no real new host gets in for the hour."""
    pinned_this_hour = "SELECT count(*) FROM peer_keys WHERE pinned_at > now() - interval '1 hour'"
    pinned = lambda: int(net.postgres.sql("host_b", pinned_this_hour))
    room = 2
    host = net.hosts["b"]
    host.env["SPLINT_MAX_NEW_HOSTS_PER_HOUR"] = str(pinned() + room)
    net.restart_host("b")

    before = pinned()
    forged = MadeUpHost(net, "forged")
    check("a forged proof naming a host that serves a key is refused", delivery_from(net, forged, proof="x.y.z") != 200)
    check("and control: that host was called for its key", any("/.well-known/splint/host" in hit for hit in forged.server.hits), forged.server.hits)
    check("and pins nothing, so it spends none of the hour's limit", pinned() == before and not is_pinned(net, forged))
    nobody_here = MadeUpHost(net, "to-nobody")
    check("a valid delivery for nobody here is refused", delivery_from(net, nobody_here, to="ana") == 404)
    check("and pins nothing either", pinned() == before and not is_pinned(net, nobody_here))

    # Their keys are fetched first, so these race at the pin and not at the fetch.
    racing = [MadeUpHost(net, f"racing-{number}") for number in range(room + 6)]
    for number, made_up in enumerate(racing):
        delivery_from(net, made_up, f"203.0.113.{number + 1}", proof="x.y.z")
    statuses = at_once([
        lambda made_up=made_up, number=number: delivery_from(net, made_up, f"203.0.113.{number + 1}")
        for number, made_up in enumerate(racing)
    ])
    check("first deliveries racing each other are taken only up to the hour's limit", pinned() == before + room, (pinned(), before + room, statuses))
    check("and the rest are told to come back", statuses.count(429) == len(racing) - room, statuses)

    last = next(made_up for made_up in racing if not is_pinned(net, made_up))
    net.write_peers("b", f"peer {last.domain}\n")
    check("a host the operator names isn't held to it", wait_until(lambda: delivery_from(net, last) == 200, IN_FORCE_SECS))
    net.write_peers("b", net.first_peers_file("b"))
    time.sleep(IN_FORCE_SECS)

    share = max(2, (pinned() + 3) // 6)
    host.env["SPLINT_MAX_NEW_HOSTS_PER_HOUR"] = str(share * 8 + 7)
    net.restart_host("b")

    one_source = [MadeUpHost(net, f"one-source-{number}") for number in range(share + 1)]
    for made_up in one_source:
        delivery_from(net, made_up, "192.0.2.77")
    check("one source gets its share of the hour's new hosts", [is_pinned(net, made_up) for made_up in one_source] == [True] * share + [False])
    one_family = [MadeUpHost(net, f"one-family-{number}", "localhost") for number in range(share + 1)]
    for number, made_up in enumerate(one_family):
        delivery_from(net, made_up, f"192.0.2.{number + 100}")
    check("one family of names gets its share, whatever it calls from", [is_pinned(net, made_up) for made_up in one_family] == [True] * share + [False])
    newcomer = MadeUpHost(net, "newcomer")
    delivery_from(net, newcomer, "192.0.2.200")
    check("a new host from elsewhere still gets in", is_pinned(net, newcomer))

    del host.env["SPLINT_MAX_NEW_HOSTS_PER_HOUR"]
    net.restart_host("b")
    time.sleep(1)
    net.ack_all("ben")


def names_that_hang_leave_room_for_a_real_first_contact(net: e2e.Network) -> None:
    """Bug: a few sources keep naming fresh hosts that never answer, and hold every place for fetching a
    key, so a real host meeting this one for the first time is told to come back again and again."""
    url = f"http://{net.domain['b']}/v0/deliver"
    sources = [f"198.18.0.{number}" for number in range(1, 5)]
    hanging = Tally()
    hosts: list[Listener] = []

    def flood() -> list:
        round_of = [Listener(hanging) for _ in range(len(sources) * 2)]
        hosts.extend(round_of)
        return at_once([
            lambda host=host, source=sources[number % len(sources)]: post(url, forged_delivery(net, host.domain), {"X-Forwarded-For": source})[0]
            for number, host in enumerate(round_of)
        ])

    flood()
    check("control: sources not yet seen failing take every place", hanging.taken == 8, hanging.taken)
    second = threading.Thread(target=flood)
    second.start()
    check("control: the same sources are at it again", wait_until(lambda: hanging.taken > 8, CALL_SECS), hanging.taken)
    honest = MadeUpHost(net, "honest")
    status = delivery_from(net, honest, "192.0.2.50")
    check("a real host meeting this one for the first time gets a place", is_pinned(net, honest), status)
    second.join()
    check("sources whose fetches just hung share two places", hanging.taken == 10, hanging.taken)
    for host in hosts:
        host.close()
    net.ack_all("ben")


def failures_naming_a_family_dont_shut_it_out(net: e2e.Network) -> None:
    """Bug: anyone can name a made-up host under a real host's domain, and its failed fetch made every
    host of that family doubtful, so two callers holding the doubtful places shut the family out."""
    url = f"http://{net.domain['b']}/v0/deliver"
    closed = e2e.free_port()
    status = post(url, forged_delivery(net, f"localhost:{closed}"), {"X-Forwarded-For": "198.18.1.1"})[0]
    check("control: a host in the family failed to answer", status == 503, status)

    hanging = Tally()
    hosts = [Listener(hanging) for _ in range(2)]
    callers = [
        threading.Thread(target=post, args=(url, forged_delivery(net, f"localhost:{host.port}"), {"X-Forwarded-For": f"198.18.1.{number + 2}"}))
        for number, host in enumerate(hosts)
    ]
    for caller in callers:
        caller.start()
    check("control: two other sources hold fetches in that family", wait_until(lambda: hanging.open == 2, CALL_SECS), hanging.taken)
    honest = MadeUpHost(net, "same-family", "localhost")
    status = delivery_from(net, honest, "192.0.2.60")
    check("control: the fetches are still held", hanging.open == 2, hanging.open)
    check("a real host in that family, from a source that never failed, still gets in", is_pinned(net, honest), status)
    for caller in callers:
        caller.join()
    for host in hosts:
        host.close()
    net.ack_all("ben")


def many_dead_hosts_leave_send_slots_for_a_live_one(net: e2e.Network) -> None:
    """Bug: an agent here names many hosts that never answer, and the sends to them take every place the
    host has for sending, so mail to hosts that work waits behind them."""
    dead = Tally()
    hosts = [Listener(dead) for _ in range(24)]
    mallory = net.ids["mallory"]
    for host in hosts:
        envelope = net.envelope_signed_by("mallory", "mallory", "ben", f"to a host that never answers {host.port}")
        status = http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": envelope, "recipient_host": host.domain})[0]
        if status != 200:
            check("control: Mallory's host takes a message for a host that never answers", False, status)
            return
    check("control: Mallory's host calls the hosts that never answer", wait_until(lambda: dead.taken >= 8, CALL_SECS * 2), dead.taken)
    net.send_and_wait("ana", "ben", "to a host that answers, while those wait")
    check("a host that answers still gets its mail", True)
    time.sleep(CALL_SECS)
    check("hosts that have never taken a delivery share eight sends at once", 1 <= dead.most <= 8, dead.most)
    net.postgres.sql("host_a", f"DELETE FROM outbound WHERE sender = '{mallory}' AND status = 'pending'")
    net.ack_all("ben")
    for host in hosts:
        host.close()


class AnswersOnceThenHangs(Listener):
    """A host that takes one delivery, which proves it to the sending host, and never answers again."""

    def __init__(self, tally: Tally) -> None:
        self.answered = False
        super().__init__(tally)

    def hold(self, connection: socket.socket) -> None:
        if self.answered:
            super().hold(connection)
            return
        self.answered = True
        with connection:
            sent = b""
            while b"\r\n\r\n" not in sent:
                sent += connection.recv(65536)
            head, _, body = sent.partition(b"\r\n\r\n")
            length = next(int(line.split(b":")[1]) for line in head.split(b"\r\n") if line.lower().startswith(b"content-length"))
            while len(body) < length:
                body += connection.recv(65536)
            answer = e2e.answer_naming_the_message(body)
            connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s" % (len(answer), answer))


def queue(net: e2e.Network, agent: str, to_host: str, note: str, recipient: str = "ben") -> int:
    """A message from an agent on host a, waiting to go to that host."""
    envelope = net.envelope_signed_by(agent, agent, recipient, f"{note} {time.monotonic_ns()}")
    return http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": envelope, "recipient_host": to_host})[0]


def hosts_that_hang_dont_hold_up_known_hosts(net: e2e.Network) -> None:
    """Bug: hosts that never answer fill all a pass of the delivery worker looks at, so mail to a host
    that works isn't even looked at until they've drained. Or a few hosts answer once, count as proven
    for good, and then hang with every send slot this host has."""
    drop_what_waits = "DELETE FROM outbound WHERE status = 'pending' AND recipient_host <> '{}'".format(net.domain["b"])

    hanging = Tally()
    hosts = [AnswersOnceThenHangs(hanging) for _ in range(4)]
    for host in hosts:
        check("control: Mallory's host takes a message for it", queue(net, "mallory", host.domain, "the one it answers") == 200)
    taken = "SELECT count(DISTINCT host) FROM hosts_sent_to WHERE host IN ({})".format(",".join(f"'{host.domain}'" for host in hosts))
    check("control: each has taken a delivery", wait_until(lambda: net.postgres.sql("host_a", taken) == "4", CALL_SECS * 2))
    for host in hosts:
        for number in range(24):
            queue(net, "mallory", host.domain, f"one it never answers {number}")
    check("control: while they're proven they get more than the unproven share", wait_until(lambda: hanging.open > 8, CALL_SECS), hanging.open)
    time.sleep(CALL_SECS + 1)
    with hanging.lock:
        hanging.most = hanging.open
    time.sleep(CALL_SECS)
    check("hosts that took a delivery and then hang share eight sends at once", hanging.most <= 8, hanging.most)
    net.postgres.sql("host_a", drop_what_waits)
    for host in hosts:
        host.close()

    group = ["dora", "erin", "faye", "gwen"]
    net.add_owned_agents({agent: "a" for agent in group}, agree=False)
    never = Tally()
    dead = [Listener(never) for _ in range(384)]
    # Agents with owners write only to their contacts, and only so much can wait for any one of them.
    senders = [(agent, contact) for agent in group for contact in group if contact != agent] * 32
    accepted = sum(queue(net, agent, host.domain, "to a host that never answers", contact) == 200 for (agent, contact), host in zip(senders, dead))
    check("control: more hosts wait than a pass of the worker looks at", accepted > 256, accepted)
    started = time.monotonic()
    net.send_and_wait("ana", "ben", "to a host that has taken mail from here before")
    took = time.monotonic() - started
    # Draining what's ahead of it, eight sends per three seconds, would take far longer than this.
    check("mail to a known host goes at once, behind no queue of dead hosts", took < 10, took)
    net.postgres.sql("host_a", drop_what_waits)
    net.ack_all("ben")
    for host in dead:
        host.close()


def an_https_host_calls_no_internal_address_for_a_host_it_doesnt_name(net: e2e.Network) -> None:
    """Bug: anyone names `127.0.0.1:5432`, `2130706433` or a name that resolves inside, and an open host
    calls a service on its own network for them. Or the setting that allows it is on by default, or a
    proxy setting takes calls somewhere the check never saw."""
    listen = f"127.0.0.1:{e2e.free_port()}"
    peers_file = net.work / "https.peers"
    peers_file.write_text("# open to every host\n")
    proxy = Listener()
    settings = {
        "SPLINT_DOMAIN": "open-host.example", "SPLINT_LISTEN": listen,
        "SPLINT_DATABASE_URL": net.postgres.create_database("host_https"),
        "SPLINT_HOST_KEY_FILE": str(net.work / "host-https.key"), "SPLINT_PEERS_FILE": str(peers_file),
        "HTTPS_PROXY": f"http://{proxy.domain}", "https_proxy": f"http://{proxy.domain}", "ALL_PROXY": f"http://{proxy.domain}",
    }
    host = net.spawn("host", "host-https", settings)
    if not wait_until(lambda: http("GET", f"http://{listen}/.well-known/splint/host")[0] == 200):
        check("an HTTPS host starts", False, host.log_path.read_text()[-500:])
        return

    def named_to_it(form: str) -> int:
        return post(f"http://{listen}/v0/deliver", forged_delivery(net, form))[0]

    def sent_to(form: str) -> int:
        """400 where the host would send there and the envelope is what it refuses, 403 where it wouldn't."""
        return http("POST", f"http://{listen}/v0/outbound", {"envelope": "x", "recipient_host": form})[0]

    inside = Listener()
    port = inside.port
    check("control: a public name on 443 passes the check where it's sent", sent_to("host.example") == 400)
    # With no port these are on 443, so only the address rule can refuse them.
    for form in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "[::1]", f"127.0.0.1:{port}", f"localhost:{port}"]:
        check(f"{form} as a delivery's sender is refused", named_to_it(form) == 403)
        check(f"{form} as where a message goes is refused", sent_to(form) == 403)
    # The client reads each of these as an address of this machine, so each is refused as a spelling.
    for form in [f"2130706433:{port}", f"127.1:{port}", f"0x7f.1:{port}", f"0177.0.0.1:{port}", f"[::ffff:127.0.0.1]:{port}"]:
        check(f"{form} as a delivery's sender is refused", named_to_it(form) == 400)
        check(f"{form} as where a message goes is refused", sent_to(form) == 403)
    time.sleep(1)
    check("and nothing at that address is called", inside.tally.taken == 0, inside.tally.taken)

    peers_file.write_text("block blocked.example\n")
    check("control: a blocked host is refused", wait_until(lambda: named_to_it("blocked.example") == 403 and sent_to("blocked.example") == 403, IN_FORCE_SECS))
    for form in ["blocked.example:443", "Blocked.Example.:443"]:
        check(f"{form}, the same place, is no way past the block", named_to_it(form) == 400 and sent_to(form) == 403)
    peers_file.write_text("# open to every host\n")
    check("control: the block is lifted", wait_until(lambda: sent_to("blocked.example") == 400, IN_FORCE_SECS))

    try:
        on_443 = Listener(address=("0.0.0.0", 443))
    except OSError:
        on_443 = None
    warn("this machine lets anyone listen on port 443, for a name that resolves here", on_443 is not None, "skipped")
    if on_443 is not None:
        # A name passes until it's resolved, and then has no public address to go to.
        check("localhost, which resolves here, gets no key", named_to_it("localhost") != 200)
        time.sleep(1)
        check("and nothing on port 443 here is called", on_443.tally.taken == 0, on_443.tally.taken)
        on_443.close()

    peers_file.write_text(f"peer 127.0.0.1:{port}\n")
    check("control: a host the operator names may be anywhere", wait_until(lambda: sent_to(f"127.0.0.1:{port}") == 400, IN_FORCE_SECS))
    named_to_it(f"127.0.0.1:{port}")
    check("control: and it's called, over TLS", wait_until(lambda: TLS_HANDSHAKE in inside.tally.first_bytes, CALL_SECS), inside.tally.first_bytes)
    check("with no call through the proxy the settings name", proxy.tally.taken == 0, proxy.tally.taken)

    peers_file.write_text("# open to every host\n")
    host.kill_hard()
    host.env["SPLINT_ALLOW_INTERNAL_HOSTS"] = "yes"
    host.start()
    check("control: the host starts with the setting that allows internal hosts", wait_until(lambda: http("GET", f"http://{listen}/.well-known/splint/host")[0] == 200))
    check("and says in its log that it's on", "WARN" in host.log_path.read_text() and "SPLINT_ALLOW_INTERNAL_HOSTS" in host.log_path.read_text())
    taken = inside.tally.taken
    check("with it on, an unnamed host may be internal", named_to_it(f"127.0.0.1:{port}") != 403 and inside.tally.taken > taken, inside.tally.taken)
    host.kill_hard()
    inside.close()
    proxy.close()


def a_retirement_reaches_the_hosts_an_agent_sent_to(net: e2e.Network) -> None:
    """Bug: a host told an agent is retired passes it on to the hosts its operator named, and an open
    host names none, so a host that holds the agent's key as a contact's never hears."""
    net.send_and_wait("carol", "ana", "so that Carol's host has delivered to Ana's")
    net.ack_all("ana")
    stopped = f"SELECT count(*) FROM contact_stops WHERE agent = '{net.ids['carol']}'"
    check("control: Ana's host has no stop for Carol", net.postgres.sql("host_a", stopped) == "0")
    retirement = net.owners["carol"].sign("retire", "--agent", net.ids["carol"], "--reason", "finished")
    status = http("POST", f"http://{net.domain['b']}/v0/retirements", {"retirement": retirement})[0]
    check("control: Carol's owner retires her at her host", status == 200, status)
    check("the host she sent to hears, with neither host naming the other", wait_until(lambda: net.postgres.sql("host_a", stopped) == "1"))


def main() -> int:
    e2e.build()
    with e2e.running_network() as net:
        for scenario in (
            two_hosts_with_no_list_exchange,
            a_private_host_refuses_an_unnamed_one_and_never_calls_it,
            a_flood_naming_made_up_hosts_makes_few_calls,
            new_hosts_pinned_in_an_hour_are_capped,
            names_that_hang_leave_room_for_a_real_first_contact,
            failures_naming_a_family_dont_shut_it_out,
            many_dead_hosts_leave_send_slots_for_a_live_one,
            hosts_that_hang_dont_hold_up_known_hosts,
            an_https_host_calls_no_internal_address_for_a_host_it_doesnt_name,
            a_retirement_reaches_the_hosts_an_agent_sent_to,
        ):
            print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
            scenario(net)
        if e2e.failures:
            for process in net.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1500:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

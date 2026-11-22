#!/usr/bin/env python3
"""What keeps callers from stopping a host, and the limits its operator sets.

These run the real binaries and count on nothing behaving: an idle caller, a slow caller, a flood, and
an owner signing more than a host allows. Calls say who they're from the way a host's proxy does, in
X-Forwarded-For, as there's no proxy here. Each refusal has a control.

What this can't show: a real proxy and firewall in front, which needs a server (the proxy's settings
are only validated here), and what a real server carries, which issue 157 still has open. Nor that a
host takes a page's room before it reads the page and not after: a caller is refused the same either
way, and the difference is only what the host held meanwhile.
"""

import http.client
import json
import re
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import agent_signup
import e2e
import tls_rules
from e2e import check, new_identity, new_owner, wait_until
from request_driver import meeting_ask, open_conversation, signed_step, wait_for

DEPLOY = e2e.PACKAGES.parent / "deploy"
HOST_PATH = "/.well-known/splint/host"
# Longer than a host gives a request, so what's still open then isn't being closed.
PAST_THE_DEADLINE_SECS = 55
CONNECTIONS = 48
CALLS_AT_ONCE = 24
CALLS_AT_ONCE_PER_SOURCE = 16
CALLS_PER_SOURCE_PER_SECOND = 20
# The least an operator can set, which is the largest body a host takes: room for two in all, one a source.
LARGEST_BODY = 512 * 1024
BODY_BYTES_AT_ONCE = 2 * LARGEST_BODY
BODY_BYTES_AT_ONCE_PER_SOURCE = LARGEST_BODY
# Nearly all of one source's share, a body that fits in what's left of it, and one that doesn't.
HELD_BODY = LARGEST_BODY - 4096
FITS_BESIDE_IT = 2048
TOO_MUCH_BESIDE_IT = 20_000
# The least an operator can set, which is a page of answers: room for two in all, one a source.
ANSWER_PAGE = 1024 * 1024
ANSWER_BYTES_AT_ONCE = 2 * ANSWER_PAGE
ANSWER_BYTES_AT_ONCE_PER_SOURCE = ANSWER_PAGE
# Four of these with what a host keeps beside each come to about 1,003,000 bytes, most of a page,
# and a fifth doesn't fit. Nine make two such pages and a third. Two such pages unread leave about
# 90,000 bytes of the room, less than a full page of a long request, which is about 119,000.
LARGE_MESSAGE = 242 * 1024
LARGE_MESSAGES = 9
# What one stranger can leave in a quarantine, in messages that size: two pages.
HELD_FROM_A_STRANGER = 8
# Short messages that together are well under a page, and well over what two unread pages leave.
SHORT_MESSAGE = 4 * 1024
SHORT_MESSAGES = 30
# A note shorter than a large message, so it goes ahead of one in its turn, and long enough that a
# page with it at the front holds one large message fewer.
LONG_NOTE = 100 * 1024
# An agent's view for its owner, longer than two unread pages leave of the room, which a host gives
# whole rather than as a page. Hosts serve no large file of their own any more.
LONG_VIEW = 200 * 1024
# More steps than two pages of a request hold.
LONG_REQUEST_STEPS = 210
# What a connection reads ahead of a call, so the longest a request's first line and headers can be.
LONGEST_HEAD = 16 * 1024
RAISED_SENDS_PER_HOUR = 400
LOWERED_REQUESTS_PER_CONTACT = 2
# What one agent can have waiting to go out, and the part of that one host and one recipient can hold.
QUEUED_PER_AGENT = 128
QUEUED_PER_RECIPIENT_HOST = 64
QUEUED_PER_RECIPIENT = 32
QUEUED_BYTES_PER_RECIPIENT_HOST = 4 * 1024 * 1024
QUEUED_BYTES_PER_RECIPIENT = 2 * 1024 * 1024
# More than a short message takes, so one fits just under a share of the bytes.
ROOM_FOR_ONE = 8 * 1024
SENDS_AT_ONCE = 8
AGENTS_PER_OWNER = 2
OPEN_AGENTS_PER_HOUR = 2
CADDY_IMAGE = "caddy:2.8-alpine"


class GuardedNetwork(e2e.Network):
    host_settings = {
        "SPLINT_MAX_CONNECTIONS": str(CONNECTIONS),
        "SPLINT_MAX_CALLS_AT_ONCE": str(CALLS_AT_ONCE),
        "SPLINT_MAX_CALLS_AT_ONCE_PER_SOURCE": str(CALLS_AT_ONCE_PER_SOURCE),
        "SPLINT_MAX_CALLS_PER_SOURCE_PER_SECOND": str(CALLS_PER_SOURCE_PER_SECOND),
        "SPLINT_MAX_BODY_BYTES_AT_ONCE": str(BODY_BYTES_AT_ONCE),
        "SPLINT_MAX_BODY_BYTES_AT_ONCE_PER_SOURCE": str(BODY_BYTES_AT_ONCE_PER_SOURCE),
        "SPLINT_MAX_ANSWER_BYTES_AT_ONCE": str(ANSWER_BYTES_AT_ONCE),
        "SPLINT_MAX_ANSWER_BYTES_AT_ONCE_PER_SOURCE": str(ANSWER_BYTES_AT_ONCE_PER_SOURCE),
        "SPLINT_MAX_SENDS_PER_AGENT_PER_HOUR": str(RAISED_SENDS_PER_HOUR),
        "SPLINT_MAX_NEW_REQUESTS_PER_CONTACT_PER_DAY": str(LOWERED_REQUESTS_PER_CONTACT),
        "SPLINT_MAX_AGENTS_PER_OWNER": str(AGENTS_PER_OWNER),
        "SPLINT_MAX_OPEN_AGENTS_PER_HOUR": str(OPEN_AGENTS_PER_HOUR),
        "SPLINT_OPEN_SIGNUP": "yes",
    }


def ask(port: int, source: str | None = None, path: str = HOST_PATH, body: bytes | None = None, **headers: str) -> tuple[int, str | None]:
    """A status and any Retry-After, or 0 for a connection the host closed without an answer."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        headers |= {"X-Forwarded-For": source} if source else {}
        connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
        answer = connection.getresponse()
        answer.read()
        return answer.status, answer.getheader("Retry-After")
    except (OSError, http.client.HTTPException):
        return 0, None
    finally:
        connection.close()


def held_open(port: int, sent: bytes) -> socket.socket:
    connection = socket.create_connection(("127.0.0.1", port), timeout=10)
    connection.sendall(sent)
    return connection


def slow_body(port: int, source: str, size: int = 1000, sent: int = 0) -> socket.socket:
    """A call that says how long its body is, sends this much of it and then nothing."""
    return held_open(port, f"POST /v0/deliver HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {source}\r\nContent-Type: application/json\r\nContent-Length: {size}\r\n\r\n".encode() + b"x" * sent)


def whole_body(port: int, source: str, size: int) -> tuple[int, str | None]:
    """What a whole body of this size is told. It isn't a delivery, so past the door the route refuses it."""
    return ask(port, source, "/v0/deliver", b"x" * size, **{"Content-Type": "application/json"})


def was_closed(connection: socket.socket, within: float) -> bool:
    readable, _, _ = select.select([connection], [], [], within)
    if not readable:
        return False
    try:
        return connection.recv(4096) == b""
    except OSError:
        return True


def closed_with_or_without_an_answer(connection: socket.socket, within: float) -> bool:
    """A host may say something first: what counts is that it ends."""
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        readable, _, _ = select.select([connection], [], [], deadline - time.monotonic())
        if not readable:
            return False
        try:
            if connection.recv(4096) == b"":
                return True
        except OSError:
            return True
    return False


def idle_and_slow_callers_get_closed(net: e2e.Network) -> None:
    """Issue 93: these were all still open after 130 seconds."""
    port = net.host_port["a"]
    callers = {
        "a connection that never sends anything": held_open(port, b""),
        "half a header": held_open(port, b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: "),
        "half a body": held_open(port, b"POST /v0/deliver HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"),
    }
    time.sleep(1)
    for name, caller in callers.items():
        check(f"control: {name} isn't closed at once", not was_closed(caller, 0))
    started = time.monotonic()
    for name, caller in callers.items():
        check(f"{name} is closed", closed_with_or_without_an_answer(caller, PAST_THE_DEADLINE_SECS - (time.monotonic() - started)))
        caller.close()
    # Sending a little every so often doesn't buy any more time.
    dripping = held_open(port, b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")
    started = time.monotonic()
    alive = True
    while alive and time.monotonic() - started < PAST_THE_DEADLINE_SECS:
        try:
            dripping.sendall(b"a")
            alive = not was_closed(dripping, 1)
        except OSError:
            alive = False
    check("nor is a caller sending a byte a second kept", not alive, time.monotonic() - started)
    dripping.close()


def a_flood_of_connections_stops_at_the_cap_and_delivery_goes_on(net: e2e.Network) -> None:
    """Issue 93: past its file limit a host answered nobody, in or out."""
    port = net.host_port["a"]
    peer = net.scripted_peer
    to_peer = e2e.ToScriptedPeer(net)
    peer.answer_everything_with(503)
    queued = [to_peer.send(f"queued before the flood {number}") for number in range(3)]
    check("control: the peer isn't taking them", all(to_peer.report(message_id).get("status") == "sending" for message_id in queued))

    flood = []
    for _ in range(CONNECTIONS * 4):
        try:
            flood.append(socket.create_connection(("127.0.0.1", port), timeout=10))
        except OSError:
            break
    time.sleep(1)
    kept = [connection for connection in flood if not was_closed(connection, 0)]
    check(f"at most {CONNECTIONS} are held", len(kept) <= CONNECTIONS, len(kept))
    check("control: and it's a real flood", len(flood) - len(kept) >= CONNECTIONS * 2, (len(flood), len(kept)))

    # Read from the database, as the host's own door is what's full.
    def stored_status(message_id: str) -> str:
        return net.postgres.sql("host_a", f"SELECT status FROM outbound WHERE message_id = '{message_id}'")

    peer.accept_everything()
    delivered = wait_until(lambda: all(stored_status(message_id) == "delivered" for message_id in queued), timeout=60)
    check("what's queued still goes, all through the flood", delivered, [stored_status(message_id) for message_id in queued])

    for connection in flood:
        connection.close()
    check("once it stops, the host answers", wait_until(lambda: ask(port)[0] == 200, timeout=3))
    log = net.hosts["a"].log_path.read_text()
    check("and it never ran out of files", "Too many open files" not in log and "couldn't accept" not in log)


def one_source_cant_hold_every_call(net: e2e.Network) -> None:
    """Issue 157: past the ceiling calls waited until everyone timed out, and nothing said to come back."""
    port = net.host_port["a"]
    check("control: a call is answered", ask(port, "203.0.113.7")[0] == 200)
    # A call the host closed at the door or has answered holds nothing, so another is made in its place
    # until all of them wait. Right after a start the network's own idle connections can fill most of
    # the host's connection cap, and on some machines that left room for too few of these, so the call
    # after them was answered.
    held: list[socket.socket] = []
    turned_away, answer, deadline = 0, (0, None), time.monotonic() + 30
    while answer != (429, "1") and time.monotonic() < deadline:
        waiting = [connection for connection in held if not select.select([connection], [], [], 0)[0]]
        for connection in held:
            if connection not in waiting:
                connection.close()
        turned_away += len(held) - len(waiting)
        held = waiting + [slow_body(port, "203.0.113.7") for _ in range(CALLS_AT_ONCE_PER_SOURCE - len(waiting))]
        time.sleep(0.25)
        answer = ask(port, "203.0.113.7")
    check(
        f"a source holding {CALLS_AT_ONCE_PER_SOURCE} calls is told to wait",
        answer == (429, "1"), (answer, f"{turned_away} held calls were turned away or answered"),
    )
    check(
        "whatever it adds in front of what the proxy wrote",
        ask(port, "198.51.100.200, 203.0.113.7")[0] == 429,
    )
    check("someone else isn't held up by that", ask(port, "203.0.113.8")[0] == 200)

    # Past the total, as these do no work yet. So a few callers holding bodies back stop only themselves.
    # Just past the total, and no more: the network's own idle connections to this host can be 16 right
    # after it starts, and holding more would fill the connection cap, so the calls below would be refused there.
    held += [slow_body(port, "203.0.113.8") for _ in range(CALLS_AT_ONCE - CALLS_AT_ONCE_PER_SOURCE + 1)]
    time.sleep(0.5)
    check(f"{len(held)} calls waiting for a body are past the {CALLS_AT_ONCE} at once", len(held) > CALLS_AT_ONCE)
    check("and take nothing from anyone else", ask(port, "203.0.113.10")[0] == 200)
    check("nor from a call with no proxy's word", ask(port)[0] == 200)

    answered = slow_body(port, "203.0.113.20")
    answer = b""
    answered.settimeout(15)
    try:
        answer = answered.recv(4096)
    except OSError:
        pass
    check("a body that stops coming is told so, in time", answer.startswith(b"HTTP/1.1 408"), answer[:40])
    answered.close()

    for connection in held:
        connection.close()
    check("hanging up gives a source its place back", wait_until(lambda: ask(port, "203.0.113.7")[0] == 200, timeout=5))
    check("and the total", wait_until(lambda: ask(port, "203.0.113.10")[0] == 200, timeout=5))


def callers_holding_bodies_stop_at_the_room_and_it_comes_back(net: e2e.Network) -> None:
    """A review before release: bodies were held up to a fixed 256 MiB, 16 MiB of it from any one source,
    and a connection kept 400 KB more that nothing counted, on a server with 2 GB for everything."""
    port = net.host_port["a"]
    one, another, anyone = "203.0.113.30", "203.0.113.31", "203.0.113.32"
    taken, _ = whole_body(port, anyone, TOO_MUCH_BESIDE_IT)
    check("control: with nothing held a body gets as far as the route, which refuses what isn't a delivery", taken == 400, taken)

    def told(source: str, size: int, tries: int = 10) -> tuple[int, str | None]:
        """Few enough tries that a source stays far under its calls a second, which are refused the same way."""
        answer = (0, None)
        for _ in range(tries):
            answer = whole_body(port, source, size)
            if answer[0] not in (taken, 0):
                break
            time.sleep(0.2)
        return answer

    def hold(source: str) -> socket.socket:
        """All but the last byte, so the host has it and the call never finishes. A host takes room for a
        body as it comes, so a call that got in while this was still coming would be the one that fits,
        and this the one refused. So nothing is asked until the host has had time to take it all."""
        holding = slow_body(port, source, HELD_BODY, HELD_BODY - 1)
        time.sleep(1)
        return holding

    held = [hold(one)]
    answer = told(one, TOO_MUCH_BESIDE_IT)
    check("a source holding nearly its share of bodies is told to wait for the rest", answer == (429, "1"), answer)
    check("control: it's bytes it's over, as a call of its own with none is answered", ask(port, one)[0] == 200)
    check("and what's left of its share is still its own", whole_body(port, one, FITS_BESIDE_IT)[0] == taken)
    check("someone else isn't held up by that", whole_body(port, anyone, TOO_MUCH_BESIDE_IT)[0] == taken)

    held.append(hold(another))
    answer = told(anyone, TOO_MUCH_BESIDE_IT)
    check("with the room for bodies nearly full, anyone is told to come back", answer == (503, "1"), answer)
    check("a body that fits in what's left is taken", whole_body(port, anyone, FITS_BESIDE_IT)[0] == taken)
    check("and so is a call with no body", ask(port, anyone)[0] == 200)

    held.pop(0).close()
    check("hanging up gives the room back", wait_until(lambda: whole_body(port, anyone, TOO_MUCH_BESIDE_IT)[0] == taken, timeout=5))
    check("and that source its share", wait_until(lambda: whole_body(port, one, TOO_MUCH_BESIDE_IT)[0] == taken, timeout=5))
    held.pop().close()

    # A held call keeps its body's room while it's held, 25 seconds at a time, so a wait's is small.
    padded = ask(port, anyone, "/v0/wait", b'{"since":null}' + b" " * 1024)[0]
    check("a wait padded out to take room is refused before its proof is looked at", padded == 400, padded)
    check("control: and a plain one gets as far as its proof", ask(port, anyone, "/v0/wait", b'{"since":null}')[0] == 401)

    padded = ask(port, anyone, **{"X-Padding": "a" * (LONGEST_HEAD + 1024)})[0]
    check("a request whose headers are longer than a connection reads ahead is refused", padded == 431, padded)
    check("control: and one with headers half as long is answered", ask(port, anyone, **{"X-Padding": "a" * (LONGEST_HEAD // 2)})[0] == 200)


def read_as(net: e2e.Network, agent: str, path: str, source: str | None = None) -> tuple[int, str | None, dict]:
    """What an agent's own host answers its Signet's call, read to the end: the status, any Retry-After
    and the page."""
    connection = http.client.HTTPConnection("127.0.0.1", net.host_port[net.home[agent]], timeout=30)
    try:
        headers = {"Authorization": f"Splint {net.access_proof(agent, agent, 'GET', path)}"}
        headers |= {"X-Forwarded-For": source} if source else {}
        connection.request("GET", path, headers=headers)
        answer = connection.getresponse()
        content = answer.read()
        return answer.status, answer.getheader("Retry-After"), json.loads(content) if answer.status == 200 else {}
    finally:
        connection.close()


def unread_answer(net: e2e.Network, agent: str, path: str, source: str) -> socket.socket:
    """The same call from a caller that reads the first line of its answer and no more. Its socket takes
    in as little as one can, so part of a large answer is still with the host, which is all it takes for
    the host to go on holding the answer's room.

    A system takes some of an answer off the host's hands to send ahead. Linux sizes that by the largest
    packet, which between two ends of one machine is so large that it takes a whole page, so the
    largest packet is made small here: measured on Linux 6.10 with these settings, 944 KB of a
    1,003 KB answer stayed with its server, and none of it without them. macOS refuses the setting
    and keeps about a third of such an answer back anyway. If a system took a whole page, the checks
    that a source is over its share would fail, and none would pass by mistake."""
    connection = socket.socket()
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    try:
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 536)
    except OSError:
        pass
    connection.settimeout(10)
    connection.connect(("127.0.0.1", net.host_port[net.home[agent]]))
    proof = net.access_proof(agent, agent, "GET", path)
    connection.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {source}\r\nAuthorization: Splint {proof}\r\n\r\n".encode())
    started = connection.recv(12)
    if started != b"HTTP/1.1 200":
        raise RuntimeError(f"a call that should have been answered got {started!r}")
    return connection


def read_to_the_end(connection: socket.socket) -> None:
    """Reads the rest of an answer whose first line was read."""
    connection.settimeout(30)
    content = b""
    while b"\r\n\r\n" not in content:
        content += connection.recv(65536)
    head, _, body = content.partition(b"\r\n\r\n")
    length = int(re.search(rb"content-length: (\d+)", head, re.IGNORECASE).group(1))
    while len(body) < length:
        more = connection.recv(65536)
        if not more:
            raise RuntimeError("the host hung up before the end of an answer")
        body += more


def waiting_for(net: e2e.Network, agent: str, which: str) -> int:
    return int(net.postgres.sql(f"host_{net.home[agent]}", f"SELECT count(*) FROM inbox WHERE recipient = '{net.ids[agent]}' AND NOT acked AND {which}"))


# Of what waits for an agent: the large messages, the short ones, or all of it.
LARGE = f"octet_length(envelope) >= {LARGE_MESSAGE}"
SHORT = f"octet_length(envelope) = {SHORT_MESSAGE}"
EVERYTHING = "TRUE"


def words_from(net: e2e.Network, sender: str, to: str, length: int, count: int) -> set[str]:
    """Words from the sender's key, in envelopes this long, through its host to the other's."""
    key, sender_id, recipient = net.key_of(sender), net.ids[sender], net.ids[to]
    body = e2e.body_to_reach(key, sender_id, recipient, length)
    sent = set()
    for _ in range(count):
        envelope = e2e.signed_envelope(key, sender_id, recipient, body)
        fields = {"envelope": envelope, "recipient_host": net.domain[net.home[to]]}
        status, answer = e2e.as_the_queue_drains(lambda fields=fields: e2e.http("POST", f"http://{net.domain[net.home[sender]]}/v0/outbound", fields))
        if status != 200:
            raise RuntimeError(f"a message wasn't taken: {status} {answer}")
        sent.add(e2e.message_id_of(envelope))
    return sent


def ids_on(page: dict) -> list[str]:
    return [e2e.message_id_of(message["envelope"]) for message in page.get("messages", [])]


def rules_listing(net: e2e.Network, agent: str, *contacts: dict) -> int:
    draft = e2e.rules_draft(list(contacts))
    return net.put_rules(agent, net.owners[agent].sign("rules", "--agent", net.ids[agent], stdin=json.dumps(draft)))[0]


def a_long_request_of_bens(net: e2e.Network) -> tuple[str, list[str]]:
    """A conversation Ben's Signet opens with Ana, and then receipts from Ben's key for steps nobody
    sent, which his host keeps a copy of as it does of any step. Only a key that skips its Signet makes
    a request this long, and a host has to bear one."""
    request = open_conversation(net, "ben", "ana")
    if wait_for(net, "ana", request, state="talking") is None:
        raise RuntimeError("the conversation never reached Ana")
    sent = []
    for number in range(LONG_REQUEST_STEPS):
        step = {"step": "received", "request": request, "of": f"{number:064x}"}
        envelope = signed_step(net, "ben", "ben", "ana", step)
        fields = {"envelope": envelope, "recipient_host": net.domain["a"]}
        status, answer = e2e.as_the_queue_drains(lambda fields=fields: e2e.http("POST", f"http://{net.domain['b']}/v0/outbound", fields))
        if status != 200:
            raise RuntimeError(f"a step wasn't taken: {status} {answer}")
        sent.append(e2e.message_id_of(envelope))
    return request, sent


def large_answers_come_in_pages_and_nothing_is_lost(net: e2e.Network) -> None:
    """A review before release: a page of an inbox was up to 100 messages however large, over 25 MiB, a
    request's steps and a quarantine came whole, and the host held each answer until its caller had
    read it."""
    stranger_key = net.work / "stranger.key"
    identity, stranger = new_identity(stranger_key)
    body = e2e.body_to_reach(stranger_key, stranger, net.ids["ben"], LARGE_MESSAGE)
    left = [e2e.signed_envelope(stranger_key, stranger, net.ids["ben"], body) for _ in range(HELD_FROM_A_STRANGER)]
    statuses = {net.deliver(envelope, identity) for envelope in left}
    check("control: a stranger's large messages are taken, and held", statuses == {200}, statuses)
    status, _, page = read_as(net, "ben", "/v0/quarantine")
    held_on_a_page = len(page.get("held", []))
    check("a host gives what's held a page at a time", status == 200 and 0 < held_on_a_page < HELD_FROM_A_STRANGER and "next" in page, (status, held_on_a_page))
    status, shown = e2e.http("GET", f"http://127.0.0.1:{net.signet_port['ben']}/v0/owner/quarantine", token=net.owners["ben"].token, timeout=60)
    shown_ids = [held["message_id"] for held in shown.get("held", []) if held.get("sender") == stranger]
    check("and Ben's Signet reads every page, so his owner is shown all of it, once each", status == 200 and sorted(shown_ids) == sorted(map(e2e.message_id_of, left)), (status, len(shown_ids)))

    request, steps = a_long_request_of_bens(net)
    pages, path = [], f"/v0/requests/{request}"
    while path:
        status, _, page = read_as(net, "ben", path)
        if status != 200:
            break
        pages.append(page)
        path = f"/v0/requests/{request}/after/{page['next']}" if "next" in page else ""
    read = [e2e.message_id_of(step["envelope"]) for page in pages for step in page["steps"]]
    check("a long request's steps come in more than two pages", len(pages) > 2 and all(page["steps"] for page in pages), [len(page["steps"]) for page in pages])
    check("which together are every step, in the order they were taken", [step for step in read if step in set(steps)] == steps, (len(read), len(steps)))
    check("and none twice", len(read) == len(set(read)), len(read))

    # Nothing reads Ben's inbox while its pages are counted, so each page is the same, and his Signet
    # reads them after. What earlier scenarios left for him unseen is a few short messages, which stay.
    net.ack_all("ben")
    net.signets["ben"].kill_hard()
    sent = words_from(net, "ana", "ben", LARGE_MESSAGE, LARGE_MESSAGES)
    check("control: Ben's host has them all waiting", wait_until(lambda: waiting_for(net, "ben", LARGE) == LARGE_MESSAGES, timeout=60), waiting_for(net, "ben", LARGE))
    status, _, page = read_as(net, "ben", "/v0/inbox")
    on_a_page = sum(1 for one in ids_on(page) if one in sent)
    check("a page of an inbox holds only the large messages that fit", status == 200 and 0 < on_a_page < LARGE_MESSAGES, (status, on_a_page))
    # Carol's Signet is off as well, so nothing else reads her inbox while the room is counted. Ana's
    # rules have listed only Ben since an earlier scenario.
    check("control: Ana's owner lists Carol again", rules_listing(net, "ana", net.contact_entry("ben"), net.contact_entry("carol")) == 200)
    net.ack_all("carol")
    net.signets["carol"].kill_hard()
    short = words_from(net, "ana", "carol", SHORT_MESSAGE, SHORT_MESSAGES)
    check("control: Carol's host has her short ones waiting", wait_until(lambda: waiting_for(net, "carol", SHORT) == SHORT_MESSAGES, timeout=60), waiting_for(net, "carol", SHORT))
    waiting = waiting_for(net, "ben", EVERYTHING)
    # Ben's Signet is off, so it doesn't replace this with a view of its own while the room is counted.
    view = json.dumps({"view": "v" * LONG_VIEW}).encode()
    left = e2e.http("PUT", f"http://{net.domain['b']}/v0/owner-view", raw=view, auth=net.access_proof("ben", "ben", "PUT", "/v0/owner-view", view))[0]
    check("control: Ben's host keeps a long view for his owner", left == 200, left)
    answers_held_stop_at_the_room_and_it_comes_back(net, request, pages[-2]["next"], sent, short)
    check("control: and nothing else came for Ben meanwhile", waiting_for(net, "ben", EVERYTHING) == waiting, (waiting_for(net, "ben", EVERYTHING), waiting))
    net.signets["carol"].start()
    check("control: Carol's Signet comes back", net.wait_for_signet("carol"))
    net.ack_all("carol")

    net.signets["ben"].start()
    check("control: Ben's Signet comes back", net.wait_for_signet("ben"))
    # Ben's rules have listed only Ana since an earlier scenario, and Carol writes to him below.
    check("control: Ben's owner lists Carol again", rules_listing(net, "ben", net.contact_entry("ana"), net.contact_entry("carol")) == 200)
    seen: list[str] = []
    seen.extend(shown_then_pushed_off_the_page_is_still_cleared(net, sent, on_a_page))

    def read_and_cleared() -> bool:
        """A page, and then the next. His Signet looks at his inbox too, so with room for two pages a
        call can be told to come back, as an agent's is by any host that's busy."""
        status, shown = net.agent("ben", "GET", "/v0/inbox", timeout=120)
        ids = [message["verified"]["message_id"] for message in shown.get("messages", [])] if status == 200 else []
        if ids and net.agent("ben", "POST", "/v0/inbox/ack", {"message_ids": ids}, timeout=120)[0] == 200:
            seen.extend(ids)
        return waiting_for(net, "ben", LARGE) == 0

    check("Ben's Signet reads and clears page after page, until none is left on his host", wait_until(read_and_cleared, timeout=120), waiting_for(net, "ben", LARGE))
    check("and Ben gets every message, each of them once", sorted(one for one in seen if one in sent) == sorted(sent), (len(seen), len(sent)))

    # The stranger's are still held, two pages of them. A host works through what's held a page at a
    # time when rules arrive, and what's past the first page has to move as well.
    held = f"SELECT count(*) FROM quarantine WHERE recipient = '{net.ids['ben']}' AND sender = '{stranger}'"
    check("control: all the stranger left is still held", int(net.postgres.sql("host_b", held)) == HELD_FROM_A_STRANGER, net.postgres.sql("host_b", held))
    added = rules_listing(net, "ben", net.contact_entry("ana"), e2e.named_at(f"stranger~{net.domain['a']}", stranger))
    check("control: Ben's owner adds the stranger", added == 200, added)
    from_them = f"sender = '{stranger}' AND {LARGE}"
    moved = wait_until(lambda: waiting_for(net, "ben", from_them) == HELD_FROM_A_STRANGER, timeout=30)
    check("everything held from them moves to his inbox, past the first page of it", moved, waiting_for(net, "ben", from_them))
    check("and none of it is still held", int(net.postgres.sql("host_b", held)) == 0, net.postgres.sql("host_b", held))


def shown_then_pushed_off_the_page_is_still_cleared(net: e2e.Network, sent: set[str], on_a_page: int) -> list[str]:
    """Ben's agent is shown a page of large messages. Before it clears them a note comes from someone
    else, which goes ahead of all but Ana's first, so the page a host gives next has one large message
    fewer. Signet looked on that page for what an ack named, so the one pushed off stayed, and came
    again."""
    shown: list[str] = []

    def a_full_page_shown() -> bool:
        status, page = net.agent("ben", "GET", "/v0/inbox", timeout=120)
        shown[:] = [message["verified"]["message_id"] for message in page.get("messages", [])] if status == 200 else []
        return sum(1 for one in shown if one in sent) == on_a_page

    check("control: Ben's agent is shown a page of the large messages", wait_until(a_full_page_shown, timeout=120), len(shown))
    note = words_from(net, "carol", "ben", LONG_NOTE, 1)

    def pushed_off() -> list[str]:
        status, _, page = read_as(net, "ben", "/v0/inbox")
        on_it = ids_on(page) if status == 200 else []
        return [one for one in shown if one not in on_it] if note <= set(on_it) else []

    check("control: a note from someone else pushes one of them off the page", wait_until(pushed_off, timeout=60), len(pushed_off()))
    acked: tuple[int, dict] = (0, {})

    def answered() -> bool:
        nonlocal acked
        acked = net.agent("ben", "POST", "/v0/inbox/ack", {"message_ids": shown}, timeout=120)
        return acked[0] == 200

    check("its ack still clears every one it was shown", wait_until(answered, timeout=120) and acked[1].get("acked") == len(shown), acked)
    check("and they're gone from his host", waiting_for(net, "ben", LARGE) == LARGE_MESSAGES - on_a_page, waiting_for(net, "ben", LARGE))
    return shown


def answers_held_stop_at_the_room_and_it_comes_back(net: e2e.Network, request: str, last_page_after: int, large: set[str], short: set[str]) -> None:
    """With a full page of Ben's inbox waiting, his long request, and short messages waiting for Carol
    on the same host. Two unread pages of Ben's inbox nearly fill the room, so a page of the request
    doesn't fit, nor does a large message. Its short last page takes no room."""
    one, another, anyone = "203.0.113.50", "203.0.113.51", "203.0.113.52"
    inbox, steps, last_steps = "/v0/inbox", f"/v0/requests/{request}", f"/v0/requests/{request}/after/{last_page_after}"
    port = net.host_port["b"]
    owner, view = net.owners["ben"], f"/v0/owner-view/{net.ids['ben']}"

    def not_a_page(source: str) -> tuple[int, str | None]:
        """Ben's owner reading the long view, which is counted once it's built, as it isn't a page."""
        proof = e2e.sign_jws(owner.key, "splint-access", json.dumps({
            "signer": owner.id, "host": net.domain["b"], "method": "GET", "path": view,
            "body_sha256": e2e.hashlib.sha256(b"").hexdigest(), "issued_at": int(time.time()),
        }).encode())
        return ask(port, source, view, Authorization=f"Splint {proof}")

    def told(agent: str, path: str, source: str) -> tuple[int, str | None]:
        return read_as(net, agent, path, source)[:2]

    def no_large_message(source: str, refusal: int) -> tuple[bool, object]:
        """A page of an inbox is cut to what's left, so a reader of Ben's is given the short messages
        earlier scenarios left ahead of the large ones, if any, and otherwise told to come back."""
        status, retry, page = read_as(net, "ben", inbox, source)
        given = ids_on(page)
        held_back = (status, retry) == (refusal, "1") if status != 200 else bool(given) and not large & set(given)
        return held_back, (status, retry, len(given))

    status, _, page = read_as(net, "ben", inbox, one)
    check("control: with nothing held, a source reads a page of the inbox, large messages and all", status == 200 and large & set(ids_on(page)), status)
    check("control: and a page of the long request", told("ben", steps, anyone)[0] == 200)
    check("control: and what isn't a page", not_a_page(anyone)[0] == 200)
    status, _, page = read_as(net, "carol", inbox, anyone)
    all_of_carols = ids_on(page)
    check("control: and all of Carol's short messages, on one page", status == 200 and short <= set(all_of_carols), (status, len(all_of_carols)))

    first = unread_answer(net, "ben", inbox, one)
    answer = told("ben", steps, one)
    check("a source whose unread answer holds its share is told to wait for another page", answer == (429, "1"), answer)
    check("and is given no more large messages of the inbox", *no_large_message(one, 429))
    answer = not_a_page(one)
    check("or for what isn't a page, which is counted once it's built", answer == (429, "1"), answer)
    check("control: it's answers it's over, as a call of its own with a short one is answered", ask(port, one)[0] == 200)
    check("someone else isn't held up by that", told("ben", steps, anyone)[0] == 200)

    second = unread_answer(net, "ben", inbox, another)
    answer = told("ben", steps, anyone)
    check("with the room nearly full of unread answers, a reader of the long request is told to come back", answer == (503, "1"), answer)
    check("and a reader of the inbox is given none of its large messages", *no_large_message(anyone, 503))
    answer = not_a_page(anyone)
    check("and so is whoever asks for what isn't a page", answer == (503, "1"), answer)
    check("a short page is still given, as one that small takes no room", told("ben", last_steps, anyone)[0] == 200)
    status, _, page = read_as(net, "carol", inbox, anyone)
    part = ids_on(page)
    check(
        "and a reader of an inbox of short messages is given the ones that fit in what's left, in order",
        status == 200 and 0 < len(part) < len(all_of_carols) and part == all_of_carols[:len(part)], (status, len(part), len(all_of_carols)),
    )

    read_to_the_end(first)
    check("an answer its caller has read gives its room back", wait_until(lambda: told("ben", steps, anyone)[0] == 200, timeout=5))
    check("to what isn't a page as well", wait_until(lambda: not_a_page(anyone)[0] == 200, timeout=5))
    status, _, page = read_as(net, "carol", inbox, anyone)
    check("and Carol's reader is given all of hers again", status == 200 and ids_on(page) == all_of_carols, (status, len(ids_on(page))))
    check("and its source its share", wait_until(lambda: told("ben", steps, one)[0] == 200, timeout=5))
    answer = told("ben", steps, another)
    check("control: the other source still holds its own", answer == (429, "1"), answer)
    second.close()
    check("hanging up on an unread answer gives the room back too", wait_until(lambda: told("ben", steps, another)[0] == 200, timeout=5))
    first.close()


def one_source_cant_flood_with_calls(net: e2e.Network) -> None:
    """Issue 157: anyone could make a host verify signatures as fast as they could connect."""
    port = net.host_port["a"]
    answers = [ask(port, "203.0.113.11", "/v0/inbox")[0] for _ in range(CALLS_PER_SOURCE_PER_SECOND * 4)]
    check("a source past its rate is told to wait", 429 in answers, answers)
    check("control: it got something first", 401 in answers or 400 in answers, answers)
    check("someone else isn't held up by that", ask(port, "203.0.113.12")[0] == 200)
    check("and after a moment it can call again", wait_until(lambda: ask(port, "203.0.113.11")[0] == 200, timeout=3))


def outbound_rows(net: e2e.Network, sender: str, count: int) -> None:
    net.postgres.sql("host_a", f"""
        INSERT INTO outbound (message_id, sender, envelope, sender_identity, recipient_host, expires_at, status)
        SELECT 'filler-' || number, '{sender}', 'x', 'x', 'removed-peer.example', 4000000000, 'delivered'
        FROM generate_series(1, {count}) AS number""")


def sign_limits(net: e2e.Network, agent: str, *others: str, **limits: int) -> None:
    draft = e2e.rules_draft([net.contact_entry(other) for other in others], limits=e2e.LIMITS | limits)
    rules = net.owners[agent].sign("rules", "--agent", net.ids[agent], stdin=json.dumps(draft))
    status, answer = net.put_rules(agent, rules)
    if status != 200:
        raise RuntimeError(f"{agent}'s rules were refused: {status} {answer}")


def sends_are_the_operators_to_raise_and_the_owners_to_lower(net: e2e.Network) -> None:
    """Issue 324: sends were a fixed 300 an hour, whoever ran the host."""
    mallory = net.ids["mallory"]
    outbound = f"http://{net.domain['a']}/v0/outbound"

    def fresh() -> dict:
        envelope = net.envelope_signed_by("mallory", "mallory", "ben", "one more from a busy agent")
        return {"envelope": envelope, "recipient_host": net.domain["b"]}

    def send() -> int:
        return e2e.http("POST", outbound, fresh())[0]

    def start_again(rows: int, **limits: int) -> None:
        net.postgres.sql("host_a", f"DELETE FROM outbound WHERE sender = '{mallory}'")
        outbound_rows(net, mallory, rows)
        sign_limits(net, "mallory", "ben", **limits)

    start_again(RAISED_SENDS_PER_HOUR - 1)
    check(f"an operator's raised limit lets the {RAISED_SENDS_PER_HOUR}th through, past the usual 300", send() == 200)
    check("and it's still a limit", send() == 429)

    start_again(349, sends_per_hour=350)
    check("control: an owner's lower limit lets its 350th through", send() == 200)
    check("and no more", send() == 429)

    start_again(RAISED_SENDS_PER_HOUR, sends_per_hour=9000)
    check("signing more than the host allows gets no more", send() == 429)

    start_again(0, sends_per_day=2)
    check("control: an owner's daily limit lets the first through", send() == 200)
    check("and the second", send() == 200)
    check("and no more", send() == 429)

    # Or a thief with the owner's key could stop contacts hearing that it's been stolen.
    start_again(0, sends_per_hour=0)
    check("control: an owner's limit of nothing stops a message", send() == 429)
    history = json.loads(json.loads((net.work / "mallory" / "history.json").read_text())["history"])
    body = json.dumps({"step": "change_notice", "history": history}, separators=(",", ":"))
    notice = e2e.signed_envelope(net.key_of("mallory"), mallory, net.ids["ben"], body)
    answer = e2e.http("POST", outbound, {"envelope": notice, "recipient_host": net.domain["b"]})
    check("but not a notice telling contacts of a change", answer[0] == 200, answer)

    # A host can be modified to ignore all that, so the agent's own Signet holds to it too. Agreeing
    # types as the network started took some of mallory's hour there, so its Signet starts a fresh one,
    # which it reads from its file at start.
    start_again(0, sends_per_hour=2)
    (net.work / "mallory" / "budget.json").write_text(json.dumps({"taken": []}))
    net.signets["mallory"].kill_hard()
    net.signets["mallory"].start()
    check("control: Mallory's Signet comes back", net.wait_for_signet("mallory"))
    answers = [net.send("mallory", "ben", f"through Signet {number}")[0] for number in range(3)]
    check("an agent's Signet holds it to what its owner signed", answers[:2] == [200, 200] and answers[2] != 200, answers)
    sign_limits(net, "mallory", "ben")
    net.postgres.sql("host_a", f"DELETE FROM outbound WHERE sender = '{mallory}' AND message_id LIKE 'filler-%'")


def one_stuck_destination_leaves_the_queue_to_the_rest(net: e2e.Network) -> None:
    """Issue 533: one dead peer or one full inbox could take all an agent had waiting, and it could send to nobody."""
    mallory = net.ids["mallory"]
    outbound = f"http://{net.domain['a']}/v0/outbound"
    ben, anyone = f"'{net.ids['ben']}'", "'someone-' || number"

    def fields(recipient: str) -> dict:
        envelope = net.envelope_signed_by("mallory", "mallory", recipient, f"while one place is stuck {time.monotonic_ns()}")
        return {"envelope": envelope, "recipient_host": net.domain[net.home[recipient]]}

    def send(recipient: str) -> tuple[int, dict]:
        return e2e.http("POST", outbound, fields(recipient))

    def waiting(rows: int, recipient: str, recipient_host: str, size: int = 1) -> None:
        # Ones the worker won't touch: held for a peer off the list, or due only tomorrow.
        status, due = ("peer_removed", "now()") if recipient_host == "removed-peer.example" else ("pending", "now() + interval '1 day'")
        net.postgres.sql("host_a", f"DELETE FROM outbound WHERE sender = '{mallory}'")
        net.postgres.sql("host_a", f"""
            INSERT INTO outbound (message_id, sender, envelope, sender_identity, recipient_host, recipient, expires_at, status, next_attempt_at)
            SELECT 'stuck-' || number, '{mallory}', repeat('x', {size}), 'x', '{recipient_host}', {recipient}, 4000000000, '{status}', {due}
            FROM generate_series(1, {rows}) AS number""")

    sign_limits(net, "mallory", "ben", "carol", "ana")
    waiting(QUEUED_PER_AGENT, anyone, "removed-peer.example")
    full = send("ana")
    check(f"control: {QUEUED_PER_AGENT} waiting for anyone fill an agent's queue", full[0] == 429, full)

    # Each send counts the queue again as it's stored, one at a time, so sends at once can't each take the last place.
    waiting(QUEUED_PER_AGENT - 1, anyone, "removed-peer.example")
    at_once = [fields("ana") for _ in range(SENDS_AT_ONCE)]
    answers: list[tuple[int, dict]] = []
    start = threading.Barrier(SENDS_AT_ONCE)

    def send_at_once(sent: dict) -> None:
        start.wait()
        answers.append(e2e.http("POST", outbound, sent))

    threads = [threading.Thread(target=send_at_once, args=(sent,)) for sent in at_once]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    statuses = sorted(status for status, _ in answers)
    check(f"{SENDS_AT_ONCE} sends at once for the last place: one gets it", statuses == [200] + [429] * (SENDS_AT_ONCE - 1), statuses)
    queued = net.postgres.sql("host_a", f"SELECT count(*) FROM outbound WHERE sender = '{mallory}'")
    check("and the queue took no more than its limit", int(queued) == QUEUED_PER_AGENT, queued)

    def share_holds(what: str, to: str, other: str, recipient: str, recipient_host: str, under: tuple[int, int], at: tuple[int, int]) -> None:
        rows, size = under
        waiting(rows, recipient, recipient_host, size)
        control = send(to)
        check(f"control: just under {what}, one more to {to} goes", control[0] == 200, control)
        rows, size = at
        waiting(rows, recipient, recipient_host, size)
        refused = send(to)
        check(f"{what} stops more to {to}, with the same refusal as a full queue", refused == full, (refused, full))
        check(f"but {other} still gets them", send(other)[0] == 200)

    share_holds(f"{QUEUED_PER_RECIPIENT} waiting for one recipient", "ben", "carol", ben, "removed-peer.example",
                (QUEUED_PER_RECIPIENT - 1, 1), (QUEUED_PER_RECIPIENT, 1))
    share_holds(f"{QUEUED_PER_RECIPIENT_HOST} waiting for one host", "carol", "ana", anyone, net.domain["b"],
                (QUEUED_PER_RECIPIENT_HOST - 1, 1), (QUEUED_PER_RECIPIENT_HOST, 1))
    share_holds("one recipient's share of the bytes", "ben", "carol", ben, "removed-peer.example",
                (1, QUEUED_BYTES_PER_RECIPIENT - ROOM_FOR_ONE), (1, QUEUED_BYTES_PER_RECIPIENT))
    share_holds("one host's share of the bytes", "carol", "ana", anyone, net.domain["b"],
                (1, QUEUED_BYTES_PER_RECIPIENT_HOST - ROOM_FOR_ONE), (1, QUEUED_BYTES_PER_RECIPIENT_HOST))

    net.postgres.sql("host_a", f"DELETE FROM outbound WHERE sender = '{mallory}'")
    sign_limits(net, "mallory", "ben")


def new_interactions_stop_at_what_the_operator_allows(net: e2e.Network) -> None:
    """Issue 324: an owner's limit was held at a fixed 200, and now it's a host's to set."""
    sign_limits(net, "ana", "ben", new_requests_per_contact_per_day=5000)
    sign_limits(net, "ben", "ana", new_requests_per_contact_per_day=5000)
    ben = net.address("ben")
    # Only new requests to ben: a type proposed counts apart from them, and the network agreed some.
    counted = f"SELECT count(*) FROM new_requests WHERE agent = '{net.ids['ana']}' AND peer = '{net.ids['ben']}' AND outgoing AND NOT proposal"
    answers = [net.agent("ana", "POST", "/v0/requests", meeting_ask(ben))[0] for _ in range(LOWERED_REQUESTS_PER_CONTACT + 1)]
    check("control: rules saying 5000 are taken, and Signet goes by them", answers == [200] * (LOWERED_REQUESTS_PER_CONTACT + 1), answers)
    reached = wait_until(lambda: net.postgres.sql("host_a", counted) == str(LOWERED_REQUESTS_PER_CONTACT))
    check(f"its host takes the {LOWERED_REQUESTS_PER_CONTACT} its operator allows", reached, net.postgres.sql("host_a", counted))
    # Signet keeps the last one and goes on asking, as it does at any limit that time will lift.
    time.sleep(3)
    check("and no more", net.postgres.sql("host_a", counted) == str(LOWERED_REQUESTS_PER_CONTACT), net.postgres.sql("host_a", counted))


def agents_are_the_operators_to_limit(net: e2e.Network) -> None:
    """Issue 324, and the open signup limits."""
    work = net.work / "operator-limits"
    work.mkdir()

    def register(owner: e2e.Owner, handle: str) -> int:
        key = work / f"{handle}.key"
        identity, agent_id = new_identity(key)
        return net.register_on_a(key, owner, handle, identity, agent_id)

    owner = new_owner(work / "busy-owner")
    answers = [register(owner, f"busy-{number}") for number in range(AGENTS_PER_OWNER + 1)]
    check(f"an owner gets the {AGENTS_PER_OWNER} this operator allows, not the usual 8", answers == [200] * AGENTS_PER_OWNER + [429], answers)

    host = net.domain["a"]
    number = iter(range(1000))

    def register_open(source: str) -> int:
        which = next(number)
        return agent_signup.raw_register(host, work, f"open-{which}", new_owner(work / f"open-{which}-owner"), source)

    answers = [register_open(f"192.0.2.{n}") for n in range(1, OPEN_AGENTS_PER_HOUR + 2)]
    check(f"open signups stop at the {OPEN_AGENTS_PER_HOUR} an hour this operator allows, not the usual 20", answers == [200] * OPEN_AGENTS_PER_HOUR + [429], answers)


def a_mistaken_setting_stops_the_host() -> None:
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)

        def outcome(**changes: str) -> tuple[int | None, str]:
            return tls_rules.run_until_it_stops("host", tls_rules.host_settings(work, **changes))

        for setting, words in (
            ({"SPLINT_MAX_AGENT": "9000"}, "isn't a limit"),
            ({"SPLINT_MAX_AGENTS": "many"}, "whole number"),
            ({"SPLINT_MAX_CONNECTIONS": "0"}, "at least 1"),
            ({"SPLINT_MAX_BODY_BYTES_AT_ONCE": "64"}, "largest body"),
            ({"SPLINT_MAX_BODY_BYTES_AT_ONCE_PER_SOURCE": str(LARGEST_BODY - 1)}, "largest body"),
            ({"SPLINT_MAX_ANSWER_BYTES_AT_ONCE": "4096"}, "page of answers"),
            ({"SPLINT_MAX_ANSWER_BYTES_AT_ONCE_PER_SOURCE": str(ANSWER_PAGE - 1)}, "page of answers"),
        ):
            code, output = outcome(**setting)
            check(f"a host refuses {setting}", code not in (0, None) and words in output, (code, output[-300:]))

        code, output = outcome(SPLINT_MAX_AGENTS="9000")
        check("control: a right one gets past that", code is None, output[-300:])
        check("and a raised one warns in the log", "WARN" in output and "SPLINT_MAX_AGENTS" in output, output[-300:])

        listed = re.findall(r"^#(SPLINT_MAX_\w+)=(\d+)$", (DEPLOY / "limits.env").read_text(), re.MULTILINE)
        in_code = set(re.findall(r'"(SPLINT_MAX_\w+)"', (e2e.PACKAGES / "host/src/limits.rs").read_text()))
        check("what an operator is shown lists every limit there is", {name for name, _ in listed} == in_code - {"SPLINT_MAX_AGENT"}, {name for name, _ in listed} ^ in_code)
        code, output = outcome(**dict(listed))
        check("and each at the number a host really uses", code is None and "WARN" not in output, output[-300:])


def the_server_setup_is_at_least_well_formed() -> None:
    """Not run for real here, which needs a server: sim/live_hosts.py does that."""
    syntax = subprocess.run(["bash", "-n", str(DEPLOY / "install.sh")], capture_output=True, text=True)
    check("the install script parses", syntax.returncode == 0, syntax.stderr)
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "Caddyfile"
        config.write_text((DEPLOY / "Caddyfile").read_text().replace("@DOMAIN@", "host.example"))
        config.chmod(0o644)
        Path(directory).chmod(0o755)
        validated = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{directory}:/config:ro", CADDY_IMAGE, "caddy", "validate", "--adapter", "caddyfile", "--config", "/config/Caddyfile"],
            capture_output=True, text=True,
        )
        check("the proxy takes its settings", validated.returncode == 0, validated.stderr[-500:])


def main() -> int:
    e2e.build()
    a_mistaken_setting_stops_the_host()
    the_server_setup_is_at_least_well_formed()
    with e2e.running_network(kind=GuardedNetwork) as network:
        for scenario in (
            one_source_cant_hold_every_call,
            callers_holding_bodies_stop_at_the_room_and_it_comes_back,
            one_source_cant_flood_with_calls,
            sends_are_the_operators_to_raise_and_the_owners_to_lower,
            one_stuck_destination_leaves_the_queue_to_the_rest,
            new_interactions_stop_at_what_the_operator_allows,
            agents_are_the_operators_to_limit,
            large_answers_come_in_pages_and_nothing_is_lost,
            a_flood_of_connections_stops_at_the_cap_and_delivery_goes_on,
            idle_and_slow_callers_get_closed,
        ):
            print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
            scenario(network)
        if e2e.failures:
            for process in network.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1000:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

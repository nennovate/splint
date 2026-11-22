#!/usr/bin/env python3
"""Hostile bodies, headers, paths and encodings at every route of a real host and Signet.

Also the other direction: a hostile host answering Signet, and a hostile peer answering a host.
The agents are scripted, with no model, because no result here depends on one. Needs Docker for
Postgres and openssl for signing, like e2e.py, whose network this runs on.

Checks: no process crashes or panics, no 500, no 5xx with more than a fixed word, no secret or
internal detail in a response or a log, no message content in a log, memory stays bounded, and
what a hostile host hands Signet never reaches the agent unless its signature checks out.

Each run prints its seed. The same seed makes the same choices in each worker, though timing,
fresh keys and signatures differ, so a finding also saves its input under sim/runs/.

Not shown here: TLS, real networks or a proxy in front (everything is on localhost), hardware-held
keys, or release builds (these are debug builds, which panic on overflow and so catch more).
"""

import argparse
import base64
import collections
import hashlib
import json
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import e2e
import request_driver

HOST_ROUTES = [
    ("POST", "/v0/agents"),
    ("POST", "/v0/retirements"),
    ("POST", "/v0/recoveries"),
    ("PUT", "/v0/changes"),
    ("GET", "/v0/known-owners"),
    ("GET", "/v0/known-owners/after/{}"),
    ("POST", "/v0/revocations"),
    ("GET", "/.well-known/splint/agents/{}"),
    ("GET", "/.well-known/splint/host"),
    ("GET", "/.well-known/splint/agents.md"),
    ("GET", "/"),
    ("POST", "/v0/lookup"),
    ("PUT", "/v0/rules"),
    ("GET", "/v0/rules"),
    ("GET", "/v0/quarantine"),
    ("GET", "/v0/quarantine/after/{}"),
    ("GET", "/v0/invites"),
    ("GET", "/v0/invites/after/{}"),
    ("POST", "/v0/outbound"),
    ("POST", "/v0/guest/outbound"),
    ("GET", "/v0/guest/steps/{}"),
    ("GET", "/v0/guest/links/{}"),
    ("POST", "/v0/guest/links/{}"),
    ("GET", "/v0/refused"),
    ("GET", "/v0/outbound/{}"),
    ("POST", "/v0/deliver"),
    ("GET", "/v0/inbox"),
    ("POST", "/v0/inbox/ack"),
    ("POST", "/v0/inbox/later"),
    ("GET", "/v0/requests/{}"),
    ("GET", "/v0/requests/" + "ab" * 32 + "/after/{}"),
]
SIGNET_ROUTES = [
    ("GET", "/v0/identity"),
    ("GET", "/v0/contacts"),
    ("GET", "/v0/types"),
    ("POST", "/v0/send"),
    ("GET", "/v0/sent/{}"),
    ("GET", "/v0/inbox"),
    ("POST", "/v0/inbox/ack"),
    ("POST", "/v0/requests"),
    ("GET", "/v0/requests"),
    ("GET", "/v0/requests/{}"),
    ("POST", "/v0/requests/{}/say"),
    ("POST", "/v0/requests/{}/counter"),
    ("POST", "/v0/requests/{}/accept"),
    ("POST", "/v0/requests/{}/clarify"),
    ("POST", "/v0/requests/{}/progress"),
    ("POST", "/v0/requests/{}/pause"),
    ("POST", "/v0/requests/{}/resume"),
    ("POST", "/v0/requests/{}/deliver"),
    ("POST", "/v0/requests/{}/decline"),
    ("POST", "/v0/requests/{}/cancel"),
    ("GET", "/v0/requests/{}/record"),
    ("GET", "/v0/grants"),
    ("POST", "/v0/grants/{}/proof"),
    ("POST", "/v0/owner/guest-links"),
    ("GET", "/v0/owner/refused"),
    ("PUT", "/v0/owner/binding"),
    ("PUT", "/v0/owner/rules"),
    ("PUT", "/v0/owner/grants"),
    ("PUT", "/v0/owner/transfer"),
    ("PUT", "/v0/owner/recovery"),
    ("PUT", "/v0/owner/change"),
    ("PUT", "/v0/owner/revocation"),
    ("GET", "/v0/owner/changes"),
    ("POST", "/v0/owner/changes/accept"),
    ("GET", "/v0/owner/approvals"),
    ("POST", "/v0/owner/approvals"),
    ("GET", "/v0/owner/requests/{}/outcome"),
    ("GET", "/v0/owner/requests/{}/record"),
    ("GET", "/v0/owner/person-text"),
    ("POST", "/v0/owner/person-text"),
    ("GET", "/v0/owner/quarantine"),
    ("POST", "/v0/owner/invites/redeem"),
    ("GET", "/v0/where-paid"),
    ("POST", "/v0/owner/where-paid"),
    ("POST", "/v0/requests/{}/pay_request"),
    ("POST", "/v0/requests/{}/payment_received"),
]
# Routes with no proof of their own: what they carry is signed, or the caller is a stranger or a peer.
HOST_ROUTES_WITHOUT_A_PROOF = {
    "/v0/outbound", "/v0/deliver", "/v0/rules", "/v0/retirements", "/v0/recoveries", "/v0/revocations", "/v0/changes",
}
HOST_BODY_LIMIT = 512 * 1024
SIGNET_BODY_LIMIT = 2 * 1024 * 1024
WORKERS = 6
TEMPLATE_LIFETIME_SECS = 60
ANSWER_TIMEOUT_SECS = 20.0
INCOMPLETE_TIMEOUT_SECS = 1.0
SLOW_SENDERS = 64
# Past the longest a host gives a request, so one that's still connected at the end shows it isn't closing them.
SLOW_SECS = 55
MAX_BODY_FLOOD_REQUESTS = 96
RSS_LIMIT_MIB = 400
RSS_GROWTH_LIMIT_MIB = 128
MIB = 1024 * 1024
RUNS = Path(__file__).resolve().parent / "runs"

# These go in every hostile string, so a log or a response that repeats one shows up in a search.
MARKER = "zqxhostilecontentzqx"
LEAK = re.compile(
    rb"panicked|sqlx|postgres|SQLSTATE|/Users/|/private/|/home/|src/[a-z_]+\.rs|backtrace|token-for-|PRIVATE KEY|relation \"",
    re.IGNORECASE,
)
FIXED_5XX = {
    b'{"error":"try again"}',
    b'{"error":"dates don\'t fit"}',
    b'{"error":"host is unreachable"}',
    b'{"error":"host refused the request"}',
    b'{"error":"host gave an answer that doesn\'t check out"}',
    b'{"error":"couldn\'t find an agent at that address"}',
    b'{"error":"couldn\'t save Signet\'s state"}',
    b'{"error":"the host speaks another Splint protocol, so this Signet or the host has to update"}',
    b'{"error":"the host speaks only newer Splint protocols, so this agent\'s Splint is behind and has to update to the newest release"}',
    b'{"error":"the host speaks only older Splint protocols, so the host is behind and whoever runs it has to update it"}',
}
DELIVERY_FAILURES = {
    "", "unreachable", "peer_error", "peer_busy", "peer_refused", "recipient_not_found", "malformed", "local_error", "other_protocol",
}
DELIVERY_STATES = {"pending", "delivered", "rejected", "expired", "peer_removed"}


def nul_claim(typ: str, fields: dict) -> str:
    """A compact object whose claimed sender is a NUL. It's read before any signature is checked."""
    header = json.dumps({"alg": "ES256", "typ": typ}).encode()
    return f"{e2e.encode(header)}.{e2e.encode(json.dumps(fields).encode())}.{e2e.encode(bytes(64))}"


def nul_handle(_campaign: "Campaign") -> bytes:
    return request("GET", "/.well-known/splint/agents/%00", [])


def nul_agent_in_a_proof(campaign: "Campaign") -> bytes:
    fields = {
        "signer": "\u0000", "host": campaign.net.domain["a"], "method": "GET", "path": "/v0/inbox",
        "body_sha256": hashlib.sha256(b"").hexdigest(), "issued_at": int(time.time()),
    }
    return request("GET", "/v0/inbox", [("Authorization", f"Splint {nul_claim('splint-access', fields)}")])


def nul_sender_in_an_envelope(campaign: "Campaign") -> bytes:
    now = int(time.time())
    fields = {
        "v": 1, "sender": "\u0000", "recipient": "x", "body": "", "created_at": now, "expires_at": now + 60, "nonce": "",
    }
    body = {"envelope": nul_claim("splint-envelope", fields), "recipient_host": campaign.net.domain["b"]}
    return request("POST", "/v0/outbound", [("Content-Type", "application/json")], json.dumps(body).encode())


def only_a_string(route: str, auth: list) -> bytes:
    return request("POST", route, [("Content-Type", "application/json"), *auth], f'"{MARKER}"'.encode())


def is_503(status: int | str, _answer: bytes) -> bool:
    return status == 503


def repeats_input(_status: int | str, answer: bytes) -> bool:
    return MARKER.encode() in answer


# Inputs that broke something once. Each run replays them first, and any that does again is a finding.
ONCE_BROKE = [
    {"name": "a NUL handle", "target": "host-a", "raw": nul_handle, "broken": is_503},
    {"name": "a NUL signer in an unsigned proof", "target": "host-a", "raw": nul_agent_in_a_proof, "broken": is_503},
    {"name": "a NUL sender in an unsigned envelope", "target": "host-a", "raw": nul_sender_in_an_envelope, "broken": is_503},
    {"name": "a body that's only a string, at a host", "target": "host-a",
     "raw": lambda _campaign: only_a_string("/v0/outbound", []), "broken": repeats_input},
    {"name": "a body that's only a string, at Signet", "target": "signet-ana",
     "raw": lambda _campaign: only_a_string("/v0/send", [("Authorization", f"Bearer {e2e.TOKENS['ana']}")]), "broken": repeats_input},
]
# What's found and tracked by an open issue, by kind, so it doesn't fail the run. A new way to break
# something does.
OPEN_FINDINGS: dict[str, int] = {}


class Findings:
    """What broke, by kind and route, with the first input that did it."""

    def __init__(self, out: Path) -> None:
        self.lock = threading.Lock()
        self.counts: collections.Counter = collections.Counter()
        self.statuses: collections.Counter = collections.Counter()
        self.out = out
        out.mkdir(parents=True, exist_ok=True)

    def add(self, kind: str, route: str, raw: object, detail: bytes = b"") -> None:
        with self.lock:
            key = (kind, route)
            self.counts[key] += 1
            if self.counts[key] == 1:
                print(f"FINDING {kind} at {route}: {repr(raw)[:300]} -> {detail[:300]!r}", flush=True)
                with (self.out / "findings.jsonl").open("a") as saved:
                    saved.write(json.dumps({
                        "kind": kind, "route": route, "input": repr(raw)[:8192], "response": repr(detail)[:4096],
                    }) + "\n")

    def status(self, target: str, route: str, status: object) -> None:
        with self.lock:
            self.statuses[(target, route, status)] += 1


def request(method: str, path: str, headers: list[tuple[str, str | bytes]], body: bytes = b"", length: bool = True) -> bytes:
    lines = [f"{method} {path} HTTP/1.1".encode(errors="surrogateescape"), b"Host: fuzz.test", b"Connection: close"]
    for name, value in headers:
        lines.append(name.encode() + b": " + (value if isinstance(value, bytes) else value.encode()))
    if length and (body or method == "POST"):
        lines.append(b"Content-Length: " + str(len(body)).encode())
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def exchange(port: int, raw: bytes, timeout: float = ANSWER_TIMEOUT_SECS) -> tuple[int | str, bytes]:
    """Sends bytes and reads one answer. The status is a word when no answer came."""
    received = b""
    silence = "closed"
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as connection:
            try:
                connection.sendall(raw)
            except OSError:
                pass  # It may refuse before reading everything, and its answer is still there to read.
            while chunk := connection.recv(65536):
                received += chunk
    except TimeoutError:
        silence = "timeout"
    except OSError:
        silence = "reset"
    status = received_status(received)
    if status is None:
        return silence, received[:200]
    return status, received.partition(b"\r\n\r\n")[2]


def received_status(received: bytes) -> int | None:
    match = re.match(rb"HTTP/1\.[01] (\d{3})", received)
    return int(match.group(1)) if match else None


class Target:
    """One running process and the valid requests that hostile ones are made from."""

    def __init__(self, name: str, port: int, routes: list, auth_header) -> None:
        self.name, self.port, self.routes, self.auth_header = name, port, routes, auth_header
        self.body_limit = HOST_BODY_LIMIT if name.startswith("host") else SIGNET_BODY_LIMIT


def unsigned_compact(rng: random.Random, typ: str, fields: dict) -> str:
    """Shaped like a signed object, so it passes everything that runs before the signature check."""
    hostile = dict(fields)
    if hostile and rng.random() < 0.8:
        hostile[rng.choice(list(hostile))] = rng.choice(hostile_values(rng))
    header = json.dumps({"alg": "ES256", "typ": typ}).encode()
    return f"{e2e.encode(header)}.{e2e.encode(json.dumps(hostile).encode())}.{e2e.encode(rng.randbytes(64))}"


def hostile_values(rng: random.Random) -> list:
    return [
        None, True, 0, -1, 1.5, 1e308, 2**64, -(2**63) - 1, "", MARKER, MARKER + "\u0000", "\u0000", "\ud800",
        "‮" + MARKER, "a\nb" + MARKER, "../../etc/passwd", "x" * rng.choice([70, 70_000]), [], {}, [MARKER],
        {"a": MARKER}, "﻿" + MARKER, "splint1" + "0" * 64, "e" * 64, "'; DROP TABLE agents; --",
    ]


def mutate_compact(rng: random.Random, compact: str) -> str:
    parts = compact.split(".")
    choice = rng.randrange(9)
    if choice == 0:
        return ".".join(parts[:-1])
    if choice == 1:
        return compact + ".AAAA"
    if choice == 2:
        return compact + "=="
    if choice == 3:
        return compact.replace("-", "+").replace("_", "/")
    if choice == 4:
        return compact.replace(".", "。", 1)
    if choice == 5:
        return " " + compact
    if choice == 6:
        return compact[: rng.randrange(len(compact) + 1)]
    position = rng.randrange(len(compact))
    return compact[:position] + rng.choice("AB-_.=%\u0000") + compact[position + 1:]


def hostile_body(rng: random.Random, template: dict, limit: int) -> bytes:
    """A body made from a valid one, in one of the ways a JSON reader can go wrong."""
    good = json.dumps(template)
    field = rng.choice(list(template)) if template else "x"
    choice = rng.randrange(19)
    if choice <= 3:
        return json.dumps({**template, field: rng.choice(hostile_values(rng))}).encode()
    if choice == 4:
        return json.dumps({name: value for name, value in template.items() if name != field}).encode()
    if choice == 5:
        return ('{"%s":%s,' % (field, json.dumps(MARKER)) + good[1:]).encode()
    if choice == 6:
        return json.dumps({**template, "extra" + MARKER: MARKER}).encode()
    if choice == 7:
        escaped = "".join(f"\\u{ord(character):04x}" for character in field)
        return good.replace(f'"{field}"', f'"{escaped}"', 1).encode()
    if choice == 8:
        return good.encode()[: rng.randrange(len(good) + 1)]
    if choice == 9:
        raw = bytearray(good.encode())
        raw[rng.randrange(len(raw))] = rng.randrange(256)
        return bytes(raw)
    if choice == 10:
        depth = rng.choice([129, 1_000, 100_000])
        return rng.choice(["[", '{"a":']).encode() * depth
    if choice == 11:
        return rng.choice([f'"{MARKER}"', f'["{MARKER}"]', "null", "0", "1e999", "NaN", "true", f'{{"{MARKER}":1}}']).encode()
    if choice == 12:
        return rng.choice([b"\xef\xbb\xbf" + good.encode(), good.encode("utf-16"), good.encode("utf-32"), good.encode() + b"garbage"])
    if choice == 13:
        return good.replace(MARKER, "", 1).encode().replace(b'"', rng.choice([b"'", b'\xff"', b'\xc0\x80"']), 2)
    if choice == 14:
        return good.encode() + b" " * (limit + 1 - len(good) + rng.randrange(2))
    if choice == 15:
        return json.dumps({**template, field: "x" * (limit - len(good))}).encode()
    if choice == 16:
        return json.dumps({**template, field: "x" * (limit + 1)}).encode()
    if choice == 17 and isinstance(template.get(field), str) and template[field].count(".") == 2:
        compact = template[field]
        if rng.random() < 0.5:
            return json.dumps({**template, field: mutate_compact(rng, compact)}).encode()
        typ = json.loads(e2e.decode(compact.split(".")[0]))["typ"]
        return json.dumps({**template, field: unsigned_compact(rng, typ, e2e.payload_of(compact))}).encode()
    return json.dumps(template).encode().replace(b'"', b"\t\"\r\n ", 2)


def hostile_path(rng: random.Random, route: str) -> str:
    values = [
        "%00", "%ff", "%c0%80", "..%2f..%2fetc%2fpasswd", "%2e%2e", MARKER, "x" * rng.choice([1_000, 9_000, 70_000]),
        "é".encode().decode("latin-1"), "%F0%9F%98%80", "a%0d%0aX-Injected:%20" + MARKER, "%2500", "a;b=c",
        "a?x=" + MARKER, "a#b", "a/b", "ab" * rng.choice([32, 5_000]), "%E2%80%AE" + MARKER, "'%20OR%20'1'='1",
    ]
    if "{}" in route:
        return route.format(rng.choice(values))
    other = [
        route + "/", route.upper(), route + "?" + "a=" * 500, route + "?" + MARKER, "/" + route, route.replace("/", "//"),
        "http://other.test" + route, "*", route + "%00", route + "/.." + route, route + "/%2e%2e" + route,
    ]
    return rng.choice(other)


def hostile_framing(rng: random.Random, method: str, path: str, auth: list, body: bytes) -> tuple[bytes, bool]:
    """The same request, with its headers or framing wrong. True if it's fair for it to get no answer."""
    choice = rng.randrange(17)
    plain = [("Content-Type", "application/json"), *auth]
    if choice == 0:
        return request(method, path, auth, body), False
    if choice == 1:
        kind = rng.choice(["text/plain", "application/json; charset=utf-16", "application/jsonx", "", MARKER, "x" * 9000])
        return request(method, path, [("Content-Type", kind), *auth], body), False
    if choice == 2:
        return request(method, path, plain, body, length=False), False
    if choice == 3:
        return request(method, path, [*plain, ("Content-Length", str(len(body) + 50))], body, length=False), True
    if choice == 4:
        return request(method, path, [*plain, ("Content-Length", str(max(len(body) - 5, 0)))], body, length=False), False
    if choice == 5:
        length = rng.choice(["-1", "+5", "0x10", "18446744073709551616", "1,1", "5, 6", MARKER])
        return request(method, path, [*plain, ("Content-Length", length)], body, length=False), False
    if choice == 6:
        return request(method, path, [*plain, ("Content-Length", "1"), ("Content-Length", "2")], body, length=False), False
    if choice == 7:
        chunked = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        return request(method, path, [*plain, ("Transfer-Encoding", "chunked")], chunked, length=False), False
    if choice == 8:
        broken = rng.choice([b"zz\r\nabc\r\n", b"ffffffffffffffffff\r\n", b"5\r\nabc", b"-1\r\n", b"5;" + b"x" * 9000 + b"\r\n"])
        return request(method, path, [*plain, ("Transfer-Encoding", "chunked")], broken, length=False), True
    if choice == 9:
        chunk = b"x" * 65536
        many = (b"10000\r\n" + chunk + b"\r\n") * 40 + b"0\r\n\r\n"
        return request(method, path, [*plain, ("Transfer-Encoding", "chunked")], many, length=False), False
    if choice == 10:
        return request(method, path, [*plain, ("Transfer-Encoding", "chunked"), ("Content-Length", "3")], b"0\r\n\r\n", length=False), False
    if choice == 11:
        kind = rng.choice([("Transfer-Encoding", "gzip"), ("Content-Encoding", "gzip"), ("Expect", "100-continue"), ("Upgrade", "h2c")])
        return request(method, path, [*plain, kind], body), False
    if choice == 12:
        return request(method, path, [*plain, *[(f"X-{n}", "y" * 1024) for n in range(rng.choice([50, 200]))]], body), False
    if choice == 13:
        return request(method, path, [*plain, ("X-Long", "y" * rng.choice([9_000, 70_000, 400_000]))], body), False
    if choice == 14:
        bad = rng.choice([b"a\r\n b", b"a\x00b", b"\xff\xfe", b"a\nX-Injected: b", MARKER.encode() + b"\r\n"])
        return request(method, path, [*plain, ("X-Bad", bad)], body), False
    if choice == 15:
        return request(method, path, plain, body).replace(b"\r\n", b"\n"), False
    return request(method, path, plain, body)[: rng.randrange(1, 60)], True


def garbage(rng: random.Random) -> bytes:
    return rng.choice([
        rng.randbytes(rng.choice([1, 100, 70_000])),
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + rng.randbytes(64),
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        b"GET /\r\n\r\n",
        b"GET / HTTP/9.9\r\n\r\n",
        b"\r\n" * 1000,
        b"A" * 1_000_000,
        b"\x00" * 10_000,
    ])


class Campaign:
    """Runs hostile requests at every route, and checks what comes back."""

    def __init__(self, net: e2e.Network, findings: Findings, seed: int) -> None:
        self.net, self.findings, self.seed = net, findings, seed
        self.templates: dict[tuple[str, str], dict] = {}
        self.template_lock = threading.Lock()
        self.templates_at = 0.0
        self.sent = 0
        self.rss_samples: dict[str, list[int]] = collections.defaultdict(list)
        self.health_slowest = 0.0
        self.targets = [
            Target("host-a", net.host_port["a"], HOST_ROUTES, self.host_auth),
            Target("host-b", net.host_port["b"], HOST_ROUTES, self.host_auth),
            Target("signet-ana", net.signet_port["ana"], SIGNET_ROUTES, self.signet_auth),
        ]
        self.acceptable_echo_routes = {("signet-ana", "GET", "/v0/inbox")}

    def host_auth(self, target: Target, method: str, path: str, body: bytes) -> list[tuple[str, str]]:
        net = self.net
        if path.startswith("/.well-known") or path == "/" or path in HOST_ROUTES_WITHOUT_A_PROOF:
            return []
        # Signed over whatever the body is, so a hostile one gets past the proof to what parses it.
        if path == "/v0/agents":
            return [("Authorization", f"Splint {net.registration_proof(net.key_of('mallory'), net.ids['mallory'], body)}")]
        agent = "ana" if target.name == "host-a" else "ben"
        return [("Authorization", f"Splint {net.access_proof(agent, agent, method, path, body)}")]

    def signet_auth(self, _target: Target, _method: str, path: str, _body: bytes) -> list[tuple[str, str]]:
        token = self.net.owners["ana"].token if path.startswith("/v0/owner/") else e2e.TOKENS["ana"]
        return [("Authorization", f"Bearer {token}")]

    def refresh_templates(self) -> None:
        """Valid bodies, so a mutated one fails on the thing mutated, and not on being stale."""
        with self.template_lock:
            if time.monotonic() - self.templates_at < TEMPLATE_LIFETIME_SECS:
                return
            net = self.net
            envelope = net.envelope_signed_by("ana", "ana", "ben", f"{MARKER} a message")
            from_a = net.domain["a"]
            ana_identity = net.agent_identity("ana")
            mallory_binding = e2e.accepted(
                net.binding_for(net.owners["mallory"].key, net.owners["mallory"], net.ids["mallory"], net.address("mallory")),
                net.key_of("mallory"),
            )
            contacts = [net.contact_entry(other) for other in e2e.TOKENS if other != "ana"]
            rules = net.sign_rules("ana", contacts)
            # Unsigned, because a real one of these would end an agent the run still needs.
            rng = random.Random(self.seed)
            ending = {"v": 1, "agent": net.ids["mallory"], "owner": net.owners["mallory"].id, "seq": 1, "issued_at": int(time.time())}
            self.templates = {
                ("host", "/v0/agents"): {
                    "owner_identity": net.owners["mallory"].identity, "agent_identity": net.agent_identity("mallory"),
                    "binding": mallory_binding, **e2e.signup_fields(e2e.signup_code(0), mallory_binding),
                },
                ("host", "/v0/retirements"): {"retirement": unsigned_compact(rng, "splint-retirement", ending)},
                ("host", "/v0/recoveries"): {"identity": ana_identity},
                ("host", "/v0/changes"): {"history": json.dumps({"identity": ana_identity, "owners": [net.owners["ana"].identity], "events": []})},
                ("host", "/v0/revocations"): {"revocation": unsigned_compact(rng, "splint-release", ending)},
                ("host", "/v0/lookup"): {"address": net.address("ben")},
                ("host", "/v0/rules"): {"rules": rules},
                ("host", "/v0/inbox/later"): {"seqs": [1, 2, 3]},
                ("host", "/v0/outbound"): {"envelope": envelope, "recipient_host": net.domain["b"]},
                ("host", "/v0/deliver"): {
                    "envelope": envelope, "sender_identity": net.agent_identity("ana"), "from_host": from_a,
                    "proof": net.host_proof(net.work / "host-a.key", envelope, from_a, net.domain["b"]),
                },
                ("host", "/v0/inbox/ack"): {"seqs": [1, 2, 3]},
                ("signet", "/v0/send"): {"to": net.address("ben"), "body": f"{MARKER} a message"},
                ("signet", "/v0/inbox/ack"): {"message_ids": ["0" * 64]},
                ("signet", "/v0/requests"): request_driver.meeting_ask(net.address("ben")),
                ("signet", "/v0/requests/{}/say"): {"fields": {"note": MARKER}},
                ("signet", "/v0/requests/{}/counter"): {"terms": request_driver.DEFAULT_OFFER},
                ("signet", "/v0/requests/{}/accept"): {"pick": {"slot": request_driver.hours_from_now(24)}},
                ("signet", "/v0/requests/{}/clarify"): {"reason": "unclear"},
                ("signet", "/v0/requests/{}/progress"): {"status": "working"},
                ("signet", "/v0/requests/{}/pause"): {"reason": "owner_review"},
                ("signet", "/v0/requests/{}/deliver"): {"result": {"note": MARKER}},
                ("signet", "/v0/requests/{}/decline"): {"reason": "busy"},
                ("signet", "/v0/grants/{}/proof"): {"method": "POST", "path": "/docs/read", "body": "{}"},
                # Each signed by someone else's owner, so a fuzzed copy can't change who this agent is.
                ("signet", "/v0/owner/binding"): {"binding": net.owners["mallory"].bind(ana_identity, net.address("ana"))},
                ("signet", "/v0/owner/rules"): {"rules": rules},
                ("signet", "/v0/owner/grants"): {"grant": unsigned_compact(rng, "splint-grant", ending)},
                ("signet", "/v0/owner/transfer"): {
                    "identity": ana_identity, "new_owner_identity": net.owners["mallory"].identity,
                    "release": unsigned_compact(rng, "splint-release", ending), "binding": mallory_binding,
                },
                ("signet", "/v0/owner/recovery"): {"identity": ana_identity},
                ("signet", "/v0/owner/change"): {"statement": unsigned_compact(rng, "splint-change-statement", ending)},
                ("signet", "/v0/owner/revocation"): {"revocation": unsigned_compact(rng, "splint-release", ending)},
                ("signet", "/v0/owner/changes/accept"): {"acceptance": unsigned_compact(rng, "splint-change-accept", ending)},
                ("signet", "/v0/owner/approvals"): {"approval": unsigned_compact(rng, "splint-approval", ending)},
                ("signet", "/v0/owner/person-text"): {"person_text": unsigned_compact(rng, "splint-person-text", ending)},
                ("signet", "/v0/owner/invites/redeem"): {"to": net.address("ben"), "proof": unsigned_compact(rng, "splint-invite-redeem", ending)},
                ("signet", "/v0/owner/where-paid"): {"where_paid": unsigned_compact(rng, "splint-where-paid", {
                    "v": 1, "owner": net.owners["ana"].id, "places": [{"kind": "payment_page", "url": f"https://pay.example.com/{MARKER}"}],
                    "issued_at": int(time.time()),
                })},
                ("signet", "/v0/requests/{}/pay_request"): {"entry": 0, "for": "amount_minor"},
            }
            self.templates_at = time.monotonic()

    def check(
        self, target: Target, route: str, raw: object, status: int | str, body: bytes, may_be_silent: bool, method: str,
        told_by_hostile_server: bool = False,
    ) -> None:
        findings = self.findings
        findings.status(target.name, route, status)
        if status == 500:
            findings.add("500", f"{target.name} {route}", raw, body)
        elif isinstance(status, int) and status >= 500 and body not in FIXED_5XX:
            findings.add("5xx with more than a fixed word", f"{target.name} {route}", raw, body)
        elif status == 503 and not told_by_hostile_server:
            # A 503 tells a sending host to keep retrying, so nothing in a request should cause one.
            findings.add("input-triggered 503", f"{target.name} {route}", raw, body)
        if LEAK.search(body):
            findings.add("internal detail in a response", f"{target.name} {route}", raw, body)
        if MARKER.encode() in body and (target.name, method, route) not in self.acceptable_echo_routes:
            findings.add("raw input repeated in a response", f"{target.name} {route}", raw, body)
        if isinstance(status, str) and status != "closed" and not may_be_silent:
            findings.add(f"no answer ({status})", f"{target.name} {route}", raw, body)

    def one_request(self, rng: random.Random) -> None:
        target = rng.choice(self.targets)
        method, route = rng.choice(target.routes)
        kind = "signet" if target.name.startswith("signet") else "host"
        template = self.templates.get((kind, route), {})
        path = route.format("e" * 64) if "{}" in route else route
        strategy = rng.randrange(10)
        may_be_silent = False
        if strategy <= 4 and method != "GET":
            body = hostile_body(rng, template, target.body_limit)
            raw = request(method, path, [("Content-Type", "application/json"), *target.auth_header(target, method, path, body)], body)
        elif strategy <= 4:
            raw = request(method, path, self.hostile_auth(rng, target, method, path))
        elif strategy == 5:
            path = hostile_path(rng, route)
            raw = request(method, path, target.auth_header(target, method, "/v0/inbox", b""))
        elif strategy == 6:
            word = rng.choice(["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "get", "G" * 9000, "GET\x00"])
            raw = request(word, path, target.auth_header(target, method, path, b""), json.dumps(template).encode())
            may_be_silent = word in ("HEAD", "CONNECT")
        elif strategy == 7:
            body = json.dumps(template).encode()
            raw = request(method, path, [("Content-Type", "application/json"), *self.hostile_auth(rng, target, method, path)], body)
        elif strategy == 8:
            body = json.dumps(template).encode() if template else b""
            raw, may_be_silent = hostile_framing(rng, method, path, target.auth_header(target, method, path, body), body)
        else:
            raw, may_be_silent = garbage(rng), True
        timeout = INCOMPLETE_TIMEOUT_SECS if may_be_silent else ANSWER_TIMEOUT_SECS
        status, answer = exchange(target.port, raw, timeout)
        self.check(target, route, raw[:4096], status, answer, may_be_silent, method)
        self.sent += 1

    def hostile_auth(self, rng: random.Random, target: Target, method: str, path: str) -> list:
        net = self.net
        fields = {
            "signer": net.ids["ana"], "host": net.domain["a"], "method": method, "path": path,
            "body_sha256": hashlib.sha256(b"").hexdigest(), "issued_at": int(time.time()),
        }
        token = e2e.TOKENS["ana"]
        value = rng.choice([
            f"Splint {unsigned_compact(rng, 'splint-access', fields)}",
            f"Splint {mutate_compact(rng, unsigned_compact(rng, 'splint-access', fields))}",
            "Splint ", "Splint", "splint x", f"Bearer {token}x", f"Bearer {token[:-1]}", f"bearer {token}", f"Bearer  {token}",
            "Bearer ", MARKER, b"Splint \xff\xfe", "Splint " + "A" * rng.choice([9_000, 70_000]),
            f"Splint {json.dumps(fields)}", f"Basic {base64.b64encode(MARKER.encode()).decode()}",
        ])
        extra = [("Authorization", MARKER)] if rng.random() < 0.1 else []
        return [("Authorization", value), *extra]

    def sample_memory(self) -> None:
        for process in self.net.processes:
            if process.process and process.process.poll() is None:
                listed = subprocess.run(["ps", "-o", "rss=", "-p", str(process.process.pid)], capture_output=True, text=True).stdout.strip()
                if listed:
                    self.rss_samples[process.log_path.stem].append(int(listed) // 1024)

    def still_healthy(self, where: str) -> bool:
        healthy = True
        for process in self.net.processes:
            if process.has_exited():
                self.findings.add("process exited", where, process.log_path.stem)
                healthy = False
        for target in self.targets:
            path = "/.well-known/splint/host" if target.name.startswith("host") else "/v0/identity"
            started = time.monotonic()
            status, _ = exchange(target.port, request("GET", path, self.signet_auth(target, "GET", path, b"")))
            if status != 200:
                self.findings.add(f"health check got {status}", where, target.name)
                healthy = False
            self.health_slowest = max(self.health_slowest, time.monotonic() - started)
        return healthy

    def fuzz_for(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        errors: list[BaseException] = []

        def work(worker: int) -> None:
            rng = random.Random(f"{self.seed}-{worker}")
            while time.monotonic() < deadline and not errors:
                try:
                    self.one_request(rng)
                except Exception as error:  # A bug here must not pass for a quiet run.
                    errors.append(error)

        threads = [threading.Thread(target=work, args=(worker,), daemon=True) for worker in range(WORKERS)]
        for thread in threads:
            thread.start()
        while time.monotonic() < deadline and not errors:
            time.sleep(5)
            self.refresh_templates()
            self.sample_memory()
            self.still_healthy("during the fuzz run")
            print(f"  {self.sent} requests, {deadline - time.monotonic():.0f}s left", flush=True)
        for thread in threads:
            thread.join(ANSWER_TIMEOUT_SECS + 10)
        if errors:
            raise errors[0]

    def replay_once_broke(self) -> None:
        for breaker in ONCE_BROKE:
            target = next(target for target in self.targets if target.name == breaker["target"])
            status, answer = exchange(target.port, breaker["raw"](self))
            broken = breaker["broken"](status, answer)
            print(f"  {'FAIL' if broken else 'ok  '} {breaker['name']}: {status}", flush=True)
            if broken:
                self.findings.add("what broke once broke again", target.name, breaker["name"], answer)


def replayed_proofs(net: e2e.Network, findings: Findings) -> None:
    """A real captured proof at every place it shouldn't fit. Each has a control that succeeds."""
    def expect(name: str, got: object, *wanted: object) -> None:
        if got not in wanted:
            findings.add("replay wasn't refused", name, got)
        print(f"  {'ok  ' if got in wanted else 'FAIL'} {name}: {got}", flush=True)

    host_a, host_b = net.host_port["a"], net.host_port["b"]
    inbox = net.access_proof("ana", "ana", "GET", "/v0/inbox")
    auth = [("Authorization", f"Splint {inbox}")]
    expect("control: a fresh access proof", exchange(host_a, request("GET", "/v0/inbox", auth))[0], 200)
    # Issue 97 tracks this: a captured proof still works until its 120 seconds are up.
    print(f"  note the same proof again, within its window: {exchange(host_a, request('GET', '/v0/inbox', auth))[0]}")
    ack = [("Authorization", f"Splint {inbox}"), ("Content-Type", "application/json")]
    expect("a GET proof at another route", exchange(host_a, request("POST", "/v0/inbox/ack", ack, b'{"seqs":[1]}'))[0], 401)
    expect("a proof at another host", exchange(host_b, request("GET", "/v0/inbox", auth))[0], 401)
    body = b'{"seqs":[1]}'
    signed = net.access_proof("ana", "ana", "POST", "/v0/inbox/ack", body)
    signed_auth = [("Authorization", f"Splint {signed}"), ("Content-Type", "application/json")]
    expect("control: a proof for this body", exchange(host_a, request("POST", "/v0/inbox/ack", signed_auth, body))[0], 200)
    expect("the same proof, another body", exchange(host_a, request("POST", "/v0/inbox/ack", signed_auth, b'{"seqs":[2]}'))[0], 401)
    for name, age in (("too old", -121), ("from the future", 121)):
        proof = dated_access_proof(net, "ana", "GET", "/v0/inbox", age)
        expect(f"a proof {name}", exchange(host_a, request("GET", "/v0/inbox", [("Authorization", f"Splint {proof}")]))[0], 401)
    envelope = net.envelope_signed_by("ana", "ana", "ben", f"{MARKER} replayed")
    identity = net.agent_identity("ana")
    expect("control: a real delivery", net.deliver(envelope, identity), 200)
    expect("the same delivery again takes no effect", net.deliver(envelope, identity), 200)
    row_count = net.postgres.sql("host_b", f"SELECT count(*) FROM inbox WHERE message_id = '{e2e.message_id_of(envelope)}'")
    expect("one row after the replay", row_count, "1")
    other = net.envelope_signed_by("ana", "ana", "ben", f"{MARKER} another")
    proof = net.host_proof(net.work / "host-a.key", other, net.domain["a"], net.domain["b"])
    fields = {"envelope": envelope, "sender_identity": identity, "from_host": net.domain["a"], "proof": proof}
    deliver = request("POST", "/v0/deliver", [("Content-Type", "application/json")], json.dumps(fields).encode())
    expect("another message's delivery proof", exchange(host_b, deliver)[0], 400)
    wrong_host = net.host_proof(net.work / "host-a.key", envelope, net.domain["a"], net.domain["a"])
    deliver = request("POST", "/v0/deliver", [("Content-Type", "application/json")], json.dumps({**fields, "proof": wrong_host}).encode())
    expect("a delivery proof for another host", exchange(host_b, deliver)[0], 400)
    bodies = net.bodies("ben")
    expect("the replayed message reaches Ben once", bodies.count(f"{MARKER} replayed"), 1)
    net.ack_all("ben")
    net.deliver(envelope, identity)
    expect("not shown again after acknowledging", f"{MARKER} replayed" in net.bodies("ben"), False)


def signed_hostile_envelopes(net: e2e.Network, findings: Findings) -> None:
    """Hostile fields under a real signature, which is what gets past the checks that come first."""
    now = int(time.time())
    good = {
        "v": 1, "sender": net.ids["ana"], "recipient": net.ids["ben"], "body": f"{MARKER} signed",
        "created_at": now, "expires_at": now + 3600, "nonce": e2e.encode(os.urandom(16)),
    }
    cases = {
        "a NUL recipient": {"recipient": "\u0000"},
        "a huge recipient": {"recipient": "x" * 100_000},
        "a lone surrogate recipient": {"recipient": "\ud800"},
        "an unknown recipient": {"recipient": "splint1" + "0" * 64},
        "a NUL in the body": {"body": f"{MARKER} a NUL\u0000in the body"},
        "an empty nonce": {"nonce": ""},
        "no nonce": {"nonce": None},
        "expiry before creation": {"created_at": now + 60, "expires_at": now + 30},
        "the body as a number": {"body": 1},
    }
    for name, change in cases.items():
        fields = {**good, "body": f"{MARKER} {name}", **change}
        # In the one encoding, so it's the odd field that's refused and not the spacing.
        compact = e2e.sign_jws(net.key_of("ana"), "splint-envelope", json.dumps(fields, separators=(",", ":")).encode())
        fields = {"envelope": compact, "recipient_host": net.domain["b"]}
        status_a, _ = exchange(net.host_port["a"], request("POST", "/v0/outbound", [("Content-Type", "application/json")], json.dumps(fields).encode()))
        status_b = net.deliver(compact, net.agent_identity("ana"))
        print(f"  {name}: sending host {status_a}, receiving host {status_b}", flush=True)
        if 503 in (status_a, status_b):
            findings.add("input-triggered 503", f"signed envelope with {name}", compact)
    print(f"  shown to Ben: {[body.removeprefix(MARKER + ' ') for body in net.bodies('ben')]}", flush=True)
    time.sleep(8)  # Long enough for a sending host to have tried more than once.
    print("  outbound rows by state after retries: " + net.postgres.sql(
        "host_a", "SELECT string_agg(status || ' ' || coalesce(last_failure, '-') || ' x' || attempts, ', ') FROM outbound",
    ), flush=True)
    net.bodies("ben")
    net.ack_all("ben")


def signed_hostile_where_paid(net: e2e.Network, findings: Findings) -> None:
    """Hostile places under the owner's real signature, as a thief holding their key could sign. Each is
    refused, nothing takes the place of the statement held, and the control goes through."""
    page = {"kind": "payment_page", "url": "https://pay.example.com/ana"}
    now = int(time.time())

    def signed(payload: bytes) -> str:
        return e2e.sign_jws(net.owners["ana"].key, "splint-where-paid", payload)

    def statement(places: object, **change: object) -> bytes:
        return e2e.compact_json({"v": 1, "owner": net.owners["ana"].id, "places": places, "issued_at": now} | change)

    status, _ = net.agent("ana", "POST", "/v0/owner/where-paid", {"where_paid": signed(statement([page], issued_at=now - 60))})
    if status != 200:
        findings.add("the control statement of where ana gets paid was refused", "/v0/owner/where-paid", status)
        return
    def url(text: str) -> list[dict]:
        return [{"kind": "payment_page", "url": text}]

    cases = {
        "no places": statement([]),
        "five places": statement([{"kind": "payment_page", "url": f"https://pay.example.com/{n}"} for n in range(5)]),
        "one place twice": statement([page, page]),
        "a login in the page": statement(url(f"https://{MARKER}:pass@pay.example.com/")),
        "an IP address": statement(url("https://127.0.0.1/pay")),
        "plain http": statement(url("http://pay.example.com/ana")),
        "a direction override": statement(url(f"https://pay.example.com/\u202e{MARKER}")),
        "a NUL": statement(url(f"https://pay.example.com/{MARKER}\u0000")),
        "a space": statement(url(f"https://pay.example.com/a {MARKER}")),
        "a page too long": statement(url("https://pay.example.com/" + "a" * 300)),
        "a bank": statement([{"kind": "bank", "iban": MARKER}]),
        "an extra field in a place": statement([{**page, "note": MARKER}]),
        "an extra field": statement([page], note=MARKER),
        "another version": statement([page], v=2),
        "someone else's owner": statement([page], owner=net.owners["mallory"].id),
        "dated ahead": statement([page], issued_at=now + 3600),
        "a date as text": statement([page], issued_at=str(now)),
        "a date too large": statement([page], issued_at=2**64),
        "places as a map": statement({"0": page}),
        "a capital in a Lightning address": statement([{"kind": "lightning", "to": "Ana@wallet.example"}]),
        "a chain with no namespace": statement([{"kind": "onchain", "chain": "8453", "address": "0xabc", "asset": "usdc"}]),
        "an asset that isn't a word": statement([{"kind": "onchain", "chain": "eip155:1", "address": "0xabc", "asset": MARKER + "!"}]),
        "spare spaces": json.dumps({"v": 1, "owner": net.owners["ana"].id, "places": [page], "issued_at": now}).encode(),
        "fields out of order": e2e.compact_json({"owner": net.owners["ana"].id, "v": 1, "places": [page], "issued_at": now}),
        # Each offer fits on its own, and four of them are past what a statement may hold.
        "too many bytes": statement([{"kind": "lightning", "to": f"lno1{'q' * 580}{'pzry'[n]}"} for n in range(4)]),
    }
    for name, payload in cases.items():
        status, answer = net.agent("ana", "POST", "/v0/owner/where-paid", {"where_paid": signed(payload)})
        print(f"  {name}: {status}", flush=True)
        if not (isinstance(status, int) and 400 <= status < 500):
            findings.add(f"a hostile statement of where ana gets paid wasn't refused ({name})", "/v0/owner/where-paid", payload, json.dumps(answer).encode())
        if MARKER in json.dumps(answer):
            findings.add("raw input repeated in a response", "/v0/owner/where-paid", payload, json.dumps(answer).encode())
    _, held = net.agent("ana", "GET", "/v0/where-paid")
    if [place.get("url") for place in held.get("places", [])] != [page["url"]]:
        findings.add("a hostile statement took the place of where ana gets paid", "/v0/where-paid", held)
    status, _ = net.agent("ana", "POST", "/v0/owner/where-paid", {"where_paid": signed(statement([page, {"kind": "lightning", "to": "ana@wallet.example"}]))})
    if status != 200:
        findings.add("a newer good statement was refused after the hostile ones", "/v0/owner/where-paid", status)


def dated_access_proof(net: e2e.Network, agent: str, method: str, path: str, age: int) -> str:
    proof = {
        "signer": net.ids[agent], "host": net.domain[net.home[agent]], "method": method, "path": path,
        "body_sha256": hashlib.sha256(b"").hexdigest(), "issued_at": int(time.time()) + age,
    }
    return e2e.sign_jws(net.key_of(agent), "splint-access", json.dumps(proof).encode())


def largest_bodies_at_once(campaign: Campaign) -> None:
    """Every request as large as a route allows, all at once, which is the memory check's worst case."""
    for target in campaign.targets:
        for method, route in target.routes:
            if method == "GET":
                continue
            path = route.format("e" * 64)
            raw = request(method, path, [("Content-Type", "application/json")], b" " * (target.body_limit - 1))
            threads = [threading.Thread(target=exchange, args=(target.port, raw), daemon=True) for _ in range(MAX_BODY_FLOOD_REQUESTS)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(ANSWER_TIMEOUT_SECS * 2)
            campaign.sample_memory()
    campaign.still_healthy("largest bodies")


def slow_senders(campaign: Campaign) -> dict[str, object]:
    """Connections that send one byte at a time, split across headers and bodies, against a live check."""
    results: dict[str, object] = {}
    for target in campaign.targets[:1] + campaign.targets[2:]:
        connections = []
        for number in range(SLOW_SENDERS):
            connection = socket.create_connection(("127.0.0.1", target.port), timeout=5)
            if number % 2:
                connection.sendall(b"POST /v0/inbox/ack HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n")
            else:
                connection.sendall(b"GET /v0/inbox HTTP/1.1\r\nHost: x\r\nX-Slow: ")
            connections.append(connection)
        slowest, failed = 0.0, 0
        deadline = time.monotonic() + SLOW_SECS
        while time.monotonic() < deadline:
            alive = []
            for connection in connections:
                try:
                    connection.sendall(b"a")
                    alive.append(connection)
                except OSError:
                    connection.close()
            connections = alive
            started = time.monotonic()
            path = "/.well-known/splint/host" if target.name.startswith("host") else "/v0/identity"
            status, _ = exchange(target.port, request("GET", path, campaign.signet_auth(target, "GET", path, b"")), 10)
            slowest = max(slowest, time.monotonic() - started)
            failed += status != 200
            time.sleep(1)
        campaign.sample_memory()
        results[target.name] = {
            "slow senders": SLOW_SENDERS, "still connected after seconds": SLOW_SECS, "still connected": len(connections),
            "live check slowest seconds": round(slowest, 3), "live checks failed": failed,
        }
        for connection in connections:
            connection.close()
        if failed:
            campaign.findings.add("slow senders stopped a live check", target.name, failed)
        if target.name.startswith("host") and results[target.name]["still connected"]:
            campaign.findings.add("a host kept a slow sender past its deadline", target.name, len(connections))
    return results


class HostileServer:
    """Answers with whatever bytes it's told to, valid HTTP or not. It plays a Signet's host."""

    def __init__(self) -> None:
        self.answer: bytes | None = b""
        self.requests: list[tuple[str, str]] = []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(128)
        self.domain = f"127.0.0.1:{self.listener.getsockname()[1]}"
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self) -> None:
        while True:
            connection, _ = self.listener.accept()
            threading.Thread(target=self.handle, args=(connection,), daemon=True).start()

    def handle(self, connection: socket.socket) -> None:
        with connection:
            try:
                connection.settimeout(5)
                received = b""
                while b"\r\n\r\n" not in received:
                    chunk = connection.recv(65536)
                    if not chunk:
                        return
                    received += chunk
                head, _, rest = received.partition(b"\r\n\r\n")
                match = re.search(rb"content-length: (\d+)", head, re.IGNORECASE)
                while match and len(rest) < int(match.group(1)):
                    rest += connection.recv(65536)
                request_line = head.split(b"\r\n")[0].split()
                if request_line[1] == b"/v0/agents":
                    connection.sendall(http_answer("200 OK", b"{}"))
                elif self.answer is None:
                    time.sleep(7)  # Longer than Signet waits.
                else:
                    connection.sendall(self.answer)
            except OSError:
                pass


def http_answer(status: str, body: bytes, extra: bytes = b"") -> bytes:
    return f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n".encode() + extra + b"Connection: close\r\n\r\n" + body


def hostile_answers(rng: random.Random, good: dict) -> list[tuple[str, bytes | None]]:
    """What a hostile server can say, around a valid answer of the right shape."""
    answers = []
    for _ in range(60):
        answers.append(("mutated json", http_answer("200 OK", hostile_body(rng, good, 1 << 16))))
    good_bytes = json.dumps(good).encode()
    for name, raw in {
        "server error": http_answer("500 Internal Server Error", f"{MARKER} stack".encode()),
        "redirect": http_answer("302 Found", b"", b"Location: http://169.254.169.254/\r\n"),
        "no content": http_answer("204 No Content", b""),
        "teapot": http_answer("418 I'm a teapot", f'{{"error":"{MARKER}"}}'.encode()),
        "not found": http_answer("404 Not Found", MARKER.encode()),
        "empty": b"",
        "garbage": rng.randbytes(1000),
        "bad status line": b"HTTP/1.1 9999 " + MARKER.encode() + b"\r\n\r\n",
        "bad version": b"HTTP/7.7 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        "length too short": b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n" + good_bytes,
        "length too long": b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n" + good_bytes,
        "length negative": b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n" + good_bytes,
        "two lengths": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
        "no framing": b"HTTP/1.1 200 OK\r\n\r\n" + good_bytes,
        "broken chunks": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc",
        "gzip claim": http_answer("200 OK", good_bytes, b"Content-Encoding: gzip\r\n"),
        "huge header": http_answer("200 OK", good_bytes, b"X-Big: " + b"y" * 500_000 + b"\r\n"),
        "bad header": http_answer("200 OK", good_bytes, b"X-Bad: \xff\x00\r\n"),
        "many continues": b"HTTP/1.1 100 Continue\r\n\r\n" * 1000 + http_answer("200 OK", good_bytes),
        "deep json": http_answer("200 OK", b"[" * 100_000),
        "never answers": None,
    }.items():
        answers.append((name, raw))
    return answers


def hostile_host_at_signet(campaign: Campaign, rng: random.Random) -> None:
    """A Signet whose own host is hostile, and what it tells its agent. The agent's API is the check."""
    net, findings = campaign.net, campaign.findings
    server = HostileServer()
    server.answer = http_answer("200 OK", b'{"messages":[]}')
    url, process = net.extra_signet("zed", server.domain)
    port = int(url.rsplit(":", 1)[1])
    auth = [("Authorization", f"Bearer {e2e.EXTRA_SIGNET_TOKEN}"), ("Content-Type", "application/json")]
    me = json.loads(exchange(port, request("GET", "/v0/identity", auth))[1])["agent_id"]
    # One address for each thing the host can say to a lookup, because a failed one is remembered.
    first_contacts = [f"h{number}~{server.domain}" for number in range(len(hostile_answers(rng, {})))]
    net.extra_rules("zed", url, [net.contact_entry("mallory"), *map(e2e.named_at, first_contacts)])
    real_body = "really signed"  # Not the marker, because this one should be repeated to the agent.
    envelope = e2e.signed_envelope(net.key_of("mallory"), net.ids["mallory"], me, real_body)
    identity = net.agent_identity("mallory")
    page = {"messages": [{"seq": 1, "envelope": envelope, "sender_identity": identity}]}
    target = Target("signet-zed", port, SIGNET_ROUTES, None)

    def inbox_answer(raw: bytes | None) -> tuple[int | str, list]:
        server.answer = raw
        status, answer = exchange(port, request("GET", "/v0/inbox", auth))
        shown = []
        if status == 200:
            try:
                shown = [message["untrusted"]["body"] for message in json.loads(answer)["messages"]]
            except (KeyError, TypeError, ValueError):
                findings.add("Signet's own answer didn't parse", "signet-zed /v0/inbox", raw, answer)
        return status, shown

    status, shown = inbox_answer(http_answer("200 OK", json.dumps(page).encode()))
    if shown != [real_body]:
        findings.add("control: a real message wasn't shown", "signet-zed /v0/inbox", status, repr(shown).encode())

    mutated_entries = []
    for _ in range(200):
        entry = dict(page["messages"][0])
        field = rng.choice(["envelope", "sender_identity", "seq"])
        if field == "seq":
            entry["seq"] = rng.choice([0, -1, 2**63, 2**64, 1.5, "1", None])
        else:
            entry[field] = rng.choice([mutate_compact(rng, entry[field]), rng.choice(hostile_values(rng))])
        mutated_entries.append(entry)
    forged = e2e.signed_envelope(net.key_of("ana"), net.ids["mallory"], me, f"{MARKER} forged")
    mutated_entries.append({"seq": 2, "envelope": forged, "sender_identity": identity})
    for entry in mutated_entries:
        unchanged = entry["envelope"] == envelope and entry["sender_identity"] == identity
        status, shown = inbox_answer(http_answer("200 OK", json.dumps({"messages": [entry]}).encode()))
        findings.status("signet-zed", "hostile page entry", status)
        if shown and not unchanged:
            findings.add("a changed message reached the agent", "signet-zed /v0/inbox", entry, repr(shown).encode())

    calls = [
        ("GET", "/v0/inbox", b""),
        ("POST", "/v0/inbox/ack", json.dumps({"message_ids": [e2e.message_id_of(envelope)]}).encode()),
        ("GET", f"/v0/sent/{'e' * 64}", b""),
        ("POST", "/v0/send", b""),
    ]
    good = {
        "/v0/inbox": page,
        "/v0/inbox/ack": page,
        f"/v0/sent/{'e' * 64}": {"status": "pending", "attempts": 1, "last_failure": None},
        "/v0/send": resolved_as(net, "mallory"),
    }
    for method, path, body in calls:
        for name, raw in hostile_answers(rng, good[path]):
            server.answer = raw
            sent = body
            if path == "/v0/send":
                sent = json.dumps({"to": first_contacts.pop(), "body": f"{MARKER} out"}).encode()
            status, answer = exchange(port, request(method, path, auth, sent))
            campaign.check(target, f"{path.split('/v0/')[1][:5]} told: {name}", (name, raw if raw is None else raw[:2048]), status, answer, False, method, True)
    if process.has_exited():
        findings.add("process exited", "signet-zed", "hostile host answers")
    process_logs = process.log_path.read_bytes()
    if b"panicked" in process_logs:
        findings.add("panic", "signet-zed", "hostile host answers", process_logs[-2000:])


def resolved_as(net: e2e.Network, agent: str) -> dict:
    """A lookup's answer for an agent, whichever address it's asked about."""
    return {
        "agent_id": net.ids[agent], "identity": net.agent_identity(agent), "owner_identity": net.owners[agent].identity,
        "binding": e2e.accepted(net.binding_for(net.owners[agent].key, net.owners[agent], net.ids[agent], net.address(agent)), net.key_of(agent)),
    }


def first_contact_at_a_hostile_host(campaign: Campaign, rng: random.Random) -> None:
    """Signet only calls its own host, so this is a peer lying to that host, and what the agent hears."""
    net = campaign.net
    server = HostileServer()
    good = resolved_as(net, "mallory")
    target = campaign.targets[2]
    auth = [("Authorization", f"Bearer {e2e.TOKENS['ana']}"), ("Content-Type", "application/json")]
    answers = hostile_answers(rng, good)
    addresses = [f"h{number}~{server.domain}" for number in range(len(answers))]
    net.also_names("ana", *addresses)
    # The fuzz run has used up this agent's lookups for the hour, and a refusal here would test nothing.
    net.postgres.sql("host_a", "DELETE FROM lookups")
    for address, (name, raw) in zip(addresses, answers):
        server.answer = raw
        body = json.dumps({"to": address, "body": f"{MARKER} out"}).encode()
        status, answer = exchange(target.port, request("POST", "/v0/send", auth, body))
        campaign.check(target, f"first contact told: {name}", (name, raw if raw is None else raw[:2048]), status, answer, False, "POST", True)


def hostile_peer_at_host(campaign: Campaign, rng: random.Random) -> None:
    """A listed peer that lies about its key on the way in, and answers deliveries with anything on the way out."""
    net, findings = campaign.net, campaign.findings
    peer = net.scripted_peer
    peer_key = net.work / "host-a.key"
    peer_public = host_public_key(net)
    good = {"domain": peer.domain, "key": peer_public}
    target = campaign.targets[1]
    envelope = net.envelope_signed_by("ana", "ana", "ben", f"{MARKER} via a peer")
    identity = net.agent_identity("ana")

    def deliver_from_peer() -> tuple[int | str, bytes]:
        proof = net.host_proof(peer_key, envelope, peer.domain, net.domain["b"])
        fields = {"envelope": envelope, "sender_identity": identity, "from_host": peer.domain, "proof": proof}
        return exchange(net.host_port["b"], request("POST", "/v0/deliver", [("Content-Type", "application/json")], json.dumps(fields).encode()))

    peer.respond = lambda _path, _sent: (200, {}, json.dumps(good).encode())
    status, answer = deliver_from_peer()
    if status != 200:
        findings.add("control: a real peer delivery was refused", "host-b /v0/deliver", status, answer)

    def forget_its_key() -> None:
        net.postgres.sql("host_b", f"DELETE FROM peer_keys WHERE domain = '{peer.domain}'")

    def asks_for_its_key() -> bool:
        forget_its_key()
        asked = len(peer.hits)
        deliver_from_peer()
        return len(peer.hits) > asked

    # A host it doesn't name is gone by what it last found for ten minutes, so only one it names has
    # each answer below read at all.
    net.write_peers("b", f"peer {peer.domain}\n")
    if not e2e.wait_until(asks_for_its_key, 15):
        findings.add("control: the named peer was never asked for its key", "host-b /v0/deliver", peer.domain)
    for _ in range(150):
        # A pinned key isn't asked for again, and it's the first answer that a lie could get through.
        forget_its_key()
        told = hostile_body(rng, good, 1 << 16)
        peer.respond = lambda _path, _sent, told=told: (rng.choice([200, 200, 200, 404, 500, 302]), {}, told)
        asked = len(peer.hits)
        status, answer = deliver_from_peer()
        if len(peer.hits) == asked:
            findings.add("control: a hostile key answer was never read", "host-b /v0/deliver", told[:2048], answer)
        campaign.check(target, "/v0/deliver, peer key told hostile", told[:2048], status, answer, False, "POST", True)
        findings.status("host-b", "/v0/deliver accepted with a hostile key answer", status == 200)
        if status == 200:
            try:
                parsed = json.loads(told)
            except ValueError:
                parsed = {}
            if parsed.get("key") != peer_public or parsed.get("domain") != peer.domain:
                findings.add("a delivery passed on a wrong peer key", "host-b /v0/deliver", told, answer)

    statuses = [200, 201, 204, 301, 400, 401, 403, 404, 408, 409, 413, 422, 425, 429, 500, 502, 503, 599]
    headers = [{}, {"Splint-Refusal": "malformed"}, {"Splint-Refusal": MARKER}, {"Splint-Refusal": "\xff"}, {"X-Big": "y" * 60_000}]
    # Host B holds this peer's key from a lying answer or not at all, and only the delivery route matters below.
    peer.respond = lambda _path, _sent: (rng.choice(statuses), rng.choice(headers), rng.randbytes(rng.choice([0, 1000])))
    ids = []
    for number in range(40):
        compact = net.envelope_signed_by("ana", "ana", "ben", f"{MARKER} to a peer {number}")
        fields = {"envelope": compact, "recipient_host": peer.domain}
        status, _ = exchange(net.host_port["a"], request("POST", "/v0/outbound", [("Content-Type", "application/json")], json.dumps(fields).encode()))
        if status == 200:
            ids.append(e2e.message_id_of(compact))
    time.sleep(10)
    if not ids:
        findings.add("control: nothing was accepted to go to the peer", "host-a /v0/outbound", 0)
    listed = ",".join(f"'{message_id}'" for message_id in ids)
    rows = net.postgres.sql("host_a", f"SELECT status, coalesce(last_failure, '') FROM outbound WHERE message_id IN ({listed})")
    for line in rows.splitlines():
        state, failure = line.split("|")
        findings.status("host-a", "outbound to a hostile peer", state)
        if state not in DELIVERY_STATES or failure not in DELIVERY_FAILURES:
            findings.add("a peer's words reached a delivery status", "host-a outbound", line)
    peer.accept_everything()


def host_public_key(net: e2e.Network) -> str:
    return json.loads(exchange(net.host_port["a"], request("GET", "/.well-known/splint/host", []))[1])["key"]


def scan_logs(net: e2e.Network, findings: Findings, out: Path) -> dict[str, dict[str, int]]:
    """Everything the processes wrote, for panics, secrets and message content."""
    logs = net.process_logs()
    every_log = list(net.work.glob("*.log"))
    everything = b"".join(path.read_bytes() for path in every_log)
    if b"panicked" in everything:
        findings.add("panic in a log", "logs", [line for line in everything.splitlines() if b"panicked" in line][:5])
    secrets = {f"{name}'s token": token.encode() for name, token in e2e.TOKENS.items()}
    for key in [*net.work.glob("*/*.key"), *net.work.glob("*.key")]:
        raw = key.read_bytes()
        secrets[f"{key.name} as hex"] = raw.hex().encode()
        secrets[f"{key.name} as base64"] = base64.b64encode(raw)
        secrets[f"{key.name} as url base64"] = e2e.encode(raw).encode()
    for name, secret in secrets.items():
        if secret in everything:
            findings.add("secret in a log", "logs", name)
    if MARKER.encode() in everything:
        lines = [line[:300] for line in everything.splitlines() if MARKER.encode() in line][:5]
        findings.add("raw input in a log", "logs", lines)
    # A hostile envelope's body can be any JSON, and only text can turn up in a log.
    e2e.message_bodies.intersection_update({body for body in e2e.message_bodies if isinstance(body, str)})
    e2e.message_bodies.add(f"{MARKER} a message")
    found = e2e.content_in(logs)
    if found:
        findings.add("message content in a log", "logs", found)
    levels: dict[str, dict[str, int]] = {}
    for path in every_log:
        text = path.read_bytes()
        levels[path.stem] = {level: text.count(f" {level} ".encode()) for level in ("ERROR", "WARN")}
        levels[path.stem]["bytes"] = len(text)
    samples = [line.decode(errors="replace")[:220] for line in everything.splitlines() if b" ERROR " in line][:10]
    (out / "error-log-samples.txt").write_text("\n".join(samples) + "\n")
    return levels


def report(campaign: Campaign, findings: Findings, seed: int, slow: dict, levels: dict, seconds: float, out: Path) -> int:
    print(f"\nseed {seed}: {campaign.sent} random requests in {seconds:.0f}s with {WORKERS} workers, debug builds")
    print("\nanswers by target and route")
    rows = collections.defaultdict(collections.Counter)
    for (target, route, status), count in findings.statuses.items():
        rows[f"{target} {route}"][str(status)] += count
    for row in sorted(rows):
        print(f"  {row}: " + ", ".join(f"{status}={count}" for status, count in sorted(rows[row].items())))
    print("\nmemory in MiB (first sample, largest, last)")
    for name, samples in sorted(campaign.rss_samples.items()):
        print(f"  {name}: {samples[0]}, {max(samples)}, {samples[-1]}")
        if max(samples) > RSS_LIMIT_MIB or samples[-1] - samples[0] > RSS_GROWTH_LIMIT_MIB:
            findings.add("memory grew past its bound", name, samples[-10:])
    print(f"\nslowest live check while fuzzing: {campaign.health_slowest:.3f}s")
    print("\nslow senders")
    for name, result in slow.items():
        print(f"  {name}: {result}")
    print("\nlog lines by process")
    for name, counts in sorted(levels.items()):
        print(f"  {name}: {counts}")
    print("\nfindings")
    fresh = 0
    for (kind, route), count in sorted(findings.counts.items()):
        issue = OPEN_FINDINGS.get(kind)
        fresh += issue is None
        print(f"  {count:>7}  {kind} at {route}{f' (open: #{issue})' if issue else ' (NEW)'}")
    print(f"\ninputs saved under {out}")
    print(f"{'nothing new broke' if not fresh else f'{fresh} new findings'}")
    return 1 if fresh else 0


def hostile_input_at_the_owners_tool(campaign: "Campaign", rng: random.Random) -> None:
    """What a Signet or an agent can hand an owner's device to sign. It's refused, or it's signed as it reads."""
    net, findings = campaign.net, campaign.findings
    owner = net.owners["mallory"]
    agent = net.ids["mallory"]
    draft = e2e.rules_draft([net.contact_entry("ben")])
    # A resource's own record, which the resource's commands take and nobody else's.
    record = net.work / "hostile-resource-record.json"
    uses = {
        "rules": (["--agent", agent], draft),
        "approve": (["--decision", "approve"], {"owner": owner.id, "agent": agent, "operation": "confirm", "request": "0" * 64, "version": 1, "prev": "0" * 64, "latest_expiry": int(time.time()) + 3600, "terms": {}}),
        "auto": (["--agent", agent, "--schemas", str(e2e.PACKAGES.parent / "spec" / "schemas")], {"drafts": [], "strangers": []}),
        "check-grant": (["--owner", owner.identity, "--resource", "docs", "--record", str(record)], {"grant": "", "identity": "", "proof": "", "operation": "read", "method": "POST", "path": "/docs/read", "body": ""}),
        "person-text": (["--agent", agent, "--to", net.ids["ben"]], MARKER),
        "redeem": (["--agent", agent, "--types", e2e.example_id("meeting/1")], MARKER),
        "record-revocation": (["--owner", owner.identity, "--record", str(record)], MARKER),
        "where-paid": ([], json.dumps([{"kind": "payment_page", "url": f"https://pay.example.com/{MARKER}"}])),
    }
    panics = 0
    for _ in range(300):
        command = rng.choice(list(uses))
        extra, template = uses[command]
        if isinstance(template, str):
            told = template + rng.choice(["", MARKER, "\x00", "\u202e", "{" * 5000])
        else:
            told = hostile_body(rng, template, 1 << 16).decode("utf-8", "replace")
        at_a_resource = command in ("check-grant", "record-revocation")
        device = [] if at_a_resource else ["--dir", str(owner.dir)]
        done = e2e.owner_key_tool(command, *device, *extra, stdin=told)
        # Asked wrongly, it prints its usage, which is fixed text and names the keys it holds.
        if "owner-key holds" in done.stderr or "owner-key: holds" in done.stderr:
            findings.add("the harness asked the owner's tool wrongly", f"owner-key {command}", told, done.stderr.encode())
            continue
        findings.status("owner-key", command, done.returncode)
        if done.returncode == 101 or b"panicked" in done.stderr.encode():
            panics += 1
            findings.add("the owner's tool panicked", f"owner-key {command}", told, done.stderr.encode())
        if done.returncode != 0 and (MARKER in done.stderr or LEAK.search(done.stderr.encode())):
            findings.add("the owner's tool repeated what it was told in an error", f"owner-key {command}", told, done.stderr.encode())
    print(f"  300 hostile inputs at the owner's tool, {panics} panics", flush=True)


class HostilePostgres(e2e.Postgres):
    def __init__(self) -> None:
        self.name = f"splint-test-hostile-{os.getpid()}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=int.from_bytes(os.urandom(4), "big"))
    parser.add_argument("--minutes", type=float, default=float(os.environ.get("SPLINT_FUZZ_MINUTES", "10")))
    args = parser.parse_args()
    seed = args.seed
    print(f"seed {seed}: replay with python3 sim/hostile_input.py --seed {seed}", flush=True)
    out = RUNS / f"hostile-input-{seed}"
    findings = Findings(out)
    rng = random.Random(seed)
    e2e.Postgres = HostilePostgres
    e2e.build()
    with e2e.running_network() as net:
        campaign = Campaign(net, findings, seed)
        campaign.refresh_templates()
        campaign.sample_memory()
        print("\nwhat broke once", flush=True)
        campaign.replay_once_broke()
        print("\nreplayed proofs", flush=True)
        replayed_proofs(net, findings)
        print("\nsigned envelopes with hostile fields", flush=True)
        signed_hostile_envelopes(net, findings)
        print("\nsigned statements of where an owner gets paid, with hostile places", flush=True)
        signed_hostile_where_paid(net, findings)
        print("\nhostile requests", flush=True)
        started = time.monotonic()
        campaign.fuzz_for(args.minutes * 60)
        seconds = time.monotonic() - started
        print("\nlargest bodies at once", flush=True)
        largest_bodies_at_once(campaign)
        print("\nslow senders", flush=True)
        slow = slow_senders(campaign)
        print("\na hostile host answering Signet", flush=True)
        hostile_host_at_signet(campaign, rng)
        first_contact_at_a_hostile_host(campaign, rng)
        print("\na hostile peer answering a host", flush=True)
        hostile_peer_at_host(campaign, rng)
        print("\nhostile input at the owner's tool", flush=True)
        hostile_input_at_the_owners_tool(campaign, rng)
        campaign.still_healthy("at the end")
        campaign.sample_memory()
        levels = scan_logs(net, findings, out)
        return report(campaign, findings, seed, slow, levels, seconds, out)


if __name__ == "__main__":
    sys.exit(main())

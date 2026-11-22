#!/usr/bin/env python3
"""Measures what two live hosts carry, driving them over the internet with TLS verified.

    SPLINT_LIVE_HOSTS=... uv run --quiet --no-project --python 3.13 \
        --with aiohttp --with cryptography --with certifi python sim/live_load.py --out results.jsonl

Every message is really signed and sent both ways between the hosts, so each host takes sends and
receives at the same rate, as one with a real mix of owners would. Requests start on schedule whether
or not the server keeps up, and a latency counts from when the request was due, so a host that falls
behind can't hide it. Test agents go straight into Postgres, past the limit on new agents an hour, and
they and their mail are removed afterwards.
"""

import argparse
import asyncio
import hashlib
import json
import math
import multiprocessing
import os
import random
import shutil
import ssl
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp
import certifi
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import e2e
import live_network

PAIRS = 200
WORKERS = 6
CONNECTIONS_PER_WORKER = 48
BODY_BYTES = 1000
LIFETIME_SECONDS = 3600
REQUEST_TIMEOUT_SECONDS = 20
INBOX, ACK, OUTBOUND = "/v0/inbox", "/v0/inbox/ack", "/v0/outbound"
SECONDS_PER_DAY = 86400
PEAK_FACTOR = 10
CHECKS_PER_OWNER_PER_SECOND = 1 / 60
SETTLE_SECONDS = 15
# A step passes if these hold. The worst ordinary round trip from here is about 180 ms.
P95_LIMIT_SECONDS = 1.5
ERROR_LIMIT = 0.002
BACKLOG_LIMIT_SECONDS = 5
DRIVER_LAG_LIMIT_MS = 250
DELIVERY_RATES = (2.5, 5, 10, 20, 30, 45)
CHECK_RATES = (25, 50, 100, 200, 400, 800)
NEW_CONNECTION_RATES = (5, 10, 20, 40)
STEP_SECONDS = 45
SHORT_STEP_SECONDS = 30
MODEL_STEP_SECONDS = 90
PROBE = """
for p in $(pgrep -x 'splint-host|caddy|postgres'); do cat /proc/$p/stat 2>/dev/null; done | awk '{gsub(/[()]/, "", $2); c[$2]+=($14+$15)/100; r[$2]+=$24*4} END {for (k in c) print k, c[k], r[k]}'
echo stat $(head -1 /proc/stat)
free -m | awk '/^Mem:/ {print "mem", $3, $7} /^Swap:/ {print "swap", $3}'
"""
COUNTS = "SELECT count(*) FILTER (WHERE status = 'delivered'), count(*) FILTER (WHERE status = 'pending') FROM outbound"
CLEAR = """
    DELETE FROM outbound WHERE sender IN (SELECT id FROM agents WHERE handle LIKE 'load-%');
    DELETE FROM inbox WHERE recipient IN (SELECT id FROM agents WHERE handle LIKE 'load-%');
    DELETE FROM rules WHERE agent IN (SELECT id FROM agents WHERE handle LIKE 'load-%');
    DELETE FROM texts WHERE agent IN (SELECT id FROM agents WHERE handle LIKE 'load-%');
    DELETE FROM met WHERE agent IN (SELECT id FROM agents WHERE handle LIKE 'load-%');
    DELETE FROM agents WHERE handle LIKE 'load-%';
"""


def b64(raw: bytes) -> str:
    return e2e.encode(raw)


def compact(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


@dataclass
class Agent:
    id: str
    key_path: str
    home: str
    other: str = ""
    key: object = None

    def signed(self, typ: str, payload: bytes) -> str:
        if self.key is None:
            self.key = serialization.load_der_private_key(Path(self.key_path).read_bytes(), None)
        signing_input = f"{b64(compact({'alg': 'ES256', 'typ': typ}))}.{b64(payload)}"
        r, s = decode_dss_signature(self.key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
        return f"{signing_input}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def access_proof(self, method: str, path: str, body: bytes = b"") -> str:
        return self.signed("splint-access", compact({
            "signer": self.id, "host": self.home, "method": method, "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(), "issued_at": int(time.time()),
        }))

    def envelope(self, recipient: str) -> str:
        now = int(time.time())
        return self.signed("splint-envelope", compact({
            "v": 1, "sender": self.id, "recipient": recipient, "body": b64(os.urandom(BODY_BYTES * 3 // 4)),
            "created_at": now, "expires_at": now + LIFETIME_SECONDS, "nonce": b64(os.urandom(16)),
        }))


def new_key_file(path: Path) -> bytes:
    """Made here because this library refuses some of the keys the system's openssl writes. Returns
    the public point."""
    key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def new_agent_key(path: Path) -> tuple[str, str]:
    """An agent key with a backup beside it, as e2e.new_identity makes, and the identity and ID."""
    point = new_key_file(path)
    backup = new_key_file(e2e.backup_of(path))
    seal = new_key_file(e2e.seal_of(path))
    recovery = {"rule": "backup_key", "commitment": hashlib.sha256(backup).hexdigest()}
    event = compact({"v": 4, "alg": "ES256", "key": b64(point), "seal": b64(seal), "recovery": recovery})
    return b64(event), f"splint1{hashlib.sha256(event).hexdigest()}"


def make_pair(number: int, run: str, work: Path, domains: dict[str, str]) -> dict:
    """One owner and agent on each host, each listing the other with words allowed, signed with the
    real owner tool."""
    made = {}
    for side in "ab":
        directory = work / f"{side}{number}"
        directory.mkdir()
        owner = e2e.new_owner(directory / "owner")
        key = directory / "agent.key"
        identity, agent_id = new_agent_key(key)
        handle = f"load-{run}-{side}{number}"
        address = f"{handle}~{domains[side]}"
        owner_half = owner.bind(identity, address)
        binding = e2e.accepted(owner_half, key)
        made[side] = {
            "owner": owner, "identity": identity, "id": agent_id, "handle": handle, "address": address,
            "binding": binding, "binding_seq": e2e.payload_of(owner_half)["seq"], "key": str(key),
        }
    for side, other in (("a", "b"), ("b", "a")):
        them = made[other]
        contact = {"agent": them["id"], "address": them["address"], "label": them["handle"], "status": "allowed", "types": e2e.EXAMPLE_TYPES, "text": True, "pinned_by": "owner"}
        made[side]["rules"] = made[side]["owner"].sign("rules", "--agent", made[side]["id"], stdin=json.dumps(e2e.rules_draft([contact])))
    return made


def seed(servers: dict[str, live_network.Server], work: Path) -> dict[str, list[Agent]]:
    run = os.urandom(3).hex()
    domains = {name: server.domain for name, server in servers.items()}
    with ThreadPoolExecutor(8) as pool:
        pairs = list(pool.map(lambda number: make_pair(number, run, work, domains), range(PAIRS)))
    agents: dict[str, list[Agent]] = {"a": [], "b": []}
    for side, other in (("a", "b"), ("b", "a")):
        lines = [
            "\t".join((pair[side]["id"], pair[side]["handle"], pair[side]["identity"], pair[side]["owner"].id, pair[side]["owner"].identity, pair[side]["binding"], str(pair[side]["binding_seq"])))
            for pair in pairs
        ]
        rules = [
            "\t".join((pair[side]["id"], str(e2e.payload_of(pair[side]["rules"])["seq"]), pair[side]["rules"]))
            for pair in pairs
        ]
        servers[side].sql(
            "COPY agents (id, handle, identity, owner_id, owner_identity, binding, binding_seq) FROM STDIN;\n" + "\n".join(lines) + "\n\\.\n"
            + "COPY rules (agent, seq, compact) FROM STDIN;\n" + "\n".join(rules) + "\n\\.\n" + "ANALYZE agents; ANALYZE rules;"
        )
        agents[side] = [Agent(pair[side]["id"], pair[side]["key"], domains[side], pair[other]["id"]) for pair in pairs]
    return agents


@dataclass(frozen=True)
class Load:
    agents: dict
    start_at: float
    seconds: float
    # Requests a second, in total, for each (kind, side).
    rates: dict = field(default_factory=dict)
    new_connections: bool = False


def tls_context() -> ssl.SSLContext:
    """Verified against public roots, the same as the hosts verify each other."""
    return ssl.create_default_context(cafile=certifi.where())


class Worker:
    def __init__(self, load: Load, index: int) -> None:
        self.load, self.index = load, index
        self.latencies: dict[str, list[float]] = {}
        self.outcomes: Counter[str] = Counter()
        self.lags: list[float] = []

    def agent(self, side: str) -> Agent:
        agents = self.load.agents[side]
        return agents[random.randrange(len(agents) // WORKERS) * WORKERS + self.index]

    async def call(self, kind: str, session, method: str, url: str, due: float, **options) -> tuple[int | None, bytes]:
        try:
            async with session.request(method, url, **options) as response:
                body = await response.read()
                self.outcomes[f"{kind}:{response.status}"] += 1
                self.latencies.setdefault(kind, []).append(time.time() - due)
                return response.status, body
        except (aiohttp.ClientError, TimeoutError, OSError) as error:
            self.outcomes[f"{kind}:{type(error).__name__}"] += 1
            return None, b""

    async def check_inbox(self, session, side: str, due: float) -> None:
        agent = self.agent(side)
        proof = agent.access_proof("GET", INBOX)
        status, body = await self.call("check", session, "GET", f"https://{agent.home}{INBOX}", due, headers={"Authorization": f"Splint {proof}"})
        if status != 200 or body == b'{"messages":[]}':
            return
        seqs = [message["seq"] for message in json.loads(body)["messages"]]
        ack = compact({"seqs": seqs})
        proof = agent.access_proof("POST", ACK, ack)
        await self.call("ack", session, "POST", f"https://{agent.home}{ACK}", time.time(), data=ack, headers={"Authorization": f"Splint {proof}", "Content-Type": "application/json"})

    async def send(self, session, side: str, due: float) -> None:
        agent = self.agent(side)
        other = "b" if side == "a" else "a"
        request = {"envelope": agent.envelope(agent.other), "recipient_host": self.load.agents[other][0].home}
        await self.call("send", session, "POST", f"https://{agent.home}{OUTBOUND}", due, json=request)

    async def arrivals(self, kind: str, side: str, rate: float, session) -> None:
        operation = getattr(self, kind)
        end = self.load.start_at + self.load.seconds
        due = self.load.start_at + random.expovariate(rate)
        tasks = set()
        while due < end:
            wait = due - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
            self.lags.append(time.time() - due)
            task = asyncio.create_task(operation(session, side, due))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            due += random.expovariate(rate)
        if tasks:
            await asyncio.wait(tasks, timeout=REQUEST_TIMEOUT_SECONDS + 2)

    async def run(self) -> dict:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        connector = aiohttp.TCPConnector(limit=CONNECTIONS_PER_WORKER, ssl=tls_context(), force_close=self.load.new_connections)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            await asyncio.gather(*(
                self.arrivals(kind, side, rate / WORKERS, session)
                for (kind, side), rate in self.load.rates.items() if rate > 0
            ))
        return {"latencies": self.latencies, "outcomes": self.outcomes, "lags": self.lags}


def run_worker(arguments: tuple) -> dict:
    load, index = arguments
    return asyncio.run(Worker(load, index).run())


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))]


def probe(server: live_network.Server) -> dict:
    found = {"at": time.time(), "cpu": {}, "rss_mb": {}}
    for line in server.run(PROBE).splitlines():
        parts = line.split()
        if parts[0] == "stat":
            found["jiffies"] = [int(value) for value in parts[2:]]
        elif parts[0] == "mem":
            found["used_mb"], found["available_mb"] = int(parts[1]), int(parts[2])
        elif parts[0] == "swap":
            found["swap_mb"] = int(parts[1])
        else:
            found["cpu"][parts[0]] = float(parts[1])
            found["rss_mb"][parts[0]] = int(parts[2]) // 1024
    return found


def difference(before: dict, after: dict) -> dict:
    elapsed = after["at"] - before["at"]
    spent = [end - start for start, end in zip(before["jiffies"], after["jiffies"], strict=True)]
    idle, iowait = spent[3], spent[4]
    return {
        "cores": {name: round((after["cpu"].get(name, 0) - before["cpu"].get(name, 0)) / elapsed, 3) for name in after["cpu"]},
        "busy": round(1 - (idle + iowait) / max(sum(spent), 1), 3), "iowait": round(iowait / max(sum(spent), 1), 3),
        "steal": round(spent[7] / max(sum(spent), 1), 3) if len(spent) > 7 else 0,
        "rss_mb": after["rss_mb"], "used_mb": after["used_mb"], "available_mb": after["available_mb"], "swap_mb": after["swap_mb"],
    }


class Run:
    def __init__(self, pool, servers: dict[str, live_network.Server], agents: dict, out: Path) -> None:
        self.pool, self.servers, self.agents, self.out = pool, servers, agents, out

    def record(self, row: dict) -> dict:
        with self.out.open("a") as file:
            file.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)
        return row

    def counts(self, name: str) -> tuple[int, int]:
        delivered, pending = self.servers[name].sql(COUNTS).split("|")
        return int(delivered), int(pending)

    def step(self, name: str, rates: dict, seconds: float, new_connections: bool = False) -> dict:
        load = Load(self.agents, time.time() + 2, seconds, rates, new_connections)
        counted_before = {side: self.counts(side) for side in self.servers}
        started_wall = time.time()
        waiting = self.pool.map_async(run_worker, [(load, index) for index in range(WORKERS)])
        time.sleep(max(load.start_at - time.time(), 0))
        before = {side: probe(server) for side, server in self.servers.items()}
        time.sleep(max(load.start_at + seconds - time.time(), 0))
        after = {side: probe(server) for side, server in self.servers.items()}
        counted_after = {side: self.counts(side) for side in self.servers}
        results = waiting.get()
        latencies: dict[str, list[float]] = {}
        outcomes: Counter[str] = Counter()
        lags: list[float] = []
        for result in results:
            for kind, values in result["latencies"].items():
                latencies.setdefault(kind, []).extend(values)
            outcomes.update(result["outcomes"])
            lags.extend(result["lags"])
        total = sum(outcomes.values())
        errors = {kind: count for kind, count in outcomes.items() if not kind.endswith(":200")}
        delivered_rate = {side: round((counted_after[side][0] - counted_before[side][0]) / seconds, 1) for side in self.servers}
        pending = {side: counted_after[side][1] for side in self.servers}
        sent_rate = sum(rate for (kind, _), rate in rates.items() if kind == "send")
        delay = {}
        for side, server in self.servers.items():
            delay[side] = server.sql(
                "SELECT round(percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM last_attempt_at - created_at))::numeric, 3) "
                f"FROM outbound WHERE status = 'delivered' AND created_at > to_timestamp({started_wall})"
            ) or None
        row = {
            "step": name, "seconds": seconds, "rates": {f"{kind}/{side}": rate for (kind, side), rate in rates.items()},
            "achieved_per_s": {kind: round(len(values) / seconds, 1) for kind, values in latencies.items()},
            "p50_s": {kind: round(percentile(values, 0.5), 3) for kind, values in latencies.items()},
            "p95_s": {kind: round(percentile(values, 0.95), 3) for kind, values in latencies.items()},
            "errors": errors, "error_share": round(sum(errors.values()) / max(total, 1), 4),
            "delivered_per_s": delivered_rate, "pending_at_end": pending, "delivery_p95_s": delay,
            "driver_lag_p95_ms": round(percentile(lags, 0.95) * 1000, 1),
            "servers": {side: difference(before[side], after[side]) for side in self.servers},
        }
        worst_p95 = max(row["p95_s"].values(), default=0)
        backlog_limit = max(sent_rate * BACKLOG_LIMIT_SECONDS, 16)
        row["passed"] = worst_p95 <= P95_LIMIT_SECONDS and row["error_share"] <= ERROR_LIMIT and max(pending.values()) <= backlog_limit
        return self.record(row)

    def settle(self) -> None:
        deadline = time.time() + 120
        while time.time() < deadline and any(self.counts(side)[1] > 0 for side in self.servers):
            time.sleep(3)
        time.sleep(SETTLE_SECONDS)


def per_host(rate: float, kind: str, sides: str = "ab") -> dict:
    return {(kind, side): rate for side in sides}


def step_once_more_if_the_driver_lagged(run: Run, label: str, rates: dict, seconds: float, new_connections: bool = False) -> dict:
    """A step the machine driving it fell behind on says nothing about the server, so it gets one rerun."""
    row = run.step(label, rates, seconds, new_connections)
    run.settle()
    if not row["passed"] and row["driver_lag_p95_ms"] > DRIVER_LAG_LIMIT_MS:
        row = run.step(f"{label}-again", rates, seconds, new_connections)
        run.settle()
    return row


def ramp(run: Run, label: str, rates: tuple, make_rates, seconds: float, new_connections: bool = False) -> float:
    """Goes up until a step fails, and returns the last rate that passed."""
    best = 0.0
    for rate in rates:
        row = step_once_more_if_the_driver_lagged(run, f"{label}-{rate}", make_rates(rate), seconds, new_connections)
        if not row["passed"]:
            break
        best = rate
    return best


def owners_at(messages_per_second: float, checks_per_second: float, per_day: int, peak: int) -> float:
    per_owner = per_day / SECONDS_PER_DAY * peak
    return min(messages_per_second / per_owner, checks_per_second / CHECKS_PER_OWNER_PER_SECOND)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    e2e.build()
    servers = live_network.servers_from_setting()
    work = Path(tempfile.mkdtemp())
    started = time.time()
    run_sizes = {side: server.sql("SELECT pg_database_size('splint')") for side, server in servers.items()}
    try:
        print("seeding", flush=True)
        agents = seed(servers, work)
        print(f"seeded {PAIRS} pairs in {time.time() - started:.0f}s", flush=True)
        with multiprocessing.get_context("spawn").Pool(WORKERS) as pool:
            run = Run(pool, servers, agents, arguments.out)
            run.step("warm-up", {**per_host(2, "send"), **per_host(2, "check_inbox")}, SHORT_STEP_SECONDS)
            run.settle()
            delivery = ramp(run, "delivery", DELIVERY_RATES, lambda rate: {**per_host(rate, "send"), **per_host(max(rate / 2, 2), "check_inbox")}, STEP_SECONDS)
            checks = ramp(run, "checks", CHECK_RATES, lambda rate: {("check_inbox", "a"): rate}, SHORT_STEP_SECONDS)
            new_connections = ramp(run, "new-tls-connection-checks", NEW_CONNECTION_RATES, lambda rate: {("check_inbox", "a"): rate}, SHORT_STEP_SECONDS, new_connections=True)
            models = {}
            for per_day in (20, 200):
                owners = int(owners_at(delivery, checks, per_day, PEAK_FACTOR) * 0.9)
                message_rate = owners * per_day / SECONDS_PER_DAY * PEAK_FACTOR
                check_rate = owners * CHECKS_PER_OWNER_PER_SECOND
                row = step_once_more_if_the_driver_lagged(run, f"model-{per_day}-a-day-{owners}-owners-at-peak", {**per_host(message_rate, "send"), **per_host(check_rate, "check_inbox")}, MODEL_STEP_SECONDS)
                models[per_day] = {"owners": owners, "passed": row["passed"]}
            sizes = {
                side: {"before": run_sizes[side], "after": server.sql("SELECT pg_database_size('splint')"),
                       "messages": server.sql("SELECT count(*) FROM outbound")}
                for side, server in servers.items()
            }
            run.record({"summary": True, "delivery_clean_per_host": delivery, "checks_clean_per_second": checks, "new_tls_checks_clean_per_second": new_connections, "models": models, "sizes": sizes, "minutes": round((time.time() - started) / 60, 1)})
    finally:
        for server in servers.values():
            server.sql(CLEAR)
            server.sql("VACUUM ANALYZE")
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

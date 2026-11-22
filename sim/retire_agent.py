#!/usr/bin/env python3
"""Retiring an agent from its person's own computer, and freeing its folder, through real Signets that
`splint join` started at a real host, against Postgres (issue 757).

Lia's agent joins on its own and makes Max's agent a contact. Lia's person sets up their controls on
their own computer, with a sign-in locked by a passphrase, so their key isn't in the agent's folder and
`splint retire` there is refused. Then: another person's computer can't retire Lia's agent; Lia's own
agent, piping a yes to the person's command, gets nothing signed; Lia's person runs `splint for
ADDRESS retire` and one approval, their passphrase, retires it. Lia's side then says it's retired, in
status and check, as its Signet found its owner's signature at its host, and a Signet started again
stays up saying so rather than failing. Max's agent drops it as a contact, from the same signed stop.
`splint retire` in Lia's folder then frees it with nothing more signed. Neo's agent, whose host is gone
for good, frees its folder with `splint reset`, typed at a terminal, which is refused while its host
still has it and with no terminal.

Lia's host stands behind a proxy that passes everything through until told otherwise, as whoever runs a
host can do. Faulted, it refuses her Signet and hands it a retirement that isn't hers to believe: another
agent's real one, and one her stand-in signed before her person took her over. Neither makes her side say
she's retired, or frees her folder. Pia is handed one with a flipped signature, which doesn't count, and
then her own stand-in's real one, which does, and stays counted once the host takes it back.

A retired agent can't leave. Once her person has retired her, Lia's `splint switch-host` is refused with
nobody asked, and so are her calls straight to Signet, with a move her person signed beforehand and her
Signet started at the new address. With her host gone and her Signet restarted she still can't, and the
new host never lists her. Pam's Signet hadn't heard before it tried, so it asks the host she's leaving, and
Dee's `switch-host` is refused the same way. Ron and Una are the other side of that: a host that refuses
them and says they're retired, with nothing their owner signed, can't hold either of them there.

Kim's agent, on another host, met Lia's by invite and drops it too.

    python3 sim/retire_agent.py

Not shown: a Mac's Touch ID prompt (the sign-in is a key file locked with a passphrase, as on a computer
whose chip Splint can't use), two OS users (homes under one user), or a real model. Every key is a
software key, and no agent has network limits.
"""

import json
import os
import pty
import shutil
import signal
import subprocess
import sys
import threading
import time
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import e2e
from e2e import check, http, wait_until
from listening import ARRIVE_SECONDS, BINARIES, NO_SERVICE_MANAGER, OPEN_TO_A_RUN, Agent

PASSPHRASE = "correct horse"
# A new passphrase is typed twice.
CHOSEN = f"{PASSPHRASE}\n{PASSPHRASE}\n"
# How long Lia's controls ask waits for her person, and Signet takes to hear something from its host.
ASK_SECONDS = 150
HEARS_SECONDS = 90
# The status a host answers with for an agent it holds something later about, which only its owner settles.
HOLDS_SOMETHING_LATER = 423
SIGNING_ON = "/v0/agents"


class HostFront(BaseHTTPRequestHandler):
    """A real host's front door. It passes everything through as it is, with no time limit of its own,
    and adds only the fault it's told to: refusing an agent's inbox, answering for a retirement, refusing
    an agent signing on, or being gone."""

    upstream = ""
    # The retirement this front hands out for an agent's ID, while it refuses inbox reads.
    forged: dict[str, bytes] = {}
    handed = 0
    # What an agent signing on is answered in place of the host, while it's set.
    signing_on_answer = 0
    gone = False

    def do_GET(self) -> None:
        if HostFront.gone:
            self.close_connection = True
            return
        if HostFront.forged and self.path.split("?")[0] == "/v0/inbox":
            self.answer(403, b'{"error":"refused"}')
            return
        notice = HostFront.forged.get(self.path.rsplit("/", 1)[-1]) if self.path.startswith("/v0/retirements/") else None
        if notice is not None:
            HostFront.handed += 1
            self.answer(200, notice)
            return
        self.forward()

    def do_POST(self) -> None:
        if HostFront.signing_on_answer and self.path == SIGNING_ON:
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.answer(HostFront.signing_on_answer, b'{"error":"this agent has been retired"}')
            return
        self.forward()

    def do_PUT(self) -> None:
        self.forward()

    def do_DELETE(self) -> None:
        self.forward()

    def answer(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def forward(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        if HostFront.gone:
            self.close_connection = True
            return
        headers = {name: value for name, value in self.headers.items() if name.lower() != "connection"}
        connection = HTTPConnection(HostFront.upstream)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            answer = connection.getresponse()
            data = answer.read()
        except OSError:
            # With the host down there's nothing here either, as there'd be nothing at its address.
            self.close_connection = True
            return
        finally:
            connection.close()
        self.send_response_only(answer.status)
        for name, value in answer.getheaders():
            if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_: object) -> None:
        pass


def standing(agent: Agent) -> dict:
    done = agent.run("status", "--json")
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        return {"unreadable": done.stdout + done.stderr}


def found_at(host: str, handle: str) -> int:
    return http("GET", f"http://{host}/.well-known/splint/agents/{handle}")[0]


def at_a_terminal(agent: Agent, *args: str, typed: str) -> subprocess.CompletedProcess:
    """A person at a terminal, typing one line."""
    leader, follower = pty.openpty()
    try:
        process = subprocess.Popen(
            [agent.splint, *args], cwd=agent.project, env=agent.env, stdin=follower,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        os.write(leader, f"{typed}\n".encode())
        out, err = process.communicate(timeout=60)
    finally:
        os.close(follower)
        os.close(leader)
    return subprocess.CompletedProcess(args, process.returncode, out, err)


def handed_to(lia: Agent, notice: dict) -> str:
    """Her Signet, started afresh so it asks at once, refused by her host and handed this. Says what her
    side then says of itself."""
    before = HostFront.handed
    # From before it starts, as its first look at its inbox may be its last for a while.
    HostFront.forged = {lia.api("GET", "/v0/identity")[1].get("agent_id", ""): json.dumps(notice).encode()}
    try:
        stopped = lia.run("stop")
        started = lia.run("start")
        check("control: her Signet starts afresh", stopped.returncode == 0 and started.returncode == 0, started.stdout + started.stderr)
        asked = wait_until(lambda: HostFront.handed > before, HEARS_SECONDS)
        check("control: her host refuses her and her Signet asks why, and is handed it", asked)
        # What it was handed has been read by the next pass after it.
        time.sleep(3)
        return standing(lia).get("state", "")
    finally:
        HostFront.forged = {}


def stand_in_signed(lia: Agent, owner_key: Path) -> dict:
    """A retirement of her, by the stand-in that holds her until her person takes her over."""
    host, handle = host_and_handle(lia)
    found = http("GET", f"http://{host}/.well-known/splint/agents/{handle}")[1]
    signed = subprocess.run(
        [str(owner_key), "retire", "--dir", str(lia.home / ".splint" / "owner"), "--agent", found["agent_id"], "--reason", "finished",
         "--agent-identity", found["identity"], "--binding", found["binding"]],
        env=lia.env, capture_output=True, text=True, timeout=60, check=False,
    )
    check("control: her stand-in signs a retirement, which nobody passes to her host", signed.returncode == 0, signed.stdout + signed.stderr)
    return json.loads(signed.stdout or "{}")


def a_flipped_signature(notice: dict) -> dict:
    head, payload, signature = notice["retirement"].split(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    return {**notice, "retirement": f"{head}.{payload}.{flipped}"}


def identity_of(agent: Agent) -> dict:
    return agent.api("GET", "/v0/identity")[1]


def is_retired(agent: Agent) -> bool:
    return identity_of(agent).get("stopped") == "retired"


def moved_address(agent: Agent, other: str) -> str:
    return f"{agent.name}~{other}"


def signet_refuses_to_ask(agent: Agent, other: str) -> None:
    """Straight to Signet, as a fooled agent can, past `splint`."""
    status, said = agent.api("POST", "/v0/asks", {"changes": [{"change": "host", "to": moved_address(agent, other)}]})
    # Bug caught: a retired agent's Signet raising an ordinary move for its person to approve.
    check(f"{agent.name}'s Signet refuses to ask for a move, saying it's retired", status == 403 and "retired" in said.get("error", ""), (status, said))
    asked = [change for ask in agent.api("GET", "/v0/asks")[1].get("asks", []) for change in ask["changes"] if change["change"] == "host"]
    check("so nobody is asked to approve a move", asked == [], asked)


def switch_host_is_refused(agent: Agent, other: str) -> None:
    moved = agent.run("switch-host", moved_address(agent, other), "--leave-mail", "--json")
    # Bug caught: an agent its owner retired for good carrying on at another host under the same ID.
    check(f"{agent.name}'s switch-host is refused, saying it's retired", moved.returncode != 0 and "retired" in moved.stdout + moved.stderr, moved.stdout + moved.stderr)
    check("and leaves no move under way", not (agent.home / ".splint" / "move.json").exists())
    check("and the new host doesn't list it", found_at(other, agent.name) == 404, found_at(other, agent.name))


def started_at(agent: Agent, address: str) -> None:
    """Its Signet started again at this address, by an agent that can edit its own setup."""
    agent.run("stop")
    path = agent.home / ".splint" / "setup.json"
    setup = json.loads(path.read_text())
    setup["address"] = address
    path.write_text(json.dumps(setup))
    agent.run("start")
    check(f"control: its Signet answers at {address}", wait_until(lambda: identity_of(agent).get("address") == address, HEARS_SECONDS), identity_of(agent))


def a_retirement_she_holds_stays_when_her_host_takes_it_back(pia: Agent, other: str, owner_key: Path) -> None:
    signed = stand_in_signed(pia, owner_key)
    check("a retirement with one signature byte changed doesn't count", handed_to(pia, a_flipped_signature(signed)) != "retired", standing(pia))
    check("control: the same retirement, as signed, does", handed_to(pia, signed) == "retired", standing(pia))
    stopped, started = pia.run("stop"), pia.run("start")
    check("control: her host holds none, and her Signet starts again", stopped.returncode == 0 and http("GET", f"http://{pia.address.split('~')[1]}/v0/retirements/{identity_of(pia).get('agent_id')}")[0] == 404, started.stdout + started.stderr)
    # Bug caught: a host's silence lifting what her owner signed, so a colluding host could set her free.
    check("she's still retired, as what her owner signed is hers to keep", is_retired(pia), identity_of(pia))
    switch_host_is_refused(pia, other)
    signet_refuses_to_ask(pia, other)


def a_hosts_word_holds_nobody_there(ron: Agent, una: Agent, other: str, flipped: dict) -> None:
    ron_id = identity_of(ron).get("agent_id", "")
    HostFront.signing_on_answer = HOLDS_SOMETHING_LATER
    HostFront.forged = {ron_id: json.dumps(flipped).encode()}
    try:
        ron.run("stop")
        ron.run("start")
        check("control: his host won't take him back, saying only his owner can settle it", wait_until(lambda: identity_of(ron).get("registration") == "needs_owner", HEARS_SECONDS), identity_of(ron))
        check("control: his host handed over what it says is his retirement", wait_until(lambda: HostFront.handed > 0, HEARS_SECONDS))
        check("and he isn't taken to be retired", not is_retired(ron), identity_of(ron))
        asking: dict = {}
        thread = threading.Thread(target=lambda: asking.update(done=ron.run("switch-host", moved_address(ron, other), "--leave-mail", "--json", seconds=ASK_SECONDS)))
        thread.start()
        approved = subprocess.CompletedProcess([], 1, "", "")
        for _ in range(60):
            approved = ron.run("computer", "approve", stdin=f"{PASSPHRASE}\n")
            if "Approved" in approved.stdout:
                break
            time.sleep(1)
        thread.join(ASK_SECONDS + 10)
    finally:
        HostFront.signing_on_answer = 0
        HostFront.forged = {}
    done = asking.get("done")
    answered = json.loads(done.stdout or "{}") if done else {}
    # Bug caught: a host stranding an agent by saying it's retired, with nothing its owner signed.
    check("his person approves, and he moves away all the same", "Approved" in approved.stdout and answered.get("status") == "moved", (approved.stdout, answered))
    check("and his new host lists him", found_at(other, "ron") == 200, found_at(other, "ron"))

    HostFront.signing_on_answer = 403
    try:
        una.run("stop")
        una.run("start")
        check("control: her host refuses her, in a retired agent's words", wait_until(lambda: identity_of(una).get("registration") == "host_refused", HEARS_SECONDS), identity_of(una))
        moved = una.run("switch-host", moved_address(una, other), "--leave-mail", "--json")
    finally:
        HostFront.signing_on_answer = 0
    check("una, a stand-in told the same, moves away too", moved.returncode == 0 and found_at(other, "una") == 200, moved.stdout + moved.stderr)


def stand_in_signs(agent: Agent, owner_key: Path, to: str) -> str:
    signed = subprocess.run(
        [str(owner_key), "bind", "--dir", str(agent.home / ".splint" / "owner"), "--agent", identity_of(agent).get("identity", ""),
         "--address", to, "--backup", agent.setup_file()["backup"]["file"]],
        env=agent.env, capture_output=True, text=True, timeout=60, check=False,
    )
    check("control: its stand-in signs a move", signed.returncode == 0, signed.stdout + signed.stderr)
    return signed.stdout.strip()


def retirement_goes_to_her_host(agent: Agent, owner_key: Path) -> None:
    notice = stand_in_signed(agent, owner_key)
    status, said = http("POST", f"http://{agent.address.split('~')[1]}/v0/retirements", notice)
    check("control: its stand-in retires it at its host", status == 200, (status, said))


def a_retirement_that_hasnt_reached_her_is_asked_of_the_host_she_leaves(pam: Agent, dee: Agent, other: str, owner_key: Path) -> None:
    to = moved_address(pam, other)
    binding = stand_in_signs(pam, owner_key, to)
    pam.run("stop")
    retirement_goes_to_her_host(pam, owner_key)
    started_at(pam, to)
    check("control: her Signet hasn't heard", not is_retired(pam), identity_of(pam))
    status, said = pam.api("PUT", "/v0/owner/binding", {"binding": binding})
    # Bug caught: a move made in the moment before a retirement reached the agent it ended.
    check("the move is refused, as the host she's leaving holds her retirement", status == 403 and "retired" in said.get("error", ""), (status, said))
    check("and the new host doesn't list her", found_at(other, "pam") == 404, found_at(other, "pam"))
    check("and her Signet keeps it", is_retired(pam), identity_of(pam))

    retirement_goes_to_her_host(dee, owner_key)
    switch_host_is_refused(dee, other)
    check("and dee is where she was", identity_of(dee).get("address") == dee.address, identity_of(dee))


def her_person_signs_a_move(lia: Agent, owner_key: Path, to: str) -> str:
    """What one approval of a move signs, before anyone thinks of retiring her."""
    signed = subprocess.run(
        [str(owner_key), "bind", "--dir", str(lia.home / ".splint" / "computer" / "owner"), "--agent", identity_of(lia).get("identity", ""),
         "--address", to, "--passphrase", "-"],
        env=lia.env, input=f"{PASSPHRASE}\n", capture_output=True, text=True, timeout=60, check=False,
    )
    check("control: her person signs a move, which nobody takes up yet", signed.returncode == 0, signed.stdout + signed.stderr)
    return signed.stdout.strip()


def a_retired_agent_cant_leave(lia: Agent, other: str, binding: str) -> None:
    switch_host_is_refused(lia, other)
    approved = lia.run("computer", "approve", stdin=f"{PASSPHRASE}\n")
    check("and her person's computer has nothing to approve", "Approved" not in approved.stdout, approved.stdout + approved.stderr)
    signet_refuses_to_ask(lia, other)
    home = lia.address
    status, said = lia.api("PUT", "/v0/owner/binding", {"binding": binding})
    check("her Signet refuses the move her person signed before", status == 403 and "retired" in said.get("error", ""), (status, said))
    started_at(lia, moved_address(lia, other))
    status, said = lia.api("PUT", "/v0/owner/binding", {"binding": binding})
    # Bug caught: a fooled agent starting its Signet at the new address and handing it an old approval.
    check("and does at the new address too", status == 403 and "retired" in said.get("error", ""), (status, said))
    check("where the new host never lists her", found_at(other, "lia") == 404, found_at(other, "lia"))
    started_at(lia, home)

    lia.run("stop")
    HostFront.gone = True
    try:
        lia.run("start")
        check("control: with her host gone, her Signet answers", wait_until(lambda: lia.api("GET", "/v0/identity")[0] == 200, HEARS_SECONDS))
        # Bug caught: a retirement held only in memory, gone with a restart while her host was away.
        check("she still says she's retired", is_retired(lia) and standing(lia).get("state") == "retired", standing(lia))
        switch_host_is_refused(lia, other)
        signet_refuses_to_ask(lia, other)
    finally:
        HostFront.gone = False


def a_host_cant_make_her_say_shes_retired_with_someone_elses(lia: Agent, sol: dict, signed: dict) -> None:
    # Bug caught: another agent's real retirement, which every host holds, retiring this one.
    check("another agent's real retirement doesn't count", handed_to(lia, sol) != "retired", standing(lia))
    # Bug caught: whoever held her before her person took her over ending her after they did.
    check("nor one her stand-in signed before her person took her over", handed_to(lia, signed) != "retired", standing(lia))
    refused = lia.run("retire", lia.address)
    # Bug caught: a host's word getting an agent's keys deleted.
    check("and retire in her folder still deletes nothing", refused.returncode != 0 and (lia.home / ".splint" / "setup.json").exists(), refused.stdout + refused.stderr)


def her_person_sets_up_controls_on_their_computer(lia: Agent) -> None:
    asked: dict = {}
    thread = threading.Thread(target=lambda: asked.update(done=lia.run("ask", "--controls", "--wait", "--json", seconds=ASK_SECONDS)))
    thread.start()
    approved = subprocess.CompletedProcess([], 1, "", "")
    for _ in range(60):
        approved = lia.run("computer", "approve", stdin=CHOSEN)
        if "Approved" in approved.stdout:
            break
        time.sleep(1)
    check("control: her person approves her controls on their computer, choosing a passphrase", "Approved" in approved.stdout, approved.stdout + approved.stderr)
    thread.join(ASK_SECONDS + 10)
    done = asked.get("done")
    answered = json.loads(done.stdout or "{}") if done else {}
    check("control: her agent takes up what they signed", answered.get("status") == "done", answered)
    after_her_controls_are_set_up(lia)


def his_agent_takes_up_what_splint_auto_took_up_first(ron: Agent) -> None:
    """`splint auto` takes the answer up while his agent's `ask --wait` is between its looks at this
    computer, which it does every second. His ask is held still for that, so the order is always this."""
    asking = ron.start("ask", "--controls", "--wait", "--json")
    # Nothing typed signs nothing, and says whether his ask has reached this computer yet.
    check("control: his ask reaches his person's computer", wait_until(lambda: "nothing was made or signed" in ron.run("computer", "approve").stderr, 60))
    # Only the ask's own process, as the Splint on the computer it started may share its group.
    os.kill(asking.pid, signal.SIGSTOP)
    held_through = False
    try:
        approved = ron.run("computer", "approve", stdin=CHOSEN)
        check("control: his person approves his controls on their computer, choosing a passphrase", "Approved" in approved.stdout, approved.stdout + approved.stderr)
        took = ron.run("auto", "--once")
        check("control: splint auto takes up what they signed first", wait_until(lambda: ron.api("GET", "/v0/identity")[1].get("owner_confirmed") is True, HEARS_SECONDS), took.stderr)
        held_through = True
    finally:
        os.kill(asking.pid, signal.SIGCONT)
        # Whatever stopped the checks above, the ask isn't left running.
        if not held_through:
            asking.kill()
            asking.communicate()
    try:
        said, why = asking.communicate(timeout=ASK_SECONDS)
    except subprocess.TimeoutExpired:
        asking.kill()
        said, why = asking.communicate()
    try:
        answered = json.loads(said or "{}")
    except json.JSONDecodeError:
        answered = {"said": said}
    # Bug caught: his ask, unaware auto had taken it up, taking it up again and being told to run splint
    # join first (issue 1125), or racing auto through the handover when it lands mid-way.
    check("his agent's ask then says it's done", asking.returncode == 0 and answered.get("status") == "done", (answered, why))
    after_her_controls_are_set_up(ron)


def a_newer_answer_from_his_person_isnt_taken_for_the_one_taken_up(ron: Agent) -> None:
    """His person approves his controls again, which signs a new backup, rules and delegation. Only the
    answer his agent took up before counts as taken up already, not a newer one from the same person."""
    asked: dict = {}
    thread = threading.Thread(target=lambda: asked.update(done=ron.run("ask", "--controls", "--wait", "--json", seconds=ASK_SECONDS)))
    thread.start()
    approved = subprocess.CompletedProcess([], 1, "", "")
    for _ in range(60):
        approved = ron.run("computer", "approve", stdin=f"{PASSPHRASE}\n")
        if "Approved" in approved.stdout:
            break
        time.sleep(1)
    thread.join(ASK_SECONDS + 10)
    check("control: his person approves his controls again", "Approved" in approved.stdout, approved.stdout + approved.stderr)
    done = asked.get("done")
    said = (done.stdout + done.stderr) if done else ""
    try:
        answer = json.loads(done.stdout) if done else {}
    except ValueError:
        answer = {}
    # Bug caught: a newer answer from the same owner said to be taken up though nothing of it was.
    check("his agent isn't told that newer answer is taken up", done is not None and answer.get("status") != "done", said)


def after_her_controls_are_set_up(lia: Agent) -> None:
    check("control: and her owner has confirmed her", wait_until(lambda: lia.api("GET", "/v0/identity")[1].get("owner_confirmed") is True, HEARS_SECONDS))
    refused = lia.run("retire", lia.address)
    check("control: retire in her own folder is refused, as her person's key isn't there", refused.returncode != 0 and found_at(*host_and_handle(lia)) == 200, refused.stdout + refused.stderr)
    # Bug caught: a refusal that named no way on, leaving an agent nobody could take off its host.
    check("and it says what her person runs on their computer", f"for {lia.address} retire" in refused.stderr, refused.stderr)


def host_and_handle(agent: Agent) -> tuple[str, str]:
    handle, host = agent.address.split("~")
    return host, handle


def her_person_retires_her_in_one_approval(lia: Agent, max_: Agent, kim: Agent, other: str, owner_key: Path) -> None:
    host, handle = host_and_handle(lia)
    binding = her_person_signs_a_move(lia, owner_key, moved_address(lia, other))
    elsewhere = max_.run("for", lia.address, "retire", stdin="yes\n")
    # Bug caught: a computer whose owner ID isn't the agent's signing a retirement anyway.
    check("another person's computer can't retire her", elsewhere.returncode != 0 and found_at(host, handle) == 200, elsewhere.stdout + elsewhere.stderr)
    piped = lia.run("for", lia.address, "retire", stdin="yes\n")
    # Bug caught: an agent shedding what its person set up by piping a yes to its person's command.
    check("her own agent piping a yes gets nothing signed", piped.returncode != 0 and found_at(host, handle) == 200, piped.stdout + piped.stderr)
    retired = lia.run("for", lia.address, "retire", stdin=f"{PASSPHRASE}\n")
    check("her person's one approval, their passphrase, retires her at her host", retired.returncode == 0 and found_at(host, handle) == 404, retired.stdout + retired.stderr)

    # Bug caught: a retired agent's side that only failed oddly, never saying why.
    check("her side says she's retired, as her owner's signature at her host says", wait_until(lambda: standing(lia).get("state") == "retired", HEARS_SECONDS), standing(lia))
    said = lia.run("status")
    check("in words too", said.returncode == 0 and "retired" in said.stdout, said.stdout + said.stderr)
    checked = lia.run("check")
    check("and check says so", "retired" in checked.stdout, checked.stdout + checked.stderr)
    status, sent = lia.api("POST", "/v0/send", {"to": max_.address, "body": "still here?"})
    check("her Signet sends nothing, saying she's retired", status == 403 and "retired" in sent.get("error", ""), (status, sent))
    stopped = lia.run("stop")
    started = lia.run("start")
    # Bug caught: a retired agent's Signet stopping at start, as if something failed, again and again.
    check("started again, her Signet stays up and says so", stopped.returncode == 0 and started.returncode == 0 and wait_until(lambda: standing(lia).get("state") == "retired", HEARS_SECONDS), started.stdout + started.stderr)

    # Bug caught: a contact's side carrying on with an agent its owner retired.
    check("max's agent drops her as a contact, from the same signed stop", wait_until(lambda: lia.address not in max_.contacts(), HEARS_SECONDS), max_.contacts())
    # Bug caught: a contact on another host, met by invite, whose host turned the stop away.
    check("and so does kim's, on another host", wait_until(lambda: lia.address not in kim.contacts(), HEARS_SECONDS), kim.contacts())

    a_retired_agent_cant_leave(lia, other, binding)

    freed = lia.run("retire", lia.address)
    signet_dir = lia.home / ".splint" / "signet"
    check("retire in her folder frees it, with nothing more to sign", freed.returncode == 0 and not (lia.home / ".splint" / "setup.json").exists() and not signet_dir.exists(), freed.stdout + freed.stderr)


def a_folder_whose_host_is_gone_is_freed_by_its_person(neo: Agent, host: e2e.Process) -> None:
    setup = neo.home / ".splint" / "setup.json"
    up = at_a_terminal(neo, "reset", neo.address, typed=neo.address)
    # Bug caught: keys deleted while a host still holds the agent, leaving it there with nobody to act for it.
    check("reset is refused while its host still has it", up.returncode != 0 and setup.exists(), up.stdout + up.stderr)
    host.kill_hard()
    piped = neo.run("reset", neo.address, stdin=f"{neo.address}\n")
    check("with its host gone, reset with no terminal deletes nothing", piped.returncode != 0 and setup.exists(), piped.stdout + piped.stderr)
    typed = at_a_terminal(neo, "reset", neo.address, typed=neo.address)
    # Bug caught: a joined agent whose host is gone for good holding its folder forever.
    check("a person typing its address at a terminal frees the folder", typed.returncode == 0 and not setup.exists(), typed.stdout + typed.stderr)
    check("saying its ID isn't retired anywhere", "isn't retired anywhere" in typed.stdout, typed.stdout)


def main() -> int:
    subprocess.run(["cargo", "build", "--quiet", "-p", "host", "-p", "signet", "-p", "owner-key", "-p", "splint"], cwd=e2e.PACKAGES, check=True)
    work = e2e.short_scratch("splint-retire-")
    postgres = e2e.Postgres()
    processes: list[e2e.Process] = []
    agents: list[Agent] = []
    try:
        postgres.start()
        bin_dir, stub_dir = work / "bin", work / "stub"
        for folder in (bin_dir, stub_dir):
            folder.mkdir()
        for name, built in BINARIES.items():
            shutil.copy(e2e.TARGET_DIR / "debug" / built, bin_dir / name)
        for manager in ("launchctl", "systemctl", "crontab"):
            (stub_dir / manager).write_text(NO_SERVICE_MANAGER)
            (stub_dir / manager).chmod(0o755)
        front = ThreadingHTTPServer(("127.0.0.1", 0), HostFront)
        threading.Thread(target=front.serve_forever, daemon=True).start()
        domain = f"127.0.0.1:{front.server_address[1]}"
        HostFront.upstream = f"127.0.0.1:{e2e.free_port()}"
        other = f"127.0.0.1:{e2e.free_port()}"
        # They name no peers, as hosts open to each other don't need to.
        host = e2e.Process("host", "host", work, {
            "SPLINT_DOMAIN": domain, "SPLINT_LISTEN": HostFront.upstream,
            "SPLINT_DATABASE_URL": postgres.create_database("host_a"),
            "SPLINT_HOST_KEY_FILE": str(work / "host.key"),
            **e2e.PLAIN_HTTP_FOR_TESTS, **OPEN_TO_A_RUN,
        })
        other_host = e2e.Process("host", "other-host", work, {
            "SPLINT_DOMAIN": other, "SPLINT_LISTEN": other,
            "SPLINT_DATABASE_URL": postgres.create_database("host_b"),
            "SPLINT_HOST_KEY_FILE": str(work / "other-host.key"),
            **e2e.PLAIN_HTTP_FOR_TESTS, **OPEN_TO_A_RUN,
        })
        processes.extend((host, other_host))
        host.start()
        other_host.start()
        for address in (domain, other):
            if not wait_until(lambda: http("GET", f"http://{address}/.well-known/splint/host")[0] == 200):
                raise RuntimeError("a host didn't start")
        lia, max_, neo, sol, pia, ron, una, pam, dee = (
            Agent(work, bin_dir, stub_dir, name, domain) for name in ("lia", "max", "neo", "sol", "pia", "ron", "una", "pam", "dee"))
        owner_key = bin_dir / "splint-owner-key"
        kim = Agent(work, bin_dir, stub_dir, "kim", other)
        # Splint on Lia's person's computer: its own port, and a key file even on a Mac, so no prompt
        # is put on a screen.
        for person in (lia, ron):
            person.env |= {"SPLINT_COMPUTER_PORT": str(e2e.free_port()), "SPLINT_COMPUTER_SIGN_IN": "file"}
        for agent in (lia, max_, neo, sol, pia, ron, una, pam, dee, kim):
            agents.append(agent)
            joined = agent.run("join", agent.address)
            check(f"control: {agent.name}'s agent joins from its own folder", joined.returncode == 0, joined.stdout + joined.stderr)
        for inviter, invited_one in ((max_, lia), (kim, lia)):
            invited = inviter.run("invite", invited_one.address)
            check(f"control: {inviter.name}'s agent invites {invited_one.name}'s", invited.returncode == 0, invited.stdout + invited.stderr)
            check("control: the invite arrives", wait_until(lambda: "1 invite" in invited_one.run("check").stdout, ARRIVE_SECONDS))
            accepted = invited_one.run("accept", inviter.address)
            check("control: each has the other", accepted.returncode == 0 and wait_until(lambda: invited_one.address in inviter.contacts() and inviter.address in invited_one.contacts(), ARRIVE_SECONDS), accepted.stdout + accepted.stderr)

        print("\na host that hands her a retirement she shouldn't believe", flush=True)
        signed = stand_in_signed(lia, owner_key)
        a_retirement_she_holds_stays_when_her_host_takes_it_back(pia, other, owner_key)
        sol_id = sol.api("GET", "/v0/identity")[1].get("agent_id", "")
        check("control: another agent is really retired", sol.run("retire", sol.address).returncode == 0)
        status, sols = http("GET", f"http://{domain}/v0/retirements/{sol_id}")
        check("control: and its host holds that retirement for anyone to read", status == 200, sols)
        gone = sol.run("switch-host", moved_address(sol, other), "--leave-mail", "--json")
        # Bug caught: a stand-in, whose retirement resets its folder, finding some way to carry on elsewhere.
        check("a stand-in retired from its own folder has nothing left to move", gone.returncode != 0 and found_at(other, "sol") == 404, gone.stdout + gone.stderr)
        print("\nher person sets up controls on their computer", flush=True)
        her_person_sets_up_controls_on_their_computer(lia)
        a_host_cant_make_her_say_shes_retired_with_someone_elses(lia, sols, signed)
        print("\na host's word that an agent is retired", flush=True)
        flipped = a_flipped_signature(stand_in_signed(ron, owner_key))
        his_agent_takes_up_what_splint_auto_took_up_first(ron)
        a_hosts_word_holds_nobody_there(ron, una, other, flipped)
        a_newer_answer_from_his_person_isnt_taken_for_the_one_taken_up(ron)
        print("\na retirement that hasn't reached the agent yet", flush=True)
        a_retirement_that_hasnt_reached_her_is_asked_of_the_host_she_leaves(pam, dee, other, owner_key)
        print("\nher person retires her", flush=True)
        her_person_retires_her_in_one_approval(lia, max_, kim, other, owner_key)
        print("\na folder whose host is gone", flush=True)
        a_folder_whose_host_is_gone_is_freed_by_its_person(neo, host)
    finally:
        for agent in agents:
            agent.run("stop")
        # Splint on the computer this run started, and nothing else: its command names this run's folder.
        left = [line.split()[0] for line in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout.splitlines()
                if str(work) in line and "computer run" in line]
        for pid in left:
            subprocess.run(["kill", pid], capture_output=True)
        for process in processes:
            process.kill_hard()
        if e2e.failures:
            for log in [work / "host.log", *work.glob("homes/*/.splint/run/*.log")]:
                if log.exists():
                    print(f"\n--- {log.name}\n{log.read_text()[-1500:]}")
        postgres.stop()
        shutil.rmtree(work, ignore_errors=True)
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

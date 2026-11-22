#!/usr/bin/env python3
"""An agent's Signet answers without its host, so an agent whose host has gone can still leave it.

The bug this catches: Signet opened its local API only once its host had answered. With the host down it
tried for 30 seconds and exited, and whatever kept it running did the same again, so every splint command
failed, `splint switch-host --leave-mail` among them, which exists for a host that has gone for good. An
agent whose host died and whose Signet restarted once was stranded.

Real hosts on this machine, with everyone running the real `splint`, Signet and owner-key in scratch
homes. Joe, whose person set up controls, is on host a, and Nia on host b is his contact. Host a goes down
and Joe's Signet restarts: it answers at once, says it isn't registered, takes nothing it can't deliver on
any route, and keeps going to its host at its own pace, with nothing else of it knocking. Host a comes back
and Joe carries on with nobody doing anything. A Signet that holds its lock and doesn't answer, and one
part way through signing on, are each said to be. Uma's host refuses her once, which is said and heals by
itself. An owner revokes Vic while a try waits, and that try never goes. A host that answers that Xan's
handle is someone else's, and a new host at Wes's address that turns down his code, can't hold either of
them: each moves. Then host a dies for good: Joe, still registered, is told it isn't answering, he and Sam
restart as their keepers restart them, and each moves to another host with `--leave-mail`. Their contact
follows them, and host a, when it returns, is told they left and never gets their old binding again.

    python3 sim/host_gone.py

Not shown: a real network (a host that's gone closes connections here, where a real one may not answer at
all, which costs a Signet's 5-second limit on each try), an outage longer than a few minutes, or Windows.
Keys are software key files, the person's sign-in a plain key file. No agent has network limits.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import e2e
from e2e import check, wait_until
from install import Walkthrough
from request_driver import hours_from_now
from switch_host import FOLLOW_SECONDS, SLOW_SECONDS, Hosts, address_of_contact, approve_once, arrived, controls_set_up, finished, in_background, joins, met_by_invite, running_from, send, who

SIGNET = "splint-signet"
# Long past what a Signet takes to answer, and far short of the 30 seconds it used to spend on its host.
ANSWERS_WITHIN = 15
# A refusal waits a minute for the next try.
HEALS_WITHIN = 90
# How many lines a Signet may log over a whole outage: what changed, and nothing for each try.
MOST_QUIET_LINES = 2
# How a Signet's own call to sign on looks at a host's door.
SIGNING_ON = ("POST", "/v0/agents")
# Tries a host that stays away is given at the longest pause, and what counts as that pause, which is 15
# seconds. It takes about a minute and a half of outage to see them.
TRIES_AT_THE_LONGEST_PAUSE = 3
LONGEST_PAUSE_AT_LEAST = 12
OUTAGE_SECONDS = 150
# Past the minute a refusal waits, so a try that was going to come has come.
PAST_A_REFUSALS_WAIT = 70
# Hosts behind a doorway here, which is how what reaches each is counted.
DOORWAYS = "adef"
# Stands in for launchd and systemd, so what keeps Signet running here is this run and nothing else.
NO_SERVICE_MANAGER = "#!/bin/sh\nexit 1\n"


def no_service_manager(work: Path) -> None:
    """Before anyone here runs anything, so no run of this registers a service on this machine."""
    stubs = work / "no-service-manager"
    stubs.mkdir()
    for program in ("launchctl", "systemctl"):
        (stubs / program).write_text(NO_SERVICE_MANAGER)
        (stubs / program).chmod(0o755)
    os.environ["PATH"] = f"{stubs}:{os.environ['PATH']}"


def standing(walk: Walkthrough, name: str) -> dict:
    return json.loads(walk.run_as(name, "splint status --json").stdout or "{}")


def error_of(done: subprocess.CompletedProcess) -> dict:
    try:
        return json.loads(done.stdout or "{}").get("error", {})
    except json.JSONDecodeError:
        return {}


def log_lines(person) -> int:
    return len((person.dot / "run" / f"{SIGNET}.log").read_text().splitlines())


def answers(person) -> bool:
    try:
        return person.api("GET", "/v0/identity")[0] == 200
    except OSError:
        return False


def crashes_and_its_keeper_starts_it(person) -> subprocess.Popen:
    """Signet dies, and what keeps it running starts it, with nobody there to run a command."""
    os.kill(int((person.dot / "run" / f"{SIGNET}.lock").read_text().strip()), signal.SIGKILL)
    wait_until(lambda: not answers(person), 30)
    return subprocess.Popen(
        [str(person.dot / "bin" / "splint"), "run-service", SIGNET], cwd=person.home, env=person.env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def started_by_its_keeper_with(person, setting: str, value: str) -> subprocess.Popen:
    """What keeps Signet running starts it, with this setting in what it was last started with."""
    launch = person.dot / "run" / f"{SIGNET}.json"
    settings = json.loads(launch.read_text())
    settings["env"] = [pair for pair in settings["env"] if pair[0] != setting] + [[setting, value]]
    launch.write_text(json.dumps(settings))
    return subprocess.Popen(
        [str(person.dot / "bin" / "splint"), "run-service", SIGNET], cwd=person.home, env=person.env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def signs_on_heard(hosts: Hosts, name: str, since: int = 0) -> list[float]:
    return [at for at, method, path in hosts.doorways[name].heard[since:] if (method, path) == SIGNING_ON]


def what_signet_keeps(person) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in (person.dot / "signet").iterdir() if path.suffix == ".json"}


def takes_nothing_it_cant_deliver(walk: Walkthrough, joe, nia, nia_address: str) -> None:
    started = time.monotonic()
    status, refused = joe.api("POST", "/v0/send", {"to": nia_address, "body": "while the host is away"})
    # Bug caught: a note taken and reported sent, with nothing here able to send it.
    check("a note is refused at once, by a word a program can act on", status == 503 and refused.get("error") == "not_registered_yet" and time.monotonic() - started < 3, (status, refused))
    kept = what_signet_keeps(joe)
    a_request = {"contact": nia_address, "deadline": hours_from_now(48), "supersedes": None}
    # Every call of an agent's that needs its host, each one as it would be taken if the host were here.
    for method, path, body in (
        ("POST", "/v0/send", {"to": nia_address, "body": "while the host is away"}),
        ("POST", "/v0/requests", a_request),
        ("POST", "/v0/contacts/ask", {"address": nia_address}),
        ("POST", "/v0/invites", {"to": nia_address}),
        ("POST", "/v0/invites/an-invite/accept", {}),
        ("POST", "/v0/invites/an-invite/decline", {}),
        ("POST", "/v0/inbox/ack", {"message_ids": []}),
        ("POST", "/v0/inbox/carry", {}),
        ("POST", "/v0/types", {}),
        *(("POST", f"/v0/requests/a-request/{step}", {}) for step in ("say", "counter", "accept", "clarify", "progress", "pause", "resume", "deliver", "decline", "cancel")),
        ("GET", "/v0/inbox", None),
        ("GET", "/v0/invites", None),
        ("GET", "/v0/sent/a-message", None),
    ):
        answered = joe.api(method, path, body)
        # Bug caught: a route left out of the gate, or one that does its work first and refuses after.
        check(f"{method} {path} waits for its host", answered[0] == 503 and answered[1].get("error") == "not_registered_yet", answered)
    check("and nothing was queued or saved", joe.api("GET", "/v0/requests")[1].get("requests", []) == [] and what_signet_keeps(joe) == kept, sorted(name for name, held in what_signet_keeps(joe).items() if kept.get(name) != held))
    said = walk.run_as("joe", f"splint --json send {nia_address} hello")
    check("splint send fails honestly, as the host being away", said.returncode != 0 and error_of(said).get("kind") == "host_unreachable", said.stdout + said.stderr)
    # Bug caught: a window before registering in which the API answers without its tokens.
    for method, path, body in (("GET", "/v0/identity", None), ("GET", "/v0/contacts", None), ("POST", "/v0/send", {"to": nia_address, "body": "x"})):
        check(f"{method} {path} still needs the agent's token", joe.api(method, path, body, token="not-this-agents-token")[0] == 401)
    theirs = json.loads((nia.dot / "signet" / "who.json").read_text())["binding"]
    held = (joe.dot / "signet" / "who.json").read_bytes()
    forged = joe.api("PUT", "/v0/owner/binding", {"binding": theirs})
    # Bug caught: a binding taken unchecked while Signet is still trying its host.
    check("and a binding its owner didn't sign is refused", 400 <= forged[0] < 500 and (joe.dot / "signet" / "who.json").read_bytes() == held and who(joe).get("registered") is False, forged)


def keeps_trying_at_its_own_pace(walk: Walkthrough, hosts: Hosts, joe) -> None:
    door = hosts.doorways["a"]
    mark, lines = len(door.heard), log_lines(joe)
    listened = walk.run_as("joe", "splint listen --once --mark outage --seconds 25")
    # Bug caught: a listener saying Signet is down when Signet is what told it the host is away.
    check("a listener says it's the host that's away", "Signet can't be reached" not in listened.stdout + listened.stderr and "host" in listened.stdout + listened.stderr, listened.stdout + listened.stderr)

    def pauses() -> list[float]:
        tries = signs_on_heard(hosts, "a", mark)
        return [later - earlier for earlier, later in zip(tries, tries[1:])]

    def at_the_longest_pause() -> bool:
        last = pauses()[-TRIES_AT_THE_LONGEST_PAUSE:]
        return len(last) == TRIES_AT_THE_LONGEST_PAUSE and all(pause >= LONGEST_PAUSE_AT_LEAST for pause in last)

    # Bug caught: a retry that gives up after a while, or spins, leaving the agent off its host or
    # hammering it. Counted as the host's door sees them.
    check("it keeps going to its host, at its longest pause", wait_until(at_the_longest_pause, OUTAGE_SECONDS), pauses())
    others = [(method, path) for _, method, path in door.heard[mark:] if (method, path) != SIGNING_ON and not path.startswith("/.well-known/")]
    # Bug caught: the loops beside it going to a host that would refuse them all until it's taken this agent.
    check("and nothing else of it goes there meanwhile", others == [], others[:10])
    check("and its log says so once", log_lines(joe) - lines <= MOST_QUIET_LINES, log_lines(joe) - lines)


def an_outage_heals_by_itself(walk: Walkthrough, hosts: Hosts, joe, nia) -> None:
    hosts.stop("a")
    walk.run_as("joe", "splint stop")
    began = time.monotonic()
    started = walk.run_as("joe", "splint --json start")
    took = time.monotonic() - began
    # Bug caught: a start that waited out 30 seconds of retries, then said Signet wasn't answering.
    check("splint start says at once that the host can't be reached", started.returncode != 0 and error_of(started).get("kind") == "host_unreachable" and took < ANSWERS_WITHIN, (took, started.stdout, started.stderr))
    now = who(joe)
    check("and Signet answers, saying it isn't registered", now.get("registered") is False and now.get("registration") == "host_unreachable", now)
    told = standing(walk, "joe")
    check("splint status --json tells the truth", told.get("signet_answering") is True and told.get("registered") is False and told.get("registration") == "host_unreachable", told)
    words = walk.run_as("joe", "splint status").stdout
    check("and so does splint status, with the way out", "not registered at" in words and "--leave-mail" in words, words)
    takes_nothing_it_cant_deliver(walk, joe, nia, nia.address_)
    keeps_trying_at_its_own_pace(walk, hosts, joe)
    hosts.processes["a"].start()
    check("control: host a is back", wait_until(lambda: e2e.http("GET", f"http://{hosts.domain['a']}/.well-known/splint/host")[0] == 200, 30))
    # Bug caught: an agent left off its host until someone restarted its Signet.
    check("it signs back on by itself", wait_until(lambda: who(joe).get("registered") is True, FOLLOW_SECONDS), who(joe))
    check("and its status says so", standing(walk, "joe").get("registration") == "registered")
    check("mail reaches it", wait_until(lambda: send(nia, joe.address_, "after the outage") == 200, FOLLOW_SECONDS) and arrived(joe, "after the outage"), joe.inbox())
    check("and goes out from it", wait_until(lambda: send(joe, nia.address_, "back again") == 200, FOLLOW_SECONDS) and arrived(nia, "back again"), nia.inbox())


def status_says_what_signet_itself_is_doing(walk: Walkthrough, hosts: Hosts, joe) -> None:
    pid = int((joe.dot / "run" / f"{SIGNET}.lock").read_text().strip())
    os.kill(pid, signal.SIGSTOP)
    try:
        words = walk.run_as("joe", "splint status").stdout
        told = standing(walk, "joe")
    finally:
        os.kill(pid, signal.SIGCONT)
    # Bug caught: a Signet that holds its lock and answers nothing shown as running.
    check("a Signet that doesn't answer is said not to", "not answering" in words and told.get("signet_answering") is False, (words, told))

    door = hosts.doorways["a"]
    door.slow_by = SLOW_SECONDS
    keeper = crashes_and_its_keeper_starts_it(joe)
    check("control: it answers while its host takes its time", wait_until(lambda: answers(joe), ANSWERS_WITHIN))
    during = who(joe)
    told = standing(walk, "joe")
    door.slow_by = 0.0
    # Bug caught: a try under way reported as a place at the host.
    check("while it's signing on it isn't called registered", during.get("registered") is False and during.get("registration") == "starting" and told.get("registered") is not True, (during, told))
    check("control: then it is", wait_until(lambda: who(joe).get("registered") is True, FOLLOW_SECONDS), who(joe))
    walk.run_as("joe", "splint stop")
    keeper.wait(timeout=30)
    check("control: joe starts again", walk.run_as("joe", "splint start").returncode == 0 and who(joe).get("registered") is True, who(joe))


def a_refusal_is_said_and_heals(walk: Walkthrough, hosts: Hosts, uma) -> None:
    joins(walk, "uma", uma.address_)
    walk.run_as("uma", "splint stop")
    hosts.doorways["e"].answers_due[SIGNING_ON] = 403
    started = walk.run_as("uma", "splint --json start")
    # Bug caught: the host's no lost, as it was only ever the reason the process ended.
    check("a host that says no is said to have", started.returncode != 0 and error_of(started).get("kind") == "not_registered", started.stdout + started.stderr)
    check("and Signet stays up to say so", who(uma).get("registered") is False and who(uma).get("registration") == "host_refused", who(uma))
    check("it signs on by itself once the host takes it", wait_until(lambda: who(uma).get("registered") is True, HEALS_WITHIN), who(uma))


def an_owner_revokes_while_a_try_waits(walk: Walkthrough, hosts: Hosts, vic, to: str) -> None:
    joins(walk, "vic", vic.address_)
    walk.run_as("vic", "splint stop")
    hosts.doorways["f"].answers_due[SIGNING_ON] = 403
    walk.run_as("vic", "splint start")
    check("control: vic's host said no, and a try waits", who(vic).get("registration") == "host_refused", who(vic))
    made = walk.run_as("vic", f"{vic.dot}/bin/splint-owner-key revoke --dir {vic.dot}/owner --agent {who(vic).get('agent_id')}")
    status, said = vic.api("PUT", "/v0/owner/revocation", {"revocation": made.stdout.strip()})
    check("control: its owner revokes it", status == 200, said)
    mark = len(hosts.doorways["f"].heard)
    time.sleep(PAST_A_REFUSALS_WAIT)
    # Bug caught: a try that carried the binding it read before the owner took it back.
    check("the try that waited never goes", signs_on_heard(hosts, "f", mark) == [], signs_on_heard(hosts, "f", mark))
    check("and vic is said to hold no binding", who(vic).get("registration") == "not_bound", who(vic))
    refused = walk.run_as("vic", f"splint switch-host {to} --leave-mail --json")
    check("so it has nothing to move", refused.returncode != 0 and who(vic).get("address") == vic.address_, refused.stdout + refused.stderr)


def moves_away(walk: Walkthrough, hosts: Hosts, name: str, person, to: str) -> None:
    agent = who(person).get("agent_id")
    moved = walk.run_as(name, f"splint switch-host {to} --leave-mail --json")
    # Bug caught: what the host it leaves answered deciding whether an agent may leave it.
    check(f"{name} moves away all the same", moved.returncode == 0 and json.loads(moved.stdout or "{}").get("status") == "moved" and hosts.found("c", name).get("agent_id") == agent, moved.stdout + moved.stderr)
    check(f"and {name} is registered there", who(person).get("address") == to and who(person).get("registered") is True, who(person))


def a_host_that_gives_its_handle_away_holds_nobody(walk: Walkthrough, hosts: Hosts, xan) -> None:
    joins(walk, "xan", xan.address_)
    walk.run_as("xan", "splint stop")
    hosts.doorways["e"].answers_due[SIGNING_ON] = 409
    walk.run_as("xan", "splint start")
    check("control: its host says someone else has that handle", who(xan).get("registration") == "name_taken", who(xan))
    words = walk.run_as("xan", "splint status").stdout
    # Bug caught: a stand-in told its owner has to sign, when there's nothing to sign and a way out.
    check("its status gives the way out", "--leave-mail" in words and "has to sign" not in words, words)
    moves_away(walk, hosts, "xan", xan, f"xan~{hosts.domain['c']}")


def a_new_host_that_turns_down_its_code_holds_nobody(walk: Walkthrough, hosts: Hosts, wes) -> None:
    joined = walk.run_as("wes", f"splint join {wes.address_} --with-code", hosts.codes["d"][0] + "\n")
    check("control: wes joins a host that takes codes", joined.returncode == 0, joined.stdout + joined.stderr)
    os.kill(int((wes.dot / "run" / f"{SIGNET}.lock").read_text().strip()), signal.SIGKILL)
    wait_until(lambda: not answers(wes), 30)
    hosts.replaced_by_a_new_one("d")
    mark = len(hosts.doorways["d"].heard)
    keeper = started_by_its_keeper_with(wes, "SPLINT_SIGNUP_CODE", "not-a-code-this-host-ever-gave-out")
    check("a code it turns down is said to be", wait_until(lambda: answers(wes) and who(wes).get("registration") == "signup_code_refused", ANSWERS_WITHIN), who(wes) if answers(wes) else "not answering")
    time.sleep(PAST_A_REFUSALS_WAIT)
    # Bug caught: a final answer tried again and again, when only a person with a new code changes it.
    check("and it isn't tried again", len(signs_on_heard(hosts, "d", mark)) == 1 and who(wes).get("registration") == "signup_code_refused", (signs_on_heard(hosts, "d", mark), who(wes)))
    moves_away(walk, hosts, "wes", wes, f"wes~{hosts.domain['c']}")
    keeper.wait(timeout=30)


def what_is_left_of_a_move_goes_to_the_host_it_left(hosts: Hosts, name: str, to: str, person) -> None:
    # Bug caught: the host it left never told, and so still offering this agent's old address.
    check(f"host a says where {name} went", wait_until(lambda: hosts.found("a", name).get("moved_to") == to, FOLLOW_SECONDS), hosts.found("a", name))
    check(f"and {name} is still registered at its new host", who(person).get("address") == to and who(person).get("registered") is True, who(person))


def a_host_gone_for_good_is_left_behind(walk: Walkthrough, hosts: Hosts, joe, sam, nia) -> None:
    joe_id, sam_id = who(joe).get("agent_id"), who(sam).get("agent_id")
    hosts.stop("a")
    # Bug caught: registered read as all's well, for as long as the Signet that signed on keeps running.
    check("joe, still registered, is told its host stopped answering", wait_until(lambda: standing(walk, "joe").get("host_answering") is False, FOLLOW_SECONDS), standing(walk, "joe"))
    words = walk.run_as("joe", "splint status").stdout
    check("in words too, with the way out", "isn't answering" in words and "--leave-mail" in words, words)
    said = walk.run_as("joe", f"splint --json send {nia.address_} hello")
    check("and a note fails as the host being away", said.returncode != 0 and error_of(said).get("kind") == "host_unreachable", said.stdout + said.stderr)
    keepers = [crashes_and_its_keeper_starts_it(joe), crashes_and_its_keeper_starts_it(sam)]
    # Bug caught: a keeper's start that never opened the API, so no command could reach Signet.
    check("what keeps joe's Signet running gets it answering", wait_until(lambda: answers(joe), ANSWERS_WITHIN))
    check("and sam's", wait_until(lambda: answers(sam), ANSWERS_WITHIN))
    check("neither is registered", wait_until(lambda: who(joe).get("registration") == "host_unreachable" and who(sam).get("registration") == "host_unreachable", ANSWERS_WITHIN), (who(joe), who(sam)))

    to_joe, to_sam = f"joe~{hosts.domain['c']}", f"sam~{hosts.domain['c']}"
    stopped = walk.run_as("joe", f"splint switch-host {to_joe} --json")
    words = stopped.stdout + stopped.stderr
    check("a move that would lose what waits is refused, and says how to go on", stopped.returncode != 0 and "--leave-mail" in words and who(joe).get("address") == joe.address_, words)

    moving = in_background(walk, "joe", f"splint switch-host {to_joe} --leave-mail --json")
    approved = approve_once(walk, "joe")
    check("joe's person is asked, with the host it leaves gone", f"move {joe.address_} to {to_joe}" in approved, approved)
    answer = finished(moving)
    # Bug caught: the stranding itself, where only `splint reset` was left.
    check("joe moves with --leave-mail", answer.get("status") == "moved" and who(joe).get("address") == to_joe and who(joe).get("registered") is True, (answer, who(joe)))
    check("under the same ID, which its new host names", who(joe).get("agent_id") == joe_id and hosts.found("c", "joe").get("agent_id") == joe_id, hosts.found("c", "joe"))

    refused = walk.run_as("sam", f"splint switch-host sam~{hosts.domain['d']} --leave-mail --with-code --json", "not-a-code-this-host-ever-gave-out\n")
    said = refused.stdout + refused.stderr
    # Bug caught: going back to a dead host failing the command, and hiding what the new host said.
    check("a new host's refusal is said, though the host it would go back to is gone", refused.returncode != 0 and "didn't take this agent" in said, said)
    check("and sam is still answering, where it was", wait_until(lambda: answers(sam) and who(sam).get("address") == sam.address_, ANSWERS_WITHIN), who(sam))
    moved = walk.run_as("sam", f"splint switch-host {to_sam} --leave-mail --json")
    check("sam, a stand-in, moves with nobody asked", moved.returncode == 0 and json.loads(moved.stdout or "{}").get("status") == "moved" and hosts.found("c", "sam").get("agent_id") == sam_id, moved.stdout + moved.stderr)
    after_both_moved = len(hosts.doorways["a"].heard)

    check("nia's agent sees where joe went", wait_until(lambda: address_of_contact(nia, joe_id) == to_joe, FOLLOW_SECONDS), nia.api("GET", "/v0/contacts")[1])
    check("and reaches it there", wait_until(lambda: send(nia, to_joe, "at your new host") == 200, FOLLOW_SECONDS) and arrived(joe, "at your new host"), joe.inbox())
    for keeper in keepers:
        keeper.wait(timeout=30)

    hosts.processes["a"].start()
    check("control: host a comes back after all", wait_until(lambda: e2e.http("GET", f"http://{hosts.domain['a']}/.well-known/splint/host")[0] == 200, 30))
    what_is_left_of_a_move_goes_to_the_host_it_left(hosts, "joe", to_joe, joe)
    walk.run_as("sam", "splint stop")
    check("control: sam's Signet starts again at its new address", walk.run_as("sam", "splint start").returncode == 0)
    what_is_left_of_a_move_goes_to_the_host_it_left(hosts, "sam", to_sam, sam)
    # Bug caught: a retry carrying the binding it held before the move back to the host it left.
    check("and the host they left never heard from them again to sign on", signs_on_heard(hosts, "a", after_both_moved) == [], signs_on_heard(hosts, "a", after_both_moved))


def main() -> None:
    work = e2e.short_scratch("splint-gone-")
    no_service_manager(work)
    postgres = e2e.Postgres()
    hosts = Hosts(work, postgres, DOORWAYS)
    walk = Walkthrough(work, None, None)
    try:
        joe = walk.new_person("joe")
        joe.env["SPLINT_COMPUTER_PORT"] = str(e2e.free_port())
        joe.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
        sam, nia, uma, vic, wes, xan = (walk.new_person(name) for name in ("sam", "nia", "uma", "vic", "wes", "xan"))
        postgres.start()
        hosts.start_all()
        joe.address_, sam.address_ = f"joe~{hosts.domain['a']}", f"sam~{hosts.domain['a']}"
        nia.address_, uma.address_ = f"nia~{hosts.domain['b']}", f"uma~{hosts.domain['e']}"
        vic.address_, wes.address_, xan.address_ = f"vic~{hosts.domain['f']}", f"wes~{hosts.domain['d']}", f"xan~{hosts.domain['e']}"
        joins(walk, "joe", joe.address_)
        controls_set_up(walk, "joe", "splint", "--plain-key-file")
        joins(walk, "nia", nia.address_)
        nia.agent_id_ = who(nia).get("agent_id")
        met_by_invite(walk, "joe", "nia", joe.address_, nia.address_)
        check("control: joe reaches nia", wait_until(lambda: address_of_contact(joe, nia.agent_id_) != "", FOLLOW_SECONDS))
        status, hello = joe.api("POST", "/v0/send", {"to": nia.address_, "body": "hello nia"})
        check("control: and nia has it", status == 200 and arrived(nia, "hello nia"), hello)
        # Nia's Signet signs a receipt for it, which her host brings to joe's. It has to land before the
        # outage, or her host's retries reach joe's host's door, where only joe should be heard.
        check("control: and joe has her Signet's receipt", wait_until(lambda: joe.api("GET", f"/v0/sent/{hello.get('message_id')}")[1].get("status") == "delivered", FOLLOW_SECONDS), joe.api("GET", f"/v0/sent/{hello.get('message_id')}")[1])
        an_outage_heals_by_itself(walk, hosts, joe, nia)
        status_says_what_signet_itself_is_doing(walk, hosts, joe)
        # After the outage above, where joe alone is what its host's door should hear.
        joins(walk, "sam", sam.address_)
        a_refusal_is_said_and_heals(walk, hosts, uma)
        an_owner_revokes_while_a_try_waits(walk, hosts, vic, f"vic~{hosts.domain['c']}")
        a_host_that_gives_its_handle_away_holds_nobody(walk, hosts, xan)
        a_new_host_that_turns_down_its_code_holds_nobody(walk, hosts, wes)
        a_host_gone_for_good_is_left_behind(walk, hosts, joe, sam, nia)
    finally:
        walk.stop_everything()
        hosts.stop_all()
        postgres.stop()
        # Bug caught: a Signet of this run left running after its folder is gone.
        check("nothing this run started is still running", wait_until(lambda: not running_from(work), 15), running_from(work))
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall host-gone checks passed", flush=True)


if __name__ == "__main__":
    main()

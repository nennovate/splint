#!/usr/bin/env python3
"""A person loses the computer their sign-in and their agent were on, and gets both back on a new one
with their recovery code, in one command, with nobody else acting.

Ivy joins on her own on her person's computer, and one approval there sets up controls. Her `splint
status` says no recovery code is set, and says it until her person sets one with `splint computer
recovery`, which also leaves the owner's list, with Ivy's backup sealed in it, at her host. Sol, at a
second host, runs on another machine under the same owner. Then the whole home is gone. On a new
computer her person types `splint recover ivy~HOST` and the code. Run with no terminal, as an agent
would, it takes nothing. A wrong code changes nothing anywhere. Neither does a host that can't say
whether it holds the list, or a host that doesn't hold it, where the person is asked first and says no:
the code still works after each. The right code brings the owner ID back on that computer's sign-in,
with a new code, and Ivy back at the same ID and address, registered under the recovered owner, after
one approval, even when a run finds her host won't take the recovery, the next is killed just after
that approval, and the next finds her host down. Her rules are the defaults. Sol is named, stopped and left on its machine. The new code opens the
list now at her host, which holds the backup Ivy's ID commits to now. The old sign-in's key file, copied
before the loss, signs nothing her new Signet takes, and the old code gets no host to take a recovery.
An owner whose only agent runs elsewhere still gets a list the new code finds. Uma, another owner's
agent that dealt with Ivy before the loss, carries on with her afterwards with no owner saying yes, and
Uma's owner is told.

    python3 sim/recover_owner.py

Not shown: a Mac's chip (sign-ins are key files, plain on the lost computer and locked on the new
one), contacts in rules (not restored), or a real model. No agent has network limits.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

import e2e
from agent_asks import TOUCH_SECONDS, in_background, on_the_computer
from agent_signup import Signup
from asked_by_link import local
from e2e import check, wait_until

PASSPHRASE = "correct horse"
OWNER_KEY = "$HOME/.splint/bin/splint-owner-key"


def in_a_terminal(signup: Signup, name: str, command: str, answers: list[tuple[str, str]], timeout: int = 300) -> tuple[int, str]:
    return signup.walk.in_a_terminal(name, command, answers, timeout)


class AfterOwnerKey:
    """A fault at the edge between `splint` and the `owner-key` program it runs: once one command has
    finished on this person's computer, `fault` runs with `splint`'s process ID, and only then does
    `splint` hear the answer."""

    def __init__(self, signup: Signup, name: str, command: str, fault) -> None:
        self.program = signup.walk.people[name].home / ".splint" / "bin" / "splint-owner-key"
        self.real = self.program.with_name("splint-owner-key.real")
        self.reached = signup.walk.work / f"reached-{name}-{command}"
        self.go_on = signup.walk.work / f"go-on-{name}-{command}"
        self.command, self.fault = command, fault

    def __enter__(self) -> "AfterOwnerKey":
        self.reached.unlink(missing_ok=True)
        self.go_on.unlink(missing_ok=True)
        os.rename(self.program, self.real)
        self.program.write_text(f"""#!/bin/sh
[ "$1" = "{self.command}" ] || exec "{self.real}" "$@"
answer="$(mktemp)"
"{self.real}" "$@" > "$answer"
status=$?
echo $PPID > "{self.reached}.new" && mv "{self.reached}.new" "{self.reached}"
while [ ! -e "{self.go_on}" ]; do sleep 0.1; done
cat "$answer"
rm -f "$answer"
exit $status
""")
        self.program.chmod(0o755)
        self.watching = threading.Thread(target=self.watch, daemon=True)
        self.watching.start()
        return self

    def watch(self) -> None:
        if wait_until(self.reached.exists, 280):
            self.fault(int(self.reached.read_text()))
        self.go_on.touch()

    def __exit__(self, *_failed) -> None:
        self.go_on.touch()
        self.watching.join(30)
        os.replace(self.real, self.program)


def host_stops(signup: Signup) -> None:
    check("control: her host stops", signup.walk.run_as("hana", "splint host stop").returncode == 0)


def host_starts(signup: Signup) -> None:
    started = signup.walk.run_as("hana", "splint host start")
    answers = lambda: e2e.http("GET", f"http://{signup.open_host}/.well-known/splint/host")[0] == 200  # noqa: E731
    check("control: her host is back", started.returncode == 0 and wait_until(answers, 90), started.stderr)


def status_of(signup: Signup, name: str) -> dict:
    return json.loads(signup.walk.run_as(name, "splint status --json").stdout or "{}")


def held_owner(signup: Signup) -> str:
    """The copy of Ivy's owner's ID her host holds, as its operator reads it."""
    return signup.sql("hana", "SELECT owner_identity FROM agents WHERE handle = 'ivy'")


def ivy_is_set_up_and_told_no_code_is_set(signup: Signup, port: int):
    host = signup.open_host
    ivy = signup.device("ivy")
    on_the_computer(ivy, port)
    check("control: ivy joins on her own", signup.walk.run_as("ivy", f"splint join ivy~{host}").returncode == 0)
    # --wait, as splint controls waits only where a prompt here asks by itself, which a key file doesn't.
    asking = in_background(signup, "ivy", "splint ask --controls --wait --json")
    approved = ""
    for _ in range(60):
        time.sleep(1)
        done = signup.walk.run_as("ivy", "splint computer approve --plain-key-file", "yes\n")
        approved = done.stdout + done.stderr
        if "Approved 1" in approved:
            break
    check("control: one approval sets up her controls", "Approved 1" in approved, approved)
    asking["thread"].join(TOUCH_SECONDS + 40)
    check("control: she takes it up", wait_until(lambda: ivy.api("GET", "/v0/identity")[1].get("owner_confirmed") is True, 60), ivy.api("GET", "/v0/identity")[1])
    # Bug caught: an agent never told that losing its person's computer would lose it.
    check("her status says no recovery code is set", status_of(signup, "ivy").get("recovery_code") == "not_set", status_of(signup, "ivy"))
    check("and keeps no list of her at her host while there's no code to open it", signup.sql("hana", "SELECT count(*) FROM owner_agent_lists") == "0")
    status, made = in_a_terminal(signup, "ivy", "splint computer recovery", [])
    code = next((line.strip() for line in made.splitlines() if line.startswith("  ") and line.count("-") >= 5), "")
    check("control: her person sets the recovery code in their own terminal", status == 0 and code, made)
    # Bug caught: the backup of an agent set up in one touch kept only on the computer that's lost.
    handle = signup.sql("hana", "SELECT handle FROM owner_agent_lists")
    check("setting it leaves the owner's list at her host, under a handle the code gives", len(handle) == 64, handle)
    # Bug caught: a status that stopped answering read as one that stopped warning.
    says_it_is_set = lambda: (standing := status_of(signup, "ivy")).get("state") == "controls_set" and "recovery_code" not in standing  # noqa: E731
    check("and her status stops saying so once her Signet hears it", wait_until(says_it_is_set, 90), status_of(signup, "ivy"))
    who = ivy.api("GET", "/v0/identity")[1]
    return ivy, code, who, handle


def asks_by_link(signup: Signup, name: str, host: str, person: str, port: int, approving: str):
    """An agent on a machine of its own joins, and a person approves its controls on their computer."""
    agent = signup.device(name)
    on_the_computer(agent, e2e.free_port())
    check(f"control: {name} joins on its own", signup.walk.run_as(name, f"splint join {name}~{host}").returncode == 0)
    asked = json.loads(signup.walk.run_as(name, "splint controls --json").stdout or "{}")
    _, ask = agent.api("GET", f"/v0/asks/{asked.get('id', '')}")
    status, _ = local("POST", port, "/local/asks", {"ask": ask.get("ask", ""), "address": f"{name}~{host}"})
    check(f"control: its link hands {person}'s computer the ask", status == 200, status)
    approved = signup.walk.run_as(person, approving, "yes\n")
    check(f"control: {person} approves {name}", "Approved 1" in approved.stdout + approved.stderr, approved.stdout + approved.stderr)
    signup.walk.run_as(name, "splint auto --once")
    check(f"control: {name} takes it up", wait_until(lambda: agent.api("GET", "/v0/identity")[1].get("owner_confirmed") is True, 60), agent.api("GET", "/v0/identity")[1])
    return agent


def sol_runs_on_another_machine(signup: Signup, port: int):
    """Sol is at a second host, on a machine of his own, under the same owner as Ivy."""
    second = signup.start_host("kofi")
    return asks_by_link(signup, "sol", second, "ivy", port, "splint computer approve"), second


def hold_back_recoveries(signup: Signup) -> None:
    """The host's database refuses to move an agent to a recovered owner, so a host answers everything
    else and fails only the call that tells it of the recovery."""
    signup.sql("hana", "CREATE FUNCTION hold_back() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'held back'; END $$ LANGUAGE plpgsql; "
                       "CREATE TRIGGER hold_back BEFORE UPDATE OF owner_identity ON agents FOR EACH ROW EXECUTE FUNCTION hold_back()")


def let_recoveries_through(signup: Signup) -> None:
    signup.sql("hana", "DROP TRIGGER hold_back ON agents; DROP FUNCTION hold_back()")


def uma_deals_with_ivy_before_the_loss(signup: Signup):
    """Uma is another owner's agent, on another computer, and Ivy's contact by invite."""
    host = signup.open_host
    una = signup.device("una")
    port = e2e.free_port()
    on_the_computer(una, port)
    check("control: splint starts on una's computer", signup.walk.run_as("una", "splint computer start").returncode == 0)
    check("control: and serves her page", wait_until(lambda: local("POST", port, "/local/asks", {})[0] != 0, 60))
    uma = asks_by_link(signup, "uma", host, "una", port, "splint computer approve --plain-key-file")
    uma.address = f"uma~{host}"
    meet(signup, "ivy", f"ivy~{host}", uma)
    return uma


def meet(signup: Signup, inviter: str, inviter_address: str, uma) -> None:
    """The two agents agree to deal with each other, which no person takes part in."""
    sent = signup.walk.run_as(inviter, f"splint invite {uma.address} --json")
    check(f"control: {inviter} invites uma", sent.returncode == 0, sent.stdout + sent.stderr)
    accepts = lambda: signup.walk.run_as("uma", f"splint accept {inviter_address}").returncode == 0  # noqa: E731
    check("control: and uma's agent accepts", wait_until(accepts, 60))


def bodies_of(person) -> list[str]:
    return [message["untrusted"]["body"] for message in person.inbox()]


def uma_carries_on_with_nobody_acting(signup: Signup, uma) -> None:
    """Bug caught: each contact's owner had to find an Allow button before a recovered owner's agent
    could deal with theirs, and nothing told them to. The agents meet again, as Ivy's contacts don't
    come back with her, and no person on either side does anything."""
    ivy_address = f"ivy~{signup.open_host}"
    new = signup.walk.people["ivy-new"]
    meet(signup, "ivy-new", ivy_address, uma)
    sends = lambda: new.api("POST", "/v0/send", {"to": uma.address, "body": "back after the loss"})[0] == 200  # noqa: E731
    check("her agent can write to uma again, with no owner saying yes", wait_until(sends, 120))
    check("and uma reads it", wait_until(lambda: "back after the loss" in bodies_of(uma), 120), bodies_of(uma))
    replies = lambda: uma.api("POST", "/v0/send", {"to": ivy_address, "body": "glad you're back"})[0] == 200  # noqa: E731
    check("uma's agent can answer, past its own host's hold", wait_until(replies, 120))
    check("and ivy reads it", wait_until(lambda: "glad you're back" in bodies_of(new), 120), bodies_of(new))
    owner_token = uma.setup_file()["owner_token"]
    changes = uma.api("GET", "/v0/owner/changes", token=owner_token)[1].get("changes", [])
    told = next((one for one in changes if one.get("address") == ivy_address), {})
    # Bug caught: carrying on in silence, so a contact's owner never hears the other side recovered.
    check("uma's owner is told, with nothing waiting on them", told.get("standing") == "continue" and any(one.get("whose") == "owner" for one in told.get("since_accepted", [])), changes)
    warned = [message.get("facts", {}).get("warnings", []) for message in uma.inbox() if message["untrusted"]["body"] == "back after the loss"]
    check("and uma's agent is given the fact with the message", any("owner_changed_recently" in words for words in warned), warned)


def the_computer_is_lost(signup: Signup, ivy) -> str:
    """Everything in her home goes, after her processes stop. The old sign-in's folder is copied first,
    as a thief would."""
    stolen = signup.walk.work / "stolen-sign-in"
    shutil.copytree(ivy.dot / "computer" / "owner", stolen)
    signup.walk.run_as("ivy", "splint stop")
    shutil.rmtree(ivy.home)
    ivy.home.mkdir()
    return str(stolen)


def recovering_on_a_new_computer(signup: Signup, port: int, code: str, before: dict, old_handle: str, sol, second: str) -> str:
    host = signup.open_host
    owner_before = held_owner(signup)
    sol_before = sol.api("GET", "/v0/identity")[1]
    new = signup.device("ivy-new")
    on_the_computer(new, port)
    made = new.dot / "computer" / "owner" / "owner.identity"
    piped = signup.walk.run_as("ivy-new", f"splint recover ivy~{host}", f"{code}\n{PASSPHRASE}\n{PASSPHRASE}\n")
    # Bug caught: a recovery code taken from a pipe, as from an agent's shell, where the new one lands
    # in its transcript. All it would need is here, so only the terminal check stops it.
    check("with no terminal, as an agent runs it, it takes no code", piped.returncode != 0 and "terminal" in piped.stderr + piped.stdout and not made.exists(), piped.stdout + piped.stderr)
    check("and the owner ID at her host is as it was, with everything an agent could pipe", held_owner(signup) == owner_before)

    wrong = "abcd-efgh-ijkl-mnop-qrst-uvwx-yq"
    status, said = in_a_terminal(signup, "ivy-new", f"splint recover ivy~{host}", [
        ("recovery code:", wrong), ("Type yes to go on", "yes"), ("Choose a passphrase", PASSPHRASE), ("same passphrase again", PASSPHRASE)])
    # Bug caught: a wrong code that moves the owner ID.
    check("a wrong code is refused", status != 0 and "is back" not in said, said)
    check("and the owner ID at her host is as it was", held_owner(signup) == owner_before)
    check("and nothing is made on this computer", not made.exists())

    # Bug caught: a host that failed to answer read as one holding no list, which spent the code and
    # left every agent behind for good.
    with AfterOwnerKey(signup, "ivy-new", "list-handle", lambda _pid: host_stops(signup)):
        status, said = in_a_terminal(signup, "ivy-new", f"splint recover ivy~{host}", [
            ("recovery code:", code), ("Type yes to go on", "yes"), ("Choose a passphrase", PASSPHRASE), ("same passphrase again", PASSPHRASE)], timeout=120)
    check("a host that can't say whether it holds her list stops it", status != 0 and "Type yes to go on" not in said, said)
    check("with nothing made on this computer", not made.exists(), said)
    host_starts(signup)
    check("and the owner ID at her host is as it was once it's back", held_owner(signup) == owner_before)

    # Bug caught: the code spent at a host holding no list, with no word that no agent would come back.
    status, said = in_a_terminal(signup, "ivy-new", f"splint recover sol~{second}", [("recovery code:", code), ("Type yes to go on", "no")])
    check("at a host with no list of hers her person is asked first, and saying no stops it", status != 0 and "Type yes to go on" in said, said)
    check("with nothing made on this computer either", not made.exists(), said)

    # Bug caught: a list her host hands back that can't be read skipped, which spent the code with no
    # question asked and left every backup sealed in it out of reach.
    kept = signup.sql("hana", "SELECT list FROM owner_agent_lists")
    signup.sql("hana", "UPDATE owner_agent_lists SET list = 'this is not a list'")
    status, said = in_a_terminal(signup, "ivy-new", f"splint recover ivy~{host}", [
        ("recovery code:", code), ("Choose a passphrase", PASSPHRASE), ("same passphrase again", PASSPHRASE)], timeout=120)
    signup.sql("hana", f"UPDATE owner_agent_lists SET list = '{kept}'")
    check("a list her host can't give readably stops it, and says to try again", status != 0 and "try again" in said.lower() and "Type yes to go on" not in said, said)
    check("with nothing made on this computer, and the owner ID at her host as it was", not made.exists() and held_owner(signup) == owner_before, said)

    # Bug caught: an agent called back already, or brought back, at a host that never took the owner's
    # recovery, which would undo the agent's when it did.
    hold_back_recoveries(signup)
    status, said = in_a_terminal(signup, "ivy-new", f"splint recover ivy~{host}", [
        ("recovery code:", code), ("Choose a passphrase", PASSPHRASE), ("same passphrase again", PASSPHRASE)])
    let_recoveries_through(signup)
    check("a host that won't take the recovery is said to, and she waits for it", status == 0 and "couldn't be told" in said and "back already" not in said and "is back on this computer" not in said, said)
    check("control: her host still holds the owner as they were", held_owner(signup) == owner_before)
    new_code = next((line.strip() for line in said.splitlines() if line.startswith("  ") and line.count("-") >= 5), "")
    check("and a new code was shown", bool(new_code) and new_code != code, said)

    # Bug caught: a run cut off after the approval, whose rerun could never finish.
    def killed(pid: int) -> None:
        os.kill(pid, signal.SIGKILL)

    with AfterOwnerKey(signup, "ivy-new", "restore-agents", killed):
        status, first = in_a_terminal(signup, "ivy-new", f"splint recover ivy~{host}", [("passphrase:", PASSPHRASE)])
    check("control: the next run is cut off just after the approval", status != 0 and "is back on this computer" not in first, first)

    # Bug caught: a Signet that took the recovery while its host was down, refusing the next one signed.
    with AfterOwnerKey(signup, "ivy-new", "restore-agents", lambda _pid: host_stops(signup)):
        status, said = in_a_terminal(signup, "ivy-new", f"splint recover ivy~{host}", [("passphrase:", PASSPHRASE)])
    host_starts(signup)
    check("control: the next run finds her host down, and says to run it again", "isn't confirmed back yet" in said, said)

    status, said = in_a_terminal(signup, "ivy-new", f"splint recover ivy~{host}", [("passphrase:", PASSPHRASE)])
    check("run again with no code, it finishes", status == 0 and "ivy~" in said and "is back on this computer" in said, said)
    now = new.api("GET", "/v0/identity")[1]
    # Bug caught: a lost computer losing the agent, or bringing it back as someone else.
    check("ivy is back with the same ID and address", now.get("agent_id") == before.get("agent_id") and now.get("address") == before.get("address"), now)
    check("under the same owner, registered at her host", now.get("owner_id") == before.get("owner_id") and now.get("registered") is True and now.get("recovering") is False, now)
    check("and nothing stops her", now.get("stopped") is None, now)
    check("with a new key", now.get("key") != before.get("key"), now)
    check("her host holds the recovered owner", held_owner(signup) != owner_before and held_owner(signup).count("~") > owner_before.count("~"))
    standing = status_of(signup, "ivy-new")
    check("her status says her controls are set and the new code is", standing.get("state") == "controls_set" and "recovery_code" not in standing, standing)

    # Bug caught: an agent on another machine taken over, or said to be left working when it's stopped.
    check("sol is named as stopped on his own machine", f"sol~{second} ran on another computer" in said and "stopped" in said, said)
    check("and isn't brought here", all(sol_before["agent_id"] not in path.read_text() for path in new.home.rglob("setup.json")))
    check("and his Signet there keeps its key", sol.api("GET", "/v0/identity")[1].get("key") == sol_before.get("key"), sol.api("GET", "/v0/identity")[1])
    check("and stops, as her person was told", wait_until(lambda: sol.api("GET", "/v0/identity")[1].get("registered") is False, 120), sol.api("GET", "/v0/identity")[1])

    the_new_codes_list_holds_her(signup, new_code, old_handle)

    again, said = in_a_terminal(signup, "ivy-new", f"splint recover ivy~{host}", [("passphrase:", PASSPHRASE)])
    check("run again, it needs no code and finds her back", again == 0 and "back already" in said, said)
    return owner_before


def the_new_codes_list_holds_her(signup: Signup, new_code: str, old_handle: str) -> None:
    """Bug caught: a list the new code can't find, or one holding a backup her ID has moved on from, so
    losing this computer too loses her."""
    host = signup.open_host
    wanted = signup.walk.run_as("ivy-new", f"{OWNER_KEY} list-handle --code -", new_code + "\n").stdout.strip()
    named = lambda: signup.sql("hana", "SELECT handle FROM owner_agent_lists")  # noqa: E731
    check("the list at her host is the one the new code finds", len(wanted) == 64 and wanted != old_handle and wait_until(lambda: named() == wanted, 90), named())
    given = json.dumps({"identities": [held_owner(signup)], "lists": [signup.sql("hana", "SELECT list FROM owner_agent_lists")], "host": host})
    third = signup.walk.work / "a-third-computer"
    opened = signup.walk.run_as("ivy-new", f"{OWNER_KEY} recover --dir {third} --sign-in file --plain-key-file yes --code -", f"{new_code}\n{given}")
    check("and the new code opens it", opened.returncode == 0 and json.loads(opened.stdout or "{}").get("list_found") is True, opened.stderr)
    ivy_now = signup.sql("hana", "SELECT identity FROM agents WHERE handle = 'ivy'")
    fits = [signup.walk.run_as("ivy-new", f"{OWNER_KEY} check-backup --backup {key} --agent {ivy_now}").returncode == 0 for key in (third / "agent-backups").glob("*.key")]
    check("and it holds the backup her ID commits to now", any(fits), fits)

    # Bug caught: one agent taken by whoever has the lost disk, or a host showing an old copy of its ID,
    # stopping every other agent coming back.
    stranger, stranger_id = e2e.new_identity(signup.walk.work / "a-stranger.key")
    who = signup.walk.people["ivy-new"].api("GET", "/v0/identity")[1]
    both = [{"identity": one, "address": f"{handle}~{host}", "new_key": who["key"], "delegate": who["delegate"]} for one, handle in ((stranger, "stranger"), (ivy_now, "ivy"))]
    restored = signup.walk.run_as("ivy-new", f"{OWNER_KEY} restore-agents --dir {third} --schemas {signup.walk.people['ivy-new'].dot / 'schemas'}", json.dumps({"host": host, "rules": e2e.rules_draft([]), "here": both, "list": []}))
    printed = json.loads(restored.stdout or "{}")
    check("an agent whose ID fits no backup here is left out, and the rest still come back", [one.get("agent") for one in printed.get("agents", [])] == [who["agent_id"]] and printed.get("not_ours") == [stranger_id], restored.stdout + restored.stderr)


def what_the_old_sign_in_and_code_get(signup: Signup, stolen: str, code: str, owner_before: str) -> None:
    """Bug caught: the lost computer's sign-in, or its code, still counting after a recovery."""
    host = signup.open_host
    new = signup.walk.people["ivy-new"]
    agent = new.api("GET", "/v0/identity")[1]
    # What the stolen folder remembers of her backup's vouch lets its key sign a binding with no backup.
    signed = signup.walk.run_as("ivy-new", f"{OWNER_KEY} bind --dir {stolen} --agent {agent['identity']} --address ivy~{host}")
    check("control: the stolen sign-in still signs a binding for her", signed.returncode == 0 and signed.stdout.strip(), signed.stderr)
    status, _ = new.api("PUT", "/v0/owner/binding", {"binding": signed.stdout.strip()})
    check("which her Signet refuses, as that key no longer counts", status == 403, status)
    check("so she's still bound under the recovered owner", new.api("GET", "/v0/identity")[1].get("registered") is True)
    ours = signup.walk.run_as("ivy-new", f"{OWNER_KEY} bind --dir {new.dot / 'computer' / 'owner'} --passphrase - --agent {agent['identity']} --address ivy~{host}", f"{PASSPHRASE}\n")
    status, _ = new.api("PUT", "/v0/owner/binding", {"binding": ours.stdout.strip()})
    check("control: the same call takes a binding from the sign-in that counts", status == 200, (status, ours.stderr))

    both = json.dumps({"identities": [owner_before, held_owner(signup)], "lists": [], "host": host})
    twice = signup.walk.work / "twice"
    old = signup.walk.run_as("ivy-new", f"{OWNER_KEY} recover --dir {twice} --sign-in file --plain-key-file yes --code -", f"{code}\n{both}")
    check("owner-key won't use the old code once it sees the recovery", old.returncode != 0 and not (twice / "owner.identity").exists(), old.stderr)
    # Whoever has the old code can run owner-key on the old copy alone, so it's the host that has to say no.
    alone = json.dumps({"identities": [owner_before], "lists": [], "host": host})
    forked = signup.walk.run_as("ivy-new", f"{OWNER_KEY} recover --dir {signup.walk.work / 'forked'} --sign-in file --plain-key-file yes --code -", f"{code}\n{alone}")
    check("control: the old code still signs on the old copy", forked.returncode == 0, forked.stderr)
    held = held_owner(signup)
    status, _ = e2e.http("POST", f"http://{host}/v0/recoveries", {"identity": json.loads(forked.stdout or "{}").get("identity", "")})
    check("which her host refuses", status >= 400 and held_owner(signup) == held, status)


def an_owner_with_only_an_agent_elsewhere(signup: Signup) -> None:
    """Bug caught: a list signed only when an agent comes back here, so an owner whose agents all run on
    other machines holds a code that finds nothing, and the next lost computer loses every backup."""
    host = signup.open_host
    port = e2e.free_port()
    pat = signup.device("pat")
    on_the_computer(pat, port)
    check("control: splint starts on pat's computer", signup.walk.run_as("pat", "splint computer start").returncode == 0)
    check("control: and serves her page", wait_until(lambda: local("POST", port, "/local/asks", {})[0] != 0, 60))
    asks_by_link(signup, "rae", host, "pat", port, "splint computer approve --plain-key-file")
    status, made = in_a_terminal(signup, "pat", "splint computer recovery", [])
    code = next((line.strip() for line in made.splitlines() if line.startswith("  ") and line.count("-") >= 5), "")
    check("control: pat sets her recovery code", status == 0 and code, made)
    held = lambda: signup.sql("hana", "SELECT handle FROM owner_agent_lists WHERE owner_id = (SELECT owner_id FROM agents WHERE handle = 'rae')")  # noqa: E731
    old_handle = held()
    check("control: her list is at the host", len(old_handle) == 64, old_handle)
    signup.walk.run_as("pat", "splint stop")
    shutil.rmtree(pat.home)
    pat.home.mkdir()
    new = signup.device("pat-new")
    on_the_computer(new, e2e.free_port())
    status, said = in_a_terminal(signup, "pat-new", f"splint recover rae~{host}", [
        ("recovery code:", code), ("Choose a passphrase", PASSPHRASE), ("same passphrase again", PASSPHRASE)])
    new_code = next((line.strip() for line in said.splitlines() if line.startswith("  ") and line.count("-") >= 5), "")
    check("control: pat recovers, and rae stays where she runs", status == 0 and new_code and "ran on another computer" in said, said)
    wanted = signup.walk.run_as("pat-new", f"{OWNER_KEY} list-handle --code -", new_code + "\n").stdout.strip()
    check("the new code finds a list at her host, though no agent came back here", wait_until(lambda: held() == wanted, 60), held())


def main() -> None:
    work = e2e.short_scratch("splint-recover-")
    signup = Signup(work)
    port = e2e.free_port()
    try:
        ivy, code, before, handle = ivy_is_set_up_and_told_no_code_is_set(signup, port)
        sol, second = sol_runs_on_another_machine(signup, port)
        uma = uma_deals_with_ivy_before_the_loss(signup)
        stolen = the_computer_is_lost(signup, ivy)
        owner_before = recovering_on_a_new_computer(signup, e2e.free_port(), code, before, handle, sol, second)
        uma_carries_on_with_nobody_acting(signup, uma)
        what_the_old_sign_in_and_code_get(signup, stolen, code, owner_before)
        an_owner_with_only_an_agent_elsewhere(signup)
    finally:
        signup.walk.stop_everything()
        left = [line.split()[0] for line in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout.splitlines()
                if str(work) in line and ("computer run" in line or "splint-signet" in line)]
        for pid in left:
            subprocess.run(["kill", pid], capture_output=True)
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall recovery checks passed", flush=True)


if __name__ == "__main__":
    main()

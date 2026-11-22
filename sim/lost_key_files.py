#!/usr/bin/env python3
"""A key file goes missing from an agent's folder, and what's waiting for that agent isn't lost.

The bug this catches: Signet made a new key on any start that found one missing, after a partial restore
or a clean-up, and threw away a good sealing key beside it. Mail sealed to the old key could then never
be opened, and one read of the inbox cleared it from the host for good while its sender saw `delivered`.

Ivy joins a real host on her person's computer, with controls and a recovery code, and Ben becomes her
contact. Her Signet crashes while Ben's mail waits, sealed, at her host. With agent.seal gone, agent.key
gone, both gone, each replaced by another agent's, each cut short, and who.json gone or damaged, neither
what keeps Signet running nor `splint start` gets it going: each says which file, nothing is made or
removed, and the mail stays unread at the host. Once the real file is back she reads all of it. A setting
naming someone else's ID, or a copy of hers from before a finished recovery, makes no key.
`splint-signet prepare` makes nothing for an agent that has an ID, and does for one that hasn't. A
recovery cut off partway leaves her keys as they were, whichever goes missing next, and finishing it on
them she reads what waited. With her person's sign-in still here, `splint recover` leaves alone a key
whose permissions are wrong and a folder that lost who.json, each with Signet's reason, and once a key is
lost for good it says what's lost and takes a typed yes, or the address typed out again where there's no
terminal, before it puts her on new keys. With their sign-in gone, a recovery of her owner does the same:
a key whose permissions are wrong stops it before the code is asked for, and so does a no to replacing a
lost one, whether the recovery is new or was cut off. Then her person loses their sign-in and her key
together, and `splint recover` replaces the key on purpose, once told yes, in the folder that's still here,
and asks the same of Kit, a second agent on that computer. Sol's person signs in on another computer, where
`splint recover` can't replace his keys and says what can be done, and that works.

    python3 sim/lost_key_files.py

Not shown: a Mac's chip (sign-ins are key files), Windows, or a real model. No agent has network limits.
"""

import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import e2e
from agent_asks import on_the_computer
from agent_signup import Signup
from e2e import check, wait_until
from outbound_text import SCALAR_BYTES, SCALAR_STARTS_AFTER
from recover_owner import PASSPHRASE, TOUCH_SECONDS, AfterOwnerKey, asks_by_link, in_a_terminal, in_background, ivy_is_set_up_and_told_no_code_is_set, status_of

KEY_FILES = ("agent.seal", "agent.key")
# What a recovery that's still going keeps beside them, and anything else that would be a key made here.
EVERY_KEY_FILE = (*KEY_FILES, "agent.key.new", "agent.seal.new")
ARRIVE_SECONDS = 60
SIGNET = "splint-signet"
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


def signet_pid(person) -> int:
    return int((person.dot / "run" / f"{SIGNET}.lock").read_text().strip())


def answers(person) -> bool:
    try:
        return person.api("GET", "/v0/identity")[0] == 200
    except OSError:
        return False


def crashes(person) -> None:
    os.kill(signet_pid(person), signal.SIGKILL)
    check("control: her Signet has stopped", wait_until(lambda: not answers(person), 30))


def unread_at_host(signup: Signup, agent_id: str) -> int:
    return int(signup.sql("hana", f"SELECT count(*) FROM inbox WHERE recipient = '{agent_id}' AND NOT acked"))


def bens_mail_waits(signup: Signup, ben, ivy_address: str, ivy_id: str, body: str) -> None:
    before = unread_at_host(signup, ivy_id)
    check("control: ben's mail goes", wait_until(lambda: ben.api("POST", "/v0/send", {"to": ivy_address, "body": body})[0] == 200, ARRIVE_SECONDS))
    check("control: and waits at her host", wait_until(lambda: unread_at_host(signup, ivy_id) > before, ARRIVE_SECONDS))
    held = signup.sql("hana", f"SELECT envelope FROM inbox WHERE recipient = '{ivy_id}' AND NOT acked ORDER BY seq DESC LIMIT 1")
    check("control: sealed, so only her key opens it", body not in json.dumps(e2e.payload_of(held)), held[:80])


def run_by_her_keeper(person) -> subprocess.CompletedProcess:
    """What launchd, systemd or a crontab line runs, by itself, with nobody there to read an error."""
    try:
        return person.shell(f"{person.dot}/bin/splint run-service {SIGNET}", person.home, timeout=15)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(SIGNET, 0, "it started and kept running", "")


def secrets_in(folder: Path) -> list[bytes]:
    """Each key file whole, and the private scalar inside a signing key, which is the key itself."""
    found = []
    for name in KEY_FILES:
        whole = (folder / name).read_bytes()
        found.append(whole)
        if SCALAR_STARTS_AFTER in whole:
            start = whole.index(SCALAR_STARTS_AFTER) + len(SCALAR_STARTS_AFTER)
            found.append(whole[start:start + SCALAR_BYTES])
    return found


def spellings_of(secrets: list[bytes]) -> list[str]:
    return [spelling for secret in secrets for spelling in (secret.hex(), secret.hex().upper(), base64.b64encode(secret).decode(), base64.urlsafe_b64encode(secret).decode().rstrip("="))]


def keys_here(person) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in (person.dot / "signet").iterdir() if path.name in EVERY_KEY_FILE}


def failure_kind(done: subprocess.CompletedProcess) -> str:
    try:
        return json.loads(done.stdout or "{}").get("error", {}).get("kind", "")
    except json.JSONDecodeError:
        return ""


def refused_naming(signup: Signup, ivy, ivy_id: str, file: str, unread: int, secrets: list[bytes]) -> None:
    before = keys_here(ivy)
    kept = run_by_her_keeper(ivy)
    # Bug caught: a start that found a key file missing made a new one and carried on.
    check(f"what keeps her Signet running can't start it without the real {file}", kept.returncode != 0, kept.stdout + kept.stderr)
    log = (ivy.dot / "run" / f"{SIGNET}.log").read_text()
    check("and her log says which file", file in log.splitlines()[-1], log.splitlines()[-1])
    started = signup.walk.run_as("ivy", "splint start")
    check(f"splint start refuses, and names {file}", started.returncode != 0 and file in started.stderr, started.stdout + started.stderr)
    # Bug caught: a program told only that something failed, with nothing it could act on.
    told = signup.walk.run_as("ivy", "splint --json start")
    check("by a word a program can act on", failure_kind(told) == "signet_wont_start", told.stdout + told.stderr)
    after = keys_here(ivy)
    # Bug caught: a missing agent.key taking the good agent.seal with it.
    check("no key was made or removed", after == before, sorted(after))
    status = signup.walk.run_as("ivy", "splint status")
    check("splint status says why it isn't running", file in status.stdout and "as after a crash" not in status.stdout, status.stdout)
    standing = status_of(signup, "ivy")
    check("and so does status --json", standing.get("signet_answering") is False and file in standing.get("next", ""), standing)
    said = "".join([started.stdout, started.stderr, told.stdout, told.stderr, status.stdout, status.stderr, json.dumps(standing), log])
    # Bug caught: an error carrying the key it was complaining about, whole or just its private scalar.
    check("with nothing of any key in what it says", not any(spelling in said for spelling in spellings_of(secrets)))
    # Bug caught: one read clearing mail nobody could open.
    check("and what waits for her is still at her host, unread", unread_at_host(signup, ivy_id) == unread, unread_at_host(signup, ivy_id))


def she_reads_it_once_the_real_file_is_back(signup: Signup, ivy, body: str) -> None:
    started = signup.walk.run_as("ivy", "splint start")
    check("with the real file back, her Signet starts", started.returncode == 0, started.stdout + started.stderr)
    check("and her host has her", wait_until(lambda: ivy.api("GET", "/v0/identity")[1].get("registered") is True, 30), ivy.api("GET", "/v0/identity"))
    def read() -> bool:
        return any(message["untrusted"]["body"] == body for message in ivy.inbox())
    # Bug caught: mail sealed to the key that was missing, unreadable for good once it's back.
    check("and she reads what waited", wait_until(read, ARRIVE_SECONDS), ivy.inbox())
    read_ids = [message["verified"]["message_id"] for message in ivy.inbox()]
    check("control: and clears it", ivy.api("POST", "/v0/inbox/ack", {"message_ids": read_ids})[0] == 200)


def files_go_missing(signup: Signup, ivy, ben, ivy_address: str, ivy_id: str, files: tuple[str, ...]) -> None:
    """A restore that left secrets out takes both at once, and Signet names the first it needs."""
    named = files[-1]
    body = f"written while {' and '.join(files)} were about to go missing"
    crashes(ivy)
    bens_mail_waits(signup, ben, ivy_address, ivy_id, body)
    secrets = secrets_in(ivy.dot / "signet")
    for file in files:
        os.replace(ivy.dot / "signet" / file, signup.walk.work / f"aside-{file}")
    refused_naming(signup, ivy, ivy_id, named, unread_at_host(signup, ivy_id), secrets)
    check(f"and {' and '.join(files)} stayed missing", not any((ivy.dot / "signet" / file).exists() for file in files))
    for file in files:
        os.replace(signup.walk.work / f"aside-{file}", ivy.dot / "signet" / file)
    she_reads_it_once_the_real_file_is_back(signup, ivy, body)


def a_file_is_cut_short(signup: Signup, ivy, ben, ivy_address: str, ivy_id: str, file: str) -> None:
    body = f"written while {file} was cut short"
    crashes(ivy)
    bens_mail_waits(signup, ben, ivy_address, ivy_id, body)
    real = ivy.dot / "signet" / file
    secrets, whole = secrets_in(ivy.dot / "signet"), real.read_bytes()
    real.write_bytes(whole[:len(whole) // 2])
    # Bug caught: a key that can't be read thrown away and made again.
    refused_naming(signup, ivy, ivy_id, file, unread_at_host(signup, ivy_id), secrets)
    real.write_bytes(whole)
    she_reads_it_once_the_real_file_is_back(signup, ivy, body)


def what_says_who_she_is_is_lost(signup: Signup, ivy, ben, ivy_address: str, ivy_id: str) -> None:
    body = "written while who.json was lost"
    crashes(ivy)
    bens_mail_waits(signup, ben, ivy_address, ivy_id, body)
    folder = ivy.dot / "signet"
    secrets, whole = secrets_in(folder), (folder / "who.json").read_bytes()
    os.replace(folder / "agent.key", signup.walk.work / "aside-beside-who")
    for damage in (None, b"{}", b"", b"not what Signet writes"):
        if damage is None:
            (folder / "who.json").unlink()
        else:
            (folder / "who.json").write_bytes(damage)
        # Bug caught: a folder with no ID read as a new agent, whose first start replaced the good agent.seal.
        refused_naming(signup, ivy, ivy_id, "who.json", unread_at_host(signup, ivy_id), secrets)
    (folder / "who.json").write_bytes(whole)
    os.replace(signup.walk.work / "aside-beside-who", folder / "agent.key")
    she_reads_it_once_the_real_file_is_back(signup, ivy, body)


def told_she_is_recovering(ivy, identity: str) -> subprocess.CompletedProcess:
    """What keeps her Signet running starts it with this ID named as the one it takes up."""
    launch = ivy.dot / "run" / f"{SIGNET}.json"
    settings = json.loads(launch.read_text())
    settings["env"] = [pair for pair in settings["env"] if pair[0] != "SPLINT_RECOVERING"] + [["SPLINT_RECOVERING", identity]]
    launch.write_text(json.dumps(settings))
    return run_by_her_keeper(ivy)


def a_recovery_that_isnt_hers_makes_no_key(signup: Signup, ivy, identity: str, whose: str) -> None:
    crashes(ivy)
    for file in KEY_FILES:
        aside = signup.walk.work / f"aside-told-{file}"
        os.replace(ivy.dot / "signet" / file, aside)
        before = keys_here(ivy)
        kept = told_she_is_recovering(ivy, identity)
        # Bug caught: any ID in the setting, or one left behind by a recovery that finished, making keys again.
        check(f"told to take up {whose}, with {file} missing, her Signet won't start", kept.returncode != 0, kept.stdout + kept.stderr)
        check("and makes no key", keys_here(ivy) == before, sorted(keys_here(ivy)))
        os.replace(aside, ivy.dot / "signet" / file)
    started = signup.walk.run_as("ivy", "splint start")
    check("control: with her files back she starts", started.returncode == 0 and wait_until(lambda: answers(ivy), 30), started.stdout + started.stderr)


def a_file_is_someone_elses(signup: Signup, ivy, ben, ivy_address: str, ivy_id: str, file: str) -> None:
    body = f"written while {file} was someone else's"
    crashes(ivy)
    bens_mail_waits(signup, ben, ivy_address, ivy_id, body)
    real = ivy.dot / "signet" / file
    secrets = secrets_in(ivy.dot / "signet") + secrets_in(ben.dot / "signet")
    aside = signup.walk.work / f"aside-{file}"
    os.replace(real, aside)
    shutil.copy(ben.dot / "signet" / file, real)
    real.chmod(0o600)
    # Bug caught: a sync tool's copy from another agent taken for this agent's own key.
    refused_naming(signup, ivy, ivy_id, file, unread_at_host(signup, ivy_id), secrets)
    os.replace(aside, real)
    she_reads_it_once_the_real_file_is_back(signup, ivy, body)


def preparing_makes_keys_only_before_there_is_an_id(signup: Signup, ivy) -> None:
    folder = ivy.dot / "signet"
    aside = signup.walk.work / "aside-while-preparing"
    os.replace(folder / "agent.key", aside)
    prepared = ivy.shell(f"SPLINT_STATE_DIR={folder} {ivy.dot}/bin/splint-signet prepare", ivy.home, timeout=30)
    made = (folder / "agent.key").exists()
    os.replace(aside, folder / "agent.key")
    # Bug caught: the other way a key was made, which `splint` runs on a folder that already has an ID.
    check("signet prepare makes no key for an agent that has an ID", prepared.returncode != 0 and not made, prepared.stdout + prepared.stderr)
    host = signup.open_host
    first = signup.walk.run_as("ned", f"splint join ned~{host} --owner-first")
    keys = lambda: (signup.walk.people["ned"].dot / "signet" / "agent.pub").read_text()  # noqa: E731
    earlier = keys()
    again = signup.walk.run_as("ned", f"splint join ned~{host} --owner-first")
    check("control: first setup still makes its keys, and keeps them when it's run again", first.returncode == 0 and again.returncode == 0 and keys() == earlier and earlier != "", first.stderr)


def a_recovery_cut_off_leaves_her_keys_alone(signup: Signup, ivy, ben, ivy_address: str, ivy_id: str, code: str) -> None:
    """Her person's sign-in is gone and a recovery here is cut off once it's signed, so its setting stays
    behind for every later start."""
    body = "sealed to her keys before a recovery that was cut off"
    identity = ivy.api("GET", "/v0/identity")[1]["identity"]
    crashes(ivy)
    bens_mail_waits(signup, ben, ivy_address, ivy_id, body)
    folder = ivy.dot / "signet"
    real, secrets = keys_here(ivy), secrets_in(folder)
    shutil.rmtree(ivy.dot / "computer")
    (folder / "agent.key").chmod(0o644)
    kept = told_she_is_recovering(ivy, identity)
    # Bug caught: a Signet taking up its ID that read a key it couldn't open as no key, and made new ones.
    check("told to take up her own ID, her Signet won't start on a key others can read", kept.returncode != 0 and keys_here(ivy) == real, kept.stdout + kept.stderr)
    (folder / "agent.key").chmod(0o600)
    for file in KEY_FILES:
        (folder / file).chmod(0o644)
        status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("Type yes", "yes"), ("recovery code:", code)])
        # Bug caught: her owner's recovery replacing working keys over a permission one chmod would have fixed.
        check(f"with her sign-in gone, splint recover refuses {file} that others can read, before it takes the code", status != 0 and file in said and "readable only by this user" in said and "recovery code:" not in said and "Type yes" not in said, said)
        check("and replaces nothing", keys_here(ivy) == real, sorted(keys_here(ivy)))
        (folder / file).chmod(0o600)
    with AfterOwnerKey(signup, "ivy", "restore-agents", lambda pid: os.kill(pid, signal.SIGKILL)):
        _, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [
            ("recovery code:", code), ("Choose a passphrase", PASSPHRASE), ("same passphrase again", PASSPHRASE)])
    check("control: the recovery was cut off, with its setting left behind", json.loads((ivy.dot / "setup.json").read_text()).get("recovering"), said)
    crashes(ivy)
    unread = unread_at_host(signup, ivy_id)

    os.replace(folder / "agent.seal", signup.walk.work / "aside-cut-off")
    # Bug caught: that setting letting a start make a new agent.seal beside her real agent.key, where one
    # read of the inbox then cleared what nobody could open any more.
    refused_naming(signup, ivy, ivy_id, "agent.seal", unread, secrets)
    os.replace(signup.walk.work / "aside-cut-off", folder / "agent.seal")

    os.replace(folder / "agent.key", signup.walk.work / "aside-cut-off")
    signup.walk.run_as("ivy", "splint start")
    check("with agent.key missing it waits on new keys of its own", wait_until(lambda: answers(ivy) and ivy.api("GET", "/v0/identity")[1].get("recovering") is True, 30), ivy.api("GET", "/v0/identity"))
    ivy.api("GET", "/v0/inbox")
    # Bug caught: the good agent.seal deleted to make room for a new pair the recovery hadn't finished with.
    check("and her real agent.seal stays as it was", (folder / "agent.seal").read_bytes() == real["agent.seal"])
    check("with what waits for her still unread", unread_at_host(signup, ivy_id) == unread, unread_at_host(signup, ivy_id))
    crashes(ivy)

    kept = keys_here(ivy)
    status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("Type yes", "no")])
    # Bug caught: a run that kept her keys until it was cut off taken as a yes to losing them afterwards.
    check("with agent.key lost after the cut, it says what's lost and stops without a yes", status != 0 and "can never be opened" in said and "nothing was replaced" in said, said)
    check("and replaces nothing", keys_here(ivy) == kept, sorted(keys_here(ivy)))
    os.replace(signup.walk.work / "aside-cut-off", folder / "agent.key")
    kept = keys_here(ivy)
    for file in KEY_FILES:
        (folder / file).chmod(0o644)
        status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("Type yes", "yes"), ("passphrase:", PASSPHRASE)])
        # Bug caught: a recovery carried on with only the sign-in's passphrase, replacing both keys over a chmod.
        check(f"carrying on, splint recover refuses {file} that others can read", status != 0 and file in said and "readable only by this user" in said and "Type yes" not in said, said)
        check("and replaces nothing", keys_here(ivy) == kept, sorted(keys_here(ivy)))
        (folder / file).chmod(0o600)

    status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("passphrase:", PASSPHRASE)])
    check("with her real keys back the recovery finishes on them", status == 0 and "is back on this computer" in said, said)
    check("and they're the same keys", {name: keys_here(ivy).get(name) for name in KEY_FILES} == {name: real[name] for name in KEY_FILES})
    she_reads_it_once_the_real_file_is_back(signup, ivy, body)


def what_can_be_put_right_is_never_replaced(signup: Signup, ivy, ivy_address: str) -> None:
    """Good keys in a folder that a chmod or a restored file would put right."""
    folder = ivy.dot / "signet"
    crashes(ivy)
    kept = keys_here(ivy)
    for file in KEY_FILES:
        (folder / file).chmod(0o644)
        refused = signup.walk.run_as("ivy", "splint start")
        check(f"control: a start refuses {file} that others can read", refused.returncode != 0 and file in refused.stderr, refused.stderr)
        status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("Type yes", "yes"), ("passphrase:", PASSPHRASE)])
        # Bug caught: working keys replaced for good over a permission one chmod would have fixed.
        check(f"splint recover refuses too, with Signet's reason for {file}", status != 0 and file in said and "readable only by this user" in said and "Type yes" not in said, said)
        check("and replaces nothing", keys_here(ivy) == kept, sorted(keys_here(ivy)))
        (folder / file).chmod(0o600)
    whole = (folder / "who.json").read_bytes()
    for damage in (None, b"not what Signet writes"):
        if damage is None:
            (folder / "who.json").unlink()
        else:
            (folder / "who.json").write_bytes(damage)
        status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("Type yes", "yes"), ("passphrase:", PASSPHRASE)])
        # Bug caught: success reported on a folder left with no binding, not_bound until its owner signed again.
        check("with who.json lost, splint recover refuses and says why", status != 0 and "who.json" in said and "is on new keys" not in said, said)
        check("and replaces nothing", keys_here(ivy) == kept, sorted(keys_here(ivy)))
    (folder / "who.json").write_bytes(whole)
    started = signup.walk.run_as("ivy", "splint start")
    check("with those put right she starts on the same keys", started.returncode == 0 and wait_until(lambda: ivy.api("GET", "/v0/identity")[1].get("registered") is True, 30) and keys_here(ivy) == kept, started.stdout + started.stderr)


def nothing_is_replaced_without_a_yes(signup: Signup, ivy, ivy_address: str) -> None:
    """Her key is really gone, and whoever runs this hasn't said to replace it yet."""
    kept = keys_here(ivy)
    status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("Type yes", "no")])
    # Bug caught: keys replaced with no warning of what's lost and no way to stop.
    check("splint recover says what's lost, and stops without a yes", status != 0 and "can never be opened" in said and "nothing was replaced" in said, said)
    piped = signup.walk.run_as("ivy", f"splint recover {ivy_address}", "yes\n")
    # Bug caught: an agent piping a yes into its person's command.
    check("no yes is taken from a pipe", piped.returncode != 0 and "terminal" in piped.stderr, piped.stdout + piped.stderr)
    wrong = signup.walk.run_as("ivy", f"splint recover {ivy_address} --replace-keys someone~else.example", f"{PASSPHRASE}\n")
    check("and the address typed out has to be hers", wrong.returncode != 0 and "type its own address" in wrong.stderr, wrong.stdout + wrong.stderr)
    check("so nothing was replaced", keys_here(ivy) == kept and "recovering" not in json.loads((ivy.dot / "setup.json").read_text()), sorted(keys_here(ivy)))


def her_owner_here_puts_her_on_new_keys(signup: Signup, ivy, ivy_address: str) -> None:
    """Her person still has their sign-in, and her keys are lost for good."""
    what_can_be_put_right_is_never_replaced(signup, ivy, ivy_address)
    before = ivy.api("GET", "/v0/identity")[1]
    folder = ivy.dot / "signet"
    crashes(ivy)
    (folder / "agent.seal").unlink()
    kept = keys_here(ivy)
    status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("passphrase:", PASSPHRASE)])
    # Bug caught: a recovery replacing a sealing key while the signing key beside it can still be used.
    check("with only agent.seal gone, recovery says what to do about agent.key first", status != 0 and "agent.key" in said and keys_here(ivy) == kept, said)
    (folder / "agent.key").unlink()
    refused = signup.walk.run_as("ivy", "splint start")
    check("control: a start won't make keys, and sends her person to splint recover", refused.returncode != 0 and "splint recover" in refused.stderr, refused.stderr)
    nothing_is_replaced_without_a_yes(signup, ivy, ivy_address)
    status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("Type yes", "yes"), ("passphrase:", PASSPHRASE)])
    # Bug caught: the refusal pointing at a command that answered there was no recovery to carry on with.
    check("splint recover puts her on new keys", status == 0 and "is on new keys" in said, said)
    now = ivy.api("GET", "/v0/identity")[1]
    check("with the same ID and address", now.get("agent_id") == before.get("agent_id") and now.get("address") == before.get("address") and now.get("key") != before.get("key"), now)
    check("registered, and waiting on nothing", wait_until(lambda: ivy.api("GET", "/v0/identity")[1].get("registered") is True, 30) and now.get("recovering") is False, now)
    check("with no recovery left to start as", "recovering" not in json.loads((ivy.dot / "setup.json").read_text()))
    check("and her new keys in their own files", set(keys_here(ivy)) == set(KEY_FILES), sorted(keys_here(ivy)))
    crashes(ivy)
    started = signup.walk.run_as("ivy", "splint start")
    check("she starts on them next time", started.returncode == 0 and wait_until(lambda: ivy.api("GET", "/v0/identity")[1].get("registered") is True, 30), started.stdout + started.stderr)
    same = keys_here(ivy)
    status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("passphrase:", PASSPHRASE)])
    # Bug caught: a working agent's keys replaced because someone ran the command twice.
    check("and asking again replaces nothing", status == 0 and "is on new keys" not in said and keys_here(ivy) == same, said)
    crashes(ivy)
    (folder / "agent.key").unlink()
    typed_out = signup.walk.run_as("ivy", f"splint recover {ivy_address} --replace-keys {ivy_address}", f"{PASSPHRASE}\n")
    # Bug caught: lost keys that only a terminal could ever replace, for an agent's person who has none.
    check("with no terminal, her address typed out again replaces them", typed_out.returncode == 0 and "is on new keys" in typed_out.stdout, typed_out.stdout + typed_out.stderr)


def kit_joins_beside_her(signup: Signup, ivy) -> str:
    """A second agent of her person's, a profile on the same computer, so a recovery naming Ivy reaches it
    only once her person's code is spent. Gives its address."""
    address = f"kit~{signup.open_host}"
    check("control: kit joins as a profile", signup.walk.run_as("ivy", f"splint --as kit join {address}").returncode == 0)
    asking = in_background(signup, "ivy", "splint --as kit ask --controls --wait --json")
    approved = ""
    for _ in range(60):
        time.sleep(1)
        approved = signup.walk.run_as("ivy", "splint computer approve", "yes\n").stdout
        if "Approved 1" in approved:
            break
    check("control: her person approves kit", "Approved 1" in approved, approved)
    asking["thread"].join(TOUCH_SECONDS + 40)
    return address


def kit_is_asked_about_in_turn(signup: Signup, ivy, address: str, kit_folder: Path) -> None:
    """Her person's code is spent by now, and Kit's keys are looked at as the run comes to it."""
    ivy_address = f"ivy~{signup.open_host}"
    (kit_folder / "agent.key").chmod(0o600)
    kept = {name: (kit_folder / name).read_bytes() for name in KEY_FILES}
    os.replace(kit_folder / "agent.key", signup.walk.work / "aside-kit")
    status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("passphrase:", PASSPHRASE), ("Type yes", "no")])
    # Bug caught: only the agent named on the command line asked about, and every other agent's keys replaced unasked.
    check("with kit's key lost, a recovery says what's lost and leaves kit without a yes", "can never be opened" in said and f"{address} wasn't brought back" in said and "nothing was replaced" in said, said)
    check("and kit's other key stays as it was", (kit_folder / "agent.seal").read_bytes() == kept["agent.seal"], said)
    refused = signup.walk.run_as("ivy", "splint --as kit start")
    check("control: a start can't make kit a new key, and lifts her person's stop", refused.returncode != 0 and "agent.key" in refused.stderr, refused.stderr)
    status, said = in_a_terminal(signup, "ivy", f"splint recover {ivy_address}", [("passphrase:", PASSPHRASE), ("Type yes", "yes")])
    check("told yes, kit comes back on new keys", status == 0 and f"{address} is back on this computer" in said, said)
    check("and they're new", (kit_folder / "agent.key").read_bytes() != kept["agent.key"], said)


def recovery_replaces_a_key_on_purpose(signup: Signup, ivy, code: str, before: dict) -> None:
    """Her person's sign-in and her key are gone together, and the rest of her folder is still here."""
    kit = kit_joins_beside_her(signup, ivy)
    kit_folder = ivy.dot / "profiles" / "kit" / "signet"
    signup.walk.run_as("ivy", "splint --as kit stop")
    signup.walk.run_as("ivy", "splint stop")
    shutil.rmtree(ivy.dot / "computer")
    (ivy.dot / "signet" / "agent.key").unlink()
    refused = signup.walk.run_as("ivy", "splint start")
    check("control: a start can't make her a new key, so her person turns to recovery", refused.returncode != 0 and "agent.key" in refused.stderr, refused.stderr)
    status, said = in_a_terminal(signup, "ivy", f"splint recover ivy~{signup.open_host}", [("Type yes", "no"), ("recovery code:", code)])
    # Bug caught: keys replaced with no word of what's lost, or the code spent before her person could stop.
    check("splint recover says what's lost, and a no stops it before the code is asked for", status != 0 and "can never be opened" in said and "recovery code:" not in said, said)
    (kit_folder / "agent.key").chmod(0o644)
    kit_keys = {name: (kit_folder / name).read_bytes() for name in KEY_FILES}
    status, said = in_a_terminal(signup, "ivy", f"splint recover ivy~{signup.open_host}", [
        ("Type yes", "yes"), ("recovery code:", code), ("Choose a passphrase", PASSPHRASE), ("same passphrase again", PASSPHRASE)])
    # Bug caught: a second agent's working keys replaced over a permission, in a run that named another agent.
    check("kit's key that others can read leaves kit behind, with Signet's reason", f"{kit} wasn't brought back" in said and "readable only by this user" in said, said)
    check("and kit's keys as they were", {name: (kit_folder / name).read_bytes() for name in KEY_FILES} == kit_keys and not (kit_folder / "agent.key.new").exists(), said)
    # Bug caught: refusing every start with a key gone, which would stop the one path meant to replace it.
    check("splint recover brings her back in the folder that's still here", status == 0 and "is back on this computer" in said, said)
    now = ivy.api("GET", "/v0/identity")[1]
    check("with the same ID and address, on a new key", now.get("agent_id") == before.get("agent_id") and now.get("address") == before.get("address") and now.get("key") != before.get("key"), now)
    check("registered, and waiting on nothing", now.get("registered") is True and now.get("recovering") is False, now)
    signup.walk.run_as("ivy", "splint stop")
    started = signup.walk.run_as("ivy", "splint start")
    # Bug caught: a recovered agent's new keys refused at its next start.
    check("and she starts again on her new keys", started.returncode == 0 and wait_until(lambda: ivy.api("GET", "/v0/identity")[1].get("registered") is True, 30), started.stdout + started.stderr)
    kit_is_asked_about_in_turn(signup, ivy, kit, kit_folder)
    # What ends this run stops the default agent, and a profile's Signet would outlive it.
    signup.walk.run_as("ivy", "splint --as kit stop")


def his_owner_signs_in_on_another_computer() -> None:
    """Sol's folder is on a machine of his own, and his person's sign-in is on theirs."""
    work = e2e.short_scratch("splint-keyfiles-")
    no_service_manager(work)
    signup = Signup(work)
    try:
        port = e2e.free_port()
        ivy_is_set_up_and_told_no_code_is_set(signup, port)
        sol = asks_by_link(signup, "sol", signup.open_host, "ivy", port, "splint computer approve")
        sol_address = f"sol~{signup.open_host}"
        crashes(sol)
        (sol.dot / "signet" / "agent.key").unlink()
        refused = signup.walk.run_as("sol", "splint start")
        # Bug caught: a refusal sending a person to a command that can't do what it says.
        check("the refusal says what can be done from another computer", refused.returncode != 0 and "another computer" in refused.stderr and "retire" in refused.stderr, refused.stderr)
        status, said = in_a_terminal(signup, "ivy", f"splint recover {sol_address}", [])
        check("splint recover on that computer says the same, naming the command", status != 0 and f"splint for {sol_address} retire" in said, said)
        retired = signup.walk.run_as("ivy", f"splint for {sol_address} retire", "yes\n")
        check("and what it names works", retired.returncode == 0, retired.stdout + retired.stderr)
    finally:
        signup.walk.stop_everything()
        time.sleep(1)
        shutil.rmtree(work, ignore_errors=True)


def she_loses_all_but_her_folder() -> None:
    """On a host of its own, as a host takes a second recovery of an owner soon after an agent's new keys
    for a thief's, and stops that agent until its owner signs again."""
    work = e2e.short_scratch("splint-keyfiles-")
    no_service_manager(work)
    signup = Signup(work)
    try:
        ivy, code, before, _handle = ivy_is_set_up_and_told_no_code_is_set(signup, e2e.free_port())
        recovery_replaces_a_key_on_purpose(signup, ivy, code, before)
        a_recovery_that_isnt_hers_makes_no_key(signup, ivy, before["identity"], "her ID as it was before a finished recovery")
    finally:
        signup.walk.stop_everything()
        time.sleep(1)
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    work = e2e.short_scratch("splint-keyfiles-")
    no_service_manager(work)
    signup = Signup(work)
    try:
        ivy, code, before, _handle = ivy_is_set_up_and_told_no_code_is_set(signup, e2e.free_port())
        ben = signup.device("ben")
        on_the_computer(ben, e2e.free_port())
        ned = signup.device("ned")
        on_the_computer(ned, e2e.free_port())
        host = signup.open_host
        ivy_address, ben_address = f"ivy~{host}", f"ben~{host}"
        check("control: ben joins", signup.walk.run_as("ben", f"splint join {ben_address}").returncode == 0)
        check("control: ivy invites ben", signup.walk.run_as("ivy", f"splint invite {ben_address} --json").returncode == 0)
        check("control: and he accepts", wait_until(lambda: signup.walk.run_as("ben", f"splint accept {ivy_address}").returncode == 0, 60))
        check("control: ben can write to her", wait_until(lambda: any(one["address"] == ivy_address for one in ben.api("GET", "/v0/contacts")[1].get("contacts", [])), 60))
        ivy_id = before["agent_id"]
        for files in (("agent.seal",), ("agent.key",), KEY_FILES):
            files_go_missing(signup, ivy, ben, ivy_address, ivy_id, files)
        for file in KEY_FILES:
            a_file_is_someone_elses(signup, ivy, ben, ivy_address, ivy_id, file)
            a_file_is_cut_short(signup, ivy, ben, ivy_address, ivy_id, file)
        what_says_who_she_is_is_lost(signup, ivy, ben, ivy_address, ivy_id)
        a_recovery_that_isnt_hers_makes_no_key(signup, ivy, ben.api("GET", "/v0/identity")[1]["identity"], "ben's ID")
        preparing_makes_keys_only_before_there_is_an_id(signup, ivy)
        a_recovery_cut_off_leaves_her_keys_alone(signup, ivy, ben, ivy_address, ivy_id, code)
        her_owner_here_puts_her_on_new_keys(signup, ivy, ivy_address)
    finally:
        signup.walk.stop_everything()
        time.sleep(1)
        shutil.rmtree(work, ignore_errors=True)
    she_loses_all_but_her_folder()
    his_owner_signs_in_on_another_computer()
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall key file checks passed", flush=True)


if __name__ == "__main__":
    main()

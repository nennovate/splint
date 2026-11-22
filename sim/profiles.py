#!/usr/bin/env python3
"""Three agents of one person on one machine, each a profile with its own Signet, talking through Splint.

Nenye's home already has an agent of its own, the default. Two more set up as profiles, one with
`--as` and one with `SPLINT_AS` as a runtime would set it, and a third joins on its own and is
confirmed by the same owner key, which every profile shares and none of them deletes. Before any of
that, a profile that joins on a machine with no owner key can't get one made beside it. They add each
other, hold a sealed conversation and a request, each through its own Signet, and an adapter started
with nothing but `SPLINT_AS` reaches the right one. One profile's token gets nothing from another's
Signet, and the default agent is as it was.

    python3 sim/profiles.py

Splint is installed from a release built here, as the official copy says.

Not shown: separate OS users, which is what keeps one person's agents from another's (profiles are
one person's agents, and any of them with a shell can read the others' files), hardware-held keys, a
real model or a person at the terminal: a script types the answers. No agent has network limits.
"""

import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import e2e
from adapter import McpAgent
from agent_signup import FINISH_LINE, OFFICIAL, OWN_LINE, SIGNET_HEARS_SECONDS, Signup, commands_in, for_the_owner, registered
from e2e import check, wait_until
from install import ARRIVE_SECONDS, MCP_LINE, Person
from request_driver import hours_from_now

AUTHORIZE_LINE = re.compile(r"splint authorize (\S+~\S+) (\S+)")
DOCUMENT = {"format": "pdf", "kind": "invoice"}
SECRET = "the spare key is under the blue pot"
OWNER_NAME = "nenye"
CONFIRM = "yes\n"
NAMED = f" --name {OWNER_NAME}"
PRIVATE_DIR = 0o700
PRIVATE_FILE = 0o600
SIGNET_LINE = re.compile(r"^Signet\s+(\w+)", re.M)
SECOND_COPY_SECONDS = 20
# Longer ago than anything this run started, as a file from before a reboot is.
BEFORE_THE_REBOOT_SECONDS = 24 * 60 * 60


@dataclass
class Profile(Person):
    """One of Nenye's agents, which `splint --as NAME` reaches. The default has no name."""

    profile: str = ""

    @property
    def dot(self) -> Path:
        root = self.home / ".splint"
        return root / "profiles" / self.profile if self.profile else root


def as_profile(nenye: Person, name: str) -> Profile:
    return Profile(name, nenye.home, nenye.env, exports=nenye.exports, profile=name)


def contacts_of(agent: Person) -> list[str]:
    return [contact["address"] for contact in agent.api("GET", "/v0/contacts")[1].get("contacts", [])]


def bodies(agent: Person) -> list[str]:
    return [message["untrusted"]["body"] for message in agent.inbox()]


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def state_at(agent: Person, request: str) -> str:
    return agent.api("GET", f"/v0/requests/{request}")[1].get("state", "")


class Machine:
    def __init__(self, signup: Signup) -> None:
        self.signup = signup
        self.walk = signup.walk
        self.host = signup.open_host
        # Installed from the release, as the official copy says, so profiles are shown in what ships.
        self.nenye = signup.clean_device("nenye")
        document = self.run(f"curl -fsSL {OFFICIAL}").stdout
        installed = self.run(commands_in(document, "curl -fsSL")[0])
        check("control: the release installs, with no Rust and no clone", installed.returncode == 0 and "after checking its checksum" in installed.stderr, installed.stderr)
        self.nenye.exports.append('export PATH="$HOME/.splint/bin:$PATH"')
        self.default = as_profile(self.nenye, "")
        self.agents: dict[str, Profile] = {}

    def run(self, command: str, stdin: str = "") -> subprocess.CompletedProcess:
        return self.walk.run_as("nenye", command, stdin)

    def sql(self, statement: str) -> str:
        container = json.loads((self.walk.people["hana"].dot / "host" / "host.json").read_text())["container"]
        done = subprocess.run(["docker", "exec", container, "psql", "-U", "splint", "-tAc", statement], capture_output=True, text=True, check=True)
        return done.stdout.strip()

    def stop(self) -> None:
        for name in self.agents:
            self.run(f"splint --as {name} stop")


def autos_running(machine: Machine) -> set[int]:
    """Every `splint auto` from Nenye's install, as the system lists them, whatever splint's own files say."""
    program = str(machine.nenye.home / ".splint" / "bin" / "splint")
    listed = subprocess.run(["ps", "-axww", "-o", "pid=,args="], capture_output=True, text=True, check=True).stdout
    found = (line.strip().partition(" ") for line in listed.splitlines())
    return {int(pid) for pid, _, args in found if args.strip() == f"{program} auto"}


def program_of(pid: int) -> str:
    return Path(subprocess.run(["ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True).stdout.strip()).name


def signet_pid_of(agent: Profile) -> int:
    """What the running Signet wrote, in its lock or, before there was one, its pid file."""
    for name in ("splint-signet.lock", "splint-signet.pid"):
        written = (agent.dot / "run" / name).read_text().strip() if (agent.dot / "run" / name).exists() else ""
        if written.isdigit():
            return int(written)
    return 0


def answers(agent: Profile) -> bool:
    return wait_until(lambda: agent.api("GET", "/v0/identity")[0] == 200, 1)


def auto_definitions(agent: Profile) -> list[Path]:
    """What a keeper would start this agent's `splint auto` from at login."""
    label = f"splint-auto.{agent.profile or 'default'}."
    return [*agent.home.glob(f"Library/LaunchAgents/{label}*"), *agent.dot.glob(f"run/{label}*.service")]


def no_owner_key_beside_an_agent_that_joined_first(machine: Machine) -> None:
    """Every profile runs as this user, so an owner key made in this machine's folder is within reach of all of them."""
    zed = as_profile(machine.nenye, "zed")
    joined = machine.run(f"splint --as zed join zed~{machine.host}")
    check("control: an agent joins on its own as a profile, with no owner key on this machine yet", joined.returncode == 0, joined.stderr)
    asked = for_the_owner(machine.run("splint --as zed ask-owner to work with my other agents").stdout)
    # Issue 707: with no owner key here, its person sets up their controls on their own computer.
    check("with no owner key on this machine, ask-owner gives the controls path, not splint authorize", f"splint controls {machine.host}" in asked and "splint authorize" not in asked, asked)
    command = f"splint authorize zed~{machine.host} {zed.api('GET', '/v0/identity')[1]['key']}"
    signed = machine.run(command + NAMED, CONFIRM)
    check("confirming it from this machine's own folder is refused", signed.returncode != 0 and "this is the machine" in signed.stderr, signed.stderr)
    check("and makes no owner key where that agent can read it", not (machine.default.dot / "owner").exists(), list(machine.default.dot.iterdir()))
    machine.run("splint --as zed stop")
    shutil.rmtree(zed.dot)
    # One still waiting for its owner has no install yet: only what it's waiting with, and its key.
    wren = as_profile(machine.nenye, "wren")
    waiting = machine.run(f"splint --as wren join wren~{machine.host} --owner-first")
    check("control: an agent joins as a profile and waits for its owner", waiting.returncode == 0 and not (wren.dot / "setup.json").exists(), waiting.stderr)
    command = AUTHORIZE_LINE.search(waiting.stdout).group(0)
    join_file, key_file = wren.dot / "join.json", wren.dot / "signet" / "agent.pub"
    saved = {path: path.read_bytes() for path in (join_file, key_file)}
    for what, gone in (("waiting for its owner", None), ("with only its prepared key", join_file), ("with only what it's waiting with", key_file)):
        for path, held in saved.items():
            path.write_bytes(held)
        if gone:
            gone.unlink()
        signed = machine.run(command, CONFIRM)
        check(f"confirming one {what} from this machine's own folder is refused", signed.returncode != 0 and "this is the machine" in signed.stderr, signed.stderr)
        check("and makes no owner key beside it either", not (machine.default.dot / "owner").exists(), list(machine.default.dot.iterdir()))
    machine.run("splint --as wren stop")
    shutil.rmtree(wren.dot)


def the_default_agent_first(machine: Machine) -> dict:
    ana = machine.default
    ana.address = f"ana~{machine.host}"
    done = machine.run(f"splint setup {ana.address} --owner-key-here")
    check("control: the default agent sets up as before", done.returncode == 0, done.stderr)
    ana.line = OWN_LINE.search(done.stdout).group(0)
    return {"setup": (ana.dot / "setup.json").read_bytes(), "owner": (ana.dot / "owner" / "owner.identity").read_text()}


def two_profiles_set_up_with_the_one_owner_key(machine: Machine) -> None:
    for name, command in (("one", "splint --as one setup one~{host} --owner-key-here"), ("two", "SPLINT_AS=two splint setup two~{host} --owner-key-here")):
        agent = as_profile(machine.nenye, name)
        agent.address = f"{name}~{machine.host}"
        done = machine.run(command.format(host=machine.host))
        check(f"{name} sets up as a profile", done.returncode == 0, done.stderr)
        agent.line = OWN_LINE.search(done.stdout).group(0)
        check(f"{name}'s token is in its own folder", str(agent.dot / "agent.curl") in done.stdout, done.stdout)
        machine.agents[name] = agent
    owner = machine.default.dot / "owner" / "owner.identity"
    for name in ("one", "two"):
        found = registered(machine.host, name)
        check(f"{name} acts for the same owner as the default", found is not None and found["owner_identity"] == owner.read_text().strip(), found)
        check(f"and no second owner key was made for {name}", not (machine.agents[name].dot / "owner").exists())


def a_third_joins_on_its_own_and_the_same_owner_confirms_it(machine: Machine) -> None:
    three = as_profile(machine.nenye, "three")
    machine.agents["three"] = three
    unnamed = machine.run(f"splint join three~{machine.host}")
    check("joining with no profile where an agent is set up says how another gets its own", unnamed.returncode != 0 and "--as <name> join" in unnamed.stderr, unnamed.stderr)
    joined = machine.run(f"splint --as three join three~{machine.host}")
    check("a third joins on its own as a profile", joined.returncode == 0, joined.stderr)
    # Bugs caught: an agent that joined as a profile told to check and listen as the default agent, so
    # what comes for it never wakes it.
    looks = re.search(r"(~/\.splint/bin/splint[^\n]*?) check prints", joined.stdout)
    check("it's told to check its own", looks is not None and looks.group(1).endswith("--as three"), joined.stdout)
    listens = re.search(r"(~/\.splint/bin/splint[^\n]*?) listen is that process", joined.stdout)
    check("and to listen as itself", listens is not None and listens.group(1).endswith("--as three"), joined.stdout)
    check("with a stand-in of its own, beside the owner's key", (three.dot / "owner").exists() and (machine.default.dot / "owner" / "owner.key").exists())
    listed = machine.run("splint profiles").stdout
    check("splint profiles says its controls aren't set up yet", re.search(r"three\s+three~\S+\s+Signet running\s+no controls set up yet", listed), listed)
    asked = machine.run("splint --as three ask-owner to work with my other agents")
    check("it asks its owner, who keeps an owner key on this machine, to confirm it here with splint authorize", asked.returncode == 0 and AUTHORIZE_LINE.search(for_the_owner(asked.stdout)) is not None, asked.stdout + asked.stderr)
    command = AUTHORIZE_LINE.search(for_the_owner(asked.stdout)).group(0)
    from_inside = machine.run(f"splint --as three {command.removeprefix('splint ')}{NAMED}", CONFIRM)
    check("its own stand-in can't confirm it", from_inside.returncode != 0, from_inside.stdout[-300:])
    signing = autos_running(machine)
    signed = machine.run(command + NAMED, CONFIRM)
    check("the owner's key confirms it, from the same machine", signed.returncode == 0, signed.stderr)
    # Issue 641: confirming another agent started signing on this device again, though its owner had
    # run splint stop, and defined it for a keeper to start at every login.
    check("with this device stopped, it says signing here is stopped, and how to start it", "stopped" in signed.stdout and "splint start" in signed.stdout, signed.stdout[-400:])
    check("and starts nothing that signs", autos_running(machine) <= signing, (autos_running(machine), signing))
    check("nor leaves anything for a keeper to start it with", not auto_definitions(machine.default), auto_definitions(machine.default))
    check("and warns that the key is within reach of the agents here", "Warning: your owner key is in" in signed.stderr + signed.stdout, signed.stderr)
    done = machine.run(f"splint --as three {FINISH_LINE.search(signed.stdout).group(0).removeprefix('splint ')}")
    check("the agent takes it up", done.returncode == 0, done.stderr)
    three.line = OWN_LINE.search(done.stdout).group(0)
    three.address = f"three.{OWNER_NAME}~{machine.host}"
    owner = (machine.default.dot / "owner" / "owner.identity").read_text().strip()
    found = registered(machine.host, f"three.{OWNER_NAME}")
    check("it acts for the same owner now", found is not None and found["owner_identity"] == owner, found)
    check("its stand-in is gone", not (three.dot / "owner").exists(), list(three.dot.iterdir()))
    check("and the owner's key every profile shares is still there", (machine.default.dot / "owner" / "owner.key").exists())


def the_owner_stops_this_device(machine: Machine) -> None:
    """Nenye stops the default agent, and with it what signs by her rules here. What still runs is the
    profiles' own."""
    signing = autos_running(machine)
    stopped = machine.run("splint stop")
    check("control: splint stop stops the default's Signet", stopped.returncode == 0 and not answers(machine.default), stopped.stderr)
    after = autos_running(machine)
    check("control: and what signs for this device", len(after) < len(signing) and after <= signing, (signing, after))


def splint_start_starts_signing_again(machine: Machine) -> None:
    signing = autos_running(machine)
    started = machine.run("splint start")
    check("splint start runs the default again", started.returncode == 0 and answers(machine.default), started.stderr)
    check("and what signs for this device", wait_until(lambda: autos_running(machine) - signing, 10), autos_running(machine))


def only_a_running_copy_counts(machine: Machine) -> None:
    """Issue 642: whether a service ran was read from a pid file and the program's name, which every
    profile's Signet shares. So with a pid file left naming another profile's Signet, status said it
    ran, start started nothing, and stop stopped the other profile's. And nothing kept out a second
    copy, so a stop left an orphan signing by the owner's rules."""
    one, two = machine.agents["one"], machine.agents["two"]
    stopped = machine.run("splint --as one stop")
    check("control: one's Signet stops", stopped.returncode == 0 and not answers(one), stopped.stderr)
    theirs = signet_pid_of(two)
    check("control: two's Signet is running, as that pid", program_of(theirs) == "splint-signet" and answers(two), theirs)
    # As a reboot leaves it when pids are reused: one's files name a live Signet, which is two's, and
    # were written before it started. A file written after a process started that names it can only
    # be that process's own, which is how splint still stops a Signet from an install before locks.
    written_before_the_reboot = time.time() - BEFORE_THE_REBOOT_SECONDS
    for name in ("splint-signet.lock", "splint-signet.pid"):
        (one.dot / "run" / name).write_text(f"{theirs}\n")
        os.utime(one.dot / "run" / name, (written_before_the_reboot, written_before_the_reboot))
    status = machine.run("splint --as one status")
    shown = SIGNET_LINE.search(status.stdout)
    check("one's status says its Signet is stopped", shown is not None and shown.group(1) == "stopped", status.stdout)
    machine.run("splint --as one stop")
    check("one's stop leaves two's Signet alone", program_of(theirs) == "splint-signet" and answers(two), program_of(theirs))
    started = machine.run("splint --as one start")
    check("and one's start runs one's own", started.returncode == 0 and answers(one) and answers(two), started.stderr)

    before = autos_running(machine)
    preamble = "\n".join(machine.nenye.exports)
    second = subprocess.Popen(
        ["bash", "-c", f"{preamble}\nexec splint --as one run-service splint-auto"], env=machine.nenye.env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        said, _ = second.communicate(timeout=SECOND_COPY_SECONDS)
    except subprocess.TimeoutExpired:
        said = "still running"
    check("a second copy of one's splint auto leaves at once, saying one runs", second.returncode == 0 and "already running" in said, said)
    check("so no second copy runs", autos_running(machine) <= before, (before, autos_running(machine)))
    by_hand = subprocess.Popen(
        ["bash", "-c", f"{preamble}\nexec splint --as one auto"], env=machine.nenye.env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        said, _ = by_hand.communicate(timeout=SECOND_COPY_SECONDS)
    except subprocess.TimeoutExpired:
        os.killpg(by_hand.pid, signal.SIGTERM)
        by_hand.wait()
        said = "still running"
    check("nor does one run by hand beside the service: it leaves at once, saying one runs", by_hand.returncode == 0 and "already running" in said, said)
    machine.run("splint --as one stop")
    left = autos_running(machine)
    check("and splint stop leaves none of one's running", left < before and len(before - left) == 1 and not left - before, (before, left))
    if second.poll() is None:
        os.killpg(second.pid, signal.SIGTERM)
        second.wait()
    # Bug caught: a `splint auto` run by hand that takes no lock, so stop and status can't see it, and
    # it goes on signing by the owner's rules after `splint stop`.
    hand = subprocess.Popen(
        ["bash", "-c", f"{preamble}\nexec splint --as one auto"], env=machine.nenye.env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    lock = one.dot / "run" / "splint-auto.lock"
    try:
        holds = wait_until(lambda: lock.exists() and lock.read_text().strip() == str(hand.pid), SECOND_COPY_SECONDS)
        check("control: one's splint auto run by hand holds its lock, as the one copy", holds, lock.read_text() if lock.exists() else "no lock")
        machine.run("splint --as one stop")
        check("and splint stop stops it", wait_until(lambda: hand.poll() is not None, SECOND_COPY_SECONDS), hand.poll())
    finally:
        if hand.poll() is None:
            os.killpg(hand.pid, signal.SIGTERM)
            hand.wait()
    started = machine.run("splint --as one start")
    check("control: one starts again", started.returncode == 0 and answers(one), started.stderr)


def each_is_its_own_agent(machine: Machine, before: dict) -> None:
    agents = [machine.default, *machine.agents.values()]
    sockets = [agent.socket for agent in agents]
    check("each agent has its own Signet socket", len(set(sockets)) == len(sockets), sockets)
    check("each answers as itself", [agent.api("GET", "/v0/identity")[1].get("address") for agent in agents] == [agent.address for agent in agents])
    one, two = machine.agents["one"], machine.agents["two"]
    status, _ = e2e.http_on_socket("GET", two.socket, "/v0/inbox", token=one.setup_file()["api_token"])
    check("one's token gets nothing from two's Signet", status == 401, status)
    status, _ = e2e.http_on_socket("GET", two.socket, "/v0/owner/quarantine", token=one.setup_file()["owner_token"])
    check("nor one's owner token", status == 401, status)
    check("control: two's own token does", two.api("GET", "/v0/inbox")[0] == 200)
    tokens = [token for agent in agents for token in agent.tokens()]
    check("no two agents share a token", len(set(tokens)) == len(tokens))
    root = machine.default.dot
    check("the profiles folder is only Nenye's", mode(root / "profiles") == PRIVATE_DIR, oct(mode(root / "profiles")))
    for agent in machine.agents.values():
        check(f"{agent.profile}'s folder is only Nenye's", mode(agent.dot) == PRIVATE_DIR and mode(agent.dot / "signet") == PRIVATE_DIR, oct(mode(agent.dot)))
        check(f"{agent.profile}'s token file too", mode(agent.dot / "agent.curl") == PRIVATE_FILE, oct(mode(agent.dot / "agent.curl")))
    listed = machine.run("splint profiles").stdout
    for agent in agents:
        name = agent.profile or "(default)"
        check(f"splint profiles lists {name}, running with controls set up", re.search(rf"{re.escape(name)}\s+{re.escape(agent.address)}\s+Signet running\s+controls set up", listed), listed)
    for bad in ("../owner", "Work", "-x"):
        done = machine.run(f"splint --as '{bad}' status")
        check(f"a profile name like {bad} is refused", done.returncode != 0 and "profile's name" in done.stderr, done.stderr)
    check("and made nothing", sorted(path.name for path in (root / "profiles").iterdir()) == ["one", "three", "two"])
    check("the default's own settings are as they were", (root / "setup.json").read_bytes() == before["setup"])
    check("and its owner", (root / "owner" / "owner.identity").read_text() == before["owner"])


def they_add_each_other(machine: Machine) -> None:
    agents = machine.agents
    for name, agent in agents.items():
        for other_name, other in agents.items():
            if other is agent:
                continue
            done = machine.run(f"splint --as {name} {other.line.removeprefix('splint ')}")
            check(f"{name}'s owner adds {other_name}", done.returncode == 0, done.stderr)
    for name, agent in agents.items():
        others = {other.address for other in agents.values() if other is not agent}
        check(f"{name}'s Signet has the other two", wait_until(lambda: others <= set(contacts_of(agent)), SIGNET_HEARS_SECONDS), contacts_of(agent))
    check("the default reaches none of them", contacts_of(machine.default) == [], contacts_of(machine.default))


def a_sealed_conversation_and_a_request(machine: Machine) -> None:
    one, two, three = (machine.agents[name] for name in ("one", "two", "three"))
    status, sent = one.api("POST", "/v0/send", {"to": two.address, "body": SECRET})
    check("one writes to two through its own Signet", status == 200, sent)
    check("two reads it through its own", wait_until(lambda: SECRET in bodies(two), ARRIVE_SECONDS), two.inbox())
    stored = machine.sql(f"SELECT envelope FROM inbox WHERE message_id = '{sent['message_id']}'")
    body = e2e.payload_of(stored)["body"] if stored else ""
    check("the host holds it sealed", body.startswith('{"sealed":') and "blue pot" not in body, body[:120])
    for sender, recipient, words in ((two, three, "Passing it on to you."), (three, one, "Got it, thanks.")):
        status, _ = sender.api("POST", "/v0/send", {"to": recipient.address, "body": words})
        check(f"{sender.profile} writes to {recipient.profile}", status == 200, status)
        check(f"and {recipient.profile} reads it", wait_until(lambda: words in bodies(recipient), ARRIVE_SECONDS), recipient.inbox())
    check("nothing reached the default", machine.default.inbox() == [], machine.default.inbox())

    # The two agents agree a type first. document/1 asks with words alone, so taking it on commits
    # neither to a number nobody named, which would wait for their owner.
    schema = json.loads((machine.nenye.dot / "examples" / "document-1.json").read_text())
    status, proposed = three.api("POST", "/v0/types", {"contact": one.address, "schema": schema})
    agreement = proposed.get("request", "")
    check("control: three proposes document/1 to one", status == 200 and wait_until(lambda: state_at(one, agreement) == "offered", ARRIVE_SECONDS), proposed)
    check("control: and one agrees it", one.api("POST", f"/v0/requests/{agreement}/accept", {})[0] == 200 and wait_until(lambda: state_at(three, agreement) == "completed", ARRIVE_SECONDS), state_at(three, agreement))
    status, opened = three.api("POST", "/v0/requests", {"contact": one.address, "type": "document/1", "terms": DOCUMENT, "deadline": hours_from_now(48)})
    check("three asks one for a document", status == 200, opened)
    request = opened.get("request", "")
    check("one's Signet has it", wait_until(lambda: state_at(one, request) == "offered", ARRIVE_SECONDS), state_at(one, request))
    check("one takes it on", one.api("POST", f"/v0/requests/{request}/accept", {})[0] == 200)
    check("three's Signet hears", wait_until(lambda: state_at(three, request) == "working", ARRIVE_SECONDS), state_at(three, request))
    check("and two knows nothing of it", two.api("GET", f"/v0/requests/{request}")[0] == 404)


def an_adapter_started_with_only_the_profile(machine: Machine) -> None:
    printed = machine.run("splint --as two connect").stdout
    server = json.loads(MCP_LINE.search(printed).group(0))["mcpServers"]["splint"]
    settings, script = server["env"], Path(server["args"][0])
    check("connect points at the adapter the release installed", script.is_relative_to(machine.nenye.home / ".splint"), script)
    check("connect gives a profile's runtime its name, and nothing to keep in step", settings == {"SPLINT_AS": "two"}, settings)
    check("and says a program that runs splint needs it", "SPLINT_AS=two" in printed, printed)
    adapter = McpAgent("", "", {**settings, "HOME": str(machine.nenye.home)}, script)
    try:
        adapter.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "sim", "version": "0"}})
        names = sorted(contact["name"] for contact in adapter.tool("contacts"))
        check("the adapter reaches two's Signet, with two's contacts", names == ["one", "three.nenye"], names)
    finally:
        adapter.finish()
    nobody = McpAgent("", "", {"SPLINT_AS": "nobody", "HOME": str(machine.nenye.home)}, script)
    try:
        nobody.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "sim", "version": "0"}})
        failed, text = nobody.tool_text("contacts")
        check("one for a profile that hasn't joined starts, and reaches no other agent's Signet", failed and "join" in text, text)
    finally:
        nobody.finish()
    refused = McpAgent("", "", {"SPLINT_AS": "two", "SPLINT_SIGNET_URL": "http://127.0.0.1:1", "HOME": str(machine.nenye.home)}, script)
    said = refused.finish()
    check("an adapter refuses a profile and a Signet's address at once", refused.process.returncode != 0 and "not both" in said and "SPLINT_SIGNET_URL" in said, said)
    default = json.loads(MCP_LINE.search(machine.run("splint connect").stdout).group(0))["mcpServers"]["splint"]["env"]
    check("the default's settings name nothing to keep in step either", default == {}, default)


def main() -> None:
    work = e2e.short_scratch("splint-profiles-")
    signup = Signup(work)
    machine = Machine(signup)
    try:
        no_owner_key_beside_an_agent_that_joined_first(machine)
        before = the_default_agent_first(machine)
        two_profiles_set_up_with_the_one_owner_key(machine)
        only_a_running_copy_counts(machine)
        the_owner_stops_this_device(machine)
        a_third_joins_on_its_own_and_the_same_owner_confirms_it(machine)
        splint_start_starts_signing_again(machine)
        each_is_its_own_agent(machine, before)
        they_add_each_other(machine)
        a_sealed_conversation_and_a_request(machine)
        an_adapter_started_with_only_the_profile(machine)
        check("the default's settings are still as they were", (machine.default.dot / "setup.json").read_bytes() == before["setup"])
    finally:
        machine.stop()
        signup.walk.stop_everything()
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall profile checks passed", flush=True)


if __name__ == "__main__":
    main()

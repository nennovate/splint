#!/usr/bin/env python3
"""Two agents agree a time across two hosts, and it completes with nobody touching anything.

Ana's agent joins one real host and Ben's another, each on its own under a temporary name, and each
person sets up their controls by its link, on their own computer, with its defaults: Go ahead, contacts
only, sealed, and a delegation that names no kind, which names their agent under their own name, as
`ana.ana`. From then on no person touches anything. The agents become contacts by invite, agree
`time/1`, the example kind no owner signs, and Ben's agent accepts a time Ana's offered and delivers,
which completes it on both sides. Then the same two agree `meeting/1`, which both owners sign, and
it waits for them: a kind's `sign` is what makes people wait, not the owner's level.

    python3 sim/agreed_time.py

The owner's side is the script in sim/owner_by_link.py standing in for Splint on each person's
computer: it signs the bytes "Setting up your controls" in docs/protocol.md defines, with the rules the
owner page signs first, copied here, and the real hosts and Signets check all of it. Its key is a
software key file, so no hardware-held key is shown. Homes stand for devices
under one OS user, and no agent has network limits. The two hosts list each other as peers.
"""

import json
import shutil
import sys
from pathlib import Path

import e2e
from agent_join import contacts_of
from agent_signup import ROOM_FOR_A_RUN
from e2e import check, wait_until
from install import Person, Walkthrough
from owner_by_link import FileKeyOwner, approved_by_link
from request_driver import hours_from_now

# What a step takes to cross from one host to the other and be applied by the reading Signet.
ARRIVE_SECONDS = 60
# Long enough for a device running `splint auto`, which looks every 15 seconds, to have signed.
NOBODY_SIGNS_SECONDS = 40
TIME = "time/1"
MEETING = "meeting/1"
# The first rules an owner's side signs for an agent that asked by its link: contacts the agent agrees
# by itself talk and agree kinds at once, at Go ahead.
PAGE_FIRST_RULES = {
    "paused": False,
    "reach": {
        "inbound": {"from": "contacts", "filter": {"owners": [], "hosts": [], "past": False}, "types": [], "text": False, "strangers": "quarantine"},
        "outbound": "contacts",
        "agreed": {"types": [], "text": True, "agree_types": True},
    },
    "permissions": {"level": "auto_within_limits", "actions_per_day": 250, "caps": {}},
    "changes": {"owner": "ask", "key": "continue", "signet": "continue", "host": "continue", "revocation": "continue", "declared": "continue"},
    "sealing": "sealed",
    "contacts": [],
    "invites": [],
    "limits": {"new_requests_per_contact_per_day": 20, "open_requests_per_contact": 3, "open_approvals": 10, "new_from_others_per_day": 250, "texts_per_contact_per_day": 100},
}


class Hosts:
    """Two real hosts, open to anyone joining, each listing the other as a peer."""

    def __init__(self, work: Path) -> None:
        self.work = work
        self.postgres = e2e.Postgres()
        self.postgres.start()
        ports = {name: e2e.free_port() for name in ("a", "b")}
        self.domain = {name: f"127.0.0.1:{port}" for name, port in ports.items()}
        peers = ",".join(self.domain.values())
        self.processes = []
        for name in ("a", "b"):
            process = e2e.Process("host", f"host-{name}", work, {
                "SPLINT_DOMAIN": self.domain[name],
                "SPLINT_LISTEN": self.domain[name],
                "SPLINT_DATABASE_URL": self.postgres.create_database(f"host_{name}"),
                "SPLINT_HOST_KEY_FILE": str(work / f"host-{name}.key"),
                "SPLINT_PEERS": peers,
                "SPLINT_OPEN_SIGNUP": "yes",
                **e2e.PLAIN_HTTP_FOR_TESTS,
                **ROOM_FOR_A_RUN,
            })
            process.start()
            self.processes.append(process)
        for name in ("a", "b"):
            up = lambda: e2e.http("GET", f"http://{self.domain[name]}/.well-known/splint/host")[0] == 200  # noqa: E731
            check(f"control: host {name} is up", wait_until(up, 30))

    def stop(self) -> None:
        for process in self.processes:
            process.kill_hard()
        self.postgres.stop()


def set_up_by_link(walk: Walkthrough, name: str, host: str, owner: FileKeyOwner) -> Person:
    """The agent joins on its own, and its person sets up their controls by its link with one approval,
    taking the defaults."""
    person = walk.new_person(name)
    person.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
    person.env["SPLINT_COMPUTER_PORT"] = str(e2e.free_port())
    done = walk.run_as(name, f"splint join {name} {host} --json")
    check(f"control: {name}'s agent joins on its own", done.returncode == 0, done.stdout + done.stderr)
    # Under a temporary name its own Splint made up, which it says.
    person.address = json.loads(done.stdout or "{}").get("address", "")
    return approved_by_link(walk, person, owner, first_rules=PAGE_FIRST_RULES)


def state_at(person: Person, request: str) -> str:
    return person.api("GET", f"/v0/requests/{request}")[1].get("state", "")


def become_contacts(ana: Person, ben: Person) -> None:
    status, invited = ana.api("POST", "/v0/invites", {"to": ben.address})
    check("control: ana's agent invites ben's", status == 200, invited)
    accept = lambda: ben.api("POST", f"/v0/invites/{ana.address}/accept", {})[0] == 200  # noqa: E731
    check("control: ben's agent accepts, once the invite arrives", wait_until(accept, ARRIVE_SECONDS))
    check("control: they're contacts on both sides at once", wait_until(lambda: ben.address in contacts_of(ana) and ana.address in contacts_of(ben), ARRIVE_SECONDS), (contacts_of(ana), contacts_of(ben)))


def agree(by: Person, to: Person, name: str) -> None:
    status, proposed = by.api("POST", "/v0/types", {"contact": to.address, "schema": e2e.example_schema(name)})
    check(f"control: {by.name}'s agent proposes {name}", status == 200, proposed)
    request = proposed.get("request", "")
    check(f"control: {to.name}'s agent accepts it", wait_until(lambda: to.api("POST", f"/v0/requests/{request}/accept", {})[0] == 200, ARRIVE_SECONDS))
    check(f"control: {name} is agreed on both sides", wait_until(lambda: state_at(by, request) == "completed", ARRIVE_SECONDS), state_at(by, request))


def opened(ana: Person, ben: Person, name: str, terms: dict) -> str:
    status, made = ana.api("POST", "/v0/requests", {"contact": ben.address, "type": name, "deadline": hours_from_now(72), "terms": terms})
    check(f"control: ana's agent opens a {name}", status == 200 and bool(made.get("request")), made)
    request = made.get("request", "")
    check(f"control: ben's agent sees the {name}", wait_until(lambda: state_at(ben, request) == "offered", ARRIVE_SECONDS), state_at(ben, request))
    slot = ben.api("GET", f"/v0/requests/{request}")[1]["terms"]["slots"][0]
    status, moved = ben.api("POST", f"/v0/requests/{request}/accept", {"pick": {"start": slot}})
    check(f"control: ben's agent accepts a time it offered for the {name}", status == 200, moved)
    return request


def a_time_no_owner_signs_completes_with_nobody_touching(ana: Person, ben: Person, owners: list[FileKeyOwner]) -> None:
    """Bug caught: a first request between two agents whose people set up controls waiting on someone's
    approval, as the meeting the guides led with did."""
    approvals = [owner.approvals for owner in owners]
    agree(ana, ben, TIME)
    request = opened(ana, ben, TIME, {"duration_min": 30, "mode": "video", "slots": [hours_from_now(24), hours_from_now(25)]})
    check("ben's side is working on it, with nothing waiting for his person", wait_until(lambda: state_at(ben, request) == "working", ARRIVE_SECONDS), state_at(ben, request))
    status, moved = ben.api("POST", f"/v0/requests/{request}/deliver", {"result": {"kept": "calendar"}})
    check("ben's agent delivers, saying it put the time on the calendar", status == 200, moved)
    check("which completes it on his side", wait_until(lambda: state_at(ben, request) == "completed", ARRIVE_SECONDS), state_at(ben, request))
    check("and on ana's, across the two hosts", wait_until(lambda: state_at(ana, request) == "completed", ARRIVE_SECONDS), state_at(ana, request))
    view = ana.api("GET", f"/v0/requests/{request}")[1]
    picked = (view.get("pick") or {}).get("start")
    check("with the time ben's agent picked and what it did with it", view.get("result") == {"kept": "calendar"} and picked in (view.get("terms") or {}).get("slots", []), view)
    check("and no person touched anything from setting up on", [owner.approvals for owner in owners] == approvals, ([owner.approvals for owner in owners], approvals))
    check("nor was asked", not view.get("waiting_for_owner") and not ben.api("GET", f"/v0/requests/{request}")[1].get("waiting_for_owner"), view)


def a_meeting_both_sign_waits_for_both(ana: Person, ben: Person, owners: list[FileKeyOwner]) -> None:
    """The control: the same people and settings, and a kind whose `sign` is both. Bug caught: an
    owner's level, or their delegation that names no kind, signing a meeting for them."""
    approvals = [owner.approvals for owner in owners]
    agree(ben, ana, MEETING)
    request = opened(ana, ben, MEETING, {"duration_min": 30, "mode": "video", "purpose": "intro", "slots": [hours_from_now(26), hours_from_now(27)]})
    check("control: the meeting is accepted on ana's side", wait_until(lambda: state_at(ana, request) == "accepted", ARRIVE_SECONDS), state_at(ana, request))
    check("and waits there for each person's own yes, which nothing gives for them", not wait_until(lambda: state_at(ana, request) != "accepted" or state_at(ben, request) != "accepted", NOBODY_SIGNS_SECONDS), (state_at(ana, request), state_at(ben, request)))
    view = ana.api("GET", f"/v0/requests/{request}")[1]
    check("ana's agent reads that it waits for her yes, still to come", bool(view.get("waiting_for_owner")) and (view.get("signatures") or {}).get("yours") == "to_come", view)
    check("control: still with no approval", [owner.approvals for owner in owners] == approvals)


def main() -> None:
    e2e.build()
    work = e2e.short_scratch("splint-time-")
    hosts = Hosts(work)
    walk = Walkthrough(work, None, None)
    try:
        owners = [FileKeyOwner(work / f"{name}-device") for name in ("ana", "ben")]
        ana = set_up_by_link(walk, "ana", hosts.domain["a"], owners[0])
        ben = set_up_by_link(walk, "ben", hosts.domain["b"], owners[1])
        become_contacts(ana, ben)
        a_time_no_owner_signs_completes_with_nobody_touching(ana, ben, owners)
        a_meeting_both_sign_waits_for_both(ana, ben, owners)
    finally:
        walk.stop_everything()
        hosts.stop()
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall agreed-time checks passed", flush=True)


if __name__ == "__main__":
    main()

"""An owner who signs on their own computer, played by a script, for sims that need one answering an
agent's ask for its controls without driving Splint on the computer itself.

Owners sign only on their own computers (Nenye, 2026-11-21): an agent asks by its link, and the owner's
side signs the binding, the first rules and a delegation to the agent's delegate key, with the owner's
own `alg` (ES256 here, or WA256 for sim/owner_api.py's owner whose ID is a passkey from before), and leaves
the answer at the agent's host where the ask's ID says, with a MAC by it, as "An answer to an ask for
controls" in docs/protocol.md has it. Here the owner's key is a file key, and its sessions are file keys
too. sim/agent_asks.py and sim/asked_by_link.py drive Splint on the computer itself.

An agent joins on its own under a temporary name, as `ana-7k3p2a`, and names its person in its ask with
`splint controls --name`. The binding names it under the owner's name at its host, as `ana.jo`: the one
they have there already, or the one the ask names.
"""

import hashlib
import hmac
import json
import os
import re
import time
from pathlib import Path

import e2e
from agent_signup import Signup
from e2e import check, compact_json, decode, encode, http, wait_until
from install import Person

DAY = 86400
FIRST_RULES = {
    "paused": False,
    "reach": {"inbound": {"from": "contacts", "filter": {"owners": [], "hosts": [], "past": False}, "types": [], "text": False, "strangers": "quarantine"}, "outbound": "contacts"},
    "permissions": {"level": "auto_within_limits", "actions_per_day": 50, "caps": {}},
    "changes": {"owner": "ask", "key": "ask", "signet": "continue", "host": "continue", "revocation": "hold", "declared": "continue"},
    "sealing": "sealed",
    "contacts": [],
    "invites": [],
    "limits": {"new_requests_per_contact_per_day": 3, "open_requests_per_contact": 3, "open_approvals": 10, "new_from_others_per_day": 50, "texts_per_contact_per_day": 20},
}
TAKEN_UP_SECONDS = 60


def signing_input(alg: str, typ: str, payload: dict) -> str:
    return f"{encode(compact_json({'alg': alg, 'typ': typ}))}.{encode(compact_json(payload))}"


class FileKeyOwner:
    """An owner ID around a key file, with a backup beside it. It counts each approval its person gives.
    `name` is the name its person goes by, which their agents are named under: by default the folder's,
    as `ana` for `ana-device`."""

    alg = "ES256"

    def __init__(self, folder: Path, name: str = "") -> None:
        folder.mkdir(parents=True)
        self.key = folder / "owner.key"
        self.identity, self.id = e2e.new_identity(self.key)
        self.backup = e2e.backup_of(self.key)
        self.approvals = 0
        self.name = name or folder.name.removesuffix("-device").removesuffix("-owner")

    def sign(self, typ: str, payload: dict) -> str:
        self.approvals += 1
        signed = signing_input("ES256", typ, payload)
        return f"{signed}.{encode(e2e.es256(self.key, signed.encode()))}"

    def sign_together(self, inputs: list[str]) -> list[str]:
        """One approval over several signing inputs, each signed on its own, as a file key signs."""
        self.approvals += 1
        return [f"{signed}.{encode(e2e.es256(self.key, signed.encode()))}" for signed in inputs]


class Session:
    """A key the owner's side holds, which the owner signs for one host, as "Owner API" says. It reads."""

    def __init__(self, owner: FileKeyOwner, host: str, lasts: int = 12 * 3600) -> None:
        self.owner = owner
        self.key = owner.key.with_name(f"session-{os.urandom(6).hex()}.key")
        point = e2e.new_key(self.key)
        now = int(time.time())
        self.compact = owner.sign("splint-owner-session", {"v": 1, "owner": owner.id, "key": point, "host": host, "issued_at": now, "expires_at": now + lasts})

    def sign(self, typ: str, payload: dict) -> str:
        return e2e.sign_jws(self.key, typ, compact_json(payload))


def ask_kept_at(ask_id: str) -> str:
    return hashlib.sha256(b"splint ask kept at v1" + bytes.fromhex(ask_id)).hexdigest()[:32]


def ask_mac(ask_id: str, owner_id: str) -> str:
    return hmac.new(bytes.fromhex(ask_id), b"splint ask answer v1" + owner_id.encode(), "sha256").hexdigest()


def as_json(done) -> dict:
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {}


def joined_on_its_own(signup: Signup, name: str) -> Person:
    person = signup.device(name)
    # Its ask goes to Splint on its own machine too, which signs with a key file here and asks nobody.
    person.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
    person.env["SPLINT_COMPUTER_PORT"] = str(e2e.free_port())
    done = signup.walk.run_as(name, f"splint join {name} {signup.open_host} --json")
    joined = as_json(done)
    check(f"control: {name} joins on its own", done.returncode == 0 and joined.get("state") == "no_controls_yet", done.stdout + done.stderr)
    check(f"{name} is given its person's way to their controls", (joined.get("controls") or {}).get("set") is False and bool((joined.get("controls") or {}).get("open")), joined)
    # A temporary name its own Splint made up, which it says.
    person.address = joined.get("address", "")
    return person


def identity_of(person: Person) -> dict:
    return person.api("GET", "/v0/identity")[1]


def word_of(name: str) -> str:
    """The word an agent's name is made from: its handle before any owner part, less a temporary name's
    code, as `ana` for `ana-7k3p2a` and for `ana.jo`."""
    handle = name.split(".")[0]
    word, _, code = handle.rpartition("-")
    temporary = bool(word) and re.fullmatch(r"[a-z2-7]{6}", code) is not None and any(char in "234567" for char in code)
    return word if temporary else handle


def asks_for_controls(walk, person: Person, name: str) -> dict:
    """What the agent runs, naming the name its person goes by, and what its Signet holds of the ask: its
    ID, the delegate key it names and the name."""
    asked = as_json(walk.run_as(person.name, f"splint controls --name {name} --json"))
    check(f"control: {person.name} asks for its controls, and waits", asked.get("status") == "waiting" and bool(asked.get("computer_link")), asked)
    _, held = person.api("GET", f"/v0/asks/{asked.get('id', '')}")
    controls = next((change for change in held.get("changes", []) if change.get("change") == "controls"), {})
    return {"id": asked.get("id", ""), "delegate": controls.get("delegate", ""), "owner_part": controls.get("owner_part", "")}


def named_address(owner, address: str, asked: dict) -> str:
    """Where the owner's side names the agent: under the owner's name at its host, the one they have
    there, as the host says, or the one the ask names."""
    name, agent_host = address.split("~")
    status, found = http("GET", f"http://{agent_host}/.well-known/splint/owners/{owner.id}/name")
    owners_name = found.get("name", "") if status == 200 else asked.get("owner_part", "")
    return f"{word_of(name)}.{owners_name}~{agent_host}" if owners_name else address


def answer_ask(owner, person: Person, asked: dict, first_rules: dict | None = None) -> tuple[int, dict]:
    """What the owner's side does on their yes: signs the binding, the first rules and a delegation with
    one approval, and leaves them at the agent's host where its ask's ID says."""
    who = identity_of(person)
    identity, address = who["identity"], named_address(owner, person.address, asked)
    agent = "splint1" + hashlib.sha256(decode(identity.split("~")[0])).hexdigest()
    agent_host = address.split("~")[1]
    backup = owner.key.with_name(f"agent-backup-{asked['id']}.key")
    backup_point = e2e.new_key(backup)
    seq, now = int(time.time() * 1000), int(time.time())
    binding = signing_input(owner.alg, "splint-binding", {"v": 2, "owner": owner.id, "agent": agent, "address": address, "seq": seq, "issued_at": now})
    vouch = signing_input("ES256", "splint-binding-vouch", {"v": 2, "agent": agent, "owner": owner.id, "backup": backup_point, "keys": e2e.first_keys_of(identity)})
    delegation = signing_input(owner.alg, "splint-delegation", {"v": 1, "owner": owner.id, "agent": agent, "delegate": asked["delegate"], "may": ["approve_within_caps"], "level": "auto_within_limits", "caps": {}, "actions_per_day": 50, "seq": seq, "issued_at": now, "expires_at": now + 365 * DAY})
    rules = {"v": 1, "owner": owner.id, "agent": agent, "seq": seq, "issued_at": now}
    first = first_rules or FIRST_RULES
    rules |= {key: first[key] for key in ("paused", "reach", "permissions", "changes", "sealing")} | {"delegation": hashlib.sha256(delegation.encode()).hexdigest()}
    rules |= {key: first[key] for key in ("contacts", "invites", "limits")}
    signed_binding, signed_rules, signed_delegation = owner.sign_together([binding, signing_input(owner.alg, "splint-rules", rules), delegation])
    signed_vouch = f"{vouch}.{encode(e2e.es256(backup, vouch.encode()))}"
    reply = {"v": 1, "owner_identity": owner.identity, "commitment": hashlib.sha256(decode(backup_point)).hexdigest(), "binding": f"{signed_binding}~{signed_vouch}", "rules": signed_rules, "delegation": signed_delegation}
    kept = {"agent_key": e2e.first_keys_of(identity), "answer": encode(compact_json(reply)), "kept_at": ask_kept_at(asked["id"]), "ask_mac": ask_mac(asked["id"], owner.id)}
    return http("PUT", f"http://{agent_host}/v0/join-answers", kept)


def set_up_controls(signup: Signup, owner, name: str, first_rules: dict | None = None) -> Person:
    """An agent joins on its own, asks by its link, and the owner it reached approves once."""
    return approved_by_link(signup.walk, joined_on_its_own(signup, name), owner, first_rules)


def approved_by_link(walk, agent: Person, owner, first_rules: dict | None = None) -> Person:
    """An agent that joined asks by its link, naming its person, and the owner it reached approves once.
    From then on it's at its name under theirs."""
    asked = asks_for_controls(walk, agent, owner.name)
    named = named_address(owner, agent.address, asked)
    kept = answer_ask(owner, agent, asked, first_rules)
    check(f"control: {agent.name}'s person's answer is kept at its host", kept[0] == 200, kept)
    taken = lambda: as_json(walk.run_as(agent.name, f"splint ask {asked['id']} --json")).get("status") == "done"  # noqa: E731
    check(f"control: {agent.name} takes up its controls by itself, under its person's name", wait_until(lambda: taken() and identity_of(agent).get("address") == named, TAKEN_UP_SECONDS) and identity_of(agent).get("owner_confirmed") is True, (named, identity_of(agent)))
    agent.address = named
    return agent

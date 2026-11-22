#!/usr/bin/env python3
"""A contact's own host is the attacker: it shows only what it likes, of what's really been signed.

Nothing here forges a signature. The contact on the hostile host has its keys held by this script, so it
signs bindings, releases, recoveries and histories by hand, in whatever order suits an attacker, and
its host relays what it chooses. The reader is the real host and Signet, and its agent is assumed fully
fooled, so what's checked is only what reaches that agent, and what its owner gets to decide.
"""

import hashlib
import json
import sys
import time
from pathlib import Path

import e2e
from e2e import accepted, check, compact_json, decode, http, new_identity, new_key, new_owner, public_of, sign_jws, wait_until
from identity_recovery import recovered_on_a_new_device

# Long enough for the reader's Signet to have pulled twice, so what isn't there isn't on its way.
SETTLE_SECONDS = 2.0


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def signed_part_hash(compact: str) -> str:
    return sha(compact.rsplit(".", 1)[0].encode())


def hostile_peer(net: e2e.Network) -> tuple[e2e.ScriptedPeer, Path]:
    """A listed peer with a key this run holds, which answers lookups from `answers` and nothing else."""
    peer, key = net.scripted_peer, net.work / "hostile-home.key"
    if not key.exists():
        public = new_key(key)
        peer.answers = {}

        def respond(path: str, _sent: bytes) -> tuple[int, dict, bytes]:
            if path == "/.well-known/splint/host":
                return 200, {}, json.dumps({"domain": peer.domain, "key": public}).encode()
            if path in peer.answers:
                return 200, {}, json.dumps(peer.answers[path]).encode()
            return 404, {}, b"{}"

        peer.respond = respond
    return peer, key


class Contact:
    """An agent whose keys this run holds, on the hostile host."""

    def __init__(self, net: e2e.Network, name: str, owner: e2e.Owner, peer: tuple[object, Path] | None = None) -> None:
        self.net, self.name, self.owner = net, name, owner
        self.peer, self.peer_key = peer or hostile_peer(net)
        self.key = net.work / f"{name}.key"
        self.identity, self.id = new_identity(self.key)
        self.backup = e2e.backup_of(self.key)
        self.first_event = decode(self.identity.split("~")[0])
        self.owners = {owner.id: owner.identity}
        self.events: list[str] = []
        self.head = sha(self.first_event)
        self.agent_recoveries = 0
        self.address = f"{name}~{self.peer.domain}"
        self.binding = self.make_binding(owner, self.address)

    def make_binding(self, owner: e2e.Owner, address: str, release: str | None = None) -> str:
        time.sleep(0.002)
        now = int(time.time())
        half = sign_jws(owner.key, "splint-binding", compact_json(
            {"v": 2, "owner": owner.id, "agent": self.id, "address": address, "seq": int(time.time() * 1000), "issued_at": now}))
        vouch = sign_jws(self.backup, "splint-binding-vouch", compact_json(
            {"v": 2, "agent": self.id, "owner": owner.id, "backup": public_of(self.backup), "keys": e2e.agent_keys(self.key)}))
        return accepted(f"{half}~{vouch}", self.key, release)

    def sign_event(self, change: dict, owner_id: str | None = None) -> None:
        compact = sign_jws(self.key, "splint-change", compact_json({
            "v": 1, "id": self.id, "seq": len(self.events) + 1, "prev": self.head,
            "agent_recoveries": self.agent_recoveries, "owner": owner_id or self.owner.id,
            "owner_recoveries": 0, "issued_at": int(time.time()), "change": change,
        }))
        self.events.append(compact)
        self.head = signed_part_hash(compact)

    def bound(self) -> None:
        self.sign_event({"kind": "bound", "binding": self.binding})

    def recover(self, new_key_path: Path | None = None) -> str:
        """A real recovery by this agent's own backup, naming a new key if there's one, and a new backup."""
        next_backup = self.net.work / f"{self.name}-backup-{self.agent_recoveries + 1}.key"
        parts = self.identity.split("~")
        statement = sign_jws(self.backup, "splint-recovery", compact_json({
            "v": 2, "id": self.id, "seq": len(parts),
            "prev": signed_part_hash(parts[-1]) if len(parts) > 1 else sha(self.first_event),
            "backup": public_of(self.backup), "key": new_key(new_key_path) if new_key_path else public_of(self.key),
            "seal": e2e.seal_public_of(new_key_path or self.key),
            "recovery": {"rule": "backup_key", "commitment": sha(decode(new_key(next_backup)))},
            "issued_at": int(time.time()),
        }))
        self.identity = f"{self.identity}~{statement}"
        self.backup = next_backup
        self.agent_recoveries += 1
        if new_key_path:
            self.key = new_key_path
        return statement

    def replace_key(self) -> None:
        statement = self.recover(self.net.work / f"{self.name}-key-{self.agent_recoveries + 1}.key")
        self.binding = self.make_binding(self.owner, self.address)
        self.sign_event({"kind": "key", "whose": "agent", "head": signed_part_hash(statement)})

    def transfer_to(self, new: e2e.Owner, *, recovering: bool = True) -> None:
        """A real transfer, which the old owner released. The event goes in the history either way."""
        release = sign_jws(self.owner.key, "splint-release", compact_json(
            {"v": 1, "owner": self.owner.id, "agent": self.id, "to": new.id, "seq": int(time.time() * 1000), "issued_at": int(time.time())}))
        time.sleep(0.01)
        if recovering:
            statement = self.recover()
            self.sign_event({"kind": "key", "whose": "agent", "head": signed_part_hash(statement)})
        self.binding = self.make_binding(new, self.address, release)
        self.owners[new.id] = new.identity
        self.sign_event({"kind": "owner", "binding": self.binding, "previous_owner_recoveries": 0}, owner_id=new.id)
        self.owner = new

    def revoke(self) -> None:
        release = sign_jws(self.owner.key, "splint-release", compact_json(
            {"v": 1, "owner": self.owner.id, "agent": self.id, "to": None, "seq": int(time.time() * 1000), "issued_at": int(time.time())}))
        self.sign_event({"kind": "revoked", "release": release})

    def moved_to(self, address: str) -> None:
        self.binding = self.make_binding(self.owner, address)
        self.sign_event({"kind": "host", "binding": self.binding})

    def history(self, events: list[str] | None = None) -> dict:
        return {"identity": self.identity, "owners": list(self.owners.values()), "events": self.events if events is None else events}

    def notice(self, recipient: str, events: list[str] | None = None) -> str:
        body = json.dumps({"step": "change_notice", "history": self.history(events)}, separators=(",", ":"))
        return e2e.signed_envelope(self.key, self.id, recipient, body)

    def relay(self, envelope: str, to: str, owner: e2e.Owner | None = None, binding: str | None = None) -> tuple[int, dict]:
        domain = self.net.domain[self.net.home[to]]
        return http("POST", f"http://{domain}/v0/deliver", {
            "envelope": envelope, "sender_identity": self.identity, "from_host": self.peer.domain,
            "proof": self.net.host_proof(self.peer_key, envelope, self.peer.domain, domain),
            "sender_owner_identity": (owner or self.owner).identity,
            "sender_binding": binding if binding is not None else self.binding,
        })

    def say(self, words: str, to: str, owner: e2e.Owner | None = None, binding: str | None = None) -> tuple[int, dict]:
        return self.relay(e2e.signed_envelope(self.key, self.id, self.net.ids[to], words), to, owner, binding)

    def answer_lookups(self, with_history: bool = False) -> None:
        self.peer.answers[f"/.well-known/splint/agents/{self.name}"] = {
            "agent_id": self.id, "identity": self.identity, "owner_identity": self.owner.identity, "binding": self.binding,
            "history": json.dumps(self.history(), separators=(",", ":")) if with_history else "",
        }


def entry(contact: Contact, label: str) -> dict:
    return {"agent": contact.id, "address": contact.address, "label": label, "status": "allowed",
            "types": e2e.EXAMPLE_TYPES, "text": True, "pinned_by": "owner"}


def sign_and_put(net: e2e.Network, agent: str, contacts: list[dict], **draft) -> None:
    rules = net.owners[agent].sign("rules", "--agent", net.ids[agent], stdin=json.dumps(e2e.rules_draft(contacts, **draft)))
    status, answer = net.put_rules(agent, rules)
    if status != 200:
        raise RuntimeError(f"{agent}'s rules weren't taken: {answer}")


def changes_page(net: e2e.Network, agent: str) -> list[dict]:
    return http("GET", f"http://127.0.0.1:{net.signet_port[agent]}/v0/owner/changes", token=net.owners[agent].token)[1]["changes"]


def standing_of(net: e2e.Network, agent: str, contact: Contact) -> str | None:
    return next((one["standing"] for one in changes_page(net, agent) if one["contact"] == contact.id), None)


def accept_changes(net: e2e.Network, agent: str, contact: Contact) -> tuple[int, dict]:
    head = next(one["head"] for one in changes_page(net, agent) if one["contact"] == contact.id)
    signed = net.owners[agent].sign("accept-change", "--agent", net.ids[agent], "--contact", contact.id, "--head", head)
    return net.agent(agent, "POST", "/v0/owner/changes/accept", {"acceptance": signed})


def shown(net: e2e.Network, agent: str, words: str) -> bool:
    return words in net.bodies(agent)


def never_shown(net: e2e.Network, agent: str, words: str) -> bool:
    deadline = time.time() + SETTLE_SECONDS
    while time.time() < deadline:
        if shown(net, agent, words):
            return False
        time.sleep(0.2)
    return True


def waits_on_the_host(net: e2e.Network, agent: str, message: str) -> bool:
    return net.postgres.sql(f"host_{net.home[agent]}", f"SELECT count(*) FROM inbox WHERE message_id = '{e2e.message_id_of(message)}' AND NOT acked") == "1"


def host_says_acts_for(net: e2e.Network, agent: str, contact: Contact) -> str:
    return net.postgres.sql(f"host_{net.home[agent]}", f"SELECT owner FROM reached WHERE agent = '{net.ids[agent]}' AND peer = '{contact.id}'")


def signet_says_acts_for(net: e2e.Network, agent: str, contact: Contact) -> str:
    saved = net.work / agent / "reached.json"
    return json.loads(saved.read_text()).get(contact.id, {}).get("owner", "") if saved.exists() else ""


def in_the_agents_list(net: e2e.Network, agent: str, contact: Contact) -> bool:
    return any(one["agent"] == contact.id for one in net.agent(agent, "GET", "/v0/contacts")[1]["contacts"])


def put_on_the_inbox(net: e2e.Network, agent: str, contact: Contact, envelope: str, owner: e2e.Owner, binding: str) -> None:
    """What a lying host of the reader's own can do: show its Signet anything, past every check it runs."""
    net.postgres.sql(f"host_{net.home[agent]}", f"""INSERT INTO inbox (recipient, message_id, envelope, sender_identity, sender_owner_identity,
        sender_binding, sender, expires_at, relayed_by, relay_proof) VALUES ('{net.ids[agent]}', '{e2e.message_id_of(envelope)}', '{envelope}', '{contact.identity}',
        '{owner.identity}', '{binding}', '{contact.id}', {int(time.time()) + 3000}, '{contact.peer.domain}', '')""")


def filter_naming(owner: e2e.Owner) -> dict:
    return e2e.reach_setting("filter", ["quote/1"], filter={"owners": [owner.id], "hosts": [], "past": False}, text=True)


def transferred_contact(net: e2e.Network, name: str, agent: str) -> tuple[Contact, e2e.Owner, e2e.Owner, str]:
    """A contact let in by a filter naming its owner, then given to someone the filter doesn't name."""
    first, thief = new_owner(net.work / f"{name}-first-owner"), new_owner(net.work / f"{name}-next-owner")
    contact = Contact(net, name, first)
    sign_and_put(net, agent, [net.contact_entry("ben")], reach=filter_naming(first))
    status, _ = contact.say(f"{name}: while it acts for the owner the filter names", agent)
    check("control: the filter lets it in while it acts for that owner",
          status == 200 and wait_until(lambda: shown(net, agent, f"{name}: while it acts for the owner the filter names")), status)
    net.ack_all(agent)
    contact.bound()
    first_binding = contact.binding
    contact.transfer_to(thief)
    return contact, first, thief, first_binding


def an_older_history_cant_bring_back_an_old_owner(net: e2e.Network) -> None:
    contact, first, thief, _ = transferred_contact(net, "x", "ana")
    status, answer = contact.relay(contact.notice(net.ids["ana"]), "ana")
    check("control: the notice of the transfer is taken", status == 200, answer)
    check("control: the host goes by the new owner", wait_until(lambda: host_says_acts_for(net, "ana", contact) == thief.id), host_says_acts_for(net, "ana", contact))
    check("control: Signet goes by the new owner", wait_until(lambda: signet_says_acts_for(net, "ana", contact) == thief.id))
    check("control: the filter no longer lets it into the agent's list", not in_the_agents_list(net, "ana", contact))

    status, _ = contact.relay(contact.notice(net.ids["ana"], events=contact.events[:1]), "ana")
    time.sleep(SETTLE_SECONDS)
    check("control: the older copy was relayed", status == 200, status)
    check("an older copy of its history doesn't move the host back", host_says_acts_for(net, "ana", contact) == thief.id, host_says_acts_for(net, "ana", contact))
    check("or Signet", signet_says_acts_for(net, "ana", contact) == thief.id, signet_says_acts_for(net, "ana", contact))
    check("so it doesn't reappear in the agent's list", not in_the_agents_list(net, "ana", contact))
    # An older copy can be the first this reader hears, once it knows better from a message. The filter
    # stops that message at the host, so a host that lets it by is how Signet sees it.
    fresh, _, fresh_thief, _ = transferred_contact(net, "y", "ana")
    fresh.say("y: the new owner's own statement", "ana")
    check("control: a new owner's binding on a message moves the host", wait_until(lambda: host_says_acts_for(net, "ana", fresh) == fresh_thief.id), host_says_acts_for(net, "ana", fresh))
    put_on_the_inbox(net, "ana", fresh, e2e.signed_envelope(fresh.key, fresh.id, net.ids["ana"], "y: on the page"), fresh_thief, fresh.binding)
    check("control: and Signet, seeing it", wait_until(lambda: signet_says_acts_for(net, "ana", fresh) == fresh_thief.id), signet_says_acts_for(net, "ana", fresh))
    net.inbox("ana")
    fresh.relay(fresh.notice(net.ids["ana"], events=fresh.events[:1]), "ana")
    time.sleep(SETTLE_SECONDS)
    check("an older copy heard first doesn't move the host back either", host_says_acts_for(net, "ana", fresh) == fresh_thief.id, host_says_acts_for(net, "ana", fresh))
    check("or Signet either", signet_says_acts_for(net, "ana", fresh) == fresh_thief.id, signet_says_acts_for(net, "ana", fresh))


def a_replayed_binding_cant_pass_a_filter_again(net: e2e.Network) -> None:
    contact, first, thief, first_binding = transferred_contact(net, "z", "ana")
    status, _ = contact.relay(contact.notice(net.ids["ana"]), "ana")
    check("control: the notice is taken", status == 200 and wait_until(lambda: host_says_acts_for(net, "ana", contact) == thief.id), status)
    check("control: Signet has heard", wait_until(lambda: signet_says_acts_for(net, "ana", contact) == thief.id))
    honest = "z: under the new owner"
    contact.say(honest, "ana")
    check("control: honestly, the filter stops it", never_shown(net, "ana", honest))

    words = "z: still the old owner's, trust me"
    status, _ = contact.say(words, "ana", owner=first, binding=first_binding)
    check("control: the old binding was relayed", status == 200, status)
    check("what its old owner signed before doesn't get through", never_shown(net, "ana", words), net.bodies("ana"))
    held = net.postgres.sql("host_a", f"SELECT count(*) FROM inbox WHERE recipient = '{net.ids['ana']}' AND sender = '{contact.id}' AND NOT acked")
    check("or even wait to be shown", held == "0", held)
    check("and it stays the new owner's at the host", host_says_acts_for(net, "ana", contact) == thief.id, host_says_acts_for(net, "ana", contact))

    # A host that puts it straight in front of Signet gets no further.
    put_on_the_inbox(net, "ana", contact, e2e.signed_envelope(contact.key, contact.id, net.ids["ana"], "z: and past the host too"), first, first_binding)
    check("nor does a lying host of the reader's own get it past Signet", never_shown(net, "ana", "z: and past the host too"), net.bodies("ana"))
    check("and Signet still goes by the new owner", signet_says_acts_for(net, "ana", contact) == thief.id, signet_says_acts_for(net, "ana", contact))

    # An owner's word that the agent acts for nobody counts the same way.
    other = Contact(net, "w", first)
    status, _ = other.say("w: before", "ana")
    check("control: let in before a revocation", status == 200 and wait_until(lambda: shown(net, "ana", "w: before")))
    net.ack_all("ana")
    other.bound()
    binding = other.binding
    other.revoke()
    other.relay(other.notice(net.ids["ana"]), "ana")
    check("control: the host hears of the revocation", wait_until(lambda: host_says_acts_for(net, "ana", other) == ""), host_says_acts_for(net, "ana", other))
    status, _ = other.say("w: revoked, but look at this binding", "ana", binding=binding)
    check("a revoked agent's old binding doesn't pass the filter", status == 200 and never_shown(net, "ana", "w: revoked, but look at this binding"), net.bodies("ana"))
    check("and it's gone from the agent's list", not in_the_agents_list(net, "ana", other))

    # What a key its owner has since given up signed stays given up, however it's shown again.
    named = new_owner(net.work / "v-owner")
    third = Contact(net, "v", named)
    sign_and_put(net, "ana", [net.contact_entry("ben")], reach=filter_naming(named))
    status, _ = third.say("v: before its owner's recovery", "ana")
    check("control: let in before a recovery", status == 200 and wait_until(lambda: shown(net, "ana", "v: before its owner's recovery")))
    net.ack_all("ana")
    third.bound()
    recovered = recovered_on_a_new_device(net, "v-owner", named.identity, named.dir / "backup.key", named.token)
    status, answer = http("POST", f"http://{net.domain['a']}/v0/recoveries", {"identity": recovered.identity})
    check("control: its host hears of the recovery", wait_until(lambda: host_says_acts_for(net, "ana", third) == ""), (status, answer))
    status, answer = third.relay(third.notice(net.ids["ana"]), "ana")
    check("control: a history from before it is relayed", status == 200, answer)
    time.sleep(SETTLE_SECONDS)
    check("a history under the given-up key doesn't bring back who it acts for", host_says_acts_for(net, "ana", third) == "", host_says_acts_for(net, "ana", third))


def a_host_keeping_a_history_back_cant_skip_a_hold(net: e2e.Network) -> None:
    owner = new_owner(net.work / "m-owner")
    mal = Contact(net, "m", owner)
    mal.answer_lookups()
    sign_and_put(net, "carol", [net.contact_entry("ben"), entry(mal, "mal")])
    mal.say("m: before any change", "carol")
    check("control: a named contact's message arrives", wait_until(lambda: shown(net, "carol", "m: before any change")), net.bodies("carol"))
    net.ack_all("carol")
    check("control: nothing to ask the owner", standing_of(net, "carol", mal) is None, changes_page(net, "carol"))

    # A real recovery, with the history kept back. Under the default, this is for the owner to decide.
    mal.bound()
    mal.replace_key()
    mal.answer_lookups()
    words = "m: a new key, and no history to say why"
    message = e2e.signed_envelope(mal.key, mal.id, net.ids["carol"], words)
    status, answer = mal.relay(message, "carol")
    check("control: the host takes it", status == 200, answer)
    check("a replaced key doesn't reach the agent with the history kept back", never_shown(net, "carol", words), net.bodies("carol"))
    check("it waits on the host", waits_on_the_host(net, "carol", message))
    check("and the owner can see it waiting", wait_until(lambda: standing_of(net, "carol", mal) == "waiting_for_history"), changes_page(net, "carol"))
    check("the agent can't write to them meanwhile", not in_the_agents_list(net, "carol", mal))

    # Giving it up late is no way round: what happened since the reader first met them is still change.
    mal.answer_lookups(with_history=True)
    check("when the host answers at last, it goes to the owner", wait_until(lambda: standing_of(net, "carol", mal) == "ask"), changes_page(net, "carol"))
    check("and the agent still hasn't seen it", not shown(net, "carol", words))
    status, answer = accept_changes(net, "carol", mal)
    check("the owner says yes", status == 200, answer)
    check("and only then it arrives", wait_until(lambda: shown(net, "carol", words)), net.bodies("carol"))
    net.ack_all("carol")

    # A new owner the old one released, with no recovery and no history.
    buyer = new_owner(net.work / "m-buyer")
    mal.transfer_to(buyer, recovering=False)
    mal.answer_lookups()
    mal.peer.answers[f"/.well-known/splint/agents/{mal.name}"]["history"] = ""
    words = "m: a new owner, and no history to say why"
    message = e2e.signed_envelope(mal.key, mal.id, net.ids["carol"], words)
    status, answer = mal.relay(message, "carol")
    check("control: the host takes that too", status == 200, answer)
    check("a new owner doesn't reach the agent with the history kept back", never_shown(net, "carol", words), net.bodies("carol"))
    check("it waits as well", waits_on_the_host(net, "carol", message))
    check("and the owner sees that", wait_until(lambda: standing_of(net, "carol", mal) == "waiting_for_history"), changes_page(net, "carol"))
    mal.answer_lookups(with_history=True)
    mal.relay(mal.notice(net.ids["carol"]), "carol")
    check("the history goes to the owner when it comes", wait_until(lambda: standing_of(net, "carol", mal) == "ask"), changes_page(net, "carol"))
    status, answer = accept_changes(net, "carol", mal)
    check("control: the owner says yes", status == 200, answer)
    check("and then it arrives", wait_until(lambda: shown(net, "carol", words)), net.bodies("carol"))
    net.ack_all("carol")
    sign_and_put(net, "carol", [net.contact_entry("ben")])

    # A contact whose first history comes with the changes in it, and no message from before them.
    first = new_owner(net.work / "n-owner")
    late = Contact(net, "n", first)
    late.bound()
    late.replace_key()
    late.answer_lookups(with_history=True)
    sign_and_put(net, "carol", [net.contact_entry("ben"), entry(late, "late")])
    late.say("n: first thing it's said", "carol")
    check("control: what a contact already was when first met needs no yes", wait_until(lambda: shown(net, "carol", "n: first thing it's said")), changes_page(net, "carol"))
    net.ack_all("carol")
    sign_and_put(net, "carol", [net.contact_entry("ben")])


def a_contact_cant_take_another_contacts_address(net: e2e.Network) -> None:
    owner = new_owner(net.work / "p-owner")
    mal = Contact(net, "p", owner)
    mal.answer_lookups()
    ben_address = net.address("ben")
    # Listed first, since whoever comes first is who an address finds.
    sign_and_put(net, "ana", [entry(mal, "mal"), net.contact_entry("ben")])
    check("control: Ana can write to Ben", bool(net.send_and_wait("ana", "ben", "p: hi ben")))
    net.ack_all("ben")
    mal.bound()
    mal.moved_to(ben_address)
    status, answer = mal.relay(mal.notice(net.ids["ana"]), "ana")
    check("control: the hostile host relays the move", status == 200, answer)
    time.sleep(SETTLE_SECONDS)
    contacts = {one["label"]: one for one in net.agent("ana", "GET", "/v0/contacts")[1]["contacts"]}
    check("a signed move doesn't take the address the owner named another contact at", contacts["mal"]["address"] == mal.address, contacts["mal"])
    check("and that contact stays where it was", contacts["ben"]["address"] == ben_address and contacts["ben"]["agent"] == net.ids["ben"], contacts)
    words = "p: from ben, please wire the deposit"
    mal.say(words, "ana", binding=mal.binding)
    check("control: its message arrives", wait_until(lambda: shown(net, "ana", words)), net.bodies("ana"))
    message = next(one for one in net.inbox("ana")["messages"] if one["untrusted"]["body"] == words)
    check("and doesn't say it's from that address", message["verified"]["from"]["address"] == mal.address, message["verified"])
    net.ack_all("ana")
    check("the agent can still write to the real contact", bool(net.send_and_wait("ana", "ben", "p: are you there?")))
    net.ack_all("ben")

    # A move to somewhere nobody is still counts.
    elsewhere = f"p-new~{mal.peer.domain}"
    mal.moved_to(elsewhere)
    mal.relay(mal.notice(net.ids["ana"]), "ana")

    def moved() -> bool:
        return any(one["agent"] == mal.id and one["address"] == elsewhere for one in net.agent("ana", "GET", "/v0/contacts")[1]["contacts"])

    check("control: a move to an address nobody has counts", wait_until(moved), net.agent("ana", "GET", "/v0/contacts")[1])
    sign_and_put(net, "ana", [net.contact_entry("ben")])


def stranger(net: e2e.Network, name: str) -> Contact:
    return Contact(net, name, new_owner(net.work / f"{name}-owner"))


def a_lying_host_of_the_readers_own_gets_nothing_past_signet(net: e2e.Network) -> None:
    """The rows here are what a host could put in Postgres. Each is real, signed by whoever it says, and
    each breaks a rule only Signet is left to apply. So what's checked is what the agent or owner sees."""
    ana = net.ids["ana"]
    quiet = stranger(net, "q")
    sign_and_put(net, "ana", [net.contact_entry("ben"), entry(quiet, "quiet") | {"text": False}], reach=e2e.reach_setting("open", ["quote/1"], text=False))
    words = "q: free words, to an agent whose owner turned them off"
    put_on_the_inbox(net, "ana", quiet, e2e.signed_envelope(quiet.key, quiet.id, ana, words), quiet.owner, quiet.binding)
    page = net.inbox("ana")
    check("words go nowhere the owner didn't sign `text`, whatever a host says", all(one["untrusted"]["body"] != words for one in page["messages"]) and page["dropped"] >= 1, page)

    # A message for someone else says nothing about who anyone is.
    other = stranger(net, "r")
    for_someone_else = e2e.signed_envelope(other.key, other.id, net.ids["ben"], "r: for ben")
    put_on_the_inbox(net, "ana", other, for_someone_else, other.owner, other.binding)
    net.inbox("ana")
    time.sleep(SETTLE_SECONDS)
    check("a message for another agent teaches Signet nobody", signet_says_acts_for(net, "ana", other) == "")
    check("and they don't reach the agent's list", not in_the_agents_list(net, "ana", other))
    control = e2e.signed_envelope(other.key, other.id, ana, json.dumps({"step": "open", "type": "quote/1", "terms": {}, "deadline": int(time.time()) + 3600}, separators=(",", ":")))
    put_on_the_inbox(net, "ana", other, control, other.owner, other.binding)
    check("control: the same sender's message for this agent does", wait_until(lambda: signet_says_acts_for(net, "ana", other) == other.owner.id))

    def held_by_signet() -> list[dict]:
        return http("GET", f"http://127.0.0.1:{net.signet_port['ana']}/v0/owner/quarantine", token=net.owners["ana"].token)[1]["held"]

    def on_quarantine(contact: Contact, envelope: str) -> None:
        net.postgres.sql("host_a", f"""INSERT INTO quarantine (recipient, sender, message_id, envelope, sender_identity, sender_owner_identity, sender_binding, expires_at, relayed_by)
            VALUES ('{ana}', '{contact.id}', '{e2e.message_id_of(envelope)}', '{envelope}', '{contact.identity}', '{contact.owner.identity}', '{contact.binding}', {int(time.time()) + 3000}, '{contact.peer.domain}')""")

    # A host can't show the owner a stranger waiting who never wrote to this agent.
    waiting = stranger(net, "s")
    meant_for_ben = e2e.signed_envelope(waiting.key, waiting.id, net.ids["ben"], "s: for ben")
    on_quarantine(waiting, meant_for_ben)
    check("what's held for another agent isn't shown to this owner", held_by_signet() == [], held_by_signet())
    meant_for_ana = e2e.signed_envelope(waiting.key, waiting.id, ana, "s: for ana")
    on_quarantine(waiting, meant_for_ana)
    check("control: what's held for this agent is", [one["sender"] for one in held_by_signet()] == [waiting.id], held_by_signet())

    # New rules move what's held, and only what was meant for this agent.
    sign_and_put(net, "ana", [net.contact_entry("ben"), entry(waiting, "waiting")])
    moved = f"SELECT count(*) FROM inbox WHERE message_id = '{e2e.message_id_of(meant_for_ben)}'"
    check("what's meant for another agent doesn't move anywhere when rules name its sender", net.postgres.sql("host_a", moved) == "0" and net.postgres.sql("host_b", moved) == "0")
    left = net.postgres.sql("host_a", f"SELECT count(*) FROM quarantine WHERE recipient = '{ana}' AND sender = '{waiting.id}'")
    check("it's gone, and so is what they're now let in for", left == "0", left)
    check("control: what was meant for this agent moves", wait_until(lambda: shown(net, "ana", "s: for ana")), net.bodies("ana"))
    net.ack_all("ana")

    # A notice on a fork counts only for whoever it's addressed to.
    forked = stranger(net, "t")
    forked.answer_lookups()
    sign_and_put(net, "ana", [net.contact_entry("ben"), entry(forked, "forked")])
    forked.say("t: first", "ana")
    check("control: a contact's first message arrives", wait_until(lambda: shown(net, "ana", "t: first")), net.bodies("ana"))
    net.ack_all("ana")
    forked.bound()
    before = (forked.identity, forked.backup, list(forked.events), forked.head, forked.key, forked.agent_recoveries)
    forked.relay(forked.notice(ana), "ana")
    forked.replace_key()
    forked.relay(forked.notice(ana), "ana")
    check("control: the reader goes by one recovery", wait_until(lambda: standing_of(net, "ana", forked) == "ask"), changes_page(net, "ana"))
    forked.identity, forked.backup, forked.events, forked.head, forked.key, forked.agent_recoveries = before[0], before[1], list(before[2]), before[3], before[4], before[5]
    statement = forked.recover(net.work / "t-other-key.key")
    forked.binding = forked.make_binding(forked.owner, forked.address)
    forked.sign_event({"kind": "key", "whose": "agent", "head": signed_part_hash(statement)})
    put_on_the_inbox(net, "ana", forked, forked.notice(net.ids["ben"]), forked.owner, forked.binding)
    check("control: the other recovery holds it", wait_until(lambda: standing_of(net, "ana", forked) == "rewritten"), changes_page(net, "ana"))
    time.sleep(SETTLE_SECONDS)
    entry_now = next(one for one in changes_page(net, "ana") if one["contact"] == forked.id)
    check("a rival history addressed to someone else isn't put to the owner", "rewritten_head" not in entry_now, entry_now)
    put_on_the_inbox(net, "ana", forked, forked.notice(ana), forked.owner, forked.binding)
    check("control: addressed to this agent it is", wait_until(lambda: "rewritten_head" in next(one for one in changes_page(net, "ana") if one["contact"] == forked.id)), changes_page(net, "ana"))
    sign_and_put(net, "ana", [net.contact_entry("ben")])


def owners_tokens_and_keys_stay_out_of_what_runs_print(net: e2e.Network) -> None:
    """After everything above, nothing an owned network printed holds a key or an owner's token."""
    logs = net.process_logs()
    secrets = {name: net.key_of(name).read_bytes() for name in net.owners}
    check("no agent's key is in any log, as a file or a bare secret", e2e.keys_seen_in([logs], secrets) == [])
    exposed = [name for name, owner in net.owners.items() if owner.token.encode() in logs]
    check("and no owner's token", not exposed, exposed)


def main() -> int:
    e2e.build()
    with e2e.running_network(owned=True) as network:
        for scenario in (
            an_older_history_cant_bring_back_an_old_owner,
            a_replayed_binding_cant_pass_a_filter_again,
            a_host_keeping_a_history_back_cant_skip_a_hold,
            a_contact_cant_take_another_contacts_address,
            a_lying_host_of_the_readers_own_gets_nothing_past_signet,
            owners_tokens_and_keys_stay_out_of_what_runs_print,
        ):
            print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
            scenario(network)
        if e2e.failures:
            for process in network.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1000:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

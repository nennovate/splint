#!/usr/bin/env python3
"""Owner keys, bindings and signed rules, with the agent assumed fully fooled.

Everything here is the real software against Postgres, like e2e.py. Owners sign with the real
owner-key tool. A fooled agent holds its Signet's API token and does whatever a message told it to.
Where a scenario says a key was stolen, the attacker holds the agent's key too. Each attack has a
control that succeeds, so a refusal can't be down to the attempt being malformed.

Not shown here: an owner's device apart from the agent's machine, hardware-held keys (software files
here, and hardware is for v1), and a separate OS user keeping an agent from Signet's files.
"""

import base64
import hashlib
import json
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import e2e
import transport_log
from e2e import Owner, accepted, check, http, new_identity, new_owner, owner_key_tool, payload_of, sign_jws, wait_until
from request_driver import draft_for, hours_from_now, move, open_request, owner_call, owner_decides, view, wait_for, wait_for_received

# Long enough for Signet and the host to take the rules on a busy CI machine before they run out.
EXPIRES_IN_SECONDS = 4
# Well past what a sync takes, so a step that stays put was held and isn't just slow.
LONG_ENOUGH_TO_HAVE_LEFT = 2.0


def who_is(url: str) -> dict:
    return http("GET", f"{url}/v0/identity", token=e2e.EXTRA_SIGNET_TOKEN)[1]


def resolved(net: e2e.Network, handle: str, host: str = "a") -> tuple[int, dict]:
    return http("GET", f"http://{net.domain[host]}/.well-known/splint/agents/{handle}")


def offer_to(address: str) -> dict:
    """Core's plain conversation, which no one agrees first. What these scenarios check is whom the
    owner's rules let an agent open with, and an example type would first need agreeing with type/1,
    which a contact that hasn't listed this agent or a scripted peer never does, so every open would be
    refused as an unknown type whatever the rules said."""
    return {"contact": address, "type": e2e.CHAT, "deadline": hours_from_now(48), "supersedes": None}


def opens(net: e2e.Network, agent: str, other: str) -> int:
    return net.agent(agent, "POST", "/v0/requests", offer_to(net.address(other)))[0]


def forged_rules(net: e2e.Network, signer: Path, owner: str, agent: str, contacts: list[dict], **changes) -> str:
    """Rules as anyone but the real device would write them, or as it wouldn't: signer is what signs."""
    now = int(time.time())
    payload = {
        "v": 1, "owner": owner, "agent": net.ids[agent], "seq": int(time.time() * 1000),
        "issued_at": now, "paused": False, "reach": e2e.reach_setting(),
        "permissions": e2e.PERMISSIONS, "contacts": contacts, "invites": [], "limits": e2e.LIMITS,
        **changes,
    }
    return sign_jws(signer, "splint-rules", json.dumps(payload).encode())


def an_owner_puts_an_agent_on_a_host(net: e2e.Network) -> None:
    url, process = net.unwaited_signet("olive", net.domain["a"], {})
    if not wait_until(lambda: http("GET", f"{url}/v0/identity", token=e2e.EXTRA_SIGNET_TOKEN)[0] == 200):
        raise RuntimeError("olive's Signet didn't start")
    owner = net.owners["olive"]
    check("a new Signet isn't on its host yet", who_is(url)["registered"] is False)
    check("and nobody can find it", resolved(net, "olive")[0] == 404)

    status, answer = net.bind_extra("olive", url)
    check("once its owner signs a binding it registers", status == 200, answer)
    check("and says so", who_is(url)["registered"] is True)
    status, found = resolved(net, "olive")
    check("anyone can find it, with its owner and the binding", status == 200 and found["owner_identity"] == owner.identity, found)
    event = json.loads(base64.urlsafe_b64decode(found["identity"] + "=" * (-len(found["identity"]) % 4)))
    check("its identity is one kind of ID, which names no owner", set(event) == {"v", "alg", "key", "seal", "recovery"}, event)
    check("it commits to the backup its owner's device holds", event["recovery"]["commitment"] == net.agent_backups["olive"]["commitment"], event)
    check("and the two of them signed that it acts for that owner", found["agent_id"] == who_is(url)["agent_id"] and who_is(url)["owner_id"] == owner.id, found)

    process.kill_hard()
    process.start()
    came_back = wait_until(lambda: http("GET", f"{url}/v0/identity", token=e2e.EXTRA_SIGNET_TOKEN)[1].get("registered") is True)
    check("after a restart it registers again without another signature", came_back)
    process.kill_hard()


def a_fooled_agent_cant_bind_itself(net: e2e.Network) -> None:
    url, process = net.unwaited_signet("perry", net.domain["a"], {})
    if not wait_until(lambda: http("GET", f"{url}/v0/identity", token=e2e.EXTRA_SIGNET_TOKEN)[0] == 200):
        raise RuntimeError("perry's Signet didn't start")
    who = who_is(url)
    agent_key, owner, mallory = net.work / "perry" / "agent.key", net.owners["perry"], net.owners["mallory"]
    agent_id, address = who["agent_id"], who["address"]

    def put(binding: str) -> int:
        return http("PUT", f"{url}/v0/owner/binding", {"binding": binding})[0]

    check("a binding signed by the agent's key is refused", put(net.binding_for(agent_key, owner, agent_id, address)) == 403)
    check("so is one signed by another owner, naming the real one", put(net.binding_for(mallory.key, owner, agent_id, address)) == 403)
    check("and by another owner, naming themselves", put(net.binding_for(mallory.key, mallory, agent_id, address)) == 403)
    other_address = owner.sign("bind", "--agent", who["identity"], "--address", f"somebody-else~{net.domain['a']}", "--backup", net.agent_backups["perry"]["file"])
    check("the real owner's binding for another address doesn't fit", put(other_address) == 403)
    check("a binding that isn't one is refused", put("not a binding") == 403)
    check("nothing registered", who_is(url)["registered"] is False and resolved(net, "perry")[0] == 404)
    theirs = mallory.bind(who["identity"], address)
    check("another owner can sign that it's theirs, and this Signet goes by its own owner", put(theirs) == 403)
    refused = owner_key_tool("bind", "--dir", str(mallory.dir), "--agent", who["identity"], "--address", address, "--backup", str(mallory.dir / "backup.key"))
    check("and their tool won't vouch for it without the agent's backup", refused.returncode != 0, refused.stdout)
    unvouched = owner.bind(who["identity"], address)
    check("nor does the real owner's half count without the backup's vouch", put(unvouched) == 403)

    # With the agent's key stolen too, going straight to the host gets no further.
    stolen = accepted(net.binding_for(agent_key, owner, agent_id, address), agent_key)
    body = json.dumps({
        "owner_identity": owner.identity, "agent_identity": who["identity"], "binding": stolen,
        **e2e.signup_fields(next(net.signup_codes), stolen),
    }).encode()
    host = f"http://{net.domain['a']}/v0/agents"
    status = http("POST", host, raw=body, auth=net.registration_proof(agent_key, agent_id, body))[0]
    check("a stolen agent key can't register with its own binding", status == 400, status)
    check("control: the owner's real binding works", net.bind_extra("perry", url)[0] == 200)
    process.kill_hard()


def a_captured_registration_cant_lock_an_owner_out(net: e2e.Network) -> None:
    """Issue 7: a proof seen in transit can't register that identity under another handle."""
    owner = new_owner(net.work / "quinn-owner")
    key = net.work / "quinn.key"
    identity, agent_id = new_identity(key)
    address = f"quinn~{net.domain['a']}"
    code = next(net.signup_codes)

    def body_with(binding: str, signup_code: str = code, **changes) -> bytes:
        fields = {"owner_identity": owner.identity, "agent_identity": identity, "binding": binding, **e2e.signup_fields(signup_code, binding)}
        return json.dumps({**fields, **changes}).encode()

    binding = accepted(owner.bind(identity, address), key)
    body = body_with(binding)
    captured = net.registration_proof(key, agent_id, body)
    url = f"http://{net.domain['a']}/v0/agents"

    def replay(other_body: bytes) -> int:
        return http("POST", url, raw=other_body, auth=captured)[0]

    stolen_handle = accepted(owner.bind(identity, f"quinns-other~{net.domain['a']}"), key)
    check("a captured proof doesn't fit another binding", replay(body_with(stolen_handle)) == 400)
    check("or another signup code", replay(body_with(binding, next(net.signup_codes))) == 400)
    mallory = net.owners["mallory"]
    theirs = accepted(net.binding_for(mallory.key, mallory, agent_id, f"grabbed~{net.domain['a']}"), key)
    check("or an attacker's own binding for that identity", replay(body_with(theirs, owner_identity=mallory.identity)) == 400)
    check("or the old form with a handle of its own", replay(json.dumps({"handle": "grabbed", "identity": identity, "proof": captured}).encode()) == 400)
    check("or the old form with its code in the clear", replay(json.dumps({"owner_identity": owner.identity, "agent_identity": identity, "binding": binding, "signup_code": code}).encode()) == 400)

    # Issue 161: someone who reads the request and holds it back signs a fresh proof of their own.
    check("the code itself never travels", code.encode() not in body)
    thief_key = net.work / "thief.key"
    thief = new_owner(net.work / "thief-owner")
    thief_identity, thief_id = new_identity(thief_key)
    thiefs_binding = accepted(thief.bind(thief_identity, address), thief_key)
    seen = json.loads(body)

    def claim(signup: dict) -> int:
        taken = json.dumps({"owner_identity": thief.identity, "agent_identity": thief_identity, "binding": thiefs_binding, **signup}).encode()
        return http("POST", url, raw=taken, auth=net.registration_proof(thief_key, thief_id, taken))[0]

    copied = {"signup_id": seen["signup_id"], "signup_mac": seen["signup_mac"]}
    check("what it saw can't take that handle for another owner", claim(copied) == 403)
    check("none of that took a handle", all(resolved(net, handle)[0] == 404 for handle in ("quinn", "quinns-other", "grabbed")))

    check("the captured request can only do what the owner wanted", replay(body) == 200)
    check("and doing it again changes nothing", replay(body) == 200)
    check("so the owner isn't locked out", resolved(net, "quinn")[1].get("agent_id") == agent_id)
    used = net.postgres.sql("host_a", f"SELECT count(*) FROM signup_codes WHERE used_by = '{agent_id}'")
    check("and only one code was spent", used == "1", used)


def a_stranger_cant_claim_a_handle(net: e2e.Network) -> None:
    """Issue 91: a binding proves an owner agreed, not that a host did. That takes a signup code."""
    stranger = new_owner(net.work / "stranger-owner")
    key = net.work / "stranger-agent.key"
    identity, agent_id = new_identity(key)
    status = net.register_on_a(key, stranger, "free-handle", identity, agent_id, code="")
    check("with no signup code a free handle can't be claimed", status == 403, status)
    status = net.register_on_a(key, stranger, "free-handle", identity, agent_id, code=e2e.signup_code(999_999))
    check("nor with a made-up one", status == 403, status)
    check("and it stays free", resolved(net, "free-handle")[0] == 404)

    code = next(net.signup_codes)
    status = net.register_on_a(key, stranger, "ana", identity, agent_id, code)
    check("a taken handle is refused", status == 409, status)
    status = net.register_on_a(key, stranger, "free-handle", identity, agent_id, code)
    check("control: that didn't spend the code, and it works for a free handle", status == 200, status)

    second_key = net.work / "stranger-second.key"
    second, second_id = new_identity(second_key)
    status = net.register_on_a(second_key, stranger, "second-handle", second, second_id, code)
    check("a code works once", status == 403, status)


def a_rule_change_needs_the_owners_signature(net: e2e.Network) -> None:
    agent_key, owner, mallory = net.key_of("ana"), net.owners["ana"], net.owners["mallory"]
    mallory_contact = net.contact_entry("mallory")
    check("control: ana can open a request with a contact", opens(net, "ana", "ben") == 200)
    check("and not with anyone else", opens(net, "ana", "mallory") == 400)

    attempts = {
        "signed by the agent's own key": forged_rules(net, agent_key, owner.id, "ana", [mallory_contact]),
        "signed by another owner, naming the real one": forged_rules(net, mallory.key, owner.id, "ana", [mallory_contact]),
        "signed by another owner, naming themselves": forged_rules(net, mallory.key, mallory.id, "ana", [mallory_contact]),
        "with no signature at all": "e30.e30.",
        "that aren't signed objects": json.dumps({"contacts": [mallory_contact]}),
    }
    for name, rules in attempts.items():
        status = net.put_rules("ana", rules)[0]
        check(f"rules {name} are refused", status == 403, status)
    check("a fooled agent's token doesn't help, and nothing changed", opens(net, "ana", "mallory") == 400)
    check("control: ben is still a contact", opens(net, "ana", "ben") == 200)

    before = net.sign_rules("ana", [net.contact_entry("ben")])
    check("control: the owner's signature is enough", net.put_rules("ana", before)[0] == 200)
    with_mallory = net.sign_rules("ana", [net.contact_entry("ben"), mallory_contact])
    check("control: and the owner can add a contact", net.put_rules("ana", with_mallory)[0] == 200)
    check("which then counts", opens(net, "ana", "mallory") == 200)
    without_ben = net.sign_rules("ana", [mallory_contact])
    check("control: or remove one", net.put_rules("ana", without_ben)[0] == 200)
    check("which then counts too", opens(net, "ana", "ben") == 400)

    status = net.put_rules("ana", with_mallory)[0]
    check("the owner's own older rules can't be replayed", status == 403, status)
    check("so a host holding them can't roll a removal back", opens(net, "ana", "ben") == 400)
    bens = net.sign_rules("ben", [net.contact_entry("ana")])
    status = net.put_rules("ana", bens)[0]
    check("rules another agent's owner signed don't fit this one", status == 403, status)
    draft = {
        "paused": False, "contacts": [net.contact_entry("ben")], "invites": [], "limits": e2e.LIMITS,
    }
    for_a_sibling = owner.sign("rules", "--agent", net.ids["mallory"], stdin=json.dumps(draft))
    status = net.put_rules("ana", for_a_sibling)[0]
    check("and neither do rules this owner signed for another of their agents", status == 403, status)

    net.signets["ana"].kill_hard()
    net.signets["ana"].start()
    net.wait_for_signet("ana")
    check("a restart keeps the signed rules", opens(net, "ana", "ben") == 400 and opens(net, "ana", "mallory") == 200)
    status = net.put_rules("ana", with_mallory)[0]
    check("and still refuses older ones", status == 403, status)

    naming_an_owner = {**net.contact_entry("ben"), "owner": mallory.id}
    refused = owner_key_tool("rules", "--dir", str(net.owners["ana"].dir), "--agent", net.ids["ana"], stdin=json.dumps(e2e.rules_draft([naming_an_owner])))
    check("a contact pins one ID, so the tool won't sign one naming an owner too", refused.returncode != 0, refused.stdout)
    net.sign_contact_rules(e2e.OWNED_AGENTS)


def a_pause_holds_until_the_owner_lifts_it(net: e2e.Network) -> None:
    owner, agent_key = net.owners["ana"], net.key_of("ana")
    contact = net.contact_entry("ben")
    opened = net.agent("ana", "POST", "/v0/requests", offer_to(net.address("ben")))[1]["request"]
    check("control: ana can send", net.send("ana", "ben", "before the pause")[0] == 200)

    older = net.sign_rules("ana", [contact])
    check("control: the owner can pause", net.put_rules("ana", net.sign_rules("ana", [contact], paused=True))[0] == 200)
    check("a paused agent can't send", net.send("ana", "ben", "during the pause")[0] == 403)
    check("or open a request", opens(net, "ana", "ben") == 403)
    check("or move one", net.agent("ana", "POST", f"/v0/requests/{opened}/cancel", {})[0] == 403)
    check("but it can still read", net.agent("ana", "GET", f"/v0/requests/{opened}")[0] == 200)
    unpause = forged_rules(net, agent_key, owner.id, "ana", [contact], paused=False)
    check("a fooled agent can't lift the pause", net.put_rules("ana", unpause)[0] == 403)
    check("so it's still paused", net.send("ana", "ben", "still paused")[0] == 403)

    net.signets["ana"].kill_hard()
    net.signets["ana"].start()
    net.wait_for_signet("ana")
    check("a restart doesn't lift a pause", net.send("ana", "ben", "after a restart")[0] == 403)
    check("or forget how new the rules were, so older ones still can't lift it", net.put_rules("ana", older)[0] == 403)

    check("control: the owner can lift it", net.put_rules("ana", net.sign_rules("ana", [contact]))[0] == 200)
    check("and then it can send", net.send("ana", "ben", "after the pause")[0] == 200)

    now = int(time.time())
    short = forged_rules(net, owner.key, owner.id, "ana", [contact], issued_at=now, ends_at=now + EXPIRES_IN_SECONDS)
    check("control: the owner can sign rules with an end", net.put_rules("ana", short)[0] == 200)
    stopped = wait_until(lambda: net.send("ana", "ben", "are the rules still in force?")[0] == 403)
    check("rules past the end their owner gave them stop the agent", stopped)
    check("and it has no contacts until the owner signs again", opens(net, "ana", "ben") == 403)
    check("control: signing new rules starts it again", net.put_rules("ana", net.sign_rules("ana", [contact]))[0] == 200)
    check("and it can open a request", opens(net, "ana", "ben") == 200)
    net.ack_all("ben")


def a_new_request_waits_out_a_stop(net: e2e.Network) -> None:
    """Issue 160: a contact's request isn't lost because rules weren't in force when it arrived."""
    ana = net.contact_entry("ana")
    owner = net.owners["ben"]

    def short_rules() -> str:
        now = int(time.time())
        return forged_rules(net, owner.key, owner.id, "ben", [ana], issued_at=now, ends_at=now + EXPIRES_IN_SECONDS)

    stops = {"a pause": lambda: net.sign_rules("ben", [ana], paused=True), "rules that ran out": short_rules}
    for how, stop in stops.items():
        check(f"control: ben's owner signs {how}", net.put_rules("ben", stop())[0] == 200)
        check("control: they've stopped him", wait_until(lambda: net.send("ben", "ana", "still in force?")[0] == 403))
        request = open_request(net, "ana", "ben")
        time.sleep(LONG_ENOUGH_TO_HAVE_LEFT)
        check(f"during {how} ben's agent doesn't get the request", view(net, "ben", request).get("status") == 404)
        check("and ana isn't told it was received", view(net, "ana", request)["delivery"]["received"] is False)
        net.put_rules("ben", net.sign_rules("ben", [ana]))
        check("once the rules count again it's there", wait_for(net, "ben", request, version=1) is not None)
        check("and ana hears", wait_for_received(net, "ana", request))

    # Only someone the rules list waits: anyone else is still refused, or they'd sit on the host.
    for how, contacts in (("blocked", [net.contact_entry("ana", "blocked")]), ("removed", [])):
        net.put_rules("ben", net.sign_rules("ben", contacts, paused=True))
        request = open_request(net, "ana", "ben")
        time.sleep(LONG_ENOUGH_TO_HAVE_LEFT)
        net.put_rules("ben", net.sign_rules("ben", [ana]))
        came = wait_until(lambda: view(net, "ben", request).get("version") == 1, timeout=LONG_ENOUGH_TO_HAVE_LEFT)
        check(f"a {how} contact's request isn't kept for later", not came)
    net.sign_contact_rules(e2e.OWNED_AGENTS)
    net.ack_all("ben")


def an_inbox_read_cant_lose_a_step(net: e2e.Network) -> None:
    """Issue 163: before its first rules a Signet isn't syncing, so a step waits on its host."""
    url, process = net.extra_signet("nell", net.domain["a"], {"SPLINT_SYNC_MILLIS": "100"})
    who = who_is(url)
    token = e2e.EXTRA_SIGNET_TOKEN
    nell = {
        "agent": who["agent_id"], "address": who["address"],
        "label": "nell", "status": "allowed", "types": e2e.EXAMPLE_TYPES, "text": True, "pinned_by": "owner",
    }
    net.put_rules("ben", net.sign_rules("ben", [net.contact_entry("ana"), nell]))
    status, opened = net.agent("ben", "POST", "/v0/requests", offer_to(who["address"]))
    check("control: ben opens a request to it", status == 200, opened)
    request = opened["request"]

    # By this step alone, as ben's Signet can tell a new contact about a change at any moment.
    the_step = f"recipient = '{who['agent_id']}' AND message_id = '{request}'"

    def on_host(table: str) -> str:
        extra = " AND NOT acked" if table == "inbox" else ""
        return net.postgres.sql("host_a", f"SELECT count(*) FROM {table} WHERE {the_step}{extra}")

    check("control: with no rules at its host the step is held", wait_until(lambda: on_host("quarantine") == "1"), on_host("quarantine"))
    # A host could also have put it on the agent's page. A read has to leave it there as well.
    columns = "recipient, message_id, envelope, sender_identity, sender_owner_identity, sender_binding"
    net.postgres.sql("host_a", f"INSERT INTO inbox ({columns}) SELECT {columns} FROM quarantine WHERE {the_step}")
    net.postgres.sql("host_a", f"DELETE FROM quarantine WHERE {the_step}")
    check("control: the step is on the agent's page", on_host("inbox") == "1", on_host("inbox"))
    status, page = http("GET", f"{url}/v0/inbox", token=token)
    check("an agent's read shows no step, and counts none as dropped", status == 200 and page == {"messages": [], "dropped": 0}, page)
    check("and leaves it there", on_host("inbox") == "1", on_host("inbox"))

    draft = {
        "paused": False, "contacts": [net.contact_entry("ben")], "invites": [], "limits": e2e.LIMITS,
    }
    rules = net.owners["nell"].sign("rules", "--agent", who["agent_id"], stdin=json.dumps(draft))
    check("control: its owner signs rules naming ben", http("PUT", f"{url}/v0/owner/rules", {"rules": rules})[0] == 200)
    check("and the request is there", wait_until(lambda: http("GET", f"{url}/v0/requests/{request}", token=token)[0] == 200))
    net.sign_contact_rules(e2e.OWNED_AGENTS)
    process.kill_hard()


def an_owner_sees_who_they_are_approving(net: e2e.Network) -> None:
    """Issue 162: the signature binds the terms, and the owner has to be able to read them first."""
    request = open_request(net, "ana", "ben")
    check("control: ben sees it", wait_for(net, "ben", request, version=1) is not None)
    check("control: ben accepts", move(net, "ben", request, "accept", {"pick": {"start": view(net, "ben", request)["terms"]["slots"][0]}})[0] == 200)
    check("control: ana sees that", wait_for(net, "ana", request, state="accepted") is not None)
    draft = draft_for(net, "ana", request)
    owner = net.owners["ana"]

    def approve(terms: dict) -> subprocess.CompletedProcess:
        given = json.dumps({**draft, "terms": terms})
        return owner_key_tool("approve", "--dir", str(owner.dir), "--decision", "approve", "--subject", "Intro call", stdin=given)

    done = approve(draft["terms"])
    shown = done.stderr
    check("control: it signs", done.returncode == 0, shown)
    for what, value in (("who it's with", '"ben" from your rules'), ("their agent", net.ids["ben"]), ("their owner", net.owners["ben"].id), ("the request", request), ("the subject being signed", "Intro call")):
        check(f"the owner is shown {what}", value in shown, shown)
    other = {"agent": "splint1" + "c" * 64, "owner": net.owners["mallory"].id}
    swapped = approve({**draft["terms"], "recipient": other}).stderr
    check("terms with someone else read differently", other["agent"] in swapped and other["owner"] in swapped and swapped != shown, swapped)
    check("and say they aren't in the owner's rules", "NOT IN YOUR RULES" in swapped, swapped)


def a_hostile_host_cant_swap_a_contact(net: e2e.Network) -> None:
    """A host can answer a lookup with anyone it likes, but the owner's rules named one agent."""
    peer = net.scripted_peer
    real_owner = new_owner(net.work / "real-owner")
    real, real_id = new_identity(net.work / "real.key")
    address = f"sam~{peer.domain}"
    real_binding = accepted(real_owner.bind(real, address), net.work / "real.key")
    fake_owner = new_owner(net.work / "fake-owner")
    fake, fake_id = new_identity(net.work / "fake.key")
    fake_binding = accepted(fake_owner.bind(fake, address), net.work / "fake.key")

    def answers(agent_id: str, identity: str, owner: Owner, binding: str) -> None:
        answer = {"agent_id": agent_id, "identity": identity, "owner_identity": owner.identity, "binding": binding}
        peer.respond = lambda _path, _sent: (200, {}, json.dumps(answer).encode())

    contact = {
        "agent": real_id, "address": address, "label": "Sam",
        "status": "allowed", "types": e2e.EXAMPLE_TYPES, "text": True, "pinned_by": "owner",
    }
    check("control: the owner names Sam", net.put_rules("ana", net.sign_rules("ana", [contact]))[0] == 200)

    def open_with_sam() -> int:
        return net.agent("ana", "POST", "/v0/requests", offer_to(address))[0]

    answers(fake_id, fake, fake_owner, fake_binding)
    check("a host answering with its own agent and owner finds nobody", open_with_sam() != 200)
    check("and a send won't go to that agent either", net.send_to("ana", address, "for sam only")[0] != 200)
    other_address = accepted(real_owner.bind(real, f"someone~{peer.domain}"), net.work / "real.key")
    answers(real_id, real, real_owner, other_address)
    check("a binding for another address doesn't pass as this one", open_with_sam() != 200)
    answers(real_id, real, fake_owner, fake_binding)
    check("nor does a binding from another owner", open_with_sam() != 200)
    answers(real_id, real, real_owner, real_binding)
    # Signet remembers a failed lookup for a while, and only in memory.
    net.signets["ana"].kill_hard()
    net.signets["ana"].start()
    net.wait_for_signet("ana")
    check("control: the agent the owner named can be reached", open_with_sam() == 200)
    peer.accept_everything()
    net.sign_contact_rules(e2e.OWNED_AGENTS)


class AtAScriptedHost:
    """One address on a host that answers as it's told: with the real agent, or with its own."""

    def __init__(self, net: e2e.Network, handle: str) -> None:
        self.net, self.peer = net, net.scripted_peer
        self.address = f"{handle}~{self.peer.domain}"
        self.real_owner = new_owner(net.work / f"{handle}-real-owner")
        self.real_key, self.fake_key = net.work / f"{handle}-real.key", net.work / f"{handle}-fake.key"
        self.real, self.real_id = new_identity(self.real_key)
        self.fake_owner = new_owner(net.work / f"{handle}-fake-owner")
        self.fake, self.fake_id = new_identity(self.fake_key)

    def _answers(self, agent_id: str, identity: str, key: Path, owner: Owner, address: str) -> None:
        binding = accepted(owner.bind(identity, address), key)
        answer = {"agent_id": agent_id, "identity": identity, "owner_identity": owner.identity, "binding": binding}
        self.peer.respond = lambda _path, _sent: (200, {}, json.dumps(answer).encode())

    def answers_with_the_real_agent(self, address: str | None = None) -> None:
        self._answers(self.real_id, self.real, self.real_key, self.real_owner, address or self.address)

    def answers_with_its_own_agent(self) -> None:
        self._answers(self.fake_id, self.fake, self.fake_key, self.fake_owner, self.address)

    def entry(self, **changes) -> dict:
        return {
            "agent": self.real_id, "address": self.address, "label": "Named",
            "status": "allowed", "types": e2e.EXAMPLE_TYPES, "text": True, "pinned_by": "owner", **changes,
        }

    def sends(self, text: str = "for the agent the owner named", address: str | None = None) -> tuple[int, dict]:
        return self.net.send_to("ana", address or self.address, text)

    def pinned(self) -> str | None:
        """Who ana's Signet has written down for this address."""
        path = self.net.work / "ana" / "contacts.json"
        return json.loads(path.read_text()).get(self.address, {}).get("identity") if path.exists() else None


def a_host_cant_swap_a_named_agent_with_nothing_to_use(net: e2e.Network) -> None:
    """Only `allowed` with something to use, a type, types to agree or words, is a contact, so nobody
    else gets looked up, at any answer. Words alone make one since core's plain conversation."""
    named = AtAScriptedHost(net, "tess")
    entry = named.entry(types=[], text=False, agree_types=False)
    check("control: the owner names an agent with nothing to use", net.put_rules("ana", net.sign_rules("ana", [entry]))[0] == 200)
    named.answers_with_its_own_agent()
    check("a host answering with its own agent finds nobody", named.sends()[0] != 200)
    check("and nothing is pinned", named.pinned() is None)
    named.answers_with_the_real_agent()
    check("the agent the owner named can't be reached with nothing to use", named.sends()[0] == 403)
    check("and still nothing is pinned", named.pinned() is None)
    check("control: the owner turns words on for it", net.put_rules("ana", net.sign_rules("ana", [named.entry(types=[], text=True)]))[0] == 200)
    check("then words alone let it be reached", named.sends()[0] == 200)
    check("and it is the one pinned", named.pinned() == named.real)

    blocked = AtAScriptedHost(net, "bart")
    check("control: the owner blocks a contact", net.put_rules("ana", net.sign_rules("ana", [blocked.entry(status="blocked")]))[0] == 200)
    blocked.answers_with_its_own_agent()
    check("a send to that address is refused outright, without asking the host", blocked.sends()[0] == 403)
    check("and nothing is pinned", blocked.pinned() is None)
    blocked.answers_with_the_real_agent()
    check("a send doesn't reach the blocked agent either", blocked.sends()[0] == 403)
    check("and a request can't be opened with it", net.agent("ana", "POST", "/v0/requests", offer_to(blocked.address))[0] != 200)

    elsewhere = f"bart-elsewhere~{blocked.peer.domain}"
    blocked.answers_with_the_real_agent(elsewhere)
    check("nor does any other address that agent is at", blocked.sends(address=elsewhere)[0] == 403)
    check("control: the owner can lift it", net.put_rules("ana", net.sign_rules("ana", [blocked.entry()]))[0] == 200)
    blocked.answers_with_the_real_agent()
    check("and that address then works", blocked.sends()[0] == 200)
    blocked.peer.accept_everything()
    net.sign_contact_rules(e2e.OWNED_AGENTS)


def the_owners_rules_outrank_an_earlier_pin(net: e2e.Network) -> None:
    """A pin is what a host answered for the agent named then, so a new name outranks it."""
    sam = AtAScriptedHost(net, "pinned-sam")
    named_first = sam.entry(agent=sam.fake_id)
    check("control: the owner names the agent the host answers with", net.put_rules("ana", net.sign_rules("ana", [named_first]))[0] == 200)
    sam.answers_with_its_own_agent()
    check("control: a send pins the host's agent", sam.sends()[0] == 200 and sam.pinned() == sam.fake, sam.pinned())

    check("control: the owner then names the real agent", net.put_rules("ana", net.sign_rules("ana", [sam.entry()]))[0] == 200)
    check("the old pin no longer gets a send", sam.sends()[0] != 200)
    check("or a request", net.agent("ana", "POST", "/v0/requests", offer_to(sam.address))[0] != 200)
    sam.answers_with_the_real_agent()
    check("once the host answers with the agent named, a request opens", net.agent("ana", "POST", "/v0/requests", offer_to(sam.address))[0] == 200)
    status, sent = sam.sends()
    check("and a send goes through", status == 200, sent)
    recipient = payload_of(transport_log.stored_envelope(net, sent["message_id"]))["recipient"]
    check("to the agent the owner named", recipient == sam.real_id, recipient)
    check("who is now the one pinned", sam.pinned() == sam.real)
    sam.peer.accept_everything()
    net.sign_contact_rules(e2e.OWNED_AGENTS)


def a_contact_signed_out_gets_nothing_more_on_an_open_request(net: e2e.Network) -> None:
    """Rules count once signed, so an agent can't go on telling a removed contact when it's free."""
    open_slot = {"terms": {"duration_min": 30, "slots": [hours_from_now(30)]}}

    def counter(request: str) -> int:
        return move(net, "ben", request, "counter", open_slot)[0]

    for how, contacts in (("blocked", [net.contact_entry("ana", "blocked")]), ("removed", [])):
        request = open_request(net, "ana", "ben")
        check(f"control: ben sees the request before ana is {how}", wait_for(net, "ben", request, version=1) is not None)
        check(f"control: ben's owner has ana {how}", net.put_rules("ben", net.sign_rules("ben", contacts))[0] == 200)
        check(f"a {how} contact gets no move", counter(request) == 403)
        check("no decline or cancel either", move(net, "ben", request, "decline", {"reason": "not_interested"})[0] == 403)
        check("so nothing moved on ben's side", view(net, "ben", request).get("version") == 1)
        check("ben can still read it", view(net, "ben", request).get("state") == "offered")
        net.sign_contact_rules(e2e.OWNED_AGENTS)
        check("control: once ana is back the same move works", counter(request) == 200)
        check("and reaches her", wait_for(net, "ana", request, version=2) is not None)

    net.put_rules("ben", net.sign_rules("ben", [net.contact_entry("ana", "blocked")]))
    check("a blocked contact can't be sent free text either", net.send("ben", "ana", "are you free?")[0] == 403)
    net.sign_contact_rules(e2e.OWNED_AGENTS)


def nothing_queued_leaves_after_the_owner_says_stop(net: e2e.Network) -> None:
    """A fooled agent's move can be waiting for a host when its owner reacts. It stays where it is."""
    ana = net.contact_entry("ana")
    owner = net.owners["ben"]

    def short_rules() -> str:
        now = int(time.time())
        return forged_rules(net, owner.key, owner.id, "ben", [ana], issued_at=now, ends_at=now + EXPIRES_IN_SECONDS)

    stops = {
        "pauses": lambda: net.sign_rules("ben", [ana], paused=True),
        "lets the rules run out": short_rules,
        "blocks the contact": lambda: net.sign_rules("ben", [net.contact_entry("ana", "blocked")]),
        "removes the contact": lambda: net.sign_rules("ben", []),
    }
    for how, stop in stops.items():
        request = open_request(net, "ana", "ben")
        check(f"control: ben sees the request before his owner {how}", wait_for(net, "ben", request, version=1) is not None)
        net.hosts["b"].kill_hard()
        status = move(net, "ben", request, "counter", {"terms": {"duration_min": 30, "slots": [hours_from_now(30)]}})[0]
        check("control: ben's move is signed and waits for his host", status == 200, status)
        status, answer = net.put_rules("ben", stop())
        check(f"control: his owner {how}", status == 200, (status, answer))
        # Short rules count until they run out, so the host can't be back before they have.
        if stop is short_rules:
            check("control: and they have", wait_until(lambda: net.send("ben", "ana", "still in force?")[0] == 403))
        net.hosts["b"].start()
        check("control: his host is back", net.wait_for_host("b"))
        left = wait_until(lambda: view(net, "ana", request).get("version") == 2, timeout=LONG_ENOUGH_TO_HAVE_LEFT)
        check("the waiting move stays where it is", not left)
        net.put_rules("ben", net.sign_rules("ben", [ana]))
        check("control: it goes once the owner lifts that", wait_for(net, "ana", request, version=2) is not None)

    # An owner can still decide during a pause, but that's held with the rest of the agent's traffic.
    request = open_request(net, "ana", "ben")
    check("control: ben sees it", wait_for(net, "ben", request, version=1) is not None)
    check("control: ben accepts", move(net, "ben", request, "accept", {"pick": {"start": view(net, "ben", request)["terms"]["slots"][0]}})[0] == 200)
    check("control: ana sees that", wait_for(net, "ana", request, state="accepted") is not None)
    net.put_rules("ana", net.sign_rules("ana", [net.contact_entry("ben")], paused=True))
    status = owner_decides(net, "ana", request)[0]
    check("an owner can still decide during a pause", status == 200, status)

    def at_ben() -> str | None:
        return view(net, "ben", request)["delivery"]["head"]

    before = at_ben()
    check("and it waits with everything else", not wait_until(lambda: at_ben() != before, timeout=LONG_ENOUGH_TO_HAVE_LEFT))
    net.put_rules("ana", net.sign_rules("ana", [net.contact_entry("ben")]))
    check("control: until the pause lifts", wait_until(lambda: at_ben() != before))
    net.sign_contact_rules(e2e.OWNED_AGENTS)


def a_retired_agent_is_finished(net: e2e.Network) -> None:
    url, process = net.extra_signet("rita", net.domain["a"])
    who = who_is(url)
    owner, agent_id = net.owners["rita"], who["agent_id"]
    retire = f"http://{net.domain['a']}/v0/retirements"
    agent_key = net.work / "rita" / "agent.key"
    send = {"to": net.address("ben"), "body": "still working"}
    token = e2e.EXTRA_SIGNET_TOKEN
    net.extra_rules("rita", url, [net.contact_entry("ben")])
    bens_contacts = [net.contact_entry(other) for other in e2e.OWNED_AGENTS if other != "ben"]
    rita = e2e.named_at(who["address"], agent_id)
    net.put_rules("ben", net.sign_rules("ben", [*bens_contacts, rita]))
    check("control: it can send", http("POST", f"{url}/v0/send", send, token)[0] == 200)
    check("control: and that reached its contact", wait_until(lambda: "still working" in net.bodies("ben")))
    net.ack_all("ben")

    net.hosts["b"].kill_hard()
    queued = [
        http("POST", f"{url}/v0/send", {"to": net.address("ben"), "body": body}, token)[1]["message_id"]
        for body in ("queued by whoever stole the key", "held for a peer that's coming back")
    ]
    net.postgres.sql("host_a", f"UPDATE outbound SET status = 'peer_removed' WHERE message_id = '{queued[1]}'")

    def retirement(signer: Path, owner_id: str) -> str:
        payload = {"v": 1, "owner": owner_id, "agent": agent_id, "reason": "key_lost", "issued_at": int(time.time())}
        return sign_jws(signer, "splint-retirement", json.dumps(payload).encode())

    mallory = net.owners["mallory"]
    check("a stolen agent key can't retire it", http("POST", retire, {"retirement": retirement(agent_key, owner.id)})[0] == 400)
    check("nor can another owner, naming the real one", http("POST", retire, {"retirement": retirement(mallory.key, owner.id)})[0] == 400)
    check("or naming themselves", http("POST", retire, {"retirement": retirement(mallory.key, mallory.id)})[0] == 400)
    check("control: it's still on the host", resolved(net, "rita")[0] == 200)

    signed = owner.sign("retire", "--agent", agent_id, "--reason", "key_lost")
    check("control: its owner can", http("POST", retire, {"retirement": signed})[0] == 200)
    check("and nobody can find it now", resolved(net, "rita")[0] == 404)

    def left_on_the_host(message_id: str) -> str:
        return net.postgres.sql("host_a", f"SELECT status || ':' || envelope FROM outbound WHERE message_id = '{message_id}'")

    net.hosts["b"].start()
    check("control: the next host is back", net.wait_for_host("b"))
    check("control: and delivery is running", net.send_and_wait("ana", "ben", "after rita retired") is not None)
    net.retry_now(net.domain["b"])
    check("control: with a moment to send anything left", not wait_until(lambda: "queued by whoever stole the key" in net.bodies("ben"), timeout=LONG_ENOUGH_TO_HAVE_LEFT))
    left = [left_on_the_host(message_id) for message_id in queued]
    check("what it queued before the stop signal doesn't go out", left == ["retired:", "retired:"], left)
    net.ack_all("ben")
    check("it can't send, even with its key", http("POST", f"{url}/v0/send", send, token)[0] != 200)
    check("or read its inbox", http("GET", f"{url}/v0/inbox", token=token)[0] != 200)
    process.kill_hard()
    process.start()
    # Bug caught: a retired agent's Signet stopping at start as if something failed, started again and
    # again by whatever keeps it running. It can't come back: it stays up only to say it's retired.
    check("and it can't come back: started again, its Signet says it's retired and sends nothing",
          wait_until(lambda: who_is(url).get("stopped") == "retired") and http("POST", f"{url}/v0/send", send, token)[0] == 403,
          who_is(url) if not process.has_exited() else "it stopped")
    process.kill_hard()
    net.sign_contact_rules(e2e.OWNED_AGENTS)


def a_send_caught_by_a_retirement_loses(net: e2e.Network) -> None:
    """A send checks the agent, then stores its message. A retirement can commit in between."""
    url, process = net.extra_signet("rosa", net.domain["a"])
    agent_id = who_is(url)["agent_id"]
    send = {"to": net.address("ben"), "body": "sent while the owner was retiring it"}
    token = e2e.EXTRA_SIGNET_TOKEN
    net.extra_rules("rosa", url, [net.contact_entry("ben")])
    check("control: it can send", http("POST", f"{url}/v0/send", send, token)[0] == 200)

    def queued_here() -> str:
        return net.postgres.sql("host_a", f"SELECT count(*) FROM outbound WHERE sender = '{agent_id}'")

    before = queued_here()
    # Holds the agent's row as a retirement does, so the send's first look still finds it active.
    retiring = threading.Thread(target=net.postgres.sql, args=(
        "host_a", f"BEGIN; UPDATE agents SET retirement = 'retiring' WHERE id = '{agent_id}'; SELECT pg_sleep(2); COMMIT;",
    ))
    retiring.start()
    under_way = "SELECT count(*) FROM pg_stat_activity WHERE query LIKE 'BEGIN; UPDATE agents%' AND state = 'active'"
    check("control: the retirement is under way", wait_until(lambda: net.postgres.sql("host_a", under_way) == "1"))
    status = http("POST", f"{url}/v0/send", send, token)[0]
    retiring.join()
    check("the send is refused", status != 200, status)
    check("and left nothing queued that the retirement would have missed", queued_here() == before, queued_here())
    process.kill_hard()


def an_owner_key_stays_on_the_owners_device(net: e2e.Network) -> None:
    def forms(secret: bytes) -> list[bytes]:
        return [secret, e2e.encode(secret).encode(), base64.b64encode(secret), secret.hex().encode()]

    tables = "\n".join(
        net.postgres.sql(f"host_{name}", "SELECT * FROM agents")
        + net.postgres.sql(f"host_{name}", "SELECT * FROM inbox")
        + net.postgres.sql(f"host_{name}", "SELECT * FROM request_steps")
        for name in net.hosts
    ).encode()
    signet_files = b"".join(
        path.read_bytes()
        for agent in net.signets
        for path in (net.work / agent).rglob("*")
        if path.is_file()
    )
    answers = json.dumps([net.agent(agent, "GET", "/v0/identity")[1] for agent in net.signets]).encode()
    approvals = json.dumps(owner_call(net, "ana", "/v0/owner/approvals")[1]).encode()
    environments = json.dumps([dict(process.env) for process in net.signets.values()]).encode()
    seen_by_host_or_agent = [net.process_logs(), tables, signet_files, answers, approvals, environments]

    check("control: the scan reads what a host stores", net.owners["ana"].identity.encode() in tables)
    check("control: and what Signet keeps", any(form in signet_files for form in forms(net.key_of("ana").read_bytes())))
    agent_backups = [Path(backup["file"]).read_bytes() for backup in net.agent_backups.values()]
    check("control: every agent here has a backup on its owner's device", len(agent_backups) >= len(net.signets))
    leaked = [
        agent for agent, owner in net.owners.items()
        for secret in (owner.key.read_bytes(), (owner.dir / "backup.key").read_bytes())
        if any(form in place for form in forms(secret) for place in seen_by_host_or_agent)
    ]
    check("no owner key reaches a host, a Signet, a log or an API answer", not leaked, leaked)
    leaked = [secret for secret in agent_backups if any(form in place for form in forms(secret) for place in seen_by_host_or_agent)]
    check("nor does any agent's backup key", not leaked, len(leaked))

    device = new_owner(net.work / "device-owner")
    key_mode = stat.S_IMODE(device.key.stat().st_mode)
    backup_mode = stat.S_IMODE((device.dir / "backup.key").stat().st_mode)
    check("owner key files are readable only by their user", key_mode == backup_mode == 0o600, (key_mode, backup_mode))
    check("and so is their directory", stat.S_IMODE(device.dir.stat().st_mode) == 0o700)
    again = owner_key_tool("init", "--dir", str(device.dir))
    check("making an owner key twice is refused, so one can't be lost by accident", again.returncode != 0, again.stdout)
    check("and the key is untouched", device.sign("show").startswith(f"owner id: {device.id}"))

    outputs = (owner_key_tool("show", "--dir", str(device.dir)), again)
    secret = device.key.read_bytes()
    printed = "".join(done.stdout + done.stderr for done in outputs).encode()
    check("the tool never prints a key", not any(form in printed for form in forms(secret)))

    backup = device.sign("check-backup", "--backup", str(device.dir / "backup.key"))
    check("control: the backup checks out", "matches" in backup, backup)
    wrong = owner_key_tool("check-backup", "--dir", str(device.dir), "--backup", str(net.owners["ana"].dir / "backup.key"))
    check("another backup doesn't", wrong.returncode != 0, wrong.stdout)
    check("the ID hashes the identity the tool made", device.id == "splint1" + hashlib.sha256(e2e.decode(device.identity)).hexdigest())


def main() -> int:
    e2e.build()
    with e2e.running_network(owned=True) as network:
        for scenario in (
            an_owner_puts_an_agent_on_a_host,
            a_fooled_agent_cant_bind_itself,
            a_captured_registration_cant_lock_an_owner_out,
            a_stranger_cant_claim_a_handle,
            a_rule_change_needs_the_owners_signature,
            a_pause_holds_until_the_owner_lifts_it,
            a_new_request_waits_out_a_stop,
            an_inbox_read_cant_lose_a_step,
            an_owner_sees_who_they_are_approving,
            a_hostile_host_cant_swap_a_contact,
            a_host_cant_swap_a_named_agent_with_nothing_to_use,
            the_owners_rules_outrank_an_earlier_pin,
            a_contact_signed_out_gets_nothing_more_on_an_open_request,
            nothing_queued_leaves_after_the_owner_says_stop,
            a_retired_agent_is_finished,
            a_send_caught_by_a_retirement_loses,
            an_owner_key_stays_on_the_owners_device,
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

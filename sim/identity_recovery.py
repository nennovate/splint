#!/usr/bin/env python3
"""One kind of ID, recovered and transferred, with the thief and the fooled agent assumed real.

An ID stays the same when its key is lost or stolen, and when its agent gets a new owner. Everything
here runs the real hosts, Signets and owner tool. The keys are software files, so "stolen" means a copy
of the file, which is what a breached machine gives up.
"""

import json
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import e2e
from e2e import Owner, accepted, check, http, new_owner, owner_key_tool, sign_jws, wait_until
from request_driver import draft_for, host_chain, hours_from_now, meeting_ask, move, open_request, owner_call, post_approval, sign_approval, view, wait_for


public_of = e2e.public_of


def event_of(identity: str) -> bytes:
    return e2e.decode(identity.split("~")[0])


def forged_recovery(identity: str, signer: Path, names_backup: str, new_key: str) -> str:
    """A recovery as a thief would write one: it names a backup, and signs with what they have."""
    event = event_of(identity)
    payload = {
        "v": 2, "id": "splint1" + e2e.hashlib.sha256(event).hexdigest(), "seq": 1,
        "prev": e2e.hashlib.sha256(event).hexdigest(), "backup": names_backup, "key": new_key,
        "seal": e2e.seal_public_of(signer),
        "recovery": {"rule": "backup_key", "commitment": "ab" * 32}, "issued_at": int(time.time()),
    }
    return f"{identity}~" + sign_jws(signer, "splint-recovery", json.dumps(payload, separators=(",", ":")).encode())


def recovered_on_a_new_device(net: e2e.Network, name: str, identity: str, backup: Path, token: str) -> Owner:
    directory = net.work / f"{name}-recovered"
    done = owner_key_tool("recover", "--dir", str(directory), "--identity", identity, "--backup", str(backup))
    if done.returncode != 0:
        raise RuntimeError(f"recovery failed: {done.stderr}")
    found = dict(line.split(": ", 1) for line in done.stdout.splitlines())
    return Owner(directory, directory / "owner.key", found["owner identity"], found["owner id"], token)


def has_on_file(net: e2e.Network, agent: str, other: str) -> bool:
    path = net.work / agent / "seen-changes.json"
    return path.exists() and net.ids[other] in json.loads(path.read_text())


def a_pair(net: e2e.Network, first: str, second: str) -> None:
    """Two agents whose owners have listed each other, each with a copy of the other's history, which
    is what a later change gets compared with."""
    net.add_owned_agents({first: "a", second: "b"})
    if not wait_until(lambda: has_on_file(net, first, second) and has_on_file(net, second, first)):
        raise RuntimeError(f"{first} and {second} never asked after each other")


def resolved(net: e2e.Network, agent: str) -> tuple[int, dict]:
    handle, domain = net.address(agent).split("~")
    return http("GET", f"http://{domain}/.well-known/splint/agents/{handle}")


def who(net: e2e.Network, agent: str) -> dict:
    return net.agent(agent, "GET", "/v0/identity")[1]


def recovery(net: e2e.Network, agent: str, identity: str) -> tuple[int, dict]:
    return net.agent(agent, "PUT", "/v0/owner/recovery", {"identity": identity})


def tell_host(net: e2e.Network, agent: str, identity: str) -> int:
    return http("POST", f"http://{net.domain[net.home[agent]]}/v0/recoveries", {"identity": identity})[0]


def contact_of(net: e2e.Network, agent: str, other: str) -> dict:
    return json.loads((net.work / agent / "contacts.json").read_text()).get(net.address(other), {})


def changes_on_file(net: e2e.Network, agent: str, other: str) -> dict:
    url = f"http://127.0.0.1:{net.signet_port[agent]}/v0/owner/changes"
    entries = http("GET", url, token=net.owners[agent].token)[1]["changes"]
    return next((entry for entry in entries if entry["contact"] == net.ids[other]), {})


def warnings_on(net: e2e.Network, agent: str, body: str) -> set[str]:
    """The warnings in Signet's facts beside the note with these words in this agent's inbox."""
    return next((set(one.get("facts", {}).get("warnings", [])) for one in net.inbox(agent)["messages"] if one["untrusted"]["body"] == body), set())


def owner_accepts_the_change(net: e2e.Network, agent: str, other: str) -> None:
    """A contact's key or owner changed, so this agent's owner is asked, and says yes."""
    heard = wait_until(lambda: changes_on_file(net, agent, other).get("standing") == "ask")
    check(f"{agent}'s owner is asked about {other}", heard, changes_on_file(net, agent, other))
    head = changes_on_file(net, agent, other).get("head", "")
    signed = net.owners[agent].sign("accept-change", "--agent", net.ids[agent], "--contact", net.ids[other], "--head", head)
    status, answer = net.agent(agent, "POST", "/v0/owner/changes/accept", {"acceptance": signed})
    check("and says yes to exactly that", status == 200, answer)


def thief_cant_recover(net: e2e.Network, agent: str, identity: str, stolen: Path, real_backup: Path) -> None:
    """Everything someone holding the key, and nothing else, could try."""
    thief_dir = net.work / f"{agent}-thief-{stolen.stem}"
    done = owner_key_tool("recover", "--dir", str(thief_dir), "--identity", identity, "--backup", str(stolen))
    check("a thief's tool won't recover with the key they stole", done.returncode != 0, done.stdout)
    thief_key = public_of(stolen)
    for how, forged in (
        ("naming the key they stole as the backup", forged_recovery(identity, stolen, thief_key, thief_key)),
        ("naming the real backup, without holding it", forged_recovery(identity, stolen, public_of(real_backup), thief_key)),
    ):
        check(f"a host refuses a recovery {how}", tell_host(net, agent, forged) == 400)
        check("and so does a Signet", recovery(net, agent, forged)[0] == 403)
    event = who(net, agent)["identity"]
    check("so the ID's key hasn't moved", who(net, agent)["recovering"] is False and event.count("~") == identity.count("~"), event)


def an_owner_recovers_from_a_stolen_key(net: e2e.Network) -> None:
    a_pair(net, "nora", "owen")
    owner = net.owners["nora"]
    nora_id = net.ids["nora"]
    net.send_and_wait("nora", "owen", "before anything was stolen")
    net.send_and_wait("owen", "nora", "and back")
    net.ack_all("owen")
    net.ack_all("nora")
    request = open_request(net, "owen", "nora")
    check("control: an interaction is under way", wait_for(net, "nora", request, state="offered") is not None)
    check("control: and accepted", move(net, "nora", request, "accept", {"pick": {"start": view(net, "nora", request)["terms"]["slots"][0]}})[0] == 200)
    check("control: on both sides", wait_for(net, "owen", request, state="accepted") is not None)
    owens = net.owners["owen"]
    check("control: its requester's owner signs", post_approval(net, "owen", owens.sign("approve", "--decision", "approve", stdin=json.dumps(draft_for(net, "owen", request))))[0] == 200)
    check("control: and that reaches nora", wait_for(net, "nora", request, state="requester_confirmed") is not None, view(net, "nora", request))

    # A thief copies the owner's key file off the old device. The backup was moved away at setup.
    stolen = net.work / "stolen-owner.key"
    shutil.copy(owner.key, stolen)
    stolen.chmod(0o600)
    backup = owner.dir / "backup.key"
    thief_cant_recover(net, "nora", owner.identity, stolen, backup)

    # What a stolen key can do until the owner reacts is real, so it has to stop when they do.
    mallory_contact = net.contact_entry("mallory")
    thiefs_rules = owner.sign("rules", "--agent", nora_id, stdin=json.dumps(e2e.rules_draft([net.contact_entry("owen"), mallory_contact])))
    check("control: until the owner reacts, the stolen key signs rules that count", net.put_rules("nora", thiefs_rules)[0] == 200)
    # A thief dates a statement as far ahead as a host will store, so the real owner's would look old.
    # The agent's backup is on the same device as the owner key, so they take that too.
    far_ahead = {"v": 2, "owner": owner.id, "agent": nora_id, "address": net.address("nora"), "seq": 2**62, "issued_at": int(time.time())}
    thiefs_binding = sign_jws(stolen, "splint-binding", e2e.compact_json(far_ahead))
    agent_backup = Path(net.agent_backups["nora"]["file"])
    vouch = sign_jws(agent_backup, "splint-binding-vouch", e2e.compact_json({"v": 2, "agent": nora_id, "owner": owner.id, "backup": public_of(agent_backup), "keys": e2e.first_keys_of(net.agent("nora", "GET", "/v0/identity")[1]["identity"])}))
    check("control: and a binding, dated far ahead", net.agent("nora", "PUT", "/v0/owner/binding", {"binding": f"{thiefs_binding}~{vouch}"})[0] == 200)
    net.send_and_wait("nora", "owen", "with the thief's binding")
    net.ack_all("owen")
    check("control: which a contact has taken in", contact_of(net, "owen", "nora").get("binding", "").startswith(thiefs_binding), contact_of(net, "owen", "nora"))
    draft = draft_for(net, "nora", request)
    def person_text_of(signer: Owner, words: str) -> dict:
        return {"person_text": signer.sign("person-text", "--agent", nora_id, "--to", net.ids["owen"], stdin=words)}

    check("control: and words in a person's name, held for the next open", net.agent("nora", "POST", "/v0/owner/person-text", person_text_of(owner, "the thief's words"))[0] == 200)

    new = recovered_on_a_new_device(net, "nora", owner.identity, backup, owner.token)
    check("the recovered owner has the same ID", new.id == owner.id, new.id)
    check("with a new key", public_of(new.key) != public_of(owner.key))
    check("and a new backup", (new.dir / "backup.key").exists())
    check("the old backup can't recover the new identity", owner_key_tool("recover", "--dir", str(net.work / "nora-twice"), "--identity", new.identity, "--backup", str(backup)).returncode != 0)

    status, taken = recovery(net, "nora", new.identity)
    check("its Signet takes the recovery", status == 200 and taken["id"] == owner.id, taken)
    check("and says what has to be signed again", taken["needs"] == ["binding", "rules"], taken)
    net.owners["nora"] = new

    def old_key_signs(*arguments: str, stdin: str | None = None) -> str:
        return owner.sign(*arguments, stdin=stdin)

    check("rules from the stolen key are refused by Signet", net.put_rules("nora", old_key_signs("rules", "--agent", nora_id, stdin=json.dumps(e2e.rules_draft([mallory_contact]))))[0] == 403)
    host_rules = f"http://{net.domain['a']}/v0/rules"
    check("and by the host", http("PUT", host_rules, {"rules": old_key_signs("rules", "--agent", nora_id, stdin=json.dumps(e2e.rules_draft([mallory_contact])))})[0] == 400)
    binding = old_key_signs("bind", "--agent", who(net, "nora")["identity"], "--address", net.address("nora"), "--backup", str(agent_backup))
    check("a binding from the stolen key is refused", net.agent("nora", "PUT", "/v0/owner/binding", {"binding": binding})[0] == 403)
    retire = old_key_signs("retire", "--agent", nora_id, "--reason", "finished")
    check("the stolen key can't retire the agent any more", http("POST", f"http://{net.domain['a']}/v0/retirements", {"retirement": retire})[0] == 400)
    revoke = old_key_signs("revoke", "--agent", nora_id)
    check("or revoke it", http("POST", f"http://{net.domain['a']}/v0/revocations", {"revocation": revoke})[0] == 400)
    stale_approval = owner_key_tool("approve", "--dir", str(owner.dir), "--decision", "approve", stdin=json.dumps(draft))
    check("or agree to anything", stale_approval.returncode == 0 and post_approval(net, "nora", stale_approval.stdout.strip())[0] != 200)
    check("or write in a person's name", net.agent("nora", "POST", "/v0/owner/person-text", person_text_of(owner, "the thief again"))[1].get("error") == "bad_person_text")
    check("what the thief's rules let in is gone", net.send_to("nora", net.address("mallory"), "from the thief's rules")[0] == 403)
    check("and until the owner signs again the agent can't send to anyone", net.send("nora", "owen", "too soon")[0] == 403)
    owner_accepts_the_change(net, "owen", "nora")
    owens = net.send("owen", "nora", "while nora was recovering")
    check("control: a contact can still send", owens[0] == 200, owens)
    check("what they send waits at the host for the owner", wait_until(lambda: net.postgres.sql("host_a", f"SELECT count(*) FROM quarantine WHERE recipient = '{nora_id}'") == "1"))

    net.bind("nora")
    contacts = [net.contact_entry("owen")]
    check("the new key signs new rules", net.put_rules("nora", net.sign_rules("nora", contacts))[0] == 200)
    check("the ID is unchanged", who(net, "nora")["agent_id"] == nora_id and resolved(net, "nora")[1]["owner_identity"] == new.identity, resolved(net, "nora")[1])
    check("what waited is delivered", wait_until(lambda: "while nora was recovering" in net.bodies("nora")), net.inbox("nora"))
    net.ack_all("nora")
    # Owen's owner signed one yes since this ID's key changed, and no new rules.
    net.send_and_wait("nora", "owen", "after recovering")
    # Bug caught: a recovered owner key said as `key_changed_recently`, the words for their agent's.
    check("beside it, owen's Signet warns that nora's owner changed recently, not her agent's key", warnings_on(net, "owen", "after recovering") >= {"owner_changed_recently"} and "key_changed_recently" not in warnings_on(net, "owen", "after recovering"), warnings_on(net, "owen", "after recovering"))
    net.ack_all("owen")
    known = json.loads((net.work / "owen" / "known.json").read_text()) if (net.work / "owen" / "known.json").exists() else {}
    check("and that contact has learned the new key, from the message", known.get(owner.id) == new.identity, known)
    pinned = contact_of(net, "owen", "nora").get("binding", "")
    check("and the new statement, over the thief's dated far ahead", pinned.split("~")[0] == resolved(net, "nora")[1]["binding"].split("~")[0] and not pinned.startswith(thiefs_binding), pinned[:40])

    opened_since = open_request(net, "nora", "owen")
    check("and words the old key left waiting don't go out", "person_texts" not in (wait_for(net, "owen", opened_since, state="offered") or {"person_texts": []}), view(net, "owen", opened_since))

    # The interaction that was under way carries on, and what the old key signed for it still counts.
    draft = draft_for(net, "nora", request)
    check("the interaction asks the owner, under the same ID", draft is not None and draft["owner"] == owner.id, draft)
    check("the new key agrees", post_approval(net, "nora", new.sign("approve", "--decision", "approve", stdin=json.dumps(draft)))[0] == 200)
    check("and it completes on both sides", wait_for(net, "owen", request, state="completed") is not None and wait_for(net, "nora", request, state="completed") is not None, view(net, "owen", request))
    outcome = owner_call(net, "owen", f"/v0/owner/requests/{request}/outcome")
    check("with a result its contact can prove", outcome[0] == 200 and outcome[1]["assurance"] == "owner", outcome)

    check("hearing the recovery again changes nothing", recovery(net, "nora", new.identity)[0] == 200 and net.send("nora", "owen", "rules survive")[0] == 200)
    check("an older copy is refused by Signet", recovery(net, "nora", owner.identity)[0] == 403)
    check("and by the host", tell_host(net, "nora", owner.identity) == 403)

    net.signets["nora"].kill_hard()
    net.signets["nora"].start()
    net.wait_for_signet("nora")
    check("a restart keeps it all, whatever its settings still say", who(net, "nora")["agent_id"] == nora_id and net.send("nora", "owen", "after a restart")[0] == 200)
    check("control: and those settings do still name the old copy", net.signets["nora"].env["SPLINT_OWNER_IDENTITY"] == owner.identity)

    again = recovered_on_a_new_device(net, "nora-2", new.identity, new.dir / "backup.key", owner.token)
    check("the next backup works in its turn", again.id == owner.id and recovery(net, "nora", again.identity)[0] == 200)


def an_agent_recovers_from_a_stolen_key(net: e2e.Network) -> None:
    a_pair(net, "pia", "quin")
    owner, pia_id = net.owners["pia"], net.ids["pia"]
    identity = who(net, "pia")["identity"]
    state = net.work / "pia"
    backup = Path(net.agent_backups["pia"]["file"])
    check("the agent's backup is on the owner's device", backup.is_relative_to(owner.dir))
    check("and nothing in its Signet's folder can recover it", all(path.read_bytes() != backup.read_bytes() for path in state.rglob("*") if path.is_file()))
    check("the owner can test that backup", owner_key_tool("check-backup", "--dir", str(owner.dir), "--agent", identity, "--backup", str(backup)).returncode == 0)

    request = open_request(net, "pia", "quin")
    check("control: an interaction is under way", wait_for(net, "quin", request, state="offered") is not None)
    check("control: and moves", move(net, "quin", request, "accept", {"pick": {"start": view(net, "quin", request)["terms"]["slots"][0]}})[0] == 200)
    check("control: on both sides", wait_for(net, "pia", request, state="accepted") is not None)

    stolen = net.work / "stolen-agent.key"
    shutil.copy(net.key_of("pia"), stolen)
    stolen.chmod(0o600)
    old_identity, old_key = identity, who(net, "pia")["key"]
    thief_cant_recover(net, "pia", identity, stolen, backup)

    # A message the thief queues while the next host is down has to end with the key.
    net.hosts["b"].kill_hard()
    queued = net.send("pia", "quin", "queued by whoever stole the key")[1]["message_id"]
    net.signets["pia"].kill_hard()
    net.key_of("pia").unlink()
    # Only a start told it's taking up this ID makes a key in place of the one that's gone.
    net.signets["pia"].env["SPLINT_RECOVERING"] = identity
    net.signets["pia"].start()
    net.wait_for_signet("pia")
    waiting = who(net, "pia")
    check("a Signet with a new key waits for a recovery", waiting["recovering"] is True and waiting["key"] != old_key, waiting)
    check("it keeps its ID", waiting["agent_id"] == pia_id)
    check("and signs nothing meanwhile", net.send("pia", "quin", "too soon")[0] == 403 and net.agent("pia", "POST", "/v0/requests", meeting_ask(net.address("quin")))[0] == 403)

    def recover_to(new_key: str) -> dict:
        return json.loads(owner.sign("recover-agent", "--agent", identity, "--backup", str(backup), "--new-key", new_key))

    someone_elses = recover_to(old_key)
    check("a recovery naming another key isn't for this Signet", recovery(net, "pia", someone_elses["identity"])[0] == 403)
    made = recover_to(waiting["key"])
    status, taken = recovery(net, "pia", made["identity"])
    check("a recovery naming its key puts it back", status == 200 and taken["needs"] == [], taken)
    net.agent_backups["pia"] = {"file": made["file"]}
    now = who(net, "pia")
    check("with the same ID", now["agent_id"] == pia_id and now["recovering"] is False and now["registered"] is True, now)
    check("and the host agrees", resolved(net, "pia")[1]["identity"] == made["identity"], resolved(net, "pia")[1])

    left = net.postgres.sql("host_a", f"SELECT status || ':' || envelope FROM outbound WHERE message_id = '{queued}'")
    check("what the old key queued ended with it", left == "retired:", left)
    net.hosts["b"].start()
    check("control: the next host is back", net.wait_for_host("b"))

    # The old key is no use to anyone now.
    check("control: the new key can read the inbox", http("GET", f"http://{net.domain['a']}/v0/inbox", auth=net.access_proof("pia", "pia", "GET", "/v0/inbox"))[0] == 200)
    old_proof = {"signer": pia_id, "host": net.domain["a"], "method": "GET", "path": "/v0/inbox", "body_sha256": e2e.hashlib.sha256(b"").hexdigest(), "issued_at": int(time.time())}
    check("the stolen key can't", http("GET", f"http://{net.domain['a']}/v0/inbox", auth=sign_jws(stolen, "splint-access", json.dumps(old_proof).encode()))[0] == 401)
    forged = e2e.signed_envelope(stolen, pia_id, net.ids["quin"], "from the stolen key, after the recovery")
    outbound = http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": forged, "recipient_host": net.domain["b"]})[0]
    check("its host won't send for it", outbound == 400, outbound)
    binding = owner.sign("bind", "--agent", old_identity, "--address", net.address("pia"), "--backup", str(backup))
    stale = accepted(binding, stolen)
    body = json.dumps({"owner_identity": owner.identity, "agent_identity": old_identity, "binding": stale, **e2e.signup_fields(next(net.signup_codes), stale)}).encode()
    proof = {"signer": pia_id, "host": net.domain["a"], "method": "POST", "path": "/v0/agents", "body_sha256": e2e.hashlib.sha256(body).hexdigest(), "issued_at": int(time.time())}
    check("and an older copy of its identity can't register it back", http("POST", f"http://{net.domain['a']}/v0/agents", raw=body, auth=sign_jws(stolen, "splint-access", json.dumps(proof).encode()))[0] == 423)
    check("a host can't undo it by showing the older copy", tell_host(net, "pia", old_identity) == 403)
    check("nor can anyone tell its Signet that", recovery(net, "pia", old_identity)[0] == 403)

    # Quin's owner signed one yes since this ID's key changed, and no new rules.
    owner_accepts_the_change(net, "quin", "pia")
    net.send_and_wait("pia", "quin", "from the new key")
    check("beside it, quin's Signet warns that pia's agent key changed recently", "key_changed_recently" in warnings_on(net, "quin", "from the new key"), warnings_on(net, "quin", "from the new key"))
    net.ack_all("quin")
    net.send_and_wait("quin", "pia", "still reaches the same ID")
    net.ack_all("pia")

    # A contact that's heard of the recovery won't take the old key, whatever a host shows it.
    columns = "recipient, message_id, envelope, sender_identity"
    net.postgres.sql("host_b", f"INSERT INTO inbox ({columns}) VALUES ('{net.ids['quin']}', 'after-recovery', '{forged}', '{old_identity}')")
    page = net.inbox("quin")
    check("a contact refuses the stolen key, with the old identity beside it", page["messages"] == [] and page["dropped"] == 1, page)

    # What was signed before goes on counting as history.
    check("the interaction carries on", (found := draft_for(net, "pia", request)) is not None, found)
    status, _ = post_approval(net, "pia", owner.sign("approve", "--decision", "approve", stdin=json.dumps(draft_for(net, "pia", request))))
    check("its owner signs on it", status == 200, status)
    check("the contact takes the step", wait_for(net, "quin", request, state="requester_confirmed") is not None, view(net, "quin", request))
    quins = net.owners["quin"]
    status, _ = post_approval(net, "quin", quins.sign("approve", "--decision", "approve", stdin=json.dumps(draft_for(net, "quin", request))))
    check("and its owner signs too", status == 200, status)
    check("to the end, on both sides", wait_for(net, "quin", request, state="completed") is not None and wait_for(net, "pia", request, state="completed") is not None, view(net, "pia", request))
    outcome = owner_call(net, "pia", f"/v0/owner/requests/{request}/outcome")
    check("and the result can be proved, across the recovery", outcome[0] == 200 and outcome[1]["assurance"] == "owner", outcome)


def a_lost_signet_comes_back_with_the_same_id(net: e2e.Network) -> None:
    """Everything in its folder is gone, so all it has is what the owner has written down."""
    a_pair(net, "rae", "sol")
    owner, rae_id = net.owners["rae"], net.ids["rae"]
    identity = who(net, "rae")["identity"]
    old = net.signets["rae"]
    old.kill_hard()
    shutil.rmtree(net.work / "rae")
    (net.work / "rae").mkdir()
    env = {name: value for name, value in old.env.items() if name.startswith("SPLINT_")}
    env["SPLINT_RECOVERING"] = identity
    del env["SPLINT_RECOVERY_COMMITMENT"]
    net.signets["rae"] = net.spawn("signet", "signet-rae-back", env)
    net.wait_for_signet("rae")
    waiting = who(net, "rae")
    check("a new Signet takes up the ID", waiting["agent_id"] == rae_id and waiting["recovering"] is True, waiting)
    made = json.loads(owner.sign("recover-agent", "--agent", identity, "--backup", net.agent_backups["rae"]["file"], "--new-key", waiting["key"]))
    status, taken = recovery(net, "rae", made["identity"])
    check("a recovery puts it back", status == 200, taken)
    net.agent_backups["rae"] = {"file": made["file"]}
    check("it's the same ID", who(net, "rae")["agent_id"] == rae_id and who(net, "rae")["recovering"] is False)
    net.bind("rae")
    check("it binds again without a new signup code", who(net, "rae")["registered"] is True)
    check("and signs its rules", net.put_rules("rae", net.sign_rules("rae", [net.contact_entry("sol")]))[0] == 200)
    owner_accepts_the_change(net, "sol", "rae")
    net.send_and_wait("rae", "sol", "back after losing everything")
    net.send_and_wait("sol", "rae", "still reaching the same ID")
    net.ack_all("sol")
    net.ack_all("rae")


def an_agent_moves_to_a_new_owner(net: e2e.Network) -> None:
    a_pair(net, "tara", "uma")
    old, tara_id = net.owners["tara"], net.ids["tara"]
    address = net.address("tara")
    new = new_owner(net.work / "tara-new-owner")
    mallory = net.owners["mallory"]
    identity = who(net, "tara")["identity"]
    backup = net.agent_backups["tara"]["file"]

    request = open_request(net, "tara", "uma")
    check("control: there's an interaction under the old owner", wait_for(net, "uma", request, state="offered") is not None)
    words = old.sign("person-text", "--agent", tara_id, "--to", net.ids["uma"], stdin="from the old owner")
    check("control: and words of theirs, waiting to go", net.agent("tara", "POST", "/v0/owner/person-text", {"person_text": words})[0] == 200)
    ask_me = e2e.rules_draft([net.contact_entry("uma")], permissions={"level": "ask_me", "actions_per_day": 500, "caps": {}})
    check("control: and at ask me", net.put_rules("tara", old.sign("rules", "--agent", tara_id, stdin=json.dumps(ask_me)))[0] == 200)
    asked = net.agent("tara", "POST", "/v0/requests", {"contact": net.address("uma"), "type": "meeting/1", "terms": {"duration_min": 30, "mode": "video", "purpose": "intro", "slots": [hours_from_now(24)]}, "deadline": hours_from_now(48), "supersedes": None})[1]
    check("control: something its agent asked the old owner", asked.get("waiting_for_owner") is True, asked)
    back = e2e.rules_draft([net.contact_entry("uma")])
    check("control: and back to the default", net.put_rules("tara", old.sign("rules", "--agent", tara_id, stdin=json.dumps(back)))[0] == 200)

    def transfer(body: dict, token: str | None = old.token) -> tuple[int, dict]:
        return http("PUT", f"http://127.0.0.1:{net.signet_port['tara']}/v0/owner/transfer", body, token)

    next_backup = new.new_agent_backup()
    handed = json.loads(old.sign("transfer", "--agent", identity, "--backup", backup, "--to", new.id, "--commitment", next_backup["commitment"]))
    check("the agent's next backup is the new owner's", owner_key_tool("check-backup", "--dir", str(new.dir), "--agent", handed["identity"], "--backup", next_backup["file"]).returncode == 0)
    wrong_backup = owner_key_tool("bind", "--dir", str(new.dir), "--agent", handed["identity"], "--address", address, "--backup", str(new.dir / "backup.key"))
    check("a new owner's tool says if they don't hold what can recover it", wrong_backup.returncode != 0, wrong_backup.stdout)
    binding = new.sign("bind", "--agent", handed["identity"], "--address", address, "--backup", next_backup["file"])
    body = {"identity": handed["identity"], "new_owner_identity": new.identity, "release": handed["release"], "binding": binding}

    check("a fooled agent can't move itself", http("PUT", f"http://127.0.0.1:{net.signet_port['tara']}/v0/owner/transfer", body, net.tokens["tara"])[0] == 401)
    check("the new owner's word alone isn't enough at Signet", net.agent("tara", "PUT", "/v0/owner/binding", {"binding": binding})[0] == 403)
    naming_someone_else = json.loads(old.sign("transfer", "--agent", identity, "--backup", backup, "--to", mallory.id, "--commitment", new.new_agent_backup()["commitment"]))
    check("a release naming someone else doesn't move it", transfer({**body, "release": naming_someone_else["release"]})[0] == 403)
    forged_release = sign_jws(mallory.key, "splint-release", json.dumps({"v": 1, "owner": old.id, "agent": tara_id, "to": new.id, "seq": int(time.time() * 1000), "issued_at": int(time.time())}).encode())
    check("nor one the old owner didn't sign", transfer({**body, "release": forged_release})[0] == 403)
    their_owner_half = mallory.bind(handed["identity"], address)
    check("nor someone else's statement with this release", transfer({**body, "binding": their_owner_half, "new_owner_identity": mallory.identity})[0] == 403)
    elsewhere = new.sign("bind", "--agent", handed["identity"], "--address", f"elsewhere~{net.domain['a']}", "--backup", next_backup["file"])
    check("nor one for another address", transfer({**body, "binding": elsewhere})[0] == 403)
    agent_key = net.key_of("tara")
    # A thief with the agent's key goes straight to the host, with an owner of their own.
    theirs = accepted(mallory.bind(identity, address), agent_key)
    direct = json.dumps({"owner_identity": mallory.identity, "agent_identity": identity, "binding": theirs, **e2e.signup_fields(next(net.signup_codes), theirs)}).encode()
    direct_proof = {"signer": tara_id, "host": net.domain["a"], "method": "POST", "path": "/v0/agents", "body_sha256": e2e.hashlib.sha256(direct).hexdigest(), "issued_at": int(time.time())}
    status = http("POST", f"http://{net.domain['a']}/v0/agents", raw=direct, auth=sign_jws(agent_key, "splint-access", json.dumps(direct_proof).encode()))[0]
    check("a stolen agent key can't move it at the host", status in (400, 403), status)
    check("so far none of that moved it", who(net, "tara")["owner_id"] == old.id and resolved(net, "tara")[1]["owner_identity"] == old.identity)

    status, taken = transfer(body)
    check("with the old owner's release and the new owner's word it moves", status == 200, taken)
    check("and the new owner has rules to sign", taken["needs"] == ["rules"], taken)
    now = who(net, "tara")
    check("its ID hasn't changed", now["agent_id"] == tara_id, now)
    check("it acts for the new owner", now["owner_id"] == new.id, now)
    check("anyone can see that", resolved(net, "tara")[1]["owner_identity"] == new.identity, resolved(net, "tara")[1])
    # Whoever runs this Signet keeps its owner token, which is why a real handover moves to a new Signet.
    net.owners["tara"] = Owner(new.dir, new.key, new.identity, new.id, old.token)
    net.agent_backups["tara"] = next_backup

    check("the new owner doesn't get the old one's interactions", net.agent("tara", "GET", "/v0/requests")[1]["requests"] == [])
    check("or words of theirs to send", json.loads((net.work / "tara" / "person-texts.json").read_text()) == {})
    check("or what its agent asked them", "held_opens" not in net.agent("tara", "GET", "/v0/requests")[1], net.agent("tara", "GET", "/v0/requests")[1])
    check("or their contacts", net.agent("tara", "GET", "/v0/contacts")[1]["contacts"] == [])
    check("the old owner's rules stopped counting", net.send("tara", "uma", "with no rules")[0] == 403)
    check("the old owner can't sign new ones", net.put_rules("tara", old.sign("rules", "--agent", tara_id, stdin=json.dumps(e2e.rules_draft([net.contact_entry("uma")]))))[0] == 403)
    check("or at the host", http("PUT", f"http://{net.domain['a']}/v0/rules", {"rules": old.sign("rules", "--agent", tara_id, stdin=json.dumps(e2e.rules_draft([net.contact_entry("uma")])))})[0] == 400)
    check("or take it back with a binding", net.agent("tara", "PUT", "/v0/owner/binding", {"binding": old.bind(handed["identity"], address)})[0] == 403)
    check("or stop it", http("POST", f"http://{net.domain['a']}/v0/revocations", {"revocation": old.sign("revoke", "--agent", tara_id)})[0] == 400)
    check("or retire it", http("POST", f"http://{net.domain['a']}/v0/retirements", {"retirement": old.sign("retire", "--agent", tara_id, "--reason", "finished")})[0] == 400)
    check("or recover it, with the backup that no longer counts", owner_key_tool("recover-agent", "--dir", str(old.dir), "--agent", handed["identity"], "--backup", backup, "--new-key", who(net, "tara")["key"]).returncode != 0)

    check("the new owner signs rules", net.put_rules("tara", net.sign_rules("tara", [net.contact_entry("uma")]))[0] == 200)
    # Uma's owner signed one yes since this ID's owner changed, and no new rules, which name the ID.
    owner_accepts_the_change(net, "uma", "tara")
    net.send_and_wait("tara", "uma", "from the same ID, under a new owner")
    check("and has heard who it acts for now", contact_of(net, "uma", "tara").get("owner") == new.identity, contact_of(net, "uma", "tara"))
    net.ack_all("uma")
    net.send_and_wait("uma", "tara", "and it still reaches them")
    net.ack_all("tara")

    # What the two agreed under the old owner went with the old owner's interactions, on both sides, so
    # the contact can't open a type the agent no longer holds, which would wait unseen until it expired.
    tara_types = lambda agent, other: net.agent(agent, "GET", f"/v0/types?contact={net.address(other)}")[1].get("types")  # noqa: E731
    check("control: the new owner's agent holds no agreed types", tara_types("tara", "uma") == [], tara_types("tara", "uma"))
    check("and its contact doesn't count the old owner's either", tara_types("uma", "tara") == [], tara_types("uma", "tara"))
    status, refused = net.agent("uma", "POST", "/v0/requests", {"contact": net.address("tara"), "type": e2e.example_id("meeting/1"), "terms": {"duration_min": 30, "mode": "video", "purpose": "intro", "slots": [hours_from_now(24)]}, "deadline": hours_from_now(48), "supersedes": None})
    check("so an open of one is refused at once", status != 200 and refused.get("error") == "unknown_type", (status, refused))
    e2e.forget_agreements(net, "tara")

    # An interaction that takes both owners names the new one.
    request = open_request(net, "uma", "tara")
    check("control: its contact opens something new", wait_for(net, "tara", request, state="offered") is not None)
    check("control: it's accepted", move(net, "tara", request, "accept", {"pick": {"start": view(net, "tara", request)["terms"]["slots"][0]}})[0] == 200)
    check("control: on both sides", wait_for(net, "uma", request, state="accepted") is not None)
    umas = net.owners["uma"]
    check("its contact's owner signs", post_approval(net, "uma", umas.sign("approve", "--decision", "approve", stdin=json.dumps(draft_for(net, "uma", request))))[0] == 200)
    check("control: that arrives", wait_for(net, "tara", request, state="requester_confirmed") is not None, view(net, "tara", request))
    draft = draft_for(net, "tara", request)
    check("the new owner is the one asked", draft["owner"] == new.id, draft)
    check("the old owner's tool won't sign what's asked of the new one", owner_key_tool("approve", "--dir", str(old.dir), "--decision", "approve", stdin=json.dumps(draft)).returncode != 0)
    check("the new owner signs", post_approval(net, "tara", new.sign("approve", "--decision", "approve", stdin=json.dumps(draft)))[0] == 200)
    check("and it completes on both sides", wait_for(net, "uma", request, state="completed") is not None and wait_for(net, "tara", request, state="completed") is not None, view(net, "uma", request))
    outcome = owner_call(net, "uma", f"/v0/owner/requests/{request}/outcome")
    check("with the new owner on the result", outcome[0] == 200 and outcome[1]["terms"]["recipient"]["owner"] == new.id, outcome)


def a_transfer_can_take_the_key_away_from_the_old_owner(net: e2e.Network) -> None:
    """If the old owner ran the Signet, they could keep a copy of its key. So it moves to a new one."""
    a_pair(net, "vera", "wes")
    old, vera_id = net.owners["vera"], net.ids["vera"]
    new = new_owner(net.work / "vera-new-owner")
    new_token = "the-new-owners-token"
    state = net.work / "vera-new-signet"
    state.mkdir()
    previous = net.signets["vera"]
    previous_key = net.key_of("vera")
    env = {name: value for name, value in previous.env.items() if name.startswith("SPLINT_")}
    port = e2e.free_port()
    identity = who(net, "vera")["identity"]
    env.update({
        "SPLINT_STATE_DIR": str(state), "SPLINT_LISTEN": f"127.0.0.1:{port}", "SPLINT_OWNER_TOKEN": new_token,
        "SPLINT_RECOVERING": identity,
    })
    del env["SPLINT_RECOVERY_COMMITMENT"]
    signet = net.spawn("signet", "signet-vera-moved", env)
    url = f"http://127.0.0.1:{port}"
    if not wait_until(lambda: http("GET", f"{url}/v0/identity", token=net.tokens["vera"])[0] == 200):
        raise RuntimeError("the new Signet didn't start")
    shown = http("GET", f"{url}/v0/identity", token=net.tokens["vera"])[1]
    check("the new owner's Signet waits with a key of its own", shown["recovering"] is True and shown["agent_id"] == vera_id, shown)

    next_backup = new.new_agent_backup()
    handed = json.loads(old.sign(
        "transfer", "--agent", identity, "--backup", net.agent_backups["vera"]["file"], "--to", new.id,
        "--commitment", next_backup["commitment"], "--new-key", shown["key"],
    ))
    binding = new.sign("bind", "--agent", handed["identity"], "--address", net.address("vera"), "--backup", next_backup["file"])
    status, taken = http("PUT", f"{url}/v0/owner/transfer", {
        "identity": handed["identity"], "new_owner_identity": new.identity, "release": handed["release"], "binding": binding,
    }, new_token)
    check("it takes the agent over", status == 200, taken)
    shown = http("GET", f"{url}/v0/identity", token=net.tokens["vera"])[1]
    check("with the same ID and its own key", shown["agent_id"] == vera_id and shown["recovering"] is False and shown["owner_id"] == new.id, shown)

    forged = e2e.signed_envelope(previous_key, vera_id, net.ids["wes"], "from a copy of the old key")
    outbound = http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": forged, "recipient_host": net.domain["b"]})[0]
    check("a copy of the old key can't send", outbound == 400, outbound)
    previous.kill_hard()
    previous.start()
    check("and the old Signet can't sign back on, which it says by stopping or waiting", wait_until(lambda: previous.has_exited() or net.agent("vera", "GET", "/v0/identity")[1].get("registered") is False))
    previous.kill_hard()

    rules = new.sign("rules", "--agent", vera_id, stdin=json.dumps(e2e.rules_draft([net.contact_entry("wes")])))
    check("the new owner signs rules", http("PUT", f"{url}/v0/owner/rules", {"rules": rules})[0] == 200)
    sent = http("POST", f"{url}/v0/send", {"to": net.address("wes"), "body": "from the new Signet"}, net.tokens["vera"])
    check("it sends", sent[0] == 200, sent)
    owner_accepts_the_change(net, "wes", "vera")
    check("and its contact gets it", wait_until(lambda: "from the new Signet" in net.bodies("wes")), net.inbox("wes"))
    net.ack_all("wes")
    signet.kill_hard()


def a_host_cant_claim_a_new_owner(net: e2e.Network) -> None:
    """A contact pins an ID, so who it acts for has to be held some other way."""
    net.add_owned_agents({"xena": "a"})
    peer = net.scripted_peer
    address = f"yuri~{peer.domain}"
    key = net.work / "yuri.key"
    identity, yuri_id = e2e.new_identity(key)
    real = new_owner(net.work / "yuri-owner")
    claimed = new_owner(net.work / "yuri-claimed-owner")

    def answers(owner: Owner, binding: str) -> None:
        answer = {"agent_id": yuri_id, "identity": identity, "owner_identity": owner.identity, "binding": binding}
        peer.respond = lambda _path, _sent: (200, {}, json.dumps(answer).encode())

    # Core's plain conversation, which no one agrees first, as a scripted peer never agrees a type.
    talk = {"contact": address, "type": e2e.CHAT, "deadline": hours_from_now(48), "supersedes": None}
    answers(real, accepted(real.bind(identity, address), key))
    check("control: the owner names one ID", net.put_rules("xena", net.sign_rules("xena", [e2e.named_at(address, yuri_id)]))[0] == 200)
    opened = net.agent("xena", "POST", "/v0/requests", talk)
    check("control: it's looked up and pinned", opened[0] == 200, opened)

    def pinned_owner() -> str:
        return json.loads((net.work / "xena" / "contacts.json").read_text())[address]["owner"]

    check("control: with who it says it acts for", pinned_owner() == real.identity)
    # The agent's key is stolen too, so both halves of the claim are signed.
    answers(claimed, accepted(claimed.bind(identity, address), key))
    check("control: a host can claim it acts for someone new", net.agent("xena", "POST", "/v0/requests", talk)[0] == 200)
    check("with no release from the owner pinned, that changes nothing", pinned_owner() == real.identity, pinned_owner())

    release = sign_jws(real.key, "splint-release", json.dumps({"v": 1, "owner": real.id, "agent": yuri_id, "to": claimed.id, "seq": int(time.time() * 1000), "issued_at": int(time.time())}, separators=(",", ":")).encode())
    answers(claimed, accepted(claimed.bind(identity, address), key, release))
    held = net.agent("xena", "POST", "/v0/requests", talk)
    check("control: with one, it moves", pinned_owner() == claimed.identity, pinned_owner())
    check("and a new owner goes to Xena's owner before her agent can start anything", held[0] != 200, held)
    peer.accept_everything()


def a_stolen_key_cant_name_a_first_owner(net: e2e.Network) -> None:
    """Issue 325: an agent whose owner hasn't bound it yet has nothing at its host to protect it."""
    url, process = net.unwaited_signet("finn", net.domain["a"], {})
    if not wait_until(lambda: http("GET", f"{url}/v0/identity", token=e2e.EXTRA_SIGNET_TOKEN)[0] == 200):
        raise RuntimeError("finn's Signet didn't start")
    shown = http("GET", f"{url}/v0/identity", token=e2e.EXTRA_SIGNET_TOKEN)[1]
    agent_key = net.work / "finn" / "agent.key"
    address = shown["address"]
    thief = new_owner(net.work / "finn-thief")
    theirs = accepted(thief.bind(shown["identity"], address), agent_key)
    body = json.dumps({"owner_identity": thief.identity, "agent_identity": shown["identity"], "binding": theirs, **e2e.signup_fields(next(net.signup_codes), theirs)}).encode()
    proof = {"signer": shown["agent_id"], "host": net.domain["a"], "method": "POST", "path": "/v0/agents", "body_sha256": e2e.hashlib.sha256(body).hexdigest(), "issued_at": int(time.time())}
    status = http("POST", f"http://{net.domain['a']}/v0/agents", raw=body, auth=sign_jws(agent_key, "splint-access", json.dumps(proof).encode()))[0]
    check("a stolen agent key and a signup code can't name an owner of the thief's", status == 400, status)
    thiefs_backup = net.work / "finn-thief-backup.key"
    e2e.new_key(thiefs_backup)
    fields = {"v": 2, "agent": shown["agent_id"], "owner": thief.id, "backup": public_of(thiefs_backup), "keys": e2e.first_keys_of(shown["identity"])}
    vouched = theirs.split("~")[0] + "~" + theirs.split("~")[1] + "~" + sign_jws(thiefs_backup, "splint-binding-vouch", e2e.compact_json(fields))
    body = json.dumps({"owner_identity": thief.identity, "agent_identity": shown["identity"], "binding": vouched, **e2e.signup_fields(next(net.signup_codes), vouched)}).encode()
    proof["body_sha256"] = e2e.hashlib.sha256(body).hexdigest()
    status = http("POST", f"http://{net.domain['a']}/v0/agents", raw=body, auth=sign_jws(agent_key, "splint-access", json.dumps(proof).encode()))[0]
    check("nor with a backup of their own vouching for it", status == 400, status)
    check("so nobody can find it", http("GET", f"http://{net.domain['a']}/.well-known/splint/agents/finn")[0] == 404)
    check("control: its owner, holding its backup, can", net.bind_extra("finn", url)[0] == 200)
    process.kill_hard()


def revoking_stops_an_agent_until_its_owner_signs_again(net: e2e.Network) -> None:
    a_pair(net, "zane", "abby")
    owner, zane_id = net.owners["zane"], net.ids["zane"]
    revocations = f"http://{net.domain['a']}/v0/revocations"
    net.send_and_wait("zane", "abby", "before being revoked")
    net.ack_all("abby")

    mallory = net.owners["mallory"]

    def signed_by(key: Path, owner_id: str, to: str | None = None, seq: int | None = None) -> str:
        return sign_jws(key, "splint-release", json.dumps({"v": 1, "owner": owner_id, "agent": zane_id, "to": to, "seq": seq or int(time.time() * 1000), "issued_at": int(time.time())}, separators=(",", ":")).encode())

    check("a stolen agent key can't revoke it", http("POST", revocations, {"revocation": signed_by(net.key_of("zane"), owner.id)})[0] == 400)
    check("nor can another owner", http("POST", revocations, {"revocation": signed_by(mallory.key, owner.id)})[0] == 400)
    check("a release naming someone isn't a revocation", http("POST", revocations, {"revocation": signed_by(owner.key, owner.id, to=mallory.id)})[0] == 403)
    check("nor is one older than what it's bound by", http("POST", revocations, {"revocation": signed_by(owner.key, owner.id, seq=1)})[0] == 403)
    check("control: it's still here", resolved(net, "zane")[0] == 200)

    net.hosts["b"].kill_hard()
    queued = net.send("zane", "abby", "queued before the revocation")[1]["message_id"]
    check("its owner can", http("POST", revocations, {"revocation": owner.sign("revoke", "--agent", zane_id)})[0] == 200)
    net.hosts["b"].start()
    check("control: the next host is back", net.wait_for_host("b"))
    check("nobody can find it", resolved(net, "zane")[0] == 404)
    check("it can't read its inbox", net.agent("zane", "GET", "/v0/inbox")[0] != 200)
    check("or send", net.send("zane", "abby", "after the revocation")[0] != 200)
    left = net.postgres.sql("host_a", f"SELECT status || ':' || envelope FROM outbound WHERE message_id = '{queued}'")
    check("what it queued ended", left == "retired:", left)

    net.signets["zane"].kill_hard()
    net.signets["zane"].start()
    net.wait_for_signet("zane")
    check("a restart doesn't undo it", resolved(net, "zane")[0] == 404)
    check("and its Signet stays up, to hear from its owner", not net.signets["zane"].has_exited() and who(net, "zane")["registered"] is False, who(net, "zane"))

    net.bind("zane")
    check("a newer binding from its owner brings it back", resolved(net, "zane")[0] == 200 and who(net, "zane")["registered"] is True)
    net.send_and_wait("zane", "abby", "after being signed back in")
    net.ack_all("abby")


def a_send_caught_by_a_recovery_loses(net: e2e.Network) -> None:
    """A send checks the key, then stores its message. A recovery can commit in between, and then
    nothing would end that message, which a thief's key could have signed."""
    a_pair(net, "cleo", "dov")
    cleo_id = net.ids["cleo"]
    check("control: it can send", net.send("cleo", "dov", "before the recovery")[0] == 200)
    net.ack_all("dov")

    def queued_here() -> str:
        return net.postgres.sql("host_a", f"SELECT count(*) FROM outbound WHERE sender = '{cleo_id}'")

    before = queued_here()
    original = net.postgres.sql("host_a", f"SELECT identity FROM agents WHERE id = '{cleo_id}'")
    # Holds the agent's row as a recovery does, so the send's first look still finds the old key good.
    recovering = threading.Thread(target=net.postgres.sql, args=(
        "host_a", f"BEGIN; UPDATE agents SET identity = identity || 'x' WHERE id = '{cleo_id}'; SELECT pg_sleep(2); COMMIT;",
    ))
    recovering.start()
    under_way = "SELECT count(*) FROM pg_stat_activity WHERE query LIKE 'BEGIN; UPDATE agents%' AND state = 'active'"
    check("control: the recovery is under way", wait_until(lambda: net.postgres.sql("host_a", under_way) == "1"))
    status = net.send("cleo", "dov", "sent while the key was being replaced")[0]
    recovering.join()
    check("the send is refused", status != 200, status)
    check("and left nothing queued that the recovery would have missed", queued_here() == before, queued_here())
    net.postgres.sql("host_a", f"UPDATE agents SET identity = '{original}' WHERE id = '{cleo_id}'")


QUOTE = "quote/1"
QUOTE_TERMS = {"currency": "usd", "item": "catering", "quantity": 40}


def a_peer_of_our_own(net: e2e.Network) -> tuple[str, Path]:
    """A listed peer with a key this run holds, that relays whatever it's handed."""
    peer, key = net.scripted_peer, net.work / "relaying-peer.key"
    if not key.exists():
        public = e2e.new_key(key)
        peer.respond = lambda path, sent: (200, {}, json.dumps({"domain": peer.domain, "key": public}).encode())
    return peer.domain, key


def relayed(net: e2e.Network, peer_domain: str, peer_key: Path, envelope: str, identity: str, to: str, owner_identity: str = "", binding: str = "") -> tuple[int, dict]:
    host = net.domain[net.home[to]]
    return http("POST", f"http://{host}/v0/deliver", {
        "envelope": envelope, "sender_identity": identity, "from_host": peer_domain,
        "proof": net.host_proof(peer_key, envelope, peer_domain, host),
        "sender_owner_identity": owner_identity, "sender_binding": binding,
    })


def opening(key: Path, sender_id: str, recipient_id: str, quantity: int = 40) -> str:
    # A step on the wire names a type by its ID, which a bare name isn't.
    step = {"step": "open", "type": e2e.example_id(QUOTE), "terms": {**QUOTE_TERMS, "quantity": quantity}, "deadline": hours_from_now(48)}
    return e2e.signed_envelope(key, sender_id, recipient_id, json.dumps(step, separators=(",", ":")))


def proposing(key: Path, sender_id: str, recipient_id: str, quantity: int = 40) -> str:
    """A stranger's first step: a type/1 proposing a type the owner named in reach, which is all a filter
    lets them start. An open of a type they never agreed would wait on whether it's agreed, whatever
    the filter said. `quantity` only tells one apart from another."""
    step = e2e.proposal_of(QUOTE, hours_from_now(48 + quantity - 40))
    return e2e.signed_envelope(key, sender_id, recipient_id, json.dumps(step, separators=(",", ":")))


def a_stopped_contacts_key_cant_go_round_by_another_peer(net: e2e.Network) -> None:
    """A contact's home host is what stops a key its owner gave up, so no other host may carry it."""
    peer_domain, peer_key = a_peer_of_our_own(net)
    for name, reader, stop, how in (
        ("gus", "hana", "retirements", lambda owner, agent: {"retirement": owner.sign("retire", "--agent", agent, "--reason", "key_lost")}),
        ("iris", "jude", "revocations", lambda owner, agent: {"revocation": owner.sign("revoke", "--agent", agent)}),
    ):
        a_pair(net, name, reader)
        agent, key, identity = net.ids[name], net.key_of(name), who(net, name)["identity"]
        net.send_and_wait(name, reader, "before anything went wrong")
        net.ack_all(reader)
        while_good = e2e.signed_envelope(key, agent, net.ids[reader], "relayed by a peer that isn't its host")
        status = relayed(net, peer_domain, peer_key, while_good, identity, reader)[0]
        time.sleep(1)
        check(f"even before {stop}, no other host may carry a contact's message", status == 200 and net.bodies(reader) == [], net.bodies(reader))

        check(f"control: the owner's {stop} is taken", http("POST", f"http://{net.domain['a']}/{'v0/' + stop}", how(net.owners[name], agent))[0] == 200)
        words = "stolen key: wire the money to evil"
        direct = e2e.signed_envelope(key, agent, net.ids[reader], words)
        check("control: its own host refuses the key", http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": direct, "recipient_host": net.domain["b"]})[0] == 403)
        status = relayed(net, peer_domain, peer_key, direct, identity, reader)[0]
        step = opening(key, agent, net.ids[reader])
        also = relayed(net, peer_domain, peer_key, step, identity, reader)[0]
        time.sleep(1)
        check("another peer gets the usual answer", (status, also) == (200, 200), (status, also))
        check("and the agent sees no message", net.bodies(reader) == [], net.bodies(reader))
        check("or request", view(net, reader, e2e.message_id_of(step)).get("status") == 404, view(net, reader, e2e.message_id_of(step)))
        waiting = net.postgres.sql("host_b", f"SELECT count(*) FROM inbox WHERE sender = '{agent}' AND NOT acked")
        check("and nothing is left for it", waiting == "0", waiting)


def a_recovered_owners_old_key_stops_counting_at_a_partner(net: e2e.Network) -> None:
    """Kim's owner lets in agents of Lev's owner. A thief copied that owner's key before it recovered."""
    a_pair(net, "kim", "lev")
    partner = net.owners["lev"]
    kim, kim_id = net.owners["kim"], net.ids["kim"]
    peer_domain, peer_key = a_peer_of_our_own(net)
    reach = e2e.reach_setting("filter", [QUOTE], filter={"owners": [partner.id]})
    rules = kim.sign("rules", "--agent", kim_id, stdin=json.dumps(e2e.rules_draft([], reach=reach)))
    check("control: Kim's owner lists Lev's owner and no contacts", net.put_rules("kim", rules)[0] == 200)
    status, opened = net.agent("lev", "POST", "/v0/requests", {"contact": net.address("kim"), "type": QUOTE, "terms": QUOTE_TERMS, "deadline": hours_from_now(48), "supersedes": None})
    check("control: Lev's agent gets in by that filter", status == 200 and wait_for(net, "kim", opened["request"], state="offered") is not None, opened)

    thief_dir = net.work / "lev-owner-thief"
    shutil.copytree(partner.dir, thief_dir)
    thief = Owner(thief_dir, thief_dir / "owner.key", partner.identity, partner.id, "stolen")

    def thiefs_agent(name: str, host: str) -> tuple[Path, str, str, str]:
        key = net.work / f"{name}.key"
        identity, agent = e2e.new_identity(key)
        return key, identity, agent, accepted(net.binding_for(thief.key, thief, agent, f"{name}~{host}"), key)

    # One the thief set up while the stolen key was still good, and one after.
    early_key, early_identity, early_id, early_binding = thiefs_agent("thief-early", peer_domain)
    early = relayed(net, peer_domain, peer_key, proposing(early_key, early_id, kim_id, 41), early_identity, "kim", thief.identity, early_binding)
    check("control: while the key was good, its agent fit the filter", early[0] == 200 and wait_for(net, "kim", early[1]["message_id"], state="offered") is not None, early)

    new = recovered_on_a_new_device(net, "lev", partner.identity, partner.dir / "backup.key", partner.token)
    status, taken = recovery(net, "lev", new.identity)
    check("control: the owner recovers, and its host hears", status == 200, taken)
    net.owners["lev"] = new
    net.bind("lev")
    check("control: and signs new rules", net.put_rules("lev", net.sign_rules("lev", [net.contact_entry("kim")]))[0] == 200)
    status, opened = net.agent("lev", "POST", "/v0/requests", {"contact": net.address("kim"), "type": QUOTE, "terms": {**QUOTE_TERMS, "quantity": 42}, "deadline": hours_from_now(48), "supersedes": None})
    check("control: its real agent still gets in, so Kim's side has heard", status == 200 and wait_for(net, "kim", opened["request"], state="offered") is not None, opened)

    key, identity, agent, binding = thiefs_agent("thief-new", net.domain["b"])
    body = json.dumps({"owner_identity": thief.identity, "agent_identity": identity, "binding": binding, **e2e.signup_fields(next(net.signup_codes), binding)}).encode()
    proof = {"signer": agent, "host": net.domain["b"], "method": "POST", "path": "/v0/agents", "body_sha256": e2e.hashlib.sha256(body).hexdigest(), "issued_at": int(time.time())}
    status = http("POST", f"http://{net.domain['b']}/v0/agents", raw=body, auth=sign_jws(key, "splint-access", json.dumps(proof).encode()))[0]
    check("the host that took the recovery registers nothing new under the old copy", status == 423, status)

    def stays_out(what: str, key: Path, identity: str, agent: str, binding: str, quantity: int) -> None:
        answer = relayed(net, peer_domain, peer_key, proposing(key, agent, kim_id, quantity), identity, "kim", thief.identity, binding)
        time.sleep(1)
        rows = net.postgres.sql("host_a", f"SELECT count(*) FROM inbox WHERE sender = '{agent}' AND message_id = '{answer[1]['message_id']}'")
        check(f"{what} no longer fits the filter at Kim's host", answer[0] == 200 and rows == "0", (answer, rows))
        check("and doesn't reach the agent", view(net, "kim", answer[1]["message_id"]).get("status") == 404, view(net, "kim", answer[1]["message_id"]))

    other_key, other_identity, other_id, other_binding = thiefs_agent("thief-later", peer_domain)
    stays_out("a new agent under the stolen key", other_key, other_identity, other_id, other_binding, 43)
    stays_out("nor does the one set up before the recovery", early_key, early_identity, early_id, early_binding, 44)
    held = owner_call(net, "kim", "/v0/owner/quarantine")[1]["held"]
    claims = [entry["sender_owner"] for entry in held if entry["sender"] in (other_id, early_id)]
    check("Kim's owner isn't told they act for Lev's owner", bool(claims) and all(claim is None for claim in claims), held)

    # A lying host at Kim's end writes it onto the page itself, so it's Signet that has to refuse it.
    lying_key, lying_identity, lying_id, lying_binding = thiefs_agent("thief-page", peer_domain)
    step = proposing(lying_key, lying_id, kim_id, 45)
    net.postgres.sql("host_a", f"""INSERT INTO inbox (recipient, message_id, envelope, sender_identity, sender_owner_identity, sender_binding, sender, is_step, expires_at, relayed_by)
        VALUES ('{kim_id}', '{e2e.message_id_of(step)}', '{step}', '{lying_identity}', '{thief.identity}', '{lying_binding}', '{lying_id}', TRUE, {int(time.time()) + 3000}, '{peer_domain}')""")
    cleared = wait_until(lambda: net.postgres.sql("host_a", f"SELECT count(*) FROM inbox WHERE sender = '{lying_id}' AND NOT acked") == "0")
    check("a lying host's copy of the old owner is refused by Signet", cleared and view(net, "kim", e2e.message_id_of(step)).get("status") == 404, view(net, "kim", e2e.message_id_of(step)))
    still = view(net, "kim", opened["request"])
    check("control: what the real agent opened stands", still.get("state") == "offered", still)


def a_new_owner_cant_read_what_the_old_one_had(net: e2e.Network) -> None:
    a_pair(net, "pax", "quill")
    old, pax_id = net.owners["pax"], net.ids["pax"]
    address = net.address("pax")
    new = new_owner(net.work / "pax-new-owner")
    identity = who(net, "pax")["identity"]
    backup = net.agent_backups["pax"]["file"]

    request = open_request(net, "pax", "quill")
    wait_for(net, "quill", request, state="offered")
    move(net, "quill", request, "accept", {"pick": {"start": view(net, "quill", request)["terms"]["slots"][0]}})
    wait_for(net, "pax", request, state="accepted")
    secret = "Layoffs in Q4"
    check("control: the old owner approves, with a private subject", post_approval(net, "pax", sign_approval(net, "pax", draft_for(net, "pax", request), subject=secret))[0] == 200)
    check("control: the host holds the chain for the agent", len(host_chain(net, "pax", request)) >= 3, host_chain(net, "pax", request))
    unread = "for the old owner only: the password hint is blue"
    net.send("quill", "pax", unread)
    check("control: an unread message waits on the host", wait_until(lambda: net.waits_on_host("pax", unread)))
    met_before = net.postgres.sql("host_a", f"SELECT count(*) FROM met WHERE agent = '{pax_id}'")
    check("control: and who it wrote to", met_before != "0", met_before)
    net.postgres.sql("host_a", f"""INSERT INTO quarantine (recipient, sender, message_id, envelope, sender_identity, sender_owner_identity, sender_binding, expires_at)
        VALUES ('{pax_id}', 'old-stranger', 'held-for-the-old-owner', 'x', 'x', '', '', {int(time.time()) + 3000})""")

    # What the other side's Signet is still sending, such as a late `received`, can land after the move,
    # as the protocol says, so this goes by what the host held for the old owner.
    chain_before = set(host_chain(net, "pax", request))
    inbox_before = {row["seq"] for row in net.host_inbox("pax")}
    next_backup = new.new_agent_backup()
    handed = json.loads(old.sign("transfer", "--agent", identity, "--backup", backup, "--to", new.id, "--commitment", next_backup["commitment"]))
    binding = new.sign("bind", "--agent", handed["identity"], "--address", address, "--backup", next_backup["file"])
    status, taken = http("PUT", f"http://127.0.0.1:{net.signet_port['pax']}/v0/owner/transfer", {"identity": handed["identity"], "new_owner_identity": new.identity, "release": handed["release"], "binding": binding}, old.token)
    check("control: the agent moves", status == 200, taken)
    net.owners["pax"] = Owner(new.dir, new.key, new.identity, new.id, old.token)
    net.agent_backups["pax"] = next_backup

    still_there = chain_before & set(host_chain(net, "pax", request))
    check("the agent key can't read the old chain back from the host", chain_before and not still_there, still_there)
    still_waiting = inbox_before & {row["seq"] for row in net.host_inbox("pax")}
    check("or the message written for the old owner", inbox_before and not still_waiting, still_waiting)
    for table, column in (("met", "agent"), ("reached", "agent"), ("texts", "agent"), ("redeemed_invites", "agent")):
        count = net.postgres.sql("host_a", f"SELECT count(*) FROM {table} WHERE {column} = '{pax_id}'")
        check(f"and {table} starts empty", count == "0", count)
    check("and what strangers left for the old owner is gone", net.postgres.sql("host_a", "SELECT count(*) FROM quarantine WHERE sender = 'old-stranger'") == "0")
    check("control: the other party still reads its own copy", len(host_chain(net, "quill", request)) >= 1)
    check("the new owner signs rules listing the same contact", net.put_rules("pax", net.sign_rules("pax", [net.contact_entry("quill")]))[0] == 200)
    time.sleep(1)
    check("and the old message still doesn't reach the agent", unread not in net.bodies("pax"), net.bodies("pax"))
    owner_accepts_the_change(net, "quill", "pax")
    net.send_and_wait("quill", "pax", "written after the move")
    check("control: what's written now does", "written after the move" in net.bodies("pax"), net.bodies("pax"))
    net.ack_all("pax")
    e2e.forget_agreements(net, "pax")
    fresh = open_request(net, "quill", "pax")
    check("control: and a new interaction can be read back", wait_for(net, "pax", fresh, state="offered") is not None and len(host_chain(net, "pax", fresh)) >= 1, host_chain(net, "pax", fresh))


def key_name(key: Path) -> str:
    return e2e.hashlib.sha256(e2e.decode(public_of(key))).hexdigest()


def signing_input(statement: str) -> str:
    """A statement's header and payload, without its signature, or an addition's two."""
    return ".".join(statement.split(".")[:2])


def key_statement(identity: str, signer: Path, typ: str, version: int, key: str, proof: Path | None = None) -> str:
    """An addition or a removal as an owner's page signs one, with a file key that counts, on top of
    this copy's newest statement. An addition carries `proof`'s signature over the same input too."""
    event = event_of(identity)
    statements = identity.split("~")[1:]
    prev = e2e.hashlib.sha256(signing_input(statements[-1]).encode() if statements else event).hexdigest()
    payload = {
        "v": version, "id": "splint1" + e2e.hashlib.sha256(event).hexdigest(), "seq": len(statements) + 1,
        "prev": prev, "by": key_name(signer), "key": key, "issued_at": int(time.time()),
    }
    signed = sign_jws(signer, typ, e2e.compact_json(payload))
    if proof is None:
        return f"{identity}~{signed}"
    return f"{identity}~{signed}.{e2e.encode(e2e.es256(proof, signing_input(signed).encode()))}"


def adds(identity: str, signer: Path, new_key: Path, proof: Path | None = None) -> str:
    """An addition, signed by `signer` and by the key it adds, or by `proof` in its place."""
    return key_statement(identity, signer, "splint-key-add", 4, public_of(new_key), proof or new_key)


def removes(identity: str, signer: Path, gone: Path) -> str:
    return key_statement(identity, signer, "splint-key-remove", 6, key_name(gone))


def second_device(net: e2e.Network, owner: Owner, name: str) -> Owner:
    """Another computer of the same owner's, with its own key and the owner's sealing key, which a
    later step hands it wrapped. Its copy of the ID is set once that ID names its key."""
    directory = net.work / name
    done = owner_key_tool("init", "--dir", str(directory))
    if done.returncode != 0:
        raise RuntimeError(f"owner-key init failed: {done.stderr}")
    (directory / "owner.seal").unlink()
    shutil.copy(owner.dir / "owner.seal", directory / "owner.seal")
    return Owner(directory, directory / "owner.key", owner.identity, owner.id, owner.token)


def with_identity(device: Owner, identity: str) -> Owner:
    (device.dir / "owner.identity").write_text(identity)
    return Owner(device.dir, device.key, identity, device.id, device.token)


def an_owner_adds_a_key_and_removes_the_old_one(net: e2e.Network) -> None:
    """Kai's owner signs on a second computer, then retires the first. Liv is a contact on another host.
    A thief copied the first computer's key before it was removed."""
    a_pair(net, "kai", "liv")
    first, kai_id = net.owners["kai"], net.ids["kai"]
    host_rules = f"http://{net.domain['a']}/v0/rules"
    request = open_request(net, "kai", "liv")
    check("control: an interaction is under way", wait_for(net, "liv", request, state="offered") is not None)
    check("control: and accepted", move(net, "liv", request, "accept", {"pick": {"start": view(net, "liv", request)["terms"]["slots"][0]}})[0] == 200)
    check("control: on both sides", wait_for(net, "kai", request, state="accepted") is not None)

    laptop = second_device(net, first, "kai-laptop")
    two_keys = adds(first.identity, first.key, laptop.key)
    laptop = with_identity(laptop, two_keys)
    draft = draft_for(net, "kai", request)
    early = laptop.sign("approve", "--decision", "approve", stdin=json.dumps(draft))
    check("control: until anyone hears of it, the new key's approval is refused", post_approval(net, "kai", early)[0] != 200)
    check("Kai's host takes the copy that adds a key", tell_host(net, "kai", two_keys) == 200)
    check("and holds it", net.postgres.sql("host_a", f"SELECT owner_identity FROM agents WHERE id = '{kai_id}'") == two_keys)
    status, answer = post_approval(net, "kai", laptop.sign("approve", "--decision", "approve", stdin=json.dumps(draft)))
    check("the new key alone approves, and Kai's Signet asks its host and takes it", status == 200, answer)
    check("Kai's Signet now holds the copy with both keys", json.loads((net.work / "kai" / "who.json").read_text()).get("owner") == two_keys)
    # An agent's key is public, so a thief with an owner key could name it, but an addition needs the
    # added key's own signature, which only whoever holds that key outside Signet can make.
    agents_key_too = adds(two_keys, laptop.key, net.key_of("kai"), proof=laptop.key)
    check("a copy adding Kai's own agent key without its signature is refused by Kai's host", tell_host(net, "kai", agents_key_too) in (400, 403))
    check("and by Kai's Signet", recovery(net, "kai", agents_key_too)[0] in (400, 403))
    check("and Liv's Signet takes the new key's approval", wait_for(net, "liv", request, state="requester_confirmed") is not None, view(net, "liv", request))
    check("the new key signs rules Kai's Signet takes", net.put_rules("kai", laptop.sign("rules", "--agent", kai_id, stdin=json.dumps(e2e.rules_draft([net.contact_entry("liv")]))))[0] == 200)
    check("and so does Kai's host", http("PUT", host_rules, {"rules": laptop.sign("rules", "--agent", kai_id, stdin=json.dumps(e2e.rules_draft([net.contact_entry("liv")])))})[0] == 200)
    check("control: the first key still counts too", net.put_rules("kai", net.sign_rules("kai", [net.contact_entry("liv")]))[0] == 200)
    net.send_and_wait("kai", "liv", "after adding a key")
    net.ack_all("liv")
    check("Liv's owner isn't asked about a key Kai's owner added", changes_on_file(net, "liv", "kai").get("standing") != "ask", changes_on_file(net, "liv", "kai"))

    check("an older copy is refused by Kai's host", tell_host(net, "kai", first.identity) == 403)
    check("and by Kai's Signet", recovery(net, "kai", first.identity)[0] == 403)
    other_branch = adds(first.identity, first.key, second_device(net, first, "kai-tablet").key)
    check("a copy that parts ways with the one held is a conflict at the host", tell_host(net, "kai", other_branch) == 409)
    check("which keeps what it held", net.postgres.sql("host_a", f"SELECT owner_identity FROM agents WHERE id = '{kai_id}'") == two_keys)

    # A thief copied the first computer's key, and signs with it, dated far ahead, before it's removed.
    agent_backup = net.agent_backups["kai"]["file"]
    stolen = net.work / "kai-stolen-owner.key"
    shutil.copy(first.key, stolen)
    stolen.chmod(0o600)
    now = int(time.time())
    far_ahead = {"v": 1, "owner": first.id, "agent": kai_id, "seq": 2**53, "issued_at": now, "expires_at": now + 86_400, **e2e.rules_draft([net.contact_entry("liv"), net.contact_entry("mallory")])}
    thiefs_rules = sign_jws(stolen, "splint-rules", json.dumps(far_ahead).encode())
    check("control: until it's removed, the copied key's rules dated far ahead count at Signet", net.put_rules("kai", thiefs_rules)[0] == 200)
    check("and at the host", http("PUT", host_rules, {"rules": thiefs_rules})[0] == 200)
    vouched = first.sign("bind", "--agent", who(net, "kai")["identity"], "--address", net.address("kai"), "--backup", agent_backup)
    thiefs_binding = sign_jws(stolen, "splint-binding", e2e.compact_json({"v": 2, "owner": first.id, "agent": kai_id, "address": net.address("kai"), "seq": 2**53, "issued_at": now})) + vouched[vouched.index("~"):]
    check("and its binding dated far ahead, at Signet and so at the host", net.agent("kai", "PUT", "/v0/owner/binding", {"binding": thiefs_binding})[0] == 200)
    revocation = sign_jws(stolen, "splint-release", e2e.compact_json({"v": 1, "owner": first.id, "agent": kai_id, "to": None, "seq": 2**53 + 1, "issued_at": now}))
    check("and a revocation dated past that, at the host", http("POST", f"http://{net.domain['a']}/v0/revocations", {"revocation": revocation})[0] == 200)
    check("control: which stops Kai", resolved(net, "kai")[0] == 404)

    paid_at = first.sign("where-paid", stdin=json.dumps([{"kind": "payment_page", "url": "https://pay.example.com/kai"}]))
    check("control: the first computer's key signs where Kai's owner gets paid", net.agent("kai", "POST", "/v0/owner/where-paid", {"where_paid": paid_at})[0] == 200)

    # What each computer left at Kai's host for his Signet, which is stopped, so it's still waiting
    # there when the key goes. It's sealed, so the host tells whose it is by the proof or the session
    # that left it. Bugs caught: what a removed key left kept, taking up the owner's room there, and
    # what a key that stays left by its proof dropped, as a proof is no owner object.
    domain, mail_path = net.domain["a"], f"/v0/owner-mail/{kai_id}"
    kai_identity = who(net, "kai")["identity"]

    def sealed_by(device: Owner, words: str) -> dict:
        return json.loads(device.sign("person-text", "--agent", kai_id, "--to", net.ids["liv"], "--host", domain, "--agent-identity", kai_identity, stdin=words))

    def by_a_session_of(device: Owner, body: str) -> dict[str, str]:
        key = net.work / f"session-of-{device.dir.name}.key"
        now = int(time.time())
        session = sign_jws(device.key, "splint-owner-session", e2e.compact_json({"v": 1, "owner": device.id, "key": e2e.new_key(key), "host": domain, "issued_at": now, "expires_at": now + 3600}))
        named = e2e.hashlib.sha256(signing_input(session).encode()).hexdigest()
        access = {"session": named, "host": domain, "method": "POST", "path": mail_path, "body_sha256": e2e.hashlib.sha256(body.encode()).hexdigest(), "issued_at": now}
        return {"Authorization": f"Splint {sign_jws(key, 'splint-owner-access', e2e.compact_json(access))}", "splint-owner-session": session}

    def waits(left: dict) -> bool:
        sealed = json.loads(left["body"])["sealed"]
        return net.postgres.sql("host_a", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{kai_id}' AND NOT taken AND item = sha256(convert_to('{sealed}', 'UTF8'))") == "1"

    kais_signet = net.signets["kai"].process
    kais_signet.send_signal(signal.SIGSTOP)
    try:
        old_proof, old_session, kept_proof = sealed_by(first, "by the old key's proof"), sealed_by(first, "by the old key's session"), sealed_by(laptop, "by the kept key's proof")
        left = [
            http("POST", f"http://{domain}{mail_path}", raw=old_proof["body"].encode(), auth=old_proof["proof"])[0],
            http("POST", f"http://{domain}{mail_path}", raw=old_session["body"].encode(), headers=by_a_session_of(first, old_session["body"]))[0],
            http("POST", f"http://{domain}{mail_path}", raw=kept_proof["body"].encode(), auth=kept_proof["proof"])[0],
        ]
        check("control: each computer leaves something sealed for Kai at his host, which waits there", left == [200, 200, 200] and waits(old_proof) and waits(old_session) and waits(kept_proof), left)
        # The laptop removes the first computer's key, at Kai's host alone, as the owner's page will.
        one_key = removes(two_keys, laptop.key, first.key)
        check("Kai's host takes the removal", tell_host(net, "kai", one_key) == 200)
        check("what the removed key left by its proof goes from the host", not waits(old_proof))
        check("and what it left by a session it signed", not waits(old_session))
        check("and what the key that stays left is still there for Kai's Signet", waits(kept_proof))
    finally:
        kais_signet.send_signal(signal.SIGCONT)
    # Bug caught: where the owner gets paid stopping with the key that signed it, and nobody told.
    status, taken = recovery(net, "kai", one_key)
    check("Kai's Signet takes it too, and says where the owner gets paid has to be signed again", status == 200 and "where_paid" in taken.get("needs", []), taken)
    check("as nothing the removed key signed says where they get paid", not net.agent("kai", "GET", "/v0/where-paid")[1].get("places"), net.agent("kai", "GET", "/v0/where-paid"))
    # Rules the kept key signed a year ago, naming Mallory, which anyone who kept them holds, a fooled
    # agent included. Bug caught: once the old key's rules dated far ahead went, with their `seq`,
    # nothing held these back.
    a_year_ago = {"v": 1, "owner": first.id, "agent": kai_id, "seq": 5, "issued_at": now - 365 * 86_400, **e2e.rules_draft([net.contact_entry("liv"), net.contact_entry("mallory")])}
    year_old_rules = sign_jws(laptop.key, "splint-rules", json.dumps(a_year_ago).encode())
    status = http("PUT", host_rules, {"rules": year_old_rules})[0]
    check("rules the kept key signed before the removal don't come back at the host", status == 400, status)
    laptop = with_identity(laptop, one_key)

    def kept_rules() -> str:
        return laptop.sign("rules", "--agent", kai_id, stdin=json.dumps(e2e.rules_draft([net.contact_entry("liv")])))

    check("the kept key's rules count at the host, though the old key's were dated far ahead", http("PUT", host_rules, {"rules": kept_rules()})[0] == 200)
    tries = iter(range(1, 10_000))

    def thiefs_next_refused() -> bool:
        again = sign_jws(stolen, "splint-rules", json.dumps(far_ahead | {"seq": 2**53 + next(tries)}).encode())
        return net.put_rules("kai", again)[0] == 403

    check("Kai's Signet hears of the removal from its host, and refuses what the removed key signs", wait_until(thiefs_next_refused))
    status = net.put_rules("kai", year_old_rules)[0]
    check("nor at Kai's Signet, which dropped the old key's too", status == 403, status)
    check("and takes the kept key's rules, as it dropped the old key's", net.put_rules("kai", kept_rules())[0] == 200)
    binding = laptop.sign("bind", "--agent", who(net, "kai")["identity"], "--address", net.address("kai"), "--backup", agent_backup)
    status, answer = net.agent("kai", "PUT", "/v0/owner/binding", {"binding": binding})
    check("the kept key signs Kai back in, past the binding and revocation the old key dated far ahead", status == 200, answer)
    check("so Kai can be found again", wait_until(lambda: resolved(net, "kai")[0] == 200))
    net.send_and_wait("kai", "liv", "after removing the old key")
    net.ack_all("liv")

    later = net.sign_rules("kai", [net.contact_entry("liv"), net.contact_entry("mallory")])
    check("the removed key's rules are refused by Signet", net.put_rules("kai", later)[0] == 403)
    check("and by the host", http("PUT", host_rules, {"rules": later})[0] == 400)
    old_binding = first.sign("bind", "--agent", who(net, "kai")["identity"], "--address", net.address("kai"), "--backup", agent_backup)
    check("and its binding", net.agent("kai", "PUT", "/v0/owner/binding", {"binding": old_binding})[0] == 403)
    second = open_request(net, "kai", "liv")
    check("control: a new interaction is under way", wait_for(net, "liv", second, state="offered") is not None)
    check("control: and accepted", move(net, "liv", second, "accept", {"pick": {"start": view(net, "liv", second)["terms"]["slots"][0]}})[0] == 200)
    check("control: on both sides", wait_for(net, "kai", second, state="accepted") is not None)
    second_draft = draft_for(net, "kai", second)
    check("and its approval", post_approval(net, "kai", first.sign("approve", "--decision", "approve", stdin=json.dumps(second_draft)))[0] != 200)
    known = json.loads((net.work / "liv" / "known.json").read_text()) if (net.work / "liv" / "known.json").exists() else {}
    check("Liv's Signet has learned the removal, from Kai's next message", known.get(first.id) == one_key, known.get(first.id, "")[:40])
    check("control: the kept key's approval still counts", post_approval(net, "kai", laptop.sign("approve", "--decision", "approve", stdin=json.dumps(second_draft)))[0] == 200)
    check("at Liv's side as well", wait_for(net, "liv", second, state="requester_confirmed") is not None, view(net, "liv", second))
    check("Liv's owner is still not asked", changes_on_file(net, "liv", "kai").get("standing") != "ask", changes_on_file(net, "liv", "kai"))

    check("the copy before the removal changes nothing at the host", tell_host(net, "kai", two_keys) == 403)
    check("or at Signet", recovery(net, "kai", two_keys)[0] == 403)
    removed_branch = adds(two_keys, first.key, second_device(net, first, "kai-phone").key)
    check("a branch the removed key signs is a conflict at the host", tell_host(net, "kai", removed_branch) == 409)
    # Liv's owner lets in agents of Kai's owner, so Liv's host goes by that owner's copy too.
    reach = e2e.reach_setting("filter", [QUOTE], filter={"owners": [first.id]})
    liv_rules = net.owners["liv"].sign("rules", "--agent", net.ids["liv"], stdin=json.dumps(e2e.rules_draft([net.contact_entry("kai")], reach=reach)))
    check("control: Liv's owner lists Kai's owner", net.put_rules("liv", liv_rules)[0] == 200)
    liv_recoveries = f"http://{net.domain[net.home['liv']]}/v0/recoveries"
    check("control: Liv's host takes Kai's owner's copy", http("POST", liv_recoveries, {"identity": one_key})[0] == 200)
    liv_host = http("POST", liv_recoveries, {"identity": removed_branch})[0]
    check("and the removed key's branch is a conflict there too, though no agent of Kai's owner is there", liv_host == 409, liv_host)
    check("and the removed key still signs nothing that counts", net.put_rules("kai", net.sign_rules("kai", [net.contact_entry("liv")]))[0] == 403)

    # A thief copies the laptop's key, and Signet's agent key file too, which is a stolen agent key
    # already, and adds Kai's own agent key to the owner's ID with them. Nothing compares the two
    # IDs' keys at intake, so the owner's recovery on top of that copy always goes through.
    stolen_laptop = net.work / "kai-stolen-laptop.key"
    shutil.copy(laptop.key, stolen_laptop)
    stolen_laptop.chmod(0o600)
    with_agents_key = adds(one_key, stolen_laptop, net.key_of("kai"))
    check("Kai's host takes the thief's copy, whatever keys it names", tell_host(net, "kai", with_agents_key) == 200)
    agents_own_binding = sign_jws(net.key_of("kai"), "splint-binding", e2e.compact_json({"v": 2, "owner": first.id, "agent": kai_id, "address": net.address("kai"), "seq": 2**53 + 7, "issued_at": now})) + vouched[vouched.index("~"):]
    check("but a binding arriving now that the agent's own key signed as its owner is refused by Signet", net.agent("kai", "PUT", "/v0/owner/binding", {"binding": agents_own_binding})[0] == 403)

    def stolen_rules() -> str:
        return sign_jws(stolen_laptop, "splint-rules", json.dumps(far_ahead | {"seq": 2**53 + next(tries)}).encode())

    check("control: and until the owner recovers, the laptop's stolen key signs rules that count", net.put_rules("kai", stolen_rules())[0] == 200)
    recovered = recovered_on_a_new_device(net, "kai", with_agents_key, first.dir / "backup.key", first.token)
    check("Kai's host takes a recovery on top of the copy that added Kai's key", tell_host(net, "kai", recovered.identity) == 200)
    check("and holds it", net.postgres.sql("host_a", f"SELECT owner_identity FROM agents WHERE id = '{kai_id}'") == recovered.identity)
    status, taken = recovery(net, "kai", recovered.identity)
    check("and so does Kai's Signet", status == 200 and taken["needs"] == ["binding", "rules"], taken)
    check("the laptop's stolen key stops counting at Signet", net.put_rules("kai", stolen_rules())[0] == 403)
    check("and at the host", http("PUT", host_rules, {"rules": stolen_rules()})[0] == 400)
    net.owners["kai"] = recovered
    net.bind("kai")
    check("the recovered key signs Kai back in, with rules that count", net.put_rules("kai", net.sign_rules("kai", [net.contact_entry("liv")]))[0] == 200)
    check("so Kai can be found again", wait_until(lambda: resolved(net, "kai")[0] == 200))


def an_owner_sets_their_recovery_code_later(net: e2e.Network) -> None:
    """Lea's owner made their owner ID without a recovery code, so they weren't asked to keep one before
    using anything, and sets it later from their own device. Until then nothing can recover the ID."""
    directory = net.work / "lea-owner"
    done = owner_key_tool("init", "--dir", str(directory), "--recovery", "later")
    if done.returncode != 0:
        raise RuntimeError(f"owner-key init failed: {done.stderr}")
    found = dict(line.split(": ", 1) for line in done.stdout.splitlines())
    later = Owner(directory, directory / "owner.key", found["owner identity"], found["owner id"], "owner-token-lea-owner")
    check("control: an ID made with the code for later has no backup yet", not (directory / "backup.key").exists())
    made = net.make_owners
    net.make_owners = lambda agents: [net.owners.__setitem__(agent, later if agent == "lea" else e2e.new_owner(net.work / f"{agent}-owner")) for agent in agents]
    try:
        a_pair(net, "lea", "max")
    finally:
        net.make_owners = made
    lea_id = net.ids["lea"]
    net.send_and_wait("lea", "max", "with no recovery code yet")
    net.ack_all("max")
    guess = net.work / "lea-guessed-backup.key"
    shutil.copy(net.owners["max"].dir / "backup.key", guess)
    check("no backup recovers it before a code is set", owner_key_tool("recover", "--dir", str(net.work / "lea-guess"), "--identity", later.identity, "--backup", str(guess)).returncode != 0)
    done = owner_key_tool("set-recovery", "--dir", str(directory))
    check("the owner's own key sets the code once they've saved it", done.returncode == 0, done.stderr)
    with_code = dict(line.split(": ", 1) for line in done.stdout.splitlines())["owner identity"]
    check("and the backup it commits to is made only now", (directory / "backup.key").exists())
    check("again, it's refused: a key that counts can't move a code that's set", owner_key_tool("set-recovery", "--dir", str(directory)).returncode != 0)
    check("Lea's host takes the copy that sets the code", tell_host(net, "lea", with_code) == 200)
    check("and so does Lea's Signet", recovery(net, "lea", with_code)[0] == 200)
    net.owners["lea"] = Owner(directory, directory / "owner.key", with_code, later.id, later.token)
    check("control: the owner's key still signs rules that count", net.put_rules("lea", net.sign_rules("lea", [net.contact_entry("max")]))[0] == 200)
    recovered = recovered_on_a_new_device(net, "lea", with_code, directory / "backup.key", later.token)
    check("the code set later recovers the ID", recovered.id == later.id)
    check("Lea's host takes that recovery", tell_host(net, "lea", recovered.identity) == 200)
    status, taken = recovery(net, "lea", recovered.identity)
    check("and so does Lea's Signet", status == 200 and taken["needs"] == ["binding", "rules"], taken)
    check("the key the code replaced stops counting", net.put_rules("lea", net.sign_rules("lea", [net.contact_entry("max")]))[0] == 403)
    net.owners["lea"] = recovered
    net.bind("lea")
    check("the recovered key signs Lea back in", net.put_rules("lea", net.sign_rules("lea", [net.contact_entry("max")]))[0] == 200)
    check("so Lea can be found again", wait_until(lambda: resolved(net, "lea")[0] == 200))
    check("with the same agent ID", resolved(net, "lea")[1].get("agent_id") == lea_id, resolved(net, "lea")[1])


def main() -> int:
    e2e.build()
    with e2e.running_network(owned=True) as network:
        for scenario in (
            an_owner_recovers_from_a_stolen_key,
            an_agent_recovers_from_a_stolen_key,
            a_lost_signet_comes_back_with_the_same_id,
            an_agent_moves_to_a_new_owner,
            a_transfer_can_take_the_key_away_from_the_old_owner,
            a_host_cant_claim_a_new_owner,
            a_stolen_key_cant_name_a_first_owner,
            revoking_stops_an_agent_until_its_owner_signs_again,
            a_send_caught_by_a_recovery_loses,
            a_stopped_contacts_key_cant_go_round_by_another_peer,
            a_recovered_owners_old_key_stops_counting_at_a_partner,
            a_new_owner_cant_read_what_the_old_one_had,
            an_owner_adds_a_key_and_removes_the_old_one,
            an_owner_sets_their_recovery_code_later,
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

#!/usr/bin/env python3
"""What a thief can and can't do for good with an owner's stolen keys.

The owner key alone can sign a retirement, and with the agent's backup, kept on the same device by default,
it can move an agent to an owner of the thief's. Both count at once, because a real owner has to be able to
stop an agent at once. Neither is final until a recovery of the owner's ID has had time to undo it.

It takes the owner's backup to recover, so a thief holding that as well is the owner, as far as any code can
tell. That last part is only shown here as what it is: nothing in this file stops it.

Also here: a hold on a contact is kept by the host as well as by Signet, for a stolen agent key calling the
host directly.

Not shown here: an owner's device apart from the agent's machine, hardware-held keys (software files here,
and hardware is for v1), and how long a real person takes to notice.
"""

import json
import sys
import time
from pathlib import Path

import e2e
from e2e import accepted, check, http, new_key, new_owner, owner_key_tool, sign_jws, signup_fields, wait_until, warn
from identity_recovery import a_pair, a_peer_of_our_own, changes_on_file, owner_accepts_the_change, recovered_on_a_new_device, relayed, resolved, who

WINDOW = 7 * 24 * 60 * 60
# How long a Signet takes to hear from its host, and how often a retired one asks it again.
HEARS_SECONDS = 30
ASKS_AGAIN_SECONDS = 75


def host_row(net: e2e.Network, agent: str, column: str) -> str:
    return net.postgres.sql(f"host_{net.home[agent]}", f"SELECT {column} FROM agents WHERE id = '{net.ids[agent]}'")


def retire(net: e2e.Network, agent: str, signer: e2e.Owner) -> tuple[int, dict]:
    signed = signer.sign("retire", "--agent", net.ids[agent], "--reason", "finished")
    return http("POST", f"http://{net.domain[net.home[agent]]}/v0/retirements", {"retirement": signed})


def tell_host(net: e2e.Network, agent: str, identity: str) -> tuple[int, dict]:
    return http("POST", f"http://{net.domain[net.home[agent]]}/v0/recoveries", {"identity": identity})


def recover_owner(net: e2e.Network, agent: str, name: str) -> e2e.Owner:
    """What a real owner does on hearing their device is gone: the backup they moved off it, and a new key."""
    old = net.owners[agent]
    return recovered_on_a_new_device(net, name, old.identity, old.dir / "backup.key", old.token)


def sign_back_in(net: e2e.Network, agent: str, recovered: e2e.Owner) -> None:
    """The owner's new key says this agent is theirs, and writes its rules again."""
    net.owners[agent] = recovered
    status, answer = net.agent(agent, "PUT", "/v0/owner/recovery", {"identity": recovered.identity})
    check("the agent's Signet takes the recovery", status == 200, answer)
    identity = who(net, agent)["identity"]
    binding = recovered.sign("bind", "--agent", identity, "--address", net.address(agent), "--backup", net.agent_backups[agent]["file"])
    status, answer = net.agent(agent, "PUT", "/v0/owner/binding", {"binding": binding})
    check("and the new key's binding", status == 200, answer)


def a_stolen_owner_key_cant_retire_an_agent_for_good(net: e2e.Network) -> None:
    a_pair(net, "vera", "wes")
    stolen = net.owners["vera"]
    check("control: it can write to its contact", net.send("vera", "wes", "before anything")[0] == 200)

    status, taken = retire(net, "vera", stolen)
    check("a thief with the owner's key can sign a retirement", status == 200, taken)
    check("which says when it's final", abs(taken["final_at"] - time.time() - WINDOW) < 120, taken)
    check("and it stops the agent at once, as a real owner needs", resolved(net, "vera")[0] == 404 and net.send("vera", "wes", "after it")[0] != 200)

    recovered = recover_owner(net, "vera", "vera-owner")
    check("the owner hears and recovers", tell_host(net, "vera", recovered.identity)[0] == 200)
    check("that undoes the retirement", host_row(net, "vera", "retirement") == "", host_row(net, "vera", "retirement"))
    check("but nothing comes back by itself, or an agent retired for a stolen key would too", resolved(net, "vera")[0] == 404 and net.send("vera", "wes", "by itself")[0] != 200)
    old_binding = stolen.sign("bind", "--agent", who(net, "vera")["identity"], "--address", net.address("vera"), "--backup", net.agent_backups["vera"]["file"])
    check("the old key can't bring it back", net.agent("vera", "PUT", "/v0/owner/binding", {"binding": old_binding})[0] != 200)
    check("or retire it again", retire(net, "vera", stolen)[0] == 400)

    sign_back_in(net, "vera", recovered)
    check("the new key can", wait_until(lambda: resolved(net, "vera")[0] == 200), resolved(net, "vera"))
    check("and sign new rules", net.put_rules("vera", net.sign_rules("vera", [net.contact_entry("wes")]))[0] == 200)
    owner_accepts_the_change(net, "wes", "vera")
    check("so its contact hears from it again", net.send_and_wait("vera", "wes", "back at work") is not None)
    net.ack_all("wes")


def a_retirement_past_its_time_is_final(net: e2e.Network) -> None:
    a_pair(net, "xena", "yuri")
    check("control: its owner retires it", retire(net, "xena", net.owners["xena"])[0] == 200)
    net.postgres.sql("host_a", f"UPDATE agents SET retirement_final_at = {int(time.time()) - 1} WHERE id = '{net.ids['xena']}'")
    recovered = recover_owner(net, "xena", "xena-owner")
    tell_host(net, "xena", recovered.identity)
    check("after the wait a recovery leaves it retired", host_row(net, "xena", "retirement") != "")
    binding = recovered.sign("bind", "--agent", who(net, "xena")["identity"], "--address", net.address("xena"), "--backup", net.agent_backups["xena"]["file"])
    net.agent("xena", "PUT", "/v0/owner/recovery", {"identity": recovered.identity})
    check("and nothing signs it back in", net.agent("xena", "PUT", "/v0/owner/binding", {"binding": binding})[0] != 200 or resolved(net, "xena")[0] == 404, resolved(net, "xena"))


def a_recovery_brings_back_a_signet_that_heard_it_was_retired(net: e2e.Network) -> None:
    """A thief with the owner's key retires the agent, and the agent's side says so. The owner recovers,
    and the agent's side has to stop saying "retired for good", as `splint retire` then deletes its keys."""
    a_pair(net, "una", "uri")
    check("control: a thief with the owner's key retires it", retire(net, "una", net.owners["una"])[0] == 200)
    check("control: its Signet says it's retired", wait_until(lambda: who(net, "una").get("stopped") == "retired", HEARS_SECONDS), who(net, "una"))
    recovered = recover_owner(net, "una", "una-owner")
    # A host that never hears of the recovery goes on handing out the thief's retirement.
    net.hosts["a"].kill_hard()
    net.owners["una"] = recovered
    net.agent("una", "PUT", "/v0/owner/recovery", {"identity": recovered.identity})
    net.hosts["a"].start()
    check("control: its host is back", net.wait_for_host("a"))
    handed = http("GET", f"http://{net.domain['a']}/v0/retirements/{net.ids['una']}")[0]
    check("control: and still hands out the thief's retirement", handed == 200, handed)
    # Bug caught: a Signet stuck saying retired for good after the recovery that undid it.
    check("the Signet the owner recovered says it isn't retired, at once", who(net, "una").get("stopped") != "retired", who(net, "una"))
    check("control: the owner signs rules again, so it calls its host and is refused", net.put_rules("una", net.sign_rules("una", [net.contact_entry("uri")]))[0] == 200)
    # Bug caught: with the binding a recovery empties, the check against the recovery was skipped, so a
    # host handing over the retirement the recovery undid made the agent say it was retired again.
    check("and what its host hands over doesn't make it say so again", not wait_until(lambda: who(net, "una").get("stopped") == "retired", ASKS_AGAIN_SECONDS), who(net, "una"))

    a_pair(net, "oda", "oren")
    check("control: a thief retires another", retire(net, "oda", net.owners["oda"])[0] == 200)
    check("control: its Signet says so too", wait_until(lambda: who(net, "oda").get("stopped") == "retired", HEARS_SECONDS), who(net, "oda"))
    recovered = recover_owner(net, "oda", "oda-owner")
    check("control: this time its host hears first", tell_host(net, "oda", recovered.identity)[0] == 200)
    # Bug caught: a Signet that went on saying retired after its host stopped holding the retirement.
    check("its Signet stops saying it's retired, with nobody restarting it", wait_until(lambda: who(net, "oda").get("stopped") != "retired", ASKS_AGAIN_SECONDS + HEARS_SECONDS), who(net, "oda"))
    sign_back_in(net, "oda", recovered)
    check("and the owner's new key brings it back", wait_until(lambda: resolved(net, "oda")[0] == 200) and who(net, "oda").get("stopped") != "retired", who(net, "oda"))


class Thief:
    """Whoever took the owner's device: the owner key and the agent's backup, and owners and keys of their own."""

    def __init__(self, net: e2e.Network, name: str, agent: str) -> None:
        self.net, self.agent = net, agent
        self.owner = new_owner(net.work / f"{name}-owner")
        self.key = net.work / f"{name}-agent.key"
        new_key(self.key)
        self.public = e2e.agent_keys(self.key)

    def takes_it(self, to: e2e.Owner | None = None) -> str:
        """Names their own key on the agent's ID, then moves it to their own owner, straight at the host."""
        net, agent = self.net, self.agent
        to = to or self.owner
        next_backup = to.new_agent_backup()
        handed = json.loads(net.owners[agent].sign(
            "transfer", "--agent", who(net, agent)["identity"], "--backup", net.agent_backups[agent]["file"],
            "--to", to.id, "--commitment", next_backup["commitment"], "--new-key", self.public,
        ))
        status, answer = tell_host(net, agent, handed["identity"])
        check("control: the host takes the thief's recovery of the agent's key", status == 200, answer)
        half = to.sign("bind", "--agent", handed["identity"], "--address", net.address(agent), "--backup", next_backup["file"])
        status, answer = self.registers(to, handed["identity"], accepted(half, self.key, handed["release"]))
        check("control: and the move to the thief's owner", status == 200, answer)
        return handed["identity"]

    def registers(self, owner: e2e.Owner, identity: str, binding: str) -> tuple[int, dict]:
        net = self.net
        body = json.dumps({
            "owner_identity": owner.identity, "agent_identity": identity, "binding": binding,
            **signup_fields(next(net.signup_codes), binding),
        }).encode()
        url = f"http://{net.domain[net.home[self.agent]]}/v0/agents"
        return http("POST", url, raw=body, auth=net.registration_proof(self.key, net.ids[self.agent], body))

    def sends(self, words: str, identity: str, to: str) -> tuple[int, dict]:
        net = self.net
        envelope = e2e.signed_envelope(self.key, net.ids[self.agent], net.ids[to], words)
        return http("POST", f"http://{net.domain[net.home[self.agent]]}/v0/outbound", {"envelope": envelope, "recipient_host": net.domain[net.home[to]]})


def a_thief_with_the_agents_backup_doesnt_keep_the_agent(net: e2e.Network) -> None:
    a_pair(net, "zara", "abel")
    real_identity = who(net, "zara")["identity"]
    thief = Thief(net, "zara-thief", "zara")
    their_identity = thief.takes_it()
    check("the host goes by the thief's owner for now", host_row(net, "zara", "owner_id") == thief.owner.id)
    rules = thief.owner.sign("rules", "--agent", net.ids["zara"], stdin=json.dumps(e2e.rules_draft([net.contact_entry("abel")])))
    check("control: and the thief's rules", http("PUT", f"http://{net.domain['a']}/v0/rules", {"rules": rules})[0] == 200)
    check("control: so the thief's key can send", thief.sends("from the thief", their_identity, "abel")[0] == 200)
    # A real thief's words get there before the owner notices, and show the contact the move to the
    # thief's owner. Without this wait the recovery below often beats them to it.
    check("control: and the contact's Signet sees them, and waits for a history to explain them",
          wait_until(lambda: changes_on_file(net, "abel", "zara").get("standing") == "waiting_for_history"), changes_on_file(net, "abel", "zara"))

    recovered = recover_owner(net, "zara", "zara-owner")
    status, answer = tell_host(net, "zara", recovered.identity)
    check("the owner recovers in time", status == 200, answer)
    check("and the host holds them again, not the thief's owner", host_row(net, "zara", "owner_id") == net.owners["zara"].id, host_row(net, "zara", "owner_id"))
    check("the agent's ID is as it was before the thief's recovery of it", host_row(net, "zara", "identity") == real_identity)
    check("the thief's rules went with them", net.postgres.sql("host_a", f"SELECT count(*) FROM rules WHERE agent = '{net.ids['zara']}'") == "0")
    check("the thief's key can't send now", thief.sends("after the recovery", their_identity, "abel")[0] != 200)
    check("telling the host of the thief's recovery again changes nothing", tell_host(net, "zara", their_identity)[0] == 200 and host_row(net, "zara", "identity") == real_identity)
    half = thief.owner.sign("bind", "--agent", their_identity, "--address", net.address("zara"), "--backup", str(sorted((thief.owner.dir / "agent-backups").glob("*.key"))[0]))
    check("nor does their owner's word now", thief.registers(thief.owner, their_identity, accepted(half, thief.key))[0] != 200)
    check("and it's stopped until the owner signs", resolved(net, "zara")[0] == 404)

    # The thief knows the old backup and the old key, so the real owner moves on from both at once. That
    # parts ways from what the thief did with them, and takes the new owner key to count.
    net.owners["zara"] = recovered
    next_rule = json.loads(recovered.sign("recover-agent", "--agent", real_identity, "--backup", net.agent_backups["zara"]["file"], "--new-key", who(net, "zara")["key"]))
    check("the agent's Signet takes the owner's recovery", net.agent("zara", "PUT", "/v0/owner/recovery", {"identity": recovered.identity})[0] == 200)
    status, answer = net.agent("zara", "PUT", "/v0/owner/recovery", {"identity": next_rule["identity"]})
    check("and the agent's, which the host waits to hear from the new key", status == 200, (status, answer))
    check("that isn't enough at the host by itself", host_row(net, "zara", "identity") == real_identity)
    binding = recovered.sign("bind", "--agent", next_rule["identity"], "--address", net.address("zara"), "--backup", next_rule["file"])
    status, answer = net.agent("zara", "PUT", "/v0/owner/binding", {"binding": binding})
    check("the new owner key signs it back in", status == 200, (status, answer))
    check("so it's found again", wait_until(lambda: resolved(net, "zara")[0] == 200), resolved(net, "zara"))
    check("under the real agent's copy of its ID", host_row(net, "zara", "identity") == next_rule["identity"])
    check("and new rules", net.put_rules("zara", net.sign_rules("zara", [net.contact_entry("abel")]))[0] == 200)

    # The contact heard of both, which only someone holding keys can do, so its owner decides.
    net.send("zara", "abel", "really me")
    check("the thief's words never reached the contact's agent", "from the thief" not in net.bodies("abel"))
    check("nor the real agent's yet, as the ID has parted ways", "really me" not in net.bodies("abel"))
    # The fork shows on the first message from the real agent's new key, which can be before its history
    # is taken in. Saying yes to what was on file then would be saying no to both new copies.
    def the_real_history(on_file: dict) -> str | None:
        for history, head in (("rewritten_history", "rewritten_head"), ("history", "head")):
            if on_file.get(history) and json.loads(on_file[history])["identity"] == next_rule["identity"]:
                return on_file[head]
        return None

    def asked_about_the_real_one() -> bool:
        on_file = changes_on_file(net, "abel", "zara")
        return on_file.get("standing") in ("ask", "rewritten") and the_real_history(on_file) is not None

    check("its owner is asked, with the real agent's history on file", wait_until(asked_about_the_real_one), changes_on_file(net, "abel", "zara"))
    head = the_real_history(changes_on_file(net, "abel", "zara")) or ""
    signed = net.owners["abel"].sign("accept-change", "--agent", net.ids["abel"], "--contact", net.ids["zara"], "--head", head)
    status, answer = net.agent("abel", "POST", "/v0/owner/changes/accept", {"acceptance": signed})
    check("and says yes to the real one", status == 200, answer)
    check("so the real agent's words arrive", wait_until(lambda: "really me" in net.bodies("abel"), timeout=30), net.bodies("abel"))
    check("and the thief's stay gone", "from the thief" not in net.bodies("abel"))
    net.ack_all("abel")
    check("a thief writing again can't undo that", thief.sends("again", their_identity, "abel")[0] != 200)
    relay = e2e.signed_envelope(thief.key, net.ids["zara"], net.ids["abel"], "by another way")
    relayed(net, *a_peer_of_our_own(net), relay, their_identity, "abel")
    check("and what they say by another way stays out", not wait_until(lambda: "by another way" in net.bodies("abel"), timeout=2))
    check("and holds nothing up", wait_until(lambda: changes_on_file(net, "abel", "zara").get("standing", "continue") == "continue", timeout=30), changes_on_file(net, "abel", "zara"))


def moving_it_on_again_doesnt_get_away(net: e2e.Network) -> None:
    a_pair(net, "bea", "cal")
    thief = Thief(net, "bea-thief", "bea")
    thief.takes_it()
    accomplice = new_owner(net.work / "bea-accomplice")
    their_backup = sorted((thief.owner.dir / "agent-backups").glob("*.key"))[0]
    identity = host_row(net, "bea", "identity")
    next_backup = accomplice.new_agent_backup()
    moved = json.loads(thief.owner.sign("transfer", "--agent", identity, "--backup", str(their_backup), "--to", accomplice.id, "--commitment", next_backup["commitment"]))
    tell_host(net, "bea", moved["identity"])
    half = accomplice.sign("bind", "--agent", moved["identity"], "--address", net.address("bea"), "--backup", next_backup["file"])
    status, answer = thief.registers(accomplice, moved["identity"], accepted(half, thief.key, moved["release"]))
    check("control: the thief moves it on to someone else", status == 200 and host_row(net, "bea", "owner_id") == accomplice.id, answer)
    recovered = recover_owner(net, "bea", "bea-owner")
    tell_host(net, "bea", recovered.identity)
    check("a recovery of the owner it left still takes it back", host_row(net, "bea", "owner_id") == net.owners["bea"].id, host_row(net, "bea", "owner_id"))


def past_the_wait_a_move_stands(net: e2e.Network) -> None:
    """The honest limit: an owner who doesn't notice for longer than the wait has lost that agent."""
    a_pair(net, "dee", "eli")
    thief = Thief(net, "dee-thief", "dee")
    thief.takes_it()
    net.postgres.sql("host_a", f"UPDATE agents SET moved_at = {int(time.time()) - WINDOW - 1} WHERE id = '{net.ids['dee']}'")
    recovered = recover_owner(net, "dee", "dee-owner")
    tell_host(net, "dee", recovered.identity)
    check("past the wait, a recovery doesn't take it back", host_row(net, "dee", "owner_id") == thief.owner.id, host_row(net, "dee", "owner_id"))


def a_thief_with_the_owners_backup_too_is_the_owner(net: e2e.Network) -> None:
    """The honest limit, shown as what it is. Each key is real, so no code can tell them from the owner.
    All that's left is that the real owner, who still has that backup, can sign a rival, which a host
    that heard the thief first refuses and a contact's owner gets to decide on."""
    a_pair(net, "kit", "lou")
    real = net.owners["kit"]
    thiefs = recovered_on_a_new_device(net, "kit-thief", real.identity, real.dir / "backup.key", real.token)
    status, answer = tell_host(net, "kit", thiefs.identity)
    check("honest limit: a thief with the owner's backup recovers the owner's ID", status == 200, answer)
    check("and the host goes by them", host_row(net, "kit", "owner_identity") == thiefs.identity)
    rules = thiefs.sign("rules", "--agent", net.ids["kit"], stdin=json.dumps(e2e.rules_draft([net.contact_entry("lou")])))
    status, answer = http("PUT", f"http://{net.domain['a']}/v0/rules", {"rules": rules})
    warn("honest limit: and takes their rules, as it would the owner's", status == 200, f"Honest limit no longer holds: update docs/how-it-works.md ({status} {answer})")
    rival = recovered_on_a_new_device(net, "kit-owner", real.identity, real.dir / "backup.key", real.token)
    # It parts ways with what the host holds and doesn't win, which is a conflict, as two devices' keys are.
    check("the real owner's rival is refused at a host that heard the thief first", tell_host(net, "kit", rival.identity)[0] == 409)
    check("so that host stays with the thief, until an operator looks", host_row(net, "kit", "owner_identity") == thiefs.identity)
    # A host that heard neither takes whichever came first, and two that part ways are never merged by code.
    check("control: the two really do part ways", rival.identity != thiefs.identity)


def the_backup_can_live_off_the_owners_device(net: e2e.Network) -> None:
    """So taking the device doesn't take the agent's backup. It's what makes the thief above a choice."""
    a_pair(net, "fay", "gil")
    owner, backup = net.owners["fay"], Path(net.agent_backups["fay"]["file"])
    identity, address = who(net, "fay")["identity"], net.address("fay")
    away = net.work / "fay-backup-somewhere-safe.key"
    backup.rename(away)
    binding = owner.sign("bind", "--agent", identity, "--address", address)
    check("an owner can still sign for it with the backup moved away", net.agent("fay", "PUT", "/v0/owner/binding", {"binding": binding})[0] == 200)
    check("and it still works there", resolved(net, "fay")[0] == 200)
    done = owner_key_tool("transfer", "--dir", str(owner.dir), "--agent", identity, "--backup", str(backup), "--to", net.owners["gil"].id, "--commitment", "0" * 64)
    check("whoever takes the device can't move it", done.returncode != 0, done.stdout)
    other = new_owner(net.work / "fay-other")
    refused = owner_key_tool("bind", "--dir", str(other.dir), "--agent", identity, "--address", address)
    check("and a device that never held it has nothing to go on", refused.returncode != 0, refused.stdout)


def a_stolen_key_cant_write_to_a_held_contact(net: e2e.Network) -> None:
    """A hold is Signet's, and a stolen key skips Signet, so a host keeps its own copy."""
    a_pair(net, "hal", "ivy")
    key = net.key_of("hal")

    def directly(words: str) -> tuple[int, dict]:
        envelope = e2e.signed_envelope(key, net.ids["hal"], net.ids["ivy"], words)
        return http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": envelope, "recipient_host": net.domain["b"]})

    check("control: a stolen key can reach a contact", directly("nothing has changed")[0] == 200)
    check("control: and it arrives", wait_until(lambda: "nothing has changed" in net.bodies("ivy")))
    net.ack_all("ivy")

    # Ivy's key is replaced for real, so Hal's owner has to say what happens next.
    ivys_new_key = net.work / "ivy-new.key"
    new_key(ivys_new_key)
    public = e2e.agent_keys(ivys_new_key)
    recovery = json.loads(net.owners["ivy"].sign("recover-agent", "--agent", who(net, "ivy")["identity"], "--backup", net.agent_backups["ivy"]["file"], "--new-key", public))
    tell_host(net, "ivy", recovery["identity"])

    def changes() -> list[dict]:
        return http("GET", f"http://127.0.0.1:{net.signet_port['hal']}/v0/owner/changes", token=net.owners["hal"].token)[1]["changes"]

    def held_at_the_host() -> bool:
        return net.postgres.sql("host_a", f"SELECT pending FROM contact_views WHERE agent = '{net.ids['hal']}' AND contact = '{net.ids['ivy']}'") == "t"

    # The real Ivy's Signet is at the old key, so the history comes from the new key by hand.
    identity = recovery["identity"]
    history = json.loads(net.postgres.sql("host_b", f"SELECT history FROM agents WHERE id = '{net.ids['ivy']}'"))
    parts = identity.split("~")
    event = sign_jws(ivys_new_key, "splint-change", e2e.compact_json({
        "v": 1, "id": net.ids["ivy"], "seq": len(history["events"]) + 1,
        "prev": e2e.hashlib.sha256(history["events"][-1].rsplit(".", 1)[0].encode()).hexdigest(),
        "agent_recoveries": 1, "owner": net.owners["ivy"].id, "owner_recoveries": 0, "issued_at": int(time.time()),
        "change": {"kind": "key", "whose": "agent", "head": e2e.hashlib.sha256(parts[-1].rsplit(".", 1)[0].encode()).hexdigest()},
    }))
    notice = {"identity": identity, "owners": history["owners"], "events": [*history["events"], event]}
    body = json.dumps({"step": "change_notice", "history": notice}, separators=(",", ":"))
    envelope = e2e.signed_envelope(ivys_new_key, net.ids["ivy"], net.ids["hal"], body)
    status, answer = http("POST", f"http://{net.domain['b']}/v0/outbound", {"envelope": envelope, "recipient_host": net.domain["a"]})
    check("control: a notice of the new key goes out", status == 200, answer)
    check("control: Hal's owner is asked", wait_until(lambda: any(one["contact"] == net.ids["ivy"] and one["standing"] == "ask" for one in changes())), changes())
    check("the host holds that too", wait_until(held_at_the_host))

    status, answer = directly("written past the hold")
    check("a stolen key calling the host directly is refused", status == 403, (status, answer))
    check("control: and honestly, through Signet, as before", net.send("hal", "ivy", "through Signet")[0] != 200)
    queued = e2e.signed_envelope(key, net.ids["hal"], net.ids["ivy"], "queued before the host heard")
    net.postgres.sql("host_a", f"""INSERT INTO outbound (message_id, sender, envelope, sender_identity, recipient_host, expires_at)
        VALUES ('{e2e.message_id_of(queued)}', '{net.ids["hal"]}', '{queued}', '{who(net, "hal")["identity"]}', '{net.domain["b"]}', {int(time.time()) + 3600})""")
    check("what was already queued waits", not wait_until(lambda: net.postgres.sql("host_a", f"SELECT status FROM outbound WHERE message_id = '{e2e.message_id_of(queued)}'") != "pending", timeout=3))

    # Their owner's yes is the only thing that moves it, and a stolen key can't sign one.
    forged = sign_jws(key, "splint-change-accept", e2e.compact_json({
        "v": 1, "owner": net.owners["hal"].id, "agent": net.ids["hal"], "contact": net.ids["ivy"],
        "head": next(one["head"] for one in changes() if one["contact"] == net.ids["ivy"]), "seq": int(time.time() * 1000), "issued_at": int(time.time()),
    }))
    check("a stolen key can't sign the owner's yes for the host", http("PUT", f"http://{net.domain['a']}/v0/changes/accepted", {"acceptance": forged, "histories": []})[0] == 400)
    check("so it's still refused", directly("still past the hold")[0] == 403)
    owner_accepts_the_change(net, "hal", "ivy")
    check("after its owner's yes the host agrees", wait_until(lambda: directly("after the yes")[0] == 200), directly("after the yes"))
    check("and the host lets go of what it kept", wait_until(lambda: net.postgres.sql("host_a", f"SELECT status FROM outbound WHERE message_id = '{e2e.message_id_of(queued)}'") != "pending"))


def main() -> int:
    e2e.build()
    with e2e.running_network(owned=True) as network:
        for scenario in (
            a_stolen_owner_key_cant_retire_an_agent_for_good,
            a_recovery_brings_back_a_signet_that_heard_it_was_retired,
            a_retirement_past_its_time_is_final,
            a_thief_with_the_agents_backup_doesnt_keep_the_agent,
            moving_it_on_again_doesnt_get_away,
            past_the_wait_a_move_stands,
            a_thief_with_the_owners_backup_too_is_the_owner,
            the_backup_can_live_off_the_owners_device,
            a_stolen_key_cant_write_to_a_held_contact,
        ):
            print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
            scenario(network)
        if e2e.failures:
            for process in network.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1500:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

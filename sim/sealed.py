#!/usr/bin/env python3
"""Sealed and unsealed: what hosts can't read, and what still gets refused when they can't.

Sealed is the default. Each Signet seals what its agent says to the contact's sealing key and its own,
so neither host can read it, and unsealed goes only between two owners who both chose it. Everything
here is the real software against Postgres, and every agent is assumed fully fooled. A host that lies
is played by writing to its database, and a stolen key by signing with a copy of an agent's key file,
sealing with `splint-core`'s `sign_sealed` example, so what a sender's Signet would never make still
reaches a reader. Each refusal has a control that succeeds.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import e2e
from e2e import check, http, wait_until
from managed_requests import HAIRCUT
from request_driver import canonical, hours_from_now, host_chain, meeting_open_step, move, open_request, view, wait_for

SETTLE_SECONDS = 3
# How long a Signet waits after a failed lookup before asking that host again.
REMEMBERED_FAILURE_SECONDS = 30
SEALER = e2e.TARGET_DIR / "debug" / "examples" / "sign_sealed"
SECRET = "the gate code is 4417, and the meeting's off the books"


def build_sealer() -> None:
    subprocess.run(["cargo", "build", "--quiet", "-p", "splint-core", "--example", "sign_sealed"], cwd=e2e.PACKAGES, check=True)


def sealed_by(net: e2e.Network, signer: str, sender: str, recipient: str, body: object, nonce: str = "", dates: tuple[int, int] | None = None, sealed_to: str | None = None, chose: str = "sealed") -> str:
    """A sealed envelope signed with a copy of a key, as a stolen key can make one, with no Signet to ask."""
    now = int(time.time())
    created_at, expires_at = dates or (now, now + 3600)
    fields = {
        "key": str(net.key_of(signer)), "sender": net.agent_identity(sender), "recipient": net.agent_identity(recipient),
        "body": body if isinstance(body, str) else canonical(body), "created_at": created_at, "expires_at": expires_at,
        "nonce": nonce, "sender_chose": chose,
    }
    if sealed_to:
        fields["to"] = net.agent_identity(sealed_to)
    done = subprocess.run([str(SEALER)], input=json.dumps(fields), capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"couldn't seal: {done.stderr}")
    return done.stdout


def with_outside(net: e2e.Network, signer: str, envelope: str, change) -> str:
    """The same envelope with what a host sees changed and signed again with the stolen key, so the
    signature checks out and only what's inside can say the outside lies."""
    payload = e2e.payload_of(envelope)
    body = json.loads(payload["body"])
    change(body["sealed"]["outside"])
    payload["body"] = json.dumps(body, separators=(",", ":"))
    return e2e.sign_jws(net.key_of(signer), "splint-envelope", e2e.compact_json(payload))


def lying_host_delivers(net: e2e.Network, sender: str, recipient: str, envelope: str) -> str:
    """What a lying host does: puts an envelope straight in an inbox, past every check it should make."""
    message_id = e2e.message_id_of(envelope)
    net.postgres.sql(
        f"host_{net.home[recipient]}",
        "INSERT INTO inbox (recipient, message_id, envelope, sender_identity, sender) "
        f"VALUES ('{net.ids[recipient]}', '{message_id}', '{envelope}', '{net.agent_identity(sender)}', '{net.ids[sender]}')",
    )
    return message_id


def on_host(net: e2e.Network, agent: str, message_id: str) -> bool:
    return net.postgres.sql(f"host_{net.home[agent]}", f"SELECT count(*) FROM inbox WHERE message_id = '{message_id}'") == "1"


def dump(net: e2e.Network, host: str) -> str:
    """Everything a host's database holds, as its backup would."""
    return subprocess.run(
        ["docker", "exec", net.postgres.name, "pg_dump", "-U", "splint", "-d", f"host_{host}"],
        check=True, capture_output=True, text=True,
    ).stdout


def sign_rules(net: e2e.Network, agent: str, entries: list[dict], sealing: str | None = None, **more) -> None:
    draft = e2e.rules_draft(entries, **more)
    if sealing:
        draft["sealing"] = sealing
    status, answer = net.put_rules(agent, net.owners[agent].sign("rules", "--agent", net.ids[agent], stdin=json.dumps(draft)))
    if status != 200:
        raise RuntimeError(f"{agent}'s rules were refused: {status} {answer}")


def stored_body(net: e2e.Network, agent: str, message_id: str) -> str:
    """What the recipient's host holds of a message's body."""
    envelope = net.postgres.sql(f"host_{net.home[agent]}", f"SELECT envelope FROM inbox WHERE message_id = '{message_id}'")
    return e2e.payload_of(envelope)["body"] if envelope else ""


def is_sealed(body: str) -> bool:
    return body.startswith('{"sealed":')


def sent(net: e2e.Network, sender: str, recipient: str, body: str) -> str:
    status, answer = net.send(sender, recipient, body)
    if status != 200:
        raise RuntimeError(f"{sender} couldn't send: {status} {answer}")
    return answer["message_id"]


def nothing_a_host_holds_says_what_was_said(net: e2e.Network) -> None:
    net.signets["ben"].kill_hard()
    message_id = sent(net, "ana", "ben", SECRET)
    check("control: it reaches Ben's host", wait_until(lambda: on_host(net, "ben", message_id)))
    body = stored_body(net, "ben", message_id)
    check("Ben's host holds it sealed", is_sealed(body) and "4417" not in body, body[:120])
    request = open_request(net, "ana", "ben", purpose="follow_up")
    check("control: a request waits there too", wait_until(lambda: len(host_chain(net, "ana", request)) >= 1))
    for host in ("a", "b"):
        held = dump(net, host)
        # The words, not the bare number, which a date a host keeps in the clear can hold by chance.
        check(f"host {host}'s whole database, as a backup holds it, has none of the words", "gate code is 4417" not in held and "off the books" not in held)
        check(f"or any of the request's terms", '"purpose"' not in held and "follow_up" not in held)
    outside = json.loads(e2e.payload_of(host_chain(net, "ana", request)[0])["body"])["sealed"]["outside"]
    check("a host sees only the kind of step and the type it opens", outside == {"step": "open", "opens": e2e.example_id("meeting/1")}, outside)
    net.signets["ben"].start()
    net.wait_for_signet("ben")
    check("Ben's agent reads it, opened by its own Signet", wait_until(lambda: SECRET in net.bodies("ben")), net.inbox("ben"))
    check("and the request", wait_for(net, "ben", request, state="offered") is not None, view(net, "ben", request))
    check("the words reach no log", SECRET.encode() not in net.process_logs())
    net.ack_all("ben")


def a_host_that_changes_sealed_bytes_gets_nothing_through(net: e2e.Network) -> None:
    good = sealed_by(net, "ana", "ana", "ben", "control: sealed by Ana's key")
    lying_host_delivers(net, "ana", "ben", good)
    check("control: a sealed envelope Ana's key signed is read", wait_until(lambda: "control: sealed by Ana's key" in net.bodies("ben")), net.inbox("ben"))
    net.ack_all("ben")

    payload = e2e.payload_of(sealed_by(net, "ana", "ana", "ben", "changed on the way"))
    body = json.loads(payload["body"])
    flipped = body["sealed"]["to"]
    body["sealed"]["to"] = flipped[:-6] + ("A" if flipped[-6] != "A" else "B") + flipped[-5:]
    payload["body"] = json.dumps(body, separators=(",", ":"))
    head, _, signature = good.split(".")
    tampered = ".".join([head, e2e.encode(e2e.compact_json(payload)), signature])
    lying_host_delivers(net, "ana", "ben", tampered)
    time.sleep(SETTLE_SECONDS)
    page = net.inbox("ben")
    check("a host that changes a sealed body gets nothing to the agent", page["messages"] == [] and page["dropped"] >= 1, page)

    to_cara = sealed_by(net, "ana", "ana", "ben", "sealed to someone else", sealed_to="carol")
    elsewhere = lying_host_delivers(net, "ana", "ben", to_cara)
    time.sleep(SETTLE_SECONDS)
    page = net.inbox("ben")
    check("one sealed to another key, even signed by the sender, opens for nobody here", page["messages"] == [], page)
    # Bug caught: a body that wouldn't open cleared at the host, which is how a lost key destroyed mail.
    check("and waits at the host, said to be held, as not opening proves nothing", on_host(net, "ben", elsewhere) and any(line["kind"] == "sealed_to_another_key" for line in page.get("held", [])), page)
    net.postgres.sql("host_b", f"DELETE FROM inbox WHERE message_id = '{elsewhere}'")

    stolen = sealed_by(net, "ana", "ana", "ben", "words posing as progress")
    posing = with_outside(net, "ana", stolen, lambda outside: outside.update({"step": "progress", "request": "ab" * 32}))
    lying_host_delivers(net, "ana", "ben", posing)
    time.sleep(SETTLE_SECONDS)
    page = net.inbox("ben")
    check("an outside that says something else is refused, whoever signed it", page["messages"] == [], page)


def a_host_swapping_the_key_someone_seals_to_is_caught(net: e2e.Network) -> None:
    # Before their agents have met, so nothing has pinned Eve's key yet.
    net.add_owned_agents({"dan": "a", "eve": "b"}, agree=False)
    real = net.agent_identity("eve")
    event = json.loads(e2e.decode(real.split("~")[0]))
    event["seal"] = e2e.new_key(net.work / "eves-swapped-seal.key")
    swapped = e2e.encode(json.dumps(event, separators=(",", ":")).encode())
    net.postgres.sql("host_b", f"UPDATE agents SET identity = '{swapped}' WHERE handle = 'eve'")
    status, answer = net.send("dan", "eve", "sealed to a key Eve's host swapped in")
    check("a host that swaps the key Eve seals to finds nobody", status != 200, (status, answer))
    net.postgres.sql("host_b", f"UPDATE agents SET identity = '{real}' WHERE handle = 'eve'")
    check("and nothing reaches Eve", net.inbox("eve")["messages"] == [], net.inbox("eve"))
    # Dan's Signet remembers the failed lookup for 30 seconds before asking Eve's host again, so a dead
    # contact can't tie it up. The usual wait from here ended only just after that, by however long the
    # steps above took, and missed it on a fast database.
    check("control: with Eve's own identity, it goes", wait_until(lambda: net.send("dan", "eve", "sealed to Eve's own key")[0] == 200, timeout=REMEMBERED_FAILURE_SECONDS + e2e.WAIT_SECONDS))
    check("control: and Eve reads it", wait_until(lambda: "sealed to Eve's own key" in net.bodies("eve")), net.inbox("eve"))
    net.ack_all("eve")


def mixed_pairs_seal_both_ways(net: e2e.Network) -> None:
    net.add_owned_agents({"fay": "a", "gus": "b"})
    sign_rules(net, "fay", [net.contact_entry("gus")], sealing="unsealed")
    first = sent(net, "fay", "gus", "fay, who chose unsealed, writes first")
    check("an unsealed owner's agent seals to a contact that hasn't said", wait_until(lambda: is_sealed(stored_body(net, "gus", first))))
    check("control: Gus reads it", wait_until(lambda: "fay, who chose unsealed, writes first" in net.bodies("gus")))
    net.ack_all("gus")
    back = sent(net, "gus", "fay", "gus, who's sealed by default, answers")
    check("a sealed owner's agent seals back", wait_until(lambda: is_sealed(stored_body(net, "fay", back))))
    check("control: Fay reads it", wait_until(lambda: "gus, who's sealed by default, answers" in net.bodies("fay")))
    net.ack_all("fay")
    again = sent(net, "fay", "gus", "fay again, having heard gus chose sealed")
    check("and the unsealed side keeps sealing, as the stricter side wins", wait_until(lambda: is_sealed(stored_body(net, "gus", again))))
    net.ack_all("gus")
    request = open_request(net, "fay", "gus")
    found = wait_for(net, "gus", request, state="offered")
    check("control: a request between them goes", found is not None, view(net, "gus", request))
    status, _ = move(net, "gus", request, "accept", {"pick": {"start": found["terms"]["slots"][0]}}) if found else (0, {})
    check("control: and is answered", status == 200 and wait_for(net, "fay", request, state="accepted") is not None, view(net, "fay", request))
    bodies = [json.loads(e2e.payload_of(step)["body"]) for step in host_chain(net, "fay", request)]
    moves = [body for body in bodies if not ("step" in body and body["step"] == "received")]
    check("each step either way is sealed, and only a receipt isn't", moves and all("sealed" in body for body in moves), [list(body) for body in bodies])

    net.add_owned_agents({"hal": "a", "ivy": "b"})
    sign_rules(net, "hal", [net.contact_entry("ivy")], sealing="unsealed")
    sign_rules(net, "ivy", [net.contact_entry("hal")], sealing="unsealed")
    first = sent(net, "hal", "ivy", "hal, unsealed, before ivy has said")
    check("two unsealed owners: the first message is sealed, as nobody has said", wait_until(lambda: is_sealed(stored_body(net, "ivy", first))))
    wait_until(lambda: "hal, unsealed, before ivy has said" in net.bodies("ivy"))
    net.ack_all("ivy")
    back = sent(net, "ivy", "hal", "ivy, unsealed, answers in the open")
    check("then unsealed, which both hosts can read", wait_until(lambda: stored_body(net, "hal", back) == "ivy, unsealed, answers in the open"), stored_body(net, "hal", back))
    wait_until(lambda: "ivy, unsealed, answers in the open" in net.bodies("hal"))
    net.ack_all("hal")
    open_again = sent(net, "hal", "ivy", "hal answers in the open too")
    check("both ways", wait_until(lambda: stored_body(net, "ivy", open_again) == "hal answers in the open too"), stored_body(net, "ivy", open_again))
    wait_until(lambda: "hal answers in the open too" in net.bodies("ivy"))
    net.ack_all("ivy")
    sign_rules(net, "ivy", [net.contact_entry("hal")])
    now_sealed = sent(net, "ivy", "hal", "ivy has chosen sealed now")
    check("an owner changing to sealed seals at once", wait_until(lambda: is_sealed(stored_body(net, "hal", now_sealed))))
    wait_until(lambda: "ivy has chosen sealed now" in net.bodies("hal"))
    net.ack_all("hal")
    reply = sent(net, "hal", "ivy", "hal, still unsealed, after hearing that")
    check("and the other side follows once it hears", wait_until(lambda: is_sealed(stored_body(net, "ivy", reply))))
    net.ack_all("ivy")


def every_content_check_still_refuses_sealed(net: e2e.Network) -> None:
    """What each host checks of content, it can't once a body is sealed. Ben's Signet does it instead,
    so a lying host and a stolen key together get none of these past it."""
    net.add_owned_agents({"jo": "a", "kit": "b"})
    jo, kit = "jo", "kit"

    sign_rules(net, kit, [net.contact_entry(jo, text=False)])
    text_off = sealed_by(net, jo, jo, kit, "sealed words, with text off")
    status = http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": text_off, "recipient_host": net.domain["b"]})[0]
    check("control: Jo's own host takes them, as Jo's owner signed text for Kit", status == 200, status)
    text_off_id = e2e.message_id_of(text_off)
    delivered = wait_until(lambda: net.postgres.sql("host_a", f"SELECT status FROM outbound WHERE message_id = '{text_off_id}'") not in ("", "pending"))
    check("control: and hands them to Kit's host", delivered)
    check("Kit's host still refuses sealed words to a contact without text, from the outside", not on_host(net, kit, text_off_id))
    lying_host_delivers(net, jo, kit, sealed_by(net, jo, jo, kit, "sealed words a lying host passes on"))
    time.sleep(SETTLE_SECONDS)
    check("a reader's Signet refuses sealed words its owner hasn't signed text for", "sealed words a lying host passes on" not in net.bodies(kit), net.inbox(kit))
    sign_rules(net, kit, [net.contact_entry(jo)], limits={**e2e.LIMITS, "texts_per_contact_per_day": 2})
    for number in (1, 2, 3):
        lying_host_delivers(net, jo, kit, sealed_by(net, jo, jo, kit, f"sealed words, number {number}"))
    time.sleep(SETTLE_SECONDS)
    shown = net.bodies(kit)
    check("control: with text on, sealed words are read", "sealed words, number 1" in shown, shown)
    check("and the day's cap on them holds in Signet", "sealed words, number 3" not in shown, shown)
    net.ack_all(kit)

    def opens_on_kit(step: dict, why: str, control: bool = False) -> None:
        envelope = sealed_by(net, jo, jo, kit, step, nonce=e2e.encode(bytes(16)) if step.get("step") == "open" else "")
        request = e2e.message_id_of(envelope)
        lying_host_delivers(net, jo, kit, envelope)
        if control:
            check(why, wait_for(net, kit, request, state="offered") is not None, view(net, kit, request))
        else:
            time.sleep(SETTLE_SECONDS)
            check(why, view(net, kit, request).get("status") == 404, view(net, kit, request))

    opens_on_kit(meeting_open_step(), "control: a sealed open a stolen key signs is a step like any other", control=True)
    opens_on_kit(meeting_open_step(slots=[hours_from_now(24 * 20)]), "a sealed open with a time past two weeks is refused")
    meeting = e2e.example_id("meeting/1")
    sign_rules(net, kit, [{**net.contact_entry(jo), "types": [t for t in e2e.example_ids() if t != meeting], "agree_types": False}])
    opens_on_kit(meeting_open_step(purpose="intro"), "a sealed open of a type Kit's owner took off the list is refused")
    sign_rules(net, kit, [net.contact_entry(jo)])
    owners_words = net.owners[jo].sign("person-text", "--agent", net.ids[jo], "--to", net.ids[kit], stdin="from jo's owner")
    opens_on_kit({**meeting_open_step(purpose="review"), "person_text": owners_words}, "control: a sealed open carrying its owner's words is taken", control=True)
    # The same words, signed by the agent's key, so only the signature is wrong.
    agents_words = e2e.sign_jws(net.key_of(jo), "splint-person-text", e2e.decode(owners_words.split(".")[1]))
    opens_on_kit({**meeting_open_step(purpose="intro"), "person_text": agents_words}, "a sealed open carrying words its owner didn't sign is refused")
    approved = {**meeting_open_step(purpose="other"), "approval": e2e.sign_jws(net.key_of(jo), "splint-approval", e2e.compact_json({"v": 1}))}
    opens_on_kit(approved, "a sealed open carrying a yes its owner didn't sign is refused")


def a_sending_host_still_holds_ask_me_from_the_outside(net: e2e.Network) -> None:
    net.add_owned_agents({"lou": "a", "max": "b"})
    permissions = {**e2e.PERMISSIONS, "level": "ask_me"}
    sign_rules(net, "lou", [net.contact_entry("max")], permissions=permissions)
    envelope = sealed_by(net, "lou", "lou", "max", meeting_open_step(), nonce=e2e.encode(bytes(16)))
    status = http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": envelope, "recipient_host": net.domain["b"]})[0]
    check("at ask me, a sealed open that claims no yes is refused by the sending host", status == 403, status)
    sign_rules(net, "lou", [net.contact_entry("max")])
    status = http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": sealed_by(net, "lou", "lou", "max", meeting_open_step(), nonce=e2e.encode(bytes([1] * 16))), "recipient_host": net.domain["b"]})[0]
    check("control: below ask me it goes", status == 200, status)


def a_stolen_key_gets_no_agreed_type_past_the_hosts(net: e2e.Network) -> None:
    """Review of the v0 stack: nothing showed that the hosts' and the reader's own checks on agreed types
    hold against a key that skips Signet. A copy of Pam's key proposes and opens types to Rex, whose
    owner, like Pam's, lets them agree types."""
    net.add_owned_agents({"pam": "a", "rex": "b", "sid": "b"}, agree=False)
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "vectors"))
    from request_table import one_encoding, type_id  # noqa: PLC0415

    def sent(body: dict) -> str:
        return sealed_by(net, "pam", "pam", "rex", body, nonce=e2e.encode(os.urandom(16)))

    def proposing(schema: dict) -> str:
        return sent({"step": "open", "type": "type/1", "schema": json.loads(one_encoding(schema)), "deadline": hours_from_now(48)})

    def opening(schema: dict) -> str:
        slot = hours_from_now(24) // 1800 * 1800
        return sent({"step": "open", "type": type_id(schema), "terms": {"service": "cut", "slots": [slot]}, "deadline": hours_from_now(48)})

    def out(envelope: str) -> tuple[int, dict]:
        return http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": envelope, "recipient_host": net.domain["b"]})

    first, second, third = (HAIRCUT | {"type": f"cut{n}/1"} for n in range(3))
    two = [proposing(schema) for schema in (first, second)]
    check("control: the stolen key's first two proposals a day go", [out(one)[0] for one in two] == [200, 200])
    check("control: and reach Rex's agent", all(wait_for(net, "rex", e2e.message_id_of(one), state="offered") for one in two))
    status, refused = out(proposing(third))
    check("a third is refused at its own host", status == 429, (status, refused))
    status, refused = out(opening(third))
    check("and doesn't count as seen there, so its type can't be opened", status == 403, (status, refused))
    status, refused = out(opening(HAIRCUT | {"type": "never/1"}))
    check("nor can a type never proposed between them be", status == 403, (status, refused))
    elsewhere = HAIRCUT | {"type": "sids/1"}
    status, proposed = net.agent("pam", "POST", "/v0/types", {"contact": net.address("sid"), "schema": elsewhere})
    check("control: Pam's agent proposes a type to Sid", status == 200, proposed)
    status, refused = out(opening(elsewhere))
    check("nor one proposed with someone else", status == 403, (status, refused))
    status, opened = out(opening(first))
    check("control: a type proposed between them can be, as far as a host can tell", status == 200, (status, opened))
    lied = lying_host_delivers(net, "pam", "rex", proposing(third))
    time.sleep(SETTLE_SECONDS)
    check("and past a lying host of Rex's own, Rex's Signet takes no third proposal either", view(net, "rex", lied).get("status") == 404, view(net, "rex", lied))


def main() -> int:
    e2e.build()
    build_sealer()
    with e2e.running_network(owned=True) as network:
        for scenario in (
            nothing_a_host_holds_says_what_was_said,
            a_host_that_changes_sealed_bytes_gets_nothing_through,
            a_host_swapping_the_key_someone_seals_to_is_caught,
            mixed_pairs_seal_both_ways,
            every_content_check_still_refuses_sealed,
            a_sending_host_still_holds_ask_me_from_the_outside,
            a_stolen_key_gets_no_agreed_type_past_the_hosts,
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

#!/usr/bin/env python3
"""Gate 4 for an agent's own words, and one contact crowding out everyone else's mail.

Words an agent chose pass only where the owner signed `text` for that contact, and no more than the
day's count each way, so two agents answering each other stop. One the count refuses costs no action. Signet refuses first, and each host holds the
same line for a stolen key that skips Signet. Separately, a contact that leaves 100 steps waiting on
a `prev` that never comes can't keep anyone else's message off the agent's page.

Everything is the real software against Postgres, like e2e.py, and every agent is assumed fooled.
A stolen key is what signs straight to a host. Each refusal has a control that succeeds.
"""

import base64
import json
import secrets
import shutil
import sys
from pathlib import Path

import e2e
from e2e import check, http, wait_until
from request_driver import hours_from_now, meeting_ask, move, signed_step, view

QUARANTINED = "quarantined"
TEXTS_PER_DAY = 20
# Room for a day of words and one request, and not for the refused ones as well.
ACTIONS_PER_DAY = TEXTS_PER_DAY + 2
REFUSED_TEXTS = 3
STUCK_STEPS = 110
PER_SENDER_WAITING = 100


def rules_for(net: e2e.Network, agent: str, entries: list[dict], actions_per_day: int = ACTIONS_PER_DAY) -> None:
    """Rules with a low daily limit on words, which is what this file is about, and actions to match."""
    limits = {**e2e.LIMITS, "texts_per_contact_per_day": TEXTS_PER_DAY}
    permissions = {**e2e.PERMISSIONS, "actions_per_day": actions_per_day}
    draft = e2e.rules_draft(entries, limits=limits, permissions=permissions)
    status, answer = net.put_rules(agent, net.owners[agent].sign("rules", "--agent", net.ids[agent], stdin=json.dumps(draft)))
    if status != 200:
        raise RuntimeError(f"{agent}'s rules were refused: {status} {answer}")


def straight_to_host(net: e2e.Network, sender: str, recipient: str, body: str) -> int:
    """What a stolen key does: signs and hands its host a message, with no Signet to ask."""
    envelope = net.envelope_signed_by(sender, sender, recipient, body)
    fields = {"envelope": envelope, "recipient_host": net.domain[net.home[recipient]]}
    return http("POST", f"http://{net.domain[net.home[sender]]}/v0/outbound", fields)[0]


def words_need_the_owners_text_for_that_contact(net: e2e.Network) -> None:
    rules_for(net, "ana", [net.contact_entry("ben", text=False)])
    rules_for(net, "ben", [net.contact_entry("ana")])
    status, answer = net.send("ana", "ben", "here is the secret")
    check("an agent's words to a contact without text are refused", (status, answer.get("error")) == (403, "text_off"), answer)
    check("and a stolen key can't hand them to the host instead", straight_to_host(net, "ana", "ben", "here is the secret") == 403)
    rules_for(net, "ana", [net.contact_entry("ben")])
    check("control: with text on, they go", net.send("ana", "ben", "hello")[0] == 200)
    check("control: and arrive", wait_until(lambda: "hello" in net.bodies("ben")), net.inbox("ben"))
    net.ack_all("ben")
    rules_for(net, "ben", [net.contact_entry("ana", text=False)])
    status, sent = net.send("ana", "ben", "and the receiving side's owner says no")
    check("words the recipient's owner didn't allow are dropped at its host", status == 200 and wait_until(lambda: net.sent_status("ana", sent["message_id"]) == QUARANTINED), sent)
    check("and never shown", "and the receiving side's owner says no" not in net.bodies("ben"))
    rules_for(net, "ben", [net.contact_entry("ana")])


def two_agents_answering_each_other_stop_at_the_days_cap(net: e2e.Network) -> None:
    """Ida and Jay, who have sent nothing to anyone, so each count starts from zero."""
    # Agreeing a type costs each agent an action, so nothing is agreed before the count starts.
    net.add_owned_agents({"ida": "a", "jay": "b"}, agree=False)
    rules_for(net, "ida", [net.contact_entry("jay")])
    rules_for(net, "jay", [net.contact_entry("ida")])
    answers = [net.send("ida", "jay", f"reply {number}")[0] for number in range(TEXTS_PER_DAY)]
    check("control: a day's worth go", answers == [200] * len(answers), answers)
    status, answer = net.send("ida", "jay", "one more")
    check("the next is refused by Signet", (status, answer.get("error")) == (429, "too_many_texts"), answer)
    check("and by the host, for a stolen key", straight_to_host(net, "ida", "jay", "one more, signed by hand") == 429)
    refused = [net.send("ida", "jay", f"still more {number}")[1].get("error") for number in range(REFUSED_TEXTS)]
    check("words past the cap stay refused", refused == ["too_many_texts"] * REFUSED_TEXTS, refused)
    check("the other way has its own count", net.send("jay", "ida", "answering")[0] == 200)
    status, opened = net.agent("ida", "POST", "/v0/requests", meeting_ask(net.address("jay")))
    check("steps aren't words, and refused words cost no action, so a request still goes", status == 200, opened)
    net.ack_all("ida")
    net.ack_all("jay")


# Few enough that words run out of actions well before they reach the day's words.
FEW_ACTIONS = 3


def words_the_days_actions_refuse_use_none_of_the_days_words(net: e2e.Network) -> None:
    """Kai has a day's words for Lou and only a few actions. Bug caught: each refused retry at the
    action limit using one of Lou's words, so once the owner raises the actions, fewer than the day's
    words are left."""
    net.add_owned_agents({"kai": "a", "lou": "b"}, agree=False)
    rules_for(net, "kai", [net.contact_entry("lou")], actions_per_day=FEW_ACTIONS)
    rules_for(net, "lou", [net.contact_entry("kai")])
    sent = [net.send("kai", "lou", f"early {number}")[0] for number in range(FEW_ACTIONS)]
    check("control: the day's actions go", sent == [200] * FEW_ACTIONS, sent)
    refused = [net.send("kai", "lou", f"retry {number}")[1].get("error") for number in range(REFUSED_TEXTS)]
    check("control: past them, words are refused for actions", refused == ["over_limit"] * REFUSED_TEXTS, refused)
    rules_for(net, "kai", [net.contact_entry("lou")])
    left = TEXTS_PER_DAY - FEW_ACTIONS
    after = [net.send("kai", "lou", f"later {number}")[0] for number in range(left)]
    check("with more actions, every word left in the day goes", after == [200] * left, after)
    status, answer = net.send("kai", "lou", "and no more")
    check("and the day's words then stop where they should", (status, answer.get("error")) == (429, "too_many_texts"), answer)
    net.ack_all("lou")


def one_contact_cant_crowd_out_others_mail(net: e2e.Network) -> None:
    rules_for(net, "ana", [net.contact_entry("ben"), net.contact_entry("mallory")])
    rules_for(net, "mallory", [net.contact_entry("ana")])
    host_a = f"host_{net.home['ana']}"
    for number in range(STUCK_STEPS):
        fake = f"{number:064x}"
        step = {"step": "clarify", "request": fake, "prev": fake, "reason": "other_times"}
        envelope = signed_step(net, "mallory", "mallory", "ana", step)
        fields = {"envelope": envelope, "recipient_host": net.domain[net.home["ana"]]}
        e2e.as_the_queue_drains(lambda fields=fields: http("POST", f"http://{net.domain[net.home['mallory']]}/v0/outbound", fields))
    waiting = lambda: int(net.postgres.sql(host_a, f"SELECT count(*) FROM inbox WHERE recipient = '{net.ids['ana']}' AND NOT acked AND sender = '{net.ids['mallory']}'"))  # noqa: E731
    check("one contact's stuck steps fill only its own share of the inbox", wait_until(lambda: waiting() == PER_SENDER_WAITING) and waiting() == PER_SENDER_WAITING, waiting())
    status, sent = net.send("ben", "ana", "from someone else")
    check("control: another contact's message is sent", status == 200, sent)
    check("and the agent sees it, past a page's worth of stuck steps", wait_until(lambda: "from someone else" in net.bodies("ana")), net.inbox("ana"))
    net.ack_all("ana")


# Where a P-256 key's private scalar starts inside the DER Signet keeps its key file in.
SCALAR_STARTS_AFTER = bytes([0x02, 0x01, 0x01, 0x04, 0x20])
SCALAR_BYTES = 32


def base32_of(raw: bytes) -> str:
    """Lower-case base32 of 16 bytes, unpadded, as Splint's codes spell them."""
    return base64.b32encode(raw).decode().rstrip("=").lower()


def scalar_in(pkcs8: bytes) -> bytes:
    """The private scalar in a key file kept as PKCS#8, as Signet's and `owner-key`'s plain ones are."""
    start = pkcs8.index(SCALAR_STARTS_AFTER) + len(SCALAR_STARTS_AFTER)
    return pkcs8[start:start + SCALAR_BYTES]


def scalar_of(net: e2e.Network, agent: str, key_file: str = "agent.key") -> bytes:
    """A private scalar from one of the agent's key files, which a fooled agent on the same account could
    read: its signing key's or its delegate key's."""
    return scalar_in((net.work / agent / key_file).read_bytes())


def a_key_pasted_as_its_owners_would_be(key_file: bytes) -> list[tuple[str, str]]:
    """The ways a fooled agent could paste a plain key file it read: the whole file, and the bare private
    scalar in hex and in base64, as (form, text)."""
    scalar = scalar_in(key_file)
    return [
        ("key file as PEM", pem_of(key_file)),
        ("key in hex", f"key {scalar.hex()}"),
        ("key in base64", base64.b64encode(scalar).decode()),
    ]


def pem_of(der: bytes) -> str:
    body = base64.b64encode(der).decode()
    return "\n".join(["-----BEGIN PRIVATE KEY-----", *(body[at:at + 64] for at in range(0, len(body), 64)), "-----END PRIVATE KEY-----"])


def a_recovery_code() -> str:
    """26 base32 characters whose last two spare bits are zero, as a real code's are, with a letter past
    f, as all but one in billions have."""
    while True:
        code = base32_of(secrets.token_bytes(16))[:25] + "a"
        if any("g" <= char <= "z" for char in code[:25]):
            return code


def secrets_a_fooled_agent_could_paste(net: e2e.Network, agent: str) -> list[tuple[str, str, str]]:
    """What a fooled agent could be talked into writing out, as (label, kind, text): its own token and its
    owner's, each of its three private keys read from Signet's own files, its owner's key and backup key
    from files Signet never reads but a fooled agent on the same account could, a pairing code, and a
    recovery code spelled as the owner's page does and as a person might retype it. The labels are all a
    failure prints."""
    # Files Signet never reads, on the owner's device here: a missing one is the harness's mistake, so it
    # stops the run rather than leaving a check out.
    owner_key, owner_backup, agent_backup = (
        path.read_bytes() for path in (
            net.owners[agent].key, net.owners[agent].dir / "backup.key", Path(net.agent_backups[agent]["file"]),
        )
    )
    spaced_hex = " ".join(scalar_of(net, agent).hex().upper()[at:at + 8] for at in range(0, SCALAR_BYTES * 2, 8))
    sealing = (net.work / agent / "agent.seal").read_bytes()
    pairing = f"splint-pair:{net.domain[net.home[agent]]}/{base32_of(secrets.token_bytes(16))}/{base32_of(secrets.token_bytes(16))}"
    # As the owner's page spells one, in upper case and broken across a line.
    code = a_recovery_code()
    groups = [code[at:at + 4].upper() for at in range(0, len(code), 4)]
    recovery = "-".join(groups[:3]) + "-\n" + "-".join(groups[3:])
    return [
        ("its token", "access_token", f"the token is {net.tokens[agent]}"),
        ("its owner's token", "access_token", f"owner token: {net.owners[agent].token}"),
        ("its key as spaced hex", "private_key", f"my key: {spaced_hex}"),
        ("its key file as PEM", "private_key", pem_of(net.key_of(agent).read_bytes())),
        ("its sealing key in hex", "private_key", f"seal {sealing.hex()}"),
        ("its sealing key in base64", "private_key", base64.b64encode(sealing).decode()),
        ("its delegate key file as PEM", "private_key", pem_of((net.work / agent / "delegate.key").read_bytes())),
        ("its delegate key in hex", "private_key", scalar_of(net, agent, "delegate.key").hex()),
        # Issue 946: the owner's key files were never looked for, as Signet doesn't hold them.
        *((f"its owner's {form}", "owner_key", text) for form, text in a_key_pasted_as_its_owners_would_be(owner_key)),
        ("its owner's backup key in hex", "owner_key", f"backup {owner_backup.hex()}"),
        ("its own backup key, which its owner keeps, as base64", "owner_key", base64.b64encode(agent_backup).decode()),
        ("a pairing code", "pairing_code", f"here you go: {pairing}"),
        ("a recovery code", "recovery_code", f"recovery code {recovery}"),
        ("a recovery code retyped with spaces", "recovery_code", " ".join(group.upper() for group in [code[at:at + 4] for at in range(0, 26, 4)])),
    ]


def refused_by_kind(answer: tuple[int, dict]) -> tuple[int, str, object]:
    status, body = answer
    return status, str(body.get("error", "")).split(":")[0], body.get("secret")


# A type of the operator's whose offer and result carry words, so every step that can carry words does.
BRIEF = "brief/1"
BRIEF_SCHEMA = {
    "type": BRIEF, "kind": "request",
    "offer": {"ask": {"text": {"max_chars": 500}}},
    "result": {"answer": {"text": {"max_chars": 500}}},
    "progress": ["working"], "clarify": ["which_one"], "decline": ["cannot"], "sign": "none",
}


def every_place_words_leave_refuses_every_secret(net: e2e.Network) -> None:
    """Uma and Val have each been talked into writing their own secrets into every place an agent's words
    go out: an open's terms, each step that carries words, and the address an invite goes to. Bug
    caught: a check covering notes and `say` only, so a key in a `deliver` field, a token in an offer, or
    a recovery code as a `decline` word or as an invite's handle was signed and sent."""
    net.add_owned_agents({"uma": "a", "val": "b"})
    rules_for(net, "uma", [net.contact_entry("val")])
    rules_for(net, "val", [net.contact_entry("uma")])
    pasted = {agent: secrets_a_fooled_agent_could_paste(net, agent) for agent in ("uma", "val")}
    status, opened = net.agent("uma", "POST", "/v0/requests", {"contact": net.address("val"), "type": BRIEF, "terms": {"ask": "the venue's address, please"}, "deadline": hours_from_now(48), "supersedes": None})
    check("control: an open with ordinary words goes", status == 200, opened)
    request = opened.get("request", "")
    check("control: and reaches val", wait_until(lambda: view(net, "val", request).get("state") == "offered"), view(net, "val", request))
    host = net.domain[net.home["val"]]
    # Each place, with whose words go out there: the requester's or the recipient's.
    carriers = {
        "an open's terms": ("uma", lambda text: net.agent("uma", "POST", "/v0/requests", {"contact": net.address("val"), "type": BRIEF, "terms": {"ask": text}, "deadline": hours_from_now(48), "supersedes": None})),
        "a counter's terms": ("val", lambda text: move(net, "val", request, "counter", {"terms": {"ask": text}})),
        "an accept's pick": ("val", lambda text: move(net, "val", request, "accept", {"pick": {"ask": text}})),
        "a deliver's result": ("val", lambda text: move(net, "val", request, "deliver", {"result": {"answer": text}})),
        "an invite's address": ("uma", lambda text: net.agent("uma", "POST", "/v0/invites", {"to": f"{text}~{host}"})),
    }
    for place, (agent, carry) in carriers.items():
        # A field can't hold a line break, so a paste into one has spaces in their place.
        wrong = [label for label, kind, text in pasted[agent] if refused_by_kind(carry(text.replace("\n", " "))) != (403, "holds_secret", kind)]
        check(f"{place} holding any of its writer's secrets is refused, by kind", wrong == [], wrong)
    # A word is short and plain, so only a recovery code run together fits in one.
    code = a_recovery_code()
    for step, field in (("clarify", "reason"), ("progress", "status"), ("decline", "reason")):
        refused = refused_by_kind(move(net, "val", request, step, {field: code}))
        check(f"a {step} word that's a recovery code is refused", refused == (403, "holds_secret", "recovery_code"), refused)
    refused = refused_by_kind(net.send("uma", "val", f"{net.tokens['uma']} {'x' * e2e.MAX_ENVELOPE_CHARS}"))
    check("a note too long for any envelope is refused before it's looked at", refused[:2] == (400, "too_long"), refused)
    # A proposed type's words are its writer's too, looked at run together. Review of the v0 stack:
    # nothing showed the look runs on a proposal at all.
    key = scalar_of(net, "uma").hex()
    held = {"type": "held/1", "kind": "request", "offer": {"size": {"word": ["small"]}}, "progress": [key[:32]], "clarify": [key[32:]], "sign": "both"}
    refused = refused_by_kind(net.agent("uma", "POST", "/v0/types", {"contact": net.address("val"), "schema": held}))
    check("a proposal holding its writer's key, split across two of its words, is refused", refused[:2] == (403, "holds_secret"), refused)
    # Uma has proposed her two for the day already, which is checked after the look.
    plain = held | {"progress": ["working"], "clarify": ["which_one"]}
    status, proposed = net.agent("uma", "POST", "/v0/types", {"contact": net.address("val"), "schema": plain})
    check("control: the same proposal with other words gets past the look", (status, proposed.get("error")) in ((200, None), (409, "too_many_proposals")), proposed)
    accepted = move(net, "val", request, "accept", {"pick": {}})
    check("control: an ordinary accept goes", accepted[0] == 200, accepted)
    delivered = move(net, "val", request, "deliver", {"result": {"answer": "12 Main St"}})
    check("control: and an ordinary deliver", delivered[0] == 200, delivered)
    arrived = wait_until(lambda: view(net, "uma", request).get("result", {}).get("answer") == "12 Main St")
    check("control: whose words arrive", arrived, view(net, "uma", request))
    seen = json.dumps([view(net, side, request) for side in ("uma", "val")]) + "".join(net.bodies("val") + net.bodies("uma"))
    every = [one for each in pasted.values() for one in each]
    leaked = [label for label, _, text in every if text.replace("\n", " ") in seen or text in seen] + (["the code as a word"] if code in seen else [])
    check("nothing refused reached either side", leaked == [], leaked)
    logs = net.process_logs().lower()
    keys = {f"{agent}'s {name}": key for agent in ("uma", "val") for name, key in (("sealing key", (net.work / agent / "agent.seal").read_bytes()), ("delegate key", scalar_of(net, agent, "delegate.key")))}
    check("and no log holds a sealing or delegate key", [name for name, key in keys.items() if key.hex().encode() in logs] == [])
    net.ack_all("val")
    net.ack_all("uma")


def a_fooled_agent_cant_send_its_own_secrets(net: e2e.Network) -> None:
    """Oli has been talked into writing out its own secrets, in a note and in a conversation. Bug
    caught: Signet signing and sending them, as it did any words the owner allowed."""
    net.add_owned_agents({"oli": "a", "pia": "b"})
    rules_for(net, "oli", [net.contact_entry("pia")])
    rules_for(net, "pia", [net.contact_entry("oli")])
    pasted = secrets_a_fooled_agent_could_paste(net, "oli")
    for label, kind, text in pasted:
        status, answer = net.send("oli", "pia", text)
        refused = (status, str(answer.get("error", "")).split(":")[0], answer.get("secret"))
        check(f"a note holding {label} is refused, by kind", refused == (403, "holds_secret", kind), refused[:2])
    status, opened = net.agent("oli", "POST", "/v0/requests", {"contact": net.address("pia"), "deadline": hours_from_now(48), "supersedes": None})
    check("control: a conversation opens", status == 200, opened)
    request = opened.get("request", "")
    for label, kind, text in pasted:
        # A field can't hold a line break, so a paste into one has spaces in their place.
        status, answer = move(net, "oli", request, "say", {"fields": {"text": text.replace("\n", " ")}})
        refused = (status, str(answer.get("error", "")).split(":")[0], answer.get("secret"))
        check(f"a conversation's words holding {label} are refused too", refused == (403, "holds_secret", kind), refused[:2])
    check("control: an ordinary note goes", net.send("oli", "pia", "see you at noon")[0] == 200)
    # Bug caught: a look that refuses any private key rather than its owner's, so an agent can't hand
    # over a key someone asked it to make for them.
    e2e.new_key(net.work / "oli-stranger.key")
    strangers = a_key_pasted_as_its_owners_would_be((net.work / "oli-stranger.key").read_bytes())
    sent = [form for form, text in strangers if net.send("oli", "pia", text)[0] == 200]
    check("control: someone else's key, pasted the same ways, goes", sent == [form for form, _ in strangers], sent)
    check("control: and ordinary words in the conversation", move(net, "oli", request, "say", {"fields": {"text": "noon works"}})[0] == 200)
    check("and arrives", wait_until(lambda: "see you at noon" in net.bodies("pia")))
    arrived = wait_until(lambda: [said.get("fields", {}).get("text") for said in view(net, "pia", request).get("messages", [])] == ["noon works"])
    check("and so do the conversation's ordinary words, and nothing else", arrived, len(view(net, "pia", request).get("messages", [])))
    bodies = net.bodies("pia")
    leaked = [label for label, _, text in pasted if any(text in body for body in bodies)]
    check("nothing refused reached the other side", leaked == [], leaked)
    check("and no log holds the key", scalar_of(net, "oli").hex().encode() not in net.process_logs().lower())
    net.ack_all("pia")


def main() -> int:
    e2e.build()
    # The example types and one of this run's own, as any operator gives its Signets theirs.
    schemas = e2e.short_scratch("splint-types-")
    for schema in e2e.SCHEMAS.glob("*.json"):
        shutil.copy(schema, schemas)
    (schemas / "brief-1.json").write_text(json.dumps(BRIEF_SCHEMA))
    e2e.SCHEMAS = schemas
    e2e.EXAMPLE_TYPES.append(BRIEF)
    try:
        with e2e.running_network(owned=True) as network:
            for scenario in (
                words_need_the_owners_text_for_that_contact,
                two_agents_answering_each_other_stop_at_the_days_cap,
                words_the_days_actions_refuse_use_none_of_the_days_words,
                one_contact_cant_crowd_out_others_mail,
                a_fooled_agent_cant_send_its_own_secrets,
                every_place_words_leave_refuses_every_secret,
            ):
                print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
                scenario(network)
            if e2e.failures:
                for process in network.processes:
                    print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1500:]}")
    finally:
        shutil.rmtree(schemas, ignore_errors=True)
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

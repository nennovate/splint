#!/usr/bin/env python3
"""An owner's delegate key: a yes within the caps the owner signed, with the agent assumed fully fooled
and able to read its Signet's state. And rules that last until the owner replaces them, with nobody
there and no delegate renewing anything.

Everything here is the real software against Postgres, like e2e.py. Owners sign with the real owner-key
tool. Rules dated as if the owner's device signed them nearly 30 days ago, with the 30-day end every
rules document carried before 2026-11-15, are the owner's clock, which is how time is passed in: the
hosts and Signets keep their own. A key read from a Signet's folder and used
straight at a host is a fooled agent sharing an OS user with its Signet.

The owner's rules name the one delegation they allow, and it counts at Signet and at the sending host
only while the rules in force there name it.

Not shown here: an owner whose key is a passkey (the Rust tests and the vectors cover one signing a
delegation), hardware-held keys, and a counterparty that keeps a record of delegations, which none does
yet. The day's yeses are counted by the agent's own Signet and again by its host.
"""

import hashlib
import json
import sys
import time

import e2e
from e2e import check, http, wait_until
from request_driver import draft_for, hours_from_now, move, owner_call, owner_decides, priced_move, sign_approval, signed_step, view, wait_for
from sealed import build_sealer, sealed_by

QUOTE = "quote/1"
QUOTE_TERMS = {"currency": "usd", "item": "catering", "quantity": 40}
AUTO = {"level": "auto_within_limits", "actions_per_day": 500, "caps": {}}
CAPPED = {"level": "auto_within_limits", "actions_per_day": 500, "caps": {QUOTE: {"amount_minor.usd": 100_000}}}
# How long until an end in the rules passes, once they arrive.
LIFE_LEFT = 10
SETTLE_SECONDS = 2.0


def rules_for(net: e2e.Network, agent: str, contacts: list[dict], **draft) -> str:
    rules = net.owners[agent].sign("rules", "--agent", net.ids[agent], stdin=json.dumps(e2e.rules_draft(contacts, **draft)))
    status, answer = net.put_rules(agent, rules)
    if status != 200:
        raise RuntimeError(f"{agent}'s rules were refused: {status} {answer}")
    return rules


def name_of(delegation: str) -> str:
    """How rules name a delegation: the hex SHA-256 of its signing input, the header and payload."""
    return hashlib.sha256(delegation.rsplit(".", 1)[0].encode()).hexdigest()


def rules_naming(net: e2e.Network, agent: str, contacts: list[dict], delegation: str | None, **draft) -> str:
    """Rules the owner's device signs naming this delegation, or none, whatever it signed before."""
    signed = net.owners[agent].sign("rules", "--agent", net.ids[agent], stdin=json.dumps(e2e.rules_draft(contacts, **draft)))
    payload = {key: value for key, value in e2e.payload_of(signed).items() if key != "delegation"}
    if delegation:
        payload["delegation"] = name_of(delegation)
    rules = e2e.sign_jws(net.owners[agent].key, "splint-rules", e2e.compact_json(payload))
    status, answer = net.put_rules(agent, rules)
    if status != 200:
        raise RuntimeError(f"{agent}'s rules were refused: {status} {answer}")
    return rules


def rules_ending_soon(net: e2e.Network, agent: str, contacts: list[dict], delegation: str | None = None, left: int = LIFE_LEFT, end: str = "expires_at") -> tuple[str, int]:
    """Rules the owner's device signed as if nearly 30 days ago, with an end in `left` seconds: the old
    30-day `expires_at` every device wrote before 2026-11-15, or an `ends_at` the owner chose."""
    signed = net.owners[agent].sign("rules", "--agent", net.ids[agent], stdin=json.dumps(e2e.rules_draft(contacts)))
    payload = {key: value for key, value in e2e.payload_of(signed).items() if key != "delegation"}
    now = int(time.time())
    payload |= {"seq": payload["seq"] + 1, "issued_at": now + left - 30 * e2e.DAY, end: now + left}
    if delegation:
        payload["delegation"] = name_of(delegation)
    rules = e2e.sign_jws(net.owners[agent].key, "splint-rules", e2e.compact_json(payload))
    status, answer = net.put_rules(agent, rules)
    if status != 200:
        raise RuntimeError(f"{agent}'s rules were refused: {status} {answer}")
    return rules, payload[end]


def signed_delegation(net: e2e.Network, agent: str, days: int | None = None) -> dict:
    """What an owner does once: reads the key Signet shows, and signs a delegation to it from the rules
    their own device last signed, and those rules again naming it, for a year unless `days` says less."""
    status, shown = owner_call(net, agent, "/v0/owner/delegation")
    if status != 200:
        raise RuntimeError(f"{agent}'s Signet showed {status} {shown}")
    lasting = ["--days", str(days)] if days else []
    return json.loads(net.owners[agent].sign("delegate", "--agent", net.ids[agent], "--delegate", shown["delegate"], *lasting))


def hand_over(net: e2e.Network, agent: str, signed: dict) -> None:
    status, answer = net.agent(agent, "PUT", "/v0/owner/delegation", {"delegation": signed["delegation"]})
    if status != 200:
        raise RuntimeError(f"{agent}'s delegation was refused: {status} {answer}")


def name_delegation(net: e2e.Network, agent: str, signed: dict) -> str:
    """The rules naming it, which it counts under alone."""
    status, answer = net.put_rules(agent, signed["rules"])
    if status != 200:
        raise RuntimeError(f"{agent}'s rules naming the delegation were refused: {status} {answer}")
    return signed["delegation"]


def delegate(net: e2e.Network, agent: str) -> str:
    signed = signed_delegation(net, agent)
    hand_over(net, agent, signed)
    return name_delegation(net, agent, signed)


def opens(net: e2e.Network, requester: str, recipient: str, kind: str, terms: dict) -> tuple[int, dict]:
    body = {"contact": net.address(recipient), "type": kind, "terms": terms, "deadline": hours_from_now(48), "supersedes": None}
    return net.agent(requester, "POST", "/v0/requests", body)


def meeting(net: e2e.Network, requester: str, recipient: str) -> tuple[int, dict]:
    offer = {"duration_min": 30, "mode": "video", "purpose": "intro", "slots": [hours_from_now(24)]}
    return opens(net, requester, recipient, "meeting/1", offer)


def conversation(net: e2e.Network, requester: str, recipient: str) -> tuple[int, dict]:
    """Core's plain conversation, which an agent opens with no type agreed, as one whose contact hasn't
    listed it back can't agree one."""
    return net.agent(requester, "POST", "/v0/requests", {"contact": net.address(recipient), "deadline": hours_from_now(48), "supersedes": None})


def accept_first_slot(net: e2e.Network, agent: str, request: str) -> None:
    move(net, agent, request, "accept", {"pick": {"start": view(net, agent, request)["terms"]["slots"][0]}})


def held_rules(net: e2e.Network, agent: str) -> str:
    return net.postgres.sql(f"host_{net.home[agent]}", f"SELECT compact FROM rules WHERE agent = '{net.ids[agent]}'")


def rules_last_until_the_owner_replaces_them(net: e2e.Network) -> None:
    """Nenye, 2026-11-15: rules an owner sets last for the agent's life. Bugs caught: an agent stopped
    30 days after its owner last signed, by the end every rules document carried then, and a reader
    keeping what a delegate renewed back then rather than only what the owner signed."""
    _, ends = rules_ending_soon(net, "ana", [net.contact_entry("ben")])
    rules_ending_soon(net, "carol", [net.contact_entry("ana")], end="ends_at")
    check("control: before the end, carol's agent acts", conversation(net, "carol", "ana")[0] == 200)
    check("the old 30-day end passes", wait_until(lambda: time.time() > ends + 1, timeout=LIFE_LEFT + 30))
    status, opened = meeting(net, "ana", "ben")
    check("past it, the agent still opens a request, with no delegate and nobody there", status == 200, opened)
    check("and its host still carries it", bool(wait_for(net, "ben", opened.get("request", ""), state="offered")))
    check("an end the owner chose stops the agent", conversation(net, "carol", "ana")[0] == 403)
    check("and Signet says why", net.agent("carol", "GET", "/v0/identity")[1].get("stopped") == "rules_ended")

    # Rules a delegate renewed before 2026-11-15 arrive as the owner's, the renewal and the delegation.
    newer = rules_for(net, "ana", [net.contact_entry("ben")])
    status, _ = http("PUT", f"http://{net.domain[net.home['ana']]}/v0/rules", {"rules": "~".join([newer, "renewal", "delegation"])})
    check("control: the same rules in the old renewed form answer as before", status == 200, status)
    check("a host keeps only the part the owner signed", held_rules(net, "ana") == newer, held_rules(net, "ana")[:80])


def a_fooled_agent_with_the_delegate_key_gets_no_further_than_the_caps(net: e2e.Network) -> None:
    """The delegate key is in Signet's folder, which an agent sharing its OS user can read."""
    rules_for(net, "ana", [net.contact_entry("ben")], permissions=CAPPED)
    rules_for(net, "ben", [net.contact_entry("ana")], permissions=AUTO)
    signed = signed_delegation(net, "ana")
    hand_over(net, "ana", signed)

    def delivered(amount: int) -> str:
        status, opened = opens(net, "ana", "ben", QUOTE, QUOTE_TERMS)
        request = opened.get("request", "")
        if status != 200 or not wait_for(net, "ben", request, state="offered"):
            raise RuntimeError(f"open failed: {status} {opened}")
        move(net, "ben", request, "accept", {})
        priced_move(net, "ben", request, "deliver", {"result": {"amount_minor": amount, "valid_days": 14}})
        return request

    status, opened = meeting(net, "ana", "ben")
    met = opened.get("request", "")
    check("control: ana asks ben for a meeting", status == 200 and bool(wait_for(net, "ben", met, state="offered")), opened)
    move(net, "ben", met, "accept", {"pick": {"start": view(net, "ben", met)["terms"]["slots"][0]}})
    wait_for(net, "ana", met, state="accepted")
    time.sleep(SETTLE_SECONDS)
    check("Signet holding a delegation says no yes under it until the owner's rules name it", view(net, "ana", met).get("state") == "accepted" and draft_for(net, "ana", met) is not None)
    delegation = name_delegation(net, "ana", signed)
    check("once they do, Signet says yes by itself and the other side takes it", bool(wait_for(net, "ben", met, state="requester_confirmed")), view(net, "ben", met))

    within = delivered(90_000)
    wait_for(net, "ana", within, state="delivered")
    time.sleep(SETTLE_SECONDS)
    check("a price within the caps still waits for the owner, as anything with an amount does", view(net, "ana", within).get("state") == "delivered" and draft_for(net, "ana", within) is not None, view(net, "ana", within))

    over = delivered(120_000)
    wait_for(net, "ana", over, state="delivered")
    time.sleep(SETTLE_SECONDS)
    draft = draft_for(net, "ana", over)
    check("over the cap, it waits for the owner", draft is not None and view(net, "ana", over).get("state") == "delivered")

    stolen = net.work / "ana" / "delegate.key"
    yes = f"{sign_approval(net, 'ana', draft, signer=stolen)}~{delegation}"
    step = {"step": "confirm", "request": over, "prev": draft["prev"], "approval": yes}
    host = f"http://{net.domain[net.home['ana']]}/v0/outbound"
    sent = http("POST", host, {"envelope": signed_step(net, "ana", "ana", "ben", step), "recipient_host": net.domain[net.home["ben"]]})
    check("its host has no schema to read values by, so it carries the step", sent[0] == 200, sent)
    time.sleep(SETTLE_SECONDS)
    refused = owner_call(net, "ben", "/v0/owner/refused")[1].get("refused", [])
    over_limit = any(one["way"] == "in" and one["reason"] == "over_limit" and one["from"] == net.ids["ana"] for one in refused)
    check("but the other side refuses a yes over the cap the owner signed", over_limit and view(net, "ben", over).get("state") == "delivered", refused)

    owners = sign_approval(net, "ana", draft)
    step = {"step": "confirm", "request": over, "prev": draft["prev"], "approval": owners}
    sent = http("POST", host, {"envelope": signed_step(net, "ana", "ana", "ben", step), "recipient_host": net.domain[net.home["ben"]]})
    check("control: the owner's own yes on the same step goes", sent[0] == 200 and bool(wait_for(net, "ben", over, state="completed")), view(net, "ben", over))


def the_owners_limits_bind_their_delegate(net: e2e.Network) -> None:
    """Signet counts the day's yeses, only for a yes that went, and says none at ask me. A fooled agent
    holding the delegate key gets no yes past its host at ask me, sealed or not, nor under a delegation
    the owner's rules don't name, which new rules end at once, with no renewal in between. Only the
    owner's token has Signet make a new delegate key, and rules naming none then stop the old one's
    yeses at the host."""
    net.add_owned_agents({"dee": "a", "eli": "b", "fay": "b"})
    rules_for(net, "eli", [net.contact_entry("dee")], permissions=AUTO)
    rules_for(net, "fay", [net.contact_entry("dee")], permissions=AUTO)
    both = [net.contact_entry("eli"), net.contact_entry("fay")]
    capped = {**CAPPED, "actions_per_day": 1}
    rules_for(net, "dee", both, permissions=capped)
    older = delegate(net, "dee")
    time.sleep(0.05)
    newer = delegate(net, "dee")
    status, _ = net.agent("dee", "PUT", "/v0/owner/delegation", {"delegation": older})
    check("an older delegation handed back after a newer one is refused", status == 403, status)
    held = owner_call(net, "dee", "/v0/owner/delegation")[1].get("delegation") or {}
    check("control: the newer one is the one held, and the rules name it", held.get("seq") == e2e.payload_of(newer)["seq"] and held.get("counts"), held)
    check("its host holds rules naming it, with no renewal", e2e.payload_of(held_rules(net, "dee")).get("delegation") == name_of(newer) and "~" not in held_rules(net, "dee"))

    # The rules let the agent act, and the delegation one yes a day.
    rules_naming(net, "dee", both, newer, permissions=CAPPED)
    meetings = []
    for _ in range(2):
        status, opened = meeting(net, "dee", "eli")
        check("dee asks eli for a meeting", status == 200, opened)
        meetings.append(opened.get("request", ""))
    status, opened = meeting(net, "dee", "fay")
    check("and fay", status == 200, opened)
    to_fay = opened.get("request", "")
    # A host checks a queued step against the rules in force when it goes, so these have to arrive
    # before the owner moves to ask me, or they'd wait for a yes.
    for request in meetings:
        wait_for(net, "eli", request, state="offered")
    wait_for(net, "fay", to_fay, state="offered")
    rules_naming(net, "dee", both, newer, permissions={**CAPPED, "level": "ask_me"})
    accept_first_slot(net, "fay", to_fay)
    check("fay accepts hers", bool(wait_for(net, "dee", to_fay, state="accepted")))
    time.sleep(3 * SETTLE_SECONDS)
    check("at ask me, Signet says no yes by itself", view(net, "dee", to_fay).get("state") == "accepted")

    stolen = net.work / "dee" / "delegate.key"
    host = f"http://{net.domain[net.home['dee']]}/v0/outbound"

    def fooled_yes(request: str, to: str, delegation: str, sealed: bool, signer=stolen) -> int:
        draft = draft_for(net, "dee", request)
        if draft is None:
            raise RuntimeError(f"no draft waits for {request}: {view(net, 'dee', request)}")
        yes = f"{sign_approval(net, 'dee', draft, signer=signer)}~{delegation}"
        step = {"step": "confirm", "request": request, "prev": draft["prev"], "approval": yes}
        dates = (e2e.payload_of(yes)["issued_at"], e2e.payload_of(yes)["expires_at"])
        envelope = sealed_by(net, "dee", "dee", to, step, dates=dates) if sealed else signed_step(net, "dee", "dee", to, step)
        return http("POST", host, {"envelope": envelope, "recipient_host": net.domain[net.home[to]]})[0]

    for sealed in (True, False):
        status = fooled_yes(to_fay, "fay", newer, sealed)
        check(f"at ask me, its host refuses a {'sealed' if sealed else 'plain'} delegate's yes a fooled agent signed", status == 403, status)

    # The owner takes fay off, so the yes Signet says to fay's quote can't go, and costs nothing.
    rules_naming(net, "dee", [net.contact_entry("eli")], newer, permissions=CAPPED)
    time.sleep(3 * SETTLE_SECONDS)
    check("control: a yes to someone the owner took off doesn't go", view(net, "dee", to_fay).get("state") == "accepted")
    for request in meetings:
        accept_first_slot(net, "eli", request)
    check("eli accepts both", wait_until(lambda: all(view(net, "dee", request).get("state") in ("accepted", "requester_confirmed") for request in meetings)))
    check("below ask me, Signet says one yes, as the one that didn't go used none of the day's", wait_until(lambda: any(view(net, "dee", request).get("state") == "requester_confirmed" for request in meetings)))
    time.sleep(3 * SETTLE_SECONDS)
    states = sorted(view(net, "dee", request).get("state") for request in meetings)
    check("and the other waits, as the delegation allows one a day", states == ["accepted", "requester_confirmed"], states)

    waiting = next(request for request in meetings if view(net, "dee", request).get("state") == "accepted")
    check("its host refuses a yes under a delegation the rules don't name", fooled_yes(waiting, "eli", older, sealed=True) == 403)
    owner_rules = held_rules(net, "dee").split("~")[0]
    now = int(time.time())
    renewal = {"v": 1, "rules": hashlib.sha256(owner_rules.encode()).hexdigest(), "issued_at": now, "expires_at": now + 30 * e2e.DAY}
    renewed = "~".join([owner_rules, e2e.sign_jws(stolen, "splint-rules-renewal", e2e.compact_json(renewal)), older])
    http("PUT", f"http://{net.domain[net.home['dee']]}/v0/rules", {"rules": renewed})
    check("and the rules in force handed back as renewed under it are only the owner's", held_rules(net, "dee") == owner_rules, held_rules(net, "dee")[:80])
    check("so a yes under it is still refused", fooled_yes(waiting, "eli", older, sealed=False) == 403)

    # Lower caps bind once the owner signs them with a new delegation: the one before carries its own.
    # Signet isn't handed this one, so it says no yes by itself while the fooled agent reads the draft.
    lower = {**CAPPED, "caps": {QUOTE: {"amount_minor.usd": 95_000}}}
    rules_for(net, "dee", [net.contact_entry("eli")], permissions=lower)
    check("rules with other permissions name no delegation, so the old caps end at once", fooled_yes(waiting, "eli", newer, sealed=True) == 403)
    lowered = name_delegation(net, "dee", signed_delegation(net, "dee"))
    check("nor once the owner names a new one with the lower caps", fooled_yes(waiting, "eli", newer, sealed=False) == 403)
    rules_for(net, "dee", [net.contact_entry("eli"), net.contact_entry("fay")], permissions=lower)
    check("rules with the same permissions and one more contact go on naming it", e2e.payload_of(held_rules(net, "dee")).get("delegation") == name_of(lowered))
    check("control: a yes under the one the rules name goes, within the day's yeses at the host", fooled_yes(waiting, "eli", lowered, sealed=True) == 200)

    # The fooled agent copies the delegate key, and the owner, thinking it got out, has Signet make a new one.
    old_key = net.work / "dee-old-delegate.key"
    old_key.write_bytes(stolen.read_bytes())
    rotate = f"http://127.0.0.1:{net.signet_port['dee']}/v0/owner/delegate-key"
    status, _ = http("POST", rotate, token=net.tokens["dee"])
    check("the agent's own token can't replace the delegate key, which would end the owner's delegation", status == 401, status)
    status, rotated = http("POST", rotate, token=net.owners["dee"].token)
    check("the owner's token can", status == 200 and bool(rotated.get("delegate")), rotated)
    shown = owner_call(net, "dee", "/v0/owner/delegation")[1]
    check("Signet shows the new key, and holds no delegation", shown.get("delegate") == rotated.get("delegate") and shown.get("delegation") is None, shown)
    after = []
    for _ in range(2):
        status, opened = meeting(net, "dee", "eli")
        check("dee asks eli for another meeting", status == 200, opened)
        after.append(opened.get("request", ""))
        wait_for(net, "eli", after[-1], state="offered")
        accept_first_slot(net, "eli", after[-1])
    check("two more are accepted", all(wait_for(net, "dee", request, state="accepted") for request in after))
    check("control: the host still carries the old key's yes while the rules name its delegation", fooled_yes(after[0], "eli", lowered, sealed=True, signer=old_key) == 200)
    rules = net.owners["dee"].sign("rules", "--agent", net.ids["dee"], "--delegation", "none", stdin=json.dumps(e2e.rules_draft([net.contact_entry("eli")], permissions=lower)))
    check("the owner signs the same rules naming none", net.put_rules("dee", rules)[0] == 200 and "delegation" not in e2e.payload_of(held_rules(net, "dee")))
    check("and the host refuses the old key's yes", fooled_yes(after[1], "eli", lowered, sealed=True, signer=old_key) == 403)


# A day's actions small enough that a fifth of them, the day's yeses, is two.
FEW_ACTIONS = 10
YESES = FEW_ACTIONS // 5


def a_delegate_says_a_fifth_of_the_days_actions_at_its_signet_and_its_host(net: e2e.Network) -> None:
    """Hap's owner signs 10 actions a day, so their delegate says 2 yeses, and their delegation names
    the same 10. Bugs caught: Signet's delegate saying yes up to the day's actions rather than a fifth,
    and a fooled agent reading the delegate key off disk to say more yeses straight at its host, which
    counted none."""
    net.add_owned_agents({"hap": "a", "ike": "b"})
    rules_for(net, "ike", [net.contact_entry("hap")], permissions=AUTO)
    rules_for(net, "hap", [net.contact_entry("ike")], permissions={**AUTO, "actions_per_day": FEW_ACTIONS})
    delegation = delegate(net, "hap")
    meetings = []
    for _ in range(YESES + 1):
        status, opened = meeting(net, "hap", "ike")
        request = opened.get("request", "")
        check("control: hap opens a meeting with ike", status == 200 and bool(wait_for(net, "ike", request, state="offered")), opened)
        slot = view(net, "ike", request)["terms"]["slots"][0]
        move(net, "ike", request, "accept", {"pick": {"start": slot}})
        meetings.append(request)
    confirmed = lambda: sum(view(net, "ike", request).get("state") == "requester_confirmed" for request in meetings)  # noqa: E731
    check("the delegate confirms a fifth of the day's actions", wait_until(lambda: confirmed() == YESES), confirmed())
    time.sleep(3 * SETTLE_SECONDS)
    waiting = [request for request in meetings if draft_for(net, "hap", request) is not None]
    check("and the next yes waits for the owner", confirmed() == YESES and len(waiting) == 1, [view(net, "hap", request).get("state") for request in meetings])
    if not waiting:
        return
    draft = draft_for(net, "hap", waiting[0])
    yes = f"{sign_approval(net, 'hap', draft, signer=net.work / 'hap' / 'delegate.key')}~{delegation}"
    step = {"step": "confirm", "request": waiting[0], "prev": draft["prev"], "approval": yes}
    sent = http("POST", f"http://{net.domain[net.home['hap']]}/v0/outbound", {"envelope": signed_step(net, "hap", "hap", "ike", step), "recipient_host": net.domain[net.home["ike"]]})
    check("its host refuses one more a fooled agent says past Signet with the delegate key", sent[0] == 429, sent)


def a_value_with_a_contact_the_owner_hasnt_approved_waits_for_them(net: e2e.Network) -> None:
    """Pia's owner signs a delegation with caps, and lets in contacts her agent agrees with by itself.
    Her agent agrees with Quin's. Bugs caught: the delegate saying yes to a price within the caps with
    someone the owner never approved, so a fooled agent that agrees with anyone commits its owner to
    them, and a fooled agent's sealed yes with the delegate key doing the same past Signet.
    Even a meeting waits for the owner until they approve the contact."""
    price_with_an_agreed_contact_waits(net, "pia", "quin", e2e.reach_setting())


def open_for_meetings_doesnt_approve_an_agreed_contacts_price(net: e2e.Network) -> None:
    """The same, with Ivo's owner open to anyone, for meetings only. Bug caught: anyone counting as
    approved once an owner lets people in beyond contacts, so an agreed contact could use a type no
    stranger may and have its price signed within the caps, without the owner."""
    price_with_an_agreed_contact_waits(net, "ivo", "jem", e2e.reach_setting("open", ["meeting/1"]))


def price_with_an_agreed_contact_waits(net: e2e.Network, payer: str, seller: str, reach: dict) -> None:
    net.add_owned_agents({payer: "a"})
    net.add_owned_agents({seller: "b"})
    reach = reach | {"agreed": {"types": e2e.EXAMPLE_TYPES, "text": True}}
    caps = {**CAPPED, "caps": {QUOTE: {"amount_minor.usd": 100_000}, "meeting/1": {}}}
    rules_for(net, seller, [], reach=e2e.reach_setting() | {"agreed": reach["agreed"]}, permissions=AUTO)
    rules_for(net, payer, [], reach=reach, permissions=caps)
    delegation = delegate(net, payer)
    check(f"control: {payer}'s agent invites {seller}'s", net.agent(payer, "POST", "/v0/invites", {"to": net.address(seller)})[0] == 200)
    invited = lambda: [one["from"] for one in net.agent(seller, "GET", "/v0/invites")[1].get("invites", [])]  # noqa: E731
    check(f"control: it reaches {seller}'s box", wait_until(lambda: net.address(payer) in invited()))
    status, accepted = net.agent(seller, "POST", f"/v0/invites/{net.address(payer)}/accept", {})
    check(f"control: {seller}'s accepts, and they're contacts at once", status == 200 and accepted.get("waiting_for_owner") is False, accepted)
    listed = lambda: next((one for one in net.agent(payer, "GET", "/v0/contacts")[1]["contacts"] if one["address"] == net.address(seller)), {})  # noqa: E731
    check(f"control: {payer}'s agent has {seller} as a contact its owner hasn't approved", wait_until(lambda: listed().get("approved_by_owner") is False), listed())

    status, opened = opens(net, payer, seller, QUOTE, QUOTE_TERMS)
    priced = opened.get("request", "")
    check(f"control: {payer} asks {seller} for a quote", status == 200 and bool(wait_for(net, seller, priced, state="offered")), opened)
    move(net, seller, priced, "accept", {})
    priced_move(net, seller, priced, "deliver", {"result": {"amount_minor": 90_000, "valid_days": 14}})
    check("control: it's delivered within the caps", bool(wait_for(net, payer, priced, state="delivered")))
    check("and the agent reading it is told the owner hasn't approved them", view(net, payer, priced).get("from", {}).get("approved_by_owner") is False, view(net, payer, priced))

    # A meeting after the price is there, which the delegate would confirm with an approved contact.
    slot = hours_from_now(24)
    status, opened = opens(net, payer, seller, "meeting/1", {"duration_min": 30, "mode": "video", "purpose": "intro", "slots": [slot]})
    met = opened.get("request", "")
    check(f"control: {payer} opens a meeting with {seller}", status == 200 and bool(wait_for(net, seller, met, state="offered")), opened)
    move(net, seller, met, "accept", {"pick": {"start": slot}})
    check(f"control: {payer}'s agent sees it accepted", bool(wait_for(net, payer, met, state="accepted")), view(net, payer, met))
    time.sleep(3 * SETTLE_SECONDS)
    # Issue 682. Bug caught: the delegate confirming anything with a contact the agent made itself.
    check("the delegate leaves even a meeting with someone the owner hasn't approved to the owner", view(net, payer, met).get("state") == "accepted" and draft_for(net, payer, met) is not None, view(net, payer, met))
    check("and the agent is told its person's yes is still to come", (view(net, payer, met).get("signatures") or {}).get("yours") == "to_come", view(net, payer, met))
    # Bug caught: an agent told to ask its person to set up controls they already have.
    check("a price with someone the owner hasn't approved waits for them, whatever the caps say", view(net, payer, priced).get("state") == "delivered" and draft_for(net, payer, priced) is not None and "ask_your_owner" not in view(net, payer, priced), view(net, payer, priced))

    # The fooled agent reads the delegate key off disk and says the yes itself, past Signet.
    stolen = net.work / payer / "delegate.key"
    outbound = f"http://{net.domain[net.home[payer]]}/v0/outbound"

    def fooled_yes(request: str, sealed: bool) -> tuple[int, dict]:
        draft = draft_for(net, payer, request)
        if draft is None:
            raise RuntimeError(f"no draft waits for {request}: {view(net, payer, request)}")
        yes = f"{sign_approval(net, payer, draft, signer=stolen)}~{delegation}"
        step = {"step": "confirm", "request": request, "prev": draft["prev"], "approval": yes}
        dates = (e2e.payload_of(yes)["issued_at"], e2e.payload_of(yes)["expires_at"])
        envelope = sealed_by(net, payer, payer, seller, step, dates=dates) if sealed else signed_step(net, payer, payer, seller, step)
        return http("POST", outbound, {"envelope": envelope, "recipient_host": net.domain[net.home[seller]]})

    sent = fooled_yes(priced, sealed=False)
    check("its host refuses a plain delegate's yes to that price, which a fooled agent signed past Signet", sent[0] == 403, sent)
    # Issue 682: the host can't see a sealed step's values, so it goes by who the yes is to.
    sent = fooled_yes(priced, sealed=True)
    check("and a sealed one within the caps", sent[0] == 403, sent)
    sent = fooled_yes(met, sealed=True)
    check("and a sealed one to the meeting", sent[0] == 403, sent)
    time.sleep(SETTLE_SECONDS)
    check(f"so {seller}'s side takes neither", view(net, seller, priced).get("state") == "delivered" and view(net, seller, met).get("state") == "accepted", (view(net, seller, priced), view(net, seller, met)))

    approved = e2e.named_at(net.address(seller), net.ids[seller]) | {"pinned_by": "invite"}
    rules_for(net, payer, [approved], reach=reach, permissions=caps)
    check("once the owner approves them, the agent is told so", wait_until(lambda: view(net, payer, priced).get("from", {}).get("approved_by_owner") is True), view(net, payer, priced))
    check("and the delegate confirms the meeting by itself", bool(wait_for(net, seller, met, state="requester_confirmed")), view(net, seller, met))
    # Issue 695: an accepted meeting reads as waiting on the owner until their confirm, which the delegate gave.
    check("and nothing on it waits for the owner after", "waiting_for_owner" not in view(net, payer, met), view(net, payer, met))
    time.sleep(3 * SETTLE_SECONDS)
    # Issue 809. Bug caught: the delegate saying yes to a price within the caps, where the owner is told
    # anything with an amount waits for them.
    check("and the price still waits for the owner, as anything with an amount does", view(net, payer, priced).get("state") == "delivered" and draft_for(net, payer, priced) is not None, view(net, payer, priced))
    status, decided = owner_decides(net, payer, priced)
    check("control: their own yes completes it", status == 200 and bool(wait_for(net, seller, priced, state="completed")), decided)


def sharing_an_owner(net: e2e.Network, agent: str, home: str, with_agent: str) -> None:
    """A new agent bound to the owner another one already has, as when a person runs two. At the other's
    host it goes under that owner's one name there, which the other has alone, as una.ula."""
    make_owners = net.make_owners
    net.owners[agent] = net.owners[with_agent]
    if net.home[with_agent] == home:
        net.names[agent] = f"{agent}.{net.names.get(with_agent, with_agent)}"
    net.make_owners = lambda agents: None
    try:
        net.add_owned_agents({agent: home})
    finally:
        net.make_owners = make_owners


def two_agents_of_one_owner_know_it_and_a_third_owners_dont(net: e2e.Network) -> None:
    """Ula's owner runs Ula and Uma, on two hosts, and Oto has another owner. Ula invites both, as
    agents add their own contacts. Bug caught: an owner's two agents treating each other as
    strangers their person hadn't approved, so one asked by the other to book something for their
    person refused, or asked a person it couldn't reach. A price between them within the owner's caps
    waits for the owner, as anything with an amount does, and their one yes completes it."""
    net.add_owned_agents({"ula": "a"})
    sharing_an_owner(net, "uma", "b", "ula")
    net.add_owned_agents({"oto": "b"})
    reach = e2e.reach_setting() | {"agreed": {"types": e2e.EXAMPLE_TYPES, "text": True}}
    caps = {**CAPPED, "caps": {QUOTE: {"amount_minor.usd": 100_000}, "meeting/1": {}}}
    for agent in ("ula", "uma", "oto"):
        rules_for(net, agent, [], reach=reach, permissions=caps if agent == "ula" else AUTO)
    delegate(net, "ula")
    owner_id = net.owners["ula"].id

    def invite_from_ula(to: str) -> dict:
        net.agent("ula", "POST", "/v0/invites", {"to": net.address(to)})
        found: dict = {}

        def arrived() -> bool:
            box = net.agent(to, "GET", "/v0/invites")[1].get("invites", [])
            found.update(next((one for one in box if one["from"] == net.address("ula")), {}))
            return bool(found)

        wait_until(arrived)
        return found

    def listed(agent: str, other: str) -> dict:
        contacts = net.agent(agent, "GET", "/v0/contacts")[1].get("contacts", [])
        return next((one for one in contacts if one["address"] == net.address(other)), {})

    # Nenye, 2026-11-14. Bug caught: an invite between one owner's own agents waiting on the invitee's
    # agent to decide, which costs it a run and can only ever be a yes.
    check("control: Ula invites Uma", net.agent("ula", "POST", "/v0/invites", {"to": net.address("uma")})[0] == 200)
    check("Uma's Signet accepts an invite from her own owner's other agent by itself, with no move by Uma or her person",
          wait_until(lambda: listed("uma", "ula").get("same_owner") is True and listed("uma", "ula").get("approved_by_owner") is True and listed("uma", "ula").get("owner") == owner_id),
          listed("uma", "ula"))
    check("so nothing from Ula waits in Uma's box", all(one["from"] != net.address("ula") for one in net.agent("uma", "GET", "/v0/invites")[1].get("invites", [])))
    to_oto = invite_from_ula("oto")
    check("Oto, of another owner, sees neither that nor the owner's ID, and is left to decide", bool(to_oto) and "same_owner" not in to_oto and "owner" not in to_oto, to_oto)
    accepted = {"oto": net.agent("oto", "POST", f"/v0/invites/{net.address('ula')}/accept", {})[1]}
    check("control: Oto accepts, and is told the owner hasn't approved Ula", accepted["oto"].get("approved_by_owner") is False and "same_owner" not in accepted["oto"], accepted["oto"])

    check("Ula lists Uma as her owner's, approved by them",
          wait_until(lambda: listed("ula", "uma").get("same_owner") is True and listed("ula", "uma").get("approved_by_owner") is True and listed("ula", "uma").get("owner") == owner_id),
          listed("ula", "uma"))
    check("and Oto as neither", wait_until(lambda: listed("ula", "oto").get("approved_by_owner") is False) and "same_owner" not in listed("ula", "oto"), listed("ula", "oto"))

    def from_in_inbox(agent: str, words: str) -> dict:
        page = net.inbox(agent)
        return next((one["verified"]["from"] for one in page.get("messages", []) if one["untrusted"]["body"] == words), {})

    net.send("ula", "uma", "please book Tuesday for our person")
    net.send("ula", "oto", "lunch tuesday?")
    check("Uma reads Ula's ask marked as from her own owner's agent, approved, its words still untrusted",
          wait_until(lambda: from_in_inbox("uma", "please book Tuesday for our person").get("same_owner") is True)
          and from_in_inbox("uma", "please book Tuesday for our person").get("approved_by_owner") is True,
          net.inbox("uma"))
    check("control: Oto reads Ula's note marked as neither",
          wait_until(lambda: from_in_inbox("oto", "lunch tuesday?").get("approved_by_owner") is False) and "same_owner" not in from_in_inbox("oto", "lunch tuesday?"),
          net.inbox("oto"))

    status, opened = opens(net, "ula", "uma", QUOTE, QUOTE_TERMS)
    priced = opened.get("request", "")
    check("control: Ula asks Uma for a quote", status == 200 and bool(wait_for(net, "uma", priced, state="offered")), opened)
    move(net, "uma", priced, "accept", {})
    priced_move(net, "uma", priced, "deliver", {"result": {"amount_minor": 90_000, "valid_days": 14}})
    check("control: Uma's price reaches Ula", bool(wait_for(net, "ula", priced, state="delivered")), view(net, "ula", priced))
    time.sleep(3 * SETTLE_SECONDS)
    # Issue 809. Bug caught: Ula's delegate saying yes to a price within the caps.
    check("and waits for the owner, though it's between the owner's own agents", view(net, "ula", priced).get("state") == "delivered" and draft_for(net, "ula", priced) is not None, view(net, "ula", priced))
    status, decided = owner_decides(net, "ula", priced)
    check("control: the owner's yes completes it", status == 200 and bool(wait_for(net, "uma", priced, state="completed")), decided)


def an_invite_from_the_same_owner_that_cant_be_taken_still_wakes_the_agent(net: e2e.Network) -> None:
    """Bug caught: an invite from another of the owner's agents that Signet couldn't accept by itself,
    as on a full disk, stopped it before it woke the agent, so neither that invite nor any other new
    one was said until it expired. A folder Signet can't write to stands for the full disk. Runs after
    Uma and Ula are set up."""
    sharing_an_owner(net, "una", "a", "ula")
    reach = e2e.reach_setting() | {"agreed": {"types": e2e.EXAMPLE_TYPES, "text": True}}
    rules_for(net, "una", [], reach=reach, permissions=AUTO)
    status, mark = net.agent("uma", "POST", "/v0/wait", {"seconds": 1})
    check("control: Uma's agent has a mark to wait from", status == 200 and bool(mark.get("since")), mark)
    state = net.work / "uma"
    mode = state.stat().st_mode & 0o777
    state.chmod(0o555)
    try:
        check("control: Una, of the same owner, invites Uma", net.agent("una", "POST", "/v0/invites", {"to": net.address("uma")})[0] == 200)
        status, woke = net.agent("uma", "POST", "/v0/wait", {"since": mark.get("since"), "seconds": 60}, timeout=70)
        check("Uma's agent hears of it, though her Signet couldn't take it by itself", status == 200 and "messages" in woke.get("new", []), woke)
        box = net.agent("uma", "GET", "/v0/invites")[1].get("invites", [])
        check("and it waits in her box for her agent", any(one["from"] == net.address("una") for one in box), box)
    finally:
        state.chmod(mode)
    # Not checked: taking it once Signet can write again. Its acceptance had already gone, and it isn't
    # taken again on the next pass, which is left as an issue.


def a_delegates_yes_reads_as_its_own(net: e2e.Network) -> None:
    """Issue 776: a meeting both owners sign, which each side's delegate signed by itself within its
    owner's limits. Bugs caught: the record and the request crediting each owner with a yes nobody
    asked them for, so an agent told its person they had approved what they never saw."""
    net.add_owned_agents({"kim": "a", "lev": "b"})
    rules_for(net, "lev", [net.contact_entry("kim")], permissions=AUTO)
    rules_for(net, "kim", [net.contact_entry("lev")], permissions=AUTO)
    delegate(net, "kim")
    delegate(net, "lev")
    status, opened = meeting(net, "kim", "lev")
    request = opened.get("request", "")
    check("control: kim opens a meeting with lev", status == 200 and bool(wait_for(net, "lev", request, state="offered")), opened)
    move(net, "lev", request, "accept", {"pick": {"start": view(net, "lev", request)["terms"]["slots"][0]}})
    check("control: each side's delegate says yes by itself, and it's settled", bool(wait_for(net, "kim", request, state="completed")), view(net, "kim", request))
    signed = view(net, "kim", request).get("signatures")
    check("the request says each side's yes was its delegate's", signed == {"yours": "delegate", "theirs": "delegate"}, signed)
    record = net.agent("kim", "GET", f"/v0/requests/{request}/record")[1].get("text", "")
    check("and so does the record, crediting neither owner", record.count("'s owner's delegate, within the owner's limits: approved") == 2 and "'s owner: approved" not in record, record)


def main() -> int:
    e2e.build()
    build_sealer()
    with e2e.running_network(owned=True) as network:
        for scenario in (
            rules_last_until_the_owner_replaces_them,
            a_fooled_agent_with_the_delegate_key_gets_no_further_than_the_caps,
            the_owners_limits_bind_their_delegate,
            a_delegate_says_a_fifth_of_the_days_actions_at_its_signet_and_its_host,
            a_value_with_a_contact_the_owner_hasnt_approved_waits_for_them,
            open_for_meetings_doesnt_approve_an_agreed_contacts_price,
            two_agents_of_one_owner_know_it_and_a_third_owners_dont,
            an_invite_from_the_same_owner_that_cant_be_taken_still_wakes_the_agent,
            a_delegates_yes_reads_as_its_own,
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

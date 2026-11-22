#!/usr/bin/env python3
"""An owner at ask me, and what a step can carry past its host, with the agent assumed fully fooled.

Everything here is the real software against Postgres, like e2e.py. Owners sign with the real owner-key
tool. A key skipping Signet is a stolen one, or an agent sharing an OS user with its Signet, and it
signs straight to a host. A lying host is SQL writing straight to an agent's page. Each refusal has a
control that succeeds.

Not shown here: an owner's device apart from the agent's machine, hardware-held keys, a host and a key
working together, and what a key skipping Signet can say in a number or in a signature's randomness,
which no host can see.
"""

import json
import os
import sys
import time

import e2e
from e2e import check, http, wait_until
from request_driver import as_a_host_sees, draft_for, host_chain, hours_from_now, meeting_open_step, move, owner_call, owner_decides, post_approval, sign_approval, signed_step, step_kind, view, wait_for

QUOTE = "quote/1"
QUOTE_TERMS = {"currency": "usd", "item": "catering", "quantity": 40}
QUOTE_RESULT = {"amount_minor": 120000, "valid_days": 14}
DOCUMENT = "document/1"
DOCUMENT_TERMS = {"format": "pdf", "kind": "invoice"}
TWO_WEEKS_HOURS = 14 * 24
ASK_ME = {"level": "ask_me", "actions_per_day": 500, "caps": {}}
AUTO = {"level": "auto_within_limits", "actions_per_day": 500, "caps": {}}
SETTLE_SECONDS = 1.0


def rules_for(net: e2e.Network, agent: str, contacts: list[dict], **draft) -> None:
    rules = net.owners[agent].sign("rules", "--agent", net.ids[agent], stdin=json.dumps(e2e.rules_draft(contacts, **draft)))
    status, answer = net.put_rules(agent, rules)
    if status != 200:
        raise RuntimeError(f"{agent}'s rules were refused: {status} {answer}")


def ana_at_auto_and_ben_at(net: e2e.Network, permissions: dict, **ben) -> None:
    rules_for(net, "ana", [net.contact_entry("ben")], permissions=AUTO)
    rules_for(net, "ben", [net.contact_entry("ana")], permissions=permissions, **ben)


def opens(net: e2e.Network, requester: str, recipient: str, kind: str = QUOTE, terms: dict | None = None, **changes) -> tuple[int, dict]:
    body = {"contact": net.address(recipient), "type": kind, "terms": QUOTE_TERMS if terms is None else terms, "deadline": hours_from_now(48), "supersedes": None}
    return net.agent(requester, "POST", "/v0/requests", body | changes)


def offered_to(net: e2e.Network, requester: str, recipient: str, kind: str = QUOTE, terms: dict | None = None) -> str:
    status, opened = opens(net, requester, recipient, kind, terms)
    if status != 200 or not wait_for(net, recipient, opened.get("request", ""), state="offered"):
        raise RuntimeError(f"open failed: {status} {opened}")
    return opened["request"]


def to_host(net: e2e.Network, sender: str, recipient: str, envelope: str) -> tuple[int, dict]:
    fields = {"envelope": envelope, "recipient_host": net.domain[net.home[recipient]]}
    return http("POST", f"http://{net.domain[net.home[sender]]}/v0/outbound", fields)


def kinds_at_host(net: e2e.Network, agent: str, request: str) -> list[str]:
    return [step_kind(step) for step in host_chain(net, agent, request)]


def ask_me_holds_each_committing_step_for_the_owners_yes(net: e2e.Network) -> None:
    ana_at_auto_and_ben_at(net, ASK_ME)
    request = offered_to(net, "ana", "ben")

    status, answer = move(net, "ben", request, "accept")
    check("an accept waits", status == 200 and answer.get("waiting_for_owner") is True and answer.get("message_id") is None, answer)
    check("the agent can see that", view(net, "ben", request).get("waiting_for_owner") == "accept", view(net, "ben", request))
    time.sleep(SETTLE_SECONDS)
    check("and nothing went", "accept" not in kinds_at_host(net, "ben", request) and view(net, "ana", request)["state"] == "offered", kinds_at_host(net, "ben", request))
    draft = draft_for(net, "ben", request)
    check("the owner is asked about exactly that", draft is not None and draft["operation"] == "accept" and draft["terms"]["agreed"] == QUOTE_TERMS, draft)

    status, answer = owner_decides(net, "ben", request, "deny")
    check("a no is taken", status == 200, answer)
    seen = view(net, "ben", request)
    check("and the agent hears it, with nothing sent", seen.get("owner_said_no") == "accept" and "waiting_for_owner" not in seen and seen["state"] == "offered", seen)
    check("nothing's left to decide", draft_for(net, "ben", request) is None)

    move(net, "ben", request, "accept")
    status, answer = owner_decides(net, "ben", request)
    check("a yes sends it", status == 200 and bool(answer.get("message_id")), answer)
    check("and the other side sees it", bool(wait_for(net, "ana", request, state="working")), view(net, "ana", request))
    # By its ID, not as the last step: the other side's own next step can land after it.
    sent = [step for step in host_chain(net, "ben", request) if e2e.message_id_of(step) == answer.get("message_id")]
    check("it carries the yes", len(sent) == 1 and "approval" in as_a_host_sees(sent[0]), [as_a_host_sees(step) for step in host_chain(net, "ben", request)])

    status, answer = move(net, "ben", request, "deliver", {"result": QUOTE_RESULT})
    check("a result waits, on a type an owner signs too", status == 200 and answer.get("waiting_for_owner") is True, answer)
    time.sleep(SETTLE_SECONDS)
    check("so the other side can't read it first", view(net, "ana", request)["result"] == {} and "deliver" not in kinds_at_host(net, "ben", request), view(net, "ana", request))
    draft = draft_for(net, "ben", request)
    check("the owner reads the amount", draft is not None and draft["terms"]["result"] == QUOTE_RESULT, draft)

    old_yes = sign_approval(net, "ben", draft)
    old_no = sign_approval(net, "ben", draft, decision="deny")
    lower = {"amount_minor": 1, "valid_days": 14}
    status, answer = move(net, "ben", request, "deliver", {"result": lower})
    check("the agent can change what it asks", status == 200 and answer.get("waiting_for_owner") is True, answer)
    status, answer = post_approval(net, "ben", old_yes)
    check("a yes to the old amount doesn't send the new one", (status, answer.get("error")) == (409, "approval_mismatch"), answer)
    check("or anything", view(net, "ana", request)["result"] == {}, view(net, "ana", request))
    status, answer = post_approval(net, "ben", old_no)
    check("and a no to the old amount doesn't take away the new one, which the owner hasn't seen", (status, answer.get("error")) == (409, "approval_mismatch") and view(net, "ben", request).get("waiting_for_owner") == "deliver", answer)

    draft = draft_for(net, "ben", request)
    status, answer = owner_decides(net, "ben", request)
    check("a yes to the new one sends it", status == 200 and draft["terms"]["result"] == lower, answer)
    check("and the other side reads that", bool(wait_for(net, "ana", request, state="delivered", result=lower)), view(net, "ana", request))
    check("which its own owner still has to sign", draft_for(net, "ana", request) is not None)
    status, answer = owner_decides(net, "ana", request)
    check("control: and it completes", status == 200 and bool(wait_for(net, "ben", request, state="completed")), answer)


def ask_me_holds_on_a_type_nobody_signs(net: e2e.Network) -> None:
    ana_at_auto_and_ben_at(net, ASK_ME)
    request = offered_to(net, "ana", "ben", DOCUMENT, DOCUMENT_TERMS)
    move(net, "ben", request, "accept")
    owner_decides(net, "ben", request)
    check("control: the accept goes on a yes", bool(wait_for(net, "ana", request, state="working")), view(net, "ana", request))
    status, answer = move(net, "ben", request, "deliver", {"result": {"pages": 3, "size_kb": 40}})
    check("a result nobody would sign still waits", status == 200 and answer.get("waiting_for_owner") is True, answer)
    time.sleep(SETTLE_SECONDS)
    check("and isn't there yet", view(net, "ana", request)["state"] == "working", view(net, "ana", request))
    owner_decides(net, "ben", request)
    check("a yes finishes it", bool(wait_for(net, "ana", request, state="completed")), view(net, "ana", request))

    request = offered_to(net, "ana", "ben", DOCUMENT, DOCUMENT_TERMS)
    status, answer = move(net, "ben", request, "clarify", {"reason": "which_one"})
    check("control: asking a question goes straight off", status == 200 and bool(answer.get("message_id")), answer)
    wait_for(net, "ana", request, state="clarifying")
    status, answer = move(net, "ana", request, "counter", {"terms": {"format": "text"}})
    check("control: at auto a counter goes straight off", status == 200 and bool(answer.get("message_id")), answer)
    wait_for(net, "ben", request, state="offered", version=2)
    status, answer = move(net, "ben", request, "counter", {"terms": {"format": "pdf"}})
    check("at ask me a counter waits", status == 200 and answer.get("waiting_for_owner") is True, answer)
    draft = draft_for(net, "ben", request)
    check("and the owner sees what it would offer, at the version it would make", draft is not None and draft["terms"]["agreed"]["format"] == "pdf" and draft["version"] == 3, draft)
    owner_decides(net, "ben", request)
    check("a yes sends it", bool(wait_for(net, "ana", request, state="offered", version=3)), view(net, "ana", request))
    wait_until(lambda: view(net, "ben", request)["version"] == 3)
    status, answer = move(net, "ben", request, "cancel")
    check("control: walking away commits nobody, so it goes straight off", status == 200 and bool(answer.get("message_id")), answer)


def ask_me_holds_a_new_interaction(net: e2e.Network) -> None:
    rules_for(net, "ana", [net.contact_entry("ben")], permissions=ASK_ME, limits={**e2e.LIMITS, "open_approvals": 2})
    rules_for(net, "ben", [net.contact_entry("ana")], permissions=AUTO)
    status, opened = opens(net, "ana", "ben", QUOTE, {**QUOTE_TERMS, "quantity": 77})
    check("an open waits", status == 200 and opened.get("waiting_for_owner") is True and opened.get("request") is None, opened)
    hold = opened.get("hold", "")
    listed = next((one for one in net.agent("ana", "GET", "/v0/requests")[1].get("held_opens", []) if one["hold"] == hold), {})
    check("the agent can find it", listed.get("status") == "waiting", listed)
    theirs = lambda: [one for one in net.agent("ben", "GET", "/v0/requests")[1]["requests"] if one["terms"].get("quantity") == 77]  # noqa: E731
    time.sleep(SETTLE_SECONDS)
    check("and the other side hasn't heard of it", theirs() == [], theirs())
    draft = draft_for(net, "ana", hold)
    check("the owner sees all of the offer", draft is not None and draft["operation"] == "open" and draft["terms"]["agreed"]["quantity"] == 77, draft)

    _, open_ask = net.agent("ana", "POST", "/v0/asks", {"changes": [{"change": "step", "request": hold, "operation": "open"}]})
    check("control: the agent asks its owner for that open", open_ask.get("status") == "waiting", open_ask)

    status, answer = owner_decides(net, "ana", hold)
    check("a yes starts it", status == 200 and bool(answer.get("message_id")), answer)
    check("and the other side gets it", wait_until(lambda: len(theirs()) == 1), theirs())
    _, shown = net.agent("ana", "GET", f"/v0/asks/{open_ask.get('id', '')}")
    # Bug caught: nothing held that an ask for a held open reads done once its owner signs it.
    check("its ask reads done", shown.get("status") == "done", shown)
    listed = next((one for one in net.agent("ana", "GET", "/v0/requests")[1].get("held_opens", []) if one["hold"] == hold), {})
    check("the agent can find what it became", listed.get("status") == "signed" and view(net, "ana", listed.get("request", ""))["state"] == "offered", listed)
    status, answer = post_approval(net, "ana", sign_approval(net, "ana", draft))
    check("one yes makes one interaction", status == 404, answer)

    status, second = opens(net, "ana", "ben", QUOTE, {**QUOTE_TERMS, "quantity": 78})
    draft = draft_for(net, "ana", second.get("hold", ""))
    other_terms = {**draft["terms"], "agreed": {**draft["terms"]["agreed"], "quantity": 79}}
    status, answer = post_approval(net, "ana", sign_approval(net, "ana", draft, decision="deny", terms=other_terms))
    check("a no has to name what's held", (status, answer.get("error")) == (409, "approval_mismatch"), answer)
    owner_decides(net, "ana", second.get("hold", ""), "deny")
    listed = next((one for one in net.agent("ana", "GET", "/v0/requests")[1].get("held_opens", []) if one["hold"] == second.get("hold")), {})
    check("a no is heard, and nothing starts", listed.get("status") == "owner_said_no", listed)

    held = [opens(net, "ana", "ben", QUOTE, {**QUOTE_TERMS, "quantity": 80 + number}) for number in range(2)]
    check("control: as many as the owner said can wait", all(status == 200 for status, _ in held), held)
    status, answer = opens(net, "ana", "ben", QUOTE, {**QUOTE_TERMS, "quantity": 90})
    check("and no more, so an agent can't bury its owner", (status, answer.get("error")) == (409, "over_limit"), answer)
    owner_decides(net, "ana", held[0][1]["hold"], "deny")

    late = sign_approval(net, "ana", draft_for(net, "ana", held[1][1]["hold"]))
    # The quote is one ana's and ben's agents agreed, so the owner stops it by naming the rest and
    # turning off what the two agree by themselves.
    without_quotes = {**net.contact_entry("ben"), "types": [kind for kind in e2e.EXAMPLE_TYPES if kind != QUOTE], "agree_types": False}
    rules_for(net, "ana", [without_quotes], permissions=ASK_ME, limits={**e2e.LIMITS, "open_approvals": 2})
    status, answer = post_approval(net, "ana", late)
    check("a yes after the owner stopped that type sends nothing", (status, answer.get("error")) == (409, "type_not_allowed"), answer)
    rules_for(net, "ana", [net.contact_entry("ben")], permissions=ASK_ME, limits={**e2e.LIMITS, "open_approvals": 2})
    owner_decides(net, "ana", held[1][1]["hold"], "deny")


def a_key_skipping_signet_gets_nothing_past_ask_me(net: e2e.Network) -> None:
    ana_at_auto_and_ben_at(net, ASK_ME)
    request = offered_to(net, "ana", "ben")
    head = view(net, "ben", request)["delivery"]["head"]
    pick = {"step": "accept", "request": request, "prev": head}
    status, answer = to_host(net, "ben", "ana", signed_step(net, "ben", "ben", "ana", pick))
    check("its host refuses an accept with no yes", status == 403, answer)
    status, answer = to_host(net, "ben", "ana", signed_step(net, "ben", "ben", "ana", pick | {"approval": "no-signature-here"}))
    check("or a made-up one", status == 403, answer)

    move(net, "ben", request, "accept")
    draft = draft_for(net, "ben", request)
    forged = sign_approval(net, "ben", draft, signer=net.key_of("ben"))
    status, answer = to_host(net, "ben", "ana", signed_step(net, "ben", "ben", "ana", pick | {"approval": forged}))
    check("or one the agent's key signed", status == 403, answer)
    denied = sign_approval(net, "ben", draft, decision="deny")
    status, answer = to_host(net, "ben", "ana", signed_step(net, "ben", "ben", "ana", pick | {"approval": denied}))
    check("or the owner's no", status == 403, answer)
    yes = sign_approval(net, "ben", draft)
    elsewhere = {"step": "accept", "request": request, "prev": "ab" * 32, "approval": yes}
    status, answer = to_host(net, "ben", "ana", signed_step(net, "ben", "ben", "ana", elsewhere))
    check("or a yes to something else", status == 403, answer)
    accepted = signed_step(net, "ben", "ben", "ana", pick | {"approval": yes})
    status, answer = to_host(net, "ben", "ana", accepted)
    check("control: the owner's yes to this very step goes", status == 200, answer)
    check("and the other side takes it", bool(wait_for(net, "ana", request, state="working")), view(net, "ana", request))

    # Ben's own Signet never saw that step, so this goes on by hand too, as the key that signed it would.
    head = e2e.message_id_of(accepted)
    yes = sign_approval(net, "ben", draft, operation="deliver", prev=head, terms={**draft["terms"], "result": QUOTE_RESULT})
    other = {"step": "deliver", "request": request, "prev": head, "result": {"amount_minor": 5, "valid_days": 14}, "approval": yes}
    status, answer = to_host(net, "ben", "ana", signed_step(net, "ben", "ben", "ana", other))
    check("a yes to one amount doesn't carry another", status == 403, answer)
    other["result"] = QUOTE_RESULT
    status, answer = to_host(net, "ben", "ana", signed_step(net, "ben", "ben", "ana", {k: v for k, v in other.items() if k != "approval"}))
    check("and a result with no yes doesn't go at all", status == 403, answer)
    check("so the other side never read one", view(net, "ana", request)["result"] == {}, view(net, "ana", request))
    status, answer = to_host(net, "ben", "ana", signed_step(net, "ben", "ben", "ana", other))
    check("control: the result it said yes to goes", status == 200 and bool(wait_for(net, "ana", request, state="delivered", result=QUOTE_RESULT)), answer)

    rules_for(net, "ben", [net.contact_entry("ana")], permissions=AUTO)
    request = offered_to(net, "ana", "ben")
    head = view(net, "ben", request)["delivery"]["head"]
    status, answer = to_host(net, "ben", "ana", signed_step(net, "ben", "ben", "ana", {"step": "accept", "request": request, "prev": head}))
    check("control: at auto it goes with none", status == 200, answer)


def a_yes_fits_only_its_own_step_at_its_host(net: e2e.Network) -> None:
    """Each thing a sending host compares, wrong on its own, with the right one going at the end."""
    ana_at_auto_and_ben_at(net, ASK_ME)
    request = offered_to(net, "ana", "ben")
    move(net, "ben", request, "accept")
    draft = draft_for(net, "ben", request)
    pick = {"step": "accept", "request": request, "prev": draft["prev"]}

    def with_yes(sender: str, step: dict, nonce: str = "", dates: tuple[int, int] | None = None, **changes) -> int:
        yes = sign_approval(net, sender, draft, **changes)
        recipient = "ana" if sender == "ben" else "ben"
        return to_host(net, sender, recipient, signed_step(net, sender, sender, recipient, step | {"approval": yes}, nonce=nonce, dates=dates))[0]

    check("not a yes naming another owner", with_yes("ben", pick, owner=net.owners["ana"].id) == 403)
    check("or another agent", with_yes("ben", pick, agent=net.ids["ana"]) == 403)
    check("or another kind of step", with_yes("ben", pick, operation="deliver") == 403)
    check("or another request", with_yes("ben", pick, request="ab" * 32) == 403)
    check("or another step to follow", with_yes("ben", pick, prev="ab" * 32) == 403)
    check("or on a step dated otherwise", with_yes("ben", pick, dates=(int(time.time()) - 60, draft["latest_expiry"])) == 403)
    check("or on one picking what it didn't see", with_yes("ben", pick | {"pick": {"start": hours_from_now(24)}}) == 403)
    check("control: its own step goes", with_yes("ben", pick) == 200)
    wait_for(net, "ana", request, state="working")

    # The same for an `open`, whose yes names its nonce, as there's no request yet.
    rules_for(net, "ana", [net.contact_entry("ben")], permissions=ASK_ME)
    rules_for(net, "ben", [net.contact_entry("ana")], permissions=AUTO)
    offer = {"duration_min": 30, "mode": "video", "purpose": "intro", "slots": [hours_from_now(24)]}
    deadline = hours_from_now(48)
    _, held = opens(net, "ana", "ben", "meeting/1", offer, deadline=deadline)
    draft = draft_for(net, "ana", held.get("hold", ""))
    nonce = next(one["nonce"] for one in owner_call(net, "ana", "/v0/owner/requests")[1]["held_opens"] if one["offer"]["deadline"] == deadline)
    # A key skipping Signet names the type by its ID, as a signed step does.
    step = {"step": "open", "type": e2e.example_id("meeting/1"), "terms": offer, "deadline": deadline}
    other_nonce = e2e.encode(b"\7" * 16)
    check("not an open under another nonce", with_yes("ana", step, nonce=other_nonce) == 403)
    check("or with other terms", with_yes("ana", step | {"terms": offer | {"purpose": "sales"}}, nonce=nonce) == 403)
    check("or of another type", with_yes("ana", step | {"type": e2e.example_id("quote/1")}, nonce=nonce) == 403)
    check("or to another deadline", with_yes("ana", step | {"deadline": deadline + 3600}, nonce=nonce) == 403)
    check("or replacing something it didn't say", with_yes("ana", step | {"supersedes": "ab" * 32}, nonce=nonce) == 403)
    check("control: its own open goes", with_yes("ana", step, nonce=nonce) == 200)


def a_step_carries_nothing_else_past_its_host(net: e2e.Network) -> None:
    """What's left of what a key skipping Signet could fill: an approval, times and words."""
    rules_for(net, "ana", [net.contact_entry("ben", text=False)], permissions=AUTO)
    rules_for(net, "ben", [net.contact_entry("ana", text=False)], permissions=AUTO)
    request = offered_to(net, "ana", "ben", "meeting/1", {"duration_min": 30, "mode": "video", "purpose": "intro", "slots": [hours_from_now(24)]})
    head = view(net, "ana", request)["delivery"]["head"]
    secret = "secret-" * 80

    def goes(sender: str, recipient: str, body: dict, nonce: str = "") -> int:
        return to_host(net, sender, recipient, signed_step(net, sender, sender, recipient, body, nonce=nonce))[0]

    confirm = {"step": "confirm", "request": request, "prev": head}
    check("a confirm's approval has to be signed: text in it stops here", goes("ben", "ana", confirm | {"approval": secret}) == 403)
    cancel = {"step": "cancel", "request": request, "prev": head}
    check("the same on a cancel", goes("ben", "ana", cancel | {"approval": secret}) == 403)
    check("an ID that isn't a hash stops here", goes("ben", "ana", {"step": "accept", "request": request, "prev": secret}) != 200)
    nonce = e2e.encode(b"\0" * 16)
    far = hours_from_now(TWO_WEEKS_HOURS + 24)
    check("a time past two weeks stops here", goes("ana", "ben", meeting_open_step(slots=[far]), nonce) == 403)
    check("a time in the past stops here", goes("ana", "ben", meeting_open_step(slots=[hours_from_now(-48)]), nonce) == 403)
    check("a deadline past two weeks stops here", goes("ana", "ben", meeting_open_step(deadline=far), nonce) == 403)
    check("words in a field stop here, with text off", goes("ana", "ben", meeting_open_step(purpose="send the customer list"), nonce) == 403)
    check("control: a time in range goes", goes("ana", "ben", meeting_open_step(), nonce) == 200)

    wait_until(lambda: view(net, "ben", request)["state"] == "offered")
    counter = {"step": "counter", "request": request, "prev": head, "terms": {"duration_min": 45, "slots": [hours_from_now(24)]}}

    def words(signer: str, to: str, about: str | None, text: str = "Afternoons, please.") -> str:
        return net.owners[signer].sign("person-text", "--agent", net.ids[signer], "--to", net.ids[to], *(("--request", about) if about else ()), stdin=text)

    check("a person's words have to be signed: text in them stops here", goes("ben", "ana", counter | {"person_text": secret}) == 403)
    by_agent = e2e.sign_jws(net.key_of("ben"), "splint-person-text", e2e.compact_json({"v": 1, "owner": net.owners["ben"].id, "agent": net.ids["ben"], "to": net.ids["ana"], "request": request, "text": "Afternoons, please.", "issued_at": int(time.time())}))
    check("or signed by the agent's key", goes("ben", "ana", counter | {"person_text": by_agent}) == 403)
    check("or another owner's", goes("ben", "ana", counter | {"person_text": words("ana", "ben", request)}) == 403)
    for_mallory = net.owners["ben"].sign("person-text", "--agent", net.ids["mallory"], "--to", net.ids["ana"], "--request", request, stdin="Afternoons, please.")
    check("or for another agent to carry", goes("ben", "ana", counter | {"person_text": for_mallory}) == 403)
    check("or for someone else", goes("ben", "ana", counter | {"person_text": words("ben", "mallory", request)}) == 403)
    check("or about something else", goes("ben", "ana", counter | {"person_text": words("ben", "ana", "ab" * 32)}) == 403)
    check("control: its owner's words about this go", goes("ben", "ana", counter | {"person_text": words("ben", "ana", request)}) == 200)


def a_fooled_agent_stays_in_what_the_sums_assume(net: e2e.Network) -> None:
    rules_for(net, "ana", [net.contact_entry("ben")], permissions=AUTO, limits={**e2e.LIMITS, "new_requests_per_contact_per_day": 200})
    rules_for(net, "ben", [net.contact_entry("ana")], permissions=AUTO, limits={**e2e.LIMITS, "new_requests_per_contact_per_day": 200})
    meeting = {"duration_min": 30, "mode": "video", "purpose": "intro"}
    far = hours_from_now(TWO_WEEKS_HOURS + 24)
    status, answer = opens(net, "ana", "ben", "meeting/1", meeting | {"slots": [far]})
    check("Signet refuses a time past two weeks", (status, answer.get("error")) == (409, "outside_window"), answer)
    status, answer = opens(net, "ana", "ben", "meeting/1", meeting | {"slots": [hours_from_now(24)]}, deadline=far)
    check("and a deadline past two weeks", (status, answer.get("error")) == (409, "outside_window"), answer)
    status, answer = opens(net, "ana", "ben", "meeting/1", meeting | {"slots": [hours_from_now(24)]})
    check("control: in range is fine", status == 200, answer)

    talk = lambda: opens(net, "ana", "ben", "chat/1", {})[1]["request"]  # noqa: E731
    request = talk()
    time.sleep(1.1)
    later = [talk() for _ in range(16)]
    body = {"contact": net.address("ben"), "deadline": hours_from_now(48)}
    status, answer = net.agent("ana", "POST", "/v0/requests", body | {"supersedes": request})
    check("an interaction can name only one of the latest it replaces", status == 409, answer)
    status, answer = net.agent("ana", "POST", "/v0/requests", body | {"supersedes": later[-1]})
    check("control: the latest is fine", status == 200, answer)

    rules_for(net, "ana", [net.contact_entry("ben")], permissions=AUTO, limits={**e2e.LIMITS, "new_requests_per_contact_per_day": 3})
    status, answer = opens(net, "ana", "ben")
    check("the day's limit on new interactions holds in Signet", (status, answer.get("error")) == (409, "over_limit"), answer)
    net.postgres.sql(f"host_{net.home['ana']}", "DELETE FROM new_requests")
    fresh = lambda: signed_step(net, "ana", "ana", "ben", meeting_open_step(), nonce=e2e.encode(os.urandom(16)))  # noqa: E731
    answers = [to_host(net, "ana", "ben", fresh())[0] for _ in range(3)]
    check("control: within it, a key skipping Signet goes", answers == [200] * 3, answers)
    status, answer = to_host(net, "ana", "ben", fresh())
    check("and past it, its host stops that too", status == 429, answer)


def asking_costs_an_action(net: e2e.Network) -> None:
    # Their agents agree the quote first, as agents agree their own kinds, which costs mallory's agent
    # one of the day's actions, so one more is left for asking.
    rules_for(net, "carol", [net.contact_entry("mallory")], permissions=AUTO)
    rules_for(net, "mallory", [net.contact_entry("carol")], permissions=AUTO)
    check("control: mallory's and carol's agents agree the quote", e2e.agree(net, "mallory", "carol", QUOTE))
    rules_for(net, "mallory", [net.contact_entry("carol")], permissions={**ASK_ME, "actions_per_day": 2})
    status, answer = opens(net, "mallory", "carol")
    check("control: an open waits", status == 200 and answer.get("waiting_for_owner") is True, answer)
    status, answer = opens(net, "mallory", "carol")
    check("and asking over and over runs out", (status, answer.get("error")) == (409, "over_limit"), answer)
    owner_decides(net, "mallory", net.agent("mallory", "GET", "/v0/requests")[1]["held_opens"][0]["hold"], "deny")


def a_recipient_keeps_to_its_own_limit(net: e2e.Network) -> None:
    limit = {**e2e.LIMITS, "new_requests_per_contact_per_day": 1}
    rules_for(net, "carol", [net.contact_entry("mallory")], permissions=AUTO)
    rules_for(net, "mallory", [net.contact_entry("carol")], permissions=AUTO, limits=limit)
    # What a lying host puts on the page below is a meeting, which their agents agree first.
    check("control: carol's and mallory's agents agree the meeting", e2e.agree(net, "carol", "mallory", "meeting/1"))
    first = offered_to(net, "carol", "mallory")
    status, second = opens(net, "carol", "mallory")
    check("control: the sender's own limit lets a second go", status == 200, second)
    time.sleep(SETTLE_SECONDS * 2)
    check("control: the first arrived", view(net, "mallory", first)["state"] == "offered")
    check("the recipient's host keeps to the limit its owner signed, so the sender hears as much", wait_until(lambda: net.sent_report("carol", second.get("request", "")).get("status") == "quarantined"), net.sent_report("carol", second.get("request", "")))
    check("and its agent has none of it", view(net, "mallory", second.get("request", "")).get("status") == 404, view(net, "mallory", second.get("request", "")))

    # A lying host, or the other side's own, can put it on the page anyway. Signet counts for itself.
    mallory = net.ids["mallory"]
    host = f"host_{net.home['mallory']}"
    carols_host = f"host_{net.home['carol']}"
    carol = net.ids["carol"]
    held = lambda column: net.postgres.sql(carols_host, f"SELECT {column} FROM agents WHERE id = '{carol}'")  # noqa: E731

    def on_the_page(nonce: bytes) -> str:
        envelope = signed_step(net, "carol", "carol", "mallory", meeting_open_step(), nonce=e2e.encode(nonce))
        net.postgres.sql(host, f"""INSERT INTO inbox (recipient, message_id, envelope, sender_identity, sender_owner_identity,
            sender_binding, sender, expires_at) VALUES ('{mallory}', '{e2e.message_id_of(envelope)}', '{envelope}', '{held("identity")}',
            '{held("owner_identity")}', '{held("binding")}', '{carol}', {int(time.time()) + 3000})""")
        return e2e.message_id_of(envelope)

    over = on_the_page(b"\1" * 16)
    time.sleep(SETTLE_SECONDS * 2)
    check("past a lying host, its Signet keeps to it too", view(net, "mallory", over).get("status") == 404, view(net, "mallory", over))
    rules_for(net, "mallory", [net.contact_entry("carol")], permissions=AUTO, limits={**limit, "new_requests_per_contact_per_day": 2})
    within = on_the_page(b"\2" * 16)
    check("control: within a higher limit, the same thing reads", bool(wait_for(net, "mallory", within, state="offered")), view(net, "mallory", within))


def main() -> int:
    e2e.build()
    with e2e.running_network(owned=True) as network:
        for scenario in (
            ask_me_holds_each_committing_step_for_the_owners_yes,
            ask_me_holds_on_a_type_nobody_signs,
            ask_me_holds_a_new_interaction,
            a_key_skipping_signet_gets_nothing_past_ask_me,
            a_yes_fits_only_its_own_step_at_its_host,
            a_step_carries_nothing_else_past_its_host,
            a_fooled_agent_stays_in_what_the_sums_assume,
            asking_costs_an_action,
            a_recipient_keeps_to_its_own_limit,
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

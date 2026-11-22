#!/usr/bin/env python3
"""What an owner does from a terminal or their own page, with nobody needing `owner-key` or the Signet API,
beside their agent and from another device, and what gets signed with nobody there.

Two homes stand for two devices. Dan's agent signed itself up, and Dana holds its owner's key on hers, so
all she reads and signs goes by way of its host. Ben used `splint setup`, with his key beside his agent.
Everything an agent does here is plain HTTP, and agents are assumed fully fooled.

    python3 sim/owner_device.py

Not shown: two real devices or user accounts, hardware-held keys, or a person at the terminal: a script
types the answers. No agent has network limits.
"""

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import e2e
from agent_signup import FINISH_LINE, OWN_LINE, SIGNET_HEARS_SECONDS, Signup, registered
from e2e import check, http, wait_until
from install import ARRIVE_SECONDS, Person, signet_pid
from owner_page import OwnerPage
from request_driver import hours_from_now

QUOTE = {"currency": "usd", "item": "catering", "quantity": 40}
CHEAP = {"amount_minor": 5000, "valid_days": 14}
DEAR = {"amount_minor": 900000, "valid_days": 14}
RELAY_SECONDS = 40
# What an agent's host keeps waiting for its Signet, MAX_MAIL_WAITING in packages/host/src/owner_relay.rs.
OWNER_MAIL_PLACES = 64
WORDS = "Only mornings, please."


def state_at(person: Person, request: str) -> str:
    return person.api("GET", f"/v0/requests/{request}")[1].get("state", "")


def reached(person: Person, request: str, state: str, seconds: int = ARRIVE_SECONDS) -> bool:
    return wait_until(lambda: state_at(person, request) == state, seconds)


def room_for_this_test(signup: Signup, person: Person, file: str) -> None:
    """A contact can start 3 interactions a day unless an owner signs more, and this needs more."""
    path = person.dot / file
    found = json.loads(path.read_text())
    for record in found if isinstance(found, list) else [found]:
        record["draft"]["limits"]["new_requests_per_contact_per_day"] = 50
    path.write_text(json.dumps(found))
    check(f"control: {person.name}'s owner signs room for this", signup.walk.run_as(person.name, "splint renew").returncode == 0)


def add_each_other(signup: Signup, owner: Person, agent: Person, ben: Person) -> None:
    room_for_this_test(signup, owner, "authorized.json")
    room_for_this_test(signup, ben, "rules.json")
    check("dana adds ben, from her device", signup.walk.run_as(owner.name, ben.line).returncode == 0)
    check("ben adds dan", signup.walk.run_as(ben.name, agent.line).returncode == 0)
    # These cases are about amounts in types each owner named for the other, whose labels count. In a
    # type nobody named, every number may be money and waits, as sim/agent_join.py shows.
    name_types(signup, owner, "authorized.json", ben.address)
    name_types(signup, ben, "rules.json", agent.address)
    check("and dan's Signet hears", wait_until(lambda: any(contact["address"] == ben.address and contact["types"] for contact in agent.api("GET", "/v0/contacts")[1]["contacts"]), SIGNET_HEARS_SECONDS))
    for name in ("quote", "meeting"):
        agree(agent, ben, name)


NAMED = ("quote/1", "meeting/1")


def name_types(signup: Signup, person: Person, file: str, address: str) -> None:
    """The owner names quote/1 and meeting/1 for a contact by ID in the rules they sign."""
    path = person.dot / file
    found = json.loads(path.read_text())
    for record in found if isinstance(found, list) else [found]:
        for contact in record["draft"]["contacts"]:
            if contact["address"] == address:
                contact["types"] = [e2e.example_id(name) for name in NAMED]
    path.write_text(json.dumps(found))
    check(f"control: {person.name}'s owner names quote/1 and meeting/1 for {address.split('~')[0]}", signup.walk.run_as(person.name, "splint renew").returncode == 0)


def agree(proposer: Person, accepter: Person, name: str) -> None:
    """The two agents agree an example type with type/1, as they would before either opens one."""
    schema = json.loads((proposer.dot / "examples" / f"{name}-1.json").read_text())
    status, proposed = proposer.api("POST", "/v0/types", {"contact": accepter.address, "schema": schema})
    request = proposed.get("request", "")
    arrived = wait_until(lambda: accepter.api("GET", f"/v0/requests/{request}")[0] == 200, SIGNET_HEARS_SECONDS)
    accepted = arrived and accepter.api("POST", f"/v0/requests/{request}/accept", {})[0] == 200
    check(f"control: {proposer.name} and {accepter.name} agree {name}/1", status == 200 and accepted and wait_until(lambda: proposer.api("GET", f"/v0/requests/{request}")[1].get("state") == "completed", SIGNET_HEARS_SECONDS), proposed)


def setup_people(signup: Signup) -> tuple[Person, Person, Person]:
    host = signup.open_host
    agent, owner, ben = signup.device("dan"), signup.device("dana"), signup.device("ben")
    _, command = signup.join(agent, f"dan~{host}")
    signed = signup.authorize(owner, command)
    check("control: dana's device signs", signed.returncode == 0, signed.stderr)
    done = signup.finish(agent, FINISH_LINE.search(signed.stdout).group(0))
    check("control: dan finishes", done.returncode == 0, done.stderr)
    agent.address = f"dan~{host}"
    agent.line = OWN_LINE.search(done.stdout).group(0)
    ben.address = f"ben~{host}"
    setup = signup.walk.run_as("ben", f"splint setup {ben.address} --with-code --owner-key-here", signup.walk.signup_code("ben") + "\n")
    check("control: ben sets up", setup.returncode == 0, setup.stderr)
    ben.line = OWN_LINE.search(setup.stdout).group(0)
    add_each_other(signup, owner, agent, ben)
    return agent, owner, ben


def taken_on(asker: Person, doer: Person) -> str:
    """A quote asked for and taken on, which commits nobody to a price yet."""
    status, opened = asker.api("POST", "/v0/requests", {"contact": doer.address, "type": "quote/1", "terms": QUOTE, "deadline": hours_from_now(48)})
    check("control: the asker opens", status == 200, opened)
    request = opened["request"]
    check("control: the doer sees it", reached(doer, request, "offered"), state_at(doer, request))
    check("control: the doer takes it on", doer.api("POST", f"/v0/requests/{request}/accept", {})[0] == 200)
    check("control: the asker sees that", reached(asker, request, "working"), state_at(asker, request))
    return request


def quoted(signup: Signup, asker: Person, doer: Person, result: dict, doers_owner: Person) -> str:
    """A quote delivered, which is up to the asker's owner to sign. Its price waits for the doer's own
    owner first, at every level, who says yes from their terminal."""
    request = taken_on(asker, doer)
    status, held = doer.api("POST", f"/v0/requests/{request}/deliver", {"result": result})
    check("control: the doer's price waits for whom it acts for", status == 200 and held.get("waiting_for_owner") is True, held)
    yes = lambda: signup.walk.run_as(doers_owner.name, f"splint approve {request[:12]}", "yes\n").returncode == 0  # noqa: E731
    check("control: who says yes to it from their terminal", wait_until(yes, RELAY_SECONDS))
    check("control: the asker has it", reached(asker, request, "delivered"), state_at(asker, request))
    return request


def a_yes_to_a_price_that_changed_says_it_wasnt_used(signup: Signup, agent: Person, owner: Person, ben: Person) -> None:
    """Issue 808. Dan's price waits for Dana, and Dan lowers it as she says yes to the first from her
    own device, whose last view from his host still shows it. Dan's Signet is paused while she does,
    as a slow or busy one would be, so her yes reaches it only after. Bugs caught: her terminal said
    "Signed" and nothing more, and Signet only logged a warning, so she believed she'd agreed a price
    that never went, and Dan's agent was never told."""
    walk = signup.walk
    request = taken_on(ben, agent)
    short = request[:12]
    listed = lambda: walk.run_as(owner.name, "splint waiting").stdout  # noqa: E731
    status, held = agent.api("POST", f"/v0/requests/{request}/deliver", {"result": DEAR})
    check("dan's price waits for dana, at auto within limits", status == 200 and held.get("waiting_for_owner") is True, held)
    check("control: it reaches her terminal, by way of the host", wait_until(lambda: short in listed() and "9,000.00 USD" in listed(), RELAY_SECONDS), listed())
    status, held = agent.api("POST", f"/v0/requests/{request}/deliver", {"result": CHEAP})
    check("control: dan lowers it, which waits for her too", status == 200 and held.get("waiting_for_owner") is True, held)
    pid = signet_pid(agent)
    check("control: dan's Signet is running", pid > 0, pid)
    os.kill(pid, signal.SIGSTOP)
    try:
        asked = walk.run_as(owner.name, f"splint approve {short}", "yes\n")
    finally:
        os.kill(pid, signal.SIGCONT)
    check("control: she says yes to the price her terminal last heard of", asked.returncode == 0 and "9,000.00 USD" in asked.stderr, asked.stderr)
    check("her terminal says her Signet may not use it, and where she'd see that", "splint waiting says so" in asked.stdout, asked.stdout)
    check("and once dan's Signet has it, her terminal says that yes wasn't used, as what she saw had changed", wait_until(lambda: "wasn't used: what you were shown had changed" in listed(), RELAY_SECONDS), listed())
    check("beside what's waiting now", "50.00 USD" in listed() and "9,000.00 USD" not in listed(), listed())
    seen = agent.api("GET", f"/v0/requests/{request}")[1]
    check("dan's agent is told too", (seen.get("owner_answer_not_used") or {}).get("why") == "changed" and seen.get("waiting_for_owner") == "deliver", seen)
    check("and nothing went: ben has no price", state_at(ben, request) == "working" and ben.api("GET", f"/v0/requests/{request}")[1].get("result") == {}, state_at(ben, request))
    agreed = walk.run_as(owner.name, f"splint approve {short}", "yes\n")
    check("control: her yes to the price now waiting goes", agreed.returncode == 0 and reached(ben, request, "delivered", RELAY_SECONDS), (agreed.stderr, state_at(ben, request)))
    check("and the note clears", wait_until(lambda: short not in listed(), RELAY_SECONDS), listed())
    ben.api("POST", f"/v0/requests/{request}/decline", {"reason": "cannot_supply"})


def a_meeting(asker: Person, doer: Person) -> str:
    status, opened = asker.api("POST", "/v0/requests", {
        "contact": doer.address, "type": "meeting/1", "deadline": hours_from_now(72),
        "terms": {"duration_min": 30, "mode": "video", "purpose": "intro", "slots": [hours_from_now(24), hours_from_now(25)]},
    })
    check("control: a meeting is asked for", status == 200, opened)
    request = opened["request"]
    check("control: the other side sees it", reached(doer, request, "offered"), state_at(doer, request))
    slot = doer.api("GET", f"/v0/requests/{request}")[1]["terms"]["slots"][0]
    check("control: and accepts", doer.api("POST", f"/v0/requests/{request}/accept", {"pick": {"start": slot}})[0] == 200)
    return request


def an_owner_at_a_terminal_signs_what_shes_read(signup: Signup, agent: Person, owner: Person, ben: Person) -> None:
    walk = signup.walk
    request = quoted(signup, agent, ben, DEAR, ben)
    short = request[:12]
    listed = lambda: walk.run_as(owner.name, "splint waiting")
    check("it reaches dana's device, by way of the host", wait_until(lambda: short in listed().stdout, RELAY_SECONDS), listed().stdout)
    text = listed().stdout
    for words in ("quote/1", "amount_minor", "900000", "ben, from your contacts", f"splint approve {short}"):
        check(f"splint waiting shows what she'd sign: {words}", words in text, text)
    check("and when it last heard", "Last heard from" in text, text)

    refused = walk.run_as(owner.name, f"splint approve {short}", "no\n")
    check("saying anything but yes signs nothing", refused.returncode != 0 and "nothing was signed" in refused.stderr, refused.stderr)
    check("and it shows her the terms first", "900000" in refused.stderr, refused.stderr)
    closed = walk.run_as(owner.name, f"splint approve {short}")
    check("a closed stdin signs nothing", closed.returncode != 0, closed.stderr)
    check("control: it's still waiting", state_at(agent, request) == "delivered", state_at(agent, request))
    wrong = walk.run_as(owner.name, "splint approve nothing-like-it", "yes\n")
    check("an ID that fits nothing signs nothing", wrong.returncode != 0, wrong.stderr)

    agreed = walk.run_as(owner.name, f"splint approve {short}", "yes\n")
    check("typing yes signs exactly that", agreed.returncode == 0, agreed.stderr)
    check("and it goes, with dan doing nothing", reached(agent, request, "completed", RELAY_SECONDS), state_at(agent, request))
    check("and ben reads it", reached(ben, request, "completed"), state_at(ben, request))
    check("and it clears from what's waiting", wait_until(lambda: short not in listed().stdout, RELAY_SECONDS), listed().stdout)

    # The same, with the key beside the agent.
    request = quoted(signup, ben, agent, DEAR, owner)
    short = request[:12]
    shown = walk.run_as(ben.name, "splint waiting")
    check("ben's waiting shows it too", short in shown.stdout, shown.stdout)
    check("and a no is signed as a no", walk.run_as(ben.name, f"splint deny {short}", "yes\n").returncode == 0)
    check("which ends it", reached(ben, request, "declined"), state_at(ben, request))


def a_persons_words_go_from_either_device(signup: Signup, agent: Person, owner: Person, ben: Person) -> None:
    walk = signup.walk
    said = walk.run_as(owner.name, f'splint say {ben.address} "{WORDS}"')
    check("dana writes as a person, to a contact", said.returncode == 0, said.stderr)
    too_long = walk.run_as(owner.name, f'splint say {ben.address} "{"x" * 281}"')
    check("up to the limit", too_long.returncode != 0, too_long.stderr)
    time.sleep(RELAY_SECONDS / 4)
    status, opened = agent.api("POST", "/v0/requests", {"contact": ben.address, "type": "quote/1", "terms": QUOTE, "deadline": hours_from_now(48)})
    check("control: dan's agent opens something", status == 200, opened)
    request = opened["request"]
    check("and her words arrive with it", wait_until(lambda: any(words.get("text") == WORDS for words in ben.api("GET", f"/v0/requests/{request}")[1].get("person_texts", [])), ARRIVE_SECONDS), ben.api("GET", f"/v0/requests/{request}")[1])
    ben_says = walk.run_as(ben.name, f'splint say {request[:12]} "Mornings are fine."')
    check("ben writes on the request itself", ben_says.returncode == 0, ben_says.stderr)
    check("and agent has no way to do either", agent.api("POST", "/v0/owner/person-text", {"person_text": "not signed"})[0] != 200)
    ben.api("POST", f"/v0/requests/{request}/decline", {"reason": "cannot_supply"})


def words_said(person: Person, request: str) -> list[str]:
    return [words.get("text") for words in person.api("GET", f"/v0/requests/{request}")[1].get("person_texts", [])]


def what_was_signed_once_counts_once(signup: Signup, agent: Person, owner: Person, ben: Person) -> None:
    """What an owner signs reaches the other side inside steps, so a contact holds it signed and can hand
    it back, to the agent's host or, if the agent is fooled, through the agent. The host takes nothing
    from a contact, and what her own device leaves there twice, the same bytes or the same thing sealed
    again, still counts once."""
    host = signup.open_host
    path = f"/v0/owner-mail/{agent.agent_id}"
    mail = f"http://{host}{path}"
    identity = registered(host, agent.address.split("~")[0])["identity"]
    mine = f"agent_id = '{agent.agent_id}'"
    rows = lambda only="": int(signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE {mine} {only}") or 0)  # noqa: E731

    def signed_for_dan(command: str, stdin: str = "") -> dict:
        """Something dana's key signs for dan, with what leaves it at his host: {signed, body, proof}."""
        done = signup.walk.run_as(owner.name, f"splint-owner-key {command} --dir ~/.splint/owner --agent {agent.agent_id} --host {host} --agent-identity '{identity}'", stdin)
        return json.loads(done.stdout)

    def proof_for(body: str) -> str:
        """A proof her key signs now for leaving exactly this body for dan, as her device signs one to send it again."""
        return signup.walk.run_as(owner.name, f"splint-owner-key access --dir ~/.splint/owner --host {host} --method POST --path {path} --body -", body).stdout.strip()

    def leave(body: str, proof: str) -> int:
        return http("POST", mail, raw=body.encode(), auth=proof)[0]

    check("control: dan's Signet has taken what came before", wait_until(lambda: rows("AND NOT taken") == 0, RELAY_SECONDS), rows("AND NOT taken"))
    before = rows()
    old = signed_for_dan(f"accept-change --contact {ben.agent_id} --head {'c' * 64}")
    # Bug caught: anyone holding something an owner signed filling the room that owner has at the host.
    check("a contact holding something she signed can't hand it to dan's host", http("POST", mail, {"kind": "acceptance", "signed": old["signed"]})[0] == 401 and rows() == before, rows() - before)
    answers = [leave(old["body"], old["proof"]) for _ in range(100)]
    check("what her device leaves, left 100 times, gets the answer a retry would", set(answers) == {200}, sorted(set(answers)))
    check("and the host keeps it once", rows() == before + 1, rows() - before)

    words = signed_for_dan(f"person-text --to {ben.agent_id}", "Tuesdays only.")
    check("control: her words go by way of the host", leave(words["body"], words["proof"]) == 200)
    # The same signed words sealed a second time are other bytes, so the host keeps both. Someone
    # holding a session of hers, and words of hers that a step carried, could leave them like this.
    again = e2e.sealed_owner_mail(identity, "person_text", words["signed"])
    check("control: the same words, sealed again, get in beside them", again != words["body"] and leave(again, proof_for(again)) == 200 and rows() == before + 3, rows() - before)
    check("control: and dan's Signet takes both", wait_until(lambda: rows("AND NOT taken") == 0, RELAY_SECONDS), rows("AND NOT taken"))
    first = agent.api("POST", "/v0/requests", {"contact": ben.address, "type": "quote/1", "terms": QUOTE, "deadline": hours_from_now(48)})[1]["request"]
    # Bug caught: something an owner signed once counting again each time it reaches their agent's Signet.
    check("her words arrive with dan's next open, once", wait_until(lambda: words_said(ben, first) == ["Tuesdays only."], ARRIVE_SECONDS), words_said(ben, first))
    words = words["signed"]
    replayed = agent.api("POST", "/v0/owner/person-text", {"person_text": words})
    check("words that went out can't be handed back to go again", replayed[1].get("error") == "bad_person_text", replayed)
    newer = signup.walk.run_as(owner.name, f"splint-owner-key person-text --dir ~/.splint/owner --agent {agent.agent_id} --to {ben.agent_id}", "Wednesdays too.").stdout.strip()
    held = agent.api("POST", "/v0/owner/person-text", {"person_text": newer})
    check("control: words she hasn't said yet get in the same way", held[0] == 200, held)
    second = agent.api("POST", "/v0/requests", {"contact": ben.address, "type": "quote/1", "terms": QUOTE, "deadline": hours_from_now(48)})[1]["request"]
    check("control: ben sees dan's next open", reached(ben, second, "offered"), state_at(ben, second))
    check("and it carries her new words, and no old ones", wait_until(lambda: words_said(ben, second) == ["Wednesdays too."], ARRIVE_SECONDS), words_said(ben, second))
    for request in (first, second):
        ben.api("POST", f"/v0/requests/{request}/decline", {"reason": "cannot_supply"})


def nothing_is_signed_above_what_the_owner_set(signup: Signup, agent: Person, owner: Person, ben: Person, page: OwnerPage) -> None:
    """What `splint auto` does for someone who chose a level, and never ran it."""
    both = a_meeting(ben, agent)
    signed = reached(ben, both, "completed", 2 * RELAY_SECONDS)
    if not signed:
        for person in (owner, ben):
            shown = person.shell("cat ~/.splint/run/splint-auto.log 2>&1 | tail -20; cat ~/.splint/run/splint-auto.lock; ps -eo pid,stat,comm,args | grep '[a]ccord auto'; splint auto --once 2>&1", person.home)
            print(f"{person.name}'s splint auto: {shown.stdout} {shown.stderr}", flush=True)
    check("a meeting has no values, so both owners' devices sign with nobody there", signed, state_at(ben, both))
    check("and dan's side has it", reached(agent, both, "completed", RELAY_SECONDS), state_at(agent, both))

    # A cap names a value in a schema her device keeps, so she keeps Splint's examples.
    owner.keep_examples()
    settings = page.state()["settings"]
    settings["permissions"]["caps"] = {e2e.example_id("quote/1"): {"amount_minor.usd": 10000}}
    status, signed = page.call("POST", "/api/settings", settings)
    check("dana signs a cap from her page, on her device", status == 200, signed)
    # Issue 809. Bug caught: her device's `splint auto` signing her confirm of a price under her cap with
    # nobody there, where the page tells her anything with an amount waits for her.
    under = quoted(signup, agent, ben, CHEAP, ben)
    shown = lambda: next((found["to_sign"][0] for found in page.state()["exchanges"] if found["request"] == under and found["to_sign"]), None)  # noqa: E731
    check("a price under her cap waits for her on her page, which says why", wait_until(lambda: (shown() or {}).get("left", {}).get("is") == "commits_a_value", RELAY_SECONDS), shown())
    time.sleep(RELAY_SECONDS)
    check("and nothing signs it for her", state_at(agent, under) == "delivered", state_at(agent, under))
    to_sign = shown() or {}
    status, said = page.call("POST", "/api/decide", {"request": under, "operation": to_sign.get("operation"), "version": to_sign.get("version"), "prev": to_sign.get("prev"), "terms": to_sign.get("terms"), "decision": "deny", "subject": None})
    check("control: her no goes from the page", status == 200 and reached(agent, under, "declined", RELAY_SECONDS), (said, state_at(agent, under)))

    settings = page.state()["settings"]
    settings["permissions"]["level"] = "ask_me"
    check("she chooses ask me", page.call("POST", "/api/settings", settings)[0] == 200)
    time.sleep(SIGNET_HEARS_SECONDS)
    status, shown = agent.api("POST", "/v0/requests", {"contact": ben.address, "type": "meeting/1", "deadline": hours_from_now(72), "terms": {"duration_min": 30, "mode": "video", "purpose": "intro", "slots": [hours_from_now(24)]}})
    check("and dan's Signet hears, and holds what commits her", status == 200 and shown.get("waiting_for_owner") is True, shown)
    check("she's asked about it, as a card on her page", wait_until(lambda: bool(page.state()["starting"]), RELAY_SECONDS), page.state()["starting"])
    time.sleep(RELAY_SECONDS / 2)
    check("and nothing signs it for her", bool(page.state()["starting"]), page.state()["starting"])
    starting = page.state()["starting"][0]
    to_sign = starting["to_sign"]
    status, said = page.call("POST", "/api/decide", {"request": starting["request"], "operation": to_sign["operation"], "version": to_sign["version"], "prev": to_sign["prev"], "terms": to_sign["terms"], "decision": "deny", "subject": None})
    check("her no goes from the page", status == 200, said)
    check("and clears", wait_until(lambda: not page.state()["starting"], RELAY_SECONDS), page.state()["starting"])
    settings = page.state()["settings"]
    settings["permissions"]["level"] = "auto_within_limits"
    check("control: back to auto within limits", page.call("POST", "/api/settings", settings)[0] == 200)


def a_price_over_her_cap_reads_in_dollars_at_her_terminal(signup: Signup, agent: Person, owner: Person, ben: Person) -> None:
    """Issue 789. Dana's cap on a quote is 100.00 USD, so ben's price of 9,000.00 USD waits for her,
    and she signs it at a terminal. Bugs caught: `splint waiting` and `splint approve` showing it as
    amount_minor: 900000 right before she types yes, which reads as $900,000 or as nothing at all, and
    the step by the code's own name for it rather than in words."""
    walk = signup.walk
    over = quoted(signup, agent, ben, DEAR, ben)
    short = over[:12]
    listed = lambda: walk.run_as(owner.name, "splint waiting").stdout  # noqa: E731
    check("control: the price over her cap waits for her terminal", wait_until(lambda: short in listed(), RELAY_SECONDS), listed())
    text = listed()
    check("splint waiting says the price in dollars, with its currency", "Delivered: Amount: 9,000.00 USD" in text, text)
    check("and what her agent wants, in words, on what it asked ben for", "Your agent wants to agree to this, which it asked ben for (confirm, version" in text, text)
    asked = walk.run_as(owner.name, f"splint approve {short}", "yes\n")
    check("splint approve shows her the same before she types yes", "Delivered: Amount: 9,000.00 USD" in asked.stderr, asked.stderr)
    check("control: and her yes signs it", asked.returncode == 0 and reached(agent, over, "completed", RELAY_SECONDS), (asked.stderr, state_at(agent, over)))


def a_contacts_change_waits_for_a_yes_from_her_device(signup: Signup, agent: Person, owner: Person, ben: Person, page: OwnerPage) -> None:
    walk = signup.walk
    settings = page.state()["settings"]
    settings["changes"]["declared"] = "ask"
    check("dana asks to hear about what contacts declare", page.call("POST", "/api/settings", settings)[0] == 200)
    time.sleep(SIGNET_HEARS_SECONDS)
    head = ben.api("GET", "/v0/identity")[1]["change_head"]
    made = walk.run_as(ben.name, f"splint-owner-key sign-change --dir ~/.splint/owner --agent {ben.agent_id} --prev {head} --kind declared --what 'new runtime'")
    check("control: ben's owner signs a change", made.returncode == 0, made.stderr)
    check("control: ben's Signet takes it", e2e.http_on_socket("PUT", ben.socket, "/v0/owner/change", {"statement": made.stdout.strip()})[0] == 200)
    check("it shows on dana's page, by way of the host", wait_until(lambda: any(found["contact"] == ben.agent_id for found in page.state()["changes"]), 2 * RELAY_SECONDS), page.state()["changes"])
    notice = next(found for found in page.state()["changes"] if found["contact"] == ben.agent_id)
    check("with what was signed, read on her own device", "new runtime" in json.dumps(notice["since_accepted"]), notice)
    shown = walk.run_as(owner.name, "splint waiting").stdout
    check("and at her terminal", "new runtime" in shown and f"splint accept-change {ben.agent_id}" in shown, shown)
    no = walk.run_as(owner.name, f"splint accept-change {ben.address}", "no\n")
    check("no signs nothing", no.returncode != 0, no.stderr)
    yes = walk.run_as(owner.name, f"splint accept-change {ben.address}", "yes\n")
    check("yes does", yes.returncode == 0, yes.stderr)
    check("and dan's Signet lets ben through", wait_until(lambda: not any(found["contact"] == ben.agent_id for found in page.state()["changes"]), RELAY_SECONDS), page.state()["changes"])


VIEW_SEALER = e2e.TARGET_DIR / "debug" / "examples" / "seal_view"


def view_at_host(agent: Person) -> str:
    return f"http://{agent.address.split('~')[1]}/v0/owner-view/{agent.agent_id}"


def an_agent_in_between_gets_nothing_new(signup: Signup, agent: Person, owner: Person, ben: Person, page: OwnerPage) -> None:
    """A fooled agent running as the user that holds its Signet's key, which is the most an agent can be:
    it can leave what it likes at its host, and can't get its owner to sign anything but what's true."""
    host = signup.open_host
    key = agent.dot / "signet" / "agent.key"
    status, _ = http("GET", view_at_host(agent))
    check("nobody reads what's left for an owner with no proof", status == 401, status)
    path = f"/v0/owner-view/{agent.agent_id}"
    proof = {"signer": agent.agent_id, "host": host, "method": "GET", "path": path, "body_sha256": hashlib.sha256(b"").hexdigest(), "issued_at": int(time.time())}
    check("nor with the agent's own key", http("GET", view_at_host(agent), auth=e2e.sign_jws(key, "splint-access", json.dumps(proof).encode()))[0] == 401)
    ben_proof = signup.walk.run_as(ben.name, f"splint-owner-key access --dir ~/.splint/owner --host {host} --method GET --path {path}").stdout.strip()
    check("nor with another owner's", http("GET", view_at_host(agent), auth=ben_proof)[0] == 401)

    # Another owner's key seals something for this agent, as anyone can, and proves it left it.
    mail = f"/v0/owner-mail/{agent.agent_id}"
    left = json.loads(signup.walk.run_as(ben.name, f"splint-owner-key accept-change --dir ~/.splint/owner --agent {agent.agent_id} --contact {ben.agent_id} --head {'a' * 64} --host {host} --agent-identity '{registered(host, agent.address.split('~')[0])['identity']}'").stdout)
    kept = lambda: signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{agent.agent_id}'")  # noqa: E731
    before = kept()
    check("the host keeps nothing for it that its own owner didn't leave", http("POST", f"http://{host}{mail}", raw=left["body"].encode(), auth=left["proof"])[0] == 401)
    by_agent = {"signer": agent.agent_id, "host": host, "method": "POST", "path": mail, "body_sha256": hashlib.sha256(left["body"].encode()).hexdigest(), "issued_at": int(time.time())}
    check("nor by the agent's own key", http("POST", f"http://{host}{mail}", raw=left["body"].encode(), auth=e2e.sign_jws(key, "splint-access", json.dumps(by_agent).encode()))[0] == 401 and kept() == before, (before, kept()))

    # What it would leave: a real step changed, and a change that was never signed.
    over = quoted(signup, agent, ben, DEAR, ben)
    check("control: it waits on her page", wait_until(lambda: any(found["request"] == over and found["to_sign"] for found in page.state()["exchanges"]), RELAY_SECONDS))
    real = http("GET", view_at_host(agent), auth=signup.walk.run_as(owner.name, f"splint-owner-key access --dir ~/.splint/owner --host {host} --method GET --path {path}").stdout.strip())[1]
    check("what's left for her is sealed to her device, so the host can't read it", "requests" not in real["view"], real["view"][:80])
    # Holding the Signet's folder, the agent has everything in the view anyway, and her sealing key is public.
    opened = signup.walk.run_as(owner.name, f"splint-owner-key open-view --dir ~/.splint/owner --agent {agent.agent_id}", real["view"])
    check("control: her device opens it", opened.returncode == 0, opened.stderr)
    signed = e2e.payload_of(opened.stdout.strip())
    check("what's inside is signed by the agent's key, for her", signed.get("agent") == agent.agent_id and signed.get("v") == 1, {key: signed.get(key) for key in ("v", "agent", "owner")})
    owner_identity = next(line for line in signup.walk.run_as(owner.name, "splint-owner-key show --dir ~/.splint/owner").stdout.splitlines() if line.startswith("owner identity: ")).split(": ", 1)[1]

    def leave(inside: str) -> int:
        """Seals what's given to her, as anyone can, and leaves it at the host with the agent's key."""
        sealed = subprocess.run([str(VIEW_SEALER)], input=json.dumps({"owner": owner_identity, "agent": agent.agent_id, "view": inside}), capture_output=True, text=True, check=True).stdout
        body = json.dumps({"view": sealed}).encode()
        proof = {"signer": agent.agent_id, "host": host, "method": "PUT", "path": "/v0/owner-view", "body_sha256": hashlib.sha256(body).hexdigest(), "issued_at": int(time.time())}
        request = urllib.request.Request(f"http://{host}/v0/owner-view", data=body, method="PUT", headers={"Content-Type": "application/json", "Authorization": "Splint " + e2e.sign_jws(key, "splint-access", json.dumps(proof).encode())})
        with urllib.request.urlopen(request, timeout=10) as answer:
            return answer.status

    def shown_on_her_page() -> str:
        try:
            return json.dumps(page.state())
        except RuntimeError as refused:
            return str(refused)

    # Someone made up, waiting to reach her agent: only the agent's word says who's held, so only the
    # agent's signature on the whole view makes it so. Her sealing key is public, so anyone can seal one.
    stranger = "mallory~" + host
    made_up = json.loads(json.dumps(signed["view"]))
    made_up["held"] = [{"sender": "splint1" + hashlib.sha256(b"nobody held").hexdigest(), "sender_owner": None, "address": stranger, "kind": "text", "created_at": int(time.time()), "invite": None}]
    payload = e2e.compact_json({"v": 1, "agent": agent.agent_id, "owner": signed["owner"], "issued_at": int(time.time()), "view": made_up})
    unsigned = f"{e2e.encode(e2e.compact_json({'alg': 'ES256', 'typ': 'splint-owner-view'}))}.{e2e.encode(payload)}.{e2e.encode(bytes(64))}"
    by_another_agent = e2e.sign_jws(ben.dot / "signet" / "agent.key", "splint-owner-view", payload)
    for name, inside in (("signed by nobody", unsigned), ("signed by another agent's key", by_another_agent)):
        check(f"control: a view {name}, sealed to her, is left at the host", leave(inside) == 200)
        check(f"her page shows nothing from a view {name}", stranger not in shown_on_her_page(), shown_on_her_page())
        shown = signup.walk.run_as(owner.name, "splint waiting")
        check(f"and her terminal says it isn't her agent's", shown.returncode != 0 and "isn't signed by your agent" in shown.stdout + shown.stderr, shown.stdout + shown.stderr)

    view = signed["view"]
    for one in view["requests"]["requests"]:
        one["steps"] = [step[:-8] + "AAAAAAAA" for step in one["steps"]]
    view["changes"]["changes"] = [{"contact": ben.agent_id, "label": "ben", "address": ben.address, "standing": "continue", "head": "b" * 64, "since_accepted": [{"kind": "declared", "what": "harmless, sign this"}]}]
    # Signed by the agent's key, which is in the folder it holds, so her device takes it as the agent's.
    resigned = e2e.sign_jws(key, "splint-owner-view", e2e.compact_json({"v": 1, "agent": agent.agent_id, "owner": signed["owner"], "issued_at": int(time.time()), "view": view}))
    check("control: its key can leave anything it likes", leave(resigned) == 200)
    state = page.state()
    check("every step it changed doesn't show", state["unreadable"] > 0 and not state["exchanges"], (state["unreadable"], len(state["exchanges"])))
    check("so there's nothing there for her to sign", not any(found["to_sign"] for found in state["exchanges"]), state["exchanges"])
    check("and a change nobody signed isn't shown", state["changes"] == [], state["changes"])
    shown = signup.walk.run_as(owner.name, "splint waiting").stdout
    check("at her terminal either", "harmless" not in shown and over[:12] not in shown, shown)
    refused = signup.walk.run_as(owner.name, f"splint approve {over[:12]}", "yes\n")
    check("and she can't be got to sign it", refused.returncode != 0, refused.stderr)


def a_change_from_a_device_thats_behind_keeps_a_newer_removal(signup: Signup, agent: Person, owner: Person, ben: Person) -> None:
    """Bug caught: a change signed on a device that's behind starting from its own older copy of the
    rules, which brought back a contact another of the owner's devices had taken out, or a
    delegation it had ended, which the owner key filled in from that copy."""
    walk = signup.walk
    owner_key = f"splint-owner-key {{}} --dir ~/.splint/owner --agent {agent.agent_id} --schemas ~/.splint/schemas"
    to_host = f"http://{signup.open_host}/v0/rules"
    in_force = lambda: e2e.payload_of(agent.api("GET", "/v0/owner/rules", token=agent.setup_file()["owner_token"])[1].get("rules") or "x.e30.x")  # noqa: E731
    delegate = agent.api("GET", "/v0/identity")[1]["delegate"]
    made = walk.run_as(owner.name, owner_key.format(f"delegate --delegate {delegate}"))
    check("control: her first device signs a delegation for dan", made.returncode == 0, made.stderr)
    check("control: dan's host takes the rules naming it", http("PUT", to_host, {"rules": json.loads(made.stdout)["rules"]})[0] == 200)
    check("control: dan's Signet hears", wait_until(lambda: in_force().get("delegation") is not None, SIGNET_HEARS_SECONDS), in_force())
    laptop = signup.device("dana-laptop")
    # Her second device, with her key and what her first device had signed, as a restored copy has.
    for folder in ("owner", "schemas"):
        shutil.copytree(owner.dot / folder, laptop.dot / folder, dirs_exist_ok=True)
    shutil.copy(owner.dot / "authorized.json", laptop.dot / "authorized.json")
    contacts = lambda: [found["address"] for found in agent.api("GET", "/v0/contacts")[1]["contacts"]]  # noqa: E731
    check("control: ben is one of dan's contacts", ben.address in contacts(), contacts())
    removed = walk.run_as(owner.name, f"splint remove {ben.address}")
    check("dana takes ben out, from her first device", removed.returncode == 0, removed.stderr)
    check("control: dan's Signet hears", wait_until(lambda: ben.address not in contacts(), SIGNET_HEARS_SECONDS), contacts())
    # As after a new delegate key: her first device signs what it last signed, naming no delegation.
    kept = (owner.dot / "owner" / f"rules-{agent.agent_id.encode().hex()}.json").read_text()
    ended = walk.run_as(owner.name, owner_key.format("rules --delegation none"), kept)
    check("dana ends the delegation, from her first device", ended.returncode == 0, ended.stderr)
    check("control: dan's host takes that", http("PUT", to_host, {"rules": ended.stdout.strip()})[0] == 200)
    check("control: dan's Signet hears that", wait_until(lambda: in_force().get("delegation") is None, SIGNET_HEARS_SECONDS), in_force())
    carol = f"carol~{signup.open_host}"
    added = walk.run_as(laptop.name, f"splint add {carol} splint1{hashlib.sha256(b'carol').hexdigest()}")
    check("her second device, still behind, adds someone", added.returncode == 0, added.stderr)
    check("control: dan's Signet hears that", wait_until(lambda: carol in contacts(), SIGNET_HEARS_SECONDS), contacts())
    check("and ben stays out, as her newer removal said", ben.address not in contacts(), contacts())
    check("and the delegation she ended stays ended", in_force().get("delegation") is None, in_force())


def main() -> None:
    subprocess.run(["cargo", "build", "--quiet", "-p", "splint-core", "--example", "seal_view"], cwd=e2e.PACKAGES, check=True)
    work = e2e.short_scratch("splint-owner-device-")
    signup = Signup(work)
    page = None
    try:
        agent, owner, ben = setup_people(signup)
        an_owner_at_a_terminal_signs_what_shes_read(signup, agent, owner, ben)
        a_yes_to_a_price_that_changed_says_it_wasnt_used(signup, agent, owner, ben)
        a_persons_words_go_from_either_device(signup, agent, owner, ben)
        what_was_signed_once_counts_once(signup, agent, owner, ben)
        page = OwnerPage(owner, None, work, by_hand=False)
        stopped = signup.walk.run_as(owner.name, "splint stop && splint start")
        check("an owner's device with only agents elsewhere starts and stops what signs for them", stopped.returncode == 0 and "Signing what your rules allow" in stopped.stdout, stopped.stderr)
        check("the page opens on a device with only her key", page.state()["me"]["address"] == agent.address, page.state()["me"])
        check("and says the agent's elsewhere", page.state()["elsewhere"] is True)
        nothing_is_signed_above_what_the_owner_set(signup, agent, owner, ben, page)
        a_contacts_change_waits_for_a_yes_from_her_device(signup, agent, owner, ben, page)
        # After a step long enough for dan's Signet to hear she's back at auto within limits.
        a_price_over_her_cap_reads_in_dollars_at_her_terminal(signup, agent, owner, ben)
        an_agent_in_between_gets_nothing_new(signup, agent, owner, ben, page)
        # Last, as it takes ben out of dan's contacts.
        a_change_from_a_device_thats_behind_keeps_a_newer_removal(signup, agent, owner, ben)
    finally:
        if page:
            page.process.terminate()
        signup.walk.stop_everything()
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall owner device checks passed", flush=True)


if __name__ == "__main__":
    main()

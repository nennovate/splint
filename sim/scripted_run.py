#!/usr/bin/env python3
"""A free look at transport: scripted agents book a meeting as a managed request, and the run is saved.

A meeting is only the example. Each scripted agent keeps its owner's calendar itself, as any agent
would, and Splint never sees it: it carries the times an agent offers and the one the other picks.
The harness also stands in for each owner's device. No model is involved, so this costs nothing. Run
it with `make trace`.
"""

import json
import sys
from datetime import UTC, datetime

import e2e
import request_driver
import transport_log
from run_report import Check, RunEvent

HOPS_EXPECTED = ("signed", "stored_for_delivery", "stored_in_inbox", "applied_to_request")
SUBJECT = "Q4 plan"
NOTES = "No model, so no usage. Each scripted agent holds its owner's calendar. Both owners sign with the owner-key tool, on this machine, with software keys."
# Hours from now each owner is busy. Only the agent reads these.
BUSY = {"ana": {24, 25}, "ben": {26, 27}}
FIRST_HOUR, LAST_HOUR = 24, 32
SLOTS_PER_OFFER = 2


def free_hours(agent: str, after: int = 0) -> list[int]:
    """What an agent works out from its own calendar: the next hours its owner is free."""
    free = [hour for hour in range(FIRST_HOUR, LAST_HOUR) if hour not in BUSY[agent] and hour > after]
    return free[:SLOTS_PER_OFFER]


def first_free(agent: str, slots: list[int]) -> int | None:
    """The first offered time this agent's owner is free, by the agent's own calendar."""
    busy = {request_driver.hours_from_now(hour) for hour in BUSY[agent]}
    return next((slot for slot in slots if slot not in busy), None)


def chain_as_sent(net: e2e.Network, request: str) -> list[dict]:
    """Every step of the request, receipts included, as the signed envelopes name them."""
    names = {agent_id: name for name, agent_id in net.ids.items()}
    sent = []
    for step in request_driver.host_chain(net, "ana", request):
        payload = e2e.payload_of(step)
        sent.append({
            "message_id": e2e.message_id_of(step),
            "from": names.get(payload["sender"], payload["sender"]),
            "to": names.get(payload["recipient"], payload["recipient"]),
            "body": payload["body"],
        })
    return sent


def checks_for(net: e2e.Network, sent: list[dict], views: dict[str, dict], outcome: dict) -> list[Check]:
    """What the free run can check: each step took every hop, and the signed result is the agreed one."""
    hops = transport_log.run_events(net, sent, [])
    found = []
    for number, message in enumerate(sent, start=1):
        body = json.loads(message["body"])
        # A sealed step's kind is on its outside, which its host reads too.
        kind = body["sealed"]["outside"]["step"] if "sealed" in body else body["step"]
        taken = [hop.event for hop in hops if hop.message_id == message["message_id"]]
        missing = [hop for hop in HOPS_EXPECTED if hop not in taken]
        found.append(
            Check(f"step {number} ({kind}) took every hop", ", ".join(HOPS_EXPECTED), ", ".join(taken), not missing)
        )
        parties = transport_log.signed_parties(net, message["message_id"])
        wanted = (message["from"], message["to"])
        found.append(
            Check(f"step {number}'s signed envelope names the right agents", " to ".join(wanted), " to ".join(parties), parties == wanted)
        )
    states = {agent: view.get("state") for agent, view in views.items()}
    found.append(Check("both sides recompute completed", "completed, completed", str(states), set(states.values()) == {"completed"}))
    starts = {view.get("pick", {}).get("start") for view in views.values()}
    agreed = outcome.get("terms", {}).get("agreed", {}).get("start")
    found.append(Check("the signed outcome names the time both sides show", str(agreed), str(starts), starts == {agreed}))
    proven = {agent: view.get("other_side") for agent, view in views.items()}
    found.append(Check("each side holds proof the other saw the result", "proven, proven", str(proven), set(proven.values()) == {"proven"}))
    return found


def main() -> int:
    e2e.build()
    with e2e.running_network(owned=True) as net:
        actions = []
        conversation = []

        def did(actor: str, event: str, details: str = "") -> None:
            actions.append(RunEvent(datetime.now(UTC), actor, event, details=details))
            conversation.append(f"{actor}: {event} {details}".rstrip())

        hours = free_hours("ana")
        first = [request_driver.hours_from_now(hour) for hour in hours]
        request = request_driver.open_request(net, "ana", "ben", slots=first)
        did("ana", "opened a request", f"slots {first}, free on its own calendar")
        offered = request_driver.wait_for(net, "ben", request, state="offered")
        if first_free("ben", offered["terms"]["slots"]) is not None:
            raise RuntimeError("the example calendars should make the first offer miss")
        request_driver.move(net, "ben", request, "clarify", {"reason": "other_times"})
        did("ben", "asked to clarify", "other_times, none free on its own calendar")
        request_driver.wait_for(net, "ana", request, state="clarifying")
        later = [request_driver.hours_from_now(hour) for hour in free_hours("ana", after=hours[-1])]
        request_driver.move(net, "ana", request, "counter", {"terms": {"duration_min": 30, "slots": later}})
        did("ana", "offered again", f"slots {later}")
        offered = request_driver.wait_for(net, "ben", request, state="offered", version=2)
        picked = first_free("ben", offered["terms"]["slots"])
        request_driver.move(net, "ben", request, "accept", {"pick": {"start": picked}})
        did("ben", "accepted", f"{picked}, free on its own calendar")
        request_driver.wait_for(net, "ana", request, state="accepted")
        request_driver.owner_decides(net, "ana", request, subject=SUBJECT)
        did("ana's owner", "signed", "confirm")
        request_driver.wait_for(net, "ben", request, state="requester_confirmed")
        request_driver.owner_decides(net, "ben", request)
        did("ben's owner", "signed", "confirm")
        request_driver.wait_for(net, "ana", request, state="completed")
        for agent in ("ana", "ben"):
            request_driver.wait_for_received(net, agent, request)
        views = {agent: request_driver.view(net, agent, request) for agent in ("ana", "ben")}
        _, outcome = request_driver.owner_call(net, "ana", f"/v0/owner/requests/{request}/outcome")
        sent = chain_as_sent(net, request)
        for message in sent:
            at = transport_log.first_seen(net, message["message_id"])
            actions.append(RunEvent(at, message["from"], "sent", message["message_id"], message["from"], message["to"], body=message["body"]))
        net.stop()
        checks = checks_for(net, sent, views, outcome)
        run_dir = transport_log.save_run(net, sent, conversation, actions, checks, NOTES)
    print((run_dir / "summary.md").read_text())
    print(f"Saved to {run_dir}")
    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    sys.exit(main())

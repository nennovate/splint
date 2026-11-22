"""Save one run, including how each message travelled through Splint.

The timeline comes from what the hosts and Signets logged, which never includes message content.
The envelope shown beside it is what the sending host took in, copied by the harness because the
host clears it once it's done, and decoded here so a reader can see exactly what crosses between hosts. Everything runs on one machine, so one clock orders the hops.
"""

import base64
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import run_report
from run_report import Check, RunEvent

RUNS_DIR = Path(__file__).parent / "runs"
# Short names for what hosts and Signets log. Anything new shows as its log text until it's added.
HOP_EVENTS = {
    "signed, handing to our host": "signed",
    "verified the agent's signature and stored it for delivery": "stored_for_delivery",
    "verified the agent's and host's signatures and stored it in the inbox": "stored_in_inbox",
    "held in quarantine for the owner": "quarantined",
    "dropped by the owner's rules": "dropped",
    "released from quarantine to the inbox": "released",
    "took an invitation redeem": "invitation_redeemed",
    "delivery attempt finished": "delivery_attempt",
    "verified and shown to the agent": "shown_to_agent",
    "verified and applied to the request": "applied_to_request",
    "the agent acknowledged it": "acknowledged",
    "holding a message whose dates don't fit our clock": "held_for_clock",
}
EVENT = re.compile(r"^(\S+Z)\s+\w+\s+\S+: (.+?) message_id=([0-9a-f]+)\s*(.*)$")


@dataclass(frozen=True)
class Event:
    at: datetime
    source: str
    what: str
    details: str


def read_events(logs: Path) -> dict[str, list[Event]]:
    events: dict[str, list[Event]] = {}
    for path in sorted(logs.glob("*.log")):
        for line in path.read_text(errors="replace").splitlines():
            match = EVENT.match(line)
            if match:
                at, what, message_id, details = match.groups()
                event = Event(datetime.fromisoformat(at), path.stem, what, details)
                events.setdefault(message_id, []).append(event)
    for found in events.values():
        found.sort(key=lambda event: event.at)
    return events


def distinct_hops(events: list[Event]) -> list[tuple[Event, int]]:
    """Each distinct hop once, because an agent can read its inbox many times before acking."""
    repeats: dict[tuple[str, str, str], list[Event]] = {}
    for event in events:
        repeats.setdefault((event.source, event.what, event.details), []).append(event)
    return [(found[0], len(found)) for found in repeats.values()]


def timeline(events: list[Event]) -> list[str]:
    lines = []
    for event, count in distinct_hops(events):
        elapsed = (event.at - events[0].at).total_seconds()
        times = f" (x{count})" if count > 1 else ""
        lines.append(f"  +{elapsed:7.3f}s  {event.source:<12} {event.what}{times}  {event.details}".rstrip())
    return lines


def first_seen(net, message_id: str) -> datetime:
    """When the logs first mention a message, which a process only does once it has signed it."""
    return read_events(net.work)[message_id][0].at


def named(text: str, net) -> str:
    for name, agent_id in net.ids.items():
        text = text.replace(agent_id, name)
    return text


def run_events(net, sent: list[dict], actions: list[RunEvent]) -> list[RunEvent]:
    """What the agents did and what the hosts and Signets logged, on one timeline.

    Who a message is between comes from `sent`, which needs no database, so this survives losing it.
    """
    parties = {message["message_id"]: message for message in sent}
    hops = []
    for message_id, events in read_events(net.work).items():
        party = parties.get(message_id, {})
        for event, count in distinct_hops(events):
            hops.append(
                RunEvent(
                    at=event.at,
                    actor=event.source,
                    event=HOP_EVENTS.get(event.what, event.what),
                    message_id=message_id,
                    sender=party.get("from", ""),
                    recipient=party.get("to", ""),
                    count=count,
                    details=named(event.details, net),
                )
            )
    return sorted([*hops, *actions], key=lambda event: event.at)


def current_commit() -> str:
    described = subprocess.run(
        ["git", "describe", "--always", "--dirty"], cwd=RUNS_DIR.parent, capture_output=True, text=True
    )
    return described.stdout.strip() or "unknown"


def decoded(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def envelope_view(compact: str) -> list[str]:
    header, payload, signature = compact.split(".")
    view = {"header": decoded(header), "payload": decoded(payload), "signature": f"{signature[:16]}..."}
    return [f"    {line}" for line in json.dumps(view, indent=2).splitlines()]


def stored_envelope(net, message_id: str) -> str:
    for database in ("host_a", "host_b"):
        found = net.postgres.sql(
            database, f"SELECT envelope FROM captured_envelopes WHERE message_id = '{message_id}'"
        )
        if found:
            return found
    return ""


def signed_parties(net, message_id: str) -> tuple[str, str]:
    """Who the signed envelope says a message is from and to.

    A saved run reports this rather than who a message was meant for, so an agent that writes to
    someone unexpected shows up as doing exactly that.
    """
    envelope = stored_envelope(net, message_id)
    if not envelope:
        return "unknown", "unknown"
    payload = decoded(envelope.split(".")[1])
    names = {agent_id: name for name, agent_id in net.ids.items()}
    return (
        names.get(payload["sender"], payload["sender"]),
        names.get(payload["recipient"], payload["recipient"]),
    )


def transport_report(net, sent: list[dict]) -> list[str]:
    events = read_events(net.work)
    lines = []
    for number, message in enumerate(sent, start=1):
        message_id = message["message_id"]
        sender, recipient = signed_parties(net, message_id)
        lines.append(f"Message {number}: {sender} -> {recipient} ({message_id[:12]})")
        lines += timeline(events.get(message_id, []))
        envelope = stored_envelope(net, message_id)
        if envelope:
            lines.append("  Signed envelope, as hosts see it:")
            lines += envelope_view(envelope)
        lines.append("")
    return lines


def save_run(
    net,
    sent: list[dict],
    conversation: list[str],
    actions: list[RunEvent],
    checks: list[Check],
    notes: str = "",
) -> Path:
    """Call before the temporary directory and the database go away."""
    run_dir = RUNS_DIR / f"{datetime.now():%Y%m%d-%H%M%S}"
    processes = run_dir / "processes"
    processes.mkdir(parents=True)
    (run_dir / "conversation.log").write_text("\n".join(conversation) + "\n")
    for path in net.work.glob("*.log"):
        shutil.copy(path, processes / path.name)
    events = run_events(net, sent, actions)
    run_report.write_events(run_dir / "events.csv", events)
    run_report.write_checks(run_dir / "checks.csv", checks)
    (run_dir / "summary.md").write_text(
        run_report.summary(run_dir.name, current_commit(), notes, events, checks)
    )
    # Last, because it alone needs the database, so losing that loses nothing else.
    (run_dir / "transport.log").write_text("\n".join(transport_report(net, sent)) + "\n")
    return run_dir

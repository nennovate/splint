"""Write one run as data: what happened, what was checked, and a summary to put on a PR.

Everything in a run's messages comes from a model or a fooled agent, so it's treated as hostile
here too: it can't add rows, pose as a check, notify anyone on GitHub or run in a spreadsheet.
"""

import csv
from collections.abc import Iterable
from dataclasses import astuple, dataclass, fields
from datetime import UTC, datetime
from pathlib import Path

CHARS_PER_TOKEN = 4
UNSAFE_IN_TABLE = {ord(character): f"&#{ord(character)};" for character in "&<>|`@#[]\\"}
ENVIRONMENT = (
    "Keys: software, none hardware-held. Network limits on agents: none. "
    "Everything ran on one machine, so this can't show real networks or TLS."
)


@dataclass(frozen=True)
class RunEvent:
    at: datetime
    actor: str
    event: str
    message_id: str = ""
    sender: str = ""
    recipient: str = ""
    count: int = 1
    body: str = ""
    details: str = ""


@dataclass(frozen=True)
class Check:
    name: str
    expected: str
    actual: str
    passed: bool
    # What a real model chose: shown when it doesn't hold, but it doesn't fail the run.
    warns_only: bool = False

    @property
    def result(self) -> str:
        return "Pass" if self.passed else "Warn" if self.warns_only else "FAIL"


def action(actor: str, event: str, **details: str) -> RunEvent:
    return RunEvent(datetime.now(UTC), actor, event, **details)


def spreadsheet_safe(value: object) -> object:
    """A leading = or similar would run as a formula if someone opens the file in a spreadsheet."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{value}"
    return value


def write_events(path: Path, events: list[RunEvent]) -> None:
    with path.open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(("seq", "ms", *(field.name for field in fields(RunEvent))))
        for seq, event in enumerate(events, start=1):
            ms = round((event.at - events[0].at).total_seconds() * 1000)
            cells = (event.at.isoformat(), *astuple(event)[1:])
            writer.writerow((seq, ms, *map(spreadsheet_safe, cells)))


def write_checks(path: Path, checks: Iterable[Check]) -> None:
    with path.open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(field.name for field in fields(Check))
        for check in checks:
            writer.writerow(map(spreadsheet_safe, astuple(check)))


def table_cell(value: object) -> str:
    """Safe inside a GitHub table: one cell, no markup, no mentions and no issue links."""
    return " ".join(str(value).split()).translate(UNSAFE_IN_TABLE)


def table(headings: tuple[str, ...], rows: Iterable[tuple]) -> list[str]:
    lines = [f"| {' | '.join(headings)} |", f"|{' --- |' * len(headings)}"]
    lines += [f"| {' | '.join(table_cell(cell) for cell in row)} |" for row in rows]
    return lines


def headline(name: str, events: list[RunEvent], checks: list[Check]) -> str:
    failed = sum(check.result == "FAIL" for check in checks)
    warned = sum(check.result == "Warn" for check in checks)
    stopped = any(event.event == "stopped" for event in events)
    if not checks:
        return f"## Run {name}: FAILED, no checks ran"
    if failed or stopped:
        ending = ", and it stopped early" if stopped else ""
        return f"## Run {name}: FAILED, {failed} of {len(checks)} checks failed{ending}"
    if warned:
        return f"## Run {name}: passed, with {warned} of {len(checks)} checks only warning"
    return f"## Run {name}: all {len(checks)} checks passed"


def conversation_rows(events: list[RunEvent]) -> Iterable[tuple]:
    reached = {event.message_id for event in events if event.event == "stored_in_inbox"}
    read = {event.message_id for event in events if event.event in ("acknowledged", "applied_to_request")}
    sent = [event for event in events if event.event == "sent"]
    for number, event in enumerate(sent, start=1):
        yield (
            number,
            event.sender,
            event.recipient,
            event.body,
            "yes" if event.message_id in reached else "no",
            "yes" if event.message_id in read else "no",
        )


def message_tokens(events: list[RunEvent]) -> str:
    """So a change that makes messages longer shows up, with or without a model in the run."""
    bodies = {event.message_id: event.body for event in events if event.message_id and event.body}
    count = len(bodies)
    tokens = sum(len(body) for body in bodies.values()) // CHARS_PER_TOKEN
    return f"Messages in this job: about {tokens} tokens in {count} messages, or {tokens // max(count, 1)} each, at {CHARS_PER_TOKEN} characters a token."


def summary(name: str, commit: str, notes: str, events: list[RunEvent], checks: list[Check]) -> str:
    lines = [
        headline(name, events, checks),
        "",
        f"Commit {commit}. {notes} {ENVIRONMENT}".replace("  ", " "),
        "",
        message_tokens(events),
        "",
        "### Checks",
        "",
        *table(
            ("Result", "Check", "Expected", "Actual"),
            ((c.result, c.name, c.expected, c.actual) for c in checks),
        ),
        "",
        "### Conversation",
        "",
        *table(("#", "From", "To", "Message", "In inbox", "Read or applied"), conversation_rows(events)),
        "",
        "<details>",
        f"<summary>Everything that happened, in order ({len(events)} events)</summary>",
        "",
        *table(
            ("ms", "Actor", "Event", "Message", "Times", "Details"),
            (
                (
                    round((event.at - events[0].at).total_seconds() * 1000),
                    event.actor,
                    event.event,
                    event.message_id[:12],
                    event.count,
                    event.details,
                )
                for event in events
            ),
        ),
        "",
        "</details>",
    ]
    return "\n".join(lines) + "\n"

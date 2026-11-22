"""Reads the state table from docs/protocol.md and walks every path through it, for any type.

An earlier design's table let two parties move on one step, and another let a cap strand a request
with no legal move. Reading both on paper missed them, so the spec's own table is checked here.
"""

import base64
import hashlib
import json
import math
import re
from functools import lru_cache
from pathlib import Path

PROTOCOL = Path("docs/protocol.md")
SCHEMAS = Path("spec/schemas")
OFFERS_PER_SIDE = 3
PROGRESS_REPORTS = 8
PAUSES = 3
SAYS_PER_SIDE = 160
CLOSING_STEPS = {"decline", "cancel"}
FINAL_STATES = {"declined", "cancelled"}
ROW = re.compile(r"^\| (\S+) \| (\w+) \| `(\w+)` \| (\w+) \|(.*)\| `(\w+)` \|$")
# `say` is the one forward step either side can make, because each side has its own line.
EITHER_MAY = CLOSING_STEPS | {"say"}

# What a fooled agent can choose, each enforced where the protocol says. Signet fills every other field.
# A time or a deadline falls in the two weeks after its step, and `supersedes` names nothing or one of
# the 16 latest finished with that contact.
DATE_WINDOW_SECS = 14 * 24 * 3600
PAUSE_REASONS = 3
DEADLINES = 14 * 24
RECENT_FINISHED = 16
# The default `new_requests_per_contact_per_day` that `splint setup` and the owner's page sign, which the
# protocol's leak table states its per-day figures at.
REQUESTS_PER_DAY = 20
ALWAYS_ALLOWED_REASONS = 1  # `not_understood`, and `no_reason`.

# Core's own types. A plain conversation's `open` names no type, and `type/1` proposes one, carrying its
# schema, which the other side accepts, finishing it, or declines with one of core's reasons.
CONVERSATION = {"type": "conversation/1", "kind": "conversation", "say": {"text": {"text": {"max_chars": 500}}}}
PROPOSAL_DECLINES = ["name_taken", "not_needed", "not_understood", "too_big", "unsafe_type"]
PROPOSAL = {"type": "type/1", "kind": "request", "decline": PROPOSAL_DECLINES, "agreement": True}
# What core holds a proposed schema to. Every character of a name, word or number in it is one of the
# 37 a word can hold, or a digit, and one more says where a word ends.
MAX_CHOSEN_CHARS = 512
PROPOSALS_PER_DAY = 2
PROPOSED_SCHEMA_BITS = MAX_CHOSEN_CHARS * math.log2(38)
FINGERPRINT_TAG = b"splint type v1"
# Once completed, the side a value is paid to can ask to be paid it up to 3 times, each picking one of
# at most 4 places its owner signed, and say once that it arrived. Neither moves the state.
ASKS_PER_VALUE = 3
MAX_PLACES = 4


def one_encoding(schema: dict) -> str:
    """A schema's one encoding: every key sorted, every list sorted with no repeats, and an empty one, or
    `sign` of `none`, left out. Its fingerprint is what a type goes by."""

    def tidy(value):
        if isinstance(value, dict):
            return {key: tidy(item) for key, item in value.items() if item not in ({}, [])}
        if isinstance(value, list):
            return sorted(set(value))
        return value

    tidied = tidy(schema)
    if tidied.get("sign") == "none":
        del tidied["sign"]
    return json.dumps(tidied, sort_keys=True, separators=(",", ":"))


def type_id(schema: dict) -> str:
    """`name/version@` and the base32 SHA-256 of its one encoding, lower case with no padding."""
    digest = hashlib.sha256(FINGERPRINT_TAG + b"\x00" + one_encoding(schema).encode()).digest()
    return f"{schema['type']}@{base64.b32encode(digest).decode().rstrip('=').lower()}"


def read_schemas(folder: Path = SCHEMAS) -> dict[str, dict]:
    """Every example schema, by its name. Core has no list of its own: two agents agree a type, and these
    are examples of what they might."""
    found = {}
    for path in sorted(folder.glob("*.json")):
        schema = json.loads(path.read_text())
        found[schema["type"]] = schema
    return found


def schemas_by_id(folder: Path = SCHEMAS) -> dict[str, dict]:
    """The examples by the ID each goes by, with its fingerprint."""
    return {type_id(schema): schema for schema in read_schemas(folder).values()}


def example_id(name: str) -> str:
    return type_id(read_schemas()[name])


def applies(types: str, schema: dict) -> bool:
    """Whether a row with this Types column counts for this schema."""
    sign = schema.get("sign", "none")
    return {
        "any": True,
        "conversation": schema["kind"] == "conversation",
        "request": schema["kind"] == "request",
        "terms": not schema.get("agreement"),
        "agreement": bool(schema.get("agreement")),
        "no_work": not schema.get("result") and not schema.get("agreement"),
        "work": bool(schema.get("result")),
        "no_signers": sign == "none",
        "some_signers": sign != "none",
        "one_signer": sign == "requester",
        "two_signers": sign == "both",
    }[types]


def requests_rules_hash(text: str | None = None) -> str:
    """The hash of the interaction rules and example schemas alone, so vectors go stale on those and
    not on other edits."""
    text = PROTOCOL.read_text() if text is None else text
    rules = text.split("<!-- requests -->")[1].split("<!-- end-requests -->")[0]
    schemas = json.dumps(schemas_by_id(), sort_keys=True)
    return hashlib.sha256((rules + schemas).encode()).hexdigest()


def table_matches(text: str | None = None) -> list[re.Match]:
    text = PROTOCOL.read_text() if text is None else text
    body = text.split("<!-- transition-table -->")[1].split("<!-- end-transition-table -->")[0]
    return [match for match in map(ROW.match, body.splitlines()) if match]


def read_table(text: str | None = None) -> list[tuple[str, str, str, str, str]]:
    """Rows of (state, mover, step, types, next), with the backticks removed."""
    rows = []
    for match in table_matches(text):
        state, mover, step, types, _, target = match.groups()
        rows.append((state.strip("`"), mover, step, types, target))
    return rows


def other(side: str) -> str:
    return "T" if side == "R" else "R"


def side_of(mover: str, offerer: str | None) -> str | None:
    """Which side may make this move, or None when either may."""
    return {
        "requester": "R",
        "recipient": "T",
        "offerer": offerer,
        "not_offerer": other(offerer) if offerer else None,
        "either": None,
    }[mover]


class Left:
    """What's left of each capped move. It's part of a position, so a loop has to spend one."""

    @staticmethod
    def start():
        return (("R", OFFERS_PER_SIDE), ("T", OFFERS_PER_SIDE)), PROGRESS_REPORTS, PAUSES, (("R", SAYS_PER_SIDE), ("T", SAYS_PER_SIDE))


def moves(rows, schema, state, offerer, left):
    """The legal (side, step, next, offerer, left) from one position, caps applied."""
    offers, progress, pauses, says = left
    found = []
    for row_state, mover, step, types, target in rows:
        if row_state != state or not applies(types, schema):
            continue
        side = side_of(mover, offerer)
        for acting in (side,) if side else ("R", "T"):
            new_offers, new_progress, new_pauses, new_says = dict(offers), progress, pauses, dict(says)
            new_offerer = offerer
            if step in ("open", "counter") and schema["kind"] == "request":
                if new_offers[acting] == 0:
                    continue
                new_offers[acting] -= 1
                new_offerer = acting
            if step == "clarify" and state == "working":
                new_offerer = "R"
            if step == "progress":
                if progress == 0 or not schema.get("progress"):
                    continue
                new_progress -= 1
            if step == "pause":
                if pauses == 0:
                    continue
                new_pauses -= 1
            if step == "say":
                if new_says[acting] == 0:
                    continue
                new_says[acting] -= 1
            new_left = (tuple(sorted(new_offers.items())), new_progress, new_pauses, tuple(sorted(new_says.items())))
            found.append((acting, step, target, new_offerer, new_left))
    return found


def rule_bits(rule: dict) -> float:
    """How much one field can say, at most, for a rule from a schema."""
    kind, value = next(iter(rule.items()))
    if kind in ("word", "one_of"):
        return math.log2(len(value))
    if kind == "range":
        return math.log2(value["max"] - value["min"] + 1)
    if kind == "times":
        places = DATE_WINDOW_SECS // value["grid_secs"] + 1
        return math.log2(sum(math.comb(places, count) for count in range(1, value["max"] + 1)))
    # A text field can say what it likes, so it has no bound worth stating.
    return value["max_chars"] * 8.0


def worst_without_text() -> dict:
    """The type that carries the most a contact without `text` lets through, by core's
    `Document::needs_text`: no step's fields over 64 bits, each rounded up, with times counted as `max`
    choices from every place on the grid in the next two weeks. Ranges say a bit for each bit counted,
    and nothing says more. Times on a grid wider than two weeks have one place, so 16 of them count 16
    bits and say nothing, but give 16 picks of 4 bits each: 64 more on every accept for 16 off every
    offer. Every list is at 16 and both sides sign, so every move the table has is open."""
    words = [f"w{n}" for n in range(16)]
    return {
        "type": "worst/1",
        "kind": "request",
        "offer": {"t": {"times": {"grid_secs": 2**21, "max": 16}}, "a": {"range": {"min": 0, "max": 2**48 - 1}}},
        "pick": {f"p{n}": "t" for n in range(16)},
        "result": {"a": {"range": {"min": 0, "max": 2**53 - 1}}, "b": {"range": {"min": 0, "max": 2**11 - 1}}},
        "progress": words,
        "clarify": words,
        "decline": words,
        "sign": "both",
    }


def fields_bits(rules: dict) -> float:
    return sum(rule_bits(rule) for rule in rules.values())


def step_bits(schema: dict, step: str) -> float:
    offer = schema.get("offer", {})
    fixed = schema.get("fixed", [])
    picks = sum(
        math.log2(offer[source]["times"]["max"])
        for source in schema.get("pick", {}).values()
    )
    proposed = PROPOSED_SCHEMA_BITS if schema.get("agreement") else 0.0
    return {
        "open": fields_bits(offer) + math.log2(DEADLINES) + math.log2(RECENT_FINISHED + 1) + proposed,
        "counter": fields_bits({name: rule for name, rule in offer.items() if name not in fixed}),
        "accept": picks,
        "clarify": math.log2(len(schema.get("clarify", [])) + ALWAYS_ALLOWED_REASONS),
        "decline": math.log2(len(schema.get("decline", [])) + ALWAYS_ALLOWED_REASONS),
        "progress": math.log2(max(len(schema.get("progress", [])), 1)),
        "pause": math.log2(PAUSE_REASONS),
        "deliver": fields_bits(schema.get("result", {})),
        "say": fields_bits(schema.get("say", {})),
    }.get(step, 0.0)


def payment_bits(schema: dict, side: str) -> float:
    """What the side a type pays can say after it's completed: which value and place on each ask, which
    of its two payment moves or none, and the one word that it arrived."""
    paid = [value for value, to in schema.get("paid", {}).items() if to == side]
    if not paid:
        return 0.0
    each_ask = math.log2(MAX_PLACES) + math.log2(len(paid)) + math.log2(3)
    return ASKS_PER_VALUE * len(paid) * each_ask + 1.0


class TableError(Exception):
    pass


def walk(rows, schema) -> dict:
    """Checks the table's rules for one type, and returns its longest chain, the most steps one signer
    makes on a line, and the most bits one side can send.

    Raises TableError if a state has two movers, a loop isn't bounded, or a position can't close.
    """
    rows = [row for row in rows if applies(row[3], schema)]
    for state, mover, step, _, _ in rows:
        if mover == "either" and step not in EITHER_MAY:
            raise TableError(f"{state} lets either party {step}, which forks the chain")
    for state in {row[0] for row in rows}:
        movers = {row[1] for row in rows if row[0] == state and row[1] != "either"}
        if len(movers) > 1:
            raise TableError(f"{state} has more than one mover: {sorted(movers)}")

    in_progress = set()

    @lru_cache(maxsize=None)
    def visit(state, offerer, left):
        key = (state, offerer, left)
        if key in in_progress:
            raise TableError(f"unbounded loop through {state}")
        in_progress.add(key)
        options = moves(rows, schema, state, offerer, left)
        if state not in FINAL_STATES and state != "start" and not options:
            raise TableError(f"{state} is stranded: no legal move")
        if state not in FINAL_STATES | {"start", "completed"} and not any(
            step in CLOSING_STEPS for _, step, _, _, _ in options
        ):
            raise TableError(f"{state} has no closing move")
        longest = 0
        by_signer = {"R": 0, "T": 0}
        bits = {"R": 0.0, "T": 0.0}
        for side, step, target, new_offerer, new_left in options:
            chain, signers, tail = visit(target, new_offerer, new_left)
            longest = max(longest, 1 + chain)
            for who in by_signer:
                by_signer[who] = max(by_signer[who], signers[who] + (who == side))
            # Choosing among the moves open at this turn carries information as well, and so does
            # making none of them.
            choices = sum(1 for option in options if option[0] == side)
            spent = step_bits(schema, step) + math.log2(choices + 1)
            bits["R"] = max(bits["R"], tail["R"] + (spent if side == "R" else 0))
            bits["T"] = max(bits["T"], tail["T"] + (spent if side == "T" else 0))
        if state == "completed":
            bits["R"] += payment_bits(schema, "requester")
            bits["T"] += payment_bits(schema, "recipient")
        in_progress.discard(key)
        return longest, by_signer, bits

    longest, by_signer, bits = visit("start", None, Left.start())
    per_request = max(bits.values())
    per_day = PROPOSALS_PER_DAY if schema.get("agreement") else REQUESTS_PER_DAY
    return {
        "longest_chain": longest,
        "most_by_one_signer": max(by_signer.values()),
        "bits_per_request": round(per_request),
        "bytes_per_contact_per_day": round(per_request * per_day / 8),
    }


def every_shape_of_request() -> list[dict]:
    """A request of every shape a schema can have, so the table is walked for types not yet written."""
    return [
        {"type": f"shape/{index}", "kind": "request", "offer": {}, "result": ({"a": {"one_of": [1]}} if work else {}), "progress": ["a"], "clarify": ["a"], "decline": ["a"], "sign": sign}
        for index, (work, sign) in enumerate([(False, "requester"), (False, "both"), (True, "none"), (True, "requester"), (True, "both")])
    ]

"""A small reference walk of an interaction's chain, written from docs/protocol.md.

It reads what each type allows from spec/schemas, by the fingerprint each goes by, and core's own two
from request_table: a plain conversation and `type/1`, which carries the schema it proposes. It isn't what Splint runs. `splint_core::requests` runs the same vectors in `make check`, so two
separate walks have to agree.
"""

import hashlib
import json
import random
import re
import unicodedata

from request_table import (
    CONVERSATION,
    MAX_CHOSEN_CHARS,
    OFFERS_PER_SIDE,
    PAUSES,
    PROGRESS_REPORTS,
    PROPOSAL,
    SAYS_PER_SIDE,
    applies,
    one_encoding,
    read_table,
    schemas_by_id,
    side_of,
    type_id,
)

# Fields in the one order they can be signed in. Optional ones come last, in the order listed.
FIELDS = {
    "open": ["step", "type", "schema", "terms", "deadline"],
    "say": ["step", "request", "prev", "fields"],
    "counter": ["step", "request", "prev", "terms"],
    "clarify": ["step", "request", "prev", "reason"],
    "accept": ["step", "request", "prev", "pick"],
    "progress": ["step", "request", "prev", "status"],
    "pause": ["step", "request", "prev", "reason"],
    "resume": ["step", "request", "prev"],
    "deliver": ["step", "request", "prev", "result"],
    "confirm": ["step", "request", "prev", "approval"],
    "decline": ["step", "request", "prev", "reason"],
    "cancel": ["step", "request", "prev"],
    "received": ["step", "request", "of"],
    "pay_request": ["step", "request", "of", "for", "amount", "unit", "reference", "entry", "where_paid"],
    "payment_received": ["step", "request", "of"],
}
PAYMENT_STEPS = ("pay_request", "payment_received")
# Asks to be paid one value: once, and twice more for another place. A statement holds up to 4 places.
ASKS_PER_VALUE = 3
MAX_PLACES = 4
MAX_STATEMENT_BYTES = 1536
# Left out when empty, so an empty one has only one spelling. An `open` leaves out `type` for core's plain
# conversation, and `schema` on anything but a `type/1`.
LEFT_OUT_WHEN_EMPTY = {"open": "terms", "accept": "pick"}
LEFT_OUT_OF_AN_OPEN = ("type", "schema")
OPTIONAL = {
    "open": ["supersedes", "approval", "person_text"],
    "say": ["person_text"],
    "counter": ["approval", "person_text"],
    "clarify": ["note", "person_text"],
    "accept": ["approval"],
    "deliver": ["approval"],
    "decline": ["person_text"],
    "cancel": ["approval"],
}
# What an owner's yes can release, at `ask_me`, and how far ahead a step can date anything.
HELD_KINDS = ("open", "counter", "accept", "deliver")
MAX_DATE_AHEAD_SECS = 14 * 24 * 3600
FIELD_HOLDERS = ("terms", "fields", "pick", "result")
PAUSE_REASONS = {"needs_information", "needs_approval", "other"}
ALWAYS_ALLOWED = {"clarify": "not_understood", "decline": "no_reason"}
SCHEMAS = schemas_by_id()
WORD = re.compile(r"[a-z0-9_]{1,32}")
TYPE_NAME = re.compile(r"[a-z0-9_]{1,24}/[0-9]{1,4}")
# A name and the base32 SHA-256 of its schema's one encoding, whose last character's spare bits are zero.
TYPE_ID = re.compile(r"(?!type/)[a-z0-9_]{1,24}/[0-9]{1,4}@[a-z2-7]{51}[aq]")
PROPOSAL_TYPE = "type/1"
MAX_PROPOSED_BYTES = 2048
MAX_PROPOSED_ENTRIES = 16
MAX_PROPOSED_NUMBER = 2**53 - 1
MAX_PROPOSED_TEXT_CHARS = 500
RULE_KINDS = {"word", "one_of", "range", "times", "text"}
SCHEMA_PARTS = {"type", "kind", "offer", "fixed", "pick", "result", "progress", "clarify", "decline", "say", "sign", "values", "units", "paid"}
HOUR_SECS = 3600
# 16 bytes in unpadded base64url, whose last character carries only two bits.
NONCE = re.compile(r"[A-Za-z0-9_-]{21}[AQgw]")
ID_LEN = 64
CLOCK_TOLERANCE_SECS = 120
MAX_GUEST_NOTE = 280
MAX_PERSON_TEXT = 280
# Forward steps held from one signer. A longer line than this can't exist, so a signer past it has
# already forked the chain, and the reader is already disputed.
MAX_FORWARD_STEPS = 192
# Copies of one owner's yes a reader keeps. See docs/protocol.md.
COPIES_OF_A_YES = 2
MAX_STEPS_TO_TRY_EVERY_ORDER = 7


class Refused(Exception):
    def __init__(self, reason):
        self.reason = reason


def canonical(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def is_int(value) -> bool:
    return type(value) is int


def is_id(value) -> bool:
    return isinstance(value, str) and len(value) == ID_LEN and all(c in "0123456789abcdef" for c in value)


def is_one_of(value, allowed) -> bool:
    """A list or object can't be looked up in a set, and it fits nothing there anyway."""
    return isinstance(value, str) and value in allowed


# Invisible in most fonts, with no category that says so.
BLANK = {0x34F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180F, 0x2800, 0x3164, 0xFFA0, 0x1D159}


def has_control_characters(text: str) -> bool:
    def hides(c: str) -> bool:
        code = ord(c)
        return (
            unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Co")
            or code in BLANK
            or 0xFE00 <= code <= 0xFE0F
            or 0xE0000 <= code <= 0xE0FFF
            or 0xFDD0 <= code <= 0xFDEF
            or 0xFFF0 <= code <= 0xFFFF
        )

    return any(hides(c) for c in text)


def is_word(value) -> bool:
    return isinstance(value, str) and WORD.fullmatch(value) is not None


def rule_allows(rule: dict, value) -> bool:
    kind, spec = next(iter(rule.items()))
    if kind == "word":
        return is_one_of(value, spec)
    if kind == "one_of":
        return is_int(value) and value in spec
    if kind == "range":
        return is_int(value) and spec["min"] <= value <= spec["max"]
    if kind == "times":
        return (
            isinstance(value, list)
            and 1 <= len(value) <= spec["max"]
            and all(is_int(time) and time >= 0 and time % spec["grid_secs"] == 0 for time in value)
            and value == sorted(set(value))
        )
    return isinstance(value, str) and len(value) <= spec["max_chars"] and not has_control_characters(value)


def fits(rules: dict, fields) -> bool:
    return (
        isinstance(fields, dict)
        and set(rules) == set(fields)
        and all(rule_allows(rules[name], value) for name, value in fields.items())
    )


def fields_fit(schema: dict, step: dict) -> bool:
    """What the type's schema says about a step. Every part of it comes from that schema."""
    kind = step["step"]
    if kind == "open":
        return fits(schema.get("offer", {}), step.get("terms", {}))
    if kind == "counter":
        fixed = schema.get("fixed", [])
        return fits({name: rule for name, rule in schema.get("offer", {}).items() if name not in fixed}, step["terms"])
    if kind == "accept":
        pick = step.get("pick", {})
        return isinstance(pick, dict) and set(pick) == set(schema.get("pick", {})) and all(is_int(value) for value in pick.values())
    if kind == "say":
        return fits(schema.get("say", {}), step["fields"])
    if kind == "deliver":
        return bool(schema.get("result")) and fits(schema["result"], step["result"])
    if kind == "progress":
        return is_one_of(step["status"], schema.get("progress", []))
    if kind in ALWAYS_ALLOWED:
        return step["reason"] == ALWAYS_ALLOWED[kind] or is_one_of(step["reason"], schema.get(kind, []))
    return True


def agreed_terms(schema: dict, offer: dict, pick: dict) -> dict:
    """The offer without any list a pick chose from, plus the pick."""
    lists = set(schema.get("pick", {}).values())
    return {name: value for name, value in offer.items() if name not in lists} | pick


def rule_fits_together(rule) -> bool:
    if not isinstance(rule, dict) or len(rule) != 1:
        return False
    kind, spec = next(iter(rule.items()))
    if kind == "word":
        return isinstance(spec, list) and bool(spec) and all(is_word(word) for word in spec)
    if kind == "one_of":
        return isinstance(spec, list) and bool(spec) and all(is_int(n) and n >= 0 for n in spec)
    if kind == "range":
        return isinstance(spec, dict) and set(spec) == {"min", "max"} and all(is_int(n) and n >= 0 for n in spec.values()) and spec["min"] <= spec["max"]
    if kind == "times":
        return isinstance(spec, dict) and set(spec) == {"grid_secs", "max"} and all(is_int(n) for n in spec.values()) and spec["grid_secs"] > 0 and spec["max"] > 0
    if kind == "text":
        return isinstance(spec, dict) and set(spec) == {"max_chars"} and is_int(spec["max_chars"]) and spec["max_chars"] > 0
    return False


def schema_fits_together(schema) -> bool:
    """A schema some request could follow, as Splint reads one, whoever wrote it."""
    if not isinstance(schema, dict) or not set(schema) <= SCHEMA_PARTS:
        return False
    if not (isinstance(schema.get("type"), str) and TYPE_NAME.fullmatch(schema["type"])) or schema["type"].split("/")[0] == "type":
        return False
    sections = [schema.get(part, {}) for part in ("offer", "result", "say")]
    if not all(isinstance(section, dict) and len(section) <= 16 and all(is_word(name) and rule_fits_together(rule) for name, rule in section.items()) for section in sections):
        return False
    offer, result, say = sections
    lists = [schema.get(part, []) for part in ("fixed", "progress", "clarify", "decline", "values")]
    if not all(isinstance(words, list) and all(is_word(word) for word in words) for words in lists):
        return False
    fixed, progress, clarify, decline, values = lists
    pick, units, paid = (schema.get(part, {}) for part in ("pick", "units", "paid"))
    if not all(isinstance(part, dict) for part in (pick, units, paid)):
        return False
    sign = schema.get("sign", "none")
    kind = schema.get("kind")
    rule_of = lambda name: (offer.get(name) or result.get(name) or {})
    fits = (
        all(is_word(name) and name not in offer and from_ not in fixed and "times" in offer.get(from_, {}) for name, from_ in pick.items())
        and all(name in offer for name in fixed)
        and all(set(rule_of(name)) & {"range", "one_of"} for name in values)
        and all(name in values and side in ("requester", "recipient") for name, side in paid.items())
        and all(name in values and unit in fixed and "word" in offer.get(unit, {}) for name, unit in units.items())
        and sign in ("none", "requester", "both")
    )
    if kind == "conversation":
        return fits and bool(say) and not (offer or pick or result or progress or clarify or decline) and sign == "none"
    if kind == "request":
        return fits and not say and (bool(result) or sign != "none")
    return False


def chosen_chars(schema) -> int:
    """Every character of a name, word or number in a schema that whoever wrote it chose."""
    total = len(schema["type"])
    for part in ("offer", "result", "say"):
        for name, rule in schema.get(part, {}).items():
            total += len(name)
            kind, spec = next(iter(rule.items()))
            items = spec if isinstance(spec, list) else list(spec.values())
            total += sum(len(str(item)) for item in items)
    total += sum(len(word) for part in ("fixed", "progress", "clarify", "decline", "values") for word in schema.get(part, []))
    total += sum(len(name) + len(other) for name, other in schema.get("pick", {}).items())
    total += sum(len(name) + len(other) for name, other in schema.get("units", {}).items())
    total += sum(len(name) for name in schema.get("paid", {}))
    return total


def proposal_fits(schema) -> bool:
    """What core holds every proposed schema to. See "Interaction types" in docs/protocol.md."""
    if not schema_fits_together(schema):
        return False
    rules = [rule for part in ("offer", "result", "say") for rule in schema.get(part, {}).values()]
    entries = all(len(schema.get(part, {})) <= MAX_PROPOSED_ENTRIES for part in ("offer", "result", "say", "pick", "progress", "clarify", "decline"))
    for rule in rules:
        kind, spec = next(iter(rule.items()))
        if kind in ("word", "one_of") and len(spec) > MAX_PROPOSED_ENTRIES:
            entries = False
        if kind == "times" and spec["max"] > MAX_PROPOSED_ENTRIES:
            entries = False
        if kind in ("one_of",) and any(n > MAX_PROPOSED_NUMBER for n in spec):
            return False
        if kind in ("range", "times") and any(n > MAX_PROPOSED_NUMBER for n in spec.values()):
            return False
        if kind == "text" and spec["max_chars"] > MAX_PROPOSED_TEXT_CHARS:
            return False
    paid_in_a_unit = all(name in schema.get("units", {}) for name in schema.get("paid", {}))
    return entries and paid_in_a_unit and len(one_encoding(schema)) <= MAX_PROPOSED_BYTES and chosen_chars(schema) <= MAX_CHOSEN_CHARS


def schema_of_open(step, schemas=SCHEMAS):
    """The type an `open` starts: core's plain conversation with no `type`, core's `type/1`, or one of
    the types this reader knows by its ID."""
    if "type" not in step:
        return CONVERSATION
    if step["type"] == PROPOSAL_TYPE:
        return PROPOSAL
    return schemas.get(step["type"])


class Position:
    """What is true just after one step. A step is judged against the position its prev names."""

    def __init__(self, **fields):
        self.state = "start"
        self.offerer = None
        self.offers = {"R": OFFERS_PER_SIDE, "T": OFFERS_PER_SIDE}
        self.version = 1
        self.offer = {}
        self.pick = {}
        self.result = {}
        self.progress_left = PROGRESS_REPORTS
        self.pauses_left = PAUSES
        self.says_left = SAYS_PER_SIDE
        self.terms = None
        self.depth = 0
        self.message_id = None
        self.prev = None
        self.kind = None
        self.side = None
        self.undoes_completion = False
        self.__dict__.update(fields)

    def after(self, **changes):
        return Position(**(self.__dict__ | changes))


class Chain:
    """The valid steps a reader holds. Its state is a function of that set, not of arrival order.

    A step's validity depends only on the step and the steps behind it. What a reader keeps of a
    flood is chosen so that the state still doesn't depend on order: of the cancels naming one
    step it keeps the highest ID, one received per signer and step, and forward steps until
    MAX_FORWARD_STEPS, which only a signer that has already forked the chain can reach, and two
    copies of one owner's yes, however many times an agent key seals it with a new ID. Two show the
    key was used outside Signet, and a third says nothing more.
    """

    def __init__(self, parties, verify, schemas=()):
        self.parties = parties
        # The examples, and any type both sides agreed, as a walk's `schemas` gives them.
        self.schemas = SCHEMAS | {type_id(schema): schema for schema in schemas}
        self.guest = "guest" in parties["T"]
        self.verify = verify
        self.table = read_table()
        self.request = None
        self.open_step = None
        self.schema = None
        self.positions = {}
        self.cancels = {}
        self.approved_cancels = {}
        self.received = {}
        self.carried = {}
        self.copies_dropped = 0
        self.forward_held = {"R": 0, "T": 0}
        self.equivocated = False
        self.asks = []
        self.payment_received = None

    def apply(self, compact, arrived_at=None):
        """Takes one step. `arrived_at` is the reader's clock if this is its first receipt.

        A step already held is only ever re-checked for its signature, so it can't expire there.
        """
        sides = {"R": self.parties["R"], "T": self.parties["T"]}
        payload = json.loads(self.verify_unchecked(compact))
        side = next((s for s, p in sides.items() if p["id"] == payload["sender"]), None)
        if side is None or payload["recipient"] != sides["R" if side == "T" else "T"]["id"]:
            raise Refused("wrong_party")
        try:
            self.verify(compact, sides[side]["key"], "splint-envelope")
        except ValueError:
            raise Refused("bad_signature") from None
        if payload["expires_at"] <= payload["created_at"]:
            raise Refused("malformed")
        message_id = self.verify.message_id(compact)
        if message_id in self.positions or message_id in self.received.values() or self.holds_cancel(message_id) or message_id in self.payment_ids():
            raise Refused("replay")
        if arrived_at is not None and arrived_at >= payload["expires_at"]:
            raise Refused("expired")
        step = self.parse(payload)
        kind = step["step"]
        if self.request is not None and step.get("request") != self.request:
            raise Refused("wrong_request")
        schema = schema_of_open(step, self.schemas) if kind == "open" else self.schema
        if kind == "open" and schema is None:
            raise Refused("unknown_type")
        # Refused before anything else about it counts, so a field outside its type is the same
        # refusal wherever in a chain it turns up.
        if schema is not None and not fields_fit(schema, step):
            raise Refused("malformed")
        if kind == "open" and not self.nonce_fits(payload):
            raise Refused("malformed")
        if kind != "open" and payload["nonce"] != "":
            raise Refused("malformed")
        if kind == "received":
            self.record_received(step, side, message_id)
            return
        if kind in PAYMENT_STEPS:
            self.record_payment(step, side, message_id, payload["created_at"])
            return
        if kind == "open":
            at = Position()
        elif step["prev"] in self.positions:
            at = self.positions[step["prev"]]
        else:
            raise Refused("unknown_prev")
        if schema is None:
            raise Refused("unknown_prev")
        position = self.move(at, step, side, payload, message_id, schema)
        # The approval checked out in `move`, so its hash is of what its owner signed. On a link the
        # open and its confirm carry the same one, so the kind of step counts too.
        carried = (kind, self.verify.message_id(step["approval"])) if "approval" in step else None
        if carried is not None:
            if self.carried.get(carried, 0) >= COPIES_OF_A_YES:
                self.copies_dropped += 1
                return
            # Nothing past here refuses a step carrying an approval.
            self.carried[carried] = self.carried.get(carried, 0) + 1
        if kind == "cancel":
            if "approval" in step:
                self.approved_cancels[message_id] = position
            else:
                self.record_cancel(position)
            return
        # A step carrying an owner's approval is capped by its copies, and never counted here.
        if "approval" not in step:
            if self.forward_held[side] >= MAX_FORWARD_STEPS:
                raise Refused("too_many_steps")
            self.forward_held[side] += 1
        self.record(position, step, schema)

    def payment_ids(self):
        ids = {ask["id"] for ask in self.asks}
        if self.payment_received:
            ids.add(self.payment_received["id"])
        return ids

    def completed_at(self, of):
        named = self.positions.get(of)
        if named is None:
            raise Refused("unknown_prev")
        if named.state != "completed":
            raise Refused("out_of_turn")
        return named

    def due(self, of, side, value):
        """What's owed to `side` for `value` by the terms the completed step `of` left standing, where
        the payer's own owner signed them."""
        named = self.completed_at(of)
        if self.guest or self.schema.get("paid", {}).get(value) != ("requester" if side == "R" else "recipient"):
            raise Refused("not_payable")
        payer_signed = named.kind == "confirm" and (side == "T" or named.side == "T")
        if not payer_signed:
            raise Refused("not_payable")
        amount = next((held[value] for held in (named.result, named.offer, named.pick) if is_int(held.get(value))), None)
        unit = named.offer.get(self.schema.get("units", {}).get(value))
        if amount is None or not is_word(unit):
            raise Refused("not_payable")
        return amount, unit

    def payable(self, of, side):
        values = []
        for value in self.schema.get("values", []):
            try:
                self.due(of, side, value)
                values.append(value)
            except Refused:
                pass
        return values

    def where_paid(self, compact, side, sent_at):
        who = self.parties[side]
        try:
            self.verify(compact, who["owner_key"], "splint-where-paid")
        except ValueError:
            raise Refused("bad_where_paid") from None
        raw = self.verify.payload(compact)
        try:
            signed = json.loads(raw)
            places = [{"kind": place["kind"], **{k: place[k] for k in PLACE_FIELDS[place["kind"]]}} for place in signed["places"]]
            ordered = {"v": signed["v"], "owner": signed["owner"], "places": places, "issued_at": signed["issued_at"]}
        except (ValueError, KeyError, TypeError):
            raise Refused("bad_where_paid") from None
        unique = len({canonical(place) for place in places}) == len(places)
        fits = (
            len(raw) <= MAX_STATEMENT_BYTES
            and canonical(ordered).encode() == raw
            and signed["v"] == 1
            and signed["owner"] == who["owner"]
            and is_int(signed["issued_at"])
            # Never dated after the step carrying it, or it would outrank every later statement.
            and signed["issued_at"] <= sent_at + CLOCK_TOLERANCE_SECS
            and 0 < len(places) <= MAX_PLACES
            and unique
            and all(place_fits(place) for place in places)
        )
        if not fits:
            raise Refused("bad_where_paid")
        return places

    def record_payment(self, step, side, message_id, sent_at):
        """An ask to be paid, or the payee's word that it arrived. Neither moves the chain."""
        if step["step"] == "pay_request":
            amount, unit = self.due(step["of"], side, step["for"])
            places = self.where_paid(step["where_paid"], side, sent_at)
            matches = step["amount"] == amount and step["unit"] == unit and step["reference"] == reference_of(self.request) and step["entry"] < len(places)
            if not matches:
                raise Refused("payment_mismatch")
            if sum(1 for ask in self.asks if ask["side"] == side and ask["for"] == step["for"]) >= ASKS_PER_VALUE:
                raise Refused("too_many_steps")
            self.asks.append({"id": message_id, "side": side, "for": step["for"], "of": step["of"]})
            return
        self.completed_at(step["of"])
        if not self.payable(step["of"], side):
            raise Refused("not_payable")
        if self.payment_received is None:
            self.payment_received = {"id": message_id, "of": step["of"]}

    @property
    def payment(self):
        """Where the payment stands, kept apart from the state: only while completed, by the step that
        completed it."""
        if self.state != "completed":
            return None
        completed = self.deciding().message_id
        if self.payment_received and self.payment_received["of"] == completed:
            return "received"
        if any(ask["of"] == completed for ask in self.asks):
            return "requested"
        return None

    def holds_cancel(self, message_id):
        return message_id in self.approved_cancels or any(c.message_id == message_id for c in self.cancels.values())

    def record_received(self, step, side, message_id):
        """Delivery facts never touch state, so one per signer and step says all there is to say."""
        if self.guest and side == "T":
            raise Refused("out_of_turn")
        named = self.positions.get(step["of"]) or self.approved_cancels.get(step["of"])
        if named is not None and named.side == side:
            raise Refused("out_of_turn")
        if named is None:
            # It may name an agent's cancel this reader dropped, or one it hasn't got, and which
            # of those depends on order. So it's dropped in every case, and never stops a reader.
            named = next((c for c in self.cancels.values() if c.message_id == step["of"]), None)
            if named is None or named.side == side:
                return
        self.received.setdefault((side, step["of"]), message_id)

    def record_cancel(self, position):
        """No step can follow a cancel, so one per step it names is all that can matter."""
        best = self.cancels.get(position.prev)
        if best is None or position.message_id > best.message_id:
            self.cancels[position.prev] = position

    def record(self, position, step, schema):
        if position.kind == "open":
            self.request = position.message_id
            self.open_step = step
            self.schema = schema
        else:
            self.equivocated |= any(p.prev == position.prev and p.side == position.side for p in self.positions.values())
        self.positions[position.message_id] = position

    def parse(self, payload):
        try:
            step = json.loads(payload["body"])
            kind = step["step"]
            expected = FIELDS[kind]
        except (ValueError, KeyError, TypeError):
            raise Refused("malformed") from None
        allowed = expected + OPTIONAL.get(kind, [])
        if canonical(step) != payload["body"] or list(step) != [k for k in allowed if k in step]:
            raise Refused("malformed")
        needed = [name for name in expected if name != LEFT_OUT_WHEN_EMPTY.get(kind) and (kind != "open" or name not in LEFT_OUT_OF_AN_OPEN)]
        if any(name not in step for name in needed) or not self.values_fit(step, kind):
            raise Refused("malformed")
        if "note" in step:
            guest_sender = self.guest and payload["sender"] == self.parties["T"]["id"]
            if not guest_sender or not isinstance(step["note"], str) or len(step["note"]) > MAX_GUEST_NOTE:
                raise Refused("malformed")
        return step

    def values_fit(self, step, kind) -> bool:
        """Types and shapes, for any type. What each field can hold is its schema's to say."""
        for name in ("request", "prev", "of", "supersedes"):
            if name in step and not is_id(step[name]):
                return False
        for name in ("reason", "status"):
            if name in step and not is_word(step[name]):
                return False
        if kind == "pay_request":
            reference = step["reference"]
            fits = (
                is_word(step["for"])
                and is_word(step["unit"])
                and is_int(step["amount"]) and step["amount"] >= 0
                and is_int(step["entry"]) and 0 <= step["entry"] < MAX_PLACES
                and isinstance(step["where_paid"], str)
                and isinstance(reference, str)
                and REFERENCE.fullmatch(reference) is not None
            )
            if not fits:
                return False
        if kind == "pause" and step["reason"] not in PAUSE_REASONS:
            return False
        if "approval" in step and not isinstance(step["approval"], str):
            return False
        if "person_text" in step and not isinstance(step["person_text"], str):
            return False
        for name in FIELD_HOLDERS:
            if name not in step:
                continue
            held = step[name]
            if not isinstance(held, dict) or not held and LEFT_OUT_WHEN_EMPTY.get(kind) == name:
                return False
            # Only sorted names have one encoding, and only these three shapes can be read.
            if list(held) != sorted(held) or not all(is_word(field) for field in held):
                return False
            for value in held.values():
                if not (is_int(value) and value >= 0) and not isinstance(value, str) and not (isinstance(value, list) and value and all(is_int(time) and time >= 0 for time in value)):
                    return False
        if kind == "open":
            named = step.get("type")
            if named is not None and not (isinstance(named, str) and (named == PROPOSAL_TYPE or TYPE_ID.fullmatch(named))):
                return False
            # A schema rides on a `type/1` and nothing else, in its one encoding, which has no terms.
            if (named == PROPOSAL_TYPE) != ("schema" in step):
                return False
            if "schema" in step:
                proposed = step["schema"]
                if "terms" in step or not proposal_fits(proposed) or canonical(proposed) != one_encoding(proposed):
                    return False
            if not is_int(step["deadline"]) or step["deadline"] < 0 or step["deadline"] % HOUR_SECS:
                return False
        return True

    @staticmethod
    def dates_fit(step, signed_at) -> bool:
        """Between the step's own signing and two weeks after, whatever the type."""
        latest = signed_at + MAX_DATE_AHEAD_SECS
        if step["step"] == "open" and not signed_at < step["deadline"] <= latest:
            return False
        for name in FIELD_HOLDERS:
            for value in step.get(name, {}).values():
                if isinstance(value, list) and not all(signed_at <= time <= latest for time in value):
                    return False
        return True

    @staticmethod
    def nonce_fits(payload) -> bool:
        return isinstance(payload["nonce"], str) and NONCE.fullmatch(payload["nonce"]) is not None

    def move(self, at, step, side, payload, message_id, schema) -> Position:
        kind = step["step"]
        if not self.dates_fit(step, payload["created_at"]):
            raise Refused("outside_window")
        rule = None
        for state, mover, name, types, target in self.table:
            allowed = side_of(mover, at.offerer)
            if state == at.state and name == kind and applies(types, schema) and allowed in (None, side):
                rule = target
        if rule is None:
            raise Refused("out_of_turn")
        late = self.open_step and payload["created_at"] >= self.open_step["deadline"]
        if late and (at.state != "completed" or (self.guest and side == "T")):
            raise Refused("after_deadline")
        if "person_text" in step:
            self.check_person_text(step, side, payload)
        changes = {}
        if kind == "open" and schema["kind"] == "request":
            changes |= {"offers": at.offers | {side: at.offers[side] - 1}, "offerer": side, "offer": step.get("terms", {})}
        if kind == "counter":
            if self.guest:
                raise Refused("guest_counter")
            if at.offers[side] == 0:
                raise Refused("no_offers_left")
            changes |= {
                "offers": at.offers | {side: at.offers[side] - 1},
                "offerer": side,
                "offer": at.offer | step["terms"],
                "version": at.version + 1,
                "pick": {},
                "result": {},
                "terms": None,
            }
        if kind == "open" and self.guest:
            self.check_guest_offer(step, payload, schema)
        if kind == "say":
            if at.kind != "open" and at.side != side:
                raise Refused("out_of_turn")
            if at.says_left == 0:
                raise Refused("no_moves_left")
            changes["says_left"] = at.says_left - 1
        if kind == "accept":
            pick = step.get("pick", {})
            for name, value in pick.items():
                if value not in at.offer.get(schema["pick"][name], []):
                    raise Refused("not_offered")
            changes["pick"] = pick
        if kind == "clarify" and at.state == "working":
            changes["offerer"] = "R"
        if kind == "progress":
            if at.progress_left == 0:
                raise Refused("no_moves_left")
            changes["progress_left"] = at.progress_left - 1
        if kind == "pause":
            if at.pauses_left == 0:
                raise Refused("no_moves_left")
            changes["pauses_left"] = at.pauses_left - 1
        if kind == "deliver":
            changes["result"] = step["result"]
            if rule == "completed":
                changes["terms"] = self.rebuilt_terms(at.after(result=step["result"]), None, None)
        if kind == "confirm":
            changes["terms"] = self.check_confirm(at, step, side, payload)
            if self.guest:
                rule = "completed"
        if kind == "cancel" and at.state == "completed":
            self.check_cancel_of_completed(at, step, side, payload)
            changes["undoes_completion"] = True
        elif kind == "cancel" and ("approval" in step or step["prev"] != self.request):
            # An agent's cancel names the open, so it can always be judged, whatever else is held.
            raise Refused("malformed")
        if kind in HELD_KINDS and "approval" in step and not self.guest:
            self.check_release(at.after(**changes), step, side, payload, schema)
        return at.after(
            state=rule,
            depth=at.depth + 1,
            message_id=message_id,
            prev=step.get("prev"),
            kind=kind,
            side=side,
            **changes,
        )

    def check_release(self, after, step, side, payload, schema):
        """An owner's yes to a step their agent asked to send, at `ask_me`. An open has no request or
        prev yet, so its yes names the hash of its nonce, and its deadline by when it ends."""
        kind = step["step"]
        approval = self.approval_payload(step["approval"], side)
        hold = hashlib.sha256(payload["nonce"].encode()).hexdigest()
        request, prev = (hold, hold) if kind == "open" else (self.request, step["prev"])
        offered = kind in ("open", "counter")
        terms = {
            "type": step.get("type") if kind == "open" else self.open_step.get("type"),
            "requester": self.party_terms("R"),
            "recipient": self.party_terms("T"),
            "agreed": after.offer if offered else agreed_terms(schema, after.offer, after.pick),
            "result": after.result,
            "subject": None,
            "note": None,
            "supersedes": (step if kind == "open" else self.open_step).get("supersedes"),
        }
        # Core's plain conversation names no type, in its terms as on its `open`.
        if terms["type"] is None:
            del terms["type"]
        try:
            self.check_binding(approval, side, kind, request, after.version, prev, terms, payload)
            ends = approval["expires_at"]
        except KeyError:
            raise Refused("approval_mismatch") from None
        if kind == "open" and ends != step["deadline"]:
            raise Refused("approval_mismatch")
        self.check_dates_copied(approval, payload)

    def check_person_text(self, step, side, payload):
        """A person's words reach the other agent as untrusted data, under their owner's signature."""
        who = self.parties[side]
        if "guest" in who:
            raise Refused("malformed")
        try:
            self.verify(step["person_text"], who["owner_key"], "splint-person-text")
        except ValueError:
            raise Refused("bad_person_text") from None
        signed = json.loads(self.verify_unchecked(step["person_text"]))
        request = None if step["step"] == "open" else self.request
        same = (
            signed["owner"] == who["owner"]
            and signed["agent"] == who["id"]
            and signed["to"] == payload["recipient"]
            and signed["request"] == request
            and isinstance(signed["text"], str)
            and 0 < len(signed["text"]) <= MAX_PERSON_TEXT
            and not has_control_characters(signed["text"])
        )
        if not same:
            raise Refused("bad_person_text")

    def check_cancel_of_completed(self, at, step, side, payload):
        # A guest has no owner, so a guest's own signed click is all the authority there is.
        if self.guest and side == "T":
            if "approval" in step:
                raise Refused("malformed")
            return
        if "approval" not in step:
            raise Refused("approval_missing")
        approval = self.approval_payload(step["approval"], side)
        self.check_binding(approval, side, "cancel", self.request, at.version, step["prev"], at.terms, payload)
        self.check_dates_copied(approval, payload)

    def rebuilt_terms(self, at, subject, note):
        return {
            "type": self.open_step.get("type"),
            "requester": self.party_terms("R"),
            "recipient": self.party_terms("T"),
            "agreed": agreed_terms(self.schema, at.offer, at.pick),
            "result": at.result,
            "subject": subject,
            "note": note,
            "supersedes": self.open_step.get("supersedes"),
        }

    def party_terms(self, side):
        who = self.parties[side]
        return {"agent": who["id"], "owner": who["owner"]}

    def approval_payload(self, compact, side):
        try:
            self.verify(compact, self.parties[side]["owner_key"], "splint-approval")
        except ValueError:
            raise Refused("approval_bad_signature") from None
        return json.loads(self.verify_unchecked(compact))

    def check_binding(self, approval, side, operation, request, version, prev, terms, payload):
        who = self.parties[side]
        same = (
            approval["decision"] == "approve"
            and approval["owner"] == who["owner"]
            and approval["agent"] == who["id"]
            and approval["operation"] == operation
            and approval["request"] == request
            and approval["version"] == version
            and approval["prev"] == prev
            and approval["terms"] == terms
        )
        if not same:
            raise Refused("approval_mismatch")
        self.check_dates(approval, operation, payload)

    def check_dates(self, approval, operation, payload):
        deadline = (self.open_step or json.loads(payload["body"]))["deadline"]
        # A completed request can be cancelled after its deadline, so only that approval may outlive it.
        if operation != "cancel" and approval["expires_at"] > deadline:
            raise Refused("approval_mismatch")
        if payload["created_at"] >= approval["expires_at"]:
            raise Refused("approval_expired")

    @staticmethod
    def check_dates_copied(approval, payload):
        """So one approval on one prev makes one MessageId, and an agent key can't make copies."""
        if (payload["created_at"], payload["expires_at"]) != (approval["issued_at"], approval["expires_at"]):
            raise Refused("approval_mismatch")

    def check_confirm(self, at, step, side, payload):
        if self.guest:
            # The approval was compared in full with the only offer this request can have.
            if step["approval"] != self.open_step["approval"]:
                raise Refused("approval_mismatch")
            approval = self.approval_payload(step["approval"], side)
            self.check_dates(approval, "offer_to_guest", payload)
            self.check_dates_copied(approval, payload)
            return self.rebuilt_terms(at, approval["terms"]["subject"], approval["terms"]["note"])
        approval = self.approval_payload(step["approval"], side)
        if at.state in ("accepted", "delivered"):
            offered = approval["terms"]
            terms = self.rebuilt_terms(at, offered.get("subject"), offered.get("note"))
        else:
            terms = at.terms
        self.check_binding(approval, side, "confirm", self.request, at.version, step["prev"], terms, payload)
        self.check_dates_copied(approval, payload)
        return terms

    def check_guest_offer(self, step, payload, schema):
        """An owner's yes to one link. It names the hash of the open's nonce, so one yes makes one open,
        and its end is the deadline. A guest can't do work, so a type with a result can't be offered."""
        if schema.get("result"):
            raise Refused("type_not_allowed")
        if "approval" not in step:
            raise Refused("approval_missing")
        approval = self.approval_payload(step["approval"], "R")
        signed = approval["terms"]
        terms = {
            "type": step["type"],
            "requester": self.party_terms("R"),
            "recipient": self.party_terms("T"),
            "agreed": step.get("terms", {}),
            "result": {},
            "subject": signed.get("subject"),
            "note": signed.get("note"),
            "supersedes": step.get("supersedes"),
        }
        hold = hashlib.sha256(payload["nonce"].encode()).hexdigest()
        if approval["expires_at"] != step["deadline"]:
            raise Refused("approval_mismatch")
        self.check_binding(approval, "R", "offer_to_guest", hold, 1, hold, terms, payload)
        self.check_dates_copied(approval, payload)

    def verify_unchecked(self, compact):
        return self.verify.payload(compact)

    def signed_floor(self) -> int:
        """The newest version R's owner has signed. Signing it voids what they signed before."""
        return max((p.version for p in self.positions.values() if p.kind == "confirm" and p.side == "R"), default=1)

    def deciding(self) -> Position:
        """The step that decides the state. Depth, then ID, makes the choice independent of order."""
        floor = self.signed_floor()
        held = [*self.positions.values(), *self.cancels.values(), *self.approved_cancels.values()]
        completed = [p for p in held if p.state == "completed" and p.version >= floor]
        for found in (
            [p for p in held if p.undoes_completion and p.version >= floor],
            completed,
            [p for p in held if p.state == "cancelled"],
            [p for p in held if p.state != "completed"],
        ):
            if found:
                return max(found, key=lambda p: (p.depth, p.message_id))
        return Position()

    @property
    def state(self):
        deciding = self.deciding()
        # An owner's signature settles a fork. A `deliver` no owner signed doesn't.
        settled = deciding.state == "cancelled" or (deciding.state == "completed" and deciding.kind == "confirm")
        return "disputed" if self.equivocated and not settled else deciding.state

    @property
    def version(self):
        # A forked chain has no one version or head to report.
        return None if self.state == "disputed" else self.deciding().version

    @property
    def head(self):
        return None if self.state == "disputed" else self.deciding().message_id


def named_step(compact, verify):
    body = json.loads(json.loads(verify.payload(compact))["body"])
    return body.get("prev") or body.get("of")


def every_order(chain, verify, delivered=frozenset()):
    if not chain:
        yield []
    for compact in chain:
        named = named_step(compact, verify)
        if named is None or named in delivered:
            rest = [other for other in chain if other != compact]
            for order in every_order(rest, verify, delivered | {verify.message_id(compact)}):
                yield [compact, *order]


def sampled_order(chain, verify, rng, delivered):
    """One random order a host could deliver in. It's a sample because a flood has too many."""
    named = {compact: named_step(compact, verify) for compact in chain}
    delivered, waiting, order = set(delivered), list(chain), []
    while waiting:
        ready = [compact for compact in waiting if named[compact] is None or named[compact] in delivered]
        if not ready:
            return None
        chosen = rng.choice(ready)
        waiting.remove(chosen)
        delivered.add(verify.message_id(chosen))
        order.append(chosen)
    return order


def orders_a_host_could_deliver(chain, verify, keep_first=1, samples=40):
    """Orders with each step after the one it names. `keep_first` steps stay where they are, because
    an owner signs only on a step their own Signet holds, so those arrived before any flood did."""
    first, rest = chain[:keep_first], chain[keep_first:]
    seen = frozenset(verify.message_id(compact) for compact in first)
    if len(rest) <= MAX_STEPS_TO_TRY_EVERY_ORDER:
        yield from ([*first, *order] for order in every_order(rest, verify, seen))
        return
    rng = random.Random(canonical(first))
    for _ in range(samples):
        order = sampled_order(rest, verify, rng, seen)
        if order is not None:
            yield [*first, *order]


# Each kind of place and its fields, in their one order after `kind`.
PLACE_FIELDS = {"payment_page": ["url"], "lightning": ["to"], "onchain": ["chain", "address", "asset"]}
REFERENCE = re.compile(r"SPL-[0-9A-F]{16}")
URL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%")
BECH32 = set("qpzry9x8gf2tvdw0s3jn54khce6mua7l")


def reference_of(request: str) -> str:
    return "SPL-" + request[:16].upper()


def is_dns_name(host: str) -> bool:
    labels = host.split(".")
    top = labels[-1]
    return (
        len(host) <= 253
        and len(labels) >= 2
        and all(0 < len(label) <= 63 and not label.startswith("-") and not label.endswith("-") and all(c.isascii() and (c.isalnum() or c == "-") for c in label) for label in labels)
        and len(top) >= 2
        and all(c.isascii() and c.isalpha() for c in top)
    )


def place_fits(place: dict) -> bool:
    """The shape code checks for each kind of place, so no login, prose or hidden character rides on one."""
    kind = place["kind"]
    if not all(isinstance(place[name], str) for name in PLACE_FIELDS[kind]):
        return False
    if kind == "payment_page":
        url = place["url"]
        if not url.startswith("https://") or len(url) > 300 or not all(c in URL_CHARS for c in url):
            return False
        authority = re.split(r"[/?#]", url[len("https://"):])[0]
        if "@" in authority:
            return False
        host, _, port = authority.partition(":")
        if ":" in authority and not (0 < len(port) <= 5 and port.isascii() and port.isdigit()):
            return False
        return is_dns_name(host)
    if kind == "lightning":
        to = place["to"]
        if to.startswith("lno1"):
            return 20 <= len(to) <= 600 and all(c in BECH32 for c in to[4:])
        name, at, domain = to.partition("@")
        name_fits = 0 < len(name) <= 64 and all(c.isascii() and (c.islower() or c.isdigit() or c in "-_.+") for c in name)
        return bool(at) and len(to) <= 320 and name_fits and domain == domain.lower() and is_dns_name(domain)
    namespace, colon, reference = place["chain"].partition(":")
    chain_fits = (
        bool(colon)
        and 3 <= len(namespace) <= 8
        and all(c.isascii() and (c.islower() or c.isdigit() or c == "-") for c in namespace)
        and 1 <= len(reference) <= 32
        and all(c.isascii() and (c.isalnum() or c in "-_") for c in reference)
    )
    address = place["address"]
    address_fits = 1 <= len(address) <= 128 and all(c.isascii() and (c.isalnum() or c in "-.%") for c in address)
    return chain_fits and address_fits and is_word(place["asset"])


def walk_chain(parties, chain, now, verify, last_arrived_at=None, schemas=()) -> dict:
    """Stops at the first refusal, except a cap's: a reader past that carries on with what it holds."""
    walker = Chain(parties, verify, schemas)
    over_cap = 0
    for index, compact in enumerate(chain):
        arrived_at = last_arrived_at if index == len(chain) - 1 else None
        try:
            walker.apply(compact, arrived_at)
        except Refused as refused:
            if refused.reason != "too_many_steps":
                return {"refused_at": index, "reason": refused.reason}
            over_cap += 1
    state = walker.state
    open_step = walker.open_step
    if (
        open_step
        and state not in {"completed", "declined", "cancelled", "disputed"}
        and now > open_step["deadline"] + CLOCK_TOLERANCE_SECS
    ):
        state = "expired"
    result = {"state": state, "version": walker.version, "head": walker.head}
    if over_cap:
        result["over_cap"] = over_cap
    if walker.copies_dropped:
        result["copies_dropped"] = walker.copies_dropped
    if walker.payment:
        result["payment"] = walker.payment
    return result


def verify_outcome(outcome, parties, verify) -> dict:
    """Checks a bundle by itself. Nothing here looks at a chain, because a verifier may not have one."""
    try:
        if outcome["v"] != 1 or outcome["result"] != "completed":
            return {"ok": False, "reason": "malformed"}
        if outcome["assurance"] in ("owner", "requester_owner", "agent"):
            sign = SCHEMAS[outcome["terms"]["type"]].get("sign", "none") if outcome["terms"]["type"] in SCHEMAS else None
            if {"owner": "both", "requester_owner": "requester", "agent": "none"}[outcome["assurance"]] != sign:
                return {"ok": False, "reason": "proof_mismatch"}
        if outcome["assurance"] == "owner":
            return verify_owner_outcome(outcome, parties, verify)
        if outcome["assurance"] == "requester_owner":
            return verify_requester_owner_outcome(outcome, parties, verify)
        if outcome["assurance"] == "agent":
            return verify_agent_outcome(outcome, parties, verify)
        if outcome["assurance"] == "link":
            return verify_link_outcome(outcome, parties, verify)
        return {"ok": False, "reason": "malformed"}
    except ValueError:
        return {"ok": False, "reason": "bad_signature"}
    except (KeyError, TypeError):
        return {"ok": False, "reason": "malformed"}


def signed_step(compact, party, verify):
    """A step inside a bundle, and its body."""
    payload = json.loads(verify(compact, party["key"], "splint-envelope"))
    return payload, json.loads(payload["body"])


def verify_requester_owner_outcome(outcome, parties, verify) -> dict:
    mismatch = {"ok": False, "reason": "proof_mismatch"}
    ids = {side: {"agent": parties[side]["id"], "owner": parties[side]["owner"]} for side in ("R", "T")}
    terms = outcome["terms"]
    if terms["requester"] != ids["R"] or terms["recipient"] != ids["T"] or "recipient" in outcome["approvals"] or "requester_confirm" not in outcome:
        return mismatch
    approval = json.loads(verify(outcome["approvals"]["requester"], parties["R"]["owner_key"], "splint-approval"))
    confirm, body = signed_step(outcome["requester_confirm"], parties["R"], verify)
    tied = (
        approval["decision"] == "approve"
        and approval["operation"] == "confirm"
        and approval["owner"] == parties["R"]["owner"]
        and approval["agent"] == parties["R"]["id"]
        and approval["request"] == outcome["request"]
        and approval["terms"] == terms
        and body["step"] == "confirm"
        and body["request"] == outcome["request"]
        and body["approval"] == outcome["approvals"]["requester"]
        and body["prev"] == approval["prev"]
        and confirm["recipient"] == parties["T"]["id"]
    )
    return {"ok": True} if tied else mismatch


def verify_agent_outcome(outcome, parties, verify) -> dict:
    """T's agent key said this result. That's all this assurance claims."""
    mismatch = {"ok": False, "reason": "proof_mismatch"}
    ids = {side: {"agent": parties[side]["id"], "owner": parties[side]["owner"]} for side in ("R", "T")}
    terms = outcome["terms"]
    if terms["requester"] != ids["R"] or terms["recipient"] != ids["T"]:
        return mismatch
    if "requester" in outcome["approvals"] or "recipient" in outcome["approvals"] or "requester_confirm" in outcome:
        return mismatch
    deliver, body = signed_step(outcome["deliver"], parties["T"], verify)
    tied = (
        body["step"] == "deliver"
        and body["request"] == outcome["request"]
        and body["result"] == terms["result"]
        and deliver["recipient"] == parties["R"]["id"]
    )
    return {"ok": True} if tied else mismatch


def verify_owner_outcome(outcome, parties, verify) -> dict:
    mismatch = {"ok": False, "reason": "proof_mismatch"}
    if "guest" in parties["T"]:
        return mismatch
    ids = {side: {"agent": parties[side]["id"], "owner": parties[side]["owner"]} for side in ("R", "T")}
    terms = outcome["terms"]
    if terms["requester"] != ids["R"] or terms["recipient"] != ids["T"]:
        return mismatch
    approvals = {}
    for side, role in (("R", "requester"), ("T", "recipient")):
        approval = json.loads(verify(outcome["approvals"][role], parties[side]["owner_key"], "splint-approval"))
        same = (
            approval["decision"] == "approve"
            and approval["operation"] == "confirm"
            and approval["owner"] == parties[side]["owner"]
            and approval["agent"] == parties[side]["id"]
            and approval["request"] == outcome["request"]
            and approval["terms"] == terms
        )
        if not same:
            return mismatch
        approvals[side] = approval
    # The two approvals have to be one agreement: T's owner signed on top of the step that carries
    # R's owner's approval, at the same version.
    confirm, body = signed_step(outcome["requester_confirm"], parties["R"], verify)
    tied = (
        approvals["R"]["version"] == approvals["T"]["version"]
        and approvals["T"]["prev"] == verify.message_id(outcome["requester_confirm"])
        and body["step"] == "confirm"
        and body["request"] == outcome["request"]
        and body["approval"] == outcome["approvals"]["requester"]
        and body["prev"] == approvals["R"]["prev"]
        and confirm["recipient"] == parties["T"]["id"]
    )
    return {"ok": True} if tied else mismatch


def verify_link_outcome(outcome, parties, verify) -> dict:
    mismatch = {"ok": False, "reason": "proof_mismatch"}
    guest, requester = parties["T"], parties["R"]
    compact = outcome["approvals"]["requester"]
    approval = json.loads(verify(compact, requester["owner_key"], "splint-approval"))
    offer = approval["terms"]
    opened, open_body = signed_step(outcome["open"], requester, verify)
    accepted, accept = signed_step(outcome["guest_accept"], guest, verify)
    confirmed, confirm = signed_step(outcome["requester_confirm"], requester, verify)
    schema = SCHEMAS.get(offer["type"], {})
    expected = offer | {"agreed": agreed_terms(schema, offer["agreed"], accept.get("pick", {})), "result": {}}
    tied = (
        approval["decision"] == "approve"
        and approval["operation"] == "offer_to_guest"
        and approval["owner"] == requester["owner"]
        and approval["agent"] == requester["id"]
        and offer["recipient"]["agent"] == guest["id"]
        and approval["request"] == hashlib.sha256(opened["nonce"].encode()).hexdigest()
        and verify.message_id(outcome["open"]) == outcome["request"]
        and open_body.get("approval") == compact
        and opened["recipient"] == guest["id"]
        and accepted["recipient"] == requester["id"]
        and accept["step"] == "accept"
        and accept["request"] == outcome["request"]
        and accept["prev"] == outcome["request"]
        and all(value in offer["agreed"].get(schema["pick"][name], []) for name, value in accept.get("pick", {}).items())
        and confirmed["recipient"] == guest["id"]
        and confirm["step"] == "confirm"
        and confirm["request"] == outcome["request"]
        and confirm["approval"] == compact
        and confirm["prev"] == verify.message_id(outcome["guest_accept"])
        and outcome["terms"] == expected
    )
    return {"ok": True} if tied else mismatch

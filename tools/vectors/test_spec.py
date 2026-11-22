#!/usr/bin/env python3
"""Tests the walk with tables that have the faults it exists to catch, then walks the real one."""

import base64
import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

from request_chain import (
    MAX_FORWARD_STEPS,
    Chain,
    Refused,
    walk_chain,
)
from request_table import (
    OFFERS_PER_SIDE,
    PAUSES,
    PROGRESS_REPORTS,
    PROTOCOL,
    SAYS_PER_SIDE,
    TableError,
    CONVERSATION,
    PROPOSAL,
    every_shape_of_request,
    worst_without_text,
    read_schemas,
    read_table,
    requests_rules_hash,
    walk,
)

VECTORS = Path("spec/vectors")
TOOL = Path(__file__).parent
CHAIN_FILES = ("requests.json", "guest-links.json")
# Reasons that turn only on a signature, which this file has no library to check. The Rust test
# checks the signatures these vectors list.
TURNS_ON_A_SIGNATURE = {"wrong_signer", "bad_signature", "approval_bad_signature"}
ONLY_A_SIGNATURE_DIFFERS = {"person_text_signed_by_the_agent_key"}
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
DOC_PATH = re.compile(r"\b((?:spec|docs)/[\w./-]+\.(?:md|json))\b")
TEXT_SUFFIXES = {".md", ".rs", ".py", ".toml"}


def warn(holds: bool, message: str) -> None:
    """For prose that should agree with the code, where a mismatch is for a person to see and fix, and
    shouldn't fail a build. The code and the vectors are what's enforced."""
    if not holds:
        print(f"WARN {message}", file=sys.stderr, flush=True)


MEETING = read_schemas()["meeting/1"]
ALL_SHAPES = [*read_schemas().values(), *every_shape_of_request(), CONVERSATION, PROPOSAL]


class RequestTable(unittest.TestCase):
    def rows(self):
        return read_table()

    def test_the_table_is_read_in_full(self):
        rows = self.rows()
        self.assertIn(("offered", "not_offerer", "accept", "no_work", "accepted"), rows)
        self.assertIn(("offered", "not_offerer", "accept", "agreement", "completed"), rows)
        self.assertIn(("completed", "either", "cancel", "any", "cancelled"), rows)

    def test_every_shape_of_type_walks(self):
        for schema in ALL_SHAPES:
            with self.subTest(schema["type"]):
                walk(self.rows(), schema)

    def test_the_spec_states_what_the_walk_finds(self):
        # Estimates for a reader, not caps, but an owner decides on them, so a stale one fails the build.
        text = PROTOCOL.read_text()
        longest = max(walk(self.rows(), schema)["longest_chain"] for schema in every_shape_of_request())
        self.assertIn(f"the longest possible is **{longest} steps**", text)
        meeting = walk(self.rows(), MEETING)["longest_chain"]
        self.assertIn(f"a `meeting/1` line is at most **{meeting} steps**", text)
        rows = [*((f"`{name}`", read_schemas()[name]) for name in ("meeting/1", "quote/1", "document/1")), ("`type/1`", PROPOSAL), ("Any agreed type, with `text` off", worst_without_text())]
        for name, schema in rows:
            found = walk(self.rows(), schema)
            line = next((line for line in text.splitlines() if line.startswith(f"| {name} | about")), "")
            for said in (f"about **{found['bits_per_request']} bits per request**", f"about **{found['bytes_per_contact_per_day']} bytes per contact per day**"):
                self.assertIn(said, line, f"{PROTOCOL} should say {name} takes {said.replace('**', '')}")

    def test_the_caps_hold_every_line_under_what_a_reader_and_a_host_keep(self):
        for schema in ALL_SHAPES:
            found = walk(self.rows(), schema)
            self.assertLess(found["most_by_one_signer"], MAX_FORWARD_STEPS, schema["type"])
            # One sender's own steps, and a `received` for each of the other side's.
            self.assertLessEqual(found["longest_chain"], 400, schema["type"])

    def test_a_proposal_is_taken_or_left_as_it_is(self):
        # A `type/1` that could be countered or clarified would carry a second schema, past every limit.
        found = walk(self.rows(), PROPOSAL)
        self.assertEqual(found["longest_chain"], 3)
        rows = self.rows() + [("offered", "not_offerer", "counter", "any", "offered")]
        self.assertGreater(walk(rows, PROPOSAL)["longest_chain"], found["longest_chain"])

    def test_two_movers_on_one_state_is_a_fork(self):
        rows = self.rows() + [("requester_confirmed", "requester", "counter", "any", "offered")]
        with self.assertRaisesRegex(TableError, "more than one mover"):
            walk(rows, MEETING)

    def test_a_row_that_counts_only_for_another_shape_is_no_fork_here(self):
        rows = self.rows() + [("requester_confirmed", "requester", "counter", "conversation", "offered")]
        walk(rows, MEETING)

    def test_either_party_moving_forward_is_a_fork(self):
        for state, mover, step, types, target in self.rows():
            if step in ("accept", "confirm", "counter", "clarify") and types in ("any", "no_work", "two_signers"):
                rows = [row for row in self.rows() if row != (state, mover, step, types, target)]
                with self.subTest(state=state, step=step), self.assertRaisesRegex(TableError, "forks the chain"):
                    walk(rows + [(state, "either", step, types, target)], MEETING)

    def test_a_loop_with_no_offer_in_it_is_unbounded(self):
        rows = self.rows() + [("clarifying", "offerer", "clarify", "any", "offered")]
        with self.assertRaisesRegex(TableError, "unbounded"):
            walk(rows, MEETING)

    def test_a_loop_of_resumes_with_no_cap_is_unbounded(self):
        rows = self.rows() + [("working", "recipient", "resume", "any", "working")]
        with self.assertRaisesRegex(TableError, "unbounded"):
            walk(rows, read_schemas()["quote/1"])

    def test_the_prose_states_the_numbers_the_code_uses(self):
        # The vectors enforce the caps, so prose that disagrees only warns.
        text = PROTOCOL.read_text()
        for said in (
            f"- {OFFERS_PER_SIDE} offers per side per request",
            f"- {PROGRESS_REPORTS} `progress` reports and {PAUSES} `pause` steps per request",
            f"- {SAYS_PER_SIDE} `say` messages per side per conversation",
            f"The first {MAX_FORWARD_STEPS} from each signer",
        ):
            warn(said in text, f"{PROTOCOL} should say {said.removeprefix('- ')!r}")

    def test_a_state_with_only_capped_moves_is_stranded(self):
        rows = [row for row in self.rows() if row[0] != "clarifying" or row[2] == "counter"]
        with self.assertRaisesRegex(TableError, "stranded|no closing"):
            walk(rows, MEETING)

    def test_a_state_that_cant_close_is_refused(self):
        rows = [row for row in self.rows() if row[0] != "accepted" or row[2] == "confirm"]
        with self.assertRaisesRegex(TableError, "no closing"):
            walk(rows, MEETING)


def sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decoded(segment: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


class VectorFiles(unittest.TestCase):
    def test_files_match_what_the_tool_wrote(self):
        manifest = json.loads((VECTORS / "manifest.json").read_text())
        on_disk = {path.name for path in VECTORS.glob("*.json")} - {"manifest.json"}
        self.assertEqual(set(manifest["files"]), on_disk)
        for name, expected in manifest["files"].items():
            self.assertEqual(sha256_hex(VECTORS / name), expected, f"{name} was edited by hand, run make vectors")

    def test_vectors_were_written_by_the_tool_as_it_is_now(self):
        manifest = json.loads((VECTORS / "manifest.json").read_text())
        for name, expected in manifest["tool"].items():
            self.assertEqual(sha256_hex(TOOL / name), expected, f"{name} changed, run make vectors")

    def test_vectors_were_written_from_the_request_rules_as_they_are_now(self):
        manifest = json.loads((VECTORS / "manifest.json").read_text())
        self.assertEqual(manifest["requests_rules"], requests_rules_hash(), "request rules changed, run make vectors")

    def test_only_the_interaction_rules_make_vectors_stale(self):
        text = PROTOCOL.read_text()
        self.assertNotEqual(requests_rules_hash(text.replace("`disputed`", "`stopped`", 1)), requests_rules_hash(text))
        self.assertEqual(requests_rules_hash(text.replace("## Host API", "## Hosts")), requests_rules_hash(text))


class Unsigned:
    """Stands in for the signature layer, and checks only each object's type."""

    def __call__(self, compact: str, _key, typ: str) -> bytes:
        header = decoded(compact.split(".")[0])
        if header != {"alg": "ES256", "typ": typ}:
            raise ValueError("wrong type")
        return self.payload(compact)

    @staticmethod
    def payload(compact: str) -> bytes:
        segment = compact.split(".")[1]
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))

    def message_id(self, compact: str) -> str:
        return hashlib.sha256(self.payload(compact)).hexdigest()


UNSIGNED = Unsigned()


def turns_on_a_signature(vector: dict) -> bool:
    return vector["expect"].get("reason") in TURNS_ON_A_SIGNATURE or vector["name"] in ONLY_A_SIGNATURE_DIFFERS


def parties_of(given: dict) -> dict:
    requester, recipient = given["requester"], given["recipient"]
    parties = {"R": {"id": requester["agent_id"], "owner": requester["owner_id"], "key": None, "owner_key": None}}
    if "guest_id" in recipient:
        parties["T"] = {"id": recipient["guest_id"], "owner": recipient["guest_id"], "guest": True, "identity": recipient["guest_identity"], "key": None}
    else:
        parties["T"] = {"id": recipient["agent_id"], "owner": recipient["owner_id"], "key": None, "owner_key": None}
    return parties


def chain_vectors():
    for name in CHAIN_FILES:
        for vector in json.loads((VECTORS / name).read_text())["vectors"]:
            if "chain" in vector["input"] and not turns_on_a_signature(vector):
                yield vector


def walked(vector: dict, chain: list[str], arrived: bool = True) -> dict:
    given = vector["input"]
    last_arrived_at = given.get("last_arrived_at") if arrived else None
    return walk_chain(parties_of(given), chain, given["now"], UNSIGNED, last_arrived_at, given.get("schemas", ()))


class ChainVectors(unittest.TestCase):
    """The reference walk runs here too, so the spec's rules can't quietly stop holding."""

    def named(self, name: str) -> dict:
        return next(vector for vector in chain_vectors() if vector["name"] == name)

    def test_a_flood_cant_block_what_decides_the_result(self):
        for name, state in [
            ("recipient_flood_of_cancels_then_the_final_confirm", "completed"),
            ("requester_flood_of_cancels_then_the_final_confirm", "completed"),
            ("flood_of_received_then_the_final_confirm", "completed"),
            ("flood_of_cancels_then_an_approved_cancel", "cancelled"),
            ("a_forward_flood_cant_block_the_final_confirm", "completed"),
        ]:
            vector = self.named(name)
            # With the last step held back, the flood alone mustn't reach this result.
            without_the_decider = walked(vector, vector["input"]["chain"][:-1])
            self.assertNotEqual(without_the_decider["state"], state, name)
            self.assertEqual(walked(vector, vector["input"]["chain"])["state"], state, name)

    def test_a_flood_of_cancels_leaves_one_held(self):
        vector = self.named("recipient_flood_of_cancels_then_the_final_confirm")
        reader = Chain(parties_of(vector["input"]), UNSIGNED)
        for compact in vector["input"]["chain"]:
            reader.apply(compact)
        self.assertEqual(len(reader.cancels), 1)

    def test_a_flood_of_received_leaves_one_held(self):
        vector = self.named("flood_of_received_then_the_final_confirm")
        reader = Chain(parties_of(vector["input"]), UNSIGNED)
        for compact in vector["input"]["chain"]:
            reader.apply(compact)
        self.assertEqual(len(reader.received), 1)

    def test_every_approved_cancel_is_held(self):
        vector = self.named("both_owners_cancel_a_booking")
        reader = Chain(parties_of(vector["input"]), UNSIGNED)
        for compact in vector["input"]["chain"]:
            reader.apply(compact)
        self.assertEqual(len(reader.approved_cancels), 2)

    def test_the_forward_cap_is_per_signer_and_refuses_only_past_it(self):
        vector = self.named("too_many_forward_steps")
        reader = Chain(parties_of(vector["input"]), UNSIGNED)
        chain = vector["input"]["chain"]
        for compact in chain[:-1]:
            reader.apply(compact)
        self.assertEqual(reader.forward_held, {"R": 1, "T": MAX_FORWARD_STEPS})
        with self.assertRaises(Refused) as refused:
            reader.apply(chain[-1])
        self.assertEqual(refused.exception.reason, "too_many_steps")

def tracked_text_files() -> list[Path]:
    listed = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.splitlines()
    return [Path(name) for name in listed if Path(name).suffix in TEXT_SUFFIXES or Path(name).name == "Makefile"]


class DocPaths(unittest.TestCase):
    def test_relative_links_resolve(self):
        for document in (path for path in tracked_text_files() if path.suffix == ".md"):
            for target in LINK.findall(document.read_text()):
                if not target.startswith(("http", "mailto:")):
                    self.assertTrue((document.parent / target).exists(), f"{document}: {target}")

    def test_every_doc_path_named_in_the_repo_exists(self):
        # Links are held above. A path named in a comment or in prose only warns.
        for document in tracked_text_files():
            for named in DOC_PATH.findall(document.read_text()):
                warn(Path(named).exists(), f"{document} names {named}, which isn't there")

    def test_the_path_check_sees_a_path_in_a_comment(self):
        gone = "spec" + "/gone.md"
        self.assertEqual(DOC_PATH.findall(f"//! See `{gone}`."), [gone])

    def test_core_names_no_type_outside_its_tests(self):
        """A type is a schema, so core has no type's name or field in it, and can't grow one by accident."""
        names = [name for name in ("meeting", "slots", "duration_min", "booking", "calendar", "quote/1", "chat/1", "document/1")]
        for path in sorted(Path("packages/splint-core/src").rglob("*.rs")):
            if path.name in ("spec_vectors.rs", "link_tests.rs"):  # These whole files run the example types in tests.
                continue
            code = path.read_text().split("#[cfg(test)]")[0]
            for name in names:
                self.assertFalse(name in code.lower(), f"{path} names {name}")


if __name__ == "__main__":
    unittest.main()

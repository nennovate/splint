#!/usr/bin/env python3
"""Fails if CI's shards stop adding up to what make runs, as a dropped sim would otherwise pass unseen."""

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "ci"))

import shards  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "check.yml"
CORE_MAKEFILE = ROOT / "make" / "core.mk"
# What `make check` runs that isn't the end-to-end half, which CI's check job runs.
FAST_HALF = {"rules", "rust", "deps", "verifier"}
# Without these the workflow could run fewer shards than the plan splits the sims across.
WORKFLOW_MUST_SAY = (
    "tools/ci/shards.py matrix",
    "fromJSON(needs.plan.outputs.shards)",
    "tools/ci/shards.py run ${{ matrix.shard }}",
)


def check_targets() -> list[str]:
    found = re.search(r"^check:(.*)$", CORE_MAKEFILE.read_text(), re.MULTILINE)
    suites = set(found.group(1).split()) - FAST_HALF if found else set()
    if suites != set(shards.TARGETS):
        return [f"make check runs {sorted(suites)}, but the shards cover {sorted(shards.TARGETS)}"]
    return []


def check_plan(made: list[str], count: int) -> list[str]:
    """Compares the lists the shards run with make's own lines, apart from how the plan sorts them."""
    wanted = Counter(sim for line in made for sim in re.findall(r"\bsim/\w+\.py\b", line))
    if not wanted:
        return ["make would run no sims, so the plan can't be checked"]
    problems = [f"make runs {sim} {times} times" for sim, times in wanted.items() if times > 1]
    commands = shards.classify(made)
    runs = [shards.shard_commands(commands, number, count) for number in range(1, count + 1)]
    on_shards = Counter(command for run in runs for command in set(run))
    on_every_shard = [shards.PROGRAMS, *commands.setup]
    problems += [f"no shard runs `{line}`" for line in dict.fromkeys(made) if line not in on_shards]
    problems += [f"a shard runs `{line}`, but make doesn't" for line in on_shards if line not in {*made, shards.PROGRAMS}]
    problems += [f"more than one shard runs `{line}`" for line, times in on_shards.items() if times > 1 and line not in on_every_shard]
    problems += [f"shard {number} skips what every shard runs first" for number, run in enumerate(runs, 1)
                 if run[:len(on_every_shard)] != on_every_shard]
    return problems


def check_workflow() -> list[str]:
    text = WORKFLOW.read_text()
    return [f"{WORKFLOW.relative_to(ROOT)} no longer says `{words}`" for words in WORKFLOW_MUST_SAY if words not in text]


def main() -> int:
    try:
        problems = check_targets() + check_plan(shards.make_commands(), shards.SHARD_COUNT) + check_workflow()
    except shards.PlanError as problem:
        problems = [str(problem)]
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

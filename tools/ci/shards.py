#!/usr/bin/env python3
"""Splits the end-to-end suites across CI runners, from what make itself would run.

    python3 tools/ci/shards.py plan      what each shard runs, and about how long it takes
    python3 tools/ci/shards.py matrix    the shard numbers, for the workflow's matrix
    python3 tools/ci/shards.py build     builds what the shards share, so the cache holds it
    python3 tools/ci/shards.py run 3     runs shard 3

The commands come from `make -n`, so a sim added to a make target is picked up with no second list.
tools/checks/check_ci_shards.py fails `make rules` if the shards ever stop adding up to what make runs.

No sims are pinned together. Each makes its own ports, database and scratch folders, and a shard is a
machine of its own. The one thing a sim took from those before it was the debug programs, which some
use without building, so every shard builds them first. Within a shard, sims keep make's order.

A sim that fails on a shard runs once more. One that fails twice fails the shard. One that then passes
was caught by timing on that machine, not by a bug that's always there: the shard passes, and the run
carries a warning naming the sim, so it gets fixed rather than costing every shard a second run.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ("e2e", "test-adapter", "test-install", "test-owner-page")

# The longest sim, host_gone, takes over 10 minutes alone, so no number of shards beats that, and nine
# come out at about 11 minutes each. A shard spends under a minute starting up, so fewer would save little.
SHARD_COUNT = 9

SIM = re.compile(r"python3 sim/(\w+)\.py")
MENTIONS_SIM = re.compile(r"\bsim/\w+\.py\b")

# The debug programs, built exactly as the sims build them, so their own builds find nothing to do.
PROGRAMS = "cd packages && cargo build --quiet -p host -p signet -p owner-key -p splint"
# All that the sims compile, for the cache: the debug programs, the release ones `make install` builds,
# the examples some sims sign with, and the release tests `make e2e` starts with.
SHARED_BUILDS = (
    PROGRAMS,
    "cd packages && cargo build --quiet --locked --profile release -p splint -p host -p signet -p owner-key",
    "cd packages && cargo build --quiet -p splint-core --examples",
    "cd packages && cargo test --release --quiet -p splint-core --lib --no-run",
)

# What the commands that aren't sims add to the first shard, which runs the ones that run once.
ONCE_SECONDS = 90
# For a sim not in the table yet. It only affects how evenly the shards come out.
DEFAULT_SECONDS = 120
# Seconds on the 2-core runners CI uses, from one full run's job logs. The balance needs them only roughly.
SECONDS = {
    "adapter": 16,
    "agent_asks": 126,
    "agent_join": 255,
    "agent_signup": 261,
    "agreed_time": 47,
    "asked_by_link": 106,
    "change_notices": 50,
    "cleanup_check": 6,
    "colluders": 98,
    "contact_rules": 59,
    "delegation": 109,
    "direct_access": 120,
    "e2e": 112,
    "fooled_agent": 25,
    "grants": 6,
    "guest_link": 107,
    "hanging_up": 11,
    "host_closing": 16,
    "host_gone": 633,
    "host_id": 23,
    "host_limits": 137,
    "host_operator": 18,
    "hostile_home_host": 35,
    "identity_recovery": 48,
    "install": 100,
    "invites": 74,
    "join_with_code": 19,
    "kept_listener": 27,
    "key_safety": 104,
    "listening": 273,
    "lost_key_files": 290,
    "managed_requests": 203,
    "open_federation": 90,
    "outbound_text": 14,
    "owner_api": 78,
    "owner_control": 22,
    "owner_controls": 62,
    "owner_device": 495,
    "owner_keys": 52,
    "owner_mail_sealed": 56,
    "owner_page": 317,
    "owner_page_here": 196,
    "payments": 17,
    "peers_file": 100,
    "profiles": 37,
    "proxied_agents": 24,
    "reach_and_permissions": 44,
    "readable_records": 43,
    "retire_agent": 84,
    "rules_at_host": 66,
    "sealed": 80,
    "sent_mail": 15,
    "shell_agent": 32,
    "switch_host": 218,
    "tls_rules": 18,
    "unopened_mail": 120,
    "waiting": 122,
}


class PlanError(Exception):
    """make would run something this can't place, so a shard might leave it out."""


@dataclass(frozen=True)
class Commands:
    setup: tuple[str, ...]  # On every shard, before anything else.
    once: tuple[str, ...]  # On the first shard only.
    sims: tuple[str, ...]  # Each on exactly one shard.


def make_commands() -> list[str]:
    """What make would run, in its order. Run under make, its own flags are left out of this one."""
    env = {name: value for name, value in os.environ.items() if name not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    made = subprocess.run(
        ["make", "-n", "--no-print-directory", *TARGETS], cwd=ROOT, env=env, capture_output=True, text=True, check=True,
    )
    return [line.strip() for line in made.stdout.splitlines() if line.strip()]


def classify(commands: list[str]) -> Commands:
    """`npm ci` is what later commands need, so every shard runs the lines that hold it."""
    setup, once, sims = [], [], []
    for command in dict.fromkeys(commands):
        if SIM.fullmatch(command):
            sims.append(command)
        elif MENTIONS_SIM.search(command):
            raise PlanError(f"a sim must be a line of its own, as `python3 sim/name.py`: {command}")
        elif "npm ci" in command:
            setup.append(command)
        else:
            once.append(command)
    return Commands(tuple(setup), tuple(once), tuple(sims))


def name_of(sim: str) -> str:
    found = SIM.fullmatch(sim)
    if not found:
        raise PlanError(f"not a sim: {sim}")
    return found.group(1)


def seconds_of(sim: str) -> int:
    return SECONDS.get(name_of(sim), DEFAULT_SECONDS)


def split(sims: tuple[str, ...], count: int) -> list[list[str]]:
    """Longest first, each onto the shard with the least so far. Each shard keeps make's order."""
    shards: list[list[str]] = [[] for _ in range(count)]
    loads = [ONCE_SECONDS, *[0] * (count - 1)]
    for sim in sorted(sims, key=lambda sim: (-seconds_of(sim), sim)):
        lightest = min(range(count), key=lambda shard: (loads[shard], shard))
        shards[lightest].append(sim)
        loads[lightest] += seconds_of(sim)
    return [sorted(shard, key=sims.index) for shard in shards]


def load_of(shard: list[str], number: int) -> int:
    return sum(seconds_of(sim) for sim in shard) + (ONCE_SECONDS if number == 1 else 0)


def print_plan(count: int) -> None:
    commands = classify(make_commands())
    shards = split(commands.sims, count)
    total = sum(load_of(shard, number) for number, shard in enumerate(shards, 1))
    print(f"{len(commands.sims)} sims on {count} shards, {total / 60:.0f} minutes of running in all")
    print("\nEvery shard first runs:")
    for command in (PROGRAMS, *commands.setup):
        print(f"  {command}")
    print("\nThe first shard also runs:")
    for command in commands.once:
        print(f"  {command}")
    print()
    for number, shard in enumerate(shards, 1):
        names = [name_of(sim) + ("" if name_of(sim) in SECONDS else "*") for sim in shard]
        print(f"shard {number:>2}  {load_of(shard, number) / 60:5.1f} min  {' '.join(names)}")
    if any(name_of(sim) not in SECONDS for sim in commands.sims):
        print(f"\n* not measured yet, so counted as {DEFAULT_SECONDS} seconds")


def run_one(command: str) -> bool:
    print(f"\n=== {command}", flush=True)
    started = time.monotonic()
    code = subprocess.run(command, shell=True, cwd=ROOT).returncode
    result = "PASS" if code == 0 else f"FAIL (exit {code})"
    print(f"--- {result} {command} ({time.monotonic() - started:.0f}s)", flush=True)
    return code == 0


def run_all(commands: list[str], heading: str, again: bool = False) -> int:
    """Runs every command even after one fails, so one run shows everything that's wrong. With `again`,
    a sim that fails runs once more, and one that then passes is warned of rather than failed."""
    failed, flaky = [], []
    for command in commands:
        if run_one(command):
            continue
        if again and SIM.fullmatch(command) and run_one(command):
            flaky.append(command)
        else:
            failed.append(command)
    print(f"\n{heading}: {len(commands) - len(failed)} passed, {len(failed)} failed", flush=True)
    for command in flaky:
        # GitHub shows a line that starts this way as a warning on the run and beside the PR's checks.
        print(f"::warning title=Passed only when run again::{command} failed, then passed when run again, so it depends on timing", flush=True)
    for command in failed:
        print(f"FAILED {command}", flush=True)
    return 1 if failed else 0


def shard_commands(commands: Commands, number: int, count: int) -> list[str]:
    """All that a shard runs, in order. tools/checks/check_ci_shards.py checks this very list."""
    once = commands.once if number == 1 else ()
    return [PROGRAMS, *commands.setup, *once, *split(commands.sims, count)[number - 1]]


def run_shard(number: int, count: int) -> int:
    return run_all(shard_commands(classify(make_commands()), number, count), f"Shard {number} of {count}", again=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Splits the end-to-end suites across CI runners.")
    parser.add_argument("--of", type=int, default=SHARD_COUNT, help="how many shards to split into")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("plan")
    actions.add_parser("matrix")
    actions.add_parser("build")
    actions.add_parser("run").add_argument("shard", type=int)
    arguments = parser.parse_args()
    if arguments.of < 1:
        parser.error("--of must be at least 1")
    if arguments.action == "plan":
        print_plan(arguments.of)
    elif arguments.action == "matrix":
        print(json.dumps(list(range(1, arguments.of + 1))))
    elif arguments.action == "build":
        return run_all(list(SHARED_BUILDS), "Shared build")
    elif not 1 <= arguments.shard <= arguments.of:
        parser.error(f"shard must be from 1 to {arguments.of}")
    else:
        return run_shard(arguments.shard, arguments.of)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PlanError as problem:
        print(problem, file=sys.stderr)
        sys.exit(2)

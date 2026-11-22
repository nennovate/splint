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

# A private repository's runners have 2 cores, and each shard spends about 4 minutes starting up. The
# longest sim, owner_device, takes over 7 minutes alone, so no number of shards beats that.
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
# Seconds on a hosted 2-core runner, from the job logs. The balance needs them only roughly.
SECONDS = {
    "adapter": 22,
    "agent_asks": 154,
    "agent_join": 336,
    "agent_signup": 311,
    "asked_by_link": 57,
    "change_notices": 64,
    "cleanup_check": 12,
    "colluders": 190,
    "contact_rules": 74,
    "delegation": 111,
    "direct_access": 144,
    "e2e": 121,
    "fooled_agent": 34,
    "grants": 8,
    "guest_link": 114,
    "host_limits": 148,
    "hostile_home_host": 38,
    "identity_recovery": 59,
    "install": 64,
    "invites": 88,
    "key_safety": 32,
    "listening": 327,
    "managed_requests": 250,
    "outbound_text": 20,
    "owner_api": 24,
    "owner_control": 26,
    "owner_controls": 53,
    "owner_device": 442,
    "owner_keys": 64,
    "owner_mail_sealed": 72,
    "owner_page": 165,
    "payments": 21,
    "profiles": 54,
    "proxied_agents": 57,
    "reach_and_permissions": 62,
    "readable_records": 47,
    "sealed": 91,
    "shell_agent": 42,
    "tls_rules": 49,
    "waiting": 127,
    # No CI log has these yet. Timed on a Mac and scaled by the sims timed in both places, and host_id
    # allowed the time a 2-core runner takes to compile the older host it builds.
    "agreed_time": 41,
    "owner_page_here": 150,
    "hanging_up": 40,
    "host_closing": 17,
    "host_id": 190,
    "host_operator": 24,
    "join_with_code": 41,
    "kept_listener": 30,
    "open_federation": 79,
    "peers_file": 88,
    "retire_agent": 111,
    "rules_at_host": 53,
    "switch_host": 124,
    "unopened_mail": 170,
    "sent_mail": 60,
    "lost_key_files": 150,
    "host_gone": 240,
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


def run_all(commands: list[str], heading: str) -> int:
    """Runs every command even after one fails, so one run shows everything that's wrong."""
    failed = [command for command in commands if not run_one(command)]
    print(f"\n{heading}: {len(commands) - len(failed)} passed, {len(failed)} failed", flush=True)
    for command in failed:
        print(f"FAILED {command}", flush=True)
    return 1 if failed else 0


def shard_commands(commands: Commands, number: int, count: int) -> list[str]:
    """All that a shard runs, in order. tools/checks/check_ci_shards.py checks this very list."""
    once = commands.once if number == 1 else ()
    return [PROGRAMS, *commands.setup, *once, *split(commands.sims, count)[number - 1]]


def run_shard(number: int, count: int) -> int:
    return run_all(shard_commands(classify(make_commands()), number, count), f"Shard {number} of {count}")


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

#!/usr/bin/env python3
"""Decides which end-to-end sims a change needs, splits them across CI runners, and runs a runner's share.

    python3 tools/ci/shards.py plan                    what each shard runs, and about how long it takes
    python3 tools/ci/shards.py needed BASE HEAD        what a change needs, as lines for the workflow
    python3 tools/ci/shards.py build                   builds what the shards share, so the cache holds it
    python3 tools/ci/shards.py run 3 --of 5            runs shard 3 of 5

The commands come from `make -n`, so a sim added to a make target is picked up with no second list.
tools/checks/check_ci_shards.py fails `make rules` if the shards ever stop adding up to what make runs.

Which sims a change needs: every one, for a change to product code, to what builds or installs it, or
to this. For a change to files in sim/ alone, only the sims that could run that file: the sim itself,
and every sim that imports it or names it. Nothing else can reach it, so nothing else is run.

A shard runs several sims at once, one for each core. Two thirds of a sim's time is spent waiting on
real timers, a retry or a poll, so run one at a time a machine sits idle. Each sim makes its own ports,
database and scratch folders, and none are pinned together. The one thing a sim took from those before
it was the debug programs, which some use without building, so every shard builds them first.

A sim that fails runs once more, alone, after the rest. One that fails twice fails the shard. One that
then passes was caught by timing on that machine, not by a bug that's always there: the shard passes,
and the run carries a warning naming the sim, so it gets fixed rather than costing a second run.
"""

import argparse
import ast
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIMS = ROOT / "sim"
TARGETS = ("e2e", "test-adapter", "test-install", "test-owner-page")

# The most shards a run takes. The longest sim, host_gone, takes over 10 minutes alone, so no number
# of shards finishes sooner than that, and a shard is given about that much to do on each core.
SHARD_COUNT = 9
SHARD_SECONDS = 660

SIM = re.compile(r"python3 sim/(\w+)\.py")
MENTIONS_SIM = re.compile(r"\bsim/\w+\.py\b")

# A change to any of these runs every sim: product code, what builds or installs it, the two docs the
# sims follow or ship, the folders under sim/, and the workflow and this, so a change to CI is always
# tested by the CI it makes. A moved file counts where it was and where it went.
EVERY_SIM = re.compile(
    r"^(packages|adapters|deploy|make|spec|tools/ci|sim/[^/]+)/|^docs/(agents|getting-started)\.md$"
    r"|^Makefile$|^\.github/workflows/check\.yml$"
)
ONE_SIM_FILE = re.compile(r"^sim/([^/]+)$")
# What Windows builds: its four crates, the workspace's own files, the schemas built into them and how
# git writes their files out. The host runs on Linux and nothing depends on it, so it isn't one.
WINDOWS = re.compile(
    r"^packages/(splint-core|signet|splint|owner-key)/|^packages/[^/]+$|^spec/|^\.gitattributes$"
    r"|^\.github/workflows/check\.yml$"
)

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
    once: tuple[str, ...]  # On the first shard only, when every sim runs.
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


def reaches(folder: Path = SIMS) -> dict[str, set[str]]:
    """For each Python file in sim/, the files in sim/ it could run: those it imports, and those it
    names in a string, as one sim starts another as a program or reads a script beside it. Then theirs,
    and so on. A file named only in a comment or a docstring isn't run, so it doesn't count."""
    files = sorted(path.name for path in folder.iterdir() if path.is_file())
    direct: dict[str, set[str]] = {}
    for name in files:
        if not name.endswith(".py"):
            continue
        tree = ast.parse((folder / name).read_text())
        described = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                      if isinstance(node, described) and node.body and isinstance(node.body[0], ast.Expr)}
        found = set()
        for node in ast.walk(tree):
            modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else []
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            found |= {f"{module}.py" for module in modules if f"{module}.py" in files}
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                found |= {word.rsplit("/", 1)[-1] for word in node.value.split()} & set(files)
        direct[name] = found - {name}
    reached: dict[str, set[str]] = {}
    for name in direct:
        seen, queue = set(), [name]
        while queue:
            for other in direct.get(queue.pop(), ()):
                if other not in seen:
                    seen.add(other)
                    queue.append(other)
        reached[name] = seen
    return reached


def sims_for(changed: list[str], sims: tuple[str, ...], reached: dict[str, set[str]]) -> tuple[str, ...]:
    """The sims a change needs, in make's order. None, when it touches nothing a sim could run."""
    if any(EVERY_SIM.search(path) for path in changed):
        return sims
    touched = {found.group(1) for path in changed if (found := ONE_SIM_FILE.match(path))}
    if not touched:
        return ()
    return tuple(sim for sim in sims
                 if (file := f"{name_of(sim)}.py") in touched or reached.get(file, set()) & touched)


def at_once() -> int:
    """How many sims a machine runs side by side: one for each core, and no more than four."""
    return max(1, min(4, os.cpu_count() or 1))


def count_for(sims: tuple[str, ...], side_by_side: int) -> int:
    """As few shards as give each about SHARD_SECONDS of sims on each core."""
    total = sum(seconds_of(sim) for sim in sims)
    return max(1, min(SHARD_COUNT, math.ceil(total / (SHARD_SECONDS * side_by_side))))


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


def print_plan(count: int | None, side_by_side: int) -> None:
    commands = classify(make_commands())
    count = count or count_for(commands.sims, side_by_side)
    shards = split(commands.sims, count)
    total = sum(load_of(shard, number) for number, shard in enumerate(shards, 1))
    print(f"{len(commands.sims)} sims on {count} shards, {side_by_side} at once on each, {total / 60:.0f} minutes of running in all")
    print("\nEvery shard first runs:")
    for command in (PROGRAMS, *commands.setup):
        print(f"  {command}")
    print("\nThe first shard also runs:")
    for command in commands.once:
        print(f"  {command}")
    print()
    for number, shard in enumerate(shards, 1):
        names = [name_of(sim) + ("" if name_of(sim) in SECONDS else "*") for sim in shard]
        longest = max((seconds_of(sim) for sim in shard), default=0)
        about = max(longest, load_of(shard, number) / side_by_side)
        print(f"shard {number:>2}  about {about / 60:4.1f} min  {' '.join(names)}")
    if any(name_of(sim) not in SECONDS for sim in commands.sims):
        print(f"\n* not measured yet, so counted as {DEFAULT_SECONDS} seconds")


def changed_files(base: str, head: str) -> list[str]:
    """A diff that fails stops the plan, rather than passing as a change that needs nothing."""
    diff = subprocess.run(
        ["git", "diff", "--no-renames", "--name-only", f"{base}...{head}"], cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return [line for line in diff.stdout.splitlines() if line]


def print_needed(changed: list[str] | None, draft: bool) -> None:
    """Lines for the workflow's plan: whether Windows runs, which sims, and on how many shards. With
    no list of changes, as on `main` after a merge, everything runs."""
    every = classify(make_commands()).sims
    if draft:
        sims, windows = (), False
    elif changed is None:
        sims, windows = every, True
    else:
        sims = sims_for(changed, every, reaches())
        windows = any(WINDOWS.search(path) for path in changed)
    side_by_side = at_once()
    count = count_for(sims, side_by_side) if sims else 0
    names = "" if sims == every else " ".join(name_of(sim) for sim in sims)
    print(f"windows={str(windows).lower()}")
    print(f"e2e={str(bool(sims)).lower()}")
    print(f"sims={names}")
    print(f"count={count}")
    print(f"shards={json.dumps(list(range(1, count + 1)))}")
    said = "every sim" if sims == every else f"{len(sims)} of {len(every)} sims: {names}" if sims else "no sims"
    where = f", on {count} shard{'s' if count != 1 else ''}, {side_by_side} at once" if sims else ""
    print(f"{'A draft, so only the quick checks. ' if draft else ''}Windows: {windows}. Suites: {said}{where}.", file=sys.stderr)


def run_one(command: str) -> bool:
    print(f"\n=== {command}", flush=True)
    started = time.monotonic()
    code = subprocess.run(command, shell=True, cwd=ROOT).returncode
    result = "PASS" if code == 0 else f"FAIL (exit {code})"
    print(f"--- {result} {command} ({time.monotonic() - started:.0f}s)", flush=True)
    return code == 0


def run_kept(command: str) -> bool:
    """One of several running at once, so what it prints is kept and shown whole when it ends. A pass
    is folded away in GitHub's log, and a failure is left open."""
    started = time.monotonic()
    with tempfile.TemporaryFile() as kept:
        code = subprocess.run(command, shell=True, cwd=ROOT, stdout=kept, stderr=subprocess.STDOUT).returncode
        kept.seek(0)
        printed = kept.read().decode(errors="replace")
    result = "PASS" if code == 0 else f"FAIL (exit {code})"
    opening, closing = (f"::group::{command}", "::endgroup::") if code == 0 else (f"=== {command}", "")
    print(f"\n{opening}\n{printed}\n{closing}\n--- {result} {command} ({time.monotonic() - started:.0f}s)", flush=True)
    return code == 0


def run_all(commands: list[str], heading: str, side_by_side: int = 1, again: bool = False) -> int:
    """Runs every command even after one fails, so one run shows everything that's wrong. What isn't a
    sim runs first, in order. Sims then run `side_by_side`, longest first. With `again`, a sim that
    failed runs once more when the rest are done, alone, and one that then passes is warned of."""
    first = [command for command in commands if not SIM.fullmatch(command)]
    sims = [command for command in commands if SIM.fullmatch(command)]
    failed = [command for command in first if not run_one(command)]
    if side_by_side > 1:
        ordered = sorted(sims, key=lambda sim: -seconds_of(sim))
        with ThreadPoolExecutor(max_workers=side_by_side) as pool:
            tripped = [sim for sim, passed in zip(ordered, pool.map(run_kept, ordered)) if not passed]
    else:
        tripped = [sim for sim in sims if not run_one(sim)]
    flaky = [sim for sim in tripped if again and run_one(sim)]
    failed += [sim for sim in tripped if sim not in flaky]
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


def run_shard(number: int, count: int, only: list[str], side_by_side: int) -> int:
    """With `only`, a change that needs some sims: just those, and not what runs once for them all."""
    commands = classify(make_commands())
    if only:
        unknown = set(only) - {name_of(sim) for sim in commands.sims}
        if unknown:
            raise PlanError(f"make runs no sim called {', '.join(sorted(unknown))}")
        commands = Commands(commands.setup, (), tuple(sim for sim in commands.sims if name_of(sim) in only))
    return run_all(shard_commands(commands, number, count), f"Shard {number} of {count}", side_by_side, again=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Decides which sims a change needs, and runs a CI runner's share of them.")
    actions = parser.add_subparsers(dest="action", required=True)
    plan = actions.add_parser("plan")
    plan.add_argument("--of", type=int, help="how many shards to split into, rather than as few as fit")
    plan.add_argument("--at-once", type=int, default=at_once(), help="how many sims a shard runs side by side")
    needed = actions.add_parser("needed")
    needed.add_argument("base", nargs="?")
    needed.add_argument("head", nargs="?")
    needed.add_argument("--draft", action="store_true", help="a draft PR, which runs no sims")
    actions.add_parser("build")
    run = actions.add_parser("run")
    run.add_argument("shard", type=int)
    run.add_argument("--of", type=int, default=SHARD_COUNT, help="how many shards the sims are split into")
    run.add_argument("--sims", default="", help="the only sims to run, by name, when a change needs some")
    run.add_argument("--at-once", type=int, default=at_once(), help="how many sims to run side by side")
    arguments = parser.parse_args()
    if arguments.action == "plan":
        print_plan(arguments.of, arguments.at_once)
    elif arguments.action == "needed":
        if bool(arguments.base) != bool(arguments.head):
            parser.error("give both commits, or neither to run everything")
        print_needed(changed_files(arguments.base, arguments.head) if arguments.base else None, arguments.draft)
    elif arguments.action == "build":
        return run_all(list(SHARED_BUILDS), "Shared build")
    elif not 1 <= arguments.shard <= arguments.of:
        parser.error(f"shard must be from 1 to {arguments.of}")
    else:
        return run_shard(arguments.shard, arguments.of, arguments.sims.split(), max(1, arguments.at_once))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PlanError as problem:
        print(problem, file=sys.stderr)
        sys.exit(2)

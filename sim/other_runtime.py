#!/usr/bin/env python3
"""The catering quote from sim/realistic_agents.py, with a runtime that isn't the one the rest of the
tests use: Codex, started fresh on a schedule, reaching its Signet over plain HTTP with curl. Nothing in
packages/ or adapters/ knows it's there. It reads what the HTTP adapter's note and the protocol say, as any
program could.

    SPLINT_CODEX=/path/to/codex python3 sim/other_runtime.py

Uses model usage on whichever account that runtime is logged in to, so it isn't part of `make check`. Each
agent runs in the runtime's workspace-write sandbox with network access, on this machine. Not shown: an
open-weight model, or a network limit on the agent.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import e2e
import request_driver
from e2e import check, wait_until
from reach_and_permissions import sign_and_put
from realistic_agents import BUDGET_MINOR, EXPECTED_QUOTE, RUNS, SETTLED, Agents, Wake, both_sides_completed, newest, run_until_settled


ROOT = Path(__file__).resolve().parent.parent
CODEX = os.environ.get("SPLINT_CODEX", "codex")
WAKE_SECONDS = 240
TASK = "Ana: please get a catering quote from Ben's Kitchen for the Harbor dinner. Details are in event-brief.md. If it's inside budget, take it."
PERMISSIONS = {"level": "auto_within_limits", "actions_per_day": 500, "caps": {"quote/1": {"amount_minor.usd": BUDGET_MINOR}}}


def signet_calls() -> str:
    """The part of the protocol an agent uses, as it's written for anyone."""
    text = (ROOT / "docs" / "protocol.md").read_text()
    return text[text.index("## Signet API") : text.index("### Owner calls")]


class CodexAgents(Agents):
    def __init__(self, net: e2e.Network, out: Path, now: datetime) -> None:
        super().__init__(net, out, now, "not-a-secret-here")
        connect = (ROOT / "adapters" / "http" / "connect.txt").read_text()
        for agent, folder in self.dirs.items():
            curl = folder.parent / f"{agent}.curl"
            curl.write_text(f'header = "Authorization: Bearer {net.tokens[agent]}"\nheader = "Content-Type: application/json"\n')
            curl.chmod(0o600)
            signet = f"http://127.0.0.1:{net.signet_port[agent]}"
            note = connect.replace("{curl}", str(curl)).replace("{signet}", signet).replace("{env}", "").replace("{adapter}", "").replace("{splint}", "~/.splint/bin/splint").replace("{wake}", "")
            (folder / "splint-api.md").write_text(note + "\n\n" + signet_calls())
            words = (folder / "CLAUDE.md").read_text()
            (folder / "AGENTS.md").write_text(words + "\nThe splint tools are its HTTP calls: splint-api.md says how, with curl.\n")
            (folder / "CLAUDE.md").unlink()

    def wake(self, agent: str, interaction: str, prompt: str, why: str) -> Wake:
        wake = Wake(agent, interaction, why)
        print(f"  [waking {agent}: {why}]", flush=True)
        command = [
            CODEX, "exec", "--json", "--skip-git-repo-check", "--sandbox", "workspace-write",
            "-c", "sandbox_workspace_write.network_access=true", "-c", "model_reasoning_effort=low", prompt,
        ]
        try:
            done = subprocess.run(command, cwd=self.dirs[agent], capture_output=True, text=True, timeout=WAKE_SECONDS, stdin=subprocess.DEVNULL, check=False)
        except subprocess.TimeoutExpired:
            wake.failed = "timed out"
            self.wakes.append(wake)
            return wake
        for line in done.stdout.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("type") == "turn.completed":
                usage = event.get("usage", {})
                wake.fresh += usage.get("input_tokens", 0) - usage.get("cached_input_tokens", 0)
                wake.cache_read += usage.get("cached_input_tokens", 0)
                wake.output += usage.get("output_tokens", 0)
            item = event.get("item", {})
            if event.get("type") == "item.completed" and item.get("type") == "agent_message":
                wake.said = item.get("text", "")
            if event.get("type") == "item.completed" and item.get("type") == "command_execution":
                print(f"    {agent} ran {re.sub(chr(10), ' ', item.get('command', ''))[:220]}", flush=True)
        if done.returncode != 0:
            wake.failed = f"exited {done.returncode}: {done.stderr[-300:]}"
        self.wakes.append(wake)
        print(f"    {agent} says: {' '.join(wake.said.split())[:300]} {wake.failed}", flush=True)
        return wake


def main() -> int:
    if shutil.which(CODEX) is None:
        print("this needs a Codex CLI, logged in: set SPLINT_CODEX to it", file=sys.stderr)
        return 2
    e2e.build()
    out = RUNS / f"{datetime.now(UTC):%Y%m%d-%H%M%S}-other-runtime"
    out.mkdir(parents=True)
    (out / "wakes.jsonl").touch()
    with e2e.running_network(owned=True) as net:
        agents = CodexAgents(net, out, datetime.now(UTC))
        for agent, other in (("ana", "ben"), ("ben", "ana")):
            sign_and_put(net, agent, [{**net.contact_entry(other, text=False), "types": ["quote/1"]}], permissions=PERMISSIONS if agent == "ana" else {**PERMISSIONS, "caps": {}})
        told: dict[str, set] = {"ana": set(), "ben": set()}
        agents.wake("ana", "job", TASK, "owner's task")

        def settled() -> bool:
            found = newest(net, "ana", "quote/1", set())
            return bool(found) and found["state"] in SETTLED

        run_until_settled(net, agents, "job", told, {}, settled)
        found = newest(net, "ana", "quote/1", set())
        check("the agents opened a quote", bool(found), net.agent("ana", "GET", "/v0/requests")[1])
        if found:
            request = found["request"]
            check("both sides recompute it completed, from signed steps", wait_until(lambda: both_sides_completed(net, request)), request_driver.view(net, "ana", request))
            result = request_driver.view(net, "ana", request).get("result", {})
            check("for the amount on Ben's price list", result.get("amount_minor") == EXPECTED_QUOTE, result)
        tokens = sum(wake.context + wake.output for wake in agents.wakes)
        print(f"\n{len(agents.wakes)} wakes, {tokens:,} tokens.", flush=True)
    print("all checks passed" if e2e.failures == 0 else f"{e2e.failures} checks failed", flush=True)
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""The same job done with compact typed messages and with plain sentences, by real agents, to see whether
compact ones reach a correct result as often, and what each costs.

The job is a catering quote, as in sim/realistic_agents.py: Ana's agent gets a price from Ben's, which it
has to work out from his price list. Each run has its own hosts and folders. Compact agents may only use
quote/1. Plain ones may only use core's plain conversation and free text, so nothing typed is there to lean on.

    python3 sim/token_compare.py [--runs N]

Costs real model usage, capped at SPLINT_COMPARE_BUDGET_USD, 3 by default. It appends to and rewrites
sim/runs/token-compare/report.md, so a run can be split over several calls. What a model chose is only
reported. A few runs on one small job can show a difference this large, and can't show a small one.
"""

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

os.environ.setdefault("SPLINT_AGENT_MODEL", "haiku")
os.environ.setdefault("SPLINT_AGENT_BUDGET_USD", "0.6")

import e2e

from reach_and_permissions import sign_and_put
from realistic_agents import BUDGET_MINOR, EXPECTED_QUOTE, MODEL, RUNS, SETTLED, Agents, newest, run_until_settled, wake_rows

OUT = RUNS / "token-compare"
TOTAL_BUDGET_USD = float(os.environ.get("SPLINT_COMPARE_BUDGET_USD", "3"))
TASK = "Ana: please get a catering quote from Ben's Kitchen for the Harbor dinner. Details are in event-brief.md. If it's inside budget, take it."
PLAIN_TASK = TASK + " Write to Ben's agent in ordinary sentences."
ASK_AFTER = "Ana: what total did we end up with from Ben's Kitchen, in dollars?"
PERMISSIONS = {"level": "auto_within_limits", "actions_per_day": 500, "caps": {"quote/1": {"amount_minor.usd": BUDGET_MINOR}}}


def said_the_right_total(words: str) -> bool:
    digits = re.sub(r"[,\s]", "", words)
    dollars = EXPECTED_QUOTE // 100
    return f"{dollars}" in digits


def contact(net: e2e.Network, other: str, kind: str, text: bool) -> dict:
    # Core's plain conversation is no type the owner names: words are `text`.
    return {**net.contact_entry(other, text=text), "types": [kind] if kind != e2e.CHAT else []}


def one_run(mode: str) -> dict:
    compact = mode == "compact"
    kind = "quote/1" if compact else e2e.CHAT
    out = OUT / f"{datetime.now(UTC):%Y%m%d-%H%M%S}-{mode}"
    out.mkdir(parents=True)
    (out / "wakes.jsonl").touch()
    with e2e.running_network(owned=True) as net:
        agents = Agents(net, out, datetime.now(UTC), "not-a-secret-here")
        sign_and_put(net, "ana", [contact(net, "ben", kind, not compact)], permissions=PERMISSIONS)
        sign_and_put(net, "ben", [contact(net, "ana", kind, not compact)], permissions={**PERMISSIONS, "caps": {}})
        told: dict[str, set] = {"ana": set(), "ben": set()}
        agents.wake("ana", "job", TASK if compact else PLAIN_TASK, "owner's task")

        def settled() -> bool:
            found = newest(net, "ana", "quote/1", set())
            return compact and bool(found) and found["state"] in SETTLED

        run_until_settled(net, agents, "job", told, {}, settled)
        signed = None
        if compact:
            found = newest(net, "ana", "quote/1", set())
            signed = (found or {}).get("result", {}).get("amount_minor") if (found or {}).get("state") == "completed" else None
        job = [wake for wake in agents.wakes if wake.interaction == "job"]
        row = wake_rows(job)
        splint_calls = [call for wake in job for call in wake.splint_calls()]
        answer = agents.wake("ana", "after", ASK_AFTER, "owner's question")
        return {
            "model": MODEL,
            "mode": mode,
            "correct": signed == EXPECTED_QUOTE if compact else said_the_right_total(answer.said),
            "said": " ".join(answer.said.split())[:200],
            "signed_amount": signed,
            "wakes": row["wakes"],
            "model_calls": row["api_calls"],
            "splint_calls": len(splint_calls),
            "tokens_read": row["context"],
            "not_from_cache": row["uncached"],
            "written": row["output"],
            "splint_share": row["splint_tokens"],
            "message_chars": sum(len(json.dumps(call["input"])) for call in splint_calls if call["name"].endswith(("__send", "__open", "__move"))),
            "cost": row["cost"],
            "all_cost": agents.spent,
        }


def report(results: list[dict]) -> str:
    lines = [
        f"One catering quote, {len(results)} runs. Correct means the signed amount, or for plain the agent's own answer, matches Ben's price list.",
        "",
        "| Model | Mode | Correct | Wakes | Model calls | Splint calls | Tokens read | Not from cache | Written | Splint's share | Message chars | Cost |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for one in results:
        lines.append(f"| {one.get('model', 'haiku')} | {one['mode']} | {'yes' if one['correct'] else 'NO'} | {one['wakes']} | {one['model_calls']} | {one['splint_calls']} | {one['tokens_read']:,} | {one['not_from_cache']:,} | {one['written']:,} | {one['splint_share']:,} | {one['message_chars']:,} | ${one['cost']:.3f} |")
    lines += ["", "Averages per job:", ""]
    for model, mode in sorted({(one.get("model", "haiku"), one["mode"]) for one in results}):
        mine = [one for one in results if one["mode"] == mode and one.get("model", "haiku") == model]
        if mine:
            right = sum(one["correct"] for one in mine)
            mean = lambda name: sum(one[name] for one in mine) / len(mine)
            lines.append(f"- {model}, {mode}: {right} of {len(mine)} correct, {mean('tokens_read'):,.0f} tokens read, {mean('not_from_cache'):,.0f} not from cache, {mean('written'):,.0f} written, {mean('message_chars'):,.0f} message characters, ${mean('cost'):.3f}.")
    lines += ["", f"Spent in all: ${sum(one['all_cost'] for one in results):.2f}, capped at ${TOTAL_BUDGET_USD:.2f}.", "", "No agent has network limits, and keys are software files. Everything ran on one machine."]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--modes", default="compact,plain")
    options = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    kept = OUT / "results.json"
    results = json.loads(kept.read_text()) if kept.exists() else []
    e2e.build()
    for _ in range(options.runs):
        for mode in options.modes.split(","):
            if sum(one["all_cost"] for one in results) >= TOTAL_BUDGET_USD - 0.6:
                print("stopping: this would go over the budget", flush=True)
                break
            print(f"\n{mode}", flush=True)
            results.append(one_run(mode))
            kept.write_text(json.dumps(results))
            (OUT / "report.md").write_text(report(results))
    print(report(results), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

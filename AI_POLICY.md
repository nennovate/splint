# Contributing with AI

Splint is built with AI. Most of its code is written by coding agents, and we expect most contributions to be written that way too. The repository is set up for it, and a few things are still yours to do.

## What the repository gives your agent

These files are written for agents, and we keep them current because we use them every day.

| File | What it's for |
|---|---|
| [`AGENTS.md`](AGENTS.md) | The rules every change follows: what Splint is and isn't, the security invariants, how the code is organised and how to test it. Most coding agents load it by themselves, and `CLAUDE.md` points Claude Code at it. |
| [`docs/how-we-build.md`](docs/how-we-build.md) | How to apply those rules: what to work on, how big a pull request should be, and which command to run for which kind of change. |
| [`docs/how-it-works.md`](docs/how-it-works.md) and [`docs/protocol.md`](docs/protocol.md) | The system as it's built today, and the formats every implementation follows. |
| [`.claude/skills/create-pr`](.claude/skills/create-pr/SKILL.md) | A skill that writes the pull request description in the form we use: before, after, how it works, trade-offs, how it was tested and key decisions. |
| [`.claude/agents/evaluator.md`](.claude/agents/evaluator.md) | A read-only reviewer that didn't write the change. It runs the code and reports anything it couldn't verify. |

## How a change is usually made

You don't have to follow these steps exactly, but each one catches a kind of mistake we've seen.

1. Start from an issue we've agreed to, so the change is one we want. [`CONTRIBUTING.md`](CONTRIBUTING.md) explains which issues are open to pull requests.
2. Before your agent writes anything, have it read `AGENTS.md` and the part of `docs/how-it-works.md` that covers what you're changing.
3. Ask for the test first: one that fails on `main` and passes with the change. `AGENTS.md` lists the kinds of test that pass whether or not the code works, and we delete those in review.
4. Run `make rules rust deps verifier` while you work, and then the end-to-end runs that cover what you changed. The table in `docs/how-we-build.md` says which.
5. Get a second opinion from a session that didn't write the change. In Claude Code, the `evaluator` agent does this. In another agent, start a fresh session and ask it to review the diff against `AGENTS.md` by running the code.
6. Read the diff yourself before you open the pull request, and ask your agent about anything you don't follow.
7. Write the pull request with the `create-pr` skill, then read it through and cut what a reviewer doesn't need. The [humanizer](https://github.com/blader/humanizer) skill helps with that last pass.

## What we ask you to do yourself

We look for these when we read a pull request or a report, and an agent can't do them for you.

- Understand the change. You should be able to tell us what it does, why it's the right fix and how it fits the rest of Splint, in your own words. We may ask during review.
- Show that it works. Include a test that fails without the change, or steps someone else can repeat, and tell us what you ran. If there was something you couldn't check, such as a platform you don't have, say so. That's useful to know, and it doesn't count against the change.
- Tell us which tool you used and what it did. One line is enough, for example "Cursor wrote the fix and its test. I read both and ran `make check`." It helps us decide where to look most carefully.
- Write the first few lines yourself. A short summary in your own words at the top of a pull request, issue or report tells us more than a long generated one. Using a model to translate or tidy your writing is fine. Please answer review questions yourself too.
- Reproduce a security report before you send it, so it shows the problem happening in Splint's own code. [`SECURITY.md`](SECURITY.md) explains how to report one privately.
- Agree to the licence terms yourself. They're in `CONTRIBUTING.md`, and an agent can't accept them for you.

## If something is missing

Reading a change carefully takes much longer than generating one. When a pull request or report arrives without the things above, we'll usually close it with a link to this page and leave the review for later. You're welcome to add what's missing and open it again.

## How we use AI ourselves

Our own changes go through the same steps, under the rules in `AGENTS.md`. An agent that didn't write the change reviews it, and how deep that review goes depends on what a mistake would cost. Changes to keys, signatures, approvals and wire formats get two reviews, one attacking the code and one trying to break its tests. Every change needs a test that fails without it, and the security invariants run on every change to product code, against an agent that is assumed to be fully fooled. Pull requests written by an agent carry the `agent: created` label, and Nenye approves every merge.

That process catches a lot, but it doesn't catch everything. [`SECURITY.md`](SECURITY.md) says where Splint stands.

Some of what we ask here is borrowed from the AI policies of [Ghostty](https://github.com/ghostty-org/ghostty/blob/main/AI_POLICY.md), [LLVM](https://llvm.org/docs/AIToolPolicy.html), [curl](https://github.com/curl/curl/blob/master/docs/CONTRIBUTE.md) and the [Model Context Protocol](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/AI_POLICY.md).

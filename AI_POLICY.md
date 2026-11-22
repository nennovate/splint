# AI policy

Splint is built with AI, and yours can be too. Most of Splint's code is written by coding agents, so we don't ask whether a model wrote your change. We ask whether anyone checked it.

Work that's been thought about gets our time. Work that hasn't is closed.

## The rules

These cover what comes into this repository from outside: pull requests, issues, discussions, comments and security reports.

- **You answer for it.** Whatever wrote it, you're its author. You can say what it changes, why that's right and how it fits the rest of Splint, without asking a model. The licence terms in [`CONTRIBUTING.md`](CONTRIBUTING.md) are yours to agree to, not your agent's.
- **It's shown working.** A test that fails without your change, or steps someone else can repeat. Say what you ran, and say what you couldn't check.
- **It's wanted.** A pull request is for an issue labelled `help wanted`. Don't point an agent at the repository and send us what it finds.
- **You write to us yourself.** The opening lines of a pull request, an issue or a report are yours, and so are your replies in review: short, and in your own words. Translating is fine. Pasting our questions into a model and posting its answer isn't.
- **You say what you used.** One line naming the tool and what it did, such as "Cursor wrote the fix and its test. I read both and ran `make check`." It tells a reviewer where to look harder, and it never counts against you. Typo fixes don't need one.
- **A report is real.** A security report shows the problem in Splint's own code, reproduced by you. A model's guess at what might be there isn't a report.

## What we close

Anything that reads as unchecked output is closed without a review:

- a change its author can't explain
- a wall of text around a small change
- a fix for a problem nobody has
- a test that passes whether or not the code works
- a report nobody reproduced

It may be closed with no explanation. If we got yours wrong, say so in a sentence and we'll look again. Someone who keeps sending them is blocked from the repository.

## Why so strict

Writing a change now takes minutes. Reviewing one takes as long as it ever did, and in Splint a mistake that gets through could let a message be forged or a key leak. Splint has one maintainer. So a contribution has to be worth more than the time it takes to review, and only its author can make it that.

None of this limits what you build on Splint, or in a fork of it. That's yours, made however you like.

## How Splint itself is built

We ask more of our own work than of yours. Most of Splint's code is written by coding agents under the rules in [`AGENTS.md`](AGENTS.md), which put security first and keep the model out of every security decision.

- **Separate agents review each change.** They didn't write it, and the review is scaled to what a mistake would cost. Changes to keys, signatures, approvals and wire formats get two reviews, one attacking the code and one trying to break its tests.
- **Every change needs tests that fail without it,** and the security invariants run on every change to product code, with a fully fooled agent.
- **Nenye approves every merge,** and nobody else can merge.
- **Pull requests written by an agent carry the `agent: created` label.**

That process catches a lot, and not everything. [`SECURITY.md`](SECURITY.md) says where Splint stands.

This page borrows from the AI policies of [Ghostty](https://github.com/ghostty-org/ghostty/blob/main/AI_POLICY.md), [LLVM](https://llvm.org/docs/AIToolPolicy.html), [curl](https://github.com/curl/curl/blob/master/docs/CONTRIBUTE.md) and the [Model Context Protocol](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/AI_POLICY.md).

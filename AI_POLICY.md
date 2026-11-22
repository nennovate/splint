# AI policy

AI help is welcome here, and saying how much you used is required.

## If you contribute

Say in the issue, pull request or report whether you used AI, and for what. For example:

> Written mostly by an AI coding agent. I checked the change and the tests myself.

Or:

> I used an AI model to understand the code, and wrote the fix myself.

Typo and spacing fixes don't need a note. Comments written by an AI need one too.

Whatever made it, you're answerable for it:

- **You understand it.** You can explain what it changes and why.
- **It's shown working.** A test, a run or steps someone else can repeat.
- **It's real.** A security report shows the problem against Splint's own code, not a guess about what might be there.

We close issues, pull requests and reports that hide AI use, or that read as unchecked AI output.

## How Splint itself is built

Most of Splint's code is written by AI coding agents, under the rules in [`AGENTS.md`](AGENTS.md). Those rules put security first and keep the model out of every security decision.

- **Separate agents review each change.** They didn't write it, and the review is scaled to what a mistake would cost. Changes to keys, signatures, approvals and wire formats get two reviews, one attacking the code and one trying to break its tests.
- **Every change needs tests that fail without it,** and the security invariants run on every change to product code, with a fully fooled agent.
- **Nenye approves every merge.**
- **Pull requests written by an agent carry the `agent: created` label.**

That process catches a lot, and not everything. [`SECURITY.md`](SECURITY.md) says where Splint stands.

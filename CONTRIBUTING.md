# Contributing

Thanks for helping. Splint is a network, so it grows mostly through what people run on it: their own agents, connectors, hosts and types of request.

## Build on Splint

You can build any of these in your own repository, without asking us or opening a pull request. Everything outside the host is under the Apache License 2.0, so what you build with it can go into any product.

| Build | Start from |
|---|---|
| Your own agent on the network | [Getting started](docs/getting-started.md) |
| A connector for an agent runtime Splint doesn't cover yet | The ones in [`adapters/`](adapters/), and [Signet's API](docs/protocol.md#signet-api) |
| A host on your own server | [Run a host](docs/run-a-host.md) |
| A type of request of your own, which two agents agree between themselves with nothing installed | [Interaction types](docs/protocol.md#interaction-types), and the examples in [`spec/schemas/`](spec/schemas/) |
| Another implementation, or a verifier | [The protocol](docs/protocol.md), and the shared vectors in [`spec/vectors/`](spec/vectors/) |

Show it in [Discussions](https://github.com/nennovate/splint/discussions/categories/show-and-tell), so other people can find it.

## Reporting issues

- For a bug, open an issue with the bug form. Steps to reproduce, logs and your own analysis of the cause help most.
- For a question or an idea, start in [Discussions](https://github.com/nennovate/splint/discussions). An idea becomes an issue once it's clear enough to build.
- For a vulnerability, don't open an issue. Follow [`SECURITY.md`](SECURITY.md), which explains how to report one privately.

Running Splint somewhere we haven't yet is useful too. [`ROADMAP.md`](ROADMAP.md) lists what hasn't been run, such as anything end to end on Windows, and the controls page in Safari and Firefox. The "Tried Splint" issue form is for telling us how it went.

## When to open a pull request, and when to fork

| You want to | What to do |
|---|---|
| Fix a typo or a wrong sentence in the docs | Open a pull request. It doesn't need an issue first. |
| Fix a bug | Open an issue with the bug form. Once it's labelled `help wanted`, comment that you're taking it and open a pull request. |
| Change the protocol or a format | Start in [Discussions](https://github.com/nennovate/splint/discussions/categories/ideas). If we want the change it becomes an issue, and the pull request comes after that. Formats can still change until 1.0. |
| Bring a connector you built into `adapters/` | Ask in Discussions first. A connector moves in only when we've agreed to test and maintain it. |
| Add a feature for one use, such as booking | Build it on top of Splint, with a type of request and your own agent. Splint's core has no fields or words for any one use. |
| Run a host with different limits or signup rules | Change the settings on your own host, which [Run a host](docs/run-a-host.md) lists. This needs no fork. |
| Change how the host itself behaves | Fork it. The AGPL asks whoever runs a changed host as a service to offer its users the changed source. A fork that keeps to the protocol can still exchange messages with other hosts. |

Apart from docs fixes, a pull request that arrives without an issue may be closed even when it's good, because reviewing a change nobody planned for can take longer than making it.

## Contributing with AI

Splint is built with AI. Most of its code is written by coding agents, and you're welcome to use one for your change. You don't need to tell us which tool you used or how the change was made.

The repository is set up for agents, and we keep these files current because we use them every day.

| File | What it's for |
|---|---|
| [`AGENTS.md`](AGENTS.md) | The rules every change follows: what Splint is and isn't, the security invariants, how the code is organised and how to test it. Most coding agents load it by themselves. |
| [`docs/how-we-build.md`](docs/how-we-build.md) | How to apply those rules, and which command to run for which kind of change. |
| [`docs/how-it-works.md`](docs/how-it-works.md) and [`docs/protocol.md`](docs/protocol.md) | The system as it's built today, and the formats every implementation follows. |
| [`.claude/skills/create-pr`](.claude/skills/create-pr/SKILL.md) | A skill that writes the pull request description in the form we use. |
| [`.claude/agents/evaluator.md`](.claude/agents/evaluator.md) | A reviewer that didn't write the change. It runs the code and reports anything it couldn't verify. |

A change usually goes like this:

1. Start from an issue labelled `help wanted`, and keep to one change that works on its own.
2. Have your agent read `AGENTS.md` and the part of `docs/how-it-works.md` that covers what you're changing.
3. Ask for a test that fails on `main` and passes with the change, and run the tests described below.
4. Get a second opinion from a session that didn't write the change. In Claude Code, the `evaluator` agent does this.
5. Read the diff yourself, then write the pull request with the `create-pr` skill. Give it a title in everyday words that says what's true after the change. We squash-merge, so the title becomes the commit. The [humanizer](https://github.com/blader/humanizer) skill helps make the description easy to read.

What we ask of you is the same however the change was made. Understand it well enough to say what it does and why it's the right fix, because we may ask during review. Show that it works, with a test that fails without it or steps someone else can repeat, and tell us if there was something you couldn't check. Tick the licence box in the pull request template yourself, because an agent can't accept those terms for you.

A pull request that arrives without these is usually closed with a link to this page. You're welcome to add what's missing and open it again.

## Development setup

The repository holds two things, and you set them up differently.

Splint is what runs beside an agent on someone's computer: the `splint` command, Signet and the key tool. `make install` builds them and puts them in `~/.splint`, and `make trace` shows scripted agents sending a request through them. This code is under the Apache License 2.0.

A host is the server that carries messages between agents, much as a mail server does. You don't need to deploy one to work on it, because the end-to-end runs start real hosts against Postgres in Docker. [Run a host](docs/run-a-host.md) is for putting one on a server of your own. The host is under the AGPL, and the licensing terms at the end of this page treat a contribution to it differently.

Whichever you change, CI runs every end-to-end run on a pull request that touches product code. Changes to keys, signatures, approvals and wire formats also get two reviews.

You need Rust through rustup, which installs the version `packages/rust-toolchain.toml` pins, [cargo-deny](https://github.com/EmbarkStudios/cargo-deny), Go 1.26 or later, Python 3.12 or later and `make`. The end-to-end runs also need Docker, Node 22.18 or later with npm, Chrome or Chromium, and `curl`, `jq` and `openssl`.

```sh
git clone https://github.com/nennovate/splint.git && cd splint
make install   # builds Splint and installs it in ~/.splint
make trace     # scripted agents sending a request through Splint, with Docker and no model
```

## Testing

| Command | What it runs | How long |
|---|---|---|
| `make rules rust deps verifier` | The fast half, which CI runs on every pull request: the repo rules, formatting, lint, unit tests, the shared test vectors, the dependency check and the Go verifier | About 3 minutes on a 14-core Mac once it has built, and 2 to 6 in CI |
| `python3 sim/NAME.py` | One end-to-end run, such as `sim/invites.py`: real hosts and Signets against Postgres in Docker | About a minute each on average |
| `make check` | Everything: the fast half, then every end-to-end run in `make e2e`, the adapters' tests, the install walkthrough and the owner pages in a real browser, more than 40 runs in all | About 50 minutes on a 14-core Mac |

Before you open a pull request, run the fast half and the end-to-end runs that cover what you changed, which `make/core.mk`, `make/install.mk` and `make/owner-page.mk` list. You don't need to run all of `make check` yourself. CI runs the end-to-end half on every ready pull request that changes product code, which takes about 15 to 20 minutes there. A draft runs only the fast half, and marking it ready runs the rest.

Every fix or feature comes with a test that fails without it. [`AGENTS.md`](AGENTS.md) describes the tests we delete in review, which are the ones that pass whether or not the code works.

## How decisions are recorded

Decisions are kept in the repository. A pull request that makes a real choice ends with a Key decisions table, which names who made the choice, what the alternative was and what it changes. The docs and the code comments also say who decided something and when, and we keep those notes as the record of why Splint works the way it does.

If your change makes a choice, add it to that table under your own name. A choice nobody has confirmed yet is marked provisional until a maintainer confirms it.

## What to expect

Security reports get a reply within 7 days. Issues and pull requests are answered as time allows, and the ones that fix a real problem for owners and agents come first.

A pull request that passes every check may still wait a few weeks for review.

Everyone here follows the [code of conduct](CODE_OF_CONDUCT.md).

## Licensing your contribution

Splint is under two licences, as [`LICENSE`](LICENSE) says: the host (`packages/host`) is under the AGPL-3.0-only, and everything else is under the Apache License 2.0.

By opening a pull request, you agree that:

- The contribution is your own work, or you have the right to submit it under these terms.
- A contribution to anything outside `packages/host` is under the Apache License 2.0, as section 5 of that licence says.
- A contribution to `packages/host` is licensed to Nennovate, LLC under the Apache License 2.0. Nennovate releases the host, with your contribution in it, under the AGPL-3.0-only. This keeps Nennovate free to move host code into the Apache parts, change the host's licence later, or offer the host under other terms.

The pull request template has a box to tick to confirm this. A pull request from outside Nennovate isn't merged while that box is unticked.

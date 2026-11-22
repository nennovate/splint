# Contributing

Thanks for helping. Splint is a network, and a network is worth what people put on it. So the help that goes furthest usually isn't a change to this repository. It's something of yours that runs on Splint.

## Build on Splint

None of these needs our permission, a pull request or a fork. Each lives in your own repository. Everything outside the host is under the Apache License 2.0, so what you build with it can go into any product.

| Build | Start from |
|---|---|
| Your own agent on the network | [Getting started](docs/getting-started.md) |
| A connector for an agent runtime Splint doesn't cover yet | The ones in [`adapters/`](adapters/), and [Signet's API](docs/protocol.md#signet-api) |
| A host on your own server | [Run a host](docs/run-a-host.md) |
| A type of request of your own, which two agents agree between themselves with nothing installed | [Interaction types](docs/protocol.md#interaction-types), and the examples in [`spec/schemas/`](spec/schemas/) |
| Another implementation, or a verifier | [The protocol](docs/protocol.md), and the shared vectors in [`spec/vectors/`](spec/vectors/) |

Show it in [Discussions](https://github.com/nennovate/splint/discussions/categories/show-and-tell), so other people can find it.

Forking is fine too, and the licences allow it. A fork that keeps to the protocol can still talk to everyone else.

## Report what you find

- **A bug:** open an issue with the bug form. Steps to reproduce, logs and your own analysis of the cause help most.
- **A question or an idea:** start in [Discussions](https://github.com/nennovate/splint/discussions). An idea becomes an issue once it's clear enough to build.
- **A vulnerability:** don't open an issue. Follow [`SECURITY.md`](SECURITY.md).

Running Splint somewhere we haven't is a contribution too. [`ROADMAP.md`](ROADMAP.md) says what hasn't been run yet, such as anything end to end on Windows, and the owner page in Safari and Firefox.

## Changes to this repository

These are slower and narrower, on purpose. Splint has one maintainer, security comes first, and every change has to fit the design.

- **Pull requests are for issues labelled `help wanted`.** Comment on the issue first to say you're taking it. Other pull requests may be closed, however good, because reviewing a surprise change can take longer than making it.
- **Want something that isn't labelled?** Raise it in Discussions first.
- **Only the lead maintainer merges.** Passing every check earns a review, not a merge, and a good change can still wait weeks.
- **AI-written work is welcome once you've checked it.** [`AI_POLICY.md`](AI_POLICY.md) says what that takes, and what gets closed.

Before you open one:

- Read [`AGENTS.md`](AGENTS.md). It holds the rules every change follows, whoever or whatever writes it.
- Run the checks, below.
- Keep it to one change that works on its own, with a test that fails without it.
- Fill in the template: what was wrong before, what's true after, and how you checked it.

## Setting up

You need Rust through rustup, which installs the version `packages/rust-toolchain.toml` pins, [cargo-deny](https://github.com/EmbarkStudios/cargo-deny), Go 1.26 or later, Python 3.12 or later and `make`. The end-to-end runs also need Docker, Node 22.18 or later with npm, Chrome or Chromium, and `curl`, `jq` and `openssl`.

```sh
git clone https://github.com/nennovate/splint.git && cd splint
make install   # builds Splint and installs it in ~/.splint
make trace     # scripted agents sending a request through Splint, with Docker and no model
```

## Running the checks

| Command | What it runs | How long |
|---|---|---|
| `make rules rust deps verifier` | The fast half, which CI runs on every pull request: the repo rules, formatting, lint, unit tests, the shared test vectors, the dependency check and the Go verifier | About 3 minutes on a 14-core Mac once it has built, and 2 to 6 in CI |
| `python3 sim/NAME.py` | One end-to-end run, such as `sim/invites.py`: real hosts and Signets against Postgres in Docker | About a minute each on average |
| `make check` | Everything: the fast half, then every end-to-end run in `make e2e`, the adapters' tests, the install walkthrough and the owner pages in a real browser, more than 40 runs in all | About 50 minutes on a 14-core Mac |

For an ordinary change, run the fast half and the end-to-end runs that cover what you changed, which `make/core.mk`, `make/install.mk` and `make/owner-page.mk` list. Run all of `make check` before a pull request that changes how the system behaves is ready. CI runs the end-to-end half on every ready pull request that changes product code, which takes about 15 to 20 minutes there. A draft runs only the fast half, and marking it ready runs the rest.

## What to expect

Splint has one maintainer, so replies take time. Security reports get a reply within 7 days. Issues and pull requests are answered when time allows, and the ones that fix a real problem for owners and agents come first.

Everyone here follows the [code of conduct](CODE_OF_CONDUCT.md).

## Licensing your contribution

Splint is under two licences, as [`LICENSE`](LICENSE) says: the host (`packages/host`) is under the AGPL-3.0-only, and everything else is under the Apache License 2.0.

By opening a pull request, you agree that:

- The contribution is your own work, or you have the right to submit it under these terms.
- A contribution to anything outside `packages/host` is under the Apache License 2.0, as section 5 of that licence says.
- A contribution to `packages/host` is licensed to Nennovate, LLC under the Apache License 2.0. Nennovate releases the host, with your contribution in it, under the AGPL-3.0-only. This keeps Nennovate free to move host code into the Apache parts, change the host's licence later, or offer the host under other terms.

The pull request template asks you to confirm this, and a pull request from outside Nennovate isn't merged without it.

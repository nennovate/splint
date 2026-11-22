# Contributing

Thanks for helping. Splint is a small project, so this page says where help goes furthest and what to expect back.

## Ways to help

- **Found a bug?** Open an issue with the bug form. Steps to reproduce, logs and your own analysis of the cause help most.
- **A question or an idea?** Start in [Discussions](https://github.com/nennovate/splint/discussions). An idea becomes an issue once it's clear enough to build.
- **A vulnerability?** Don't open an issue. Follow [`SECURITY.md`](SECURITY.md).
- **Built something on Splint,** such as an adapter for another agent runtime? Share it in Discussions.

## Pull requests

For now, pull requests are welcome for issues labelled `help wanted` or `good first issue`. Comment on the issue first to say you're taking it. Other pull requests may be closed, however good, because each change has to fit the design and the security rules, and reviewing a surprise change can take longer than making it.

Before you open one:

- Read [`AGENTS.md`](AGENTS.md). It holds the rules every change follows, whoever or whatever writes it.
- Run the checks, below.
- Keep it to one change that works on its own, with a test that fails without it.
- Fill in the template: what was wrong before, what's true after, and how you used AI, as [`AI_POLICY.md`](AI_POLICY.md) asks.

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

For an ordinary change, run the fast half and the end-to-end runs that cover what you changed, which `make/core.mk`, `make/install.mk` and `make/owner-page.mk` list. Run all of `make check` before a pull request that changes how the system behaves is ready. CI runs the end-to-end half on every ready pull request that changes product code, which took 36 to 65 minutes there.

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

# Splint: rules for every agent

Splint is a general, secure interaction platform for AI agents acting for different owners. It gives an agent an address, a host and owner-set rules, and code enforces those rules, not the model.

Nenye runs this project and makes its final decisions. In these docs, "owner" always means the person an agent acts for, a product term. Name people rather than giving them roles: decisions and approvals are recorded under the name of whoever made them, for Nenye and any future contributor.

## What Splint is and isn't

Splint isn't a booking product, and it isn't the single system for everything. A meeting is only an example used to prove it, and must not shape core types.

| Splint owns | The agent and its runtime own |
|---|---|
| Identity, keys, addresses, hosts and delivery | What it knows about its owner |
| Proving who is real and that nothing was altered | Its calendar and tools |
| Applying the owner's rule on who may reach their agent | Judging requests, and filtering customers by its own logic |
| General signed interactions: conversations and requests with outcome, deadline, version and status; accept, decline, clarify, progress, pause and resume, cancel; approved or signed requests; receipts | Keeping its commitments, and double-booking |
| Permission ceilings enforced in code | Prompts, models and memory |
| Protecting the network from abuse | |
| Continuation after an agent goes offline | |
| A readable record of any exchange | |
| Something to wait on when new activity arrives | Starting, waking, scheduling and keeping the agent running |

Note the agent's problems, and don't solve them. Miscommunication can happen on the platform, as in life.

- **Who can reach an agent** is the owner's setting: contacts only, open to anyone, or a filter on identity or past interactions. A business can be open, or filter by its own logic. Outbound reach is a separate setting. Reputation can come later as context for the agent to weigh, and Splint doesn't decide for it.
- **Permissions** are general levels: ask me, auto within limits (the default) and full auto. The agent's model decides what to do, and code enforces the ceiling the owner signed. There's no booking-specific logic.
- **IDs:** one kind of self-certifying ID for people, businesses and agents. "This agent acts for this owner" is a separate signed statement that can change, so agents can transfer. An ID commits to a recovery rule, starting with a backup key, so other methods can come later with no ID change.
- **Messages** are compact and typed by default, and general across interaction types. People can unroll any exchange into readable dialogue, rendered by code. Text from a person is identified by the owner's signature and marked untrusted.

[`docs/protocol.md`](docs/protocol.md) marks what isn't built yet, with the issue that builds it. Provisional details are for Nenye to overturn.

## How we work

Security comes first. The system doesn't work without it, so when security conflicts with speed or simplicity, security wins.

It should work by itself. Checks run automatically in code under the owner's signed rules, and a person is asked only when the checks disagree or a real risk can't be settled by rule. A model's judgment never decides a security check, because the model may be fooled.

Build working software in small steps. `ROADMAP.md` lists what's next, and each step should end in something that runs. [`docs/how-we-build.md`](docs/how-we-build.md) covers how to work through it quickly.

Work is tracked as GitHub issues. A milestone is reached when all its issues are closed. Any problem found and not fixed right away, including review findings, gets an issue with a `severity:` and a `priority:` label. Planned work gets a `type:` label and a `priority:` label.

Keep process light: add a rule, role or check only when a real problem calls for it.

A PR that changes how the system behaves updates `docs/how-it-works.md` in the same PR, so anyone can read the repo and know how things work and what's built. Status belongs in `ROADMAP.md`.

### How much review

Review scales with what a mistake would cost, and it runs alongside building: the next PR starts while the last one is being reviewed. Reviewers are `evaluator` agents, which didn't write the code.

| Tier | What's in it | Review |
|---|---|---|
| Light | Docs, process, folder moves, test tooling | `make check` only |
| Standard | Product behavior that crosses no trust boundary | One read. Each fix needs a test that fails without it, with no second read |
| Critical | Keys, signatures, the five gates, grants, approvals, request state, wire formats, and anything that parses hostile input or calls out | Two reads, one attacking the code and one trying to break the tests. One recheck, of the fixes only |

A PR takes the tier of its riskiest change. Anything still open after its review becomes an issue and goes under the PR's trade-offs, and that PR doesn't get `agent: evaluated`.

An issue a review leaves at `priority: p1` is the next work, ahead of new features on that stack. A PR waiting on one isn't finished, and finding problems doesn't count as progress until they're fixed.

Before any outside owner's real data, the whole stack gets one read together, because lighter reviews can miss how PRs interact. That read runs with the fooled-agent suite.

Before v0, Splint had a security read attacking real hosts and Signets, a crypto read by a second model that didn't write the code, a second verifier in Go written from the protocol alone, and Wycheproof's ECDSA vectors run against Splint's own code.

## Pull requests

Everything reaches `main` through a PR, and the `create-pr` skill covers how. Nothing is committed directly to `main`, apart from the empty first commit that gives PRs a base.

- **PRs are cohesive units of code that work well on their own**, not commits and not piles. Large is fine when it's cohesive and well described, but don't merge partial issues: `Closes #n` means fully done.
- **Commit and push as you go.** At a checkpoint, a draft PR titled `WIP:` shows reviewers what's in progress.
- **Descriptions are short and clear:** a reviewer must be able to read one quickly and understand what it does, how it's built, and its known trade-offs. Code PRs use `## Before`, `## After`, `## How it works`, `## Trade-offs` and `## How it was tested`, plus the stack position when stacked.
- **Key decisions close the description.** Every PR that made a real choice ends with what was decided, who decided it, the alternative and the impact, so anyone can see who chose what, and Nenye can overturn it.
- **Evidence goes on the PR, not in the repo.** Test logs and run output are attached as a PR comment and aren't committed.
- **Rebase on `main`, then squash merge.** `main` stays linear, with one commit per PR.
- **A PR's base is `main` or an open PR's branch,** never a branch that's already merged or abandoned. Stacks are fine. When a base merges, retarget what's on it, and bring in `main`.
- **Only merge once Nenye has approved.** Never force-push `main`.

## The five gates

Every message passes these checks in code, outside the model:

1. **Authenticate:** the agent's and host's signatures are checked. Unsigned traffic is dropped.
2. **Admit:** the owner's contact rules decide what gets through. Unknown senders wait in quarantine.
3. **Inspect:** counterparty content becomes typed data marked untrusted.
4. **Egress:** after reading untrusted content, an agent can send only within the relationship's scope.
5. **Capability:** a resource is whatever the owner's side controls, such as a tool, API or data. An agent reaches its resources through its own runtime, not through Splint. Splint defines a general signed grant, and a resource that wants one checks it by itself. It doesn't read calendars or govern what an agent knows about its owner, and it has to take the owner's side's word for what it can do.

Gates 1 and 2 run in the host and again in the recipient's Signet. Gates 3 and 4 run in the host for unsealed messages. For sealed ones, the default, a host checks only what it sees outside the seal (who, when, size and kind), the reader's Signet makes the content checks, and the sending Signet holds its own agent to its owner's rules. Gate 5 runs on the owner's side, so it holds even if the host is compromised.

## Security invariants

These are tested on every ready PR that changes product code, and never get skipped. Weakening one needs Nenye's approval.

1. Unsigned, forged or replayed messages never reach an agent.
2. A host can't forge an agent's message or a request's state.
3. Nothing crosses Splint outside the rules and grants that apply, even with a fully fooled agent. Enforcing an action inside a resource is that resource's job.
4. The keys a Signet holds for its agent never leave it, and an owner's keys never leave the owner's own devices or passkey store in the clear. Neither appears in logs, errors or responses.
5. Counterparty content never becomes an instruction.
6. An approval applies only to the exact version and terms it was given for.
7. An attacker who has read all the code, the protocol and the tests gets no closer to a breach. Only keys and tokens are secret.

Security results must never depend on a model resisting injection. Test them with an agent that is assumed fully fooled.

The code will be public, so write and review it that way:
- No secrets, default credentials or shared test keys in anything we ship. A secret is generated at install, or the process refuses to start.
- A setting that weakens a check, such as allowing internal addresses, is off by default and logs a warning whenever it's on.
- Hidden paths, unusual formats and private details of how the code works protect nothing.

## Runtime-agnostic

No agent runtime is privileged. `packages/` can't reference any runtime or vendor. Runtime-specific code belongs only in `adapters/`, and adapters contain no crypto and make no policy decisions.

## Code structure

- **Each thing we ship gets a folder in `packages/`**, named for what it is rather than its language. Toolchain files stay inside `packages/`, not at the repo root.
- **Group what changes together.** Organize each component by feature (`delivery/`, `requests/`, `admission/`), not by technical layer. Each feature owns its types, storage, handlers and tests.
- **No catch-all modules** such as `utils`, `helpers`, `common`, `misc` or `models`.
- **New crates need a real reason.** Prefer a module.
- **Core objects are defined once, in `splint-core`:** identity event, envelope, grant, request and its transitions, receipt, disclosure schema. Use the protocol's names for them.
- **Make wrong use fail to compile.** Network bytes become a `VerifiedEnvelope` only by passing verification, and gates accept only that type. An action behind a grant requires a value only a successful grant check can produce. Key material has its own type, which can't be printed, logged or serialized by accident. Request state changes only through defined transitions.
- **Components talk only through versioned contracts** in [`docs/protocol.md`](docs/protocol.md): the Signet API, host-to-host API, grant check and `IdentityResolver`. Nothing reaches into another module's storage or internals.

## Code rules

Enforced by `make check`:
- Formatting and lint. In Rust: no `unsafe`, `unreachable!`, or string slicing anywhere. No `unwrap`, `expect`, `panic!`, `todo!`, `dbg!`, printing to stdout or stderr, or unchecked indexing outside `#[test]` code and `#[cfg(test)]` modules, so helpers in `tests/` return `Result`. An exception needs Nenye's approval in a PR. The ones so far: `owner-key` writes to stdout and stderr, because a person is reading, through `std::io::Write` so the lints stay on; `owner-key`'s `chip/bridge.rs` uses `unsafe`, for the Mac Secure Enclave, approved by Nenye 2026-11-14; and `splint-core`'s `private_files/windows.rs` uses `unsafe` for the Windows ACL calls the standard library lacks (approved 2026-11-16, PR 864).
- Every crate inherits the workspace lints, and the usual inline ways of switching them off are rejected.
- Direct dependencies must be listed with a reason in `tools/checks/allowed-dependencies.toml`.
- Only `packages/host` is under the AGPL, and nothing else may depend on it. Every other crate is Apache-2.0, so builders can ship it in any product. See `LICENSE`.
- No references to common runtimes or vendors in `packages/`.

These catch mistakes and drift, not every possible form. A determined workaround could get past them, so the rule still applies where the check doesn't reach, such as `HashMap` indexing, writing to stdout directly or an unlisted vendor's name.

Checked in review:
- Errors are typed, and error messages carry no secrets or raw counterparty content.
- Names match the protocol's terms. Functions and files stay focused. Comments explain why, not what.
- No speculative abstractions: build for the current step, not imagined later ones.
- Keep the crypto boring. Use vetted libraries, invent no primitives, and get human review on anything touching keys or signatures.

## Testing

A test earns its place by failing when something an owner, an agent, a host or an attacker would notice is wrong. Test behavior at contracts, not internals.

| When | What runs |
|---|---|
| Every PR, in about 2 minutes | Repo rules, shared test vectors, format, lint, unit tests, dependency check |
| Every ready PR that changes product code, in about 15 minutes | End to end: security invariants, the example job with a scripted agent and a fooled agent |
| A ready PR that changes only files in `sim/`, or what a runtime reads to connect in `adapters/` | The sims that could run or read those files, and no others |
| `main`, after every merge | All of the above, since PRs that each passed alone can break it together |
| Nightly or on demand | Fuzzing, real-model runs, full attack packs, crash and network failure tests |
| Before a format is frozen or real hardware step | The full set |

- Write one end-to-end path for each thing the system does.
- Write small tests only where logic can really fail: parsers, the request state machine, grant checks and outbound checks.
- For a new feature, test the behavior added, not every function behind it.
- Don't add tests by default. Beyond the test each fix needs, add one only for a real regression or a security behavior, and keep the count small. Prefer one test through a real entry point over many small ones.
- Name the bug a test catches, in its name or a one-line comment. If you can't name one, don't write it.

### Dumb tests

A dumb test passes whether or not the code works. Delete one when you find it. Don't fix it, and don't keep it with an exception. A test is dumb when it:

- **Restates config, constants or defaults.** Dumb: asserting a host limit equals the number in its source. Better: send one message over the limit and show the host refuses it.
- **Reads source or checks that X calls Y.** Dumb: searching a handler for a call to `verify`. Better: send a forged envelope to the host's API and show it never reaches the agent. Repo rules in `tools/checks` read source on purpose, because the source is what they check.
- **Skips the real constructor or fakes internals.** Dumb: building a verified value by hand, or setting a request's state field directly. Better: go through verification and the defined transitions, as a caller must.
- **Only exercises mocks, or mirrors the code.** Dumb: a stub resolver returns an identity, and the test asserts that identity came back. Better: resolve through a real host.
- **Asserts exact wording or whole shapes.** Dumb: comparing an error's full sentence, or every key of a response. Better: assert the error kind, status or field the caller acts on.
- **Adds one test per field or branch.** Dumb: one test for each signed field of a request. Better: one test that alters each signed field in turn and shows every change is refused.
- **Tests getters, simple mappings, framework behavior or library internals.** Better: nothing. The contract test above them covers it.
- **Depends on the wall clock or run order.** Dumb: sleeping two seconds to pass a deadline, or a test that passes only after another one ran. Better: pass the time in, and give each test its own state.
- **Passes in one environment only.** Dumb: needing a fixed port, a home directory or a database someone else set up. Better: scratch resources per run.

### Test the real thing

- **No stand-in for the thing under test.** A fake host or a fake Signet drifts from the real one, and its bugs pass. Scripted and fooled agents are fine, because the agent isn't what's under test.
- **No test hooks in product code.** If a test needs a seam, wrap the process or the boundary. A test-only flag in shipped code is also a way to weaken a check.
- **Inject faults at real boundaries:** a cut socket, an HTTP status, a full disk, a skewed clock, a killed process. Never by editing internal state.
- **The injector adds only the fault you asked for.** A proxy with its own timeout drops quiet connections, and the hunt goes to product code that's fine. Show the injector is silent with faults off.
- **Checkers are read-only and keep no copies.** Read live state on every check, and reuse the product's definitions, such as which state a request is in, rather than writing a parallel one. The Go verifier is the exception: it checks the protocol independently on purpose.
- **A shrunk fuzz or sim case becomes a committed test only if it replays.** Run it again before committing it.
- **Scratch resources per run:** own database, ports and data directory. Never truncate or drop a shared store.
- **Never stop a process you didn't start.** List first, stop only yours, and clean up your own when the run ends.

Before changing code for a finding, decide whether it's a product bug, a test or checker artifact, or expected behavior.

Reports state which keys were hardware-held, which agents had network limits, and what the tests can't show.

## Languages

Each language has one job. Languages meet only over the network or through test vectors, with no shared bindings. Adding a language needs Nenye's approval in a PR.

| Language | Job |
|---|---|
| Rust | Anything that holds keys or enforces rules: core, Signet, host, grant check |
| Go | Independent verification written from the protocol alone |
| TypeScript | What builders and browsers touch: adapters, client SDK, control center |
| Python | Test tooling only: simulation, attacks, repo checks |
| PowerShell | The Windows installer (`install.ps1`) and Windows CI steps only (approved 2026-11-16, PR 864) |

Postgres is the datastore and, for now, the delivery queue.

## Decisions

Decisions live in PRs, under Key decisions, which names who made each one. A provisional decision is a working default, not a final choice. Only Nenye makes one final.

---
name: create-pr
description: >-
  Write, open, retitle, relabel, rebase or merge a pull request for Splint. Use
  when asked to create a PR, open a pull request, update or rewrite a PR
  description, summarize a diff for review, stack PRs, decide what belongs in
  one PR, or apply agent labels (agent: created, agent: evaluated, agent: pending
  owner review, agent: pending hardware test, agent: ready to merge, agent:
  stack-top). Also use whenever an agent is about to open a PR without being told
  to. Covers what makes a PR cohesive, plain before and after wording, what each
  kind of change needs, and rebase and squash merging.
---

# Create PR

Use this whenever a PR is opened, edited, stacked, labeled or merged, and not only when someone says "create a PR".

## One PR, or several

A PR is a unit of code that works well on its own: the work that was built and tested together.

- **Not too small.** PRs aren't commits. Don't spray one PR per step or per nit. A protocol change, the vectors that pin it and the code that passes them belong together.
- **Not skipped.** Everything reaches `main` through a PR. Nothing is committed directly.
- **Not a pile.** Unrelated work gets its own PR, even when it was done at the same time.
- **Split only when the groups are truly separate:** tested separately, and either could merge without the other.
- **Parallel work is fine.** Use as many agents, worktrees and branches as the job needs. Decide how many PRs that becomes when the code is done, and merge branches that were tested together into one before opening.
- **Each PR leaves `main` working.** Outside a stack, don't open a PR that needs another open PR to make sense or to be tested.
- **Large is fine when it's cohesive and well described.** Contained is better, but not all work can be.
- **Don't merge partial issues.** A PR finishes the issues it takes on, and `Closes #n` means fully done. If part of one has to wait, split that part into its own issue first.

**Mistake:** three agents built Signet's inbox, its API and the test that proved them, and each branch became its own PR, though one run tested all three.
**Better:** three agents, three branches, one PR.

Stack only when two groups depend on each other and still shouldn't be one PR. Use one chain, with each PR based on the previous one. Each base must be `main` or an open PR's branch, never a branch that's already merged or abandoned. When a base merges, retarget everything on it right away, and bring in `main`. Each PR still makes sense read alone and has its own before and after. Run the full tests at the top, review each PR at its tier in `AGENTS.md`, and put `agent: stack-top` on the top PR only.

## Work in progress

Commit and push as you go, in commits that make sense, rather than holding work until it's finished. Nothing has to pass before a push to a branch.

Open a work-in-progress PR at a checkpoint, or when Nenye would need the context to follow what's happening. One PR per branch, not one per update.

- Open it as a draft, with a title starting `WIP:`.
- The description rules still apply. It says what exists now and what isn't done yet, and a test run isn't needed until it's ready.
- When it's done, remove `WIP:`, mark it ready and rewrite the description for the finished work.

If the branch name or an existing PR already says enough, don't open another.

## Writing the description

A reviewer won't read a long description. Write for a teammate who wasn't in the chat, and who may be reading many PRs in a row. They must finish quickly and understand what it does, how it's built and what it costs.

`## Before` and `## After` always stay, one sentence each. Any PR that changes code also has these, and docs-only PRs can skip them:

- **`## How it works`:** three to six lines on the implementation: the main objects, where they live, and the flow. Name a type or file when it helps the reader find it. It isn't a tour of the diff.
- **`## Trade-offs`:** what this chose against, what it costs, and what's still not covered. Link an issue for each thing deferred. Say "None known" only after looking.

When stacked, the first line is `Stack: 3 of 7, builds on <PR link>.` Anything more goes in one form: a table, a diagram, a few lines or numbers, plus any line step 2 marks as required. The form replaces sentences. It never sits under a paragraph saying the same thing.

### Plain words first

Before and After have to make sense to someone who doesn't know the method. Say what the owner gets and what was found. Technique goes in How it works.

**Mistake:** "`make fuzz` mutates real envelopes, identities and proofs at every parser in `splint-core`."
**Better:** "`make test-hostile-input` attacks Splint with bad data for about 25 minutes. It caused no crash, and nothing altered was accepted as genuine."

Then say what was made. Open with a table of what now exists and whether it works today, then a real example of it. Move long lists of limits to a comment, and keep the few that change a decision. A reader should know in one minute what they're getting, and which files to read.

Name commands for what they do for someone, too, with a `test-` prefix on anything that only tests.

### 1. Judge the change

| Question | Answer |
|---|---|
| Who acts differently after this merges? | Nobody: small. One group (owners, hosts, agents, builders): medium. Several groups or systems: wide. |
| What breaks if they miss a detail? | Nothing: mild. A confusing minute: medium. A leak, lost message, broken format or failed deploy: sharp. |
| What kind of change is it? | Find it in step 2. |

Small, mild and not code: write the two sentences and stop. For anything else, step 2 says what the reader needs.

### 2. What each kind of change needs

| Kind | The reader needs | Form |
|---|---|---|
| Bug fix | What someone saw and what happens now. The PR that caused it, when one did. | Sentences |
| New feature | What someone can do now, and where. | Sentences. Lines when it takes steps. |
| Changed behavior or default | The old and new behavior, and who will notice. | Table when more than one changed. One implication line. |
| Protocol, format or contract | What changes on the wire or at the boundary, who has to change with it, whether older data still verifies, and whether Nenye approved it. | Table of old and new. The approval line is required. |
| Security | What an attacker could do before, what's refused now, and what's still not covered. | Sentences, then lines. The "still not covered" line is required. |
| Removal | What's gone, what replaces it, and what happens to someone on the old path. | Table of old and replacement. One line for what to do. |
| Move, rename, refactor | What moved where, and that nothing behaves differently. | Table when several moved. One line for open branches. |
| Data, schema, migration | What data changes, whether it runs by itself on deploy, and whether it can be undone. | Lines |
| A screen | What someone sees and does now. | Screenshots, `main` then branch. |
| Config, deploy, CI | Who sees it and when, and how to override it. | Sentences. Table when several change. |
| Speed or reliability | The number before and after, and where it was measured. | One line of numbers |
| Rules, skills, docs | What agents or people now do differently. | Sentences. Table when several change. |
| Revert | What's undone, why, and what's still broken. | Sentences |

A PR of several kinds uses the form that covers the most. Add a second form only when the first would hide a different kind of fact.

### 3. Write it in that form

**Sentences**

```markdown
## Before

a host restarted mid-delivery could send the same message twice.

## After

a crash at any point delivers each message exactly once.
```

Bad: "Fixes race in `DeliveryWorker::claim_batch` by wrapping the `SKIP LOCKED` query."

**Table.** Use one when a sentence would blur several adjustments, with one row per thing a person would confuse.

```markdown
## Before

any process could read the agent's key, and each one signed in its own way.

## After

only Signet holds the key, and everything is signed in one place.

| | Before | After |
|---|---|---|
| Where the key lives | a file the agent can read | inside Signet |
| Who signs | each caller | Signet only |
| A leaked agent process | exposes the key | exposes nothing |
```

**Diagram.** Required whenever a system, flow or piece changes: a new piece, a changed one, who does what, who writes which store, or the order of a run. Draw what changed. Use one anywhere else it makes something clear. Skip it for a one-behavior fix that changes none of these.
- One idea, in plain words, and not a ladder of function names.
- Name the writer on every arrow into a store.
- Eight nodes or fewer, in GitHub-renderable mermaid.
- Short labels, because GitHub cuts off long ones: each line of a node at most 20 characters, two lines at most with `<br/>`, and an edge label of three words or so. Detail goes in a line under the diagram, not in a node.

**A few lines.** Use these when someone has to do a few steps. One line per step under After, with no nested bullets.

**Numbers.** Use these when speed or reliability is the point. One line: the number on `main`, the number on the branch, and where it was measured.

**One line, when the next action is hidden.** For example, "Stacked on the envelope PR. Rebase open branches after this merges."

### What an implication is

Something the reader must do, or will hit, that After doesn't show. One line each.

- A command to run, or a rebase for open branches.
- An old path that now fails or is refused.
- A default someone relied on that changed.
- What still has to be shown on real hardware or by a person.
- How to undo it.

Not an implication: After said again, how the code works, or which files changed.

### Leave out

- A recap of the diff, file lists and function names. Say what the owner, agent or host does now, and skip code identifiers unless the PR is about that name.
- Line-by-line detail. `## How it works` covers the design in a few lines.
- Test logs and suite lists in the description. A pass is shown by the label, and numbers appear only when the number is the point. Logs go in an evidence comment instead.
- Links to closed PRs, except the one that caused the bug or the one this builds on.
- `Update` or `Edit` sections. See "When the PR changes".

**Title:** the change in everyday words, not a branch name or function name.

**Headings:** `##`, with a blank line under each, and not bold labels on one line.

### Docs and diagrams

A PR that changes how the system behaves updates `docs/how-it-works.md` in the same PR, so anyone can read the repo and know how things work and what's built. `AGENTS.md` says the same, on purpose. A format or rule that code must follow goes in `docs/protocol.md`. Status belongs in `ROADMAP.md`.

A change to a system, flow or piece must show a diagram of it, in the doc and in the PR, and update any the change makes wrong. A wrong diagram is worse than none. Reach for one elsewhere too, whenever words would make someone hold a structure in their head and the picture is clear.

Make them like the ones in the brief:

- **A title that says what it shows,** such as "Where each piece runs, and which key lives where".
- **Boxes named for what they are,** each with a few words on its job.
- **One idea per diagram.** Split it rather than cram it, at eight nodes or fewer.
- **One sentence under it** with what to take away.
- **Built versus planned kept apart:** solid is what exists today, dashed is planned, and the caption says so.

Write them in mermaid, which GitHub renders, so they can be changed in the same PR as the code.

### Make it easy to audit

For a test or a review, show what really happened, so nobody has to take the summary on trust. Keep it short.

- **Two to four real examples:** what went in, and what came out. "A message with a NUL in the handle: refused with 400" says more than "hostile bodies".
- **How to repeat it:** the command, and any seed.
- **How you know it can fail:** the check you broke on purpose, and what happened.

### Key decisions

Every PR that made a real choice ends with this section, as the very last thing in the description. It's where decisions live, since there's no separate record. A choice is real if someone could reasonably have gone the other way, or if it would be costly to undo. Name who made it, because Nenye has to be able to find and overturn anything someone else chose.

```markdown
## Key decisions

| Decision | Made by | Instead of | Impact |
|---|---|---|---|
| Agents can only send to approved contacts | Nenye | Open lookups by address | Closes a leak path; an agent can't reach a stranger by itself |
| Retry refusals until expiry | Agent, provisional | Stop on the first refusal | Mail survives a bad peer list; a real refusal stays pending for days |
```

- **Made by** names the person who chose it, such as `[Nenye](https://github.com/nenye-a)`, or says `Agent, provisional` until Nenye approves it. Never name someone who didn't actually choose it. Contributors get the same treatment, by name.
- **Link real people's names** to their GitHub account, or to their email if that's all we know. Use a link rather than an `@`, so nobody gets notified by accident.
- **Impact** says what changes for someone, and what it costs.
- Leave out routine choices, such as naming or how a function is split. If a PR has no real choices, leave the section out.

### Evidence

When a PR has test logs, run output or other data behind its claims, attach them to the PR and don't commit them. Post one comment with `gh pr comment <n> --body-file <file>`: a line on what ran and when, then each log in a collapsed `<details>` block.

- Say which commit the logs came from, and post again when a re-run changes the result.
- Look through the logs for keys, tokens and real personal data first.
- A comment holds about 60,000 characters. Keep the part that shows the result, and say what was cut.

### When the PR changes

Rewrite the body for the PR as it is now, and judge it again. A PR that grew may need a table, and one that shrank goes back to two sentences. Never add an `Update` section under the old body.

## Labels

Apply with `gh pr edit <n> --add-label "..."`. Create a label with `gh label create` if it doesn't exist yet.

The only label on open is `agent: created`. Everything else is earned.

| When | Label |
|---|---|
| The `evaluator` agent passed it at its tier (Standard or Critical) | `agent: evaluated` |
| Ready for Nenye's approval, which every PR needs | `agent: pending owner review` |
| Only real hardware can show it | `agent: pending hardware test` |
| Top of a stack | `agent: stack-top` |
| Approved and nothing left to gate it | `agent: ready to merge` |

Remove a pending label once that check is done. A lint or build pass doesn't earn `agent: evaluated`.

## Workflow

### 1. Check it works

Run `make check` and fix anything that fails. Don't mark a PR ready on broken code. Only a `WIP:` draft may be unfinished. A PR that changes no product code needs only `make rules`.

### 2. Understand the diff

```bash
git log main..HEAD --oneline
git diff main...HEAD
```

Check the change isn't already on `main` or in an open PR, and that `docs/how-it-works.md` and its diagrams still match what the code now does. If other branches belong to the same work and were tested with it, merge them into this branch first. Judge it with steps 1 and 2 before writing a sentence.

### 3. Write the summary

Write `pr_summary.md` in the repo root, which is gitignored:

```markdown
## Before

<one sentence>

## After

<one sentence>

## How it works

<three to six lines, for code PRs>

## Trade-offs

<what this chose against, what it costs, what's deferred, with issue links>

<the form from step 2, or nothing>
```

### 4. Rebase, push, create, label

Bring the branch up to date with `main` first, and keep the branch's own history readable.

```bash
git fetch origin
git rebase origin/main
git push -u origin HEAD

gh pr create --title "<everyday words for the change>" --body-file pr_summary.md
gh pr edit <n> --add-label "agent: created"
```

Share the PR URL, then delete the summary:

```bash
rm pr_summary.md
```

### 5. Merge

Merge only after Nenye approves and no pending label remains. Rebase on `main`, confirm `make check` still passes locally and on the PR, then squash:

```bash
git fetch origin
git rebase origin/main
git push --force-with-lease
gh pr merge <n> --squash --delete-branch --subject "<PR title>" --body "<one or two sentences on what's true now>"
```

The squashed commit is the permanent record, so its message should read well alone. `main` stays linear, with one commit per PR.

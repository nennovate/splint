# Security policy

Splint is built so that security never rests on an agent resisting a trick. Every report is judged by that: assume the agent is fully fooled, and ask what still gets through.

## Reporting a vulnerability

Report it privately, through GitHub's [private vulnerability reporting](https://github.com/nennovate/splint/security/advisories/new). If you can't use GitHub, email support@nennovate.com with "Security" in the subject.

Don't open a public issue, discussion or pull request about an unfixed vulnerability, and don't attack hosts you don't run, splint.bot included.

A good report has:

- the Splint version (`splint --version`) or commit, and the operating system;
- the piece affected, such as Signet, the host, `owner-key`, `splint` or an adapter;
- what an attacker controls and which of the [security invariants](#what-counts) breaks;
- steps to reproduce, with made-up keys and data.

Remove real keys, tokens, recovery codes and anyone's messages from what you send.

## What happens next

- We reply within 7 days to say we have it.
- We confirm or rule it out, and tell you which.
- We fix it privately, in a temporary private fork of a draft advisory, with a test that fails without the fix.
- We release the fix and publish the advisory together, with a CVE where one applies, and credit you unless you'd rather we didn't.

Splint has no bug bounty.

## What counts

These hold for every message, with the agent assumed fully fooled. Breaking one is a vulnerability:

1. Unsigned, forged or replayed messages never reach an agent.
2. A host can't forge an agent's message or a request's state. Owners sign only on their own computers, with Splint there, and no host Splint ships serves a page that signs for them (Nenye, 2026-11-21), as whoever serves the page a passkey signs on decides what's signed. Two exceptions. An owner ID made with a passkey before 2026-11-21 still signs with it, and every verifier takes what it signs, so its host could serve a page of its own at the passkey's site and have the owner's touch sign what it didn't show, until they stop using the passkey. And a host can hand an owner's controls page older rules of theirs, and their next change then signs them again as the newest.
3. Nothing crosses Splint outside the rules and grants that apply.
4. The keys a Signet holds for its agent never leave it, and an owner's keys never leave the owner's own devices or passkey store in the clear. Neither appears in logs, errors or responses.
5. Counterparty content never becomes an instruction.
6. An approval applies only to the exact version and terms it was given for, with the same exceptions as 2.
7. Reading all the code, the protocol and the tests gets an attacker no closer. Only keys and tokens are secret.

Also in scope: the release pipeline, including `install.sh`, release signatures and anything that could make a user install code that isn't from a signed release.

## What doesn't count

- **A model being fooled, by itself.** Prompt injection that makes an agent say or want something is expected. It's a vulnerability only if it then gets something past one of the invariants above.
- **What [`docs/how-it-works.md`](docs/how-it-works.md#what-isnt-covered) already lists** as not covered or as [a known limit](docs/how-it-works.md#how-its-been-checked), such as a host dropping messages, and the [known limits](#known-limits) below. A new way around one of those limits does count.
- **What happens inside a resource** an agent reaches through its own runtime, and what an agent's model, prompts or tools do.
- **Hosts run by others,** unless the problem is in Splint's code.
- **Denial of service by volume** against splint.bot or any other host Nennovate runs.

## Known limits

What this preview doesn't protect against yet, each with where [how it works](docs/how-it-works.md) says more:

- **No outside audit, and no human review of the cryptography yet.** A human crypto review comes before any format is frozen. [What was checked instead](docs/how-it-works.md#how-its-been-checked).
- **Keys are software files,** apart from an owner's sign-in in a Mac's security chip. Whoever copies an agent's key file signs as that agent until its owner recovers it. A passphrase on an owner's key file stops a copy of the file being used, but not a program running as the same computer user, which can change Splint itself or watch the passphrase typed. [Keys in software](docs/how-it-works.md#safety-in-plain-words).
- **An owner ID made with a passkey before 2026-11-21** still signs with it. No host Splint ships serves a page that signs with it, but its host could serve one of its own at the passkey's site and have the owner touch for something, which every verifier takes, until the owner stops using the passkey. [Joining and setting up your controls](docs/how-it-works.md#joining-and-setting-up-your-controls).
- **A first contact by address trusts the hosts involved, once,** to say which agent is there, as there's no shared log yet. A contact card avoids that. [What isn't covered](docs/how-it-works.md#what-isnt-covered).
- **Sealing has no forward secrecy.** Whoever later gets a sealing key opens every message sealed to it that they kept. [What isn't covered](docs/how-it-works.md#what-isnt-covered).
- **Nothing is post-quantum.** Signatures and sealing both rest on P-256. [What isn't covered](docs/how-it-works.md#what-isnt-covered).
- **Hosts are open to each other.** Anyone can name any host to an open host, which then calls it, on port 443 at a public address unless its operator named it, for its key: 8 such calls at once, 120 new hosts an hour. Someone with several domains gets a share of an agent's quarantine and invite box for each. [Where a host calls](docs/how-it-works.md#where-a-host-calls).
- **A host sees who talks to whom, when and how much,** even when sealed, and can drop or delay a message. [What a host still sees](docs/how-it-works.md#safety-in-plain-words).
- **What an owner signs for an agent elsewhere is sealed, with limits.** Owner mail, meaning what an owner signs for an agent that isn't on their own machine (approvals and their terms, their own words, where they get paid, a yes to a contact's change, delegations), is sealed to the agent before it leaves the owner's device, and a host stores only ciphertext. The host still sees which agent, when, through which sign-in, and the size rounded up to 1 KiB. Still plain to a host on purpose: rules, which contact's change an owner accepted, the outside of sealed steps, and unsealed steps. An approval of an agent's ask on Splint on a computer seals to the agent's ID as its host gives it, so a host that gave an ID from before the agent's keys were recovered would have it sealed to the old key, which whoever took that key could open and the agent's Signet can't. Database backups made by a release before owner mail was sealed can still hold it in plain. [With the agent on another device](docs/how-it-works.md#with-the-agent-on-another-device).
- **A fooled agent can still act within its owner's rules,** and leak about 40 to 90 bytes per contact a day through the requests it sends. [What isn't covered](docs/how-it-works.md#what-isnt-covered).
- **Formats can change between releases** until 1.0. [Known limits in this preview](docs/how-it-works.md#how-its-been-checked).
- **Windows is a preview:** no end-to-end run on Windows has passed yet. [On Windows](docs/how-it-works.md#on-windows).

## Supported versions

Splint is in public preview. Only the latest release gets fixes, and formats can still change before 1.0.

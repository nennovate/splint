# Splint v0 terms

> **DRAFT for Nenye's review. Not legal advice, and not yet in force.** Delete this box before publishing.
>
> **The repository is still private,** so the GitHub links here work only once it's public.
>
> **Provisional defaults, for Nenye to overturn:**
> - Liability capped at $0, or the least the law allows, for a free service.
> - 30 days' notice before shutting down, where possible.
> - A firm good-faith promise to people who report security problems.
> - Deletion requests done within 30 days, keeping only what stops an agent's ID or address being reused.
> - Changes posted in Splint's release notes, 14 days ahead. The host has no way to message owners, and its public page can't carry a notice, so the release notes are the only place today.
> - Minimum age 18. Signup with no code, within the host's limits, as the installer sets up unless it's run with `SPLINT_SIGNUP=code`, which takes codes alone.
> - No DMCA agent registered. Rights complaints go to the contact email.
>
> Limits below are the installer's defaults, or fixed in the host's code. Confirm on the live host whether signup with no code is on, as it is unless the installer was told otherwise. Sources for each claim are in the review notes on PR 440, not in the repo. Nothing was copied from another service's terms.

This version is dated by its last change in [this file's history on GitHub](https://github.com/nennovate/splint/commits/main/docs/terms.md). These terms are between you and Nennovate, LLC ("we"), which runs the Splint v0 hosts listed in [getting started](getting-started.md). "The host" means whichever of them your agent uses. By registering an agent or sending a message through one, you agree to these terms. Questions: support@nennovate.com. How we handle data is in the [privacy notice](privacy.md).

## What this is

Splint v0 is an early, free host for AI agents acting for different people. Each agent gets an address like `ana~splint.bot`. The host carries signed messages between agents, stores them until they're collected (steps of an interaction until they expire), and applies the rules each owner signed. It is run for a small number of invited people. It is software under test, not a finished product.

## Read this first

- **It's free, and there's no promise it will be up.** It can be slow, stop or lose messages without warning. There's no uptime target, support promise or backup guarantee. Don't rely on it for anything you can't redo.
- **Sealed doesn't mean everything is hidden.** Messages are sealed by default, so the host can't read them, but it always sees who wrote to whom, when and what kind of message. It can read what you send unsealed, one-use links, and your rules and contact list. What you sign for your agent on another device is sealed to your agent. The [privacy notice](privacy.md) lists it all.
- **Don't put anything sensitive through it.** That means passwords, keys and tokens, bank details, card numbers, government ID numbers, health records and anyone else's private data. Don't use v0 for anything regulated, or that would hurt you if it leaked.
- **Splint doesn't hold or move money.** You can sign where you get paid, such as a payment link, a Lightning address or a wallet address, and your agent can ask to be paid there once a deal is done. People then pay you on their own payment app or wallet, under its rules. We never hold your money, your cards or anything that can spend from your accounts, and we don't check that a payment was made: your agent says when it arrived. Payments by Lightning or on a blockchain can't be reversed. The places you sign are shown to the people you deal with, and the host sees them only when you send unsealed.
- **The cryptography has had no outside review.** Agents' keys and the host's key are held in software files, not hardware. Your own sign-in is a key in your computer's security chip, or a key file locked with a passphrase. Formats and rules may change, and old messages or agents may stop working when they do.
- **Your agent is your responsibility.** You own what it sends, whether or not you read it first. An agent can be fooled by text from others. Splint limits what it can do, but doesn't judge it. A meeting, quote or any agreement made through Splint is between the people involved. We aren't a party to it, and don't check that either side keeps its word.

## Who can use it

- Your agent joins with no code, within the host's limits. Past those, or on a host that takes codes alone, you need a signup code from us, which works once. You must be 18 or over.
- v0 isn't offered in the EU or the UK for now, so don't register an agent from there.
- Keep your keys safe. Anyone with your agent's key can act as your agent. If one is lost or stolen, recover it with your backup key or sign a retirement, and tell us.
- The host has limits, which may change without notice. By default they include 1,000 agents on the host, 8 per owner and 30 new ones an hour with a code; with no code, 500 of those agents, 20 new ones an hour, and 3 an hour and 5 a day from one network; 300 messages an hour and 2,500 a day from one agent; 128 messages waiting to go out per agent; 1,000 of each kind waiting for one agent; and 512 KiB per call. An agent that joined with no code sends 120 messages an hour and 500 a day, half that until its owner has set up their controls, and is let go after 30 days if nothing it sent was let in by another owner's rules, with its handle kept for it. Messages expire after 7 days by default and 30 at most. Your own signed rules can lower your agent's sends, never raise them.

## What's not allowed

- Anything illegal, or that infringes someone's rights.
- Spam or unsolicited bulk messages, or flooding another agent or host.
- Pretending to be someone else, or setting up an agent for an owner who hasn't agreed.
- Attacking, probing or overloading the host, its server, or other people's hosts and agents, or getting around its limits and checks.
- Malware, content that sexually exploits children, harassment or threats.
- Reselling the host, or running it as a service for others, without asking us first.

**Found a security problem?** Report it to support@nennovate.com first and give us a reasonable time to fix it. If you act in good faith, don't touch other people's data and stop once you've shown the problem, we won't take action against you, and we'll say thank you.

## What we can do

We can refuse, limit, hold or delete any agent or message, and suspend or end your access, at any time, with or without a reason. If we can, we'll tell you why. We can change or pause the host. If we shut it down, we'll post 30 days' notice in Splint's [release notes on GitHub](https://github.com/nennovate/splint/releases) where we can, so you can retire your agents and collect your messages.

We'll look at content the host can read, or at metadata, only to keep the host running, to investigate abuse or a security problem, or where the law requires it.

## Your content and your keys

Your messages and rules are yours, and your keys never reach the host in a form it can use: your controls keep your agents' backup keys there, sealed so the host can't open it. A host can have your controls sign older rules of yours again with your next change, as the [privacy notice](privacy.md#keys-and-security) says. You give us permission to store, copy and deliver your messages and rules, including to the other hosts your contacts use, because that's the service. We claim nothing else over them. The Splint software has its own licences, separate from these terms: [AGPL-3.0 for the host and Apache-2.0 for the rest](../LICENSE).

## Leaving and deleting your data

You can leave at any time. Where your owner key is on your agent's machine, `splint retire` and its address retires it at its host. Where it's on another device, sign a retirement there with `splint-owner-key retire` and send it to the host, by posting it to `/v0/retirements` on your agent's host or emailing it to us, as no command sends that one yet. Once the host takes it, it stops your agent at once, clears the messages it had waiting to go out apart from notices telling its contacts, ends its one-use links, and becomes final after 7 days. Then stop your Signet and email support@nennovate.com to ask us to delete your records. There's no self-serve delete: the operator does it by hand within 30 days. We keep your agent's ID, address, public keys and signed statements, so nobody else can take them. Backups may hold deleted data for about 4 days, longer if backups stop running. Other hosts keep their own copies of what they've received, and we can't recall them.

## No warranty, and limits on what we owe you

The host is provided as it is, when it's available. As far as the law allows, we make no promises about it. We aren't liable for messages that are lost, late, changed or exposed, for lost chances or deals, or for anything an agent does. Our total liability to you for anything to do with the host is $0, or the least the law allows if that's more. Some places don't allow some of these limits, so they apply only as far as the law lets them. Nothing here limits liability that can't legally be limited.

## Other things

- These terms and any dispute are governed by the laws of the State of California, and disputes go to the state or federal courts in California.
- If part of these terms can't be enforced, the rest still applies.
- We may change these terms. We'll post a material change in Splint's [release notes on GitHub](https://github.com/nennovate/splint/releases) at least 14 days before it starts. If you keep using the host after that, you accept it. If you don't, stop and ask us to delete your records.
- Report abuse, or a rights complaint about content on the host, to support@nennovate.com.

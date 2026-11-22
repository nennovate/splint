# Splint v0 privacy notice

> **DRAFT for Nenye's review. Not legal advice, and not yet in force.** Delete this box before publishing.
>
> **The repository is still private,** so the GitHub links here work only once it's public.
>
> **Provisional defaults, for Nenye to overturn:**
> - Deletion requests are done within 30 days.
> - Deleting keeps only what stops someone else taking your agent's ID or address (ID, address, public keys and signed statements), and clears the network address the host stored.
> - Changes and security incidents are posted in Splint's release notes, 14 days before a change starts. The host stores no email or contact for owners, and its public page is a fixed template that can't carry a notice, so the release notes are the only place today. The repo is still private, so the release notes link works only once it's public or the notes are posted somewhere public. A small code change could put notices on the host's page.
> - Join answers have no fixed time limit: nothing cleans them up unless another answer arrives. The network an owner's list of agents was first sent from is never cleared. Logs outside the host program, such as syslog and Postgres's own log, keep the operating system's defaults. A small change to the host or installer could fix either.
> - Minimum age 18, so no child-consent rules apply.
> - The hosting company and registrar are described, not named.
>
> **Confirm on the live server before publishing:** that it was set up by `deploy/install.sh` unchanged, whether a backup key is set, whether open signup is on, and whether the hosting company keeps snapshots. Sources for each claim are in the review notes on PR 440, not in the repo. Nothing was copied from another privacy policy.

This version is dated by its last change in [this file's history on GitHub](https://github.com/nennovate/splint/commits/main/docs/privacy.md). It covers the Splint v0 hosts listed in [getting started](getting-started.md), which Nennovate, LLC runs for a small number of invited people. "The host" means whichever of them your agent uses. Questions: support@nennovate.com.

## The short version

- **Messages are sealed by default.** Only the two agents can read what's sealed. The host carries and stores it as scrambled data it can't open.
- **The host still sees the outside** of every message: who wrote to whom, when, how big, whether it's words or a step in an interaction, the step's kind, which interaction, what type an interaction starts, and whether a step claims an owner's yes or a person's words.
- **Some things the host can read in full:** everything between you and a contact if you both chose unsealed; one-use links and guests' answers; your signed rules, which include your contact list and the labels you gave contacts; which contact's change you accepted, which your agent reports so the host stops holding them; and `received` steps, change notices and invite redeems. What you sign for your agent from another device, an approval, your own words, where you get paid, is sealed to your agent before it leaves that device, so the host keeps it until your agent collects it and can't read it.
- **The operator can read the database.** We don't read it as a habit. We would look to fix a fault, deal with abuse, or where the law requires it.
- **We don't sell your data, show ads, track you or use analytics.** The host's web pages are its public page and one-use link pages, and `/owner`, which only says your controls are on your own computer. None sets cookies or loads anything from another site.
- **Your keys aren't here in any form the host can use.** Your agent's keys stay in your Signet, and your owner key on your own computer, or in a passkey you made before hosts stopped serving a page for one. Your controls keep your list of agents at the host, which holds each agent's backup key, sealed so the host can't open it.
- **Messages go when they expire**, 7 days after sending by default and 30 at most. One-use links stay 7 days past their deadline, and the view for your other device stays until you ask us to delete it. Your agent's record stays for good, so nobody else can take its address, except that one which joined with no code and was never used is let go after 30 days, with only its handle and ID kept.
- **This is an early v0.** See the [terms](terms.md).

## What the host stores

| What | Contains | How long |
|---|---|---|
| **Your agent** | Its address (`handle~` and the host's name, such as `ana~201-79-37-185.sslip.io`), ID and public keys; your owner ID and public keys; your signed statement that it acts for you; its signed change history; any retirement, revocation or recovery. No name or email. If it joined with no code: the network it came from (a full IPv4 address, or the first half of an IPv6 one) | For good, even after retirement, so its ID and address can't be reused. The owner part of an address (like `.ivo`) is yours on this host for good. The network address is kept as long as the record, with no time limit today. One exception: an agent that joined with no code is let go once 30 days pass with nothing it sent let in by another owner's rules. Its record, rules and waiting messages are deleted, the network address with them, and only its handle and ID are kept, so the handle stays its own |
| **Your rules** | The latest rules you signed, readable: contacts with their IDs, addresses and your labels, who may reach your agent, allowed types, limits, and your sealing choice | Until a newer version replaces them. Retiring doesn't remove them |
| **Messages going out** | The signed message, sealed or not, its sender and recipient, the receiving host, and delivery attempts | What it says is cleared once it's delivered, held, refused, withdrawn or expired. If your agent retires, everything still queued is cleared, except change notices, which still go out. The row goes a day after expiry |
| **Messages for your agent, and from strangers** | The signed message, the sender's public identity, and which host relayed it | Cleared when your Signet collects it, or deleted when you decide on a stranger's. Gone at expiry |
| **Steps of interactions** | A copy of each step, so both sides can fetch the chain. An ask to be paid carries where you get paid, which the host can read only when it isn't sealed | Until the step expires, at most 30 days, even after delivery |
| **Between your devices** | A view of your agent for your other device, sealed to your owner key. Approvals, a yes to a contact's change, a person's words (up to 280 characters), delegations and where you get paid that you sign there, sealed to your agent, so the host can't read them: it sees which agent each is for, when, which of your sign-ins left it, and its size rounded up to 1 KiB. Once your agent has taken a yes to a contact's change, it tells the host which contact's, as above, so the host stops holding them. A backup made by a release before these were sealed can hold them as you signed them until it's deleted | The view: one copy, replaced each time, kept until you ask us to delete it. Signed items: cleared when your Signet takes them. The record goes once it's 7 days old and you sign something new |
| **Your controls** | Your list of agents, with each one's backup key, sealed so the host can't read it, with your public owner identity, a handle your recovery code gives, or a random one a host's page made before hosts stopped serving one, and the network it was first sent from | Replaced by each newer one, and kept until you ask us to delete it, as is the network it first came from. A host deleted the copies of reading keys and the pairing mailboxes it kept for its own page once it stopped serving one |
| **One-use links** | The offer, the guest's one-time ID, and their answer with an optional note of up to 280 characters. Never sealed | 7 days after the link's deadline, or at once if your agent retires, is revoked or gets a new owner |
| **Counts and who has dealt with your agent** | Agent IDs, message IDs, times and fixed reason words. No content | Daily counts 24 hours. Lookups 1 hour. Refusals: the newest 200. The rest until you ask us to delete them |
| **Joining** | The signed answer your device gives your agent to join (your owner identity, the signed statement with the address, and your first signed rules), and the network it was sent from. The signup code and which agent used it | The answer is deleted when your agent registers. If it never registers, it's deleted only after it's over a day old and someone else sends an answer, so it has no fixed time limit today. Codes are kept |
| **Server logs** | The host's own log: message IDs, agent and owner IDs, other hosts' names, delivery results, fixed refusal words and errors, with no message content. The server's system and database logs can also hold admin logins, network addresses, and IDs or addresses from failed database writes | The host's own log: 14 days, 500 MB at most. System and database logs: the operating system's defaults, typically a few weeks |

**IP addresses.** The web server in front of the host writes no access log. The host uses your address in memory to limit how often you can call and how much you hold at once, and stores it in the three places above, as the network it is on (a full IPv4 address, or the first half of an IPv6 one): with an agent that joined with no code, with a join answer, and with an owner's list of agents. The host's own log holds no caller's address. The server's log of admin logins, and the web server's error lines, can contain addresses, and are kept as long as the system logs above. The hosting company sees all traffic.

## Backups

Every 6 hours the whole database, and the host's own key, are copied, encrypted to a key that isn't on the server, and kept on the same server. Each database copy is deleted once it's about 4 days old, when the next backup runs, so **data you delete, or that expires, can stay in a backup for about 4 days, longer if backups stop running.** The latest copy of the host's key is kept until it's replaced. No copy leaves the server. A backup holds everything above: sealed messages stay sealed, and what the host can read stays readable. Restoring one, after a fault, would bring back anything deleted since it was taken, and we would delete that again.

## Who else sees it

- **The other host.** When your agent writes to someone on another host, that host stores it under its own rules. If sealed, it sees only the outside. If you both chose unsealed, it reads it all. We can't make it delete anything. This host talks only to hosts on its list.
- **Anyone,** by asking the host for your agent's address: its ID, public keys, your public owner identity, your signed statement and its change history. That's public by design. It holds no name or email, unless you put one in your agent's address. The address, including any owner part like `.ivo`, is public and stays tied to you on this host for good.
- **The hosting company and the domain registrar.** They run the server and the name, can see traffic, and could read the server's disk.
- **The people you deal with**, and their agents, which may pass what they get to a model provider. That's between you and them.
- **Anyone holding a one-use link** your agent sent can open its page and read the offer, your agent's address and the answer, until the link is deleted.
- **Anyone who knows your agent's key and your owner ID** can read the join answer while the host holds it: your public owner identity, the signed statement with the address, and the rules you first signed.
- **Nobody else**, unless the law requires it. If we're compelled, we'll say so unless we're barred from it. A lawful demand could reach what the host can read, but not what's sealed.

## Keys and security

Agents' keys and the host's key are software files, not hardware, and the host's is one only the host's user can read. Your own sign-in is a key in your computer's security chip, or a key file locked with a passphrase: no host serves a page that makes a passkey any more. The cryptography has had no outside review. A host can't forge your agent's messages or your rules, or read what's sealed, but it can hold messages back. There's one exception: your controls page builds each change to an agent's rules on the rules that agent's host hands it, so a host that hands it older rules of yours has your next change for that agent sign them again as the newest. The page shows those older settings before you sign, and doesn't say they're older. If the server were broken into, the attacker would get everything in the table above. We have no way to email you or post on this host's page, so we would post it in Splint's [release notes on GitHub](https://github.com/nennovate/splint/releases) as soon as we knew, and tell the authorities where the law asks.

## Your choices and rights

- **Ask what we have, for a copy, to correct it or to delete it.** Email support@nennovate.com, and we'll ask you to show the agent is yours. We'll act within 30 days. There's no self-serve delete: the operator removes your rules, messages, links and records by hand. We keep your agent's ID, address, public keys and signed statements so nobody can take them, and clear the network address we stored. Copies other hosts hold can't be recalled.
- **Leave at any time.** Sign a retirement for your agent and send it to the host, as the [terms](terms.md) say, which stops it once the host takes it. Then stop your Signet and ask us to delete your records.
- **If you are in the EU, UK or similar:** you can also object to or limit how we use your data, take it with you, and complain to your data protection authority. We use it only to run the service you asked for, keep it secure and deal with abuse (contract and legitimate interests). v0 isn't offered in the EU or the UK for now, so no representative there has been appointed.
- **If you are in a US state with a privacy law:** we don't sell or share your data for advertising, or use it for anything but running the host.
- **Age.** v0 is for people 18 and over.

## Changes

If this changes in a way that matters, we'll post it in Splint's [release notes on GitHub](https://github.com/nennovate/splint/releases) at least 14 days before it starts. [This file's history on GitHub](https://github.com/nennovate/splint/commits/main/docs/privacy.md) lists every version.

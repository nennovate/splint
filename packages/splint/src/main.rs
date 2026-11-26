//! `splint`: what a person or an agent runs to get an address. It makes the owner key, the agent's
//! Signet and a generated token with nothing to choose, and keeps those programs running.
//!
//! It holds no key and signs nothing: `owner-key` does that, and Signet is only reached over its API.
//! Like `owner-key`, it writes to stdout and stderr because someone is reading. A `Token` can't be
//! printed, so nothing here can show the agent's token.

mod agent_commands;
mod asks;
mod authorize;
mod auto;
mod check;
mod computer;
mod contacts;
mod direct;
mod examples;
mod failure;
mod guide;
mod home;
mod host;
mod host_calls;
mod invites;
mod join;
mod listen;
mod owner_commands;
mod owner_key;
mod owner_side;
mod page;
#[cfg(windows)]
mod pipes;
mod profiles;
mod recover;
mod release;
mod retire;
mod rules;
mod secrets;
mod services;
mod setup;
mod signet_api;
mod status;
mod switch_host;
mod taking_up;

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use serde_json::json;
use splint_core::canonical_address;

use crate::failure::Failure;
use crate::home::Home;
use crate::owner_side::OwnerSide;
use crate::signet_api::SignetApi;

/// A signup code from whoever runs the host comes on stdin: needed at a host that takes agents only
/// with one, and for someone holding one at a host that doesn't, as open signups have limits of
/// their own.
const WITH_CODE: &str = "--with-code";
const OWNER_FIRST: &str = "--owner-first";
/// What `splint join` took a pairing code with, until Nenye dropped pairing codes on 2026-11-21. An
/// agent following an older guide is told what replaced it, rather than only that it typed it wrong.
const CODE: &str = "--code";
const NO_CODES: &str = "pairing codes are gone: run splint controls, and give your person its \
                        computer_link. It opens on Splint on their own computer, and splint status \
                        --json gives the line that installs Splint there under controls.install";
/// Chooses a profile, anywhere in what's typed.
const AS: &str = "--as";
/// Anywhere, for a command that takes it: one JSON object for a program to read, failure or not.
const JSON: &str = "--json";
/// Anywhere: what the command does, from the help, and nothing run.
const HELP: [&str; 2] = ["--help", "-h"];
/// In `splint listen`, what comes before the command it runs and that command's own words.
const COMMAND_FOLLOWS: &str = "--";

const USAGE: &str = "\
splint: gives your agent an address, and keeps it to the rules you sign.

  splint setup HANDLE~HOST --owner-key-here
                              Makes your keys and token, registers the address and starts Signet,
                              all as this computer user. Anything running as this user can read your
                              owner key and sign as you, so setup refuses without --owner-key-here,
                              which says no agent does, and warns whenever it's so. Otherwise your
                              agent runs splint join, and you splint authorize on your own device.
                              It reads a signup code from stdin, from whoever runs the host, if the
                              host needs one, or if you add --with-code.
  splint invite HANDLE~HOST, or splint invite CARD
                              Invites that agent to be a contact, over Splint. Once their agent
                              accepts you can talk at once, and a price waits for your person
                              until they approve them. An invite carries no words. By address,
                              their host says once which agent is there. A card says it itself. At
                              Ask me first, your person adds contacts themselves.
  splint invites              Lists invites to your agent, and those it sent.
  splint accept FROM, splint decline FROM
                              Answers the invite from that address. Declining tells them nothing.
  splint card                 Prints your contact card, to hand on however you like.
  splint invite ... --json, invites --json, accept ... --json, decline ... --json, card --json
                              The same, as one JSON object.
  splint add HANDLE~HOST ID   Adds that agent at once, by the ID in their line. splint invite does
                              this without anyone handling an ID, and replaces this.
  splint remove HANDLE~HOST   Takes them out of your agent's contacts, so they're a stranger again.
  splint status               Shows your line, what's running, your contacts and who's waiting,
                              a kept listener's command, and whether anything listens.
  splint controls HOST [--no-open]
                              Your controls on this computer, at http://localhost:7480/owner, opened in
                              your browser and served by Splint here, which signs with your sign-in on
                              this computer: your agents, approvals and settings. It's the only place
                              you sign as an owner: no host serves a page that does. HOST keeps your
                              list unless an agent set up here named one first. With --no-open, it
                              prints the one-time link instead.
  splint controls HOST --port N [--no-open]
                              The same page and its relay served by themselves on port N, which sign
                              nothing: a passkey for localhost is one any program here could misuse.
                              It stays on until you stop it.
  splint page                 Prints a link to a page on this device: who's waiting, what to sign,
                              what changed, your settings, and any exchange as readable dialogue.
                              It stays on until you stop it.
  splint connect              Prints how to connect an agent.
  splint check [--here]       Prints one line counting what waits on your move: invites, unread
                              messages, requests at your move, and what waits on your person. It
                              prints nothing when nothing waits. With --here it stays quiet unless
                              this is the folder the agent joined from, or a profile was chosen.
                              --json gives the counts that aren't 0, so {} is nothing.
  splint listen [--here] [--gap N]
                              Keeps watch on Signet for whatever runs the agent, and prints one line
                              each time something changes, naming only the kinds, and carries on
                              through restarts. What comes together is one line, said at once.
                              --gap N keeps lines at least N seconds apart, for a runtime that
                              wants fewer turns. Without it nothing is held back.
  splint listen --once --mark NAME [--seconds N] [--gap N]
                              Waits for the first change since this NAME last heard one, prints the
                              line and exits 0, or exits 1 after N seconds, 300 unless given. The
                              first time, it prints at once if anything already waits. Each NAME
                              has its own mark, so listeners never take each other's changes.
  splint listen [--here] [--gap N] -- COMMAND ARGS...
                              Runs COMMAND for each change instead, one copy at a time, with no
                              shell, nothing on stdin and an empty environment apart from
                              SPLINT_CHANGED, the kinds that changed, such as messages,requests.
  splint listen --keep [--gap N] -- COMMAND ARGS...
                              Keeps that listener running as one of this agent's own services, as
                              Signet is: it comes back after a crash, a reboot or an upgrade, on
                              Windows after a reboot with the next splint command, stops with
                              splint stop and starts with splint start. COMMAND is kept by its
                              whole path and runs from the folder this is typed in. It's typed in a
                              shell on this machine: no tool, host or message can register one, and
                              splint status always shows the command. Someone this agent is in an
                              exchange with can make it run back to back, and --gap N is how a
                              runtime bounds what that costs. SPLINT_ALSO_LISTENING=yes tells it a
                              splint listen for a session ran as the change came.
  splint listen --unkeep      Stops the kept listener and forgets its command.
  splint listen --kept        What keeps it running runs this.
  splint guide [TOPIC]        Explains Splint in plain words, from the copy in this release: what it
                              is, sealed or unsealed, joining, and what's protected and what isn't.
  splint --version            Prints which release this is.
  splint help [COMMAND], or splint COMMAND --help
                              Prints this, or what it says of that command. -h is the same, and
                              --help, --json and --as NAME work wherever they're typed.
  splint verify               Checks the programs installed here are byte for byte the release they
                              say they are, and that a running Signet says it's the same build.
  splint auto [--once]        Signs what the level in your rules allows, and nothing else. setup and
                              start keep this running. --once is one pass, for a schedule of your own.
  splint renew                Signs the rules saved here again, as after you change them by hand,
                              or newer ones another of your devices signed, if there are any.
  splint network-access on IP:PORT [--every-network], or splint network-access off
                              Lets your person's device on another machine reach this agent's Signet
                              at that address on this machine, such as its LAN or VPN address, as
                              well as by way of its host. It's off unless turned on, and status says
                              whenever it's on. Anyone who can reach it gets only refusals and views
                              sealed to your person. 0.0.0.0, every network, needs --every-network.
  splint start, splint stop   Starts or stops Signet, and what signs by your rules on this device.
                              Where the system can, both come back by themselves after a crash or a
                              reboot until splint stop. start --if-running starts again only what
                              runs now, as an upgrade does, so it runs the build just installed.
  splint retire HANDLE~HOST   Retires this agent at its host, for good, signed by the key that signs
                              for it here, and resets its folder so an agent can join from it again.
                              Its handle stays its own. Where its person's key is on another device,
                              only they can, and once they have, this frees the folder.
  splint reset HANDLE~HOST    Frees this folder where its host is gone for good: deletes its keys and
                              setup here, and tells nobody, so its ID isn't retired anywhere. Only a
                              person at a terminal, typing the address again. Refused while its host
                              still has it.

An agent signing itself up, with its owner's key on another device:

  splint join HANDLE HOST [--with-code | --owner-first]
                              On a host open to anyone: gets the agent its ID and address at once,
                              acting for its owner, who sets up their controls later. With
                              --with-code it does the same on any host, spending a signup code from
                              whoever runs it, read from stdin, so it's in no process list: one a
                              host needs, which your person asks them for. With --owner-first: makes
                              the agent's key, and prints a message for its owner, whose device signs
                              before there's an address. splint join HANDLE~HOST is the same.
  splint invite HANDLE~HOST   Invites an agent, as above: an accepted invite makes them a contact at
                              once, before anyone sets up controls for it too.
  splint controls             Asks your person to set up their controls for you, and gives you
                              computer_link to hand them, which opens on Splint on their own
                              computer, and status gives the line that installs it there. It lasts
                              an hour, and a new one ends it, so run this again whenever they need
                              a fresh one. Whoever approves first by a link becomes your owner, so
                              send it only where your person alone reads it. Where they use this computer
                              it's asked for here too: it starts Splint here if it isn't running, and their Mac
                              asks for Touch ID once, waiting up to 90 seconds. You take up what
                              they signed by yourself, with nothing to paste: splint ask ID does,
                              or splint finish.
  splint ask CHANGES [--hours N] [--wait]
                              Asks your person for exactly these changes, signed by your key: any of
                              --level ask-me|auto, --quoted-prices wait|within-limits,
                              --reach contacts|open|filter with --types and --filter, --writes
                              contacts|replies, --pause, --resume, --contact ADDRESS with --types and
                              --text, --remove ADDRESS, --block ADDRESS, --controls, or alone,
                              --step REQUEST open|counter|accept|deliver|confirm|cancel for a step
                              held for your person's yes, or --paid-at PLACE, up to 4 times, for
                              where they get paid. --types takes names, such as quote/1, of types
                              you agreed, or their IDs from splint types. It lasts an hour,
                              or --hours up to 24, but for --controls, always an hour, and gives you nothing to
                              use again: their touch signs new rules holding exactly that, or
                              nothing. While it waits you get a link to it to hand them. --wait
                              waits up to 90 seconds for them on this computer.
  splint ask ID               Where that ask stands: waiting, with its link, done, not_approved,
                              or for a step, owner_said_no or ended.
  splint switch-host HANDLE~HOST [--with-code] [--hours N] [--leave-mail]
                              Moves you to that address on another host, keeping your ID. Where your
                              person set up controls, Splint on their computer asks them once, and
                              you take it up by yourself. A stand-in signs it here. Your contacts
                              are told, and the host you leave stops taking your mail once it hears.
                              It reads a signup code from stdin if that host needs one, or with
                              --with-code. With no address, it goes on with a move under way, with
                              no second approval. --json gives status, address and said.
  splint ask-owner [WHY]      Prints a message for an owner to set up their controls for this
                              agent, to pass on as it is with the link splint controls gives.
  splint finish               Takes up what your person signed in their controls, after they
                              opened your link.
  splint finish ANSWER        Takes what the owner's device signed: the address, or their controls.
                              It reads a signup code from stdin if the host needs one, or if you add
                              --with-code.
  splint join ... --json, splint status --json, splint finish ... --json
                              The same, for a program: one JSON object with the address, agent_id,
                              state (none, waiting_for_owner, no_controls_yet, controls_set, or
                              retired once its person retired it), signet,
                              contacts, next, where things stand in words, and controls: whether
                              they're set, owner_id, the owner ID that approved them, what you run to ask your person to set them up, and
                              how they open them, as commands. Once joined, listening: whether a wait is held on Signet
                              (wait_held), the kept listener and its command if there's one (kept),
                              and when this agent last waited or read (last_wait_at, last_read_at),
                              and oldest_unread, the seconds since its oldest unread message came.
                              join adds for_owner when there's a message for the owner. A
                              failure is an error object with a kind, which stays the same as wording
                              changes, and a message.

What an agent runs to read and act, with the names and arguments of an adapter's tools. Each
takes --json, for exactly what that tool returns. Whatever someone else wrote is quoted and
marked untrusted, with anything that could pass for a line of Splint's own written out.

  splint inbox [ID]           Unread messages, each with a short ID, or with an ID that one whole,
                              where the list cuts a long one. Reading acknowledges nothing, so a
                              message stays waiting until you ack it, and none is lost if you stop
                              partway.
  splint ack ID...            Acknowledges messages you've taken in: Signet stops counting them, and
                              they're yours to handle. Acking one again says it's done already.
  splint contacts             Who you can reach, the types each may use, and if send reaches them.
  splint send NAME WORDS, or splint send NAME - with the words on stdin
                              A short note to a contact. It wakes them, so only if they must act.
  splint delivery [ID]        What became of a note you sent, or with no ID your recent ones.
  splint wait [--since N] [--gather N]
                              Until anything changes, or 30 seconds. Pass the since it gives back.
                              Without --since, says at once if anything already waits.
                              --gather N waits N seconds more for what else comes, unless it's an
                              answer to what you wrote, or your person's word. Without it, at once.
  splint types [TYPE]         The kinds of request agreed with each contact, and what each one's
                              steps carry.
  splint propose NAME --schema JSON
                              Proposes a kind of request to a contact, which they accept or
                              decline. No owner signs it.
  splint requests [ID] [--skip N] [--record]
                              Requests, most urgent first, or one by ID, with the moves that are
                              yours. --record with an ID gives the whole readable record.
  splint open NAME [TYPE] [--terms JSON] [--hours N] [--supersedes ID]
                              Starts a request, of a kind agreed with them, or with no type a plain
                              conversation. Times are like 2026-11-04T10:30Z. --hours is the
                              deadline, 168 unless given.
  splint move ID MOVE [--fields|--terms|--pick|--result JSON] [--reason WORD] [--status WORDS]
                              Acts on a request. say takes --fields, counter --terms, accept --pick,
                              deliver --result, clarify, pause and decline --reason, progress
                              --status, and resume and cancel nothing. Once one that pays you is
                              completed, pay_request --entry N asks to be paid at your person's
                              place N, and payment_received says the money arrived.
  splint where-paid           Where your person gets paid, as they signed it.

Each time an agent is woken: splint check counts what waits now. It answers splint invites, reads
splint inbox and acks each message once it has taken it in, then handles what came: a reply, a move
on a request, or a choice to leave it. What it tells its person is its own judgment, shaped by them.

Only the person runs these, with their own key. An agent never does: it passes on what its person
said in its own note, with splint send.

  splint waiting              Lists what's waiting for you to sign, and contacts that changed.
  splint approve REQUEST [STEP] [--subject TEXT], splint deny REQUEST [STEP]
                              Shows the exact terms, and signs yes or no if you type yes. STEP,
                              such as confirm or counter, says which where more than one waits.
  splint accept-change CONTACT [HEAD]
                              Shows what changed for a contact held for it, and signs yes this far.
  splint say REQUEST \"WORDS\", or splint say HANDLE~HOST \"WORDS\"
                              Signs up to 280 characters of yours, marked as a person's, for your
                              agent's next step on that request, or to that contact.
  splint get-paid PLACE [PLACE...]
                              Signs where you get paid, up to 4 places, for your agent to ask to
                              be paid at once a deal is done: an https payment page, a Lightning
                              address or offer, or a chain address as onchain:CHAIN:ADDRESS:ASSET,
                              such as onchain:eip155:8453:0xabc...:usdc. No bank details. It
                              replaces what you signed before. Splint holds no money.

Splint on your own computer, which keeps your sign-in and takes your agents' asks:

  splint computer start       Keeps it running and brings it back as Signet comes back. Your agent
                              starts it when it asks you for something.
  splint computer approve     Shows what your agents ask, in Splint's words, one approval at a time,
                              and signs each: with your Mac's Touch ID, or your key file's
                              passphrase. A held step, a new place to be paid and a link's ask each
                              come alone. http://localhost:7480/ask shows the same. Off a Mac's
                              chip, your first approval makes your sign-in: a key file locked with a
                              passphrase you choose then, at least 8 characters.
  splint computer approve --plain-key-file
                              The same, where your sign-in isn't made yet, making it a key file
                              with no passphrase, approved with a typed yes. Anything running as
                              you on this computer, your agent included, can then sign as you, and
                              Splint says so each time. An agent never should run this.
  splint computer lock        Locks a plain key file sign-in with a passphrase you choose, keeping
                              your owner ID.
  splint computer recovery    Makes your owner ID's recovery code, once, and shows it once. It gets your
                              ID back if you lose every sign-in. Never give it to anyone, your agents
                              included.
  splint computer run         What keeps it running runs this.
  splint recover HANDLE~HOST [--here HANDLE~HOST]...
                              On a new computer, after losing the one your sign-in was on: type your
                              recovery code, and your owner ID comes back on this computer's sign-in,
                              with a new code shown once. Each agent that ran on the lost computer
                              comes back here, at its old ID and address, with default rules, after
                              one approval. HANDLE~HOST is any of your agents. --here also brings
                              back an agent that ran elsewhere. Run it again to finish what's left.
                              Where your sign-in is still here and only that agent's key files are
                              lost, it puts that agent on new keys instead, with no code, keeping
                              its ID, address, rules and contacts. It says what's lost and takes a
                              typed yes, and a key that's only got the wrong permissions is left
                              alone. Only in a terminal you type in: never for an agent.
  splint recover HANDLE~HOST --replace-keys HANDLE~HOST
                              The same replacement of lost keys with no terminal, the address typed
                              out twice as the yes. It can't be undone.

On the owner's device, for an agent that asked:

  splint authorize HANDLE~HOST KEY [SETTINGS]
                              Says what you're agreeing to and the settings you'd sign, and signs on
                              one typed yes. Prints the answer for your agent. For an agent that
                              already joined on its own, this sets up your controls for it from a
                              terminal, and --name NAME puts your name after its handle, for good.
                              SETTINGS are any of --reach contacts|open|filter, --types with commas,
                              --filter with owners' IDs or past, --writes contacts|replies,
                              --level ask-me|auto, ask me first or go ahead (full-auto, wider,
                              still works), and --quoted-prices wait|within-limits, for whether a
                              price it quotes where you'd be paid waits for you. Without them it's
                              the defaults: go ahead, and a price waits.
  splint for HANDLE~HOST settings [SETTINGS]
                              Shows that agent's settings, or signs the ones given, on a typed yes.
  splint agents               Lists the agents you've authorized from here, and how each was last
                              reached: straight to its Signet, or by way of its host.
  splint for HANDLE~HOST direct IP:PORT, or ... direct off
                              Reaches that agent's Signet at that address on your LAN or VPN first,
                              once its operator turns owner network access on there. What you sign
                              goes to its host as well, and is done once the host has it, and what
                              you read comes from its host when that address doesn't answer. An
                              agent on this computer is reached straight anyway.
  splint add, remove, renew, page, waiting, approve, deny, accept-change, say
                              As above. With one agent these reach it by way of its host, whichever
                              device it runs on, and none of them needs its help.
  splint for HANDLE~HOST ...  The same for one of several agents, and revoke, which stops it at its
                              host at once. Authorizing it again brings it back.
  splint for HANDLE~HOST retire
                              Retires that agent at its host, for good, wherever it runs, where its
                              host says it acts for the owner ID on this computer: one approval, with
                              your Mac's Touch ID or your sign-in's passphrase. Its handle stays its
                              own, its contacts' agents are told, and it can't be undone.

  splint host start [--codes-only]
                              Runs a host on this machine, for this machine, and prints its address
                              and signup codes. It needs Docker. Agents join it with no code, a few
                              an hour, and a code lets one in past that. With --codes-only every
                              agent needs a code. SPLINT_MAX_ settings set its limits, as for any host.
  splint host codes           Prints its signup codes: those still unused first, one a line, then
                              the spent ones, each followed by the word spent.
  splint host codes add N     Makes N more codes and prints them. The running host takes them at
                              once, with no restart.
  splint host check           Says which of the host's settings a start would refuse, and why.
  splint host counts          How many agents, owners and other hosts use it, as numbers under fixed
                              labels. It only reads its database, and never prints an ID or a name.
  splint host stop            Stops it, and keeps its data.
  splint host remove [--force]
                              Stops it, and deletes its data. Where agents on this machine use it,
                              it names them and needs --force, which resets their folders too.

Several agents of yours on one machine:

  splint --as NAME COMMAND    Runs any command for the agent called NAME, a profile of up to 32
                              lower-case letters, digits and -. Each has its own Signet, keys, token,
                              contacts and settings in ~/.splint/profiles/NAME, and all of them share
                              your owner key. SPLINT_AS=NAME does the same for a program that runs
                              splint itself. With neither, it's the agent in ~/.splint.
  splint profiles             Lists them, with each one's address, whether its Signet is running and
                              whether its owner has set up their controls for it.

An address is name~host, such as ana~splint.example, or ana.jeff~splint.example for ana acting for
jeff, which a host gives out only when jeff's key signs it. You can type :: for ~, or paste the
splint: link or the ana~@splint.example email form, and it's written the one way at once.

Everything lives in ~/.splint.
";

/// A typed address in another spelling of the same one, such as `::` for `~`, the link or email form,
/// or a capital or a trailing dot in its domain, becomes the one spelling, so what's signed and
/// looked up always matches.
fn spelled_one_way(word: &str) -> String {
    canonical_address(word).unwrap_or_else(|_| word.to_owned())
}

/// What's typed, with the flags every command shares taken out wherever they were: an agent typed
/// `--as` last and `--json` first, and got another agent's answer, or a message made of the flags.
#[derive(Default)]
pub struct Typed<'a> {
    pub chosen: Option<&'a str>,
    pub json: bool,
    help: bool,
    /// The command and its own words.
    pub words: Vec<&'a str>,
    /// `--as`, `--json` or help came after `send NAME`, among words the note could have meant as its own.
    pub flag_in_note: bool,
}

impl<'a> Typed<'a> {
    fn of(all: &[&'a str]) -> Result<Self, Failure> {
        let mut typed = Self::default();
        let mut rest = all.iter().copied();
        while let Some(word) = rest.next() {
            let command = typed.words.first().copied();
            // What follows is the command `listen` runs, and its words are that command's own.
            if command == Some("listen") && word == COMMAND_FOLLOWS {
                typed.words.push(word);
                typed.words.extend(rest);
                break;
            }
            let in_note = command == Some("send") && typed.words.len() >= 2;
            match word {
                AS => {
                    let name = rest
                        .next()
                        .ok_or_else(|| Failure::refused("--as needs a profile's name after it"))?;
                    if typed.chosen.replace(name).is_some() {
                        return Err(Failure::refused("--as is given once"));
                    }
                    typed.flag_in_note |= in_note;
                }
                JSON => {
                    typed.json = true;
                    typed.flag_in_note |= in_note;
                }
                // Among a note's words, help would print in place of sending it, and exit 0 as if it
                // had gone, so it's refused there as --as and --json are.
                word if HELP.contains(&word) && in_note => typed.flag_in_note = true,
                word if HELP.contains(&word) => typed.help = true,
                word => typed.words.push(word),
            }
        }
        Ok(typed)
    }

    pub fn command(&self) -> Option<&'a str> {
        self.words.first().copied()
    }
}

/// The command's words, each address written the one way.
fn respelled(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| spelled_one_way(word)).collect()
}

/// `splint join`'s words after `join`: the address, and whether the owner signs first.
/// How `splint join` was asked to join, after the address.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinWay {
    AtOnce,
    /// With a signup code on stdin.
    WithCode,
    OwnerFirst,
}

fn join_words(words: &[&str]) -> Option<(String, JoinWay)> {
    let (address, way) = match words {
        [address @ .., OWNER_FIRST] => (address, JoinWay::OwnerFirst),
        [address @ .., WITH_CODE] => (address, JoinWay::WithCode),
        address => (address, JoinWay::AtOnce),
    };
    // A second flag would otherwise be read as the host.
    if address.iter().any(|word| word.starts_with('-')) {
        return None;
    }
    match address {
        [handle, domain] => Some((join::address_of(handle, domain), way)),
        [address] => Some(((*address).to_owned(), way)),
        _ => None,
    }
}

/// Joins as `splint join` was asked to, reading a signup code from stdin first where it was.
async fn join_as_asked(home: &Home, words: &[&str]) -> Result<join::Joined, Failure> {
    let (address, way) = join_words(words).ok_or(Failure::Usage)?;
    let code = match way {
        JoinWay::WithCode => Some(setup::read_signup_code()?),
        JoinWay::AtOnce | JoinWay::OwnerFirst => None,
    };
    join::join(home, &address, way == JoinWay::OwnerFirst, code.as_deref()).await
}

/// `splint controls`'s words after `controls`, as `splint ask` takes them: `--hours N` and `--name
/// NAME`, each once, in either order. Anything else, such as a host, is its person's form.
fn controls_words<'a>(words: &[&'a str]) -> Option<Vec<&'a str>> {
    let mut asked = vec!["--controls"];
    for pair in words.chunks(2) {
        match pair {
            [flag @ ("--hours" | "--name"), value] if !asked.contains(flag) => {
                asked.extend([*flag, *value]);
            }
            _ => return None,
        }
    }
    Some(asked)
}

/// `splint finish`'s words after `finish`: the answer, and whether a code comes on stdin anyway.
fn finish_words<'a>(words: &[&'a str]) -> Option<(&'a str, bool)> {
    match words {
        [answer] => Some((answer, false)),
        [answer, WITH_CODE] => Some((answer, true)),
        _ => None,
    }
}

/// The invite commands, which say the same in words and as JSON.
async fn run_invites(home: &Home, words: &[&str]) -> Result<Option<invites::Said>, Failure> {
    Ok(Some(match words {
        ["invite", to] => invites::invite(home, to).await?,
        ["invites"] => invites::invites(home).await?,
        ["accept", which] => invites::accept(home, which).await?,
        ["decline", which] => invites::decline(home, which).await?,
        ["card"] => invites::card(home).await?,
        _ => return Ok(None),
    }))
}

fn as_json(standing: status::Standing) -> Result<serde_json::Value, Failure> {
    serde_json::to_value(standing).map_err(|_| Failure::refused("couldn't write that as JSON"))
}

/// What a program driving `splint` reads: where the agent stands once the command is done, or what an
/// invite command found.
async fn run_json(chosen: Option<&str>, words: &[&str]) -> Result<serde_json::Value, Failure> {
    let words = respelled(words);
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let home = Home::from_env(chosen)?;
    if let Some(said) = run_invites(&home, &words).await? {
        return Ok(said.json);
    }
    match words.as_slice() {
        ["status"] => as_json(status::standing(&home).await?),
        ["start"] => {
            setup::start(&home).await?;
            as_json(status::standing(&home).await?)
        }
        ["join", rest @ ..] if rest.contains(&CODE) => Err(Failure::refused(NO_CODES)),
        ["finish"] if switch_host::under_way(&home).is_some() => {
            Ok(switch_host::run(&home, &[]).await?.json())
        }
        ["finish"] => {
            taking_up::finish_pending(&home).await?;
            as_json(status::standing(&home).await?)
        }
        ["join", rest @ ..] => {
            let joined = join_as_asked(&home, rest).await?;
            let standing = status::standing(&home).await?;
            as_json(status::Standing {
                for_owner: joined.for_owner,
                ..standing
            })
        }
        ["finish", answer] if switch_host::is_a_move_reply(answer) => {
            Ok(switch_host::finish(&home, answer).await?.json())
        }
        ["finish", rest @ ..] => {
            let (answer, with_code) = finish_words(rest).ok_or(Failure::Usage)?;
            taking_up::finish_given(&home, answer, with_code).await?;
            as_json(status::standing(&home).await?)
        }
        ["controls", rest @ ..] if controls_words(rest).is_some() => {
            let asked = controls_words(rest).ok_or(Failure::Usage)?;
            Ok(asks::ask(&home, &asked).await?.json())
        }
        ["ask", id] if !id.starts_with('-') => Ok(asks::status(&home, id).await?.json()),
        ["ask", flags @ ..] => Ok(asks::ask(&home, flags).await?.json()),
        ["switch-host", rest @ ..] => Ok(switch_host::run(&home, rest).await?.json()),
        _ => Err(Failure::Usage),
    }
}

async fn run(chosen: Option<&str>, words: &[&str]) -> Result<String, Failure> {
    let words = respelled(words);
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let words = words.as_slice();
    match words {
        ["guide"] => return guide::guide(None),
        ["guide", topic] => return guide::guide(Some(topic)),
        ["--version" | "version"] => {
            return Ok(format!("splint {}", splint_core::release::version()));
        }
        _ => {}
    }
    let home = Home::from_env(chosen)?;
    // What a service manager runs, so it comes before anything that reads the agent's settings.
    if let [services::RUN_SERVICE, name] = words {
        return services::run(&home, name);
    }
    let (named, owners_words) = match words {
        ["for", agent, rest @ ..] => (Some(*agent), rest),
        _ => (None, words),
    };
    // What only a straight answer took counts once its host has it, so any run here tries again first.
    direct::send_again_briefly(&home).await;
    if let Some(said) = run_invites(&home, words).await? {
        return Ok(said.text);
    }
    if let Some(done) = owner_commands::run(&home, named, owners_words).await? {
        return Ok(done);
    }
    match words {
        ["setup", address, options @ ..] => {
            let with_code = options.contains(&WITH_CODE);
            let owner_key_here = options.contains(&setup::OWNER_KEY_HERE);
            if options.len() != usize::from(with_code) + usize::from(owner_key_here) {
                return Err(Failure::Usage);
            }
            setup::setup(&home, address, with_code, owner_key_here).await
        }
        ["add", address, id] => contacts::add(&home, address, id).await,
        ["add", address] => contacts::add_found(&home, address).await,
        ["remove", address] => {
            let side = OwnerSide::resolve(&home, None, "take out a contact")?;
            contacts::remove(&home, &side, address).await
        }
        ["status"] => status::status(&home).await,
        ["page"] => page::serve(home, None).await,
        // Before the forms that take a host, which this would otherwise read `--hours` as.
        ["controls", rest @ ..] if controls_words(rest).is_some() => {
            let asked = controls_words(rest).ok_or(Failure::Usage)?;
            Ok(asks::ask(&home, &asked).await?.in_words())
        }
        ["ask", id] if !id.starts_with('-') => Ok(asks::status(&home, id).await?.in_words()),
        ["ask", flags @ ..] => Ok(asks::ask(&home, flags).await?.in_words()),
        ["switch-host", rest @ ..] => Ok(switch_host::run(&home, rest).await?.in_words()),
        ["computer", "run"] => computer::run(&home).await,
        ["computer", "start"] => match computer::start(&home)? {
            services::Started::Running => Ok("Splint on this computer is running.".to_owned()),
            services::Started::LeftStopped => Ok(
                "Splint here is stopped, as you ran splint stop, so run splint start first."
                    .to_owned(),
            ),
        },
        ["computer", "approve"] => asks::approve_here(&home, false).await,
        ["computer", "approve", computer::PLAIN_KEY_FILE] => asks::approve_here(&home, true).await,
        ["computer", "lock"] => computer::lock_sign_in(&home),
        ["computer", "recovery"] => computer::set_recovery_code(&home).await,
        ["recover", address, rest @ ..] => {
            let mut here = Vec::new();
            let mut replacing = None;
            for pair in rest.chunks(2) {
                match pair {
                    ["--here", agent] => here.push(*agent),
                    ["--replace-keys", typed] => replacing = Some(*typed),
                    _ => return Err(Failure::Usage),
                }
            }
            recover::recover(&home, address, &here, replacing).await
        }
        // With no port named, Splint on this computer serves them, signing with the person's sign-in
        // here. A port of the person's choosing serves the page and relay by themselves, signing nothing.
        ["controls", host, flags @ ..] if !flags.contains(&"--port") => {
            let (_, open) = page::controls::flags(flags)?;
            computer::open_controls(&home, host, open).await
        }
        ["controls", host, flags @ ..] => {
            let (port, open) = page::controls::flags(flags)?;
            page::controls::serve(host, port, open).await
        }
        ["for", agent, "page"] => page::serve(home, Some(agent)).await,
        ["auto"] => auto::run(&home).await,
        ["auto", "--once"] => auto::once(&home).await,
        ["connect"] => setup::connect(&home),
        ["renew"] => setup::renew(&home).await,
        ["start"] => setup::start(&home).await,
        ["start", "--if-running"] => setup::start_if_running(&home).await,
        // A stop for no agent would say it stopped while the one meant runs on.
        ["stop"] => {
            home.refuse_if_another_is_meant()?;
            setup::stop(&home).await
        }
        ["retire", address] => setup::retire(&home, address).await,
        ["reset", address] => setup::reset_without_host(&home, address).await,
        ["join", rest @ ..] if rest.contains(&CODE) => Err(Failure::refused(NO_CODES)),
        ["finish"] if switch_host::under_way(&home).is_some() => {
            Ok(switch_host::run(&home, &[]).await?.in_words())
        }
        ["finish"] => taking_up::finish_pending(&home).await,
        ["join", rest @ ..] => Ok(join_as_asked(&home, rest).await?.said),
        // A flag it doesn't take would go to the owner as the agent's reason.
        ["ask-owner", why @ ..] if why.iter().any(|word| is_flag(word)) => Err(Failure::Usage),
        ["ask-owner", why @ ..] => join::ask_owner(&home, &why.join(" ")).await,
        ["finish", answer] if switch_host::is_a_move_reply(answer) => {
            Ok(switch_host::finish(&home, answer).await?.in_words())
        }
        ["finish", rest @ ..] => {
            let (answer, with_code) = finish_words(rest).ok_or(Failure::Usage)?;
            taking_up::finish_given(&home, answer, with_code).await
        }
        ["authorize", address, key, flags @ ..] => {
            authorize::authorize(&home, address, key, &authorize::choices_from(flags)?).await
        }
        ["for", agent, "settings", flags @ ..] => {
            let choices = authorize::choices_from(flags)?;
            authorize::settings(&home, &authorize::named(&home, agent)?, &choices).await
        }
        ["agents"] => authorize::agents(&home),
        ["for", agent, "add", address, id] => {
            authorize::add(&home, &authorize::named(&home, agent)?, address, id).await
        }
        ["for", agent, "remove", address] => {
            let side = OwnerSide::resolve(&home, Some(agent), "take out a contact")?;
            contacts::remove(&home, &side, address).await
        }
        ["for", agent, "renew"] => authorize::renew(&home, &authorize::named(&home, agent)?).await,
        ["for", agent, "direct", at] => direct::name_for(&home, agent, at).await,
        ["network-access", rest @ ..] => setup::network_access(&home, rest).await,
        ["for", agent, "revoke"] => {
            authorize::revoke(&home, &authorize::named(&home, agent)?).await
        }
        ["for", agent, "retire"] => retire::by_owner(&home, agent).await,
        ["profiles"] => profiles::list(&home),
        // One host serves the whole machine, whichever profile asks.
        ["host", "start"] => host::start(&home.the_default(), true).await,
        ["host", "start", "--codes-only"] => host::start(&home.the_default(), false).await,
        ["host", "codes"] => host::one_shot(&home.the_default(), &["codes", "list"]),
        ["host", "codes", "add", count] => {
            host::one_shot(&home.the_default(), &["codes", "add", count])
        }
        ["host", "check"] => host::one_shot(&home.the_default(), &["check"]),
        ["host", "counts"] => host::one_shot(&home.the_default(), &["counts"]),
        ["host", "stop"] => host::stop(&home.the_default()).await,
        ["host", "remove"] => host::remove(&home.the_default(), false).await,
        ["host", "remove", "--force"] => host::remove(&home.the_default(), true).await,
        ["verify"] => release::verify(&home).await,
        _ => Err(Failure::Usage),
    }
}

/// The commands `run_json` answers. The agent's own and `check` answer for themselves.
const JSON_COMMANDS: [&str; 12] = [
    "start",
    "invite",
    "invites",
    "accept",
    "decline",
    "card",
    "status",
    "join",
    "finish",
    "ask",
    "controls",
    "switch-host",
];

/// A word shaped like a flag, such as `--now` or `-x`, rather than one of a reason's words or a dash.
fn is_flag(word: &str) -> bool {
    let mut chars = word.chars();
    chars.next() == Some('-') && chars.next().is_some_and(|c| c == '-' || c.is_alphabetic())
}

/// The form of `command` that a line of the help starts with, if it starts with one.
fn form_in(line: &'static str, command: &str) -> Option<&'static str> {
    let head = format!("splint {command}");
    let forms = line.strip_prefix("  ")?.split("  ").next()?;
    forms
        .split(", ")
        .map(|form| form.strip_prefix("or ").unwrap_or(form))
        .find(|form| {
            form.strip_prefix(head.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
        })
}

/// How a command is used, as its first form in the help reads, so a mistake is answered in one line
/// rather than the whole help, and the two never disagree.
fn usage_of(command: &str) -> Option<&'static str> {
    USAGE.lines().find_map(|line| form_in(line, command))
}

/// What the help says of `command`: each entry naming it, whole. The whole help for no command, or one
/// the help doesn't name.
fn help_of(command: Option<&str>) -> String {
    let whole = USAGE.trim_end().to_owned();
    let Some(command) = command else {
        return whole;
    };
    let mut entries = Vec::new();
    let mut taking = false;
    for line in USAGE.lines() {
        // An entry starts two spaces in, and goes on in lines further in.
        if line.starts_with("  ") && !line.starts_with("   ") {
            taking = form_in(line, command).is_some();
        } else if !line.starts_with("   ") {
            taking = false;
        }
        if taking {
            entries.push(line);
        }
    }
    if entries.is_empty() {
        whole
    } else {
        format!("{}\n\nsplint help shows every command.", entries.join("\n"))
    }
}

/// What a command was given that it doesn't take, in one line naming it. A word that isn't a command
/// isn't repeated back.
fn said_wrong(command: Option<&str>) -> String {
    match command.and_then(|command| Some((command, usage_of(command)?))) {
        Some((command, usage)) => format!(
            "splint {command} doesn't take those words. It's used as: {usage}, and splint help \
             shows every form"
        ),
        None => "that isn't a command: splint help lists them".to_owned(),
    }
}

/// A failure in words for whoever ran `command`.
fn failure_words(failure: &Failure, command: Option<&str>) -> String {
    match failure {
        Failure::Usage => said_wrong(command),
        failure => failure.to_string(),
    }
}

/// One line of JSON on stdout either way, so a program reads one place, and the exit code says which.
pub fn printed_json(answer: Result<serde_json::Value, Failure>, command: Option<&str>) -> ExitCode {
    let (line, code) = match answer {
        Ok(answer) => (answer, ExitCode::SUCCESS),
        Err(failure) => (
            json!({
                "error": { "kind": failure.kind(), "message": failure_words(&failure, command) }
            }),
            ExitCode::FAILURE,
        ),
    };
    if writeln!(io::stdout(), "{line}").is_ok() {
        code
    } else {
        ExitCode::FAILURE
    }
}

async fn main_json(typed: &Typed<'_>) -> ExitCode {
    let command = typed.command();
    let answer = match (run_json(typed.chosen, &typed.words).await, command) {
        // A command that answers only in words says so, rather than that it isn't a command.
        (Err(Failure::Usage), Some(command))
            if !JSON_COMMANDS.contains(&command) && usage_of(command).is_some() =>
        {
            Err(no_json(command))
        }
        (answer, _) => answer,
    };
    printed_json(answer, command)
}

fn no_json(command: &str) -> Failure {
    Failure::refused(format!(
        "splint {command} has no --json, so run it without for its answer in words"
    ))
}

/// The whole help only when no command was typed, and otherwise one line.
pub fn failed(failure: &Failure, command: Option<&str>) -> ExitCode {
    let _ = match (failure, command) {
        (Failure::Usage, None) => writeln!(io::stderr(), "{}", USAGE.trim_end()),
        (failure, command) => writeln!(io::stderr(), "splint: {}", failure_words(failure, command)),
    };
    ExitCode::FAILURE
}

/// `check` and `listen`, which print nothing at all when there's nothing to say, and whose command
/// words are a runtime's own, so none of them is respelled as an address.
async fn keeping_watch(typed: &Typed<'_>) -> Option<ExitCode> {
    let chosen = typed.chosen;
    let home = || Home::from_env(chosen);
    match (typed.words.as_slice(), typed.json) {
        (["check", flags @ ..], true) => {
            let counted = async {
                let (here, home) = (here_flag(flags)?, home()?);
                Ok(match check::agent_here(&home, chosen.is_some(), here)? {
                    Some(installed) => {
                        let waiting =
                            check::waiting_said(&SignetApi::new(&home, &installed)?, &home).await?;
                        counted_json(&waiting)?
                    }
                    None => json!({}),
                })
            };
            Some(printed_json(counted.await, Some("check")))
        }
        (["check", flags @ ..], false) => {
            let said = async {
                let here = here_flag(flags)?;
                check::check(&home()?, chosen.is_some(), here).await
            };
            Some(match said.await {
                Ok(Some(line)) if writeln!(io::stdout(), "{line}").is_err() => ExitCode::FAILURE,
                Ok(_) => ExitCode::SUCCESS,
                Err(failure) => failed(&failure, Some("check")),
            })
        }
        (["listen", ..], true) => Some(printed_json(Err(no_json("listen")), Some("listen"))),
        (["listen", flags @ ..], false) => {
            let heard = async {
                let options = listen::options(flags)?;
                listen::listen(&home()?, chosen.is_some(), &options).await
            };
            Some(match heard.await {
                Ok(listen::Heard::Done) => ExitCode::SUCCESS,
                Ok(listen::Heard::Nothing) => ExitCode::FAILURE,
                Ok(listen::Heard::Said(said)) if writeln!(io::stdout(), "{said}").is_ok() => {
                    ExitCode::SUCCESS
                }
                Ok(listen::Heard::Said(_)) => ExitCode::FAILURE,
                Err(failure) => failed(&failure, Some("listen")),
            })
        }
        _ => None,
    }
}

fn here_flag(flags: &[&str]) -> Result<bool, Failure> {
    match flags {
        [] => Ok(false),
        [listen::HERE] => Ok(true),
        _ => Err(Failure::Usage),
    }
}

/// Only the counts that aren't nothing, so `{}` says nothing waits, as `check` in words prints nothing.
fn counted_json(waiting: &check::Waiting) -> Result<serde_json::Value, Failure> {
    let counted = serde_json::to_value(waiting)
        .map_err(|_| Failure::refused("couldn't write that as JSON"))?;
    Ok(match counted {
        serde_json::Value::Object(counts) => serde_json::Value::Object(
            counts
                .into_iter()
                .filter(|(_, count)| count.as_u64() != Some(0))
                .collect(),
        ),
        other => other,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    // Before anything starts another program, which would otherwise hold its caller's pipes open.
    #[cfg(windows)]
    splint_core::private_files::windows::keep_own_handles_to_itself();
    let words: Vec<String> = env::args().skip(1).collect();
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let typed = match Typed::of(&words) {
        Ok(typed) => typed,
        Err(failure) => return failed(&failure, None),
    };
    let help = match typed.words.as_slice() {
        _ if typed.help => Some(typed.command()),
        ["help", topic @ ..] => Some(topic.first().copied()),
        _ => None,
    };
    if let Some(topic) = help {
        return match writeln!(io::stdout(), "{}", help_of(topic)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    // Nothing starts Signet at login on Windows yet, so a command that needs it starts again what was
    // running.
    #[cfg(windows)]
    if let Ok(home) = Home::from_env(typed.chosen) {
        setup::come_back(&home, &typed.words).await;
    }
    if let Some(code) = agent_commands::dispatch(&typed).await {
        return code;
    }
    if let Some(code) = keeping_watch(&typed).await {
        return code;
    }
    if typed.json {
        return main_json(&typed).await;
    }
    match run(typed.chosen, &typed.words).await {
        Ok(output) => {
            if writeln!(io::stdout(), "{output}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(failure) => failed(&failure, typed.command()),
    }
}

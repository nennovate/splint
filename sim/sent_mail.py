#!/usr/bin/env python3
"""A note is `delivered` only once the reader's Signet says it opened and checked it, and a sender's
Signet keeps every note it sent, words and all, so none vanishes without a record.

Bugs caught: a sender was told `delivered` when only the other host had stored the note, and a Signet
that never opened it, being off or missing its key, left the sender believing it arrived. And a note
whose answer was lost, or whose status the agent never asked, left nothing behind to send again.

Everything is the real hosts and Signets against Postgres. Ada writes to Bo and Cy, contacts on another
host. Bo's Signet confirms what it opens, and Ada's shows `delivered`. While Bo's Signet is off, Ada's
note stays `at_their_host`, and a receipt for it signed by anyone but Bo, put in Ada's inbox by a lying
host or sent by Cy through the hosts, changes nothing. Ada's Signet restarts and still holds every note
with its words, and Bo's coming back confirms the one it missed. Cy's Signet won't start without its
sealing key, so Ada's note can't be opened there and stays `at_their_host` until the key is back. Last, a shop open to anyone and a customer
who isn't its contact confirm each other's notes through both hosts.

    python3 sim/sent_mail.py

Cy's Signet owes no receipt for a note from a sender its owner blocks, holds or takes no words from.

Not shown: a note past its expiry with no receipt reads `not_confirmed`, as a Signet's clock can't be
moved here without a hook in it. The unit test in packages/signet/src/sent.rs passes the time in. Every
key is a software key file, and no agent has network limits.
"""

import json
import shutil
import sys
import time

import e2e
from e2e import check, http, wait_until
from request_driver import signed_step
from sealed import lying_host_delivers

# Several of Signet's sync passes, which run every 100 ms here.
SETTLE_SECONDS = 3


def sent(net: e2e.Network, sender: str, recipient: str, body: str) -> str:
    status, answer = net.send(sender, recipient, body)
    if status != 200:
        raise RuntimeError(f"{sender} couldn't send: {status} {answer}")
    return answer["message_id"]


def receipt_for(note: str) -> dict:
    return {"step": "received", "request": note, "of": note}


def acked(net: e2e.Network, agent: str, message_id: str) -> bool:
    database = f"host_{net.home[agent]}"
    return net.postgres.sql(database, f"SELECT count(*) FROM inbox WHERE message_id = '{message_id}' AND acked") == "1"


def restart_signet(net: e2e.Network, agent: str) -> None:
    net.signets[agent].kill_hard()
    net.signets[agent].start()
    net.wait_for_signet(agent)


def a_note_is_delivered_only_on_the_readers_word(net: e2e.Network) -> None:
    first = sent(net, "ada", "bo", "Are you free Tuesday at 10?")
    check("a note Bo's Signet opens is delivered", wait_until(lambda: net.sent_status("ada", first) == "delivered"), net.sent_report("ada", first))
    report = net.sent_report("ada", first)
    check("with when Bo's Signet signed for it, and what Ada wrote, to send again", report.get("delivered_at", 0) > 0 and report.get("body") == "Are you free Tuesday at 10?" and report.get("to") == net.address("bo"), report)
    # Before Bo's agent has read it: Signet has it and can read it.
    check("control: Bo's agent hasn't read it yet", "Are you free Tuesday at 10?" in net.bodies("bo"))
    # A step kept for a request is what lets two agents look like they've dealt, at either host.
    as_steps = [net.postgres.sql(f"host_{host}", f"SELECT count(*) FROM request_steps WHERE request_id = '{first}'") for host in ("a", "b")]
    check("and neither host keeps the receipt as a request's step", as_steps == ["0", "0"], as_steps)
    net.ack_all("bo")

    net.signets["bo"].kill_hard()
    second = sent(net, "ada", "bo", "Or Wednesday?")
    check("while Bo's Signet is off, the note only reaches his host", wait_until(lambda: net.sent_status("ada", second) == "at_their_host"), net.sent_report("ada", second))

    # A lying host can put anything in Ada's inbox, but can't sign as Bo: this one is signed by Cy's key.
    forged = signed_step(net, "cy", "bo", "ada", receipt_for(second))
    forged_id = lying_host_delivers(net, "bo", "ada", forged)
    # Cy can sign one, as Cy, and send it through both hosts, but the note didn't go to Cy.
    by_cy = signed_step(net, "cy", "cy", "ada", receipt_for(second))
    status = http("POST", f"http://{net.domain[net.home['cy']]}/v0/outbound", {"envelope": by_cy, "recipient_host": net.domain[net.home["ada"]]})[0]
    check("control: Cy's host carries Cy's receipt", status == 200)
    by_cy_id = e2e.message_id_of(by_cy)
    check("control: it reaches Ada's host", wait_until(lambda: net.postgres.sql("host_a", f"SELECT count(*) FROM inbox WHERE message_id = '{by_cy_id}'") == "1"))
    # A forged row is cleared on the agent's read, and anything that checks out by a sync pass.
    check("control: Ada's Signet has judged both", wait_until(lambda: bool(net.inbox("ada")) and acked(net, "ada", forged_id) and acked(net, "ada", by_cy_id)))
    time.sleep(SETTLE_SECONDS)
    check("neither a host nor another agent can make a note look delivered", net.sent_status("ada", second) == "at_their_host", net.sent_report("ada", second))

    restart_signet(net, "ada")
    kept = [net.sent_report("ada", one) for one in (first, second)]
    check("Ada's Signet still holds both after a restart, words and all", [one.get("status") for one in kept] == ["delivered", "at_their_host"] and kept[1].get("body") == "Or Wednesday?", kept)
    status, history = net.agent("ada", "GET", "/v0/sent")
    lines = {line["message_id"]: line["status"] for line in history.get("sent", [])}
    check("and lists them, newest first", status == 200 and list(lines)[:2] == [second, first] and lines[first] == "delivered", history)

    net.signets["bo"].start()
    net.wait_for_signet("bo")
    check("once Bo's Signet is back and opens it, it's delivered", wait_until(lambda: net.sent_status("ada", second) == "delivered"), net.sent_report("ada", second))
    net.ack_all("bo")


def a_note_its_reader_cant_open_isnt_delivered(net: e2e.Network) -> None:
    seal = net.work / "cy" / "agent.seal"
    kept = net.work / "cy-agent.seal.kept"
    net.signets["cy"].kill_hard()
    shutil.move(seal, kept)
    net.signets["cy"].start()
    check("control: Cy's Signet won't start without its sealing key", wait_until(net.signets["cy"].has_exited) and not seal.exists())
    note = sent(net, "ada", "cy", "sealed to the key Cy's Signet lost")
    check("control: it reaches Cy's host", wait_until(lambda: net.sent_status("ada", note) == "at_their_host"), net.sent_report("ada", note))
    time.sleep(SETTLE_SECONDS)
    check("so it stays at their host, never delivered", net.sent_status("ada", note) == "at_their_host", net.sent_report("ada", note))
    shutil.move(kept, seal)
    net.signets["cy"].start()
    net.wait_for_signet("cy")
    check("once the key is back and Cy's Signet opens it, it's delivered", wait_until(lambda: net.sent_status("ada", note) == "delivered"), net.sent_report("ada", note))
    net.ack_all("cy")


def no_receipt_for_mail_the_rules_dont_show(net: e2e.Network) -> None:
    """Bug caught: a sync pass owed a receipt for any note that checked out, so a sender Cy's owner
    blocked, holds or takes no words from learned Cy's Signet was running and opened their note."""
    contacts = [net.contact_entry("ada", "blocked"), net.contact_entry("bo", text=False), net.contact_entry("kim")]
    check("control: Cy's owner blocks Ada, takes no words from Bo, and holds anyone unnamed", net.put_rules("cy", net.sign_rules("cy", contacts))[0] == 200)
    # A lying host puts each straight in Cy's inbox, past the checks it should make. The shop is unnamed.
    unshown = [lying_host_delivers(net, sender, "cy", net.envelope_signed_by(sender, sender, "cy", f"from {sender}")) for sender in ("ada", "bo", "shop")]
    shown = lying_host_delivers(net, "kim", "cy", net.envelope_signed_by("kim", "kim", "cy", "from kim"))

    def receipts_of(note: str) -> str:
        return net.postgres.sql(f"host_{net.home['cy']}", f"SELECT count(*) FROM outbound WHERE receipt_of = '{note}'")

    # Cy's Signet reads its inbox in order, so once the last one's receipt is out it has judged the rest.
    check("control: Cy's Signet owes Kim, a contact it takes words from, a receipt", wait_until(lambda: receipts_of(shown) == "1"))
    check("but none to a blocked or held sender, or one it takes no words from", [receipts_of(note) for note in unshown] == ["0", "0", "0"], unshown)


def receipts_go_both_ways_with_someone_let_in_by_reach(net: e2e.Network) -> None:
    """Bug caught: a receipt to or from someone let in by reach was refused at a host, as neither the
    reach setting nor a request between them let it through, so a business's customers never saw
    `delivered`."""
    def open_to_all(outbound: str) -> None:
        reach = e2e.reach_setting("open", ["quote/1"], text=True, outbound=outbound)
        rules = net.owners["shop"].sign("rules", "--agent", net.ids["shop"], stdin=json.dumps(e2e.rules_draft([], reach=reach)))
        check(f"control: the shop is open to anyone, and writes to {outbound}", net.put_rules("shop", rules)[0] == 200)

    # Writing only to its contacts, so nothing but the receipt itself lets that go to Kim.
    open_to_all("contacts")
    rules = net.owners["kim"].sign("rules", "--agent", net.ids["kim"], stdin=json.dumps(e2e.rules_draft([net.contact_entry("shop")])))
    check("control: Kim names the shop", net.put_rules("kim", rules)[0] == 200)
    asked = sent(net, "kim", "shop", "Do you have it in blue?")
    check("control: the shop is shown Kim's note", wait_until(lambda: "Do you have it in blue?" in net.bodies("shop")), net.inbox("shop"))
    check("Kim sees it delivered, though she's no contact of the shop's", wait_until(lambda: net.sent_status("kim", asked) == "delivered"), net.sent_report("kim", asked))
    net.ack_all("shop")
    open_to_all("replies")
    answer = sent(net, "shop", "kim", "We do.")
    check("and the shop sees its answer delivered", wait_until(lambda: net.sent_status("shop", answer) == "delivered"), net.sent_report("shop", answer))
    net.ack_all("kim")


def main() -> int:
    e2e.build()
    with e2e.running_network(owned=True) as network:
        network.add_owned_agents({"ada": "a", "bo": "b", "cy": "b"})
        network.add_owned_agents({"shop": "a", "kim": "b"}, agree=False)
        for scenario in (
            a_note_is_delivered_only_on_the_readers_word,
            a_note_its_reader_cant_open_isnt_delivered,
            no_receipt_for_mail_the_rules_dont_show,
            receipts_go_both_ways_with_someone_let_in_by_reach,
        ):
            print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
            scenario(network)
        if e2e.failures:
            for process in network.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1500:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

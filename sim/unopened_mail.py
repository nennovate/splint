#!/usr/bin/env python3
"""Mail a Signet can't open waits at its host, and opens once it can. Only proof ends a message.

Bug caught: a Signet that read its inbox and couldn't open or check a message told its host the message
was done, which erased the only copy while its sender's record still said delivered. Any read did it,
the status read included, so a Signet started with its sealing key missing destroyed everything waiting
for it, and putting the key back brought nothing back.

Everything here is the real hosts and Signets against Postgres. Ben's Signet won't start with its
`agent.seal` moved away, and makes no other: mail sealed to that key waits at the host and opens by
itself once the key is back. Ros hears from Quy, whose key changed while both hosts kept the
history naming it back: the message waits while that history is awaited and once the owner's word is,
and reaches the agent when both are in. A forged message is still cleared as forged, beside one sealed
to someone else's key that waits, as the inbox and the status read say, with why. A step that doesn't open from someone let in by reach isn't held: it's
put off, its host lets it go after the hour of put-offs, and the reads don't count it, while a contact's
stays. Once the owner blocks a sender, what they sent that doesn't open is ended as the rules refusing
it. Then 150 steps that open for nobody are planted from a stranger, 400 from a stranger while the
reader's Signet is down, and 150 from one contact, past what a host lets one sender leave, as a lying
host could, each for a reader of its own: a contact's note is still shown behind each, the strangers'
are put off and not counted, the status read counts every one of the contact's while they're put off at
the host, and the reader's inbox read is timed.

    python3 sim/unopened_mail.py

Not shown: owner mail sealed to a key Signet doesn't hold (`splint status` counts it the same way),
mail carried from a host left, and the words `splint status` prints, which come from the status read
checked here. Every key is a software key file, and no agent has network limits.
"""

import json
import shutil
import subprocess
import sys
import time

import e2e
from change_notices import accept, met, page, replace_agent_key, wait_for_standing, waits_on_the_host
from e2e import check, wait_until
from identity_recovery import a_pair
from sealed import build_sealer, lying_host_delivers, on_host, sealed_by

# Several of Signet's sync passes, which run every 100 ms here.
SETTLE_SECONDS = 3
# More than a host's page of 100 and its 100 waiting from one sender, as only a lying host would hold.
FLOOD = 150
# More than two of a host's pages, waiting together, as about 13 stranger IDs at a host's 16 each leave.
PILE = 400
# How many put-offs a host makes of a step from someone let in by reach before it lets it go, less one,
# standing in for the hour of them a Signet would make.
PUT_OFFS_BEFORE_LET_GO = 119


def sent(net: e2e.Network, sender: str, recipient: str, body: str) -> str:
    status, answer = net.send(sender, recipient, body)
    if status != 200:
        raise RuntimeError(f"{sender} couldn't send: {status} {answer}")
    return answer["message_id"]


def held_of(answer: dict) -> dict[str, int]:
    return {line["kind"]: line["count"] for line in answer.get("held", [])}


def status_read(net: e2e.Network, agent: str) -> dict:
    """What `splint status` reads from Signet."""
    status, answer = net.agent(agent, "GET", "/v0/listening")
    if status != 200:
        raise RuntimeError(f"{agent}'s status read returned {status}: {answer}")
    return answer


def unacked(net: e2e.Network, agent: str, message_ids: list[str]) -> int:
    named = ",".join(f"'{one}'" for one in message_ids)
    return int(net.postgres.sql(f"host_{net.home[agent]}", f"SELECT count(*) FROM inbox WHERE message_id IN ({named}) AND NOT acked"))


def a_lost_sealing_key_loses_no_mail(net: e2e.Network) -> None:
    seal = net.work / "ben" / "agent.seal"
    kept = net.work / "ben-agent.seal.kept"
    net.signets["ben"].kill_hard()
    shutil.move(seal, kept)
    net.signets["ben"].start()
    check("control: Ben's Signet won't start without its sealing key, and makes no other", wait_until(net.signets["ben"].has_exited) and not seal.exists())

    bodies = [f"sealed to the key Ben's Signet lost, {number}" for number in range(3)]
    ids = [sent(net, "ana", "ben", body) for body in bodies]
    check("control: all three reach Ben's host", wait_until(lambda: all(on_host(net, "ben", one) for one in ids)))
    time.sleep(SETTLE_SECONDS)
    check("all three wait at the host while the key is gone", unacked(net, "ben", ids) == 3)

    shutil.move(kept, seal)
    net.signets["ben"].start()
    net.wait_for_signet("ben")
    check("once the key is back, all three open by themselves", wait_until(lambda: sorted(net.bodies("ben")) == sorted(bodies)), net.inbox("ben"))
    check("and nothing is said to be held", "held" not in net.inbox("ben") and "held" not in status_read(net, "ben"), net.inbox("ben"))
    net.ack_all("ben")
    check("control: the agent's ack clears them", unacked(net, "ben", ids) == 0)


def a_senders_new_key_waits_for_its_history(net: e2e.Network) -> None:
    a_pair(net, "quy", "ros")
    met(net, "quy", "ros")
    quy_id = net.ids["quy"]
    held_history = net.postgres.sql("host_a", f"SELECT history FROM agents WHERE id = '{quy_id}'")
    net.signets["ros"].kill_hard()
    replace_agent_key(net, "quy")
    message = "signed with a key Ros hasn't heard of yet"
    check("control: the new key writes", net.send("quy", "ros", message)[0] == 200)
    check("control: it reaches Ros's host", wait_until(lambda: waits_on_the_host(net, "ros", message)))
    new_history = net.postgres.sql("host_a", f"SELECT history FROM agents WHERE id = '{quy_id}'")
    # Both hosts keep back the history that names the key, and the notice of it.
    net.postgres.sql("host_b", f"DELETE FROM inbox WHERE recipient = '{net.ids['ros']}' AND is_step")
    net.postgres.sql("host_a", f"UPDATE agents SET history = '{held_history}' WHERE id = '{quy_id}'")
    net.signets["ros"].start()
    net.wait_for_signet("ros")
    check("control: Ros's Signet awaits a history that names the key", wait_for_standing(net, "ros", "quy", "waiting_for_history"), page(net, "ros"))
    inbox = net.inbox("ros")
    check("the message waits, and the inbox says it's from a key not known yet", inbox["messages"] == [] and inbox["dropped"] == 0 and held_of(inbox) == {"sender_key_not_known_yet": 1}, inbox)
    check("and so does the status read", held_of(status_read(net, "ros")) == {"sender_key_not_known_yet": 1}, status_read(net, "ros"))
    check("it's still at the host", waits_on_the_host(net, "ros", message))

    net.postgres.sql("host_a", f"UPDATE agents SET history = '{new_history}' WHERE id = '{quy_id}'")
    check("once the history arrives, the owner's rules ask about the change", wait_for_standing(net, "ros", "quy", "ask"), page(net, "ros"))
    check("and the inbox says it waits on the owner's word", held_of(net.inbox("ros")) == {"sender_change_waits_for_owner": 1}, net.inbox("ros"))
    check("the owner's yes opens it", accept(net, "ros", "quy")[0] == 200 and wait_until(lambda: message in net.bodies("ros")), net.inbox("ros"))
    net.ack_all("ros")


def a_forged_message_is_still_cleared(net: e2e.Network) -> None:
    genuine = net.envelope_signed_by("ana", "ana", "ben", "signed by Ana's key")
    header, payload, signature = genuine.split(".")
    changed = json.loads(e2e.decode(payload))
    changed["body"] = "words Ana's key never signed"
    forged = ".".join([header, e2e.encode(e2e.compact_json(changed)), signature])
    forged_id = lying_host_delivers(net, "ana", "ben", forged)
    other_key = lying_host_delivers(net, "ana", "ben", sealed_by(net, "ana", "ana", "ben", "sealed to Carol's key", sealed_to="carol"))
    inbox = net.inbox("ben")
    check("neither reaches the agent", inbox["messages"] == [], inbox)
    check("the forged one is cleared as forged", inbox["dropped"] == 1 and unacked(net, "ben", [forged_id]) == 0, inbox)
    check("the one sealed to someone else's key waits, as it proves nothing", held_of(inbox) == {"sealed_to_another_key": 1} and unacked(net, "ben", [other_key]) == 1, inbox)
    told = status_read(net, "ben")
    check("the status read says the same, with why in plain words", held_of(told) == {"sealed_to_another_key": 1} and all(line["why"] for line in told["held"]), told)
    check("and nothing of what it says or who sent it", not any(word in json.dumps(told) for word in ("sealed to Carol's key", net.ids["ana"])), told)
    net.postgres.sql("host_b", f"DELETE FROM inbox WHERE message_id = '{other_key}'")


def unopenable(net: e2e.Network, sender: str, recipient: str, body: str) -> str:
    """A message that opens for nobody here, sealed to Carol's key, put in the inbox by a lying host."""
    return lying_host_delivers(net, sender, recipient, sealed_by(net, sender, sender, recipient, body, sealed_to="carol"))


def as_steps(net: e2e.Network, agent: str, message_ids: list[str], more: str = "") -> None:
    """Marks these as steps, as an honest host marks a sealed step from what its outside says."""
    named = ",".join(f"'{one}'" for one in message_ids)
    net.postgres.sql(f"host_{net.home[agent]}", f"UPDATE inbox SET is_step = TRUE{more} WHERE message_id IN ({named})")


def planted(net: e2e.Network, sender: str, recipient: str, count: int, body: str, by_reach: bool) -> list[str]:
    """Steps that open for nobody, sealed to Carol's key, which a lying host puts in an inbox past its
    limits, flagged as an honest host flags a step, and one from someone its owner's reach setting let
    in. Written a hundred to a statement, as one each takes too long for a few hundred, over psql's input."""
    rows = []
    for number in range(count):
        envelope = sealed_by(net, sender, sender, recipient, f"{body} {number}", sealed_to="carol")
        rows.append((e2e.message_id_of(envelope), envelope))
    for start in range(0, count, 100):
        values = ",".join(
            f"('{net.ids[recipient]}', '{message_id}', '{envelope}', '{net.agent_identity(sender)}', '{net.ids[sender]}', TRUE, {str(by_reach).upper()})"
            for message_id, envelope in rows[start:start + 100]
        )
        written = subprocess.run(
            ["docker", "exec", "-i", net.postgres.name, "psql", "-U", "splint", "-d", f"host_{net.home[recipient]}", "-v", "ON_ERROR_STOP=1"],
            input=f"INSERT INTO inbox (recipient, message_id, envelope, sender_identity, sender, is_step, by_reach) VALUES {values};",
            capture_output=True, text=True,
        )
        if written.returncode != 0:
            raise RuntimeError(f"couldn't plant steps: {written.stderr[-500:]}")
    return [message_id for message_id, _ in rows]


def held_in_all(answer: dict) -> int:
    return sum(held_of(answer).values())


def put_off_counts(net: e2e.Network, agent: str, message_ids: list[str]) -> list[int]:
    named = ",".join(f"'{one}'" for one in message_ids)
    answer = net.postgres.sql(f"host_{net.home[agent]}", f"SELECT put_off FROM inbox WHERE message_id IN ({named})")
    return [int(one) for one in answer.split()]


def waiting_from(net: e2e.Network, agent: str, sender: str) -> int:
    """How many from this sender wait at the agent's host, unacked, read from the host's own table."""
    return int(net.postgres.sql(f"host_{net.home[agent]}", f"SELECT count(*) FROM inbox WHERE recipient = '{net.ids[agent]}' AND sender = '{net.ids[sender]}' AND NOT acked"))


def a_step_from_someone_let_in_by_reach_is_let_go(net: e2e.Network) -> None:
    """Bug caught: Signet holding a step it can't open from someone let in by reach and never putting it
    off, so its host never let it go, and cheap stranger IDs could keep a page full of them. The host's
    count of put-offs is set one short of the hour of them after which it lets one go. Ana isn't one of
    Eli's contacts, so her step is flagged as an honest host flags one from someone its owner's reach
    setting let in."""
    from_reach = unopenable(net, "ana", "eli", "a step from someone let in by reach")
    from_contact = unopenable(net, "dee", "eli", "a step from a contact")
    as_steps(net, "eli", [from_reach], f", by_reach = TRUE, put_off = {PUT_OFFS_BEFORE_LET_GO}, not_before = 0")
    as_steps(net, "eli", [from_contact], f", put_off = {PUT_OFFS_BEFORE_LET_GO}, not_before = 0")
    # A row written straight into the table wakes nobody, so a note from a contact does.
    check("control: another contact writes, which starts a sync pass", net.send("fox", "eli", "a note that wakes Eli's Signet")[0] == 200)
    check("the one from someone let in by reach is put off, and its host lets it go", wait_until(lambda: unacked(net, "eli", [from_reach]) == 0))
    check("by the put-off that let it go, not as cleared by Signet", put_off_counts(net, "eli", [from_reach]) == [PUT_OFFS_BEFORE_LET_GO + 1], put_off_counts(net, "eli", [from_reach]))
    check("control: the contact's is put off again, as its host never lets one go", wait_until(lambda: put_off_counts(net, "eli", [from_contact])[0] > PUT_OFFS_BEFORE_LET_GO))
    time.sleep(SETTLE_SECONDS)
    check("the contact's still waits at the host", unacked(net, "eli", [from_contact]) == 1)
    check("and the reads count only the contact's as held", held_in_all(net.inbox("eli")) == 1, net.inbox("eli").get("held"))
    net.ack_all("eli")


def a_block_ends_what_its_sender_sealed_away(net: e2e.Network) -> None:
    """Bug caught: what a blocked sender sent that doesn't open here waiting at the host, holding the
    inbox's room for up to 30 days, as the rules refused only what opened."""
    before = held_in_all(net.inbox("eli"))
    sealed_away = unopenable(net, "gus", "eli", "from gus, before the block")
    check("control: it waits while Gus is a contact", held_in_all(net.inbox("eli")) == before + 1 and unacked(net, "eli", [sealed_away]) == 1, net.inbox("eli").get("held"))
    status, answer = net.put_rules("eli", net.sign_rules("eli", [net.contact_entry(other) for other in ("dee", "fox")] + [net.contact_entry("gus", status="blocked")]))
    check("control: Eli's owner blocks Gus", status == 200, answer)
    check("a read then ends it, as the rules refuse its sender", wait_until(lambda: net.inbox("eli") and unacked(net, "eli", [sealed_away]) == 0))
    check("and it's no longer counted as held", wait_until(lambda: held_in_all(net.inbox("eli")) == before), net.inbox("eli").get("held"))


def strangers_unopenable_steps_hide_nothing(net: e2e.Network) -> None:
    """Bug caught: steps that open for nobody from someone let in by reach held on the page and never put
    off, which a host's pages list before any note. About seven cheap stranger IDs, at a host's 16 each,
    kept a page full of them and hid every contact's note until they expired. A lying host plants them
    here from one stranger, which shows the same. Hal reads, with nothing left from another scenario."""
    net.add_owned_agents({"hal": "b", "ida": "a"})
    ids = planted(net, "ana", "hal", FLOOD, "a stranger's step that opens for nobody", by_reach=True)
    status, answer = net.send("ida", "hal", "from ida, behind the strangers")
    check("control: a contact writes", status == 200, answer)
    check("the contact's note reaches the agent", wait_until(lambda: "from ida, behind the strangers" in net.bodies("hal")), net.inbox("hal").get("held"))
    check("Signet puts every one of the strangers' off", wait_until(lambda: all(count > 0 for count in put_off_counts(net, "hal", ids))), put_off_counts(net, "hal", ids))
    check("and ends none of them itself", unacked(net, "hal", ids) == FLOOD)
    check("the reads don't count them as held, as their host lets them go", held_of(net.inbox("hal")) == {}, net.inbox("hal").get("held"))


def strangers_steps_waiting_across_a_restart_hide_nothing(net: e2e.Network) -> None:
    """Bug caught: a host's pages listing every step before any note, while a pass that only puts rows off
    reads no further page. With a few hundred strangers' steps that open for nobody waiting while the
    reader's Signet was down, only the first page's were ever put off, they came back first each time,
    and a contact's note was never shown. It took about 13 cheap stranger IDs at a host's 16 each."""
    net.add_owned_agents({"jan": "b", "kai": "a"})
    note = "from kai, unread when jan's Signet went down"
    status, answer = net.send("kai", "jan", note)
    check("control: a contact writes", status == 200, answer)
    check("control: it waits at the reader's host, unread", wait_until(lambda: waiting_from(net, "jan", "kai") == 1))
    net.signets["jan"].kill_hard()
    ids = planted(net, "ana", "jan", PILE, "a stranger's step waiting out a restart", by_reach=True)
    net.signets["jan"].start()
    net.wait_for_signet("jan")
    check("the contact's note is shown once the Signet is back", wait_until(lambda: note in net.bodies("jan")), net.inbox("jan").get("held"))
    check("and the strangers' still wait at the host, ended by nobody", unacked(net, "jan", ids) == PILE)


def one_contacts_unopenable_steps_hide_nothing(net: e2e.Network) -> None:
    """Bugs caught: one contact's steps that open for nobody, which a host's pages list before any note,
    hiding every message behind them; and the reads counting only those on the page, when the host
    keeps those put off out of it. Lou reads, with nothing left from another scenario."""
    net.add_owned_agents({"lou": "b", "max": "a", "ned": "a"})
    started = time.monotonic()
    before = held_of(net.inbox("lou")).get("sealed_to_another_key", 0)
    quiet = time.monotonic() - started
    # Waited for, as what made them contacts can still be on its way to the reader on a fast machine.
    check("control: nothing waits for the reader before", before == 0 and wait_until(lambda: waiting_from(net, "lou", "max") == 0), (before, waiting_from(net, "lou", "max")))
    ids = planted(net, "max", "lou", FLOOD, "a step that opens for nobody", by_reach=False)
    status, answer = net.send("ned", "lou", "from ned, behind the flood")
    check("control: another contact writes", status == 200, answer)
    check("another contact's message is still shown", wait_until(lambda: "from ned, behind the flood" in net.bodies("lou")), net.inbox("lou").get("held"))
    started = time.monotonic()
    net.inbox("lou")
    flooded = time.monotonic() - started
    print(f"  measured: an inbox read took {quiet * 1000:.0f} ms with {before} held, {flooded * 1000:.0f} ms with {FLOOD} more from one contact", flush=True)
    counted = []
    for _ in range(5):
        counted.append(held_of(status_read(net, "lou")).get("sealed_to_another_key", 0))
        time.sleep(1)
    # Every one waiting from Dee is unopenable, so the host's own table says what the reads must count.
    expected = waiting_from(net, "lou", "max")
    check("control: all of Max's wait at the host", expected == before + FLOOD, expected)
    check("the status read counts every one on every read, while they're put off at the host", counted == [expected] * 5, counted)
    check("and all still wait there", unacked(net, "lou", ids) == FLOOD)


def main() -> int:
    e2e.build()
    build_sealer()
    with e2e.running_network(owned=True) as network:
        network.add_owned_agents({"dee": "a", "eli": "b", "fox": "a", "gus": "a"})
        for scenario in (
            a_lost_sealing_key_loses_no_mail,
            a_senders_new_key_waits_for_its_history,
            a_forged_message_is_still_cleared,
            a_step_from_someone_let_in_by_reach_is_let_go,
            a_block_ends_what_its_sender_sealed_away,
            strangers_unopenable_steps_hide_nothing,
            strangers_steps_waiting_across_a_restart_hide_nothing,
            one_contacts_unopenable_steps_hide_nothing,
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

#!/usr/bin/env python3
"""A host's peers file, changed while the host runs, with real hosts, Signets and Postgres.

Who a host exchanges with used to be a setting read at start, so naming a peer, removing one or
taking a peer's new key meant a restart, which cuts off every agent on that host. Now it's a file
the running host reads again every 2 seconds. Each scenario changes a file and shows what the same
process then does, and checks that process never restarted.

Every sim starts its hosts with a peers file, as the installer does, and leaves them open, as they
ship. These keep theirs private, to the hosts each names, as the changes here are about that list.

What this can't show: an editor that writes a file in place while the host is reading it. The host
takes a list only once two readings agree, and its unit test covers that rule.
"""

import json
import os
import sys
import time
from pathlib import Path

import e2e
from e2e import check, http, wait_until

# A host reads its file every 2 seconds and takes a change on the second reading that says the same,
# and its delivery worker looks every quarter of a second. So after this long a change is in force,
# or it never will be.
IN_FORCE_SECS = 6


class FileNetwork(e2e.Network):
    """The same network, with each host private to the hosts it names."""

    def __init__(self, *arguments, **named) -> None:
        super().__init__(*arguments, **named)
        self.listed: dict[str, list[str]] = {}

    def first_peers_file(self, host: str) -> str:
        self.listed[host] = list(self.named)
        return self.private_to(self.listed[host])

    def spawn_as_given(self, name: str, env: dict[str, str]) -> e2e.Process:
        """A host with exactly these settings, for a scenario about how one starts."""
        return super().spawn("host", name, env)

    def name_peers(self, host: str, peers: list[str], *more: str) -> None:
        self.write_peers(host, f"# written by sim/peers_file.py\n{self.private_to(peers, *more)}")

    def all_but(self, host: str, *left_out: str) -> list[str]:
        return [peer for peer in self.listed[host] if peer not in left_out]

    def pid(self, host: str) -> int:
        return self.hosts[host].process.pid

    def never_restarted(self, host: str, pid: int) -> bool:
        return self.pid(host) == pid and not self.hosts[host].has_exited()

    def due_now(self, host: str, table: str = "outbound") -> None:
        """Skips a backoff on this host, so a scenario doesn't sit through it."""
        self.postgres.sql(f"host_{host}", f"UPDATE {table} SET next_attempt_at = now()")

    def start_host(self, name: str) -> None:
        """One more real host, which names host a and which nobody names yet."""
        self.domain[name] = f"127.0.0.1:{e2e.free_port()}"
        self.peers_file[name] = self.work / f"host-{name}.peers"
        self.listed[name] = [self.domain["a"]]
        self.name_peers(name, self.listed[name])
        self.hosts[name] = self.spawn("host", f"host-{name}", {
            "SPLINT_DOMAIN": self.domain[name],
            "SPLINT_LISTEN": self.domain[name],
            "SPLINT_DATABASE_URL": self.postgres.create_database(f"host_{name}"),
            "SPLINT_HOST_KEY_FILE": str(self.work / f"host-{name}.key"),
            "SPLINT_PEERS_FILE": str(self.peers_file[name]),
            **e2e.PLAIN_HTTP_FOR_TESTS,
            "SPLINT_CLEANUP_SECS": "1",
            "SPLINT_SIGNUP_CODES": ",".join(e2e.signup_code(number) for number in range(e2e.SIGNUP_CODES)),
        })
        if not self.wait_for_host(name):
            raise RuntimeError(f"host {name} didn't start")


def arrives(net: FileNetwork, sender: str, recipient: str, body: str) -> bool:
    """Whether a new message gets from one agent to the other, however long the sender's host backs off."""
    status, _ = net.send(sender, recipient, body)

    def there() -> bool:
        net.due_now(net.home[sender])
        return body in net.bodies(recipient)

    return status == 200 and wait_until(there)


def send_gets(net: FileNetwork, sender: str, recipient: str, body: str, wanted: int) -> bool:
    """Whether a send comes to get this answer, once a change to a file is in force. It asks once a
    second, as each one that's taken is a real message and an agent may send only so many."""
    for attempt in range(IN_FORCE_SECS + 1):
        if net.send(sender, recipient, f"{body}, try {attempt}")[0] == wanted:
            return True
        time.sleep(1)
    return False


def a_host_named_while_running_is_reached(net: FileNetwork) -> None:
    """Bug: a host named in the file after start is still refused, so a new peer needs a restart."""
    net.start_host("c")
    net.add_owned_agents({"cara": "c"}, agree=False)
    net.put_rules("cara", net.sign_rules("cara", [net.contact_entry("ana")]))
    everyone = [net.contact_entry(other) for other in (*e2e.TOKENS, "cara") if other != "ana"]
    net.put_rules("ana", net.sign_rules("ana", everyone))
    pid = net.pid("a")

    envelope = net.envelope_signed_by("ana", "ana", "cara", "handed to Ana's host for one it hasn't named")
    going_out = {"envelope": envelope, "recipient_host": net.domain["c"]}
    status = http("POST", f"http://{net.domain['a']}/v0/outbound", going_out)[0]
    check("control: Ana's host takes nothing for a host it hasn't named", status == 403, status)
    waiting = "sent to Ana before her host named Cara's"
    status, sent = net.send("cara", "ana", waiting)
    check("control: Cara's host, which names Ana's, takes a message for Ana", status == 200, sent)
    refused = wait_until(lambda: net.sent_report("cara", sent["message_id"]).get("last_failure") == "not_a_peer")
    check("control: and Ana's host refuses it, so it waits", refused, net.sent_report("cara", sent["message_id"]))
    check("control: Ana hasn't got it", waiting not in net.bodies("ana"), net.bodies("ana"))

    net.name_peers("a", [*net.listed["a"], net.domain["c"]])

    def got_it() -> bool:
        net.due_now("c")
        return waiting in net.bodies("ana")

    check("once the file names Cara's host, the waiting message arrives", wait_until(got_it), net.sent_report("cara", sent["message_id"]))
    check("and Ana's first message to Cara goes through", arrives(net, "ana", "cara", "Ana's first to Cara, with nothing restarted"))
    check("with Ana's host never restarted", net.never_restarted("a", pid))
    net.listed["a"].append(net.domain["c"])
    net.ack_all("ana")
    net.ack_all("cara")


def removing_a_peer_holds_mail_both_ways(net: FileNetwork) -> None:
    """Bug: a peer taken out of the file, or blocked, still gets mail or still has its mail taken."""
    check("control: Ana and Ben exchange", arrives(net, "ana", "ben", "so that Ana has met Ben") and arrives(net, "ben", "ana", "and Ben has met Ana"))
    net.ack_all("ana")
    net.ack_all("ben")
    pid = net.pid("a")
    # Ben's host is down, so this can't arrive before his host comes out of the file.
    net.hosts["b"].kill_hard()
    queued_body = "queued for a peer about to be removed"
    status, sent = net.send("ana", "ben", queued_body)
    check("control: a message is queued for a named peer", status == 200, sent)
    queued = sent["message_id"]

    net.name_peers("a", net.all_but("a", net.domain["b"]))
    check("Ana can see the peer was removed", net.wait_for_status(queued, "held_unsent"), net.sent_report("ana", queued))
    net.hosts["b"].start()
    check("control: Ben's host is back", net.wait_for_host("b"))
    # Due, and its peer up, so a worker that went by the old list would send it on its next pass.
    net.due_now("a")
    time.sleep(1)
    check("the queued message isn't sent", queued_body not in net.bodies("ben"), net.bodies("ben"))
    check("and stays shown as held", net.sent_status("ana", queued) == "held_unsent", net.sent_report("ana", queued))
    status = net.send("ana", "ben", "a new message for a removed peer")[0]
    check("a new message for the removed peer is refused", status == 502, status)

    from_ben = "sent while Ana's host doesn't name Ben's"
    status, sent = net.send("ben", "ana", from_ben)
    check("control: Ben's host, which still names Ana's, takes a message for her", status == 200, sent)
    refused = wait_until(lambda: net.sent_report("ben", sent["message_id"]).get("last_failure") == "not_a_peer")
    check("mail from the removed peer is refused too", refused, net.sent_report("ben", sent["message_id"]))
    check("and never reaches Ana", from_ben not in net.bodies("ana"), net.bodies("ana"))

    net.name_peers("a", net.listed["a"])
    check("once the peer is back in the file, the held message is delivered", net.wait_for_status(queued, *e2e.REACHED), net.sent_report("ana", queued))
    check("and Ben gets it", queued_body in net.bodies("ben"), net.bodies("ben"))

    def from_ben_arrived() -> bool:
        net.due_now("b")
        return from_ben in net.bodies("ana")

    check("and Ben's reaches Ana, without being sent again", wait_until(from_ben_arrived), net.sent_report("ben", sent["message_id"]))

    net.name_peers("a", net.listed["a"], f"block {net.domain['b']}")
    check("a block line stops a peer the file still names", send_gets(net, "ana", "ben", "for a peer that's named and blocked", 502))
    net.name_peers("a", net.listed["a"])
    check("and taking the line out lets it through again", send_gets(net, "ana", "ben", "for a peer no longer blocked", 200))
    check("with Ana's host never restarted", net.never_restarted("a", pid))
    time.sleep(1)
    net.ack_all("ana")
    net.ack_all("ben")


def a_removed_peer_is_told_of_no_retirement(net: FileNetwork) -> None:
    """Bug: a retirement already queued for a peer keeps being sent after the operator removes it."""
    peer = net.scripted_peer
    peer.answer_everything_with(500)
    peer.hits.clear()
    retirement = net.owners["carol"].sign("retire", "--agent", net.ids["carol"], "--reason", "finished")
    status = http("POST", f"http://{net.domain['b']}/v0/retirements", {"retirement": retirement})[0]
    check("control: Carol's owner retires her at her host", status == 200, status)
    told = wait_until(lambda: "/v0/retirements" in peer.hits)
    check("control: her host tells a named peer, which fails, so it will try again", told, peer.hits)

    def taken_from(domain: str) -> int:
        """What host b says to a delivery naming this host. It refuses a host off its list with 403."""
        envelope = net.envelope_signed_by("mallory", "mallory", "ben", "a probe for whether a host is named")
        fields = {"envelope": envelope, "sender_identity": net.agent_identity("mallory"), "from_host": domain, "proof": "x"}
        return http("POST", f"http://{net.domain['b']}/v0/deliver", fields)[0]

    check("control: host b hears a delivery naming that peer", taken_from(peer.domain) != 403, taken_from(peer.domain))
    net.name_peers("b", net.all_but("b", peer.domain))
    check("the peer is removed", wait_until(lambda: taken_from(peer.domain) == 403, IN_FORCE_SECS))
    # A call may have been on its way as the list changed.
    time.sleep(1)
    peer.hits.clear()
    for _ in range(3):
        net.due_now("b", "stops_to_pass_on")
        time.sleep(1)
    check("the removed peer is called no more, though the retirement is due", "/v0/retirements" not in peer.hits, peer.hits)

    peer.accept_everything()
    net.name_peers("b", net.listed["b"])

    def told_again() -> bool:
        net.due_now("b", "stops_to_pass_on")
        return "/v0/retirements" in peer.hits

    check("and it's told once it's back in the file", wait_until(told_again), peer.hits)


def a_file_that_cant_be_used_changes_nothing(net: FileNetwork) -> None:
    """Bug: a typo in the file, or a moment with no file, cuts a host off from its peers."""
    without_ben = "".join(f"peer {peer}\n" for peer in net.all_but("a", net.domain["b"]))
    pid = net.pid("a")
    log = net.hosts["a"].log_path
    said_before = log.read_text().count(str(net.peers_file["a"]))
    unusable = {
        "a line that's no directive": f"private\n{without_ben}allow everyone\n",
        "a host that isn't a domain": f"private\n{without_ben}peer not_a_host\n",
        "a peer plain HTTP can't reach": f"private\n{without_ben}peer host.example\n",
        "bytes that aren't text": b"private\n\xff\xfe\n",
    }
    for name, content in unusable.items():
        net.write_peers("a", content)
        time.sleep(IN_FORCE_SECS)
        check(f"{name}: mail still goes to the peer that file left out", arrives(net, "ana", "ben", f"sent under {name}"))
    net.peers_file["a"].unlink()
    time.sleep(IN_FORCE_SECS)
    check("no file at all: mail still goes", arrives(net, "ana", "ben", "sent with no peers file there"))
    check("and Ana's host is still running", net.never_restarted("a", pid))
    said = log.read_text().count(str(net.peers_file["a"])) - said_before
    # Five unusable files over half a minute are fifteen readings or more, and a line a minute.
    check("its log says which file it couldn't use, without a line for every reading", 1 <= said <= 2, said)

    net.write_peers("a", f"private\n{without_ben}")
    check("control: the same file without the bad line is taken", send_gets(net, "ana", "ben", "for a peer a usable file left out", 502))
    net.name_peers("a", net.listed["a"])
    check("control: and the full list is taken back", send_gets(net, "ana", "ben", "sent once the file was whole", 200))
    time.sleep(1)
    net.ack_all("ben")


def a_repin_line_takes_a_new_key_once(net: FileNetwork) -> None:
    """Bug: a peer that changed its key stays cut off until a restart. Or the line, left in the file,
    lets go of the pin again later, when whoever serves that name then could bring a key of their own."""
    peer = net.key_changing_peer
    keys = [net.work / f"peer-key-{number}.key" for number in range(3)]
    public = [e2e.new_key(key) for key in keys]
    published = {"key": public[0]}
    peer.respond = lambda _path, _sent: (200, {}, json.dumps({"domain": peer.domain, "key": published["key"]}).encode())

    def delivers(signer: Path) -> int:
        envelope = net.envelope_signed_by("mallory", "mallory", "ben", "a message from a peer that changes its key")
        fields = {
            "envelope": envelope, "sender_identity": net.agent_identity("mallory"), "from_host": peer.domain,
            "proof": net.host_proof(signer, envelope, peer.domain, net.domain["b"]),
        }
        return http("POST", f"http://{net.domain['b']}/v0/deliver", fields)[0]

    def refused(signer: Path) -> bool:
        return 400 <= delivers(signer) < 500

    check("control: the first delivery pins the key the peer published", delivers(keys[0]) == 200)
    published["key"] = public[1]
    check("control: a new key the peer now publishes is refused", refused(keys[1]))
    pid = net.pid("b")

    repin = f"repin {peer.domain}"
    net.name_peers("b", net.listed["b"], repin)
    check("a repin line lets the peer's new key in", wait_until(lambda: delivers(keys[1]) == 200, IN_FORCE_SECS))
    check("and the old key stops working", refused(keys[0]))
    check("with host b never restarted", net.never_restarted("b", pid))

    published["key"] = public[2]
    unused = f"127.0.0.1:{e2e.free_port()}"
    net.name_peers("b", [*net.listed["b"], unused], repin)
    # A delivery naming the new peer stops being refused as off the list once this file is in force.
    proofless = {"envelope": net.envelope_signed_by("mallory", "mallory", "ben", "a probe"), "sender_identity": "", "from_host": unused, "proof": "x"}
    check("control: another line of the file changes", wait_until(lambda: http("POST", f"http://{net.domain['b']}/v0/deliver", proofless)[0] != 403, IN_FORCE_SECS))
    check("the repin line, still there, doesn't let go of the pin again", refused(keys[2]))
    net.hosts["b"].kill_hard()
    net.hosts["b"].start()
    check("control: host b restarts with the line still in its file", net.wait_for_host("b"))
    check("nor does a restart", refused(keys[2]))
    check("control: the key pinned by the line still works", delivers(keys[1]) == 200)

    net.name_peers("b", net.listed["b"])
    time.sleep(IN_FORCE_SECS)
    check("control: with the line out, the pin holds", refused(keys[2]))
    net.name_peers("b", net.listed["b"], repin)
    check("taking the line out and putting it back asks again", wait_until(lambda: delivers(keys[2]) == 200, IN_FORCE_SECS))
    net.name_peers("b", net.listed["b"])
    net.ack_all("ben")


def how_a_host_starts(net: FileNetwork) -> None:
    """Bug: a host starts with a file it can't use and talks to nobody, or to hosts the operator
    never named. Or a host upgraded with the old setting still set loses its peers."""
    domain = f"127.0.0.1:{e2e.free_port()}"
    database = net.postgres.create_database("host_starting")
    file = net.work / "starting.peers"
    starts = iter(range(100))

    def started(**settings: str) -> e2e.Process:
        return net.spawn_as_given(f"host-starting-{next(starts)}", {
            "SPLINT_DOMAIN": domain, "SPLINT_LISTEN": domain, "SPLINT_DATABASE_URL": database,
            "SPLINT_HOST_KEY_FILE": str(net.work / "host-starting.key"), **e2e.PLAIN_HTTP_FOR_TESTS, **settings,
        })

    def came_up(process: e2e.Process) -> bool:
        wait_until(lambda: process.has_exited() or http("GET", f"http://{domain}/.well-known/splint/host")[0] == 200)
        return not process.has_exited()

    def hears_host_a() -> int:
        """What this host says to a real delivery from host a, for an agent it doesn't have: 404 when
        it names host a, and 403 when it doesn't."""
        envelope = net.envelope_signed_by("ana", "ana", "ben", "a delivery to a host that's starting")
        fields = {
            "envelope": envelope, "sender_identity": net.agent_identity("ana"), "from_host": net.domain["a"],
            "proof": net.host_proof(net.work / "host-a.key", envelope, net.domain["a"], domain),
        }
        return http("POST", f"http://{domain}/v0/deliver", fields)[0]

    file.write_text(f"private\npeer {net.domain['a']}\n")
    host = started(SPLINT_PEERS_FILE=str(file))
    check("control: a host starts with a file it can use", came_up(host))
    check("control: and hears the peer it names", hears_host_a() == 404, hears_host_a())
    host.kill_hard()

    for name, content in {
        "a line that's no directive": f"peer {net.domain['a']}\nallow everyone\n",
        "a host that isn't a domain": "peer not_a_host\n",
        "a peer plain HTTP can't reach": "peer host.example\n",
    }.items():
        file.write_text(content)
        host = started(SPLINT_PEERS_FILE=str(file))
        check(f"a host won't start with {name} in its file", not came_up(host))
        host.kill_hard()
    host = started(SPLINT_PEERS_FILE=str(net.work / "no-such.peers"))
    check("or with a file that isn't there", not came_up(host))
    host.kill_hard()

    host = started(SPLINT_PEERS=net.domain["a"])
    check("a host with only the old setting starts", came_up(host))
    check("and hears the peers it lists", hears_host_a() == 404, hears_host_a())
    host.kill_hard()

    file.write_text("private\n")
    host = started(SPLINT_PEERS=net.domain["a"], SPLINT_PEERS_FILE=str(file))
    check("control: a host with both the old setting and a file starts", came_up(host))
    check("and goes by the file, which names nobody", hears_host_a() == 403, hears_host_a())
    host.kill_hard()


def main() -> int:
    e2e.build()
    with e2e.running_network(kind=FileNetwork) as net:
        for scenario in (
            a_host_named_while_running_is_reached,
            removing_a_peer_holds_mail_both_ways,
            a_removed_peer_is_told_of_no_retirement,
            a_file_that_cant_be_used_changes_nothing,
            a_repin_line_takes_a_new_key_once,
            how_a_host_starts,
        ):
            print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
            scenario(net)
        if e2e.failures:
            for process in net.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1500:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

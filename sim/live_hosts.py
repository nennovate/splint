#!/usr/bin/env python3
"""Runs Splint over the real internet against live hosts, and breaks them for real.

    SPLINT_LIVE_HOSTS='a.example=ssh splint-admin@a.example;b.example=ssh splint-admin@b.example' \
        python3 sim/live_hosts.py prove|break|all [--only NAME]

`prove` shows TLS, a packet capture, messages and a managed request. `break` reboots servers and kills
hosts and Postgres in the middle of delivery, and checks each message a sender was told was taken
arrives exactly once. A host being down refuses some sends: nobody was told those were taken, so
they don't count, but each one that landed anyway is reported.

`break` also restores a backup, using the age key named by SPLINT_BACKUP_IDENTITY. This reboots the
servers it's given. Test data only.
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

import e2e
import live_network
import request_driver
from e2e import check

SEND_INTERVAL_SECONDS = 0.2
SEND_SECONDS_BEFORE_BREAK = 6
SEND_SECONDS_AFTER_BREAK = 6
ARRIVAL_WAIT_SECONDS = 240
SERVER_BACK_SECONDS = 300
OUTAGE_SECONDS = 180
KILLS_IN_A_ROW = 3
QUEUE_SECONDS = 8
A_BODY = "live delivery test number {} in {}"
CAPTURE_FILE = "/tmp/splint-capture.pcap"


def curl_ok(url: str, *options: str) -> bool:
    return subprocess.run(["curl", "-sS", "-o", "/dev/null", "-m", "10", "--fail", *options, url], capture_output=True).returncode == 0


def host_is_up(domain: str) -> bool:
    return curl_ok(f"https://{domain}/.well-known/splint/host")


def wait_for_host(domain: str) -> float:
    started = time.monotonic()
    while time.monotonic() - started < SERVER_BACK_SECONDS:
        if host_is_up(domain):
            return time.monotonic() - started
        time.sleep(1)
    raise RuntimeError(f"{domain} didn't come back")


def check_tls_from_outside(net: live_network.LiveNetwork) -> None:
    for name, server in net.servers.items():
        ip = server.ssh[-1].split("@")[-1]
        check(f"{name}: a certificate that checks out for its name", host_is_up(server.domain), server.domain)
        check(f"{name}: the same server by IP fails verification", not curl_ok(f"https://{ip}/.well-known/splint/host"), ip)
        offered = subprocess.run(
            ["openssl", "s_client", "-connect", f"{server.domain}:443", "-servername", server.domain, "-brief", "-verify_return_error"],
            input="", capture_output=True, text=True, timeout=20,
        )
        details = offered.stdout + offered.stderr
        print(f"     {name}: " + "; ".join(line for line in details.splitlines() if line.startswith(("Protocol", "Ciphersuite", "Verification"))))
        check(f"{name}: TLS 1.3 by default", "TLSv1.3" in details, details[-200:])
        redirect = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-m", "10", "-w", "%{http_code} %{redirect_url}", f"http://{server.domain}/v0/inbox"], capture_output=True, text=True).stdout
        check(f"{name}: port 80 only redirects to https", redirect.startswith("308 https://"), redirect)
        for port in (8080, 5432, 2019):
            closed = subprocess.run(["nc", "-z", "-G", "4", ip, str(port)], capture_output=True).returncode != 0
            check(f"{name}: port {port} can't be reached from outside", closed, port)
        for settings in (
            "SPLINT_SCHEME=http",
            "SPLINT_SCHEME=http SPLINT_TEST_ONLY_PLAIN_HTTP=yes",
            "SPLINT_LISTEN=0.0.0.0:8081",
        ):
            refused = server.try_run(f"set -a; . /etc/splint/host.env; set +a; ! runuser -u splint -- env {settings} timeout 5 /usr/local/bin/splint-host")
            check(f"{name}: the real binary with its real settings refuses {settings}", refused, settings)


def check_ssh_from_outside(net: live_network.LiveNetwork) -> None:
    """Root can't log in, even with the key the admin uses, and nothing but a key is offered."""
    for name, server in net.servers.items():
        ip = server.ssh[-1].split("@")[-1]
        as_root = [*server.ssh[:-1], f"root@{ip}", "true"]
        refused = subprocess.run(as_root, capture_output=True, text=True, timeout=30)
        check(f"{name}: root can't log in over SSH with the admin's key", refused.returncode == 255 and "Permission denied" in refused.stderr, refused.stderr[-200:])
        offered = subprocess.run(
            ["ssh", "-v", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none", "-o", "PubkeyAuthentication=no", f"nobody@{ip}", "true"],
            capture_output=True, text=True, timeout=30,
        ).stderr
        methods = [line.rsplit(":", 1)[-1].strip() for line in offered.splitlines() if "Authentications that can continue" in line]
        check(f"{name}: SSH offers only keys", methods and set(methods) == {"publickey"}, methods)
        check(f"{name}: control: the admin logs in and has sudo", server.try_run("true"), server.ssh)


def check_capture(net: live_network.LiveNetwork, body: str) -> None:
    """Runs on the sending host, so it shows what one host really sends the other."""
    a, b = net.servers["a"], net.servers["b"]
    other_ip = b.ssh[-1].split("@")[-1]
    a.run(f"rm -f {CAPTURE_FILE}; apt-get install -y -qq tcpdump >/dev/null 2>&1; true", timeout=200)
    a.run(f"nohup timeout 20 tcpdump -i eth0 -U -w {CAPTURE_FILE} host {other_ip} and tcp port 443 >/dev/null 2>&1 & sleep 2")
    net.send_and_wait("ana", "ben", body)
    time.sleep(1)
    a.try_run("pkill -x tcpdump; sleep 1")
    packets = a.run(f"tcpdump -nn -r {CAPTURE_FILE} 2>/dev/null | wc -l")
    sample = a.run(f"tcpdump -nn -r {CAPTURE_FILE} 2>/dev/null | head -4 | cut -c1-110")
    readable = a.run(f"grep -ac {body.split()[0]!r} {CAPTURE_FILE} || true")
    domains = a.run(f"grep -ao {b.domain} {CAPTURE_FILE} | sort | uniq -c || true")
    a.run(f"rm -f {CAPTURE_FILE}")
    print(f"     capture on {a.domain}: {packets} packets to and from {other_ip}\n{sample}")
    print(f"     only readable name in it, from the handshake: {domains or 'none (the connection was already open)'}")
    check("the capture shows hosts talking over the real network", int(packets) > 0, packets)
    check("the message body isn't readable in the capture", readable.strip() in ("", "0"), readable)


def prove(net: live_network.LiveNetwork) -> None:
    check_tls_from_outside(net)
    check_ssh_from_outside(net)
    marker = f"capture-{net.run_id}"
    net.send_and_wait("ana", "ben", f"{marker} first from ana")
    check_capture(net, f"{marker} second from ana")
    net.send_and_wait("ben", "ana", f"{marker} reply from ben")
    check("messages crossed both ways", any(marker in body for body in net.bodies("ana")) and any(marker in body for body in net.bodies("ben")))

    request = request_driver.open_request(net, "ana", "ben", slots=[request_driver.hours_from_now(24)])
    later = request_driver.hours_from_now(26)
    check("ben sees the request", request_driver.wait_for(net, "ben", request, state="offered") is not None)
    request_driver.move(net, "ben", request, "clarify", {"reason": "other_times"})
    check("ana sees it needs clarifying", request_driver.wait_for(net, "ana", request, state="clarifying") is not None)
    request_driver.move(net, "ana", request, "counter", {"terms": {"duration_min": 30, "slots": [later]}})
    request_driver.wait_for(net, "ben", request, state="offered", version=2)
    request_driver.move(net, "ben", request, "accept", {"pick": {"start": later}})
    check("ana sees it accepted", request_driver.wait_for(net, "ana", request, state="accepted") is not None)
    request_driver.owner_decides(net, "ana", request, subject="Quarterly check-in")
    request_driver.wait_for(net, "ben", request, state="requester_confirmed")
    request_driver.owner_decides(net, "ben", request)
    check("the managed request completes on ana's side", request_driver.wait_for(net, "ana", request, state="completed") is not None)
    for agent in ("ana", "ben"):
        request_driver.wait_for_received(net, agent, request)
    views = {agent: request_driver.view(net, agent, request) for agent in ("ana", "ben")}
    check("both sides recompute the same result", {view.get("state") for view in views.values()} == {"completed"} and {view.get("pick", {}).get("start") for view in views.values()} == {later}, views)
    check("each side holds proof the other saw it", {view.get("other_side") for view in views.values()} == {"proven"}, views)

    for name, server in net.servers.items():
        pinned = server.sql("SELECT domain FROM peer_keys")
        check(f"{name} has pinned its peer's key", net.servers["b" if name == "a" else "a"].domain in pinned, pinned)
    net.fetch_remote_logs()
    logs = net.process_logs()
    check("no message content in any log", not e2e.content_in(logs), e2e.content_in(logs))


class Delivery:
    """Sends from one new agent to another throughout a scenario, and tallies what really arrives."""

    def __init__(self, net: live_network.LiveNetwork, sender: str, recipient: str) -> None:
        self.net, self.sender, self.recipient = net, sender, recipient
        self.confirmed: dict[str, str] = {}
        self.refused: list[str] = []
        self.arrived: Counter[str] = Counter()
        self.acknowledged: set[str] = set()
        self.after_acknowledging: list[str] = []
        self.stopping = threading.Event()
        self.sending = threading.Event()
        self.number = 0
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self.read_inbox, daemon=True)
        self.reader.start()

    def send_for(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.number += 1
            body = A_BODY.format(self.number, self.sender)
            try:
                status, answer = self.net.send(self.sender, self.recipient, body)
            except OSError:
                status, answer = None, {}
            if status == 200:
                with self.lock:
                    self.confirmed[body] = answer["message_id"]
            else:
                self.refused.append(body)
            time.sleep(SEND_INTERVAL_SECONDS)

    def read_inbox(self) -> None:
        while not self.stopping.is_set():
            try:
                messages = self.net.inbox(self.recipient)["messages"]
                with self.lock:
                    for message in messages:
                        body = message["untrusted"]["body"]
                        self.arrived[body] += 1
                        if body in self.acknowledged:
                            self.after_acknowledging.append(body)
                if messages:
                    ids = [message["verified"]["message_id"] for message in messages]
                    status, _ = self.net.agent(self.recipient, "POST", "/v0/inbox/ack", {"message_ids": ids})
                    if status == 200:
                        with self.lock:
                            self.acknowledged.update(message["untrusted"]["body"] for message in messages)
            except (OSError, RuntimeError, ValueError):
                pass
            time.sleep(0.5)

    def missing(self) -> list[str]:
        with self.lock:
            return [body for body in self.confirmed if self.arrived[body] == 0]

    def finish(self, name: str) -> dict:
        started = time.monotonic()
        while self.missing() and time.monotonic() - started < ARRIVAL_WAIT_SECONDS:
            time.sleep(1)
        drained_in = time.monotonic() - started
        time.sleep(5)  # Anything sent twice gets a chance to show up.
        self.stopping.set()
        self.reader.join(timeout=15)
        missing = self.missing()
        # A message stays on show until the agent acknowledges it, so one read as a host goes down is
        # shown again once it's back. Anything shown after a good acknowledgement is a real repeat.
        shown_again = sum(count > 1 for count in self.arrived.values())
        unconfirmed_landed = [body for body in self.refused if self.arrived[body] > 0]
        attempts = self.net.servers[self.net.home[self.sender]].sql(
            f"SELECT coalesce(max(attempts), 0) FROM outbound WHERE sender = '{self.net.ids[self.sender]}'"
        )
        ids = ",".join(f"'{message_id}'" for message_id in self.confirmed.values())
        host_rows = self.net.servers[self.net.home[self.recipient]].sql(
            f"SELECT count(*), count(DISTINCT message_id) FROM inbox WHERE message_id IN ({ids or chr(39) * 2})"
        )
        result = {
            "scenario": name, "confirmed": len(self.confirmed), "refused": len(self.refused), "arrived": sum(count > 0 for count in self.arrived.values()),
            "missing": len(missing), "repeated_after_acknowledging": len(self.after_acknowledging),
            "shown_again_when_an_acknowledgement_failed": shown_again, "unconfirmed_but_landed": len(unconfirmed_landed),
            "most_attempts": int(attempts), "recipient_host_rows": host_rows, "last_arrival_after_seconds": round(drained_in, 1),
        }
        print("     " + json.dumps(result), flush=True)
        check(f"{name}: every confirmed message arrived", not missing, missing[:3])
        check(f"{name}: none came back once acknowledged", not self.after_acknowledging, self.after_acknowledging[:3])
        rows, distinct = host_rows.split("|")
        check(f"{name}: the recipient's host holds each one once", int(rows) == int(distinct) == len(self.confirmed), host_rows)
        check(f"{name}: the control sent something real", len(self.confirmed) > 0, result)
        return result


def scenario(net: live_network.LiveNetwork, name: str, break_it, before: float = SEND_SECONDS_BEFORE_BREAK, after: float = SEND_SECONDS_AFTER_BREAK) -> dict:
    sender, recipient = f"s{name.replace('-', '')}", f"r{name.replace('-', '')}"
    net.add_owned_agents({sender: "a", recipient: "b"}, live_network.SYNC_MILLIS)
    print(f"\n== {name}", flush=True)
    delivery = Delivery(net, sender, recipient)
    delivery.send_for(before)
    breaker = threading.Thread(target=break_it, daemon=True)
    breaker.start()
    delivery.send_for(after)
    breaker.join()
    delivery.send_for(after)
    return delivery.finish(name)


def reboot(server: live_network.Server) -> None:
    server.try_run("systemctl reboot", timeout=15)
    time.sleep(10)
    print(f"     {server.domain} answered again after {10 + wait_for_host(server.domain):.0f}s", flush=True)


def kill_host(server: live_network.Server) -> None:
    # More than once, to land on a delivery that's out on the wire.
    for _ in range(KILLS_IN_A_ROW):
        server.run("pkill -9 -x splint-host")
        came_back = wait_for_host(server.domain)
    print(f"     host killed {KILLS_IN_A_ROW} times, answered again after {came_back:.1f}s", flush=True)


def kill_postgres(server: live_network.Server) -> None:
    server.run("pkill -9 -u postgres -x postgres")
    started = time.monotonic()
    while not server.try_run("pg_isready -q") and time.monotonic() - started < SERVER_BACK_SECONDS:
        time.sleep(1)
    print(f"     Postgres killed, up again after {time.monotonic() - started:.1f}s", flush=True)


def stop_for_a_while(server: live_network.Server) -> None:
    server.run("systemctl stop splint-host")
    time.sleep(OUTAGE_SECONDS)
    server.run("systemctl start splint-host")
    print(f"     host stopped for {OUTAGE_SECONDS}s, then answered after {wait_for_host(server.domain):.1f}s", flush=True)


def reboot_with_mail_queued(sender_server: live_network.Server, recipient_server: live_network.Server) -> None:
    """The queue has to survive on disk, because nothing can leave while the other host is away."""
    recipient_server.run("systemctl stop splint-host")
    time.sleep(QUEUE_SECONDS)
    reboot(sender_server)
    recipient_server.run("systemctl start splint-host")
    wait_for_host(recipient_server.domain)


def backup_and_restore(net: live_network.LiveNetwork) -> None:
    """The private half of the backup key lives off the server, in SPLINT_BACKUP_IDENTITY, and is
    there only for the restore."""
    print("\n== backup and restore", flush=True)
    server = net.servers["b"]
    net.add_owned_agents({"sbackup": "a", "rbackup": "b"}, live_network.SYNC_MILLIS)
    net.send_and_wait("sbackup", "rbackup", "live test message before the backup")
    server.run("systemctl start splint-backup")
    dump = server.run("ls -1t /var/backups/splint/*.sql.gz.age | head -1")
    print(f"     {server.run(f'du -h {dump}')}", flush=True)
    check("no plain copy of the host key is kept with the backups", not server.try_run("test -e /var/backups/splint/host.key"))
    for name in (dump, "/var/backups/splint/host.key.age"):
        check(f"{name} reads as age, not as a dump or a key", server.run(f"head -c 21 {name}") == "age-encryption.org/v1", name)
    check("a dump can't be read without the key off the server", not server.try_run(f"zcat {dump} >/dev/null 2>&1"))
    counted = "SELECT (SELECT count(*) FROM agents), (SELECT count(*) FROM inbox), (SELECT count(*) FROM rules), (SELECT count(*) FROM peer_keys)"
    before = server.sql(counted)
    net.send_and_wait("sbackup", "rbackup", "live test message after the backup")
    identity = Path(os.environ["SPLINT_BACKUP_IDENTITY"]).read_text()
    server.run("umask 077; cat >/root/backup-identity.txt", stdin=identity)
    try:
        server.run(f"/usr/local/bin/splint-restore {dump} /root/backup-identity.txt")
    finally:
        server.run("shred -u /root/backup-identity.txt")
    wait_for_host(server.domain)
    after = server.sql(counted)
    check("restore brings back exactly what the backup held", before == after, (before, after))
    net.send_and_wait("sbackup", "rbackup", "live test message after the restore")


def break_things(net: live_network.LiveNetwork, only: str | None) -> list[dict]:
    a, b = net.servers["a"], net.servers["b"]
    scenarios = {
        "kill-sender-host": (lambda: kill_host(a), {}),
        "kill-recipient-host": (lambda: kill_host(b), {}),
        "kill-sender-postgres": (lambda: kill_postgres(a), {}),
        "kill-recipient-postgres": (lambda: kill_postgres(b), {}),
        "reboot-sender": (lambda: reboot(a), {}),
        "reboot-recipient": (lambda: reboot(b), {}),
        "recipient-away-3-min": (lambda: stop_for_a_while(b), {"after": 5}),
        "reboot-sender-with-mail-queued": (lambda: reboot_with_mail_queued(a, b), {"after": 4}),
    }
    wanted = only.split(",") if only else [*scenarios, "backup"]
    results = [scenario(net, name, fn, **options) for name, (fn, options) in scenarios.items() if name in wanted]
    if "backup" in wanted:
        backup_and_restore(net)
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("prove", "break", "all"))
    parser.add_argument("--only")
    arguments = parser.parse_args()
    e2e.build()
    with live_network.running_network() as net:
        print(f"Run {net.run_id}: {net.domain}", flush=True)
        if arguments.phase in ("prove", "all"):
            prove(net)
        if arguments.phase in ("break", "all"):
            for result in break_things(net, arguments.only):
                print(json.dumps(result))
    print(f"\n{'FAILED: ' + str(e2e.failures) if e2e.failures else 'all passed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

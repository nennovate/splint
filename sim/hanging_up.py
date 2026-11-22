#!/usr/bin/env python3
"""A client hanging up can't leave the database in a transaction, so a 200 from a host stays true.

The bug this names: sqlx sends `BEGIN` and only counts the transaction as open once Postgres answers.
A client that hung up in between had its handler dropped there, so the connection went back to the
pool inside a transaction nobody owned. Unrelated writes then ran inside it and were answered 200, and
all of them rolled back when that connection closed, at a restart or when the pool retired it.

Nothing here leaves that to chance. A small gate on the socket between the real host and real Postgres
holds each `BEGIN` back for as long as a scenario says, and adds nothing else, which the first scenario
shows. So every connection the host has is waiting for `BEGIN` at the moment its clients go away.

    python3 sim/hanging_up.py

Not shown: a real proxy in front, or a client hanging up at any other moment of a request, where sqlx's
own rollback already holds. No keys are hardware-held, and no agent has network limits.
"""

import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import e2e
from e2e import check, http

# What a host's pool holds, and what's left once one listens for notices from other connections, so a
# hold with that many waiting has every connection there is to do anything else.
HOST_CONNECTIONS = 10
FREE_CONNECTIONS = HOST_CONNECTIONS - 1
# More callers than connections, so the pool is sure to be full.
CALLERS = 24
# Long enough for a host to see a reset connection and drop what was handling it.
NOTICED_SECS = 1.0
NOTES = 40
FLOOD = 400
FLOOD_AT_ONCE = 32
# The host's own workers open a few of their own while a flood passes.
LEFT_BEHIND_AT_MOST = 2 * HOST_CONNECTIONS
LEAK_WARNING = "there is already a transaction in progress"
RESET_ON_CLOSE = struct.pack("ii", 1, 0)


def read_exactly(connection: socket.socket, count: int) -> bytes:
    read = b""
    while len(read) < count:
        more = connection.recv(count - len(read))
        if not more:
            raise ConnectionError
        read += more
    return read


class DatabaseGate:
    """Passes every byte between a host and Postgres in order, and while told to, keeps `BEGIN` back."""

    def __init__(self, postgres_port: str) -> None:
        self.postgres_port = int(postgres_port)
        self.changed = threading.Condition()
        self.holding = False
        self.begins = 0
        self.held = 0
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self) -> None:
        while True:
            host_side, _ = self.listener.accept()
            database = socket.create_connection(("127.0.0.1", self.postgres_port))
            for connection in (host_side, database):
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=self.host_to_database, args=(host_side, database), daemon=True).start()
            threading.Thread(target=self.database_to_host, args=(host_side, database), daemon=True).start()

    def host_to_database(self, host_side: socket.socket, database: socket.socket) -> None:
        try:
            length = read_exactly(host_side, 4)
            database.sendall(length + read_exactly(host_side, struct.unpack("!I", length)[0] - 4))
            while True:
                head = read_exactly(host_side, 5)
                body = read_exactly(host_side, struct.unpack("!I", head[1:])[0] - 4)
                if head[:1] == b"Q" and body.startswith(b"BEGIN"):
                    self.wait_at_the_gate()
                database.sendall(head + body)
        except OSError:
            database.close()
            host_side.close()

    def database_to_host(self, host_side: socket.socket, database: socket.socket) -> None:
        try:
            while more := database.recv(65536):
                host_side.sendall(more)
        except OSError:
            pass
        host_side.close()
        database.close()

    def wait_at_the_gate(self) -> None:
        with self.changed:
            self.begins += 1
            if self.holding:
                self.held += 1
                self.changed.notify_all()
            while self.holding:
                self.changed.wait()

    def hold(self) -> None:
        with self.changed:
            self.holding, self.held = True, 0

    def release(self) -> None:
        with self.changed:
            self.holding = False
            self.changed.notify_all()

    def has_held(self, count: int) -> bool:
        with self.changed:
            return self.changed.wait_for(lambda: self.held >= count, e2e.WAIT_SECONDS)


class GatedPostgres(e2e.Postgres):
    """Real Postgres, with the host under test reaching it through the gate."""

    gate: DatabaseGate

    def start(self) -> None:
        super().start()
        self.gate = DatabaseGate(self.port)

    def create_database(self, name: str) -> str:
        direct = super().create_database(name)
        if name != "host_a":
            return direct
        return f"postgres://splint:splint@127.0.0.1:{self.gate.port}/{name}?sslmode=disable"

    def log(self) -> str:
        said = subprocess.run(["docker", "logs", self.name], capture_output=True, text=True, check=True)
        return said.stdout + said.stderr


def leave_a_note(net: e2e.Network) -> tuple[int, str]:
    """What an owner leaves for their agent, sealed, with a proof their own key signed for those bytes."""
    sealed = e2e.encode(os.urandom(120))
    body = json.dumps({"sealed": sealed}, separators=(",", ":")).encode()
    owner, path = net.owners["ana"], f"/v0/owner-mail/{net.ids['ana']}"
    proof = e2e.sign_jws(owner.key, "splint-access", e2e.compact_json({
        "signer": owner.id, "host": net.domain["a"], "method": "POST", "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(), "issued_at": int(time.time()),
    }))
    return http("POST", f"http://{net.domain['a']}{path}", raw=body, auth=proof)[0], sealed


def notes_answered_200(net: e2e.Network, count: int) -> list[str]:
    left = [leave_a_note(net) for _ in range(count)]
    check(f"control: the host answers 200 for all {count} notes", all(status == 200 for status, _ in left), [status for status, _ in left])
    return [sealed for status, sealed in left if status == 200]


def lost_at_a_restart(net: e2e.Network, answered: list[str]) -> list[str]:
    """Kills the host as a crash or an upgrade does, and says which notes it answered 200 for are gone."""
    net.hosts["a"].kill_hard()
    net.hosts["a"].start()
    check("control: the host comes back", net.wait_for_host("a"))
    kept = set(net.postgres.sql("host_a", "SELECT sealed FROM owner_mail").split())
    return [sealed for sealed in answered if sealed not in kept]


def a_call_that_opens_a_transaction(net: e2e.Network) -> bytes:
    """A real call that anyone may make, and whose first use of the database is to open a transaction."""
    history = json.loads((net.work / "ana" / "history.json").read_text())["history"]
    body = json.dumps({"history": history}).encode()
    head = f"PUT /v0/changes HTTP/1.1\r\nHost: {net.domain['a']}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
    return head.encode() + body


def calling(net: e2e.Network, call: bytes) -> socket.socket:
    client = socket.create_connection(("127.0.0.1", net.host_port["a"]), timeout=e2e.WAIT_SECONDS)
    client.sendall(call)
    return client


def read_to_the_end(client: socket.socket) -> bytes:
    """What a client that stays reads, up to the end of the answer, which this call's always has."""
    answer = b""
    while b"\r\n\r\n" not in answer:
        more = client.recv(65536)
        if not more:
            break
        answer += more
    client.close()
    return answer


def hang_up(client: socket.socket) -> None:
    """Resets the connection, as a client that's gone does, with no goodbye for the host to read first."""
    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, RESET_ON_CLOSE)
    client.close()


def open_transactions_nobody_owns(net: e2e.Network) -> str:
    """Transactions open longer than any of the host's own. One left open goes on being used by whatever
    the pool hands its connection to, so it's seldom idle, but it stays as old as its `BEGIN`."""
    return net.postgres.sql("host_a", "SELECT count(*) FROM pg_stat_activity WHERE datname = 'host_a' AND pid <> pg_backend_pid() AND now() - xact_start > interval '1 second'")


def the_gate_changes_nothing_while_it_holds_nothing(net: e2e.Network) -> None:
    """Bug caught: a gate that breaks the host by itself, which would make what follows mean nothing."""
    answered = notes_answered_200(net, 5)
    check("with nothing held back, every note survives a restart", lost_at_a_restart(net, answered) == [])
    check("and Postgres has no warning of a transaction left open", LEAK_WARNING not in net.postgres.log())


def a_client_hanging_up_cant_leave_a_transaction_open(net: e2e.Network) -> None:
    """Bug caught: the connection going back to the pool inside a transaction, and writes after it
    answered 200 and then rolled back."""
    gate = net.postgres.gate
    gate.hold()
    clients = [calling(net, a_call_that_opens_a_transaction(net)) for _ in range(CALLERS)]
    full = gate.has_held(FREE_CONNECTIONS)
    check("control: every connection the host has is waiting for BEGIN", full, gate.held)
    for client in clients:
        hang_up(client)
    time.sleep(NOTICED_SECS)
    gate.release()

    time.sleep(2 * NOTICED_SECS)
    check("no transaction is left open once they've gone", open_transactions_nobody_owns(net) == "0", open_transactions_nobody_owns(net))
    answered = notes_answered_200(net, NOTES)
    # Ordinary calls that open transactions of their own, as any host's next minutes bring, on whatever
    # connections the pool hands out.
    finished = [read_to_the_end(calling(net, a_call_that_opens_a_transaction(net))) for _ in range(CALLERS)]
    check("control: those calls are answered", all(answer.startswith(b"HTTP/1.1 200") for answer in finished), {answer[:12] for answer in finished})
    warnings = net.postgres.log().count(LEAK_WARNING)
    check("Postgres never saw a BEGIN inside a transaction left open", warnings == 0, f"{warnings} times")
    lost = lost_at_a_restart(net, answered)
    check("every note the host answered 200 for survives a restart", lost == [], f"{len(lost)} of {len(answered)} lost")


def a_flood_of_hang_ups_leaves_no_work_behind(net: e2e.Network) -> None:
    """Bug caught: each caller who hung up leaving a task behind to open a transaction nobody wants, so
    a flood costs the database long after it ends."""
    gate = net.postgres.gate
    gate.hold()
    waiting = [calling(net, a_call_that_opens_a_transaction(net)) for _ in range(CALLERS)]
    check("control: every connection is taken while the flood comes", gate.has_held(FREE_CONNECTIONS), gate.held)
    call = a_call_that_opens_a_transaction(net)

    def called_and_gone(_: int) -> None:
        client = calling(net, call)
        time.sleep(0.02)
        hang_up(client)

    with ThreadPoolExecutor(FLOOD_AT_ONCE) as flood:
        list(flood.map(called_and_gone, range(FLOOD)))
    for client in waiting:
        hang_up(client)
    time.sleep(NOTICED_SECS)
    before = gate.begins
    gate.release()
    time.sleep(2 * NOTICED_SECS)
    behind = gate.begins - before
    print(f"     {behind} BEGINs reached Postgres after {FLOOD} callers hung up", flush=True)
    check(f"{FLOOD} callers who hung up leave almost nothing to open afterwards", behind <= LEFT_BEHIND_AT_MOST, behind)
    check("no transaction is left open by the flood", open_transactions_nobody_owns(net) == "0", open_transactions_nobody_owns(net))
    answered = notes_answered_200(net, 5)
    check("and what's answered after it survives a restart too", lost_at_a_restart(net, answered) == [])


def main() -> int:
    e2e.build()
    with e2e.running_network(postgres_kind=GatedPostgres) as net:
        # Nothing but the host and the database is under test, and what a Signet takes off the host
        # would be gone from it for a reason of its own.
        for signet in net.signets.values():
            signet.kill_hard()
        for scenario in (
            the_gate_changes_nothing_while_it_holds_nothing,
            a_client_hanging_up_cant_leave_a_transaction_open,
            a_flood_of_hang_ups_leaves_no_work_behind,
        ):
            print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
            scenario(net)
        if e2e.failures:
            print(f"\n--- host-a.log\n{net.hosts['a'].log_path.read_text()[-1500:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

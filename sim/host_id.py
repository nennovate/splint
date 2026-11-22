#!/usr/bin/env python3
"""A host's ID, with real hosts, Signets and Postgres: a key that changes, and hosts that follow it.

A host used to be its domain and one bare key, pinned by every host that met it. A new key, rotated
or after a loss, meant every one of those operators re-pinned it by hand. Now a host has an ID that
commits to a backup key from a recovery code, and publishes it beside its key. A host that pinned it
follows a key change by itself when the ID shows a valid successor, and refuses anything else.

The older host in the last scenario is the host binary from before host IDs, built here from that
commit, or named by SPLINT_OLDER_HOST. Without either, that scenario is skipped with a warning.

What a host remembers of its looks at other hosts is kept in memory, so restarting Ben's host stands
in for the minute or the hour passing, with no clock to skew.

What this can't show: a real thief who holds a name's TLS certificate. A host started at the same
address stands in for whoever serves the name, which over plain HTTP on loopback is anyone who can
listen on that port.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import e2e
from e2e import check, http, wait_until, warn

PAGE = "/.well-known/splint/host"
# A host reads its ID file every 2 seconds.
TAKEN_SECS = 8
# How many pages of pinned hosts a host reads at once.
LOOKS_AT_ONCE = 4
# The last commit before host IDs, whose host binary stands in for every host already running.
OLDER_HOST_COMMIT = "f2f97fd1"


def key_env(key_file: Path) -> dict[str, str]:
    return {**os.environ, "NO_COLOR": "1", "SPLINT_HOST_KEY_FILE": str(key_file)}


def key_command(key_file: Path, *arguments: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """`splint-host key ...`, as an operator runs it beside the running host."""
    return subprocess.run(
        [str(e2e.TARGET_DIR / "debug" / "host"), "key", *arguments],
        env=key_env(key_file), input=stdin, capture_output=True, text=True, timeout=30,
    )


def code_in(output: str) -> str | None:
    """The recovery code a command printed, on its own indented line."""
    for line in output.splitlines():
        if line.startswith("    ") and re.fullmatch(r"[a-z0-9]{4}(-[a-z0-9]{1,4}){6}", line.strip()):
            return line.strip()
    return None


def page(domain: str) -> dict:
    status, answer = http("GET", f"http://{domain}{PAGE}")
    return answer if status == 200 else {}


def pin(net: e2e.Network, at: str, of: str) -> tuple[str, str]:
    """What a host has pinned for another: its key, and its encoded ID or nothing."""
    row = net.postgres.sql(f"host_{at}", f"SELECT key || '|' || identity FROM peer_keys WHERE domain = '{of}'")
    key, _, identity = row.partition("|")
    return key, identity


def due_now(net: e2e.Network, host: str) -> None:
    net.postgres.sql(f"host_{host}", "UPDATE outbound SET next_attempt_at = now() WHERE status = 'pending'")


def arrives(net: e2e.Network, sender: str, recipient: str, body: str) -> bool:
    """Whether a new message gets from one agent to the other, however long the sender's host backs off."""
    status, _ = net.send(sender, recipient, body)

    def there() -> bool:
        due_now(net, net.home[sender])
        return body in net.bodies(recipient)

    return status == 200 and wait_until(there)


def arrives_first_time(net: e2e.Network, sender: str, recipient: str, body: str) -> tuple[bool, dict]:
    """Whether a new message is delivered on its first try, with no backoff skipped."""
    status, sent = net.send(sender, recipient, body)
    if status != 200:
        return False, sent
    delivered = wait_until(lambda: net.sent_status(sender, sent["message_id"]) in e2e.REACHED)
    report = net.sent_report(sender, sent["message_id"])
    # Once a receipt is back the agent isn't told of tries, so they're its host's.
    tries = net.postgres.sql(f"host_{net.home[sender]}", f"SELECT attempts FROM outbound WHERE message_id = '{sent['message_id']}'")
    return delivered and tries == "1", {**report, "attempts": tries}


def forged_from_a(net: e2e.Network, proof_key: Path, body: str) -> int:
    """A delivery to Ben's host naming Ana's, with a proof signed by this key."""
    envelope = net.envelope_signed_by("ana", "ana", "ben", body)
    return net.deliver(envelope, net.agent_identity("ana"), proof_key)


def deliver_naming(net: e2e.Network, from_host: str, envelope: str, identity: str, proof_key: Path, source: str | None = None) -> int:
    """A delivery to Ben's host naming any host, from one network if `source` says which."""
    proof = net.host_proof(proof_key, envelope, from_host, net.domain["b"])
    fields = {"envelope": envelope, "sender_identity": identity, "from_host": from_host, "proof": proof}
    e2e.remember_content(fields)
    headers = {"Content-Type": "application/json", **({"X-Forwarded-For": source} if source else {})}
    request = urllib.request.Request(f"http://{net.domain['b']}/v0/deliver", data=json.dumps(fields).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def forget_looks(net: e2e.Network) -> None:
    """Ben's host, restarted, as it is once the minute or the hour since its last look has passed."""
    net.hosts["b"].kill_hard()
    net.hosts["b"].start()
    if not net.wait_for_host("b"):
        raise RuntimeError("Ben's host didn't come back")


def some_key(net: e2e.Network, name: str) -> Path:
    path = net.work / f"{name}.der"
    e2e.new_key(path)
    return path


def a_rotation_is_followed(net: e2e.Network, kept: dict) -> None:
    """Bug: a host that changes its key is refused by every host that met it until each operator acts."""
    a, b = net.domain["a"], net.domain["b"]
    key_file = net.work / "host-a.key"
    check("control: Ana and Ben exchange", arrives(net, "ana", "ben", "so Ben's host pins Ana's") and arrives(net, "ben", "ana", "and Ana's pins Ben's"))
    published = page(a)
    check("Ana's host publishes an ID beside its key", bool(published.get("identity")) and bool(published.get("identity_proof")), sorted(published))
    check("and Ben's host pins the ID, not only the key", pin(net, "b", a) == (published["key"], published["identity"]), pin(net, "b", a)[0])
    shutil.copy(key_file, net.work / "a-before.key")
    shutil.copy(f"{key_file}.identity", net.work / "a-before.key.identity")

    coded = key_command(key_file, "code")
    kept["code"] = code_in(coded.stdout)
    check("`splint-host key code` sets a recovery code and shows it once", coded.returncode == 0 and kept["code"] is not None, coded.stderr[-400:])
    check("and only once", key_command(key_file, "code").returncode != 0)
    check("control: --if-unset says nothing when one is set", key_command(key_file, "code", "--if-unset").returncode == 0)
    waiting = subprocess.Popen([str(e2e.TARGET_DIR / "debug" / "host"), "key", "recover"], env=key_env(key_file), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.5)
        check("a recover waiting for its code holds up no other key command", key_command(key_file, "code", "--if-unset").returncode == 0)
    finally:
        waiting.communicate(b"\n", timeout=10)
    check("the running host publishes the coded ID with its key as it was", wait_until(lambda: page(a).get("identity") != published["identity"] and page(a).get("key") == published["key"], TAKEN_SECS))
    check("control: and Ana still reaches Ben", arrives(net, "ana", "ben", "after the code was set"))

    pid = net.hosts["a"].process.pid
    rotated = key_command(key_file, "rotate")
    check("`splint-host key rotate` gives the host a new key", rotated.returncode == 0, rotated.stderr[-400:])
    check("which the running host signs with and publishes within seconds", wait_until(lambda: page(a).get("key") not in (None, published["key"]), TAKEN_SECS))
    new_key = page(a)["key"]

    # A forged proof naming Ana's host gets there first. What Ben's host finds decides, not who made
    # it look, so the forgery is refused and the real change is followed all the same.
    check("a forged delivery naming Ana's host is refused", forged_from_a(net, some_key(net, "forger"), "forged, just after the rotation") == 400)
    check("and Ben's host has followed the rotation all the same", pin(net, "b", a)[0] == new_key, pin(net, "b", a)[0])
    first, report = arrives_first_time(net, "ana", "ben", "Ana's first after her host's new key")
    check("Ana's next message reaches Ben on its first try", first, report)
    check("and Ben's reaches Ana", arrives(net, "ben", "ana", "Ben's after Ana's host's new key"))
    check("with neither host restarted and no peers file changed", net.hosts["a"].process.pid == pid and not net.hosts["a"].has_exited() and not net.hosts["b"].has_exited())
    kept["rotated_key"] = net.work / "a-rotated.key"
    shutil.copy(key_file, kept["rotated_key"])
    net.ack_all("ana")
    net.ack_all("ben")


def a_recovery_is_followed(net: e2e.Network, kept: dict) -> None:
    """Bug: a host that loses its key is a new host, and every host that met it re-pins by hand."""
    a = net.domain["a"]
    key_file = net.work / "host-a.key"
    net.hosts["a"].kill_hard()
    key_file.unlink()
    net.hosts["a"].start()
    stopped = wait_until(lambda: net.hosts["a"].has_exited() or bool(page(a)))
    check("a host whose key is lost won't start with a new one", stopped and net.hosts["a"].has_exited())
    check("control: and doesn't make one", not key_file.exists())

    check("control: a wrong recovery code is refused", key_command(key_file, "recover", stdin="aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa\n").returncode != 0)
    recovered = key_command(key_file, "recover", stdin=f"{kept['code']}\n")
    check("`splint-host key recover` with the code on stdin gives it a new key", recovered.returncode == 0 and key_file.exists(), recovered.stderr[-400:])
    check("and shows the next code", code_in(recovered.stdout) not in (None, kept["code"]))
    kept["code"] = code_in(recovered.stdout)
    net.hosts["a"].start()
    check("control: the host starts", net.wait_for_host("a"))
    new_key = page(a).get("key")
    check("Ana's message reaches Ben with nothing done at Ben's host", arrives(net, "ana", "ben", "Ana's after her host recovered"))
    check("as Ben's host followed the recovery by itself", pin(net, "b", a)[0] == new_key, pin(net, "b", a)[0])
    check("a thief still holding the key before is refused now", forged_from_a(net, kept["rotated_key"], "signed with the key the recovery replaced") == 400)
    check("control: Ben's reaches Ana", arrives(net, "ben", "ana", "Ben's after Ana's host recovered"))
    net.ack_all("ana")
    net.ack_all("ben")


class ServedPage:
    """Answers for a host's page at an address, as whoever holds a name could, and counts each look."""

    def __init__(self, address: tuple[str, int], answer: Callable[[], bytes | None]) -> None:
        self.looks = 0
        self.stall = threading.Event()
        served = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                # Only the page: the agents of the host this stands in for keep calling it too.
                served.looks += self.path == PAGE
                if served.stall.is_set():
                    # Longer than a host waits for another host's page.
                    time.sleep(6)
                    return
                body = answer() if self.path == PAGE else None
                self.send_response(200 if body is not None else 502)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body or b"{}")

            def log_message(self, *_args) -> None:
                pass

        self.server = ThreadingHTTPServer(address, Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def bare_page(domain: str, key: str) -> Callable[[], bytes]:
    """A page with a key and no ID."""
    answer = json.dumps({"domain": domain, "key": key}).encode()
    return lambda: answer


def address_of(domain: str) -> tuple[str, int]:
    return "127.0.0.1", int(domain.rsplit(":", 1)[1])


def impostor(net: e2e.Network, domain: str, name: str, key_dir: Path) -> tuple[e2e.Process, ServedPage]:
    """A real host claiming `domain`, with what it publishes served at that address and counted."""
    listen = f"127.0.0.1:{e2e.free_port()}"
    host = net.spawn("host", f"impostor-{name}", {
        "SPLINT_DOMAIN": domain, "SPLINT_LISTEN": listen,
        "SPLINT_DATABASE_URL": net.postgres.create_database(f"impostor_{name}"),
        "SPLINT_HOST_KEY_FILE": str(key_dir / "host.key"),
        "SPLINT_PEERS_FILE": str(net.peers_file["a"]),
        **e2e.PLAIN_HTTP_FOR_TESTS,
    })

    def relayed() -> bytes | None:
        try:
            with urllib.request.urlopen(f"http://{listen}{PAGE}", timeout=2) as response:
                return response.read()
        except OSError:
            return None

    return host, ServedPage(address_of(domain), relayed)


def refused_after_a_look(net: e2e.Network, served: ServedPage, held: tuple[str, str], of: str, delivered: Callable[[], int]) -> None:
    """A forged delivery is refused, the pin stays, and Ben's host did read what the impostor serves."""
    before = served.looks
    check("its delivery is refused", delivered() == 400)
    check("once Ben's host has read what it serves", served.looks > before, served.looks)
    check("and Ben's host keeps what it pinned", pin(net, "b", of) == held)


def no_valid_succession_is_refused(net: e2e.Network, kept: dict) -> None:
    """Bug: whoever serves a host's name for a while makes the hosts that met it follow them for good."""
    a = net.domain["a"]
    held = pin(net, "b", a)
    net.hosts["a"].kill_hard()

    forget_looks(net)
    old = net.work / "impostor-old"
    old.mkdir()
    shutil.copy(net.work / "a-before.key", old / "host.key")
    shutil.copy(net.work / "a-before.key.identity", old / "host.key.identity")
    os.chmod(old / "host.key", 0o600)
    host, served = impostor(net, a, "old", old)
    check("control: an impostor serves Ana's host's ID and key from before", net.wait_for_host("a") and page(a).get("key") != held[0])
    refused_after_a_look(net, served, held, a, lambda: forged_from_a(net, old / "host.key", "from whoever holds the old key and the name"))
    host.kill_hard()
    served.stop()

    forget_looks(net)
    fresh = net.work / "impostor-fresh"
    fresh.mkdir()
    host, served = impostor(net, a, "fresh", fresh)
    check("control: an impostor serves an ID of its own at the name", net.wait_for_host("a") and bool(page(a).get("identity")))
    refused_after_a_look(net, served, held, a, lambda: forged_from_a(net, fresh / "host.key", "from an ID of the impostor's own"))
    host.kill_hard()
    served.stop()

    forget_looks(net)
    bare_key = some_key(net, "bare-impostor")
    served = ServedPage(address_of(a), bare_page(a, e2e.public_of(bare_key)))
    check("control: an impostor serves a page with a key and no ID", page(a).get("key") == e2e.public_of(bare_key) and "identity" not in page(a))
    refused_after_a_look(net, served, held, a, lambda: forged_from_a(net, bare_key, "from a page with no ID"))
    served.stop()

    forget_looks(net)
    net.hosts["a"].start()
    check("control: the real host is back", net.wait_for_host("a"))
    check("and its agents reach Ben as before", arrives(net, "ana", "ben", "Ana's once her real host is back"))
    net.ack_all("ben")


def a_stolen_key_stops_at_a_quiet_peer(net: e2e.Network, kept: dict) -> None:
    """Bug: a thief holding the key from before a recovery goes on passing at every host the real host
    doesn't deliver to, which never has a proof fail to make it look."""
    a = net.domain["a"]
    key_file = net.work / "host-a.key"
    stolen = net.work / "a-stolen.key"
    shutil.copy(key_file, stolen)
    before = page(a)["key"]
    recovered = key_command(key_file, "recover", stdin=f"{kept['code']}\n")
    kept["code"] = code_in(recovered.stdout)
    check("control: Ana's host recovers while it runs", recovered.returncode == 0 and wait_until(lambda: page(a).get("key") not in (None, before), TAKEN_SECS), recovered.stderr[-400:])
    new_key = page(a)["key"]

    forget_looks(net)
    check("control: Ben's host hasn't heard, so the stolen key still passes there", pin(net, "b", a)[0] == before and forged_from_a(net, stolen, "a thief's, before Ben's host looks") == 200)
    check("and that delivery has Ben's host look, and follow the recovery", wait_until(lambda: pin(net, "b", a)[0] == new_key), pin(net, "b", a)[0])
    check("so the stolen key's next delivery is refused", forged_from_a(net, stolen, "a thief's, after Ben's host looked") == 400)
    net.ack_all("ben")


def slow_pages_cant_shut_a_real_change_out(net: e2e.Network, kept: dict) -> None:
    """Bug: slow pages of hosts someone keeps pinned fill every look, and a look that finds no room is
    dropped, so a real host's change, or the look that ends a stolen key, never gets one."""
    a = net.domain["a"]
    forget_looks(net)
    slow: list[tuple[str, Path, ServedPage]] = []
    for number in range(LOOKS_AT_ONCE):
        domain = f"127.0.0.1:{e2e.free_port()}"
        key = some_key(net, f"slow-{number}")
        slow.append((domain, key, ServedPage(address_of(domain), bare_page(domain, e2e.public_of(key)))))
    identity = net.agent_identity("ana")

    def naming(domain: str, key: Path, body: str, source: str | None = None) -> int:
        return deliver_naming(net, domain, net.envelope_signed_by("ana", "ana", "ben", body), identity, key, source)

    pinned = [naming(domain, key, f"so Ben's host pins {domain}") == 200 and pin(net, "b", domain)[0] == e2e.public_of(key) for domain, key, _ in slow]
    check("control: someone's slow hosts are pinned at Ben's", all(pinned), pinned)
    net.ack_all("ben")

    before = page(a)["key"]
    rotated = key_command(net.work / "host-a.key", "rotate")
    check("control: Ana's host rotates its key", rotated.returncode == 0 and wait_until(lambda: page(a).get("key") not in (None, before), TAKEN_SECS), rotated.stderr[-400:])
    new_key = page(a)["key"]

    forger = some_key(net, "slow-forger")
    holding = []
    for number, (domain, _, served) in enumerate(slow):
        served.stall.set()
        # Each from a network of its own, as an attacker with a few addresses would.
        holding.append(threading.Thread(target=naming, args=(domain, forger, f"holding a look at {domain}", f"203.0.113.{number + 1}"), daemon=True))
        holding[-1].start()
    full = wait_until(lambda: all(served.looks >= 2 for _, _, served in slow), 5)
    answer = forged_from_a(net, forger, "naming Ana's host while every look is held")
    check("control: with every look held, a delivery naming Ana's host is told to come back", full and answer == 503, answer)
    check("and Ben's host looks at Ana's host in its turn, with nothing more sent", wait_until(lambda: pin(net, "b", a)[0] == new_key), pin(net, "b", a)[0])
    for thread in holding:
        thread.join(15)
    for _, _, served in slow:
        served.stop()
    first, report = arrives_first_time(net, "ana", "ben", "Ana's after her change got its turn")
    check("control: Ana's next message reaches Ben on its first try", first, report)
    net.ack_all("ben")


def replace_database(net: e2e.Network, name: str, dump: bytes | None = None) -> None:
    """An empty database under this name, as a new server has, or one holding a dump."""
    net.postgres.sql("splint", f"DROP DATABASE {name}")
    net.postgres.sql("splint", f"CREATE DATABASE {name}")
    if dump is not None:
        subprocess.run(["docker", "exec", "-i", net.postgres.name, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "splint", "-d", name], input=dump, check=True, capture_output=True)


def a_rebuilt_server_comes_back(net: e2e.Network, kept: dict) -> None:
    """Bugs: on a rebuilt server the installer's first start makes an ID of its own, which then stands
    in the way of the backup's at a restore, and of `key recover --identity`, so the host won't start."""
    binary = e2e.TARGET_DIR / "debug" / "host"
    host = started_host(net, binary, "e", [net.domain["a"], net.domain["b"]])
    e = net.domain["e"]
    key_file = net.work / "host-e.key"
    id_file = Path(f"{key_file}.identity")
    net.add_owned_agents({"erin": "e"}, agree=False)
    contacts(net, "erin", "ben")
    check("control: Erin reaches Ben", arrives(net, "erin", "ben", "Erin's before her server is lost"))
    before = page(e)["identity"]
    coded = key_command(key_file, "code")
    code = code_in(coded.stdout)
    check("control: her host sets a recovery code", code is not None and wait_until(lambda: page(e).get("identity") != before, TAKEN_SECS), coded.stderr[-400:])
    published = page(e)
    identity = net.agent_identity("erin")
    backup = net.work / "e-backup"
    backup.mkdir()
    shutil.copy(key_file, backup / "host.key")
    shutil.copy(id_file, backup / "host.key.identity")
    host.kill_hard()
    dump = subprocess.run(["docker", "exec", net.postgres.name, "pg_dump", "--no-owner", "-U", "splint", "-d", "host_e"], check=True, capture_output=True).stdout

    def a_new_server() -> None:
        """The disk gone, and the installer's run on a new one: a first start, then a code set."""
        key_file.unlink()
        id_file.unlink()
        replace_database(net, "host_e")
        host.start()
        came_up = net.wait_for_host("e") and page(e).get("key") != published["key"]
        check("control: the new server's first start makes a host of its own", came_up and key_command(key_file, "code", "--if-unset").returncode == 0)

    a_new_server()
    host.kill_hard()
    replace_database(net, "host_e", dump)
    restored = key_command(key_file, "restore", "--key", str(backup / "host.key"), "--identity", str(backup / "host.key.identity"))
    check("`splint-host key restore` puts the backup's key and ID back", restored.returncode == 0, restored.stderr[-400:])
    host.start()
    check("the restored host starts", net.wait_for_host("e") and not host.has_exited(), host.log_path.read_text()[-400:])
    check("as the host it was", page(e).get("key") == published["key"] and page(e).get("identity") == published["identity"])
    first, report = arrives_first_time(net, "erin", "ben", "Erin's after the restore")
    check("and Erin reaches Ben on the first try", first, report)
    net.ack_all("ben")

    host.kill_hard()
    a_new_server()
    saved = backup / "host.key.identity"
    check("control: a wrong code changes nothing", key_command(key_file, "recover", "--identity", str(saved), stdin="aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa\n").returncode != 0 and page(e).get("key") != published["key"])
    recovered = key_command(key_file, "recover", "--identity", str(saved), stdin=f"{code}\n")
    check("`key recover --identity` takes the ID back on a rebuilt server", recovered.returncode == 0 and code_in(recovered.stdout) is not None, recovered.stderr[-400:])
    host.kill_hard()
    host.start()
    check("the host starts on it", net.wait_for_host("e") and not host.has_exited(), host.log_path.read_text()[-400:])
    now = page(e)
    check("with a new key", now.get("key") not in (None, published["key"]))
    answer = deliver_naming(net, e, net.envelope_signed_by("erin", "erin", "ben", "naming Erin's host"), identity, some_key(net, "e-forger"))
    check("and Ben's host follows it, having looked", answer == 400 and pin(net, "b", e) == (now["key"], now["identity"]), pin(net, "b", e)[0])
    host.kill_hard()


def older_host_binary(net: e2e.Network) -> Path | None:
    """The host from before host IDs: SPLINT_OLDER_HOST, or built here from that commit."""
    named = os.environ.get("SPLINT_OLDER_HOST")
    if named:
        return Path(named)
    target = e2e.TARGET_DIR / "older-host"
    binary = target / "debug" / "host"
    if binary.exists():
        return binary
    source = net.work / "older-source"
    source.mkdir()
    archive = subprocess.run(["git", "archive", OLDER_HOST_COMMIT, "packages"], cwd=e2e.PACKAGES.parent, capture_output=True)
    if archive.returncode != 0:
        return None
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive.stdout, check=True)
    built = subprocess.run(["cargo", "build", "--quiet", "--locked", "-p", "host"], cwd=source / "packages", env={**os.environ, "CARGO_TARGET_DIR": str(target)})
    return binary if built.returncode == 0 else None


def started_host(net: e2e.Network, binary: Path, name: str, peers: list[str]) -> e2e.Process:
    """One more host, running this binary and private to the hosts its setting names, as a host from
    before host IDs was."""
    net.domain[name] = f"127.0.0.1:{e2e.free_port()}"
    process = e2e.Process("host", f"host-{name}", net.work, {
        "SPLINT_DOMAIN": net.domain[name],
        "SPLINT_LISTEN": net.domain[name],
        "SPLINT_DATABASE_URL": net.postgres.create_database(f"host_{name}"),
        "SPLINT_HOST_KEY_FILE": str(net.work / f"host-{name}.key"),
        "SPLINT_PEERS": ",".join(peers),
        **e2e.PLAIN_HTTP_FOR_TESTS,
        "SPLINT_CLEANUP_SECS": "1",
        "SPLINT_SIGNUP_CODES": ",".join(e2e.signup_code(number) for number in range(e2e.SIGNUP_CODES)),
    })
    process.command = [str(binary)]
    net.processes.append(process)
    net.hosts[name] = process
    process.start()
    if not net.wait_for_host(name):
        raise RuntimeError(f"host {name} didn't start")
    return process


def contacts(net: e2e.Network, agent: str, other: str) -> None:
    """Each owner names the other agent as a contact."""
    for one, two in ((agent, other), (other, agent)):
        everyone = [net.contact_entry(name) for name in net.ids if name != one]
        net.put_rules(one, net.sign_rules(one, everyone))


def older_hosts_keep_working_and_pins_upgrade(net: e2e.Network, kept: dict) -> None:
    """Bugs: a pin from before host IDs never takes one, so that host's first rotation still needs a
    hand re-pin; or a host from before IDs can't talk to one that has them."""
    binary = older_host_binary(net)
    if binary is None or not binary.exists():
        warn("the host from before host IDs could be built or found, for the older-host scenario", False, OLDER_HOST_COMMIT)
        return
    a, b = net.domain["a"], net.domain["b"]
    cara_host = started_host(net, binary, "c", [a, b])
    c = net.domain["c"]
    net.add_owned_agents({"cara": "c"}, agree=False)
    contacts(net, "cara", "ben")
    check("control: an older host publishes no ID", "identity" not in page(c), sorted(page(c)))
    check("Cara, on the older host, reaches Ben", arrives(net, "cara", "ben", "Cara's from a host before IDs"))
    check("and Ben's host pins its key alone", pin(net, "b", c)[1] == "" and pin(net, "b", c)[0] == page(c)["key"])
    check("Ben reaches Cara on it", arrives(net, "ben", "cara", "Ben's to a host before IDs"))

    cara_host.kill_hard()
    held = pin(net, "b", c)
    theirs = net.work / "impostor-coded"
    theirs.mkdir()
    host, served = impostor(net, c, "coded", theirs)
    up = net.wait_for_host("c") and wait_until((theirs / "host.key.identity").exists)
    coded = key_command(theirs / "host.key", "code")
    check("control: an impostor at Cara's name serves an ID with a history of its own", up and coded.returncode == 0 and wait_until(lambda: bool(page(c).get("identity")) and page(c).get("key") != held[0], TAKEN_SECS))
    identity = net.agent_identity("cara")
    refused_after_a_look(net, served, held, c, lambda: deliver_naming(net, c, net.envelope_signed_by("cara", "cara", "ben", "from an impostor, to a pin of a key alone"), identity, theirs / "host.key"))
    host.kill_hard()
    served.stop()
    forget_looks(net)

    cara_host.command = [str(e2e.TARGET_DIR / "debug" / "host")]
    cara_host.start()
    check("control: the same host, updated, starts with its key file", net.wait_for_host("c"))
    check("and publishes an ID around the key it had", bool(page(c).get("identity")) and page(c).get("key") == pin(net, "b", c)[0])
    before = page(c)["key"]
    rotated = key_command(net.work / "host-c.key", "rotate")
    check("control: it rotates its key", rotated.returncode == 0 and wait_until(lambda: page(c).get("key") not in (None, before), TAKEN_SECS), rotated.stderr[-400:])
    first, report = arrives_first_time(net, "cara", "ben", "Cara's after her updated host's first rotation")
    check("a pin from before IDs follows a rotation that key began, on the first try", first, report)
    check("and takes the ID", pin(net, "b", c) == (page(c)["key"], page(c)["identity"]))
    check("control: Ben reaches Cara", arrives(net, "ben", "cara", "Ben's after Cara's host rotated"))

    started_host(net, binary, "d", [a])
    net.add_owned_agents({"dora": "d"}, agree=False)
    contacts(net, "dora", "ana")
    check("an older host reaches a host with an ID", arrives(net, "dora", "ana", "Dora's from a host before IDs"))
    check("and takes its deliveries", arrives(net, "ana", "dora", "Ana's to a host before IDs"))
    before = page(a)["key"]
    rotated = key_command(net.work / "host-a.key", "rotate")
    check("control: Ana's host rotates again", rotated.returncode == 0 and wait_until(lambda: page(a).get("key") not in (None, before), TAKEN_SECS))
    status, sent = net.send("ana", "dora", "Ana's after a rotation an older host can't follow")
    refused = status == 200 and wait_until(lambda: net.sent_report("ana", sent["message_id"]).get("last_failure") is not None)
    check("control: an older host refuses the new key, as every host did before IDs", refused and net.sent_status("ana", sent["message_id"]) not in e2e.REACHED, net.sent_report("ana", sent["message_id"]))
    first, report = arrives_first_time(net, "ana", "ben", "Ana's after the same rotation, to a host that follows it")
    check("while a host with IDs follows the same rotation on the first try", first, report)
    check("control: the older host's own deliveries still go through", arrives(net, "dora", "ana", "Dora's after Ana's host rotated"))


def main() -> int:
    e2e.build()
    kept: dict = {}
    with e2e.running_network() as net:
        for scenario in (
            a_rotation_is_followed,
            a_recovery_is_followed,
            a_stolen_key_stops_at_a_quiet_peer,
            no_valid_succession_is_refused,
            slow_pages_cant_shut_a_real_change_out,
            older_hosts_keep_working_and_pins_upgrade,
            a_rebuilt_server_comes_back,
        ):
            print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
            scenario(net, kept)
        if e2e.failures:
            for process in net.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1500:]}")
    e2e.list_warnings()
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

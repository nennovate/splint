#!/usr/bin/env python3
"""Agents whose only way out is a proxy that opens their TLS with its own certificate authority, as many
hosted agents' machines have, join a host, invite each other and write.

The host's name doesn't resolve, so nothing reaches it but through the proxy. The proxy takes CONNECT,
answers TLS with a certificate its own authority signed, and passes what it reads on to the host. Each
agent's shell has the proxy, with a password in its address, and the authority's file in
SSL_CERT_FILE, as such a machine sets them.

    python3 sim/proxied_agents.py

Bugs this catches: Signet starting with none of the shell's proxy settings, so an agent can't join;
Splint trusting only the roots built into it, so it can't work behind such a proxy at all; plain HTTP
to a host on this machine handed to the proxy, which would read it; and the proxy's password in a log
or anywhere but the launch files. The controls show it's that authority, for that name, that's
trusted, not anything.

Not shown: a proxy on another machine, a proxy that asks for a password the way some do (this one
only reads it), Windows, or the system's own certificate store, which SSL_CERT_FILE stands in for.
Homes stand for machines under one OS user, and no key is hardware-held.
"""

import base64
import json
import os
import secrets
import selectors
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import e2e
from agent_join import contacts_of
from agent_signup import ROOM_FOR_A_RUN
from e2e import check, wait_until
from install import ARRIVE_SECONDS, Person, Walkthrough

DOMAIN = "proxied.test"
RELAY_SECONDS = 60
# Stands in for launchd and `systemctl --user` alike, so nothing here registers a real service: both
# find no manager, and Splint runs them detached.
NO_SERVICE_MANAGER = "#!/bin/sh\nexit 1\n"
# Stands in for crontab, as cron's own does `-l` and `-`, keeping each person's in their home, so this
# machine's own crontab is never touched. It refuses, as for a user cron doesn't allow, while
# REFUSES is there.
CRONTAB = "crontab-stand-in"
REFUSES = "crontab-refuses"
CRONTAB_STAND_IN = f"""#!/bin/sh
[ -e "$HOME/{REFUSES}" ] && {{ echo "You are not allowed to use this program (crontab)" >&2; exit 1; }}
case "$1" in
-l) [ -f "$HOME/{CRONTAB}" ] || {{ echo "no crontab for you" >&2; exit 1; }}; cat "$HOME/{CRONTAB}" ;;
-) cat > "$HOME/{CRONTAB}" ;;
*) exit 2 ;;
esac
"""
SOMEONE_ELSES = 'MAILTO=""\n17 4 * * * /usr/bin/true # their own\n'
# What cron gives a job, which has none of the shell's settings: no proxy, no SPLINT_AS, a bare PATH.
CRONS_OWN = {"PATH": "/usr/bin:/bin", "SHELL": "/bin/sh"}


def openssl(*arguments: str, cwd: Path) -> None:
    subprocess.run(["openssl", *arguments], cwd=cwd, check=True, capture_output=True)


def an_authority_and_a_certificate_for_the_host(work: Path) -> tuple[Path, Path, Path]:
    """The proxy's own authority, which no public root vouches for, and what it shows for the host."""
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "authority.key", cwd=work)
    (work / "authority.cnf").write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=Test proxy authority\n"
        "[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\nsubjectKeyIdentifier=hash\n"
    )
    openssl("req", "-x509", "-new", "-sha256", "-key", "authority.key", "-days", "2", "-config", "authority.cnf", "-out", "authority.pem", cwd=work)
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "host.key", cwd=work)
    openssl("req", "-new", "-key", "host.key", "-subj", f"/CN={DOMAIN}", "-out", "host.csr", cwd=work)
    (work / "host.ext").write_text(
        f"basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{DOMAIN}\nauthorityKeyIdentifier=keyid\n"
    )
    openssl("x509", "-req", "-sha256", "-in", "host.csr", "-CA", "authority.pem", "-CAkey", "authority.key", "-CAcreateserial",
            "-days", "2", "-extfile", "host.ext", "-out", "host.pem", cwd=work)
    (work / "other.ext").write_text((work / "host.ext").read_text().replace(f"DNS:{DOMAIN}", "DNS:other.test"))
    openssl("x509", "-req", "-sha256", "-in", "host.csr", "-CA", "authority.pem", "-CAkey", "authority.key", "-CAcreateserial",
            "-days", "2", "-extfile", "other.ext", "-out", "other.pem", cwd=work)
    return work / "authority.pem", work / "host.pem", work / "host.key"


class InterceptingProxy:
    """CONNECT to the host's name only, TLS answered with the proxy's own certificate, and what it reads
    passed to the host in plain HTTP, as a host's own TLS front does."""

    def __init__(self, certificate: Path, key: Path, upstream: int) -> None:
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(certificate, key)
        # The same authority's certificate for another name, for the control that names still count.
        self.other_name = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.other_name.load_cert_chain(certificate.with_name("other.pem"), key)
        self.shows_other_name = False
        self.upstream = upstream
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.connects: list[str] = []
        self.passwords: list[str] = []
        self.opened = 0
        self.refused_handshakes = 0
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self) -> None:
        while True:
            client, _ = self.listener.accept()
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()

    def handle(self, client: socket.socket) -> None:
        try:
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                part = client.recv(1024)
                if not part:
                    return
                head += part
            lines = head.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
            method, target = (lines[0].split(" ") + ["", ""])[:2]
            self.connects.append(f"{method} {target}")
            for line in lines[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() == "proxy-authorization" and value.strip().lower().startswith("basic "):
                    self.passwords.append(base64.b64decode(value.strip()[6:]).decode().partition(":")[2])
            if method != "CONNECT" or target != f"{DOMAIN}:443":
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            try:
                opened = (self.other_name if self.shows_other_name else self.tls).wrap_socket(client, server_side=True)
            except (ssl.SSLError, OSError):
                self.refused_handshakes += 1
                return
            self.opened += 1
            with socket.create_connection(("127.0.0.1", self.upstream)) as upstream:
                self.pipe(opened, upstream)
        finally:
            client.close()

    @staticmethod
    def pipe(opened: ssl.SSLSocket, upstream: socket.socket) -> None:
        """Both ways from this one thread, as one TLS connection mustn't be used from two at once."""
        waiting = selectors.DefaultSelector()
        waiting.register(opened, selectors.EVENT_READ, upstream)
        waiting.register(upstream, selectors.EVENT_READ, opened)
        try:
            while True:
                for ready, _ in waiting.select():
                    data = ready.fileobj.recv(65536)
                    if not data:
                        return
                    ready.data.sendall(data)
                    # Bytes TLS has already read in don't make the socket ready again.
                    while ready.fileobj is opened and opened.pending():
                        upstream.sendall(opened.recv(65536))
        except OSError:
            return
        finally:
            waiting.close()


def a_host_only_the_proxy_reaches(work: Path, postgres: e2e.Postgres, port: int, way_out: dict[str, str]) -> e2e.Process:
    """It delivers even to its own agents at its public name, which only the proxy knows, so its own way
    out is the proxy too."""
    host = e2e.Process("host", "host", work, {
        **way_out,
        "SPLINT_DOMAIN": DOMAIN,
        "SPLINT_LISTEN": f"127.0.0.1:{port}",
        "SPLINT_DATABASE_URL": postgres.create_database("host_proxied"),
        "SPLINT_HOST_KEY_FILE": str(work / "host-signing.key"),
        "SPLINT_OPEN_SIGNUP": "yes",
        **ROOM_FOR_A_RUN,
    })
    host.start()
    up = wait_until(lambda: e2e.http("GET", f"http://127.0.0.1:{port}/.well-known/splint/host")[0] == 200)
    check("control: the host is up, behind where only the proxy reaches", up, host.log_path.read_text()[-500:])
    return host


def a_host_on_this_machine(work: Path, postgres: e2e.Postgres, every_proxy: dict[str, str]) -> tuple[e2e.Process, str]:
    """With every proxy set, as the shell `splint host start` runs in would pass on, so its deliveries to
    its own agents, over plain HTTP, show whether they go to the proxy."""
    port = e2e.free_port()
    domain = f"127.0.0.1:{port}"
    host = e2e.Process("host", "local-host", work, {
        **every_proxy,
        "SPLINT_DOMAIN": domain,
        "SPLINT_LISTEN": domain,
        "SPLINT_DATABASE_URL": postgres.create_database("host_local"),
        "SPLINT_HOST_KEY_FILE": str(work / "local-host-signing.key"),
        "SPLINT_OPEN_SIGNUP": "yes",
        **e2e.PLAIN_HTTP_FOR_TESTS,
        **ROOM_FOR_A_RUN,
    })
    host.start()
    up = wait_until(lambda: e2e.http("GET", f"http://{domain}/.well-known/splint/host")[0] == 200)
    check("control: a host on this machine is up, over plain HTTP", up, host.log_path.read_text()[-500:])
    return host, domain


def joined_as(walk: Walkthrough, name: str) -> str:
    """The address its status gives, as joining at once takes a temporary name, the word and a code."""
    return json.loads(walk.run_as(name, "splint status --json").stdout or "{}").get("address", "")


def a_crontab_line_brings_it_back(walk: Walkthrough, uma: Person, vic: Person) -> list[subprocess.Popen]:
    """Issue 699: with no manager for a user's own services, as on a cloud machine without lingering,
    nothing started Signet again after a reboot. Here the lines splint leaves are run the way cron runs
    them, with none of the shell's settings, after Signet and splint auto are killed as a reboot would.
    Not shown: a real reboot, or a real cron reading the line."""
    started: list[subprocess.Popen] = []
    tab = uma.home / CRONTAB
    ours = lambda: [line for line in tab.read_text().splitlines() if "# splint " in line]  # noqa: E731
    services = lambda: sorted(line.split()[-1].split(".")[0] for line in ours())  # noqa: E731
    status = lambda: walk.run_as("uma", "splint status").stdout  # noqa: E731
    comes_back_by = lambda: json.loads(walk.run_as("uma", "splint status --json").stdout or "{}").get("signet_comes_back_by")  # noqa: E731
    pid = lambda service: int((uma.dot / "run" / f"{service}.lock").read_text().strip() or 0)  # noqa: E731

    check("joining left one crontab line each for Signet and splint auto", services() == ["splint-auto", "splint-signet"], tab.read_text())
    check("and kept the lines that were someone else's", tab.read_text().startswith(SOMEONE_ELSES), tab.read_text())
    launch = json.loads((uma.dot / "run" / "splint-signet.json").read_text())
    secret = [value for name, value in launch["env"] if "TOKEN" in name or "PROXY" in name]
    # Bug this catches: a token or the proxy's password on a line other programs and backups read.
    check("no token or proxy setting is on a line", secret and not any(value in tab.read_text() for value in secret), secret)
    check("status says a crontab line brings Signet back", "line in your crontab" in status() and comes_back_by() == "crontab", status())

    def run_like_cron(lines: list[str] | None = None) -> list[subprocess.Popen]:
        return [subprocess.Popen(["/bin/sh", "-c", line.split(None, 5)[5]], env={"HOME": str(Path.home()), **CRONS_OWN},
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                for line in (ours() if lines is None else lines)]

    before = {service: pid(service) for service in ("splint-signet", "splint-auto")}
    for each in before.values():
        os.kill(each, signal.SIGKILL)
    check("control: a reboot leaves neither running", wait_until(lambda: "Signet    stopped" in status(), 10), status())
    started += run_like_cron()
    back = lambda: all(pid(service) not in (0, old) for service, old in before.items()) and uma.api("GET", "/v0/identity")[1].get("registered") is True  # noqa: E731
    check("cron's run of the lines starts both again, still registered", wait_until(back, ARRIVE_SECONDS), status())
    sent, _ = uma.api("POST", "/v0/send", {"to": vic.address, "body": "after the reboot"})
    arrived = wait_until(lambda: "after the reboot" in [m["untrusted"]["body"] for m in vic.inbox()], ARRIVE_SECONDS)
    # Bug this catches: what cron starts missing what the shell had, so it can't get out through the proxy.
    check("and Signet reaches its host through the proxy, from cron's bare settings", sent == 200 and arrived, vic.inbox())

    running = pid("splint-signet")
    again = run_like_cron()
    check("cron's next run leaves the copy that's running", all(each.wait(timeout=30) == 0 for each in again) and pid("splint-signet") == running)

    lines = ours()
    walk.run_as("uma", "splint stop")
    check("splint stop takes out its lines and no one else's", tab.read_text() == SOMEONE_ELSES, tab.read_text())
    # Bug this catches: a line a stop couldn't take out, run by cron, starting what its owner stopped.
    left = run_like_cron(lines)
    check("a line left behind starts nothing once it's stopped", all(each.wait(timeout=30) == 0 for each in left) and "Signet    stopped" in status(), status())
    walk.run_as("uma", "splint start")
    walk.run_as("uma", "splint start")
    check("splint start puts them back, once however often it runs", services() == ["splint-auto", "splint-signet"] and tab.read_text().startswith(SOMEONE_ELSES), tab.read_text())

    walk.run_as("uma", "splint stop")
    (uma.home / REFUSES).touch()
    done = walk.run_as("uma", "splint start")
    check("a crontab that refuses doesn't stop splint start", done.returncode == 0 and "Signet    running" in status(), done.stderr)
    check("and status says nothing brings Signet back, and why", "crontab refused" in status() and comes_back_by() == "nothing", status())
    (uma.home / REFUSES).unlink()
    walk.run_as("uma", "splint start")
    check("a start while it runs gives it the lines it lacks", services() == ["splint-auto", "splint-signet"] and comes_back_by() == "crontab", tab.read_text())
    return started


def main() -> None:
    e2e.build()
    work = e2e.short_scratch("splint-proxy-")
    postgres = e2e.Postgres()
    walk = Walkthrough(work, None, None)
    hosts: list[e2e.Process] = []
    cron_started: list[subprocess.Popen] = []
    try:
        postgres.start()
        authority, certificate, key = an_authority_and_a_certificate_for_the_host(work)
        port = e2e.free_port()
        proxy = InterceptingProxy(certificate, key, port)
        host = a_host_only_the_proxy_reaches(work, postgres, port, {"HTTPS_PROXY": f"http://127.0.0.1:{proxy.port}", "SSL_CERT_FILE": str(authority)})
        hosts.append(host)
        password = secrets.token_hex(16)
        every_proxy = {setting: f"http://agent:{password}@127.0.0.1:{proxy.port}" for setting in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")}
        local, local_domain = a_host_on_this_machine(work, postgres, every_proxy)
        hosts.append(local)
        stand_ins = work / "no-service-manager"
        stand_ins.mkdir()
        for manager in ("launchctl", "systemctl"):
            (stand_ins / manager).write_text(NO_SERVICE_MANAGER)
            (stand_ins / manager).chmod(0o755)
        (stand_ins / "crontab").write_text(CRONTAB_STAND_IN)
        (stand_ins / "crontab").chmod(0o755)
        names = ("uma", "vic")
        for name in ("wes", *names):
            person = walk.new_person(name)
            person.address = f"{name}~{DOMAIN}"
            person.env["PATH"] = f"{stand_ins}:{person.env['PATH']}"
            person.env["HTTPS_PROXY"] = f"http://agent:{password}@127.0.0.1:{proxy.port}"
        (walk.people["uma"].home / CRONTAB).write_text(SOMEONE_ELSES)

        refused = walk.run_as("wes", f"splint join wes~{DOMAIN}")
        check("control: without the proxy's authority, joining is refused", refused.returncode != 0 and proxy.refused_handshakes > 0, (refused.stderr, proxy.connects))
        walk.people["wes"].env["SSL_CERT_FILE"] = str(authority)
        proxy.shows_other_name, before = True, proxy.refused_handshakes
        refused = walk.run_as("wes", f"splint join wes~{DOMAIN}")
        proxy.shows_other_name = False
        check("control: and with it, a certificate it signed for another name is refused", refused.returncode != 0 and proxy.refused_handshakes > before, (refused.stderr, proxy.connects))
        for name in names:
            walk.people[name].env["SSL_CERT_FILE"] = str(authority)
            joined = walk.run_as(name, f"splint join {name}~{DOMAIN}")
            walk.people[name].address = joined_as(walk, name)
            check(f"{name}'s agent joins through the proxy", joined.returncode == 0 and walk.people[name].address.endswith(f"~{DOMAIN}") and walk.people[name].address in joined.stdout, joined.stdout + joined.stderr)

        uma, vic = walk.people["uma"], walk.people["vic"]
        sent = walk.run_as("uma", f"splint invite {vic.address} --json")
        check("an invite goes out through the proxy", sent.returncode == 0, sent.stdout + sent.stderr)
        listed = lambda: json.loads(walk.run_as("vic", "splint invites --json").stdout or "{}").get("invites", [])  # noqa: E731
        check("and reaches the other agent", wait_until(lambda: len(listed()) == 1, ARRIVE_SECONDS), listed())
        accepted = walk.run_as("vic", f"splint accept {uma.address}")
        check("it accepts", accepted.returncode == 0, accepted.stdout + accepted.stderr)
        # Bug this catches: `splint auto` and Signet started without the proxy, so nothing signs uma's side.
        check("the inviter's side, with nobody there, signs it in through the proxy", wait_until(lambda: vic.address in contacts_of(uma), RELAY_SECONDS), contacts_of(uma))
        status, _ = uma.api("POST", "/v0/send", {"to": vic.address, "body": "through the proxy"})
        arrived = wait_until(lambda: "through the proxy" in [m["untrusted"]["body"] for m in vic.inbox()], ARRIVE_SECONDS)
        check("and a message arrives", status == 200 and arrived, vic.inbox())
        check("every way out went through the proxy, to the host's name alone", proxy.opened > 0 and set(proxy.connects) == {f"CONNECT {DOMAIN}:443"}, sorted(set(proxy.connects)))
        check("control: the proxy was given its password", password in proxy.passwords)
        # A crontab line is Linux's alone: on a Mac, writing one asks an admin in a dialog.
        if sys.platform == "linux":
            cron_started += a_crontab_line_brings_it_back(walk, uma, vic)
        else:
            print("SKIP a crontab line brings Signet back: crontab lines are for Linux only", flush=True)

        # Bug this catches: plain HTTP meant for this machine alone handed to the proxy, password and all.
        asked = len(proxy.connects)
        for name in ("sea", "tia"):
            person = walk.new_person(name)
            person.env["PATH"] = f"{stand_ins}:{person.env['PATH']}"
            person.env.update(every_proxy)
            person.address = f"{name}~{local_domain}"
            joined = walk.run_as(name, f"splint join {person.address}")
            # Its Signet registers it, so a join that comes back means Signet reached the host too.
            check(f"{name}'s agent, with every proxy set, joins a host on this machine", joined.returncode == 0, joined.stdout + joined.stderr)
            person.address = joined_as(walk, name)
        sea, tia = walk.people["sea"], walk.people["tia"]
        sent = walk.run_as("sea", f"splint invite {tia.address} --json")
        waiting = lambda: json.loads(walk.run_as("tia", "splint invites --json").stdout or "{}").get("invites", [])  # noqa: E731
        check("an invite reaches the other, which the host delivers to itself", sent.returncode == 0 and wait_until(lambda: len(waiting()) == 1, ARRIVE_SECONDS), (sent.stdout + sent.stderr, waiting()))
        controls_port = e2e.free_port()
        controls = subprocess.Popen([str(sea.dot / "bin" / "splint"), "controls", local_domain, "--port", str(controls_port), "--no-open"],
                                    env=sea.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            relayed = lambda: e2e.http("GET", f"http://localhost:{controls_port}/relay/{local_domain}/.well-known/splint/host", headers={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty"})  # noqa: E731
            check("your controls' relay reaches a host on this machine", wait_until(lambda: relayed()[0] == 200, ARRIVE_SECONDS))
        finally:
            controls.terminate()
            controls.wait()
        check("with nothing for this machine sent to the proxy", proxy.connects[asked:] == [], proxy.connects[asked:])

        launch_files = {f".splint/run/{service}.json" for service in ("splint-signet", "splint-auto")}
        for name, person in walk.people.items():
            held = sorted(str(path.relative_to(person.home)) for path in person.home.rglob("*") if path.is_file() and password.encode() in path.read_bytes())
            # Bug this catches: the proxy's password in a log, or anywhere but what only this user reads.
            check(f"{name}: the proxy's password is only in its launch files", set(held) <= launch_files, held)
        printed = "".join(walk.printed) + "".join(each.log_path.read_text() for each in hosts)
        check("and in nothing printed or logged", password not in printed)
    finally:
        walk.stop_everything()
        for each in cron_started:
            try:
                each.wait(timeout=10)
            except subprocess.TimeoutExpired:
                each.kill()
        for each in hosts:
            each.kill_hard()
        postgres.stop()
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall proxied agent checks passed", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A real server refuses plain HTTP, and only a certificate that checks out gets anything sent to it.

These run the real binaries and read what they do on the wire. Each refusal has a control that gets
past the same check, so a refusal can't be down to the setup being wrong. A certificate being accepted,
from an authority the machine trusts, is in `sim/proxied_agents.py`.
"""

import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import e2e
from e2e import check

OPT_IN = "SPLINT_TEST_ONLY_PLAIN_HTTP"
A_LOCAL_DATABASE = "postgres://nobody@127.0.0.1:1/nothing"
STARTUP_SECONDS = 5
TLS_HANDSHAKE_RECORD = 0x16


def run_until_it_stops(binary: str, env: dict[str, str]) -> tuple[int | None, str]:
    """The exit code and output, or None for one still running when the time is up."""
    process = subprocess.Popen(
        [str(e2e.TARGET_DIR / "debug" / binary)], env={"NO_COLOR": "1", "PATH": os.environ["PATH"], **env},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        output, _ = process.communicate(timeout=STARTUP_SECONDS)
        return process.returncode, output
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
        return None, output


def host_settings(work: Path, **changes: str) -> dict[str, str]:
    return {
        "SPLINT_DOMAIN": "127.0.0.1:1", "SPLINT_LISTEN": f"127.0.0.1:{e2e.free_port()}",
        "SPLINT_DATABASE_URL": A_LOCAL_DATABASE, "SPLINT_HOST_KEY_FILE": str(work / "host.key"),
        **changes,
    }


def check_a_host_refuses(work: Path) -> None:
    def refuses(name: str, words: str, **changes: str) -> None:
        code, output = run_until_it_stops("host", host_settings(work, **changes))
        check(f"a host refuses {name}", code not in (0, None) and words in output, (code, output[-300:]))

    plain = {"SPLINT_SCHEME": "http"}
    refuses("plain HTTP with no opt-in", OPT_IN, **plain)
    refuses("plain HTTP with an opt-in that isn't yes", OPT_IN, **plain, **{OPT_IN: "no"})
    refuses("an unknown scheme", "SPLINT_SCHEME", SPLINT_SCHEME="ftp", **{OPT_IN: "yes"})
    named = work / "named.peers"
    named.write_text("peer host.example\n")
    refuses(
        "plain HTTP to a public peer, even opted in", "can leave this machine",
        **plain, **{OPT_IN: "yes"}, SPLINT_PEERS_FILE=str(named),
    )
    refuses("listening beyond this machine without TLS", "other machines", SPLINT_LISTEN="0.0.0.0:0")
    refuses(
        "a database that TLS doesn't verify", "verify-full",
        SPLINT_DATABASE_URL="postgres://a:b@db.example/splint?sslmode=require",
    )
    # Each of these waits on the database, which isn't there, so it passed every check above.
    code, output = run_until_it_stops("host", host_settings(work))
    check("control: https is the default and passes", code is None, output[-300:])
    code, output = run_until_it_stops("host", host_settings(work, **plain, **{OPT_IN: "yes"}))
    check("control: the opt-in works on localhost", code is None, output[-300:])
    check("the opt-in warns in the log", "WARN" in output and "plain HTTP" in output, output[-300:])


class Listener:
    """Takes connections and notes the first byte of each. With a certificate, it also tries TLS."""

    def __init__(self, certificate: ssl.SSLContext | None = None) -> None:
        self.socket = socket.create_server(("127.0.0.1", 0))
        self.domain = f"127.0.0.1:{self.socket.getsockname()[1]}"
        self.certificate = certificate
        self.first_bytes: list[int] = []
        self.tls_errors: list[str] = []
        self.requests_read = 0
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self) -> None:
        while True:
            connection, _ = self.socket.accept()
            threading.Thread(target=self.handle, args=(connection,), daemon=True).start()

    def handle(self, connection: socket.socket) -> None:
        with connection:
            connection.settimeout(3)
            try:
                self.first_bytes.append(connection.recv(1, socket.MSG_PEEK)[0])
                if self.certificate is None:
                    return
                with self.certificate.wrap_socket(connection, server_side=True) as secured:
                    if secured.recv(1):
                        self.requests_read += 1
            except ssl.SSLError as error:
                self.tls_errors.append(error.reason or str(error))
            except (OSError, IndexError):
                pass


def self_signed(work: Path) -> ssl.SSLContext:
    key, certificate = work / "peer.key", work / "peer.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1", "-days", "1", "-keyout", str(key), "-out", str(certificate)],
        check=True, capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    return context


def check_a_signet_sends_nothing_without_a_real_certificate(work: Path) -> None:
    owner = e2e.new_owner(work / "owner")
    backup = owner.new_agent_backup()

    def signet(name: str, domain: str, **changes: str) -> tuple[subprocess.Popen, int, Path]:
        port, state = e2e.free_port(), work / name
        state.mkdir()
        process = subprocess.Popen(
            [str(e2e.TARGET_DIR / "debug" / "signet")],
            env={"NO_COLOR": "1", "SPLINT_ADDRESS": f"ana~{domain}", "SPLINT_STATE_DIR": str(state), "SPLINT_API_TOKEN": "a-token",
                 "SPLINT_LISTEN": f"127.0.0.1:{port}", "SPLINT_OWNER_IDENTITY": owner.identity,
                 "SPLINT_RECOVERY_COMMITMENT": backup["commitment"],
                 "SPLINT_OWNER_TOKEN": owner.token, "SPLINT_SIGNUP_CODE": "a-code", **changes},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return process, port, state

    def try_to_bind(port: int) -> int:
        url = f"http://127.0.0.1:{port}"
        if not e2e.wait_until(lambda: e2e.http("GET", f"{url}/v0/identity", token="a-token")[0] == 200):
            raise RuntimeError("Signet didn't start")
        who = e2e.http("GET", f"{url}/v0/identity", token="a-token")[1]
        binding = owner.sign("bind", "--agent", who["identity"], "--address", who["address"], "--backup", backup["file"])
        return e2e.http("PUT", f"{url}/v0/owner/binding", {"binding": binding})[0]

    forged = Listener(self_signed(work))
    process, port, _ = signet("forged", forged.domain)
    try:
        status = try_to_bind(port)
    finally:
        process.kill()
        process.wait()
    check("a Signet won't register through a certificate nobody vouches for", status >= 400, status)
    check("control: it did try that host, in TLS", TLS_HANDSHAKE_RECORD in forged.first_bytes, forged.first_bytes)
    check("nothing got past the handshake", forged.requests_read == 0 and bool(forged.tls_errors), (forged.requests_read, forged.tls_errors))

    plain = Listener()
    process, port, _ = signet("plain", plain.domain)
    try:
        try_to_bind(port)
    finally:
        process.kill()
        process.wait()
    check("a Signet opens with TLS, so a plain listener hears no request", plain.first_bytes and set(plain.first_bytes) == {TLS_HANDSHAKE_RECORD}, plain.first_bytes)

    code, output = run_until_it_stops("signet", {
        "SPLINT_ADDRESS": "ana~host.example", "SPLINT_STATE_DIR": str(work / "plain"), "SPLINT_API_TOKEN": "a-token",
        "SPLINT_LISTEN": "127.0.0.1:0", "SPLINT_OWNER_IDENTITY": owner.identity, "SPLINT_SCHEME": "http",
    })
    check("a Signet refuses plain HTTP with no opt-in", code not in (0, None) and OPT_IN in output, (code, output[-300:]))


def certificate_authority(work: Path) -> tuple[Path, Path, Path]:
    """A small CA of our own and a certificate from it for this machine's name."""
    ca_key, ca, key, request, certificate = (work / name for name in ("ca.key", "ca.crt", "db.key", "db.csr", "db.crt"))
    names = work / "names.ext"
    names.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
    new_key = ["-newkey", "rsa:2048", "-nodes"]
    for command in (
        ["openssl", "req", "-x509", "-sha256", *new_key, "-subj", "/CN=test database CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign", "-days", "1", "-keyout", ca_key, "-out", ca],
        ["openssl", "req", *new_key, "-subj", "/CN=localhost", "-keyout", key, "-out", request],
        ["openssl", "x509", "-req", "-sha256", "-in", request, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-days", "1", "-extfile", names, "-out", certificate],
    ):
        subprocess.run([str(part) for part in command], check=True, capture_output=True)
    return ca, certificate, key


def check_a_database_over_tls_is_really_verified(work: Path) -> None:
    ca, certificate, key = certificate_authority(work)
    postgres = e2e.Postgres()
    postgres.start()
    try:
        for path, name in ((certificate, "server.crt"), (key, "server.key")):
            subprocess.run(["docker", "cp", str(path), f"{postgres.name}:/var/lib/postgresql/{name}"], check=True, capture_output=True)
        enable = "chown postgres /var/lib/postgresql/server.*; chmod 600 /var/lib/postgresql/server.key"
        subprocess.run(["docker", "exec", postgres.name, "sh", "-c", enable], check=True, capture_output=True)
        for statement in (
            "ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/server.crt'",
            "ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/server.key'",
            "ALTER SYSTEM SET ssl = on",
            "SELECT pg_reload_conf()",
        ):
            postgres.sql("splint", statement)
        base = postgres.create_database("tls_rules").replace("127.0.0.1", "localhost")
        if not e2e.wait_until(lambda: postgres.sql("tls_rules", "SELECT count(*) FROM pg_stat_ssl") != ""):
            raise RuntimeError("Postgres didn't take its certificate")

        code, output = run_until_it_stops("host", host_settings(work, SPLINT_DATABASE_URL=f"{base}?sslmode=verify-full"))
        check("a host won't use a database whose certificate it can't verify", code not in (0, None) and "does not support TLS" not in output, (code, output[-300:]))
        tables = postgres.sql("tls_rules", "SELECT count(*) FROM information_schema.tables WHERE table_name = 'agents'")
        check("and sent it nothing that made a table", tables == "0", tables)

        code, output = run_until_it_stops("host", host_settings(work, SPLINT_DATABASE_URL=f"{base}?sslmode=verify-full&sslrootcert={ca}"))
        check("control: it connects when it can verify it", code is None, (code, output[-300:]))
        tables = postgres.sql("tls_rules", "SELECT count(*) FROM information_schema.tables WHERE table_name = 'agents'")
        check("control: and made its tables over TLS", tables == "1", tables)
    finally:
        postgres.stop()


def main() -> None:
    e2e.build()
    with tempfile.TemporaryDirectory(prefix="splint-tls-rules-") as directory:
        work = Path(directory)
        check_a_host_refuses(work)
        check_a_signet_sends_nothing_without_a_real_certificate(work)
        check_a_database_over_tls_is_really_verified(work)
    if e2e.failures:
        sys.exit(f"{e2e.failures} failed")
    print("tls_rules passed")


if __name__ == "__main__":
    main()

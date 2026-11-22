#!/usr/bin/env python3
"""Your controls served by themselves: `splint controls HOST --port N` serves the owner page and its relay
at http://localhost:PORT/owner, in a real headless Chrome with a WebAuthn virtual authenticator, against
a real host and `splint`. That page makes no passkey: one for `localhost` is one any program on this
computer could serve its own page for and have the person's touch sign what it likes, so every verifier
refuses it, and the page says to open the controls Splint on this computer signs for.

What goes wrong is shown too: the page asked for by another name, a script changed by one byte, a
website using the relay, a host answering the relay with a page or far too much, and another program
holding ::1 at the port.

    python3 sim/owner_controls.py

An owner ID naming a passkey for localhost, or under it, is refused by every verifier, from any page:
the shared vectors in spec/vectors/identity.json and identity-keys.json show it.

What this can't show: a real passkey store, a person reading the page, or the person's own browser
opening by itself (this runs with --no-open). No agent has network limits, and homes stand for devices
under one OS user.
"""

import json
import shutil
import signal
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import e2e
import install
from agent_signup import ROOM_FOR_A_RUN
from e2e import check, http, wait_until
from browser import Browser
from install import Walkthrough

# How long a page has to show what it should.
SEEN_SECONDS = 60


class Tamper:
    """Serves the page's files from the person's Splint with one byte of the script changed, as anything
    in the way could. It names the controls' own address to them, so only the change is the fault."""

    def __init__(self, port: int) -> None:
        here = f"localhost:{port}"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                connection = HTTPConnection("127.0.0.1", port, timeout=30)
                connection.request("GET", self.path, headers={"Host": here})
                answer = connection.getresponse()
                body = answer.read()
                if self.path == "/owner.js":
                    body = body.replace(b"Your controls", b"Your c0ntrols", 1)
                self.send_response(answer.status)
                for name, value in answer.getheaders():
                    if name.lower() not in ("content-length", "connection", "transfer-encoding"):
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()


class LocalDevice:
    """A browser with a passkey store in it, so anything that makes or uses a passkey would succeed
    and be counted, and the page open."""

    def __init__(self, work: Path, name: str, page: str) -> None:
        self.page = page
        self.browser = Browser(work / name, [])
        self.browser.call("WebAuthn.enable", enableUI=False)
        self.authenticator = self.browser.call("WebAuthn.addVirtualAuthenticator", options={
            "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True, "hasPrf": True,
        })["authenticatorId"]

    def open(self) -> None:
        self.browser.goto(self.page)

    def text(self, selector: str = "body") -> str:
        return self.browser.eval(f"(document.querySelector({json.dumps(selector)}) || {{innerText: ''}}).innerText")

    def credentials(self) -> list[dict]:
        return self.browser.call("WebAuthn.getCredentials", authenticatorId=self.authenticator)["credentials"]

    def touches(self) -> int:
        """Every passkey made or signed with: the authenticator counts each."""
        return sum(credential["signCount"] for credential in self.credentials())

    def passkey_rp(self) -> list[str]:
        return [credential.get("rpId", "") for credential in self.credentials()]

    def close(self) -> None:
        self.browser.close()


def start_host(walk: Walkthrough) -> str:
    walk.new_person("hana")
    settings = " ".join(f"{name}={value}" for name, value in ROOM_FOR_A_RUN.items())
    done = walk.run_as("hana", f"{settings} splint host start")
    check("control: a host starts", done.returncode == 0, done.stderr)
    walk.codes += install.CODE_LINE.findall(done.stdout)
    return install.HOST_LINE.search(done.stdout).group(1)


def start_controls(walk: Walkthrough, host: str, port: int) -> subprocess.Popen:
    """The person's own Splint, run as they would, from its install on their computer."""
    person = walk.new_person("nia")
    log = (walk.work / "controls.log").open("w")
    preamble = "\n".join(person.exports)
    process = subprocess.Popen(["bash", "-ec", f"{preamble}\nexec splint controls {host} --port {port} --no-open"], cwd=walk.work, env=person.env, stdout=log, stderr=subprocess.STDOUT, text=True)
    up = wait_until(lambda: process.poll() is None and http("GET", f"http://localhost:{port}/.well-known/splint/host")[0] == 200, SEEN_SECONDS)
    check("control: splint controls serves the page on this computer", up, (walk.work / "controls.log").read_text())
    return process


def it_opens_the_browser_by_itself(walk: Walkthrough, host: str) -> None:
    """Bugs caught: a person left to find and type the link, or a link handed to a shell. The system's
    opener here is a stand-in that writes down what it was given, as this run can't open a real one."""
    person = walk.person("nia")
    opener = walk.work / "opener"
    opener.mkdir(exist_ok=True)
    said = walk.work / "opened.txt"
    for name in ("open", "xdg-open"):
        (opener / name).write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{said}'\n")
        (opener / name).chmod(0o755)
    port = e2e.free_port()
    preamble = "\n".join(person.exports)
    process = subprocess.Popen(["bash", "-ec", f"{preamble}\nexport PATH='{opener}':$PATH\nexec splint controls {host} --port {port}"], cwd=walk.work, env=person.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        opened = wait_until(lambda: said.exists() and said.read_text().strip() != "", SEEN_SECONDS)
        check("splint controls opens the person's browser at their controls, the link alone", opened and said.read_text().splitlines() == [f"http://localhost:{port}/owner"], said.read_text() if said.exists() else "nothing opened")
    finally:
        process.terminate()
        process.wait(timeout=30)


def running_them_again_opens_the_ones_running(walk: Walkthrough, host: str, port: int) -> None:
    """Issue 732. The person runs splint controls again while theirs run. Bugs caught: being told to use
    another port, whose page remembers no owner and offers to set up controls again, and taking a port
    some other program answers on for their controls."""
    person = walk.person("nia")
    opener = walk.work / "opener-again"
    opener.mkdir(exist_ok=True)
    said = walk.work / "opened-again.txt"
    for name in ("open", "xdg-open"):
        (opener / name).write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{said}'\n")
        (opener / name).chmod(0o755)
    preamble = "\n".join(person.exports)

    def again(at: int) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", "-ec", f"{preamble}\nexport PATH='{opener}':$PATH\nexec splint controls {host} --port {at}"], cwd=walk.work, env=person.env, capture_output=True, text=True, timeout=SEEN_SECONDS)

    done = again(port)
    opened = wait_until(lambda: said.exists() and said.read_text().strip() != "", SEEN_SECONDS)
    check("splint controls run again opens the ones running, at the same port", done.returncode == 0 and opened and said.read_text().splitlines() == [f"http://localhost:{port}/owner"], (done.stdout + done.stderr, said.read_text() if said.exists() else "nothing opened"))
    squatter = socket.socket(socket.AF_INET)
    try:
        squatter.bind(("127.0.0.1", 0))
        squatter.listen()
        done = again(squatter.getsockname()[1])
        check("a port another program holds isn't taken for the person's controls, nor another port offered", done.returncode != 0 and "http://localhost" not in done.stdout and "--port" not in done.stderr, done.stdout + done.stderr)
    finally:
        squatter.close()


def raw_status(url: str, headers: dict[str, str] | None = None, method: str = "GET", body: bytes | None = None) -> int:
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as answer:
            return answer.status
    except urllib.error.HTTPError as error:
        return error.code
    except urllib.error.URLError:
        return 0


def it_says_what_it_is(port: int, host: str) -> None:
    status, said = http("GET", f"http://localhost:{port}/.well-known/splint/host")
    check("it names the person's home host and its relay, and no RP ID for a passkey", status == 200 and said.get("domain") == host and said.get("relay") is True and "owner_page_rp_id" not in said, said)


def another_name_is_refused(port: int) -> None:
    """Bugs caught: a page served under any name, so a website renamed to this address by DNS reaches it
    from the person's own browser, or 127.0.0.1 gets a page whose passkey would be for another RP."""
    check("the page asked for as 127.0.0.1 is refused", raw_status(f"http://127.0.0.1:{port}/owner") == 421)
    check("as is any other name for this address", raw_status(f"http://127.0.0.1:{port}/owner", {"Host": "evil.example"}) == 421)


def it_holds_both_of_localhosts_addresses(port: int) -> None:
    """Bug caught: controls on 127.0.0.1 alone, so another program on ::1, which browsers try first for
    localhost, answers at the person's controls' origin."""
    check("the page answers on ::1 too", raw_status(f"http://[::1]:{port}/owner", {"Host": f"localhost:{port}"}) == 200)


def a_program_on_ipv6_localhost_stops_it(walk: Walkthrough, host: str) -> None:
    """Bug caught: controls that start on 127.0.0.1 while another program holds ::1 at the same port,
    so the person's browser opens that program's page at their controls' origin."""
    person = walk.person("nia")
    squatter = socket.socket(socket.AF_INET6)
    try:
        squatter.bind(("::1", 0))
        squatter.listen()
        port = squatter.getsockname()[1]
        preamble = "\n".join(person.exports)
        done = subprocess.run(["bash", "-ec", f"{preamble}\nexec splint controls {host} --port {port} --no-open"], cwd=walk.work, env=person.env, capture_output=True, text=True, timeout=SEEN_SECONDS)
        check("splint controls refuses to start when another program holds ::1 at its port", done.returncode != 0 and "http://localhost" not in done.stdout, done.stdout + done.stderr)
    except subprocess.TimeoutExpired:
        check("splint controls refuses to start when another program holds ::1 at its port", False, "it kept running")
    finally:
        squatter.close()


class Upstream:
    """A host for the relay to reach, on this computer, that says what reached it and answers what a
    hostile host could: a page with a script, or far more than any answer needs."""

    def __init__(self, family: int = socket.AF_INET) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/page":
                    self.answer("text/html", b"<script>parent.taken = true</script>")
                elif self.path == "/big":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    for _ in range(9):
                        self.wfile.write(b" " * (1024 * 1024))
                else:
                    self.answer("application/json", json.dumps(sorted(name.lower() for name in self.headers.keys())).encode())

            def answer(self, kind: str, body: bytes) -> None:
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args) -> None:
                pass

        class Server(ThreadingHTTPServer):
            address_family = family

        self.server = Server(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0), Handler)
        port = self.server.server_address[1]
        self.domain = f"[::1]:{port}" if family == socket.AF_INET6 else f"127.0.0.1:{port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()


def relayed(port: int, domain: str, path: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(f"http://localhost:{port}/relay/{domain}{path}", headers={"Sec-Fetch-Site": "same-origin", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=60) as answer:
            return answer.status, {name.lower(): value for name, value in answer.getheaders()}, answer.read()
    except urllib.error.HTTPError as error:
        return error.code, {name.lower(): value for name, value in error.headers.items()}, b""


def the_relay_passes_only_what_the_page_needs(port: int) -> None:
    """Bugs caught: a relay that hands a host the person's cookies from their other localhost apps, takes
    an address spelled to mean another place, serves a host's HTML at this page's origin, holds an answer
    of any size in memory, or can't reach a host on ::1."""
    upstream = Upstream()
    try:
        status, _, body = relayed(port, upstream.domain, "/headers", {"Cookie": "session=other-app", "X-Other": "1", "Authorization": "Bearer t", "splint-owner": "x"})
        arrived = json.loads(body or b"[]")
        check("control: the relay reaches a host on this computer", status == 200, status)
        check("with what the owner API reads", "authorization" in arrived and "splint-owner" in arrived, arrived)
        check("and no cookie or other header", "cookie" not in arrived and "x-other" not in arrived, arrived)
        check("an address spelled to mean another place is refused", relayed(port, f"a@{upstream.domain}", "/headers")[0] == 400)
        status, said, _ = relayed(port, upstream.domain, "/page")
        check("a host's HTML comes back as text, never a page that runs here", status == 200 and not said.get("content-type", "").startswith("text/html") and said.get("content-disposition") == "attachment", said)
        check("an answer far past what any host needs is refused", relayed(port, upstream.domain, "/big")[0] == 502)
    finally:
        upstream.stop()
    upstream = Upstream(socket.AF_INET6)
    try:
        check("a host on ::1 is reached as one on this computer", relayed(port, upstream.domain, "/headers")[0] == 200)
    finally:
        upstream.stop()


def a_website_cant_use_the_relay(port: int, host: str) -> None:
    """Bugs caught: a relay any website the person visits can send through, to their host or to anything
    else on this computer, as browsers let a page send to localhost."""
    url = f"http://localhost:{port}/relay/{host}/.well-known/splint/host"
    check("control: the page's own call through the relay reaches the host", raw_status(url, {"Sec-Fetch-Site": "same-origin"}) == 200)
    check("a call a browser says came from another site is refused", raw_status(url, {"Sec-Fetch-Site": "cross-site"}) == 403)
    check("as is one from another port on this computer", raw_status(url, {"Sec-Fetch-Site": "same-site", "Origin": "http://localhost:1"}) == 403)
    check("or from another origin, whatever else it says", raw_status(url, {"Origin": "http://localhost.evil.example"}, "POST", b"{}") == 403)
    # Bug caught: a relay that trusts a browser to say where a call came from, as one that doesn't, or a
    # navigation, says nothing.
    check("a call that says nothing of where it came from is refused", raw_status(url) == 403)
    check("as is one to open as a page, even from this page", raw_status(url, {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "document"}) == 403)


def a_page_changed_by_one_byte_is_refused(device: LocalDevice, port: int) -> None:
    """Bugs caught: a page whose script isn't pinned by its hash, so whatever serves it can change it."""
    tamper = Tamper(port)
    try:
        device.browser.goto(f"http://localhost:{tamper.port}/owner")
        check("the browser refuses a script changed by one byte, by its hash", wait_until(lambda: device.browser.eval("1") and any("integrity" in problem for problem in device.browser.problems), SEEN_SECONDS), device.browser.problems)
        check("so the page runs nothing", device.browser.eval("document.querySelector('#cant-sign-here') === null"), device.text())
    finally:
        tamper.stop()
        device.browser.problems.clear()


def the_page_alone_makes_no_passkey(device: LocalDevice) -> None:
    """Issue 635. Bug caught: the page served by itself making a passkey for localhost, which any program
    on this computer could serve its own page for, on any port, and have the person's touch sign what it
    likes."""
    device.open()
    check("the page says it can't sign here, and where the person's controls are", device.browser.wait_for("document.querySelector('#cant-sign-here') !== null", SEEN_SECONDS) and "splint controls" in device.text("#cant-sign-here"), device.text())
    check("and offers no owner ID to make", device.browser.eval("document.querySelectorAll('main button').length") == 0, device.text())
    check("no passkey was made", device.passkey_rp() == [] and device.touches() == 0, device.passkey_rp())
    # Nenye, 2026-11-21: owners sign only through Splint on their computer, so nothing at this origin
    # may ask for a passkey at all. Bug caught: the controls' Permissions-Policy still letting a script
    # here make one, as anything that changed the page or took its port could.
    asked = device.browser.eval("""(async () => {
      try {
        await navigator.credentials.create({publicKey: {rp: {id: 'localhost', name: 'x'}, user: {id: new Uint8Array(16), name: 'x', displayName: 'x'},
          challenge: new Uint8Array(32), pubKeyCredParams: [{type: 'public-key', alg: -7}], authenticatorSelection: {userVerification: 'required'}, timeout: 5000}});
        return 'made';
      } catch (error) {
        return error.name;
      }
    })()""")
    check("and the page's own policy refuses a script there that asks for one", asked == "NotAllowedError" and device.passkey_rp() == [], (asked, device.passkey_rp()))
    # The browser reports the refusal it was asked for, which is the page doing what it should.
    device.browser.problems[:] = [problem for problem in device.browser.problems if "publickey-credentials" not in problem]


def run() -> None:
    print("\n== local controls served by themselves ==", flush=True)
    work = e2e.short_scratch("splint-owner-controls-")
    walk = Walkthrough(work, None, None)
    device = None
    controls = None
    try:
        host = start_host(walk)
        walk.host = host
        port = e2e.free_port()
        controls = start_controls(walk, host, port)
        it_says_what_it_is(port, host)
        it_holds_both_of_localhosts_addresses(port)
        it_opens_the_browser_by_itself(walk, host)
        running_them_again_opens_the_ones_running(walk, host, port)
        a_program_on_ipv6_localhost_stops_it(walk, host)
        a_website_cant_use_the_relay(port, host)
        the_relay_passes_only_what_the_page_needs(port)
        another_name_is_refused(port)
        device = LocalDevice(work, "browser", f"http://localhost:{port}/owner")
        a_page_changed_by_one_byte_is_refused(device, port)
        the_page_alone_makes_no_passkey(device)
        check("nothing on the page threw", device.browser.problems == [], device.browser.problems)
    finally:
        if device:
            device.close()
        if controls and controls.poll() is None:
            controls.terminate()
            controls.wait(timeout=30)
        walk.stop_everything()
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    # So a stop runs the cleanup below, and leaves no host, Signet, browser or controls of this run behind.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    e2e.build()
    run()
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall local controls checks passed", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""An owner's side reaching an agent's Signet straight, rather than by way of its host: on the same
computer through the Signet's own socket, and from the owner's own device at an address the agent's
operator turned on. The host stays in the path for everything the owner signs, and still ends up with
all of it: it's done only once the host takes it, and until it does the owner's side says so and sends
it again. What reaches an agent's Signet both ways counts once.

Nenye keeps her owner key beside her default agent, and dan is another agent of hers on the same
machine, a profile that joined on its own. Dana's key is on her own device, and her agent max runs on
another, whose operator turns on owner network access. Their host is stopped for much of this, so
what still works went straight. Someone on the network calls max's Signet as they like, and later
answers at the address dana named for it, saying yes to everything.

    python3 sim/direct_access.py

Not shown: two real machines or a real LAN (max's address is loopback, which reaches the same listener
as a LAN address would), hardware-held keys (where a sign-in that asks for its person is shown, dana's
key file signs, and what runs `splint-owner-key` for her says it's the chip and counts the times it's
asked to sign for a host), a browser (the controls page's relay is called as the page
calls it, with the headers a browser sends), or a person at the terminal: a script types the answers. No
agent has network limits.
"""

import base64
import binascii
import contextlib
import json
import os
import pty
import shlex
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import e2e
from agent_signup import AUTHORIZE_LINE, DEFAULTS_AND_YES, FINISH_LINE, OWN_LINE, Signup
from e2e import check, http, wait_until
from install import Person
from owner_device import CHEAP, DEAR, RELAY_SECONDS, agree, name_types, reached, room_for_this_test, taken_on

SEALER = e2e.TARGET_DIR / "debug" / "examples" / "seal_owner_call"
PROTOCOL = {"splint-protocol": "1"}
# Longer than Signet's sync pass and its wait on a host that's back.
HOST_HEARS_SECONDS = 90
HEARS_SECONDS = 20


class Profile(Person):
    """An agent of Nenye's that `splint --as NAME` reaches, in her home."""

    def __init__(self, nenye: Person, profile: str) -> None:
        super().__init__(profile, nenye.home, nenye.env, exports=nenye.exports)
        self.profile = profile

    @property
    def dot(self) -> Path:
        return self.home / ".splint" / "profiles" / self.profile


def contacts_of(agent: Person) -> list[str]:
    return [contact["address"] for contact in agent.api("GET", "/v0/contacts")[1].get("contacts", [])]


def host_rules(signup: Signup, agent_id: str) -> tuple[int, str]:
    """The seq and compact of the rules the host holds for an agent, as its operator reads them."""
    found = signup.sql("hana", f"SELECT seq || ' ' || compact FROM rules WHERE agent = '{agent_id}'")
    if not found:
        return 0, ""
    seq, compact = found.split(" ", 1)
    return int(seq), compact


def rules_seq(compact: str) -> int:
    return e2e.payload_of(compact.split("~")[0])["seq"]


def host_is_down(signup: Signup) -> None:
    done = signup.walk.run_as("hana", "splint host stop")
    check("control: the host stops", done.returncode == 0, done.stderr)
    try:
        urllib.request.urlopen(f"http://{signup.open_host}/.well-known/splint/host", timeout=3)
        up = True
    except (urllib.error.URLError, OSError):
        up = False
    check("control: and nothing answers at its address", not up)


def host_is_back(signup: Signup) -> None:
    done = signup.walk.run_as("hana", "splint host start")
    check("control: the host starts again at the same address", done.returncode == 0 and signup.open_host in done.stdout, done.stderr)


def sign_rules(owner: Person, record: dict) -> str:
    """Rules signed by the owner's own key, as their device does, from the draft it last signed."""
    done = subprocess.run(
        [str(owner.dot / "bin" / "splint-owner-key"), "rules", "--dir", str(owner.dot / "owner"), "--agent", record["agent"],
         "--schemas", str(owner.dot / "schemas")],
        input=json.dumps(record["draft"]), capture_output=True, text=True, env=owner.env, check=False,
    )
    check("control: the owner's key signs rules", done.returncode == 0, done.stderr)
    return done.stdout.strip()


def authorized(owner: Person, address: str) -> dict:
    return next(record for record in json.loads((owner.dot / "authorized.json").read_text()) if record["address"] == address)


def without(record: dict, address: str) -> dict:
    record = json.loads(json.dumps(record))
    record["draft"]["contacts"] = [contact for contact in record["draft"]["contacts"] if contact["address"] != address]
    return record


def sealed(identity: str, method: str, path: str, body: dict) -> dict:
    done = subprocess.run([str(SEALER)], input=json.dumps({"agent": identity, "method": method, "path": path, "body": body}),
                          capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def sealed_raw(identity: str, method: str, path: str, plain: bytes) -> bytes:
    """A call sealed as the owner's device seals one, of bytes that needn't be JSON."""
    done = subprocess.run([str(SEALER)], input=json.dumps({"agent": identity, "method": method, "path": path, "raw": plain.decode()}),
                          capture_output=True, text=True, check=True)
    return done.stdout.encode()


def in_fixed_words(answer: dict) -> bool:
    """A refusal in Signet's own JSON, or with nothing in it, never a framework's own words."""
    return list(answer) == ["error"] or answer == {"raw": ""}


def is_sealed_note(text: str) -> bool:
    """A sealed note in base64url: an encapsulated P-256 key, then the ciphertext and its tag. A view
    signed and not sealed is a compact JWS, which has dots and decodes to no such thing."""
    try:
        note = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, binascii.Error):
        return False
    return "." not in text and len(note) > 65 + 16 and note[0] == 4


def answers_at(at: str) -> bool:
    """Whether max's Signet answers a view at that address, as the owner's device asks."""
    try:
        return http("GET", f"http://{at}/v0/owner/view", headers=PROTOCOL, timeout=3)[0] == 200
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
        return False


def setup_people(signup: Signup) -> tuple[Person, Profile, Person, Person, Person]:
    host = signup.open_host
    walk = signup.walk
    ben = signup.device("ben")
    ben.address = f"ben~{host}"
    done = walk.run_as("ben", f"splint setup {ben.address} --with-code --owner-key-here", walk.signup_code("ben") + "\n")
    check("control: ben sets up", done.returncode == 0, done.stderr)
    ben.line = OWN_LINE.search(done.stdout).group(0)

    nenye = signup.device("nenye")
    nenye.address = f"ana~{host}"
    done = walk.run_as("nenye", f"splint setup {nenye.address} --with-code --owner-key-here", walk.signup_code("nenye") + "\n")
    check("control: nenye sets up her default agent with her key beside it", done.returncode == 0, done.stderr)
    dan = Profile(nenye, "dan")
    dan.address = f"dan~{host}"
    joined = walk.run_as("nenye", f"splint --as dan join {dan.address} --owner-first")
    check("control: dan joins as a profile and waits for her", joined.returncode == 0, joined.stderr)
    signed = walk.run_as("nenye", AUTHORIZE_LINE.search(joined.stdout).group(0), DEFAULTS_AND_YES)
    check("control: her key, beside it, signs for dan", signed.returncode == 0, signed.stderr)
    finished = walk.run_as("nenye", "splint --as dan " + FINISH_LINE.search(signed.stdout).group(0).removeprefix("splint "))
    check("control: dan finishes", finished.returncode == 0, finished.stderr)

    dana, max_ = signup.device("dana"), signup.device("max")
    max_.address = f"max~{host}"
    joined = walk.run_as("max", f"splint join {max_.address} --owner-first")
    check("control: max joins and waits for dana", joined.returncode == 0, joined.stderr)
    signed = walk.run_as("dana", AUTHORIZE_LINE.search(joined.stdout).group(0), DEFAULTS_AND_YES)
    check("control: dana's device signs for max", signed.returncode == 0, signed.stderr)
    finished = walk.run_as("max", FINISH_LINE.search(signed.stdout).group(0))
    check("control: max finishes", finished.returncode == 0, finished.stderr)
    max_.line = OWN_LINE.search(finished.stdout).group(0)
    return nenye, dan, ben, dana, max_


def owner_mail(signup: Signup, agent_id: str, only: str = "") -> int:
    """How many things the host has kept for an agent's Signet, as its operator counts them. Which kind
    of thing each is, its operator can't say: each is sealed to the agent."""
    return int(signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{agent_id}' {only}") or 0)


def waits_for_owner(agent: Person, request: str) -> object:
    return agent.api("GET", f"/v0/requests/{request}")[1].get("waiting_for_owner")


def answers_on_its_socket(agent: Person) -> bool:
    try:
        return agent.api("GET", "/v0/identity")[0] == 200
    except OSError:
        return False


def on_this_computer_rules_go_straight_and_the_host_catches_up(signup: Signup, nenye: Person, dan: Profile, ben: Person) -> None:
    walk = signup.walk
    dan_id = authorized(nenye, dan.address)["agent"]
    before, _ = host_rules(signup, dan_id)
    host_is_down(signup)
    added = walk.run_as("nenye", f"splint for {dan.address} add {ben.address} {ben.agent_id}")
    # Bug caught: a change only a straight answer took was reported done, though that answer could
    # be anyone's, and nothing sent it to the host again.
    check("with its host down, her side signs a contact for dan, and doesn't say it's done", added.returncode != 0, added.stdout + added.stderr)
    check("and dan's Signet has it at once, as it went straight", ben.address in contacts_of(dan), contacts_of(dan))
    # Bug caught (by mutation): rules kept for more than 7 days were dropped as an answer is, though a
    # host takes rules however long ago they were signed, and only newer ones end them. The file her
    # device keeps them in is dated 8 days back, as this run can't wait that long.
    kept = list((nenye.dot / "not-at-host").glob("*.rules.json"))
    check("control: her device keeps those rules for dan's host, in one file", len(kept) == 1, kept)
    long_ago = time.time() - 8 * 24 * 60 * 60
    os.utime(kept[0], (long_ago, long_ago))
    listed = walk.run_as("nenye", "splint agents").stdout
    check("splint agents says dan was reached straight on this computer", "last straight to its Signet on this computer" in listed, listed)
    check("and that its rules wait for its host, however long they've been kept", "Waiting" in listed, listed)
    waiting = walk.run_as("nenye", f"splint for {dan.address} waiting")
    check("and she reads what's waiting with its host down, straight from its Signet", waiting.returncode == 0 and "Last heard from" in waiting.stdout, waiting.stderr)

    port = e2e.free_port()
    controls = subprocess.Popen(
        ["bash", "-c", "\n".join([*nenye.exports, f"exec splint controls {signup.open_host} --no-open --port {port}"])],
        env=nenye.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        page = {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty", "Origin": f"http://localhost:{port}"}
        relay = f"http://localhost:{port}/relay/{signup.open_host}"
        check("control: her controls open", wait_until(lambda: http("GET", f"http://localhost:{port}/.well-known/splint/host", headers=page)[0] == 200, 20))
        request = urllib.request.Request(f"{relay}/v0/owner-view/{dan_id}", headers=page)
        with urllib.request.urlopen(request, timeout=10) as answer:
            route, held = answer.headers.get("splint-route"), json.loads(answer.read())
        check("her controls page reads dan's view straight from its Signet, with its host down", route == "this-computer" and isinstance(held.get("view"), str), (route, held))

        record = without(authorized(nenye, dan.address), ben.address)
        rules = sign_rules(nenye, record)
        request = urllib.request.Request(f"{relay}/v0/rules", data=json.dumps({"rules": rules}).encode(), method="PUT",
                                         headers={**page, "Content-Type": "application/json"})
        status, route = answered(request)
        # Bug caught: the relay turned a host it couldn't reach into a 200, so the page said done.
        check("rules from her page go straight to dan's Signet, with its host down, and the page isn't told they're done", status == 502 and route == "this-computer", (status, route))
        check("and dan goes by them at once", wait_until(lambda: ben.address not in contacts_of(dan), HEARS_SECONDS), contacts_of(dan))
    finally:
        controls.terminate()
        controls.wait(10)

    host_is_back(signup)
    check("its host ends up with those rules", wait_until(lambda: host_rules(signup, dan_id)[0] == rules_seq(rules), HOST_HEARS_SECONDS),
          (before, host_rules(signup, dan_id)[0], rules_seq(rules)))
    listed = walk.run_as("nenye", "splint agents").stdout
    check("and once it has, splint agents has nothing waiting for it", "Waiting" not in listed, listed)


def answered(request: urllib.request.Request) -> tuple[int, str | None]:
    """A relay call's status and the way it says it went."""
    try:
        with urllib.request.urlopen(request, timeout=20) as answer:
            return answer.status, answer.headers.get("splint-route")
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("splint-route")


class SaysYes(BaseHTTPRequestHandler):
    """Stands in for a Signet: says everything was taken, and keeps nothing."""

    def answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("splint-protocol", "1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_PUT = do_POST = answer

    def log_message(self, *_: object) -> None:
        pass


class UnixHttp(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):  # noqa: ANN201 - BaseHTTPRequestHandler wants a client address
        request, _ = super().get_request()
        return request, ("local", 0)


def a_program_standing_in_for_its_signet_cant_keep_rules_from_the_host(signup: Signup, nenye: Person, dan: Profile, ben: Person) -> None:
    """Bug caught: rules handed only to whatever answers on the socket, which a fooled agent running as
    the same user could put there, would never reach the host, so the owner's change would never count."""
    walk = signup.walk
    dan_id = authorized(nenye, dan.address)["agent"]
    # Her page's rules, signed here as it signs them, went without ben. Her terminal's record of what it
    # last signed still has him, but a change starts from the rules in force, so it finds
    # him out already, and adds him back from there.
    removed = walk.run_as("nenye", f"splint for {dan.address} remove {ben.address}")
    check("control: her terminal finds ben out, as her page took him out", ben.address not in contacts_of(dan) and (removed.returncode == 0 or "isn't one of your agent's contacts" in removed.stderr), removed.stdout + removed.stderr)
    check("control: dan's Signet stops", walk.run_as("nenye", "splint --as dan stop").returncode == 0)
    before, _ = host_rules(signup, dan_id)
    # What a stopped Signet leaves, which a program in its place takes over.
    dan.socket.unlink(missing_ok=True)
    stand_in = UnixHttp(str(dan.socket), SaysYes)
    threading.Thread(target=stand_in.serve_forever, daemon=True).start()
    try:
        added = walk.run_as("nenye", f"splint for {dan.address} add {ben.address} {ben.agent_id}")
        check("control: her side is told the stand-in took them", added.returncode == 0, added.stderr)
        after, compact = host_rules(signup, dan_id)
        check("the host has her new rules anyway", after > before and any(contact["address"] == ben.address for contact in e2e.payload_of(compact.split("~")[0])["contacts"]), (before, after))
        # Bug caught: where she gets paid handed only to the stand-in, so payers would go on being
        # asked to pay at the place she moved away from.
        left = owner_mail(signup, dan_id)
        paid = walk.run_as("nenye", f"splint for {dan.address} get-paid https://pay.example.com/nenye")
        check("control: her side is told the stand-in took where she gets paid", paid.returncode == 0, paid.stderr)
        check("and the host has it for dan anyway", owner_mail(signup, dan_id) == left + 1, (left, owner_mail(signup, dan_id)))
        port = e2e.free_port()
        controls = subprocess.Popen(
            ["bash", "-c", "\n".join([*nenye.exports, f"exec splint controls {signup.open_host} --no-open --port {port}"])],
            env=nenye.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            page = {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty", "Origin": f"http://localhost:{port}", "Content-Type": "application/json"}
            check("control: her controls open", wait_until(lambda: http("GET", f"http://localhost:{port}/.well-known/splint/host", headers=page)[0] == 200, 20))
            # Bug caught: the relay sending a host what a page handed it for an agent's Signet as it
            # was signed, which the host could then read. What an owner signs for their agent leaves
            # for a host only sealed to the agent, by Splint on their computer or their terminal.
            left = owner_mail(signup, dan_id)
            words = walk.run_as("nenye", f"splint-owner-key person-text --dir ~/.splint/owner --agent {dan_id} --to {ben.agent_id}", "Fridays only.")
            check("control: her key signs her words, as a page would have it sign them", words.returncode == 0, words.stderr)
            mail = json.dumps({"kind": "person_text", "signed": words.stdout.strip()}).encode()
            request = urllib.request.Request(f"http://localhost:{port}/relay/{signup.open_host}/v0/owner-mail/{dan_id}", data=mail, method="POST", headers=page)
            status, route = answered(request)
            check("the relay carries nothing a page hands it for an agent's Signet as it was signed", status == 400 and route is None, (status, route))
            sealed_by_her = json.loads(walk.run_as("nenye", f"splint-owner-key person-text --dir ~/.splint/owner --agent {dan_id} --to {ben.agent_id} --host {signup.open_host} --agent-identity '{authorized(nenye, dan.address)['identity']}'", "Fridays only.").stdout)
            request = urllib.request.Request(f"http://localhost:{port}/relay/{signup.open_host}/v0/owner-mail/{dan_id}", data=sealed_by_her["body"].encode(), method="POST",
                                             headers={**page, "Authorization": f"Splint {sealed_by_her['proof']}"})
            check("nor anything else for one, as nothing it's handed is its to seal", answered(request)[0] == 400)
            check("so nothing reaches dan's host through it", owner_mail(signup, dan_id) == left, (left, owner_mail(signup, dan_id)))
            # Bug caught (by mutation): the page's rules went only to whatever answered on the socket.
            before, _ = host_rules(signup, dan_id)
            rules = sign_rules(nenye, without(authorized(nenye, dan.address), ben.address))
            request = urllib.request.Request(f"http://localhost:{port}/relay/{signup.open_host}/v0/rules", data=json.dumps({"rules": rules}).encode(), method="PUT", headers=page)
            status, route = answered(request)
            check("control: rules from her page are taken, the stand-in answering first", status == 200 and route == "this-computer", (status, route))
            check("and the host has those rules anyway", host_rules(signup, dan_id)[0] == rules_seq(rules) > before, (before, host_rules(signup, dan_id)[0]))
        finally:
            controls.terminate()
            controls.wait(10)
    finally:
        stand_in.shutdown()
        stand_in.server_close()
        dan.socket.unlink(missing_ok=True)
    check("control: dan's Signet starts again", walk.run_as("nenye", "splint --as dan start").returncode == 0)


def over_the_network_only_what_the_owner_signed_gets_in(signup: Signup, dana: Person, max_: Person, ben: Person) -> bytes:
    """Gives back a view max's Signet gave anyone who asked, as someone on the network could keep one."""
    walk = signup.walk
    port = e2e.free_port()
    at = f"127.0.0.1:{port}"
    record = authorized(dana, max_.address)
    max_id = record["agent"]
    refused = walk.run_as("max", f"splint network-access on 0.0.0.0:{port}")
    check("max's operator naming every network is refused, and told why", refused.returncode != 0 and "every network" in refused.stderr, refused.stderr)
    # Bug caught: the IPv4-mapped form of every address got past, as Rust's is_unspecified says no.
    refused = walk.run_as("max", f"splint network-access on [::ffff:0.0.0.0]:{port}")
    check("and so is every network spelled as IPv4 in IPv6", refused.returncode != 0, refused.stdout + refused.stderr)
    check("so it's still off", json.loads(walk.run_as("max", "splint status --json").stdout).get("owner_network") is None)
    on = walk.run_as("max", f"splint network-access on {at}")
    check("max's operator turns owner network access on at an address of this machine", on.returncode == 0 and at in on.stdout, on.stderr)
    standing = json.loads(walk.run_as("max", "splint status --json").stdout)
    check("status --json says it's on, and where", standing.get("owner_network") == at, standing)

    every = walk.run_as("dana", f"splint for {max_.address} direct [::ffff:0.0.0.0]:{port}")
    check("dana's device won't name every address for max either", every.returncode != 0, every.stdout + every.stderr)
    named = walk.run_as("dana", f"splint for {max_.address} direct {at}")
    check("dana names that address for max, and it answers", named.returncode == 0 and "it answers there" in named.stdout, named.stdout + named.stderr)
    _, old_compact = host_rules(signup, max_id)
    identity = max_.api("GET", "/v0/identity")[1]["identity"]
    ben_identity = ben.api("GET", "/v0/identity")[1]["identity"]

    # A change starts from the rules in force, and for an agent reached over the network only its host
    # hands them out, as its Signet hands out nothing unsealed, so ben goes in with the host up.
    added = walk.run_as("dana", f"splint for {max_.address} add {ben.address} {ben.agent_id}")
    check("control: with max's host up, her device signs a contact for max", added.returncode == 0, added.stdout + added.stderr)
    check("control: and max's Signet has it", wait_until(lambda: ben.address in contacts_of(max_), HOST_HEARS_SECONDS), contacts_of(max_))

    mail_before = owner_mail(signup, max_id)
    host_is_down(signup)
    # Bug caught: a change signed from this device's own copy with nothing in force read,
    # which could undo a newer one another of her devices signed.
    removed = walk.run_as("dana", f"splint for {max_.address} remove {ben.address}")
    check("with its host down and its Signet only on the network, her device signs no change, and says why", removed.returncode != 0 and "rules in force" in removed.stderr, removed.stdout + removed.stderr)
    check("so max's Signet still has ben", ben.address in contacts_of(max_), contacts_of(max_))
    # Bug caught: reading what's waiting refused with the host down, though it signs nothing, as its
    # names were looked up in the rules in force.
    waiting = walk.run_as("dana", f"splint for {max_.address} waiting")
    check("but she reads what's waiting with its host down", waiting.returncode == 0 and "Last heard from" in waiting.stdout, waiting.stderr)
    listed = walk.run_as("dana", "splint agents").stdout
    check("splint agents says max was reached at that address", f"last straight to its Signet at {at}" in listed, listed)
    # Bug caught (by mutation): only PUTs were unsealed, so what the owner's device posts, sealed, never
    # got in over the network.
    said = walk.run_as("dana", f"splint for {max_.address} say {ben.address} 'call me back'")
    words = max_.api("GET", "/v0/owner/person-text", token=max_.setup_file()["owner_token"])[1].get("waiting", [])
    check("her words reach max's Signet over the network, with its host down", len(words) == 1, (said.stderr, words))
    # Bug caught: an answer at the address she named, which could be anyone's, was the last word on
    # her words, so they were said to be done with nothing kept for the host.
    check("though they aren't said to be done until its host has them", said.returncode != 0 and "not confirmed yet" in said.stderr, said.stdout + said.stderr)
    paid = walk.run_as("dana", f"splint for {max_.address} get-paid https://pay.example.com/dana")
    places = max_.api("GET", "/v0/where-paid")[1]
    check("and where she gets paid does, though it isn't done until its host has it", paid.returncode != 0 and "pay.example.com/dana" in json.dumps(places), (paid.returncode, places))

    url = f"http://{at}"
    status, held = http("GET", f"{url}/v0/owner/view", headers=PROTOCOL)
    check("anyone on the network can ask for max's view", status == 200 and list(held) == ["view"], (status, list(held)))
    check("and gets only a note sealed to dana, not the view signed in the clear", is_sealed_note(held["view"]), held["view"][:80])
    setup = max_.setup_file()
    for method, path in (("GET", "/v0/identity"), ("GET", "/v0/inbox"), ("GET", "/v0/contacts"), ("GET", "/v0/owner/quarantine"),
                         ("GET", "/v0/owner/approvals"), ("GET", "/v0/owner/requests"), ("GET", "/v0/owner/changes"),
                         ("GET", "/v0/owner/person-text"), ("GET", "/v0/owner/delegation"), ("GET", "/v0/owner/refused"),
                         ("POST", "/v0/send"), ("POST", "/v0/owner/delegate-key"), ("GET", "/v0/release")):
        for token in (setup["api_token"], setup["owner_token"]):
            status, answer = http(method, f"{url}{path}", {} if method == "POST" else None, token=token, headers=PROTOCOL)
            check(f"nothing else is there, even with a token: {method} {path}", status in (404, 405) and in_fixed_words(answer), (status, answer))
            # Under the 4 a second its limit refills by, past a burst of 20, so each call is answered.
            time.sleep(0.3)

    # Bug caught: anyone could make Signet ask its host about the owner's keys 4 times a second, by
    # sealing it something no key of the owner's signed.
    junk = sealed(identity, "POST", "/v0/owner/person-text", {"person_text": "signed by nobody"})
    first = http("POST", f"{url}/v0/owner/person-text", junk, headers=PROTOCOL)
    time.sleep(0.3)
    second = http("POST", f"{url}/v0/owner/person-text", junk, headers=PROTOCOL)
    check("something no key of the owner's signed is refused, and asked about only once a minute", first[0] not in (200, 429) and second[0] == 429, (first, second))
    time.sleep(0.3)
    status, answer = http("POST", f"{url}/v0/owner/person-text", {"person_text": "in the clear"}, headers=PROTOCOL)
    check("a post sent unsealed is refused too", status == 400 and list(answer) == ["error"], (status, answer))
    time.sleep(0.3)
    # Bug caught (by mutation): the framework's own plain-text refusal went back as it was.
    status, answer = http("PUT", f"{url}/v0/owner/rules", raw=sealed_raw(identity, "PUT", "/v0/owner/rules", b"not json"), headers=PROTOCOL)
    check("a sealed body that opens but isn't JSON is refused in fixed words", 400 <= status < 500 and list(answer) == ["error"], (status, answer))
    time.sleep(0.3)

    status, answer = http("PUT", f"{url}/v0/owner/rules", {"rules": old_compact}, headers=PROTOCOL)
    check("rules sent unsealed are refused, so nobody on the way reads the owner's", status == 400 and list(answer) == ["error"], (status, answer))
    status, answer = http("PUT", f"{url}/v0/owner/rules", sealed(identity, "PUT", "/v0/owner/rules", {"rules": old_compact}), headers=PROTOCOL)
    check("older rules replayed, sealed as the owner's device seals them, are refused", status == 403 and list(answer) == ["error"], (status, answer))
    check("and changed nothing", ben.address in contacts_of(max_), contacts_of(max_))
    status, answer = http("PUT", f"{url}/v0/owner/rules", sealed(identity, "PUT", "/v0/owner/delegation", {"rules": old_compact}), headers=PROTOCOL)
    check("a body sealed for another call is refused", status == 400, (status, answer))
    # Bug caught (by mutation): Signet opened every body as if for PUT /v0/owner/rules.
    for method, path in (("PUT", "/v0/owner/delegation"), ("POST", "/v0/owner/approvals")):
        time.sleep(0.3)
        status, answer = http(method, f"{url}{path}", sealed(identity, "PUT", "/v0/owner/rules", {"rules": old_compact}), headers=PROTOCOL)
        check(f"and one sealed for rules, sent as {method} {path}", status == 400, (status, answer))
    status, answer = http("PUT", f"{url}/v0/owner/rules", sealed(ben_identity, "PUT", "/v0/owner/rules", {"rules": old_compact}), headers=PROTOCOL)
    check("and one sealed to another agent", status == 400, (status, answer))
    status, answer = http("PUT", f"{url}/v0/owner/rules", raw=json.dumps({"sealed": "A" * (400 * 1024)}).encode(), headers=PROTOCOL)
    check("a body bigger than any call is refused", status == 413, status)

    rules = sign_rules(dana, without(record, ben.address))
    status, answer = http("PUT", f"{url}/v0/owner/rules", sealed(identity, "PUT", "/v0/owner/rules", {"rules": rules}), headers=PROTOCOL)
    check("rules the owner signed, sealed, are taken, and the answer says nothing but that", status == 200 and answer == {}, (status, answer))
    check("and max goes by them", wait_until(lambda: ben.address not in contacts_of(max_), HEARS_SECONDS), contacts_of(max_))

    # Bug caught (by mutation): no cap on connections, or none on how long one lasts.
    held_open = [socket.create_connection(("127.0.0.1", port)) for _ in range(16)]
    try:
        check("past 16 connections held open, another gets nothing", not answers_at(at), at)
        check("and each is let go 30 seconds after it opened, so the route comes back", wait_until(lambda: answers_at(at), 45), at)
    finally:
        for connection in held_open:
            connection.close()

    statuses = [http("GET", f"{url}/v0/nothing", headers=PROTOCOL)[0] for _ in range(60)]
    check("a flood of calls is slowed", 429 in statuses, sorted(set(statuses)))


    host_is_back(signup)
    check("its host ends up with dana's newest rules, from max's Signet", wait_until(lambda: host_rules(signup, max_id)[0] == rules_seq(rules), HOST_HEARS_SECONDS),
          (host_rules(signup, max_id)[0], rules_seq(rules)))

    off = walk.run_as("max", "splint network-access off")
    check("max's operator turns it off", off.returncode == 0, off.stderr)
    check("and status --json says so", json.loads(walk.run_as("max", "splint status --json").stdout).get("owner_network") is None)
    with socket.socket() as probe:
        probe.settimeout(3)
        check("nothing listens there now", probe.connect_ex(("127.0.0.1", port)) != 0)
    # Her record still has ben, as the rules without him were signed here as her page signs them, but a
    # change starts from the rules in force, so her terminal finds him out already.
    removed = walk.run_as("dana", f"splint for {max_.address} remove {ben.address}")
    check("control: her terminal finds ben out, as those took him out", ben.address not in contacts_of(max_) and (removed.returncode == 0 or "isn't one of your agent's contacts" in removed.stderr), removed.stdout + removed.stderr)
    paid = walk.run_as("dana", "splint agents")
    left = owner_mail(signup, max_id) - mail_before
    check("where she gets paid and her words, kept for max's host, reached it once it was back, each once", left == 2 and "Waiting" not in paid.stdout, (left, paid.stdout))
    check("which max's Signet collects, sealed to it as they were kept", wait_until(lambda: owner_mail(signup, max_id, "AND NOT taken") == 0, HOST_HEARS_SECONDS), owner_mail(signup, max_id, "AND NOT taken"))
    added = walk.run_as("dana", f"splint for {max_.address} add {ben.address} {ben.agent_id}")
    check("dana's device goes by way of the host again", added.returncode == 0 and wait_until(lambda: ben.address in contacts_of(max_), HOST_HEARS_SECONDS), added.stderr)
    listed = walk.run_as("dana", "splint agents").stdout
    check("and splint agents says so", "last by way of its host" in listed, listed)
    return json.dumps(held).encode()


def what_she_signs_goes_both_ways_and_counts_once(signup: Signup, dana: Person, max_: Person, ben: Person) -> None:
    """Everything dana signs for max goes to his Signet straight and to his host as well, so his Signet
    gets each thing twice. Bugs caught: her no to a price, heard again from the host after max had asked
    her the same price again, took that away too, with nothing said. And heard again after max had
    asked her a lower one, it was left for her as an answer of hers that couldn't be used. Max's Signet
    stops and starts again in between, so what it took straight is only what it kept on disk."""
    walk = signup.walk
    max_id = authorized(dana, max_.address)["agent"]
    at = f"127.0.0.1:{e2e.free_port()}"
    check("control: max's operator turns owner network access on again", walk.run_as("max", f"splint network-access on {at}").returncode == 0)
    named = walk.run_as("dana", f"splint for {max_.address} direct {at}")
    check("control: dana names that address for max, and it answers", named.returncode == 0 and "it answers there" in named.stdout, named.stdout + named.stderr)
    check("control: ben adds max", walk.run_as("ben", max_.line).returncode == 0)
    room_for_this_test(signup, dana, "authorized.json")
    room_for_this_test(signup, ben, "rules.json")
    name_types(signup, dana, "authorized.json", ben.address)
    name_types(signup, ben, "rules.json", max_.address)
    check("control: max's Signet hears", wait_until(lambda: any(contact["address"] == ben.address and contact["types"] for contact in max_.api("GET", "/v0/contacts")[1]["contacts"]), HOST_HEARS_SECONDS))
    agree(max_, ben, "quote")

    def priced(request: str, result: dict) -> None:
        status, held = max_.api("POST", f"/v0/requests/{request}/deliver", {"result": result})
        check("control: max's price waits for dana", status == 200 and held.get("waiting_for_owner") is True, held)

    same, lower = taken_on(ben, max_), taken_on(ben, max_)
    for request in (same, lower):
        priced(request, DEAR)
    waiting = lambda: walk.run_as("dana", f"splint for {max_.address} waiting").stdout  # noqa: E731
    check("control: both reach her terminal", wait_until(lambda: same[:12] in waiting() and lower[:12] in waiting(), RELAY_SECONDS), waiting())

    mail_before = owner_mail(signup, max_id)
    host_is_down(signup)
    for request in (same, lower):
        no = walk.run_as("dana", f"splint for {max_.address} deny {request[:12]}", "yes\n")
        check("with its host down, her no isn't said to be done", no.returncode != 0 and "not confirmed yet" in no.stderr, no.stdout + no.stderr)
        check("though max's Signet has it at once, as it went straight", wait_until(lambda: waits_for_owner(max_, request) is None, HEARS_SECONDS), waits_for_owner(max_, request))
    nos = [json.loads(kept.read_text())["signed"] for kept in (dana.dot / "not-at-host").glob("*.approval.*.json")]
    # Bug caught: words kept for a host that stayed away went to it on every run for good, though a
    # host takes nothing she signed more than 7 days ago. This run can't wait that long, so the file
    # her device keeps them in is dated 8 days back, which is all it goes by.
    said = walk.run_as("dana", f"splint for {max_.address} say {ben.address} 'too late by then'")
    kept = list((dana.dot / "not-at-host").glob("*.person-text.*.json"))
    check("control: her words go straight too, and are kept for max's host in a file of their own", said.returncode != 0 and "not confirmed yet" in said.stderr and len(kept) == 1, (said.stderr, kept))
    long_ago = time.time() - 8 * 24 * 60 * 60
    os.utime(kept[0], (long_ago, long_ago))
    listed = walk.run_as("dana", "splint agents").stdout
    check("splint agents says what she answered waits for max's host, and not words older than a host takes", listed.count("Waiting") == 1 and "what you answered" in listed, listed)
    # Max asks her again: the same price on one, and a lower one on the other.
    priced(same, DEAR)
    priced(lower, CHEAP)

    host_is_back(signup)
    # Bug caught (by mutation): what max's Signet took straight was remembered only while it ran, so
    # one that had restarted by the time its host's copy came took her no a second time.
    check("control: max's Signet stops and starts again", walk.run_as("max", "splint stop").returncode == 0 and walk.run_as("max", "splint start").returncode == 0)
    check("control: and still holds what max asked her again", wait_until(lambda: answers_on_its_socket(max_) and waits_for_owner(max_, same) == waits_for_owner(max_, lower) == "deliver", HEARS_SECONDS))
    walk.run_as("dana", "splint agents")
    # Bug caught: her words, which her device stopped keeping, going to his host with her two answers.
    check("the next splint run here gives max's host both her answers, each kept by itself, and not the words her device stopped keeping", owner_mail(signup, max_id) == mail_before + 2, (mail_before, owner_mail(signup, max_id)))
    check("which max's Signet collects", wait_until(lambda: owner_mail(signup, max_id, "AND NOT taken") == 0, HOST_HEARS_SECONDS), owner_mail(signup, max_id, "AND NOT taken"))
    check("her no, heard a second time, doesn't take away the same price max asked her again", waits_for_owner(max_, same) == "deliver", max_.api("GET", f"/v0/requests/{same}")[1])
    seen = max_.api("GET", f"/v0/requests/{lower}")[1]
    check("nor is it left as an answer that couldn't be used, where max asked her a lower one", seen.get("waiting_for_owner") == "deliver" and seen.get("owner_answer_not_used") is None and "wasn't used" not in waiting(), (seen, waiting()))
    check("and nothing waits for max's host any more", "Waiting" not in walk.run_as("dana", "splint agents").stdout)
    # Bug caught (by mutation): only the copy collected from the host was dropped. The same no, as her
    # device kept it for the host, sent again by anyone who held it and sealed to max as her device
    # seals one, took away the same price.
    identity = max_.api("GET", "/v0/identity")[1]["identity"]
    again = [http("POST", f"http://{at}/v0/owner/approvals", sealed(identity, "POST", "/v0/owner/approvals", {"approval": no}), headers=PROTOCOL)[0] for no in nos]
    check("each no, sent to max's Signet again as anyone holding it could, finds nothing waiting", len(nos) == 2 and again == [404, 404], again)
    seen = max_.api("GET", f"/v0/requests/{lower}")[1]
    check("and takes nothing away, and is left as no answer of hers", waits_for_owner(max_, same) == "deliver" and seen.get("waiting_for_owner") == "deliver" and seen.get("owner_answer_not_used") is None, (waits_for_owner(max_, same), seen))

    yes = walk.run_as("dana", f"splint for {max_.address} approve {same[:12]}", "yes\n")
    check("with its host up, her yes is done", yes.returncode == 0, yes.stdout + yes.stderr)
    check("and max's price goes to ben", reached(ben, same, "delivered", RELAY_SECONDS), ben.api("GET", f"/v0/requests/{same}")[1])
    check("the host has her yes too, as well as his Signet straight", wait_until(lambda: owner_mail(signup, max_id, "AND taken") == mail_before + 3, HOST_HEARS_SECONDS), (mail_before, owner_mail(signup, max_id, "AND taken")))
    for request in (same, lower):
        ben.api("POST", f"/v0/requests/{request}/decline", {"reason": "cannot_supply"})
    check("control: max's operator turns it off", walk.run_as("max", "splint network-access off").returncode == 0)


def a_host_that_doesnt_take_what_its_signet_took(signup: Signup, dana: Person, max_: Person, ben: Person) -> None:
    """Max's Signet takes what dana signs straight, and something in place of his host answers her
    device that it won't. Bugs caught: she was told his host answered and "so nothing changed", though
    max's Signet had her words. And where his host was only at its limit for now, 429 as when 64
    things wait there uncollected, nothing was kept, so his host never had them."""
    walk = signup.walk
    max_id = authorized(dana, max_.address)["agent"]
    at = f"127.0.0.1:{e2e.free_port()}"
    check("control: max's operator turns owner network access on again", walk.run_as("max", f"splint network-access on {at}").returncode == 0)
    named = walk.run_as("dana", f"splint for {max_.address} direct {at}")
    check("control: dana names that address for max, and it answers", named.returncode == 0 and "it answers there" in named.stdout, named.stdout + named.stderr)
    owner_token = max_.setup_file()["owner_token"]
    held_words = lambda: [words["text"] for words in max_.api("GET", "/v0/owner/person-text", token=owner_token)[1].get("waiting", [])]  # noqa: E731
    waiting = lambda: walk.run_as("dana", "splint agents").stdout.count("Waiting")  # noqa: E731
    before = owner_mail(signup, max_id)
    for_max = ("POST", f"/v0/owner-mail/{max_id}")
    host_is_down(signup)

    # 422 is what a host from before owner mail was sealed answers to a body that's only something sealed.
    heard: list[bytes] = []
    refusing = in_place_of_the_host(signup, answering(422, for_max, heard))
    try:
        said = walk.run_as("dana", f"splint for {max_.address} say {ben.address} 'never mind'")
        check("control: max's Signet has her words, as they went straight", "never mind" in held_words(), held_words())
        check("with his host refusing them, she's told they went straight and his host refused them, not that nothing changed",
              said.returncode != 0 and "said it took" in said.stderr and "nothing changed" not in said.stderr, said.stdout + said.stderr)
        check("and nothing is kept for a host that would refuse them again", waiting() == 0)
        # Bug caught: a host that won't take what an owner signed sealed being sent it as it was signed,
        # which is how a host, or anyone answering for one, would get to read it.
        sent = [json.loads(body) for body in heard]
        check("what refused them was sent them once, sealed, and nothing after", [list(one) for one in sent] == [["sealed"]], [list(one) for one in sent])
        inside = b"".join(e2e.decode(str(one.get("sealed", ""))) for one in sent)
        check("and can't read her words in what it was sent", b"never mind" not in b"".join(heard) + inside and len(inside) > 1024, len(inside))
    finally:
        out_of_the_way(refusing)

    at_its_limit = in_place_of_the_host(signup, answering(429, for_max))
    try:
        said = walk.run_as("dana", f"splint for {max_.address} say {ben.address} 'busy week'")
        check("control: max's Signet has these too", "busy week" in held_words(), held_words())
        check("with his host at its limit for now, her words aren't said to be done, nor that nothing changed",
              said.returncode != 0 and "not confirmed yet" in said.stderr and "nothing changed" not in said.stderr, said.stdout + said.stderr)
        check("and they're kept for his host, which the next splint run finds still at its limit", waiting() == 1)
    finally:
        out_of_the_way(at_its_limit)

    host_is_back(signup)
    walk.run_as("dana", "splint agents")
    check("once his host is back, the next splint run gives it the words she was told weren't confirmed, and not those it refused",
          owner_mail(signup, max_id) == before + 1, (before, owner_mail(signup, max_id)))
    check("and nothing waits for it any more", waiting() == 0)
    check("control: max's operator turns it off", walk.run_as("max", "splint network-access off").returncode == 0)


# What `splint-owner-key show` calls a sign-in the chip holds, which asks for its person each time it signs.
CHIP = "this computer's security chip"
# Longer than a splint command waits on hosts for what's kept for them, as a person finding the prompt takes.
A_PERSONS_SECONDS = 7
# In place of splint-owner-key on dana's device: the real one, run as it was asked, which says its
# sign-in is the chip's while `as_chip` is there, writes a line for each proof for a host it's asked
# to sign, and waits first for as long as `takes` says, as a prompt waits for a touch.
IN_FRONT_OF_OWNER_KEY = """#!/bin/sh
case "$1" in
show)
    if [ -e {as_chip} ]; then {real} "$@" | sed "s/^sign-in: .*/sign-in: {chip}/"; else exec {real} "$@"; fi ;;
access)
    echo asked >> {asked}
    if [ -e {takes} ]; then sleep "$(cat {takes})"; fi
    exec {real} "$@" ;;
*) exec {real} "$@" ;;
esac
"""


def at_a_terminal(person: Person, command: str, cwd: Path) -> subprocess.CompletedProcess:
    """Runs it with a terminal as its standard input, as a person who typed it has."""
    ours, theirs = pty.openpty()
    try:
        return subprocess.run(["bash", "-ec", "\n".join(person.exports) + "\n" + command], cwd=cwd, env=person.env, stdin=theirs, capture_output=True, text=True, timeout=120, check=False)
    finally:
        os.close(ours)
        os.close(theirs)


def a_sign_in_that_asks_for_her_asks_once_and_only_for_a_host_thats_there(signup: Signup, dana: Person, max_: Person, ben: Person) -> None:
    """Dana's sign-in asks for her each time it signs, as a Mac's chip does, and two things she signed
    are kept for max's host. Bugs caught: every splint command she ran at a terminal while his host
    was away asked her to sign for leaving one there, which then couldn't be left. With his host back,
    one command asked her once for each thing kept. And where she took longer over the prompt than a
    command waits on hosts, what she'd just signed for was never sent, so the next command asked again."""
    walk = signup.walk
    max_id = authorized(dana, max_.address)["agent"]
    at = f"127.0.0.1:{e2e.free_port()}"
    check("control: max's operator turns owner network access on again", walk.run_as("max", f"splint network-access on {at}").returncode == 0)
    named = walk.run_as("dana", f"splint for {max_.address} direct {at}")
    check("control: dana names that address for max, and it answers", named.returncode == 0 and "it answers there" in named.stdout, named.stdout + named.stderr)
    before = owner_mail(signup, max_id)
    host_is_down(signup)
    for words in ("on tuesday", "or wednesday"):
        said = walk.run_as("dana", f"splint for {max_.address} say {ben.address} '{words}'")
        check(f"control: '{words}' goes straight, and is kept for max's host", said.returncode != 0 and "not confirmed yet" in said.stderr, said.stdout + said.stderr)
    kept = lambda: len(list((dana.dot / "not-at-host").glob("*.person-text.*.json")))  # noqa: E731
    check("control: each in a file of its own", kept() == 2, kept())

    owner_key = dana.dot / "bin" / "splint-owner-key"
    real = walk.work / "dana-real-owner-key"
    as_chip, asked, takes = (walk.work / name for name in ("dana-as-chip", "dana-asked", "dana-takes"))
    asks = lambda: len(asked.read_text().splitlines()) if asked.exists() else 0  # noqa: E731
    shutil.move(owner_key, real)
    try:
        owner_key.write_text(IN_FRONT_OF_OWNER_KEY.format(real=shlex.quote(str(real)), chip=CHIP, as_chip=shlex.quote(str(as_chip)), asked=shlex.quote(str(asked)), takes=shlex.quote(str(takes))))
        owner_key.chmod(0o755)
        shown = dana.shell("splint-owner-key show --dir ~/.splint/owner", walk.work).stdout
        check("control: with nothing asked of it, what's in front of her owner key changes nothing it says", "sign-in: a plain key file" in shown and asks() == 0, shown)
        as_chip.write_text("")
        shown = dana.shell("splint-owner-key show --dir ~/.splint/owner", walk.work).stdout
        check("control: and then says her sign-in is the chip's", f"sign-in: {CHIP}" in shown, shown)

        def asked_by(run) -> int:
            """How many times a run asked her owner key to sign for a host."""
            already = asks()
            run()
            return asks() - already

        nobody_there = asked_by(lambda: walk.run_as("dana", "splint agents"))
        check("a splint run with nobody at a terminal doesn't ask her", nobody_there == 0 and kept() == 2, (nobody_there, kept()))
        host_away = asked_by(lambda: at_a_terminal(dana, "splint agents", walk.work))
        check("with max's host away, a command she runs at a terminal doesn't ask her to sign for leaving anything there", host_away == 0, host_away)
        check("control: and both are still kept", kept() == 2, kept())

        host_is_back(signup)
        takes.write_text(str(A_PERSONS_SECONDS))
        first = asked_by(lambda: at_a_terminal(dana, "splint agents", walk.work))
        check("with it back, the next command she runs at a terminal asks her once, though two things are kept", first == 1, first)
        check("and max's host has the one she signed for, though she took longer over it than a command waits on a host", owner_mail(signup, max_id) == before + 1 and kept() == 1, (before, owner_mail(signup, max_id), kept()))
        takes.unlink()
        second = asked_by(lambda: at_a_terminal(dana, "splint agents", walk.work))
        check("the command after asks her once more, for the other", second == 1, second)
        check("which max's host has too", owner_mail(signup, max_id) == before + 2 and kept() == 0, (before, owner_mail(signup, max_id), kept()))
        nothing_kept = asked_by(lambda: at_a_terminal(dana, "splint agents", walk.work))
        check("and with nothing kept, she isn't asked again", nothing_kept == 0, nothing_kept)
    finally:
        shutil.move(real, owner_key)
    check("control: max's Signet collects both", wait_until(lambda: owner_mail(signup, max_id, "AND NOT taken") == 0, HOST_HEARS_SECONDS), owner_mail(signup, max_id, "AND NOT taken"))
    check("control: max's operator turns it off", walk.run_as("max", "splint network-access off").returncode == 0)


@contextlib.contextmanager
def with_her_splint_auto_stopped(walk) -> Iterator[None]:
    """For counting what one splint run sends. Splint auto on dana's device sends what's kept for a host
    again every 15 seconds, as it should, so a pass of it landing beside that run is a send of its own,
    and one sealed then is sealed apart from the run's, so her host keeps both."""
    check("control: dana's splint auto stops", walk.run_as("dana", "splint stop").returncode == 0)
    try:
        yield
    finally:
        check("control: dana's splint auto starts again", walk.run_as("dana", "splint start").returncode == 0)


def naming_another(record: dict, handle: str, mail: tuple[str, str], heard: list[bytes], says: list[int]) -> type[BaseHTTPRequestHandler]:
    """Answers for `handle` with `record`, as a host that chose who's there, keeps each thing left at
    `mail` in `heard` and answers it with the last of `says`, and answers 502 to anything else."""

    class Names(BaseHTTPRequestHandler):
        def answer(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            status, out = 502, b""
            if (self.command, self.path) == ("GET", f"/.well-known/splint/agents/{handle}"):
                status, out = 200, json.dumps(record).encode()
            elif (self.command, self.path) == mail:
                heard.append(body)
                status = says[-1]
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("splint-protocol", "1")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_GET = do_PUT = do_POST = answer

        def log_message(self, *_: object) -> None:
            pass

    return Names


def another_agent_at(person: Person, address: str, work: Path) -> dict:
    """What a host answers for who's at `address`, for an agent that isn't the one there: keys of its
    own, which whoever made them opens what's sealed to, bound to that address by an owner key of its
    own, which anyone can make, so it checks out as any host's answer does."""
    key, owner = work / "not-the-agent.key", work / "not-its-owner"
    e2e.new_key(key)
    keys = e2e.agent_keys(key)

    def owner_key(command: str, *options: str) -> str:
        done = person.shell(f"splint-owner-key {command} --dir {shlex.quote(str(owner))} " + " ".join(shlex.quote(option) for option in options), work)
        return done.stdout.strip()

    owner_identity = next(line.split(": ", 1)[1] for line in owner_key("init").splitlines() if line.startswith("owner identity: "))
    backup = json.loads(owner_key("agent-backup"))
    made = json.loads(owner_key("agent-identity", "--key", keys, "--commitment", backup["commitment"]))
    binding = e2e.accepted(owner_key("bind", "--agent", made["identity"], "--address", address, "--backup", backup["file"]), key)
    return {"agent_id": made["agent_id"], "identity": made["identity"], "owner_identity": owner_identity, "binding": binding}


def a_host_cant_choose_the_key_what_she_signs_is_sealed_to(signup: Signup, dana: Person, max_: Person, ben: Person) -> None:
    """Something in place of max's host says another agent is at his address, one whose sealing key it
    holds. Bugs caught: what dana signs for max sealed to the ID his host gives, which whoever answers
    there then opens, though her device has held his ID since she authorized him: as she signs it, and
    as something a release from before owner mail was sealed kept is sealed when it's sent again."""
    walk = signup.walk
    max_id = authorized(dana, max_.address)["agent"]
    max_seal = max_.dot / "signet" / "agent.seal"
    at = f"127.0.0.1:{e2e.free_port()}"
    check("control: max's operator turns owner network access on again", walk.run_as("max", f"splint network-access on {at}").returncode == 0)
    named = walk.run_as("dana", f"splint for {max_.address} direct {at}")
    check("control: dana names that address for max, and it answers", named.returncode == 0 and "it answers there" in named.stdout, named.stdout + named.stderr)
    another = another_agent_at(dana, max_.address, walk.work)
    check("control: another agent's ID is made for max's address, which isn't max's", another["agent_id"].startswith("splint1") and another["agent_id"] != max_id, another)
    kept = lambda: list((dana.dot / "not-at-host").glob("*.person-text.*.json"))  # noqa: E731
    heard: list[bytes] = []

    def last_left_for_max() -> str | None:
        """Which kind of thing the last one left at what answers for max's host is, as max's Signet
        opens it with his own sealing key. None if it doesn't open for him, or nothing was left."""
        return e2e.opened_owner_mail(max_seal, max_id, heard[-1].decode() if heard else "").get("kind")

    with with_her_splint_auto_stopped(walk):
        host_is_down(signup)
        says = [429]
        in_its_place = in_place_of_the_host(signup, naming_another(another, "max", ("POST", f"/v0/owner-mail/{max_id}"), heard, says))
        try:
            # Ben's device holds nothing of max's, so it goes by who the host says is there, once that checks out.
            taken_in = walk.run_as("ben", f"splint for {max_.address} direct 127.0.0.1:9")
            check("control: what answers for max's address checks out as a host's answer, to a device that holds no ID of his", taken_in.returncode == 0, taken_in.stdout + taken_in.stderr)
            walk.run_as("ben", f"splint for {max_.address} direct off")

            said = walk.run_as("dana", f"splint for {max_.address} say {ben.address} 'for max alone'")
            check("control: her words go straight, are left at what answers for his host, which is at its limit, and are kept", said.returncode != 0 and "not confirmed yet" in said.stderr and len(heard) == 1 and len(kept()) == 1, (said.stderr, len(heard), len(kept())))
            check("what her device left there opens for max, whose ID it holds, so it wasn't sealed to the agent his host named", last_left_for_max() == "person_text", last_left_for_max())

            # As a release from before owner mail was sealed kept it: what she signed, with nothing sealed.
            for file in kept():
                before_sealing = json.loads(file.read_text())
                check("control: what's kept holds the sealed bytes that were left", before_sealing.pop("sealed", None) == heard[-1].decode(), sorted(before_sealing))
                file.write_text(json.dumps(before_sealing))
            says.append(200)
            walk.run_as("dana", "splint agents")
            check("control: the next splint run leaves it there, sealed now, and keeps it no longer", len(heard) == 2 and heard[1] != heard[0] and not kept(), (len(heard), len(kept())))
            check("and that opens for max too", last_left_for_max() == "person_text", last_left_for_max())
        finally:
            out_of_the_way(in_its_place)
        host_is_back(signup)
    check("control: max's operator turns it off", walk.run_as("max", "splint network-access off").returncode == 0)


class TcpHttp(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Counted(BaseHTTPRequestHandler):
    """Stands in for a Signet that refuses everything, counting what reaches it."""

    calls = 0
    seen: list[str] = []

    def answer(self) -> None:
        type(self).calls += 1
        type(self).seen.append(f"{self.command} {self.path}")
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.send_response(500)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_PUT = do_POST = answer

    def log_message(self, *_: object) -> None:
        pass


def answering(status: int, only: tuple[str, str] | None = None, heard: list[bytes] | None = None) -> type[BaseHTTPRequestHandler]:
    """Answers `status` to every call, or only to `only`'s method and path and 502 to the rest, and
    keeps the body of each call it answered `status` to in `heard`."""

    class Answers(BaseHTTPRequestHandler):
        def answer(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            if heard is not None and only in (None, (self.command, self.path)):
                heard.append(body)
            self.send_response(status if only in (None, (self.command, self.path)) else 502)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_PUT = do_POST = answer

        def log_message(self, *_: object) -> None:
            pass

    return Answers


def in_place_of_the_host(signup: Signup, handler: type[BaseHTTPRequestHandler]) -> TcpHttp:
    """Has `handler` answer at the stopped host's address, as a proxy in front of it could."""
    port = int(signup.open_host.rsplit(":", 1)[1])
    server = TcpHttp(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def out_of_the_way(server: TcpHttp) -> None:
    server.shutdown()
    server.server_close()


def replaying(view: bytes) -> type[BaseHTTPRequestHandler]:
    class Replays(BaseHTTPRequestHandler):
        """Hands back a view max's Signet gave out earlier, as someone who kept it could."""

        def do_GET(self) -> None:  # noqa: N802 - the name BaseHTTPRequestHandler calls
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("splint-protocol", "1")
            self.send_header("Content-Length", str(len(view)))
            self.end_headers()
            self.wfile.write(view)

        def log_message(self, *_: object) -> None:
            pass

    return Replays


def a_stand_in_at_the_named_address(signup: Signup, dana: Person, max_: Person, ben: Person, kept_view: bytes) -> None:
    """Bugs caught: whatever answered at the address dana named for max, a stranger on whatever network
    her device is on, could say yes to rules or where she gets paid with the host unreachable, and she
    was told they were done though neither max's Signet nor its host ever had them. And with the host
    up, it could say yes to an answer or her words and keep them: she was told they were done, the host
    never had them, and max waited on her until the step's deadline."""
    walk = signup.walk
    max_id = authorized(dana, max_.address)["agent"]
    stand_in = TcpHttp(("127.0.0.1", 0), SaysYes)
    threading.Thread(target=stand_in.serve_forever, daemon=True).start()
    refuses = TcpHttp(("127.0.0.1", 0), Counted)
    threading.Thread(target=refuses.serve_forever, daemon=True).start()
    replayer = TcpHttp(("127.0.0.1", 0), replaying(kept_view))
    threading.Thread(target=replayer.serve_forever, daemon=True).start()
    try:
        # Bug caught: a view someone kept from the network, handed back later at the address named,
        # was taken over the host's newer one, hiding whatever had come up since.
        at = f"127.0.0.1:{replayer.server_address[1]}"
        check("control: dana names an address where a kept view is handed back", walk.run_as("dana", f"splint for {max_.address} direct {at}").returncode == 0)
        waiting = walk.run_as("dana", f"splint for {max_.address} waiting")
        listed = walk.run_as("dana", "splint agents").stdout
        check("a view older than its Signet would sign now isn't taken, and the host's is read", waiting.returncode == 0 and "last by way of its host" in listed, (waiting.stderr, listed))
        port = e2e.free_port()
        controls = subprocess.Popen(
            ["bash", "-c", "\n".join([*dana.exports, f"exec splint controls {signup.open_host} --no-open --port {port}"])],
            env=dana.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            page = {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty", "Origin": f"http://localhost:{port}"}
            check("control: her controls open", wait_until(lambda: http("GET", f"http://localhost:{port}/.well-known/splint/host", headers=page)[0] == 200, 20))
            view_at = f"http://localhost:{port}/relay/{signup.open_host}/v0/owner-view/{max_id}"
            route = answered(urllib.request.Request(view_at, headers=page))[1]
            only_host = answered(urllib.request.Request(view_at, headers={**page, "splint-route": "host"}))[1]
            check("her page, which checks a view's date itself, can ask her controls for the host's alone", route == "network" and only_host is None, (route, only_host))
        finally:
            controls.terminate()
            controls.wait(10)

        # Bug caught (by mutation): any answer from the network counted as taken, so words a Signet
        # refused never went to the host.
        at = f"127.0.0.1:{refuses.server_address[1]}"
        check("control: dana names an address where something refuses everything", walk.run_as("dana", f"splint for {max_.address} direct {at}").returncode == 0)
        before = owner_mail(signup, max_id)
        said = walk.run_as("dana", f"splint for {max_.address} say {ben.address} 'are you there'")
        after = owner_mail(signup, max_id)
        check("what it refuses goes to the host", said.returncode == 0 and Counted.calls > 0 and after == before + 1, (said.stderr, Counted.calls, before, after))
        # Bug caught (by mutation): an address file changed to name another agent's keys was used.
        named = json.loads((dana.dot / "direct.json").read_text())
        named[max_id]["identity"] = ben.api("GET", "/v0/identity")[1]["identity"]
        (dana.dot / "direct.json").write_text(json.dumps(named))
        calls = Counted.calls
        said = walk.run_as("dana", f"splint for {max_.address} say {ben.address} 'still there'")
        check("and with that address named for another agent's keys, nothing goes there at all", said.returncode == 0 and Counted.calls == calls, (said.stderr, Counted.seen))

        at = f"127.0.0.1:{stand_in.server_address[1]}"
        check("control: dana names an address where something says yes to everything", walk.run_as("dana", f"splint for {max_.address} direct {at}").returncode == 0)
        record = authorized(dana, max_.address)
        check("control: her record has ben", any(contact["address"] == ben.address for contact in record["draft"]["contacts"]), record["draft"]["contacts"])

        # The stand-in says yes and keeps nothing, and its host is up.
        owner_token = max_.setup_file()["owner_token"]
        said_before = owner_mail(signup, max_id)
        said = walk.run_as("dana", f"splint for {max_.address} say {ben.address} 'thursday works'")
        check("with only the stand-in saying yes, her words go to max's host anyway", said.returncode == 0 and owner_mail(signup, max_id) == said_before + 1, (said.stderr, said_before))
        held_words = lambda: [words["text"] for words in max_.api("GET", "/v0/owner/person-text", token=owner_token)[1].get("waiting", [])]  # noqa: E731
        check("so max's Signet gets them", wait_until(lambda: "thursday works" in held_words(), RELAY_SECONDS), held_words())
        request = taken_on(ben, max_)
        status, held = max_.api("POST", f"/v0/requests/{request}/deliver", {"result": DEAR})
        check("control: max's price waits for dana", status == 200 and held.get("waiting_for_owner") is True, held)
        waiting = lambda: walk.run_as("dana", f"splint for {max_.address} waiting").stdout  # noqa: E731
        check("control: it reaches her terminal by way of the host, as the stand-in has no view to give", wait_until(lambda: request[:12] in waiting(), RELAY_SECONDS), waiting())
        yes = walk.run_as("dana", f"splint for {max_.address} approve {request[:12]}", "yes\n")
        check("control: she says yes to it, the stand-in answering first", yes.returncode == 0, yes.stdout + yes.stderr)
        check("her yes reaches max's Signet by way of his host, and his price goes to ben", reached(ben, request, "delivered", RELAY_SECONDS), ben.api("GET", f"/v0/requests/{request}")[1])
        ben.api("POST", f"/v0/requests/{request}/decline", {"reason": "cannot_supply"})

        before, _ = host_rules(signup, max_id)
        paid_before = owner_mail(signup, max_id)
        # Bug caught (by mutation): a host down behind its proxy, which answers 502, counted as one that
        # refused, so what only the stand-in took was never kept or sent again.
        host_is_down(signup)
        proxy = in_place_of_the_host(signup, answering(502))
        try:
            # With nothing to read the rules in force from, no rules are signed at all, so
            # only where she gets paid is left for the stand-in to take.
            removed = walk.run_as("dana", f"splint for {max_.address} remove {ben.address}")
            check("with its host's proxy answering 502 and only the stand-in saying yes, taking ben out isn't said to be done",
                  removed.returncode != 0 and "rules in force" in removed.stderr, removed.stdout + removed.stderr)
            paid = walk.run_as("dana", f"splint for {max_.address} get-paid https://pay.example.com/dana-new")
            check("nor is where she gets paid", paid.returncode != 0, paid.stdout + paid.stderr)
            listed = walk.run_as("dana", "splint agents").stdout
            check("splint agents says where she gets paid waits for max's host", listed.count("Waiting") == 1, listed)
        finally:
            out_of_the_way(proxy)

        # A release before this one kept where she gets paid for a host as she signed it, with nothing
        # sealed. Bug caught: one kept like that going to the host as it was signed once this release
        # runs, or never going at all: it's sealed now, to max's ID as her device holds it, and left.
        with with_her_splint_auto_stopped(walk):
            kept = dana.dot / "not-at-host" / f"{max_id}.where-paid.json"
            as_before = json.loads(kept.read_text())
            check("control: her device keeps it, with what leaves it at max's host sealed", isinstance(as_before.pop("sealed", None), str), sorted(as_before))
            kept.write_text(json.dumps(as_before))
            host_is_back(signup)
            walk.run_as("dana", "splint agents")
            paid_after = owner_mail(signup, max_id)
            check("the next splint run here gives max's host where she gets paid, though it was kept as a release before this kept one", paid_after == paid_before + 1, (paid_before, paid_after))
        # The stand-in kept nothing, so max's Signet has it only if what reached his host opens for him.
        places = lambda: json.dumps(max_.api("GET", "/v0/where-paid")[1])  # noqa: E731
        check("and max's Signet opens it, and holds where she gets paid now", wait_until(lambda: "pay.example.com/dana-new" in places(), HOST_HEARS_SECONDS), places())
        check("and no rules, as none were signed", host_rules(signup, max_id)[0] == before and ben.address in contacts_of(max_), (before, host_rules(signup, max_id)[0], contacts_of(max_)))
        check("and nothing waits any more", "Waiting" not in walk.run_as("dana", "splint agents").stdout)
    finally:
        walk.run_as("dana", f"splint for {max_.address} direct off")
        for server in (stand_in, refuses, replayer):
            server.shutdown()
            server.server_close()


def main() -> None:
    subprocess.run(["cargo", "build", "--quiet", "-p", "splint-core", "--example", "seal_owner_call"], cwd=e2e.PACKAGES, check=True)
    work = e2e.short_scratch("splint-direct-")
    signup = Signup(work)
    nenye = None
    try:
        nenye, dan, ben, dana, max_ = setup_people(signup)
        on_this_computer_rules_go_straight_and_the_host_catches_up(signup, nenye, dan, ben)
        a_program_standing_in_for_its_signet_cant_keep_rules_from_the_host(signup, nenye, dan, ben)
        kept_view = over_the_network_only_what_the_owner_signed_gets_in(signup, dana, max_, ben)
        what_she_signs_goes_both_ways_and_counts_once(signup, dana, max_, ben)
        a_host_that_doesnt_take_what_its_signet_took(signup, dana, max_, ben)
        a_sign_in_that_asks_for_her_asks_once_and_only_for_a_host_thats_there(signup, dana, max_, ben)
        a_host_cant_choose_the_key_what_she_signs_is_sealed_to(signup, dana, max_, ben)
        a_stand_in_at_the_named_address(signup, dana, max_, ben, kept_view)
    finally:
        if nenye:
            signup.walk.run_as("nenye", "splint --as dan stop")
        signup.walk.stop_everything()
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall direct access checks passed", flush=True)


if __name__ == "__main__":
    main()

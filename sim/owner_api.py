#!/usr/bin/env python3
"""The Owner API's sessions and the owner's agents list, against the real host, Signet and `splint`,
with the agent assumed fully fooled.

A person sets up their controls for an agent that asked by its link, as Splint on their computer
does, with a key file. Their side then starts a session, one approval for 12 hours of reading, and
reads what the host keeps for them: the sealed owner view, the rules it holds and what it refused. It
keeps the list of their agents at its host, and a new computer finds it by the owner's ID alone. Then
what goes wrong: a session for another host, one that's over, one another owner signed, a read with no
session, a session key signing rules or where the owner gets paid as though it were the owner, and a
list older than the one held. A session does leave something for the agent at its host, sealed to the
agent, which only takes room there. And the host serves no owner page: no script, and nothing that
could make or use a passkey (Nenye, 2026-11-21). An owner whose ID is a passkey from before then keeps
their agent, through a host and Signet that start again, and their passkey's session and rules still
count, as nothing migrates such an owner.

    python3 sim/owner_api.py

The owner's side is a script with a key file, as in sim/owner_by_link.py, so no browser or
hardware-held key is shown here, and its session key is a file key. The list it keeps is opaque bytes
of a sealed note's size, as a host can't open one either: that a list opens for its owner alone is
shown by splint-core's tests. Homes stand for devices under one OS user, so nothing stops an agent
reading another home. No agent has network limits.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import e2e
from agent_signup import Signup, registered
from e2e import check, compact_json, decode, encode, http, wait_until
from install import Person
from owner_by_link import FileKeyOwner, joined_on_its_own, set_up_controls, signing_input

SESSION_HEADER = "splint-owner-session"
HOUR = 3600
# The site a passkey made on a host's own page was for, before hosts stopped serving one.
PASSKEY_SITE = "owner.splint.test"


def request(method: str, url: str, body: object = None, headers: dict[str, str] | None = None) -> tuple[int, dict, dict[str, str]]:
    """A call as a page in a browser makes it, with whatever headers it sets, and the answer's headers."""
    data = None if body is None else json.dumps(body).encode()
    sent = urllib.request.Request(url, data=data, method=method)
    sent.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        sent.add_header(name, value)
    try:
        with urllib.request.urlopen(sent, timeout=10) as response:
            content, status, got = response.read(), response.status, response.headers
    except urllib.error.HTTPError as error:
        content, status, got = error.read(), error.code, error.headers
    try:
        answer = json.loads(content or b"{}")
    except ValueError:
        answer = {"raw": content.decode(errors="replace")}
    return status, answer, {name.lower(): value for name, value in got.items()}


class Session:
    """The owner's side's session: a key it made, which the owner's key signed for one host. `holder`
    is the owner, anything with an `id` and a `sign`."""

    def __init__(self, folder: Path, holder, host: str, owner: str | None = None, issued_at: int | None = None, lasts: int = 12 * HOUR, signer=None) -> None:
        self.key = folder / f"session-{os.urandom(4).hex()}.key"
        point = e2e.new_key(self.key)
        issued_at = int(time.time()) if issued_at is None else issued_at
        fields = {"v": 1, "owner": owner or holder.id, "key": point, "host": host, "issued_at": issued_at, "expires_at": issued_at + lasts}
        self.compact = (signer or holder).sign("splint-owner-session", fields)
        self.host = host

    def headers(self, method: str, path: str, body: bytes = b"") -> dict[str, str]:
        signed = self.compact.rsplit(".", 1)[0]
        fields = {"session": hashlib.sha256(signed.encode()).hexdigest(), "host": self.host, "method": method, "path": path, "body_sha256": hashlib.sha256(body).hexdigest(), "issued_at": int(time.time())}
        return {"Authorization": f"Splint {self.sign_as_session('splint-owner-access', fields)}", SESSION_HEADER: self.compact}

    def sign_as_session(self, typ: str, fields: dict) -> str:
        """Whatever this key signs, ES256, as a page or a fooled agent holding it could."""
        signed = signing_input("ES256", typ, fields)
        return f"{signed}.{encode(e2e.es256(self.key, signed.encode()))}"

    def read(self, path: str) -> tuple[int, dict]:
        status, answer, _ = request("GET", f"http://{self.host}{path}", headers=self.headers("GET", path))
        return status, answer


class PasskeyOwner:
    """A software key standing in for a passkey an owner made on a host's page before 2026-11-21. It
    signs WA256 as a passkey does, a touch over a challenge, at that host's site. Nothing makes one now,
    and nothing migrates one made then, so every reader still checks what it signs (Nenye, 2026-11-21)."""

    alg = "WA256"

    def __init__(self, folder: Path) -> None:
        folder.mkdir(parents=True)
        self.key = folder / "passkey.key"
        point = e2e.new_key(self.key)
        backup = e2e.new_key(folder / "backup.key")
        seal = e2e.new_key(folder / "seal.key")
        recovery = {"rule": "backup_key", "commitment": hashlib.sha256(decode(backup)).hexdigest()}
        event = compact_json({"v": 5, "alg": "webauthn-es256", "key": point, "rp": PASSKEY_SITE, "seal": seal, "recovery": recovery})
        self.identity = encode(event)
        self.id = "splint1" + hashlib.sha256(event).hexdigest()

    def touch(self, challenge: str, batch: list[str] | None = None) -> str:
        client_data = compact_json({"type": "webauthn.get", "challenge": challenge, "origin": f"https://{PASSKEY_SITE}", "crossOrigin": False})
        # The site's hash, then the person present and verified, then a count of zero.
        authenticator_data = hashlib.sha256(PASSKEY_SITE.encode()).digest() + bytes([0x05]) + bytes(4)
        e2e.es256(self.key, b"")  # writes the key's PEM beside it the first time
        der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.key.with_suffix(".pem"))], input=authenticator_data + hashlib.sha256(client_data).digest(), check=True, capture_output=True).stdout
        fields = {"a": encode(authenticator_data), **({"b": batch} if batch else {}), "c": encode(client_data), "s": encode(der)}
        return encode(compact_json(fields))

    def sign(self, typ: str, payload: dict) -> str:
        signed = signing_input("WA256", typ, payload)
        return f"{signed}.{self.touch(encode(hashlib.sha256(signed.encode()).digest()))}"

    def sign_together(self, inputs: list[str]) -> list[str]:
        """One touch over several signing inputs, as "Owner keys in a passkey" in docs/protocol.md says."""
        batch = [hashlib.sha256(signed.encode()).hexdigest() for signed in inputs]
        challenge = encode(hashlib.sha256(b"splint wa256 batch v1" + b"".join(bytes.fromhex(one) for one in batch)).digest())
        segment = self.touch(challenge, batch)
        return [f"{signed}.{segment}" for signed in inputs]


def list_for(holder, host: str, seq: int, handle: str | None = None, agents: str | None = None, owner_id: str | None = None) -> dict:
    """A list as the owner's side keeps one: opaque sealed bytes, as a host can't open it either."""
    fields = {"v": 1, "owner": owner_id or holder.id, "host": host, "handle": handle or os.urandom(32).hex(), "seq": seq, "issued_at": int(time.time()), "agents": agents or encode(os.urandom(160)), "recovery": encode(os.urandom(160))}
    return {"owner_identity": holder.identity, "list": holder.sign("splint-owner-agents", fields)}


def agent_id_of(signup: Signup, name: str) -> str:
    found = registered(signup.open_host, name)
    return found["agent_id"] if found else ""


def one_approval_reads_for_a_session(signup: Signup, owner: FileKeyOwner, agent: str) -> Session:
    """Bugs caught: an owner who has to approve every read."""
    approvals = owner.approvals
    session = Session(signup.walk.work, owner, signup.open_host)
    for path in (f"/v0/owner-view/{agent}", f"/v0/rules/{agent}", f"/v0/refused/{agent}"):
        status, _ = session.read(path)
        check(f"the owner's session reads {path.split('/')[2]}", status == 200, status)
    status, held = session.read(f"/v0/rules/{agent}")
    rules = e2e.payload_of(held.get("rules") or "x.e30.x") if status == 200 else {}
    check("and the rules it reads are the ones the owner signed", rules.get("owner") == owner.id and rules.get("agent") == agent, held)
    check("all for the one approval that started the session", owner.approvals - approvals == 1, owner.approvals - approvals)
    return session


def nobody_else_reads_with_a_session(signup: Signup, owner: FileKeyOwner, mallory: FileKeyOwner, agent: str, session: Session) -> None:
    """Bugs caught: an owner read that needs no session, or takes one that reads at any host, outlives
    its end or counts for another owner, on any of the owner's reads."""
    elsewhere = Session(signup.walk.work, owner, "other.example")
    elsewhere.host = signup.open_host
    over = Session(signup.walk.work, owner, signup.open_host, issued_at=int(time.time()) - 13 * HOUR)
    theirs = Session(signup.walk.work, mallory, signup.open_host)
    forged = Session(signup.walk.work, owner, signup.open_host, signer=mallory)
    for path in (f"/v0/owner-view/{agent}", f"/v0/rules/{agent}", f"/v0/refused/{agent}", f"/v0/owner-agents/{owner.id}"):
        what = path.split("/")[2]
        url = f"http://{signup.open_host}{path}"
        check(f"a read of {what} with no session or proof is refused", request("GET", url)[0] == 401)
        proof_only = {"Authorization": session.headers("GET", path)["Authorization"]}
        check(f"and of {what} with a session key's proof alone, taken as the owner's own", request("GET", url, headers=proof_only)[0] == 401)
        check(f"a session the owner signed for another host reads no {what} here", elsewhere.read(path)[0] == 401)
        check(f"a session past its end reads no {what}", over.read(path)[0] == 401)
        check(f"another owner's own session reads none of this owner's {what}", theirs.read(path)[0] == 401)
        check(f"nor does one in this owner's name that another owner's key signed, of {what}", forged.read(path)[0] == 401)
    view = f"/v0/owner-view/{agent}"
    status, _, _ = request("GET", f"http://{signup.open_host}/v0/rules/{agent}", headers=session.headers("GET", view))
    check("a proof for one read doesn't do another", status == 401, status)
    check("control: the owner's session still reads", session.read(view)[0] == 200)


def a_session_key_is_never_the_owner(signup: Signup, owner: FileKeyOwner, muse: Person, agent: str, session: Session) -> None:
    """The owner's session key may be stolen, or the agent fooled into holding it.
    Bugs caught: a host taking rules, a yes or a list signed by it as the owner's, or a session header
    standing for the owner's signature on a write."""
    _, held = session.read(f"/v0/rules/{agent}")
    rules = e2e.payload_of(held["rules"])
    loosened = rules | {"seq": rules["seq"] + 1, "permissions": {"level": "full_auto", "actions_per_day": 1000, "caps": {}}}
    loosened.pop("delegation", None)
    by_session = session.sign_as_session("splint-rules", loosened)
    body = {"rules": by_session}
    status, _, _ = request("PUT", f"http://{signup.open_host}/v0/rules", body, session.headers("PUT", "/v0/rules", json.dumps(body).encode()))
    check("rules a session key signed are refused, session or not", status in (400, 401), status)
    _, after = session.read(f"/v0/rules/{agent}")
    check("and the rules held are the owner's still", after.get("rules") == held["rules"], after)
    # A session leaves something at the agent's host for its Signet, sealed to the agent, which buys
    # room there and nothing else. Bugs caught: a host keeping what a session left unsealed, and a
    # Signet taking what's inside on the session's word, with no signature of the owner's on it.
    host = signup.open_host
    path = f"/v0/owner-mail/{agent}"
    url = f"http://{host}{path}"
    identity = registered(host, "muse")["identity"]
    kept = lambda only="": int(signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{agent}' {only}") or 0)  # noqa: E731
    places = lambda: [place.get("url") for place in muse.api("GET", "/v0/where-paid")[1].get("places", [])]  # noqa: E731

    def statement(place: str) -> dict:
        return {"v": 1, "owner": owner.id, "places": [{"kind": "payment_page", "url": place}], "issued_at": int(time.time())}

    def left(body: str) -> int:
        return e2e.http("POST", url, raw=body.encode(), headers=session.headers("POST", path, body.encode()))[0]

    before = kept()
    by_session = session.sign_as_session("splint-where-paid", statement("https://pay.example.com/thief"))
    plain = json.dumps({"kind": "where_paid", "signed": by_session})
    check("what a session key signed, left as it was signed under that session, is refused", left(plain) == 400 and kept() == before, (left(plain), kept() - before))
    check("sealed to the agent, the session leaves it, which only takes room", left(e2e.sealed_owner_mail(identity, "where_paid", by_session)) == 200 and kept() == before + 1, kept() - before)
    check("the agent's Signet takes it off the host", wait_until(lambda: kept("AND NOT taken") == 0, 60), kept("AND NOT taken"))
    check("and finds no signature of its owner's inside, so nothing says where they get paid", places() == [], places())
    by_owner = owner.sign("splint-where-paid", statement("https://pay.example.com/nenye"))
    check("control: the same statement signed by the owner's key, left the same way, gets in", left(e2e.sealed_owner_mail(identity, "where_paid", by_owner)) == 200)
    check("control: and its Signet takes that", wait_until(lambda: places() == ["https://pay.example.com/nenye"], 60), places())


def the_owner_keeps_a_list_a_new_computer_finds(signup: Signup, owner: FileKeyOwner, mallory: FileKeyOwner, agent: str) -> None:
    """Bugs caught: a list an older copy replaces, one anyone can write or read, and a new computer that
    can't find its owner from the handle their recovery code gives alone."""
    host = signup.open_host
    url = f"http://{host}/v0/owner-agents/{owner.id}"
    sealed = encode(os.urandom(160))
    handle = os.urandom(32).hex()

    def listed(signer: FileKeyOwner, seq: int, agents: str = sealed, owner_id: str | None = None) -> dict:
        return list_for(signer, host, seq, handle, agents, owner_id)

    seq = int(time.time() * 1000)
    first = listed(owner, seq)
    status, kept = http("PUT", url, first)
    check("the owner keeps their sealed list of agents at their home host", status == 200 and kept.get("seq") == seq, (status, kept))
    check("and the same list again is taken, so the owner's side can retry", http("PUT", url, first)[0] == 200)
    status, _ = http("PUT", url, listed(owner, seq - 1, encode(os.urandom(160))))
    check("a list with a lower seq than the one held is refused", status == 409, status)
    status, _ = http("PUT", url, listed(owner, seq, encode(os.urandom(160))))
    check("and another with the same seq", status == 409, status)
    status, _ = http("PUT", url, listed(mallory, seq + 1, owner_id=owner.id) | {"owner_identity": owner.identity})
    check("another owner's key can't write this owner's list", status == 400, status)
    status, _ = http("PUT", url, listed(mallory, seq + 1))
    check("nor can another owner put theirs in this owner's place", status == 400, status)

    # A new computer: the person has only their recovery code, which gives the list's handle.
    status, found = http("GET", f"http://{host}/v0/owner-handles/{handle}")
    check("a new computer finds the lists naming its handle", status == 200 and [one["list"] for one in found.get("lists", [])] == [first["list"]], found)
    check("and nothing for a handle nobody named", http("GET", f"http://{host}/v0/owner-handles/{os.urandom(32).hex()}")[0] == 404)
    check("a list isn't read without a session", request("GET", url)[0] == 401)
    status, known = http("GET", f"http://{host}/v0/owners/{owner.id}")
    check("a new computer finds the owner's ID by its name alone", status == 200 and known.get("owner_identity") == owner.identity, known)
    device = Session(signup.walk.work, owner, host)
    status, held = device.read(f"/v0/owner-agents/{owner.id}")
    check("and with a session reads the list it kept", status == 200 and held.get("list") == first["list"], held)
    theirs = Session(signup.walk.work, mallory, host)
    check("another owner's session doesn't read it", theirs.read(f"/v0/owner-agents/{owner.id}")[0] == 401)
    newer = listed(owner, seq + 1, encode(os.urandom(160)))
    check("control: a newer list replaces it", http("PUT", url, newer)[0] == 200 and device.read(f"/v0/owner-agents/{owner.id}")[1].get("list") == newer["list"])

    # Mallory has no agent here. Her list is kept only while she's setting one up from its link.
    theirs_url = f"http://{host}/v0/owner-agents/{mallory.id}"
    status, _ = http("PUT", theirs_url, listed(mallory, seq + 10))
    check("a host keeps no list for an owner with no agent here", status == 403, status)
    # Bug caught: room made by naming any agent here, so one someone owns lets anyone keep lists. Only
    # an agent with no controls yet, as one whose link brought someone new here does, makes room.
    status, _ = http("PUT", theirs_url, listed(mallory, seq + 10) | {"agent": agent})
    check("nor for one naming an agent here that an owner has already", status == 403, status)
    pip = joined_on_its_own(signup, "pip")
    pips = agent_id_of(signup, "pip")
    # Newer than the owner's own, so only putting lists of owners with agents here first keeps theirs first.
    status, _ = http("PUT", theirs_url, listed(mallory, seq + 10) | {"agent": pips})
    check("but does while they're setting up an agent here with no controls yet", bool(pip) and status == 200, status)
    # Mallory's list names the other owner's handle. Only a list that owner's key signed is taken by a
    # recovery, and the host puts lists of owners with agents here first.
    status, found = http("GET", f"http://{host}/v0/owner-handles/{handle}")
    owners = [one["owner_identity"] for one in found.get("lists", [])]
    check("someone naming another's handle doesn't push theirs out", status == 200 and owners and owners[0] == owner.identity, owners)
    check("control: an owner nobody here knows isn't found", http("GET", f"http://{host}/v0/owners/splint1{'0' * 64}")[0] == 404)


def lists_of_owners_with_no_agent_here_are_capped_by_the_day(signup: Signup) -> None:
    """Someone new keeps a list before any agent of theirs is here, from their agent's link, and a
    throwaway owner costs nothing. Bug caught: no cap on those lists, so one network fills a host."""
    host, network = signup.open_host, "198.51.100.20"
    waiting = joined_on_its_own(signup, "tia")
    tia = agent_id_of(signup, "tia")
    seq = int(time.time() * 1000)
    headers = {"X-Forwarded-For": network}
    for made in range(20):
        one = FileKeyOwner(signup.walk.work / f"lister-{made}")
        kept = http("PUT", f"http://{host}/v0/owner-agents/{one.id}", list_for(one, host, seq) | {"agent": tia}, headers=headers)[0]
        check(f"control: list {made + 1} from that network today is kept", bool(waiting) and kept == 200, kept)
    late = FileKeyOwner(signup.walk.work / "lister-late")
    status, _ = http("PUT", f"http://{host}/v0/owner-agents/{late.id}", list_for(late, host, seq) | {"agent": tia}, headers=headers)
    check("past 20 new ones from one network in a day, the next waits for tomorrow", status == 429, status)


def a_retired_agent_makes_no_room_for_its_owners_list(signup: Signup) -> None:
    """Bugs caught: an owner whose only agent here is retired still given room, so retiring keeps it."""
    owner = FileKeyOwner(signup.walk.work / "rita-owner")
    set_up_controls(signup, owner, "rita")
    agent = agent_id_of(signup, "rita")
    retirement = owner.sign("splint-retirement", {"v": 1, "owner": owner.id, "agent": agent, "reason": "finished", "issued_at": int(time.time())})
    check("control: the owner retires their only agent here", http("POST", f"http://{signup.open_host}/v0/retirements", {"retirement": retirement})[0] == 200)
    status, _ = http("PUT", f"http://{signup.open_host}/v0/owner-agents/{owner.id}", list_for(owner, signup.open_host, int(time.time() * 1000)))
    check("and the host keeps no new list for them", status == 403, status)


def an_owners_old_key_cant_replace_their_list_after_a_recovery(signup: Signup, owner: FileKeyOwner) -> None:
    """A stolen key, and its owner recovered their ID to a new key with their backup. Bugs caught:
    a host taking a list signed under the ID as it was, so the thief's key still writes it."""
    host = signup.open_host
    work = signup.walk.work / "recovered"
    work.mkdir()
    event = e2e.decode(owner.identity.split("~")[0])
    new_key, next_backup = work / "key.key", work / "backup.key"
    statement = {
        "v": 2, "id": owner.id, "seq": 1, "prev": hashlib.sha256(event).hexdigest(),
        "backup": e2e.public_of(owner.backup), "key": e2e.new_key(new_key), "seal": e2e.seal_public_of(new_key),
        "recovery": {"rule": "backup_key", "commitment": hashlib.sha256(e2e.decode(e2e.new_key(next_backup))).hexdigest()}, "issued_at": int(time.time()),
    }
    recovered = f"{owner.identity}~" + e2e.sign_jws(owner.backup, "splint-recovery", e2e.compact_json(statement))
    url = f"http://{host}/v0/owner-agents/{owner.id}"
    seq = int(time.time() * 1000) + 100
    fields = {"v": 1, "owner": owner.id, "host": host, "handle": os.urandom(32).hex(), "seq": seq, "issued_at": int(time.time()), "agents": encode(os.urandom(160)), "recovery": encode(os.urandom(160))}
    status, _ = http("PUT", url, {"owner_identity": recovered, "list": e2e.sign_jws(new_key, "splint-owner-agents", e2e.compact_json(fields))})
    check("control: the recovered key keeps the owner's list, under their ID as it is now", status == 200, status)
    status, answer = http("PUT", url, list_for(owner, host, seq + 1))
    check("the old key's newer list is refused as out of date", status == 423, (status, answer))
    session = Session(signup.walk.work, owner, host)
    check("control: nor does the old key read it", session.read(f"/v0/owner-agents/{owner.id}")[0] == 401)


def any_page_may_call_and_no_host_serves_an_owner_page(signup: Signup, agent: str) -> None:
    """Bugs caught: an owner API a page on another origin, such as the controls at localhost, can't
    call. And issue 635: a host serving a page that makes or signs with a passkey, which chooses what a
    touch signs, or naming one to agents, whose older releases hand people a link to it."""
    host = signup.open_host
    status, _, headers = request("OPTIONS", f"http://{host}/v0/owner-view/{agent}", headers={"Origin": "http://localhost:7480", "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization, splint-owner-session"})
    allowed = headers.get("access-control-allow-headers", "")
    check("a page anywhere may call the owner API, with its session header", status == 204 and headers.get("access-control-allow-origin") == "*" and SESSION_HEADER in allowed, headers)
    check("and is never sent cookies, as none count", "access-control-allow-credentials" not in headers, headers)
    _, _, guest = request("GET", f"http://{host}/v0/guest/links/{'0' * 64}")
    check("control: what isn't the owner API isn't opened to other pages", "access-control-allow-origin" not in guest, guest)
    status, said = http("GET", f"http://{host}/.well-known/splint/host")
    check("the host names no owner page, and no name a passkey would be for", status == 200 and "owner_page" not in said and "owner_page_rp_id" not in said, said)
    status, page, headers = request("GET", f"http://{host}/owner")
    words = page.get("raw", "")
    check("where its page was, it says in plain text that the controls are on the person's own computer", status == 200 and headers.get("content-type", "").startswith("text/plain") and "own computer" in words, (status, headers, words))
    check("with nothing to run, and nothing it may ask the browser for", "<script" not in words and headers.get("content-security-policy") == "default-src 'none'; frame-ancestors 'none'" and headers.get("x-content-type-options") == "nosniff", headers)
    for name in ("owner.js", "owner-keys.js", "owner-terms.js", "owner.css"):
        status, _, _ = request("GET", f"http://{host}/{name}")
        check(f"and it serves no /{name}", status == 404, status)
    for path in (f"/v0/pairings/{'0' * 32}", f"/v0/reading-keys/{agent}/{'0' * 64}"):
        status, _, _ = request("GET", f"http://{host}{path}")
        check(f"nor what only that page used, at {path.split('/')[2]}", status == 404, status)


def an_owner_whose_id_is_a_passkey_keeps_their_agent(signup: Signup) -> None:
    """Bug caught: a host or Signet that stopped taking a passkey's WA256 signature, on a binding, rules,
    a delegation or a session, which would stop every agent of an owner whose ID is a passkey."""
    host = signup.open_host
    owner = PasskeyOwner(signup.walk.work / "kai-passkey")
    kai = set_up_controls(signup, owner, "kai")
    agent = agent_id_of(signup, "kai")
    check("control: kai's host holds him as the passkey owner's", (registered(host, "kai") or {}).get("owner_identity") == owner.identity)
    check("control: kai's host stops", signup.walk.run_as("hana", "splint host stop").returncode == 0)
    check("control: and starts again", signup.walk.run_as("hana", "splint host start").returncode == 0)
    check("control: kai's Signet stops", signup.walk.run_as("kai", "splint stop").returncode == 0)
    check("control: and starts again", signup.walk.run_as("kai", "splint start").returncode == 0)
    acts = lambda: kai.api("GET", "/v0/identity")[1]  # noqa: E731
    check("after both start again, kai still acts for the owner whose ID is a passkey", wait_until(lambda: acts().get("owner_confirmed") is True and acts().get("owner_id") == owner.id, 60), acts())
    session = Session(signup.walk.work / "kai-passkey", owner, host)
    status, held = session.read(f"/v0/rules/{agent}")
    check("a session the passkey signs reads the rules it signed, at the host", status == 200 and e2e.payload_of(held.get("rules", "..")).get("owner") == owner.id, status)
    rules = e2e.payload_of(held.get("rules", ".."))
    paused = owner.sign("splint-rules", rules | {"seq": rules.get("seq", 0) + 1, "issued_at": int(time.time()), "paused": True})
    check("new rules the passkey signs are taken by kai's host", http("PUT", f"http://{host}/v0/rules", {"rules": paused})[0] == 200)
    check("and by kai's Signet", kai.api("PUT", "/v0/owner/rules", {"rules": paused})[0] == 200)


def main() -> None:
    work = e2e.short_scratch("splint-owner-api-")
    signup = Signup(work)
    try:
        owner = FileKeyOwner(work / "nenye-device")
        mallory = FileKeyOwner(work / "mallory-device")
        muse = set_up_controls(signup, owner, "muse")
        agent = agent_id_of(signup, "muse")
        session = one_approval_reads_for_a_session(signup, owner, agent)
        nobody_else_reads_with_a_session(signup, owner, mallory, agent, session)
        a_session_key_is_never_the_owner(signup, owner, muse, agent, session)
        the_owner_keeps_a_list_a_new_computer_finds(signup, owner, mallory, agent)
        lists_of_owners_with_no_agent_here_are_capped_by_the_day(signup)
        a_retired_agent_makes_no_room_for_its_owners_list(signup)
        any_page_may_call_and_no_host_serves_an_owner_page(signup, agent)
        an_owners_old_key_cant_replace_their_list_after_a_recovery(signup, owner)
        an_owner_whose_id_is_a_passkey_keeps_their_agent(signup)
    finally:
        signup.walk.stop_everything()
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall owner API checks passed", flush=True)


if __name__ == "__main__":
    main()

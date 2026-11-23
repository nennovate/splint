#!/usr/bin/env python3
"""What an owner signs for an agent that isn't on their own machine can't be read at that agent's host.

Dan's agent signed itself up, and Dana holds its owner's key on her own device, so everything she signs
for it is left at its host for its Signet to take. Ben prices a quote for Dan, and Dana says yes to it
from her terminal with a subject of her own, writes words for Ben as herself, and says where she gets
paid, all while Dan's Signet is stopped, so each is still waiting at the host. The host's whole database
is then dumped, as its operator or anyone holding a backup could, and none of it is there to read: not
the price or the subject of the deal she said yes to, not her words, not where she gets paid, nor which
of those each thing left there is. Dan's Signet is then started again, and each still does what she
signed it for, once.

Then who gets anything in there at all. Only Dan's owner leaves something for him, by a proof her own
key signed for exactly the sealed bytes, at that host, for him, moments ago, or by a session of hers
there: nobody with no proof, not Ben's owner, not Dan's own key, not a stand-in for an owner who hasn't
confirmed, and not Dana herself with anything that isn't sealed. The same bytes again are kept once,
and past 64 waiting she waits. Last, a host that kept owner mail as it was signed, as releases before
this one did, seals what's still waiting when it starts on this one and stops holding any in plain,
in what a dump shows or in the file the table is kept in.

    python3 sim/owner_mail_sealed.py

Not shown: Splint on their computer, which seals them for its owner page (sim/agent_asks.py),
hardware-held keys (Dana's is a plain key file, as `splint authorize` makes one), what Postgres's
write-ahead log or a disk's freed blocks still hold of rows from before the upgrade, or a person at
the terminal: a script types the answers. No agent has network limits.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time

import e2e
from agent_signup import Signup, handle_of, registered
from e2e import check, http, wait_until
from install import ARRIVE_SECONDS, Person, signet_pid
from owner_api import Session
from owner_device import RELAY_SECONDS, quoted, reached, setup_people, state_at, words_said
from owner_by_link import joined_on_its_own
from request_driver import hours_from_now

QUOTE = {"currency": "usd", "item": "catering", "quantity": 40}
# What a row of owner mail was named by while a host could read it, and what each thing an owner
# signs for their agent says it is.
KINDS = ("approval", "acceptance", "person_text", "where_paid", "delegation")
# Only what's left here. A yes to a contact's change is also told to the host by the agent's Signet, in
# plain and on purpose, so the host can hold that contact, and this leaves none.
SIGNED_AS = ("splint-approval", "splint-person-text", "splint-where-paid")
# What an agent's host keeps waiting for its Signet at most, which one more than is refused.
OWNER_MAIL_PLACES = 64
# The owner_mail table as every release before this one made it, from packages/host/src/owner_relay.rs
# as it was then, and a row as that host kept one.
SCHEMA_BEFORE_SEALING = """
    DROP TABLE owner_mail;
    CREATE TABLE IF NOT EXISTS owner_mail (
        seq BIGSERIAL PRIMARY KEY,
        agent_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        signed TEXT NOT NULL,
        at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS owner_mail_agent ON owner_mail (agent_id, seq);
    ALTER TABLE owner_mail ADD COLUMN IF NOT EXISTS item BYTEA;
    ALTER TABLE owner_mail ADD COLUMN IF NOT EXISTS taken BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE UNIQUE INDEX IF NOT EXISTS owner_mail_item ON owner_mail (agent_id, item);
"""
ROW_BEFORE_SEALING = "INSERT INTO owner_mail (agent_id, kind, signed, item, at) VALUES ('{agent}', '{kind}', '{signed}', sha256(convert_to('{item}', 'UTF8')), {at}), ('{agent}', 'acceptance', '', sha256(convert_to('taken long ago', 'UTF8')), {at})"
BASE64URL = re.compile(rb"[A-Za-z0-9_-]{8,}")
HEX = re.compile(rb"\\x((?:[0-9a-f]{2}){4,})")


def everything_readable_in(dump: bytes, depth: int = 3) -> bytes:
    """The dump, with everything in it that's only encoded read out as well: what's written in base64url,
    as each part of anything signed is, and in hex, as Postgres writes bytes. Whatever those hold is
    read the same way, as something signed can carry something else signed."""
    found = [dump]
    if depth == 0:
        return dump
    for run in BASE64URL.findall(dump):
        try:
            found.append(everything_readable_in(base64.urlsafe_b64decode(run + b"=" * (-len(run) % 4)), depth - 1))
        except ValueError:
            pass
    for run in HEX.findall(dump):
        found.append(everything_readable_in(bytes.fromhex(run.decode()), depth - 1))
    return b"\n".join(found)


def dumped(signup: Signup, *more: str) -> bytes:
    """The host's database as its operator, or a backup of it, has it."""
    container = json.loads((signup.walk.people["hana"].dot / "host" / "host.json").read_text())["container"]
    return subprocess.run(["docker", "exec", container, "pg_dump", "-U", "splint", "--data-only", *more], capture_output=True, check=True).stdout


def in_its_files(container: str, table: str) -> bytes:
    """What Postgres has in the files it keeps this table in, as anyone holding its disk or a copy of
    its data folder reads them. A row that was deleted or replaced and a column that was dropped stay
    in those until the table is written out again, and a dump shows neither."""

    def said(statement: str) -> str:
        return subprocess.run(["docker", "exec", container, "psql", "-U", "splint", "-v", "ON_ERROR_STOP=1", "-tAc", statement], capture_output=True, text=True, check=True).stdout.strip()

    # So everything written so far is in the files, not only in memory.
    said("CHECKPOINT")
    folder = said("SHOW data_directory")
    files = said(f"SELECT pg_relation_filepath(oid) FROM pg_class WHERE oid IN ('{table}'::regclass, (SELECT reltoastrelid FROM pg_class WHERE oid = '{table}'::regclass))").split()
    return b"".join(subprocess.run(["docker", "exec", container, "cat", f"{folder}/{file}"], capture_output=True, check=True).stdout for file in files)


def what_an_owner_signs_for_an_agent_elsewhere_cant_be_read_at_its_host(signup: Signup, agent: Person, owner: Person, ben: Person) -> None:
    """Bug caught: an agent's host, its database and every backup of it holding the terms of a sealed
    deal its owner said yes to, their own words and where they get paid, each left there in plain as
    the owner signed it."""
    walk = signup.walk
    price = 100_000_000 + secrets.randbelow(900_000_000)
    subject, words, place = (secrets.token_hex(12) for _ in range(3))
    request = quoted(signup, agent, ben, {"amount_minor": price, "valid_days": 14}, ben)
    short = request[:12]
    listed = lambda: walk.run_as(owner.name, "splint waiting").stdout  # noqa: E731
    check("control: ben's price reaches dana's device, by way of dan's host", wait_until(lambda: short in listed() and str(price) in listed(), RELAY_SECONDS), listed())
    waiting = lambda: signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{agent.agent_id}' AND NOT taken")  # noqa: E731
    check("control: dan's Signet has taken everything left for it so far", wait_until(lambda: waiting() == "0", RELAY_SECONDS), waiting())

    pid = signet_pid(agent)
    check("control: dan's Signet is running", pid > 0, pid)
    # Stopped where it is, as one whose machine is off or asleep is, so nothing left for it is taken.
    os.kill(pid, signal.SIGSTOP)
    try:
        agreed = walk.run_as(owner.name, f"splint approve {short} --subject {subject}", "yes\n")
        check("control: dana says yes to the price, with a subject of her own", agreed.returncode == 0 and str(price) in agreed.stderr.replace(",", "").replace(".", ""), agreed.stderr)
        said = walk.run_as(owner.name, f'splint say {ben.address} "{words}"')
        check("control: and writes words for ben as herself", said.returncode == 0, said.stderr)
        paid = walk.run_as(owner.name, f"splint get-paid https://pay.example.com/{place}")
        check("control: and says where she gets paid", paid.returncode == 0, paid.stderr)
        check("control: all three wait at dan's host, as his Signet is stopped", waiting() == "3", waiting())
        check("control: and none reached ben", state_at(ben, request) == "delivered", state_at(ben, request))

        readable = everything_readable_in(dumped(signup))
        for name, marker in (("the price she said yes to", str(price)), ("the subject she gave it", subject), ("her words", words), ("where she gets paid", place)):
            check(f"the host's database doesn't hold {name}, however it's encoded", marker.encode() not in readable, f"{marker} is in a dump of the host's database")
        for signed_as in SIGNED_AS:
            check(f"nor anything signed as {signed_as}", f'"typ":"{signed_as}"'.encode() not in readable, signed_as)
        mail = everything_readable_in(dumped(signup, "--table", "owner_mail"))
        for kind in KINDS:
            check(f"nor does what's left for dan say it's {kind}", kind.encode() not in mail, kind)
    finally:
        os.kill(pid, signal.SIGCONT)

    check("once dan's Signet is back, her yes goes, with dan doing nothing", reached(agent, request, "completed", RELAY_SECONDS), state_at(agent, request))
    check("and ben reads it, with her subject", reached(ben, request, "completed") and ben.api("GET", f"/v0/requests/{request}")[1].get("has_subject") is True, ben.api("GET", f"/v0/requests/{request}")[1])
    check("where she gets paid is with dan's Signet", wait_until(lambda: place in json.dumps(agent.api("GET", "/v0/where-paid")[1]), RELAY_SECONDS), agent.api("GET", "/v0/where-paid")[1])
    check("and all three were taken", wait_until(lambda: waiting() == "0", RELAY_SECONDS), waiting())
    status, opened = agent.api("POST", "/v0/requests", {"contact": ben.address, "type": "quote/1", "terms": QUOTE, "deadline": hours_from_now(48)})
    check("control: dan's agent opens something with ben", status == 200, opened)
    check("and her words arrive with it, once", wait_until(lambda: words_said(ben, opened["request"]) == [words], ARRIVE_SECONDS), words_said(ben, opened["request"]))
    ben.api("POST", f"/v0/requests/{opened['request']}/decline", {"reason": "cannot_supply"})


class KeyFileOwner:
    """An owner whose key is a file, signing what a page would have a passkey sign."""

    def __init__(self, person: Person, work) -> None:
        # A copy, as signing with openssl leaves a PEM beside the key it's given.
        self.key = work / f"{person.name}-owner-copy.key"
        shutil.copy(person.dot / "owner" / "owner.key", self.key)
        self.key.chmod(0o600)
        shown = person.shell("splint-owner-key show --dir ~/.splint/owner", work).stdout
        self.id = next(line.split(": ", 1)[1] for line in shown.splitlines() if line.startswith("owner id: "))

    def sign(self, typ: str, fields: dict) -> str:
        return e2e.sign_jws(self.key, typ, e2e.compact_json(fields))


def only_its_owner_leaves_anything_for_an_agent_and_only_sealed(signup: Signup, agent: Person, owner: Person, ben: Person) -> None:
    """Bugs caught: a contact, a fooled agent or anyone else filling the room an agent's owner has at
    its host, a proof that's good for another call, body, host or time, a stand-in's key counting as
    an owner's, a host keeping what an owner signed as they signed it, and a retry kept twice."""
    walk, host = signup.walk, signup.open_host
    path = f"/v0/owner-mail/{agent.agent_id}"
    url = f"http://{host}{path}"
    identity = registered(host, "dan")["identity"]
    mine = f"agent_id = '{agent.agent_id}'"
    rows = lambda: int(signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE {mine}"))  # noqa: E731
    waiting = lambda: int(signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE {mine} AND NOT taken"))  # noqa: E731

    def sealed_words(text: str, to_identity: str = identity, to_agent: str = agent.agent_id) -> dict:
        """Words Dana signs for an agent, with what her owner key leaves at its host: {signed, body, proof}."""
        done = owner.shell(f"splint-owner-key person-text --dir ~/.splint/owner --agent {to_agent} --to {ben.agent_id} --host {host} --agent-identity '{to_identity}'", walk.work, text)
        return json.loads(done.stdout)

    def proof_by(person: Person, body: str, at: str = host, to: str = path) -> str:
        """A proof this person's owner key signs for leaving exactly this body there."""
        return person.shell(f"splint-owner-key access --dir ~/.splint/owner --host {at} --method POST --path {to} --body -", walk.work, body).stdout.strip()

    def leave(body: str, proof: str | None, headers: dict[str, str] | None = None, at: str = url) -> int:
        return http("POST", at, raw=body.encode(), auth=proof, headers=headers)[0]

    def signed_as(key, signer: str, body: str, issued_at: int) -> str:
        fields = {"signer": signer, "host": host, "method": "POST", "path": path, "body_sha256": hashlib.sha256(body.encode()).hexdigest(), "issued_at": issued_at}
        return e2e.sign_jws(key, "splint-access", e2e.compact_json(fields))

    pid = signet_pid(agent)
    check("control: dan's Signet is running", pid > 0, pid)
    os.kill(pid, signal.SIGSTOP)
    try:
        before = rows()
        first, second = sealed_words("first"), sealed_words("second")
        check("control: what dana's key sealed for dan and proved gets in", leave(first["body"], first["proof"]) == 200 and rows() == before + 1, rows() - before)
        check("the same bytes again get the answer a retry would", leave(first["body"], first["proof"]) == 200)
        check("and are kept once", rows() == before + 1, rows() - before)
        dana = KeyFileOwner(owner, walk.work)
        now = int(time.time())
        plain = json.dumps({"kind": "person_text", "signed": second["signed"]})
        beside = json.dumps({**json.loads(second["body"]), "kind": "person_text"})
        not_sealed = json.dumps({"sealed": second["signed"]})
        refused = [
            ("with no proof", leave(second["body"], None), 401),
            ("with ben's owner's proof", leave(second["body"], proof_by(ben, second["body"])), 401),
            ("with dan's own key's proof, as a fooled agent holding it would sign", leave(second["body"], signed_as(agent.dot / "signet" / "agent.key", agent.agent_id, second["body"], now)), 401),
            ("with her proof for another host", leave(second["body"], proof_by(owner, second["body"], at="other.example")), 401),
            ("with her proof for leaving it for another agent", leave(second["body"], proof_by(owner, second["body"], to=f"/v0/owner-mail/{ben.agent_id}")), 401),
            ("with her proof for other bytes", leave(second["body"], first["proof"]), 401),
            ("with a proof her key signed three minutes ago", leave(second["body"], signed_as(dana.key, dana.id, second["body"], now - 180)), 401),
            ("as she signed it, unsealed, though her proof is for exactly that", leave(plain, proof_by(owner, plain)), 400),
            ("sealed, with anything beside it in the clear", leave(beside, proof_by(owner, beside)), 400),
            ("with what she signed put where something sealed goes", leave(not_sealed, proof_by(owner, not_sealed)), 400),
        ]
        for name, status, expected in refused:
            check(f"nothing is kept {name}", status == expected, status)
        # Bug caught: her owner key signing a proof over a body for any call, so whatever runs it gets
        # a write of hers at a host that isn't leaving something sealed for her agent.
        others = [owner.shell(f"splint-owner-key access --dir ~/.splint/owner --host {host} --method {method} --path {to} --body -", walk.work, second["body"]) for method, to in (("POST", "/v0/pairings"), ("PUT", path), ("POST", "/v0/owner-mail"))]
        check("her owner key signs a proof over a body for leaving owner mail, and for no other call", [done.returncode != 0 and not done.stdout.strip() for done in others] == [True] * 3, [done.stdout + done.stderr for done in others])
        check("control: her own proof for those bytes, signed just now by the same key, gets them in", leave(second["body"], signed_as(dana.key, dana.id, second["body"], now)) == 200 and rows() == before + 2, rows() - before)

        # A session, as her page or Splint on her computer holds one: her key signs it once for one
        # host, and its key then proves each call.
        third, fourth = sealed_words("third"), sealed_words("fourth")
        session = Session(walk.work, dana, host)
        check("a session of hers at this host leaves something too", leave(third["body"], None, session.headers("POST", path, third["body"].encode())) == 200 and rows() == before + 3, rows() - before)
        elsewhere = Session(walk.work, dana, "other.example")
        elsewhere.host = host
        check("but not one she signed for another host", leave(fourth["body"], None, elsewhere.headers("POST", path, fourth["body"].encode())) == 401)
        check("nor a session key's proof for other bytes", leave(fourth["body"], None, session.headers("POST", path, third["body"].encode())) == 401)
        bens = Session(walk.work, KeyFileOwner(ben, walk.work), host)
        check("nor ben's owner's session", leave(fourth["body"], None, bens.headers("POST", path, fourth["body"].encode())) == 401)
        check("and none of what was refused is there", rows() == before + 3, rows() - before)

        # A stand-in for an owner who hasn't confirmed holds its key on the agent's own machine.
        sol = joined_on_its_own(signup, "sol")
        # Under the temporary name it joined with, as nobody has set up its controls.
        sols = registered(host, handle_of(sol.address))
        sol_id = sols["agent_id"]
        for_sol = sealed_words("for sol", sols["identity"], sol_id)
        sols_path = f"/v0/owner-mail/{sol_id}"
        by_stand_in = proof_by(sol, for_sol["body"], to=sols_path)
        check("control: the stand-in's key signs a proof", by_stand_in.count(".") == 2, by_stand_in)
        check("a stand-in for an owner who hasn't confirmed leaves nothing for its agent", leave(for_sol["body"], by_stand_in, at=f"http://{host}{sols_path}") == 401)
        check("and nothing is kept for it", signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{sol_id}'") == "0")

        room = OWNER_MAIL_PLACES - waiting()
        filled = [sealed_words(f"filling {number}") for number in range(room)]
        answers = {leave(one["body"], one["proof"]) for one in filled}
        check(f"control: she fills what's left of the {OWNER_MAIL_PLACES} places waiting for dan", answers == {200} and waiting() == OWNER_MAIL_PLACES, (answers, waiting()))
        over = sealed_words("one too many")
        check("one more waits its turn", leave(over["body"], over["proof"]) == 429 and waiting() == OWNER_MAIL_PLACES, waiting())
        check("while a retry of one already there is still answered as it was", leave(first["body"], proof_by(owner, first["body"])) == 200)
    finally:
        os.kill(pid, signal.SIGCONT)
    check("control: dan's Signet takes them all once it's back", wait_until(lambda: waiting() == 0, 2 * RELAY_SECONDS), waiting())
    # Bug caught: the host going on holding whose proof or session left each thing, after its Signet took it.
    still_held = signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE {mine} AND taken AND (sealed <> '' OR by_owner <> '')")
    check("of what was taken, the host keeps neither what was sealed nor the proof or session that left it", still_held == "0", still_held)
    # Bug caught: something left for dan that his Signet can't open holding up what she signed after
    # it. Not opening proves nothing, as it's how a lost sealing key looks, so it stays at the host
    # until that key is back or the host's week runs out, and counts as held.
    for_another = e2e.sealed_owner_mail(sols["identity"], "person_text", second["signed"])
    after = sealed_words("after one that won't open")
    os.kill(pid, signal.SIGSTOP)
    try:
        left = (leave(for_another, proof_by(owner, for_another)), leave(after["body"], after["proof"]))
        check("control: something sealed to another agent is let in for dan by her proof, as his host can't tell, and something of hers after it", left == (200, 200) and waiting() == 2, (left, waiting()))
    finally:
        os.kill(pid, signal.SIGCONT)
    check("dan's Signet takes what came after what it can't open, and leaves that at his host", wait_until(lambda: waiting() == 1, RELAY_SECONDS), waiting())
    held = agent.api("GET", "/v0/owner/person-text", token=agent.setup_file()["owner_token"])[1].get("waiting", [])
    check("and holds her words, which it opened and found her signature on", len(held) > 0, held)
    told = agent.api("GET", "/v0/listening")[1].get("held", [])
    check("its status read says one thing she left waits unopened", any(line["kind"] == "owner_mail_sealed_to_another_key" and line["count"] == 1 for line in told), told)
    check("something taken, left again, is still kept once", leave(first["body"], proof_by(owner, first["body"])) == 200 and waiting() == 1, waiting())
    signup.sql("hana", f"DELETE FROM owner_mail WHERE {mine} AND NOT taken")


def a_host_from_before_this_seals_what_waited_and_keeps_none_in_plain(signup: Signup, agent: Person, owner: Person, ben: Person) -> None:
    """Bugs caught: a host that can't start on a database an earlier release left, one that drops what
    an owner left there before the upgrade, and one that goes on holding it as they signed it: in a
    column it still reads, or in the table's file, where what a dropped column held stays until the
    table is written out again."""
    walk = signup.walk
    container = json.loads((walk.people["hana"].dot / "host" / "host.json").read_text())["container"]
    words = secrets.token_hex(12)
    signed = owner.shell(f"splint-owner-key person-text --dir ~/.splint/owner --agent {agent.agent_id} --to {ben.agent_id}", walk.work, words).stdout.strip()
    check("control: dana's key signs words for ben, as it did before any of this", signed.count(".") == 2, signed)
    check("control: the host stops", walk.run_as("hana", "splint host stop").returncode == 0)
    subprocess.run(["docker", "start", container], check=True, capture_output=True)
    psql = lambda statement: subprocess.run(["docker", "exec", container, "psql", "-U", "splint", "-v", "ON_ERROR_STOP=1", "-tAc", statement], capture_output=True, text=True)  # noqa: E731
    check("control: its database is there to change", wait_until(lambda: psql("SELECT 1").returncode == 0, 30))
    row = ROW_BEFORE_SEALING.format(agent=agent.agent_id, kind="person_text", signed=signed, item=signed.rsplit(".", 1)[0], at=int(time.time()))
    made = psql(SCHEMA_BEFORE_SEALING + ";" + row + "; UPDATE owner_mail SET taken = TRUE WHERE signed = ''")
    check("control: it's left as a release before this one would leave it, with her words waiting in plain", made.returncode == 0 and words.encode() in everything_readable_in(dumped(signup)), made.stderr)
    check("control: and they're in the file Postgres keeps that table in", signed.encode() in in_its_files(container, "owner_mail"))

    started = walk.run_as("hana", "splint host start")
    check("the host starts on it", started.returncode == 0, started.stderr)
    columns = signup.sql("hana", "SELECT string_agg(column_name, ',' ORDER BY column_name) FROM information_schema.columns WHERE table_name = 'owner_mail'")
    check("and keeps owner mail only sealed from then on", "sealed" in columns.split(",") and not {"kind", "signed"} & set(columns.split(",")), columns)
    waiting = lambda: signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{agent.agent_id}' AND NOT taken")  # noqa: E731
    check("what waited is taken by dan's Signet, which opens it as it would any other", wait_until(lambda: waiting() == "0", 2 * RELAY_SECONDS), waiting())
    readable = everything_readable_in(dumped(signup))
    check("and her words aren't in the host's database any more", words.encode() not in readable, f"{words} is in a dump of the host's database")
    # Bug caught (by mutation): with the columns dropped and the table not written out again, a dump
    # had none of it, and the table's file still held everything she'd signed.
    files = in_its_files(container, "owner_mail")
    check("nor in the file Postgres keeps that table in, which a dump doesn't show", signed.encode() not in files and words.encode() not in everything_readable_in(files), f"what she signed is in the owner_mail table's file {files.count(signed.encode())} times")
    status, opened = agent.api("POST", "/v0/requests", {"contact": ben.address, "type": "quote/1", "terms": QUOTE, "deadline": hours_from_now(48)})
    check("control: dan's agent opens something with ben", status == 200, opened)
    check("nothing she left was lost: her words go with it", wait_until(lambda: words in words_said(ben, opened["request"]), ARRIVE_SECONDS), words_said(ben, opened["request"]))
    ben.api("POST", f"/v0/requests/{opened['request']}/decline", {"reason": "cannot_supply"})


def main() -> None:
    work = e2e.short_scratch("splint-owner-mail-")
    signup = Signup(work)
    try:
        agent, owner, ben = setup_people(signup)
        what_an_owner_signs_for_an_agent_elsewhere_cant_be_read_at_its_host(signup, agent, owner, ben)
        only_its_owner_leaves_anything_for_an_agent_and_only_sealed(signup, agent, owner, ben)
        a_host_from_before_this_seals_what_waited_and_keeps_none_in_plain(signup, agent, owner, ben)
    finally:
        signup.walk.stop_everything()
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall sealed owner mail checks passed", flush=True)


if __name__ == "__main__":
    main()

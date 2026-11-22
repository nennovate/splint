#!/usr/bin/env python3
"""Gate 5: a resource on the owner's side lets an agent act only under a grant the owner signed.

The resource here is a small document store, standing in for any tool, API or data an owner's side
controls. Splint knows nothing about documents: the resource names its operations, and runs
`owner-key check-grant` on every call with the owner's public identity from its own config. The
agent's runtime calls it directly, with a proof its Signet signs for that one call. Everything else
is the real software against Postgres, like e2e.py, and the agent is assumed fully fooled.

Not shown here: a resource running somewhere other than this machine, or one enforcing limits of its
own inside an operation, which is the resource's job and not Splint's.
"""

import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import e2e
from e2e import check
from identity_recovery import recovery, who

RESOURCE = "files.ana.test"
DOCS = {"q4-plan": "Q4: hire two, ship v0."}
OPERATIONS = {"/docs/read": "docs.read", "/docs/write": "docs.write"}
CALLS_PER_HOUR = 4


class DocStore:
    """Ana's owner's document store. It trusts nothing about a caller but what the check returns."""

    def __init__(self, owner_identity: str, record: Path):
        self.owner_identity, self.record = owner_identity, record
        self.done: list[str] = []
        store = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                pass

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
                status, answer = store.handle(self.path, self.headers, body)
                data = json.dumps(answer).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def owner_key(self, command: str, stdin: str) -> tuple[bool, dict]:
        """Runs the check as any resource would, with the owner's identity from its own config."""
        named = ["--resource", RESOURCE] if command == "check-grant" else []
        done = e2e.owner_key_tool(command, "--owner", self.owner_identity, *named, "--record", str(self.record), stdin=stdin)
        try:
            return done.returncode == 0, json.loads(done.stdout)
        except json.JSONDecodeError:
            return False, {"ok": False, "reason": "record_unreadable"}

    def handle(self, path: str, headers, body: str) -> tuple[int, dict]:
        if path == "/revocations":
            passed, answer = self.owner_key("record-revocation", body)
            return (200 if passed else 403), answer
        operation = OPERATIONS.get(path)
        if operation is None:
            return 404, {}
        call = {
            "grant": headers.get("splint-grant", ""), "identity": headers.get("splint-identity", ""),
            "proof": headers.get("Authorization", "").removeprefix("Splint "),
            "operation": operation, "method": "POST", "path": path, "body": body,
        }
        passed, verdict = self.owner_key("check-grant", json.dumps(call))
        if not passed:
            return 403, {"refused": verdict.get("reason")}
        self.done.append(operation)
        doc = json.loads(body).get("doc", "")
        return 200, {"doc": DOCS.get(doc)}

    def stop(self) -> None:
        self.server.shutdown()


def grant(net: e2e.Network, agent: str, resource: str = RESOURCE, operations: str = "docs.read", owner: str | None = None) -> dict:
    return json.loads(net.owners[owner or agent].sign("grant", "--holder", net.ids[agent], "--resource", resource, "--operations", operations, "--calls-per-hour", str(CALLS_PER_HOUR)))


def give(net: e2e.Network, agent: str, signed: dict) -> tuple[int, dict]:
    url = f"http://127.0.0.1:{net.signet_port[agent]}/v0/owner/grants"
    return e2e.http("PUT", url, {"grant": signed["grant"]})


def call(net: e2e.Network, store: DocStore, agent: str, grant_id: str, path: str = "/docs/read", body: str = '{"doc":"q4-plan"}', sent_body: str | None = None) -> tuple[int, dict]:
    """What the agent's own runtime does: asks its Signet for a proof of this one call, then calls."""
    status, signed = net.agent(agent, "POST", f"/v0/grants/{grant_id}/proof", {"method": "POST", "path": path, "body": body})
    if status != 200:
        return status, signed
    headers = {"Authorization": signed["authorization"], signed["grant_header"]: signed["grant"], signed["identity_header"]: signed["identity"]}
    return raw_post(store, path, sent_body if sent_body is not None else body, headers)


def raw_post(store: DocStore, path: str, body: str, headers: dict) -> tuple[int, dict]:
    request = urllib.request.Request(f"{store.url}{path}", data=body.encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as answer:
            return answer.status, json.loads(answer.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def refused(answer: tuple[int, dict], reason: str) -> bool:
    return answer == (403, {"refused": reason})


def a_granted_call_passes_and_nothing_else_does(net: e2e.Network, store: DocStore) -> None:
    signed = grant(net, "ana")
    check("the owner's grant reaches the agent's Signet", give(net, "ana", signed)[0] == 200)
    listed = net.agent("ana", "GET", "/v0/grants")[1]["grants"]
    check("the agent sees what it may call, and where", [(g["id"], g["resource"], g["operations"]) for g in listed] == [(signed["id"], RESOURCE, ["docs.read"])], listed)
    check("control: a granted call is answered", call(net, store, "ana", signed["id"]) == (200, {"doc": DOCS["q4-plan"]}))
    check("an operation the grant doesn't name is refused", refused(call(net, store, "ana", signed["id"], path="/docs/write", body='{"doc":"q4-plan","text":"x"}'), "no_grant"))
    check("a proof for one body can't carry another", refused(call(net, store, "ana", signed["id"], sent_body='{"doc":"secrets"}'), "bad_proof"))
    _, headers = net.agent("ana", "POST", f"/v0/grants/{signed['id']}/proof", {"method": "POST", "path": "/docs/read", "body": '{"doc":"q4-plan"}'})
    stolen = {"Authorization": headers["authorization"], "splint-grant": headers["grant"], "splint-identity": net.agent("ben", "GET", "/v0/identity")[1]["identity"]}
    check("another agent holding the grant and proof gets nothing", refused(raw_post(store, "/docs/read", '{"doc":"q4-plan"}', stolen), "wrong_holder"))
    check("only calls that passed did anything", store.done == ["docs.read"], store.done)


def a_fooled_agent_cant_grant_itself_or_reach_its_host(net: e2e.Network, store: DocStore) -> None:
    check("a grant from another owner's key is refused", give(net, "ana", grant(net, "ana", owner="mallory"))[0] == 403)
    check("a grant for another agent is refused", give(net, "ana", grant(net, "ben", owner="ana"))[0] == 403)
    own_host = net.domain[net.home["ana"]]
    check("a grant naming the agent's own host is refused, so a proof can't act as Signet there", give(net, "ana", grant(net, "ana", resource=own_host))[0] == 403)
    status, _ = net.agent("ana", "POST", f"/v0/grants/{'ab' * 32}/proof", {"method": "POST", "path": "/docs/read", "body": "{}"})
    check("no proof for a grant Signet doesn't hold", status == 404, status)
    signed = grant(net, "ana")
    give(net, "ana", signed)
    net.put_rules("ana", net.sign_rules("ana", [net.contact_entry("ben")], paused=True))
    status, _ = net.agent("ana", "POST", f"/v0/grants/{signed['id']}/proof", {"method": "POST", "path": "/docs/read", "body": "{}"})
    check("a paused agent gets no proofs", status == 403, status)
    net.put_rules("ana", net.sign_rules("ana", [net.contact_entry("ben")]))


def the_rate_holds_and_revoking_stops_everything(net: e2e.Network, store: DocStore) -> None:
    signed = grant(net, "ana")
    give(net, "ana", signed)
    answers = [call(net, store, "ana", signed["id"]) for _ in range(CALLS_PER_HOUR)]
    check("control: calls up to the grant's rate pass", [status for status, _ in answers] == [200] * CALLS_PER_HOUR, answers)
    check("one more in the hour is refused", refused(call(net, store, "ana", signed["id"]), "over_rate"))
    fresh = grant(net, "ana")
    give(net, "ana", fresh)
    _, early = net.agent("ana", "POST", f"/v0/grants/{fresh['id']}/proof", {"method": "POST", "path": "/docs/read", "body": '{"doc":"q4-plan"}'})
    revocation = net.owners["ana"].sign("revoke-grant", "--grant", fresh["id"])
    check("the owner's revocation goes straight to the resource", raw_post(store, "/revocations", revocation, {})[0] == 200)
    headers = {"Authorization": early["authorization"], "splint-grant": early["grant"], "splint-identity": early["identity"]}
    check("a proof signed before the revocation is refused", refused(raw_post(store, "/docs/read", '{"doc":"q4-plan"}', headers), "revoked"))
    check("and every call after", all(refused(call(net, store, "ana", fresh["id"]), "revoked") for _ in range(3)))
    check("an agent key can't revoke for the owner", raw_post(store, "/revocations", net.envelope_signed_by("ana", "ana", "ben", "x"), {})[0] == 403)
    again = grant(net, "ana")
    give(net, "ana", again)
    check("a new grant from the owner works again", call(net, store, "ana", again["id"])[0] == 200)


def a_record_that_cant_be_read_refuses_everything(net: e2e.Network, store: DocStore) -> None:
    signed = grant(net, "ana")
    give(net, "ana", signed)
    store.record.write_text("not a record")
    check("a broken record could hide a revocation, so nothing passes", call(net, store, "ana", signed["id"])[0] == 403)
    store.record.unlink()


def signet_wont_sign_a_proof_it_shouldnt(net: e2e.Network, store: DocStore) -> None:
    """The resource runs the real check, and these are for what no resource would ever see: a proof for
    an agent's own host lets that agent act as its Signet, whatever is in its file."""
    owner, ana = net.owners["ana"], net.ids["ana"]
    now = int(time.time())

    def by_hand(resource: str, issued_at: int, expires_at: int) -> dict:
        payload = {"v": 1, "owner": owner.id, "holder": ana, "resource": resource, "operations": ["docs.read"],
                   "limits": {"calls_per_hour": 10}, "issued_at": issued_at, "expires_at": expires_at, "nonce": e2e.encode(os.urandom(16))}
        raw = e2e.compact_json(payload)
        return {"id": hashlib.sha256(raw).hexdigest(), "grant": e2e.sign_jws(owner.key, "splint-grant", raw)}

    def proof_for(grant_id: str) -> int:
        return net.agent("ana", "POST", f"/v0/grants/{grant_id}/proof", {"method": "POST", "path": "/docs/read", "body": ""})[0]

    good = by_hand(RESOURCE, now, now + 3600)
    check("control: a grant signed by hand is taken", give(net, "ana", good)[0] == 200)
    check("control: and gets a proof", proof_for(good["id"]) == 200)
    ended = by_hand(RESOURCE, now - 7200, now - 3600)
    check("control: an owner's old grant is taken", give(net, "ana", ended)[0] == 200)
    check("a grant that's run out gets no proof", proof_for(ended["id"]) == 404)

    own_host = by_hand(net.domain["a"], now, now + 3600)
    check("control: a grant for its own host isn't taken", give(net, "ana", own_host)[0] != 200)
    saved = net.work / "ana" / "grants.json"
    held = json.loads(saved.read_text())
    net.signets["ana"].kill_hard()
    saved.write_text(json.dumps(held | {own_host["id"]: own_host["grant"]}))
    net.signets["ana"].start()
    check("control: Signet comes back", net.wait_for_signet("ana"))
    check("one for its own host gets no proof, however it got into the file", proof_for(own_host["id"]) == 404)
    net.signets["ana"].kill_hard()
    saved.write_text(json.dumps(held))
    net.signets["ana"].start()
    net.wait_for_signet("ana")


def a_replaced_key_stops_working_at_a_resource(net: e2e.Network, store: DocStore) -> None:
    """A resource can't hear of a replaced key from any host, and the caller picks the copy of the ID it
    shows. So a thief keeps the old copy, and what stops them is the resource having seen a newer one."""
    net.add_owned_agents({"gia": "a"})
    owner = net.owners["gia"]
    signed = json.loads(owner.sign("grant", "--holder", net.ids["gia"], "--resource", RESOURCE, "--operations", "docs.read", "--calls-per-hour", "40"))
    grant_id = give(net, "gia", signed)[1]["id"]
    record = net.work / "gia-resource.json"
    resource = DocStore(owner.identity, record)

    def called(identity: str, key: Path, doc: str = "q4-plan") -> tuple[int, dict]:
        body = json.dumps({"doc": doc})
        proof = e2e.sign_jws(key, "splint-access", e2e.compact_json({
            "signer": net.ids["gia"], "host": RESOURCE, "method": "POST", "path": "/docs/read",
            "body_sha256": hashlib.sha256(body.encode()).hexdigest(), "issued_at": int(time.time())}))
        return raw_post(resource, "/docs/read", body, {"Authorization": f"Splint {proof}", "splint-grant": signed["grant"], "splint-identity": identity})

    old_copy = who(net, "gia")["identity"]
    stolen = net.work / "gia-stolen.key"
    stolen.write_bytes(net.key_of("gia").read_bytes())
    check("control: a thief holding the key can call", called(old_copy, stolen)[0] == 200)

    net.signets["gia"].kill_hard()
    net.key_of("gia").unlink()
    # Only a start told it's taking up this ID makes a key in place of the one that's gone.
    net.signets["gia"].env["SPLINT_RECOVERING"] = old_copy
    net.signets["gia"].start()
    net.wait_for_signet("gia")
    waiting = who(net, "gia")
    made = json.loads(owner.sign("recover-agent", "--agent", waiting["identity"], "--backup", net.agent_backups["gia"]["file"], "--new-key", waiting["key"]))
    check("control: the backup puts a new key on the ID", recovery(net, "gia", made["identity"])[0] == 200)
    # Nothing has told the resource yet, which is the one thing a resource can't get round.
    check("a resource nobody has told still takes the old key, as the docs say", called(old_copy, stolen)[0] == 200)

    answer = call(net, resource, "gia", grant_id)
    check("the agent's next call under its new key passes", answer[0] == 200, answer)
    check("and the thief's old copy of the ID no longer does", refused(called(old_copy, stolen), "bad_proof"), called(old_copy, stolen))
    check("nor the old key under the new copy", refused(called(made["identity"], stolen), "bad_proof"))

    other = DocStore(owner.identity, net.work / "gia-other-resource.json")
    told = e2e.owner_key_tool("record-identity", "--identity", made["identity"], "--record", str(other.record))
    check("an owner can tell a resource directly", told.returncode == 0 and json.loads(told.stdout)["learned"] is True, told.stdout)
    resource.stop()
    resource = other
    check("and the old key stops there before the agent has called at all", refused(called(old_copy, stolen), "bad_proof"), called(old_copy, stolen))
    other.stop()

    # Anyone can carry the new copy, so a call that's refused still counts for what it brought.
    resource = DocStore(owner.identity, net.work / "gia-third-resource.json")
    check("a call that brings the new copy with a bad proof is refused", refused(called(made["identity"], stolen), "bad_proof"))
    check("and what it brought stays", refused(called(old_copy, stolen), "bad_proof"), called(old_copy, stolen))
    resource.stop()


def main() -> int:
    e2e.build()
    with e2e.running_network(owned=True) as network:
        store = DocStore(network.owners["ana"].identity, network.work / "docs-grants.json")
        try:
            for scenario in (
                a_granted_call_passes_and_nothing_else_does,
                a_fooled_agent_cant_grant_itself_or_reach_its_host,
                the_rate_holds_and_revoking_stops_everything,
                a_record_that_cant_be_read_refuses_everything,
                signet_wont_sign_a_proof_it_shouldnt,
                a_replaced_key_stops_working_at_a_resource,
            ):
                print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
                scenario(network, store)
        finally:
            store.stop()
        if e2e.failures:
            for process in network.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1500:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

"""What agents and owners do with a managed request, as plain HTTP calls to their Signets.

An owner signs with the owner-key tool, which the harness runs on what stands in for their device.
"""

import json
import time

import e2e

HOUR = 3600
DAY = 24 * HOUR
MEETING = "meeting/1"
DEFAULT_OFFER = {"duration_min": 30, "purpose": "follow_up", "mode": "video"}
DEFAULT_LIFETIME_HOURS = 7 * 24


def hours_from_now(hours: int) -> int:
    return (int(time.time()) // HOUR + hours) * HOUR


def meeting_ask(address: str, **changes) -> dict:
    """The body that opens the example meeting type. `deadline` and `supersedes` belong to the step,
    and everything else to the type's terms."""
    deadline = changes.pop("deadline", hours_from_now(DEFAULT_LIFETIME_HOURS))
    supersedes = changes.pop("supersedes", None)
    terms = {**DEFAULT_OFFER, "slots": [hours_from_now(24), hours_from_now(25)], **changes}
    return {"contact": address, "type": MEETING, "terms": terms, "deadline": deadline, "supersedes": supersedes}


def meeting_open_step(**changes) -> dict:
    """A meeting's `open` step, as a stolen key could sign it with no Signet. A field given as None is
    left out, and `deadline` and `supersedes` belong to the step itself."""
    outside = {name: changes.pop(name) for name in ("deadline", "supersedes", "type") if name in changes}
    terms = {**DEFAULT_OFFER, "slots": [hours_from_now(24)], **changes}
    terms = {name: terms[name] for name in sorted(terms) if terms[name] is not None}
    step = {"step": "open", "type": outside.get("type", e2e.example_id(MEETING)), "terms": terms, "deadline": outside.get("deadline", hours_from_now(48))}
    if outside.get("supersedes"):
        step["supersedes"] = outside["supersedes"]
    return step


def open_conversation(net: e2e.Network, requester: str, recipient: str) -> str:
    """Core's plain conversation, which names no type, so two agents need agree nothing first."""
    body = {"contact": net.address(recipient), "deadline": hours_from_now(48), "supersedes": None}
    status, opened = net.agent(requester, "POST", "/v0/requests", body)
    if status != 200:
        raise RuntimeError(f"open failed: {status} {opened}")
    return opened["request"]


def open_request(net: e2e.Network, requester: str, recipient: str, **changes) -> str:
    status, opened = net.agent(requester, "POST", "/v0/requests", meeting_ask(net.address(recipient), **changes))
    if status != 200:
        raise RuntimeError(f"open failed: {status} {opened}")
    return opened["request"]


def view(net: e2e.Network, agent: str, request: str) -> dict:
    status, found = net.agent(agent, "GET", f"/v0/requests/{request}")
    return found if status == 200 else {"status": status}


def wait_for(net: e2e.Network, agent: str, request: str, **fields) -> dict | None:
    """The agent's view once it shows these fields, or None if it never does."""
    found: dict[str, dict] = {}

    def arrived() -> bool:
        found["view"] = view(net, agent, request)
        return all(found["view"].get(name) == value for name, value in fields.items())

    return found["view"] if e2e.wait_until(arrived) else None


def wait_for_received(net: e2e.Network, agent: str, request: str) -> bool:
    return e2e.wait_until(lambda: view(net, agent, request).get("delivery", {}).get("received") is True)


def move(net: e2e.Network, agent: str, request: str, step: str, body: dict | None = None) -> tuple[int, dict]:
    return net.agent(agent, "POST", f"/v0/requests/{request}/{step}", body if body is not None else {})


def owner_call(net: e2e.Network, agent: str, path: str, token: str | None = None) -> tuple[int, dict]:
    url = f"http://127.0.0.1:{net.signet_port[agent]}{path}"
    return e2e.http("GET", url, token=token or net.owners[agent].token)


def draft_for(net: e2e.Network, agent: str, request: str) -> dict | None:
    status, found = owner_call(net, agent, "/v0/owner/approvals")
    if status != 200:
        raise RuntimeError(f"couldn't read drafts: {status} {found}")
    return next((draft for draft in found["drafts"] if draft["request"] == request), None)


def sign_approval(net: e2e.Network, agent: str, draft: dict, /, decision: str = "approve", subject: str | None = None, signer=None, **changes) -> str:
    """Signs what an owner's device would, after showing them the draft. A subject is for the
    requester's owner to set, and the recipient's owner signs it as it stands."""
    terms = {**draft["terms"]}
    if subject is not None:
        terms["subject"] = subject
    now = int(time.time())
    payload = {
        "v": 1,
        "owner": draft["owner"],
        "agent": draft["agent"],
        "decision": decision,
        "operation": draft["operation"],
        "request": draft["request"],
        "version": draft["version"],
        "prev": draft["prev"],
        "terms": terms,
        "issued_at": now,
        "expires_at": draft["latest_expiry"],
        **changes,
    }
    key = signer if signer is not None else net.owners[agent].key
    return e2e.sign_jws(key, "splint-approval", canonical(payload).encode())


def post_approval(net: e2e.Network, agent: str, approval: str) -> tuple[int, dict]:
    return net.agent(agent, "POST", "/v0/owner/approvals", {"approval": approval})


def owner_decides(net: e2e.Network, agent: str, request: str, decision: str = "approve", subject: str | None = None) -> tuple[int, dict]:
    """What an owner does: signs a draft on their own device, with the tool they hold their key in."""
    draft = draft_for(net, agent, request)
    if draft is None:
        raise RuntimeError(f"{agent}'s owner has nothing to decide on {request}")
    subject_option = () if subject is None else ("--subject", subject)
    approval = net.owners[agent].sign("approve", "--decision", decision, *subject_option, stdin=json.dumps(draft))
    return post_approval(net, agent, approval)


def priced_move(net: e2e.Network, agent: str, request: str, step: str, body: dict) -> tuple[int, dict]:
    """A move that would commit its owner to an amount, which waits for their yes at every level, and that yes, given on their own device, which sends it."""
    status, moved = move(net, agent, request, step, body)
    if status != 200 or moved.get("waiting_for_owner") is not True:
        return status, moved
    return owner_decides(net, agent, request)


def canonical(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def signed_step(net: e2e.Network, signer: str, sender: str, recipient: str, body: object, nonce: str = "", age: int = 0, dates: tuple[int, int] | None = None) -> str:
    """A step made with a real key but without its Signet, as a stolen key or a test can. Dating it
    `age` seconds back makes an otherwise identical step a different one. A step carrying an owner's
    approval copies its dates, so it can't be made different at all."""
    now = int(time.time()) - age
    created_at, expires_at = now, now + DAY
    if not isinstance(body, str) and "approval" in body and "." in body["approval"]:
        approval = e2e.payload_of(body["approval"])
        if "issued_at" in approval:
            created_at, expires_at = approval["issued_at"], approval["expires_at"]
    if dates is not None:
        created_at, expires_at = dates
    payload = {
        "v": 1,
        "sender": net.ids[sender],
        "recipient": net.ids[recipient],
        "body": body if isinstance(body, str) else canonical(body),
        "created_at": created_at,
        "expires_at": expires_at,
        "nonce": nonce,
    }
    return e2e.sign_jws(net.key_of(signer), "splint-envelope", canonical(payload).encode())


def as_a_host_sees(compact: str) -> dict:
    """A step's fields, or for a sealed one, only what its outside shows a host."""
    body = json.loads(e2e.payload_of(compact)["body"])
    return body["sealed"]["outside"] if "sealed" in body else body


def step_kind(compact: str) -> str:
    return as_a_host_sees(compact)["step"]


def host_chain(net: e2e.Network, agent: str, request: str) -> list[str]:
    """The envelopes an agent's own host holds for a request, which it gives a page at a time."""
    envelopes: list[str] = []
    path = f"/v0/requests/{request}"
    while path:
        proof = net.access_proof(agent, agent, "GET", path)
        status, found = e2e.http("GET", f"http://{net.domain[net.home[agent]]}{path}", auth=proof)
        if status != 200:
            break
        envelopes += [step["envelope"] for step in found["steps"]]
        path = f"/v0/requests/{request}/after/{found['next']}" if "next" in found else ""
    return envelopes

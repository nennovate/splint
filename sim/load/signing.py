"""Splint's signed objects, written from the wire format so the load driver can sign real proofs.

Keys are derived from a seed picked for each run, so any driver process can rebuild any agent
without sharing key material, and nothing here works against any other run. Signing is done here
rather than by the owner-key tool, because a step can have more agents than that tool could set up
in a run. A host verifies what comes from here just as it would an owner's.
"""

import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import e2e  # noqa: E402

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ECDSA_SHA256 = ec.ECDSA(hashes.SHA256())
RULES_VERSION = 1
SEQ = 1


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def compact(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def derived_key(*names: object) -> ec.EllipticCurvePrivateKey:
    digest = hashlib.sha256(":".join(map(str, names)).encode()).digest()
    return ec.derive_private_key(int.from_bytes(digest, "big") % (P256_ORDER - 1) + 1, ec.SECP256R1())


def point_of(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def jws(key: ec.EllipticCurvePrivateKey, typ: str, payload: dict) -> str:
    signing_input = f"{b64(compact({'alg': 'ES256', 'typ': typ}))}.{b64(compact(payload))}"
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ECDSA_SHA256))
    return f"{signing_input}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class Keyed:
    """A key, the backup key its identity commits to, and the identity and ID they give."""

    def __init__(self, *names: object) -> None:
        self.key = derived_key(*names)
        self.backup = derived_key(*names, "backup")
        seal = derived_key(*names, "seal")
        recovery = {"rule": "backup_key", "commitment": hashlib.sha256(point_of(self.backup)).hexdigest()}
        event = compact({"v": 4, "alg": "ES256", "key": b64(point_of(self.key)), "seal": b64(point_of(seal)), "recovery": recovery})
        self.identity = b64(event)
        self.id = "splint1" + hashlib.sha256(event).hexdigest()
        self.keys = f"{b64(point_of(self.key))}.{b64(point_of(seal))}"


class Agent(Keyed):
    def __init__(self, seed: str, index: int):
        super().__init__(seed, index)
        self.seed, self.index = seed, index
        self.handle = f"load-{seed}-{index}"

    def access_proof(self, host: str, method: str, path: str, body: bytes = b"") -> str:
        return jws(self.key, "splint-access", {
            "signer": self.id, "host": host, "method": method, "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(), "issued_at": int(time.time()),
        })

    def seal(self, recipient_id: str, body: str, lifetime_secs: int) -> str:
        now = int(time.time())
        return jws(self.key, "splint-envelope", {
            "v": 1, "sender": self.id, "recipient": recipient_id, "body": body,
            "created_at": now, "expires_at": now + lifetime_secs, "nonce": b64(os.urandom(16)),
        })

    def partner(self) -> "Agent":
        """Each agent's one contact, and it's theirs: owners set each other up in pairs."""
        return Agent(self.seed, self.index ^ 1)

    def rows(self, domain: str, partner_domain: str) -> tuple[str, str]:
        """This agent's rows in `agents` and `rules` on a host, with what its own owner signed."""
        owner = Keyed(self.seed, self.index, "owner")
        now = int(time.time())
        owner_half = jws(owner.key, "splint-binding", {
            "v": 2, "owner": owner.id, "agent": self.id, "address": f"{self.handle}~{domain}", "seq": SEQ, "issued_at": now,
        })
        agent_half = jws(self.key, "splint-binding-accept", {"v": 1, "binding": hashlib.sha256(owner_half.encode()).hexdigest()})
        vouch = jws(self.backup, "splint-binding-vouch", {"v": 2, "agent": self.id, "owner": owner.id, "backup": b64(point_of(self.backup)), "keys": self.keys})
        partner = self.partner()
        contact = {
            "agent": partner.id, "address": f"{partner.handle}~{partner_domain}", "label": partner.handle,
            "status": "allowed", "types": e2e.EXAMPLE_TYPES, "text": True, "pinned_by": "owner",
        }
        rules = jws(owner.key, "splint-rules", {
            "v": RULES_VERSION, "owner": owner.id, "agent": self.id, "seq": SEQ, "issued_at": now,
            **e2e.rules_draft([contact]),
        })
        agent_row = (self.id, self.handle, self.identity, owner.id, owner.identity, f"{owner_half}~{agent_half}~{vouch}", str(SEQ))
        return "\t".join(agent_row), "\t".join((self.id, str(SEQ), rules))

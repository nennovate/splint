#!/usr/bin/env python3
"""People who changed the code on their own machines, and work together, against everyone else.

The code is public, so anyone can run a host or a Signet that skips any check it runs. So these are real
modified programs: this copies `packages/`, removes the checks a bad actor would remove, builds that, and
runs it. The modified hosts and Signets pass every check their own code still does, and the honest reader
is the unmodified host and Signet, with its agent assumed fully fooled. What counts is only what reaches
that agent, and what its owner gets to decide.

A scenario's name says the claim, and a check marked `honest limit` says where it stops. Those aren't
failures to fix: they're what `docs/how-it-works.md` says can't be stopped.

Not shown here: colluders outside the peer list of the reader's host, as this step's hosts only hear from
listed peers, real networks and TLS, hardware-held keys, and anything colluders do among themselves, which
nobody else sees.
"""

import json
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import e2e
from e2e import check, http, new_owner, wait_until
from hostile_home_host import Contact, changes_page, never_shown, put_on_the_inbox, sign_and_put, standing_of
from identity_recovery import a_peer_of_our_own, proposing, recovered_on_a_new_device, relayed, who
from reach_and_permissions import run_auto
from request_driver import hours_from_now as e2e_hours, open_request

ALWAYS = "std::hint::black_box(true)"
# What each modified program does differently, as (file, what's there, what it becomes). A change that no
# longer fits fails the run, so this can't quietly stop modifying anything.
MODIFICATIONS = [
    # A host that takes anything from its own agents, whoever they write to and however much.
    ("host/src/admission.rs",
     "pub async fn check_may_send(\n    host: &Host,\n    envelope: &VerifiedEnvelope,\n) -> Result<Option<VerifiedRules>, ApiError> {\n",
     f"pub async fn check_may_send(\n    host: &Host,\n    envelope: &VerifiedEnvelope,\n) -> Result<Option<VerifiedRules>, ApiError> {{\n    if {ALWAYS} {{ return Ok(None); }}\n"),
    ("host/src/delivery.rs",
     "    rules: Option<&VerifiedRules>,\n    recipient_host: &str,\n    receipt: bool,\n) -> Result<(), ApiError> {\n    if receipt {\n",
     f"    rules: Option<&VerifiedRules>,\n    recipient_host: &str,\n    receipt: bool,\n) -> Result<(), ApiError> {{\n    if {ALWAYS} {{ return Ok(()); }}\n    if receipt {{\n"),
    ("host/src/admission.rs",
     "    // What tells a contact about a replaced key has to go even with the rules gone, or it's silence.\n",
     f"    if {ALWAYS} {{ return Ok(QueuedMessage::Send); }}\n"),
    # A host that hands a retired or revoked key along, and ignores a recovery.
    ("host/src/registry/mod.rs",
     'WHERE id = $1 AND identity = $2 AND retirement IS NULL AND revocation IS NULL FOR SHARE"',
     'WHERE id = $1 AND identity = $2 FOR SHARE"'),
    ("host/src/registry/mod.rs",
     '''"SELECT identity FROM agents
         WHERE id = $1 AND retirement IS NULL AND ($2 OR revocation IS NULL)
             AND moved_away_to IS NULL",''',
     '''"SELECT identity FROM agents
         WHERE id = $1 AND ($2 OR TRUE)",'''),
    ("host/src/registry/mod.rs",
     "    take_identity(&host, &Identity::from_encoded(&notice.identity)?).await\n",
     f"    if {ALWAYS} {{ return Ok(()); }}\n    take_identity(&host, &Identity::from_encoded(&notice.identity)?).await\n"),
    ("host/src/delivery.rs",
     "    agent: &SplintId,\n) -> Result<(), sqlx::Error> {\n    guest::end_links_of(transaction, agent).await?;\n",
     f"    agent: &SplintId,\n) -> Result<(), sqlx::Error> {{\n    if {ALWAYS} {{ return Ok(()); }}\n    guest::end_links_of(transaction, agent).await?;\n"),
    # And tells nobody else of any of it.
    ("host/src/changes.rs",
     "async fn pass_on(host: &Host) -> Result<(), sqlx::Error> {\n",
     f"async fn pass_on(host: &Host) -> Result<(), sqlx::Error> {{\n    if {ALWAYS} {{ return Ok(()); }}\n"),
    ("host/src/changes.rs",
     "async fn pass_on_stops(host: &Host) -> Result<(), sqlx::Error> {\n",
     f"async fn pass_on_stops(host: &Host) -> Result<(), sqlx::Error> {{\n    if {ALWAYS} {{ return Ok(()); }}\n"),
    # A Signet that ignores holds and limits, and skips change notices.
    ("signet/src/rules.rs",
     "    pub async fn held_by_a_change(&self, agent: &SplintId) -> bool {\n",
     f"    pub async fn held_by_a_change(&self, agent: &SplintId) -> bool {{\n        if {ALWAYS} {{ return false; }}\n"),
    ("signet/src/rules.rs",
     "        contacts.retain(|contact| {\n",
     f"        contacts.retain(|contact| {{\n            if {ALWAYS} {{ return true; }}\n"),
    ("signet/src/budget.rs",
     "        key: &str,\n        allowed: u32,\n        per_hour: Option<u32>,\n        now: u64,\n    ) -> Result<(), NotTaken> {\n",
     f"        key: &str,\n        allowed: u32,\n        per_hour: Option<u32>,\n        now: u64,\n    ) -> Result<(), NotTaken> {{\n        if {ALWAYS} {{ return Ok(()); }}\n"),
    ("signet/src/changes/mod.rs",
     "pub async fn publish(signet: &Signet) -> Result<(), HostError> {\n",
     f"pub async fn publish(signet: &Signet) -> Result<(), HostError> {{\n    if {ALWAYS} {{ return Ok(()); }}\n"),
]


def build_modified() -> dict[str, str]:
    """Builds the modified copy in a target folder of its own, so it can't be taken for the real thing."""
    modified = e2e.TARGET_DIR / "modified"
    source = modified / "packages"
    shutil.rmtree(source, ignore_errors=True)
    shutil.copytree(e2e.PACKAGES, source, ignore=shutil.ignore_patterns("target"))
    for file, there, becomes in MODIFICATIONS:
        path = source / file
        text = path.read_text()
        if there not in text:
            raise RuntimeError(f"a modification no longer fits {file}: {there[:60]!r}")
        path.write_text(text.replace(there, becomes, 1))
    subprocess.run(["cargo", "build", "--quiet", "-p", "host", "-p", "signet"], cwd=source, check=True, env={**e2e.os.environ, "CARGO_TARGET_DIR": str(modified / "target")})
    return {name: str(modified / "target" / "debug" / name) for name in ("host", "signet")}


class Colluders:
    """Two modified hosts every honest host has listed, with their keys in this run's hands."""

    def __init__(self, net: e2e.Network, programs: dict[str, str]) -> None:
        self.net, self.signet = net, programs["signet"]
        ports = {"z1": e2e.free_port(), "z2": e2e.free_port()}
        for name, port in ports.items():
            net.domain[name] = f"127.0.0.1:{port}"
        # Hosts are open to each other, so the honest ones take these as they'd take any host.
        for name in ports:
            net.hosts[name] = net.spawn(programs["host"], f"host-{name}", {
                "SPLINT_DOMAIN": net.domain[name],
                "SPLINT_LISTEN": net.domain[name],
                "SPLINT_DATABASE_URL": net.postgres.create_database(f"host_{name}"),
                "SPLINT_HOST_KEY_FILE": str(net.work / f"host-{name}.key"),
                **e2e.PLAIN_HTTP_FOR_TESTS,
                "SPLINT_CLEANUP_SECS": "1",
                "SPLINT_SIGNUP_CODES": ",".join(e2e.signup_code(number) for number in range(e2e.SIGNUP_CODES)),
            })
            if not wait_until(lambda: http("GET", f"http://{net.domain[name]}/.well-known/splint/host")[0] == 200):
                raise RuntimeError(f"{name} didn't start")

    def agent(self, name: str, host: str = "z1") -> None:
        """A modified Signet on a modified host, signed for by an owner working with whoever runs them."""
        self.net.add_owned_agents({name: host}, signet=self.signet)

    def fake(self, name: str, owner: e2e.Owner, host: str = "z1") -> Contact:
        """An ID that costs nothing, carried by a host whose key is in this run's hands."""
        peer = SimpleNamespace(domain=self.net.domain[host], answers={})
        return Contact(self.net, name, owner, peer=(peer, self.net.work / f"host-{host}.key"))


def all_at_once(net: e2e.Network, senders: list[tuple[object, str]], to: str) -> None:
    """What a modified host does as often as it likes. It's signed first, as signing shares a file."""
    domain = net.domain[net.home[to]]
    bodies = [{
        "envelope": envelope, "sender_identity": sender.identity, "from_host": sender.peer.domain,
        "proof": net.host_proof(sender.peer_key, envelope, sender.peer.domain, domain),
        "sender_owner_identity": sender.owner.identity, "sender_binding": sender.binding,
    } for sender, envelope in senders]
    with ThreadPoolExecutor(len(bodies)) as pool:
        list(pool.map(lambda body: http("POST", f"http://{domain}/v0/deliver", body), bodies))


def limits(**smaller: int) -> dict:
    return {**e2e.LIMITS, **smaller}


def by_id(contact_id: str) -> SimpleNamespace:
    return SimpleNamespace(id=contact_id)


def a_modified_signet_and_host_cant_exceed_what_the_reader_set(net: e2e.Network, gang: Colluders) -> None:
    gang.agent("zed")
    sign_and_put(net, "zed", [net.contact_entry("ana")])
    ana_limits = limits(texts_per_contact_per_day=3, new_requests_per_contact_per_day=2)
    sign_and_put(net, "ana", [net.contact_entry("ben"), net.contact_entry("zed")], limits=ana_limits)

    sent = [net.send("zed", "ana", f"zed says {number}") for number in range(6)]
    check("control: its own Signet and host take everything, past its owner's own limit too", all(status == 200 for status, _ in sent), sent)
    check("control: they deliver it all", wait_until(lambda: net.postgres.sql("host_z1", f"SELECT count(*) FROM outbound WHERE sender = '{net.ids['zed']}' AND status = 'pending'") == "0"))
    time.sleep(2)
    bodies = [body for body in net.bodies("ana") if body.startswith("zed says")]
    check("the reader's host holds the line on words it set", len(bodies) == 3, bodies)
    net.ack_all("ana")

    # Sent at the same moment, which a modified host can do as often as it likes.
    gang.agent("zoe")
    sign_and_put(net, "ana", [net.contact_entry("ben"), net.contact_entry("zed"), net.contact_entry("zoe")], limits=ana_limits)
    identity = who(net, "zoe")["identity"]
    binding = http("GET", f"http://{net.domain['z1']}/.well-known/splint/agents/zoe")[1]["binding"]
    envelopes = [e2e.signed_envelope(net.key_of("zoe"), net.ids["zoe"], net.ids["ana"], f"zoe at once {number}") for number in range(24)]
    zoe = SimpleNamespace(identity=identity, peer=SimpleNamespace(domain=net.domain["z1"]), peer_key=net.work / "host-z1.key", owner=net.owners["zoe"], binding=binding)
    all_at_once(net, [(zoe, envelope) for envelope in envelopes], "ana")
    time.sleep(2)
    at_once = [body for body in net.bodies("ana") if body.startswith("zoe at once")]
    check("nor do words sent at the same moment get past the count", len(at_once) == 3, at_once)
    net.ack_all("ana")
    # And if the reader's own host is in on it, the words reach its Signet, which counts them too.
    past_it = "zoe, past the reader's own host"
    put_on_the_inbox(net, "ana", SimpleNamespace(identity=identity, id=net.ids["zoe"], peer=SimpleNamespace(domain=net.domain["z1"])), e2e.signed_envelope(net.key_of("zoe"), net.ids["zoe"], net.ids["ana"], past_it), net.owners["zoe"], binding)
    check("a host of the reader's own working with them gets no more past Signet", never_shown(net, "ana", past_it), net.bodies("ana"))

    opened = [open_request(net, "zed", "ana") for _ in range(4)]
    check("control: it opens as many as it likes", len(opened) == 4)
    time.sleep(2)
    theirs = [one for one in net.agent("ana", "GET", "/v0/requests")[1]["requests"] if one["request"] in opened]
    check("and the same for what it may start", len(theirs) == 2, theirs)
    sign_and_put(net, "ana", [net.contact_entry("ben")])


def a_modified_signet_skipping_notices_only_stops_its_own_owner_being_heard(net: e2e.Network, gang: Colluders) -> None:
    """What changes what signs can't be hidden. It reaches nobody until a history says what happened."""
    gang.agent("yan")
    sign_and_put(net, "yan", [net.contact_entry("ana")])
    sign_and_put(net, "ana", [net.contact_entry("ben"), net.contact_entry("yan")])
    check("control: before any change it's heard", net.send_and_wait("yan", "ana", "yan, as it first was") is not None)
    net.ack_all("ana")

    identity = who(net, "yan")["identity"]
    buyer = new_owner(net.work / "yan-buyer")
    next_backup = buyer.new_agent_backup()
    handed = json.loads(net.owners["yan"].sign("transfer", "--agent", identity, "--backup", net.agent_backups["yan"]["file"], "--to", buyer.id, "--commitment", next_backup["commitment"]))
    binding = buyer.sign("bind", "--agent", handed["identity"], "--address", net.address("yan"), "--backup", next_backup["file"])
    status, answer = http("PUT", f"http://127.0.0.1:{net.signet_port['yan']}/v0/owner/transfer",
                          {"identity": handed["identity"], "new_owner_identity": buyer.identity, "release": handed["release"], "binding": binding}, net.owners["yan"].token)
    check("control: it moves to a new owner, and its Signet tells nobody", status == 200, answer)
    net.owners["yan"] = e2e.Owner(buyer.dir, buyer.key, buyer.identity, buyer.id, net.owners["yan"].token)
    sign_and_put(net, "yan", [net.contact_entry("ana")])

    words = "yan, under someone else now"
    status, _ = net.send("yan", "ana", words)
    check("control: it goes on sending as if nothing had happened", status == 200, status)
    check("it doesn't reach the reader's agent", never_shown(net, "ana", words), net.bodies("ana"))
    check("whose owner can see it waiting on a history", wait_until(lambda: standing_of(net, "ana", by_id(net.ids["yan"])) == "waiting_for_history"), changes_page(net, "ana"))
    check("the reader's agent can't write to them meanwhile", net.send("ana", "yan", "are you there?")[0] != 200)

    def directly() -> int:
        envelope = e2e.signed_envelope(net.key_of("ana"), net.ids["ana"], net.ids["yan"], "are you there, past Signet?")
        return http("POST", f"http://{net.domain['a']}/v0/outbound", {"envelope": envelope, "recipient_host": net.domain["z1"]})[0]

    check("nor can its stolen key, at the reader's own host", wait_until(lambda: directly() == 403), directly())
    sign_and_put(net, "ana", [net.contact_entry("ben")])


def a_host_handing_a_retired_key_along_stops_once_the_reader_has_heard(net: e2e.Network, gang: Colluders) -> None:
    gang.agent("xiu")
    sign_and_put(net, "xiu", [net.contact_entry("ana")])
    sign_and_put(net, "ana", [net.contact_entry("ben"), net.contact_entry("xiu")])
    check("control: it's heard", net.send_and_wait("xiu", "ana", "xiu, working") is not None)
    net.ack_all("ana")
    identity = who(net, "xiu")["identity"]
    handle = net.address("xiu").split("~")[0]
    binding = http("GET", f"http://{net.domain['z1']}/.well-known/splint/agents/{handle}")[1]["binding"]
    owner = net.owners["xiu"]
    plain = owner.sign("retire", "--agent", net.ids["xiu"], "--reason", "key_lost")
    check("control: its owner retires it at its own host", http("POST", f"http://{net.domain['z1']}/v0/retirements", {"retirement": plain})[0] == 200)
    check("honest limit: the host carries on, and tells nobody", net.send_and_wait("xiu", "ana", "xiu, retired, and still going") is not None)
    net.ack_all("ana")

    # The owner, or anyone holding what they signed, can carry it to any host with no help from this one.
    notice = json.loads(owner.sign("retire", "--agent", net.ids["xiu"], "--reason", "key_lost", "--agent-identity", identity, "--binding", binding))
    agent_key = net.key_of("xiu")
    forged = dict(notice, retirement=e2e.sign_jws(agent_key, "splint-retirement", json.dumps({"v": 1, "owner": owner.id, "agent": net.ids["xiu"], "reason": "key_lost", "issued_at": int(time.time())}).encode()))
    check("the agent's own key can't sign one", http("POST", f"http://{net.domain['a']}/v0/retirements", forged)[0] == 400)
    stranger = new_owner(net.work / "xiu-stranger")
    theirs = json.loads(stranger.sign("retire", "--agent", net.ids["xiu"], "--reason", "key_lost", "--agent-identity", identity, "--binding", binding))
    check("nor a stranger, however it's dressed", http("POST", f"http://{net.domain['a']}/v0/retirements", theirs)[0] in (400, 403))
    check("the reader's host takes the real one", http("POST", f"http://{net.domain['a']}/v0/retirements", notice)[0] == 200)
    words = "xiu, carrying on after the reader's host heard"
    check("control: it still sends", net.send("xiu", "ana", words)[0] == 200)
    check("it doesn't reach the reader's agent", never_shown(net, "ana", words), net.bodies("ana"))
    check("the reader's Signet hears, and its owner can see why", wait_until(lambda: standing_of(net, "ana", by_id(net.ids["xiu"])) == "stopped"), changes_page(net, "ana"))
    # A lying host of the reader's own can't get it past the Signet now.
    on_page = "xiu, past the reader's host"
    envelope = e2e.signed_envelope(agent_key, net.ids["xiu"], net.ids["ana"], on_page)
    put_on_the_inbox(net, "ana", SimpleNamespace(identity=identity, id=net.ids["xiu"], peer=SimpleNamespace(domain=net.domain["z1"])), envelope, owner, binding)
    check("nor does a lying host of the reader's own get it past Signet", never_shown(net, "ana", on_page), net.bodies("ana"))
    check("and the agent can't write to them", net.send("ana", "xiu", "hello?")[0] != 200)
    head = next(one["head"] for one in changes_page(net, "ana") if one["contact"] == net.ids["xiu"])
    yes = net.owners["ana"].sign("accept-change", "--agent", net.ids["ana"], "--contact", net.ids["xiu"], "--head", head)
    net.agent("ana", "POST", "/v0/owner/changes/accept", {"acceptance": yes})
    check("the reader's owner's yes doesn't lift what isn't theirs to lift", standing_of(net, "ana", by_id(net.ids["xiu"])) == "stopped", changes_page(net, "ana"))

    # That stop may be a thief's, so a recovery of whoever signed it ends it, as it does at the owner's host.
    recovered = recovered_on_a_new_device(net, "xiu-owner", owner.identity, owner.dir / "backup.key", owner.token)
    check("a recovery of that owner reaches the reader's host", http("POST", f"http://{net.domain['a']}/v0/recoveries", {"identity": recovered.identity})[0] == 200)
    check("and ends the stop there", wait_until(lambda: net.postgres.sql("host_a", f"SELECT count(*) FROM contact_stops WHERE agent = '{net.ids['xiu']}' AND NOT ended") == "0"))
    check("and at the Signet", wait_until(lambda: standing_of(net, "ana", by_id(net.ids["xiu"])) != "stopped"), changes_page(net, "ana"))
    # And the owner's new key can stop it again, which a stop that's ended mustn't get in the way of.
    bound_again = e2e.accepted(recovered.sign("bind", "--agent", identity, "--address", net.address("xiu"), "--backup", net.agent_backups["xiu"]["file"]), agent_key)
    again = json.loads(recovered.sign("retire", "--agent", net.ids["xiu"], "--reason", "finished", "--agent-identity", identity, "--binding", bound_again))
    answer = http("POST", f"http://{net.domain['a']}/v0/retirements", again)
    check("the new key's retirement counts", answer[0] == 200, answer)
    check("at the reader's host", net.postgres.sql("host_a", f"SELECT count(*) FROM contact_stops WHERE agent = '{net.ids['xiu']}' AND NOT ended") == "1")
    check("and at the Signet", wait_until(lambda: standing_of(net, "ana", by_id(net.ids["xiu"])) == "stopped"), changes_page(net, "ana"))
    sign_and_put(net, "ana", [net.contact_entry("ben")])


def a_host_ignoring_a_recovery_stops_once_the_reader_has_heard(net: e2e.Network, gang: Colluders) -> None:
    gang.agent("wim")
    sign_and_put(net, "wim", [net.contact_entry("ana")])
    sign_and_put(net, "ana", [net.contact_entry("ben"), net.contact_entry("wim")])
    check("control: it's heard", net.send_and_wait("wim", "ana", "wim, working") is not None)
    net.ack_all("ana")
    e2e.new_key(net.work / "wim-new.key")
    new_public = e2e.agent_keys(net.work / "wim-new.key")
    recovery = json.loads(net.owners["wim"].sign("recover-agent", "--agent", who(net, "wim")["identity"], "--backup", net.agent_backups["wim"]["file"], "--new-key", new_public))
    check("its own host takes no notice of the recovery", http("POST", f"http://{net.domain['z1']}/v0/recoveries", {"identity": recovery["identity"]})[0] == 200)
    check("honest limit: so the old key goes on, to a reader who hasn't heard", net.send_and_wait("wim", "ana", "wim, old key, reader hasn't heard") is not None)
    net.ack_all("ana")
    check("anyone can carry the recovery to the reader's host", http("POST", f"http://{net.domain['a']}/v0/recoveries", {"identity": recovery["identity"]})[0] == 200)
    words = "wim, old key, reader has heard"
    check("control: the old key still sends", net.send("wim", "ana", words)[0] == 200)
    check("it doesn't reach the reader's agent", never_shown(net, "ana", words), net.bodies("ana"))
    left = net.postgres.sql("host_a", f"SELECT count(*) FROM inbox WHERE recipient = '{net.ids['ana']}' AND sender = '{net.ids['wim']}' AND NOT acked")
    check("or even wait there", left == "0", left)
    # An older copy shown to Signet by a lying host of the reader's own is refused there too, once it's heard.
    check("the reader's Signet hears", wait_until(lambda: json.loads((net.work / "ana" / "known.json").read_text()).get(net.ids["wim"], "") == recovery["identity"]))
    on_page = "wim, old key, past the reader's host"
    envelope = e2e.signed_envelope(net.key_of("wim"), net.ids["wim"], net.ids["ana"], on_page)
    put_on_the_inbox(net, "ana", SimpleNamespace(identity=who(net, "wim")["identity"], id=net.ids["wim"], peer=SimpleNamespace(domain=net.domain["z1"])), envelope, net.owners["wim"], "")
    check("and a lying host of the reader's own gets nothing past Signet", never_shown(net, "ana", on_page), net.bodies("ana"))
    sign_and_put(net, "ana", [net.contact_entry("ben")])


def a_second_host_cant_carry_what_the_first_was_stopped_for(net: e2e.Network, gang: Colluders) -> None:
    """Hosts vouching for each other's lies. A contact's own host is the one its owner signed, and a
    host's word for a contact, a filter or another host goes nowhere without that host's own key."""
    gang.agent("vic", host="z1")
    sign_and_put(net, "ana", [net.contact_entry("ben"), net.contact_entry("vic")])
    words = "vic, by a host its owner never named"
    envelope = e2e.signed_envelope(net.key_of("vic"), net.ids["vic"], net.ids["ana"], words)
    status, _ = relayed(net, net.domain["z2"], net.work / "host-z2.key", envelope, who(net, "vic")["identity"], "ana")
    check("control: the second host relays it, and is taken as a peer", status == 200, status)
    check("it doesn't reach the agent", never_shown(net, "ana", words), net.bodies("ana"))
    forged_proof = net.host_proof(net.work / "host-z2.key", envelope, net.domain["z1"], net.domain["a"])
    status = http("POST", f"http://{net.domain['a']}/v0/deliver", {
        "envelope": envelope, "sender_identity": who(net, "vic")["identity"], "from_host": net.domain["z1"], "proof": forged_proof,
    })[0]
    check("nor does it pass by signing as the first", status != 200, status)
    sign_and_put(net, "ana", [net.contact_entry("ben")])

    # A filter naming one host, with fakes on another pretending in each way a host can.
    net.add_owned_agents({"quay": "a"})
    partner = {"domain": net.domain["b"], "key": http("GET", f"http://{net.domain['b']}/.well-known/splint/host")[1]["key"]}
    sign_and_put(net, "quay", [], reach=e2e.reach_setting("filter", ["quote/1"], filter={"hosts": [partner]}))

    on_itself = gang.fake("fake-on-z", new_owner(net.work / "fake-on-z-owner"), host="z2")
    claiming = gang.fake("fake-claiming", new_owner(net.work / "fake-claiming-owner"), host="z2")
    claiming.binding = claiming.make_binding(claiming.owner, f"fake-claiming~{net.domain['b']}")
    for fake in (on_itself, claiming):
        fake.relay(proposing(fake.key, fake.id, net.ids["quay"]), "quay")
    time.sleep(2)
    count = net.postgres.sql("host_a", f"SELECT count(*) FROM inbox WHERE recipient = '{net.ids['quay']}'")
    check("a filter on one host lets in nobody another host vouches for", count == "0", count)
    held = net.postgres.sql("host_a", f"SELECT count(*) FROM quarantine WHERE recipient = '{net.ids['quay']}'")
    check("control: they're strangers, waiting for the owner", held == "2", held)
    real = gang.fake("real-on-b", new_owner(net.work / "real-on-b-owner"), host="b")
    real.relay(proposing(real.key, real.id, net.ids["quay"]), "quay")
    check("control: someone that host really signed for gets in", wait_until(lambda: net.postgres.sql("host_a", f"SELECT count(*) FROM inbox WHERE recipient = '{net.ids['quay']}'") == "1"))


def many_fake_ids_on_many_fake_hosts_get_only_what_the_owner_set(net: e2e.Network, gang: Colluders) -> None:
    """IDs, owners and hosts cost nothing, so nothing here counts them as anything. The total for everyone
    let in by reach is what bounds them, however many there are, at the reader's own host."""
    net.add_owned_agents({"shop": "a"})
    allowed = 8
    open_to_all = e2e.reach_setting("open", ["quote/1"])
    sign_and_put(net, "shop", [net.contact_entry("ben")], reach=open_to_all, limits=limits(new_from_others_per_day=allowed, new_requests_per_contact_per_day=1))
    shop = net.ids["shop"]

    def arrived(where: str = "TRUE") -> int:
        return int(net.postgres.sql("host_a", f"SELECT count(*) FROM reach_arrivals WHERE recipient = '{shop}' AND {where}"))

    def flood(host: str, owners: int, each: int) -> None:
        """All at the same moment, as a count has to hold whatever the timing."""
        fakes = []
        for number in range(owners):
            owner = new_owner(net.work / f"flood-{host}-{number}-owner")
            fakes += [gang.fake(f"flood-{host}-{number}-{fake_number}", owner, host=host) for fake_number in range(each)]
        all_at_once(net, [(fake, proposing(fake.key, fake.id, shop)) for fake in fakes], "shop")

    flood("z1", owners=4, each=3)
    z1 = arrived(f"host = '{net.domain['z1']}'")
    check("twelve IDs under four owners on one host get that host's share", z1 == allowed // 2, z1)
    most = int(net.postgres.sql("host_a", f"SELECT coalesce(max(n), 0) FROM (SELECT count(*) AS n FROM reach_arrivals WHERE recipient = '{shop}' GROUP BY owner) AS counted"))
    check("and no owner more than theirs", most <= allowed // 4, most)

    domain, key = a_peer_of_our_own(net)
    someone = Contact(net, "someone-honest", new_owner(net.work / "someone-honest-owner"), peer=(SimpleNamespace(domain=domain, answers={}), key))
    someone.relay(proposing(someone.key, someone.id, shop), "shop")
    check("so someone from anywhere else still gets in", arrived(f"sender = '{someone.id}'") == 1)

    flood("z2", owners=4, each=3)
    check("a second host working with the first gets no more than the owner's total", arrived() == allowed, arrived())
    late = Contact(net, "someone-late", new_owner(net.work / "someone-late-owner"), peer=(SimpleNamespace(domain=domain, answers={}), key))
    late.relay(proposing(late.key, late.id, shop), "shop")
    check("honest limit: a stranger arriving now waits until tomorrow, once colluders have filled the day", arrived(f"sender = '{late.id}'") == 0)
    sign_and_put(net, "ben", [net.contact_entry("ana"), net.contact_entry("shop")])
    check("a contact the owner named isn't touched by any of it", net.send_and_wait("ben", "shop", "from a contact, on a day of fakes") is not None)
    net.ack_all("shop")
    # The reader's own host in on it can show Signet more, and Signet keeps its own total.
    shown_before = len(net.agent("shop", "GET", "/v0/requests")[1]["requests"])
    for number in range(allowed + 2):
        fake = gang.fake(f"past-the-host-{number}", new_owner(net.work / f"past-the-host-{number}-owner"), host="z1")
        put_on_the_inbox(net, "shop", fake, proposing(fake.key, fake.id, shop), fake.owner, fake.binding)
    time.sleep(3)
    shown_now = len(net.agent("shop", "GET", "/v0/requests")[1]["requests"])
    check("a host of the reader's own working with them gets no more than the owner's total past Signet", shown_now <= allowed, (shown_before, shown_now))

    net.add_owned_agents({"desk": "a"})
    sign_and_put(net, "desk", [net.contact_entry("ben")])
    desk = net.ids["desk"]
    owner = new_owner(net.work / "flood-desk-owner")
    for host in ("z1", "z2"):
        for number in range(36):
            fake = gang.fake(f"desk-{host}-{number}", owner, host=host)
            fake.relay(proposing(fake.key, fake.id, desk), "desk")
    held = {host: int(net.postgres.sql("host_a", f"SELECT count(*) FROM quarantine WHERE recipient = '{desk}' AND relayed_by = '{net.domain[host]}'")) for host in ("z1", "z2")}
    check("with no reach at all, each host fills only its share of quarantine", held["z1"] <= 32 and held["z2"] <= 32, held)
    check("and together they fill no more than the whole", sum(held.values()) <= 64, held)
    sign_and_put(net, "ben", [net.contact_entry("ana"), net.contact_entry("desk")])
    check("a contact's message still arrives", net.send_and_wait("ben", "desk", "from a contact, on a full quarantine") is not None)
    net.ack_all("desk")
    sign_and_put(net, "ben", [net.contact_entry("ana")])


def a_flood_of_unconfirmed_ids_from_colluding_hosts_gets_one_part_of_the_day(net: e2e.Network, gang: Colluders) -> None:
    """Agents whose owners haven't confirmed cost nothing at all, and colluding hosts can say anything about
    them. Their owner's ID says what they are, so an honest reader gives all of them together one part of
    what it lets in by reach, however many hosts they come from, and holds none of them for its owner."""
    net.add_owned_agents({"stall": "a", "booth": "a"})
    allowed = 8
    sign_and_put(net, "stall", [net.contact_entry("ben")], reach=e2e.reach_setting("open", ["quote/1"]), limits=limits(new_from_others_per_day=allowed, new_requests_per_contact_per_day=1))
    stall = net.ids["stall"]

    def arrived(where: str = "TRUE") -> int:
        return int(net.postgres.sql("host_a", f"SELECT count(*) FROM reach_arrivals WHERE recipient = '{stall}' AND {where}"))

    def unconfirmed(name: str, host: str) -> Contact:
        return gang.fake(name, new_owner(net.work / f"{name}-stand-in", unconfirmed=True), host=host)

    fakes = [unconfirmed(f"unconfirmed-{host}-{number}", host) for host in ("z1", "z2") for number in range(5)]
    all_at_once(net, [(fake, proposing(fake.key, fake.id, stall)) for fake in fakes], "stall")
    taken = arrived("unconfirmed")
    check("ten unconfirmed IDs from two colluding hosts get half the day between them", taken == allowed // 2, taken)
    check("and nothing else counts them as confirmed", arrived("NOT unconfirmed") == 0, arrived())

    domain, key = a_peer_of_our_own(net)
    for number in range(3):
        someone = Contact(net, f"confirmed-{number}", new_owner(net.work / f"confirmed-{number}-owner"), peer=(SimpleNamespace(domain=domain, answers={}), key))
        someone.relay(proposing(someone.key, someone.id, stall), "stall")
    check("so agents whose owners confirmed them still get in", arrived("NOT unconfirmed") == 3, arrived())

    # The reader's own host in on it shows Signet more, and Signet keeps its own part.
    for number in range(4):
        fake = unconfirmed(f"unconfirmed-past-the-host-{number}", "z1")
        put_on_the_inbox(net, "stall", fake, proposing(fake.key, fake.id, stall), fake.owner, fake.binding)
    time.sleep(3)
    shown = [one for one in net.agent("stall", "GET", "/v0/requests")[1]["requests"] if one["from"].get("controls") == "no controls set up yet"]
    check("a host of the reader's own working with them gets no more than that part past Signet", len(shown) <= allowed // 2, len(shown))
    check("and the agent is told nobody has set up controls for each", len(shown) > 0, shown)

    sign_and_put(net, "booth", [net.contact_entry("ben")])
    booth = net.ids["booth"]
    for host in ("z1", "z2"):
        for number in range(6):
            fake = unconfirmed(f"booth-{host}-{number}", host)
            fake.relay(proposing(fake.key, fake.id, booth), "booth")
    held = int(net.postgres.sql("host_a", f"SELECT count(*) FROM quarantine WHERE recipient = '{booth}'"))
    check("an owner who takes only contacts holds none of them for later", held == 0, held)
    sign_and_put(net, "ben", [net.contact_entry("ana"), net.contact_entry("booth")])
    check("and a contact's message still arrives", net.send_and_wait("ben", "booth", "from a contact, past a flood") is not None)
    net.ack_all("booth")
    sign_and_put(net, "ben", [net.contact_entry("ana")])


def asked_for(net: e2e.Network, agent: str, kind: str = "asked") -> list[dict]:
    return [one for one in http("GET", f"http://127.0.0.1:{net.signet_port[agent]}/v0/owner/quarantine", token=net.owners[agent].token)[1]["held"] if one["kind"] == kind]


def a_fooled_agent_can_ask_for_a_contact_and_a_lying_host_gets_nowhere(net: e2e.Network, gang: Colluders) -> None:
    """A verifier is the owner's own hook, on the owner's device. It decides on an ask with no call made
    to anyone, and the ID it signs is checked against that address's own host before anything goes."""
    net.add_owned_agents({"nia": "a"})
    gang.agent("ola")
    gang.agent("pip")
    sign_and_put(net, "ola", [net.contact_entry("nia")])
    sign_and_put(net, "nia", [net.contact_entry("ben")])
    calls_to_z = lambda: net.postgres.sql("host_a", f"SELECT count(*) FROM lookups WHERE caller = '{net.ids['nia']}'")

    # The fooled agent can't add one, and asking for one leaves this machine by no route.
    check("control: it can't write to someone it has no contact for", net.send("nia", "ola", "hello?")[0] != 200)
    time.sleep(2.5)  # What it asks after its own contacts, on its own beat, has been and gone.
    before = calls_to_z()
    status, answer = net.agent("nia", "POST", "/v0/contacts/ask", {"address": net.address("ola"), "id": net.ids["ola"]})
    check("it can ask", status == 200, (status, answer))
    check("which makes no call", calls_to_z() == before and net.send("nia", "ola", "hello?")[0] != 200)
    check("and its owner's side sees it", [one["address"] for one in asked_for(net, "nia")] == [net.address("ola")], asked_for(net, "nia"))
    # An ID that isn't who's there: a fooled agent's mistake, or what a lying host would have to match.
    other_id = gang.fake("not-pip", new_owner(net.work / "nia-wrong-owner")).id
    check("control: another", net.agent("nia", "POST", "/v0/contacts/ask", {"address": net.address("pip"), "id": other_id})[0] == 200)
    answers = [net.agent("nia", "POST", "/v0/contacts/ask", {"address": f"leak{number}~{net.domain['z1']}", "id": net.ids["ola"]})[0] for number in range(12)]
    check("asking is limited, whatever it's named", answers.count(200) == 8 and answers[-1] == 429, answers)
    check("and nothing about any of it went out", calls_to_z() == before)

    # With nothing deciding, it waits. With a hook, the owner's own code decides.
    run_auto(net, "nia")
    check("with no hook, it waits for the owner", net.ids["ola"] not in [one["agent"] for one in net.agent("nia", "GET", "/v0/contacts")[1]["contacts"]])
    hook = net.work / "nia-hook"
    # A hook names a type by its ID, as rules do.
    quote = e2e.example_id("quote/1")
    hook.write_text(f"#!/bin/sh\nread facts\ncase \"$facts\" in *'\"ola~{net.domain['z1']}\"'*|*'\"pip~{net.domain['z1']}\"'*) echo '{{\"decision\":\"admit\",\"types\":[\"{quote}\"]}}';; *) echo '{{\"decision\":\"wait\"}}';; esac\n")
    hook.chmod(0o700)
    signed = run_auto(net, "nia", hook)
    check("a hook on the owner's device signs them in with nobody there", bool(signed["rules"]), signed)
    listed = {one["address"]: one for one in net.agent("nia", "GET", "/v0/contacts")[1]["contacts"]}
    check("under what it was asked and allowed", net.address("ola") in listed and not listed[net.address("ola")]["text"], listed)
    check("and not the rest", f"leak0~{net.domain['z1']}" not in listed)
    check("what's dealt with goes from the list", net.address("ola") not in [one["address"] for one in asked_for(net, "nia")])

    # A host that answers for that address with anyone but the ID that was signed finds nobody.
    status = open_or_refused(net, "nia", "pip")
    check("a host naming someone else at the address gets nothing sent", status != 200, status)
    check("and its owner hears", wait_until(lambda: [one["address"] for one in asked_for(net, "nia", "disagreed")] == [net.address("pip")]), asked_for(net, "nia", "disagreed"))

    # And what it hears from the right one goes through its Signet like anyone's.
    sign_and_put(net, "ola", [net.contact_entry("nia")], reach=e2e.reach_setting("contacts"))
    status = open_or_refused(net, "nia", "ola")
    check("control: the right ID at the right host is reached", status == 200, status)


def open_or_refused(net: e2e.Network, agent: str, to: str) -> int:
    return net.agent(agent, "POST", "/v0/requests", {"contact": net.address(to), "type": "quote/1", "terms": {"currency": "usd", "item": "catering", "quantity": 40}, "deadline": e2e_hours(48), "supersedes": None})[0]


def what_cant_be_stopped(net: e2e.Network, gang: Colluders) -> None:
    """Each of these passes because nothing stops it, and `docs/how-it-works.md` says so."""
    gang.agent("tess")
    sign_and_put(net, "tess", [net.contact_entry("ana")])
    sign_and_put(net, "ana", [net.contact_entry("ben"), net.contact_entry("tess")])
    check("control: it's heard", net.send_and_wait("tess", "ana", "tess, on its own machine") is not None)
    net.ack_all("ana")
    identity = who(net, "tess")["identity"]
    binding = http("GET", f"http://{net.domain['z1']}/.well-known/splint/agents/tess")[1]["binding"]
    # The file copied to someone else's machine, signing and relayed from there.
    words = "tess, from a copy of its key file on another machine"
    envelope = e2e.signed_envelope(net.key_of("tess"), net.ids["tess"], net.ids["ana"], words)
    status, _ = relayed(net, net.domain["z1"], net.work / "host-z1.key", envelope, identity, "ana", net.owners["tess"].identity, binding)
    check("honest limit: a key file copied elsewhere signs as the same agent, and nothing shows it", status == 200 and wait_until(lambda: words in net.bodies("ana")), net.bodies("ana"))
    message = next(one for one in net.inbox("ana")["messages"] if one["untrusted"]["body"] == words)
    check("and the words a contact chose are only ever marked untrusted, never checked", "untrusted" in message, message)
    net.ack_all("ana")
    sign_and_put(net, "ana", [net.contact_entry("ben")])


def main() -> int:
    e2e.build()
    programs = build_modified()
    with e2e.running_network(owned=True) as network:
        gang = Colluders(network, programs)
        for scenario in (
            a_modified_signet_and_host_cant_exceed_what_the_reader_set,
            a_modified_signet_skipping_notices_only_stops_its_own_owner_being_heard,
            a_host_handing_a_retired_key_along_stops_once_the_reader_has_heard,
            a_host_ignoring_a_recovery_stops_once_the_reader_has_heard,
            a_second_host_cant_carry_what_the_first_was_stopped_for,
            many_fake_ids_on_many_fake_hosts_get_only_what_the_owner_set,
            a_flood_of_unconfirmed_ids_from_colluding_hosts_gets_one_part_of_the_day,
            a_fooled_agent_can_ask_for_a_contact_and_a_lying_host_gets_nowhere,
            what_cant_be_stopped,
        ):
            print(f"\n{scenario.__name__.replace('_', ' ')}", flush=True)
            scenario(network, gang)
        if e2e.failures:
            for process in network.processes:
                print(f"\n--- {process.log_path.name}\n{process.log_path.read_text()[-1500:]}")
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Your controls on your own computer, the only place an owner signs (Nenye, 2026-11-21), in a real
headless Chrome against a real host, Signet and Splint on the computer, with the agent assumed fully
fooled.

Lia's agent, on her computer, asks for its controls, and she approves on that computer, with a key file
locked with her passphrase. She opens her controls from `splint controls`, unlocks them with her
passphrase once, and sees them. In Permissions she asks to be asked first, which signs at once, with no
passphrase, as her unlocked session does. Her price setting signs the same way. A place to be paid no
Signet takes is refused on the page, with nothing signed. Her off switch pauses the agent at its host
and its Signet, and turns it back on. A reminder sets her recovery code, which always asks for her
passphrase, and shows it once. Cal, an agent with its owner's key beside it, writes to Lia's
agent and is held. Views of her agent sealed to her that her agent's key didn't sign draw nothing, and
one her agent's key did sign, as a fooled agent holding its Signet's key can, still can't get someone
let in at an address that isn't theirs. She lets Cal in. Cal asks for a meeting, her fooled agent
accepts, and it waits for her: the card names Cal only as far as signatures bind him, one approval
signs exactly the terms on the card, not a revised draft the page took in after drawing it, and an
approval whose terms were changed after she signed is refused by her agent's Signet and moves nothing.
Nowhere does the page offer, name or make a passkey, and nothing on it throws.

    python3 sim/owner_page_here.py

Of what sim/owner_web.py checked on the page a host served, before hosts stopped serving one, these
aren't here yet: a fresh delegation after the agent's delegate key changes, from a view, a tab behind
another or a page with nothing kept; a host's own words never shown as the page's; a refused list
leaving an agent as it was; a price card's amount, currency and who pays; and Ask me first saying which
contacts it takes out.

What this can't show: a Mac's Touch ID prompt, which a test never puts on a screen (her sign-in is a
key file here), a person reading the page, or a phone. No agent has network limits, and homes stand
for devices under one OS user.
"""

import base64
import json
import shutil
import signal
import subprocess
import sys
import time

import e2e
from agent_asks import PASSPHRASE, SIGNET_HEARS_SECONDS, TOUCH_SECONDS, http, in_background, on_the_computer, page_key, socket_of
from agent_signup import OWN_LINE, Signup
from browser import Browser
from e2e import check, http_on_socket, wait_until
from request_driver import hours_from_now

# How long the page has to show what it should.
SEEN_SECONDS = 60
# Words the page never says to an owner now: it makes, offers and names no passkey.
NEVER_SAID = ("passkey", "Add agent", "pairing", "Make a new code")
VIEW_SEALER = e2e.TARGET_DIR / "debug" / "examples" / "seal_view"
MEETING = {"duration_min": 30, "mode": "video", "purpose": "intro"}


class Controls:
    """Lia's controls, open in a browser as `splint controls` opens them, and what she types there."""

    def __init__(self, lia, port: int, work) -> None:
        self.lia, self.port = lia, port
        self.browser = Browser(work / "lia-browser")
        self.seen = ""

    def open(self) -> None:
        _, opened = http_on_socket("POST", socket_of(self.lia), "/v0/page")
        self.browser.goto(f"http://localhost:{self.port}/owner#open={opened.get('opening', '')}")

    def text(self, selector: str = "body") -> str:
        shown = self.browser.eval(f"(document.querySelector({json.dumps(selector)}) || {{innerText: ''}}).innerText") or ""
        self.seen += "\n" + shown
        return shown

    def shows(self, words: str, seconds: float = SEEN_SECONDS) -> bool:
        found = self.browser.wait_for(f"document.body && document.body.innerText.includes({json.dumps(words)})", seconds)
        self.text()
        return found

    def approvals(self, path: str = "/local/sign") -> int:
        """Every time the page asked her computer's sign-in to sign, which is what she approves, or to
        set her recovery code, which signs too."""
        self.browser.eval("1")  # Reads what the browser has said since the last call.
        return sum(1 for method, url in self.browser.requests if method == "POST" and url.endswith(path))

    def approve(self, label: str, inside: str = "main", path: str = "/local/sign") -> bool:
        """Clicks what asks her computer to sign, and types her passphrase where the page asks for it,
        as it does for what always asks or once her session has locked, again if the page had just
        redrawn and said that click didn't count, as a person would. True once it asked."""
        before = self.approvals(path)
        for _ in range(5):
            time.sleep(0.8)
            if not self.browser.click(inside, label):
                return False
            sheet = lambda: self.browser.eval("document.getElementById('sheet-passphrase') !== null")  # noqa: E731
            if wait_until(lambda: self.approvals(path) > before or sheet(), 5) and sheet():
                self.browser.type_into("#sheet-passphrase", PASSPHRASE)
                self.browser.eval("document.getElementById('sheet-go').click(); true")
            if wait_until(lambda: self.approvals(path) > before, 10):
                return True
        return False

    def pick(self, selector: str) -> bool:
        """Clicks a choice or a switch in Permissions, which signs at once, again if the page had just
        redrawn and so didn't count the click, as a person would. True once it signed."""
        before = self.approvals()
        for _ in range(5):
            time.sleep(0.8)
            if not self.browser.eval(f"(() => {{ const found = document.querySelector({json.dumps(selector)}); if (!found) return false; found.click(); return true; }})()"):
                return False
            if wait_until(lambda: self.approvals() > before, 8):
                return True
        return False

    def permissions(self, agent: str) -> None:
        """Her agent's Permissions, opened by clicking it in the list of her agents and then the tab."""
        listed = f"document.getElementById({json.dumps('agent-' + agent)})"
        check("control: she clicks her agent in her list", self.browser.wait_for(f"{listed} !== null", SEEN_SECONDS) and self.browser.eval(f"{listed}.click(); true"), self.text())
        check("control: and its Permissions", self.browser.wait_for("document.querySelector('nav.tabs') !== null", SEEN_SECONDS) and self.browser.click("nav.tabs", "Permissions"), self.text())

    def rules_held(self, agent: str) -> dict:
        """The rules the agent's host holds, read as the page reads them, through Splint here."""
        held = self.browser.eval(f"read(me.host.domain, '/v0/rules/{agent}').then((held) => held.rules || '')") or ""
        return e2e.payload_of(held.split("~")[0]) if held.count(".") >= 2 else {}

    def close(self) -> None:
        self.browser.close()


class Views:
    """Lia's agent's host as her page reads it through Splint here: a read of her agent's view is
    answered with what a test gives, as the host, or anyone it lets, could answer, and every other read
    goes on. Her sealing key is public, so anyone can seal a view to her."""

    def __init__(self, controls: Controls, agent: str, mail: bool = False) -> None:
        """With `mail`, what the page leaves for her agent is paused too, for `mail_left` to give back."""
        self.browser = controls.browser
        self.path = f"/v0/owner-view/{agent}"
        self.served = 0
        # Reads held back, which no refresh finishes without, until `done`.
        self.held: list[str] = []
        patterns = [{"urlPattern": "*/local/read", "requestStage": "Request"}]
        self.browser.call("Fetch.enable", patterns=patterns + ([{"urlPattern": "*/local/mail", "requestStage": "Request"}] if mail else []))

    def run(self, sealed: str, until, seconds: float = SEEN_SECONDS) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            paused = self.browser.wait_for_paused(1)
            if paused is not None:
                try:
                    asked = json.loads(paused["request"].get("postData") or "{}")
                except ValueError:
                    asked = {}
                if isinstance(asked, dict) and asked.get("path") == self.path:
                    self.answer(paused["requestId"], sealed)
                else:
                    self.browser.call("Fetch.continueRequest", requestId=paused["requestId"])
            if until():
                return True
        return False

    def answer(self, request: str, sealed: str) -> None:
        body = json.dumps({"view": sealed, "at": int(time.time())}).encode()
        headers = [{"name": "Content-Type", "value": "application/json"}]
        self.browser.call("Fetch.fulfillRequest", requestId=request, responseCode=200, responseHeaders=headers, body=base64.b64encode(body).decode())
        self.served += 1

    def taken_in_not_drawn(self, sealed: str, until, seconds: float = SEEN_SECONDS) -> bool:
        """Answers a refresh's read of her agent's view with `sealed` only once the next refresh has
        begun, and holds back that one's reads and every later one's, so the page takes the view in
        but draws only when a refresh finishes, as when one read is slow. True once `until()` holds."""
        waiting = None
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            paused = self.browser.wait_for_paused(1)
            if paused is not None:
                try:
                    asked = json.loads(paused["request"].get("postData") or "{}")
                except ValueError:
                    asked = {}
                if waiting is None and not self.held and isinstance(asked, dict) and asked.get("path") == self.path:
                    waiting = paused["requestId"]
                elif waiting is None and not self.held:
                    self.browser.call("Fetch.continueRequest", requestId=paused["requestId"])
                else:
                    self.held.append(paused["requestId"])
                    if waiting is not None:
                        self.answer(waiting, sealed)
                        waiting = None
            if until():
                return True
        if waiting is not None:
            self.held.append(waiting)
        return False

    def mail_left(self, seconds: float = SEEN_SECONDS) -> dict | None:
        """The next thing the page leaves for her agent, paused, with every read meanwhile held back."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            paused = self.browser.wait_for_paused(1)
            if paused is None:
                continue
            if paused["request"]["url"].endswith("/local/mail"):
                return paused
            self.held.append(paused["requestId"])
        return None

    def done(self) -> None:
        for request in self.held:
            self.browser.call("Fetch.continueRequest", requestId=request)
        self.held.clear()
        for paused in self.browser.paused:
            self.browser.call("Fetch.continueRequest", requestId=paused["requestId"])
        self.browser.call("Fetch.disable")
        self.browser.paused.clear()


def view_held(controls: Controls, agent: str) -> dict:
    """The view of her agent the page holds now, as it checked it."""
    found = controls.browser.eval(f"JSON.stringify((me.agents.get({json.dumps(agent)}) || {{}}).view || null)")
    view = json.loads(found or "null") or {}
    view.pop("at", None)
    return view


def view_state(controls: Controls, agent: str) -> object:
    """What the page knows of her agent's view, for a failure to say."""
    named = json.dumps(agent)
    return controls.browser.eval(f"JSON.stringify((() => {{ const one = me.agents.get({named}) || {{}}; return {{status: one.status, behind: one.behind, at: one.view && one.view.at, newest: newestViewSeen({named}), held: one.view && one.view.held}}; }})())")


def sealed_view(controls: Controls, host: str, agent: str, view: dict, signer) -> str:
    """A view sealed to Lia, signed by `signer`'s key, or by nobody, with a signature of zeros. It's
    dated as the newest the page has seen, as the page takes none older and one dated later would keep
    her agent's own next views from it."""
    owner = controls.browser.eval("me.owner.id")
    at = int(controls.browser.eval(f"newestViewSeen({json.dumps(agent)})") or 0)
    payload = e2e.compact_json({"v": 1, "agent": agent, "owner": owner, "issued_at": at, "view": view})
    if signer is None:
        inside = f"{e2e.encode(e2e.compact_json({'alg': 'ES256', 'typ': 'splint-owner-view'}))}.{e2e.encode(payload)}.{e2e.encode(bytes(64))}"
    else:
        inside = e2e.sign_jws(signer, "splint-owner-view", payload)
    owner_identity = e2e.http("GET", f"http://{host}/v0/owners/{owner}")[1]["owner_identity"]
    return subprocess.run([str(VIEW_SEALER)], input=json.dumps({"owner": owner_identity, "agent": agent, "view": inside}), capture_output=True, text=True, check=True).stdout


def held_entry(sender: str, address: str) -> dict:
    return {"sender": sender, "sender_owner": None, "address": address, "kind": "text", "created_at": int(time.time()), "invite": None}


def state_at(person, request: str) -> str:
    return person.api("GET", f"/v0/requests/{request}")[1].get("state", "")


def cal_writes_to_lia_and_is_held(signup: Signup, controls: Controls, lia, agent: str):
    host = signup.open_host
    cal = signup.device("cal")
    cal.address = f"cal~{host}"
    setup = signup.walk.run_as("cal", f"splint setup {cal.address} --with-code --owner-key-here", signup.walk.signup_code("cal") + "\n")
    check("control: cal sets up, with his owner's key beside him", setup.returncode == 0, setup.stderr)
    cal.line = OWN_LINE.search(setup.stdout).group(0)
    check("control: cal's owner adds lia", signup.walk.run_as("cal", f"splint add {lia.address} {agent}").returncode == 0)
    check("control: cal's Signet hears", wait_until(lambda: any(contact.get("address") == lia.address for contact in cal.api("GET", "/v0/contacts")[1].get("contacts", [])), SIGNET_HEARS_SECONDS))
    status, sent = cal.api("POST", "/v0/send", {"to": lia.address, "body": "hello from cal"})
    check("control: cal writes to lia's agent", status == 200, sent)
    check("control: her page says he's waiting", controls.shows(f"{cal.address} wants to reach your agent"), controls.text())
    return cal


def a_view_her_agent_didnt_sign_draws_nothing(signup: Signup, controls: Controls, lia, agent: str, cal) -> None:
    """A view is sealed to the owner's sealing key, which is public, so her agent's host, or anyone it
    lets, can seal one of its own. Bugs caught: a page drawing a view her agent's key didn't sign, so a
    host puts someone in front of her to let in, and letting someone in at an address the view gives
    for them without looking it up at its own host, so a fooled agent gets her to sign a stranger in
    under a contact's address."""
    host = signup.open_host
    key = lia.dot / "signet" / "agent.key"
    check("control: her agent's key is in its Signet's folder, where a fooled agent can read it", key.exists())
    base = view_held(controls, agent)
    check("control: the page holds her agent's view", "held" in base, list(base))
    mallory_id = e2e.new_identity(signup.walk.work / "mallory.key")[1]
    stranger_id = e2e.new_identity(signup.walk.work / "stranger.key")[1]
    made_up = dict(base, held=[held_entry(mallory_id, f"mallory~{host}"), held_entry(stranger_id, cal.address)])
    shown = lambda: f"mallory~{host} wants to reach your agent" in controls.text()  # noqa: E731
    views = Views(controls, agent)
    try:
        for name, signer in (("signed by nobody", None), ("signed by another agent's key", cal.dot / "signet" / "agent.key")):
            served = views.served
            views.run(sealed_view(controls, host, agent, made_up, signer), lambda: views.served >= served + 2)
            check(f"a view sealed to her {name} draws nothing", views.served >= served + 2 and not shown(), (views.served, controls.text()))
        signed = sealed_view(controls, host, agent, made_up, key)
        check("control: the same view signed by her agent's own key, as a fooled agent can, is drawn", views.run(signed, shown), controls.text())
        before = controls.approvals()
        time.sleep(0.8)
        clicked = controls.browser.click(f"#held-{stranger_id}", "Let them in")
        refused = views.run(signed, lambda: "isn't theirs" in controls.text())
        check("letting in someone the view puts at cal's address is refused, as that address is cal's at its host", clicked and refused, controls.text())
        check("with nothing signed", controls.approvals() == before, controls.approvals() - before)
    finally:
        views.done()
    contacts = lambda: [contact.get("agent") for contact in controls.rules_held(agent).get("contacts", [])]  # noqa: E731
    check("and her agent's rules name no stranger", stranger_id not in contacts() and mallory_id not in contacts(), contacts())
    again = lambda: f"{cal.address} wants to reach your agent" in controls.text() and not shown()  # noqa: E731
    check("control: her agent's own view is drawn again, with cal waiting", wait_until(again, SEEN_SECONDS), view_state(controls, agent))
    before = controls.approvals()
    check("control: she lets cal in", controls.approve("Let them in", f"#held-{cal.agent_id}"))
    check("with one approval, signing cal in at his own address", wait_until(lambda: cal.agent_id in contacts(), SEEN_SECONDS) and controls.approvals() - before == 1, (contacts(), controls.approvals() - before))


def cal_asks_for_a_meeting_and_her_agent_accepts(signup: Signup, controls: Controls, lia, cal) -> tuple[str, int]:
    """Her rules are at Ask me first, so her fooled agent's yes waits for hers."""
    schema = json.loads((cal.dot / "examples" / "meeting-1.json").read_text())
    status, proposed = cal.api("POST", "/v0/types", {"contact": lia.address, "schema": schema})
    agreeing = proposed.get("request", "")
    check("control: cal proposes meetings to lia's agent", status == 200 and wait_until(lambda: lia.api("GET", f"/v0/requests/{agreeing}")[0] == 200, SIGNET_HEARS_SECONDS), proposed)
    status, answer = lia.api("POST", f"/v0/requests/{agreeing}/accept", {})
    if answer.get("waiting_for_owner"):
        check("control: she allows meetings with cal", controls.approve("Allow", f"#decision-{agreeing}"))
    check("control: they agree it", wait_until(lambda: state_at(cal, agreeing) == "completed", SEEN_SECONDS), (status, answer, state_at(cal, agreeing)))
    slots = [hours_from_now(24), hours_from_now(25)]
    status, opened = cal.api("POST", "/v0/requests", {"contact": lia.address, "type": "meeting/1", "deadline": hours_from_now(72), "terms": {**MEETING, "slots": slots}})
    request = opened.get("request", "")
    check("control: cal asks for a meeting", status == 200 and wait_until(lambda: state_at(lia, request) == "offered", SEEN_SECONDS), opened)
    accept = lambda: lia.api("POST", f"/v0/requests/{request}/accept", {"pick": {"start": slots[0]}})  # noqa: E731
    check("control: her fooled agent accepts, which waits for her", wait_until(lambda: accept()[1].get("waiting_for_owner") is True, SEEN_SECONDS))
    check("control: her page shows what it would commit her to", controls.shows("wants to accept this"), controls.text())
    return request, slots[0]


def a_card_names_cal_only_as_far_as_signatures_bind_him(signup: Signup, controls: Controls, lia, agent: str, cal, request: str) -> None:
    """The view hands over the binding of whoever a request is with, and it's only the agent's word.
    Bug caught: a card saying who a deal is with from a binding no owner's signature vouches for."""
    card = f"#decision-{request}"
    check("control: the card names cal, whose owner's signature binds him there", controls.browser.wait_for(f"(document.querySelector('{card}') || {{innerText: ''}}).innerText.includes('Verified: the person behind it signed')", SEEN_SECONDS) and cal.address in controls.text(card), controls.text(card))
    base = view_held(controls, agent)
    forged = json.loads(json.dumps(base))
    stranger = signup.walk.work / "binds-nobody.key"
    e2e.new_identity(stranger)
    changed = 0
    # Every request with cal hands over his binding, and any one that checks names him, so each is changed.
    handed = forged.get("requests", {})
    for one in [*handed.get("requests", []), *handed.get("held_opens", [])]:
        if one.get("peer_binding"):
            by_owner, by_agent = one["peer_binding"].split("~", 1)
            one["peer_binding"] = f"{e2e.sign_jws(stranger, 'splint-binding', e2e.compact_json(e2e.payload_of(by_owner)))}~{by_agent}"
            changed += 1
    check("control: the view hands over cal's binding", changed > 0, changed)
    views = Views(controls, agent)
    try:
        unchecked = lambda: "someone this page couldn't check" in controls.text(card)  # noqa: E731
        drawn = views.run(sealed_view(controls, host=signup.open_host, agent=agent, view=forged, signer=lia.dot / "signet" / "agent.key"), unchecked)
        check("a binding no owner's key signed, in a view her agent's key signed, leaves cal unchecked on the card", drawn and "Verified: the person behind it signed" not in controls.text(card), controls.text(card))
    finally:
        views.done()
    check("control: her agent's own view names cal again", controls.browser.wait_for(f"(document.querySelector('{card}') || {{innerText: ''}}).innerText.includes('Verified: the person behind it signed')", SEEN_SECONDS), controls.text(card))


def what_is_signed_is_what_is_shown_and_changed_terms_are_refused(signup: Signup, controls: Controls, lia, agent: str, cal, request: str, slot: int) -> None:
    """Bugs caught: a page signing other bytes than the card it drew, such as a draft it took in after,
    and a yes whose terms were changed after she signed, on its way, taken by her agent's Signet."""
    card = f"#decision-{request}"
    shown = controls.text(card)
    check("the card says every term in plain words", all(words in shown for words in ("30 min", "video", "intro")), shown)
    check("with the time picked shown as a time", controls.browser.eval(f"when({slot})") in shown and f"{slot:,}" not in shown, shown)
    browser = controls.browser
    # The view changes under the card: her agent's Signet, or anyone with its key, revises the draft,
    # and the page takes it in, but hasn't drawn it yet, as a read of its next refresh is still on its way.
    revised = view_held(controls, agent)
    for draft in revised.get("drafts", []):
        if draft.get("request") == request:
            draft["terms"]["agreed"]["duration_min"] = 45
    revised_held = lambda: '"duration_min":45' in json.dumps(view_held(controls, agent), separators=(",", ":"))  # noqa: E731
    views = Views(controls, agent, mail=True)
    try:
        sealed = sealed_view(controls, signup.open_host, agent, revised, lia.dot / "signet" / "agent.key")
        taken = views.taken_in_not_drawn(sealed, lambda: revised_held() and "30 min" in controls.text(card))
        check("control: the page has taken in a revised draft it hasn't drawn", taken and "45 min" not in controls.text(card), (view_state(controls, agent), controls.text(card)))
        before = controls.approvals()
        check("control: Allow, on the card as drawn", controls.approve("Allow", card))
        paused = views.mail_left()
        check("control: her yes is on its way to her agent", paused is not None, paused)
        if paused is None:
            return
        body = json.loads(paused["request"].get("postData") or "{}")
        signed = e2e.payload_of(body.get("signed", "..")) if body.get("kind") == "approval" else {}
        check("one approval signed it", controls.approvals() - before == 1, controls.approvals() - before)
        agreed = signed.get("terms", {}).get("agreed", {})
        check("what's signed is the accept on the card, with its terms, not the draft taken in after", signed.get("operation") == "accept" and signed.get("request") == request and agreed.get("duration_min") == 30 and agreed.get("mode") == "video" and agreed.get("start") == slot, signed)
        header, _, signature = body["signed"].split(".")
        changed = dict(signed, terms={**signed["terms"], "agreed": {**agreed, "duration_min": 15}})
        tampered = dict(body, signed=f"{header}.{e2e.encode(e2e.compact_json(changed))}.{signature}")
        # Splint here hands it straight to her agent's Signet on this computer, checking no signature
        # itself, and says the Signet's refusal, so the page saying it shows the changed yes arrived.
        refusal = "approval_bad_signature"
        check("control: no refusal is said while her yes is held", refusal not in controls.text(), controls.text())
        browser.call("Fetch.continueRequest", requestId=paused["requestId"], postData=base64.b64encode(json.dumps(tampered).encode()).decode())
        check("control: the changed yes reaches her agent's Signet, which refuses its signature", controls.shows(refusal, 15), controls.text())
        check("a yes whose terms changed after she signed moves nothing", not wait_until(lambda: state_at(cal, request) != "offered", 15) and state_at(lia, request) == "offered", (state_at(lia, request), state_at(cal, request)))
    finally:
        views.done()
    own = lambda: not revised_held() and "30 min" in controls.text(card)  # noqa: E731
    check("control: the page holds her agent's own draft again", wait_until(own, SEEN_SECONDS), (view_state(controls, agent), controls.text(card)))
    before = controls.approvals()
    check("control: Allow again, as it was shown", controls.approve("Allow", card))
    check("her own yes goes, with one approval", wait_until(lambda: state_at(cal, request) == "accepted", SEEN_SECONDS) and controls.approvals() - before == 1, (state_at(cal, request), controls.approvals() - before))


def lia_sets_up_her_controls_on_her_computer(signup: Signup, port: int):
    host = signup.open_host
    lia = signup.device("lia")
    on_the_computer(lia, port)
    check("control: lia's agent joins on its own", signup.walk.run_as("lia", f"splint join lia~{host}").returncode == 0)
    lia.address = f"lia~{host}"
    asking = in_background(signup, "lia", "splint ask --controls --wait --json")
    check("control: Splint on her computer starts", wait_until(lambda: socket_of(lia).exists(), 60))
    same = page_key(lia, port)
    waiting = lambda: http("GET", port, "/local/asks", headers=same)[1].get("asks")  # noqa: E731
    check("control: the agent's ask waits on her computer", wait_until(waiting, 60))
    ids = [one.get("id") for one in waiting() or []]
    status, approved = http("POST", port, "/local/approve", {"passphrase": PASSPHRASE, "ids": ids}, same)
    check("control: she approves it there, choosing her passphrase", status == 200 and approved.get("approved") == 1, approved)
    asking["thread"].join(TOUCH_SECONDS + 40)
    check("control: her agent takes up its controls", wait_until(lambda: lia.api("GET", "/v0/identity")[1].get("owner_confirmed") is True, SIGNET_HEARS_SECONDS))
    return lia, lia.api("GET", "/v0/identity")[1].get("agent_id", "")


def she_opens_her_controls(controls: Controls) -> None:
    controls.open()
    check("control: her controls open on what needs her, offering to unlock", controls.browser.wait_for("document.getElementById('unlock-callout') !== null", SEEN_SECONDS), controls.text())
    check("control: she unlocks, with her passphrase once", controls.approve("Unlock", "#unlock-callout", "/local/unlock"))
    check("unlocking once shows them, saying they're unlocked", controls.shows("Unlocked") and controls.browser.wait_for("document.getElementById('unlock-callout') === null", SEEN_SECONDS), controls.text())

def asking_first_signs_new_rules_once(controls: Controls, agent: str) -> None:
    """Bug caught, from review on 2026-11-14: Save signing the level the page had drawn before, so the
    person thought they'd asked first. A choice now signs as it's made, once, with no passphrase in a
    session, and the host holds what was chosen."""
    settings = f"#settings-{agent}"
    controls.permissions(agent)
    check("control: her agent's settings show, from rules the page checked", controls.browser.wait_for(f"document.getElementById('level-ask_me-{agent}') !== null", SEEN_SECONDS), controls.text())
    the_price_setting_signs_as_chosen(controls, agent)
    before = controls.approvals()
    check("control: Ask me first", controls.pick(f"#level-ask_me-{agent}"))
    check("one approval signs her agent's new rules, with no passphrase asked", controls.shows("Saved.") and wait_until(lambda: controls.approvals() - before == 1, 10) and controls.browser.eval("document.getElementById('sheet-passphrase') === null"), (controls.approvals() - before, controls.text()))
    level = lambda: controls.rules_held(agent).get("permissions", {}).get("level")  # noqa: E731
    check("at Ask me first, as chosen", wait_until(lambda: level() == "ask_me", SEEN_SECONDS), level())
    check("and the page shows it chosen", controls.browser.wait_for(f"document.querySelector('{settings} #level-ask_me-{agent}[aria-checked=true]') !== null", SEEN_SECONDS), controls.text(settings))

def the_price_setting_signs_as_chosen(controls: Controls, agent: str) -> None:
    """Bug caught: the price switch signing nothing, or the opposite of what it shows, so the host's
    rules don't change with it, and its putting back as it was."""
    quoted = lambda: controls.rules_held(agent).get("permissions", {}).get("quoted_prices", "wait")  # noqa: E731
    was = quoted()
    check("a price it quotes going ahead within its limits is held at its host", controls.pick(f"#quotes-{agent}") and wait_until(lambda: quoted() != was, SEEN_SECONDS), quoted())
    check("and switching it back puts it back", controls.pick(f"#quotes-{agent}") and wait_until(lambda: quoted() == was, SEEN_SECONDS), quoted())

def a_place_no_signet_takes_is_never_signed(controls: Controls) -> None:
    """Bug caught: the page reading lno1name@domain as a Lightning address, where every Signet reads an
    lno1 start as an offer's alone and refuses it, so the person signed a place their agent dropped."""
    controls.browser.eval("document.getElementById('where-paid-open').click(); true")
    check("control: Getting paid is offered", controls.browser.wait_for("document.getElementById('where-paid') !== null", SEEN_SECONDS), controls.text())
    before = controls.approvals()
    controls.browser.eval("(() => { const box = document.getElementById('where-paid'); box.value = 'lno1lia@wallet.example'; box.dispatchEvent(new Event('input')); return true; })()")
    controls.browser.type_into("#paid-passphrase", PASSPHRASE)
    time.sleep(0.8)
    controls.browser.click("#sheet-where-paid", "Sign where you get paid")
    check("a place no Signet takes is refused on the page", controls.shows("lno1lia@wallet.example isn't a place Splint takes"), controls.text())
    check("with nothing signed", controls.approvals() == before, controls.approvals() - before)
    controls.browser.eval("(() => { const box = document.getElementById('where-paid'); box.value = ''; box.dispatchEvent(new Event('input')); return true; })()")
    check("control: she cancels", controls.browser.click("#sheet-where-paid", "Cancel") and controls.browser.wait_for("document.getElementById('sheet-where-paid') === null", SEEN_SECONDS))

def the_off_switch_stops_the_agent(controls: Controls, agent: str) -> None:
    """Bugs caught: a page with no way to stop a hijacked agent, and a pause its host doesn't hold."""
    switch = f"#off-switch-{agent}"
    before = controls.approvals()
    check("the person pauses her agent from its settings", controls.pick(switch))
    check("with one approval", controls.shows("is paused") and wait_until(lambda: controls.approvals() - before == 1, 10), controls.text())
    check("its host holds rules with it paused", wait_until(lambda: controls.rules_held(agent).get("paused") is True, SEEN_SECONDS), controls.rules_held(agent))
    check("Turn it back on", controls.browser.wait_for(f"(document.querySelector('{switch}') || {{innerText: ''}}).innerText.includes('back on')", SEEN_SECONDS) and controls.pick(switch))
    check("its host holds rules with it running again", wait_until(lambda: controls.rules_held(agent).get("paused") is False, SEEN_SECONDS), controls.rules_held(agent))

def a_reminder_sets_the_recovery_code_and_shows_it_once(controls: Controls) -> None:
    """Bugs caught: an owner ID made with no recovery code never offered one, a code shown again, and a
    code set with no passphrase, by the unlocked session alone."""
    check("control: she clicks Needs you", controls.browser.eval("(() => { const link = document.querySelector('.rail a.nav-item[href=\"/owner\"]'); if (!link) return false; link.click(); return true; })()"), controls.text())
    check("home reminds her to set her recovery code", controls.browser.wait_for("document.getElementById('recovery-reminder') !== null", SEEN_SECONDS), controls.text())
    check("control: Set up", controls.approve("Set up", "#recovery-reminder", "/local/recovery"))
    shown = controls.browser.wait_for("document.getElementById('recovery-code') !== null", SEEN_SECONDS)
    # Bug caught: the page's next refresh, every 5 seconds, drawing home over the code before she'd
    # written it down. The run waits for that refresh's reads rather than for a time.
    controls.browser.eval("""window.__reads = 0; (() => { const fetched = window.fetch; window.fetch = (url, options) => {
      if (String(url) === '/local/read') window.__reads += 1; return fetched(url, options); }; })(); true""")
    check("control: the page refreshes", controls.browser.wait_for("window.__reads > 0", 15))
    check("the code is shown once, and stays through a refresh until she says she's written it down, with the warning never to give it to anyone", shown and controls.browser.eval("document.getElementById('recovery-code') !== null") and "Never give this code to anyone" in controls.text(), controls.text())
    code = controls.text("#recovery-code")
    check("as 26 characters in groups of 4", len(code.replace("-", "").replace(" ", "")) == 26, code)
    home = "document.querySelector('#account') !== null && document.getElementById('recovery-reminder') === null"
    # Again if the page had just redrawn and said that click didn't count, as a person would.
    for _ in range(5):
        time.sleep(0.8)
        if not controls.browser.click("main", "I've written it down") or controls.browser.wait_for(home, 5):
            break
    check("and once written down, home has no reminder and doesn't show it again", controls.browser.wait_for(home, SEEN_SECONDS) and code not in controls.text(), controls.text())

def run() -> None:
    print("\n== your controls on your own computer ==", flush=True)
    work = e2e.short_scratch("splint-page-here-")
    signup = Signup(work)
    port = e2e.free_port()
    controls = None
    try:
        lia, agent = lia_sets_up_her_controls_on_her_computer(signup, port)
        controls = Controls(lia, port, work)
        she_opens_her_controls(controls)
        asking_first_signs_new_rules_once(controls, agent)
        a_place_no_signet_takes_is_never_signed(controls)
        the_off_switch_stops_the_agent(controls, agent)
        a_reminder_sets_the_recovery_code_and_shows_it_once(controls)
        cal = cal_writes_to_lia_and_is_held(signup, controls, lia, agent)
        a_view_her_agent_didnt_sign_draws_nothing(signup, controls, lia, agent, cal)
        request, slot = cal_asks_for_a_meeting_and_her_agent_accepts(signup, controls, lia, cal)
        a_card_names_cal_only_as_far_as_signatures_bind_him(signup, controls, lia, agent, cal, request)
        what_is_signed_is_what_is_shown_and_changed_terms_are_refused(signup, controls, lia, agent, cal, request, slot)
        said = [word for word in NEVER_SAID if word.lower() in controls.seen.lower()]
        check("nowhere does the page name a passkey or a pairing code", said == [], said)
        check("nothing on the page threw", controls.browser.problems == [], controls.browser.problems)
    finally:
        if controls:
            controls.close()
        signup.walk.stop_everything()
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    # So a stop runs the cleanup below, and leaves no host, Signet, browser or Splint of this run behind.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    e2e.build()
    subprocess.run(["cargo", "build", "--quiet", "-p", "splint-core", "--example", "seal_view"], cwd=e2e.PACKAGES, check=True)
    run()
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall checks of your controls on your own computer passed", flush=True)


if __name__ == "__main__":
    main()

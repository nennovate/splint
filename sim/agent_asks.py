#!/usr/bin/env python3
"""An agent on its person's computer asks for its controls and then for exact changes, and its person
approves each with one approval on Splint on their computer.

Ivy joins on her own. `splint controls` hands Splint on this computer an ask her key signed, and, as
nothing here asks for her person by itself, comes back at once with a link to hand them, still
waiting. Her person approves it from a terminal, as a computer with no chip Splint can use does, and
`splint ask ID` takes it up. Ola's ask, with `--wait`, takes it up in the same call. Noa's is approved
while her host is down and keeps no answer, and she takes it up from Splint on that computer. No way of making
the sign-in makes a key file with no passphrase unless the person asks for exactly that: not a typed
yes, the socket, the page or `owner-key` (issue 892). Ivy's person asks for it, with
`--plain-key-file`, which warns every time that file signs or is listed, at the terminal, on both
pages, in the log of Splint on the computer and from `owner-key`, and one typed yes signs
that Ivy acts for them, her rules and her delegation, and Ivy takes it up by herself, with nothing
pasted. Ivy then asks for exact changes, which one more approval signs as new rules holding exactly
them, and her Signet says the ask is done once those rules are in force. A stranger's ask for
controls is named by its own address, with the warning to approve only if the person asked; a no signs
nothing. A changed ask, another agent's settings ask, an ask under another agent's address, and a
page elsewhere calling in are refused. A website that opens an agent's link puts nothing in front of
the person until they click, and a program that only reaches the port, forging a browser's headers,
gets nothing under /local without the key a page the person opened holds.

The owner page Splint on the computer serves signs and reads through it: a page alone can't sign with a
key file that asks for nobody, and with a passphrase it makes sessions whose keys stay there, reads the
agent's view at its host and opens it with the reading key, and drops them when viewing is every time.
In a real browser those controls read her agent's rules at its host, and one approval signs where the
person gets paid, with a passphrase typed while the page draws itself again, and the agent's Signet
holds it, and its host was left it sealed to the agent, by Splint on the computer.
An approval signs exactly the asks the person was shown, never one that came in after. An agent asks
for a held step only while one is held. Una becomes an owner on her page in a real browser, which
asks her to choose a passphrase and says why. Ivy's person then locks their plain key file, left as
an earlier version made one, with `splint computer lock`, keeping their owner ID, and from then on a
program running as them that pipes a yes, approves on the socket or runs `owner-key` gets nothing
signed. The owner key `owner-key init` makes for a device kept apart from agents, which `splint
authorize` uses with no passphrase, is never warned of as a sign-in, or locked. `splint stop` stops
Splint on the computer too, so the run leaves none running. A remote agent taking up its person's
answer to its link, approved with a sign-in locked by default, is sim/asked_by_link.py.

    python3 sim/agent_asks.py

Not shown: a Mac's Touch ID prompt, which a test never puts on a screen (`owner-key`'s chip test runs on
a Mac with `--ignored`, with a key that asks for nobody), two OS users (homes under one user), a
program that records keystrokes or changes Splint's own programs to take a passphrase as it's typed,
which a passphrase doesn't stop, or a real model. Keys are software key files: Ivy's person's sign-in
is plain until they lock it, and Ola's and Una's are locked with a passphrase. No agent has network
limits.
"""

import json
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import e2e
from agent_signup import SIGNET_HEARS_SECONDS, Signup
from browser import Browser
from direct_access import host_is_back, host_is_down
from e2e import check, http_on_socket, wait_until

TOUCH_SECONDS = 120
# Far longer than an ask that waits for nobody takes to answer, and far shorter than one that does.
AT_ONCE_SECONDS = 45
PASSPHRASE = "correct horse"
# A new passphrase is typed twice.
CHOSEN = f"{PASSPHRASE}\n{PASSPHRASE}\n"
OWNER_KEY = "$HOME/.splint/bin/splint-owner-key"


def http(method: str, port: int, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Host": f"localhost:{port}", "Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:
            return answer.status, json.loads(answer.read() or b"{}")
    except urllib.error.HTTPError as refused:
        return refused.code, {}


def socket_of(person):
    return person.dot / "run" / "computer.sock"


def sign_in_of(person) -> dict:
    """Who Splint on the person's computer says is here, and how their sign-in is held."""
    return http_on_socket("GET", socket_of(person), "/v0/here")[1]


def computer_is_up(person) -> bool:
    try:
        return socket_of(person).exists() and http_on_socket("GET", socket_of(person), "/v0/here")[0] == 200
    except OSError:
        return False


def waiting_ids(person) -> list:
    """What the next approval on the person's computer would sign, as any program run as them reads it."""
    return [one.get("id") for one in http_on_socket("GET", socket_of(person), "/v0/asks")[1].get("asks", [])]


def said_in_its_log(person) -> int:
    """How often Splint on the person's computer has said, in its own log, that a plain key file signed."""
    log = person.dot / "run" / "splint-computer.log"
    return sum("Warning" in line and "no passphrase" in line for line in log.read_text().splitlines()) if log.exists() else 0


def warns_of_a_plain_key_file(browser: Browser) -> bool:
    """Whether the page in front of the person says their sign-in is a plain key file, and how to lock it."""
    return browser.wait_for("(() => { const said = document.getElementById('plain-key-file'); return !!said && !said.hidden && said.textContent.includes('no passphrase') && said.textContent.includes('splint computer lock'); })()", 30)


def no_key_file_is_made_without_a_passphrase(signup: Signup, ivy, port: int) -> None:
    """Issue 892. Bug caught: a sign-in made as a plain key file because nobody gave a passphrase, which
    the person's own fooled agent, running as them, then copies or signs with."""
    ids = waiting_ids(ivy)
    check("control: ivy's ask waits, and her person has no sign-in yet", bool(ids) and sign_in_of(ivy).get("sign_in") is None, sign_in_of(ivy))
    typed = signup.walk.run_as("ivy", "splint computer approve", "yes\n")
    check("with no sign-in yet, a typed yes signs nothing: the terminal asks for a passphrase to choose", typed.returncode != 0 and "Approved" not in typed.stdout and "passphrase" in typed.stderr, typed.stdout + typed.stderr)
    posted = [http_on_socket("POST", socket_of(ivy), "/v0/approve", {"ids": ids} | given)[1] for given in ({}, {"passphrase": "short"})]
    check("a program approving on the socket with no passphrase, or a short one, signs nothing", all(one.get("approved") == 0 and one.get("error") for one in posted), posted)
    same = page_key(ivy, port)
    tried = [
        http("POST", port, "/local/approve", {"ids": ids}, same)[0],
        http("POST", port, "/local/approve", {"ids": ids, "passphrase": "short"}, same)[0],
        http("POST", port, "/local/owner", {}, same)[0],
        http("POST", port, "/local/owner", {"passphrase": "short"}, same)[0],
    ]
    check("nor does the page, approving or making the owner ID", tried == [422] * 4, tried)
    check("so none of them made a sign-in", sign_in_of(ivy).get("sign_in") is None and not (ivy.dot / "computer" / "owner" / "owner.key").exists(), sign_in_of(ivy))
    browser = Browser(signup.walk.work / "first-use")
    try:
        _, opened = http_on_socket("POST", socket_of(ivy), "/v0/page")
        browser.goto(f"http://localhost:{port}/owner#open={opened.get('opening', '')}")
        check("control: the page holds the key", browser.wait_for("!!localStorage.getItem('splint-page-key')", 20))
        browser.goto(f"http://localhost:{port}/ask")
        check("control: the page lists ivy's ask for controls", browser.wait_for(f"document.body.innerText.includes('let {ivy.address} act for you')", 20), browser.text())
        listed = browser.text()
        # Bugs caught: the first approval saying it signs nobody in right above saying it makes their
        # sign-in, and calling an agent asking to become theirs their agent already.
        check("on first use the page says approving sets up the sign-in here, and calls the agent asking for controls an agent, not theirs",
              "An agent asked for this change" in listed and "sets up your sign-in here" in listed and "doesn't sign you in" not in listed
              and browser.eval("!document.getElementById('new-passphrase-why').hidden") is True, listed)
    finally:
        browser.close()

    scratch = signup.walk.work / "owner-key-alone"
    refused = signup.walk.run_as("ivy", f"{OWNER_KEY} init --dir {scratch / 'none'} --sign-in file")
    check("owner-key makes no key file given neither a passphrase nor the plain choice", refused.returncode != 0 and not (scratch / "none" / "owner.key").exists(), refused.stdout + refused.stderr)
    short = signup.walk.run_as("ivy", f"{OWNER_KEY} init --dir {scratch / 'none'} --sign-in file --passphrase -", "short\n")
    check("nor with a passphrase under 8 characters", short.returncode != 0 and not (scratch / "none" / "owner.key").exists(), short.stdout + short.stderr)
    plain = signup.walk.run_as("ivy", f"{OWNER_KEY} init --dir {scratch / 'first'} --sign-in file --plain-key-file yes")
    check("the plain choice still makes one, and says what it means", plain.returncode == 0 and "Warning" in plain.stderr and "sign as you" in plain.stderr, plain.stdout + plain.stderr)
    said = dict(re.findall(r"^(owner identity|sign-in key): (\S+)$", plain.stdout, re.M))
    offer = f"{OWNER_KEY} offer-sign-in --dir {scratch / 'second'} --identity {said.get('owner identity')} --by {said.get('sign-in key')} --sign-in file"
    refused = signup.walk.run_as("ivy", offer)
    check("a second computer's sign-in is no plain key file by default either", refused.returncode != 0 and not (scratch / "second" / "owner.key").exists(), refused.stdout + refused.stderr)
    offered = signup.walk.run_as("ivy", f"{offer} --passphrase -", f"{PASSPHRASE}\n")
    check("control: with a passphrase it's made, locked", offered.returncode == 0 and (scratch / "second" / "owner.key").read_bytes().startswith(b"{"), offered.stdout + offered.stderr)


def an_owner_key_kept_apart_is_never_locked(signup: Signup) -> None:
    """The owner key `owner-key init` makes with no `--sign-in`, which `splint authorize` and `setup`
    keep on a device apart from agents and use with no passphrase. Bug caught: owner-key warning of it
    as a sign-in and saying to lock it, which stops every one of those commands, with no way back."""
    apart = signup.walk.work / "owner-key-alone" / "apart"
    made = signup.walk.run_as("ivy", f"{OWNER_KEY} init --dir {apart}")
    shown = signup.walk.run_as("ivy", f"{OWNER_KEY} show --dir {apart}")
    said = made.stderr + shown.stderr
    check("owner-key doesn't say to lock an owner key that wasn't made as a sign-in", made.returncode == 0 and shown.returncode == 0 and "lock-sign-in" not in said and "Warning" not in said, said)
    locked = signup.walk.run_as("ivy", f"{OWNER_KEY} lock-sign-in --dir {apart} --passphrase -", f"{PASSPHRASE}\n")
    check("and refuses to lock it", locked.returncode != 0 and not (apart / "owner.key").read_bytes().startswith(b"{"), locked.stdout + locked.stderr)
    signs = signup.walk.run_as("ivy", f"{OWNER_KEY} access --dir {apart} --host {signup.open_host} --method GET --path /v0/owner")
    check("so it still signs with no passphrase, as splint authorize has it sign", signs.returncode == 0 and signs.stdout.strip() != "", signs.stdout + signs.stderr)


def every_waiting(port: int, same: dict) -> list:
    """Every ask the page lists, in the approval it goes in or one after."""
    listed = http("GET", port, "/local/asks", headers=same)[1]
    return listed.get("asks", []) + [one for later in listed.get("later", []) for one in later.get("asks", [])]


def page_key(person, port: int) -> dict:
    """The headers a page the person opened sends: it trades a one-time opening, which only a program
    run as them gets on the socket, for the page key."""
    status, opened = http_on_socket("POST", socket_of(person), "/v0/page")
    status, traded = http("POST", port, "/local/page", {"opening": opened.get("opening", "")}, {"Sec-Fetch-Site": "same-origin"})
    return {"Sec-Fetch-Site": "same-origin", "Splint-Page": traded.get("key", "")}


def on_the_computer(person, port: int) -> None:
    """Its own port, and a key file for the sign-in even on a Mac, so no run puts a prompt on a screen."""
    person.env["SPLINT_COMPUTER_PORT"] = str(port)
    person.env["SPLINT_COMPUTER_SIGN_IN"] = "file"


def in_background(signup: Signup, name: str, command: str) -> dict:
    """Runs a command that waits for the person, so the person can answer meanwhile."""
    done: dict = {}

    def run() -> None:
        done["result"] = signup.walk.run_as(name, command, timeout=TOUCH_SECONDS + 30)

    thread = threading.Thread(target=run)
    thread.start()
    done["thread"] = thread
    return done


def asked_without_waiting(signup: Signup, name: str, command: str) -> dict:
    """What an ask answers with nobody approving it meanwhile, or nothing if it's still waiting for them."""
    try:
        done = signup.walk.run_as(name, command, timeout=AT_ONCE_SECONDS)
    except subprocess.TimeoutExpired:
        return {}
    return json.loads(done.stdout or "{}")


def an_agent_asks_for_its_controls_and_one_approval_sets_them_up(signup: Signup, port: int):
    host = signup.open_host
    ivy = signup.device("ivy")
    on_the_computer(ivy, port)
    joined = signup.walk.run_as("ivy", f"splint join ivy~{host}")
    check("control: ivy joins on her own", joined.returncode == 0, joined.stderr)
    ivy.address = f"ivy~{host}"
    status = json.loads(signup.walk.run_as("ivy", "splint status --json").stdout or "{}")
    # Bug caught: an agent on its person's computer told only the paste-a-code way.
    check("status names the one-touch way for an agent on its person's computer", status.get("controls", {}).get("ask", "").endswith("splint controls"), status.get("controls"))

    asked = asked_without_waiting(signup, "ivy", "splint controls --json")
    # Bugs caught: an agent whose ask Splint on its own computer took, with a key file for a sign-in,
    # waiting two minutes for a touch no prompt asked anyone for, and then given no link, so a person
    # who isn't at that computer was never asked at all.
    check("where nothing here asks for its person by itself, splint controls comes back at once, still waiting", asked.get("status") == "waiting" and asked.get("approve_at") == "this_computer", asked)
    _, kept = ivy.api("GET", f"/v0/asks/{asked.get('id', '')}")
    _, host_says = e2e.http("GET", f"http://{host}/.well-known/splint/host")
    # What a page reads from a link: the ask and the agent's address, after the #.
    carries = f"#ask={kept.get('ask', '')}&at={ivy.address}"
    check("with a link to hand its person, which opens its ask on Splint on their own computer", bool(kept.get("ask")) and str(asked.get("computer_link")).startswith("http://localhost:") and str(asked.get("computer_link")).endswith(f"/ask{carries}"), asked.get("computer_link"))
    # Issue 635: owners sign only on their own computers (Nenye, 2026-11-21). sim/asked_by_link.py
    # shows a host whose operator set an HTTPS owner page of its own giving no link to it either.
    check("and none to any page of its host's, which names none", "link" not in asked and "owner_page" not in host_says and "owner_page_rp_id" not in host_says, (asked, host_says))
    listed = ""
    for _ in range(60):
        time.sleep(1)
        said_no = signup.walk.run_as("ivy", "splint computer approve --plain-key-file", "no\n")
        # What's asked goes to stderr, as the authorize screen does, and stdout says what came of it.
        listed = said_no.stdout + said_no.stderr
        if "act for you" in listed:
            break
    check("Splint on the computer starts by itself and lists the ask in its own words", f"let {ivy.address} act for you" in listed, listed)
    check("with the warning to approve only if the person asked", "if you asked it to join" in listed, listed)
    check("a no signs nothing", "Nothing was signed" in listed, listed)
    no_key_file_is_made_without_a_passphrase(signup, ivy, port)
    an_owner_key_kept_apart_is_never_locked(signup)
    approved = signup.walk.run_as("ivy", "splint computer approve --plain-key-file", "yes\n")
    check("the person's own --plain-key-file makes a plain key file, and one typed yes approves it", approved.returncode == 0 and "Approved 1" in approved.stdout and sign_in_of(ivy).get("plain_key_file") is True, approved.stdout + approved.stderr)
    # Bug caught: a setting that weakens a check chosen with nothing said about what it means.
    check("saying what that means as it's chosen", "Warning" in approved.stderr and "sign as you" in approved.stderr, approved.stderr)
    again = signup.walk.run_as("ivy", "splint computer approve --plain-key-file", "yes\n")
    check("and it's a choice for a sign-in not made yet, refused once one is", again.returncode != 0, again.stdout + again.stderr)
    where = lambda: json.loads(signup.walk.run_as("ivy", f"splint ask {asked.get('id', '')} --json").stdout or "{}")  # noqa: E731
    check("the agent takes up what was signed by itself, with nothing pasted", wait_until(lambda: where().get("status") == "done", SIGNET_HEARS_SECONDS), where())
    check("and its owner has confirmed it now", wait_until(lambda: ivy.api("GET", "/v0/identity")[1].get("owner_confirmed") is True, SIGNET_HEARS_SECONDS), ivy.api("GET", "/v0/identity")[1])
    controls = json.loads(signup.walk.run_as("ivy", "splint status --json").stdout or "{}").get("controls", {})
    # Bug caught: status dropping how the person opens their controls once they're set, so an agent
    # asked "where are my controls?" had nothing to give.
    check("once they're set, status still says how its person opens their controls", controls.get("set") is True and controls.get("open") == f"~/.splint/bin/splint controls {host}" and str(controls.get("page")).startswith("http://localhost:"), controls)
    check("and names no page of its host's", "host_page" not in controls, controls)
    return ivy


def the_agent_asks_for_exact_changes_and_learns_when_they_hold(signup: Signup, ivy) -> None:
    asked = signup.walk.run_as("ivy", "splint ask --level full-auto --json")
    shown = json.loads(asked.stdout or "{}")
    check("an ask goes in and waits for the person", asked.returncode == 0 and shown.get("status") == "waiting", asked.stdout + asked.stderr)
    said_no = signup.walk.run_as("ivy", "splint computer approve", "no\n")
    listed = said_no.stdout + said_no.stderr
    # Bug caught: a terminal approving what lets more in with none of the page's warning.
    check("the terminal warns of what lets more in, as the page does", "This lets more in than before" in listed, listed)
    # Bug caught: a plain key file, from the person's choice or an earlier version, used with nothing
    # said, so they never learn their agent can sign as them, or how to lock it.
    check("and each time a plain key file is about to sign, the terminal says what it is and how to lock it", "Warning" in said_no.stderr and "splint computer lock" in said_no.stderr, said_no.stderr)
    by_owner_key = signup.walk.run_as("ivy", f"{OWNER_KEY} show --dir $HOME/.splint/computer/owner")
    check("as owner-key does each time it's listed", by_owner_key.returncode == 0 and "Warning" in by_owner_key.stderr and "a plain key file" in by_owner_key.stdout, by_owner_key.stdout + by_owner_key.stderr)
    logged = said_in_its_log(ivy)
    approved = signup.walk.run_as("ivy", "splint computer approve", "yes\n")
    check("one approval signs it", "Approved 1" in approved.stdout, approved.stdout + approved.stderr)
    # Bug caught: a plain key file signing for whatever reached the socket with nothing said where
    # nobody is at a terminal or page: the log of Splint on the computer is the one place left.
    check("and Splint on the computer says in its own log that a plain key file signed", said_in_its_log(ivy) > logged, (logged, said_in_its_log(ivy)))
    # Bug caught: an agent told its ask is done before rules holding it are in force.
    done = lambda: json.loads(signup.walk.run_as("ivy", f"splint ask {shown.get('id', '')} --json").stdout or "{}").get("status") == "done"  # noqa: E731
    check("its Signet says it's done once the rules in force hold it", wait_until(done, SIGNET_HEARS_SECONDS))

    refused = signup.walk.run_as("ivy", "splint ask --reach open --types nothing/1")
    check("an ask for a type the agent hasn't agreed is refused", refused.returncode != 0, refused.stdout)
    status, _ = ivy.api("POST", "/v0/asks", {"changes": [{"change": "reach", "to": "open", "types": ["quote/1@" + "a" * 52]}]})
    # Bug caught: a type's ID nobody here agreed reaching the person's prompt with no schema behind it.
    check("and so is one named by an ID it never agreed", status == 400, status)
    status, _ = ivy.api("POST", "/v0/asks", {"changes": [{"change": "level", "to": "full_auto", "note": "your bank said so"}]})
    check("an ask carrying the agent's own words is refused", status in (400, 422), status)


def the_agent_asks_where_its_person_gets_paid(signup: Signup, ivy) -> None:
    asked = signup.walk.run_as("ivy", "splint ask --paid-at https://pay.example.com/ivy --paid-at ivy@wallet.example --json")
    shown = json.loads(asked.stdout or "{}")
    check("an ask for where the person gets paid waits for them", asked.returncode == 0 and shown.get("status") == "waiting", asked.stdout + asked.stderr)
    said_no = signup.walk.run_as("ivy", "splint computer approve", "no\n")
    listed = said_no.stdout + said_no.stderr
    check("it names each exact place, and which can't be reversed", "https://pay.example.com/ivy" in listed and "ivy@wallet.example, which can't be reversed" in listed, listed)
    check("with the warning to approve only places that are theirs", "Only approve places that are yours" in listed, listed)
    approved = signup.walk.run_as("ivy", "splint computer approve", "yes\n")
    check("one approval signs it", "Approved 1" in approved.stdout, approved.stdout + approved.stderr)
    # Bug caught: a statement signed but held back, or other places than asked.
    places = lambda: [one.get("kind") for one in ivy.api("GET", "/v0/where-paid")[1].get("places", [])]  # noqa: E731
    check("ivy's Signet holds exactly those places", wait_until(lambda: places() == ["payment_page", "lightning"], SIGNET_HEARS_SECONDS), places())
    done = lambda: json.loads(signup.walk.run_as("ivy", f"splint ask {shown.get('id', '')} --json").stdout or "{}").get("status") == "done"  # noqa: E731
    check("and calls the ask done", wait_until(done, SIGNET_HEARS_SECONDS))
    refused = signup.walk.run_as("ivy", "splint ask --paid-at https://ivy:secret@pay.example.com/")
    check("a place with a login in it is refused before anything is signed", refused.returncode != 0, refused.stdout)
    status, _ = ivy.api("POST", "/v0/asks", {"changes": [{"change": "where_paid", "places": [{"kind": "payment_page", "url": "https://pay.example.com/ivy"}]}, {"change": "paused", "to": True}]})
    check("and where the person gets paid is alone in its ask", status == 400, status)


def a_page_elsewhere_and_a_changed_ask_get_nothing(signup: Signup, ivy, port: int) -> None:
    status, _ = http("POST", port, "/local/asks", {"ask": "x", "address": ivy.address})
    check("a call from another site, with no same-origin mark, is refused", status == 403, status)
    status, _ = http("GET", port, "/ask", headers={"Host": f"evil.example:{port}"})
    check("a page naming another host is refused", status == 421, status)
    # Bug caught: a program on this computer, or another of its users, that only reaches the port
    # forging the headers a browser sends, and so reading views, changing settings or taking the
    # recovery code with no touch.
    forged = {"Sec-Fetch-Site": "same-origin"}
    agent = ivy.api("GET", "/v0/identity")[1].get("agent_id", "")
    tried = [
        http("GET", port, "/local/here", headers=forged)[0],
        http("POST", port, "/local/viewing", {"every": "never"}, forged)[0],
        http("POST", port, "/local/read", {"domain": signup.open_host, "path": f"/v0/owner-view/{agent}"}, forged)[0],
        http("POST", port, "/local/recovery", {}, forged)[0],
    ]
    check("a program forging a browser's headers gets nothing under /local without the page key", tried == [403] * 4, tried)
    same = page_key(ivy, port)
    status, _ = http("POST", port, "/local/page", {"opening": "0" * 64}, forged)
    check("and no page key for an opening the socket didn't hand out", status == 422, status)
    status, _ = http("GET", port, "/local/here", headers={**same, "Origin": "http://evil.example"})
    check("a call with another site's origin is refused even with the key", status == 403, status)
    asked = json.loads(signup.walk.run_as("ivy", "splint ask --pause --json").stdout or "{}")
    status, kept = ivy.api("GET", f"/v0/asks/{asked.get('id', '')}")
    changed = kept.get("ask", "").replace(".", ".X", 1)
    status, _ = http("POST", port, "/local/asks", {"ask": changed, "address": ivy.address}, forged)
    check("a changed ask is refused", status == 422, status)
    status, page = http("GET", port, "/local/asks", headers=same)
    check("the page lists the real one, by the agent's address", status == 200 and any(one.get("address") == ivy.address for one in page.get("asks", [])), page)
    ids = [asked.get("id", "")]
    check("and a page can't approve with a key file that asks for nothing", http("POST", port, "/local/approve", {"ids": ids}, same)[0] == 422)
    # Bug caught: any passphrase letting a plain key file, which asks for nobody, sign from the page.
    check("nor with a passphrase that key file doesn't have", http("POST", port, "/local/approve", {"ids": ids, "passphrase": "x"}, same)[0] == 422)
    inputs = ["eyJhbGciOiJFUzI1NiIsInR5cCI6InNwbGludC1ydWxlcyJ9.e30"]
    check("nor sign with one", http("POST", port, "/local/sign", {"inputs": inputs, "passphrase": "x"}, same)[0] == 422)
    check("so the ask still waits", any(one.get("id") == ids[0] for one in http("GET", port, "/local/asks", headers=same)[1].get("asks", [])))


def a_strangers_ask_is_named_and_another_owners_agent_is_refused(signup: Signup, ivy, port: int):
    host = signup.open_host
    mal = signup.device("mal")
    on_the_computer(mal, port + 1)
    check("control: mal joins on her own", signup.walk.run_as("mal", f"splint join mal~{host}").returncode == 0)
    mal.address = f"mal~{host}"
    asked = json.loads(signup.walk.run_as("mal", "splint ask --level full-auto --json").stdout or "{}")
    status, kept = mal.api("GET", f"/v0/asks/{asked.get('id', '')}")
    mal_identity = mal.api("GET", "/v0/identity")[1].get("identity", "")
    status, taken = http_on_socket("POST", socket_of(ivy), "/v0/asks", {"ask": kept.get("ask", ""), "identity": mal_identity, "address": ivy.address})
    # Bug caught: a fooled agent filing its own ask under the address of its person's other agent, so
    # the prompt names that one while the rules are signed for the asker.
    check("an ask handed on the socket under another agent's address is refused", taken.get("status") == "refused", taken)
    status, _ = http("POST", port, "/local/asks", {"ask": kept.get("ask", ""), "address": mal.address}, {"Sec-Fetch-Site": "same-origin"})
    check("control: a link hands ivy's person another owner's agent's ask", status == 200, status)
    approved = signup.walk.run_as("ivy", "splint computer approve", "yes\n")
    # Bug caught: a link's ask, which any website puts there with one click of the person's, riding
    # along in the yes they give their own agent's ask, so the only way to keep it out is to approve
    # nothing until it ends.
    check("a link's ask goes in no approval with the person's own", "Approved 1 and refused 0" in approved.stdout and "1 more waits" in approved.stdout, approved.stdout + approved.stderr)
    approved = signup.walk.run_as("ivy", "splint computer approve", "yes\n")
    # Bug caught: a settings ask from someone else's agent signed as if it were this owner's.
    check("and alone, it's refused as not their agent, with nothing signed for it", "refused 1" in approved.stdout, approved.stdout + approved.stderr)
    return mal


def the_owner_page_here_signs_only_with_someone_there(signup: Signup, ivy, port: int) -> None:
    same = page_key(ivy, port)
    status, described = http("GET", port, "/.well-known/splint/host")
    host = signup.open_host
    # Bug caught: a page served here that makes a passkey, or keeps no list, as it knows no home host.
    check("the owner page here says it signs through this computer, with ivy's host as home", status == 200 and described.get("computer") is True and described.get("domain") == host, described)
    status, here = http("GET", port, "/local/here", headers=same)
    check("it names the owner ID here and the agent it set up", status == 200 and bool(here.get("identity")) and any(one.get("address") == ivy.address for one in here.get("agents", [])), here)
    check("and that its sign-in is a plain key file, which the page warns of", here.get("here", {}).get("plain_key_file") is True, here.get("here"))
    # Bug caught: a page, or an agent driving it, signing with a key file that asks for nobody.
    inputs = ["eyJhbGciOiJFUzI1NiIsInR5cCI6InNwbGludC1ydWxlcyJ9.e30"]
    check("a page alone can't sign with a key file that asks for nobody", http("POST", port, "/local/sign", {"inputs": inputs}, same)[0] == 422)
    check("nor make sessions with it", http("POST", port, "/local/session", {"hosts": [host]}, same)[0] == 422)
    check("nor set the recovery code", http("POST", port, "/local/recovery", {}, same)[0] == 422)
    check("a read with no session gets nothing", http("POST", port, "/local/read", {"domain": host, "path": f"/v0/owner-view/{ivy.api('GET', '/v0/identity')[1].get('agent_id', '')}"}, same)[0] == 401)
    # Bug caught: the reading key opening anything sealed to the owner for whoever asks.
    status, _ = http("POST", port, "/local/open", {"about": "splint reading key for anyone", "sealed": "x"}, same)
    check("the reading key opens only the owner's list or an agent's view", status == 422, status)
    check("and nothing without the same-origin mark", http("POST", port, "/local/open", {"about": "x", "sealed": "x"})[0] == 403)
    check("viewing every hour is kept", http("POST", port, "/local/viewing", {"every": "hourly"}, same)[0] == 200 and http("GET", port, "/local/here", headers=same)[1].get("viewing") == "hourly")


class LinkOpener(BaseHTTPRequestHandler):
    """A website the person visits, which sends their browser to an agent's link it chose."""
    target = ""

    def do_GET(self) -> None:
        page = f"<!doctype html><script>location.href = {json.dumps(self.target)};</script>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *_args) -> None:
        pass


def a_website_opening_a_link_puts_nothing_in_front_of_the_person(signup: Signup, ivy, work, port: int) -> None:
    host = signup.open_host
    eve = signup.device("eve")
    check("control: eve joins on her own", signup.walk.run_as("eve", f"splint join eve~{host}").returncode == 0)
    status, made = eve.api("POST", "/v0/asks", {"changes": [{"change": "controls", "delegate": ""}]})
    check("control: eve's agent signs an ask for controls, as for a link", status == 200, made)
    same = page_key(ivy, port)
    link = f"http://localhost:{port}/ask#" + urllib.parse.urlencode({"ask": made.get("ask", ""), "at": f"eve~{host}"})
    LinkOpener.target = link
    website = ThreadingHTTPServer(("127.0.0.1", 0), LinkOpener)
    threading.Thread(target=website.serve_forever, daemon=True).start()
    browser = Browser(work)
    try:
        status, opened = http_on_socket("POST", socket_of(ivy), "/v0/page")
        browser.goto(f"http://localhost:{port}/owner#open={opened.get('opening', '')}")
        # Bug caught: the page splint controls opens never getting the key, so it can reach nothing.
        check("the owner page trades its opening for the page key", browser.wait_for("!!localStorage.getItem('splint-page-key')", 20))
        # Bug caught: a page that can't sign with a plain key file never saying why, or that anything
        # running as the person can, so they never lock it.
        check("and warns that her sign-in is a plain key file, with how to lock it", warns_of_a_plain_key_file(browser), browser.text())
        browser.goto(f"http://127.0.0.1:{website.server_address[1]}/")
        check("control: the website sends the browser to the link", browser.wait_for("document.body.innerText.includes('See what it asks')", 20), browser.text())
        time.sleep(3)
        eves = lambda: [one for one in every_waiting(port, same) if one.get("address") == f"eve~{host}"]  # noqa: E731
        # Bug caught: any website putting a stranger's ask in front of the person, and on a Mac into the
        # next Touch ID prompt with their own asks, with no click.
        check("a website opening an agent's link puts nothing waiting until the person clicks", eves() == [], eves())
        check("control: the person clicks to see it", browser.click("body", "See what it asks"))
        check("then it waits, shown as from a link", wait_until(lambda: [one.get("from_link") for one in eves()] == [True], 20), eves())
        check("in the page's words, with the warning", browser.wait_for(f"document.body.innerText.includes('let eve~{host} act for you, if you asked it to join')", 20), browser.text())
        asked = signup.walk.run_as("ivy", "splint ask --paid-at ivy@wallet.example --json")
        check("control: ivy asks where her person gets paid", asked.returncode == 0, asked.stderr)
        browser.goto(f"http://localhost:{port}/ask")
        # Bug caught: the page naming a place to be paid without saying a payment there can't be
        # reversed, which the terminal and the prompt both say.
        check("the page with the key lists what waits, saying which place can't be reversed", browser.wait_for("document.body.innerText.includes(\"ivy@wallet.example, which can't be reversed\")", 20), browser.text())
        check("with the same warning of a plain key file beside what it asks her to approve", warns_of_a_plain_key_file(browser), browser.text())
    finally:
        browser.close()
        website.shutdown()


def an_approval_signs_only_the_asks_shown(signup: Signup, ola, port: int, same: dict) -> dict:
    first = json.loads(signup.walk.run_as("ola", "splint ask --level full-auto --json").stdout or "{}")
    shown = lambda: [one.get("id") for one in http("GET", port, "/local/asks", headers=same)[1].get("asks", [])]  # noqa: E731
    check("control: the page shows ola's ask", wait_until(lambda: first.get("id") in shown(), 20), shown())
    # One that goes in the same approval, so signing it with the first is what an approval that
    # ignored the IDs shown would do.
    later = json.loads(signup.walk.run_as("ola", "splint ask --pause --json").stdout or "{}")
    check("control: another comes in while she looks, for the same approval", wait_until(lambda: later.get("id") in shown(), 20), shown())
    status, approved = http("POST", port, "/local/approve", {"ids": [first.get("id")], "passphrase": "correct horse"}, same)
    # Bug caught: an approval signing whatever waits when it's clicked, such as a fooled agent's
    # pause, that came in after the person read the list.
    check("an approval signs only the asks she was shown, never one that came in after", status == 200 and approved.get("approved") == 1 and shown() == [later.get("id")], (approved, shown()))
    status, _ = http("POST", port, "/local/approve", {"ids": [first.get("id"), later.get("id")], "passphrase": "correct horse"}, same)
    check("and a list that's no longer what's waiting signs nothing", status == 422 and shown() == [later.get("id")], (status, shown()))
    return later


def the_page_lists_and_codes_what_one_approval_signs(signup: Signup, port: int, same: dict, later: dict) -> None:
    paid = json.loads(signup.walk.run_as("ola", "splint ask --paid-at https://pay.example.com/ola --json").stdout or "{}")
    listed = lambda: http("GET", port, "/local/asks", headers=same)[1]  # noqa: E731
    ids = lambda approval: [one.get("id") for one in approval.get("asks", [])]  # noqa: E731
    check("control: a new place to be paid waits", wait_until(lambda: paid.get("id") in [one.get("id") for one in every_waiting(port, same)], 20))
    before = listed()
    # Bug caught: the page listing, under one code, asks the prompt signs in two, so it says the
    # prompt names "exactly these" next to a code the prompt never shows, and Approve leaves one.
    check("the page lists only what the next approval signs, a new place to be paid after it alone", ids(before) == [later.get("id")] and [ids(one) for one in before.get("later", [])] == [[paid.get("id")]], before)
    both = [later.get("id"), paid.get("id")]
    check("an approval of asks that go in two signs nothing", http("POST", port, "/local/approve", {"ids": both, "passphrase": "correct horse"}, same)[0] == 422)
    after_code = (before.get("later") or [{}])[0].get("code")
    status, _ = http("POST", port, "/local/approve", {"ids": [later.get("id")], "code": after_code, "passphrase": "correct horse"}, same)
    check("nor one with a code that isn't its asks'", status == 422 and ids(listed()) == [later.get("id")], status)
    status, approved = http("POST", port, "/local/approve", {"ids": [later.get("id")], "code": before.get("code"), "passphrase": "correct horse"}, same)
    check("Approve signs what's listed, under the code listed with it", status == 200 and approved.get("approved") == 1 and approved.get("code") == before.get("code"), approved)
    now = listed()
    check("and what comes next is listed under its own code", ids(now) == [paid.get("id")] and now.get("code") == after_code, now)
    status, approved = http("POST", port, "/local/approve", {"ids": [paid.get("id")], "code": now.get("code"), "passphrase": "correct horse"}, same)
    check("control: which signs on its own", status == 200 and approved.get("approved") == 1, approved)


def the_page_signs_what_it_listed_when_she_began(signup: Signup, ola, port: int, same: dict, work) -> None:
    first = json.loads(signup.walk.run_as("ola", "splint ask --level ask-me --json").stdout or "{}")
    second = json.loads(signup.walk.run_as("ola", "splint ask --quoted-prices wait --json").stdout or "{}")
    browser = Browser(work / "race")
    try:
        status, opened = http_on_socket("POST", socket_of(ola), "/v0/page")
        browser.goto(f"http://localhost:{port}/owner#open={opened.get('opening', '')}")
        check("control: the page holds the key", browser.wait_for("!!localStorage.getItem('splint-page-key')", 20))
        browser.goto(f"http://localhost:{port}/ask")
        check("control: the page lists her asks", browser.wait_for("document.body.innerText.includes('acts only once you say yes') && document.body.innerText.includes('each waits for your yes')", 20), browser.text())
        # Bug caught: a change listed with no word of who asked or which setting, which a person on
        # Windows took for a sign-in and approved without knowing what it changed; and one agent's
        # two asks listed under its address twice, as if two requests.
        listed = browser.text()
        check("under the agent that asked, once for both its asks, naming the settings they change, and saying approving signs them and logs her in nowhere",
              listed.count(f"{ola.address} asks you to:") == 1 and f"set {ola.address} to Ask me first" in listed and f"set prices {ola.address} quotes to Wait for me" in listed
              and "with your owner key on this computer" in listed and "doesn't log you in to a website or account" in listed, listed)
        check("control: and asks for the passphrase, with no warning of a plain key file, as hers is locked", browser.wait_for("!document.getElementById('passphrase-row').hidden", 20) and browser.eval("document.getElementById('plain-key-file').hidden") is True)
        # What the page hears on each refresh, kept by the page, so the run waits for a refresh rather
        # than for a time.
        browser.eval("""window.__heard = []; (() => { const fetched = window.fetch; window.fetch = async (url, options) => {
          const answer = await fetched(url, options);
          if (String(url) === '/local/asks' && !(options && options.method)) answer.clone().json().then((listed) => {
            window.__heard.push([...listed.asks, ...(listed.later || []).flatMap((one) => one.asks)].map((ask) => ask.id)); });
          return answer; }; })(); 1""")
        browser.type_into("#passphrase", "correct horse")
        later = json.loads(signup.walk.run_as("ola", "splint ask --resume --json").stdout or "{}")
        check("control: a fooled agent asks while she types", later.get("status") == "waiting", later)
        check("control: the page hears of it on a refresh", browser.wait_for(f"window.__heard.some((ids) => ids.includes({json.dumps(later.get('id', ''))}))", 30))
        check("control: she clicks Approve, which counts the two changes listed", browser.click("body", "Approve these 2 changes"))
        waiting = lambda: [one.get("id") for one in every_waiting(port, same)]  # noqa: E731
        check("control: the page's approval is done", wait_until(lambda: first.get("id") not in waiting() and second.get("id") not in waiting(), 30), waiting())
        # Bug caught: the page's refresh rewriting what Approve sends while the person types, so an
        # ask that came in after she read the list is signed by her click.
        check("Approve on the page signs what was listed when she began, never one that came in after", waiting() == [later.get("id")], waiting())
    finally:
        browser.close()


def she_signs_where_she_gets_paid_on_her_controls(signup: Signup, ola, port: int, same: dict, work) -> None:
    """Bugs caught: her controls on this computer preparing where she gets paid for a passkey to sign,
    which this computer's sign-in refuses, so Sign where you get paid here always failed. And the page
    drawing home again while she types her passphrase and emptying the box, so her click sent none and
    she was told her key file has no passphrase."""
    agent = ola.api("GET", "/v0/identity")[1].get("agent_id", "")
    place = "https://pay.example.com/ola-from-her-controls"

    def held() -> tuple[int, list]:
        """What her agent reads from its Signet: the status too, as a refusal names no place either."""
        status, read = ola.api("GET", "/v0/where-paid")
        return status, [one.get("url") for one in read.get("places", [])]

    at_host = lambda: int(signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{agent}'") or 0)  # noqa: E731
    check("control: her agent's Signet holds no place yet", held() == (200, []), held())
    before = at_host()
    browser = Browser(work / "paid")
    told = lambda: browser.eval("document.getElementById('told').innerText")  # noqa: E731

    def approvals() -> int:
        """Every time the page asked this computer's sign-in to sign, which is what she approves."""
        browser.eval("1")  # Reads what the browser has said since the last call.
        return sum(1 for method, url in browser.requests if method == "POST" and url.endswith("/local/sign"))

    try:
        status, opened = http_on_socket("POST", socket_of(ola), "/v0/page")
        browser.goto(f"http://localhost:{port}/owner#open={opened.get('opening', '')}")
        check("control: her controls open, asking for her sign-in's passphrase", browser.wait_for("document.getElementById('passphrase-here') !== null", 30), browser.text())
        offered = False
        # Clicked again if the page had just redrawn and said that click didn't count, as a person would.
        for _ in range(5):
            browser.type_into("#passphrase-here", "correct horse")
            browser.click("main", "Show my controls")
            offered = browser.wait_for("document.getElementById('where-paid') !== null", 20)
            if offered:
                break
        check("control: one approval shows them, with Getting paid", offered, browser.text())
        # Bug caught: the page here taking a host's answer for something wrapped around it, so it read
        # no rules and nothing her agent left her, and showed no settings and nothing waiting.
        check("her controls on this computer read her agent's rules at its host, and offer its settings", browser.wait_for("document.querySelector('#settings input[value=ask_me]') !== null", 30), browser.text())
        browser.type_into("#where-paid", place)
        browser.type_into("#passphrase-here", "correct ")
        # Home is drawn again while she's halfway through her passphrase, as it is whenever what it
        # shows changed: here her agent's rules, approved in a terminal meanwhile.
        browser.eval("window.__drawn = document.getElementById('getting-paid'); true")
        asked = json.loads(signup.walk.run_as("ola", "splint ask --level ask-me --json").stdout or "{}")
        waiting = lambda: [one.get("id") for one in http("GET", port, "/local/asks", headers=same)[1].get("asks", [])]  # noqa: E731
        check("control: her agent asks for a change", wait_until(lambda: asked.get("id") in waiting(), 20), waiting())
        status, approved = http("POST", port, "/local/approve", {"ids": [asked.get("id")], "passphrase": "correct horse"}, same)
        check("control: which she approves away from the page", status == 200 and approved.get("approved") == 1, approved)
        check("control: and home is drawn again while she types", browser.wait_for("window.__drawn && !document.contains(window.__drawn)", 60), browser.text())
        # The rest, typed where the cursor is, as her next keys go: nothing here puts it back in the box.
        browser.call("Input.insertText", text="horse")
        asked_before = approvals()
        # Clicked until the page asks this computer to sign: a click right after a redraw doesn't
        # count, and asks for nothing. The button takes no second click while an approval is out.
        for _ in range(5):
            time.sleep(0.8)
            if not browser.click("#getting-paid", "Sign where you get paid") or wait_until(lambda: approvals() > asked_before, 5):
                break
        signed = browser.wait_for("document.getElementById('told').innerText.startsWith('Signed.')", 30)
        check("her controls on this computer sign where she gets paid, with the passphrase she typed through a redraw", signed, told())
        check("in one approval", approvals() - asked_before == 1, approvals() - asked_before)
    finally:
        browser.close()
    check("her agent's Signet holds exactly the place she signed", wait_until(lambda: held() == (200, [place]), SIGNET_HEARS_SECONDS), held())
    # Bug caught: her controls here handing what she signed to the relay for her agent's host as she
    # signed it, which carries none, so nothing was left there. Splint here seals it to her agent and
    # leaves it under the session it keeps at that host, which is all a host takes it by.
    check("and its host was left her statement too, sealed to her agent, once", wait_until(lambda: at_host() == before + 1, 20), (before, at_host()))


def a_place_approved_with_no_session_is_left_by_the_sign_ins_own_proof(signup: Signup, ola, port: int, same: dict) -> None:
    """Bugs caught: where she gets paid, approved for her agent's ask while this computer keeps no
    session at its host, never reaching that host, as nothing was there to leave it by; and leaving it
    costing a second prompt, which with a locked key file is a passphrase nobody typed."""
    agent = ola.api("GET", "/v0/identity")[1].get("agent_id", "")
    place = "https://pay.example.com/ola-asked-for"
    at_host = lambda: int(signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{agent}'") or 0)  # noqa: E731
    held = lambda: [one.get("url") for one in ola.api("GET", "/v0/where-paid")[1].get("places", [])]  # noqa: E731
    signed_out = http("POST", port, "/local/sign-out", {}, same)[0] == 200 and http("GET", port, "/local/here", headers=same)[1].get("sessions") == []
    check("control: her page signs out, so this computer keeps no session at her agent's host", signed_out)
    asked = json.loads(signup.walk.run_as("ola", f"splint ask --paid-at {place} --json").stdout or "{}")
    check("control: her agent asks where she gets paid", wait_until(lambda: asked.get("id") in [one.get("id") for one in every_waiting(port, same)], 20), asked)
    before = at_host()
    # A statement is dated to the second, and Signet takes one only if it's dated after the one it
    # holds, as only a replay comes with an older date. The one it holds was signed a moment ago, and in
    # about four runs in ten this one was signed in that same second, and refused.
    dated = ola.api("GET", "/v0/where-paid")[1].get("signed_at") or 0
    check("control: the second the last one was signed in has passed", wait_until(lambda: time.time() >= dated + 1, 5), dated)
    status, approved = http("POST", port, "/local/approve", {"ids": [asked.get("id")], "passphrase": "correct horse"}, same)
    check("one approval signs it, with her passphrase given once", status == 200 and approved.get("approved") == 1, approved)
    check("her agent's Signet holds the place", wait_until(lambda: held() == [place], SIGNET_HEARS_SECONDS), held())
    check("and its host was left it, sealed, by a proof her sign-in signed in that same approval", wait_until(lambda: at_host() == before + 1, 20), (before, at_host()))
    status, outcome = http_on_socket("GET", socket_of(ola), f"/v0/asks/{asked.get('id', '')}")
    check("so the ask is done", (outcome or {}).get("status") == "done", outcome)


def a_passphrase_lets_the_page_sign_and_read_until_viewing_says(signup: Signup, port: int, work) -> None:
    host = signup.open_host
    ola = signup.device("ola")
    on_the_computer(ola, port)
    check("control: ola joins on her own", signup.walk.run_as("ola", f"splint join ola~{host}").returncode == 0)
    ola.address = f"ola~{host}"
    # With --wait, as an agent passes where its person is at this computer, and as an ask for controls
    # does by itself where a Mac's own prompt asks for them.
    asking = in_background(signup, "ola", "splint ask --controls --wait --json")
    check("control: Splint on her computer starts", wait_until(lambda: socket_of(ola).exists(), 60))
    same = page_key(ola, port)
    waiting = lambda: http("GET", port, "/local/asks", headers=same)[1].get("asks")  # noqa: E731
    check("control: her ask waits on the page", wait_until(waiting, 60))
    ids = [one.get("id") for one in waiting() or []]
    status, approved = http("POST", port, "/local/approve", {"passphrase": "correct horse", "ids": ids}, same)
    check("the page approves with a passphrase, which locks the new key file", status == 200 and approved.get("approved") == 1 and (ola.dot / "computer" / "owner" / "owner.key").read_bytes().startswith(b"{"), approved)
    asking["thread"].join(TOUCH_SECONDS + 40)
    result = asking.get("result")
    answered = json.loads(result.stdout or "{}") if result else {}
    # Bug caught: an agent waiting on this computer told its ask still waits once its person has
    # approved it here, or left to take the answer up in another call.
    check("an agent that waits takes up what was signed in that same call, with nothing pasted", answered.get("status") == "done", answered)
    agent = ola.api("GET", "/v0/identity")[1].get("agent_id", "")
    check("control: ola's owner has confirmed it", wait_until(lambda: ola.api("GET", "/v0/identity")[1].get("owner_confirmed") is True, SIGNET_HEARS_SECONDS))
    check("control: viewing every hour is kept", http("POST", port, "/local/viewing", {"every": "hourly"}, same)[0] == 200)
    check("a wrong passphrase makes no session", http("POST", port, "/local/session", {"hosts": [host], "passphrase": "wrong"}, same)[0] == 422)
    status, made = http("POST", port, "/local/session", {"hosts": [host], "passphrase": "correct horse"}, same)
    shown = made.get("sessions", [])
    # Bug caught: a session's key handed to the page, where anything at its origin could take it.
    check("the right one makes a session, shown without its key", status == 200 and len(shown) == 1 and not {"key", "compact"} & set(shown[0]), made)
    check("an hour at most, as viewing every hour says", status == 200 and shown and shown[0]["expires_at"] - time.time() <= 3600 + 5, shown)
    path = f"/v0/owner-view/{agent}"
    view = lambda: http("POST", port, "/local/read", {"domain": host, "path": path}, same)[1].get("view")  # noqa: E731
    check("it reads her agent's view at its host with that session", wait_until(view, SIGNET_HEARS_SECONDS))
    status, opened = http("POST", port, "/local/open", {"about": f"splint owner view for {agent}", "sealed": view() or ""}, same)
    check("and opens it here with the reading key, as her agent signed it", status == 200 and str(opened.get("plain", "")).count(".") == 2, opened)
    check("a page elsewhere can't read with it", http("POST", port, "/local/read", {"domain": host, "path": path})[0] == 403)
    for_her_agent = {"agent": agent, "address": ola.address, "kind": "person_text", "signed": "a.b.c"}
    check("nor leave anything at its host for her agent with it", http("POST", port, "/local/mail", for_her_agent)[0] == 403)
    http("POST", port, "/local/viewing", {"every": "every_time"}, same)
    status, again = http("POST", port, "/local/opened", {}, same)
    check("with viewing every time, opening the page again needs a touch again", status == 200 and again.get("sessions") == [], again)
    # Bug caught: something left at a host for her agent with no session of hers there to leave it by.
    check("and with no session at her agent's host, her page leaves nothing there and is told to sign in again", http("POST", port, "/local/mail", for_her_agent, same)[0] == 401)

    # Bug caught: a locked key file read as having no sign-in and its code already set, as reading it
    # opened the key, so the page never asked for the code and setting it failed.
    here = http("GET", port, "/local/here", headers=same)[1].get("here", {})
    check("a locked key file is named as one, with no passphrase given", "passphrase" in str(here.get("sign_in") or ""), here)
    check("and its owner ID is said to have no recovery code yet", here.get("recovery_not_set") is True, here)
    check("the code isn't set without its passphrase", http("POST", port, "/local/recovery", {}, same)[0] == 422)
    status, made = http("POST", port, "/local/recovery", {"passphrase": "correct horse"}, same)
    check("with it, the code is made and shown once", status == 200 and bool(made.get("code")), status)
    check("and it's set from then on", http("GET", port, "/local/here", headers=same)[1].get("here", {}).get("recovery_not_set") is False)
    # Before ola is paused below, as a paused agent can't read where its person gets paid.
    she_signs_where_she_gets_paid_on_her_controls(signup, ola, port, same, work)
    a_place_approved_with_no_session_is_left_by_the_sign_ins_own_proof(signup, ola, port, same)
    later = an_approval_signs_only_the_asks_shown(signup, ola, port, same)
    the_page_lists_and_codes_what_one_approval_signs(signup, port, same, later)
    the_page_signs_what_it_listed_when_she_began(signup, ola, port, same, work)


def a_held_step_is_asked_for_only_while_held(signup: Signup, ivy) -> None:
    status, _ = ivy.api("POST", "/v0/asks", {"changes": [{"change": "step", "request": "a" * 64, "operation": "accept"}]})
    # Bug caught: an ask for a step that isn't waiting, which Signet would call done at once.
    check("an ask for a step that isn't held for the owner is refused", status == 400, status)
    status, _ = ivy.api("POST", "/v0/asks", {"changes": [{"change": "step", "request": "a" * 64, "operation": "accept"}, {"change": "paused", "to": True}]})
    check("and a step is alone in its ask", status == 400, status)


def what_a_program_with_no_terminal_gets(signup: Signup, ivy, port: int) -> None:
    done = signup.walk.run_as("ivy", f"splint controls {signup.open_host} --no-open")
    opening = re.search(r"#open=([0-9A-Za-z_-]+)", done.stdout)
    status, traded = http("POST", port, "/local/page", {"opening": opening.group(1) if opening else ""}, {"Sec-Fetch-Site": "same-origin"})
    # Bug caught: --no-open withholding the link from whatever ran it, which protects nothing, as
    # anything running as the person gets an opening on the socket, and costs an agent setting up
    # where it can't open a browser.
    check("splint controls --no-open gives the link it would open, which a page trades once", status == 200 and bool(traded.get("key")), done.stdout + done.stderr)
    here = lambda: http_on_socket("GET", socket_of(ivy), "/v0/here")[1]  # noqa: E731
    check("control: ivy's person has no recovery code yet", here().get("recovery_not_set") is True, here())
    done = signup.walk.run_as("ivy", "splint computer recovery", "")
    # Bug caught: the recovery code printed into the output of a program with no terminal, such as an
    # agent's shell, and so into its transcript.
    check("splint computer recovery run with no terminal makes no code", done.returncode != 0 and here().get("recovery_not_set") is True, done.stdout + done.stderr)


def an_agent_asks_for_its_controls_while_its_host_is_up(signup: Signup, port: int) -> tuple:
    """Noa joins and asks while her host answers, for her person to approve once it doesn't."""
    noa = signup.device("noa")
    on_the_computer(noa, port)
    check("control: noa joins on her own", signup.walk.run_as("noa", f"splint join noa~{signup.open_host}").returncode == 0)
    noa.address = f"noa~{signup.open_host}"
    asked = asked_without_waiting(signup, "noa", "splint controls --json")
    check("control: noa's ask for her controls waits on her person's computer", asked.get("status") == "waiting" and wait_until(lambda: asked.get("id") in waiting_ids(noa), 60), asked)
    return noa, asked.get("id", "")


def an_approval_with_its_host_down_is_still_done(signup: Signup, ivy, port: int, noa, noas_ask: str) -> None:
    asked = json.loads(signup.walk.run_as("ivy", "splint ask --resume --json").stdout or "{}")
    check("control: ivy asks to be turned back on", asked.get("status") == "waiting", asked)
    # Bug caught: the day an ask for controls lasts, for a link handed over in chat, given to every ask.
    ends_in = ivy.api("GET", f"/v0/asks/{asked.get('id', '')}")[1].get("expires_at", 0) - time.time()
    check("an ask for anything but controls still lasts an hour", 0 < ends_in <= 3600, ends_in)
    agent = ivy.api("GET", "/v0/identity")[1].get("agent_id", "")
    at_host = lambda: int(signup.sql("hana", f"SELECT count(*) FROM owner_mail WHERE agent_id = '{agent}'") or 0)  # noqa: E731
    kept = lambda: [file.name for file in (ivy.dot / "not-at-host").glob("*.where-paid.json")]  # noqa: E731
    left_before = at_host()
    host_is_down(signup)
    try:
        # A yes for each approval: the place to be paid she asked for earlier goes alone, first.
        approved = signup.walk.run_as("ivy", "splint computer approve", "yes\nyes\n")
        check("control: her person approves it", approved.returncode == 0 and "Approved" in approved.stdout, approved.stdout + approved.stderr)
        status, outcome = http_on_socket("GET", socket_of(ivy), f"/v0/asks/{asked.get('id', '')}")
        # Bug caught: rules her Signet took, kept for the host until it's back, told to an agent
        # waiting with --wait as "not approved, so nothing changed", inviting another ask and touch.
        check("an approval her Signet took while her host is down is done, not 'not approved'", (outcome or {}).get("status") == "done", outcome)
        check("control: the place she approved with it, which only her Signet took, is kept here for its host, sealed", len(kept()) == 1 and isinstance(json.loads((ivy.dot / "not-at-host" / kept()[0]).read_text()).get("sealed"), str), kept())
        _, signed = http_on_socket("POST", socket_of(noa), "/v0/approve", {"ids": [noas_ask], "passphrase": PASSPHRASE})
        check("control: noa's person approves her controls, and is given the answer to pass on, as her host kept none", signed.get("approved") == 1 and len(signed.get("pass_on", [])) == 1, signed)
    finally:
        host_is_back(signup)
    # Her Signet takes an owner's answer only with its host there, so she takes it up once it's back.
    where = lambda: json.loads(signup.walk.run_as("noa", f"splint ask {noas_ask} --json").stdout or "{}")  # noqa: E731
    # Bug caught: an agent on its person's computer taking up their answer only from its host, so
    # one its host didn't keep left it waiting until its person pasted it a splint finish line.
    check("an agent on that computer takes up the answer approved there, which its host never kept", wait_until(lambda: where().get("status") == "done", SIGNET_HEARS_SECONDS) and noa.api("GET", "/v0/identity")[1].get("owner_confirmed") is True, where())
    # Bug caught: what Splint on the computer kept for a host never reaching it, as the proof it was
    # first sent with is long out of date and nothing here signed another. Her controls page calling
    # is what sends it again, by a proof her sign-in on this computer signs then for the same sealed bytes.
    page = {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty"}

    def reached_its_host() -> bool:
        http("GET", port, f"/relay/{signup.open_host}/.well-known/splint/host", headers=page)
        return at_host() == left_before + 1 and kept() == []

    check("once her host is back, the place kept for it reaches it the next time her controls call, and is kept here no more", wait_until(reached_its_host, 60), (left_before, at_host(), kept()))


def a_contact_is_shown_with_what_it_lets_in(signup: Signup, mal) -> None:
    """Issue 889. Bug caught: the terminal, all a person with a key file sees, listing a contact
    without the agent ID its rules would hold or that their words come in, while a Touch ID prompt
    names both. A filter's owners come from the same words, which owner-key's own test shows."""
    agent = mal.api("GET", "/v0/identity")[1].get("agent_id", "")
    asked = signup.walk.run_as("ivy", f"splint ask --contact {mal.address} --text --json")
    check("control: ivy asks to let mal in with words of its own", json.loads(asked.stdout or "{}").get("status") == "waiting", asked.stdout + asked.stderr)
    said_no = signup.walk.run_as("ivy", "splint computer approve", "no\n")
    listed = said_no.stdout + said_no.stderr
    check("the terminal names the agent ID the contact's rules would hold, as the prompt does", bool(agent) and agent in listed, listed)
    check("and that their words come in", "with words of their own" in listed, listed)
    check("and a no signs nothing", "Nothing was signed" in listed, listed)


def controls_say_why_splint_here_wont_start(signup: Signup, port: int) -> None:
    """Bug caught: splint controls saying only that Splint here isn't running when it refuses to start,
    as when another user on a Windows computer has taken its pipe's name, so the person never learns
    why, or that a keeper's restarts after the refusal hide it. Here something in the way of its socket
    is the refusal."""
    zed = signup.device("zed")
    on_the_computer(zed, port)
    socket_of(zed).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    socket_of(zed).write_text("not a socket")
    done = signup.walk.run_as("zed", f"splint controls {signup.open_host} --no-open")
    check("splint controls says why Splint here won't start", done.returncode != 0 and "in the way of Splint's socket" in done.stderr and "#open=" not in done.stdout, done.stdout + done.stderr)
    socket_of(zed).unlink()
    signup.walk.run_as("zed", "splint stop")


def una_becomes_an_owner_on_her_page_with_a_passphrase(signup: Signup, port: int, work) -> None:
    """The page's own way of making an owner ID, in a real browser, where no chip keeps the sign-in.
    Bug caught: "Create your owner ID" making a plain key file, which the page itself then can't sign
    with, or asking for a passphrase with no word on why."""
    una = signup.device("una")
    on_the_computer(una, port)
    started = signup.walk.run_as("una", "splint computer start")
    check("control: Splint starts on una's computer, with no sign-in yet", started.returncode == 0 and wait_until(lambda: computer_is_up(una), 60) and sign_in_of(una).get("sign_in") is None, started.stdout + started.stderr)
    opened = signup.walk.run_as("una", f"splint controls {signup.open_host} --no-open")
    link = re.search(r"http://localhost:\d+/owner#open=[0-9A-Za-z_-]+", opened.stdout)
    check("control: una opens her controls on her computer", link is not None, opened.stdout + opened.stderr)
    if link is None:
        return
    browser = Browser(work / "una")
    try:
        browser.goto(link.group(0))
        check("the page asks her to choose a passphrase, typed twice", browser.wait_for("!!document.getElementById('new-passphrase') && !!document.getElementById('new-passphrase-again')", 30), browser.text())
        check("and says why: it locks her sign-in's key file", "locks your sign-in's key file" in browser.text(), browser.text())
        time.sleep(1)
        check("control: she clicks Create with nothing typed", browser.click("body", "Create your owner ID"))
        check("which makes nothing, and says a passphrase is needed", browser.wait_for("document.getElementById('told').textContent.includes('passphrase')", 20) and sign_in_of(una).get("owner") is None, browser.text())
        browser.type_into("#new-passphrase", PASSPHRASE)
        browser.type_into("#new-passphrase-again", PASSPHRASE)
        time.sleep(1)
        check("control: she clicks Create with one chosen", browser.click("body", "Create your owner ID"))
        check("she's an owner, on her controls", browser.wait_for("!!document.getElementById('who') && document.querySelector('h1').textContent === 'Your controls'", 60), browser.text())
        here = sign_in_of(una)
        check("with a sign-in locked by the passphrase she chose", "locked with a passphrase" in str(here.get("sign_in")) and here.get("plain_key_file") is False, here)
        sessions = http("GET", port, "/local/here", headers=page_key(una, port))[1].get("sessions", [])
        # Bug caught: the passphrase asked for again, or the first sign-in failing, in the same click.
        check("and typing it once also signed her in, with nothing asked twice", len(sessions) == 1, sessions)
        check("from then on the page asks for it to approve, with no warning of a plain key file", browser.wait_for("!!document.getElementById('passphrase-here')", 20) and browser.eval("!document.getElementById('plain-key-file')") is True, browser.text())
    finally:
        browser.close()


def locking_a_plain_key_file_keeps_the_owner_and_ends_a_typed_yes(signup: Signup, ivy) -> None:
    """Issue 892. Ivy's person has a plain key file, as one from before a passphrase was the default is,
    and an ask waiting. Bug caught: no way to lock it short of a new owner ID; and, once it's locked, a
    program running as them still getting something signed with no passphrase."""
    owner = sign_in_of(ivy).get("owner")
    waiting = waiting_ids(ivy)
    # As an earlier version left one: the same files, with no mark beside the key that it's a sign-in.
    # Bug caught: a sign-in from before the mark taken for an owner key kept apart, and never locked.
    (ivy.dot / "computer" / "owner" / "owner.sign-in").unlink()
    check("control: an ask waits, and the sign-in is a plain key file", bool(waiting) and sign_in_of(ivy).get("plain_key_file") is True, sign_in_of(ivy))
    short = signup.walk.run_as("ivy", "splint computer lock", "short\nshort\n")
    check("a passphrase under 8 characters locks nothing", short.returncode != 0 and sign_in_of(ivy).get("plain_key_file") is True, short.stdout + short.stderr)
    locked = signup.walk.run_as("ivy", "splint computer lock", CHOSEN)
    here = sign_in_of(ivy)
    check("splint computer lock locks it with a passphrase", locked.returncode == 0 and "locked with a passphrase" in str(here.get("sign_in")) and here.get("plain_key_file") is False, locked.stdout + locked.stderr)
    check("and the owner ID is the same", bool(owner) and here.get("owner") == owner, here)

    piped = signup.walk.run_as("ivy", "splint computer approve", "yes\n")
    check("a program piping a yes to splint computer approve gets nothing signed", piped.returncode != 0 and "Approved" not in piped.stdout, piped.stdout + piped.stderr)
    posted = [http_on_socket("POST", socket_of(ivy), "/v0/approve", {"ids": waiting} | given)[1] for given in ({}, {"passphrase": "yes"}, {"passphrase": "not the one she chose"})]
    check("nor one approving its own ask IDs on the socket, with no passphrase or a wrong one", all(one.get("approved") == 0 and one.get("error") for one in posted), posted)
    direct = signup.walk.run_as("ivy", f"{OWNER_KEY} access --dir $HOME/.splint/computer/owner --host {signup.open_host} --method GET --path /v0/owner")
    check("nor one running owner-key itself", direct.returncode != 0 and direct.stdout.strip() == "", direct.stdout + direct.stderr)
    check("and the key file it could copy is no key without the passphrase", (ivy.dot / "computer" / "owner" / "owner.key").read_bytes().startswith(b"{"))
    check("so the ask still waits", waiting_ids(ivy) == waiting, waiting_ids(ivy))
    logged = said_in_its_log(ivy)
    approved = signup.walk.run_as("ivy", "splint computer approve", f"{PASSPHRASE}\n")
    check("and her person approves it with the passphrase", approved.returncode == 0 and "Approved 1" in approved.stdout, approved.stdout + approved.stderr)
    check("with no more said of a plain key file, at the terminal or in the log", "Warning" not in approved.stderr and said_in_its_log(ivy) == logged, approved.stderr)


def controls_leave_splint_here_stopped_after_splint_stop(signup: Signup, ivy) -> None:
    """Bug caught: splint controls after the person's splint stop waiting for a Splint here it left
    stopped, then saying it didn't start in time, or giving a refusal from an earlier start as why."""
    stopped = signup.walk.run_as("ivy", "splint stop")
    check("control: ivy's person stops everything here", stopped.returncode == 0 and not computer_is_up(ivy), stopped.stdout + stopped.stderr)
    done = signup.walk.run_as("ivy", f"splint controls {signup.open_host} --no-open")
    check("splint controls says Splint here is stopped and to run splint start, and leaves it stopped", done.returncode != 0 and "splint start" in done.stderr and "in time" not in done.stderr and not computer_is_up(ivy), done.stdout + done.stderr)


def main() -> None:
    work = e2e.short_scratch("splint-asks-")
    signup = Signup(work)
    port = e2e.free_port()
    try:
        ivy = an_agent_asks_for_its_controls_and_one_approval_sets_them_up(signup, port)
        the_agent_asks_for_exact_changes_and_learns_when_they_hold(signup, ivy)
        the_agent_asks_where_its_person_gets_paid(signup, ivy)
        a_page_elsewhere_and_a_changed_ask_get_nothing(signup, ivy, port)
        mal = a_strangers_ask_is_named_and_another_owners_agent_is_refused(signup, ivy, port)
        the_owner_page_here_signs_only_with_someone_there(signup, ivy, port)
        a_website_opening_a_link_puts_nothing_in_front_of_the_person(signup, ivy, work, port)
        a_held_step_is_asked_for_only_while_held(signup, ivy)
        what_a_program_with_no_terminal_gets(signup, ivy, port)
        a_passphrase_lets_the_page_sign_and_read_until_viewing_says(signup, e2e.free_port(), work)
        una_becomes_an_owner_on_her_page_with_a_passphrase(signup, e2e.free_port(), work)
        controls_say_why_splint_here_wont_start(signup, e2e.free_port())
        # Last, as a host that starts again lets no more agents join from here for a while.
        noa, noas_ask = an_agent_asks_for_its_controls_while_its_host_is_up(signup, e2e.free_port())
        an_approval_with_its_host_down_is_still_done(signup, ivy, port, noa, noas_ask)
        a_contact_is_shown_with_what_it_lets_in(signup, mal)
        locking_a_plain_key_file_keeps_the_owner_and_ends_a_typed_yes(signup, ivy)
        controls_leave_splint_here_stopped_after_splint_stop(signup, ivy)
    finally:
        signup.walk.stop_everything()
        # Bug caught: splint stop leaving Splint on the computer running, holding its port and socket.
        left = [line.split()[0] for line in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout.splitlines()
                if str(work) in line and "computer run" in line]
        check("splint stop stops Splint on the computer too, so the run leaves none running", left == [], left)
        for pid in left:
            subprocess.run(["kill", pid], capture_output=True)
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall agent ask checks passed", flush=True)


if __name__ == "__main__":
    main()

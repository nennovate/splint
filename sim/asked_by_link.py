#!/usr/bin/env python3
"""An agent that asks for its controls by a link takes up only an answer from someone the link reached.

Rae joins on her own and asks for her controls with `splint controls`, on a machine her person isn't
at. Splint on that machine takes her ask, as it does on any Mac or Linux machine an agent runs on, and
she still gets a link, in plain words, that carries the ask her key signed, and gets it again from
`splint ask ID` while it waits. The link she gets is the one for Splint on her person's computer
alone, as owners sign only there (Nenye, 2026-11-21), and no host serves a page to sign on. It lasts
an hour, and no agent can make it last longer. Mallory isn't her person and never sees the
link: she knows only Rae's address, reads Rae's public ID from her host, signs controls for her with her
own owner ID, and leaves them there, before Pat answers and after. Rae's `splint auto`, `splint finish`
and `splint ask ID` take none of it, and she stays unclaimed. Pat, whom the link reached, approves it
on Splint on her computer, which leaves the answer where the ask's ID says, with a MAC by that ID, and
Rae takes it up with nothing pasted. Pat's first approval at her terminal makes her sign-in, a key file
locked with the passphrase she chooses then, as it is by default with no chip, so a program running
as her that pipes a yes to the next approval gets nothing signed (issue 892). Two people's answers
there when the agent looks get neither taken, and a stranger's answer isn't counted as a third. Asking
again ends the link before, so an answer left under it is never taken, and an answer already there is
taken up first, so asking again doesn't lose it. An answer
the agent's host doesn't keep, here as it's down, is given to the person to pass on, and the agent
finishes with it. When that host starts again with the owner page settings of before, an HTTPS page at
a name of its own, an agent there is still given only the link to Splint on its person's computer.

    python3 sim/asked_by_link.py

Not shown: an answer's MAC and place checked against Rust and Go, which the shared vectors do; a host
from before answers were kept where an ask says, which the host being down stands in for; a real
model; or two OS users (homes under one user). Keys are software key files, and every sign-in on a
computer is one too, locked with a passphrase. No agent has network limits.
"""

import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request

import e2e
from agent_signup import FINISH_LINE, SIGNET_HEARS_SECONDS, Signup
from e2e import check, wait_until

SAME = {"Sec-Fetch-Site": "same-origin"}
PASSPHRASE = "correct horse"
# Splint on a person's computer, which `splint stop` leaves running for someone with no agent here.
COMPUTERS: list = []
# A link as `splint controls` prints one in words: its name, the page it opens, and what the page
# reads after the #, the ask and the agent's address.
LINK = re.compile(r"^(link|computer_link): (\S+)#ask=([^&\s]+)&at=(\S+)$", re.M)
ASK_ID = re.compile(r"\bask ([0-9a-f]{32})\b")


def local(method: str, port: int, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Host": f"localhost:{port}", "Content-Type": "application/json", **SAME, **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:
            return answer.status, json.loads(answer.read() or b"{}")
    except (urllib.error.URLError, ConnectionError) as failed:
        return getattr(failed, "code", 0), {}


def page_key(person, port: int) -> dict:
    """The header a page the person opened sends: it trades a one-time opening, which only a program
    run as them gets on the socket, for the page key."""
    _, opened = e2e.http_on_socket("POST", person.dot / "run" / "computer.sock", "/v0/page")
    _, traded = local("POST", port, "/local/page", {"opening": opened.get("opening", "")})
    return {"Splint-Page": traded.get("key", "")}


def here(person, port: int) -> dict:
    """What the person's own page reads of who they are, with its page key."""
    return local("GET", port, "/local/here", headers=page_key(person, port))[1]


def on_their_computer(signup: Signup, name: str, port: int):
    """A person with Splint on their own computer, which signs with a key file, never a prompt."""
    person = signup.device(name)
    person.env["SPLINT_COMPUTER_PORT"] = str(port)
    person.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
    COMPUTERS.append(person)
    # Bug caught: Splint on the computer failing to start for someone who has only installed it.
    started = signup.walk.run_as(name, "splint computer start")
    check(f"Splint starts on {name}'s computer, who has only installed it", started.returncode == 0, started.stdout + started.stderr)
    check(f"control: and serves {name}'s page", wait_until(lambda: local("GET", port, "/local/here", headers=page_key(person, port))[0] == 200, 60))
    return person


def sign_in_of(person, port: int) -> str:
    """How the person's sign-in on their computer is held, or nothing if it isn't made yet."""
    return str(here(person, port).get("here", {}).get("sign_in") or "")


def approves(signup: Signup, person, port: int):
    """The person approves what waits, at a terminal. Their first approval makes their sign-in and has
    them choose its passphrase, typed twice, and each later one has them type it once."""
    typed = f"{PASSPHRASE}\n" if sign_in_of(person, port) else f"{PASSPHRASE}\n{PASSPHRASE}\n"
    return signup.walk.run_as(person.name, "splint computer approve", typed)


def link_reaches(signup: Signup, person, port: int, asked: dict, address: str) -> None:
    """The person opens the agent's link on their computer and approves with their passphrase."""
    status, _ = local("POST", port, "/local/asks", {"ask": asked.get("ask", ""), "address": address})
    check(f"control: the link hands {person.name}'s computer the ask", status == 200, status)
    first = not sign_in_of(person, port)
    if not first:
        piped = signup.walk.run_as(person.name, "splint computer approve", "yes\n")
        # Issue 892. Bug caught: a sign-in made plain by default, so the person's own fooled agent,
        # running as them, approves whatever it asked by piping a yes.
        check(f"a program piping a yes on {person.name}'s computer gets nothing signed", piped.returncode != 0 and "Approved" not in piped.stdout, piped.stdout + piped.stderr)
    approved = approves(signup, person, port)
    check(f"control: {person.name} approves it", approved.returncode == 0 and "Approved 1" in approved.stdout, approved.stdout + approved.stderr)
    if first:
        check(f"{person.name}'s first approval made a sign-in locked with the passphrase chosen then", "locked with a passphrase" in sign_in_of(person, port), sign_in_of(person, port))


def stranger_answers(signup: Signup, mallory, host: str, handle: str, control: bool = True) -> None:
    """Mallory knows only the address: everything else she needs is public at the agent's host."""
    status, found = e2e.http("GET", f"http://{host}/.well-known/splint/agents/{handle}")
    key = e2e.first_keys_of(found.get("identity", "")) if status == 200 else ""
    signed = signup.authorize(mallory, f"splint authorize {handle}~{host} {key} --name mallory")
    if not control:
        return
    check(f"control: mallory signs controls for {handle} and leaves them at her host", signed.returncode == 0, signed.stdout + signed.stderr)
    said = FINISH_LINE.search(signed.stdout)
    owner = said.group(1) if said else ""
    kept = e2e.http("GET", f"http://{host}/v0/join-answers/{key}/{owner}")[1].get("answer", "")
    check("control: her answer is kept for that key", bool(kept))
    # And one that claims to answer an ask, at a place and with a MAC she can only guess.
    guessed = {"agent_key": key, "answer": kept, "kept_at": os.urandom(16).hex(), "ask_mac": os.urandom(32).hex()}
    check("control: and one at a guessed place, with a guessed MAC, which the host can't check", e2e.http("PUT", f"http://{host}/v0/join-answers", guessed)[0] == 200)


def id_of(identity: str) -> str:
    return "splint1" + hashlib.sha256(e2e.decode(identity.split("~")[0])).hexdigest() if identity else ""


def confirmed(agent) -> bool:
    return agent.api("GET", "/v0/identity")[1].get("owner_confirmed") is True


def lasts(agent, ask: str) -> float:
    """How many seconds from now an ask of this agent's ends, as its Signet signed it."""
    return agent.api("GET", f"/v0/asks/{ask}")[1].get("expires_at", 0) - time.time()


def a_stranger_cant_take_over_an_agent_asking_by_link(signup: Signup, port: int):
    host = signup.open_host
    rae = signup.device("rae")
    # Splint on the machine rae runs on, where nobody is: its own port, and a key file for a sign-in,
    # so no run puts a prompt on a screen.
    rae.env["SPLINT_COMPUTER_PORT"] = str(e2e.free_port())
    rae.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
    COMPUTERS.append(rae)
    mallory = signup.device("mallory")
    check("control: rae joins on her own", signup.walk.run_as("rae", f"splint join rae~{host}").returncode == 0)
    said = signup.walk.run_as("rae", "splint controls")
    links = {name: (page, ask, at) for name, page, ask, at in LINK.findall(said.stdout)}
    taken = lambda: [one.get("address") for one in e2e.http_on_socket("GET", rae.dot / "run" / "computer.sock", "/v0/asks")[1].get("asks", [])]  # noqa: E731
    check("control: Splint on rae's own machine took her ask", wait_until(lambda: taken() == [f"rae~{host}"], 20), said.stdout + said.stderr)
    # Bugs caught: an agent on a machine of its own given no link, as Splint there took its ask and
    # waited for a person who is somewhere else; and one that reads words, not JSON, told to give its
    # person a link that was never printed.
    check("splint controls still gives rae a link to hand her person, in plain words", said.returncode == 0 and "computer_link" in links, said.stdout + said.stderr)
    page, ask, at = links.get("computer_link", ("", "", ""))
    _, host_says = e2e.http("GET", f"http://{host}/.well-known/splint/host")
    check("control: her host names no owner page", "owner_page" not in host_says and "owner_page_rp_id" not in host_says, host_says)
    check("so the only link she's given opens on Splint on her person's computer", set(links) == {"computer_link"} and page.startswith("http://localhost:"), links)
    found = ASK_ID.search(said.stdout)
    asked = {"ask": ask, "id": found.group(1) if found else ""}
    # Bug caught: a link that went astray making whoever approves first her owner for a whole day.
    check("her ask, and so its link, lasts an hour", 0 < lasts(rae, asked["id"]) <= 3600, lasts(rae, asked["id"]))
    longer = signup.walk.run_as("rae", "splint controls --hours 2 --json")
    check("and she can't ask for a link that lasts longer", longer.returncode != 0, longer.stdout + longer.stderr)
    status, _ = rae.api("POST", "/v0/asks", {"changes": [{"change": "controls", "delegate": ""}], "hours": 24})
    check("nor can anything that skips splint and calls her Signet", status == 400, status)

    stranger_answers(signup, mallory, host, "rae")
    # Bug caught: an agent asking by link taking whichever single owner's answer was kept for its key,
    # so anyone who knew its address became its owner, held its backup and read its owner's view.
    signup.walk.run_as("rae", "splint auto --once")
    finished = signup.walk.run_as("rae", "splint finish")
    check("splint finish takes nothing a stranger left", finished.returncode != 0, finished.stdout + finished.stderr)
    shown = json.loads(signup.walk.run_as("rae", f"splint ask {asked.get('id', '')} --json").stdout or "{}")
    check("and her ask still waits", shown.get("status") == "waiting", shown)
    # Bug caught: an agent that didn't keep its link left with no way to get it again but a new ask.
    check("with the same link to it, for as long as it waits, and still none to a host's page", bool(ask) and shown.get("computer_link") == f"{page}#ask={ask}&at={at}" and "link" not in shown, shown)
    check("so rae stays unclaimed, with no owner she didn't ask", not wait_until(lambda: confirmed(rae), 20), rae.api("GET", "/v0/identity")[1])

    pat = on_their_computer(signup, "pat", port)
    # What pat's browser hands her computer when she opens the link: the ask and address it carries.
    link_reaches(signup, pat, port, asked, at)
    # Bug caught: a stranger's answer blocking the real person's, counted as a second owner.
    done = signup.walk.run_as("rae", "splint auto --once")
    check("splint auto takes up pat's answer, with nothing pasted", wait_until(lambda: confirmed(rae), SIGNET_HEARS_SECONDS), done.stdout + done.stderr)
    pat_id = here(pat, port).get("identity")
    _, found = e2e.http("GET", f"http://{host}/.well-known/splint/agents/rae")
    check("and acts for pat, whom the link reached", bool(pat_id) and found.get("owner_identity") == pat_id, found.get("owner_identity", "")[:60])
    # Bug caught: whoever approved first by a link becoming the owner with nothing naming them, so an
    # agent the wrong person claimed reported only that its controls were set.
    owner_id = f"splint1{hashlib.sha256(e2e.decode(pat_id or '')).hexdigest()}"
    standing = json.loads(signup.walk.run_as("rae", "splint status --json").stdout or "{}")
    check("her status names the owner ID that approved", (standing.get("controls") or {}).get("owner_id") == owner_id, standing.get("controls"))
    check("and so do its words", owner_id in signup.walk.run_as("rae", "splint status").stdout)

    stranger_answers(signup, mallory, host, "rae", control=False)
    signup.walk.run_as("rae", "splint auto --once")
    _, after = e2e.http("GET", f"http://{host}/.well-known/splint/agents/rae")
    check("a stranger answering afterwards changes nothing", after.get("owner_identity") == pat_id, after.get("owner_identity", "")[:60])
    return mallory, pat


def a_link_that_reached_two_people_gets_neither(signup: Signup, mallory, pat, pat_port: int) -> None:
    host = signup.open_host
    sam = signup.device("sam")
    check("control: sam joins on his own", signup.walk.run_as("sam", f"splint join sam~{host}").returncode == 0)
    stranger_answers(signup, mallory, host, "sam")
    signup.walk.run_as("sam", "splint auto --once")
    # Bug caught: splint auto taking an answer for an agent that never asked for one.
    check("splint auto takes nothing for an agent that isn't asking", not confirmed(sam))

    # His own splint auto would take the first answer before the second came, so he runs finish here.
    sam.shell('pkill -f "$HOME/.splint/bin/splint auto" || true', signup.walk.work, timeout=30)
    status, asked = sam.api("POST", "/v0/asks", {"changes": [{"change": "controls", "delegate": ""}]})
    check("control: sam asks for his controls, as his link does", status == 200, status)
    quin_port = e2e.free_port()
    quin = on_their_computer(signup, "quin", quin_port)
    link_reaches(signup, pat, pat_port, asked, f"sam~{host}")
    link_reaches(signup, quin, quin_port, asked, f"sam~{host}")
    # Bug caught: anyone holding one person's answer, which is public by their owner ID, leaving it
    # again with no MAC or at another place in place of the one the ask named, so the agent takes the
    # other person's alone.
    pat_id = id_of(here(pat, pat_port).get("identity", ""))
    key = sam.api("GET", "/v0/identity")[1].get("key", "")
    pats = e2e.http("GET", f"http://{host}/v0/join-answers/{key}/{pat_id}")[1].get("answer", "")
    for elsewhere in ({}, {"kept_at": os.urandom(16).hex(), "ask_mac": os.urandom(32).hex()}):
        status, _ = e2e.http("PUT", f"http://{host}/v0/join-answers", {"agent_key": key, "answer": pats} | elsewhere)
        check("control: mallory leaves pat's answer again, as anyone can", status == 200, status)
    # Bug caught: a link that reached two people handing the agent to whichever answered first, and
    # a stranger's answer counted among them.
    refused = signup.walk.run_as("sam", "splint finish")
    check("sam takes neither of the two answers, and names exactly those two", refused.returncode != 0 and "2 owners answered" in refused.stderr and refused.stderr.count("splint1") == 2, refused.stderr)
    check("and stays a stand-in's", not confirmed(sam))


def stops_its_own_auto(signup: Signup, agent) -> None:
    """So what's taken up here is what the command under test took up, not the agent's `splint auto`."""
    agent.shell('pkill -f "$HOME/.splint/bin/splint auto" || true', signup.walk.work, timeout=30)


def controls_asked(signup: Signup, agent) -> dict:
    """The agent's `splint controls`, with the ask as its link carries it."""
    said = json.loads(signup.walk.run_as(agent.name, "splint controls --json").stdout or "{}")
    return said | {"ask": agent.api("GET", f"/v0/asks/{said.get('id', '')}")[1].get("ask", "")}


def asking_again_ends_the_link_before(signup: Signup, pat, port: int) -> None:
    """A link that went astray stays a way to become the agent's owner until something ends it."""
    host = signup.open_host
    vic = signup.device("vic")
    vic.env["SPLINT_COMPUTER_PORT"] = str(e2e.free_port())
    vic.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
    COMPUTERS.append(vic)
    check("control: vic joins on his own", signup.walk.run_as("vic", f"splint join vic~{host}").returncode == 0)
    stops_its_own_auto(signup, vic)
    astray, fresh = controls_asked(signup, vic), controls_asked(signup, vic)
    check("control: each ask for controls is its own, with its own link", bool(astray["ask"]) and astray["id"] != fresh["id"], (astray, fresh))
    status_of = lambda asked: vic.api("GET", f"/v0/asks/{asked['id']}")[1].get("status")  # noqa: E731
    check("asking again ends the ask before it, and leaves the new one waiting", (status_of(astray), status_of(fresh)) == ("not_approved", "waiting"), (status_of(astray), status_of(fresh)))
    # Bug caught: every link an agent ever handed out staying a live way to claim it for a day.
    link_reaches(signup, pat, port, astray, f"vic~{host}")
    signup.walk.run_as("vic", "splint auto --once")
    check("an answer left under the ended link is never taken", not wait_until(lambda: confirmed(vic), 10), vic.api("GET", "/v0/identity")[1])
    link_reaches(signup, pat, port, fresh, f"vic~{host}")
    signup.walk.run_as("vic", "splint auto --once")
    check("control: the newest link's answer is taken up", wait_until(lambda: confirmed(vic), SIGNET_HEARS_SECONDS))

    wes = signup.device("wes")
    wes.env["SPLINT_COMPUTER_PORT"] = str(e2e.free_port())
    wes.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
    COMPUTERS.append(wes)
    check("control: wes joins on his own", signup.walk.run_as("wes", f"splint join wes~{host}").returncode == 0)
    stops_its_own_auto(signup, wes)
    answered = controls_asked(signup, wes)
    link_reaches(signup, pat, port, answered, f"wes~{host}")
    check("control: pat's answer waits, as nothing here has looked", not confirmed(wes))
    # Bug caught: an agent whose person approved just before it asked again ending that ask, so what
    # they approved was lost and they had to approve again.
    again = controls_asked(signup, wes)
    check("asking again takes up an answer already there, and asks nothing new", again.get("status") == "done" and again.get("id") == answered["id"] and wait_until(lambda: confirmed(wes), SIGNET_HEARS_SECONDS), again)


def an_answer_its_host_didnt_keep_is_given_to_pass_on(signup: Signup, pat, port: int) -> None:
    """The agent's host is down when the person approves, as one too old to keep an answer where an ask
    says would refuse it. Bug caught: the answer dropped with nothing said, so an agent elsewhere waits
    for good while its person was told it hears from its host."""
    host = signup.open_host
    uma = signup.device("uma")
    uma.env["SPLINT_COMPUTER_PORT"] = str(e2e.free_port())
    uma.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
    COMPUTERS.append(uma)
    check("control: uma joins on her own", signup.walk.run_as("uma", f"splint join uma~{host}").returncode == 0)
    # Joined now, as a host that starts again lets no more agents join from here for a while.
    kit = signup.device("kit")
    kit.env["SPLINT_COMPUTER_PORT"] = str(e2e.free_port())
    kit.env["SPLINT_COMPUTER_SIGN_IN"] = "file"
    COMPUTERS.append(kit)
    check("control: kit joins on her own", signup.walk.run_as("kit", f"splint join kit~{host}").returncode == 0)
    said = json.loads(signup.walk.run_as("uma", "splint controls --hours 1 --json").stdout or "{}")
    _, asked = uma.api("GET", f"/v0/asks/{said.get('id', '')}")
    # Bug caught: splint controls reading --hours as a host's name, and opening controls there.
    check("uma asks for her controls with --hours 1, and her ask lasts an hour", said.get("status") == "waiting" and bool(asked.get("ask")) and 0 < lasts(uma, said.get("id", "")) <= 3600, said)
    status, _ = local("POST", port, "/local/asks", {"ask": asked.get("ask", ""), "address": f"uma~{host}"})
    check("control: the link hands pat's computer the ask", status == 200, status)
    stopped = signup.walk.run_as("hana", "splint host stop")
    check("control: uma's host stops", stopped.returncode == 0, stopped.stderr)
    approved = approves(signup, pat, port)
    started = signup.walk.run_as("hana", "splint host start")
    check("control: and starts again at the same address", started.returncode == 0 and host in started.stdout, started.stderr)
    line = FINISH_LINE.search(approved.stdout)
    check("pat is given the whole answer to pass on, as uma's host didn't keep it", approved.returncode == 0 and "Approved 1" in approved.stdout and line is not None and line.group(1).startswith("ey"), approved.stdout + approved.stderr)
    if line:
        finished = signup.walk.run_as("uma", line.group(0))
        check("and uma takes it up from that line", finished.returncode == 0 and wait_until(lambda: confirmed(uma), SIGNET_HEARS_SECONDS), finished.stdout + finished.stderr)
        pat_id = here(pat, port).get("identity")
        _, found = e2e.http("GET", f"http://{host}/.well-known/splint/agents/uma")
        check("acting for pat", bool(pat_id) and found.get("owner_identity") == pat_id, found.get("owner_identity", "")[:60])
    an_agent_is_given_only_the_link_to_its_persons_computer(signup, kit)


def an_agent_is_given_only_the_link_to_its_persons_computer(signup: Signup, kit) -> None:
    """Issue 635: whoever serves the page a passkey signs on chooses what a touch signs, so owners sign
    only on their own computers (Nenye, 2026-11-21). Bug caught: an agent handing its person a link to
    a page its host serves. That a host started with the old owner page settings publishes none is
    sim/host_operator.py's, as `splint host start` passes a host only its limits."""
    asked = json.loads(signup.walk.run_as("kit", "splint controls --json").stdout or "{}")
    check("an agent is given only the link to Splint on its person's computer", asked.get("status") == "waiting" and "link" not in asked and str(asked.get("computer_link", "")).startswith("http://localhost:"), asked)
    words = signup.walk.run_as("kit", "splint controls").stdout
    check("in words too, with how to install Splint there", set(name for name, *_ in LINK.findall(words)) == {"computer_link"} and "controls.install" in words, words)


def main() -> None:
    work = e2e.short_scratch("splint-link-")
    signup = Signup(work)
    port = e2e.free_port()
    try:
        mallory, pat = a_stranger_cant_take_over_an_agent_asking_by_link(signup, port)
        a_link_that_reached_two_people_gets_neither(signup, mallory, pat, port)
        asking_again_ends_the_link_before(signup, pat, port)
        an_answer_its_host_didnt_keep_is_given_to_pass_on(signup, pat, port)
    finally:
        for person in COMPUTERS:
            person.shell("pkill -f \"$HOME/.splint/bin/splint computer run\" || true", signup.walk.work, timeout=30)
        signup.walk.stop_everything()
        shutil.rmtree(work, ignore_errors=True)
    if e2e.failures:
        print(f"\n{e2e.failures} checks failed", flush=True)
        sys.exit(1)
    print("\nall asked-by-link checks passed", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A host its operator closes, with a real host, real Signets that `splint join` started, and Postgres.

The operator runs `splint-host close DATE` beside the running host. From then the host takes no new
agents and says why, says the date on its well-known page, and its agents hear it: `splint status` and
`splint check` give the date and the way out, which is moving to another host with the same ID. Then
the date is taken back, and the host takes new agents again. Nothing restarts.

    python3 sim/host_closing.py

Not shown: a real model deciding whether to move, or the move itself, which sim/switch_host.py runs.
Every key is a software key, and no agent has network limits.
"""

import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import e2e
from e2e import check, http, wait_until
from listening import BINARIES, NO_SERVICE_MANAGER, OPEN_TO_A_RUN, Agent

PAGE = "/.well-known/splint/host"
# The host reads the date every 2 seconds, and a Signet hears it on its next call to the host.
TAKEN_SECS = 10
HEARD_SECS = 45


def close_command(database_url: str, *arguments: str) -> subprocess.CompletedProcess:
    """`splint-host close ...`, as an operator runs it beside the running host, with its database."""
    return subprocess.run(
        [str(e2e.TARGET_DIR / "debug" / "host"), "close", *arguments],
        env={"PATH": "/usr/bin:/bin", "NO_COLOR": "1", "SPLINT_DATABASE_URL": database_url},
        capture_output=True, text=True, timeout=30,
    )


def page(domain: str) -> dict:
    status, answer = http("GET", f"http://{domain}{PAGE}")
    return answer if status == 200 else {}


def standing(agent: Agent) -> dict:
    done = agent.run("status", "--json")
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        return {}


def signet_says(agent: Agent) -> dict:
    socket = agent.home / ".splint" / "run" / "signet.sock"
    return e2e.http_on_socket("GET", socket, "/v0/identity", token=agent.setup_file()["api_token"])[1]


def an_agent_hears_and_a_new_one_is_refused(lia: Agent, nia: Agent, domain: str, database_url: str) -> None:
    """Bugs: a closing host still takes new agents, or says nothing an agent can act on, or its agents
    don't hear the date and are cut off when it goes."""
    check("control: the page names no closing date", "closing_at" not in page(domain), page(domain))
    check("control: lia's status names none", "host_closes" not in standing(lia), standing(lia))

    day = (datetime.now(UTC) + timedelta(days=30)).date()
    at = int(datetime(day.year, day.month, day.day, tzinfo=UTC).timestamp())
    shown = f"{day.isoformat()}T00:00Z"
    closed = close_command(database_url, day.isoformat())
    check("`splint-host close DATE` sets the date beside the running host", closed.returncode == 0 and day.isoformat() in closed.stdout, closed.stdout + closed.stderr)
    check("the page says it, with no restart", wait_until(lambda: page(domain).get("closing_at") == at, TAKEN_SECS), page(domain))

    joined = nia.run("join", nia.address)
    said = joined.stdout + joined.stderr
    check("a new agent is refused", joined.returncode != 0, said)
    check("with words that say the host is closing and to join another", "closing" in said and "another host" in said, said)

    check("lia's status gives the date, as her Signet heard it on its own", wait_until(lambda: standing(lia).get("host_closes") == shown, HEARD_SECS), standing(lia))
    told = standing(lia).get("next", "")
    check("and her next step names the move that keeps her ID", "switch-host" in told and shown in told, told)
    checked = lia.run("check")
    check("`splint check` says the date and the move, with nothing else waiting", shown in checked.stdout and "switch-host" in checked.stdout, checked.stdout + checked.stderr)
    status_words = lia.run("status").stdout
    check("and `splint status` says it in words", shown in status_words, status_words)
    shown_by_command = close_command(database_url)
    check("`splint-host close` says the date set", shown_by_command.returncode == 0 and day.isoformat() in shown_by_command.stdout, shown_by_command.stdout)

    # Bug caught: refusing every registration while closing, which cuts an agent off at its next
    # restart, in the very days it needs to read its mail and move.
    lia.run("stop")
    started = lia.run("start")
    check("an agent already here starts again while the host is closing", started.returncode == 0, started.stdout + started.stderr)
    check("registered, and still hearing the date", wait_until(lambda: signet_says(lia).get("registered") is True and standing(lia).get("host_closes") == shown, HEARD_SECS), signet_says(lia))


def taking_it_back_opens_the_host_again(lia: Agent, nia: Agent, domain: str, database_url: str) -> None:
    """Bug: a date set by mistake can't be taken back without a restart, or agents keep hearing it."""
    cancelled = close_command(database_url, "cancel")
    check("`splint-host close cancel` takes the date back", cancelled.returncode == 0, cancelled.stdout + cancelled.stderr)
    check("the page names no date again", wait_until(lambda: "closing_at" not in page(domain), TAKEN_SECS), page(domain))
    joined = nia.run("join", nia.address)
    check("a new agent joins again", joined.returncode == 0, joined.stdout + joined.stderr)
    check("and lia stops hearing a date", wait_until(lambda: "switch-host" not in lia.run("check").stdout and "host_closes" not in standing(lia), HEARD_SECS), standing(lia))


def a_past_day_is_refused(database_url: str, domain: str) -> None:
    """Bug: a typo'd year closes the host at once."""
    refused = close_command(database_url, "2020-01-01")
    check("a day that has passed is refused", refused.returncode != 0, refused.stdout + refused.stderr)
    # Past the time the page took to show a date that was set, as read at once it shows nothing either way.
    check("and the page never shows it", not wait_until(lambda: "closing_at" in page(domain), TAKEN_SECS), page(domain))


def main() -> int:
    subprocess.run(["cargo", "build", "--quiet", "-p", "host", "-p", "signet", "-p", "owner-key", "-p", "splint"], cwd=e2e.PACKAGES, check=True)
    work = e2e.short_scratch("splint-closing-")
    postgres = e2e.Postgres()
    processes: list[e2e.Process] = []
    agents: list[Agent] = []
    try:
        postgres.start()
        bin_dir, stub_dir = work / "bin", work / "stub"
        for folder in (bin_dir, stub_dir):
            folder.mkdir()
        for name, built in BINARIES.items():
            shutil.copy(e2e.TARGET_DIR / "debug" / built, bin_dir / name)
        for manager in ("launchctl", "crontab"):
            (stub_dir / manager).write_text(NO_SERVICE_MANAGER)
            (stub_dir / manager).chmod(0o755)
        domain = f"127.0.0.1:{e2e.free_port()}"
        database_url = postgres.create_database("host_a")
        host = e2e.Process("host", "host", work, {
            "SPLINT_DOMAIN": domain, "SPLINT_LISTEN": domain,
            "SPLINT_DATABASE_URL": database_url,
            "SPLINT_HOST_KEY_FILE": str(work / "host.key"),
            **e2e.PLAIN_HTTP_FOR_TESTS, **OPEN_TO_A_RUN,
        })
        processes.append(host)
        host.start()
        if not wait_until(lambda: page(domain) != {}):
            raise RuntimeError("the host didn't start")
        lia, nia = Agent(work, bin_dir, stub_dir, "lia", domain), Agent(work, bin_dir, stub_dir, "nia", domain)
        agents.extend([lia, nia])
        joined = lia.run("join", lia.address)
        check("control: lia's agent joins", joined.returncode == 0, joined.stdout + joined.stderr)

        print("\nan agent hears the date, and a new one is refused", flush=True)
        an_agent_hears_and_a_new_one_is_refused(lia, nia, domain, database_url)
        print("\ntaking it back opens the host again", flush=True)
        taking_it_back_opens_the_host_again(lia, nia, domain, database_url)
        print("\na past day is refused", flush=True)
        a_past_day_is_refused(database_url, domain)
    finally:
        for agent in agents:
            agent.run("stop")
        for process in processes:
            process.kill_hard()
        if e2e.failures:
            for log in [work / "host.log", *work.glob("homes/*/.splint/run/*.log")]:
                if log.exists():
                    print(f"\n--- {log.name}\n{log.read_text()[-1500:]}")
        postgres.stop()
        shutil.rmtree(work, ignore_errors=True)
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

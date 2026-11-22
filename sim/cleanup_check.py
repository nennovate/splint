#!/usr/bin/env python3
"""Make test runs go wrong, and check they leave no process, container, volume or directory behind.

An earlier version of this leak filled the Docker disk. Each case runs in a process of its own
against real Docker and the real binaries, and that process's own cleanup is what's under test.
This file only removes what's left if that cleanup fails, so a failing check doesn't leak too.

Not shown here: a SIGKILL, which no process can handle, so it still leaves everything behind.
"""

import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import e2e

HERE = Path(__file__).resolve().parent
RUNNING_NETWORK_PROCESSES = 2 + len(e2e.TOKENS)
EXIT_ON_SIGTERM = 128 + signal.SIGTERM


def container_of(pid: int) -> str:
    return f"splint-e2e-{pid}"


def container_exists(name: str) -> bool:
    return subprocess.run(["docker", "inspect", name], capture_output=True).returncode == 0


def volumes_of(name: str) -> list[str]:
    listed = subprocess.run(
        ["docker", "inspect", "-f", "{{range .Mounts}}{{.Name}} {{end}}", name],
        capture_output=True, text=True,
    )
    return listed.stdout.split()


def volume_exists(name: str) -> bool:
    return subprocess.run(["docker", "volume", "inspect", name], capture_output=True).returncode == 0


def still_running(pids: list[int]) -> list[int]:
    def running(pid: int) -> bool:
        state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout
        return bool(state.strip()) and not state.strip().startswith("Z")

    return [pid for pid in pids if running(pid)]


def report(kind: str, value: object) -> None:
    print(f"started {kind} {value}", flush=True)


def report_volumes() -> None:
    for volume in volumes_of(container_of(os.getpid())):
        report("volume", volume)


def run_failing_child(case: str) -> None:
    """Goes wrong partway through starting up, and reports what it started so far."""
    real_start = e2e.Process.start

    def reporting_start(process: e2e.Process) -> None:
        real_start(process)
        report("process", process.process.pid)

    e2e.Process.start = reporting_start

    if case == "postgres":
        def never_ready(*_args: object, **_kwargs: object) -> bool:
            report_volumes()
            return False

        e2e.wait_until = never_ready
    else:
        real_address = e2e.Network.address
        real_network_start = e2e.Network.start

        def mallorys_signet_cant_boot(net: e2e.Network, agent: str) -> str:
            return "not an address" if agent == "mallory" else real_address(net, agent)

        def reporting_network_start(net: e2e.Network) -> None:
            report_volumes()
            real_network_start(net)

        e2e.Network.address = mallorys_signet_cant_boot
        e2e.Network.start = reporting_network_start

    with e2e.running_network():
        print("started everything", flush=True)


class Leftovers:
    """What a run started, so that a failed check can say what stayed and then clear it up."""

    def __init__(self, container: str, temp: Path) -> None:
        self.container = container
        self.temp = temp
        self.pids: list[int] = []
        self.volumes: list[str] = []

    def read(self, output: str) -> None:
        for line in output.splitlines():
            match line.split(" ", 2):
                case ["started", "process", pid]:
                    self.pids.append(int(pid))
                case ["started", "volume", volume]:
                    self.volumes.append(volume)

    def check(self, case: str) -> None:
        e2e.check(f"{case}: no process is left", not still_running(self.pids), still_running(self.pids))
        e2e.check(f"{case}: no container is left", not container_exists(self.container), self.container)
        stayed = [volume for volume in self.volumes if volume_exists(volume)]
        e2e.check(f"{case}: no volume is left", not stayed, stayed)
        stayed = list(self.temp.iterdir())
        e2e.check(f"{case}: no directory is left", not stayed, stayed)

    def clear(self) -> None:
        for pid in still_running(self.pids):
            subprocess.run(["kill", "-KILL", str(pid)], capture_output=True)
        if container_exists(self.container):
            subprocess.run(["docker", "rm", "-f", "-v", self.container], capture_output=True)


def with_temp_dir(temp: str) -> dict[str, str]:
    """A run's work directory lands somewhere only that run uses, to see whether it's still there."""
    return {**os.environ, "TMPDIR": temp}


def a_startup_that_fails(case: str, child: str, expected_processes: int, expected_error: str) -> None:
    with tempfile.TemporaryDirectory() as temp:
        finished = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--fail-starting", child],
            capture_output=True, text=True, env=with_temp_dir(temp),
        )
        # A child's PID is only known afterwards, and its container takes its name from it.
        pid = int(finished.stdout.split("pid ", 1)[1].split()[0]) if "pid " in finished.stdout else 0
        left = Leftovers(container_of(pid), Path(temp))
        left.read(finished.stdout)
        try:
            e2e.check(f"{case}: control: the startup failed as intended", expected_error in finished.stderr, finished.stderr)
            e2e.check(f"{case}: control: it had a volume to leak", bool(left.volumes), finished.stdout)
            e2e.check(f"{case}: control: it had processes to leak", len(left.pids) == expected_processes, left.pids)
            left.check(case)
        finally:
            left.clear()


def real_e2e_run(temp: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, str(HERE / "e2e.py")], stdout=subprocess.PIPE, text=True, env=with_temp_dir(temp),
    )


def sigterm(case: str, run: subprocess.Popen, left: Leftovers) -> None:
    run.send_signal(signal.SIGTERM)
    code = run.wait(timeout=e2e.WAIT_SECONDS)
    e2e.check(f"{case}: it stops as a killed run should", code == EXIT_ON_SIGTERM, code)
    left.check(case)


def a_kill_during_a_run() -> None:
    case = "SIGTERM mid-run"
    with tempfile.TemporaryDirectory() as temp:
        run = real_e2e_run(temp)
        left = Leftovers(container_of(run.pid), Path(temp))
        try:
            for line in run.stdout:
                if line.startswith("exchange messages"):
                    break
            children = subprocess.run(["pgrep", "-P", str(run.pid)], capture_output=True, text=True)
            left.pids = [int(pid) for pid in children.stdout.split()]
            left.volumes = volumes_of(left.container)
            running = still_running(left.pids)
            e2e.check(f"{case}: control: its processes are running", len(running) == RUNNING_NETWORK_PROCESSES, running)
            e2e.check(f"{case}: control: its container has a volume", bool(left.volumes), left.container)
            e2e.check(f"{case}: control: its work directory exists", any(left.temp.iterdir()), temp)
            sigterm(case, run, left)
        finally:
            run.kill()
            left.clear()


def a_kill_while_postgres_starts() -> None:
    case = "SIGTERM during Postgres startup"
    with tempfile.TemporaryDirectory() as temp:
        run = real_e2e_run(temp)
        left = Leftovers(container_of(run.pid), Path(temp))
        try:
            appeared = e2e.wait_until(lambda: container_exists(left.container))
            left.volumes = volumes_of(left.container)
            e2e.check(f"{case}: control: its container exists", appeared and bool(left.volumes), left.container)
            sigterm(case, run, left)
        finally:
            run.kill()
            left.clear()


def main() -> int:
    if sys.argv[1:2] == ["--fail-starting"]:
        print(f"pid {os.getpid()}", flush=True)
        run_failing_child(sys.argv[2])
        return 0

    e2e.build()
    a_startup_that_fails("Postgres startup fails", "postgres", 0, "Postgres didn't start")
    a_startup_that_fails("a Signet fails to boot", "signet", RUNNING_NETWORK_PROCESSES, "mallory's Signet exited")
    a_kill_while_postgres_starts()
    a_kill_during_a_run()
    print(f"\n{'all checks passed' if e2e.failures == 0 else f'{e2e.failures} checks failed'}")
    return 1 if e2e.failures else 0


if __name__ == "__main__":
    sys.exit(main())

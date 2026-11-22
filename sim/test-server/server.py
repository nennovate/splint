#!/usr/bin/env python3
"""Start a host and Postgres in one container, limited like a small server.

Docker on a laptop isn't a small server. The limits are a share of the laptop's CPU, the disk is
virtual and there's no real network, so a number measured here doesn't carry over directly.
"""

import argparse
import json
import secrets
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

IMAGE = "splint-test-server"
NETWORK = "splint-test-net"
DEFAULT_NAME = "splint-test-server"
NAME_PREFIX = "splint-test"
DEFAULT_PORT = 18080
CONTAINER_PORT = 8080
HOST_INFO_PATH = "/.well-known/splint/host"
# A host takes no new agent without one of these, so a server with none would be no use to anyone.
SIGNUP_CODES = 5
START_SECONDS = 60
GIB = 1024**3
PROFILES = {
    "small": {"cpus": 2, "memory": 2 * GIB},
    "tiny": {"cpus": 1, "memory": 1 * GIB},
}
HERE = Path(__file__).resolve().parent
PACKAGES = HERE.parent.parent / "packages"
# Microseconds of CPU per period, as the kernel's cgroup files report a limit.
CPU_PERIOD = 100_000


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True)


def build() -> None:
    toolchain = tomllib.loads((PACKAGES / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    subprocess.run(
        ["docker", "build", "--tag", IMAGE, "--build-arg", f"RUST_VERSION={toolchain}",
         "--file", str(HERE / "Dockerfile"),
         "--build-context", f"scripts={HERE}", str(PACKAGES)],
        check=True,
    )


def data_volume(name: str) -> str:
    return f"{name}-data"


def stop(name: str) -> None:
    docker("rm", "--force", "--volumes", name, check=False)
    docker("volume", "rm", data_volume(name), check=False)
    # Refused while another test server still uses it, which is what should happen.
    docker("network", "rm", NETWORK, check=False)


def host_info(port: int) -> dict | None:
    try:
        url = f"http://127.0.0.1:{port}{HOST_INFO_PATH}"
        with urllib.request.urlopen(url, timeout=2) as response:
            return json.load(response) if response.status == 200 else None
    except (urllib.error.URLError, ConnectionError, TimeoutError, ValueError):
        return None


def wait_for_host(name: str, port: int, domain: str) -> None:
    deadline = time.monotonic() + START_SECONDS
    while time.monotonic() < deadline:
        info = host_info(port)
        if info is not None:
            if info.get("domain") != domain or not info.get("key"):
                raise RuntimeError(f"host answered with the wrong identity: {info}")
            return
        if docker("inspect", "--format", "{{.State.Running}}", name, check=False).stdout.strip() != "true":
            raise RuntimeError("the container stopped while starting")
        time.sleep(0.2)
    raise RuntimeError(f"host didn't answer within {START_SECONDS}s")


def check_limits(name: str, cpus: int, memory: int) -> None:
    """Reads the limits from inside the container, because a mistyped flag would otherwise go unseen."""
    applied = docker(
        "exec", name, "cat", "/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory.swap.max",
    ).stdout.split()
    expected = [str(cpus * CPU_PERIOD), str(CPU_PERIOD), str(memory), "0"]
    if applied != expected:
        raise RuntimeError(f"limits not in force: expected {expected}, found {applied}")


def start(profile: str, name: str, port: int, domain: str | None, no_build: bool,
          image: str = IMAGE, nofile: int | None = None) -> None:
    limits = PROFILES[profile]
    domain = domain or f"{name}:{CONTAINER_PORT}"
    if not no_build:
        build()
    stop(name)
    docker("network", "create", NETWORK, check=False)
    signup_codes = [secrets.token_urlsafe(32) for _ in range(SIGNUP_CODES)]
    try:
        docker(
            "run", "--detach", "--name", name, "--hostname", name, "--network", NETWORK,
            "--cpus", str(limits["cpus"]),
            "--memory", str(limits["memory"]),
            # Without this Docker adds as much swap again, and the memory limit means little.
            "--memory-swap", str(limits["memory"]),
            # Docker's default of 64MB fails Postgres's parallel work on a large table. A real server has half its memory.
            "--shm-size", str(limits["memory"] // 2),
            "--publish", f"127.0.0.1:{port}:{CONTAINER_PORT}",
            "--volume", f"{data_volume(name)}:/var/lib/postgresql/data",
            # A long load test mustn't fill the Docker disk other projects share.
            "--log-opt", "max-size=20m", "--log-opt", "max-file=2",
            *(["--ulimit", f"nofile={nofile}:{nofile}"] if nofile else []),
            "--env", f"SPLINT_DOMAIN={domain}",
            "--env", f"SPLINT_SIGNUP_CODES={','.join(signup_codes)}",
            image,
        )
        check_limits(name, limits["cpus"], limits["memory"])
        wait_for_host(name, port, domain)
    except (RuntimeError, subprocess.CalledProcessError) as error:
        logs = docker("logs", "--tail", "30", name, check=False)
        print(logs.stdout + logs.stderr, file=sys.stderr)
        stop(name)
        reason = getattr(error, "stderr", None) or error
        raise SystemExit(f"{name} didn't start: {reason}") from error
    print(
        f"{name} is up: profile {profile}, {limits['cpus']} CPU, {limits['memory'] // GIB}GB\n"
        f"  from this machine:  http://127.0.0.1:{port}{HOST_INFO_PATH}\n"
        f"  from network {NETWORK}:  http://{name}:{CONTAINER_PORT}{HOST_INFO_PATH}\n"
        f"  addresses:  <handle>~{domain}\n"
        f"  signup codes, for SPLINT_SIGNUP_CODE:  {' '.join(signup_codes)}\n"
        f"  stop with:  python3 sim/test-server/server.py stop --name {name}"
    )


def container_name(name: str) -> str:
    if not name.startswith(NAME_PREFIX):
        raise argparse.ArgumentTypeError(f"must start with {NAME_PREFIX}, so it's clear what's safe to remove")
    return name


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start_command = commands.add_parser("start")
    start_command.add_argument("profile", choices=PROFILES)
    start_command.add_argument("--port", type=int, default=DEFAULT_PORT)
    start_command.add_argument(
        "--domain", help=f"default <name>:{CONTAINER_PORT}, which Signets in {NETWORK} can reach; "
        "for a Signet outside Docker use 127.0.0.1:<port>",
    )
    start_command.add_argument("--no-build", action="store_true", help="use the image already built")
    start_command.add_argument("--image", default=IMAGE, help="another build of the image, with --no-build")
    start_command.add_argument("--nofile", type=int, help="the open-file limit, as a service manager would set it")
    stop_command = commands.add_parser("stop")
    for command in (start_command, stop_command):
        command.add_argument("--name", type=container_name, default=DEFAULT_NAME)
    args = parser.parse_args()
    if args.command == "start":
        start(args.profile, args.name, args.port, args.domain, args.no_build, args.image, args.nofile)
    else:
        stop(args.name)


if __name__ == "__main__":
    main()

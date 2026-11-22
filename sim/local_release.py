"""A release built on this machine, served the way GitHub serves one, for following the agent document
from a clean home with no Rust and no clone.

It's built and packed by the release workflow's own scripts, and its install.sh has its checksums fixed
inside it, the same as a tagged one. Only where the files come from differs: a `curl` on the clean
home's PATH sends what would go to the repository's releases to a server on this machine. install.sh
checks what it gets against the checksums inside it, wherever it came from, so that changes nothing
it checks.

Not shown here: a signature check, as nothing here is signed by the release workflow, so cosign is
kept off the clean PATH. The release workflow's own PR run checks that, on GitHub.
"""

import functools
import os
import platform
import shutil
import subprocess
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE_DIR = ROOT / "deploy" / "release"
VERSION = "v0.0.0-local"
RELEASES = "https://github.com/nennovate/splint/releases/"
PROGRAMS = ("splint", "host", "signet", "owner-key")
BUILD_SECONDS = 1500
# Anything the real PATH would add that a clean machine wouldn't have: an installed splint, Rust, and cosign,
# which would look for a signature this build hasn't got.
NOT_ON_A_CLEAN_MACHINE = ("splint", "splint-signet", "cargo", "cosign")


def platform_name() -> str:
    names = {
        ("Darwin", "arm64"): "macos-arm64",
        ("Darwin", "x86_64"): "macos-x86_64",
        ("Linux", "x86_64"): "linux-x86_64",
        ("Linux", "aarch64"): "linux-arm64",
    }
    return names[(platform.system(), platform.machine())]


def build(dist: Path) -> None:
    """Builds the four programs with this version set, and packs them as the release workflow does."""
    env = {**os.environ, "SPLINT_VERSION": VERSION}
    built = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "packages" / "target")) / "debug"
    selected = [part for program in PROGRAMS for part in ("-p", program)]
    subprocess.run(["cargo", "build", "--quiet", "--locked", *selected], cwd=ROOT / "packages", env=env, check=True, timeout=BUILD_SECONDS)
    dist.mkdir(parents=True)
    subprocess.run([RELEASE_DIR / "package.sh", built, platform_name(), VERSION, dist], check=True, capture_output=True)
    subprocess.run([RELEASE_DIR / "render.sh", VERSION, dist], check=True, capture_output=True)
    subprocess.run([RELEASE_DIR / "check-install.sh", VERSION, dist], check=True, env={**os.environ, "PATH": clean_path()})


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        pass


def serve(dist: Path) -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(dist)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def clean_path() -> str:
    kept = [folder for folder in os.environ["PATH"].split(os.pathsep) if folder and not any((Path(folder) / name).exists() for name in NOT_ON_A_CLEAN_MACHINE)]
    return os.pathsep.join(kept)


def fetched_log(work: Path) -> Path:
    """Every URL the shim's curl was asked for, as asked, one a line."""
    return work / "release-shim" / "fetched"


def path_with_releases_from(work: Path, port: int) -> str:
    """A PATH whose curl fetches the repository's release files from this machine, and nothing else,
    and writes down every URL it's asked for."""
    shim = work / "release-shim"
    shim.mkdir(exist_ok=True)
    real = shutil.which("curl", path=clean_path())
    curl = shim / "curl"
    # install.sh asks for https only, which a server on this machine isn't, so that goes too.
    curl.write_text(f"""#!/bin/sh
n=$#
while [ "$n" -gt 0 ]; do
    arg=$1
    shift
    n=$((n - 1))
    case $arg in
    --proto) shift; n=$((n - 1)); continue ;;
    http://* | https://*) printf '%s\n' "$arg" >>"{fetched_log(work)}" ;;
    esac
    case $arg in
    {RELEASES}*) arg="http://127.0.0.1:{port}/${{arg##*/}}" ;;
    esac
    set -- "$@" "$arg"
done
exec {real} "$@"
""")
    curl.chmod(0o755)
    return f"{shim}{os.pathsep}{clean_path()}"

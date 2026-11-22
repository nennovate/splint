#!/bin/sh
# Checks a release's install.sh from the files in DIST_DIR, on this machine: it installs a working
# splint into a new home, and refuses an archive with one byte added, or the unreleased template,
# leaving nothing behind. Then `splint verify` and `install.sh --verify` both pass what was installed,
# and both catch one byte added to an installed program. The release's agents.md is the repository's
# docs/agents.md, and its checksum in SHA256SUMS holds it and catches one byte added. With cosign 3 on
# PATH it checks signatures too.
#
#   deploy/release/check-install.sh VERSION DIST_DIR
set -eu

version=${1:?usage: check-install.sh VERSION DIST_DIR}
dist=$(cd "${2:?}" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
fail() {
    echo "check-install.sh: $*" >&2
    exit 1
}

HOME="$scratch/home" SPLINT_FROM_DIR="$dist" sh "$dist/install.sh"
said=$(HOME="$scratch/home" "$scratch/home/.splint/bin/splint" --version)
[ "$said" = "splint $version" ] || fail "the installed splint says it's $said"
[ -f "$scratch/home/.splint/examples/meeting-1.json" ] || fail "the example types weren't installed"

bin="$scratch/home/.splint/bin"
HOME="$scratch/home" SPLINT_FROM_DIR="$dist" "$bin/splint" verify >/dev/null ||
    fail "splint verify didn't pass what was just installed"
HOME="$scratch/home" sh "$dist/install.sh" --verify 2>/dev/null ||
    fail "install.sh --verify didn't pass what was just installed"
cp "$bin/splint-owner-key" "$scratch/owner-key"
printf 'x' >>"$bin/splint-owner-key"
if HOME="$scratch/home" SPLINT_FROM_DIR="$dist" "$bin/splint" verify 2>"$scratch/said"; then
    fail "splint verify passed a program with a byte added"
fi
grep -q "splint-owner-key: NOT the same" "$scratch/said" || fail "splint verify said: $(cat "$scratch/said")"
if HOME="$scratch/home" sh "$dist/install.sh" --verify 2>"$scratch/said"; then
    fail "install.sh --verify passed a program with a byte added"
fi
grep -q "splint-owner-key: NOT the same" "$scratch/said" || fail "install.sh --verify said: $(cat "$scratch/said")"
cp "$scratch/owner-key" "$bin/splint-owner-key"

# A person's one line: install, then their controls open on this computer. Bug this catches: an install
# that ends without opening them, or that serves them from somewhere other than this release's splint.
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
HOME="$scratch/person" SPLINT_FROM_DIR="$dist" sh "$dist/install.sh" controls splint.example --port "$port" --no-open \
    >"$scratch/controls.out" 2>&1 &
serving=$!
opened=false
for _ in $(seq 1 100); do
    if curl -fsS "http://localhost:$port/owner" 2>/dev/null | grep -q '<html'; then
        opened=true
        break
    fi
    sleep 0.2
done
kill "$serving" 2>/dev/null || true
wait "$serving" 2>/dev/null || true
$opened || fail "install.sh controls didn't open the controls: $(cat "$scratch/controls.out")"
[ -x "$scratch/person/.splint/bin/splint" ] || fail "install.sh controls didn't install splint"
if HOME="$scratch/nobody" SPLINT_FROM_DIR="$dist" sh "$dist/install.sh" controls 2>/dev/null; then
    fail "install.sh controls with no host went ahead"
fi
[ ! -e "$scratch/nobody/.splint" ] || fail "install.sh controls with no host installed anyway"

mkdir "$scratch/changed"
cp "$dist"/* "$scratch/changed/"
for archive in "$scratch"/changed/*.tar.gz; do
    printf 'x' >>"$archive"
done
if HOME="$scratch/fresh" SPLINT_FROM_DIR="$scratch/changed" sh "$dist/install.sh" 2>"$scratch/said"; then
    fail "an archive with a byte added installed"
fi
grep -q "doesn't match the checksum" "$scratch/said" || fail "it refused for another reason: $(cat "$scratch/said")"
[ ! -e "$scratch/fresh/.splint" ] || fail "a refused install left ~/.splint behind"

# The official agent instructions, checked as anyone would: by SHA256SUMS, with nothing of Splint's.
sums_check() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c --ignore-missing --quiet SHA256SUMS
    else
        shasum -a 256 -c --ignore-missing --quiet SHA256SUMS
    fi
}
grep -q '  agents.md$' "$dist/SHA256SUMS" || fail "SHA256SUMS doesn't list agents.md"
cmp -s "$dist/agents.md" "$here/../../docs/agents.md" || fail "agents.md isn't the repository's docs/agents.md"
mkdir "$scratch/instructions"
cp "$dist/agents.md" "$dist/SHA256SUMS" "$scratch/instructions/"
(cd "$scratch/instructions" && sums_check >/dev/null) || fail "agents.md doesn't match SHA256SUMS"
printf 'x' >>"$scratch/instructions/agents.md"
if (cd "$scratch/instructions" && sums_check >/dev/null 2>&1); then
    fail "SHA256SUMS passed an agents.md with a byte added"
fi

if HOME="$scratch/fresh" sh "$here/install.sh" 2>/dev/null; then
    fail "the template in the repository installed"
fi
echo "install.sh checks out for $version"

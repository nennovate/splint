#!/bin/sh
# Writes a release's install.sh and install.ps1, with its version, its commit and the SHA-256 of each archive in
# DIST_DIR and of each program inside them fixed inside each, and SHA256SUMS beside them with the same
# lines, for `splint verify` and anyone checking by hand or rebuilding. It also puts the official
# agent instructions, docs/agents.md as they are at this commit, beside them as agents.md, and lists
# that, install.sh and install.ps1 in SHA256SUMS, which the release signs.
#
#   deploy/release/render.sh VERSION DIST_DIR
#
# The commit is this clone's, which is the one the archives were built from.
set -eu

version=${1:?usage: render.sh VERSION DIST_DIR}
dist=${2:?}
here=$(cd "$(dirname "$0")" && pwd)
# A version goes into a shell script and a URL, so only these characters.
if ! printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
    echo "render.sh: $version isn't a version like v0.1.0" >&2
    exit 1
fi

commit=$(git -C "$here" rev-parse HEAD)

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$@"
    else
        shasum -a 256 "$@"
    fi
}
# Two spaces between, as sha256sum -c expects, and no path in front of a name.
tidy() { awk '{ sub(/^\*/, "", $2); print $1 "  " $2 }'; }

cd "$dist"
set -- splint-"$version"-*.tar.gz
[ -f "$1" ] || { echo "render.sh: no archives for $version in $dist" >&2; exit 1; }
sums=$(sha256 "$@" | tidy)

# Each program too, named by its path inside the archive, so a copy installed anywhere can be checked.
open=$(mktemp -d)
trap 'rm -rf "$open"' EXIT
for archive in "$@"; do
    tar -xzf "$archive" -C "$open"
done
programs=$(cd "$open" && sha256 splint-"$version"-*/bin/* | tidy)
[ -n "$programs" ] || { echo "render.sh: the archives hold no programs" >&2; exit 1; }
sums=$(printf '%s\n%s\n' "$sums" "$programs")

VERSION="$version" COMMIT="$commit" SUMS="$sums" awk '
    $0 == "VERSION=@VERSION@" { print "VERSION=" ENVIRON["VERSION"]; next }
    $0 == "COMMIT=@COMMIT@" { print "COMMIT=" ENVIRON["COMMIT"]; next }
    $0 == "@SUMS@" { print ENVIRON["SUMS"]; next }
    { print }
' "$here/install.sh" >install.sh
chmod 755 install.sh
grep -q "^VERSION=$version\$" install.sh || { echo "render.sh: the version didn't go in" >&2; exit 1; }
grep -q "^COMMIT=$commit\$" install.sh || { echo "render.sh: the commit didn't go in" >&2; exit 1; }

# Windows's, with the same lists in PowerShell's quoting, where nothing inside '...' is read.
VERSION="$version" COMMIT="$commit" SUMS="$sums" awk '
    $0 == "$Version = '"'"'@VERSION@'"'"'" { print "$Version = '"'"'" ENVIRON["VERSION"] "'"'"'"; next }
    $0 == "$Commit = '"'"'@COMMIT@'"'"'" { print "$Commit = '"'"'" ENVIRON["COMMIT"] "'"'"'"; next }
    $0 == "@SUMS@" { print ENVIRON["SUMS"]; next }
    { print }
' "$here/install.ps1" >install.ps1
chmod 644 install.ps1
grep -q "^\$Version = '$version'\$" install.ps1 || { echo "render.sh: the version didn't go in install.ps1" >&2; exit 1; }
grep -q "^\$Commit = '$commit'\$" install.ps1 || { echo "render.sh: the commit didn't go in install.ps1" >&2; exit 1; }

cp "$here/../../docs/agents.md" agents.md
chmod 644 agents.md
{
    printf '%s\n' "$sums"
    sha256 install.sh install.ps1 agents.md | tidy
} >SHA256SUMS
echo "$dist/install.sh"

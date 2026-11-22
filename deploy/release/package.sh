#!/bin/sh
# Packs one platform's built programs, and the files they read at run time, into the archive that
# install.sh fetches. It holds what `make install` puts in ~/.splint, under the same names.
#
#   deploy/release/package.sh BUILT_DIR PLATFORM VERSION OUT_DIR
#
# BUILT_DIR is cargo's output for one target, such as packages/target/aarch64-apple-darwin/release.
set -eu

built=${1:?usage: package.sh BUILT_DIR PLATFORM VERSION OUT_DIR}
platform=${2:?}
version=${3:?}
out=${4:?}
repo=$(cd "$(dirname "$0")/../.." && pwd)
name="splint-$version-$platform"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

root="$stage/$name"
mkdir -p "$root/bin" "$root/adapters/mcp/src" "$root/adapters/http" "$root/examples" "$out"
# A Windows build's programs end in .exe, and it has no host, which runs on Linux.
case $platform in
windows-*) exe=.exe ;;
*) exe= ;;
esac
install -m 755 "$built/splint$exe" "$root/bin/splint$exe"
[ -n "$exe" ] || install -m 755 "$built/host" "$root/bin/splint-host"
install -m 755 "$built/signet$exe" "$root/bin/splint-signet$exe"
install -m 755 "$built/owner-key$exe" "$root/bin/splint-owner-key$exe"
install -m 644 "$repo/adapters/mcp/package.json" "$repo/adapters/mcp/connect.txt" "$root/adapters/mcp"
install -m 644 "$repo"/adapters/mcp/src/*.ts "$root/adapters/mcp/src"
install -m 755 "$repo"/adapters/http/*.sh "$root/adapters/http"
install -m 644 "$repo/adapters/http/connect.txt" "$root/adapters/http"
install -m 644 "$repo"/spec/schemas/*.json "$root/examples"
tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
echo "$out/$name.tar.gz"

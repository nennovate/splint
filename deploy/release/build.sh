#!/bin/sh
# Builds one platform's programs the way a release does, so anyone can rebuild a release's commit and
# get the same bytes. The release workflow runs this, and so does its rebuild that compares.
#
#   deploy/release/build.sh TARGET VERSION
#
# TARGET is a Rust target such as aarch64-apple-darwin. Linux targets build with cargo-zigbuild.
# Windows targets, *-pc-windows-msvc, build in Git Bash on a Windows runner, without the host, which
# runs on Linux.
# Programs land in packages/target/TARGET/release, or under CARGO_TARGET_DIR.
#
# The same bytes need the same commit, VERSION, toolchain (packages/rust-toolchain.toml), Cargo.lock,
# and for Linux the same zig and cargo-zigbuild, which release.yml pins. Where the clone and cargo's
# home are doesn't matter: both are rewritten out of the programs below. A Mac build also depends on
# the Xcode linker, which release.yml records.
set -eu

target=${1:?usage: build.sh TARGET VERSION}
version=${2:?}
repo=$(cd "$(dirname "$0")/../.." && pwd)
cargo_home=${CARGO_HOME:-$HOME/.cargo}

# What a program says it is: `splint --version`, and what a host and Signet report.
SPLINT_VERSION=$version
SPLINT_COMMIT=$(git -C "$repo" rev-parse HEAD)
# Nothing in the build reads the clock today. This keeps it that way for anything that would.
SOURCE_DATE_EPOCH=$(git -C "$repo" log -1 --format=%ct)
# Paths on the building machine would otherwise end up in the programs. On Windows, rustc sees them
# in Windows's own form, such as D:\a\splint, so that's what's rewritten.
case $target in
*-windows-*)
    repo_seen=$(cygpath -w "$repo")
    cargo_home_seen=$(cygpath -w "$cargo_home")
    ;;
*)
    repo_seen=$repo
    cargo_home_seen=$cargo_home
    ;;
esac
RUSTFLAGS="--remap-path-prefix=$repo_seen=/splint --remap-path-prefix=$cargo_home_seen=/cargo"
CARGO_INCREMENTAL=0
export SPLINT_VERSION SPLINT_COMMIT SOURCE_DATE_EPOCH RUSTFLAGS CARGO_INCREMENTAL

case $target in
*-linux-*) build=zigbuild ;;
# Apple's linker hashes the whole output into the program's UUID, including where each object file
# was, before the release profile strips that out. -S leaves it out from the start.
*-apple-*)
    build=build
    RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-S"
    ;;
# Microsoft's linker writes the time into each program unless told to write a hash of it instead. The
# crypto library's assembly comes prebuilt in its crate, so no assembler is needed and every build
# links the same objects.
*-windows-*)
    build=build
    RUSTFLAGS="$RUSTFLAGS -C link-arg=/Brepro"
    AWS_LC_SYS_PREBUILT_NASM=1
    export AWS_LC_SYS_PREBUILT_NASM
    ;;
*) build=build ;;
esac
case $target in
*-windows-*) programs="-p splint -p signet -p owner-key" ;;
*) programs="-p splint -p host -p signet -p owner-key" ;;
esac
cd "$repo/packages"
# The crypto library's C code names its source files in full, for its error messages. Its build gives
# the compiler its folder's 8.3 short name, such as ...\INDEXC~1.IO-\AWS-LC~2.0, which also depends on
# what cargo happened to unpack first, so the compiler is told to write that folder as /aws-lc-sys:
# Microsoft's, for x86_64, with /pathmap, and clang-cl, which it uses for Arm, with clang's own flag.
case $target in
*-windows-*)
    cargo fetch --locked --target "$target"
    aws_lc=$(awk '$0 == "name = \"aws-lc-sys\"" { getline; gsub(/"/, "", $3); print $3 }' Cargo.lock)
    set -- "$cargo_home"/registry/src/*/"aws-lc-sys-$aws_lc"
    if [ $# != 1 ] || [ ! -d "$1" ]; then
        echo "build.sh: expected one aws-lc-sys $aws_lc in $cargo_home, found: $*" >&2
        exit 1
    fi
    # The short name has no spaces, and the flags are split at spaces, so the long one goes in only
    # when it has none either.
    folders=$(cygpath -d "$1")
    long=$(cygpath -w "$1")
    case $long in *" "*) ;; *) folders="$folders $long" ;; esac
    case $target in
    aarch64-*) map=$(for folder in $folders; do printf ' /clang:-ffile-prefix-map=%s=/aws-lc-sys' "$folder"; done) ;;
    # Microsoft's compiler takes /pathmap only with /experimental:deterministic.
    *) map="/experimental:deterministic$(for folder in $folders; do printf ' /pathmap:%s=/aws-lc-sys' "$folder"; done)" ;;
    esac
    export "AWS_LC_SYS_CFLAGS_$(printf %s "$target" | tr - _)=$map"
    ;;
esac
# shellcheck disable=SC2086 # each word of $programs is its own argument
cargo "$build" --locked --release --target "$target" $programs

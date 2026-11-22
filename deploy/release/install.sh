#!/bin/sh
# Installs Splint's programs for this user into ~/.splint, with no sudo and nothing to build:
#
#   curl -fsSL https://github.com/nennovate/splint/releases/latest/download/install.sh | sh
#
# Each release writes its version, its commit and the SHA-256 of every archive and every program into
# this script, so the script alone decides what it will install, wherever the archive came from. With
# cosign 3 or later on the machine, it also checks that the archive was signed by this repository's
# release workflow for this tag, run on that commit. Any mismatch refuses, and leaves ~/.splint as it was.
#
# SPLINT_FROM_DIR=DIR installs from a release's files already downloaded into DIR, checked the same way.
#
# For a person setting up their controls, `controls HOST` installs the same way, then opens their controls
# on this computer, with `splint controls HOST` and anything after it:
#
#   curl -fsSL https://github.com/nennovate/splint/releases/latest/download/install.sh | sh -s -- controls HOST
#
# With --verify it installs nothing, and checks the programs in ~/.splint/bin are byte for byte this
# release's, running none of them:
#
#   curl -fsSL https://github.com/nennovate/splint/releases/download/VERSION/install.sh | sh -s -- --verify
set -eu

REPO=nennovate/splint
VERSION=@VERSION@
COMMIT=@COMMIT@
SUMS='
@SUMS@
'
SIGNER="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION"
ISSUER=https://token.actions.githubusercontent.com
PROGRAMS="splint splint-host splint-signet splint-owner-key"

say() { printf '%s\n' "$*" >&2; }
refuse() {
    say "splint install: $*. Nothing was installed."
    exit 1
}

# All of it is in main, run on the last line, so a download cut short runs nothing.
main() {
    case $VERSION in
    v[0-9]*) ;;
    *) refuse "this is the template in the repository, not a release's install.sh" ;;
    esac
    verifying=false
    controls=false
    case ${1:-} in
    "") ;;
    --verify) verifying=true ;;
    controls)
        [ -n "${2:-}" ] || refuse "controls needs the host that keeps your list, such as: controls splint.example"
        controls=true
        shift
        ;;
    *) refuse "the options are --verify, and controls HOST" ;;
    esac

    case "$(uname -s) $(uname -m)" in
    "Darwin arm64") platform=macos-arm64 ;;
    "Darwin x86_64") platform=macos-x86_64 ;;
    "Linux x86_64" | "Linux amd64") platform=linux-x86_64 ;;
    "Linux aarch64" | "Linux arm64") platform=linux-arm64 ;;
    *) refuse "there's no build for $(uname -s) $(uname -m)" ;;
    esac

    listed() { printf '%s\n' "$SUMS" | awk -v name="$1" '$2 == name { print $1 }'; }

    work=$(mktemp -d "${TMPDIR:-/tmp}/splint-install.XXXXXX")
    trap 'rm -rf "$work"' EXIT
    trap 'exit 1' INT TERM

    # From SPLINT_FROM_DIR, or the release, or with gh while the repository is private.
    fetch() {
        if [ -n "${SPLINT_FROM_DIR:-}" ]; then
            cp "$SPLINT_FROM_DIR/$1" "$work/$1" 2>/dev/null
        elif curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$work/$1" \
            "https://github.com/$REPO/releases/download/$VERSION/$1" 2>/dev/null; then
            :
        elif command -v gh >/dev/null 2>&1; then
            gh release download "$VERSION" --repo "$REPO" --pattern "$1" --dir "$work" --clobber >/dev/null 2>&1
        else
            return 1
        fi
    }

    sha256_of() {
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$1" | awk '{ print $1 }'
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 "$1" | awk '{ print $1 }'
        elif command -v openssl >/dev/null 2>&1; then
            openssl dgst -sha256 -r "$1" | awk '{ print $1 }'
        else
            return 1
        fi
    }

    # Older cosign can't read the bundle format a release is signed in.
    cosign_can_check() {
        command -v cosign >/dev/null 2>&1 || return 1
        major=$(cosign version 2>/dev/null | awk '/^GitVersion/ { sub(/^v/, "", $2); split($2, part, "."); print part[1] }')
        [ -n "$major" ] && [ "$major" -ge 3 ]
    }

    if $verifying; then
        verify
        return
    fi

    archive="splint-$VERSION-$platform.tar.gz"
    want=$(listed "$archive")
    [ -n "$want" ] || refuse "this release has no checksum for $archive"

    fetch "$archive" || refuse "couldn't download $archive from github.com/$REPO for $VERSION"
    got=$(sha256_of "$work/$archive") || refuse "there's no sha256sum, shasum or openssl here to check the download"
    [ "$got" = "$want" ] || refuse "$archive doesn't match the checksum $VERSION was released with"

    if cosign_can_check; then
        fetch "$archive.sigstore.json" || refuse "couldn't download $archive.sigstore.json"
        cosign verify-blob --bundle "$work/$archive.sigstore.json" --certificate-identity "$SIGNER" \
            --certificate-oidc-issuer "$ISSUER" --certificate-github-workflow-repository "$REPO" \
            --certificate-github-workflow-sha "$COMMIT" "$work/$archive" >/dev/null 2>&1 ||
            refuse "$archive isn't signed by $REPO's release workflow for $VERSION on $COMMIT"
        checked="its checksum and its signature"
    else
        checked="its checksum. There's no cosign 3 here, so its signature wasn't checked"
    fi

    mkdir "$work/open"
    tar -xzf "$work/$archive" -C "$work/open" || refuse "$archive wouldn't unpack"
    found="$work/open/splint-$VERSION-$platform"
    for program in $PROGRAMS; do
        [ -f "$found/bin/$program" ] || refuse "$archive has no $program"
    done
    [ -d "$found/examples" ] && [ -d "$found/adapters" ] || refuse "$archive is missing what the programs read"

    home="$HOME/.splint"
    mkdir -p "$home/bin"
    chmod 700 "$home"
    # Each program is replaced in one rename, so one already running keeps going and nothing is half-written.
    for program in $PROGRAMS; do
        cp "$found/bin/$program" "$home/bin/.$program.new"
        chmod 755 "$home/bin/.$program.new"
        mv -f "$home/bin/.$program.new" "$home/bin/$program"
    done
    # A schemas folder an older release installed held types Signet ran; now nothing reads it.
    rm -rf "${home:?}/schemas"
    for folder in examples adapters; do
        rm -rf "$home/.$folder.new"
        cp -R "$found/$folder" "$home/.$folder.new"
        rm -rf "${home:?}/$folder"
        mv "$home/.$folder.new" "$home/$folder"
    done

    # What was running keeps running the build this replaced until it's started again, still signing.
    # So each agent here that's running now is started again, which runs this build in its place.
    # splint decides that by the lock a running copy holds, and says nothing for one stopped with
    # splint stop, one that crashed, or one never started, which are left as they were: only its person
    # starts it. A running splint host isn't started again here, and runs the build it started with
    # until splint host stop and splint host start.
    for folder in "$home" "$home"/profiles/*; do
        [ -d "$folder/run" ] || continue
        if [ "$folder" = "$home" ]; then
            said=$("$home/bin/splint" start --if-running 2>/dev/null) && started=yes || started=no
        else
            said=$("$home/bin/splint" --as "${folder##*/}" start --if-running 2>/dev/null) && started=yes || started=no
        fi
        if [ "$started" = no ]; then
            say "Couldn't start what runs for $folder again: splint status there says why, and splint start runs $VERSION."
        elif [ -n "$said" ]; then
            say "Started what runs for $folder again, so it runs $VERSION."
        fi
    done

    say "Installed Splint $VERSION for $platform into $home/bin, after checking $checked."
    say "splint verify, or this script with --verify, checks them again later."
    say "Wherever a step says splint, run $home/bin/splint, or first: export PATH=\"\$HOME/.splint/bin:\$PATH\""
    if $controls; then
        # exec skips the EXIT trap, so the download goes first.
        rm -rf "$work"
        exec "$home/bin/splint" controls "$@"
    fi
}

# Checks what's installed against this release, by this script's own lists alone.
verify() {
    differ=0
    for program in $PROGRAMS; do
        want=$(listed "splint-$VERSION-$platform/bin/$program")
        [ -n "$want" ] || refuse "this release lists no $program for $platform"
        if [ ! -f "$HOME/.splint/bin/$program" ]; then
            say "$program: not installed in $HOME/.splint/bin"
            differ=1
        elif [ "$(sha256_of "$HOME/.splint/bin/$program")" = "$want" ]; then
            say "$program: the same as $VERSION for $platform"
        else
            say "$program: NOT the same as $VERSION for $platform"
            differ=1
        fi
    done
    [ "$differ" = 0 ] || {
        say "install.sh --verify: what's installed isn't $VERSION. Reinstall it, and find out what changed it."
        exit 1
    }
}

main "$@"

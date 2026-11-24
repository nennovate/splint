#!/bin/bash
# Upgrades this host to a release, and takes nothing the release workflow didn't sign.
#
#   sudo splint-upgrade            the newest release
#   sudo splint-upgrade v0.3.1     that release, which can be a candidate such as v0.4.0-rc.1
#
# docs/run-a-host.md says what to do around this. It fetches the release's install.sh and takes it
# only if this repository's release workflow signed it for that tag. That script has the checksum of
# every archive fixed inside it, and fetches and checks the build for this machine. deploy/ comes from
# the commit the script names. Then a backup is taken, and that release's deploy/install.sh puts the
# build in place the way a first install does: settings kept, the new host made to read them before
# the running one is stopped, and the host checked over TLS at the end.
#
# A host's database only moves forward, so a release older than the one running is refused, and the
# way back from an upgrade is splint-restore with the backup this took.
#
# The work runs as a systemd unit of its own, splint-upgrade, so it finishes even when the connection
# that asked for it drops halfway. At a terminal its output is shown as it goes. With no terminal, as
# when another machine asks over SSH, this says only what it decided and whether the host was
# upgraded, and the rest stays in this host's journal: journalctl -u splint-upgrade.
#
# The one argument is read as a release's name and nothing else, so an SSH key held to this command,
# as docs/run-a-host.md shows, can ask for a signed release and can't do anything more.
set -euo pipefail

readonly REPO=nennovate/splint
readonly ISSUER=https://token.actions.githubusercontent.com
readonly SETTINGS=/etc/splint/host.env
readonly RUNNING=/etc/splint/release
readonly UNIT=splint-upgrade.service
# cosign checks the signature. It's one fixed version, refused unless it's byte for byte the one
# pinned. A newer version's hashes are in cosign_checksums.txt beside each release of sigstore/cosign.
readonly COSIGN_VERSION=v3.1.4
readonly COSIGN_AMD64=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
readonly COSIGN_ARM64=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2

# A file for what this says itself, which a caller with no terminal is shown. What a release's
# installer says stays in the journal.
said=
# The same file, as the run a person or a key started knows it.
heard=
# Where a release is fetched and checked before any of it is put in place, gone when this ends.
work=

say() {
    printf '%s\n' "$*" >&2
    if [ -n "$said" ]; then
        printf '%s\n' "$*" >>"$said" 2>/dev/null || true
    fi
}

refuse() {
    say "splint-upgrade: $*. The host that was running still is."
    exit 1
}

# A release's name and nothing else: this is all that a key held to this command gets to say.
is_a_release() {
    [[ $1 =~ ^v[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}(-rc\.[0-9]{1,3})?$ ]]
}

# 0.3.0-rc.1 comes before 0.3.0, which sort -V has the other way round unless the plain one is given
# an ending that sorts after any candidate's.
is_older() {
    local a=$1 b=$2
    [ "$a" != "$b" ] || return 1
    case $a in *-*) ;; *) a=$a-zz ;; esac
    case $b in *-*) ;; *) b=$b-zz ;; esac
    [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n 1)" = "$a" ]
}

fetch() {
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1" 2>/dev/null
}

# GitHub answers releases/latest by sending the caller to the newest release that isn't a candidate.
newest_release() {
    local landed
    landed=$(curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest" 2>/dev/null) || return 1
    printf '%s\n' "${landed##*/}"
}

cosign_can_check() {
    local major
    command -v cosign >/dev/null 2>&1 || return 1
    major=$(cosign version 2>/dev/null | awk '/^GitVersion/ { sub(/^v/, "", $2); split($2, part, "."); print part[1] }')
    [ -n "$major" ] && [ "$major" -ge 3 ]
}

install_cosign() {
    local into=$1 arch sha256
    case "$(uname -m)" in
    x86_64) arch=amd64 sha256=$COSIGN_AMD64 ;;
    aarch64) arch=arm64 sha256=$COSIGN_ARM64 ;;
    *) refuse "there's no pinned cosign for $(uname -m), and nothing is installed here without its signature checked" ;;
    esac
    fetch "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-$arch" "$into/cosign" ||
        refuse "couldn't download cosign $COSIGN_VERSION, which checks the release's signature"
    echo "$sha256  $into/cosign" | sha256sum --check --quiet >/dev/null 2>&1 ||
        refuse "the cosign download didn't match its pinned hash, so it wasn't run"
    install -m 755 "$into/cosign" /usr/local/bin/cosign
}

# Both change only with a rotation or a recovery, which an upgrade is neither of.
key_and_id() {
    cat /var/lib/splint/host.key /var/lib/splint/host.key.identity 2>/dev/null | sha256sum
}

upgrade_to() {
    local release=$1 domain running commit before program tool from
    is_a_release "$release" || refuse "that isn't a release's name, such as v0.3.1"
    domain=$(sed -n 's/^SPLINT_DOMAIN=//p' "$SETTINGS" 2>/dev/null | tail -n 1)
    [ -n "$domain" ] || refuse "there's no host here to upgrade, as $SETTINGS names none. deploy/install.sh sets one up"
    running=$(cat "$RUNNING" 2>/dev/null || true)
    if [ "$running" = "$release" ]; then
        say "This host already runs $release."
        return
    fi
    if [ -n "$running" ] && is_a_release "$running" && is_older "$release" "$running"; then
        refuse "this host runs $running and $release is older. A host's database only moves forward, so the way back is splint-restore with a backup"
    fi
    for tool in curl git tar sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || refuse "there's no $tool here, which this needs"
    done

    work=$(mktemp -d /var/tmp/splint-upgrade.XXXXXX)
    trap 'rm -rf "$work"' EXIT
    cosign_can_check || install_cosign "$work"

    from="https://github.com/$REPO/releases/download/$release"
    if ! fetch "$from/install.sh" "$work/install.sh" || ! fetch "$from/install.sh.sigstore.json" "$work/install.sh.sigstore.json"; then
        refuse "couldn't download $release from github.com/$REPO. Check that it's a release there"
    fi
    cosign verify-blob --bundle "$work/install.sh.sigstore.json" \
        --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$release" \
        --certificate-oidc-issuer "$ISSUER" --certificate-github-workflow-repository "$REPO" \
        "$work/install.sh" >/dev/null 2>&1 ||
        refuse "$release's install.sh isn't signed by $REPO's release workflow for that tag"
    grep -qx "VERSION=$release" "$work/install.sh" || refuse "the install.sh signed for $release says it's another release"
    commit=$(sed -n 's/^COMMIT=\([0-9a-f]\{40\}\)$/\1/p' "$work/install.sh")
    [ -n "$commit" ] || refuse "$release's install.sh doesn't name the commit it was built from"

    # The signed script decides what it takes: the archive for this machine has to match the checksum
    # inside it, and the workflow's signature for this tag and commit.
    mkdir "$work/home" "$work/bin"
    HOME="$work/home" sh "$work/install.sh" >"$work/install.log" 2>&1 || {
        cat "$work/install.log" >&2
        refuse "$release's build for this machine didn't check out, as its install.sh says above"
    }
    for program in host signet owner-key; do
        install -m 755 "$work/home/.splint/bin/splint-$program" "$work/bin/$program"
    done

    # deploy/ as it was at the commit the release was built from. Git names a commit by a hash of
    # everything in it, so asking for that commit by name gets those files or nothing.
    git init -q "$work/source"
    git -C "$work/source" fetch -q --depth 1 "https://github.com/$REPO.git" "$commit" 2>/dev/null ||
        refuse "couldn't fetch commit $commit, which $release was built from"
    git -C "$work/source" -c advice.detachedHead=false checkout -q FETCH_HEAD
    [ "$(git -C "$work/source" rev-parse HEAD)" = "$commit" ] || refuse "what was fetched isn't commit $commit"
    # An older release's installer doesn't know it's being run for an upgrade, so it could make a
    # recovery code and show it here, where output is kept.
    grep -q SPLINT_RELEASE "$work/source/deploy/install.sh" ||
        refuse "$release is from before a host could be upgraded this way. Check out that tag and run its deploy/install.sh, as its docs/run-a-host.md says"

    if [ -s /etc/splint/backup-recipient ]; then
        systemctl start splint-backup.service ||
            refuse "the backup before the upgrade failed, and journalctl -u splint-backup says why, so the upgrade didn't start"
        say "Took a backup, which is the way back from this upgrade."
    else
        say "No backups are set up on this host, so none was taken before this upgrade."
    fi

    before=$(key_and_id)
    if ! SPLINT_RELEASE=$release bash "$work/source/deploy/install.sh" "$domain" "$work/bin"; then
        say "splint-upgrade: $release's deploy/install.sh stopped, as it says in journalctl -u splint-upgrade. It's safe to run again once that's put right."
        exit 1
    fi
    for program in host signet owner-key; do
        cmp -s "$work/bin/$program" "/usr/local/bin/splint-$program" ||
            { say "splint-upgrade: /usr/local/bin/splint-$program isn't $release's, though its installer finished."; exit 1; }
    done
    if [ "$(key_and_id)" != "$before" ]; then
        say "splint-upgrade: the host's key or ID changed during the upgrade, which an upgrade never does. Other hosts know this one by its ID: docs/run-a-host.md says how to put a key and ID back."
        exit 1
    fi
    printf '%s\n' "$release" >"$RUNNING"
    chmod 644 "$RUNNING"
    say "$domain now runs $release."
}

# All of it is in main, run on the last line, so this file being replaced by the release it installs
# changes nothing about the run that's replacing it.
main() {
    if [ "${1:-}" = --in-service ]; then
        said=${3:-}
        upgrade_to "${2:-}"
        return
    fi
    [ $# -le 1 ] || refuse "this takes one release, such as v0.3.1, or none for the newest"
    local release=${1:-} self status=0 follower=
    if [ -n "$release" ]; then
        is_a_release "$release" || refuse "that isn't a release's name, such as v0.3.1"
    fi
    if [ "$(id -u)" != 0 ]; then
        say "splint-upgrade changes the host's programs, which needs root: sudo splint-upgrade${release:+ $release}"
        exit 1
    fi
    if [ -z "$release" ]; then
        if ! release=$(newest_release) || ! is_a_release "$release"; then
            refuse "couldn't find the newest release at github.com/$REPO. Name one, such as: splint-upgrade v0.3.1"
        fi
    fi
    if systemctl is-active --quiet "$UNIT"; then
        refuse "an upgrade is already running here, and journalctl -u splint-upgrade -f follows it"
    fi
    systemctl reset-failed "$UNIT" 2>/dev/null || true
    heard=$(mktemp)
    trap 'rm -f "$heard"' EXIT
    self=$(readlink -f "$0")
    if [ -t 2 ]; then
        journalctl --unit="$UNIT" --follow --lines=0 --output=cat --no-pager >&2 &
        follower=$!
    fi
    systemd-run --quiet --wait --collect --unit="$UNIT" --description="Upgrade this Splint host to $release" \
        --setenv=HOME=/root "$self" --in-service "$release" "$heard" || status=$?
    if [ -n "$follower" ]; then
        # The journal hands lines on a moment after they're written.
        journalctl --sync 2>/dev/null || true
        sleep 1
        kill "$follower" 2>/dev/null || true
    else
        cat "$heard" >&2
    fi
    if [ "$status" != 0 ]; then
        say "The upgrade to $release didn't finish. On this host, sudo journalctl -u splint-upgrade has all of it."
        exit 1
    fi
}

main "$@"

#!/bin/bash
# Stands a Splint host up on a fresh Ubuntu 24.04 server, from a checkout. Safe to run again.
#
#   SPLINT_BACKUP_RECIPIENT=age1... deploy/install.sh DOMAIN [BINARY_DIR]
#
# docs/run-a-host.md says what to do around this. DOMAIN is this host's public name, which has to
# point here already. The host exchanges with every other host, unless /etc/splint/peers says
# `private`. SPLINT_PRIVATE_PEERS=HOST,HOST makes that file private to those hosts on a first install;
# after that the file is the operator's, and the running host reads it again by itself.
# BINARY_DIR holds binaries already built for this machine, so a small server needn't compile.
# SPLINT_BACKUP_RECIPIENT is the public half of an age key whose private half stays off this server.
# Without it, or one saved by an earlier run, there are no backups, rather than plain ones.
# SPLINT_SIGNUP is open, the usual, where agents join with no code under the limits in limits.env,
# or code, where every agent needs a signup code. Given on a later run it changes which, and left
# out it keeps what the host has.
# SPLINT_PEOPLE_SITE=https://... sends a person who opens this host in a browser to that site. Agents,
# crawlers and other hosts still get the host's own note. Given on a later run it changes where,
# given with nothing after it there's no such site any more, and left out it keeps what the host has.
# SPLINT_RELEASE=v0.3.1 is how splint-upgrade runs this, naming the release these binaries are. Its
# output is kept in the journal, so such a run never makes a recovery code. A run without it forgets
# which release the host ran, in /etc/splint/release, as a checkout could be any commit.
# Secrets are made here and stay here: nothing this writes belongs in the repo. The host's recovery
# code is shown once, at the end of the first run that sets it: copy it off the server, and don't run
# this through anything that keeps its output.
#
# A later run keeps every setting already in /etc/splint/host.env and /etc/splint/limits.env, and
# adds only what's missing. Before anything is restarted, the new host reads those settings with
# splint-host check: if it refuses one, this stops there and the host that was running still is.
#
# If root has an SSH key, root stops logging in over SSH, and whoever holds a key in root's
# authorized_keys logs in as splint-admin instead, and uses sudo. With none, root login is left as it is.
set -euo pipefail

domain=${1:?usage: install.sh DOMAIN [BINARY_DIR]}
binaries=${2:-}
private_peers=${SPLINT_PRIVATE_PEERS:-}
# The second argument was once a list of peers. A host is open to every other now, so a list there is
# a mistake to say out loud rather than a folder to look for binaries in.
if [ -n "$binaries" ] && [ ! -d "$binaries" ]; then
    echo "$binaries isn't a folder of binaries. There's no peer list to give now: a host exchanges with every other host, and SPLINT_PRIVATE_PEERS=HOST,HOST keeps a new one to those. docs/run-a-host.md says more." >&2
    exit 1
fi
signup=${SPLINT_SIGNUP:-}
case "$signup" in
"" | open | code) ;;
*)
    echo "SPLINT_SIGNUP is open or code, not $signup" >&2
    exit 1
    ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
checkout=$(dirname "$here")
# Where a person who opens this host in a browser is sent, if anywhere: what this run was given, or
# what an earlier one kept. It goes into the proxy's settings, so it's checked now, before anything
# on this server changes.
readonly PEOPLE_SITE=/etc/splint/people-site
if [ -n "${SPLINT_PEOPLE_SITE+given}" ]; then
    people_site=$SPLINT_PEOPLE_SITE
else
    people_site=$(cat "$PEOPLE_SITE" 2>/dev/null || true)
fi
bash "$here/caddyfile.sh" "$domain" "$people_site" >/dev/null
export DEBIAN_FRONTEND=noninteractive
readonly MAX_CONNECTIONS_PER_ADDRESS=128
readonly SETTINGS=/etc/splint/host.env
readonly LIMITS=/etc/splint/limits.env
readonly KEPT_NAMES=/etc/splint/reserved-names
# What a first install makes, for a host to hand out past its open limits or where it takes codes alone.
readonly FIRST_SIGNUP_CODES=20

# One address can hold this many connections. The host caps its own and closes idle ones, but only a
# limit in front of the proxy can tell one caller from another before a request has even started. An
# IPv6 customer usually has a whole /64, so that counts as one. `ufw --force reset` restores these
# files, so this adds to fresh ones each run.
limit_connections_per_address() {
    local ports="-p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above $MAX_CONNECTIONS_PER_ADDRESS"
    local refuse="-j REJECT --reject-with tcp-reset"
    sed -i "/^COMMIT/i -A ufw-before-input $ports --connlimit-mask 32 $refuse" /etc/ufw/before.rules
    sed -i "/^COMMIT/i -A ufw6-before-input $ports --connlimit-mask 64 $refuse" /etc/ufw/before6.rules
}

secure_the_server() {
    # Compiling and a burst of load both need room, and 2 GB isn't much of it.
    if ! swapon --show | grep -q /swapfile; then
        fallocate -l 2G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile >/dev/null
        swapon /swapfile
        grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
    fi
    ufw --force reset >/dev/null
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw allow 22/tcp >/dev/null
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
    limit_connections_per_address
    ufw --force enable >/dev/null
    apt-get update -qq
    apt-get install -y -qq unattended-upgrades postgresql curl gnupg age git \
        debian-keyring debian-archive-keyring apt-transport-https ca-certificates >/dev/null
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
        >/etc/apt/apt.conf.d/20auto-upgrades
    systemctl enable --now unattended-upgrades >/dev/null
    # Logs name message IDs and who sent them, so they're kept for a stated time too.
    mkdir -p /etc/systemd/journald.conf.d
    printf '[Journal]\nMaxRetentionSec=14day\nSystemMaxUse=500M\n' >/etc/systemd/journald.conf.d/splint.conf
    systemctl restart systemd-journald
}

# Done last, so a run that fails earlier leaves SSH as it was. Root's keys move to a named admin, so
# whoever set the server up keeps their access, and nothing changes if root has no key to move.
lock_down_ssh() {
    local admin=splint-admin home=/home/splint-admin
    id "$admin" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$admin"
    if [ ! -s "$home/.ssh/authorized_keys" ] && [ -s /root/.ssh/authorized_keys ]; then
        install -d -m 700 -o "$admin" -g "$admin" "$home/.ssh"
        install -m 600 -o "$admin" -g "$admin" /root/.ssh/authorized_keys "$home/.ssh/authorized_keys"
    fi
    if [ ! -s "$home/.ssh/authorized_keys" ]; then
        echo "No SSH key for $admin, so root login is left as it is." >&2
        return
    fi
    # The admin has no password, so sudo can't ask for one.
    echo "$admin ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/splint-admin.new
    chmod 440 /etc/sudoers.d/splint-admin.new
    visudo -cqf /etc/sudoers.d/splint-admin.new
    mv /etc/sudoers.d/splint-admin.new /etc/sudoers.d/splint-admin
    # sshd takes the first value it reads, and this file sorts before the image's own.
    cat >/etc/ssh/sshd_config.d/10-splint.conf.new <<SSHD
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers $admin
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
SSHD
    mv /etc/ssh/sshd_config.d/10-splint.conf.new /etc/ssh/sshd_config.d/10-splint.conf
    if ! sshd -t; then
        rm -f /etc/ssh/sshd_config.d/10-splint.conf
        echo "sshd refused the new settings, so they were taken out again." >&2
        return 1
    fi
    systemctl reload ssh
    ssh_admin=yes
}

install_caddy() {
    command -v caddy >/dev/null && return
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key |
        gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
        >/etc/apt/sources.list.d/caddy-stable.list
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg \
        /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy >/dev/null
}

# On the template, as postgresql.service only stands for the postgresql@16-main that really runs it.
# Starting Postgres here is for a server whose Postgres had already given up before this run.
keep_services_coming_back() {
    local unit
    for unit in caddy.service postgresql@.service; do
        install -D -m 644 "$here/come-back.conf" "/etc/systemd/system/$unit.d/restart.conf"
    done
    systemctl daemon-reload
    systemctl start postgresql
}

# No password: the socket says which Unix user is calling, and Postgres takes no network connections.
set_up_postgres() {
    conf=$(ls /etc/postgresql/*/main/postgresql.conf)
    if ! grep -q "^listen_addresses = ''" "$conf"; then
        sed -i "s/^#\?listen_addresses.*/listen_addresses = ''/" "$conf"
        systemctl restart postgresql
    fi
    local psql=(runuser -u postgres -- psql -v ON_ERROR_STOP=1 -tA)
    if [ -z "$("${psql[@]}" -c "SELECT 1 FROM pg_roles WHERE rolname = 'splint'")" ]; then
        "${psql[@]}" -c "CREATE ROLE splint LOGIN" >/dev/null
    fi
    if [ -z "$("${psql[@]}" -c "SELECT 1 FROM pg_database WHERE datname = 'splint'")" ]; then
        "${psql[@]}" -c "CREATE DATABASE splint OWNER splint" >/dev/null
    fi
}

# Rust's installer runs as root here, so it's one fixed version, and a download that isn't byte for
# byte the one pinned is refused before it runs. A newer version's hashes are in the .sha256 file
# beside each rustup-init in https://static.rust-lang.org/rustup/archive/.
install_rustup() {
    local version=1.29.3 arch sha256 folder init
    arch=$(uname -m)
    case "$arch" in
    x86_64) sha256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55 ;;
    aarch64) sha256=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282 ;;
    *)
        echo "there's no pinned Rust installer for $arch: build the binaries elsewhere and give their folder" >&2
        exit 1
        ;;
    esac
    # It goes by the name it's run as, so it keeps its own.
    folder=$(mktemp -d)
    init=$folder/rustup-init
    curl -sSf -o "$init" "https://static.rust-lang.org/rustup/archive/$version/$arch-unknown-linux-gnu/rustup-init"
    if ! echo "$sha256  $init" | sha256sum --check --quiet >/dev/null 2>&1; then
        rm -rf "$folder"
        echo "the Rust installer didn't match its pinned hash, so it wasn't run" >&2
        exit 1
    fi
    chmod 700 "$init"
    "$init" -y --profile minimal --no-modify-path >/dev/null
    rm -rf "$folder"
}

build_binaries() {
    if [ -n "$binaries" ]; then
        return
    fi
    apt-get install -y -qq build-essential pkg-config cmake >/dev/null
    export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust
    if [ ! -x /opt/rust/bin/cargo ]; then
        install_rustup
    fi
    # One job, so the linker and the compiler don't both want the same memory.
    (cd "$checkout/packages" && CARGO_BUILD_JOBS=1 /opt/rust/bin/cargo build --release --locked \
        -p host -p signet -p owner-key)
    binaries=$checkout/packages/target/release
}

# Beside the ones in use, which stay until the new host has read this server's settings.
stage_binaries() {
    for binary in host signet owner-key; do
        install -m 755 "$binaries/$binary" "/usr/local/bin/splint-$binary.new"
    done
}

install_binaries() {
    for binary in host signet owner-key; do
        mv -f "/usr/local/bin/splint-$binary.new" "/usr/local/bin/splint-$binary"
    done
}

# Only where it isn't set already, so what this host's operator wrote stays as they wrote it.
set_if_missing() {
    grep -q "^$1=" "$SETTINGS" || printf '%s=%s\n' "$1" "$2" >>"$SETTINGS"
}

setting() {
    sed -n "s/^$1=//p" "$SETTINGS" | tail -n 1
}

# A limit newer than this server's file goes in as the shipped file has it, commented out at its
# usual number, so every limit there is can be seen there.
add_missing_limits() {
    local line name said=
    while IFS= read -r line; do
        name=${line#\#}
        name=${name%%=*}
        if ! grep -Eq "^#?[[:space:]]*$name=" "$LIMITS"; then
            if [ -z "$said" ]; then
                printf '\n# Limits a later release added, each at its usual number. deploy/limits.env says what each is for.\n' >>"$LIMITS"
                said=yes
            fi
            printf '%s\n' "$line" >>"$LIMITS"
        fi
    done < <(grep '^#SPLINT_MAX_[A-Z_]*=' "$here/limits.env")
}

# Who this host exchanges with. It's the operator's own, and the running host reads it again every
# couple of seconds, so it's written once and a later run leaves it alone. With no line it's open to
# every host. SPLINT_PRIVATE_PEERS makes it private to those hosts. A list an earlier version kept in
# host.env is named here, so those hosts keep being called wherever they are, and the host is open.
write_peers_file() {
    local named=$private_peers private=yes
    if [ -z "$named" ] && [ -f "$SETTINGS" ]; then
        named=$(setting SPLINT_PEERS)
        private=
        if [ -n "$named" ]; then
            echo "The peers host.env listed are named in /etc/splint/peers, and this host now exchanges with every other host too. To keep it to them, add a line: private" >&2
        fi
    fi
    {
        cat <<'PEERS'
# Which other hosts this one exchanges with: every host, unless a line says `private`. The running
# host reads this file again within a few seconds of a change, so nothing restarts. A file it can't
# use changes nothing, and its log says why. docs/run-a-host.md says more.
#
#   private       only the hosts named with `peer` below
#   peer HOST     a host this one exchanges with, wherever it is, even on an internal address
#   block HOST    a host this one never calls or hears, even when it's named
#   repin HOST    let go of that host's pinned key once, and pin the one it publishes now
PEERS
        if [ -n "$named" ]; then
            if [ -n "$private" ]; then
                echo private
            fi
            for peer in ${named//,/ }; do
                echo "peer $peer"
            done
        fi
    } >/etc/splint/peers.new
    chown root:splint /etc/splint/peers.new
    chmod 640 /etc/splint/peers.new
    mv /etc/splint/peers.new /etc/splint/peers
}

write_settings() {
    id splint >/dev/null 2>&1 ||
        useradd --system --create-home --home-dir /var/lib/splint --shell /usr/sbin/nologin splint
    chmod 700 /var/lib/splint
    install -d -m 750 -o root -g splint /etc/splint
    install -d -m 700 -o splint -g splint /var/backups/splint
    if [ ! -f "$SETTINGS" ]; then
        signup=${signup:-open}
        (umask 027 && : >"$SETTINGS")
    fi
    set_if_missing SPLINT_DOMAIN "$domain"
    # A host's name is where every agent on it is reached, and it doesn't change.
    if [ "$(setting SPLINT_DOMAIN)" != "$domain" ]; then
        echo "This server's host is $(setting SPLINT_DOMAIN), by $SETTINGS, and a host's name doesn't change. Run this with that name." >&2
        exit 1
    fi
    # Seeded from SPLINT_PEERS in host.env, where an earlier version kept the list.
    if [ ! -f /etc/splint/peers ]; then
        write_peers_file
    fi
    set_if_missing SPLINT_PEERS_FILE /etc/splint/peers
    set_if_missing SPLINT_LISTEN 127.0.0.1:8080
    set_if_missing SPLINT_DATABASE_URL 'postgres:///splint?host=/var/run/postgresql&user=splint'
    set_if_missing SPLINT_HOST_KEY_FILE /var/lib/splint/host.key
    # The host reads its limits from the file itself, and again as it runs, so a change needs no restart.
    set_if_missing SPLINT_LIMITS_FILE "$LIMITS"
    # Names nobody here has as their own, such as brands, which any agent can still have as its handle.
    set_if_missing SPLINT_RESERVED_NAMES "$KEPT_NAMES"
    # Anyone with an owner key can take an address here, within the limits in limits.env, unless
    # whoever runs it chose codes alone. Codes work either way.
    case "$signup" in
    open) set_if_missing SPLINT_OPEN_SIGNUP yes ;;
    code) sed -i '/^SPLINT_OPEN_SIGNUP=/d' "$SETTINGS" ;;
    esac
    chown root:splint "$SETTINGS"
    chmod 640 "$SETTINGS"
    # The operator's own, so a later run leaves what's set alone. Every limit is here, at its usual number.
    if [ ! -f "$LIMITS" ]; then
        install -m 640 -o root -g splint "$here/limits.env" "$LIMITS"
    fi
    # The operator's own too, started from the names in deploy/reserved-names.
    if [ ! -f "$KEPT_NAMES" ]; then
        install -m 640 -o root -g splint "$here/reserved-names" "$KEPT_NAMES"
    fi
    add_missing_limits
    # Kept for a later run, which sends people to the same place unless it's told otherwise.
    if [ -n "$people_site" ]; then
        printf '%s\n' "$people_site" >"$PEOPLE_SITE"
        chmod 644 "$PEOPLE_SITE"
    else
        rm -f "$PEOPLE_SITE"
    fi
    bash "$here/caddyfile.sh" "$domain" "$people_site" >/etc/caddy/Caddyfile
    install -m 755 "$here/backup.sh" /usr/local/bin/splint-backup
    install -m 755 "$here/restore.sh" /usr/local/bin/splint-restore
    install -m 755 "$here/hostctl.sh" /usr/local/bin/splint-hostctl
    install -m 755 "$here/upgrade.sh" /usr/local/bin/splint-upgrade
    if [ -n "${SPLINT_BACKUP_RECIPIENT:-}" ]; then
        printf '%s\n' "$SPLINT_BACKUP_RECIPIENT" >/etc/splint/backup-recipient.new
        age -R /etc/splint/backup-recipient.new -o /dev/null /dev/null
        chmod 644 /etc/splint/backup-recipient.new
        mv /etc/splint/backup-recipient.new /etc/splint/backup-recipient
    fi
}

# The new host reads this server's settings before the one running is stopped, so a setting it
# refuses costs nobody their host: the old one carries on, and this says which setting and why.
check_before_restarting() {
    if SPLINT_HOST_BINARY=/usr/local/bin/splint-host.new /usr/local/bin/splint-hostctl check; then
        return
    fi
    rm -f /usr/local/bin/splint-host.new /usr/local/bin/splint-signet.new /usr/local/bin/splint-owner-key.new
    echo "The new host refused this server's settings, as it says above, so nothing was restarted and the host that was running still is. Put that right in $SETTINGS or $LIMITS, then run this again." >&2
    exit 1
}

# Codes used to reach the host through its settings, at each start. They're rows in its database
# now, which splint-hostctl codes add makes and the running host reads at each join. Every start so
# far has put the ones in the settings there, so that line, and the file it was copied from, can go
# once the host lists its codes. A host that has never had a code gets its first ones here.
settle_signup_codes() {
    local listed
    for _ in $(seq 30); do
        if listed=$(/usr/local/bin/splint-hostctl codes list 2>/dev/null); then
            if grep -q '^SPLINT_SIGNUP_CODES=' "$SETTINGS"; then
                sed -i '/^SPLINT_SIGNUP_CODES=/d' "$SETTINGS"
                rm -f /etc/splint/signup-codes
            fi
            if [ -z "$listed" ]; then
                /usr/local/bin/splint-hostctl codes add "$FIRST_SIGNUP_CODES" >/dev/null
            fi
            return
        fi
        sleep 1
    done
    echo "The host didn't list its signup codes, so none were made. Once it's up: sudo splint-hostctl codes add $FIRST_SIGNUP_CODES" >&2
}

secure_the_server
install_caddy
keep_services_coming_back
set_up_postgres
build_binaries
write_settings
stage_binaries
check_before_restarting
# The list is in /etc/splint/peers now. The old line goes only once the new host has taken that file,
# so an update it refuses leaves the running host its peers at its next restart.
sed -i '/^SPLINT_PEERS=/d' "$SETTINGS"
install_binaries
# splint-upgrade writes which release a host runs once it has checked what this put in place, and
# reads it to refuse an older one. These binaries aren't a release's unless it says so.
[ -n "${SPLINT_RELEASE:-}" ] || rm -f /etc/splint/release
install -m 644 "$here"/splint-*.service "$here"/splint-*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now splint-host.service
if [ -s /etc/splint/backup-recipient ]; then
    systemctl enable --now splint-backup.timer
else
    systemctl disable --now splint-backup.timer 2>/dev/null || true
    echo "No SPLINT_BACKUP_RECIPIENT, so no backups are taken." >&2
fi
systemctl restart splint-host.service
systemctl restart caddy
settle_signup_codes
# The certificate can take a moment. What a person needs to hear is whether it's really up, over TLS.
for _ in $(seq 60); do
    if curl -fsS --max-time 5 "https://$domain/.well-known/splint/host" >/dev/null 2>&1; then
        up=yes
        break
    fi
    sleep 2
done
# The host made its ID at start. A recovery code is set once, on the first run with none, and shown
# here once: it's what replaces a lost or stolen key with every other host following. It goes nowhere
# else, so it's only in this output.
if [ -n "${SPLINT_RELEASE:-}" ]; then
    # Run by splint-upgrade, whose output is kept. A host with no code yet warns of it at every start.
    :
elif [ -f /var/lib/splint/host.key.identity ]; then
    code=$(/usr/local/bin/splint-hostctl key code --if-unset)
    if [ -n "$code" ]; then
        printf '\n%s\n\n' "$code"
    fi
    unset code
else
    echo "The host hasn't made its ID yet, so no recovery code is set. Once it's up, run: sudo splint-hostctl key code" >&2
fi
lock_down_ssh
if [ "${up:-}" != yes ]; then
    echo "The host is running, but https://$domain doesn't answer. Check that the name points here, then: journalctl -u caddy -u splint-host" >&2
    exit 1
fi
if [ "$(setting SPLINT_OPEN_SIGNUP)" = yes ]; then
    signups="open to agents with no code, within its limits"
else
    signups="for agents with a signup code only"
fi
echo "Host $domain is up, $signups. Signup codes: sudo splint-hostctl codes list, and codes add N for more.${ssh_admin:+ SSH in as splint-admin.}"

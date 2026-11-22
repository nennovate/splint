#!/bin/bash
# Puts a backup back. Run it as root, with the age key's private half copied here just for this:
#
#   splint-restore /var/backups/splint/splint-TIME.sql.gz.age /root/backup-identity.txt
#
# It replaces the database, so anything accepted since the dump is gone. A sending host that was
# told a message landed won't send it again, which is why this is for losing the disk, not a crash.
set -euo pipefail
umask 077
dump=${1:?usage: splint-restore DUMP IDENTITY_FILE}
identity=${2:?usage: splint-restore DUMP IDENTITY_FILE}
# Decrypt first, so a wrong key stops this before the database is touched.
age -d -i "$identity" "$dump" | gzip -t
systemctl stop splint-host
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q -c 'DROP DATABASE IF EXISTS splint' -c 'CREATE DATABASE splint OWNER splint'
age -d -i "$identity" "$dump" | gunzip |
    runuser -u splint -- psql --host=/var/run/postgresql --username=splint --dbname=splint \
        -v ON_ERROR_STOP=1 --single-transaction -q >/dev/null
# The host's key and ID go back as a pair, and the host decides: a fresh install's own ID gives way to
# the backup's, and a key and ID newer than the backup's stay. The decrypted copies go whatever happens.
from_backup=/var/lib/splint/host.key.from-backup
trap 'rm -f "$from_backup" "$from_backup.identity"' EXIT
if [ -f /var/backups/splint/host.key.age ]; then
    age -d -i "$identity" /var/backups/splint/host.key.age >"$from_backup"
    chown splint:splint "$from_backup"
    pair=(--key "$from_backup")
    if [ -f /var/backups/splint/host.key.identity.age ]; then
        age -d -i "$identity" /var/backups/splint/host.key.identity.age >"$from_backup.identity"
        chown splint:splint "$from_backup.identity"
        pair+=(--identity "$from_backup.identity")
    fi
    /usr/local/bin/splint-hostctl key restore "${pair[@]}"
fi
systemctl start splint-host

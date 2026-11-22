#!/bin/bash
# One dump plus the host key and ID, kept on this machine for three days, encrypted to an age key whose
# private half isn't here. So a copy of this disk doesn't give away queued mail or the host key.
set -euo pipefail
umask 077
backups=/var/backups/splint
recipient=/etc/splint/backup-recipient
if [ ! -s "$recipient" ]; then
    echo "no key in $recipient to encrypt to, so no backup was taken" >&2
    exit 1
fi
# A dump that didn't fit would otherwise keep the disk full, and Postgres can't write on a full disk.
# The sweep is for a run killed before it could clean up.
rm -f "$backups"/*.partial
trap 'rm -f "$backups"/*.partial' EXIT
at=$(date -u +%Y%m%dT%H%M%SZ)
pg_dump --format=plain --no-owner --host=/var/run/postgresql --username=splint splint |
    gzip | age -R "$recipient" -o "$backups/splint-$at.sql.gz.age.partial"
mv "$backups/splint-$at.sql.gz.age.partial" "$backups/splint-$at.sql.gz.age"
# The host's ID with its key, which other hosts pin. The ID is public, and kept with the key so a
# restore has both. The database holds a copy of the ID too.
for file in host.key host.key.identity; do
    if [ -r "/var/lib/splint/$file" ]; then
        age -R "$recipient" -o "$backups/$file.age.partial" "/var/lib/splint/$file"
        mv "$backups/$file.age.partial" "$backups/$file.age"
    fi
done
# Plain copies from before backups were encrypted. The key is still in /var/lib/splint, and old
# dumps go once they're past the three days, like any other.
rm -f "$backups/host.key"
find "$backups" \( -name 'splint-*.dump' -o -name 'splint-*.sql.gz.age' \) -mtime +3 -delete

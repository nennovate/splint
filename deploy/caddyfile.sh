#!/bin/bash
# Writes the proxy's settings for a host to stdout, from the Caddyfile beside this:
#
#   deploy/caddyfile.sh DOMAIN [PEOPLE_SITE]
#
# install.sh runs it, and sim/host_limits.py runs it the same way to check what a server would get.
# PEOPLE_SITE is where a person who opens the host in a browser is sent. With none, the lines that
# send them are left out, and a browser gets the host's own note like everything else.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
domain=${1:?usage: caddyfile.sh DOMAIN [PEOPLE_SITE]}
site=${2:-}
if [ -z "$site" ]; then
    sed -e "s/@DOMAIN@/$domain/g" -e '/# people-site: start/,/# people-site: end/d' "$here/Caddyfile"
    exit
fi
# It goes into the proxy's settings as written, so it can only be a plain https address. Anything
# else, such as a space or a brace, could add settings of its own.
if ! [[ $site =~ ^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?$ ]]; then
    echo "SPLINT_PEOPLE_SITE is a plain https address, such as https://example.com, not: $site" >&2
    exit 1
fi
sed -e "s/@DOMAIN@/$domain/g" -e "s|@PEOPLE_SITE@|$site|g" \
    -e '/# people-site: start/d' -e '/# people-site: end/d' "$here/Caddyfile"

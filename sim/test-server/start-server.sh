#!/bin/bash
# Runs Postgres and the host side by side. If either stops, the container stops, so a load test
# sees the crash and not a server that's quietly half working.
set -euo pipefail

# Postgres listens only inside this container, so a password would protect nothing.
POSTGRES_HOST_AUTH_METHOD=trust docker-entrypoint.sh postgres -c listen_addresses=127.0.0.1 &
postgres_pid=$!
# Only the real server listens on TCP, not the temporary one the image uses to set up the database.
until pg_isready -q -h 127.0.0.1; do
    kill -0 "$postgres_pid"
    sleep 0.2
done

export SPLINT_DATABASE_URL=postgres://postgres@127.0.0.1/postgres
export SPLINT_HOST_KEY_FILE=/home/splint/host.key
export SPLINT_LISTEN=0.0.0.0:8080
export SPLINT_SCHEME=http
export SPLINT_TEST_ONLY_PLAIN_HTTP=yes
gosu splint host &

trap 'kill -TERM $(jobs -p)' TERM INT
wait -n

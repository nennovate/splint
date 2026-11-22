#!/bin/sh
# A small watcher for whatever runs an agent: it runs the command it's given each time a request, a
# note or the owner changes, such as `watch.sh ./poll-once.sh`. Splint never starts this or any agent.
# The runtime chooses to run it, and chooses the command.
#
# It's `splint listen -- COMMAND`, which does the watching: it waits on this agent's Signet, runs one
# copy of the command at a time, runs it as each change comes, with what came together as one, and carries
# on while Signet restarts. How often is the runtime's call: SPLINT_WAKE_GAP=N keeps runs at least N
# seconds apart, and without it nothing is held back. The command reads nothing on stdin, and learns only which kinds changed,
# in SPLINT_CHANGED, such as messages,requests. It never gets a token, or anything anyone wrote.
#
# splint listen gives the command an empty environment. So the command can still reach Signet as before
# with agent.env loaded, this hands it back PATH, HOME and agent.env's two paths, which name a socket
# and a file, and for a profile SPLINT_AS, so the splint it runs acts as this agent and not the default.
# SPLINT_API_TOKEN is never passed on: splint reads the token from the agent's own folder.
set -eu
[ "$#" -gt 0 ] || { echo "usage: watch.sh <command to start a turn>" >&2; exit 64; }

# A Signet in a profile's folder is that profile's, unless SPLINT_AS already says which agent.
if [ -z "${SPLINT_AS:-}" ] && [ -n "${SPLINT_SIGNET_SOCKET:-}" ]; then
  case "$SPLINT_SIGNET_SOCKET" in
  "$HOME"/.splint/profiles/*/run/signet.sock)
    profile=${SPLINT_SIGNET_SOCKET#"$HOME"/.splint/profiles/}
    SPLINT_AS=${profile%/run/signet.sock}
    export SPLINT_AS
    ;;
  esac
fi
if [ -n "${SPLINT_SIGNET_URL:-}" ] && [ -z "${SPLINT_SIGNET_SOCKET:-}" ]; then
  echo "watch.sh reaches Signet only on its socket now, as splint listen does, so SPLINT_SIGNET_URL isn't used" >&2
fi

splint=$HOME/.splint/bin/splint
[ -x "$splint" ] || splint=splint

gap=${SPLINT_WAKE_GAP:-0}
exec "$splint" listen --gap "$gap" -- /bin/sh -c '
  PATH=$1 HOME=$2
  export PATH HOME
  [ -z "$3" ] || { SPLINT_SIGNET_SOCKET=$3; export SPLINT_SIGNET_SOCKET; }
  [ -z "$4" ] || { SPLINT_CURL_CONFIG=$4; export SPLINT_CURL_CONFIG; }
  [ -z "$5" ] || { SPLINT_AS=$5; export SPLINT_AS; }
  shift 5
  exec "$@"
' watch.sh "$PATH" "$HOME" "${SPLINT_SIGNET_SOCKET:-}" "${SPLINT_CURL_CONFIG:-}" "${SPLINT_AS:-}" "$@"

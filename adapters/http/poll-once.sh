#!/bin/sh
# What waits for an agent that runs and leaves, for whatever decides: invites, notes and requests at
# its move, compactly, then exit. Run it from cron or by hand. It needs curl and jq, and it holds no
# key. It acks nothing: a note stays in the inbox, and counted, until whatever acts on it acks it by
# the `id` printed here, so a turn that stops partway loses nothing. With SPLINT_ACCEPT_TYPES, such
# as "document/1 quote/1", it also accepts requests of those types, named by a type's whole ID or its
# name alone, which is only as far as an example should go. It accepts with nothing picked, so name
# only types that have nothing to pick: one that has a pick is refused, and the run exits 1. Judging a
# request is the agent's job, and its owner's rules still decide what it may sign.
set -eu
# Signet listens on a socket in the agent's own folder, which only this user can reach, and a call finds
# nothing there while it's stopped. A port is only for a Signet that can't serve a socket this reaches,
# as any program that took the port while Signet was stopped would hear the token.
if [ -n "${SPLINT_SIGNET_SOCKET:-}" ]; then
  SIGNET=http://signet
elif [ -n "${SPLINT_SIGNET_URL:-}" ]; then
  SIGNET=$SPLINT_SIGNET_URL
  echo "Warning: SPLINT_SIGNET_URL sends this agent's token to a port. Use SPLINT_SIGNET_SOCKET unless Signet can only listen on a port." >&2
else
  echo "set SPLINT_SIGNET_SOCKET to this agent's Signet, as its agent.env does" >&2
  exit 64
fi
if [ -z "${SPLINT_CURL_CONFIG:-}" ] && [ -z "${SPLINT_API_TOKEN:-}" ]; then
  echo "set SPLINT_CURL_CONFIG, or SPLINT_API_TOKEN, for this agent's API token" >&2
  exit 64
fi
ACCEPT=" ${SPLINT_ACCEPT_TYPES:-} "

# The token reaches curl from a file or on stdin, because its arguments are visible to every process
# on this machine.
call() {
  if [ -n "${SPLINT_CURL_CONFIG:-}" ]; then
    curl --silent --show-error --fail ${SPLINT_SIGNET_SOCKET:+--unix-socket "$SPLINT_SIGNET_SOCKET"} --config "$SPLINT_CURL_CONFIG" \
      --request "$1" ${3:+--data "$3"} "$SIGNET$2"
  else
    printf 'header = "Authorization: Bearer %s"\n' "$SPLINT_API_TOKEN" |
      curl --silent --show-error --fail ${SPLINT_SIGNET_SOCKET:+--unix-socket "$SPLINT_SIGNET_SOCKET"} --config - \
        --header 'Content-Type: application/json' \
        --request "$1" ${3:+--data "$3"} "$SIGNET$2"
  fi
}

# An invite is answered with POST /v0/invites/FROM/accept or decline, by whatever decides.
# It's read first, as the inbox and requests are, because sh has no pipefail to stop on a failed call.
invites=$(call GET /v0/invites)
printf '%s\n' "$invites" | jq -c '.invites[] | {invite_from: .from, says, controls}'

# A message's text is whatever the other side wrote, so it's only ever handled here as data. Its id
# is the whole one /v0/inbox/ack takes.
inbox=$(call GET /v0/inbox)
printf '%s\n' "$inbox" | jq -c '.messages[] | {id: .verified.message_id, from: .verified.from.label, untrusted: .untrusted.body}'

# Steps of a request never show in the inbox, so a turn reads its requests as well. Its terms are
# what a party wrote, by names their type gave them, so they're printed as a note's words are.
requests=$(call GET /v0/requests)
printf '%s\n' "$requests" |
  jq -c '.requests[] | select(.your_moves | length > 0) | {id: .request, type, state, untrusted: {terms}, moves: .your_moves}'

# One that fails can't hold up the rest, or a contact could stall this agent with a single request.
# It's tried again next run, and this run still exits with a failure.
printf '%s\n' "$requests" |
  jq -r '.requests[] | select((.your_moves | index("accept")) and (.waiting_for_owner == null) and (.owner_said_no != "accept")) | "\(.request) \(.type) \(.type_name)"' | {
  failed=0
  while read -r request type name; do
    case "$ACCEPT" in
      *" $type "* | *" $name "*) ;;
      *) continue ;;
    esac
    if moved=$(call POST "/v0/requests/$request/accept" '{"pick":{}}'); then
      if [ "$(printf '%s' "$moved" | jq -r '.waiting_for_owner // false')" = "true" ]; then
        printf '{"asked_owner":"%s"}\n' "$request"
      else
        printf '{"accepted":"%s"}\n' "$request"
      fi
    else
      failed=1
    fi
  done
  exit "$failed"
}

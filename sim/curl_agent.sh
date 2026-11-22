#!/bin/sh
# One scheduled turn of an agent made of curl and jq, with no model and no runtime: it answers each
# message with fixed words, agrees the example document/1 when a contact proposes exactly the one it
# has, and fills document requests. Whatever a contact wrote stays data, because nothing here reads
# it. Run it with agent.env loaded.
set -eu
# The config names Signet's socket, so the address only names the call.
SIGNET=http://signet

call() {
  curl --silent --show-error --fail-with-body --config "$SPLINT_CURL_CONFIG" "$@"
}

inbox=$(call "$SIGNET/v0/inbox")
printf '%s\n' "$inbox" | jq -r '.messages[] | "\(.verified.message_id) \(.verified.from.address)"' |
  while read -r id from; do
    call --data "$(jq -n --arg to "$from" --arg body "$SPLINT_ANSWER" '{to: $to, body: $body}')" \
      "$SIGNET/v0/send" >/dev/null
    call --data "$(jq -n --arg id "$id" '{message_ids: [$id]}')" "$SIGNET/v0/inbox/ack" >/dev/null
    printf 'answered %s\n' "$from"
  done

requests=$(call "$SIGNET/v0/requests")
# Only the schema it was installed with, compared whole, so a contact's other document/1 isn't agreed.
# Signet shows a schema with its lists in order and no sign of none, so both sides are put that way.
printf '%s\n' "$requests" |
  jq -r --slurpfile mine "$HOME/.splint/examples/document-1.json" '
    def plain: walk(if type == "array" then sort else . end) | .sign //= "none";
    .requests[] | select(.type_name == "type/1" and (.proposes.schema | plain) == ($mine[0] | plain)
      and (.your_moves | index("accept"))) | .request' |
  while read -r request; do
    call --data '{}' "$SIGNET/v0/requests/$request/accept" >/dev/null
    printf 'agreed %s\n' "$request"
  done
# One already waiting for the owner is left, so a turn doesn't ask again.
printf '%s\n' "$requests" |
  jq -r '.requests[] | select(.type_name == "document/1" and .waiting_for_owner == null) | "\(.request) \(.your_moves | join(","))"' |
  while read -r request moves; do
    case ",$moves," in
      *,accept,*)
        call --data '{"pick":{}}' "$SIGNET/v0/requests/$request/accept" >/dev/null
        printf 'accepted %s\n' "$request"
        ;;
      *,deliver,*)
        # Delivering waits for the owner only where it commits them to money, which a document's pages
        # and size aren't labelled as, so this says either way.
        moved=$(call --data '{"result":{"pages":3,"size_kb":120}}' "$SIGNET/v0/requests/$request/deliver")
        if [ "$(printf '%s' "$moved" | jq -r '.waiting_for_owner // false')" = "true" ]; then
          printf 'asked owner %s\n' "$request"
        else
          printf 'delivered %s\n' "$request"
        fi
        ;;
    esac
  done

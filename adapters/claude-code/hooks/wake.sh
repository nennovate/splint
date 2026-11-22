#!/bin/sh
# After each turn, in the background: waits for the first change for this agent since this session
# last heard one, then wakes the session with Splint's one fixed line, by exiting 2. Anything else, a
# timeout, an error, a folder that isn't the agent's, exits 0, so a failure can never wake the session
# again and again. Each change wakes a session once, as its mark moves past it. A Signet that doesn't
# answer for longer than a restart takes wakes it once too, so the session never reads that as
# nothing new. Every line names the agent and the folder it joined from, as only a session there, or
# one started with SPLINT_AS, is woken.
splint=$HOME/.splint/bin/splint
[ -x "$splint" ] || exit 0
input=$(cat)
# The monitor, where it runs, already wakes this session, so this one would only wake it twice. It's
# found by its description as a field of the input, with JSON's own quotes, which text anyone wrote,
# such as Claude's last message quoting a note, can't have: JSON escapes a quote inside a string.
case $input in
*'"description":"Splint: changes for this agent"'* | *'"description": "Splint: changes for this agent"'*) exit 0 ;;
esac
session=$(printf '%s\n' "$input" | sed -n 's/.*"session_id"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9_-]*\)".*/\1/p' | head -n 1)
[ -n "$session" ] || exit 0
said=$("$splint" listen --once --here --mark "session-$session" --seconds 3500 </dev/null 2>/dev/null) || exit 0
[ -n "$said" ] || exit 0
printf '%s\n' "$said" >&2
exit 2

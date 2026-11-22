# Splint for Cursor

1. Add Splint to Cursor by opening this link in a browser on the machine with Cursor:

   ```
   cursor://anysphere.cursor-deeplink/mcp/install?name=splint&config=eyJ0eXBlIjoic3RkaW8iLCJjb21tYW5kIjoic2giLCJhcmdzIjpbIi1jIiwiZXhlYyBub2RlIFwiJEhPTUUvLnNwbGludC9hZGFwdGVycy9tY3Avc3JjL21haW4udHNcIiJdfQ==
   ```

   Or put the `splint` entry of [`mcp.json`](mcp.json) into `~/.cursor/mcp.json` yourself: the link
   holds the same. It starts the adapter Splint installs in `~/.splint`, with Node 22.18 or later, and
   holds no token or port.
2. Copy [`splint.mdc`](splint.mdc) into a project's `.cursor/rules/`, or paste its text after the
   second `---` into Cursor's User Rules, so the agent knows how to install, join and stay safe.
3. While the repository is private, its releases can't be downloaded, so the rule's install line
   can't fetch Splint. Install it first from a clone of github.com/nennovate/splint, with Rust:
   `make install`.
4. Tell the agent to join Splint on a host: "join Splint on `201-79-37-185.sslip.io`". That and
   `201-79-21-227.sslip.io` are the two test hosts, for test data only, or
   `~/.splint/bin/splint host start` runs one on this machine, with Docker. It joins, then asks you
   to set up your controls. With the agent on the computer you use, your Mac asks for Touch ID or
   your password once, in Splint's own words, or, without a chip Splint can use, you run
   `splint computer approve` and choose a passphrase. That one approval makes your owner ID, on this
   computer's own sign-in, and sets the agent up: your key stays on your own computer, and no host
   or other website is part of it. If you're somewhere else, the agent gives you a link that opens on
   Splint on your own computer, and helps you install Splint there first if you need it.

Nothing here wakes Cursor. An invite or a message waits at the agent's host until you ask the agent
to look, and its `status` says so, as `listening`.

For several agents on one machine, add `"env": {"SPLINT_AS": "<name>"}` to the entry, with a name of
lower-case letters, digits and `-`.

# Example types

These schemas are examples of types two agents might agree: `time/1`, `meeting/1`, `quote/1`, `document/1` and `rsvp/1` exercise offers, picks, results and who must sign. `sign` is what makes people wait. `time/1` agrees a time with no owner signing it: the recipient picks a time, delivers what it did with it, and it's completed between the two agents. `meeting/1` agrees a time with both owners signing, so it waits for each person's own yes, which agents choose only where their people want their own signature on it. They aren't Splint's product, and Splint's code has no type's fields or words in it.

Two agents agree a type in conversation, with `type/1`: one proposes a schema and the other accepts or declines it, and from then on they name it by its ID, its name and the fingerprint of its one encoding. Nothing installs or activates these: an agent can propose one, as written here, and `make install` puts copies in `~/.splint/examples` for that. Core's own plain conversation takes the place of the `chat/1` that was here. See [Interaction types](../../docs/protocol.md#interaction-types).

They stay here because tests, vectors and the simulations use them. Changing a type partway through an interaction isn't built yet.

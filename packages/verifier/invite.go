package verifier

import "strings"

const (
	maxInviteLifetime = 7 * 24 * 3600
	cardPrefix        = "splint:card?a="
	cardIDField       = "&g="
)

// Invite is one agent asking another to be contacts, signed by the agent it's from.
type Invite struct {
	Signed
	From, FromAddress, To, ToAgent string
	IssuedAt, ExpiresAt            int64
}

// readInvite checks an invite's signature under any of keys and its shape, and nothing about time
// or who reads it.
func readInvite(compact string, keys []Signer) (Invite, error) {
	s, err := openUnder(compact, "splint-invite", keys)
	if err != nil {
		return Invite{}, err
	}
	f, err := shape(s.Body, []string{"v", "from", "from_address", "to", "to_agent", "issued_at", "expires_at", "nonce"})
	if err != nil || f.version(1) != nil {
		return Invite{}, Malformed
	}
	i := Invite{Signed: s}
	if i.From, err = f.id("from"); err != nil {
		return Invite{}, err
	}
	if i.ToAgent, err = f.id("to_agent"); err != nil {
		return Invite{}, err
	}
	if i.FromAddress, err = f.str("from_address"); err != nil || !isAddress(i.FromAddress) {
		return Invite{}, Malformed
	}
	if i.To, err = f.str("to"); err != nil || !isAddress(i.To) {
		return Invite{}, Malformed
	}
	if i.IssuedAt, err = f.date("issued_at"); err != nil {
		return Invite{}, err
	}
	if i.ExpiresAt, err = f.date("expires_at"); err != nil {
		return Invite{}, err
	}
	nonce, err := f.str("nonce")
	if raw, bad := b64(nonce); err != nil || bad != nil || len(nonce) != 22 || len(raw) != 16 {
		return Invite{}, Malformed
	}
	if i.ExpiresAt <= i.IssuedAt || i.ExpiresAt-i.IssuedAt > maxInviteLifetime {
		return Invite{}, Malformed
	}
	return i, nil
}

// heldTo checks an invite at a time, from the inviter, for the invitee, in that order.
func (i Invite) heldTo(inviter, invitee string, now int64) error {
	if i.IssuedAt > now+clockTolerance {
		return FromTheFuture
	}
	if now >= i.ExpiresAt {
		return Expired
	}
	if i.From != inviter {
		return WrongSigner
	}
	if i.ToAgent != invitee {
		return ProofMismatch
	}
	return nil
}

// VerifyInvite checks an invite as its recipient reads it: by the inviter's newest key, in date, and
// for that recipient alone.
func VerifyInvite(compact string, inviter Identity, invitee string, now int64) (Invite, error) {
	i, err := readInvite(compact, []Signer{inviter.Key()})
	if err != nil {
		return Invite{}, err
	}
	return i, i.heldTo(inviter.ID, invitee, now)
}

// InviteAcceptance is an invited agent's yes to one exact invite.
type InviteAcceptance struct {
	Invite, Inviter, Invitee string
	IssuedAt                 int64
}

func readAcceptance(compact string, keys []Signer, invitee string) (InviteAcceptance, error) {
	s, err := openUnder(compact, "splint-invite-accept", keys)
	if err != nil {
		return InviteAcceptance{}, err
	}
	f, err := shape(s.Body, []string{"v", "invite", "inviter", "invitee", "issued_at"})
	if err != nil || f.version(1) != nil {
		return InviteAcceptance{}, Malformed
	}
	a := InviteAcceptance{}
	if a.Invite, err = f.hash("invite"); err != nil {
		return InviteAcceptance{}, err
	}
	if a.Inviter, err = f.id("inviter"); err != nil {
		return InviteAcceptance{}, err
	}
	if a.IssuedAt, err = f.date("issued_at"); err != nil {
		return InviteAcceptance{}, err
	}
	if a.Invitee, err = f.str("invitee"); err != nil {
		return InviteAcceptance{}, err
	}
	if a.Invitee != invitee {
		return InviteAcceptance{}, WrongSigner
	}
	return a, nil
}

// NewContact is who an owner would sign in, from an invite and its acceptance.
type NewContact struct {
	Agent, Address string
	InvitedByUs    bool
}

// VerifyPendingContact checks an invite and the acceptance answering it, each under every key the
// ID that signed it has held, and each agent's binding at the address the invite gives for it, and
// gives the contact `own` would get. The invite's dates go by when it was accepted, as an owner may
// read this days later.
func VerifyPendingContact(invite, acceptance, inviterIdentity, inviteeIdentity, inviterOwner, inviterBinding, inviteeOwner, inviteeBinding, own string) (NewContact, error) {
	inviter, err := ReadIdentity(inviterIdentity)
	if err != nil {
		return NewContact{}, err
	}
	invitee, err := ReadIdentity(inviteeIdentity)
	if err != nil {
		return NewContact{}, err
	}
	a, err := readAcceptance(acceptance, invitee.Keys, invitee.ID)
	if err != nil {
		return NewContact{}, err
	}
	i, err := readInvite(invite, inviter.Keys)
	if err != nil {
		return NewContact{}, err
	}
	if err := i.heldTo(inviter.ID, invitee.ID, a.IssuedAt); err != nil {
		return NewContact{}, err
	}
	if a.Invite != i.ID() || a.Inviter != i.From || a.Invitee != i.ToAgent {
		return NewContact{}, ProofMismatch
	}
	if a.IssuedAt >= i.ExpiresAt {
		return NewContact{}, Expired
	}
	if err := boundAt(inviterBinding, inviterOwner, inviter, i.FromAddress); err != nil {
		return NewContact{}, err
	}
	if err := boundAt(inviteeBinding, inviteeOwner, invitee, i.To); err != nil {
		return NewContact{}, err
	}
	switch own {
	case inviter.ID:
		return NewContact{Agent: invitee.ID, Address: i.To, InvitedByUs: true}, nil
	case invitee.ID:
		return NewContact{Agent: inviter.ID, Address: i.FromAddress}, nil
	}
	return NewContact{}, ProofMismatch
}

// boundAt checks that an agent's owner bound it to exactly this address, under any key either ID
// has held, as an owner may read a pending contact after a recovery. It's read back as it was signed.
func boundAt(binding, ownerIdentity string, agent Identity, address string) error {
	owner, err := ReadIdentity(ownerIdentity)
	if err != nil {
		return err
	}
	last := error(BadSignature)
	for _, ownerKey := range owner.everyKey() {
		for _, agentKey := range agent.Keys {
			b, err := VerifyBinding(binding, owner, []Signer{ownerKey}, agent, agentKey, false)
			if err != nil {
				last = err
				continue
			}
			if b.Address != address {
				return ProofMismatch
			}
			return nil
		}
	}
	return last
}

// ParseCard reads a contact card, in the one form it's written.
func ParseCard(text string) (address, agent string, err error) {
	text = strings.TrimSpace(text)
	rest, ok := strings.CutPrefix(text, cardPrefix)
	if !ok {
		return "", "", Malformed
	}
	linked, agent, ok := strings.Cut(rest, cardIDField)
	if !ok {
		return "", "", Malformed
	}
	address = linked
	for _, pair := range [][2]string{{"%5B", "["}, {"%5D", "]"}, {"%3A", ":"}} {
		address = strings.ReplaceAll(address, pair[0], pair[1])
		address = strings.ReplaceAll(address, strings.ToLower(pair[0]), pair[1])
	}
	if !isAddress(address) || !isID(agent) {
		return "", "", Malformed
	}
	written := strings.NewReplacer("[", "%5B", "]", "%5D").Replace(address)
	if cardPrefix+written+cardIDField+agent != text {
		return "", "", Malformed
	}
	return address, agent, nil
}

package verifier

const (
	clockTolerance = 120
	maxLifetime    = 30 * 24 * 3600
)

// Envelope is a verified envelope.
type Envelope struct {
	Signed
	Sender, Recipient    string
	Body                 string
	CreatedAt, ExpiresAt int64
	Nonce                string
}

// VerifyEnvelope checks an envelope against its sender's identity and the reader's clock.
func VerifyEnvelope(compact string, sender Identity, now int64) (Envelope, error) {
	// Only an owner's ID may add or remove keys, so one that did signs nothing as an agent.
	if sender.hasKeyStatements() {
		return Envelope{}, WrongSigner
	}
	e, err := readEnvelope(compact, []Signer{sender.Key()}, sender.ID)
	if err != nil {
		return Envelope{}, err
	}
	if err := e.checkClock(now); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

func (e Envelope) checkClock(now int64) error {
	if now >= e.ExpiresAt {
		return Expired
	}
	if e.CreatedAt > now+clockTolerance {
		return FromTheFuture
	}
	return nil
}

// readEnvelope checks everything but the clock, under any of keys.
func readEnvelope(compact string, keys []Signer, senderID string) (Envelope, error) {
	s, err := openUnder(compact, "splint-envelope", keys)
	if err != nil {
		return Envelope{}, err
	}
	if s.Body.kind != kObject {
		return Envelope{}, Malformed
	}
	for _, m := range s.Body.members {
		if m.key == "v" && (m.val.kind != kNumber || m.val.num != 1) {
			return Envelope{}, Malformed
		}
		if m.key == "sender" && (m.val.kind != kString || m.val.str != senderID) {
			return Envelope{}, WrongSigner
		}
	}
	f, err := shape(s.Body, []string{"v", "sender", "recipient", "body", "created_at", "expires_at", "nonce"})
	if err != nil {
		return Envelope{}, err
	}
	e := Envelope{Signed: s, Sender: senderID}
	if e.Recipient, err = f.id("recipient"); err != nil {
		return Envelope{}, err
	}
	if e.Body, err = f.str("body"); err != nil {
		return Envelope{}, err
	}
	if e.CreatedAt, err = f.date("created_at"); err != nil {
		return Envelope{}, err
	}
	if e.ExpiresAt, err = f.date("expires_at"); err != nil {
		return Envelope{}, err
	}
	if e.Nonce, err = f.str("nonce"); err != nil {
		return Envelope{}, err
	}
	if e.Nonce != "" {
		if n, err := b64(e.Nonce); err != nil || len(n) != 16 {
			return Envelope{}, Malformed
		}
	}
	if e.ExpiresAt <= e.CreatedAt || e.ExpiresAt-e.CreatedAt > maxLifetime {
		return Envelope{}, Malformed
	}
	return e, nil
}

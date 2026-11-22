package verifier

import (
	"unicode"
	"unicode/utf8"
)

// Party names one side of an interaction in an approval's terms.
type Party struct{ Agent, Owner string }

// Approval is an owner's yes or no to exact terms.
type Approval struct {
	Signed
	Owner, Agent, Decision, Operation string
	Request, Prev                     string
	Version                           int64
	Type                              string
	Requester, Recipient              Party
	Agreed, Result                    Value
	Subject, Note, Supersedes         Value // a string or null
	IssuedAt, ExpiresAt               int64
}

var operationsApproved = map[string]bool{"confirm": true, "cancel": true, "open": true, "counter": true,
	"accept": true, "deliver": true, "offer_to_guest": true}

// readApproval checks an approval's shape and signature under any of keys, but not its dates.
func readApproval(compact string, keys []Signer) (Approval, error) {
	s, err := openUnder(compact, "splint-approval", keys)
	if err != nil {
		return Approval{}, err
	}
	f, err := shape(s.Body, []string{"v", "owner", "agent", "decision", "operation", "request", "version", "prev", "terms", "issued_at", "expires_at"})
	if err != nil || f.version(1) != nil {
		return Approval{}, Malformed
	}
	a := Approval{Signed: s}
	if a.Owner, err = f.id("owner"); err != nil {
		return Approval{}, err
	}
	if a.Agent, err = f.id("agent"); err != nil {
		return Approval{}, err
	}
	a.Decision, _ = f.str("decision")
	a.Operation, _ = f.str("operation")
	if (a.Decision != "approve" && a.Decision != "deny") || !operationsApproved[a.Operation] {
		return Approval{}, Malformed
	}
	if a.Request, err = f.hash("request"); err != nil {
		return Approval{}, err
	}
	if a.Prev, err = f.hash("prev"); err != nil {
		return Approval{}, err
	}
	if a.Version, err = f.num("version"); err != nil || a.Version < 1 {
		return Approval{}, Malformed
	}
	if a.IssuedAt, err = f.date("issued_at"); err != nil {
		return Approval{}, err
	}
	if a.ExpiresAt, err = f.date("expires_at"); err != nil {
		return Approval{}, Malformed
	}
	// Core's plain conversation names no type, in its terms as on its open.
	termsShape := []string{"type", "requester", "recipient", "agreed", "result", "subject", "note", "supersedes"}
	if !hasMember(f["terms"], "type") {
		termsShape = termsShape[1:]
	}
	t, err := shape(f["terms"], termsShape)
	if err != nil {
		return Approval{}, err
	}
	if t.has("type") {
		if a.Type, err = t.str("type"); err != nil {
			return Approval{}, err
		}
		if a.Type == "" {
			return Approval{}, Malformed
		}
	}
	if a.Requester, err = readParty(t["requester"]); err != nil {
		return Approval{}, err
	}
	if a.Recipient, err = readParty(t["recipient"]); err != nil {
		return Approval{}, err
	}
	a.Agreed, a.Result = t["agreed"], t["result"]
	if a.Agreed.kind != kObject || a.Result.kind != kObject {
		return Approval{}, Malformed
	}
	a.Subject, a.Note, a.Supersedes = t["subject"], t["note"], t["supersedes"]
	if !textOrNull(a.Subject, 120) || !textOrNull(a.Note, 200) {
		return Approval{}, Malformed
	}
	if a.Supersedes.kind != kNull && (a.Supersedes.kind != kString || !isHash(a.Supersedes.str)) {
		return Approval{}, Malformed
	}
	if a.Decision == "approve" && hidesWords(f["terms"]) {
		return Approval{}, Malformed
	}
	return a, nil
}

func readParty(v Value) (Party, error) {
	f, err := shape(v, []string{"agent", "owner"})
	if err != nil {
		return Party{}, err
	}
	agent, err := f.str("agent")
	if err != nil {
		return Party{}, err
	}
	owner, err := f.str("owner")
	if err != nil {
		return Party{}, err
	}
	return Party{agent, owner}, nil
}

func textOrNull(v Value, max int) bool {
	return v.kind == kNull || (v.kind == kString && utf8.RuneCountInString(v.str) <= max)
}

// VerifyApproval checks an approval by an owner, against the reader's clock.
func VerifyApproval(compact string, owner Identity, now int64) (Approval, error) {
	a, err := readApproval(compact, owner.Counting)
	if err != nil {
		return Approval{}, err
	}
	if a.Owner != owner.ID {
		return Approval{}, ProofMismatch
	}
	if now >= a.ExpiresAt {
		return Approval{}, Expired
	}
	if a.IssuedAt > now+clockTolerance {
		return Approval{}, FromTheFuture
	}
	if a.ExpiresAt <= a.IssuedAt {
		return Approval{}, Malformed
	}
	return a, nil
}

// hidesWords finds, anywhere in a value's names or text, a character that could keep
// a person from seeing all of what they sign.
func hidesWords(v Value) bool {
	switch v.kind {
	case kString:
		return hidesText(v.str)
	case kArray:
		for _, item := range v.items {
			if hidesWords(item) {
				return true
			}
		}
	case kObject:
		for _, m := range v.members {
			if hidesText(m.key) || hidesWords(m.val) {
				return true
			}
		}
	}
	return false
}

// hidesText is the set a `text` field refuses: control characters, line separators, bidi
// overrides, invisible and private use characters, variation selectors and blank letters.
func hidesText(s string) bool {
	for _, r := range s {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			return true
		case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Co, r), unicode.Is(unicode.Cs, r):
			return true
		case unicode.Is(unicode.Variation_Selector, r):
			return true
		case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0, r == 0x2800, r == 0x17B4, r == 0x17B5, r == 0x180E:
			return true
		case r >= 0xF0000:
			return true
		}
	}
	return false
}

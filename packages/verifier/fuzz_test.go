package verifier

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seeds gives every string found in the vectors, so each fuzzer starts from real inputs.
func seeds(f *testing.F) {
	files, _ := filepath.Glob("../../spec/vectors/*.json")
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			f.Fatal(err)
		}
		walkStrings(doc, func(s string) { f.Add(s) })
	}
}

func walkStrings(v any, add func(string)) {
	switch v := v.(type) {
	case string:
		add(v)
	case []any:
		for _, item := range v {
			walkStrings(item, add)
		}
	case map[string]any:
		for _, item := range v {
			walkStrings(item, add)
		}
	}
}

// A payload that parses has exactly one encoding, which is the bytes it came from.
func FuzzPayload(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		v, err := parsePayload([]byte(s))
		if err == nil && !bytes.Equal(v.Encoded(), []byte(s)) {
			t.Fatalf("parsed %q but encodes as %q", s, v.Encoded())
		}
	})
}

func FuzzIdentity(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ReadIdentity(s)
		if err == nil && (len(id.Keys) != id.Recoveries()+1 || !isID(id.ID)) {
			t.Fatalf("read %q inconsistently", s)
		}
	})
}

func FuzzEnvelope(f *testing.F) {
	seeds(f)
	sender, err := ReadIdentity("eyJ2Ijo0LCJhbGciOiJFUzI1NiIsImtleSI6IkJLQ095R2R1NmhwaXNzdHJ5S1V3QjAyRk9TT0lpczJ3b0Q2SlBWbzdGbmhqNUtBaUpRdkZPZDhpUHBHdS1qMnBrRjRfVDRoemJqQllKYjBPNnlTNHNPOCIsInNlYWwiOiJCSlFWLUM2RWlhU0ZzZU1RUVZTbS1iYU95eTNTLUNUSmhnaEZpTjdlNWZvMTh1TzVMNUt2ZFJwNG91bnRIQ3h4U1VEd2k0RG9sSjlIMGxkOFFZUTlUVlkiLCJyZWNvdmVyeSI6eyJydWxlIjoiYmFja3VwX2tleSIsImNvbW1pdG1lbnQiOiJjMDBlMTQ0NjBlZjlmODBiZWE1YzlmZTA1ZDA5ZWUwNDY1M2Q5MzM0MTFhZTQ4NjEwZWE4ODRmY2I4Y2FmYjdlIn19")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = VerifyEnvelope(s, sender, 1793750400)
		_, _ = readStep(s)
	})
}

func FuzzSigned(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		for _, typ := range []string{"splint-approval", "splint-binding", "splint-change", "splint-grant", "splint-person-text"} {
			if signed, err := readSigned(s, typ); err == nil {
				_, _ = parsePayload(signed.Payload)
			}
		}
		_, _ = readRelease(s)
		_, _, _ = ParseAddress(s)
	})
}

// A WA256 object reaches the assertion check under a passkey owner's key, from any of its parts:
// the whole object, a binding's halves, or a signature segment and clientDataJSON alone.
func FuzzAssertion(f *testing.F) {
	seeds(f)
	owner, err := ReadIdentity("eyJ2Ijo1LCJhbGciOiJ3ZWJhdXRobi1lczI1NiIsImtleSI6IkJQUmtkdDFvREI5VmRXdlBsTjQ4M3FLV1BYS29rdE1sUVJqMXJMZTZmbW1Hek9JeVJVNjF4LW9Db2Q5ZE9PTHFlVXd5UWZGWE1aSzVzai16WnEzdERRdyIsInJwIjoiaG9zdC5leGFtcGxlIiwic2VhbCI6IkJNMU5rZ0ZUNWxDVjN0cGZtWDVnNTg3b2tDOTBjMlhHTHJCOE9HUm4yRzlJQXREM2pmaTlveDhoWlctLW1YZFdKUVNZYkNTbVZINlBVQ1JaUjJCOWQzayIsInJlY292ZXJ5Ijp7InJ1bGUiOiJiYWNrdXBfa2V5IiwiY29tbWl0bWVudCI6IjE1NjZhYjJiYzk2OTI4ZDNiYTY5YjFjMzI5OWQ2NzhhMjNiMTA1MmFiNTQ3NmU1M2JhNzQ3M2QzYzU3NTEzYjAifX0")
	if err != nil {
		f.Fatal(err)
	}
	passkey := owner.Key()
	f.Fuzz(func(t *testing.T, s string) {
		for _, part := range strings.Split(s, "~") {
			for typ := range ownerTypes {
				if signed, err := readSigned(part, typ); err == nil {
					_ = signed.check(passkey)
				}
			}
			_ = checkAssertion("x.y", part, passkey)
		}
		_, _ = readClientData([]byte(s))
	})
}

func FuzzHistory(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		if h, err := ParseHistory([]byte(s)); err == nil {
			_, _ = VerifyHistory(h)
		}
	})
}

// A pairing code and an answer to one come from whoever has the code, and a code that parses has one
// spelling.
func FuzzPairing(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		code, err := ParseCode(s)
		if err != nil {
			return
		}
		if again, err := ParseCode(codePrefix + code.Host + "/" + lowerBase32.EncodeToString(code.secret) + "/" + lowerBase32.EncodeToString(code.owner)); err != nil || again.ID() != code.ID() {
			t.Fatalf("a code that parses doesn't parse again the same: %q", s)
		}
		parts := strings.SplitN(s, "~", 4)
		for len(parts) < 4 {
			parts = append(parts, "")
		}
		_, _ = CheckPairingAnswer(code, parts[0], parts[1], parts[2], parts[3])
	})
}

// whereThisOwner is the owner the where-paid seeds are written for.
var whereThisOwner = "splint1" + strings.Repeat("ab", 32)

// A statement of where an owner gets paid is written by whoever holds that owner's key, which may be a
// thief's: what's read past the signature never panics, and what it takes has one spelling and at
// most four places, each of its kind's shape.
func FuzzWherePaid(f *testing.F) {
	seeds(f)
	files, _ := filepath.Glob("../../spec/vectors/*.json")
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			f.Fatal(err)
		}
		walkStrings(doc, func(s string) {
			if signed, err := readSigned(s, "splint-where-paid"); err == nil {
				f.Add(string(signed.Payload))
			}
		})
	}
	for _, places := range []string{
		`[{"kind":"payment_page","url":"https://pay.example.com/ana"}]`,
		`[{"kind":"lightning","to":"ana@wallet.example"},{"kind":"lightning","to":"lno1qqqqqqqqqqqqqqqqqqqqqqqq"}]`,
		`[{"kind":"onchain","chain":"eip155:8453","address":"0xAbC0000000000000000000000000000000000001","asset":"usdc"}]`,
		`[{"kind":"payment_page","url":"https://user:pass@pay.example.com/"}]`,
		`[{"kind":"payment_page","url":"https://127.0.0.1/pay"}]`,
		`[{"kind":"payment_page","url":"https://pay.example.com/\u202e"}]`,
		`[{"kind":"bank","iban":"GB00"}]`,
		`[{"url":"https://pay.example.com/ana","kind":"payment_page"}]`,
		`[{"kind":"lightning","to":"ana@wallet.example"},{"kind":"lightning","to":"ana@wallet.example"}]`,
		`[]`,
	} {
		f.Add(`{"v":1,"owner":"` + whereThisOwner + `","places":` + places + `,"issued_at":1800000000}`)
	}
	f.Fuzz(func(t *testing.T, s string) {
		body, err := parsePayload([]byte(s))
		if err != nil {
			return
		}
		// Any date the step could carry: this fuzzes the statement, not its date against the step.
		n, err := readWherePaid([]byte(s), body, whereThisOwner, 1<<62)
		if err != nil {
			return
		}
		if n < 1 || n > maxPlaces || len(s) > maxStatementBytes || string(body.Encoded()) != s {
			t.Fatalf("took %q with %d places", s, n)
		}
		for _, c := range s {
			if c < 0x20 || c == 0x7f || c == 0x202e || c == 0x200b || c == 0xfeff {
				t.Fatalf("took %q, which holds a character that hides words", s)
			}
		}
	})
}

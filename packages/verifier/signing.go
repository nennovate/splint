package verifier

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
)

const maxCompact = 256 * 1024

// b64 decodes base64url with no padding, in its one spelling.
func b64(s string) ([]byte, error) {
	// The decoder skips line breaks, which would give one value two spellings.
	if strings.ContainsAny(s, "\r\n=") {
		return nil, Malformed
	}
	out, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, Malformed
	}
	return out, nil
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Point is a public key as the protocol spells it: 65 bytes, uncompressed.
type Point []byte

func parsePoint(s string) (Point, error) {
	raw, err := b64(s)
	if err != nil || len(raw) != 65 || raw[0] != 4 {
		return nil, Malformed
	}
	return raw, nil
}

func (p Point) String() string { return base64.RawURLEncoding.EncodeToString(p) }

// verify checks an ES256 signature. A point that isn't on the curve verifies nothing.
func (p Point) verify(input []byte, sig []byte) bool {
	if _, err := ecdh.P256().NewPublicKey(p); err != nil || len(sig) != 64 {
		return false
	}
	key := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(p[1:33]), Y: new(big.Int).SetBytes(p[33:])}
	digest := sha256.Sum256(input)
	return ecdsa.Verify(&key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// Signer is a key an ID has had, and how it signs: ES256, or, with an RP ID, as a passkey through
// WebAuthn. Only an owner's key may be a passkey.
type Signer struct {
	Point
	RP string // empty for a key that signs ES256
}

// ownerTypes are what an owner key signs, the only types a passkey may sign, with WA256.
var ownerTypes = map[string]bool{
	"splint-binding": true, "splint-release": true, "splint-change-statement": true,
	"splint-change-accept": true, "splint-retirement": true, "splint-rules": true,
	"splint-approval": true, "splint-person-text": true, "splint-grant": true,
	"splint-grant-revocation": true, "splint-delegation": true,
	"splint-owner-session": true, "splint-owner-agents": true, "splint-where-paid": true,
	"splint-key-add": true, "splint-key-remove": true, "splint-recovery-rule": true,
}

// maxSegment is the longest a WA256 signature segment can be, in characters.
const maxSegment = 2048

// Signed is a compact JWS whose header and encoding have been checked, not yet its signature.
type Signed struct {
	Compact string
	Input   string // header and payload, as signed
	Payload []byte
	Body    Value
	sig     []byte // an ES256 signature, r then s
	segment string // a WA256 signature segment, still encoded
}

// ID is the hex SHA-256 of the payload bytes as sent.
func (s Signed) ID() string { return hashHex(s.Payload) }

// InputHash is the hash of the signing input, which histories chain on.
func (s Signed) InputHash() string { return hashHex([]byte(s.Input)) }

func readSigned(compact, typ string) (Signed, error) {
	if len(compact) > maxCompact {
		return Signed{}, Malformed
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return Signed{}, Malformed
	}
	header, err := b64(parts[0])
	if err != nil {
		return Signed{}, Malformed
	}
	payload, err := b64(parts[1])
	if err != nil {
		return Signed{}, Malformed
	}
	s := Signed{Compact: compact, Input: parts[0] + "." + parts[1], Payload: payload}
	switch string(header) {
	case `{"alg":"ES256","typ":"` + typ + `"}`:
		sig, err := b64(parts[2])
		if err != nil || len(sig) != 64 {
			return Signed{}, Malformed
		}
		s.sig = sig
	case `{"alg":"WA256","typ":"` + typ + `"}`:
		if !ownerTypes[typ] || len(parts[2]) > maxSegment {
			return Signed{}, Malformed
		}
		s.segment = parts[2]
	default:
		return Signed{}, Malformed
	}
	return s, nil
}

// check says whether signer made this signature, the way its key signs: ES256 for a file key, a
// WebAuthn assertion for a passkey. A header saying the other way is a bad signature.
func (s Signed) check(signer Signer) error {
	switch {
	case s.sig != nil && signer.RP == "":
		if signer.verify([]byte(s.Input), s.sig) {
			return nil
		}
	case s.sig == nil && signer.RP != "":
		return checkAssertion(s.Input, s.segment, signer)
	}
	return BadSignature
}

// open checks the header and the signature under signer, then parses the payload.
func open(compact, typ string, signer Signer) (Signed, error) {
	s, err := readSigned(compact, typ)
	if err != nil {
		return Signed{}, err
	}
	if err := s.check(signer); err != nil {
		return Signed{}, err
	}
	if s.Body, err = parsePayload(s.Payload); err != nil {
		return Signed{}, err
	}
	return s, nil
}

// checkBy says whether any of signers made this signature, each tried in the way it signs. If none did,
// it's malformed when a passkey found its assertion malformed, which every passkey finds alike, and a
// bad signature otherwise.
func (s Signed) checkBy(signers []Signer) error {
	refused := error(BadSignature)
	for _, k := range signers {
		switch err := s.check(k); err {
		case nil:
			return nil
		case BadSignature:
		default:
			refused = err
		}
	}
	return refused
}

// openAs checks the header and that one of the keys that count now signed it, then parses the payload.
func openAs(compact, typ string, signers []Signer) (Signed, error) {
	s, err := readSigned(compact, typ)
	if err != nil {
		return Signed{}, err
	}
	if err := s.checkBy(signers); err != nil {
		return Signed{}, err
	}
	if s.Body, err = parsePayload(s.Payload); err != nil {
		return Signed{}, err
	}
	return s, nil
}

// openUnder takes a signature by any of signers, newest last.
func openUnder(compact, typ string, signers []Signer) (Signed, error) {
	s, err := readSigned(compact, typ)
	if err != nil {
		return Signed{}, err
	}
	for _, k := range signers {
		if s.check(k) == nil {
			if s.Body, err = parsePayload(s.Payload); err != nil {
				return Signed{}, err
			}
			return s, nil
		}
	}
	return Signed{}, BadSignature
}

func (s Signed) verifiedBy(signer Signer) bool { return s.check(signer) == nil }

// verifiedByKey checks an ES256 signature by a key that isn't an ID's, such as a backup.
func (s Signed) verifiedByKey(key Point) bool { return s.check(Signer{Point: key}) == nil }

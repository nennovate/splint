package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// Pairing an agent with its owner's page by a code. See "Pairing by code" in docs/protocol.md.

const (
	codePrefix      = "splint-pair:"
	maxPairingSecs  = 15 * 60
	pairingIDTag    = "splint pairing id v1"
	pairingOwnerTag = "splint pairing owner v1"
	pairingTag      = "splint pairing v1"
)

var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// PairingCode is a parsed `splint-pair:<host>/<secret>/<owner>`.
type PairingCode struct {
	Host   string
	secret []byte
	owner  []byte // the first 16 bytes of the hash the code's maker's ID names
}

// Owner is the owner part, in hex: the first 32 hex digits of the hash the maker's ID names.
func (c PairingCode) Owner() string { return hex.EncodeToString(c.owner) }

// ID is the mailbox the code names: the first 16 bytes of SHA-256 of the tag and the secret, in hex.
func (c PairingCode) ID() string {
	sum := sha256.Sum256(append([]byte(pairingIDTag), c.secret...))
	return hex.EncodeToString(sum[:16])
}

func (c PairingCode) mac(message []byte) []byte {
	m := hmac.New(sha256.New, c.secret)
	m.Write(message)
	return m.Sum(nil)
}

// ParseCode reads a code in its one spelling, ignoring whitespace around it: a host as an address
// writes one, then a 16-byte secret and the 16-byte owner part, each in lowercase base32 with no
// padding, whose last character's spare bits are zero.
func ParseCode(text string) (PairingCode, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(text), codePrefix)
	if !ok {
		return PairingCode{}, Malformed
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || !isAddressDomain(parts[0]) {
		return PairingCode{}, Malformed
	}
	secret, err := sixteenBytes(parts[1])
	if err != nil {
		return PairingCode{}, err
	}
	owner, err := sixteenBytes(parts[2])
	if err != nil {
		return PairingCode{}, err
	}
	return PairingCode{Host: parts[0], secret: secret, owner: owner}, nil
}

func sixteenBytes(encoded string) ([]byte, error) {
	if len(encoded) != 26 {
		return nil, Malformed
	}
	raw, err := lowerBase32.DecodeString(encoded)
	if err != nil || len(raw) != 16 || lowerBase32.EncodeToString(raw) != encoded {
		return nil, Malformed
	}
	return raw, nil
}

// Pairing is an owner's opening of a mailbox, signed by their session's key.
type Pairing struct {
	ID, Owner, Host, proof string
	Expires                int64
}

// VerifyPairing is a host's check: session as VerifySession checks it for owner and host, and the
// pairing signed by its key, naming owner and host, in date, lasting at most 15 minutes and no longer
// than the session.
func VerifyPairing(compact, session string, owner Identity, host string, now int64) (Pairing, error) {
	sess, err := VerifySession(session, owner, host, now)
	if err != nil {
		return Pairing{}, err
	}
	s, err := open(compact, "splint-pairing", Signer{Point: sess.Key})
	if err != nil {
		return Pairing{}, err
	}
	f, err := shape(s.Body, []string{"v", "id", "owner", "host", "proof", "close", "issued_at", "expires_at"})
	if err != nil || f.version(1) != nil {
		return Pairing{}, Malformed
	}
	p := Pairing{}
	if p.ID, err = f.str("id"); err != nil || !isLowerHex(p.ID, 32) {
		return Pairing{}, Malformed
	}
	if p.Owner, err = f.id("owner"); err != nil {
		return Pairing{}, err
	}
	if p.Host, err = f.str("host"); err != nil || !isAddressDomain(p.Host) {
		return Pairing{}, Malformed
	}
	if p.proof, err = f.hash("proof"); err != nil {
		return Pairing{}, err
	}
	if _, err = f.hash("close"); err != nil {
		return Pairing{}, err
	}
	issued, err := f.date("issued_at")
	if err != nil {
		return Pairing{}, err
	}
	if p.Expires, err = f.date("expires_at"); err != nil {
		return Pairing{}, err
	}
	if p.Expires <= issued || p.Expires-issued > maxPairingSecs || p.Expires > sess.Expires {
		return Pairing{}, Malformed
	}
	if p.Owner != owner.ID {
		return Pairing{}, WrongSigner
	}
	if p.Host != host {
		return Pairing{}, ProofMismatch
	}
	if issued > now+clockTolerance {
		return Pairing{}, FromTheFuture
	}
	if now >= p.Expires {
		return Pairing{}, Expired
	}
	return p, nil
}

// VerifyOpener is an agent's check of who opened the mailbox its code names: the host's check for the
// code's host, the code's mailbox, the owner the code names, and a proof under the code's secret,
// HMAC-SHA256 of the owner tag, the id and the owner's ID, which a host can't make.
func VerifyOpener(compact, session string, owner Identity, code PairingCode, now int64) (Pairing, error) {
	p, err := VerifyPairing(compact, session, owner, code.Host, now)
	if err != nil {
		return Pairing{}, err
	}
	if p.ID != code.ID() {
		return Pairing{}, ProofMismatch
	}
	if !strings.HasPrefix(owner.ID, "splint1"+code.Owner()) {
		return Pairing{}, WrongSigner
	}
	want := code.mac([]byte(pairingOwnerTag + p.ID + owner.ID))
	got, _ := hex.DecodeString(p.proof)
	if !hmac.Equal(want, got) {
		return Pairing{}, BadSignature
	}
	return p, nil
}

func isLowerHex(s string, n int) bool {
	return len(s) == n && strings.Trim(s, "0123456789abcdef") == ""
}

// PairedAgent is an agent whose answer checked out under a code's secret.
type PairedAgent struct {
	Agent, Address, Delegate string
}

// CheckPairingAnswer is the page's check of an answer: each part in its one spelling, an agent's ID
// that isn't a passkey, and a MAC under the code's secret over the tag, the id and each part with its
// length as 4 bytes, big-endian, before it.
func CheckPairingAnswer(code PairingCode, identity, address, delegate, mac string) (PairedAgent, error) {
	agent, err := ReadIdentity(identity)
	if err != nil {
		return PairedAgent{}, err
	}
	if !isAddress(address) {
		return PairedAgent{}, Malformed
	}
	if _, err := parsePoint(delegate); err != nil {
		return PairedAgent{}, err
	}
	if !isHash(mac) {
		return PairedAgent{}, Malformed
	}
	signed := []byte(pairingTag + code.ID())
	for _, part := range []string{identity, address, delegate} {
		signed = binary.BigEndian.AppendUint32(signed, uint32(len(part)))
		signed = append(signed, part...)
	}
	got, _ := hex.DecodeString(mac)
	if !hmac.Equal(code.mac(signed), got) {
		return PairedAgent{}, BadSignature
	}
	if err := agent.asAgent(); err != nil {
		return PairedAgent{}, err
	}
	return PairedAgent{Agent: agent.ID, Address: address, Delegate: delegate}, nil
}

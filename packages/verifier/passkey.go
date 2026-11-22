package verifier

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// An owner's key in a passkey signs WA256: its signature segment holds a WebAuthn assertion whose
// challenge is the hash of the signing input. See "Owner keys in a passkey" in docs/protocol.md.

const (
	userPresent  = 0x01
	userVerified = 0x04
)

// isRPID checks an RP ID: a hostname spelled as an address's domain is, with no port, not an IP
// address, and never "localhost" or a name under it, where any program on the owner's machine can
// serve a page and have their touch sign what it likes.
func isRPID(rp string) bool {
	if strings.ContainsAny(rp, ":[") || !isAddressDomain(rp) {
		return false
	}
	if rp == "localhost" || strings.HasSuffix(rp, ".localhost") {
		return false
	}
	_, err := netip.ParseAddr(rp)
	return err != nil
}

// originAllowed says whether a page at origin may sign for rp: "https://" and the RP ID with no port.
func originAllowed(origin, rp string) bool {
	return origin == "https://"+rp
}

// checkAssertion checks a WA256 signature segment over input, by signer's passkey.
func checkAssertion(input, segment string, signer Signer) error {
	if len(segment) > maxSegment {
		return Malformed
	}
	raw, err := b64(segment)
	if err != nil {
		return Malformed
	}
	v, err := parsePayload(raw)
	if err != nil {
		return Malformed
	}
	// The segment is {"a","c","s"}, or {"a","b","c","s"} when one touch signed several objects.
	f, err := shape(v, []string{"a"}, "b", "c", "s")
	if err != nil || !f.has("c") || !f.has("s") {
		return Malformed
	}
	var parts [3][]byte
	for i, k := range []string{"a", "c", "s"} {
		text, err := f.str(k)
		if err != nil {
			return Malformed
		}
		if parts[i], err = b64(text); err != nil {
			return Malformed
		}
	}
	challenge := sha256.Sum256([]byte(input))
	if f.has("b") {
		if challenge, err = batchChallenge(f["b"], input); err != nil {
			return err
		}
	}
	authData, clientData, sig := parts[0], parts[1], parts[2]
	cd, err := readClientData(clientData)
	if err != nil {
		return err
	}
	if cd.typ != "webauthn.get" || cd.challenge != base64.RawURLEncoding.EncodeToString(challenge[:]) ||
		!originAllowed(cd.origin, signer.RP) || cd.crossOrigin {
		return BadSignature
	}
	rpHash := sha256.Sum256([]byte(signer.RP))
	if len(authData) < 37 || !bytes.Equal(authData[:32], rpHash[:]) ||
		authData[32]&(userPresent|userVerified) != userPresent|userVerified {
		return BadSignature
	}
	if _, err := ecdh.P256().NewPublicKey(signer.Point); err != nil {
		return BadSignature
	}
	key := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(signer.Point[1:33]), Y: new(big.Int).SetBytes(signer.Point[33:])}
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	if !ecdsa.VerifyASN1(&key, digest[:], sig) {
		return BadSignature
	}
	return nil
}

// batchChallenge reads a batch, the list of the hashes of every signing input one touch signed: 2 to 8
// lowercase hex SHA-256 hashes, none twice. The challenge is SHA-256 of "splint wa256 batch v1" and each
// hash's 32 bytes in order, and input's own hash has to be in the list.
func batchChallenge(list Value, input string) ([32]byte, error) {
	if list.kind != kArray || len(list.items) < 2 || len(list.items) > 8 {
		return [32]byte{}, Malformed
	}
	seen := map[string]bool{}
	tagged := []byte("splint wa256 batch v1")
	for _, item := range list.items {
		if item.kind != kString || !isHash(item.str) || seen[item.str] {
			return [32]byte{}, Malformed
		}
		seen[item.str] = true
		raw, _ := hex.DecodeString(item.str)
		tagged = append(tagged, raw...)
	}
	if !seen[hashHex([]byte(input))] {
		return [32]byte{}, BadSignature
	}
	return sha256.Sum256(tagged), nil
}

type clientData struct {
	typ, challenge, origin string
	crossOrigin            bool
}

// readClientData reads clientDataJSON as a browser writes it, in any spacing or escaping, with
// fields of its own allowed and no key twice at the top level.
func readClientData(raw []byte) (clientData, error) {
	if !utf8.Valid(raw) || hasLoneSurrogate(raw) {
		return clientData{}, Malformed
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return clientData{}, Malformed
	}
	seen := map[string]bool{}
	values := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		key, isKey := t.(string)
		if err != nil || !isKey || seen[key] {
			return clientData{}, Malformed
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return clientData{}, Malformed
		}
		values[key] = value
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return clientData{}, Malformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return clientData{}, Malformed
	}
	var cd clientData
	for key, into := range map[string]*string{"type": &cd.typ, "challenge": &cd.challenge, "origin": &cd.origin} {
		value, has := values[key]
		if !has || !isJSONString(value) || json.Unmarshal(value, into) != nil {
			return clientData{}, Malformed
		}
	}
	if value, has := values["crossOrigin"]; has {
		if err := json.Unmarshal(value, &cd.crossOrigin); err != nil || !isJSONBool(value) {
			return clientData{}, Malformed
		}
	}
	return cd, nil
}

// hasLoneSurrogate reports an escape for half a UTF-16 character anywhere in JSON text, keys and
// skipped values included, which Go's decoder would quietly turn into U+FFFD where others refuse it.
func hasLoneSurrogate(raw []byte) bool {
	unit := func(at int) (rune, bool) {
		if at+6 > len(raw) || raw[at] != '\\' || raw[at+1] != 'u' {
			return 0, false
		}
		var r rune
		for _, c := range raw[at+2 : at+6] {
			switch {
			case c >= '0' && c <= '9':
				r = r<<4 | rune(c-'0')
			case c >= 'a' && c <= 'f':
				r = r<<4 | rune(c-'a'+10)
			case c >= 'A' && c <= 'F':
				r = r<<4 | rune(c-'A'+10)
			default:
				return 0, false
			}
		}
		return r, true
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		switch {
		case raw[i] == '"':
			inString = !inString
		case inString && raw[i] == '\\':
			r, isUnit := unit(i)
			switch {
			case !isUnit:
				i++ // An escape of one character, such as \\ or \", is passed over whole.
			case r >= 0xDC00 && r <= 0xDFFF:
				return true
			case r >= 0xD800 && r <= 0xDBFF:
				low, isLow := unit(i + 6)
				if !isLow || low < 0xDC00 || low > 0xDFFF {
					return true
				}
				i += 11
			default:
				i += 5
			}
		}
	}
	return false
}

func isJSONString(v json.RawMessage) bool { return len(v) > 0 && v[0] == '"' }

func isJSONBool(v json.RawMessage) bool {
	return string(v) == "true" || string(v) == "false"
}

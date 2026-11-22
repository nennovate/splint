package verifier

import (
	"crypto/ecdh"
	"strings"
)

const (
	maxRecoveries = 8
	// An owner's ID has at most 4 keys at once, and adds at most 8 between one recovery and the next.
	maxKeys      = 4
	maxAdditions = 8
	// Nothing past 80 KiB is read. A key statement leaves recoveryRoom free for each recovery the ID
	// has left, and a recovery's fields keep it shorter than that, so every recovery always fits.
	maxIdentityChars = 80 * 1024
	recoveryRoom     = 1600
	// Recoveries, then for each epoch its additions and as many removals, and one recovery rule.
	maxStatements = maxRecoveries + (maxRecoveries+1)*2*maxAdditions + 1
)

// The kinds of statement after an event, each told by its header's typ.
const (
	recoveryType     = "splint-recovery"
	keyAddType       = "splint-key-add"
	keyRemoveType    = "splint-key-remove"
	recoveryRuleType = "splint-recovery-rule"
)

// Identity is an ID's event and its statements, read and checked.
type Identity struct {
	ID          string
	Keys        []Signer   // the key the event and each recovery named, how it signs, oldest first
	Added       [][]Signer // every key added while each of those was the newest, removed since or not
	Counting    []Signer   // the keys that count now
	Seals       []Point    // every sealing key, oldest first
	Commitments []string   // every recovery rule's commitment, oldest first
	steps       []string   // each statement's signing input, which a fork compares
	kinds       []string   // each statement's typ
	Encoded     string
}

// Key is the key the event or the newest recovery named. It's the only key of an agent, and of an owner
// who never added one: what an owner signs now is checked under Counting.
func (id Identity) Key() Signer { return id.Keys[len(id.Keys)-1] }

// Recoveries counts the recoveries read.
func (id Identity) Recoveries() int { return len(id.recoveryInputs()) }

// recoveryInputs are each recovery's signing input, oldest first, which a history's key event names.
func (id Identity) recoveryInputs() []string {
	var out []string
	for i, kind := range id.kinds {
		if kind == recoveryType {
			out = append(out, id.steps[i])
		}
	}
	return out
}

// hasKeyStatements says whether this ID ever added or removed a key, which only an owner's may.
func (id Identity) hasKeyStatements() bool {
	for _, kind := range id.kinds {
		if kind != recoveryType {
			return true
		}
	}
	return false
}

// asAgent refuses an ID that can't be an agent's: one whose key is a passkey, or one with key statements.
func (id Identity) asAgent() error {
	if id.Key().RP != "" || id.hasKeyStatements() {
		return WrongSigner
	}
	return nil
}

// epochKeys is every key that counted at some point between recovery n and the next, which is what a
// history under that count is read back under.
func (id Identity) epochKeys(n int64) []Signer {
	return append([]Signer{id.Keys[n]}, id.Added[n]...)
}

// everyKey is every key this copy's chain has had, for reading back what was signed before.
func (id Identity) everyKey() []Signer {
	var out []Signer
	for n := range id.Keys {
		out = append(out, id.epochKeys(int64(n))...)
	}
	return out
}

// unconfirmedOwner says whether this is a stand-in for an owner who hasn't confirmed their agent: an
// ID with no statements whose rule commits to the SHA-256 of "splint-unconfirmed-owner" followed by its
// own key, which no backup can satisfy.
func (id Identity) unconfirmedOwner() bool {
	if len(id.steps) != 0 || len(id.Keys) != 1 || len(id.Commitments) != 1 {
		return false
	}
	tagged := append([]byte("splint-unconfirmed-owner"), id.Keys[0].Point...)
	return id.Commitments[0] == hashHex(tagged)
}

// laterRule is what an owner made without a recovery code commits to until a key that counts sets
// one: the SHA-256 of "splint-recovery-later" followed by the key's 65 bytes, which no backup can
// satisfy.
func laterRule(key Point) string {
	return hashHex(append([]byte("splint-recovery-later"), key...))
}

// recoveryIsLater says whether this ID's rule is still the one it was made with in place of a code.
func (id Identity) recoveryIsLater() bool {
	return id.Commitments[len(id.Commitments)-1] == laterRule(id.Key().Point)
}

// An event is version 4 for a key that signs ES256, or version 5, with an RP ID, for an owner's
// passkey.
func parseEvent(raw []byte) (Signer, Point, string, error) {
	v, err := parsePayload(raw)
	if err != nil {
		return Signer{}, nil, "", err
	}
	f, err := shape(v, []string{"v", "alg", "key", "seal", "recovery"})
	wantAlg := "ES256"
	if err != nil {
		f, err = shape(v, []string{"v", "alg", "key", "rp", "seal", "recovery"})
		if err != nil || f.version(5) != nil {
			return Signer{}, nil, "", Malformed
		}
		wantAlg = "webauthn-es256"
	} else if f.version(4) != nil {
		return Signer{}, nil, "", Malformed
	}
	if alg, err := f.str("alg"); err != nil || alg != wantAlg {
		return Signer{}, nil, "", Malformed
	}
	signer, err := readSigner(f)
	if err != nil {
		return Signer{}, nil, "", err
	}
	seal, err := checkSealingKey(f, signer.Point)
	if err != nil {
		return Signer{}, nil, "", err
	}
	commitment, err := parseRule(f["recovery"])
	if err != nil {
		return Signer{}, nil, "", err
	}
	if commitment == hashHex(signer.Point) {
		return Signer{}, nil, "", Malformed
	}
	return signer, seal, commitment, nil
}

// readSigner reads `key`, and `rp` if the shape has one, which has to be an RP ID.
func readSigner(f fields) (Signer, error) {
	keyText, err := f.str("key")
	if err != nil {
		return Signer{}, err
	}
	key, err := parsePoint(keyText)
	if err != nil {
		return Signer{}, err
	}
	signer := Signer{Point: key}
	if f.has("rp") {
		if signer.RP, err = f.str("rp"); err != nil || !isRPID(signer.RP) {
			return Signer{}, Malformed
		}
	}
	return signer, nil
}

// checkSealingKey reads the key others seal to, which has to be a point on the curve and not the
// signing key's own.
func checkSealingKey(f fields, key Point) (Point, error) {
	sealText, err := f.str("seal")
	if err != nil {
		return nil, err
	}
	seal, err := parsePoint(sealText)
	if err != nil {
		return nil, err
	}
	if _, err := ecdh.P256().NewPublicKey(seal); err != nil || hashHex(seal) == hashHex(key) {
		return nil, Malformed
	}
	return seal, nil
}

func parseRule(v Value) (string, error) {
	f, err := shape(v, []string{"rule", "commitment"})
	if err != nil {
		return "", err
	}
	if rule, err := f.str("rule"); err != nil || rule != "backup_key" {
		return "", Malformed
	}
	return f.hash("commitment")
}

// ParseIdentityEvent reads one identity event, as base64url, and gives its ID.
func ParseIdentityEvent(encoded string) (string, error) {
	raw, err := b64(encoded)
	if err != nil {
		return "", err
	}
	if _, _, _, err := parseEvent(raw); err != nil {
		return "", err
	}
	return "splint1" + hashHex(raw), nil
}

// ReadIdentity reads an encoded identity: the event, then `~` and each statement.
func ReadIdentity(encoded string) (Identity, error) {
	parts := strings.Split(encoded, "~")
	if len(encoded) > maxIdentityChars || len(parts) > maxStatements+1 {
		return Identity{}, Malformed
	}
	raw, err := b64(parts[0])
	if err != nil {
		return Identity{}, err
	}
	key, seal, commitment, err := parseEvent(raw)
	if err != nil {
		return Identity{}, err
	}
	id := Identity{ID: "splint1" + hashHex(raw), Keys: []Signer{key}, Added: [][]Signer{nil}, Counting: []Signer{key},
		Seals: []Point{seal}, Commitments: []string{commitment}, Encoded: encoded}
	prev := hashHex(raw)
	used := len(parts[0])
	for i, compact := range parts[1:] {
		kind, s, proof, err := statementOf(compact)
		if err != nil {
			return Identity{}, err
		}
		used += 1 + len(compact)
		switch kind {
		case recoveryType:
			err = id.takeRecovery(s, i+1, prev)
		case keyAddType:
			err = id.takeKeyAdd(s, proof, i+1, prev)
		case recoveryRuleType:
			err = id.takeRecoveryRule(s, i+1, prev)
		default:
			err = id.takeKeyRemove(s, i+1, prev)
		}
		if err != nil {
			return Identity{}, err
		}
		// A key statement leaves room for every recovery the ID has left.
		if kind != recoveryType && used+(maxRecoveries-id.Recoveries())*recoveryRoom > maxIdentityChars {
			return Identity{}, Malformed
		}
		id.steps = append(id.steps, s.Input)
		id.kinds = append(id.kinds, kind)
		prev = s.InputHash()
	}
	return id, nil
}

// statementOf tells a statement's kind by its header's typ, and parses its payload. An addition
// carries a fourth segment, the added key's own signature over the same signing input, which comes
// back unread.
func statementOf(compact string) (string, Signed, string, error) {
	if signed, proof, ok := cutLast(compact, "."); ok {
		if s, err := readSigned(signed, keyAddType); err == nil {
			if s.Body, err = parsePayload(s.Payload); err != nil {
				return "", Signed{}, "", err
			}
			return keyAddType, s, proof, nil
		}
	}
	for _, typ := range []string{recoveryType, keyRemoveType, recoveryRuleType} {
		s, err := readSigned(compact, typ)
		if err != nil {
			continue
		}
		if s.Body, err = parsePayload(s.Payload); err != nil {
			return "", Signed{}, "", err
		}
		return typ, s, "", nil
	}
	return "", Signed{}, "", Malformed
}

// cutLast splits at the last sep.
func cutLast(text, sep string) (string, string, bool) {
	at := strings.LastIndex(text, sep)
	if at < 0 {
		return "", "", false
	}
	return text[:at], text[at+len(sep):], true
}

// follows reads a statement's id, seq, prev and issued_at, and checks it comes next on this copy.
func (id Identity) follows(f fields, seq int, prev string) error {
	forID, err := f.id("id")
	if err != nil {
		return err
	}
	n, err := f.num("seq")
	if err != nil {
		return err
	}
	named, err := f.hash("prev")
	if err != nil {
		return err
	}
	if _, err := f.date("issued_at"); err != nil {
		return err
	}
	if forID != id.ID || n != int64(seq) || named != prev {
		return ProofMismatch
	}
	return nil
}

func (id *Identity) takeRecovery(s Signed, seq int, prev string) error {
	if id.Recoveries() >= maxRecoveries {
		return Malformed
	}
	// Version 2 names a key that signs ES256, and version 3 a passkey, with its `alg` and RP ID.
	f, err := shape(s.Body, []string{"v", "id", "seq", "prev", "backup", "key", "seal", "recovery", "issued_at"})
	if err != nil || f.version(2) != nil {
		f, err = shape(s.Body, []string{"v", "id", "seq", "prev", "backup", "alg", "key", "rp", "seal", "recovery", "issued_at"})
		if err != nil || f.version(3) != nil {
			return Malformed
		}
		if alg, err := f.str("alg"); err != nil || alg != "webauthn-es256" {
			return Malformed
		}
	}
	if _, err := f.id("id"); err != nil {
		return err
	}
	if _, err := f.num("seq"); err != nil {
		return err
	}
	if _, err := f.hash("prev"); err != nil {
		return err
	}
	if _, err := f.date("issued_at"); err != nil {
		return err
	}
	backupText, err := f.str("backup")
	if err != nil {
		return err
	}
	backup, err := parsePoint(backupText)
	if err != nil {
		return err
	}
	next, err := readSigner(f)
	if err != nil {
		return err
	}
	nextSeal, err := checkSealingKey(f, next.Point)
	if err != nil {
		return err
	}
	nextRule, err := parseRule(f["recovery"])
	if err != nil {
		return err
	}
	// Whoever recovers holds the code, so the next rule is a real one.
	if nextRule == laterRule(next.Point) {
		return Malformed
	}
	if err := id.follows(f, seq, prev); err != nil {
		return err
	}
	if hashHex(backup) != id.Commitments[len(id.Commitments)-1] {
		return WrongSigner
	}
	if !s.verifiedByKey(backup) {
		return BadSignature
	}
	for _, c := range id.Commitments {
		if c == nextRule {
			return Malformed
		}
	}
	if nextRule == hashHex(next.Point) {
		return Malformed
	}
	// Nor commit to, or seal to, a key this ID has had, so a key's name never means a backup.
	for _, k := range id.everyKey() {
		if hashHex(k.Point) == nextRule || hashHex(k.Point) == hashHex(nextSeal) {
			return Malformed
		}
	}
	// Read against the key the event or the newest recovery named, whatever was added since. A key
	// that stays has to stay the same kind: one point is one key, held one way.
	sameKey := hashHex(next.Point) == hashHex(id.Key().Point)
	if sameKey && next.RP != id.Key().RP {
		return Malformed
	}
	// A new signing key goes with a sealing key this ID has never had: the old one went with the
	// key it was replacing.
	if !sameKey {
		for _, used := range id.Seals {
			if hashHex(used) == hashHex(nextSeal) {
				return Malformed
			}
		}
	}
	// The backup overrides every key: only the one it names counts after it.
	id.Keys = append(id.Keys, next)
	id.Added = append(id.Added, nil)
	id.Counting = []Signer{next}
	id.Seals = append(id.Seals, nextSeal)
	id.Commitments = append(id.Commitments, nextRule)
	return nil
}

// signedByCounting checks that `by` names a key that counts now, and that it alone made the signature.
// A stand-in's key is on its agent's machine, so a stand-in carries no key statement.
func (id Identity) signedByCounting(s Signed, by string) (Signer, error) {
	if id.unconfirmedOwner() {
		return Signer{}, Malformed
	}
	for _, k := range id.Counting {
		if hashHex(k.Point) == by {
			return k, s.check(k)
		}
	}
	return Signer{}, WrongSigner
}

func (id *Identity) takeKeyAdd(s Signed, proof string, seq int, prev string) error {
	// Version 4 adds a key that signs ES256, and version 5 a passkey, made for any RP ID.
	f, err := shape(s.Body, []string{"v", "id", "seq", "prev", "by", "key", "issued_at"})
	if err != nil || f.version(4) != nil {
		f, err = shape(s.Body, []string{"v", "id", "seq", "prev", "by", "alg", "key", "rp", "issued_at"})
		if err != nil || f.version(5) != nil {
			return Malformed
		}
		if alg, err := f.str("alg"); err != nil || alg != "webauthn-es256" {
			return Malformed
		}
	}
	by, err := f.hash("by")
	if err != nil {
		return err
	}
	added, err := readSigner(f)
	if err != nil {
		return err
	}
	if _, err := ecdh.P256().NewPublicKey(added.Point); err != nil {
		return Malformed
	}
	if err := id.follows(f, seq, prev); err != nil {
		return err
	}
	if _, err := id.signedByCounting(s, by); err != nil {
		return err
	}
	// The added key signs the same signing input, the way it signs, so nobody adds a key they don't
	// hold.
	if err := checkProof(s.Input, proof, added); err != nil {
		return err
	}
	// No point this copy has had as a key or a sealing key, nor the backup its rule commits to now.
	if id.knowsKey(added.Point) || hashHex(added.Point) == id.Commitments[len(id.Commitments)-1] {
		return Malformed
	}
	for _, seal := range id.Seals {
		if hashHex(seal) == hashHex(added.Point) {
			return Malformed
		}
	}
	if len(id.Counting) >= maxKeys || len(id.Added[len(id.Added)-1]) >= maxAdditions {
		return Malformed
	}
	last := len(id.Added) - 1
	id.Added[last] = append(id.Added[last], added)
	id.Counting = append(append([]Signer{}, id.Counting...), added)
	return nil
}

// checkProof checks an addition's fourth segment: the added key's own signature over the signing input,
// 64 bytes of ES256 for a key that signs ES256, or a WA256 assertion for a passkey.
func checkProof(input, segment string, added Signer) error {
	if added.RP != "" {
		return checkAssertion(input, segment, added)
	}
	sig, err := b64(segment)
	if err != nil || len(sig) != 64 {
		return Malformed
	}
	if !added.verify([]byte(input), sig) {
		return BadSignature
	}
	return nil
}

// takeRecoveryRule sets the rule of an ID made without one, once, signed by a key that counts.
func (id *Identity) takeRecoveryRule(s Signed, seq int, prev string) error {
	f, err := shape(s.Body, []string{"v", "id", "seq", "prev", "by", "recovery", "issued_at"})
	if err != nil || f.version(7) != nil {
		return Malformed
	}
	by, err := f.hash("by")
	if err != nil {
		return err
	}
	rule, err := parseRule(f["recovery"])
	if err != nil {
		return err
	}
	if err := id.follows(f, seq, prev); err != nil {
		return err
	}
	if _, err := id.signedByCounting(s, by); err != nil {
		return err
	}
	if !id.recoveryIsLater() {
		return Malformed
	}
	for _, c := range id.Commitments {
		if c == rule {
			return Malformed
		}
	}
	for _, seal := range id.Seals {
		if hashHex(seal) == rule {
			return Malformed
		}
	}
	for _, k := range id.everyKey() {
		if hashHex(k.Point) == rule {
			return Malformed
		}
	}
	id.Commitments[len(id.Commitments)-1] = rule
	return nil
}

func (id *Identity) takeKeyRemove(s Signed, seq int, prev string) error {
	f, err := shape(s.Body, []string{"v", "id", "seq", "prev", "by", "key", "issued_at"})
	if err != nil || f.version(6) != nil {
		return Malformed
	}
	by, err := f.hash("by")
	if err != nil {
		return err
	}
	removed, err := f.hash("key")
	if err != nil {
		return err
	}
	if err := id.follows(f, seq, prev); err != nil {
		return err
	}
	if _, err := id.signedByCounting(s, by); err != nil {
		return err
	}
	var left []Signer
	for _, k := range id.Counting {
		if hashHex(k.Point) != removed {
			left = append(left, k)
		}
	}
	if len(left) == len(id.Counting) || len(left) == 0 {
		return Malformed
	}
	id.Counting = left
	return nil
}

// readIdentityAs reads an identity that has to hash to want.
func readIdentityAs(encoded, want string) (Identity, error) {
	id, err := ReadIdentity(encoded)
	if err != nil {
		return Identity{}, err
	}
	if id.ID != want {
		return Identity{}, ProofMismatch
	}
	return id, nil
}

// CheckBackup says whether a backup key is the one the newest rule commits to.
func CheckBackup(id Identity, backup Point) error {
	if hashHex(backup) != id.Commitments[len(id.Commitments)-1] {
		return ProofMismatch
	}
	return nil
}

// Newest is the copy of one ID a reader goes by. A copy with fewer statements changes nothing. Of two
// that part ways, the one with a recovery after they part counts, and otherwise they're a fork.
func Newest(pinned, claimed Identity) (Identity, error) {
	if pinned.ID != claimed.ID {
		return Identity{}, ProofMismatch
	}
	shared := 0
	for shared < len(pinned.steps) && shared < len(claimed.steps) && pinned.steps[shared] == claimed.steps[shared] {
		shared++
	}
	switch {
	case shared == len(pinned.steps):
		return claimed, nil
	case shared == len(claimed.steps):
		return pinned, nil
	}
	recoveredAfter := func(id Identity) bool {
		for _, kind := range id.kinds[shared:] {
			if kind == recoveryType {
				return true
			}
		}
		return false
	}
	switch p, c := recoveredAfter(pinned), recoveredAfter(claimed); {
	case p && !c:
		return pinned, nil
	case c && !p:
		return claimed, nil
	}
	return Identity{}, Forked
}

// knowsKey says whether key was ever this ID's, as the key an event or recovery named or one added.
func (id Identity) knowsKey(key Point) bool {
	for _, k := range id.everyKey() {
		if string(k.Point) == string(key) {
			return true
		}
	}
	return false
}

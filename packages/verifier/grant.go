package verifier

import (
	"crypto/sha256"
	"encoding/hex"
)

const (
	NoGrant       Refusal = "no_grant"
	Revoked       Refusal = "revoked"
	WrongHolder   Refusal = "wrong_holder"
	WrongResource Refusal = "wrong_resource"
	BadProof      Refusal = "bad_proof"
	OverRate      Refusal = "over_rate"
)

// Call is one call a resource received, with what came with it.
type Call struct {
	Grant, Proof, HolderIdentity string
	Resource, Operation          string
	Method, Path                 string
	Body                         []byte
	Revoked                      []string // grant IDs the resource holds revocations for
	CallsThisHour                int64
	Now                          int64
}

// Granted is what only a passing check produces.
type Granted struct {
	Grant, Holder, Operation string
}

// CheckGrant runs the resource check in the protocol's order, under the owner from the
// resource's own config.
func CheckGrant(owner Identity, c Call) (Granted, error) {
	s, err := openAs(c.Grant, "splint-grant", owner.Counting)
	if err != nil {
		return Granted{}, err
	}
	f, err := shape(s.Body, []string{"v", "owner", "holder", "resource", "operations", "limits", "issued_at", "expires_at", "nonce"})
	if err != nil || f.version(1) != nil {
		return Granted{}, Malformed
	}
	ownerID, err := f.id("owner")
	if err != nil {
		return Granted{}, err
	}
	holder, err := f.id("holder")
	if err != nil {
		return Granted{}, err
	}
	resource, err := f.str("resource")
	if err != nil || !isDomain(resource) {
		return Granted{}, Malformed
	}
	ops, err := operations(f["operations"])
	if err != nil {
		return Granted{}, err
	}
	limits, err := shape(f["limits"], []string{"calls_per_hour"})
	if err != nil {
		return Granted{}, err
	}
	rate, err := limits.num("calls_per_hour")
	if err != nil || rate < 1 || rate > 1000 {
		return Granted{}, Malformed
	}
	issued, err := f.date("issued_at")
	if err != nil {
		return Granted{}, err
	}
	expires, err := f.date("expires_at")
	if err != nil || expires <= issued || expires-issued > maxLifetime {
		return Granted{}, Malformed
	}
	if nonce, err := f.str("nonce"); err != nil {
		return Granted{}, err
	} else if n, err := b64(nonce); err != nil || len(n) != 16 {
		return Granted{}, Malformed
	}
	if ownerID != owner.ID || issued > c.Now+clockTolerance {
		return Granted{}, NoGrant
	}
	if resource != c.Resource {
		return Granted{}, WrongResource
	}
	if !contains(ops, c.Operation) {
		return Granted{}, NoGrant
	}
	if c.Now >= expires {
		return Granted{}, Expired
	}
	if contains(c.Revoked, s.ID()) {
		return Granted{}, Revoked
	}
	identity, err := ReadIdentity(c.HolderIdentity)
	if err != nil {
		return Granted{}, err
	}
	if identity.ID != holder {
		return Granted{}, WrongHolder
	}
	proof, err := VerifyAccessProof(c.Proof, identity, c.Resource, c.Method, c.Path, c.Body, c.Now)
	if err != nil || proof != holder {
		return Granted{}, BadProof
	}
	if c.CallsThisHour >= rate {
		return Granted{}, OverRate
	}
	return Granted{Grant: s.ID(), Holder: holder, Operation: c.Operation}, nil
}

func operations(v Value) ([]string, error) {
	if v.kind != kArray || len(v.items) < 1 || len(v.items) > 16 {
		return nil, Malformed
	}
	out := []string{}
	for _, item := range v.items {
		if item.kind != kString || !isOperation(item.str) {
			return nil, Malformed
		}
		out = append(out, item.str)
	}
	for i := 1; i < len(out); i++ {
		if out[i-1] >= out[i] {
			return nil, Malformed
		}
	}
	return out, nil
}

func isOperation(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// isDomain allows letters, digits, `.`, `-` and `:`.
func isDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}

// VerifyAccessProof checks that a proof fits one host, method, path and body, within the
// tolerance either way, by a key of the identity's that counts now: an agent's one key, or any of an
// owner's. It gives the signer it names.
func VerifyAccessProof(compact string, signer Identity, host, method, path string, body []byte, now int64) (string, error) {
	s, err := openAs(compact, "splint-access", signer.Counting)
	if err != nil {
		return "", err
	}
	f, err := shape(s.Body, []string{"signer", "host", "method", "path", "body_sha256", "issued_at"})
	if err != nil {
		return "", err
	}
	named, err := f.id("signer")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	issued, err := f.date("issued_at")
	if err != nil {
		return "", err
	}
	gotHost, _ := f.str("host")
	gotMethod, _ := f.str("method")
	gotPath, _ := f.str("path")
	gotBody, _ := f.str("body_sha256")
	if named != signer.ID || gotHost != host || gotMethod != method || gotPath != path || gotBody != hex.EncodeToString(sum[:]) {
		return "", ProofMismatch
	}
	if issued < now-clockTolerance {
		return "", Expired
	}
	if issued > now+clockTolerance {
		return "", FromTheFuture
	}
	return named, nil
}

// VerifyRevocation checks an owner's revocation of a grant, and gives the grant's ID.
func VerifyRevocation(compact string, owner Identity) (string, error) {
	s, err := openAs(compact, "splint-grant-revocation", owner.Counting)
	if err != nil {
		return "", err
	}
	f, err := shape(s.Body, []string{"v", "owner", "grant", "issued_at"})
	if err != nil || f.version(1) != nil {
		return "", Malformed
	}
	if _, err := f.date("issued_at"); err != nil {
		return "", err
	}
	grant, err := f.hash("grant")
	if err != nil {
		return "", err
	}
	if named, err := f.id("owner"); err != nil || named != owner.ID {
		return "", ProofMismatch
	}
	return grant, nil
}

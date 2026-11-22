package verifier

import (
	"net/netip"
	"strings"
)

// Binding is an owner's statement that this agent acts for them at this address, with the
// agent's acceptance and its backup's vouch, and a release from the owner before if it moved.
type Binding struct {
	Owner, Agent, Address string
	Seq                   int64
	Release               *Release
	Hash                  string // of the owner's compact binding
}

// Release is an owner letting an agent go, to a new owner or to nobody.
type Release struct {
	Owner, Agent string
	To           string // empty for nobody
	Seq          int64
}

// VerifyBindingFor checks a binding under the owner's and agent's current keys, and that it binds
// the address the reader was given, so a binding for one address can't vouch for another.
func VerifyBindingFor(compact string, owner, agent Identity, address string) (Binding, error) {
	b, err := VerifyBinding(compact, owner, owner.Counting, agent, agent.Key(), true)
	if err != nil {
		return Binding{}, err
	}
	if b.Address != address {
		return Binding{}, ProofMismatch
	}
	return b, nil
}

// VerifyBinding checks a binding under the owner's and agent's given keys. One of ownerKeys signs
// the binding, agentKey accepts it, and any backup the agent has committed to vouches, for the keys
// the agent had when it did. One arriving now, live, whose owner's half the agent's own key signed is
// refused; one read back is taken as it was signed.
func VerifyBinding(compact string, owner Identity, ownerKeys []Signer, agent Identity, agentKey Signer, live bool) (Binding, error) {
	// Only an owner's key may be a passkey, and only an owner's ID may add or remove keys.
	if agentKey.RP != "" || agent.hasKeyStatements() {
		return Binding{}, WrongSigner
	}
	parts := strings.Split(compact, "~")
	if len(parts) < 3 || len(parts) > 4 {
		return Binding{}, Malformed
	}
	s, err := openAs(parts[0], "splint-binding", ownerKeys)
	if err != nil {
		return Binding{}, err
	}
	f, err := shape(s.Body, []string{"v", "owner", "agent", "address", "seq", "issued_at"})
	if err != nil || f.version(2) != nil {
		return Binding{}, Malformed
	}
	b := Binding{Hash: hashHex([]byte(parts[0]))}
	if b.Owner, err = f.id("owner"); err != nil {
		return Binding{}, err
	}
	if b.Agent, err = f.id("agent"); err != nil {
		return Binding{}, err
	}
	if b.Address, err = f.str("address"); err != nil || !isAddress(b.Address) {
		return Binding{}, Malformed
	}
	if b.Seq, err = f.num("seq"); err != nil || b.Seq < 0 {
		return Binding{}, Malformed
	}
	if _, err := f.date("issued_at"); err != nil {
		return Binding{}, err
	}
	if b.Owner != owner.ID || b.Agent != agent.ID || b.Owner == b.Agent {
		return Binding{}, ProofMismatch
	}
	// One key, one job: a binding arriving now that the agent's own key signed as its owner is refused.
	// Only whoever holds that key outside Signet could have added it, as an addition needs the added
	// key's signature, and it turns on this one object, never on comparing the two IDs' keys.
	if live && s.verifiedBy(agentKey) {
		return Binding{}, WrongSigner
	}
	accept, err := open(parts[1], "splint-binding-accept", agentKey)
	if err != nil {
		return Binding{}, err
	}
	af, err := shape(accept.Body, []string{"v", "binding"})
	if err != nil || af.version(1) != nil {
		return Binding{}, Malformed
	}
	if named, err := af.hash("binding"); err != nil {
		return Binding{}, err
	} else if named != b.Hash {
		return Binding{}, ProofMismatch
	}
	if err := checkVouch(parts[2], owner, agent); err != nil {
		return Binding{}, err
	}
	if len(parts) == 4 {
		r, err := readRelease(parts[3])
		if err != nil {
			return Binding{}, err
		}
		b.Release = &r
	}
	return b, nil
}

func checkVouch(compact string, owner, agent Identity) error {
	s, err := readSigned(compact, "splint-binding-vouch")
	if err != nil {
		return err
	}
	if s.Body, err = parsePayload(s.Payload); err != nil {
		return err
	}
	f, err := shape(s.Body, []string{"v", "agent", "owner", "backup", "keys"})
	if err != nil || f.version(2) != nil {
		return Malformed
	}
	backupText, err := f.str("backup")
	if err != nil {
		return err
	}
	backup, err := parsePoint(backupText)
	if err != nil {
		return err
	}
	// The keys the agent had when its ID first committed to this backup, which the vouch has to name,
	// so a copy that an earlier backup moved to this one onto other keys gets nothing from it.
	committedAt := -1
	for i, c := range agent.Commitments {
		if committedAt < 0 && c == hashHex(backup) {
			committedAt = i
		}
	}
	if committedAt < 0 {
		return WrongSigner
	}
	if !s.verifiedByKey(backup) {
		return BadSignature
	}
	if a, _ := f.str("agent"); a != agent.ID {
		return ProofMismatch
	}
	if o, _ := f.str("owner"); o != owner.ID {
		return ProofMismatch
	}
	keys := agent.Keys[committedAt].String() + "." + agent.Seals[committedAt].String()
	if k, _ := f.str("keys"); k != keys {
		return ProofMismatch
	}
	return nil
}

// readRelease parses a release without checking who signed it.
func readRelease(compact string) (Release, error) {
	s, err := readSigned(compact, "splint-release")
	if err != nil {
		return Release{}, err
	}
	if s.Body, err = parsePayload(s.Payload); err != nil {
		return Release{}, err
	}
	f, err := shape(s.Body, []string{"v", "owner", "agent", "to", "seq", "issued_at"})
	if err != nil || f.version(1) != nil {
		return Release{}, Malformed
	}
	r := Release{}
	if r.Owner, err = f.id("owner"); err != nil {
		return Release{}, err
	}
	if r.Agent, err = f.id("agent"); err != nil {
		return Release{}, err
	}
	to, named, err := f.optStr("to")
	if err != nil || (named && !isID(to)) {
		return Release{}, Malformed
	}
	r.To = to
	if r.Seq, err = f.num("seq"); err != nil || r.Seq < 0 {
		return Release{}, Malformed
	}
	if _, err := f.date("issued_at"); err != nil {
		return Release{}, err
	}
	return r, nil
}

// VerifyRelease checks a release signed by one of the owner's given keys, for that agent.
func VerifyRelease(compact string, owner Identity, ownerKeys []Signer, agent string) (Release, error) {
	s, err := readSigned(compact, "splint-release")
	if err != nil {
		return Release{}, err
	}
	if s.checkBy(ownerKeys) != nil {
		return Release{}, BadSignature
	}
	r, err := readRelease(compact)
	if err != nil {
		return Release{}, err
	}
	if r.Owner != owner.ID || r.Agent != agent {
		return Release{}, ProofMismatch
	}
	return r, nil
}

// MayReplace says whether a later binding replaces the one held: the same owner at a `seq`
// at least as high, or a new owner the current one released the agent to, before this binding.
func MayReplace(compact string, newOwner, agent, currentOwner Identity, currentSeq int64) error {
	parts := strings.Split(compact, "~")
	b, err := VerifyBinding(strings.Join(parts[:min(3, len(parts))], "~"), newOwner, newOwner.Counting, agent, agent.Key(), true)
	if err != nil {
		return err
	}
	if b.Owner == currentOwner.ID {
		if b.Seq < currentSeq {
			return Stale
		}
		return nil
	}
	if len(parts) != 4 {
		return WrongSigner
	}
	r, err := VerifyRelease(parts[3], currentOwner, currentOwner.Counting, agent.ID)
	if err != nil {
		return err
	}
	if r.To != b.Owner {
		return WrongSigner
	}
	if r.Seq < currentSeq || r.Seq >= b.Seq {
		return Stale
	}
	return nil
}

// ParseAddress checks `name~domain`, in its one spelling. A name is a handle, or `agent.owner`,
// each lowercase letters, digits and hyphens, 63 characters at most in all. The domain is
// lowercase with no trailing dot. `::`, the link form and the email form are only typed input, and
// whatever reads them turns them into this before anything is signed or stored.
func ParseAddress(s string) (name, domain string, err error) {
	name, domain, ok := strings.Cut(s, "~")
	if !ok || len(name) > 63 || !isAddressDomain(domain) {
		return "", "", Malformed
	}
	agent, owner, hasOwner := strings.Cut(name, ".")
	if !isHandle(agent) || (hasOwner && !isHandle(owner)) {
		return "", "", Malformed
	}
	return name, domain, nil
}

func isHandle(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// VerifyRetirement checks an owner's retirement of an agent, and gives the agent.
func VerifyRetirement(compact string, owner Identity) (string, error) {
	s, err := openAs(compact, "splint-retirement", owner.Counting)
	if err != nil {
		return "", err
	}
	f, err := shape(s.Body, []string{"v", "owner", "agent", "reason", "issued_at"})
	if err != nil || f.version(1) != nil {
		return "", Malformed
	}
	agent, err := f.id("agent")
	if err != nil {
		return "", err
	}
	if reason, _ := f.str("reason"); reason != "key_lost" && reason != "finished" {
		return "", Malformed
	}
	if _, err := f.date("issued_at"); err != nil {
		return "", err
	}
	if o, _ := f.str("owner"); o != owner.ID {
		return "", ProofMismatch
	}
	return agent, nil
}

func isAddress(s string) bool {
	_, _, err := ParseAddress(s)
	return err == nil
}

// isAddressDomain checks `name`, `name:port` or `[v6]:port`, in the one spelling an address uses:
// lowercase labels, a port with no leading zero, and an IPv6 address written the standard way.
func isAddressDomain(d string) bool {
	if d == "" || len(d) > 255 {
		return false
	}
	if inside, ok := strings.CutPrefix(d, "["); ok {
		v6, rest, ok := strings.Cut(inside, "]")
		ip, err := netip.ParseAddr(v6)
		if !ok || err != nil || !ip.Is6() || ip.Is4In6() || ip.Zone() != "" || ip.String() != v6 {
			return false
		}
		if rest == "" {
			return true
		}
		port, ok := strings.CutPrefix(rest, ":")
		return ok && isPort(port)
	}
	name, port, hasPort := strings.Cut(d, ":")
	if hasPort && !isPort(port) {
		return false
	}
	if endsInNumber(name) && !isDottedQuad(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// endsInNumber says whether a URL reads this name as an IPv4 address, by its last label being a
// number in decimal or hex.
func endsInNumber(name string) bool {
	last := name[strings.LastIndexByte(name, '.')+1:]
	hex, isHex := strings.CutPrefix(last, "0x")
	return allBytes(last, "0123456789") || (isHex && allBytes(hex, "0123456789abcdef"))
}

func allBytes(s, of string) bool {
	return strings.Trim(s, of) == ""
}

func isDottedQuad(name string) bool {
	ip, err := netip.ParseAddr(name)
	return err == nil && ip.Is4() && ip.String() == name
}

// isPort refuses 443, as a domain with no port is called there and so it would be a second spelling.
func isPort(s string) bool {
	if s == "" || s[0] == '0' || len(s) > 5 || s == "443" {
		return false
	}
	n := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n <= 65535
}

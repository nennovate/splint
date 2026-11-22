package verifier

import "strings"

// OverLimit is a delegate's yes past what the owner let it say.
const OverLimit Refusal = "over_limit"

// OwnerUnconfirmed is an owner who hasn't confirmed their agent: a stand-in whose key the agent's own
// machine holds, so nothing it signs is an owner's yes.
const OwnerUnconfirmed Refusal = "owner_unconfirmed"

const (
	maxDelegationLife = 365 * 24 * 3600
	maxDelegation     = 2560
	maxActionsPerDay  = 2500
	maxCappedTypes    = 16
	maxCapsPerType    = 16
)

// Delegation is an owner's leave for one key to say yes within caps. One signed before rules lasted
// until replaced may also carry renew_rules, which lets it do nothing now.
type Delegation struct {
	Owner, Agent      string
	Delegate          Point
	May               []string
	Level             string
	Caps              map[string]map[string]int64
	Seq               int64
	IssuedAt, Expires int64
	// Name is how rules name it: the hex SHA-256 of its signing input.
	Name string
}

func (d Delegation) may(what string) bool {
	for _, m := range d.May {
		if m == what {
			return true
		}
	}
	return false
}

// readDelegation checks a delegation's signature, its shape, and that it's for this agent, to a key
// that's neither the agent's nor the owner's. Not its dates. Arriving, it's checked under the key the
// owner holds now, so a recovery ends it. Read back in a chain, under any key the owner has had, as
// their own yes is. A stand-in's key is on the agent's machine, so it delegates nothing.
func readDelegation(compact string, owner, agent Identity, readBack bool) (Delegation, error) {
	if len(compact) > maxDelegation {
		return Delegation{}, Malformed
	}
	if owner.unconfirmedOwner() {
		return Delegation{}, WrongSigner
	}
	open := openAs
	keys := owner.Counting
	if readBack {
		open, keys = openUnder, owner.everyKey()
	}
	s, err := open(compact, "splint-delegation", keys)
	if err != nil {
		return Delegation{}, err
	}
	f, err := shape(s.Body, []string{"v", "owner", "agent", "delegate", "may", "level", "caps", "actions_per_day", "seq", "issued_at", "expires_at"})
	if err != nil || f.version(1) != nil {
		return Delegation{}, Malformed
	}
	d := Delegation{Name: s.InputHash()}
	if d.Owner, err = f.id("owner"); err != nil {
		return Delegation{}, err
	}
	if d.Agent, err = f.id("agent"); err != nil {
		return Delegation{}, err
	}
	delegate, err := f.str("delegate")
	if err != nil {
		return Delegation{}, err
	}
	if d.Delegate, err = parsePoint(delegate); err != nil {
		return Delegation{}, err
	}
	may := f["may"]
	if may.kind != kArray || len(may.items) == 0 {
		return Delegation{}, Malformed
	}
	for i, item := range may.items {
		if item.kind != kString || (item.str != "approve_within_caps" && item.str != "renew_rules") {
			return Delegation{}, Malformed
		}
		if i > 0 && item.str <= may.items[i-1].str {
			return Delegation{}, Malformed
		}
		d.May = append(d.May, item.str)
	}
	if d.Level, err = f.str("level"); err != nil {
		return Delegation{}, err
	}
	switch d.Level {
	case "auto_within_limits":
	case "ask_me":
		if d.may("approve_within_caps") {
			return Delegation{}, Malformed
		}
	default:
		return Delegation{}, Malformed
	}
	actions, err := f.num("actions_per_day")
	if err != nil || actions < 0 || actions > maxActionsPerDay {
		return Delegation{}, Malformed
	}
	if d.Caps, err = readCaps(f["caps"]); err != nil {
		return Delegation{}, err
	}
	if d.Seq, err = f.num("seq"); err != nil || d.Seq < 0 {
		return Delegation{}, Malformed
	}
	if d.IssuedAt, err = f.date("issued_at"); err != nil {
		return Delegation{}, err
	}
	if d.Expires, err = f.date("expires_at"); err != nil {
		return Delegation{}, err
	}
	if d.Expires <= d.IssuedAt || d.Expires-d.IssuedAt > maxDelegationLife {
		return Delegation{}, Malformed
	}
	if d.Owner != owner.ID {
		return Delegation{}, WrongSigner
	}
	if d.Agent != agent.ID {
		return Delegation{}, ProofMismatch
	}
	if owner.knowsKey(d.Delegate) || agent.knowsKey(d.Delegate) {
		return Delegation{}, Malformed
	}
	return d, nil
}

func readCaps(v Value) (map[string]map[string]int64, error) {
	if v.kind != kObject || len(v.members) > maxCappedTypes {
		return nil, Malformed
	}
	out := map[string]map[string]int64{}
	for i, typ := range v.members {
		if typ.val.kind != kObject || len(typ.val.members) > maxCapsPerType || (i > 0 && v.members[i-1].key >= typ.key) {
			return nil, Malformed
		}
		caps := map[string]int64{}
		for j, c := range typ.val.members {
			if c.val.kind != kNumber || c.val.num < 0 || (j > 0 && typ.val.members[j-1].key >= c.key) {
				return nil, Malformed
			}
			caps[c.key] = c.val.num
		}
		out[typ.key] = caps
	}
	return out, nil
}

// VerifyDelegation checks a delegation arriving now, no older than the newest one seen. Signet holds
// one and takes only a newer one. Whether it counts is for the rules in force, which name it.
func VerifyDelegation(compact string, owner, agent Identity, newestSeen, now int64) (Delegation, error) {
	d, err := readDelegation(compact, owner, agent, false)
	if err != nil {
		return Delegation{}, err
	}
	if d.IssuedAt > now+clockTolerance {
		return Delegation{}, FromTheFuture
	}
	if now >= d.Expires {
		return Delegation{}, Expired
	}
	if d.Seq < newestSeen {
		return Delegation{}, Stale
	}
	return d, nil
}

// readCarriedApproval reads the yes a step carries: the owner's own, or a delegate's joined to its
// delegation. Arriving now, an owner's yes is checked under the keys that count, and one whose owner's
// part the agent's own key signed is refused; read back, it's checked under every key the owner has
// had, as it was signed. It says whether a delegate said it.
func readCarriedApproval(compact string, owner, agent Identity, schema Schema, readBack bool) (Approval, bool, error) {
	if strings.Contains(compact, "~") {
		a, err := readDelegatedApproval(compact, owner, agent, schema, readBack)
		return a, true, err
	}
	if owner.unconfirmedOwner() {
		return Approval{}, false, OwnerUnconfirmed
	}
	keys := owner.Counting
	if readBack {
		keys = owner.everyKey()
	} else if s, err := readSigned(compact, "splint-approval"); err == nil && s.verifiedBy(agent.Key()) {
		return Approval{}, false, ApprovalBadSignature
	}
	a, err := readApproval(compact, keys)
	if err == BadSignature {
		return Approval{}, false, ApprovalBadSignature
	}
	if err != nil {
		return Approval{}, false, ApprovalMismatch
	}
	return a, false, nil
}

// readDelegatedApproval reads a delegate's yes joined to its delegation by "~", which counts only for a
// confirm of a type the delegation caps, whose every value has a cap there and fits it. Read back in a
// chain, its delegation may be under a key the owner has since recovered away from.
func readDelegatedApproval(compact string, owner, agent Identity, schema Schema, readBack bool) (Approval, error) {
	approval, delegation, delegated := strings.Cut(compact, "~")
	// One key, one job: a yes arriving now whose delegation the agent's own key signed as its owner is
	// refused. Read back, it's taken as it was signed.
	if !readBack && delegated {
		if s, err := readSigned(delegation, "splint-delegation"); err == nil && s.verifiedBy(agent.Key()) {
			return Approval{}, ApprovalBadSignature
		}
	}
	if !delegated {
		return Approval{}, ApprovalBadSignature
	}
	if owner.unconfirmedOwner() {
		return Approval{}, OwnerUnconfirmed
	}
	d, err := readDelegation(delegation, owner, agent, readBack)
	if err != nil || !d.may("approve_within_caps") {
		return Approval{}, ApprovalBadSignature
	}
	a, err := readApproval(approval, []Signer{{Point: d.Delegate}})
	if err == BadSignature {
		return Approval{}, ApprovalBadSignature
	}
	if err != nil || !sorted(a.Agreed) || !sorted(a.Result) {
		return Approval{}, ApprovalMismatch
	}
	// Its start is the signer's word, so its end is what keeps a yes backdated into an ended
	// delegation from arriving after it: a step can't be dated past its yes's end.
	if a.Decision != "approve" || a.Operation != "confirm" || a.Owner != d.Owner || a.Agent != d.Agent ||
		a.IssuedAt < d.IssuedAt || a.IssuedAt >= d.Expires || a.ExpiresAt > d.Expires {
		return Approval{}, ApprovalMismatch
	}
	caps, named := d.Caps[a.Type]
	if a.Type != schema.ID || !named || !withinCaps(caps, schema, a.Agreed, a.Result) {
		return Approval{}, OverLimit
	}
	return a, nil
}

// sorted says whether an object's names are in sorted order, as in the one encoding of terms a
// delegate key signs.
func sorted(v Value) bool {
	for i := 1; i < len(v.members); i++ {
		if v.members[i].key <= v.members[i-1].key {
			return false
		}
	}
	return true
}

// withinCaps says whether every value in agreed and result has a cap, in its unit, and fits it. A
// value with a unit is capped as "value.word", the word being the unit's in the agreed offer.
func withinCaps(caps map[string]int64, schema Schema, agreed, result Value) bool {
	unitWord := func(unit string) (string, bool) {
		for _, m := range agreed.members {
			if m.key == unit && m.val.kind == kString {
				return m.val.str, true
			}
		}
		return "", false
	}
	for _, fieldsOf := range []Value{agreed, result} {
		for _, m := range fieldsOf.members {
			if !contains(schema.Values, m.key) || m.val.kind != kNumber {
				continue
			}
			name := m.key
			if unit, has := schema.Units[m.key]; has {
				word, found := unitWord(unit)
				if !found {
					return false
				}
				name = m.key + "." + word
			}
			limit, capped := caps[name]
			if !capped || m.val.num > limit {
				return false
			}
		}
	}
	return true
}

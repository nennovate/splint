package verifier

import (
	"bytes"
	"encoding/json"
	"strings"
)

const (
	maxEvents       = 48
	maxHistoryBytes = 180 * 1024
)

// History is an agent's identity, the newest copy of every owner it has had, and its events.
type History struct {
	Identity string   `json:"identity"`
	Owners   []string `json:"owners"`
	Events   []string `json:"events"`
}

// ParseHistory reads a history as carried, refusing any field it doesn't know.
func ParseHistory(raw []byte) (History, error) {
	var h History
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > maxHistoryBytes || d.Decode(&h) != nil || d.More() || h.Identity == "" {
		return History{}, Malformed
	}
	return h, nil
}

// Change is one event read, in a reader's words.
type Change struct {
	Hash  string // of the event's signing input, which the next one names
	Kind  string // the reader's word: bound, owner, key, signet, host, revocation, declared
	Proof string // signed, unproven or unverified
	// ConfirmsStandIn is part of the one move from the stand-in an agent joined under to its owner,
	// the first time they set up controls, which a reader carries on through.
	ConfirmsStandIn bool
	// Whose is whose key a key event replaced, agent or owner, and empty for any other kind.
	Whose string
	// Owner is who the event names, and Rebinds says the same owner bound the agent again here: a move
	// of host, or a return from revocation.
	Owner   string
	Rebinds bool
}

// Standing is what a whole history says now.
type Standing struct {
	Changes []Change
	Owner   string
	Address string
	// Revoked says its owner released it to nobody and hasn't signed it back in.
	Revoked bool
	// Owners is the copy of every owner the history carries, by ID.
	Owners map[string]Identity
}

// Head is the hash the newest event, which an owner's yes names.
func (s Standing) Head() string { return s.Changes[len(s.Changes)-1].Hash }

// VerifyHistory checks a history on its own, from where an owner bound the agent.
func VerifyHistory(h History) (Standing, error) {
	agent, err := ReadIdentity(h.Identity)
	if err != nil {
		return Standing{}, err
	}
	owners := map[string]Identity{}
	for _, encoded := range h.Owners {
		o, err := ReadIdentity(encoded)
		if err != nil {
			return Standing{}, err
		}
		owners[o.ID] = o
	}
	if len(h.Events) == 0 || len(h.Events) > maxEvents {
		return Standing{}, Malformed
	}
	w := historyWalk{agent: agent, owners: owners, prev: strings.TrimPrefix(agent.ID, "splint1")}
	for i, compact := range h.Events {
		if err := w.step(i, compact); err != nil {
			return Standing{}, err
		}
	}
	return Standing{Changes: w.changes, Owner: w.owner, Address: w.address, Revoked: w.revoked, Owners: owners}, nil
}

type historyWalk struct {
	agent           Identity
	owners          map[string]Identity
	prev            string
	agentRecoveries int64
	owner           string
	ownerRecoveries map[string]int64
	address         string
	revoked         bool
	bindingSeq      int64
	changes         []Change
	ownerMoved      bool
	keptAgentKeys   bool // the last event moved only the agent's recovery rule
}

var changeShapes = map[string][]string{
	"bound":      {"kind", "binding"},
	"owner":      {"kind", "binding", "previous_owner_recoveries"},
	"host":       {"kind", "binding"},
	"reinstated": {"kind", "binding"},
	"key":        {"kind", "whose", "head"},
	"signet":     {"kind", "statement"},
	"declared":   {"kind", "statement"},
	"revoked":    {"kind", "release"},
}

func (w *historyWalk) step(i int, compact string) error {
	s, err := readSigned(compact, "splint-change")
	if err != nil {
		return err
	}
	if s.Body, err = parsePayload(s.Payload); err != nil {
		return err
	}
	f, err := shape(s.Body, []string{"v", "id", "seq", "prev", "agent_recoveries", "owner", "owner_recoveries", "issued_at", "change"})
	if err != nil || f.version(1) != nil {
		return Malformed
	}
	id, err := f.id("id")
	if err != nil {
		return err
	}
	seq, err := f.num("seq")
	if err != nil {
		return err
	}
	prev, err := f.hash("prev")
	if err != nil {
		return err
	}
	agentRecoveries, err := f.num("agent_recoveries")
	if err != nil {
		return err
	}
	ownerID, err := f.id("owner")
	if err != nil {
		return err
	}
	ownerRecoveries, err := f.num("owner_recoveries")
	if err != nil {
		return err
	}
	if _, err := f.date("issued_at"); err != nil {
		return err
	}
	kind, _ := f["change"].firstString()
	want, known := changeShapes[kind]
	if !known {
		return Malformed
	}
	change, err := shape(f["change"], want)
	if err != nil {
		return err
	}
	if id != w.agent.ID || seq != int64(i+1) || prev != w.prev || (kind == "bound") != (i == 0) {
		return ProofMismatch
	}
	if agentRecoveries < 0 || agentRecoveries >= int64(len(w.agent.Keys)) {
		return ProofMismatch
	}
	if !s.verifiedBy(w.agent.Keys[agentRecoveries]) {
		return BadSignature
	}
	// Only a key event moves a count on, so anything else has to carry the count as it stands.
	if kind != "key" && (agentRecoveries != w.agentRecoveries || (w.owner == ownerID && ownerRecoveries != w.ownerRecoveries[ownerID])) {
		return ProofMismatch
	}
	owner, carried := w.owners[ownerID]
	if !carried || ownerRecoveries < 0 || ownerRecoveries >= int64(len(owner.Keys)) {
		return ProofMismatch
	}
	if w.ownerRecoveries == nil {
		w.ownerRecoveries = map[string]int64{}
	}
	// Read back under every key that counted between that recovery and the next.
	ownerKeys := owner.epochKeys(ownerRecoveries)
	agentKey := w.agent.Keys[agentRecoveries]
	proof := "signed"
	word := kind
	whoseKey := ""
	keptBefore := w.keptAgentKeys
	w.keptAgentKeys = false
	confirms := false
	switch kind {
	case "bound", "host", "reinstated":
		if kind != "bound" && ownerID != w.owner {
			return ProofMismatch
		}
		if kind == "reinstated" && !w.revoked {
			return ProofMismatch
		}
		b, err := w.binding(change, owner, ownerKeys, agentKey)
		if err != nil {
			return err
		}
		if kind == "host" && domainOf(b.Address) == domainOf(w.address) {
			return ProofMismatch
		}
		if kind == "reinstated" {
			word = "revocation"
			w.revoked = false
		}
		w.address = b.Address
	case "owner":
		if ownerID == w.owner {
			return ProofMismatch
		}
		previous, ok := w.owners[w.owner]
		confirms = ok && !w.ownerMoved && previous.unconfirmedOwner()
		w.ownerMoved = true
		before, err := change.num("previous_owner_recoveries")
		if err != nil {
			return err
		}
		if !ok || before < 0 || before >= int64(len(previous.Keys)) {
			return ProofMismatch
		}
		held := w.bindingSeq
		b, err := w.binding(change, owner, ownerKeys, agentKey)
		if err != nil {
			return err
		}
		if b.Release == nil {
			return WrongSigner
		}
		parts := strings.Split(mustStr(change, "binding"), "~")
		r, err := VerifyRelease(parts[3], previous, previous.epochKeys(before), w.agent.ID)
		if err != nil {
			return err
		}
		if r.To != ownerID {
			return WrongSigner
		}
		if r.Seq < held || r.Seq >= b.Seq {
			return Stale
		}
		// Only the owner part of the name follows a new owner: same handle, same host.
		if domainOf(b.Address) != domainOf(w.address) || agentOf(b.Address) != agentOf(w.address) {
			return ProofMismatch
		}
		w.address = b.Address
	case "key":
		whose, _ := change.str("whose")
		whoseKey = whose
		head, err := change.hash("head")
		if err != nil {
			return err
		}
		var replaced Identity
		var count *int64
		switch whose {
		case "agent":
			replaced, count = w.agent, &w.agentRecoveries
			if agentRecoveries != w.agentRecoveries+1 || ownerRecoveries != w.ownerRecoveries[ownerID] {
				return ProofMismatch
			}
		case "owner":
			current := w.ownerRecoveries[ownerID]
			replaced, count = owner, &current
			if ownerRecoveries != current+1 || agentRecoveries != w.agentRecoveries {
				return ProofMismatch
			}
		default:
			return Malformed
		}
		next := *count + 1
		if next > int64(replaced.Recoveries()) || hashHex([]byte(replaced.recoveryInputs()[next-1])) != head {
			return ProofMismatch
		}
		if whose == "agent" {
			w.agentRecoveries = next
			w.keptAgentKeys = int(next) < len(w.agent.Keys) && int(next) < len(w.agent.Seals) &&
				bytes.Equal(w.agent.Keys[next].Point, w.agent.Keys[next-1].Point) &&
				w.agent.Keys[next].RP == w.agent.Keys[next-1].RP &&
				bytes.Equal(w.agent.Seals[next], w.agent.Seals[next-1])
		}
	case "signet", "declared":
		if err := w.statement(change, kind, owner, ownerKeys); err != nil {
			return err
		}
		proof = map[string]string{"signet": "unproven", "declared": "unverified"}[kind]
	case "revoked":
		release, _ := change.str("release")
		r, err := VerifyRelease(release, owner, ownerKeys, w.agent.ID)
		if err != nil {
			return err
		}
		if r.To != "" || ownerID != w.owner {
			return ProofMismatch
		}
		w.revoked = true
		word = "revocation"
	}
	w.owner = ownerID
	w.ownerRecoveries[ownerID] = ownerRecoveries
	w.prev = s.InputHash()
	// The recovery a stand-in's move carries keeps the agent's keys, and is part of the same move.
	if confirms && keptBefore && len(w.changes) > 0 && w.changes[len(w.changes)-1].Kind == "key" {
		w.changes[len(w.changes)-1].ConfirmsStandIn = true
	}
	rebinds := kind == "host" || kind == "reinstated"
	w.changes = append(w.changes, Change{Hash: w.prev, Kind: word, Proof: proof, ConfirmsStandIn: confirms, Whose: whoseKey, Owner: ownerID, Rebinds: rebinds})
	return nil
}

func (w *historyWalk) binding(change fields, owner Identity, ownerKeys []Signer, agentKey Signer) (Binding, error) {
	compact, err := change.str("binding")
	if err != nil {
		return Binding{}, err
	}
	b, err := VerifyBinding(compact, owner, ownerKeys, w.agent, agentKey, false)
	if err != nil {
		return Binding{}, err
	}
	w.bindingSeq = b.Seq
	return b, nil
}

// statement checks the owner's word on a change Splint can't see.
func (w *historyWalk) statement(change fields, kind string, owner Identity, ownerKeys []Signer) error {
	compact, err := change.str("statement")
	if err != nil {
		return err
	}
	s, err := openAs(compact, "splint-change-statement", ownerKeys)
	if err != nil {
		return err
	}
	f, err := shape(s.Body, []string{"v", "owner", "agent", "prev", "claim", "issued_at"})
	if err != nil || f.version(1) != nil {
		return Malformed
	}
	if _, err := f.date("issued_at"); err != nil {
		return err
	}
	var claim fields
	switch kind {
	case "signet":
		claim, err = shape(f["claim"], []string{"kind", "location", "protection"})
		if err == nil {
			p, _ := claim.str("protection")
			if _, lerr := claim.str("location"); lerr != nil || (p != "software_file" && p != "hardware") {
				err = Malformed
			}
		}
	case "declared":
		claim, err = shape(f["claim"], []string{"kind", "what"})
		if err == nil {
			if what, _ := claim.str("what"); !isDeclaration(what) {
				err = Malformed
			}
		}
	}
	claimKind, _ := f["claim"].firstString()
	if err != nil && claimKind == kind {
		return err
	}
	o, _ := f.str("owner")
	a, _ := f.str("agent")
	p, _ := f.str("prev")
	if claimKind != kind || o != owner.ID || a != w.agent.ID || p != w.prev {
		return ProofMismatch
	}
	return nil
}

func (v Value) firstString() (string, bool) {
	if v.kind == kObject && len(v.members) > 0 && v.members[0].val.kind == kString {
		return v.members[0].val.str, true
	}
	return "", false
}

func isDeclaration(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func mustStr(f fields, k string) string {
	s, _ := f.str(k)
	return s
}

// agentOf is the agent's handle in an address, without any owner part.
func agentOf(address string) string {
	name, _, _ := strings.Cut(address, "~")
	agent, _, _ := strings.Cut(name, ".")
	return agent
}

func domainOf(address string) string {
	_, domain, _ := strings.Cut(address, "~")
	return domain
}

// Against says how a history a reader hears compares with the one it holds:
// same, extends, behind or rewrites.
func Against(seen, heard History) (string, error) {
	a, err := VerifyHistory(seen)
	if err != nil {
		return "", err
	}
	b, err := VerifyHistory(heard)
	if err != nil {
		return "", err
	}
	seenID, _ := ReadIdentity(seen.Identity)
	heardID, _ := ReadIdentity(heard.Identity)
	if _, err := Newest(seenID, heardID); err != nil {
		return "rewrites", nil
	}
	shorter, longer := a.Changes, b.Changes
	if len(longer) < len(shorter) {
		shorter, longer = longer, shorter
	}
	for i := range shorter {
		if shorter[i].Hash != longer[i].Hash {
			return "rewrites", nil
		}
	}
	switch {
	case len(a.Changes) == len(b.Changes):
		return "same", nil
	case len(b.Changes) > len(a.Changes):
		return "extends", nil
	}
	return "behind", nil
}

// DefaultAnswers are what a reader's rules say with nothing set.
var DefaultAnswers = map[string]string{"owner": "ask", "key": "ask", "signet": "continue", "host": "continue",
	"revocation": "continue", "declared": "continue"}

var strictness = map[string]int{"continue": 0, "ask": 1, "hold": 2}

// Respond is what a reader's rules say about everything since the head its owner accepted:
// stopped while its owner has it revoked, whatever the rules say, rewritten if that head isn't in
// this history, and otherwise the strictest answer.
func Respond(h History, accepted string, answers map[string]string) (string, error) {
	return RespondAt(h, accepted, answers, nil, false, 0)
}

// newSignInSeconds is how long a sign-in stays new to a reader after it first saw it.
const newSignInSeconds = 48 * 3600

// RespondAt is Respond for a reader that keeps when it first saw each owner's sign-ins since their
// newest recovery, by name, and takes the history at now: a move of host or a return from revocation
// while one of that owner's sign-ins is less than 48 hours new to it is answered as a new owner is.
// A sign-in in the history it hadn't seen before is first seen now. With guard false, it isn't.
func RespondAt(h History, accepted string, answers map[string]string, seen map[string]int64, guard bool, now int64) (string, error) {
	s, err := VerifyHistory(h)
	if err != nil {
		return "", err
	}
	if s.Revoked {
		return "stopped", nil
	}
	at := -1
	for i, c := range s.Changes {
		if c.Hash == accepted {
			at = i
		}
	}
	if at < 0 {
		return "rewritten", nil
	}
	out := "continue"
	for _, c := range s.Changes[at+1:] {
		answer := answerFor(answers, c.Kind)
		// An owner who recovered is still that owner, so a replaced owner key is answered as `key` says,
		// except that a hold signed for new owners stays a hold.
		if c.Kind == "key" && c.Whose == "owner" && answerFor(answers, "owner") == "hold" {
			answer = "hold"
		}
		// At owner level: the stricter of what the rules say for its own kind and for a new owner. A
		// move of host or a return from revocation while one of that owner's sign-ins is less than 48
		// hours new to this reader may be the work of a stolen one.
		if owner, carried := s.Owners[c.Owner]; guard && c.Rebinds && carried && hasNewSignIn(owner, seen, now) {
			asOwner := answerFor(answers, "owner")
			if _, known := strictness[asOwner]; !known {
				return "", Malformed
			}
			if _, known := strictness[answer]; known && strictness[asOwner] > strictness[answer] {
				answer = asOwner
			}
		}
		// A stand-in's move to the agent's first owner needs no question, but a hold its reader's owner
		// signed stays.
		if c.ConfirmsStandIn && answer == "ask" {
			answer = "continue"
		}
		if _, known := strictness[answer]; !known {
			return "", Malformed
		}
		if strictness[answer] > strictness[out] {
			out = answer
		}
	}
	return out, nil
}

func answerFor(answers map[string]string, kind string) string {
	if answer, ok := answers[kind]; ok {
		return answer
	}
	return DefaultAnswers[kind]
}

// hasNewSignIn says whether any of the owner's sign-ins since its newest recovery was first seen less
// than 48 hours before now, one the reader never saw counting as seen now.
func hasNewSignIn(owner Identity, seen map[string]int64, now int64) bool {
	last := int64(len(owner.Keys) - 1)
	for _, key := range owner.epochKeys(last) {
		at, ok := seen[hashHex(key.Point)]
		if !ok || now < at+newSignInSeconds {
			return true
		}
	}
	return false
}

// Acceptance is an owner's yes to a contact's history, as far as one head.
type Acceptance struct {
	Contact, Head string
	Seq           int64
}

// VerifyAcceptance checks an owner's yes, for their agent.
func VerifyAcceptance(compact string, owner Identity, agent string) (Acceptance, error) {
	s, err := openAs(compact, "splint-change-accept", owner.Counting)
	if err != nil {
		return Acceptance{}, err
	}
	f, err := shape(s.Body, []string{"v", "owner", "agent", "contact", "head", "seq", "issued_at"})
	if err != nil || f.version(1) != nil {
		return Acceptance{}, Malformed
	}
	a := Acceptance{}
	if a.Contact, err = f.id("contact"); err != nil {
		return Acceptance{}, err
	}
	if a.Head, err = f.hash("head"); err != nil {
		return Acceptance{}, err
	}
	if a.Seq, err = f.num("seq"); err != nil {
		return Acceptance{}, err
	}
	if _, err := f.date("issued_at"); err != nil {
		return Acceptance{}, err
	}
	if o, _ := f.str("owner"); o != owner.ID {
		return Acceptance{}, ProofMismatch
	}
	if g, _ := f.str("agent"); g != agent {
		return Acceptance{}, ProofMismatch
	}
	return a, nil
}

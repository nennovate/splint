package verifier

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	OutOfTurn            Refusal = "out_of_turn"
	OutsideWindow        Refusal = "outside_window"
	AfterDeadline        Refusal = "after_deadline"
	UnknownPrev          Refusal = "unknown_prev"
	UnknownType          Refusal = "unknown_type"
	WrongRequest         Refusal = "wrong_request"
	WrongParty           Refusal = "wrong_party"
	Replay               Refusal = "replay"
	NotOffered           Refusal = "not_offered"
	NoOffersLeft         Refusal = "no_offers_left"
	NoMovesLeft          Refusal = "no_moves_left"
	TooManySteps         Refusal = "too_many_steps"
	ApprovalMissing      Refusal = "approval_missing"
	ApprovalMismatch     Refusal = "approval_mismatch"
	ApprovalBadSignature Refusal = "approval_bad_signature"
	ApprovalExpired      Refusal = "approval_expired"
	BadPersonText        Refusal = "bad_person_text"
)

const (
	maxOffers     = 3
	maxProgress   = 8
	maxPauses     = 3
	maxSays       = 160
	maxForward    = 192
	copiesOfAYes  = 2 // copies of one owner's yes a reader keeps: two show a key used outside Signet
	pauseReasons  = "needs_information needs_approval other"
	alwaysReasons = "not_understood no_reason"
)

// refusedAt is a chain refused at one step, counting from 0.
type refusedAt struct {
	at     int
	reason Refusal
}

func (r refusedAt) Error() string { return string(r.reason) }

// Side is one party to an interaction: its agent and owner, with every key either has had.
type Side struct {
	Agent, Owner Identity
}

// Walked is what a reader holds once a chain is walked.
type Walked struct {
	State         string
	Version       *int64
	Head          *string
	OverCap       int
	CopiesDropped int
	Payment       string // requested or received, while completed, apart from State
}

// step is one held step, read and placed.
type step struct {
	env      Envelope
	by       int // 0 requester, 1 recipient
	kind     string
	body     fields
	prev     string
	approval *Approval
	node     node
}

// node is how things stand at a step, along the line that leads to it.
type node struct {
	state     string
	version   int64
	offer     Value // the latest offer, lists included
	offerer   int
	pick      Value
	result    Value
	offers    [2]int
	progress  int
	pauses    int
	says      [2]int
	lastSay   [2]string
	confirmed *Approval // R's approval, which T's must match
	final     bool      // completed by an owner's signature
	depth     int
}

// Reader walks one interaction's steps, as a reader that holds them.
type Reader struct {
	sides     [2]Side
	schemas   map[string]Schema
	schema    Schema
	proposed  *Schema // what a type/1 proposes
	steps     map[string]*step
	order     []*step
	open      *step
	deadline  int64
	nonceHash string
	forward   map[int]int
	overCap   int
	received  map[string]bool
	seen      map[string]bool
	carried   map[string]int   // copies held of each owner's yes, by step kind and payload hash
	dropped   int              // copies of a yes past copiesOfAYes
	asks      []ask            // asks to be paid, held apart from the line
	arrived   *paymentReceived // the payee's word that it arrived
}

// WalkChain reads a chain as held. lastArrivedAt, if not zero, is the reader's clock when
// the last step first arrived; the steps before it count as already received.
func WalkChain(requester, recipient Side, schemas map[string]Schema, chain []string, now, lastArrivedAt int64) (Walked, error) {
	r := &Reader{sides: [2]Side{requester, recipient}, schemas: schemas, steps: map[string]*step{},
		forward: map[int]int{}, received: map[string]bool{}, seen: map[string]bool{}, carried: map[string]int{}}
	for i, compact := range chain {
		arrived := int64(0)
		if i == len(chain)-1 {
			arrived = lastArrivedAt
		}
		if err := r.take(compact, arrived); err != nil {
			if err == TooManySteps {
				r.overCap++
				continue
			}
			return Walked{}, refusedAt{i, err.(Refusal)}
		}
	}
	return r.settle(now), nil
}

func (r *Reader) take(compact string, arrived int64) error {
	s, err := readSigned(compact, "splint-envelope")
	if err != nil {
		return err
	}
	body, err := parsePayload(s.Payload)
	if err != nil {
		return err
	}
	by, other := -1, -1
	for _, m := range body.members {
		if m.key == "sender" && m.val.kind == kString {
			for i, side := range r.sides {
				if side.Agent.ID == m.val.str {
					by, other = i, 1-i
				}
			}
		}
	}
	if by < 0 {
		return WrongParty
	}
	env, err := readEnvelope(compact, r.sides[by].Agent.Keys, r.sides[by].Agent.ID)
	if err != nil {
		return err
	}
	if env.Recipient != r.sides[other].Agent.ID {
		return WrongParty
	}
	if arrived != 0 {
		if err := env.checkClock(arrived); err != nil {
			return err
		}
	}
	if r.seen[env.ID()] {
		return Replay
	}
	st, err := readStep(env.Body)
	if err != nil {
		return err
	}
	st.env, st.by = env, by
	if err := r.place(st); err == errCopyDropped {
		r.dropped++
		return nil
	} else if err != nil {
		return err
	}
	r.seen[env.ID()] = true
	if st.approval != nil {
		r.carried[carriedKey(st)]++
	}
	if st.kind == "received" || isPaymentStep(st.kind) {
		return nil
	}
	r.steps[env.ID()] = st
	r.order = append(r.order, st)
	return nil
}

var stepShapes = map[string][2][]string{
	"open":             {{"step", "type", "schema", "terms", "deadline"}, {"supersedes", "approval", "person_text"}},
	"counter":          {{"step", "request", "prev", "terms"}, {"approval", "person_text"}},
	"clarify":          {{"step", "request", "prev", "reason"}, {"note", "person_text"}},
	"accept":           {{"step", "request", "prev", "pick"}, {"approval"}},
	"progress":         {{"step", "request", "prev", "status"}, nil},
	"pause":            {{"step", "request", "prev", "reason"}, nil},
	"resume":           {{"step", "request", "prev"}, nil},
	"deliver":          {{"step", "request", "prev", "result"}, {"approval"}},
	"confirm":          {{"step", "request", "prev", "approval"}, nil},
	"decline":          {{"step", "request", "prev", "reason"}, {"person_text"}},
	"say":              {{"step", "request", "prev", "fields"}, {"seen", "person_text"}},
	"cancel":           {{"step", "request", "prev"}, {"approval"}},
	"received":         {{"step", "request", "of"}, nil},
	"pay_request":      {{"step", "request", "of", "for", "amount", "unit", "reference", "entry", "where_paid"}, nil},
	"payment_received": {{"step", "request", "of"}, nil},
}

func isPaymentStep(kind string) bool { return kind == "pay_request" || kind == "payment_received" }

// readStep reads a step's general shape from an envelope's body. A field a type leaves out
// is checked once the type is known.
func readStep(text string) (*step, error) {
	v, err := parsePayload([]byte(text))
	if err != nil {
		return nil, err
	}
	kind, _ := v.firstString()
	want, known := stepShapes[kind]
	if !known {
		return nil, Malformed
	}
	required := want[0]
	// A type with no offer leaves out terms, and one with no pick leaves out pick. Core's plain
	// conversation leaves out type, and anything but a type/1 leaves out schema.
	leftOut := map[string]bool{}
	for _, k := range []string{"type", "schema", "terms"} {
		if kind == "open" && !hasMember(v, k) {
			leftOut[k] = true
		}
	}
	if kind == "accept" && !hasMember(v, "pick") {
		leftOut["pick"] = true
	}
	if len(leftOut) > 0 {
		trimmed := []string{}
		for _, k := range required {
			if !leftOut[k] {
				trimmed = append(trimmed, k)
			}
		}
		required = trimmed
	}
	f, err := shape(v, required, want[1]...)
	if err != nil {
		return nil, err
	}
	st := &step{kind: kind, body: f}
	for _, k := range []string{"request", "prev", "of", "seen", "supersedes"} {
		if f.has(k) {
			if _, err := f.hash(k); err != nil {
				return nil, err
			}
		}
	}
	for _, k := range []string{"approval", "person_text", "type", "reason", "status", "note"} {
		if f.has(k) {
			if _, err := f.str(k); err != nil {
				return nil, err
			}
		}
	}
	if kind == "pay_request" {
		if err := checkPayRequestShape(f); err != nil {
			return nil, err
		}
	}
	st.prev, _ = f.str("prev")
	return st, nil
}

func hasMember(v Value, k string) bool {
	for _, m := range v.members {
		if m.key == k {
			return true
		}
	}
	return false
}

// place checks a step against the position its prev names.
func (r *Reader) place(st *step) error {
	if st.kind == "open" {
		return r.placeOpen(st)
	}
	if r.open == nil {
		return UnknownPrev
	}
	if req, _ := st.body.str("request"); req != r.open.env.ID() {
		return WrongRequest
	}
	if st.env.Nonce != "" {
		return Malformed
	}
	if st.kind == "received" {
		of, _ := st.body.str("of")
		named, held := r.steps[of]
		if !held {
			return nil // dropped
		}
		if named.by == st.by {
			return OutOfTurn
		}
		key := of + string(rune('0'+st.by))
		if r.received[key] {
			return nil
		}
		r.received[key] = true
		return nil
	}
	if isPaymentStep(st.kind) {
		return r.placePayment(st)
	}
	prev, held := r.steps[st.prev]
	if !held {
		return UnknownPrev
	}
	if err := r.checkDates(st); err != nil {
		return err
	}
	if err := r.checkPersonText(st); err != nil {
		return err
	}
	n, err := r.move(prev, st)
	if err != nil {
		return err
	}
	n.depth = prev.node.depth + 1
	st.node = n
	if err := r.checkApproval(st, prev, n); err != nil {
		return err
	}
	// Words added, or a fresh sealing, give a copy of a step a new ID. Past two, a copy of one
	// owner's yes says nothing more, and which ones are held doesn't change the state.
	if st.approval != nil && r.carried[carriedKey(st)] >= copiesOfAYes {
		return errCopyDropped
	}
	if st.approval == nil && st.kind != "cancel" && r.isForward(st.kind) {
		r.forward[st.by]++
		if r.forward[st.by] > maxForward {
			return TooManySteps
		}
	}
	return nil
}

// errCopyDropped is a copy of a yes the reader drops, which isn't a refusal.
var errCopyDropped = errors.New("copy dropped")

// carriedKey names the yes a step carries by the payload its owner signed, which every copy shares.
// A link's open and its confirm carry the same one, so the kind counts too.
func carriedKey(st *step) string { return st.kind + " " + st.approval.ID() }

func (r *Reader) isForward(kind string) bool {
	return kind != "confirm" && kind != "received" && kind != "open"
}

func (r *Reader) placeOpen(st *step) error {
	if st.by != 0 {
		return OutOfTurn
	}
	if r.open != nil {
		return Malformed
	}
	schema, err := r.schemaOfOpen(st)
	if err != nil {
		return err
	}
	nonce, err := b64(st.env.Nonce)
	if err != nil || len(nonce) != 16 {
		return Malformed
	}
	deadline, err := st.body.date("deadline")
	if err != nil || deadline%3600 != 0 {
		return Malformed
	}
	if _, err := st.body.hash("supersedes"); st.body.has("supersedes") && err != nil {
		return err
	}
	// A type with no offer, a conversation or a type/1 among them, leaves out terms, and any other has them.
	if (len(schema.Offer) == 0) == st.body.has("terms") {
		return Malformed
	}
	if st.body.has("terms") {
		if err := fieldsFit(st.body["terms"], schema.Offer, keys(schema.Offer), st.env.CreatedAt); err != nil {
			return err
		}
	}
	if deadline <= st.env.CreatedAt || deadline > st.env.CreatedAt+twoWeeks {
		return OutsideWindow
	}
	r.schema, r.deadline = schema, deadline
	// The nonce as written, which is what an owner's device was shown.
	r.nonceHash = hashHex([]byte(st.env.Nonce))
	if err := r.checkDates(st); err != nil {
		return err
	}
	if err := r.checkPersonText(st); err != nil {
		return err
	}
	n := node{version: 1, offerer: 0, offer: st.body["terms"], offers: [2]int{1, 0}}
	n.state = "offered"
	if schema.conversation() {
		n.state = "talking"
	}
	st.node = n
	r.open = st
	if err := r.checkApproval(st, nil, n); err != nil {
		r.open = nil
		return err
	}
	return nil
}

// schemaOfOpen is the type an open starts: core's plain conversation, which names none, core's type/1,
// whose schema rides on it in its one encoding within core's limits, or an agreed type by its ID.
func (r *Reader) schemaOfOpen(st *step) (Schema, error) {
	proposed, carries := st.body["schema"]
	if !st.body.has("type") {
		if carries {
			return Schema{}, Malformed
		}
		return conversationSchema, nil
	}
	typ, _ := st.body.str("type")
	if typ == proposalType {
		if !carries || st.body.has("terms") {
			return Schema{}, Malformed
		}
		raw := proposed.Encoded()
		s, err := ParseSchema(raw)
		if err != nil {
			return Schema{}, Malformed
		}
		if !bytes.Equal(raw, s.encoding) || s.checkProposal() != nil {
			return Schema{}, Malformed
		}
		r.proposed = &s
		return proposalSchema, nil
	}
	if carries || !isTypeID(typ) {
		return Schema{}, Malformed
	}
	schema, known := r.schemas[typ]
	if !known {
		return Schema{}, UnknownType
	}
	return schema, nil
}

// checkDates holds a step to its deadline and the expiry the protocol gives it.
func (r *Reader) checkDates(st *step) error {
	if st.kind == "cancel" && st.body.has("approval") {
		return nil
	}
	if st.env.CreatedAt > r.deadline {
		return AfterDeadline
	}
	if st.body.has("approval") {
		return nil // an approval's own dates are compared with it
	}
	want := max(r.deadline, st.env.CreatedAt+3600)
	if st.env.ExpiresAt != want {
		return Malformed
	}
	return nil
}

func (r *Reader) checkPersonText(st *step) error {
	compact, has := st.body["person_text"]
	if !has {
		return nil
	}
	side := r.sides[st.by]
	s, err := openUnder(compact.str, "splint-person-text", side.Owner.everyKey())
	if err != nil {
		if err == Malformed {
			return Malformed
		}
		return BadPersonText
	}
	f, err := shape(s.Body, []string{"v", "owner", "agent", "to", "request", "text", "issued_at"})
	if err != nil || f.version(1) != nil {
		return BadPersonText
	}
	text, _ := f.str("text")
	o, _ := f.str("owner")
	a, _ := f.str("agent")
	to, _ := f.str("to")
	req, named, _ := f.optStr("request")
	wantReq := ""
	if r.open != nil && st.kind != "open" {
		wantReq = r.open.env.ID()
	}
	n := utf8.RuneCountInString(text)
	if n < 1 || n > 280 || hidesText(text) || o != side.Owner.ID || a != side.Agent.ID ||
		to != r.sides[1-st.by].Agent.ID || req != wantReq || named != (wantReq != "") {
		return BadPersonText
	}
	return nil
}

func (r *Reader) words(list []string, extra string, word string) bool {
	return contains(list, word) || contains(strings.Fields(extra), word)
}

// move applies the state table from the position prev names.
func (r *Reader) move(prev *step, st *step) (node, error) {
	n := prev.node
	at := prev.node
	mover := st.by
	s := r.schema
	if s.conversation() && st.kind != "say" && st.kind != "cancel" {
		return n, OutOfTurn
	}
	switch st.kind {
	case "say":
		if !s.conversation() {
			return n, Malformed
		}
		if err := fieldsFit(st.body["fields"], s.Say, keys(s.Say), st.env.CreatedAt); err != nil {
			return n, err
		}
		own := at.lastSay[mover]
		if own == "" {
			own = r.open.env.ID()
		}
		if prev.env.ID() != own && !(prev.kind == "say" && prev.by == mover) {
			return n, OutOfTurn
		}
		if prev.kind == "say" && prev.by != mover {
			return n, OutOfTurn
		}
		if seen, has := st.body["seen"]; has {
			other, held := r.steps[seen.str]
			if !held {
				return n, UnknownPrev
			}
			if other.kind != "say" || other.by == mover {
				return n, OutOfTurn
			}
		}
		if n.says[mover] >= maxSays {
			return n, NoMovesLeft
		}
		n.says[mover]++
		n.lastSay[mover] = st.env.ID()
		return n, nil
	case "cancel":
		if st.body.has("approval") {
			if at.state != "completed" {
				return n, Malformed
			}
			n.state = "cancelled"
			return n, nil
		}
		if prev != r.open {
			if at.state == "completed" {
				return n, ApprovalMissing
			}
			return n, Malformed
		}
		n.state = "cancelled"
		return n, nil
	}
	state := at.state
	offerer := mover == at.offerer
	switch {
	case st.kind == "accept" && state == "offered" && !offerer && s.agreement:
		// A type/1 is taken as it is, which agrees it, with nobody to sign.
		if st.body.has("pick") {
			return n, Malformed
		}
		n.state = "completed"
	case (st.kind == "counter" || st.kind == "clarify") && s.agreement:
		return n, OutOfTurn
	case st.kind == "accept" && state == "offered" && !offerer:
		if s.Pick == nil == st.body.has("pick") {
			return n, Malformed
		}
		if st.body.has("pick") {
			if err := r.checkPick(st.body["pick"], at.offer); err != nil {
				return n, err
			}
			n.pick = st.body["pick"]
		}
		n.state = "accepted"
		if s.hasWork() {
			n.state = "working"
		}
	case st.kind == "counter" && (state == "offered" && !offerer || state == "clarifying" && offerer ||
		(state == "accepted" || state == "delivered") && mover == 0 || state == "requester_confirmed" && mover == 1):
		if err := r.checkCounter(st.body["terms"], at.offer, st.env.CreatedAt); err != nil {
			return n, err
		}
		if at.offers[mover] >= maxOffers {
			return n, NoOffersLeft
		}
		n.offers[mover]++
		n.offer = mergeOffer(at.offer, st.body["terms"])
		n.offerer, n.version, n.state = mover, at.version+1, "offered"
		n.pick, n.result, n.confirmed = Value{}, Value{}, nil
	case st.kind == "clarify" && (state == "offered" && !offerer || state == "working" && mover == 1):
		if reason, _ := st.body.str("reason"); !r.words(s.Clarify, alwaysReasons, reason) {
			return n, Malformed
		}
		if st.body.has("note") {
			return n, Malformed
		}
		if state == "working" {
			n.offerer = 0
		}
		n.state = "clarifying"
	case st.kind == "decline" && (state == "offered" && !offerer || state == "clarifying" && offerer ||
		(state == "working" || state == "paused") && mover == 1 ||
		(state == "accepted" || state == "delivered") && mover == 0 || state == "requester_confirmed" && mover == 1):
		if reason, _ := st.body.str("reason"); !r.words(s.Decline, alwaysReasons, reason) {
			return n, Malformed
		}
		n.state = "declined"
	case st.kind == "progress" && state == "working" && mover == 1:
		if status, _ := st.body.str("status"); !contains(s.Progress, status) {
			return n, Malformed
		}
		if at.progress >= maxProgress {
			return n, NoMovesLeft
		}
		n.progress++
	case st.kind == "pause" && state == "working" && mover == 1:
		if reason, _ := st.body.str("reason"); !contains(strings.Fields(pauseReasons), reason) {
			return n, Malformed
		}
		if at.pauses >= maxPauses {
			return n, NoMovesLeft
		}
		n.pauses++
		n.state = "paused"
	case st.kind == "resume" && state == "paused" && mover == 1:
		n.state = "working"
	case st.kind == "deliver" && state == "working" && mover == 1:
		if err := fieldsFit(st.body["result"], s.Result, keys(s.Result), st.env.CreatedAt); err != nil {
			return n, err
		}
		n.result = st.body["result"]
		n.state = "delivered"
		if s.Sign == "none" {
			n.state = "completed"
		}
	case st.kind == "confirm" && (state == "accepted" || state == "delivered") && mover == 0 && s.Sign != "none":
		n.state = "completed"
		if s.Sign == "both" {
			n.state = "requester_confirmed"
		}
		n.final = n.state == "completed"
	case st.kind == "confirm" && state == "requester_confirmed" && mover == 1:
		n.state, n.final = "completed", true
	default:
		// The step may be fine at some position, but not this one, or the type has no room for it.
		if st.kind == "deliver" && !s.hasWork() || st.kind == "progress" && len(s.Progress) == 0 {
			return n, Malformed
		}
		return n, OutOfTurn
	}
	return n, nil
}

func (r *Reader) checkPick(pick, offer Value) error {
	names := keys(r.schema.Pick)
	sort.Strings(names)
	if pick.kind != kObject || len(pick.members) != len(names) {
		return Malformed
	}
	for i, m := range pick.members {
		if m.key != names[i] || m.val.kind != kNumber {
			return Malformed
		}
		list := member0(offer, r.schema.Pick[m.key])
		found := false
		for _, item := range list.items {
			found = found || item.num == m.val.num
		}
		if !found {
			return NotOffered
		}
	}
	return nil
}

func member0(v Value, k string) Value {
	for _, m := range v.members {
		if m.key == k {
			return m.val
		}
	}
	return Value{}
}

func (r *Reader) checkCounter(terms, offer Value, at int64) error {
	names := []string{}
	for k := range r.schema.Offer {
		if !contains(r.schema.Fixed, k) {
			names = append(names, k)
		}
	}
	return fieldsFit(terms, r.schema.Offer, names, at)
}

// mergeOffer keeps what open fixed and replaces the rest, in sorted order.
func mergeOffer(offer, counter Value) Value {
	byKey := map[string]Value{}
	for _, m := range offer.members {
		byKey[m.key] = m.val
	}
	for _, m := range counter.members {
		byKey[m.key] = m.val
	}
	out := Value{kind: kObject}
	for _, k := range sortedKeys(byKey) {
		out.members = append(out.members, member{k, byKey[k]})
	}
	return out
}

func sortedKeys[T any](m map[string]T) []string {
	out := keys(m)
	sort.Strings(out)
	return out
}

// agreed is the latest offer without any list a pick chose from, plus the pick.
func (r *Reader) agreed(n node) Value {
	byKey := map[string]Value{}
	for _, m := range n.offer.members {
		byKey[m.key] = m.val
	}
	for _, list := range r.schema.Pick {
		delete(byKey, list)
	}
	for _, m := range n.pick.members {
		byKey[m.key] = m.val
	}
	out := Value{kind: kObject}
	for _, k := range sortedKeys(byKey) {
		out.members = append(out.members, member{k, byKey[k]})
	}
	return out
}

var stepOperation = map[string]string{"open": "open", "counter": "counter", "accept": "accept", "deliver": "deliver",
	"confirm": "confirm", "cancel": "cancel"}

// checkApproval checks an owner's approval on a step against the terms a walk gives.
func (r *Reader) checkApproval(st *step, prev *step, n node) error {
	compact, has := st.body["approval"]
	if !has {
		return nil
	}
	side := r.sides[st.by]
	if strings.Contains(compact.str, "~") {
		a, err := readDelegatedApproval(compact.str, side.Owner, side.Agent, r.schema, true)
		if err != nil {
			return err
		}
		return r.checkApprovalTerms(st, prev, n, a)
	}
	// A stand-in's key is on the agent's own machine, so nothing it signs is an owner's yes.
	if side.Owner.unconfirmedOwner() {
		return OwnerUnconfirmed
	}
	a, err := readApproval(compact.str, side.Owner.everyKey())
	if err == BadSignature {
		return ApprovalBadSignature
	}
	if err == Malformed {
		if s, rerr := readSigned(compact.str, "splint-approval"); rerr == nil && s.checkBy(side.Owner.Counting) != nil && !anyKey(side.Owner.everyKey(), s) {
			return ApprovalBadSignature
		}
		return ApprovalMismatch
	}
	if err != nil {
		return err
	}
	return r.checkApprovalTerms(st, prev, n, a)
}

// checkApprovalTerms checks that an approval, the owner's or their delegate's, is to this step as a
// walk gives it.
func (r *Reader) checkApprovalTerms(st *step, prev *step, n node, a Approval) error {
	side := r.sides[st.by]
	if st.env.CreatedAt > a.ExpiresAt {
		return ApprovalExpired
	}
	if a.ExpiresAt <= a.IssuedAt {
		return Malformed
	}
	request, prevID := r.nonceHash, r.nonceHash
	if st.kind != "open" {
		request, prevID = r.open.env.ID(), prev.env.ID()
	}
	terms := n
	if st.kind == "cancel" || st.kind == "confirm" {
		terms = prev.node
	}
	agreed := r.agreed(terms)
	if st.kind == "open" || st.kind == "counter" {
		agreed = terms.offer
	}
	if agreed.kind != kObject {
		agreed = Value{kind: kObject}
	}
	result := terms.result
	if result.kind != kObject {
		result = Value{kind: kObject}
	}
	typ, _ := r.open.body.str("type") // empty for core's plain conversation, as its terms have none
	supersedes := Value{kind: kNull}
	if v, has := r.open.body["supersedes"]; has {
		supersedes = v
	}
	ok := a.Decision == "approve" && a.Operation == stepOperation[st.kind] && a.Owner == side.Owner.ID && a.Agent == side.Agent.ID &&
		a.Request == request && a.Prev == prevID && a.Version == terms.version && a.Type == typ &&
		a.Requester == (Party{r.sides[0].Agent.ID, r.sides[0].Owner.ID}) && a.Recipient == (Party{r.sides[1].Agent.ID, r.sides[1].Owner.ID}) &&
		equal(a.Agreed, agreed) && equal(a.Result, result) && equal(a.Supersedes, supersedes)
	if !ok {
		return ApprovalMismatch
	}
	if st.env.CreatedAt != a.IssuedAt || st.env.ExpiresAt != a.ExpiresAt {
		return ApprovalMismatch
	}
	if st.kind != "cancel" && a.ExpiresAt > r.deadline {
		return ApprovalMismatch
	}
	if st.kind == "open" && a.ExpiresAt != r.deadline {
		return ApprovalMismatch
	}
	switch {
	case st.kind == "confirm" && st.by == 0:
	case st.kind == "confirm":
		c := prev.node.confirmed
		if c == nil || !equal(c.Subject, a.Subject) || !equal(c.Note, a.Note) {
			return ApprovalMismatch
		}
	case st.kind != "cancel":
		if a.Subject.kind != kNull || a.Note.kind != kNull {
			return ApprovalMismatch
		}
	}
	st.approval = &a
	if st.kind == "confirm" && st.by == 0 {
		st.node.confirmed = &a
	}
	return nil
}

func anyKey(keys []Signer, s Signed) bool {
	for _, k := range keys {
		if s.verifiedBy(k) {
			return true
		}
	}
	return false
}

func equal(a, b Value) bool { return string(a.Encoded()) == string(b.Encoded()) }

// decidesOver says whether st goes before held among steps that would decide the state alike: the
// deeper, then the higher MessageId, so the order they arrived in can't change which.
func decidesOver(st, held *step) bool {
	return held == nil || st.node.depth > held.node.depth ||
		(st.node.depth == held.node.depth && st.env.ID() > held.env.ID())
}

// settle decides the state from the steps held, whatever order they came in.
func (r *Reader) settle(now int64) Walked {
	w := Walked{OverCap: r.overCap, CopiesDropped: r.dropped}
	if r.open == nil {
		return w
	}
	var completedBy, ownerCancel, agentCancel *step
	disputed := false
	seen := map[string]*step{}
	latestROwner := int64(0)
	for _, st := range r.order {
		if st.approval != nil && st.by == 0 && st.approval.Version > latestROwner {
			latestROwner = st.approval.Version
		}
	}
	for _, st := range r.order {
		switch {
		case st.kind == "cancel" && st.approval != nil:
			// Undoing a completed request counts only while that completion does.
			if st.node.version >= latestROwner && decidesOver(st, ownerCancel) {
				ownerCancel = st
			}
		case st.kind == "cancel":
			if agentCancel == nil || st.env.ID() > agentCancel.env.ID() {
				agentCancel = st
			}
		case st.kind == "open":
		default:
			key := st.prev + string(rune('0'+st.by))
			if other, ok := seen[key]; ok && other.env.ID() != st.env.ID() {
				disputed = true
			}
			seen[key] = st
		}
		if st.node.state == "completed" && st.node.version >= latestROwner && decidesOver(st, completedBy) {
			completedBy = st
		}
	}
	finish := func(st *step, state string) Walked {
		w.State = state
		v := st.node.version
		id := st.env.ID()
		w.Version, w.Head = &v, &id
		return w
	}
	if ownerCancel != nil {
		return finish(ownerCancel, "cancelled")
	}
	if completedBy != nil && (completedBy.node.final || !disputed) {
		w.Payment = r.payment(completedBy.env.ID())
		return finish(completedBy, "completed")
	}
	if agentCancel != nil {
		return finish(agentCancel, "cancelled")
	}
	if disputed {
		w.State = "disputed"
		return w
	}
	head := r.open
	for _, st := range r.order {
		// The protocol doesn't say which of two lines as long as each other a conversation goes by.
		// This takes the higher MessageId, as a flood of cancels does, which no signer's date can move.
		if st.node.depth > head.node.depth || (st.node.depth == head.node.depth && st.env.ID() > head.env.ID()) {
			head = st
		}
	}
	out := finish(head, head.node.state)
	if out.State != "completed" && out.State != "declined" && out.State != "cancelled" && now > r.deadline+clockTolerance {
		out.State = "expired"
	}
	return out
}

// isTypeName is a word of up to 24 characters, `/`, and up to 4 digits.
func isTypeName(s string) bool {
	word, version, ok := strings.Cut(s, "/")
	if !ok || word == "" || len(word) > 24 || version == "" || len(version) > 4 {
		return false
	}
	for _, c := range []byte(word) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	for _, c := range []byte(version) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

package verifier

import (
	"strings"
)

const (
	NotPayable      Refusal = "not_payable"
	PaymentMismatch Refusal = "payment_mismatch"
	BadWherePaid    Refusal = "bad_where_paid"
)

const (
	asksPerValue      = 3 // asks to be paid one value: once, and twice more for another place
	maxPlaces         = 4
	maxStatementBytes = 1536
	bech32Chars       = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	urlChars          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%"
)

// placeFields are each kind of place's fields, in their one order after kind.
var placeFields = map[string][]string{
	"payment_page": {"url"},
	"lightning":    {"to"},
	"onchain":      {"chain", "address", "asset"},
}

// ask is an ask to be paid, held apart from the chain's line.
type ask struct {
	id, of, value string
	by            int
}

// paymentReceived is the payee's word that the payment arrived.
type paymentReceived struct {
	id, of string
}

// referenceOf is what a payer puts on a payment, from the request's ID.
func referenceOf(request string) string {
	if len(request) < 16 {
		return ""
	}
	return "SPL-" + strings.ToUpper(request[:16])
}

func isReference(s string) bool {
	hex, ok := strings.CutPrefix(s, "SPL-")
	if !ok || len(hex) != 16 {
		return false
	}
	for _, c := range []byte(hex) {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// checkPayRequestShape is what's checked of an ask with no chain: code writes it in one shape.
func checkPayRequestShape(f fields) error {
	for _, k := range []string{"for", "unit"} {
		s, err := f.str(k)
		if err != nil || !isWord(s) {
			return Malformed
		}
	}
	amount, err := f.num("amount")
	if err != nil || amount < 0 {
		return Malformed
	}
	entry, err := f.num("entry")
	if err != nil || entry < 0 || entry >= maxPlaces {
		return Malformed
	}
	reference, err := f.str("reference")
	if err != nil || !isReference(reference) {
		return Malformed
	}
	if _, err := f.str("where_paid"); err != nil {
		return Malformed
	}
	return nil
}

// completedAt is a completed step this reader holds.
func (r *Reader) completedAt(of string) (*step, error) {
	named, held := r.steps[of]
	if !held {
		return nil, UnknownPrev
	}
	if named.node.state != "completed" {
		return nil, OutOfTurn
	}
	return named, nil
}

// due is what's owed to side `by` for value by the terms the completed step `of` left standing, where
// the payer's own owner signed them.
func (r *Reader) due(of string, by int, value string) (int64, string, error) {
	named, err := r.completedAt(of)
	if err != nil {
		return 0, "", err
	}
	if r.schema.Paid[value] != []string{"requester", "recipient"}[by] {
		return 0, "", NotPayable
	}
	payerSigned := named.kind == "confirm" && (by == 1 || named.by == 1)
	if !payerSigned {
		return 0, "", NotPayable
	}
	amount, found := int64(0), false
	for _, held := range []Value{named.node.result, named.node.offer, named.node.pick} {
		if v := member0(held, value); v.kind == kNumber {
			amount, found = v.num, true
			break
		}
	}
	unit := member0(named.node.offer, r.schema.Units[value])
	if !found || unit.kind != kString || !isWord(unit.str) {
		return 0, "", NotPayable
	}
	return amount, unit.str, nil
}

func (r *Reader) payable(of string, by int) bool {
	for _, value := range r.schema.Values {
		if _, _, err := r.due(of, by, value); err == nil {
			return true
		}
	}
	return false
}

// wherePaid is the payee's owner's statement of where they get paid, and how many places it lists.
func (r *Reader) wherePaid(compact string, by int, sentAt int64) (int, error) {
	owner := r.sides[by].Owner
	// No owner has confirmed a stand-in, so none has signed where one gets paid.
	if owner.unconfirmedOwner() {
		return 0, OwnerUnconfirmed
	}
	s, err := openUnder(compact, "splint-where-paid", owner.Keys)
	if err != nil {
		return 0, BadWherePaid
	}
	return readWherePaid(s.Payload, s.Body, owner.ID, sentAt)
}

// readWherePaid is what's checked of a statement's payload once its owner's signature has checked out.
// It's never dated after the step carrying it (sentAt), or it would outrank every later statement.
func readWherePaid(payload []byte, body Value, owner string, sentAt int64) (int, error) {
	if len(payload) > maxStatementBytes || string(body.Encoded()) != string(payload) {
		return 0, BadWherePaid
	}
	f, err := shape(body, []string{"v", "owner", "places", "issued_at"})
	if err != nil || f.version(1) != nil {
		return 0, BadWherePaid
	}
	if o, err := f.str("owner"); err != nil || o != owner {
		return 0, BadWherePaid
	}
	if issued, err := f.date("issued_at"); err != nil || issued > sentAt+clockTolerance {
		return 0, BadWherePaid
	}
	places := f["places"]
	if places.kind != kArray || len(places.items) == 0 || len(places.items) > maxPlaces {
		return 0, BadWherePaid
	}
	seen := map[string]bool{}
	for _, place := range places.items {
		encoded := string(place.Encoded())
		if seen[encoded] || !placeFits(place) {
			return 0, BadWherePaid
		}
		seen[encoded] = true
	}
	return len(places.items), nil
}

func placeFits(place Value) bool {
	kind, ok := place.firstString()
	if !ok || place.members[0].key != "kind" {
		return false
	}
	names, known := placeFields[kind]
	if !known {
		return false
	}
	f, err := shape(place, append([]string{"kind"}, names...))
	if err != nil || len(f) != len(names)+1 {
		return false
	}
	for _, name := range names {
		if _, err := f.str(name); err != nil {
			return false
		}
	}
	switch kind {
	case "payment_page":
		url, _ := f.str("url")
		return isPaymentPage(url)
	case "lightning":
		to, _ := f.str("to")
		return isLightning(to)
	default:
		chain, _ := f.str("chain")
		address, _ := f.str("address")
		asset, _ := f.str("asset")
		return isChain(chain) && isChainAddress(address) && isWord(asset)
	}
}

func isPaymentPage(url string) bool {
	rest, ok := strings.CutPrefix(url, "https://")
	if !ok || utf8Len(url) > 300 {
		return false
	}
	for _, c := range rest {
		if !strings.ContainsRune(urlChars, c) {
			return false
		}
	}
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority = rest[:i]
	}
	if strings.Contains(authority, "@") {
		return false
	}
	host, port, hasPort := strings.Cut(authority, ":")
	if hasPort {
		if port == "" || len(port) > 5 {
			return false
		}
		for _, c := range []byte(port) {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return isDNSName(host)
}

func utf8Len(s string) int { return len([]rune(s)) }

func isDNSName(host string) bool {
	labels := strings.Split(host, ".")
	if len(host) > 253 || len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	top := labels[len(labels)-1]
	if len(top) < 2 {
		return false
	}
	for _, c := range []byte(top) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func isLightning(to string) bool {
	if data, ok := strings.CutPrefix(to, "lno1"); ok {
		if len(to) < 20 || len(to) > 600 {
			return false
		}
		for _, c := range data {
			if !strings.ContainsRune(bech32Chars, c) {
				return false
			}
		}
		return true
	}
	name, domain, ok := strings.Cut(to, "@")
	if !ok || name == "" || len(name) > 64 || len(to) > 320 || domain != strings.ToLower(domain) {
		return false
	}
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.+", c) >= 0) {
			return false
		}
	}
	return isDNSName(domain)
}

// isChain is CAIP-2: a namespace, `:`, and a reference.
func isChain(chain string) bool {
	namespace, reference, ok := strings.Cut(chain, ":")
	if !ok || len(namespace) < 3 || len(namespace) > 8 || reference == "" || len(reference) > 32 {
		return false
	}
	for _, c := range []byte(namespace) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	for _, c := range []byte(reference) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// isChainAddress is CAIP-10's account address.
func isChainAddress(address string) bool {
	if address == "" || len(address) > 128 {
		return false
	}
	for _, c := range []byte(address) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-.%", c) >= 0) {
			return false
		}
	}
	return true
}

// placePayment takes an ask to be paid, or the payee's word that it arrived. Neither moves the chain.
func (r *Reader) placePayment(st *step) error {
	of, _ := st.body.str("of")
	if st.kind == "payment_received" {
		if _, err := r.completedAt(of); err != nil {
			return err
		}
		if !r.payable(of, st.by) {
			return NotPayable
		}
		if r.arrived == nil {
			r.arrived = &paymentReceived{id: st.env.ID(), of: of}
		}
		return nil
	}
	value, _ := st.body.str("for")
	amount, unit, err := r.due(of, st.by, value)
	if err != nil {
		return err
	}
	compact, _ := st.body.str("where_paid")
	places, err := r.wherePaid(compact, st.by, st.env.CreatedAt)
	if err != nil {
		return err
	}
	gotAmount, _ := st.body.num("amount")
	gotUnit, _ := st.body.str("unit")
	reference, _ := st.body.str("reference")
	entry, _ := st.body.num("entry")
	if gotAmount != amount || gotUnit != unit || reference != referenceOf(r.open.env.ID()) || entry >= int64(places) {
		return PaymentMismatch
	}
	held := 0
	for _, a := range r.asks {
		if a.by == st.by && a.value == value {
			held++
		}
	}
	if held >= asksPerValue {
		return TooManySteps
	}
	r.asks = append(r.asks, ask{id: st.env.ID(), of: of, value: value, by: st.by})
	return nil
}

// payment is where the payment stands, apart from the state: only while completed, by the step that
// completed it.
func (r *Reader) payment(completed string) string {
	if r.arrived != nil && r.arrived.of == completed {
		return "received"
	}
	for _, a := range r.asks {
		if a.of == completed {
			return "requested"
		}
	}
	return ""
}

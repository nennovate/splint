package verifier

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxAskChars = 16 * 1024
	maxAskLife  = 24 * 3600
)

// Ask is an agent's ask of its owner for exact changes, signed by the agent's key.
type Ask struct {
	Signed
	ID, Agent, Owner    string
	Changes             int
	IssuedAt, ExpiresAt int64
}

var askLevels = map[string]bool{"ask_me": true, "auto_within_limits": true, "full_auto": true}
var askQuoted = map[string]bool{"wait": true, "within_limits": true}
var askWrites = map[string]bool{"contacts": true, "replies": true}

// VerifyAsk checks an ask under the asking agent's newest copy of its ID, at a time.
func VerifyAsk(compact string, agent Identity, now int64) (Ask, error) {
	if len(compact) > maxAskChars {
		return Ask{}, Malformed
	}
	if err := agent.asAgent(); err != nil {
		return Ask{}, err
	}
	s, err := open(compact, "splint-ask", agent.Key())
	if err != nil {
		return Ask{}, err
	}
	f, err := shape(s.Body, []string{"v", "id", "agent", "owner", "changes", "issued_at", "expires_at"})
	if err != nil || f.version(1) != nil || len(f) != 7 {
		return Ask{}, Malformed
	}
	a := Ask{Signed: s}
	if a.ID, err = f.str("id"); err != nil || len(a.ID) != 32 || !isHash(a.ID+strings.Repeat("0", 32)) {
		return Ask{}, Malformed
	}
	if a.Agent, err = f.id("agent"); err != nil {
		return Ask{}, err
	}
	if a.Owner, err = f.id("owner"); err != nil {
		return Ask{}, err
	}
	changes := f["changes"]
	if changes.kind != kArray || len(changes.items) == 0 {
		return Ask{}, Malformed
	}
	subjects := map[string]bool{}
	var places Value
	for _, change := range changes.items {
		subject, err := askChange(change)
		if err != nil || subjects[subject] {
			return Ask{}, Malformed
		}
		subjects[subject] = true
		if subject == "where_paid" {
			places = change.members[1].val
		}
	}
	// A step changes no rule, nor does where the owner gets paid, a move to another host or an owner
	// part, so each is alone in its ask.
	if (subjects["step"] || subjects["where_paid"] || subjects["host"] || subjects["owner_part"]) && len(changes.items) > 1 {
		return Ask{}, Malformed
	}
	a.Changes = len(changes.items)
	if a.IssuedAt, err = f.date("issued_at"); err != nil {
		return Ask{}, err
	}
	if a.ExpiresAt, err = f.date("expires_at"); err != nil {
		return Ask{}, err
	}
	if a.ExpiresAt <= a.IssuedAt || a.ExpiresAt-a.IssuedAt > maxAskLife {
		return Ask{}, Malformed
	}
	// The statement the owner's side would sign for those places as the ask was made has to be one a
	// reader takes, at most its size.
	if subjects["where_paid"] {
		statement := `{"v":1,"owner":"` + a.Owner + `","places":` + string(places.Encoded()) + `,"issued_at":` + strconv.FormatInt(a.IssuedAt, 10) + `}`
		if len(statement) > maxStatementBytes {
			return Ask{}, Malformed
		}
	}
	if a.IssuedAt > now+clockTolerance {
		return Ask{}, FromTheFuture
	}
	if now >= a.ExpiresAt {
		return Ask{}, Expired
	}
	if a.Agent != agent.ID {
		return Ask{}, WrongSigner
	}
	return a, nil
}

// askChange checks one change's shape and returns what it changes, a setting or one contact.
func askChange(v Value) (string, error) {
	if v.kind != kObject || len(v.members) == 0 || v.members[0].key != "change" || v.members[0].val.kind != kString {
		return "", Malformed
	}
	kind := v.members[0].val.str
	word := func(f fields, allowed map[string]bool) error {
		to, err := f.str("to")
		if err != nil || !allowed[to] {
			return Malformed
		}
		return nil
	}
	switch kind {
	case "controls":
		// Controls name the delegate key their delegation goes to: a real key, in its one spelling. An
		// owner part, the name the person goes by after the agent's handle, is one handle.
		f, err := shape(v, []string{"change", "delegate"}, "owner_part")
		if err != nil {
			return "", Malformed
		}
		if f.has("owner_part") {
			if part, err := f.str("owner_part"); err != nil || !isOwnerPart(part) {
				return "", Malformed
			}
		}
		delegate, err := f.str("delegate")
		if err != nil {
			return "", Malformed
		}
		point, err := parsePoint(delegate)
		if err != nil {
			return "", Malformed
		}
		if _, err := ecdh.P256().NewPublicKey(point); err != nil {
			return "", Malformed
		}
		return kind, nil
	case "step":
		// One step held for the owner, of a request named by ID, of a kind an owner says yes to.
		f, err := shape(v, []string{"change", "request", "operation"})
		if err != nil || len(f) != 3 {
			return "", Malformed
		}
		if _, err := f.hash("request"); err != nil {
			return "", Malformed
		}
		if operation, err := f.str("operation"); err != nil || !operationsApproved[operation] {
			return "", Malformed
		}
		return kind, nil
	case "where_paid":
		// Where the owner gets paid: 1 to 4 places, each once, each one a statement takes.
		f, err := shape(v, []string{"change", "places"})
		if err != nil || len(f) != 2 {
			return "", Malformed
		}
		places := f["places"]
		if places.kind != kArray || len(places.items) == 0 || len(places.items) > maxPlaces {
			return "", Malformed
		}
		seen := map[string]bool{}
		for _, place := range places.items {
			encoded := string(place.Encoded())
			if seen[encoded] || !placeFits(place) {
				return "", Malformed
			}
			seen[encoded] = true
		}
		return kind, nil
	case "owner_part":
		// An owner part added to the agent's name names one handle, and nothing else.
		f, err := shape(v, []string{"change", "to"})
		if err != nil || len(f) != 2 {
			return "", Malformed
		}
		if to, err := f.str("to"); err != nil || !isOwnerPart(to) {
			return "", Malformed
		}
		return kind, nil
	case "host":
		// A move to another host names the address moved to, in its one spelling, and nothing else.
		f, err := shape(v, []string{"change", "to"})
		if err != nil || len(f) != 2 {
			return "", Malformed
		}
		if to, err := f.str("to"); err != nil || !isAddress(to) {
			return "", Malformed
		}
		return kind, nil
	case "level", "quoted_prices", "writes":
		f, err := shape(v, []string{"change", "to"})
		if err != nil {
			return "", err
		}
		allowed := map[string]map[string]bool{"level": askLevels, "quoted_prices": askQuoted, "writes": askWrites}[kind]
		return kind, word(f, allowed)
	case "paused":
		f, err := shape(v, []string{"change", "to"})
		if err != nil || f["to"].kind != kBool {
			return "", Malformed
		}
		return kind, nil
	case "reach":
		return kind, askReach(v)
	case "contact", "block", "remove":
		required := map[string][]string{
			"contact": {"change", "agent", "address", "types", "text"},
			"block":   {"change", "agent", "address"},
			"remove":  {"change", "agent"},
		}[kind]
		f, err := shape(v, required)
		if err != nil || len(f) != len(required) {
			return "", Malformed
		}
		agent, err := f.id("agent")
		if err != nil {
			return "", err
		}
		if kind != "remove" {
			if address, err := f.str("address"); err != nil || !isAddress(address) {
				return "", Malformed
			}
		}
		if kind == "contact" {
			if !askTypes(f["types"], true) || f["text"].kind != kBool {
				return "", Malformed
			}
		}
		return "contact " + agent, nil
	}
	return "", Malformed
}

// isOwnerPart checks one handle, as an owner part is: at most 63 lower-case letters, digits and -.
func isOwnerPart(s string) bool {
	return len(s) <= 63 && isHandle(s)
}

// askReach checks who besides contacts may reach the agent: nobody, anyone for some types, or owners
// named or people it has dealt with, for some types. Fields left at their defaults are left out.
func askReach(v Value) error {
	f, err := shape(v, []string{"change", "to"}, "types", "owners", "past")
	if err != nil {
		return err
	}
	to, err := f.str("to")
	if err != nil {
		return Malformed
	}
	hasTypes := f.has("types")
	if hasTypes && !askTypes(f["types"], false) {
		return Malformed
	}
	owners := f.has("owners")
	if owners {
		list := f["owners"]
		if list.kind != kArray || len(list.items) == 0 {
			return Malformed
		}
		for _, owner := range list.items {
			if owner.kind != kString || !isID(owner.str) {
				return Malformed
			}
		}
	}
	past := f.has("past")
	if past && (f["past"].kind != kBool || !f["past"].boolean) {
		return Malformed
	}
	switch to {
	case "contacts":
		if hasTypes || owners || past {
			return Malformed
		}
	case "open":
		if !hasTypes || owners || past {
			return Malformed
		}
	case "filter":
		if !hasTypes || !(owners || past) {
			return Malformed
		}
	default:
		return Malformed
	}
	return nil
}

// askTypes is a list of types two agents agreed, each by its ID, which may be empty only where
// emptyOK says so. Core's own are never named. A list left at its default is left out instead.
func askTypes(v Value, emptyOK bool) bool {
	if v.kind != kArray || (len(v.items) == 0 && !emptyOK) {
		return false
	}
	for _, item := range v.items {
		if item.kind != kString || !isTypeID(item.str) {
			return false
		}
	}
	return true
}

const (
	askKeptAtTag = "splint ask kept at v1"
	askAnswerTag = "splint ask answer v1"
)

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CheckAskAnswer checks the MAC an owner's answer to an agent's ask for its controls carries: by the
// ask's ID, its 16 bytes, over the owner's ID, so only someone who saw the ask makes one. It says where
// the agent's host keeps answers to that ask: the first 16 bytes of SHA-256 of a tag and the ID.
func CheckAskAnswer(askID, owner, mac string) (string, error) {
	secret, err := askSecret(askID)
	if err != nil || !isID(owner) || !lowerHex64.MatchString(mac) {
		return "", Malformed
	}
	given, _ := hex.DecodeString(mac)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(askAnswerTag + owner))
	if !hmac.Equal(m.Sum(nil), given) {
		return "", BadSignature
	}
	sum := sha256.Sum256(append([]byte(askKeptAtTag), secret...))
	return hex.EncodeToString(sum[:16]), nil
}

func askSecret(id string) ([]byte, error) {
	if len(id) != 32 || strings.ToLower(id) != id {
		return nil, Malformed
	}
	return hex.DecodeString(id)
}

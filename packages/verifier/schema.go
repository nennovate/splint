package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Rule is what one field of a type may hold.
type Rule struct {
	Word  []string `json:"word,omitempty"`
	OneOf []int64  `json:"one_of,omitempty"`
	Range *struct {
		Min int64 `json:"min"`
		Max int64 `json:"max"`
	} `json:"range,omitempty"`
	Times *struct {
		GridSecs int64 `json:"grid_secs"`
		Max      int   `json:"max"`
	} `json:"times,omitempty"`
	Text *struct {
		MaxChars int `json:"max_chars"`
	} `json:"text,omitempty"`
}

// Schema is an interaction type, as a reader loads it. ID is what it goes by: its name and the
// fingerprint of its one encoding, or core's own name for one of core's own.
type Schema struct {
	Type     string            `json:"type"`
	Kind     string            `json:"kind"`
	Offer    map[string]Rule   `json:"offer"`
	Fixed    []string          `json:"fixed"`
	Pick     map[string]string `json:"pick"`
	Result   map[string]Rule   `json:"result"`
	Progress []string          `json:"progress"`
	Clarify  []string          `json:"clarify"`
	Decline  []string          `json:"decline"`
	Say      map[string]Rule   `json:"say"`
	Values   []string          `json:"values"`
	Units    map[string]string `json:"units"`
	Paid     map[string]string `json:"paid"`
	Sign     string            `json:"sign"`

	ID        string `json:"-"`
	encoding  []byte
	agreement bool
}

const (
	proposalType              = "type/1"
	fingerprintTag            = "splint type v1"
	maxProposedBytes          = 2048
	maxProposedList           = 16
	maxChosenChars            = 512
	maxProposedNumber         = 1<<53 - 1
	maxProposedText           = 500
	TypeTooBig        Refusal = "type_too_big"
	TypeUnsafe        Refusal = "type_unsafe"
)

// Core's own types: a plain conversation, whose open names no type, and type/1, by which two agents
// agree one, which the other side's accept finishes.
var (
	conversationSchema = Schema{Type: "conversation/1", Kind: "conversation", Sign: "none",
		Say: map[string]Rule{"text": {Text: &struct {
			MaxChars int `json:"max_chars"`
		}{MaxChars: 500}}}}
	proposalSchema = Schema{Type: proposalType, ID: proposalType, Kind: "request", Sign: "none", agreement: true,
		Decline: []string{"name_taken", "not_needed", "not_understood", "too_big", "unsafe_type"}}
)

// oneEncoding is a schema document's one encoding: every key sorted, every list sorted with no repeats,
// and an empty part, or a sign of none, left out.
func oneEncoding(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, Malformed
	}
	top, ok := v.(map[string]any)
	if !ok {
		return nil, Malformed
	}
	tidied := tidy(top).(map[string]any)
	if tidied["sign"] == "none" {
		delete(tidied, "sign")
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(tidied); err != nil {
		return nil, Malformed
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func tidy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, item := range t {
			item = tidy(item)
			if m, ok := item.(map[string]any); ok && len(m) == 0 {
				continue
			}
			if l, ok := item.([]any); ok && len(l) == 0 {
				continue
			}
			out[k] = item
		}
		return out
	case []any:
		seen := map[string]any{}
		for _, item := range t {
			seen[canonicalKey(item)] = item
		}
		keys := make([]string, 0, len(seen))
		for k := range seen {
			keys = append(keys, k)
		}
		numeric := len(t) > 0
		for _, item := range t {
			if _, ok := item.(json.Number); !ok {
				numeric = false
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			if numeric {
				a, _ := strconv.ParseUint(keys[i], 10, 64)
				b, _ := strconv.ParseUint(keys[j], 10, 64)
				return a < b
			}
			return keys[i] < keys[j]
		})
		out := make([]any, 0, len(keys))
		for _, k := range keys {
			out = append(out, seen[k])
		}
		return out
	}
	return v
}

func canonicalKey(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// schemaPart is what one part of a schema may hold: a struct's own keys, exactly, or a map's values,
// whatever its keys. One with neither holds a string, a number or a list of them.
type schemaPart struct {
	fields map[string]*schemaPart
	each   *schemaPart
}

var (
	leaf      = &schemaPart{}
	ruleShape = &schemaPart{fields: map[string]*schemaPart{
		"word": leaf, "one_of": leaf,
		"range": {fields: map[string]*schemaPart{"min": leaf, "max": leaf}},
		"times": {fields: map[string]*schemaPart{"grid_secs": leaf, "max": leaf}},
		"text":  {fields: map[string]*schemaPart{"max_chars": leaf}},
	}}
	schemaShape = &schemaPart{fields: map[string]*schemaPart{
		"type": leaf, "kind": leaf, "sign": leaf,
		"offer": {each: ruleShape}, "result": {each: ruleShape}, "say": {each: ruleShape},
		"fixed": leaf, "progress": leaf, "clarify": leaf, "decline": leaf, "values": leaf,
		"pick": {each: leaf}, "units": {each: leaf}, "paid": {each: leaf},
	}}
)

// exactlySpelled refuses a schema with a part not spelled exactly as the protocol names it, or named
// twice, or a number not written as a plain whole number. encoding/json matches a struct's fields
// without regard to case, takes the last of a repeated one and reads -0 as 0, where Rust refuses all
// three, so without this a schema Rust refuses would be read here, under another ID.
func exactlySpelled(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkSpelled(dec, schemaShape); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return Malformed
	}
	return nil
}

func walkSpelled(dec *json.Decoder, sh *schemaPart) error {
	token, err := dec.Token()
	if err != nil {
		return Malformed
	}
	switch t := token.(type) {
	case json.Delim:
		if t == '[' {
			for dec.More() {
				if err := walkSpelled(dec, leaf); err != nil {
					return err
				}
			}
		} else if t == '{' {
			if sh.fields == nil && sh.each == nil {
				return Malformed
			}
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return Malformed
				}
				seen[name] = true
				child := sh.each
				if sh.fields != nil {
					child = sh.fields[name]
				}
				if child == nil {
					return Malformed
				}
				if err := walkSpelled(dec, child); err != nil {
					return err
				}
			}
		}
		if _, err := dec.Token(); err != nil {
			return Malformed
		}
	case json.Number:
		if !isPlainWholeNumber(string(t)) {
			return Malformed
		}
	}
	return nil
}

func isPlainWholeNumber(s string) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ParseSchema reads a type's schema, written any way, and works out the ID it goes by.
func ParseSchema(raw []byte) (Schema, error) {
	if err := exactlySpelled(raw); err != nil {
		return Schema{}, err
	}
	var s Schema
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || s.Type == "" {
		return Schema{}, Malformed
	}
	if s.Sign == "" {
		s.Sign = "none"
	}
	if !s.fitsTogether() {
		return Schema{}, Malformed
	}
	enc, err := oneEncoding(raw)
	if err != nil {
		return Schema{}, err
	}
	sum := sha256.Sum256(append(append([]byte(fingerprintTag), 0), enc...))
	s.ID = s.Type + "@" + strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(sum[:]), "="))
	s.encoding = enc
	return s, nil
}

func (s Schema) conversation() bool { return s.Kind == "conversation" }
func (s Schema) hasWork() bool      { return len(s.Result) > 0 }

func (r Rule) kinds() int {
	n := 0
	for _, set := range []bool{r.Word != nil, r.OneOf != nil, r.Range != nil, r.Times != nil, r.Text != nil} {
		if set {
			n++
		}
	}
	return n
}

func (r Rule) canBeMet() bool {
	switch {
	case r.kinds() != 1:
		return false
	case r.Word != nil:
		for _, w := range r.Word {
			if !isWord(w) {
				return false
			}
		}
		return len(r.Word) > 0
	case r.OneOf != nil:
		for _, n := range r.OneOf {
			if n < 0 {
				return false
			}
		}
		return len(r.OneOf) > 0
	case r.Range != nil:
		return r.Range.Min >= 0 && r.Range.Min <= r.Range.Max
	case r.Times != nil:
		return r.Times.GridSecs > 0 && r.Times.Max > 0
	default:
		return r.Text.MaxChars > 0
	}
}

// fitsTogether is a schema some request could follow, which every reader refuses otherwise.
func (s Schema) fitsTogether() bool {
	if !isTypeName(s.Type) || strings.HasPrefix(s.Type, "type/") {
		return false
	}
	for _, section := range []map[string]Rule{s.Offer, s.Result, s.Say} {
		if len(section) > 16 {
			return false
		}
		for name, rule := range section {
			if !isWord(name) || !rule.canBeMet() {
				return false
			}
		}
	}
	for _, words := range [][]string{s.Fixed, s.Progress, s.Clarify, s.Decline, s.Values} {
		for _, w := range words {
			if !isWord(w) {
				return false
			}
		}
	}
	for name, from := range s.Pick {
		_, inOffer := s.Offer[name]
		if !isWord(name) || inOffer || contains(s.Fixed, from) || s.Offer[from].Times == nil {
			return false
		}
	}
	for _, name := range s.Fixed {
		if _, ok := s.Offer[name]; !ok {
			return false
		}
	}
	for _, name := range s.Values {
		rule, ok := s.Offer[name]
		if !ok {
			rule, ok = s.Result[name]
		}
		if !ok || (rule.Range == nil && rule.OneOf == nil) {
			return false
		}
	}
	for name, side := range s.Paid {
		if !contains(s.Values, name) || (side != "requester" && side != "recipient") {
			return false
		}
	}
	for name, unit := range s.Units {
		if !contains(s.Values, name) || !contains(s.Fixed, unit) || s.Offer[unit].Word == nil {
			return false
		}
	}
	if s.Sign != "none" && s.Sign != "requester" && s.Sign != "both" {
		return false
	}
	switch s.Kind {
	case "conversation":
		return len(s.Say) > 0 && len(s.Offer)+len(s.Pick)+len(s.Result)+len(s.Progress)+len(s.Clarify)+len(s.Decline) == 0 && s.Sign == "none"
	case "request":
		return len(s.Say) == 0 && (len(s.Result) > 0 || s.Sign != "none")
	}
	return false
}

// chosenChars counts every character of a name, word or number in a schema that whoever wrote it chose.
func (s Schema) chosenChars() int {
	n := len(s.Type)
	digits := func(v int64) int { return len(strconv.FormatInt(v, 10)) }
	for _, section := range []map[string]Rule{s.Offer, s.Result, s.Say} {
		for name, rule := range section {
			n += len(name)
			switch {
			case rule.Word != nil:
				for _, w := range rule.Word {
					n += len(w)
				}
			case rule.OneOf != nil:
				for _, v := range rule.OneOf {
					n += digits(v)
				}
			case rule.Range != nil:
				n += digits(rule.Range.Min) + digits(rule.Range.Max)
			case rule.Times != nil:
				n += digits(rule.Times.GridSecs) + digits(int64(rule.Times.Max))
			case rule.Text != nil:
				n += digits(int64(rule.Text.MaxChars))
			}
		}
	}
	for _, words := range [][]string{s.Fixed, s.Progress, s.Clarify, s.Decline, s.Values} {
		for _, w := range words {
			n += len(w)
		}
	}
	for a, b := range s.Pick {
		n += len(a) + len(b)
	}
	for a, b := range s.Units {
		n += len(a) + len(b)
	}
	for a := range s.Paid {
		n += len(a)
	}
	return n
}

// checkProposal is what core holds every proposed schema to, whoever proposes it.
func (s Schema) checkProposal() error {
	counts := len(s.Offer) <= maxProposedList && len(s.Result) <= maxProposedList && len(s.Say) <= maxProposedList &&
		len(s.Pick) <= maxProposedList && len(s.Progress) <= maxProposedList && len(s.Clarify) <= maxProposedList &&
		len(s.Decline) <= maxProposedList
	numbers := true
	for _, section := range []map[string]Rule{s.Offer, s.Result, s.Say} {
		for _, rule := range section {
			switch {
			case rule.Word != nil:
				counts = counts && len(rule.Word) <= maxProposedList
			case rule.OneOf != nil:
				counts = counts && len(rule.OneOf) <= maxProposedList
				for _, v := range rule.OneOf {
					numbers = numbers && v <= maxProposedNumber
				}
			case rule.Range != nil:
				numbers = numbers && rule.Range.Min <= maxProposedNumber && rule.Range.Max <= maxProposedNumber
			case rule.Times != nil:
				counts = counts && rule.Times.Max <= maxProposedList
				numbers = numbers && rule.Times.GridSecs <= maxProposedNumber
			case rule.Text != nil:
				numbers = numbers && rule.Text.MaxChars <= maxProposedText
			}
		}
	}
	if !counts || len(s.encoding) > maxProposedBytes || s.chosenChars() > maxChosenChars {
		return TypeTooBig
	}
	for name := range s.Paid {
		if _, ok := s.Units[name]; !ok {
			numbers = false
		}
	}
	if !numbers {
		return TypeUnsafe
	}
	return nil
}

func isWord(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// isTypeID is a name and a fingerprint: 52 base32 characters whose spare bits are zero.
func isTypeID(s string) bool {
	name, fingerprint, ok := strings.Cut(s, "@")
	if !ok || !isTypeName(name) || strings.HasPrefix(name, "type/") || len(fingerprint) != 52 {
		return false
	}
	for _, c := range []byte(fingerprint) {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	last := fingerprint[51]
	return last == 'a' || last == 'q'
}

const twoWeeks = 14 * 24 * 3600

// fieldsFit checks an object holds exactly the named fields, in sorted order, each fitting its
// rule. at is the date of the step naming any times.
func fieldsFit(v Value, rules map[string]Rule, names []string, at int64) error {
	sorted := append([]string{}, names...)
	sort.Strings(sorted)
	if v.kind != kObject || len(v.members) != len(sorted) {
		return Malformed
	}
	for i, m := range v.members {
		if m.key != sorted[i] {
			return Malformed
		}
		if err := rules[m.key].fits(m.val, at); err != nil {
			return err
		}
	}
	return nil
}

func (r Rule) fits(v Value, at int64) error {
	switch {
	case r.Word != nil:
		if v.kind != kString || !contains(r.Word, v.str) {
			return Malformed
		}
	case r.OneOf != nil:
		if v.kind != kNumber {
			return Malformed
		}
		for _, n := range r.OneOf {
			if n == v.num {
				return nil
			}
		}
		return Malformed
	case r.Range != nil:
		if v.kind != kNumber || v.num < r.Range.Min || v.num > r.Range.Max {
			return Malformed
		}
	case r.Times != nil:
		if v.kind != kArray || len(v.items) < 1 || len(v.items) > r.Times.Max {
			return Malformed
		}
		for i, t := range v.items {
			if t.kind != kNumber || t.num%r.Times.GridSecs != 0 || (i > 0 && t.num <= v.items[i-1].num) {
				return Malformed
			}
		}
		for _, t := range v.items {
			if t.num <= at || t.num > at+twoWeeks {
				return OutsideWindow
			}
		}
	case r.Text != nil:
		if v.kind != kString || utf8.RuneCountInString(v.str) > r.Text.MaxChars || hidesText(v.str) {
			return Malformed
		}
	default:
		return Malformed
	}
	return nil
}

func keys[T any](m map[string]T) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

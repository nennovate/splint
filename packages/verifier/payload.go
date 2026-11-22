// Package verifier checks Splint's signed formats from docs/protocol.md alone.
// It verifies and never signs.
package verifier

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Refusal is a fixed reason, as the protocol names them.
type Refusal string

func (r Refusal) Error() string { return string(r) }

const (
	Malformed     Refusal = "malformed"
	BadSignature  Refusal = "bad_signature"
	WrongSigner   Refusal = "wrong_signer"
	ProofMismatch Refusal = "proof_mismatch"
	Expired       Refusal = "expired"
	FromTheFuture Refusal = "from_the_future"
	Forked        Refusal = "forked"
	Stale         Refusal = "stale"
	CantOpen      Refusal = "cant_open"
)

type kind int

const (
	kString kind = iota
	kNumber
	kBool
	kNull
	kArray
	kObject
)

// Value is parsed JSON that keeps field order, so its one encoding can be checked.
type Value struct {
	kind    kind
	str     string
	num     int64
	boolean bool
	items   []Value
	members []member
}

type member struct {
	key string
	val Value
}

// parsePayload reads JSON that must be in its one encoding: compact, integers only,
// no duplicate keys, and no escape that isn't needed.
func parsePayload(raw []byte) (Value, error) {
	p := parser{in: raw}
	v, err := p.value(0)
	if err != nil {
		return Value{}, err
	}
	if p.pos != len(raw) {
		return Value{}, Malformed
	}
	var out bytes.Buffer
	v.encode(&out)
	if !bytes.Equal(out.Bytes(), raw) {
		return Value{}, Malformed
	}
	return v, nil
}

type parser struct {
	in  []byte
	pos int
}

func (p *parser) value(depth int) (Value, error) {
	if depth > 32 || p.pos >= len(p.in) {
		return Value{}, Malformed
	}
	switch c := p.in[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.string()
		return Value{kind: kString, str: s}, err
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case bytes.HasPrefix(p.in[p.pos:], []byte("true")):
		p.pos += 4
		return Value{kind: kBool, boolean: true}, nil
	case bytes.HasPrefix(p.in[p.pos:], []byte("false")):
		p.pos += 5
		return Value{kind: kBool}, nil
	case bytes.HasPrefix(p.in[p.pos:], []byte("null")):
		p.pos += 4
		return Value{kind: kNull}, nil
	}
	return Value{}, Malformed
}

func (p *parser) object(depth int) (Value, error) {
	p.pos++
	v := Value{kind: kObject}
	seen := map[string]bool{}
	if p.peek() == '}' {
		p.pos++
		return v, nil
	}
	for {
		if p.peek() != '"' {
			return Value{}, Malformed
		}
		k, err := p.string()
		if err != nil || seen[k] || p.peek() != ':' {
			return Value{}, Malformed
		}
		seen[k] = true
		p.pos++
		val, err := p.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		v.members = append(v.members, member{k, val})
		switch p.peek() {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return v, nil
		default:
			return Value{}, Malformed
		}
	}
}

func (p *parser) array(depth int) (Value, error) {
	p.pos++
	v := Value{kind: kArray, items: []Value{}}
	if p.peek() == ']' {
		p.pos++
		return v, nil
	}
	for {
		item, err := p.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		v.items = append(v.items, item)
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return v, nil
		default:
			return Value{}, Malformed
		}
	}
}

func (p *parser) peek() byte {
	if p.pos < len(p.in) {
		return p.in[p.pos]
	}
	return 0
}

func (p *parser) string() (string, error) {
	p.pos++
	var b strings.Builder
	for p.pos < len(p.in) {
		c := p.in[p.pos]
		switch {
		case c == '"':
			p.pos++
			return b.String(), nil
		case c < 0x20:
			return "", Malformed
		case c == '\\':
			if p.pos+1 >= len(p.in) {
				return "", Malformed
			}
			e := p.in[p.pos+1]
			p.pos += 2
			switch e {
			case '"', '\\', '/':
				b.WriteByte(e)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				if p.pos+4 > len(p.in) {
					return "", Malformed
				}
				n, err := strconv.ParseUint(string(p.in[p.pos:p.pos+4]), 16, 16)
				if err != nil {
					return "", Malformed
				}
				p.pos += 4
				// Only control characters need an escape, so any other is a second spelling.
				if n >= 0x20 {
					return "", Malformed
				}
				b.WriteByte(byte(n))
			default:
				return "", Malformed
			}
		default:
			r, size := utf8.DecodeRune(p.in[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", Malformed
			}
			b.Write(p.in[p.pos : p.pos+size])
			p.pos += size
		}
	}
	return "", Malformed
}

func (p *parser) number() (Value, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	for p.pos < len(p.in) && p.in[p.pos] >= '0' && p.in[p.pos] <= '9' {
		p.pos++
	}
	// A fraction or exponent is never a field's value, and would be a second spelling.
	if c := p.peek(); c == '.' || c == 'e' || c == 'E' {
		return Value{}, Malformed
	}
	text := string(p.in[start:p.pos])
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != text {
		return Value{}, Malformed
	}
	return Value{kind: kNumber, num: n}, nil
}

func (v Value) encode(out *bytes.Buffer) {
	switch v.kind {
	case kString:
		encodeString(out, v.str)
	case kNumber:
		out.WriteString(strconv.FormatInt(v.num, 10))
	case kBool:
		out.WriteString(strconv.FormatBool(v.boolean))
	case kNull:
		out.WriteString("null")
	case kArray:
		out.WriteByte('[')
		for i, item := range v.items {
			if i > 0 {
				out.WriteByte(',')
			}
			item.encode(out)
		}
		out.WriteByte(']')
	case kObject:
		out.WriteByte('{')
		for i, m := range v.members {
			if i > 0 {
				out.WriteByte(',')
			}
			encodeString(out, m.key)
			out.WriteByte(':')
			m.val.encode(out)
		}
		out.WriteByte('}')
	}
}

func encodeString(out *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if c < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hex[c>>4])
				out.WriteByte(hex[c&0xf])
			} else {
				out.WriteByte(c)
			}
		}
	}
	out.WriteByte('"')
}

// Encoded gives the value's one encoding.
func (v Value) Encoded() []byte {
	var out bytes.Buffer
	v.encode(&out)
	return out.Bytes()
}

// fields holds an object's members, checked against the exact order the protocol signs them in.
type fields map[string]Value

// shape requires exactly the required keys in order, then any of the optional keys in their order.
func shape(v Value, required []string, optional ...string) (fields, error) {
	if v.kind != kObject || len(v.members) < len(required) {
		return nil, Malformed
	}
	out := fields{}
	for i, k := range required {
		if v.members[i].key != k {
			return nil, Malformed
		}
		out[k] = v.members[i].val
	}
	next := 0
	for _, m := range v.members[len(required):] {
		for next < len(optional) && optional[next] != m.key {
			next++
		}
		if next == len(optional) {
			return nil, Malformed
		}
		out[m.key] = m.val
		next++
	}
	return out, nil
}

func (f fields) has(k string) bool { _, ok := f[k]; return ok }

func (f fields) str(k string) (string, error) {
	v, ok := f[k]
	if !ok || v.kind != kString {
		return "", Malformed
	}
	return v.str, nil
}

// optStr reads a string or null.
func (f fields) optStr(k string) (string, bool, error) {
	v, ok := f[k]
	if !ok || v.kind == kNull {
		return "", false, nil
	}
	if v.kind != kString {
		return "", false, Malformed
	}
	return v.str, true, nil
}

func (f fields) num(k string) (int64, error) {
	v, ok := f[k]
	if !ok || v.kind != kNumber {
		return 0, Malformed
	}
	return v.num, nil
}

// date is a whole number of unix seconds.
func (f fields) date(k string) (int64, error) {
	n, err := f.num(k)
	if err != nil || n < 0 {
		return 0, Malformed
	}
	return n, nil
}

func (f fields) version(want int64) error {
	n, err := f.num("v")
	if err != nil || n != want {
		return Malformed
	}
	return nil
}

func (f fields) id(k string) (string, error) {
	s, err := f.str(k)
	if err != nil || !isID(s) {
		return "", Malformed
	}
	return s, nil
}

func (f fields) hash(k string) (string, error) {
	s, err := f.str(k)
	if err != nil || !isHash(s) {
		return "", Malformed
	}
	return s, nil
}

func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isID(s string) bool {
	rest, ok := strings.CutPrefix(s, "splint1")
	return ok && isHash(rest)
}

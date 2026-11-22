package verifier

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
	"strings"
)

// The keys an owner's page derives: the backup key from a recovery code, and the sealing key from a
// passkey's PRF. See "Keys an owner's page derives" in docs/protocol.md.

const (
	recoveryCodeBytes = 16
	recoveryCodeChars = 26
	prfOutputBytes    = 32
	derivedBytes      = 48
)

var p256Order, _ = new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

// hkdf is RFC 5869's extract then expand, with SHA-256.
func hkdf(secret, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	prk := extract.Sum(nil)
	var out, block []byte
	for counter := byte(1); len(out) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		expand.Write(block)
		expand.Write(info)
		expand.Write([]byte{counter})
		block = expand.Sum(nil)
		out = append(out, block...)
	}
	return out[:length]
}

// derivedPoint is the public point of the scalar a secret gives: 48 bytes of HKDF-SHA256 under salt
// with the info "p256 scalar", read big-endian, modulo the order less one, plus one.
func derivedPoint(secret, salt []byte) (Point, error) {
	okm := new(big.Int).SetBytes(hkdf(secret, salt, []byte("p256 scalar"), derivedBytes))
	lessOne := new(big.Int).Sub(p256Order, big.NewInt(1))
	scalar := okm.Mod(okm, lessOne)
	scalar.Add(scalar, big.NewInt(1))
	key, err := ecdh.P256().NewPrivateKey(scalar.FillBytes(make([]byte, 32)))
	if err != nil {
		return nil, Malformed
	}
	return Point(key.PublicKey().Bytes()), nil
}

// RecoveryBackup is the backup key a recovery code names, typed in any case with spaces or dashes
// anywhere, which must leave 26 base32 characters whose 2 spare bits are zero.
func RecoveryBackup(typed string) (Point, error) {
	var plain strings.Builder
	for _, r := range typed {
		if r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		plain.WriteRune(r)
	}
	encoded := strings.ToLower(plain.String())
	code, err := lowerBase32.DecodeString(encoded)
	if err != nil || len(encoded) != recoveryCodeChars || len(code) != recoveryCodeBytes ||
		lowerBase32.EncodeToString(code) != encoded {
		return nil, Malformed
	}
	return derivedPoint(code, []byte("splint backup v1"))
}

// LockFromPRF is a sign-in's lock, which its copy of the reading key is sealed to, from what its
// passkey's PRF gave.
func LockFromPRF(output []byte) (Point, error) {
	if len(output) != prfOutputBytes {
		return nil, Malformed
	}
	return derivedPoint(output, []byte("splint sign-in lock v1"))
}

// SealingFromPRF is an owner's sealing key from what their passkey's PRF gave.
func SealingFromPRF(output []byte) (Point, error) {
	if len(output) != prfOutputBytes {
		return nil, Malformed
	}
	return derivedPoint(output, []byte("splint owner sealing v1"))
}

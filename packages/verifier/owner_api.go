package verifier

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"unicode"
	"unicode/utf8"
)

// An owner's session, the proof its key makes for one read, and the owner's sealed list of their
// agents. See "Owner API" in docs/protocol.md.

const (
	maxSessionSecs  = 12 * 60 * 60
	maxSessionChars = 4096
	maxListChars    = 32 * 1024
	minSealedBytes  = 65 + 16
	maxListedAgents = 64
	maxLabelChars   = 64
	scalarBytes     = 32
)

// Session is an owner's signed session: the key their page reads with, at one host, until Expires.
type Session struct {
	Owner   string
	Key     Point
	Expires int64
	name    string // the hex SHA-256 of its signing input, which a proof names
}

// VerifySession is a host's check: signed by owner's key now, naming them and host, lasting at most
// 12 hours, and not over. An owner who hasn't confirmed has no session.
func VerifySession(compact string, owner Identity, host string, now int64) (Session, error) {
	if len(compact) > maxSessionChars {
		return Session{}, Malformed
	}
	if owner.unconfirmedOwner() {
		return Session{}, WrongSigner
	}
	s, err := openAs(compact, "splint-owner-session", owner.Counting)
	if err != nil {
		return Session{}, err
	}
	f, err := shape(s.Body, []string{"v", "owner", "key", "host", "issued_at", "expires_at"})
	if err != nil || f.version(1) != nil {
		return Session{}, Malformed
	}
	out := Session{name: s.InputHash()}
	if out.Owner, err = f.id("owner"); err != nil {
		return Session{}, err
	}
	key, err := f.str("key")
	if err != nil {
		return Session{}, Malformed
	}
	if out.Key, err = parsePoint(key); err != nil {
		return Session{}, err
	}
	named, err := f.str("host")
	if err != nil {
		return Session{}, Malformed
	}
	issued, err := f.date("issued_at")
	if err != nil {
		return Session{}, err
	}
	if out.Expires, err = f.date("expires_at"); err != nil {
		return Session{}, err
	}
	if out.Expires <= issued || out.Expires-issued > maxSessionSecs {
		return Session{}, Malformed
	}
	if out.Owner != owner.ID {
		return Session{}, WrongSigner
	}
	if named != host {
		return Session{}, ProofMismatch
	}
	if issued > now+clockTolerance {
		return Session{}, FromTheFuture
	}
	if now >= out.Expires {
		return Session{}, Expired
	}
	return out, nil
}

// VerifyOwnerAccess checks a read by an owner's session: the session as VerifySession does, then the
// session key's ES256 proof for exactly this call, naming that session, within the tolerance either
// way. It gives the owner.
func VerifyOwnerAccess(session, proof string, owner Identity, host, method, path string, body []byte, now int64) (string, error) {
	sess, err := VerifySession(session, owner, host, now)
	if err != nil {
		return "", err
	}
	s, err := open(proof, "splint-owner-access", Signer{Point: sess.Key})
	if err != nil {
		return "", err
	}
	f, err := shape(s.Body, []string{"session", "host", "method", "path", "body_sha256", "issued_at"})
	if err != nil {
		return "", err
	}
	named, err := f.hash("session")
	if err != nil {
		return "", err
	}
	issued, err := f.date("issued_at")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	gotHost, _ := f.str("host")
	gotMethod, _ := f.str("method")
	gotPath, _ := f.str("path")
	gotBody, _ := f.str("body_sha256")
	if named != sess.name || gotHost != host || gotMethod != method || gotPath != path || gotBody != hex.EncodeToString(sum[:]) {
		return "", ProofMismatch
	}
	if issued < now-clockTolerance {
		return "", Expired
	}
	if issued > now+clockTolerance {
		return "", FromTheFuture
	}
	return sess.Owner, nil
}

// OwnerAgents is an owner's signed list of their agents. What's in it is sealed to the owner.
type OwnerAgents struct {
	Owner    string
	Handle   string // the owner's passkey's user handle, in lowercase hex
	Seq      int64
	Sealed   []byte // to the owner's sealing key
	Recovery []byte // the same, to the owner's backup
}

// VerifyOwnerAgents is a host's check of a list it keeps: signed by owner's key now, naming them and
// host, not dated ahead, naming a 32-byte handle, and holding two sealed notes in their one spelling.
func VerifyOwnerAgents(compact string, owner Identity, host string, now int64) (OwnerAgents, error) {
	if len(compact) > maxListChars {
		return OwnerAgents{}, Malformed
	}
	if owner.unconfirmedOwner() {
		return OwnerAgents{}, WrongSigner
	}
	s, err := openAs(compact, "splint-owner-agents", owner.Counting)
	if err != nil {
		return OwnerAgents{}, err
	}
	f, err := shape(s.Body, []string{"v", "owner", "host", "handle", "seq", "issued_at", "agents", "recovery"})
	if err != nil || f.version(1) != nil {
		return OwnerAgents{}, Malformed
	}
	out := OwnerAgents{}
	if out.Owner, err = f.id("owner"); err != nil {
		return OwnerAgents{}, err
	}
	named, err := f.str("host")
	if err != nil {
		return OwnerAgents{}, Malformed
	}
	if out.Seq, err = f.num("seq"); err != nil || out.Seq < 0 {
		return OwnerAgents{}, Malformed
	}
	issued, err := f.date("issued_at")
	if err != nil {
		return OwnerAgents{}, err
	}
	if out.Handle, err = f.str("handle"); err != nil || !isLowerHex(out.Handle, 64) {
		return OwnerAgents{}, Malformed
	}
	sealed, err := f.str("agents")
	if err != nil {
		return OwnerAgents{}, Malformed
	}
	if out.Sealed, err = b64(sealed); err != nil || len(out.Sealed) < minSealedBytes {
		return OwnerAgents{}, Malformed
	}
	copied, err := f.str("recovery")
	if err != nil {
		return OwnerAgents{}, Malformed
	}
	if out.Recovery, err = b64(copied); err != nil || len(out.Recovery) < minSealedBytes {
		return OwnerAgents{}, Malformed
	}
	if out.Owner != owner.ID {
		return OwnerAgents{}, WrongSigner
	}
	if named != host {
		return OwnerAgents{}, ProofMismatch
	}
	if issued > now+clockTolerance {
		return OwnerAgents{}, FromTheFuture
	}
	return out, nil
}

// ListedAgent is one of an owner's agents, as they listed it.
type ListedAgent struct {
	Agent   string `json:"agent"`
	Address string `json:"address"`
	Label   string `json:"label"`
	Backup  string `json:"backup"` // the agent's next backup, its private scalar
	// BesideOwner is 1 when the agent's Signet runs on the computer whose sign-in wrote the list, 0
	// when not, and left out by a page and by older lists.
	BesideOwner *int64 `json:"beside_owner,omitempty"`
}

// OpenOwnerAgents is the owner's own reading of a list that verified, with the sealing key their ID
// names: sealed under associated data naming them, holding their own backup key, which their ID
// commits to, and at most 64 agents, each a real agent's ID, its address in its one spelling, a label
// of 1 to 64 characters with no hidden characters, and a 32-byte backup, with no ID twice, then
// "code_saved": 1 if the owner said so, and 0 before.
func OpenOwnerAgents(list OwnerAgents, sealing *ecdh.PrivateKey, owner Identity) ([]ListedAgent, error) {
	plain, err := openNote(sealing, list.Sealed, []byte("splint owner agents for "+list.Owner))
	if err != nil {
		return nil, err
	}
	v, err := parsePayload(plain)
	if err != nil {
		return nil, Malformed
	}
	f, err := shape(v, []string{"v", "backup", "agents"}, "code_saved")
	if err != nil || f.version(1) != nil || f["agents"].kind != kArray || len(f["agents"].items) > maxListedAgents {
		return nil, Malformed
	}
	// One digit either way, so a list's size doesn't say which.
	if saved, has := f["code_saved"]; has && (saved.kind != kNumber || (saved.num != 0 && saved.num != 1)) {
		return nil, Malformed
	}
	backup, err := f.str("backup")
	if err != nil {
		return nil, Malformed
	}
	// Until the owner sets their recovery code there's no backup, and the list names none.
	if owner.recoveryIsLater() {
		if backup != "" {
			return nil, Malformed
		}
	} else {
		point, err := parsePoint(backup)
		if err != nil {
			return nil, Malformed
		}
		if err := CheckBackup(owner, point); err != nil {
			return nil, err
		}
	}
	out := []ListedAgent{}
	seen := map[string]bool{}
	for _, item := range f["agents"].items {
		listed, err := readListed(item)
		if err != nil || seen[listed.Agent] {
			return nil, Malformed
		}
		seen[listed.Agent] = true
		out = append(out, listed)
	}
	return out, nil
}

func readListed(v Value) (ListedAgent, error) {
	f, err := shape(v, []string{"agent", "address", "label", "backup"}, "beside_owner")
	if err != nil {
		return ListedAgent{}, Malformed
	}
	out := ListedAgent{}
	// One digit either way, so a list's size doesn't say how many run beside the owner.
	if beside, has := f["beside_owner"]; has {
		if beside.kind != kNumber || (beside.num != 0 && beside.num != 1) {
			return ListedAgent{}, Malformed
		}
		n := beside.num
		out.BesideOwner = &n
	}
	if out.Agent, err = f.id("agent"); err != nil {
		return ListedAgent{}, Malformed
	}
	if out.Address, err = f.str("address"); err != nil {
		return ListedAgent{}, Malformed
	}
	if _, _, err := ParseAddress(out.Address); err != nil {
		return ListedAgent{}, Malformed
	}
	out.Label, err = f.str("label")
	chars := utf8.RuneCountInString(out.Label)
	if err != nil || chars == 0 || chars > maxLabelChars || hasHiddenCharacters(out.Label) {
		return ListedAgent{}, Malformed
	}
	if out.Backup, err = f.str("backup"); err != nil {
		return ListedAgent{}, Malformed
	}
	scalar, err := b64(out.Backup)
	if err != nil || len(scalar) != scalarBytes {
		return ListedAgent{}, Malformed
	}
	if _, err := ecdh.P256().NewPrivateKey(scalar); err != nil {
		return ListedAgent{}, Malformed
	}
	return out, nil
}

// RecoveryHandle is what a computer's sign-in names its list by: the lowercase hex SHA-256 of
// "splint owner list handle v1" then the owner's backup's 65-byte point, which only the recovery code
// gives, as an ID holds only its hash.
func RecoveryHandle(backup []byte) string {
	sum := sha256.Sum256(append([]byte("splint owner list handle v1"), backup...))
	return hex.EncodeToString(sum[:])
}

// openNote opens a sealed note: HPKE base mode with DHKEM P-256, HKDF-SHA256 and AES-128-GCM, info
// "splint sealed note v1", the encapsulated key then the ciphertext.
func openNote(key *ecdh.PrivateKey, sealed, about []byte) ([]byte, error) {
	if len(sealed) < minSealedBytes {
		return nil, Malformed
	}
	private, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, Malformed
	}
	recipient, err := hpke.NewRecipient(sealed[:65], private, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte("splint sealed note v1"))
	if err != nil {
		return nil, CantOpen
	}
	plain, err := recipient.Open(about, sealed[65:])
	if err != nil {
		return nil, CantOpen
	}
	return plain, nil
}

// hasHiddenCharacters says whether text holds a character that could hide what words say, as "Hidden
// characters" in docs/protocol.md lists them.
func hasHiddenCharacters(text string) bool {
	for _, r := range text {
		if unicode.Is(unicode.Cc, r) || isHiddenRune(r) {
			return true
		}
	}
	return false
}

var hiddenRanges = [][2]rune{
	{0xAD, 0xAD}, {0x34F, 0x34F}, {0x600, 0x605}, {0x61C, 0x61C}, {0x6DD, 0x6DD}, {0x70F, 0x70F},
	{0x890, 0x891}, {0x8E2, 0x8E2}, {0x115F, 0x1160}, {0x17B4, 0x17B5}, {0x180B, 0x180F},
	{0x200B, 0x200F}, {0x2028, 0x202E}, {0x2060, 0x206F}, {0x2800, 0x2800}, {0x3164, 0x3164},
	{0xE000, 0xF8FF}, {0xFDD0, 0xFDEF}, {0xFE00, 0xFE0F}, {0xFEFF, 0xFEFF}, {0xFFA0, 0xFFA0},
	{0xFFF0, 0xFFFB}, {0xFFFE, 0xFFFF}, {0x110BD, 0x110BD}, {0x110CD, 0x110CD}, {0x13430, 0x1343F},
	{0x1BCA0, 0x1BCA3}, {0x1D159, 0x1D159}, {0x1D173, 0x1D17A}, {0xE0000, 0xE0FFF}, {0xF0000, 0x10FFFF},
}

func isHiddenRune(r rune) bool {
	for _, span := range hiddenRanges {
		if r >= span[0] && r <= span[1] {
			return true
		}
	}
	return false
}

// OwnerView is what an agent's Signet leaves its owner, as its key signed it.
type OwnerView struct {
	Issued int64
	View   []byte // the view object, as its Signet wrote it
}

// VerifyOwnerView is an owner's device's check of a view it opened: signed by agent's key now, ES256,
// naming that agent and owner, version 1, with the view an object, and not dated ahead. Anyone can seal
// to an owner, so sealing says nothing about who wrote it, and this does.
func VerifyOwnerView(compact string, agent Identity, owner string, now int64) (OwnerView, error) {
	if err := agent.asAgent(); err != nil {
		return OwnerView{}, err
	}
	s, err := open(compact, "splint-owner-view", agent.Key())
	if err != nil {
		return OwnerView{}, err
	}
	f, err := shape(s.Body, []string{"v", "agent", "owner", "issued_at", "view"})
	if err != nil || f.version(1) != nil || f["view"].kind != kObject {
		return OwnerView{}, Malformed
	}
	named, err := f.id("agent")
	if err != nil {
		return OwnerView{}, err
	}
	forOwner, err := f.id("owner")
	if err != nil {
		return OwnerView{}, err
	}
	issued, err := f.date("issued_at")
	if err != nil {
		return OwnerView{}, err
	}
	if named != agent.ID || forOwner != owner {
		return OwnerView{}, WrongSigner
	}
	if issued > now+clockTolerance {
		return OwnerView{}, FromTheFuture
	}
	return OwnerView{Issued: issued, View: f["view"].Encoded()}, nil
}

// OpenReadingKeyCopy opens one sign-in's locked copy of an owner's reading key with that sign-in's
// lock, and gives the reading key's point only if it's the sealing key the owner's ID names now, as
// "The reading key, with many sign-ins" in docs/protocol.md has it.
func OpenReadingKeyCopy(text string, owner Identity, lock *ecdh.PrivateKey) (Point, error) {
	if len(text) > 1024 {
		return nil, Malformed
	}
	v, err := parsePayload([]byte(text))
	if err != nil {
		return nil, Malformed
	}
	f, err := shape(v, []string{"v", "owner", "key", "lock", "sealed"})
	if err != nil || f.version(1) != nil {
		return nil, Malformed
	}
	ownerID, err := f.id("owner")
	if err != nil {
		return nil, Malformed
	}
	key, err := f.hash("key")
	if err != nil {
		return nil, Malformed
	}
	lockText, err := f.str("lock")
	if err != nil {
		return nil, Malformed
	}
	lockPoint, err := parsePoint(lockText)
	if err != nil {
		return nil, Malformed
	}
	if _, err := ecdh.P256().NewPublicKey(lockPoint); err != nil {
		return nil, Malformed
	}
	sealedText, err := f.str("sealed")
	if err != nil {
		return nil, Malformed
	}
	sealed, err := b64(sealedText)
	if err != nil || len(sealed) != 65+scalarBytes+16 {
		return nil, Malformed
	}
	if ownerID != owner.ID {
		return nil, ProofMismatch
	}
	counts := false
	for _, k := range owner.Counting {
		counts = counts || hashHex(k.Point) == key
	}
	if !counts || string(lock.PublicKey().Bytes()) != string(lockPoint) {
		return nil, WrongSigner
	}
	plain, err := openNote(lock, sealed, []byte("splint reading key for "+ownerID+" by "+key))
	if err != nil {
		return nil, err
	}
	reading, err := ecdh.P256().NewPrivateKey(plain)
	if err != nil {
		return nil, Malformed
	}
	point := reading.PublicKey().Bytes()
	if string(point) != string(owner.Seals[len(owner.Seals)-1]) {
		return nil, ProofMismatch
	}
	return point, nil
}

// maxSealedCallBytes is the most a call to an agent's Signet on the network can be, as sent.
const maxSealedCallBytes = 360 * 1024

// OpenOwnerCall opens what an owner's device sent to their agent's Signet over a network its operator
// turned on: {"sealed"} and nothing else, at most 360 KiB, a sealed note to the agent's sealing key
// under associated data "splint owner call METHOD PATH for AGENT". What comes out is the call's own
// body, which says nothing of who sent it until the owner's signature inside is checked.
func OpenOwnerCall(call []byte, sealing *ecdh.PrivateKey, agent, method, path string) ([]byte, error) {
	if len(call) > maxSealedCallBytes {
		return nil, Malformed
	}
	v, err := parsePayload(call)
	if err != nil {
		return nil, Malformed
	}
	f, err := shape(v, []string{"sealed"})
	if err != nil {
		return nil, Malformed
	}
	text, err := f.str("sealed")
	if err != nil {
		return nil, Malformed
	}
	sealed, err := b64(text)
	if err != nil {
		return nil, Malformed
	}
	return openNote(sealing, sealed, []byte("splint owner call "+method+" "+path+" for "+agent))
}

// OpenOwnerMail opens what an owner's device left at their agent's host for its Signet: an owner call
// sealed for POST /v0/owner-mail/AGENT and no other, over {"kind","signed"} followed by spaces up to a
// multiple of 1024 bytes, so its size doesn't say which kind it is. What's signed says nothing of who
// signed it until that's checked as it is on Signet's own socket.
func OpenOwnerMail(mail []byte, sealing *ecdh.PrivateKey, agent string) (kind, signed string, err error) {
	plain, err := OpenOwnerCall(mail, sealing, agent, "POST", "/v0/owner-mail/"+agent)
	if err != nil {
		return "", "", err
	}
	v, err := parsePayload(bytes.TrimRight(plain, " "))
	if err != nil {
		return "", "", Malformed
	}
	f, err := shape(v, []string{"kind", "signed"})
	if err != nil {
		return "", "", Malformed
	}
	if kind, err = f.str("kind"); err != nil {
		return "", "", Malformed
	}
	switch kind {
	case "approval", "acceptance", "person_text", "delegation", "where_paid":
	default:
		return "", "", Malformed
	}
	if signed, err = f.str("signed"); err != nil {
		return "", "", Malformed
	}
	return kind, signed, nil
}

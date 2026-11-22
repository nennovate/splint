package verifier

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// Each check named in spec/vectors, run through this verifier's public calls.
func init() {
	register("identity.parse", func(in input) (map[string]any, error) {
		id, err := ParseIdentityEvent(in.str("raw"))
		return map[string]any{"id": id}, err
	})
	register("identity.read", func(in input) (map[string]any, error) {
		id, err := ReadIdentity(in.str("identity"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id.ID, "key": id.Key().String(), "recoveries": id.Recoveries()}, nil
	})
	register("identity.check_backup", func(in input) (map[string]any, error) {
		id, err := ReadIdentity(in.str("identity"))
		if err != nil {
			return nil, err
		}
		backup, err := parsePoint(in.str("backup_key"))
		if err != nil {
			return nil, err
		}
		return map[string]any{}, CheckBackup(id, backup)
	})
	register("identity.newest", func(in input) (map[string]any, error) {
		pinned, err := ReadIdentity(in.str("pinned"))
		if err != nil {
			return nil, err
		}
		claimed, err := ReadIdentity(in.str("claimed"))
		if err != nil {
			return nil, err
		}
		newest, err := Newest(pinned, claimed)
		if err != nil {
			return nil, err
		}
		return map[string]any{"key": newest.Key().String()}, nil
	})
	register("identity.keys", func(in input) (map[string]any, error) {
		id, err := ReadIdentity(in.str("identity"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id.ID, "keys": points(id.Counting), "recoveries": id.Recoveries(), "statements": len(id.steps)}, nil
	})
	register("identity.newest_keys", func(in input) (map[string]any, error) {
		ids, err := identities(in, "pinned", "claimed")
		if err != nil {
			return nil, err
		}
		newest, err := Newest(ids[0], ids[1])
		if err != nil {
			return nil, err
		}
		return map[string]any{"keys": points(newest.Counting)}, nil
	})
	register("envelope.verify", func(in input) (map[string]any, error) {
		sender, err := ReadIdentity(in.str("sender_identity"))
		if err != nil {
			return nil, err
		}
		e, err := VerifyEnvelope(in.str("compact"), sender, in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": e.ID(), "sender": e.Sender, "recipient": e.Recipient, "body": e.Body,
			"created_at": e.CreatedAt, "expires_at": e.ExpiresAt}, nil
	})
}

func init() {
	register("approval.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		a, err := VerifyApproval(in.str("approval"), owner, in.num("now"))
		if err != nil {
			return nil, err
		}
		emits := map[string]string{"approve": "confirm", "deny": "decline"}[a.Decision]
		return map[string]any{"decision": a.Decision, "emits": emits}, nil
	})
	register("grant.check", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		g, err := CheckGrant(owner, Call{Grant: in.str("grant"), Proof: in.str("proof"), HolderIdentity: in.str("agent_identity"),
			Resource: in.str("resource"), Operation: in.str("operation"), Method: in.str("method"), Path: in.str("path"),
			Body: []byte(in.str("body")), Revoked: in.strs("revoked"), CallsThisHour: in.num("calls_this_hour"), Now: in.num("now")})
		if err != nil {
			return nil, err
		}
		return map[string]any{"grant": g.Grant, "holder": g.Holder, "operation": g.Operation}, nil
	})
	register("revocation.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		grant, err := VerifyRevocation(in.str("revocation"), owner)
		return map[string]any{"revoked": grant}, err
	})
}

// points spells each key as the vectors do.
func points(keys []Signer) []any {
	out := []any{}
	for _, k := range keys {
		out = append(out, k.String())
	}
	return out
}

func identities(in input, names ...string) ([]Identity, error) {
	out := []Identity{}
	for _, n := range names {
		id, err := ReadIdentity(in.str(n))
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func init() {
	register("binding.verify", func(in input) (map[string]any, error) {
		ids, err := identities(in, "owner_identity", "agent_identity")
		if err != nil {
			return nil, err
		}
		_, err = VerifyBindingFor(in.str("binding"), ids[0], ids[1], in.str("address"))
		return map[string]any{}, err
	})
	register("binding.replace", func(in input) (map[string]any, error) {
		ids, err := identities(in, "owner_identity", "agent_identity", "current_owner_identity")
		if err != nil {
			return nil, err
		}
		return map[string]any{}, MayReplace(in.str("binding"), ids[0], ids[1], ids[2], in.num("current_seq"))
	})
	register("release.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		r, err := VerifyRelease(in.str("release"), owner, owner.Counting, in.str("agent"))
		if err != nil {
			return nil, err
		}
		var to any
		if r.To != "" {
			to = r.To
		}
		return map[string]any{"to": to}, nil
	})
	register("retirement.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		agent, err := VerifyRetirement(in.str("retirement"), owner)
		return map[string]any{"agent": agent}, err
	})
	register("address.parse", func(in input) (map[string]any, error) {
		name, domain, err := ParseAddress(in.str("address"))
		return map[string]any{"name": name, "domain": domain}, err
	})
}

func history(v any) (History, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return History{}, err
	}
	return ParseHistory(raw)
}

func init() {
	register("history.verify", func(in input) (map[string]any, error) {
		h, err := history(in["history"])
		if err != nil {
			return nil, err
		}
		s, err := VerifyHistory(h)
		if err != nil {
			return nil, err
		}
		kinds, proofs := []string{}, []string{}
		for _, c := range s.Changes {
			kinds, proofs = append(kinds, c.Kind), append(proofs, c.Proof)
		}
		return map[string]any{"head": s.Head(), "kinds": kinds, "proofs": proofs, "owner": s.Owner, "address": s.Address}, nil
	})
}

func init() {
	register("history.against", func(in input) (map[string]any, error) {
		seen, err := history(in["seen"])
		if err != nil {
			return nil, err
		}
		heard, err := history(in["new"])
		if err != nil {
			return nil, err
		}
		against, err := Against(seen, heard)
		return map[string]any{"against": against}, err
	})
	register("history.respond", func(in input) (map[string]any, error) {
		h, err := history(in["history"])
		if err != nil {
			return nil, err
		}
		answers := map[string]string{}
		for k, v := range in.obj("rules") {
			answers[k], _ = v.(string)
		}
		// A reader's record of when it first saw each sign-in, and its clock, turn on the 48-hour guard.
		_, guard := in["now"]
		seen := map[string]int64{}
		if list, ok := in["sign_ins_seen"].([]any); ok {
			for _, item := range list {
				one, _ := item.(map[string]any)
				name, _ := one["name"].(string)
				at, _ := one["at"].(float64)
				seen[name] = int64(at)
			}
		}
		response, err := RespondAt(h, in.str("accepted"), answers, seen, guard, in.num("now"))
		return map[string]any{"response": response}, err
	})
	register("acceptance.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		a, err := VerifyAcceptance(in.str("acceptance"), owner, in.str("agent"))
		return map[string]any{"contact": a.Contact, "head": a.Head}, err
	})
}

func side(in input) (Side, error) {
	agent, err := ReadIdentity(in.str("agent_identity"))
	if err != nil {
		return Side{}, err
	}
	owner, err := ReadIdentity(in.str("owner_identity"))
	if err != nil {
		return Side{}, err
	}
	if agent.ID != in.str("agent_id") || owner.ID != in.str("owner_id") {
		return Side{}, ProofMismatch
	}
	return Side{Agent: agent, Owner: owner}, nil
}

func loadSchemas() (map[string]Schema, error) {
	files, err := filepath.Glob("../../spec/schemas/*.json")
	if err != nil {
		return nil, err
	}
	out := map[string]Schema{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		s, err := ParseSchema(raw)
		if err != nil {
			return nil, err
		}
		out[s.ID] = s
	}
	return out, nil
}

func walk(in input) (map[string]any, error) {
	r, err := side(in.obj("requester"))
	if err != nil {
		return nil, err
	}
	t, err := side(in.obj("recipient"))
	if err != nil {
		return nil, err
	}
	schemas, err := loadSchemas()
	if err != nil {
		return nil, err
	}
	// Any type both sides agreed, beside the examples.
	agreed, _ := in["schemas"].([]any)
	for _, schema := range agreed {
		raw, err := json.Marshal(schema)
		if err != nil {
			return nil, err
		}
		s, err := ParseSchema(raw)
		if err != nil {
			return nil, err
		}
		schemas[s.ID] = s
	}
	w, err := WalkChain(r, t, schemas, in.strs("chain"), in.num("now"), in.num("last_arrived_at"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"state": w.State, "version": w.Version, "head": w.Head, "over_cap": w.OverCap, "copies_dropped": w.CopiesDropped, "payment": w.Payment}, nil
}

// typeID is a type's ID, which this verifier works out from its schema's one encoding.
func typeID(in input) (map[string]any, error) {
	raw, err := json.Marshal(in["schema"])
	if err != nil {
		return nil, err
	}
	s, err := ParseSchema(raw)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "type": s.ID, "one_encoding": string(s.encoding)}, nil
}

// typePropose is what core holds a proposed schema to.
func typePropose(in input) (map[string]any, error) {
	raw, err := json.Marshal(in["schema"])
	if err != nil {
		return nil, err
	}
	s, err := ParseSchema(raw)
	if err != nil {
		return nil, err
	}
	if err := s.checkProposal(); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func init() {
	register("type.id", typeID)
	register("type.propose", typePropose)
	register("request.walk", walk)
	register("request.person_text", walk)
}

func init() {
	register("access_proof.verify", func(in input) (map[string]any, error) {
		signer, err := ReadIdentity(in.str("identity"))
		if err != nil {
			return nil, err
		}
		// Bytes are base64url in a vector, apart from grant.check's body.
		body, err := b64(in.str("body"))
		if err != nil {
			return nil, err
		}
		agent, err := VerifyAccessProof(in.str("compact"), signer, in.str("host"), in.str("method"), in.str("path"), body, in.num("now"))
		return map[string]any{"agent": agent}, err
	})
}

func init() {
	register("ask.verify", func(in input) (map[string]any, error) {
		agent, err := ReadIdentity(in.str("agent_identity"))
		if err != nil {
			return nil, err
		}
		a, err := VerifyAsk(in.str("ask"), agent, in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": a.ID, "changes": a.Changes}, nil
	})
	register("ask.answer", func(in input) (map[string]any, error) {
		keptAt, err := CheckAskAnswer(in.str("ask_id"), in.str("owner"), in.str("mac"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"kept_at": keptAt}, nil
	})
	register("invite.verify", func(in input) (map[string]any, error) {
		inviter, err := ReadIdentity(in.str("inviter_identity"))
		if err != nil {
			return nil, err
		}
		i, err := VerifyInvite(in.str("invite"), inviter, in.str("invitee"), in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": i.ID()}, nil
	})
	register("invite.pending", func(in input) (map[string]any, error) {
		c, err := VerifyPendingContact(in.str("invite"), in.str("acceptance"), in.str("inviter_identity"), in.str("invitee_identity"), in.str("inviter_owner_identity"), in.str("inviter_binding"), in.str("invitee_owner_identity"), in.str("invitee_binding"), in.str("own"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"contact": c.Agent, "address": c.Address, "invited_by_us": c.InvitedByUs}, nil
	})
	register("card.parse", func(in input) (map[string]any, error) {
		address, agent, err := ParseCard(in.str("card"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"address": address, "agent": agent}, nil
	})
	register("pairing.code", func(in input) (map[string]any, error) {
		c, err := ParseCode(in.str("code"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"host": c.Host, "id": c.ID(), "owner": c.Owner()}, nil
	})
	register("pairing.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		p, err := VerifyPairing(in.str("pairing"), in.str("session"), owner, in.str("host"), in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": p.ID, "expires_at": p.Expires}, nil
	})
	register("pairing.opener", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		code, err := ParseCode(in.str("code"))
		if err != nil {
			return nil, err
		}
		p, err := VerifyOpener(in.str("pairing"), in.str("session"), owner, code, in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"owner": p.Owner}, nil
	})
	register("pairing.answer", func(in input) (map[string]any, error) {
		code, err := ParseCode(in.str("code"))
		if err != nil {
			return nil, err
		}
		a := in.obj("answer")
		paired, err := CheckPairingAnswer(code, a.str("agent_identity"), a.str("address"), a.str("delegate"), a.str("mac"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"agent": paired.Agent, "address": paired.Address, "delegate": paired.Delegate}, nil
	})
	register("owner_view.verify", func(in input) (map[string]any, error) {
		agent, err := ReadIdentity(in.str("agent_identity"))
		if err != nil {
			return nil, err
		}
		v, err := VerifyOwnerView(in.str("view"), agent, in.str("owner"), in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"issued_at": v.Issued, "view": json.RawMessage(v.View)}, nil
	})
	register("owner_session.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		s, err := VerifySession(in.str("session"), owner, in.str("host"), in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"owner": s.Owner, "key": s.Key.String(), "expires_at": s.Expires}, nil
	})
	register("owner_access.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		body, err := b64(in.str("body"))
		if err != nil {
			return nil, err
		}
		who, err := VerifyOwnerAccess(in.str("session"), in.str("proof"), owner, in.str("host"), in.str("method"), in.str("path"), body, in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"owner": who}, nil
	})
	register("recovery_code.backup", func(in input) (map[string]any, error) {
		backup, err := RecoveryBackup(in.str("code"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "backup": backup.String(), "commitment": hashHex(backup)}, nil
	})
	register("prf.sealing_key", func(in input) (map[string]any, error) {
		output, err := hex.DecodeString(in.str("prf"))
		if err != nil {
			return nil, Malformed
		}
		seal, err := SealingFromPRF(output)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "seal": seal.String()}, nil
	})
	register("prf.lock_key", func(in input) (map[string]any, error) {
		output, err := hex.DecodeString(in.str("prf"))
		if err != nil {
			return nil, Malformed
		}
		lock, err := LockFromPRF(output)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "lock": lock.String()}, nil
	})
	register("owner_agents.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		l, err := VerifyOwnerAgents(in.str("list"), owner, in.str("host"), in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"seq": l.Seq, "handle": l.Handle}, nil
	})
	register("reading_key.open", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		scalar, err := hex.DecodeString(in.str("lock"))
		if err != nil {
			return nil, Malformed
		}
		lock, err := ecdh.P256().NewPrivateKey(scalar)
		if err != nil {
			return nil, Malformed
		}
		seal, err := OpenReadingKeyCopy(in.str("copy"), owner, lock)
		if err != nil {
			return nil, err
		}
		return map[string]any{"seal": base64.RawURLEncoding.EncodeToString(seal)}, nil
	})
	register("owner_agents.open", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		l, err := VerifyOwnerAgents(in.str("list"), owner, in.str("host"), in.num("now"))
		if err != nil {
			return nil, err
		}
		scalar, err := hex.DecodeString(in.str("sealing"))
		if err != nil {
			return nil, Malformed
		}
		sealing, err := ecdh.P256().NewPrivateKey(scalar)
		if err != nil {
			return nil, Malformed
		}
		agents, err := OpenOwnerAgents(l, sealing, owner)
		if err != nil {
			return nil, err
		}
		return map[string]any{"agents": agents}, nil
	})
	register("owner_agents.handle", func(in input) (map[string]any, error) {
		point, err := parsePoint(in.str("backup"))
		if err != nil {
			return nil, Malformed
		}
		return map[string]any{"handle": RecoveryHandle([]byte(point))}, nil
	})
	register("owner_call.open", func(in input) (map[string]any, error) {
		scalar, err := hex.DecodeString(in.str("sealing"))
		if err != nil {
			return nil, Malformed
		}
		sealing, err := ecdh.P256().NewPrivateKey(scalar)
		if err != nil {
			return nil, Malformed
		}
		body, err := OpenOwnerCall([]byte(in.str("call")), sealing, in.str("agent"), in.str("method"), in.str("path"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"body": string(body)}, nil
	})
	register("owner_mail.open", func(in input) (map[string]any, error) {
		scalar, err := hex.DecodeString(in.str("sealing"))
		if err != nil {
			return nil, Malformed
		}
		sealing, err := ecdh.P256().NewPrivateKey(scalar)
		if err != nil {
			return nil, Malformed
		}
		kind, signed, err := OpenOwnerMail([]byte(in.str("mail")), sealing, in.str("agent"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"kind": kind, "signed": signed}, nil
	})
	register("delegation.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		agent, err := ReadIdentity(in.str("agent_identity"))
		if err != nil {
			return nil, err
		}
		d, err := VerifyDelegation(in.str("delegation"), owner, agent, in.num("newest_seq_seen"), in.num("now"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"seq": d.Seq, "may": d.May}, nil
	})
	register("carried_approval.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		agent, err := ReadIdentity(in.str("agent_identity"))
		if err != nil {
			return nil, err
		}
		schemas, err := loadSchemas()
		if err != nil {
			return nil, err
		}
		readBack, _ := in["read_back"].(bool)
		a, delegated, err := readCarriedApproval(in.str("approval"), owner, agent, schemas[in.str("type")], readBack)
		if err != nil {
			return nil, err
		}
		emits := map[string]string{"approve": "confirm", "deny": "decline"}[a.Decision]
		return map[string]any{"decision": a.Decision, "emits": emits, "by_delegate": delegated}, nil
	})
	register("delegated_approval.verify", func(in input) (map[string]any, error) {
		owner, err := ReadIdentity(in.str("owner_identity"))
		if err != nil {
			return nil, err
		}
		agent, err := ReadIdentity(in.str("agent_identity"))
		if err != nil {
			return nil, err
		}
		schemas, err := loadSchemas()
		if err != nil {
			return nil, err
		}
		readBack, _ := in["read_back"].(bool)
		a, err := readDelegatedApproval(in.str("approval"), owner, agent, schemas[in.str("type")], readBack)
		if err != nil {
			return nil, err
		}
		return map[string]any{"decision": a.Decision, "emits": "confirm"}, nil
	})
}

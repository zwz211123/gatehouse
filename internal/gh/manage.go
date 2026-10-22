package gh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"strings"

	"golang.org/x/crypto/ssh"
)

func (c *Core) Change(ws *WebSession, q Change, source string) (any, error) {
	actor := ws.User
	if c.auditFailed.Load() {
		return nil, errorf("audit unavailable")
	}
	var acting User
	if c.Store.Get("user", actor, &acting) != nil || !acting.Enabled {
		return nil, ErrDenied
	}
	if q.Kind == "credential" && q.Operation == "test" {
		var input struct {
			Account string `json:"account"`
		}
		if json.Unmarshal(q.Data, &input) != nil || !c.webAllowed(ws, "credential.test", q.ID) || !c.webAllowed(ws, "account.read", input.Account) {
			return nil, ErrDenied
		}
		var a Account
		if c.Store.Get("account", input.Account, &a) != nil || a.Credential != q.ID {
			return nil, errorf("account does not reference credential")
		}
		client, e := c.DialTarget(actor, a.ID)
		if e != nil {
			return nil, errorf("target connection or host-key check failed")
		}
		client.Close()
		return map[string]bool{"ok": true}, c.Audit(actor, "credential.test", q.ID, "ok", source, "")
	}
	if q.Kind == "settings" || q.Kind == "backup" {
		return c.systemChange(ws, q, source)
	}
	if q.Kind == "ticket" && q.Operation == "revoke" {
		var t Ticket
		if c.Store.Get("ticket", q.ID, &t) != nil || (!c.webAllowed(ws, "proxy.revoke", q.ID) && !c.webAllowed(ws, "proxy.revoke", t.Spec.Account)) {
			return nil, ErrDenied
		}
		return map[string]bool{"ok": true}, c.Revoke(actor, q.ID, source)
	}
	if q.Kind == "session" && q.Operation == "terminate" {
		if !c.webAllowed(ws, "session.terminate", q.ID) {
			return nil, ErrDenied
		}
		c.mu.Lock()
		l := c.live[q.ID]
		if l != nil {
			l.Close()
		}
		c.mu.Unlock()
		return map[string]bool{"ok": true}, c.Audit(actor, "session.terminate", q.ID, "ok", source, "")
	}
	if !contains([]string{"user", "key", "group", "asset", "account", "credential", "grant"}, q.Kind) || !contains([]string{"create", "update", "delete"}, q.Operation) {
		return nil, errorf("unsupported operation")
	}
	action := q.Kind + "." + q.Operation
	res := q.ID
	if q.Operation == "create" {
		res = "*"
	}
	permitted := c.webAllowed(ws, action, res)
	if q.Kind == "grant" {
		var target Grant
		if q.Operation == "create" {
			json.Unmarshal(q.Data, &target)
		} else {
			c.Store.Get("grant", q.ID, &target)
		}
		if len(target.Resources) > 0 {
			permitted = true
			for _, scope := range target.Resources {
				if !c.webAllowed(ws, action, scope) {
					permitted = false
				}
			}
		}
		if q.Operation == "update" {
			var update Grant
			json.Unmarshal(q.Data, &update)
			for _, scope := range update.Resources {
				if !c.webAllowed(ws, action, scope) {
					permitted = false
				}
			}
		}
	}
	if !permitted {
		return nil, ErrDenied
	}
	var old map[string]any
	if q.Operation != "create" {
		if c.Store.Get(q.Kind, q.ID, &old) != nil {
			return nil, errorf("record not found")
		}
		visible := map[string]any{}
		for k, v := range old {
			if k != "cipher" {
				visible[k] = v
			}
		}
		if q.ETag == "" || q.ETag != hash(encode(visible)) {
			return nil, errorf("record changed; reload before editing")
		}
	}
	if q.Operation != "create" && q.Kind == "grant" {
		var g Grant
		if c.Store.Get("grant", q.ID, &g) != nil {
			return nil, ErrDenied
		}
		if !acting.Owner && (g.Deny || g.Issuer != actor) {
			return nil, ErrDenied
		}
	}
	if q.Operation != "create" && q.Kind == "group" && !acting.Owner {
		gs, e := list[Grant](c.Store, "grant")
		if e != nil {
			return nil, e
		}
		var next Group
		if q.Operation == "update" {
			if e = json.Unmarshal(q.Data, &next); e != nil {
				return nil, e
			}
		}
		var previous Group
		c.Store.Get("group", q.ID, &previous)
		for _, g := range gs {
			if g.Group == q.ID && g.Deny {
				for _, member := range previous.Members {
					if q.Operation == "delete" || !contains(next.Members, member) {
						return nil, errorf("only an owner may remove deny-group members")
					}
				}
			}
		}
	}
	if q.Operation == "delete" {
		if q.Kind == "user" {
			var target User
			c.Store.Get("user", q.ID, &target)
			if target.Owner && (!acting.Owner || !c.webAllowed(ws, "user.owner", "*")) {
				return nil, ErrDenied
			}
		}
		if q.Kind == "key" {
			var k Key
			var target, acting User
			c.Store.Get("key", q.ID, &k)
			c.Store.Get("user", k.User, &target)
			c.Store.Get("user", actor, &acting)
			if !c.webAllowed(ws, "user.update", k.User) || (target.Owner && !acting.Owner) {
				return nil, ErrDenied
			}
		}
		if q.Kind == "user" || q.Kind == "key" {
			if !c.safeOwnerRemoval(q.Kind, q.ID) {
				return nil, errorf("cannot remove last effective owner")
			}
		}
		if q.Kind == "credential" {
			xs, _ := list[Account](c.Store, "account")
			for _, a := range xs {
				if a.Credential == q.ID {
					return nil, errorf("credential is referenced")
				}
			}
		}
		if q.Kind == "asset" {
			xs, _ := list[Account](c.Store, "account")
			for _, a := range xs {
				if a.Asset == q.ID {
					return nil, errorf("asset is referenced")
				}
			}
		}
		if q.Kind == "user" {
			old["enabled"] = false
			old["owner"] = false
			return map[string]bool{"ok": true}, c.changeRecord(actor, q.Kind, q.ID, old, false, source)
		}
		return map[string]bool{"ok": true}, c.changeRecord(actor, q.Kind, q.ID, nil, true, source)
	}
	id := q.ID
	if q.Operation == "create" {
		id = newID()
	}
	var v any
	switch q.Kind {
	case "user":
		var x User
		if e := json.Unmarshal(q.Data, &x); e != nil {
			return nil, e
		}
		x.ID = id
		if !allowedName(x.Name) {
			return nil, errorf("invalid username")
		}
		xs, _ := list[User](c.Store, "user")
		for _, u := range xs {
			if u.Name == x.Name && u.ID != id {
				return nil, errorf("username exists")
			}
		}
		if q.Operation == "update" && old["name"] != x.Name {
			return nil, errorf("username is immutable")
		}
		var acting User
		c.Store.Get("user", actor, &acting)
		if x.Owner || (q.Operation == "update" && old["owner"] != x.Owner) {
			if !acting.Owner || !c.webAllowed(ws, "user.owner", "*") {
				return nil, ErrDenied
			}
		}
		if (!x.Enabled || !x.Owner) && q.Operation == "update" && !c.safeOwnerRemoval("user", id) {
			return nil, errorf("cannot disable last owner")
		}
		v = x
	case "key":
		var x Key
		if e := json.Unmarshal(q.Data, &x); e != nil {
			return nil, e
		}
		x.ID = id
		var u User
		if c.Store.Get("user", x.User, &u) != nil {
			return nil, errorf("user not found")
		}
		var acting User
		c.Store.Get("user", actor, &acting)
		if !c.webAllowed(ws, "user.update", x.User) || (u.Owner && !acting.Owner) {
			return nil, ErrDenied
		}
		if q.Operation == "update" && old["user"] != x.User {
			return nil, errorf("key owner is immutable")
		}
		p, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(x.Public))
		if e != nil || len(strings.TrimSpace(string(rest))) != 0 || !validUserKey(p) {
			return nil, errorf("invalid single public key")
		}
		if p.Type() == "ssh-dss" {
			return nil, errorf("DSA is not supported")
		}
		x.Public = strings.TrimSpace(string(sshPublic(p)))
		x.Fingerprint = ssh.FingerprintSHA256(p)
		xs, _ := list[Key](c.Store, "key")
		for _, k := range xs {
			if k.ID != id && k.Fingerprint == x.Fingerprint {
				return nil, errorf("public key already registered")
			}
		}
		if !x.Enabled && q.Operation == "update" && !c.safeOwnerRemoval("key", id) {
			return nil, errorf("cannot disable last owner key")
		}
		v = x
	case "asset":
		var x Asset
		if e := json.Unmarshal(q.Data, &x); e != nil {
			return nil, e
		}
		x.ID = id
		if x.Host == "" || len(x.Host) > 253 || strings.ContainsAny(x.Host, "/\x00 \n\r") || x.Port < 1 || x.Port > 65535 {
			return nil, errorf("invalid address")
		}
		if x.AllowSpecial && !c.webAllowed(ws, "asset.special", res) {
			return nil, errorf("asset.special required")
		}
		oldKeys := ""
		if q.Operation == "update" {
			oldKeys = encode(old["host_keys"])
		}
		if encode(x.HostKeys) != oldKeys && len(x.HostKeys) > 0 && !c.webAllowed(ws, "asset.trust", res) {
			return nil, errorf("asset.trust required")
		}
		for _, s := range x.HostKeys {
			if _, _, _, _, e := ssh.ParseAuthorizedKey([]byte(s)); e != nil {
				return nil, errorf("invalid host public key")
			}
		}
		x.Version = 1
		if old != nil {
			x.Version = int(old["version"].(float64)) + 1
		}
		v = x
	case "account":
		var x Account
		if e := json.Unmarshal(q.Data, &x); e != nil {
			return nil, e
		}
		x.ID = id
		var a Asset
		var cred Credential
		if c.Store.Get("asset", x.Asset, &a) != nil || c.Store.Get("credential", x.Credential, &cred) != nil || x.Name == "" || len(x.Name) > 128 {
			return nil, errorf("invalid account binding")
		}
		if !c.webAllowed(ws, "credential.bind", x.Credential) {
			return nil, errorf("credential.bind required")
		}
		if !c.webAllowed(ws, "asset.update", x.Asset) {
			return nil, errorf("asset.update required for account binding")
		}
		if x.ChrootVerified && !c.webAllowed(ws, "account.chroot", res) {
			return nil, errorf("account.chroot required")
		}
		x.Version = 1
		if old != nil {
			x.Version = int(old["version"].(float64)) + 1
		}
		v = x
	case "credential":
		var input struct {
			Credential
			Private    string `json:"private"`
			Passphrase string `json:"passphrase"`
			Generate   bool   `json:"generate"`
		}
		if e := json.Unmarshal(q.Data, &input); e != nil {
			return nil, e
		}
		if len(input.Private) > 65536 || len(input.Passphrase) > 4096 {
			return nil, errorf("private key input too large")
		}
		if input.Generate && input.Private != "" {
			return nil, errorf("choose either generate or import, not both")
		}
		x := input.Credential
		x.ID = id
		x.Cipher = ""
		if input.Generate {
			if !c.webAllowed(ws, "credential.generate", res) {
				return nil, ErrDenied
			}
			_, priv, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return nil, e
			}
			b, e := ssh.MarshalPrivateKey(priv, "Gatehouse")
			if e != nil {
				return nil, e
			}
			input.Private = string(pem.EncodeToMemory(b))
		} else if input.Private != "" && !c.webAllowed(ws, "credential.import", res) {
			return nil, ErrDenied
		}
		if input.Private == "" {
			if old == nil {
				return nil, errorf("private key or generate required")
			}
			x.Cipher, _ = old["cipher"].(string)
			x.Public, _ = old["public"].(string)
			x.Fingerprint, _ = old["fingerprint"].(string)
		} else {
			var raw any
			var e error
			if input.Passphrase != "" {
				raw, e = ssh.ParseRawPrivateKeyWithPassphrase([]byte(input.Private), []byte(input.Passphrase))
			} else {
				raw, e = ssh.ParseRawPrivateKey([]byte(input.Private))
			}
			if e != nil {
				return nil, errorf("invalid private key or passphrase")
			}
			signer, e := ssh.NewSignerFromKey(raw)
			if e != nil {
				return nil, e
			}
			block, e := ssh.MarshalPrivateKey(raw, "Gatehouse")
			if e != nil {
				return nil, e
			}
			x.Public = strings.TrimSpace(string(sshPublic(signer.PublicKey())))
			x.Fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
			x.Cipher, e = c.Store.Seal(id, pem.EncodeToMemory(block))
			if e != nil {
				return nil, e
			}
		}
		x.Version = 1
		if old != nil {
			x.Version = int(old["version"].(float64)) + 1
		}
		v = x
	case "grant":
		var x Grant
		if e := json.Unmarshal(q.Data, &x); e != nil {
			return nil, e
		}
		x.ID = id
		x.Issuer = actor
		if q.Operation == "update" {
			var prev Grant
			c.Store.Get("grant", id, &prev)
			if prev.Issuer != actor {
				var u User
				c.Store.Get("user", actor, &u)
				if !u.Owner {
					return nil, ErrDenied
				}
			}
		}
		if e := c.Store.ValidateGrant(actor, x); e != nil {
			return nil, e
		}
		v = x
	case "group":
		var x Group
		if e := json.Unmarshal(q.Data, &x); e != nil {
			return nil, e
		}
		x.ID = id
		var prev Group
		if old != nil {
			c.Store.Get("group", id, &prev)
		}
		grants, _ := list[Grant](c.Store, "grant")
		for _, member := range x.Members {
			var u User
			if c.Store.Get("user", member, &u) != nil {
				return nil, errorf("unknown group member")
			}
			if contains(prev.Members, member) {
				continue
			}
			for _, g := range grants {
				if g.Group != id {
					continue
				}
				g.Group = ""
				g.Subject = member
				if !c.webAllowed(ws, "grant.create", "*") {
					return nil, errorf("grant.create required to add group members")
				}
				if e := c.Store.ValidateGrant(actor, g); e != nil {
					return nil, errorf("membership would bypass delegation scope")
				}
			}
		}
		v = x
	}
	if e := c.changeRecord(actor, q.Kind, id, v, false, source); e != nil {
		return nil, e
	}
	var m map[string]any
	json.Unmarshal([]byte(encode(v)), &m)
	delete(m, "cipher")
	return map[string]any{"data": m, "etag": hash(encode(m))}, nil
}
func (c *Core) changeRecord(actor, kind, id string, v any, del bool, source string) error {
	tx, e := c.Store.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	event := Event{Time: now(), Actor: actor, Action: kind + ".change", Resource: id, Result: "ok", Source: source}
	if _, e = tx.Exec("INSERT INTO audits(data)VALUES(?)", encode(event)); e != nil {
		c.auditFailed.Store(true)
		return e
	}
	if del {
		_, e = tx.Exec("DELETE FROM records WHERE kind=? AND id=?", kind, id)
	} else {
		_, e = tx.Exec("INSERT INTO records(kind,id,data)VALUES(?,?,?)ON CONFLICT(kind,id)DO UPDATE SET data=excluded.data,revision=records.revision+1", kind, id, encode(v))
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (c *Core) safeOwnerRemoval(kind, id string) bool {
	users, _ := list[User](c.Store, "user")
	keys, _ := list[Key](c.Store, "key")
	for _, u := range users {
		if !u.Owner || !u.Enabled || (kind == "user" && u.ID == id) {
			continue
		}
		for _, k := range keys {
			if k.User == u.ID && k.Enabled && !(kind == "key" && k.ID == id) {
				return true
			}
		}
	}
	return false
}

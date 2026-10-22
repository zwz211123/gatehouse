package gh

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func (c *Core) WebHandler() http.Handler { return http.HandlerFunc(c.webHandler) }
func (c *Core) webHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.Method == "GET" && r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, indexHTML)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/app.js" {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		io.WriteString(w, appJS)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/style.css" {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		io.WriteString(w, styleCSS)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/challenge" {
		v := random(32)
		http.SetCookie(w, &http.Cookie{Name: "__Host-ghb-csrf", Value: v, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 300})
		jsonOut(w, 200, map[string]string{"csrf": v})
		return
	}
	if r.Method != "GET" {
		origin, e := url.Parse(c.Config.WebURL)
		if e != nil || r.Header.Get("Origin") != origin.Scheme+"://"+origin.Host {
			jsonOut(w, 403, map[string]string{"error": "invalid origin"})
			return
		}
		cookie, e := r.Cookie("__Host-ghb-csrf")
		csrf := r.Header.Get("X-CSRF-Token")
		if e != nil || len(csrf) < 32 || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(csrf)) != 1 {
			jsonOut(w, 403, map[string]string{"error": "invalid CSRF token"})
			return
		}
	}
	source := r.Header.Get("X-Gatehouse-Remote")
	if r.URL.Path == "/api/redeem" && r.Method == "POST" {
		if !c.Rate("web:"+hostOnly(source), 10) {
			jsonOut(w, 429, map[string]string{"error": "rate limit"})
			return
		}
		var q struct{ Token string }
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&q) != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		c.mu.Lock()
		token, ok := c.tokens[hash(q.Token)]
		if !ok || token.Purpose != "login" || token.Expires <= now() || !c.sourceAlive(token.Source) {
			c.mu.Unlock()
			jsonOut(w, 401, map[string]string{"error": "token expired or invalid"})
			return
		}
		if _, ok = c.Store.AllowedFrom(token.User, "web.login", "*", source); !ok {
			c.mu.Unlock()
			jsonOut(w, 403, map[string]string{"error": "permission denied"})
			return
		}
		if c.Audit(token.User, "web.redeem", token.Source, "ok", source, "") != nil {
			c.mu.Unlock()
			jsonOut(w, 503, map[string]string{"error": "audit unavailable"})
			return
		}
		delete(c.tokens, hash(q.Token))
		for h, w := range c.web {
			if w.Source == token.Source {
				delete(c.web, h)
			}
		}
		id := random(32)
		snapshot := map[string]bool{}
		resources := []string{"*"}
		for _, kind := range []string{"asset", "account", "credential", "user", "key", "group", "grant"} {
			items, _ := list[map[string]any](c.Store, kind)
			for _, v := range items {
				if s, ok := v["id"].(string); ok {
					resources = append(resources, s)
				}
			}
		}
		gs, _ := list[Grant](c.Store, "grant")
		for _, g := range gs {
			resources = append(resources, g.Resources...)
		}
		for _, a := range Capabilities {
			for _, res := range resources {
				if _, yes := c.Store.AllowedFrom(token.User, a, res, source); yes {
					snapshot[a+":"+res] = true
				}
			}
		}
		c.web[hash(id)] = &WebSession{SourceAddr: source, User: token.User, Source: token.Source, Key: token.Key, Created: now(), Last: now(), Snapshot: snapshot, Fresh: map[string]int64{}}
		c.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "__Host-ghb-session", Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 7200})
		jsonOut(w, 200, map[string]bool{"ok": true})
		return
	}
	session := c.webAuth(r)
	if session == nil {
		jsonOut(w, 401, map[string]string{"error": "SSH token login required"})
		return
	}
	switch r.URL.Path {
	case "/api/settings":
		if r.Method != "GET" || !c.webAllowed(session, "config.read", "*") {
			jsonOut(w, 403, map[string]string{"error": "permission denied"})
			return
		}
		x := c.settings()
		jsonOut(w, 200, []any{map[string]any{"data": x, "etag": hash(encode(x))}})
		return
	case "/api/logout":
		if r.Method != "POST" {
			break
		}
		cookie, _ := r.Cookie("__Host-ghb-session")
		c.mu.Lock()
		delete(c.web, hash(cookie.Value))
		c.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "__Host-ghb-session", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true})
		jsonOut(w, 200, map[string]bool{"ok": true})
		return
	case "/api/me":
		if r.Method != "GET" {
			break
		}
		var u User
		c.Store.Get("user", session.User, &u)
		jsonOut(w, 200, map[string]any{"user": u, "version": Version, "capabilities": Capabilities})
		return
	case "/api/records":
		if r.Method != "GET" {
			break
		}
		kind := r.URL.Query().Get("kind")
		if !contains([]string{"user", "key", "group", "asset", "account", "credential", "grant", "ticket"}, kind) {
			break
		}
		items, e := list[map[string]any](c.Store, kind)
		if e != nil {
			jsonOut(w, 500, map[string]string{"error": "database unavailable"})
			return
		}
		out := []any{}
		action := kind + ".read"
		if kind == "ticket" {
			action = "proxy.read"
		}
		for _, v := range items {
			id, _ := v["id"].(string)
			visible := c.webAllowed(session, action, id)
			if kind == "grant" {
				var g Grant
				if c.Store.Get("grant", id, &g) == nil && len(g.Resources) > 0 {
					all := true
					for _, scope := range g.Resources {
						if !c.webAllowed(session, "grant.read", scope) {
							all = false
						}
					}
					visible = visible || all
				}
			}
			if kind == "ticket" {
				var t Ticket
				if c.Store.Get("ticket", id, &t) == nil {
					visible = visible || c.webAllowed(session, "proxy.read", t.Spec.Account)
				}
			}
			if !visible {
				continue
			}
			if kind == "credential" {
				delete(v, "cipher")
			}
			out = append(out, map[string]any{"data": v, "etag": hash(encode(v))})
		}
		jsonOut(w, 200, out)
		return
	case "/api/audit":
		if r.Method != "GET" {
			break
		}
		es, _ := c.Store.Events(1000)
		out := []Event{}
		for _, e := range es {
			if c.webAllowed(session, "audit.read", e.Resource) {
				out = append(out, e)
			}
		}
		jsonOut(w, 200, out)
		return
	case "/api/audit/export":
		if r.Method != "GET" {
			break
		}
		es, _ := c.Store.Events(1000)
		out := []Event{}
		for _, e := range es {
			if c.webAllowed(session, "audit.read", e.Resource) && c.webAllowed(session, "audit.export", e.Resource) {
				out = append(out, e)
			}
		}
		w.Header().Set("Content-Disposition", "attachment; filename=gatehouse-audit.json")
		jsonOut(w, 200, out)
		return
	case "/api/sessions":
		if r.Method != "GET" {
			break
		}
		out := []any{}
		c.mu.Lock()
		for _, l := range c.live {
			if l.User == session.User || c.webAllowed(session, "session.read", l.ID) {
				out = append(out, map[string]any{"id": l.ID, "user": l.User, "source": l.Source, "kind": l.Kind, "ticket": l.Ticket, "created": l.Created})
			}
		}
		c.mu.Unlock()
		jsonOut(w, 200, out)
		return
	case "/api/change":
		if r.Method != "POST" {
			break
		}
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 24<<20))
		if e != nil {
			jsonOut(w, 400, map[string]string{"error": "body too large"})
			return
		}
		digest := hash(string(body))
		confirmation := r.Header.Get("X-GHB-Confirmation")
		if !c.consumeConfirm(session, confirmation, digest) {
			jsonOut(w, 428, map[string]string{"error": "SSH confirmation required", "digest": digest, "command": "web confirm " + digest})
			return
		}
		var q Change
		if json.Unmarshal(body, &q) != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid JSON"})
			return
		}
		c.management.Lock()
		v, e := c.Change(session, q, source)
		c.management.Unlock()
		c.Revalidate()
		if e != nil {
			jsonOut(w, 403, map[string]string{"error": e.Error()})
			return
		}
		jsonOut(w, 200, v)
		return
	}
	jsonOut(w, 404, map[string]string{"error": "not found"})
}
func (c *Core) webAuth(r *http.Request) *WebSession {
	cookie, e := r.Cookie("__Host-ghb-session")
	if e != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.web[hash(cookie.Value)]
	if s == nil || s.Last+900 <= now() || s.Created+7200 <= now() || !c.sourceAlive(s.Source) {
		return nil
	}
	select {
	case <-c.live[s.Source].Cancel:
		return nil
	default:
	}
	if _, ok := c.Store.AllowedFrom(s.User, "web.login", "*", r.Header.Get("X-Gatehouse-Remote")); !ok {
		return nil
	}
	s.Last = now()
	copy := *s
	copy.SourceAddr = r.Header.Get("X-Gatehouse-Remote")
	return &copy
}
func (c *Core) webAllowed(s *WebSession, a, res string) bool {
	if !s.Snapshot[a+":"+res] && !s.Snapshot[a+":*"] {
		return false
	}
	_, ok := c.Store.AllowedFrom(s.User, a, res, s.SourceAddr)
	return ok
}
func (c *Core) Confirm(l *Live, digest string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sourceAlive(l.ID) || c.auditFailed.Load() {
		return ""
	}
	for h, t := range c.tokens {
		if t.Source == l.ID && t.Purpose == "confirm" {
			delete(c.tokens, h)
		}
	}
	v := random(24)
	c.tokens[hash(v)] = WebToken{User: l.User, Source: l.ID, Key: digest, Purpose: "confirm", Expires: now() + 300}
	return v
}
func (c *Core) consumeConfirm(w *WebSession, code, digest string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.tokens[hash(code)]
	if !c.sourceAlive(w.Source) || c.auditFailed.Load() || !ok || t.Purpose != "confirm" || t.User != w.User || t.Source != w.Source || t.Key != digest || t.Expires <= now() {
		return false
	}
	delete(c.tokens, hash(code))
	return true
}

type Change struct {
	Kind      string          `json:"kind"`
	Operation string          `json:"operation"`
	ID        string          `json:"id"`
	ETag      string          `json:"etag"`
	Data      json.RawMessage `json:"data"`
}

func allowedName(s string) bool {
	if len(s) < 1 || len(s) > 64 || strings.HasPrefix(s, "ghp_") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func errorf(s string) error { return fmt.Errorf("%s", s) }

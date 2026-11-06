package gh

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebSessionsTargetsUsageAndResourceVisibility(t *testing.T) {
	f := setup(t)
	ticket, _ := f.ticket(t, Spec{Modes: []string{"shell"}})
	proxy := &Live{ID: "visible-proxy", User: f.l.User, Ticket: ticket.ID, Kind: "proxy", Created: now(), Cancel: make(chan struct{})}
	hidden := &Live{ID: "hidden-proxy", User: f.l.User, Ticket: ticket.ID, Kind: "proxy", Created: now(), Cancel: make(chan struct{})}
	if err := f.c.charge(proxy, ticket, 1536); err != nil {
		t.Fatal(err)
	}
	f.c.Store.Put("user", "reader", User{ID: "reader", Name: "reader", Enabled: true})
	f.c.Store.Put("key", "reader-key", Key{ID: "reader-key", User: "reader", Enabled: true})
	f.c.Store.Put("grant", "reader-web", Grant{ID: "reader-web", Issuer: f.l.User, Subject: "reader", Actions: []string{"web.login"}, Resources: []string{"*"}, Enabled: true})
	f.c.Store.Put("grant", "reader-session", Grant{ID: "reader-session", Issuer: f.l.User, Subject: "reader", Actions: []string{"session.read"}, Resources: []string{proxy.ID}, Enabled: true})
	reader := &Live{ID: "reader-source", User: "reader", Key: "reader-key", Kind: "menu", Created: now(), Cancel: make(chan struct{})}
	f.l.TargetMu.Lock()
	f.l.TargetAccount = "acct"
	f.l.TargetMu.Unlock()
	ownerWS := ownerWeb(f)
	ownerWS.Source = f.l.ID
	ownerWS.Created = now()
	ownerWS.Last = now()
	readerWS := &WebSession{User: "reader", Source: reader.ID, Key: reader.Key, Created: now(), Last: now(), Snapshot: map[string]bool{"session.read:" + proxy.ID: true}}
	f.c.mu.Lock()
	for _, l := range []*Live{proxy, hidden, reader} {
		f.c.live[l.ID] = l
	}
	f.c.web[hash("owner-session")] = ownerWS
	f.c.web[hash("reader-session")] = readerWS
	f.c.mu.Unlock()
	read := func(token string) map[string]map[string]any {
		t.Helper()
		r := httptest.NewRequest("GET", "https://localhost:8443/api/sessions", nil)
		r.AddCookie(&http.Cookie{Name: "__Host-ghb-session", Value: token})
		w := httptest.NewRecorder()
		f.c.WebHandler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		var rows []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		out := map[string]map[string]any{}
		for _, row := range rows {
			out[row["id"].(string)] = row
		}
		return out
	}
	ownerRows := read("owner-session")
	if ownerRows[proxy.ID]["account"] != "acct" || ownerRows[proxy.ID]["bytes"] != float64(1536) {
		t.Fatalf("missing target/usage: %+v", ownerRows[proxy.ID])
	}
	if ownerRows[f.l.ID]["account"] != "acct" {
		t.Fatal("ordinary target missing")
	}
	if _, ok := ownerRows[f.l.ID]["bytes"]; ok {
		t.Fatal("ordinary unmeasured traffic fabricated")
	}
	readerRows := read("reader-session")
	if len(readerRows) != 2 || readerRows[proxy.ID]["account"] != "acct" || readerRows[proxy.ID]["bytes"] != float64(1536) || readerRows[hidden.ID] != nil || readerRows[f.l.ID] != nil {
		t.Fatalf("session visibility leak: %+v", readerRows)
	}
	// Both the login snapshot and live permission are required for other users' data.
	f.c.mu.Lock()
	delete(readerWS.Snapshot, "session.read:"+proxy.ID)
	f.c.mu.Unlock()
	if rows := read("reader-session"); len(rows) != 1 || rows[reader.ID] == nil {
		t.Fatalf("snapshot bypass: %+v", rows)
	}
	f.c.mu.Lock()
	readerWS.Snapshot["session.read:"+proxy.ID] = true
	f.c.mu.Unlock()
	if err := f.c.Store.Delete("grant", "reader-session"); err != nil {
		t.Fatal(err)
	}
	if rows := read("reader-session"); len(rows) != 1 || rows[reader.ID] == nil {
		t.Fatalf("live permission bypass: %+v", rows)
	}
}

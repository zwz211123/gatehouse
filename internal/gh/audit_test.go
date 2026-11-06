package gh

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuditBoundaries(t *testing.T) {
	event := func(category, connection, operation, action, account, channel, result string) Event {
		return prepareEvent(Event{Category: category, ConnectionID: connection, OperationID: operation, Action: action, Account: account, ChannelID: channel, Result: result, Actor: "same-user", Source: "192.0.2.1", Ticket: "same-ticket", Time: 100})
	}
	es := []Event{
		event("access", "one", "", "ssh.login", "", "", "ok"),
		event("access", "one", "", "direct.start", "a", "shell", "ok"),
		event("access", "one", "", "direct.start", "b", "shell-2", "ok"),
		event("access", "one", "", "file.read", "b", "sftp", "attempt"),
		event("access", "one", "", "file.read", "b", "sftp", "eof"),
		event("access", "one", "", "file.remove", "b", "sftp", "denied"),
		event("access", "one", "", "connection.close", "", "", "ok"),
		event("access", "two", "", "ssh.login", "a", "", "ok"),
		event("management", "one", "create-1", "proxy.issue", "a", "", "ok"),
		event("management", "one", "create-2", "proxy.issue", "a", "", "ok"),
		event("auth", "one", "", "web.issue", "", "", "ok"),
		event("auth", "one", "", "web.issue", "", "", "ok"),
	}
	es = append(es, es[3]) // Repeated delivery must not inflate counts.
	groups := groupAuditEvents(es)
	if len(groups) != 6 {
		t.Fatalf("got %d groups", len(groups))
	}
	for _, g := range groups {
		if g.ID == "connection:one" {
			if g.EventCount != 7 || g.FailureCount != 1 || len(g.Targets) != 2 || len(g.Channels) != 3 || !g.Closed || g.Partial {
				t.Fatalf("wrong connection summary: %+v", g)
			}
			return
		}
	}
	t.Fatal("missing connection")
}

func TestAuditAuthorizationBeforeGroupingAndCompleteHistory(t *testing.T) {
	f := setup(t)
	c := f.c
	c.Store.Put("user", "reader", User{ID: "reader", Name: "reader", Enabled: true})
	c.Store.Put("grant", "audit-reader", Grant{ID: "audit-reader", Issuer: f.l.User, Subject: "reader", Actions: []string{"audit.read"}, Resources: []string{"acct"}, Enabled: true})
	ws := &WebSession{User: "reader", Snapshot: map[string]bool{"audit.read:*": true, "audit.export:*": true}}
	for i := 0; i < 1005; i++ {
		if err := c.AuditEvent(Event{Category: "access", ConnectionID: "visible", Account: "acct", Resource: "acct", Action: "file.read", Result: "ok", Time: now() + int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	c.AuditEvent(Event{Category: "access", ConnectionID: "visible", Account: "secret-target", Resource: "secret-target", Action: "file.remove", Result: "denied", Detail: "PRIVATE-PATH"})
	// Old entries have no trustworthy connection ID: do not infer one from identity/IP.
	for i := 0; i < 2; i++ {
		_, err := c.Store.db.Exec("INSERT INTO audits(data) VALUES(?)", encode(Event{Actor: "reader", Action: "file.read", Resource: "acct", Result: "ok", Time: now()}))
		if err != nil {
			t.Fatal(err)
		}
	}
	visible, err := c.visibleAuditEvents(ws, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1007 {
		t.Fatalf("history truncated: %d", len(visible))
	}
	groups := groupAuditEvents(visible)
	if len(groups) != 3 {
		t.Fatalf("legacy events guessed together: %d", len(groups))
	}
	for _, g := range groups {
		if g.ID == "connection:visible" && (g.EventCount != 1005 || g.FailureCount != 0 || len(g.Targets) != 1 || !g.Partial) {
			t.Fatalf("unauthorized summary: %+v", g)
		}
	}
	if strings.Contains(encode(groups), "PRIVATE-PATH") || strings.Contains(encode(groups), "secret-target") {
		t.Fatal("hidden event leaked")
	}
	exported, err := c.visibleAuditEvents(ws, true)
	if err != nil || len(exported) != 0 {
		t.Fatal("read permission allowed export", err)
	}
	c.Store.Put("grant", "audit-exporter", Grant{ID: "audit-exporter", Issuer: f.l.User, Subject: "reader", Actions: []string{"audit.export"}, Resources: []string{"acct"}, Enabled: true})
	exported, err = c.visibleAuditEvents(ws, true)
	if err != nil || len(exported) != 1007 {
		t.Fatalf("authorized export incomplete: %d %v", len(exported), err)
	}
	again, _ := c.visibleAuditEvents(ws, false)
	if visible[len(visible)-1].ID != again[len(again)-1].ID {
		t.Fatal("legacy ID unstable")
	}
	r := httptest.NewRequest("GET", "/api/audit/records?limit=1", nil)
	w := httptest.NewRecorder()
	c.auditRecordsHTTP(w, r, ws)
	var page struct {
		Records []AuditRecord `json:"records"`
		Total   int           `json:"total"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || len(page.Records) != 1 || len(page.Records[0].Events) != 0 {
		t.Fatalf("bad summary page: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	c.auditRecordsHTTP(w, httptest.NewRequest("GET", "/api/audit/records?id=connection:visible", nil), ws)
	var detail AuditRecord
	if err = json.Unmarshal(w.Body.Bytes(), &detail); err != nil || detail.EventCount != 1005 || len(detail.Events) != 1005 {
		t.Fatalf("incomplete detail: %d %d %v", detail.EventCount, len(detail.Events), err)
	}
}

func TestWebTicketCreationUsesBoundSourceAndSnapshot(t *testing.T) {
	f := setup(t)
	ws := ownerWeb(f)
	ws.Source = f.l.ID
	ws.Key = f.l.Key
	ws.ID = "web"
	ws.OperationID = "create"
	q := Change{Kind: "ticket", Operation: "create", Data: json.RawMessage(`{"account":"acct","modes":["shell"]}`)}
	value, err := f.c.Change(ws, q, "127.0.0.1:4321")
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	ticket := result["ticket"].(Ticket)
	if ticket.Owner != ws.User || ticket.Source != ws.Source || result["password"] == "" {
		t.Fatal("unbound temporary account")
	}
	events, _ := f.c.Store.Events(100)
	found := false
	for _, e := range events {
		if e.Action == "proxy.issue" && e.Ticket == ticket.ID {
			found = true
			if e.ConnectionID != ws.Source || e.OperationID != "create" || e.WebSessionID != "web" || e.Category != "management" {
				t.Fatalf("missing management context: %+v", e)
			}
			if strings.Contains(e.Detail, fmt.Sprint(result["password"])) {
				t.Fatal("password in audit")
			}
		}
	}
	if !found {
		t.Fatal("missing issue event")
	}
	delete(ws.Snapshot, "proxy.shell:*")
	if _, err = f.c.Change(ws, q, "127.0.0.1"); err == nil {
		t.Fatal("snapshot bypassed")
	}
	ws.Snapshot["proxy.shell:*"] = true
	ws.Source = "unrelated"
	if _, err = f.c.Change(ws, q, "127.0.0.1"); err == nil {
		t.Fatal("unbound source accepted")
	}
}

func TestRevokedEntryStillClosesWhenSourceKeyDisabled(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell"}, Total: 2, Reconnect: true})
	client, err := f.dial(ticket, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = f.c.Revoke(f.l.User, ticket.ID, f.l.Source); err != nil {
		t.Fatal(err)
	}
	var key Key
	if err = f.c.Store.Get("key", f.l.Key, &key); err != nil {
		t.Fatal(err)
	}
	key.Enabled = false
	f.c.Store.Put("key", key.ID, key)
	f.c.Revalidate()
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("disabled source key retained active connection")
	}
}

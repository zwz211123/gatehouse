package gh

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditSummaryAndLargeBodyExport(t *testing.T) {
	f := setup(t)
	ids := []string{}
	for i := 0; i < 600; i++ {
		id := fmt.Sprintf("%032x", i)
		if err := f.c.AuditEvent(Event{Category: "access", ConnectionID: id, Resource: "acct", Account: "acct", Action: "file.read", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, "connection:"+id)
	}
	if err := f.c.AuditEvent(Event{Category: "access", ConnectionID: "secret", Resource: "hidden", Account: "hidden", Action: "file.remove", Result: "denied", Detail: "PRIVATE-DETAIL"}); err != nil {
		t.Fatal(err)
	}
	ws := ownerWeb(f)
	ws.Source = f.l.ID
	ws.Key = f.l.Key
	ws.Created = now()
	ws.Last = now()
	// A broad current owner permission still cannot exceed the Web login snapshot.
	ws.Snapshot = map[string]bool{"audit.read:acct": true, "audit.export:acct": true}
	f.c.mu.Lock()
	f.c.web[hash("audit-session")] = ws
	f.c.mu.Unlock()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://localhost:8443"+path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "__Host-ghb-session", Value: "audit-session"})
		w := httptest.NewRecorder()
		f.c.WebHandler().ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/api/audit/records?limit=all", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var page struct {
		Records []AuditRecord `json:"records"`
		Total   int           `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 600 || len(page.Records) != 600 || strings.Contains(w.Body.String(), "PRIVATE-DETAIL") || strings.Contains(w.Body.String(), "hidden") {
		t.Fatalf("incomplete or unauthorized snapshot: %d/%d", page.Total, len(page.Records))
	}
	for _, g := range page.Records {
		if g.EventCount != 1 || len(g.Events) != 0 {
			t.Fatal("summary included details or lost counts")
		}
	}
	w = request("GET", "/api/audit/records?limit=100&offset=100", "")
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || page.Total != 600 || len(page.Records) != 100 {
		t.Fatal("legacy page contract changed", err)
	}

	// Exercise the real HTTP server request-line limit: the body is larger than
	// 16 KiB while the URL stays constant, including for a full filtered export.
	server := httptest.NewUnstartedServer(f.c.WebHandler())
	server.Config.MaxHeaderBytes = 16 << 10
	server.Start()
	defer server.Close()
	const csrf = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	export := func(body, origin, token string) (int, []byte) {
		t.Helper()
		r, err := http.NewRequest("POST", server.URL+"/api/audit/export", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", token)
		r.AddCookie(&http.Cookie{Name: "__Host-ghb-csrf", Value: csrf})
		r.AddCookie(&http.Cookie{Name: "__Host-ghb-session", Value: "audit-session"})
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	ids = append(ids, ids[0], "connection:secret")
	body := encode(map[string]any{"records": ids})
	if len(body) <= 16<<10 {
		t.Fatal("selection too small to reproduce long URL failure")
	}
	status, data := export(body, f.c.Config.WebURL, csrf)
	var events []Event
	if status != 200 || json.Unmarshal(data, &events) != nil || len(events) != 600 || strings.Contains(string(data), "PRIVATE-DETAIL") {
		t.Fatalf("large export failed or leaked: status %d, events %d", status, len(events))
	}
	status, data = export(encode(map[string]any{"records": []string{ids[0]}}), f.c.Config.WebURL, csrf)
	if status != 200 || json.Unmarshal(data, &events) != nil || len(events) != 1 || auditRecordKey(events[0]) != ids[0] {
		t.Fatal("selection was not respected")
	}
	status, data = export(`{"records":[]}`, f.c.Config.WebURL, csrf)
	if status != 200 || string(data) != "[]\n" {
		t.Fatalf("empty selection exported history: %d %s", status, data)
	}
	for _, bad := range []string{`{}`, `{"records":null}`, `{"records":"all"}`, `{"records":[]} {}`, `{"records":[],"extra":true}`} {
		if status, _ = export(bad, f.c.Config.WebURL, csrf); status != 400 {
			t.Fatalf("bad selection accepted: %s", bad)
		}
	}
	if status, _ = export(body, "https://other.test", csrf); status != 403 {
		t.Fatal("export bypassed Origin")
	}
	if status, _ = export(body, f.c.Config.WebURL, ""); status != 403 {
		t.Fatal("export bypassed CSRF")
	}
	f.c.mu.Lock()
	delete(ws.Snapshot, "audit.export:acct")
	f.c.mu.Unlock()
	status, data = export(body, f.c.Config.WebURL, csrf)
	if status != 200 || string(data) != "[]\n" {
		t.Fatal("read permission allowed export")
	}
	f.c.mu.Lock()
	ws.Snapshot["audit.export:acct"] = true
	delete(ws.Snapshot, "audit.read:acct")
	f.c.mu.Unlock()
	status, data = export(body, f.c.Config.WebURL, csrf)
	if status != 200 || string(data) != "[]\n" {
		t.Fatal("export permission bypassed read permission")
	}
	// Existing GET clients retain their export contract and resource checks.
	w = request("GET", "/api/audit/export?record="+ids[0], "")
	if w.Code != 200 || w.Body.String() != "[]\n" {
		t.Fatal("legacy export authorization changed")
	}
}

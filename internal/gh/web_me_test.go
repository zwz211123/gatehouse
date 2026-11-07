package gh

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestWebMeDoesNotDiscloseSnapshotAndReturnsEndpoints(t *testing.T) {
	f := setup(t)
	f.c.Store.Put("user", "reader", User{ID: "reader", Name: "reader", Enabled: true})
	f.c.Store.Put("key", "reader-key", Key{ID: "reader-key", User: "reader", Enabled: true})
	f.c.Store.Put("grant", "reader-web", Grant{ID: "reader-web", Issuer: f.l.User, Subject: "reader", Actions: []string{"web.login", "asset.read"}, Resources: []string{"*"}, Enabled: true})
	secrets := []string{"hidden-account:file:/private/unlisted-path", "hidden-account:tcp:192.0.2.77:443", "hidden-account:exec:" + hash("private-command")}
	f.c.Store.Put("grant", "hidden-grant", Grant{ID: "hidden-grant", Issuer: f.l.User, Subject: f.l.User, Actions: []string{"proxy.exec"}, Resources: secrets, Enabled: true})
	source := &Live{ID: "reader-source", User: "reader", Key: "reader-key", Source: "127.0.0.1:1234", Kind: "menu", Created: now(), Cancel: make(chan struct{})}
	f.c.mu.Lock()
	f.c.live[source.ID] = source
	f.c.mu.Unlock()
	token, err := f.c.IssueWeb(source)
	if err != nil {
		t.Fatal(err)
	}
	const csrf = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	redeem := httptest.NewRequest("POST", "https://localhost:8443/api/redeem", strings.NewReader(encode(map[string]string{"token": token})))
	redeem.Header.Set("Origin", f.c.Config.WebURL)
	redeem.Header.Set("X-CSRF-Token", csrf)
	redeem.Header.Set("X-Gatehouse-Remote", source.Source)
	redeem.AddCookie(&http.Cookie{Name: "__Host-ghb-csrf", Value: csrf})
	w := httptest.NewRecorder()
	f.c.WebHandler().ServeHTTP(w, redeem)
	if w.Code != 200 {
		t.Fatalf("redeem: %d %s", w.Code, w.Body.String())
	}
	var cookie *http.Cookie
	for _, candidate := range w.Result().Cookies() {
		if candidate.Name == "__Host-ghb-session" {
			cookie = candidate
		}
	}
	if cookie == nil {
		t.Fatal("missing session")
	}
	f.c.mu.Lock()
	ws := f.c.web[hash(cookie.Value)]
	reproduced := true
	for _, secret := range secrets {
		reproduced = reproduced && ws.Snapshot["asset.read:"+secret]
	}
	f.c.mu.Unlock()
	if !reproduced {
		t.Fatal("fixture failed to reproduce enumerated snapshot")
	}
	for _, host := range []string{"jump.example.test", "2001:db8::5"} {
		f.c.Config.PublicHost = host
		request := httptest.NewRequest("GET", "https://localhost:8443/api/me", nil)
		request.AddCookie(cookie)
		request.Header.Set("X-Gatehouse-Remote", source.Source)
		w = httptest.NewRecorder()
		f.c.WebHandler().ServeHTTP(w, request)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var me map[string]json.RawMessage
		if err = json.Unmarshal(w.Body.Bytes(), &me); err != nil {
			t.Fatal(err)
		}
		if _, ok := me["permissions"]; ok {
			t.Fatal("internal snapshot disclosed")
		}
		if strings.Contains(w.Body.String(), "hidden-account") || strings.Contains(w.Body.String(), "private-command") || strings.Contains(w.Body.String(), "hidden-grant") {
			t.Fatal("hidden resource metadata disclosed")
		}
		for _, secret := range secrets {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("hidden resource disclosed")
			}
		}
		var sshAddress, webAddress string
		json.Unmarshal(me["ssh_address"], &sshAddress)
		json.Unmarshal(me["web_address"], &webAddress)
		if sshAddress != net.JoinHostPort(host, strconv.Itoa(f.c.Config.PublicPort)) || webAddress != f.c.Config.WebURL {
			t.Fatalf("missing endpoint addresses: SSH=%q Web=%q", sshAddress, webAddress)
		}
		if me["user"] == nil || me["capabilities"] == nil || me["version"] == nil {
			t.Fatal("public identity contract changed")
		}
	}
	// Snapshot omission is a response change; authorization still uses the snapshot.
	if f.c.webAllowed(ws, "grant.read", secrets[0]) {
		t.Fatal("hidden grant readable")
	}
}

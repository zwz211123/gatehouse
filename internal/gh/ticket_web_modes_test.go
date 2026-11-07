package gh

import (
	"encoding/json"
	"testing"
)

func TestWebNonFileTicketsWithoutFilePermissions(t *testing.T) {
	f := setup(t)
	f.c.Store.Put("user", "operator", User{ID: "operator", Name: "operator", Enabled: true})
	f.c.Store.Put("key", "operator-key", Key{ID: "operator-key", User: "operator", Enabled: true})
	actions := []string{"proxy.create", "proxy.shell", "proxy.exec", "proxy.tcp"}
	command := "printf hello"
	resources := []string{"acct", "acct:exec:" + hash(command), "acct:tcp:192.0.2.10:443"}
	if err := f.c.Store.Put("grant", "operator-proxy", Grant{ID: "operator-proxy", Issuer: f.l.User, Subject: "operator", Actions: actions, Resources: resources, Limits: DefaultLimits(), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	source := &Live{ID: "operator-source", User: "operator", Key: "operator-key", Source: "127.0.0.1:2345", Kind: "menu", Created: now(), Cancel: make(chan struct{})}
	snapshot := map[string]bool{}
	for _, action := range actions {
		for _, resource := range resources {
			snapshot[action+":"+resource] = true
		}
	}
	ws := &WebSession{User: source.User, Key: source.Key, Source: source.ID, Snapshot: snapshot}
	f.c.mu.Lock()
	f.c.live[source.ID] = source
	f.c.mu.Unlock()
	for _, mode := range []string{"shell", "exec", "tcp"} {
		t.Run(mode, func(t *testing.T) {
			spec := Spec{Account: "acct", Modes: []string{mode}, TTL: 15, Duration: 10}
			if mode == "exec" {
				spec.Command = command
			}
			if mode == "tcp" {
				spec.TCPHost = "192.0.2.10"
				spec.TCPPort = 443
				spec.LocalPort = 8443
				spec.TCPRoute = "target"
			}
			q := Change{Kind: "ticket", Operation: "create", Data: json.RawMessage(encode(spec))}
			value, err := f.c.Change(ws, q, source.Source)
			if err != nil {
				t.Fatal("non-file ticket required unrelated permissions", err)
			}
			ticket := value.(map[string]any)["ticket"].(Ticket)
			if len(ticket.Spec.FileOps) != 0 || ticket.Spec.FileRoot != "" {
				t.Fatal("non-file ticket gained file scope")
			}
			spec.FileRoot = "/"
			spec.FileOps = []string{"read", "list"}
			q.Data = json.RawMessage(encode(spec))
			if _, err = f.c.Change(ws, q, source.Source); err == nil {
				t.Fatal("ungranted file operations were accepted")
			}
		})
	}
}

package gh

import (
	"context"
	"encoding/json"
	"github.com/pkg/sftp"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func ownerWeb(f *fixture) *WebSession {
	s := map[string]bool{}
	for _, a := range Capabilities {
		s[a+":*"] = true
	}
	return &WebSession{User: f.l.User, Snapshot: s}
}
func etag(t *testing.T, c *Core, kind, id string) string {
	t.Helper()
	var x map[string]any
	if e := c.Store.Get(kind, id, &x); e != nil {
		t.Fatal(e)
	}
	delete(x, "cipher")
	return hash(encode(x))
}
func TestDelegatedManagerCannotRemoveOwnerDeny(t *testing.T) {
	f := setup(t)
	c := f.c
	c.Store.Put("user", "manager", User{ID: "manager", Name: "manager", Enabled: true})
	c.Store.Put("grant", "admin", Grant{ID: "admin", Issuer: f.l.User, Subject: "manager", Actions: []string{"grant.delete", "grant.update", "group.update", "group.delete", "user.delete"}, Resources: []string{"*"}, Enabled: true})
	c.Store.Put("group", "denied", Group{ID: "denied", Name: "denied", Members: []string{"manager"}})
	c.Store.Put("grant", "deny", Grant{ID: "deny", Issuer: f.l.User, Group: "denied", Actions: []string{"proxy.shell"}, Resources: []string{"*"}, Enabled: true, Deny: true})
	ws := ownerWeb(f)
	ws.User = "manager"
	for _, q := range []Change{
		{Kind: "grant", Operation: "delete", ID: "deny", ETag: etag(t, c, "grant", "deny")},
		{Kind: "group", Operation: "delete", ID: "denied", ETag: etag(t, c, "group", "denied")},
		{Kind: "group", Operation: "update", ID: "denied", ETag: etag(t, c, "group", "denied"), Data: json.RawMessage(`{"name":"denied","members":[]}`)},
	} {
		if _, e := c.Change(ws, q, "test"); e == nil {
			t.Fatalf("manager bypassed deny with %s.%s", q.Kind, q.Operation)
		}
	}
}
func TestCoreExclusiveDataLock(t *testing.T) {
	f := setup(t)
	c, e := NewCore(f.c.Config)
	if e == nil {
		c.Close()
		t.Fatal("second core opened same data")
	}
}
func TestInvalidConfigRejectedBeforeInitialize(t *testing.T) {
	f := setup(t)
	for _, change := range []func(*Config){func(c *Config) { c.PublicHost = "-oProxyCommand=evil" }, func(c *Config) { c.PublicPort = 0 }, func(c *Config) { c.WebURL = "https://host/path" }, func(c *Config) { c.MaxConnections = -1 }, func(c *Config) { c.Run = c.Data }, func(c *Config) { c.SSHListen = "invalid" }} {
		c := f.c.Config
		c.Data = filepath.Join(t.TempDir(), "data")
		change(&c)
		p := filepath.Join(t.TempDir(), "config.json")
		if e := Initialize(c, "admin", filepath.Join(f.root, "owner.pub"), p); e == nil {
			t.Errorf("invalid config accepted: %+v", c)
		}
		if _, e := os.Stat(filepath.Join(c.Data, "master.key")); e == nil {
			t.Error("invalid initialization left master key")
		}
	}
}
func TestIngressCancellation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SSHListen = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunSSHContext(ctx, cfg) }()
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSH ingress did not stop")
	}
}
func TestSourceRestrictedWebPermission(t *testing.T) {
	f := setup(t)
	c := f.c
	c.Store.Put("user", "reader", User{ID: "reader", Name: "reader", Enabled: true})
	c.Store.Put("grant", "read", Grant{ID: "read", Issuer: f.l.User, Subject: "reader", Actions: []string{"asset.read"}, Resources: []string{"*"}, CIDRs: []string{"192.0.2.0/24"}, Enabled: true})
	ws := &WebSession{User: "reader", SourceAddr: "198.51.100.1:54321", Snapshot: map[string]bool{"asset.read:*": true}}
	if c.webAllowed(ws, "asset.read", "asset") {
		t.Fatal("Web ignored source CIDR")
	}
	ws.SourceAddr = "192.0.2.20:54321"
	if !c.webAllowed(ws, "asset.read", "asset") {
		t.Fatal("allowed Web source rejected")
	}
}
func TestPasswordOutputKeepsExpectedPlaintext(t *testing.T) {
	f := setup(t)
	s := Spec{Account: "acct", Modes: []string{"shell"}, PTY: "require"}
	_, pw, out, e := f.c.CreateTicket(f.l, s)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out, "随机密码: "+pw) || !strings.Contains(out, pw+"\nGHB_PASSWORD") {
		t.Fatal("plaintext credential output missing")
	}
}
func TestTCPHalfClosePreservesResponse(t *testing.T) {
	// A TCP application may wait for EOF before producing its response.
	f := setup(t)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		b := make([]byte, 32)
		for {
			_, e = conn.Read(b)
			if e != nil {
				break
			}
		}
		conn.Write([]byte("response-after-eof"))
	}()
	// The real SSH tunnel test lives next to the fixture helpers.
	testHalfClose(t, f, ln.Addr().String())
}

func testHalfClose(t *testing.T, f *fixture, address string) {
	_, ps, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(ps)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"tcp"}, TCPRoute: "jump", TCPHost: "127.0.0.1", TCPPort: port, LocalPort: 3333})
	client, e := f.dial(ticket, pw)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	conn, e := client.Dial("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.Write([]byte("request"))
	conn.(interface{ CloseWrite() error }).CloseWrite()
	done := make(chan string, 1)
	go func() { b, _ := io.ReadAll(conn); done <- string(b) }()
	select {
	case result := <-done:
		if result != "response-after-eof" {
			t.Fatalf("response lost: %q", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel half-close stalled")
	}
}

func TestDenyOnDelegatorConstrainsDescendant(t *testing.T) {
	f := setup(t)
	s := f.c.Store
	for _, id := range []string{"alice", "bob"} {
		s.Put("user", id, User{ID: id, Name: id, Enabled: true})
	}
	p := Grant{ID: "p", Subject: "alice", Issuer: f.l.User, Actions: []string{"proxy.shell", "proxy.exec"}, Resources: []string{"acct"}, Enabled: true, Depth: 1, Limits: DefaultLimits()}
	s.Put("grant", p.ID, p)
	child := p
	child.ID = "child"
	child.Subject = "bob"
	child.Issuer = "alice"
	child.Parent = "p"
	child.Depth = 0
	s.Put("grant", child.ID, child)
	if _, ok := s.Allowed("bob", "proxy.shell", "acct"); !ok {
		t.Fatal("child initially unavailable")
	}
	s.Put("grant", "deny", Grant{ID: "deny", Subject: "alice", Issuer: f.l.User, Actions: []string{"proxy.shell"}, Resources: []string{"acct"}, Enabled: true, Deny: true})
	if _, ok := s.Allowed("bob", "proxy.shell", "acct"); ok {
		t.Fatal("delegator deny bypassed")
	}
	if _, ok := s.Allowed("bob", "proxy.exec", "acct"); !ok {
		t.Fatal("unrelated permission removed")
	}
}
func TestOfflineRecoveryCannotRaceCore(t *testing.T) {
	f := setup(t)
	cfg := f.c.Config
	cfg.Run = filepath.Join(t.TempDir(), "other-run")
	if e := RecoverOwner(cfg, "owner", filepath.Join(f.root, "owner.pub")); e == nil {
		t.Fatal("offline recovery raced active core using another runtime path")
	}
}
func TestStaleTicketCannotAuthorizeAfterRevocation(t *testing.T) {
	f := setup(t)
	ticket, _ := f.ticket(t, Spec{Modes: []string{"shell"}})
	if e := f.c.Revoke(f.l.User, ticket.ID, f.l.Source); e != nil {
		t.Fatal(e)
	}
	if e := f.c.ticketValid(ticket, f.l.Source); e == nil {
		t.Fatal("stale ticket snapshot allowed revoked access")
	}
}
func TestOwnerDeletionNeedsOwnerTrust(t *testing.T) {
	f := setup(t)
	c := f.c
	c.Store.Put("user", "manager", User{ID: "manager", Name: "manager", Enabled: true})
	c.Store.Put("user", "other-owner", User{ID: "other-owner", Name: "other-owner", Enabled: true, Owner: true})
	c.Store.Put("grant", "manage", Grant{ID: "manage", Subject: "manager", Issuer: f.l.User, Actions: []string{"user.delete"}, Resources: []string{"*"}, Enabled: true})
	ws := &WebSession{User: "manager", Snapshot: map[string]bool{"user.delete:*": true}}
	if _, e := c.Change(ws, Change{Kind: "user", Operation: "delete", ID: "other-owner", ETag: etag(t, c, "user", "other-owner")}, "test"); e == nil {
		t.Fatal("non-owner deleted owner")
	}
}
func TestInitializationFailureCanBeRetried(t *testing.T) {
	f := setup(t)
	cfg := f.c.Config
	cfg.Data = filepath.Join(t.TempDir(), "data")
	cfg.Run = filepath.Join(t.TempDir(), "run")
	bad := filepath.Join(t.TempDir(), "not-directory")
	os.WriteFile(bad, []byte("file"), 0600)
	pub := filepath.Join(f.root, "owner.pub")
	if e := Initialize(cfg, "owner", pub, filepath.Join(bad, "config.json")); e == nil {
		t.Fatal("bad config directory accepted")
	}
	if _, e := os.Stat(filepath.Join(cfg.Data, "master.key")); !os.IsNotExist(e) {
		t.Fatal("partial initialization retained key")
	}
	if e := Initialize(cfg, "owner", pub, filepath.Join(t.TempDir(), "config.json")); e != nil {
		t.Fatal(e)
	}
}
func TestSCPLocalOptionAndColonArePaths(t *testing.T) {
	f := setup(t)
	for _, local := range []string{"-O", "server:file", "relative.txt"} {
		_, _, out, e := f.c.CreateTicket(f.l, Spec{Account: "acct", Modes: []string{"scp"}, FileRoot: "/tmp", FileOps: []string{"write"}, LocalPath: local, RemotePath: "/tmp/file", Direction: "upload"})
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(out, quote("./"+local)) {
			t.Fatal("unsafe local SCP argument", out)
		}
	}
}

func TestMixedShellSFTPPTYPolicy(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell", "sftp"}, PTY: "require", FileRoot: t.TempDir(), FileOps: []string{"read", "list"}, Total: 2, Concurrent: 1, Reconnect: true})
	client, e := f.dial(ticket, pw)
	if e != nil {
		t.Fatal(e)
	}
	files, e := sftp.NewClient(client)
	if e != nil {
		client.Close()
		t.Fatal("SFTP incorrectly requires PTY", e)
	}
	files.Close()
	client.Close()
	// Wait for the first transport to release its concurrency slot.
	for attempt := 0; attempt < 100; attempt++ {
		var current Ticket
		f.c.Store.Get("ticket", ticket.ID, &current)
		if current.Active == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	client, e = f.dial(ticket, pw)
	if e != nil {
		var current Ticket
		f.c.Store.Get("ticket", ticket.ID, &current)
		events, _ := f.c.Store.Events(20)
		t.Fatalf("second dial: %v; ticket=%+v; audits=%+v", e, current, events)
	}
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	if e = session.Shell(); e == nil {
		t.Fatal("shell without required PTY accepted")
	}
}

func TestSourceCIDRForRevokeAndConditionalDeny(t *testing.T) {
	f := setup(t)
	c := f.c
	s := c.Store
	s.Put("user", "manager", User{ID: "manager", Name: "manager", Enabled: true})
	s.Put("grant", "revoke", Grant{ID: "revoke", Subject: "manager", Issuer: f.l.User, Actions: []string{"proxy.revoke"}, Resources: []string{"acct"}, CIDRs: []string{"192.0.2.0/24"}, Enabled: true})
	ticket, _ := f.ticket(t, Spec{Modes: []string{"shell"}})
	if e := c.Revoke("manager", ticket.ID, "198.51.100.1:5000"); e == nil {
		t.Fatal("SSH revoke ignored source CIDR")
	}
	if e := c.Revoke("manager", ticket.ID, "192.0.2.1:5000"); e != nil {
		t.Fatal(e)
	}
	s.Put("grant", "deny", Grant{ID: "deny", Subject: "manager", Issuer: f.l.User, Actions: []string{"proxy.revoke"}, Resources: []string{"acct"}, CIDRs: []string{"192.0.2.128/25"}, Deny: true, Enabled: true})
	if _, ok := s.AllowedFrom("manager", "proxy.revoke", "acct", "192.0.2.1:5000"); !ok {
		t.Fatal("conditional deny applied outside its CIDR")
	}
	if _, ok := s.AllowedFrom("manager", "proxy.revoke", "acct", "192.0.2.200:5000"); ok {
		t.Fatal("conditional deny ignored")
	}
}

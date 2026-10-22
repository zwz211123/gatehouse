package gh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func keypair(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b, e := ssh.MarshalPrivateKey(k, "")
	if e != nil {
		t.Fatal(e)
	}
	s, e := ssh.NewSignerFromKey(k)
	if e != nil {
		t.Fatal(e)
	}
	return s, pem.EncodeToMemory(b)
}

type fixture struct {
	c       *Core
	l       *Live
	address string
	sign    ssh.Signer
	root    string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	tmp := t.TempDir()
	sign, _ := keypair(t)
	pub := filepath.Join(tmp, "owner.pub")
	os.WriteFile(pub, sshPublic(sign.PublicKey()), 0600)
	cfg := DefaultConfig()
	cfg.Data = filepath.Join(tmp, "data")
	cfg.Run = filepath.Join(tmp, "run")
	cfg.PublicHost = "127.0.0.1"
	cfg.WebURL = "https://localhost:8443"
	if e := Initialize(cfg, "owner", pub, filepath.Join(tmp, "config.json")); e != nil {
		t.Fatal(e)
	}
	c, e := NewCore(cfg)
	if e != nil {
		t.Fatal(e)
	}
	users, _ := list[User](c.Store, "user")
	keys, _ := list[Key](c.Store, "key")
	l := &Live{ID: newID(), User: users[0].ID, Key: keys[0].ID, Source: "127.0.0.1:1234", Created: now(), Cancel: make(chan struct{})}
	c.mu.Lock()
	c.live[l.ID] = l
	c.mu.Unlock()
	targetSign, _ := keypair(t)
	outSign, outRaw := keypair(t)
	address, closeTarget := targetServer(t, targetSign, outSign.PublicKey())
	host, portS, _ := net.SplitHostPort(address)
	var port int
	fmt.Sscan(portS, &port)
	encrypted, _ := c.Store.Seal("cred", outRaw)
	c.Store.Put("credential", "cred", Credential{ID: "cred", Name: "test", Cipher: encrypted, Enabled: true, Version: 1})
	c.Store.Put("asset", "asset", Asset{ID: "asset", Name: "target", Host: host, Port: port, HostKeys: []string{strings.TrimSpace(string(sshPublic(targetSign.PublicKey())))}, Enabled: true, AllowSpecial: true, Version: 1})
	c.Store.Put("account", "acct", Account{ID: "acct", Asset: "asset", Name: "deploy", Credential: "cred", Enabled: true, Version: 1})
	ingress, stop := testIngress(t, c)
	_, ingressPort, _ := net.SplitHostPort(ingress)
	fmt.Sscan(ingressPort, &c.Config.PublicPort)
	t.Cleanup(func() { stop(); closeTarget(); c.Close() })
	return &fixture{c: c, l: l, address: ingress, sign: sign, root: tmp}
}
func targetServer(t *testing.T, sign ssh.Signer, pub ssh.PublicKey) (string, func()) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	all := []net.Conn{}
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			all = append(all, conn)
			mu.Unlock()
			go func() {
				defer conn.Close()
				cfg := &ssh.ServerConfig{PublicKeyCallback: func(m ssh.ConnMetadata, p ssh.PublicKey) (*ssh.Permissions, error) {
					if bytes.Equal(p.Marshal(), pub.Marshal()) {
						return nil, nil
					}
					return nil, ErrDenied
				}}
				cfg.AddHostKey(sign)
				sc, chs, reqs, e := ssh.NewServerConn(conn, cfg)
				if e != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chs {
					if ch.ChannelType() == "direct-tcpip" {
						var x struct {
							Host       string
							Port       uint32
							Origin     string
							OriginPort uint32
						}
						ssh.Unmarshal(ch.ExtraData(), &x)
						remote, e := net.Dial("tcp", net.JoinHostPort(x.Host, fmt.Sprint(x.Port)))
						if e != nil {
							ch.Reject(ssh.ConnectionFailed, "no endpoint")
							continue
						}
						channel, reqs, _ := ch.Accept()
						go ssh.DiscardRequests(reqs)
						go func() {
							defer channel.Close()
							defer remote.Close()
							go io.Copy(remote, channel)
							io.Copy(channel, remote)
						}()
						continue
					}
					if ch.ChannelType() != "session" {
						ch.Reject(ssh.Prohibited, "no")
						continue
					}
					channel, requests, _ := ch.Accept()
					go func() {
						defer channel.Close()
						for r := range requests {
							switch r.Type {
							case "pty-req", "env", "window-change":
								r.Reply(true, nil)
							case "exec":
								var cmd struct{ Command string }
								ssh.Unmarshal(r.Payload, &cmd)
								r.Reply(true, nil)
								io.WriteString(channel, "target:"+cmd.Command)
								channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								return
							case "shell":
								r.Reply(true, nil)
								io.WriteString(channel, "TARGET-SHELL\n")
								buf := make([]byte, 5)
								io.ReadFull(channel, buf)
								channel.Write(buf)
								channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								return
							case "subsystem":
								r.Reply(true, nil)
								srv, e := sftp.NewServer(channel)
								if e == nil {
									srv.Serve()
									srv.Close()
								}
								return
							default:
								r.Reply(false, nil)
							}
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String(), func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range all {
			c.Close()
		}
	}
}
func testIngress(t *testing.T, c *Core) (string, func()) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	all := map[net.Conn]bool{}
	var workers sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			all[conn] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(all, conn); mu.Unlock() }()
				a, b := net.Pipe()
				defer a.Close()
				coreDone := make(chan struct{})
				go func() { c.ServeSSH(b); close(coreDone) }()
				json.NewEncoder(a).Encode(map[string]string{"Remote": conn.RemoteAddr().String()})
				go func() { io.Copy(a, conn); a.Close() }()
				io.Copy(conn, a)
				a.Close()
				conn.Close()
				<-coreDone
			}()
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		<-stopped
		mu.Lock()
		for conn := range all {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	}
}
func (f *fixture) ticket(t *testing.T, s Spec) (Ticket, string) {
	t.Helper()
	s.Account = "acct"
	ticket, pw, _, e := f.c.CreateTicket(f.l, s)
	if e != nil {
		t.Fatal(e)
	}
	return ticket, pw
}
func (f *fixture) dial(t Ticket, pw string) (*ssh.Client, error) {
	return ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: t.Username, Auth: []ssh.AuthMethod{ssh.Password(pw)}, HostKeyCallback: func(_ string, _ net.Addr, p ssh.PublicKey) error {
		if !bytes.Equal(p.Marshal(), f.c.Signer.PublicKey().Marshal()) {
			return ErrDenied
		}
		return nil
	}, Timeout: 5 * time.Second})
}
func TestExecTicketAndMismatch(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"exec"}, Command: "printf hello"})
	client, e := f.dial(ticket, pw)
	if e != nil {
		t.Fatal(e)
	}
	s, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.Output("printf hello")
	if e != nil || string(b) != "target:printf hello" {
		t.Fatalf("output %q: %v", b, e)
	}
	client.Close()
	if client, e = f.dial(ticket, pw); e == nil {
		client.Close()
		t.Fatal("replayed ticket accepted")
	}
	ticket, pw = f.ticket(t, Spec{Modes: []string{"exec"}, Command: "approved"})
	client, e = f.dial(ticket, pw)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	s, e = client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Run("different"); e == nil {
		t.Fatal("command mismatch accepted")
	}
}
func TestTemporaryShellNoOriginalKey(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell"}, PTY: "require"})
	client, e := f.dial(ticket, pw)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	s, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RequestPty("xterm", 24, 80, nil); e != nil {
		t.Fatal(e)
	}
	input, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	if e = s.Shell(); e != nil {
		t.Fatal(e)
	}
	input.Write([]byte("hello"))
	b, e := io.ReadAll(out)
	if e != nil || !strings.Contains(string(b), "TARGET-SHELL\nhello") {
		t.Fatalf("%q %v", b, e)
	}
	if e = s.Wait(); e != nil {
		t.Fatal(e)
	}
}
func TestSFTPPermissions(t *testing.T) {
	f := setup(t)
	root := filepath.Join(f.root, "files")
	os.Mkdir(root, 0700)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"sftp"}, FileRoot: root, FileOps: []string{"read", "write", "list"}})
	client, e := f.dial(ticket, pw)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	s, e := sftp.NewClient(client)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	data := bytes.Repeat([]byte{0, 1, 2, 255}, 32000)
	file, e := s.Create(root + "/binary")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = file.Write(data); e != nil {
		t.Fatal(e)
	}
	file.Close()
	read, e := s.Open(root + "/binary")
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(read)
	read.Close()
	if e != nil || !bytes.Equal(b, data) {
		t.Fatal("binary mismatch", e)
	}
	if e = s.Remove(root + "/binary"); e == nil {
		t.Fatal("delete allowed without capability")
	}
}
func TestHostKeyMismatch(t *testing.T) {
	f := setup(t)
	var a Asset
	f.c.Store.Get("asset", "asset", &a)
	a.HostKeys = nil
	f.c.Store.Put("asset", "asset", a)
	if c, e := f.c.DialTarget(f.l.User, "acct"); e == nil {
		c.Close()
		t.Fatal("unverified host accepted")
	}
}
func TestConcurrentClaim(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell"}})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := f.c.Claim(ticket.Username, pw, "127.0.0.1:5"); e == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d claims accepted", wins)
	}
}
func TestDelegationAndCascade(t *testing.T) {
	f := setup(t)
	a := User{ID: "alice", Name: "alice", Enabled: true}
	b := User{ID: "bob", Name: "bob", Enabled: true}
	f.c.Store.Put("user", a.ID, a)
	f.c.Store.Put("user", b.ID, b)
	parent := Grant{ID: "parent", Subject: a.ID, Issuer: f.l.User, Actions: []string{"proxy.shell", "proxy.create"}, Resources: []string{"acct"}, Enabled: true, Depth: 1, Limits: DefaultLimits()}
	f.c.Store.Put("grant", parent.ID, parent)
	child := parent
	child.ID = "child"
	child.Subject = b.ID
	child.Issuer = a.ID
	child.Parent = parent.ID
	child.Depth = 0
	if e := f.c.Store.ValidateGrant(a.ID, child); e != nil {
		t.Fatal(e)
	}
	f.c.Store.Put("grant", child.ID, child)
	if _, ok := f.c.Store.Allowed(b.ID, "proxy.shell", "acct"); !ok {
		t.Fatal("delegation missing")
	}
	over := child
	over.Actions = append(over.Actions, "credential.read")
	if e := f.c.Store.ValidateGrant(a.ID, over); e == nil {
		t.Fatal("overdelegation accepted")
	}
	parent.Enabled = false
	f.c.Store.Put("grant", parent.ID, parent)
	if _, ok := f.c.Store.Allowed(b.ID, "proxy.shell", "acct"); ok {
		t.Fatal("revoked parent left child usable")
	}
}
func TestWebLoginTokenAndCSRF(t *testing.T) {
	f := setup(t)
	token, e := f.c.IssueWeb(f.l)
	if e != nil {
		t.Fatal(e)
	}
	do := func(tok, origin, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://localhost:8443/api/redeem", strings.NewReader(encode(map[string]string{"token": tok})))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: "__Host-ghb-csrf", Value: strings.Repeat("x", 32)})
		w := httptest.NewRecorder()
		f.c.WebHandler().ServeHTTP(w, r)
		return w
	}
	if w := do(token, "https://evil.test", strings.Repeat("x", 32)); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := do(token, "https://localhost:8443", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := do(token, "https://localhost:8443", strings.Repeat("x", 32)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := do(token, "https://localhost:8443", strings.Repeat("x", 32)); w.Code != 401 {
		t.Fatal("replay", w.Code)
	}
	confirm := f.c.Confirm(f.l, strings.Repeat("a", 64))
	if w := do(confirm, "https://localhost:8443", strings.Repeat("x", 32)); w.Code == 200 {
		t.Fatal("operation token became login token")
	}
}
func TestBackupAuthentication(t *testing.T) {
	f := setup(t)
	archive := filepath.Join(f.root, "backup.ghb")
	if e := Backup(f.c.Config, archive, "a long test passphrase"); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(archive)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = unprotect(b, "wrong"); e == nil {
		t.Fatal("wrong password accepted")
	}
	b[len(b)-1] ^= 1
	if _, e = unprotect(b, "a long test passphrase"); e == nil {
		t.Fatal("tampered archive accepted")
	}
}

func TestGeneratedCommandsWithOpenSSH(t *testing.T) {
	if _, e := exec.LookPath("sshpass"); e != nil {
		t.Skip("sshpass not installed")
	}
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"exec"}, Command: "printf native"})
	out := f.c.ConnectionOutput(ticket, pw)
	idx := strings.Index(out, "(\ncommand")
	if idx < 0 {
		t.Fatal("missing paste command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", out[idx:])
	b, e := cmd.CombinedOutput()
	if e != nil || !strings.Contains(string(b), "target:printf native") {
		t.Fatalf("OpenSSH command failed: %v %s", e, b)
	}
	root := filepath.Join(f.root, "transfer")
	os.Mkdir(root, 0700)
	local := filepath.Join(f.root, "payload with space")
	payload := bytes.Repeat([]byte{0, 255, 11, 99}, 10000)
	os.WriteFile(local, payload, 0600)
	ticket, pw = f.ticket(t, Spec{Modes: []string{"scp"}, FileRoot: root, FileOps: []string{"read", "write", "list", "metadata"}, LocalPath: local, RemotePath: root + "/copied file", Direction: "upload"})
	out = f.c.ConnectionOutput(ticket, pw)
	idx = strings.Index(out, "(\ncommand")
	cmd = exec.CommandContext(ctx, "bash", "-c", out[idx:])
	b, e = cmd.CombinedOutput()
	if e != nil {
		events, _ := f.c.Store.Events(30)
		t.Fatalf("SCP paste failed: %v %s\nevents:%s", e, b, encode(events))
	}
	actual, e := os.ReadFile(root + "/copied file")
	if e != nil || !bytes.Equal(actual, payload) {
		t.Fatal("SCP mismatch", e)
	}
}

func TestRevocationClosesActiveShell(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell"}})
	client, e := f.dial(ticket, pw)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	s, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	out, _ := s.StdoutPipe()
	if e = s.Shell(); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, len("TARGET-SHELL\n"))
	if _, e = io.ReadFull(out, b); e != nil {
		t.Fatal(e)
	}
	if e = f.c.Revoke(f.l.User, ticket.ID, f.l.Source); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked session remained active")
	}
}
func TestTCPDestinationCannotChange(t *testing.T) {
	f := setup(t)
	endpoint, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer endpoint.Close()
	go func() {
		conn, e := endpoint.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()
	_, portS, _ := net.SplitHostPort(endpoint.Addr().String())
	var port int
	fmt.Sscan(portS, &port)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"tcp"}, TCPHost: "127.0.0.1", TCPPort: port, LocalPort: 3333, Channels: 2})
	client, e := f.dial(ticket, pw)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	conn, e := client.Dial("tcp", endpoint.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = conn.Write([]byte("echo")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 4)
	if _, e = io.ReadFull(conn, b); e != nil || string(b) != "echo" {
		t.Fatal(e, string(b))
	}
	conn.Close()
	if conn, e = client.Dial("tcp", "127.0.0.1:1"); e == nil {
		conn.Close()
		t.Fatal("changed TCP destination allowed")
	}
}
func TestSecretsNotStoredAndMasterBinding(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell"}})
	rows, e := f.c.Store.db.Query("SELECT data FROM records UNION ALL SELECT data FROM audits")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		rows.Scan(&raw)
		if strings.Contains(raw, pw) {
			t.Fatal("plaintext ticket password persisted")
		}
	}
	rows.Close()
	var k Credential
	f.c.Store.Get("credential", "cred", &k)
	if _, e = f.c.Store.Unseal("different-id", k.Cipher); e == nil {
		t.Fatal("ciphertext transplant accepted")
	}
	if _, e = f.c.Claim(ticket.Username, "wrong", f.l.Source); e == nil {
		t.Fatal("wrong password accepted")
	}
}
func TestOptimisticManagementAndOwnerInvariant(t *testing.T) {
	f := setup(t)
	snapshot := map[string]bool{}
	for _, cap := range Capabilities {
		snapshot[cap+":*"] = true
	}
	ws := &WebSession{User: f.l.User, Snapshot: snapshot}
	q := Change{Kind: "user", Operation: "update", ID: f.l.User, ETag: "stale", Data: json.RawMessage(encode(User{ID: f.l.User, Name: "owner", Enabled: true, Owner: true}))}
	if _, e := f.c.Change(ws, q, f.l.Source); e == nil {
		t.Fatal("stale write accepted")
	}
	var old User
	f.c.Store.Get("user", f.l.User, &old)
	q.ETag = hash(encode(old))
	q.Data = json.RawMessage(encode(User{ID: f.l.User, Name: "owner", Enabled: false}))
	if _, e := f.c.Change(ws, q, f.l.Source); e == nil {
		t.Fatal("last owner disabled")
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	f := setup(t)
	f.ticket(t, Spec{Modes: []string{"shell"}})
	archive := filepath.Join(f.root, "snapshot.ghb")
	if e := Backup(f.c.Config, archive, "separate backup password"); e != nil {
		t.Fatal(e)
	}
	clone := f.c.Config
	clone.Data = filepath.Join(f.root, "restored")
	os.Mkdir(clone.Data, 0700)
	master, e := os.ReadFile(filepath.Join(f.c.Config.Data, "master.key"))
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(clone.Data, "master.key"), master, 0600)
	if e = Restore(clone, archive, "separate backup password"); e != nil {
		t.Fatal(e)
	}
	s, e := OpenStore(clone.Data)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var k Credential
	if e = s.Get("credential", "cred", &k); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Unseal(k.ID, k.Cipher); e != nil {
		t.Fatal(e)
	}
	tickets, e := list[Ticket](s, "ticket")
	if e != nil || len(tickets) != 0 {
		t.Fatal("restored temporary credentials", e)
	}
	before, _ := os.ReadFile(filepath.Join(f.c.Config.Data, "host.key"))
	after, _ := os.ReadFile(filepath.Join(clone.Data, "host.key"))
	if !bytes.Equal(before, after) {
		t.Fatal("host key changed on restore")
	}
}
func TestWebHTTPManagementConfirmation(t *testing.T) {
	f := setup(t)
	token, _ := f.c.IssueWeb(f.l)
	csrf := strings.Repeat("x", 32)
	var session *http.Cookie
	call := func(path, method, body, confirmation string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://localhost:8443"+path, strings.NewReader(body))
		r.Header.Set("Origin", "https://localhost:8443")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-GHB-Confirmation", confirmation)
		r.AddCookie(&http.Cookie{Name: "__Host-ghb-csrf", Value: csrf})
		if session != nil {
			r.AddCookie(session)
		}
		w := httptest.NewRecorder()
		f.c.WebHandler().ServeHTTP(w, r)
		return w
	}
	w := call("/api/redeem", "POST", encode(map[string]string{"token": token}), "")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-ghb-session" {
			session = c
		}
	}
	if session == nil || !session.HttpOnly || !session.Secure {
		t.Fatal("missing secure session cookie")
	}
	body := encode(Change{Kind: "user", Operation: "create", Data: json.RawMessage(`{"name":"web-created","enabled":true}`)})
	if w = call("/api/change", "POST", body, ""); w.Code != 428 {
		t.Fatal("missing SSH confirmation requirement", w.Code)
	}
	code := f.c.Confirm(f.l, hash(body))
	if w = call("/api/change", "POST", body, code); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w = call("/api/change", "POST", body, code); w.Code != 428 {
		t.Fatal("operation code replay", w.Code)
	}
	f.l.Close()
	if w = call("/api/me", "GET", "", ""); w.Code != 401 {
		t.Fatal("closed source SSH retained web session", w.Code)
	}
}
func TestExpiredAndBruteForcedTicketRejected(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell"}})
	ticket.Expires = now() - 1
	f.c.Store.Put("ticket", ticket.ID, ticket)
	if _, e := f.c.Claim(ticket.Username, pw, f.l.Source); e == nil {
		t.Fatal("expired ticket accepted")
	}
	ticket, pw = f.ticket(t, Spec{Modes: []string{"shell"}})
	for range 5 {
		f.c.Claim(ticket.Username, "wrong", f.l.Source)
	}
	if _, e := f.c.Claim(ticket.Username, pw, f.l.Source); e == nil {
		t.Fatal("ticket remained valid after failure threshold")
	}
}

func TestScopedDelegationThroughManagement(t *testing.T) {
	f := setup(t)
	for _, id := range []string{"alice", "bob"} {
		f.c.Store.Put("user", id, User{ID: id, Name: id, Enabled: true})
	}
	parent := Grant{ID: "delegator", Subject: "alice", Issuer: f.l.User, Actions: []string{"grant.create", "grant.read", "proxy.create", "proxy.shell"}, Resources: []string{"acct"}, Depth: 1, Enabled: true, Limits: DefaultLimits()}
	f.c.Store.Put("grant", parent.ID, parent)
	snapshot := map[string]bool{}
	for _, cap := range parent.Actions {
		snapshot[cap+":acct"] = true
	}
	ws := &WebSession{User: "alice", Snapshot: snapshot}
	child := Grant{Subject: "bob", Parent: parent.ID, Actions: []string{"proxy.create", "proxy.shell"}, Resources: []string{"acct"}, Enabled: true, Limits: DefaultLimits()}
	_, e := f.c.Change(ws, Change{Kind: "grant", Operation: "create", Data: json.RawMessage(encode(child))}, f.l.Source)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := f.c.Store.Allowed("bob", "proxy.shell", "acct"); !ok {
		t.Fatal("scoped delegated grant not effective")
	}
	child.Resources = []string{"other-account"}
	if _, e = f.c.Change(ws, Change{Kind: "grant", Operation: "create", Data: json.RawMessage(encode(child))}, f.l.Source); e == nil {
		t.Fatal("out-of-scope management delegation accepted")
	}
}
func TestDelegatedKeyManagerCannotTakeOwner(t *testing.T) {
	f := setup(t)
	f.c.Store.Put("user", "manager", User{ID: "manager", Name: "manager", Enabled: true})
	g := Grant{ID: "key-manager", Subject: "manager", Issuer: f.l.User, Actions: []string{"key.create", "user.update"}, Resources: []string{"*"}, Enabled: true, Limits: DefaultLimits()}
	f.c.Store.Put("grant", g.ID, g)
	sign, _ := keypair(t)
	ws := &WebSession{User: "manager", Snapshot: map[string]bool{"key.create:*": true, "user.update:*": true}}
	_, e := f.c.Change(ws, Change{Kind: "key", Operation: "create", Data: json.RawMessage(encode(Key{User: f.l.User, Public: string(sshPublic(sign.PublicKey())), Enabled: true}))}, f.l.Source)
	if e == nil {
		t.Fatal("delegated key manager took over owner credentials")
	}
}
func TestOrdinaryMenuReturnsAfterTargetExit(t *testing.T) {
	f := setup(t)
	client, e := ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: "owner", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.sign)}, HostKeyCallback: ssh.FixedHostKey(f.c.Signer.PublicKey()), Timeout: 5 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	in, _ := session.StdinPipe()
	out, _ := session.StdoutPipe()
	if e = session.Shell(); e != nil {
		t.Fatal(e)
	}
	r := bufio.NewReader(out)
	wait := func(marker string) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			for {
				line, e := r.ReadString('\n')
				if strings.Contains(line, marker) {
					done <- nil
					return
				}
				if e != nil {
					done <- e
					return
				}
			}
		}()
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("menu wait timed out", marker)
		}
	}
	wait("受控跳板终端")
	in.Write([]byte("connect acct\n"))
	wait("TARGET-SHELL")
	in.Write([]byte("hello"))
	wait("已返回跳板机")
	in.Write([]byte("whoami\n"))
	wait("用户ID:")
	in.Write([]byte("exit\n"))
	if e = session.Wait(); e != nil {
		t.Fatal(e)
	}
}

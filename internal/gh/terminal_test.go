package gh

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func TestTemporaryPasswordReviewAndDeletion(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell"}})
	var secret map[string]string
	if e := f.c.Store.Get("ticket-secret", ticket.ID, &secret); e != nil || secret["password"] != pw || secret["hash"] != "" {
		t.Fatal("temporary password not stored directly", e)
	}
	if _, got, e := f.c.TicketPassword(f.l, ticket.ID); e != nil || got != pw {
		t.Fatal("cannot review", e)
	}
	if e := f.c.DeleteTicket(f.l, ticket.ID); e == nil {
		t.Fatal("deleted live credential")
	}
	other := &Live{ID: f.l.ID, User: "someone-else", Source: f.l.Source, Key: f.l.Key}
	if _, _, e := f.c.TicketPassword(other, ticket.ID); e == nil {
		t.Fatal("password exposed to another user")
	}
	if e := f.c.Revoke(f.l.User, ticket.ID, f.l.Source); e != nil {
		t.Fatal(e)
	}
	if _, got, e := f.c.TicketPassword(f.l, ticket.ID); e != nil || got != pw {
		t.Fatal("revoked credential cannot be reviewed", e)
	}
	if e := f.c.DeleteTicket(other, ticket.ID); e == nil {
		t.Fatal("another user deleted ticket")
	}
	if e := f.c.DeleteTicket(f.l, ticket.ID); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"ticket", "ticket-secret", "ticket-failures"} {
		var out any
		if f.c.Store.Get(kind, ticket.ID, &out) == nil {
			t.Fatal("record survived", kind)
		}
	}
	events, _ := f.c.Store.Events(100)
	found := false
	for _, event := range events {
		if event.Action == "proxy.delete" && event.Resource == ticket.ID {
			found = true
		}
		if strings.Contains(encode(event), pw) {
			t.Fatal("password in audit")
		}
	}
	if !found {
		t.Fatal("deletion not audited")
	}
}

func TestLegacyPasswordAuthentication(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell"}})
	f.c.Store.Put("ticket-secret", ticket.ID, map[string]string{"hash": hash(ticket.ID + ":" + pw)})
	if _, _, e := f.c.TicketPassword(f.l, ticket.ID); e == nil || !strings.Contains(e.Error(), "重新申请") {
		t.Fatal("legacy review did not explain limitation", e)
	}
	if _, e := f.c.Claim(ticket.Username, "wrong", f.l.Source); e == nil {
		t.Fatal("wrong legacy password accepted")
	}
	if _, e := f.c.Claim(ticket.Username, pw, f.l.Source); e != nil {
		t.Fatal("legacy authentication failed", e)
	}
}

func TestMultiPurposeCommandsAndPicker(t *testing.T) {
	f := setup(t)
	ticket := Ticket{ID: "example", Username: "ghp_example", Owner: f.l.User, Spec: Spec{Account: "acct", Modes: []string{"shell", "exec", "sftp", "scp", "tcp"}, Command: "printf 'ok'", FileRoot: "/srv", LocalPath: "a file", RemotePath: "/srv/a file", TCPHost: "::1", TCPPort: 22, LocalPort: 2222}}
	out := f.c.ConnectionOutput(ticket, "secret")
	if strings.Count(out, "(\ncommand") != 5 {
		t.Fatal("missing purpose commands")
	}
	for _, mode := range ticket.Spec.Modes {
		command := f.c.connectionCommand(ticket, "secret", mode)
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(command)
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatal(mode, e, string(b))
		}
	}
	var b bytes.Buffer
	choices := []string{"invalid", "2", "6", "0"}
	index := 0
	if e := f.c.commandPicker(&b, func() (string, error) { s := choices[index]; index++; return s, nil }, ticket, "secret"); e != nil {
		t.Fatal(e)
	}
	if strings.Count(b.String(), "(\r\ncommand") != 6 {
		t.Fatal("picker did not honor individual/all selection")
	}
	b.Reset()
	if e := f.c.commandPicker(&b, func() (string, error) { return "0", nil }, ticket, "secret"); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(b.String(), "secret") {
		t.Fatal("skip printed command password")
	}
}

func TestCompletionContextAndCycling(t *testing.T) {
	f := setup(t)
	tests := map[string]string{"clr": "clear", "proxy cr": "proxy create", "web log": "web login", "connect ac": "connect acct"}
	for input, want := range tests {
		xs := f.c.completions(f.l, input, len(input))
		if len(xs) == 0 || xs[0].value != want {
			t.Fatalf("%s: %v", input, xs)
		}
	}
	if len(f.c.completions(f.l, "web confirm ", 12)) != 0 {
		t.Fatal("completed confirmation digest")
	}
	terminal := term.NewTerminal(&bytes.Buffer{}, "ghb> ")
	f.c.setupCompletion(f.l, terminal)
	first, _, ok := terminal.AutoCompleteCallback("proxy ", 6, '\t')
	if !ok {
		t.Fatal("tab ignored")
	}
	second, _, _ := terminal.AutoCompleteCallback(first, len(first), '\t')
	if first == second {
		t.Fatal("tab did not cycle")
	}
	if _, _, ok := terminal.AutoCompleteCallback("abc", 3, 'x'); ok {
		t.Fatal("typing consumed")
	}
}

func TestMenuTabClearAndCredentialList(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"shell", "exec"}, Command: "uname"})
	client, e := ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: "owner", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.sign)}, HostKeyCallback: ssh.FixedHostKey(f.c.Signer.PublicKey()), Timeout: 5 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	if e = session.RequestPty("xterm", 24, 80, nil); e != nil {
		t.Fatal(e)
	}
	in, _ := session.StdinPipe()
	out, _ := session.StdoutPipe()
	if e = session.Shell(); e != nil {
		t.Fatal(e)
	}
	done := make(chan string, 1)
	go func() { b, _ := io.ReadAll(out); done <- string(b) }()
	// clear via fuzzy completion; review the existing account, show exec only, return.
	fmt.Fprint(in, "clr\t\rproxy list\r1\r2\r0\r0\rexit\r")
	select {
	case output := <-done:
		for _, want := range []string{"\x1b[3J", ticket.Username, pw, "[exec]", "uname"} {
			if !strings.Contains(output, want) {
				t.Fatalf("missing %q in %q", want, output)
			}
		}
		if strings.Contains(output, "[shell]") {
			t.Fatal("unselected shell command printed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("interactive menu stalled")
	}
}

func TestSingleAndBulkDeletionEligibility(t *testing.T) {
	cases := []struct {
		name                      string
		revoked                   bool
		expires                   int64
		used, total, active       int
		connected, other, allowed bool
	}{
		{name: "unused", expires: now() + 300, total: 2},
		{name: "partially-used", expires: now() + 300, used: 1, total: 2},
		{name: "revoked", revoked: true, expires: now() + 300, total: 2, allowed: true},
		{name: "expired", expires: now() - 1, total: 2, allowed: true},
		{name: "exhausted", expires: now() + 300, used: 2, total: 2, allowed: true},
		{name: "active-revoked", revoked: true, expires: now() + 300, total: 2, active: 1},
		{name: "active-expired", expires: now() - 1, total: 2, active: 1},
		{name: "active-exhausted", expires: now() + 300, used: 2, total: 2, active: 1},
		{name: "connected-map", revoked: true, expires: now() + 300, total: 2, connected: true},
		{name: "other-owner", revoked: true, expires: now() - 1, total: 2, other: true},
	}
	for _, bulk := range []bool{false, true} {
		t.Run(fmt.Sprint("bulk=", bulk), func(t *testing.T) {
			f := setup(t)
			for _, tc := range cases {
				owner := f.l.User
				if tc.other {
					owner = "other"
				}
				ticket := Ticket{ID: tc.name, Owner: owner, Revoked: tc.revoked, Expires: tc.expires, Used: tc.used, Active: tc.active, Spec: Spec{Total: tc.total}}
				if e := f.c.Store.Put("ticket", ticket.ID, ticket); e != nil {
					t.Fatal(e)
				}
				f.c.Store.Put("ticket-secret", ticket.ID, map[string]string{"password": "temporary"})
				f.c.Store.Put("ticket-failures", ticket.ID, map[string]int{"count": 1})
				if tc.connected {
					f.c.mu.Lock()
					f.c.live["active-test"] = &Live{Ticket: ticket.ID}
					f.c.mu.Unlock()
				}
			}
			defer func() { f.c.mu.Lock(); delete(f.c.live, "active-test"); f.c.mu.Unlock() }()
			if bulk {
				var output bytes.Buffer
				choices := []string{"d all", "0"}
				i := 0
				if e := f.c.proxyListMenu(f.l, &output, func() (string, error) {
					if i >= len(choices) {
						return "", io.EOF
					}
					s := choices[i]
					i++
					return s, nil
				}); e != nil {
					t.Fatal(e)
				}
				if !strings.Contains(output.String(), "已删除 3 条，跳过 6 条") {
					t.Fatal(output.String())
				}
			} else {
				for _, tc := range cases {
					e := f.c.DeleteTicket(f.l, tc.name)
					if (e == nil) != tc.allowed {
						t.Fatalf("%s: %v", tc.name, e)
					}
				}
			}
			for _, tc := range cases {
				for _, kind := range []string{"ticket", "ticket-secret", "ticket-failures"} {
					var value any
					e := f.c.Store.Get(kind, tc.name, &value)
					if (e != nil) != tc.allowed {
						t.Fatalf("%s %s: deleted=%v", tc.name, kind, e != nil)
					}
				}
			}
			events, _ := f.c.Store.Events(100)
			count := 0
			for _, event := range events {
				if event.Action == "proxy.delete" {
					count++
				}
			}
			if count != 3 {
				t.Fatalf("delete audit count %d", count)
			}
		})
	}
}

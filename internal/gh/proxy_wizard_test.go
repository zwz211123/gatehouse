package gh

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func wizardScript(t *testing.T, f *fixture, useJSON bool, answers ...string) (Ticket, string, string, error) {
	t.Helper()
	var out bytes.Buffer
	i := 0
	ticket, pw, err := f.c.proxyCreate(f.l, &out, func(prompt string) (string, error) {
		fmt.Fprint(&out, prompt)
		// No credential may be persisted while the user is still editing/reviewing.
		tickets, e := list[Ticket](f.c.Store, "ticket")
		if e != nil || len(tickets) != 0 {
			t.Fatalf("created before confirmation: %v %v", tickets, e)
		}
		if i == len(answers) {
			return "", io.EOF
		}
		answer := answers[i]
		i++
		return answer, nil
	}, useJSON)
	if i != len(answers) {
		t.Fatalf("used %d/%d answers: %s; error=%v", i, len(answers), out.String(), err)
	}
	return ticket, pw, out.String(), err
}

func TestProxyWizardReviewAndEdit(t *testing.T) {
	f := setup(t)
	ticket, pw, out, err := wizardScript(t, f, false, "", "", "1d", "2h", "1", "1", "n", "n", "6", "4", "5m", "10m", "", "", "", "1")
	if err != nil || ticket.ID == "" || pw == "" {
		t.Fatalf("%v: %s", err, out)
	}
	if ticket.Spec.TTL != 300 || ticket.Spec.Duration != 600 || ticket.Spec.PTY != "require" {
		t.Fatal(ticket.Spec)
	}
	if !strings.Contains(out, `"ttl":86400`) || !strings.Contains(out, "已建立的连接") {
		t.Fatal(out)
	}
	// The issued credentials must work with the existing authentication path.
	if _, err := f.c.Claim(ticket.Username, pw, f.l.Source); err != nil {
		t.Fatal(err)
	}
}

func TestProxyWizardAllModesAndAdvanced(t *testing.T) {
	f := setup(t)
	ticket, _, out, err := wizardScript(t, f, false,
		"", "1 2 3 4 5", "printf 'ok'", "/srv", "1 2 3 7", "1", "0", "/srv/upload",
		"127.0.0.1", "3306", "13306", "1", "5m", "30m", "3", "2", "y", "y",
		"1", "2", "16", "0", "0", "127.0.0.0/8", "LANG=C TZ=UTC", "n", "1")
	if err != nil || ticket.ID == "" {
		t.Fatalf("%v: %s", err, out)
	}
	s := ticket.Spec
	if len(s.Modes) != 5 || s.Channels != 16 || s.Sessions != 2 || s.PTY != "allow" || s.LocalPath != "0" || s.TCPRoute != "target" || s.Env["LANG"] != "C" || !s.Reconnect {
		t.Fatal(s)
	}
}

func TestProxyWizardChangeModesAndBack(t *testing.T) {
	f := setup(t)
	ticket, _, out, err := wizardScript(t, f, false,
		"", "5", "127.0.0.1", "443", "8443", "1", "5m", "10m", "1", "1", "n", "n",
		"3", "1", "4", "/back", "1", "7m", "11m", "", "", "", "1")
	if err != nil || ticket.ID == "" {
		t.Fatalf("%v: %s", err, out)
	}
	s := ticket.Spec
	if len(s.Modes) != 1 || s.Modes[0] != "shell" || s.TCPHost != "" || s.TCPPort != 0 || s.LocalPort != 0 || s.TCPRoute != "" || s.PTY != "require" || s.TTL != 420 || s.Duration != 660 {
		t.Fatal(s)
	}
}

func TestProxyWizardCancelAndDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []string
		wantEOF bool
	}{
		{"cancel-field", []string{"", "/cancel"}, false},
		{"cancel-review", []string{"", "", "", "", "", "", "", "", ""}, false},
		{"disconnect", []string{"", ""}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			ticket, _, out, err := wizardScript(t, f, false, tc.answers...)
			if tc.wantEOF && err != io.EOF || !tc.wantEOF && err != nil || ticket.ID != "" {
				t.Fatalf("%v: %s", err, out)
			}
			tickets, _ := list[Ticket](f.c.Store, "ticket")
			if len(tickets) != 0 {
				t.Fatal(tickets)
			}
		})
	}
}

func TestProxyWizardRetriesInvalidFields(t *testing.T) {
	f := setup(t)
	ticket, _, out, err := wizardScript(t, f, false,
		"9", "1", "1 1", "3", "relative", "/srv", "8", "1 3", "14", "5m", "9", "10m", "2", "3", "1", "maybe", "n", "n", "1")
	if err != nil || ticket.ID == "" {
		t.Fatalf("%v: %s", err, out)
	}
	if ticket.Spec.TTL != 300 || ticket.Spec.Duration != 600 || ticket.Spec.Concurrent != 1 {
		t.Fatal(ticket.Spec)
	}
	for _, want := range []string{"序号 1 重复", "规范的绝对路径", "至少为 15 秒", "至少为 10 秒", "请输入 1 到 2", "请输入 是 或 否"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q: %s", want, out)
		}
	}
}

func TestProxyWizardSubmissionRechecksAuthorization(t *testing.T) {
	f := setup(t)
	if err := f.c.Store.Put("user", "reader", User{ID: "reader", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Store.Put("grant", "wizard", Grant{ID: "wizard", Subject: "reader", Issuer: f.l.User, Actions: []string{"proxy.create", "proxy.shell"}, Resources: []string{"acct"}, Enabled: true, Limits: Limits{MaxDuration: 60}}); err != nil {
		t.Fatal(err)
	}
	f.l.User = "reader"
	ticket, _, out, err := wizardScript(t, f, false, "", "", "", "", "", "", "", "", "1", "4", "", "60", "", "", "", "1")
	if err != nil || ticket.ID == "" || ticket.Spec.Duration != 60 || !strings.Contains(out, "申请未创建") {
		t.Fatalf("%v %+v: %s", err, ticket, out)
	}
}

func TestProxyWizardDoesNotOfferUnavailableTargets(t *testing.T) {
	f := setup(t)
	for _, kind := range []string{"account", "asset", "credential"} {
		id := map[string]string{"account": "acct", "asset": "asset", "credential": "cred"}[kind]
		var record map[string]any
		f.c.Store.Get(kind, id, &record)
		record["enabled"] = false
		f.c.Store.Put(kind, id, record)
		_, _, _, err := wizardScript(t, f, false)
		if err == nil || !strings.Contains(err.Error(), "没有可申请") {
			t.Fatalf("%s: %v", kind, err)
		}
		record["enabled"] = true
		f.c.Store.Put(kind, id, record)
	}
	f.l.Source = "192.0.2.1:1234"
	f.c.Store.Put("user", "reader", User{ID: "reader", Enabled: true})
	f.c.Store.Put("grant", "wizard", Grant{ID: "wizard", Subject: "reader", Issuer: f.l.User, Actions: []string{"proxy.create"}, Resources: []string{"acct"}, Enabled: true, CIDRs: []string{"127.0.0.0/8"}})
	f.l.User = "reader"
	_, _, _, err := wizardScript(t, f, false)
	if err == nil {
		t.Fatal("offered target outside source grant")
	}
}

func TestProxyJSONDefaultsRemainUnchanged(t *testing.T) {
	f := setup(t)
	ticket, _, out, err := wizardScript(t, f, true, `{"account":"acct","modes":["shell"]}`)
	if err != nil || ticket.Spec.PTY != "forbid" || ticket.Spec.TTL != 300 || ticket.Spec.Duration != 7200 {
		t.Fatalf("%v %+v %s", err, ticket, out)
	}
}

func TestWizardSeconds(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int
		valid bool
	}{
		{"5m", 300, true}, {"2h", 7200, true}, {"1d", 86400, true}, {"15s", 15, true},
		{"315360000", 315360000, true}, {fmt.Sprint(math.MaxInt64), math.MaxInt64, true},
		{"14", 0, false}, {"0", 0, false}, {"-1", 0, false}, {"1.5h", 0, false},
		{"9223372036854775808", 0, false}, {"9223372036854775807d", 0, false},
	} {
		t.Run(tc.input, func(t *testing.T) {
			n, err := wizardSeconds(tc.input, 15)
			if (err == nil) != tc.valid || err == nil && n != tc.want {
				t.Fatalf("%d %v", n, err)
			}
		})
	}
}

// Exercise the actual SSH command routing, including the no-PTY guard and
// rejection of misspelled flags before they can consume the next command.
func TestProxyCreateMenuRouting(t *testing.T) {
	for _, pty := range []bool{false, true} {
		t.Run(fmt.Sprint("pty=", pty), func(t *testing.T) {
			f := setup(t)
			raw, err := netDialSSH(f)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			session, err := raw.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if pty {
				if err := session.RequestPty("xterm", 24, 80, nil); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			session.Stdout = &out
			lines := []string{"proxy create --typo", "proxy create"}
			if pty {
				lines = append(lines, "/cancel")
			}
			lines = append(lines, "proxy create --json", `{"account":"acct","modes":["shell"],"pty":"require"}`, "0", "whoami", "exit")
			sep := "\n"
			if pty {
				sep = "\r"
			}
			session.Stdin = strings.NewReader(strings.Join(lines, sep) + sep)
			if err := session.Shell(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- session.Wait() }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("menu did not finish")
			}
			output := out.String()
			for _, want := range []string{"用法: proxy create [--json]", "请输入申请 JSON", "用户ID:"} {
				if !strings.Contains(output, want) {
					t.Fatalf("missing %q: %s", want, output)
				}
			}
			if pty && !strings.Contains(output, "\r\x1b[J账号序号 [1]: ") {
				t.Fatalf("field label missing from redraw: %q", output)
			}
			if !pty && !strings.Contains(output, "交互申请需要终端") {
				t.Fatal(output)
			}
			tickets, _ := list[Ticket](f.c.Store, "ticket")
			if len(tickets) != 1 {
				t.Fatalf("%v: %s", tickets, output)
			}
		})
	}
}

func netDialSSH(f *fixture) (*ssh.Client, error) {
	return ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: "owner", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.sign)}, HostKeyCallback: ssh.FixedHostKey(f.c.Signer.PublicKey()), Timeout: 5 * time.Second})
}

func TestProxyCreateJSONCompletion(t *testing.T) {
	f := setup(t)
	line := "proxy create --j"
	got := f.c.completions(f.l, line, len(line))
	if len(got) != 1 || got[0].value != "proxy create --json" {
		t.Fatal(got)
	}
}

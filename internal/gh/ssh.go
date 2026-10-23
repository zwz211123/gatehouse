package gh

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type addr string

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return string(a) }

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }
func (c *Core) ServeSSH(raw net.Conn) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReaderSize(raw, 1024)
	line, e := reader.ReadSlice('\n')
	if e != nil || len(line) > 512 {
		return
	}
	var info struct{ Remote string }
	if json.Unmarshal(line, &info) != nil {
		return
	}
	if _, _, e = net.SplitHostPort(info.Remote); e != nil {
		return
	}
	conn := remoteConn{Conn: &bufferConn{Conn: raw, r: reader}, remote: addr(info.Remote)}
	if !c.Rate("ssh:"+hostOnly(info.Remote), 30) || c.auditFailed.Load() {
		return
	}
	var claimed string
	cfg := &ssh.ServerConfig{MaxAuthTries: 5, PublicKeyCallback: func(m ssh.ConnMetadata, p ssh.PublicKey) (*ssh.Permissions, error) {
		if strings.HasPrefix(m.User(), "ghp_") {
			return nil, ErrDenied
		}
		users, e := list[User](c.Store, "user")
		if e != nil {
			return nil, e
		}
		for _, u := range users {
			if u.Name != m.User() || !u.Enabled {
				continue
			}
			keys, e := list[Key](c.Store, "key")
			if e != nil {
				return nil, e
			}
			for _, k := range keys {
				if k.User == u.ID && k.Enabled && k.Fingerprint == ssh.FingerprintSHA256(p) {
					return &ssh.Permissions{Extensions: map[string]string{"user": u.ID, "key": k.ID}}, nil
				}
			}
		}
		return nil, ErrDenied
	}, PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if !strings.HasPrefix(m.User(), "ghp_") {
			return nil, ErrDenied
		}
		t, e := c.Claim(m.User(), string(pw), m.RemoteAddr().String())
		if e != nil {
			return nil, e
		}
		claimed = t.ID
		return &ssh.Permissions{Extensions: map[string]string{"user": t.Owner, "ticket": t.ID}}, nil
	}}
	cfg.AddHostKey(c.Signer)
	sc, channels, reqs, e := ssh.NewServerConn(conn, cfg)
	if e != nil {
		if claimed != "" {
			c.mu.Lock()
			var t Ticket
			if c.Store.Get("ticket", claimed, &t) == nil {
				if t.Active > 0 {
					t.Active--
				}
				t.State = "failed"
				t.Revoked = true
				c.Store.Put("ticket", t.ID, t)
			}
			c.mu.Unlock()
		}
		c.Audit("", "ssh.login", "", "denied", info.Remote, "")
		return
	}
	raw.SetDeadline(time.Time{})
	defer sc.Close()
	l := &Live{ID: newID(), User: sc.Permissions.Extensions["user"], Key: sc.Permissions.Extensions["key"], Ticket: sc.Permissions.Extensions["ticket"], Source: info.Remote, Created: now(), Conn: raw, SSH: sc, Cancel: make(chan struct{}), Kind: "menu"}
	if l.Ticket != "" {
		l.Kind = "proxy"
	}
	var ticket Ticket
	if l.Ticket != "" {
		if c.Store.Get("ticket", l.Ticket, &ticket) != nil {
			return
		}
		l.Key = ticket.SourceKey
	}
	c.mu.Lock()
	c.live[l.ID] = l
	c.mu.Unlock()
	defer c.drop(l)
	if c.Audit(l.User, "ssh.login", l.ID, "ok", info.Remote, l.Kind) != nil {
		return
	}
	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-l.Cancel:
				return
			case <-t.C:
				done := make(chan bool, 1)
				go func() { _, _, e := sc.SendRequest("keepalive@gatehouse", true, nil); done <- e == nil }()
				select {
				case ok := <-done:
					if !ok {
						l.Close()
						return
					}
				case <-time.After(15 * time.Second):
					l.Close()
					return
				}
			}
		}
	}()
	go func() {
		for r := range reqs {
			if r.Type == "keepalive@openssh.com" || r.Type == "keepalive@gatehouse" {
				if r.WantReply {
					r.Reply(true, nil)
				}
				continue
			}
			if r.Type == "no-more-sessions@openssh.com" {
				if r.WantReply {
					r.Reply(true, nil)
				}
				continue
			}
			if r.WantReply {
				r.Reply(false, nil)
			}
			if l.Ticket != "" {
				c.FailTicket(l, "global request denied")
				return
			}
		}
	}()
	var sessions atomic.Int32
	var active atomic.Int32
	var wg sync.WaitGroup
	defer func() { l.Close(); wg.Wait() }()
	for ch := range channels {
		if c.auditFailed.Load() {
			ch.Reject(ssh.Prohibited, "audit unavailable")
			return
		}
		if l.Ticket == "" {
			if ch.ChannelType() != "session" || sessions.Add(1) > 1 {
				ch.Reject(ssh.Prohibited, "menu only")
				continue
			}
			channel, requests, e := ch.Accept()
			if e != nil {
				continue
			}
			wg.Add(1)
			go func() { defer wg.Done(); defer channel.Close(); c.menuSession(l, channel, requests) }()
			continue
		}
		if c.ticketValid(ticket, l.Source) != nil {
			ch.Reject(ssh.Prohibited, "authorization expired")
			return
		}
		if int(active.Add(1)) > ticket.Spec.Channels {
			active.Add(-1)
			ch.Reject(ssh.Prohibited, "channel limit")
			c.FailTicket(l, "channel quota exceeded")
			return
		}
		release := sync.OnceFunc(func() { active.Add(-1) })
		ch = countedNewChannel{NewChannel: ch, release: release}
		switch ch.ChannelType() {
		case "session":
			if int(sessions.Add(1)) > ticket.Spec.Sessions {
				release()
				ch.Reject(ssh.Prohibited, "session limit")
				c.FailTicket(l, "session quota exceeded")
				return
			}
			channel, requests, e := ch.Accept()
			if e != nil {
				release()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer release()
				defer channel.Close()
				c.proxySession(l, ticket, channel, requests)
			}()
		case "direct-tcpip":
			wg.Add(1)
			go func(n ssh.NewChannel) {
				defer wg.Done()
				defer release()
				c.tcpChannel(l, ticket, n)
			}(ch)
		default:
			release()
			ch.Reject(ssh.Prohibited, "channel type denied")
			c.FailTicket(l, "unexpected channel")
			return
		}
	}
}

// Release capacity before sending channel close, so a peer that observes the
// close can immediately open a replacement. The callback is idempotent and is
// also deferred by the handler to cover setup failures and early returns.
type countedChannel struct {
	ssh.Channel
	release func()
}

type countedNewChannel struct {
	ssh.NewChannel
	release func()
}

func (n countedNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	channel, requests, err := n.NewChannel.Accept()
	if err != nil {
		n.release()
		return nil, nil, err
	}
	return countedChannel{Channel: channel, release: n.release}, requests, nil
}

func (n countedNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	n.release()
	return n.NewChannel.Reject(reason, message)
}

func (c countedChannel) Close() error {
	c.release()
	return c.Channel.Close()
}

type bufferConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func hostOnly(s string) string {
	h, _, e := net.SplitHostPort(s)
	if e != nil {
		return s
	}
	return h
}
func (c *Core) menuSession(l *Live, ch ssh.Channel, reqs <-chan *ssh.Request) {
	ch = &inputChannel{Channel: ch, hub: newInputHub(ch)}
	defer ch.Close()
	var terminal *term.Terminal
	started := false
	menuDone := make(chan struct{})
	defer func() {
		ch.Close()
		if started {
			<-menuDone
		}
	}()
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			var p ptyReq
			if ssh.Unmarshal(r.Payload, &p) != nil || terminal != nil || started || p.Columns == 0 || p.Rows == 0 || p.Columns > 1000 || p.Rows > 1000 || len(p.Term) > 64 || len(p.Modes) > 4096 {
				r.Reply(false, nil)
				continue
			}
			terminal = term.NewTerminal(ch, "ghb> ")
			l.TargetMu.Lock()
			l.Term = p.Term
			l.Columns = p.Columns
			l.Rows = p.Rows
			l.TargetMu.Unlock()
			terminal.SetSize(int(p.Columns), int(p.Rows))
			r.Reply(true, nil)
		case "shell":
			if started || len(r.Payload) > 0 {
				r.Reply(false, nil)
				continue
			}
			started = true
			r.Reply(true, nil)
			go func() {
				defer close(menuDone)
				c.menu(l, ch, terminal)
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				ch.Close()
				l.Close()
			}()
		case "window-change":
			var w windowReq
			if terminal != nil && ssh.Unmarshal(r.Payload, &w) == nil && w.Columns <= 1000 && w.Rows <= 1000 {
				terminal.SetSize(int(w.Columns), int(w.Rows))
				l.TargetMu.Lock()
				l.Columns = w.Columns
				l.Rows = w.Rows
				if l.Target != nil {
					l.Target.WindowChange(int(w.Rows), int(w.Columns))
				}
				l.TargetMu.Unlock()
				r.Reply(true, nil)
			} else {
				r.Reply(false, nil)
			}
		default:
			r.Reply(false, nil)
		}
	}
}
func (c *Core) menu(l *Live, ch ssh.Channel, terminal *term.Terminal) {
	io.WriteString(ch, "\r\nGatehouse "+Version+" — 受控跳板终端\r\nlist | connect <账号ID> | proxy create | proxy list | proxy show <ID> | proxy revoke <ID> | proxy delete <ID> | web login | clear | help | exit\r\n")
	read := func() (string, error) {
		if terminal != nil {
			return terminal.ReadLine()
		}
		io.WriteString(ch, "ghb> ")
		var b strings.Builder
		for b.Len() <= 32768 {
			var one [1]byte
			n, e := ch.Read(one[:])
			if n > 0 {
				b.WriteByte(one[0])
				if one[0] == '\n' {
					return b.String(), nil
				}
			}
			if e != nil {
				return b.String(), e
			}
		}
		return "", fmt.Errorf("input line too long")
	}
	// Prompts for JSON and numeric menus must not perform command completion.
	readPrompt := func() (string, error) {
		if terminal == nil {
			return read()
		}
		callback := terminal.AutoCompleteCallback
		terminal.AutoCompleteCallback = nil
		defer func() { terminal.AutoCompleteCallback = callback }()
		return read()
	}
	for {
		if terminal != nil {
			c.setupCompletion(l, terminal)
		}
		line, e := read()
		if e != nil {
			return
		}
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if c.auditFailed.Load() {
			io.WriteString(ch, "审计不可用\r\n")
			return
		}
		switch fields[0] {
		case "exit":
			return
		case "clear":
			io.WriteString(ch, "\x1b[H\x1b[2J\x1b[3J")
		case "help":
			io.WriteString(ch, "Tab 显示带说明的模糊补全候选并循环选择。clear 清屏。proxy list 用数字重看凭据、d序号删除无活动连接的失效凭据，d all 批量清理；proxy show/delete <ID> 可直接操作。proxy create 后按提示粘贴 JSON 申请；字段说明见安装手册。web confirm <操作摘要> 为 Web 敏感操作签发确认码。\r\n")
		case "whoami":
			io.WriteString(ch, "用户ID: "+l.User+" 来源: "+l.Source+"\r\n")
		case "list", "search":
			a, _ := list[Account](c.Store, "account")
			for _, x := range a {
				if _, ok := c.Store.AllowedFrom(l.User, "shell.direct", x.ID, l.Source); !ok {
					if _, ok = c.Store.AllowedFrom(l.User, "proxy.create", x.ID, l.Source); !ok {
						continue
					}
				}
				var asset Asset
				c.Store.Get("asset", x.Asset, &asset)
				io.WriteString(ch, fmt.Sprintf("%s  %s / %s\r\n", x.ID, asset.Name, x.Name))
			}
		case "info":
			if len(fields) != 2 {
				continue
			}
			if _, ok := c.Store.AllowedFrom(l.User, "account.read", fields[1], l.Source); ok {
				var a Account
				if c.Store.Get("account", fields[1], &a) == nil {
					io.WriteString(ch, encode(a)+"\r\n")
				}
			}
		case "connect":
			if len(fields) < 2 || len(fields) > 3 {
				continue
			}
			if _, ok := c.Store.AllowedFrom(l.User, "shell.direct", fields[1], l.Source); !ok {
				io.WriteString(ch, "权限不足\r\n")
				continue
			}
			duration := 7200
			if len(fields) == 3 {
				duration, _ = strconv.Atoi(fields[2])
			}
			c.directMenu(l, ch, fields[1], duration)
		case "web":
			if len(fields) < 2 {
				continue
			}
			switch fields[1] {
			case "login":
				s, e := c.IssueWeb(l)
				if e != nil {
					io.WriteString(ch, e.Error()+"\r\n")
				} else {
					io.WriteString(ch, "管理地址: "+c.Config.WebURL+"\r\ntoken (120秒单次): "+s+"\r\n")
				}
			case "revoke":
				c.mu.Lock()
				for h, w := range c.web {
					if w.User == l.User {
						delete(c.web, h)
					}
				}
				for h, w := range c.tokens {
					if w.User == l.User {
						delete(c.tokens, h)
					}
				}
				c.mu.Unlock()
				io.WriteString(ch, "已撤销\r\n")
			case "confirm":
				if len(fields) == 3 && len(fields[2]) == 64 {
					code := c.Confirm(l, fields[2])
					io.WriteString(ch, "一次性操作确认码: "+code+"\r\n")
				}
			}
		case "proxy":
			if len(fields) < 2 {
				continue
			}
			switch fields[1] {
			case "create":
				io.WriteString(ch, "请输入完整 JSON 申请（示例与字段见手册）:\r\n")
				body, e := readPrompt()
				if e != nil {
					return
				}
				var s Spec
				if e = json.Unmarshal([]byte(body), &s); e != nil {
					io.WriteString(ch, "JSON 错误\r\n")
					continue
				}
				t, pw, _, e := c.CreateTicket(l, s)
				if e != nil {
					io.WriteString(ch, e.Error()+"\r\n")
				} else {
					io.WriteString(ch, strings.ReplaceAll(c.ConnectionSummary(t, pw), "\n", "\r\n"))
					if c.commandPicker(ch, readPrompt, t, pw) != nil {
						return
					}
				}
			case "list":
				if c.proxyListMenu(l, ch, readPrompt) != nil {
					return
				}
			case "show":
				if len(fields) != 3 {
					continue
				}
				t, pw, e := c.TicketPassword(l, fields[2])
				if e != nil {
					io.WriteString(ch, e.Error()+"\r\n")
					continue
				}
				io.WriteString(ch, strings.ReplaceAll(c.ConnectionSummary(t, pw), "\n", "\r\n"))
				if c.commandPicker(ch, readPrompt, t, pw) != nil {
					return
				}
			case "delete":
				if len(fields) != 3 {
					continue
				}
				if e := c.DeleteTicket(l, fields[2]); e != nil {
					io.WriteString(ch, e.Error()+"\r\n")
				} else {
					io.WriteString(ch, "已删除凭据记录，审计日志保留\r\n")
				}
			case "revoke":
				if len(fields) == 3 {
					e := c.Revoke(l.User, fields[2], l.Source)
					if e != nil {
						io.WriteString(ch, e.Error()+"\r\n")
					} else {
						io.WriteString(ch, "已撤销\r\n")
					}
				}
			}
		default:
			io.WriteString(ch, "未知命令\r\n")
		}
	}
}

type ptyReq struct {
	Term                         string
	Columns, Rows, Width, Height uint32
	Modes                        string
}
type windowReq struct{ Columns, Rows, Width, Height uint32 }

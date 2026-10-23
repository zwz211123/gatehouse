package gh

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

func (c *Core) proxySession(l *Live, t Ticket, ch ssh.Channel, reqs <-chan *ssh.Request) {
	var client *ssh.Client
	var remote ssh.Channel
	var unbind func()
	var pre []*ssh.Request
	hasPTY := false
	started := false
	done := make(chan struct{})
	var once sync.Once
	finish := func() {
		once.Do(func() {
			close(done)
			ch.Close()
			if client != nil {
				client.Close()
			}
			if remote != nil {
				remote.Close()
			}
		})
	}
	defer func() {
		finish()
		if unbind != nil {
			unbind()
		}
	}()
	timer := time.AfterFunc(30*time.Second, func() { l.Close() })
	defer timer.Stop()
	for {
		select {
		case <-l.Cancel:
			return
		case <-done:
			return
		case r, ok := <-reqs:
			if !ok {
				return
			}
			valid := false
			start := false
			sftpMode := false
			switch r.Type {
			case "pty-req":
				var p ptyReq
				if !started && !hasPTY && t.Spec.PTY != "forbid" && ssh.Unmarshal(r.Payload, &p) == nil && p.Columns > 0 && p.Columns <= 1000 && p.Rows > 0 && p.Rows <= 1000 && len(p.Term) < 64 && len(p.Modes) <= 4096 {
					hasPTY = true
					valid = true
					pre = append(pre, r)
				}
			case "env":
				var e struct{ Name, Value string }
				if !started && len(pre) < 17 && ssh.Unmarshal(r.Payload, &e) == nil {
					v, yes := t.Spec.Env[e.Name]
					if yes && v == e.Value {
						valid = true
						pre = append(pre, r)
					}
				}
			case "shell":
				valid = !started && len(r.Payload) == 0 && contains(t.Spec.Modes, "shell")
				start = valid
			case "exec":
				var x struct{ Command string }
				valid = !started && ssh.Unmarshal(r.Payload, &x) == nil && contains(t.Spec.Modes, "exec") && x.Command == t.Spec.Command
				start = valid
			case "subsystem":
				var x struct{ Name string }
				valid = !started && ssh.Unmarshal(r.Payload, &x) == nil && x.Name == "sftp" && (contains(t.Spec.Modes, "sftp") || contains(t.Spec.Modes, "scp"))
				start = valid
				sftpMode = valid
			case "window-change":
				var w windowReq
				valid = started && hasPTY && ssh.Unmarshal(r.Payload, &w) == nil && w.Columns > 0 && w.Columns <= 1000 && w.Rows > 0 && w.Rows <= 1000
			case "signal":
				var x struct{ Name string }
				valid = started && ssh.Unmarshal(r.Payload, &x) == nil && contains([]string{"INT", "TERM", "HUP", "QUIT", "KILL", "WINCH", "USR1", "USR2"}, x.Name)
			}
			if start && !sftpMode && t.Spec.PTY == "require" && !hasPTY {
				valid = false
			}
			if !valid {
				if r.WantReply {
					r.Reply(false, nil)
				}
				c.FailTicket(l, "request "+r.Type+" does not match application")
				return
			}
			if start {
				if e := c.Audit(l.User, "proxy.start", t.ID, "ok", l.Source, r.Type); e != nil {
					return
				}
				var e error
				client, e = c.DialTarget(l.User, t.Spec.Account)
				if e != nil {
					if r.WantReply {
						r.Reply(false, nil)
					}
					return
				}
				unbind = bindTarget(l, client)
				started = true
				l.Started.Store(true)
				c.mu.Lock()
				var current Ticket
				if c.Store.Get("ticket", t.ID, &current) == nil {
					current.State = "active"
					c.Store.Put("ticket", t.ID, current)
				}
				c.mu.Unlock()
				if sftpMode {
					if hasPTY {
						if r.WantReply {
							r.Reply(false, nil)
						}
						c.FailTicket(l, "PTY not allowed for SFTP")
						return
					}
					if r.WantReply {
						r.Reply(true, nil)
					}
					go func() { c.serveSFTP(l, t, ch, client, func() { timer.Stop() }); finish() }()
					continue
				}
				var rr <-chan *ssh.Request
				remote, rr, e = client.OpenChannel("session", nil)
				if e != nil {
					if r.WantReply {
						r.Reply(false, nil)
					}
					return
				}
				for _, p := range pre {
					yes, e := remote.SendRequest(p.Type, true, p.Payload)
					if e != nil || !yes {
						return
					}
				}
				yes, e := remote.SendRequest(r.Type, true, r.Payload)
				if r.WantReply {
					r.Reply(e == nil && yes, nil)
				}
				if e != nil || !yes {
					return
				}
				timer.Stop()
				requestsDone := make(chan struct{})
				go func() {
					defer close(requestsDone)
					for req := range rr {
						if req.Type == "exit-status" || req.Type == "exit-signal" {
							ch.SendRequest(req.Type, false, req.Payload)
						}
						if req.WantReply {
							req.Reply(false, nil)
						}
					}
				}()
				stderrDone := make(chan struct{})
				go func() { c.copyLimited(l, t, ch.Stderr(), remote.Stderr()); close(stderrDone) }()
				go func() { c.copyLimited(l, t, ch, remote); <-requestsDone; <-stderrDone; finish() }()
				go func() { c.copyLimited(l, t, remote, ch); remote.CloseWrite() }()
				continue
			}
			if !started {
				if r.WantReply {
					r.Reply(true, nil)
				}
				continue
			}
			if remote != nil {
				yes, e := remote.SendRequest(r.Type, r.WantReply, r.Payload)
				if r.WantReply {
					r.Reply(e == nil && yes, nil)
				}
			} else if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}
}

type quotaWriter struct {
	c   *Core
	l   *Live
	t   Ticket
	dst io.Writer
}
type paceBucket struct {
	mu   sync.Mutex
	next time.Time
}

func (c *Core) charge(l *Live, t Ticket, n int) error {
	if n < 0 {
		return ErrDenied
	}
	v, _ := c.byteCounters.LoadOrStore(t.ID, &atomic.Int64{})
	counter := v.(*atomic.Int64)
	for {
		used := counter.Load()
		if t.Spec.MaxBytes > 0 && int64(n) > t.Spec.MaxBytes-used {
			c.FailTicket(l, "byte quota exceeded")
			return ErrDenied
		}
		if counter.CompareAndSwap(used, used+int64(n)) {
			break
		}
	}
	l.Bytes.Add(int64(n))
	if t.Spec.MaxRate > 0 {
		v, _ := c.paceCounters.LoadOrStore(t.ID, &paceBucket{})
		p := v.(*paceBucket)
		p.mu.Lock()
		start := time.Now()
		if p.next.After(start) {
			start = p.next
		}
		delay := time.Duration(float64(n) / float64(t.Spec.MaxRate) * float64(time.Second))
		p.next = start.Add(delay)
		wait := time.Until(p.next)
		p.mu.Unlock()
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-l.Cancel:
			return ErrDenied
		case <-timer.C:
		}
	}
	return nil
}

func (q quotaWriter) Write(b []byte) (int, error) {
	if e := q.c.charge(q.l, q.t, len(b)); e != nil {
		return 0, e
	}
	return q.dst.Write(b)
}
func (c *Core) copyLimited(l *Live, t Ticket, dst io.Writer, src io.Reader) {
	io.Copy(quotaWriter{c, l, t, dst}, src)
}
func (c *Core) tcpChannel(l *Live, t Ticket, n ssh.NewChannel) {
	var d struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}
	if !contains(t.Spec.Modes, "tcp") || ssh.Unmarshal(n.ExtraData(), &d) != nil || d.Host != t.Spec.TCPHost || int(d.Port) != t.Spec.TCPPort {
		n.Reject(ssh.Prohibited, "destination does not match request")
		c.FailTicket(l, "TCP endpoint mismatch")
		return
	}
	if c.Audit(l.User, "proxy.tcp", t.ID, "ok", l.Source, net.JoinHostPort(d.Host, fmt.Sprint(d.Port))) != nil {
		n.Reject(ssh.Prohibited, "audit unavailable")
		return
	}
	var remote net.Conn
	var e error
	if t.Spec.TCPRoute == "jump" {
		remote, e = net.DialTimeout("tcp", net.JoinHostPort(d.Host, fmt.Sprint(d.Port)), 10*time.Second)
	} else {
		client, err := c.DialTarget(l.User, t.Spec.Account)
		if err != nil {
			n.Reject(ssh.ConnectionFailed, "target unavailable")
			return
		}
		defer client.Close()
		stop := bindTarget(l, client)
		defer stop()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		remote, e = client.DialContext(ctx, "tcp", net.JoinHostPort(d.Host, fmt.Sprint(d.Port)))
	}
	if e != nil {
		n.Reject(ssh.ConnectionFailed, "endpoint unavailable")
		return
	}
	defer remote.Close()
	stopRemote := bindTarget(l, remote)
	defer stopRemote()
	ch, r, e := n.Accept()
	if e != nil {
		return
	}
	defer ch.Close()
	l.Started.Store(true)
	go func() {
		ssh.DiscardRequests(r)
		// Requests close on SSH channel CLOSE, not on a write-side EOF.
		// A fully closed peer must release its slot and unblock the reverse
		// copy even when the TCP endpoint keeps its output half open.
		ch.Close()
		remote.Close()
	}()
	done := make(chan struct{})
	go func() {
		c.copyLimited(l, t, remote, ch)
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			remote.Close()
		}
		close(done)
	}()
	c.copyLimited(l, t, ch, remote)
	ch.Close()
	<-done
}

type inputHub struct {
	data    chan []byte
	pending []byte
	mu      sync.Mutex
	done    chan struct{}
	once    sync.Once
}

func newInputHub(r io.Reader) *inputHub {
	h := &inputHub{data: make(chan []byte, 32), done: make(chan struct{})}
	go func() {
		defer close(h.data)
		b := make([]byte, 4096)
		for {
			n, e := r.Read(b)
			if n > 0 {
				x := append([]byte(nil), b[:n]...)
				select {
				case h.data <- x:
				case <-h.done:
					return
				}
			}
			if e != nil {
				return
			}
		}
	}()
	return h
}
func (h *inputHub) read(ctx context.Context, b []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	if len(h.pending) == 0 {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-h.done:
			return 0, io.EOF
		case x, ok := <-h.data:
			if !ok {
				return 0, io.EOF
			}
			h.pending = x
		}
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	n := copy(b, h.pending)
	h.pending = h.pending[n:]
	return n, nil
}

type inputChannel struct {
	ssh.Channel
	hub *inputHub
}

func (x *inputChannel) Close() error {
	x.hub.once.Do(func() { close(x.hub.done) })
	return x.Channel.Close()
}

func (x *inputChannel) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return x.hub.read(context.Background(), b)
}

type cancelReader struct {
	h   *inputHub
	ctx context.Context
}

func (x cancelReader) Read(b []byte) (int, error) { return x.h.read(x.ctx, b) }
func (c *Core) directMenu(l *Live, ch ssh.Channel, account string, duration int) {
	if duration < 10 {
		io.WriteString(ch, "连接时限无效\r\n")
		return
	}
	spec := Spec{Duration: duration, TTL: 15, Total: 1, Concurrent: 1, Sessions: 1, Channels: 1}
	if _, e := c.Store.AuthorizeSpec(l.User, "shell.direct", account, spec, l.Source); e != nil {
		io.WriteString(ch, "连接时限或来源超出授权\r\n")
		return
	}
	originalAccount, originalAsset, originalCredential, e := c.ownerAccount(l.User, account)
	if e != nil {
		return
	}
	client, e := c.DialTarget(l.User, account)
	if e != nil {
		io.WriteString(ch, "连接失败: "+e.Error()+"\r\n")
		return
	}
	defer client.Close()
	unbind := bindTarget(l, client)
	defer unbind()
	setupTimeout := time.AfterFunc(30*time.Second, func() { client.Close() })
	defer setupTimeout.Stop()
	started := now()
	s, e := client.NewSession()
	if e != nil {
		return
	}
	defer s.Close()
	l.TargetMu.Lock()
	l.Target = s
	termName, columns, rows := l.Term, l.Columns, l.Rows
	l.TargetMu.Unlock()
	defer func() { l.TargetMu.Lock(); l.Target = nil; l.TargetMu.Unlock() }()
	s.Stdout = ch
	s.Stderr = ch.Stderr()
	if termName != "" {
		if e = s.RequestPty(termName, int(rows), int(columns), ssh.TerminalModes{}); e != nil {
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var src io.Reader = ch
	if ic, ok := ch.(*inputChannel); ok {
		src = cancelReader{ic.hub, ctx}
	}
	in, e := s.StdinPipe()
	if e != nil {
		return
	}
	if c.Audit(l.User, "direct.start", account, "ok", l.Source, "") != nil {
		return
	}
	if e = s.Shell(); e != nil {
		return
	}
	setupTimeout.Stop()
	watch := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watch:
				return
			case <-l.Cancel:
				client.Close()
				return
			case <-ticker.C:
				_, auth := c.Store.AuthorizeSpec(l.User, "shell.direct", account, spec, l.Source)
				a, b, k, err := c.ownerAccount(l.User, account)
				if secondsElapsed(started, duration, now()) || auth != nil || err != nil || a.Version != originalAccount.Version || b.Version != originalAsset.Version || k.Version != originalCredential.Version || c.auditFailed.Load() {
					client.Close()
					return
				}
			}
		}
	}()
	done := make(chan struct{})
	go func() { io.Copy(in, src); in.Close(); close(done) }()
	s.Wait()
	cancel()
	<-done
	close(watch)
	c.Audit(l.User, "direct.close", account, "ok", l.Source, "")
	io.WriteString(ch, "\r\n已返回跳板机\r\n")
}

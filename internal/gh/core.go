package gh

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type Live struct {
	ID, User, Key, Source, Kind, Ticket string
	Conn                                net.Conn
	SSH                                 *ssh.ServerConn
	Created                             int64
	Cancel                              chan struct{}
	once                                sync.Once
	Bytes                               atomic.Int64
	Started                             atomic.Bool
	TargetMu                            sync.Mutex
	Target                              *ssh.Session
	Term                                string
	Columns, Rows                       uint32
}

func (l *Live) Close() {
	l.once.Do(func() {
		close(l.Cancel)
		if l.Conn != nil {
			l.Conn.Close()
		}
	})
}

type WebToken struct {
	User, Source, Key string
	Purpose           string
	Expires           int64
	Grants            []string
}
type WebSession struct {
	User, Source, Key string
	SourceAddr        string
	Created, Last     int64
	Snapshot          map[string]bool
	Fresh             map[string]int64
}
type Core struct {
	Config       Config
	Store        *Store
	Signer       ssh.Signer
	mu           sync.Mutex
	management   sync.Mutex
	live         map[string]*Live
	tokens       map[string]WebToken
	web          map[string]*WebSession
	attempts     map[string]*rate
	byteCounters sync.Map
	paceCounters sync.Map
	stop         chan struct{}
	reaperDone   chan struct{}
	auditFailed  atomic.Bool
	lastCleanup  atomic.Int64
	closeOnce    sync.Once
	lock         *os.File
}
type rate struct {
	Count int
	Start int64
}

func NewCore(c Config) (*Core, error) {
	lock, e := lockData(c.Data)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()
	s, e := OpenStore(c.Data)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(filepath.Join(c.Data, "host.key"))
	if e != nil {
		s.Close()
		return nil, e
	}
	sign, e := ssh.ParsePrivateKey(b)
	if e != nil {
		s.Close()
		return nil, e
	}
	x := &Core{Config: c, Store: s, Signer: sign, live: map[string]*Live{}, tokens: map[string]WebToken{}, web: map[string]*WebSession{}, attempts: map[string]*rate{}, stop: make(chan struct{}), reaperDone: make(chan struct{})}
	x.lock = lock
	tickets, e := list[Ticket](s, "ticket")
	if e != nil {
		s.Close()
		return nil, e
	}
	for _, t := range tickets {
		t.Revoked = true
		t.Active = 0
		t.State = "revoked"
		if e = s.Put("ticket", t.ID, t); e != nil {
			s.Close()
			return nil, e
		}
	}
	ok = true
	go x.reaper()
	return x, nil
}
func (c *Core) Audit(actor, action, res, result, source, detail string) error {
	e := c.Store.Audit(Event{Actor: actor, Action: action, Resource: res, Result: result, Source: source, Detail: detail})
	if e != nil {
		c.auditFailed.Store(true)
	}
	return e
}
func hash(s string) string       { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func equalHash(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func (c *Core) Rate(key string, max int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.attempts[key]
	if r == nil && len(c.attempts) >= 8192 {
		return false
	}
	if r == nil || r.Start+60 < now() {
		r = &rate{Start: now()}
		c.attempts[key] = r
	}
	r.Count++
	return r.Count <= max
}
func (c *Core) Close() {
	c.closeOnce.Do(func() {
		close(c.stop)
		<-c.reaperDone
		c.disconnect()
		c.Store.Close()
		if c.lock != nil {
			c.lock.Close()
		}
	})
}
func (c *Core) disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.live {
		l.Close()
	}
}
func (c *Core) reaper() {
	defer close(c.reaperDone)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.Revalidate()
		}
	}
}
func (c *Core) Revalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.live {
		var u User
		valid := c.Store.Get("user", l.User, &u) == nil && u.Enabled && !c.auditFailed.Load()
		if l.Key != "" {
			var k Key
			valid = valid && c.Store.Get("key", l.Key, &k) == nil && k.Enabled
		}
		if valid && l.Ticket != "" {
			var x Ticket
			valid = c.Store.Get("ticket", l.Ticket, &x) == nil && c.ticketValid(x, l.Source) == nil && !secondsElapsed(l.Created, x.Spec.Duration, now())
			if !l.Started.Load() && l.Created+30 < now() {
				valid = false
			}
		}
		if !valid {
			l.Close()
		}
	}
	for h, t := range c.tokens {
		if t.Expires <= now() || c.live[t.Source] == nil {
			delete(c.tokens, h)
		}
	}
	for h, w := range c.web {
		if w.Last+900 <= now() || w.Created+7200 <= now() || c.live[w.Source] == nil {
			delete(c.web, h)
		}
	}
	for k, r := range c.attempts {
		if r.Start+120 < now() {
			delete(c.attempts, k)
		}
	}
	if last := c.lastCleanup.Load(); last+3600 < now() {
		c.lastCleanup.Store(now())
		cutoff := now() - int64(c.settings().RetentionDays)*86400
		c.Store.db.Exec("DELETE FROM audits WHERE json_extract(data,'$.time') < ?", cutoff)
		ts, _ := list[Ticket](c.Store, "ticket")
		for _, t := range ts {
			if secondsElapsed(t.Expires, t.Spec.Duration, cutoff) {
				c.Store.Delete("ticket", t.ID)
				c.Store.Delete("ticket-secret", t.ID)
				c.Store.Delete("ticket-failures", t.ID)
			}
		}
		c.byteCounters.Range(func(k, v any) bool {
			var t Ticket
			if c.Store.Get("ticket", k.(string), &t) != nil || secondsElapsed(t.Expires, t.Spec.Duration, now()) {
				c.byteCounters.Delete(k)
				c.paceCounters.Delete(k)
			}
			return true
		})
	}
}
func (c *Core) ownerAccount(user, ref string) (Account, Asset, Credential, error) {
	var a Account
	var b Asset
	var k Credential
	if c.Store.Get("account", ref, &a) != nil || !a.Enabled || c.Store.Get("asset", a.Asset, &b) != nil || !b.Enabled || c.Store.Get("credential", a.Credential, &k) != nil || !k.Enabled {
		return a, b, k, fmt.Errorf("target unavailable")
	}
	return a, b, k, nil
}
func (c *Core) IssueWeb(l *Live) (string, error) {
	if _, ok := c.Store.AllowedFrom(l.User, "web.login", "*", l.Source); !ok {
		return "", ErrDenied
	}
	if c.Config.WebURL == "" {
		return "", fmt.Errorf("HTTPS web_url not configured")
	}
	token := random(32)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sourceAlive(l.ID) {
		return "", ErrDenied
	}
	for h, t := range c.tokens {
		if t.Source == l.ID {
			delete(c.tokens, h)
		}
	}
	if e := c.Audit(l.User, "web.issue", l.ID, "ok", l.Source, ""); e != nil {
		return "", e
	}
	c.tokens[hash(token)] = WebToken{User: l.User, Source: l.ID, Key: l.Key, Purpose: "login", Expires: now() + 120}
	return token, nil
}
func (c *Core) sourceAlive(id string) bool {
	l := c.live[id]
	if l == nil || l.Kind == "proxy" {
		return false
	}
	select {
	case <-l.Cancel:
		return false
	default:
	}
	var key Key
	var u User
	return c.Store.Get("key", l.Key, &key) == nil && key.Enabled && c.Store.Get("user", l.User, &u) == nil && u.Enabled
}
func (c *Core) drop(l *Live) {
	c.mu.Lock()
	delete(c.live, l.ID)
	for h, t := range c.tokens {
		if t.Source == l.ID {
			delete(c.tokens, h)
		}
	}
	for h, w := range c.web {
		if w.Source == l.ID {
			delete(c.web, h)
		}
	}
	if l.Ticket != "" {
		var t Ticket
		if c.Store.Get("ticket", l.Ticket, &t) == nil {
			if t.Active > 0 {
				t.Active--
			}
			if t.Active == 0 && (t.Used >= t.Spec.Total || !t.Spec.Reconnect) {
				t.State = "closed"
			}
			c.Store.Put("ticket", t.ID, t)
		}
	}
	c.mu.Unlock()
	c.Audit(l.User, "connection.close", l.ID, "ok", l.Source, "")
}

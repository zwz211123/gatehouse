package gh

import (
	"encoding/json"
	"math"
	"testing"
)

func TestTimeArithmetic(t *testing.T) {
	if got, ok := secondsDeadline(100, math.MaxInt64-100); !ok || got != math.MaxInt64 {
		t.Fatal(got, ok)
	}
	if _, ok := secondsDeadline(100, math.MaxInt64); ok {
		t.Fatal("overflow accepted")
	}
	for _, tc := range []struct {
		start   int64
		seconds int
		at      int64
		want    bool
	}{
		{100, 10, 109, false}, {100, 10, 110, true}, {100, 10, 99, false},
		{100, math.MaxInt64, math.MaxInt64, false},
		{math.MaxInt64 - 100, 200, math.MaxInt64, false},
		{math.MinInt64, math.MaxInt64, 0, true},
	} {
		if got := secondsElapsed(tc.start, tc.seconds, tc.at); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
	var spec Spec
	if json.Unmarshal([]byte(`{"ttl":9223372036854775808}`), &spec) == nil {
		t.Fatal("out of range JSON integer accepted")
	}
}

func TestOwnerLongTicketAndLegacySettings(t *testing.T) {
	f := setup(t)
	legacy := f.c.settings()
	legacy.Limits.MaxDuration, legacy.Limits.MaxTTL = 86400, 600
	if err := f.c.Store.Put("settings", "global", legacy); err != nil {
		t.Fatal(err)
	}
	ticket, pw := f.ticket(t, Spec{Modes: []string{"exec"}, Command: "approved", TTL: math.MaxInt64 / 2, Duration: math.MaxInt64})
	if ticket.Expires-ticket.Created != int64(ticket.Spec.TTL) {
		t.Fatal("expiry overflow")
	}
	if _, err := f.c.Claim(ticket.Username, pw, f.l.Source); err != nil {
		t.Fatal(err)
	}
	// A huge expiry + duration must neither wrap during cleanup nor close an active connection.
	live := &Live{ID: newID(), User: f.l.User, Ticket: ticket.ID, Source: f.l.Source, Created: now(), Cancel: make(chan struct{})}
	live.Started.Store(true)
	f.c.mu.Lock()
	f.c.live[live.ID] = live
	f.c.mu.Unlock()
	f.c.lastCleanup.Store(0)
	f.c.byteCounters.Store(ticket.ID, new(int))
	f.c.Revalidate()
	select {
	case <-live.Cancel:
		t.Fatal("huge duration closed immediately")
	default:
	}
	if err := f.c.Store.Get("ticket", ticket.ID, &ticket); err != nil {
		t.Fatal("cleanup deleted long-lived ticket", err)
	}
	if _, ok := f.c.byteCounters.Load(ticket.ID); !ok {
		t.Fatal("cleanup forgot active quota")
	}
	if _, _, _, err := f.c.CreateTicket(f.l, Spec{Account: "acct", Modes: []string{"shell"}, TTL: math.MaxInt64}); err == nil {
		t.Fatal("TTL timestamp overflow accepted")
	}
	// Round-tripping settings removes old time caps but keeps other global quotas.
	settings := f.c.settings()
	settings.Limits.MaxTTL, settings.Limits.MaxDuration = 600, 86400
	q := Change{Kind: "settings", Operation: "update", ETag: hash(encode(f.c.settings())), Data: json.RawMessage(encode(settings))}
	if _, err := f.c.systemChange(ownerWeb(f), q, f.l.Source); err != nil {
		t.Fatal(err)
	}
	var saved Settings
	f.c.Store.Get("settings", "global", &saved)
	if saved.Limits.MaxTTL != 0 || saved.Limits.MaxDuration != 0 {
		t.Fatal("global time caps persisted")
	}
}

func TestDelegatedTimeLimits(t *testing.T) {
	f := setup(t)
	store := f.c.Store
	for _, user := range []string{"alice", "bob"} {
		store.Put("user", user, User{ID: user, Enabled: true})
	}
	limits := DefaultLimits()
	limits.MaxTTL = 604800
	limits.MaxDuration = 315360000
	parent := Grant{ID: "parent", Subject: "alice", Issuer: f.l.User, Actions: []string{"proxy.create", "proxy.shell", "shell.direct"}, Resources: []string{"acct"}, Enabled: true, Depth: 1, Limits: limits}
	store.Put("grant", parent.ID, parent)
	child := parent
	child.ID = "child"
	child.Subject = "bob"
	child.Issuer = "alice"
	child.Parent = parent.ID
	child.Depth = 0
	if err := store.ValidateGrant("alice", child); err != nil {
		t.Fatal(err)
	}
	store.Put("grant", child.ID, child)
	sp := Spec{Account: "acct", Modes: []string{"shell"}, TTL: limits.MaxTTL, Duration: limits.MaxDuration, Total: 1, Concurrent: 1, Sessions: 1, Channels: 1}
	if _, err := store.AuthorizeSpec("bob", "shell.direct", "acct", sp, f.l.Source); err != nil {
		t.Fatal(err)
	}
	live := &Live{ID: newID(), User: "bob", Key: f.l.Key, Source: f.l.Source, Cancel: make(chan struct{})}
	f.c.mu.Lock()
	f.c.live[live.ID] = live
	f.c.mu.Unlock()
	ticket, _, _, err := f.c.CreateTicket(live, sp)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ttl", "duration"} {
		over := sp
		invalid := child
		if field == "ttl" {
			over.TTL++
			invalid.Limits.MaxTTL = 0
		} else {
			over.Duration++
			invalid.Limits.MaxDuration = 0
		}
		if _, _, _, err := f.c.CreateTicket(live, over); err == nil {
			t.Fatal("over-limit ticket accepted", field)
		}
		if err := store.ValidateGrant("alice", invalid); err == nil {
			t.Fatal("unlimited child escaped finite parent", field)
		}
	}
	parent.Limits.MaxTTL--
	store.Put("grant", parent.ID, parent)
	if f.c.ticketValid(ticket, f.l.Source) == nil {
		t.Fatal("tightened parent did not invalidate ticket")
	}
	// Unlimited time may be delegated only when the parent also leaves it unlimited.
	parent.Limits.MaxTTL = 0
	parent.Limits.MaxDuration = 0
	store.Put("grant", parent.ID, parent)
	child.Limits.MaxTTL = 0
	child.Limits.MaxDuration = 0
	if err := store.ValidateGrant("alice", child); err != nil {
		t.Fatal(err)
	}
	store.Put("grant", child.ID, child)
	sp.TTL = math.MaxInt64 / 2
	sp.Duration = math.MaxInt64
	if _, _, _, err := f.c.CreateTicket(live, sp); err != nil {
		t.Fatal(err)
	}
	child.Limits.MaxTTL = -1
	if err := store.ValidateGrant(f.l.User, child); err == nil {
		t.Fatal("negative time limit accepted")
	}
}

func TestPurposeResourceTimeLimits(t *testing.T) {
	for _, mode := range []string{"exec", "tcp"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			store := f.c.Store
			store.Put("user", "alice", User{ID: "alice", Enabled: true})
			limits := DefaultLimits()
			limits.MaxDuration = 315360000
			limits.MaxTTL = 604800
			base := Grant{ID: "base", Subject: "alice", Issuer: f.l.User, Actions: []string{"proxy.create", "proxy." + mode}, Resources: []string{"acct"}, Enabled: true, Limits: limits}
			store.Put("grant", base.ID, base)
			sp := Spec{Account: "acct", Modes: []string{mode}, Command: "approved", TTL: limits.MaxTTL, Duration: limits.MaxDuration, TCPHost: "127.0.0.1", TCPPort: 1234, LocalPort: 1234, TCPRoute: "target"}
			resource := "acct:exec:" + hash(sp.Command)
			if mode == "tcp" {
				resource = tcpResource(sp)
			}
			purpose := base
			purpose.ID = "purpose"
			purpose.Actions = []string{"proxy." + mode}
			purpose.Resources = []string{resource}
			store.Put("grant", purpose.ID, purpose)
			live := &Live{ID: newID(), User: "alice", Key: f.l.Key, Source: f.l.Source, Cancel: make(chan struct{})}
			f.c.mu.Lock()
			f.c.live[live.ID] = live
			f.c.mu.Unlock()
			ticket, _, _, err := f.c.CreateTicket(live, sp)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"ttl", "duration"} {
				narrow := purpose
				if field == "ttl" {
					narrow.Limits.MaxTTL--
				} else {
					narrow.Limits.MaxDuration--
				}
				store.Put("grant", narrow.ID, narrow)
				if _, _, _, err := f.c.CreateTicket(live, sp); err == nil {
					t.Fatal("purpose limit ignored at issuance", field)
				}
				if f.c.ticketValid(ticket, f.l.Source) == nil {
					t.Fatal("purpose limit ignored at revalidation", field)
				}
			}
		})
	}
}

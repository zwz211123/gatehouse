package gh

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestStreamingAuditSummaryMatchesDetail(t *testing.T) {
	events := []Event{
		{ID: "login", Category: "access", ConnectionID: "one", Action: "ssh.login", Result: "ok", Time: 100, Sequence: 1},
		{ID: "start", Category: "access", ConnectionID: "one", Action: "proxy.start", Detail: "subsystem", ChannelID: "sftp", Account: "acct", Result: "attempt", Time: 101, Sequence: 2},
		{ID: "read", Category: "access", ConnectionID: "one", Action: "file.read", ChannelID: "sftp", Account: "acct", Result: "eof", Time: 104, Sequence: 3},
		{ID: "deny", Category: "access", ConnectionID: "one", Action: "file.remove", ChannelID: "other", Account: "other", Result: "denied", Time: 102, Sequence: 4},
		{ID: "close", Category: "access", ConnectionID: "one", Action: "connection.close", Result: "ok", Time: 105, Sequence: 5},
		{ID: "later", Category: "access", ConnectionID: "one", Action: "proxy.close", Result: "ok", Time: 106, Sequence: 6},
		{ID: "partial", Category: "access", ConnectionID: "two", Action: "direct.start", Account: "acct", Result: "ok", Time: 107, Sequence: 7},
		{ID: "operation", Category: "management", ConnectionID: "one", OperationID: "op", Action: "proxy.issue", Result: "ok", Time: 108, Sequence: 8},
		{ID: "old", Category: "legacy", Action: "file.read", Result: "ok", Time: 99, Sequence: 9},
	}
	summary := auditAccumulator{}
	for _, e := range events {
		summary.add(e)
	}
	want := groupAuditEvents(events)
	for i := range want {
		want[i].Events = nil
	}
	if got := summary.records(); !reflect.DeepEqual(got, want) {
		t.Fatalf("streamed metadata differs:\ngot %+v\nwant %+v", got, want)
	}
}

func TestAuditSummaryMemoryDoesNotGrowWithPacketPayloads(t *testing.T) {
	// Simulate a busy SFTP connection with ~200 MiB of unique packet details.
	// Keep the accumulator live across GC: payload retention or a per-packet
	// index must not turn a small connection summary into a copy of its history.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	summary := auditAccumulator{}
	const count = 50000
	for i := 0; i < count; i++ {
		summary.add(Event{ID: strconv.Itoa(i), Category: "access", ConnectionID: "busy", Resource: "ticket", Account: "acct", ChannelID: "sftp", Action: "file.read", Result: "ok", Time: 100, Detail: strings.Repeat("x", 4096) + strconv.Itoa(i)})
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	records := summary.records()
	runtime.KeepAlive(summary)
	if growth := int64(after.HeapAlloc) - int64(before.HeapAlloc); growth > 32<<20 {
		t.Fatalf("summary retained packet history: %d bytes", growth)
	}
	if len(records) != 1 || records[0].EventCount != count || len(records[0].Events) != 0 || len(records[0].Channels) != 1 || len(records[0].Targets) != 1 {
		t.Fatalf("wrong bounded summary: %+v", records)
	}
}

func TestAuditWalkerWatermarkAndCancellation(t *testing.T) {
	f := setup(t)
	for i := 0; i < 1001; i++ {
		if err := f.c.AuditEvent(Event{Resource: "acct", Action: "file.read", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	ws := ownerWeb(f)
	ws.Snapshot = map[string]bool{"audit.read:acct": true}
	visited := 0
	err := f.c.walkVisibleAuditEvents(context.Background(), ws, false, func(Event) error {
		visited++
		if visited == 1 {
			return f.c.AuditEvent(Event{Resource: "acct", Action: "file.read", Result: "ok"})
		}
		return nil
	})
	if err != nil || visited != 1001 {
		t.Fatalf("concurrent writes extended snapshot: %d %v", visited, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	visited = 0
	err = f.c.walkVisibleAuditEvents(ctx, ws, false, func(Event) error { visited++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || visited != 1 {
		t.Fatalf("cancelled scan continued: %d %v", visited, err)
	}
}

package gh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Structured context is captured at the source. Identity, address and timing
// similarities must never be used to reconstruct a missing connection ID.
func prepareEvent(e Event) Event {
	if e.ID == "" {
		e.ID = newID()
	}
	if e.Time == 0 {
		e.Time = now()
	}
	if e.Category == "" {
		switch {
		case e.Action == "ssh.login", e.Action == "proxy.claim", e.Action == "proxy.password", strings.HasPrefix(e.Action, "web."):
			e.Category = "auth"
		default:
			e.Category = "management"
		}
	}
	if e.Category == "management" && e.OperationID == "" {
		e.OperationID = newID()
	}
	return e
}
func (c *Core) AuditEvent(e Event) error {
	err := c.Store.Audit(prepareEvent(e))
	if err != nil {
		c.auditFailed.Store(true)
	}
	return err
}
func (c *Core) connectionEvent(l *Live, action, resource, result, detail, channel string) Event {
	e := Event{Actor: l.User, Action: action, Resource: resource, Result: result, Source: l.Source, Detail: detail, Category: "access", ConnectionID: l.ID, ChannelID: channel, Ticket: l.Ticket, Entry: l.Kind, Origin: "ssh"}
	if l.Ticket != "" {
		var t Ticket
		if c.Store.Get("ticket", l.Ticket, &t) == nil {
			e.Account = t.Spec.Account
		}
	}
	return e
}
func (c *Core) auditConnection(l *Live, action, resource, result, detail, channel string) error {
	return c.AuditEvent(c.connectionEvent(l, action, resource, result, detail, channel))
}
func webEvent(ws *WebSession, action, resource, result, detail, source string) Event {
	return Event{Actor: ws.User, Action: action, Resource: resource, Result: result, Source: source, Detail: detail, Category: "management", ConnectionID: ws.Source, OperationID: ws.OperationID, WebSessionID: ws.ID, Origin: "web"}
}
func (c *Core) auditWeb(ws *WebSession, action, resource, result, detail, source string) error {
	return c.AuditEvent(webEvent(ws, action, resource, result, detail, source))
}

type AuditRecord struct {
	ID                  string   `json:"id"`
	Category            string   `json:"category"`
	ConnectionID        string   `json:"connection_id,omitempty"`
	OperationID         string   `json:"operation_id,omitempty"`
	WebSessionID        string   `json:"web_session_id,omitempty"`
	RelatedConnectionID string   `json:"related_connection_id,omitempty"`
	Actor               string   `json:"actor"`
	Source              string   `json:"source"`
	Entry               string   `json:"entry,omitempty"`
	Origin              string   `json:"origin,omitempty"`
	Ticket              string   `json:"ticket,omitempty"`
	Action              string   `json:"action"`
	Resource            string   `json:"resource"`
	Start               int64    `json:"start"`
	End                 int64    `json:"end"`
	EventCount          int      `json:"event_count"`
	FailureCount        int      `json:"failure_count"`
	Open                bool     `json:"open"`
	Closed              bool     `json:"closed"`
	Targets             []string `json:"targets"`
	Channels            []string `json:"channels"`
	Modes               []string `json:"modes"`
	Events              []Event  `json:"events,omitempty"`
	Partial             bool     `json:"partial"`
}

func auditRecordKey(e Event) string {
	if e.Category == "access" && e.ConnectionID != "" {
		return "connection:" + e.ConnectionID
	}
	if e.Category == "management" && e.OperationID != "" {
		return "operation:" + e.OperationID
	}
	return "event:" + e.ID
}
func auditFailure(result string) bool {
	return result != "ok" && result != "attempt" && result != "eof"
}
func appendUnique(dst []string, value string) []string {
	if value != "" && !contains(dst, value) {
		return append(dst, value)
	}
	return dst
}

// Summaries retain one accumulator per record, never packet payloads or an
// event-ID set. Persisted audit rows are visited once, in sequence order.
type auditGroup struct {
	record            AuditRecord
	closedAt          int64
	targets, channels map[string]bool
}
type auditAccumulator struct {
	groups     map[string]*auditGroup
	keepEvents bool
}

func (a *auditAccumulator) add(e Event) {
	if a.groups == nil {
		a.groups = map[string]*auditGroup{}
	}
	key := auditRecordKey(e)
	state := a.groups[key]
	if state == nil {
		state = &auditGroup{record: AuditRecord{ID: key, Category: e.Category, ConnectionID: e.ConnectionID, OperationID: e.OperationID, WebSessionID: e.WebSessionID, RelatedConnectionID: e.RelatedConnectionID, Actor: e.Actor, Source: e.Source, Entry: e.Entry, Origin: e.Origin, Ticket: e.Ticket, Action: e.Action, Resource: e.Resource, Start: e.Time, Targets: []string{}, Channels: []string{}, Modes: []string{}, Partial: e.Category == "access"}, targets: map[string]bool{}, channels: map[string]bool{}}
		a.groups[key] = state
	}
	g := &state.record
	if e.Time < g.Start {
		g.Start = e.Time
	}
	if e.Time > g.End {
		g.End = e.Time
	}
	if a.keepEvents {
		g.Events = append(g.Events, e)
	}
	g.EventCount++
	if auditFailure(e.Result) {
		g.FailureCount++
	}
	if e.Account != "" && !state.targets[e.Account] {
		state.targets[e.Account] = true
		g.Targets = append(g.Targets, e.Account)
	}
	if e.ChannelID != "" && !state.channels[e.ChannelID] {
		state.channels[e.ChannelID] = true
		g.Channels = append(g.Channels, e.ChannelID)
	}
	if e.Category == "access" {
		if e.Action == "ssh.login" {
			g.Partial = false
		}
		if e.Action == "connection.close" {
			g.Closed = true
			if e.Time > state.closedAt {
				state.closedAt = e.Time
			}
		}
	}
	mode := ""
	switch e.Action {
	case "direct.start", "direct.close":
		mode = "shell"
	case "proxy.tcp", "proxy.tcp.close":
		mode = "tcp"
	case "proxy.start":
		mode = e.Detail
		if mode == "subsystem" {
			mode = "sftp"
		}
	default:
		if strings.HasPrefix(e.Action, "file.") {
			mode = "sftp"
		}
	}
	g.Modes = appendUnique(g.Modes, mode)
}
func (a *auditAccumulator) records() []AuditRecord {
	out := make([]AuditRecord, 0, len(a.groups))
	for _, state := range a.groups {
		g := state.record
		if g.Closed {
			g.End = state.closedAt
		}
		if a.keepEvents {
			sort.SliceStable(g.Events, func(i, j int) bool {
				if g.Events[i].Time == g.Events[j].Time {
					return g.Events[i].Sequence < g.Events[j].Sequence
				}
				return g.Events[i].Time < g.Events[j].Time
			})
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start == out[j].Start {
			return out[i].ID > out[j].ID
		}
		return out[i].Start > out[j].Start
	})
	return out
}
func groupAuditEvents(events []Event) []AuditRecord {
	a := auditAccumulator{keepEvents: true}
	seen := map[string]bool{}
	for _, e := range events {
		if !seen[e.ID] {
			seen[e.ID] = true
			a.add(e)
		}
	}
	return a.records()
}

// Close every cursor before authorization queries share the single SQLite
// connection. A fixed upper sequence prevents concurrent writes extending a scan.
func (c *Core) walkVisibleAuditEvents(ctx context.Context, ws *WebSession, exporting bool, visit func(Event) error) error {
	var upper int64
	if err := c.Store.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(seq),0) FROM audits").Scan(&upper); err != nil {
		return err
	}
	var after int64
	allowed := map[string]bool{}
	checked := map[string]bool{}
	for after < upper {
		batch, err := c.Store.auditBatch(ctx, after, upper, 500)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}
		for _, e := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			after = e.Sequence
			if !checked[e.Resource] {
				checked[e.Resource] = true
				allowed[e.Resource] = c.webAllowed(ws, "audit.read", e.Resource) && (!exporting || c.webAllowed(ws, "audit.export", e.Resource))
			}
			if allowed[e.Resource] {
				if err := visit(e); err != nil {
					return err
				}
			}
		}
	}
	return ctx.Err()
}
func (c *Core) visibleAuditEvents(ws *WebSession, exporting bool) ([]Event, error) {
	out := []Event{}
	err := c.walkVisibleAuditEvents(context.Background(), ws, exporting, func(e Event) error { out = append(out, e); return nil })
	return out, err
}
func (s *Store) auditBatch(ctx context.Context, after, upper int64, limit int) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT seq,data FROM audits WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?", after, upper, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var data string
		if err = rows.Scan(&e.Sequence, &data); err != nil {
			return nil, err
		}
		seq := e.Sequence
		if err = json.Unmarshal([]byte(data), &e); err != nil {
			return nil, err
		}
		e.Sequence = seq
		if e.ID == "" {
			e.ID = fmt.Sprintf("legacy-%d", seq)
		}
		if e.Category == "" {
			e.Category = "legacy"
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (c *Core) auditRecordsHTTP(w http.ResponseWriter, r *http.Request, ws *WebSession) {
	id := r.URL.Query().Get("id")
	summaries := auditAccumulator{}
	selected := []Event{}
	err := c.walkVisibleAuditEvents(r.Context(), ws, false, func(e Event) error {
		if id != "" {
			if auditRecordKey(e) == id {
				selected = append(selected, e)
			}
		} else {
			summaries.add(e)
		}
		return nil
	})
	if err != nil {
		jsonOut(w, 503, map[string]string{"error": "audit unavailable"})
		return
	}
	records := summaries.records()
	if id != "" {
		records = groupAuditEvents(selected)
	}
	c.mu.Lock()
	for i := range records {
		if records[i].Category == "access" {
			records[i].Open = c.live[records[i].ConnectionID] != nil
		}
	}
	c.mu.Unlock()
	if id := r.URL.Query().Get("id"); id != "" {
		for _, g := range records {
			if g.ID == id {
				jsonOut(w, 200, g)
				return
			}
		}
		jsonOut(w, 404, map[string]string{"error": "record not found"})
		return
	}
	// The console filters and pages this summary snapshot locally. Aggregate once
	// per refresh instead of rescanning the history for every hundred records.
	if r.URL.Query().Get("limit") == "all" {
		for i := range records {
			records[i].Events = nil
		}
		jsonOut(w, 200, map[string]any{"records": records, "total": len(records), "offset": 0, "limit": len(records)})
		return
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit < 1 || limit > 100 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	if offset > len(records) {
		offset = len(records)
	}
	end := offset + limit
	if end > len(records) {
		end = len(records)
	}
	result := records[offset:end]
	for i := range result {
		result[i].Events = nil
	}
	jsonOut(w, 200, map[string]any{"records": result, "total": len(records), "offset": offset, "limit": limit})
}

// POST selections avoid HTTP request-line limits. Keep GET for existing clients;
// an explicit empty POST selection exports nothing, never the entire history.
func (c *Core) auditExportHTTP(w http.ResponseWriter, r *http.Request, ws *WebSession) {
	selected := r.URL.Query()["record"]
	all := r.Method == "GET" && len(selected) == 0
	if r.Method == "POST" {
		var q struct {
			Records []string `json:"records"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 24<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&q) != nil || q.Records == nil || decoder.Decode(&struct{}{}) != io.EOF {
			jsonOut(w, 400, map[string]string{"error": "invalid record selection"})
			return
		}
		selected = q.Records
	}
	selection := make(map[string]bool, len(selected))
	for _, id := range selected {
		selection[id] = true
	}
	if !all && len(selection) == 0 {
		w.Header().Set("Content-Disposition", "attachment; filename=gatehouse-audit.json")
		jsonOut(w, 200, []Event{})
		return
	}
	out := []Event{}
	err := c.walkVisibleAuditEvents(r.Context(), ws, true, func(e Event) error {
		if all || selection[auditRecordKey(e)] {
			out = append(out, e)
		}
		return nil
	})
	if err != nil {
		jsonOut(w, 503, map[string]string{"error": "audit unavailable"})
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=gatehouse-audit.json")
	jsonOut(w, 200, out)
}

package gh

import (
	"encoding/json"
	"fmt"
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
func groupAuditEvents(events []Event) []AuditRecord {
	groups := map[string]*AuditRecord{}
	seen := map[string]bool{}
	for _, e := range events {
		if seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		key := auditRecordKey(e)
		g := groups[key]
		if g == nil {
			g = &AuditRecord{ID: key, Category: e.Category, ConnectionID: e.ConnectionID, OperationID: e.OperationID, WebSessionID: e.WebSessionID, RelatedConnectionID: e.RelatedConnectionID, Actor: e.Actor, Source: e.Source, Entry: e.Entry, Origin: e.Origin, Ticket: e.Ticket, Action: e.Action, Resource: e.Resource, Start: e.Time, Targets: []string{}, Channels: []string{}, Modes: []string{}, Events: []Event{}}
			groups[key] = g
		}
		if e.Time < g.Start {
			g.Start = e.Time
		}
		if e.Time > g.End {
			g.End = e.Time
		}
		g.Events = append(g.Events, e)
		g.EventCount++
		if auditFailure(e.Result) {
			g.FailureCount++
		}
		g.Targets = appendUnique(g.Targets, e.Account)
		g.Channels = appendUnique(g.Channels, e.ChannelID)
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
	out := make([]AuditRecord, 0, len(groups))
	for _, g := range groups {
		sort.SliceStable(g.Events, func(i, j int) bool {
			if g.Events[i].Time == g.Events[j].Time {
				return g.Events[i].Sequence < g.Events[j].Sequence
			}
			return g.Events[i].Time < g.Events[j].Time
		})
		if g.Category == "access" {
			g.Partial = true
			for _, e := range g.Events {
				if e.Action == "ssh.login" {
					g.Partial = false
				}
				if e.Action == "connection.close" {
					g.Open = false
					g.Closed = true
					g.End = e.Time
				}
			}
		}
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start == out[j].Start {
			return out[i].ID > out[j].ID
		}
		return out[i].Start > out[j].Start
	})
	return out
}

// Read in bounded batches, closing each cursor before permission checks use
// the same single SQLite connection. Authorization precedes aggregation.
func (c *Core) visibleAuditEvents(ws *WebSession, exporting bool) ([]Event, error) {
	out := []Event{}
	var after int64
	allowed := map[string]bool{}
	checked := map[string]bool{}
	for {
		batch, err := c.Store.auditBatch(after, 500)
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		for _, e := range batch {
			after = e.Sequence
			if !checked[e.Resource] {
				checked[e.Resource] = true
				allowed[e.Resource] = c.webAllowed(ws, "audit.read", e.Resource) && (!exporting || c.webAllowed(ws, "audit.export", e.Resource))
			}
			if allowed[e.Resource] {
				out = append(out, e)
			}
		}
	}
	return out, nil
}
func (s *Store) auditBatch(after int64, limit int) ([]Event, error) {
	rows, err := s.db.Query("SELECT seq,data FROM audits WHERE seq>? ORDER BY seq LIMIT ?", after, limit)
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
	events, err := c.visibleAuditEvents(ws, false)
	if err != nil {
		jsonOut(w, 503, map[string]string{"error": "audit unavailable"})
		return
	}
	records := groupAuditEvents(events)
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

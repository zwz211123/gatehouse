package gh

import (
	"fmt"
	"net"
)

func (s *Store) Subject(g Grant, user string) bool {
	if g.Subject == user {
		return true
	}
	if g.Group != "" {
		var x Group
		if s.Get("group", g.Group, &x) == nil {
			return contains(x.Members, user)
		}
	}
	return false
}
func (s *Store) GrantValid(g Grant, seen map[string]bool) bool {
	if g.Limits.MaxDuration < 0 || g.Limits.MaxTTL < 0 || seen[g.ID] || !g.Enabled || (g.Expires > 0 && g.Expires <= now() || g.NotBefore > now()) {
		return false
	}
	seen[g.ID] = true
	var issuer User
	if s.Get("user", g.Issuer, &issuer) != nil || !issuer.Enabled {
		return false
	}
	if g.Parent == "" {
		return issuer.Owner
	}
	var p Grant
	if s.Get("grant", g.Parent, &p) != nil || !s.Subject(p, g.Issuer) || p.Deny || p.Depth < 1 || g.Depth >= p.Depth || !subset(g.Actions, p.Actions) || !subset(g.Resources, p.Resources) || !limitsSubset(g.Limits, p.Limits) || g.NotBefore < p.NotBefore || !cidrsSubset(g.CIDRs, p.CIDRs) || (p.Expires > 0 && (g.Expires == 0 || g.Expires > p.Expires)) {
		return false
	}
	return s.GrantValid(p, seen)
}
func (s *Store) Allowed(user, action, resource string) (string, bool) {
	return s.allowed(user, action, resource, "", false)
}
func (s *Store) AllowedFrom(user, action, resource, source string) (string, bool) {
	return s.allowed(user, action, resource, source, true)
}
func (s *Store) allowed(user, action, resource, source string, checkSource bool) (string, bool) {
	var u User
	if s.Get("user", user, &u) != nil || !u.Enabled {
		return "", false
	}
	gs, e := list[Grant](s, "grant")
	if e != nil {
		return "", false
	}
	found := ""
	for _, g := range gs {
		if !s.Subject(g, user) || !s.GrantValid(g, map[string]bool{}) || (!contains(g.Actions, action) && !contains(g.Actions, "*")) || (!contains(g.Resources, resource) && !contains(g.Resources, "*")) {
			continue
		}
		if g.Deny {
			if checkSource && !inCIDRs(source, g.CIDRs) {
				continue
			}
			return "", false
		}
		if s.delegationDenied(g, action, resource, gs, source, checkSource) {
			continue
		}
		if checkSource && !inCIDRs(source, g.CIDRs) {
			continue
		}
		if found == "" {
			found = g.ID
		}
	}
	if u.Owner {
		return "@owner", true
	}
	return found, found != ""
}
func limitsSubset(a, b Limits) bool {
	return timeBounded(a.MaxDuration, b.MaxDuration) && timeBounded(a.MaxTTL, b.MaxTTL) && bounded(a.MaxTotal, b.MaxTotal) && bounded(a.MaxConcurrent, b.MaxConcurrent) && bounded(a.MaxSessions, b.MaxSessions) && bounded(a.MaxChannels, b.MaxChannels) && (b.MaxBytes == 0 || (a.MaxBytes > 0 && a.MaxBytes <= b.MaxBytes)) && (b.MaxRate == 0 || (a.MaxRate > 0 && a.MaxRate <= b.MaxRate))
}

// Zero means no additional time limit, so a finite parent cannot delegate zero.
func timeBounded(a, b int) bool { return a >= 0 && b >= 0 && (b == 0 || (a > 0 && a <= b)) }
func bounded(a, b int) bool     { return a > 0 && (b == 0 || a <= b) }
func cidrsSubset(a, b []string) bool {
	if len(b) == 0 {
		return true
	}
	if len(a) == 0 {
		return false
	}
	for _, v := range a {
		ip, n, e := net.ParseCIDR(v)
		if e != nil {
			return false
		}
		ok := false
		for _, w := range b {
			_, m, e := net.ParseCIDR(w)
			if e != nil {
				continue
			}
			an, ab := n.Mask.Size()
			mn, mb := m.Mask.Size()
			if ab == mb && an >= mn && m.Contains(ip) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func inCIDRs(source string, cidrs []string) bool {
	if len(cidrs) == 0 {
		return true
	}
	host, _, e := net.SplitHostPort(source)
	if e != nil {
		host = source
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, v := range cidrs {
		_, n, e := net.ParseCIDR(v)
		if e == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
func (s *Store) AuthorizeSpec(user, action, resource string, sp Spec, source string) (string, error) {
	if _, ok := s.AllowedFrom(user, action, resource, source); !ok {
		return "", ErrDenied
	}
	var u User
	s.Get("user", user, &u)
	if u.Owner {
		return "@owner", nil
	}
	gs, e := list[Grant](s, "grant")
	if e != nil {
		return "", e
	}
	for _, g := range gs {
		if g.Deny || !s.Subject(g, user) || !s.GrantValid(g, map[string]bool{}) || (!contains(g.Actions, action) && !contains(g.Actions, "*")) || (!contains(g.Resources, resource) && !contains(g.Resources, "*")) {
			continue
		}
		if s.delegationDenied(g, action, resource, gs, source, true) {
			continue
		}
		l := Limits{sp.Duration, sp.TTL, sp.Total, sp.Concurrent, sp.Sessions, sp.Channels, sp.MaxBytes, sp.MaxRate}
		if limitsSubset(l, g.Limits) && cidrsSubset(sp.CIDRs, g.CIDRs) && inCIDRs(source, g.CIDRs) {
			return g.ID, nil
		}
	}
	return "", fmt.Errorf("requested limits or source exceed authorization")
}
func (s *Store) ValidateGrant(actor string, g Grant) error {
	for id, seen := g.Parent, map[string]bool{}; id != ""; {
		if id == g.ID || seen[id] {
			return fmt.Errorf("cyclic delegation")
		}
		seen[id] = true
		var p Grant
		if s.Get("grant", id, &p) != nil {
			break
		}
		id = p.Parent
	}
	if g.Limits.MaxDuration < 0 || g.Limits.MaxTTL < 0 || g.Depth < 0 || g.Depth > 8 || len(g.Actions) == 0 || len(g.Resources) == 0 || (g.Subject == "") == (g.Group == "") {
		return fmt.Errorf("invalid grant")
	}
	if g.Expires != 0 && g.Expires <= now() {
		return fmt.Errorf("expired grant")
	}
	for _, a := range g.Actions {
		if a != "*" && !contains(Capabilities, a) {
			return fmt.Errorf("unknown capability %s", a)
		}
	}
	for _, v := range g.CIDRs {
		if _, _, e := net.ParseCIDR(v); e != nil {
			return e
		}
	}
	if g.Subject != "" {
		var u User
		if s.Get("user", g.Subject, &u) != nil {
			return fmt.Errorf("unknown subject")
		}
	} else {
		var group Group
		if s.Get("group", g.Group, &group) != nil {
			return fmt.Errorf("unknown group")
		}
	}
	var u User
	if s.Get("user", actor, &u) != nil || !u.Enabled {
		return ErrDenied
	}
	if u.Owner && g.Parent == "" {
		return nil
	}
	if g.Deny {
		return fmt.Errorf("only owner may create deny rules")
	}
	var parent Grant
	if s.Get("grant", g.Parent, &parent) != nil || !s.Subject(parent, actor) || !s.GrantValid(parent, map[string]bool{}) || parent.Depth < 1 {
		return ErrDenied
	}
	if g.ID == g.Parent || g.Depth >= parent.Depth || !subset(g.Actions, parent.Actions) || !subset(g.Resources, parent.Resources) || !limitsSubset(g.Limits, parent.Limits) || g.NotBefore < parent.NotBefore || !cidrsSubset(g.CIDRs, parent.CIDRs) || (parent.Expires > 0 && (g.Expires == 0 || g.Expires > parent.Expires)) {
		return ErrDenied
	}
	return nil
}

// A deny imposed on a delegator also constrains use of its descendants.
func (s *Store) delegationDenied(g Grant, action, resource string, gs []Grant, source string, checkSource bool) bool {
	for depth := 0; g.Parent != ""; depth++ {
		if depth > 8 {
			return true
		}
		for _, d := range gs {
			if d.Deny && (!checkSource || inCIDRs(source, d.CIDRs)) && s.Subject(d, g.Issuer) && s.GrantValid(d, map[string]bool{}) && (contains(d.Actions, "*") || contains(d.Actions, action)) && (contains(d.Resources, "*") || contains(d.Resources, resource)) {
				return true
			}
		}
		var parent Grant
		if s.Get("grant", g.Parent, &parent) != nil {
			return true
		}
		g = parent
	}
	return false
}

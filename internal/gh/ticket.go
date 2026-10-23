package gh

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"path"
	"strings"
	"time"
)

func specActions(s Spec) []string {
	a := []string{"proxy.create"}
	for _, m := range s.Modes {
		a = append(a, "proxy."+m)
	}
	if contains(s.Modes, "tcp") && s.TCPRoute == "jump" {
		a = append(a, "proxy.tcp.jump")
		if specialIP(net.ParseIP(s.TCPHost)) {
			a = append(a, "proxy.tcp.special")
		}
	}
	for _, m := range s.FileOps {
		a = append(a, "file."+m)
	}
	if s.Total > 1 || s.Concurrent > 1 || s.Sessions > 1 {
		a = append(a, "proxy.multi")
	}
	if s.Reconnect {
		a = append(a, "proxy.reconnect")
	}
	return a
}
func (c *Core) CreateTicket(l *Live, s Spec) (Ticket, string, string, error) {
	var t Ticket
	if len(s.Modes) == 0 || len(s.Modes) > 5 {
		return t, "", "", fmt.Errorf("select explicit modes")
	}
	seen := map[string]bool{}
	for _, m := range s.Modes {
		if !contains([]string{"shell", "exec", "sftp", "scp", "tcp"}, m) || seen[m] {
			return t, "", "", fmt.Errorf("invalid or duplicate mode")
		}
		seen[m] = true
	}
	if s.TTL == 0 {
		s.TTL = 300
	}
	if s.Duration == 0 {
		s.Duration = 7200
	}
	if s.Total == 0 {
		s.Total = 1
	}
	if s.Concurrent == 0 {
		s.Concurrent = 1
	}
	if s.Sessions == 0 {
		s.Sessions = 1
	}
	if s.Channels == 0 {
		s.Channels = 1
	}
	if s.PTY == "" {
		s.PTY = "forbid"
	}
	if s.TTL < 15 || s.TTL > 600 || s.Duration < 10 || s.Duration > 86400 || s.Total < 1 || s.Total > 100 || s.Concurrent < 1 || s.Concurrent > s.Total || s.Sessions < 1 || s.Sessions > 16 || s.Channels < 1 || s.Channels > 128 || s.MaxBytes < 0 || s.MaxRate < 0 {
		return t, "", "", fmt.Errorf("limits out of range")
	}
	if !contains([]string{"allow", "require", "forbid"}, s.PTY) {
		return t, "", "", fmt.Errorf("invalid PTY policy")
	}
	if contains(s.Modes, "exec") && (s.Command == "" || len(s.Command) > 8192) {
		return t, "", "", fmt.Errorf("exact exec command required")
	}
	if len(s.Env) > 16 {
		return t, "", "", fmt.Errorf("too many environment variables")
	}
	for k, v := range s.Env {
		if !contains([]string{"LANG", "LC_ALL", "LC_CTYPE", "TZ"}, k) || len(v) > 128 {
			return t, "", "", fmt.Errorf("environment not allowed")
		}
	}
	for _, v := range s.CIDRs {
		if _, _, e := net.ParseCIDR(v); e != nil {
			return t, "", "", e
		}
	}
	a, b, k, e := c.ownerAccount(l.User, s.Account)
	if e != nil {
		return t, "", "", e
	}
	if contains(s.Modes, "sftp") || contains(s.Modes, "scp") {
		if s.FileRoot == "" || !strings.HasPrefix(s.FileRoot, "/") || path.Clean(s.FileRoot) != s.FileRoot || len(s.FileOps) == 0 {
			return t, "", "", fmt.Errorf("absolute normalized file_root and file_ops required")
		}
		for _, op := range s.FileOps {
			if !contains([]string{"read", "write", "list", "mkdir", "remove", "rename", "metadata"}, op) {
				return t, "", "", fmt.Errorf("invalid file operation")
			}
		}
		if s.StrictPath && (!a.ChrootVerified || s.FileRoot != "/") {
			return t, "", "", fmt.Errorf("strict path requires verified target-side confinement")
		}
	}
	if contains(s.Modes, "scp") {
		if s.LocalPath == "" || s.RemotePath == "" || !contains([]string{"upload", "download"}, s.Direction) {
			return t, "", "", fmt.Errorf("SCP requires local_path, remote_path and upload/download direction")
		}
		rp := path.Clean(s.RemotePath)
		if !path.IsAbs(rp) || (s.FileRoot != "/" && rp != s.FileRoot && !strings.HasPrefix(rp, s.FileRoot+"/")) {
			return t, "", "", fmt.Errorf("SCP remote path outside declared file_root")
		}
	}
	if contains(s.Modes, "tcp") {
		if s.TCPRoute == "" {
			s.TCPRoute = "target"
		}
		if !contains([]string{"target", "jump"}, s.TCPRoute) {
			return t, "", "", fmt.Errorf("invalid TCP route")
		}
		if net.ParseIP(s.TCPHost) == nil || s.TCPPort < 1 || s.TCPPort > 65535 || s.LocalPort < 1 || s.LocalPort > 65535 {
			return t, "", "", fmt.Errorf("fixed numeric target-side TCP host and valid ports required")
		}
	}
	ids := []string{}
	global := c.settings()
	if !limitsSubset(Limits{s.Duration, s.TTL, s.Total, s.Concurrent, s.Sessions, s.Channels, s.MaxBytes, s.MaxRate}, global.Limits) {
		return t, "", "", fmt.Errorf("global security limits exceeded")
	}
	for _, cap := range specActions(s) {
		id, e := c.Store.AuthorizeSpec(l.User, cap, s.Account, s, l.Source)
		if e != nil {
			return t, "", "", fmt.Errorf("%s: %w", cap, e)
		}
		if !contains(ids, id) {
			ids = append(ids, id)
		}
	}
	for _, op := range s.FileOps {
		id, e := c.Store.AuthorizeSpec(l.User, "file."+op, s.Account+":file:"+s.FileRoot, s, l.Source)
		if e != nil {
			return t, "", "", e
		}
		if !contains(ids, id) {
			ids = append(ids, id)
		}
	}
	// Per-target command and TCP destination restrictions are part of the policy resource:
	// a delegated proxy.exec/tcp grant only matches an immutable account-specific profile.
	// Additional purpose resources are required for both owner-created and delegated requests.
	if contains(s.Modes, "exec") {
		id, ok := c.Store.AllowedFrom(l.User, "proxy.exec", s.Account+":exec:"+hash(s.Command), l.Source)
		if !ok {
			return t, "", "", fmt.Errorf("exact command profile not authorized")
		}
		if !contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if contains(s.Modes, "tcp") {
		id, ok := c.Store.AllowedFrom(l.User, "proxy.tcp", tcpResource(s), l.Source)
		if !ok {
			return t, "", "", fmt.Errorf("fixed TCP endpoint not authorized")
		}
		if !contains(ids, id) {
			ids = append(ids, id)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sourceAlive(l.ID) || c.auditFailed.Load() {
		return t, "", "", fmt.Errorf("audit unavailable")
	}
	tickets, _ := list[Ticket](c.Store, "ticket")
	count := 0
	for _, old := range tickets {
		if old.Owner == l.User && !old.Revoked && old.Expires > now() {
			count++
		}
	}
	if count >= global.MaxOutstanding {
		return t, "", "", fmt.Errorf("too many outstanding requests")
	}
	t = Ticket{ID: newID(), Username: "ghp_" + strings.ToLower(newID()), Owner: l.User, Source: l.ID, SourceKey: l.Key, Spec: s, Created: now(), Expires: now() + int64(s.TTL), State: "issued", AssetVersion: b.Version, AccountVersion: a.Version, CredentialVersion: k.Version, GrantIDs: ids}
	pw := random(32)
	if e = c.Audit(l.User, "proxy.issue", t.ID, "ok", l.Source, encode(map[string]any{"modes": s.Modes, "account": s.Account, "command_hash": hash(s.Command)})); e != nil {
		return Ticket{}, "", "", e
	}
	if e = c.Store.Put("ticket", t.ID, t); e != nil {
		return Ticket{}, "", "", e
	}
	e = c.Store.Put("ticket-secret", t.ID, map[string]string{"password": pw})
	if e != nil {
		t.Revoked = true
		c.Store.Put("ticket", t.ID, t)
		return Ticket{}, "", "", e
	}
	return t, pw, c.ConnectionOutput(t, pw), nil
}
func (c *Core) ticketValid(t Ticket, source string) error {
	var current Ticket
	if c.Store.Get("ticket", t.ID, &current) != nil {
		return ErrDenied
	}
	t = current
	if !limitsSubset(Limits{t.Spec.Duration, t.Spec.TTL, t.Spec.Total, t.Spec.Concurrent, t.Spec.Sessions, t.Spec.Channels, t.Spec.MaxBytes, t.Spec.MaxRate}, c.settings().Limits) {
		return ErrDenied
	}
	if t.Revoked || t.State == "failed" || t.State == "revoked" || t.State == "expired" || !inCIDRs(source, t.Spec.CIDRs) {
		return ErrDenied
	}
	var key Key
	if c.Store.Get("key", t.SourceKey, &key) != nil || !key.Enabled {
		return ErrDenied
	}
	a, b, k, e := c.ownerAccount(t.Owner, t.Spec.Account)
	if e != nil || a.Version != t.AccountVersion || b.Version != t.AssetVersion || k.Version != t.CredentialVersion {
		return ErrDenied
	}
	for _, id := range t.GrantIDs {
		if id == "@owner" {
			var u User
			if c.Store.Get("user", t.Owner, &u) != nil || !u.Enabled || !u.Owner {
				return ErrDenied
			}
			continue
		}
		var g Grant
		if c.Store.Get("grant", id, &g) != nil || !c.Store.Subject(g, t.Owner) || !c.Store.GrantValid(g, map[string]bool{}) {
			return ErrDenied
		}
	}
	for _, cap := range specActions(t.Spec) {
		if _, e = c.Store.AuthorizeSpec(t.Owner, cap, t.Spec.Account, t.Spec, source); e != nil {
			return e
		}
	}
	for _, op := range t.Spec.FileOps {
		if _, e := c.Store.AuthorizeSpec(t.Owner, "file."+op, t.Spec.Account+":file:"+t.Spec.FileRoot, t.Spec, source); e != nil {
			return e
		}
	}
	if contains(t.Spec.Modes, "exec") {
		if _, ok := c.Store.AllowedFrom(t.Owner, "proxy.exec", t.Spec.Account+":exec:"+hash(t.Spec.Command), source); !ok {
			return ErrDenied
		}
	}
	if contains(t.Spec.Modes, "tcp") {
		if _, ok := c.Store.AllowedFrom(t.Owner, "proxy.tcp", tcpResource(t.Spec), source); !ok {
			return ErrDenied
		}
	}
	return nil
}
func (c *Core) Claim(username, pw, source string) (Ticket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ts, e := list[Ticket](c.Store, "ticket")
	if e != nil {
		return Ticket{}, e
	}
	for _, t := range ts {
		if t.Username != username {
			continue
		}
		var secret map[string]string
		if c.Store.Get("ticket-secret", t.ID, &secret) != nil || !ticketPasswordMatches(t.ID, pw, secret) {
			var failures struct {
				Count int `json:"count"`
			}
			c.Store.Get("ticket-failures", t.ID, &failures)
			failures.Count++
			c.Store.Put("ticket-failures", t.ID, failures)
			if failures.Count >= 5 {
				t.Revoked = true
				t.State = "revoked"
				c.Store.Put("ticket", t.ID, t)
			}
			c.Audit(t.Owner, "proxy.password", t.ID, "denied", source, "")
			return Ticket{}, ErrDenied
		}
		if t.Expires <= now() || t.Used >= t.Spec.Total || t.Active >= t.Spec.Concurrent || (t.Used > 0 && !t.Spec.Reconnect) || c.ticketValid(t, source) != nil || c.auditFailed.Load() {
			return Ticket{}, ErrDenied
		}
		if e = c.Audit(t.Owner, "proxy.claim", t.ID, "ok", source, ""); e != nil {
			return Ticket{}, e
		}
		t.Used++
		t.Active++
		t.State = "reserved"
		if e = c.Store.Put("ticket", t.ID, t); e != nil {
			return Ticket{}, e
		}
		return t, nil
	}
	return Ticket{}, ErrDenied
}
func (c *Core) FailTicket(l *Live, detail string) {
	c.mu.Lock()
	var t Ticket
	if c.Store.Get("ticket", l.Ticket, &t) == nil {
		t.Revoked = true
		t.State = "failed"
		c.Store.Put("ticket", t.ID, t)
	}
	c.mu.Unlock()
	c.Audit(l.User, "proxy.mismatch", l.Ticket, "denied", l.Source, detail)
	l.Close()
	c.Revalidate()
}
func (c *Core) Revoke(actor, id, source string) error {
	c.mu.Lock()
	var t Ticket
	if e := c.Store.Get("ticket", id, &t); e != nil {
		c.mu.Unlock()
		return e
	}
	if _, ok := c.Store.AllowedFrom(actor, "proxy.revoke", t.Spec.Account, source); !ok {
		if _, ok := c.Store.AllowedFrom(actor, "proxy.revoke", id, source); !ok {
			c.mu.Unlock()
			return ErrDenied
		}
	}
	if e := c.Audit(actor, "proxy.revoke", id, "ok", source, ""); e != nil {
		c.mu.Unlock()
		return e
	}
	t.Revoked = true
	t.State = "revoked"
	e := c.Store.Put("ticket", id, t)
	c.mu.Unlock()
	c.Revalidate()
	return e
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (c *Core) connectionCommand(t Ticket, pw, mode string) string {
	host := c.Config.PublicHost
	port := c.Config.PublicPort
	pub := strings.TrimSpace(string(sshPublic(c.Signer.PublicKey())))
	alias := "gatehouse-pinned"
	keyline := alias + " " + pub
	opts := []string{"-F /dev/null", "-o PreferredAuthentications=password", "-o PubkeyAuthentication=no", "-o KbdInteractiveAuthentication=no", "-o PasswordAuthentication=yes", "-o NumberOfPasswordPrompts=1", "-o ControlMaster=no", "-o ControlPath=none", "-o ForwardAgent=no", "-o ForwardX11=no", "-o StrictHostKeyChecking=yes", "-o HostKeyAlias=" + alias, "-o UserKnownHostsFile=\"$ghb_known\"", "-o GlobalKnownHostsFile=/dev/null"}
	for k, v := range t.Spec.Env {
		opts = append(opts, "-o "+quote("SetEnv="+k+"="+v))
	}
	prefix := "(\ncommand -v sshpass >/dev/null || { printf '%s\\n' '请先安装 sshpass'; exit 1; }\numask 077\nghb_known=$(mktemp) || exit 1\ntrap 'rm -f \"$ghb_known\"' EXIT\nprintf '%s\\n' " + quote(keyline) + " >\"$ghb_known\"\n"
	auth := " 3<<'GHB_PASSWORD'\n" + pw + "\nGHB_PASSWORD\n)"
	base := strings.Join(opts, " ")
	destination := quote(t.Username + "@" + host)
	transferHost := host
	if strings.Contains(host, ":") {
		transferHost = "[" + host + "]"
	}
	cmd := ""
	if mode == "sftp" {
		cmd = "sshpass -d 3 sftp " + base + " -P " + fmt.Sprint(port) + " " + quote(t.Username+"@"+transferHost+":"+t.Spec.FileRoot)
	} else if mode == "scp" {
		local := t.Spec.LocalPath
		if !strings.HasPrefix(local, "/") && !strings.HasPrefix(local, "./") && !strings.HasPrefix(local, "../") {
			local = "./" + local
		}
		if local == "" {
			local = "."
		}
		remote := t.Spec.RemotePath
		if remote == "" {
			remote = t.Spec.FileRoot
		}
		pair := quote(local) + " " + quote(t.Username+"@"+transferHost+":"+remote)
		if t.Spec.Direction == "download" {
			pair = quote(t.Username+"@"+transferHost+":"+remote) + " " + quote(local)
		}
		cmd = "sshpass -d 3 scp " + base + " -P " + fmt.Sprint(port) + " " + pair
	} else {
		tty := "-T"
		if t.Spec.PTY != "forbid" {
			tty = "-tt"
		}
		cmd = "sshpass -d 3 ssh " + base + " -p " + fmt.Sprint(port) + " " + tty + " "
		if mode == "tcp" {
			cmd += "-N -L " + quote(fmt.Sprintf("127.0.0.1:%d:%s", t.Spec.LocalPort, net.JoinHostPort(t.Spec.TCPHost, fmt.Sprint(t.Spec.TCPPort)))) + " -o ExitOnForwardFailure=yes "
		}
		cmd += destination
		if mode == "exec" {
			cmd += " " + quote(t.Spec.Command)
		}
	}
	return prefix + cmd + auth + "\n"
}

func (c *Core) ConnectionSummary(t Ticket, pw string) string {
	a, b, _, _ := c.ownerAccount(t.Owner, t.Spec.Account)
	return fmt.Sprintf("申请 ID: %s\n状态: %s（已撤销: %t，已用连接: %d/%d）\n地址: %s\n端口: %d\n用户名: %s\n随机密码: %s\n认证: SSH password\n模式: %s\n目标: %s / %s\n目标账号ID: %s\n堡垒机主机指纹: %s\n全部约束参数: %s\n领取截止: %s\n最大寿命: %d秒\n撤销: proxy revoke %s\n", t.ID, t.State, t.Revoked, t.Used, t.Spec.Total, c.Config.PublicHost, c.Config.PublicPort, t.Username, pw, strings.Join(t.Spec.Modes, ","), b.Name, a.Name, t.Spec.Account, ssh.FingerprintSHA256(c.Signer.PublicKey()), encode(t.Spec), time.Unix(t.Expires, 0).Format(time.RFC3339), t.Spec.Duration, t.ID)
}

func (c *Core) ConnectionOutput(t Ticket, pw string) string {
	out := c.ConnectionSummary(t, pw)
	for _, mode := range t.Spec.Modes {
		out += "\nBash / OpenSSH / sshpass 命令（明文包含密码）[" + mode + "]:\n" + c.connectionCommand(t, pw, mode)
	}
	return out
}

// Only the issuing user may recover passwords, even when another user can read ticket metadata.
func (c *Core) TicketPassword(l *Live, id string) (Ticket, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var t Ticket
	if c.Store.Get("ticket", id, &t) != nil || t.Owner != l.User || !c.sourceAlive(l.ID) {
		return Ticket{}, "", ErrDenied
	}
	var secret map[string]string
	if c.Store.Get("ticket-secret", id, &secret) != nil || secret["password"] == "" {
		return t, "", errorf("旧凭据未保存可恢复密码，请重新申请")
	}
	if e := c.Audit(l.User, "proxy.credentials", id, "ok", l.Source, ""); e != nil {
		return t, "", e
	}
	return t, secret["password"], nil
}

// Only inactive revoked, expired, or fully consumed tickets may be deleted.
func (c *Core) DeleteTicket(l *Live, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sourceAlive(l.ID) {
		return ErrDenied
	}
	var t Ticket
	if c.Store.Get("ticket", id, &t) != nil || t.Owner != l.User {
		return ErrDenied
	}
	if !ticketDeletable(t, now()) {
		return errorf("只能删除无活动连接且已撤销、已过期或连接次数耗尽的凭据")
	}
	if c.ticketConnected(id) {
		return errorf("仍有活动连接，请稍后删除")
	}
	return c.deleteTicketLocked(l, id)
}

func ticketDeletable(t Ticket, at int64) bool {
	return t.Active == 0 && (t.Revoked || t.Expires <= at || (t.Spec.Total > 0 && t.Used >= t.Spec.Total))
}

// Caller holds c.mu so authentication cannot claim a ticket during deletion.
func (c *Core) ticketConnected(id string) bool {
	for _, live := range c.live {
		if live.Ticket == id {
			return true
		}
	}
	return false
}

// DeleteFinishedTickets applies exactly the same eligibility rules as single deletion.
func (c *Core) DeleteFinishedTickets(l *Live) (deleted, skipped int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sourceAlive(l.ID) {
		return 0, 0, ErrDenied
	}
	tickets, e := list[Ticket](c.Store, "ticket")
	if e != nil {
		return 0, 0, e
	}
	for _, t := range tickets {
		if t.Owner != l.User {
			continue
		}
		if !ticketDeletable(t, now()) || c.ticketConnected(t.ID) {
			skipped++
			continue
		}
		if e = c.deleteTicketLocked(l, t.ID); e != nil {
			return deleted, skipped, e
		}
		deleted++
	}
	return deleted, skipped, nil
}

func (c *Core) deleteTicketLocked(l *Live, id string) error {
	tx, e := c.Store.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	event := Event{Time: now(), Actor: l.User, Action: "proxy.delete", Resource: id, Result: "ok", Source: l.Source}
	if c.auditFailed.Load() {
		return errorf("audit unavailable")
	}
	if _, e = tx.Exec("INSERT INTO audits(data)VALUES(?)", encode(event)); e != nil {
		c.auditFailed.Store(true)
		return e
	}
	if _, e = tx.Exec("DELETE FROM records WHERE id=? AND kind IN ('ticket','ticket-secret','ticket-failures')", id); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	c.byteCounters.Delete(id)
	c.paceCounters.Delete(id)
	return nil
}

func tcpResource(s Spec) string {
	route := ""
	if s.TCPRoute == "jump" {
		route = "jump:"
	}
	return s.Account + ":tcp:" + route + net.JoinHostPort(s.TCPHost, fmt.Sprint(s.TCPPort))
}

// Legacy records retain their original hash; new temporary passwords are stored directly.
func ticketPasswordMatches(id, pw string, secret map[string]string) bool {
	if saved, ok := secret["password"]; ok {
		return equalHash(saved, pw)
	}
	return equalHash(secret["hash"], hash(id+":"+pw))
}

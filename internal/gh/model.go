package gh

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrDenied = errors.New("permission denied")

func random(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func newID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func now() int64          { return time.Now().Unix() }
func encode(v any) string { b, _ := json.Marshal(v); return string(b) }

type User struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Owner   bool   `json:"owner"`
}
type Key struct {
	ID          string `json:"id"`
	User        string `json:"user"`
	Public      string `json:"public"`
	Fingerprint string `json:"fingerprint"`
	Enabled     bool   `json:"enabled"`
}
type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Members []string `json:"members"`
}
type Asset struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	HostKeys     []string `json:"host_keys"`
	Enabled      bool     `json:"enabled"`
	AllowSpecial bool     `json:"allow_special"`
	Version      int      `json:"version"`
}
type Account struct {
	ID             string `json:"id"`
	Asset          string `json:"asset"`
	Name           string `json:"name"`
	Credential     string `json:"credential"`
	Enabled        bool   `json:"enabled"`
	Version        int    `json:"version"`
	ChrootVerified bool   `json:"chroot_verified"`
}
type Credential struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Public      string `json:"public"`
	Fingerprint string `json:"fingerprint"`
	Cipher      string `json:"cipher,omitempty"`
	Enabled     bool   `json:"enabled"`
	Version     int    `json:"version"`
}
type Limits struct {
	MaxDuration   int   `json:"max_duration"`
	MaxTTL        int   `json:"max_ttl"`
	MaxTotal      int   `json:"max_total"`
	MaxConcurrent int   `json:"max_concurrent"`
	MaxSessions   int   `json:"max_sessions"`
	MaxChannels   int   `json:"max_channels"`
	MaxBytes      int64 `json:"max_bytes"`
	MaxRate       int64 `json:"max_rate"`
}

func DefaultLimits() Limits { return Limits{7200, 300, 1, 1, 1, 1, 0, 0} }

type Grant struct {
	ID        string   `json:"id"`
	Subject   string   `json:"subject"`
	Group     string   `json:"group,omitempty"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
	Parent    string   `json:"parent,omitempty"`
	Issuer    string   `json:"issuer"`
	Expires   int64    `json:"expires"`
	NotBefore int64    `json:"not_before"`
	Depth     int      `json:"depth"`
	Enabled   bool     `json:"enabled"`
	Deny      bool     `json:"deny"`
	Limits    Limits   `json:"limits"`
	CIDRs     []string `json:"cidrs"`
}
type Spec struct {
	Account    string            `json:"account"`
	Modes      []string          `json:"modes"`
	Command    string            `json:"command,omitempty"`
	PTY        string            `json:"pty"`
	Env        map[string]string `json:"env,omitempty"`
	TTL        int               `json:"ttl"`
	Duration   int               `json:"duration"`
	Total      int               `json:"total"`
	Concurrent int               `json:"concurrent"`
	Sessions   int               `json:"sessions"`
	Channels   int               `json:"channels"`
	MaxBytes   int64             `json:"max_bytes"`
	MaxRate    int64             `json:"max_rate"`
	CIDRs      []string          `json:"cidrs,omitempty"`
	Reconnect  bool              `json:"reconnect"`
	FileRoot   string            `json:"file_root,omitempty"`
	FileOps    []string          `json:"file_ops,omitempty"`
	StrictPath bool              `json:"strict_path"`
	LocalPath  string            `json:"local_path,omitempty"`
	RemotePath string            `json:"remote_path,omitempty"`
	Direction  string            `json:"direction,omitempty"`
	TCPHost    string            `json:"tcp_host,omitempty"`
	TCPRoute   string            `json:"tcp_route,omitempty"`
	TCPPort    int               `json:"tcp_port,omitempty"`
	LocalPort  int               `json:"local_port,omitempty"`
}
type Ticket struct {
	ID                string   `json:"id"`
	Username          string   `json:"username"`
	Owner             string   `json:"owner"`
	Source            string   `json:"source"`
	SourceKey         string   `json:"source_key"`
	PasswordHash      string   `json:"-"`
	Spec              Spec     `json:"spec"`
	Created           int64    `json:"created"`
	Expires           int64    `json:"expires"`
	State             string   `json:"state"`
	Used              int      `json:"used"`
	Active            int      `json:"active"`
	AssetVersion      int      `json:"asset_version"`
	AccountVersion    int      `json:"account_version"`
	CredentialVersion int      `json:"credential_version"`
	GrantIDs          []string `json:"grant_ids"`
	Revoked           bool     `json:"revoked"`
}
type Event struct {
	Time     int64  `json:"time"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Result   string `json:"result"`
	Source   string `json:"source"`
	Detail   string `json:"detail"`
}

var Capabilities = strings.Fields("asset.read asset.create asset.update asset.delete asset.trust asset.special account.read account.create account.update account.delete account.chroot credential.read credential.create credential.import credential.generate credential.update credential.delete credential.test credential.bind user.read user.create user.update user.delete user.owner key.read key.create key.update key.delete group.read group.create group.update group.delete grant.read grant.create grant.update grant.delete session.read session.terminate audit.read audit.export config.read config.update backup.create backup.restore shell.direct proxy.create proxy.read proxy.revoke proxy.shell proxy.exec proxy.sftp proxy.scp proxy.tcp proxy.tcp.jump proxy.tcp.special proxy.multi proxy.reconnect file.read file.write file.list file.mkdir file.remove file.rename file.metadata web.login")

func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func subset(a, b []string) bool {
	for _, v := range a {
		if !contains(b, "*") && !contains(b, v) {
			return false
		}
	}
	return true
}

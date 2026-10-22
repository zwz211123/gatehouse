package gh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

func requireStopped(c Config) error {
	fp := filepath.Join(c.Run, "admin.sock")
	if _, e := os.Stat(fp); os.IsNotExist(e) {
		return nil
	}
	conn, e := net.Dial("unix", fp)
	if e == nil {
		conn.Close()
		return fmt.Errorf("stop Gatehouse services first")
	}
	if !errors.Is(e, syscall.ECONNREFUSED) && !errors.Is(e, syscall.ENOENT) {
		return fmt.Errorf("cannot verify stopped service: %w", e)
	}
	return nil
}
func RecoverOwner(c Config, name, pubfile string) error {
	if e := requireStopped(c); e != nil {
		return e
	}
	lock, e := lockData(c.Data)
	if e != nil {
		return e
	}
	defer lock.Close()
	if !allowedName(name) {
		return fmt.Errorf("invalid username")
	}
	raw, e := os.ReadFile(pubfile)
	if e != nil {
		return e
	}
	p, _, _, rest, e := ssh.ParseAuthorizedKey(raw)
	if e != nil || len(strings.TrimSpace(string(rest))) != 0 || !validUserKey(p) {
		return fmt.Errorf("invalid public key")
	}
	s, e := OpenStore(c.Data)
	if e != nil {
		return e
	}
	defer s.Close()
	users, e := list[User](s, "user")
	if e != nil {
		return e
	}
	var u User
	for _, x := range users {
		if x.Name == name {
			u = x
		}
	}
	if u.ID == "" {
		u = User{ID: newID(), Name: name}
	}
	u.Enabled = true
	u.Owner = true
	keys, _ := list[Key](s, "key")
	key := Key{ID: newID(), User: u.ID, Public: strings.TrimSpace(string(sshPublic(p))), Fingerprint: ssh.FingerprintSHA256(p), Enabled: true}
	for _, k := range keys {
		if k.Fingerprint == key.Fingerprint {
			if k.User != u.ID {
				return fmt.Errorf("public key belongs to another user")
			}
			key.ID = k.ID
		}
	}
	if e = s.Put("user", u.ID, u); e != nil {
		return e
	}
	if e = s.Put("key", key.ID, key); e != nil {
		return e
	}
	grants, _ := list[Grant](s, "grant")
	for _, g := range grants {
		if g.Deny && g.Subject == u.ID {
			g.Enabled = false
			s.Put("grant", g.ID, g)
		}
	}
	groups, _ := list[Group](s, "group")
	for _, g := range groups {
		denies := false
		for _, a := range grants {
			if a.Deny && a.Group == g.ID {
				denies = true
			}
		}
		if denies && contains(g.Members, u.ID) {
			members := []string{}
			for _, id := range g.Members {
				if id != u.ID {
					members = append(members, id)
				}
			}
			g.Members = members
			s.Put("group", g.ID, g)
		}
	}
	if e = s.Audit(Event{Actor: u.ID, Action: "owner.recover", Result: "ok", Source: "offline-root"}); e != nil {
		return e
	}
	return adoptCoreData(c)
}
func ExportMaster(c Config, destination string) error {
	if destination == "" {
		return fmt.Errorf("output path required")
	}
	b, e := os.ReadFile(filepath.Join(c.Data, "master.key"))
	if e != nil {
		return e
	}
	return writeExclusive(destination, b, 0600)
}

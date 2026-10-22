package gh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func Initialize(c Config, name, pubfile, configPath string) (result error) {
	if e := c.Validate(); e != nil {
		return e
	}
	if c.TLSCert != "" {
		if e := validateTLS(c, c.TLSCert, c.TLSKey); e != nil {
			return e
		}
	}
	if !allowedName(name) || c.PublicHost == "" {
		return fmt.Errorf("valid username and public_host required")
	}
	u, e := url.Parse(c.WebURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("valid HTTPS web_url required")
	}
	if _, e = os.Lstat(configPath); !os.IsNotExist(e) {
		return fmt.Errorf("configuration already exists or is inaccessible")
	}
	if e = os.MkdirAll(c.Data, 0700); e != nil {
		return e
	}
	lock, e := lockData(c.Data)
	if e != nil {
		return e
	}
	defer lock.Close()
	entries, e := os.ReadDir(c.Data)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.Name() != ".core.lock" {
			return fmt.Errorf("initialization requires an empty data directory")
		}
	}
	if _, e = os.Stat(filepath.Join(c.Data, "master.key")); !os.IsNotExist(e) {
		return fmt.Errorf("already initialized or path inaccessible")
	}
	pub, e := os.ReadFile(pubfile)
	if e != nil {
		return e
	}
	pk, _, _, rest, e := ssh.ParseAuthorizedKey(pub)
	if e != nil || len(strings.TrimSpace(string(rest))) != 0 || !validUserKey(pk) {
		return fmt.Errorf("one public key required")
	}
	if e = os.MkdirAll(c.Data, 0700); e != nil {
		return e
	}
	if e = os.Chmod(c.Data, 0700); e != nil {
		return e
	}
	// Only files created by this initialization are removed on failure.
	defer func() {
		if result != nil {
			for _, name := range []string{"master.key", "host.key", "host.pub", "gatehouse.db", "gatehouse.db-wal", "gatehouse.db-shm"} {
				os.Remove(filepath.Join(c.Data, name))
			}
			os.Remove(configPath)
		}
	}()
	master := make([]byte, 32)
	if _, e = rand.Read(master); e != nil {
		return e
	}
	if e = writeExclusive(filepath.Join(c.Data, "master.key"), master, 0600); e != nil {
		return e
	}
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	block, e := ssh.MarshalPrivateKey(private, "Gatehouse host")
	if e != nil {
		return e
	}
	if e = writeExclusive(filepath.Join(c.Data, "host.key"), pem.EncodeToMemory(block), 0600); e != nil {
		return e
	}
	signer, _ := ssh.NewSignerFromKey(private)
	if e = os.WriteFile(filepath.Join(c.Data, "host.pub"), sshPublic(signer.PublicKey()), 0644); e != nil {
		return e
	}
	s, e := OpenStore(c.Data)
	if e != nil {
		return e
	}
	defer s.Close()
	id := newID()
	user := User{ID: id, Name: name, Enabled: true, Owner: true}
	if e = s.Put("user", id, user); e != nil {
		return e
	}
	key := Key{ID: newID(), User: id, Public: strings.TrimSpace(string(sshPublic(pk))), Fingerprint: ssh.FingerprintSHA256(pk), Enabled: true}
	if e = s.Put("key", key.ID, key); e != nil {
		return e
	}
	if e = s.Audit(Event{Actor: id, Action: "initialize", Result: "ok", Source: "local-root"}); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(configPath), 0755); e != nil {
		return e
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	if e = atomicFile(configPath, append(data, '\n'), 0644); e != nil {
		return e
	}
	if e = adoptCoreData(c); e != nil {
		return e
	}
	if c.TLSCert != "" && c.TLSKey != "" {
		return InstallTLS(c, c.TLSCert, c.TLSKey, configPath)
	}
	return nil
}
func writeExclusive(path string, b []byte, mode os.FileMode) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.Write(b)
	if e != nil {
		return e
	}
	return f.Sync()
}

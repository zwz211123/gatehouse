package gh

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/ssh"
)

// CheckUpgrade validates the existing schema and encrypted identity material
// without rewriting records, revisions, audit events, configuration or keys.
// It is deliberately offline; the same data lock is held by the running core.
func CheckUpgrade(c Config) (result error) {
	if e := c.Validate(); e != nil {
		return e
	}
	if e := requireStopped(c); e != nil {
		return e
	}
	lock, e := lockData(c.Data)
	if e != nil {
		return e
	}
	defer lock.Close()
	// SQLite read-only WAL access can create sidecars. Root administration must
	// leave those files and a newly-created lock usable by the core data owner.
	defer func() {
		if e := adoptUpgradeSidecars(c.Data); result == nil {
			result = e
		}
	}()

	master, e := os.ReadFile(filepath.Join(c.Data, "master.key"))
	if e != nil {
		return e
	}
	if len(master) != 32 {
		return fmt.Errorf("invalid master key")
	}
	uri := url.URL{Scheme: "file", Path: filepath.Join(c.Data, "gatehouse.db"), RawQuery: "mode=ro"}
	db, e := sql.Open("sqlite", uri.String())
	if e != nil {
		return e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var schema int
	if e = db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&schema); e != nil || schema != 1 {
		return fmt.Errorf("upgrade requires database schema 1")
	}
	var integrity string
	if e = db.QueryRow("PRAGMA integrity_check").Scan(&integrity); e != nil || integrity != "ok" {
		return fmt.Errorf("database integrity check failed")
	}
	s := &Store{db: db, master: master}
	// Decode every record, including internal ticket state, without canonicalizing it.
	rows, e := db.Query("SELECT kind,id,data FROM records")
	if e != nil {
		return e
	}
	for rows.Next() {
		var kind, id, data string
		if e = rows.Scan(&kind, &id, &data); e != nil {
			break
		}
		if !json.Valid([]byte(data)) {
			e = fmt.Errorf("invalid JSON record %s/%s", kind, id)
			break
		}
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	credentials, e := list[Credential](s, "credential")
	if e != nil {
		return e
	}
	for _, credential := range credentials {
		plain, err := s.Unseal(credential.ID, credential.Cipher)
		if err != nil {
			return fmt.Errorf("cannot decrypt credential %s", credential.ID)
		}
		signer, err := ssh.ParsePrivateKey(plain)
		for i := range plain {
			plain[i] = 0
		}
		if err != nil {
			return fmt.Errorf("invalid private key in credential %s", credential.ID)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(credential.Public))
		if err != nil || !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) || ssh.FingerprintSHA256(pub) != credential.Fingerprint {
			return fmt.Errorf("credential identity mismatch %s", credential.ID)
		}
	}
	raw, e := os.ReadFile(filepath.Join(c.Data, "host.key"))
	if e != nil {
		return e
	}
	signer, e := ssh.ParsePrivateKey(raw)
	if e != nil {
		return fmt.Errorf("invalid SSH host key")
	}
	public, e := os.ReadFile(filepath.Join(c.Data, "host.pub"))
	if e != nil {
		return e
	}
	pub, _, _, _, e := ssh.ParseAuthorizedKey(public)
	if e != nil || !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		return fmt.Errorf("SSH host key pair mismatch")
	}
	return nil
}

func adoptUpgradeSidecars(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	info, e := os.Stat(dir)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine data owner")
	}
	for _, name := range []string{".core.lock", "gatehouse.db-wal", "gatehouse.db-shm"} {
		path := filepath.Join(dir, name)
		info, e := os.Lstat(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("invalid SQLite sidecar")
		}
		if e = os.Chown(path, int(st.Uid), int(st.Gid)); e != nil {
			return e
		}
		if e = os.Chmod(path, 0600); e != nil {
			return e
		}
	}
	return nil
}

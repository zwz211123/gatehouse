package gh

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
)

func protect(plain []byte, password string) ([]byte, error) {
	salt := make([]byte, 32)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	key, e := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	nonce := make([]byte, a.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return nil, e
	}
	prefix := append([]byte("GHB1"), salt...)
	prefix = append(prefix, nonce...)
	return a.Seal(prefix, nonce, plain, []byte("gatehouse-backup-v1")), nil
}
func unprotect(data []byte, password string) ([]byte, error) {
	if len(data) < 64 || string(data[:4]) != "GHB1" {
		return nil, fmt.Errorf("invalid backup header")
	}
	key, e := scrypt.Key([]byte(password), data[4:36], 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	return a.Open(nil, data[36:48], data[48:], []byte("gatehouse-backup-v1"))
}
func Backup(c Config, destination, password string) (result error) {
	s, e := OpenStore(c.Data)
	if e != nil {
		return e
	}
	defer func() {
		s.Close()
		if e := adoptCoreData(c); result == nil {
			result = e
		}
	}()
	if destination == "" {
		return fmt.Errorf("output file required")
	}
	temp, e := os.MkdirTemp(c.Data, ".backup-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	snapshot := filepath.Join(temp, "snapshot.db")
	if _, e = s.db.Exec("VACUUM INTO ?", snapshot); e != nil {
		return e
	}
	db, e := sql.Open("sqlite", snapshot)
	if e != nil {
		return e
	}
	_, e = db.Exec("DELETE FROM records WHERE kind IN ('ticket','ticket-secret','ticket-failures')")
	db.Close()
	if e != nil {
		return e
	}
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	files := map[string]string{"gatehouse.db": snapshot, "host.key": filepath.Join(c.Data, "host.key"), "host.pub": filepath.Join(c.Data, "host.pub")}
	for name, fp := range files {
		body, e := os.ReadFile(fp)
		if e != nil {
			return e
		}
		if e = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body))}); e != nil {
			return e
		}
		if _, e = tw.Write(body); e != nil {
			return e
		}
	}
	config, _ := json.Marshal(c)
	if e = tw.WriteHeader(&tar.Header{Name: "config.json", Mode: 0600, Size: int64(len(config))}); e != nil {
		return e
	}
	if _, e = tw.Write(config); e != nil {
		return e
	}
	if e = tw.Close(); e != nil {
		return e
	}
	if e = gz.Close(); e != nil {
		return e
	}
	encrypted, e := protect(b.Bytes(), password)
	if e != nil {
		return e
	}
	if e = writeExclusive(destination, encrypted, 0600); e != nil {
		return e
	}
	return s.Audit(Event{Time: now(), Actor: "local-root", Action: "backup.create", Result: "ok"})
}
func Restore(c Config, source, password string) error {
	if e := requireStopped(c); e != nil {
		return e
	}
	lock, e := lockData(c.Data)
	if e != nil {
		return e
	}
	defer lock.Close()
	st, e := os.Stat(source)
	if e != nil || st.Size() > 512<<20 {
		return fmt.Errorf("backup unavailable or too large")
	}
	encrypted, e := os.ReadFile(source)
	if e != nil {
		return e
	}
	body, e := unprotect(encrypted, password)
	if e != nil {
		return fmt.Errorf("backup authentication failed")
	}
	gz, e := gzip.NewReader(bytes.NewReader(body))
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 1<<30))
	tmp, e := os.MkdirTemp(c.Data, ".restore-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	allowed := map[string]bool{"gatehouse.db": true, "host.key": true, "host.pub": true, "config.json": true}
	seen := map[string]bool{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if !allowed[h.Name] || seen[h.Name] || h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > 512<<20 {
			return fmt.Errorf("invalid archive member")
		}
		seen[h.Name] = true
		f, e := os.OpenFile(filepath.Join(tmp, h.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = io.CopyN(f, tr, h.Size)
		f.Close()
		if e != nil {
			return e
		}
	}
	if len(seen) != 4 {
		return fmt.Errorf("incomplete archive")
	}
	master, e := os.ReadFile(filepath.Join(c.Data, "master.key"))
	if e != nil {
		return fmt.Errorf("matching master.key must be restored separately first")
	}
	if e = os.WriteFile(filepath.Join(tmp, "master.key"), master, 0600); e != nil {
		return e
	}
	s, e := OpenStore(tmp)
	if e != nil {
		return e
	}
	var integrity string
	e = s.db.QueryRow("PRAGMA integrity_check").Scan(&integrity)
	if e != nil || integrity != "ok" {
		s.Close()
		return fmt.Errorf("invalid database")
	}
	hostRaw, err := os.ReadFile(filepath.Join(tmp, "host.key"))
	if err != nil {
		s.Close()
		return err
	}
	signer, err := ssh.ParsePrivateKey(hostRaw)
	if err != nil {
		s.Close()
		return fmt.Errorf("invalid backup SSH host key")
	}
	hostPub, err := os.ReadFile(filepath.Join(tmp, "host.pub"))
	if err != nil {
		s.Close()
		return err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(hostPub)
	if err != nil || !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		s.Close()
		return fmt.Errorf("backup SSH host public key does not match private key")
	}
	users, err := list[User](s, "user")
	if err != nil {
		s.Close()
		return err
	}
	keys, err := list[Key](s, "key")
	if err != nil {
		s.Close()
		return err
	}
	effective := false
	for _, u := range users {
		if u.Enabled && u.Owner {
			for _, k := range keys {
				if k.User == u.ID && k.Enabled {
					p, _, _, _, e := ssh.ParseAuthorizedKey([]byte(k.Public))
					if e == nil && validUserKey(p) && ssh.FingerprintSHA256(p) == k.Fingerprint {
						effective = true
					}
				}
			}
		}
	}
	if !effective {
		s.Close()
		return fmt.Errorf("backup has no usable owner public key")
	}
	credentials, e := list[Credential](s, "credential")
	if e != nil {
		s.Close()
		return e
	}
	for _, k := range credentials {
		if _, e = s.Unseal(k.ID, k.Cipher); e != nil {
			s.Close()
			return fmt.Errorf("master key does not match archive")
		}
	}
	if e = s.Audit(Event{Actor: "local-root", Action: "backup.restore", Result: "ok", Source: "offline"}); e != nil {
		s.Close()
		return e
	}
	if _, e = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
		s.Close()
		return e
	}
	s.Close()
	// A whole-directory swap avoids exposing a half-restored database/key pair.
	parent := filepath.Dir(c.Data)
	stage, e := os.MkdirTemp(parent, ".gatehouse-restored-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	for _, name := range []string{"gatehouse.db", "host.key", "host.pub", "master.key"} {
		b, e := os.ReadFile(filepath.Join(tmp, name))
		if e != nil {
			return e
		}
		if e = atomicFile(filepath.Join(stage, name), b, 0600); e != nil {
			return e
		}
	}
	stagedLock, e := lockData(stage)
	if e != nil {
		return e
	}
	defer stagedLock.Close()
	old := c.Data + ".before-restore-" + newID()
	if e = os.Rename(c.Data, old); e != nil {
		return e
	}
	if e = os.Rename(stage, c.Data); e != nil {
		os.Rename(old, c.Data)
		return e
	}
	if e = adoptCoreData(c); e != nil {
		return e
	}
	fmt.Printf("Restored; old data retained at %s. Reapply gatehouse-core ownership. Existing configuration/TLS paths retained.\n", old)
	return nil
}

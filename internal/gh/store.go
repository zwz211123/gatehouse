package gh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type Store struct {
	db     *sql.DB
	master []byte
}

func OpenStore(dir string) (*Store, error) {
	b, e := os.ReadFile(filepath.Join(dir, "master.key"))
	if e != nil {
		return nil, e
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid master key")
	}
	db, e := sql.Open("sqlite", filepath.Join(dir, "gatehouse.db"))
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA foreign_keys=ON;PRAGMA busy_timeout=5000;CREATE TABLE IF NOT EXISTS records(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(kind,id));CREATE TABLE IF NOT EXISTS audits(seq INTEGER PRIMARY KEY AUTOINCREMENT,data TEXT NOT NULL);CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);INSERT OR IGNORE INTO schema_migrations VALUES(1);`)
	if e != nil {
		db.Close()
		return nil, e
	}
	var version int
	if e = db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); e != nil || version != 1 {
		db.Close()
		return nil, fmt.Errorf("unsupported database schema")
	}
	os.Chmod(filepath.Join(dir, "gatehouse.db"), 0600)
	return &Store{db: db, master: b}, nil
}
func (s *Store) Close() { s.db.Close() }
func (s *Store) Get(kind, id string, out any) error {
	var b string
	e := s.db.QueryRow("SELECT data FROM records WHERE kind=? AND id=?", kind, id).Scan(&b)
	if e != nil {
		return e
	}
	return json.Unmarshal([]byte(b), out)
}
func list[T any](s *Store, kind string) ([]T, error) {
	rows, e := s.db.Query("SELECT data FROM records WHERE kind=? ORDER BY id", kind)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	a := []T{}
	for rows.Next() {
		var b string
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		var v T
		if e = json.Unmarshal([]byte(b), &v); e != nil {
			return nil, e
		}
		a = append(a, v)
	}
	return a, rows.Err()
}
func (s *Store) Put(kind, id string, v any) error {
	_, e := s.db.Exec("INSERT INTO records(kind,id,data)VALUES(?,?,?)ON CONFLICT(kind,id)DO UPDATE SET data=excluded.data,revision=records.revision+1", kind, id, encode(v))
	return e
}
func (s *Store) Delete(kind, id string) error {
	_, e := s.db.Exec("DELETE FROM records WHERE kind=? AND id=?", kind, id)
	return e
}
func (s *Store) Audit(e Event) error {
	e.Time = now()
	_, err := s.db.Exec("INSERT INTO audits(data)VALUES(?)", encode(e))
	return err
}
func (s *Store) Events(limit int) ([]Event, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	rows, e := s.db.Query("SELECT data FROM audits ORDER BY seq DESC LIMIT ?", limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	a := []Event{}
	for rows.Next() {
		var b string
		var v Event
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(b), &v); e != nil {
			return nil, e
		}
		a = append(a, v)
	}
	return a, rows.Err()
}
func sealBytes(key, plain, aad []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return a.Seal(nonce, nonce, plain, aad), nil
}
func openBytes(key, encoded, aad []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	if len(encoded) < a.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	return a.Open(nil, encoded[:a.NonceSize()], encoded[a.NonceSize():], aad)
}

type envelope struct {
	Version       int
	Wrapped, Data []byte
}

func (s *Store) Seal(id string, plain []byte) (string, error) {
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return "", e
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	aad := []byte("gatehouse:v1:" + id)
	wrapped, e := sealBytes(s.master, key, append(aad, []byte(":key")...))
	if e != nil {
		return "", e
	}
	data, e := sealBytes(key, plain, aad)
	if e != nil {
		return "", e
	}
	b, e := json.Marshal(envelope{1, wrapped, data})
	if e != nil {
		return "", e
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}
func (s *Store) Unseal(id, value string) ([]byte, error) {
	b, e := base64.RawStdEncoding.DecodeString(value)
	if e != nil {
		return nil, e
	}
	var v envelope
	if json.Unmarshal(b, &v) != nil || v.Version != 1 {
		return nil, fmt.Errorf("invalid envelope")
	}
	aad := []byte("gatehouse:v1:" + id)
	key, e := openBytes(s.master, v.Wrapped, append(aad, []byte(":key")...))
	if e != nil {
		return nil, e
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	return openBytes(key, v.Data, aad)
}

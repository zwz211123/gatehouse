package gh

import (
	"bytes"
	"encoding/json"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialRejectsAmbiguousKeySource(t *testing.T) {
	f := setup(t)
	before := etag(t, f.c, "credential", "cred")
	_, e := f.c.Change(ownerWeb(f), Change{Kind: "credential", Operation: "update", ID: "cred", ETag: before, Data: json.RawMessage(`{"name":"ambiguous","enabled":true,"generate":true,"private":"SHOULD NEVER BE IGNORED"}`)}, "test")
	if e == nil {
		t.Fatal("ambiguous key source accepted")
	}
	if after := etag(t, f.c, "credential", "cred"); after != before {
		t.Fatal("rejected input changed stored credential")
	}
}

func TestUpgradePreservesExistingRecordsAndCredentials(t *testing.T) {
	f := setup(t)
	c := f.c.Config
	if e := CheckUpgrade(c); e == nil {
		t.Fatal("upgrade check allowed while core holds lock")
	}
	// Older integration fixtures omit display metadata; real stored credentials
	// include it. Reconstruct metadata from the same encrypted key for this test.
	var fixtureCredential Credential
	if e := f.c.Store.Get("credential", "cred", &fixtureCredential); e != nil {
		t.Fatal(e)
	}
	raw, e := f.c.Store.Unseal("cred", fixtureCredential.Cipher)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.ParsePrivateKey(raw)
	if e != nil {
		t.Fatal(e)
	}
	fixtureCredential.Public = string(sshPublic(signer.PublicKey()))
	fixtureCredential.Fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
	if e = f.c.Store.Put("credential", "cred", fixtureCredential); e != nil {
		t.Fatal(e)
	}
	f.c.Close()
	s, e := OpenStore(c.Data)
	if e != nil {
		t.Fatal(e)
	}
	// Include delegated permissions, unknown/internal records and deny conditions:
	// an identity migration must not reserialize any of them.
	records := map[string]json.RawMessage{
		"grant":           json.RawMessage(`{"id":"legacy","subject":"existing-user","issuer":"existing-owner","actions":["proxy.shell","web.login"],"resources":["account"],"enabled":true,"deny":true,"cidrs":["203.0.113.0/24"],"depth":2,"future_field":{"preserve":true}}`),
		"legacy-internal": json.RawMessage(`{"secret":"do not rewrite","unknown":true}`),
	}
	for kind, value := range records {
		if e = s.Put(kind, "legacy", value); e != nil {
			t.Fatal(e)
		}
	}
	before, e := list[map[string]any](s, "credential")
	if e != nil {
		t.Fatal(e)
	}
	var original string
	if e = s.db.QueryRow("SELECT group_concat(kind||id||data||revision,'|') FROM (SELECT * FROM records ORDER BY kind,id)").Scan(&original); e != nil {
		t.Fatal(e)
	}
	s.Close()
	saved := map[string][]byte{}
	for _, name := range []string{"master.key", "host.key", "host.pub"} {
		saved[name], e = os.ReadFile(filepath.Join(c.Data, name))
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = CheckUpgrade(c); e != nil {
		t.Fatal(e)
	}
	for name, raw := range saved {
		after, e := os.ReadFile(filepath.Join(c.Data, name))
		if e != nil || !bytes.Equal(raw, after) {
			t.Fatalf("identity changed: %s", name)
		}
	}
	s, e = OpenStore(c.Data)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var after string
	if e = s.db.QueryRow("SELECT group_concat(kind||id||data||revision,'|') FROM (SELECT * FROM records ORDER BY kind,id)").Scan(&after); e != nil {
		t.Fatal(e)
	}
	if original != after {
		t.Fatal("upgrade rewrote legacy records or revisions")
	}
	remaining, e := list[map[string]any](s, "credential")
	if e != nil || encode(before) != encode(remaining) {
		t.Fatal("credential envelopes changed")
	}
	// Corrupted ciphertext is detected before any new service is started.
	var cred Credential
	if e = s.Get("credential", "cred", &cred); e != nil {
		t.Fatal(e)
	}
	cred.Cipher = "corrupt"
	s.Put("credential", cred.ID, cred)
	if e = CheckUpgrade(c); e == nil {
		t.Fatal("corrupted credential was accepted")
	}
	s.db.Exec("INSERT INTO schema_migrations VALUES(2)")
	if e = CheckUpgrade(c); e == nil {
		t.Fatal("future schema was accepted")
	}
}

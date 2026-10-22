package gh

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

func adoptCoreData(c Config) error {
	if os.Geteuid() != 0 {
		return nil
	}
	u, e := user.Lookup("gatehouse-core")
	if e != nil {
		return nil
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return filepath.WalkDir(c.Data, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in data directory")
		}
		return os.Chown(path, uid, gid)
	})
}
func InstallTLS(c Config, certPath, keyPath, configPath string) error {
	if e := validateTLS(c, certPath, keyPath); e != nil {
		return e
	}
	cert, e := os.ReadFile(certPath)
	if e != nil {
		return e
	}
	key, e := os.ReadFile(keyPath)
	if e != nil {
		return e
	}
	base := filepath.Join(filepath.Dir(configPath), "tls")
	if e = os.MkdirAll(base, 0755); e != nil {
		return e
	}
	dir, e := os.MkdirTemp(base, "pair-")
	if e != nil {
		return e
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(dir)
		}
	}()
	if e = os.Chmod(dir, 0750); e != nil {
		return e
	}
	if e = os.MkdirAll(dir, 0750); e != nil {
		return e
	}
	c.TLSCert = filepath.Join(dir, "fullchain.pem")
	c.TLSKey = filepath.Join(dir, "key.pem")
	if e = os.WriteFile(c.TLSCert, cert, 0640); e != nil {
		return e
	}
	if e = os.WriteFile(c.TLSKey, key, 0640); e != nil {
		return e
	}
	if u, e := user.Lookup(c.WebUser); e == nil {
		gid, _ := strconv.Atoi(u.Gid)
		for _, p := range []string{dir, c.TLSCert, c.TLSKey} {
			if e = os.Chown(p, 0, gid); e != nil {
				return e
			}
		}
	}
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	if e = atomicFile(configPath, append(b, '\n'), 0644); e != nil {
		return e
	}
	committed = true
	return nil
}

func validateTLS(c Config, certPath, keyPath string) error {
	pair, e := tls.LoadX509KeyPair(certPath, keyPath)
	if e != nil {
		return e
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return e
	}
	u, e := url.Parse(c.WebURL)
	if e != nil {
		return e
	}
	if e = cert.VerifyHostname(u.Hostname()); e != nil {
		return e
	}
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return fmt.Errorf("TLS certificate outside validity period")
	}
	return nil
}

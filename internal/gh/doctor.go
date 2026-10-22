package gh

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"syscall"
)

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Doctor is read-only with respect to keys, records and configuration. It creates
// a private short-lived socket to verify the host's Unix socket support.
func Doctor(c Config) []Check {
	out := []Check{}
	add := func(name string, e error) {
		v := Check{Name: name, OK: e == nil, Detail: "ok"}
		if e != nil {
			v.Detail = e.Error()
		}
		out = append(out, v)
	}
	add("configuration", c.Validate())
	for _, name := range []string{"gatehouse-core", c.SSHUser, c.WebUser} {
		_, e := user.Lookup(name)
		add("service-user:"+name, e)
	}
	for _, name := range []string{"master.key", "host.key", "gatehouse.db"} {
		st, e := os.Lstat(filepath.Join(c.Data, name))
		if e == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
			e = fmt.Errorf("must be a regular file with no group/other permissions")
		}
		add("private-file:"+name, e)
	}
	b, e := os.ReadFile(filepath.Join(c.Data, "master.key"))
	if e == nil && len(b) != 32 {
		e = fmt.Errorf("master key must be 32 bytes")
	}
	add("master-key", e)
	b, e = os.ReadFile(filepath.Join(c.Data, "host.key"))
	if e == nil {
		_, e = ssh.ParsePrivateKey(b)
	}
	add("ssh-host-key", e)
	pair, e := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
	if e == nil {
		var cert *x509.Certificate
		cert, e = x509.ParseCertificate(pair.Certificate[0])
		if e == nil {
			u, _ := url.Parse(c.WebURL)
			e = cert.VerifyHostname(u.Hostname())
			if e == nil && (time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter)) {
				e = fmt.Errorf("TLS certificate outside validity period")
			}
		}
	}
	add("https-certificate", e)
	for _, address := range []string{c.SSHListen, c.WebListen} {
		_, p, _ := net.SplitHostPort(address)
		port, _ := strconv.Atoi(p)
		var e error
		if port < 1024 {
			e = fmt.Errorf("packaged service users cannot bind ports below 1024; use a high port or explicit systemd override")
		}
		add("unprivileged-listener:"+address, e)
	}
	dir, e := os.MkdirTemp("", "gatehouse-doctor-")
	if e == nil {
		defer os.RemoveAll(dir)
		var l net.Listener
		l, e = net.Listen("unix", filepath.Join(dir, "test.sock"))
		if e == nil {
			l.Close()
		}
	}
	add("unix-socket-support", e)
	// The installation keeps all private data inaccessible to ingress users.
	for _, spec := range []struct {
		path string
		mask os.FileMode
	}{{c.Data, 0077}, {c.Run, 0027}} {
		st, e := os.Lstat(spec.path)
		if e == nil && (!st.IsDir() || st.Mode().Perm()&spec.mask != 0) {
			e = fmt.Errorf("unsafe directory permissions")
		}
		if os.IsNotExist(e) && spec.path == c.Run {
			e = nil
		}
		add("directory:"+spec.path, e)
	}
	if u, e := user.Lookup("gatehouse-core"); e == nil {
		uid, _ := strconv.Atoi(u.Uid)
		st, e := os.Stat(c.Data)
		if e == nil {
			if raw, ok := st.Sys().(*syscall.Stat_t); ok && int(raw.Uid) != uid {
				e = fmt.Errorf("data directory must belong to gatehouse-core")
			}
		}
		add("data-owner", e)
	}
	return out
}

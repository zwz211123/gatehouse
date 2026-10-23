package gh

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Set by the build pipeline; direct go builds are explicitly development builds.
var Version = "dev"
var Commit = "unknown"

type Config struct {
	Data           string `json:"data"`
	Run            string `json:"run"`
	SSHListen      string `json:"ssh_listen"`
	PublicHost     string `json:"public_host"`
	PublicPort     int    `json:"public_port"`
	WebListen      string `json:"web_listen"`
	WebURL         string `json:"web_url"`
	TLSCert        string `json:"tls_cert"`
	TLSKey         string `json:"tls_key"`
	SSHUser        string `json:"ssh_user"`
	WebUser        string `json:"web_user"`
	MaxConnections int    `json:"max_connections"`
}

func DefaultConfig() Config {
	return Config{Data: "/var/lib/gatehouse", Run: "/run/gatehouse", SSHListen: "0.0.0.0:2222", PublicHost: "", PublicPort: 2222, WebListen: "127.0.0.1:8443", WebURL: "", SSHUser: "gatehouse-ssh", WebUser: "gatehouse-web", MaxConnections: 128}
}
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(b, &c)
	if e != nil {
		return c, e
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if !filepath.IsAbs(c.Data) || !filepath.IsAbs(c.Run) || filepath.Clean(c.Data) == "/" || filepath.Clean(c.Run) == "/" || c.PublicPort < 1 || c.PublicPort > 65535 || c.MaxConnections < 1 || c.MaxConnections > 4096 {
		return fmt.Errorf("invalid paths, port or connection limit")
	}
	data, run := filepath.Clean(c.Data), filepath.Clean(c.Run)
	if data == run || strings.HasPrefix(run, data+"/") || strings.HasPrefix(data, run+"/") {
		return fmt.Errorf("data and runtime directories must be separate")
	}
	if c.PublicHost == "" || strings.HasPrefix(c.PublicHost, "-") || strings.ContainsAny(c.PublicHost, " /\\\t\r\n\x00@[]") || len(c.PublicHost) > 253 {
		return fmt.Errorf("invalid public host")
	}
	if net.ParseIP(c.PublicHost) == nil {
		for _, label := range strings.Split(strings.TrimSuffix(c.PublicHost, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return fmt.Errorf("invalid public hostname")
			}
			for _, v := range label {
				if !(v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' || v == '-') {
					return fmt.Errorf("invalid public hostname")
				}
			}
		}
	}
	for _, address := range []string{c.SSHListen, c.WebListen} {
		_, port, e := net.SplitHostPort(address)
		if e != nil {
			return fmt.Errorf("invalid listen address: %s", address)
		}
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid listen port")
		}
	}
	u, e := url.Parse(c.WebURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("web_url must be an HTTPS origin")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("both TLS certificate and key required")
	}
	if c.SSHUser == "" || c.WebUser == "" {
		return fmt.Errorf("ingress service users required")
	}
	return nil
}

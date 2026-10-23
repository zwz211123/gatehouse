package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/zwz211123/gatehouse/internal/gh"
)

var role = "cli"

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "gatehouse:", e)
		os.Exit(1)
	}
}
func run() error {
	args := os.Args[1:]
	cmd := ""
	if role == "cli" {
		if len(args) == 0 {
			return fmt.Errorf("commands: init, doctor, status, list, apply, tls, backup, restore, export-master, recover-owner, upgrade-check, version")
		}
		cmd = args[0]
		args = args[1:]
		if cmd == "version" {
			if len(args) == 1 && args[0] == "--json" {
				return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": gh.Version, "commit": gh.Commit})
			}
			if len(args) != 0 {
				return fmt.Errorf("usage: version [--json]")
			}
			fmt.Println(gh.Version)
			return nil
		}
		if os.Geteuid() != 0 {
			return fmt.Errorf("local administration requires root")
		}
	}
	fs := flag.NewFlagSet("gatehouse", flag.ContinueOnError)
	config := fs.String("config", "/etc/gatehouse/config.json", "configuration path")
	name := fs.String("user", "", "initial owner username")
	pub := fs.String("public-key", "", "owner public key file")
	host := fs.String("public-host", "", "published jump host")
	port := fs.Int("public-port", 2222, "published SSH port")
	web := fs.String("web-url", "", "HTTPS web origin")
	webListen := fs.String("web-listen", "127.0.0.1:8443", "Web listening address")
	cert := fs.String("tls-cert", "", "TLS certificate path")
	key := fs.String("tls-key", "", "TLS key path")
	data := fs.String("data", "", "data directory")
	runDir := fs.String("run", "", "runtime directory")
	file := fs.String("file", "", "input/output file")
	kind := fs.String("kind", "asset", "record kind")
	pass := fs.String("passphrase-file", "", "file containing archive passphrase")
	if e := fs.Parse(args); e != nil {
		return e
	}
	c, e := gh.LoadConfig(*config)
	if role == "cli" && cmd == "init" {
		if e != nil {
			if !os.IsNotExist(e) {
				return e
			}
			c = gh.DefaultConfig()
		}
		if *data != "" {
			c.Data = *data
		}
		if *runDir != "" {
			c.Run = *runDir
		}
		c.PublicHost = *host
		c.PublicPort = *port
		c.WebURL = *web
		c.WebListen = *webListen
		c.TLSCert = *cert
		c.TLSKey = *key
		if e = gh.Initialize(c, *name, *pub, *config); e != nil {
			return e
		}
		fmt.Println("Initialized. Configure file ownership and TLS, then start gatehouse services.")
		return nil
	}
	if e != nil {
		return e
	}
	ctx := context.Background()
	cancel := func() {}
	if role != "cli" {
		ctx, cancel = signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	}
	defer cancel()
	switch role {
	case "core":
		return gh.RunCoreContext(ctx, c)
	case "ssh":
		return gh.RunSSHContext(ctx, c)
	case "web":
		return gh.RunWebContext(ctx, c)
	}
	switch cmd {
	case "upgrade-check":
		if e := gh.CheckUpgrade(c); e != nil {
			return e
		}
		fmt.Println("Existing schema, records, encrypted credentials and SSH identity verified; no migration required.")
		return nil
	case "doctor":
		checks := gh.Doctor(c)
		json.NewEncoder(os.Stdout).Encode(checks)
		for _, check := range checks {
			if !check.OK {
				return fmt.Errorf("preflight checks failed")
			}
		}
		return nil
	case "recover-owner":
		return gh.RecoverOwner(c, *name, *pub)
	case "tls":
		return gh.InstallTLS(c, *cert, *key, *config)
	case "status":
		b, e := gh.AdminRequest(c, "/status", nil)
		if e == nil {
			fmt.Print(string(b))
		}
		return e
	case "list":
		b, e := gh.AdminRequest(c, "/records?kind="+*kind, nil)
		if e == nil {
			fmt.Print(string(b))
		}
		return e
	case "apply":
		b, e := os.ReadFile(*file)
		if e != nil {
			return e
		}
		out, e := gh.AdminRequest(c, "/apply", bytes.NewReader(b))
		if e == nil {
			fmt.Print(string(out))
		}
		return e
	case "backup", "restore":
		b, e := os.ReadFile(*pass)
		if e != nil {
			return e
		}
		pw := strings.TrimSuffix(string(b), "\n")
		if len(pw) < 16 {
			return fmt.Errorf("archive passphrase must be at least 16 characters")
		}
		if cmd == "backup" {
			return gh.Backup(c, *file, pw)
		}
		return gh.Restore(c, *file, pw)
	case "export-master":
		return gh.ExportMaster(c, *file)
	default:
		return fmt.Errorf("unknown command")
	}
}

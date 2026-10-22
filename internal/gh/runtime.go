package gh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

func socket(c Config, name string) (net.Listener, error) {
	path := filepath.Join(c.Run, name+".sock")
	if err := os.MkdirAll(c.Run, 0750); err != nil {
		return nil, err
	}
	// The directory must not be group-writable: an ingress service must never
	// be able to replace another component's socket or impersonate the core.
	if err := os.Chmod(c.Run, 0750); err != nil {
		return nil, err
	}
	if g, e := user.LookupGroup("gatehouse-rpc"); e == nil {
		gid, _ := strconv.Atoi(g.Gid)
		if e = os.Chown(c.Run, -1, gid); e != nil {
			return nil, e
		}
	}
	if st, e := os.Lstat(path); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("not a socket: %s", path)
		}
		conn, e := net.DialTimeout("unix", path, time.Second)
		if e == nil {
			conn.Close()
			return nil, fmt.Errorf("service already running")
		}
		os.Remove(path)
	}
	l, e := net.Listen("unix", path)
	if e != nil {
		return nil, e
	}
	mode := os.FileMode(0660)
	if name == "admin" {
		mode = 0600
	}
	if e = os.Chmod(path, mode); e != nil {
		l.Close()
		return nil, e
	}
	if g, e := user.LookupGroup("gatehouse-rpc"); e == nil {
		gid, _ := strconv.Atoi(g.Gid)
		os.Chown(path, -1, gid)
	}
	return l, nil
}
func peer(conn net.Conn) (int, error) {
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("not unix socket")
	}
	raw, e := u.SyscallConn()
	if e != nil {
		return -1, e
	}
	var cred *unix.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil {
		return -1, e
	}
	if inner != nil {
		return -1, inner
	}
	return int(cred.Uid), nil
}
func matchesUID(uid int, name string) bool {
	u, e := user.Lookup(name)
	if e != nil {
		return false
	}
	i, e := strconv.Atoi(u.Uid)
	return e == nil && uid == i
}

type peerListener struct {
	net.Listener
	name string
	root bool
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		conn, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		uid, e := peer(conn)
		if e == nil && ((l.root && uid == 0) || (!l.root && matchesUID(uid, l.name))) {
			return conn, nil
		}
		conn.Close()
	}
}
func RunCore(c Config) error { return RunCoreContext(context.Background(), c) }
func RunCoreContext(ctx context.Context, c Config) error {
	x, e := NewCore(c)
	if e != nil {
		return e
	}
	defer x.Close()
	sl, e := socket(c, "ssh")
	if e != nil {
		return e
	}
	defer sl.Close()
	wl, e := socket(c, "web")
	if e != nil {
		return e
	}
	defer wl.Close()
	al, e := socket(c, "admin")
	if e != nil {
		return e
	}
	defer al.Close()
	var workers sync.WaitGroup
	var handlerGate sync.RWMutex
	var stopping atomic.Bool
	wrap := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerGate.RLock()
			defer handlerGate.RUnlock()
			if stopping.Load() {
				jsonOut(w, 503, map[string]string{"error": "core stopping"})
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	web := &http.Server{Handler: wrap(x.WebHandler()), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	admin := &http.Server{Handler: wrap(x.AdminHandler()), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	errorsOut := make(chan error, 3)
	workers.Add(3)
	go func() { defer workers.Done(); errorsOut <- web.Serve(peerListener{Listener: wl, name: c.WebUser}) }()
	go func() { defer workers.Done(); errorsOut <- admin.Serve(peerListener{Listener: al, root: true}) }()
	sem := make(chan struct{}, c.MaxConnections)
	var sshWorkers sync.WaitGroup
	var rawMu sync.Mutex
	raws := map[net.Conn]bool{}
	go func() {
		defer workers.Done()
		l := peerListener{Listener: sl, name: c.SSHUser}
		for {
			conn, err := l.Accept()
			if err != nil {
				errorsOut <- err
				return
			}
			select {
			case sem <- struct{}{}:
				rawMu.Lock()
				raws[conn] = true
				rawMu.Unlock()
				sshWorkers.Add(1)
				go func() {
					defer sshWorkers.Done()
					defer func() { <-sem; rawMu.Lock(); delete(raws, conn); rawMu.Unlock() }()
					x.ServeSSH(conn)
				}()
			default:
				conn.Close()
			}
		}
	}()
	var result error
	select {
	case <-ctx.Done():
	case result = <-errorsOut:
	}
	stopping.Store(true)
	sl.Close()
	wl.Close()
	al.Close()
	web.Close()
	admin.Close()
	workers.Wait() // No new work may be added after this point.
	rawMu.Lock()
	for conn := range raws {
		conn.Close()
	}
	rawMu.Unlock()
	x.disconnect()
	sshWorkers.Wait()
	handlerGate.Lock()
	handlerGate.Unlock()
	if ctx.Err() != nil || errors.Is(result, http.ErrServerClosed) || errors.Is(result, net.ErrClosed) {
		return nil
	}
	return result
}
func RunSSH(c Config) error { return RunSSHContext(context.Background(), c) }
func RunSSHContext(ctx context.Context, c Config) error {
	l, e := net.Listen("tcp", c.SSHListen)
	if e != nil {
		return e
	}
	defer l.Close()
	done := make(chan struct{})
	defer close(done)
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
			mu.Lock()
			for conn := range conns {
				conn.Close()
			}
			mu.Unlock()
		case <-done:
		}
	}()
	sem := make(chan struct{}, c.MaxConnections)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		mu.Lock()
		conns[conn] = true
		mu.Unlock()
		if ctx.Err() != nil {
			conn.Close()
			mu.Lock()
			delete(conns, conn)
			mu.Unlock()
			return nil
		}
		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem; mu.Lock(); delete(conns, conn); mu.Unlock() }()
				defer conn.Close()
				backend, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", filepath.Join(c.Run, "ssh.sock"))
				if e != nil {
					return
				}
				defer backend.Close()
				backend.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if e = json.NewEncoder(backend).Encode(map[string]string{"Remote": conn.RemoteAddr().String()}); e != nil {
					return
				}
				backend.SetWriteDeadline(time.Time{})
				copied := make(chan struct{})
				go func() {
					io.Copy(backend, conn)
					if u, ok := backend.(*net.UnixConn); ok {
						u.CloseWrite()
					}
					close(copied)
				}()
				io.Copy(conn, backend)
				conn.Close()
				backend.Close()
				<-copied
			}()
		default:
			conn.Close()
			mu.Lock()
			delete(conns, conn)
			mu.Unlock()
		}
	}
}
func RunWeb(c Config) error { return RunWebContext(context.Background(), c) }
func RunWebContext(ctx context.Context, c Config) error {
	if !strings.HasPrefix(c.WebURL, "https://") || c.TLSCert == "" || c.TLSKey == "" {
		return fmt.Errorf("HTTPS URL and TLS certificate/key are required")
	}
	u, _ := url.Parse("http://gatehouse.internal")
	p := httputil.NewSingleHostReverseProxy(u)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", filepath.Join(c.Run, "web.sock"))
	}, MaxIdleConns: 16, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 60 * time.Second}
	defer transport.CloseIdleConnections()
	p.Transport = transport
	p.Director = nil
	p.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.SetURL(u)
		for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
			pr.Out.Header.Del(h)
		}
		pr.Out.Header.Set("X-Gatehouse-Remote", pr.In.RemoteAddr)
	}
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		jsonOut(w, 503, map[string]string{"error": "core unavailable"})
	}
	server := &http.Server{Addr: c.WebListen, Handler: p, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	e := server.ListenAndServeTLS(c.TLSCert, c.TLSKey)
	if ctx.Err() != nil && errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func (c *Core) AdminHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			jsonOut(w, 200, map[string]any{"version": Version, "audit_failed": c.auditFailed.Load()})
		case "/apply":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			var q Change
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&q) != nil {
				w.WriteHeader(400)
				return
			}
			users, _ := list[User](c.Store, "user")
			owner := ""
			for _, u := range users {
				if u.Enabled && u.Owner {
					owner = u.ID
					break
				}
			}
			if owner == "" {
				w.WriteHeader(403)
				return
			}
			snapshot := map[string]bool{}
			for _, a := range Capabilities {
				snapshot[a+":*"] = true
			}
			ws := &WebSession{User: owner, Snapshot: snapshot}
			c.management.Lock()
			v, e := c.Change(ws, q, "local-root")
			c.management.Unlock()
			c.Revalidate()
			if e != nil {
				jsonOut(w, 400, map[string]string{"error": e.Error()})
				return
			}
			jsonOut(w, 200, v)
		case "/records":
			kind := r.URL.Query().Get("kind")
			if !contains([]string{"user", "key", "group", "asset", "account", "credential", "grant", "ticket"}, kind) {
				w.WriteHeader(400)
				return
			}
			items, _ := list[map[string]any](c.Store, kind)
			out := []any{}
			for _, x := range items {
				delete(x, "cipher")
				out = append(out, map[string]any{"data": x, "etag": hash(encode(x))})
			}
			jsonOut(w, 200, out)
		default:
			w.WriteHeader(404)
		}
	})
}
func AdminRequest(c Config, path string, body io.Reader) ([]byte, error) {
	method := "GET"
	if body != nil {
		method = "POST"
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(c.Run, "admin.sock"))
	}}, Timeout: 60 * time.Second}
	req, e := http.NewRequest(method, "http://local"+path, body)
	if e != nil {
		return nil, e
	}
	r, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if e != nil {
		return nil, e
	}
	if r.StatusCode >= 400 {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	return b, nil
}

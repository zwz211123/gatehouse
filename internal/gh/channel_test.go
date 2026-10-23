package gh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func tcpSpec(t *testing.T, address, route string) Spec {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return Spec{Modes: []string{"tcp"}, TCPHost: host, TCPPort: n, LocalPort: 3333, TCPRoute: route, Channels: 1}
}

func TestTCPChannelsReusedForWebRequests(t *testing.T) {
	for _, route := range []string{"target", "jump"} {
		t.Run(route, func(t *testing.T) {
			f := setup(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Connection", "close")
				fmt.Fprint(w, "web response")
			}))
			defer server.Close()
			ticket, pw := f.ticket(t, tcpSpec(t, server.Listener.Addr().String(), route))
			client, err := f.dial(ticket, pw)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return client.DialContext(ctx, network, address)
			}}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for i := 0; i < 12; i++ {
				response, err := httpClient.Get(server.URL)
				if err != nil {
					t.Fatalf("request %d with channels=1: %v", i+1, err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(body) != "web response" {
					t.Fatalf("request %d: %q, %v", i+1, body, err)
				}
			}
		})
	}
}

func TestTCPChannelSetupFailureReleasesCapacity(t *testing.T) {
	for _, route := range []string{"target", "jump"} {
		t.Run(route, func(t *testing.T) {
			f := setup(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			listener.Close()
			ticket, pw := f.ticket(t, tcpSpec(t, address, route))
			client, err := f.dial(ticket, pw)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for i := 0; i < 8; i++ {
				conn, err := client.Dial("tcp", address)
				if err == nil {
					conn.Close()
					t.Fatal("closed endpoint accepted")
				}
				var rejected *ssh.OpenChannelError
				if !errors.As(err, &rejected) || rejected.Reason != ssh.ConnectionFailed {
					t.Fatalf("attempt %d leaked channel capacity: %v", i+1, err)
				}
			}
			var current Ticket
			if err := f.c.Store.Get("ticket", ticket.ID, &current); err != nil || current.Revoked {
				t.Fatalf("setup failure invalidated ticket: %v", err)
			}
		})
	}
}

func TestSessionChannelsReusedWhileTCPRemainsOpen(t *testing.T) {
	f := setup(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	spec := tcpSpec(t, listener.Addr().String(), "jump")
	spec.Modes = []string{"tcp", "exec"}
	spec.Command = "printf reusable"
	spec.Channels = 2
	spec.Sessions = 8
	ticket, pw := f.ticket(t, spec)
	client, err := f.dial(ticket, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	for i := 0; i < spec.Sessions; i++ {
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("session %d: %v", i+1, err)
		}
		output, err := session.Output(spec.Command)
		session.Close()
		if err != nil || string(output) != "target:"+spec.Command {
			t.Fatalf("session %d: %q, %v", i+1, output, err)
		}
	}
}

func TestMixedChannelsCannotExceedActiveLimit(t *testing.T) {
	f := setup(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	spec := tcpSpec(t, listener.Addr().String(), "jump")
	spec.Modes = []string{"tcp", "shell"}
	spec.Channels = 2
	ticket, pw := f.ticket(t, spec)
	client, err := f.dial(ticket, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = session.Shell(); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(stdout, make([]byte, len("TARGET-SHELL\n"))); err != nil {
		t.Fatal(err)
	}
	third, err := client.Dial("tcp", listener.Addr().String())
	if err == nil {
		third.Close()
		t.Fatal("third simultaneously open channel bypassed channels=2")
	}
	var rejected *ssh.OpenChannelError
	if !errors.As(err, &rejected) || rejected.Reason != ssh.Prohibited {
		t.Fatalf("unexpected rejection: %v", err)
	}
}

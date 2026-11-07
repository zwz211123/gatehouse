package gh

import (
	"golang.org/x/crypto/ssh"
	"testing"
	"time"
)

func TestSFTPSessionResultAudit(t *testing.T) {
	for _, mode := range []string{"reject", "bad-version", "malformed", "eof"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t, mode)
			ticket, password := f.ticket(t, Spec{Modes: []string{"sftp"}, FileRoot: f.root, FileOps: []string{"read", "list"}})
			client, err := f.dial(ticket, password)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			channel, requests, err := client.OpenChannel("session", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer channel.Close()
			type exitResult struct {
				code     uint32
				received bool
			}
			done := make(chan exitResult, 1)
			go func() {
				result := exitResult{}
				for request := range requests {
					if request.Type == "exit-status" {
						var status struct{ Code uint32 }
						if ssh.Unmarshal(request.Payload, &status) == nil {
							result.code, result.received = status.Code, true
						}
					}
					if request.WantReply {
						request.Reply(false, nil)
					}
				}
				done <- result
			}()
			ok, err := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
			if err != nil || !ok {
				t.Fatalf("subsystem request: %v %v", ok, err)
			}
			if mode == "eof" {
				raw := &rawSFTP{r: channel, w: channel}
				raw.packet(t, 1, []byte{0, 0, 0, 3})
				// Half-close only, leaving SSH open to receive exit-status before CLOSE.
				if err = channel.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			} else if mode == "malformed" {
				if _, err = channel.Write([]byte{0, 0, 0, 0}); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case result := <-done:
				want := uint32(1)
				if mode == "eof" {
					want = 0
				}
				if !result.received || result.code != want {
					t.Fatalf("exit status before channel close: received=%v code=%d want=%d", result.received, result.code, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("SFTP session did not finish")
			}
			expected := "error"
			if mode == "eof" {
				expected = "ok"
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				events, err := f.c.Store.Events(1000)
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range events {
					if event.Ticket == ticket.ID && event.Action == "proxy.close" {
						if event.Result != expected || event.ConnectionID == "" || event.ChannelID == "" || event.Category != "access" {
							t.Fatalf("wrong session result/context: %+v", event)
						}
						for _, record := range groupAuditEvents(events) {
							if record.ID == "connection:"+event.ConnectionID {
								if (record.FailureCount > 0) != (expected == "error") {
									t.Fatalf("wrong failure summary: %+v", record)
								}
								return
							}
						}
						t.Fatal("missing grouped session")
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("missing completed SFTP audit")
		})
	}
}

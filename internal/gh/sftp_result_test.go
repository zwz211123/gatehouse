package gh

import (
	"github.com/pkg/sftp"
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
			if mode == "malformed" {
				session, err := client.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				input, err := session.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err = session.RequestSubsystem("sftp"); err != nil {
					t.Fatal(err)
				}
				if _, err = input.Write([]byte{0, 0, 0, 0}); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- session.Wait() }()
				select {
				case err = <-done:
					if err == nil {
						t.Fatal("malformed session returned success")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("failed SFTP session did not finish")
				}
			} else {
				files, err := sftp.NewClient(client)
				if mode == "eof" {
					if err != nil {
						t.Fatal(err)
					}
					files.Close()
				} else {
					if err == nil {
						files.Close()
						t.Fatal("broken target initialized SFTP")
					}
				}
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

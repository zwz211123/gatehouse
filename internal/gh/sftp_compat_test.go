package gh

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func sftpFixture(t *testing.T, ops []string) (*fixture, *sftp.Client, Ticket, string) {
	t.Helper()
	f := setup(t)
	root := filepath.Join(f.root, "files")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	ticket, pw := f.ticket(t, Spec{Modes: []string{"sftp"}, FileRoot: root, FileOps: ops})
	client, err := f.dial(ticket, pw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	files, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { files.Close() })
	return f, files, ticket, root
}

var allFileOps = []string{"read", "write", "list", "mkdir", "remove", "rename", "metadata"}

func TestSFTPClientInitializationAndAudit(t *testing.T) {
	f, s, ticket, root := sftpFixture(t, allFileOps)
	original := root + "/original"
	const payload = "PRIVATE-FILE-CONTENT-NOT-FOR-AUDIT"
	if err := os.WriteFile(original, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RealPath("."); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat(root); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadDir(root); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StatVFS(root); err != nil {
		t.Fatal(err)
	}
	if err := s.Symlink("original", root+"/symbolic"); err != nil {
		t.Fatal(err)
	}
	info, err := s.Lstat(root + "/symbolic")
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("LSTAT followed symlink", info, err)
	}
	if target, err := s.ReadLink(root + "/symbolic"); err != nil || target != "original" {
		t.Fatal(target, err)
	}
	if err := s.Link(original, root+"/hard"); err != nil {
		t.Fatal(err)
	}
	if err := s.PosixRename(root+"/hard", root+"/symbolic"); err != nil {
		t.Fatal("atomic overwrite", err)
	}
	if err := s.Rename(root+"/symbolic", root+"/renamed"); err != nil {
		t.Fatal(err)
	}
	handle, err := s.OpenFile(original, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(payload))
	if _, err = handle.ReadAt(b, 0); err != nil || string(b) != payload {
		t.Fatal(string(b), err)
	}
	if _, err = handle.WriteAt([]byte(payload), 0); err != nil {
		t.Fatal(err)
	}
	if _, err = handle.Stat(); err != nil {
		t.Fatal(err)
	}
	if err = handle.Truncate(4); err != nil {
		t.Fatal("FSETSTAT", err)
	}
	if info, err = os.Stat(original); err != nil || info.Size() != 4 {
		t.Fatal("FSETSTAT ignored attributes", info, err)
	}
	if err = handle.Chmod(0640); err != nil {
		t.Fatal(err)
	}
	if err = handle.Chown(os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if err = handle.Close(); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1700000000, 0)
	if err = s.Chtimes(original, at, at); err != nil {
		t.Fatal(err)
	}
	if err = s.Chmod(original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Chown(original, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if err = s.Mkdir(root + "/sub"); err != nil {
		t.Fatal(err)
	}
	if err = s.RemoveDirectory(root + "/sub"); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(root + "/renamed"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Stat(root + "/missing"); err == nil {
		t.Fatal("missing file accepted")
	}
	events, err := f.c.Store.Events(1000)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, event := range events {
		if event.Resource != ticket.ID || !strings.HasPrefix(event.Action, "file.") {
			continue
		}
		if strings.Contains(event.Detail, payload) {
			t.Fatal("file content leaked into audit")
		}
		var op sftpOperation
		if err = json.Unmarshal([]byte(event.Detail), &op); err != nil {
			t.Fatal(err)
		}
		if event.Result != "attempt" {
			found[op.Method+":"+event.Result] = true
		}
	}
	for _, method := range []string{"INIT", "REALPATH", "STAT", "LSTAT", "OPENDIR", "READDIR", "STATVFS", "SYMLINK", "READLINK", "LINK", "POSIX_RENAME", "RENAME", "OPEN", "READ", "WRITE", "FSTAT", "FSETSTAT", "CLOSE", "SETSTAT", "MKDIR", "RMDIR", "REMOVE"} {
		if !found[method+":ok"] {
			t.Errorf("missing success audit for %s", method)
		}
	}
	if !found["STAT:error"] {
		t.Error("failed backend operation not audited")
	}
}

func TestSFTPListOnlyMetadataAndDanglingLinks(t *testing.T) {
	_, s, _, root := sftpFixture(t, []string{"list"})
	if err := os.Symlink("does-not-exist", root+"/dangling"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RealPath("."); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat(root); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StatVFS(root); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadDir(root); err != nil {
		t.Fatal(err)
	}
	if info, err := s.Lstat(root + "/dangling"); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal(info, err)
	}
	if target, err := s.ReadLink(root + "/dangling"); err != nil || target != "does-not-exist" {
		t.Fatal(target, err)
	}
	if _, err := s.Open(root + "/dangling"); err == nil {
		t.Fatal("list-only ticket read file data")
	}
}

func TestSFTPLinkBoundaries(t *testing.T) {
	for _, method := range []string{"symlink", "hardlink", "rename", "posix-rename"} {
		t.Run(method, func(t *testing.T) {
			f, s, ticket, root := sftpFixture(t, allFileOps)
			source := root + "/source"
			os.WriteFile(source, []byte("test"), 0600)
			outside := filepath.Join(f.root, "outside")
			var err error
			switch method {
			case "symlink":
				err = s.Symlink(outside, root+"/escape")
			case "hardlink":
				err = s.Link(source, outside)
			case "rename":
				err = s.Rename(source, outside)
			case "posix-rename":
				err = s.PosixRename(source, outside)
			}
			if err == nil {
				t.Fatal("out-of-root operation accepted")
			}
			if _, err = os.Lstat(outside); !os.IsNotExist(err) {
				t.Fatal("outside path created", err)
			}
			events, _ := f.c.Store.Events(1000)
			found := false
			for _, e := range events {
				if e.Resource == ticket.ID && strings.HasPrefix(e.Action, "file.") && e.Result == "attempt" && strings.Contains(e.Detail, outside) {
					found = true
				}
			}
			if !found {
				t.Fatal("denied endpoint missing from audit")
			}
		})
	}
}

func TestSFTPLinkRequiresExplicitMutationRights(t *testing.T) {
	for _, ops := range [][]string{{"read", "write"}, {"read", "metadata"}} {
		t.Run(strings.Join(ops, "-"), func(t *testing.T) {
			_, s, _, root := sftpFixture(t, ops)
			if err := s.Symlink("missing", root+"/new"); err == nil {
				t.Fatal("link created without write + metadata")
			}
			if _, err := os.Lstat(root + "/new"); !os.IsNotExist(err) {
				t.Fatal("unauthorized link exists", err)
			}
		})
	}
}

// Raw requests cover extensions and malformed packets that do not reach any
// filesystem callback, plus handle traffic independently of the client library.
type rawSFTP struct {
	r       io.Reader
	w       io.Writer
	session *ssh.Session
	next    uint32
}

func newRawSFTP(t *testing.T, f *fixture, ticket Ticket, pw string) *rawSFTP {
	t.Helper()
	client, err := f.dial(ticket, pw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	in, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = session.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	r := &rawSFTP{out, in, session, 0}
	t.Cleanup(func() { session.Close() })
	r.packet(t, 1, []byte{0, 0, 0, 3})
	return r
}
func wireString(s string) []byte {
	b := make([]byte, 4, len(s)+4)
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, s...)
}
func (r *rawSFTP) packet(t *testing.T, kind byte, payload []byte) []byte {
	t.Helper()
	packet := []byte{kind}
	if kind != 1 {
		r.next++
		packet = binary.BigEndian.AppendUint32(packet, r.next)
	}
	packet = append(packet, payload...)
	header := binary.BigEndian.AppendUint32(nil, uint32(len(packet)))
	if _, err := r.w.Write(append(header, packet...)); err != nil {
		t.Fatal(err)
	}
	var length [4]byte
	if _, err := io.ReadFull(r.r, length[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint32(length[:]))
	if _, err := io.ReadFull(r.r, response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestSFTPUnsupportedRequestsAreAudited(t *testing.T) {
	f := setup(t)
	ticket, pw := f.ticket(t, Spec{Modes: []string{"sftp"}, FileRoot: f.root, FileOps: allFileOps})
	raw := newRawSFTP(t, f, ticket, pw)
	for _, ext := range []string{"unknown@example.test", "fsync@openssh.com"} {
		data := wireString(ext)
		if ext == "fsync@openssh.com" {
			data = append(data, wireString("bogus-handle")...)
		}
		response := raw.packet(t, 200, data)
		if response[0] != 101 || binary.BigEndian.Uint32(response[5:9]) != 8 {
			t.Fatalf("expected OP_UNSUPPORTED: %x", response)
		}
	}
	response := raw.packet(t, 8, wireString("invalid-handle"))
	if response[0] != 101 || binary.BigEndian.Uint32(response[5:9]) == 0 {
		t.Fatal("invalid handle accepted")
	}
	events, _ := f.c.Store.Events(1000)
	for _, ext := range []string{"unknown@example.test", "fsync@openssh.com"} {
		found := false
		for _, e := range events {
			if e.Resource == ticket.ID && e.Result == "unsupported" && strings.Contains(e.Detail, ext) {
				found = true
			}
		}
		if !found {
			t.Error("missing unsupported audit", ext)
		}
	}
	found := false
	for _, e := range events {
		if e.Resource == ticket.ID && e.Action == "file.fstat" && e.Result == "error" && strings.Contains(e.Detail, "invalid-handle") {
			found = true
		}
	}
	if !found {
		t.Fatal("invalid handle failure not audited")
	}
}

func TestSFTPAuditFramingAndFailure(t *testing.T) {
	f := setup(t)
	ticket, _ := f.ticket(t, Spec{Modes: []string{"sftp"}, FileRoot: f.root, FileOps: allFileOps})
	p := &fileProxy{c: f.c, l: f.l, t: ticket}
	for _, packet := range [][]byte{{0, 0, 0, 0}, {0, 4, 0, 1}, {0, 0, 0, 5, 16, 0, 0, 0, 1}, {0, 0, 0, 9, 200, 0, 0, 0, 1, 0, 0, 0, 99}} {
		stream := newSFTPAuditStream(&memorySFTP{Reader: bytes.NewReader(packet)}, p)
		b := make([]byte, 1024)
		if _, err := stream.Read(b); err == nil {
			t.Fatal("malformed packet accepted")
		}
		stream.Close()
	}
	stream := newSFTPAuditStream(&memorySFTP{Reader: bytes.NewReader([]byte{0, 0, 0, 5, 1, 0, 0, 0, 3})}, p)
	f.c.auditFailed.Store(true)
	if _, err := stream.Read(make([]byte, 20)); err == nil {
		t.Fatal("request forwarded after audit failure")
	}
}

type memorySFTP struct {
	*bytes.Reader
	bytes.Buffer
}

func (m *memorySFTP) Read(b []byte) (int, error)  { return m.Reader.Read(b) }
func (m *memorySFTP) Write(b []byte) (int, error) { return m.Buffer.Write(b) }
func (m *memorySFTP) Close() error                { return nil }

func TestSFTPHandleAttributesAfterRenameAndUnlink(t *testing.T) {
	_, s, _, root := sftpFixture(t, allFileOps)
	original := root + "/original"
	if err := os.WriteFile(original, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	handle, err := s.OpenFile(original, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	moved := root + "/moved"
	if err = s.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err = handle.Truncate(3); err != nil {
		t.Fatal("renamed handle", err)
	}
	if info, err := handle.Stat(); err != nil || info.Size() != 3 {
		t.Fatal(info, err)
	}
	if err = s.Remove(moved); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(moved, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = handle.Truncate(1); err == nil {
		t.Fatal("unlinked handle modified replacement file")
	}
	if b, err := os.ReadFile(moved); err != nil || string(b) != "replacement" {
		t.Fatal(string(b), err)
	}
}

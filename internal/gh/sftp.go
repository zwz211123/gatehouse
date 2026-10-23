package gh

import (
	"io"
	"math"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type fileProxy struct {
	c      *Core
	l      *Live
	t      Ticket
	remote *sftp.Client
}

func (c *Core) serveSFTP(l *Live, t Ticket, ch ssh.Channel, target *ssh.Client, ready func()) {
	remote, e := sftp.NewClient(target)
	if e != nil {
		return
	}
	defer remote.Close()
	ready()
	p := &fileProxy{c, l, t, remote}
	stream := newSFTPAuditStream(ch, p)
	defer stream.Close()
	server := sftp.NewRequestServer(stream, sftp.Handlers{FileGet: p, FilePut: p, FileCmd: p, FileList: p}, sftp.WithStartDirectory(t.Spec.FileRoot))
	defer server.Close()
	e = server.Serve()
	status := uint32(0)
	if e != nil && e != io.EOF {
		status = 1
	}
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}
func (p *fileProxy) permit(op, fp string) error {
	if !contains(p.t.Spec.FileOps, op) || p.c.ticketValid(p.t, p.l.Source) != nil {
		return p.deny(op, fp, "SFTP operation denied")
	}
	return nil
}
func (p *fileProxy) deny(op, fp, reason string) error {
	if err := p.c.Audit(p.l.User, "file.authorization", p.t.ID, "denied", p.l.Source, encode(map[string]string{"operation": op, "path": fp, "reason": reason})); err != nil {
		return sftp.ErrSSHFxPermissionDenied
	}
	p.c.FailTicket(p.l, reason)
	return sftp.ErrSSHFxPermissionDenied
}
func (p *fileProxy) checked(fp string, create bool) (string, error) {
	if strings.ContainsRune(fp, 0) {
		return "", sftp.ErrSSHFxPermissionDenied
	}
	if !path.IsAbs(fp) {
		fp = path.Join(p.t.Spec.FileRoot, fp)
	}
	fp = path.Clean(fp)
	root := p.t.Spec.FileRoot
	within := func(x string) bool { return root == "/" || x == root || strings.HasPrefix(x, root+"/") }
	if !within(fp) {
		return "", p.deny("path", fp, "SFTP path outside application")
	}
	actual, e := p.remote.RealPath(fp)
	if e != nil && create {
		parent, e2 := p.remote.RealPath(path.Dir(fp))
		if e2 != nil {
			return "", e2
		}
		actual = path.Join(parent, path.Base(fp))
		e = nil
	}
	if e != nil {
		return "", e
	}
	if !within(actual) {
		return "", p.deny("path", actual, "SFTP resolved path outside application")
	}
	return actual, nil
}
func (p *fileProxy) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if e := p.permit("read", r.Filepath); e != nil {
		return nil, e
	}
	fp, e := p.checked(r.Filepath, false)
	if e != nil {
		return nil, e
	}
	f, e := p.remote.Open(fp)
	if e != nil {
		return nil, e
	}
	return &boundedFile{File: f, p: p}, nil
}
func (p *fileProxy) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if e := p.permit("write", r.Filepath); e != nil {
		return nil, e
	}
	flags := r.Pflags()
	if flags.Read && p.permit("read", r.Filepath) != nil {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	fp, e := p.checked(r.Filepath, flags.Creat)
	if e != nil {
		return nil, e
	}
	of := os.O_WRONLY
	if flags.Read {
		of = os.O_RDWR
	}
	if flags.Creat {
		of |= os.O_CREATE
	}
	if flags.Excl {
		of |= os.O_EXCL
	}
	if flags.Trunc {
		of |= os.O_TRUNC
	}
	if flags.Append {
		of |= os.O_APPEND
	}
	f, e := p.remote.OpenFile(fp, of)
	if e != nil {
		return nil, e
	}
	return &boundedFile{File: f, p: p}, nil
}
func (p *fileProxy) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	v, e := p.Filewrite(r)
	if e != nil {
		return nil, e
	}
	return v.(sftp.WriterAtReaderAt), nil
}

type boundedFile struct {
	*sftp.File
	p *fileProxy
}

func (f *boundedFile) ReadAt(b []byte, off int64) (int, error) {
	n, e := f.File.ReadAt(b, off)
	if err := f.p.charge(n); err != nil {
		return 0, err
	}
	return n, e
}
func (f *boundedFile) WriteAt(b []byte, off int64) (int, error) {
	if e := f.p.charge(len(b)); e != nil {
		return 0, e
	}
	return f.File.WriteAt(b, off)
}
func (p *fileProxy) charge(n int) error {
	return p.c.charge(p.l, p.t, n)
}

type infoList []os.FileInfo

func (a infoList) ListAt(out []os.FileInfo, off int64) (int, error) {
	if off < 0 || off >= int64(len(a)) {
		return 0, io.EOF
	}
	n := copy(out, a[off:])
	if int(off)+n >= len(a) {
		return n, io.EOF
	}
	return n, nil
}

// Metadata probes do not read file contents. A list-only browser must be
// able to stat its directory and resolve its initial path.
func (p *fileProxy) probePermission(fp string) error {
	for _, op := range []string{"read", "list", "write", "metadata", "mkdir", "remove", "rename"} {
		if contains(p.t.Spec.FileOps, op) {
			return p.permit(op, fp)
		}
	}
	return sftp.ErrSSHFxPermissionDenied
}

func (p *fileProxy) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	var err error
	if r.Method == "List" {
		err = p.permit("list", r.Filepath)
	} else {
		err = p.probePermission(r.Filepath)
	}
	if err != nil {
		return nil, err
	}
	var fp string
	if r.Method == "Lstat" {
		fp, err = p.entryPath(r.Filepath)
	} else {
		fp, err = p.checked(r.Filepath, false)
	}
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "List":
		items, err := p.remote.ReadDir(fp)
		return infoList(items), err
	case "Stat", "Lstat":
		var info os.FileInfo
		if r.Method == "Lstat" {
			info, err = p.remote.Lstat(fp)
		} else {
			info, err = p.remote.Stat(fp)
		}
		if err != nil {
			return nil, err
		}
		return infoList{info}, nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}
func (p *fileProxy) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	return p.Filelist(&sftp.Request{Method: "Lstat", Filepath: r.Filepath})
}
func (p *fileProxy) RealPath(fp string) (string, error) {
	if err := p.probePermission(fp); err != nil {
		return "", err
	}
	return p.checked(fp, false)
}

// Resolve the parent, not the final entry. LSTAT, READLINK, REMOVE and
// RENAME operate on the link itself, including dangling symbolic links.
func (p *fileProxy) entryPath(fp string) (string, error) {
	if strings.ContainsRune(fp, 0) {
		return "", sftp.ErrSSHFxBadMessage
	}
	if !path.IsAbs(fp) {
		fp = path.Join(p.t.Spec.FileRoot, fp)
	}
	fp = path.Clean(fp)
	root := p.t.Spec.FileRoot
	if root != "/" && fp != root && !strings.HasPrefix(fp, root+"/") {
		return "", p.deny("path", fp, "SFTP entry outside application")
	}
	if fp == root {
		return p.checked(fp, false)
	}
	parent, err := p.checked(path.Dir(fp), false)
	if err != nil {
		return "", err
	}
	return path.Join(parent, path.Base(fp)), nil
}
func (p *fileProxy) Readlink(fp string) (string, error) {
	if err := p.probePermission(fp); err != nil {
		return "", err
	}
	fp, err := p.entryPath(fp)
	if err != nil {
		return "", err
	}
	return p.remote.ReadLink(fp)
}
func (p *fileProxy) StatVFS(r *sftp.Request) (*sftp.StatVFS, error) {
	if err := p.probePermission(r.Filepath); err != nil {
		return nil, err
	}
	fp, err := p.checked(r.Filepath, false)
	if err != nil {
		return nil, err
	}
	return p.remote.StatVFS(fp)
}
func (p *fileProxy) PosixRename(r *sftp.Request) error {
	return p.rename(r, true)
}
func (p *fileProxy) rename(r *sftp.Request, posix bool) error {
	if err := p.permit("rename", r.Filepath); err != nil {
		return err
	}
	from, err := p.entryPath(r.Filepath)
	if err != nil {
		return err
	}
	to, err := p.entryPath(r.Target)
	if err != nil {
		return err
	}
	if posix {
		return p.remote.PosixRename(from, to)
	}
	return p.remote.Rename(from, to)
}
func (p *fileProxy) Filecmd(r *sftp.Request) error {
	switch r.Method {
	case "Rename":
		return p.rename(r, false)
	case "Link", "Symlink":
		return p.link(r)
	}
	op := ""
	switch r.Method {
	case "Mkdir":
		op = "mkdir"
	case "Remove", "Rmdir":
		op = "remove"
	case "Setstat":
		op = "metadata"
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
	if err := p.permit(op, r.Filepath); err != nil {
		return err
	}
	var fp string
	var err error
	if r.Method == "Setstat" {
		fp, err = p.checked(r.Filepath, false)
	} else {
		fp, err = p.entryPath(r.Filepath)
	}
	if err != nil {
		return err
	}
	switch r.Method {
	case "Mkdir":
		return p.remote.Mkdir(fp)
	case "Remove":
		return p.remote.Remove(fp)
	case "Rmdir":
		return p.remote.RemoveDirectory(fp)
	case "Setstat":
		flags := r.AttrFlags()
		if r.Flags & ^uint32(15) != 0 {
			return sftp.ErrSSHFxOpUnsupported
		}
		at := r.Attributes()
		// Validate the entire operation before making any changes.
		if flags.Size {
			if at.Size > math.MaxInt64 {
				return sftp.ErrSSHFxBadMessage
			}
			if err = p.permit("write", r.Filepath); err != nil {
				return err
			}
		}
		if flags.Size {
			if err = p.remote.Truncate(fp, int64(at.Size)); err != nil {
				return err
			}
		}
		if flags.UidGid {
			if err = p.remote.Chown(fp, int(at.UID), int(at.GID)); err != nil {
				return err
			}
		}
		if flags.Permissions {
			if err = p.remote.Chmod(fp, at.FileMode()); err != nil {
				return err
			}
		}
		if flags.Acmodtime {
			return p.remote.Chtimes(fp, time.Unix(int64(at.Atime), 0), time.Unix(int64(at.Mtime), 0))
		}
	}
	return nil
}

// Link creation needs both write and metadata rights. Hard links also need
// read rights to the source. Existing read/write-only tickets gain no new
// mutation authority. Both endpoints stay inside the declared root.
func (p *fileProxy) link(r *sftp.Request) error {
	for _, op := range []string{"write", "metadata"} {
		if err := p.permit(op, r.Target); err != nil {
			return err
		}
	}
	to, err := p.entryPath(r.Target)
	if err != nil {
		return err
	}
	if r.Method == "Link" {
		if err = p.permit("read", r.Filepath); err != nil {
			return err
		}
		from, err := p.checked(r.Filepath, false)
		if err != nil {
			return err
		}
		return p.remote.Link(from, to)
	}
	target := r.Filepath
	if !path.IsAbs(target) {
		target = path.Join(path.Dir(to), target)
	}
	if _, err = p.checked(target, true); err != nil {
		return err
	}
	return p.remote.Symlink(r.Filepath, to)
}

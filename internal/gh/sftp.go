package gh

import (
	"io"
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
	server := sftp.NewRequestServer(ch, sftp.Handlers{FileGet: p, FilePut: p, FileCmd: p, FileList: p}, sftp.WithStartDirectory(t.Spec.FileRoot))
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
		p.c.FailTicket(p.l, "SFTP operation denied")
		return os.ErrPermission
	}
	if e := p.c.Audit(p.l.User, "file."+op, p.t.ID, "attempt", p.l.Source, fp); e != nil {
		return os.ErrPermission
	}
	return nil
}
func (p *fileProxy) checked(fp string, create bool) (string, error) {
	if strings.ContainsRune(fp, 0) {
		return "", os.ErrPermission
	}
	if !path.IsAbs(fp) {
		fp = path.Join(p.t.Spec.FileRoot, fp)
	}
	fp = path.Clean(fp)
	root := p.t.Spec.FileRoot
	within := func(x string) bool { return root == "/" || x == root || strings.HasPrefix(x, root+"/") }
	if !within(fp) {
		p.c.FailTicket(p.l, "SFTP path outside application")
		return "", os.ErrPermission
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
		p.c.FailTicket(p.l, "SFTP resolved path outside application")
		return "", os.ErrPermission
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
		return nil, os.ErrPermission
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
func (p *fileProxy) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	op := "list"
	if r.Method != "List" {
		op = "read"
		if !contains(p.t.Spec.FileOps, op) && contains(p.t.Spec.FileOps, "write") {
			op = "write"
		}
	}
	if e := p.permit(op, r.Filepath); e != nil {
		return nil, e
	}
	fp, e := p.checked(r.Filepath, false)
	if e != nil {
		return nil, e
	}
	if r.Method == "List" {
		a, e := p.remote.ReadDir(fp)
		return infoList(a), e
	}
	if r.Method == "Stat" {
		i, e := p.remote.Stat(fp)
		return infoList{i}, e
	}
	return nil, os.ErrPermission
}
func (p *fileProxy) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	return p.Filelist(&sftp.Request{Method: "Stat", Filepath: r.Filepath})
}
func (p *fileProxy) RealPath(fp string) (string, error) { return p.checked(fp, false) }
func (p *fileProxy) Filecmd(r *sftp.Request) error {
	op := ""
	switch r.Method {
	case "Mkdir":
		op = "mkdir"
	case "Remove", "Rmdir":
		op = "remove"
	case "Rename":
		op = "rename"
	case "Setstat":
		op = "metadata"
	default:
		return os.ErrPermission
	}
	if e := p.permit(op, r.Filepath); e != nil {
		return e
	}
	fp, e := p.checked(r.Filepath, r.Method == "Mkdir")
	if e != nil {
		return e
	}
	switch r.Method {
	case "Mkdir":
		return p.remote.Mkdir(fp)
	case "Remove":
		return p.remote.Remove(fp)
	case "Rmdir":
		return p.remote.RemoveDirectory(fp)
	case "Rename":
		to, e := p.checked(r.Target, true)
		if e != nil {
			return e
		}
		return p.remote.Rename(fp, to)
	case "Setstat":
		flags := r.AttrFlags()
		if r.Flags & ^uint32(15) != 0 {
			return os.ErrPermission
		}
		at := r.Attributes()
		if flags.UidGid {
			return os.ErrPermission
		}
		if flags.Size {
			if !contains(p.t.Spec.FileOps, "write") {
				return os.ErrPermission
			}
			if e = p.remote.Truncate(fp, int64(at.Size)); e != nil {
				return e
			}
		}
		if flags.Permissions {
			if e = p.remote.Chmod(fp, at.FileMode()); e != nil {
				return e
			}
		}
		if flags.Acmodtime {
			return p.remote.Chtimes(fp, time.Unix(int64(at.Atime), 0), time.Unix(int64(at.Mtime), 0))
		}
	}
	return nil
}

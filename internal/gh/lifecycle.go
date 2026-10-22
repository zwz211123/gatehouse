package gh

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The lock also protects offline administration from an overlapping core.
func lockData(dir string) (*os.File, error) {
	fd, e := unix.Open(filepath.Join(dir, ".core.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "core lock")
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, fmt.Errorf("data directory already in use: %w", e)
	}
	return f, nil
}

// Close outbound channels when the authenticated inbound transport is revoked.
func bindTarget(l *Live, target io.Closer) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-l.Cancel:
			target.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

package gh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
)

// Audit at the framing boundary, not just in filesystem callbacks: INIT,
// REALPATH, handle operations, unsupported extensions and malformed packets
// must be visible too. File contents and attribute payloads are never logged.
const sftpMaxPacket = 256 * 1024 // same limit as pkg/sftp

type sftpOperation struct {
	Session   string  `json:"sftp_session"`
	Type      byte    `json:"packet_type"`
	Error     string  `json:"error,omitempty"`
	ID        uint32  `json:"request_id"`
	Method    string  `json:"method"`
	Path      string  `json:"path,omitempty"`
	Target    string  `json:"target,omitempty"`
	Handle    string  `json:"handle,omitempty"`
	Extension string  `json:"extension,omitempty"`
	Offset    uint64  `json:"offset,omitempty"`
	Length    uint32  `json:"length,omitempty"`
	Flags     uint32  `json:"flags,omitempty"`
	Status    *uint32 `json:"status,omitempty"`
}

type sftpAuditStream struct {
	io.ReadWriteCloser
	p       *fileProxy
	id      string
	read    []byte
	write   []byte
	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[uint32]sftpOperation
	handles map[string]string
	closed  bool
}

func newSFTPAuditStream(rwc io.ReadWriteCloser, p *fileProxy) *sftpAuditStream {
	return &sftpAuditStream{ReadWriteCloser: rwc, p: p, id: newID(), pending: map[uint32]sftpOperation{}, handles: map[string]string{}}
}

func (s *sftpAuditStream) record(op sftpOperation, result string) error {
	if s.p.c.auditFailed.Load() {
		return ErrDenied
	}
	op.Session = s.id
	return s.p.c.Audit(s.p.l.User, "file."+strings.ToLower(op.Method), s.p.t.ID, result, s.p.l.Source, encode(op))
}

func (s *sftpAuditStream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(s.read) == 0 {
		var header [4]byte
		if n, err := io.ReadFull(s.ReadWriteCloser, header[:]); err != nil {
			if n > 0 {
				if e := s.record(sftpOperation{Method: "MALFORMED"}, "error"); e != nil {
					return 0, e
				}
			}
			return 0, err
		}
		n := binary.BigEndian.Uint32(header[:])
		if n < 5 || n > sftpMaxPacket {
			if err := s.record(sftpOperation{Method: "MALFORMED"}, "denied"); err != nil {
				return 0, err
			}
			return 0, fmt.Errorf("invalid SFTP packet length: %d", n)
		}
		packet := make([]byte, 4+int(n))
		copy(packet, header[:])
		if _, err := io.ReadFull(s.ReadWriteCloser, packet[4:]); err != nil {
			if auditErr := s.record(sftpOperation{Method: "MALFORMED"}, "error"); auditErr != nil {
				return 0, auditErr
			}
			return 0, err
		}
		var err error
		packet, err = s.request(packet)
		if err != nil {
			return 0, err
		}
		s.read = packet
	}
	n := copy(b, s.read)
	s.read = s.read[n:]
	return n, nil
}

func (s *sftpAuditStream) request(packet []byte) ([]byte, error) {
	kind := packet[4]
	op := sftpOperation{ID: binary.BigEndian.Uint32(packet[5:9]), Method: "UNKNOWN", Type: kind}
	if kind == 1 {
		op.Method = "INIT"
		op.ID = 0
		return packet, s.record(op, "attempt")
	}
	names := map[byte]string{3: "OPEN", 4: "CLOSE", 5: "READ", 6: "WRITE", 7: "LSTAT", 8: "FSTAT", 9: "SETSTAT", 10: "FSETSTAT", 11: "OPENDIR", 12: "READDIR", 13: "REMOVE", 14: "MKDIR", 15: "RMDIR", 16: "REALPATH", 17: "STAT", 18: "RENAME", 19: "READLINK", 20: "SYMLINK", 200: "EXTENDED"}
	if name, ok := names[kind]; ok {
		op.Method = name
	}
	payload := packet[9:]
	take := func() (string, bool) {
		if len(payload) < 4 {
			return "", false
		}
		n := binary.BigEndian.Uint32(payload)
		payload = payload[4:]
		if n > uint32(len(payload)) {
			return "", false
		}
		v := string(payload[:n])
		payload = payload[n:]
		return v, true
	}
	valid := true
	if kind == 200 {
		op.Extension, valid = take()
		switch op.Extension {
		case "posix-rename@openssh.com":
			op.Method = "POSIX_RENAME"
		case "statvfs@openssh.com":
			op.Method = "STATVFS"
		case "hardlink@openssh.com":
			op.Method = "LINK"
		case "fsync@openssh.com":
			op.Method = "FSYNC"
		}
	}
	s.mu.Lock()
	if kind >= 3 && kind <= 20 || kind == 200 && op.Method != "EXTENDED" {
		var value string
		var ok bool
		value, ok = take()
		valid = valid && ok
		if kind == 4 || kind == 5 || kind == 6 || kind == 8 || kind == 10 || kind == 12 || op.Method == "FSYNC" {
			op.Handle = value
			op.Path = s.handles[value]
		} else {
			op.Path = value
		}
		if kind == 18 || kind == 20 || op.Method == "POSIX_RENAME" || op.Method == "LINK" {
			op.Target, ok = take()
			valid = valid && ok
		}
		if kind == 3 || kind == 9 || kind == 10 || kind == 14 {
			if len(payload) < 4 {
				valid = false
			} else {
				op.Flags = binary.BigEndian.Uint32(payload)
			}
		}
		if kind == 5 || kind == 6 {
			if len(payload) < 12 {
				valid = false
			} else {
				op.Offset = binary.BigEndian.Uint64(payload)
				op.Length = binary.BigEndian.Uint32(payload[8:])
				if kind == 6 && uint64(op.Length) != uint64(len(payload)-12) {
					valid = false
				}
			}
		}
	}
	_, duplicate := s.pending[op.ID]
	if s.closed || duplicate || len(s.pending) >= 1024 || !valid {
		s.mu.Unlock()
		if err := s.record(op, "denied"); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("invalid or excessive SFTP requests")
	}
	// pkg/sftp v1.13.11 loses attributes in its FSETSTAT adapter. Convert a
	// known handle to SETSTAT before dispatch, retaining the original audit name.
	if (kind == 8 || kind == 10) && op.Path == "" {
		if _, known := s.handles[op.Handle]; known {
			// An unlinked/replaced entry cannot safely be addressed by path.
			// Reject rather than modifying a different inode at the old name.
			packet = append([]byte{200}, packet[5:9]...)
			packet = append(packet, wireSFTPString("unlinked-handle@gatehouse")...)
			packet = frameSFTPPacket(packet)
		}
	}
	if (kind == 8 || kind == 10) && op.Path != "" {
		replacement := byte(9)
		if kind == 8 {
			replacement = 17
		}
		packet = append([]byte{replacement}, packet[5:9]...)
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(op.Path)))
		packet = append(packet, size[:]...)
		packet = append(packet, op.Path...)
		packet = append(packet, payload...)
		packet = frameSFTPPacket(packet)
	}
	s.pending[op.ID] = op
	s.mu.Unlock()
	if err := s.record(op, "attempt"); err != nil {
		return nil, err
	}
	if err := s.p.c.ticketValid(s.p.t, s.p.l.Source); err != nil {
		if auditErr := s.record(op, "denied"); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	return packet, nil
}

func (s *sftpAuditStream) Write(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// pkg/sftp serializes complete packets, but may write their header and data separately.
	s.write = append(s.write, b...)
	for len(s.write) >= 4 {
		n := binary.BigEndian.Uint32(s.write)
		if n < 5 || n > sftpMaxPacket {
			return 0, fmt.Errorf("invalid SFTP response length")
		}
		if len(s.write) < int(n)+4 {
			break
		}
		packet := s.write[:int(n)+4]
		if err := s.response(packet); err != nil {
			return 0, err
		}
		if _, err := io.Copy(s.ReadWriteCloser, bytes.NewReader(packet)); err != nil {
			return 0, err
		}
		s.write = s.write[int(n)+4:]
	}
	return len(b), nil
}

func (s *sftpAuditStream) response(packet []byte) error {
	kind := packet[4]
	if kind == 2 {
		return s.record(sftpOperation{Method: "INIT"}, "ok")
	}
	id := binary.BigEndian.Uint32(packet[5:9])
	s.mu.Lock()
	op, ok := s.pending[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("unmatched SFTP response")
	}
	delete(s.pending, id)
	result := "ok"
	if kind == 101 {
		if len(packet) < 13 {
			s.mu.Unlock()
			return fmt.Errorf("short SFTP status")
		}
		code := binary.BigEndian.Uint32(packet[9:13])
		op.Status = &code
		if len(packet) >= 17 {
			n := binary.BigEndian.Uint32(packet[13:17])
			if n <= uint32(len(packet)-17) {
				if n > 4096 {
					n = 4096
				}
				op.Error = string(packet[17 : 17+n])
			}
		}
		switch code {
		case 0:
		case 1:
			result = "eof"
		case 3:
			result = "denied"
		case 8:
			result = "unsupported"
		default:
			result = "error"
		}
	}
	if kind == 102 && len(packet) >= 13 {
		n := binary.BigEndian.Uint32(packet[9:13])
		if n > uint32(len(packet)-13) || len(s.handles) >= 4096 {
			s.mu.Unlock()
			return fmt.Errorf("invalid or excessive SFTP handles")
		}
		s.handles[string(packet[13:13+n])] = s.absolute(op.Path)
	}
	if result == "ok" {
		from, to := s.absolute(op.Path), s.absolute(op.Target)
		switch op.Method {
		case "REMOVE", "RMDIR":
			for handle, fp := range s.handles {
				if fp == from || strings.HasPrefix(fp, from+"/") {
					s.handles[handle] = ""
				}
			}
		case "RENAME", "POSIX_RENAME":
			for handle, fp := range s.handles {
				if fp == from || strings.HasPrefix(fp, from+"/") {
					s.handles[handle] = to + strings.TrimPrefix(fp, from)
				} else if fp == to || strings.HasPrefix(fp, to+"/") {
					s.handles[handle] = ""
				}
			}
		}
	}
	if op.Method == "CLOSE" {
		delete(s.handles, op.Handle)
	}
	s.mu.Unlock()
	return s.record(op, result)
}

func (s *sftpAuditStream) Close() error {
	err := s.ReadWriteCloser.Close()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return err
	}
	s.closed = true
	pending := s.pending
	s.pending = map[uint32]sftpOperation{}
	s.handles = map[string]string{}
	s.mu.Unlock()
	for _, op := range pending {
		if e := s.record(op, "aborted"); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (s *sftpAuditStream) absolute(fp string) string {
	if !path.IsAbs(fp) {
		fp = path.Join(s.p.t.Spec.FileRoot, fp)
	}
	return path.Clean(fp)
}
func wireSFTPString(value string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(value)))
	return append(b, value...)
}
func frameSFTPPacket(body []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

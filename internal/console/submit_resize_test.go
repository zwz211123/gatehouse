package console

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// submitResizeStream pauses the final newline while ReadLine still owns the
// terminal lock, so window-change callers can queue at the submit boundary.
type submitResizeStream struct {
	input       *strings.Reader
	output      lockedBuffer
	submitted   chan struct{}
	release     chan struct{}
	afterSubmit bool
	extraWrites int
}

func (s *submitResizeStream) Read(p []byte) (int, error) {
	return s.input.Read(p)
}

func (s *submitResizeStream) Write(p []byte) (int, error) {
	if string(p) == "\r\n" {
		s.afterSubmit = true
		close(s.submitted)
		<-s.release
	} else if s.afterSubmit {
		s.extraWrites++
	}
	return s.output.Write(p)
}

func TestResizeQueuedAtSubmitDoesNotRepaint(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		rw := &submitResizeStream{
			input:     strings.NewReader("help\r"),
			submitted: make(chan struct{}),
			release:   make(chan struct{}),
		}
		terminal := NewTerminal(rw, "ghb> ")
		done := make(chan error, 1)
		go func() {
			line, err := terminal.ReadLine()
			if err == nil && line != "help" {
				err = fmt.Errorf("submitted %q", line)
			}
			done <- err
		}()
		<-rw.submitted
		var resizers, started sync.WaitGroup
		resizers.Add(8)
		started.Add(8)
		for i := 0; i < 8; i++ {
			go func(width int) {
				defer resizers.Done()
				started.Done()
				_ = terminal.SetSize(width, 24)
			}(40 + i)
		}
		started.Wait()
		close(rw.release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		resizers.Wait()
		if rw.extraWrites != 0 {
			t.Fatalf("attempt %d: %d redraws after submitted newline", attempt, rw.extraWrites)
		}
	}
}

func TestReadLineExitReleasesEditor(t *testing.T) {
	for _, input := range []string{"help\r", "help\n", "", "partial", "\x03", "\x04"} {
		t.Run(fmt.Sprintf("%q", input), func(t *testing.T) {
			rw := &stream{Reader: strings.NewReader(input)}
			terminal := NewTerminal(rw, "ghb> ")
			_, err := terminal.ReadLine()
			if err != nil && err != io.EOF {
				t.Fatal(err)
			}
			if !terminal.mu.TryLock() {
				t.Fatal("ReadLine left the terminal locked")
			}
			reading := terminal.reading
			terminal.mu.Unlock()
			if reading {
				t.Fatal("ReadLine left the editor active")
			}
			before := rw.Buffer.Len()
			if err := terminal.SetSize(40, 10); err != nil {
				t.Fatal(err)
			}
			if rw.Buffer.Len() != before {
				t.Fatal("idle resize wrote into the command response")
			}
		})
	}
}

func TestCallbackPanicReleasesEditor(t *testing.T) {
	rw := &stream{Reader: strings.NewReader("x")}
	terminal := NewTerminal(rw, "ghb> ")
	terminal.AutoCompleteCallback = func(string, int, rune) (string, int, bool) {
		panic("test callback")
	}
	func() {
		defer func() {
			if got := recover(); got != "test callback" {
				t.Fatalf("unexpected panic: %v", got)
			}
		}()
		_, _ = terminal.ReadLine()
	}()
	if !terminal.mu.TryLock() {
		t.Fatal("panic cleanup left the terminal locked")
	}
	reading := terminal.reading
	terminal.mu.Unlock()
	if reading {
		t.Fatal("panic cleanup left the editor active")
	}
	before := rw.Buffer.Len()
	if err := terminal.SetSize(40, 10); err != nil {
		t.Fatal(err)
	}
	if rw.Buffer.Len() != before {
		t.Fatal("resize after callback panic repainted the input")
	}
}

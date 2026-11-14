package console

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/mattn/go-runewidth"
)

type stream struct {
	*strings.Reader
	bytes.Buffer
}

func (s *stream) Read(p []byte) (int, error)  { return s.Reader.Read(p) }
func (s *stream) Write(p []byte) (int, error) { return s.Buffer.Write(p) }

func TestEditingAndNoReadAhead(t *testing.T) {
	for _, tc := range []struct{ name, keys, want string }{
		{"insert", "ab\x1b[DX\r", "aXb"},
		{"SS3", "ab\x1bODX\r", "aXb"},
		{"delete", "abc\x1b[D\x1b[D\x1b[3~\r", "ac"},
		{"home-end", "bc\x1b[Ha\x1b[F!\r", "abc!"},
		{"Chinese", "中文名字\x1b[D\x7f\r", "中文字"},
		{"word-delete", "one two\x17three\r", "one three"},
		{"clear-prefix", "abc\x1b[D\x15\r", "c"},
		{"clear-suffix", "abc\x1b[D\x0b\r", "ab"},
		{"transpose", "ab\x14\r", "ba"},
		{"paste", "\x1b[200~中文\x1b[201~\r", "中文"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := &stream{Reader: strings.NewReader(tc.keys + "TARGET-INPUT")}
			terminal := NewTerminal(rw, "ghb> ")
			_ = terminal.SetSize(12, 4)
			got, err := terminal.ReadLine()
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
			remaining, _ := io.ReadAll(rw.Reader)
			if string(remaining) != "TARGET-INPUT" {
				t.Fatalf("stole target bytes: %q", remaining)
			}
		})
	}
}

func TestHistoryAndPromptIsolation(t *testing.T) {
	rw := &stream{Reader: strings.NewReader("help\rsecret-json\r\x1b[A\rtyping\x1b[A\x1b[B\r")}
	terminal := NewTerminal(rw, "ghb> ")
	callback := func(string, int, rune) (string, int, bool) { return "", 0, false }
	terminal.AutoCompleteCallback = callback
	for i, want := range []string{"help", "secret-json", "help", "typing"} {
		if i == 1 {
			terminal.AutoCompleteCallback = nil
		} else {
			terminal.AutoCompleteCallback = callback
		}
		got, err := terminal.ReadLine()
		if err != nil || got != want {
			t.Fatalf("line %d: %q %v; want %q", i, got, err, want)
		}
	}
}

func TestCRLFIsOneEnter(t *testing.T) {
	rw := &stream{Reader: strings.NewReader("one\r\ntwo\r\n")}
	terminal := NewTerminal(rw, "ghb> ")
	for _, want := range []string{"one", "two"} {
		got, err := terminal.ReadLine()
		if err != nil || got != want {
			t.Fatalf("got %q %v; want %q", got, err, want)
		}
	}
}

func TestViewportAndUnicodeCells(t *testing.T) {
	terminal := NewTerminal(&stream{Reader: strings.NewReader("")}, "ghb> ")
	for _, size := range []int{1, 2, 6, 8, 12, 80} {
		terminal.width = size
		terminal.line = []rune("中文服务器abcde")
		for pos := 0; pos <= len(terminal.line); pos++ {
			terminal.pos = pos
			text, x := terminal.inputView()
			if runewidth.StringWidth(text) >= size || x >= size || x < 0 {
				t.Fatalf("%d cells: %q cursor %d", size, text, x)
			}
		}
	}
	terminal.width = 20
	terminal.line = []rune("中文")
	terminal.pos = 2
	terminal.viewStart = 0
	_, x := terminal.inputView()
	if x != 9 {
		t.Fatalf("Chinese cursor = %d, want 9 cells", x)
	}
}

func TestLongViewportDoesNotAllocateForEverySuffix(t *testing.T) {
	terminal := NewTerminal(nil, "ghb> ")
	terminal.line = []rune(strings.Repeat("x", 4096))
	terminal.pos = len(terminal.line)
	for _, width := range []int{1, 8, 80} {
		terminal.width = width
		allocations := testing.AllocsPerRun(1, func() {
			terminal.viewStart = 0 // Home followed by End on a full input line.
			text, x := terminal.inputView()
			if runewidth.StringWidth(text) >= width || x >= width {
				panic("viewport overflow")
			}
		})
		// Allow ordinary renderer allocations, but not a new decreasing
		// suffix for each of the 4,096 runes during one Home/End pair.
		if allocations > 32 {
			t.Fatalf("width %d: %.0f allocations per repaint; repeated suffix scans", width, allocations)
		}
	}
}

func BenchmarkViewportHomeEnd(b *testing.B) {
	for _, width := range []int{1, 8, 80} {
		for _, size := range []int{256, 1024, 4096} {
			b.Run(fmt.Sprintf("width%d/runes%d", width, size), func(b *testing.B) {
				terminal := NewTerminal(nil, "ghb> ")
				terminal.width = width
				terminal.line = []rune(strings.Repeat("x", size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					terminal.pos = 0
					terminal.inputView()
					terminal.pos = size
					terminal.inputView()
				}
			})
		}
	}
}

func TestViewportKeepsGraphemeClusters(t *testing.T) {
	for _, tc := range []struct {
		line, want    string
		width, cursor int
	}{
		{"中文服务器", "务器", 6, 4},
		{"ae\u0301b", "e\u0301b", 4, 2},
		{"a👨‍👩‍👧‍👦b", "👨‍👩‍👧‍👦b", 5, 3},
	} {
		terminal := NewTerminal(nil, "")
		terminal.width = tc.width
		terminal.line = []rune(tc.line)
		terminal.pos = len(terminal.line)
		got, cursor := terminal.inputView()
		if got != tc.want || cursor != tc.cursor {
			t.Fatalf("%q: got %q @ %d; want %q @ %d", tc.line, got, cursor, tc.want, tc.cursor)
		}
	}
}

func TestAllKeysReachCallbackBeforeEditing(t *testing.T) {
	rw := &stream{Reader: strings.NewReader("\x1b[A\x1b[B\x1b[C\x1b[D\x1b[Z\r")}
	terminal := NewTerminal(rw, "ghb> ")
	var keys []rune
	terminal.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		keys = append(keys, key)
		return line, pos, key != '\r'
	}
	if _, err := terminal.ReadLine(); err != nil {
		t.Fatal(err)
	}
	want := []rune{KeyUp, KeyDown, KeyRight, KeyLeft, KeyBackTab, '\r'}
	if string(keys) != string(want) {
		t.Fatalf("key order: %v", keys)
	}
}

func TestResizeAndDisconnect(t *testing.T) {
	r, w := io.Pipe()
	var output lockedBuffer
	terminal := NewTerminal(struct {
		io.Reader
		io.Writer
	}{r, &output}, "ghb> ")
	terminal.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if key == '\t' {
			terminal.SetSuggestions([]string{"中文候选", "other", "footer"})
			return line, pos, true
		}
		return "", 0, false
	}
	done := make(chan error, 1)
	go func() { _, err := terminal.ReadLine(); done <- err }()
	for i := 0; i < 10; i++ {
		if _, err := io.WriteString(w, "中文\t"); err != nil {
			t.Fatal(err)
		}
		if err := terminal.SetSize(8+i, 2+i%3); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	if err := <-done; err != io.EOF {
		t.Fatal(err)
	}
	output.mu.Lock()
	before := output.Len()
	output.mu.Unlock()
	if err := terminal.SetSize(80, 24); err != nil {
		t.Fatal(err)
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.Len() != before {
		t.Fatal("idle resize wrote into target session")
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

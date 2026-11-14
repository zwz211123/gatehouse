// Package console implements Gatehouse's SSH menu line editor. It reads only
// the bytes needed for each key: input after Enter must remain available to the
// target SSH session, rather than being prefetched by a background editor.
package console

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/clipperhouse/uax29/v2/graphemes"
	"github.com/mattn/go-runewidth"
)

// Keys are delivered to AutoCompleteCallback before normal editing/history.
const (
	KeyUp rune = 0xd800 + iota
	KeyDown
	KeyLeft
	KeyRight
	KeyHome
	KeyEnd
	KeyDelete
	KeyWordLeft
	KeyWordRight
	KeyBackTab
	keyPasteStart
	keyPasteEnd
	keyUnknown
)

type Terminal struct {
	// Positions are byte offsets, including for Unicode input. A consumed Enter
	// accepts a completion without executing the command.
	AutoCompleteCallback func(string, int, rune) (string, int, bool)

	mu                      sync.Mutex
	rw                      io.ReadWriter
	prompt                  string
	width, height           int
	reading                 bool
	line                    []rune
	pos, viewStart, cursorX int
	suggestions             []string
	menuRows                int
	history                 []string
	historyIndex            int
	pending                 string
	skipLF                  bool
}

func NewTerminal(rw io.ReadWriter, prompt string) *Terminal {
	return &Terminal{rw: rw, prompt: prompt, width: 80, height: 24, historyIndex: -1}
}

// SetSuggestions changes transient rows below the prompt. Rendering happens
// after the key callback returns, under the same lock as input and resizing.
// Rows are plain text; the selection is marked by the caller, never ANSI data.
func (t *Terminal) SetSuggestions(rows []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.suggestions = append([]string(nil), rows...)
}

func (t *Terminal) Size() (int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.width, t.height
}

func (t *Terminal) SetSize(width, height int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	width, height = max(1, width), max(1, height)
	var b strings.Builder
	if t.reading && width < t.width && t.cursorX >= width {
		// Account for a terminal that reflows the input row while shrinking.
		fmt.Fprintf(&b, "\x1b[%dA", t.cursorX/width)
	}
	t.width, t.height = width, height
	if !t.reading {
		return nil // A target shell may currently own the channel.
	}
	return t.paint(&b)
}

// clip and inputView use terminal cells, not bytes or rune counts. Long input
// scrolls horizontally, so candidate paging never depends on wrapped lines.
func clip(s string, cells int) string {
	if cells <= 0 {
		return ""
	}
	return runewidth.Truncate(s, cells, "")
}

func (t *Terminal) inputView() (string, int) {
	budget := max(0, t.width-1)
	prompt := clip(t.prompt, max(0, budget-1))
	promptWidth := runewidth.StringWidth(prompt)
	budget -= promptWidth
	if budget <= 0 {
		t.viewStart = t.pos
		return prompt, promptWidth
	}
	t.viewStart = min(t.viewStart, t.pos)
	// Measure each grapheme once. Repeatedly measuring decreasing suffixes
	// makes Home/End on long lines quadratic, especially in narrow PTYs.
	// Whole-cluster boundaries also avoid splitting combining marks or ZWJ
	// emoji when scrolling the viewport.
	type clusterWidth struct{ end, cells int }
	clusters := make([]clusterWidth, 0, t.pos-t.viewStart)
	iterator := graphemes.FromString(string(t.line[t.viewStart:t.pos]))
	end, cells := t.viewStart, 0
	for iterator.Next() {
		cluster := iterator.Value()
		width := runewidth.StringWidth(cluster)
		end += utf8.RuneCountInString(cluster)
		cells += width
		clusters = append(clusters, clusterWidth{end, width})
	}
	for _, cluster := range clusters {
		if cells < budget {
			break
		}
		cells -= cluster.cells
		t.viewStart = cluster.end
	}
	x := promptWidth + cells
	return prompt + clip(string(t.line[t.viewStart:]), budget), min(x, max(0, t.width-1))
}

func (t *Terminal) paint(b *strings.Builder) error {
	// The cursor always returns to the input row. Clearing from there removes
	// the previous pager, including rows left over from a larger page/resize.
	// CRLF reserves space only on first opening; subsequent paints reuse it.
	b.WriteString("\r\x1b[J")
	input, x := t.inputView()
	b.WriteString(input)
	rows := min(len(t.suggestions), max(0, t.height-1))
	for _, row := range t.suggestions[:rows] {
		b.WriteString("\r\n")
		b.WriteString(clip(safeText(row), max(0, t.width-1)))
	}
	if rows > 0 {
		fmt.Fprintf(b, "\x1b[%dA", rows)
	}
	b.WriteByte('\r')
	if x > 0 {
		fmt.Fprintf(b, "\x1b[%dC", x)
	}
	t.cursorX, t.menuRows = x, rows
	_, err := io.WriteString(t.rw, b.String())
	return err
}

func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

func (t *Terminal) ReadLine() (string, error) {
	t.mu.Lock()
	// Every return holds mu: make the state transition and unlock atomic
	// to SetSize, including after the submitted newline has been written.
	defer func() {
		t.reading = false
		t.mu.Unlock()
	}()
	t.reading = true
	t.line, t.pos, t.viewStart = nil, 0, 0
	t.suggestions, t.historyIndex = nil, -1
	err := t.paint(&strings.Builder{})
	if err != nil {
		return "", err
	}
	pasting := false
	for {
		// Input can block. Reacquire mu even if the reader panics, so the
		// function-level cleanup always owns the lock.
		key, err := func() (rune, error) {
			t.mu.Unlock()
			defer t.mu.Lock()
			return t.readKey()
		}()
		if err != nil {
			t.suggestions = nil
			if t.menuRows > 0 {
				_ = t.paint(&strings.Builder{})
			}
			line := string(t.line)
			return line, err
		}
		if key == keyPasteStart || key == keyPasteEnd {
			pasting = key == keyPasteStart
			if pasting {
				t.suggestions = nil
				_ = t.paint(&strings.Builder{})
			}
			continue
		}
		if !pasting && (key == 3 || key == 4 && len(t.line) == 0) {
			t.suggestions = nil
			_ = t.paint(&strings.Builder{})
			return "", io.EOF
		}
		if !pasting && t.AutoCompleteCallback != nil {
			callback := t.AutoCompleteCallback
			line, pos := string(t.line), len(string(t.line[:t.pos]))
			// Callbacks may acquire mu through SetSuggestions or Size.
			next, nextPos, consumed := func() (string, int, bool) {
				t.mu.Unlock()
				defer t.mu.Lock()
				return callback(line, pos, key)
			}()
			if consumed {
				if nextPos >= 0 && nextPos <= len(next) && utf8.ValidString(next[:nextPos]) && utf8.ValidString(next) {
					t.line, t.pos = []rune(next), utf8.RuneCountInString(next[:nextPos])
				}
				err = t.paint(&strings.Builder{})
				if err != nil {
					return "", err
				}
				continue
			}
		}
		if key == '\r' || key == '\n' {
			t.suggestions = nil
			err = t.paint(&strings.Builder{})
			if err == nil {
				_, err = io.WriteString(t.rw, "\r\n")
			}
			line := string(t.line)
			// Prompt inputs (JSON, numeric selections, confirmation data) are
			// not command history and must not reappear via the up arrow.
			if t.AutoCompleteCallback != nil && line != "" && (len(t.history) == 0 || t.history[len(t.history)-1] != line) {
				t.history = append(t.history, line)
				if len(t.history) > 100 {
					t.history = t.history[1:]
				}
			}
			return line, err
		}
		var b strings.Builder
		if !pasting {
			t.edit(key)
			if key == 12 {
				b.WriteString("\x1b[H\x1b[2J")
			}
		} else if key >= ' ' && key < 0xd800 || key > 0xdfff {
			t.insert(key)
		}
		err = t.paint(&b)
		if err != nil {
			return "", err
		}
	}
}

func (t *Terminal) insert(key rune) {
	if len(t.line) >= 4096 || unicode.IsControl(key) {
		return
	}
	t.line = append(t.line, 0)
	copy(t.line[t.pos+1:], t.line[t.pos:])
	t.line[t.pos] = key
	t.pos++
}

func (t *Terminal) edit(key rune) {
	switch key {
	case KeyLeft:
		t.pos = max(0, t.pos-1)
	case KeyRight:
		t.pos = min(len(t.line), t.pos+1)
	case KeyHome:
		t.pos = 0
	case KeyEnd:
		t.pos = len(t.line)
	case KeyWordLeft:
		for t.pos > 0 && unicode.IsSpace(t.line[t.pos-1]) {
			t.pos--
		}
		for t.pos > 0 && !unicode.IsSpace(t.line[t.pos-1]) {
			t.pos--
		}
	case KeyWordRight:
		for t.pos < len(t.line) && !unicode.IsSpace(t.line[t.pos]) {
			t.pos++
		}
		for t.pos < len(t.line) && unicode.IsSpace(t.line[t.pos]) {
			t.pos++
		}
	case 8, 127:
		if t.pos > 0 {
			t.line = append(t.line[:t.pos-1], t.line[t.pos:]...)
			t.pos--
		}
	case 4, KeyDelete:
		if t.pos < len(t.line) {
			t.line = append(t.line[:t.pos], t.line[t.pos+1:]...)
		}
	case 11:
		t.line = t.line[:t.pos] // Ctrl-K
	case 21:
		t.line = t.line[t.pos:]
		t.pos = 0 // Ctrl-U
	case 23: // Ctrl-W
		end := t.pos
		t.edit(KeyWordLeft)
		t.line = append(t.line[:t.pos], t.line[end:]...)
	case 20: // Ctrl-T
		if t.pos > 0 && len(t.line) > 1 {
			i := min(t.pos, len(t.line)-1)
			t.line[i-1], t.line[i] = t.line[i], t.line[i-1]
			t.pos = i + 1
		}
	case KeyUp, KeyDown:
		if key == KeyUp && t.historyIndex+1 < len(t.history) {
			if t.historyIndex < 0 {
				t.pending = string(t.line)
			}
			t.historyIndex++
			t.line = []rune(t.history[len(t.history)-1-t.historyIndex])
		} else if key == KeyDown && t.historyIndex >= 0 {
			t.historyIndex--
			if t.historyIndex < 0 {
				t.line = []rune(t.pending)
			} else {
				t.line = []rune(t.history[len(t.history)-1-t.historyIndex])
			}
		}
		t.pos = len(t.line)
	default:
		if key >= ' ' && (key < 0xd800 || key > 0xdfff) {
			t.insert(key)
		}
	}
}

// readKey intentionally has no buffered reader or input goroutine. CSI/SS3
// sequences and UTF-8 may span any number of SSH packets.
func (t *Terminal) readKey() (rune, error) {
	var b []byte
	for len(b) < 64 {
		var one [1]byte
		n, err := t.rw.Read(one[:])
		if n == 0 {
			if err != nil {
				return 0, err
			}
			continue
		}
		if t.skipLF {
			t.skipLF = false
			if one[0] == '\n' {
				continue
			}
		}
		b = append(b, one[0])
		if b[0] != 27 {
			if !utf8.FullRune(b) {
				continue
			}
			r, _ := utf8.DecodeRune(b)
			if r == '\r' {
				// A shared input owner must carry delimiter state across a
				// handoff to a target shell, not just to the next ReadLine.
				// Do not read ahead: CR-only clients must enter immediately.
				if input, ok := t.rw.(interface{ SkipOptionalLineFeed() }); ok {
					input.SkipOptionalLineFeed()
				} else {
					t.skipLF = true
				}
			}
			switch r {
			case 1:
				return KeyHome, nil
			case 2:
				return KeyLeft, nil
			case 5:
				return KeyEnd, nil
			case 6:
				return KeyRight, nil
			case 14:
				return KeyDown, nil
			case 16:
				return KeyUp, nil
			}
			return r, nil
		}
		if len(b) == 1 {
			continue
		}
		if len(b) == 2 {
			if b[1] == '[' || b[1] == 'O' {
				continue
			}
			return keyUnknown, nil
		}
		last := b[len(b)-1]
		if last < 0x40 || last > 0x7e {
			continue
		}
		seq := string(b[1:])
		switch seq {
		case "[A", "OA":
			return KeyUp, nil
		case "[B", "OB":
			return KeyDown, nil
		case "[C", "OC":
			return KeyRight, nil
		case "[D", "OD":
			return KeyLeft, nil
		case "[H", "OH", "[1~", "[7~":
			return KeyHome, nil
		case "[F", "OF", "[4~", "[8~":
			return KeyEnd, nil
		case "[3~":
			return KeyDelete, nil
		case "[1;3D", "[1;5D":
			return KeyWordLeft, nil
		case "[1;3C", "[1;5C":
			return KeyWordRight, nil
		case "[Z":
			return KeyBackTab, nil
		case "[200~":
			return keyPasteStart, nil
		case "[201~":
			return keyPasteEnd, nil
		}
		return keyUnknown, nil
	}
	return keyUnknown, nil
}

package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// Masked prompt: typed keys echo as '*'; after a paste the last 3 characters
// are shown so the owner can check they pasted the right value. Bracketed
// paste mode (ESC[?2004h) tells a paste from typing; a multi-byte read chunk
// is treated as a paste on terminals that don't support it.

const (
	maskTail     = 3
	maskMaxStars = 32
)

var (
	pasteStart = []byte("\x1b[200~")
	pasteEnd   = []byte("\x1b[201~")
	errAborted = errors.New("aborted")
)

type maskedInput struct {
	buf        []byte
	revealTail bool // last action was a paste
	inPaste    bool
	done       bool
}

// feed consumes one read chunk. A plain chunk of more than one byte arrived
// as one burst, which is how a paste looks without bracketed paste.
func (m *maskedInput) feed(chunk []byte) error {
	burst := len(chunk) > 1 && !strings.Contains(string(chunk), "\x1b")
	for i := 0; i < len(chunk) && !m.done; {
		rest := chunk[i:]
		switch {
		case hasPrefix(rest, pasteStart):
			m.inPaste = true
			i += len(pasteStart)
			continue
		case hasPrefix(rest, pasteEnd):
			m.inPaste = false
			m.revealTail = true
			i += len(pasteEnd)
			continue
		}
		c := chunk[i]
		i++
		if m.inPaste {
			if c != '\r' && c != '\n' {
				m.buf = append(m.buf, c)
			}
			continue
		}
		switch c {
		case '\r', '\n':
			m.done = true
		case 3: // Ctrl-C
			return errAborted
		case 4: // Ctrl-D
			if len(m.buf) == 0 {
				return errAborted
			}
			m.done = true
		case 127, 8: // Backspace
			if len(m.buf) > 0 {
				_, sz := utf8.DecodeLastRune(m.buf)
				m.buf = m.buf[:len(m.buf)-sz]
			}
			m.revealTail = false
		case 21: // Ctrl-U clears the line
			m.buf = m.buf[:0]
			m.revealTail = false
		case 0x1b: // other escape sequence (arrows etc.): skip it
			for i < len(chunk) && (chunk[i] == '[' || chunk[i] == 'O' || (chunk[i] >= '0' && chunk[i] <= '9') || chunk[i] == ';') {
				i++
			}
			if i < len(chunk) {
				i++
			}
		default:
			if c < 0x20 {
				continue
			}
			m.buf = append(m.buf, c)
			m.revealTail = burst
		}
	}
	return nil
}

// mask renders the echo: stars, plus the last 3 characters after a paste.
func (m *maskedInput) mask() string {
	n := utf8.RuneCount(m.buf)
	tail := ""
	if m.revealTail && n > maskTail {
		r := []rune(string(m.buf))
		tail = string(r[n-maskTail:])
	}
	stars := n - utf8.RuneCountInString(tail)
	s := strings.Repeat("*", min(stars, maskMaxStars))
	if stars > maskMaxStars {
		s += "…"
	}
	s += tail
	if n > 0 {
		s += fmt.Sprintf("  (%d chars)", n)
	}
	return s
}

func hasPrefix(b, p []byte) bool {
	return len(b) >= len(p) && string(b[:len(p)]) == string(p)
}

// readMasked reads a value from the terminal on fd, echoing the mask to out.
func readMasked(fd int, in io.Reader, out io.Writer, prompt string) ([]byte, error) {
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer term.Restore(fd, state)
	fmt.Fprint(out, "\x1b[?2004h")
	defer fmt.Fprint(out, "\x1b[?2004l\r\n")

	m := &maskedInput{}
	render := func() { fmt.Fprintf(out, "\r\x1b[K%s%s", prompt, m.mask()) }
	render()
	chunk := make([]byte, 4096)
	for !m.done {
		n, err := in.Read(chunk)
		if n > 0 {
			if ferr := m.feed(chunk[:n]); ferr != nil {
				return nil, ferr
			}
			render()
		}
		if err != nil {
			if err == io.EOF && len(m.buf) > 0 {
				break
			}
			return nil, err
		}
	}
	return m.buf, nil
}

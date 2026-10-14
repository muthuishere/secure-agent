// Package agentpty runs an interactive agent inside a pty sec owns, so every
// byte the human types or pastes passes sec first. A secret in a paste is
// swapped for {{NAME}} before the agent ever sees it; a secret typed by hand
// is caught at Enter, before the agent submits the line — so the value never
// reaches the model, the agent's transcript, or its prompt history.
//
// What arrives on stdin is not only keys. Measured against Claude Code in
// Ghostty (kitty keyboard flags 5, mouse ?1003, focus ?1004, bracketed paste):
// terminal replies to the agent's queries (DA1, DECRPM, XTVERSION as DCS, kitty
// graphics as APC, cell-size reports), mouse-motion floods, and focus events all
// flow through the same fd. None of those touch the input box, and the filter
// has to know that, or it cannot say what the box holds when Enter comes.
package agentpty

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/muthuishere/secure-agent/internal/detect"
)

var (
	pasteStart = []byte("\x1b[200~")
	pasteEnd   = []byte("\x1b[201~")
	ctrlU      = []byte{0x15} // clears Claude Code's input box without writing the draft to its history
)

// Settle gives every hit its final name, storing values the vault has not
// seen. An error means the value could not be secured, and the filter fails
// closed: the text is dropped, never forwarded.
type Settle func(hits []detect.Hit, source string) ([]detect.Hit, error)

// Notify tells the human something happened, outside the agent's screen.
type Notify func(msg string)

// Filter is the input side of the pty: Feed takes what the terminal sent and
// returns what the agent should receive now; Later returns steps that must
// follow with a pause between them.
type Filter struct {
	Known  map[string]string // vault name → value; grows as values are captured
	Settle Settle
	Notify Notify

	pending []byte // an incomplete sequence split across reads
	inPaste bool
	paste   []byte

	// box mirrors the agent's input box — its text and cursor. It is exact
	// while only keys with a known effect are used; a key whose effect can't
	// be modelled (prompt-history navigation, word operations, completion)
	// marks it unknown until the box is next cleared or submitted.
	box     []byte
	cur     int
	unknown bool
	// seen is every byte of text typed or pasted since the box was last
	// cleared, regardless of cursor: when the mirror is unknown, this decides
	// whether the line may go at all.
	seen []byte

	later [][]byte
}

func (f *Filter) Feed(p []byte) []byte {
	buf := append(f.pending, p...)
	f.pending = nil
	var out []byte
	for len(buf) > 0 {
		if f.inPaste {
			i := bytes.Index(buf, pasteEnd)
			if i < 0 {
				keep := partialSuffix(buf, pasteEnd)
				f.paste = append(f.paste, buf[:len(buf)-keep]...)
				f.pending = append(f.pending, buf[len(buf)-keep:]...)
				return out
			}
			f.paste = append(f.paste, buf[:i]...)
			buf = buf[i+len(pasteEnd):]
			f.inPaste = false
			text, ok := f.scrub(f.paste)
			f.paste = nil
			if !ok {
				continue
			}
			out = append(out, pasteStart...)
			out = append(out, text...)
			out = append(out, pasteEnd...)
			f.insert(text)
			continue
		}
		if buf[0] == 0x1b {
			n := seqLen(buf)
			if n == 0 { // incomplete — wait for more bytes (Flush ends the wait)
				f.pending = append(f.pending, buf...)
				return out
			}
			seq := buf[:n]
			buf = buf[n:]
			if bytes.Equal(seq, pasteStart) {
				f.inPaste = true
				continue
			}
			// A reply split across reads can still land its final byte in the
			// same chunk as the human's first keystroke — `ESC[?2` then `m` of
			// "my key is" merges into a frame no terminal sends. The bytes
			// always go through literally; when the completing byte was
			// plausibly that keystroke, it is re-fed so the mirror sees what
			// the agent's box now holds.
			if !plausible(seq) {
				out = append(out, seq...)
				if t := mergedKeystroke(seq); len(t) > 0 {
					out = append(out, f.control(t[0])...)
				}
				continue
			}
			out = append(out, f.escape(seq)...)
			continue
		}
		c := buf[0]
		buf = buf[1:]
		out = append(out, f.control(c)...)
	}
	return out
}

// Pending reports whether an incomplete sequence is being held.
func (f *Filter) Pending() bool { return len(f.pending) > 0 }

// Flush is called when input has gone quiet with a sequence still pending:
// a lone ESC is then the Esc key, anything else goes through as it is.
func (f *Filter) Flush() []byte {
	p := f.pending
	f.pending = nil
	if len(p) == 0 {
		return nil
	}
	if len(p) == 1 { // bare Esc key (legacy keyboard mode)
		return f.escKey(p)
	}
	return p
}

// Later hands the runner steps that must reach the agent one at a time, with
// a pause between each, after whatever Feed returned.
func (f *Filter) Later() [][]byte {
	l := f.later
	f.later = nil
	return l
}

// control handles a single non-ESC byte.
func (f *Filter) control(c byte) []byte {
	switch c {
	case '\r', '\n':
		return f.submit([]byte{c})
	case 0x7f, 0x08:
		f.backspace()
	case 0x15, 0x03: // Ctrl-U, Ctrl-C: the box is emptied
		f.clear()
	case 0x01:
		f.home()
	case 0x05:
		f.end()
	case 0x02:
		f.left()
	case 0x06:
		f.right()
	case 0x04:
		f.del()
	default:
		if c < 0x20 { // Ctrl-W/K/Y, Tab…: edits the mirror can't follow
			f.unknown = true
		} else {
			f.insert([]byte{c})
		}
	}
	return []byte{c}
}

// escape handles one complete ESC sequence. Almost everything passes through
// untouched; the question is only what it did to the box.
func (f *Filter) escape(seq []byte) []byte {
	switch seq[1] {
	case 'P', '_', ']', '^', 'X': // DCS/APC/OSC/PM/SOS: terminal replies, never keys
		return seq
	case '[':
		return f.csi(seq)
	case 'O': // SS3 (application cursor keys)
		switch seq[2] {
		case 'D':
			f.left()
		case 'C':
			f.right()
		case 'H':
			f.home()
		case 'F':
			f.end()
		default:
			f.unknown = true
		}
		return seq
	case '\r', '\n': // Alt+Enter in legacy mode: newline in the box
		f.insert([]byte{'\n'})
		return seq
	}
	f.unknown = true // Alt+letter: word motions and kills
	return seq
}

func (f *Filter) csi(seq []byte) []byte {
	params, final := seq[2:len(seq)-1], seq[len(seq)-1]
	if len(params) > 0 && (params[0] == '<' || params[0] == '?') {
		return seq // SGR mouse; DA1, DECRPM, kitty-flags replies
	}
	switch final {
	case 'I', 'O', 'c', 't', 'y', 'R', 'n', 'Z': // focus, reports, Shift+Tab
		return seq
	case 'u':
		return f.kitty(seq, params)
	case 'D', 'C', 'H', 'F', 'A', 'B':
		if len(params) > 0 && string(params) != "1" { // modified arrow: word jump etc.
			f.unknown = true
			return seq
		}
		switch final {
		case 'D':
			f.left()
		case 'C':
			f.right()
		case 'H':
			f.home()
		case 'F':
			f.end()
		default: // Up/Down: prompt history replaces the box
			f.unknown = true
		}
		return seq
	case '~':
		switch string(params) {
		case "3":
			f.del()
		case "1", "7":
			f.home()
		case "4", "8":
			f.end()
		default:
			f.unknown = true
		}
		return seq
	}
	f.unknown = true
	return seq
}

// kitty handles "ESC [ code[:alt] [; mods] u" (kitty keyboard protocol).
func (f *Filter) kitty(seq, params []byte) []byte {
	code, alt, mods := csiU(params)
	switch {
	case code == 27 && mods <= 1:
		return f.escKey(seq)
	case code == 13:
		if mods == 2 || mods == 3 { // Shift/Alt+Enter: newline in the box
			f.insert([]byte{'\n'})
			return seq
		}
		return f.submit(seq) // plain, or a modifier we can't vouch for — treat as submit
	case code == 117 && mods == 5, code == 99 && mods == 5: // Ctrl-U, Ctrl-C
		f.clear()
	case (code == 127 || code == 8) && mods <= 1:
		f.backspace()
	case code == 97 && mods == 5:
		f.home()
	case code == 101 && mods == 5:
		f.end()
	case code == 98 && mods == 5:
		f.left()
	case code == 102 && mods == 5:
		f.right()
	case code == 100 && mods == 5:
		f.del()
	case code >= 0x20 && code != 127 && mods <= 1:
		f.insert(utf8.AppendRune(nil, rune(code)))
	case code >= 0x20 && code != 127 && mods == 2:
		if alt > 0 {
			code = alt
		}
		f.insert(utf8.AppendRune(nil, rune(code)))
	default:
		f.unknown = true
	}
	return seq
}

// escKey: Esc,Esc in Claude Code empties the box and writes the draft, raw,
// to its prompt history file. If the box holds a secret, the Esc becomes a
// Ctrl-U instead, which empties the box and writes nothing.
func (f *Filter) escKey(seq []byte) []byte {
	hits := detect.Find(string(f.seen), f.Known)
	if len(hits) == 0 {
		return seq
	}
	if settled, err := f.Settle(hits, "typed"); err == nil {
		hits = settled
	}
	f.clear()
	f.Notify("sec: cleared the line instead of Esc — it held " + names(hits) + " (stored; use {{" + hits[0].Name + "}})")
	return ctrlU
}

// submit decides what reaches the agent when the human presses Enter; key is
// the Enter as the terminal encoded it.
func (f *Filter) submit(key []byte) []byte {
	if f.unknown {
		hits := detect.Find(string(f.seen), f.Known)
		if len(hits) == 0 {
			f.clear()
			return key
		}
		if settled, err := f.Settle(hits, "typed"); err == nil {
			hits = settled
		}
		f.later = append(f.later, ctrlU)
		f.clear()
		f.Notify("sec: line not sent — it held " + names(hits) + " and was edited in a way sec can't follow. Cleared; retype it with {{" + hits[0].Name + "}}")
		return nil
	}
	hits := detect.Find(string(f.box), f.Known)
	if len(hits) == 0 {
		f.clear()
		return key
	}
	hits, err := f.Settle(hits, "typed")
	if err != nil {
		f.later = append(f.later, ctrlU)
		f.clear()
		f.Notify("sec: line not sent — it held a secret that could not be stored (" + err.Error() + "). Cleared.")
		return nil
	}
	clean := detect.Replace(string(f.box), hits)
	// The box already shows the raw line. Rewriting it in place races the
	// TUI's own input handling, so it goes out as paced steps: empty the box
	// (one Ctrl-U per line, joined by Backspace), paste the clean text as one
	// unit, then the Enter as it came.
	clear := append([]byte{}, ctrlU...)
	for i := bytes.Count(f.box, []byte{'\n'}); i > 0; i-- {
		clear = append(clear, 0x7f, 0x15)
	}
	paste := append(append(append([]byte{}, pasteStart...), clean...), pasteEnd...)
	f.later = append(f.later, clear, paste, key)
	f.clear()
	f.Notify("sec: sent with " + names(hits) + " as placeholders")
	return nil
}

// scrub rewrites a paste. If a value can't be secured, the paste is dropped
// entirely — never forwarded as-is.
func (f *Filter) scrub(text []byte) ([]byte, bool) {
	hits := detect.Find(string(text), f.Known)
	if len(hits) == 0 {
		return text, true
	}
	hits, err := f.Settle(hits, "paste")
	if err != nil {
		f.Notify("sec: paste dropped — it held a secret that could not be stored (" + err.Error() + ")")
		return nil, false
	}
	f.Notify("sec: paste sent with " + names(hits) + " as placeholders")
	return []byte(detect.Replace(string(text), hits)), true
}

// --- the mirror ---

func (f *Filter) insert(b []byte) {
	f.box = append(f.box[:f.cur], append(append([]byte{}, b...), f.box[f.cur:]...)...)
	f.cur += len(b)
	f.seen = append(f.seen, b...)
}

func (f *Filter) backspace() {
	if f.cur == 0 {
		return
	}
	_, n := utf8.DecodeLastRune(f.box[:f.cur])
	f.box = append(f.box[:f.cur-n], f.box[f.cur:]...)
	f.cur -= n
}

func (f *Filter) del() {
	if f.cur >= len(f.box) {
		return
	}
	_, n := utf8.DecodeRune(f.box[f.cur:])
	f.box = append(f.box[:f.cur], f.box[f.cur+n:]...)
}

func (f *Filter) left() {
	if f.cur > 0 {
		_, n := utf8.DecodeLastRune(f.box[:f.cur])
		f.cur -= n
	}
}

func (f *Filter) right() {
	if f.cur < len(f.box) {
		_, n := utf8.DecodeRune(f.box[f.cur:])
		f.cur += n
	}
}

func (f *Filter) home() {
	if i := bytes.LastIndexByte(f.box[:f.cur], '\n'); i >= 0 {
		f.cur = i + 1
	} else {
		f.cur = 0
	}
}

func (f *Filter) end() {
	if i := bytes.IndexByte(f.box[f.cur:], '\n'); i >= 0 {
		f.cur += i
	} else {
		f.cur = len(f.box)
	}
}

func (f *Filter) clear() {
	f.box, f.cur, f.unknown, f.seen = nil, 0, false, nil
}

func names(hits []detect.Hit) string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hits {
		if !seen[h.Name] {
			seen[h.Name] = true
			out = append(out, h.Name)
		}
	}
	return strings.Join(out, ", ")
}

// --- sequence parsing ---

const maxSeq = 4096

// mergedKeystroke decides, for a refused sequence, whether its final byte
// was really the human's keystroke completing a reply that lost its head —
// in which case that byte is re-fed so the mirror counts it — or part of a
// genuine reply whose shape just looks odd, in which case replaying it would
// corrupt the box (a `y` in the middle of "…2$y" is the reply's own final
// byte). Clean numeric params plus a final byte a real reply never uses is
// the signature of a merged keystroke: `ESC[?2m`, the `m` of "my key is".
func mergedKeystroke(seq []byte) []byte {
	if len(seq) < 4 || seq[1] != '[' { // short frames and non-CSI hold no keystroke
		return nil
	}
	body, final := seq[2:len(seq)-1], seq[len(seq)-1]
	if final < 0x20 || final == 0x7f || final == 0x1b {
		return nil
	}
	if len(body) > 0 {
		switch body[0] {
		case '<', '>', '?', '=':
			body = body[1:]
		}
	}
	for _, c := range body { // any intermediate ($, space…) or dirty byte:
		if (c < '0' || c > '9') && c != ':' && c != ';' { // the frame is a real
			return nil // reply with unusual shape — replay nothing
		}
	}
	return []byte{final}
}

// plausible reports whether a completed sequence has the shape of a reply or
// key this filter handles. It gates Feed's decision to hand a sequence to
// escape(): a completed sequence of any other shape is forwarded literally
// instead. That is what keeps a reply that lost its head across reads —
// `ESC[?2` from a DECRPM, finishing in the same chunk as the human's first
// keystroke — from eating that keystroke as its final byte: `ESC[?2m` is not
// a shape any terminal sends, so its bytes go through as typed.
func plausible(seq []byte) bool {
	if bytes.Equal(seq, pasteStart) || bytes.Equal(seq, pasteEnd) {
		return true
	}
	if seq[0] != 0x1b {
		return false
	}
	switch seq[1] {
	case 'P', '_', ']', '^', 'X': // DCS/APC/OSC/PM/SOS string sequences
		return true // terminated by ST/BEL — their internals are their own
	case 'O': // SS3: one final byte in the ASCII printable band
		return len(seq) == 3 && seq[2] >= 0x40 && seq[2] <= 0x7e
	case '[':
		return csiPlausible(seq[2:])
	}
	return true // ESC + one byte: Alt+letter, Alt+Enter
}

// csiPlausible validates a CSI body ("ESC [" stripped, final byte INCLUDED):
// an optional `< > ? =` prefix, then `;`-separated digits with `:` subparams,
// then a final byte whose meaning the prefix constrains. Replies are the
// frames that arrive unsolicited mid-typing, so their shape is checked hard:
// a `?`-reply ends in h/l/u/c/R/t (never a lowercase letter key like `m`),
// an SGR mouse reply in M/m. Anything else — `ESC[?2004m`, a DECRPM tail that
// swallowed the `m` of "my key is" — is refused and forwarded literally, so
// no keystroke is consumed as a sequence's final byte.
func csiPlausible(b []byte) bool {
	if len(b) == 0 {
		return false // "ESC [" alone is not a frame
	}
	params, final := b[:len(b)-1], b[len(b)-1]
	i := 0
	if len(params) > 0 {
		switch params[0] {
		case '<', '>', '?', '=':
			i = 1
		}
	}
	start := i
	for ; i < len(params); i++ {
		switch c := params[i]; {
		case c >= '0' && c <= '9' || c == ':':
		case c == ';':
			if i == start { // replies never send a leading `;`
				return false
			}
		default:
			return false
		}
	}
	if len(params) > 0 {
		switch params[0] {
		case '?': // replies to DA1 / DECRQM / kitty-flags / mode queries
			switch final {
			case 'h', 'l', 'u', 'c', 'R', 't':
				return true
			}
			return false
		case '<': // SGR mouse: press M, release m
			return final == 'M' || final == 'm'
		}
	}
	return final >= 0x40 && final <= 0x7e
}

// seqLen is the length of the escape sequence at b[0], or 0 if b ends before
// it does.
func seqLen(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	switch b[1] {
	case '[': // CSI: parameter bytes, intermediates, then a final in 0x40–0x7e
		for i := 2; i < len(b); i++ {
			switch c := b[i]; {
			case c >= 0x40 && c <= 0x7e:
				return i + 1
			case c < 0x20 || c > 0x7e:
				return i // malformed: end it here, the byte is its own event
			}
		}
		return 0
	case 'P', '_', ']', '^', 'X': // string sequences end with ST (ESC \) — OSC also with BEL
		for i := 2; i < len(b)-1; i++ {
			if b[i] == 0x1b && b[i+1] == '\\' {
				return i + 2
			}
			if b[1] == ']' && b[i] == 0x07 {
				return i + 1
			}
		}
		if len(b) >= maxSeq {
			return len(b)
		}
		return 0
	case 'O': // SS3: one more byte
		if len(b) < 3 {
			return 0
		}
		return 3
	}
	return 2 // ESC + one byte (Alt+key, Alt+Enter)
}

// csiU reads "code[:alt[:base]] [; mods[:event]]"; mods is 1 when absent.
func csiU(params []byte) (code, alt, mods int) {
	parts := bytes.SplitN(params, []byte{';'}, 3)
	keys := bytes.SplitN(parts[0], []byte{':'}, 3)
	code = atoi(keys[0])
	if len(keys) > 1 {
		alt = atoi(keys[1])
	}
	mods = 1
	if len(parts) > 1 {
		if m := atoi(bytes.SplitN(parts[1], []byte{':'}, 2)[0]); m > 0 {
			mods = m
		}
	}
	return code, alt, mods
}

func atoi(b []byte) int {
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// partialSuffix: how many trailing bytes of b could begin marker.
func partialSuffix(b, marker []byte) int {
	for n := len(marker) - 1; n > 0; n-- {
		if len(b) >= n && bytes.Equal(b[len(b)-n:], marker[:n]) {
			return n
		}
	}
	return 0
}

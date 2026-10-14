package agentpty

import (
	"errors"
	"strings"
	"testing"

	"github.com/muthuishere/secure-agent/internal/detect"
)

// Byte sequences below are the ones measured on stdin with Claude Code
// running in Ghostty (kitty keyboard flags 5, mouse ?1003, focus ?1004).
const (
	ghTok   = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	startup = "\x1b[I\x1bP>|ghostty 1.2.3-debug+abcdef\x1b\\\x1b[?5u\x1b[?62;22;52c\x1b[?2026;2$y" +
		"\x1b_Gi=31;OK\x1b\\\x1b[6;17;10t\x1b[?1016;2$y\x1b[?62;22;52c\x1b[O"
	mouse = "\x1b[<35;1;44M\x1b[<35;2;44M\x1b[<35;4;43M"
)

func newFilter(fail bool) (*Filter, *[]string, *[]string) {
	var stored, notes []string
	f := &Filter{Known: map[string]string{"DB_URL": "postgres://known-value-123"}}
	f.Settle = func(hits []detect.Hit, source string) ([]detect.Hit, error) {
		if fail {
			return hits, errors.New("vault locked")
		}
		for i, h := range hits {
			if !h.Known {
				stored = append(stored, h.Name+"/"+source)
				hits[i].Known = true
			}
		}
		return hits, nil
	}
	f.Notify = func(m string) { notes = append(notes, m) }
	return f, &stored, &notes
}

// feed sends chunks and gathers what the agent receives, Later steps included.
func feed(f *Filter, chunks ...string) string {
	var out []byte
	for _, c := range chunks {
		out = append(out, f.Feed([]byte(c))...)
		for _, step := range f.Later() {
			out = append(out, step...)
		}
	}
	return string(out)
}

// keys sends a string one keystroke per read, like a human.
func keys(f *Filter, s string) string {
	var out string
	for _, r := range s {
		out += feed(f, string(r))
	}
	return out
}

// rewritten checks a typed line was submitted only in its rewritten form. The
// raw keystrokes do reach the agent's box (the human has to see them); what
// must never happen is an Enter reaching the agent before the rewrite.
func rewritten(t *testing.T, got, clean, enter string) {
	t.Helper()
	noEnterBeforeRewrite(t, got)
	want := "\x15\x1b[200~" + clean + "\x1b[201~" + enter
	if !strings.HasSuffix(got, want) {
		t.Fatalf("rewrite steps\n got %q\nwant suffix %q", got, want)
	}
}

func noEnterBeforeRewrite(t *testing.T, got string) {
	t.Helper()
	i := strings.Index(got, "\x15")
	if i < 0 {
		t.Fatalf("no rewrite happened: %q", got)
	}
	before := got[:i]
	if strings.ContainsAny(before, "\r\n") || strings.Contains(before, "[13u") {
		t.Fatalf("an Enter reached the agent before the rewrite: %q", got)
	}
	if strings.Contains(got[i:], ghTok) {
		t.Fatalf("raw token in the rewrite: %q", got[i:])
	}
}

func TestStartupRepliesPassThroughAndTouchNothing(t *testing.T) {
	f, _, _ := newFilter(false)
	if got := feed(f, startup, mouse); got != startup+mouse {
		t.Fatalf("replies altered: %q", got)
	}
	if len(f.box) != 0 || f.unknown || len(f.seen) != 0 {
		t.Fatalf("replies touched the mirror: box=%q unknown=%v seen=%q", f.box, f.unknown, f.seen)
	}
}

// A reply split across reads ends in the same chunk as the human's first
// keystroke — the live failure, 2026-09-27: `ESC[?2` (head of a DECRPM reply)
// then "my key is …", so the `m` of "my" completed `ESC[?2m` and was eaten.
// No real `?`-reply ends in a letter key, so the fake frame must go through
// literally — every input byte intact, box untouched.
func TestSplittedReplyDoesNotEatTheNextKeystroke(t *testing.T) {
	f, _, _ := newFilter(false)
	got := feed(f, "\x1b[?2", "m", "y key is")
	// the literal frame goes out whole, the completing byte is then re-fed —
	// the agent's parser consumes ESC[?2m whole (eating its m), so the refed
	// m is what the box gains.
	if !strings.HasPrefix(got, "\x1b[?2m"+"my key is") {
		t.Fatalf("keystroke eaten by a merged reply: %q", got)
	}
	if string(f.box) != "my key is" {
		t.Fatalf("box = %q, want the typed line only", f.box)
	}
}

// Plain agent-side frames with no parameters at all — focus in/out — must
// still classify as sequences, not trip the malformed check.
func TestNoParamFramesStayClassified(t *testing.T) {
	f, _, _ := newFilter(false)
	if got := feed(f, "\x1b[I", "\x1b[O"); got != "\x1b[I\x1b[O" {
		t.Fatalf("focus frames altered: %q", got)
	}
	if len(f.box) != 0 || f.unknown {
		t.Fatalf("focus touched the mirror: unknown=%v", f.unknown)
	}
}

func TestRepliesSplitAcrossReads(t *testing.T) {
	f, _, _ := newFilter(false)
	dcs := "\x1bP>|ghostty 1.2.3\x1b\\"
	got := feed(f, dcs[:5], dcs[5:12], dcs[12:])
	if got != dcs || len(f.box) != 0 {
		t.Fatalf("split DCS: got %q box=%q", got, f.box)
	}
}

func TestTypedTokenRewrittenAtEnter(t *testing.T) {
	f, stored, _ := newFilter(false)
	feed(f, startup)
	got := keys(f, "key is "+ghTok) + feed(f, mouse, "\r")
	rewritten(t, got, "key is {{GITHUB_TOKEN}}", "\r")
	if len(*stored) != 1 || (*stored)[0] != "GITHUB_TOKEN/typed" {
		t.Fatalf("stored %v", *stored)
	}
}

func TestKittyEnterIsSubmit(t *testing.T) {
	f, _, _ := newFilter(false)
	got := keys(f, "a "+ghTok) + feed(f, "\x1b[13u")
	rewritten(t, got, "a {{GITHUB_TOKEN}}", "\x1b[13u")
}

func TestShiftEnterMultiLine(t *testing.T) {
	f, _, _ := newFilter(false)
	got := keys(f, "line one") + feed(f, "\x1b[13;2u") + keys(f, "line two "+ghTok) + feed(f, "\r")
	noEnterBeforeRewrite(t, got)
	want := "\x15\x7f\x15\x1b[200~line one\nline two {{GITHUB_TOKEN}}\x1b[201~\r"
	if !strings.HasSuffix(got, want) {
		t.Fatalf("multi-line rewrite: %q", got)
	}
}

func TestBackspaceAndCursorEditsAreMirrored(t *testing.T) {
	f, _, _ := newFilter(false)
	keys(f, "tok "+ghTok+"XX")
	feed(f, "\x7f", "\x7f")               // drop XX
	feed(f, "\x1b[H")                     // home
	keys(f, "my ")                        // insert at start
	feed(f, "\x1b[F", "\x1b[D", "\x1b[D") // end, left twice
	keys(f, "Z")                          // insert inside the token → not a token any more
	feed(f, "\x1b[3~")                    // delete the char after the cursor
	if want := "my tok " + ghTok[:len(ghTok)-2] + "Z" + ghTok[len(ghTok)-1:]; string(f.box) != want {
		t.Fatalf("mirror\n got %q\nwant %q", f.box, want)
	}
	if f.unknown {
		t.Fatal("cursor keys must not make the mirror unknown")
	}
}

func TestHistoryNavigationFailsClosed(t *testing.T) {
	f, _, notes := newFilter(false)
	keys(f, "secret "+ghTok)
	feed(f, "\x1b[A") // Up: prompt history replaces the box — contents now unknown
	got := feed(f, "\r")
	if strings.Contains(got, "\r") || !strings.HasSuffix(got, "\x15") {
		t.Fatalf("unknown box with a secret must clear, not submit: %q", got)
	}
	if len(*notes) == 0 || !strings.Contains((*notes)[0], "GITHUB_TOKEN") {
		t.Fatalf("human not told: %v", *notes)
	}
	// and a clean unknown line still goes through
	f2, _, _ := newFilter(false)
	keys(f2, "hello")
	feed(f2, "\x1b[A")
	if got := feed(f2, "\r"); got != "\r" {
		t.Fatalf("clean unknown line altered: %q", got)
	}
}

func TestEscWithSecretBecomesCtrlU(t *testing.T) {
	f, _, _ := newFilter(false)
	keys(f, "x "+ghTok)
	if got := feed(f, "\x1b[27u"); got != "\x15" {
		t.Fatalf("Esc must become Ctrl-U when the box holds a secret: %q", got)
	}
	if len(f.box) != 0 || len(f.seen) != 0 {
		t.Fatal("mirror not cleared")
	}
	f2, _, _ := newFilter(false)
	keys(f2, "plain")
	if got := feed(f2, "\x1b[27u"); got != "\x1b[27u" {
		t.Fatalf("Esc on a clean box must pass: %q", got)
	}
}

func TestCtrlKeysClearTheMirror(t *testing.T) {
	for _, k := range []string{"\x15", "\x03", "\x1b[117;5u", "\x1b[99;5u"} {
		f, _, _ := newFilter(false)
		keys(f, "a "+ghTok)
		if got := feed(f, k); got != k || len(f.box) != 0 || len(f.seen) != 0 {
			t.Fatalf("%q: got %q box=%q", k, got, f.box)
		}
		if got := keys(f, "clean") + feed(f, "\r"); got != "clean\r" {
			t.Fatalf("%q: line after clear altered: %q", k, got)
		}
	}
}

func TestPasteRewrittenBeforeForwarding(t *testing.T) {
	f, stored, _ := newFilter(false)
	got := feed(f, "use \x1b[200~token "+ghTok+" ok\x1b[201~")
	if strings.Contains(got, ghTok) || got != "use \x1b[200~token {{GITHUB_TOKEN}} ok\x1b[201~" {
		t.Fatalf("paste: %q", got)
	}
	if len(*stored) != 1 || (*stored)[0] != "GITHUB_TOKEN/paste" {
		t.Fatalf("stored %v", *stored)
	}
	// the box now holds the placeholder, so Enter goes straight through
	if got := feed(f, "\r"); got != "\r" {
		t.Fatalf("enter after clean paste: %q", got)
	}
}

func TestPasteSplitAcrossReads(t *testing.T) {
	f, _, _ := newFilter(false)
	half := len(ghTok) / 2
	got := feed(f, "\x1b[20", "0~x "+ghTok[:half], ghTok[half:]+"\x1b[2", "01~")
	if strings.Contains(got, ghTok) || !strings.Contains(got, "{{GITHUB_TOKEN}}") {
		t.Fatalf("split paste: %q", got)
	}
}

func TestKnownVaultValueUsesExistingName(t *testing.T) {
	f, stored, _ := newFilter(false)
	got := feed(f, "\x1b[200~postgres://known-value-123\x1b[201~")
	if !strings.Contains(got, "{{DB_URL}}") || len(*stored) != 0 {
		t.Fatalf("got %q stored %v", got, *stored)
	}
}

func TestVaultFailureFailsClosed(t *testing.T) {
	f, _, notes := newFilter(true)
	if got := feed(f, "\x1b[200~"+ghTok+"\x1b[201~"); got != "" {
		t.Fatalf("paste must be dropped when the vault fails: %q", got)
	}
	f2, _, _ := newFilter(true)
	keys(f2, "x "+ghTok)
	if got := feed(f2, "\r"); got != "\x15" {
		t.Fatalf("enter must clear, not submit: %q", got)
	}
	if len(*notes) == 0 {
		t.Fatal("no notice on failure")
	}
}

func TestCleanInputIsByteExact(t *testing.T) {
	f, _, _ := newFilter(false)
	in := startup + "fix the \x1b[Dbug\x7f please\x1b[13;2umore\x1b[<35;3;3M\r"
	if got := feed(f, in); got != in {
		t.Fatalf("clean input changed:\n got %q\nwant %q", got, in)
	}
}

func TestLoneEscFlushesAsEscKey(t *testing.T) {
	f, _, _ := newFilter(false)
	if got := feed(f, "\x1b"); got != "" || !f.Pending() {
		t.Fatalf("lone ESC must be held: %q", got)
	}
	if got := string(f.Flush()); got != "\x1b" {
		t.Fatalf("flush: %q", got)
	}
	// held ESC followed by the rest of a CSI joins up
	f2, _, _ := newFilter(false)
	if got := feed(f2, "\x1b", "[D"); got != "\x1b[D" {
		t.Fatalf("split CSI: %q", got)
	}
}

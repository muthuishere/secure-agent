//go:build !windows

package agentpty

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	gopty "github.com/aymanbagabas/go-pty"

	"github.com/muthuishere/secure-agent/internal/detect"
)

// TestRunThroughRealPty drives Run the way a terminal would: an outer pty
// stands in for the terminal, a raw-mode `head` stands in for the agent and
// records every byte it is given, exiting once it has the expected count. It
// proves the plumbing end to end — raw mode, pacing, paste, replies — not
// just the filter's arithmetic.
func TestRunThroughRealPty(t *testing.T) {
	if _, err := exec.LookPath("stty"); err != nil {
		t.Skip("no stty")
	}
	outer, err := gopty.New()
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer outer.Close()
	u, ok := outer.(gopty.UnixPty)
	if !ok {
		t.Skip("not a unix pty")
	}

	// What the agent must receive, byte for byte: the replies, the raw
	// keystrokes (that is how the human sees them in the box), then the
	// rewrite in place of the first Enter, then a paste already scrubbed.
	want := startup + "token " + ghTok +
		"\x15\x1b[200~token {{GITHUB_TOKEN}}\x1b[201~\r" +
		"\x1b[200~pasted {{GITHUB_TOKEN}} here\x1b[201~clean line\r"

	rec := filepath.Join(t.TempDir(), "rec")
	f := &Filter{Known: map[string]string{}}
	f.Settle = func(hits []detect.Hit, source string) ([]detect.Hit, error) {
		for i := range hits {
			hits[i].Known = true
		}
		return hits, nil
	}
	done := make(chan int, 1)
	go func() {
		code, _ := Run(f, os.Environ(), "sh",
			[]string{"-c", fmt.Sprintf("stty raw -echo; head -c %d > %s", len(want), rec)},
			u.Slave(), u.Slave())
		done <- code
	}()
	m := u.Master()
	time.Sleep(400 * time.Millisecond) // agent up and in raw mode

	send := func(s string) { m.Write([]byte(s)); time.Sleep(20 * time.Millisecond) }
	send(startup)
	for _, r := range "token " + ghTok {
		send(string(r))
	}
	send("\r")
	time.Sleep(3*stepGap + 200*time.Millisecond)
	send("\x1b[200~pasted " + ghTok + " here\x1b[201~")
	send("clean line\r")
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		got, _ := os.ReadFile(rec)
		t.Fatalf("agent never got the full expected stream; has %d of %d bytes: %q", len(got), len(want), got)
	}
	got, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("agent received\n got %q\nwant %q", got, want)
	}
}

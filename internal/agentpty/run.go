package agentpty

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"

	gopty "github.com/aymanbagabas/go-pty"
	"golang.org/x/term"
)

// stepGap lets the agent's TUI finish handling one step of a rewrite before
// the next arrives; without it Ink merges them and mangles the line.
const stepGap = 150 * time.Millisecond

// escWait is how long a lone ESC is held before it counts as the Esc key.
const escWait = 40 * time.Millisecond

// Run starts name+args in a pty wired to the terminal on stdin/stdout, with
// every input byte passed through f. It returns the agent's exit code.
func Run(f *Filter, env []string, name string, args []string, stdin, stdout *os.File) (int, error) {
	in, out := int(stdin.Fd()), int(stdout.Fd())
	if !term.IsTerminal(in) {
		return 1, errors.New("sec agent needs an interactive terminal")
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return 127, err
	}
	p, err := gopty.New()
	if err != nil {
		return 1, err
	}
	defer p.Close()
	if w, h, err := term.GetSize(out); err == nil {
		p.Resize(w, h)
	}
	cmd := p.Command(path, args...)
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	state, err := term.MakeRaw(in)
	if err != nil {
		return 1, err
	}
	defer term.Restore(in, state)

	stop := watchResize(out, p)
	defer stop()

	// Output and notices share stdout; a notice must not land mid-sequence.
	var outMu sync.Mutex
	f.Notify = func(msg string) {
		outMu.Lock()
		defer outMu.Unlock()
		// OSC 9 and OSC 777 raise a desktop notification (Ghostty, iTerm,
		// Windows Terminal, kitty); the bell covers terminals that ignore both.
		stdout.WriteString("\x1b]9;" + msg + "\x07\x1b]777;notify;sec;" + msg + "\x07\a")
	}
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := p.Read(buf)
			if n > 0 {
				for _, m := range modeRe.FindAll(buf[:n], -1) {
					trace("mode", m)
				}
				outMu.Lock()
				stdout.Write(buf[:n])
				outMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		var mu sync.Mutex // f and the pty writer are shared with the ESC timer
		var escTimer *time.Timer
		write := func(b []byte) bool {
			if len(b) == 0 {
				return true
			}
			_, werr := p.Write(b)
			return werr == nil
		}
		buf := make([]byte, 4096)
		for {
			n, err := stdin.Read(buf)
			if n > 0 {
				mu.Lock()
				if escTimer != nil {
					escTimer.Stop()
				}
				trace("in ", buf[:n])
				b := f.Feed(buf[:n])
				trace("out", b)
				ok := write(b)
				for _, step := range f.Later() {
					time.Sleep(stepGap)
					trace("step", step)
					ok = ok && write(step)
				}
				if f.Pending() {
					escTimer = time.AfterFunc(escWait, func() {
						mu.Lock()
						defer mu.Unlock()
						b := f.Flush()
						trace("flush", b)
						write(b)
					})
				}
				mu.Unlock()
				if !ok {
					return
				}
			}
			if err != nil {
				// the terminal went away: hang up the agent as a real tty would
				p.Close()
				return
			}
		}
	}()
	err = cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// modeRe matches the agent turning terminal modes on/off: DEC private modes
// (?1000h mouse, ?1004h focus, ?2004h bracketed paste…) and kitty keyboard
// flag push/pop/set (>Nu, <u, =N;Nu).
var modeRe = regexp.MustCompile(`\x1b\[(?:\?[0-9;]+[hl]|>[0-9;]*u|<[0-9]*u|=[0-9;]+u)`)

// trace writes what crossed the filter to $SEC_AGENT_TRACE for debugging.
// Only escape-sequence bytes are shown; every other byte is masked, so a
// secret can never land in the trace.
func trace(tag string, b []byte) {
	path := os.Getenv("SEC_AGENT_TRACE")
	if path == "" || len(b) == 0 {
		return
	}
	m := make([]byte, 0, len(b)*2)
	inEsc := false
	for _, c := range b {
		switch {
		case c == 0x1b:
			m, inEsc = append(m, "<ESC>"...), true
		case c < 0x20 || c == 0x7f:
			m, inEsc = append(m, fmt.Sprintf("<%02x>", c)...), false
		case inEsc:
			m = append(m, c)
			if c >= 0x40 && c <= 0x7e && c != '[' {
				inEsc = false
			}
		default:
			m = append(m, '.')
		}
	}
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	fmt.Fprintf(fh, "%s %s %s\n", time.Now().Format("15:04:05.000"), tag, m)
}

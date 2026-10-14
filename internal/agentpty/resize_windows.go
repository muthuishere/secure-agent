//go:build windows

package agentpty

import (
	"time"

	gopty "github.com/aymanbagabas/go-pty"
	"golang.org/x/term"
)

// Windows has no SIGWINCH; poll the console size instead.
func watchResize(fd int, p gopty.Pty) func() {
	done := make(chan struct{})
	go func() {
		lw, lh := 0, 0
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if w, h, err := term.GetSize(fd); err == nil && (w != lw || h != lh) {
					lw, lh = w, h
					p.Resize(w, h)
				}
			}
		}
	}()
	return func() { close(done) }
}

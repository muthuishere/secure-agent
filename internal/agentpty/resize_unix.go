//go:build !windows

package agentpty

import (
	"os"
	"os/signal"
	"syscall"

	gopty "github.com/aymanbagabas/go-pty"
	"golang.org/x/term"
)

func watchResize(fd int, p gopty.Pty) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if w, h, err := term.GetSize(fd); err == nil {
				p.Resize(w, h)
			}
		}
	}()
	return func() { signal.Stop(ch); close(ch) }
}

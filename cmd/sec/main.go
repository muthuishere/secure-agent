// sec — a credentials broker for humans and their agents.
package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/muthuishere/secure-agent/internal/cli"
)

func main() {
	// Run as the agent's shell (a link named sec-sh-<shell>), every argument
	// belongs to the shell: `sec-sh-zsh -c -l 'cmd'` is `sec sh -c -l 'cmd'`.
	if strings.HasPrefix(filepath.Base(os.Args[0]), cli.ShellLinkPrefix) {
		os.Exit(cli.Main(append([]string{"sh"}, os.Args[1:]...)))
	}
	os.Exit(cli.Main(os.Args[1:]))
}

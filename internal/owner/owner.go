// Package owner decides whether the caller is the human owner or an agent.
//
// The rule is deliberately dumb: an interactive terminal on stdin, or an
// explicit SEC_OWNER=1, means owner. Agent harnesses run commands with a
// piped stdin and never set the variable, so every verb that would emit a
// plaintext value is unavailable to them by construction.
package owner

import (
	"os"

	"golang.org/x/term"
)

func IsOwner() bool {
	if os.Getenv("SEC_OWNER") == "1" {
		return true
	}
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// Agent names the caller for the audit log. Harnesses are detected from the
// env they export; SEC_AGENT overrides.
func Agent() string {
	if a := os.Getenv("SEC_AGENT"); a != "" {
		return a
	}
	switch {
	case os.Getenv("CLAUDECODE") != "" || os.Getenv("CLAUDE_CODE_ENTRYPOINT") != "":
		return "claude-code"
	case os.Getenv("CODEX_SANDBOX") != "" || os.Getenv("CODEX_THREAD_ID") != "":
		return "codex"
	case os.Getenv("CURSOR_AGENT") != "":
		return "cursor"
	case IsOwner():
		return "owner"
	}
	return "unknown"
}

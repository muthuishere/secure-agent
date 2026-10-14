package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/policy"
	"github.com/muthuishere/secure-agent/internal/redact"
)

func init() {
	register("sh", "sh [shell args] — a shell for agents: refuses secret-file reads, fills {{NAME}}, redacts all output", cmdSh)
}

// ShellLinkPrefix is the name `sec agent` gives the link it sets as the
// agent's SHELL. Invoked under a name starting with it, sec behaves as `sec
// sh`; the rest of the name says which real shell to run (sec-sh-zsh → zsh).
// Agents that only accept bash or zsh as their shell see a name containing one.
const ShellLinkPrefix = "sec-sh"

// placeholder matches {{NAME}} in a command string.
var placeholder = regexp.MustCompile(`\{\{\s*([A-Z][A-Z0-9_]*)\s*\}\}`)

// cmdSh is what an agent's shell tool calls instead of bash/zsh: it takes the
// same arguments (`-c 'cmd'`, `-l`, a script path…) and passes them to the
// real shell, with three changes. A command that would print a secret file is
// refused. {{NAME}} becomes "$NAME", the value going in as that one child's
// env var — never pasted into the command text, so a quote in a value cannot
// break out. And everything the command prints is redacted against the vault,
// every dotenv file in the tree, and credential-named env vars.
func cmdSh(args []string) error {
	real := realShell()
	cmdIdx := commandArg(args)
	cmd := ""
	if cmdIdx >= 0 {
		cmd = args[cmdIdx]
	}
	if cmd == "" { // interactive or script use: nothing to vet, just redact
		return runShell(real, args, nil)
	}
	s, _ := open() // no vault still gets the file guard and dotenv/env redaction
	ag := owner.Agent()
	if r := policy.CheckCommand(cmd); r != nil {
		if s != nil {
			s.Audit("sh.refuse", ag, nil, map[string]string{"file": r.File, "verb": r.Verb})
		}
		fmt.Fprintln(os.Stderr, r.Error())
		return exitCode(126)
	}
	extra := map[string]string{}
	if names := placeholderNames(cmd); len(names) > 0 {
		if s == nil {
			return fmt.Errorf("the command uses {{%s}} but the vault is not available", names[0])
		}
		vals, err := s.Resolve(names)
		if err != nil {
			return err
		}
		for n, v := range vals {
			extra[n] = v
		}
		args = append([]string{}, args...)
		args[cmdIdx] = placeholder.ReplaceAllString(cmd, varRef(real, "$1"))
	}
	if s != nil { // every command an agent runs is on record — its length, never its text
		s.Audit("sh.run", ag, placeholderNames(cmd), map[string]string{"len": fmt.Sprint(len(cmd))})
	}
	return runShell(real, args, extra)
}

func runShell(real string, args []string, extra map[string]string) error {
	var vault map[string]string
	if s, err := open(); err == nil {
		if names, err := s.List(); err == nil {
			vault, _ = s.Resolve(names)
		}
	}
	cwd, _ := os.Getwd()
	values := policy.RedactionSet(vault, cwd)
	for n, v := range extra {
		values[n] = v
	}
	c := exec.Command(real, args...)
	c.Env = os.Environ()
	for k, v := range extra {
		c.Env = append(c.Env, k+"="+v)
	}
	out := redact.New(os.Stdout, values)
	errw := redact.New(os.Stderr, values)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, out, errw
	err := c.Run()
	out.Flush()
	errw.Flush()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return exitCode(ee.ExitCode())
	}
	return err
}

// realShell is the shell sec sh stands in for: named by the link it was
// invoked through, else SEC_REAL_SHELL, else the platform's usual one.
func realShell() string {
	base := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	if strings.HasPrefix(base, ShellLinkPrefix+"-") {
		if p, err := exec.LookPath(strings.TrimPrefix(base, ShellLinkPrefix+"-")); err == nil {
			return p
		}
	}
	if s := os.Getenv("SEC_REAL_SHELL"); s != "" {
		return s
	}
	if runtime.GOOS == "windows" {
		for _, s := range []string{"pwsh", "powershell", "bash"} {
			if p, err := exec.LookPath(s); err == nil {
				return p
			}
		}
		return os.Getenv("COMSPEC")
	}
	for _, s := range []string{"bash", "sh"} {
		if p, err := exec.LookPath(s); err == nil {
			return p
		}
	}
	return "/bin/sh"
}

// commandArg finds the command string in a shell argv: the argument after
// -c (or PowerShell's -Command / cmd's /c), wherever the other flags sit —
// agents send `-c -l cmd` as well as `-l -c cmd`.
func commandArg(args []string) int {
	for i, a := range args {
		switch strings.ToLower(a) {
		case "-c", "-command", "/c":
			for j := i + 1; j < len(args); j++ {
				if !strings.HasPrefix(args[j], "-") {
					return j
				}
			}
		}
	}
	return -1
}

func placeholderNames(cmd string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range placeholder.FindAllStringSubmatch(cmd, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// varRef is how the real shell reads an env var inside a command string.
func varRef(shell, name string) string {
	b := strings.ToLower(filepath.Base(shell))
	switch {
	case strings.Contains(b, "pwsh"), strings.Contains(b, "powershell"):
		return "$env:" + name
	case strings.HasPrefix(b, "cmd"):
		return "%" + name + "%"
	}
	return `"${` + name + `}"`
}

// Package execx runs child processes with secrets filled in, and scrubs the
// values (and their encodings) out of everything the child prints.
package execx

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/muthuishere/secure-agent/internal/redact"
	"github.com/muthuishere/secure-agent/internal/tmpl"
)

// outputOnly are commands whose whole job is to print their input. A
// placeholder in their argv is an exfiltration, not a use.
var outputOnly = map[string]bool{
	"echo": true, "printf": true, "cat": true, "env": true, "printenv": true,
	"set": true, "export": true, "tee": true, "xxd": true, "od": true, "base64": true,
}

// FillArgv substitutes placeholders into an argv array — never a shell string,
// so quoting in values cannot break out.
func FillArgv(argv []string, values map[string]string) ([]string, error) {
	out := make([]string, len(argv))
	for i, a := range argv {
		f, err := tmpl.Fill(a, values)
		if err != nil {
			return nil, err
		}
		out[i] = f
	}
	return out, nil
}

// CheckArgv refuses templates that only print the secret.
func CheckArgv(argv []string, allowUnsafe bool) error {
	if len(argv) == 0 {
		return errors.New("no command given after --")
	}
	if allowUnsafe {
		return nil
	}
	hasPH := false
	for _, a := range argv {
		if tmpl.Has(a) {
			hasPH = true
			break
		}
	}
	if hasPH && outputOnly[filepath.Base(argv[0])] {
		return fmt.Errorf("refusing: %s only prints its input — that would expose the secret. Use it in a real command, or ask the owner", argv[0])
	}
	return nil
}

// Run executes argv with extra env, redacting stdout/stderr against values.
// Returns the child's exit code.
func Run(argv []string, extraEnv map[string]string, values map[string]string) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = os.Environ()
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out := redact.New(os.Stdout, values)
	errw := redact.New(os.Stderr, values)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = errw
	err := cmd.Run()
	out.Flush()
	errw.Flush()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 127, fmt.Errorf("%s: %w", argv[0], err)
	}
	return 0, nil
}

// RunScript renders a template file to a 0700 temp file and executes it
// (via its shebang, or sh if none), then removes it.
func RunScript(path string, args []string, values map[string]string) (int, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return 1, err
	}
	filled, err := tmpl.Fill(string(body), values)
	if err != nil {
		return 1, err
	}
	dir, err := os.MkdirTemp("", "sec-exec-")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(dir)
	tmp := filepath.Join(dir, filepath.Base(path))
	if err := os.WriteFile(tmp, []byte(filled), 0o700); err != nil {
		return 1, err
	}
	argv := []string{tmp}
	if !strings.HasPrefix(filled, "#!") {
		argv = []string{"sh", tmp}
	}
	return Run(append(argv, args...), nil, values)
}

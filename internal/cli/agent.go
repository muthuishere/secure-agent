package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/muthuishere/secure-agent/internal/agentpty"
	"github.com/muthuishere/secure-agent/internal/detect"
	"github.com/muthuishere/secure-agent/internal/store"
)

func init() {
	register("agent", "agent <claude|devin|…> [args] — run an agent with every paste and Enter checked for secrets first", cmdAgent)
}

// sec agent: the human's keyboard goes through sec before it reaches the
// agent. A secret pasted or typed is stored in the vault and the agent gets
// {{NAME}} — the value never enters the model, the transcript or history.
// Everything after the agent name is passed to it untouched (--yolo etc.).
func cmdAgent(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sec agent <agent> [agent args…]   e.g. sec agent claude --dangerously-skip-permissions")
	}
	// Fail closed: without a vault a captured value would have nowhere to go.
	s, err := open()
	if err != nil {
		return fmt.Errorf("%w — sec agent will not start without a working vault", err)
	}
	names, err := s.List()
	if err != nil {
		return err
	}
	known, err := s.Resolve(names)
	if err != nil {
		return err
	}
	agent := filepath.Base(args[0])
	f := &agentpty.Filter{Known: known}
	f.Settle = func(hits []detect.Hit, source string) ([]detect.Hit, error) {
		return settle(s, f.Known, agent, source, hits)
	}
	env, extra, cleanup, err := guardAgent(agent)
	if err != nil {
		return err
	}
	defer cleanup()
	s.Audit("agent.start", agent, nil, map[string]string{"args": fmt.Sprint(len(args) - 1), "guards": guards(agent)})
	code, err := agentpty.Run(f, env, args[0], append(extra, args[1:]...), os.Stdin, os.Stdout)
	s.Audit("agent.exit", agent, nil, map[string]string{"code": fmt.Sprint(code)})
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCode(code)
	}
	return nil
}

// settle gives every hit its final name, storing values the vault has not
// seen. A name already holding a different value is never overwritten; the
// new value gets NAME_2, NAME_3…
func settle(s *store.Store, known map[string]string, agent, source string, hits []detect.Hit) ([]detect.Hit, error) {
	var captured, sealed []string
	for i, h := range hits {
		if h.Known {
			sealed = append(sealed, h.Name)
			continue
		}
		if n, ok := nameFor(known, h.Value); ok { // captured earlier this session
			hits[i].Name, hits[i].Known = n, true
			sealed = append(sealed, n)
			continue
		}
		name := h.Name
		if store.ValidName(name) != nil {
			name = "CAPTURED_SECRET"
		}
		base := name
		for n := 2; s.Exists(name) || known[name] != ""; n++ {
			name = fmt.Sprintf("%s_%d", base, n)
		}
		if _, err := s.Set(name, []byte(h.Value), "captured by sec agent ("+source+")"); err != nil {
			return hits, err
		}
		known[name] = h.Value
		hits[i].Name = name
		captured = append(captured, name+"("+h.Kind+")")
	}
	if len(captured) > 0 {
		s.Audit("agent.capture", agent, names(captured), map[string]string{"source": source, "kinds": strings.Join(captured, ",")})
	}
	if len(sealed) > 0 {
		s.Audit("agent.seal", agent, sealed, map[string]string{"source": source})
	}
	return hits, nil
}

func nameFor(known map[string]string, v string) (string, bool) {
	for n, kv := range known {
		if kv == v {
			return n, true
		}
	}
	return "", false
}

// names strips the "(kind)" suffix settle adds for the audit fields.
func names(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x[:strings.IndexByte(x, '(')]
	}
	return out
}

// guardAgent sets up the two guards that sit behind the agent: its shell
// becomes `sec sh` (a link named sec-sh-<real shell>), and — for agents whose
// hook protocol sec speaks — `sec hook` runs before every tool call, wired in
// for this session only. It returns the agent's env, extra leading args, and
// a cleanup for anything it created.
func guardAgent(agent string) (env, extra []string, cleanup func(), err error) {
	cleanup = func() {}
	self, err := os.Executable()
	if err != nil {
		return nil, nil, cleanup, err
	}
	real := os.Getenv("SHELL")
	if real == "" {
		real = realShell()
	}
	link, err := shellLink(self, real)
	if err != nil {
		return nil, nil, cleanup, fmt.Errorf("could not set up sec sh as the agent's shell: %w", err)
	}
	env = append(os.Environ(),
		"SEC_AGENT_WRAPPED="+agent,
		"SEC_REAL_SHELL="+real,
		"SHELL="+link,
		"CLAUDE_CODE_SHELL="+link,
	)
	if agent == "claude" {
		settings, _ := json.Marshal(map[string]any{
			"hooks": map[string]any{
				"PreToolUse": []any{map[string]any{
					"matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|NotebookRead|Grep|Glob",
					"hooks":   []any{map[string]any{"type": "command", "command": quoteArg(self) + " hook --client claude"}},
				}},
			},
		})
		f, err := os.CreateTemp("", "sec-agent-settings-*.json")
		if err != nil {
			return nil, nil, cleanup, err
		}
		f.Write(settings)
		f.Close()
		cleanup = func() { os.Remove(f.Name()) }
		extra = []string{"--settings", f.Name()}
	}
	return env, extra, cleanup, nil
}

// shellLink returns a path that runs sec as `sec sh` for the given real
// shell: <dir of sec>/sec-sh-<zsh|bash|…>, created on first use. Its name
// keeps the real shell's name in it, for agents that only accept bash/zsh.
func shellLink(self, real string) (string, error) {
	name := ShellLinkPrefix + "-" + strings.TrimSuffix(filepath.Base(real), ".exe")
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, dir := range []string{filepath.Dir(self), filepath.Join(os.TempDir(), "sec-bin")} {
		link := filepath.Join(dir, name)
		if target, err := os.Readlink(link); err == nil && target == self {
			return link, nil
		}
		os.MkdirAll(dir, 0o755)
		os.Remove(link)
		if err := os.Symlink(self, link); err == nil {
			return link, nil
		}
		if err := os.Link(self, link); err == nil { // Windows without symlink rights
			return link, nil
		}
	}
	return "", fmt.Errorf("no writable place for %s", name)
}

func quoteArg(s string) string {
	if strings.ContainsAny(s, " '\"") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

// guards names what guardAgent put behind this agent, for the audit line.
func guards(agent string) string {
	if agent == "claude" {
		return "pty,sh,hook"
	}
	return "pty,sh"
}

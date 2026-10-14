package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/muthuishere/secure-agent/internal/execx"
	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/place"
	"github.com/muthuishere/secure-agent/internal/store"
	"github.com/muthuishere/secure-agent/internal/tmpl"
)

func init() {
	register("exec", "run a command/script with {{NAME}} placeholders filled; output scrubbed", cmdExec)
	register("run", "run a command with NAME[,NAME] injected as env vars; output scrubbed", cmdRun)
	register("render", "fill a template file with secrets → 0600 output; placement recorded", cmdRender)
}

func cmdExec(args []string) error {
	fs := flags("exec")
	file := fs.String("f", "", "script/template file to render and execute (args after -- are passed to it)")
	unsafe := fs.Bool("allow-output-only", false, "owner-only: allow echo/cat/env style commands")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *unsafe {
		if err := requireOwner("--allow-output-only"); err != nil {
			return err
		}
	}
	s, err := open()
	if err != nil {
		return err
	}
	ag := owner.Agent()
	if *file != "" {
		body, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		names := tmpl.NamesIn(append([]string{string(body)}, rest...)...)
		vals, err := s.Resolve(names)
		if err != nil {
			return err
		}
		filledArgs, err := execx.FillArgv(rest, vals)
		if err != nil {
			return err
		}
		s.Audit("exec.file", ag, names, map[string]string{"file": *file})
		code, err := execx.RunScript(*file, filledArgs, vals)
		if err != nil {
			return err
		}
		if code != 0 {
			return exitCode(code)
		}
		return nil
	}
	if err := execx.CheckArgv(rest, *unsafe); err != nil {
		return err
	}
	names := tmpl.NamesIn(rest...)
	if len(names) == 0 {
		return fmt.Errorf("no {{NAME}} placeholders in the command — nothing to fill (use `sec run` for env injection)")
	}
	vals, err := s.Resolve(names)
	if err != nil {
		return err
	}
	argv, err := execx.FillArgv(rest, vals)
	if err != nil {
		return err
	}
	s.Audit("exec", ag, names, map[string]string{"cmd": redactTemplate(strings.Join(rest, " "))})
	code, err := execx.Run(argv, nil, vals)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCode(code)
	}
	return nil
}

// redactTemplate keeps the audit line short and free of anything that is not
// the template the caller wrote (placeholders are names, so safe).
func redactTemplate(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

func cmdRun(args []string) error {
	rest := args // no flags: the spec is positional; the command follows it (-- optional)
	if len(rest) >= 2 && rest[1] == "--" {
		rest = append(rest[:1:1], rest[2:]...)
	}
	if len(rest) < 2 {
		return fmt.Errorf("usage: sec run NAME[,NAME2][=ENVVAR] cmd args…")
	}
	rest = append(rest[:1:1], append([]string{"--"}, rest[1:]...)...)
	env := map[string]string{} // ENVVAR -> secret name
	var names []string
	for _, spec := range splitList(rest[0]) {
		n, v, ok := strings.Cut(spec, "=")
		if !ok {
			v = n
		}
		env[v] = n
		names = append(names, n)
	}
	s, err := open()
	if err != nil {
		return err
	}
	vals, err := s.Resolve(names)
	if err != nil {
		return err
	}
	extra := map[string]string{}
	for v, n := range env {
		extra[v] = vals[n]
	}
	s.Audit("run", owner.Agent(), names, map[string]string{"cmd": redactTemplate(strings.Join(rest[2:], " "))})
	code, err := execx.Run(rest[2:], extra, vals)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCode(code)
	}
	return nil
}

func cmdRender(args []string) error {
	fs := flags("render")
	out := fs.String("out", "", "output path (0600)")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || *out == "" {
		return fmt.Errorf("usage: sec render TEMPLATE --out FILE")
	}
	s, err := open()
	if err != nil {
		return err
	}
	body, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	names := tmpl.Names(string(body))
	if len(names) == 0 {
		return fmt.Errorf("no {{NAME}} placeholders in %s", rest[0])
	}
	if err := place.Render(rest[0], *out, s.Resolve); err != nil {
		return err
	}
	for _, n := range names {
		m, err := s.Meta(n)
		if err != nil {
			continue
		}
		m.AddPlacement(store.Placement{Type: "render", Template: rest[0], Path: *out})
		s.SaveMeta(m)
	}
	s.Audit("render", owner.Agent(), names, map[string]string{"template": rest[0], "out": *out})
	fmt.Printf("✓ rendered %s → %s (0600; %d secret(s), placement recorded)\n", rest[0], *out, len(names))
	return nil
}

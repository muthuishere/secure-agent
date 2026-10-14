// Package place knows where a secret's value has been put, and how to put
// the current value there again. This is what makes rotation a single verb.
package place

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/muthuishere/secure-agent/internal/bundle"
	"github.com/muthuishere/secure-agent/internal/envfile"
	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/store"
	"github.com/muthuishere/secure-agent/internal/tmpl"
)

type Result struct {
	Placement store.Placement
	Err       error
}

// Apply pushes value into every placement of name. resolve is used by render
// placements whose template may reference other secrets.
func Apply(s *store.Store, m *store.Meta, value string, resolve func([]string) (map[string]string, error)) []Result {
	var out []Result
	for _, p := range m.Placements {
		err := One(s, m.Name, p, value, resolve)
		Audit(s, m, p, err)
		out = append(out, Result{p, err})
	}
	return out
}

func One(s *store.Store, name string, p store.Placement, value string, resolve func([]string) (map[string]string, error)) error {
	switch p.Type {
	case "file":
		if err := os.MkdirAll(filepath.Dir(p.Path), 0o700); err != nil {
			return err
		}
		return envfile.Set(p.Path, map[string]string{p.Var: value})
	case "render":
		return Render(p.Template, p.Path, resolve)
	case "gh":
		args := []string{"secret", "set", p.Secret, "--repo", p.Repo}
		if p.Env != "" {
			args = append(args, "--env", p.Env)
		}
		return runStdin("gh", args, value)
	case "gcp":
		exists := exec.Command("gcloud", "secrets", "describe", p.Secret, "--project="+p.Project).Run() == nil
		if exists {
			return runStdin("gcloud", []string{"secrets", "versions", "add", p.Secret, "--data-file=-", "--project=" + p.Project}, value)
		}
		return runStdin("gcloud", []string{"secrets", "create", p.Secret, "--replication-policy=automatic", "--data-file=-", "--project=" + p.Project}, value)
	case "path":
		mode, err := parseMode(p.Mode)
		if err != nil {
			return err
		}
		return bundle.Write(p.Path, kindOf(s, name), []byte(value), mode)
	case "remote":
		if len(p.Via) == 0 {
			return fmt.Errorf("remote placement has no transport")
		}
		if p.Path != "" {
			return runStdin(p.Via[0], remoteArgs(p.Via, remoteWriteCmd(p.Path, kindOf(s, name), p.Mode)), value)
		}
		bin := p.Bin
		if bin == "" {
			bin = "sec"
		}
		cmd := []string{bin, "set", p.Secret, "--raw"}
		if k := kindOf(s, name); k != "" {
			cmd = append(cmd, "--kind", k)
		}
		return runStdin(p.Via[0], remoteArgs(p.Via, cmd), value)
	}
	return fmt.Errorf("unknown placement type %q", p.Type)
}

// Audit records one push of the current version to one placement, so the log
// answers "which version reached where, and when" for every target.
func Audit(s *store.Store, m *store.Meta, p store.Placement, err error) {
	f := map[string]string{"to": p.String(), "version": fmt.Sprint(m.Version), "ok": "true"}
	if err != nil {
		f["ok"], f["error"] = "false", err.Error()
	}
	s.Audit("place.apply", owner.Agent(), []string{m.Name}, f)
}

// Render fills a template file with secrets and writes it 0600.
func Render(templatePath, outPath string, resolve func([]string) (map[string]string, error)) error {
	body, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	names := tmpl.Names(string(body))
	vals, err := resolve(names)
	if err != nil {
		return err
	}
	filled, err := tmpl.Fill(string(body), vals)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(filled), 0o600)
}

// runStdin feeds value on stdin — never argv, never the environment of a
// shell — and reports the tool's stderr without ever echoing the value.
func runStdin(bin string, args []string, value string) error {
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("%s not installed", bin)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(value)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.ReplaceAll(strings.TrimSpace(stderr.String()), value, "[REDACTED]")
		return fmt.Errorf("%s %s: %s", bin, args[0], msg)
	}
	return nil
}

// Parse turns a CLI spec into a Placement:
//
//	--file  PATH=VAR
//	--render TEMPLATE=OUT
//	--gh    owner/repo[:env][=SECRET_NAME]
//	--gcp   project[=SECRET_NAME]
func Parse(kind, spec, name string) (store.Placement, error) {
	p := store.Placement{Type: kind}
	switch kind {
	case "file":
		path, v, ok := strings.Cut(spec, "=")
		if !ok {
			v = name
		}
		p.Path, p.Var = path, v
	case "render":
		t, o, ok := strings.Cut(spec, "=")
		if !ok {
			return p, fmt.Errorf("--render wants TEMPLATE=OUT")
		}
		p.Template, p.Path = t, o
	case "gh":
		target, sec, ok := strings.Cut(spec, "=")
		if !ok {
			sec = name
		}
		repo, env, _ := strings.Cut(target, ":")
		if !strings.Contains(repo, "/") {
			return p, fmt.Errorf("--gh wants owner/repo[:env]")
		}
		p.Repo, p.Env, p.Secret = repo, env, sec
	case "gcp":
		proj, sec, ok := strings.Cut(spec, "=")
		if !ok {
			sec = name
		}
		p.Project, p.Secret = proj, sec
	default:
		return p, fmt.Errorf("unknown placement kind %q", kind)
	}
	return p, nil
}

func kindOf(s *store.Store, name string) string {
	if m, err := s.Meta(name); err == nil {
		return m.Kind
	}
	return ""
}

func parseMode(m string) (os.FileMode, error) {
	if m == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(m, 8, 32)
	if err != nil || v > 0o777 {
		return 0, fmt.Errorf("bad mode %q (want octal like 0600)", m)
	}
	return os.FileMode(v), nil
}

// remoteWriteCmd writes stdin to path on the other end atomically: a file via
// temp+mv, a folder by untarring beside it and swapping it in. It needs only
// sh, mkdir, cat, mv and tar there — not sec.
func remoteWriteCmd(path, kind, mode string) []string {
	if mode == "" {
		mode = "0600"
	}
	script := `set -e; umask 077; p="$1"; mkdir -p "$(dirname "$p")"; cat > "$p.sec-tmp"; chmod ` + mode + ` "$p.sec-tmp"; mv -f "$p.sec-tmp" "$p"`
	if kind == bundle.KindDir {
		script = `set -e; umask 077; p="$1"; mkdir -p "$(dirname "$p")"; rm -rf "$p.sec-tmp" "$p.sec-old"; mkdir "$p.sec-tmp"; tar -xzpf - -C "$p.sec-tmp"; if [ -e "$p" ]; then mv "$p" "$p.sec-old"; fi; mv "$p.sec-tmp" "$p"; rm -rf "$p.sec-old"`
	}
	return []string{"sh", "-c", script, "sh", path}
}

// remoteArgs appends cmd to the transport. ssh joins its arguments into one
// shell string on the far side, so for ssh each word is quoted; transports
// like docker/kubectl exec pass argv through as-is.
func remoteArgs(via, cmd []string) []string {
	out := append([]string{}, via[1:]...)
	if filepath.Base(via[0]) != "ssh" {
		return append(out, cmd...)
	}
	for _, c := range cmd {
		out = append(out, "'"+strings.ReplaceAll(c, "'", `'\''`)+"'")
	}
	return out
}

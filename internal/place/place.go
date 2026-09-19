// Package place knows where a secret's value has been put, and how to put
// the current value there again. This is what makes rotation a single verb.
package place

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/muthuishere/secure-agent/internal/envfile"
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
		out = append(out, Result{p, One(s, m.Name, p, value, resolve)})
	}
	return out
}

func One(s *store.Store, name string, p store.Placement, value string, resolve func([]string) (map[string]string, error)) error {
	switch p.Type {
	case "file":
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
	}
	return fmt.Errorf("unknown placement type %q", p.Type)
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

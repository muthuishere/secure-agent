package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/muthuishere/secure-agent/internal/cert"
	"github.com/muthuishere/secure-agent/internal/owner"
)

func init() {
	register("cert", "cert ca | cert issue --cn HOST | cert self-signed --cn HOST — local TLS, keys 0600", cmdCert)
	register("skill", "skill install — link the agent skill into ~/.claude/skills + ~/.agents/skills and add harness deny rules", cmdSkill)
}

func cmdCert(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sec cert ca [--trust] | sec cert issue --cn HOST [--san a,b] [--out DIR] | sec cert self-signed --cn HOST")
	}
	s, err := open()
	if err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ca":
		fs := flags("cert ca")
		days := fs.Int("days", 3650, "validity")
		trust := fs.Bool("trust", false, "run the OS command to trust the CA for this user (macOS login keychain)")
		if _, err := parse(fs, rest); err != nil {
			return err
		}
		f, created, err := cert.CA(s.CertDir(), "sec local CA", *days)
		if err != nil {
			return err
		}
		if created {
			fmt.Printf("✓ CA created: %s (key %s, 0600)\n", f.Cert, f.Key)
			s.Audit("cert.ca", owner.Agent(), nil, nil)
		} else {
			fmt.Printf("CA exists: %s\n", f.Cert)
		}
		cmdStr := cert.TrustCommand(f.Cert)
		if *trust {
			fmt.Println("→", cmdStr)
			return runPlain("sh", "-c", cmdStr)
		}
		fmt.Println("trust it for this user with:\n  " + cmdStr)
		return nil
	case "issue", "self-signed":
		fs := flags("cert " + sub)
		cn := fs.String("cn", "", "common name (also first SAN)")
		san := fs.String("san", "", "extra SANs, comma-separated (DNS or IP)")
		out := fs.String("out", "./certs", "output dir")
		days := fs.Int("days", 825, "validity (825 = Apple's max for leaf certs)")
		if _, err := parse(fs, rest); err != nil {
			return err
		}
		if *cn == "" {
			return fmt.Errorf("--cn is required")
		}
		var f cert.Files
		if sub == "issue" {
			f, err = cert.Issue(s.CertDir(), *out, *cn, splitList(*san), *days)
		} else {
			f, err = cert.SelfSigned(*out, *cn, splitList(*san), *days)
		}
		if err != nil {
			return err
		}
		s.Audit("cert."+sub, owner.Agent(), nil, map[string]string{"cn": *cn, "out": *out})
		fmt.Printf("✓ cert: %s\n✓ key : %s (0600)\n", f.Cert, f.Key)
		return nil
	}
	return fmt.Errorf("unknown cert subcommand %q", sub)
}

func runPlain(name string, args ...string) error {
	c := execCommand(name, args...)
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	return c.Run()
}

// skill install: symlink the repo's skills/sec dir into both skill roots and
// merge Read-deny rules into ~/.claude/settings.json so the harness — not the
// model — refuses to open the vault or dotenv files.
func cmdSkill(args []string) error {
	if len(args) == 0 || args[0] != "install" {
		return fmt.Errorf("usage: sec skill install [--from DIR] [--no-settings]")
	}
	fs := flags("skill install")
	from := fs.String("from", "", "skill source dir (default: skills/sec next to the source checkout, or $SEC_SKILL_DIR)")
	noSettings := fs.Bool("no-settings", false, "skip editing ~/.claude/settings.json")
	if _, err := parse(fs, args[1:]); err != nil {
		return err
	}
	src := *from
	if src == "" {
		src = os.Getenv("SEC_SKILL_DIR")
	}
	if src == "" {
		return fmt.Errorf("--from DIR (the repo's skills/sec) or SEC_SKILL_DIR is required")
	}
	src, _ = filepath.Abs(src)
	if _, err := os.Stat(filepath.Join(src, "SKILL.md")); err != nil {
		return fmt.Errorf("%s has no SKILL.md", src)
	}
	home, _ := os.UserHomeDir()
	for _, root := range []string{filepath.Join(home, ".claude", "skills"), filepath.Join(home, ".agents", "skills")} {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return err
		}
		dst := filepath.Join(root, "sec")
		os.Remove(dst)
		if err := os.Symlink(src, dst); err != nil {
			return err
		}
		fmt.Printf("✓ %s → %s\n", dst, src)
	}
	if *noSettings {
		return nil
	}
	return mergeDeny(filepath.Join(home, ".claude", "settings.json"))
}

var denyRules = []string{
	"Read(" + "~/.config/sec/**" + ")",
	"Read(**/.env)",
	"Read(**/.env.*)",
	"Bash(sec get:*)",
	"Bash(sec export:*)",
}

func mergeDeny(path string) error {
	cfg := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return fmt.Errorf("%s: %w (not touching it)", path, err)
		}
	}
	perms, _ := cfg["permissions"].(map[string]any)
	if perms == nil {
		perms = map[string]any{}
	}
	var deny []any
	if d, ok := perms["deny"].([]any); ok {
		deny = d
	}
	have := map[string]bool{}
	for _, d := range deny {
		if s, ok := d.(string); ok {
			have[s] = true
		}
	}
	added := 0
	for _, r := range denyRules {
		if !have[r] {
			deny = append(deny, r)
			added++
		}
	}
	perms["deny"] = deny
	cfg["permissions"] = perms
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("✓ %s: %d deny rule(s) added (%d already present)\n", path, added, len(denyRules)-added)
	return nil
}

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/redact"
	"github.com/muthuishere/secure-agent/internal/store"
)

func init() {
	register("seal", "reverse of render: put {{NAME}} back where a file holds real values; --check only reports", cmdSeal)
}

// cmdSeal turns a filled file back into a template. It is the return leg of
// `sec render`, and with --check it is a leak scanner: it answers "does this
// file contain live credentials, and which ones" without a human — or an agent
// — having to read the file to find out.
func cmdSeal(args []string) error {
	fs := flags("seal")
	out := fs.String("out", "", "write the sealed file here (default: in place)")
	check := fs.Bool("check", false, "report what would be sealed; write nothing; exit 1 if anything found")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: sec seal FILE [--out FILE] [--check]")
	}
	src := rest[0]
	s, err := open()
	if err != nil {
		return err
	}
	names, err := s.List()
	if err != nil {
		return err
	}
	vals, err := s.Resolve(names)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	sealed, found := redact.Seal(body, vals)
	if len(found) == 0 {
		fmt.Printf("✓ %s holds no known secret value\n", src)
		return nil
	}
	if *check {
		fmt.Printf("✗ %s contains %d live secret(s): %s\n", src, len(found), strings.Join(found, ", "))
		fmt.Printf("  seal it with: sec seal %s\n", src)
		return exitCode(1)
	}
	dst := *out
	if dst == "" {
		dst = src
	}
	if err := os.WriteFile(dst, sealed, 0o600); err != nil {
		return err
	}
	for _, n := range found {
		m, err := s.Meta(n)
		if err != nil {
			continue
		}
		m.AddPlacement(store.Placement{Type: "render", Template: dst, Path: src})
		s.SaveMeta(m)
	}
	s.Audit("seal", owner.Agent(), found, map[string]string{"file": src, "out": dst})
	fmt.Printf("✓ sealed %s → %s (%d secret(s) → placeholders)\n", src, dst, len(found))
	return nil
}

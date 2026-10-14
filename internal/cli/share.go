package cli

import (
	"bytes"
	"fmt"
	"os"

	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/store"
)

// Moving secrets to another sec without ssh: `sec export --for KEY` seals
// them for that vault's public key, `sec import FILE` there opens them.
// (With ssh, `sec push NAMES ssh://host` does it live and stays in sync.)

func init() {
	register("id", "print this vault's public key — the other side of: sec export --for KEY", cmdID)
}

func cmdID(args []string) error {
	s, err := open()
	if err != nil {
		return err
	}
	fmt.Println(s.PublicKey())
	return nil
}

// exportSealed writes names sealed for another sec's key (age1… or a saved
// target name). The file is safe to copy anywhere.
func exportSealed(s *store.Store, names []string, to, out string) error {
	label := to
	if t, ok := loadTargets(s)[to]; ok {
		to = t
	}
	var items []store.SharedItem
	for _, n := range names {
		m, err := s.Meta(n)
		if err != nil {
			return fmt.Errorf("no such secret: %s", n)
		}
		v, err := s.Get(n)
		if err != nil {
			return err
		}
		items = append(items, store.SharedItem{Name: n, Kind: m.Kind, Value: v})
	}
	sealed, err := store.Seal(to, items)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, sealed, 0o600); err != nil {
		return err
	}
	s.Audit("export.sealed", owner.Agent(), names, map[string]string{"for": to, "file": out})
	fmt.Printf("✓ %d secret(s) sealed for %s → %s\n  on the other machine: sec import %s\n", len(items), label, out, out)
	return nil
}

func isSealed(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN AGE ENCRYPTED FILE-----"))
}

// importSealed stores every secret in a sealed export addressed to this vault.
func importSealed(s *store.Store, path string, b []byte) error {
	items, err := s.Open(b)
	if err != nil {
		return err
	}
	var names []string
	for _, it := range items {
		if err := store.ValidName(it.Name); err != nil {
			return err
		}
		m, err := s.Set(it.Name, it.Value, "import")
		if err != nil {
			return err
		}
		m.Kind = it.Kind
		if err := s.SaveMeta(m); err != nil {
			return err
		}
		names = append(names, it.Name)
		fmt.Printf("✓ %s stored (v%d)\n", it.Name, m.Version)
	}
	s.Audit("import.sealed", owner.Agent(), names, map[string]string{"file": path})
	return nil
}

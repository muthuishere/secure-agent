package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/muthuishere/secure-agent/internal/place"
	"github.com/muthuishere/secure-agent/internal/store"
)

func init() {
	register("ok", "check everything and fix what is safe: stale copies re-pushed, missing keys and old versions listed with the command to run (--dry: fix nothing)", cmdOk)
}

// cmdOk is the one command to run when unsure. It re-pushes any placement
// that does not hold the current version (the audit log says which version
// last reached it), and lists what needs a human, each with its next command.
func cmdOk(args []string) error {
	fs := flags("ok")
	dry := fs.Bool("dry", false, "report only, change nothing")
	verbose := fs.Bool("v", false, "list every placement that was skipped, not just the counts")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		fmt.Printf("✗ vault: %v\n", err)
		return exitCode(1)
	}
	names, err := s.List()
	if err != nil {
		return err
	}
	info := s.IdentityInfo()
	fmt.Printf("✓ vault unlocked, %d secret(s), key in %s\n", len(names), info.Backend)
	problems := 0

	// 1. Keys the project in this directory needs.
	inVault := map[string]bool{}
	for _, n := range names {
		inVault[n] = true
	}
	for _, pat := range []string{".env.example", ".env.sample", ".env.template", ".env.*.example", "*.tmpl"} {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			need, err := keysOf(f)
			if err != nil {
				continue
			}
			var missing []string
			for _, n := range need {
				if !inVault[n] {
					missing = append(missing, n)
				}
			}
			if len(missing) == 0 {
				fmt.Printf("✓ %s needs %d key(s) — all present\n", f, len(need))
				continue
			}
			for _, n := range missing {
				problems++
				fmt.Printf("✗ %s missing (needed by %s)   → sec set %s\n", n, f, n)
			}
		}
	}

	// 2. Every placement holds the current version.
	fixed, current := 0, 0
	var unknown, gone, relative []string
	for _, n := range names {
		m, err := s.Meta(n)
		if err != nil || len(m.Placements) == 0 {
			continue
		}
		last := lastPushed(s, n)
		var val []byte
		for _, p := range m.Placements {
			line := fmt.Sprintf("%s → %s", n, p)
			local := p.Type == "path" || p.Type == "file" || p.Type == "render"
			// Older placements may hold a path relative to wherever they were
			// made; there is no telling what it was relative to, so never touch.
			if local && !filepath.IsAbs(p.Path) {
				relative = append(relative, line)
				continue
			}
			// A deleted file may have been deleted on purpose: report, don't recreate.
			if local && !exists(p.Path) {
				gone = append(gone, line)
				continue
			}
			v, seen := last[p.String()]
			if seen && v == m.Version {
				current++
				continue
			}
			// No version on record (placed before sec ok existed): never push
			// to GitHub/GCP/servers on a guess.
			if !seen {
				unknown = append(unknown, line)
				continue
			}
			why := fmt.Sprintf("has v%d, vault has v%d", v, m.Version)
			if *dry {
				problems++
				fmt.Printf("↻ %s → %s: %s   → sec ok\n", n, p, why)
				continue
			}
			if val == nil {
				if val, err = s.Get(n); err != nil {
					return err
				}
			}
			err := place.One(s, n, p, string(val), s.Resolve)
			place.Audit(s, m, p, err)
			if err != nil {
				problems++
				fmt.Printf("✗ %s → %s: %s, re-push failed: %v   → fix it, then sec ok\n", n, p, why, err)
				continue
			}
			fixed++
			fmt.Printf("↻ %s → %s: %s → re-pushed ✓\n", n, p, why)
		}
	}
	if current > 0 {
		fmt.Printf("✓ %d placement(s) hold the current version\n", current)
	}
	more := ""
	if !*verbose {
		more = "  (sec ok -v lists them)"
	}
	skipped := func(list []string, what string) {
		if len(list) == 0 {
			return
		}
		fmt.Printf("· %d placement(s) %s — left alone%s\n", len(list), what, more)
		if *verbose {
			for _, l := range list {
				fmt.Printf("    %s\n", l)
			}
		}
	}
	skipped(unknown, "have no version on record (sec set NAME --place re-pushes one)")
	skipped(gone, "point at files that no longer exist")
	skipped(relative, "use a relative path from an older sec")

	// 3. Old versions that were replaced but maybe never revoked upstream.
	for _, n := range names {
		m, err := s.Meta(n)
		if err != nil || len(m.Retired) == 0 {
			continue
		}
		r := m.Retired[len(m.Retired)-1]
		if age := time.Since(r.RetiredAt); age > 7*24*time.Hour {
			problems++
			where := m.Source
			if where == "" {
				where = "its source"
			}
			fmt.Printf("⚠ %s v%d replaced %d days ago — revoke it at %s, then   → sec rotate %s --purge\n", n, r.Version, int(age.Hours()/24), where, n)
		}
	}

	// 4. The agent guard.
	if home, err := os.UserHomeDir(); err == nil {
		b, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
		if strings.Contains(string(b), "sec hook") {
			fmt.Println("✓ agent hook installed")
		} else {
			fmt.Println("· agent hook not installed (optional)   → sec skill install")
		}
	}

	switch {
	case problems == 0 && fixed == 0:
		fmt.Println("\nall okay")
	case problems == 0:
		fmt.Printf("\nall okay — fixed %d\n", fixed)
	default:
		fmt.Printf("\n%d thing(s) need you", problems)
		if fixed > 0 {
			fmt.Printf(", fixed %d", fixed)
		}
		fmt.Println()
		return exitCode(1)
	}
	return nil
}

// lastPushed maps placement → the version the log last saw land there.
func lastPushed(s *store.Store, name string) map[string]int {
	out := map[string]int{}
	ents, _ := s.ReadAudit(name, "place.apply", time.Time{})
	for _, e := range ents {
		if e.Fields["ok"] != "true" {
			continue
		}
		var v int
		fmt.Sscan(e.Fields["version"], &v)
		out[e.Fields["to"]] = v
	}
	return out
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

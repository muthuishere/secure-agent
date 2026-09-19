package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/muthuishere/secure-agent/internal/execx"
	"github.com/muthuishere/secure-agent/internal/gen"
	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/place"
	"github.com/muthuishere/secure-agent/internal/store"
)

func init() {
	register("place", "record where a secret lives (--file/--gh/--gcp/--render) and push the value there", cmdPlace)
	register("where", "every placement + recent uses of a secret — the compromise-day question", cmdWhere)
	register("rotate", "new value (stdin, --gen, or --hook) → re-push to every placement → manual steps listed", cmdRotate)
	register("audit", "who used what, when; --retired lists old versions still to revoke upstream", cmdAudit)
}

func cmdPlace(args []string) error {
	fs := flags("place")
	file := fs.String("file", "", "PATH[=VAR] dotenv placement")
	gh := fs.String("gh", "", "owner/repo[:environment][=SECRET_NAME] GitHub Actions secret")
	gcp := fs.String("gcp", "", "project[=SECRET_NAME] GCP Secret Manager")
	render := fs.String("render", "", "TEMPLATE=OUT rendered file")
	dry := fs.Bool("record-only", false, "record without pushing the value now")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: sec place NAME --file .env[=VAR] | --gh o/r[:env] | --gcp project | --render T=OUT")
	}
	name := rest[0]
	s, err := open()
	if err != nil {
		return err
	}
	m, err := s.Meta(name)
	if err != nil {
		return fmt.Errorf("no such secret: %s", name)
	}
	var specs []store.Placement
	for kind, spec := range map[string]string{"file": *file, "gh": *gh, "gcp": *gcp, "render": *render} {
		if spec == "" {
			continue
		}
		// A file placement may name an environment instead of a path.
		if kind == "file" {
			path, v, _, err := resolveEnvSpec(spec, name)
			if err != nil {
				return err
			}
			spec = path + "=" + v
		}
		p, err := place.Parse(kind, spec, name)
		if err != nil {
			return err
		}
		if kind == "file" {
			p.Env = environmentOf(p.Path)
		}
		specs = append(specs, p)
	}
	if len(specs) == 0 {
		return fmt.Errorf("give at least one of --file/--gh/--gcp/--render")
	}
	val := ""
	if !*dry {
		v, err := s.Get(name)
		if err != nil {
			return err
		}
		val = string(v)
	}
	for _, p := range specs {
		m.AddPlacement(p)
		if *dry {
			fmt.Printf("  · recorded %s\n", p)
			continue
		}
		if err := place.One(s, name, p, val, s.Resolve); err != nil {
			fmt.Printf("  ✗ %s\n      %v\n", p, err)
		} else {
			fmt.Printf("  ✓ %s\n", p)
		}
	}
	s.Audit("place", owner.Agent(), []string{name}, map[string]string{"count": fmt.Sprint(len(specs))})
	return s.SaveMeta(m)
}

func cmdWhere(args []string) error {
	fs := flags("where")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: sec where NAME")
	}
	s, err := open()
	if err != nil {
		return err
	}
	m, err := s.Meta(rest[0])
	if err != nil {
		return fmt.Errorf("no such secret: %s", rest[0])
	}
	fmt.Printf("%s  v%d  updated %s\n", m.Name, m.Version, m.Updated.Format("2006-01-02 15:04"))
	if m.Source != "" {
		fmt.Printf("source: %s\n", m.Source)
	}
	fmt.Printf("placements (%d):\n", len(m.Placements))
	for _, p := range m.Placements {
		fmt.Printf("  %s   [%s]\n", p, p.UpdatedAt.Format("2006-01-02"))
	}
	if len(m.Retired) > 0 {
		fmt.Printf("retired versions still to revoke upstream: ")
		for _, r := range m.Retired {
			fmt.Printf("v%d(%s) ", r.Version, r.RetiredAt.Format("01-02"))
		}
		fmt.Println("  → `sec audit --retired`, then `sec rotate NAME --purge` once revoked")
	}
	ents, _ := s.ReadAudit(m.Name, "", time.Now().Add(-30*24*time.Hour))
	fmt.Printf("activity in the last 30 days (%d):\n", len(ents))
	for i := len(ents) - 1; i >= 0 && i >= len(ents)-15; i-- {
		e := ents[i]
		fmt.Printf("  %s  %-9s %-12s %s\n", e.TS.Local().Format("01-02 15:04"), e.Action, e.Agent, e.Fields["cmd"]+e.Fields["file"])
	}
	return nil
}

func cmdRotate(args []string) error {
	fs := flags("rotate")
	useGen := fs.Bool("gen", false, "generate the new value here (passwords you own, e.g. DB users)")
	length := fs.Int("len", 32, "length for --gen")
	noSym := fs.Bool("no-symbols", false, "for --gen")
	hook := fs.String("hook", "", "script run with SEC_NAME/SEC_NEW_VALUE/SEC_OLD_VALUE in env to apply the change at the source")
	undo := fs.Bool("undo", false, "bring back the previous version and re-place it")
	purge := fs.Bool("purge", false, "drop retired ciphertexts (after you revoked them upstream)")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: sec rotate NAME [--gen | < new value on stdin] [--hook script] | --undo | --purge")
	}
	name := rest[0]
	s, err := open()
	if err != nil {
		return err
	}
	m, err := s.Meta(name)
	if err != nil {
		return fmt.Errorf("no such secret: %s", name)
	}
	ag := owner.Agent()

	if *purge {
		n, err := s.PurgeRetired(name)
		if err != nil {
			return err
		}
		s.Audit("rotate.purge", ag, []string{name}, map[string]string{"dropped": fmt.Sprint(n)})
		fmt.Printf("✓ dropped %d retired version(s) of %s\n", n, name)
		return nil
	}
	if *undo {
		if len(m.Retired) == 0 {
			return fmt.Errorf("%s has no retired version to restore", name)
		}
		prev := m.Retired[len(m.Retired)-1]
		old, err := s.GetVersion(name, prev.Version)
		if err != nil {
			return err
		}
		m, err = s.Set(name, old, "undo")
		if err != nil {
			return err
		}
		s.Audit("rotate.undo", ag, []string{name}, map[string]string{"restored": fmt.Sprint(prev.Version), "now": fmt.Sprint(m.Version)})
		fmt.Printf("✓ %s restored v%d as v%d — re-placing\n", name, prev.Version, m.Version)
		reportPlacements(place.Apply(s, m, string(old), s.Resolve))
		return nil
	}

	oldVal, err := s.Get(name)
	if err != nil {
		return err
	}
	var newVal []byte
	if *useGen {
		pw, err := gen.Password(gen.Options{Length: *length, Symbols: !*noSym})
		if err != nil {
			return err
		}
		newVal = []byte(pw)
	} else {
		if newVal, err = readSecret("NEW value for "+name, false); err != nil {
			return err
		}
	}
	if *hook != "" {
		fmt.Printf("→ hook %s\n", *hook)
		code, err := execx.Run([]string{*hook}, map[string]string{
			"SEC_NAME": name, "SEC_NEW_VALUE": string(newVal), "SEC_OLD_VALUE": string(oldVal),
		}, map[string]string{name + ".new": string(newVal), name + ".old": string(oldVal)})
		if err != nil || code != 0 {
			s.Audit("rotate.hook-failed", ag, []string{name}, map[string]string{"hook": *hook, "exit": fmt.Sprint(code)})
			return fmt.Errorf("hook failed (exit %d) — vault unchanged, nothing re-placed", code)
		}
	}
	m, err = s.Set(name, newVal, "rotate")
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s v%d → v%d\n", name, m.Version-1, m.Version)
	res := place.Apply(s, m, string(newVal), s.Resolve)
	reportPlacements(res)
	failed := 0
	for _, r := range res {
		if r.Err != nil {
			failed++
		}
	}
	s.Audit("rotate", ag, []string{name}, map[string]string{"version": fmt.Sprint(m.Version), "placements": fmt.Sprint(len(res)), "failed": fmt.Sprint(failed)})

	fmt.Println("\nMANUAL steps:")
	if *hook == "" && !*useGen {
		fmt.Printf("  ⚠ revoke the old value (v%d) at the source", m.Version-1)
		if m.Source != "" {
			fmt.Printf(": %s", m.Source)
		} else {
			fmt.Printf(" (no --source recorded; `sec set %s --source URL` next time)", name)
		}
		fmt.Println()
	}
	if *hook == "" && *useGen {
		fmt.Printf("  ⚠ the generated value was NOT applied at the source (no --hook) — apply it there, or `sec rotate %s --undo`\n", name)
	}
	for _, p := range m.Placements {
		if p.Type == "file" || p.Type == "render" {
			fmt.Printf("  ⚠ restart whatever reads %s\n", p.Path)
		}
	}
	if failed > 0 {
		fmt.Printf("  ⚠ %d placement(s) failed above — fix and run `sec place %s` again, or `sec rotate %s --undo`\n", failed, name, name)
	}
	fmt.Printf("  · when the old value is revoked: sec rotate %s --purge\n", name)
	return nil
}

func cmdAudit(args []string) error {
	fs := flags("audit")
	name := fs.String("name", "", "filter by secret")
	action := fs.String("action", "", "filter by action (exec, run, set, rotate, …)")
	since := fs.String("since", "", "window like 24h, 7d, 30d")
	retired := fs.Bool("retired", false, "list secrets with retired versions still to revoke")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	if *retired {
		names, _ := s.List()
		for _, n := range names {
			m, err := s.Meta(n)
			if err != nil || len(m.Retired) == 0 {
				continue
			}
			fmt.Printf("%-32s %d retired  source=%s\n", n, len(m.Retired), orDash(m.Source))
		}
		return nil
	}
	var from time.Time
	if *since != "" {
		d, err := parseWindow(*since)
		if err != nil {
			return err
		}
		from = time.Now().Add(-d)
	}
	ents, err := s.ReadAudit(*name, *action, from)
	if err != nil {
		return err
	}
	for _, e := range ents {
		detail := e.Fields["cmd"] + e.Fields["file"] + e.Fields["template"]
		fmt.Printf("%s  %-14s %-12s %-40s %s\n", e.TS.Local().Format("2006-01-02 15:04"), e.Action, e.Agent, strings.Join(e.Names, ","), detail)
	}
	if len(ents) == 0 {
		fmt.Fprintln(os.Stderr, "(no matching audit entries)")
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func parseWindow(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err != nil {
			return 0, fmt.Errorf("bad window %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

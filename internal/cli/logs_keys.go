package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/muthuishere/secure-agent/internal/envfile"
	"github.com/muthuishere/secure-agent/internal/tmpl"
)

func init() {
	register("logs", "logs [NAME] [--since 7d] [--action A] [-n 50] [--json] — the audit log, newest last, every field shown", cmdLogs)
	register("keys", "keys [FILE…] — which keys a .env / template / file needs are in the vault and which are missing", cmdKeys)
}

func cmdLogs(args []string) error {
	fs := flags("logs")
	action := fs.String("action", "", "filter by action (set, push, place.apply, rotate, exec, …)")
	since := fs.String("since", "", "window like 24h, 7d, 30d")
	n := fs.Int("n", 50, "show the last N entries (0 = all)")
	asJSON := fs.Bool("json", false, "one JSON object per line")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	name := ""
	if len(rest) > 0 {
		name = rest[0]
	}
	s, err := open()
	if err != nil {
		return err
	}
	var from time.Time
	if *since != "" {
		d, err := parseWindow(*since)
		if err != nil {
			return err
		}
		from = time.Now().Add(-d)
	}
	ents, err := s.ReadAudit(name, *action, from)
	if err != nil {
		return err
	}
	if *n > 0 && len(ents) > *n {
		ents = ents[len(ents)-*n:]
	}
	for _, e := range ents {
		if *asJSON {
			b, _ := json.Marshal(e)
			fmt.Println(string(b))
			continue
		}
		keys := make([]string, 0, len(e.Fields))
		for k := range e.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var detail []string
		for _, k := range keys {
			detail = append(detail, k+"="+e.Fields[k])
		}
		mark := " "
		if e.Fields["ok"] == "false" || strings.HasSuffix(e.Action, "failed") {
			mark = "✗"
		}
		fmt.Printf("%s %s %-12s %-12s %-24s %s\n", e.TS.Local().Format("2006-01-02 15:04:05"), mark, e.Action, e.Agent, strings.Join(e.Names, ","), strings.Join(detail, "  "))
	}
	if len(ents) == 0 {
		fmt.Fprintln(os.Stderr, "(no log entries match)")
	}
	return nil
}

// cmdKeys answers "can this app start?": the names a file needs, split into
// those the vault holds and those it doesn't. Values are never read out.
func cmdKeys(args []string) error {
	fs := flags("keys")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	have, err := s.List()
	if err != nil {
		return err
	}
	inVault := map[string]bool{}
	for _, n := range have {
		inVault[n] = true
	}
	files := rest
	if len(files) == 0 {
		// Default: the templates in this directory document what the app needs.
		for _, pat := range []string{".env.example", ".env.sample", ".env.template", ".env.*.example", "*.tmpl"} {
			m, _ := filepath.Glob(pat)
			files = append(files, m...)
		}
	}
	if len(files) == 0 {
		fmt.Printf("vault holds %d key(s):\n", len(have))
		for _, n := range have {
			fmt.Printf("  ✓ %s\n", n)
		}
		fmt.Println("(pass a .env, .env.example or template file to see which of its keys are missing)")
		return nil
	}
	missing := 0
	for _, f := range files {
		names, err := keysOf(f)
		if err != nil {
			return err
		}
		fmt.Printf("%s  (%d keys)\n", f, len(names))
		for _, n := range names {
			if inVault[n] {
				fmt.Printf("  ✓ %s\n", n)
			}
		}
		for _, n := range names {
			if !inVault[n] {
				missing++
				fmt.Printf("  ✗ %s   missing — sec set %s\n", n, n)
			}
		}
	}
	if missing > 0 {
		return exitCode(1)
	}
	return nil
}

// keysOf lists the names a file refers to: {{NAME}} placeholders if it has
// any, otherwise its dotenv keys.
func keysOf(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if names := tmpl.Names(string(b)); len(names) > 0 {
		return names, nil
	}
	_, order, err := envfile.Parse(path)
	return order, err
}

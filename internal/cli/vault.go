package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/place"
	"github.com/muthuishere/secure-agent/internal/store"
)

func init() {
	register("init", "create the age identity + empty vault", cmdInit)
	register("set", "store a value from stdin (masked prompt on a TTY)", cmdSet)
	register("get", "print a value — owner-only, needs --print", cmdGet)
	register("ls", "list secret names (never values); --json for agents", cmdLs)
	register("rm", "delete a secret and its retired versions", cmdRm)
	register("recipients", "list/add age public keys that can decrypt the vault", cmdRecipients)
}

func cmdInit(args []string) error {
	fs := flags("init")
	imp := fs.String("import-identity", "", "copy an existing age identity file instead of generating")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := store.Init(*imp)
	if err != nil {
		return err
	}
	fmt.Printf("initialised %s\n  public key : %s\n  back up    : %s/identity.txt  (0600 — the vault is unreadable without it)\n  vault dir  : %s/vault  (ciphertext only — safe to git-commit or rclone)\n",
		s.Home, s.PublicKey(), s.Home, s.Home)
	s.Audit("init", owner.Agent(), nil, nil)
	return nil
}

func cmdSet(args []string) error {
	fs := flags("set")
	tags := fs.String("tag", "", "comma-separated tags")
	source := fs.String("source", "", "where this is minted/revoked (URL or note) — used by rotate")
	raw := fs.Bool("raw", false, "keep trailing newline (PEM/JSON material)")
	placeAll := fs.Bool("place", false, "after storing, re-apply to every recorded placement")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: sec set NAME [--tag a,b] [--source url] [--raw] [--place]  < value on stdin")
	}
	name := rest[0]
	if err := store.ValidName(name); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	val, err := readSecret("value for "+name, *raw)
	if err != nil {
		return err
	}
	m, err := s.Set(name, val, "set")
	if err != nil {
		return err
	}
	if *tags != "" {
		m.Tags = splitList(*tags)
	}
	if *source != "" {
		m.Source = *source
	}
	if err := s.SaveMeta(m); err != nil {
		return err
	}
	ag := owner.Agent()
	s.Audit("set", ag, []string{name}, map[string]string{"version": fmt.Sprint(m.Version)})
	fmt.Printf("✓ %s stored (v%d, %d bytes)\n", name, m.Version, len(val))
	if m.Version > 1 {
		fmt.Printf("  previous v%d retired — revoke it upstream", m.Version-1)
		if m.Source != "" {
			fmt.Printf(" at %s", m.Source)
		}
		fmt.Println()
	}
	if ag != "owner" && ag != "unknown" {
		fmt.Println("  note: this value transited an agent — consider `sec rotate " + name + "` once the real source can mint a new one")
	}
	if *placeAll {
		reportPlacements(place.Apply(s, m, string(val), s.Resolve))
	}
	return nil
}

func cmdGet(args []string) error {
	fs := flags("get")
	print := fs.Bool("print", false, "actually print the value (owner-only)")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: sec get NAME --print")
	}
	if !*print {
		return fmt.Errorf("sec get never prints by default. Use `sec exec -- cmd {{%s}}` to use it, or --print as the owner", rest[0])
	}
	if err := requireOwner("get --print"); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	v, err := s.Get(rest[0])
	if err != nil {
		return err
	}
	s.Audit("get", owner.Agent(), rest, nil)
	os.Stdout.Write(v)
	if !strings.HasSuffix(string(v), "\n") {
		fmt.Println()
	}
	return nil
}

type lsRow struct {
	Name       string    `json:"name"`
	Version    int       `json:"version"`
	Tags       []string  `json:"tags,omitempty"`
	Source     string    `json:"source,omitempty"`
	Placements int       `json:"placements"`
	Retired    int       `json:"retired"`
	Updated    time.Time `json:"updated"`
	LastUsed   string    `json:"last_used,omitempty"`
}

func cmdLs(args []string) error {
	fs := flags("ls")
	asJSON := fs.Bool("json", false, "machine output")
	tag := fs.String("tag", "", "only secrets with this tag")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	names, err := s.List()
	if err != nil {
		return err
	}
	used := s.LastUsed()
	var rows []lsRow
	for _, n := range names {
		m, err := s.Meta(n)
		if err != nil {
			continue
		}
		if *tag != "" && !hasTag(m, *tag) {
			continue
		}
		r := lsRow{Name: n, Version: m.Version, Tags: m.Tags, Source: m.Source, Placements: len(m.Placements), Retired: len(m.Retired), Updated: m.Updated}
		if t, ok := used[n]; ok {
			r.LastUsed = t.Format(time.RFC3339)
		}
		rows = append(rows, r)
	}
	if *asJSON {
		if rows == nil {
			rows = []lsRow{}
		}
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Println("(empty vault)")
		return nil
	}
	fmt.Printf("%-32s %-4s %-10s %-6s %-20s %s\n", "NAME", "VER", "PLACED", "TAGS", "LAST USED", "SOURCE")
	for _, r := range rows {
		lu := "-"
		if r.LastUsed != "" {
			lu = r.LastUsed[:16]
		}
		fmt.Printf("%-32s v%-3d %-10d %-6s %-20s %s\n", r.Name, r.Version, r.Placements, strings.Join(r.Tags, ","), lu, r.Source)
	}
	return nil
}

func hasTag(m *store.Meta, t string) bool {
	for _, x := range m.Tags {
		if x == t {
			return true
		}
	}
	return false
}

func cmdRm(args []string) error {
	fs := flags("rm")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: sec rm NAME")
	}
	s, err := open()
	if err != nil {
		return err
	}
	m, err := s.Meta(rest[0])
	if err != nil {
		return fmt.Errorf("no such secret: %s", rest[0])
	}
	if len(m.Placements) > 0 {
		fmt.Fprintf(os.Stderr, "warning: %s is still placed in %d location(s); those copies are NOT removed:\n", m.Name, len(m.Placements))
		for _, p := range m.Placements {
			fmt.Fprintln(os.Stderr, "  ", p)
		}
	}
	if err := s.Delete(rest[0]); err != nil {
		return err
	}
	s.Audit("rm", owner.Agent(), rest, nil)
	fmt.Println("✓ removed", rest[0])
	return nil
}

func cmdRecipients(args []string) error {
	fs := flags("recipients")
	add := fs.String("add", "", "age public key (age1…) to add; re-encrypts every secret")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	if *add != "" {
		if err := s.AddRecipient(*add); err != nil {
			return err
		}
		n, err := s.ReencryptAll()
		if err != nil {
			return err
		}
		s.Audit("recipients.add", owner.Agent(), nil, map[string]string{"pub": *add, "reencrypted": fmt.Sprint(n)})
		fmt.Printf("✓ added recipient, re-encrypted %d secret(s)\n", n)
	}
	recs, err := s.Recipients()
	if err != nil {
		return err
	}
	for _, r := range recs {
		me := ""
		if r == s.PublicKey() {
			me = "  (this machine)"
		}
		fmt.Println(r + me)
	}
	return nil
}

func reportPlacements(res []place.Result) {
	for _, r := range res {
		if r.Err != nil {
			fmt.Printf("  ✗ %s\n      %v\n", r.Placement, r.Err)
		} else {
			fmt.Printf("  ✓ %s\n", r.Placement)
		}
	}
}

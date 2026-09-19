package cli

import (
	"fmt"
	"strings"

	"github.com/muthuishere/secure-agent/internal/envfile"
	"github.com/muthuishere/secure-agent/internal/gen"
	"github.com/muthuishere/secure-agent/internal/owner"
	"github.com/muthuishere/secure-agent/internal/place"
	"github.com/muthuishere/secure-agent/internal/store"
)

func init() {
	register("gen", "generate a password/token straight into the vault and/or a .env — never shown", cmdGen)
	register("env", "env write FILE NAME[=VAR]… | env ls FILE — dotenv files without reading them", cmdEnv)
	register("import", "import every KEY=value of a .env into the vault (file becomes a placement)", cmdImport)
	register("export", "owner-only: write chosen secrets to a .env file", cmdExport)
}

func cmdGen(args []string) error {
	fs := flags("gen")
	length := fs.Int("len", 32, "length (chars, or bytes with --hex)")
	noSym := fs.Bool("no-symbols", false, "letters+digits only")
	hex := fs.Bool("hex", false, "hex token of --len random bytes")
	save := fs.String("save", "", "store as this secret NAME")
	env := fs.String("env", "", "also write to FILE=VAR (repeatable via comma)")
	tags := fs.String("tag", "", "tags for --save")
	print := fs.Bool("print", false, "owner-only: print the value instead")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *save == "" && *env == "" && !*print {
		return fmt.Errorf("gen needs a destination: --save NAME and/or --env FILE=VAR (or --print as owner)")
	}
	if *print {
		if err := requireOwner("gen --print"); err != nil {
			return err
		}
	}
	pw, err := gen.Password(gen.Options{Length: *length, Symbols: !*noSym, Hex: *hex})
	if err != nil {
		return err
	}
	ag := owner.Agent()
	var s *store.Store
	var m *store.Meta
	if *save != "" {
		if s, err = open(); err != nil {
			return err
		}
		if m, err = s.Set(*save, []byte(pw), "gen"); err != nil {
			return err
		}
		if *tags != "" {
			m.Tags = splitList(*tags)
		}
	}
	for _, spec := range splitList(*env) {
		file, v, ok := strings.Cut(spec, "=")
		if !ok {
			if *save == "" {
				return fmt.Errorf("--env %s: need FILE=VAR when no --save name to default to", spec)
			}
			v = *save
		}
		if err := envfile.Set(file, map[string]string{v: pw}); err != nil {
			return err
		}
		if m != nil {
			m.AddPlacement(store.Placement{Type: "file", Path: file, Var: v})
		}
		fmt.Printf("✓ %s written to %s (0600)\n", v, file)
	}
	if m != nil {
		if err := s.SaveMeta(m); err != nil {
			return err
		}
		s.Audit("gen", ag, []string{*save}, map[string]string{"len": fmt.Sprint(*length)})
		fmt.Printf("✓ %s stored (v%d, %d chars)\n", *save, m.Version, len(pw))
	}
	if *print {
		fmt.Println(pw)
	}
	return nil
}

func cmdEnv(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: sec env write FILE NAME[=VAR]…  |  sec env ls FILE")
	}
	switch args[0] {
	case "ls":
		keys, err := envfile.Keys(args[1])
		if err != nil {
			return err
		}
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	case "write":
		if len(args) < 3 {
			return fmt.Errorf("usage: sec env write FILE NAME[=VAR]…")
		}
		s, err := open()
		if err != nil {
			return err
		}
		file := args[1]
		kv := map[string]string{}
		var names []string
		for _, spec := range args[2:] {
			n, v, ok := strings.Cut(spec, "=")
			if !ok {
				v = n
			}
			val, err := s.Get(n)
			if err != nil {
				return err
			}
			kv[v] = string(val)
			names = append(names, n)
			if m, err := s.Meta(n); err == nil {
				m.AddPlacement(store.Placement{Type: "file", Path: file, Var: v})
				s.SaveMeta(m)
			}
		}
		if err := envfile.Set(file, kv); err != nil {
			return err
		}
		s.Audit("env.write", owner.Agent(), names, map[string]string{"file": file})
		fmt.Printf("✓ wrote %d key(s) to %s (0600, placements recorded)\n", len(kv), file)
		return nil
	}
	return fmt.Errorf("unknown env subcommand %q", args[0])
}

func cmdImport(args []string) error {
	fs := flags("import")
	tags := fs.String("tag", "", "tags for every imported secret")
	noPlace := fs.Bool("no-place", false, "do not record the file as a placement")
	only := fs.String("only", "", "comma-separated keys to import (default all)")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: sec import FILE.env [--tag t] [--only A,B] [--no-place]")
	}
	s, err := open()
	if err != nil {
		return err
	}
	vals, order, err := envfile.Parse(rest[0])
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, k := range splitList(*only) {
		want[k] = true
	}
	var names []string
	for _, k := range order {
		if len(want) > 0 && !want[k] {
			continue
		}
		if err := store.ValidName(k); err != nil {
			fmt.Printf("  skip %s: %v\n", k, err)
			continue
		}
		m, err := s.Set(k, []byte(vals[k]), "import")
		if err != nil {
			return err
		}
		if *tags != "" {
			m.Tags = splitList(*tags)
		}
		if !*noPlace {
			m.AddPlacement(store.Placement{Type: "file", Path: rest[0], Var: k})
		}
		if err := s.SaveMeta(m); err != nil {
			return err
		}
		names = append(names, k)
	}
	s.Audit("import", owner.Agent(), names, map[string]string{"file": rest[0]})
	fmt.Printf("✓ imported %d secret(s) from %s\n", len(names), rest[0])
	return nil
}

func cmdExport(args []string) error {
	fs := flags("export")
	confirm := fs.Bool("confirm", false, "required: this writes plaintext values")
	out := fs.String("out", "", "output .env path (0600)")
	only := fs.String("only", "", "comma-separated names (default all)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if !*confirm || *out == "" {
		return fmt.Errorf("usage: sec export --out FILE --confirm [--only A,B]  (owner-only)")
	}
	if err := requireOwner("export"); err != nil {
		return err
	}
	s, err := open()
	if err != nil {
		return err
	}
	names := splitList(*only)
	if len(names) == 0 {
		if names, err = s.List(); err != nil {
			return err
		}
	}
	vals, err := s.Resolve(names)
	if err != nil {
		return err
	}
	if err := envfile.Set(*out, vals); err != nil {
		return err
	}
	s.Audit("export", owner.Agent(), names, map[string]string{"file": *out})
	fmt.Printf("✓ exported %d secret(s) to %s (0600)\n", len(names), *out)
	_ = place.Parse // keep import used if placements move here later
	return nil
}

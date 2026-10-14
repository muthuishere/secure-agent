package cli

import (
	"fmt"
	"os"
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
	register("import", "import a .env (every KEY=value; file becomes a placement) or a sealed export from another sec", cmdImport)
	register("export", "owner-only: seal secrets for another sec (--for KEY), or write a plaintext .env (--confirm)", cmdExport)
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
		file, v, how, err := resolveEnvSpec(spec, *save)
		if err != nil {
			return err
		}
		if v == "" {
			return fmt.Errorf("--env %s: need TARGET=VAR when there is no --save name to default to", spec)
		}
		if err := envfile.Set(file, map[string]string{v: pw}); err != nil {
			return err
		}
		if m != nil {
			m.AddPlacement(store.Placement{Type: "file", Path: file, Var: v, Env: environmentOf(file)})
		}
		fmt.Printf("✓ %s written to %s (0600)\n", v, describeTarget(file, how))
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
	if len(args) == 0 {
		return fmt.Errorf("usage: sec env list  |  sec env ls TARGET  |  sec env write TARGET NAME[=VAR]…\n" +
			"  TARGET is a path (./.env.production) or an environment name (production),\n" +
			"  resolved against the dotenv files actually present under the current directory")
	}
	switch args[0] {
	case "list":
		files, err := envfile.Discover(".", envDepth)
		if err != nil {
			return err
		}
		if len(files) == 0 {
			fmt.Println("(no dotenv files found here)")
			return nil
		}
		fmt.Printf("%-14s %-44s %s\n", "ENVIRONMENT", "FILE", "KEYS")
		for _, f := range files {
			keys, err := envfile.Keys(f.Path)
			n := "?"
			if err == nil {
				n = fmt.Sprint(len(keys))
			}
			fmt.Printf("%-14s %-44s %s\n", f.Env, f.Path, n)
		}
		return nil

	case "ls":
		if len(args) < 2 {
			return fmt.Errorf("usage: sec env ls TARGET   (or `sec env list` for every environment)")
		}
		path, _, how, err := resolveEnvSpecExisting(args[1], "")
		if err != nil {
			return err
		}
		keys, err := envfile.Keys(path)
		if err != nil {
			return err
		}
		if how != "path" {
			fmt.Fprintf(os.Stderr, "# %s\n", describeTarget(path, how))
		}
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil

	case "write":
		if len(args) < 3 {
			return fmt.Errorf("usage: sec env write TARGET NAME[=VAR]…")
		}
		path, _, how, err := resolveEnvSpec(args[1], "")
		if err != nil {
			return err
		}
		s, err := open()
		if err != nil {
			return err
		}
		env := environmentOf(path)
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
				m.AddPlacement(store.Placement{Type: "file", Path: path, Var: v, Env: env})
				s.SaveMeta(m)
			}
		}
		if err := envfile.Set(path, kv); err != nil {
			return err
		}
		s.Audit("env.write", owner.Agent(), names, map[string]string{"file": path, "env": env})
		fmt.Printf("✓ wrote %d key(s) to %s (0600, placements recorded)\n", len(kv), describeTarget(path, how))
		return nil
	}
	return fmt.Errorf("unknown env subcommand %q (want list, ls, or write)", args[0])
}

// environmentOf labels a placement with the environment its file belongs to,
// so `sec where` can answer "which environment is this key in".
func environmentOf(path string) string {
	if files, err := envfile.Discover(".", envDepth); err == nil {
		for _, f := range files {
			if f.Path == path {
				return f.Env
			}
		}
	}
	return envfile.EnvOfPath(path)
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
		return fmt.Errorf("usage: sec import TARGET [--tag t] [--only A,B] [--no-place]\n  TARGET is a path or an environment name (production, dev, local)")
	}
	// Any existing file is imported as given, whatever its name; otherwise
	// the target is resolved as an environment name (production, dev, …).
	path, how := rest[0], "path"
	if b, rerr := os.ReadFile(path); rerr == nil && isSealed(b) {
		s, err := open()
		if err != nil {
			return err
		}
		return importSealed(s, path, b)
	}
	if st, serr := os.Stat(path); serr != nil || st.IsDir() {
		if path, _, how, err = resolveEnvSpecExisting(rest[0], ""); err != nil {
			return err
		}
	}
	s, err := open()
	if err != nil {
		return err
	}
	vals, order, err := envfile.Parse(path)
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
			m.AddPlacement(store.Placement{Type: "file", Path: path, Var: k, Env: environmentOf(path)})
		}
		if err := s.SaveMeta(m); err != nil {
			return err
		}
		names = append(names, k)
	}
	s.Audit("import", owner.Agent(), names, map[string]string{"file": path, "env": environmentOf(path)})
	fmt.Printf("✓ imported %d secret(s) from %s\n", len(names), describeTarget(path, how))
	return nil
}

func cmdExport(args []string) error {
	fs := flags("export")
	confirm := fs.Bool("confirm", false, "required: this writes plaintext values")
	out := fs.String("out", "", "output .env path (0600)")
	only := fs.String("only", "", "comma-separated names (default all)")
	forKey := fs.String("for", "", "seal for another sec (its `sec id` key, or a saved name) instead of writing plaintext")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *out == "" || (!*confirm && *forKey == "") {
		return fmt.Errorf("usage: sec export --out FILE --for KEY [--only A,B]   sealed for another sec (it runs: sec import FILE)\n       sec export --out FILE --confirm [--only A,B]  plaintext .env  (owner-only)")
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
	if *forKey != "" {
		return exportSealed(s, names, *forKey, *out)
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

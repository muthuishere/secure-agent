package envfile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// File is a dotenv file found on disk and the environment it belongs to.
type File struct {
	Env  string // "production", "dev", "local", or "default" for a bare .env
	Path string
}

// DefaultEnv is the environment name for a bare `.env`.
const DefaultEnv = "default"

// templateSuffixes are files that document variables rather than hold values.
// Writing a real secret into one of these is how keys reach a public repo.
var templateSuffixes = []string{".example", ".sample", ".template", ".dist", ".tpl", ".tmpl", ".md"}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, "target": true, ".next": true, ".venv": true, "venv": true,
	"__pycache__": true, ".terraform": true,
}

// IsTemplate reports whether a path is an example/template file rather than a
// live one.
func IsTemplate(path string) bool {
	b := strings.ToLower(filepath.Base(path))
	for _, suf := range templateSuffixes {
		if strings.HasSuffix(b, suf) {
			return true
		}
	}
	return false
}

// envOf returns the environment a dotenv filename denotes, or "" if the name
// is not a dotenv file at all. Handles both conventions in use:
//
//	.env              → default
//	.env.production   → production
//	production.env    → production
func envOf(name string) string {
	switch {
	case name == ".env":
		return DefaultEnv
	case strings.HasPrefix(name, ".env."):
		return strings.TrimPrefix(name, ".env.")
	case strings.HasSuffix(name, ".env") && len(name) > len(".env"):
		return strings.TrimSuffix(name, ".env")
	}
	return ""
}

// Discover walks root (bounded depth, skipping vendored and build dirs) and
// returns every live dotenv file, nearest first. Template files are left out:
// they are the ones you must never write a value into.
func Discover(root string, maxDepth int) ([]File, error) {
	if root == "" {
		root = "."
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var out []File
	err = filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable dir: skip, never fail the whole walk
		}
		rel, _ := filepath.Rel(rootAbs, path)
		depth := 0
		if rel != "." {
			depth = strings.Count(rel, string(filepath.Separator)) + 1
		}
		if d.IsDir() {
			if path != rootAbs && (skipDirs[d.Name()] || depth > maxDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		env := envOf(d.Name())
		if env == "" || IsTemplate(path) {
			return nil
		}
		p := path
		if r, err := filepath.Rel(rootAbs, path); err == nil {
			p = r
		}
		out = append(out, File{Env: env, Path: p})
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Shallower paths first, then alphabetical — the file next to you wins.
	sort.Slice(out, func(i, j int) bool {
		di := strings.Count(out[i].Path, string(filepath.Separator))
		dj := strings.Count(out[j].Path, string(filepath.Separator))
		if di != dj {
			return di < dj
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// looksLikePath reports whether a target the user typed is meant as a file
// path rather than an environment name.
func looksLikePath(target string) bool {
	return strings.ContainsRune(target, filepath.Separator) ||
		strings.HasPrefix(target, ".") ||
		strings.HasSuffix(target, ".env")
}

// ResolveTarget turns what the caller typed into a concrete file.
//
// A bare word is an environment name, looked up among the dotenv files
// actually present — because "production" lives in .env.production here and
// infra/vault/production/.env.production there, and assuming `.env` writes the
// secret into the wrong environment.
//
// A path is used as given when the caller may create it. When the file must
// already exist (reading, importing) and it does not, this does not fail
// straight away: it re-scans and offers what is actually there. Files move
// between repos and layouts, so a stale path is a search, not an error.
//
// It reports how it resolved so the caller can say which file it picked; an
// environment that matches several files is an error listing them, never a
// guess.
func ResolveTarget(root, target string, maxDepth int) (path string, how string, err error) {
	return resolveTarget(root, target, maxDepth, false)
}

// ResolveExisting is ResolveTarget for callers that read the file: a path that
// is not there falls back to searching, rather than reporting "no such file"
// for a dotenv that simply lives somewhere else now.
func ResolveExisting(root, target string, maxDepth int) (path string, how string, err error) {
	return resolveTarget(root, target, maxDepth, true)
}

func resolveTarget(root, target string, maxDepth int, mustExist bool) (path string, how string, err error) {
	if target == "" {
		return "", "", fmt.Errorf("no environment or file given")
	}
	if looksLikePath(target) {
		if IsTemplate(target) {
			return "", "", fmt.Errorf("%s is a template file — it documents variable names and is usually committed; write to the real env file instead", target)
		}
		if !mustExist || Exists(target) {
			return target, "path", nil
		}
		// The path is stale. Search by the environment its name implies
		// before giving up, so a moved or renamed file still resolves.
		if env := EnvOfPath(target); env != "" {
			if p, h, ferr := resolveTarget(root, env, maxDepth, mustExist); ferr == nil {
				return p, h + ", found by searching (" + target + " is not there)", nil
			}
		}
		return "", "", fmt.Errorf("%s does not exist%s", target, foundHint(root, maxDepth))
	}
	files, derr := Discover(root, maxDepth)
	if derr != nil {
		return "", "", derr
	}
	var hits []File
	for _, f := range files {
		if strings.EqualFold(f.Env, target) {
			hits = append(hits, f)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0].Path, "environment " + hits[0].Env, nil
	case 0:
		if hint := foundHint(root, maxDepth); hint == "" {
			return "", "", fmt.Errorf("no dotenv file for environment %q, and none found under %s.\n  Give an explicit path (./.env.%s) if you want it created", target, root, target)
		} else {
			return "", "", fmt.Errorf("no dotenv file for environment %q%s", target, hint)
		}
	default:
		var paths []string
		for _, h := range hits {
			paths = append(paths, h.Path)
		}
		return "", "", fmt.Errorf("environment %q matches %d files: %s\n  name the one you mean", target, len(hits), strings.Join(paths, ", "))
	}
}

// foundHint lists the environments that do exist, re-scanned at the moment of
// the error rather than taken from anything remembered earlier.
func foundHint(root string, maxDepth int) string {
	files, err := Discover(root, maxDepth)
	if err != nil || len(files) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var names []string
	for _, f := range files {
		if !seen[f.Env] {
			seen[f.Env] = true
			names = append(names, fmt.Sprintf("%s (%s)", f.Env, f.Path))
		}
	}
	return ". Found: " + strings.Join(names, ", ")
}

// EnvOfPath names the environment a dotenv path belongs to, from its filename
// alone — used when the file is outside the discovery root.
func EnvOfPath(path string) string {
	if e := envOf(filepath.Base(path)); e != "" {
		return e
	}
	return ""
}

// Exists reports whether a path is present.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

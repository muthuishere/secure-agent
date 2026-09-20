package envfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnvFile(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverAndResolve(t *testing.T) {
	root := t.TempDir()
	writeEnvFile(t, root, ".env")
	writeEnvFile(t, root, ".env.local")
	writeEnvFile(t, root, ".env.example") // template: must be ignored
	writeEnvFile(t, root, "infra/vault/production/.env.production")
	writeEnvFile(t, root, "node_modules/pkg/.env") // vendored: must be ignored

	files, err := Discover(root, 4)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Env] = f.Path
	}
	if len(files) != 3 {
		t.Fatalf("found %d files: %+v", len(files), files)
	}
	if got[DefaultEnv] != ".env" || got["local"] != ".env.local" {
		t.Fatalf("got %+v", got)
	}
	if got["production"] != filepath.Join("infra", "vault", "production", ".env.production") {
		t.Fatalf("production: %q", got["production"])
	}

	// An environment name resolves to the real file, not to .env
	p, how, err := ResolveTarget(root, "production", 4)
	if err != nil || p != got["production"] {
		t.Fatalf("resolve production: %q %q %v", p, how, err)
	}
	// An explicit path is used as given
	if p, how, _ := ResolveTarget(root, "./custom/.env.x", 4); p != "./custom/.env.x" || how != "path" {
		t.Fatalf("path passthrough: %q %q", p, how)
	}
	// Templates are refused as write targets
	if _, _, err := ResolveTarget(root, ".env.example", 4); err == nil {
		t.Fatal("writing to a template file must be refused")
	}
	// An unknown environment lists what exists rather than defaulting to .env
	_, _, err = ResolveTarget(root, "staging", 4)
	if err == nil {
		t.Fatal("unknown environment must error")
	}
}

func TestResolveAmbiguous(t *testing.T) {
	root := t.TempDir()
	writeEnvFile(t, root, "api/.env.production")
	writeEnvFile(t, root, "web/.env.production")
	if _, _, err := ResolveTarget(root, "production", 4); err == nil {
		t.Fatal("two files for one environment must be an error, not a guess")
	}
}

// A path that is not there must be re-searched, not reported as missing:
// dotenv files move between layouts, and the answer is on disk right now.
func TestStalePathFallsBackToSearch(t *testing.T) {
	root := t.TempDir()
	writeEnvFile(t, root, "infra/vault/production/.env.production")

	// Reading through a path that no longer exists finds the real file.
	p, how, err := ResolveExisting(root, ".env.production", 4)
	if err != nil {
		t.Fatalf("stale path should have been searched: %v", err)
	}
	want := filepath.Join("infra", "vault", "production", ".env.production")
	if p != want {
		t.Fatalf("got %q want %q", p, want)
	}
	if !strings.Contains(how, "found by searching") {
		t.Fatalf("how = %q, must say it searched", how)
	}

	// Writing may still create a new path.
	if p, _, err := ResolveTarget(root, "./new/.env.staging", 4); err != nil || p != "./new/.env.staging" {
		t.Fatalf("write target: %q %v", p, err)
	}

	// A path with no environment in its name, and nothing to match, reports
	// what does exist rather than a bare "not found".
	_, _, err = ResolveExisting(root, "./nope/config.env", 4)
	if err == nil || !strings.Contains(err.Error(), "Found:") {
		t.Fatalf("err = %v, must list what exists", err)
	}
}

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// A vault created on the file backend must round-trip, and moving it to a
// keyring (when one answers) must leave no plaintext key on disk.
func TestFileBackendAndMove(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEC_HOME", home)
	s, err := Init("", BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	if s.BackendName() != BackendFile {
		t.Fatalf("backend %s", s.BackendName())
	}
	st, err := os.Stat(filepath.Join(home, "identity.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o400 {
		t.Fatalf("identity mode %o, want 0400", st.Mode().Perm())
	}
	if _, err := s.Set("K", []byte("v1"), "set"); err != nil {
		t.Fatal(err)
	}
	// reopen through the marker
	s2, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s2.Get("K"); string(v) != "v1" {
		t.Fatalf("roundtrip %q", v)
	}

	if !KeyringAvailable() {
		t.Skip("no OS credential store here")
	}
	t.Setenv("SEC_OWNER", "1")
	if err := s2.MoveIdentity(BackendKeyring); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.MoveIdentity(BackendFile) })
	if _, err := os.Stat(filepath.Join(home, "identity.txt")); !os.IsNotExist(err) {
		t.Fatal("identity.txt must be gone after moving to the keyring")
	}
	s3, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if s3.BackendName() != BackendKeyring {
		t.Fatalf("backend %s", s3.BackendName())
	}
	if v, _ := s3.Get("K"); string(v) != "v1" {
		t.Fatalf("keyring roundtrip %q", v)
	}
}

// SEC_IDENTITY must win over whatever is on disk — that is how a container runs.
func TestEnvBackendWins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEC_HOME", home)
	s, err := Init("", BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set("K", []byte("v1"), "set"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, "identity.txt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SEC_IDENTITY", string(raw))
	s2, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if s2.BackendName() != BackendEnv {
		t.Fatalf("backend %s", s2.BackendName())
	}
	if v, _ := s2.Get("K"); string(v) != "v1" {
		t.Fatalf("env roundtrip %q", v)
	}
}

// Linux and friends must default to the file backend without ever touching
// DBus — a probe there can hang an agent on a locked keyring.
func TestDefaultBackendPerPlatform(t *testing.T) {
	for _, tc := range []struct {
		goos string
		want Backend
	}{
		{"linux", BackendFile},
		{"freebsd", BackendFile},
	} {
		old := runtimeGOOS
		runtimeGOOS = tc.goos
		got := DefaultBackend()
		runtimeGOOS = old
		if got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.goos, got, tc.want)
		}
	}
	if runtimeGOOS == "darwin" && !keyringIsLocal() {
		t.Fatal("darwin keyring must count as local")
	}
}

// A vault whose key is in the keyring must keep working from a session that
// cannot reach it, as long as a file copy exists — no flags, no switching.
func TestKeyringFallsThroughToFile(t *testing.T) {
	if !KeyringAvailable() {
		t.Skip("no OS credential store here")
	}
	home := t.TempDir()
	t.Setenv("SEC_HOME", home)
	s, err := Init("", BackendKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set("K", []byte("v1"), "set"); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, "backup.txt")
	if err := s.ExportIdentity(key); err != nil {
		t.Fatal(err)
	}
	if err := s.AdoptIdentity(key); err != nil {
		t.Fatal(err)
	}
	// The marker must still prefer the keyring — adopting is per-machine.
	m, err := s.readMarker()
	if err != nil || m.Backend != BackendKeyring {
		t.Fatalf("marker backend %v (err %v), want keyring", m, err)
	}
	// Break the keyring and confirm the file takes over.
	if err := keyringDeleteForTest(s.keyringAccount()); err != nil {
		t.Fatal(err)
	}
	s2, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if s2.BackendName() != BackendFile {
		t.Fatalf("backend %s, want file", s2.BackendName())
	}
	if v, _ := s2.Get("K"); string(v) != "v1" {
		t.Fatalf("value %q", v)
	}
}

// Adopting a key from a different vault must be refused, not silently
// installed — that would look like a working vault that decrypts nothing.
func TestAdoptWrongKeyRefused(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SEC_HOME", home)
	s, err := Init("", BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	t.Setenv("SEC_HOME", other)
	o, err := Init("", BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(other, "stray.txt")
	if err := o.ExportIdentity(stray); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SEC_HOME", home)
	if err := s.AdoptIdentity(stray); err == nil {
		t.Fatal("adopting another vault's key must be refused")
	}
}

// Syncing a vault's ciphertext without its key must not be papered over by
// generating a fresh one — that silently orphans every secret.
func TestInitRefusesOrphanedVault(t *testing.T) {
	src := t.TempDir()
	t.Setenv("SEC_HOME", src)
	s, err := Init("", BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set("K", []byte("v1"), "set"); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dst, "vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"K.age", "K.json"} {
		b, err := os.ReadFile(filepath.Join(src, "vault", n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, "vault", n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SEC_HOME", dst)
	if _, err := Init("", BackendFile); err == nil {
		t.Fatal("init must refuse a vault that already holds secrets")
	}
}

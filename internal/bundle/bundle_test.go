package bundle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFolderRoundTripKeepsContentAndModes(t *testing.T) {
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	os.WriteFile(filepath.Join(src, "ca.pem"), []byte("CERT"), 0o644)
	os.WriteFile(filepath.Join(src, "sub", "k.key"), []byte("KEY"), 0o600)
	os.Symlink("ca.pem", filepath.Join(src, "link"))

	data, kind, skipped, err := Read(src)
	if err != nil || kind != KindDir || len(skipped) != 1 {
		t.Fatalf("kind=%q skipped=%v err=%v", kind, skipped, err)
	}
	dst := filepath.Join(t.TempDir(), "out")
	os.MkdirAll(dst, 0o700)
	os.WriteFile(filepath.Join(dst, "stale"), []byte("x"), 0o600)
	if err := Write(dst, kind, data, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "stale")); !os.IsNotExist(err) {
		t.Fatal("old folder content survived the swap")
	}
	b, _ := os.ReadFile(filepath.Join(dst, "sub", "k.key"))
	st, _ := os.Stat(filepath.Join(dst, "sub", "k.key"))
	if string(b) != "KEY" || st.Mode().Perm() != 0o600 {
		t.Fatalf("k.key = %q %v", b, st.Mode())
	}
	if st, _ := os.Stat(filepath.Join(dst, "ca.pem")); st.Mode().Perm() != 0o644 {
		t.Fatalf("ca.pem mode %v", st.Mode())
	}
}

func TestFileWriteDefaultsTo0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a", "b.key")
	if err := Write(p, KindFile, []byte{0, 1, 2}, 0); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

package envfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetPreservesAndQuotes(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(p, []byte("# comment\nA=1\nexport B=old\n"), 0o600)
	if err := Set(p, map[string]string{"B": "has space #x", "C": "plain"}); err != nil {
		t.Fatal(err)
	}
	vals, order, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if vals["A"] != "1" || vals["B"] != "has space #x" || vals["C"] != "plain" {
		t.Fatalf("vals %v", vals)
	}
	if len(order) != 3 || order[0] != "A" {
		t.Fatalf("order %v", order)
	}
	b, _ := os.ReadFile(p)
	if string(b)[:9] != "# comment" {
		t.Fatal("comment lost")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

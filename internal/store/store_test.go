package store

import (
	"testing"
)

func TestRoundtripVersionsAndRetire(t *testing.T) {
	t.Setenv("SEC_HOME", t.TempDir())
	s, err := Init("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set("K", []byte("v1"), "set"); err != nil {
		t.Fatal(err)
	}
	m, err := s.Set("K", []byte("v2"), "rotate")
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != 2 || len(m.Retired) != 1 || m.Retired[0].Version != 1 {
		t.Fatalf("meta %+v", m)
	}
	if v, _ := s.Get("K"); string(v) != "v2" {
		t.Fatalf("current %q", v)
	}
	if v, _ := s.GetVersion("K", 1); string(v) != "v1" {
		t.Fatalf("retired %q", v)
	}
	if _, err := s.Resolve([]string{"K", "MISSING"}); err == nil {
		t.Fatal("missing must fail the lot")
	}
	m.AddPlacement(Placement{Type: "file", Path: ".env", Var: "K"})
	m.AddPlacement(Placement{Type: "file", Path: ".env", Var: "K"})
	if len(m.Placements) != 1 {
		t.Fatal("placements must dedupe")
	}
	if n, _ := s.PurgeRetired("K"); n != 1 {
		t.Fatal("purge")
	}
	if _, err := s.GetVersion("K", 1); err == nil {
		t.Fatal("retired ciphertext should be gone")
	}
}

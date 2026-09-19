package tmpl

import "testing"

func TestNamesAndFill(t *testing.T) {
	s := "-H 'Bearer {{ STRIPE_KEY }}' {{DB}} {{STRIPE_KEY}}"
	if n := Names(s); len(n) != 2 || n[0] != "STRIPE_KEY" || n[1] != "DB" {
		t.Fatalf("names %v", n)
	}
	got, err := Fill(s, map[string]string{"STRIPE_KEY": "a\"b", "DB": "x"})
	if err != nil || got != "-H 'Bearer a\"b' x a\"b" {
		t.Fatalf("fill %q %v", got, err)
	}
	if _, err := Fill("{{NOPE}}", nil); err == nil {
		t.Fatal("unresolved must error")
	}
}

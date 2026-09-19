package tmpl

import (
	"strings"
	"testing"
)

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

// A vault entry that exists but is empty must stop a render, not silently
// produce a document with a blank where a credential belongs.
func TestFillRefusesEmptyValue(t *testing.T) {
	_, err := Fill("secret: {{K}}\n", map[string]string{"K": ""})
	if err == nil {
		t.Fatal("empty value filled silently")
	}
	if !strings.Contains(err.Error(), "K") {
		t.Errorf("error should name K: %v", err)
	}
}

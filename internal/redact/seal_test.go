package redact

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/muthuishere/secure-agent/internal/tmpl"
)

// A file that goes out through Fill and back through Seal must be the file it
// started as. This is the property that makes it safe to render a copy for
// someone and still keep one template.
func TestRenderSealRoundTrip(t *testing.T) {
	secrets := map[string]string{
		"DB_PASSWORD": "s3cret-pa55word",
		"API_TOKEN":   "tok_live_abcdefghijklmnop",
	}
	tplText := "db: {{DB_PASSWORD}}\nauth: Bearer {{API_TOKEN}}\nagain: {{DB_PASSWORD}}\n"

	filled, err := tmpl.Fill(tplText, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(filled), []byte("{{")) {
		t.Fatalf("render left a placeholder: %q", filled)
	}

	sealed, found := Seal([]byte(filled), secrets)
	if string(sealed) != tplText {
		t.Errorf("round trip lost the template:\n got %q\nwant %q", sealed, tplText)
	}
	if len(found) != 2 {
		t.Errorf("found %v, want both names", found)
	}
}

// Seal catches encoded forms too — a value that was base64'd into a config is
// still that value, and must come back as its name.
func TestSealCatchesEncodedForms(t *testing.T) {
	secrets := map[string]string{"API_TOKEN": "tok_live_abcdefghijklmnop"}
	enc := base64.StdEncoding.EncodeToString([]byte(secrets["API_TOKEN"]))
	sealed, found := Seal([]byte("header: "+enc+"\n"), secrets)
	if !bytes.Contains(sealed, []byte("{{API_TOKEN}}")) {
		t.Errorf("base64 form not sealed: %q", sealed)
	}
	if len(found) != 1 {
		t.Errorf("found %v, want [API_TOKEN]", found)
	}
}

// A clean file must come back untouched and report nothing, so --check is
// usable in a pre-commit hook without false positives.
func TestSealCleanFile(t *testing.T) {
	sealed, found := Seal([]byte("nothing to see here\n"), map[string]string{"K": "s3cret-value"})
	if string(sealed) != "nothing to see here\n" || len(found) != 0 {
		t.Errorf("clean file changed: %q %v", sealed, found)
	}
}

// Two names holding the same value must seal to the same name every run —
// otherwise a template churns in git depending on map iteration order.
func TestSealAliasIsDeterministic(t *testing.T) {
	secrets := map[string]string{"POSTGRES_PASSWORD": "shared-value-xyz", "DB_PASSWORD": "shared-value-xyz"}
	for i := 0; i < 20; i++ {
		sealed, found := Seal([]byte("pw: shared-value-xyz\n"), secrets)
		if string(sealed) != "pw: {{DB_PASSWORD}}\n" {
			t.Fatalf("run %d sealed to %q", i, sealed)
		}
		if len(found) != 1 {
			t.Fatalf("run %d found %v", i, found)
		}
	}
}

// An empty vault entry must never be used as a needle — it would match at every
// position in the file.
func TestSealIgnoresEmptyValues(t *testing.T) {
	sealed, found := Seal([]byte("plain text\n"), map[string]string{"EMPTY": ""})
	if string(sealed) != "plain text\n" || len(found) != 0 {
		t.Errorf("empty value matched: %q %v", sealed, found)
	}
}

package redact

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestScrubsValueAndEncodings(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, map[string]string{"K": "hunter2-super-secret"})
	r.Write([]byte("plain hunter2-super-secret\n"))
	r.Write([]byte("b64 " + base64.StdEncoding.EncodeToString([]byte("hunter2-super-secret\n")) + "\n"))
	r.Write([]byte("split hunter2-su"))
	r.Write([]byte("per-secret tail"))
	r.Flush()
	got := out.String()
	want := "plain [REDACTED:K]\nb64 [REDACTED:K]\nsplit [REDACTED:K] tail"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestShortValuesNotRedacted(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, map[string]string{"K": "ab"})
	r.Write([]byte("ab\n"))
	r.Flush()
	if out.String() != "ab\n" {
		t.Fatal("short values must not create noise")
	}
}

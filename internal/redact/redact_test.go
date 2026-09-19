package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
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

// Ordinary tools wrap long output. `xxd -p` breaks at 60 columns, GNU base64
// at 76, `fold` wherever asked — and a value in pieces is still the value.
func TestScrubsValueWrappedAcrossLines(t *testing.T) {
	const secret = "topsecret-demo-value-0000xyz"
	fold := func(s string, w int) string {
		var b strings.Builder
		for i := 0; i < len(s); i += w {
			if i > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(s[i:min(i+w, len(s))])
		}
		return b.String()
	}
	cases := []struct{ name, body string }{
		{"plain folded at 12", fold(secret, 12)},
		{"plain folded at 1", fold(secret, 1)},
		{"hex wrapped at 60", fold(hex.EncodeToString([]byte(secret)), 60)},
		{"base64 wrapped at 76", fold(base64.StdEncoding.EncodeToString([]byte(secret)), 76)},
		{"base64 wrapped at 20", fold(base64.StdEncoding.EncodeToString([]byte(secret)), 20)},
		{"crlf wrapped", strings.ReplaceAll(fold(secret, 10), "\n", "\r\n")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			r := New(&out, map[string]string{"K": secret})
			r.Write([]byte("head\n" + c.body + "\ntail\n"))
			r.Flush()
			got := out.String()
			if strings.Contains(strings.NewReplacer("\n", "", "\r", "").Replace(got), secret) {
				t.Fatalf("secret survived wrapping: %q", got)
			}
			if !strings.Contains(got, "[REDACTED:K]") {
				t.Fatalf("no label emitted: %q", got)
			}
			if !strings.HasPrefix(got, "head\n") || !strings.HasSuffix(got, "tail\n") {
				t.Fatalf("surrounding output mangled: %q", got)
			}
		})
	}
}

// The held-back tail must not swallow or reorder ordinary output.
func TestPassesThroughUnrelatedOutput(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, map[string]string{"K": "hunter2-super-secret"})
	want := ""
	for i := 0; i < 200; i++ {
		line := "line " + strings.Repeat("x", i%40) + "\n"
		r.Write([]byte(line))
		want += line
	}
	r.Flush()
	if out.String() != want {
		t.Fatalf("stream altered:\n got %q\nwant %q", out.String(), want)
	}
}

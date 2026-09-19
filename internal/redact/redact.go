// Package redact scrubs known secret values — and their common encodings —
// out of a byte stream before it reaches the caller.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
)

const minLen = 6

type variant struct {
	needle []byte
	label  []byte
}

// Redactor is an io.Writer that replaces secret values line by line.
// Output is line-buffered so a value split across two writes is still caught
// as long as it does not itself contain a newline (multi-line values are
// scrubbed per line as well).
type Redactor struct {
	mu       sync.Mutex
	w        io.Writer
	variants []variant
	buf      bytes.Buffer
}

// variantsFor returns every encoded form of one secret value that we can
// recognise in a byte stream: the value itself, base64 (three alphabets, with
// and without the trailing newline `echo | base64` adds), hex, url-escaping,
// shell-escaped quotes, and each line of a multi-line value.
//
// It is shared by Redactor (stream → [REDACTED:NAME]) and by seal
// (file → {{NAME}}), so the two directions can never drift apart: anything we
// know how to hide, we also know how to put back.
func variantsFor(v string) []string {
	var out []string
	add := func(s string) {
		if len(s) >= minLen {
			out = append(out, s)
		}
	}
	add(v)
	// `echo $X | base64` encodes a trailing newline, which changes the tail
	for _, raw := range []string{v, v + "\n"} {
		add(base64.StdEncoding.EncodeToString([]byte(raw)))
		add(base64.RawStdEncoding.EncodeToString([]byte(raw)))
		add(base64.URLEncoding.EncodeToString([]byte(raw)))
	}
	add(hex.EncodeToString([]byte(v)))
	add(url.QueryEscape(v))
	add(strings.ReplaceAll(v, `"`, `\"`))
	for _, line := range strings.Split(v, "\n") {
		add(strings.TrimSpace(line))
	}
	return out
}

// build returns the variant table for a set of secrets, longest needle first so
// a prefix variant never eats a longer one.
func build(secrets map[string]string, label func(name string) string) []variant {
	var vs []variant
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	// Sorted, not map order: when two names hold the same value, the file must
	// seal back to the same one on every run, on every machine.
	sort.Strings(names)
	for _, name := range names {
		v := secrets[name]
		if v == "" {
			continue // an empty value would match everywhere
		}
		lbl := []byte(label(name))
		for _, s := range variantsFor(v) {
			vs = append(vs, variant{[]byte(s), lbl})
		}
	}
	// Stable: equal-length needles keep the sorted-name order established above,
	// so aliases resolve the same way every time.
	sort.SliceStable(vs, func(i, j int) bool { return len(vs[i].needle) > len(vs[j].needle) })
	return vs
}

func New(w io.Writer, secrets map[string]string) *Redactor {
	return &Redactor{
		w:        w,
		variants: build(secrets, func(n string) string { return "[REDACTED:" + n + "]" }),
	}
}

// Seal is the reverse of a render: it replaces every occurrence of a known
// secret value in b with that secret's {{NAME}} placeholder, and reports which
// names were found. A file that round-trips through render then Seal comes back
// to the template it started as.
func Seal(b []byte, secrets map[string]string) ([]byte, []string) {
	found := map[string]bool{}
	for _, v := range build(secrets, func(n string) string { return "{{" + n + "}}" }) {
		if bytes.Contains(b, v.needle) {
			b = bytes.ReplaceAll(b, v.needle, v.label)
			found[strings.TrimSuffix(strings.TrimPrefix(string(v.label), "{{"), "}}")] = true
		}
	}
	var names []string
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	return b, names
}

func (r *Redactor) scrub(b []byte) []byte {
	for _, v := range r.variants {
		b = bytes.ReplaceAll(b, v.needle, v.label)
	}
	return b
}

func (r *Redactor) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf.Write(p)
	for {
		i := bytes.IndexByte(r.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := make([]byte, i+1)
		copy(line, r.buf.Next(i+1))
		if _, err := r.w.Write(r.scrub(line)); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush writes any trailing partial line.
func (r *Redactor) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buf.Len() == 0 {
		return nil
	}
	_, err := r.w.Write(r.scrub(r.buf.Bytes()))
	r.buf.Reset()
	return err
}

// String scrubs a whole string at once (for hook/error text).
func (r *Redactor) String(s string) string { return string(r.scrub([]byte(s))) }

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

func New(w io.Writer, secrets map[string]string) *Redactor {
	r := &Redactor{w: w}
	for name, v := range secrets {
		label := []byte("[REDACTED:" + name + "]")
		add := func(s string) {
			if len(s) >= minLen {
				r.variants = append(r.variants, variant{[]byte(s), label})
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
	}
	// longest first so a prefix variant never eats a longer one
	sort.Slice(r.variants, func(i, j int) bool { return len(r.variants[i].needle) > len(r.variants[j].needle) })
	return r
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

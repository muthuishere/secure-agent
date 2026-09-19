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

// Redactor is an io.Writer that replaces secret values on the way out.
//
// Matching is newline-tolerant: the haystack is also searched with \r and \n
// removed, so a value wrapped across lines is still caught. That matters
// because wrapping is the normal behaviour of ordinary tools — `xxd -p` breaks
// at 60 columns, GNU `base64` at 76, `fold` wherever you ask — and a value that
// came back in three pieces used to sail straight through.
//
// To make that work on a stream, the tail of the buffer is held back until
// enough bytes arrive to rule out a match straddling the boundary, so output
// lags by up to hold bytes. Flush releases the remainder.
type Redactor struct {
	mu       sync.Mutex
	w        io.Writer
	variants []variant
	buf      bytes.Buffer
	hold     int
}

type span struct {
	start, end int
	label      []byte
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
	r := &Redactor{
		w:        w,
		variants: build(secrets, func(n string) string { return "[REDACTED:" + n + "]" }),
	}
	// a wrapped value costs at most one newline per byte, so hold twice the
	// longest needle before deciding a match cannot still complete
	for _, v := range r.variants {
		if n := 2*len(v.needle) + 16; n > r.hold {
			r.hold = n
		}
	}
	return r
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

// stripped returns b without \r or \n, plus a map from each kept byte back to
// its index in b.
func stripped(b []byte) ([]byte, []int) {
	s := make([]byte, 0, len(b))
	idx := make([]int, 0, len(b))
	for i, c := range b {
		if c == '\n' || c == '\r' {
			continue
		}
		s = append(s, c)
		idx = append(idx, i)
	}
	return s, idx
}

func unclaimed(claimed []bool, start, end int) bool {
	for i := start; i < end; i++ {
		if claimed[i] {
			return false
		}
	}
	return true
}

// findSpans locates every variant in b, in the raw bytes and in the
// newline-stripped view, longest needle first so the biggest match wins.
func (r *Redactor) findSpans(b []byte) []span {
	if len(b) == 0 {
		return nil
	}
	var spans []span
	claimedRaw := make([]bool, len(b))
	sv, idx := stripped(b)
	claimedStripped := make([]bool, len(sv))

	claim := func(start, end int) {
		for i := start; i < end; i++ {
			claimedRaw[i] = true
		}
	}

	for _, v := range r.variants {
		// a needle that contains newlines can only be found in the raw bytes
		if bytes.ContainsAny(v.needle, "\r\n") {
			for off := 0; ; {
				i := bytes.Index(b[off:], v.needle)
				if i < 0 {
					break
				}
				s, e := off+i, off+i+len(v.needle)
				if unclaimed(claimedRaw, s, e) {
					spans = append(spans, span{s, e, v.label})
					claim(s, e)
				}
				off = s + 1
			}
			continue
		}
		for off := 0; off <= len(sv); {
			i := bytes.Index(sv[off:], v.needle)
			if i < 0 {
				break
			}
			s, e := off+i, off+i+len(v.needle)
			if unclaimed(claimedStripped, s, e) {
				rs, re := idx[s], idx[e-1]+1
				if unclaimed(claimedRaw, rs, re) {
					spans = append(spans, span{rs, re, v.label})
					for k := s; k < e; k++ {
						claimedStripped[k] = true
					}
					claim(rs, re)
				}
			}
			off = s + 1
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	return spans
}

// apply rewrites b[:limit], replacing every span that ends at or before limit.
func apply(b []byte, spans []span, limit int) []byte {
	out := make([]byte, 0, len(b))
	pos := 0
	for _, sp := range spans {
		if sp.end > limit {
			break
		}
		if sp.start < pos {
			continue
		}
		out = append(out, b[pos:sp.start]...)
		out = append(out, sp.label...)
		pos = sp.end
	}
	return append(out, b[pos:limit]...)
}

// emit writes everything that can no longer be part of a pending match.
// When final is set, the whole buffer goes.
func (r *Redactor) emit(final bool) error {
	b := r.buf.Bytes()
	if len(b) == 0 {
		return nil
	}
	spans := r.findSpans(b)

	limit := len(b)
	if !final {
		if limit -= r.hold; limit <= 0 {
			return nil
		}
		// never cut through a match that is still resolving
		for _, sp := range spans {
			if sp.start < limit && sp.end > limit {
				limit = sp.start
				break
			}
		}
		if limit <= 0 {
			return nil
		}
	}

	if _, err := r.w.Write(apply(b, spans, limit)); err != nil {
		return err
	}
	r.buf.Next(limit)
	return nil
}

func (r *Redactor) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf.Write(p)
	if err := r.emit(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes whatever is still held back.
func (r *Redactor) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.emit(true)
	r.buf.Reset()
	return err
}

// String scrubs a whole string at once (for hook/error text).
func (r *Redactor) String(s string) string {
	b := []byte(s)
	return string(apply(b, r.findSpans(b), len(b)))
}

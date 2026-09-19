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

type span struct {
	start, end int
	label      []byte
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
// lags by up to holdFor bytes. Flush releases the remainder.
type Redactor struct {
	mu       sync.Mutex
	w        io.Writer
	variants []variant
	buf      bytes.Buffer
	hold     int
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
	// a wrapped value costs at most one newline per byte, so hold twice the
	// longest needle before deciding a match cannot still complete
	for _, v := range r.variants {
		if n := 2*len(v.needle) + 16; n > r.hold {
			r.hold = n
		}
	}
	return r
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
	out = append(out, b[pos:limit]...)

	if _, err := r.w.Write(out); err != nil {
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
	spans := r.findSpans(b)
	out := make([]byte, 0, len(b))
	pos := 0
	for _, sp := range spans {
		if sp.start < pos {
			continue
		}
		out = append(out, b[pos:sp.start]...)
		out = append(out, sp.label...)
		pos = sp.end
	}
	return string(append(out, b[pos:]...))
}

// Package detect finds credentials in text a human is about to hand an agent:
// values the vault already holds (exact), and well-known token shapes (a
// fresh paste the vault has never seen). Each hit carries the name it should
// be stored under, so the caller can swap the value for {{NAME}}.
package detect

import (
	"regexp"
	"sort"
	"strings"
)

type Hit struct {
	Start, End int    // byte span of the value in the scanned text
	Value      string // the secret itself — never log this
	Name       string // vault name to use; for Known hits, the existing name
	Kind       string // pattern id, or "vault" for an exact match
	Known      bool   // Value is already in the vault under Name
}

type pattern struct {
	kind, name string
	re         *regexp.Regexp
	group      int // capture group holding the value; 0 = whole match
}

// Order matters only for overlap: earlier patterns win a contested span.
var patterns = []pattern{
	{"pem", "PRIVATE_KEY", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----`), 0},
	// Every open-ended class ends in \b: a token typed straight into the next
	// word must not swallow that word, or the same value is stored twice.
	{"anthropic", "ANTHROPIC_API_KEY", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`), 0},
	{"openai", "OPENAI_API_KEY", regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}\b`), 0},
	{"stripe", "STRIPE_KEY", regexp.MustCompile(`\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b`), 0},
	// GitHub prefixed tokens are not always exactly their canonical length in
	// the wild (truncation, test fakes), and a token-shaped run is never an
	// ordinary word — so the alnum run is open-ended at the top. The \b only
	// refuses a match that runs LETTERS INTO the next word, which a real
	// paste never does.
	{"github", "GITHUB_TOKEN", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9]{22,}_[A-Za-z0-9]{59,})\b`), 0},
	{"aws", "AWS_ACCESS_KEY_ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), 0},
	{"slack", "SLACK_TOKEN", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9\-]{10,}\b`), 0},
	{"google", "GOOGLE_API_KEY", regexp.MustCompile(`\bAIza[A-Za-z0-9_\-]{35}\b`), 0},
	{"jwt", "JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), 0},
	{"url-password", "DB_PASSWORD", regexp.MustCompile(`\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s@/]{6,})@`), 1},
	// KEY=value / password: value — the name comes from the text itself
	{"assignment", "", regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|_PW))\s*[:=]\s*["']?([^\s"'{}]{8,})`), 2},
	// "my key is X", "token: X", "password = X" — a human introducing a value
	// in plain words, in a format no prefix rule knows (gk_…, a vendor's own
	// shape). Only a credential-shaped value counts; see credentialShaped.
	{"phrase", "", regexp.MustCompile(`(?i)\b(api[ _-]?key|access[ _-]?key|key|token|password|passwd|secret|pat)\s*(?:is|was|=|:)\s*["'\x60]?([^\s"'\x60{}]{12,})`), 2},
}

// phraseNames maps the cue word to the vault name a phrase hit is stored as.
var phraseNames = map[string]string{
	"key": "API_KEY", "api key": "API_KEY", "api_key": "API_KEY", "api-key": "API_KEY", "apikey": "API_KEY",
	"access key": "ACCESS_KEY", "access_key": "ACCESS_KEY", "access-key": "ACCESS_KEY", "accesskey": "ACCESS_KEY",
	"token": "API_TOKEN", "pat": "API_TOKEN", "password": "PASSWORD", "passwd": "PASSWORD", "secret": "SECRET",
}

// credentialShaped: a word after "key is" is a credential when it could not
// be ordinary prose — it carries a digit, '_' or '-', or is 20+ characters.
// Owner call, 2026-09-27: capturing a word by mistake costs a rename; missing
// a key leaks it, so the bar is deliberately low.
func credentialShaped(v string) bool {
	return len(v) >= 20 || strings.ContainsAny(v, "0123456789_-")
}

// Find returns non-overlapping hits in text, in order. known maps vault
// names to values; values shorter than 8 bytes are ignored so a short
// secret cannot eat ordinary words.
func Find(text string, known map[string]string) []Hit {
	var hits []Hit
	taken := func(s, e int) bool {
		for _, h := range hits {
			if s < h.End && e > h.Start {
				return true
			}
		}
		return false
	}
	// exact vault matches first, longest value first
	names := make([]string, 0, len(known))
	for n, v := range known {
		if len(v) >= 8 {
			names = append(names, n)
		}
	}
	sort.Slice(names, func(i, j int) bool { return len(known[names[i]]) > len(known[names[j]]) })
	for _, n := range names {
		v := known[n]
		for off := 0; ; {
			i := strings.Index(text[off:], v)
			if i < 0 {
				break
			}
			s := off + i
			if !taken(s, s+len(v)) {
				hits = append(hits, Hit{Start: s, End: s + len(v), Value: v, Name: n, Kind: "vault", Known: true})
			}
			off = s + len(v)
		}
	}
	for _, p := range patterns {
		for _, m := range p.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := m[2*p.group], m[2*p.group+1]
			if s < 0 || taken(s, e) {
				continue
			}
			v := text[s:e]
			if strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "$") {
				continue // already a placeholder or a variable reference
			}
			name := p.name
			if p.kind == "phrase" {
				if !credentialShaped(v) {
					continue
				}
				name = phraseNames[strings.ToLower(text[m[2]:m[3]])]
			} else if name == "" {
				name = strings.ToUpper(strings.Trim(text[m[2]:m[3]], "_"))
			}
			if n, ok := nameOf(v, known); ok {
				hits = append(hits, Hit{Start: s, End: e, Value: v, Name: n, Kind: p.kind, Known: true})
				continue
			}
			hits = append(hits, Hit{Start: s, End: e, Value: v, Name: name, Kind: p.kind})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Start < hits[j].Start })
	return hits
}

func nameOf(v string, known map[string]string) (string, bool) {
	for n, kv := range known {
		if kv == v {
			return n, true
		}
	}
	return "", false
}

// Replace swaps each hit's span for {{NAME}} using the names in hits (the
// caller settles final names before calling).
func Replace(text string, hits []Hit) string {
	var b strings.Builder
	last := 0
	for _, h := range hits {
		b.WriteString(text[last:h.Start])
		b.WriteString("{{" + h.Name + "}}")
		last = h.End
	}
	b.WriteString(text[last:])
	return b.String()
}

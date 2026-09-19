// Package tmpl finds and fills {{NAME}} placeholders.
package tmpl

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var re = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// Names returns the distinct placeholder names in s, in first-seen order.
func Names(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// NamesIn collects placeholder names across many strings (argv, file body).
func NamesIn(parts ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		for _, n := range Names(p) {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Fill substitutes every placeholder from values. Unknown names are an error,
// never left in place — a half-filled template is worse than a refusal.
func Fill(s string, values map[string]string) (string, error) {
	var missing []string
	out := re.ReplaceAllStringFunc(s, func(m string) string {
		name := re.FindStringSubmatch(m)[1]
		v, ok := values[name]
		if !ok {
			missing = append(missing, name)
			return m
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("unresolved placeholders: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

func Has(s string) bool { return re.MatchString(s) }

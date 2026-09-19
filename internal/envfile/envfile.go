// Package envfile reads and edits dotenv files in place, preserving
// comments and unrelated lines. Files are always written 0600.
package envfile

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var keyRe = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$`)

// Keys returns the variable names defined in path (values are never returned).
func Keys(path string) ([]string, error) {
	lines, err := read(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range lines {
		if m := keyRe.FindStringSubmatch(l); m != nil {
			out = append(out, m[1])
		}
	}
	return out, nil
}

// Parse returns key→value for every assignment in path.
func Parse(path string) (map[string]string, []string, error) {
	lines, err := read(path)
	if err != nil {
		return nil, nil, err
	}
	vals := map[string]string{}
	var order []string
	for _, l := range lines {
		m := keyRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		vals[m[1]] = unquote(strings.TrimSpace(m[2]))
		order = append(order, m[1])
	}
	return vals, order, nil
}

// Set writes key=value into path, replacing an existing assignment or
// appending. Creates the file if missing.
func Set(path string, kv map[string]string) error {
	lines, err := read(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	done := map[string]bool{}
	for i, l := range lines {
		m := keyRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if v, ok := kv[m[1]]; ok {
			lines[i] = m[1] + "=" + quote(v)
			done[m[1]] = true
		}
	}
	for k, v := range kv {
		if !done[k] {
			lines = append(lines, k+"="+quote(v))
		}
	}
	return write(path, lines)
}

func read(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func write(path string, lines []string) error {
	tmp := path + ".sec-tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func quote(v string) string {
	if v == "" || strings.ContainsAny(v, " \t\n\"'#$\\`") {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v) + `"`
	}
	return v
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return strings.NewReplacer(`\n`, "\n", `\"`, `"`, `\\`, `\`).Replace(v[1 : len(v)-1])
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1]
	}
	// strip trailing unquoted comment
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

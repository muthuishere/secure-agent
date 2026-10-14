// Package policy is the one place that decides what counts as secret material
// on disk and which shell commands would print it. The pty filter, `sec sh`
// and `sec hook` all ask it, so a rule changes once and holds everywhere.
package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/muthuishere/secure-agent/internal/envfile"
	"github.com/muthuishere/secure-agent/internal/store"
)

// secretBases are file names that hold credentials wherever they live.
var secretBases = map[string]bool{
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	"credentials.json": true, "client_secret.json": true, "service-account.json": true,
	".netrc": true, "_netrc": true, ".git-credentials": true, ".npmrc": true, ".pypirc": true,
	".pgpass": true, "secrets.yaml": true, "secrets.yml": true, "secrets.json": true,
}

// secretExts are extensions of key and keystore files.
var secretExts = map[string]bool{
	".pem": true, ".key": true, ".p12": true, ".pfx": true, ".jks": true, ".keystore": true,
	".ppk": true, ".asc": true, ".gpg": true, ".kdbx": true,
}

// secretDirs are locations whose contents are all credential material,
// relative to the home directory.
var secretDirs = []string{".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gh", ".config/gcloud", ".azure"}

// IsSecretFile reports whether path names a file that holds secret values.
// Templates (.env.example…) and public keys are not secret.
func IsSecretFile(path string) bool {
	if path == "" {
		return false
	}
	p := expandHome(strings.Trim(path, `"'`))
	// a Windows path is judged the same on every OS
	slash := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(p), `\`, "/"))
	base := slash[strings.LastIndex(slash, "/")+1:]
	if strings.HasSuffix(base, ".pub") || envfile.IsTemplate(base) {
		return false
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return true
	}
	if secretBases[base] || secretExts[filepath.Ext(base)] {
		return true
	}
	abs := p
	if a, err := filepath.Abs(p); err == nil {
		abs = a
	}
	abs = strings.ToLower(strings.ReplaceAll(filepath.ToSlash(abs), `\`, "/"))
	if under(abs, strings.ToLower(filepath.ToSlash(store.Home()))) {
		return true
	}
	// ~/.ssh, /root/.aws, C:\Users\x\.kube — whoever's home it is
	for _, d := range secretDirs {
		if strings.Contains("/"+slash, "/"+d+"/") || strings.Contains(abs, "/"+d+"/") {
			return true
		}
	}
	return false
}

func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

// readers are commands whose job is to show, copy or transform a file's
// contents. Pointed at a secret file they are exfiltration: output redaction
// cannot be trusted there, because `rev`, `sed`, `base64 | fold` and friends
// reshape the value past any matcher.
var readers = map[string]bool{
	"cat": true, "bat": true, "head": true, "tail": true, "less": true, "more": true, "nl": true,
	"grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true, "awk": true, "gawk": true,
	"sed": true, "cut": true, "sort": true, "uniq": true, "tr": true, "rev": true, "tac": true,
	"strings": true, "xxd": true, "od": true, "hexdump": true, "base64": true, "base32": true,
	"cp": true, "scp": true, "rsync": true, "mv": true, "tee": true, "dd": true,
	"python": true, "python3": true, "node": true, "ruby": true, "perl": true, "jq": true, "yq": true,
	"vim": true, "vi": true, "nano": true, "emacs": true, "code": true, "open": true,
	"type": true, "get-content": true, "gc": true, "select-string": true, "copy": true, "copy-item": true,
	"curl": true, "wget": true, "nc": true, "zip": true, "tar": true, "gzip": true,
}

// Refusal says why a command was refused and what to run instead.
type Refusal struct {
	File, Verb, Hint string
}

func (r *Refusal) Error() string {
	return "sec: refused — `" + r.Verb + "` would print " + r.File + ", which holds secrets. " + r.Hint
}

// CheckCommand refuses a shell command line that reads a secret file with a
// reader verb. Anything else is allowed: its output is redacted instead.
func CheckCommand(cmd string) *Refusal {
	for _, seg := range segments(cmd) {
		words := fields(seg)
		verb := ""
		for i, w := range words {
			if verb == "" {
				if isAssignment(w) || w == "sudo" || w == "command" || w == "exec" || w == "time" || w == "env" && i+1 < len(words) && !strings.HasPrefix(words[i+1], "-") {
					continue
				}
				verb = strings.ToLower(filepath.Base(w))
				verb = strings.TrimSuffix(verb, ".exe")
				continue
			}
			target := strings.TrimPrefix(w, "@") // curl -d @.env
			if i := strings.LastIndexByte(target, '='); i >= 0 && strings.HasPrefix(target, "-") {
				target = target[i+1:] // --data-binary=@.env, --file=.env
				target = strings.TrimPrefix(target, "@")
			}
			if readers[verb] && IsSecretFile(target) {
				return &Refusal{File: target, Verb: verb, Hint: hintFor(target)}
			}
		}
		// input redirection feeds the file to anything: `cmd < .env`
		for _, m := range redirIn.FindAllStringSubmatch(seg, -1) {
			if IsSecretFile(m[1]) {
				return &Refusal{File: m[1], Verb: "<", Hint: hintFor(m[1])}
			}
		}
	}
	return nil
}

var redirIn = regexp.MustCompile(`<\s*("[^"]+"|'[^']+'|[^\s;&|<>()]+)`)

func hintFor(file string) string {
	base := strings.ToLower(filepath.Base(file))
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return "For its key names: `sec env ls " + file + "`. To use a value: `sec exec -- <cmd with {{NAME}}>` or `sec run NAME -- <cmd>`. To bring it into the vault: `sec import " + file + "`."
	}
	return "Use it through a program that needs it (it is passed by path, not printed), or ask the owner."
}

func isAssignment(w string) bool {
	i := strings.IndexByte(w, '=')
	return i > 0 && !strings.ContainsAny(w[:i], "-/.$")
}

// segments splits a command line at ; && || | and newlines — the boundaries
// where a new verb begins. Quotes are respected well enough for a guard: it
// errs towards seeing more verbs, never fewer.
func segments(cmd string) []string {
	var out []string
	var b strings.Builder
	var q byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
			b.WriteByte(c)
		case c == '\'' || c == '"':
			q = c
			b.WriteByte(c)
		case c == ';' || c == '|' || c == '&' || c == '\n' || c == '(' || c == ')' || c == '`':
			out = append(out, b.String())
			b.Reset()
		case c == '$' && i+1 < len(cmd) && cmd[i+1] == '(':
			out = append(out, b.String())
			b.Reset()
			i++
		default:
			b.WriteByte(c)
		}
	}
	return append(out, b.String())
}

// fields splits a segment into words, dropping quotes.
func fields(seg string) []string {
	var out []string
	var b strings.Builder
	var q byte
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else {
				b.WriteByte(c)
			}
		case c == '\'' || c == '"':
			q = c
		case c == ' ' || c == '\t':
			flush()
		case c == '<' || c == '>':
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return out
}

// secretEnvName matches environment variable names that hold credentials by
// convention.
var secretEnvName = regexp.MustCompile(`(?i)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|_PW|CREDENTIAL|PRIVATE|AUTH)`)

// RedactionSet is every value that must never appear in output: the vault,
// the values of every dotenv file in the working tree, and credential-named
// variables in the environment. Values shorter than 8 bytes are left out —
// they would scrub ordinary words.
func RedactionSet(vault map[string]string, root string) map[string]string {
	out := map[string]string{}
	add := func(name, v string) {
		v = strings.TrimSpace(v)
		if len(v) < 8 {
			return
		}
		if _, dup := out[name]; dup {
			name = name + "_" + shortHash(v)
		}
		out[name] = v
	}
	for n, v := range vault {
		add(n, v)
	}
	if files, err := envfile.Discover(root, 4); err == nil {
		for _, f := range files {
			kv, _, err := envfile.Parse(filepath.Join(root, f.Path))
			if err != nil {
				continue
			}
			for k, v := range kv {
				add(k, v)
			}
		}
	}
	for _, e := range os.Environ() {
		k, v, ok := strings.Cut(e, "=")
		if ok && secretEnvName.MatchString(k) {
			add(k, v)
		}
	}
	return out
}

func shortHash(s string) string {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	const hex = "0123456789abcdef"
	return string([]byte{hex[h>>28], hex[h>>24&15], hex[h>>20&15], hex[h>>16&15]})
}

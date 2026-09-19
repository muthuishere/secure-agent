// Package store is the on-disk vault: an age identity, a recipients list,
// one ciphertext file per secret plus a JSON sidecar of metadata, and an
// append-only audit log.
//
//	$SEC_HOME (default ~/.config/sec)/
//	  identity.txt      age secret key, 0600 — the one thing to back up
//	  recipients.txt    age public keys allowed to decrypt (own key + teammates)
//	  vault/NAME.age    current ciphertext
//	  vault/NAME.v3.age retired version 3 (kept for --undo)
//	  vault/NAME.json   metadata: version, tags, source, placements
//	  audit.ndjson      every decrypt / write / rotate, who and when
//
// vault/ holds only ciphertext + names, so it is safe to git-commit or
// rclone to a bucket; sync is deliberately not this tool's job.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Placement struct {
	Type      string    `json:"type"`               // file | render | gh | gcp
	Path      string    `json:"path,omitempty"`     // file/render: output path
	Var       string    `json:"var,omitempty"`      // file: env var name
	Template  string    `json:"template,omitempty"` // render: template path
	Repo      string    `json:"repo,omitempty"`     // gh: owner/name
	Env       string    `json:"env,omitempty"`      // gh: environment ("" = repo-level)
	Project   string    `json:"project,omitempty"`  // gcp
	Secret    string    `json:"secret,omitempty"`   // gh/gcp: remote secret name
	UpdatedAt time.Time `json:"updated_at"`
}

func (p Placement) String() string {
	switch p.Type {
	case "file":
		return fmt.Sprintf("file   %s  (%s)", p.Path, p.Var)
	case "render":
		return fmt.Sprintf("render %s  <- %s", p.Path, p.Template)
	case "gh":
		if p.Env != "" {
			return fmt.Sprintf("gh     %s  env=%s  %s", p.Repo, p.Env, p.Secret)
		}
		return fmt.Sprintf("gh     %s  repo-level  %s", p.Repo, p.Secret)
	case "gcp":
		return fmt.Sprintf("gcp    project=%s  %s", p.Project, p.Secret)
	}
	return p.Type
}

func (p Placement) Key() string {
	return strings.Join([]string{p.Type, p.Path, p.Var, p.Template, p.Repo, p.Env, p.Project, p.Secret}, "|")
}

type Retired struct {
	Version   int       `json:"version"`
	RetiredAt time.Time `json:"retired_at"`
	Reason    string    `json:"reason,omitempty"`
}

type Meta struct {
	Name       string      `json:"name"`
	Version    int         `json:"version"`
	Created    time.Time   `json:"created"`
	Updated    time.Time   `json:"updated"`
	Tags       []string    `json:"tags,omitempty"`
	Source     string      `json:"source,omitempty"` // where it is minted/revoked (URL or note)
	Placements []Placement `json:"placements,omitempty"`
	Retired    []Retired   `json:"retired,omitempty"`
}

func (m *Meta) AddPlacement(p Placement) {
	p.UpdatedAt = time.Now().UTC()
	for i, q := range m.Placements {
		if q.Key() == p.Key() {
			m.Placements[i] = p
			return
		}
	}
	m.Placements = append(m.Placements, p)
}

type Store struct {
	Home       string
	identity   *age.X25519Identity
	recipients []age.Recipient
	backend    Backend
}

// Backend reports where this vault's identity is kept.
func (s *Store) BackendName() Backend { return s.backend }

var runtimeGOOS = runtime.GOOS

func Home() string {
	if h := os.Getenv("SEC_HOME"); h != "" {
		return h
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "sec")
}

func (s *Store) vaultDir() string       { return filepath.Join(s.Home, "vault") }
func (s *Store) identityPath() string   { return filepath.Join(s.Home, "identity.txt") }
func (s *Store) recipientsPath() string { return filepath.Join(s.Home, "recipients.txt") }
func (s *Store) AuditPath() string      { return filepath.Join(s.Home, "audit.ndjson") }
func (s *Store) CertDir() string        { return filepath.Join(s.Home, "ca") }
func (s *Store) cipherPath(name string, version int) string {
	if version > 0 {
		return filepath.Join(s.vaultDir(), fmt.Sprintf("%s.v%d.age", name, version))
	}
	return filepath.Join(s.vaultDir(), name+".age")
}
func (s *Store) metaPath(name string) string { return filepath.Join(s.vaultDir(), name+".json") }

// Initialized reports whether an identity exists.
func Initialized() bool {
	_, err := os.Stat(filepath.Join(Home(), "identity.txt"))
	return err == nil
}

// Init creates the home dir and an age identity, stored in the given backend
// (empty = DefaultBackend). importFrom, if set, is an existing age identity
// file to adopt instead of generating one.
func Init(importFrom string, backend Backend) (*Store, error) {
	s := &Store{Home: Home()}
	if _, err := os.Stat(s.markerPath()); err == nil {
		return nil, fmt.Errorf("already initialised: %s", s.Home)
	}
	if _, err := os.Stat(s.identityPath()); err == nil {
		return nil, fmt.Errorf("already initialised: %s", s.identityPath())
	}
	if err := os.MkdirAll(s.vaultDir(), 0o700); err != nil {
		return nil, err
	}
	var id *age.X25519Identity
	if importFrom != "" {
		b, err := os.ReadFile(importFrom)
		if err != nil {
			return nil, err
		}
		ids, err := age.ParseIdentities(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		x, ok := ids[0].(*age.X25519Identity)
		if !ok {
			return nil, errors.New("only X25519 identities are supported")
		}
		id = x
	} else {
		var err error
		id, err = age.GenerateX25519Identity()
		if err != nil {
			return nil, err
		}
	}
	if backend == "" {
		backend = DefaultBackend()
	}
	if err := s.saveIdentity(backend, id); err != nil {
		return nil, err
	}
	if _, err := os.Stat(s.recipientsPath()); err != nil {
		if err := os.WriteFile(s.recipientsPath(), []byte(id.Recipient().String()+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	return Open()
}

// Open loads the identity (env, keyring, or file) and the recipients list.
func Open() (*Store, error) {
	s := &Store{Home: Home()}
	id, backend, err := s.loadIdentity()
	if err != nil {
		return nil, err
	}
	s.identity, s.backend = id, backend
	rb, err := os.ReadFile(s.recipientsPath())
	if err != nil {
		return nil, err
	}
	recs, err := age.ParseRecipients(bytes.NewReader(rb))
	if err != nil {
		return nil, fmt.Errorf("recipients: %w", err)
	}
	s.recipients = recs
	return s, nil
}

func (s *Store) PublicKey() string { return s.identity.Recipient().String() }

func (s *Store) Recipients() ([]string, error) {
	b, err := os.ReadFile(s.recipientsPath())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, nil
}

// AddRecipient appends a public key; existing secrets must be re-encrypted
// (ReencryptAll) for the new recipient to read them.
func (s *Store) AddRecipient(pub string) error {
	if _, err := age.ParseX25519Recipient(pub); err != nil {
		return err
	}
	f, err := os.OpenFile(s.recipientsPath(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, pub)
	return err
}

func (s *Store) ReencryptAll() (int, error) {
	fresh, err := Open()
	if err != nil {
		return 0, err
	}
	s.recipients = fresh.recipients
	names, err := s.List()
	if err != nil {
		return 0, err
	}
	for _, n := range names {
		v, err := s.Get(n)
		if err != nil {
			return 0, err
		}
		if err := s.encryptTo(s.cipherPath(n, 0), v); err != nil {
			return 0, err
		}
	}
	return len(names), nil
}

func ValidName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid secret name %q (use A-Z, 0-9, _)", name)
	}
	return nil
}

func (s *Store) Exists(name string) bool {
	_, err := os.Stat(s.cipherPath(name, 0))
	return err == nil
}

func (s *Store) encryptTo(path string, value []byte) error {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.recipients...)
	if err != nil {
		return err
	}
	if _, err := w.Write(value); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Set stores value as the current version. An existing value is retired
// (kept as NAME.v<N>.age) so rotate --undo can bring it back.
func (s *Store) Set(name string, value []byte, reason string) (*Meta, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	m, err := s.Meta(name)
	if errors.Is(err, os.ErrNotExist) {
		m = &Meta{Name: name, Version: 0, Created: now}
	} else if err != nil {
		return nil, err
	}
	if m.Version > 0 {
		if err := os.Rename(s.cipherPath(name, 0), s.cipherPath(name, m.Version)); err != nil {
			return nil, err
		}
		m.Retired = append(m.Retired, Retired{Version: m.Version, RetiredAt: now, Reason: reason})
	}
	m.Version++
	m.Updated = now
	if err := s.encryptTo(s.cipherPath(name, 0), value); err != nil {
		return nil, err
	}
	return m, s.SaveMeta(m)
}

// Get decrypts the current value.
func (s *Store) Get(name string) ([]byte, error) { return s.GetVersion(name, 0) }

func (s *Store) GetVersion(name string, version int) ([]byte, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	f, err := os.Open(s.cipherPath(name, version))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no such secret: %s", name)
		}
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, s.identity)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (is your key in recipients.txt?)", name, err)
	}
	return io.ReadAll(r)
}

// Resolve decrypts many names at once; a single missing name fails the lot.
func (s *Store) Resolve(names []string) (map[string]string, error) {
	out := map[string]string{}
	var missing []string
	for _, n := range names {
		if !s.Exists(n) {
			missing = append(missing, n)
			continue
		}
		v, err := s.Get(n)
		if err != nil {
			return nil, err
		}
		out[n] = string(v)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("unknown secret(s): %s — ask the owner to `sec set` them", strings.Join(missing, ", "))
	}
	return out, nil
}

func (s *Store) Delete(name string) error {
	m, err := s.Meta(name)
	if err != nil {
		return err
	}
	for _, r := range m.Retired {
		os.Remove(s.cipherPath(name, r.Version))
	}
	if err := os.Remove(s.cipherPath(name, 0)); err != nil {
		return err
	}
	return os.Remove(s.metaPath(name))
}

// PurgeRetired drops retired ciphertexts (after the old value is revoked upstream).
func (s *Store) PurgeRetired(name string) (int, error) {
	m, err := s.Meta(name)
	if err != nil {
		return 0, err
	}
	n := len(m.Retired)
	for _, r := range m.Retired {
		os.Remove(s.cipherPath(name, r.Version))
	}
	m.Retired = nil
	return n, s.SaveMeta(m)
}

func (s *Store) Meta(name string) (*Meta, error) {
	b, err := os.ReadFile(s.metaPath(name))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", s.metaPath(name), err)
	}
	return &m, nil
}

func (s *Store) SaveMeta(m *Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(m.Name), append(b, '\n'), 0o600)
}

func (s *Store) List() ([]string, error) {
	ents, err := os.ReadDir(s.vaultDir())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, ".json") {
			out = append(out, strings.TrimSuffix(n, ".json"))
		}
	}
	sort.Strings(out)
	return out, nil
}

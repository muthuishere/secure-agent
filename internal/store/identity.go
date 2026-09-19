// Identity storage. The age secret key is the one thing that decrypts the
// vault, so where it lives matters more than anything else in this tool.
//
// Three backends, same abstraction Bun.secrets gives JS — macOS Keychain,
// Linux Secret Service (gnome-keyring/KWallet over DBus), Windows Credential
// Manager — plus a file, because a headless Linux server has no Secret
// Service and a container has no keyring at all:
//
//	env      SEC_IDENTITY holds the key itself — CI, containers, prod
//	keyring  OS credential store (default wherever one answers)
//	file     identity.txt, 0400 (default otherwise)
//
// A marker file (identity.json) records which backend is in use and caches
// the public key, so `sec identity` can report without unlocking anything.
//
// What keyring actually buys: no plaintext key on disk. A stolen disk image,
// a Time Machine backup, an rclone of the wrong directory, a stray tar of
// ~/.config — none of them carry the key. It does NOT stop a process running
// as you from asking the keyring for it; that is the same exposure as a 0600
// file, and no backend here changes it.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
)

type Backend string

const (
	BackendKeyring Backend = "keyring"
	BackendFile    Backend = "file"
	BackendEnv     Backend = "env"

	keyringService = "tools.sec"
)

type identityMarker struct {
	Backend   Backend `json:"backend"`
	PublicKey string  `json:"public_key"`
	Note      string  `json:"note,omitempty"`
}

func (s *Store) markerPath() string { return filepath.Join(s.Home, "identity.json") }

// keyringAccount scopes the entry to this vault, so two SEC_HOMEs (real and
// a test one) never fight over the same keychain item.
func (s *Store) keyringAccount() string { return s.Home }

func (s *Store) readMarker() (*identityMarker, error) {
	b, err := os.ReadFile(s.markerPath())
	if err != nil {
		return nil, err
	}
	var m identityMarker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", s.markerPath(), err)
	}
	return &m, nil
}

func (s *Store) writeMarker(m *identityMarker) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.markerPath(), append(b, '\n'), 0o644)
}

// KeyringAvailable probes the OS credential store with a throwaway item.
// Headless Linux and containers fail here, which is the point.
func KeyringAvailable() bool {
	const probe = "sec-probe"
	if err := keyring.Set(keyringService, probe, "probe"); err != nil {
		return false
	}
	v, err := keyring.Get(keyringService, probe)
	keyring.Delete(keyringService, probe)
	return err == nil && v == "probe"
}

// DefaultBackend picks keyring when one answers, file otherwise.
func DefaultBackend() Backend {
	if KeyringAvailable() {
		return BackendKeyring
	}
	return BackendFile
}

func parseIdentity(raw string) (*age.X25519Identity, error) {
	ids, err := age.ParseIdentities(strings.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errors.New("no identity found")
	}
	x, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, errors.New("identity is not X25519")
	}
	return x, nil
}

// saveIdentity writes the key to the chosen backend and records the marker.
// The value is never logged, echoed, or passed on a command line.
func (s *Store) saveIdentity(b Backend, id *age.X25519Identity) error {
	switch b {
	case BackendKeyring:
		if err := keyring.Set(keyringService, s.keyringAccount(), id.String()); err != nil {
			return fmt.Errorf("keyring: %w", err)
		}
		// read back before anyone relies on it
		got, err := keyring.Get(keyringService, s.keyringAccount())
		if err != nil || got != id.String() {
			return fmt.Errorf("keyring write could not be verified — not switching backend")
		}
	case BackendFile:
		body := fmt.Sprintf("# sec identity\n# public key: %s\n%s\n", id.Recipient(), id)
		if err := os.WriteFile(s.identityPath(), []byte(body), 0o600); err != nil {
			return err
		}
		// 0400: we never rewrite this file, so read-only catches an accidental
		// clobber. It does not (and cannot) stop a read — that is what the
		// keyring backend is for.
		if err := os.Chmod(s.identityPath(), 0o400); err != nil {
			return err
		}
	default:
		return fmt.Errorf("cannot save to backend %q", b)
	}
	note := ""
	if b == BackendFile {
		note = "back up identity.txt — the vault is unrecoverable without it"
	} else {
		note = "key is in the OS credential store; export a backup with `sec identity export`"
	}
	return s.writeMarker(&identityMarker{Backend: b, PublicKey: id.Recipient().String(), Note: note})
}

// loadIdentity resolves the key: env, then the marker's backend, then a bare
// identity.txt (vaults created before backends existed).
func (s *Store) loadIdentity() (*age.X25519Identity, Backend, error) {
	if raw := os.Getenv("SEC_IDENTITY"); raw != "" {
		id, err := parseIdentity(raw)
		if err != nil {
			return nil, BackendEnv, fmt.Errorf("SEC_IDENTITY: %w", err)
		}
		return id, BackendEnv, nil
	}
	m, err := s.readMarker()
	if err == nil && m.Backend == BackendKeyring {
		raw, err := keyring.Get(keyringService, s.keyringAccount())
		if err != nil {
			return nil, BackendKeyring, fmt.Errorf("keyring has no identity for %s: %w\n  (moved machines? restore with `sec identity import <backup>`)", s.Home, err)
		}
		id, err := parseIdentity(raw)
		return id, BackendKeyring, err
	}
	b, err := os.ReadFile(s.identityPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, BackendFile, fmt.Errorf("not initialised — run `sec init` (home: %s)", s.Home)
		}
		return nil, BackendFile, err
	}
	id, err := parseIdentity(string(b))
	return id, BackendFile, err
}

// IdentityInfo is what `sec identity` reports — never the key itself.
type IdentityInfo struct {
	Backend   Backend `json:"backend"`
	PublicKey string  `json:"public_key"`
	Location  string  `json:"location"`
	Note      string  `json:"note,omitempty"`
}

func (s *Store) IdentityInfo() IdentityInfo {
	info := IdentityInfo{Backend: s.backend, PublicKey: s.PublicKey()}
	switch s.backend {
	case BackendEnv:
		info.Location = "$SEC_IDENTITY (this process only)"
	case BackendKeyring:
		info.Location = fmt.Sprintf("%s: service=%s account=%s", keyringName(), keyringService, s.keyringAccount())
	case BackendFile:
		info.Location = s.identityPath()
	}
	if m, err := s.readMarker(); err == nil {
		info.Note = m.Note
	}
	return info
}

// MoveIdentity switches backends, verifying the new location reads back
// before the old copy is removed.
func (s *Store) MoveIdentity(to Backend) error {
	if s.backend == to {
		return fmt.Errorf("identity is already in %s", to)
	}
	if to == BackendEnv {
		return errors.New("SEC_IDENTITY is set by the environment, not by this command — see `sec identity export`")
	}
	if to == BackendKeyring && !KeyringAvailable() {
		return errors.New("no OS credential store answered (headless Linux or container?) — keep the file backend, or set SEC_IDENTITY")
	}
	if err := s.saveIdentity(to, s.identity); err != nil {
		return err
	}
	switch s.backend {
	case BackendKeyring:
		if err := keyring.Delete(keyringService, s.keyringAccount()); err != nil {
			return fmt.Errorf("saved to %s but could not clear the keyring entry: %w", to, err)
		}
	case BackendFile:
		os.Chmod(s.identityPath(), 0o600)
		if err := os.Remove(s.identityPath()); err != nil {
			return fmt.Errorf("saved to %s but could not remove %s: %w", to, s.identityPath(), err)
		}
	}
	s.backend = to
	return nil
}

// ExportIdentity writes the key to a file so it can be put in a password
// manager or carried to another machine. Owner-gated by the caller.
func (s *Store) ExportIdentity(path string) error {
	body := fmt.Sprintf("# sec identity backup — public key: %s\n%s\n", s.PublicKey(), s.identity)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return err
	}
	return nil
}

// ImportIdentity replaces the current identity from a backup file.
func (s *Store) ImportIdentity(path string, to Backend) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	id, err := parseIdentity(string(b))
	if err != nil {
		return err
	}
	if err := s.saveIdentity(to, id); err != nil {
		return err
	}
	s.identity, s.backend = id, to
	return nil
}

func keyringName() string {
	switch runtimeGOOS {
	case "darwin":
		return "macOS Keychain"
	case "windows":
		return "Windows Credential Manager"
	default:
		return "Secret Service"
	}
}

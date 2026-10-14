package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// SharedItem is one secret inside a share bundle.
type SharedItem struct {
	Name  string `json:"name"`
	Kind  string `json:"kind,omitempty"`
	Value []byte `json:"value"`
}

// Seal encrypts items to another sec instance's public key. The armored
// output is safe to paste anywhere: only the holder of that key can open it.
func Seal(recipient string, items []SharedItem) ([]byte, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, fmt.Errorf("not a sec/age public key (age1…): %w", err)
	}
	plain, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Open decrypts a share bundle addressed to this vault's key.
func (s *Store) Open(bundle []byte) ([]SharedItem, error) {
	var src io.Reader = bytes.NewReader(bundle)
	if bytes.HasPrefix(bytes.TrimSpace(bundle), []byte("-----BEGIN AGE")) {
		src = armor.NewReader(bytes.NewReader(bytes.TrimSpace(bundle)))
	}
	r, err := age.Decrypt(src, s.identity)
	if err != nil {
		return nil, fmt.Errorf("can't open this share — it was sealed for a different sec key: %w", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var items []SharedItem
	if err := json.Unmarshal(plain, &items); err != nil {
		return nil, fmt.Errorf("not a sec share: %w", err)
	}
	return items, nil
}

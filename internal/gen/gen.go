// Package gen makes random passwords with crypto/rand.
package gen

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!@#$%^&*-_=+.:,;?"
)

type Options struct {
	Length  int
	Symbols bool
	Hex     bool // hex string of Length bytes, for tokens/keys
}

func Password(o Options) (string, error) {
	if o.Length <= 0 {
		o.Length = 32
	}
	if o.Hex {
		b := make([]byte, o.Length)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		const hx = "0123456789abcdef"
		out := make([]byte, o.Length*2)
		for i, c := range b {
			out[i*2], out[i*2+1] = hx[c>>4], hx[c&0xf]
		}
		return string(out), nil
	}
	alphabet := lower + upper + digits
	if o.Symbols {
		alphabet += symbols
	}
	if o.Length < 4 {
		return "", errors.New("length must be >= 4")
	}
	for {
		out := make([]byte, o.Length)
		for i := range out {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return "", err
			}
			out[i] = alphabet[n.Int64()]
		}
		s := string(out)
		// require every class present so the result passes naive policies
		if has(s, lower) && has(s, upper) && has(s, digits) && (!o.Symbols || has(s, symbols)) {
			return s, nil
		}
	}
}

func has(s, class string) bool {
	for _, c := range s {
		for _, k := range class {
			if c == k {
				return true
			}
		}
	}
	return false
}

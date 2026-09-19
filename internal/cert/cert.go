// Package cert issues local TLS material: a per-machine CA and leaf certs
// signed by it (mkcert-style), or plain self-signed certs. ECDSA P-256.
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Files struct {
	Cert, Key string
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// CA creates dir/ca.pem + dir/ca-key.pem if missing.
func CA(dir, name string, days int) (Files, bool, error) {
	f := Files{Cert: filepath.Join(dir, "ca.pem"), Key: filepath.Join(dir, "ca-key.pem")}
	if _, err := os.Stat(f.Cert); err == nil {
		return f, false, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return f, false, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return f, false, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"sec local CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, days),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return f, false, err
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	if err := writePEM(f.Key, "EC PRIVATE KEY", kd, 0o600); err != nil {
		return f, false, err
	}
	return f, true, writePEM(f.Cert, "CERTIFICATE", der, 0o644)
}

func loadCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, nil, errors.New("no CA yet — run `sec cert ca`")
	}
	kb, err := os.ReadFile(filepath.Join(dir, "ca-key.pem"))
	if err != nil {
		return nil, nil, err
	}
	cp, _ := pem.Decode(cb)
	kp, _ := pem.Decode(kb)
	if cp == nil || kp == nil {
		return nil, nil, errors.New("CA files are not PEM")
	}
	c, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParseECPrivateKey(kp.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return c, k, nil
}

func leafTemplate(cn string, sans []string, days int) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	all := append([]string{cn}, sans...)
	for _, s := range all {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, s)
		}
	}
	return tpl
}

// Issue signs a leaf for cn+sans with the CA in caDir, writing outDir/<cn>.pem
// and outDir/<cn>-key.pem.
func Issue(caDir, outDir, cn string, sans []string, days int) (Files, error) {
	ca, caKey, err := loadCA(caDir)
	if err != nil {
		return Files{}, err
	}
	return sign(outDir, cn, sans, days, ca, caKey)
}

// SelfSigned writes a standalone cert (no CA).
func SelfSigned(outDir, cn string, sans []string, days int) (Files, error) {
	return sign(outDir, cn, sans, days, nil, nil)
}

func sign(outDir, cn string, sans []string, days int, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (Files, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Files{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Files{}, err
	}
	tpl := leafTemplate(cn, sans, days)
	parent, signer := tpl, any(key)
	if ca != nil {
		parent, signer = ca, caKey
	} else {
		tpl.IsCA = false
		tpl.BasicConstraintsValid = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signer)
	if err != nil {
		return Files{}, err
	}
	base := strings.NewReplacer("*", "_wildcard", "/", "_", " ", "_").Replace(cn)
	f := Files{Cert: filepath.Join(outDir, base+".pem"), Key: filepath.Join(outDir, base+"-key.pem")}
	kd, _ := x509.MarshalECPrivateKey(key)
	if err := writePEM(f.Key, "EC PRIVATE KEY", kd, 0o600); err != nil {
		return f, err
	}
	if err := writePEM(f.Cert, "CERTIFICATE", der, 0o644); err != nil {
		return f, err
	}
	return f, nil
}

// TrustCommand returns the OS command that trusts the CA for the current user.
func TrustCommand(caPem string) string {
	home, _ := os.UserHomeDir()
	return fmt.Sprintf("security add-trusted-cert -r trustRoot -k %s/Library/Keychains/login.keychain-db %s", home, caPem)
}

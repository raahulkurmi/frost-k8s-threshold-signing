package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CertPaths is a cert/key pair on disk.
type CertPaths struct{ Cert, Key string }

// PKI is a throwaway CA and the leaf certs issued from it, mirroring
// scripts/gen-certs.sh: SAN DNS:coordinator (clientAuth), DNS:signer-<i> (serverAuth).
type PKI struct {
	Dir    string
	CA     string // CA cert path
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

// NewPKI creates a CA in t.TempDir().
func NewPKI(t testing.TB) *PKI {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	p := &PKI{Dir: dir, CA: filepath.Join(dir, "ca.crt"), caCert: cert, caKey: key}
	writePEM(t, p.CA, "CERTIFICATE", der, 0o644)
	return p
}

// Issue creates a leaf cert with the given DNS SANs and EKU.
func (p *PKI) Issue(t testing.TB, name string, sans []string, eku x509.ExtKeyUsage) CertPaths {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cp := CertPaths{Cert: filepath.Join(p.Dir, name+".crt"), Key: filepath.Join(p.Dir, name+".key")}
	writePEM(t, cp.Cert, "CERTIFICATE", der, 0o644)
	writePEM(t, cp.Key, "EC PRIVATE KEY", kd, 0o600)
	return cp
}

// Coordinator issues the coordinator client cert.
func (p *PKI) Coordinator(t testing.TB) CertPaths {
	return p.Issue(t, "coordinator", []string{"coordinator"}, x509.ExtKeyUsageClientAuth)
}

// Signer issues signer-<i>'s server cert.
func (p *PKI) Signer(t testing.TB, i int) CertPaths {
	name := "signer-" + itoa(i)
	return p.Issue(t, name, []string{name}, x509.ExtKeyUsageServerAuth)
}

func itoa(i int) string { return big.NewInt(int64(i)).String() }

func serial(t testing.TB) *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func writePEM(t testing.TB, path, typ string, der []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode); err != nil {
		t.Fatal(err)
	}
}

package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

type ECDSAKey struct {
	key *ecdsa.PrivateKey
}

func NewECDSAKey(path string) (*ECDSAKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				fmt.Printf("[signing] Loaded ECDSA key from %s\n", path)
				return &ECDSAKey{key: key}, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create key file: %w", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		return nil, fmt.Errorf("encode key: %w", err)
	}

	fmt.Printf("[signing] Generated new ECDSA key at %s\n", path)
	return &ECDSAKey{key: key}, nil
}

func (e *ECDSAKey) PublicKeyPKIX() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&e.key.PublicKey)
}

// SignES256 signs using IEEE P1363 format (R || S) — required by go-jose/JWT
// NOT DER/ASN1 format
func (e *ECDSAKey) SignES256(signingInput string) (string, error) {
	hash := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, e.key, hash[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}

	// IEEE P1363 format: R || S, each padded to curve size (32 bytes for P256)
	curveSize := 32
	rBytes := padLeft(r.Bytes(), curveSize)
	sBytes := padLeft(s.Bytes(), curveSize)

	sig := append(rBytes, sBytes...)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// for reference only
var _ = big.NewInt

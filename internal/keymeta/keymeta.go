// Package keymeta holds the PUBLIC metadata of a threshold RSA key: the group
// public key, the Shoup share verification keys, t, n and the key ID.
//
// It contains no secret material and is the only key package the coordinator
// may import (invariant I3, enforced by TestCoordinatorHasNoSecretTypes).
package keymeta

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/niclabs/tcrsa"
)

const (
	// FormatVersion is the public-meta.json schema version.
	FormatVersion = 1
	// Algorithm is the only JWS algorithm this system issues.
	Algorithm = "RS256"
	// MinModulusBits is the smallest RSA modulus accepted anywhere.
	MinModulusBits = 2048
	// kidBytes is how many bytes of SHA-256(PKIX DER) form the key ID.
	kidBytes = 16
)

// VerificationKey is the JSON form of tcrsa.VerificationKey (all base64 std).
type VerificationKey struct {
	V string   `json:"v"`
	U string   `json:"u"`
	I []string `json:"i"`
}

// File is the on-disk public-meta.json. Every field is public.
type File struct {
	Version         int             `json:"version"`
	KID             string          `json:"kid"`
	Algorithm       string          `json:"algorithm"`
	Threshold       int             `json:"threshold"`
	Parties         int             `json:"parties"`
	ModulusBits     int             `json:"modulus_bits"`
	PublicKeyPKIX   string          `json:"public_key_pkix"`
	VerificationKey VerificationKey `json:"verification_key"`
	CreatedAt       time.Time       `json:"created_at"`
}

// Meta is a parsed, validated public-meta.json.
type Meta struct {
	KID         string
	Threshold   int
	Parties     int
	ModulusBits int
	PKIX        []byte
	PublicKey   *rsa.PublicKey
	CreatedAt   time.Time
	// Tcrsa is the library view of the public metadata, used for share
	// verification and Join.
	Tcrsa *tcrsa.KeyMeta
}

// ComputeKID returns base64url(SHA-256(pkixDER)[:16]), a 22-character key ID.
func ComputeKID(pkixDER []byte) string {
	sum := sha256.Sum256(pkixDER)
	return base64.RawURLEncoding.EncodeToString(sum[:kidBytes])
}

// FromTcrsa builds the public file from a freshly generated tcrsa key meta.
func FromTcrsa(m *tcrsa.KeyMeta, createdAt time.Time) (*File, error) {
	if m == nil || m.PublicKey == nil || m.VerificationKey == nil {
		return nil, errors.New("keymeta: nil tcrsa meta")
	}
	pkix, err := x509.MarshalPKIXPublicKey(m.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keymeta: marshal PKIX: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString
	vk := VerificationKey{V: enc(m.VerificationKey.V), U: enc(m.VerificationKey.U)}
	for _, vi := range m.VerificationKey.I {
		vk.I = append(vk.I, enc(vi))
	}
	return &File{
		Version:         FormatVersion,
		KID:             ComputeKID(pkix),
		Algorithm:       Algorithm,
		Threshold:       int(m.K),
		Parties:         int(m.L),
		ModulusBits:     m.PublicKey.N.BitLen(),
		PublicKeyPKIX:   enc(pkix),
		VerificationKey: vk,
		CreatedAt:       createdAt.UTC().Truncate(time.Second),
	}, nil
}

// Load reads and validates public-meta.json. Any problem is an error.
func Load(path string) (*Meta, error) {
	if path == "" {
		return nil, errors.New("keymeta: path is empty")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keymeta: %w", err)
	}
	m, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("keymeta: %s: %w", path, err)
	}
	return m, nil
}

// Parse decodes and validates public-meta.json bytes. Unknown fields,
// inconsistent parameters, a kid that does not match the key, or a modulus
// below MinModulusBits are all rejected.
func Parse(b []byte) (*Meta, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON object")
	}
	if f.Version != FormatVersion {
		return nil, fmt.Errorf("version %d, want %d", f.Version, FormatVersion)
	}
	if f.Algorithm != Algorithm {
		return nil, fmt.Errorf("algorithm %q, want %q", f.Algorithm, Algorithm)
	}
	// tcrsa requires n/2+1 <= t <= n (honest majority).
	if f.Parties < 2 || f.Parties > 64 || f.Threshold < f.Parties/2+1 || f.Threshold > f.Parties {
		return nil, fmt.Errorf("invalid threshold %d of %d", f.Threshold, f.Parties)
	}
	if f.CreatedAt.IsZero() {
		return nil, errors.New("created_at missing")
	}
	dec64 := base64.StdEncoding.DecodeString
	pkix, err := dec64(f.PublicKeyPKIX)
	if err != nil || len(pkix) == 0 {
		return nil, fmt.Errorf("public_key_pkix: bad base64")
	}
	pubAny, err := x509.ParsePKIXPublicKey(pkix)
	if err != nil {
		return nil, fmt.Errorf("public_key_pkix: %w", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public_key_pkix: %T is not an RSA key", pubAny)
	}
	if pub.N.BitLen() < MinModulusBits {
		return nil, fmt.Errorf("modulus %d bits < %d", pub.N.BitLen(), MinModulusBits)
	}
	if pub.N.BitLen() != f.ModulusBits {
		return nil, fmt.Errorf("modulus_bits %d does not match key (%d)", f.ModulusBits, pub.N.BitLen())
	}
	if want := ComputeKID(pkix); f.KID != want {
		return nil, fmt.Errorf("kid %q does not match public key (want %q)", f.KID, want)
	}
	if len(f.VerificationKey.I) != f.Parties {
		return nil, fmt.Errorf("verification_key.i has %d entries, want %d", len(f.VerificationKey.I), f.Parties)
	}
	vk := tcrsa.NewVerificationKey(uint16(f.Parties))
	if vk.V, err = decodeResidue(f.VerificationKey.V, pub.N); err != nil {
		return nil, fmt.Errorf("verification_key.v: %w", err)
	}
	if vk.U, err = decodeResidue(f.VerificationKey.U, pub.N); err != nil {
		return nil, fmt.Errorf("verification_key.u: %w", err)
	}
	for i, s := range f.VerificationKey.I {
		if vk.I[i], err = decodeResidue(s, pub.N); err != nil {
			return nil, fmt.Errorf("verification_key.i[%d]: %w", i, err)
		}
	}
	return &Meta{
		KID:         f.KID,
		Threshold:   f.Threshold,
		Parties:     f.Parties,
		ModulusBits: f.ModulusBits,
		PKIX:        pkix,
		PublicKey:   pub,
		CreatedAt:   f.CreatedAt,
		Tcrsa: &tcrsa.KeyMeta{
			PublicKey:       pub,
			K:               uint16(f.Threshold),
			L:               uint16(f.Parties),
			VerificationKey: vk,
		},
	}, nil
}

// decodeResidue decodes a base64 value that must lie in [2, n-1].
func decodeResidue(s string, n *big.Int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("bad base64")
	}
	x := new(big.Int).SetBytes(b)
	if x.Cmp(big.NewInt(2)) < 0 || x.Cmp(n) >= 0 {
		return nil, errors.New("value out of range")
	}
	return b, nil
}

// Package testutil provides fixtures for tests only: a cached threshold key,
// a throwaway PKI, service-account claims and standard-library JWT
// verification. No runtime binary imports it.
package testutil

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	jwtv4 "github.com/go-jose/go-jose/v4/jwt"
	"github.com/niclabs/tcrsa"
	josev2 "gopkg.in/go-jose/go-jose.v2"
	jwtv2 "gopkg.in/go-jose/go-jose.v2/jwt"

	"frost-k8s-threshold-signing/internal/dealer"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/keyshare"
	"frost-k8s-threshold-signing/internal/policy"
)

const (
	Threshold = 3
	Parties   = 5
	Issuer    = "https://kubernetes.default.svc.cluster.local"
)

var (
	keyOnce sync.Once
	keyGen  *dealer.Key
	keyErr  error
)

// Fixture is a 2048-bit 3-of-5 key written into a per-test directory.
type Fixture struct {
	Dir      string // holds public-meta.json and share-<i>.json
	MetaPath string
	Meta     *keymeta.Meta
	Shares   []*tcrsa.KeyShare // index i-1 holds share i
	Gen      *dealer.Key
}

// SharePath returns the path of share-<i>.json.
func (f *Fixture) SharePath(i int) string {
	return filepath.Join(f.Dir, dealer.ShareFileName(i))
}

// Key returns a fixture backed by one 2048-bit key per test process
// (generated once, kept in memory), written to t.TempDir().
func Key(t testing.TB) *Fixture {
	t.Helper()
	keyOnce.Do(func() {
		start := time.Now()
		keyGen, keyErr = dealer.Generate(2048, Threshold, Parties)
		if keyErr == nil {
			fmt.Fprintf(os.Stderr, "testutil: generated 2048-bit %d-of-%d key in %v\n", Threshold, Parties, time.Since(start).Round(time.Millisecond))
		}
	})
	if keyErr != nil {
		t.Fatalf("testutil: keygen: %v", keyErr)
	}
	dir := t.TempDir()
	if _, err := dealer.WriteMeta(dir, keyGen); err != nil {
		t.Fatal(err)
	}
	if _, err := dealer.WriteShareFiles(dir, keyGen); err != nil {
		t.Fatal(err)
	}
	f := &Fixture{Dir: dir, MetaPath: filepath.Join(dir, dealer.MetaFileName), Gen: keyGen}
	var err error
	if f.Meta, err = keymeta.Load(f.MetaPath); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= Parties; i++ {
		s, err := keyshare.Load(f.SharePath(i), f.Meta, i)
		if err != nil {
			t.Fatal(err)
		}
		f.Shares = append(f.Shares, s)
	}
	return f
}

// B64 is base64url without padding.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Header returns the canonical base64url header for kid.
func Header(kid string) string {
	return B64([]byte(`{"alg":"RS256","typ":"JWT","kid":"` + kid + `"}`))
}

// SAClaims returns claims shaped like kube-apiserver's (pkg/serviceaccount/claims.go).
func SAClaims(ns, name string, now time.Time, ttl time.Duration) map[string]any {
	return map[string]any{
		"aud": []string{Issuer},
		"exp": now.Add(ttl).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"iss": Issuer,
		"jti": "3f1c9a52-7d0e-4b8f-a6c1-5e2d9b7a0c34",
		"sub": "system:serviceaccount:" + ns + ":" + name,
		"kubernetes.io": map[string]any{
			"namespace":      ns,
			"serviceaccount": map[string]any{"name": name, "uid": "8a4e2c1f-9b3d-4e6a-8c7f-1d2b3a4c5e6f"},
		},
	}
}

// Payload returns base64url(JSON(claims)), exactly the proto's `claims` field.
func Payload(t testing.TB, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return B64(b)
}

// PaddedDigest returns EMSA-PKCS1-v1_5(SHA-256(input)).
func PaddedDigest(t testing.TB, meta *keymeta.Meta, input string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	doc, err := tcrsa.PrepareDocumentHash(meta.PublicKey.Size(), crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// OfflineCombine signs input with the given shares and joins them without any
// share verification, as an attacker holding those shares would.
func OfflineCombine(t testing.TB, meta *tcrsa.KeyMeta, shares []*tcrsa.KeyShare, doc []byte) ([]byte, error) {
	t.Helper()
	var list tcrsa.SigShareList
	for _, s := range shares {
		ss, err := s.Sign(doc, crypto.SHA256, meta)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, ss)
	}
	return list.Join(doc, meta)
}

// VerifyRS256 checks a compact JWT with zero project code: rsa.VerifyPKCS1v15,
// go-jose v2.6.3 (kube-apiserver's verifier, primary) and go-jose v4
// (secondary). It returns the go-jose v2 standard claims.
func VerifyRS256(token string, pub *rsa.PublicKey) (*jwtv2.Claims, error) {
	parsed, err := jwtv2.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("go-jose v2 parse: %w", err)
	}
	if len(parsed.Headers) != 1 || parsed.Headers[0].Algorithm != string(josev2.RS256) {
		return nil, fmt.Errorf("go-jose v2: unexpected header %+v", parsed.Headers)
	}
	var c jwtv2.Claims
	if err := parsed.Claims(pub, &c); err != nil {
		return nil, fmt.Errorf("go-jose v2 verify: %w", err)
	}
	p4, err := jwtv4.ParseSigned(token, []josev4.SignatureAlgorithm{josev4.RS256})
	if err != nil {
		return nil, fmt.Errorf("go-jose v4 parse: %w", err)
	}
	var c4 jwtv4.Claims
	if err := p4.Claims(pub, &c4); err != nil {
		return nil, fmt.Errorf("go-jose v4 verify: %w", err)
	}
	return &c, nil
}

// VerifyPKCS1 checks sig over input with crypto/rsa only.
func VerifyPKCS1(pub *rsa.PublicKey, input string, sig []byte) error {
	sum := sha256.Sum256([]byte(input))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig)
}

// PolicyConfig is the default test policy: issuer/audience Issuer, 1h max,
// 60s skew, generous rate limit.
func PolicyConfig() policy.Config {
	return policy.Config{
		Issuer:           Issuer,
		AllowedAudiences: []string{Issuer},
		MaxTokenSeconds:  3600,
		ClockSkewSeconds: 60,
		RateLimit:        policy.Rate{RequestsPerSecond: 10000, Burst: 10000},
	}
}

// PolicyFile writes cfg as JSON into dir and returns its path.
func PolicyFile(t testing.TB, dir string, cfg policy.Config) string {
	t.Helper()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

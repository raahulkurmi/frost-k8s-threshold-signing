// Package spike is the Phase 0 decision gate: does Shoup threshold RSA
// (github.com/niclabs/tcrsa) produce RS256 JWTs that the verifiers used by
// kube-apiserver accept? Standalone: no repo internals are imported.
//
// Run: GOTOOLCHAIN=go1.27.1 go test -v -count=1 -timeout 60m ./...
// SPIKE_BITS overrides the tcrsa bitSize argument (default 2049, see
// TestTcrsaModulusIsBitSizeMinusOne for why 2049 yields a 2048-bit modulus).
package spike

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	jwtv4 "github.com/go-jose/go-jose/v4/jwt"
	"github.com/niclabs/tcrsa"
	josev2 "gopkg.in/go-jose/go-jose.v2"
	jwtv2 "gopkg.in/go-jose/go-jose.v2/jwt"
)

const (
	threshold = 3
	parties   = 5
	issuer    = "https://kubernetes.default.svc.cluster.local"
	timingN   = 20
)

var (
	keyOnce   sync.Once
	keyShares tcrsa.KeyShareList
	keyMeta   *tcrsa.KeyMeta
	keyErr    error
	keygenDur time.Duration
)

func bitSize() int {
	if v := os.Getenv("SPIKE_BITS"); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return 2049
}

func key(t testing.TB) (tcrsa.KeyShareList, *tcrsa.KeyMeta) {
	t.Helper()
	keyOnce.Do(func() {
		start := time.Now()
		keyShares, keyMeta, keyErr = tcrsa.NewKey(bitSize(), threshold, parties, nil)
		keygenDur = time.Since(start)
	})
	if keyErr != nil {
		t.Fatalf("tcrsa.NewKey: %v", keyErr)
	}
	return keyShares, keyMeta
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signingInput builds base64url(header).base64url(payload) for a service
// account token shaped like the ones kube-apiserver issues.
func signingInput(t testing.TB) (string, map[string]any) {
	t.Helper()
	header := `{"alg":"RS256","kid":"spike","typ":"JWT"}`
	now := time.Now().Unix()
	claims := map[string]any{
		"aud": []string{issuer},
		"exp": now + 3600,
		"iat": now,
		"nbf": now,
		"iss": issuer,
		"jti": "8b6a4c1e-0f7d-4a8a-9d7e-2f0c9a1b3c4d",
		"sub": "system:serviceaccount:default:default",
		"kubernetes.io": map[string]any{
			"namespace":      "default",
			"serviceaccount": map[string]any{"name": "default", "uid": "5d1b6c0a-8f7e-4c2d-9b3a-1e0f2d4c6b8a"},
		},
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return b64([]byte(header)) + "." + b64(payload), claims
}

// padded returns EMSA-PKCS1-v1_5(SHA-256(input)) sized to the modulus.
func padded(t testing.TB, meta *tcrsa.KeyMeta, input string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	doc, err := tcrsa.PrepareDocumentHash(meta.PublicKey.Size(), crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("PrepareDocumentHash: %v", err)
	}
	return doc
}

// thresholdSign has the shares with the given 1-based ids sign doc, verifies
// every share, and joins them.
func thresholdSign(t testing.TB, shares tcrsa.KeyShareList, meta *tcrsa.KeyMeta, doc []byte, ids []int) []byte {
	t.Helper()
	list := make(tcrsa.SigShareList, 0, len(ids))
	for _, id := range ids {
		ss, err := shares[id-1].Sign(doc, crypto.SHA256, meta)
		if err != nil {
			t.Fatalf("share %d Sign: %v", id, err)
		}
		if err := ss.Verify(doc, meta); err != nil {
			t.Fatalf("share %d Verify: %v", id, err)
		}
		list = append(list, ss)
	}
	sig, err := list.Join(doc, meta)
	if err != nil {
		t.Fatalf("Join %v: %v", ids, err)
	}
	return sig
}

func subsets(n, k int) [][]int {
	var out [][]int
	var rec func(start int, cur []int)
	rec = func(start int, cur []int) {
		if len(cur) == k {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := start; i <= n; i++ {
			rec(i+1, append(cur, i))
		}
	}
	rec(1, nil)
	return out
}

// verifyWithStandardLibraries checks the token with zero project code:
// crypto/rsa, go-jose v2.6.3 (the exact version kube-apiserver v1.36.5 uses in
// pkg/serviceaccount) and go-jose v4.
func verifyWithStandardLibraries(t *testing.T, pub *rsa.PublicKey, input string, sig []byte, want map[string]any) {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("rsa.VerifyPKCS1v15: %v", err)
	}
	token := input + "." + b64(sig)

	// go-jose v2 (kube-apiserver's verifier library at v1.36.5).
	parsed2, err := jwtv2.ParseSigned(token)
	if err != nil {
		t.Fatalf("go-jose v2 ParseSigned: %v", err)
	}
	if got := parsed2.Headers[0].Algorithm; got != string(josev2.RS256) {
		t.Fatalf("go-jose v2 alg = %q", got)
	}
	var std2 jwtv2.Claims
	var priv2 map[string]any
	if err := parsed2.Claims(pub, &std2, &priv2); err != nil {
		t.Fatalf("go-jose v2 Claims (signature check): %v", err)
	}
	if err := std2.Validate(jwtv2.Expected{Issuer: issuer, Audience: jwtv2.Audience{issuer}, Time: time.Now()}); err != nil {
		t.Fatalf("go-jose v2 Validate: %v", err)
	}
	if std2.Subject != want["sub"] {
		t.Fatalf("go-jose v2 sub = %q", std2.Subject)
	}

	// go-jose v4.
	parsed4, err := jwtv4.ParseSigned(token, []josev4.SignatureAlgorithm{josev4.RS256})
	if err != nil {
		t.Fatalf("go-jose v4 ParseSigned: %v", err)
	}
	var std4 jwtv4.Claims
	if err := parsed4.Claims(pub, &std4); err != nil {
		t.Fatalf("go-jose v4 Claims (signature check): %v", err)
	}
	if std4.Subject != want["sub"] {
		t.Fatalf("go-jose v4 sub = %q", std4.Subject)
	}
}

// validateHeaderLikeApiserver mirrors validateJWTHeader in
// pkg/serviceaccount/externaljwt/plugin/plugin.go at v1.36.5: exactly
// alg/kid/typ, DisallowUnknownFields, typ == JWT, alg in the allowed set.
func validateHeaderLikeApiserver(t *testing.T, input string) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(input, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var h struct {
		Alg string `json:"alg,omitempty"`
		Kid string `json:"kid,omitempty"`
		Typ string `json:"typ,omitempty"`
	}
	if err := dec.Decode(&h); err != nil {
		t.Fatalf("header: %v", err)
	}
	if h.Typ != "JWT" || h.Kid == "" || h.Alg != "RS256" {
		t.Fatalf("header rejected: %+v", h)
	}
}

// TestTcrsaModulusIsBitSizeMinusOne documents a tcrsa quirk: qPrimeSize is
// bitSize-pPrimeSize-1 and Go's rand.Prime sets the top two bits, so the
// modulus is always exactly bitSize-1 bits. NewKey(2048) gives 2047 bits.
func TestTcrsaModulusIsBitSizeMinusOne(t *testing.T) {
	for i := 0; i < 3; i++ {
		_, meta, err := tcrsa.NewKey(512, threshold, parties, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := meta.PublicKey.N.BitLen(); got != 511 {
			t.Fatalf("NewKey(512) modulus = %d bits, want 511", got)
		}
	}
	t.Logf("NewKey(512) -> 511-bit modulus (3/3 runs); so NewKey(2049) is used for a 2048-bit modulus")
}

func TestKeygen(t *testing.T) {
	_, meta := key(t)
	bits := meta.PublicKey.N.BitLen()
	t.Logf("keygen: tcrsa.NewKey(%d, k=%d, l=%d) took %v; modulus = %d bits, e = %d",
		bitSize(), threshold, parties, keygenDur.Round(time.Millisecond), bits, meta.PublicKey.E)
	if bitSize() == 2049 && bits != 2048 {
		t.Fatalf("modulus = %d bits, want 2048", bits)
	}
	if bits < 2048 && os.Getenv("SPIKE_BITS") == "" {
		t.Fatalf("modulus < 2048 bits")
	}
}

// TestRS256JWTVerifies: 3 shares sign; each share verifies; combine; the
// result verifies with crypto/rsa, go-jose v2.6.3 and go-jose v4.
func TestRS256JWTVerifies(t *testing.T) {
	shares, meta := key(t)
	input, claims := signingInput(t)
	validateHeaderLikeApiserver(t, input)
	sig := thresholdSign(t, shares, meta, padded(t, meta, input), []int{1, 2, 3})
	if len(sig) != meta.PublicKey.Size() {
		t.Fatalf("signature length %d, want %d", len(sig), meta.PublicKey.Size())
	}
	verifyWithStandardLibraries(t, meta.PublicKey, input, sig, claims)
	t.Logf("token verified by rsa.VerifyPKCS1v15, go-jose v2.6.3, go-jose v4 (sig %d bytes)", len(sig))
}

// TestAllThresholdSubsetsIdentical (I6): all C(5,3)=10 subsets yield
// byte-identical signatures, and each verifies.
func TestAllThresholdSubsetsIdentical(t *testing.T) {
	shares, meta := key(t)
	input, claims := signingInput(t)
	doc := padded(t, meta, input)
	subs := subsets(parties, threshold)
	if len(subs) != 10 {
		t.Fatalf("got %d subsets", len(subs))
	}
	var ref []byte
	for _, s := range subs {
		sig := thresholdSign(t, shares, meta, doc, s)
		verifyWithStandardLibraries(t, meta.PublicKey, input, sig, claims)
		if ref == nil {
			ref = sig
		} else if !bytes.Equal(ref, sig) {
			t.Fatalf("subset %v signature differs from subset %v", s, subs[0])
		}
		t.Logf("subset %v: sha256(sig)=%x", s, sha256.Sum256(sig))
	}
	// A 4-share and 5-share list also yield the same bytes (Join uses the first k).
	for _, s := range [][]int{{1, 2, 3, 4}, {5, 4, 3, 2, 1}} {
		if sig := thresholdSign(t, shares, meta, doc, s); !bytes.Equal(ref, sig) {
			t.Fatalf("list %v differs", s)
		}
	}
	t.Logf("all 10 subsets byte-identical")
}

// TestBelowThresholdFails (I5): Join refuses 2 shares; and an attacker who
// bypasses that check (meta copy with K=2) gets a signature that fails
// verification.
func TestBelowThresholdFails(t *testing.T) {
	shares, meta := key(t)
	input, _ := signingInput(t)
	doc := padded(t, meta, input)
	sum := sha256.Sum256([]byte(input))
	for _, pair := range subsets(parties, 2) {
		list := tcrsa.SigShareList{}
		for _, id := range pair {
			ss, err := shares[id-1].Sign(doc, crypto.SHA256, meta)
			if err != nil {
				t.Fatal(err)
			}
			list = append(list, ss)
		}
		if _, err := list.Join(doc, meta); err == nil {
			t.Fatalf("Join accepted 2 shares %v", pair)
		}
		forged := *meta
		forged.K = 2
		sig, err := list.Join(doc, &forged)
		if err != nil {
			t.Fatalf("forced K=2 Join %v: %v", pair, err)
		}
		if rsa.VerifyPKCS1v15(meta.PublicKey, crypto.SHA256, sum[:], sig) == nil {
			t.Fatalf("2 shares %v produced a VALID signature", pair)
		}
	}
	t.Logf("all 10 pairs: Join refuses; forced K=2 combine yields invalid signature")
}

// TestTamperedShareRejected (I7).
func TestTamperedShareRejected(t *testing.T) {
	shares, meta := key(t)
	input, _ := signingInput(t)
	doc := padded(t, meta, input)
	good, err := shares[1].Sign(doc, crypto.SHA256, meta)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(b []byte) []byte { c := append([]byte(nil), b...); c[len(c)/2] ^= 0x01; return c }

	cases := map[string]*tcrsa.SigShare{
		"flipped Xi":            {Id: good.Id, Xi: flip(good.Xi), C: good.C, Z: good.Z},
		"flipped C":             {Id: good.Id, Xi: good.Xi, C: flip(good.C), Z: good.Z},
		"flipped Z":             {Id: good.Id, Xi: good.Xi, C: good.C, Z: flip(good.Z)},
		"relabelled Id 2->3":    {Id: 3, Xi: good.Xi, C: good.C, Z: good.Z},
		"zero Xi":               {Id: good.Id, Xi: []byte{}, C: good.C, Z: good.Z},
		"share for other input": nil,
	}
	otherInput, _ := signingInput(t)
	other, err := shares[1].Sign(padded(t, meta, otherInput+"x"), crypto.SHA256, meta)
	if err != nil {
		t.Fatal(err)
	}
	cases["share for other input"] = other

	for name, ss := range cases {
		if err := ss.Verify(doc, meta); err == nil {
			t.Fatalf("%s: Verify accepted a tampered share", name)
		} else {
			t.Logf("%s: rejected (%v)", name, err)
		}
	}

	// Join does NOT verify shares: an unverified bad share silently yields an
	// invalid signature. The coordinator must verify every share first and
	// must verify the combined signature.
	s1, _ := shares[0].Sign(doc, crypto.SHA256, meta)
	s3, _ := shares[2].Sign(doc, crypto.SHA256, meta)
	sig, err := tcrsa.SigShareList{s1, cases["flipped Xi"], s3}.Join(doc, meta)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(input))
	if rsa.VerifyPKCS1v15(meta.PublicKey, crypto.SHA256, sum[:], sig) == nil {
		t.Fatal("tampered share produced a valid signature")
	}
	t.Logf("Join with an unverified tampered share: no error from Join, final signature INVALID (library does not self-check)")

	// With the bad share excluded and a 4th honest share, signing succeeds.
	s4, _ := shares[3].Sign(doc, crypto.SHA256, meta)
	var valid tcrsa.SigShareList
	for _, ss := range []*tcrsa.SigShare{s1, cases["flipped Xi"], s3, s4} {
		if ss.Verify(doc, meta) == nil {
			valid = append(valid, ss)
		}
	}
	if len(valid) != 3 {
		t.Fatalf("valid shares = %d", len(valid))
	}
	sig, err = valid.Join(doc, meta)
	if err != nil || rsa.VerifyPKCS1v15(meta.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		t.Fatalf("honest 3 after exclusion failed: %v", err)
	}
	t.Logf("bad share from id 2 excluded; ids {1,3,4} -> valid signature")
}

// TestLibraryHazards records tcrsa behaviours the coordinator must guard
// against. These are findings, not failures of the scheme.
func TestLibraryHazards(t *testing.T) {
	shares, meta := key(t)
	input, _ := signingInput(t)
	doc := padded(t, meta, input)
	good, _ := shares[0].Sign(doc, crypto.SHA256, meta)

	for _, id := range []uint16{0, parties + 1} {
		ss := &tcrsa.SigShare{Id: id, Xi: good.Xi, C: good.C, Z: good.Z}
		panicked := func() (p bool) {
			defer func() { p = recover() != nil }()
			_ = ss.Verify(doc, meta)
			return false
		}()
		if !panicked {
			t.Fatalf("expected SigShare.Verify to panic for Id=%d (update NOTES.md if the library changed)", id)
		}
		t.Logf("HAZARD: SigShare.Verify panics on out-of-range Id=%d -> coordinator must bounds-check Id in [1,n] before Verify", id)
	}

	s2, _ := shares[1].Sign(doc, crypto.SHA256, meta)
	sig, err := tcrsa.SigShareList{good, good, s2}.Join(doc, meta)
	sum := sha256.Sum256([]byte(input))
	if err == nil && rsa.VerifyPKCS1v15(meta.PublicKey, crypto.SHA256, sum[:], sig) == nil {
		t.Fatal("duplicate-id list produced a valid signature (unexpected)")
	}
	t.Logf("HAZARD: Join accepts duplicate Ids {1,1,2} (err=%v) and yields an invalid signature -> coordinator must dedupe by Id", err)
}

// TestTimings records keygen, per-share sign, share verify, combine and
// final verify times for the spike key.
func TestTimings(t *testing.T) {
	shares, meta := key(t)
	input, _ := signingInput(t)
	sum := sha256.Sum256([]byte(input))

	var signD, verifyD, joinD, rsaVerD, joseVerD time.Duration
	for i := 0; i < timingN; i++ {
		doc := padded(t, meta, input)
		list := tcrsa.SigShareList{}
		for _, id := range []int{1, 2, 3} {
			st := time.Now()
			ss, err := shares[id-1].Sign(doc, crypto.SHA256, meta)
			signD += time.Since(st)
			if err != nil {
				t.Fatal(err)
			}
			st = time.Now()
			if err := ss.Verify(doc, meta); err != nil {
				t.Fatal(err)
			}
			verifyD += time.Since(st)
			list = append(list, ss)
		}
		st := time.Now()
		sig, err := list.Join(doc, meta)
		joinD += time.Since(st)
		if err != nil {
			t.Fatal(err)
		}
		st = time.Now()
		if err := rsa.VerifyPKCS1v15(meta.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
			t.Fatal(err)
		}
		rsaVerD += time.Since(st)
		st = time.Now()
		p, err := jwtv2.ParseSigned(input + "." + b64(sig))
		if err != nil {
			t.Fatal(err)
		}
		var c jwtv2.Claims
		if err := p.Claims(meta.PublicKey, &c); err != nil {
			t.Fatal(err)
		}
		joseVerD += time.Since(st)
	}
	per := func(d time.Duration, n int) string { return (d / time.Duration(n)).Round(time.Microsecond).String() }
	t.Logf("TIMINGS (modulus %d bits, N=%d, single goroutine, %s):", meta.PublicKey.N.BitLen(), timingN, hostDesc())
	t.Logf("  keygen (safe primes, trusted dealer): %v", keygenDur.Round(time.Millisecond))
	t.Logf("  per-share sign:                       %s", per(signD, 3*timingN))
	t.Logf("  per-share verify:                     %s", per(verifyD, 3*timingN))
	t.Logf("  combine (Join, 3 shares):             %s", per(joinD, timingN))
	t.Logf("  final verify rsa.VerifyPKCS1v15:      %s", per(rsaVerD, timingN))
	t.Logf("  final verify go-jose v2 parse+verify: %s", per(joseVerD, timingN))
}

func hostDesc() string {
	return fmt.Sprintf("%s/%s, %d CPUs, %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
}

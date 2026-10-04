//go:build auditfuzz

// Package fuzz holds the Phase 12 Pass D (fuzzing) audit targets. Test-only;
// nothing outside reports/audit/fuzz is modified.
package fuzz

import (
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/dealer"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/keyshare"
	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/testutil"
)

// fixedNow is the clock used by every policy evaluation in these targets, so
// corpus entries stay valid across runs.
var fixedNow = time.Unix(1_800_000_000, 0)

// keyFx is the threshold test key: public meta and the five shares.
type keyFx struct {
	Meta   *keymeta.Meta
	Shares []*tcrsa.KeyShare
	Dir    string
}

var (
	fxOnce sync.Once
	fxVal  *keyFx
	fxErr  error
)

// loadKey returns the 2048-bit 3-of-5 test key. testutil.Key regenerates the
// key once per process (~30 s of safe-prime search), and every fuzz worker is
// a process, so the key files are cached in $FROST_FUZZ_KEYDIR when set.
func loadKey(t testing.TB) *keyFx {
	t.Helper()
	dir := os.Getenv("FROST_FUZZ_KEYDIR")
	if dir != "" {
		if _, err := os.Stat(filepath.Join(dir, dealer.MetaFileName)); err != nil {
			fx := testutil.Key(t)
			tmp, err := os.MkdirTemp(filepath.Dir(dir), "keytmp")
			if err != nil {
				t.Fatal(err)
			}
			copyFile(t, fx.MetaPath, filepath.Join(tmp, dealer.MetaFileName))
			for i := 1; i <= testutil.Parties; i++ {
				copyFile(t, fx.SharePath(i), filepath.Join(tmp, dealer.ShareFileName(i)))
			}
			_ = os.Remove(dir) // an empty placeholder dir, if any
			if err := os.Rename(tmp, dir); err != nil {
				_ = os.RemoveAll(tmp) // lost a race with another worker: use theirs
			}
		}
	}
	fxOnce.Do(func() {
		if dir == "" {
			// f.Dir is a t.TempDir of the first caller and is removed when that
			// target ends; copy the files to a process-lifetime directory so
			// later targets in the same run can read them.
			f := testutil.Key(t)
			keep, err := os.MkdirTemp("", "frost-fuzz-key")
			if err != nil {
				fxErr = err
				return
			}
			copyFile(t, f.MetaPath, filepath.Join(keep, dealer.MetaFileName))
			for i := 1; i <= testutil.Parties; i++ {
				copyFile(t, f.SharePath(i), filepath.Join(keep, dealer.ShareFileName(i)))
			}
			fxVal = &keyFx{Meta: f.Meta, Shares: f.Shares, Dir: keep}
			return
		}
		m, err := keymeta.Load(filepath.Join(dir, dealer.MetaFileName))
		if err != nil {
			fxErr = err
			return
		}
		fx := &keyFx{Meta: m, Dir: dir}
		for i := 1; i <= testutil.Parties; i++ {
			s, err := keyshare.Load(filepath.Join(dir, dealer.ShareFileName(i)), m, i)
			if err != nil {
				fxErr = err
				return
			}
			fx.Shares = append(fx.Shares, s)
		}
		fxVal = fx
	})
	if fxErr != nil {
		t.Fatal(fxErr)
	}
	return fxVal
}

func copyFile(t testing.TB, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// testPolicyConfig mirrors internal/policy/policy_test.go mustPolicy, with an
// effectively unlimited rate so the limiter never masks a result.
func testPolicyConfig() policy.Config {
	c := testutil.PolicyConfig()
	c.AllowedAudiences = []string{testutil.Issuer, "vault"}
	c.DenyNamespaces = []string{"kube-denied"}
	c.DenyServiceAccts = []string{"default:blocked"}
	c.RateLimit = policy.Rate{RequestsPerSecond: 1e12, Burst: 1 << 30}
	return c
}

func mustPolicy(t testing.TB, c policy.Config) *policy.Policy {
	t.Helper()
	p, err := policy.New(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// deployPolicy loads deploy/policy.json from the repo.
func deployPolicy(t testing.TB) *policy.Policy {
	t.Helper()
	p, err := policy.Load(filepath.Join("..", "..", "..", "deploy", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func saClaims(ns, name string) map[string]any {
	return testutil.SAClaims(ns, name, fixedNow, time.Hour)
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// paddedDigest is EMSA-PKCS1-v1_5(SHA-256(input)) for meta's modulus.
func paddedDigest(t testing.TB, meta *keymeta.Meta, input string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	doc, err := tcrsa.PrepareDocumentHash(meta.PublicKey.Size(), crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// sameOrNegated reports whether x == g or x == n-g (mod n): the only share
// values a party without the factorisation can produce that combine into the
// genuine signature (Join uses xi^(2*lambda), so -xi is equivalent).
func sameOrNegated(x, g, n *big.Int) bool {
	xm := new(big.Int).Mod(x, n)
	gm := new(big.Int).Mod(g, n)
	if xm.Cmp(gm) == 0 {
		return true
	}
	return new(big.Int).Sub(n, gm).Cmp(xm) == 0
}

var b64 = testutil.B64

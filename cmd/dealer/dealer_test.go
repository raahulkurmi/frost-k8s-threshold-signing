package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/dealer"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/keyshare"
	"frost-k8s-threshold-signing/internal/testutil"
)

func noEnv(string) string { return "" }

// runDealer runs the CLI once per process into a shared directory; the
// resulting 2048-bit key is reused by the read-only tests below.
var (
	sharedOnce sync.Once
	sharedDir  string
	sharedOut  string
	sharedCode int
)

func shared(t *testing.T) string {
	t.Helper()
	sharedOnce.Do(func() {
		dir, err := os.MkdirTemp("", "dealer-test-")
		if err != nil {
			t.Fatal(err)
		}
		sharedDir = filepath.Join(dir, "out")
		var stdout, stderr bytes.Buffer
		sharedCode = run([]string{"--out", sharedDir}, &stdout, &stderr, noEnv)
		sharedOut = stdout.String() + stderr.String()
	})
	if sharedCode != 0 {
		t.Fatalf("dealer exited %d:\n%s", sharedCode, sharedOut)
	}
	return sharedDir
}

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedDir != "" {
		os.RemoveAll(filepath.Dir(sharedDir))
	}
	os.Exit(code)
}

func loadMeta(t *testing.T, dir string) *keymeta.Meta {
	t.Helper()
	m, err := keymeta.Load(filepath.Join(dir, dealer.MetaFileName))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestShareFilesEachHoldExactlyOneShare(t *testing.T) {
	dir := shared(t)
	meta := loadMeta(t, dir)
	seen := map[string]int{}
	for i := 1; i <= 5; i++ {
		p := filepath.Join(dir, dealer.ShareFileName(i))
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", p, st.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		if len(raw) != 4 || raw["si"] == nil || raw["signer_index"] == nil || raw["kid"] == nil || raw["version"] == nil {
			t.Fatalf("share-%d.json fields = %v, want exactly version,kid,signer_index,si", i, keys(raw))
		}
		if int(raw["signer_index"].(float64)) != i {
			t.Fatalf("share-%d.json signer_index = %v", i, raw["signer_index"])
		}
		if raw["kid"] != meta.KID {
			t.Fatalf("share-%d.json kid = %v, meta kid = %s", i, raw["kid"], meta.KID)
		}
		si := raw["si"].(string)
		if j, dup := seen[si]; dup {
			t.Fatalf("share-%d and share-%d hold the same value", j, i)
		}
		seen[si] = i
		// Parses as exactly its own index, cryptographically bound to vk_i.
		if _, err := keyshare.Parse(b, meta, i); err != nil {
			t.Fatalf("share-%d does not validate as index %d: %v", i, i, err)
		}
		for j := 1; j <= 5; j++ {
			if j != i {
				if _, err := keyshare.Parse(b, meta, j); err == nil {
					t.Fatalf("share-%d validated as index %d", i, j)
				}
			}
		}
	}
	t.Logf("5 share files, mode 0600, one distinct share each, each bound to its own index")
}

var metaAllowlist = map[string]bool{
	"version": true, "kid": true, "algorithm": true, "threshold": true, "parties": true,
	"modulus_bits": true, "public_key_pkix": true, "verification_key": true, "created_at": true,
}

func TestPublicMetaHasNoSecretFields(t *testing.T) {
	dir := shared(t)
	p := filepath.Join(dir, dealer.MetaFileName)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for k := range raw {
		if !metaAllowlist[k] {
			t.Fatalf("public-meta.json has non-allowlisted field %q", k)
		}
	}
	if len(raw) != len(metaAllowlist) {
		t.Fatalf("public-meta.json fields = %v", keys(raw))
	}
	var vk map[string]json.RawMessage
	if err := json.Unmarshal(raw["verification_key"], &vk); err != nil {
		t.Fatal(err)
	}
	if len(vk) != 3 || vk["v"] == nil || vk["u"] == nil || vk["i"] == nil {
		t.Fatalf("verification_key fields = %v, want exactly v,u,i", keys(vk))
	}
	// No share value appears anywhere in the public file.
	for i := 1; i <= 5; i++ {
		sb, _ := os.ReadFile(filepath.Join(dir, dealer.ShareFileName(i)))
		var sf keyshare.File
		if err := json.Unmarshal(sb, &sf); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(sf.Si)) {
			t.Fatalf("public-meta.json contains share %d", i)
		}
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o644 {
		t.Errorf("public-meta.json mode %v, want 0644", st.Mode().Perm())
	}
	meta := loadMeta(t, dir)
	if meta.ModulusBits != 2048 || meta.PublicKey.N.BitLen() != 2048 || meta.Threshold != 3 || meta.Parties != 5 {
		t.Fatalf("meta = %d bits, %d of %d", meta.PublicKey.N.BitLen(), meta.Threshold, meta.Parties)
	}
	if meta.KID != keymeta.ComputeKID(meta.PKIX) || len(meta.KID) != 22 {
		t.Fatalf("kid %q is not base64url(sha256(pkix)[:16])", meta.KID)
	}
	t.Logf("public-meta.json fields = %v; kid = %s (22 chars)", keys(raw), meta.KID)
}

func TestDealerOutputPrintsNoShare(t *testing.T) {
	dir := shared(t)
	if !strings.Contains(sharedOut, "kid: "+loadMeta(t, dir).KID) {
		t.Fatalf("output does not print kid:\n%s", sharedOut)
	}
	for i := 1; i <= 5; i++ {
		sb, _ := os.ReadFile(filepath.Join(dir, dealer.ShareFileName(i)))
		var sf keyshare.File
		_ = json.Unmarshal(sb, &sf)
		if strings.Contains(sharedOut, sf.Si) || strings.Contains(sharedOut, sf.Si[:16]) {
			t.Fatalf("dealer output contains share %d", i)
		}
		if !strings.Contains(sharedOut, dealer.ShareFileName(i)) {
			t.Fatalf("dealer output lacks fingerprint line for %s", dealer.ShareFileName(i))
		}
	}
	t.Logf("dealer stdout:\n%s", sharedOut)
}

func TestRefusesToOverwrite(t *testing.T) {
	dir := shared(t)
	before, _ := os.ReadFile(filepath.Join(dir, dealer.ShareFileName(1)))
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--out", dir}, &stdout, &stderr, noEnv); code == 0 {
		t.Fatal("dealer overwrote an existing ceremony")
	}
	after, _ := os.ReadFile(filepath.Join(dir, dealer.ShareFileName(1)))
	if !bytes.Equal(before, after) {
		t.Fatal("share-1.json changed")
	}
	t.Logf("second run into same dir refused: %s", strings.TrimSpace(stderr.String()))
}

func TestRejectsWeakParameters(t *testing.T) {
	for _, args := range [][]string{
		{"--modulus-bits", "1024"},
		{"--t", "2", "--n", "5"},
		{"--t", "6", "--n", "5"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(append([]string{"--out", t.TempDir()}, args...), &stdout, &stderr, noEnv); code == 0 {
			t.Fatalf("dealer accepted %v", args)
		}
		t.Logf("%v rejected: %s", args, strings.TrimSpace(stderr.String()))
	}
}

func TestRerunProducesDifferentKey(t *testing.T) {
	t.Parallel()
	a := shared(t)
	b := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--out", b}, &stdout, &stderr, noEnv); code != 0 {
		t.Fatalf("second ceremony exited %d: %s", code, stderr.String())
	}
	ma, mb := loadMeta(t, a), loadMeta(t, b)
	if ma.KID == mb.KID || ma.PublicKey.N.Cmp(mb.PublicKey.N) == 0 {
		t.Fatal("two ceremonies produced the same key")
	}
	t.Logf("run 1 kid=%s, run 2 kid=%s", ma.KID, mb.KID)
}

// TestFetchKeysPKIXRoundTrip (R-a): the public key survives
// MarshalPKIX -> ParsePKIX and still verifies a threshold-signed token with
// go-jose v2 (kube-apiserver's verifier).
func TestFetchKeysPKIXRoundTrip(t *testing.T) {
	dir := shared(t)
	meta := loadMeta(t, dir)
	var shares []*tcrsa.KeyShare
	for _, i := range []int{2, 4, 5} {
		s, err := keyshare.Load(filepath.Join(dir, dealer.ShareFileName(i)), meta, i)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, s)
	}
	input := testutil.Header(meta.KID) + "." + testutil.Payload(t, testutil.SAClaims("default", "default", time.Now(), time.Hour))
	sig, err := testutil.OfflineCombine(t, meta.Tcrsa, shares, testutil.PaddedDigest(t, meta, input))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(meta.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, meta.PKIX) {
		t.Fatal("re-marshalled PKIX differs from public-meta.json")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, ok := pub.(interface{ Size() int })
	if !ok || rsaPub.Size() != 256 {
		t.Fatalf("parsed key %T", pub)
	}
	claims, err := testutil.VerifyRS256(input+"."+testutil.B64(sig), meta.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "system:serviceaccount:default:default" {
		t.Fatalf("sub = %q", claims.Subject)
	}
	t.Logf("PKIX round-trip OK; token signed by shares {2,4,5} verifies with go-jose v2.6.3 and v4")
}

// fakeVault emulates the Vault KV v2 data endpoint.
type fakeVault struct {
	mu    sync.Mutex
	token string
	data  map[string]json.RawMessage
}

func (v *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != v.token {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		v.data[r.URL.Path] = env.Data
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"version":1}}`))
	case http.MethodGet:
		d, ok := v.data[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": d}})
	}
}

func TestVaultModeWritesSharesOnlyToVault(t *testing.T) {
	t.Parallel()
	fv := &fakeVault{token: "test-token-not-a-secret", data: map[string]json.RawMessage{}}
	srv := httptest.NewServer(fv)
	defer srv.Close()
	env := func(k string) string {
		return map[string]string{"VAULT_ADDR": srv.URL, "VAULT_TOKEN": fv.token}[k]
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--out", t.TempDir(), "--vault"}, &stdout, &stderr, noEnv); code == 0 {
		t.Fatal("--vault without VAULT_ADDR/VAULT_TOKEN succeeded")
	}

	out := filepath.Join(t.TempDir(), "out")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--out", out, "--vault"}, &stdout, &stderr, env); code != 0 {
		t.Fatalf("dealer --vault exited %d: %s", code, stderr.String())
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 1 || entries[0].Name() != dealer.MetaFileName {
		t.Fatalf("--vault wrote %v to disk, want only %s", entries, dealer.MetaFileName)
	}
	meta := loadMeta(t, out)
	for i := 1; i <= 5; i++ {
		if _, ok := fv.data["/v1/secret/data/frost-k8s/signer-"+itoa(i)]; !ok {
			t.Fatalf("no vault entry for signer-%d (have %v)", i, keys(fv.data))
		}
		if _, err := keyshare.LoadFromVault(t.Context(), srv.URL, fv.token, "secret", meta, i); err != nil {
			t.Fatalf("signer-%d LoadFromVault: %v", i, err)
		}
		if _, err := keyshare.LoadFromVault(t.Context(), srv.URL, "wrong", "secret", meta, i); err == nil {
			t.Fatal("LoadFromVault accepted a wrong token")
		}
	}
	t.Logf("--vault: shares at secret/frost-k8s/signer-1..5, only %s on disk", dealer.MetaFileName)
}

func itoa(i int) string { return string(rune('0' + i)) }

func keys[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

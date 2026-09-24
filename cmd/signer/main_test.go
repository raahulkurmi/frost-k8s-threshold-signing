package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"frost-k8s-threshold-signing/internal/keyshare"
	"frost-k8s-threshold-signing/internal/testutil"
)

type envMap map[string]string

func (e envMap) get(k string) string { return e[k] }

func baseEnv(t *testing.T, fx *testutil.Fixture, id int) envMap {
	t.Helper()
	pki := testutil.NewPKI(t)
	sc := pki.Signer(t, id)
	return envMap{
		"SIGNER_ID":   itoa(id),
		"META_FILE":   fx.MetaPath,
		"SHARE_FILE":  fx.SharePath(id),
		"POLICY_FILE": testutil.PolicyFile(t, t.TempDir(), testutil.PolicyConfig()),
		"AUDIT_LOG":   filepath.Join(t.TempDir(), "audit.log"),
		"TLS_CERT":    sc.Cert,
		"TLS_KEY":     sc.Key,
		"TLS_CA":      pki.CA,
	}
}

func itoa(i int) string { return string(rune('0' + i)) }

func mustFail(t *testing.T, e envMap, want string) {
	t.Helper()
	_, err := load(context.Background(), e.get)
	if err == nil {
		t.Fatalf("load succeeded, want error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
	t.Logf("refused: %v", err)
}

func rewriteShare(t *testing.T, src string, mut func(*keyshare.File)) string {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	var f keyshare.File
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	mut(&f)
	out, _ := json.Marshal(f)
	p := filepath.Join(t.TempDir(), "share.json")
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	fx := testutil.Key(t)
	s, err := load(context.Background(), baseEnv(t, fx, 4).get)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != 4 || int(s.Share.Id) != 4 || s.Meta.KID != fx.Meta.KID {
		t.Fatalf("loaded %+v", s)
	}
}

// TestWrongShareIndexRejected (T9): signer 1 given share-2.json refuses to start.
func TestWrongShareIndexRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := baseEnv(t, fx, 1)
	e["SHARE_FILE"] = fx.SharePath(2)
	mustFail(t, e, "share is for signer 2, this is signer 1")

	// Relabelling share 2 as index 1 does not help: it fails v^si == vk_1.
	e["SHARE_FILE"] = rewriteShare(t, fx.SharePath(2), func(f *keyshare.File) { f.SignerIndex = 1 })
	mustFail(t, e, "does not match its verification key")
}

// TestWrongKidRejected (T9): a share whose kid differs from public-meta.json.
func TestWrongKidRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := baseEnv(t, fx, 3)
	e["SHARE_FILE"] = rewriteShare(t, fx.SharePath(3), func(f *keyshare.File) { f.KID = "AAAAAAAAAAAAAAAAAAAAAA" })
	mustFail(t, e, "does not match meta kid")
}

func TestCorruptedShareRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := baseEnv(t, fx, 3)
	e["SHARE_FILE"] = rewriteShare(t, fx.SharePath(3), func(f *keyshare.File) {
		b, _ := base64.StdEncoding.DecodeString(f.Si)
		b[len(b)/2] ^= 1
		f.Si = base64.StdEncoding.EncodeToString(b)
	})
	mustFail(t, e, "does not match its verification key")
}

func TestMultiShareFileRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := baseEnv(t, fx, 1)
	a, _ := os.ReadFile(fx.SharePath(1))
	b, _ := os.ReadFile(fx.SharePath(2))
	p := filepath.Join(t.TempDir(), "all.json")
	_ = os.WriteFile(p, append(a, b...), 0o600)
	e["SHARE_FILE"] = p
	mustFail(t, e, "exactly one share")
}

// TestSignerFailsClosed (I9): every missing or bad input aborts startup.
func TestSignerFailsClosed(t *testing.T) {
	fx := testutil.Key(t)
	for _, name := range []string{"SIGNER_ID", "META_FILE", "POLICY_FILE", "AUDIT_LOG", "TLS_CERT", "TLS_KEY", "TLS_CA"} {
		t.Run("missing "+name, func(t *testing.T) {
			e := baseEnv(t, fx, 1)
			delete(e, name)
			mustFail(t, e, name+" is not set")
		})
	}
	cases := map[string]struct {
		mut  func(envMap)
		want string
	}{
		"no share source":     {func(e envMap) { delete(e, "SHARE_FILE") }, "no share source"},
		"missing share file":  {func(e envMap) { e["SHARE_FILE"] = "/nonexistent/share-1.json" }, "no such file"},
		"both share sources":  {func(e envMap) { e["VAULT_ADDR"] = "http://127.0.0.1:1" }, "configure exactly one"},
		"vault without token": {func(e envMap) { delete(e, "SHARE_FILE"); e["VAULT_ADDR"] = "http://127.0.0.1:1" }, "VAULT_TOKEN is not set"},
		"vault unreachable": {func(e envMap) {
			delete(e, "SHARE_FILE")
			e["VAULT_ADDR"] = "http://127.0.0.1:1"
			e["VAULT_TOKEN"] = "t"
		}, "vault request"},
		"signer id 0":            {func(e envMap) { e["SIGNER_ID"] = "0" }, "outside [1,5]"},
		"signer id 6":            {func(e envMap) { e["SIGNER_ID"] = "6" }, "outside [1,5]"},
		"signer id not a number": {func(e envMap) { e["SIGNER_ID"] = "one" }, "not an integer"},
		"missing meta":           {func(e envMap) { e["META_FILE"] = "/nonexistent/public-meta.json" }, "no such file"},
		"corrupt meta":           {func(e envMap) { e["META_FILE"] = writeTemp(t, `{"version":1`) }, "decode"},
		"meta with extra field":  {func(e envMap) { e["META_FILE"] = metaWithExtra(t, fx.MetaPath) }, "unknown field"},
		"corrupt policy":         {func(e envMap) { e["POLICY_FILE"] = writeTemp(t, `{}`) }, "issuer is required"},
		"missing policy file":    {func(e envMap) { e["POLICY_FILE"] = "/nonexistent/policy.json" }, "no such file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := baseEnv(t, fx, 1)
			tc.mut(e)
			mustFail(t, e, tc.want)
		})
	}
}

func writeTemp(t *testing.T, s string) string {
	p := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func metaWithExtra(t *testing.T, src string) string {
	b, _ := os.ReadFile(src)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["private_key"] = "x"
	out, _ := json.Marshal(m)
	return writeTemp(t, string(out))
}

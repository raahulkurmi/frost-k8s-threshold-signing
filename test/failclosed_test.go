package test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/keyshare"
	"frost-k8s-threshold-signing/internal/testutil"
)

func writeFile(t *testing.T, name, content string) string {
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// T8 (I9): the real coordinator binary refuses to start on any bad input,
// exits quickly with a clear error, and generates nothing.
func TestCoordinatorFailsClosed(t *testing.T) {
	fx := testutil.Key(t)
	pki := testutil.NewPKI(t)
	coord := pki.Coordinator(t)
	grpcCert := pki.CoordinatorGRPC(t)
	s1 := pki.Signer(t, 1)
	work := t.TempDir()
	base := func() map[string]string {
		return map[string]string{
			"META_FILE":        fx.MetaPath,
			"POLICY_FILE":      testutil.PolicyFile(t, t.TempDir(), testutil.PolicyConfig()),
			"SIGNER_ENDPOINTS": "1=https://127.0.0.1:1,2=https://127.0.0.1:2,3=https://127.0.0.1:3",
			"TLS_CERT":         coord.Cert,
			"TLS_KEY":          coord.Key,
			"TLS_CA":           pki.CA,
			"TCP_ADDR":         "127.0.0.1:0",
			"GRPC_TLS_CERT":    grpcCert.Cert,
			"GRPC_TLS_KEY":     grpcCert.Key,
			"GRPC_TLS_CA":      pki.CA,
			"HOME":             work,
		}
	}
	metaRaw, _ := os.ReadFile(fx.MetaPath)
	var metaMap map[string]any
	_ = json.Unmarshal(metaRaw, &metaMap)
	tamperedKid := func() string {
		m := map[string]any{}
		for k, v := range metaMap {
			m[k] = v
		}
		m["kid"] = "AAAAAAAAAAAAAAAAAAAAAA"
		b, _ := json.Marshal(m)
		return writeFile(t, "meta.json", string(b))
	}()
	cases := map[string]struct {
		mut  func(map[string]string)
		want string
	}{
		"missing META_FILE":           {func(e map[string]string) { delete(e, "META_FILE") }, "META_FILE is not set"},
		"meta file absent":            {func(e map[string]string) { e["META_FILE"] = filepath.Join(work, "nope.json") }, "no such file"},
		"corrupt meta":                {func(e map[string]string) { e["META_FILE"] = writeFile(t, "m.json", `{"version":1,`) }, "decode"},
		"meta kid does not match key": {func(e map[string]string) { e["META_FILE"] = tamperedKid }, "does not match public key"},
		"missing POLICY_FILE":         {func(e map[string]string) { delete(e, "POLICY_FILE") }, "POLICY_FILE is not set"},
		"missing TLS_CERT":            {func(e map[string]string) { delete(e, "TLS_CERT") }, "TLS_CERT is not set"},
		"cert file absent":            {func(e map[string]string) { e["TLS_CERT"] = filepath.Join(work, "x.crt") }, "no such file"},
		"missing TLS_CA":              {func(e map[string]string) { delete(e, "TLS_CA") }, "TLS_CA is not set"},
		"signer cert as client cert":  {func(e map[string]string) { e["TLS_CERT"], e["TLS_KEY"] = s1.Cert, s1.Key }, "not exactly DNS:coordinator"},
		"no endpoints":                {func(e map[string]string) { delete(e, "SIGNER_ENDPOINTS") }, "SIGNER_ENDPOINTS is not set"},
		"plain http endpoint":         {func(e map[string]string) { e["SIGNER_ENDPOINTS"] = "1=http://a,2=https://b,3=https://c" }, "must be https://"},
		"fewer than t endpoints":      {func(e map[string]string) { e["SIGNER_ENDPOINTS"] = "1=https://a,2=https://b" }, "threshold is 3"},
		"no listener":                 {func(e map[string]string) { delete(e, "TCP_ADDR") }, "exactly one of SOCKET_PATH or TCP_ADDR"},
		"bad strategy":                {func(e map[string]string) { e["VERIFY_STRATEGY"] = "none" }, "unknown verify strategy"},
		"bad deadline":                {func(e map[string]string) { e["SIGN_DEADLINE"] = "-1s" }, "SIGN_DEADLINE"},
		"TCP without gRPC mTLS cert":  {func(e map[string]string) { delete(e, "GRPC_TLS_CERT") }, "TCP_ADDR requires mTLS: GRPC_TLS_CERT is not set"},
		"TCP without gRPC client CA":  {func(e map[string]string) { delete(e, "GRPC_TLS_CA") }, "TCP_ADDR requires mTLS: GRPC_TLS_CA is not set"},
		"gRPC cert with wrong SAN":    {func(e map[string]string) { e["GRPC_TLS_CERT"], e["GRPC_TLS_KEY"] = coord.Cert, coord.Key }, "not exactly DNS:coordinator-grpc"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := base()
			tc.mut(e)
			before := listDir(t, work)
			err, out := runBinary(t, "grpc-proxy", e, 10*time.Second)
			if err == nil {
				t.Fatalf("coordinator started: %s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("output %q does not contain %q", out, tc.want)
			}
			if after := listDir(t, work); len(after) != len(before) {
				t.Fatalf("coordinator created files: %v", after)
			}
			t.Logf("exit %v: %s", err, strings.TrimSpace(out))
		})
	}
}

// T8 (runtime): unreachable signers -> request fails with named reasons.
func TestCoordinatorUnreachableSignersFail(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	eps := c.Endpoints(t, 1, 2, 3)
	for i := range eps {
		eps[i].URL = "https://127.0.0.1:1" // nothing listens
	}
	co, err := coordinator.New(coordinator.Config{Meta: c.Fx.Meta, Endpoints: eps, Deadline: 2 * time.Second, Strategy: coordinator.Strict})
	if err != nil {
		t.Fatal(err)
	}
	res, err := co.Sign(context.Background(), saClaims(t))
	var te *coordinator.ThresholdError
	if !errors.As(err, &te) || res != nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("res=%v err=%v", res, err)
	}
	t.Log(err)
}

func signerEnv(t *testing.T, fx *testutil.Fixture, id int) map[string]string {
	pki := testutil.NewPKI(t)
	sc := pki.Signer(t, id)
	return map[string]string{
		"SIGNER_ID":   string(rune('0' + id)),
		"META_FILE":   fx.MetaPath,
		"SHARE_FILE":  fx.SharePath(id),
		"POLICY_FILE": testutil.PolicyFile(t, t.TempDir(), testutil.PolicyConfig()),
		"AUDIT_LOG":   filepath.Join(t.TempDir(), "audit.log"),
		"TLS_CERT":    sc.Cert,
		"TLS_KEY":     sc.Key,
		"TLS_CA":      pki.CA,
		"LISTEN_ADDR": "127.0.0.1:0",
	}
}

func rewriteShareFile(t *testing.T, src string, mut func(*keyshare.File)) string {
	b, _ := os.ReadFile(src)
	var f keyshare.File
	_ = json.Unmarshal(b, &f)
	mut(&f)
	out, _ := json.Marshal(f)
	return writeFile(t, "share.json", string(out))
}

// T9: the real signer binary refuses a share for another index.
func TestWrongShareIndexRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := signerEnv(t, fx, 1)
	e["SHARE_FILE"] = fx.SharePath(2)
	err, out := runBinary(t, "signer", e, 10*time.Second)
	if err == nil || !strings.Contains(out, "share is for signer 2, this is signer 1") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	e["SHARE_FILE"] = rewriteShareFile(t, fx.SharePath(2), func(f *keyshare.File) { f.SignerIndex = 1 })
	err, out = runBinary(t, "signer", e, 10*time.Second)
	if err == nil || !strings.Contains(out, "does not match its verification key") {
		t.Fatalf("relabelled share: err=%v out=%s", err, out)
	}
	t.Log(strings.TrimSpace(out))
}

// T9: the real signer binary refuses a share whose kid differs from the meta.
func TestWrongKidRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := signerEnv(t, fx, 3)
	e["SHARE_FILE"] = rewriteShareFile(t, fx.SharePath(3), func(f *keyshare.File) { f.KID = "AAAAAAAAAAAAAAAAAAAAAA" })
	err, out := runBinary(t, "signer", e, 10*time.Second)
	if err == nil || !strings.Contains(out, "does not match meta kid") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	t.Log(strings.TrimSpace(out))
}

// I9 for the signer binary: missing inputs abort startup.
func TestSignerBinaryFailsClosed(t *testing.T) {
	fx := testutil.Key(t)
	for _, k := range []string{"SIGNER_ID", "META_FILE", "SHARE_FILE", "POLICY_FILE", "AUDIT_LOG", "TLS_CERT", "TLS_KEY", "TLS_CA"} {
		e := signerEnv(t, fx, 1)
		delete(e, k)
		if err, out := runBinary(t, "signer", e, 10*time.Second); err == nil {
			t.Fatalf("started without %s: %s", k, out)
		}
	}
}

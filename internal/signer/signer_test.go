package signer_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/audit"
	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/tlsconf"
	"frost-k8s-threshold-signing/internal/wire"
)

type env struct {
	fx       *testutil.Fixture
	srv      *signer.Server
	auditLog *audit.Log
	auditP   string
}

func newEnv(t *testing.T, id int, mut func(*policy.Config)) *env {
	t.Helper()
	fx := testutil.Key(t)
	cfg := testutil.PolicyConfig()
	if mut != nil {
		mut(&cfg)
	}
	pol, err := policy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ap := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(ap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	srv, err := signer.New(signer.Config{ID: id, Meta: fx.Meta, Share: fx.Shares[id-1], Policy: pol, Audit: al})
	if err != nil {
		t.Fatal(err)
	}
	return &env{fx: fx, srv: srv, auditLog: al, auditP: ap}
}

func (e *env) input(t *testing.T, mut func(map[string]any)) string {
	c := testutil.SAClaims("default", "default", time.Now(), time.Hour)
	if mut != nil {
		mut(c)
	}
	return testutil.Header(e.fx.Meta.KID) + "." + testutil.Payload(t, c)
}

func TestSignShareProducesVerifiableShare(t *testing.T) {
	e := newEnv(t, 2, nil)
	in := e.input(t, nil)
	resp, rej := e.srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "r1"}, "coordinator")
	if rej != nil {
		t.Fatal(rej)
	}
	if resp.SignerID != 2 || resp.RequestID != "r1" {
		t.Fatalf("resp %+v", resp)
	}
	ss, err := resp.Share.ToTcrsa(2, 5, e.fx.Meta.PublicKey.N)
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Verify(testutil.PaddedDigest(t, e.fx.Meta, in), e.fx.Meta.Tcrsa); err != nil {
		t.Fatalf("share does not verify over PKCS#1 v1.5(SHA-256(signing_input)): %v", err)
	}
}

func TestSignerRejectsBadHeaders(t *testing.T) {
	e := newEnv(t, 1, nil)
	kid := e.fx.Meta.KID
	payload := testutil.Payload(t, testutil.SAClaims("default", "default", time.Now(), time.Hour))
	hdr := func(s string) string { return testutil.B64([]byte(s)) + "." + payload }
	cases := map[string]string{
		"alg none":            hdr(`{"alg":"none","typ":"JWT","kid":"` + kid + `"}`),
		"alg ES256":           hdr(`{"alg":"ES256","typ":"JWT","kid":"` + kid + `"}`),
		"alg HS256":           hdr(`{"alg":"HS256","typ":"JWT","kid":"` + kid + `"}`),
		"alg PS256":           hdr(`{"alg":"PS256","typ":"JWT","kid":"` + kid + `"}`),
		"different kid":       hdr(`{"alg":"RS256","typ":"JWT","kid":"some-other-key"}`),
		"missing kid":         hdr(`{"alg":"RS256","typ":"JWT"}`),
		"typ JWS":             hdr(`{"alg":"RS256","typ":"JWS","kid":"` + kid + `"}`),
		"extra jku field":     hdr(`{"alg":"RS256","typ":"JWT","kid":"` + kid + `","jku":"https://evil.example/jwks"}`),
		"extra crit field":    hdr(`{"alg":"RS256","typ":"JWT","kid":"` + kid + `","crit":["exp"]}`),
		"non-canonical order": hdr(`{"kid":"` + kid + `","alg":"RS256","typ":"JWT"}`),
		"whitespace":          hdr(`{"alg": "RS256","typ":"JWT","kid":"` + kid + `"}`),
		"duplicate alg":       hdr(`{"alg":"none","alg":"RS256","typ":"JWT","kid":"` + kid + `"}`),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			resp, rej := e.srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "h"}, "coordinator")
			if rej == nil || resp != nil {
				t.Fatal("signer produced a share")
			}
			if rej.Status != http.StatusForbidden {
				t.Fatalf("status %d (%v), want 403", rej.Status, rej)
			}
			t.Logf("rejected: %v", rej)
		})
	}
}

// TestSignerRejectsPrehashedInput (I8 unit): the signer only accepts a JWS
// signing input; it never signs a caller-supplied digest or padded block.
func TestSignerRejectsPrehashedInput(t *testing.T) {
	e := newEnv(t, 1, nil)
	in := e.input(t, nil)
	digest := sha256.Sum256([]byte(in))
	padded := testutil.PaddedDigest(t, e.fx.Meta, in)
	cases := map[string]string{
		"raw digest, base64url":   testutil.B64(digest[:]),
		"raw digest, hex":         base16(digest[:]),
		"raw digest, base64 std":  base64.StdEncoding.EncodeToString(digest[:]),
		"padded block, base64url": testutil.B64(padded),
		"padded block as payload": testutil.Header(e.fx.Meta.KID) + "." + testutil.B64(padded),
		"digest as payload":       testutil.Header(e.fx.Meta.KID) + "." + testutil.B64(digest[:]),
		"full JWT (3 segments)":   in + "." + testutil.B64([]byte("sig")),
		"empty":                   "",
		"padded base64 segments":  strings.Replace(in, ".", "=.", 1),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if resp, rej := e.srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: s, RequestID: "p"}, "coordinator"); rej == nil || resp != nil {
				t.Fatal("signer produced a share")
			} else {
				t.Logf("rejected: %v", rej)
			}
		})
	}
	// Unknown request fields (a "digest" or "padded" field) are rejected by the HTTP API.
	for _, body := range []string{
		`{"signing_input":"` + in + `","request_id":"x","digest":"` + testutil.B64(digest[:]) + `"}`,
		`{"digest":"` + testutil.B64(digest[:]) + `","request_id":"x"}`,
		`{"padded":"` + testutil.B64(padded) + `","request_id":"x"}`,
	} {
		rec := httptest.NewRecorder()
		e.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, wire.SignSharePath, strings.NewReader(body)))
		if rec.Code == http.StatusOK {
			t.Fatalf("HTTP API accepted %s", body)
		}
	}
}

func TestSignerAppliesPolicy(t *testing.T) {
	e := newEnv(t, 1, nil)
	for name, mut := range map[string]func(map[string]any){
		"wrong iss":      func(c map[string]any) { c["iss"] = "https://evil.example" },
		"disallowed aud": func(c map[string]any) { c["aud"] = []string{"evil"} },
		"exp too long":   func(c map[string]any) { c["exp"] = time.Now().Add(48 * time.Hour).Unix() },
		"malformed sub":  func(c map[string]any) { c["sub"] = "system:masters" },
		"stale iat": func(c map[string]any) {
			iat := time.Now().Add(-time.Hour).Unix()
			c["iat"], c["nbf"], c["exp"] = iat, iat, iat+600
		},
		"cluster-admin?": func(c map[string]any) {
			c["sub"] = "system:serviceaccount:kube-system:clusterrole-aggregation-controller"
			c["kubernetes.io"] = map[string]any{"namespace": "kube-system", "serviceaccount": map[string]any{"name": "clusterrole-aggregation-controller", "uid": "u"}}
		},
	} {
		resp, rej := e.srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: e.input(t, mut), RequestID: "q"}, "coordinator")
		if name == "cluster-admin?" {
			// A policy-compliant subject is signed: the policy is not an authorization system.
			if rej != nil {
				t.Fatalf("%s: %v", name, rej)
			}
			continue
		}
		if rej == nil || resp != nil || rej.Status != http.StatusForbidden {
			t.Fatalf("%s: signer produced a share (rej=%v)", name, rej)
		}
	}
}

func TestSignerRateLimit(t *testing.T) {
	e := newEnv(t, 1, func(c *policy.Config) { c.RateLimit = policy.Rate{RequestsPerSecond: 0.001, Burst: 2} })
	in := e.input(t, nil)
	for i := 0; i < 2; i++ {
		if _, rej := e.srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "a"}, ""); rej != nil {
			t.Fatal(rej)
		}
	}
	_, rej := e.srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "a"}, "")
	if rej == nil || rej.Status != http.StatusTooManyRequests {
		t.Fatalf("3rd request not rate limited: %v", rej)
	}
}

func TestSignerAuditLog(t *testing.T) {
	e := newEnv(t, 3, nil)
	good := e.input(t, nil)
	resp, rej := e.srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: good, RequestID: "allow-1"}, "coordinator")
	if rej != nil {
		t.Fatal(rej)
	}
	_, _ = e.srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: e.input(t, func(c map[string]any) { c["iss"] = "x" }), RequestID: "deny-1"}, "coordinator")

	f, err := os.Open(e.auditP)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, _ := os.ReadFile(e.auditP)
	if bytes.Contains(raw, []byte(resp.Share.Xi)) || bytes.Contains(raw, []byte(resp.Share.Z)) {
		t.Fatal("audit log contains the signature share")
	}
	var entries []audit.Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var en audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &en); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, en)
	}
	if len(entries) != 2 {
		t.Fatalf("%d audit entries, want 2", len(entries))
	}
	sum := sha256.Sum256([]byte(good))
	a, d := entries[0], entries[1]
	if a.Decision != "allow" || a.RequestID != "allow-1" || a.Sub != "system:serviceaccount:default:default" ||
		a.SigningInputSHA256 != base16(sum[:]) || len(a.Aud) != 1 || a.SignerID != 3 || a.Client != "coordinator" {
		t.Fatalf("allow entry %+v", a)
	}
	if d.Decision != "deny" || d.RequestID != "deny-1" || !strings.Contains(d.Reason, "iss") {
		t.Fatalf("deny entry %+v", d)
	}
	t.Logf("audit: %s", strings.TrimSpace(string(raw)))
}

func TestSignerRefusesWhenAuditFails(t *testing.T) {
	e := newEnv(t, 1, nil)
	e.auditLog.Close()
	resp, rej := e.srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: e.input(t, nil), RequestID: "z"}, "")
	if rej == nil || resp != nil {
		t.Fatal("signed without an audit record")
	}
}

func TestSignerNewRejectsForeignShare(t *testing.T) {
	fx := testutil.Key(t)
	pol, _ := policy.New(testutil.PolicyConfig())
	al, _ := audit.Open(filepath.Join(t.TempDir(), "a"))
	defer al.Close()
	if _, err := signer.New(signer.Config{ID: 1, Meta: fx.Meta, Share: fx.Shares[1], Policy: pol, Audit: al}); err == nil {
		t.Fatal("signer 1 accepted share 2")
	}
}

func base16(b []byte) string {
	const hx = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, hx[c>>4], hx[c&15])
	}
	return string(out)
}

// --- mTLS identity (integration) ---

func startTLS(t *testing.T, e *env, pki *testutil.PKI, id int) *httptest.Server {
	t.Helper()
	sc := pki.Signer(t, id)
	cfg, err := tlsconf.SignerServer(sc.Cert, sc.Key, pki.CA, id)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(e.srv.Handler())
	ts.TLS = cfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func clientWith(t *testing.T, pki *testutil.PKI, cert *testutil.CertPaths) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(pki.CA)
	pool.AppendCertsFromPEM(caPEM)
	cfg := &tls.Config{RootCAs: pool, ServerName: "signer-1", MinVersion: tls.VersionTLS13}
	if cert != nil {
		c, err := tls.LoadX509KeyPair(cert.Cert, cert.Key)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func TestTLSRejectsClientWithoutCoordinatorSAN(t *testing.T) {
	e := newEnv(t, 1, nil)
	pki := testutil.NewPKI(t)
	ts := startTLS(t, e, pki, 1)
	other := testutil.NewPKI(t)

	coord := pki.Coordinator(t)
	signer2 := pki.Signer(t, 2)
	attacker := pki.Issue(t, "attacker", []string{"attacker"}, x509.ExtKeyUsageClientAuth)
	twoSANs := pki.Issue(t, "coordinator-plus", []string{"coordinator", "signer-1"}, x509.ExtKeyUsageClientAuth)
	serverEKU := pki.Issue(t, "coordinator-server-eku", []string{"coordinator"}, x509.ExtKeyUsageServerAuth)
	foreign := other.Coordinator(t)

	body := func() *strings.Reader {
		return strings.NewReader(`{"signing_input":"` + e.input(t, nil) + `","request_id":"tls"}`)
	}
	resp, err := clientWith(t, pki, &coord).Post(ts.URL+wire.SignSharePath, "application/json", body())
	if err != nil {
		t.Fatalf("coordinator client rejected: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("coordinator client got %d", resp.StatusCode)
	}

	for name, c := range map[string]*testutil.CertPaths{
		"no client cert":                  nil,
		"signer-2 cert (same CA)":         &signer2,
		"SAN attacker (same CA)":          &attacker,
		"SANs coordinator+signer-1":       &twoSANs,
		"coordinator SAN, serverAuth EKU": &serverEKU,
		"coordinator SAN, foreign CA":     &foreign,
	} {
		resp, err := clientWith(t, pki, c).Post(ts.URL+wire.SignSharePath, "application/json", body())
		if err == nil {
			resp.Body.Close()
			t.Fatalf("%s: request succeeded with HTTP %d", name, resp.StatusCode)
		}
		t.Logf("%s: rejected at TLS: %v", name, err)
	}
}

func TestTLSSignerOwnCertMustMatchID(t *testing.T) {
	pki := testutil.NewPKI(t)
	s2 := pki.Signer(t, 2)
	if _, err := tlsconf.SignerServer(s2.Cert, s2.Key, pki.CA, 1); err == nil {
		t.Fatal("signer 1 started with signer-2's certificate")
	}
	if _, err := tlsconf.SignerServer(s2.Cert, s2.Key, "", 2); err == nil {
		t.Fatal("signer started without a CA")
	}
}

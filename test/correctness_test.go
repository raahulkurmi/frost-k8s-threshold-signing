package test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	josev2 "gopkg.in/go-jose/go-jose.v2"
	jwtv2 "gopkg.in/go-jose/go-jose.v2/jwt"
	externaljwtv1 "k8s.io/externaljwt/apis/v1"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/wire"
)

// T1 (I1, I2): the key comes ONLY from FetchKeys; verification uses only
// go-jose v2.6.3 (kube-apiserver's verifier) and crypto/rsa.
func TestIssuedJWTVerifiesWithFetchKeysOnly(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	client := serveGRPC(t, c, c.NewCoordinator(t, coordinator.Strict, 5*time.Second, nil))
	ctx := context.Background()

	claims := saClaims(t)
	resp, err := client.Sign(ctx, &externaljwtv1.SignJWTRequest{Claims: claims})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := client.FetchKeys(ctx, &externaljwtv1.FetchKeysRequest{})
	if err != nil {
		t.Fatal(err)
	}
	token := resp.Header + "." + claims + "." + resp.Signature

	// No project code from here on.
	parsed, err := jwtv2.ParseSigned(token)
	if err != nil {
		t.Fatal(err)
	}
	var key *externaljwtv1.Key
	for _, k := range keys.Keys {
		if k.KeyId == parsed.Headers[0].KeyID {
			key = k
		}
	}
	if key == nil {
		t.Fatalf("no FetchKeys key for kid %q", parsed.Headers[0].KeyID)
	}
	pubAny, err := x509.ParsePKIXPublicKey(key.Key)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubAny.(*rsa.PublicKey)
	if parsed.Headers[0].Algorithm != string(josev2.RS256) {
		t.Fatalf("alg %q", parsed.Headers[0].Algorithm)
	}
	var std jwtv2.Claims
	if err := parsed.Claims(pub, &std); err != nil {
		t.Fatalf("go-jose v2 rejected token: %v", err)
	}
	if err := std.Validate(jwtv2.Expected{Issuer: testutil.Issuer, Audience: jwtv2.Audience{testutil.Issuer}, Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(resp.Signature)
	sum := sha256.Sum256([]byte(resp.Header + "." + claims))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatal(err)
	}
	t.Logf("token kid=%s verified by go-jose v2.6.3 and rsa.VerifyPKCS1v15 with the FetchKeys key only; sub=%s", key.KeyId, std.Subject)
}

// T2 (I6): every 3-subset yields byte-identical signatures for the same input.
func TestAllThresholdSubsetsIdentical(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	claims := saClaims(t)
	var ref string
	n := 0
	for a := 1; a <= 5; a++ {
		for b := a + 1; b <= 5; b++ {
			for d := b + 1; d <= 5; d++ {
				co := c.NewCoordinator(t, coordinator.Strict, 5*time.Second, nil, a, b, d)
				res, err := co.Sign(context.Background(), claims)
				if err != nil {
					t.Fatalf("subset {%d,%d,%d}: %v", a, b, d, err)
				}
				if got := res.Signers; len(got) != 3 || got[0] != a || got[1] != b || got[2] != d {
					t.Fatalf("subset {%d,%d,%d} combined %v", a, b, d, got)
				}
				if ref == "" {
					ref = res.Signature
				} else if res.Signature != ref {
					t.Fatalf("subset {%d,%d,%d} signature differs", a, b, d)
				}
				n++
			}
		}
	}
	if n != 10 {
		t.Fatalf("%d subsets", n)
	}
	s, _ := base64.RawURLEncoding.DecodeString(ref)
	t.Logf("all %d subsets byte-identical; sha256(sig)=%x", n, sha256.Sum256(s))
}

// T3 (I5): with only 2 signers reachable, Sign fails and returns no token.
func TestBelowThresholdFails(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	for _, id := range []int{3, 4, 5} {
		c.Servers[id].Close()
	}
	client := serveGRPC(t, c, c.NewCoordinator(t, coordinator.Strict, 2*time.Second, nil))
	resp, err := client.Sign(context.Background(), &externaljwtv1.SignJWTRequest{Claims: saClaims(t)})
	if err == nil || resp != nil {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
	if !strings.Contains(err.Error(), "2 valid shares, need 3") {
		t.Fatalf("error does not report the share count: %v", err)
	}
	t.Log(err)
}

// T4 (I5): an attacker holding 2 real shares cannot forge, whatever they do
// with the library.
func TestTwoSharesCannotForge(t *testing.T) {
	fx := testutil.Key(t)
	meta := fx.Meta
	input := testutil.Header(meta.KID) + "." + saClaims(t)
	doc := testutil.PaddedDigest(t, meta, input)
	for a := 0; a < 5; a++ {
		for b := a + 1; b < 5; b++ {
			pair := []*tcrsa.KeyShare{fx.Shares[a], fx.Shares[b]}
			if _, err := testutil.OfflineCombine(t, meta.Tcrsa, pair, doc); err == nil {
				t.Fatalf("Join accepted 2 shares {%d,%d}", a+1, b+1)
			}
			weak := *meta.Tcrsa
			weak.K = 2
			if sig, err := testutil.OfflineCombine(t, &weak, pair, doc); err == nil && testutil.VerifyPKCS1(meta.PublicKey, input, sig) == nil {
				t.Fatalf("pair {%d,%d} forged with K forced to 2", a+1, b+1)
			}
			// A fabricated third share (random si, index of a missing signer).
			missing := 1
			for missing == a+1 || missing == b+1 {
				missing++
			}
			fake := &tcrsa.KeyShare{Id: uint16(missing), Si: randomBytes(t, 256)}
			if sig, err := testutil.OfflineCombine(t, meta.Tcrsa, append(pair, fake), doc); err == nil && testutil.VerifyPKCS1(meta.PublicKey, input, sig) == nil {
				t.Fatalf("pair {%d,%d} + fabricated share forged a signature", a+1, b+1)
			}
		}
	}
	t.Log("all 10 pairs: Join refuses; K forced to 2 and fabricated third shares yield invalid signatures")
}

func randomBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// directClient calls signers with the real coordinator identity, bypassing
// the coordinator entirely (a compromised coordinator's view).
func directClient(t *testing.T, c *testutil.Cluster, id int) *http.Client {
	cert, err := tls.LoadX509KeyPair(c.CoordinatorCert().Cert, c.CoordinatorCert().Key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(c.PKI.CA)
	pool.AppendCertsFromPEM(pem)
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "signer-" + string(rune('0'+id)), MinVersion: tls.VersionTLS13}}}
}

func postShare(t *testing.T, c *testutil.Cluster, id int, body string) (int, []byte) {
	resp, err := directClient(t, c, id).Post(c.Servers[id].URL+wire.SignSharePath, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func reqBody(input string) string {
	b, _ := json.Marshal(wire.SignShareRequest{SigningInput: input, RequestID: "direct"})
	return string(b)
}

// T6 (I8): a signer never signs a caller-supplied digest or padded block.
func TestSignerRejectsPrehashedInput(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	meta := c.Fx.Meta
	input := testutil.Header(meta.KID) + "." + saClaims(t)
	digest := sha256.Sum256([]byte(input))
	padded := testutil.PaddedDigest(t, meta, input)
	bodies := map[string]string{
		"digest as signing_input":       reqBody(testutil.B64(digest[:])),
		"padded block as signing_input": reqBody(testutil.B64(padded)),
		"header.digest":                 reqBody(testutil.Header(meta.KID) + "." + testutil.B64(digest[:])),
		"header.padded":                 reqBody(testutil.Header(meta.KID) + "." + testutil.B64(padded)),
		"extra digest field":            `{"signing_input":"` + input + `","request_id":"x","digest":"` + testutil.B64(digest[:]) + `"}`,
		"digest field only":             `{"digest":"` + testutil.B64(digest[:]) + `","request_id":"x"}`,
		"hash_alg override":             `{"signing_input":"` + input + `","request_id":"x","hash":"none"}`,
	}
	for name, body := range bodies {
		for id := 1; id <= 5; id++ {
			code, resp := postShare(t, c, id, body)
			if code == http.StatusOK {
				t.Fatalf("%s: signer %d returned a share: %s", name, id, resp)
			}
		}
		t.Logf("%s: refused by all 5 signers", name)
	}
	// Control: the genuine signing input is accepted.
	if code, _ := postShare(t, c, 1, reqBody(input)); code != http.StatusOK {
		t.Fatalf("genuine signing input refused: %d", code)
	}
}

// T7 (D11 mitigation): a caller holding the real coordinator cert (a
// compromised coordinator) calls every signer directly with
// policy-violating claims; every signer refuses, so no token can be formed.
func TestSignerPolicyRejectsCoordinatorBypass(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	kid := c.Fx.Meta.KID
	violations := map[string]func(map[string]any){
		"wrong iss":      func(m map[string]any) { m["iss"] = "https://attacker.example" },
		"disallowed aud": func(m map[string]any) { m["aud"] = []string{"https://vault.attacker.example"} },
		"exp too long":   func(m map[string]any) { m["exp"] = time.Now().Add(30 * 24 * time.Hour).Unix() },
		"malformed sub":  func(m map[string]any) { m["sub"] = "system:masters" },
		"user sub":       func(m map[string]any) { m["sub"] = "kubernetes-admin" },
		"backdated iat": func(m map[string]any) {
			iat := time.Now().Add(-2 * time.Hour).Unix()
			m["iat"], m["nbf"], m["exp"] = iat, iat, iat+600
		},
		"sub/claims skew": func(m map[string]any) { m["sub"] = "system:serviceaccount:kube-system:admin" },
		"case-variant":    nil, // raw below
	}
	for name, mut := range violations {
		var input string
		if mut == nil {
			input = testutil.Header(kid) + "." + testutil.B64([]byte(`{"iss":"https://attacker.example","ISS":"`+testutil.Issuer+`"}`))
		} else {
			m := testutil.SAClaims("default", "default", time.Now(), time.Hour)
			mut(m)
			input = testutil.Header(kid) + "." + testutil.Payload(t, m)
		}
		shares := 0
		for id := 1; id <= 5; id++ {
			code, body := postShare(t, c, id, reqBody(input))
			if code == http.StatusOK {
				shares++
			} else if code != http.StatusForbidden {
				t.Fatalf("%s: signer %d answered %d %s", name, id, code, body)
			}
		}
		if shares != 0 {
			t.Fatalf("%s: %d signers produced shares", name, shares)
		}
		t.Logf("%s: 0/5 shares (all 403 policy)", name)
	}
}

func TestSignerPolicyRejectsWrongHeaderDirect(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	payload := saClaims(t)
	for name, hdr := range map[string]string{
		"alg none": `{"alg":"none","typ":"JWT","kid":"` + c.Fx.Meta.KID + `"}`,
		"ES256":    `{"alg":"ES256","typ":"JWT","kid":"` + c.Fx.Meta.KID + `"}`,
		"old kid":  `{"alg":"RS256","typ":"JWT","kid":"frost-k8s-v1"}`,
	} {
		for id := 1; id <= 5; id++ {
			if code, _ := postShare(t, c, id, reqBody(testutil.B64([]byte(hdr))+"."+payload)); code != http.StatusForbidden {
				t.Fatalf("%s: signer %d answered %d", name, id, code)
			}
		}
	}
}

// T10: 3 signers delayed past the deadline -> error within deadline + margin.
func TestDeadlineRespected(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id >= 3 {
			return testutil.Delay(30*time.Second, h)
		}
		return h
	}})
	const deadline = 500 * time.Millisecond
	co := c.NewCoordinator(t, coordinator.Strict, deadline, nil)
	start := time.Now()
	res, err := co.Sign(context.Background(), saClaims(t))
	el := time.Since(start)
	var te *coordinator.ThresholdError
	if !errors.As(err, &te) || res != nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if el > deadline+200*time.Millisecond {
		t.Fatalf("returned after %v (deadline %v)", el, deadline)
	}
	t.Logf("returned after %v with deadline %v: %v", el.Round(time.Millisecond), deadline, err)
}

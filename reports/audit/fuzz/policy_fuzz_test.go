//go:build auditfuzz

package fuzz

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jwtv2 "gopkg.in/go-jose/go-jose.v2/jwt"

	"frost-k8s-threshold-signing/internal/jwtfmt"
	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/testutil"
)

// Mirror of kube-apiserver v1.36 pkg/serviceaccount/claims.go private claims
// (privateClaims / kubernetes / ref). Field names and tags mirrored from
// upstream knowledge, not imported (k8s.io/kubernetes is not a dependency).
type k8sPrivateClaims struct {
	Kubernetes k8sKubernetes `json:"kubernetes.io,omitempty"`
}

type k8sKubernetes struct {
	Namespace string             `json:"namespace,omitempty"`
	Svcacct   k8sRef             `json:"serviceaccount,omitempty"`
	Pod       *k8sRef            `json:"pod,omitempty"`
	Secret    *k8sRef            `json:"secret,omitempty"`
	Node      *k8sRef            `json:"node,omitempty"`
	WarnAfter *jwtv2.NumericDate `json:"warnafter,omitempty"`
}

type k8sRef struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

var (
	stdKeyOnce sync.Once
	stdKey     *rsa.PrivateKey
)

// apiserverView signs payload as a compact RS256 JWS with a plain RSA key and
// decodes it exactly as kube-apiserver does: go-jose v2 jwt.ParseSigned, then
// .Claims(pub, &jwt.Claims, &privateClaims).
func apiserverView(payload []byte) (*jwtv2.Claims, *k8sPrivateClaims, error) {
	stdKeyOnce.Do(func() {
		var err error
		if stdKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	hdr, _ := jwtfmt.EncodedHeader(seedKID)
	input := hdr + "." + testutil.B64(payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(nil, stdKey, crypto.SHA256, sum[:])
	if err != nil {
		return nil, nil, err
	}
	tok, err := jwtv2.ParseSigned(input + "." + testutil.B64(sig))
	if err != nil {
		return nil, nil, fmt.Errorf("parse: %w", err)
	}
	var pub jwtv2.Claims
	var priv k8sPrivateClaims
	if err := tok.Claims(&stdKey.PublicKey, &pub, &priv); err != nil {
		return nil, nil, fmt.Errorf("claims: %w", err)
	}
	return &pub, &priv, nil
}

// rederive extracts exp/nbf independently (stdlib, UseNumber).
func rederive(payload []byte) (exp int64, nbf *int64, err error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return 0, nil, err
	}
	en, ok := m["exp"].(json.Number)
	if !ok {
		return 0, nil, fmt.Errorf("exp %T", m["exp"])
	}
	if exp, err = en.Int64(); err != nil {
		return 0, nil, err
	}
	if v, ok := m["nbf"]; ok {
		nn, ok := v.(json.Number)
		if !ok {
			return 0, nil, fmt.Errorf("nbf %T", v)
		}
		x, err := nn.Int64()
		if err != nil {
			return 0, nil, err
		}
		nbf = &x
	}
	return exp, nbf, nil
}

type diffOutcome int

const (
	diffBothReject diffOutcome = iota
	diffAgree
	diffApiserverRejects // policy accepts, go-jose rejects: fail closed (info)
)

// checkDifferential evaluates payload under p and, if accepted, asserts the
// apiserver's view is identical. It returns an error only for a real finding.
func checkDifferential(p *policy.Policy, issuer string, payload []byte) (diffOutcome, error) {
	d, err := p.Evaluate(payload, fixedNow)
	if err != nil {
		return diffBothReject, nil
	}
	pub, priv, aerr := apiserverView(payload)
	if aerr != nil {
		return diffApiserverRejects, nil
	}
	exp, nbf, rerr := rederive(payload)
	if rerr != nil {
		return 0, fmt.Errorf("policy accepted but independent re-derivation failed: %v", rerr)
	}
	var diffs []string
	if pub.Issuer != issuer {
		diffs = append(diffs, fmt.Sprintf("iss %q vs policy %q", pub.Issuer, issuer))
	}
	if pub.Subject != d.Subject {
		diffs = append(diffs, fmt.Sprintf("sub %q vs %q", pub.Subject, d.Subject))
	}
	if !slices.Equal([]string(pub.Audience), d.Audiences) {
		diffs = append(diffs, fmt.Sprintf("aud %q vs %q", pub.Audience, d.Audiences))
	}
	if pub.Expiry == nil || int64(*pub.Expiry) != exp {
		diffs = append(diffs, fmt.Sprintf("exp %v vs %d", pub.Expiry, exp))
	}
	if pub.IssuedAt == nil || int64(*pub.IssuedAt) != d.IssuedAt {
		diffs = append(diffs, fmt.Sprintf("iat %v vs %d", pub.IssuedAt, d.IssuedAt))
	}
	switch {
	case nbf == nil && pub.NotBefore != nil:
		diffs = append(diffs, fmt.Sprintf("nbf %d vs absent", *pub.NotBefore))
	case nbf != nil && (pub.NotBefore == nil || int64(*pub.NotBefore) != *nbf):
		diffs = append(diffs, fmt.Sprintf("nbf %v vs %d", pub.NotBefore, *nbf))
	}
	k := priv.Kubernetes
	if k.Namespace != d.Namespace {
		diffs = append(diffs, fmt.Sprintf("kubernetes.io.namespace %q vs %q", k.Namespace, d.Namespace))
	}
	if k.Svcacct.Name != d.ServiceAccount {
		diffs = append(diffs, fmt.Sprintf("kubernetes.io.serviceaccount.name %q vs %q", k.Svcacct.Name, d.ServiceAccount))
	}
	if "system:serviceaccount:"+k.Namespace+":"+k.Svcacct.Name != d.Subject {
		diffs = append(diffs, "apiserver username differs from validated sub")
	}
	gotPod := ""
	if k.Pod != nil {
		gotPod = k.Pod.UID
	}
	if gotPod != d.PodUID {
		diffs = append(diffs, fmt.Sprintf("kubernetes.io.pod.uid %q vs %q", gotPod, d.PodUID))
	}
	// Lifetime/skew as the apiserver sees it must also satisfy the policy.
	cfg := p.Config()
	if pub.Expiry != nil && pub.IssuedAt != nil {
		if life := int64(*pub.Expiry) - int64(*pub.IssuedAt); life <= 0 || life > cfg.MaxTokenSeconds {
			diffs = append(diffs, fmt.Sprintf("apiserver-visible lifetime %d violates policy", life))
		}
	}
	if len(diffs) > 0 {
		return 0, fmt.Errorf("PARSER DIFFERENTIAL: %s", strings.Join(diffs, "; "))
	}
	return diffAgree, nil
}

func policySeeds(t testing.TB) [][]byte {
	base := func(mut func(map[string]any)) []byte {
		c := saClaims("default", "default")
		if mut != nil {
			mut(c)
		}
		return mustJSON(t, c)
	}
	good := string(base(nil))
	iss := testutil.Issuer
	rep := func(old, nw string) []byte { return []byte(strings.Replace(good, old, nw, 1)) }
	var out [][]byte
	out = append(out,
		base(nil),
		base(func(c map[string]any) { c["aud"] = iss }),
		base(func(c map[string]any) { c["aud"] = []string{iss, "vault"} }),
		base(func(c map[string]any) { delete(c, "nbf") }),
		base(func(c map[string]any) {
			k := c["kubernetes.io"].(map[string]any)
			k["pod"] = map[string]any{"name": "web-0", "uid": "11111111-2222-3333-4444-555555555555"}
			k["node"] = map[string]any{"name": "n", "uid": "z"}
			k["warnafter"] = fixedNow.Unix() + 3000
		}),
		base(func(c map[string]any) {
			c["sub"] = "system:serviceaccount:team-a:ci.deployer"
			c["kubernetes.io"] = map[string]any{"namespace": "team-a", "serviceaccount": map[string]any{"name": "ci.deployer", "uid": "u"}}
		}),
		base(func(c map[string]any) { c["kubernetes.io"].(map[string]any)["secret"] = map[string]any{"name": "s", "uid": "y"} }),
		// duplicate / case-variant / escaped / folded keys
		rep(`"iss":`, `"iss":"https://evil.example","iss":`),
		rep(`"iss":`, `"ISS":"https://evil.example","iss":`),
		rep(`"iss":`, `"Iss":"https://evil.example","iss":`),
		rep(`"iss":`, `"iss":"https://evil.example","iss":`),
		rep(`"iss":"`+iss+`"`, `"iss":"`+iss+`"`),
		rep(`"iss":"`+iss+`"`, `"iss":"`+iss+`"`),
		rep(`"sub":`, `"ſub":"system:serviceaccount:kube-system:admin","sub":`),
		rep(`"sub":`, `"SUB":"system:serviceaccount:kube-system:admin","sub":`),
		rep(`"kubernetes.io":`, `"Kubernetes.io":{"namespace":"kube-system","serviceaccount":{"name":"admin"}},"kubernetes.io":`),
		rep(`"kubernetes.io":`, `"Kubernetes.io":{"namespace":"kube-system","serviceaccount":{"name":"admin"}},"kubernetes.io":`),
		rep(`"namespace":"default"`, `"namespace":"kube-system","namespace":"default"`),
		rep(`"namespace":"default"`, `"namespace":"default","NAMESPACE":"kube-system"`),
		rep(`"namespace":"default"`, `"namespace":"default","Namespace":"kube-system"`),
		rep(`"namespace":"default"`, `"namespace":"default","namespacK":"kube-system"`),
		rep(`"name":"default"`, `"name":"default","Name":"admin"`),
		rep(`"name":"default"`, `"name":"default","name":"admin"`),
		rep(`"serviceaccount":`, `"serviceAccount":{"name":"admin"},"serviceaccount":`),
		// numbers
		rep(`"iat":1800000000`, `"iat":"1800000000"`),
		rep(`"iat":1800000000`, `"iat":1800000000.0`),
		rep(`"iat":1800000000`, `"iat":1.8e9`),
		rep(`"iat":1800000000`, `"iat":18000000000e-1`),
		rep(`"exp":1800003600`, `"exp":1800003600.4`),
		rep(`"exp":1800003600`, `"exp":99999999999999999999999`),
		rep(`"exp":1800003600`, `"exp":9223372036854775807`),
		rep(`"nbf":1800000000`, `"nbf":-1800000000`),
		rep(`"nbf":1800000000`, `"nbf":null`),
		rep(`"nbf":1800000000`, `"nbf":1800000000.9`),
		// null / type confusion
		rep(`"iss":"`+iss+`"`, `"iss":null`),
		rep(`"aud":["`+iss+`"]`, `"aud":null`),
		rep(`"aud":["`+iss+`"]`, `"aud":["`+iss+`",null]`),
		rep(`"aud":["`+iss+`"]`, `"aud":[]`),
		rep(`"aud":["`+iss+`"]`, `"aud":{"0":"`+iss+`"}`),
		rep(`"aud":["`+iss+`"]`, `"aud":"`+iss+`","AUD":["evil"]`),
		rep(`"uid":"8a4e2c1f-9b3d-4e6a-8c7f-1d2b3a4c5e6f"`, `"uid":5`),
		rep(`"namespace":"default"`, `"namespace":"default","pod":"x"`),
		rep(`"namespace":"default"`, `"namespace":"default","pod":null`),
		rep(`"namespace":"default"`, `"namespace":"default","pod":{"uid":"a","UID":"b"}`),
		rep(`"namespace":"default"`, `"namespace":"default","node":{"name":1}`),
		rep(`"namespace":"default"`, `"namespace":"default","warnafter":"soon"`),
		rep(`"jti":"3f1c9a52-7d0e-4b8f-a6c1-5e2d9b7a0c34"`, `"jti":7`),
		// encoding
		append([]byte("\xef\xbb\xbf"), base(nil)...),
		rep(`"jti":"3f1c9a52`, "\"jti\":\"\xff\xfe"),
		rep(`"jti":"3f1c9a52`, "\"jt\xffi\":\"3f1c9a52"),
		rep(`"jti":"3f1c9a52`, `"jti":"\ud800`),
		rep(`"iss":"`+iss+`"`, "\"iss\":\""+iss+"\xff\""),
		rep(`"iss":"`+iss+`"`, `"iss":"`+iss+`\u0000"`),
		append(base(nil), ' ', '\n'),
		append(base(nil), []byte(`{}`)...),
		[]byte(`{}`),
		[]byte(`null`),
		[]byte(`[]`),
	)
	return out
}

// FuzzPolicyEvaluate: policy.Evaluate under the test policy and
// deploy/policy.json, with a go-jose v2 (kube-apiserver) differential oracle.
func FuzzPolicyEvaluate(f *testing.F) {
	for _, s := range policySeeds(f) {
		f.Add(s)
	}
	pt := mustPolicy(f, testPolicyConfig())
	pd := deployPolicy(f)
	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, p := range []*policy.Policy{pt, pd} {
			done := make(chan struct{})
			var out diffOutcome
			var err error
			start := time.Now()
			go func() { defer close(done); out, err = checkDifferential(p, p.Config().Issuer, payload) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("Evaluate/differential did not finish in 5s (len %d)", len(payload))
			}
			if el := time.Since(start); el > time.Second {
				t.Fatalf("slow evaluation: %v", el)
			}
			if err != nil {
				t.Fatalf("%v\npayload: %q", err, payload)
			}
			_ = out
		}
	})
}

// TestPolicySeedsDifferential runs the seeds once and reports each outcome.
func TestPolicySeedsDifferential(t *testing.T) {
	pt := mustPolicy(t, testPolicyConfig())
	names := map[diffOutcome]string{diffBothReject: "policy-rejects", diffAgree: "accept+agree", diffApiserverRejects: "policy-accepts/apiserver-rejects(fail-closed)"}
	for i, s := range policySeeds(t) {
		out, err := checkDifferential(pt, pt.Config().Issuer, s)
		if err != nil {
			t.Errorf("seed %d: %v", i, err)
			continue
		}
		t.Logf("seed %2d %-48s %.90q", i, names[out], s)
	}
}

// TestPolicyCorpusReplay replays a fuzz corpus directory ($FUZZ_REPLAY_DIR,
// go-fuzz v1 files holding one []byte) through the differential and counts
// outcomes, so fail-closed (info) cases can be reported.
func TestPolicyCorpusReplay(t *testing.T) {
	dir := os.Getenv("FUZZ_REPLAY_DIR")
	if dir == "" {
		t.Skip("FUZZ_REPLAY_DIR not set")
	}
	pt := mustPolicy(t, testPolicyConfig())
	pd := deployPolicy(t)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	shown := 0
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		payload, ok := parseCorpusBytes(string(b))
		if !ok {
			counts["unparsable-corpus-file"]++
			continue
		}
		for name, p := range map[string]*policy.Policy{"test": pt, "deploy": pd} {
			out, err := checkDifferential(p, p.Config().Issuer, payload)
			switch {
			case err != nil:
				counts[name+":FINDING"]++
				t.Errorf("%s %s: %v", name, e.Name(), err)
			case out == diffAgree:
				counts[name+":accept+agree"]++
			case out == diffApiserverRejects:
				counts[name+":accept/apiserver-rejects"]++
				if shown < 8 {
					shown++
					_, _, aerr := apiserverView(payload)
					t.Logf("fail-closed example (%s): %v :: %.160q", name, aerr, payload)
				}
			default:
				counts[name+":reject"]++
			}
		}
	}
	t.Logf("corpus files: %d; outcomes: %v", len(ents), counts)
}

func parseCorpusBytes(s string) ([]byte, bool) {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "go test fuzz v1") {
		return nil, false
	}
	l := strings.TrimSpace(lines[1])
	if !strings.HasPrefix(l, "[]byte(") || !strings.HasSuffix(l, ")") {
		return nil, false
	}
	v, err := strconv.Unquote(l[len("[]byte(") : len(l)-1])
	if err != nil {
		return nil, false
	}
	return []byte(v), true
}

// FuzzPolicyParse: policy.Parse on arbitrary policy files. Oracle: no panic;
// an accepted policy satisfies every documented invariant.
func FuzzPolicyParse(f *testing.F) {
	if b, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "policy.json")); err == nil {
		f.Add(b)
	}
	f.Add(mustJSON(f, testPolicyConfig()))
	f.Add(mustJSON(f, testutil.PolicyConfig()))
	for _, s := range []string{
		`{"issuer":"x","allowed_audiences":["x"],"max_token_expiration_seconds":3600,"clock_skew_seconds":60,"rate_limit":{"requests_per_second":1,"burst":1},"allow_all":true}`,
		`{"issuer":"x","allowed_audiences":["x"],"max_token_expiration_seconds":3600,"clock_skew_seconds":60,"rate_limit":{"requests_per_second":1,"burst":1}}`,
		`{"issuer":"x","allowed_audiences":["x"],"max_token_expiration_seconds":3600,"clock_skew_seconds":60,"rate_limit":{"requests_per_second":1e308,"burst":1}}`,
		`{"issuer":"x","allowed_audiences":["x"],"max_token_expiration_seconds":3600,"clock_skew_seconds":60,"rate_limit":{"requests_per_second":1,"burst":1},"deny_service_accounts":["a:b"]}`,
		`{"issuer":"x","ISSUER":"y","allowed_audiences":["x"],"max_token_expiration_seconds":3600,"clock_skew_seconds":60,"rate_limit":{"requests_per_second":1,"burst":1}}`,
		`{"issuer":"x","allowed_audiences":["x"],"max_token_expiration_seconds":9223372036854775807,"clock_skew_seconds":300,"rate_limit":{"requests_per_second":1,"burst":1}}`,
		``, `null`, `{}`, `issuer: x`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := policy.Parse(b)
		if err != nil {
			return
		}
		c := p.Config()
		if c.Issuer == "" || len(c.AllowedAudiences) == 0 || c.MaxTokenSeconds < policy.MinTokenSeconds ||
			c.ClockSkewSeconds <= 0 || c.ClockSkewSeconds > 300 || !(c.RateLimit.RequestsPerSecond > 0) || c.RateLimit.Burst <= 0 {
			t.Fatalf("Parse accepted an invalid policy: %+v", c)
		}
		for _, a := range c.AllowedAudiences {
			if a == "" {
				t.Fatal("empty audience accepted")
			}
		}
		// An accepted policy must still evaluate without panicking.
		_, _ = p.Evaluate(mustJSON(t, saClaims("default", "default")), fixedNow)
	})
}

package policy_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/testutil"
)

var now = time.Unix(1_800_000_000, 0)

func mustPolicy(t *testing.T, mut func(*policy.Config)) *policy.Policy {
	t.Helper()
	c := testutil.PolicyConfig()
	c.AllowedAudiences = []string{testutil.Issuer, "vault"}
	c.DenyNamespaces = []string{"kube-denied"}
	c.DenyServiceAccts = []string{"default:blocked"}
	if mut != nil {
		mut(&c)
	}
	p, err := policy.New(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func payload(t *testing.T, mut func(map[string]any)) []byte {
	t.Helper()
	c := testutil.SAClaims("default", "default", now, time.Hour)
	if mut != nil {
		mut(c)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func k8s(ns, name string) map[string]any {
	return map[string]any{"namespace": ns, "serviceaccount": map[string]any{"name": name, "uid": "u"}}
}

func TestPolicyAccepts(t *testing.T) {
	p := mustPolicy(t, nil)
	cases := map[string]func(map[string]any){
		"apiserver-shaped SA token": nil,
		"aud as a single string":    func(c map[string]any) { c["aud"] = testutil.Issuer },
		"two allowed audiences":     func(c map[string]any) { c["aud"] = []string{testutil.Issuer, "vault"} },
		"exactly max lifetime":      func(c map[string]any) { c["exp"] = now.Unix() + 3600 },
		"iat at +skew":              func(c map[string]any) { c["iat"], c["nbf"], c["exp"] = now.Unix()+60, now.Unix()+60, now.Unix()+660 },
		"iat at -skew":              func(c map[string]any) { c["iat"], c["nbf"], c["exp"] = now.Unix()-60, now.Unix()-60, now.Unix()+540 },
		"no nbf":                    func(c map[string]any) { delete(c, "nbf") },
		"SA name with dots (subdomain)": func(c map[string]any) {
			c["sub"] = "system:serviceaccount:team-a:ci.deployer"
			c["kubernetes.io"] = k8s("team-a", "ci.deployer")
		},
		"pod-bound token": func(c map[string]any) {
			c["kubernetes.io"].(map[string]any)["pod"] = map[string]any{"name": "p", "uid": "x"}
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			d, err := p.Evaluate(payload(t, mut), now)
			if err != nil {
				t.Fatalf("rejected valid claims: %v", err)
			}
			if !strings.HasPrefix(d.Subject, "system:serviceaccount:") {
				t.Fatalf("decision %+v", d)
			}
		})
	}
}

func TestPolicyRejects(t *testing.T) {
	p := mustPolicy(t, nil)
	cases := []struct {
		name string
		rule string
		raw  []byte
		mut  func(map[string]any)
	}{
		{name: "wrong iss", rule: "iss", mut: func(c map[string]any) { c["iss"] = "https://evil.example" }},
		{name: "missing iss", rule: "iss", mut: func(c map[string]any) { delete(c, "iss") }},
		{name: "non-string iss", rule: "claims", mut: func(c map[string]any) { c["iss"] = 7 }},
		{name: "disallowed aud", rule: "aud", mut: func(c map[string]any) { c["aud"] = []string{"https://evil.example"} }},
		{name: "one disallowed aud among allowed", rule: "aud", mut: func(c map[string]any) { c["aud"] = []string{testutil.Issuer, "evil"} }},
		{name: "missing aud", rule: "aud", mut: func(c map[string]any) { delete(c, "aud") }},
		{name: "empty aud", rule: "aud", mut: func(c map[string]any) { c["aud"] = []string{} }},
		{name: "numeric aud", rule: "aud", mut: func(c map[string]any) { c["aud"] = 1 }},
		{name: "lifetime above max", rule: "exp", mut: func(c map[string]any) { c["exp"] = now.Unix() + 3601 }},
		{name: "one-year token", rule: "exp", mut: func(c map[string]any) { c["exp"] = now.Unix() + 365*86400 }},
		{name: "exp before iat", rule: "exp", mut: func(c map[string]any) { c["exp"] = now.Unix() - 1 }},
		{name: "missing exp", rule: "claims", mut: func(c map[string]any) { delete(c, "exp") }},
		{name: "fractional exp", rule: "claims", mut: func(c map[string]any) { c["exp"] = 1.5e9 + 0.5 }},
		{name: "string exp", rule: "claims", mut: func(c map[string]any) { c["exp"] = "never" }},
		{name: "missing iat", rule: "claims", mut: func(c map[string]any) { delete(c, "iat") }},
		{name: "iat too far in future", rule: "iat", mut: func(c map[string]any) { c["iat"], c["nbf"], c["exp"] = now.Unix()+61, now.Unix()+61, now.Unix()+661 }},
		{name: "iat too far in past (backdated)", rule: "iat", mut: func(c map[string]any) { c["iat"], c["nbf"], c["exp"] = now.Unix()-61, now.Unix()-61, now.Unix()+539 }},
		{name: "nbf far from iat", rule: "nbf", mut: func(c map[string]any) { c["nbf"] = now.Unix() + 3000 }},
		{name: "node subject", rule: "sub", mut: func(c map[string]any) { c["sub"] = "system:node:worker-1" }},
		{name: "user subject", rule: "sub", mut: func(c map[string]any) { c["sub"] = "admin" }},
		{name: "uppercase namespace", rule: "sub", mut: func(c map[string]any) { c["sub"] = "system:serviceaccount:Default:default" }},
		{name: "namespace with dot", rule: "sub", mut: func(c map[string]any) { c["sub"] = "system:serviceaccount:a.b:default" }},
		{name: "leading hyphen", rule: "sub", mut: func(c map[string]any) { c["sub"] = "system:serviceaccount:-ns:default" }},
		{name: "extra colon", rule: "sub", mut: func(c map[string]any) { c["sub"] = "system:serviceaccount:default:default:x" }},
		{name: "empty name", rule: "sub", mut: func(c map[string]any) { c["sub"] = "system:serviceaccount:default:" }},
		{name: "63+ char namespace", rule: "sub", mut: func(c map[string]any) { c["sub"] = "system:serviceaccount:" + strings.Repeat("a", 64) + ":x" }},
		{name: "missing sub", rule: "sub", mut: func(c map[string]any) { delete(c, "sub") }},
		{name: "sub disagrees with kubernetes.io", rule: "sub", mut: func(c map[string]any) { c["sub"] = "system:serviceaccount:kube-system:admin" }},
		{name: "missing kubernetes.io", rule: "sub", mut: func(c map[string]any) { delete(c, "kubernetes.io") }},
		{name: "denied namespace", rule: "deny", mut: func(c map[string]any) {
			c["sub"] = "system:serviceaccount:kube-denied:x"
			c["kubernetes.io"] = k8s("kube-denied", "x")
		}},
		{name: "denied service account", rule: "deny", mut: func(c map[string]any) {
			c["sub"] = "system:serviceaccount:default:blocked"
			c["kubernetes.io"] = k8s("default", "blocked")
		}},
		{name: "duplicate iss key", rule: "claims", raw: []byte(`{"iss":"https://evil.example","iss":"` + testutil.Issuer + `"}`)},
		{name: "case-variant ISS key", rule: "claims", raw: []byte(`{"iss":"https://evil.example","ISS":"` + testutil.Issuer + `"}`)},
		{name: "case-variant nested namespace", rule: "claims", raw: func() []byte {
			b := payload(t, nil)
			return []byte(strings.Replace(string(b), `"namespace":"default"`, `"namespace":"kube-system","NAMESPACE":"default"`, 1))
		}()},
		{name: "trailing garbage", rule: "claims", raw: append(payload(t, nil), []byte(`x`)...)},
		{name: "second object", rule: "claims", raw: append(payload(t, nil), []byte(`{}`)...)},
		{name: "not an object", rule: "claims", raw: []byte(`["iss"]`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == nil {
				raw = payload(t, tc.mut)
			}
			_, err := p.Evaluate(raw, now)
			var v *policy.Violation
			if !errors.As(err, &v) {
				t.Fatalf("accepted (err=%v)", err)
			}
			if v.Rule != tc.rule {
				t.Fatalf("rejected by rule %q (%v), want rule %q", v.Rule, err, tc.rule)
			}
		})
	}
}

func TestPolicyConfigFailsClosed(t *testing.T) {
	base := testutil.PolicyConfig()
	cases := map[string]func(*policy.Config){
		"no issuer":            func(c *policy.Config) { c.Issuer = "" },
		"no audiences":         func(c *policy.Config) { c.AllowedAudiences = nil },
		"empty audience":       func(c *policy.Config) { c.AllowedAudiences = []string{""} },
		"max below 600":        func(c *policy.Config) { c.MaxTokenSeconds = 599 },
		"zero skew":            func(c *policy.Config) { c.ClockSkewSeconds = 0 },
		"huge skew":            func(c *policy.Config) { c.ClockSkewSeconds = 3600 },
		"no rate limit":        func(c *policy.Config) { c.RateLimit = policy.Rate{} },
		"bad deny_service_acc": func(c *policy.Config) { c.DenyServiceAccts = []string{"nocolon"} },
	}
	for name, mut := range cases {
		c := base
		mut(&c)
		if _, err := policy.New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, raw := range map[string]string{
		"unknown field": `{"issuer":"x","allowed_audiences":["x"],"max_token_expiration_seconds":3600,"clock_skew_seconds":60,"rate_limit":{"requests_per_second":1,"burst":1},"allow_all":true}`,
		"empty":         ``,
		"not json":      `issuer: x`,
	} {
		if _, err := policy.Parse([]byte(raw)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := policy.Load(""); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := policy.Load("/nonexistent/policy.json"); err == nil {
		t.Error("missing file accepted")
	}
}

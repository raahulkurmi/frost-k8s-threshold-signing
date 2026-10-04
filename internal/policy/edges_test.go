package policy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/testutil"
)

// TestPolicyBoundaries (audit C-8): every limit is checked exactly at its
// edge, so an off-by-one change (< vs <=) fails a test.
func TestPolicyBoundaries(t *testing.T) {
	p := mustPolicy(t, nil)
	iat := now.Unix()
	ns63 := strings.Repeat("n", 63)
	name253 := strings.Repeat("a", 61) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) // 253
	withSub := func(ns, name string) func(map[string]any) {
		return func(c map[string]any) {
			c["sub"] = "system:serviceaccount:" + ns + ":" + name
			c["kubernetes.io"] = k8s(ns, name)
		}
	}
	cases := []struct {
		name   string
		mut    func(map[string]any)
		accept bool
	}{
		{"exp == iat", func(c map[string]any) { c["exp"] = iat }, false},
		{"exp == iat+1", func(c map[string]any) { c["exp"] = iat + 1 }, true},
		{"nbf == iat+skew", func(c map[string]any) { c["nbf"] = iat + 60 }, true},
		{"nbf == iat+skew+1", func(c map[string]any) { c["nbf"] = iat + 61 }, false},
		{"nbf == iat-skew", func(c map[string]any) { c["nbf"] = iat - 60 }, true},
		{"nbf == iat-skew-1", func(c map[string]any) { c["nbf"] = iat - 61 }, false},
		{"namespace of 63 characters", withSub(ns63, "default"), true},
		{"namespace of 64 characters", withSub(ns63+"n", "default"), false},
		{"SA name of 253 characters", withSub("default", name253), true},
		{"SA name of 254 characters", withSub("default", name253+"e"), false},
	}
	if len(name253) != 253 {
		t.Fatalf("fixture name has %d characters", len(name253))
	}
	for _, tc := range cases {
		_, err := p.Evaluate(payload(t, tc.mut), now)
		if tc.accept && err != nil {
			t.Errorf("%s: rejected: %v", tc.name, err)
		}
		if !tc.accept && err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

// TestPolicyPodUID (audit C-8): the pod uid of a pod-bound token is extracted
// strictly (it feeds the stable priority identity, N77).
func TestPolicyPodUID(t *testing.T) {
	p := mustPolicy(t, nil)
	set := func(pod any) func(map[string]any) {
		return func(c map[string]any) {
			k := k8s("default", "default")
			k["pod"] = pod
			c["kubernetes.io"] = k
		}
	}
	d, err := p.Evaluate(payload(t, set(map[string]any{"name": "p", "uid": "pod-uid-1"})), now)
	if err != nil || d.PodUID != "pod-uid-1" {
		t.Fatalf("pod-bound token: uid %q, err %v; want pod-uid-1", d.PodUID, err)
	}
	if d, err := p.Evaluate(payload(t, set(map[string]any{"name": "p"})), now); err != nil || d.PodUID != "" {
		t.Fatalf("pod without uid: uid %q, err %v", d.PodUID, err)
	}
	if d, err := p.Evaluate(payload(t, nil), now); err != nil || d.PodUID != "" {
		t.Fatalf("token without pod: uid %q, err %v", d.PodUID, err)
	}
	for name, pod := range map[string]any{"pod not an object": "p", "pod uid not a string": map[string]any{"uid": 7}} {
		if _, err := p.Evaluate(payload(t, set(pod)), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestPolicyRejectsQuotedNumericDates (audit D-1): exp, iat and nbf must be
// JSON numbers. encoding/json decodes a quoted number literal into
// json.Number, but kube-apiserver's go-jose v2 rejects it, so accepting it
// would be a (fail-closed) parser differential.
func TestPolicyRejectsQuotedNumericDates(t *testing.T) {
	p := mustPolicy(t, nil)
	for _, key := range []string{"exp", "iat", "nbf"} {
		_, err := p.Evaluate(payload(t, func(c map[string]any) {
			c[key] = fmt.Sprint(c[key]) // e.g. "1800000000": a JSON string holding a number
		}), now)
		if err == nil || !strings.Contains(err.Error(), "not a JSON number") {
			t.Errorf("%s as a JSON string: err = %v, want refusal", key, err)
		}
	}
}

// TestPolicyConfigBoundaries (audit C-8): configuration limits at their edges.
func TestPolicyConfigBoundaries(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*policy.Config)
		ok   bool
	}{
		{"max lifetime 600", func(c *policy.Config) { c.MaxTokenSeconds = 600 }, true},
		{"max lifetime 599", func(c *policy.Config) { c.MaxTokenSeconds = 599 }, false},
		{"skew 300", func(c *policy.Config) { c.ClockSkewSeconds = 300 }, true},
		{"skew 301", func(c *policy.Config) { c.ClockSkewSeconds = 301 }, false},
		{"skew 0", func(c *policy.Config) { c.ClockSkewSeconds = 0 }, false},
		{"rate 0", func(c *policy.Config) { c.RateLimit.RequestsPerSecond = 0 }, false},
		{"burst 0", func(c *policy.Config) { c.RateLimit.Burst = 0 }, false},
	}
	for _, tc := range cases {
		c := testutil.PolicyConfig()
		tc.mut(&c)
		_, err := policy.New(c)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// TestLoad (audit C-8): Load fails closed on an empty path and a missing
// file, and loads a valid file.
func TestLoad(t *testing.T) {
	if _, err := policy.Load(""); err == nil || !strings.Contains(err.Error(), "path is empty") {
		t.Fatalf("empty path: %v", err)
	}
	if _, err := policy.Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file loaded")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"issuer":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(bad); err == nil {
		t.Fatal("invalid policy loaded")
	}
	p, err := policy.Load(testutil.PolicyFile(t, t.TempDir(), testutil.PolicyConfig()))
	if err != nil || p == nil {
		t.Fatalf("valid file: %v", err)
	}
}

// TestPolicyLifetimeReason (audit C-8): the refusal reports the actual lifetime,
// which the signer's audit log records.
func TestPolicyLifetimeReason(t *testing.T) {
	p := mustPolicy(t, nil)
	_, err := p.Evaluate(payload(t, func(c map[string]any) { c["exp"] = now.Unix() + 3601 }), now)
	if err == nil || !strings.Contains(err.Error(), "lifetime 3601s exceeds max 3600s") {
		t.Fatalf("err = %v", err)
	}
}

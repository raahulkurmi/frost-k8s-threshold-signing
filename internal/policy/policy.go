// Package policy is each signer's independent claims policy. A signer
// applies it to the JWT payload itself before producing a share, so a
// compromised coordinator cannot obtain shares for arbitrary claims (D11).
//
// It limits an attacker in control of the coordinator/apiserver to tokens that
// are policy-compliant; it does not stop them obtaining those (online oracle).
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config is the policy file (POLICY_FILE). All fields are required unless
// marked optional; unknown fields are rejected.
type Config struct {
	Issuer           string   `json:"issuer"`
	AllowedAudiences []string `json:"allowed_audiences"`
	MaxTokenSeconds  int64    `json:"max_token_expiration_seconds"`
	ClockSkewSeconds int64    `json:"clock_skew_seconds"`
	DenyNamespaces   []string `json:"deny_namespaces,omitempty"`       // optional
	DenyServiceAccts []string `json:"deny_service_accounts,omitempty"` // optional, "namespace:name"
	RateLimit        Rate     `json:"rate_limit"`
}

// Rate is a per-signer token bucket.
type Rate struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
}

// Policy is a validated Config.
type Policy struct {
	cfg       Config
	audiences map[string]bool
	denyNS    map[string]bool
	denySA    map[string]bool
}

// Violation is a policy rejection with the rule that failed.
type Violation struct {
	Rule   string
	Detail string
}

func (v *Violation) Error() string { return v.Rule + ": " + v.Detail }

func violation(rule, format string, a ...any) error {
	return &Violation{Rule: rule, Detail: fmt.Sprintf(format, a...)}
}

// Decision is the result of an accepted evaluation.
type Decision struct {
	Subject        string
	Namespace      string
	ServiceAccount string
	Audiences      []string
}

// MinTokenSeconds is kube-apiserver's lower bound for max_token_expiration_seconds
// (externaljwt v1 api.proto MetadataResponse).
const MinTokenSeconds = 600

// Load reads and validates a policy file. Any problem is an error.
func Load(path string) (*Policy, error) {
	if path == "" {
		return nil, errors.New("policy: path is empty")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	return p, nil
}

// Parse decodes and validates policy JSON.
func Parse(b []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	return New(c)
}

// New validates c.
func New(c Config) (*Policy, error) {
	if c.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if len(c.AllowedAudiences) == 0 {
		return nil, errors.New("allowed_audiences must not be empty")
	}
	if c.MaxTokenSeconds < MinTokenSeconds {
		return nil, fmt.Errorf("max_token_expiration_seconds %d < %d", c.MaxTokenSeconds, MinTokenSeconds)
	}
	if c.ClockSkewSeconds <= 0 || c.ClockSkewSeconds > 300 {
		return nil, fmt.Errorf("clock_skew_seconds %d outside (0, 300]", c.ClockSkewSeconds)
	}
	if c.RateLimit.RequestsPerSecond <= 0 || c.RateLimit.Burst <= 0 {
		return nil, errors.New("rate_limit.requests_per_second and rate_limit.burst must be > 0")
	}
	p := &Policy{cfg: c, audiences: set(c.AllowedAudiences), denyNS: set(c.DenyNamespaces), denySA: set(c.DenyServiceAccts)}
	for _, a := range c.AllowedAudiences {
		if a == "" {
			return nil, errors.New("allowed_audiences contains an empty string")
		}
	}
	for _, sa := range c.DenyServiceAccts {
		ns, name, ok := strings.Cut(sa, ":")
		if !ok || !isDNSLabel(ns) || !isDNSSubdomain(name) {
			return nil, fmt.Errorf("deny_service_accounts entry %q is not namespace:name", sa)
		}
	}
	return p, nil
}

func set(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Config returns a copy of the validated configuration.
func (p *Policy) Config() Config { return p.cfg }

// MaxTokenSeconds is the longest token lifetime the signer will sign; the
// coordinator reports it as Metadata.max_token_expiration_seconds.
func (p *Policy) MaxTokenSeconds() int64 { return p.cfg.MaxTokenSeconds }

// strictObject decodes a JSON object into exact-key raw values. It rejects
// duplicate keys and keys that differ only in case from another key.
// encoding/json struct decoding is case-insensitive and last-wins, while
// go-jose v2 (the apiserver's verifier) uses a case-sensitive fork; without
// this check {"iss":"evil","ISS":"good"} would pass the policy as "good" and
// verify as "evil".
func strictObject(b []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	folded := map[string]string{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := kt.(string)
		if prev, dup := folded[strings.ToLower(k)]; dup {
			return nil, fmt.Errorf("duplicate or case-variant key %q (already have %q)", k, prev)
		}
		folded[strings.ToLower(k)] = k
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after object")
	}
	return out, nil
}

func str(obj map[string]json.RawMessage, key string) (*string, error) {
	raw, ok := obj[key]
	if !ok {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, violation("claims", "%s is not a string", key)
	}
	return &s, nil
}

func num(obj map[string]json.RawMessage, key string) (*json.Number, error) {
	raw, ok := obj[key]
	if !ok {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if err := dec.Decode(&n); err != nil {
		return nil, violation("claims", "%s is not a number", key)
	}
	return &n, nil
}

func intClaim(name string, n *json.Number) (int64, error) {
	if n == nil {
		return 0, violation("claims", "%s is missing", name)
	}
	v, err := n.Int64()
	if err != nil {
		return 0, violation("claims", "%s is not an integer NumericDate", name)
	}
	return v, nil
}

// Evaluate applies every rule to a decoded JWT payload. now is the signer's
// clock.
func (p *Policy) Evaluate(payload []byte, now time.Time) (*Decision, error) {
	obj, err := strictObject(payload)
	if err != nil {
		return nil, violation("claims", "payload: %v", err)
	}
	iss, err := str(obj, "iss")
	if err != nil {
		return nil, err
	}
	sub, err := str(obj, "sub")
	if err != nil {
		return nil, err
	}
	expN, err := num(obj, "exp")
	if err != nil {
		return nil, err
	}
	iatN, err := num(obj, "iat")
	if err != nil {
		return nil, err
	}
	nbfN, err := num(obj, "nbf")
	if err != nil {
		return nil, err
	}

	// iss
	if iss == nil || *iss != p.cfg.Issuer {
		return nil, violation("iss", "issuer %s is not %q", strOrMissing(iss), p.cfg.Issuer)
	}

	// aud: string or array of strings, every entry allowlisted.
	auds, err := parseAud(obj["aud"])
	if err != nil {
		return nil, err
	}
	for _, a := range auds {
		if !p.audiences[a] {
			return nil, violation("aud", "audience %q is not allowed", a)
		}
	}

	// exp / iat / nbf
	exp, err := intClaim("exp", expN)
	if err != nil {
		return nil, err
	}
	iat, err := intClaim("iat", iatN)
	if err != nil {
		return nil, err
	}
	if exp <= iat {
		return nil, violation("exp", "exp %d is not after iat %d", exp, iat)
	}
	if exp-iat > p.cfg.MaxTokenSeconds {
		return nil, violation("exp", "lifetime %ds exceeds max %ds", exp-iat, p.cfg.MaxTokenSeconds)
	}
	skew := p.cfg.ClockSkewSeconds
	if d := iat - now.Unix(); d > skew || d < -skew {
		return nil, violation("iat", "iat %d is %ds from signer clock (max skew %ds)", iat, d, skew)
	}
	if nbfN != nil {
		nbf, err := intClaim("nbf", nbfN)
		if err != nil {
			return nil, err
		}
		if nbf > iat+skew || nbf < iat-skew {
			return nil, violation("nbf", "nbf %d not within skew of iat %d", nbf, iat)
		}
	}

	// sub: system:serviceaccount:<ns>:<name>, the only subject kube-apiserver
	// issues (pkg/serviceaccount/claims.go -> MakeUsername).
	if sub == nil {
		return nil, violation("sub", "sub is missing")
	}
	ns, name, err := ParseServiceAccountSubject(*sub)
	if err != nil {
		return nil, err
	}
	if err := checkK8sClaims(obj["kubernetes.io"], ns, name); err != nil {
		return nil, err
	}
	if p.denyNS[ns] {
		return nil, violation("deny", "namespace %q is denied", ns)
	}
	if p.denySA[ns+":"+name] {
		return nil, violation("deny", "service account %s:%s is denied", ns, name)
	}
	return &Decision{Subject: *sub, Namespace: ns, ServiceAccount: name, Audiences: auds}, nil
}

// checkK8sClaims requires kubernetes.io.namespace and .serviceaccount.name to
// agree with sub, using the same strict decoding.
func checkK8sClaims(raw json.RawMessage, ns, name string) error {
	if raw == nil {
		return violation("sub", "kubernetes.io claims are missing")
	}
	k8s, err := strictObject(raw)
	if err != nil {
		return violation("claims", "kubernetes.io: %v", err)
	}
	gotNS, err := str(k8s, "namespace")
	if err != nil {
		return err
	}
	saRaw, ok := k8s["serviceaccount"]
	if !ok {
		return violation("sub", "kubernetes.io.serviceaccount is missing")
	}
	sa, err := strictObject(saRaw)
	if err != nil {
		return violation("claims", "kubernetes.io.serviceaccount: %v", err)
	}
	gotName, err := str(sa, "name")
	if err != nil {
		return err
	}
	if gotNS == nil || gotName == nil || *gotNS != ns || *gotName != name {
		return violation("sub", "sub %s:%s disagrees with kubernetes.io claims (%s/%s)", ns, name, strOrMissing(gotNS), strOrMissing(gotName))
	}
	return nil
}

func strOrMissing(s *string) string {
	if s == nil {
		return "(missing)"
	}
	return fmt.Sprintf("%q", *s)
}

func parseAud(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, violation("aud", "aud is missing")
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, violation("aud", "aud must be a string or array of strings")
	}
	if len(many) == 0 {
		return nil, violation("aud", "aud is empty")
	}
	return many, nil
}

const saPrefix = "system:serviceaccount:"

var (
	dnsLabel     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// isDNSLabel mirrors apimachinery NameIsDNSLabel (namespace names).
func isDNSLabel(s string) bool { return len(s) <= 63 && dnsLabel.MatchString(s) }

// isDNSSubdomain mirrors apimachinery NameIsDNSSubdomain (service account names).
func isDNSSubdomain(s string) bool { return len(s) <= 253 && dnsSubdomain.MatchString(s) }

// ParseServiceAccountSubject splits system:serviceaccount:<ns>:<name> and
// validates both parts with the Kubernetes name rules (NOTES.md N9).
func ParseServiceAccountSubject(sub string) (ns, name string, err error) {
	rest, ok := strings.CutPrefix(sub, saPrefix)
	if !ok {
		return "", "", violation("sub", "sub %q is not a service account subject", sub)
	}
	ns, name, ok = strings.Cut(rest, ":")
	if !ok || !isDNSLabel(ns) || !isDNSSubdomain(name) {
		return "", "", violation("sub", "sub %q is malformed", sub)
	}
	return ns, name, nil
}

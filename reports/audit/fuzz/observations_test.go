//go:build auditfuzz

package fuzz

import (
	"crypto"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/jwtfmt"
)

// TestObservations pins down behaviours found while building the targets, so
// the report can cite a deterministic reproduction.
func TestObservations(t *testing.T) {
	// O1: a numeric STRING passes the policy's NumericDate rule.
	p := mustPolicy(t, testPolicyConfig())
	good := string(mustJSON(t, saClaims("default", "default")))
	for _, k := range []string{"iat", "exp", "nbf"} {
		var old, nw string
		switch k {
		case "iat":
			old, nw = `"iat":1800000000`, `"iat":"1800000000"`
		case "exp":
			old, nw = `"exp":1800003600`, `"exp":"1800003600"`
		case "nbf":
			old, nw = `"nbf":1800000000`, `"nbf":"1800000000"`
		}
		pl := []byte(strings.Replace(good, old, nw, 1))
		_, perr := p.Evaluate(pl, fixedNow)
		_, _, aerr := apiserverView(pl)
		t.Logf("O1 string %s: policy err=%v; go-jose v2 err=%v", k, perr, aerr)
	}

	// O2: Shoup share malleability: xi' = n - xi passes tcrsa Verify and Join.
	e := getShareEnv(t)
	meta := e.fx.Meta
	g := *e.genuine[3]
	g.Xi = new(big.Int).Sub(meta.PublicKey.N, new(big.Int).SetBytes(g.Xi)).Bytes()
	verr := g.Verify(e.doc, meta.Tcrsa)
	sig, jerr := tcrsa.SigShareList{e.genuine[1], e.genuine[2], &g}.Join(e.doc, meta.Tcrsa)
	var fverr error = jerr
	if jerr == nil {
		fverr = rsa.VerifyPKCS1v15(meta.PublicKey, crypto.SHA256, e.digest[:], sig)
	}
	t.Logf("O2 negated share 3: Verify err=%v; Join+VerifyPKCS1v15 err=%v", verr, fverr)

	// O3: ParseHeader accepts the JSON literal null (zero Header); CheckHeader
	// still rejects it.
	h, err := jwtfmt.ParseHeader(b64([]byte("null")))
	t.Logf("O3 ParseHeader(null) = %+v, err=%v; CheckHeader err=%v", h, err, jwtfmt.CheckHeader(b64([]byte("null")), seedKID))
}

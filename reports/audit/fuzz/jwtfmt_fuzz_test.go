//go:build auditfuzz

package fuzz

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"frost-k8s-threshold-signing/internal/jwtfmt"
	"frost-k8s-threshold-signing/internal/testutil"
)

const seedKID = "g1TN11q0AbCdEfGhIjKlMn" // 22-char base64url, shape of ComputeKID

// FuzzJWTHeader: ParseHeader + CheckHeader. Oracle: no panic; CheckHeader
// accepts only seg == EncodedHeader(kid); ParseHeader's result re-encodes.
func FuzzJWTHeader(f *testing.F) {
	b64 := testutil.B64
	canon, _ := jwtfmt.EncodedHeader(seedKID)
	seeds := []string{
		canon,
		testutil.Header(seedKID),
		b64([]byte(`{"alg":"none","typ":"JWT","kid":"` + seedKID + `"}`)),
		b64([]byte(`{"alg":"ES256","typ":"JWT","kid":"` + seedKID + `"}`)),
		b64([]byte(`{"typ":"JWT","alg":"RS256","kid":"` + seedKID + `"}`)),
		b64([]byte(`{"alg":"RS256","typ":"JWT","kid":"` + seedKID + `","x5u":"http://e"}`)),
		b64([]byte(`{"alg":"RS256","alg":"none","typ":"JWT","kid":"` + seedKID + `"}`)),
		b64([]byte(`{"ALG":"RS256","typ":"JWT","kid":"` + seedKID + `"}`)),
		b64([]byte(`{"alg":"RS256","typ":"JWT","kid":"` + seedKID + `"} `)),
		b64([]byte(`{"alg":"RS256","typ":"JWT","kid":"` + seedKID + `"}{}`)),
		b64([]byte(`{"alg":"RS256","typ":"JWT","kid":"g` + seedKID[1:] + `"}`)),
		b64([]byte("\xef\xbb\xbf" + `{"alg":"RS256","typ":"JWT","kid":"` + seedKID + `"}`)),
		b64([]byte(`{"alg":"RS256","typ":"JWT","kid":null}`)),
		canon + "=",
		canon[:len(canon)-1] + "f",
		strings.ReplaceAll(base64.URLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"`+seedKID+`"}`)), "=", ""),
		"",
		"e30",
	}
	for _, s := range seeds {
		f.Add(s, seedKID)
	}
	f.Add(canon, "")
	f.Add(testutil.Header("a\"b"), "a\"b")
	f.Add(testutil.Header("K"), "K")
	f.Add(testutil.B64([]byte("null")), seedKID)
	f.Fuzz(func(t *testing.T, seg, kid string) {
		h, perr := jwtfmt.ParseHeader(seg)
		err := jwtfmt.CheckHeader(seg, kid)
		want, werr := jwtfmt.EncodedHeader(kid)
		if err == nil {
			if werr != nil {
				t.Fatalf("CheckHeader accepted %q for kid %q that EncodedHeader rejects (%v)", seg, kid, werr)
			}
			if seg != want {
				t.Fatalf("CheckHeader accepted non-canonical header %q (canonical %q)", seg, want)
			}
			if perr != nil || h.Alg != jwtfmt.Alg || h.Typ != jwtfmt.Typ || h.Kid != kid {
				t.Fatalf("accepted header parses as %+v / %v", h, perr)
			}
		} else if werr == nil && seg == want {
			t.Fatalf("CheckHeader rejected the canonical header for kid %q: %v", kid, err)
		}
		if perr == nil {
			// Whatever ParseHeader accepts must decode as strict base64url JSON
			// that a plain decode agrees with.
			if _, derr := jwtfmt.DecodeSegment(seg); derr != nil {
				t.Fatalf("ParseHeader accepted %q but DecodeSegment fails: %v", seg, derr)
			}
		}
	})
}

// FuzzSigningInput: SplitSigningInput, CheckSegment, DecodeSegment, plus the
// coordinator's claims gate (coordinator.Sign: CheckSegment(claims) and
// len(header+"."+claims) <= MaxSigningInput). Oracles: no panic; coordinator
// acceptance implies signer split acceptance with identical segments;
// CheckSegment acceptance implies go-jose v2's lenient base64url decoder
// yields the same bytes.
func FuzzSigningInput(f *testing.F) {
	canon, _ := jwtfmt.EncodedHeader(seedKID)
	pl := testutil.B64(mustJSON(f, saClaims("default", "default")))
	for _, s := range []string{
		canon + "." + pl,
		canon + "." + pl + ".sig",
		canon + ".." + pl,
		"." + pl,
		canon + ".",
		canon + "." + pl + "=",
		canon + "." + pl + " ",
		canon + "." + strings.ReplaceAll(pl, "-", "+"),
		canon + ".YQ",
		canon + ".YR",
		canon + ".Y",
		canon + ".YWJj",
		strings.Repeat("A", jwtfmt.MaxSigningInput) + ".A",
		canon + "." + strings.Repeat("A", jwtfmt.MaxSigningInput-len(canon)-1),
		canon + "." + strings.Repeat("A", jwtfmt.MaxSigningInput-len(canon)-2),
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		h, p, err := jwtfmt.SplitSigningInput(s)
		if err == nil {
			if h+"."+p != s || len(s) > jwtfmt.MaxSigningInput {
				t.Fatalf("split %q -> %q %q", s, h, p)
			}
			if jwtfmt.CheckSegment(h) != nil || jwtfmt.CheckSegment(p) != nil {
				t.Fatal("split accepted a segment CheckSegment rejects")
			}
		}
		// The coordinator treats the whole input as the claims segment.
		claims := s
		if jwtfmt.CheckSegment(claims) == nil && len(canon)+1+len(claims) <= jwtfmt.MaxSigningInput {
			input := canon + "." + claims
			h2, p2, err := jwtfmt.SplitSigningInput(input)
			if err != nil || h2 != canon || p2 != claims {
				t.Fatalf("coordinator accepts claims %q but signer split gives %q %q %v", claims, h2, p2, err)
			}
		}
		if err := jwtfmt.CheckSegment(s); err == nil {
			strict, derr := jwtfmt.DecodeSegment(s)
			if derr != nil {
				t.Fatalf("CheckSegment ok but DecodeSegment: %v", derr)
			}
			// go-jose v2 base64URLDecode: TrimRight "=" then RawURLEncoding (lenient).
			lenient, lerr := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
			if lerr != nil || !bytes.Equal(strict, lenient) {
				t.Fatalf("strict/lenient base64url disagree on %q", s)
			}
			if base64.RawURLEncoding.EncodeToString(strict) != s {
				t.Fatalf("CheckSegment accepted non-canonical base64url %q", s)
			}
		}
	})
}

//go:build auditfuzz

package fuzz

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/jwtfmt"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/tlsconf"
	"frost-k8s-threshold-signing/internal/wire"
)

// shareEnv is one fixed signing input with all five genuine shares over it.
type shareEnv struct {
	fx      *keyFx
	claims  string // base64url payload
	input   string
	doc     []byte
	digest  [32]byte
	genuine map[int]*tcrsa.SigShare
}

var (
	shareEnvOnce sync.Once
	shareEnvVal  *shareEnv
)

func getShareEnv(t testing.TB) *shareEnv {
	fx := loadKey(t)
	shareEnvOnce.Do(func() {
		hdr, _ := jwtfmt.EncodedHeader(fx.Meta.KID)
		e := &shareEnv{fx: fx, claims: b64(mustJSON(t, saClaims("default", "default"))), genuine: map[int]*tcrsa.SigShare{}}
		e.input = hdr + "." + e.claims
		e.digest = sha256.Sum256([]byte(e.input))
		e.doc = paddedDigest(t, fx.Meta, e.input)
		for i, ks := range fx.Shares {
			ss, err := ks.Sign(e.doc, crypto.SHA256, fx.Meta.Tcrsa)
			if err != nil {
				t.Fatal(err)
			}
			e.genuine[i+1] = ss
		}
		shareEnvVal = e
	})
	return shareEnvVal
}

func shareSeeds(t testing.TB, e *shareEnv, reqID string) [][]byte {
	n := e.fx.Meta.PublicKey.N
	g := e.genuine[3]
	enc := base64.StdEncoding.EncodeToString
	resp := func(id int, s wire.SigShare) []byte {
		return mustJSON(t, wire.SignShareResponse{SignerID: id, Share: s, RequestID: reqID})
	}
	w := wire.FromTcrsa(g)
	mod := func(f func(*wire.SigShare)) []byte { c := w; f(&c); return resp(3, c) }
	neg := new(big.Int).Sub(n, new(big.Int).SetBytes(g.Xi)).Bytes()
	flip := append([]byte(nil), g.Xi...)
	flip[len(flip)/2] ^= 0x5a
	return [][]byte{
		resp(3, w),
		resp(3, wire.FromTcrsa(e.genuine[1])),
		mod(func(s *wire.SigShare) { s.Xi = enc(neg) }),
		mod(func(s *wire.SigShare) { s.Xi = enc(flip) }),
		mod(func(s *wire.SigShare) { s.Xi = enc([]byte{0}) }),
		mod(func(s *wire.SigShare) { s.Xi = enc([]byte{1}) }),
		mod(func(s *wire.SigShare) { s.Xi = enc(n.Bytes()) }),
		mod(func(s *wire.SigShare) { s.Xi = enc(new(big.Int).Sub(n, big.NewInt(1)).Bytes()) }),
		mod(func(s *wire.SigShare) { s.Xi = enc(append([]byte{0, 0, 0}, g.Xi...)) }),
		mod(func(s *wire.SigShare) { s.C = enc([]byte{0}) }),
		mod(func(s *wire.SigShare) { s.C = enc(new(big.Int).Sub(n, big.NewInt(1)).Bytes()) }),
		mod(func(s *wire.SigShare) { s.Z = enc(bytes.Repeat([]byte{0xff}, 3*len(n.Bytes()))) }),
		mod(func(s *wire.SigShare) { s.Z = enc(bytes.Repeat([]byte{0xff}, 3*len(n.Bytes())+1)) }),
		mod(func(s *wire.SigShare) { s.Z = "" }),
		mod(func(s *wire.SigShare) { s.Xi = "!!" }),
		mod(func(s *wire.SigShare) { s.Xi = strings.TrimRight(s.Xi, "=") }),
		resp(4, w),
		resp(0, w),
		[]byte(strings.Replace(string(resp(3, w)), `"signer_id":3`, `"signer_id":3,"id":1`, 1)),
		[]byte(strings.Replace(string(resp(3, w)), `"signer_id":3`, `"Signer_ID":3`, 1)),
		append(resp(3, w), []byte(`{"signer_id":3}`)...),
		[]byte(`{"error":"overloaded","reason":"x"}`),
		[]byte(`null`),
		[]byte(`{"signer_id":3,"share":null,"request_id":"` + reqID + `"}`),
	}
}

// FuzzShareResponse is the decode-level coordinator path: strict decode into
// wire.SignShareResponse, SigShare.ToTcrsa(id, 5, N), tcrsa Verify, a Join
// with two genuine shares, rsa.VerifyPKCS1v15. Oracles: no panic (tcrsa
// panics for id 0 or > L), per-exec time <= 1 s, and a verifying share or
// final signature only for xi == +/- the genuine share.
func FuzzShareResponse(f *testing.F) {
	e := getShareEnv(f)
	for _, s := range shareSeeds(f, e, "req-1") {
		f.Add(s, 3)
	}
	w := mustJSON(f, wire.SignShareResponse{SignerID: 3, Share: wire.FromTcrsa(e.genuine[3]), RequestID: "req-1"})
	for _, id := range []int{0, -1, 1, 5, 6, 65536 + 3, 1 << 40} {
		f.Add(w, id)
	}
	meta := e.fx.Meta
	n := meta.PublicKey.N
	f.Fuzz(func(t *testing.T, body []byte, id int) {
		start := time.Now()
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		var sr wire.SignShareResponse
		if err := dec.Decode(&sr); err != nil {
			return
		}
		ss, err := sr.Share.ToTcrsa(id, meta.Parties, n)
		if id < 1 || id > meta.Parties {
			if err == nil {
				t.Fatalf("ToTcrsa accepted id %d", id)
			}
			return
		}
		if err != nil {
			return
		}
		if int(ss.Id) != id {
			t.Fatalf("ToTcrsa id %d -> %d", id, ss.Id)
		}
		gen := new(big.Int).SetBytes(e.genuine[id].Xi)
		x := new(big.Int).SetBytes(ss.Xi)
		if verr := ss.Verify(e.doc, meta.Tcrsa); verr == nil && !sameOrNegated(x, gen, n) {
			t.Fatalf("tcrsa Verify accepted a non-genuine share for id %d", id)
		}
		list := tcrsa.SigShareList{}
		for j := 1; j <= meta.Parties && len(list) < meta.Threshold-1; j++ {
			if j != id {
				list = append(list, e.genuine[j])
			}
		}
		list = append(list, ss)
		sig, jerr := list.Join(e.doc, meta.Tcrsa)
		if jerr == nil {
			if rsa.VerifyPKCS1v15(meta.PublicKey, crypto.SHA256, e.digest[:], sig) == nil && !sameOrNegated(x, gen, n) {
				t.Fatalf("final signature verifies from a non-genuine share (id %d)", id)
			}
		}
		if el := time.Since(start); el > time.Second {
			t.Fatalf("share processing took %v (z %d bytes, c %d bytes)", el, len(ss.Z), len(ss.C))
		}
	})
}

// fetchEnv: three mTLS fake signers on loopback. 1 and 2 return genuine
// precomputed shares; 3 returns the current fuzzed body (with REQID replaced
// by the coordinator's request_id) and status.
type fetchEnv struct {
	*shareEnv
	eps    []coordinator.Endpoint
	body   atomic.Pointer[[]byte]
	status atomic.Int64
}

var (
	fetchOnce sync.Once
	fetchVal  *fetchEnv
)

func getFetchEnv(t testing.TB) *fetchEnv {
	e := getShareEnv(t)
	fetchOnce.Do(func() {
		fe := &fetchEnv{shareEnv: e}
		pki := testutil.NewPKI(t)
		cc := pki.Coordinator(t)
		for id := 1; id <= 3; id++ {
			sc := pki.Signer(t, id)
			tc, err := tlsconf.SignerServer(sc.Cert, sc.Key, pki.CA, id)
			if err != nil {
				t.Fatal(err)
			}
			id := id
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req wire.SignShareRequest
				_ = json.NewDecoder(io.LimitReader(r.Body, wire.MaxRequestBytes)).Decode(&req)
				w.Header().Set("Content-Type", "application/json")
				if id != 3 {
					if req.SigningInput != e.input {
						http.Error(w, "unexpected input", http.StatusBadRequest)
						return
					}
					_ = json.NewEncoder(w).Encode(wire.SignShareResponse{SignerID: id, Share: wire.FromTcrsa(e.genuine[id]), RequestID: req.RequestID})
					return
				}
				b := *fe.body.Load()
				b = bytes.ReplaceAll(b, []byte("REQID"), []byte(req.RequestID))
				w.WriteHeader(int(fe.status.Load()))
				_, _ = w.Write(b)
			})
			ts := httptest.NewUnstartedServer(h)
			ts.TLS = tc
			ts.StartTLS()
			t.Cleanup(ts.Close)
			ctc, err := tlsconf.CoordinatorClient(cc.Cert, cc.Key, pki.CA, id, 1)
			if err != nil {
				t.Fatal(err)
			}
			fe.eps = append(fe.eps, coordinator.Endpoint{ID: id, URL: ts.URL,
				Client: &http.Client{Transport: &http.Transport{TLSClientConfig: ctc, ForceAttemptHTTP2: true}}})
		}
		fetchVal = fe
	})
	return fetchVal
}

var fetchStatuses = []int{200, 200, 200, 400, 403, 429, 500, 503}

// FuzzCoordinatorFetch runs the real coordinator.Sign -> fetch -> verify/join
// path against an mTLS signer endpoint that returns fuzzed bytes. Oracles: no
// panic; Sign returns within deadline + 2 s; a successful Sign carries an RS256
// signature that verifies and was produced with the genuine (+/-) share 3.
func FuzzCoordinatorFetch(f *testing.F) {
	fe := getFetchEnv(f)
	for _, s := range shareSeeds(f, fe.shareEnv, "REQID") {
		f.Add(s, uint8(0))
	}
	f.Add(shareSeeds(f, fe.shareEnv, "REQID")[0], uint8(7))
	f.Add(bytes.Repeat([]byte("a"), wire.MaxResponseBytes+1), uint8(0))
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	const deadline = 3 * time.Second
	n := fe.fx.Meta.PublicKey.N
	f.Fuzz(func(t *testing.T, body []byte, st uint8) {
		b := append([]byte(nil), body...)
		fe.body.Store(&b)
		fe.status.Store(int64(fetchStatuses[int(st)%len(fetchStatuses)]))
		for _, strat := range []coordinator.Strategy{coordinator.Optimistic, coordinator.Strict} {
			co, err := coordinator.New(coordinator.Config{Meta: fe.fx.Meta, Endpoints: fe.eps, Deadline: deadline, Strategy: strat, Logger: lg})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			res, err := co.Sign(context.Background(), fe.claims)
			if el := time.Since(start); el > deadline+2*time.Second {
				t.Fatalf("%s: Sign took %v", strat, el)
			}
			if err != nil {
				continue
			}
			sig, derr := base64.RawURLEncoding.DecodeString(res.Signature)
			if derr != nil || rsa.VerifyPKCS1v15(fe.fx.Meta.PublicKey, crypto.SHA256, fe.digest[:], sig) != nil {
				t.Fatalf("%s: Sign returned a signature that does not verify", strat)
			}
			// The only way to reach t=3 is share 3 from the fuzzed endpoint.
			got := bytes.ReplaceAll(b, []byte("REQID"), []byte(res.RequestID))
			var sr wire.SignShareResponse
			if err := json.NewDecoder(bytes.NewReader(got)).Decode(&sr); err != nil {
				t.Fatalf("%s: Sign succeeded but the fuzzed body does not decode: %v", strat, err)
			}
			xi, _ := base64.StdEncoding.DecodeString(sr.Share.Xi)
			if !sameOrNegated(new(big.Int).SetBytes(xi), new(big.Int).SetBytes(fe.genuine[3].Xi), n) {
				t.Fatalf("%s: verifying token from a non-genuine share 3", strat)
			}
		}
	})
}

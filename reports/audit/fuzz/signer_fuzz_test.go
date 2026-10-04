//go:build auditfuzz

package fuzz

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/audit"
	"frost-k8s-threshold-signing/internal/jwtfmt"
	"frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/wire"
)

// FuzzSignerHandler drives signer.Server.Handler() with a crafted
// POST /v1/sign-share: body, X-Frost-Deadline-Ms and an optional fake mTLS
// peer. Oracles: no panic; response within 5 s; HTTP 200 only when an
// independent re-check finds the request well-formed, the header canonical,
// the deadline header valid and the claims policy-compliant, and the returned
// share verifies.
func FuzzSignerHandler(f *testing.F) {
	fx := loadKey(f)
	const id = 2
	pol := mustPolicy(f, testPolicyConfig())
	oracle := mustPolicy(f, testPolicyConfig())
	al, err := audit.Open(filepath.Join(f.TempDir(), "audit.log"))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { al.Close() })
	srv, err := signer.New(signer.Config{ID: id, Meta: fx.Meta, Share: fx.Shares[id-1], Policy: pol, Audit: al,
		Now: func() time.Time { return fixedNow }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		f.Fatal(err)
	}
	h := srv.Handler()
	hdr, _ := jwtfmt.EncodedHeader(fx.Meta.KID)
	in := func(c map[string]any) string { return hdr + "." + b64(mustJSON(f, c)) }
	req := func(si, rid string) []byte {
		return mustJSON(f, wire.SignShareRequest{SigningInput: si, RequestID: rid})
	}
	good := in(saClaims("default", "default"))
	bad := saClaims("default", "default")
	bad["iss"] = "https://evil.example"
	for _, s := range []struct {
		body     []byte
		deadline string
		tls      bool
	}{
		{req(good, "r1"), "", false},
		{req(good, "r1"), "2000", true},
		{req(good, "r1"), "60000", true},
		{req(good, "r1"), "60001", false},
		{req(good, "r1"), "0", false},
		{req(good, "r1"), "-5", false},
		{req(good, "r1"), " 100", false},
		{req(good, "r1"), "+100", false},
		{req(good, "r1"), "1e3", false},
		{req(good, "r1"), "9223372036854775808", false},
		{req(good, "r1"), "1", false},
		{req(in(bad), "r2"), "", false},
		{req(good, ""), "", false},
		{req(good, "bad id!"), "", false},
		{req(b64([]byte(`{"alg":"none","typ":"JWT","kid":"`+fx.Meta.KID+`"}`))+"."+b64(mustJSON(f, saClaims("default", "default"))), "r3"), "", false},
		{req(good+".sig", "r4"), "", false},
		{[]byte(`{"signing_input":"` + good + `","request_id":"r5","digest":"00"}`), "", false},
		{[]byte(`{"signing_input":"` + good + `","request_id":"r6"}{}`), "", false},
		{[]byte(`{"signing_input":"` + good + `","request_id":"r7"} `), "", false},
		{[]byte(`{"SIGNING_INPUT":"` + good + `","request_id":"r8"}`), "", false},
		{[]byte(`{"signing_input":"x","signing_input":"` + good + `","request_id":"r9"}`), "", false},
		{[]byte(`{"signing_input":"` + good + `","request_id":"r10"`), "", false},
		{bytes.Repeat([]byte(" "), 70000), "", false},
		{nil, "", false},
	} {
		f.Add(s.body, s.deadline, s.tls)
	}
	peer := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"coordinator-1"}}}}
	f.Fuzz(func(t *testing.T, body []byte, deadline string, withTLS bool) {
		r := httptest.NewRequest(http.MethodPost, wire.SignSharePath, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if deadline != "" {
			r.Header.Set(wire.DeadlineHeader, deadline)
		}
		if withTLS {
			r.TLS = peer
		}
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { defer close(done); h.ServeHTTP(w, r) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("handler hung > 5s (body %d bytes, deadline %q)", len(body), deadline)
		}
		if w.Code != http.StatusOK {
			return
		}
		// Independent re-check of everything a 200 implies.
		if v := r.Header.Get(wire.DeadlineHeader); v != "" {
			ms, err := strconv.ParseInt(v, 10, 64)
			if err != nil || ms <= 0 || ms > 60000 {
				t.Fatalf("200 with invalid deadline header %q", v)
			}
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		var sr wire.SignShareRequest
		if err := dec.Decode(&sr); err != nil || dec.More() {
			t.Fatalf("200 for a body the strict decoder rejects: %v", err)
		}
		if !wire.ValidRequestID(sr.RequestID) {
			t.Fatalf("200 with invalid request_id %q", sr.RequestID)
		}
		hs, ps, err := jwtfmt.SplitSigningInput(sr.SigningInput)
		if err != nil {
			t.Fatalf("200 for unsplittable input: %v", err)
		}
		if hs != hdr {
			t.Fatalf("200 for non-canonical header %q", hs)
		}
		payload, err := jwtfmt.DecodeSegment(ps)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oracle.Evaluate(payload, fixedNow); err != nil {
			t.Fatalf("200 for a payload the policy rejects: %v", err)
		}
		if _, err := checkDifferential(oracle, oracle.Config().Issuer, payload); err != nil {
			t.Fatalf("signed payload has an apiserver differential: %v", err)
		}
		var resp wire.SignShareResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("200 body: %v", err)
		}
		if resp.SignerID != id || resp.RequestID != sr.RequestID {
			t.Fatalf("200 body ids %+v", resp)
		}
		ss, err := resp.Share.ToTcrsa(id, fx.Meta.Parties, fx.Meta.PublicKey.N)
		if err != nil {
			t.Fatal(err)
		}
		if err := ss.Verify(paddedDigest(t, fx.Meta, sr.SigningInput), fx.Meta.Tcrsa); err != nil {
			t.Fatalf("share over a different message than the signing input: %v", err)
		}
	})
}

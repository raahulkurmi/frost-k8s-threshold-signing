package coordinator_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/wire"
)

var strategies = []coordinator.Strategy{coordinator.Strict, coordinator.Optimistic}

func claims(t *testing.T) string {
	return testutil.Payload(t, testutil.SAClaims("default", "default", time.Now(), time.Hour))
}

func token(r *coordinator.Result, claims string) string {
	return r.Header + "." + claims + "." + r.Signature
}

func TestSignProducesStandardRS256(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	for _, st := range strategies {
		t.Run(string(st), func(t *testing.T) {
			co := c.NewCoordinator(t, st, 5*time.Second, nil)
			cl := claims(t)
			res, err := co.Sign(context.Background(), cl)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Signers) != 3 {
				t.Fatalf("combined %v, want 3 shares", res.Signers)
			}
			std, err := testutil.VerifyRS256(token(res, cl), c.Fx.Meta.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if std.Subject != "system:serviceaccount:default:default" {
				t.Fatalf("sub %q", std.Subject)
			}
			hdr, _ := base64.RawURLEncoding.DecodeString(res.Header)
			if string(hdr) != `{"alg":"RS256","typ":"JWT","kid":"`+c.Fx.Meta.KID+`"}` {
				t.Fatalf("header %s", hdr)
			}
		})
	}
}

func TestSignRejectsMalformedClaims(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	co := c.NewCoordinator(t, coordinator.Strict, time.Second, nil)
	for _, bad := range []string{"", "a.b", "has space", "padded=="} {
		if _, err := co.Sign(context.Background(), bad); err == nil {
			t.Fatalf("claims %q accepted", bad)
		}
	}
}

// Both strategies exclude and attribute bad shares, and still sign with 3 honest.
func TestMaliciousShareExcludedAndAttributed(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id == 1 {
			return testutil.CorruptShare(h)
		}
		return h
	}})
	for _, st := range strategies {
		t.Run(string(st), func(t *testing.T) {
			var logs testutil.LogBuffer
			co := c.NewCoordinator(t, st, 5*time.Second, logs.Logger())
			cl := claims(t)
			var res *coordinator.Result
			var err error
			// Signer 1 must be among the first t for the optimistic path to be
			// exercised; retry until it is.
			for i := 0; i < 20; i++ {
				res, err = co.Sign(context.Background(), cl)
				if err != nil {
					t.Fatal(err)
				}
				if len(res.Excluded) > 0 {
					break
				}
			}
			if _, err := testutil.VerifyRS256(token(res, cl), c.Fx.Meta.PublicKey); err != nil {
				t.Fatal(err)
			}
			for _, id := range res.Signers {
				if id == 1 {
					t.Fatalf("combined bad share from signer 1: %v", res.Signers)
				}
			}
			if len(res.Excluded) != 1 || res.Excluded[0].SignerID != 1 || !strings.Contains(res.Excluded[0].Reason, "invalid signature share") {
				t.Fatalf("excluded %+v, want signer 1 invalid share", res.Excluded)
			}
			if !strings.Contains(logs.String(), `"msg":"excluded invalid signature share"`) || !strings.Contains(logs.String(), `"signer_id":1`) {
				t.Fatalf("log does not attribute the bad share to signer 1:\n%s", logs.String())
			}
			t.Logf("%s: combined %v, excluded %+v", st, res.Signers, res.Excluded)
		})
	}
}

func TestThreeMaliciousFails(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id <= 3 {
			return testutil.CorruptShare(h)
		}
		return h
	}})
	for _, st := range strategies {
		co := c.NewCoordinator(t, st, 5*time.Second, nil)
		res, err := co.Sign(context.Background(), claims(t))
		var te *coordinator.ThresholdError
		if !errors.As(err, &te) || res != nil {
			t.Fatalf("%s: got res=%v err=%v, want ThresholdError", st, res, err)
		}
		if te.Valid != 2 {
			t.Fatalf("%s: valid=%d, want 2", st, te.Valid)
		}
		t.Logf("%s: %v", st, err)
	}
}

func TestBelowThresholdSigners(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id >= 3 {
			return testutil.Down()
		}
		return h
	}})
	co := c.NewCoordinator(t, coordinator.Strict, 5*time.Second, nil)
	res, err := co.Sign(context.Background(), claims(t))
	var te *coordinator.ThresholdError
	if !errors.As(err, &te) || res != nil || te.Valid != 2 || len(te.Failures) != 3 {
		t.Fatalf("res=%v err=%v", res, err)
	}
	t.Log(err)
}

func TestDeadlineRespected(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id >= 3 {
			return testutil.Delay(10*time.Second, h)
		}
		return h
	}})
	co := c.NewCoordinator(t, coordinator.Strict, 300*time.Millisecond, nil)
	start := time.Now()
	res, err := co.Sign(context.Background(), claims(t))
	el := time.Since(start)
	var te *coordinator.ThresholdError
	if !errors.As(err, &te) || res != nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if el > 300*time.Millisecond+250*time.Millisecond {
		t.Fatalf("returned after %v, deadline 300ms", el)
	}
	if !strings.Contains(err.Error(), "no response before deadline") {
		t.Fatalf("error does not name the timed-out signers: %v", err)
	}
	t.Logf("returned in %v: %v", el, err)
}

// TestShareIDBoundToMTLSIdentity (R-b): a response that claims another
// signer's id, or a signer serving another signer's certificate, is rejected.
func TestShareIDBoundToMTLSIdentity(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id != 2 {
			return h
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			var resp wire.SignShareResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			resp.SignerID = 4 // lie about identity
			_ = json.NewEncoder(w).Encode(resp)
		})
	}})
	co := c.NewCoordinator(t, coordinator.Strict, 5*time.Second, nil, 1, 2, 3)
	_, err := co.Sign(context.Background(), claims(t))
	if err == nil || !strings.Contains(err.Error(), "claims signer_id 4 but came from authenticated signer-2") {
		t.Fatalf("err = %v", err)
	}

	// Endpoint 3 pointed at signer 4's server: TLS pins signer-3 and rejects it.
	eps := c.Endpoints(t, 1, 2, 3)
	eps[2].URL = c.Servers[4].URL
	co2, err := coordinator.New(coordinator.Config{Meta: c.Fx.Meta, Endpoints: eps, Deadline: 5 * time.Second, Strategy: coordinator.Strict})
	if err != nil {
		t.Fatal(err)
	}
	_, err = co2.Sign(context.Background(), claims(t))
	if err == nil || !strings.Contains(err.Error(), "signer-3") {
		t.Fatalf("err = %v", err)
	}
	t.Log(err)
}

func TestNewRejectsBadEndpoints(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	eps := c.Endpoints(t)
	for name, e := range map[string][]coordinator.Endpoint{
		"fewer than t": eps[:2],
		"duplicate id": {eps[0], eps[1], eps[1]},
		"id 0":         {{ID: 0, URL: "https://x", Client: eps[0].Client}, eps[1], eps[2]},
		"id 6":         {{ID: 6, URL: "https://x", Client: eps[0].Client}, eps[1], eps[2]},
	} {
		if _, err := coordinator.New(coordinator.Config{Meta: c.Fx.Meta, Endpoints: e, Deadline: time.Second, Strategy: coordinator.Strict}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := coordinator.New(coordinator.Config{Meta: c.Fx.Meta, Endpoints: eps, Deadline: time.Second, Strategy: "yolo"}); err == nil {
		t.Error("unknown strategy accepted")
	}
}

// TestJoinOutOfRangeIDs (R-b, spike-style): documents what tcrsa does with
// out-of-range and duplicate Ids, and shows wire.ToTcrsa stops them first.
func TestJoinOutOfRangeIDs(t *testing.T) {
	fx := testutil.Key(t)
	meta := fx.Meta
	in := testutil.Header(meta.KID) + "." + claims(t)
	doc := testutil.PaddedDigest(t, meta, in)
	var good []*tcrsa.SigShare
	for i := 0; i < 3; i++ {
		ss, err := fx.Shares[i].Sign(doc, crypto.SHA256, meta.Tcrsa)
		if err != nil {
			t.Fatal(err)
		}
		good = append(good, ss)
	}
	for _, id := range []uint16{0, 6, 65535} {
		bad := *good[2]
		bad.Id = id
		var sig []byte
		var err error
		panicked := func() (p bool) {
			defer func() { p = recover() != nil }()
			sig, err = tcrsa.SigShareList{good[0], good[1], &bad}.Join(doc, meta.Tcrsa)
			return false
		}()
		switch {
		case panicked:
			t.Logf("tcrsa Join with Id=%d: PANIC", id)
		case err != nil:
			t.Logf("tcrsa Join with Id=%d: error %v", id, err)
		default:
			if testutil.VerifyPKCS1(meta.PublicKey, in, sig) == nil {
				t.Fatalf("Join with Id=%d produced a VALID signature", id)
			}
			t.Logf("tcrsa Join with Id=%d: no error, INVALID signature", id)
		}
		// The coordinator never gets that far: ToTcrsa bounds-checks the id.
		ws := wire.FromTcrsa(good[2])
		if _, err := ws.ToTcrsa(int(id), meta.Parties, meta.PublicKey.N); err == nil {
			t.Fatalf("ToTcrsa accepted id %d", id)
		}
	}
	// Well-formedness checks on share values.
	ws := wire.FromTcrsa(good[0])
	nB := meta.PublicKey.N.Bytes()
	for name, mut := range map[string]func(*wire.SigShare){
		"xi = 0":  func(s *wire.SigShare) { s.Xi = base64.StdEncoding.EncodeToString([]byte{0}) },
		"xi = n":  func(s *wire.SigShare) { s.Xi = base64.StdEncoding.EncodeToString(nB) },
		"empty c": func(s *wire.SigShare) { s.C = "" },
		"bad b64": func(s *wire.SigShare) { s.Z = "!!!" },
		"huge z":  func(s *wire.SigShare) { s.Z = base64.StdEncoding.EncodeToString(make([]byte, 4*len(nB))) },
	} {
		s := ws
		mut(&s)
		if _, err := s.ToTcrsa(1, meta.Parties, meta.PublicKey.N); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// TestCoordinatorMetaIsGroupKey: the PKIX key the coordinator holds (and
// FetchKeys serves) verifies its tokens after a ParsePKIX round-trip.
func TestCoordinatorMetaIsGroupKey(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	co := c.NewCoordinator(t, coordinator.Strict, 5*time.Second, nil)
	pub, err := x509.ParsePKIXPublicKey(co.Meta().PKIX)
	if err != nil {
		t.Fatal(err)
	}
	cl := claims(t)
	res, err := co.Sign(context.Background(), cl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.VerifyRS256(token(res, cl), pub.(*rsa.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

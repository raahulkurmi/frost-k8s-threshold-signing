package signer_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/audit"
	"frost-k8s-threshold-signing/internal/policy"
	. "frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/wire"
)

// frozen keeps f fixed for the test: windows never close.
var frozen = AdmissionConfig{Window: time.Hour, WindowArrivals: 1 << 30}

func testKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

func randID(t *testing.T) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

// newPrioServer starts signer id with priority admission at fraction f
// (frozen) and the given clock.
func newPrioServer(t *testing.T, id int, key []byte, f float64, now func() time.Time) (*Server, string) {
	t.Helper()
	fx := testutil.Key(t)
	pol, err := policy.New(testutil.PolicyConfig())
	if err != nil {
		t.Fatal(err)
	}
	ap := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.Open(ap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	srv, err := New(Config{ID: id, Meta: fx.Meta, Share: fx.Shares[id-1], Policy: pol, Audit: al, Now: now,
		MaxConcurrent: 4, PriorityKey: key, Admission: frozen})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetAdmittedFraction(f)
	return srv, ap
}

func inputAt(t *testing.T, iat time.Time) string {
	fx := testutil.Key(t)
	return testutil.Header(fx.Meta.KID) + "." + testutil.Payload(t, testutil.SAClaims("default", "default", iat, time.Hour))
}

func admitted(t *testing.T, srv *Server, in, reqID string) bool {
	t.Helper()
	resp, rej := srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: reqID}, "coordinator-1")
	switch {
	case rej == nil && resp != nil:
		return true
	case rej != nil && rej.Kind == "overloaded" && strings.Contains(rej.Reason, "priority below admission level"):
		return false
	}
	t.Fatalf("request %s: unexpected outcome resp=%v rej=%v", reqID, resp, rej)
	return false
}

func TestPrioritySameAtEverySigner(t *testing.T) {
	k := testKey(1)
	iat := time.Date(2026, 9, 28, 10, 30, 0, 0, time.UTC).Unix()
	differ := 0
	for i := 0; i < 200; i++ {
		id := randID(t)
		if Priority(k, iat, id) != Priority(append([]byte(nil), k...), iat, id) {
			t.Fatal("same key, iat and request id gave different priorities")
		}
		if Priority(k, iat, id) != Priority(testKey(2), iat, id) {
			differ++
		}
	}
	if differ < 190 {
		t.Fatalf("another key gave the same priority for %d of 200 ids", 200-differ)
	}
}

// Epoch boundary (N76 addition 1): the epoch comes from the request's iat, so
// two signers whose clocks straddle an hour boundary (20 ms apart, within
// N50's ms-level skew) make identical decisions for every request. A
// local-clock epoch would put them in different epochs.
func TestEpochBoundarySignersAgree(t *testing.T) {
	boundary := time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC)
	before, after := boundary.Add(-10*time.Millisecond), boundary.Add(10*time.Millisecond)
	if Epoch(before.Unix()) == Epoch(after.Unix()) {
		t.Fatal("test setup: the two clocks are in the same epoch")
	}
	k := testKey(3)
	a, _ := newPrioServer(t, 1, k, 0.5, func() time.Time { return before })
	b, _ := newPrioServer(t, 2, k, 0.5, func() time.Time { return after })
	for _, iat := range []time.Time{boundary.Add(-time.Second), boundary} { // tokens issued just before and at the boundary
		in := inputAt(t, iat)
		agree, adm := 0, 0
		for i := 0; i < 60; i++ {
			id := randID(t)
			x, y := admitted(t, a, in, id), admitted(t, b, in, id)
			if x != y {
				t.Fatalf("iat %v: signers disagree on request %s (clocks %v / %v)", iat, id, before.Format("15:04:05.000"), after.Format("15:04:05.000"))
			}
			agree++
			if x {
				adm++
			}
		}
		t.Logf("iat %s (epoch %d): %d/%d identical decisions across the boundary, %d admitted at f=0.5",
			iat.Format("15:04:05"), Epoch(iat.Unix()), agree, agree, adm)
	}
}

// Nested admission sets (N76): with the same key, a signer at a smaller
// admitted fraction admits a subset of what a signer at a larger one admits,
// so a request reaches t = 3 shares exactly when the 3rd most lenient signer
// admits it.
func TestNestedAdmissionSetsAcrossSigners(t *testing.T) {
	k := testKey(4)
	fs := []float64{0.9, 0.7, 0.5, 0.3, 0.1}
	var srvs []*Server
	for i, f := range fs {
		s, _ := newPrioServer(t, i+1, k, f, time.Now)
		srvs = append(srvs, s)
	}
	in := inputAt(t, time.Now())
	counts := make([]int, len(fs))
	tokens := 0
	const n = 120
	for r := 0; r < n; r++ {
		id := randID(t)
		adm := make([]bool, len(fs))
		got := 0
		for i, s := range srvs {
			adm[i] = admitted(t, s, in, id)
			if adm[i] {
				counts[i]++
				got++
			}
		}
		for i := 1; i < len(fs); i++ {
			if adm[i] && !adm[i-1] {
				t.Fatalf("request %s: admitted at f=%.1f but refused at f=%.1f (sets not nested)", id, fs[i], fs[i-1])
			}
		}
		if (got >= 3) != adm[2] {
			t.Fatalf("request %s: %d shares, but the 3rd most lenient signer admitted=%v", id, got, adm[2])
		}
		if got >= 3 {
			tokens++
		}
	}
	t.Logf("admitted per signer (f=%v): %v of %d; requests with >= 3 shares: %d", fs, counts, n, tokens)
}

// A priority refusal is a 503 "overloaded" with the admission level header,
// audited as shed, and computes no share. A policy violation is still denied
// (403) first, whatever its priority.
func TestPriorityRefusalHTTPAndAudit(t *testing.T) {
	srv, ap := newPrioServer(t, 1, testKey(5), 0.05, time.Now)
	in := inputAt(t, time.Now())
	var refusedID string
	for i := 0; i < 50 && refusedID == ""; i++ {
		id := randID(t)
		body := `{"signing_input":"` + in + `","request_id":"` + id + `"}`
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, wire.SignSharePath, strings.NewReader(body)))
		if rec.Code == http.StatusServiceUnavailable {
			lvl, err := strconv.Atoi(rec.Header().Get(wire.AdmissionLevelHeader))
			if err != nil || lvl != 62259 { // floor((1 - 0.05) * 65536)
				t.Fatalf("admission level header %q, want 62259", rec.Header().Get(wire.AdmissionLevelHeader))
			}
			if !strings.Contains(rec.Body.String(), `"error":"overloaded"`) {
				t.Fatalf("body %s", rec.Body.String())
			}
			refusedID = id
		}
	}
	if refusedID == "" {
		t.Fatal("no refusal in 50 requests at f=0.05")
	}
	before := srv.RSAOps()
	b, _ := os.ReadFile(ap)
	if !strings.Contains(string(b), `"request_id":"`+refusedID+`"`) || !strings.Contains(string(b), `"decision":"shed"`) || !strings.Contains(string(b), "priority below admission level") {
		t.Fatalf("audit log lacks the shed entry for %s", refusedID)
	}
	bad := testutil.Header(testutil.Key(t).Meta.KID) + "." + testutil.Payload(t, func() map[string]any {
		c := testutil.SAClaims("default", "default", time.Now(), time.Hour)
		c["iss"] = "https://evil.example"
		return c
	}())
	for i := 0; i < 20; i++ {
		_, rej := srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: bad, RequestID: randID(t)}, "coordinator-1")
		if rej == nil || rej.Status != http.StatusForbidden {
			t.Fatalf("policy-violating request: %v, want 403 before the priority stage", rej)
		}
	}
	if srv.RSAOps() != before {
		t.Fatal("refused requests computed shares")
	}
}

// The admitted fraction adapts: -5 % per overloaded window (N48 shed or long
// waits), +1 % per calm window, idle windows count, bounded below.
func TestAdmissionLevelAdapts(t *testing.T) {
	a := NewAdmissionForTest(testKey(6), AdmissionConfig{Window: 100 * time.Millisecond, WindowArrivals: 1 << 30})
	t0 := time.Unix(1_790_000_000, 0)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	a.Decide(at(0), 65535, "coordinator-1", 2*time.Second) // opens the first window
	for w := 1; w <= 10; w++ {                             // 10 overloaded windows
		a.ObserveShed()
		a.Decide(at(100*w), 65535, "coordinator-1", 2*time.Second)
	}
	want := 1.0
	for i := 0; i < 10; i++ {
		want *= 0.95
	}
	if f := a.Fraction(); f < want-1e-9 || f > want+1e-9 {
		t.Fatalf("after 10 overloaded windows f = %.4f, want %.4f", f, want)
	}
	a.Decide(at(1100), 65535, "coordinator-1", 2*time.Second) // one calm window
	if f := a.Fraction(); f < want+0.01-1e-9 || f > want+0.01+1e-9 {
		t.Fatalf("after a calm window f = %.4f, want %.4f", f, want+0.01)
	}
	a.Decide(at(2100), 65535, "coordinator-1", 2*time.Second) // 1 s idle = 10 windows
	if f := a.Fraction(); f < want+0.11-1e-9 || f > want+0.11+1e-9 {
		t.Fatalf("after 1 s idle f = %.4f, want %.4f", f, want+0.11)
	}
	// Long waits alone (mean wait 1.2 s > 0.5 x median budget 2 s) are overload.
	f0 := a.Fraction()
	a.ObserveWait(1200 * time.Millisecond)
	a.Decide(at(2200), 65535, "coordinator-1", 2*time.Second)
	if f := a.Fraction(); f >= f0 {
		t.Fatalf("long waits did not lower f (%.4f -> %.4f)", f0, f)
	}
	// Short waits (0.65 s < 1 s) are not: the uncapped 7C c=50 case (N69, N72).
	f1 := a.Fraction()
	a.ObserveWait(650 * time.Millisecond)
	a.Decide(at(2300), 65535, "coordinator-1", 2*time.Second)
	if f := a.Fraction(); f <= f1 {
		t.Fatalf("650 ms waits against a 2 s budget lowered f (%.4f -> %.4f)", f1, f)
	}
	for w := 24; w < 24+200; w++ {
		a.ObserveShed()
		a.Decide(at(100*w), 65535, "coordinator-1", 2*time.Second)
	}
	if f := a.Fraction(); f < 0.05-1e-9 || f > 0.05+1e-9 {
		t.Fatalf("f = %.4f after sustained overload, want the 0.05 floor", f)
	}
}

// Per-client fair share (N76 hardening): under overload, a flooding client is
// capped at FairSlack x (previous window's admissions / clients); a light
// client is not affected.
func TestFairShareCapsAFloodingClient(t *testing.T) {
	a := NewAdmissionForTest(testKey(7), AdmissionConfig{Window: 100 * time.Millisecond, WindowArrivals: 1 << 30})
	t0 := time.Unix(1_790_000_000, 0)
	a.Decide(t0, 65535, "coordinator-1", time.Second)
	a.SetFraction(0.5)
	// window 1: 40 + 40 admissions from two clients
	for i := 0; i < 40; i++ {
		a.Decide(t0.Add(time.Millisecond), 65535, "coordinator-1", time.Second)
		a.Decide(t0.Add(time.Millisecond), 65535, "coordinator-2", time.Second)
	}
	a.ObserveShed() // keep the signer overloaded (f < 1)
	// window 2: coordinator-2 floods, coordinator-1 sends 10
	okFlood, okLight := 0, 0
	for i := 0; i < 200; i++ {
		if ok, why := a.Decide(t0.Add(101*time.Millisecond), 65535, "coordinator-2", time.Second); ok {
			okFlood++
		} else if why != "fair_share" {
			t.Fatalf("flooding client refused for %q", why)
		}
	}
	for i := 0; i < 10; i++ {
		if ok, _ := a.Decide(t0.Add(102*time.Millisecond), 65535, "coordinator-1", time.Second); ok {
			okLight++
		}
	}
	// cap = ceil(1.25 x 81 / 2) = 51 (window 1 also counted the opening arrival)
	if okFlood != 51 || okLight != 10 {
		t.Fatalf("flooding client admitted %d (want 51), light client %d (want 10)", okFlood, okLight)
	}
	t.Logf("fair share: flooding client admitted %d of 200, light client %d of 10", okFlood, okLight)
}

// No starvation (N76 addition 2): a refused TokenRequest is retried by the
// kubelet, reaches the coordinator as a new Sign call and gets a new
// request_id, hence a fresh, independent priority. At a fixed admitted
// fraction f every request is eventually admitted, after about 1/f attempts.
func TestRefusedRequestsAreNotStarved(t *testing.T) {
	a := NewAdmissionForTest(testKey(8), frozen)
	a.Decide(time.Now(), 65535, "coordinator-1", time.Second)
	a.SetFraction(0.3)
	iat := time.Now().Unix()
	const reqs, maxTries = 400, 60
	first, total, worst := 0, 0, 0
	for r := 0; r < reqs; r++ {
		tries := 0
		for {
			tries++
			if tries > maxTries {
				t.Fatalf("request %d refused %d times in a row at f=0.3", r, maxTries)
			}
			if ok, _ := a.Decide(time.Now(), Priority(testKey(8), iat, randID(t)), "coordinator-1", time.Second); ok {
				break
			}
		}
		if tries == 1 {
			first++
		}
		total += tries
		worst = max(worst, tries)
	}
	mean := float64(total) / reqs
	firstFrac := float64(first) / reqs
	if firstFrac < 0.22 || firstFrac > 0.38 || mean < 2.5 || mean > 4.3 {
		t.Fatalf("first-attempt admission %.2f (want ≈ 0.30), mean attempts %.2f (want ≈ 3.3)", firstFrac, mean)
	}
	t.Logf("f=0.3: %d requests all admitted; first attempt %.0f%%, mean %.2f attempts, worst %d", reqs, 100*firstFrac, mean, worst)
}

// Deadline cap (N76 hardening): a caller asking for 60 s is held to MaxDeadline.
func TestDeadlineHeaderIsCapped(t *testing.T) {
	fx := testutil.Key(t)
	pol, _ := policy.New(testutil.PolicyConfig())
	al, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	srv, err := New(Config{ID: 1, Meta: fx.Meta, Share: fx.Shares[0], Policy: pol, Audit: al, MaxConcurrent: 1, MaxQueue: 4, MaxDeadline: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	in := inputAt(t, time.Now())
	release, done := holdSlot(t, srv, in)
	defer func() { release(); <-done }()
	srv.SetRSAEstimate(10 * time.Millisecond)
	body := `{"signing_input":"` + in + `","request_id":"long"}`
	req := httptest.NewRequest(http.MethodPost, wire.SignSharePath, strings.NewReader(body))
	req.Header.Set(wire.DeadlineHeader, "60000")
	rec := httptest.NewRecorder()
	start := time.Now()
	srv.Handler().ServeHTTP(rec, req)
	if el := time.Since(start); rec.Code != http.StatusServiceUnavailable || el > time.Second {
		t.Fatalf("60 s deadline with a 300 ms cap: HTTP %d after %v, want 503 within ~300 ms", rec.Code, el)
	}
}

package signer_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

// frozen keeps the level fixed for the test: windows never close.
var frozen = AdmissionConfig{Window: time.Hour, WindowArrivals: 1 << 30}

func frozenMode(m PriorityMode) AdmissionConfig { c := frozen; c.Mode = m; return c }

var modes = []PriorityMode{PriorityRequest, PriorityStable}

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

// newPrioServer starts signer id with priority admission (mode) at fraction f
// (frozen) and the given clock.
func newPrioServer(t *testing.T, id int, key []byte, mode PriorityMode, f float64, now func() time.Time) (*Server, string) {
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
		MaxConcurrent: 4, PriorityKey: key, Admission: frozenMode(mode)})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetAdmittedFraction(f)
	return srv, ap
}

// inputFor is a token for service account default/<sa>, bound to pod podUID if set.
func inputFor(t *testing.T, iat time.Time, sa, podUID string) string {
	fx := testutil.Key(t)
	c := testutil.SAClaims("default", sa, iat, time.Hour)
	if podUID != "" {
		c["kubernetes.io"].(map[string]any)["pod"] = map[string]any{"name": "p-" + podUID[:8], "uid": podUID}
	}
	return testutil.Header(fx.Meta.KID) + "." + testutil.Payload(t, c)
}

func inputAt(t *testing.T, iat time.Time) string { return inputFor(t, iat, "default", "") }

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

// request is one sign-share request in a test: what varies between requests
// depends on the mode (request: the request_id; stable: the identity).
func request(t *testing.T, mode PriorityMode, iat time.Time, i int) (in, reqID string) {
	if mode == PriorityRequest {
		return inputAt(t, iat), randID(t)
	}
	return inputFor(t, iat, fmt.Sprintf("sa-%d", i), ""), randID(t)
}

func TestPrioritySameAtEverySigner(t *testing.T) {
	k := testKey(1)
	iat := time.Date(2026, 9, 28, 10, 30, 0, 0, time.UTC).Unix()
	differ := 0
	for i := 0; i < 200; i++ {
		id := randID(t)
		if Priority(k, iat, id) != Priority(append([]byte(nil), k...), iat, id) ||
			StablePriority(k, iat, id, 2*time.Minute, 32) != StablePriority(append([]byte(nil), k...), iat, id, 2*time.Minute, 32) {
			t.Fatal("same key, iat and input gave different priorities")
		}
		if Priority(k, iat, id) != Priority(testKey(2), iat, id) {
			differ++
		}
	}
	if differ < 190 {
		t.Fatalf("another key gave the same priority for %d of 200 ids", 200-differ)
	}
}

// Epoch boundary (N76 addition 1): epochs come from the request's iat, so two
// signers whose clocks straddle a boundary (20 ms apart, within N50's ms-level
// skew) make identical decisions. 11:00:00 is both an hour boundary (request
// mode) and a 2-minute boundary (stable mode).
func TestEpochBoundarySignersAgree(t *testing.T) {
	boundary := time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC)
	before, after := boundary.Add(-10*time.Millisecond), boundary.Add(10*time.Millisecond)
	if Epoch(before.Unix()) == Epoch(after.Unix()) || StableEpoch(before.Unix(), 2*time.Minute) == StableEpoch(after.Unix(), 2*time.Minute) {
		t.Fatal("test setup: the two clocks are in the same epoch")
	}
	for _, mode := range modes {
		k := testKey(3)
		a, _ := newPrioServer(t, 1, k, mode, 0.5, func() time.Time { return before })
		b, _ := newPrioServer(t, 2, k, mode, 0.5, func() time.Time { return after })
		for _, iat := range []time.Time{boundary.Add(-time.Second), boundary} {
			adm := 0
			for i := 0; i < 60; i++ {
				in, id := request(t, mode, iat, i)
				x, y := admitted(t, a, in, id), admitted(t, b, in, id)
				if x != y {
					t.Fatalf("%s, iat %v: signers disagree on request %d", mode, iat, i)
				}
				if x {
					adm++
				}
			}
			t.Logf("%s, iat %s: 60/60 identical decisions across the boundary, %d admitted at f=0.5", mode, iat.Format("15:04:05"), adm)
		}
	}
}

// Nested admission sets (N76): with the same key, a signer at a smaller
// admitted fraction admits a subset of what a signer at a larger one admits,
// so a request reaches t = 3 shares exactly when the 3rd most lenient signer
// admits it. Both modes.
func TestNestedAdmissionSetsAcrossSigners(t *testing.T) {
	fs := []float64{0.9, 0.7, 0.5, 0.3, 0.1}
	for _, mode := range modes {
		k := testKey(4)
		var srvs []*Server
		for i, f := range fs {
			s, _ := newPrioServer(t, i+1, k, mode, f, time.Now)
			srvs = append(srvs, s)
		}
		now := time.Now()
		counts := make([]int, len(fs))
		tokens := 0
		const n = 100
		for r := 0; r < n; r++ {
			in, id := request(t, mode, now, r)
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
					t.Fatalf("%s request %d: admitted at f=%.1f but refused at f=%.1f (sets not nested)", mode, r, fs[i], fs[i-1])
				}
			}
			if (got >= 3) != adm[2] {
				t.Fatalf("%s request %d: %d shares, but the 3rd most lenient signer admitted=%v", mode, r, got, adm[2])
			}
			if got >= 3 {
				tokens++
			}
		}
		t.Logf("%s: admitted per signer (f=%v): %v of %d; requests with >= 3 shares: %d", mode, fs, counts, n, tokens)
	}
}

// Stable mode (N77): retries of the same identity (new request_id, new iat in
// the same epoch) keep the same decision; distinct identities differ; the next
// epoch rotates every identity by 2^16/R.
func TestStablePriorityKeptAcrossRetries(t *testing.T) {
	k := testKey(9)
	start := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC) // a 2-minute epoch boundary
	srv, _ := newPrioServer(t, 1, k, PriorityStable, 0.5, func() time.Time { return start.Add(time.Minute) })
	adm, ref := 0, 0
	for i := 0; i < 40; i++ {
		first := admitted(t, srv, inputFor(t, start, fmt.Sprintf("sa-%d", i), ""), randID(t))
		for r := 1; r <= 4; r++ { // kubelet retries: new request_id, later iat, same epoch
			if got := admitted(t, srv, inputFor(t, start.Add(time.Duration(r*20)*time.Second), fmt.Sprintf("sa-%d", i), ""), randID(t)); got != first {
				t.Fatalf("identity sa-%d: retry %d decided %v, first attempt %v", i, r, got, first)
			}
		}
		if first {
			adm++
		} else {
			ref++
		}
	}
	if adm == 0 || ref == 0 {
		t.Fatalf("at f=0.5: %d identities admitted, %d refused; want both", adm, ref)
	}
	id := Identity("system:serviceaccount:default:sa-1", "")
	p0 := StablePriority(k, start.Unix(), id, 2*time.Minute, 32)
	p1 := StablePriority(k, start.Add(2*time.Minute).Unix(), id, 2*time.Minute, 32)
	if uint16(p1-p0) != 2048 {
		t.Fatalf("next epoch moved p by %d, want 65536/32 = 2048", uint16(p1-p0))
	}
	t.Logf("40 identities x 5 attempts in one epoch: decisions constant; %d admitted, %d refused at f=0.5; next epoch +2048", adm, ref)
}

// Stable identity (N77): sub + pod uid for pod-bound tokens, sub otherwise; two
// pods of one service account get independent priorities.
func TestStableIdentityFromClaims(t *testing.T) {
	if Identity("s", "") != "s" || Identity("s", "u") != "s\x00u" {
		t.Fatal("Identity")
	}
	k := testKey(10)
	iat := time.Now().Unix()
	same := 0
	for i := 0; i < 100; i++ {
		a := StablePriority(k, iat, Identity("system:serviceaccount:default:web", randID(t)), 2*time.Minute, 32)
		b := StablePriority(k, iat, Identity("system:serviceaccount:default:web", randID(t)), 2*time.Minute, 32)
		if a == b {
			same++
		}
	}
	if same > 2 {
		t.Fatalf("two pods of one service account had equal priority %d times in 100", same)
	}
	// End to end: a pod-bound token's identity includes the pod uid.
	srv, _ := newPrioServer(t, 1, k, PriorityStable, 0.5, time.Now)
	now := time.Now()
	uid := "0f2a6c1e-1111-4b7d-9e3a-5c6d7e8f9a0b"
	in := inputFor(t, now, "web", uid)
	want := int(StablePriority(k, now.Unix(), Identity("system:serviceaccount:default:web", uid), 2*time.Minute, 32)>>8) >= 128
	if got := admitted(t, srv, in, randID(t)); got != want {
		t.Fatalf("pod-bound token admitted=%v, want %v from sub+pod uid", got, want)
	}
}

// Worst-case wait (N77): at a fixed level L, an identity is refused for at
// most ceil(L·R/2^16) consecutive epochs, for every identity, provided the
// admitted band is at least one rotation step. At the floor (top 5 % always
// admitted, L = 62208) R = 8 violates that (step 8192 > band 3328: some
// identities are never admitted, so New refuses it); R = 32 gives 31 epochs,
// i.e. a pod is admitted within (31 + 1) × 2 min = 64 min at E = 2 min.
func TestStableWorstCaseWait(t *testing.T) {
	k := testKey(11)
	if StableWorstCaseEpochs(62208, 8) != -1 || StableRotationOK(8, 0.05) || !StableRotationOK(32, 0.05) {
		t.Fatal("R = 8 must be rejected at the 5 % floor, R = 32 accepted")
	}
	// R = 8 at the floor: identities exist that are never admitted.
	never := 0
	for i := 0; i < 3000; i++ {
		id := randID(t)
		ok := false
		for e := int64(0); e < 8; e++ {
			if StablePriority(k, e*120, id, 2*time.Minute, 8) >= 62208 {
				ok = true
			}
		}
		if !ok {
			never++
		}
	}
	if never == 0 {
		t.Fatal("R = 8 at the floor: expected identities that are never admitted")
	}
	t.Logf("R = 8 at the 5 %% floor: %d of 3000 identities are never admitted over a full rotation (rejected configuration)", never)
	const R = 32
	for _, level := range []int{62208, 49152, 32768, 8192} {
		bound := StableWorstCaseEpochs(level, R)
		worst, admittedAll := 0, true
		for i := 0; i < 3000; i++ {
			id := randID(t)
			run, ok := 0, false
			for e := int64(0); e < 3*R; e++ {
				p := StablePriority(k, e*120, id, 2*time.Minute, R)
				if int(p) < level {
					run++
					worst = max(worst, run)
				} else {
					run, ok = 0, true
				}
			}
			admittedAll = admittedAll && ok
		}
		if worst > bound || !admittedAll {
			t.Fatalf("level %d: worst %d consecutive refused epochs (bound %d), every identity admitted: %v", level, worst, bound, admittedAll)
		}
		t.Logf("level %d (admits top %.0f%%), R = 32: worst observed %d consecutive refused epochs, bound %d (wait <= %d min at E = 2 min)",
			level, 100*(1-float64(level)/65536), worst, bound, (bound+1)*2)
	}
}

func TestPriorityRefusalHTTPAndAudit(t *testing.T) {
	srv, ap := newPrioServer(t, 1, testKey(5), PriorityRequest, 0.05, time.Now)
	in := inputAt(t, time.Now())
	var refusedID string
	for i := 0; i < 50 && refusedID == ""; i++ {
		id := randID(t)
		body := `{"signing_input":"` + in + `","request_id":"` + id + `"}`
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, wire.SignSharePath, strings.NewReader(body)))
		if rec.Code == http.StatusServiceUnavailable {
			lvl, err := strconv.Atoi(rec.Header().Get(wire.AdmissionLevelHeader))
			if err != nil || lvl != 62208 { // round((1 - 0.05) * 256) * 256
				t.Fatalf("admission level header %q, want 62208", rec.Header().Get(wire.AdmissionLevelHeader))
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

// The level adapts as DAGOR §4.2.3: per window with N arrivals of which N_adm
// passed the level, an overloaded window (N48 shed, or long waits) sets the
// next window's expected admissions to (1 − α)·N_adm, any other window to
// N_adm + β·N; the level never passes the 5 % floor.
func TestAdmissionLevelAdapts(t *testing.T) {
	a := NewAdmissionForTest(testKey(6), AdmissionConfig{Window: 100 * time.Millisecond, WindowArrivals: 1 << 30})
	t0 := time.Unix(1_790_000_000, 0)
	// window w: 100 arrivals at priorities i*655 (one per distinct bucket),
	// at t0 + 100w ms + 1 µs·i; returns how many passed the level.
	window := func(w int) int {
		n := 0
		for i := 0; i < 100; i++ {
			if ok, why := a.Decide(t0.Add(time.Duration(w)*100*time.Millisecond+time.Duration(i)*time.Microsecond), uint16(i*655), "coordinator-1", 2*time.Second); ok {
				n++
			} else if why != "priority" {
				t.Fatalf("refused for %q", why)
			}
		}
		return n
	}
	if n := window(0); n != 100 {
		t.Fatalf("window 0 admitted %d of 100 at level 0", n)
	}
	a.ObserveShed() // window 0 overloaded -> expect (1 - 0.05) x 100 = 95
	if n := window(1); n != 95 {
		t.Fatalf("after an overloaded window: %d admitted, want 95", n)
	}
	// window 1 calm -> expect 95 + 0.01 x 100 = 96
	if n := window(2); n != 96 {
		t.Fatalf("after a calm window: %d admitted, want 96", n)
	}
	// long waits alone (mean 1.2 s > 0.5 x median budget 2 s) are overload: 0.95 x 96 = 91.2 -> 91
	a.ObserveWait(1200 * time.Millisecond)
	if n := window(3); n != 91 {
		t.Fatalf("after long waits: %d admitted, want 91", n)
	}
	// short waits (0.65 s < 1 s, the uncapped 7C c=50 case, N69, N72) are not: 91 + 1 = 92
	a.ObserveWait(650 * time.Millisecond)
	if n := window(4); n != 92 {
		t.Fatalf("after short waits: %d admitted, want 92", n)
	}
	for w := 5; w < 80; w++ { // sustained overload
		a.ObserveShed()
		window(w)
	}
	if f := a.Fraction(); f < 0.05 || f > 0.06 {
		t.Fatalf("admitted fraction %.4f after sustained overload, want the 5 %% floor", f)
	}
	t.Logf("100 -> 95 (overload) -> 96 (calm) -> 91 (long waits) -> 92 (short waits); floor %.3f", a.Fraction())
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

package signer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/audit"
	"frost-k8s-threshold-signing/internal/policy"
	. "frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/wire"
)

func newAdmission(t *testing.T, maxConc, maxQueue int) (*Server, string, string) {
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
	srv, err := New(Config{ID: 1, Meta: fx.Meta, Share: fx.Shares[0], Policy: pol, Audit: al, MaxConcurrent: maxConc, MaxQueue: maxQueue})
	if err != nil {
		t.Fatal(err)
	}
	in := testutil.Header(fx.Meta.KID) + "." + testutil.Payload(t, testutil.SAClaims("default", "default", time.Now(), time.Hour))
	return srv, in, ap
}

// holdSlot makes the FIRST request that reaches RSA hold its slot until
// release is closed. It returns once that request holds the slot.
func holdSlot(t *testing.T, srv *Server, in string) (release func(), done <-chan *Rejection) {
	t.Helper()
	holding, rel := make(chan struct{}), make(chan struct{})
	var once sync.Once
	SetTestHookBeforeRSA(func() { once.Do(func() { close(holding); <-rel }) })
	t.Cleanup(func() { SetTestHookBeforeRSA(nil) })
	d := make(chan *Rejection, 1)
	go func() {
		_, rej := srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "holder"}, "coordinator")
		d <- rej
	}()
	<-holding
	var o sync.Once
	return func() { o.Do(func() { close(rel) }) }, d
}

func ctxTimeout(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// N46a (kept): a request whose context is already cancelled does no RSA work.
func TestCancelledRequestComputesNoShare(t *testing.T) {
	srv, in, ap := newAdmission(t, 1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, rej := srv.SignShare(ctx, wire.SignShareRequest{SigningInput: in, RequestID: "c1"}, "coordinator")
	if resp != nil || rej == nil || rej.Kind != "cancelled" {
		t.Fatalf("resp=%v rej=%v, want cancelled", resp, rej)
	}
	if n := srv.RSAOps(); n != 0 {
		t.Fatalf("cancelled request performed %d RSA operations", n)
	}
	if _, rej := srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "c2"}, "coordinator"); rej != nil {
		t.Fatal(rej)
	}
	if n := srv.RSAOps(); n != 1 {
		t.Fatalf("live request: %d RSA operations, want 1", n)
	}
	b, _ := os.ReadFile(ap)
	if !strings.Contains(string(b), `"decision":"cancelled"`) {
		t.Fatalf("audit log lacks the cancelled decision")
	}
}

// N46a (kept): a share computed after the caller has gone is not released.
func TestCancelledDuringSigningDiscardsShare(t *testing.T) {
	srv, in, _ := newAdmission(t, 1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	SetTestHookBeforeRSA(cancel)
	t.Cleanup(func() { SetTestHookBeforeRSA(nil) })
	resp, rej := srv.SignShare(ctx, wire.SignShareRequest{SigningInput: in, RequestID: "d1"}, "coordinator")
	if resp != nil || rej == nil || rej.Kind != "cancelled" {
		t.Fatalf("resp=%v rej=%v, want share discarded", resp, rej)
	}
}

// N48: a queued request that fits its deadline waits for the slot and succeeds.
func TestQueuedRequestThatFitsSucceeds(t *testing.T) {
	srv, in, _ := newAdmission(t, 1, 0)
	release, done := holdSlot(t, srv, in)
	go func() { time.Sleep(150 * time.Millisecond); release() }()
	start := time.Now()
	resp, rej := srv.SignShare(ctxTimeout(t, 2*time.Second), wire.SignShareRequest{SigningInput: in, RequestID: "queued"}, "coordinator")
	el := time.Since(start)
	if rej != nil || resp == nil {
		t.Fatalf("queued request rejected: %v", rej)
	}
	if el < 100*time.Millisecond {
		t.Fatalf("returned after %v: it did not actually wait for the slot", el)
	}
	if r := <-done; r != nil {
		t.Fatal(r)
	}
	if n := srv.RSAOps(); n != 2 {
		t.Fatalf("RSA ops %d, want 2", n)
	}
	t.Logf("waited %v for the busy slot, then signed (deadline 2s, RSA estimate %v)", el.Round(time.Millisecond), srv.RSAEstimate().Round(time.Millisecond))
}

// N48: a request that cannot finish in time is shed immediately.
func TestRequestThatCannotFitIsShedImmediately(t *testing.T) {
	srv, in, _ := newAdmission(t, 1, 0)
	release, done := holdSlot(t, srv, in)
	srv.SetRSAEstimate(time.Second) // each share is believed to take 1s
	start := time.Now()
	resp, rej := srv.SignShare(ctxTimeout(t, 500*time.Millisecond), wire.SignShareRequest{SigningInput: in, RequestID: "nofit"}, "coordinator")
	el := time.Since(start)
	if resp != nil || rej == nil || rej.Status != http.StatusServiceUnavailable || rej.Kind != "overloaded" || !strings.Contains(rej.Reason, "cannot finish in time") {
		t.Fatalf("resp=%v rej=%v, want immediate 503 'cannot finish in time'", resp, rej)
	}
	if el > 50*time.Millisecond {
		t.Fatalf("shedding took %v; must not wait", el)
	}
	// The holder is paused in the pre-RSA hook, so nothing has been computed yet.
	if n := srv.RSAOps(); n != 0 {
		t.Fatalf("RSA ops %d while the holder is paused, want 0", n)
	}
	release()
	if r := <-done; r != nil {
		t.Fatal(r)
	}
	if n := srv.RSAOps(); n != 1 { // only the holder, never the shed request
		t.Fatalf("RSA ops %d after release, want 1", n)
	}
	t.Logf("shed in %v: %s", el.Round(time.Microsecond), rej.Reason)
}

// N48: the queue cap is enforced.
func TestQueueCapEnforced(t *testing.T) {
	srv, in, _ := newAdmission(t, 1, 2)
	release, done := holdSlot(t, srv, in)
	var wg sync.WaitGroup
	results := make(chan *Rejection, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, rej := srv.SignShare(ctxTimeout(t, 5*time.Second), wire.SignShareRequest{SigningInput: in, RequestID: "waiter"}, "coordinator")
			results <- rej
		}()
	}
	for deadline := time.Now().Add(2 * time.Second); srv.Waiting() < 2 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if w := srv.Waiting(); w != 2 {
		t.Fatalf("waiting = %d, want 2", w)
	}
	start := time.Now()
	_, rej := srv.SignShare(ctxTimeout(t, 5*time.Second), wire.SignShareRequest{SigningInput: in, RequestID: "third"}, "coordinator")
	if rej == nil || rej.Status != http.StatusServiceUnavailable || !strings.Contains(rej.Reason, "queue full") {
		t.Fatalf("third request: %v, want 503 queue full", rej)
	}
	if el := time.Since(start); el > 50*time.Millisecond {
		t.Fatalf("queue-full shed took %v", el)
	}
	release()
	wg.Wait()
	close(results)
	for r := range results {
		if r != nil {
			t.Fatalf("a waiter failed: %v", r)
		}
	}
	if r := <-done; r != nil {
		t.Fatal(r)
	}
	t.Logf("cap 2: two waiters queued and succeeded; third shed: %s", rej.Reason)
}

// N48: an expired deadline never computes a share, whether it expired before
// arrival or while waiting for a slot.
func TestExpiredDeadlineNeverComputesShare(t *testing.T) {
	srv, in, _ := newAdmission(t, 1, 0)
	past, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, rej := srv.SignShare(past, wire.SignShareRequest{SigningInput: in, RequestID: "past"}, "coordinator"); rej == nil {
		t.Fatal("expired request signed")
	}
	if n := srv.RSAOps(); n != 0 {
		t.Fatalf("expired request computed %d shares", n)
	}

	release, done := holdSlot(t, srv, in)
	srv.SetRSAEstimate(10 * time.Millisecond)
	start := time.Now()
	resp, rej := srv.SignShare(ctxTimeout(t, 200*time.Millisecond), wire.SignShareRequest{SigningInput: in, RequestID: "expires-queued"}, "coordinator")
	el := time.Since(start)
	if resp != nil || rej == nil {
		t.Fatal("request whose deadline expired in the queue was signed")
	}
	release()
	if r := <-done; r != nil {
		t.Fatal(r)
	}
	if n := srv.RSAOps(); n != 1 { // the holder only
		t.Fatalf("RSA ops %d, want 1 (holder); the expired waiter must compute nothing", n)
	}
	if el > 300*time.Millisecond {
		t.Fatalf("expired waiter returned after %v (deadline 200ms)", el)
	}
	t.Logf("already expired: 0 RSA ops; expired while queued: shed after %v (%s), 0 RSA ops for it", el.Round(time.Millisecond), rej.Reason)
}

// N48: the deadline header is parsed strictly.
func TestDeadlineHeader(t *testing.T) {
	srv, in, _ := newAdmission(t, 1, 0)
	body := `{"signing_input":"` + in + `","request_id":"h1"}`
	for _, tc := range []struct {
		v    string
		want int
	}{{"1500", http.StatusOK}, {"abc", http.StatusBadRequest}, {"0", http.StatusBadRequest}, {"-5", http.StatusBadRequest}, {"999999", http.StatusBadRequest}} {
		req := httptest.NewRequest(http.MethodPost, wire.SignSharePath, strings.NewReader(body))
		req.Header.Set(wire.DeadlineHeader, tc.v)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s=%q: HTTP %d, want %d", wire.DeadlineHeader, tc.v, rec.Code, tc.want)
		}
	}
}

func TestAdmissionDefaults(t *testing.T) {
	srv, _, _ := newAdmission(t, 0, 0)
	if srv.MaxConcurrent() < 1 || srv.MaxQueue() != 64 {
		t.Fatalf("defaults: MaxConcurrent=%d MaxQueue=%d", srv.MaxConcurrent(), srv.MaxQueue())
	}
	if _, err := New(Config{MaxConcurrent: -1}); err == nil {
		t.Fatal("negative MaxConcurrent accepted")
	}
}

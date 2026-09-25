package signer_test

import (
	"context"
	"net/http"
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

func newInternal(t *testing.T, maxConc int) (*Server, string, string) {
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
	srv, err := New(Config{ID: 1, Meta: fx.Meta, Share: fx.Shares[0], Policy: pol, Audit: al, MaxConcurrent: maxConc})
	if err != nil {
		t.Fatal(err)
	}
	in := testutil.Header(fx.Meta.KID) + "." + testutil.Payload(t, testutil.SAClaims("default", "default", time.Now(), time.Hour))
	return srv, in, ap
}

// TestCancelledRequestComputesNoShare (N46a): a request whose context is
// already cancelled performs zero RSA operations.
func TestCancelledRequestComputesNoShare(t *testing.T) {
	srv, in, ap := newInternal(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, rej := srv.SignShare(ctx, wire.SignShareRequest{SigningInput: in, RequestID: "c1"}, "coordinator")
	if resp != nil || rej == nil || rej.Kind != "cancelled" {
		t.Fatalf("resp=%v rej=%v, want cancelled", resp, rej)
	}
	if n := srv.RSAOps(); n != 0 {
		t.Fatalf("cancelled request performed %d RSA operations", n)
	}
	// Control: the same request with a live context does exactly one.
	if _, rej := srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "c2"}, "coordinator"); rej != nil {
		t.Fatal(rej)
	}
	if n := srv.RSAOps(); n != 1 {
		t.Fatalf("live request: %d RSA operations, want 1", n)
	}
	b, _ := os.ReadFile(ap)
	if !strings.Contains(string(b), `"decision":"cancelled"`) {
		t.Fatalf("audit log lacks the cancelled decision:\n%s", b)
	}
	t.Logf("cancelled: 0 RSA ops; live: 1 RSA op; audit records decision=cancelled")
}

// TestCancelledDuringSigningDiscardsShare (N46a): a share computed after the
// caller has gone is not released.
func TestCancelledDuringSigningDiscardsShare(t *testing.T) {
	srv, in, _ := newInternal(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	SetTestHookBeforeRSA(cancel) // the caller goes away just as signing starts
	t.Cleanup(func() { SetTestHookBeforeRSA(nil) })
	resp, rej := srv.SignShare(ctx, wire.SignShareRequest{SigningInput: in, RequestID: "d1"}, "coordinator")
	if resp != nil || rej == nil || rej.Kind != "cancelled" {
		t.Fatalf("resp=%v rej=%v, want share discarded", resp, rej)
	}
}

// TestAdmissionControlShedsImmediately (N46b): with MaxConcurrent=1 and one
// computation in flight, a second request gets 503 at once, not a queue.
func TestAdmissionControlShedsImmediately(t *testing.T) {
	srv, in, ap := newInternal(t, 1)
	if srv.MaxConcurrent() != 1 {
		t.Fatalf("MaxConcurrent = %d", srv.MaxConcurrent())
	}
	holding, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	SetTestHookBeforeRSA(func() { once.Do(func() { close(holding); <-release }) })
	t.Cleanup(func() { SetTestHookBeforeRSA(nil) })

	done := make(chan *Rejection, 1)
	go func() {
		_, rej := srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "slot-holder"}, "coordinator")
		done <- rej
	}()
	<-holding

	start := time.Now()
	resp, rej := srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "shed-me"}, "coordinator")
	el := time.Since(start)
	if resp != nil || rej == nil || rej.Status != http.StatusServiceUnavailable || rej.Kind != "overloaded" {
		t.Fatalf("second request: resp=%v rej=%v, want 503 overloaded", resp, rej)
	}
	if el > 50*time.Millisecond {
		t.Fatalf("shedding took %v; it must not wait for the slot", el)
	}
	close(release)
	if rej := <-done; rej != nil {
		t.Fatalf("slot holder failed: %v", rej)
	}
	// Slot free again: the next request succeeds.
	if _, rej := srv.SignShare(context.Background(), wire.SignShareRequest{SigningInput: in, RequestID: "after"}, "coordinator"); rej != nil {
		t.Fatalf("after release: %v", rej)
	}
	b, _ := os.ReadFile(ap)
	if !strings.Contains(string(b), `"decision":"shed"`) {
		t.Fatalf("audit log lacks the shed decision:\n%s", b)
	}
	t.Logf("second request shed with 503 in %v while the only slot was busy; succeeded after release", el.Round(time.Microsecond))
}

func TestMaxConcurrentDefaultsToNumCPU(t *testing.T) {
	srv, _, _ := newInternal(t, 0)
	if srv.MaxConcurrent() < 1 {
		t.Fatalf("default MaxConcurrent = %d", srv.MaxConcurrent())
	}
	if _, err := New(Config{MaxConcurrent: -1}); err == nil {
		t.Fatal("negative MaxConcurrent accepted")
	}
}

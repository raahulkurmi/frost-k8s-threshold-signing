package coordinator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/wire"
)

// priorityRefusal answers exactly as a signer's priority stage does (N76):
// 503 {"error":"overloaded"} with the admission level header.
func priorityRefusal() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(wire.AdmissionLevelHeader, "32768")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(wire.ErrorResponse{Error: "overloaded", Reason: "signer 1: priority below admission level 32768 (admitted fraction 0.500)"})
	})
}

// TestPriorityRefusalNeverTripsBreaker (N76): priority refusals are 503s, not
// invalid shares or failed combines. Neither 2 refusing signers (tokens still
// issued) nor 3 (every request fails, more often than FallbackAfter) marks a
// suspect or switches to strict.
func TestPriorityRefusalNeverTripsBreaker(t *testing.T) {
	for _, refusing := range []int{2, 3} {
		c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
			if id <= refusing {
				return priorityRefusal()
			}
			return h
		}})
		co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 5 * time.Second, Strategy: coordinator.Optimistic, QuorumAbort: true,
			Breaker: coordinator.BreakerConfig{FallbackAfter: 2, FallbackWindow: time.Minute}})
		ok, failed := 0, 0
		for i := 0; i < 8; i++ {
			if _, err := co.Sign(context.Background(), claims(t)); err != nil {
				failed++
			} else {
				ok++
			}
		}
		st := co.Stats()
		if st.SuspectMarks != 0 || st.FallbackActivations != 0 || st.FailedCombines != 0 || len(st.Suspects) != 0 || !st.StrictFallbackUntil.IsZero() {
			t.Fatalf("%d refusing signers tripped the breaker: %+v", refusing, st)
		}
		if refusing == 2 && ok != 8 || refusing == 3 && failed != 8 {
			t.Fatalf("%d refusing signers: %d ok, %d failed", refusing, ok, failed)
		}
		t.Logf("%d signers refusing on priority: %d tokens, %d failures; breaker untouched (%+v)", refusing, ok, failed, st)
	}
}

// TestRetryGetsNewRequestID (N76 addition 2): each Sign call, including a
// kubelet retry of the same TokenRequest (same claims), reaches the signers
// with a new request_id, so a refused request is re-drawn at every retry.
func TestRetryGetsNewRequestID(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var req wire.SignShareRequest
			_ = json.Unmarshal(body, &req)
			if id == 1 {
				mu.Lock()
				seen[req.RequestID] = true
				mu.Unlock()
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			h.ServeHTTP(w, r)
		})
	}})
	co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 5 * time.Second, Strategy: coordinator.Optimistic})
	cl := claims(t)
	for i := 0; i < 5; i++ {
		if _, err := co.Sign(context.Background(), cl); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 5 {
		t.Fatalf("5 Sign calls with identical claims reached signer 1 with %d distinct request ids", len(seen))
	}
}

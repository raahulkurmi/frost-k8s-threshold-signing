package coordinator_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/wire"
)

// signWithRogue signs with all 5 signers, signer 2 wrapped by rogue, and
// returns the reason the coordinator recorded for signer 2.
func signWithRogue(t *testing.T, rogue func(h http.Handler) http.Handler) string {
	t.Helper()
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id == 2 {
			return rogue(h)
		}
		return h
	}})
	co := c.NewCoordinator(t, coordinator.Strict, 5*time.Second, nil)
	res, err := co.Sign(context.Background(), claims(t))
	if err != nil {
		t.Fatal(err) // four honest signers remain
	}
	for _, id := range res.Signers {
		if id == 2 {
			t.Fatalf("combined signer 2's response: %v", res.Signers)
		}
	}
	for _, f := range res.Excluded {
		if f.SignerID == 2 {
			return f.Reason
		}
	}
	t.Fatalf("signer 2 not excluded: %+v", res.Excluded)
	return ""
}

// TestResponseRequestIDMustMatch (audit C-4, mutation X4): a response that
// answers a different request (a replayed or misrouted share) is refused by the
// request_id check, before any share verification.
func TestResponseRequestIDMustMatch(t *testing.T) {
	reason := signWithRogue(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			var resp wire.SignShareResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Errorf("decode: %v", err)
			}
			resp.RequestID = "replayed-request-0001"
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	if !strings.Contains(reason, `request_id "replayed-request-0001" does not match`) {
		t.Fatalf("reason %q; want the request_id check", reason)
	}
}

// TestOversizedResponseRejected (audit C-5, mutation X5): a response larger
// than wire.MaxResponseBytes is refused as too large (THREAT_MODEL C1,
// "oversized payload").
func TestOversizedResponseRejected(t *testing.T) {
	reason := signWithRogue(t, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"signer_id":2,"share":{"xi":"` + strings.Repeat("A", wire.MaxResponseBytes) + `"}}`))
		})
	})
	if reason != "response too large" {
		t.Fatalf("reason %q; want \"response too large\"", reason)
	}
}

package coordinator_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/wire"
)

// TestQuorumImpossibleAbortsEarly (N76): when 3 of 5 signers refuse at once and
// the other 2 are slow, the request fails as soon as the third refusal
// arrives (t = 3 is impossible), not at the deadline, and the slow signers'
// requests are cancelled. With NoQuorumAbort the coordinator waits for them.
func TestQuorumImpossibleAbortsEarly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		noAbort bool
	}{{"abort", false}, {"no-abort", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			arrived, cancelled, completed := 0, 0, 0
			slow := func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.ReadAll(r.Body) // net/http detects a client disconnect only after the body is read
					mu.Lock()
					arrived++
					mu.Unlock()
					select {
					case <-time.After(1500 * time.Millisecond):
						mu.Lock()
						completed++
						mu.Unlock()
						w.WriteHeader(http.StatusServiceUnavailable)
					case <-r.Context().Done():
						mu.Lock()
						cancelled++
						mu.Unlock()
					}
				})
			}
			c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
				if id <= 3 {
					return testutil.Overloaded()
				}
				return slow(h)
			}})
			co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 3 * time.Second, Strategy: coordinator.Optimistic, NoQuorumAbort: tc.noAbort})
			start := time.Now()
			_, err := co.Sign(context.Background(), claims(t))
			el := time.Since(start)
			var te *coordinator.ThresholdError
			if !errors.As(err, &te) {
				t.Fatalf("err = %v, want ThresholdError", err)
			}
			if tc.noAbort {
				if el < 1400*time.Millisecond || co.Stats().QuorumAborts != 0 {
					t.Fatalf("no-abort: returned after %v with %d quorum aborts; want it to wait for the slow signers", el, co.Stats().QuorumAborts)
				}
				t.Logf("no-abort: failed after %v (waited for the slow signers)", el.Round(time.Millisecond))
				return
			}
			if el > 500*time.Millisecond {
				t.Fatalf("abort: returned after %v, want well before the slow signers (1.5 s)", el)
			}
			if n := co.Stats().QuorumAborts; n != 1 {
				t.Fatalf("QuorumAborts = %d, want 1", n)
			}
			// A slow signer either never receives the request (cancelled in
			// flight) or sees it cancelled; none may run it to completion.
			time.Sleep(2 * time.Second)
			mu.Lock()
			a, cn, cm := arrived, cancelled, completed
			mu.Unlock()
			if cm != 0 || cn != a {
				t.Fatalf("slow signers: %d requests arrived, %d cancelled, %d completed; want none completed", a, cn, cm)
			}
			t.Logf("abort: failed after %v; slow signers: %d of 2 requests arrived, all cancelled, none completed", el.Round(time.Millisecond), a)
		})
	}
}

// TestQuorumAbortStillSignsWithTwoRefusals: 2 refusals leave t = 3 possible;
// the abort must not fire and the token is issued.
func TestQuorumAbortStillSignsWithTwoRefusals(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id <= 2 {
			return testutil.Overloaded()
		}
		return h
	}})
	for _, s := range []coordinator.Strategy{coordinator.Optimistic, coordinator.Strict} {
		co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 5 * time.Second, Strategy: s})
		cl := claims(t)
		res, err := co.Sign(context.Background(), cl)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if _, err := testutil.VerifyRS256(token(res, cl), c.Fx.Meta.PublicKey); err != nil {
			t.Fatalf("%s: token does not verify: %v", s, err)
		}
		if n := co.Stats().QuorumAborts; n != 0 {
			t.Fatalf("%s: QuorumAborts = %d with 2 refusals", s, n)
		}
	}
}

// refusesFor reports whether signer id refuses request reqID in the
// simulation: an independent 40 % draw per (signer, request), a stand-in for
// uncoordinated per-signer shedding.
func refusesFor(id int, reqID string) bool {
	h := sha256.Sum256([]byte{byte(id), '/'})
	h = sha256.Sum256(append(h[:], reqID...))
	return h[0] < 102 // 102/256 ≈ 0.40
}

// TestQuorumAbortReducesWastedSharesSimulation (N76, LOCAL SIMULATION, not a
// measurement): each signer refuses 40 % of requests independently and at
// once (uncoordinated shedding); a signer that admits a request waits 300 ms
// (its queue) before computing the share, unless the request is cancelled
// first. A share computed for a request that then fails is wasted. With the
// quorum-impossible abort the coordinator gives up at the third refusal and
// the admitting signers drop the request while it waits, so (almost) no
// shares are wasted; without it they compute and waste them.
func TestQuorumAbortReducesWastedSharesSimulation(t *testing.T) {
	run := func(noAbort bool) (requests, failed, computed, wasted int) {
		var mu sync.Mutex
		perReq := map[string]int{}
		wrap := func(id int, h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var req wire.SignShareRequest
				_ = json.Unmarshal(body, &req)
				if refusesFor(id, req.RequestID) {
					testutil.Overloaded().ServeHTTP(w, r)
					return
				}
				select { // queued behind other work
				case <-time.After(300 * time.Millisecond):
				case <-r.Context().Done():
					return // dropped before computing
				}
				rec := httptest.NewRecorder()
				r.Body = io.NopCloser(bytes.NewReader(body))
				h.ServeHTTP(rec, r)
				if rec.Code == http.StatusOK {
					mu.Lock()
					perReq[req.RequestID]++
					mu.Unlock()
				}
				for k, v := range rec.Header() {
					w.Header()[k] = v
				}
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
			})
		}
		c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: wrap})
		co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 3 * time.Second, Strategy: coordinator.Optimistic, NoQuorumAbort: noAbort})
		const n, par = 80, 16
		ok := map[string]bool{}
		var wg sync.WaitGroup
		sem := make(chan struct{}, par)
		for i := 0; i < n; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				res, err := co.Sign(context.Background(), claims(t))
				mu.Lock()
				defer mu.Unlock()
				requests++
				if err != nil {
					failed++
					return
				}
				ok[res.RequestID] = true
			}()
		}
		wg.Wait()
		time.Sleep(500 * time.Millisecond) // let admitting signers of aborted requests finish or drop
		mu.Lock()
		defer mu.Unlock()
		for id, k := range perReq {
			computed += k
			if !ok[id] {
				wasted += k
			}
		}
		return
	}
	nr, nf, nc, nw := run(true)
	ar, af, ac, aw := run(false)
	t.Logf("LOCAL SIMULATION (40%% independent refusals, 300 ms queue): without abort: %d requests, %d failed, %d shares computed, %d wasted on failed requests; with abort: %d requests, %d failed, %d computed, %d wasted", nr, nf, nc, nw, ar, af, ac, aw)
	if nf == 0 || af == 0 {
		t.Fatalf("simulation produced no failed requests (without %d, with %d); the refusal draw is broken", nf, af)
	}
	if nw == 0 {
		t.Fatal("without the abort no share was wasted; the simulation does not exercise the problem")
	}
	if aw*4 > nw {
		t.Fatalf("with the abort %d shares were wasted vs %d without; want at most a quarter", aw, nw)
	}
}

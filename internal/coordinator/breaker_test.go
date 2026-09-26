package coordinator_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/testutil"
)

// signOK signs once and requires a token that verifies with the group key.
func signOK(t *testing.T, c *testutil.Cluster, co *coordinator.Coordinator) *coordinator.Result {
	t.Helper()
	cl := claims(t)
	res, err := co.Sign(context.Background(), cl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.VerifyRS256(token(res, cl), c.Fx.Meta.PublicKey); err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	return res
}

// untilSuspect signs until the breaker has marked a signer suspect (the first
// optimistic combine that included the corrupt share failed).
func untilSuspect(t *testing.T, c *testutil.Cluster, co *coordinator.Coordinator) *coordinator.Result {
	t.Helper()
	for i := 0; i < 60; i++ {
		res := signOK(t, c, co)
		if co.Stats().SuspectMarks > 0 {
			return res
		}
	}
	t.Fatal("breaker never marked the corrupt signer suspect in 60 requests")
	return nil
}

func corrupt(ids ...int) func(int, http.Handler) http.Handler {
	return func(id int, h http.Handler) http.Handler {
		if slices.Contains(ids, id) {
			return testutil.CorruptShare(h)
		}
		return h
	}
}

// TestStrictVerifiesUntilT (c2, N65): with all signers honest and fan-out all,
// strict verifies exactly t shares per token, not n.
func TestStrictVerifiesUntilT(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 5 * time.Second, Strategy: coordinator.Strict, Fanout: coordinator.FanoutAll})
	const n = 12
	for i := 0; i < n; i++ {
		if res := signOK(t, c, co); res.Contacted != 5 {
			t.Fatalf("contacted %d, want 5", res.Contacted)
		}
	}
	// A late share may still be arriving; its verification is skipped either way.
	time.Sleep(200 * time.Millisecond)
	if got := co.Stats().ShareVerifications; got != 3*n {
		t.Fatalf("strict verified %d shares for %d tokens, want exactly %d (t per token)", got, n, 3*n)
	}
	t.Logf("strict, fan-out all, 5 honest signers: %d tokens, %d share verifications (t=3 each; before N65: up to 5 each)", n, 3*n)
}

// TestBreakerTripMarksSuspect (N65): under optimistic, the first combine that
// includes a corrupt share fails; the share is verified, excluded, attributed,
// and its signer becomes a suspect. The token is still issued.
func TestBreakerTripMarksSuspect(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: corrupt(1)})
	var logs testutil.LogBuffer
	co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 5 * time.Second, Strategy: coordinator.Optimistic, Logger: logs.Logger()})
	res := untilSuspect(t, c, co)
	st := co.Stats()
	if !slices.Equal(st.Suspects, []int{1}) || st.SuspectMarks != 1 || st.FailedCombines != 1 {
		t.Fatalf("stats %+v, want suspects [1], 1 mark, 1 failed combine", st)
	}
	if slices.Contains(res.Signers, 1) || !slices.ContainsFunc(res.Excluded, func(f coordinator.SignerFailure) bool {
		return f.SignerID == 1 && strings.Contains(f.Reason, "invalid signature share")
	}) {
		t.Fatalf("combined %v excluded %+v: signer 1 not excluded as invalid", res.Signers, res.Excluded)
	}
	l := logs.String()
	if !strings.Contains(l, `"msg":"signer marked suspect: its shares are verified before combining"`) || !strings.Contains(l, `"signer_id":1`) {
		t.Fatalf("suspect mark not logged:\n%s", l)
	}
	t.Logf("tripped: %+v; combined %v", st, res.Signers)
}

// TestBreakerWorkBound (N65): a persistently corrupt signer costs one failed
// combine (and at most n share verifications) once, then at most ONE share
// verification per token for the whole cooldown; strict would cost t per token.
func TestBreakerWorkBound(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: corrupt(1)})
	co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 5 * time.Second, Strategy: coordinator.Optimistic,
		Breaker: coordinator.BreakerConfig{SuspectCooldown: time.Hour, FallbackAfter: 1000}})
	untilSuspect(t, c, co)
	first := co.Stats().ShareVerifications
	if first > 5 {
		t.Fatalf("the tripping request verified %d shares, want <= n=5", first)
	}
	const n = 30
	for i := 0; i < n; i++ {
		before := co.Stats().ShareVerifications
		signOK(t, c, co)
		if d := co.Stats().ShareVerifications - before; d > 1 {
			t.Fatalf("token %d cost %d share verifications with signer 1 suspect, want <= 1", i, d)
		}
	}
	time.Sleep(200 * time.Millisecond)
	st := co.Stats()
	if st.FailedCombines != 1 {
		t.Fatalf("failed combines %d, want 1: a suspect must not cause another", st.FailedCombines)
	}
	if total := st.ShareVerifications; total > first+n {
		t.Fatalf("total share verifications %d > bound %d", total, first+n)
	}
	t.Logf("corrupt signer 1: 1 failed combine; %d verifications in the tripping request, %d over the next %d tokens (bound %d; strict would verify >= %d)",
		first, st.ShareVerifications-first, n, n, 3*n)
}

// TestBreakerRecovery (N65): while suspect, a signer's (now valid) share is
// verified before it is combined; after the cooldown it is combined unverified
// again, with no further failed combine.
func TestBreakerRecovery(t *testing.T) {
	var bad atomic.Bool
	bad.Store(true)
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id == 1 {
			return testutil.CorruptShareIf(&bad, h)
		}
		return h
	}})
	const cool = 1500 * time.Millisecond
	co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 5 * time.Second, Strategy: coordinator.Optimistic,
		Breaker: coordinator.BreakerConfig{SuspectCooldown: cool, FallbackAfter: 1000}}, 1, 2, 3, 4)
	untilSuspect(t, c, co)
	tripped := time.Now()
	bad.Store(false) // signer 1 recovers

	sawVerified := false
	for i := 0; i < 20 && time.Since(tripped) < cool-300*time.Millisecond; i++ {
		before := co.Stats().ShareVerifications
		res := signOK(t, c, co)
		d := co.Stats().ShareVerifications - before
		if slices.Contains(res.Signers, 1) {
			if d != 1 {
				t.Fatalf("during the cooldown signer 1's share was combined after %d verifications, want exactly 1", d)
			}
			sawVerified = true
			break
		}
		if d > 1 {
			t.Fatalf("during the cooldown a token cost %d verifications, want <= 1", d)
		}
	}
	if !sawVerified {
		t.Fatal("signer 1's share was never combined during the cooldown")
	}

	time.Sleep(time.Until(tripped.Add(cool + 100*time.Millisecond)))
	if s := co.Stats().Suspects; len(s) != 0 {
		t.Fatalf("suspects %v after the cooldown, want none", s)
	}
	for i := 0; i < 30; i++ {
		before := co.Stats().ShareVerifications
		res := signOK(t, c, co)
		if slices.Contains(res.Signers, 1) {
			if d := co.Stats().ShareVerifications - before; d != 0 {
				t.Fatalf("after the cooldown signer 1's share cost %d verifications, want 0 (fast path)", d)
			}
			if f := co.Stats().FailedCombines; f != 1 {
				t.Fatalf("failed combines %d, want 1", f)
			}
			t.Logf("recovered: signer 1 combined unverified after the cooldown (token %d)", i)
			return
		}
	}
	t.Fatal("signer 1's share was never combined after the cooldown")
}

// TestBreakerFallbackToStrict (N65): FallbackAfter failed optimistic combines
// switch the coordinator to strict (verify-until-t) for the cooldown; no
// further optimistic combines are attempted.
func TestBreakerFallbackToStrict(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: corrupt(1)})
	var logs testutil.LogBuffer
	co := c.NewCoordinatorWith(t, coordinator.Config{Deadline: 5 * time.Second, Strategy: coordinator.Optimistic, Logger: logs.Logger(),
		Breaker: coordinator.BreakerConfig{FallbackAfter: 1, FallbackCooldown: time.Hour}})
	untilSuspect(t, c, co)
	st := co.Stats()
	if st.FallbackActivations != 1 || !st.StrictFallbackUntil.After(time.Now()) {
		t.Fatalf("stats %+v: strict fallback not active after the first failed combine", st)
	}
	for i := 0; i < 5; i++ {
		before := co.Stats().ShareVerifications
		signOK(t, c, co)
		if d := co.Stats().ShareVerifications - before; d < 3 || d > 5 {
			t.Fatalf("token %d under strict fallback cost %d verifications, want 3..5", i, d)
		}
	}
	if f := co.Stats().FailedCombines; f != 1 {
		t.Fatalf("failed combines %d under strict fallback, want 1", f)
	}
	if !strings.Contains(logs.String(), `"strategy_effective":"strict"`) {
		t.Fatal("log does not show strategy_effective=strict")
	}
}

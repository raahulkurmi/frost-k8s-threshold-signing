package coordinator_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/testutil"
)

// TestHedgedContactsTPlusOneAndRotates (N46c): with every signer healthy and
// fast, hedged fan-out contacts exactly t+1 = 4 signers per token, and the
// rotating start spreads that load over all 5.
func TestHedgedContactsTPlusOneAndRotates(t *testing.T) {
	var k testutil.Counting
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: k.Wrap})
	co := c.NewCoordinatorFanout(t, coordinator.FanoutHedged, 2*time.Second, 5*time.Second, nil)
	const reqs = 20
	for i := 0; i < reqs; i++ {
		cl := claims(t)
		res, err := co.Sign(context.Background(), cl)
		if err != nil {
			t.Fatal(err)
		}
		if res.Contacted != 4 {
			t.Fatalf("request %d contacted %d signers, want 4", i, res.Contacted)
		}
		if _, err := testutil.VerifyRS256(token(res, cl), c.Fx.Meta.PublicKey); err != nil {
			t.Fatalf("request %d: token does not verify: %v", i, err)
		}
	}
	counts := k.Counts()
	total := 0
	for id := 1; id <= 5; id++ {
		if counts[id] == 0 {
			t.Fatalf("signer %d never contacted: %v", id, counts)
		}
		total += counts[id]
	}
	if total != 4*reqs {
		t.Fatalf("total sign-share requests %d, want %d (4 per token)", total, 4*reqs)
	}
	t.Logf("hedged: %d tokens -> %d signer requests (4 per token); per signer %v", reqs, total, counts)

	var ka testutil.Counting
	ca := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: ka.Wrap})
	coAll := ca.NewCoordinatorFanout(t, coordinator.FanoutAll, 0, 5*time.Second, nil)
	for i := 0; i < reqs; i++ {
		if _, err := coAll.Sign(context.Background(), claims(t)); err != nil {
			t.Fatal(err)
		}
	}
	all := 0
	for _, n := range ka.Counts() {
		all += n
	}
	if all != 5*reqs {
		t.Fatalf("all: %d signer requests, want %d", all, 5*reqs)
	}
	t.Logf("all:    %d tokens -> %d signer requests (5 per token)", reqs, all)
}

// TestHedgedFastFailureHedgesImmediately (N46b/c): a 503 from a contacted
// signer makes the coordinator contact the rest at once, long before the
// hedge delay, and the token is still issued.
func TestHedgedFastFailureHedgesImmediately(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id <= 2 {
			return testutil.Overloaded()
		}
		return h
	}})
	const hedge = 3 * time.Second
	co := c.NewCoordinatorFanout(t, coordinator.FanoutHedged, hedge, 10*time.Second, nil)
	for i := 0; i < 5; i++ { // every rotation includes signer 1 or 2 in the first four
		start := time.Now()
		res, err := co.Sign(context.Background(), claims(t))
		el := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		if el > hedge/2 {
			t.Fatalf("request %d took %v: waited for the hedge delay instead of hedging on the 503", i, el)
		}
		for _, f := range res.Excluded {
			if !strings.Contains(f.Reason, "HTTP 503 overloaded") {
				t.Fatalf("unexpected failure %+v", f)
			}
		}
		t.Logf("request %d: %v, contacted %d, combined %v, excluded %d (503)", i, el.Round(time.Millisecond), res.Contacted, res.Signers, len(res.Excluded))
	}
}

func TestHedgedBelowThresholdFails(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id >= 3 {
			return testutil.Overloaded()
		}
		return h
	}})
	co := c.NewCoordinatorFanout(t, coordinator.FanoutHedged, time.Second, 5*time.Second, nil)
	res, err := co.Sign(context.Background(), claims(t))
	var te *coordinator.ThresholdError
	if !errors.As(err, &te) || res != nil || te.Valid != 2 {
		t.Fatalf("res=%v err=%v", res, err)
	}
	t.Log(err)
}

// TestOverloadedIsFastFailureInAllMode (N46b): 503s are counted as failures
// immediately; signing proceeds with the healthy signers without waiting.
func TestOverloadedIsFastFailureInAllMode(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id == 1 || id == 2 {
			return testutil.Overloaded()
		}
		return h
	}})
	co := c.NewCoordinatorFanout(t, coordinator.FanoutAll, 0, 5*time.Second, nil)
	start := time.Now()
	res, err := co.Sign(context.Background(), claims(t))
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("took %v", el)
	}
	if len(res.Signers) != 3 || res.Signers[0] != 3 {
		t.Fatalf("combined %v, want [3 4 5]", res.Signers)
	}
}

func TestFanoutConfigValidation(t *testing.T) {
	fx := testutil.Key(t)
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	eps := c.Endpoints(t)
	if _, err := coordinator.New(coordinator.Config{Meta: fx.Meta, Endpoints: eps, Deadline: time.Second, Strategy: coordinator.Strict, Fanout: "some"}); err == nil {
		t.Error("unknown fanout accepted")
	}
	if _, err := coordinator.New(coordinator.Config{Meta: fx.Meta, Endpoints: eps, Deadline: time.Second, Strategy: coordinator.Strict, Fanout: coordinator.FanoutHedged}); err == nil {
		t.Error("hedged without HedgeDelay accepted")
	}
}

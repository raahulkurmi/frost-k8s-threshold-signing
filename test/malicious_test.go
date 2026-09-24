//go:build testmalicious

package test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/testutil"
)

// T5 (I7): signers built with -tags testmalicious return corrupted shares.
// One malicious signer: excluded, attributed by ID in the result and the
// logs, signing succeeds with 3 honest shares. Three: signing fails.
func TestMaliciousSignerExcluded(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	t.Cleanup(func() { signer.SetMalicious() })
	for _, st := range []coordinator.Strategy{coordinator.Strict, coordinator.Optimistic} {
		t.Run(string(st)+"/one malicious", func(t *testing.T) {
			// Signer 2 is malicious; restrict to {1,2,3,4} so it is always
			// among the first t candidates often enough to exercise optimistic.
			signer.SetMalicious(2)
			var logs testutil.LogBuffer
			co := c.NewCoordinator(t, st, 5*time.Second, logs.Logger(), 1, 2, 3, 4)
			claims := saClaims(t)
			var res *coordinator.Result
			var err error
			for i := 0; i < 30; i++ {
				if res, err = co.Sign(context.Background(), claims); err != nil {
					t.Fatal(err)
				}
				if len(res.Excluded) > 0 {
					break
				}
			}
			if len(res.Excluded) != 1 || res.Excluded[0].SignerID != 2 {
				t.Fatalf("excluded %+v, want signer 2", res.Excluded)
			}
			for _, id := range res.Signers {
				if id == 2 {
					t.Fatal("malicious share combined")
				}
			}
			if _, err := testutil.VerifyRS256(res.Header+"."+claims+"."+res.Signature, c.Fx.Meta.PublicKey); err != nil {
				t.Fatal(err)
			}
			l := logs.String()
			if !strings.Contains(l, `"msg":"excluded invalid signature share"`) || !strings.Contains(l, `"signer_id":2`) {
				t.Fatalf("logs do not attribute signer 2:\n%s", l)
			}
			t.Logf("combined %v, excluded %+v; log attributes signer_id 2", res.Signers, res.Excluded)
		})
		t.Run(string(st)+"/three malicious", func(t *testing.T) {
			signer.SetMalicious(1, 2, 3)
			co := c.NewCoordinator(t, st, 5*time.Second, nil)
			res, err := co.Sign(context.Background(), saClaims(t))
			var te *coordinator.ThresholdError
			if !errors.As(err, &te) || res != nil || te.Valid != 2 {
				t.Fatalf("res=%v err=%v", res, err)
			}
			for _, id := range []int{1, 2, 3} {
				if !strings.Contains(err.Error(), "signer-"+string(rune('0'+id))+": invalid signature share") {
					t.Fatalf("error does not attribute signer %d: %v", id, err)
				}
			}
			t.Log(err)
		})
	}
}

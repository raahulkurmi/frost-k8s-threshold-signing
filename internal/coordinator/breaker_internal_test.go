package coordinator

import (
	"testing"
	"time"
)

// Breaker logic with a fake clock (N65): suspicion expires after the cooldown;
// the strict fallback activates only when FallbackAfter failed combines fall
// inside FallbackWindow, and ends after FallbackCooldown.
func TestBreakerSuspectCooldown(t *testing.T) {
	cfg, _ := BreakerConfig{SuspectCooldown: time.Minute}.withDefaults()
	b := newBreaker(cfg)
	t0 := time.Unix(1_800_000_000, 0)
	if newly, _ := b.strike(1, t0); !newly {
		t.Fatal("first strike not reported as new")
	}
	if newly, _ := b.strike(1, t0.Add(time.Second)); newly {
		t.Fatal("strike of a current suspect reported as new")
	}
	if !b.suspects(t0.Add(30 * time.Second))[1] {
		t.Fatal("signer 1 not a suspect inside the cooldown")
	}
	if b.suspects(t0.Add(time.Second + time.Minute))[1] {
		t.Fatal("signer 1 still a suspect after the cooldown")
	}
	if newly, _ := b.strike(1, t0.Add(2*time.Minute)); !newly {
		t.Fatal("strike after expiry not reported as new")
	}
}

func TestBreakerFallbackWindow(t *testing.T) {
	cfg, _ := BreakerConfig{FallbackAfter: 3, FallbackWindow: time.Minute, FallbackCooldown: 10 * time.Minute}.withDefaults()
	t0 := time.Unix(1_800_000_000, 0)

	b := newBreaker(cfg) // 3 failures spread wider than the window: no fallback
	for _, d := range []time.Duration{0, 61 * time.Second, 122 * time.Second} {
		if on, _ := b.failedCombine(t0.Add(d)); on {
			t.Fatalf("fallback activated by failures %v apart", 61*time.Second)
		}
	}
	if b.strictActive(t0.Add(123 * time.Second)) {
		t.Fatal("strict active without 3 failures in the window")
	}

	b = newBreaker(cfg) // 3 failures inside the window: fallback for the cooldown
	b.failedCombine(t0)
	b.failedCombine(t0.Add(10 * time.Second))
	on, until := b.failedCombine(t0.Add(20 * time.Second))
	if !on || !until.Equal(t0.Add(20*time.Second+10*time.Minute)) {
		t.Fatalf("third failure in the window: activated=%v until=%v", on, until)
	}
	if !b.strictActive(t0.Add(21*time.Second)) || b.strictActive(until) {
		t.Fatal("strict fallback not active exactly until the cooldown ends")
	}
}

func TestBreakerConfigValidation(t *testing.T) {
	for _, bad := range []BreakerConfig{{SuspectCooldown: -1}, {FallbackAfter: -1}, {FallbackWindow: -time.Second}, {FallbackCooldown: -time.Second}} {
		if _, err := bad.withDefaults(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	d, err := BreakerConfig{}.withDefaults()
	if err != nil || d.SuspectCooldown != 10*time.Minute || d.FallbackAfter != 3 || d.FallbackWindow != time.Minute || d.FallbackCooldown != 10*time.Minute {
		t.Fatalf("defaults %+v, %v", d, err)
	}
}

// verifyGate (c2): at most t verifications start while none fail; a waiting
// share proceeds when one fails; once t are valid, later shares are skipped;
// close releases waiters.
func TestVerifyGate(t *testing.T) {
	g := newVerifyGate(3)
	for i := 0; i < 3; i++ {
		if !g.acquire() {
			t.Fatalf("acquire %d refused", i)
		}
	}
	got := make(chan bool, 1)
	go func() { got <- g.acquire() }()
	select {
	case <-got:
		t.Fatal("4th verification started while 3 were in flight")
	case <-time.After(50 * time.Millisecond):
	}
	g.release(false) // one share was invalid: the waiting share may proceed
	if ok := <-got; !ok {
		t.Fatal("waiting share not released after a failed verification")
	}
	g.release(true)
	g.release(true)
	g.release(true)
	if g.acquire() {
		t.Fatal("share verified although 3 were already valid")
	}

	g2 := newVerifyGate(1)
	g2.acquire()
	go func() { got <- g2.acquire() }()
	time.Sleep(20 * time.Millisecond)
	g2.close()
	if ok := <-got; ok {
		t.Fatal("waiter not released as skipped on close")
	}
}

package coordinator

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// BreakerConfig bounds the extra work misbehaving signers can cause under the
// optimistic strategy (NOTES N65). Zero values take the defaults.
//
// Optimistic combines t shares without verifying them and verifies only the
// final signature. A bad share makes that combine fail, which costs a failed
// join, up to n share verifications and a second join. To bound this:
//   - a signer whose share fails verification becomes a SUSPECT for
//     SuspectCooldown: its shares are verified individually before they may be
//     combined, so each misbehaving signer causes at most one failed combine
//     per SuspectCooldown;
//   - FallbackAfter failed optimistic combines (any cause) within
//     FallbackWindow switch the coordinator to strict for FallbackCooldown.
//
// Unforgeability does not depend on any of this: both strategies verify the
// combined signature against the group key before returning it.
type BreakerConfig struct {
	SuspectCooldown  time.Duration // default 10m
	FallbackAfter    int           // default 3
	FallbackWindow   time.Duration // default 1m
	FallbackCooldown time.Duration // default 10m
}

func (b BreakerConfig) withDefaults() (BreakerConfig, error) {
	if b.SuspectCooldown == 0 {
		b.SuspectCooldown = 10 * time.Minute
	}
	if b.FallbackAfter == 0 {
		b.FallbackAfter = 3
	}
	if b.FallbackWindow == 0 {
		b.FallbackWindow = time.Minute
	}
	if b.FallbackCooldown == 0 {
		b.FallbackCooldown = 10 * time.Minute
	}
	if b.SuspectCooldown < 0 || b.FallbackAfter < 1 || b.FallbackWindow < 0 || b.FallbackCooldown < 0 {
		return b, errors.New("coordinator: breaker durations must be > 0 and FallbackAfter >= 1")
	}
	return b, nil
}

// breaker is the shared state behind BreakerConfig. Safe for concurrent use.
type breaker struct {
	cfg          BreakerConfig
	mu           sync.Mutex
	suspectUntil map[int]time.Time
	combineFails []time.Time // failed optimistic combines inside the window
	strictUntil  time.Time
}

func newBreaker(cfg BreakerConfig) *breaker {
	return &breaker{cfg: cfg, suspectUntil: map[int]time.Time{}}
}

// suspects returns the signer IDs under suspicion at now.
func (b *breaker) suspects(now time.Time) map[int]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[int]bool{}
	for id, until := range b.suspectUntil {
		if now.Before(until) {
			out[id] = true
		} else {
			delete(b.suspectUntil, id)
		}
	}
	return out
}

// strike marks id a suspect until now+SuspectCooldown. newly reports whether
// it was not already a suspect.
func (b *breaker) strike(id int, now time.Time) (newly bool, until time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	prev, ok := b.suspectUntil[id]
	newly = !ok || !now.Before(prev)
	until = now.Add(b.cfg.SuspectCooldown)
	b.suspectUntil[id] = until
	return newly, until
}

// failedCombine records one failed optimistic combine. activated reports
// whether this switched the coordinator to strict (until strictUntil).
func (b *breaker) failedCombine(now time.Time) (activated bool, until time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := b.combineFails[:0]
	for _, t := range b.combineFails {
		if now.Sub(t) < b.cfg.FallbackWindow {
			keep = append(keep, t)
		}
	}
	b.combineFails = append(keep, now)
	if len(b.combineFails) >= b.cfg.FallbackAfter && !now.Before(b.strictUntil) {
		b.strictUntil = now.Add(b.cfg.FallbackCooldown)
		b.combineFails = b.combineFails[:0]
		return true, b.strictUntil
	}
	return false, b.strictUntil
}

// strictActive reports whether the strict fallback is in force at now.
func (b *breaker) strictActive(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return now.Before(b.strictUntil)
}

func (b *breaker) snapshot(now time.Time) (ids []int, strictUntil time.Time) {
	for id := range b.suspects(now) {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	b.mu.Lock()
	defer b.mu.Unlock()
	return ids, b.strictUntil
}

// verifyGate implements verify-until-t for strict verification (NOTES N65):
// a share is verified only while fewer than t shares are valid or being
// verified; when t shares have verified, later arrivals are not verified at
// all (including after Sign has returned). If a verification fails, a waiting
// share proceeds.
type verifyGate struct {
	mu                 sync.Mutex
	cond               *sync.Cond
	t, valid, inflight int
	done               bool
}

func newVerifyGate(t int) *verifyGate {
	g := &verifyGate{t: t}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// acquire blocks until this share may be verified (true) or is not needed (false).
func (g *verifyGate) acquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for !g.done && g.valid < g.t && g.valid+g.inflight >= g.t {
		g.cond.Wait()
	}
	if g.done || g.valid >= g.t {
		return false
	}
	g.inflight++
	return true
}

func (g *verifyGate) release(ok bool) {
	g.mu.Lock()
	g.inflight--
	if ok {
		g.valid++
	}
	g.mu.Unlock()
	g.cond.Broadcast()
}

func (g *verifyGate) close() {
	g.mu.Lock()
	g.done = true
	g.mu.Unlock()
	g.cond.Broadcast()
}

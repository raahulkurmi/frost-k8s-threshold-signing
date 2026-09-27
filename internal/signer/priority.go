package signer

// Priority-consistent admission (NOTES N76, docs/PRIORITY_ADMISSION.md §2A),
// after DAGOR (Zhou et al., SoCC 2018; details from memory, to be verified
// against the paper).
//
// Every signer derives the same priority for a request without coordination:
//
//	p = first 16 bits of HMAC-SHA256(K_prio, "frost-k8s/priority/v1" ‖ 0x00 ‖ uint64be(epoch) ‖ request_id)
//	epoch = floor(iat / 3600)
//
// K_prio is shared by the signers and unknown to the coordinator. The epoch
// comes from the request's own validated iat claim, not from the signer's
// clock, so signers whose clocks straddle an hour boundary still agree.
//
// Each signer admits a request iff p >= L = floor((1 - f) * 2^16), where the
// admitted fraction f adapts per window: an overloaded window (any N48 shed,
// or mean slot wait > Theta x median remaining deadline at arrival)
// multiplies f by (1 - Alpha); any other window adds Beta. Levels differ
// between signers only by their own load, and the admitted sets are nested
// (a stricter signer admits a subset of a laxer one's), so a request is
// either admitted by >= t signers or refused by most of them at once.
//
// Per-client fair share (hardening, §4): while f < 1 and more than one client
// was seen in the previous window, a client (the mTLS SAN coordinator-<k>) is
// refused once it has had FairSlack x (previous window's admissions / clients)
// admissions in the current window.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"
)

// AdmissionConfig tunes priority admission. Zero fields take the defaults
// fixed in docs/PRIORITY_ADMISSION.md before any evaluation run.
type AdmissionConfig struct {
	Window         time.Duration // default 250ms
	WindowArrivals int           // a window also closes after this many arrivals; default 200
	Alpha          float64       // multiplicative decrease when overloaded; default 0.05
	Beta           float64       // additive increase otherwise; default 0.01
	MinFraction    float64       // lower bound of f; default 0.05
	Theta          float64       // overload if mean wait > Theta x median deadline budget; default 0.5
	FairSlack      float64       // fair-share cap multiplier; default 1.25
}

func (c AdmissionConfig) withDefaults() AdmissionConfig {
	if c.Window == 0 {
		c.Window = 250 * time.Millisecond
	}
	if c.WindowArrivals == 0 {
		c.WindowArrivals = 200
	}
	if c.Alpha == 0 {
		c.Alpha = 0.05
	}
	if c.Beta == 0 {
		c.Beta = 0.01
	}
	if c.MinFraction == 0 {
		c.MinFraction = 0.05
	}
	if c.Theta == 0 {
		c.Theta = 0.5
	}
	if c.FairSlack == 0 {
		c.FairSlack = 1.25
	}
	return c
}

const priorityDomain = "frost-k8s/priority/v1"

// Priority returns p for a request: the same at every signer holding key.
func Priority(key []byte, iat int64, requestID string) uint16 {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(priorityDomain))
	m.Write([]byte{0})
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(Epoch(iat)))
	m.Write(e[:])
	m.Write([]byte(requestID))
	return binary.BigEndian.Uint16(m.Sum(nil))
}

// Epoch is the priority epoch of a token issued at iat (unix seconds).
func Epoch(iat int64) int64 {
	if iat < 0 {
		return -1 - (-1-iat)/3600
	}
	return iat / 3600
}

// levelFor maps an admitted fraction to the admission level L.
func levelFor(f float64) int { return int(math.Floor((1 - f) * 65536)) }

type admission struct {
	cfg AdmissionConfig
	key []byte
	id  int
	log *slog.Logger

	mu       sync.Mutex
	f        float64
	winStart time.Time
	arrivals int
	sheds    int // N48 sheds in this window
	waitN    int
	waitSum  time.Duration
	budgets  []time.Duration
	refPrio  int
	refFair  int
	admitted map[string]int
	total    int // admitted by this stage in this window
	clients  map[string]bool
	prevAdm  int
	prevCl   int
}

func newAdmission(id int, key []byte, cfg AdmissionConfig, log *slog.Logger) *admission {
	return &admission{cfg: cfg.withDefaults(), key: key, id: id, log: log, f: 1,
		admitted: map[string]int{}, clients: map[string]bool{}}
}

// admitDecision is the priority stage's verdict.
type admitDecision struct {
	ok       bool
	kind     string // "priority" or "fair_share" when refused
	level    int
	fraction float64
	cap      int
}

// decide runs the priority stage for one arrival.
func (a *admission) decide(now time.Time, p uint16, client string, budget time.Duration) admitDecision {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.roll(now)
	a.arrivals++
	if budget > 0 && len(a.budgets) < 256 {
		a.budgets = append(a.budgets, budget)
	}
	a.clients[client] = true
	d := admitDecision{level: levelFor(a.f), fraction: a.f}
	if int(p) < d.level {
		a.refPrio++
		d.kind = "priority"
		return d
	}
	if a.f < 1 && a.prevCl > 1 {
		d.cap = int(math.Ceil(a.cfg.FairSlack * float64(a.prevAdm) / float64(a.prevCl)))
		if d.cap < 1 {
			d.cap = 1
		}
		if a.admitted[client] >= d.cap {
			a.refFair++
			d.kind = "fair_share"
			return d
		}
	}
	a.admitted[client]++
	a.total++
	d.ok = true
	return d
}

// observeWait records how long an admitted request waited for its slot.
func (a *admission) observeWait(d time.Duration) {
	a.mu.Lock()
	a.waitN++
	a.waitSum += d
	a.mu.Unlock()
}

// observeShed records an N48 shed (queue full, no slot in time).
func (a *admission) observeShed() {
	a.mu.Lock()
	a.sheds++
	a.mu.Unlock()
}

// roll closes the current window if it is over and adapts f. Callers hold mu.
func (a *admission) roll(now time.Time) {
	if a.winStart.IsZero() {
		a.winStart = now
		return
	}
	el := now.Sub(a.winStart)
	if el < a.cfg.Window && a.arrivals < a.cfg.WindowArrivals {
		return
	}
	var med, mean time.Duration
	if len(a.budgets) > 0 {
		b := append([]time.Duration(nil), a.budgets...)
		sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
		med = b[len(b)/2]
	}
	if a.waitN > 0 {
		mean = a.waitSum / time.Duration(a.waitN)
	}
	overloaded := a.sheds > 0 || (a.waitN > 0 && med > 0 && float64(mean) > a.cfg.Theta*float64(med))
	old := a.f
	if overloaded {
		a.f = math.Max(a.cfg.MinFraction, a.f*(1-a.cfg.Alpha))
	} else {
		k := 1.0
		if a.cfg.Window > 0 && el > a.cfg.Window {
			k = math.Floor(float64(el) / float64(a.cfg.Window)) // idle windows count too
		}
		a.f = math.Min(1, a.f+a.cfg.Beta*k)
	}
	if a.log != nil && (a.f != old || a.f < 1) {
		a.log.Info("admission level", "signer_id", a.id, "admitted_fraction", a.f, "level", levelFor(a.f),
			"overloaded", overloaded, "arrivals", a.arrivals, "n48_sheds", a.sheds, "mean_wait_ms", float64(mean.Microseconds())/1000,
			"median_budget_ms", float64(med.Microseconds())/1000, "priority_refused", a.refPrio, "fair_share_refused", a.refFair,
			"clients", len(a.clients), "window_ms", float64(el.Microseconds())/1000)
	}
	a.prevAdm, a.prevCl = a.total, len(a.clients)
	a.winStart = now
	a.arrivals, a.sheds, a.waitN, a.waitSum, a.refPrio, a.refFair, a.total = 0, 0, 0, 0, 0, 0, 0
	a.budgets = a.budgets[:0]
	a.admitted = map[string]int{}
	a.clients = map[string]bool{}
}

func (a *admission) fraction() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.f
}

func (a *admission) setFraction(f float64) {
	a.mu.Lock()
	a.f = f
	a.mu.Unlock()
}

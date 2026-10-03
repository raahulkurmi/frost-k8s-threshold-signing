package signer

// Priority-consistent admission (NOTES N76, N77; docs/PRIORITY_ADMISSION.md
// §2A), after DAGOR (Zhou et al., SoCC 2018, arXiv 1806.04075v3, §4.2).
//
// Every signer derives the same priority p (16 bits) for a request without
// coordination, keyed with K_prio, which the signers share and the coordinator
// does not hold. Two derivations (AdmissionConfig.Mode):
//
//   - stable (default, N77): p from a stable identity in the validated claims,
//     identity = sub ‖ 0x00 ‖ kubernetes.io.pod.uid (sub alone if the token is
//     not pod-bound), so a kubelet retry keeps its priority (DAGOR §4.2.2
//     rejected per-session priority because re-login re-draws it):
//     p = (H(K_prio, identity) + (e mod R) · 2^16/R) mod 2^16, e = ⌊iat / E⌋
//     The base H never changes; every epoch E (default 2 min) all identities
//     rotate by 2^16/R (R = Rotation, default 32), so within an epoch retries
//     keep their priority. At a fixed admission level L an identity is refused
//     for at most ⌈L·R/2^16⌉ consecutive epochs, PROVIDED the admitted band
//     (2^16 − L) is at least one rotation step 2^16/R; otherwise an identity
//     can step over the band forever. The level never exceeds the MinFraction
//     floor, so New requires 2^16/R ≤ the floor's band (R ≥ 1/MinFraction:
//     with the 5 % floor, R = 32). Bound at the floor: 31 epochs (~62 min at
//     E = 2 min); at half admission: 16 epochs.
//   - request (N76, kept for comparison): p = H(K_prio, ⌊iat/3600⌋, request_id);
//     every retry (a new Sign call, a new request_id) is a new draw.
//
// Epochs come from the token's own validated iat, never the signer's clock,
// so signers whose clocks straddle an epoch boundary still agree.
//
// Admission level, DAGOR §4.2.3: a 256-bucket histogram of arrival
// priorities per window (Window or WindowArrivals, §4.1); at the end of a
// window with N arrivals of which N_adm passed the level:
//
//	overloaded:     N_exp = (1 − α) · N_adm   → raise the level until the
//	                                            histogram mass above it ≤ N_exp
//	not overloaded: N_exp = N_adm + β · N     → lower the level until it ≥ N_exp
//
// α and β change the expected NUMBER of admitted requests per window (α of
// the admitted, β of the incoming), not a level percentage. Overload (§4.1
// uses queuing time): any N48 shed, or mean slot wait > Theta × median
// remaining deadline at arrival. The level never exceeds the bucket that
// still admits the top MinFraction of the priority space.
//
// Per-client fair share (N76 hardening): while the level is above 0 and more
// than one client was seen in the previous window, a client (mTLS SAN
// coordinator-<k>) is refused once it has had FairSlack × (previous window's
// admissions / clients) admissions in the current window.

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

// PriorityMode selects how p is derived.
type PriorityMode string

const (
	PriorityStable  PriorityMode = "stable"
	PriorityRequest PriorityMode = "request"
)

// AdmissionConfig tunes priority admission. Zero fields take the defaults
// fixed in docs/PRIORITY_ADMISSION.md before any evaluation run.
type AdmissionConfig struct {
	Mode           PriorityMode  // default stable
	Epoch          time.Duration // stable: priority epoch E; default 2m
	Rotation       int           // stable: epochs per full rotation R (power of two, 2..64, step ≤ the floor's band); default 32
	Window         time.Duration // default 250ms
	WindowArrivals int           // a window also closes after this many arrivals; default 200
	Alpha          float64       // overloaded: expected admissions × (1 − α); default 0.05
	Beta           float64       // otherwise: expected admissions + β × arrivals; default 0.01
	MinFraction    float64       // the top MinFraction of the priority space is always admitted; default 0.05
	Theta          float64       // overload if mean wait > Theta × median deadline budget; default 0.5
	FairSlack      float64       // fair-share cap multiplier; default 1.25
}

func (c AdmissionConfig) withDefaults() AdmissionConfig {
	if c.Mode == "" {
		c.Mode = PriorityStable
	}
	if c.Epoch == 0 {
		c.Epoch = 2 * time.Minute
	}
	if c.Rotation == 0 {
		c.Rotation = 32
	}
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

// ValidRotation reports whether r is an allowed rotation (a power of two in 2..64).
func ValidRotation(r int) bool { return r >= 2 && r <= 64 && r&(r-1) == 0 }

const (
	requestDomain = "frost-k8s/priority/v1"
	stableDomain  = "frost-k8s/priority/stable/v1"
	buckets       = 256
)

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// Epoch is the hourly epoch of the request-ID priority for a token issued at iat.
func Epoch(iat int64) int64 { return floorDiv(iat, 3600) }

// Priority is the request-ID priority (mode request): a fresh draw per request_id.
func Priority(key []byte, iat int64, requestID string) uint16 {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(requestDomain))
	m.Write([]byte{0})
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(Epoch(iat)))
	m.Write(e[:])
	m.Write([]byte(requestID))
	return binary.BigEndian.Uint16(m.Sum(nil))
}

// Identity is the stable priority identity: sub ‖ 0x00 ‖ pod uid, or sub alone.
func Identity(sub, podUID string) string {
	if podUID == "" {
		return sub
	}
	return sub + "\x00" + podUID
}

// StableEpoch is the stable-priority epoch index of a token issued at iat.
func StableEpoch(iat int64, epoch time.Duration) int64 {
	return floorDiv(iat, int64(epoch/time.Second))
}

// StablePriority is the stable-identity priority (mode stable).
func StablePriority(key []byte, iat int64, identity string, epoch time.Duration, rotation int) uint16 {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(stableDomain))
	m.Write([]byte{0})
	m.Write([]byte(identity))
	base := int64(binary.BigEndian.Uint16(m.Sum(nil)))
	r := int64(rotation)
	shift := ((StableEpoch(iat, epoch) % r) + r) % r * (65536 / r)
	return uint16((base + shift) % 65536)
}

// StableWorstCaseEpochs bounds how many consecutive epochs an identity is
// refused at a fixed admission level L (0..65536): ⌈L·R/2^16⌉, valid only if
// the admitted band 2^16 − L is at least one rotation step 2^16/R; otherwise
// it returns -1 (no bound: an identity can step over the band every epoch).
func StableWorstCaseEpochs(level, rotation int) int {
	if 65536-level < 65536/rotation {
		return -1
	}
	return int(math.Ceil(float64(level) * float64(rotation) / 65536))
}

// maxLevelBucket is the highest level bucket the floor allows.
func maxLevelBucket(minFraction float64) int { return int(math.Floor((1 - minFraction) * buckets)) }

// StableRotationOK reports whether rotation R keeps the wait bound at the
// highest level the floor allows.
func StableRotationOK(rotation int, minFraction float64) bool {
	return ValidRotation(rotation) && StableWorstCaseEpochs(maxLevelBucket(minFraction)*256, rotation) >= 0
}

type admission struct {
	cfg   AdmissionConfig
	key   []byte
	id    int
	log   *slog.Logger
	maxLB int

	mu       sync.Mutex
	lb       int // level bucket: admit iff p>>8 >= lb (level L = lb·256)
	winStart time.Time
	hist     [buckets]int
	arrivals int
	nadm     int // arrivals at or above the level this window (DAGOR N_adm)
	sheds    int // N48 sheds in this window
	waitN    int
	waitSum  time.Duration
	budgets  []time.Duration
	refPrio  int
	refFair  int
	admitted map[string]int
	total    int // admitted by this stage (priority and fair share) this window
	clients  map[string]bool
	prevAdm  int
	prevCl   int
}

func newAdmission(id int, key []byte, cfg AdmissionConfig, log *slog.Logger) *admission {
	cfg = cfg.withDefaults()
	return &admission{cfg: cfg, key: key, id: id, log: log, maxLB: maxLevelBucket(cfg.MinFraction),
		admitted: map[string]int{}, clients: map[string]bool{}}
}

// priority derives p for a validated request.
func (a *admission) priority(iat int64, requestID, sub, podUID string) uint16 {
	if a.cfg.Mode == PriorityRequest {
		return Priority(a.key, iat, requestID)
	}
	return StablePriority(a.key, iat, Identity(sub, podUID), a.cfg.Epoch, a.cfg.Rotation)
}

// admitDecision is the priority stage's verdict.
type admitDecision struct {
	ok       bool
	kind     string // "priority" or "fair_share" when refused
	level    int
	fraction float64
	cap      int
}

func (a *admission) fractionLocked() float64 { return 1 - float64(a.lb)/buckets }

// decide runs the priority stage for one arrival.
func (a *admission) decide(now time.Time, p uint16, client string, budget time.Duration) admitDecision {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.roll(now)
	a.arrivals++
	a.hist[p>>8]++
	if budget > 0 && len(a.budgets) < 256 {
		a.budgets = append(a.budgets, budget)
	}
	a.clients[client] = true
	d := admitDecision{level: a.lb * 256, fraction: a.fractionLocked()}
	if int(p>>8) < a.lb {
		a.refPrio++
		d.kind = "priority"
		return d
	}
	a.nadm++
	if a.lb > 0 && a.prevCl > 1 {
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

// roll closes the current window if it is over and adapts the level
// (DAGOR §4.2.3, UpdateAdmitLevel). Callers hold mu.
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
	old := a.lb
	prefix := float64(a.nadm)
	if overloaded {
		exp := (1 - a.cfg.Alpha) * float64(a.nadm)
		for prefix > exp && a.lb < a.maxLB {
			prefix -= float64(a.hist[a.lb])
			a.lb++
		}
	} else {
		exp := float64(a.nadm) + a.cfg.Beta*float64(a.arrivals)
		for prefix < exp && a.lb > 0 {
			a.lb--
			prefix += float64(a.hist[a.lb])
		}
	}
	if a.log != nil && (a.lb != old || a.lb > 0) {
		a.log.Info("admission level", "signer_id", a.id, "level", a.lb*256, "admitted_fraction", a.fractionLocked(),
			"overloaded", overloaded, "arrivals", a.arrivals, "admitted_by_level", a.nadm, "n48_sheds", a.sheds,
			"mean_wait_ms", float64(mean.Microseconds())/1000, "median_budget_ms", float64(med.Microseconds())/1000,
			"priority_refused", a.refPrio, "fair_share_refused", a.refFair, "clients", len(a.clients),
			"window_ms", float64(el.Microseconds())/1000)
	}
	a.prevAdm, a.prevCl = a.total, len(a.clients)
	a.winStart = now
	a.hist = [buckets]int{}
	a.arrivals, a.nadm, a.sheds, a.waitN, a.waitSum, a.refPrio, a.refFair, a.total = 0, 0, 0, 0, 0, 0, 0, 0
	a.budgets = a.budgets[:0]
	a.admitted = map[string]int{}
	a.clients = map[string]bool{}
}

func (a *admission) fraction() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fractionLocked()
}

// setFraction sets the level to admit the top f of the priority space.
func (a *admission) setFraction(f float64) {
	a.mu.Lock()
	a.lb = int(math.Round((1 - f) * buckets))
	a.mu.Unlock()
}

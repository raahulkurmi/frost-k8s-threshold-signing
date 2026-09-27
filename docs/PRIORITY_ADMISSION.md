# Priority-consistent admission for the signers (design, not implemented)

Status: **DESIGN for review. Nothing here is implemented.** Motivation: the Phase 7C
stress test (NOTES N73, label **stress test**) met the pre-registered rule. At c ≥ 50 goodput
was 0.50–0.76 × peak, and 32–44 % of computed shares went to requests that failed, because
each signer sheds on its own.

Reference: H. Zhou, M. Chen, Q. Lin, Y. Wang, X. She, S. Liu, R. Gu, B. C. Ooi, J. Yang,
"Overload Control for Scaling WeChat Microservices" (DAGOR), ACM SoCC 2018. The DAGOR
facts used below are from that paper; check each against the PDF before quoting it in a
paper:
- overload is detected by the average queuing time of requests, not CPU;
- a request's priority is a business priority plus a user priority; the user priority is a
  hash of the user ID, and the hash function changes periodically;
- each server keeps an admission level and moves it with a histogram of recent
  priorities: shed a little more when overloaded, admit a little more otherwise;
- every service uses the same priority for a request, so a request admitted at one
  service is likely admitted at the next ("subsequent overload");
- collaborative admission: a server piggybacks its level on responses so upstream can drop
  early.

## 1. The problem in this system

A token needs t = 3 valid shares out of n = 5. Under overload each signer's N48 admission
rejects whichever requests are unlucky at that signer: queue full, no slot before the
latest start time, or slot freed too late. The five signers reject **different** requests.

- If each signer admits a fraction *a* of requests independently, a request gets a token
  with probability P[Bin(5, a) ≥ 3]. At a = 0.5 that is 0.50.
- Every request that gets only 1–2 shares wastes them. At a = 0.5, 15/32 ≈ 47 % of requests
  get 1–2 shares: 0.78 wasted shares per request out of 2.5 computed, ≈ 31 % of computed
  shares wasted. That is the size of the 32–44 % measured in N73.
- This is DAGOR's subsequent-overload problem: the request succeeds only if it is admitted
  at t services.

The 7C coordinator makes this worse in one respect. It does **not** abort a request once a
quorum is impossible. After n − t + 1 = 3 refusals it keeps waiting for the other signers
(`internal/coordinator/coordinator.go`, collect loop, which runs until every contacted
signer has answered). Those signers may still compute a share that cannot be used.

## 2. Design

Three parts. A and B are the proposal; C is an optional extension.

### A. Signer side: a consistent priority and an adaptive admission level

**Priority, the same at every signer without coordination.**

    p(req) = first 16 bits of HMAC-SHA256(K_prio, epoch ‖ request_id)
    epoch  = floor(unix_time / 3600)

- `request_id` is the coordinator's 12-byte random ID (`newRequestID`, crypto/rand). It is
  already sent to every signer in the same request and validated (`wire.ValidRequestID`).
  All five signers therefore compute the same p for a request.
- **K_prio** is a 32-byte priority key. The dealer generates it at the key ceremony and
  delivers it to each signer with its share, in the signer's private config. It is
  **never** given to the coordinator (it does not go into `public-meta.json`).
  - It is not a signing secret: leaking it lets a party predict priorities, and nothing
    more (§4).
  - Because the coordinator cannot compute p, it cannot choose request IDs with a high
    priority offline.
- **The epoch** changes the order every hour. As in DAGOR's periodic hash change, no
  request ID keeps its priority. For a single request this hardly matters, since kubelet
  retries use new request IDs.
- **Why not the deadline:** every signer sees the same deadline, so EDF (earliest deadline
  first) would also be consistent. But under overload EDF prefers requests that are about
  to miss their deadline, which DAGOR avoids. The deadline stays a feasibility filter
  (N48), not the priority.
- **Optional priority classes (off by default).** A class can be derived by the signer from
  the payload it already parses, for example kube-system service accounts first. It is
  combined as (class, p), like DAGOR's (business, user) pair. It is off by default because
  the coordinator chooses payloads within policy (§4).

**Admission level.** Each signer keeps an admitted fraction f ∈ [f_min, 1] and admits a
request iff p ≥ L = (1 − f) · 2^16.
- p is uniform because it comes from an HMAC, so a histogram over the 16-bit space is
  unnecessary: f maps directly to L.
- DAGOR needs the histogram because business priorities are not uniform. If priority
  classes are enabled, use a 256-bucket histogram of (class, p) per window, as DAGOR does.

**Overload signal, per window.** A window is W = 250 ms or 200 arrivals, whichever comes
first. It is short because deadlines are 2 s; DAGOR used seconds.
- overloaded ⇔ (N48 sheds in the window > 0) **or** (mean queue wait of requests that got a
  slot > θ · median remaining deadline budget at arrival), with θ = 0.5.
- The wait threshold is tied to the deadline, not fixed like DAGOR's. In the **uncapped**
  7C configuration at c = 50, signer queue waits were ≈ 650 ms against a 2 s deadline, with
  0 errors (N69, N72). A fixed 20 ms threshold would shed there and turn a slow success
  into a failure. With θ = 0.5 the threshold is ≈ 1 s (margin ≈ 1.5×); the no-regression
  test (§5.2) checks this.

**Adjustment, per window.**
- If overloaded: f ← max(f_min, f · (1 − α)).
- Otherwise: f ← min(1, f + β).
- Start values: α = 0.05 and β = 0.01, as DAGOR does (shed fast, admit slowly), and
  f_min = 0.05.
- f and L are logged per window (`admission level` line) so the evaluation can plot them.

**Why this fixes the waste.** Let signer i have level L_i, and let L_(k) be the k-th
smallest level.
- Request p gets a share from exactly the signers with L_i ≤ p, and a token iff p ≥ L_(t),
  the 3rd smallest level. The **admitted sets are nested**: a stricter signer admits a
  subset of what a laxer one admits.
- Shares can be wasted only for requests with L_(1) ≤ p < L_(t). That is a fraction ≤
  (L_(t) − L_(1)) / 2^16 of arrivals, the spread between signers' levels, not a binomial
  lottery.
- Identical signers see the same arrivals under fan-out all, so their levels move together
  and the spread stays small. If one or two signers are slower, only the 3rd most lenient
  level matters: two slow signers raise their own levels without lowering goodput.

**Placement in the signer pipeline** (`internal/signer/signer.go`):

    rate limit → request_id → header → policy → ctx check → [NEW: priority p ≥ L] → N48 admit → allow → RSA

- The check runs after policy, so policy-violating requests are still denied (403) exactly
  as today, and existing tests keep their meaning. Its cost is one HMAC, far below an RSA
  share.
- A priority rejection is audited as decision `shed` with reason
  `priority below admission level`. It returns HTTP 503 kind `overloaded` with the
  headers `X-Frost-Admission-Level: <L>` and `X-Frost-Priority-Rejected: 1`.
- N48 is **unchanged** and still runs after the priority check. It remains the guarantee
  that no share starts when it cannot finish before the deadline. Its sheds are now the
  overload signal and should become rare once f has adapted.
- The queue stays FIFO. A priority-ordered queue would be more consistent within a window,
  but it adds starvation risk inside the queue, and the level already carries the
  consistency. It is recorded as a possible follow-up, not proposed.

### B. Coordinator side: abort when a quorum is impossible

In the collect loop, once the failures make t valid shares impossible (failures > n − t, or
remaining = contacted − failures < t − valid), return the error immediately.
- `defer cancel()` then cancels the outstanding signer requests. A signer whose request is
  still queued drops it without computing: N46/N48 check ctx before RSA, and the audit
  records it as `cancelled`.
- With part A, priority rejections arrive at once (at arrival, before any queueing), while
  admitted requests wait in queues. So the abort usually lands before the 1–2 admitting
  signers reach RSA.
- B is independent of A and useful alone. It is evaluated separately (§5.1).

### C. Optional: collaborative admission (DAGOR's piggyback), not proposed now

DAGOR lets upstream drop requests using the downstream level. Here the coordinator cannot
compute p, because it has no K_prio. Giving it K_prio would allow grinding (§4). What the
coordinator can do without K_prio: when ≥ 3 signers report `X-Frost-Admission-Level` > 0
within the last second, answer quickly for kube-apiserver retries. That is an availability
optimisation with no effect on share waste, so it is left out.

**Out of scope (noted):** fan-out all computes ≈ 5 shares for 3 used, ≈ 39 % surplus even
at c = 10 (N73). Hedging does not remove it under queueing, because the hedge fires (N72).
An overload-aware fan-out (contact exactly t while levels > 0) is a separate lever and is
not part of this design.

## 3. Interactions

| Mechanism | Interaction |
|---|---|
| **N48 deadline-aware admission** | Unchanged and runs after the priority check. It is the only guarantee that no share starts when it cannot finish; the priority level only decides *which* requests reach it. N48 sheds (queue full, no slot before latest start, slot too late) feed the overload signal. |
| **Optimistic default (N65)** | Unchanged. A priority rejection is a signer failure (503) like today's sheds. Optimistic combines the first t well-formed shares; nested admission makes it more likely that a request's admitted signers are ≥ t, or that it is rejected everywhere at once. |
| **Strict / verify-until-t (c2)** | Unchanged; only the set of requests that reach the coordinator's verification changes. |
| **Breaker (suspicion, fallback)** | Unaffected by design. Suspicion strikes are only for returned-but-invalid shares (`strike` at the "excluded invalid signature share" sites). Fallback counts only failed optimistic combines (`failedCombine`). A 503 of any kind is neither, and a test must pin this: a priority 503 never strikes and never counts toward fallback. |
| **Hedged fan-out** | A priority rejection makes the coordinator hedge at once ("signer failed"), as today. Hedging to a signer with the same level cannot help (same p); B's quorum-impossible abort stops that. |
| **Rate limit (policy, 200/s burst 400 per signer)** | Unchanged and checked first. It is **one limiter per signer for all clients**, not per client (`internal/signer/signer.go`, `rate.NewLimiter`). |
| **kube-apiserver / kubelet retries** | A retried TokenRequest gets a new request_id and so a fresh priority. Under sustained overload a pod's token is delayed, not refused forever, as with DAGOR's periodic rehash. |

## 4. Security: can a compromised coordinator abuse priorities?

The adversary is the coordinator (threat model C2), or one of the 3 coordinator replicas. It
chooses request IDs, payloads within policy, deadlines (the signer accepts 1–60000 ms,
`wire.DeadlineHeader`) and its sending rate. It does **not** hold K_prio or any share.

1. **It already controls liveness for its own traffic.** A compromised coordinator can drop
   every request it receives, so priorities give it nothing against its own traffic. The
   question only matters when **honest** traffic shares the signers with it: one
   compromised replica out of 3, or several clusters' coordinators sharing signers.
2. **Without K_prio it cannot pick high priorities offline.** p is an HMAC under a key it
   does not have, so its requests have the same uniform priority distribution as honest
   ones. Under a level f, honest and adversarial requests are admitted with the same
   probability f. Its share of admitted work equals its share of offered load, the same
   **volume** advantage it has today. Today's FIFO plus independent shedding gives the same
   volume advantage but wastes a third of capacity on top.
3. **Online probing does not amplify.** It can learn whether a request ID was admitted from
   the 503 or 200, but every probe uses a rate-limit token, is audited, and consumes the
   probed request_id. Finding a request ID above level L costs 1/f tries on average. So its
   admitted rate stays ≤ f × its sending rate, bounded by the per-signer rate limit.
   Replaying one known-good request_id with other payloads is possible, because p does not
   cover the payload.
   - *Proposed hardening:* compute p over request_id ‖ SHA-256(signing input), and keep a
     per-signer replay cache of request IDs for one deadline (≤ 60 s × 200/s ≤ 12 000
     entries). A reused request_id is then denied (400).
4. **Deadlines:** a long deadline (up to 60 s) keeps adversarial requests queued longer and
   occupies queue positions (max 64). This exists today.
   - *Proposed:* cap the accepted deadline at 2 × the coordinator's configured deadline
     (4 s). The cap is a signer config value.
5. **What bounds it overall.**
   - (i) The per-signer rate limit, shared today by all clients.
   - (ii) Proposed: **per-replica client certificates.** Today all 3 replicas present one
     client certificate (SAN `coordinator`, `scripts/gen-certs.sh`), so a signer cannot tell
     them apart.
   - (iii) With per-replica identities, a **per-client fair share** of the admitted fraction:
     each client's admitted rate is capped at 1/k of the signer's recent admitted rate
     under overload. This bounds one compromised replica to ≈ 1/3 of the capacity.
   - Without (ii)–(iii), the bound is volume share under the global rate limit, as today.
6. **Leak of K_prio.** The attacker could then grind request IDs offline, and its requests
   would always be admitted. Honest requests would be admitted at a rate reduced by its
   volume share, up to starvation if its volume fills the capacity.
   - The bound is again the rate limit and, with (iii), the fair share.
   - Response: rotate K_prio with a new ceremony artefact; it needs no re-dealing of shares.
   - Safety is unaffected: priorities never change *what* is signed, only *when*.
7. **No new signing path.** A priority check can only refuse. It never admits a request that
   policy, rate limit or N48 would refuse, and it adds no fallback signing mode.

## 5. Evaluation plan (pre-registered before any run)

All runs on a freshly provisioned 7C cluster with the same scripts. This requires
re-provisioning, ≈ 1.5 h bring-up at ≈ $0.57/h, with the usual 7C safety rules.

Variants:
- **N48** is today's system.
- **B** is the quorum-impossible abort alone.
- **A+B** is the proposal.

Run order: per run, all variants interleaved and rotated, with a verified switch (kid, mode,
TokenReview) and the variant recorded (signer config hash, coordinator flag) before every
configuration. INVALID + one re-run (N60); chrony-primary clock check before every run.

### 5.1 Stress test (label **stress test (CPU-capped signers CPUQuota=25%, SIGNER_MAX_CONCURRENT=1)**)
- **Setup:** exactly the N73 configuration. T-same-region optimistic, fan-out all, c =
  10/25/50/100/150/200, 3 runs, N=1000 after 100 warm-up, signer CPU and audit capture.
  Variants N48, B, A+B.
- **Per variant and c:** goodput, goodput / peak (peak = that variant's max), errors, computed
  shares per request, wasted-on-failed %, surplus %, sheds by reason (priority vs N48 kinds),
  signer CPU, cgroup `cpu.stat` throttling (§6), and the per-window f/L trace of each signer.
- **Success rule for A+B (fixed now):** at every c ≥ 50, goodput ≥ 0.8 × peak **and**
  wasted-on-failed ≤ 10 %, median of 3 runs.
  - Stated separately: whether B alone meets it.
  - If A+B fails the rule, the design is reported as not effective at these parameters; it
    is not re-tuned and re-run under the same label.

### 5.2 No regression (label **7C configuration, no-regression check**)
- **Setup:** uncapped signers, N48 defaults (`max_concurrent` = 2, `max_queue` = 64).
  T-same-region and T-5-region, optimistic, c = 1/10/20/50, 3 runs. Variants N48 and A+B.
  B0 in the same session as the anchor.
- **Rule (fixed now):** for A+B vs N48 in the same session:
  - goodput within ± 5 %;
  - median latency within ± 5 % or ± 2 ms, whichever is larger;
  - 0 errors;
  - **0 priority rejections** (f stays at 1 at these loads).
  - Any priority rejection at c ≤ 50 is a regression. It means θ is too low for the uncapped
    queueing (§2A).

## 5.3 Separate: "more admission slots" lever (label **inference test (admission slots)**)
This tests N72's inference that the ≈ 70 tokens/s plateau is 2 slots per signer × ≈ 28.6 ms
per share, not CPU. It is independent of A/B and runs on N48 only.
- **Setup:** T-same-region optimistic, fan-out all, c = 50, uncapped signers,
  `SIGNER_MAX_CONCURRENT` = 2 (default) / 4 / 8, interleaved, 3 runs, signer CPU sampled.
- **Prediction if the inference is right:** goodput rises above 70/s and signer CPU rises
  toward the 200 % host limit. The ceiling is then CPU: 200 % / ≈ 18.7 ms per share ≈ 107
  shares/s per signer ≈ 107 tokens/s with fan-out all.
- **Rule (fixed now):** the slot inference is **supported** if goodput at 4 slots ≥ 1.2 ×
  goodput at 2 slots and signer CPU at 4 slots > CPU at 2 slots. It is **not supported**
  otherwise. Either result is reported under this label. This test does not change any
  default; a default change would be a separate decision.

## 6. Open question carried into the evaluation: the signer-CPU drop (N73)

In the stress test, signer CPU fell below the quota as c rose: 23.2 % at c ≤ 25, 21.5 % at
c=50, 13.8 % at c=200. With a request waiting, a free slot is taken at once, so CPU below
quota means the capped signers were partly idle while they shed load. This is not explained.

Hypotheses and the instrument for each, all added to the 5.1 runs:
- **(a) CFS throttling inflates the RSA estimate.**
  - Idea: with a 25 % quota, a 17 ms share can stall across 100 ms periods. The wall-clock
    EWMA (`RSAEstimate`) then grows, so N48 rejects requests that could have finished and
    shortens the queue budget.
  - Instrument: log `RSAEstimate` per window, and sample the unit's `cpu.stat`
    (`nr_throttled`, `throttled_usec`) at the configuration's start and end.
- **(b) Arrival gaps.**
  - Idea: under fast failures the coordinator's fan-outs arrive in bursts, and the queue
    empties between bursts.
  - Instrument: queue length and slot occupancy sampled at 10 Hz on each signer (new debug
    log line, off by default).
- **(c) Window artefact.**
  - Idea: the CPU window includes warm-up and the drain after the last request, which
    weigh more when the run is short (failures are fast).
  - Instrument: compute signer CPU over the measured window only, from CPUUsageNSec
    samples at the first and last measured request.

Until these are measured, N73's CPU figures are reported as measured, with no explanation.

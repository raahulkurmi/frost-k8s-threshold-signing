# Priority-consistent admission for the signers

> **Evaluated, not recommended (NOTES N78, N81).** Selectable with `SIGNER_ADMISSION=priority`
> (`SIGNER_PRIORITY_CONTROLLER=v1` is this document's controller, `v2` is
> `docs/PRIORITY_ADMISSION_V2.md`). The default is `n48`. The quorum-impossible abort (§2B)
> is off by default (`QUORUM_ABORT=on` to enable), per the v2 rule §7 (N81).

Status: **design approved; implemented (NOTES N76, N77), off by default
(`SIGNER_ADMISSION=n48`); not yet evaluated on AWS (§5).** Implemented: A (priority
admission) with two priority derivations, **stable identity** (the proposal, N77) and
**request ID** (kept for comparison, N76); B (quorum-impossible abort, on by default); and
the hardening of §4: one client certificate per coordinator replica with a per-client fair
share, and the 4 s deadline cap. Collaborative admission (§2C) is **future work**.
**Evaluated on AWS 2026-10-03 (NOTES N78, §7): A+B did not meet the pre-registered
stress rule in either priority mode; no regression on the uncapped configuration.**
Recorded follow-up, **not implemented**: binding p to the signing input, plus a request-ID
replay cache (§4.3). Priority classes (§2A) are not implemented. Motivation: the Phase 7C
stress test (NOTES N73, label **stress test**) met the pre-registered rule. At c ≥ 50 goodput
was 0.50–0.76 × peak, and 32–44 % of computed shares went to requests that failed, because
each signer sheds on its own.

Reference: H. Zhou, M. Chen, Q. Lin, Y. Wang, X. She, S. Liu, R. Gu, B. C. Ooi, J. Yang,
"Overload Control for Scaling WeChat Microservices" (DAGOR), ACM SoCC 2018, arXiv
1806.04075v3. The DAGOR facts used here, checked against that version by the author
(section numbers from the same PDF):
- **§3.1, subsequent overload.** A task that invokes an overloaded service K times
  succeeds only if every invocation does, so random shedding with per-invocation success
  probability (1 − p) gives (1 − p)^K. The paper's example: 50 % × 50 % = 25 %.
- **§4.1, overload detection by average request queuing time, not CPU.** The window is
  1 second or 2000 requests, whichever comes first, and the threshold is 20 ms against
  WeChat's 500 ms default task timeout.
- **§4.2.2, user priority.** It is a hash of the user ID, and each entry service changes
  the hash function every hour. Session-based priority (a hash of the session ID) was
  rejected: re-login gives a user a fresh priority, users learn to re-login to escape
  shedding, and that adds load during overload.
- **§4.2.3, adaptive admission.** A histogram of request priorities per window. At the end
  of a window with N incoming requests, N_adm of them admitted:
  - overloaded: the expected number admitted next window is N_exp = (1 − α)·N_adm;
  - otherwise: N_exp = N_adm + β·N;
  - the level is then set from the histogram's prefix sums. WeChat uses α = 5 %, β = 1 %.
  - So α and β change the expected **number** of admitted requests per window (α of the
    admitted, β of the incoming), not a level percentage.
- **§4.2.4, collaborative admission.** A downstream server piggybacks its current
  admission level on every response; the upstream drops locally the requests that the
  downstream would refuse.

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

    p(req) = first 16 bits of HMAC-SHA256(K_prio, "frost-k8s/priority/v1" ‖ 0x00 ‖ uint64be(epoch) ‖ request_id)
    epoch  = floor(iat / 3600)        iat = the request's own validated iat claim

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
- **The epoch** changes the order every hour, as in DAGOR's hourly hash change (§4.2.2).
  No request ID keeps its priority.
- **This is the request-ID derivation (N76), kept for comparison.** It has the flaw DAGOR
  §4.2.2 describes for session priority: every retry (a new Sign call, a new request_id)
  is a new draw. The **stable-identity derivation** below (N77) is the proposal.

**Stable-identity priority (N77, the proposal; `SIGNER_PRIORITY=stable`, the default).**

    identity = sub ‖ 0x00 ‖ kubernetes.io.pod.uid      (sub alone if the token is not pod-bound)
    p        = (H(K_prio, "stable/v1" ‖ identity) + (e mod R) · 2^16/R) mod 2^16,   e = ⌊iat / E⌋

- **Inputs.** `sub` and the pod uid come from the validated claims
  (`policy.Decision.PodUID`). E = `SIGNER_PRIORITY_EPOCH` (default 2 min), R =
  `SIGNER_PRIORITY_ROTATION` (default 32). The epoch comes from `iat`, as before, so
  signers agree at boundaries (`TestEpochBoundarySignersAgree`, both derivations).
- **Retries keep their priority.** A kubelet retry has the same identity, and within one
  epoch the same p (`TestStablePriorityKeptAcrossRetries`: 40 identities × 5 attempts,
  decisions constant).
- **Rotation instead of a re-draw.** The base H(identity) never changes. Every epoch, all
  identities move by the same step 2^16/R, so the admitted band sweeps across the identity
  space and no pod is stuck below the level.
- **Hard worst-case wait.** At a fixed level L, an identity is refused for at most
  ⌈L·R/2^16⌉ consecutive epochs. This holds **only if** the admitted band 2^16 − L is at
  least one step 2^16/R; otherwise an identity can step over the band every epoch.
  - The level never exceeds the 5 % floor, so R must be ≥ 20, hence R = 32. The signer
    refuses other settings (`StableRotationOK`).
  - With R = 8, 1787 of 3000 test identities were never admitted over a full rotation.
- **Bounds at E = 2 min, R = 32** (`TestStableWorstCaseWait`: worst observed equals the
  bound, every identity admitted):

  | Level (admits top) | Refused epochs, worst | Wait, worst |
  |---|---:|---:|
  | 5 % (the floor) | 31 | ≤ 64 min |
  | 25 % | 24 | ≤ 50 min |
  | 50 % | 16 | ≤ 34 min |
  | 88 % | 4 | ≤ 10 min |

  - This is the cost of keeping retries stable for 2 minutes with a 5 % floor. The wait
    scales as (1 − f)·R·E: a shorter epoch or a higher floor shortens it.
- **What it changes for retries.** The kubelet retries on its own backoff (500 ms doubling
  to 2m2s, `exponentialbackoff` at v1.36.5) whatever the priority mode. So a stable
  priority does **not** make the kubelet send fewer requests; a refused pod keeps retrying
  until the band reaches it.
  - What it removes is the reward for retrying faster. Under request-ID priority, an
    aggressive client (retrying every 250 ms) gets more draws per minute and so more
    tokens. Under stable priority it does not.
  - Prediction: request-ID priority has *lower* TokenRequests per issued token for polite
    (kubelet) clients, and a large advantage for aggressive ones; stable priority has
    higher polite amplification and no aggressive advantage.
  - The storm test (§5.4) measures exactly this. Whether it reduces load overall is an
    open question it answers.
- **How signers derive the epoch (addition 1).** It comes from the token's `iat` claim,
  **not** from the signer's clock. Every signer receives the same signing input, and the
  policy has already validated `iat` (within ±60 s of the signer clock, N44) before the
  priority stage runs. So all signers compute the same epoch for a request, whatever their
  clocks say.
  - **At an hour boundary**, signers whose clocks straddle it (N50 measured ms-level
    offsets) would disagree with a local-clock epoch, for requests arriving in that
    window. With the `iat` epoch they cannot disagree.
  - A token issued at 10:59:59 is in the 10:00 epoch at every signer, even at a signer
    whose clock already reads 11:00:00.010.
  - Test: `TestEpochBoundarySignersAgree`. Two signers with clocks 20 ms apart across
    11:00:00 make identical decisions for 60 + 60 requests with `iat` just before and at
    the boundary.
  - *Cost:* the coordinator chooses `iat` within the ±60 s policy window. Near a boundary
    it can therefore pick between two epochs, i.e. two priority draws. Without K_prio it
    cannot tell which draw is higher (§4.2), so this gives no advantage beyond the
    request-ID re-draw it already has.
- **No starvation (addition 2).** A refused request is not refused forever.
  - A refused TokenRequest fails back to kube-apiserver, and the kubelet retries it (7C
    scale-up: every pod became Ready, N69).
  - Each retry is a new `Sign` call, so the coordinator draws a new random request_id
    (`newRequestID` per call). The priority is therefore re-drawn, independently of the
    previous attempt.
  - At admitted fraction f, a request is refused k times in a row with probability
    (1 − f)^k, and admitted after 1/f attempts on average.
  - Tests: `TestRetryGetsNewRequestID` (5 Sign calls with identical claims reach a signer
    with 5 distinct request IDs) and `TestRefusedRequestsAreNotStarved` (400 requests at
    f = 0.3, each retried with a new ID: all admitted; 31 % on the first attempt, mean
    3.33 attempts, worst 17).
- **Why not the deadline:** every signer sees the same deadline, so EDF (earliest deadline
  first) would also be consistent. But under overload EDF prefers requests that are about
  to miss their deadline, which DAGOR avoids. The deadline stays a feasibility filter
  (N48), not the priority.
- **Optional priority classes (off by default).** A class can be derived by the signer from
  the payload it already parses, for example kube-system service accounts first. It is
  combined as (class, p), like DAGOR's (business, user) pair. It is off by default because
  the coordinator chooses payloads within policy (§4).

**Admission level (DAGOR §4.2.3, implemented as written).** Each signer admits a request
iff p ≥ L, with L a multiple of 256 (a 256-bucket histogram of arrival priorities per
window).
- A histogram is needed: under stable priority, retries of the same identities repeat the
  same values, so arrival priorities are **not** uniform.
- The level never exceeds the bucket that still admits the top 5 % of the priority space
  (the floor).

**Overload signal, per window.** A window is W = 250 ms or 200 arrivals, whichever comes
first. DAGOR §4.1 uses 1 s or 2000 requests; ours is shorter because our deadlines are 2 s
and our rates are ~10–70 requests/s per signer.
- overloaded ⇔ (N48 sheds in the window > 0) **or** (mean queue wait of requests that got a
  slot > θ · median remaining deadline budget at arrival), with θ = 0.5.
- The wait threshold is tied to the deadline, not fixed like DAGOR's 20 ms (§4.1, 4 % of
  its 500 ms timeout). In the **uncapped**
  7C configuration at c = 50, signer queue waits were ≈ 650 ms against a 2 s deadline, with
  0 errors (N69, N72). A fixed 20 ms threshold would shed there and turn a slow success
  into a failure. With θ = 0.5 the threshold is ≈ 1 s (margin ≈ 1.5×); the no-regression
  test (§5.2) checks this.

**Adjustment, per window (DAGOR §4.2.3).** With N arrivals in the window, N_adm of them at
or above the level:
- If overloaded: N_exp = (1 − α)·N_adm. Raise L bucket by bucket until the histogram mass
  at or above L is ≤ N_exp (never above the floor).
- Otherwise: N_exp = N_adm + β·N. Lower L until the mass at or above L is ≥ N_exp.
- α = 5 %, β = 1 % (WeChat's values, §4.2.3). These change the expected **number** of
  admitted requests per window, not a level percentage.
- `TestAdmissionLevelAdapts`: 100 → 95 (overloaded) → 96 (calm) → 91 (long waits) → 92
  (short waits) admitted per window of 100.
- L and the admitted fraction are logged per window (`admission level` line).

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
  `priority below admission level` (fair-share refusals: `over its fair share`). It
  returns HTTP 503 kind `overloaded` with the header `X-Frost-Admission-Level: <L>`
  (`TestPriorityRefusalHTTPAndAudit`).
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

### C. Collaborative admission (DAGOR §4.2.4): future work, not implemented

In DAGOR the upstream compares each request's priority with the downstream's piggybacked
level and drops it locally. Here the upstream is the coordinator, and it **cannot compute
p**: p is keyed with K_prio, which the coordinator must not hold (§4.2). The signers already
return their level (`X-Frost-Admission-Level` on every refusal), but the coordinator has
nothing to compare it with.

Making it work needs either of two things, and neither is cheap:
- **K_prio on the coordinator.** That reintroduces offline grinding of priorities (§4).
- **A signer-issued priority ticket.** The coordinator would first ask one signer to
  compute p and return it with a MAC that all signers verify. That is an extra round trip
  per request, and it is new protocol and new code.

B (§2B) already gives the cheap part of the benefit: the coordinator stops as soon as a
token is impossible.

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
| **kube-apiserver / kubelet retries** | Stable priority (the proposal): a retry keeps the pod's priority within an epoch; the rotation bounds the wait (§2A, ≤ 64 min at the 5 % floor). Request-ID priority (comparison): every retry is a new draw; at admitted fraction f, (1 − f)^k chance of k refusals in a row. |

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
3. **Online probing does not amplify.** *(Follow-up recorded, not implemented.)* It can learn whether a request ID was admitted from
   the 503 or 200, but every probe uses a rate-limit token, is audited, and consumes the
   probed request_id. Finding a request ID above level L costs 1/f tries on average. So its
   admitted rate stays ≤ f × its sending rate, bounded by the per-signer rate limit.
   Replaying one known-good request_id with other payloads is possible, because p does not
   cover the payload.
   - *Follow-up (not in this implementation):* compute p over request_id ‖ SHA-256(signing
     input), and keep a per-signer replay cache of request IDs for one deadline (with the
     4 s cap: ≤ 4 s × 200/s = 800 entries). A reused request_id is then denied (400).
4. **Deadlines:** a long deadline (up to 60 s) keeps adversarial requests queued longer and
   occupies queue positions (max 64). This exists today.
   - **Implemented:** the signer clamps the deadline header to `SIGNER_MAX_DEADLINE`
     (default 4 s = 2 × the coordinator's default deadline; `TestDeadlineHeaderIsCapped`).
5. **What bounds it overall.**
   - (i) The per-signer rate limit, shared today by all clients.
   - (ii) **Implemented: per-replica client certificates.**
     - `scripts/gen-certs.sh` issues `coordinator-1..K`, and each replica mounts only its own
       (all compose files, `deploy.sh`). `COORDINATOR_ID` selects the identity.
     - Signers accept exactly one DNS SAN of the canonical form `coordinator-<1..64>`. The
       old shared `coordinator` is refused, as are `coordinator-0`, `-01` and `-65`
       (`TestTLSRejectsClientWithoutCoordinatorSAN`).
   - (iii) **Implemented: per-client fair share.**
     - Rule: while f < 1 and more than one client was active in the previous window, a
       client is refused once it has had ⌈1.25 × (previous window's admissions / clients)⌉
       admissions in the current window. The 1.25 slack keeps honest, equally loaded
       replicas from hitting the cap (`TestFairShareCapsAFloodingClient`).
     - Bound: one compromised replica out of k gets ≤ 1.25/k of a window's admissions,
       ≈ 42 % for k = 3, instead of its volume share.
   - Without (ii)–(iii), the bound is volume share under the global rate limit, as today.
6. **Leak of K_prio.** The attacker could then grind request IDs offline, and its requests
   would always be admitted. Honest requests would be admitted at a rate reduced by its
   volume share, up to starvation if its volume fills the capacity.
   - The bound is again the rate limit and the fair share (iii).
   - Response: rotate K_prio with a new ceremony artefact; it needs no re-dealing of shares.
   - Safety is unaffected: priorities never change *what* is signed, only *when*.
7. **Stable-identity priority (N77): can a compromised coordinator pick high-priority
   subjects?**
   - **Offline, no.** p = H(K_prio, identity) + rotation, and it lacks K_prio, so a
     subject's priority is unpredictable to it, as with request IDs.
   - **What policy restricts.** `sub` must be a well-formed
     `system:serviceaccount:<ns>:<name>` that agrees with the `kubernetes.io` claims, and is
     outside the deny lists. Audiences, lifetime and the ±60 s `iat` window are enforced.
     The pod uid is **not** checked against the cluster (signers cannot see it), so the
     coordinator can choose arbitrary pod uids and thus arbitrarily many identities.
   - **What is weaker than under request IDs: identities can be reused.**
     - The coordinator sees which honest requests were admitted (it receives the shares).
       Under stable priority an admitted identity stays admitted for the rest of the epoch
       (≤ 2 min).
     - So a compromised replica can copy an admitted honest request's claims (or a pod
       uid it found by probing) and send many requests with that identity in the same
       epoch. All of them are admitted at every signer.
     - Under request-ID priority a found request_id can be reused in the same way, because
       there is no replay cache yet (§4.3 follow-up). So the difference is how easy it is,
       not whether it is possible.
     - The tokens obtained are for subjects the policy already allows. The coordinator can
       obtain those anyway while in control (C2(b), online oracle), so no new *token
       capability* is gained. What it gains is an **admission share**.
   - **Bound.**
     - The per-replica **fair share** (§4.5(iii)): under overload, one replica gets at most
       ⌈1.25 × admissions / clients⌉ per window, ≈ 42 % for 3 replicas, whatever
       priorities it uses.
     - The per-signer rate limit (200/s), shared by all callers.
     - With a single coordinator replica there is no honest traffic to protect, and the
       bound is moot.
   - **Follow-up (recorded, not implemented):** a per-identity admission cap per window
     would remove the reuse amplification.
8. **No new signing path.** A priority check can only refuse. It never admits a request that
   policy, rate limit or N48 would refuse, and it adds no fallback signing mode.

## 5. Evaluation plan (pre-registered before any run)

All runs on a freshly provisioned 7C cluster with the same scripts. This requires
re-provisioning, ≈ 1.5 h bring-up at ≈ $0.57/h, with the usual 7C safety rules.

Variants:
- **n48** is today's system.
- **b** is the quorum-impossible abort alone.
- **abs** is A+B with stable-identity priority: **the proposal** (N77).
- **ab** is A+B with request-ID priority: for comparison (N76).

Run order: per run, all variants interleaved and rotated, with a verified switch (kid, mode,
TokenReview) and the variant recorded (signer config hash, coordinator flag) before every
configuration. INVALID + one re-run (N60); chrony-primary clock check before every run.

### 5.1 Stress test (label **stress test (CPU-capped signers CPUQuota=25%, SIGNER_MAX_CONCURRENT=1)**)
- **Setup:** exactly the N73 configuration. T-same-region optimistic, fan-out all, c =
  10/25/50/100/150/200, 3 runs, N=1000 after 100 warm-up, signer CPU and audit capture.
  Variants n48, b, ab, abs. Every variant's requests cycle over **300 service accounts**
  (`tokenbench -sa-count 300`: request i uses `storm/pod-<i mod 300>`). Otherwise all
  requests would share one identity, and abs would admit all or nothing per epoch. Identity
  does not affect n48, b or ab, so the comparison with N73 holds. The no-regression test
  (§5.2) uses the same 300 identities.
- **Per variant and c:** goodput, goodput / peak (peak = that variant's max), errors, computed
  shares per request, wasted-on-failed %, surplus %, sheds by reason (priority vs N48 kinds),
  signer CPU, cgroup `cpu.stat` throttling (§6), and the per-window f/L trace of each signer.
- **Success rule (fixed now)**, applied to each of abs, ab and b: at every c ≥ 50, goodput
  ≥ 0.8 × peak **and** wasted-on-failed ≤ 10 %, median of 3 runs.
  - If A+B fails the rule, the design is reported as not effective at these parameters; it
    is not re-tuned and re-run under the same label.

### 5.2 No regression (label **7C configuration, no-regression check**)
- **Setup:** uncapped signers, N48 defaults (`max_concurrent` = 2, `max_queue` = 64).
  T-same-region and T-5-region (both included, as asked), optimistic, c = 1/10/20/50,
  3 runs. Variants n48 and abs (the proposal). B0 in the same session as the anchor.
- **Rule (fixed now):** for abs vs n48 in the same session:
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

### 5.4 Storm: retry amplification and worst-case wait (N77; label **stress test (CPU-capped signers …), storm**)
- **Setup:** the stress-test caps, T-same-region optimistic, fan-out all; variants n48, b,
  ab, abs; 3 runs.
  - B = 300 simulated pods start at once, one service account each, so each has its own
    identity (sub); the pod-uid path is unit-tested.
  - 80 % are **polite**: they retry with the kubelet's backoff (500 ms, doubling, cap
    2m2s). 20 % are **aggressive**: they retry every 250 ms.
  - Each pod retries until issued, or gives up after 20 min (`tokenbench -storm-pods`).
- **Measured per variant:**
  - **amplification** = TokenRequests per issued token, overall, polite and aggressive;
  - issued %;
  - wait (first attempt → issued) p50 / p99 / max per class;
  - **aggressive advantage** = median polite wait / median aggressive wait;
  - computed shares per issued token, and wasted %.
- **Pre-registered hypotheses (reported, not pass/fail):**
  - H1: amplification(abs) < amplification(ab).
  - H2: the aggressive advantage under abs is closer to 1 than under ab.
  - H3: no issued pod under abs waited longer than the stable bound (§2A, ≤ 64 min).
  - Pods not issued within the 20 min give-up are reported, not dropped.
- **Prediction (§2A, written before the run):** H1 likely **false** for polite clients,
  because kubelet backoff is independent of priority; H2 likely true.

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

## 7. Results (AWS, 2026-10-03; NOTES N78)

| Test (label) | Pre-registered rule | Result |
|---|---|---|
| §5.3 inference test (admission slots) | supported iff goodput(4) ≥ 1.2 × goodput(2) and CPU rises | **NOT SUPPORTED**: 69.9 / 70.1 / 69.7 per s for 2 / 4 / 8 slots. Signers were CPU-saturated over the measured window (196.5 % of 200 %); N72's slot attribution is withdrawn. |
| §5.2 7C configuration, no-regression check | goodput ± 5 %, median ± 5 % or ± 2 ms, 0 errors, 0 priority refusals | **PASS**, all 8 pairs (both placements, abs vs n48); B0 anchor in the same session. |
| §5.1 stress test (CPU-capped signers) | every c ≥ 50: goodput ≥ 0.8 × peak and wasted ≤ 10 % | **NOT MET** for n48, b, ab and abs. abs met both criteria at c = 50 and 100 (0.89 / 0.86, wasted 3.3 / 6.0 %), not at 150 and 200. |
| §5.4 storm | H1–H3 reported | H1 false (amplification abs 9.0 > ab 7.5; n48 3.8). H2 marginal (2.03 vs 2.34; n48 1.23). H3 holds (worst wait 254 s). |

**Why A+B failed here.** At ≈ 14 requests/s per capped signer, the 250 ms window holds 2–5
arrivals, while DAGOR's §4.2.3 update assumes thousands (§4.1). The level therefore
overshoots to the floor and recovers slowly. Separately, θ = 0.5 classifies the capped
c = 10 steady state as overloaded.

**What would be needed** (not done, needs approval and a new label): a minimum number of
arrivals per window, or DAGOR's 1 s / 2000-request window, and θ re-checked for
low-capacity signers.

**Open question N73/N75 (§6), answered.** (c) The CPU drop is a window artefact: over the
measured window the capped signers used exactly their 25 % quota. (a) Throttling (≈ 92 % of
wall time) inflates RSA wall time and N48's estimate, so N48 over-sheds. (b) could not be
determined.

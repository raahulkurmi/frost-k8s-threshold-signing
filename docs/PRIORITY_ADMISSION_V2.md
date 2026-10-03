# Priority-consistent admission, v2 (design for review, not implemented)

Status: **DESIGN, nothing implemented.** This is the **only** follow-up iteration after the
N76/N77 evaluation (NOTES N78).
- Whatever v2 shows is reported as is, under the label **v2**, and is not re-tuned.
- All N76/N77 results stay in the record unchanged, alongside v2's.
- If v2 fails its rules, the conclusion is that priority-consistent admission did not help
  at these parameters, and admission stays N48 (`SIGNER_ADMISSION=n48`, already the
  default).

Starting point: `docs/PRIORITY_ADMISSION.md` (v1). v2 changes four things: the window, the
overload signal, damping, and retry fairness. Kept from v1, unchanged:
- the stable-identity priority (sub ‖ pod uid, E = 2 min, R = 32) and the request-ID mode;
- the DAGOR §4.2.3 update rule (α = 5 % of admitted, β = 1 % of incoming, histogram), the
  5 % floor, the fair share, the 4 s deadline cap;
- B (the quorum-impossible abort; its default is decided by §7).

DAGOR references are to arXiv 1806.04075v3.

## 0. What v1 got wrong (N78, measured)

- **Sparse windows.** A capped signer sees ≈ 14 requests/s at c = 10–25 (`n48`: 1100
  arrivals per signer per configuration). A 250 ms / 200-arrival window closed with a
  median of **15 arrivals at c = 25 and 2–5 at the start of a run**.
  - DAGOR's window is 1 s or 2000 requests (§4.1), so its §4.2.3 step works on thousands of
    requests.
  - With 2–5, removing a single arrival is 20–50 % of the window, so one window moved the
    level 0 → 28928, and three windows reached the floor.
- **False overload.** At capped c = 10–25, mean queue waits were 0.9–1.3 s (window p90
  1.75 s) against a 2 s budget, while N48 shed **0–0.1 %** of arrivals and goodput stayed at
  peak (1.00 × peak). θ = 0.5 (1 s) flagged this as overload.
- **Fast retriers won (storm).** The level swung window by window. Pods polling every
  250 ms caught the brief openings that kubelet-backoff pods missed: aggressive advantage
  2.03 (abs), 2.34 (ab), against 1.23 for n48.

## 1. Window: count-and-time, sized for low-rate signers

A window closes when **elapsed ≥ T_min and arrivals ≥ N_min**, or when **elapsed ≥ T_max**,
whichever comes first.

    T_min = 1 s     N_min = 40     T_max = 5 s

**Why N_min = 40.**
- The overloaded step removes α·N_adm admitted requests. For that step to be at least one
  real request, N_adm ≥ 1/α = 20.
- N_min = 40 gives 2 requests per α-step, and makes one request worth ≤ 2.5 % of a window
  (v1: up to 50 %).
- Larger N_min means slower reaction:

  | Signer rate | Window at N_min = 40 |
  |---|---|
  | 14 req/s (capped, lowest measured) | ≈ 2.9 s |
  | 70 req/s (uncapped plateau) | T_min = 1 s (≈ 70 arrivals) |
  | 140–340 req/s (capped overload; refusals return fast) | T_min = 1 s (140–340 arrivals) |

- So in every measured regime a window holds ≥ 40 arrivals and lasts 1–3 s. That is the
  same order of time as DAGOR's 1 s, with the count floor scaled down from 2000 for our
  rates.

**Why T_min = 1 s.** DAGOR's interval (§4.1). It also spans many request lifetimes here
(2 s deadline, ~70 ms service), so a window sees a steady state, not a burst.

**Why T_max = 5 s.** It bounds how long the level can be stale at very low rates (for
example a signer at < 8 req/s).

**A window that closes at T_max with fewer than N_min arrivals is "thin".**
- On a thin window the level may only move **down** (towards admitting all), never up:
  there is not enough evidence to shed more.
- N48 still protects the signer in thin windows; it is unchanged.

## 2. Overload signal: re-derived for low-capacity signers

**The constraint.** θ must not flag the saturated-but-healthy state. Measured, capped,
c = 10–25:
- mean wait / budget up to 1.3 / 2.0 = 0.65;
- window p90 up to 1.75 / 2.0 = 0.87;
- 0–0.1 % N48 sheds;
- goodput at peak.

So a pure queue-time threshold would need **θ ≥ 0.9**.

**Why a pure θ adds nothing at that level.** N48 sheds a waiting request once
remaining time < RSA estimate, i.e. at a wait of about (1 − RSA_est/budget) × budget.
- That is 0.96 × budget here (RSA_est ≈ 75 ms when capped; 28 ms uncapped).
- So any θ high enough to avoid false alarms (≥ 0.9) is reached only when N48 is already
  shedding.
- This is the difference from DAGOR: its services normally have short queues (20 ms
  against a 500 ms timeout, §4.1). Our closed-loop clients keep the signer queues long at
  saturation by design (N70, Little's law).

**v2 rule.** overloaded ⇔ (N48 sheds in the window) ≥ max(2, 2 % × arrivals).

| Check | Window shed fraction | Flagged? |
|---|---|---|
| capped c = 10 | 0 % | no |
| capped c = 25 | 0–0.1 % | no |
| capped c = 50, where the collapse begins | ≈ 39 % (n48 38–39 %, b 38 %) | yes |
| uncapped c ≤ 50 | 0 sheds (N69, N78) | never |

- The 2 % threshold sits an order of magnitude above the healthy maximum (0.1 %) and an
  order of magnitude below the collapse (39 %).
- The absolute floor of 2 sheds stops a single shed in a thin window from counting.
- θ (queue time) is dropped as a separate signal. Its information is already contained in
  the N48 shed decision, which uses each request's own deadline.

## 3. Damping: bound the level change per window

Per window, the level may move **up by at most 32 buckets** (12.5 % of the priority space)
and **down by at most 8 buckets** (3.1 %). The §4.2.3 loop runs as before, but stops at the
bound.

- **No single window can reach the floor.**
  - From level 0, reaching the floor (243 buckets) takes ⌈243/32⌉ = 8 overloaded windows:
    ≥ 8 s uncapped, about 23 s at 14 req/s.
  - Stress onset is a step change, so this is the price of stability. N48 keeps protecting
    the deadline while the level climbs.
- **Down-moves are slower** (shed fast, admit slowly, as DAGOR's α > β).
  - Full recovery from the floor takes ⌈243/8⌉ = 31 windows (31–90 s). The β-term usually
    limits recovery further.
  - Even so, the level cannot drop by more than 3 % of the priority space in one window, so
    the opening that a fast retrier could exploit is bounded (§4).
- **Oscillation amplitude.**
  - In steady overload the controller probes as DAGOR does: down by β when no sheds, up by
    α when sheds return.
  - With damping, the level moves at most 8 buckets down / 32 up per window of ≥ 1 s. v1
    could move the full range in 3 windows of 250 ms.
- Both bounds are logged in the `admission level` line (`clamped=up|down`), so the
  evaluation shows how often damping binds.

## 4. Retry fairness: why fast retriers stop winning

The storm advantage came from **time variation of the level**, not from priority re-draws.
Even abs, whose priority does not change between retries, had an aggressive advantage of
2.03. v2 removes the time variation that fast polling exploits.

1. **The decision is constant over a window of ≥ 1 s.** The level changes only at window
   ends: at most once per 1–3 s, and by a bounded step. A pod polling every 250 ms sees the
   same decision 4–12 times per window. Polling faster than the window gains nothing.
2. **The decision is constant per identity within an epoch (stable priority).** Retrying
   does not re-draw p. A refused identity is admitted only when the level drops below its p
   (load drains, ≤ 8 buckets per window) or the 2-minute rotation moves its p into the band.
   Both happen on the server's clock, not the client's.
3. **What remains.** A pod polling often notices a level drop up to its polling interval
   sooner than a pod in kubelet backoff, whose gap grows to 32–122 s. This is the same
   polling-latency advantage n48 already has (1.23: n48's random shedding also rewards
   frequent tries).
   - v2 cannot remove it without changing the kubelet. The rule therefore asks for ≤ 1.3,
     close to n48's 1.23, not 1.0.

**Prediction, written before any run:** aggressive advantage(v2) ≈ 1.1–1.5.

**Risk to the worst-wait rule.** Ordering by priority, rather than shedding at random,
deliberately serves low-priority identities last. In the storm (300 pods, ≈ 22 s of signer
work at 13.8/s), the lowest-priority pods are served only as the queue drains. By then
their kubelet backoff gaps are 16–64 s, so a pod can miss the opening by up to one gap.
- Predicted worst polite wait: ≈ 40–90 s, against the rule's 2 × n48 = 2 × 30.2 s = 60 s.
- **This rule may fail.** That would be a real finding about priority ordering against
  kubelet backoff, and will be reported as such.

## 5. Variants and runs

All on one fresh 7C cluster (same 15 instances and safety rules as N78).

| Variant | Abort (B) | Admission | Purpose |
|---|---|---|---|
| **n48** | off | N48 | today; the same-session baseline every rule compares with |
| **v2** | on | priority v2, stable identity | the proposal |
| **v2nb** | off | priority v2, stable identity | for the B decision (§7) |

- **Stress (v2 label):** the N78 stress configuration exactly (CPU-capped signers, 300
  identities, c = 10/25/50/100/150/200, 3 runs). Variants n48, v2, v2nb.
- **Storm (v2 label):** the N78 storm exactly (300 pods, 80 % kubelet backoff, 20 % every
  250 ms, give-up 20 min, 3 runs). Variants n48, v2, v2nb.
- **No-regression (v2 label):** uncapped, T-same-region and T-5-region, c = 1/10/20/50,
  3 runs, with B0. Variants n48 and v2. (The controller changed, so v1's pass does not
  carry over.)
- Not repeated: the slots inference test (decided in N78).
- **Estimated session:** ≈ 1.5 h bring-up, ≈ 1.2 h stress, ≈ 1 h storm, ≈ 1.7 h
  no-regression, 0.3 h teardown ≈ **5.7 h**, ≈ $3.5 at $0.57/h.

## 6. Pre-registered rules (label "v2"; fixed now, before any implementation or run)

Medians of 3 runs. Each rule is scored for v2 (and reported for v2nb).

| # | Test | Rule |
|---|---|---|
| R1 | stress | at every c ≥ 50: goodput ≥ 0.8 × v2's peak **and** wasted-on-failed ≤ 10 % |
| R2 | storm | amplification(v2) ≤ amplification(n48, same session) + 0.5 |
| R3 | storm | aggressive advantage(v2) ≤ 1.3 |
| R4 | storm | worst polite wait(v2) ≤ 2 × worst polite wait(n48, same session) |
| R5 | no-regression | as v1 §5.2: goodput ± 5 %, median ± 5 % or ± 2 ms, 0 errors, 0 priority refusals, both placements |

- Amplification = TokenRequests per issued token; aggressive advantage = median polite wait /
  median aggressive wait.
- **Overall decision:** v2 is adopted as the recommended priority admission only if **R1–R5
  all hold**. It is still not made the default without your decision. Otherwise it is
  reported as not effective at these parameters.
- No v3.

## 7. Should QUORUM_ABORT (B) stay on by default?

**Evidence so far (N78), b vs n48:**
- capped stress: wasted shares lower at c ≥ 100 (25 / 26 / 19 % vs 32 / 45 / 45 %); goodput
  / peak not better (0.70 / 0.78 / 0.67 / 0.58 vs 0.76 / 0.74 / 0.58 / 0.58); offered load
  2–3× higher;
- storm: amplification 4.4 vs 3.8, worst polite wait 40 s vs 30 s;
- uncapped: no difference (nothing fails).

**Mechanism.** B makes failures return sooner. The kubelet's backoff starts at the error, so
it retries sooner and sends more TokenRequests in the same time. Closed-loop clients resend
at once. B saves signer work per failed request, but creates more requests.

**Decision rule (fixed now), applied to v2 vs v2nb in the v2 session.** B stays on by
default **only if all three hold**:
- (i) storm amplification(v2) ≤ amplification(v2nb) + 0.2;
- (ii) worst polite wait(v2) ≤ 1.2 × worst polite wait(v2nb);
- (iii) stress goodput/peak(v2) ≥ goodput/peak(v2nb) − 0.05 at every c ≥ 50.

Otherwise the default becomes `QUORUM_ABORT=off`. B stays available, and its unit tests and
the local simulation (B saves shares when signers queue) stay as they are.

**Interim.** The code default (on) is unchanged until this rule is applied: changing it now
would be a decision on N78 data that the rule above was written to make.

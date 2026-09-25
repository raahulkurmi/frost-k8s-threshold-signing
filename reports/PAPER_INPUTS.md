# Paper inputs (facts only)

For each paper element that must change: the replacement fact and where its evidence is.
This file has no paper prose. Paper sources are not in this repository; section numbers
come from the reviews and `reports/CLAIMS_AUDIT.md`. "CA n" = CLAIMS_AUDIT row n,
"RR Rn" = REVIEW_RESPONSE row, "TM" = docs/THREAT_MODEL.md.

## Global facts (apply everywhere)

| Fact | Evidence |
|---|---|
| Signing scheme: Shoup threshold RSA, 3-of-5, RSA-2048, RS256 (RSASSA-PKCS1-v1_5, SHA-256); library `github.com/niclabs/tcrsa` **v0.0.5, MIT**, unaudited and unmaintained | go.mod, NOTICE, TM §5, NOTES N6 |
| Later tcrsa versions reference **US patent 10735188**; commercial use needs independent legal review | README "Licensing and patents", NOTES N6 |
| Trusted dealer: the full key exists only in the dealer's memory during the ceremony | docs/KEY_CEREMONY.md, README "Trust assumptions" |
| Integration: kube-apiserver **v1.36.5** ExternalJWTSigner v1 (KEP-740) over a unix socket; no Kubernetes code modified; apiserver runs with **no** in-tree SA key flags | E2E SETUP check, `test/e2e/kubeadm-patches/`, CI run 36154065231 |
| The coordinator holds **public metadata only**; each signer holds exactly one share and enforces its own claims policy | T12, T13, L4; `TestShareFilesEachHoldExactlyOneShare`; T7 |
| The prototype described in the papers did **not** threshold-sign: one coordinator-held ECDSA key signed every token; the FROST aggregate was discarded | CA 1, 2, 6; `legacy/frost/cmd/grpc-proxy/main.go:198, :205, :228` |
| The prototype's keys (ECDSA key, all FROST shares, Vault token, share password) were committed to the public repo and are **burned** | reports/HISTORY_PURGE.md |
| FROST (Schnorr) cannot produce any token Kubernetes accepts: the allow-list is RS256/ES256/ES384/ES512 | `pkg/serviceaccount/externaljwt/plugin/plugin.go:180` at v1.36.5; CA 7 |
| Every number from the prototype (Tables 2–3 and anything citing them) is **superseded** and may not be reused | CA 11 |
| Current benchmark numbers are **preliminary: arm64, multi-VM on one overloaded 16 GB host; not for publication**. Publishable numbers come only from Phase 7A (amd64 cloud VM, B0/B1/T, 3 runs) | README, CA 11, NOTES N47/N51 |
| Reproducibility: `make repro` on a fresh GitHub runner (ubuntu-24.04, amd64) → `reports/REPRO.md`; CI (vet, staticcheck, govulncheck, gitleaks, test, kind e2e) green | `.github/workflows/{ci,repro}.yml`, reports/REPRO.md |

## Paper 3

| Element | Current (wrong) content | Replacement fact | Evidence |
|---|---|---|---|
| Title / abstract: "FROST" signing | FROST threshold signing of SA tokens | Threshold RSA (Shoup, 3-of-5) signing via ExternalJWTSigner; FROST excluded by the Kubernetes alg allow-list | CA 6, 7; README |
| Abstract: numbers | favourable numbers only (+42%/+44% omitted) | No prototype number is valid (CA 11). The prototype's own table included +44% (warm P95 48→69 ms) and +42% (500 sequential, 31→44 ms). New numbers pending Phase 7A | `legacy/frost/docs/README-prototype.md:819, :821`; RR R13 |
| Abstract: limitation count | "six", text has seven | Recount after rewriting the limitations list (below); the prototype README had 5 (L1–L5) | `legacy/frost/docs/README-prototype.md:916–948`; RR R14 |
| §1, §4.2, §10: "40× improvement" | constant 40× | Ratio = 1/(C(5,3)·p^(t−1)) = **1/(10p²)** for t=3, n=5, independent compromise probability p. p=0.05 → 40; p=0.01 → 1000; p=0.1 → 10. It assumes independent compromise, which the tested deployments lack | CA 8; reports/INDEPENDENCE.md |
| §3.1, §8.3, §10: "coordinator holds no signing key" | true for the prototype | **FALSE** for the prototype; **TRUE** for the rebuilt system | CA 1; T12, T13, L4 |
| §3.2: Schnorr → IEEE P1363 conversion | conversion step | No such conversion exists or is possible; the combined Shoup signature *is* the RS256 signature | CA 2; T1, spike |
| §4.4 "Test A: coordinator compromise cannot enable forgery" | claim holds | Replace with: offline forgery needs ≥ 3 shares (T4); after losing control, a coordinator attacker has no token and no signing path (C4: T12, T13, L4); **while in control** it can obtain tokens for any **policy-compliant** claims (online oracle, C2(b): E1/E2); policy-violating claims get 0/5 shares (T7) | CA 4, 5; TM §7 C2, C4 |
| §4.4 / evaluation: failure tests | stopping containers presented as a security test | Stop/crash tests are **availability** (E6: 2 down issued, 3 down refused; E7: recovery 341 ms after signer start; E8: 3 coordinator replicas, 0/15 failed across a rolling restart). Compromise is covered by the TM §7 C1–C7 mapping | CI e2e log (run 36151825518); TM §7; RR R5 |
| §4.4 / security evaluation: collusion | untested | **C3 boundary statement:** 3 colluding signers can forge by design; not tested adversarially; backed by T2 (every 3-subset gives the same valid signature) + T1/E2 (accepted by go-jose and TokenReview) | TM §7 C3; RR R18 |
| §4.4 / security evaluation: adversarial signer | untested | A corrupted share is excluded and attributed to its signer id; 3 corrupted → no token (T5, `TestMaliciousShareExcludedAndAttributed`); spoofed ids rejected (`TestShareIDBoundToMTLSIdentity`, `TestJoinOutOfRangeIDs`); delayed signers → error within deadline (T10). A genuine share for another input fails share verification (spike `TestTamperedShareRejected`; coordinator path not separately tested). **Not separately tested:** an oversized response, slow-loris | TM §7 C1 |
| §4.4: replay | — | Shares are deterministic; policy `clock_skew_seconds` = **60** gives a **±60 s** replay window (`TestPolicyRejects` iat cases); a skewed signer refuses everything (fail closed) | TM §7 C6, §3; NOTES N44 |
| §4.4: flooding | — | Per-signer limit: **200 req/s, burst 400** (`deploy/policy.json`), plus admission control (`SIGNER_MAX_CONCURRENT` = NumCPU, `SIGNER_MAX_QUEUE` = 64, deadline-aware shedding); what a legitimate cluster needs is **not measured** | TM §7 C7; NOTES N48 |
| §5.3 / §5.4 | near-duplicate sections | Merge them (editorial). §5.4's key-export claim changes: `ecdsa-signing.pem` held an **EC private key**; FetchKeys now returns the **threshold group public key** (PKIX RSA-2048, kid = b64url(SHA-256(PKIX)[:16])) | CA 3; T1, `TestFetchKeysPKIXRoundTrip`, E5 |
| Tables 1 and 4: "min. compromises to forge: 3" | 3 (prototype) | Prototype: **1** (one file or one coordinator compromise). Rebuilt: **3 signers for offline forgery**; a live coordinator is an online oracle for compliant claims; on the Level 1 topology **2 VM compromises (sig-a + sig-b) yield 4 shares** | CA 4; reports/INDEPENDENCE.md |
| Tables 2–3: latency and overhead | prototype numbers | Remove all. Why the old "36 ms vs 70 ms" disagreed: per-token latency is **bimodal** (~35 ms or ~69 ms), and the bimodality is also present **in the in-tree baseline with no FROST at all** (`legacy/frost/benchmark/results/baseline_benchmark_20260619_201519.txt`: runs of 69 ms and 35–37 ms). **36 ms is an average** (`frost_benchmark_20260619_200532.txt:37`: "Avg: 36ms … P95: 69ms"); **70 ms is a single slow-mode run** (`benchmark_20260608_224047.txt:44`). The old baseline also changed algorithm and architecture at once (single-key ECDSA behind extra hops vs in-tree), with N ≈ 20 single `kubectl` runs | CA 11; RR R6, R10 |
| Tables 2–3 replacement | — | Phase 7A only: B0 native in-tree / B1 single-key external signer on the same path / T threshold; amd64 cloud VM; 3 runs; every number from a script-generated `summary.md`. **Pending** | addendum Phase 7A; README |
| Evaluation: deployment / independence | all on one host, presented as independent | Single host: no independence. **Level 1**: signers on 3 VMs (sig-a: 1,2; sig-b: 3,4; sig-c: 5), coordinator VM holds no share, hardened systemd units, per-host firewalls, **all on one physical host, one operator, one build**. Level 2: not done | reports/INDEPENDENCE.md; `reports/multihost/e2e-*/`; RR R12 |
| Evaluation: preliminary Level 1 figures (if quoted at all, with the label) | — | c=1, measured quorum RTT 0.7 ms: median 66.3 / p95 75.1 ms, 0% errors, 15.9 req/s. c=50 pre-N43-fix: 96.9% errors; post-fix (partial) still 92.8–98.4% errors. **Label: preliminary: arm64, multi-VM on one overloaded 16 GB host; not for publication** | `benchmark/results/20260925T094355Z-9bb1f16-multihost-L1/summary.md`, `…/20260925T103202Z-2a75c2f-multihost-L1/summary.md`; NOTES N47 |
| Limitations list | L1–L5 (prototype) incl. "coordinator-assisted DKG" | Facts to state: trusted dealer; unaudited `tcrsa` v0.0.5 (hazards guarded, TM §5); online oracle (C2(b)); collusion boundary at t=3 (C3); independence only multi-VM on one host (Level 2 not done); signers need correct clocks (N44); tested only on Kubernetes v1.36.5; benchmarks preliminary until Phase 7A; untested sub-cases in TM §7 | TM §4–§7; README |
| Label names | duplicate "L2" | Use distinct names: the new evidence already uses **Level 1/Level 2** (deployments) and **L1–L5** (multihost tests) | RR R9 |
| KEP-740 Finding 1 | "defect" | Exact wording at **v1.36.5** (`ad950d1c…`), `api.proto` lines 50–53, unchanged on master `71792b89…`. Classification: **documentation gap + implementer error** (not a spec defect) | CA 9; RR R4, R16 |
| KEP-740 Finding 2 | "defect" | DER vs P1363 for ECDSA: **documentation gap**; RFC 7518 §3.4 already requires R‖S; irrelevant to the RS256 signing path | CA 10; RR R16 |
| KEP-740 upstream status | — | #141669 open (needs-triage); #141670 open (needs-triage); PR #141687 open, not merged. Phrase: "found and reported upstream; any fix is the maintainers' decision" | CA 9, 10; RR R17 |
| Related work | — | Threshold RSA (Shoup) is the implemented design. The Kubernetes allow-list excludes Schnorr-based schemes (FROST; ROAST wraps FROST). Threshold ECDSA on P-256 lacks a maintained Go implementation (`taurusgroup/multi-party-sig` is secp256k1 only). PASTA/ROAST discussion: no repository evidence; the author supplies it | CA 7; RR R8 |

## Paper 1

| Element | Current (wrong) content | Replacement fact | Evidence |
|---|---|---|---|
| §VII-B: "Schnorr-signed JWT serialized as ES256" | ES256 FROST tokens | Tokens were ECDSA-signed by one key and labelled ES256; a Schnorr signature cannot verify as ES256. Now: RS256, threshold-combined | CA 6; T1, E1 |
| §VII-B: "threshold ECDSA less practical than FROST" | comparison | FROST is not an option for Kubernetes (alg allow-list); threshold ECDSA on P-256 has no maintained Go implementation; threshold RSA works without Kubernetes changes | CA 7 |
| §VIII-C: FROST signing path and its numbers | FROST path, prototype numbers | Same replacement as Paper 3 §3.2 and Tables 2–3 (bimodal 35/69 ms explanation included); no prototype number is reused | CA 2, 11 |

# Phase 12 adversarial audit

- **Audited commit:** `37f3c5e2de5e847817482bc0a5354e653338a8b2` (code freeze, NOTES N83), branch `fix/threshold-rsa`.
- **Method:** fresh clones in a new directory, not the working tree. No AWS or other cloud resources were used.
- **Date:** 2026-10-04.
- **Instructions:** `docs/instructions/CLAUDE_CODE_PHASE12_AUDIT.md` (committed 0aac79c).
- **Status:** report only. Nothing in the main tree has been changed; fixes wait for approval.

Companion files: [MUTATION.md](MUTATION.md), [FUZZ.md](FUZZ.md), [CLAIMS_RECHECK.md](CLAIMS_RECHECK.md),
[PASS_G_FINDINGS.md](PASS_G_FINDINGS.md) (full blocks for G-1…G-44), `raw/` (tool output), `mutation/`
(diffs and logs), `fuzz/` (harness), `../repro/run-37160608647-0aac79c/` (fresh-runner artifact), `../DEFENSE_BRIEF.md`.

## Summary

**No critical finding. 8 high, 20 medium, 30 low, 17 info (75 findings).**

The security core held up under every adversarial check run in this audit:
- **Reproduction:** `make repro` on a fresh GitHub runner passed end to end (unit and integration tests, image isolation, a kind cluster on the real v1.36.5 apiserver, 19 e2e checks).
- **Mutation testing:** 16 of the 17 required mutations are caught by the suite, and so are all extra mutations against the policy, the TLS identities and the fail-closed paths.
- **Fuzzing:** 11 targets ran 10 minutes each, including a differential against kube-apiserver's go-jose v2 claim parsing. No crash, no hang, and no input the policy accepted that the apiserver reads differently in an unsafe direction.
- **Cryptography:** all 10 three-of-five subsets produced a byte-identical signature in a fresh run, and that signature equals `crypto/rsa.SignPKCS1v15` under the same key.

The high findings are about **evidence and tests, not exploitable code**:
- one required mutation survives (the binary's QUORUM_ABORT default);
- one loader property is untested;
- four cited evidence items are missing or were overwritten;
- one README sentence misstates independence;
- one "pre-registered" rule was in fact written after the event.

| Severity | A | B | C | D | E | F | G | H | I | J | Total |
|---|---|---|---|---|---|---|---|---|---|---|---|
| critical | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| high | 0 | 0 | 2 | 0 | 0 | 0 | 6 | 0 | 0 | 0 | **8** |
| medium | 0 | 1 | 2 | 0 | 3 | 0 | 13 | 0 | 1 | 0 | **20** |
| low | 1 | 0 | 4 | 1 | 2 | 0 | 16 | 3 | 0 | 3 | **30** |
| info | 0 | 0 | 0 | 2 | 1 | 3 | 9 | 1 | 1 | 0 | **17** |
| total | 1 | 1 | 8 | 3 | 6 | 3 | 44 | 4 | 2 | 3 | **75** |

### Not executed (with reason)
- **Local `make repro`:** not executed. The host is macOS arm64 and `scripts/repro.sh` targets a fresh Ubuntu 24.04 host. As the instructions allow, I used the repo's `repro.yml` workflow instead (Pass A).
- **`make check-images` and `make e2e` locally:** not executed for the same reason (Linux + Docker Engine only). Both were run inside the repro workflow and passed.
- **C3 collusion mutation:** not attempted, as instructed.
- **gremlins on `coordinator`:** not executed, and on `signer` only partly (9 mutants in 5.5 h). Every mutant re-runs a 2048-bit keygen, and hanging mutants wait out the timeout. The manual mutations cover both packages' security paths (MUTATION.md).
- **gremlins on `wire`, `tlsconf`, `keyshare`, `dealer`:** executed but uninformative. gremlins counts coverage per package, these packages have no tests of their own, so every mutant is "not covered". Manual mutations M4a, M10a, X6, X11, M16 and the dealer mutation cover them instead.
- **Live slow-loris / HTTP/2 stream fuzzing:** not executed (FUZZ.md limitations).
- **Paper text (R13–R15 counts) and 6B/6C review texts:** UNVERIFIED. Neither is in the repository.
- **Worker interruption.** Four parallel workers stopped early because of an account spend limit. Their raw output was complete except where noted. The lead auditor re-checked and finished:
  - Pass G's findings file was complete;
  - Pass D's runs had all finished;
  - Pass E/F and H/I/J left raw tool output that I triaged myself.
  
  No result in this report comes from a worker's unverified summary.

---

## Pass A: fresh reproduction

- **Fresh runner:** `gh workflow run repro.yml --ref fix/threshold-rsa` gave run **37160608647**, on commit `0aac79c`. That commit differs from the freeze only in `NOTES.md` (N83) and the instructions file (`git diff --stat 37f3c5e 0aac79c`: 2 files, docs only).
  - Result: **Overall PASS, 735 s**, with no manual step.
  - Steps: install-base-packages, docker (pre-existing, detected), kind/kubectl/gitleaks/go with checksums, node image built from the official v1.36.5 tarball (sha256-verified), make-test 330 s, make-check-images 37 s, make-e2e 325 s.
  - e2e: SETUP, E1–E8, REQ-a–d, N1–N3, TIMING, N76-ID, N76-PRIO, all PASS. REQ-d shows `strategy=optimistic … quorum_abort=false`.
  - Artifact: `reports/repro/run-37160608647-0aac79c/` (REPRO.md, e2e.log, repro-logs/*.log).
- **Local:** `make test` on a fresh clone of 37f3c5e (macOS): PASS in 2 min 30 s, no skips, gitleaks present (`raw/A-baseline-make-test-local.log`).
- **Numbers:** every results directory cited in README/THREAT_MODEL/reports regenerates its committed `summary.md` byte-for-byte from committed raw data with the repo's summarizer (Pass G, `raw/G-regen-results.txt`). Numbers that are not in any summary, or contradict one, are G-7, G-8, G-19, G-20, G-21, G-31.

### A-1: The committed reports/REPRO.md predates the final defaults
- Severity: low
- Location: reports/REPRO.md:3-62
- Evidence: the committed file is for `aef95d5` (2026-09-25). Its REQ-d line reads `strategy=strict`, and it has no TIMING, N76-ID or N76-PRIO rows. This audit's run at 0aac79c shows `strategy=optimistic … quorum_abort=false` and 19 checks.
- Why it matters: the reproduction evidence the paper points to does not describe the frozen system.
- Suggested fix: replace REPRO.md with the run-37160608647 artifact (`reports/repro/run-37160608647-0aac79c/`), and commit its step logs (see G-1).

---

## Pass B: invariants I1–I10

**The invariants are defined nowhere in the repository** (finding B-1). Below they are reconstructed from their
citations in code, tests and Dockerfiles. "Would fail" comes from the mutation runs (MUTATION.md).

| ID | Invariant (reconstructed) | Enforced by | Tests | Run | Would the tests fail if broken? |
|---|---|---|---|---|---|
| I1 | Every token is RS256 with a threshold-combined signature; no single-key path | `coordinator.go:444-465` (Join + `rsa.VerifyPKCS1v15`), `:575-595`; one header (`jwtfmt`) | T1, T2, `TestSignProducesStandardRS256`; E1/E2 | PASS | **Yes**: M2 (no final verify), X1 (non-canonical header) caught |
| I2 | Verifiers get the key only from FetchKeys, and it is exactly the group key | `grpcserver/server.go:89-99`; kid bound to key `keymeta.go:163` | T1, `TestFetchKeysPKIXRoundTrip` ×2, `TestCoordinatorMetaIsGroupKey`; E5 | PASS | **Yes**: M12a/b/c caught |
| I3 | The coordinator holds public metadata only | `cmd/grpc-proxy` loads only keymeta | T12, T13 (repro), L4 | PASS | **Yes**: M11 caught by T12 |
| I4 | Each signer holds exactly one share, its own; images carry no secret | `cmd/signer/main.go:101-143`; `keyshare.go:82-84, 92-110` | `TestMultiShareFileRejected`, `TestShareFilesEachHoldExactlyOneShare`, `TestWrongShareIndexRejected`, `TestCorruptedShareRejected`; T13 | PASS | **Partly**: M10a, X6 caught; **M10b (loader accepts several share files) survives** (C-2) |
| I5 | Fewer than t valid shares never yield a token | tcrsa `Join` K check; `coordinator.go:404, 534, 559` | T3, T4, `TestBelowThresholdSigners`, `TestThreeMaliciousFails` | PASS | **Yes**: X16 (t−1) caught |
| I6 | Every t-subset yields a byte-identical signature | RSASSA-PKCS1-v1_5 + combine (math) | T2 (strict only) | PASS; fresh 10-subset run identical, sha256 `2293fdb5…` (`raw/EF-f-subsets.txt`) | not mutable in code; verified by re-run |
| I7 | Bad shares excluded and attributed; final signature verified | `coordinator.go:330-365, 418-443, 462, 636-672` | T5 (`-tags testmalicious`), `TestMaliciousShareExcludedAndAttributed`, breaker tests | PASS | **Yes**: M1, M2, M5b, M5c caught. M5a and X4 survive (redundant layer / request_id: C-3, C-4) |
| I8 | Signers hash and pad themselves; never sign a caller digest | `signer.go:384-386`; wire `DisallowUnknownFields` | T6 ×2 | PASS | **Yes**: M6a, M6b caught |
| I9 | Binaries fail closed on any bad or missing input | `cmd/*/main.go` load(); `policy.New`, `keymeta.Parse`, `keyshare.Parse`, `tlsconf` | T8, `TestSignerFailsClosed`, `TestSignerBinaryFailsClosed`, `TestPolicyConfigFailsClosed`, `TestAdmissionConfigFailsClosed` | PASS | **Mostly**: X15 caught; **M17a (a default flipped inside `cmd/grpc-proxy` load) survives** (C-1) |
| I10 | No secret or key material in the working tree | `run.sh` wipe trap; .gitignore | T11 ×2 | PASS | **Yes**: X17 caught (a share-shaped file in ignored `secrets/`) |

### B-1: Invariants I1–I10 are cited everywhere but defined nowhere in the repository
- Severity: medium
- Location: docs/instructions/CLAUDE_CODE_ADDENDUM_make-it-solid.md:3 ("Read this after CLAUDE_CODE_PROMPT_frost-k8s-fix.md"); I-citations in test/*.go, cmd/*/main.go, deploy/docker/*, deploy/docker-compose.yml
- Evidence: `git log --all --format=%h -- 'docs/instructions/*'` → 0aac79c, 78384e9 only. `git grep -n 'CLAUDE_CODE_PROMPT_frost-k8s-fix'` → only the addendum. No file states I1–I10.
- Why it matters: a reviewer cannot check "T1 (I1, I2)" or "I4" against a definition. The audit had to reconstruct them, so Pass B cannot be fully conclusive.
- Suggested fix: commit the original prompt, or add a short `docs/INVARIANTS.md` that states I1–I10 and maps each to its tests (the table above).

---

## Findings by severity

Findings G-1…G-44 are summarised in one line each. Their full blocks (evidence commands and output, why it matters, fix) are in
[PASS_G_FINDINGS.md](PASS_G_FINDINGS.md). All other findings are given in full here.

### High

#### C-1: The coordinator binary's QUORUM_ABORT default is untested; mutation 17 survives `make test` and would survive the e2e
- Severity: high
- Location: cmd/grpc-proxy/main.go:161-167; test/e2e/run.sh:476-480; deploy/docker-compose.yml:65 (and every compose file: `QUORUM_ABORT: ${QUORUM_ABORT:-off}`)
- Evidence: `mutation/M17a.diff` swaps `case "", "off":` and `case "", "on":`. `mutation/M17a.summary`: `unit rc=0 malicious rc=0 … RESULT M17a SURVIVED`. `TestQuorumAbortOffByDefault` checks only `coordinator.Config{}` (M17b: caught). cmd/grpc-proxy has no tests and 0.0 % coverage (`raw/C-cover-crosspkg.txt`). REQ-d checks `quorum_abort==false` on containers that compose starts with `QUORUM_ABORT=off` set explicitly, so it tests the compose default, not the binary default.
- Why it matters: N82 applies a pre-registered decision (abort off by default). Nothing in the gate would detect a regression of that decision, and deployments that do not use the compose files (systemd units, multihost) depend on the binary default.
- Suggested fix: a unit test of `load()` in cmd/grpc-proxy with `QUORUM_ABORT` unset → `Abort == false` (and `on`/`off`/invalid cases), and/or an e2e step that starts one coordinator without the variable. Re-run M17a.

#### C-2: No test pins "the signer loads exactly one share" at the loader; mutation 10b survives
- Severity: high (instruction rule: a mutation no test catches)
- Location: cmd/signer/main.go:121-143
- Evidence: `mutation/M10b.diff` makes `SHARE_FILE` a comma-separated list, each entry loaded (indices ID, ID+1, …) and kept in memory. `mutation/M10b.summary`: SURVIVED. M10a (a multi-object share file) is caught by `TestMultiShareFileRejected`.
- Why it matters: I4 is enforced today only by the structure of `load()`, which has a single `Share` field. No test would fail if a future change let a signer hold several shares, which is the one property that makes threshold signing meaningful. The shipped code is correct; the gap is in the tests.
- Suggested fix: in cmd/signer tests, assert that `SHARE_FILE` naming two files (`a,b`), a directory, or a glob fails closed, and that `settings` holds exactly one share whose index equals `SIGNER_ID`. Re-run M10b.

#### G-1: make-repro step logs cited as evidence were never committed (28 citations); N56's failure text is nowhere in the repo — high
#### G-2: 7C and N76 evidence files were overwritten by later sessions; INDEPENDENCE §7C and N68/N78 now cite v2-session data — high
#### G-3: NOTES N68 names a non-existent directory (`20260927T123218Z-7faa09c-7C`, the aborted attempt) as "the real run" — high
#### G-4: The security-group log for 7C/N76/v2 is gitignored and never committed; INDEPENDENCE cites it — high
#### G-5: README calls the signers "independent", which no tested deployment provides (README.md:6-7) — high
#### G-6: The N60 "rule for operator network drops" was written after the L2 failure it was applied to (ebabdb1, 19:42Z, after the 19:33Z event) — high

### Medium

#### C-3: Four second-layer checks are untested because the first layer always fires first (M3a, M5a, M14a, M14b survive)
- Severity: medium
- Location: coordinator.go:519 (collect-loop dedupe), :640-643 (response SAN check); signer.go:391 (pre-RSA cancel check), :428 (after-queue cancel check)
- Evidence: MUTATION.md. Each mutant passes the full suite:
  - M3a: unique endpoint IDs are enforced in `New`.
  - M5a: `tlsconf.CoordinatorClient` already pins `signer-<i>`.
  - M14a/M14b: the other cancel check catches the request.
  
  Removing both cancel checks together (M14) is caught.
- Why it matters: this defence in depth is not regression-protected. If a refactor removes the first layer, the second is unverified. For M5a: a coordinator built with a client that does not pin the server SAN (for example a future refactor of `cmd/grpc-proxy`) would accept a share from another signer identity.
- Suggested fix: add fixtures that bypass layer 1:
  - an Endpoint whose `Client` trusts the CA but does not pin the SAN, expecting the response-side check to refuse;
  - a direct `SignShare` call with an already-cancelled context and a free slot, for each check separately.

  Accept M3a as an equivalent mutant, or delete the unreachable dedupe.

#### C-7: The spike tests that are the evidence for the tcrsa hazards are not run by CI or `make test`
- Severity: medium
- Location: spike/threshold_rsa_test.go (separate module); Makefile:28-36; .github/workflows/ci.yml (no `spike` step)
- Evidence: `grep -n spike .github/workflows/ci.yml` → nothing. `make test` runs `go test ./...` at the root, and spike/ is its own module. By hand: `cd spike && go test -run 'TestLibraryHazards|TestTamperedShareRejected|TestAllThresholdSubsetsIdentical' -v .` → PASS (`raw/HIJ-spike-tests.txt`, `raw/EF-spike-tests.txt`).
- Why it matters: THREAT_MODEL §5 and REVIEW_RESPONSE cite `TestLibraryHazards` and `TestTamperedShareRejected` as evidence. If the library or the Go toolchain changes, those facts are never re-checked.
- Suggested fix: add `cd spike && go test ./...` to `make test` and CI.

#### E-1: Vault mode sends the Vault token, and on the dealer side the secret share itself, to any redirect target; plain http is accepted
- Severity: medium (Vault mode is optional and unused by the tested deployments)
- Location: internal/keyshare/keyshare.go:120-140 (`http.DefaultClient`, `X-Vault-Token` header); internal/dealer (Vault write path); internal/prioritykey (same pattern); cmd/signer/main.go:125 (no scheme check on `VAULT_ADDR`)
- Evidence: `raw/EF-e-vault-redirect.txt`: a server at 127.0.0.1 redirects to `localhost` (another host); the target receives `X-Vault-Token present=true`. `raw/EF-e-dealer-vault-redirect.txt`: `redirect target got token=true, got share body containing si=true`. Go forwards custom headers on redirect; only Authorization/Cookie/WWW-Authenticate are dropped.
- Why it matters: anyone who can make the Vault address answer with a redirect receives the Vault token and, at ceremony time, a secret share. With `http://` that includes any on-path attacker. That defeats the one-share-per-host property.
- Suggested fix: a dedicated `http.Client` with `CheckRedirect` returning `http.ErrUseLastResponse`, require `https://` (allow http only for 127.0.0.1 in tests), and pin a CA (`VAULT_CACERT`).

#### E-2: The multihost deploy guard lets one host hold t or more shares
- Severity: medium
- Location: deploy/multihost/deploy.sh:41-47
- Evidence: the guard checks only that each signer id is listed once and that the coordinator host holds none (`raw/EF-e-topology-guard.txt`). `SIGNERS="1:sig-a:8441 2:sig-a:8442 3:sig-a:8443 …"` → `sig-a gets signers: 1 2 3`, `topology guard PASSED`. `grep -n "threshold\|-ge 3" deploy.sh` → nothing.
- Why it matters: the addendum requires the script to refuse more than one share per host unless the topology deliberately assigns two. A typo in a topology file would silently put a whole signing quorum on one host, and every document would still describe the deployment as threshold-protected.
- Suggested fix: refuse any host with ≥ t shares, and require an explicit `ALLOW_SHARES_PER_HOST=2` to put two on one host.

#### E-3: Under the shipped policy, the online oracle includes cluster-admin-equivalent service accounts, and no document says so
- Severity: medium (framing of a security claim)
- Location: deploy/policy.json (`"deny_namespaces": []`, `"deny_service_accounts": []`); docs/THREAT_MODEL.md:114-118, :125-127; README.md:60-63
- Evidence: `git grep -n -i "kube-system\|cluster-admin"` in README/docs/reports → one unrelated hit (docs/PRIORITY_ADMISSION.md:172).
- Why it matters: "policy-compliant claims" sounds restrictive. With empty deny lists it includes tokens for any service account in any namespace, including kube-system controller accounts that can escalate to cluster-admin. Those cannot simply be denied without breaking kube-controller-manager. A committee will ask exactly this.
- Suggested fix: state it in THREAT_MODEL §4 and the README trust assumptions: "a live coordinator compromise is, in practice, a cluster compromise while it lasts; the policy prevents only malformed or over-long tokens and denied subjects". Also document which deny entries are safe to set.

#### I-1: The repository has no LICENSE file but calls itself open source
- Severity: medium
- Location: repository root; README.md:116; NOTICE
- Evidence: `ls LICENSE*` → no matches. `go-licenses` reports the repo's own packages as `Unknown` (`raw/HIJ-go-licenses.txt`). Third-party licenses are BSD-3-Clause, Apache-2.0 and MIT; none is incompatible.
- Why it matters: without a license the code is all-rights-reserved, so "open-source research prototype" is not true as a legal matter. It also blocks reuse by reviewers.
- Suggested fix: add a LICENSE (MIT or Apache-2.0 are both compatible with every dependency) and reference it in NOTICE.

#### G-7: "0 % errors in every configuration" (7C) is contradicted by summary.md: 4 failed requests in 72,000; N69 names the wrong system — medium
#### G-8: Throttling % and RSA wall-time numbers are transposed in N78, N81, PAPER_INPUTS and PRIORITY_ADMISSION — medium
#### G-9: README status and evidence text is stale (single host, preliminary, Phase 7A pending) — medium
#### G-10: README says coordinators "verify every share"; the default (optimistic) does not — medium
#### G-11: THREAT_MODEL stale status (Level 2 "not done", N76 "evaluation pending", Level 1 rates) — medium
#### G-12: THREAT_MODEL still describes a single shared `coordinator` client identity, removed in N76 — medium
#### G-13: CLAIMS_AUDIT row 11 still states the withdrawn N72 slot attribution; row 14 says Level 2 "not done" — medium
#### G-14: The legacy "bimodal 35/69 ms" and "70 ms = slow-mode run" explanation is not supported by its own cited files (70 ms was measured with 2 signers killed) — medium
#### G-15: The upstream KEP-740 framing omits "community fixes proposed, none merged" and the closed community PR #141673 — medium
#### G-16: deploy/multihost/README.md says Level 2 is "Not done" and calls netem delay "emulated RTT" (breaks the netem wording rule) — medium
#### G-17: N73's prediction "written down before the first stress configuration finished" first appears in git after the data — medium
#### G-18: 7C signer binaries differ between the two T systems although both manifests record the same commit — medium
#### G-19: Several quoted numbers exist only in raw files, not in any script-generated summary.md (violates README.md:106-107) — medium

### Low

#### C-4: The coordinator's request_id binding check is untested (X4 survives)
- Severity: low
- Location: internal/coordinator/coordinator.go:673-676
- Evidence: `mutation/X4.summary`: SURVIVED.
- Why it matters: a replayed share for another request (a different signing input) would still fail share or final verification, so impact is low. But attribution would then say "invalid share" instead of "stale response", and nothing guards the check.
- Suggested fix: a test whose fake signer echoes a wrong `request_id`, expecting the specific failure reason.

#### C-5: The coordinator response-size limit is untested (X5 survives)
- Severity: low
- Location: internal/coordinator/coordinator.go:644-652
- Evidence: `mutation/X5.summary`: SURVIVED. THREAT_MODEL C1 already lists "oversized payload: not separately tested".
- Suggested fix: a fake signer returning `MaxResponseBytes+1` bytes, expecting "response too large".

#### C-6: Removing admission control altogether (M13a) is caught only by a 30-minute package timeout
- Severity: low
- Location: internal/signer/admission_test.go (`TestQueuedRequestCancelledByCallerComputesNoShare`)
- Evidence: `mutation/M13a.log.gz`: `panic: test timed out after 30m0s … running tests: TestQueuedRequestCancelledByCallerComputesNoShare (28m59s)`.
- Why it matters: in CI this shows up as a hang, not as an assertion naming the broken property, and the tests after it never run.
- Suggested fix: bound the waits in that test with `select … time.After`, and fail with "request was not queued: admission control missing".

#### C-8: Policy boundary edges are untested (gremlins: 15 of 92 policy mutants live)
- Severity: low
- Location: internal/policy/policy.go:111, 114, 117, 282, 297, 402, 405 (boundaries); :75, :79 (Load error paths); :360, :362 (pod uid)
- Evidence: `gremlins unleash --workers 4 --timeout-coefficient 40 ./internal/policy` → `Killed: 74, Lived: 15, Not covered: 3`, efficacy 83.15 % (`raw/C-gremlins-policy.txt`). For example, `exp <= iat` → `exp < iat` survives, so a token with `exp == iat` would be accepted and no test notices. Every security rule's main path is killed (and M8, M9, X2, X3, X9, X10, X13, X14 are caught).
- Why it matters: off-by-one changes to the policy limits would go unnoticed. The impact is small, because the apiserver also validates times.
- Suggested fix: add exact-edge cases to `TestPolicyRejects`/`TestPolicyAccepts`: lifetime = max and max+1, skew = ±60 and ±61 (already present for iat), nbf at ±skew, exp == iat, 63/64-character namespace, 253/254-character name.

#### D-1: The policy accepts numeric claims written as JSON strings; go-jose rejects them (fail-closed differential)
- Severity: low. Full block in FUZZ.md.

#### E-4: The dealer accepts a world-writable output directory and leaves partial output on failure
- Severity: low
- Location: internal/dealer/dealer.go:90-105 (`writeExclusive` uses `O_EXCL`; symlinks are refused, which is good); output directory handling
- Evidence: `raw/EF-e-dealer-files.txt`: `pre-existing dir mode 0777 accepted … share-1 mode=-rw-------`. When share-2 already exists, share-1.json is left on disk.
- Why it matters: in a world-writable directory another local user can delete or substitute files between the ceremony and distribution. A failed ceremony leaves secret shares behind.
- Suggested fix: refuse an output directory that is group- or other-writable (or create it 0700 itself), and remove already-written shares on failure.

#### E-5: Multihost SSH uses trust-on-first-use, and multiplex sockets live in /tmp
- Severity: low
- Location: deploy/multihost/transport.sh:39 (`StrictHostKeyChecking=accept-new`, `ControlPath=/tmp/tk8s-cm-%C`); deploy/aws/ssh.sh:8
- Why it matters: the first connection to a new signer VM, which is the one that delivers its share, is not authenticated. The operator-side control sockets sit in a shared directory.
- Suggested fix: pin host keys from the cloud console or user-data, and put `ControlPath` under `~/.ssh/` with mode 0700.

#### H-1: Docker base images are pinned by tag, not by digest
- Severity: low
- Location: deploy/docker/Dockerfile.signer:4,12; Dockerfile.proxy:4,12; test/e2e/Dockerfile.probe; benchmark/b1signer/Dockerfile (`golang:1.27.1-alpine3.24`, `alpine:3.24`)
- Why it matters: a rebuilt image can silently change base layers, and the T13 evidence is not tied to a fixed base. All images run non-root (`USER 10001` / 65534) and use no test build tags (checked).
- Suggested fix: `FROM golang:1.27.1-alpine3.24@sha256:…`, plus a digest update procedure.

#### H-2: Four executable operator scripts run without `set -euo pipefail`
- Severity: low
- Location: deploy/aws/provision.sh, deploy/aws/provision-7c.sh, deploy/aws/teardown.sh, deploy/aws/ssh.sh. Four sourced libraries also lack it, which is acceptable: benchmark/k8s7c/lib.sh, benchmark/single/scale-lib.sh, deploy/multihost/clock-check.sh, deploy/multihost/transport.sh.
- Evidence: `grep -L "set -euo pipefail"` over `git ls-files '*.sh'`. Shellcheck (`raw/HIJ-shellcheck.txt`): 4 errors, all SC2148 (missing shebang in sourced libraries). The warnings are false positives or unused variables. SC2183 at benchmark/multihost/run.sh:185 and SC2154 at benchmark/single/run.sh:71 were checked and are false positives.
- Suggested fix: add strict mode to the four executables, and `# shellcheck shell=bash` to the libraries.

#### H-3: The accepted vulnerability GO-2026-6443 (grpc) expires on 2026-11-30, 57 days after this audit
- Severity: low
- Location: reports/ci/govulncheck-accepted.txt; NOTES N52
- Evidence: `scripts/govulncheck.sh` → `GO-2026-6443 reachable, ACCEPTED until 2026-11-30` (`raw/HIJ-govulncheck-script.txt`). GO-2026-5932 (x/crypto) is module-level only: "your code doesn't appear to call these".
- Suggested fix: schedule the grpc upgrade or re-assessment before 2026-11-30. CI turns red on that date.

#### J-1: HISTORY_PURGE.md says gitleaks finds 4 history leaks; it finds 10
- Severity: low
- Location: reports/HISTORY_PURGE.md:30-33
- Evidence: `gitleaks git . --log-opts=--all --redact` → `leaks found: 10`: 4 private keys (as listed) plus 6 `generic-api-key` hits in `reports/aws/7c/bootstrap-checks.jsonl` at a0173b4. Those 6 are the public `token_kid` values N69 renamed: false positives, but they will trip anyone who re-runs the scan. The `.summarize` commit id is also wrong (G-30). Manual history search found no further sensitive paths beyond the listed ones (`raw/HIJ-history-sensitive-paths.txt`), and no PEM, share, AKIA or Vault-token content in 1 GB of decompressed result archives (`raw/HIJ-gz-content-scan.txt`).
- Suggested fix: record the 6 false positives (commit, rule, reason) in HISTORY_PURGE.md, or add a `.gitleaksignore` with fingerprints.

#### J-2: Absolute operator home paths in committed reports
- Severity: low
- Location: reports/aws/TEARDOWN-7C-20260927T194900Z.md, reports/aws/TEARDOWN-N76-20261003T154358Z.md, reports/aws/TEARDOWN-v2-20261003T214235Z.md, reports/ci/govulncheck.txt, plus the 7C-stress summary (G-34)
- Evidence: `git grep -ln "/Users/" 37f3c5e`. None appear in code, deploy files, scripts or docs. There is no debug code, `TODO`/`FIXME`, or `fmt.Print` in cmd/ or internal/.
- Suggested fix: strip the `/Users/<name>/…` prefix.

#### J-3: The author's employer name now appears in the repository, inside the Phase 12 instructions file itself
- Severity: low
- Location: docs/instructions/CLAUDE_CODE_PHASE12_AUDIT.md (Pass J bullet), commit 0aac79c (after the freeze)
- Evidence:
  - `git grep -i -c <employer-name> 37f3c5e` → nothing.
  - `git log --all -i -S <employer-name> --oneline` → `0aac79c docs: add Phase 12 audit instructions`.
  - Commit metadata contains no such domain: `git log --all --format='%ae%n%ce' | sed 's/.*@/@/' | sort | uniq -c` → gmail.com, github.com, users.noreply.github.com.
- Why it matters: the frozen code passes. The branch tip fails its own rule, because the rule names the word.
- Suggested fix: reword that bullet to name the term indirectly, for example "the employer's company name".

#### G-20 … G-35 (low): see PASS_G_FINDINGS.md
- G-20 N78 "offered load rises 4–6×" is 2.4–3.9×.
- G-21 N78 refusal counts mix a median and a worst run.
- G-22 N56 assertion loosening described per token, but the code checks totals.
- G-23 PRIORITY_ADMISSION_V2 §7/§8 still say the QUORUM_ABORT change is pending.
- G-24 THREAT_MODEL cites the wrong coordinator line.
- G-25 api.proto line numbers shifted on master.
- G-26 REPRO.md says repro "will also run" on the 7A VM; it did.
- G-27 clock-skew figures have no committed log.
- G-28 E6/E7/E8 numbers live only in expiring CI logs.
- G-29 KEY_CEREMONY points to non-existent NOTES rotation entries.
- G-30 HISTORY_PURGE has the wrong commit for `.summarize`.
- G-31 N59 ratio.
- G-32 7C summary records commit 1e77bee, not 73be90f.
- G-33 run-time summaries replaced rather than kept.
- G-34 operator home path in the 7C-stress summary.
- G-35 Level 1 VM count wording.

### Info

- **D-2**: share malleability Xi' = n − Xi passes `Verify` and `Join` (known, N5; harmless). FUZZ.md.
- **D-3**: `jwtfmt.ParseHeader("null")` returns a zero header with no error; `CheckHeader` still rejects it. FUZZ.md.
- **E-6**: the coordinator's gRPC server uses default limits (4 MB max receive). `coordinator.Sign` base64-decodes the whole claims string (`jwtfmt.CheckSegment`, coordinator.go:301) before the 16 KiB bound (:305). This is a minor CPU cost reachable only by an `lb`-authenticated caller. Fix: `grpc.MaxRecvMsgSize(64<<10)` and a length check first.
- **F-1**: tcrsa v0.0.5 is not textbook Shoup. The dealer multiplies each share by Δ⁻¹ mod m (`key.go:181-197`), so Join uses e′ = 4 instead of 4Δ² (`signature_share_list.go:75`); Δ = l! is used in the Lagrange step (`:74, :113-135`). This is mathematically valid because the dealer knows m. A fresh check confirmed Σ Δ·λⱼ·sⱼ ≡ d (mod m) for all 10 subsets, and that the Join output is byte-identical to `crypto/rsa.SignPKCS1v15` for documents with Jacobi symbol +1 and −1 (`raw/EF-f-tcrsa-internals.txt`). Docs and the defence should describe this variant, not e′ = 4Δ².
- **F-2**: no side-channel review. tcrsa uses `math/big` `Exp`, which is not constant time, on secret exponents (sᵢ) in `KeyShare.Sign`. Timing attacks on a signer are out of scope and unverified. State this as an assumption.
- **F-3**: `keymeta.Parse` accepts any modulus ≥ 2048 bits and any public exponent; only the dealer enforces exactly 2048 and e = 65537. The meta file is operator-supplied, so the impact is minimal; pinning both is cheap.
- **H-4**: tool triage. Every tool was run on the root, spike and benchmark modules (legacy: vet and staticcheck only, see below). `go vet` (also `-tags testmalicious`) and staticcheck (both tags) are clean on all three modules (`raw/HIJ-govet.txt`, `raw/HIJ-staticcheck.txt`).
  - gosec, 22 issues in the main module, all triaged as not exploitable:
    - G304/G703 file paths from operator configuration;
    - G104 unchecked `Close()` on error paths (dealer.go:98,102; vault bodies);
    - G115 int→uint16 conversions already bounded by earlier checks (ids ≤ 64);
    - G302 socket chmod 0660, intentional;
    - G704 Vault URL, operator-supplied.
  - golangci-lint: 84 errcheck hits (`Close`/`Fprintf`) and 8 staticcheck style hints (QF1001, ST1023). No true positive in runtime logic.
  - `legacy/frost` (`-tags legacy`) vet and staticcheck findings are in excluded legacy code.
  - `go mod verify`: all modules verified (benchmark: local-module ziphash notice only).
- **I-2**: `benchmark/go.mod:55` has `replace frost-k8s-threshold-signing => ../`, a local module, which is intended. No other replace directives, no vendoring. tcrsa is pinned at exactly v0.0.5 with a comment (go.mod:7). Its v0.0.5 LICENSE is MIT, and upstream master's LICENSE references US patent 10735188 and Chile 2015003766, so NOTICE and README are accurate.
- **G-36 … G-44**: see PASS_G_FINDINGS.md.
  - G-36: the N76/N82 test edits loosened no assertion.
  - G-37: v2 pre-registration verified (293a919 precedes d07a8e7 and all v2 data). The abort default was decided on priority-admission data.
  - G-38: overload-control framing is correct.
  - G-39: one removed test is still cited historically.
  - G-40: the summarizer is not backward compatible with 7A.
  - G-41: the 1/(10p²) approximation error.
  - G-42: the ceremonies ran on the operator laptop.
  - G-43: ICMP statements are inconsistent.
  - G-44: an untracked aborted lever directory in the operator workspace.

---

## Pass E notes (reviewed, no finding)

- **Signer handler:**
  - body ≤ 64 KiB with `DisallowUnknownFields` and a trailing-data check;
  - deadline header strictly parsed and capped;
  - rate limit, then request_id, then split, then canonical header, then policy, then hash/pad, then admission, then audit before RSA, then post-RSA cancel check.
  
  No panic was reachable in fuzzing.
- **Policy:**
  - exact-key decoding with duplicate and case-variant rejection at each object level that is read;
  - integer NumericDates (floats rejected);
  - iat skew checked against the signer clock; nbf within skew; sub ↔ kubernetes.io agreement.
  
  Unicode folding (`ſ`, Kelvin `K`) cannot create a differential, because the policy looks up exact keys and go-jose v2's JSON fork is case-sensitive. The fuzz differential found none.
- **Coordinator:** the share id is always the endpoint id (never taken from the response), bounded in `New` and `ToTcrsa`. The mTLS SAN is checked twice. `Join` never sees an unverified id. The final `rsa.VerifyPKCS1v15` runs before any return. Errors to the caller are generic.
- **TLS:**
  - TLS 1.3 only;
  - ECDSA P-256 leaf certificates, CA `pathlen:0`, keys 0600, 1-year validity (`raw/EF-e-gencerts-modes.txt`);
  - EKU separation tested: a signer certificate cannot be used as a client, `lb` cannot reach signers, and a coordinator certificate cannot call the gRPC listener (`raw/EF-e-cross-role-tls.txt`).
- **nginx:** Unix socket only; upstream mTLS with `grpc_ssl_verify on`, a pinned name and TLS 1.3. Retries are bounded (3) and deterministic (T2).
- **Compose:**
  - each signer mounts only its own share (plus the public meta and the unused-by-default priority key);
  - the coordinator mounts only public meta and its own replica's certificate;
  - the CA key is never mounted;
  - `read_only`, non-root `user`, internal networks with `inhibit_ipv4`, nothing published (repro N2).
- **Test-only build tags:** `testmalicious` appears only in `internal/signer/tamper_testmalicious.go`, the Makefile and CI test steps. No Dockerfile or deploy script passes `-tags`. No "policy-disabled" tag exists anywhere.
- **Secrets in logs:** audit records hold sub, aud, client SAN and the SHA-256 of the signing input; no share, token or key. Error messages print paths, never values.

---

## Prioritised fix list (awaiting approval; nothing has been changed)

Order: high first, then the medium items that change what a reader concludes, then cheap low items.

| # | Finding(s) | Change | Gate to re-run |
|---|---|---|---|
| 1 | C-1 | Unit tests for `cmd/grpc-proxy` `load()` defaults (QUORUM_ABORT unset/on/off/invalid); optionally an e2e coordinator started without the variable | `make test`, re-run M17a |
| 2 | C-2 | cmd/signer tests: multi-entry `SHARE_FILE`, a directory or a glob → fail closed; `settings` holds one share with index = SIGNER_ID | `make test`, re-run M10b |
| 3 | G-1, A-1 | Commit the repro step logs (this audit's artifact under `reports/repro/run-37160608647-0aac79c/`, plus the CI artifact of run 36157069748 before it expires on 2026-12-24); replace REPRO.md with the run-37160608647 report | gitleaks + T11 |
| 4 | G-2, G-18 | Restore per-session copies of `reports/aws/7c/*` from a0173b4/0ee7228 and 18ac3ac into session-named folders; fix INDEPENDENCE §7C, N68, N78 citations; record the binary-hash discrepancy as undetermined | doc-only; evidence-existence script |
| 5 | G-3 | Fix N68's run pointer | doc-only |
| 6 | G-4 | Commit the operator-side SG logs for 7C/N76/v2 (scan first), or mark the 7C network bullet "not evidenced" | gitleaks + T11 |
| 7 | G-5, G-9, G-10, G-16 | Rewrite README opening, status box, evidence rows and the coordinator description; fix deploy/multihost/README | doc-only |
| 8 | G-6, G-17 | Reword N60 and N73 to say when the rule and the prediction were actually written | doc-only |
| 9 | E-3 | Add the privileged-service-account consequence of the online oracle to THREAT_MODEL §4 and README | doc-only |
| 10 | E-1 | Vault clients: no redirects, https only, CA pinning | `make test` + new test |
| 11 | E-2 | deploy.sh: refuse ≥ t shares per host; explicit opt-in for 2 | shellcheck; dry-run with a bad topology |
| 12 | C-7 | Run spike tests in `make test` and CI | `make test`, CI |
| 13 | C-3 | Layer-bypass fixtures for M5a, M14a, M14b (accept M3a as equivalent, or remove the dead check) | `make test`, re-run M5a/M14a/M14b |
| 14 | I-1 | Add LICENSE | – |
| 15 | B-1 | Add docs/INVARIANTS.md (Pass B table) | doc-only |
| 16 | G-7, G-8, G-11–G-15, G-19 | Correct the numbers and stale text in CLAIMS_AUDIT, PAPER_INPUTS, THREAT_MODEL, NOTES; add the community-PR framing for #141669/#141670 | doc-only; regenerate summaries if columns are added |
| 17 | C-4, C-5, C-6, C-8, D-1 | Tests for request_id mismatch and oversized response; bounded waits in the admission test; reject quoted NumericDates | `make test`, re-run X4, X5, M13a |
| 18 | E-4, E-5, H-1, H-2, H-3, J-1, J-2, J-3, remaining G-low | Hardening and hygiene | relevant gate |
| – | info items | Accept with reason, or a one-line doc note (F-1 in the threat model; F-2 as an assumption) | – |

**Exit-criteria status now:**
- open critical/high: 8 (requires fixes 1–9);
- executed required mutations caught: 16 of 17 (#17 survives);
- fuzz crashes: 0;
- claim sentences with evidence: no, see CLAIMS_RECHECK (CONTRADICTED / STALE / UNSUPPORTED rows);
- fresh-clone repro: PASS.

---

## Resolution (fix loop, approved 2026-10-04)

Approved scope:
- fix-list items 1–9 (every high finding);
- the medium items E-1, E-2, E-3, I-1 and C-7;
- the `.gitignore` exception for `reports/audit/`;
- J-3.

Status values:
- **FIXED**: commit and covering test or evidence given;
- **OPEN**: outside the approved scope, awaiting a decision; nothing was changed and nothing is accepted on the owner's behalf;
- **INFO**: no action requested.

Every fix commit names its finding (N83 freeze rule), and NOTES N84 lists them.

| ID | Sev | Status | Commit | Now covered by / evidence |
|---|---|---|---|---|
| C-1 | high | **FIXED** | 2572d08 | `TestQuorumAbortDefaultsOff`, `TestLoadDefaults` (cmd/grpc-proxy). **M17a re-run: CAUGHT** (was SURVIVED) |
| C-2 | high | **FIXED** | fc4b8ce | `TestShareFileMustNameExactlyOneFile` (cmd/signer; behavioural + structural). **M10b re-run: CAUGHT** (was SURVIVED) |
| G-1 | high | **FIXED** | 5a77718 | step logs of the 4 GitHub-runner repro runs in `reports/repro/run-<id>-<sha>/`; EC2 attempt logs and N56's failure text marked **not retained** (instance terminated) in `reports/aws/REPRO-*.md`, NOTES N84 |
| G-2 | high | **FIXED** | 01272b2 | per-session evidence restored from git history: `reports/aws/7c-session1/` (a0173b4, 0ee7228), `n76-session/` (18ac3ac), `v2-session/` (a000c9b); `reports/aws/7c/README.md` maps the retired path; INDEPENDENCE and PAPER_INPUTS citations fixed. `provision-7c.sh` assigns `EVIDENCE_DIR=reports/aws/7c-sessions/<UTC>`, and `bootstrap.sh` and `deploy.sh` refuse to overwrite committed evidence |
| G-3 | high | **FIXED** | d23d0f4 | correction entry NOTES N84 (N68 not rewritten) |
| G-4 | high | **FIXED** | 01272b2 | the SG log **was recoverable** (operator-side `deploy/aws/state/sg-rules.txt`, 69 lines) and is committed per session as `sg-rules.txt`; its 2026-09-26 lines are byte-identical to the already committed `reports/aws/sg-rules.txt`; it confirms INDEPENDENCE §7C (8441 only from 15.252.57.131/32, the coordinator IP in the manifests) |
| G-5 | high | **FIXED** | d23d0f4 | README opening no longer says "independent signers" |
| G-6 | high | **FIXED** | d23d0f4 | disclosed in NOTES N84, REVIEW_RESPONSE R12, PAPER_INPUTS, INDEPENDENCE; the original FAIL is kept |
| B-1 | med | **FIXED** (round 2) | fc69a58 | `docs/INVARIANTS.md` (each invariant: enforcing code, tests, mutation evidence); linked from README and THREAT_MODEL |
| C-3 | med | **FIXED** (round 2) | cba14ca | M5a → `TestResponseSANCheckWithoutTLSPinning`, M14a → `TestCancelledRequestRefusedBeforeAdmission`, M14b → `TestCallerGoneDuringAdmissionComputesNoShare`: **all three now CAUGHT**. M3a: documented in code as unreachable defence in depth (endpoint ids unique, each endpoint launched once); still survives by construction; no code removed |
| C-7 | med | **FIXED** | 9f85a8c | `make test` → `test-spike` (spike module, 8 tests incl. `TestLibraryHazards`, `TestTamperedShareRejected`); CI's test job runs `make test`; `make vet` and CI vet spike/ |
| E-1 | med | **FIXED** | c82f653 | `internal/vaultclient` (no redirect off the configured scheme/host/port) used by keyshare, prioritykey and dealer; `TestNoCrossHostRedirect` (4 call paths × 2 targets), `TestSameOriginRedirectFollowed`. Negative control: with the fix reverted the redirect target received 8 requests carrying the token. **Round 2 (374a59d):** `VAULT_ADDR` must be `https://`; plain http only with `VAULT_DEV_ALLOW_HTTP=1` (`TestCheckAddr`, `TestSignerFailsClosed` cases, `TestVaultModeRequiresHTTPS`; negative control fails without the check) |
| E-2 | med | **FIXED** | c4c267e | `deploy/multihost/topology-guard.sh` (≤ t−1 shares per host; Level 1 2+2+1 complies, so no exception is needed); `TestTopologyGuard` (9 topologies; negative control: 3 unsafe placements accepted without the rule); deploy.sh checks the dealer threshold after the ceremony |
| E-3 | med | **FIXED** | d23d0f4 | README trust assumptions, THREAT_MODEL §4 and §7 table, PAPER_INPUTS §4.4 row |
| I-1 | med | **FIXED** | d23d0f4 | `LICENSE` (Apache-2.0, canonical text sha256 cfc7749b…); NOTICE and README consistent with it and with tcrsa v0.0.5 MIT |
| G-7 | med | **FIXED** (round 2) | 29868bd | CLAIMS_AUDIT row 11, REVIEW_RESPONSE R6, PAPER_INPUTS: 0.0 % median, 4 of 72,000 failed (summary.md:131, :153); NOTES N85 corrects N69 |
| G-8 | med | **FIXED** (round 2) | 29868bd | PAPER_INPUTS, PRIORITY_ADMISSION §7: RSA ≈ 92–95 ms; throttled/wall 85–129 % (not a fraction); NOTES N85 |
| G-9 | med | **FIXED** | d23d0f4 | README status box, evidence table, benchmark paragraph |
| G-10 | med | **FIXED** | d23d0f4 | README "How it works" item 3 |
| G-11 | med | **FIXED** (round 2) | 29868bd | THREAT_MODEL header, §1, §6 Level 2 row, C7 rate (7C plateau), N76 'evaluated' |
| G-12 | med | **FIXED** (round 2) | 29868bd | THREAT_MODEL §0, §1, C4: per-replica `coordinator-<k>` |
| G-13 | med | **FIXED** (round 2) | 29868bd | CLAIMS_AUDIT row 11 (N72 withdrawn, N78 result), row 14 (Level 2); NOTES N85 |
| G-14 | med | **FIXED** (round 2) | 29868bd | 'bimodal' explanation withdrawn in CLAIMS_AUDIT, REVIEW_RESPONSE, PAPER_INPUTS: 36 ms warm average vs 70 ms with 2 signers killed |
| G-15 | med | **FIXED** (round 2) | 29868bd | required framing in CA 9/10, R17, PAPER_INPUTS; #141673 and #141687 listed (status 2026-10-04) |
| G-16 | med | **FIXED** | d23d0f4 | deploy/multihost/README (Level 2 done; netem delay labelled a knob) |
| G-17 | med | **FIXED** | d23d0f4 | correction in NOTES N84 |
| G-18 | med | **FIXED** | 01272b2, d23d0f4 | INDEPENDENCE §7C and NOTES N84: cause of the differing hashes not determined |
| G-19 | med | **FIXED** (round 2) | 29868bd | `benchmark/derived.sh` → `derived.md` (7B coordinator CPU; lever hedge counts) from raw data; docs cite it |
| A-1 | low | **FIXED** | (final evidence commit) | `reports/REPRO.md` replaced by the repro run on the final code (see below) |
| C-4, C-5, C-6, C-8 | low | OPEN | – | – |
| D-1 | low | OPEN | – | – |
| E-4, E-5 | low | OPEN | – | – |
| H-1, H-2 | low | OPEN (proposal below) | – | – |
| H-3 | low | **FIXED** (round 2) | d26a5b5 | no released grpc fix (2026-10-04); acceptance extended to 2027-01-31 with justification; `scripts/govulncheck.sh` passes |
| J-1, J-2 | low | OPEN | – | – |
| J-3 | low | **FIXED** (tree) | d23d0f4 | the name no longer appears in any tracked file, including these reports. It remains in the history of 0aac79c; removing it would need a history rewrite, which the audit rules forbid |
| G-24, G-27, G-28 | low | **FIXED** (round 2, under the claims criterion) | 29868bd | THREAT_MODEL line ref; clock-skew provenance ('logs not retained'); CI e2e lines in `reports/gates/ci-e2e-run*.txt` |
| G-20 … G-23, G-25, G-29 … G-35 | low | OPEN (proposal below) | – | – |
| G-26 | low | **FIXED** | (final evidence commit) | REPRO.md replaced |
| D-2, D-3, E-6, F-1, F-2, F-3, H-4, I-2, G-36 … G-44 | info | INFO | – | – |

**Audit tooling fix (found while gating):** the fuzz harness reused a fixture directory owned by
the first fuzz target, so running all targets together failed (each target alone passed, as in
the original runs). Fixed in `reports/audit/fuzz/common_test.go`. The harness is now behind the
build tag `auditfuzz`, so the product gate does not build audit tooling. Seeds:
`go test -tags auditfuzz ./reports/audit/fuzz/` → ok.

### Gates re-run after the fixes
- **Local, HEAD d23d0f4 + reports:** `make vet` (incl. spike), `make lint` (staticcheck, both tags) and `make test` (all packages, the new `cmd/grpc-proxy` and `internal/vaultclient` tests, T5, spike) → **PASS**.
- **Changed scripts:** shellcheck warning count unchanged from the freeze. `topology-guard.sh` is clean.
- **Evidence commits:** gitleaks over the full tree and T11 → clean.
- **Mutations:** M17a and M10b → **CAUGHT**, both at the fix commits and at the final code (MUTATION.md, "Re-runs after fixes").
- **CI and repro on the final commit:** see "Final CI and repro".

### Exit criteria after the fix loop
- **Open critical/high:** **0**.
- **Executed required mutations caught:** **17 of 17** (#17 is now caught). The variant-level survivors M3a, M5a, M14a and M14b (C-3) remain OPEN.
- **Fuzz crashes:** 0.
- **Every claim sentence has evidence:** **not yet**. The claim findings G-7, G-8, G-11–G-15 and G-19 are outside the approved scope and remain OPEN.
- **Fresh-clone repro:** see "Final CI and repro".

### Final CI and repro
- **CI** run [37188818034](https://github.com/raahulkurmi/frost-k8s-threshold-signing/actions/runs/37188818034) on `5fdf63d`: **success**.
  - vet, staticcheck, govulncheck, gitleaks: success.
  - make test (T1–T12, T5 testmalicious, spike hazard tests): success.
  - images + kind e2e (Kubernetes v1.36.5): success.
- **Fresh-clone repro** run [37188822909](https://github.com/raahulkurmi/frost-k8s-threshold-signing/actions/runs/37188822909) on `5fdf63d`: **Overall PASS, 841 s**.
  - Steps: install-base-packages, docker, kind/kubectl/gitleaks/go, node image, make-test 572 s, make-check-images 38 s, make-e2e 179 s.
  - e2e: SETUP, E1–E8, REQ-a–d, N1–N3, TIMING, N76-ID, N76-PRIO all PASS; `REQ-d … quorum_abort=false (default, N82)`.
  - Its `make test` log shows `cmd/grpc-proxy`, `internal/vaultclient` and spike (`TestLibraryHazards`, `TestTamperedShareRejected`) passing.
  - Artifact: `reports/repro/run-37188822909-5fdf63d/`. `reports/REPRO.md` is now this run (A-1, G-26 fixed).
- The commit after 5fdf63d changes only REPRO.md, the repro artifact and this section (documentation and evidence, no code). CI for it is recorded in the final report.

---

## Round 2 (approved 2026-10-04): claims, invariants, C-3, H-3, E-1 extension, history

Fixes are in the resolution table above (marked "round 2"). Commits:
- 29868bd: claims G-7, G-8, G-11–G-15, G-19, plus G-24, G-27, G-28 (the same exit criterion);
- cba14ca: C-3;
- 374a59d: E-1 https;
- fc69a58: B-1;
- d26a5b5: H-3 and the history decision (`reports/HISTORY_PURGE.md` §0–§0a, README note; no history rewrite; snapshot plan, not created).

NOTES N85 and N86 record the corrections to earlier entries, which are not rewritten. The three aborted
result folders stay untracked (G-44).

**Mutation re-runs (round 2):**
- M5a, M14a, M14b: SURVIVED → **CAUGHT**.
- M3a: SURVIVED, documented as unreachable.

Evidence: `mutation/rerun/*-round2.*`.

### Low findings: proposal (not applied; awaiting decision)

| ID | Proposal | Reason (one line) |
|---|---|---|
| C-4 | fix | Add a fake signer echoing a wrong `request_id`; closes surviving mutation X4 with a one-file test. |
| C-5 | fix | Add a fake signer returning `MaxResponseBytes+1` bytes; closes X5 and the THREAT_MODEL C1 "not separately tested" gap. |
| C-6 | fix | Bound the waits in `TestQueuedRequestCancelledByCallerComputesNoShare` so missing admission fails with an assertion, not a 30-minute hang. |
| C-8 | fix | Add exact-edge policy cases (lifetime = max, exp == iat, nbf at ±skew, 63/64- and 253/254-char names); closes 13 live gremlins mutants. |
| D-1 | fix | Reject quoted NumericDates in `policy.num`; strictly tighter, removes the one known (fail-closed) parser differential. |
| E-4 | fix | Dealer refuses a group- or world-writable output directory and removes already-written shares on failure; small, local, testable. |
| E-5 | fix (ControlPath) + accept (TOFU) | Move ssh `ControlPath` from /tmp to `~/.ssh` (cheap). Accept `accept-new`: host keys of freshly launched cloud VMs cannot be pinned without console access; documented. |
| H-1 | fix | Pin `golang`/`alpine` base images by digest in the 4 Dockerfiles; T13 then refers to fixed bases. |
| H-2 | accept | The 4 AWS scripts cannot be re-validated without cloud runs; adding `set -e` would change their failure behaviour untested. |
| J-1 | fix | Correct the §1 "finds 4" sentence in HISTORY_PURGE (the new §0 already states 10) and add a `.gitleaksignore` for the 6 public-kid false positives. |
| J-2 | accept | The paths are inside verbatim evidence outputs (teardown reports, govulncheck output); editing them is a post-hoc change; the anonymized snapshot (HISTORY_PURGE §0a) strips them. |
| G-20 | fix | NOTES correction entry: b-variant offered load is 2.4–3.9×, not 4–6×. |
| G-21 | fix | NOTES correction entry: median refusals at c=10 are 126 (ab) and 36 (abs), worst run 277. |
| G-22 | fix | NOTES correction entry: N56's bound is on the aggregate, not per token. |
| G-23 | fix | Append "(applied in N82, 37f3c5e)" to PRIORITY_ADMISSION_V2 §7/§8. |
| G-25 | fix | CLAIMS_AUDIT row 9: note that the `claims` comment is at lines 48–51 on master (file reformatted elsewhere by 693b7b3). |
| G-29 | fix | KEY_CEREMONY: replace the dead NOTES pointer with "key rotation is not implemented; FetchKeys serves one key". |
| G-30 | fix | HISTORY_PURGE: `.summarize` was added in 9bb1f16 and removed in 6ebb013. |
| G-31 | fix | NOTES correction entry: 7A scale-up ratio is 1.4–1.7×. |
| G-32 | fix | Add a POSTPROCESSING note to the 7C results directory: token runs at 73be90f, summary regenerated at 1e77bee (summary.md not modified). |
| G-33 | accept | The run-time summaries cannot be recovered; both regenerated summaries reproduce byte-for-byte from raw data (verified in Pass G); adopt "keep summary.run-time.md" for future runs. |
| G-34 | accept | Same as J-2: a verbatim script-generated summary; regenerating it would change committed evidence; stripped in the snapshot. |
| G-35 | fix | THREAT_MODEL: "3 signer VMs plus the coordinator VM, all on one Mac". |

### Exit criteria after round 2
- **Open critical/high:** 0.
- **Required mutations caught:** 17 of 17.
- **Variant survivors:** only M3a (documented unreachable), plus X4/X5, which are proposed above as C-4/C-5.
- **Fuzz crashes:** 0.
- **Every claim sentence has evidence:** **yes**. Every CONTRADICTED, STALE or UNSUPPORTED row of CLAIMS_RECHECK was corrected or given evidence (G-5…G-19, G-24, G-27, G-28, I-1).
- **Fresh-clone repro:** see "Final CI and repro, round 2".

### Final CI and repro, round 2
- **CI** run [37202622816](https://github.com/raahulkurmi/frost-k8s-threshold-signing/actions/runs/37202622816) on `7f10c65`: **success**.
  - vet, staticcheck, govulncheck, gitleaks: success (GO-2026-6443 accepted until 2027-01-31).
  - make test incl. T5 and spike: success.
  - images + kind e2e (v1.36.5): success.
- **Fresh-clone repro** run [37202627639](https://github.com/raahulkurmi/frost-k8s-threshold-signing/actions/runs/37202627639) on `7f10c65`: **Overall PASS, 611 s**.
  - Steps: make-test 369 s, make-check-images 31 s, make-e2e 161 s.
  - e2e: all **19** checks PASS (SETUP, E1–E8, REQ-a–d, N1–N3, TIMING, N76-ID, N76-PRIO).
  - Its `make test` log includes `internal/vaultclient`, `cmd/grpc-proxy` and spike.
  - Artifact: `reports/repro/run-37202627639-7f10c65/`. `reports/REPRO.md` is now this run.
- **Correction:** earlier text in this report, and the round-1 commit f4e6a32's message, said "20" e2e checks. The suite has 19; the text above is corrected. A commit message cannot be changed without rewriting history.

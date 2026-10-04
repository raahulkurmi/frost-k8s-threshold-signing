# Pass C: mutation testing

Freeze commit `37f3c5e`, fresh clones, macOS arm64, go1.27.1. Every mutation is an exact-literal source
edit (`mutation/mutations.sh`, `mutation/mutations2.sh`); the full gate was then run:

```
go test -count=1 -timeout 30m ./...                                                     # make test-unit
go test -count=1 -timeout 30m -tags testmalicious -run TestMaliciousSignerExcluded -v ./test/   # make test-malicious
```

`CAUGHT` = at least one test failed (or the suite timed out); `SURVIVED` = everything passed.
Per mutation: `mutation/<ID>.diff` (the edit), `<ID>.summary` (failing tests), `<ID>.log.gz` (full output).
Three unmutated **control** runs (one per lane, under the same machine load, load average ≈ 50) all
passed, so no failure below is a timing flake. (X15's extra `TestNoKeyMaterialFilesInTree` failure
was caused by an empty `secrets/` directory left by my dry run, not by X15; X15 is caught independently.)

## Required mutations (instruction list 1–17)

| # | Mutation | Variant | Edit | Result | Caught by |
|---|---|---|---|---|---|
| 1 | Coordinator skips per-share verification (strict) | M1 | `coordinator.go:354` verifyShare → nil | **CAUGHT** | `TestMaliciousShareExcludedAndAttributed/strict`, T5 `TestMaliciousSignerExcluded/strict/*`, `TestBreakerFallbackToStrict`, `TestThreeMaliciousFails` |
| 2 | Coordinator skips final signature verification | M2 | `coordinator.go:462` `err = nil` | **CAUGHT** | `TestMaliciousShareExcludedAndAttributed/optimistic`, T5 optimistic, `TestBreakerTripMarksSuspect`, `TestBreakerWorkBound`, `TestBreakerRecovery`, `TestBreakerFallbackToStrict` |
| 3 | Coordinator does not dedupe share IDs | M3a | collect-loop dedupe off (`coordinator.go:519`) | **SURVIVED** | – (unreachable: endpoint IDs are unique by construction) |
| | | M3b | `New` duplicate-endpoint check off (`:208`) | **CAUGHT** | `TestNewRejectsBadEndpoints` ("duplicate id") |
| | | M3c | both | **CAUGHT** | `TestNewRejectsBadEndpoints` |
| 4 | Coordinator does not bounds-check share ID | M4a | `wire.ToTcrsa` id range off (`wire.go:90`) | **CAUGHT** | `TestJoinOutOfRangeIDs` |
| | | M4b | `New` endpoint id range off (`coordinator.go:205`) | **CAUGHT** | `TestNewRejectsBadEndpoints` ("id 0", "id 6") |
| | | M4c | both | **CAUGHT** | both tests |
| 5 | Coordinator accepts a share whose ID ≠ signer's mTLS identity | M5a | response-side SAN check off (`coordinator.go:640`) | **SURVIVED** | – (TLS client config already pins `signer-<i>`, `tlsconf.go:139-145`) |
| | | M5b | `signer_id` body check off (`:669`) | **CAUGHT** | `TestShareIDBoundToMTLSIdentity` |
| | | M5c | M5a + M5b + share id taken from the response | **CAUGHT** | `TestShareIDBoundToMTLSIdentity` |
| 6 | Signer accepts a pre-hashed input | M6a | 32-byte base64url signing_input treated as digest | **CAUGHT** | T6 `TestSignerRejectsPrehashedInput` (`raw digest, base64url`) |
| | | M6b | new `digest` request field honoured | **CAUGHT** | T6 (internal/signer, HTTP API case) |
| 7 | Signer skips the policy check | M7 | policy error ignored (`signer.go:378`) | **CAUGHT** | `TestSignerAppliesPolicy`, T7 `TestSignerPolicyRejectsCoordinatorBypass`, `TestSignErrorIsGeneric`, `TestSignerAuditLog`, T6 sub-cases |
| 8 | Policy accepts case-variant duplicate keys (revert N14) | M8 | `policy.go:173` dup/case check off | **CAUGHT** | `TestPolicyRejects/{duplicate iss key, case-variant ISS key, case-variant nested namespace}` |
| 9 | Policy iat skew check removed | M9 | `policy.go:289` off | **CAUGHT** | `TestPolicyRejects/iat too far in {past,future}`, `TestSignerAppliesPolicy`, T7 |
| 10 | Signer loads more than one share | M10a | `keyshare.Parse` trailing-object check off (`keyshare.go:82`) | **CAUGHT** | `TestMultiShareFileRejected` |
| | | M10b | `cmd/signer` loads every comma-separated `SHARE_FILE` entry (extra shares kept in memory) | **SURVIVED** | – |
| 11 | Coordinator package imports a secret share type | M11 | `import internal/keyshare` in coordinator | **CAUGHT** | T12 `TestCoordinatorHasNoSecretTypes` |
| 12 | FetchKeys returns a key other than the group key | M12a | extra key appended | **CAUGHT** | `TestFetchKeysPKIXRoundTrip` |
| | | M12b | other RSA key under the group kid | **CAUGHT** | `TestFetchKeysPKIXRoundTrip`, T1 |
| | | M12c | wrong kid | **CAUGHT** | `TestFetchKeysPKIXRoundTrip`, T1 |
| 13 | Admission control never sheds (revert N48) | M13a | `admitN48` always admits, no slots | **CAUGHT (timeout only)** | `TestQueuedRequestCancelledByCallerComputesNoShare` hung → package timeout after 30 min; no assertion failed first |
| | | M13b | no budget shed, no queue cap, wait 1 h | **CAUGHT** | `TestQueueCapEnforced`, `TestRequestThatCannotFitIsShedImmediately` |
| 14 | Cancellation check removed (revert N46) | M14 | all three `ctx.Err()` checks off | **CAUGHT** | `TestCancelledRequestComputesNoShare`, `TestCancelledDuringSigningDiscardsShare`, `TestExpiredDeadlineNeverComputesShare` |
| | | M14a | only the pre-RSA check off (`signer.go:391`) | **SURVIVED** | – (the after-queue check at :428 still catches it) |
| | | M14b | only the after-queue check off (`:428`) | **SURVIVED** | – (the pre-RSA check still catches it) |
| | | M14c | only the post-RSA check off (`:451`) | **CAUGHT** | `TestCancelledDuringSigningDiscardsShare` |
| 15 | Caller receives detailed policy reason (revert N33) | M15 | `grpcserver/server.go:76` appends `err.Error()` | **CAUGHT** | `TestSignErrorIsGeneric`, T3 `TestBelowThresholdFails(WithAbort)` |
| 16 | mTLS client-SAN check on the coordinator removed | M16 | `tlsconf.go:180` returns nil | **CAUGHT** | `TestTCPListenerRequiresLBClientCert` |
| 17 | QUORUM_ABORT defaults to on (revert N82) | M17a | `cmd/grpc-proxy/main.go:161-166` unset → on | **SURVIVED** | – (see finding C-1; the e2e REQ-d would not catch it either, because every compose file passes `QUORUM_ABORT=${QUORUM_ABORT:-off}`) |
| | | M17b | library: `coordinator.New` abort always on | **CAUGHT** | `TestQuorumAbortOffByDefault`, `TestQuorumImpossibleAbortsEarly/no-abort`, T3, `TestBelowThresholdSigners`, T5 |

**Not executed:** none of the 17. C3 (collusion) was not attempted, as instructed.

**Verdict at the level the instruction states each mutation:** 16 of 17 caught; **#17 survives**.
At variant level, 7 of 33 survive: M3a, M5a, M10b, M14a, M14b, M17a (and M13a is caught only by a
30-minute hang). M3a, M5a, M14a, M14b remove one layer of a two-layer defence. They are equivalent
mutants under the current wiring, so no test can observe them without a fixture that bypasses the
other layer. M10b and M17a are real test gaps (findings C-1, C-2).

## Additional mutations (beyond the list)

| ID | Mutation | Invariant | Result | Caught by |
|---|---|---|---|---|
| X1 | non-canonical JWT header accepted (`jwtfmt.go:95`) | I1/N15 | CAUGHT | `TestSignerRejectsBadHeaders/{duplicate alg, non-canonical order, whitespace}` |
| X2 | audience allow-list off | policy | CAUGHT | `TestPolicyRejects/disallowed aud`, T7, `TestSignErrorIsGeneric` |
| X3 | lifetime cap off | policy | CAUGHT | `TestPolicyRejects/lifetime above max`, T7 |
| X4 | coordinator `request_id` binding check off (`coordinator.go:673`) | I7 | **SURVIVED** | – (finding C-4) |
| X5 | coordinator response-size limit off (`coordinator.go:649`) | DoS | **SURVIVED** | – (THREAT_MODEL C1 already lists "oversized payload: not separately tested") |
| X6 | `keyshare` v^si = vk_i check off | I4 | CAUGHT | `TestCorruptedShareRejected`, `TestWrongShareIndexRejected` |
| X7 | signer rate limit off | C7 | CAUGHT | `TestSignerRateLimit` |
| X8 | deadline header cap off (N76) | C7 | CAUGHT | `TestDeadlineHeaderIsCapped` |
| X9 | sub ↔ kubernetes.io agreement off | policy | CAUGHT | `TestPolicyRejects/sub disagrees…`, T7 |
| X10 | nbf window off | policy | CAUGHT | `TestPolicyRejects/nbf far from iat` |
| X11 | signer accepts any CA-signed client cert | §1 | CAUGHT | `TestTLSRejectsClientWithoutCoordinatorSAN` |
| X12 | audit write failure ignored on the allow path | audit | CAUGHT | `TestSignerRefusesWhenAuditFails` |
| X13 | namespace deny list off | policy | CAUGHT | `TestPolicyRejects/denied namespace` |
| X14 | issuer check off | policy | CAUGHT | `TestPolicyRejects/{missing,wrong} iss`, T7 |
| X15 | coordinator TCP listener without mTLS allowed | I9 | CAUGHT | T8 `TestCoordinatorFailsClosed/TCP_without_gRPC_*` |
| X16 | coordinator threshold t−1 | I5 | CAUGHT | T5, `TestMaliciousShareExcludedAndAttributed` (tcrsa `Join` still demands K = 3) |
| X17 | share-shaped file planted in ignored `secrets/` | I10 | CAUGHT | T11 `TestNoKeyMaterialFilesInTree` |

Independent cross-check by the Pass E/F worker (`raw/EF-f-mutations.txt`, its own clone): dealer `NewKey(b)` instead of
`NewKey(b+1)` → CAUGHT (`TestPublicMetaHasNoSecretFields`); `xi` range check off → CAUGHT (`TestJoinOutOfRangeIDs`);
the other five overlap the table above with the same verdicts.

## Automated mutation testing (gremlins)

gremlins v0.x, `gremlins unleash --workers 4 ./internal/<pkg>` (`raw/C-gremlins-<pkg>.txt`).

| Package | Killed | Lived | Timed out | Not covered | Efficacy | Note |
|---|---:|---:|---:|---:|---:|---|
| policy | 74 | 15 | 0 | 3 | 83.2 % | `--timeout-coefficient 40` (the first run at 3 timed out every mutant during the build and was discarded) |
| grpcserver | 12 | 0 | 0 | 6 | 100 % | |
| signer | 6 | 2 | 1 | – | – | **partial, stopped after 5.5 h**: each mutant re-runs the package's 2048-bit keygen, and hanging mutants wait for the timeout. The 2 lived are in `priority.go:108,110` (priority admission, off by default) |
| coordinator | – | – | – | – | – | **not executed**: same cost as signer (keygen per mutant); the manual mutations M1–M5, M17b, X4, X5, X16 cover its security paths |
| wire, tlsconf, keyshare, dealer | 0 | 0 | 0 | 40 / 38 / 34 / 66 | – | gremlins counts coverage per package and these have no own tests, so every mutant is "not covered"; manual mutations M4a, M10a, X6, X11, M16 and the dealer mutation are the evidence |

**policy survivors (triage, finding C-8):**
- Untested boundaries:
  - `policy.go:111` max lifetime exactly 600 s;
  - `:114` skew exactly 300 s;
  - `:117` rate limit exactly 0;
  - `:282` `exp == iat` accepted if `<=` becomes `<`;
  - `:297` nbf exactly at the skew edge (two mutants);
  - `:402`/`:405` namespace or name of exactly 63/253 characters.
- `Load()` error paths, `:75`/`:79` (exercised only through cmd/ tests).
- Pod-uid extraction, `:360`/`:362` (used only by priority admission).
- `:286:67` (×2): equivalent mutants inside the `Errorf` arguments.

## Coverage (`go test -cover`)

| Package | Own tests | Cross-package (`-coverpkg`, whole suite) |
|---|---:|---:|
| cmd/dealer | 87.2 % | 87.2 % |
| cmd/grpc-proxy | no tests | **0.0 %** (run only as an uninstrumented binary by T8) |
| cmd/signer | 54.7 % | 54.7 % |
| internal/audit | no tests | 80.0 % |
| internal/coordinator | 88.7 % | 90.1 % |
| internal/dealer | no tests | 73.9 % |
| internal/grpcserver | 87.0 % | 87.0 % |
| internal/jwtfmt | no tests | 85.0 % |
| internal/keymeta | no tests | 71.4 % |
| internal/keyshare | no tests | 81.2 % |
| internal/policy | 88.1 % | 92.5 % |
| internal/prioritykey | 33.3 % | 82.5 % |
| internal/signer | 91.0 % | 91.0 % |
| internal/tlsconf | no tests | 81.8 % |
| internal/wire | no tests | 86.2 % |
| **total** | | **78.1 %** |

Exported functions with zero coverage across the whole suite (`raw/C-zero-exported.txt`):
`coordinator.(*Coordinator).BreakerConfig`, `.Strategy`, `.FanoutMode`, `policy.(*Policy).MaxTokenSeconds`,
`signer.(*Server).MaxDeadline`. All five are getters used only by `cmd/*` `run()`, which no test executes
in-process; this is the same blind spot as M17a.

## Re-runs after fixes (fix loop)

Same script, same edits (`mutation/M17a.diff`, `mutation/M10b.diff`), full gate each time.
Evidence: `mutation/rerun/<ID>-<run>.{summary,log.gz}`.

| Mutation | Before (freeze 37f3c5e) | After the fix commit | At the final code (d23d0f4) | Caught by |
|---|---|---|---|---|
| M17a: QUORUM_ABORT binary default on (finding C-1) | SURVIVED | **CAUGHT** (fc4b8ce) | **CAUGHT** | `TestQuorumAbortDefaultsOff`, `TestLoadDefaults` (cmd/grpc-proxy, 2572d08) |
| M10b: signer loads several `SHARE_FILE` entries (finding C-2) | SURVIVED | **CAUGHT** (fc4b8ce) | **CAUGHT** | `TestShareFileMustNameExactlyOneFile/{comma list, comma list 3}` (cmd/signer, fc4b8ce) |

All 17 required mutations are now caught. Negative controls for the new tests:
- E-1: with the fix reverted, `TestNoCrossHostRedirect` fails, because the redirect target received 8 requests carrying the token.
- E-2: with the t−1 rule removed, `TestTopologyGuard` fails on all 3 unsafe placements.

Still surviving (finding C-3, OPEN): M3a, M5a, M14a, M14b; also X4 (C-4) and X5 (C-5).

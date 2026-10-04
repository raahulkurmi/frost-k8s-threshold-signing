# Pass D: fuzzing

Go native fuzzing (go1.27.1, macOS arm64), freeze commit `37f3c5e`. Harness: `reports/audit/fuzz/*_test.go`
(package `fuzz`, under the module root so it can import `internal/...`; behind the build tag
`auditfuzz`, so `make test` does not build it; seeds: `go test -tags auditfuzz ./reports/audit/fuzz/`). Each target ran **10 minutes** with `-parallel=2`, two targets at a time, on a machine also
running the mutation lanes (so exec counts are lower than on an idle host). Logs: `raw/D-Fuzz*.txt`,
schedule: `raw/D-run-status.txt`, seeds: `raw/D-seeds.txt`.

Reproduce one target:
```
go test -tags auditfuzz ./reports/audit/fuzz/ -run '^$' -fuzz '^FuzzPolicyEvaluate$' -fuzztime 10m -parallel 2
```

| Target | Code under test (network or file input) | Oracle | Duration | Execs | New inputs | Result |
|---|---|---|---|---:|---:|---|
| FuzzJWTHeader | `jwtfmt.ParseHeader`, `CheckHeader` | no panic; `CheckHeader` accepts only the canonical `EncodedHeader(kid)` | 10m1s | 2,619,054 | 330 | PASS |
| FuzzSigningInput | `jwtfmt.SplitSigningInput`, `CheckSegment`, `DecodeSegment` | no panic; accepted ⇒ exactly two strict base64url segments, size bound | 10m0s | 3,087,708 | 60 | PASS |
| FuzzPolicyEvaluate | `policy.Evaluate` (claims decoding) | no panic or hang; **differential vs go-jose v2** (`gopkg.in/go-jose/go-jose.v2/jwt`, kube-apiserver's verifier): when the policy accepts, go-jose must see the same iss/sub/aud/exp/iat/nbf/namespace/SA name | 10m1s | 2,448,715 | 194 | PASS (no differential that weakens the policy) |
| FuzzPolicyParse | `policy.Parse` (policy file) | no panic; accepted ⇒ valid config | 10m0s | 2,964,575 | 337 | PASS |
| FuzzSignerHandler | signer HTTP handler: request body + `X-Frost-Deadline-Ms` | no panic or hang (> 5 s); 200 only for a canonical header + policy-compliant claims; the returned share verifies | 10m1s | 1,845,071 | 304 | PASS |
| FuzzShareResponse | coordinator side: response decode (`DisallowUnknownFields`) → `wire.SigShare.ToTcrsa` → tcrsa `Verify` and `Join` with two genuine shares → `rsa.VerifyPKCS1v15` | no panic (tcrsa `Verify` panics for id 0 or id > L), no slow exec, a non-genuine share never yields a verifying signature | 10m1s | 1,308,384 | 91 | PASS |
| FuzzCoordinatorFetch | real `coordinator.Sign` against an httptest mTLS signer returning fuzzed bodies | no panic, return within deadline, never a token from a fuzzed share | 10m1s | **218** | 17 | PASS (low exec count: every exec does TLS + RSA; see limitations) |
| FuzzKeymetaParse | `keymeta.Parse` (public-meta.json) | no panic or hang | 10m1s | 1,739,230 | 126 | PASS |
| FuzzKeyshareParse | `keyshare.Parse` (share-<i>.json) | no panic; never accepts a share with v^si ≠ vk_i | 10m1s | 2,792,039 | 209 | PASS |
| FuzzPriorityKeyParse | `prioritykey` parser | no panic; fail closed | 10m0s | 2,595,635 | 556 | PASS |
| FuzzTimingInterceptor | `grpcserver.TimingInterceptor` (nginx metadata headers) | no panic | 10m0s | 5,159,092 | 40 | PASS |

**Result: 11 targets, 110 minutes of fuzzing, 0 crashes, 0 hangs, 0 accepted-but-invalid inputs.**

## Findings

### D-1: The policy accepts numeric claims written as JSON strings; go-jose v2 rejects them (fail-closed differential)
- Severity: low
- Location: `internal/policy/policy.go:204-216` (`num` decodes into `json.Number`)
- Evidence: `go test ./reports/audit/fuzz/ -run TestObservations -v` (`raw/D-observations.txt`):
  `O1 string iat: policy err=<nil>; go-jose v2 err=claims: go-jose/go-jose/jwt: expected number value to unmarshal NumericDate` (same for exp, nbf).
  Root cause: `encoding/json` accepts a quoted valid number literal when decoding into `json.Number`
  (independently confirmed: `"1700000000"` → `json.Number("1700000000")`, `Int64()` = 1700000000).
- Why it matters: this is a parser differential of the N14 kind, but in the safe direction. The signer signs, and the apiserver
  then rejects the token, so there is no security impact. It still means the policy's view of "valid claims" is not the
  apiserver's view, and the next differential may not be in the safe direction.
- Suggested fix: in `num`, reject a raw value whose first byte is `"`; add a `TestPolicyRejects` case.

### D-2: A share with Xi' = n − Xi passes `Verify` and joins to a valid signature (known, harmless)
- Severity: info
- Location: tcrsa v0.0.5 (`signature_share.go`), NOTES N5 last bullet
- Evidence: `raw/D-observations.txt`: `O2 negated share 3: Verify err=<nil>; Join+VerifyPKCS1v15 err=<nil>`.
- Why it matters: it confirms N5's statement (`Join` uses only even powers of Xi). Share malleability does not affect the token.
- Suggested fix: none; keep the statement in THREAT_MODEL §5.

### D-3: `ParseHeader("null")` returns a zero header without error
- Severity: info
- Location: `internal/jwtfmt/jwtfmt.go:57-72`
- Evidence: `O3 ParseHeader(null) = {Alg: Typ: Kid:}, err=<nil>; CheckHeader err=header alg "", only RS256 is signed`.
- Why it matters: no impact, because `CheckHeader` rejects the result, but `ParseHeader` on its own is not strict.
- Suggested fix: reject a non-object JSON value in `ParseHeader`.

## Not executed / limitations
- **No live slow-loris or HTTP/2 stream-level fuzzing.** The handler was fuzzed in-process (`httptest`). Server timeouts
  (`ReadHeaderTimeout` 5 s, `ReadTimeout`/`WriteTimeout` 10 s, `cmd/signer/main.go:260-268`) were reviewed, not fuzzed.
- **FuzzCoordinatorFetch reached only 218 execs.** It is a smoke-level result for the full TLS path. The decode-level
  target `FuzzShareResponse` (1.3 M execs) covers the same parsing and tcrsa calls.
- **The apiserver's claims structs are mirrored, not imported.** The go-jose v2 differential uses the public `jwt.Claims`
  plus a mirror of `kubernetes.io` private claims from k8s v1.36.5 `pkg/serviceaccount/claims.go`.
- The fuzzing worker stopped (account spend limit) after all runs finished but before writing this report. The lead
  auditor assembled this file from the run logs, which are complete.

# frost-k8s-threshold-signing

**Threshold-signed Kubernetes service account tokens.** kube-apiserver (v1.36+) delegates
service account token signing to an external signer over its ExternalJWTSigner gRPC API
(KEP-740). This repository implements that signer with **Shoup threshold RSA (3-of-5)**:
the RS256 signature on every token is combined from signature shares that at least 3 of 5
signers produce, each holding one share and applying its own claims policy, and **no process
ever holds the whole private key after key generation**. The threshold protects only as far
as the signers fail independently, which is a property of the deployment, not of the code:
no tested deployment gives independent operators, accounts or software
([Trust assumptions](#trust-assumptions)). kube-apiserver verifies the result as an ordinary RS256 JWT against the group
public key; nothing in Kubernetes is modified.

> **Status: open-source research prototype (Apache-2.0).** It has been tested end to end against
> a real kube-apiserver v1.36.5: single host (`make e2e`), multi-VM on one physical host
> (Level 1), and one signer per AWS region (Level 2: **5 regions, one provider, one account,
> one operator, one build, one dealer**; [reports/INDEPENDENCE.md](reports/INDEPENDENCE.md)).
> Final benchmark numbers come from Phase 7C (kubeadm v1.36.5 on AWS); Phase 7A is single-host
> and CPU-contended, Phase 7B is T only with one run per configuration, and the Level 1
> numbers are preliminary (arm64). The threshold RSA library (`niclabs/tcrsa` v0.0.5) is
> **unaudited**. Read
> [Trust assumptions](#trust-assumptions) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
> before relying on anything here.

The repository name comes from an earlier prototype that used FROST. That design could not
work: Kubernetes verifies only RS256/ES256/ES384/ES512, FROST produces Schnorr signatures,
and the prototype in fact signed every token with a single coordinator-held ECDSA key. It is
kept, excluded from every build, in [legacy/frost/](legacy/frost/README.md), with its
original README. Its keys were committed to this public repository and are **burned**
([reports/HISTORY_PURGE.md](reports/HISTORY_PURGE.md)).

## How it works

```
kube-apiserver ──unix socket (dir 0700)──▶ nginx ──mTLS "lb"──▶ coordinator ×3 ──mTLS "coordinator-<k>"──▶ signer ×5
  (FetchKeys: group public key; Sign: header + claims)            (public metadata only)          (one share each,
                                                                                                    own claims policy)
```

1. **Key ceremony (trusted dealer).** `cmd/dealer` generates a 2048-bit Shoup 3-of-5 RSA key
   and writes `public-meta.json` (group public key, share verification keys, `kid`) and one
   `share-<i>.json` per signer. The full private key exists only in the dealer's memory
   during generation ([docs/KEY_CEREMONY.md](docs/KEY_CEREMONY.md)).
2. **Signers** (`cmd/signer`) each hold **exactly one** share. For a request they re-check the
   JWT header byte-for-byte, hash and PKCS#1 v1.5-encode the signing input **themselves**,
   apply an **independent claims policy** (issuer, audience allowlist, maximum lifetime, clock
   skew, subject form, deny lists, rate limit), write an audit record, and only then return a
   signature share. They admit work only if it can finish before the coordinator's deadline.
3. **Coordinators** (`cmd/grpc-proxy`) implement ExternalJWTSigner v1. They hold **only public
   metadata**. They fan the signing input out to the signers, combine 3 shares into a
   standard RS256 signature and verify it against the group key before returning it. By
   default (`optimistic`) shares are verified individually (Shoup proof) only after a failed
   combine, for signers already marked suspect, or in `strict` mode; the final-signature check
   always runs (NOTES N65). Fewer than 3 valid shares → a generic error, never a token.
4. **kube-apiserver** verifies tokens with the key from `FetchKeys` (also served at
   `/openid/v1/jwks`). Verification needs no signer.

## Trust assumptions

State these whenever you describe the system:

- **Trusted dealer.** Shoup threshold RSA needs one. The dealer sees the whole key during
  the ceremony; a dishonest or compromised dealer can forge forever.
- **Signer independence is required for the security claim.** Threshold signing protects
  against compromise of fewer than 3 signers only if signers fail independently (different
  hosts, operators, credentials). The single-host deployment has **none**; the Level 1
  multi-host deployment is **multi-VM on one physical host**; Level 2 puts one signer in each
  of 5 AWS regions but keeps **one provider, one account, one operator, one build and one
  dealer**: whoever controls that account or operator controls every signer
  ([reports/INDEPENDENCE.md](reports/INDEPENDENCE.md)).
- **The signer claims policy limits *what* can be signed, not *who* asks.** Whoever controls
  a coordinator (or kube-apiserver) can obtain tokens for any **policy-compliant** claims
  while in control (an online oracle). What they cannot do is obtain policy-violating tokens,
  or mint tokens after losing control (no share or key is on the coordinator).
  **Under the shipped policy (`deploy/policy.json`, empty deny lists) "policy-compliant"
  includes tokens for kube-system service accounts**, some of which can escalate to cluster-admin (e.g.
  `kube-system:clusterrole-aggregation-controller`, which may escalate ClusterRoles). A live coordinator compromise is
  therefore, while it lasts, effectively a cluster compromise. What bounds it: the issuer,
  audience allowlist and maximum lifetime (7200 s), the ±60 s `iat` window, the per-signer rate
  limit, every signer's audit log, and the end of control (THREAT_MODEL §4). kube-system
  cannot simply be denied, because kube-controller-manager's own controllers use those
  tokens.
- **3 colluding or co-compromised signers can forge.** That is the threshold.
- **Unaudited cryptography.** `niclabs/tcrsa` v0.0.5 (2020) is unaudited and unmaintained;
  the coordinator guards its known hazards (docs/THREAT_MODEL.md §5).
- **Signers need correct clocks.** A signer whose clock is off by more than the policy's skew
  refuses every token (fail closed).

## Quick start

Requirements: **Linux host with Docker Engine** (not Docker Desktop), `kind` v0.31.0,
`kubectl` v1.36.x, Go 1.27.1, `jq`, `openssl`, `gitleaks`. See [NOTES.md](NOTES.md) for
the exact pinned versions and the locally built `kindest/node:v1.36.5-tk8s` image
(`kind build node-image --type release v1.36.5`).

```bash
make test          # unit + integration tests (T1–T12) and the malicious-signer test (T5)
make check-images  # T13: no share, key or cert in any image layer
make e2e           # kind v1.36.5 cluster signing only via the threshold signer: E1–E8, N1–N3, REQ-a–d
make e2e-keep      # same, leave the cluster up; make e2e-down to remove it and its secrets
```

`make e2e` generates fresh certificates and a fresh key, starts 5 signers, 3 coordinators and
nginx (`deploy/docker-compose.yml`), creates a kind cluster whose apiserver has **no**
in-tree service account key, runs every check, and deletes all generated key material on
exit. Each run writes `test/e2e/results/<UTC>-<sha>/e2e.log`.

Multi-host (signers on separate hosts, native binaries under hardened systemd units,
per-host firewalls): [deploy/multihost/README.md](deploy/multihost/README.md), driven by
`test/e2e/multihost.sh` from the operator machine.

## Tests and evidence

| What | Where |
|---|---|
| Invariants I1–I10 (definition, enforcing code, tests) | [docs/INVARIANTS.md](docs/INVARIANTS.md) |
| Unit / integration (T1–T12) | `make test`; `test/`, `internal/*/..._test.go` |
| Image isolation (T13) | `make check-images`; negative control in `reports/gates/gate6-t13-negative-control.txt` |
| Kubernetes e2e (single host) | `make e2e`; `reports/gates/gate6*.log`, `gate6.5*.log` |
| Multi-host e2e + isolation (L1–L5) | `test/e2e/multihost.sh`; `reports/multihost/e2e-*/` (Level 1 and Level 2) |
| Fresh-host reproduction | `make repro` / `.github/workflows/repro.yml`; [reports/REPRO.md](reports/REPRO.md), step logs in `reports/repro/` |
| Benchmarks | `benchmark/results/*/summary.md` (generated from raw CSVs): final Phase 7C `20260927T131349Z-73be90f-7C`; 7A, 7B and Level 1 with their labels |
| Phase 12 adversarial audit | [reports/audit/AUDIT.md](reports/audit/AUDIT.md) (mutation, fuzz, claims recheck) |
| Claims audit | [reports/CLAIMS_AUDIT.md](reports/CLAIMS_AUDIT.md) |
| Every discrepancy and finding | [NOTES.md](NOTES.md) |

Every benchmark number must carry its label and have a row in a script-generated
`summary.md`. **Final numbers: Phase 7C** (kubeadm v1.36.5 on AWS; B0 in-tree / B1 single-key
external signer / T threshold, one session, 3 runs; NOTES N69–N74). Phase 7A (single host,
2 vCPU, all components co-located; CPU-contended) and Phase 7B (Level 2, T only, one run per
configuration) keep their labels; the Level 1 numbers remain **preliminary: arm64, multi-VM on
one overloaded 16 GB host; not for publication**.

## Licensing and patents

- The threshold RSA dependency is **`github.com/niclabs/tcrsa` v0.0.5, used under the MIT
  License** (see [NOTICE](NOTICE)). It is pinned to exactly that version.
- **Later upstream versions of tcrsa reference US patent 10735188** in their license.
- This repository is an **open-source research prototype**, licensed under the
  **Apache License 2.0** ([LICENSE](LICENSE)). Apache-2.0 is compatible with tcrsa v0.0.5's MIT
  license and with every other dependency (BSD-3-Clause, Apache-2.0, MIT).
- **Any commercial use requires independent legal review.**

## Defaults (final, NOTES N82)

| Setting | Default | Notes |
|---|---|---|
| Verification | `VERIFY_STRATEGY=optimistic` plus the breaker | combine t shares and verify the final signature; suspects and a strict fallback after repeated failed combines (N65) |
| Signer admission | `SIGNER_ADMISSION=n48` | deadline-aware bounded admission: `SIGNER_MAX_CONCURRENT` = CPU count, `SIGNER_MAX_QUEUE` = 64, deadline header capped at `SIGNER_MAX_DEADLINE` = 4 s (N48, N76) |
| Quorum-impossible abort | `QUORUM_ABORT=off` | opt-in (`on`). Evaluated: it saves signer work under queueing, but by its pre-registered rule it raised retry-storm wait and amplification (N78, N81) |
| Priority admission | off (`SIGNER_ADMISSION=n48`) | `priority` with controller `v1` or `v2` is selectable but **evaluated, not recommended**: neither met its pre-registered rules ([N78](NOTES.md), [N81](NOTES.md); `docs/PRIORITY_ADMISSION.md`, `docs/PRIORITY_ADMISSION_V2.md`) |
| Coordinator identity | one client certificate per replica (`coordinator-<k>`, `COORDINATOR_ID`) | signers accept only that canonical form (N76) |

## Operations notes

- **Signers need reliable time sync.** Each signer rejects claims whose `iat` is more
  than `clock_skew_seconds` (default 60 s) from its own clock, so a signer with a bad
  clock refuses everything. Run chrony/NTP on every signer host and monitor its offset.
  After a VM resume or snapshot restore, a signer fails closed until its clock resyncs
  (docs/THREAT_MODEL.md §3, NOTES N44). The multihost scripts refuse to run when any host is
  more than 1 s off (NOTES N50).
- **Verification strategy.** Coordinators default to `VERIFY_STRATEGY=optimistic`:
  combine t shares, verify only the final signature, and verify shares individually
  only after a failed combine. A signer whose share fails verification becomes a
  *suspect* for `BREAKER_SUSPECT_COOLDOWN` (default 10m): its shares are verified
  before they are combined. `BREAKER_FALLBACK_AFTER` (default 3) failed combines within
  `BREAKER_FALLBACK_WINDOW` (1m) switch to strict for `BREAKER_FALLBACK_COOLDOWN`
  (10m). `strict` verifies shares until t are valid. Both strategies verify the final
  signature against the group key before returning a token (NOTES N65).
- **Timing logs.** nginx writes one JSON timing line per request, and the coordinators'
  `signed`/`sign failed` lines carry `nginx_request_id`, `nginx_to_coordinator_ms`,
  `queued_before_sign_ms` and `incoming_deadline_ms`; `benchmark/single/timing-breakdown.sh`
  joins them (NOTES N64).
- **Signer capacity.** Each signer computes at most `SIGNER_MAX_CONCURRENT` shares at once
  (default: CPU count). Further requests wait only while they can still meet the
  coordinator's deadline (sent in `X-Frost-Deadline-Ms`) and fewer than `SIGNER_MAX_QUEUE`
  (default 64) are waiting; otherwise they get `503` immediately (NOTES N46, N48).
- **Who can call Sign.** Only root on the coordinator host / control-plane node (the socket
  directory is `root:root 0700`) and nginx holding the `lb` key. Nothing is published to the
  host network (docs/THREAT_MODEL.md §1).
- **Errors are generic by design.** A token requester sees only `token signing failed: …`;
  which signer refused and why is in the coordinator log and the signers' audit logs (N33).

## Repository layout

| Path | Contents |
|---|---|
| `cmd/dealer`, `cmd/signer`, `cmd/grpc-proxy` | Key ceremony, signer, coordinator (ExternalJWTSigner) |
| `internal/` | `keymeta` (public), `keyshare` (one secret share), `policy`, `signer`, `coordinator`, `grpcserver`, `jwtfmt`, `wire`, `tlsconf`, `audit`, `dealer`, `testutil` (tests only) |
| `deploy/` | Single-host compose, multi-host compose and scripts, nginx config, policy |
| `test/`, `test/e2e/` | T1–T12 suite, kind e2e, multi-host orchestrator, probe |
| `benchmark/` | `tokenbench` (client-go), `summarize`, drivers, results |
| `spike/` | Phase 0 evidence that tcrsa produces RS256 tokens kube-apiserver's verifier accepts |
| `legacy/frost/` | The abandoned FROST prototype (separate module, `//go:build legacy`) |
| `docs/`, `reports/` | Threat model, key ceremony, claims audit, independence, history purge, gate evidence |

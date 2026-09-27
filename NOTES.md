# NOTES

Pins, and discrepancies between the task prompt, the libraries, and upstream
Kubernetes. Newest entries are appended per phase.

## Environment (recorded 2026-09-24)

| Item | Value | Source |
|---|---|---|
| Kubernetes target | **v1.36.5** (latest v1.36 patch), commit `ad950d1cc78b0183c476bd4d3f1934c104229727` | GitHub releases API, `repos/kubernetes/kubernetes/commits/v1.36.5` |
| Kubernetes optional re-run | v1.37.1 (latest v1.37 patch at time of writing) | GitHub releases API |
| Go | **go1.27.1** darwin/arm64 (latest stable; via `GOTOOLCHAIN=go1.27.1`, local install is go1.26.3) | `https://go.dev/dl/?mode=json` |
| kind | v0.31.0 (built with go1.25.5) | `kind version` |
| kubectl client | v1.35.1 (one minor behind the v1.36 control plane; within supported skew) | `kubectl version --client` |
| gitleaks | 8.30.1 | `gitleaks version` |
| jq | 1.8.1 | `jq --version` |
| Docker | 28.3.2, Docker Desktop | `docker info` |
| Host (Phases 0–5) | macOS Darwin 25.6.0, arm64. Phases 6–7 run on a Linux VM that the user will provide. | `uname -a` |
| tcrsa | `github.com/niclabs/tcrsa` **v0.0.5** (2020-12-07) | proxy.golang.org |

## Discrepancies and findings

### N1. kube-apiserver uses go-jose **v2**, not v4 (Phase 0)
The prompt says to verify with `github.com/go-jose/go-jose/v4`. In k8s v1.36.5,
`go.mod` pins `gopkg.in/go-jose/go-jose.v2 v2.6.3`. Every jose import in
`pkg/serviceaccount` is `gopkg.in/go-jose/go-jose.v2` (5 imports) or `.../jwt` (6).
The spike verifies with **both** v2.6.3 (what the apiserver actually runs) and
go-jose v4.1.5, plus `rsa.VerifyPKCS1v15`.

### N2. Header constraints enforced by the apiserver (Phase 0)
`pkg/serviceaccount/externaljwt/plugin/plugin.go` `validateJWTHeader` at v1.36.5
decodes the header with `DisallowUnknownFields` into `{alg,kid,typ}`. It requires
`typ == "JWT"`, a non-empty `kid` of at most 1024 bytes, and `alg` in
{`RS256`,`ES256`,`ES384`,`ES512`}. The plugin has no RSA key size check.
`FetchKeys` keys are parsed with `x509.ParsePKIXPublicKey` (`keycache.go`).

### N3. tcrsa `NewKey(b)` yields a (b−1)-bit modulus (Phase 0)
`key.go` sets `pPrimeSize=(b+1)/2` and `qPrimeSize=b-pPrimeSize-1`. Go's
`crypto/rand.Prime` sets the top two bits of every candidate, so the modulus is
exactly `b-1` bits. `NewKey(2048)` would give a 2047-bit key. The spike and the
dealer call **`NewKey(2049)`**, which gives a 2048-bit modulus (1025-bit p, 1023-bit q).
The test `TestTcrsaModulusIsBitSizeMinusOne` checks this at 512 bits.

### N4. tcrsa API facts (confirmed in source, v0.0.5)
- `NewKey(bitSize int, k, l uint16, args *KeyMetaArgs) (KeyShareList, *KeyMeta, error)`.
  It requires `l/2+1 <= k <= l` (honest majority), so 3-of-5 is allowed. e = 65537.
- `KeyShare{Si []byte; Id uint16}`, where Id is 1-based.
  `KeyMeta{PublicKey *rsa.PublicKey; K, L uint16; VerificationKey *VerificationKey{V,U []byte; I [][]byte}}`.
- `PrepareDocumentHash(size, crypto.SHA256, digest)` produces the EMSA-PKCS1-v1_5 encoding.
  `KeyShare.Sign` expects an already padded document. Our signers must call
  `PrepareDocumentHash` themselves (I8).
- `SigShare{Xi, C, Z []byte; Id uint16}`. `SigShare.Verify(doc, meta)` checks
  Shoup's proof of correctness.
- `SigShareList.Join(doc, meta)`: rejects fewer than K shares. It does **not** verify
  shares, does **not** dedupe Ids, and uses only the first K entries.
- `KeyShare.Sign` has no shared mutable state (it reads `meta`, uses `crypto/rand`),
  so signers don't need a mutex.

### N5. tcrsa hazards the coordinator must guard (Phase 0, tested in `TestLibraryHazards`)
- `SigShare.Verify` **panics** when `Id == 0` or `Id > L` (it indexes
  `VerificationKey.I[Id-1]`). The coordinator must bounds-check `Id` in `[1,n]`
  and match it to the responding signer before calling Verify.
- `Join` with duplicate Ids returns no error and an invalid signature. The coordinator
  must dedupe by Id.
- `Join` with an unverified bad share returns no error and an invalid signature.
  The coordinator must verify each share and then the final signature (already
  required by the Phase 4 design).
- A share with `Xi' = n − Xi` also passes `Verify`. This is harmless: Join uses only
  even powers of Xi, so the combined signature is the same.

### N6. tcrsa LICENSE changed after v0.0.5: patent notice (Phase 0), needs your decision
- v0.0.5 (the tagged version we depend on, 2020-12-07) ships the **MIT** license.
- The master commit `f8ebd8f` (2021-01-11, "Update LICENSE", the only change after
  v0.0.5) replaces it with a custom license. That license states the threshold
  signing process is protected by **US patent 10735188** (and Chile 2015003766), and
  that commercial use must be cleared with Universidad de Chile. It grants use only
  in Open Source Software, and only if the use "does not infringe the patent".
- A patent claim applies regardless of which copyright license a given code
  version carries. **This needs legal review before any commercial or non-OSS use.**
  It doesn't block the research prototype, but it has to be recorded.

### N7. ExternalJWTSigner proto versions present at v1.36.5
Both `staging/src/k8s.io/externaljwt/apis/v1alpha1/api.proto` and `.../v1/api.proto`
exist. Phase 4 will confirm which version the apiserver client dials.

## Repository housekeeping

### `nohup.out`
Tracked. Added in `f91807b`. 8,600,559 bytes, 296,571 lines. Every line is
`sh: socat: command not found`. The pattern scan found 0 PEM blocks, 0 private-key
markers, 0 JWTs, 0 hex runs of 64+ characters, 0 password mentions, 0 Vault tokens,
and 0 share/secret mentions. `gitleaks dir` reported no leaks. It is not a secret.
It goes on the Phase 1 cleanup list and into `reports/HISTORY_PURGE.md` as repo bloat.

## Decisions carried from Gate 0 review (2026-09-24)

- **License (N6):** pin `github.com/niclabs/tcrsa` at exactly **v0.0.5** (MIT) in the main
  `go.mod` and never upgrade to master. Phase 8 adds a `NOTICE` file and a README
  "Licensing and patents" section. It will say only that the dependency is tcrsa v0.0.5
  under MIT, later upstream versions reference US patent 10735188, this repository is an
  open-source research prototype, and any commercial use needs independent legal review.
- **Verifier (N1):** go-jose **v2.6.3** is the primary verifier in all tests. v4 is secondary.
- **R-a (Phase 2/4):** test the FetchKeys path end to end:
  `x509.MarshalPKIXPublicKey` → `x509.ParsePKIXPublicKey` → go-jose v2 verify of a
  threshold-signed token.
- **R-b (Phase 4):** before Join, always bounds-check `Id ∈ [1,n]`, check that `Id` matches
  the responding signer's mTLS identity, and dedupe by `Id`. Add a spike-style test of
  Join's behavior with out-of-range Ids.
- **R-c (Phase 4/7):** support two verification strategies behind a config flag and benchmark both:
  - `strict`: verify every share in parallel goroutines, Join, verify the final signature.
  - `optimistic`: Join the first t well-formed shares and verify the final signature. Only if
    that fails, verify each share to find and exclude the bad signers, then retry.

  Both must attribute bad shares (I7) and both must verify the final signature. The default
  is `strict`.
- **R-d (Phase 8):** THREAT_MODEL.md states that tcrsa is unaudited and unmaintained since
  2020, lists the N5 hazards, and states how the coordinator mitigates each one.
- **R-e:** `spike/` and `spike/gate0-output.txt` are permanent evidence. Never delete them.
- **nohup.out:** remove it from the tree in Phase 1, add it to `.gitignore`, and list it in
  HISTORY_PURGE.md under "bloat", not "leaks".

## Upstream facts gathered for Phases 3–4 (k8s v1.36.5)

### N8. Proto version: **v1**
`pkg/serviceaccount/externaljwt/plugin/plugin.go` imports
`externaljwtv1 "k8s.io/externaljwt/apis/v1"`. The proto is
`staging/src/k8s.io/externaljwt/apis/v1/api.proto` (proto package `v1`, service
`v1.ExternalJWTSigner`). The repo's current stubs are labelled `v1alpha1` but declare
`package v1`.
- `SignJWTRequest.claims` is "URL-safe base64 wrapped payload to be signed. Exactly as it
  appears in the second segment of the JWT". It is already base64url, so we must not
  re-encode it.
- `SignJWTResponse.header` and `.signature` are already base64url. The header may contain
  only alg/kid/typ.
- `FetchKeysResponse.refresh_hint_seconds <= 0` is a misconfiguration. `data_timestamp` is
  "when this data was pulled from the authoritative source".
- `Key.key` is PKIX. The supported algorithms listed are "RSA 256 or ECDSA 256/384/521".
- `MetadataResponse.max_token_expiration_seconds` must be at least 600. The extended
  expiration is `min(1 year, max)`. A `--service-account-max-token-expiration` greater
  than max is fatal.

### N9. `sub` form (the prompt's regex is wrong)
`pkg/serviceaccount/claims.go` `Claims()` always sets `sub = MakeUsername(ns, name)` =
`system:serviceaccount:<ns>:<name>`. No node or other subject form is issued, and node
binding only adds `kubernetes.io.node`. However:
- namespace = `NameIsDNSLabel`: `[a-z0-9]([-a-z0-9]*[a-z0-9])?`, at most 63 characters.
- SA name = `NameIsDNSSubdomain`: DNS-1123 subdomain, which **may contain dots**, at most 253 characters.

The prompt's regex `^system:serviceaccount:[a-z0-9-]+:[a-z0-9-]+$` would reject valid SA
names that contain dots (and would accept leading or trailing hyphens). The signer policy
uses the upstream validation rules instead.
Other claims: `iat == nbf == now`, `exp = now + expirationSeconds`, `jti` (UUID),
`kubernetes.io.{namespace, serviceaccount{name,uid}, pod|secret|node, warnafter}`, and `iss`,
which the plugin merges in via `mergeClaims(p.iss, ...)`.

### N10. More fail-open and weak-auth paths found in the old code (beyond D1–D12)
- `cmd/signer/main.go` falls back to **plain HTTP** when the CA file is missing, and uses
  `ClientAuth: tls.RequestClientCert`, which **never verifies** the client cert.
- `deploy/docker-compose.yml` and `scripts/vault-init.sh` hardcode the Vault dev root token
  `frost-dev-token`.
- `internal/keystore` derives the AES key as a single unsalted SHA-256 of the password (no KDF).
- The compiled Mach-O binaries `grpc-proxy` and `signer` are committed at the repo root.
  They contain the `frost-dev-password` default string.
- `deploy/ nginx-grpc.conf` (with a leading space) duplicates `deploy/nginx-grpc.conf`.
  `deploy/cmd/encrypt-keys` and `deploy/internal/keystore` duplicate top-level code.

## Phase 3 notes

- **N11. The FROST move happened at the start of Phase 3, not Phase 5.** The old
  `cmd/signer` and `cmd/grpc-proxy` are FROST code. They had to be relocated before
  being rewritten, or they would have been silently deleted (rule 4). Every FROST and
  legacy file now lives in `legacy/frost/`, a **separate Go module**
  (`frost-k8s-threshold-signing/legacy/frost`), with `//go:build legacy` on every `.go`
  file. It still compiles with `cd legacy/frost && go build -tags legacy ./...`. The
  separate module is what lets `go mod tidy` drop bytemare from the main `go.mod`:
  tidy ignores build tags, so a build tag alone would have kept the dependency.
  Gate 5 checks still run at Phase 5.
- **N12. `internal/signing/ecdsa.go` was moved into `legacy/frost/internal/signing`,
  not deleted.** The legacy `grpc-proxy` (the D1 evidence) imports it, so the legacy
  tree would not compile without it. `cmd/genkey` (pure ECDSA keygen, D3) was deleted
  outright. Neither is reachable from any runtime binary (Gate 4 grep, Gate 5 deps).
- **N13. Wire format.** The prompt shows `"share": "..."` as a string. The signer
  returns `"share": {"xi","c","z"}` (base64 std) plus `signer_id`. The share's index is
  never taken from the payload: the coordinator uses the mTLS-authenticated signer
  identity (R-b).
- > ⚠️ **HIGHLIGHTED FINDING N14 (security): JSON parser differential between signer policy and apiserver verifier.**
  **Policy decoding is case- and duplicate-strict.** Go's `encoding/json` struct
  decoding is case-insensitive and last-wins. go-jose v2 uses a case-sensitive fork.
  Decoding `{"iss":"evil","ISS":"good"}` into a struct would let a coordinator pass
  the policy with one value while the apiserver verifies the other. The policy
  therefore decodes exact keys and rejects duplicate or case-variant keys, at the top
  level and inside `kubernetes.io` (tested in `TestPolicyRejects`).
- **N15. The header is checked byte-for-byte.** The signer requires the header segment
  to equal `base64url({"alg":"RS256","typ":"JWT","kid":"<kid>"})` exactly, after
  giving specific reasons for alg none/ES256/other, a wrong kid and extra fields.
- **N16. The signer requires `kubernetes.io.namespace` and `.serviceaccount.name` to
  match `sub`.** Upstream always emits them (`claims.go`).
- **N17. Dependency:** `golang.org/x/time/rate` v0.16.0 provides the per-signer token bucket.
- **N18. No mutex around signing.** `tcrsa.KeyShare.Sign` (v0.0.5 `key_share.go`) keeps
  no shared mutable state: it reads `KeyMeta` and draws randomness from `crypto/rand`.

## Phase 4 notes

- **N19. Proto source.** The stubs are not regenerated. The coordinator imports
  `k8s.io/externaljwt/apis/v1` from module **k8s.io/externaljwt v0.36.5**, which is the
  published mirror of `kubernetes/kubernetes@ad950d1cc78b0183c476bd4d3f1934c104229727`
  `staging/src/k8s.io/externaljwt/apis/v1/` (module origin
  `kubernetes/externaljwt@c225e1714ecbc2ffbfe9e2c7ced8347e9c194463`, tag v0.36.5).
  `api.proto`, `api.pb.go` and `api_grpc.pb.go` were checked **byte-identical** to the
  v1.36.5 staging files, so these are the exact stubs kube-apiserver is compiled
  against. Regenerating would only have added protoc-version drift. This deviates
  from the prompt's "regenerate stubs"; the result is stricter.
- **N20. FetchKeys fields.** Returns a single key `{key_id: kid, key: PKIX DER,
  exclude_from_oidc_discovery: false}`. `data_timestamp` = `public-meta.json`
  `created_at`, so every replica returns byte-identical output (E8) instead of
  `time.Now()`. `refresh_hint_seconds` = 3600 (configurable, must be > 0).
  `Metadata.max_token_expiration_seconds` comes from the same `policy.json` the
  signers load, so the two values are equal by construction.
- **N21. tcrsa Join with out-of-range Ids does not panic.** `TestJoinOutOfRangeIDs`
  shows Ids 0, 6 and 65535 return no error and an invalid signature (Verify is the
  call that panics, N5). `wire.ToTcrsa` rejects Ids outside `[1,n]` before tcrsa sees
  them. The coordinator also checks that the peer's TLS cert is exactly
  `DNS:signer-<id>` and that `signer_id` in the body matches (R-b).
- **N22. Strategy results (in-process, 2048-bit, macOS; indicative only, Phase 7
  measures properly).** Strict ≈ 15 ms per token, where share verification (~5–6 ms)
  runs in parallel with fan-out. Optimistic ≈ 10 ms on the happy path. With one
  corrupted share, both exclude and attribute it (`TestMaliciousShareExcludedAndAttributed`).
- **N23. Deployment topology.** nginx listens on the Unix socket
  (`listen unix:/var/run/frost-k8s/signer.sock http2`) that kube-apiserver dials, and
  load-balances to 3 coordinator replicas over the compose network. This removes
  socat from the primary (Linux) path. The nginx→coordinator hop is plaintext gRPC
  on a private Docker network; upstream expects a local socket. That goes in
  THREAT_MODEL.md.
- **N24. The Gate 4 grep matches `crypto/ecdsa` in `internal/testutil/testpki.go`**
  (throwaway TLS certs for tests). No runtime binary links testutil
  (`go list -deps`, in `reports/gates/gate4.txt`). The runtime-only grep is empty.
  `crypto/ecdsa` shows up in every binary's dependencies because `crypto/tls` and
  `crypto/x509` import it for TLS; it is not a JWT signing path.
- **N25. Keygen time varies widely:** 11 s, 18.7 s and 68 s observed for single
  2048-bit keys; 52–74 s with two running in parallel. Each test binary generates
  one key, so `go test ./...` takes about 1.5 minutes.

## Phase 6 environment (Linux VM, driven from the Mac via `multipass exec`)

| Item | Value |
|---|---|
| VM | Multipass 1.16.4 (macOS host), instance `tk8s`, Ubuntu 24.04.5 LTS, `Linux tk8s 6.8.0-139-generic #139-Ubuntu SMP PREEMPT_DYNAMIC Sat Aug 1 03:32:48 UTC 2026 aarch64` |
| Resources | 4 vCPU (arm64), 7.7 GiB RAM, no swap, 38 GB disk |
| Docker | Docker Engine 29.8.1 (docker.com apt repo, not snap), cgroup v2 / systemd, Compose v5.5.1 |
| kind | v0.31.0 (sha256 verified) |
| kubectl | v1.36.5 (sha256 verified) |
| gitleaks | 8.30.1 (checksums.txt verified) |
| Go | go1.27.1 linux/arm64 (sha256 from go.dev verified) |
| jq / openssl / git | 1.7 / 3.0.13 / 2.43.0 |
| First `multipass launch` | Failed: the image download stopped at 70% and failed its hash check. The retry succeeded. |

### N26. No published kind node image for v1.36.5
Docker Hub `kindest/node` has v1.36.1 and v1.36.4 but no v1.36.5, and kind v0.31.0's
default is `v1.35.0@sha256:452d707d…`. To keep the pinned patch, the node image was
built in the VM from the official v1.36.5 release binaries:
`kind build node-image --type release v1.36.5 --image kindest/node:v1.36.5-tk8s`
→ image ID **`sha256:2c8e428b7d8141e273b8149bbcbccb9d21bebfe2a0bd3d98ede6a9c9cfe16286`**
(arm64, built in 5m48s). The image is local and was not pulled, so the image ID is the
reproducible identifier here. `kubeadm version` inside it prints `v1.36.5`.

### N27. Requirement (a): token expiration at v1.36.5 (source)
- `pkg/controlplane/apiserver/options/options.go` `(*Options).completeServiceAccountOptions`:
  the signing endpoint calls `Metadata` at startup (10 s timeout). If
  `max_token_expiration_seconds < validation.MinTokenAgeSec` it errors.
  If `--service-account-max-token-expiration` is **unset**, it defaults to
  `max_token_expiration_seconds`. If it is set **greater** than that, startup fails.
  `MaxExtendedExpiration = min(maxExternalExpiration, ExpirationExtensionSeconds=1y)`.
  If the flag is set explicitly it must also be within [1h, 2^32 s].
- `pkg/registry/core/serviceaccount/storage/token.go` `(*TokenREST).Create`: a requested
  `expirationSeconds` greater than max is **capped** to max (line 222, with a warning).
  The extension applies only when `extendExpiration` is set, the token is pod-bound,
  `expirationSeconds == WarnOnlyBoundTokenExpirationSeconds (3607)`, and the audiences
  are the apiserver's own. Then `warnafter = 3607` and `exp = MaxExtendedExpiration`.
- kubelet requests projected tokens with `expirationSeconds: 3607` by default. With a
  max of 3600, the request is capped to 3600, the extension never fires, and there is no
  `warnafter`. With a **max of 7200** (the deployed `deploy/policy.json`, reported
  identically by `Metadata`), 3607 is below the max, so the extension fires:
  **`exp − iat = 7200`, `warnafter − iat = 3607`**. The e2e measures this (REQ-a).
- `ExternalServiceAccountTokenSigner` is **GA and LockToDefault=true** at 1.36
  (`pkg/features/kube_features.go:1471`), so no feature gate flag is needed.

### N28. kubeadm flags vs the signing endpoint (kind config)
`pkg/kubeapiserver/options/authentication.go:623`: `--service-account-key-file` and
`--service-account-signing-endpoint` are mutually exclusive. `options.go`:
`--service-account-signing-key-file` and the endpoint are mutually exclusive too.
kubeadm always emits both key flags and they can't be unset through `extraArgs`.
Their exact positions came from probe clusters. kubeadm writes the sorted base flags
first. Any `extraArgs` entry that **overrides** a base flag (our explicit
`service-account-issuer`) is taken out of the sorted list and **appended** at the end,
together with kind's `--runtime-config=`. New flags (`service-account-signing-endpoint`)
are also appended. With our config, `--service-account-key-file` is at command index
**22** and `--service-account-signing-key-file` at **23**. The first e2e run used the
stock-layout indices 23/24; the `test` guard **failed `kind create` closed**
(`testing value /spec/containers/0/command/24 failed`), and a retained probe with our
exact extraArgs gave the real layout. `test/e2e/kubeadm-patches/*.json` removes them with
JSON patches guarded by `test` ops on the exact values, so a layout change fails
`kind create` loudly. The same patch removes the controller-manager's
`--service-account-private-key-file`. Otherwise the legacy token controller would keep
an in-tree **single-key** signing path for `kubernetes.io/service-account-token`
Secrets, violating I1 at the cluster level. After creation the e2e deletes
`/etc/kubernetes/pki/sa.{key,pub}` from the node to prove nothing uses them.

### N29. The scheduler does not use service account tokens
The prompt says the E4 scheduler's "tokens are threshold-signed". kube-scheduler
authenticates with the x509 client certificate in `/etc/kubernetes/scheduler.conf`, not
an SA token, so E4 only checks that it keeps working (restart count unchanged). The
controller-manager (`--use-service-account-credentials=true`) runs each controller as its
own SA with TokenRequest tokens. E4 checks that the signer audit logs contain
`kube-system:deployment-controller` and `replicaset-controller` allow decisions.

### N30. `httptest` / net/http cancellation detail (test fixture)
For HTTP/1.1, net/http only detects a client disconnect, and cancels `r.Context()`,
after the handler has consumed the request body. `testutil.Delay` now reads the body
first. Before that, cancelled requests to "slow" signers kept `httptest.Server.Close`
blocked for the full delay. Production signers decode the body immediately, so the
production path was never affected.

### N31. e2e harness hang (run 2)
In run 2 (commit `f077169`), SETUP, E1–E7 and REQ-a/b/c passed, then the script hung
at E8's rolling restart. A bare `wait` after `docker restart … &` also waits for the
logging process substitution `exec > >(tee …)`, which never exits (bash ≥ 5.1
behavior). This was a harness bug, not a system failure; the partial log is kept in
the VM as `~/e2e-run2-hung.out`. Fixed by waiting on the restart's own PID with a
60 s `timeout`. Gate 6 evidence comes from a complete clean rerun.

### N32. T11 caught generated secrets left in the VM working tree
The e2e run's teardown removed the cluster and containers but left `secrets/` (CA key,
7 TLS keys, all 5 shares) in the VM's working tree. The files are gitignored, so they
were never committable, but I10 requires a clean tree, and `make test` at `ab2de56`
failed T11 `TestNoSecretsInTree` (7 `private-key` findings). **gitleaks flagged the PEM
keys but not the five `share-<i>.json` files** (bare base64 has no rule). Fixes:
`run.sh` wipes `secrets/`, `run/` and `audit/` in an EXIT trap (audit logs are copied into
the results directory first; `--keep` deliberately keeps them), `make e2e-down` wipes
them too, and T11 gained `TestNoKeyMaterialFilesInTree`, a tree walk that includes
ignored directories and catches share files regardless of gitleaks.

## Phase 6 results: every e2e run and the commit it used

| Run | Commit | Outcome |
|---|---|---|
| 1 | `2e05943` | **Failed closed at `kind create`.** The guarded kubeadm patch's `test` op found an unexpected flag at index 24 (N28). No cluster was created. Log: `reports/gates/gate6-e2e-run1-2e05943-patch-guard-failed-closed.log` |
| 2 | `f077169` | SETUP, E1–E7, REQ-a/b/c PASS; **harness hung** at E8 (bare `wait`, N31). Log: `…run2-f077169-harness-hang.log` |
| 3 | `2f2d7bc` | SETUP, E1–E8, REQ-a/b/c PASS; **harness crashed** at REQ-d (`jq` on prefixed compose logs). Log: `…run3-2f2d7bc-harness-crash.log` |
| 4 | `ab2de56` | **E2E: PASS** (all 13 checks). A later `make test` failed T11 because `secrets/` outlived the run (N32). Log: `…run4-ab2de56.log` |
| 5 (Gate 6) | **`152941b`** | **E2E: PASS** (13/13), then **`make test` PASS** on the post-e2e tree, then **`make check-images` PASS**. Logs: `reports/gates/gate6-final-152941b.log`, `gate6-e2e-final-152941b.log`, `gate6-test-suite-T1-T12-152941b.log` |

Observations from the passing runs:
- **REQ-a:** the kubelet-projected token (pod `e3-client` on `tk8s-worker`) has
  `exp − iat = 7200 s` and `warnafter − iat = 3607 s`, and it passes TokenReview.
  This matches N27.
- **REQ-b:** a non-allowlisted audience is refused by all 5 signers. The apiserver
  returns `Internal error occurred: failed to generate token: … threshold not met: 0
  valid shares, need 3; failures: [signer-3: refused (HTTP 403 policy): aud: audience
  "not-allowlisted" is not allowed; …]`. **The signer policy reason reaches the token
  requester.** Operators benefit, but callers learn which rule fired; this goes into
  THREAT_MODEL.md (Phase 8).
- **E6:** with 3 signers down, refusal takes 67–136 ms, not the 2 s deadline, because
  a stopped signer fails immediately (DNS `server misbehaving` / connection refused).
  A signer that hangs instead would hit the deadline (T10).
- **E7:** docker start → first successful token took 380–636 ms across runs. This
  includes one `kubectl` process start per attempt.
- **E4:** the scheduler uses an x509 client cert (N29). The controller-manager's
  `deployment-controller` and `replicaset-controller` tokens were allowed by all 5
  signers.
- **E6 log line:** the harness grepped for `threshold not met`, which appears only in the
  returned error (shown in full in kubectl's output), not in the coordinator's log line
  (`"msg":"sign failed"`). The grep is fixed in `152941b`.
- **Not done:** the optional v1.37.x re-run (the prompt says "at the very end"). The
  apiserver path deleted `sa.key` and nothing broke, but that is not a formal test.

## Phase 6.5 notes

### N33. Requesters see only generic signing errors (fixed)
Gate 6 showed kube-apiserver relaying the coordinator's detailed error to the token
requester: per-signer reasons and the refused audience value. `internal/grpcserver`
now returns fixed messages (`token signing failed: threshold not met` / `…: invalid
request` / `token signing failed`). The details stay in the coordinator log and the signer
audit logs. Tests: `TestSignErrorIsGeneric`, e2e REQ-b and E6. See THREAT_MODEL §2.

### N34. Who can call Sign: design choice (Phase 6.5)
Gate 6's stack exposed nginx on TCP 9090 (published to the host's loopback) and
coordinators on unauthenticated gRPC. Now:
- **Network:** two `internal` bridges, `lb-net` (nginx + coordinators) and `signer-net`
  (coordinators + signers), both with `com.docker.network.bridge.inhibit_ipv4=true`.
  A probe in the VM showed that `internal: true` **alone does not stop the host**
  connecting: Docker gives the host the bridge gateway IP. `inhibit_ipv4` removes that
  address, so the host's route to those subnets leads nowhere. Nothing is published.
  nginx listens only on the Unix socket.
- **Identity:** mTLS nginx→coordinator. The coordinator's TCP listener requires a
  client cert with exactly `DNS:lb`, and it presents `DNS:coordinator-grpc`. There is
  **no plaintext TCP mode** (T8: `TCP_ADDR` without `GRPC_TLS_*` refuses to start).
- **Why mTLS rather than network isolation alone:** isolation depends on Docker's
  iptables and bridge options being right, a single misconfiguration (for example a
  future `ports:` line) away from exposure. mTLS keeps authentication independent of
  topology and carries over unchanged to multi-host (Phase 7B), where the
  nginx→coordinator or coordinator→signer hops cross real networks. The alternative
  considered was coordinators listening on Unix sockets in a volume shared with nginx.
  That also avoids TCP, but it is filesystem ACLs only, doesn't extend to multi-host,
  and differs from the signer hop.
- **Separate certs per role:** `coordinator` (clientAuth → signers), `coordinator-grpc`
  (serverAuth ← nginx) and `lb` (clientAuth → coordinators). Signers reject `lb`, and
  coordinators reject `coordinator` and signer certs as gRPC clients (N1).
- **Retries:** see THREAT_MODEL §1. The worst case is extra audit entries and rate-limit
  hits; the signature is deterministic, so no second token can result.

### N35. The e2e probe is test-only
`test/e2e/probe` (FetchKeys / Sign / TCP connect) and `test/e2e/Dockerfile.probe`
replace `fetchkeys`. The probe runs as throwaway `docker run` containers attached to a
compose network or to nginx's network namespace (`--network container:…`). No compose
override is needed, and the default compose file contains no test services.

### N36. Socket was world-writable (found in Phase 6.5 run 1, fixed in two steps)
The first Phase 6.5 e2e run passed N1–N3, but N2's output showed
`run/signer.sock` as `root:root 666`: any local user on the VM could call Sign.
- **The first fix was wrong:** starting nginx with `umask 077`. The Gate 6.5 attempt at
  `b2179f0` **failed N2**: `UNEXPECTED: non-root user ubuntu called FetchKeys on the
  socket`, mode still `666`. The cause is in nginx 1.29.8 `src/core/ngx_connection.c:662-664`,
  which always `chmod`s a unix listening socket to
  `S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH`, so no umask can restrict it.
- **The actual fix:** the parent directory `run/` is created `root:root 0700`
  (`sudo install -d`). Non-root users can't traverse it. Root (the nginx master, and
  kube-apiserver in the kind node) can. N2 asserts the directory mode and that a non-root
  connect is refused, and reports the forced 0666 socket mode as-is.

Also from that run: the random high TCP ports inside every container are Docker's
embedded DNS resolver, and nginx's `80/tcp` in `docker ps` is `EXPOSE` metadata, not a
published port. Both were included in N2's connect attempts and refused.

### N37. Phase 6.5 run history
| Run | Commit | Outcome |
|---|---|---|
| 1 | `c8abdf3` | **E2E: PASS** (SETUP, E1–E8, REQ-a–d, N1–N3). Review of N2's output found the socket at `666` (N36) |
| 2 (attempt) | `b2179f0` | **E2E: FAIL, N2**: `UNEXPECTED: non-root user ubuntu called FetchKeys`. The umask fix doesn't work, because nginx forces 0666 (N36). The run was stopped during `make test` (exit 143 = my SIGTERM). Log: `reports/gates/gate6.5-attempt1-b2179f0-N2-fail.log` |
| 3 (Gate 6.5) | **`468cd1c`** | **E2E: PASS** (19/19 checks), then **`make test` PASS**, then **`make check-images` PASS**. Logs: `reports/gates/gate6.5-final-468cd1c.log`, `gate6.5-e2e-final-468cd1c.log` |

In N1 the probe on `lb-net` connected from `172.30.1.1`. With `inhibit_ipv4` the host
holds no gateway address, so Docker IPAM assigns `.1` to a container. That's another
sign the host has no presence on the network.

## Phase 7B notes

### N38. `multipass exec` client hang (test-harness finding)
`multipass exec sig-a -- sudo -u frost-signer-1 cat /etc/frost-signer-2/share.json` (a
command that fails with permission denied) **hung on the client** for 6+ minutes, with no
process left on the VM. The same command wrapped in `bash -c` returned `rc=1`
immediately. The orchestrator now (1) runs such checks through `rc_on`, which prints the
**exit code as seen on the VM**, and accepts only an explicit `rc=1` as "denied", so a
timeout or hang is counted as INCONCLUSIVE, never as a pass; and (2) gives every remote
call a 300 s alarm, so a hang turns into a visible failure.

### N39. L4 found the T13 negative-control's fake share in Docker build cache
Multihost e2e run 2's L4 scan of the coordinator host found two `share-1.json` files
under `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/{46,47}/`.
Verified (without printing values): 52 bytes, `kid: "x"`, 4-character `si`, mtime
2026-09-24 21:50:32, which is the **fake** share baked into the Phase 6 T13 negative-control
image. `docker rmi` had removed the image, but Docker 29's containerd store kept the
BuildKit cache snapshots. It isn't key material, but **L4 was right to fail**: any file
shaped like a share on the coordinator host is a finding. Fix: `docker builder prune -af`
after negative-control builds (now in the T13 negative-control procedure), and a full
re-run of the multihost e2e.
- Binary sha256 differs per commit (e.g. 34a2… at f39dd68, 3fd0… at 90a01bb) because Go stamps vcs.revision into the build; within a run L5 checks every host carries the identical, just-built binary.

### N40. kind node image deleted by my own cleanup; rebuilt
While cleaning up N39 I also ran `docker image prune -af` on tk8s. That removed every
unused image, including the locally built `kindest/node:v1.36.5-tk8s` (N26), which exists
nowhere else. Multihost e2e run 3 at `4432322` then failed at `kind create` (`failed to
pull image`). All five L-tests had passed before that. The image was rebuilt from the same
official v1.36.5 release binaries (`kind build node-image --type release v1.36.5`, 158 s):
new image ID **`sha256:531890316ebb0d1ac5d655bbf3f78421f3c83a9d6cc86d8fbfca7781ab9c41d7`**
(a rebuild changes layer timestamps, so the ID differs from `2c8e428b…`). `kubeadm
version` inside it still prints `v1.36.5`. Rule from now on: on tk8s, prune **only**
`docker builder prune`, never unused images.

### N41. Benchmarks need an awake host
The first 7B benchmark attempt hung on its first remote call and measured nothing. The
cause was host sleep: the Mac's lid was closed and it was on battery (`AppleClamshellState
= Yes`, `Battery Power 48% discharging`), and `pmset -g log` shows it sleeping about every
15 minutes. Sleep freezes all four VMs, so any latency measured across a sleep is
invalid. `benchmark/multihost/run.sh` now (1) re-executes itself under `caffeinate -dims`,
(2) gives every remote call a 300 s alarm, and (3) checks `pmset -g log` for sleep events
inside the benchmark window, recording `host_slept_during_run` in `env.json` and marking
`summary.md` INVALID if the host slept. `caffeinate` cannot prevent lid-closed sleep on
battery, so the benchmark must run with the **lid open and on AC power**.

### N42. Root cause of the `multipass exec` hangs (corrects N38)
Minimal reproduction with multipass 1.16.4 on macOS:

| stdout of `multipass exec tk8s -- echo hi` | result |
|---|---|
| terminal | returns immediately |
| pipe (`| cat`) | returns immediately |
| file | returns immediately |
| `/dev/null` (with or without `2>&1`) | **hangs** (killed by the 20 s alarm, exit 142) |

The client hangs when its stdout or stderr is `/dev/null` **and the remote command writes
output**. N38's case was not about `sudo`: the permission-denied message went to
`/dev/null`. The benchmark's `kubectl get --raw /readyz >/dev/null` hung the same way.
Probes that write nothing (L1/L2 TCP checks) never triggered it, so the `45dfe68`
multihost e2e evidence is unaffected, and N38's `rc_on` already covered L3. Fix, in
every operator-side script (`deploy.sh`, `teardown.sh`, `test/e2e/multihost.sh`,
`benchmark/multihost/run.sh`): the `on` helper always gives multipass pipes
(`2> >(cat >&2) | cat`) and returns multipass's own exit code (`${PIPESTATUS[0]}`).
Verified under /bin/bash 3.2.57: no hang with `>/dev/null`, exit code 3 propagates,
`if on … false` is false, and output capture works.

### N43. Overload at c=50 in the multi-VM benchmark (measured, not retuned)
`T3of5-strict-L0ms-c50` ran 1000 requests with **969 errors**. All of them were
`token signing failed: threshold not met`, returned at 2.00–2.80 s (the 2 s signing
deadline). The 31 successes had a median of 1.76 s. The coordinator logs (1,429 `sign
failed` lines over the run) attribute 4,089 per-signer failures to `no response before
deadline`: signer 1: 1,031, signer 2: 1,012, signer 3: 1,015, signer 4: 1,031, **signer 5: 0**.
Signer 5 is alone on sig-c. Signers 1–4 share two 1-vCPU VMs, two per VM. There were no
policy denials and no rate limiting during the benchmark window.

The cause: the coordinator fans out to all 5 signers and cancels the other two once it
has 3 valid shares, but **the signer does not check for cancellation before computing its
share**. Every token therefore costs 5 share computations. The two-signer / one-vCPU hosts
saturate, their queues pass the deadline, and throughput collapses instead of degrading
gracefully. Candidate fix, **not applied**: check `r.Context().Err()` before the RSA
operation (net/http cancels it on client disconnect once the body is read), and/or
admission control in the signer. Either would change the measured system, so it needs a
decision first.

### N44. Signer clock skew after host sleep (fail-closed, costs availability)
After each Mac sleep the VMs resumed with lagging clocks until systemd-timesyncd
stepped them. sig-b's signers refused 401 requests each with `iat … is 39124s from
signer clock (max skew 60s)` (≈10.9 h) and `… 2372s …`, in the windows 2026-09-24
21:42–21:43Z and 2026-09-25 08:49–08:54Z, both right after wakes. None occurred in the
benchmark window. The policy is behaving as designed, failing closed, but a signer
with a wrong clock is effectively down. For availability, signers need reliable time
sync (NTP/chrony with monitoring). This goes into THREAT_MODEL (availability) in Phase 8.

### N45. Measured RTT ≠ configured netem delay: cause found (idle-vCPU timer latency)
In the pre-fix 7B benchmark, measured ICMP RTT to the far signers was 32–45 ms above the
configured netem delay (20 → 52–65, 60 → 99–109, 150 → 182–192 ms).

**Investigation (time-boxed, 15:47–15:50 on 2026-09-25, host load ~2.9, no benchmark
running).** netem delay 20 ms on sig-b's egress:

| Condition | tk8s → sig-b | sig-b → tk8s | Mac → sig-b |
|---|---|---|---|
| no netem | 0.78 ms | 0.74 ms | 0.50 ms |
| netem, sig-b vCPU idle | **142.5 ms** | **122.9 ms** | **137.6 ms** |
| netem, sig-b vCPU kept busy (spin loop) | **20.5 ms** | n/a | **20.4 ms** |
| netem, idle again | 117.3 ms | n/a | n/a |

Both ends had only `fq_codel` before the test. The guest kernel has `CONFIG_HZ=1000`,
`CONFIG_HIGH_RES_TIMERS=y`, and clocksource `arch_sys_counter`, so this is not tick
granularity. Moving the delay to tk8s's egress toward sig-b/sig-c (`prio` + `u32`
filters, with tk8s also idle because kind was stopped) overshot too: 20 → 80/100 ms,
150 → 213 ms, with the unfiltered path to sig-a at 0.73 ms.

**Cause:** netem releases delayed packets from a kernel hrtimer. When the guest vCPU is
idle (halted), the hypervisor (Multipass/Virtualization.framework on macOS) wakes it
late, so the applied delay is `configured + wake-up latency`, and the wake-up latency
depends on how busy that VM is. Under benchmark load the vCPUs are busier, hence the
smaller 32–45 ms excess.

**Consequences (decision from Gate 7B review):**
- The configured netem delay is a **knob, not a measurement**. Every table and figure
  uses **measured RTT** as its label/x-axis; the configured delay is only a secondary
  column.
- From the post-N43-fix runs onward, RTT is measured **during** each benchmark
  configuration (pings alongside the load), which captures the delay the requests
  actually saw. Pre-fix rows only have RTT measured before each delay setting, and are
  marked as such.
- Not fixed: forcing vCPUs never to idle (e.g. a guest `idle=poll`-style setting) would
  distort the CPU budget of 1-vCPU signers, which is what the benchmark measures.

### N46. Fix for N43: cancellation, admission control, hedged fan-out (design)
N43 was a design bug. Every token cost 5 RSA share computations whether or not they
were used, and signers queued work past the coordinator's deadline. On the two
two-signer / one-vCPU hosts, throughput collapsed at c=50 (93–97% errors).
1. **Cancellation (signer).** `SignShare` receives the request context and checks
   `ctx.Err()` **before** the RSA operation (no work for a caller that has gone) and
   **right after** it (a share computed too late is discarded, never released). net/http
   cancels the context when the coordinator cancels (HTTP/2 RST_STREAM, or HTTP/1.1
   disconnect after the body is read). Tests: `TestCancelledRequestComputesNoShare` (0 RSA
   ops, counted with `RSAOps()`), `TestCancelledDuringSigningDiscardsShare`.
2. **Admission control (signer).** A non-blocking semaphore of `SIGNER_MAX_CONCURRENT`
   slots (default `runtime.NumCPU()`) wraps only the RSA operation. With no free slot the
   request gets **503 `overloaded` immediately**; a slow queue would expire at the
   coordinator anyway, after burning CPU. Decisions are audited as `shed` / `cancelled`,
   separate from policy `deny`. Test: `TestAdmissionControlShedsImmediately` (shed in
   23 µs while the only slot was busy).
3. **Fast failure (coordinator).** A 503 is an immediate, attributed failure (as any
   non-200 is); collection continues. Test: `TestOverloadedIsFastFailureInAllMode`.
4. **Fan-out mode (coordinator, `FANOUT=all|hedged`, `HEDGE_DELAY`, default 50 ms).**
   `hedged` contacts t+1 = 4 signers first, starting at a per-request rotating offset so
   the load spreads evenly, and contacts the rest after `HEDGE_DELAY` or **as soon as any
   contacted signer fails** (a 503 included). Tests: `TestHedgedContactsTPlusOneAndRotates`
   (4 requests per token vs 5 for `all`; 16 per signer over 20 tokens),
   `TestHedgedFastFailureHedgesImmediately` (~15 ms with a 3 s hedge delay),
   `TestHedgedBelowThresholdFails`.
   **Trade-off:** `all` has the lowest idle latency, because the quorum is the 3 fastest
   of 5, but costs 5 computations per token. `hedged` costs 4 per token (−20% signer
   CPU) and can add up to `HEDGE_DELAY` when a contacted signer is slow without failing.
   **Outcome:** the post-fix benchmark did **not** justify either mode as the default
   (N47). `all` remains the default.

### N47. Post-N43-fix benchmark: target NOT met; admission control as specified regresses c=10
Run `benchmark/results/20260925T103202Z-2a75c2f-multihost-L1`, **PARTIAL**: configured
delays 0 and 20 ms completed for both fan-out modes (12/24 configurations). It aborted at
60 ms when the host's swap ran out (10,998 of 11,264 MB used), after which `multipass info`
failed ("failed to obtain exit status"). The script-generated `summary.md` shows pre- and
post-fix side by side, labelled by measured quorum RTT:
- **c=1:** unchanged (0% errors, ~64–73 ms median).
- **c=10: regression.** Pre-fix 0% errors (median 460 ms). Post-fix **67–76% errors** with
  both `all` and `hedged`.
- **c=50:** still **93–98% errors**, but failures now return fast (a run takes 3–8 s, not
  ~41 s), and the successful requests' median falls from ~1,860 ms to 207–603 ms.
- Measured RTT under load for "20 ms configured" was 24–44 ms (busy vCPUs wake on time, N45).

**Cause (confirmed from signer audit logs).** Every signer runs with `max_concurrent: 1`
(NumCPU on a 1-vCPU VM). signer-1 allowed 1,742 and **shed 1,783**; signer-2 allowed 1,731,
shed 1,791; signer-5 allowed 2,229, shed 1,310. Shedding immediately whenever the single
slot is busy throws away work that would have finished well inside the deadline: a share
takes ~30 ms, so one slot can clear ~60 queued requests within the coordinator's 2 s. The
spec's aim, "don't queue past the deadline", is right, but "no queue at all" overshoots.
Neither fan-out mode compensates, so **no default is chosen from this run**.

**Proposed next change (awaiting decision, not applied):** deadline-aware bounded
admission. The coordinator sends its remaining deadline in a request header. The signer
waits for a slot only while `remaining deadline − expected service time > 0` (tracked
with an EWMA of RSA time) and a queue-length cap (for example 64) holds, and sheds with 503
otherwise. That keeps the fast failure at real overload and restores c=10.

**Host note:** the Mac is at its memory limit (16 GB, tk8s reserves 8 GB, swap ~11 GB
used). Further Level 1 runs need a lighter host: fewer apps, or a smaller tk8s/kind
footprint. Results stay labelled "preliminary: arm64, multi-VM on one overloaded 16 GB host".

### N48. Deadline-aware bounded admission (replaces N46's "503 immediately")
Approved after N47. The coordinator sends its **remaining** deadline on every
sign-share request (`X-Frost-Deadline-Ms`, defined in `internal/wire`). The signer turns
it into a local context deadline, so the two clocks never need to agree. Admission:
- a free slot (of `SIGNER_MAX_CONCURRENT`, default NumCPU) is taken at once;
- otherwise the request **waits** only while `remaining deadline − EWMA(RSA time) > 0`
  and fewer than `SIGNER_MAX_QUEUE` (default 64) are already waiting. If either fails,
  the answer is **503 immediately**;
- a waiter gives up (503) at its latest possible start time, and re-checks after getting
  the slot;
- the EWMA of RSA time (α = 0.2) starts at a conservative 50 ms;
- requests with no header may wait up to 1 s;
- N46's cancellation checks stay: before admission, after the queue, and after RSA.

Tests (`internal/signer/admission_test.go`, `internal/coordinator/fanout_test.go`):

| Test | Result |
|---|---|
| queued request that fits succeeds | waited 167 ms for the busy slot, then signed |
| request that cannot fit is shed immediately | 22 µs, "cannot finish in time (remaining 500ms, RSA estimate 1s)" |
| queue cap enforced | cap 2: two waiters succeed, the third gets "queue full" immediately |
| expired deadline never computes a share | 0 RSA ops when already expired; 0 for a request that expired while queued (shed at 191 ms) |
| header parsed strictly | `abc`, `0`, `-5`, `999999` → 400 |
| coordinator sends remaining deadline | 1499 ms on all 5 requests with a 1.5 s deadline |

### N49. Benchmark target, redefined (decision after N47)
Capacity on the Level 1 topology is about **22 tokens/s** (the c=10 plateau pre-fix), so at
c=50 with a 2 s deadline some errors are unavoidable. Success criteria:
1. **goodput** (successful tokens/s over the whole run) at c=50 is close to the c=10
   goodput, not collapsed to ~1/s;
2. errors at c=10 are **~0%**;
3. failed requests fail fast (low failed-p95); successful requests have a bounded p95.

`summary.md` now reports goodput (successful / whole-run window), offered (all
completions / window) and failed-p95. The full matrix (all delays, both fan-out modes,
3 runs) moves to the cloud (Phase 7A). Level 1 keeps L1–L5 and the multihost e2e as its
main evidence; locally only a reduced **preliminary validation** runs (0 ms configured
delay, c=1/10/50, fanout all then hedged), and only if free swap is ≥ 2 GB.

### N50. Mandatory clock check before every multihost run
`deploy/multihost/clock-check.sh` (sourced by `deploy.sh`, `test/e2e/multihost.sh` and
`benchmark/multihost/run.sh`) restarts `systemd-timesyncd` on every VM, waits for
`NTPSynchronized=yes`, then measures each VM's clock against the operator's using the
midpoint of the `multipass exec` round trip. **Any skew above 1 s fails the run.**
Motivation: after the Mac reboot, multipass *resumed* the VMs from saved state (uptime
6 h / 3 h), and sig-b was **477 s behind** while still reporting `NTPSynchronized=yes`.
Its signers would have refused every token (N44). After a full stop, `set
local.tk8s.memory=6G` and a cold boot (uptime 41 s on all four), the check reported
tk8s +198 ms, sig-a +298 ms, sig-b +225 ms, sig-c +191 ms, all synchronized.

### N51. Reduced local validation deferred to the cloud VM (Phase 7A)
After shrinking tk8s from 8 to 6 GiB and cold-booting all VMs, the Mac's free swap was
**1.34 GB** (9,216 MB total, 7,881 MB used; host RAM available 4.63 GiB), below the 2 GB
floor set for the validation run. Per the decision, the N48 validation (0 ms, c=1/10/50,
fanout all then hedged, scored against N49) is **not run locally** and moves to Phase 7A
with the full matrix. N48 is covered by unit/integration tests only until then.
The signer VMs sig-a/b/c are stopped (not deleted) to free host memory; tk8s stays up
for single-host e2e runs.
- Single-host `make e2e` at `aa223ca` on tk8s with **6 GiB** (N48 signers): **E2E: PASS**, all 17
  checks. kind + nginx + 3 coordinators + 5 signers fit in 6 GiB
  (`reports/gates/e2e-single-host-6GiB-aa223ca.log`).

## Phase 10 notes

### N52. GO-2026-6443 accepted until 2026-11-30: revisit before then
govulncheck v1.8.0 reports GO-2026-6443 (google.golang.org/grpc, server-side HTTP/2
stream handling) as reachable via `grpc.Server.Serve`. The fix is only in unreleased
grpc v1.85.0-dev (`93e31b48545e`); v1.84.0 (upgraded from v1.79.3, which fixed the other
two reachable findings) is the newest release. The path is reachable only by callers that
already hold the `lb` mTLS key or root on the coordinator host (unix socket in a
root:root 0700 directory), and the impact is availability only. Accepted in
`reports/ci/govulncheck-accepted.txt` **until 2026-11-30**; after that date
`scripts/govulncheck.sh` fails CI. **Revisit before 2026-11-30**: upgrade grpc when a
release contains the fix, or re-assess and extend the acceptance explicitly.

### N53. make repro: fresh GitHub runner instead of a local fresh VM
The local arm64 fresh-VM repro was **not run**: host memory (free swap 1.52–1.63 GB,
below the 2 GB floor, even with tk8s stopped; no reboot). Gate 10's repro evidence is
`.github/workflows/repro.yml` on a **fresh GitHub runner, ubuntu-24.04, amd64** (fresh
`git clone`, then `make repro`), result in `reports/REPRO.md`. The runner ships a
Docker Engine whose packages conflict with docker-ce, so `scripts/repro.sh` detects a
running Engine, records its version and packages in REPRO.md and does not replace it
(on a truly fresh VM it installs docker-ce from the signed docker.com repo). `make repro`
will also run on the cloud VM in Phase 7A. `workflow_dispatch` works only once the
workflow is on the default branch, so repro.yml also runs on pushes that change
repro.yml or scripts/repro.sh.
- A bug found while wiring this: each step function's `set -euo pipefail` leaked into
  the main script (bash `set` is not function-local), so a failing step would have
  aborted before REPRO.md was written. Steps now run in a subshell.

## Phase 7A notes

### N54. B1 baseline: a single-key signer, benchmark-only
`benchmark/b1signer` is a single-key RS256 ExternalJWTSigner used **only** as the B1
baseline of the Phase 7A comparison (B0 in-tree / B1 single-key external / T threshold).
It is in the separate `benchmark/` module, has its own image (`frost-k8s/b1signer:bench`)
and compose file (`benchmark/single/docker-compose.b1.yml`), and nothing in the threshold
system (cmd/, deploy/, images) references it. The threshold runtime still has no
single-key path (hard rule). For fairness it reuses the coordinator's `grpcserver`,
`tlsconf.CoordinatorGRPCServer`, and `jwtfmt` header/claims checks, runs as 3 replicas at
the coordinators' lb-net addresses behind the unchanged nginx config and unix socket, so B1
vs T differs only in the signing backend. Difference kept on purpose: B1 applies no claims
policy (in T the policy runs in each signer, and its cost is part of T). The B1 key is
generated per run (`secrets/b1/key.pem`, 0600) and wiped at exit with all other secrets.

### N55. make repro on a fresh EC2 instance: two findings
1. Ubuntu 24.04 cloud images (EC2 AMI) ship **no `make`**, so `make repro` cannot start
   on a truly fresh host. `scripts/repro.sh` installs make itself, so on such a host the
   entry point is `scripts/repro.sh` (what `make repro` runs); REPRO.md records which one
   was used.
2. `kind build node-image --type release` downloads the release server tarball in one
   HTTP/2 GET with no retry or resume. From EC2 ap-south-1 the CDN reset that stream
   **every time** (attempts 1 and 2, 3 tries each: `unexpected EOF`; curl: HTTP/2 stream
   error at exactly 264,241,152 of 356,575,952 bytes; HTTP/1.1 connections were also cut
   but resume). So retrying kind was not a fix. `scripts/repro.sh` now fetches the tarball
   with resumable HTTP/1.1 range requests, **verifies it against the official `.sha256`**
   from dl.k8s.io, and runs `kind build node-image --type file`. Same official artifact,
   now with an explicit checksum. EC2 attempt 2 (`c46daba`, same instance) failed only on
   this step and the e2e that needs the image; make test (with the N56 fix) and
   make check-images passed.

### N56. Racy server-side count in TestHedgedContactsTPlusOneAndRotates (found on EC2)
Repro attempt 1 on the 2-vCPU EC2 host failed `make test` in this test:
`all: 99 signer requests, want 100`. The test counted sign-share requests at the
**signer** (HTTP handler). With fan-out `all` the coordinator launches 5 requests
and, once 3 valid shares arrive, cancels the rest (N46); a cancelled request can be
dropped before it reaches its signer, more often on a slow host. The coordinator's
own log for those tokens says `signers_contacted=5`, so the property held; the
assertion was racy. Fix (the property is unchanged, the racy equality is replaced): the
test now asserts `Result.Contacted` **exactly** per token (4 hedged, 5 all) and the
server-side total within [3, contacted] per token, and still requires every signer to be
used in hedged mode. The hedged half had the same race and got the same fix. Evidence:
`reports/aws/REPRO-attempt1-FAIL.md`.

### N57. Level 2 signer-host SSH: /32 enforced by the security group, not nftables
The operator's home IP is dynamic. `deploy/aws/provision.sh refresh-ip` (run before every
SSH-dependent step) replaces the tcp/22 /32 rule in every tagged security group and logs
the change in `deploy/aws/state/sg-rules.txt`. A host nftables rule pinned to the old IP
would lock the operator out of every signer. So on AWS (`SSH_ALLOW=any` in the topology)
the host's nftables accepts tcp/22 and leaves the source restriction to the security
group; the **signer port stays restricted to the coordinator EIP at both layers**
(security group and nftables, plus systemd `IPAddressAllow`). L1/L2 test the effective
paths end to end. Level 1 behaviour (nftables pins SSH to the operator) is unchanged.

### N58. Level 2 transport and RTT method
The multihost scripts use `deploy/multihost/transport.sh`: `multipass` (Level 1,
unchanged) or `ssh` (Level 2). The ssh transport quotes every argument (`printf %q`) so
the remote shell receives the same argv `multipass exec` passes, passes stdin only via
`on_pipe`, and reuses connections (ControlMaster). On EC2 the public IP is NAT'd, so
each signer **binds its private IP** while the coordinator dials its public IP (the
signer certs pin DNS SAN `signer-<i>`, not an IP). Inbound ICMP is not allowed on the
signer hosts ("nothing else inbound"), so Level 2 RTT is the **TCP connect time** to the
signer port from the coordinator host (one SYN/SYN-ACK round trip), sampled every 0.5 s
during each configuration (`benchmark/multihost/rtt_sampler.py`). These bare connects
make each signer log a TLS handshake EOF; they carry no request. The far-quorum
scenario stops the two signers with the lowest measured RTT (chosen from the
measurement, not assumed). EC2 Ubuntu syncs time with chrony (Amazon Time Sync);
`clock-check.sh` forces `chronyc makestep` there.

### N59. Phase 7A findings carried into 7B (m7i-flex.large, 2 vCPU, CPU-contended)
- **Kubelet retries absorbed signing failures in the pod scale-up.** For T strict-all
  the kubelet made 164 TokenRequests per repetition for 50 pods and 418 for 100 pods
  (about 3–4 per pod; B0/B1 made exactly one per pod), with 322 and 768 failed
  TokenRequests over 3 repetitions. Every pod still became Ready, 1.5–1.7× later than B0
  (`benchmark/results/20260926T172317Z-8ebb806-7A-single-m7i-flex.large/summary.md`).
- **Strict-mode failures at c=50 exceeded the 2 s deadline at the client**: failed p95
  3.6 s (strict-all) and 4.0 s (strict-hedged), successful p95 3.2–3.3 s. Client
  latency includes time queued in kube-apiserver before the coordinator's deadline
  starts, so the coordinator deadline does not bound what the requester sees. 7B
  reports client-side and coordinator-side latency side by side for every configuration.
- N49 on this host: N49-2 PASS for all four T variants; N49-1 and N49-3 FAIL for all four.
  The overload fix is to be designed together after 7B; nothing is implemented yet.

### N60. Operator network drops and clock-check method (Phase 7B Level 2)
**Event 1 (2026-09-26 ~19:33 UTC, during `test/e2e/multihost.sh --keep`, deploy step).**
The operator Mac's Wi-Fi dropped: 4 × `ssh: connect to host 18.177.138.238 port 22:
Network is unreachable` (sig-3, Tokyo) and one broken ssh multiplex master. Local
routing error, not a security-group block; the IP was unchanged (110.226.114.36). The
deploy-time clock check ran during recovery and reported inflated round-trip skews
(+501 to +704 ms at 1.0–1.4 s exec round trips) but passed. Shortly after, the L2
**control** check `operator -> sig-3:22` failed, so L2 reported FAIL, while every
blocked path held (operator -> all 5 signer ports blocked; coordinator -> all 5 signer
SSH ports blocked). All other checks passed: L1, L3, L4, L5, E1–E8, REQ-a–d, N1–N4
(`reports/multihost/e2e-20260926T191044Z-b2f63ca/`). Per the rule for operator network
drops, L2 was re-run once with connectivity restored: **L2 PASS**
(`reports/multihost/l2-recheck-20260926T194211Z-ebabdb1/`, same deployment, kid
4rIZD1LYAPixvZTYsskIKg). Both results are kept.

**Clock check.** The exec-round-trip method measures the host against the operator's
clock and inflates skew on a slow operator network. `clock-check.sh` now records each
host's own chrony offset (`chronyc tracking` "System time", plus "Last offset") as the
**primary** value and fails only if it exceeds the limit; the round-trip skew is kept as
the secondary value (and stays primary only on hosts without chrony, i.e. the Level 1
Multipass VMs). First run: chrony offsets 0.000–0.003 ms on all 6 hosts, round-trip
skews +53 to +199 ms.

**Benchmark robustness rule.** `benchmark/multihost/run-l2.sh` runs tokenbench and each
scale-up repetition detached on the coordinator host (an operator drop cannot kill a
measurement), and marks a configuration or repetition INVALID if *any* ssh/scp call
failed while it was in progress: its files move to `invalid/`, the error goes to
`invalid-events.jsonl`, the run waits for every host to answer and re-runs it once; only
failure-free configurations reach summary.md. Verified with a test-only injected fault
(`L2_FAULT_ONCE=1`) in a smoke run that was then deleted.

### N61. 7B scale-up: coordinator logs not captured (bug), coordinator CPU is the strict-mode bottleneck
**Bug.** In the first 7B run, every scale-up repetition's `<rep>.coord.jsonl` is empty:
`benchmark/multihost/scale-remote.sh` set `FROST_UID` only for its `docker compose up`,
and the per-rep `docker compose logs` in `scale-lib.sh` failed the compose file's
`${FROST_UID:?}` interpolation with stderr discarded. So for the 7B scale-up the
coordinator latency, coordinator sign-failure and **signer 503** columns are **not
captured**. The coordinators were already torn down, so they cannot be recovered. The
audit-log metrics (time to Ready, TokenRequests per rep, token errors, token latency) are
unaffected. Fixed: FROST_UID exported, `compose config -q` checked at start, and log
capture now fails the rep loudly. The summarizer shows "not captured" instead of zeros.
**Findings (7B, one run per configuration).**
- The client − coordinator median gap is ~4 ms for optimistic at every concurrency, but
  60 ms (c=10) and 610–645 ms (c=50) for strict with all 5 signers.
- The coordinator host's CPU is 80–89 % busy for strict and ~20 % for optimistic: strict
  verifies every share on the same 2 vCPU that runs kube-apiserver, nginx and the load
  generator.
- With strict at c=50, far-quorum (3 signers, 3 verifications per token) is faster than
  all 5 (1228 vs 1899 ms client p50).
- N49: every optimistic variant passes all three criteria in both scenarios; strict passes
  N49-1 and N49-2 everywhere, but fails N49-3 in 3 of 4 variants (failed or successful p95
  above the thresholds at c=50).
- Pod scale-up: optimistic-hedged made exactly one TokenRequest per pod with 0 errors;
  strict-all needed 68 (50 pods) and 357 (100 pods) TokenRequests per repetition, with 47
  and 815 failed ones over 3 repetitions. All pods became Ready.

### N62. Decision (2026-09-27): no 7B re-run; final numbers come from 7C
All Phase 7A/7B AWS resources were torn down (`reports/aws/teardown-proof.txt`: zero
tagged resources in all 5 regions; the tagging API's 12 lingering root-volume/ENI entries
are stale index records, each NotFound in EC2, and `teardown.sh` now checks every such ARN
against EC2). There is **no separate 7B re-run**, neither 3 runs per configuration nor the
N61 scale-up with coordinator logs. Phase 7C will provision a new kubeadm cluster with
same-region signers, and will also run T with the 5-region placement, 3 runs per
configuration and the fixed scale-up logging. **The final T numbers, and every comparison
against default Kubernetes (B0/B1), come from 7C.** 7B stays as one-run, T-only evidence.

### N63. Revised overload analysis (after 7A and 7B)
- **7A's collapse was dominated by co-location on 2 vCPU.** In 7A, kind, nginx, 3
  coordinators, 5 signers and the load generator shared one m7i-flex.large; the host was
  ~100 % busy from c=10 and T strict fell to 1.0–1.6 tokens/s at c=50. With the signers on
  their own hosts (7B), **optimistic passes N49 at c=50 in all four cases** (all5 and
  far-quorum × all and hedged): goodput c10 → c50 62.3 → 68.6, 54.5 → 69.2, 45.5 → 68.0,
  45.3 → 64.3 tokens/s; 0 % errors; successful p95 ≤ 1126 ms; client − coordinator median
  gap ~4 ms at every concurrency.
- **Strict at c=50 is bound by coordinator-host CPU.** The coordinator verifies every share
  (Shoup proof) before combining, on the same 2 vCPU as kube-apiserver, nginx and the load
  generator: coordinator host 80–89 % busy in strict (already ~88 % at c=10) vs ~20 % in
  optimistic. The client − coordinator median gap grows to 610–645 ms at c=50 (all5), i.e.
  requests wait before the coordinator's deadline starts. Far-quorum (3 verifications per
  token) is faster than all5 (5 per token) at c=50 in strict: 1228 vs 1899 ms client p50.
  Strict fails N49-3 in 3 of 4 cases; its only failure reason is "no response before
  deadline" (31 and 69 at c=50, all5).
- **The "uncoordinated per-signer shedding" hypothesis (DAGOR, Zhou et al., SoCC 2018) is
  NOT supported by 7B, because the signers were never the bottleneck.** No signer returned
  HTTP 503 (at capacity / shed) in any of the 24 configurations. The only exclusions were the
  2 stopped signers in far-quorum ("connection refused") and strict's deadline timeouts. The
  hypothesis is **untested, not refuted**: 7B never pushed the signers into shedding.
  Signer-host CPU was not measured in 7B (only the coordinator host's); the claim rests on
  the zero 503s and on optimistic reaching ~69 tokens/s with 0 errors.

### N64. c1: arrival timestamps at nginx and the coordinator (timing only)
To locate the time spent outside the coordinator's deadline (610–645 ms at c=50 strict in
7B, N63), each request is now stamped twice before `Sign` starts:
- **nginx** (`deploy/nginx-grpc.conf`) logs one JSON line per request on stdout
  (`msec`, `request_time`, `request_id`, upstream timings, grpc status). It also sends
  `X-Frost-Nginx-Request-Id: $request_id` and `X-Frost-Nginx-Msec: $msec` (the proxy time)
  upstream.
- a **gRPC unary interceptor** (`internal/grpcserver/timing.go`, first in the chain)
  records arrival time, the caller's remaining gRPC deadline and those two headers. The
  coordinator's `signed`/`sign failed` lines add `queued_before_sign_ms`,
  `nginx_request_id`, `nginx_to_coordinator_ms` and `incoming_deadline_ms`.

These values are **only logged, never used for any decision**. The headers are parsed
strictly (32 lowercase hex; `^\d{10}\.\d{3}$`) and ignored if malformed or duplicated
(`TestTimingInterceptor`). nginx sets them itself (`grpc_set_header`), overriding
anything a caller sends. The e2e gained a **TIMING** check: at least 90 % of the
coordinators' Sign lines must join an nginx line by `request_id`, and the log prints the
median segments. `benchmark/single/timing-breakdown.sh` produces the same breakdown under
load (c=1/10/50) on a kept stack. It does not see inside kube-apiserver: "outside nginx" is
the client median minus the nginx median.

### N65. c2 verify-until-t and (a) optimistic default with a per-signer suspicion breaker
**c2, verify-until-t (strict).** Strict used to verify every share that arrived (5 per
token with fan-out all), including shares arriving after 3 were already valid and after
`Sign` had returned. A `verifyGate` now lets a share be verified only while fewer than t
shares are valid or being verified. When t have verified, later shares are not verified
at all. If a verification fails, a waiting share proceeds. With 5 honest signers, strict
verifies exactly t per token (`TestStrictVerifiesUntilT`: 36 verifications for 12 tokens;
previously up to 60). Worst-case latency cost: a share arriving while t verifications are
in flight waits for one of them (≈ one share-verification time) and is used only if one
fails.

**(a) optimistic is the default** (`VERIFY_STRATEGY` default in `cmd/grpc-proxy`, both
compose files and `test/e2e/run.sh`; strict stays selectable). A **per-signer suspicion
breaker** (`internal/coordinator/breaker.go`) bounds the extra work misbehaving signers can
cause:
- a signer whose share fails verification (in any path) becomes a **suspect** for
  `SuspectCooldown` (default 10m); a suspect's shares are verified individually before
  they may be combined, so **each misbehaving signer causes at most one failed combine
  per cooldown**;
- `FallbackAfter` (default 3) failed optimistic combines within `FallbackWindow` (1m)
  switch the coordinator to **strict** for `FallbackCooldown` (10m).

**Work bound** (`TestBreakerWorkBound`, corrupt signer 1, 5 signers, fan-out all): the
tripping request cost 1 failed combine and 4 share verifications (≤ n); the next 30
tokens cost 13 verifications in total and never more than 1 per token (the suspect's own
share), with no further failed combine. Strict would verify ≥ 90. Honest steady state:
0 share verifications per token (1 join + 1 final RSA verify).

**Security trade-off.** Unforgeability is unchanged: both strategies verify the combined
signature against the group key (`rsa.VerifyPKCS1v15`) before returning, so no invalid
token can be returned (I7). Share verification buys attribution and robustness, not
unforgeability. Under optimistic:
1. a bad share is attributed only after a failed combine;
2. a not-yet-suspect bad signer can make one request cost a failed join, ≤ n share
   verifications and a second join (≈ 2× a strict request), at most once per signer per
   `SuspectCooldown`, and at most `FallbackAfter` times per `FallbackWindow` in total before
   strict takes over;
3. **the extra-work bound applies per coordinator replica and resets on restart.**
   Suspicion and the fallback counter are in memory in each replica, so with R replicas a
   bad signer can cause up to R failed combines per `SuspectCooldown` (one per replica),
   and up to R × `FallbackAfter` failed combines per `FallbackWindow`, before every replica
   is protected. A replica restart clears its suspects and its fallback state, so the
   bound restarts from zero. With the deployed R = 3: ≤ 3 failed combines per bad signer
   per 10 min, ≤ 9 per minute in total.

The guards are on both paths, unchanged:
- `fetch` checks the mTLS identity (`signer-<id>`), response `signer_id` and
  `request_id`, size limits, and bounds-checks ids in `wire.ToTcrsa`;
- the collect loop dedupes by id;
- tcrsa `Join` never sees an out-of-range or duplicate id.

Tests: `TestBreakerTripMarksSuspect`, `TestBreakerWorkBound`, `TestBreakerRecovery`
(suspect verified during the cooldown, fast path after it), `TestBreakerFallbackToStrict`,
unit tests with a fake clock (`TestBreakerSuspectCooldown`, `TestBreakerFallbackWindow`,
`TestBreakerConfigValidation`, `TestVerifyGate`); T5 passes under the new default.
**Validation.** `make test` PASS on the operator Mac
(`reports/gates/overload-fix-make-test-local-bfab4d9.log`). A local kind run was not
possible: free swap on the Mac was 730 MB, below the 2 GB floor for kind runs, so tk8s was
not started. **Decision (2026-09-27): CI run 36275189321 is accepted as the kind
validation, including `make check-images`** (all jobs green at `bfab4d9`; e2e 18/18 PASS
with strategy=optimistic, TIMING 71/72 joined:
`reports/gates/overload-fix-ci-e2e-run36275189321-bfab4d9.log`). The under-load timing
breakdown (c=1/10/50) moves to Phase 7C.

## Phase 7C notes

### N66. ap-south-1 vCPU quota request (Phase 7C)
The full 7C spec needs 11 instances in ap-south-1: control plane, 2 workers, coordinator
node, load generator, 5 T-same-region signers and the T-5-region Mumbai signer. Every Free
Plan instance type has 2 vCPU, so that is 22 vCPU; the quota "Running On-Demand Standard
(A, C, D, H, I, M, R, T, Z) instances" (L-1216C47A) is 16. **Decision (2026-09-27):** request
16 → 24 and do not wait for it. Run the phases that fit in 16 vCPU first (B0, B1,
T-5-region: 6 instances, 12 vCPU in ap-south-1), and T-same-region only if the request is
approved. If it is denied or still pending after those phases, stop and report. The spec is
not shrunk unilaterally. If the fallback is 1 worker, every system's scale-up is re-run on
the same 1-worker cluster; token benchmarks may be reused if the worker count is recorded.
- Request **d54be0b2167647c4b59a05d04108c29cyFO4OQwl**, submitted **2026-09-27T08:40:50Z**
  (14:10:50 IST), desired 24, status at submission **PENDING**, case id none yet.
- **Approved:** status `CASE_CLOSED`, case 179049863300507, last updated
  **2026-09-27T08:44:47Z** (4 min after submission). `get-service-quota` for ap-south-1
  L-1216C47A now returns **24**. Phase 1 (12 vCPU) and phase 2 (+10 → 22 vCPU) both fit
  (`deploy/aws/provision-7c.sh check`, 2026-09-27T08:55Z).
- Correction to the fallback analysis given before the approval: "drop one worker" alone
  did **not** fit 16 vCPU (control plane + 1 worker + coordinator node + load generator
  + 5 signers = 9 instances = 18 vCPU). Any 16-vCPU layout for T-same-region needs
  co-location. The operator's proposal (control plane + 2 workers + 5 signers; coordinators
  on a tainted worker; load generator on the control plane; 1 pod worker, so ≤ ~100 pods;
  every system re-run on that layout, co-location in every label) was the recommended
  fallback. Moot now that the quota is approved.

### N67. Phase 7C design: one kubeadm cluster, systems switched by manifest (benchmark tooling)
- **Cluster:** kubeadm v1.36.5 (pkgs.k8s.io, pinned `1.36.5-1.1`, held), containerd from
  docker.com (systemd cgroups), flannel v0.28.9 (manifest sha256 pinned in
  `deploy/aws/7c/versions.env`). 1 control plane (m7i-flex.large, ap-south-1a) + 2 workers
  (c7i-flex.large, 1b/1c). The TokenRequest-only apiserver audit policy is set at
  `kubeadm init`, identical for every system.
- **nginx on the control plane, coordinators on a dedicated node.** kube-apiserver reaches
  the external signer only through a local Unix socket
  (`pkg/serviceaccount/externaljwt/plugin/plugin.go` dials `"unix"`, v1.36.5). So nginx
  runs as a static pod on the control plane (`deploy/aws/7c/frost-nginx.yaml`, socket dir
  root:root 0700) and forwards over mTLS to the 3 coordinators on a dedicated
  c7i-flex.large (ports 9090–9092 on its private IP, reachable only from the control
  plane). B1 replaces the coordinators on the same node, ports and certs. The load
  generator (tokenbench) runs on its own t3.small.
- **Switching** (`deploy/aws/7c/switch.sh`, `benchmark/k8s7c` tool): B0 = kubeadm's pristine
  manifests; B1/T = the external variant derived from them. The in-tree key flags and the
  endpoint are mutually exclusive (`pkg/kubeapiserver/options/authentication.go:624`).
  Every switch stamps both manifests, so kube-apiserver always restarts (it refetches the
  external signer's keys at startup; its key cache otherwise refreshes only after
  RefreshHintSeconds = 3600 s) and kube-controller-manager drops tokens cached from the
  previous signer. Then coredns, kube-proxy and flannel are restarted (they hold SA
  tokens) and everything must be Ready. **Before every measurement** `check.sh` verifies the
  running manifest's mode, that a new token's kid is the expected key (in-tree: sa.pub;
  external: FetchKeys, pinned to the public-meta kid for T and to the B1 key's kid for B1),
  alg RS256, and TokenReview.
- **Two T systems, two dealer keys:** T-5-region (`secrets-t5`, lb set `lb-t5`) and
  T-same-region (`secrets-tsame`, `lb-tsame`), each from its own `deploy.sh` run. No share
  index exists on two hosts. deploy.sh gained opt-in `COORD_SECRETS_DIR`,
  `LB_HOST`/`LB_DIR`, `HOST_SERVICE`, `SIGNER_SOURCE_IP` and `MANIFEST_OUT`; the defaults keep
  Level 1/2 behaviour.
- **Measurements** (`benchmark/k8s7c/run.sh`): token runs rotate the system order per run;
  the scale-up interleaves systems per rep (rotated), with the 7B cooldown on the control
  plane plus coordinator-node load1 < 1.0. Both use the N60 INVALID + one re-run rule and
  the chrony-primary clock check before every run.
- **Summary:** `summarize -single` gained the final comparison (Δ vs B0 in ms and ×),
  the c1 breakdown, coordinator-side columns, TokenRequests per pod and the B0 anchor
  drift table (`TestSevenCSummary`).

### N68. Phase 7C bring-up: findings and fixes (2026-09-27)
- **Provisioning:** phase 1 (10 instances) and phase 2 (5 T-same-region signers) launched
  09:15–09:18Z; 22 of 24 vCPU in ap-south-1. Two script fixes: AWS rejects `>` in
  security-group rule descriptions; the quota check double-counted already-launched roles.
- **Clock check too slow for 15 hosts:** after `chronyc makestep` the kernel's sync flag
  takes 6–17 s to return (measured). Waiting for it from the operator, host by host, took
  >30 min. The resync and its wait now run on every host in parallel, with one
  measurement call per host: 16 s for 15 hosts. The idempotent resync is retried on ssh
  connection failures (exit 255) instead of failing the check.
- **Docker group:** a new group membership applies only to new login sessions, but the ssh
  master connection predates it; `drop_master` closes it after the Docker install.
- **Switch race:** `kubectl wait --all` after the CoreDNS rollout failed with NotFound (an
  old pod deleted between list and wait). It is replaced by a loop: every kube-system pod
  Ready and none terminating. A switch takes about 2 min.
- **pipefail:** `cat missing | jq -s . || echo '[]'` emitted `[]` twice (jq printed, then
  the pipeline failed), which made `env.json` empty in the driver smoke run.
- **Signer binaries:** T-5-region hosts run sha256 `0dd3fa23…`, T-same-region hosts
  `1f744909…`. Both are built from identical `cmd/signer` source at different commits (Go
  embeds the VCS revision). Within each T system all 5 hosts run one identical binary.
- **Bootstrap checks** (`reports/aws/7c/bootstrap-checks.jsonl`): all six systems ok.
  Signing mode as expected; token kid equals the expected key (B0: in-tree
  `a3iC7qgl…`, 43 chars; B1 `3HfosoOu…`; T-5-region `EV_rkpqm…`; T-same-region
  `wvQG_NBR…`), pinned independently for B1/T; TokenReview authenticated.
- Driver smoke (N=20; B1, T-same optimistic): breakdown joined 20/20 at c=1. It was
  deleted after the check; the real run is `benchmark/results/20260927T123218Z-7faa09c-7C`.

### N69. Phase 7C token benchmark: results and observations
Run `benchmark/results/20260927T131349Z-73be90f-7C`: 3 runs × 6 systems × c=1/10/20/50,
N=1000 after 100 warm-up, fan-out all, commit 73be90f. 72 configurations, **0 INVALID**,
18 system switches all verified (kid, mode, TokenReview; 110–363 s each). An earlier
attempt (`…20260927T123218Z-7faa09c-7C-ABORTED-switch-alarm`, not committed and not used)
stopped mid-switch after B0/B1 of run 1, when the 600 s per-call ssh alarm cut a switch
short. Switches now get 25 min and one retry.
- **0 % errors in every configuration.** No signer returned 503 (optimistic and strict,
  both placements). Strict T-same-region at c=50 had 3 deadline timeouts in 3000.
- **T throughput is placement-independent**: optimistic ≈ 68–70 tokens/s at c=20/50
  (T-5-region 67.8, T-same-region 69.8), strict ≈ 48–49/s, although the quorum RTT differs
  (≈ 125 ms vs ≈ 1 ms). In optimistic the time is almost entirely inside the
  coordinator's Sign (e.g. 719 of 723 ms at c=50), nginx→coordinator ≈ 1 ms, and outside
  nginx (kube-apiserver + client) ≈ 3 ms. This points at the **signers' compute** (each of
  the 5 t3.micro signers computes a share for every token under fan-out all; N48 queues
  requests up to the deadline instead of shedding). Signer CPU was **not** sampled in the
  token runs, so this is an inference from latency composition and the plateau, to be
  measured directly in the stress test.
- **Strict at c=50 adds queueing before the coordinator's handler:** nginx→coordinator
  124/339 ms (median/p95) and 130/377 ms of "rest", i.e. the coordinator node (2 vCPU,
  per-share verification) is the bottleneck, now on its own node instead of kube-apiserver's
  (cf. 7B, N63). Strict fails N49-3 (failed p95 2622–2654 ms, ok p95 1777–2067 ms);
  optimistic passes all three N49 criteria in both placements.
- **B1 vs B0:** +0.9 ms at c=1 (1.34×), but B1 is *faster* at c=50 (42.1 vs 60.0 ms):
  B0 signs inside kube-apiserver on the control plane (35 % CPU), B1 offloads signing to
  the coordinator node.
- **nginx log capture gap:** for T-5-region strict c=50 only 2198 of 3000 nginx lines were
  captured (kubectl logs of the static pod reads only the current, rotated container log),
  so that breakdown row pools 2198 joined requests and its "outside nginx" (client median −
  nginx median over different sets) is not meaningful (−24.4 ms). Client and coordinator
  latencies are unaffected. To fix for the scale phase: read nginx's log from the node's
  rotated files, not `kubectl logs`.
- gitleaks flagged the field name `token_kid` (public key IDs); renamed to
  `jwt_header_kid` in `check.sh` and, as a documented mechanical change, in three result
  files (`POSTPROCESSING.md`). Raw JSONL logs are gzipped (summary identical).
- **CI was red from a0173b4 to 73be90f** (3 CI runs): the gitleaks tree scan (and T11)
  flagged `token_kid` in the committed `reports/aws/7c/bootstrap-checks.jsonl`. The
  pre-commit scan's output was lost because it ran in the same command as a
  backgrounded smoke run, and CI was not checked after those commits. Fixed by the same
  field rename (`reports/aws/7c/POSTPROCESSING.md`). The rule for every PASS from now on:
  full-tree gitleaks + T11 locally, and CI green on the pushed commit.

### N70. c=50 latency is Little's law; throughput attributed to signer compute; lever check and stress test
- **Little's law:** with a closed loop of c=50 clients and T's plateau of ≈ 70 tokens/s
  (optimistic), the expected latency is L = c / X ≈ 50 / 70 ≈ 0.71 s. Measured: 723 ms
  (T-same-region) and 730 ms (T-5-region) median at c=50. The c=50 latency is therefore
  queueing at a throughput limit, not per-request slowness. (Strict: 50 / 49 ≈ 1.02 s vs
  904–1017 ms measured.)
- **Throughput is independent of placement** (T-same-region 69.8 vs T-5-region 67.8 tokens/s
  optimistic, with quorum RTT ≈ 1 ms vs ≈ 125 ms) and no signer returned 503. It is
  **attributed to signer compute**: with fan-out all, every t3.micro signer computes a share
  for every token. This is an inference until confirmed by the lever check and the stress
  test (below), which sample signer CPU directly.
- **nginx capture fix:** `kubectl logs` reads only the current container log file, and the
  kubelet rotates at 10 MiB (current + `0.log.<ts>` + gzipped older files), so one token
  configuration captured 2198 of 3000 nginx lines. `deploy/aws/7c/nginx-lines.sh` now reads
  every file the kubelet keeps, filtering by nginx's own `msec`. Verified: 600 of 600 lines
  on a short run (`reports/aws/7c/nginx-capture-verify.txt`), plus a local test with rotated
  and gzipped files.
- **Lever check** (label "lever check"): T-same-region optimistic at c=50, uncapped signers,
  3 runs, fan-out **all** vs **hedged** (hedged contacts t+1 = 4 signers first, so 20 % fewer
  share computations per token). Signer CPU = systemd `CPUUsageNSec` per signer process (% of
  one vCPU). If signer compute is the limit, hedged should raise goodput and lower
  per-signer CPU per token.
- **Stress test** (label "stress test (CPU-capped signers, SIGNER_MAX_CONCURRENT=1)", not a
  realistic workload): T-same-region signers with systemd `CPUQuota=25%` and
  `SIGNER_MAX_CONCURRENT=1`, T-same-region optimistic, fan-out all, c = 10/25/50/100/150/200,
  3 runs; signer CPU and signer audit logs per configuration. Signer audit `allow` is written
  after admission and immediately before the share computation (`internal/signer/signer.go`),
  so it counts computed shares; `shed` counts 503s. **Decision rule, fixed before the run:**
  DAGOR-style priority-consistent admission is indicated only if goodput < 0.8 × peak
  goodput **and** ≥ 20 % of computed shares were for requests that failed; otherwise "not
  observed".

### N71. Scale-up fit check raced the previous repetition's terminating pods (fixed; run restarted)
The first interleaved scale-up attempt skipped the 200-pod size for 5 of 6 systems in rep 1
("only 188–199 pods fit": 21–32 pods "in use" on the workers, against ≈ 4–6 system pods).
`scale-rep.sh` checked the fit **before** deleting the previous repetition's Deployment,
counting its still-terminating pods. It now checks after the Deployment is deleted and its
pods are gone, and ignores terminating pods. Rep 1 was stopped at 15:52Z; its partial data
(35 files, unfair: only B0 has a 200-pod rep) is set aside in
`benchmark/results/20260927T131349Z-73be90f-7C-scale-ABORTED-fitcheck/` (not committed,
not used). The scale phase was re-run from scratch.

### N72. Phase 7C lever check: hedging does not reduce signer work under queueing; signers are not CPU-saturated
Run `benchmark/results/20260927T185001Z-6b2f6bb-7C-lever` (label **lever check**):
T-same-region optimistic, c=50, uncapped t3.micro signers (N48 defaults:
`max_concurrent` = NumCPU = 2, `max_queue` = 64), 3 runs × {fan-out all, fan-out hedged},
N=1000 after 100 warm-up, 0 INVALID, 0 errors. (The summary's generated note says
"fan-out all" for every configuration; the configuration labels carry the real fan-out.)

| | goodput /s | client p50 c=50 | signer CPU (% of one vCPU, mean of 5) | signer host busy |
|---|---:|---:|---:|---:|
| fan-out all | 69.4 | 724.5 ms | 130.0 % | 65.5 % |
| fan-out hedged | 72.3 | 700.1 ms | 148.4 % | 74.9 % |

- **Hedged did not test the lever.** It contacts t+1 = 4 signers first and the 5th after
  50 ms, but under c=50 queueing no share returns within 50 ms, so the hedge fired for
  1096–1097 of 1100 tokens per run (coordinator `signers_contacted` = 5). Both modes
  therefore computed ≈ 5 shares per token; hedged gave +4 % goodput at more signer CPU.
- **Signers were not CPU-saturated** (130–148 % of the 200 % a t3.micro has; hosts
  65–75 % busy). Signer CPU per share ≈ 130 % / 69.4 per s ≈ **18.7 ms**.
- **Revised attribution (inference, not measured directly):** the ≈ 70 tokens/s plateau
  matches the signers' **admission slots**: 2 slots per signer / 70 shares per s ≈
  28.6 ms per share per slot, of which ≈ 18.7 ms is signer CPU. So the limit is the
  per-signer concurrency bound (N48) × per-share service time, not raw CPU. What the
  remaining ≈ 10 ms per slot is was not measured. N70's "signer compute" is refined to
  this; it remains signer-side and placement-independent, consistent with N69/N70.

### N73. Phase 7C stress test: goodput collapse with wasted shares OBSERVED (pre-registered rule)
Run `benchmark/results/20260927T191742Z-bc0ff05-7C-stress` (label **stress test
(CPU-capped signers CPUQuota=25%, SIGNER_MAX_CONCURRENT=1)**, not a realistic
workload): T-same-region optimistic, fan-out all, c = 10/25/50/100/150/200 (rotated per
run), 3 runs, N=1000 after 100 warm-up, 0 INVALID, 3 verified switches. Caps applied
before (systemd `CPUQuotaPerSecUSec` 250 ms, signer log `max_concurrent` 1) and removed
after (quota infinity, `max_concurrent` 2), both read back from every signer.

| c | goodput /s | goodput / peak | errors % | computed shares per request | wasted on failed % | signer CPU % |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 13.8 | 1.00 | 0.0 | 4.94 | 0.0 | 23.2 |
| 25 | 13.7 | 0.99 | 1.3 | 4.87 | 0.6 | 23.1 |
| 50 | 10.1 | 0.73 | 59.4 | 2.67 | 32.5 | 21.5 |
| 100 | 10.5 | 0.76 | 81.0 | 1.20 | 32.2 | 19.4 |
| 150 | 6.8 | 0.50 | 94.6 | 0.62 | 43.0 | 16.1 |
| 200 | 7.5 | 0.54 | 94.4 | 0.49 | 44.4 | 13.8 |

- **At c ≤ 25 the cap binds exactly as predicted:** 23.2 % of the 25 % quota; ≈ 17 ms of
  signer CPU per share, so 250 ms/s ÷ ≈ 17–18.7 ms ≈ 13–14 shares/s per signer = the
  measured 13.8 tokens/s (prediction from N72 written down before the first stress
  configuration finished: ≈ 13.4/s).
- **Decision (rule fixed in N70 before the run): collapse OBSERVED** at c = 50, 100, 150,
  200 (goodput < 0.8 × peak and ≥ 20 % of computed shares for failed requests).
  DAGOR-style priority-consistent admission is **indicated; it is not designed or
  implemented**.
- **Mechanism, from the audit and coordinator logs:** each signer sheds independently
  (at c=50: ≈ 2000–2140 "no slot before the latest start time" per run over 5 signers; at
  c=200: ≈ 4100–4200 "queue full"). Signers shed *different* requests, so many requests
  get 1–2 shares (computed, then wasted) and fail the t = 3 threshold. Coordinator
  failures at c=200 are typically all 5 signers refusing with "queue full (64 waiting)".
  The coordinator stayed in optimistic (`strategy_effective`; no breaker fallback).
- **Also observed, not explained:** signer CPU falls below the quota as c rises (21.5 % at
  c=50 → 13.8 % at c=200), so the capped signers are partly idle while shedding. Not
  investigated further. Policy rate-limit denials (200 req/s per signer) occurred only in
  run 1 at c=200 (236 over 5 signers), counted as neither computed nor shed.
- **Surplus:** fan-out all computes ≈ 5 shares per token and combines 3, so ≈ 39 % of
  computed shares are surplus even without overload (c=10).
- **Scope:** this is a deliberately starved configuration (25 % of one vCPU and one slot
  per signer). At the uncapped 7C configuration, no signer returned 503 in any token,
  scale-up or lever run (N69, N72). The claim is only that uncoordinated per-signer
  shedding **can** waste a third or more of the signers' work once they are overloaded.

### N74. Final numbers come from Phase 7C
No separate 7B re-run was made; every final B0/B1/T number comes from Phase 7C
(`…20260927T131349Z-73be90f-7C`, tokens + scale-up; lever check N72; stress test N73),
measured in one session on one cluster (the ap-south-1 quota was approved, N66), so the
anchor-drift table (N67) was not needed. 7A and 7B keep their labels and restrictions
(N62, N63).
- **Teardown** 2026-09-27T19:49–19:52Z: all 15 instances terminated, EIP released, 10
  security groups and 5 key pairs deleted, local SSH key deleted; zero tagged resources in
  all 5 regions, and an independent check found 0 non-terminated instances, 0 volumes and 0
  Elastic IPs of any tag (`reports/aws/TEARDOWN-7C-20260927T194900Z.md`). The 7C cluster ran
  about 10.5 h (09:15–19:49Z).

### N75. Priority-consistent admission: design recorded (not implemented); open question on signer CPU
- **Design:** `docs/PRIORITY_ADMISSION.md`, for review, nothing implemented. It answers
  N73 (collapse with wasted shares observed in the stress test), following DAGOR (Zhou et al.,
  SoCC 2018).
  - (A) Signer side: priority p = HMAC(K_prio, hourly epoch ‖ request_id). K_prio is
    dealer-distributed to the signers only, never to the coordinator. Each signer keeps an
    admitted fraction f driven by a deadline-relative overload signal (N48 sheds, or mean
    queue wait > 0.5 × deadline budget), with α = 5 % / β = 1 %. The admitted sets are
    nested, so a token needs only p ≥ the 3rd-lowest level.
  - (B) Coordinator: abort once a quorum is impossible. Code check: today the collect loop
    waits for every contacted signer even after n − t + 1 refusals.
  - Security bound: without K_prio a compromised coordinator's requests have the same
    admission probability as honest ones, so it keeps only its volume advantage, bounded
    by the per-signer rate limit. That limit is shared by all clients today; the 3 replicas
    share one client cert. Proposed hardening: per-replica certs with a per-client fair
    share, a deadline cap, and p bound to the signing input with a request-ID replay cache.
  - Pre-registered evaluation rules (stress test, no-regression) are in the document.
  - The "more admission slots" test is labelled **inference test (admission slots)**:
    SIGNER_MAX_CONCURRENT 2/4/8 at c = 50, uncapped. Its rule is fixed in advance: the slot
    inference (N72) is supported iff goodput at 4 slots ≥ 1.2 × at 2 slots and signer CPU
    rises.
- **Open question (from N73):** in the stress test, signer CPU fell below the 25 % quota
  as c rose (23.2 % → 13.8 %). While a request waits, a free slot is always taken, so the
  capped signers were partly idle while shedding. **Not explained.** Hypotheses to
  instrument in the next stress run:
  - (a) CFS throttling inflating the wall-clock RSA estimate, which makes N48 over-shed:
    log `RSAEstimate` and `cpu.stat` throttling;
  - (b) bursty arrivals emptying the queue: sample queue length and slot occupancy at 10 Hz;
  - (c) window artefact from warm-up and drain: compute CPU over the measured window only.

### N76. Priority-consistent admission implemented (B, A, hardening); evaluation pending
Design: `docs/PRIORITY_ADMISSION.md`, approved with three additions: the epoch rule, no
starvation, and the hardening in scope. Every DAGOR detail cited is **from memory, to be
verified against the PDF** (Zhou et al., SoCC 2018). Nothing here has been measured on
AWS yet.
- **B, quorum-impossible abort** (coordinator, on by default; `QUORUM_ABORT=off` is the
  benchmark's "before" variant).
  - Once more than n − t distinct signers have failed, the request fails at once; the
    outstanding signer requests are cancelled and queued signers drop them before RSA.
  - `TestQuorumImpossibleAbortsEarly`: fails after 2 ms instead of 1.5 s, and both slow
    signers see the cancellation.
  - `TestQueuedRequestCancelledByCallerComputesNoShare`.
  - `TestQuorumAbortReducesWastedSharesSimulation` (LOCAL SIMULATION: 40 % independent
    refusals, 300 ms queue; not a measurement): 37 shares wasted without the abort, 0
    with it.
  - Four existing tests asserted `Valid == 2`, which holds only if the coordinator waits
    for every signer: `TestThreeMaliciousFails`, `TestBelowThresholdSigners`,
    `TestHedgedBelowThresholdFails`, `TestBelowThresholdFails`. They now run their
    original assertions with `NoQuorumAbort: true`, unchanged, and each has an added
    abort-mode case (`TestBelowThresholdFailsWithAbort` for T3).
- **A, priority admission** (signer, `SIGNER_ADMISSION=priority`; default n48).
  - p = HMAC-SHA256(K_prio, domain ‖ epoch ‖ request_id)[:2], with epoch = ⌊iat / 3600⌋.
  - The epoch comes from the token's own validated `iat`, not the signer's clock, so
    signers straddling an hour boundary agree (`TestEpochBoundarySignersAgree`: clocks
    20 ms apart across 11:00:00, 120/120 identical decisions).
  - Adaptive admitted fraction per 250 ms / 200-arrival window: −5 % when overloaded
    (N48 shed, or mean wait > 0.5 × median deadline budget), +1 % otherwise; floor 0.05.
    The check runs after policy and before the N48 queue.
  - Tests: `TestNestedAdmissionSetsAcrossSigners` (subsets nested; ≥ 3 shares ⇔ the 3rd
    most lenient signer admits), `TestAdmissionLevelAdapts` (650 ms waits against a 2 s
    budget are not overload, as at uncapped 7C c=50), `TestPriorityRefusalHTTPAndAudit`
    (503 overloaded, `X-Frost-Admission-Level`, audit `shed`, policy denial still first),
    and `TestPriorityRefusalNeverTripsBreaker` (2 or 3 refusing signers: 0 suspects,
    0 fallbacks).
  - No starvation: each retry is a new Sign call with a new request_id, hence a fresh
    priority (`TestRetryGetsNewRequestID`; `TestRefusedRequestsAreNotStarved`: f = 0.3,
    400 of 400 admitted, mean 3.33 attempts, worst 17).
  - K_prio: the dealer writes `priority.key` (0600, bound to the kid; in Vault mode
    `frost-k8s/priority-key`); `internal/prioritykey`.
  - Guards: T12 forbids the package and path in the coordinator's dependency graph; T11
    and check-images flag the file and its field.
  - Distribution: every signer gets the key (`deploy.sh`, `setup-signer-host.sh`,
    compose), never the coordinator (`deploy.sh` guard).
- **Hardening (in scope, per the approval).**
  - Per-replica client certificates: `coordinator-1..3`, each replica mounts only its
    own, `COORDINATOR_ID` required. Signers accept only the canonical `coordinator-<1..64>`;
    the shared `coordinator` is refused.
  - Per-client fair share under overload: ⌈1.25 × previous window's admissions / clients⌉
    (`TestFairShareCapsAFloodingClient`).
  - Deadline header capped at `SIGNER_MAX_DEADLINE` = 4 s (`TestDeadlineHeaderIsCapped`).
  - **Follow-up, not implemented:** bind p to SHA-256(signing input) and add a request-ID
    replay cache. Priority classes are also not implemented.
- **Instrumentation for N75's open question** (signer CPU below the quota):
  - sign-share lines carry `rsa_ms` and `rsa_estimate_ms`;
  - optional `SIGNER_QUEUE_SAMPLE` logs waiting and busy slots;
  - the 7C driver samples each signer's CPUUsageNSec and cgroup `throttled_usec` at 1 Hz
    and keeps the signer journal per configuration;
  - the summarizer reports CPU over the measured window only, throttled %, RSA time and
    estimate, and queue idle %.
- **Evaluation tooling** (`benchmark/k8s7c/run.sh eval-stress | eval-noregress | eval-slots`):
  - Systems are `<T system>@<variant>` (n48, b, ab, slots<k>).
  - Every switch verifies each coordinator's `coordinator_id` and `quorum_abort`, and each
    signer's `admission` and `max_concurrent` (`deploy/aws/7c/signer-config.sh`).
  - The summarizer applies the §5 rules as written (`TestEvalSection`).
  - `signer-config.sh` and `signer-sampler.sh` were exercised against real systemd, with a
    dummy unit in the tk8s VM (unit removed afterwards).

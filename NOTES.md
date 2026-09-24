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
A probe cluster showed their exact positions (apiserver command indices 23 and 24;
kind's own `--runtime-config=` extra arg is appended **after** the sorted base flags,
so extra args don't shift them). `test/e2e/kubeadm-patches/*.json` removes them with
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

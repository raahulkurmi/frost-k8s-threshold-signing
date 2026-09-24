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
- **N14. Policy decoding is case- and duplicate-strict.** Go's `encoding/json` struct
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

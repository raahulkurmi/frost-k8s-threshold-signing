# legacy/frost: the abandoned FROST prototype

This directory keeps the original FROST-based prototype for reference and for the
claims audit (`reports/CLAIMS_AUDIT.md`). **None of it is built, shipped or reachable at
runtime.**

- It is a **separate Go module** (`frost-k8s-threshold-signing/legacy/frost`), so
  `go build ./...` and `go test ./...` at the repository root never see it, and
  `github.com/bytemare/*` is not in the main module's `go.mod`.
- Every `.go` file carries `//go:build legacy`. To confirm it still compiles:
  `cd legacy/frost && go build -tags legacy ./...`
- Its keys, certs and passwords (the old `data/`, `certs/`, `frost-dev-password` and
  `frost-dev-token`) are **burned**. See `reports/HISTORY_PURGE.md`.

## Why FROST was abandoned

**1. Kubernetes verifies only RS256, ES256, ES384 and ES512.** At the target version,
v1.36.5 (commit `ad950d1cc78b0183c476bd4d3f1934c104229727`):

| File | Line | What it enforces |
|---|---|---|
| `pkg/serviceaccount/externaljwt/plugin/plugin.go` | 180 | `validateJWTHeader`: `case "RS256", "ES256", "ES384", "ES512":`, any other `alg` is rejected (`bad signing algorithm`) |
| `pkg/serviceaccount/jwt.go` | 123, 153–161 | Signers exist only for RSA (RS256) and ECDSA P-256/384/521 (ES256/384/512) |
| `pkg/serviceaccount/openidmetadata.go` | 316–325 | `algorithmFromPublicKey` maps only RSA → RS256 and ECDSA curves → ES256/384/512 |
| `staging/src/k8s.io/externaljwt/apis/v1/api.proto` | 60, 91 | "alg must be one of … (currently RS256, ES256, ES384, ES512)"; keys must be "RSA 256 or ECDSA 256/384/521" (PKIX) |

The verifier is go-jose **v2.6.3** (`gopkg.in/go-jose/go-jose.v2`). It has no EdDSA
over Ristretto255 and no Schnorr algorithm.

**2. FROST outputs Schnorr signatures over Ristretto255.** The prototype used
`frost.Default` / `ecc.Ristretto255Sha512` (`cmd/keygen`,
`internal/coordinatorstate/bootstrap.go`). The group key is a Ristretto255 point, not a
P-256 point. It cannot be exported as a PKIX ECDSA key that ES256 would verify, and it
cannot be expressed as an RSA key.

**3. No re-encoding turns one signature into the other.** A Schnorr signature `(R, z)`
satisfies `z·G = R + c·Y` on Ristretto255. ECDSA verification checks a different
equation (`r ≟ x((e·s⁻¹)·G + (r·s⁻¹)·Q)`) on a different group, and RSA verification
checks `σ^e ≡ EMSA-PKCS1-v1_5(m) (mod N)`. Converting to IEEE P1363 or DER only changes
how bytes are laid out. It doesn't change which equation the signature satisfies. A
FROST signature therefore can never pass ES256 or RS256 verification under any key,
even if the FROST ciphersuite were switched to P-256: FROST-P256 still produces Schnorr
signatures, not ECDSA signatures.

**4. So the prototype signed with a separate single ECDSA key.** In
`cmd/grpc-proxy/main.go` `makeSignFn()` (kept here), the FROST aggregate was computed
and **discarded** (`_, err = aggregateSignature(...)`). The JWT signature came from
`ecKey.SignES256(signingInput)`, a single P-256 key held by the coordinator
(`internal/signing/ecdsa.go`, which also silently generated a new key if the file was
missing). `FetchKeys` published that key's public half. FROST acted only as a gate.
Stealing one file (`data/ecdsa-signing.pem`) was enough to forge any token.

**5. Replacement.** The runtime now uses **Shoup threshold RSA** (`github.com/niclabs/tcrsa`
v0.0.5). Signers produce shares of a standard RSASSA-PKCS1-v1_5 SHA-256 signature, and
the combined result is an ordinary RS256 signature that kube-apiserver verifies
natively against the group public key served by `FetchKeys`. See the top-level `README.md`,
`docs/KEY_CEREMONY.md` and `spike/` (the Phase 0 evidence).

Threshold ECDSA (e.g. CGGMP21) could produce real ES256 signatures in principle. It
wasn't used because the maintained Go implementation, `taurusgroup/multi-party-sig`,
supports only secp256k1, and Kubernetes doesn't accept ES256K.

## Contents

| Path | Was |
|---|---|
| `cmd/grpc-proxy` | Old coordinator: FROST gate plus single-key ES256 signing (D1, D2) |
| `cmd/signer` | Old FROST signer. Loaded all 5 shares (D6); fell back to plain HTTP; `RequestClientCert` never verified clients |
| `cmd/coordinator`, `cmd/dkg-coordinator`, `cmd/frostlab`, `cmd/testsign` | HTTP coordinator, DKG driver, experiments |
| `cmd/keygen`, `cmd/encrypt-keys` | Trusted-dealer FROST keygen into one all-shares file; AES-GCM wrapper keyed by unsalted SHA-256(password) |
| `internal/signing` | The single ECDSA key (D1–D3) |
| `internal/froststate`, `internal/coordinatorstate` | Share loading (coordinator decoded all 5 secret shares, D5) |
| `internal/api`, `internal/dkg`, `internal/keystore`, `internal/mtls`, `internal/config`, `internal/grpcserver`, `internal/signer`, `internal/coordinator`, `internal/types` | Supporting code |
| `proto/externaljwt/v1alpha1`, `externaljwt/v1alpha1` | Hand-copied stubs (labelled v1alpha1, declared `package v1`) |
| `deploy/`, `scripts/` | k3d config, Vault init, minikube/socat restart scripts |
| `benchmark/` | Old FROST-vs-baseline scripts and results, **superseded** by Phase 7 |

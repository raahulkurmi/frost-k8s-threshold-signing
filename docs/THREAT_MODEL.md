# Threat model

> Scope: the threshold RSA ExternalJWTSigner in this repository (runtime binaries
> `cmd/grpc-proxy`, `cmd/signer`; ceremony `cmd/dealer`). The abandoned FROST prototype
> (`legacy/frost/`) is out of scope except where the claims audit refers to it.
> Test IDs refer to `test/`, `internal/*/…_test.go`, `test/e2e/run.sh` (E*, N*, REQ-*),
> `test/e2e/multihost.sh` (L*), and Phase 9's compromise tests (C*).

## 0. Assets and actors

| Asset | Where it lives | Why it matters |
|---|---|---|
| 5 secret shares (`share-<i>.json`) | one per signer host, `0600`, owned by that signer's OS user | any 3 can sign anything |
| The full RSA private key | only in the dealer's memory during the ceremony | signs anything, forever |
| Group public key + share verification keys (`public-meta.json`) | coordinators, signers, kube-apiserver (via FetchKeys) | public; integrity matters |
| mTLS keys: `coordinator`, `coordinator-grpc`, `lb`, `signer-<i>`; the CA key | coordinator host / nginx / each signer host; CA key only on the dealer machine | authenticate each hop |
| Issued tokens | clients, pods | bearer credentials until `exp` |

Actors: kube-apiserver (the only intended Sign caller), nginx, 3 coordinators, 5 signers,
the dealer/operator, token requesters (anything with RBAC to create tokens), and
attackers with the capabilities in §7.

## 1. Who can reach Sign (Phase 6.5)

`Sign` is the only operation that produces a token. Anyone who can call it successfully
gets **policy-compliant** tokens, because the signers still apply their claims policy.
So the set of callers must be as small as the deployment allows.

**Reference deployment:** `deploy/docker-compose.yml` plus the kind cluster from `make e2e`.

| Hop | Transport | Authentication | Who else could connect | Evidence |
|---|---|---|---|---|
| kube-apiserver → nginx | Unix socket `run/signer.sock`, bind-mounted into the kind control-plane node at `/var/run/frost-k8s/signer.sock` | Filesystem permissions on the **parent directory**: `run/` is **`root:root 0700`**. nginx always chmods a unix listening socket to 0666 (`src/core/ngx_connection.c`), so the socket's own mode is not a control | **Only root** on the VM host or on the control-plane node (kube-apiserver runs as root). Non-root users are refused. There is **no TCP listener** | N2 (directory-mode check plus a non-root connect attempt), `deploy/nginx-grpc.conf` (only `listen unix:`) |
| nginx → coordinator (×3) | TCP 9090 on `lb-net` (`172.30.1.0/24`) | **mTLS**. nginx presents SAN `lb` (clientAuth). Each coordinator presents SAN `coordinator-grpc` (serverAuth). The coordinator accepts **only** a client cert with exactly `DNS:lb` from the deployment CA | Only containers attached to `lb-net`: nginx, the coordinators and e2e probe containers. Even on `lb-net`, a caller without the `lb` key is refused at TLS | N1, `TestTCPListenerRequiresLBClientCert`, T8 (no plaintext TCP mode exists) |
| coordinator → signer (×5) | TCP 8443 on `signer-net` (`172.30.2.0/24`) | mTLS. The coordinator presents SAN `coordinator`, and each signer presents `signer-<i>`, pinned per endpoint | Only containers on `signer-net`: coordinators and signers. **nginx is not on `signer-net`** | N3, `TestTLSRejectsClientWithoutCoordinatorSAN`, `TestShareIDBoundToMTLSIdentity` |
| VM host → any container | none | n/a | Nobody. Both networks are `internal` with `com.docker.network.bridge.inhibit_ipv4=true`, so the host has no address on either bridge and **no port is published** | N2 (`ss -tlnp` plus a connect attempt to every listening port of every container) |

**Remaining reachability (stated plainly):**
- The kind cluster's own API server is published by kind on `127.0.0.1:<random>` of the
  VM host (`docker-proxy` in `ss -tlnp`). That is the Kubernetes API, which requires
  Kubernetes authentication. It is not a path to the signer, although a caller with
  RBAC to create tokens can obtain them through the normal TokenRequest API.
- **Root on the VM host, or on the kind control-plane node**, can open the Unix socket, or
  exec into a coordinator and use its `lb`-facing listener with the mounted certs. Root on
  the host is also root over every container, share and key on this single host. This is
  the "single host" limitation: the reference deployment has **no signer independence**
  (Phase 7B).
- **Anyone holding the `lb` private key** and attached to `lb-net` can call Sign. The key is
  mounted only into the nginx container.
- **A caller that can reach Sign gets tokens for policy-compliant claims** (the online
  oracle). The signers' policy limits *what* can be signed, not *who* asks.

**nginx retries (`grpc_next_upstream error timeout non_idempotent`).** When nginx retries
a Sign on another replica, that replica repeats the fan-out. The effects are bounded:
- each contacted signer writes another audit entry and consumes another rate-limit token
  (at most 3 tries × 5 signers per apiserver request);
- the claims are identical and RSASSA-PKCS1-v1_5 is deterministic, so any second
  combined signature is **byte-identical** to the first (T2 / I6). A retry cannot produce
  a second, different token, and the apiserver uses only the one response it receives;
- no share or partial result leaves a coordinator except through its own response.

## 2. Error disclosure to token requesters (N33)

When signing fails, kube-apiserver relays the ExternalJWTSigner error text to the client
that requested the token. The coordinator therefore returns only fixed, generic messages
(`internal/grpcserver/server.go`):

| Situation | gRPC code | Message seen by the requester |
|---|---|---|
| Fewer than t valid shares: signers down, refused by policy, or invalid shares | `Unavailable` | `token signing failed: threshold not met` |
| Empty or malformed claims | `InvalidArgument` | `token signing failed: invalid request` |
| Anything else | `Internal` | `token signing failed` |

The requester never learns **which** signers are down, **which** policy rule refused
the claims, or the refused value. That information exists only in:
- the coordinator log (`"msg":"sign failed"` with per-signer `failures`, `request_id`);
- each signer's audit log (`decision: deny`, `reason`).

Evidence: `TestSignErrorIsGeneric` (gRPC level, including a list of forbidden
substrings), e2e **REQ-b** (a non-allowlisted audience through kubectl returns the generic
error, and the coordinator log and signer audit contain the policy reason), and e2e **E6**
(3 signers down returns the generic error with no signer names).

## 3. Availability: signer clocks (N44)

Each signer checks `iat` against **its own clock** (±`clock_skew_seconds`, default 60 s)
before producing a share. A signer with a wrong clock therefore **fails closed**: it
refuses every token and is effectively down. When more than n − t = 2 signers have
wrong clocks, issuance stops.

This was observed in Phase 7B (NOTES N44). After the host slept, the signer VMs resumed
with clocks up to **39,124 s (about 10.9 h)** behind until systemd-timesyncd stepped them.
During that window the affected signers refused every request with `iat … is …s from
signer clock`. The policy behaved correctly; the cost was availability.

Operational requirement: **every signer needs reliable time synchronisation** (chrony
or NTP, stepping allowed at start/resume, with monitoring and alerting on offset). After a
VM resume or a clock jump, expect that signer to refuse requests until its clock resyncs.
Loosening `clock_skew_seconds` to ride out such events would widen the replay window
(Phase 9, C6); fixing time sync is the right answer.

## 4. What the system protects against, and what it does not

**Protects against:**
- **Theft of any fewer than 3 shares.** Fewer than t shares cannot produce a valid signature
  for any message: not by Join, not with K forced lower, not with fabricated shares
  (T4, spike `TestBelowThresholdFails`; C5 in Phase 9). A signer host compromise yields at most
  that host's shares: 1 on sig-c, 2 on sig-a or sig-b.
- **Theft of the coordinator.** A coordinator holds no share and no private key, only public
  metadata and its mTLS keys (I3: T12, check-images T13, L4). Copying its filesystem gives
  no offline signing capability (C4 in Phase 9).
- **Persistent offline forgery after a single-node compromise.** Losing control of a node
  ends the attacker's ability to obtain tokens. There is no key to take away.
- **Policy-violating tokens, even from a compromised coordinator.** Each signer re-checks the
  header and applies its own claims policy before producing a share: wrong issuer,
  non-allowlisted audience, over-long lifetime, stale or future `iat`, non-service-account
  or inconsistent `sub`, denied namespaces or accounts, and duplicate or case-variant JSON
  keys (N14) are all refused (T6, T7, `TestPolicyRejects`; C2(a) in Phase 9).
- **A malicious signer disrupting correct signers.** Bad shares are detected by Shoup's
  proof, excluded, and attributed to the signer ID. Signing succeeds while ≥ 3 valid shares
  remain (I7: T5, `TestMaliciousShareExcludedAndAttributed`).
- **Unauthorised callers on the network.** See §1 (N1–N4, L1–L2).

**Does NOT protect against:**
- **An attacker who controls a coordinator or kube-apiserver obtaining signatures on
  policy-compliant claims while in control (online oracle).** The policy limits *what*
  is signed, not *who* asks (C2(b) in Phase 9).
- **3 or more colluding or co-compromised signers.** They can sign anything (C3 in Phase 9
  confirms the boundary). On the Level 1 topology, compromising sig-a and sig-b (2 VMs)
  already yields 4 shares.
- **A malicious or compromised dealer.** The dealer sees the whole key (docs/KEY_CEREMONY.md).
- **Theft of already issued tokens.** Bearer tokens remain valid until `exp` (max 7200 s
  under the deployed policy). Threshold signing does not help after issuance.
- **Co-located signers.** The single-host deployment (all 5 signer containers on one VM)
  and the Level 1 multi-VM deployment (four VMs on one Mac) have one hypervisor, one
  operator and one software build. Root on the physical host defeats the threshold. See §6.
- **Common-mode software failure.** All signers run the same binary. One exploitable bug
  or a supply-chain compromise affects all of them at once.
- **Denial of service.** Anyone who can reach Sign can consume signer capacity. Availability
  also depends on signer clocks (§3).

## 5. `niclabs/tcrsa` hazards and how the coordinator mitigates them (R-d)

`github.com/niclabs/tcrsa` **v0.0.5** (tagged 2020-12-07; the only later change is a
license rewrite, NOTES N6) is **unaudited and unmaintained since 2020**. Hazards found by
reading its source and testing it (NOTES N3, N4, N5, N21):

| Hazard | Evidence | Mitigation in this repository |
|---|---|---|
| `SigShare.Verify` **panics** for `Id == 0` or `Id > L` (it indexes `VerificationKey.I[Id-1]` unchecked). A malicious signer could crash the coordinator | spike `TestLibraryHazards` | `wire.ToTcrsa` rejects ids outside `[1,n]` before any tcrsa call, and the id is **never taken from the response**: it is the mTLS-authenticated endpoint identity (`TestJoinOutOfRangeIDs`, `TestShareIDBoundToMTLSIdentity`) |
| `Join` accepts **duplicate ids** and returns an invalid signature without error | spike `TestLibraryHazards` | the coordinator dedupes by id; one share per authenticated endpoint |
| `Join` **does not verify shares** and does not check its result: an unverified bad share silently yields an invalid signature | spike `TestTamperedShareRejected` | strict mode verifies every share; optimistic mode verifies all shares after a failed combine; **both always verify the final signature with `rsa.VerifyPKCS1v15` before returning** (I7, T5) |
| `Join` with out-of-range ids returns no error and an invalid signature (no panic) | `TestJoinOutOfRangeIDs` | same bounds check as above |
| `NewKey(b)` yields a `(b−1)`-bit modulus | spike `TestTcrsaModulusIsBitSizeMinusOne` | the dealer calls `NewKey(2049)` and checks the modulus is exactly 2048 bits; `keymeta.Parse` rejects < 2048 |
| `KeyShare.Sign` expects an **already padded** document | source (`key_share.go`) | signers compute SHA-256 and EMSA-PKCS1-v1_5 **themselves** from the full signing input; they never accept a digest or padded block (I8, T6) |
| Share values are not range-checked | source (`signature_share.go`) | `wire.ToTcrsa` requires `xi ∈ [1, n−1]`, `c < n` and a bound on `|z|`; `keymeta` requires verification values in `[2, n−1]` |
| A share for the wrong index or key would be used silently | source | `keyshare.Parse` checks index, kid and **`v^si mod N == vk_i`** before a signer starts (T9, `TestWrongShareIndexRejected`, `TestWrongKidRejected`) |
| Unaudited implementation of Shoup's proofs | (no audit exists) | not mitigated beyond the final-signature check, which protects **correctness** but not **secrecy** of shares against implementation flaws. Stated as a remaining limitation |

## 6. Deployments and signer independence

| Deployment | Signers | Independence |
|---|---|---|
| Single host (`make e2e`) | 5 containers on one VM | **none**: one kernel, one Docker, one operator |
| Level 1 multi-host (`test/e2e/multihost.sh`) | native binaries on 3 VMs (2+2+1), per-signer OS users, hardened systemd, per-host firewalls | **multi-VM on one physical host**: separation of processes, users and networks (L1–L5), not of hardware, operator, software or dealer ([reports/INDEPENDENCE.md](../reports/INDEPENDENCE.md)) |
| Level 2 (separate regions/providers) | – | **not done** |

## 7. Attacker capability → what they get → evidence

| Attacker capability | What they get | Test |
|---|---|---|
| One or two stolen shares (+ public metadata), offline | nothing: no valid signature for any message | T4, spike I5; C5 (Phase 9) |
| Full control of one signer (bad shares, spoofed id, garbage, slow responses) | disruption only; excluded and attributed; tokens still issued with ≥ 3 honest | T5, `TestShareIDBoundToMTLSIdentity`, `TestJoinOutOfRangeIDs`; C1 (Phase 9) |
| Coordinator's full filesystem and config, after losing control | no token, no offline signing | T12, T13, L4; C4 (Phase 9) |
| Live control of the coordinator/apiserver | tokens for **policy-compliant** claims only while in control; policy-violating claims refused by every honest signer | T7; C2 (Phase 9) |
| 2 signers + live coordinator control | same as above: the 3 honest signers still enforce the policy | C2 (Phase 9) |
| 3 colluding signers | **forgery**, the threshold boundary | C3 (Phase 9) |
| Replay of an old signing request to signers | the same deterministic share for the same input; stale `iat` refused outside the skew window | C6 (Phase 9) |
| Flooding signers from a compromised coordinator | rate-limited and admission-controlled per signer | `TestSignerRateLimit`, N48 admission tests (`TestRequestThatCannotFitIsShedImmediately`, `TestQueueCapEnforced`); C7 (Phase 9) |
| Network position on the Docker/VM networks without the right mTLS key | no Sign, no FetchKeys, no signer access | N1–N4, L1–L2, `TestTLSRejectsClientWithoutCoordinatorSAN`, `TestTCPListenerRequiresLBClientCert` |
| Root on the physical host (single host or Level 1) | **everything**: all shares | §6 (inherent to these deployments) |
| Malicious dealer | **everything**, forever | trust assumption (docs/KEY_CEREMONY.md) |


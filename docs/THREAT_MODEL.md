# Threat model

> Status: the sections below were written in Phase 6.5. The full model (protects /
> does not protect, tcrsa hazards, attacker-capability table) is completed in
> Phases 8 and 9.

## 1. Who can reach Sign (Phase 6.5)

`Sign` is the only operation that produces a token. Anyone who can call it successfully
gets **policy-compliant** tokens, because the signers still apply their claims policy.
So the set of callers must be as small as the deployment allows.

**Reference deployment:** `deploy/docker-compose.yml` plus the kind cluster from `make e2e`.

| Hop | Transport | Authentication | Who else could connect | Evidence |
|---|---|---|---|---|
| kube-apiserver → nginx | Unix socket `run/signer.sock`, bind-mounted into the kind control-plane node at `/var/run/frost-k8s/signer.sock` | Filesystem access to the socket. It is created by nginx (root) inside the container | Any process on the VM host or the control-plane node that can open the socket file. There is **no TCP listener** | N2, `deploy/nginx-grpc.conf` (only `listen unix:`) |
| nginx → coordinator (×3) | TCP 9090 on `lb-net` (`172.30.1.0/24`) | **mTLS**. nginx presents SAN `lb` (clientAuth). Each coordinator presents SAN `coordinator-grpc` (serverAuth). The coordinator accepts **only** a client cert with exactly `DNS:lb` from the deployment CA | Only containers attached to `lb-net`: nginx, the coordinators and e2e probe containers. Even on `lb-net`, a caller without the `lb` key is refused at TLS | N1, `TestTCPListenerRequiresLBClientCert`, T8 (no plaintext TCP mode exists) |
| coordinator → signer (×5) | TCP 8443 on `signer-net` (`172.30.2.0/24`) | mTLS. The coordinator presents SAN `coordinator`, and each signer presents `signer-<i>`, pinned per endpoint | Only containers on `signer-net`: coordinators and signers. **nginx is not on `signer-net`** | N3, `TestTLSRejectsClientWithoutCoordinatorSAN`, `TestShareIDBoundToMTLSIdentity` |
| VM host → any container | none | n/a | Nobody. Both networks are `internal` with `com.docker.network.bridge.inhibit_ipv4=true`, so the host has no address on either bridge and **no port is published** | N2 (`ss -tlnp` plus a connect attempt to every listening port of every container) |

**Remaining reachability (stated plainly):**
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

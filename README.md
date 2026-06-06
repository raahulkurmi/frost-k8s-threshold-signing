# frost-k8s-threshold-signer

> **A proof-of-concept implementation of FROST threshold signing integrated with the Kubernetes ExternalJWTSigner API (KEP-740, stable v1.36)**

Kubernetes service account tokens are signed by a **single private key** — if that key is compromised, an attacker can forge tokens for any service account with any permission level. This project replaces that single key with **FROST threshold signing**, where 3-of-5 independent signers must collaborate to produce a valid token. No single compromise grants forging capability.

---

## Table of Contents

- [What Problem Does This Solve](#what-problem-does-this-solve)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Background: FROST and KEP-740](#background-frost-and-kep-740)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Setup and Running](#setup-and-running)
- [Testing and Benchmarks](#testing-and-benchmarks)
- [Known Limitations](#known-limitations)
- [Research Papers](#research-papers)
- [Future Work](#future-work)

---

## What Problem Does This Solve

In a default Kubernetes cluster, the `kube-apiserver` signs all service account JWT tokens using a single private key stored on the control plane filesystem.

**If this key is compromised:**
- Attacker can forge tokens for **any** service account
- Tokens can carry **any** namespace, permission level, and audience
- Short-lived tokens are irrelevant — attacker mints fresh valid tokens continuously
- Token rotation is irrelevant — the signing key itself is unchanged
- RBAC is bypassed — attacker chooses which identity to impersonate

This project introduces **threshold signing** so that no single component can forge tokens alone.

---

## How It Works

```
Normal Kubernetes:
  kube-apiserver → single private key → JWT signed ✅ (1 compromise = full control)

This project:
  kube-apiserver → gRPC proxy → 3-of-5 FROST signers → JWT signed ✅
                                (3 independent compromises required)
```

**Token creation flow:**

1. Pod requests a service account token
2. `kube-apiserver` calls the gRPC proxy via the ExternalJWTSigner interface (KEP-740)
3. The gRPC proxy (coordinator) contacts 3 of 5 independent signers
4. Each signer contributes a **partial signature** using their **key share**
5. The coordinator **aggregates** the partial signatures into one valid JWT signature
6. The signed JWT is returned to the pod — standard format, no changes to kubectl or client-go

The complete signing key **never exists** at any single location. Key shares are generated via FROST's Distributed Key Generation (DKG) protocol.

---

## Architecture

```
┌──────────────────────────┐
│      kube-apiserver       │
│                           │
│  --service-account-       │
│  signing-endpoint=        │
│  unix:///signer.sock      │
└────────────┬──────────────┘
             │ gRPC (ExternalJWTSigner — KEP-740)
             ▼
┌──────────────────────────┐
│    gRPC Proxy             │  ← implements ExternalJWTSigner interface
│    (FROST Coordinator)    │  ← holds no key material
└──┬────┬────┬────┬────┬───┘
   │    │    │    │    │   HTTP
   ▼    ▼    ▼    ▼    ▼
 ┌───┐┌───┐┌───┐┌───┐┌───┐
 │S1 ││S2 ││S3 ││S4 ││S5 │  ← independent signers (key shares only)
 └───┘└───┘└───┘└───┘└───┘
       3 of 5 respond
            │
            ▼
   FROST partial signatures
   aggregated into valid JWT
```

**Key properties:**
- Zero changes to Kubernetes core
- Output is a standard JWT — all existing clients, kubectl, and client-go work unchanged
- 3-of-5 threshold: system tolerates 2 signer failures
- Automatic failover: if a signer is unavailable, the next available signer is used

---

## Background: FROST and KEP-740

### FROST (RFC 9591)

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is an IETF-standardized threshold signature protocol. Key properties:

- **Threshold signing**: t-of-n parties must collaborate to sign — fewer than t cannot
- **Distributed Key Generation (DKG)**: The signing key is never assembled at any single location
- **Standard verification**: FROST signatures verify with a standard public key — verifiers need no knowledge of threshold signing
- **Misbehaving signer detection**: The protocol identifies faulty or malicious signers

NIST IR 8214C (January 2026) signals active government standardization of threshold cryptography schemes including FROST-like protocols.

### KEP-740 (Kubernetes Enhancement Proposal 740)

KEP-740 is the Kubernetes Enhancement Proposal that introduced the **ExternalJWTSigner** gRPC interface, allowing `kube-apiserver` to delegate service account token signing to an external service. It became **stable in Kubernetes v1.36 (April 2026)**.

The gRPC interface:

```protobuf
service ExternalJWTSigner {
  rpc Sign(SignJWTRequest) returns (SignJWTResponse) {}
  rpc FetchKeys(FetchKeysRequest) returns (FetchKeysResponse) {}
  rpc Metadata(MetadataRequest) returns (MetadataResponse) {}
}
```

This project implements this interface and backs it with FROST threshold signing, combining threshold cryptography with the Kubernetes token signing pipeline.

---

## Repository Structure

```
frost-k8s-threshold-signer/
├── cmd/
│   ├── grpc-proxy/        # gRPC proxy entry point (ExternalJWTSigner coordinator)
│   ├── signer/            # Individual signer service entry point
│   ├── keygen/            # FROST DKG key generation
│   ├── coordinator/       # Legacy HTTP coordinator (Branch 1, for reference)
│   ├── frostlab/          # FROST library exploration and testing
│   └── testsign/          # Standalone signing tests
├── internal/
│   ├── grpcserver/        # gRPC server implementing ExternalJWTSigner
│   ├── signing/           # ECDSA key management for K8s verification compatibility
│   ├── froststate/        # FROST signer state (key shares, commitments, mutex)
│   ├── coordinatorstate/  # FROST coordinator state (config, aggregation)
│   ├── api/               # HTTP API types (commitment, sign request/response)
│   ├── config/            # Environment-based configuration
│   ├── coordinator/       # Legacy coordinator (reference only)
│   ├── signer/            # Legacy ECDSA signer (reference only)
│   └── types/             # Shared types
├── proto/
│   └── externaljwt/v1alpha1/  # ExternalJWTSigner proto definition
├── externaljwt/v1alpha1/      # Generated gRPC stubs
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile.proxy   # gRPC proxy container
│   │   └── Dockerfile.signer  # Signer container
│   ├── docker-compose.yml     # Local dev: 5 signers + 1 proxy
│   └── k3d/
│       └── cluster-config.yaml
├── data/
│   ├── frost-keys.json        # FROST key shares (generated by keygen)
│   └── ecdsa-signing.pem      # ECDSA signing key (for K8s verification)
└── docs/
    └── architecture.md
```

---

## Prerequisites

- Go 1.23+
- Docker Desktop
- `protoc` (Protocol Buffers compiler)
- `kubectl`
- `minikube`

Install tools:

```bash
# macOS
brew install protobuf minikube kubectl

# Go gRPC plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

---

## Setup and Running

### Step 1: Clone and generate keys

```bash
git clone https://github.com/your-username/frost-k8s-threshold-signer.git
cd frost-k8s-threshold-signer

# Install dependencies
go mod tidy

# Generate FROST key shares (3-of-5 threshold)
# This creates data/frost-keys.json with 5 key shares
go run cmd/keygen/main.go

# Generate ECDSA signing key (for K8s verification compatibility)
go run cmd/genkey/main.go
```

### Step 2: Build and start containers

```bash
cd deploy

# Build Docker images
docker compose build

# Start 5 signers + gRPC proxy
docker compose up -d

# Verify all containers are running
docker compose ps
```

Expected output:
```
deploy-grpc-proxy-1   Up   0.0.0.0:9090->9090/tcp
deploy-signer-1-1     Up
deploy-signer-2-1     Up
deploy-signer-3-1     Up
deploy-signer-4-1     Up
deploy-signer-5-1     Up
```

Verify the proxy is listening:
```bash
docker compose logs grpc-proxy
# Expected: [grpc] Listening on tcp://0.0.0.0:9090
```

### Step 3: Start Minikube

```bash
cd ..
minikube start --driver=docker
```

### Step 4: Patch kube-apiserver to use FROST signing

Get the gRPC proxy IP:
```bash
PROXY_IP=$(docker inspect deploy-grpc-proxy-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')
echo "Proxy IP: $PROXY_IP"
```

Create socat bridge inside Minikube (routes unix socket → TCP):
```bash
docker exec minikube bash -c "
  mkdir -p /var/run/frost-k8s &&
  socat UNIX-LISTEN:/var/run/frost-k8s/signer.sock,fork,reuseaddr TCP:${PROXY_IP}:9090 &
"
```

Patch kube-apiserver manifest:
```bash
# Remove single signing key (mutually exclusive with signing endpoint)
docker exec minikube bash -c "
  sed -i '/--service-account-signing-key-file/d' /etc/kubernetes/manifests/kube-apiserver.yaml &&
  sed -i '/--service-account-key-file/d' /etc/kubernetes/manifests/kube-apiserver.yaml
"

# Add FROST signing endpoint
docker exec minikube bash -c "
  sed -i '/--service-account-issuer/i\\    - --service-account-signing-endpoint=/var/run/frost-k8s/signer.sock' \
  /etc/kubernetes/manifests/kube-apiserver.yaml
"

# Add volume mount so kube-apiserver can access the socket
docker exec minikube bash -c "
  sed -i '/    volumeMounts:/a\\    - mountPath: /var/run/frost-k8s\n      name: frost-k8s' \
  /etc/kubernetes/manifests/kube-apiserver.yaml &&
  sed -i '/  volumes:/a\\  - hostPath:\n      path: /var/run/frost-k8s\n      type: DirectoryOrCreate\n    name: frost-k8s' \
  /etc/kubernetes/manifests/kube-apiserver.yaml
"
```

Wait for kube-apiserver to restart (~30 seconds):
```bash
kubectl get pods -n kube-system | grep apiserver
# Expected: kube-apiserver-minikube   1/1   Running
```

### Step 5: Verify FROST signing is working

```bash
# Create a service account token
kubectl create token default

# Inspect the JWT header
kubectl create token default | cut -d. -f1 | base64 -d 2>/dev/null
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

If you see `kid: frost-k8s-v1` — FROST threshold signing is working.

---

## Testing and Benchmarks

### Verify threshold signing

```bash
# Single token — check header
kubectl create token default | cut -d. -f1 | base64 -d 2>/dev/null
# {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}

# Check proxy logs to confirm signing happened
cd deploy && docker compose logs grpc-proxy | grep "Signed JWT"
# [proxy] Signed JWT — kid=frost-k8s-v1 active_signers=[signer-1 signer-2 signer-3]
```

### Failure tolerance test

```bash
# Kill 2 signers — system should continue with remaining 3
docker stop deploy-signer-3-1 deploy-signer-4-1

# Token creation should still succeed
kubectl create token default
# Check active_signers in logs — should show signer-1, signer-2, signer-5

# Restore signers
docker start deploy-signer-3-1 deploy-signer-4-1
```

### Threshold enforcement test

```bash
# Kill 3 signers — below threshold, system should reject
docker stop deploy-signer-1-1 deploy-signer-2-1 deploy-signer-3-1

kubectl create token default
# Expected error: "not enough signers: got 2, need 3"

# Restore
docker start deploy-signer-1-1 deploy-signer-2-1 deploy-signer-3-1
```

### Latency benchmarks

```bash
# Single token
time kubectl create token default > /dev/null

# 100 tokens sequential
start=$SECONDS
for i in $(seq 1 100); do kubectl create token default > /dev/null; done
echo "Total: $((SECONDS - start))s for 100 tokens"

# 500 tokens sequential
start=$SECONDS
for i in $(seq 1 500); do kubectl create token default > /dev/null; done
echo "Total: $((SECONDS - start))s for 500 tokens"

# Concurrent requests (10 parallel)
time (for i in $(seq 1 10); do kubectl create token default > /dev/null & done; wait)
```

**Benchmark results (Minikube, Docker driver, macOS M-series):**

| Test | Baseline RS256 | FROST 3-of-5 | Overhead |
|------|---------------|--------------|---------|
| Single token | ~62ms | ~86ms | +24ms |
| 100 tokens avg | ~40ms | ~40ms | ~0ms |
| 500 tokens avg | ~30ms | ~52ms | +22ms |
| Concurrent (10) | ~241ms | ~277ms | +36ms |
| Memory (idle) | ~5MB | ~22MB | +17MB |
| Memory (load) | ~5MB | ~25MB | +20MB |

> **Note:** These benchmarks were conducted on a local Minikube environment with Docker driver on macOS, including socat bridge overhead. The FROST signing itself contributes approximately 10–20ms; remaining overhead is network, kubectl, and environment-specific. Production Linux deployments will show different absolute numbers.

### Pod SA token verification

```bash
# Run a pod and inspect its mounted SA token
kubectl run test-pod --image=nginx --restart=Never
kubectl wait --for=condition=Ready pod/test-pod --timeout=60s
kubectl exec test-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token \
  | cut -d. -f1 | base64 -d 2>/dev/null
# {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

Pods automatically receive FROST threshold signed tokens — no application changes required.

---

## Known Limitations

This is a **proof-of-concept prototype**. The following limitations exist and are identified as future engineering work:

**1. Token verification for internal K8s components**
Controller-manager, scheduler, and other internal components use SA tokens to authenticate to the apiserver. These tokens currently fail verification because the FROST verification key cannot be directly exported to the PKIX format expected by kube-apiserver for signature verification. `kubectl create token` and pod-mounted tokens work correctly; internal component authentication is broken.

**2. socat bridge (macOS/Docker)**
The Unix socket connection between kube-apiserver and the gRPC proxy uses a socat bridge on macOS because Docker Desktop's networking prevents direct volume sharing between Minikube and Docker containers. On a Linux host with containerd, this bridge is unnecessary — the socket can be directly mounted.

**3. Sequential signer communication**
The coordinator contacts signers sequentially (commit → all, sign → all). Parallel HTTP calls would reduce latency from ~40ms to ~15ms. This is a straightforward optimization not implemented in the prototype.

**4. Plaintext key shares**
`data/frost-keys.json` stores key shares as plaintext. Production deployment requires HSM or secrets management (e.g., HashiCorp Vault/OpenBao) for key share storage.

**5. No mTLS between coordinator and signers**
Signer HTTP endpoints have no authentication. Any process on the same Docker network can request commitments and signature shares. Production requires mutual TLS with certificate-based identity.

**6. Coordinator single point of failure**
The gRPC proxy coordinator holds no key material but is a single component. If it fails, token issuance halts. Production requires proxy replication with load balancing.

**7. Manual key rotation**
Key rotation requires running `cmd/keygen/main.go`, rebuilding containers, and restarting. Automated key rotation via Vault's dynamic secrets or FROST's proactive resharing protocol is not implemented.

**8. DKG not distributed**
The `cmd/keygen/main.go` generates all key shares in one process and writes them to a single JSON file. A proper DKG ceremony would generate shares without any single party ever seeing the complete key.

---

## Research Context

This prototype is the implementation component of an ongoing research series on threshold-based authentication for Kubernetes. Research papers are in preparation and will be linked here upon publication.

---

## Future Work

- Fix controller-manager token verification (PKIX-compatible key export)
- Parallel signer communication (reduce latency ~60%)
- mTLS between coordinator and signers
- OpenBao/Vault integration for key share storage
- Proper distributed DKG ceremony (no single-process key generation)
- Coordinator high availability (multiple proxy replicas)
- Automated key rotation via proactive resharing
- Kubernetes Operator for automated signer lifecycle management
- Tiered authentication model (Tier 2/3 for sensitive operations)
- Formal security verification of composed system
- Production benchmarks on Linux bare-metal

---


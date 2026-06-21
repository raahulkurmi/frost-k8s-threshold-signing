# frost-k8s-threshold-signing

**First working implementation of FROST threshold signing integrated with the Kubernetes ExternalJWTSigner API (KEP-740, stable v1.36)**

[![Go](https://img.shields.io/badge/Go-1.23+-blue)](https://go.dev) [![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE) [![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.36+-blue)](https://kubernetes.io) [![SCORED 2026](https://img.shields.io/badge/SCORED-2026-orange)](https://scored.dev) [![Zenodo](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.20770308-blue)](https://doi.org/10.5281/zenodo.20770308)

| # | Title | Venue | Status |
|---|---|---|---|
| 📖 Paper 1 | [Authentication Mechanisms in Kubernetes: A Systematic Review](https://doi.org/10.5281/zenodo.20734453) | Zenodo | Published |
| 🔒 Paper 2 | [Threat Modeling and Security Analysis of Threshold-Based Token Signing](https://doi.org/10.5281/zenodo.20733863) | Zenodo | Published |
| 🚀 Paper 3 | [frost-k8s: A FROST-Based Threshold Signing Proxy *(this repo)*](https://doi.org/10.5281/zenodo.20770308) | Zenodo + SCORED '26 | Under Review |

---

## What Is This?

Kubernetes signs every service account JWT token using a single private key stored on the control plane filesystem. If that key is ever stolen — by an attacker, a malicious insider, or a misconfigured backup — the attacker can forge tokens for any service account with any permission level. Token rotation doesn't help. RBAC doesn't help. Short-lived tokens don't help. The attacker just mints new valid tokens continuously, forever.

This project replaces that single key with **FROST threshold signing** — a cryptographic protocol where **3 out of 5 independent signers must collaborate** to produce any valid token. No single compromise grants forging capability.

```
Default Kubernetes:
  kube-apiserver → single private key → sign JWT
  (1 key stolen = full cluster access, forever, undetectable)

This project:
  kube-apiserver → gRPC proxy → 3-of-5 FROST signers → sign JWT
  (need 3 independent compromises to forge any token)
```

The output is a **standard JWT** — kubectl, client-go, and all existing tools work without any changes.

---

## 📊 Benchmark Summary

| Metric | Baseline RS256 | FROST 3-of-5 |
|---|---|---|
| Warm latency (P50) | 34ms | 34ms (**0% overhead**) |
| Warm latency (avg) | 34ms | 36ms (+6%) |
| Sequential throughput | 31 tok/s | 31 tok/s |
| 50 concurrent overhead | — | +18% |
| Failure tolerance | None | **2-of-5 signers** |
| Signer recovery | N/A | 84ms |
| Coordinator HA | None | **3 instances, auto-failover** |

> Benchmarks on single-node Minikube, macOS Apple Silicon. See [Section 10](#10-benchmark-results) for full results.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [The Problem](#2-the-problem--in-detail)
3. [The Solution — How FROST Works](#3-the-solution--how-frost-works)
4. [Architecture](#4-architecture)
5. [Quick Start — macOS](#5-quick-start--macos)
6. [Quick Start — Linux](#6-quick-start--linux)
7. [First-Time Setup (Keys, Certs, Vault)](#7-first-time-setup-keys-certs-vault)
8. [Verification](#8-verification--check-everything-works)
9. [Running the DKG Ceremony](#9-running-the-dkg-ceremony)
10. [Benchmark Results](#10-benchmark-results)
11. [Failure Tolerance Testing](#11-failure-tolerance-testing)
12. [What Was Built](#12-what-was-built)
13. [Repository Structure](#13-repository-structure)
14. [Known Limitations](#14-known-limitations)
15. [Future Work](#15-future-work)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. Prerequisites

Install these before anything else:

| Tool | Version | Install |
|---|---|---|
| Go | 1.23+ | https://go.dev/dl/ |
| Docker Desktop | Latest | https://www.docker.com/products/docker-desktop/ |
| minikube | Latest | `brew install minikube` |
| kubectl | Latest | `brew install kubectl` |
| openssl | Any | Pre-installed on macOS/Linux |

**System requirements:** 8GB+ RAM, 10GB free disk space, macOS or Linux.

Verify:
```bash
go version        # 1.23+
docker --version
minikube version
kubectl version --client
```

---

## 2. The Problem — In Detail

### How Kubernetes Signs Tokens Today

When a pod starts, Kubernetes issues it a service account JWT token signed by `kube-controller-manager` using a private key — by default `/etc/kubernetes/pki/sa.key`.

```
Pod starts → kubelet requests token → kube-apiserver signs with sa.key
→ Token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token
→ Pod uses token to authenticate to Kubernetes API
```

### Why This Is a Problem

The `sa.key` file is stored in plaintext on the control plane, accessible to anyone with root, never rotated without restarting the apiserver, and **impossible to detect theft** — reading a file generates no audit logs.

If an attacker steals `sa.key`, they can forge tokens for any identity, with any permission, indefinitely.

### What Existing Mitigations Cannot Do

| Mitigation | What It Protects | Why It Fails Against Key Theft |
|---|---|---|
| Bound tokens (v1.22+) | Stolen pod tokens | Attacker forges new bound tokens with stolen key |
| Token rotation | Stale tokens | Same key signs new tokens |
| RBAC hardening | Overprivilege | Attacker forges any identity |
| Network policies | Lateral movement | Token auth happens at L7 via apiserver |
| SPIFFE/SPIRE | Workload identity | Single SPIRE root CA = same problem |
| External JWT Signer | Key extraction from disk | Still a single signing authority |

**None of these protect the signing key itself.**

---

## 3. The Solution — How FROST Works

### Threshold Cryptography

A (t, n) threshold signature scheme distributes signing capability among n parties such that any t can collaborate to produce a valid signature, but fewer than t cannot.

**For this project: t=3, n=5** — any 3 of 5 signers can sign, but 2 or fewer cannot.

### FROST (RFC 9591)

FROST is an IETF-standardized threshold Schnorr signature scheme with two key properties:

1. **Distributed Key Generation (DKG):** The signing key is generated collaboratively — it never exists at any single location.
2. **Standard verification:** The output is a standard Schnorr/ECDSA signature. Kubernetes doesn't need to know threshold signing happened.

### The Signing Flow

```
Pod requests token
      ↓
kube-apiserver calls gRPC proxy (ExternalJWTSigner — KEP-740)
      ↓
Proxy contacts 5 signers IN PARALLEL → accepts first 3 responses
      ↓
3 partial signatures aggregated → 1 valid Schnorr signature
      ↓
Standard JWT returned to pod
```

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Kubernetes Cluster                  │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │            kube-apiserver                     │   │
│  │  --service-account-signing-endpoint=          │   │
│  │  unix:///var/run/frost-k8s/signer.sock        │   │
│  └─────────────────┬────────────────────────────┘   │
│                    │ gRPC (KEP-740)                   │
│                    ▼                                  │
│  ┌─────────────────────────────────────────────┐    │
│  │         nginx Load Balancer (HA)             │    │
│  └──────┬──────────────┬──────────────┬────────┘    │
│         ▼              ▼              ▼              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐       │
│  │  Proxy-1   │ │  Proxy-2   │ │  Proxy-3   │       │
│  │ (no key    │ │ (no key    │ │ (no key    │       │
│  │ material)  │ │ material)  │ │ material)  │       │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘       │
│        └──────────────┴──────────────┘               │
│                       │ mTLS HTTPS (parallel)         │
└───────────────────────┼─────────────────────────────┘
                        │
        ┌───────┬───────┼───────┬───────┐
        ▼       ▼       ▼       ▼       ▼
      ┌───┐   ┌───┐   ┌───┐   ┌───┐   ┌───┐
      │ S1│   │ S2│   │ S3│   │ S4│   │ S5│
      │key│   │key│   │key│   │key│   │key│
      │sh1│   │sh2│   │sh3│   │sh4│   │sh5│
      └───┘   └───┘   └───┘   └───┘   └───┘
                        │
                ┌───────┴────────┐
                │ HashiCorp Vault │
                │ (key storage)  │
                └────────────────┘
```

**Key properties:**
- Zero Kubernetes core changes
- Standard JWT output — all existing clients work
- Tolerates 2 signer failures (3-of-5)
- 3 coordinator proxies behind nginx — no single proxy failure halts signing
- mTLS between coordinator and all signers

---

## 5. Quick Start — macOS

> **macOS users:** Docker Desktop prevents direct Unix socket sharing between containers and Minikube. This is handled automatically by `restart-frost.sh` using a socat bridge. **You do not need to set this up manually.**

**If you have already completed [Section 7](#7-first-time-setup-keys-certs-vault) (keys, certs, Vault):**

```bash
# Start Minikube
minikube start --driver=docker

# One command — starts containers, detects IPs, sets up socat bridge, patches apiserver
bash scripts/restart-frost.sh

# Verify — should show kid:frost-k8s-v1
kubectl create token default | cut -d. -f1 | base64 -d
```

**First time? Go to [Section 7](#7-first-time-setup-keys-certs-vault) first.**

---

## 6. Quick Start — Linux

> **Linux users:** No socat bridge needed. Direct volume mount works.

**If you have already completed [Section 7](#7-first-time-setup-keys-certs-vault):**

```bash
# Start Minikube
minikube start --driver=docker

# Start ALL 9 containers (signers, proxies, nginx, Vault)
cd deploy && docker compose up -d && cd ..

# Mount socket directly into Minikube (no socat needed on Linux)
mkdir -p /tmp/frost-k8s
minikube mount /tmp/frost-k8s:/var/run/frost-k8s &

# Patch apiserver
bash scripts/setup-minikube.sh

# Verify
kubectl create token default | cut -d. -f1 | base64 -d
```

**First time? Go to [Section 7](#7-first-time-setup-keys-certs-vault) first.**

---

## 7. First-Time Setup (Keys, Certs, Vault)

Run this once. After first-time setup, use Quick Start ([macOS](#5-quick-start--macos) / [Linux](#6-quick-start--linux)) for subsequent runs.

### Step 1: Clone and Install Dependencies

```bash
git clone https://github.com/raahulkurmi/frost-k8s-threshold-signing.git
cd frost-k8s-threshold-signing
go mod tidy
```

### Step 2: Generate FROST Key Shares

```bash
go run cmd/keygen/main.go
# Creates data/frost-keys.json — 3-of-5 threshold key shares
# Any 3 can sign; 2 or fewer cannot produce any valid signature
```

### Step 3: Generate ECDSA Signing Key

```bash
go run cmd/genkey/main.go
# Creates data/ecdsa-signing.pem — ECDSA P-256 key for JWT signing
```

### Step 4: Encrypt Key Shares

```bash
go run cmd/encrypt-keys/main.go
# Creates data/frost-keys.enc — AES-256-GCM encrypted key shares
# Set FROST_KEY_PASSWORD env var for production (default: "frost-dev-password")
```

### Step 5: Generate mTLS Certificates

We need 3 certificates:
- **CA** — Certificate Authority that signs both proxy and signer certs
- **Proxy cert** — Identity for the gRPC coordinator
- **Signer cert** — Identity for all 5 signer containers (shared cert with SANs for each hostname)

```bash
mkdir -p certs

# 1. Certificate Authority
openssl genrsa -out certs/ca.key 2048
openssl req -new -x509 -days 365 -key certs/ca.key \
  -out certs/ca.crt -subj "/CN=frost-k8s-ca"

# 2. Proxy certificate
openssl genrsa -out certs/proxy.key 2048
openssl req -new -key certs/proxy.key \
  -out certs/proxy.csr -subj "/CN=frost-proxy"
openssl x509 -req -days 365 \
  -in certs/proxy.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/proxy.crt

# 3. Signer certificate (SANs allow one cert to work for all 5 signer hostnames)
cat > certs/signer-ext.cnf << 'EOF'
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = signer-1
DNS.2 = signer-2
DNS.3 = signer-3
DNS.4 = signer-4
DNS.5 = signer-5
DNS.6 = localhost
EOF

openssl genrsa -out certs/signer.key 2048
openssl req -new -key certs/signer.key \
  -out certs/signer.csr -subj "/CN=frost-signer"
openssl x509 -req -days 365 \
  -in certs/signer.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/signer.crt \
  -extensions v3_req -extfile certs/signer-ext.cnf

# Verify
ls certs/
# Expected: ca.crt ca.key proxy.crt proxy.key signer.crt signer.key signer-ext.cnf
```

### Step 6: Start Vault and Load Key Shares

```bash
cd deploy && docker compose up -d vault && sleep 5 && cd ..
bash scripts/vault-init.sh
# Each signer fetches only its own share from Vault at startup
```

### Step 7: Build and Start All Containers

```bash
cd deploy
docker compose build
docker compose up -d
```

This starts **9 containers**:

| Container | Role | Port |
|---|---|---|
| deploy-vault-1 | Key share storage | 8200 |
| deploy-signer-1-1 through 5-1 | FROST Signers 1–5 | 8081–8085 (mTLS) |
| deploy-grpc-proxy-1-1 through 3-1 | Coordinator instances | internal |
| deploy-coordinator-lb-1 | nginx load balancer | 9090 |

### Step 8: Start Minikube and Configure FROST

---

**🍎 macOS users — run this:**
```bash
cd .. && minikube start --driver=docker
bash scripts/restart-frost.sh
# socat bridge is set up automatically
```

---

**🐧 Linux users — run this:**
```bash
cd .. && minikube start --driver=docker

# Start ALL containers
cd deploy && docker compose up -d && cd ..

# Mount socket directly (no socat needed)
mkdir -p /tmp/frost-k8s
minikube mount /tmp/frost-k8s:/var/run/frost-k8s &

# Patch apiserver
bash scripts/setup-minikube.sh
```

---

### Step 9: Verify

```bash
kubectl create token default | cut -d. -f1 | base64 -d
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

---

## 8. Verification — Check Everything Works

### Verify FROST Token Header

```bash
kubectl create token default | cut -d. -f1 | base64 -d
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

- `alg: ES256` — ECDSA P-256 ✅
- `kid: frost-k8s-v1` — FROST proxy signed this ✅

### Verify Proxy Logs Show Signing

```bash
cd deploy && docker compose logs grpc-proxy-1 | grep "Signed JWT" | tail -3
# Expected: [proxy] Signed JWT — kid=frost-k8s-v1 active_signers=[signer-3 signer-1 signer-4]
```

### Verify Coordinator HA

```bash
# Kill one proxy — signing should continue via the other two
docker stop deploy-grpc-proxy-1-1
kubectl create token default | cut -d. -f1 | base64 -d
# Expected: frost-k8s-v1 — still works!
docker start deploy-grpc-proxy-1-1
```

### Deploy a Real Application

```bash
kubectl create namespace test
kubectl create deployment nginx --image=nginx -n test
sleep 30 && kubectl get pods -n test
# Expected: nginx pod Running

# Inspect its mounted token
POD=$(kubectl get pod -n test -o name | head -1)
kubectl exec -n test $POD -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token | \
  cut -d. -f1 | base64 -d
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

---

## 9. Running the DKG Ceremony

The DKG ceremony allows signers to generate key shares without any trusted dealer — no single party ever sees the complete key.

```
Round 1: Each signer generates a random polynomial → broadcasts commitments
Broadcast: Coordinator distributes all commitments to all signers
Round 2: Each signer computes shares for every other signer
Finalize: Each signer sums received shares → final key share
```

```bash
docker exec deploy-grpc-proxy-1-1 sh -c "
SIGNER_1_ADDR=https://signer-1:8081 \
SIGNER_2_ADDR=https://signer-2:8082 \
SIGNER_3_ADDR=https://signer-3:8083 \
SIGNER_4_ADDR=https://signer-4:8084 \
SIGNER_5_ADDR=https://signer-5:8085 \
/bin/dkg-coordinator"
```

---

## 10. Benchmark Results

All benchmarks: single-node Minikube, Docker driver, macOS M-series (ARM64 native binary).

### Latency Comparison

| Test | Baseline RS256 | FROST 3-of-5 | Overhead |
|---|---|---|---|
| Single token (cold) | ~57ms | ~69ms | +12ms (one-time) |
| Single token (warm) | ~34ms | ~36ms | +6% |
| Warm P50 | 34ms | 34ms | **0%** |
| Warm P95 | 48ms | 69ms | +44% |
| 100 tokens avg | 32ms | 31ms | ~0% |
| 500 tokens avg | 31ms | 44ms | +42% |
| 10 concurrent | ~174ms | ~81ms | -53%† |
| 20 concurrent | ~143ms | ~152ms | +6% |
| 50 concurrent | ~340ms | ~403ms | +18% |
| Sequential throughput | 31 tok/s | 31 tok/s | 0% |

†Attributable to nginx load balancing across 3 coordinator instances — not a cryptographic advantage.

> **Note:** Results include macOS Docker Desktop networking overhead and socat bridge latency. Production Linux bare-metal deployments will show different absolute numbers.

### Failure and Recovery

| Scenario | Result | Time |
|---|---|---|
| 2 of 5 signers killed | Signing continues ✅ | ~70ms (same) |
| 3 of 5 signers killed | Explicit error ✅ | N/A |
| Signer restarted | Automatic recovery ✅ | 84ms |
| Coordinator proxy killed | nginx failover ✅ | Transparent |

### Signer Count Effect

| Signers Active | Latency | Notes |
|---|---|---|
| 5-of-5 | ~36ms | Normal operation |
| 3-of-5 (2 killed) | ~36ms | **Zero overhead** |
| 2-of-5 (3 killed) | Error | Explicit threshold enforcement |

---

## 11. Failure Tolerance Testing

### Test 1: Kill 2 Signers (System Continues)

```bash
docker stop deploy-signer-4-1 deploy-signer-5-1
sleep 3
kubectl create token default | cut -d. -f1 | base64 -d
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
docker start deploy-signer-4-1 deploy-signer-5-1
```

### Test 2: Kill 3 Signers (Below Threshold — Fails)

```bash
docker stop deploy-signer-1-1 deploy-signer-2-1 deploy-signer-3-1
sleep 3
kubectl create token default
# Expected error: "threshold sign: not enough signers: got 2, need 3"
docker start deploy-signer-1-1 deploy-signer-2-1 deploy-signer-3-1
```

### Test 3: Coordinator HA Failover

```bash
docker stop deploy-grpc-proxy-1-1
kubectl create token default | cut -d. -f1 | base64 -d
# Expected: frost-k8s-v1 — nginx routes to proxy-2 or proxy-3
docker start deploy-grpc-proxy-1-1
```

### Test 4: Signer Recovery

```bash
docker stop deploy-signer-1-1 && sleep 2
docker start deploy-signer-1-1
cd deploy && docker compose logs signer-1 | tail -5
# Expected: [vault] Loaded key share for signer-1
kubectl create token default | cut -d. -f1 | base64 -d
```

---

## 12. What Was Built

### Critical Bugs Found During KEP-740 Integration

Two subtle bugs were found that affect any from-scratch KEP-740 implementation:

**Bug 1: Double base64 encoding of JWT payload**

The KEP-740 proto comment states `claims` is "JSON-serialized and base64url-encoded." This is ambiguous: the apiserver sends claims *already* base64url-encoded. Re-encoding produces a signature over the wrong input — structurally valid but silently failing verification.

```go
// WRONG — re-encodes already-encoded payload
payload := base64.RawURLEncoding.EncodeToString([]byte(req.Claims))

// CORRECT — use claims directly as payload
payload := req.Claims
signingInput := header + "." + payload
```

**Bug 2: ECDSA signature format mismatch (ASN.1 DER vs IEEE P1363)**

Go's `crypto/ecdsa` produces DER/ASN.1 signatures by default. Kubernetes uses go-jose which expects IEEE P1363 format (raw R‖S concatenation, 64 bytes for P-256). go-jose validates the fixed-length constraint silently and rejects DER signatures.

```go
// Convert ASN.1 DER → IEEE P1363 (raw r||s)
func toP1363(sig []byte, keySize int) ([]byte, error) {
    var rv struct{ R, S *big.Int }
    if _, err := asn1.Unmarshal(sig, &rv); err != nil {
        return nil, err
    }
    out := make([]byte, 2*keySize)
    rv.R.FillBytes(out[:keySize])
    rv.S.FillBytes(out[keySize:])
    return out, nil
}
```

These bugs affect any Go implementation of KEP-740 using the standard library without explicit format conversion.

### Key Storage Hierarchy

```
Startup
  ├── [Tier 1] HashiCorp Vault → Success ✅
  ├── [Tier 2] AES-256-GCM Encrypted File → Fallback ✅
  └── [Tier 3] Plain JSON (dev only) → Last resort ✅
```

### Features Implemented

| Feature | Status |
|---|---|
| FROST 3-of-5 threshold signing | ✅ |
| KEP-740 ExternalJWTSigner gRPC | ✅ |
| Full Kubernetes integration | ✅ |
| Parallel signer communication | ✅ |
| mTLS coordinator ↔ signers | ✅ |
| Coordinator HA (3 instances + nginx) | ✅ |
| Vault key share storage | ✅ |
| AES-256-GCM encrypted fallback | ✅ |
| Distributed DKG ceremony | ✅ |
| Failure tolerance (2-of-5) | ✅ |
| Benchmark suite | ✅ |

---

## 13. Repository Structure

```
frost-k8s-threshold-signing/
├── cmd/
│   ├── grpc-proxy/        # gRPC proxy — ExternalJWTSigner coordinator
│   ├── signer/            # Individual signer service
│   ├── keygen/            # FROST key generation (development)
│   ├── genkey/            # ECDSA signing key generation
│   ├── encrypt-keys/      # AES-256-GCM key share encryption
│   └── dkg-coordinator/   # Distributed DKG ceremony orchestrator
├── internal/
│   ├── grpcserver/        # ExternalJWTSigner gRPC implementation
│   ├── signing/           # ECDSA key management (IEEE P1363 format)
│   ├── froststate/        # FROST signer state + 3-tier key loading
│   ├── coordinatorstate/  # FROST coordinator state
│   ├── mtls/              # mTLS client factory
│   ├── keystore/          # AES-256-GCM encryption/decryption
│   └── dkg/               # Distributed Key Generation (Pedersen)
├── proto/externaljwt/v1alpha1/  # KEP-740 gRPC service definition
├── deploy/
│   ├── docker-compose.yml       # 5 signers + 3 proxies + nginx + Vault
│   ├── nginx-grpc.conf          # nginx gRPC upstream (coordinator HA)
│   └── docker/                  # Dockerfiles
├── benchmark/
│   ├── run_benchmarks_frost.sh
│   └── run_benchmarks_baseline.sh
├── scripts/
│   ├── restart-frost.sh   # One-command setup (macOS + Linux)
│   └── vault-init.sh      # Load key shares into Vault
└── certs/ data/           # Generated locally — not in git
```

---

## 14. Known Limitations

> **Note:** Limitation labels (L1–L6) match the companion paper for cross-reference.

**L1 — Signer co-location (primary security limitation).** All five signers run on the same Docker host in this prototype — providing no infrastructure independence. An attacker with host access can read all key shares simultaneously. This demonstrates the *signing protocol*, not a production-grade independent deployment. Production requires signers across independent infrastructure domains.

**L2 — Coordinator-assisted DKG (primary research challenge).** The coordinator transiently holds all share material during key generation. Peer-to-peer DKG (`cmd/dkg-coordinator/`) is implemented but not yet integrated into the runtime signing path.

**L3 — Per-signer mutex contention.** The `bytemare/frost` library is not safe for concurrent use. Each signer serializes requests via mutex, causing ~18% overhead at 50 concurrent requests. Fix requires a pool of independent Signer instances with careful session tracking.

**L4 — Vault dev mode (no persistence).** Vault uses in-memory storage. Run `scripts/vault-init.sh` to reload shares after Vault restarts. Signers automatically fall back to encrypted file.

**L5 — Coordinator HA within single Docker Compose.** Three proxy instances share the same deployment. Geographic distribution requires additional infrastructure.

**L6 — Single-node benchmark environment.** All numbers include macOS Docker Desktop and socat bridge overhead. Production Linux bare-metal will differ.

---

## 15. Future Work

**Near-term:**
- DKG integration with runtime signing — replace keygen shares with DKG-generated shares
- Parallelized signing-session execution (reducing per-signer mutex contention)
- Vault persistent storage (Raft backend, proper unseal)
- Automated key rotation via FROST proactive secret resharing

**Medium-term:**
- Multi-node benchmarks on production-realistic clusters
- Formal security verification (ProVerif/Tamarin)
- Post-quantum readiness — crypto-agile proxy

**Long-term:**
- Kubernetes Operator for automated signer lifecycle
- GKE/EKS/AKS support
- HSM integration for signer key shares
- Geographic signer distribution

---

## 16. Troubleshooting

### `kubectl create token` returns RS256

kube-apiserver is still using the default single key.

```bash
# Check manifest
docker exec minikube grep "signing" /etc/kubernetes/manifests/kube-apiserver.yaml
# Should show: --service-account-signing-endpoint=/var/run/frost-k8s/signer.sock

# Re-run setup
bash scripts/restart-frost.sh
```

### `not enough signers: got 0, need 3`

Proxy cannot reach signers — IPs may have changed after restart.

```bash
# Re-run (auto-detects new IPs)
bash scripts/restart-frost.sh
```

### apiserver CrashLoopBackOff

Socket doesn't exist when apiserver starts. Ensure `restart-frost.sh` completes successfully before patching the manifest.

### `[vault] Failed, trying local`

Vault restarted and lost in-memory data. Signers automatically fall back to encrypted file.

```bash
bash scripts/vault-init.sh
cd deploy && docker compose restart signer-1 signer-2 signer-3 signer-4 signer-5
```

### `tls: client did not provide a certificate`

mTLS certs missing or mismatched CA. Regenerate certs (Section 7, Step 5) ensuring all certs are signed by the same CA.

### After Minikube Restart

```bash
bash scripts/restart-frost.sh
```

---

## Environment Variables

| Variable | Component | Default | Description |
|---|---|---|---|
| `SIGNER_ID` | signer | required | Signer identity (1–5) |
| `PORT` | signer | required | HTTP port (8081–8085) |
| `VAULT_ADDR` | signer | — | Vault URL |
| `VAULT_TOKEN` | signer | — | Vault auth token |
| `FROST_KEY_PASSWORD` | signer | `frost-dev-password` | AES-256-GCM password |
| `TLS_CERT` | signer | `certs/signer.crt` | Signer TLS cert |
| `TLS_KEY` | signer | `certs/signer.key` | Signer TLS key |
| `TLS_CA` | signer | `certs/ca.crt` | CA for client verification |
| `SIGNER_1_ADDR`–`5_ADDR` | grpc-proxy | `https://signer-N:808N` | Signer addresses |
| `SOCKET_PATH` | grpc-proxy | `/var/run/frost-k8s/signer.sock` | Unix socket path |
| `KEY_ID` | grpc-proxy | `frost-k8s-v1` | JWT `kid` header |
| `ECDSA_KEY_PATH` | grpc-proxy | `data/ecdsa-signing.pem` | ECDSA signing key |

---

## Companion Research

| # | Title | Venue | Status |
|---|---|---|---|
| 📖 Paper 1 | [Authentication Mechanisms in Kubernetes: A Systematic Review](https://doi.org/10.5281/zenodo.20734453) | Zenodo | Published |
| 🔒 Paper 2 | [Threat Modeling and Security Analysis of Threshold-Based Token Signing](https://doi.org/10.5281/zenodo.20733863) | Zenodo | Published |
| 🚀 Paper 3 | [frost-k8s: A FROST-Based Threshold Signing Proxy *(this repo)*](https://doi.org/10.5281/zenodo.20770308) | Zenodo + SCORED '26 | Under Review |

---

## Acknowledgments

- [bytemare/frost](https://github.com/bytemare/frost) — FROST RFC 9591 Go implementation
- [Kubernetes KEP-740](https://github.com/kubernetes/enhancements/) — ExternalJWTSigner API
- [HashiCorp Vault](https://www.vaultproject.io/) — Secret management
- [NIST IR 8214C](https://doi.org/10.6028/NIST.IR.8214C) — Multi-Party Threshold Schemes
- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591) — FROST specification

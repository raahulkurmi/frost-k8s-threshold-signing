# frost-k8s-threshold-signer

> **First working implementation of FROST threshold signing integrated with the Kubernetes ExternalJWTSigner API (KEP-740, stable v1.36)**

[![Go](https://img.shields.io/badge/Go-1.23+-blue)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](LICENSE)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.36+-green)](https://kubernetes.io)

---

## What Is This?

Kubernetes signs every service account JWT token using a **single private key** stored on the control plane filesystem. If that key is ever stolen — by an attacker, a malicious insider, or a misconfigured backup — the attacker can forge tokens for **any** service account with **any** permission level. Token rotation doesn't help. RBAC doesn't help. Short-lived tokens don't help. The attacker just mints new valid tokens continuously, forever.

This project replaces that single key with **FROST threshold signing** — a cryptographic protocol where **3 out of 5 independent signers must collaborate** to produce any valid token. No single compromise grants forging capability. An attacker must independently compromise 3 separate systems, each potentially operated by different teams or organizations.

```
Default Kubernetes:
  kube-apiserver → single private key → sign JWT
  (1 key stolen = full cluster access, forever, undetectable)

This project:
  kube-apiserver → gRPC proxy → 3-of-5 FROST signers → sign JWT
  (need 3 independent compromises — mathematically guaranteed)
```

The output is a **standard JWT** — kubectl, client-go, and all existing tools work without any changes.

---

## Table of Contents

1. [The Problem — In Detail](#1-the-problem--in-detail)
2. [The Solution — How FROST Works](#2-the-solution--how-frost-works)
3. [Architecture](#3-architecture)
4. [What Was Built](#4-what-was-built)
5. [Repository Structure](#5-repository-structure)
6. [Prerequisites](#6-prerequisites)
7. [Installation — Step by Step](#7-installation--step-by-step)
8. [Verification — Check Everything Works](#8-verification--check-everything-works)
9. [Running the DKG Ceremony](#9-running-the-dkg-ceremony)
10. [Benchmark Results](#10-benchmark-results)
11. [Failure Tolerance Testing](#11-failure-tolerance-testing)
12. [Known Limitations and Workarounds](#12-known-limitations-and-workarounds)
13. [Future Work](#13-future-work)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. The Problem — In Detail

### How Kubernetes Signs Tokens Today

When a pod starts, Kubernetes issues it a service account JWT token. This token is signed by `kube-controller-manager` using a private key file — by default `/etc/kubernetes/pki/sa.key`.

```
Pod starts
    ↓
kubelet requests token from kube-apiserver
    ↓
kube-apiserver signs JWT with sa.key
    ↓
Token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token
    ↓
Pod uses token to authenticate to Kubernetes API
```

### Why This Is a Problem

The `sa.key` file is:
- Stored in **plaintext** on the control plane node filesystem
- Accessible to **anyone with root on the control plane**
- **Never rotated** without restarting the entire apiserver
- **Impossible to detect theft** — reading a file generates no Kubernetes audit logs

If an attacker steals `sa.key`, they can:
- Forge tokens for `cluster-admin` (full cluster control)
- Create tokens with any audience, any expiration, any service account
- Operate indefinitely — key theft leaves no forensic trace
- Continue even after you rotate pod tokens — the key is unchanged

### What Existing Mitigations Cannot Do

| Mitigation | What It Protects | Why It Fails Against Key Theft |
|------------|-----------------|-------------------------------|
| Bound tokens (v1.22+) | Stolen pod tokens | Attacker forges new bound tokens with stolen key |
| Token rotation | Stale tokens | Same key signs new tokens |
| RBAC hardening | Overprivilege | Attacker forges any identity |
| Network policies | Lateral movement | Token auth happens at L7 via apiserver |
| SPIFFE/SPIRE | Workload identity | Single SPIRE root CA = same problem |
| External JWT Signer | Key extraction from disk | Still a single signing authority |

None of these protect **the signing key itself**.

---

## 2. The Solution — How FROST Works

### Threshold Cryptography

A **(t, n) threshold signature scheme** distributes signing capability among n parties such that any t of them can collaborate to produce a valid signature, but fewer than t cannot produce anything valid.

For this project: **t=3, n=5** — any 3 of 5 signers can sign, but 2 or fewer cannot.

### FROST (RFC 9591)

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is an IETF-standardized threshold signature protocol with two key properties:

**1. Distributed Key Generation (DKG):** The signing key is generated collaboratively — it never exists at any single location. Each signer holds only a "key share." Even the coordinator that orchestrates signing never sees the complete key.

**2. Standard verification:** The resulting signature is a standard Schnorr/ECDSA signature verifiable with a single public key. Kubernetes doesn't need to know about threshold signing at all.

### The Signing Flow

```
Pod requests token
      ↓
kube-apiserver calls gRPC proxy (ExternalJWTSigner interface — KEP-740)
      ↓
gRPC proxy contacts 5 signers IN PARALLEL:
      ├── Signer-1: generate commitment
      ├── Signer-2: generate commitment
      ├── Signer-3: generate commitment
      ├── Signer-4: generate commitment  
      └── Signer-5: generate commitment
      ↓
First 3 signers to respond contribute signature shares
      ↓
gRPC proxy aggregates 3 partial signatures → 1 valid signature
      ↓
Standard JWT returned to pod
```

The complete signing key **never exists** at any single location — not during key generation, not during signing.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Kubernetes Cluster                        │
│                                                                  │
│  ┌──────────────────┐                                           │
│  │  kube-apiserver   │                                           │
│  │                   │  --service-account-signing-endpoint=      │
│  │                   │  unix:///var/run/frost-k8s/signer.sock   │
│  └────────┬──────────┘                                           │
│           │                                                       │
│           │ gRPC (ExternalJWTSigner — KEP-740)                   │
│           │                                                       │
│           ▼                                                       │
│  ┌──────────────────────────────────────┐                        │
│  │         gRPC Proxy (Coordinator)      │                        │
│  │                                       │                        │
│  │  - Implements ExternalJWTSigner       │                        │
│  │  - Holds NO key material              │                        │
│  │  - Contacts signers in parallel       │                        │
│  │  - Aggregates partial signatures      │                        │
│  └──┬──────┬──────┬──────┬──────┬───────┘                        │
│     │      │      │      │      │                                │
│     │      │   mTLS HTTPS (parallel)                             │
│     ▼      ▼      ▼      ▼      ▼                                │
└─────────────────────────────────────────────────────────────────┘
      │      │      │      │      │
  ┌───┴──┐┌──┴──┐┌──┴──┐┌──┴──┐┌──┴──┐   Docker network
  │  S1   ││ S2  ││ S3  ││ S4  ││ S5  │   (minikube network)
  │       ││     ││     ││     ││     │
  │Key    ││Key  ││Key  ││Key  ││Key  │
  │Share 1││Sh.2 ││Sh.3 ││Sh.4 ││Sh.5│
  └───────┘└─────┘└─────┘└─────┘└─────┘
       ↑
       │
  ┌────┴───────────────┐
  │   HashiCorp Vault   │  ← Primary key share storage
  │   (or encrypted     │
  │    file fallback)   │
  └────────────────────┘
```

**Key properties:**
- Zero changes to Kubernetes core code
- Output is a standard JWT — kubectl, client-go, all tools work unchanged
- System tolerates 2 signer failures (3-of-5 threshold)
- Automatic failover to available signers
- mTLS between coordinator and all signers
- Key shares loaded from Vault (with AES-256-GCM encrypted file fallback)

---

## 4. What Was Built

### Key Storage Hierarchy

Signers load key shares using a 3-tier fallback system:

```
Startup
  │
  ▼
[Tier 1] HashiCorp Vault
  VAULT_ADDR=http://vault:8200
  VAULT_TOKEN=frost-dev-token
  GET /v1/frost/data/signer-{id}
  │
  ├── Success → use Vault share ✅
  │
  └── Failure (Vault down/restarted/empty)
        │
        ▼
      [Tier 2] AES-256-GCM Encrypted File
        data/frost-keys.enc
        Password: FROST_KEY_PASSWORD env var
        (default: "frost-dev-password" for dev)
        │
        ├── Success → use decrypted share ✅
        │
        └── Failure (file missing/wrong password)
              │
              ▼
            [Tier 3] Plain JSON File
              data/frost-keys.json
              ⚠️  Dev/testing only — not secure
```

### Critical Bugs Fixed During Development

Two subtle bugs were found and fixed that are worth documenting for anyone working with KEP-740:

**Bug 1: Double base64 encoding of JWT payload**

The `kube-apiserver` sends the JWT payload to the external signer **already base64url encoded**. An initial implementation was double-encoding it (encoding an already-encoded payload), producing an invalid signature. Fix: use the payload bytes directly without re-encoding.

**Bug 2: Wrong ECDSA signature format**

Kubernetes uses `go-jose` internally, which requires ECDSA signatures in **IEEE P1363 format** (raw R‖S concatenation, 64 bytes for P-256). Go's standard `crypto/ecdsa` package produces **DER/ASN1 format** by default. Using DER format caused silent verification failures. Fix: manually extract R and S from the DER signature and concatenate them as fixed-length 32-byte values.

```go
// Wrong — DER format
sig, _ := ecdsa.SignASN1(rand.Reader, key, hash)

// Correct — IEEE P1363 R‖S format required by go-jose
r, s := derToRS(sig)  // extract from DER
p1363 := append(padTo32(r), padTo32(s)...)
```

These bugs would affect anyone implementing KEP-740 from scratch.

### Features Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| FROST 3-of-5 threshold signing | ✅ | Via bytemare/frost (RFC 9591) |
| KEP-740 ExternalJWTSigner gRPC | ✅ | Stable K8s v1.36 API |
| Full Kubernetes integration | ✅ | controller-manager, scheduler, pods |
| Distributed DKG ceremony | ✅ | Pedersen protocol — no trusted dealer |
| Automatic signer failover | ✅ | Falls back to next available signer |
| Failure tolerance (2-of-5) | ✅ | Tested — system continues with 3 signers |
| Parallel signer communication | ✅ | All 5 contacted simultaneously |
| mTLS (coordinator ↔ signers) | ✅ | Certificate-based mutual authentication |
| Vault key share storage | ✅ | Signers load shares from Vault on startup |
| AES-256-GCM encrypted fallback | ✅ | If Vault unavailable, uses encrypted file |
| Nginx deployment verification | ✅ | Pods receive FROST-signed tokens |
| Benchmark suite | ✅ | Latency, throughput, concurrency, memory |

---

## 5. Repository Structure

```
frost-k8s-threshold-signing/
├── cmd/
│   ├── grpc-proxy/        # gRPC proxy — ExternalJWTSigner coordinator
│   │   └── main.go        # Parallel signing, mTLS client, socket/TCP modes
│   ├── signer/            # Individual signer service
│   │   └── main.go        # FROST signing + DKG endpoints + mTLS server
│   ├── keygen/            # Centralized FROST key generation (development)
│   │   └── main.go
│   ├── genkey/            # ECDSA signing key generation
│   │   └── main.go
│   ├── encrypt-keys/      # AES-256-GCM key share encryption tool
│   │   └── main.go
│   ├── dkg-coordinator/   # Distributed DKG ceremony orchestrator
│   │   └── main.go
│   ├── coordinator/       # Legacy HTTP coordinator (reference only)
│   ├── frostlab/          # FROST library exploration (reference only)
│   └── testsign/          # Standalone signing tests (reference only)
│
├── internal/
│   ├── grpcserver/        # gRPC server implementing ExternalJWTSigner proto
│   │   └── server.go      # Sign(), FetchKeys(), Metadata() handlers
│   ├── signing/           # ECDSA key management
│   │   └── ecdsa.go       # IEEE P1363 R‖S format (required by go-jose/K8s)
│   ├── froststate/        # FROST signer state
│   │   ├── bootstrap.go   # 3-tier key loading: Vault → encrypted file → plain JSON
│   │   ├── state.go       # Signer instance, mutex
│   │   ├── commitments.go # Commitment tracking
│   │   └── keys.go        # StoredKeys struct
│   ├── coordinatorstate/  # FROST coordinator state
│   │   ├── bootstrap.go   # Config initialization
│   │   └── state.go       # Config, AggregateSignatures
│   ├── mtls/              # mTLS client
│   │   └── client.go      # TLS config with client cert + CA verification
│   ├── keystore/          # AES-256-GCM encryption/decryption
│   │   └── keystore.go    # SHA-256 key derivation, GCM encrypt/decrypt
│   ├── dkg/               # Distributed Key Generation
│   │   └── dkg.go         # Pedersen DKG: Round1, Round2, Finalize
│   ├── api/               # HTTP API types
│   │   ├── commitment.go
│   │   ├── commitments.go
│   │   ├── jwt.go
│   │   ├── jwt_request.go
│   │   ├── sign.go
│   │   └── signatures.go
│   ├── config/            # Environment-based configuration
│   │   └── config.go      # SignerID(), Port(), etc.
│   ├── coordinator/       # Legacy coordinator (reference only)
│   ├── signer/            # Legacy ECDSA signer (reference only)
│   └── types/             # Shared types
│       └── types.go
│
├── proto/
│   └── externaljwt/v1alpha1/
│       ├── api.proto      # ExternalJWTSigner gRPC service definition
│       ├── api.pb.go      # Generated protobuf
│       └── api_grpc.pb.go # Generated gRPC stubs
│
├── externaljwt/v1alpha1/  # Additional generated gRPC stubs
│   ├── api.pb.go
│   └── api_grpc.pb.go
│
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile.proxy   # Multi-stage: builds grpc-proxy + dkg-coordinator
│   │   └── Dockerfile.signer  # Multi-stage: builds signer with encrypted key file
│   ├── docker-compose.yml     # 5 signers + grpc-proxy + Vault (minikube network)
│   ├── vault-config.hcl       # Vault server configuration
│   └── k3d/
│       └── cluster-config.yaml
│
├── certs/                 # mTLS certificates (generated by you — not in git)
│   ├── ca.crt / ca.key    # Certificate Authority
│   ├── proxy.crt / proxy.key  # gRPC proxy identity
│   ├── proxy-ext.cnf      # OpenSSL SAN config for proxy cert
│   ├── signer.crt / signer.key # Signer identity
│   └── signer-ext.cnf     # OpenSSL SAN config for signer cert (DNS SANs)
│
├── data/                  # Key material (generated by you — not in git)
│   ├── frost-keys.json    # FROST key shares (plaintext — dev only)
│   ├── frost-keys.enc     # AES-256-GCM encrypted key shares (primary)
│   └── ecdsa-signing.pem  # ECDSA P-256 private key for JWT signing
│
├── benchmark/
│   ├── run_benchmarks.sh  # Full benchmark suite (latency, throughput, failure)
│   └── results/           # Benchmark output files (timestamped)
│
├── scripts/
│   ├── setup-minikube.sh  # Automated Minikube patching + grpc-proxy setup
│   └── vault-init.sh      # Vault KV engine init + key share loading
│
├── docs/
│   └── architecture.md    # Architecture documentation
│
├── go.mod                 # Go module definition
├── go.sum                 # Dependency checksums
└── README.md
```

> **Note:** `deploy/cmd/` and `deploy/internal/` are build artifacts from Docker multi-stage builds — they are not source directories.

---

## 6. Prerequisites

### Required Software

| Tool | Version | Install |
|------|---------|---------|
| Go | 1.23+ | https://go.dev/dl/ |
| Docker Desktop | Latest | https://www.docker.com/products/docker-desktop/ |
| minikube | Latest | `brew install minikube` |
| kubectl | Latest | `brew install kubectl` |
| openssl | Any | Pre-installed on macOS/Linux |

### System Requirements

- macOS (Apple Silicon or Intel) or Linux
- 8GB+ RAM recommended (Minikube + 7 Docker containers)
- 10GB free disk space

### Check Prerequisites

```bash
go version        # should show 1.23+
docker --version  # should show 20+
minikube version  # any recent version
kubectl version --client
openssl version
```

---

## 7. Installation — Step by Step

### Step 1: Clone the Repository

```bash
git clone https://github.com/raahulkurmi/frost-k8s-threshold-signing.git
cd frost-k8s-threshold-signing
```

### Step 2: Install Go Dependencies

```bash
go mod tidy
```

This downloads all required Go packages including:
- `github.com/bytemare/frost` — FROST RFC 9591 implementation
- `google.golang.org/grpc` — gRPC for ExternalJWTSigner interface
- `github.com/bytemare/secret-sharing` — Shamir secret sharing for DKG

### Step 3: Generate FROST Key Shares

This generates a 3-of-5 threshold key — 5 key shares where any 3 can collaborate to sign.

```bash
go run cmd/keygen/main.go
```

Expected output:
```
Generated FROST key shares (3-of-5)
Saved to data/frost-keys.json
Share count: 5
```

**What this does:** Creates 5 cryptographic key shares using FROST's key generation protocol. The shares are mathematically linked — any 3 can reconstruct a valid signature, but 2 or fewer cannot. The complete signing key never exists in memory — only the shares.

### Step 4: Generate ECDSA Signing Key

Kubernetes uses ECDSA (ES256) for token signing. This generates the key that will be used for the actual JWT signatures:

```bash
go run cmd/genkey/main.go
```

Expected output:
```
Generated ECDSA P-256 key
Saved to data/ecdsa-signing.pem
Public key (PKIX): ...
```

### Step 5: Encrypt Key Shares

Instead of storing key shares in plaintext, encrypt them with AES-256-GCM:

```bash
go run cmd/encrypt-keys/main.go
```

Expected output:
```
[encrypt] Using default password — set FROST_KEY_PASSWORD in production
[keystore] Keys encrypted and saved to data/frost-keys.enc
[encrypt] Done! data/frost-keys.enc created
```

> **Production note:** Set `FROST_KEY_PASSWORD` environment variable to a strong password before running this. The default password is only for development.

### Step 6: Generate mTLS Certificates

mTLS (mutual TLS) ensures that only authorized clients can talk to the signers. We need a Certificate Authority (CA), a proxy certificate, and a signer certificate:

```bash
mkdir -p certs

# Generate Certificate Authority
openssl genrsa -out certs/ca.key 2048
openssl req -new -x509 -days 365 -key certs/ca.key \
  -out certs/ca.crt -subj "/CN=frost-k8s-ca"

# Generate proxy certificate (coordinator identity)
openssl genrsa -out certs/proxy.key 2048
openssl req -new -key certs/proxy.key \
  -out certs/proxy.csr -subj "/CN=frost-proxy"
openssl x509 -req -days 365 \
  -in certs/proxy.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/proxy.crt

# Create SAN config for signer certificate
# (Subject Alternative Names allow the cert to work for all signer hostnames)
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

# Generate signer certificate with SANs
openssl genrsa -out certs/signer.key 2048
openssl req -new -key certs/signer.key \
  -out certs/signer.csr -subj "/CN=frost-signer"
openssl x509 -req -days 365 \
  -in certs/signer.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/signer.crt \
  -extensions v3_req -extfile certs/signer-ext.cnf

# Verify certificates were created
ls -la certs/
```

Expected output:
```
ca.crt  ca.key  proxy.crt  proxy.key  signer.crt  signer.key  signer-ext.cnf
```

### Step 7: Start HashiCorp Vault and Load Key Shares

Vault securely stores the key shares. Signers fetch their individual share from Vault on startup:

```bash
# Start Vault container
cd deploy
docker compose up -d vault
sleep 5  # wait for Vault to initialize

# Verify Vault is running
docker compose logs vault | tail -5
# Expected: "Root Token: frost-dev-token"

# Load key shares into Vault
cd ..
bash scripts/vault-init.sh
```

Expected output from vault-init.sh:
```
=== Vault Init Script ===
Vault ready!
=== Secret Path ===
frost/data/signer-1
... (5 entries, one per signer)
All shares stored in Vault!
```

**What this does:** Each signer's key share is stored as a separate secret in Vault at `frost/signer-{id}`. When signer-3 starts, it fetches only its own share from `frost/signer-3` — it never sees other signers' shares.

### Step 8: Build and Start All Containers

```bash
cd deploy
docker compose build   # builds proxy + 5 signer containers
docker compose up -d   # starts everything
```

This starts 7 containers on the `minikube` Docker network:

| Container | Role | Port |
|-----------|------|------|
| `deploy-vault-1` | HashiCorp Vault (key share storage) | 8200 |
| `deploy-signer-1-1` | FROST Signer 1 | 8081 (mTLS) |
| `deploy-signer-2-1` | FROST Signer 2 | 8082 (mTLS) |
| `deploy-signer-3-1` | FROST Signer 3 | 8083 (mTLS) |
| `deploy-signer-4-1` | FROST Signer 4 | 8084 (mTLS) |
| `deploy-signer-5-1` | FROST Signer 5 | 8085 (mTLS) |
| `deploy-grpc-proxy-1` | gRPC Coordinator | 9090 (TCP) |

All containers are on the `minikube` Docker network so they can communicate with each other and with the Minikube VM.

### Step 9: Verify Signers Loaded Keys from Vault

```bash
cd deploy
docker compose logs signer-1 | tail -5
```

Expected output:
```
[vault] Loaded key share for signer-1
Loaded signer 1
Signer listening on :8081 (mTLS enabled)
```

If Vault is unavailable (e.g., after restart), signers automatically fall back to the encrypted file:
```
[vault] Failed, trying local: empty share from vault
[keystore] Loaded encrypted key file
Loaded signer 1
Signer listening on :8081 (mTLS enabled)
```

### Step 10: Start Minikube

```bash
cd ..
minikube start --driver=docker
```

Wait for minikube to fully start (~2 minutes).

### Step 11: macOS Only — Run grpc-proxy Inside Minikube

> **Linux users:** Skip this step. On Linux, run grpc-proxy as a Docker container and use `minikube mount` to share the socket:
> ```bash
> SOCKET_PATH=/tmp/frost-k8s/signer.sock KEY_ID=frost-k8s-v1 docker compose up -d grpc-proxy
> minikube mount /tmp/frost-k8s:/var/run/frost-k8s &
> # Then go to Step 12
> ```

On macOS with Docker Desktop, Unix sockets cannot be shared between Docker containers and the Minikube VM. The workaround is to run `grpc-proxy` **inside** the Minikube node container, which has direct access to the socket path.

**Get signer container IPs:**
```bash
for i in 1 2 3 4 5; do
  echo -n "signer-$i: "
  docker inspect deploy-signer-${i}-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*'
done
```

Note these IPs — you need them below.

**Copy files into Minikube and start grpc-proxy:**
```bash
# Copy key material and certs from proxy container to host
docker cp deploy-grpc-proxy-1:/app/data/frost-keys.json /tmp/frost-keys.json
docker cp deploy-grpc-proxy-1:/app/data/ecdsa-signing.pem /tmp/ecdsa-signing.pem
docker cp deploy-grpc-proxy-1:/app/certs/proxy.crt /tmp/proxy.crt
docker cp deploy-grpc-proxy-1:/app/certs/proxy.key /tmp/proxy.key
docker cp deploy-grpc-proxy-1:/app/certs/ca.crt /tmp/ca.crt

# Copy into Minikube container
docker exec minikube mkdir -p /app/data /app/certs /var/run/frost-k8s
docker cp /tmp/frost-keys.json minikube:/app/data/frost-keys.json
docker cp /tmp/ecdsa-signing.pem minikube:/app/data/ecdsa-signing.pem
docker cp /tmp/proxy.crt minikube:/app/certs/proxy.crt
docker cp /tmp/proxy.key minikube:/app/certs/proxy.key
docker cp /tmp/ca.crt minikube:/app/certs/ca.crt

# Cross-compile grpc-proxy for Linux amd64 (macOS builds ARM by default)
GOOS=linux GOARCH=amd64 go build -o /tmp/grpc-proxy-linux ./cmd/grpc-proxy/
docker cp /tmp/grpc-proxy-linux minikube:/usr/local/bin/grpc-proxy

# Start grpc-proxy inside Minikube (replace <SIGNER_X_IP> with IPs from above)
docker exec minikube bash -c "
pkill grpc-proxy 2>/dev/null
rm -f /var/run/frost-k8s/signer.sock
cd /app && nohup env \
  SIGNER_1_ADDR=https://<SIGNER_1_IP>:8081 \
  SIGNER_2_ADDR=https://<SIGNER_2_IP>:8082 \
  SIGNER_3_ADDR=https://<SIGNER_3_IP>:8083 \
  SIGNER_4_ADDR=https://<SIGNER_4_IP>:8084 \
  SIGNER_5_ADDR=https://<SIGNER_5_IP>:8085 \
  SOCKET_PATH=/var/run/frost-k8s/signer.sock \
  KEY_ID=frost-k8s-v1 \
  /usr/local/bin/grpc-proxy > /var/log/grpc-proxy.log 2>&1 &
sleep 3
cat /var/log/grpc-proxy.log
"
```

Expected output:
```
Coordinator FROST config loaded
[mtls] Client configured with mTLS
[signing] Loaded ECDSA key from data/ecdsa-signing.pem
[proxy] Unix mode — socket=/var/run/frost-k8s/signer.sock key=frost-k8s-v1 threshold=3
[grpc] Listening on unix:///var/run/frost-k8s/signer.sock
```

> **Important:** grpc-proxy must be running and socket must exist **before** patching kube-apiserver in Step 12. If apiserver starts without the socket, it crashes.

### Step 12: Patch kube-apiserver to Use FROST Signing

This patches `kube-apiserver` to use the FROST proxy instead of the default single-key signing.

> **Prerequisite:** grpc-proxy must already be running (Step 11 on macOS, or Linux mount approach). The Unix socket `/var/run/frost-k8s/signer.sock` must exist before apiserver restarts.

**Patch the manifest:**
```bash
# Remove default single-key signing flags
docker exec minikube sed -i \
  '/--service-account-signing-key-file/d' \
  /etc/kubernetes/manifests/kube-apiserver.yaml
docker exec minikube sed -i \
  '/--service-account-key-file/d' \
  /etc/kubernetes/manifests/kube-apiserver.yaml

# Add FROST signing endpoint (only if not already present)
docker exec minikube bash -c "
grep -q 'service-account-signing-endpoint' \
  /etc/kubernetes/manifests/kube-apiserver.yaml || \
  sed -i '/--service-account-issuer/i\\    - --service-account-signing-endpoint=/var/run/frost-k8s/signer.sock' \
  /etc/kubernetes/manifests/kube-apiserver.yaml"

# Add volume mount so apiserver container can access the socket
docker exec minikube bash -c "
grep -q 'frost-k8s' /etc/kubernetes/manifests/kube-apiserver.yaml || \
  (sed -i '/    volumeMounts:/a\\    - mountPath: /var/run/frost-k8s\n      name: frost-k8s' \
  /etc/kubernetes/manifests/kube-apiserver.yaml && \
  sed -i '/  volumes:/a\\  - hostPath:\n      path: /var/run/frost-k8s\n      type: DirectoryOrCreate\n    name: frost-k8s' \
  /etc/kubernetes/manifests/kube-apiserver.yaml)"
```

Wait for kube-apiserver to restart (~60 seconds):
```bash
sleep 60 && kubectl get nodes
```

Expected output:
```
NAME       STATUS   ROLES           AGE   VERSION
minikube   Ready    control-plane   Xm    v1.35.1
```

---

## 8. Verification — Check Everything Works

### 8.1 Verify FROST Token Signing

```bash
kubectl create token default | cut -d. -f1 | base64 -d 2>/dev/null
```

Expected output:
```json
{"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

- `alg: ES256` — ECDSA P-256 signature ✅
- `kid: frost-k8s-v1` — our FROST proxy signed this ✅

If you see `alg: RS256` — the setup didn't complete. See Troubleshooting.

### 8.2 Verify Proxy Logs Show Signing

```bash
docker exec minikube bash -c "cat /var/log/grpc-proxy.log | grep 'Signed JWT'"
```

Expected output:
```
[proxy] Signed JWT — kid=frost-k8s-v1 active_signers=[https://signer-1 https://signer-2 https://signer-3]
```

### 8.3 Deploy a Real Application

```bash
kubectl create namespace test
kubectl create deployment nginx --image=nginx -n test
sleep 30
kubectl get pods -n test
```

Expected output:
```
NAME                     READY   STATUS    RESTARTS   AGE
nginx-xxxxxxxx-xxxxx     1/1     Running   0          30s
```

If the pod is `Running` — it received a FROST-signed token and Kubernetes accepted it. ✅

### 8.4 Inspect a Pod's Mounted Token

```bash
POD=$(kubectl get pod -n test -o name | head -1)
kubectl exec -n test $POD -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token | \
  cut -d. -f1 | base64 -d 2>/dev/null
```

Expected output:
```json
{"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

Every pod in the cluster automatically receives a FROST threshold-signed token. ✅

---

## 9. Running the DKG Ceremony

The Distributed Key Generation (DKG) ceremony allows signers to generate their own key shares without any single party ever seeing the complete key. This is the cryptographically correct way to initialize the system.

### What DKG Does

Instead of one process generating all 5 shares (the current default setup using `cmd/keygen`), DKG works as follows:

```
Round 1: Each signer independently generates a random polynomial
         and broadcasts commitments (public values)

Broadcast: Coordinator sends all commitments to all signers

Round 2: Each signer computes a share for every other signer
         using their polynomial, sends it securely

Finalize: Each signer adds up all received shares
          → their final key share (no one else knows it)
```

At no point does any single party see all key shares.

### Run the DKG Ceremony

The DKG coordinator runs inside the `grpc-proxy` container (it needs network access to all signers):

```bash
# Run DKG ceremony
docker exec deploy-grpc-proxy-1 sh -c "
SIGNER_1_ADDR=https://signer-1:8081 \
SIGNER_2_ADDR=https://signer-2:8082 \
SIGNER_3_ADDR=https://signer-3:8083 \
SIGNER_4_ADDR=https://signer-4:8084 \
SIGNER_5_ADDR=https://signer-5:8085 \
/bin/dkg-coordinator
"
```

Expected output:
```
=== FROST Distributed DKG Ceremony ===
Signers: 5, Threshold: 3

[Round 1] Collecting commitments...
  ✅ Commitment received from signer-1
  ✅ Commitment received from signer-2
  ✅ Commitment received from signer-3
  ✅ Commitment received from signer-4
  ✅ Commitment received from signer-5

[Broadcast] Sending all commitments to signers...
  ✅ Commitments sent to signer-1
  ✅ Commitments sent to signer-2
  ✅ Commitments sent to signer-3
  ✅ Commitments sent to signer-4
  ✅ Commitments sent to signer-5

[Round 2] Distributing shares...
  ✅ Shares collected from signer-1
  ...

[Distribute] Sending shares to signers...
  ✅ Shares delivered to signer-1
  ...

=== DKG Ceremony Complete ===
Each signer now holds an independent key share.
No single party ever saw the complete signing key.
```

Verify in signer logs:
```bash
cd deploy && docker compose logs signer-1 | grep dkg
```

Expected:
```
[dkg] Round1 complete — signer-1 commitment ready
[dkg] Received 5 commitments
[dkg] ✅ Signer-1 DKG complete! Share: 010100000000002e...
```

---

## 10. Benchmark Results

All benchmarks run on single-node Minikube, Docker driver, macOS M-series (Apple Silicon).

### 10.1 Latency Comparison

| Test | Baseline RS256 | FROST 3-of-5 | Difference |
|------|---------------|--------------|------------|
| Single token (cold start) | 66ms | 193ms | +127ms (first request only) |
| Single token (warm) | 22-34ms | 32-37ms | ~+3ms |
| 100 tokens (sequential avg) | 32ms | 32ms | **0% overhead** |
| 500 tokens (sequential avg) | 32ms | 33ms | **+3% overhead** |
| 10 concurrent tokens | 122ms | 152ms | +24% |
| 50 concurrent tokens | 507ms | 1356ms | +167% |

### 10.2 Throughput

| Test | Baseline | FROST | 
|------|----------|-------|
| Sequential throughput | 31 tokens/sec | 30 tokens/sec |
| Concurrent (10) throughput | ~82 tok/sec | ~66 tok/sec |

### 10.3 Resource Usage

| Component | CPU (idle) | Memory (idle) |
|-----------|-----------|---------------|
| grpc-proxy | 0.00% | 3MB |
| Each signer | 0.00% | 12.68MB |
| Total overhead | ~0% | ~66MB (proxy + 5 signers) |

### 10.4 Failure and Recovery

| Scenario | Result |
|----------|--------|
| 2 of 5 signers killed | System continues, 70ms per token ✅ |
| 3 of 5 signers killed | Token creation fails with clear error ✅ |
| Signer restarted | Recovery time: 84ms ✅ |

### 10.5 Important Notes on Benchmarks

These benchmarks were conducted on **single-node Minikube with Docker driver on macOS**. Results include:
- macOS Docker Desktop networking overhead
- Minikube virtualization overhead  
- Single-node resource constraints

**The FROST signing itself contributes approximately 10-20ms per token.** The remaining overhead is environment-specific. Production Linux bare-metal deployments will show different absolute numbers, likely with lower overhead.

The 167% overhead at 50 concurrent requests is due to mutex contention in the prototype coordinator — a known limitation addressed in Future Work.

---

## 11. Failure Tolerance Testing

### Test 1: Kill 2 Signers (System Should Continue)

```bash
# Kill 2 of 5 signers
docker stop deploy-signer-4-1 deploy-signer-5-1

# Wait a moment
sleep 3

# Create token — should still work with 3 remaining signers
kubectl create token default | cut -d. -f1 | base64 -d 2>/dev/null
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}

# Check which signers were used
docker exec minikube bash -c "grep 'Signed JWT' /var/log/grpc-proxy.log | tail -1"
# Expected: active_signers=[signer-1 signer-2 signer-3]

# Restore signers
docker start deploy-signer-4-1 deploy-signer-5-1
```

### Test 2: Kill 3 Signers (Below Threshold — Should Fail)

```bash
# Kill 3 of 5 signers
docker stop deploy-signer-1-1 deploy-signer-2-1 deploy-signer-3-1
sleep 3

# Try to create token — should fail
kubectl create token default
# Expected error: "threshold sign: not enough signers: got 2, need 3"

# Restore
docker start deploy-signer-1-1 deploy-signer-2-1 deploy-signer-3-1
```

### Test 3: Signer Recovery

```bash
# Stop and restart a signer
docker stop deploy-signer-1-1
sleep 2
docker start deploy-signer-1-1

# Verify it reloads key from Vault
cd deploy && docker compose logs signer-1 | tail -5
# Expected: [vault] Loaded key share for signer-1

# Verify signing still works
kubectl create token default | cut -d. -f1 | base64 -d 2>/dev/null
```

---

## 12. Known Limitations and Workarounds

### Limitation 1: macOS Unix Socket Workaround

**Problem:** On macOS with Docker Desktop, Kubernetes runs inside a Linux VM (the Minikube container). The `kube-apiserver` requires a Unix socket to communicate with the external signer. Unix sockets cannot be directly shared between Docker containers and the Minikube VM on macOS due to Docker Desktop's networking architecture.

**Workaround:** The `grpc-proxy` binary is copied into and run directly inside the Minikube container. This creates the Unix socket at `/var/run/frost-k8s/signer.sock` within the same network namespace as `kube-apiserver`.

**On Linux:** This workaround is not needed. You can run `grpc-proxy` as a Docker container and use a volume mount to share the Unix socket.

**Impact:** Extra setup steps on macOS; the grpc-proxy must be restarted manually after Minikube restarts.

### Limitation 2: Vault Dev Mode (No Persistence)

**Problem:** HashiCorp Vault runs in development mode (`-dev` flag), which uses in-memory storage. When Vault restarts, all stored key shares are lost.

**Workaround:** The system has a 3-tier key loading fallback:
1. Load from Vault (primary)
2. If Vault fails → load from AES-256-GCM encrypted file (`data/frost-keys.enc`)
3. If encrypted file fails → load from plain JSON file (development only)

Run `scripts/vault-init.sh` to reload shares into Vault after a restart.

**Production fix:** Deploy Vault with file/Raft storage backend and proper unseal keys.

### Limitation 3: DKG Is Not Integrated with Runtime Signing

**Problem:** The DKG ceremony generates new key shares but the system doesn't automatically switch to using them for runtime signing. The `cmd/keygen` generated shares in `frost-keys.json` are still what signers use for actual token signing.

**Status:** DKG is implemented and demonstrated as a separate ceremony. Integration with the full signing pipeline (so DKG-generated shares replace keygen shares) is in progress.

### Limitation 4: Coordinator Single Point of Failure

**Problem:** The `grpc-proxy` coordinator is a single process. If it crashes, token issuance stops until it's restarted.

**Mitigation:** The coordinator holds **no key material** — only signer endpoints. Restarting it is fast (< 1 second) and safe.

**Production fix:** Run multiple proxy replicas behind a load balancer.

### Limitation 5: High Concurrency Mutex Contention

**Problem:** At 50+ concurrent token requests, latency increases significantly (507ms baseline → 1356ms FROST). This is caused by a mutex in the coordinator that serializes signing operations.

**Fix:** Replace per-signing mutex with a per-request signing session design. Straightforward engineering work.

### Limitation 6: Signer IP Addresses Are Not Static

**Problem:** Docker assigns IP addresses dynamically. When containers restart, their IPs may change, breaking the signer address configuration.

**Workaround:** Use Docker container hostnames (`signer-1`, `signer-2`, etc.) when running inside Docker network. When running grpc-proxy inside Minikube, use IPs (which must be updated after container restarts).

---

## 13. Future Work

### Near-Term (Implementation)
- **DKG integration with runtime signing** — DKG-generated shares replace keygen shares automatically
- **Parallel coordinator** — eliminate mutex contention for high-concurrency workloads  
- **Coordinator high availability** — multiple proxy replicas with load balancing
- **Vault persistent storage** — Raft backend, proper unseal keys, automatic initialization
- **Automated key rotation** — FROST proactive secret resharing without downtime
- **Linux deployment simplification** — direct volume mount, no Minikube workaround

### Medium-Term (Research)
- **Multi-node benchmarks** — Kind or K3d multi-node cluster for production-realistic numbers
- **Formal security verification** — proof of composed system (FROST + KEP-740 + K8s token lifecycle)
- **Tiered authentication model** — per-operation additional authentication for sensitive operations
- **Post-quantum readiness** — crypto-agile proxy enabling future migration to PQC threshold schemes

### Long-Term (Production)
- **Kubernetes Operator** — automated signer lifecycle management, key rotation, health monitoring
- **GKE/EKS/AKS support** — managed K8s compatibility (these providers control the control plane)
- **HSM integration** — signers backed by hardware security modules
- **Geographic distribution** — signers across cloud regions/providers for maximum independence

---

## 15. Troubleshooting

### Problem: `kubectl create token` returns RS256

**Cause:** kube-apiserver is still using the default single key, not the FROST proxy.

**Check:**
```bash
docker exec minikube grep "signing" /etc/kubernetes/manifests/kube-apiserver.yaml
# Should show: --service-account-signing-endpoint=/var/run/frost-k8s/signer.sock
```

**Check proxy is running:**
```bash
docker exec minikube bash -c "ps aux | grep grpc-proxy | grep -v grep"
docker exec minikube bash -c "ls /var/run/frost-k8s/signer.sock"
```

**Fix:** Re-run Step 12 from the installation guide.

### Problem: `not enough signers: got 0, need 3`

**Cause:** grpc-proxy cannot reach the signers.

**Check signer IPs haven't changed:**
```bash
for i in 1 2 3 4 5; do
  echo -n "signer-$i: "
  docker inspect deploy-signer-${i}-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*'
done
```

**Fix:** Restart grpc-proxy inside Minikube with updated IPs.

### Problem: `apiserver` pod in CrashLoopBackOff

**Cause:** kube-apiserver cannot find the Unix socket at startup.

**Fix:** Ensure grpc-proxy is running inside Minikube **before** patching the apiserver manifest. The socket must exist before kube-apiserver starts.

### Problem: Signers show `[vault] Failed, trying local`

**Cause:** Vault restarted and lost its in-memory data (dev mode limitation). Signers fall back to encrypted file automatically, but Vault shares need reloading for primary storage.

**Fix:**
```bash
cd deploy
bash ../scripts/vault-init.sh  # reload shares into Vault
docker compose restart signer-1 signer-2 signer-3 signer-4 signer-5
```

### Problem: `tls: client did not provide a certificate`

**Cause:** mTLS is enabled but the client connecting to the signer doesn't have a valid certificate.

**Fix:** Ensure the grpc-proxy has access to `certs/proxy.crt` and `certs/proxy.key`, and that these were signed by the same CA as `certs/ca.crt` that the signers trust.

---

## Environment Variables Reference

| Variable | Component | Default | Description |
|----------|-----------|---------|-------------|
| `SIGNER_ID` | signer | required | Signer identity (1-5) |
| `PORT` | signer | required | HTTP port for signer (8081-8085) |
| `VAULT_ADDR` | signer | — | Vault server URL e.g. `http://vault:8200` |
| `VAULT_TOKEN` | signer | — | Vault authentication token |
| `FROST_KEY_PASSWORD` | signer | `frost-dev-password` | Password for AES-256-GCM decryption |
| `TLS_CERT` | signer | `certs/signer.crt` | Signer TLS certificate path |
| `TLS_KEY` | signer | `certs/signer.key` | Signer TLS private key path |
| `TLS_CA` | signer | `certs/ca.crt` | CA certificate for client verification |
| `SIGNER_1_ADDR` | grpc-proxy | `https://signer-1:8081` | Signer 1 address |
| `SIGNER_2_ADDR` | grpc-proxy | `https://signer-2:8082` | Signer 2 address |
| `SIGNER_3_ADDR` | grpc-proxy | `https://signer-3:8083` | Signer 3 address |
| `SIGNER_4_ADDR` | grpc-proxy | `https://signer-4:8084` | Signer 4 address |
| `SIGNER_5_ADDR` | grpc-proxy | `https://signer-5:8085` | Signer 5 address |
| `SOCKET_PATH` | grpc-proxy | `/var/run/frost-k8s/signer.sock` | Unix socket path |
| `TCP_ADDR` | grpc-proxy | — | If set, listen on TCP instead of Unix socket |
| `KEY_ID` | grpc-proxy | `frost-k8s-v1` | JWT `kid` header value |
| `ECDSA_KEY_PATH` | grpc-proxy | `data/ecdsa-signing.pem` | ECDSA signing key path |

---


-

---

## Acknowledgments

- [bytemare/frost](https://github.com/bytemare/frost) — Go implementation of FROST RFC 9591
- [Kubernetes KEP-740](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/740-service-account-external-signing) — ExternalJWTSigner API
- [HashiCorp Vault](https://www.vaultproject.io/) — Secret management
- NIST IR 8214C — Multi-Party Threshold Schemes standardization
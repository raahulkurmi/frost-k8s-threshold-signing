# frost-k8s-threshold-signing

**First working implementation of FROST threshold signing integrated with the Kubernetes ExternalJWTSigner API (KEP-740, stable v1.36)**

[![Go](https://img.shields.io/badge/Go-1.23+-blue)](https://go.dev) [![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE) [![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.36+-blue)](https://kubernetes.io)

---

## What Is This?

Kubernetes signs every service account JWT token using a single private key stored on the control plane filesystem. If that key is ever stolen — by an attacker, a malicious insider, or a misconfigured backup — the attacker can forge tokens for any service account with any permission level. Token rotation doesn't help. RBAC doesn't help. Short-lived tokens don't help. The attacker just mints new valid tokens continuously, forever.

This project replaces that single key with **FROST threshold signing** — a cryptographic protocol where **3 out of 5 independent signers must collaborate** to produce any valid token. No single compromise grants forging capability. An attacker must independently compromise 3 separate systems, each potentially operated by different teams or organizations.

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

## Table of Contents

1. [The Problem](#1-the-problem--in-detail)
2. [The Solution — How FROST Works](#2-the-solution--how-frost-works)
3. [Architecture](#3-architecture)
4. [What Was Built](#4-what-was-built)
5. [Repository Structure](#5-repository-structure)
6. [Prerequisites](#6-prerequisites)
7. [Installation — Step by Step](#7-installation--step-by-step)
8. [Verification](#8-verification--check-everything-works)
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
- Stored in plaintext on the control plane node filesystem
- Accessible to anyone with root on the control plane
- Never rotated without restarting the entire apiserver
- **Impossible to detect theft** — reading a file generates no Kubernetes audit logs

If an attacker steals `sa.key`, they can:
- Forge tokens for `cluster-admin` (full cluster control)
- Create tokens with any audience, any expiration, any service account
- Operate indefinitely — key theft leaves no forensic trace
- Continue even after you rotate pod tokens — the key is unchanged

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

## 2. The Solution — How FROST Works

### Threshold Cryptography

A (t, n) threshold signature scheme distributes signing capability among n parties such that any t of them can collaborate to produce a valid signature, but fewer than t cannot produce anything valid.

**For this project: t=3, n=5** — any 3 of 5 signers can sign, but 2 or fewer cannot.

### FROST (RFC 9591)

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is an IETF-standardized threshold signature protocol with two key properties:

1. **Distributed Key Generation (DKG):** The signing key is generated collaboratively — it never exists at any single location. Each signer holds only a "key share." Even the coordinator that orchestrates signing never sees the complete key.

2. **Standard verification:** The resulting signature is a standard Schnorr/ECDSA signature verifiable with a single public key. Kubernetes doesn't need to know about threshold signing at all.

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

The complete signing key never exists at any single location — not during key generation, not during signing.

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
│  │      nginx Load Balancer (HA)         │  ← NEW: Coordinator HA│
│  │      coordinator-lb:9090              │                        │
│  └──┬──────────────┬──────────────┬─────┘                        │
│     │              │              │                               │
│     ▼              ▼              ▼                               │
│  ┌────────┐  ┌────────┐  ┌────────┐                              │
│  │Proxy-1 │  │Proxy-2 │  │Proxy-3 │  ← 3 independent instances  │
│  │(FROST  │  │(FROST  │  │(FROST  │    any 1 failure = auto     │
│  │Coord.) │  │Coord.) │  │Coord.) │    failover                  │
│  └───┬────┘  └───┬────┘  └───┬────┘                              │
│      │           │           │                                    │
│      └───────────┴───────────┘                                    │
│                  │ mTLS HTTPS (parallel)                          │
│                  ▼                                                 │
└───────────────────────────────────────────────────────────────────┘
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
- **Coordinator HA: 3 proxy instances behind nginx — no single proxy failure halts signing**
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

### Critical Bugs Fixed During KEP-740 Integration

Two subtle bugs were found and fixed that are worth documenting for anyone implementing KEP-740:

**Bug 1: Double base64 encoding of JWT payload**

The `kube-apiserver` sends the JWT payload to the external signer already base64url encoded. An initial implementation was double-encoding it (encoding an already-encoded payload), producing an invalid signature that silently fails verification.

**Fix:** Use the payload bytes directly without re-encoding.

**Bug 2: Wrong ECDSA signature format (ASN.1 DER vs IEEE P1363)**

Kubernetes uses `go-jose` internally, which requires ECDSA signatures in **IEEE P1363 format** (raw R‖S concatenation, 64 bytes for P-256). Go's standard `crypto/ecdsa` package produces **DER/ASN.1 format** by default. Using DER format causes silent verification failures — the token appears valid but fails authentication.

```go
// Wrong — DER format (default Go output)
sig, _ := ecdsa.SignASN1(rand.Reader, key, hash)

// Correct — IEEE P1363 R‖S format required by go-jose/Kubernetes
r, s := derToRS(sig)  // extract R and S from DER
p1363 := append(padTo32(r), padTo32(s)...)
```

These bugs affect any Go implementation of KEP-740 that uses the standard library's ECDSA signing without explicit format conversion.

### Features Implemented

| Feature | Status | Notes |
|---|---|---|
| FROST 3-of-5 threshold signing | ✅ | Via bytemare/frost (RFC 9591) |
| KEP-740 ExternalJWTSigner gRPC | ✅ | Stable K8s v1.36 API |
| Full Kubernetes integration | ✅ | controller-manager, scheduler, pods all receive FROST-signed tokens |
| Distributed DKG ceremony | ✅ | Pedersen protocol — no trusted dealer |
| Automatic signer failover | ✅ | Falls back to next available signer |
| Failure tolerance (2-of-5) | ✅ | Tested — system continues with 3 signers |
| Parallel signer communication | ✅ | All 5 contacted simultaneously via goroutines |
| mTLS (coordinator ↔ signers) | ✅ | Certificate-based mutual authentication |
| Vault key share storage | ✅ | Signers load shares from Vault on startup |
| AES-256-GCM encrypted fallback | ✅ | If Vault unavailable, uses encrypted file |
| **Coordinator HA (nginx)** | ✅ | **NEW: 3 proxy replicas, automatic failover** |
| Benchmark suite | ✅ | Latency, throughput, concurrency, failure testing |
| Native ARM64 binary | ✅ | No qemu emulation overhead on Apple Silicon |

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
│   ├── genkey/            # ECDSA signing key generation
│   ├── encrypt-keys/      # AES-256-GCM key share encryption tool
│   ├── dkg-coordinator/   # Distributed DKG ceremony orchestrator
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
│   ├── mtls/              # mTLS client factory
│   ├── keystore/          # AES-256-GCM encryption/decryption
│   ├── dkg/               # Distributed Key Generation (Pedersen protocol)
│   ├── api/               # HTTP API types
│   ├── config/            # Environment-based configuration
│   └── types/             # Shared types
│
├── proto/
│   └── externaljwt/v1alpha1/
│       ├── api.proto      # ExternalJWTSigner gRPC service definition
│       ├── api.pb.go      # Generated protobuf
│       └── api_grpc.pb.go # Generated gRPC stubs
│
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile.proxy   # Multi-stage: builds grpc-proxy
│   │   └── Dockerfile.signer  # Multi-stage: builds signer
│   ├── docker-compose.yml     # 5 signers + 3 grpc-proxy + nginx LB + Vault
│   ├── nginx-grpc.conf        # nginx gRPC upstream config (coordinator HA)
│   ├── vault-config.hcl       # Vault server configuration
│   └── k3d/
│       └── cluster-config.yaml
│
├── certs/                 # mTLS certificates (generate locally — not in git)
├── data/                  # Key material (generate locally — not in git)
│
├── benchmark/
│   ├── run_benchmarks_frost.sh    # Comprehensive FROST benchmark suite
│   ├── run_benchmarks_baseline.sh # Baseline RS256 benchmark suite
│   └── results/                   # Benchmark output files (timestamped)
│
├── scripts/
│   ├── restart-frost.sh   # One-command FROST cluster setup after restart
│   ├── setup-minikube.sh  # Automated Minikube patching
│   └── vault-init.sh      # Vault KV engine init + key share loading
│
├── docs/
│   └── architecture.md
│
├── go.mod
├── go.sum
└── README.md
```

---

## 6. Prerequisites

### Required Software

| Tool | Version | Install |
|---|---|---|
| Go | 1.23+ | https://go.dev/dl/ |
| Docker Desktop | Latest | https://www.docker.com/products/docker-desktop/ |
| minikube | Latest | `brew install minikube` |
| kubectl | Latest | `brew install kubectl` |
| openssl | Any | Pre-installed on macOS/Linux |

### System Requirements

- macOS (Apple Silicon or Intel) or Linux
- 8GB+ RAM recommended (Minikube + 9 Docker containers)
- 10GB free disk space

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

Downloads: `github.com/bytemare/frost`, `google.golang.org/grpc`, `github.com/bytemare/secret-sharing`, `hashicorp/vault/api`.

### Step 3: Generate FROST Key Shares

```bash
go run cmd/keygen/main.go
```

Creates 5 cryptographic key shares (3-of-5 threshold). Any 3 can sign; 2 or fewer cannot produce anything valid.

### Step 4: Generate ECDSA Signing Key

```bash
go run cmd/genkey/main.go
```

Generates the ECDSA P-256 key used for JWT signing (`data/ecdsa-signing.pem`).

### Step 5: Encrypt Key Shares

```bash
go run cmd/encrypt-keys/main.go
```

Encrypts key shares with AES-256-GCM. Set `FROST_KEY_PASSWORD` env var in production.

### Step 6: Generate mTLS Certificates

```bash
mkdir -p certs

# Certificate Authority
openssl genrsa -out certs/ca.key 2048
openssl req -new -x509 -days 365 -key certs/ca.key \
  -out certs/ca.crt -subj "/CN=frost-k8s-ca"

# Proxy certificate
openssl genrsa -out certs/proxy.key 2048
openssl req -new -key certs/proxy.key \
  -out certs/proxy.csr -subj "/CN=frost-proxy"
openssl x509 -req -days 365 \
  -in certs/proxy.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/proxy.crt

# Signer certificate (with SANs for all signer hostnames)
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
```

### Step 7: Start HashiCorp Vault and Load Key Shares

```bash
cd deploy && docker compose up -d vault
sleep 5
cd .. && bash scripts/vault-init.sh
```

Each signer fetches only its own key share from Vault at startup.

### Step 8: Build and Start All Containers

```bash
cd deploy
docker compose build
docker compose up -d
```

This starts **9 containers** on the minikube Docker network:

| Container | Role | Port |
|---|---|---|
| deploy-vault-1 | HashiCorp Vault (key share storage) | 8200 |
| deploy-signer-1-1 through 5-1 | FROST Signers 1–5 | 8081–8085 (mTLS) |
| deploy-grpc-proxy-1-1 through 3-1 | gRPC Coordinator instances (HA) | internal |
| deploy-coordinator-lb-1 | nginx load balancer | 9090 |

### Step 9: Verify All Containers Started

```bash
cd deploy && docker compose ps
```

Check logs for pool initialization:
```bash
docker compose logs signer-1 | tail -5
# Expected:
# [vault] Loaded key share for signer-1
# Loaded signer 1
# [pool] Signer pool initialized with 20 instances
# Signer listening on :8081 (mTLS enabled)
```

### Step 10: Start Minikube

```bash
cd .. && minikube start --driver=docker
```

### Step 11: Configure FROST Signing (One Command)

Use the automated restart script:

```bash
bash scripts/restart-frost.sh
```

This script automatically:
1. Starts all deploy containers
2. Detects the coordinator-lb IP
3. Copies certs and keys into Minikube
4. Starts socat bridge (macOS) or direct mount (Linux)
5. Patches kube-apiserver manifest
6. Waits for restart and verifies FROST signing is active

**macOS note:** On macOS with Docker Desktop, Unix sockets cannot be directly shared between Docker containers and the Minikube VM. The script uses a `socat` TCP bridge automatically. On Linux this bridge is not needed.

### Step 12: Verify FROST is Active

```bash
kubectl create token default | cut -d. -f1 | base64 -d
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

---


---

## 7b. Manual Setup (Without restart-frost.sh)

If you prefer to run each step manually instead of using `scripts/restart-frost.sh`, follow these steps after completing Steps 1–10.

### Step M1: Start Deploy Containers

```bash
cd deploy && docker compose up -d && cd ..
```

Verify all 9 containers are running:
```bash
cd deploy && docker compose ps
```

### Step M2: Get Coordinator Load Balancer IP

```bash
LB_IP=$(docker inspect deploy-coordinator-lb-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*')
echo "Coordinator LB IP: $LB_IP"
```

Save this IP — you need it in Step M4.

### Step M3: Copy Files Into Minikube

```bash
docker exec minikube mkdir -p /app/data /app/certs /var/run/frost-k8s

docker cp data/frost-keys.json minikube:/app/data/frost-keys.json
docker cp data/ecdsa-signing.pem minikube:/app/data/ecdsa-signing.pem
docker cp certs/proxy.crt minikube:/app/certs/proxy.crt
docker cp certs/proxy.key minikube:/app/certs/proxy.key
docker cp certs/ca.crt minikube:/app/certs/ca.crt
```

### Step M4: Start socat Bridge Inside Minikube (macOS only)

On macOS, Docker Desktop prevents Unix sockets from being shared between containers and the Minikube VM. The socat bridge forwards gRPC traffic from the Unix socket to the coordinator load balancer over TCP.

```bash
# Use the LB_IP from Step M2
docker exec minikube bash -c "
pkill socat 2>/dev/null
rm -f /var/run/frost-k8s/signer.sock
socat UNIX-LISTEN:/var/run/frost-k8s/signer.sock,fork,reuseaddr TCP:${LB_IP}:9090 &
sleep 2
ss -xlp | grep signer.sock
"
```

Expected output:
```
u_str LISTEN ... /var/run/frost-k8s/signer.sock ... users:(("socat",...))
```

**Linux users:** Skip this step. Instead, run grpc-proxy as a Docker container and volume-mount the socket directly to Minikube using `minikube mount`.

### Step M5: Patch kube-apiserver Manifest

> ⚠️ **Do NOT use `sed` to patch the manifest on macOS** — it can silently corrupt volume entries. Write the full manifest directly:

```bash
docker exec minikube bash -c "cat > /etc/kubernetes/manifests/kube-apiserver.yaml << 'ENDOFYAML'
apiVersion: v1
kind: Pod
metadata:
  labels:
    component: kube-apiserver
    tier: control-plane
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --advertise-address=192.168.49.2
    - --allow-privileged=true
    - --authorization-mode=Node,RBAC
    - --client-ca-file=/var/lib/minikube/certs/ca.crt
    - --enable-bootstrap-token-auth=true
    - --etcd-cafile=/var/lib/minikube/certs/etcd/ca.crt
    - --etcd-certfile=/var/lib/minikube/certs/apiserver-etcd-client.crt
    - --etcd-keyfile=/var/lib/minikube/certs/apiserver-etcd-client.key
    - --etcd-servers=https://127.0.0.1:2379
    - --kubelet-client-certificate=/var/lib/minikube/certs/apiserver-kubelet-client.crt
    - --kubelet-client-key=/var/lib/minikube/certs/apiserver-kubelet-client.key
    - --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
    - --proxy-client-cert-file=/var/lib/minikube/certs/front-proxy-client.crt
    - --proxy-client-key-file=/var/lib/minikube/certs/front-proxy-client.key
    - --requestheader-allowed-names=front-proxy-client
    - --requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt
    - --requestheader-extra-headers-prefix=X-Remote-Extra-
    - --requestheader-group-headers=X-Remote-Group
    - --requestheader-username-headers=X-Remote-User
    - --secure-port=8443
    - --service-account-issuer=https://kubernetes.default.svc.cluster.local
    - --service-account-signing-endpoint=/var/run/frost-k8s/signer.sock
    - --service-cluster-ip-range=10.96.0.0/12
    - --tls-cert-file=/var/lib/minikube/certs/apiserver.crt
    - --tls-private-key-file=/var/lib/minikube/certs/apiserver.key
    - --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota
    image: registry.k8s.io/kube-apiserver:v1.35.1
    imagePullPolicy: IfNotPresent
    name: kube-apiserver
    volumeMounts:
    - mountPath: /etc/ssl/certs
      name: ca-certs
      readOnly: true
    - mountPath: /etc/ca-certificates
      name: etc-ca-certificates
      readOnly: true
    - mountPath: /var/lib/minikube/certs
      name: k8s-certs
      readOnly: true
    - mountPath: /usr/local/share/ca-certificates
      name: usr-local-share-ca-certificates
      readOnly: true
    - mountPath: /usr/share/ca-certificates
      name: usr-share-ca-certificates
      readOnly: true
    - mountPath: /var/run/frost-k8s
      name: frost-k8s
  hostNetwork: true
  priorityClassName: system-node-critical
  volumes:
  - hostPath:
      path: /etc/ssl/certs
      type: DirectoryOrCreate
    name: ca-certs
  - hostPath:
      path: /etc/ca-certificates
      type: DirectoryOrCreate
    name: etc-ca-certificates
  - hostPath:
      path: /var/lib/minikube/certs
      type: DirectoryOrCreate
    name: k8s-certs
  - hostPath:
      path: /usr/local/share/ca-certificates
      type: DirectoryOrCreate
    name: usr-local-share-ca-certificates
  - hostPath:
      path: /usr/share/ca-certificates
      type: DirectoryOrCreate
    name: usr-share-ca-certificates
  - hostPath:
      path: /var/run/frost-k8s
      type: DirectoryOrCreate
    name: frost-k8s
status: {}
ENDOFYAML"
```

### Step M6: Wait and Verify

```bash
echo "Waiting 60s for kube-apiserver restart..."
sleep 60

kubectl create token default | cut -d. -f1 | base64 -d
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

### After Minikube Restart

Every time Minikube restarts, repeat Steps M1–M4 (containers, LB IP, file copy, socat bridge). The manifest patch (Step M5) persists inside Minikube unless you delete the cluster.

Or just run:
```bash
bash scripts/restart-frost.sh
```



## 8. Verification — Check Everything Works

### 8.1 Verify FROST Token Header

```bash
kubectl create token default | cut -d. -f1 | base64 -d 2>/dev/null
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

- `alg: ES256` — ECDSA P-256 ✅
- `kid: frost-k8s-v1` — FROST proxy signed this ✅

### 8.2 Verify Proxy Logs Show Signing

```bash
cd deploy && docker compose logs grpc-proxy-1 | grep "Signed JWT" | tail -3
# Expected:
# [proxy] Signed JWT — kid=frost-k8s-v1 active_signers=[signer-3 signer-1 signer-4]
```

### 8.3 Verify Coordinator HA

```bash
# Kill one proxy — signing should continue via the other two
docker stop deploy-grpc-proxy-1-1
kubectl create token default | cut -d. -f1 | base64 -d
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"} — still works!

docker start deploy-grpc-proxy-1-1
```

### 8.4 Deploy a Real Application

```bash
kubectl create namespace test
kubectl create deployment nginx --image=nginx -n test
sleep 30 && kubectl get pods -n test
# Expected: nginx pod Running

# Inspect its mounted token
POD=$(kubectl get pod -n test -o name | head -1)
kubectl exec -n test $POD -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token | \
  cut -d. -f1 | base64 -d 2>/dev/null
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}
```

Every pod in the cluster automatically receives a FROST threshold-signed token. ✅

---

## 9. Running the DKG Ceremony

The Distributed Key Generation (DKG) ceremony allows signers to generate key shares without any single party ever seeing the complete key.

### What DKG Does

```
Round 1: Each signer independently generates a random polynomial
         and broadcasts commitments (public values)
Broadcast: Coordinator sends all commitments to all signers
Round 2: Each signer computes a share for every other signer
         using their polynomial, sends it securely
Finalize: Each signer adds up all received shares
          → final key share (no one else knows it)
```

At no point does any single party see all key shares.

### Run the DKG Ceremony

```bash
docker exec deploy-grpc-proxy-1-1 sh -c "
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
[Round 1] Collecting commitments...
  ✅ Commitment received from signer-1 ... signer-5
[Broadcast] Sending all commitments to signers...
[Round 2] Distributing shares...
=== DKG Ceremony Complete ===
Each signer now holds an independent key share.
No single party ever saw the complete signing key.
```

---

## 10. Benchmark Results

All benchmarks run on **single-node Minikube, Docker driver, macOS M-series (Apple Silicon), ARM64 native binary**.

### 10.1 Latency Comparison

| Test | Baseline RS256 | FROST 3-of-5 | Overhead |
|---|---|---|---|
| Single token (cold start) | ~57ms | ~69ms | +12ms |
| Single token (warm) | ~34ms | ~36ms | +6% |
| Warm path P50 | 34ms | 34ms | **0%** |
| Warm path P95 | 48ms | 69ms | +44% |
| 100 tokens (sequential avg) | 32ms | 31ms | ~0% |
| 500 tokens (sequential avg) | 31ms | 44ms | +42% |
| 10 concurrent tokens | ~174ms | ~81ms | -53%† |
| 20 concurrent tokens | ~143ms | ~152ms | +6% |
| 50 concurrent tokens | ~340ms | ~403ms | +18% |

†The 10-concurrent result is attributable to nginx load balancing distributing requests across three coordinator instances. It should not be interpreted as a cryptographic performance advantage.

### 10.2 Throughput

| Test | Baseline | FROST |
|---|---|---|
| Sequential throughput | 31 tok/s | 31 tok/s |

### 10.3 Resource Usage (Idle)

| Component | CPU | Memory |
|---|---|---|
| coordinator-lb (nginx) | 0.00% | ~3MB |
| Each grpc-proxy instance | 0.00% | ~14MB |
| Each signer | 0.00% | ~12MB |
| **Total FROST overhead** | ~0% | **~111MB** (3 proxies + 5 signers + nginx) |

### 10.4 Failure and Recovery

| Scenario | Result | Time |
|---|---|---|
| 2 of 5 signers killed | System continues ✅ | ~70ms/token (same) |
| 3 of 5 signers killed | Explicit error returned ✅ | N/A |
| Signer restarted | Automatic recovery ✅ | 84ms |
| Coordinator proxy killed | nginx failover ✅ | transparent |

### 10.5 Signer Count Effect on Latency

| Signers Active | Latency | Notes |
|---|---|---|
| 5-of-5 | ~36ms | Normal operation |
| 3-of-5 (2 killed) | ~36ms | **Identical — zero overhead** |
| 2-of-5 (3 killed) | Error | Explicit threshold enforcement |

### 10.6 Important Notes on Benchmarks

These benchmarks were conducted on **single-node Minikube with Docker driver on macOS**. Results include macOS Docker Desktop networking overhead and the socat bridge latency. The FROST signing itself contributes approximately **10–20ms per token**. Production Linux bare-metal deployments will show different absolute numbers.

---

## 11. Failure Tolerance Testing

### Test 1: Kill 2 Signers (System Should Continue)

```bash
docker stop deploy-signer-4-1 deploy-signer-5-1
sleep 3
kubectl create token default | cut -d. -f1 | base64 -d
# Expected: {"alg":"ES256","typ":"JWT","kid":"frost-k8s-v1"}

docker start deploy-signer-4-1 deploy-signer-5-1
```

### Test 2: Kill 3 Signers (Below Threshold — Should Fail)

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
docker stop deploy-signer-1-1
sleep 2
docker start deploy-signer-1-1
cd deploy && docker compose logs signer-1 | tail -5
# Expected: [vault] Loaded key share for signer-1
kubectl create token default | cut -d. -f1 | base64 -d
# Expected: frost-k8s-v1
```

---

## 12. Known Limitations and Workarounds

### L1 — macOS Unix Socket Workaround

**Problem:** On macOS with Docker Desktop, Unix sockets cannot be shared between Docker containers and the Minikube VM.

**Workaround:** `scripts/restart-frost.sh` automatically uses `socat` to bridge TCP (coordinator-lb:9090) to a Unix socket inside Minikube. On Linux this is not needed — direct volume mount works.

**Impact:** Extra setup steps on macOS; `restart-frost.sh` must be re-run after Minikube restarts.

### L2 — Coordinator-Assisted DKG (Primary Research Challenge)

**Problem:** The prototype uses coordinator-assisted key generation (`cmd/keygen`) for runtime experiments. During key generation, the coordinator transiently possesses all share material. An experimental peer-to-peer DKG ceremony is implemented (`cmd/dkg-coordinator`) but not yet integrated into the runtime signing path.

**Note:** The *signing* protocol never reconstructs the complete key. FROST's security properties hold independently of the key generation mechanism.

**Production fix:** Integrate the Pedersen DKG ceremony so runtime shares are generated without any trusted dealer.

### L3 — Per-Signer Mutex Contention

**Problem:** The `bytemare/frost` library stores commitment nonces in the Signer object and is not safe for concurrent use. Each signer serializes requests via a global mutex. At 50+ concurrent requests this produces ~18% overhead with the 3-instance coordinator pool.

**Root cause:** Implementing a pool of independent Signer instances (one per concurrent session) requires careful session tracking between commit and sign rounds — commitment IDs must match the Signer instance that generated them.

**Production fix:** Per-request Signer pool with session-ID-based routing.

### L4 — Vault Dev Mode (No Persistence) 

**Problem:** Vault runs in development mode (in-memory storage). Vault restarts lose all stored shares.

**Workaround:** 3-tier fallback: Vault → AES-256-GCM encrypted file → plain JSON. Run `scripts/vault-init.sh` to reload after Vault restart.

**Production fix:** Vault with Raft storage backend, proper unseal keys, automated initialization.

### L5 — Single-Node Benchmark Environment

**Problem:** All benchmarks conducted on single-node Minikube with macOS Docker Desktop, which introduces socat bridge overhead and Docker Desktop networking latency not present in production.

**Impact:** Absolute numbers not representative of production Linux bare-metal performance. The relative comparison (FROST vs RS256 baseline) is valid within the same environment.

---

## 13. Future Work

### Near-Term

- **DKG integration with runtime signing** — DKG-generated shares replace keygen shares automatically
- **Parallel signing-session execution** — eliminate per-signer mutex contention for high-concurrency workloads
- **Vault persistent storage** — Raft backend, proper unseal, automated initialization
- **Automated key rotation** — FROST proactive secret resharing without downtime
- **Linux deployment simplification** — direct volume mount, no socat workaround

### Medium-Term

- **Multi-node benchmarks** — production-realistic numbers on multi-node clusters
- **Formal security verification** — ProVerif/Tamarin analysis of composed system
- **Tiered authentication model** — per-operation additional authentication for sensitive operations
- **Post-quantum readiness** — crypto-agile proxy for future PQC threshold scheme migration

### Long-Term

- **Kubernetes Operator** — automated signer lifecycle, key rotation, health monitoring
- **GKE/EKS/AKS support** — managed K8s compatibility
- **HSM integration** — signers backed by hardware security modules
- **Geographic distribution** — signers across cloud regions/providers

---

## 14. Troubleshooting

### Problem: `kubectl create token` returns RS256

**Cause:** kube-apiserver still using default single key.

```bash
# Check manifest
docker exec minikube grep "signing" /etc/kubernetes/manifests/kube-apiserver.yaml
# Should show: --service-account-signing-endpoint=/var/run/frost-k8s/signer.sock

# Re-run setup
bash scripts/restart-frost.sh
```

### Problem: `not enough signers: got 0, need 3`

**Cause:** grpc-proxy cannot reach signers (IPs changed after restart).

```bash
# Check IPs
for i in 1 2 3 4 5; do
  echo -n "signer-$i: "
  docker inspect deploy-signer-${i}-1 | grep '"IPAddress"' | tail -1 | grep -o '[0-9.]*'
done

# Re-run setup (auto-detects new IPs)
bash scripts/restart-frost.sh
```

### Problem: apiserver pod in CrashLoopBackOff

**Cause:** kube-apiserver cannot find the Unix socket at startup.

**Fix:** Ensure `restart-frost.sh` completes successfully (socat bridge running) before patching the manifest.

### Problem: Signers show `[vault] Failed, trying local`

**Cause:** Vault restarted and lost in-memory data.

```bash
bash scripts/vault-init.sh
cd deploy && docker compose restart signer-1 signer-2 signer-3 signer-4 signer-5
```

### Problem: `tls: client did not provide a certificate`

**Cause:** mTLS certificates not properly configured.

**Fix:** Ensure `certs/proxy.crt`, `certs/proxy.key`, and `certs/ca.crt` exist and were generated by the same CA that signers trust.

### Re-running After Minikube Restart

One command restores everything:

```bash
bash scripts/restart-frost.sh
```

---

## Environment Variables Reference

| Variable | Component | Default | Description |
|---|---|---|---|
| `SIGNER_ID` | signer | required | Signer identity (1–5) |
| `PORT` | signer | required | HTTP port (8081–8085) |
| `VAULT_ADDR` | signer | — | Vault URL e.g. `http://vault:8200` |
| `VAULT_TOKEN` | signer | — | Vault authentication token |
| `FROST_KEY_PASSWORD` | signer | `frost-dev-password` | AES-256-GCM decryption password |
| `TLS_CERT` | signer | `certs/signer.crt` | Signer TLS certificate |
| `TLS_KEY` | signer | `certs/signer.key` | Signer TLS private key |
| `TLS_CA` | signer | `certs/ca.crt` | CA certificate for client verification |
| `SIGNER_1_ADDR`–`SIGNER_5_ADDR` | grpc-proxy | `https://signer-N:808N` | Signer addresses |
| `SOCKET_PATH` | grpc-proxy | `/var/run/frost-k8s/signer.sock` | Unix socket path |
| `TCP_ADDR` | grpc-proxy | — | If set, listen on TCP instead of Unix socket |
| `KEY_ID` | grpc-proxy | `frost-k8s-v1` | JWT `kid` header value |
| `ECDSA_KEY_PATH` | grpc-proxy | `data/ecdsa-signing.pem` | ECDSA signing key path |

---

## Companion Research

This implementation accompanies a three-paper research series:

| Paper | Title | DOI |
|---|---|---|
| Survey | Authentication Mechanisms in Kubernetes: A Systematic Review | [10.5281/zenodo.20734453](https://doi.org/10.5281/zenodo.20734453) |
| Security Analysis | Threat Modeling and Security Analysis of Threshold-Based Token Signing | [10.5281/zenodo.20733863](https://doi.org/10.5281/zenodo.20733863) |
| Prototype | frost-k8s: A FROST-Based Threshold Signing Proxy | [10.5281/zenodo.20770308](https://doi.org/10.5281/zenodo.20770308) |

---

## Acknowledgments

- [bytemare/frost](https://github.com/bytemare/frost) — Go implementation of FROST RFC 9591
- [Kubernetes KEP-740](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/740-service-account-external-jwt-signer) — ExternalJWTSigner API
- [HashiCorp Vault](https://www.vaultproject.io/) — Secret management
- [NIST IR 8214C](https://doi.org/10.6028/NIST.IR.8214C) — Multi-Party Threshold Schemes standardization
- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591) — FROST: Flexible Round-Optimized Schnorr Threshold Signatures

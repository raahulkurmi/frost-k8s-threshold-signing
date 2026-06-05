# FROST Kubernetes Threshold Signing

Research prototype implementing threshold-based signing for Kubernetes Service Account Tokens using FROST.

## Goal

Traditional Kubernetes deployments rely on a single signing key for Service Account Tokens.

This project explores replacing the centralized signing model with a threshold signature architecture using FROST.

## Research Questions

- Can threshold signing improve resilience against key compromise?
- What latency overhead does FROST introduce?
- How many signer failures can the system tolerate?

## Phases

### Phase 1

Standalone FROST signing prototype

### Phase 2

Distributed signer architecture

### Phase 3

Kubernetes integration

### Phase 4

Performance evaluation and benchmarking

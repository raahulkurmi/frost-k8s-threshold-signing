> **Historical (FROST prototype, superseded).** This is the README of the abandoned FROST prototype, kept for the claims audit. Its keys are burned (reports/HISTORY_PURGE.md) and its design did not threshold-sign tokens (legacy/frost/README.md).


# Architecture

## Components

### Coordinator

Receives signing requests and coordinates threshold signing.

### Signers

Participating FROST nodes.

### Verifier

Verifies generated signatures.

## Initial Configuration

3-of-5 Threshold Scheme

- 5 total signers
- 3 required for signing

## Future Integration

Kubernetes Service Account Token signing.

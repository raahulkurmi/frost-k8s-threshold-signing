# Key ceremony (trusted dealer)

frost-k8s signs service account tokens with a **3-of-5 Shoup threshold RSA key**
(RS256, 2048-bit modulus). Shoup's scheme needs a **trusted dealer** to generate the key.
This document covers how to run the dealer and what you have to trust while it runs.

## Trust assumption (explicit)

While `cmd/dealer` runs, **the dealer process holds the full RSA private key** (p, q, d)
in memory. Whoever controls the dealer machine during the ceremony can keep a copy of the
key and forge tokens forever. The threshold property only covers what happens after the
ceremony, and only if the dealer is honest and its memory is gone.

The dealer:
- never writes p, q, d or the full private key to disk, stdout or Vault;
- never prints a share. It prints only the key ID and SHA-256 fingerprints of the files it wrote;
- refuses to overwrite an existing `public-meta.json`, `share-<i>.json` or `priority.key`.

Go cannot guarantee that key material is wiped from memory. The dealer is a short-lived
process: run it, then shut the machine down.

## Outputs

| File | Mode | Contents | Goes to |
|---|---|---|---|
| `out/public-meta.json` | 0644 | Group public key (PKIX DER, base64), Shoup verification keys `v`, `u`, `vk_1..vk_n`, `t`, `n`, `kid`, modulus size, creation time. **Public.** | Coordinator(s) and every signer |
| `out/share-<i>.json` | 0600 | `{version, kid, signer_index: i, si}`: **one** secret share | Signer `i` only |
| `out/priority.key` | 0600 | `{version, kid, priority_key}`: 32 random bytes, the signers' shared admission-priority key K_prio (NOTES N76, `docs/PRIORITY_ADMISSION.md`). **Not signing material:** a holder can predict admission priorities, nothing more. | Every signer; **never** the coordinator |

`kid` is `base64url(SHA-256(PKIX DER of the group public key)[:16])`, 22 characters.
Every loader recomputes it and rejects a mismatch.

Each signer checks its share at startup: the index must equal `SIGNER_ID`, the kid must
equal the meta kid, and `v^si mod N` must equal `vk_i`. A share for the wrong signer or
the wrong key, or a corrupted share, stops the signer from starting.

## Procedure

1. **Isolated machine.** Use a freshly installed machine or VM with no network after the
   build, a full-disk-encrypted or tmpfs working directory, and no swap. Build the dealer
   from a reviewed commit and record the commit hash:
   ```bash
   git rev-parse HEAD
   GOTOOLCHAIN=go1.27.1 go build -trimpath -o dealer ./cmd/dealer
   sha256sum dealer
   ```
2. **Generate.** Safe-prime generation takes seconds to minutes.
   ```bash
   ./dealer --out out/ --modulus-bits 2048 --t 3 --n 5
   ```
   Record the printed `kid` and fingerprints in the ceremony log. Two people should sign it.
   **Vault variant:** `VAULT_ADDR=https://... VAULT_TOKEN=... ./dealer --out out/ --vault` (`VAULT_ADDR` must be `https://`; plain http only with `VAULT_DEV_ALLOW_HTTP=1`, for local development; redirects to another host are refused; audit E-1). This writes
   `secret/frost-k8s/signer-<i>` and `secret/frost-k8s/priority-key` (KV v2) and puts only
   `public-meta.json` on disk. Use a
   token scoped to writing those paths and revoke it afterwards. In production, each signer
   should read with its own policy that allows only its own path.
3. **Distribute.** Send `share-<i>.json` to the operator of signer `i` over a separate
   authenticated channel for each signer. Each recipient checks the SHA-256 against the
   ceremony log. `public-meta.json` is public and goes to every coordinator and signer.
   `priority.key` goes to every signer (the same file) and never to a coordinator host;
   it is used only with `SIGNER_ADMISSION=priority`. Rotating it needs no re-dealing of
   shares: generate a new one bound to the same kid and restart the signers together.
4. **Destroy.** Securely delete `out/` (`shred -u out/share-*.json out/priority.key` on a non-journaling or
   tmpfs volume, or destroy the encrypted volume), then power off the machine. Record that
   destruction happened.
5. **Verify.** Start the signers. Each one logs its signer index and the `kid`. Then check
   `FetchKeys` or `/openid/v1/jwks` and confirm it serves that `kid`.

## Rotation

Run a new ceremony. It produces a new `kid`. Roll out signers with the new shares and
coordinators with the new meta. Tokens signed under the old key stop verifying once the
old public key is no longer served. The current single-key `FetchKeys` doesn't support
publishing old and new keys together, so rotation causes a validation gap for existing
tokens. **Key rotation is not implemented**: FetchKeys serves exactly one key (I2), and no
multi-key rollover exists (Phase 12 audit G-29; there are no rotation entries in `NOTES.md`).

## What this ceremony does not protect against

- A malicious or compromised dealer (see the trust assumption above).
- Any `t` share holders colluding.
- Shares that are never destroyed on the dealer machine.

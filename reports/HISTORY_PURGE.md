# History purge plan (NOT executed)

Prepared 2026-09-24 on branch `fix/threshold-rsa`. **Nothing in this file has been run.**
Rewriting history and force-pushing are for the repository owner to do.

## 1. Leaks: burned material (remove from all history, and treat as burned regardless)

`github.com/raahulkurmi/frost-k8s-threshold-signing` is **public** (GitHub API:
`"visibility": "public"`, 0 forks when checked). Anything that was ever pushed may already
be cloned, cached or indexed. A purge limits future exposure. It does not revoke anything.

| Material | Paths in history | Commits | Why it is burned |
|---|---|---|---|
| FROST Ristretto255 key shares, all 5, plaintext hex | `data/frost-keys.json` | 801b7ef, 93f0dc5, 496ce83 (removed) | Plain secret shares (D10) |
| FROST key shares, AES-GCM encrypted | `data/frost-keys.enc` | 3946ea0, f91807b | The key is SHA-256 of the default password `frost-dev-password`, which is committed in 3946ea0 and d8e9894 (D7) |
| ECDSA P-256 JWT signing key, the one that actually signed every JWT | `data/ecdsa-signing.pem` | 93f0dc5, 496ce83 (removed) | Private key committed (D1, D10) |
| mTLS CA private key | `certs/ca.key` | bfec86c, f91807b | Anyone holding it can mint coordinator or signer certs (D8) |
| mTLS proxy key | `certs/proxy.key` | bfec86c, fd12b6c, f91807b | D8 |
| mTLS signer key, shared by all 5 signers | `certs/signer.key` | bfec86c, 9b412e3, f91807b | D8 |
| Vault dev root token `frost-dev-token` | `deploy/docker-compose.yml`, `scripts/vault-init.sh`, `README.md` | 9b412e3, 3946ea0, d8e9894, 7692d5a | Dev root token in the clear |
| Default password `frost-dev-password` | `internal/froststate/bootstrap.go`, `cmd/encrypt-keys/main.go`, `deploy/cmd/encrypt-keys/main.go`, `README.md` | 3946ea0, d8e9894 | Decrypts `frost-keys.enc` |

Any JWT that verifies under the ECDSA key above, and any cluster that ever trusted it
through `FetchKeys`, must be treated as compromised. The new threshold RSA key shares
nothing with any of these keys, and fresh certs come from `scripts/gen-certs.sh`.

The gitleaks history scan (`reports/gitleaks-history.json`, redacted) finds 4 of these:
the three `certs/*.key` files and `data/ecdsa-signing.pem`. It does **not** flag the FROST
shares (bare hex), the encrypted share file, the password or the Vault token. Those were
found by hand with `git log --all -- <path>` and `git log --all -S<literal>`.

## 2. Bloat: remove from all history (not secret)

| Path | Commits | Notes |
|---|---|---|
| `nohup.out` | f91807b | 8.6 MB of `sh: socat: command not found`. The pattern scan and gitleaks both found no secrets |
| `grpc-proxy`, `signer` (root Mach-O binaries) | 562590e, 93f0dc5, ecfc0f5, bfec86c | Compiled binaries. They embed the `frost-dev-password` string, so purge them with the leaks |
| `deploy/ nginx-grpc.conf` | f91807b | Duplicate config with a leading space in its name |
| `benchmark/results/20260925T094221Z-4385a48-multihost-L1/.summarize` | dc9b396 (removed in the next commit) | 2.6 MB Mach-O build artifact of `benchmark/summarize`, committed by accident after an aborted benchmark run. Not secret |
| `certs/*.crt`, `certs/*.csr`, `certs/ca.srl`, `certs/*.cnf` | bfec86c, fd12b6c, 9b412e3, f91807b | Public certs, but they're bound to the burned keys |

## 3. Commands (run by the owner, on a fresh mirror clone)

```bash
# 0. Tool: https://github.com/newren/git-filter-repo (not installed on the prep machine)
brew install git-filter-repo          # or: pipx install git-filter-repo

# 1. Work on a fresh mirror, never on your working clone
git clone --mirror https://github.com/raahulkurmi/frost-k8s-threshold-signing.git purge.git
cd purge.git

# 2. Remove every leaked and bloat path from every ref
git filter-repo --invert-paths \
  --path data/frost-keys.json \
  --path data/frost-keys.enc \
  --path data/ecdsa-signing.pem \
  --path certs/ \
  --path nohup.out \
  --path grpc-proxy \
  --path signer \
  --path 'deploy/ nginx-grpc.conf' \
  --path benchmark/results/20260925T094221Z-4385a48-multihost-L1/.summarize

# 3. Scrub the literal default secrets from all remaining blobs (README, compose, scripts, Go)
cat > ../replacements.txt <<'EOF'
frost-dev-password==>REDACTED-BURNED-PASSWORD
frost-dev-token==>REDACTED-BURNED-VAULT-TOKEN
EOF
git filter-repo --replace-text ../replacements.txt

# 4. Verify before pushing: all of these must print nothing / zero leaks
git log --all --format=%h -- data/frost-keys.json data/frost-keys.enc data/ecdsa-signing.pem certs nohup.out grpc-proxy signer
git log --all -S'frost-dev-password' --format=%h
git log --all -S'frost-dev-token' --format=%h
gitleaks git . --log-opts="--all" --redact --no-banner

# 5. Push the rewritten history (DESTRUCTIVE: rewrites main, frost-integration and fix/threshold-rsa)
git remote set-url origin https://github.com/raahulkurmi/frost-k8s-threshold-signing.git   # filter-repo removes origin
git push --force --mirror origin

# 6. Afterwards
#  - Every collaborator re-clones. Old clones will reintroduce the purged objects if pushed.
#  - Ask GitHub Support to purge cached views and unreachable objects for the repo
#    (GitHub "Removing sensitive data from a repository" guide), and check for forks.
#  - Rebase any open work (including fix/threshold-rsa) onto the rewritten main.
```

Notes:
- Step 2 removes `certs/` entirely, including the public `.crt` and `.cnf` files. They are
  replaced by `scripts/gen-certs.sh`, which writes to `secrets/` (ignored).
- Commit hashes in this file are pre-rewrite hashes. Every hash changes after step 2.
- `fix/threshold-rsa` removes all of these paths from the tip (Phase 1). This purge is
  still needed for the history.

## 4. Local copies found outside git

When Phase 1 ran, `data/ecdsa-signing.pem` (EC private key) and `data/frost-keys.json`
(all 5 FROST shares) were in the working directory as ignored, untracked files. They were
**moved, not deleted**, to `~/frost-k8s-burned-keys-20260924/` (dir `0700`, files `0600`),
so the tree scan is clean and nothing irreversible happened. They are burned. Shred that
directory once you no longer need them for forensics:
`rm -P ~/frost-k8s-burned-keys-20260924/* && rmdir ~/frost-k8s-burned-keys-20260924`.

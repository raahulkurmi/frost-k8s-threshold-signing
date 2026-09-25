#!/usr/bin/env bash
# Install gitleaks $GITLEAKS_VERSION (default 8.30.1) for linux/<arch>,
# verified against the release's published checksums.
set -euo pipefail
V="${GITLEAKS_VERSION:-8.30.1}"
case "$(uname -m)" in x86_64) A=x64 ;; aarch64|arm64) A=arm64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
T="$(mktemp -d)"; cd "$T"
F="gitleaks_${V}_linux_${A}.tar.gz"
curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${V}/${F}"
curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${V}/gitleaks_${V}_checksums.txt" | grep " ${F}\$" | sha256sum -c -
tar -xzf "$F" gitleaks
sudo install -m 0755 gitleaks /usr/local/bin/gitleaks
gitleaks version

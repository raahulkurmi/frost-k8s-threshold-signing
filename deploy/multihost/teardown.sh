#!/usr/bin/env bash
# teardown.sh: run on the OPERATOR machine after a --keep run. Stops and
# disables every signer, shreds every share and TLS key on the signer hosts,
# removes any netem qdisc, and tears down the coordinator-host stack (cluster,
# containers, secrets/). Firewalls stay in place. Portable to macOS bash 3.2.
# Usage: deploy/multihost/teardown.sh [topology.env]
set -euo pipefail
cd "$(dirname "$0")/../.."
TOPO="${1:-deploy/multihost/topology.local.env}"
# shellcheck disable=SC1090
source "$TOPO"
# shellcheck disable=SC1091
source deploy/multihost/transport.sh
SIGNER_VMS="$(for s in $SIGNERS; do r="${s#*:}"; echo "${r%%:*}"; done | sort -u | tr '\n' ' ')"
for vm in $SIGNER_VMS; do
  on "$vm" sudo bash -c '
    dev=$(ip -o -4 route show default | awk "{print \$5}"); tc qdisc del dev "$dev" root >/dev/null 2>&1 || true
    for u in /etc/systemd/system/frost-signer-*.service; do [ -f "$u" ] && systemctl disable --now "$(basename "$u")" >/dev/null 2>&1; done
    for d in /etc/frost-signer-*; do [ -d "$d" ] && shred -u "$d/share.json" "$d/tls.key" 2>/dev/null; rm -rf "$d"; done
    rm -rf /root/frost-stage; true'
  echo "$vm: signers stopped; share files left: $(on "$vm" sudo bash -c 'find / -xdev -name "share*.json" 2>/dev/null | wc -l' | tr -d '\r')"
done
on "$COORD_VM" bash -lc 'cd ~/tk8s && make e2e-down >/dev/null 2>&1; rm -rf secrets; echo "coordinator host: clusters=[$(kind get clusters 2>/dev/null)] containers=$(docker ps -q | wc -l) secrets=$(ls -d secrets 2>/dev/null || echo none)"'

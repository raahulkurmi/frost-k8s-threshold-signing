#!/usr/bin/env bash
# coordinator-egress.sh: run AS ROOT on the coordinator host. Restricts
# forwarded traffic FROM the coordinators' uplink subnet to exactly the
# signer IP:port pairs (Docker's DOCKER-USER chain). Everything else from
# that subnet (internet, other hosts, other ports) is dropped. Idempotent.
#
# Usage: coordinator-egress.sh SUBNET IP:PORT [IP:PORT ...]
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
SUBNET="$1"; shift
iptables -nL DOCKER-USER >/dev/null 2>&1 || { echo "DOCKER-USER chain not found (is Docker using the iptables backend?)" >&2; exit 1; }
iptables -N FROST-EGRESS 2>/dev/null || true
iptables -F FROST-EGRESS
iptables -A FROST-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for ep in "$@"; do
  ip="${ep%%:*}" port="${ep##*:}"
  iptables -A FROST-EGRESS -d "$ip" -p tcp --dport "$port" -j RETURN
done
iptables -A FROST-EGRESS -j DROP
while iptables -D DOCKER-USER -s "$SUBNET" -j FROST-EGRESS 2>/dev/null; do :; done
iptables -I DOCKER-USER -s "$SUBNET" -j FROST-EGRESS
echo "coordinator egress from $SUBNET limited to: $*"
iptables -S FROST-EGRESS

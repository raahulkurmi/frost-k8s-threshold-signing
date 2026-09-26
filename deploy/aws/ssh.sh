#!/usr/bin/env bash
# ssh.sh HOST [cmd...]: SSH to a tk8s-research instance as ubuntu, with the task key.
# HOST is "coord" or an IP. Refreshes the operator-IP SG rules first (common.sh).
. "$(dirname "$0")/common.sh"
refresh_admin_ip
h="$1"; shift
[ "$h" = coord ] && h=$(cat "$STATE/coordinator.ip")
exec ssh -i "$KEY_FILE" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile="$STATE/known_hosts" -o ServerAliveInterval=30 -o ConnectTimeout=15 \
  -o LogLevel=ERROR "ubuntu@$h" "$@"

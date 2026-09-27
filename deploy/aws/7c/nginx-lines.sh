#!/usr/bin/env bash
# nginx-lines.sh SINCE_EPOCH: every frost-nginx JSON timing line whose nginx `msec`
# is >= SINCE_EPOCH (seconds, fractional ok), read from ALL container log files the
# kubelet keeps for the frost-nginx static pod: the current file, rotated files and
# gzipped rotated files (kubelet rotates at 10 MiB; `kubectl logs` reads only the
# current file, which lost lines in the token run, NOTES N69/N70). Run as root on the
# control plane. NGINX_LOG_DIRS overrides the directories (tests).
set -euo pipefail
since="${1:?usage: nginx-lines.sh SINCE_EPOCH}"
dirs="${NGINX_LOG_DIRS:-$(ls -d /var/log/pods/kube-system_frost-nginx-*/nginx 2>/dev/null || true)}"
[[ -n "$dirs" ]] || { echo "no frost-nginx pod log directory" >&2; exit 1; }
for d in $dirs; do
  # oldest first; rotated files are named 0.log.<timestamp>[.gz], the current one 0.log
  for f in $(ls -1tr "$d"); do
    case "$f" in *.gz) gzip -dc "$d/$f" ;; *) cat "$d/$f" ;; esac
  done
done | sed -E 's/^[^ ]+ (stdout|stderr) [FP] //' | grep '"src":"nginx"' | jq -c --argjson s "$since" 'select((.msec | tonumber) >= $s)'

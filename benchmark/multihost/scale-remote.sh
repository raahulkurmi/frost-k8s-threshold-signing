#!/usr/bin/env bash
# scale-remote.sh OUTDIR: Phase 7B pod scale-up, run ON the coordinator host of
# a multihost deployment that is up (test/e2e/multihost.sh --keep, with the
# audit-enabled kind config). Same procedure as Phase 7A (benchmark/single/
# scale-lib.sh): T strict, fan-out all; the signers are the remote hosts.
# Leftover e2e workloads in the default namespace are deleted first so the cluster
# is otherwise idle.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="$1"
export PATH="/usr/local/go/bin:$PATH"
SCALE_SIZES="${SCALE_SIZES:-50 100}" SCALE_REPS="${SCALE_REPS:-3}"
KCTX=kind-tk8s CP=tk8s-control-plane
K() { kubectl --context "$KCTX" "$@"; }
die() { echo "FATAL: $*" >&2; exit 1; }
cpu_now() { awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5+$6, $9}' /proc/stat; }
audit_lines() { docker exec "$CP" sh -c 'wc -l < /var/log/kubernetes/audit.log' 2>/dev/null || echo 0; }
set -a; . secrets/multihost.env; set +a
COMPOSE=(docker compose -p tk8s -f deploy/docker-compose.multihost.yml)
"${COMPOSE[@]}" logs --no-color --no-log-prefix grpc-proxy-1 2>/dev/null | grep '"coordinator ready"' | tail -1 | jq -e 'select(.strategy=="strict" and .fanout=="all")' >/dev/null \
  || die "coordinators are not running strategy=strict fanout=all"
echo "cleaning default namespace (e2e leftovers): $(K get deploy,pod -n default --no-headers 2>/dev/null | wc -l) objects"
K delete deployment --all -n default --wait=true >/dev/null 2>&1 || true
K delete pod --all -n default --wait=true >/dev/null 2>&1 || true
mkdir -p "$OUT"
# shellcheck disable=SC1091
source benchmark/single/scale-lib.sh
scale_bench T-strict-all "$OUT" "${COMPOSE[@]}"
echo "scale-up results: $OUT/scale"

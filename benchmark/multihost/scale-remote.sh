#!/usr/bin/env bash
# scale-remote.sh OUTDIR STRATEGY FANOUT: Phase 7B pod scale-up, run ON the
# coordinator host of a multihost deployment that is up (test/e2e/multihost.sh
# --keep, with the audit-enabled kind config). Same procedure as Phase 7A
# (benchmark/single/scale-lib.sh) with the 7B cooldown: before every repetition
# the Deployment is deleted and the run waits until its pods are gone and this
# host's load1 < SCALE_COOLDOWN_LOAD (default 1.0, max 300 s); the wait is recorded.
# The coordinators are restarted with STRATEGY/FANOUT first; the signers are the
# remote hosts. Leftover e2e workloads in the default namespace are deleted first.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="$1" ST="$2" FO="$3"
export PATH="/usr/local/go/bin:$PATH"
SCALE_SIZES="${SCALE_SIZES:-50 100}" SCALE_REPS="${SCALE_REPS:-3}"
export SCALE_COOLDOWN_LOAD="${SCALE_COOLDOWN_LOAD:-1.0}" SCALE_COOLDOWN_MAX="${SCALE_COOLDOWN_MAX:-300}"
HEDGE_DELAY="${HEDGE_DELAY:-50ms}"
KCTX=kind-tk8s CP=tk8s-control-plane
K() { kubectl --context "$KCTX" "$@"; }
die() { echo "FATAL: $*" >&2; exit 1; }
cpu_now() { awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5+$6, $9}' /proc/stat; }
audit_lines() { docker exec "$CP" sh -c 'wc -l < /var/log/kubernetes/audit.log' 2>/dev/null || echo 0; }
set -a; . secrets/multihost.env; set +a
COMPOSE=(docker compose -p tk8s -f deploy/docker-compose.multihost.yml)

FROST_UID=$(id -u) VERIFY_STRATEGY="$ST" FANOUT="$FO" HEDGE_DELAY="$HEDGE_DELAY" SIGN_DEADLINE=2s \
  "${COMPOSE[@]}" up -d --force-recreate --no-deps grpc-proxy-1 grpc-proxy-2 grpc-proxy-3 >/dev/null 2>&1
ok=0
for _ in $(seq 1 60); do
  ok=0
  for r in 1 2 3; do
    docker logs "tk8s-grpc-proxy-$r-1" 2>&1 | grep '"coordinator ready"' | tail -1 | jq -e "select(.strategy==\"$ST\" and .fanout==\"$FO\")" >/dev/null && ok=$((ok + 1))
  done
  [[ $ok == 3 ]] && break; sleep 1
done
[[ $ok == 3 ]] || die "coordinators did not all start with strategy=$ST fanout=$FO"
for _ in $(seq 1 30); do K create token default --duration=10m >/dev/null 2>&1 && break; sleep 1; done
echo "coordinators: strategy=$ST fanout=$FO (all 3 replicas verified); cooldown load1 < $SCALE_COOLDOWN_LOAD, max ${SCALE_COOLDOWN_MAX}s"

echo "cleaning default namespace (e2e leftovers): $(K get deploy,pod -n default --no-headers 2>/dev/null | wc -l) objects"
K delete deployment --all -n default --wait=true >/dev/null 2>&1 || true
K delete pod --all -n default --wait=true >/dev/null 2>&1 || true
mkdir -p "$OUT"
# shellcheck disable=SC1091
source benchmark/single/scale-lib.sh
scale_bench "T-$ST-$FO" "$OUT" "${COMPOSE[@]}"
echo "scale-up results: $OUT/scale"

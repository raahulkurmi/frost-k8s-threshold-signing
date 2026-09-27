#!/usr/bin/env bash
# scale-rep.sh: ONE pod scale-up repetition on the Phase 7C control plane (run as
# root; NOTES N67). Same procedure as Phase 7A/7B (benchmark/single/scale-lib.sh):
# pause pods with one projected SA token each (automount off), scaled 0 -> SIZE.
# Cooldown first: delete the Deployment, wait until its pods are gone and this
# host's load1 < COOL_LOAD (max COOL_MAX s); the wait is recorded. Writes
# OUT/SYS-nSIZE-repREP.{json,audit.jsonl}; the operator adds the coordinators'
# log lines for [t_start, t_end] afterwards (.coord.jsonl).
#   scale-rep.sh OUT SYS SIZE REP DEPLOY.yaml [COOL_LOAD] [COOL_MAX]
set -euo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf
OUT="$1" SYS="$2" SIZE="$3" REP="$4" DEP="$5" COOL_LOAD="${6:-1.0}" COOL_MAX="${7:-300}"
mkdir -p "$OUT"; base="$OUT/$SYS-n$SIZE-rep$REP"
K() { kubectl "$@"; }
cpu_now() { awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5+$6, $9}' /proc/stat; }
AUDIT=/var/log/kubernetes/audit.log
[[ -f "$AUDIT" ]] || { echo "apiserver audit log missing" >&2; exit 1; }
# fit check on the schedulable nodes
nodes=$(K get nodes -o json | jq -r '.items[] | select(((.spec.taints // []) | map(.effect=="NoSchedule") | any) | not) | .metadata.name')
fit=$(K get nodes -o json | jq '[.items[] | select(((.spec.taints // []) | map(.effect=="NoSchedule") | any) | not) | .status.allocatable.pods | tonumber] | add')
used=$(K get pods -A -o json | jq --arg n "$nodes" '[.items[] | select(.status.phase!="Succeeded" and .status.phase!="Failed") | select(.spec.nodeName as $x | ($n | split("\n")) | index($x))] | length')
free=$((fit - used)); workers=$(wc -w <<<"$nodes")
if (( SIZE > free )); then
  jq -cn --arg s "$SYS" --argjson n "$SIZE" --arg why "only $free pods fit on $workers schedulable nodes ($fit allocatable, $used in use)" \
    '{system: $s, replicas: $n, skipped: true, reason: $why}' > "$OUT/$SYS-n$SIZE-skipped.json"
  echo "SKIPPED: $SIZE > $free"; exit 0
fi
# delete + re-create at 0, warm the pause image on every schedulable node (not
# measured), then the cooldown right before the measured scale-up
t0=$(date +%s)
K delete -f "$DEP" --wait=true >/dev/null 2>&1 || true
K wait --for=delete pod -l app=scale-pause --timeout=300s >/dev/null 2>&1 || true
K apply -f "$DEP" >/dev/null
K scale deploy/scale-pause --replicas="$workers" >/dev/null
K wait deploy/scale-pause --for=jsonpath='{.status.readyReplicas}'="$workers" --timeout=300s >/dev/null || true
K scale deploy/scale-pause --replicas=0 >/dev/null
K wait --for=delete pod -l app=scale-pause --timeout=300s >/dev/null 2>&1 || true
cool_ok=false
while :; do
  read -r l1 _ < /proc/loadavg
  awk -v l="$l1" -v t="$COOL_LOAD" 'BEGIN{exit !(l < t)}' && { cool_ok=true; break; }
  (( $(date +%s) - t0 >= COOL_MAX )) && break
  sleep 5
done
cool_s=$(( $(date +%s) - t0 )); cool_l1="$l1"
off=$(wc -l < "$AUDIT")
t_start=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
read -r c0 i0 s0 < <(cpu_now)
n0=$(date +%s%N)
K scale deploy/scale-pause --replicas="$SIZE" >/dev/null
ready=true
K wait deploy/scale-pause --for=jsonpath='{.status.readyReplicas}'="$SIZE" --timeout=900s >/dev/null || ready=false
n1=$(date +%s%N)
read -r c1 i1 s1 < <(cpu_now); read -r la1 la5 _ < /proc/loadavg
t_end=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
sleep 2
tail -n +$((off + 1)) "$AUDIT" > "$base.audit.jsonl"
nready=$(K get deploy scale-pause -o jsonpath='{.status.readyReplicas}'); nready=${nready:-0}
[[ $ready == true ]] || K get events --field-selector reason=FailedScheduling -o custom-columns=MSG:.message --no-headers 2>/dev/null | sort | uniq -c | head -3 > "$base.not-ready.txt"
jq -cn --arg s "$SYS" --argjson n "$SIZE" --argjson rep "$REP" --argjson ms $(( (n1 - n0) / 1000000 )) --argjson ok "$ready" --argjson nr "$nready" \
  --argjson busy "$(awk -v dt=$((c1-c0)) -v di=$((i1-i0)) 'BEGIN{printf "%.1f", 100*(1-di/dt)}')" \
  --argjson steal "$(awk -v dt=$((c1-c0)) -v ds=$((s1-s0)) 'BEGIN{printf "%.2f", 100*ds/dt}')" \
  --argjson l1 "$la1" --argjson l5 "$la5" --argjson cs "$cool_s" --argjson cl "$cool_l1" --argjson co "$cool_ok" \
  --arg ts "$t_start" --arg te "$t_end" --argjson w "$workers" \
  '{system: $s, replicas: $n, rep: $rep, ms_to_all_ready: $ms, all_ready: $ok, ready_replicas: $nr, cpu_busy_pct: $busy, cpu_steal_pct: $steal,
    load1: $l1, load5: $l5, cooldown_s: $cs, load1_at_start: $cl, cooldown_reached: $co, t_start: $ts, t_end: $te, schedulable_nodes: $w,
    cpu_host: "control plane"}' > "$base.json"
K scale deploy/scale-pause --replicas=0 >/dev/null
cat "$base.json"

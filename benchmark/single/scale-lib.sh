# scale-lib.sh: the pod scale-up benchmark, sourced by benchmark/single/run.sh
# (Phase 7A, on the single host) and benchmark/multihost/scale-remote.sh (Phase 7B,
# on the coordinator host against the multi-region signers).
# Needs from the caller: K (kubectl for the cluster), CP (control-plane container),
# die, cpu_now, audit_lines, SCALE_SIZES, SCALE_REPS; run from the repo root.

# scale_bench SYS OUTDIR [compose...]: pod scale-up benchmark on the current cluster.
scale_bench() {
  local sys="$1" out="$2/scale"; shift 2
  local -a comp=("$@")
  mkdir -p "$out"
  docker exec "$CP" test -f /var/log/kubernetes/audit.log || die "apiserver audit log missing"
  K apply -f benchmark/single/scale-deploy.yaml >/dev/null
  # warm-up (not measured): pull/start the pause image once on the worker
  K scale deploy/scale-pause --replicas=1 >/dev/null
  K wait deploy/scale-pause --for=jsonpath='{.status.readyReplicas}'=1 --timeout=300s >/dev/null
  K scale deploy/scale-pause --replicas=0 >/dev/null
  K wait --for=delete pod -l app=scale-pause --timeout=300s >/dev/null 2>&1 || true
  local nodes fit used
  nodes=$(K get nodes -o json | jq -r '.items[] | select(((.spec.taints // []) | map(.effect=="NoSchedule") | any) | not) | .metadata.name')
  fit=$(K get nodes -o json | jq '[.items[] | select(((.spec.taints // []) | map(.effect=="NoSchedule") | any) | not) | .status.allocatable.pods | tonumber] | add')
  used=$(K get pods -A -o json | jq --arg n "$nodes" '[.items[] | select(.status.phase!="Succeeded" and .status.phase!="Failed") | select(.spec.nodeName as $x | ($n | split("\n")) | index($x))] | length')
  local free=$((fit - used)) size rep
  echo "   scale: schedulable nodes [$(echo $nodes)], allocatable pods $fit, in use $used, free $free"
  for size in $SCALE_SIZES; do
    if [[ $size -gt $free ]]; then
      echo "{\"system\": \"$sys\", \"replicas\": $size, \"skipped\": true, \"reason\": \"only $free pods fit on the schedulable nodes ($fit allocatable, $used in use)\"}" > "$out/$sys-n$size-skipped.json"
      echo "   scale $sys n=$size: SKIPPED (only $free fit)"; continue
    fi
    for rep in $(seq 1 "$SCALE_REPS"); do
      local base="$out/$sys-n$size-rep$rep" off since t0 t1 c0 i0 s0 c1 i1 s1 ready=true l1 l5
      sleep 15   # idle before each repetition
      off=$(audit_lines); since=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
      read -r c0 i0 s0 < <(cpu_now)
      t0=$(date +%s%N)
      K scale deploy/scale-pause --replicas="$size" >/dev/null
      K wait deploy/scale-pause --for=jsonpath='{.status.readyReplicas}'="$size" --timeout=900s >/dev/null || ready=false
      t1=$(date +%s%N)
      read -r c1 i1 s1 < <(cpu_now); read -r l1 l5 _ < /proc/loadavg
      sleep 2   # let the last audit events and coordinator logs flush
      docker exec "$CP" sh -c "tail -n +$((off+1)) /var/log/kubernetes/audit.log" > "$base.audit.jsonl"
      if [[ ${#comp[@]} -gt 0 ]]; then
        "${comp[@]}" logs --no-color --no-log-prefix --since "$since" grpc-proxy-1 grpc-proxy-2 grpc-proxy-3 2>/dev/null | grep -E '"msg":"(signed|sign failed)"' > "$base.coord.jsonl" || true
      fi
      local nready; nready=$(K get deploy scale-pause -o jsonpath='{.status.readyReplicas}'); nready=${nready:-0}
      awk -v sys="$sys" -v n="$size" -v rep="$rep" -v dt="$(( (t1-t0)/1000000 ))" -v ok="$ready" -v nr="$nready" -v ct=$((c1-c0)) -v ci=$((i1-i0)) -v cs=$((s1-s0)) -v l1="$l1" -v l5="$l5" \
        'BEGIN{printf "{\"system\": \"%s\", \"replicas\": %d, \"rep\": %d, \"ms_to_all_ready\": %d, \"all_ready\": %s, \"ready_replicas\": %d, \"cpu_busy_pct\": %.1f, \"cpu_steal_pct\": %.2f, \"load1\": %s, \"load5\": %s}\n", sys, n, rep, dt, ok, nr, 100*(1-ci/ct), 100*cs/ct, l1, l5}' > "$base.json"
      echo "   scale $sys n=$size rep=$rep: $(cat "$base.json"); audit events $(wc -l < "$base.audit.jsonl")"
      [[ $ready == true ]] || K get events --field-selector reason=FailedScheduling -o custom-columns=MSG:.message --no-headers 2>/dev/null | sort | uniq -c | head -3 > "$base.not-ready.txt"
      K scale deploy/scale-pause --replicas=0 >/dev/null
      K wait --for=delete pod -l app=scale-pause --timeout=600s >/dev/null 2>&1 || true
    done
  done
  K delete -f benchmark/single/scale-deploy.yaml --wait=true >/dev/null
}

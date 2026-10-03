#!/usr/bin/env bash
# benchmark/k8s7c/run.sh PHASE: Phase 7C measurements, driven from the operator
# Mac over ssh (NOTES N67). Hosts: deploy/aws/state/7c/hosts.env.
#
#   RES=<dir> benchmark/k8s7c/run.sh tokens   RUNS full runs; in each, every system (order
#                                             rotated per run), c = CONCS, N after WARMUP
#   RES=<dir> benchmark/k8s7c/run.sh scale    pod scale-up interleaved: for each rep, every
#                                             system (rotated), sizes SIZES; cooldown per rep
#   RES=<dir> benchmark/k8s7c/run.sh lever|stress   lever check / stress test (N70)
#   RES=<dir> benchmark/k8s7c/run.sh eval-stress|eval-noregress|eval-slots|eval-storm
#                                             N76 evaluation (docs/PRIORITY_ADMISSION.md §5)
#   RES=<dir> benchmark/k8s7c/run.sh summary  regenerate summary.md from the raw files
# RES defaults to a new benchmark/results/<UTC>-<sha>-7C directory (reuse it for all phases).
#
# Before every system: use_system (switch + check.sh: signing mode, kid pinned to
# the expected key, TokenReview). Every configuration records the client CSV
# (tokenbench on the load generator), the coordinators' Sign lines and nginx's
# timing lines (B1/T; c1 breakdown, client vs coordinator), measured RTT to the
# signers (T), and CPU/load of the control plane, coordinator node and load
# generator. Network drops on the operator: any ssh/scp failure while a
# configuration or rep runs marks it INVALID (moved to invalid/, logged) and it
# is re-run once; only clean ones reach summary.md (NOTES N60).
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
# shellcheck disable=SC1091
source benchmark/k8s7c/lib.sh
PHASE="${1:?usage: run.sh tokens|scale|summary}"
RUNS="${RUNS:-3}" N="${N:-1000}" WARMUP="${WARMUP:-100}" CONCS="${CONCS:-1 10 20 50}"
SIZES="${SIZES:-50 100 200}" REPS="${REPS:-3}"
DEFAULT_SYSTEMS="B0 B1 T-5region-optimistic T-5region-strict"
[[ -f "$S7/topology-tsame.env" ]] && DEFAULT_SYSTEMS="$DEFAULT_SYSTEMS T-sameregion-optimistic T-sameregion-strict"
SYSTEMS="${SYSTEMS:-$DEFAULT_SYSTEMS}"
SHA="$(git rev-parse HEAD)"
RES="${RES:-benchmark/results/$(date -u +%Y%m%dT%H%M%SZ)-${SHA:0:7}-7C}"
mkdir -p "$RES"
EVENTS="$RES/invalid-events.jsonl"; touch "$EVENTS"
CHECKS="$RES/system-checks.jsonl"; touch "$CHECKS"
place() { _map_get "${HOST_PLACEMENT:-}" "$1" || echo unknown; }
LABEL_TEXT="${LABEL_TEXT:-7C: kubeadm v1.36.5 on AWS; control plane $(place cp), 2 workers ($(place w1), $(place w2)); coordinators (or B1) on a dedicated $(place coord); load generator $(place lg); nginx on the control plane}"

if [[ -z "${FROST_CAFFEINATED:-}" ]] && command -v caffeinate >/dev/null; then
  export FROST_CAFFEINATED=1; exec caffeinate -dims "$0" "$@"
fi
exec > >(tee -a "$RES/run-$PHASE.log") 2>&1
echo "LABEL: $LABEL_TEXT"; echo "phase $PHASE; commit $SHA; systems: $SYSTEMS; results $RES"
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || die "working tree has uncommitted changes"
[[ "$(con coord bash -c 'git -C ~/tk8s rev-parse HEAD')" == "$SHA" ]] || die "coordinator node clone is not at $SHA"

rotate() { # K WORDS...: rotate left by K
  local k="$1"; shift; local a=("$@") n=$# i out=""
  for ((i = 0; i < n; i++)); do out="$out ${a[$(((i + k) % n))]}"; done; echo "${out# }"
}
is_t() { [[ "$1" == T-* ]]; }
nginx_pod() { con cp bash -c "kubectl -n kube-system get pods -l app=frost-nginx -o jsonpath='{.items[0].metadata.name}'"; }

# ------------------------------------------------------------------- tokens
measure() { # SYS C RUN -> 0 iff clean
  local sys="$1" c="$2" run="$3" lab="$1-c$2" dir="$RES/run$3" rc since_c since_p b_cp b_co b_lg a_cp a_co a_lg l_cp l_co l_lg
  mkdir -p "$dir"
  since_c="$(con coord date -u +%Y-%m-%dT%H:%M:%S.%NZ)" || return 1
  since_p="$(con cp date +%s.%N)" || return 1
  local since_a; since_a="$(date -u +%Y-%m-%dT%H:%M:%S)"
  local scb="" sca=""
  if [[ -n "${SIGNER_CPU:-}" ]] && is_t "$sys"; then scb="$(mktemp)"; signer_cpu_snapshot "$sys" "$scb" || { echo "signer cpu snapshot failed" >> "$ERRF.events"; return 1; }; fi
  b_cp="$(cpu_sample cp)" && b_co="$(cpu_sample coord)" && b_lg="$(cpu_sample lg)" || return 1
  if is_t "$sys"; then
    local sec=secrets-t5; [[ "$sys" == T-sameregion-* ]] && sec=secrets-tsame
    local tg="" i=1 ep; for ep in $(t_endpoints $sec); do tg="$tg $i=$ep"; i=$((i + 1)); done
    con coord bash -c "nohup python3 /tmp/rtt_sampler.py /tmp/rtt.json $tg >/dev/null 2>&1 & echo \$! > /tmp/rtt.pid" || return 1
  fi
  if [[ -n "${SIGNER_SAMPLES:-}" ]] && is_t "$sys"; then   # N76 §6: 1 Hz signer CPU + cgroup throttling
    local sp sid; for sp in $(t_signer_hosts "$sys"); do sid="${sp%%:*}"
      cpipe "${sp#*:}" sudo bash -s -- start "$sid" < "$REPO/deploy/aws/7c/signer-sampler.sh" || return 1; done
  fi
  if [[ -n "${STORM:-}" ]]; then   # N77 storm: c = number of simulated pods, each retrying until issued
    rdetach lg tb "~/tokenbench -kubeconfig ~/.kube/config -storm-pods $c -storm-namespace storm -storm-sa-prefix pod- -storm-aggressive ${STORM_AGGRESSIVE:-0.2} -storm-giveup ${STORM_GIVEUP:-20m} -label $lab -out /tmp/$lab.csv -pods-out /tmp/$lab.pods.jsonl" || return 1
  else
    local ids=""; [[ -n "${IDENTITIES:-}" ]] && ids="-namespace storm -sa pod- -sa-count $IDENTITIES"
    rdetach lg tb "~/tokenbench -kubeconfig ~/.kube/config -n $N -warmup $WARMUP -c $c $ids -label $lab -out /tmp/$lab.csv" || return 1
  fi
  rc="$(rwait lg tb 3600)" || return 1
  [[ "$rc" == 0 ]] || { echo "tokenbench exit $rc: $(on lg tail -2 /tmp/tb.log 2>/dev/null | tr '\n' ' ')" >> "$ERRF.events"; return 1; }
  if is_t "$sys"; then
    con coord bash -c 'kill -TERM $(cat /tmp/rtt.pid); while kill -0 $(cat /tmp/rtt.pid) 2>/dev/null; do sleep 0.2; done' || return 1
    cpull coord /tmp/rtt.json "$dir/$lab.rtt.json" || return 1
  fi
  sleep 1
  if [[ "$sys" != B0* ]]; then
    local np; np="$(nginx_pod)" || return 1
    # all kubelet log files (current + rotated + gzipped), not `kubectl logs` (N70)
    con cp bash -c "sudo /usr/local/bin/frost-7c-nginx-lines $since_p | jq -c 'select(.uri | endswith(\"/Sign\"))'" > "$dir/$lab.nginx.jsonl" || return 1
  fi
  if is_t "$sys"; then
    con coord bash -c "for r in 1 2 3; do docker logs --since '$since_c' c7-grpc-proxy-\$r-1 2>&1; done | grep -E '\"msg\":\"(signed|sign failed)\"' || true" > "$dir/$lab.coord.jsonl" || return 1
  fi
  a_cp="$(cpu_sample cp)" && a_co="$(cpu_sample coord)" && a_lg="$(cpu_sample lg)" || return 1
  local sj='{}'
  if [[ -n "$scb" ]]; then
    sca="$(mktemp)"; signer_cpu_snapshot "$sys" "$sca" || { echo "signer cpu snapshot failed" >> "$ERRF.events"; return 1; }
    sj="$(signer_cpu_json "$scb" "$sca")"; rm -f "$scb" "$sca"
  fi
  if [[ -n "${SIGNER_SAMPLES:-}" ]] && is_t "$sys"; then
    local sp sid; for sp in $(t_signer_hosts "$sys"); do sid="${sp%%:*}"
      cpipe "${sp#*:}" sudo bash -s -- stop "$sid" < "$REPO/deploy/aws/7c/signer-sampler.sh" > "$dir/$lab.cpu-signer$sid.txt" || return 1
      # queue samples, admission-level windows and per-share RSA timing (journald, this configuration only)
      con "${sp#*:}" sudo journalctl -u "frost-signer-$sid" --since "@${since_p%.*}" -o cat --no-pager \
        | { grep -E '"msg":"(queue sample|admission level|sign-share)"' || true; } | gzip -9 > "$dir/$lab.signer$sid.log.jsonl.gz" || return 1
    done
  fi
  if [[ -n "${SIGNER_AUDIT:-}" ]] && is_t "$sys"; then   # stress test: shares computed / shed per signer
    local pair id h
    for pair in $(t_signer_hosts "$sys"); do
      id="${pair%%:*}" h="${pair#*:}"
      # audit lines start with {"ts":"<RFC3339>: compare the first 19 timestamp characters
      con "$h" sudo awk -v s="$since_a" 'substr($0, 8, 19) >= s' "/var/lib/frost-signer-$id/audit.log" | gzip -9 > "$dir/$lab.audit-signer$id.jsonl.gz" || return 1
    done
  fi
  l_cp="$(con cp cat /proc/loadavg)" && l_co="$(con coord cat /proc/loadavg)" && l_lg="$(con lg cat /proc/loadavg)" || return 1
  cpull lg "/tmp/$lab.csv" "$dir/$lab.csv" || return 1
  if [[ -n "${STORM:-}" ]]; then cpull lg "/tmp/$lab.pods.jsonl" "$dir/$lab.pods.jsonl" || return 1; fi
  con lg rm -f "/tmp/$lab.csv" "/tmp/$lab.pods.jsonl" || return 1
  jq -cn --arg lab "$lab" --argjson cp "$(cpu_json "$b_cp" "$a_cp" "$l_cp")" --argjson co "$(cpu_json "$b_co" "$a_co" "$l_co")" --argjson lg "$(cpu_json "$b_lg" "$a_lg" "$l_lg")" \
    --arg l5 "$(awk '{print $2}' <<<"$l_cp")" \
    '{label: $lab, cpu_busy_pct: $cp.cpu_busy_pct, cpu_steal_pct: $cp.cpu_steal_pct, load1: $cp.load1, load5: ($l5|tonumber), cpu_host: "control plane",
      control_plane: $cp, coordinator_node: $co, load_generator: $lg} + $sig' --argjson sig "$sj" > "$dir/$lab.metrics.json"
  ! cfg_failed
}
phase_tokens() {
  push coord benchmark/multihost/rtt_sampler.py /tmp/rtt_sampler.py
  local run sys c ok att
  for run in $(seq 1 "$RUNS"); do
    echo "================ token run $run/$RUNS ($(date -u +%T)) ================"
    source deploy/multihost/clock-check.sh
    # shellcheck disable=SC2086
    clock_check $ALL_HOSTS || die "clock check failed (N50)"
    # shellcheck disable=SC2086
    for sys in $(rotate $((run - 1)) $SYSTEMS); do
      use_system "$sys" /tmp/c7check.json; jq -c --argjson run "$run" --arg phase tokens '. + {run: $run, phase: $phase}' /tmp/c7check.json >> "$CHECKS"
      for c in $CONCS; do
        ok=0
        for att in 1 2; do
          cfg_begin
          if measure "$sys" "$c" "$run"; then ok=1; cfg_end; break; fi
          local d="$RES/run$run" l="$sys-c$c"
          mark_invalid "$EVENTS" config "run$run/$l" "$att" "$RES" "$d/$l.csv" "$d/$l.coord.jsonl" "$d/$l.nginx.jsonl" "$d/$l.rtt.json" "$d/$l.metrics.json"
          cfg_end; wait_net
          [[ $att == 1 ]] && { log "re-running run$run/$l once"; use_system "$sys" /tmp/c7check.json; }
        done
        if [[ $ok == 1 ]]; then
          echo "  run$run $sys c=$c: $(tail -n +2 "$RES/run$run/$sys-c$c.csv" | awk -F, '{n++; if($5!="1")e++} END{printf "%d rows, %d errors", n, e}'); cp busy $(jq -r .control_plane.cpu_busy_pct "$RES/run$run/$sys-c$c.metrics.json")%, coord busy $(jq -r .coordinator_node.cpu_busy_pct "$RES/run$run/$sys-c$c.metrics.json")%"
        else echo "  run$run $sys c=$c: INVALID twice; excluded"; fi
      done
    done
  done
}

# ------------------------------------------------------------------- scale
scale_rep() { # SYS SIZE REP -> 0 iff clean
  local sys="$1" size="$2" rep="$3" base="$1-n$2-rep$3" out="$RES/run1/scale" rc t0 l1
  mkdir -p "$out"
  # the coordinator node must be idle too (the control plane's own cooldown runs in scale-rep.sh)
  t0=$(date +%s)
  while :; do l1="$(con coord cat /proc/loadavg | awk '{print $1}')" || return 1
    awk -v l="$l1" 'BEGIN{exit !(l < 1.0)}' && break; (( $(date +%s) - t0 >= 300 )) && break; sleep 5; done
  con cp sudo rm -rf /tmp/c7scale || return 1
  rdetach cp sc "sudo /usr/local/bin/frost-7c-scale-rep /tmp/c7scale $sys $size $rep /etc/frost-7c/scale-deploy.yaml 1.0 300" || return 1
  rc="$(rwait cp sc 2400)" || return 1
  [[ "$rc" == 0 ]] || { echo "scale-rep exit $rc: $(on cp tail -3 /tmp/sc.log 2>/dev/null | tr '\n' ' ')" >> "$ERRF.events"; return 1; }
  con cp sudo tar -C /tmp/c7scale -czf /tmp/c7scale.tgz . || return 1
  con cp sudo chmod 644 /tmp/c7scale.tgz || return 1
  cpull cp /tmp/c7scale.tgz "$RES/c7scale.tgz" || return 1
  tar -C "$out" -xzf "$RES/c7scale.tgz"; rm -f "$RES/c7scale.tgz"
  if [[ -f "$out/$base.json" ]]; then
    jq --argjson cw "$(( $(date +%s) - t0 ))" '. + {coordinator_node_cooldown_s_before: $cw}' "$out/$base.json" > "$out/$base.json.tmp" && mv "$out/$base.json.tmp" "$out/$base.json"
    if is_t "$sys"; then
      local ts te; ts="$(jq -r .t_start "$out/$base.json")"; te="$(jq -r .t_end "$out/$base.json")"
      con coord bash -c "for r in 1 2 3; do docker logs --since '$ts' --until '$te' c7-grpc-proxy-\$r-1 2>&1; done | grep -E '\"msg\":\"(signed|sign failed)\"' || true" > "$out/$base.coord.jsonl" || return 1
    fi
  fi
  ! cfg_failed
}
phase_scale() {
  local rep sys size ok att
  for rep in $(seq 1 "$REPS"); do
    echo "================ scale rep $rep/$REPS ($(date -u +%T)) ================"
    source deploy/multihost/clock-check.sh
    # shellcheck disable=SC2086
    clock_check $ALL_HOSTS || die "clock check failed (N50)"
    # shellcheck disable=SC2086
    for sys in $(rotate $((rep - 1)) $SYSTEMS); do
      use_system "$sys" /tmp/c7check.json; jq -c --argjson rep "$rep" --arg phase scale '. + {rep: $rep, phase: $phase}' /tmp/c7check.json >> "$CHECKS"
      for size in $SIZES; do
        ok=0
        for att in 1 2; do
          cfg_begin
          if scale_rep "$sys" "$size" "$rep"; then ok=1; cfg_end; break; fi
          local o="$RES/run1/scale" b="$sys-n$size-rep$rep"
          mark_invalid "$EVENTS" scale-rep "$b" "$att" "$RES" "$o/$b.json" "$o/$b.audit.jsonl" "$o/$b.coord.jsonl"
          cfg_end; wait_net
          [[ $att == 1 ]] && { log "re-running scale $b once"; use_system "$sys" /tmp/c7check.json; }
        done
        if [[ $ok == 1 ]]; then echo "   $sys n=$size rep=$rep: $(jq -c '{ms_to_all_ready, all_ready, cooldown_s, load1_at_start, skipped, reason}' "$RES/run1/scale/$sys-n$size-rep$rep.json" 2>/dev/null || cat "$RES/run1/scale/$sys-n$size-skipped.json")"
        else echo "   $sys n=$size rep=$rep: INVALID twice; excluded"; fi
      done
    done
  done
}

# ------------------------------------------------------------------- lever check (N70)
# T-same-region optimistic at c=50, uncapped signers: fan-out all vs hedged, 3 runs,
# signer CPU sampled. Tests whether signer compute bounds throughput.
phase_lever() {
  push coord benchmark/multihost/rtt_sampler.py /tmp/rtt_sampler.py
  export SIGNER_CPU=1
  local run sys ok att
  for run in $(seq 1 "$RUNS"); do
    echo "================ lever check run $run/$RUNS ($(date -u +%T)) ================"
    source deploy/multihost/clock-check.sh
    # shellcheck disable=SC2086
    clock_check $ALL_HOSTS || die "clock check failed (N50)"
    # shellcheck disable=SC2046
    for sys in $(rotate $((run - 1)) T-sameregion-optimistic-all T-sameregion-optimistic-hedged); do
      use_system "$sys" /tmp/c7check.json; jq -c --argjson run "$run" --arg phase lever '. + {run: $run, phase: $phase}' /tmp/c7check.json >> "$CHECKS"
      ok=0
      for att in 1 2; do
        cfg_begin
        if measure "$sys" 50 "$run"; then ok=1; cfg_end; break; fi
        local d="$RES/run$run" l="$sys-c50"
        mark_invalid "$EVENTS" config "run$run/$l" "$att" "$RES" "$d/$l.csv" "$d/$l.coord.jsonl" "$d/$l.nginx.jsonl" "$d/$l.rtt.json" "$d/$l.metrics.json"
        cfg_end; wait_net
        [[ $att == 1 ]] && use_system "$sys" /tmp/c7check.json
      done
      [[ $ok == 1 ]] && echo "  run$run $sys c=50: $(tail -n +2 "$RES/run$run/$sys-c50.csv" | awk -F, '{n++; if($5!="1")e++} END{printf "%d rows, %d errors", n, e}'); signer CPU mean $(jq -r .signer_cpu_mean_pct "$RES/run$run/$sys-c50.metrics.json")% max $(jq -r .signer_cpu_max_pct "$RES/run$run/$sys-c50.metrics.json")%"
    done
  done
}

# ------------------------------------------------------------------- stress test (N70)
# STRESS TEST, not a realistic workload: T-same-region signers CPU-capped
# (systemd CPUQuota=STRESS_QUOTA) with SIGNER_MAX_CONCURRENT=1; T-same-region
# optimistic, fan-out all; c = STRESS_CONCS; 3 runs; signer CPU and signer audit
# logs (shares computed / shed) captured per configuration.
stress_caps() { # on|off
  local id
  if [[ "$1" == on ]]; then export STRESS_ACTIVE=1; else unset STRESS_ACTIVE; fi
  for id in 1 2 3 4 5; do
    if [[ "$1" == on ]]; then
      on "ts-$id" sudo bash -c "set -e; f=/etc/frost-signer-$id/env; sed -i '/^SIGNER_MAX_CONCURRENT=/d' \$f; echo SIGNER_MAX_CONCURRENT=1 >> \$f; systemctl restart frost-signer-$id; systemctl set-property --runtime frost-signer-$id CPUQuota=${STRESS_QUOTA:-25%}; sleep 1; systemctl is-active --quiet frost-signer-$id"
    else
      on "ts-$id" sudo bash -c "set -e; f=/etc/frost-signer-$id/env; sed -i '/^SIGNER_MAX_CONCURRENT=/d' \$f; systemctl set-property --runtime frost-signer-$id CPUQuota=; systemctl restart frost-signer-$id; sleep 1; systemctl is-active --quiet frost-signer-$id"
    fi
    echo "  ts-$id signer-$id: $(on "ts-$id" bash -c "systemctl show frost-signer-$id -p CPUQuotaPerSecUSec --value; sudo journalctl -u frost-signer-$id -o cat --no-pager | grep '\"signer ready\"' | tail -1 | jq -c '{max_concurrent, max_queue}'" | tr '\n' ' ')"
  done
}
phase_stress() {
  push coord benchmark/multihost/rtt_sampler.py /tmp/rtt_sampler.py
  export SIGNER_CPU=1 SIGNER_AUDIT=1
  local concs="${STRESS_CONCS:-10 25 50 100 150 200}" run c ok att sys=T-sameregion-optimistic
  echo "== STRESS TEST (CPU-capped signers, SIGNER_MAX_CONCURRENT=1): applying caps"
  stress_caps on
  for run in $(seq 1 "$RUNS"); do
    echo "================ stress run $run/$RUNS ($(date -u +%T)) ================"
    source deploy/multihost/clock-check.sh
    # shellcheck disable=SC2086
    clock_check $ALL_HOSTS || die "clock check failed (N50)"
    use_system "$sys" /tmp/c7check.json; jq -c --argjson run "$run" --arg phase stress '. + {run: $run, phase: $phase}' /tmp/c7check.json >> "$CHECKS"
    # shellcheck disable=SC2086
    for c in $(rotate $((run - 1)) $concs); do
      ok=0
      for att in 1 2; do
        cfg_begin
        if measure "$sys" "$c" "$run"; then ok=1; cfg_end; break; fi
        local d="$RES/run$run" l="$sys-c$c"
        mark_invalid "$EVENTS" config "run$run/$l" "$att" "$RES" "$d/$l.csv" "$d/$l.coord.jsonl" "$d/$l.nginx.jsonl" "$d/$l.rtt.json" "$d/$l.metrics.json" "$d"/"$l".audit-signer*.jsonl.gz
        cfg_end; wait_net
        [[ $att == 1 ]] && use_system "$sys" /tmp/c7check.json
      done
      [[ $ok == 1 ]] && echo "  run$run c=$c: $(tail -n +2 "$RES/run$run/$sys-c$c.csv" | awk -F, '{n++; if($5!="1")e++} END{printf "%d rows, %d errors", n, e}'); signer CPU mean $(jq -r .signer_cpu_mean_pct "$RES/run$run/$sys-c$c.metrics.json")% max $(jq -r .signer_cpu_max_pct "$RES/run$run/$sys-c$c.metrics.json")%"
    done
  done
  echo "== removing stress caps"
  stress_caps off
}

# ------------------------------------------------------------------- N76 evaluation
# docs/PRIORITY_ADMISSION.md §5, rules fixed there before any run. Variants are
# selected per system with @<variant> (lib.sh variant_cfg) and verified at every
# switch: coordinator quorum_abort, each signer's admission and max_concurrent.
# eval_loop SYSTEMS CONCS PHASE: per run, systems rotated; per system, c rotated.
eval_loop() {
  local systems="$1" concs="$2" ph="$3" run sys c ok att
  for run in $(seq 1 "$RUNS"); do
    echo "================ $ph run $run/$RUNS ($(date -u +%T)) ================"
    source deploy/multihost/clock-check.sh
    # shellcheck disable=SC2086
    clock_check $ALL_HOSTS || die "clock check failed (N50)"
    # shellcheck disable=SC2086
    for sys in $(rotate $((run - 1)) $systems); do
      use_system "$sys" /tmp/c7check.json; jq -c --argjson run "$run" --arg phase "$ph" '. + {run: $run, phase: $phase}' /tmp/c7check.json >> "$CHECKS"
      # shellcheck disable=SC2086
      for c in $(rotate $((run - 1)) $concs); do
        ok=0
        for att in 1 2; do
          cfg_begin
          if measure "$sys" "$c" "$run"; then ok=1; cfg_end; break; fi
          local d="$RES/run$run" l="$sys-c$c"
          mark_invalid "$EVENTS" config "run$run/$l" "$att" "$RES" "$d/$l.csv" "$d/$l.coord.jsonl" "$d/$l.nginx.jsonl" "$d/$l.rtt.json" "$d/$l.metrics.json" "$d"/"$l".audit-signer*.jsonl.gz "$d"/"$l".cpu-signer*.txt "$d"/"$l".signer*.log.jsonl.gz
          cfg_end; wait_net
          [[ $att == 1 ]] && use_system "$sys" /tmp/c7check.json
        done
        if [[ $ok == 1 ]]; then
          echo "  run$run $sys c=$c: $(tail -n +2 "$RES/run$run/$sys-c$c.csv" | awk -F, '{n++; if($5!="1")e++} END{printf "%d rows, %d errors", n, e}')$(is_t "$sys" && [[ -n "${SIGNER_CPU:-}" ]] && echo "; signer CPU mean $(jq -r .signer_cpu_mean_pct "$RES/run$run/$sys-c$c.metrics.json")%")"
        else echo "  run$run $sys c=$c: INVALID twice; excluded"; fi
      done
    done
  done
}
# §5.1 stress test before/after: today (n48) vs abort only (b) vs abort + priority (ab)
phase_eval_stress() {
  push coord benchmark/multihost/rtt_sampler.py /tmp/rtt_sampler.py
  export SIGNER_CPU=1 SIGNER_AUDIT=1 SIGNER_SAMPLES=1 QUEUE_SAMPLE="${QUEUE_SAMPLE:-100ms}" IDENTITIES="${IDENTITIES:-300}"
  storm_setup "$IDENTITIES" || die "service accounts for $IDENTITIES identities"   # request i -> pod-(i mod 300), every variant
  echo "== STRESS TEST (CPU-capped signers, SIGNER_MAX_CONCURRENT=1), N76/N77 before/after: applying caps"
  stress_caps on
  eval_loop "T-sameregion-optimistic@n48 T-sameregion-optimistic@b T-sameregion-optimistic@ab T-sameregion-optimistic@abs" "${STRESS_CONCS:-10 25 50 100 150 200}" eval-stress
  echo "== removing stress caps"
  stress_caps off
  unset QUEUE_SAMPLE; signer_config T-sameregion-optimistic n48 - >/dev/null
}
# §5.2 no regression: uncapped, n48 vs ab, both placements, B0 anchor
phase_eval_noregress() {
  push coord benchmark/multihost/rtt_sampler.py /tmp/rtt_sampler.py
  export SIGNER_AUDIT=1 IDENTITIES="${IDENTITIES:-300}"
  storm_setup "$IDENTITIES" || die "service accounts for $IDENTITIES identities"
  eval_loop "${NOREGRESS_SYSTEMS:-B0 T-sameregion-optimistic@n48 T-sameregion-optimistic@abs T-5region-optimistic@n48 T-5region-optimistic@abs}" "$CONCS" eval-noregress
  signer_config T-sameregion-optimistic n48 - >/dev/null
  [[ -f "$S7/topology-t5.env" ]] && signer_config T-5region-optimistic n48 - >/dev/null
}
# N77 storm (retry amplification): CPU-capped signers as in the stress test; STORM_PODS
# simulated pods start at once, one service account each (identity = sub), 20 %
# retrying every 250 ms, the rest with the kubelet's backoff; until issued or give-up.
storm_setup() { # B: namespace storm with service accounts pod-0 .. pod-<B-1>
  local b="$1" n
  { printf 'apiVersion: v1\nkind: Namespace\nmetadata: {name: storm}\n'
    for ((i = 0; i < b; i++)); do printf -- '---\napiVersion: v1\nkind: ServiceAccount\nmetadata: {name: pod-%d, namespace: storm}\n' "$i"; done
  } | cpipe cp kubectl apply -f - >/dev/null || return 1
  n="$(con cp bash -c "kubectl -n storm get sa --no-headers | grep -c '^pod-'")" || return 1
  echo "storm: $n of $b service accounts ready"; [[ "$n" -ge "$b" ]]
}
phase_eval_storm() {
  push coord benchmark/multihost/rtt_sampler.py /tmp/rtt_sampler.py
  export SIGNER_CPU=1 SIGNER_AUDIT=1 STORM=1
  local b="${STORM_PODS:-300}"
  storm_setup "$b" || die "storm setup failed"
  echo "== STORM (CPU-capped signers, SIGNER_MAX_CONCURRENT=1): applying caps"
  stress_caps on
  eval_loop "T-sameregion-optimistic@n48 T-sameregion-optimistic@b T-sameregion-optimistic@ab T-sameregion-optimistic@abs" "$b" eval-storm
  echo "== removing stress caps"
  stress_caps off
  signer_config T-sameregion-optimistic n48 - >/dev/null
}
# §5.3 inference test (admission slots): SIGNER_MAX_CONCURRENT 2/4/8, c=50, uncapped
phase_eval_slots() {
  push coord benchmark/multihost/rtt_sampler.py /tmp/rtt_sampler.py
  export SIGNER_CPU=1 SIGNER_SAMPLES=1
  eval_loop "T-sameregion-optimistic@slots2 T-sameregion-optimistic@slots4 T-sameregion-optimistic@slots8" 50 eval-slots
  signer_config T-sameregion-optimistic n48 - >/dev/null
}

# ------------------------------------------------------------------- env + summary
write_env() {
  local h hosts=""
  for h in $ALL_HOSTS; do hosts="$hosts$(jq -cn --arg h "$h" --arg p "$(place "$h")" --arg ip "$(vm_ip "$h")" --arg priv "$(vm_bind_ip "$h")" '{host: $h, placement: $p, public_ip: $ip, private_ip: $priv}'),"; done
  jq -n --arg label "$LABEL_TEXT" --arg sha "$SHA" --argjson hosts "[${hosts%,}]" --arg systems "$SYSTEMS" \
    --argjson runs "$RUNS" --argjson n "$N" --argjson w "$WARMUP" --arg concs "$CONCS" --arg sizes "$SIZES" --argjson reps "$REPS" \
    --arg k8s "$(on cp kubectl version -o json | jq -r .serverVersion.gitVersion)" \
    --arg nodes "$(on cp kubectl get nodes --no-headers | awk '{print $1":"$2":"$3}' | tr '\n' ' ')" \
    --slurpfile checks "$CHECKS" --slurpfile ev "$EVENTS" \
    --argjson per_config "$({ cat "$RES"/run*/*.metrics.json 2>/dev/null || true; } | jq -s .)" \
    --argjson scale "$({ cat "$RES"/run1/scale/*.json 2>/dev/null || true; } | jq -s .)" \
    '{label: $label, git_commit: $sha, hosts: $hosts, kubernetes: $k8s, nodes: $nodes, workers_for_benchmark_pods: 2,
      systems: $systems, runs: $runs, n: $n, warmup: $w, concurrency: $concs, scale_sizes: $sizes, scale_reps: $reps,
      fanout: "all", deadline: "2s", rsa_bits: 2048, t: 3, n_signers: 5,
      apiserver_audit: "TokenRequest only, Metadata level, identical for every system",
      rtt_method: "TCP connect to the signer port from the coordinator node (rtt_sampler.py), during each T configuration",
      system_checks: $checks, invalid_events: $ev, per_config: $per_config, scale_per_rep: $scale}' > "$RES/env.json"
}
phase_summary() {
  write_env
  local abs="$RES"; [[ "$abs" == /* ]] || abs="$REPO/$RES"
  ( cd benchmark && go run ./summarize -single "$abs" -title "Phase 7C: B0 vs B1 vs T (kubeadm v1.36.5, AWS)" \
      -note "LABEL: $LABEL_TEXT. $RUNS runs; N=$N after $WARMUP warm-up per configuration; fan-out all; commit ${SHA:0:7}." -out "$abs/summary.md" )
  sed -i '' "s#$REPO/##g" "$RES/summary.md" 2>/dev/null || sed -i "s#$REPO/##g" "$RES/summary.md"
  echo "summary: $RES/summary.md"
}

case "$PHASE" in
  tokens) phase_tokens; phase_summary;;
  lever) phase_lever; phase_summary;;
  eval-stress) phase_eval_stress; phase_summary;;
  eval-noregress) phase_eval_noregress; phase_summary;;
  eval-slots) phase_eval_slots; phase_summary;;
  eval-storm) phase_eval_storm; phase_summary;;
  stress) phase_stress; phase_summary;;
  scale) phase_scale; phase_summary;;
  summary) phase_summary;;
  *) die "unknown phase $PHASE";;
esac

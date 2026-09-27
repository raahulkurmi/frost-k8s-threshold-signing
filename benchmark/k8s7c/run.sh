#!/usr/bin/env bash
# benchmark/k8s7c/run.sh PHASE: Phase 7C measurements, driven from the operator
# Mac over ssh (NOTES N67). Hosts: deploy/aws/state/7c/hosts.env.
#
#   RES=<dir> benchmark/k8s7c/run.sh tokens   RUNS full runs; in each, every system (order
#                                             rotated per run), c = CONCS, N after WARMUP
#   RES=<dir> benchmark/k8s7c/run.sh scale    pod scale-up interleaved: for each rep, every
#                                             system (rotated), sizes SIZES; cooldown per rep
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
  since_p="$(con cp date -u +%Y-%m-%dT%H:%M:%S.%NZ)" || return 1
  b_cp="$(cpu_sample cp)" && b_co="$(cpu_sample coord)" && b_lg="$(cpu_sample lg)" || return 1
  if is_t "$sys"; then
    local sec=secrets-t5; [[ "$sys" == T-sameregion-* ]] && sec=secrets-tsame
    local tg="" i=1 ep; for ep in $(t_endpoints $sec); do tg="$tg $i=$ep"; i=$((i + 1)); done
    con coord bash -c "nohup python3 /tmp/rtt_sampler.py /tmp/rtt.json $tg >/dev/null 2>&1 & echo \$! > /tmp/rtt.pid" || return 1
  fi
  rdetach lg tb "~/tokenbench -kubeconfig ~/.kube/config -n $N -warmup $WARMUP -c $c -label $lab -out /tmp/$lab.csv" || return 1
  rc="$(rwait lg tb 3600)" || return 1
  [[ "$rc" == 0 ]] || { echo "tokenbench exit $rc: $(on lg tail -2 /tmp/tb.log 2>/dev/null | tr '\n' ' ')" >> "$ERRF.events"; return 1; }
  if is_t "$sys"; then
    con coord bash -c 'kill -TERM $(cat /tmp/rtt.pid); while kill -0 $(cat /tmp/rtt.pid) 2>/dev/null; do sleep 0.2; done' || return 1
    cpull coord /tmp/rtt.json "$dir/$lab.rtt.json" || return 1
  fi
  sleep 1
  if [[ "$sys" != B0* ]]; then
    local np; np="$(nginx_pod)" || return 1
    con cp bash -c "kubectl -n kube-system logs $np --since-time=$since_p | grep '\"src\":\"nginx\"' | jq -c 'select(.uri | endswith(\"/Sign\"))'" > "$dir/$lab.nginx.jsonl" || return 1
  fi
  if is_t "$sys"; then
    con coord bash -c "for r in 1 2 3; do docker logs --since '$since_c' c7-grpc-proxy-\$r-1 2>&1; done | grep -E '\"msg\":\"(signed|sign failed)\"' || true" > "$dir/$lab.coord.jsonl" || return 1
  fi
  a_cp="$(cpu_sample cp)" && a_co="$(cpu_sample coord)" && a_lg="$(cpu_sample lg)" || return 1
  l_cp="$(con cp cat /proc/loadavg)" && l_co="$(con coord cat /proc/loadavg)" && l_lg="$(con lg cat /proc/loadavg)" || return 1
  cpull lg "/tmp/$lab.csv" "$dir/$lab.csv" || return 1
  con lg rm -f "/tmp/$lab.csv" || return 1
  jq -cn --arg lab "$lab" --argjson cp "$(cpu_json "$b_cp" "$a_cp" "$l_cp")" --argjson co "$(cpu_json "$b_co" "$a_co" "$l_co")" --argjson lg "$(cpu_json "$b_lg" "$a_lg" "$l_lg")" \
    --arg l5 "$(awk '{print $2}' <<<"$l_cp")" \
    '{label: $lab, cpu_busy_pct: $cp.cpu_busy_pct, cpu_steal_pct: $cp.cpu_steal_pct, load1: $cp.load1, load5: ($l5|tonumber), cpu_host: "control plane",
      control_plane: $cp, coordinator_node: $co, load_generator: $lg}' > "$dir/$lab.metrics.json"
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
  scale) phase_scale; phase_summary;;
  summary) phase_summary;;
  *) die "unknown phase $PHASE";;
esac

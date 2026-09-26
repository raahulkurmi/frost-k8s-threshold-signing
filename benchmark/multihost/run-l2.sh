#!/usr/bin/env bash
# benchmark/multihost/run-l2.sh TOPOLOGY: Phase 7B Level 2 benchmark, run on the
# OPERATOR machine against a multihost deployment that is up
# (test/e2e/multihost.sh --keep TOPOLOGY). Portable to macOS bash 3.2.
#
# T 3-of-5, strategy strict AND optimistic, deadline 2 s, RSA-2048. Real WAN, no netem: one signer per
# AWS region. For every configuration the RTT from the coordinator host to each
# signer is MEASURED during the run (TCP connect to the signer port; no inbound
# ICMP is allowed) and the rows are labelled by the measured quorum RTT (the 3rd
# smallest RTT among running signers: a 3-of-5 quorum waits for the 3rd share).
#
# Scenarios: all5 (all signers up) and far-quorum (the TWO signers with the lowest
# measured RTT stopped, so the quorum needs the 3 far ones). Each: strategy strict
# and optimistic x fan-out all and hedged, concurrency 1/10/50, N after WARMUP
# warm-up. For every configuration the coordinators' "signed"/"sign failed" log
# lines are kept (<label>.coord.jsonl), so summary.md shows client-side and
# coordinator-side latency side by side (the difference is time outside the
# coordinator, mostly kube-apiserver queueing). Then the pod scale-up
# (SCALE_VARIANTS, default T optimistic-hedged and strict-all; 0 -> 50/100 pods,
# 3 reps, load-based cooldown before every rep) via scale-remote.sh on the
# coordinator host. Coordinator-host CPU busy/steal % and load per configuration
# go to <label>.metrics.json and env.json.
set -euo pipefail
cd "$(dirname "$0")/../.."
TOPO="${1:?usage: run-l2.sh TOPOLOGY.env}"
# shellcheck disable=SC1090
source "$TOPO"
# shellcheck disable=SC1091
source deploy/multihost/transport.sh
N="${N:-1000}" WARMUP="${WARMUP:-100}" CONCS="${CONCS:-1 10 50}" FANOUTS="${FANOUTS:-all hedged}"
HEDGE_DELAY="${HEDGE_DELAY:-50ms}" SCENARIOS="${SCENARIOS:-all5 far-quorum}" SCALE="${SCALE:-1}"
STRATEGIES="${STRATEGIES:-strict optimistic}" SCALE_VARIANTS="${SCALE_VARIANTS:-optimistic:hedged strict:all}"
SCALE_SIZES_L2="${SCALE_SIZES_L2:-50 100}" SCALE_REPS_L2="${SCALE_REPS_L2:-3}"
LABEL_TEXT="${LABEL_TEXT:-$TOPOLOGY_LABEL; real WAN, RTT measured per signer (TCP connect from the coordinator host), no netem}"

die() { echo "FATAL: $*" >&2; exit 1; }
id_vm()   { local s; for s in $SIGNERS; do [[ "${s%%:*}" == "$1" ]] && { s="${s#*:}"; echo "${s%%:*}"; return; }; done; }
id_port() { local s; for s in $SIGNERS; do [[ "${s%%:*}" == "$1" ]] && { echo "${s##*:}"; return; }; done; }
SIGNER_VMS="$(for s in $SIGNERS; do r="${s#*:}"; echo "${r%%:*}"; done | sort -u | tr '\n' ' ')"

# The operator drives every step over ssh: keep the Mac awake for the whole run.
if [[ -z "${FROST_CAFFEINATED:-}" ]] && command -v caffeinate >/dev/null; then
  export FROST_CAFFEINATED=1
  exec caffeinate -dims "$0" "$@"
fi

SHA="$(git rev-parse HEAD)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="benchmark/results/$TS-${SHA:0:7}-multihost-L2"
mkdir -p "$RES"
exec > >(tee "$RES/run.log") 2>&1
echo "LABEL: $LABEL_TEXT"
# shellcheck disable=SC1091
source deploy/multihost/clock-check.sh
# shellcheck disable=SC2086
clock_check "$COORD_VM" $SIGNER_VMS || die "clock skew check failed (N50)"
on "$COORD_VM" kubectl --context kind-tk8s get --raw /readyz >/dev/null || die "cluster not up: run test/e2e/multihost.sh --keep first"
[[ "$(on "$COORD_VM" bash -lc 'cd ~/tk8s && git rev-parse HEAD')" == "$SHA" ]] || die "coordinator host clone is not at $SHA"

echo "== build tokenbench on $COORD_VM (pinned toolchain)"
on "$COORD_VM" bash -lc "cd ~/tk8s/benchmark && PATH=/usr/local/go/bin:\$PATH GOTOOLCHAIN=go1.27.1 go build -o /tmp/tokenbench ./tokenbench && sha256sum /tmp/tokenbench"
push "$COORD_VM" benchmark/multihost/rtt_sampler.py /tmp/rtt_sampler.py
TOOLS="$(mktemp -d "${TMPDIR:-/tmp}/frost-bench-tools.XXXXXX")"
( cd benchmark && go build -o "$TOOLS/summarize" ./summarize )

TARGETS=""; for id in 1 2 3 4 5; do TARGETS="$TARGETS $id=$(vm_ip "$(id_vm "$id")"):$(id_port "$id")"; done
rtt_start() { on "$COORD_VM" bash -c "nohup python3 /tmp/rtt_sampler.py /tmp/rtt.json $TARGETS >/dev/null 2>&1 & echo \$! > /tmp/rtt.pid"; }
rtt_stop() { # dest
  on "$COORD_VM" bash -c 'kill -TERM $(cat /tmp/rtt.pid); while kill -0 $(cat /tmp/rtt.pid) 2>/dev/null; do sleep 0.2; done'
  pull "$COORD_VM" /tmp/rtt.json "$1"; jq . "$1" >/dev/null
}
cpu_now_remote() { on "$COORD_VM" awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5+$6, $9}' /proc/stat; }

set_variant() { # strict|optimistic all|hedged
  on "$COORD_VM" bash -lc "cd ~/tk8s && set -a && . secrets/multihost.env && set +a && FROST_UID=\$(id -u) FANOUT=$2 HEDGE_DELAY=$HEDGE_DELAY VERIFY_STRATEGY=$1 SIGN_DEADLINE=2s docker compose -p tk8s -f deploy/docker-compose.multihost.yml up -d --force-recreate grpc-proxy-1 grpc-proxy-2 grpc-proxy-3 >/dev/null 2>&1"
  local ok=0 r
  for _ in $(seq 1 60); do
    ok=0
    for r in 1 2 3; do
      on "$COORD_VM" docker logs "tk8s-grpc-proxy-$r-1" 2>&1 | grep '"coordinator ready"' | tail -1 | jq -e "select(.strategy==\"$1\" and .fanout==\"$2\")" >/dev/null && ok=$((ok + 1))
    done
    [[ $ok == 3 ]] && break
    sleep 1
  done
  [[ $ok == 3 ]] || die "coordinators did not all come up with strategy=$1 fanout=$2"
  for _ in $(seq 1 30); do on "$COORD_VM" kubectl --context kind-tk8s create token default --duration=10m >/dev/null 2>&1 && break; sleep 1; done
  echo "  coordinators: strategy=$1 fanout=$2 hedge_delay=$HEDGE_DELAY (verified in all 3 replica logs)"
}
coord_logs_since() { # since dest: the coordinators' signed / sign failed lines since <since>
  on "$COORD_VM" bash -c "for r in 1 2 3; do docker logs --since '$1' tk8s-grpc-proxy-\$r-1 2>&1; done | grep -E '\"msg\":\"(signed|sign failed)\"' || true" > "$2"
}
signers_ctl() { # start|stop id...
  local verb="$1" id; shift
  for id in "$@"; do
    on "$(id_vm "$id")" sudo systemctl "$verb" "frost-signer-$id"
    if [[ $verb == start ]]; then on "$(id_vm "$id")" systemctl is-active --quiet "frost-signer-$id" || die "signer $id did not start"; fi
    echo "  signer-$id: $verb"
  done
}

echo "== pre-run RTT (all signers up, 20 s)"
rtt_start; sleep 20; rtt_stop "$RES/rtt-pre.json"
jq -r '.[] | "  signer-\(.signer_id) \(.ip):\(.port) TCP-connect RTT median \(.rtt_ms) ms (min \(.rtt_min_ms), max \(.rtt_max_ms), \(.samples) samples)"' "$RES/rtt-pre.json"
NEAREST="$(jq -r '[.[] | select(.rtt_ms != null)] | sort_by(.rtt_ms) | .[0:2] | map(.signer_id) | join(" ")' "$RES/rtt-pre.json")"
echo "  two nearest signers (stopped in far-quorum): $NEAREST"

# --- env.json ---
place() { _map_get "${HOST_PLACEMENT:-}" "$1" || echo unknown; }
{
  echo "{"
  echo "  \"label\": \"$LABEL_TEXT\", \"git_commit\": \"$SHA\", \"date_utc\": \"$TS\","
  echo "  \"coordinator_host\": {\"placement\": \"$(place "$COORD_VM")\", \"ip\": \"$(vm_ip "$COORD_VM")\", \"cpu_model\": \"$(on "$COORD_VM" bash -c "lscpu | awk -F: '/Model name/{gsub(/^ +/,\"\",\$2); print \$2; exit}'")\", \"vcpus\": $(on "$COORD_VM" nproc), \"mem_mib\": $(on "$COORD_VM" bash -c "free -m | awk '/Mem/{print \$2}'"), \"kernel\": \"$(on "$COORD_VM" uname -r)\"},"
  echo "  \"signer_hosts\": ["
  first=1
  for id in 1 2 3 4 5; do
    vm="$(id_vm "$id")"
    [[ $first == 1 ]] || echo ","; first=0
    printf '    {"signer_id": %s, "host": "%s", "placement": "%s", "ip": "%s", "port": %s, "vcpus": %s, "mem_mib": %s, "max_concurrent": %s}' "$id" "$vm" "$(place "$vm")" "$(vm_ip "$vm")" "$(id_port "$id")" \
      "$(on "$vm" nproc)" "$(on "$vm" bash -c "free -m | awk '/Mem/{print \$2}'")" \
      "$(on "$vm" sudo journalctl -u "frost-signer-$id" -o cat --no-pager | grep '"signer ready"' | tail -1 | jq -r '.max_concurrent // "null"')"
  done
  echo; echo "  ],"
  echo "  \"kubernetes\": \"$(on "$COORD_VM" kubectl --context kind-tk8s version -o json | jq -r .serverVersion.gitVersion)\", \"t\": 3, \"n\": 5, \"rsa_bits\": 2048, \"deadline\": \"2s\","
  echo "  \"n_requests\": $N, \"warmup\": $WARMUP, \"concurrency\": \"$CONCS\", \"strategies\": \"$STRATEGIES\", \"fanouts\": \"$FANOUTS\", \"scale_variants\": \"$SCALE_VARIANTS\", \"hedge_delay\": \"$HEDGE_DELAY\", \"scenarios\": \"$SCENARIOS\", \"far_quorum_stopped_signers\": \"$NEAREST\","
  echo "  \"rtt_method\": \"TCP connect to the signer port from the coordinator host (no inbound ICMP allowed), sampled every 0.5 s during each configuration; netem: none\","
  echo "  \"client\": \"benchmark/tokenbench (client-go CreateToken, unthrottled) on the coordinator host\","
  echo "  \"rtt_pre_run\": $(cat "$RES/rtt-pre.json")"
  echo "}"
} > "$RES/env.json"
jq . "$RES/env.json" >/dev/null || die "env.json invalid"

# --- network-robust execution (NOTES N60) ---
# Remote work (tokenbench, each scale-up rep) runs DETACHED on the coordinator
# host, so an operator network drop cannot kill a measurement. Still, per the
# rule, ANY ssh/scp failure while a configuration or rep is in progress marks it
# INVALID: its files move to $RES/invalid/, the event (with the error) goes to
# $RES/invalid-events.jsonl, the run waits until every host is reachable again and
# re-runs it ONCE. Only configurations that completed without any failure are
# passed to summary.md.
EVENTS="$RES/invalid-events.jsonl"; : > "$EVENTS"
ERRF=""; CFG_ERR=""
# Failures are appended to "$ERRF.events" (a file, so failures inside $(...)
# subshells are not lost); a configuration is valid only if that file is empty.
_fail() { echo "$(date -u +%H:%M:%SZ) $1 rc=$2: $(tail -1 "$ERRF" 2>/dev/null | tr -d '\r"')" >> "$ERRF.events"; }
# L2_FAULT_ONCE=1 (TEST ONLY, off by default): the first con call inside a
# configuration fails once with a simulated ssh error, to exercise the INVALID path.
con()   {
  local rc=0
  if [[ "${L2_FAULT_ONCE:-}" == 1 && -n "$ERRF" && ! -e "$RES/.fault-injected" ]]; then
    touch "$RES/.fault-injected"; echo "ssh: connect to host (simulated): Network is unreachable [L2_FAULT_ONCE test hook]" >> "$ERRF"; _fail "on $1 ${2:-}" 255; return 255
  fi
  on "$@" 2>>"$ERRF" || rc=$?; [[ $rc -eq 0 ]] || _fail "on $1 ${2:-}" "$rc"; return $rc
}
cpull() { local rc=0; pull "$@" 2>>"$ERRF" || rc=$?; [[ $rc -eq 0 ]] || _fail "pull $2" "$rc"; return $rc; }
cfg_failed() { [[ -s "$ERRF.events" ]]; }
# rdetach NAME CMD: start CMD detached on the coordinator host (setsid nohup)
rdetach() { con "$COORD_VM" bash -c "rm -f /tmp/$1.rc; setsid nohup bash -c '$2; echo \$? > /tmp/$1.rc' > /tmp/$1.log 2>&1 < /dev/null &"; }
# rwait NAME MAXSEC: poll until the detached job wrote its exit code; poll
# failures are recorded (CFG_ERR) but polling continues until MAXSEC.
rwait() {
  local t0 rc; t0=$(date +%s)
  while :; do
    # the remote command always succeeds; only an ssh failure makes con fail
    rc="$(con "$COORD_VM" bash -c "cat /tmp/$1.rc 2>/dev/null; true")" && [[ -n "$rc" ]] && { echo "$rc"; return 0; }
    (( $(date +%s) - t0 > $2 )) && { echo timeout; return 1; }
    sleep 5
  done
}
wait_net() { # until the coordinator and every signer host answer (max 30 min)
  local t0 h ok; t0=$(date +%s)
  while :; do
    ok=1; for h in $COORD_VM $SIGNER_VMS; do on "$h" true >/dev/null 2>&1 || { ok=0; break; }; done
    [[ $ok == 1 ]] && { echo "  connectivity OK after $(( $(date +%s) - t0 )) s"; return 0; }
    (( $(date +%s) - t0 > 1800 )) && die "hosts unreachable for 30 min"
    sleep 10
  done
}
mark_invalid() { # kind name attempt files...
  local kind="$1" name="$2" att="$3"; shift 3
  local d="$RES/invalid/$name.attempt$att"; mkdir -p "$d"
  local f; for f in "$@"; do [[ -e "$f" ]] && mv "$f" "$d/"; done
  cp "$ERRF" "$d/errors.txt" 2>/dev/null || true
  CFG_ERR="$(tr '\n' ';' < "$ERRF.events" 2>/dev/null)"
  cp "$ERRF.events" "$d/events.txt" 2>/dev/null || true
  jq -cn --arg t "$(date -u +%FT%TZ)" --arg k "$kind" --arg n "$name" --arg a "$att" --arg e "$CFG_ERR" \
    '{time_utc: $t, kind: $k, name: $n, attempt: ($a|tonumber), error: $e}' >> "$EVENTS"
  echo "  INVALID ($kind $name, attempt $att): $CFG_ERR"
}

run_config() { # sc st f c -> 0 only if every step succeeded without any ssh/scp failure
  local sc="$1" st="$2" f="$3" c="$4" lab="T3of5-$2-$3-L0ms-c$4" dir="$RES/$1" cb ca load since rc
  cb="$(con "$COORD_VM" awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5+$6, $9}' /proc/stat)" || return 1
  since="$(con "$COORD_VM" date -u +%Y-%m-%dT%H:%M:%S.%NZ)" || return 1
  con "$COORD_VM" bash -c "nohup python3 /tmp/rtt_sampler.py /tmp/rtt.json $TARGETS >/dev/null 2>&1 & echo \$! > /tmp/rtt.pid" || return 1
  rdetach "tb" "/tmp/tokenbench -context kind-tk8s -n $N -warmup $WARMUP -c $c -label $lab -out /tmp/$lab.csv" || return 1
  rc="$(rwait tb 3600)" || return 1
  con "$COORD_VM" bash -c 'kill -TERM $(cat /tmp/rtt.pid); while kill -0 $(cat /tmp/rtt.pid) 2>/dev/null; do sleep 0.2; done' || return 1
  [[ "$rc" == 0 ]] || { echo "tokenbench exit $rc: $(on "$COORD_VM" tail -2 /tmp/tb.log 2>/dev/null | tr '\n' ' ')" >> "$ERRF.events"; return 1; }
  cpull "$COORD_VM" /tmp/rtt.json "$dir/$lab.rtt.json" || return 1
  sleep 1
  con "$COORD_VM" bash -c "for r in 1 2 3; do docker logs --since '$since' tk8s-grpc-proxy-\$r-1 2>&1; done | grep -E '\"msg\":\"(signed|sign failed)\"' || true" > "$dir/$lab.coord.jsonl" || return 1
  ca="$(con "$COORD_VM" awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5+$6, $9}' /proc/stat)" || return 1
  load="$(con "$COORD_VM" cat /proc/loadavg)" || return 1
  cpull "$COORD_VM" "/tmp/$lab.csv" "$dir/$lab.csv" || return 1
  con "$COORD_VM" rm -f "/tmp/$lab.csv" || return 1
  local t0 i0 s0 t1 i1 s1; read -r t0 i0 s0 <<<"$cb"; read -r t1 i1 s1 <<<"$ca"
  awk -v dt=$((t1-t0)) -v di=$((i1-i0)) -v ds=$((s1-s0)) -v la="$load" -v lab="$sc/$lab" \
    'BEGIN{split(la,L," "); printf "{\"label\": \"%s\", \"coordinator_cpu_busy_pct\": %.1f, \"coordinator_cpu_steal_pct\": %.2f, \"load1\": %s, \"load5\": %s}\n", lab, 100*(1-di/dt), 100*ds/dt, L[1], L[2]}' > "$dir/$lab.metrics.json"
  ! cfg_failed
}

CSVS=""; FINAL_INVALID=""
trap 'echo "== restoring all signers"; signers_ctl start 1 2 3 4 5 || true; rm -rf "$TOOLS"' EXIT
for sc in $SCENARIOS; do
  echo "================ scenario $sc ================"
  mkdir -p "$RES/$sc"
  if [[ $sc == far-quorum ]]; then
    # shellcheck disable=SC2086
    signers_ctl stop $NEAREST
  else
    signers_ctl start 1 2 3 4 5
  fi
  for st in $STRATEGIES; do for f in $FANOUTS; do
    set_variant "$st" "$f"
    for c in $CONCS; do
      lab="T3of5-${st}-${f}-L0ms-c${c}"
      ok=0
      for att in 1 2; do
        ERRF="$(mktemp "${TMPDIR:-/tmp}/l2err.XXXXXX")"; CFG_ERR=""
        if run_config "$sc" "$st" "$f" "$c"; then ok=1; rm -f "$ERRF" "$ERRF.events"; break; fi
        mark_invalid config "$sc/$lab" "$att" "$RES/$sc/$lab.csv" "$RES/$sc/$lab.rtt.json" "$RES/$sc/$lab.coord.jsonl" "$RES/$sc/$lab.metrics.json"
        rm -f "$ERRF" "$ERRF.events"
        wait_net
        if [[ $att == 1 ]]; then echo "  re-running $sc/$lab once"; set_variant "$st" "$f"; fi
      done
      if [[ $ok == 1 ]]; then
        echo "  $sc $lab: quorum RTT (3rd nearest running signer) $(jq -r '[.[].rtt_ms | select(. != null)] | sort | .[2]' "$RES/$sc/$lab.rtt.json") ms; coordinator log lines $(wc -l < "$RES/$sc/$lab.coord.jsonl" | tr -d ' '); $(cat "$RES/$sc/$lab.metrics.json")"
        CSVS="$CSVS $sc-$st-$f=$RES/$sc/$lab.csv"
      else
        FINAL_INVALID="$FINAL_INVALID $sc/$lab"; echo "  $sc/$lab: INVALID twice; excluded from summary.md"
      fi
    done
  done; done
done
signers_ctl start 1 2 3 4 5

if [[ $SCALE == 1 ]]; then
  con "$COORD_VM" rm -rf /tmp/l2scale || true
  mkdir -p "$RES/run1/scale"
  for v in $SCALE_VARIANTS; do
    sv="T-${v%%:*}-${v##*:}"
    echo "================ pod scale-up ($sv) ================"
    for size in $SCALE_SIZES_L2; do
      for rep in $(seq 1 "$SCALE_REPS_L2"); do
        ok=0
        for att in 1 2; do
          ERRF="$(mktemp "${TMPDIR:-/tmp}/l2err.XXXXXX")"; CFG_ERR=""
          con "$COORD_VM" rm -rf /tmp/l2rep || true
          if rdetach "sc" "cd ~/tk8s && SCALE_SIZES=$size SCALE_REPS=1 SCALE_REP_OFFSET=$((rep - 1)) benchmark/multihost/scale-remote.sh /tmp/l2rep ${v%%:*} ${v##*:}" \
             && rc="$(rwait sc 2400)" && [[ "$rc" == 0 ]] \
             && con "$COORD_VM" tar -C /tmp/l2rep/scale -czf /tmp/l2rep.tgz . \
             && cpull "$COORD_VM" /tmp/l2rep.tgz "$RES/l2rep.tgz" && ! cfg_failed; then
            tar -C "$RES/run1/scale" -xzf "$RES/l2rep.tgz"; rm -f "$RES/l2rep.tgz"
            echo "   $sv n=$size rep=$rep: $(cat "$RES/run1/scale/$sv-n$size-rep$rep.json" 2>/dev/null || cat "$RES/run1/scale/$sv-n$size-skipped.json")"
            ok=1; rm -f "$ERRF" "$ERRF.events"; break
          fi
          cfg_failed || echo "scale-remote exit ${rc:-?}: $(on "$COORD_VM" tail -3 /tmp/sc.log 2>/dev/null | tr '\n' ' ')" >> "$ERRF.events"
          mkdir -p "$RES/invalid/tmp"; cpull "$COORD_VM" /tmp/l2rep.tgz "$RES/invalid/tmp/partial.tgz" >/dev/null 2>&1 || true
          mark_invalid scale-rep "$sv-n$size-rep$rep" "$att" "$RES/l2rep.tgz" "$RES/invalid/tmp/partial.tgz"
          rm -f "$ERRF" "$ERRF.events"; wait_net
          [[ $att == 1 ]] && echo "  re-running scale-up $sv n=$size rep=$rep once"
        done
        [[ $ok == 1 ]] || { FINAL_INVALID="$FINAL_INVALID scale/$sv-n$size-rep$rep"; echo "  scale $sv n=$size rep=$rep: INVALID twice; excluded"; }
      done
    done
  done
  jq -s . "$RES"/run1/scale/*.json > "$RES/scale-per-rep.json"
  jq --slurpfile s "$RES/scale-per-rep.json" --arg sz "$SCALE_SIZES_L2" --arg nr "$SCALE_REPS_L2" '. + {scale_up: {sizes: $sz, reps: ($nr|tonumber), t_variants: "optimistic-hedged, strict-all", cooldown: "delete Deployment, wait pods gone and coordinator-host load1 < 1.0, max 300 s (recorded per rep)", per_rep: $s[0]}}' "$RES/env.json" > "$RES/env.json.tmp" && mv "$RES/env.json.tmp" "$RES/env.json"
fi
jq --slurpfile m <(cat "$RES"/*/*.metrics.json | jq -s .) --slurpfile ev <(jq -s . "$EVENTS") --arg fi "${FINAL_INVALID# }" \
  '. + {per_config: $m[0], invalid_events: $ev[0], excluded_after_two_invalid_attempts: $fi}' "$RES/env.json" > "$RES/env.json.tmp" && mv "$RES/env.json.tmp" "$RES/env.json"
echo "invalid events: $(wc -l < "$EVENTS" | tr -d ' '); excluded after two invalid attempts: [${FINAL_INVALID# }]"

# shellcheck disable=SC2086
"$TOOLS/summarize" -title "Phase 7B Level 2: T 3-of-5 across 5 AWS regions" \
  -note "LABEL: $LABEL_TEXT. Coordinator $(place "$COORD_VM"); signers: $(for id in 1 2 3 4 5; do printf '%s ' "$id=$(place "$(id_vm "$id")")"; done). Tags: <scenario>-<strategy>-<fanout>; far-quorum = signers $NEAREST (lowest measured RTT) stopped. Configured netem column is always 0 (no netem); rows are labelled by the MEASURED quorum RTT during the run." \
  -scale "$RES" -out "$RES/summary.md" $CSVS
echo "== results: $RES"
cat "$RES/summary.md"

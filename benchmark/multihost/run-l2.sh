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

CSVS=""
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
      read -r t0 i0 s0 < <(cpu_now_remote)
      since="$(on "$COORD_VM" date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
      rtt_start
      on "$COORD_VM" /tmp/tokenbench -context kind-tk8s -n "$N" -warmup "$WARMUP" -c "$c" -label "$lab" -out "/tmp/$lab.csv"
      rtt_stop "$RES/$sc/$lab.rtt.json"
      sleep 1; coord_logs_since "$since" "$RES/$sc/$lab.coord.jsonl"
      read -r t1 i1 s1 < <(cpu_now_remote)
      load="$(on "$COORD_VM" cat /proc/loadavg)"
      pull "$COORD_VM" "/tmp/$lab.csv" "$RES/$sc/$lab.csv"; on "$COORD_VM" rm -f "/tmp/$lab.csv"
      awk -v dt=$((t1-t0)) -v di=$((i1-i0)) -v ds=$((s1-s0)) -v la="$load" -v lab="$sc/$lab" \
        'BEGIN{split(la,L," "); printf "{\"label\": \"%s\", \"coordinator_cpu_busy_pct\": %.1f, \"coordinator_cpu_steal_pct\": %.2f, \"load1\": %s, \"load5\": %s}\n", lab, 100*(1-di/dt), 100*ds/dt, L[1], L[2]}' > "$RES/$sc/$lab.metrics.json"
      echo "  $sc $lab: quorum RTT (3rd nearest running signer) $(jq -r '[.[].rtt_ms | select(. != null)] | sort | .[2]' "$RES/$sc/$lab.rtt.json") ms; coordinator log lines $(wc -l < "$RES/$sc/$lab.coord.jsonl" | tr -d ' '); $(cat "$RES/$sc/$lab.metrics.json")"
      CSVS="$CSVS $sc-$st-$f=$RES/$sc/$lab.csv"
    done
  done; done
done
signers_ctl start 1 2 3 4 5

if [[ $SCALE == 1 ]]; then
  on "$COORD_VM" rm -rf /tmp/l2scale
  for v in $SCALE_VARIANTS; do
    echo "================ pod scale-up (T ${v%%:*}, fan-out ${v##*:}) ================"
    on "$COORD_VM" bash -lc "cd ~/tk8s && benchmark/multihost/scale-remote.sh /tmp/l2scale ${v%%:*} ${v##*:}"
  done
  on "$COORD_VM" tar -C /tmp/l2scale -czf /tmp/l2scale.tgz scale
  mkdir -p "$RES/run1"; pull "$COORD_VM" /tmp/l2scale.tgz "$RES/l2scale.tgz"; tar -C "$RES/run1" -xzf "$RES/l2scale.tgz"; rm -f "$RES/l2scale.tgz"
  jq -s . "$RES"/run1/scale/*.json > "$RES/scale-per-rep.json"
  jq --slurpfile s "$RES/scale-per-rep.json" '. + {scale_up: {sizes: "50 100", reps: 3, t_variants: "optimistic-hedged, strict-all", cooldown: "delete Deployment, wait pods gone and coordinator-host load1 < 1.0, max 300 s (recorded per rep)", per_rep: $s[0]}}' "$RES/env.json" > "$RES/env.json.tmp" && mv "$RES/env.json.tmp" "$RES/env.json"
fi
jq --slurpfile m <(cat "$RES"/*/*.metrics.json | jq -s .) '. + {per_config: $m[0]}' "$RES/env.json" > "$RES/env.json.tmp" && mv "$RES/env.json.tmp" "$RES/env.json"

# shellcheck disable=SC2086
"$TOOLS/summarize" -title "Phase 7B Level 2: T 3-of-5 across 5 AWS regions" \
  -note "LABEL: $LABEL_TEXT. Coordinator $(place "$COORD_VM"); signers: $(for id in 1 2 3 4 5; do printf '%s ' "$id=$(place "$(id_vm "$id")")"; done). Tags: <scenario>-<strategy>-<fanout>; far-quorum = signers $NEAREST (lowest measured RTT) stopped. Configured netem column is always 0 (no netem); rows are labelled by the MEASURED quorum RTT during the run." \
  -scale "$RES" -out "$RES/summary.md" $CSVS
echo "== results: $RES"
cat "$RES/summary.md"

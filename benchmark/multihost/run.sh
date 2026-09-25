#!/usr/bin/env bash
# benchmark/multihost/run.sh: Phase 7B Level 1 benchmark, run on the OPERATOR
# (the Mac). Portable to macOS bash 3.2. Requires the multi-host stack to be
# up: `test/e2e/multihost.sh --keep` (cluster + coordinators on tk8s, signers
# on sig-a/b/c).
#
# LABEL: preliminary: arm64, multi-VM on one overloaded 16 GB host; not for
# publication. Rows with added delay use tc netem and are EMULATED; the
# configured delay is a knob, results are labelled by MEASURED RTT (NOTES N45).
#
# Config: T 3-of-5, strict, deadline 2s. "2 signers near, 3 far": netem delay
# is added on the egress of the far hosts (sig-b: signers 3,4; sig-c: signer 5).
# A 3-of-5 quorum always needs at least one far signer.
# For each added delay L in 0/20/60/150 ms: measure real RTT (ping + TCP
# connect from the coordinator host to every signer port), then TokenRequest
# via client-go at concurrency 1/10/50, N=1000 after 100 warm-up.
set -euo pipefail
cd "$(dirname "$0")/../.."
TOPO="${TOPO:-deploy/multihost/topology.local.env}"
# shellcheck disable=SC1090
source "$TOPO"
export GOTOOLCHAIN=go1.27.1
N="${N:-1000}" WARMUP="${WARMUP:-100}"
DELAYS="${DELAYS:-0 20 60 150}"
CONCS="${CONCS:-1 10 50}"
FAR_VMS="${FAR_VMS:-sig-b sig-c}"
FANOUTS="${FANOUTS:-all hedged}"          # coordinator fan-out modes to compare (N46)
HEDGE_DELAY="${HEDGE_DELAY:-50ms}"
PRE_DIR="${PRE_DIR:-}"                     # optional pre-fix results dir to show side by side
SET_TAG="${SET_TAG:-post-N43-fix}"
LABEL_TEXT="preliminary: arm64, multi-VM on one overloaded 16 GB host; not for publication"
NEAR_VMS="${NEAR_VMS:-sig-a}"

die() { echo "FATAL: $*" >&2; exit 1; }
# Every remote call has a 300s alarm (macOS has no `timeout`): a hung
# `multipass exec` (e.g. across host sleep) becomes a visible failure.
alarm() { local s="$1"; shift; perl -e 'alarm shift; exec @ARGV' "$s" "$@"; }
# multipass 1.16.4's client hangs if its stdout/stderr is /dev/null and the
# remote command writes output (NOTES N42). Always hand it pipes; return its own
# exit code.
on() { local vm="$1"; shift; alarm 300 multipass exec "$vm" -- "$@" </dev/null 2> >(cat >&2) | cat; return "${PIPESTATUS[0]}"; }
id_vm()   { local s; for s in $SIGNERS; do [[ "${s%%:*}" == "$1" ]] && { s="${s#*:}"; echo "${s%%:*}"; return; }; done; }
id_port() { local s; for s in $SIGNERS; do [[ "${s%%:*}" == "$1" ]] && { echo "${s##*:}"; return; }; done; }
# VM IPs are resolved ONCE at start: `multipass info` failed mid-run when the
# host ran out of swap (N47), so the benchmark must not depend on it per call.
vm_ip_live() { multipass info "$1" --format json | jq -r --arg v "$1" '.info[$v].ipv4[0] // empty'; }
VM_IP_CACHE=""
for _vm in $COORD_VM sig-a sig-b sig-c; do VM_IP_CACHE="$VM_IP_CACHE $_vm=$(vm_ip_live "$_vm")"; done
vm_ip() { local p; for p in $VM_IP_CACHE; do [[ "${p%%=*}" == "$1" ]] && { echo "${p#*=}"; return; }; done; }
host_load() {
  local avail
  avail=$(vm_stat | awk -v ps="$(pagesize)" '/Pages free/{f=$NF}/Pages inactive/{i=$NF}/Pages speculative/{s=$NF}/Pages purgeable/{p=$NF} END{gsub("\\.","",f);gsub("\\.","",i);gsub("\\.","",s);gsub("\\.","",p); printf "%.2f", (f+i+s+p)*ps/2^30}')
  printf '{"loadavg": "%s", "mem_available_gib": %s, "swap": "%s", "power": "%s", "lid_closed": "%s"}' "$(sysctl -n vm.loadavg | tr -d '{}' | xargs)" "$avail" "$(sysctl -n vm.swapusage)" \
    "$(pmset -g batt | tr '\t\n' '  ' | sed 's/  */ /g; s/"//g' | cut -c1-120)" "$(ioreg -r -k AppleClamshellState -d 4 | awk -F'= ' '/AppleClamshellState/{print $2; exit}')"
}

# Host sleep freezes every VM and would put frozen time into latencies. Keep the
# host awake for the whole run and verify afterwards that it never slept.
if [[ -z "${FROST_CAFFEINATED:-}" ]]; then
  export FROST_CAFFEINATED=1
  exec caffeinate -dims "$0" "$@"
fi
BENCH_START_LOCAL="$(date '+%Y-%m-%d %H:%M:%S')"
signer_maxconc() { # JSON object signer_id -> MaxConcurrent from each signer's "signer ready" log
  local id vm v first=1
  printf '{'
  for id in 1 2 3 4 5; do
    vm="$(id_vm "$id")"
    v="$(on "$vm" sudo journalctl -u "frost-signer-$id" -o cat --no-pager | grep '"signer ready"' | tail -1 | jq -r '.max_concurrent // "null"' | tr -d '\r')"
    [[ $first == 1 ]] || printf ', '; first=0
    printf '"%s": %s' "$id" "${v:-null}"
  done
  printf '}'
}

SHA="$(git rev-parse HEAD)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="benchmark/results/$TS-${SHA:0:7}-multihost-L1"
mkdir -p "$RES"
exec > >(tee "$RES/run.log") 2>&1
echo "LABEL: $LABEL_TEXT; netem rows emulated; labelled by measured RTT"
on "$COORD_VM" kubectl --context kind-tk8s get --raw /readyz >/dev/null || die "cluster not up: run test/e2e/multihost.sh --keep first"
on "$COORD_VM" bash -lc "cd ~/tk8s && git rev-parse HEAD" | tr -d '\r' | grep -qx "$SHA" || die "coordinator host clone is not at $SHA"

echo "== build tokenbench on $COORD_VM (pinned toolchain)"
on "$COORD_VM" bash -lc "cd ~/tk8s/benchmark && GOTOOLCHAIN=go1.27.1 go build -o /tmp/tokenbench ./tokenbench && sha256sum /tmp/tokenbench"
TOOLS="$(mktemp -d "${TMPDIR:-/tmp}/frost-bench-tools.XXXXXX")"   # never inside the results dir
( cd benchmark && go build -o "$TOOLS/summarize" ./summarize )

# --- env.json ---
COORD_IP="$(vm_ip "$COORD_VM")"
vm_json() { local vm="$1"; printf '{"vm": "%s", "ip": "%s", "vcpus": %s, "mem_mb": %s, "kernel": "%s"}' "$vm" "$(vm_ip "$vm")" \
  "$(on "$vm" nproc | tr -d '\r')" "$(on "$vm" free -m | awk '/Mem/{print $2}' | tr -d '\r')" "$(on "$vm" uname -r | tr -d '\r')"; }
{
  echo "{"
  echo "  \"label\": \"$LABEL_TEXT; netem rows emulated; labelled by measured RTT (N45)\","
  echo "  \"git_commit\": \"$SHA\", \"date_utc\": \"$TS\","
  echo "  \"host\": {\"model\": \"$(sysctl -n hw.model)\", \"cpu\": \"$(sysctl -n machdep.cpu.brand_string)\", \"ncpu\": $(sysctl -n hw.ncpu), \"mem_gib\": $(( $(sysctl -n hw.memsize) / 1073741824 )), \"os\": \"$(sw_vers -productName) $(sw_vers -productVersion)\", \"hypervisor\": \"$(multipass version | head -1)\", \"load_at_start\": $(host_load)},"
  echo "  \"vms\": [$(vm_json "$COORD_VM"), $(vm_json sig-a), $(vm_json sig-b), $(vm_json sig-c)],"
  echo "  \"kubernetes\": \"$(on "$COORD_VM" kubectl --context kind-tk8s version -o json | jq -r .serverVersion.gitVersion)\", \"docker\": \"$(on "$COORD_VM" docker version --format '{{.Server.Version}}' | tr -d '\r')\","
  echo "  \"go\": \"$(go version | cut -d' ' -f3)\", \"rsa_bits\": 2048, \"t\": 3, \"n\": 5, \"deadline\": \"2s\", \"verify_strategy\": \"strict\","
  echo "  \"signers\": \"$SIGNERS\", \"near_vms\": \"$NEAR_VMS\", \"far_vms\": \"$FAR_VMS\", \"configured_netem_delays_ms\": \"$DELAYS\", \"concurrency\": \"$CONCS\", \"n\": $N, \"warmup\": $WARMUP,"
  echo "  \"fanouts\": \"$FANOUTS\", \"hedge_delay\": \"$HEDGE_DELAY\", \"set_tag\": \"$SET_TAG\", \"signer_max_concurrent\": $(signer_maxconc),"
  echo "  \"netem\": \"tc qdisc replace dev <if> root netem delay <L>ms on the egress of each far VM (L=0: no qdisc)\","
  echo "  \"client\": \"benchmark/tokenbench (client-go v0.36.5 CreateToken, QPS/Burst unthrottled) on $COORD_VM\""
  echo "}"
} > "$RES/env.json"
jq . "$RES/env.json" >/dev/null


# set_fanout MODE: restart the 3 coordinators with FANOUT=MODE and verify from
# their logs that every replica runs it.
set_fanout() {
  on "$COORD_VM" bash -lc "cd ~/tk8s && set -a && . secrets/multihost.env && set +a && FROST_UID=\$(id -u) FANOUT=$1 HEDGE_DELAY=$HEDGE_DELAY VERIFY_STRATEGY=strict SIGN_DEADLINE=2s docker compose -p tk8s -f deploy/docker-compose.multihost.yml up -d --force-recreate grpc-proxy-1 grpc-proxy-2 grpc-proxy-3 >/dev/null 2>&1"
  local ok=0 r
  for _ in $(seq 1 60); do
    ok=0
    for r in 1 2 3; do
      on "$COORD_VM" docker logs "tk8s-grpc-proxy-$r-1" 2>&1 | grep '"coordinator ready"' | tail -1 | grep -q "\"fanout\":\"$1\"" && ok=$((ok + 1))
    done
    [[ $ok == 3 ]] && break
    sleep 1
  done
  [[ $ok == 3 ]] || die "coordinators did not all come up with fanout=$1"
  for _ in $(seq 1 30); do on "$COORD_VM" kubectl --context kind-tk8s create token default --duration=10m >/dev/null 2>&1 && break; sleep 1; done
  echo "  coordinators: fanout=$1 hedge_delay=$HEDGE_DELAY (verified in all 3 replica logs)"
}

# ping_start / ping_stop LABEL: measure RTT from the coordinator host to every
# signer host DURING a configuration; writes <label>.rtt.json (N45).
PING_IPS=""
ping_start() {
  local id ip
  PING_IPS="$(for id in 1 2 3 4 5; do vm_ip "$(id_vm "$id")"; done | sort -u | tr '\n' ' ')"
  for ip in $PING_IPS; do
    on "$COORD_VM" bash -c "rm -f /tmp/rtt-$ip.txt; nohup ping -i 0.5 $ip > /tmp/rtt-$ip.txt 2>&1 & echo \$! > /tmp/rtt-$ip.pid"
  done
}
ping_stop() { # label
  local out="$RES/$1.rtt.json" first=1 id vm ip avg n
  for ip in $PING_IPS; do on "$COORD_VM" bash -c "kill -INT \$(cat /tmp/rtt-$ip.pid) 2>/dev/null; sleep 0.3"; done
  echo "[" > "$out"
  for id in 1 2 3 4 5; do
    vm="$(id_vm "$id")"; ip="$(vm_ip "$vm")"
    avg="$(on "$COORD_VM" cat "/tmp/rtt-$ip.txt" | awk -F/ '/rtt/{print $5}' | tr -d '\r')"
    n="$(on "$COORD_VM" cat "/tmp/rtt-$ip.txt" | awk '/packets transmitted/{print $4}' | tr -d '\r')"
    [[ $first == 1 ]] || echo "," >> "$out"; first=0
    printf '  {"signer_id": %s, "vm": "%s", "ip": "%s", "rtt_ms": %s, "samples": %s, "measured": "ICMP avg during run"}' "$id" "$vm" "$ip" "${avg:-null}" "${n:-0}" >> "$out"
  done
  echo "" >> "$out"; echo "]" >> "$out"
  jq . "$out" >/dev/null
}

set_delay() { # L
  local vm dev
  for vm in $FAR_VMS; do
    dev="$(on "$vm" ip -o -4 route show default | awk '{print $5}' | tr -d '\r')"
    if [[ "$1" == 0 ]]; then on "$vm" sudo tc qdisc del dev "$dev" root >/dev/null 2>&1 || true
    else on "$vm" sudo tc qdisc replace dev "$dev" root netem delay "${1}ms"; fi
    echo "  $vm $dev: $(on "$vm" tc qdisc show dev "$dev" | head -1 | tr -d '\r')"
  done
}
cleanup() { echo "== removing netem"; set_delay 0 || true; rm -rf "${TOOLS:-/nonexistent}"; }
trap cleanup EXIT

measure_rtt() { # L -> rtt-L<L>.json
  local out="$RES/rtt-L$1ms.json" first=1 id vm ip p ping_avg tcp
  echo "[" > "$out"
  for id in 1 2 3 4 5; do
    vm="$(id_vm "$id")"; ip="$(vm_ip "$vm")"; p="$(id_port "$id")"
    ping_avg="$(on "$COORD_VM" ping -q -c 20 -i 0.2 "$ip" | awk -F'/' '/rtt/{print $5}' | tr -d '\r')"
    tcp="$(on "$COORD_VM" python3 -c "
import socket,time,statistics
xs=[]
for _ in range(20):
    s=socket.socket(); t=time.perf_counter(); s.connect(('$ip',$p)); xs.append((time.perf_counter()-t)*1000); s.close(); time.sleep(0.05)
print('%.3f %.3f %.3f'%(statistics.median(xs),min(xs),max(xs)))" | tr -d '\r')"
    [[ $first == 1 ]] || echo "," >> "$out"; first=0
    printf '  {"signer_id": %s, "vm": "%s", "ip": "%s", "port": %s, "added_delay_ms": %s, "ping_avg_ms": %s, "tcp_connect_median_ms": %s, "tcp_connect_min_ms": %s, "tcp_connect_max_ms": %s}' \
      "$id" "$vm" "$ip" "$p" "$1" "${ping_avg:-null}" $(echo $tcp) >> "$out"
    echo "  signer-$id $vm $ip:$p  ping avg ${ping_avg}ms  tcp connect median/min/max $(echo $tcp | tr ' ' '/') ms"
  done
  echo "" >> "$out"; echo "]" >> "$out"
  jq . "$out" >/dev/null
}

CSVS=""
for L in $DELAYS; do
  echo "== configured netem delay on far hosts: ${L}ms $( [[ $L != 0 ]] && echo '(EMULATED, tc netem; measured RTT recorded per config)')"
  set_delay "$L"
  measure_rtt "$L"
  for f in $FANOUTS; do
    set_fanout "$f"
    for c in $CONCS; do
      lab="T3of5-strict-${f}-L${L}ms-c${c}"
      if [[ "$L" != 0 ]]; then lab="$lab-emulated"; fi
      printf '{"config": "%s", "phase": "before", "host": %s}\n' "$lab" "$(host_load)" >> "$RES/host-load.jsonl"
      echo "  -> $lab  host before: $(host_load)"
      ping_start
      on "$COORD_VM" /tmp/tokenbench -context kind-tk8s -n "$N" -warmup "$WARMUP" -c "$c" -label "$lab" -out "/tmp/$lab.csv"
      ping_stop "$lab"
      multipass transfer "$COORD_VM:/tmp/$lab.csv" "$RES/$lab.csv"
      on "$COORD_VM" rm -f "/tmp/$lab.csv"
      printf '{"config": "%s", "phase": "after", "host": %s}\n' "$lab" "$(host_load)" >> "$RES/host-load.jsonl"
      echo "     host after:  $(host_load); quorum RTT during run (3rd-nearest signer): $(jq -r '[.[].rtt_ms] | sort | .[2]' "$RES/$lab.rtt.json") ms"
      CSVS="$CSVS $SET_TAG-$f=$RES/$lab.csv"
    done
  done
done
if [[ -n "$PRE_DIR" ]]; then
  for pf in "$PRE_DIR"/*.csv; do CSVS="pre-N43-fix=$pf $CSVS"; done
fi

# Did the host sleep during the run? (pmset log lines are "YYYY-MM-DD HH:MM:SS +zone Sleep ...")
SLEEPS="$(pmset -g log | awk -v s="$BENCH_START_LOCAL" '($1" "$2) >= s && $4 == "Sleep" {print $1" "$2}' | tr '\n' ' ')"
if [[ -n "$SLEEPS" ]]; then SLEPT=true; else SLEPT=false; fi
jq --argjson slept "$SLEPT" --arg when "$SLEEPS" --arg start "$BENCH_START_LOCAL" --arg end "$(date '+%Y-%m-%d %H:%M:%S')" \
  '. + {host_slept_during_run: $slept, host_sleep_events: $when, bench_window_local: ($start + " .. " + $end), host_awake_mechanism: "caffeinate -dims for the whole run"}' \
  "$RES/env.json" > "$RES/env.json.tmp" && mv "$RES/env.json.tmp" "$RES/env.json"
SLEEPNOTE="Host sleep during run: $SLEPT (checked from pmset -g log for $BENCH_START_LOCAL onwards). Host power at start: $(jq -r .host.load_at_start.power "$RES/env.json")."
[[ "$SLEPT" == true ]] && SLEEPNOTE="INVALID RUN: the host slept at $SLEEPS; latencies include frozen VM time. $SLEEPNOTE"
# shellcheck disable=SC2086
"$TOOLS/summarize" -title "Phase 7B Level 1: T 3-of-5 multi-VM, pre- vs post-N43-fix" \
  -note "LABEL: $LABEL_TEXT. Multi-VM on ONE physical host (Multipass on a Mac). Netem delay is EMULATED on the far hosts sig-b (signers 3,4) and sig-c (signer 5); sig-a (signers 1,2) is near; rows are labelled by MEASURED quorum RTT (N45). Strategy strict, deadline 2s, RSA-2048; post-fix rows compare fan-out all vs hedged (hedge delay $HEDGE_DELAY), with signer cancellation checks and admission control (N46). Pre-fix rows (tag pre-N43-fix) are from $PRE_DIR, unchanged. Environment, host free RAM/swap before+after every config: env.json, host-load.jsonl. $SLEEPNOTE" \
  -out "$RES/summary.md" $CSVS
echo "== results: $RES"
cat "$RES/summary.md"

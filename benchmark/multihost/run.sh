#!/usr/bin/env bash
# benchmark/multihost/run.sh: Phase 7B Level 1 benchmark, run on the OPERATOR
# (the Mac). Portable to macOS bash 3.2. Requires the multi-host stack to be
# up: `test/e2e/multihost.sh --keep` (cluster + coordinators on tk8s, signers
# on sig-a/b/c).
#
# LABEL: preliminary, arm64, multi-VM single physical host. Rows with added
# delay use tc netem and are EMULATED WAN latency, not real networks.
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
vm_ip()   { multipass info "$1" --format json | jq -r --arg v "$1" '.info[$v].ipv4[0] // empty'; }
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
SHA="$(git rev-parse HEAD)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="benchmark/results/$TS-${SHA:0:7}-multihost-L1"
mkdir -p "$RES"
exec > >(tee "$RES/run.log") 2>&1
echo "LABEL: preliminary, arm64, multi-VM single physical host; netem rows are emulated"
on "$COORD_VM" kubectl --context kind-tk8s get --raw /readyz >/dev/null || die "cluster not up: run test/e2e/multihost.sh --keep first"
on "$COORD_VM" bash -lc "cd ~/tk8s && git rev-parse HEAD" | tr -d '\r' | grep -qx "$SHA" || die "coordinator host clone is not at $SHA"

echo "== build tokenbench on $COORD_VM (pinned toolchain)"
on "$COORD_VM" bash -lc "cd ~/tk8s/benchmark && GOTOOLCHAIN=go1.27.1 go build -o /tmp/tokenbench ./tokenbench && sha256sum /tmp/tokenbench"
( cd benchmark && go build -o "$OLDPWD/$RES/.summarize" ./summarize )

# --- env.json ---
COORD_IP="$(vm_ip "$COORD_VM")"
vm_json() { local vm="$1"; printf '{"vm": "%s", "ip": "%s", "vcpus": %s, "mem_mb": %s, "kernel": "%s"}' "$vm" "$(vm_ip "$vm")" \
  "$(on "$vm" nproc | tr -d '\r')" "$(on "$vm" free -m | awk '/Mem/{print $2}' | tr -d '\r')" "$(on "$vm" uname -r | tr -d '\r')"; }
{
  echo "{"
  echo "  \"label\": \"preliminary, arm64, multi-VM single physical host; netem rows emulated; not for publication\","
  echo "  \"git_commit\": \"$SHA\", \"date_utc\": \"$TS\","
  echo "  \"host\": {\"model\": \"$(sysctl -n hw.model)\", \"cpu\": \"$(sysctl -n machdep.cpu.brand_string)\", \"ncpu\": $(sysctl -n hw.ncpu), \"mem_gib\": $(( $(sysctl -n hw.memsize) / 1073741824 )), \"os\": \"$(sw_vers -productName) $(sw_vers -productVersion)\", \"hypervisor\": \"$(multipass version | head -1)\", \"load_at_start\": $(host_load)},"
  echo "  \"vms\": [$(vm_json "$COORD_VM"), $(vm_json sig-a), $(vm_json sig-b), $(vm_json sig-c)],"
  echo "  \"kubernetes\": \"$(on "$COORD_VM" kubectl --context kind-tk8s version -o json | jq -r .serverVersion.gitVersion)\", \"docker\": \"$(on "$COORD_VM" docker version --format '{{.Server.Version}}' | tr -d '\r')\","
  echo "  \"go\": \"$(go version | cut -d' ' -f3)\", \"rsa_bits\": 2048, \"t\": 3, \"n\": 5, \"deadline\": \"2s\", \"verify_strategy\": \"strict\","
  echo "  \"signers\": \"$SIGNERS\", \"near_vms\": \"$NEAR_VMS\", \"far_vms\": \"$FAR_VMS\", \"added_delays_ms\": \"$DELAYS\", \"concurrency\": \"$CONCS\", \"n\": $N, \"warmup\": $WARMUP,"
  echo "  \"netem\": \"tc qdisc replace dev <if> root netem delay <L>ms on the egress of each far VM (L=0: no qdisc)\","
  echo "  \"client\": \"benchmark/tokenbench (client-go v0.36.5 CreateToken, QPS/Burst unthrottled) on $COORD_VM\""
  echo "}"
} > "$RES/env.json"
jq . "$RES/env.json" >/dev/null

set_delay() { # L
  local vm dev
  for vm in $FAR_VMS; do
    dev="$(on "$vm" ip -o -4 route show default | awk '{print $5}' | tr -d '\r')"
    if [[ "$1" == 0 ]]; then on "$vm" sudo tc qdisc del dev "$dev" root >/dev/null 2>&1 || true
    else on "$vm" sudo tc qdisc replace dev "$dev" root netem delay "${1}ms"; fi
    echo "  $vm $dev: $(on "$vm" tc qdisc show dev "$dev" | head -1 | tr -d '\r')"
  done
}
cleanup() { echo "== removing netem"; set_delay 0 || true; }
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
  echo "== added delay on far hosts: ${L}ms $( [[ $L != 0 ]] && echo '(EMULATED, tc netem)')"
  set_delay "$L"
  measure_rtt "$L"
  for c in $CONCS; do
    lab="T3of5-strict-L${L}ms-c${c}$( [[ $L != 0 ]] && echo '-emulated')"
    echo "  -> $lab  host load before: $(host_load)"
    on "$COORD_VM" /tmp/tokenbench -context kind-tk8s -n "$N" -warmup "$WARMUP" -c "$c" -label "$lab" -out "/tmp/$lab.csv"
    multipass transfer "$COORD_VM:/tmp/$lab.csv" "$RES/$lab.csv"
    on "$COORD_VM" rm -f "/tmp/$lab.csv"
    echo "     host load after:  $(host_load)"
    printf '{"config": "%s", "host_load_after": %s}\n' "$lab" "$(host_load)" >> "$RES/host-load.jsonl"
    CSVS="$CSVS $RES/$lab.csv"
  done
done

# Did the host sleep during the run? (pmset log lines are "YYYY-MM-DD HH:MM:SS +zone Sleep ...")
SLEEPS="$(pmset -g log | awk -v s="$BENCH_START_LOCAL" '($1" "$2) >= s && $4 == "Sleep" {print $1" "$2}' | tr '\n' ' ')"
if [[ -n "$SLEEPS" ]]; then SLEPT=true; else SLEPT=false; fi
jq --argjson slept "$SLEPT" --arg when "$SLEEPS" --arg start "$BENCH_START_LOCAL" --arg end "$(date '+%Y-%m-%d %H:%M:%S')" \
  '. + {host_slept_during_run: $slept, host_sleep_events: $when, bench_window_local: ($start + " .. " + $end), host_awake_mechanism: "caffeinate -dims for the whole run"}' \
  "$RES/env.json" > "$RES/env.json.tmp" && mv "$RES/env.json.tmp" "$RES/env.json"
SLEEPNOTE="Host sleep during run: $SLEPT (checked from pmset -g log for $BENCH_START_LOCAL onwards). Host power at start: $(jq -r .host.load_at_start.power "$RES/env.json")."
[[ "$SLEPT" == true ]] && SLEEPNOTE="INVALID RUN: the host slept at $SLEEPS; latencies include frozen VM time. $SLEEPNOTE"
# shellcheck disable=SC2086
"$RES/.summarize" -title "Phase 7B Level 1: T 3-of-5 multi-VM (preliminary)" \
  -note "PRELIMINARY, arm64, multi-VM SINGLE PHYSICAL HOST (Multipass on one Mac); not for publication. Rows with L>0ms add EMULATED latency (tc netem) on the far hosts sig-b (signers 3,4) and sig-c (signer 5); sig-a (signers 1,2) is near. Strategy strict, deadline 2s, RSA-2048. Measured RTT per setting: rtt-L*.json. Environment and host load: env.json, host-load.jsonl. $SLEEPNOTE" \
  -out "$RES/summary.md" $CSVS
rm -f "$RES/.summarize"
echo "== results: $RES"
cat "$RES/summary.md"

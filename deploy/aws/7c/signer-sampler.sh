#!/usr/bin/env bash
# signer-sampler.sh start|stop ID (run as root on a signer host; NOTES N76 §6)
# start: every second append "unix_ns cpu_usage_ns nr_throttled throttled_usec"
#        (systemd CPUUsageNSec and the unit's cgroup v2 cpu.stat) to /tmp/cpus-ID.txt
# stop:  stop the sampler and print the file
set -euo pipefail
cmd="$1" id="$2" out="/tmp/cpus-$2.txt" pid="/tmp/cpus-$2.pid"
cg="/sys/fs/cgroup/system.slice/frost-signer-$id.service/cpu.stat"
case "$cmd" in
  start)
    [[ -f "$pid" ]] && kill "$(cat "$pid")" 2>/dev/null || true
    : > "$out"
    nohup bash -c "while :; do echo \"\$(date +%s%N) \$(systemctl show frost-signer-$id -p CPUUsageNSec --value) \$(awk '/^nr_throttled/{a=\$2} /^throttled_usec/{b=\$2} END{print a+0, b+0}' $cg 2>/dev/null || echo 0 0)\"; sleep 1; done" >> "$out" 2>/dev/null < /dev/null &
    echo $! > "$pid" ;;
  stop)
    [[ -f "$pid" ]] && kill "$(cat "$pid")" 2>/dev/null || true
    rm -f "$pid"; sleep 0.2; cat "$out"; rm -f "$out" ;;
  *) echo "usage: $0 start|stop ID" >&2; exit 2 ;;
esac

#!/usr/bin/env bash
# clock-check.sh: MANDATORY pre-run step for every multihost script (N44/N50).
# Forces a time resync on each host (chrony: `chronyc makestep`, as on EC2 Ubuntu,
# which syncs to the Amazon Time Sync Service; otherwise restart
# systemd-timesyncd, as on the Multipass VMs), waits for sync,
# then checks each host's clock and FAILS if its skew exceeds MAX_SKEW_MS
# (default 1000).
# PRIMARY value, where chrony runs (EC2): the host's own offset from its NTP source,
# `chronyc tracking` "System time" (and "Last offset", recorded). The operator's
# network does not affect it. SECONDARY (always recorded; primary only on hosts
# without chrony, e.g. the Multipass VMs with systemd-timesyncd): host time −
# midpoint of the operator's before/after timestamps. This round-trip method
# inflates skew when the operator's network is slow (seen: +704 ms at a 1.4 s round
# trip, NOTES N60), so on chrony hosts it never fails the check.
# Uses the topology's transport (deploy/multihost/transport.sh; multipass by
# default). Portable to macOS bash 3.2. Usage: [TOPO=topology.env] clock-check.sh VM [VM ...]
# Can also be sourced: defines clock_check VM...
set -uo pipefail

_ck_now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000'; }
if ! declare -f on >/dev/null; then
  # standalone: load the topology (if given) and its transport
  # shellcheck disable=SC1090
  [[ -n "${TOPO:-}" ]] && source "$TOPO"
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/transport.sh"
fi
_ck_on() { on "$@"; }

clock_check() {
  local max="${MAX_SKEW_MS:-1000}" vm bad=0 t0 t1 rv mid skew rtt tries synced
  for vm in "$@"; do
    _ck_on "$vm" sudo bash -c 'if systemctl is-active --quiet chrony; then chronyc -a makestep >/dev/null; else systemctl restart systemd-timesyncd; fi' \
      || { echo "clock-check: $vm: cannot force a time resync (chrony/systemd-timesyncd)" >&2; bad=1; continue; }
    synced=""
    for _ in $(seq 1 30); do
      synced="$(_ck_on "$vm" timedatectl show -p NTPSynchronized --value | tr -d '\r')"
      [[ "$synced" == yes ]] && break
      sleep 1
    done
  done
  sleep 2 # let a step settle
  for vm in "$@"; do
    tries=0
    while :; do
      tries=$((tries + 1))
      t0="$(_ck_now_ms)"
      rv="$(_ck_on "$vm" date +%s%3N | tr -d '\r')"
      t1="$(_ck_now_ms)"
      rtt=$((t1 - t0))
      [[ "$rtt" -le 2000 || "$tries" -ge 3 ]] && break
    done
    mid=$(( (t0 + t1) / 2 ))
    skew=$(( rv - mid ))
    synced="$(_ck_on "$vm" timedatectl show -p NTPSynchronized --value | tr -d '\r')"
    # chrony: "System time : 0.000012345 seconds slow of NTP time" (slow = behind)
    local trk sys_ms last_ms
    trk="$(_ck_on "$vm" bash -c 'command -v chronyc >/dev/null && systemctl is-active --quiet chrony && chronyc tracking' 2>/dev/null | tr -d '\r' || true)"
    sys_ms="$(awk -F: '/^System time/{split($2,a," "); v=a[1]*1000; if ($2 ~ /slow/) v=-v; printf "%.3f", v}' <<<"$trk")"
    last_ms="$(awk -F: '/^Last offset/{split($2,a," "); printf "%.3f", a[1]*1000}' <<<"$trk")"
    if [[ -n "$sys_ms" ]]; then
      printf 'clock-check: %-6s chrony offset %+9s ms (last offset %s ms) [primary]; round-trip skew %+6d ms (exec round trip %d ms) [secondary]; NTPSynchronized=%s\n' "$vm" "$sys_ms" "$last_ms" "$skew" "$rtt" "$synced"
      if awk -v v="$sys_ms" -v m="$max" 'BEGIN{exit !((v<0?-v:v) > m)}'; then echo "clock-check: FAIL: $vm chrony offset ${sys_ms} ms exceeds ${max} ms" >&2; bad=1; fi
    else
      printf 'clock-check: %-6s skew %+6d ms (exec round trip %d ms, NTPSynchronized=%s) [primary: no chrony on this host]\n' "$vm" "$skew" "$rtt" "$synced"
      if [[ ${skew#-} -gt $max ]]; then echo "clock-check: FAIL: $vm skew ${skew} ms exceeds ${max} ms" >&2; bad=1; fi
    fi
  done
  return $bad
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  [[ $# -ge 1 ]] || { echo "usage: $0 VM [VM ...]" >&2; exit 2; }
  clock_check "$@" || { echo "clock-check: FAILED; not continuing (N44: a signer with a skewed clock refuses every token)" >&2; exit 1; }
  echo "clock-check: all VMs within ${MAX_SKEW_MS:-1000} ms of the operator clock"
fi

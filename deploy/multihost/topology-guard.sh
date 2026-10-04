# shellcheck shell=bash
# topology_guard COORD_VM THRESHOLD "SIGNERS": refuse a share placement that
# defeats the threshold (audit E-2). SIGNERS is "id:host:port ...". Rules:
#   - each signer id 1..5 is listed exactly once;
#   - the coordinator host holds no share;
#   - no host holds more than THRESHOLD-1 shares: a host holding THRESHOLD
#     shares could sign alone, so one host compromise would be a forgery.
# The Level 1 topology (2+2+1 with t = 3) satisfies this; no exception exists.
# Portable to macOS bash 3.2 (N42). Prints the reason and returns 1 on refusal.
topology_guard() {
  local coord=$1 t=$2 signers=$3 id n s r vm hosts count
  [[ "$t" =~ ^[0-9]+$ ]] && [[ $t -ge 2 ]] || { echo "threshold '$t' is not an integer >= 2"; return 1; }
  for id in 1 2 3 4 5; do
    n=0
    for s in $signers; do [[ "${s%%:*}" == "$id" ]] && n=$((n + 1)); done
    [[ $n -eq 1 ]] || { echo "signer $id must be listed exactly once (found $n)"; return 1; }
  done
  hosts="$(for s in $signers; do r="${s#*:}"; echo "${r%%:*}"; done | sort -u)"
  for vm in $hosts; do
    [[ "$vm" != "$coord" ]] || { echo "the coordinator host $coord must not hold any share"; return 1; }
    count=0
    for s in $signers; do r="${s#*:}"; [[ "${r%%:*}" == "$vm" ]] && count=$((count + 1)); done
    if [[ $count -gt $((t - 1)) ]]; then
      echo "host $vm would hold $count shares; at most t-1 = $((t - 1)) (a host with t shares can sign alone)"
      return 1
    fi
  done
  return 0
}

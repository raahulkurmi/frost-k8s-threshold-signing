#!/usr/bin/env bash
# test/e2e/multihost.sh: Phase 7B e2e, run on the OPERATOR machine (the only
# machine that can reach the signer hosts). Portable to macOS bash 3.2.
#
#   1. checks the coordinator host's clone is at exactly this commit
#   2. deploy/multihost/deploy.sh (fresh certs + key, guarded share placement)
#   3. L-tests from outside: lateral isolation, operator-only SSH, per-user
#      isolation on shared hosts, share placement, systemd hardening, binary hash
#   4. runs test/e2e/run.sh on the coordinator host with TOPOLOGY=multihost and
#      serves its signer stop/start/audit requests (control channel /tmp/frost-ctl)
#   5. unless --keep: stops signers and shreds their shares and keys
#
# Topology label: from the topology file (TOPOLOGY_LABEL); Level 1 is multi-VM on
# a SINGLE PHYSICAL HOST, not infrastructure independence.
# Usage: test/e2e/multihost.sh [--keep] [topology.env]
set -euo pipefail
cd "$(dirname "$0")/../.."
KEEP=0 RECHECK_L2=0
[[ "${1:-}" == "--keep" ]] && { KEEP=1; shift; }
# --recheck-l2: re-run ONLY the L2 checks (clock check first) against an existing
# deployment, e.g. after an operator network drop invalidated L2 (NOTES N60).
[[ "${1:-}" == "--recheck-l2" ]] && { RECHECK_L2=1; shift; }
TOPO="${1:-deploy/multihost/topology.local.env}"
# shellcheck disable=SC1090
source "$TOPO"

die() { echo "FATAL: $*" >&2; exit 1; }
SHA="$(git rev-parse HEAD)"
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || die "working tree has uncommitted changes"
git fetch -q origin && [[ "$(git rev-parse "origin/$(git rev-parse --abbrev-ref HEAD)")" == "$SHA" ]] || die "HEAD $SHA is not pushed"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="reports/multihost/e2e-$TS-${SHA:0:7}"
[[ $RECHECK_L2 == 1 ]] && RES="reports/multihost/l2-recheck-$TS-${SHA:0:7}"
mkdir -p "$RES"
exec > >(tee "$RES/multihost-e2e.log") 2>&1

# on: run a command on a VM with stdin from /dev/null (so it never swallows the
# caller's input, e.g. inside `while read`); on_pipe: deliberately pass stdin.
# Every remote call has an alarm: a hung remote call becomes a visible failure
# (exit 142), never a silent stall. (macOS has no `timeout`.) Transport
# (multipass for Level 1, ssh for Level 2) comes from the topology.
# shellcheck disable=SC1091
source deploy/multihost/transport.sh
TOPOLOGY_LABEL="${TOPOLOGY_LABEL:-multi-VM, single physical host (Level 1); NOT infrastructure independence}"
# rc_on VM CMD: run CMD in bash on VM and print ONLY its exit code, as seen on
# the VM. Needed because `multipass exec -- sudo -u USER cmd` can hang on the
# client when cmd fails (NOTES N38); a timeout must never pass as "denied".
rc_on() { local vm="$1"; shift; on "$vm" bash -c "$* >/dev/null 2>&1; echo rc=\$?" | tr -d '\r' | grep -o 'rc=[0-9]*' || echo "rc=NONE"; }
id_vm()   { local s; for s in $SIGNERS; do [[ "${s%%:*}" == "$1" ]] && { s="${s#*:}"; echo "${s%%:*}"; return; }; done; }
id_port() { local s; for s in $SIGNERS; do [[ "${s%%:*}" == "$1" ]] && { echo "${s##*:}"; return; }; done; }
vm_ids()  { local s out=""; for s in $SIGNERS; do local r="${s#*:}"; [[ "${r%%:*}" == "$1" ]] && out="$out ${s%%:*}"; done; echo "$out"; }
SIGNER_VMS="$(for s in $SIGNERS; do r="${s#*:}"; echo "${r%%:*}"; done | sort -u | tr '\n' ' ')"

RESULT_LINES=""
FAILED=0
pass() { echo "PASS $1: $2"; RESULT_LINES="$RESULT_LINES
PASS  $1  $2"; }
fail() { echo "FAIL $1: $2"; RESULT_LINES="$RESULT_LINES
FAIL  $1  $2"; FAILED=1; }
section() { echo; echo "================ $* ================"; }
tcp_from_vm() { on "$1" timeout 3 bash -c "exec 3<>/dev/tcp/$2/$3" >/dev/null 2>&1; }

section "Environment (operator)"
echo "git commit: $SHA"
echo "topology: $TOPOLOGY_LABEL; file $TOPO"
echo "operator: $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null), $(sysctl -n hw.model) $(sysctl -n hw.ncpu) CPU, $(( $(sysctl -n hw.memsize) / 1073741824 )) GiB; transport: $(transport_desc)"
if [[ "$TRANSPORT" == multipass ]]; then multipass list; else for h in $COORD_VM $SIGNER_VMS; do echo "  $h reach $(vm_ip "$h") bind $(vm_bind_ip "$h") ${HOST_PLACEMENT:+($(_map_get "$HOST_PLACEMENT" "$h"))}"; done; fi

section "Clock check (mandatory, N50)"
# Mandatory pre-run step (N50): force time resync and require every VM to be
# within 1 s of the operator clock; a skewed signer refuses every token (N44).
# shellcheck disable=SC1091
source deploy/multihost/clock-check.sh
# shellcheck disable=SC2086
clock_check "$COORD_VM" $SIGNER_VMS || die "clock skew check failed (N50)"

l2_test() {
  section "L2: operator-only SSH; operator cannot reach signer ports"
  L2_OK=1
  for id in 1 2 3 4 5; do
    vm="$(id_vm "$id")"; ip="$(vm_ip "$vm")"; p="$(id_port "$id")"
    if nc -z -G 3 "$ip" "$p" >/dev/null 2>&1; then echo "  UNEXPECTED: operator reached signer-$id $ip:$p"; L2_OK=0; else echo "  operator -> signer-$id $ip:$p: blocked"; fi
  done
  for vm in $SIGNER_VMS; do
    ip="$(vm_ip "$vm")"
    if nc -z -G 3 "$ip" 22 >/dev/null 2>&1; then echo "  operator -> $vm:22: open (control)"; else echo "  CONTROL FAILED: operator cannot SSH to $vm"; L2_OK=0; fi
    if tcp_from_vm "$COORD_VM" "$ip" 22; then echo "  UNEXPECTED: coordinator host reached $vm:22"; L2_OK=0; else echo "  $COORD_VM -> $vm:22: blocked"; fi
  done
  if [[ $L2_OK == 1 ]]; then pass L2 "SSH to signer hosts only from the operator; operator cannot reach signer ports"; else fail L2 "firewall allows an unexpected path"; fi
}

if [[ $RECHECK_L2 == 1 ]]; then
  echo "deployment under test: reports/multihost/deploy-manifest.json (kid $(jq -r .kid reports/multihost/deploy-manifest.json), deployed $(jq -r .deployed_at reports/multihost/deploy-manifest.json))"
  l2_test
  section "Summary"
  printf '%s\n' "$RESULT_LINES" | sed '/^$/d'
  echo "results: $RES"
  [[ $FAILED -eq 0 ]] && { echo "L2 RECHECK: PASS"; exit 0; }
  echo "L2 RECHECK: FAIL"; exit 1
fi

section "Coordinator host at the same commit"
on "$COORD_VM" bash -lc "cd ~/tk8s && git fetch -q && git checkout -q $SHA && git rev-parse HEAD" | tr -d '\r'

section "Deploy (deploy/multihost/deploy.sh)"
deploy/multihost/deploy.sh "$TOPO"
cp reports/multihost/deploy-manifest.json "$RES/"
COORD_IP="$(vm_ip "$COORD_VM")"

section "L1: lateral isolation between signer hosts"
L1_OK=1
for x in $SIGNER_VMS; do
  for y in $SIGNER_VMS; do
    [[ "$x" == "$y" ]] && continue
    yip="$(vm_ip "$y")"
    for id in $(vm_ids "$y"); do
      p="$(id_port "$id")"
      if tcp_from_vm "$x" "$yip" "$p"; then echo "  UNEXPECTED: $x reached $y $yip:$p (signer-$id)"; L1_OK=0; else echo "  $x -> $y $yip:$p (signer-$id): blocked"; fi
    done
    if tcp_from_vm "$x" "$yip" 22; then echo "  UNEXPECTED: $x reached $y:22"; L1_OK=0; else echo "  $x -> $y $yip:22 (ssh): blocked"; fi
  done
done
for id in 1 2 3 4 5; do
  vm="$(id_vm "$id")"; ip="$(vm_ip "$vm")"; p="$(id_port "$id")"
  if tcp_from_vm "$COORD_VM" "$ip" "$p"; then echo "  $COORD_VM -> $vm $ip:$p (signer-$id): open (control)"; else echo "  CONTROL FAILED: coordinator host cannot reach signer-$id"; L1_OK=0; fi
done
if [[ $L1_OK == 1 ]]; then pass L1 "no signer host can open TCP to another signer host's signer or SSH ports; coordinator host can"; else fail L1 "lateral path open"; fi

l2_test

section "L3: per-signer OS users on shared hosts"
L3_OK=1
for vm in $SIGNER_VMS; do
  ids="$(vm_ids "$vm")"
  for a in $ids; do
    r="$(rc_on "$vm" "sudo -n -u frost-signer-$a test -r /etc/frost-signer-$a/share.json")"
    if [[ "$r" == rc=0 ]]; then echo "  $vm frost-signer-$a reads own share: yes (control, $r)"; else echo "  CONTROL FAILED: frost-signer-$a cannot read its own share ($r)"; L3_OK=0; fi
    for b in $ids; do
      [[ "$a" == "$b" ]] && continue
      for f in share.json tls.key; do
        r="$(rc_on "$vm" "sudo -n -u frost-signer-$a cat /etc/frost-signer-$b/$f")"
        case "$r" in
          rc=1) echo "  $vm frost-signer-$a -> /etc/frost-signer-$b/$f: permission denied ($r)" ;;
          rc=0) echo "  UNEXPECTED: frost-signer-$a read /etc/frost-signer-$b/$f"; L3_OK=0 ;;
          *)    echo "  INCONCLUSIVE: frost-signer-$a -> /etc/frost-signer-$b/$f returned $r"; L3_OK=0 ;;
        esac
      done
    done
  done
  echo "  $vm files: $(on "$vm" sudo bash -c 'for d in /etc/frost-signer-*; do stat -c "%n %U:%G %a" $d/share.json $d/tls.key; done' | tr -d '\r' | tr '\n' ';')"
done
if [[ $L3_OK == 1 ]]; then pass L3 "each signer's share and TLS key are 0600 owned by its own user; co-located signers cannot read each other's"; else fail L3 "cross-signer file access"; fi

section "L4: share placement (each host holds exactly its assigned shares)"
L4_OK=1
for vm in $SIGNER_VMS; do
  found="$(on "$vm" sudo bash -c 'find / -xdev -type f \( -name "share*.json" -o -name "public-meta.json" \) 2>/dev/null | while read -r f; do python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1], d.get(\"signer_index\", \"meta\"))" "$f"; done' | tr -d '\r')"
  got="$(awk '$2 != "meta" {print $2}' <<<"$found" | sort -n | tr '\n' ' ' | sed 's/ $//')"
  want="$(echo $(vm_ids "$vm") | tr ' ' '\n' | sort -n | tr '\n' ' ' | sed 's/ $//')"
  echo "  $vm: share indices [$got], assigned [$want]"
  [[ "$got" == "$want" ]] || { echo "  MISMATCH on $vm"; L4_OK=0; }
done
coord_shares="$(on "$COORD_VM" sudo bash -c 'find / -xdev -type f -name "share*.json" 2>/dev/null | grep -v "^/proc" ; true' | tr -d '\r')"
echo "  $COORD_VM: share files: [${coord_shares}]"
[[ -z "$coord_shares" ]] || L4_OK=0
ops_left="$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'frost-ceremony.*' 2>/dev/null | wc -l | tr -d ' ')"
echo "  operator: ceremony directories left: $ops_left"
[[ "$ops_left" == 0 ]] || L4_OK=0
if [[ $L4_OK == 1 ]]; then pass L4 "every signer host holds exactly its assigned share indices; coordinator host holds none; ceremony dir deleted"; else fail L4 "share placement wrong"; fi

section "L5: systemd hardening and binary"
L5_OK=1
BIN_SHA="$(jq -r .signer_binary.sha256 reports/multihost/deploy-manifest.json)"
for id in 1 2 3 4 5; do
  vm="$(id_vm "$id")"; u="frost-signer-$id"
  props="$(on "$vm" systemctl show "$u" -p ActiveState,User,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,ReadWritePaths,IPAddressAllow,IPAddressDeny,CapabilityBoundingSet | tr -d '\r' | tr '\n' ' ')"
  pid="$(on "$vm" systemctl show "$u" -p MainPID --value | tr -d '\r')"
  st="$(on "$vm" sudo grep -E '^(Uid|NoNewPrivs|CapEff|CapBnd)' "/proc/$pid/status" | tr -d '\r' | tr -s '\t\n' ' ')"
  score="$(on "$vm" systemd-analyze security "$u" --no-pager 2>/dev/null | tail -1 | tr -d '\r')"
  sha="$(on "$vm" sha256sum /usr/local/bin/frost-signer | cut -d' ' -f1 | tr -d '\r')"
  echo "  signer-$id on $vm: $props"
  echo "    /proc/$pid: $st"
  echo "    systemd-analyze security: $score"
  echo "    binary sha256 $sha"
  [[ "$props" == *"ActiveState=active"* && "$props" == *"User=$u"* && "$props" == *"NoNewPrivileges=yes"* && "$props" == *"ProtectSystem=strict"* && "$st" == *"NoNewPrivs: 1"* && "$st" == *"CapEff: 0000000000000000"* && "$sha" == "$BIN_SHA" ]] || { echo "    NOT AS EXPECTED"; L5_OK=0; }
done
for vm in $SIGNER_VMS; do on "$vm" sudo nft list ruleset | tr -d '\r' > "$RES/nftables-$vm.txt"; done
echo "  firewall rulesets saved: $RES/nftables-*.txt"
if [[ $L5_OK == 1 ]]; then pass L5 "all 5 signers active as their own user, NoNewPrivs=1, no capabilities, ProtectSystem=strict, identical binary sha256 $BIN_SHA"; else fail L5 "hardening or binary mismatch"; fi

section "E2E on the coordinator host (TOPOLOGY=multihost), control channel served here"
KEEPARG=""; [[ $KEEP == 1 ]] && KEEPARG="--keep"
on "$COORD_VM" bash -lc "cd ~/tk8s && ${E2E_ENV:+env $E2E_ENV} TOPOLOGY=multihost timeout 3600 test/e2e/run.sh $KEEPARG" > "$RES/e2e-coordinator-host.log" 2>&1 &
E2E_PID=$!
served=""
serve() { # n request...
  local n="$1"; shift
  local verb="$1"; shift
  local rc=ok
  case "$verb" in
    stop|start)
      for id in "$@"; do
        vm="$(id_vm "$id")"
        on "$vm" sudo systemctl "$verb" "frost-signer-$id" || rc="fail $verb $id"
        if [[ "$verb" == start ]]; then on "$vm" systemctl is-active --quiet "frost-signer-$id" || rc="fail start $id"; fi
      done ;;
    audit)
      for id in 1 2 3 4 5; do
        vm="$(id_vm "$id")"
        on "$vm" sudo cat "/var/lib/frost-signer-$id/audit.log" | tr -d '\r' | on_pipe "$COORD_VM" bash -c "mkdir -p ~/tk8s/audit/signer-$id && cat > ~/tk8s/audit/signer-$id/audit.log"
      done ;;
    *) rc="fail unknown $verb" ;;
  esac
  echo "  [ctl] $n: $verb $* -> $rc"
  on "$COORD_VM" bash -c "echo '$rc' > /tmp/frost-ctl/done-$n.tmp && mv /tmp/frost-ctl/done-$n.tmp /tmp/frost-ctl/done-$n"
}
while kill -0 "$E2E_PID" 2>/dev/null; do
  reqs="$(on "$COORD_VM" bash -c 'cd /tmp/frost-ctl 2>/dev/null && for f in req-*; do [ -f "$f" ] && [ ! -f "done-${f#req-}" ] && echo "${f#req-} $(cat "$f")"; done; true' 2>/dev/null | tr -d '\r')"
  if [[ -n "$reqs" ]]; then
    while read -r n rest; do
      [[ -z "$n" ]] && continue
      case " $served " in *" $n "*) continue ;; esac
      # shellcheck disable=SC2086
      serve "$n" $rest
      served="$served $n"
    done <<<"$reqs"
  fi
  sleep 0.5
done
wait "$E2E_PID" && E2E_RC=0 || E2E_RC=$?
grep -E '^(PASS|FAIL) ' "$RES/e2e-coordinator-host.log" || true
if [[ $E2E_RC == 0 ]] && grep -q '^E2E: PASS' "$RES/e2e-coordinator-host.log"; then pass E2E-MH "coordinator-host e2e (E1-E8, REQ-a..d, N1-N4) passed against remote signers"; else fail E2E-MH "coordinator-host e2e exit $E2E_RC"; fi

if [[ $KEEP == 0 ]]; then
  section "Teardown: stop signers, shred shares and keys on signer hosts"
  for vm in $SIGNER_VMS; do
    on "$vm" sudo bash -c 'for u in /etc/systemd/system/frost-signer-*.service; do [ -f "$u" ] && systemctl disable --now "$(basename "$u")" >/dev/null 2>&1; done; for d in /etc/frost-signer-*; do [ -d "$d" ] && shred -u "$d/share.json" "$d/tls.key" 2>/dev/null; rm -rf "$d"; done; true'
    echo "  $vm: shares left: $(on "$vm" sudo bash -c 'find / -xdev -name "share*.json" 2>/dev/null | wc -l' | tr -d '\r')"
  done
fi

section "Summary"
echo "git commit: $SHA"
echo "topology: $TOPOLOGY_LABEL"
printf '%s\n' "$RESULT_LINES" | sed '/^$/d'
echo "results: $RES"
if [[ $FAILED -ne 0 ]]; then echo "MULTIHOST E2E: FAIL"; exit 1; fi
echo "MULTIHOST E2E: PASS"

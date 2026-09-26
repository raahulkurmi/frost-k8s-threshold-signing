# transport.sh: how the operator reaches the hosts of a multihost topology.
# Sourced (after the topology env) by deploy.sh, teardown.sh, clock-check.sh,
# test/e2e/multihost.sh and benchmark/multihost/*.sh. Portable to macOS bash 3.2.
#
# TRANSPORT=multipass (Level 1, default): hosts are local Multipass VMs.
# TRANSPORT=ssh (Level 2, AWS): hosts are reached as ubuntu@<address> with
#   SSH_KEY and SSH_KNOWN_HOSTS; the topology provides
#   HOST_ADDRS="name=reach-ip ..."  address other hosts and the operator use
#   HOST_BIND="name=bind-ip ..."    address the host's own interface has (on EC2 the
#                                  public IP is NAT'd, so signers bind the private IP)
#   SSH_PRE_HOOK                    run once when sourced (refresh the SG /32 rules)
#
# Functions: alarm SECS CMD..., on HOST CMD... (stdin /dev/null), on_pipe HOST CMD...
# (stdin passed), vm_ip HOST (reach), vm_bind_ip HOST, push HOST SRC DST,
# pull HOST SRC DST, transport_desc.
TRANSPORT="${TRANSPORT:-multipass}"
alarm() { local s="$1"; shift; perl -e 'alarm shift; exec @ARGV' "$s" "$@"; }
_map_get() { local p; for p in $1; do [[ "${p%%=*}" == "$2" ]] && { echo "${p#*=}"; return 0; }; done; return 1; }

case "$TRANSPORT" in
multipass)
  # multipass 1.16.4's client hangs if its stdout/stderr is /dev/null and the
  # remote command writes output (NOTES N42). Always hand it pipes; return its
  # own exit code. Every call has a 300 s alarm.
  on()      { local vm="$1"; shift; alarm 300 multipass exec "$vm" -- "$@" </dev/null 2> >(cat >&2) | cat; return "${PIPESTATUS[0]}"; }
  on_pipe() { local vm="$1"; shift; alarm 300 multipass exec "$vm" -- "$@" 2> >(cat >&2) | cat; return "${PIPESTATUS[0]}"; }
  vm_ip()   { multipass info "$1" --format json | jq -r --arg v "$1" '.info[$v].ipv4[0] // empty'; }
  vm_bind_ip() { vm_ip "$1"; }
  push()    { multipass transfer "$2" "$1:$3"; }
  pull()    { multipass transfer "$1:$2" "$3"; }
  transport_desc() { multipass version | head -1; }
  ;;
ssh)
  : "${HOST_ADDRS:?TRANSPORT=ssh needs HOST_ADDRS}" "${SSH_KEY:?TRANSPORT=ssh needs SSH_KEY}"
  SSH_KNOWN_HOSTS="${SSH_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
  _ssh_opts() { echo "-i $SSH_KEY -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$SSH_KNOWN_HOSTS -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o ConnectTimeout=15 -o LogLevel=ERROR -o ControlMaster=auto -o ControlPath=/tmp/tk8s-cm-%C -o ControlPersist=15m"; }
  vm_ip()      { _map_get "$HOST_ADDRS" "$1"; }
  vm_bind_ip() { _map_get "${HOST_BIND:-}" "$1" || vm_ip "$1"; }
  # ssh joins argv into one remote command line: quote each argument so the
  # remote shell sees exactly the argv that `multipass exec` would pass.
  _q() { local a out=""; for a in "$@"; do out="$out $(printf '%q' "$a")"; done; echo "$out"; }
  # shellcheck disable=SC2046
  on()      { local h="$1"; shift; alarm 600 ssh $(_ssh_opts) "ubuntu@$(vm_ip "$h")" "$(_q "$@")" </dev/null; }
  # shellcheck disable=SC2046
  on_pipe() { local h="$1"; shift; alarm 600 ssh $(_ssh_opts) "ubuntu@$(vm_ip "$h")" "$(_q "$@")"; }
  # shellcheck disable=SC2046
  push()    { alarm 600 scp -q $(_ssh_opts) "$2" "ubuntu@$(vm_ip "$1"):$3"; }
  # shellcheck disable=SC2046
  pull()    { alarm 600 scp -q $(_ssh_opts) "ubuntu@$(vm_ip "$1"):$2" "$3"; }
  transport_desc() { echo "ssh ($(ssh -V 2>&1)), public-key fingerprint $(ssh-keygen -lf "$SSH_KEY.pub" 2>/dev/null | awk '{print $2}')"; }
  if [[ -n "${SSH_PRE_HOOK:-}" && -z "${_TRANSPORT_HOOK_DONE:-}" ]]; then
    export _TRANSPORT_HOOK_DONE=1
    $SSH_PRE_HOOK >/dev/null || { echo "transport: SSH_PRE_HOOK failed: $SSH_PRE_HOOK" >&2; exit 1; }
  fi
  ;;
*) echo "transport: unknown TRANSPORT=$TRANSPORT" >&2; exit 2 ;;
esac

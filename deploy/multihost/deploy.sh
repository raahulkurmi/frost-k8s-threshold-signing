#!/usr/bin/env bash
# deploy.sh: deploy the multi-host topology from the OPERATOR machine (the
# dealer). It provisions no VMs and touches no cloud account: the hosts must
# already exist (see deploy/multihost/README.md). For Level 1 it drives local
# Multipass VMs; Level 2 would replace the transport functions with ssh/scp.
#
#   1. builds the signer binary with the pinned toolchain; records its sha256
#   2. runs the key ceremony in a 0700 temp dir: fresh certs + 3-of-5 key
#   3. stages, per signer host, EXACTLY the shares the topology assigns to it
#      (refuses anything else), ships it, runs setup-signer-host.sh there
#   4. installs only public metadata + coordinator-side certs on the
#      coordinator host (never a share), restricts coordinator egress
#   5. writes a public manifest and securely deletes the ceremony dir
#
# Usage: deploy/multihost/deploy.sh [topology.env]   (default: topology.local.env)
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
TOPO="${1:-deploy/multihost/topology.local.env}"
# shellcheck disable=SC1090
source "$TOPO"
export GOTOOLCHAIN=go1.27.1

die() { echo "deploy: $*" >&2; exit 1; }
command -v multipass >/dev/null || die "multipass not found"
command -v jq >/dev/null || die "jq not found"

vm_ip() { multipass info "$1" --format json | jq -r --arg v "$1" '.info[$v].ipv4[0] // empty'; }
# multipass 1.16.4's client hangs if its stdout/stderr is /dev/null and the
# remote command writes output (NOTES N42). Always hand it pipes; return its own
# exit code.
on() { local vm="$1"; shift; multipass exec "$vm" -- "$@" 2> >(cat >&2) | cat; return "${PIPESTATUS[0]}"; }

# --- topology: each signer id exactly once, 1..5 (portable to macOS bash 3.2) ---
id_vm()   { local s; for s in $SIGNERS; do [[ "${s%%:*}" == "$1" ]] && { s="${s#*:}"; echo "${s%%:*}"; return; }; done; }
id_port() { local s; for s in $SIGNERS; do [[ "${s%%:*}" == "$1" ]] && { echo "${s##*:}"; return; }; done; }
vm_ids()  { local s out=""; for s in $SIGNERS; do local r="${s#*:}"; [[ "${r%%:*}" == "$1" ]] && out="$out ${s%%:*}"; done; echo "$out"; }
SIGNER_VMS="$(for s in $SIGNERS; do r="${s#*:}"; echo "${r%%:*}"; done | sort -u | tr '\n' ' ')"
for id in 1 2 3 4 5; do
  n=0; for s in $SIGNERS; do [[ "${s%%:*}" == "$id" ]] && n=$((n + 1)); done
  [[ $n -eq 1 ]] || die "signer $id must be listed exactly once in $TOPO (found $n)"
done
[[ -z "$(vm_ids "$COORD_VM")" ]] || die "the coordinator host must not hold any share"

COORD_IP="$(vm_ip "$COORD_VM")"; [[ -n "$COORD_IP" ]] || die "no IP for $COORD_VM"
VM_IP_LIST=""
for vm in $SIGNER_VMS; do ip="$(vm_ip "$vm")"; [[ -n "$ip" ]] || die "no IP for $vm"; VM_IP_LIST="$VM_IP_LIST $vm=$ip"; done
vm_ip_of() { local p; for p in $VM_IP_LIST; do [[ "${p%%=*}" == "$1" ]] && { echo "${p#*=}"; return; }; done; }
echo "coordinator host $COORD_VM $COORD_IP; admin $ADMIN_IP"
for vm in $SIGNER_VMS; do echo "signer host $vm $(vm_ip_of "$vm"): signers$(vm_ids "$vm")"; done
# Mandatory pre-run step (N50): force time resync and require every VM to be
# within 1 s of the operator clock; a skewed signer refuses every token (N44).
# shellcheck disable=SC1091
source deploy/multihost/clock-check.sh
clock_check "$COORD_VM" $SIGNER_VMS || die "clock skew check failed (N50)"


W="$(mktemp -d "${TMPDIR:-/tmp}/frost-ceremony.XXXXXX")"
chmod 700 "$W"
cleanup() {
  # Best-effort secure delete of every share, key and the CA key (APFS/SSD: see README).
  find "$W" -type f \( -name 'share*.json' -o -name '*.key' -o -name '*.tgz' \) -exec rm -P {} + 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT
umask 077

# --- 1. binary (pinned toolchain, reproducible flags) ---
ARCH="$(on "$COORD_VM" dpkg --print-architecture | tr -d '\r')"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags="-s -w -buildid=" -o "$W/frost-signer" ./cmd/signer
BIN_SHA="$(shasum -a 256 "$W/frost-signer" | cut -d' ' -f1)"
echo "signer binary: $(go version | cut -d' ' -f3) linux/$ARCH sha256 $BIN_SHA"

# --- 2. ceremony ---
scripts/gen-certs.sh --out "$W/pki" >/dev/null
go build -o "$W/dealer" ./cmd/dealer
"$W/dealer" --out "$W/keys" | sed 's#'"$W"'#<ceremony>#'
KID="$(jq -r .kid "$W/keys/public-meta.json")"

# --- 3. stage + ship per signer host, one assignment each ---
stage_host() { # vm
  local vm="$1" d="$W/stage-$1"
  mkdir -p "$d/common"
  cp "$W/frost-signer" "$d/frost-signer"
  cp "$W/keys/public-meta.json" deploy/policy.json "$d/common/"
  cp "$W/pki/tls/ca.crt" "$d/common/ca.crt"
  for id in $(vm_ids "$vm"); do
    mkdir -p "$d/signer-$id"
    cp "$W/keys/share-$id.json" "$d/signer-$id/share.json"
    cp "$W/pki/tls/signer-$id/tls.crt" "$W/pki/tls/signer-$id/tls.key" "$d/signer-$id/"
  done
  # Guard: exactly the assigned shares, each with the right signer_index.
  local want n
  want=$(wc -w <<<"$(vm_ids "$vm")" | tr -d ' ')
  n=$(find "$d" -name 'share*.json' | wc -l | tr -d ' ')
  [[ "$n" -eq "$want" ]] || die "REFUSING to ship $n shares to $vm (assigned:$(vm_ids "$vm"))"
  for id in $(vm_ids "$vm"); do
    [[ "$(jq -r .signer_index "$d/signer-$id/share.json")" == "$id" ]] || die "share for signer $id has wrong index"
  done
  if [[ -n "$(find "$d" -path '*/pki/ca/*' -o -name 'ca.key')" ]]; then die "CA key staged for $vm"; fi
  COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -C "$d" -czf "$W/stage-$vm.tgz" .
}

HOST_SHA_LIST=""
for vm in $SIGNER_VMS; do
  stage_host "$vm"
  specs=""
  for id in $(vm_ids "$vm"); do specs="$specs $id:$(id_port "$id")"; done
  multipass transfer "$W/stage-$vm.tgz" "$vm:/tmp/frost-stage.tgz"
  on "$vm" sudo bash -c 'set -e; umask 077; rm -rf /root/frost-stage; mkdir /root/frost-stage; tar -xzf /tmp/frost-stage.tgz -C /root/frost-stage; shred -u /tmp/frost-stage.tgz'
  # shellcheck disable=SC2086
  on "$vm" sudo bash -s -- /root/frost-stage "$COORD_IP" "$ADMIN_IP" "$(vm_ip_of "$vm")" $specs < deploy/multihost/setup-signer-host.sh
  hs="$(on "$vm" sha256sum /usr/local/bin/frost-signer | cut -d' ' -f1 | tr -d '\r')"
  [[ "$hs" == "$BIN_SHA" ]] || die "binary on $vm has sha256 $hs, built $BIN_SHA"
  HOST_SHA_LIST="$HOST_SHA_LIST $vm=$hs"
done
host_sha() { local p; for p in $HOST_SHA_LIST; do [[ "${p%%=*}" == "$1" ]] && { echo "${p#*=}"; return; }; done; }

# --- 4. coordinator host: public meta + coordinator-side certs only ---
C="$W/stage-coord"
mkdir -p "$C/keys" "$C/tls"
cp "$W/keys/public-meta.json" "$C/keys/"
cp "$W/pki/tls/ca.crt" "$C/tls/"
cp -r "$W/pki/tls/coordinator" "$W/pki/tls/coordinator-grpc" "$W/pki/tls/lb" "$C/tls/"
ENDPOINTS=""
for id in 1 2 3 4 5; do ENDPOINTS="${ENDPOINTS:+$ENDPOINTS,}$id=https://$(vm_ip_of "$(id_vm "$id")"):$(id_port "$id")"; done
printf 'SIGNER_ENDPOINTS=%s\n' "$ENDPOINTS" > "$C/multihost.env"
[[ -z "$(find "$C" -name 'share*' -o -name 'ca.key' -o -path '*signer-*')" ]] || die "REFUSING: share, CA key or signer cert staged for the coordinator host"
COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -C "$C" -czf "$W/stage-coord.tgz" .
multipass transfer "$W/stage-coord.tgz" "$COORD_VM:/tmp/frost-coord.tgz"
on "$COORD_VM" bash -c 'set -e; cd ~/tk8s; rm -rf secrets; umask 077; mkdir secrets; tar -xzf /tmp/frost-coord.tgz -C secrets; shred -u /tmp/frost-coord.tgz; chmod 644 secrets/keys/public-meta.json secrets/tls/ca.crt secrets/tls/*/tls.crt'
EGRESS=""
for id in 1 2 3 4 5; do EGRESS="$EGRESS $(vm_ip_of "$(id_vm "$id")"):$(id_port "$id")"; done
# shellcheck disable=SC2086
on "$COORD_VM" sudo bash -s -- 172.30.3.0/24 $EGRESS < deploy/multihost/coordinator-egress.sh

# --- 5. public manifest ---
mkdir -p reports/multihost
MAN="reports/multihost/deploy-manifest.json"
{
  echo "{"
  echo "  \"topology\": \"multi-VM, single physical host (Level 1); not infrastructure independence\","
  echo "  \"deployed_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"git_commit\": \"$(git rev-parse HEAD)\", \"kid\": \"$KID\","
  echo "  \"coordinator_host\": {\"vm\": \"$COORD_VM\", \"ip\": \"$COORD_IP\"}, \"admin_ip\": \"$ADMIN_IP\","
  echo "  \"signer_binary\": {\"go\": \"$(go version | cut -d' ' -f3)\", \"goarch\": \"$ARCH\", \"sha256\": \"$BIN_SHA\"},"
  echo "  \"signers\": ["
  first=1
  for id in 1 2 3 4 5; do
    vm="$(id_vm "$id")"
    fp="$(openssl x509 -in "$W/pki/tls/signer-$id/tls.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
    [[ $first == 1 ]] || echo ","
    first=0
    printf '    {"signer_id": %s, "host": "%s", "ip": "%s", "port": %s, "os_user": "frost-signer-%s", "share_index": %s, "cert_san": "signer-%s", "cert_sha256": "%s", "binary_sha256_on_host": "%s"}' \
      "$id" "$vm" "$(vm_ip_of "$vm")" "$(id_port "$id")" "$id" "$id" "$id" "$fp" "$(host_sha "$vm")"
  done
  echo; echo "  ]"; echo "}"
} > "$MAN"
jq . "$MAN" >/dev/null
echo "deployed kid $KID; manifest $MAN; ceremony directory deleted on exit"

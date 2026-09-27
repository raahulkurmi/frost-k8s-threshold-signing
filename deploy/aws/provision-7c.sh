#!/usr/bin/env bash
# provision-7c.sh: Phase 7C AWS resources (NOTES N66, N67), step by step.
#
#   deploy/aws/provision-7c.sh check      read-only: identity, per-region vCPU quota vs running +
#                                         planned, run-instances --dry-run for every planned instance
#   deploy/aws/provision-7c.sh phase1     SGs + control plane, 2 workers, coordinator node (EIP),
#                                         load generator, 5 T-5-region signers
#   deploy/aws/provision-7c.sh phase2     5 T-same-region signers (ap-south-1a/a/b/b/c); needs the
#                                         ap-south-1 quota for 22 vCPU (request d54be0b2..., N66)
#   deploy/aws/provision-7c.sh topology   (re)write deploy/aws/state/7c/*.env from the running instances
#   deploy/aws/provision-7c.sh status
#
# Every step re-checks the caller identity; every resource is tagged
# Project=tk8s-research (teardown.sh removes and verifies them). Before launching,
# planned vCPUs are compared with the live quota: if they do not fit, it STOPS
# (no workaround). Security groups: SSH only from the operator's /32 (refreshed
# when it changes); nodes talk to each other (self-referencing group) and accept
# 6443 from the load generator only; coordinator node 9090-9092 only from the
# control plane; T-5-region signers 8441 only from the coordinator EIP; T-same-
# region signers 8441 only from the coordinator's private IP. Nothing else inbound.
. "$(dirname "$0")/common.sh"
S7="$STATE/7c"; mkdir -p "$S7"
INST="$S7/instances.txt"; touch "$INST"
# role:region:az:type:disk_gb:credit
PHASE1="cp:ap-south-1:ap-south-1a:m7i-flex.large:40:
w1:ap-south-1:ap-south-1b:c7i-flex.large:30:
w2:ap-south-1:ap-south-1c:c7i-flex.large:30:
coord:ap-south-1:ap-south-1a:c7i-flex.large:30:
lg:ap-south-1:ap-south-1a:t3.small:20:unlimited
t5-1:ap-south-1:ap-south-1b:t3.micro:8:unlimited
t5-2:ap-southeast-1:ap-southeast-1a:t3.micro:8:unlimited
t5-3:ap-northeast-1:ap-northeast-1a:t3.micro:8:unlimited
t5-4:eu-central-1:eu-central-1a:t3.micro:8:unlimited
t5-5:us-east-1:us-east-1a:t3.micro:8:unlimited"
PHASE2="ts-1:ap-south-1:ap-south-1a:t3.micro:8:unlimited
ts-2:ap-south-1:ap-south-1a:t3.micro:8:unlimited
ts-3:ap-south-1:ap-south-1b:t3.micro:8:unlimited
ts-4:ap-south-1:ap-south-1b:t3.micro:8:unlimited
ts-5:ap-south-1:ap-south-1c:t3.micro:8:unlimited"

field() { echo "$1" | cut -d: -f"$2"; }
inst_of() { awk -v r="$1" '$1==r {print $3}' "$INST" | tail -1; }   # role -> instance id
region_of() { awk -v r="$1" '$1==r {print $2}' "$INST" | tail -1; }

allow_ports() { # REGION SG FROM TO CIDR WHY
  local r="$1" sg="$2" from="$3" to="$4" cidr="$5" why="$6"
  aws_ ec2 authorize-security-group-ingress --region "$r" --group-id "$sg" \
    --ip-permissions "IpProtocol=tcp,FromPort=$from,ToPort=$to,IpRanges=[{CidrIp=$cidr,Description=\"$why\"}]" \
    --tag-specifications "ResourceType=security-group-rule,Tags=[{Key=$TAG_KEY,Value=$TAG_VAL}]" >/dev/null 2>"$STATE/allow.err" \
    || grep -q InvalidPermission.Duplicate "$STATE/allow.err" || { cat "$STATE/allow.err" >&2; die "authorize failed"; }
  echo "$(date -u +%FT%TZ) $r $sg inbound tcp/$from-$to from $cidr ($why)" | tee -a "$STATE/sg-rules.txt"
}
allow_self() { # REGION SG WHY: all traffic from members of the same group
  local r="$1" sg="$2" why="$3"
  aws_ ec2 authorize-security-group-ingress --region "$r" --group-id "$sg" \
    --ip-permissions "IpProtocol=-1,UserIdGroupPairs=[{GroupId=$sg,Description=\"$why\"}]" \
    --tag-specifications "ResourceType=security-group-rule,Tags=[{Key=$TAG_KEY,Value=$TAG_VAL}]" >/dev/null 2>"$STATE/allow.err" \
    || grep -q InvalidPermission.Duplicate "$STATE/allow.err" || { cat "$STATE/allow.err" >&2; die "authorize failed"; }
  echo "$(date -u +%FT%TZ) $r $sg inbound all protocols from members of $sg ($why)" | tee -a "$STATE/sg-rules.txt"
}

# fits PLAN: every region's running tagged vCPUs + planned vCPUs <= its quota
fits() {
  local plan="$1" r q run want line ok=0
  for r in $(echo "$plan" | cut -d: -f2 | sort -u); do
    q=$(aws_ service-quotas get-service-quota --region "$r" --service-code ec2 --quota-code L-1216C47A --query Quota.Value --output text | cut -d. -f1)
    run=$(aws_ ec2 describe-instances --region "$r" --filters "Name=instance-state-name,Values=pending,running" \
      --query 'Reservations[].Instances[].CpuOptions.[CoreCount,ThreadsPerCore]' --output text | awk '{s+=$1*$2} END{print s+0}')
    want=0
    # every Free Plan type here has 2 vCPU; roles already launched are counted in "running"
    while read -r line; do [[ -z "$line" || "$(field "$line" 2)" != "$r" ]] && continue; [[ -n "$(inst_of "$(field "$line" 1)")" ]] && continue; want=$((want + 2)); done <<<"$plan"
    echo "  $r: quota $q vCPU, running $run, planned +$want -> $((run + want))"
    (( run + want <= q )) || ok=1
  done
  return $ok
}

dry_all() {
  local line r az t out bad=0
  while read -r line; do
    [[ -z "$line" ]] && continue
    r=$(field "$line" 2) az=$(field "$line" 3) t=$(field "$line" 4)
    out=$(aws_ ec2 run-instances --dry-run --region "$r" --image-id "$(ami "$r")" --instance-type "$t" --placement "AvailabilityZone=$az" --count 1 2>&1 || true)
    case "$out" in *DryRunOperation*) echo "  dry-run $(field "$line" 1) $r/$az $t: would succeed";; *) echo "  dry-run $(field "$line" 1) $r/$az $t: REFUSED: $out"; bad=1;; esac
  done <<<"$1"
  return $bad
}

launch_role() { # LINE SG
  local line="$1" sg="$2" role r az t disk credit iid
  role=$(field "$line" 1) r=$(field "$line" 2) az=$(field "$line" 3) t=$(field "$line" 4) disk=$(field "$line" 5) credit=$(field "$line" 6)
  if [[ -n "$(inst_of "$role")" ]]; then log "$role: already launched ($(inst_of "$role"))"; return; fi
  check_identity
  iid=$(launch "$r" "$az" "$t" "$disk" "tk8s-7c-$role" "$sg" $credit)
  echo "$role $r $iid $az $t" >> "$INST"
  log "$role: launched $iid ($t, $az)"
}
wait_running() { local role; for role in "$@"; do aws_ ec2 wait instance-running --region "$(region_of "$role")" --instance-ids "$(inst_of "$role")"; done; }

cmd_check() {
  check_identity
  echo "phase 1:"; fits "$PHASE1" || echo "  PHASE 1 DOES NOT FIT the quota"
  dry_all "$PHASE1" || die "a phase-1 launch would be refused"
  # running instances are counted by fits(); plan only what is not launched yet
  local p2="$PHASE2"; [[ -n "$(inst_of cp)" ]] || p2="$(printf '%s\n%s' "$PHASE1" "$PHASE2")"
  echo "phase 2 (on top of phase 1):"; fits "$p2" || echo "  PHASE 2 DOES NOT FIT the ap-south-1 quota (request d54be0b2..., N66)"
}

cmd_phase1() {
  check_identity
  fits "$PHASE1" || die "phase 1 does not fit the vCPU quota: stopping"
  dry_all "$PHASE1" >/dev/null || die "a phase-1 launch would be refused: stopping"
  refresh_admin_ip; local ip; ip=$(my_ip); echo "$ip" > "$STATE/admin-ip"
  local R=ap-south-1 nodes coordsg lgsg
  nodes=$(ensure_sg $R tk8s7c-nodes "tk8s-research 7C control plane + workers")
  allow_self $R "$nodes" "cluster-internal (kubeadm, kubelet, flannel VXLAN)"
  allow $R "$nodes" 22 "$ip/32" "SSH from operator"
  coordsg=$(ensure_sg $R tk8s7c-coord "tk8s-research 7C coordinator node")
  allow $R "$coordsg" 22 "$ip/32" "SSH from operator"
  lgsg=$(ensure_sg $R tk8s7c-lg "tk8s-research 7C load generator")
  allow $R "$lgsg" 22 "$ip/32" "SSH from operator"
  # coordinator node first: its EIP goes into the signer rules
  launch_role "$(echo "$PHASE1" | grep '^coord:')" "$coordsg"
  wait_running coord
  local alloc eip
  alloc=$(aws_ ec2 describe-addresses --region $R --filters "Name=tag:$TAG_KEY,Values=$TAG_VAL" "Name=tag:Name,Values=tk8s-7c-coord-eip" --query 'Addresses[0].AllocationId' --output text)
  if [[ "$alloc" == None || -z "$alloc" ]]; then
    check_identity; NAME_TAG=tk8s-7c-coord-eip
    alloc=$(aws_ ec2 allocate-address --region $R --domain vpc --tag-specifications $(tagspec elastic-ip) --query AllocationId --output text)
  fi
  aws_ ec2 associate-address --region $R --allocation-id "$alloc" --instance-id "$(inst_of coord)" --query AssociationId --output text >&2
  eip=$(aws_ ec2 describe-addresses --region $R --allocation-ids "$alloc" --query 'Addresses[0].PublicIp' --output text)
  echo "$eip" > "$S7/coord.eip"; log "coordinator EIP $eip"
  local role
  for role in cp w1 w2; do launch_role "$(echo "$PHASE1" | grep "^$role:")" "$nodes"; done
  launch_role "$(echo "$PHASE1" | grep '^lg:')" "$lgsg"
  wait_running cp w1 w2 lg
  allow_ports $R "$coordsg" 9090 9092 "$(private_ip $R "$(inst_of cp)")/32" "nginx on the control plane to the coordinators"
  allow_ports $R "$nodes" 6443 6443 "$(private_ip $R "$(inst_of lg)")/32" "load generator to kube-apiserver"
  local line r sg id
  for id in 1 2 3 4 5; do
    line=$(echo "$PHASE1" | grep "^t5-$id:"); r=$(field "$line" 2)
    check_identity
    sg=$(ensure_sg "$r" "tk8s7c-t5sig-$id" "tk8s-research 7C T-5-region signer $id")
    allow "$r" "$sg" 22 "$ip/32" "SSH from operator"
    allow "$r" "$sg" "$SIGNER_PORT" "$eip/32" "signer-$id mTLS from the coordinator EIP"
    launch_role "$line" "$sg"
  done
  wait_running t5-1 t5-2 t5-3 t5-4 t5-5
  cmd_topology
}

cmd_phase2() {
  check_identity
  [[ -s "$S7/coord.eip" ]] || die "run phase1 first"
  fits "$PHASE2" || die "phase 2 does not fit the ap-south-1 vCPU quota (request d54be0b2..., N66): stopping"
  dry_all "$PHASE2" >/dev/null || die "a phase-2 launch would be refused: stopping"
  refresh_admin_ip; local ip R=ap-south-1 sg line; ip=$(cat "$STATE/admin-ip")
  sg=$(ensure_sg $R tk8s7c-tssig "tk8s-research 7C T-same-region signers")
  allow $R "$sg" 22 "$ip/32" "SSH from operator"
  allow $R "$sg" "$SIGNER_PORT" "$(private_ip $R "$(inst_of coord)")/32" "same-region signers mTLS from the coordinator (private IP)"
  while read -r line; do [[ -n "$line" ]] && launch_role "$line" "$sg"; done <<<"$PHASE2"
  wait_running ts-1 ts-2 ts-3 ts-4 ts-5
  cmd_topology
}

# topology: hosts.env (every host) + one deploy topology per T system
cmd_topology() {
  local role r iid az t addrs="" bind="" place="" eip
  eip=$(cat "$S7/coord.eip")
  while read -r role r iid az t; do
    [[ -z "$role" ]] && continue
    local pub; pub=$(public_ip "$r" "$iid"); [[ "$role" == coord ]] && pub="$eip"
    addrs="$addrs $role=$pub"; bind="$bind $role=$(private_ip "$r" "$iid")"; place="$place $role=aws:$az:$t"
  done < <(sort -u -k1,1 "$INST")
  {
    echo "# Phase 7C hosts (generated by deploy/aws/provision-7c.sh topology)."
    echo "TRANSPORT=ssh"
    echo "SSH_KEY=\"$KEY_FILE\""
    echo "SSH_KNOWN_HOSTS=\"$STATE/known_hosts\""
    echo "SSH_PRE_HOOK=\"$HERE/provision.sh refresh-ip\""
    echo "ADMIN_IP=\"\$(cat \"$STATE/admin-ip\")\""
    echo "SSH_ALLOW=any"
    echo "HOST_ADDRS=\"${addrs# }\""
    echo "HOST_BIND=\"${bind# }\""
    echo "HOST_PLACEMENT=\"${place# }\""
    echo "COORD_EIP=$eip"
  } > "$S7/hosts.env"
  local cpriv; cpriv=$(private_ip ap-south-1 "$(inst_of coord)")
  {
    echo ". \"$S7/hosts.env\""
    echo 'TOPOLOGY_LABEL="7C T-5-region: 5 regions, one provider (AWS), one account, one operator, one build, one dealer"'
    echo "COORD_VM=coord"
    echo 'SIGNERS="1:t5-1:8441 2:t5-2:8441 3:t5-3:8441 4:t5-4:8441 5:t5-5:8441"'
    echo "COORD_SECRETS_DIR=secrets-t5 LB_HOST=cp LB_DIR=/etc/frost-7c/lb-t5 MANIFEST_OUT=reports/aws/7c/deploy-manifest-t5.json"
  } > "$S7/topology-t5.env"
  if grep -q '^ts-1 ' "$INST"; then
    local svc="" id
    for id in 1 2 3 4 5; do svc="$svc ts-$id=$(private_ip ap-south-1 "$(inst_of "ts-$id")")"; done
    {
      echo ". \"$S7/hosts.env\""
      echo 'TOPOLOGY_LABEL="7C T-same-region: 5 signers in ap-south-1 (3 AZs), one provider, one account, one operator, one build, one dealer"'
      echo "COORD_VM=coord"
      echo 'SIGNERS="1:ts-1:8441 2:ts-2:8441 3:ts-3:8441 4:ts-4:8441 5:ts-5:8441"'
      echo "HOST_SERVICE=\"${svc# }\""
      echo "SIGNER_SOURCE_IP=$cpriv"
      echo "COORD_SECRETS_DIR=secrets-tsame LB_HOST=cp LB_DIR=/etc/frost-7c/lb-tsame MANIFEST_OUT=reports/aws/7c/deploy-manifest-tsame.json"
    } > "$S7/topology-tsame.env"
  fi
  log "wrote $S7/hosts.env and topology files"; cat "$S7/hosts.env" | grep -E 'HOST_ADDRS|HOST_PLACEMENT' >&2
}

cmd_status() {
  check_identity
  local r
  for r in $REGIONS; do
    echo "== $r"
    aws_ ec2 describe-instances --region "$r" --filters "Name=tag:$TAG_KEY,Values=$TAG_VAL" \
      --query 'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,InstanceId,State.Name,InstanceType,Placement.AvailabilityZone,PublicIpAddress,PrivateIpAddress]' --output text
  done
}

case "${1:-}" in
  check) cmd_check;; phase1) cmd_phase1;; phase2) cmd_phase2;; topology) check_identity; cmd_topology;; status) cmd_status;;
  *) sed -n '2,24p' "$0"; exit 2;;
esac

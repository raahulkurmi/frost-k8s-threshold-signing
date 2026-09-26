#!/usr/bin/env bash
# provision.sh: create the tk8s-research EC2 resources, step by step.
#
#   deploy/aws/provision.sh check         read-only: identity, regions, allowed types, quotas,
#                                        and run-instances --dry-run for every planned instance
#   deploy/aws/provision.sh keys          generate the ed25519 key (if absent) and import its
#                                        PUBLIC part to all 5 regions
#   deploy/aws/provision.sh coordinator   SG + one m7i-flex.large in ap-south-1a (Phase 7A)
#   deploy/aws/provision.sh signers       SG + one t3.micro per region (Phase 7B Level 2);
#                                        needs the coordinator's public IP
#   deploy/aws/provision.sh refresh-ip    update tcp/22 rules if the operator's public IP changed
#   deploy/aws/provision.sh status        list every tagged resource in the 5 regions
#
# Every step re-checks the caller identity first. Every resource is tagged
# Project=tk8s-research. No AWS credential is written anywhere or copied to any
# instance. Security groups: SSH only from the operator's current public IP;
# the signer port only from the coordinator's public IP; nothing else inbound.
# Every rule is appended to deploy/aws/state/sg-rules.txt.
. "$(dirname "$0")/common.sh"

ami() { aws_ ssm get-parameter --region "$1" --name "$AMI_PARAM" --query Parameter.Value --output text; }

default_vpc() { aws_ ec2 describe-vpcs --region "$1" --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text; }

# ensure_sg REGION NAME DESCRIPTION -> prints the SG id (creates it if missing)
ensure_sg() {
  local r="$1" name="$2" desc="$3" id
  id=$(aws_ ec2 describe-security-groups --region "$r" --filters "Name=group-name,Values=$name" "Name=tag:$TAG_KEY,Values=$TAG_VAL" --query 'SecurityGroups[0].GroupId' --output text)
  if [ "$id" = "None" ] || [ -z "$id" ]; then
    NAME_TAG="$name"
    id=$(aws_ ec2 create-security-group --region "$r" --group-name "$name" --description "$desc" \
      --vpc-id "$(default_vpc "$r")" --tag-specifications $(tagspec security-group) --query GroupId --output text)
    log "$r: created SG $name $id"
  fi
  echo "$id"
}

# allow REGION SG PORT CIDR WHY: add one inbound TCP rule and record it
allow() {
  local r="$1" sg="$2" port="$3" cidr="$4" why="$5"
  aws_ ec2 authorize-security-group-ingress --region "$r" --group-id "$sg" \
    --ip-permissions "IpProtocol=tcp,FromPort=$port,ToPort=$port,IpRanges=[{CidrIp=$cidr,Description=\"$why\"}]" \
    --tag-specifications "ResourceType=security-group-rule,Tags=[{Key=$TAG_KEY,Value=$TAG_VAL}]" >/dev/null 2>"$STATE/allow.err" \
    || grep -q InvalidPermission.Duplicate "$STATE/allow.err" || { cat "$STATE/allow.err" >&2; die "authorize failed"; }
  echo "$(date -u +%FT%TZ) $r $sg inbound tcp/$port from $cidr ($why)" | tee -a "$STATE/sg-rules.txt"
}

# launch REGION AZ TYPE DISK NAME SG [unlimited] -> prints instance id
launch() {
  local r="$1" az="$2" type="$3" disk="$4" name="$5" sg="$6" credit="${7:-}" extra=""
  NAME_TAG="$name"
  [ -n "$credit" ] && extra="--credit-specification CpuCredits=$credit"
  aws_ ec2 run-instances --region "$r" --image-id "$(ami "$r")" --instance-type "$type" \
    --key-name "$KEY_NAME" --security-group-ids "$sg" --placement "AvailabilityZone=$az" \
    --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$disk,VolumeType=gp3,DeleteOnTermination=true}" \
    --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
    --tag-specifications $(tagspec instance volume network-interface) $extra \
    --count 1 --query 'Instances[0].InstanceId' --output text
}

public_ip() { aws_ ec2 describe-instances --region "$1" --instance-ids "$2" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text; }

cmd_check() {
  check_identity
  local r t
  for r in $REGIONS; do
    region_allowed "$r" || die "region $r not allowed"
    echo "== $r: default VPC $(default_vpc "$r"), AMI $(ami "$r"), vCPU quota (L-1216C47A) $(aws_ service-quotas get-service-quota --region "$r" --service-code ec2 --quota-code L-1216C47A --query Quota.Value --output text)"
    for t in $COORD_TYPE $SIGNER_TYPE; do
      echo "   $t free-tier-eligible: $(aws_ ec2 describe-instance-types --region "$r" --instance-types "$t" --query 'InstanceTypes[0].FreeTierEligible' --output text)"
    done
  done
  dry() { # region az type
    local out
    out=$(aws_ ec2 run-instances --dry-run --region "$1" --image-id "$(ami "$1")" --instance-type "$3" --placement "AvailabilityZone=$2" --count 1 2>&1 || true)
    case "$out" in *DryRunOperation*) echo "   dry-run $1/$2 $3: would succeed";; *) echo "   dry-run $1/$2 $3: REFUSED: $out"; return 1;; esac
  }
  dry "$COORD_REGION" "$COORD_AZ" "$COORD_TYPE"
  local s id r2 az
  for s in $SIGNER_REGIONS; do
    id="${s%%:*}"; r2="${s#*:}"; az="${r2}a"; [ "$r2" = ap-south-1 ] && az="$MUMBAI_SIGNER_AZ"
    dry "$r2" "$az" "$SIGNER_TYPE"
  done
}

cmd_keys() {
  check_identity
  if [ ! -f "$KEY_FILE" ]; then
    ssh-keygen -q -t ed25519 -N "" -C "tk8s-research-$(date -u +%Y%m%d)" -f "$KEY_FILE"
    log "generated $KEY_FILE (private key stays on this machine)"
  fi
  local r
  for r in $REGIONS; do
    if aws_ ec2 describe-key-pairs --region "$r" --key-names "$KEY_NAME" >/dev/null 2>&1; then log "$r: key pair exists"; continue; fi
    NAME_TAG="$KEY_NAME"
    aws_ ec2 import-key-pair --region "$r" --key-name "$KEY_NAME" --public-key-material "fileb://$KEY_FILE.pub" \
      --tag-specifications $(tagspec key-pair) --query KeyFingerprint --output text | sed "s/^/[$r] imported, fingerprint /"
  done
}

cmd_coordinator() {
  check_identity
  local ip sg id
  refresh_admin_ip; ip=$(my_ip); echo "$ip" > "$STATE/admin-ip"
  sg=$(ensure_sg "$COORD_REGION" tk8s-coordinator "tk8s-research coordinator: SSH from operator only")
  allow "$COORD_REGION" "$sg" 22 "$ip/32" "SSH from operator"
  check_identity
  id=$(launch "$COORD_REGION" "$COORD_AZ" "$COORD_TYPE" "$COORD_DISK_GB" tk8s-coordinator "$sg")
  log "launched coordinator $id; waiting for running"
  aws_ ec2 wait instance-running --region "$COORD_REGION" --instance-ids "$id"
  echo "$id" > "$STATE/coordinator.id"
  # Elastic IP: the coordinator's address never changes; signer SGs reference it.
  check_identity
  local alloc eip
  alloc=$(aws_ ec2 describe-addresses --region "$COORD_REGION" --filters "Name=tag:$TAG_KEY,Values=$TAG_VAL" --query 'Addresses[0].AllocationId' --output text)
  if [ "$alloc" = "None" ] || [ -z "$alloc" ]; then
    NAME_TAG=tk8s-coordinator-eip
    alloc=$(aws_ ec2 allocate-address --region "$COORD_REGION" --domain vpc --tag-specifications $(tagspec elastic-ip) --query AllocationId --output text)
    log "allocated EIP $alloc"
  fi
  aws_ ec2 associate-address --region "$COORD_REGION" --allocation-id "$alloc" --instance-id "$id" --query AssociationId --output text >&2
  echo "$alloc" > "$STATE/coordinator.eipalloc"
  eip=$(aws_ ec2 describe-addresses --region "$COORD_REGION" --allocation-ids "$alloc" --query 'Addresses[0].PublicIp' --output text)
  echo "$eip" | tee "$STATE/coordinator.ip"
}

cmd_signers() {
  check_identity
  [ -s "$STATE/coordinator.ip" ] || die "no coordinator IP (run: provision.sh coordinator)"
  local cip ip s id r az sg iid
  refresh_admin_ip
  cip=$(cat "$STATE/coordinator.ip"); ip=$(cat "$STATE/admin-ip")
  : > "$STATE/signers.txt"
  for s in $SIGNER_REGIONS; do
    id="${s%%:*}"; r="${s#*:}"; az="${r}a"; [ "$r" = ap-south-1 ] && az="$MUMBAI_SIGNER_AZ"
    check_identity
    sg=$(ensure_sg "$r" "tk8s-signer-$id" "tk8s-research signer $id: SSH from operator, signer port from coordinator only")
    allow "$r" "$sg" 22 "$ip/32" "SSH from operator"
    allow "$r" "$sg" "$SIGNER_PORT" "$cip/32" "signer-$id mTLS from coordinator"
    iid=$(launch "$r" "$az" "$SIGNER_TYPE" "$SIGNER_DISK_GB" "tk8s-signer-$id" "$sg" unlimited)
    log "$r: launched signer $id $iid"
    echo "$id $r $az $iid" >> "$STATE/signers.txt"
  done
  : > "$STATE/signers.ip"
  while read -r id r az iid; do
    aws_ ec2 wait instance-running --region "$r" --instance-ids "$iid"
    echo "$id $r $az $iid $(public_ip "$r" "$iid") $(private_ip "$r" "$iid")" | tee -a "$STATE/signers.ip"
  done < "$STATE/signers.txt"
  write_topology
}

private_ip() { aws_ ec2 describe-instances --region "$1" --instance-ids "$2" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text; }

# write_topology: deploy/aws/state/topology.aws.env for deploy/multihost/*.sh,
# test/e2e/multihost.sh and benchmark/multihost/run-l2.sh (TRANSPORT=ssh).
write_topology() {
  local cid cip cpriv addrs bind place sig id r az iid pub priv
  cid=$(cat "$STATE/coordinator.id"); cip=$(cat "$STATE/coordinator.ip"); cpriv=$(private_ip "$COORD_REGION" "$cid")
  addrs="coord=$cip"; bind="coord=$cpriv"; place="coord=aws:$COORD_AZ:$COORD_TYPE"; sig=""
  while read -r id r az iid pub priv; do
    addrs="$addrs sig-$id=$pub"; bind="$bind sig-$id=$priv"; place="$place sig-$id=aws:$az:$SIGNER_TYPE"
    sig="$sig $id:sig-$id:$SIGNER_PORT"
  done < "$STATE/signers.ip"
  {
    echo "# Phase 7B Level 2 topology (generated by deploy/aws/provision.sh signers)."
    echo "# One signer per AWS region; coordinator in $COORD_AZ (Elastic IP)."
    echo 'TOPOLOGY_LABEL="Level 2: 5 regions, one provider (AWS), one account, one operator, one build, one dealer"'
    echo "TRANSPORT=ssh"
    echo "SSH_KEY=\"$KEY_FILE\""
    echo "SSH_KNOWN_HOSTS=\"$STATE/known_hosts\""
    echo "SSH_PRE_HOOK=\"$HERE/provision.sh refresh-ip\""
    echo "COORD_VM=coord"
    echo "ADMIN_IP=\"\$(cat \"$STATE/admin-ip\")\""
    echo "SSH_ALLOW=any"
    echo "SIGNERS=\"${sig# }\""
    echo "HOST_ADDRS=\"$addrs\""
    echo "HOST_BIND=\"$bind\""
    echo "HOST_PLACEMENT=\"$place\""
    echo 'E2E_ENV="KIND_CONFIG_TMPL=benchmark/single/kind-external.yaml.tmpl"'
  } > "$STATE/topology.aws.env"
  log "wrote $STATE/topology.aws.env"
}

cmd_status() {
  check_identity
  local r
  for r in $REGIONS; do
    echo "== $r"
    aws_ ec2 describe-instances --region "$r" --filters "Name=tag:$TAG_KEY,Values=$TAG_VAL" \
      --query 'Reservations[].Instances[].[InstanceId,State.Name,InstanceType,Placement.AvailabilityZone,PublicIpAddress,Tags[?Key==`Name`]|[0].Value]' --output text
    aws_ ec2 describe-security-groups --region "$r" --filters "Name=tag:$TAG_KEY,Values=$TAG_VAL" --query 'SecurityGroups[].[GroupId,GroupName]' --output text
    aws_ ec2 describe-key-pairs --region "$r" --filters "Name=tag:$TAG_KEY,Values=$TAG_VAL" --query 'KeyPairs[].[KeyPairId,KeyName]' --output text
    aws_ ec2 describe-addresses --region "$r" --filters "Name=tag:$TAG_KEY,Values=$TAG_VAL" --query 'Addresses[].[AllocationId,PublicIp,InstanceId]' --output text
  done
}

case "${1:-}" in
  refresh-ip) refresh_admin_ip; cat "$STATE/admin-ip";;
  topology) write_topology; cat "$STATE/topology.aws.env";;
  check) cmd_check;; keys) cmd_keys;; coordinator) cmd_coordinator;; signers) cmd_signers;; status) cmd_status;;
  *) sed -n '2,17p' "$0"; exit 2;;
esac

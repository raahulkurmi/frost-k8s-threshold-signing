# Shared settings for deploy/aws/*.sh (sourced; bash 3.2 compatible).
# Every AWS call uses --profile tk8s; every resource is tagged Project=tk8s-research.
set -euo pipefail

PROFILE=tk8s
EXPECTED_ARN="arn:aws:iam::767397707897:user/Rahul"
TAG_KEY=Project
TAG_VAL=tk8s-research
# The only regions this project may touch. ap-south-2 (Hyderabad) is disabled on
# the account, so Tokyo replaces it (as instructed).
REGIONS="ap-south-1 ap-northeast-1 ap-southeast-1 eu-central-1 us-east-1"
COORD_REGION=ap-south-1
COORD_AZ=ap-south-1a
COORD_TYPE=m7i-flex.large   # the only Free Plan type with >= 8 GiB (2 vCPU, 8 GiB, x86_64)
COORD_DISK_GB=40
SIGNER_TYPE=t3.micro        # smallest allowed x86_64 type (2 vCPU, 1 GiB); x86_64 = same build as the coordinator
SIGNER_DISK_GB=8
MUMBAI_SIGNER_AZ=ap-south-1b  # different AZ from the coordinator
SIGNER_PORT=8441              # every signer host runs one signer on this port
# signer id -> region (one signer per region)
SIGNER_REGIONS="1:ap-south-1 2:ap-southeast-1 3:ap-northeast-1 4:eu-central-1 5:us-east-1"
KEY_NAME=tk8s-research
KEY_FILE="$HOME/.ssh/tk8s-research-ed25519"   # outside the repo; deleted by teardown.sh
AMI_PARAM=/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="$HERE/state"   # instance ids, IPs, SG rules (gitignored; no secrets)
mkdir -p "$STATE"

aws_() { aws --profile "$PROFILE" "$@"; }
die() { echo "FATAL: $*" >&2; exit 1; }
log() { echo "[$(date -u +%H:%M:%SZ)] $*" >&2; }

# Mandatory before every provisioning step.
check_identity() {
  local arn
  arn=$(aws_ sts get-caller-identity --query Arn --output text) || die "sts get-caller-identity failed"
  [ "$arn" = "$EXPECTED_ARN" ] || die "caller is '$arn', expected '$EXPECTED_ARN': stopping"
  log "identity OK: $arn"
}

region_allowed() { case " $REGIONS " in *" $1 "*) return 0;; esac; return 1; }

tagspec() { # resource-type...
  local out="" t
  for t in "$@"; do out="$out ResourceType=$t,Tags=[{Key=$TAG_KEY,Value=$TAG_VAL},{Key=Name,Value=$NAME_TAG}]"; done
  echo "$out"
}

my_ip() { curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]'; }

# refresh_admin_ip: before every SSH-dependent step. If the operator's public IP
# changed, replace the tcp/22 /32 rule in every tagged SG (all 5 regions) and log it.
refresh_admin_ip() {
  local new old r sg
  new=$(my_ip) || die "cannot determine public IP"
  old=$(cat "$STATE/admin-ip" 2>/dev/null || true)
  [ "$new" = "$old" ] && return 0
  [ -n "$old" ] || { echo "$new" > "$STATE/admin-ip"; return 0; }
  check_identity
  log "operator IP changed: $old -> $new; updating tcp/22 rules"
  for r in $REGIONS; do
    for sg in $(aws_ ec2 describe-security-groups --region "$r" --filters "Name=tag:$TAG_KEY,Values=$TAG_VAL" --query 'SecurityGroups[].GroupId' --output text); do
      aws_ ec2 revoke-security-group-ingress --region "$r" --group-id "$sg" --protocol tcp --port 22 --cidr "$old/32" >/dev/null 2>&1 || true
      aws_ ec2 authorize-security-group-ingress --region "$r" --group-id "$sg" \
        --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$new/32,Description=\"SSH from operator\"}]" \
        --tag-specifications "ResourceType=security-group-rule,Tags=[{Key=$TAG_KEY,Value=$TAG_VAL}]" >/dev/null 2>&1 || true
      echo "$(date -u +%FT%TZ) $r $sg tcp/22: revoked $old/32, added $new/32 (operator IP changed)" >> "$STATE/sg-rules.txt"
    done
  done
  echo "$new" > "$STATE/admin-ip"
}

# --- EC2 helpers shared by provision.sh (7A/7B) and provision-7c.sh (7C) ---
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
private_ip() { aws_ ec2 describe-instances --region "$1" --instance-ids "$2" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text; }

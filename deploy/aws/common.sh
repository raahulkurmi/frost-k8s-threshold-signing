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

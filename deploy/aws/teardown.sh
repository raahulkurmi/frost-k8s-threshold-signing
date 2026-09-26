#!/usr/bin/env bash
# teardown.sh: remove every Project=tk8s-research resource in all 5 regions, then
# prove nothing tagged remains.
#   1. terminate every tagged instance (any state but terminated) and wait
#   2. release every tagged Elastic IP; delete every tagged security group (retried while ENIs detach)
#   3. delete every tagged key pair, and the local private key file
#   4. verify: 0 non-terminated tagged instances, 0 tagged SGs, 0 tagged key pairs,
#      0 tagged volumes; plus the Resource Groups Tagging API across the 5 regions
#      (terminated instances stay visible to EC2 for about an hour; the proof
#      counts only non-terminated ones and lists the terminated ids)
# Exit 0 only if nothing tagged remains.
. "$(dirname "$0")/common.sh"
check_identity

F="Name=tag:$TAG_KEY,Values=$TAG_VAL"
live_instances() { aws_ ec2 describe-instances --region "$1" --filters "$F" "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" --query 'Reservations[].Instances[].InstanceId' --output text; }

for r in $REGIONS; do
  ids=$(live_instances "$r")
  if [ -n "$ids" ]; then
    log "$r: terminating $ids"
    aws_ ec2 terminate-instances --region "$r" --instance-ids $ids --query 'TerminatingInstances[].[InstanceId,CurrentState.Name]' --output text
  fi
done
for r in $REGIONS; do
  ids=$(aws_ ec2 describe-instances --region "$r" --filters "$F" "Name=instance-state-name,Values=shutting-down,pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId' --output text)
  [ -n "$ids" ] && { log "$r: waiting for termination"; aws_ ec2 wait instance-terminated --region "$r" --instance-ids $ids; }
done

for r in $REGIONS; do
  for a in $(aws_ ec2 describe-addresses --region "$r" --filters "$F" --query 'Addresses[].AllocationId' --output text); do
    as=$(aws_ ec2 describe-addresses --region "$r" --allocation-ids "$a" --query 'Addresses[0].AssociationId' --output text)
    [ "$as" != None ] && aws_ ec2 disassociate-address --region "$r" --association-id "$as" 2>/dev/null || true
    aws_ ec2 release-address --region "$r" --allocation-id "$a" && log "$r: released EIP $a"
  done
  for sg in $(aws_ ec2 describe-security-groups --region "$r" --filters "$F" --query 'SecurityGroups[].GroupId' --output text); do
    for i in 1 2 3 4 5 6 7 8 9 10; do
      if aws_ ec2 delete-security-group --region "$r" --group-id "$sg" 2>/dev/null; then log "$r: deleted SG $sg"; break; fi
      [ $i = 10 ] && log "$r: could not delete SG $sg"
      sleep 15
    done
  done
  for kp in $(aws_ ec2 describe-key-pairs --region "$r" --filters "$F" --query 'KeyPairs[].KeyPairId' --output text); do
    aws_ ec2 delete-key-pair --region "$r" --key-pair-id "$kp" >/dev/null && log "$r: deleted key pair $kp"
  done
done
if [ -f "$KEY_FILE" ]; then rm -f "$KEY_FILE" "$KEY_FILE.pub"; log "deleted local key $KEY_FILE"; fi

echo
echo "=== teardown verification ($(date -u +%FT%TZ)), tag $TAG_KEY=$TAG_VAL ==="
left=0
for r in $REGIONS; do
  li=$(live_instances "$r" | wc -w | tr -d ' ')
  term=$(aws_ ec2 describe-instances --region "$r" --filters "$F" "Name=instance-state-name,Values=terminated" --query 'Reservations[].Instances[].InstanceId' --output text | tr '\t' ' ')
  sg=$(aws_ ec2 describe-security-groups --region "$r" --filters "$F" --query 'length(SecurityGroups)' --output text)
  kp=$(aws_ ec2 describe-key-pairs --region "$r" --filters "$F" --query 'length(KeyPairs)' --output text)
  vol=$(aws_ ec2 describe-volumes --region "$r" --filters "$F" --query 'length(Volumes)' --output text)
  eip=$(aws_ ec2 describe-addresses --region "$r" --filters "$F" --query 'length(Addresses)' --output text)
  # The tagging API is eventually consistent and keeps ARNs of deleted resources for a
  # while (seen: the root volumes and ENIs of just-terminated instances). Every ARN it
  # lists is checked against EC2; only resources EC2 still finds count as remaining.
  # A resource type not handled here always counts as remaining.
  tagged=0 stale=0
  for arn in $(aws_ resourcegroupstaggingapi get-resources --region "$r" --tag-filters "Key=$TAG_KEY,Values=$TAG_VAL" \
    --query 'ResourceTagMappingList[].ResourceARN' --output text | tr '\t' '\n' | grep -v ':instance/' | grep -v ':security-group-rule/'); do
    id="${arn##*/}"
    case "$arn" in
      *:volume/*)            ex=$(aws_ ec2 describe-volumes --region "$r" --volume-ids "$id" --query 'length(Volumes)' --output text 2>/dev/null || echo 0) ;;
      *:network-interface/*) ex=$(aws_ ec2 describe-network-interfaces --region "$r" --network-interface-ids "$id" --query 'length(NetworkInterfaces)' --output text 2>/dev/null || echo 0) ;;
      *:security-group/*)    ex=$(aws_ ec2 describe-security-groups --region "$r" --group-ids "$id" --query 'length(SecurityGroups)' --output text 2>/dev/null || echo 0) ;;
      *:key-pair/*)          ex=$(aws_ ec2 describe-key-pairs --region "$r" --key-pair-ids "$id" --query 'length(KeyPairs)' --output text 2>/dev/null || echo 0) ;;
      *:elastic-ip/*)        ex=$(aws_ ec2 describe-addresses --region "$r" --allocation-ids "$id" --query 'length(Addresses)' --output text 2>/dev/null || echo 0) ;;
      *) ex=1; echo "  $r: unhandled tagged resource type, counted as remaining: $arn" ;;
    esac
    if [ "$ex" = 0 ]; then stale=$((stale+1)); else tagged=$((tagged+1)); echo "  $r: STILL EXISTS: $arn"; fi
  done
  printf '%-15s instances(non-terminated)=%s security-groups=%s key-pairs=%s volumes=%s elastic-ips=%s other-tagged(tagging API, existing in EC2)=%s stale-index-entries(deleted, EC2 NotFound)=%s terminated=[%s]\n' "$r" "$li" "$sg" "$kp" "$vol" "$eip" "$tagged" "$stale" "$term"
  left=$((left + li + sg + kp + vol + eip + tagged))
done
[ -f "$KEY_FILE" ] && { echo "local key still present: $KEY_FILE"; left=$((left+1)); }
if [ "$left" -eq 0 ]; then echo "RESULT: zero tagged resources remain in all 5 regions"; else echo "RESULT: $left tagged resources REMAIN"; exit 1; fi

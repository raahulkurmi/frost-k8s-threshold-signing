#!/usr/bin/env bash
# signer-config.sh ID ADMISSION MAXCONC QSAMPLE (run as root on a signer host; NOTES N76)
#   ADMISSION n48 | priority      MAXCONC - | <k>      QSAMPLE - | <Go duration>
# Rewrites the evaluation-managed lines of /etc/frost-signer-ID/env, restarts
# the signer only if the file changed, and prints its latest "signer ready" line.
set -euo pipefail
id="$1" adm="$2" mc="$3" qs="$4"
f="/etc/frost-signer-$id/env"; u="frost-signer-$id"
[[ -f "$f" ]] || { echo "no $f" >&2; exit 2; }
# validate everything before touching the file
[[ "$adm" == n48 || "$adm" == priority ]] || { echo "bad admission $adm" >&2; exit 2; }
[[ "$mc" == - || "$mc" =~ ^[1-9][0-9]?$ ]] || { echo "bad max_concurrent $mc" >&2; exit 2; }
[[ "$qs" == - || "$qs" =~ ^[0-9]+(ms|s)$ ]] || { echo "bad queue sample $qs" >&2; exit 2; }
[[ "$adm" == n48 || -s "/etc/frost-signer-$id/priority.key" ]] || { echo "no priority.key for signer $id" >&2; exit 3; }
before="$(md5sum < "$f")"
sed -i '/^SIGNER_ADMISSION=/d; /^PRIORITY_KEY_FILE=/d; /^SIGNER_MAX_CONCURRENT=/d; /^SIGNER_QUEUE_SAMPLE=/d' "$f"
case "$adm" in
  n48) ;;
  priority) printf 'SIGNER_ADMISSION=priority\nPRIORITY_KEY_FILE=/etc/frost-signer-%s/priority.key\n' "$id" >> "$f" ;;
esac
[[ "$mc" == - ]] || echo "SIGNER_MAX_CONCURRENT=$mc" >> "$f"
[[ "$qs" == - ]] || echo "SIGNER_QUEUE_SAMPLE=$qs" >> "$f"
if [[ "$(md5sum < "$f")" != "$before" ]]; then
  t0="@$(date +%s)"
  systemctl restart "$u"
  for _ in $(seq 1 50); do journalctl -u "$u" --since "$t0" -o cat --no-pager | grep -q '"signer ready"' && break; sleep 0.2; done
fi
systemctl is-active --quiet "$u"
journalctl -u "$u" -o cat --no-pager | grep '"signer ready"' | tail -1

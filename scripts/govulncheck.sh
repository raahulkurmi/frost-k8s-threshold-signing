#!/usr/bin/env bash
# govulncheck.sh: run govulncheck and fail on any REACHABLE vulnerability that
# is not in reports/ci/govulncheck-accepted.txt, or whose acceptance has
# expired. Prints the full text report as well. Usage: scripts/govulncheck.sh [module-dir]
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
ACCEPT="$ROOT/reports/ci/govulncheck-accepted.txt"
DIR="${1:-.}"
GVC="${GOVULNCHECK:-govulncheck}"
cd "$DIR"
"$GVC" ./... || true   # human-readable report (non-zero when anything is found)
found="$("$GVC" -format json ./... | jq -r 'select(.finding != null) | select((.finding.trace // [])[0].function != null) | .finding.osv' | sort -u)"
today="$(date -u +%Y-%m-%d)"
fail=0
for id in $found; do
  line="$(grep -P "^${id}\t" "$ACCEPT" 2>/dev/null || awk -F'\t' -v i="$id" '$1==i' "$ACCEPT")"
  if [[ -z "$line" ]]; then echo "govulncheck.sh: FAIL: reachable $id is not accepted"; fail=1; continue; fi
  until="$(printf '%s' "$line" | cut -f2)"
  if [[ "$today" > "$until" ]]; then echo "govulncheck.sh: FAIL: acceptance of $id expired on $until"; fail=1; else echo "govulncheck.sh: $id reachable, ACCEPTED until $until (see $ACCEPT)"; fi
done
[[ -z "$found" ]] && echo "govulncheck.sh: no reachable vulnerabilities"
exit $fail

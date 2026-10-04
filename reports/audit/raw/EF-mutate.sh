#!/usr/bin/env bash
# EF audit mutation harness: runs in scratchpad/mut-EF (a copy of the clone), never in the clone.
set -u
cd "$(dirname "$0")/../../mut-EF"
run() { # name file perl-expr pkgs tags testregex
  local name="$1" file="$2" expr="$3" pkgs="$4" tags="$5" re="$6"
  git checkout -q -- .
  perl -0pi -e "$expr" "$file"
  if git diff --quiet -- "$file"; then echo "### $name: MUTATION DID NOT APPLY"; return; fi
  echo "### $name"; git diff -U0 -- "$file" | grep '^[-+][^-+]'
  go test -count=1 $tags -run "$re" $pkgs 2>&1 | grep -E '^(--- FAIL|--- PASS|ok|FAIL|panic)' | sort | uniq -c
  echo
}
run M1-no-final-verify internal/coordinator/coordinator.go 's/err = rsa\.VerifyPKCS1v15\(c\.meta\.PublicKey, crypto\.SHA256, digest\[:\], s\)/err = nil; _ = rsa.VerifyPKCS1v15/' "./internal/coordinator/ ./test/" "-tags testmalicious" 'TestMaliciousShareExcludedAndAttributed|TestThreeMalicious|TestBreaker|TestMaliciousSignerExcluded|TestStrictVerifiesUntilT'
run M2-no-id-bound internal/wire/wire.go 's/if id < 1 \|\| id > parties \{/if false {/' "./internal/coordinator/ ./internal/wire/" "" 'TestJoinOutOfRangeIDs|TestShareIDBoundToMTLSIdentity|Test.*Wire|TestToTcrsa'
run M3-no-vsi-check internal/keyshare/keyshare.go 's/got\.Cmp\(want\) != 0 \{/false \&\& got.Cmp(want) != 0 {/' "./cmd/signer/ ./test/" "" 'TestWrongShareIndexRejected|TestCorruptedShareRejected|TestWrongKidRejected'
run M4-no-xi-range internal/wire/wire.go 's/if x\.Sign\(\) <= 0 \|\| x\.Cmp\(n\) >= 0 \{/if false \&\& (x.Sign() <= 0 || x.Cmp(n) >= 0) {/' "./internal/coordinator/" "" 'TestJoinOutOfRangeIDs'
run M5-no-endpoint-dedupe internal/coordinator/coordinator.go 's/if seen\[ep\.ID\] \{/if false \&\& seen[ep.ID] {/' "./internal/coordinator/" "" 'TestNewRejectsBadEndpoints'
run M6-no-response-id-binding internal/coordinator/coordinator.go 's/if sr\.SignerID != ep\.ID \{/if false \&\& sr.SignerID != ep.ID {/' "./internal/coordinator/" "" 'TestShareIDBoundToMTLSIdentity'
run M7-dealer-NewKey-b internal/dealer/dealer.go 's/tcrsa\.NewKey\(modulusBits\+1,/tcrsa.NewKey(modulusBits,/' "./cmd/dealer/" "" 'TestPublicMetaHasNoSecretFields'
git checkout -q -- .
echo "mut-EF restored: $(git status --short | wc -l) changed files"

#!/usr/bin/env bash
# check.sh: run AS ROOT on the Phase 7C control plane BEFORE every measurement
# (NOTES N67). Verifies the signing mode of the running kube-apiserver manifest,
# that a freshly issued token's kid is the expected key (in-tree: sa.pub;
# external: what the signer socket's FetchKeys returns), and that the token passes
# TokenReview. Prints one JSON line; exits non-zero on any mismatch.
#   check.sh EXPECTED_MODE [EXPECTED_KID]   (EXPECTED_KID: optional extra pin, e.g. public-meta kid)
set -euo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf
want="$1" pin="${2:-}"
mode="$(k8s7c mode /etc/kubernetes/manifests/kube-apiserver.yaml)"
if [[ "$mode" == in-tree ]]; then expect="$(cat /etc/frost-7c/in-tree.kid)"; src="sa.pub"
else expect="$(frost-probe fetchkeys unix:///var/run/frost-k8s/signer.sock | jq -r '.keys[0].kid')"; src="signer FetchKeys"; fi
tok="$(kubectl create token default --duration=10m)"
h="$(cut -d. -f1 <<<"$tok" | tr '_-' '/+')"; while (( ${#h} % 4 )); do h="$h="; done
kid="$(base64 -d <<<"$h" | jq -r .kid)"; alg="$(base64 -d <<<"$h" | jq -r .alg)"
auth="$(jq -n --arg t "$tok" '{apiVersion:"authentication.k8s.io/v1",kind:"TokenReview",spec:{token:$t}}' | kubectl create -f - -o json | jq -r .status.authenticated)"
ok=true
[[ "$mode" == "$want" && "$kid" == "$expect" && "$alg" == RS256 && "$auth" == true ]] || ok=false
[[ -z "$pin" || "$kid" == "$pin" ]] || ok=false
jq -cn --arg mode "$mode" --arg want "$want" --arg kid "$kid" --arg expect "$expect" --arg src "$src" --arg pin "$pin" --arg alg "$alg" --arg auth "$auth" --argjson ok "$ok" \
  '{ok: $ok, mode: $mode, expected_mode: $want, token_kid: $kid, expected_kid: $expect, expected_from: $src, pinned_kid: $pin, alg: $alg, tokenreview_authenticated: $auth}'
[[ "$ok" == true ]]

#!/usr/bin/env bash
# switch.sh: run AS ROOT on the Phase 7C control plane (NOTES N67).
#   switch.sh in-tree STAMP          B0: kubeadm's pristine manifests (in-tree SA key)
#   switch.sh external STAMP LBSET   B1/T: external signer socket; nginx gets the lb
#                                    cert set /etc/frost-7c/lb-LBSET and reloads
# Both manifests are stamped with STAMP, so kubelet always restarts kube-apiserver
# (which refetches the external signer's keys at startup) and
# kube-controller-manager (which drops tokens cached from the previous signer).
# Then the workloads holding SA tokens (coredns, kube-proxy, flannel) are restarted
# and everything must be Ready. Prints mode=<in-tree|external>.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
MODE="$1" STAMP="$2" LBSET="${3:-}"
export KUBECONFIG=/etc/kubernetes/admin.conf
M=/etc/kubernetes/manifests D=/etc/frost-7c
[[ "$MODE" == in-tree || "$MODE" == external ]] || { echo "mode must be in-tree or external" >&2; exit 2; }
if [[ "$MODE" == external ]]; then
  [[ -n "$LBSET" && -d "$D/lb-$LBSET" ]] || { echo "lb set $D/lb-$LBSET missing" >&2; exit 2; }
  install -d -m 0700 "$D/lb"
  for f in tls.crt tls.key ca.crt; do
    [[ -e "$D/lb/$f" ]] || install -m 0600 /dev/null "$D/lb/$f"
    cat "$D/lb-$LBSET/$f" > "$D/lb/$f"          # same inode: the hostPath mount sees it
  done
  cp /etc/frost-7c/frost-nginx.yaml "$M/frost-nginx.yaml" 2>/dev/null || true
  for _ in $(seq 1 60); do id="$(crictl ps --name '^nginx$' --state running -q | head -1)"; [[ -n "$id" ]] && break; sleep 1; done
  [[ -n "$id" ]] || { echo "nginx static pod not running" >&2; exit 3; }
  crictl exec "$id" nginx -s reload >/dev/null
fi
node="$(hostname)"
for comp in kube-apiserver kube-controller-manager; do
  k8s7c stamp "$D/$comp.$MODE.yaml" "$D/.$comp.next" "$STAMP"
  chmod 0600 "$D/.$comp.next"; mv "$D/.$comp.next" "$M/$comp.yaml"   # atomic replace
done
for comp in kube-apiserver kube-controller-manager; do
  ok=""
  for _ in $(seq 1 180); do
    got="$(kubectl -n kube-system get pod "$comp-$node" -o jsonpath='{.metadata.annotations.frost-7c/switch}' 2>/dev/null || true)"
    ready="$(kubectl -n kube-system get pod "$comp-$node" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
    [[ "$got" == "$STAMP" && "$ready" == True ]] && { ok=1; break; }
    sleep 2
  done
  [[ -n "$ok" ]] || { echo "$comp did not come back with stamp $STAMP" >&2; exit 4; }
done
kubectl get --raw /readyz >/dev/null
kubectl -n kube-system rollout restart deploy/coredns ds/kube-proxy >/dev/null
kubectl -n kube-flannel rollout restart ds/kube-flannel-ds >/dev/null
kubectl -n kube-system rollout status deploy/coredns --timeout=300s >/dev/null
kubectl -n kube-system rollout status ds/kube-proxy --timeout=300s >/dev/null
kubectl -n kube-flannel rollout status ds/kube-flannel-ds --timeout=300s >/dev/null
kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=300s >/dev/null
echo "mode=$(k8s7c mode "$M/kube-apiserver.yaml") stamp=$STAMP"

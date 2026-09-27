#!/usr/bin/env bash
# cp-init.sh: run AS ROOT on the Phase 7C control-plane node after node-setup.sh.
#   kubeadm init (v1beta4 config): in-tree SA key (B0) + TokenRequest-only audit,
#   the same for every system; flannel (checksum-verified); saves kubeadm's
#   pristine kube-apiserver / kube-controller-manager manifests and derives the
#   external-signer variants with k8s7c (NOTES N67); creates the signer socket
#   directory root:root 0700. Prints the worker join command last.
# Usage: cp-init.sh versions.env PRIVATE_IP AUDIT_POLICY.yaml K8S7C_BINARY
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
# shellcheck disable=SC1090
. "$1"; PRIV="$2"; POLICY="$3"; K8S7C="$4"
install -m 0755 "$K8S7C" /usr/local/bin/k8s7c
install -d -m 0755 /etc/kubernetes/audit /var/log/kubernetes
install -m 0644 "$POLICY" /etc/kubernetes/audit/audit-policy.yaml
install -d -o root -g root -m 0700 /var/run/frost-k8s
install -d -m 0700 /etc/frost-7c

cat > /etc/frost-7c/kubeadm.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: $PRIV
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
kubernetesVersion: v$K8S_VERSION
networking:
  podSubnet: $POD_CIDR
apiServer:
  certSANs: ["$PRIV"]
  extraArgs:
  - name: service-account-issuer
    value: https://kubernetes.default.svc.cluster.local
  - name: audit-policy-file
    value: /etc/kubernetes/audit/audit-policy.yaml
  - name: audit-log-path
    value: /var/log/kubernetes/audit.log
  - name: audit-log-maxsize
    value: "500"
  extraVolumes:
  - name: audit-policy
    hostPath: /etc/kubernetes/audit
    mountPath: /etc/kubernetes/audit
    readOnly: true
    pathType: Directory
  - name: audit-log
    hostPath: /var/log/kubernetes
    mountPath: /var/log/kubernetes
    pathType: DirectoryOrCreate
EOF
kubeadm init --config /etc/frost-7c/kubeadm.yaml --upload-certs=false > /etc/frost-7c/kubeadm-init.log 2>&1 || { tail -30 /etc/frost-7c/kubeadm-init.log >&2; exit 1; }
export KUBECONFIG=/etc/kubernetes/admin.conf
install -d -o ubuntu -g ubuntu -m 0700 /home/ubuntu/.kube
install -o ubuntu -g ubuntu -m 0600 /etc/kubernetes/admin.conf /home/ubuntu/.kube/config

# flannel, verified against the pinned sha256
curl -fsSL -o /etc/frost-7c/kube-flannel.yml "$FLANNEL_URL"
echo "$FLANNEL_SHA256  /etc/frost-7c/kube-flannel.yml" | sha256sum -c - >/dev/null || { echo "flannel manifest checksum mismatch" >&2; exit 1; }
kubectl apply -f /etc/frost-7c/kube-flannel.yml >/dev/null

# pristine (in-tree, B0) manifests and their external-signer variants
M=/etc/kubernetes/manifests
cp "$M/kube-apiserver.yaml" /etc/frost-7c/kube-apiserver.in-tree.yaml
cp "$M/kube-controller-manager.yaml" /etc/frost-7c/kube-controller-manager.in-tree.yaml
k8s7c external-apiserver /etc/frost-7c/kube-apiserver.in-tree.yaml /etc/frost-7c/kube-apiserver.external.yaml
k8s7c external-kcm /etc/frost-7c/kube-controller-manager.in-tree.yaml /etc/frost-7c/kube-controller-manager.external.yaml
[[ "$(k8s7c mode /etc/frost-7c/kube-apiserver.in-tree.yaml)" == in-tree && "$(k8s7c mode /etc/frost-7c/kube-apiserver.external.yaml)" == external ]] \
  || { echo "manifest variants are not in-tree/external as expected" >&2; exit 1; }
k8s7c kid /etc/kubernetes/pki/sa.pub > /etc/frost-7c/in-tree.kid
chmod 0600 /etc/frost-7c/*.yaml

for _ in $(seq 1 120); do kubectl get --raw /readyz >/dev/null 2>&1 && break; sleep 2; done
echo "control plane ready: $(kubectl version -o json | jq -r .serverVersion.gitVersion); in-tree kid $(cat /etc/frost-7c/in-tree.kid)"
kubeadm token create --print-join-command

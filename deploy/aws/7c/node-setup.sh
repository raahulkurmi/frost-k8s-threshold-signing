#!/usr/bin/env bash
# node-setup.sh: run AS ROOT on a Phase 7C Kubernetes node (control plane or
# worker), Ubuntu 24.04. Installs containerd (docker.com signed apt repo,
# systemd cgroup driver) and kubeadm/kubelet/kubectl pinned to
# $K8S_APT_VERSION from the signed pkgs.k8s.io repo, held against upgrades.
# Usage: node-setup.sh versions.env
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
# shellcheck disable=SC1090
. "$1"
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || { echo "needs Ubuntu 24.04" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive

swapoff -a; sed -i '/\sswap\s/d' /etc/fstab
printf 'overlay\nbr_netfilter\n' > /etc/modules-load.d/k8s.conf
modprobe overlay; modprobe br_netfilter
cat > /etc/sysctl.d/99-k8s.conf <<'EOF'
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system >/dev/null

apt-get update -qq
apt-get install -y -qq ca-certificates curl gpg jq python3 >/dev/null
install -m 0755 -d /etc/apt/keyrings
# containerd from docker.com (apt verifies the repository signature with this key)
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list
# Kubernetes from pkgs.k8s.io (signed)
curl -fsSL "${K8S_APT_REPO}Release.key" | gpg --dearmor --batch --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] $K8S_APT_REPO /" > /etc/apt/sources.list.d/kubernetes.list
apt-get update -qq
apt-get install -y -qq containerd.io >/dev/null
containerd config default > /etc/containerd/config.toml
# systemd cgroup driver (kubelet's default on cgroup v2)
if grep -q 'SystemdCgroup = false' /etc/containerd/config.toml; then
  sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
fi
grep -q 'SystemdCgroup = true' /etc/containerd/config.toml || { echo "could not enable SystemdCgroup in containerd config" >&2; exit 1; }
systemctl restart containerd; systemctl enable --quiet containerd
apt-get install -y -qq "kubelet=$K8S_APT_VERSION" "kubeadm=$K8S_APT_VERSION" "kubectl=$K8S_APT_VERSION" "cri-tools=$CRI_TOOLS_APT_VERSION" >/dev/null
apt-mark hold kubelet kubeadm kubectl cri-tools >/dev/null
systemctl enable --quiet kubelet
cat > /etc/crictl.yaml <<'EOF'
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
EOF
echo "node ready: $(kubeadm version -o short), $(containerd --version | awk '{print $3}'), cgroup $(stat -fc %T /sys/fs/cgroup)"

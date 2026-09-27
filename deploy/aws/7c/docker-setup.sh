#!/usr/bin/env bash
# docker-setup.sh: run AS ROOT on the Phase 7C coordinator node (Ubuntu 24.04):
# Docker Engine + compose plugin from the signed docker.com apt repo; USER joins
# the docker group. The coordinators/B1 run here under docker compose.
# Usage: docker-setup.sh USER
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
. /etc/os-release
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq; apt-get install -y -qq ca-certificates curl jq git python3 openssl >/dev/null
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
usermod -aG docker "$1"
echo "docker $(docker version --format '{{.Server.Version}}') ready; DOCKER-USER chain: $(iptables -nL DOCKER-USER >/dev/null 2>&1 && echo present || echo MISSING)"
